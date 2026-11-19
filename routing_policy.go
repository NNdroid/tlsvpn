package main

// RoutingAlgo 是自适应多路径调度器的选路算法标识。
//
// 每个值都绑定一套完整的策略：主排名键（rank）+ 是否启用粘滞滞回（sticky）
// + 是否启用 WFQ 字节公平分摊（wfq）。这样「排名维度」与「稳定性/公平性」
// 两个关注点被显式拆开，而不是混在一次排序里。
type RoutingAlgo string

const (
	// RoutingAlgoAuto 默认算法：去程稳定地板（decayed-min fwd，叠加 recent-typical
	// 劣化抬升）+ 按路径容量的服务时间，带粘滞滞回与容量加权 WFQ。
	RoutingAlgoAuto RoutingAlgo = "auto"
	// RoutingAlgoLatencyStrict 严格最低去程稳定地板：每批选 rank[0]，无粘滞、无 WFQ。
	// 路径劣化时立即切到下一条最优，符合「按去程选」的直观预期。
	RoutingAlgoLatencyStrict RoutingAlgo = "latency_strict"
	// RoutingAlgoLatencySticky 最低去程稳定地板 + 粘滞滞回：单路径模式下当前活跃路径
	// 只要在自适应粘滞带内就不切换，抑制瞬时抖动。
	RoutingAlgoLatencySticky RoutingAlgo = "latency_sticky"
	// RoutingAlgoMinRTTStrict 严格最低内核 min_rtt 无拥塞地板，无粘滞、无 WFQ。
	RoutingAlgoMinRTTStrict RoutingAlgo = "min_rtt_strict"
	// RoutingAlgoMinRTTAdaptive 内核 min_rtt 地板排名 + 粘滞 + WFQ 字节公平：
	// 排名看无拥塞地板，集内分摊与稳定性沿用默认逻辑。
	RoutingAlgoMinRTTAdaptive RoutingAlgo = "min_rtt_adaptive"
	// RoutingAlgoRoundTripStrict 严格最低当前 SRTT 往返，无粘滞、无 WFQ。
	// 对瞬时拥塞最敏感，路径优劣翻转最快。
	RoutingAlgoRoundTripStrict RoutingAlgo = "roundtrip_strict"
)

// rankKey 是候选排名的度量维度。选路算法决定用哪个维度做主排名键。
type rankKey int

const (
	// rankOneWayPlusService 去程稳定地板 + 本批服务时间（auto 默认）。
	rankOneWayPlusService rankKey = iota
	// rankOneWay 去程稳定地板（decayed-min fwd）。
	rankOneWay
	// rankMinRTTHalf 内核 min_rtt 无拥塞地板的一半。
	rankMinRTTHalf
	// rankSRTTHalf 当前 SRTT 往返的一半。
	rankSRTTHalf
)

// routingPolicy 描述一个选路算法的完整行为。
type routingPolicy struct {
	rank   rankKey
	sticky bool // 单路径模式启用粘滞滞回（adaptiveStickySlackUS）
	wfq    bool // 活跃集内启用 WFQ 字节公平分摊
}

// routingAlgoCode 把算法标识映射为 AsyncPort 上存储的 int32 码（热路径零分配读取）。
// 0 = auto；未知值一律归一化为 0，与校验期拒绝相配合。
func routingAlgoCode(algo string) int32 {
	switch RoutingAlgo(algo) {
	case RoutingAlgoLatencyStrict:
		return 1
	case RoutingAlgoLatencySticky:
		return 2
	case RoutingAlgoMinRTTStrict:
		return 3
	case RoutingAlgoMinRTTAdaptive:
		return 4
	case RoutingAlgoRoundTripStrict:
		return 5
	default:
		return 0
	}
}

// routingPolicyForCode 把 AsyncPort 上存储的 int32 码映射为策略。
// 未知码回退 auto（默认），保证配置热更前后行为不突变。
func routingPolicyForCode(code int32) routingPolicy {
	switch code {
	case 1:
		return routingPolicy{rank: rankOneWay}
	case 2:
		return routingPolicy{rank: rankOneWay, sticky: true}
	case 3:
		return routingPolicy{rank: rankMinRTTHalf}
	case 4:
		return routingPolicy{rank: rankMinRTTHalf, sticky: true, wfq: true}
	case 5:
		return routingPolicy{rank: rankSRTTHalf}
	default:
		return routingPolicy{rank: rankOneWayPlusService, sticky: true, wfq: true}
	}
}

// routingPolicyFor 把配置字符串映射为策略；未知值回退 auto。
func routingPolicyFor(algo string) routingPolicy {
	return routingPolicyForCode(routingAlgoCode(algo))
}

// ValidRoutingAlgo 报告字符串是否为已知选路算法（配置校验用）。
func ValidRoutingAlgo(algo string) bool {
	return routingAlgoCode(algo) != 0 || algo == string(RoutingAlgoAuto)
}

// routingAlgoList 返回下拉框展示的算法列表，顺序即界面顺序。
func routingAlgoList() []RoutingAlgo {
	return []RoutingAlgo{
		RoutingAlgoAuto,
		RoutingAlgoLatencyStrict,
		RoutingAlgoLatencySticky,
		RoutingAlgoMinRTTStrict,
		RoutingAlgoMinRTTAdaptive,
		RoutingAlgoRoundTripStrict,
	}
}

// candidateRankUS 按策略计算候选的主排名键（µs，有符号）。
//
// oneWay 为探针分解的原始相对量（可为负：快于 ref 对称基准的方向），完全未测
// 路径已折到参考 minRTT/2；rttUS 为已归一化的 min_rtt（fairStart 路径取参考
// minRTT），srttUS 为原始 SRTT（未知时为 adaptiveUnknownRTTUS 哨兵——
// roundtrip_strict 会拿它做排名键：50ms/2 的固定名次是有意的保守回退，让
// 冷路径压过 SRTT>50ms 的拥塞热路径并享受 fair-start），schedRate 为调度速率。有符号保证快路径（负值）与慢路径的完整序参与
// argmin——压非负会让快路径并列，选路退化（旧 subClamp 教训）。
func candidateRankUS(p routingPolicy, oneWay int64, rttUS uint32, srttUS uint32, incomingBytes, schedRate uint64) int64 {
	switch p.rank {
	case rankOneWay:
		return oneWay
	case rankMinRTTHalf:
		return int64(rttUS) / 2
	case rankSRTTHalf:
		return int64(srttUS) / 2
	default: // rankOneWayPlusService
		// schedRate 已是 per-path 容量估计（Writer-drain EWMA，未测路径回退保守
		// 25MB/s，见 buildEligibleCandidates）：服务时间项对本批各候选不再相同，
		// auto 由此与 latency_sticky（纯地板）真正区分——快路径服务本批更早完成。
		// 该速率同时是 WFQ 的容量权重（dispatchWFQ 计费），"服务时间"与"容量
		// 权重"共用一个量是有意的：两者都回答"这条路径多快"。
		return oneWay + int64(serviceTimeUS(incomingBytes, schedRate))
	}
}

// SchedEnvelope 是候选资格门（near-minRTT envelope）的度量维度。
//
// 资格门回答"这条路径有没有资格进候选集"，与排名键回答"谁最快"是两个独立问题。
// 历史实现只用内核 min_rtt（往返地板）做门，它是**方向盲**的：会顺手毙掉一条
// "去程最快但往返很慢"的极不对称路径——而那条路径对本端 egress 的接收端乱序
// 窗口其实最有利——它慢的那一侧是对端的发送方向，会被对端自己那端的资格门挡掉。
// 两端各自按自己的发送方向设门，不需要跨端协调。
//
// 边界条件（TCP ACK 自钟控）：上述论证只对交互区间完整成立。需求进入多路径
// 区间（rttMode）后，吞吐被 cwnd/(F+B) 钉死——"去程快但回程被对端下行数据
// 踩死"的路径对本端 bulk 无交付增益，fwd 门叠加回程拥塞副门（探针回程抬升
// 超窗排除，见 envelopeGate/schedExcludeRetCongested），fwd 系排名键同步升级
// 往返（fwd+ret 之和）。
type SchedEnvelope string

const (
	// SchedEnvelopeRTT 内核 min_rtt 往返地板（历史行为，默认）。
	SchedEnvelopeRTT SchedEnvelope = "rtt"
	// SchedEnvelopeFwd 本端去程排名键（µs，有符号相对量）。探针未收敛的单条
	// 路径自动回退 rtt 门；组内无任何已收敛去程读数时整体回退 rtt 门。
	SchedEnvelopeFwd SchedEnvelope = "fwd"
)

// schedEnvelope*Ms fwd 模式的去程准入窗口（毫秒）。与 fec_near_window_ms 同量纲
// 但语义独立：这里决定"准入"，那里决定"parity 资格"。
const (
	schedEnvelopeDefaultMs = 20
	schedEnvelopeMinMs     = 1
	schedEnvelopeMaxMs     = 500
)

// ValidSchedEnvelope 校验 sched_envelope 取值。未知值按非法处理，由配置层报错。
func ValidSchedEnvelope(v string) bool {
	switch SchedEnvelope(v) {
	case SchedEnvelopeRTT, SchedEnvelopeFwd:
		return true
	}
	return false
}

// schedEnvelopeFor 把配置值归一为枚举：空串/未知值一律回退 rtt（默认，与引入本
// 选项前的历史行为一致）。
func schedEnvelopeFor(v string) SchedEnvelope {
	if v == string(SchedEnvelopeFwd) {
		return SchedEnvelopeFwd
	}
	return SchedEnvelopeRTT
}

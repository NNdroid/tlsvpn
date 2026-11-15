package main

// RoutingAlgo 是自适应多路径调度器的选路算法标识。
//
// 每个值都绑定一套完整的策略：主排名键（rank）+ 是否启用粘滞滞回（sticky）
// + 是否启用 WFQ 字节公平分摊（wfq）。这样「排名维度」与「稳定性/公平性」
// 两个关注点被显式拆开，而不是混在一次排序里。
type RoutingAlgo string

const (
	// RoutingAlgoAuto 默认算法：去程稳定地板（decayed-min fwd）+ 本批服务时间，
	// 带粘滞滞回与 WFQ 字节公平。与引入本选项前的历史行为完全一致。
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
// 0 = auto；未知值一律归一化为 0，与校验期拦截相配合。
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

// candidateRankUS 按策略计算候选的主排名键（µs）。
//
// oneWay 为已归一化的单向时延（完全未测路径已折到参考 minRTT/2），rttUS 为已归一化
// 的 min_rtt（fairStart 路径取参考 minRTT），srttUS 为原始 SRTT（未知时可能为
// adaptiveUnknownRTTUS 哨兵，仅观测用），schedRate 为调度速率。
func candidateRankUS(p routingPolicy, oneWay uint64, rttUS uint32, srttUS uint32, incomingBytes, schedRate uint64) uint64 {
	switch p.rank {
	case rankOneWay:
		return oneWay
	case rankMinRTTHalf:
		return uint64(rttUS) / 2
	case rankSRTTHalf:
		return uint64(srttUS) / 2
	default: // rankOneWayPlusService
		return oneWay + serviceTimeUS(incomingBytes, schedRate)
	}
}

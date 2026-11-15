package main

// FecStrategy 是 parity 帧分发策略（发送端本地决策，无需服务端协商）。
//
// 控制「parity 投到哪些物理连接」：与选路算法正交，但 `near` 使 parity 只
// 落在与数据路径去程时延相近的连接上，避免严格单路径模式下 parity 漏到
// 明显更慢的备用链路。
type FecStrategy string

const (
	// FecStrategyAuto 默认策略：parity 在所有健康物理后端间轮转、避开数据路径。
	// 与引入本选项前的行为完全一致，恢复价值最大。
	FecStrategyAuto FecStrategy = "auto"
	// FecStrategyNear 只把 parity 投到去程单程时延 ≤ 数据路径 fwd + 窗口（默认
	// 10ms，见 client.fec_near_window_ms）的健康后端。数据路径自身恒在窗口内，
	// 因此即使没有近速备链也不丢 FEC；慢链路上的 parity 被抑制。
	FecStrategyNear FecStrategy = "near"
)

// fecNearWindowDefaultMs 是 near 策略窗口的默认值（毫秒）。
const fecNearWindowDefaultMs = 10

// fecNearWindowMinMs / MaxMs 是 near 窗口的校验边界（毫秒）。
const (
	fecNearWindowMinMs = 1
	fecNearWindowMaxMs = 100
)

// fecStrategyCode 把策略标识映射为 AsyncPort 上存储的 int32 码（热路径零分配读取）。
// 0 = auto；未知值归一化为 0。
func fecStrategyCode(strategy string) int32 {
	switch FecStrategy(strategy) {
	case FecStrategyNear:
		return 1
	default:
		return 0
	}
}

// fecStrategyForCode 把 int32 码映射为策略；未知码回退 auto。
func fecStrategyForCode(code int32) FecStrategy {
	switch code {
	case 1:
		return FecStrategyNear
	default:
		return FecStrategyAuto
	}
}

// ValidFecStrategy 报告字符串是否为已知 FEC 策略（配置校验用）。
func ValidFecStrategy(strategy string) bool {
	return fecStrategyCode(strategy) != 0 || strategy == string(FecStrategyAuto)
}

// fecStrategyList 返回下拉框展示的策略列表，顺序即界面顺序。
func fecStrategyList() []FecStrategy {
	return []FecStrategy{FecStrategyAuto, FecStrategyNear}
}

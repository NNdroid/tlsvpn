package main

// 会话级控制平面分流（RX seq=0 typed control）。
//
// 为什么在 FEC 门控之前分流而不是统一进数据管线：0x07 active-paths、0x03/0x04
// RTT 探针、0x05/0x06 时钟偏移都是旁路控制信号——不参与保序、重排与 FEC 恢复，
// 且在未协商 FEC 的会话上同样存在。放进门控之后的统一分发，无 FEC 会话会把
// 合法控制帧判成协议违规断链。而未被本分流器认领的 typed control 仍交门控按
// 协议违规处理（fail-closed：未知 kind、kind 匹配但载荷畸形、或对应平面未协商
// 时不认领，一律断链）。
//
// 性能：每帧一次 kind 提取 + switch 完成 Dispatch（编译器生成比较/跳转链，
// 替代串行的三个独立前缀判定函数）；数据帧（seq!=0）完全不进入本函数，控制帧
// 占比仅探针节奏（500ms 级），分派开销相对数据面可忽略；位图回调走接口，
// 接收器指针传递零分配。

// peerBitmapSink 消费对端活跃位图（0x07）。由两端持有连接表的宿主实现：
// Client 按本端 conns 表槽位编号刷新，Server 按 session.conns 的 connIndex 刷新。
type peerBitmapSink interface {
	applyPeerActiveBitmap(bitmap uint16)
}

// dispatchControlFrame 按 kind 把 frame 分发给对应处理器。
//
// 返回 true = 帧已被认领并消费完毕（调用方归还缓冲即可）；false = 无匹配处理
// 器（含 kind 匹配但载荷畸形、或对应控制平面未协商），调用方必须交 FEC 门控
// 按协议违规断链——绝不能静默吞掉，否则协议混乱不可见。
func dispatchControlFrame(frame []byte, connIndex int, rtt *rttProbeScheduler, clock *clockOffsetScheduler, sink peerBitmapSink) bool {
	if len(frame) == 0 {
		return false
	}
	switch frame[0] {
	case controlKindActivePaths:
		bm, ok := parseActivePathsFrame(frame)
		if ok && bm != 0 && sink != nil {
			sink.applyPeerActiveBitmap(bm)
		}
		return ok // 长度畸形的 0x07 不认领：交门控断链，与其它未知载荷同待遇
	case controlKindRttProbe, controlKindRttReply:
		if rtt != nil && isRttProbeFrame(frame) {
			rtt.onFrame(frame, connIndex)
			return true
		}
	case controlKindClockProbe, controlKindClockReply:
		if clock != nil && isClockOffsetFrame(frame) {
			clock.onFrame(frame, connIndex)
			return true
		}
	}
	// 0x01/0x02（FEC parity/mode）与其余未知 kind 不在此认领：前者属于 FEC
	// 会话管线（门控后按协商状态分发），后者按违规断链。
	return false
}

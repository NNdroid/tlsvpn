package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
)

// ======================= 内存池与带有序列号的成帧协议 =======================
type VPNFrame struct {
	Seq  uint32
	Data []byte
}

// 后端 channel 只需要复制 VPNFrame 描述符；payload 的所有权可以从
// AsyncPort 批次直接转移给唯一数据后端，无需再次 clone 每个 []byte。
//
// 典型 1500B 数据在 64KB 聚合上限下每批约 40~50 帧；128 档覆盖常见路径。
// 池里存 *[128]VPNFrame 而不是 []VPNFrame，避免 slice header 装箱逃逸。
const hotVPNBatchCap = 128

func newVPNFrameBatch() any { return new([hotVPNBatchCap]VPNFrame) }

var vpnFrameBatchPool = sync.Pool{New: newVPNFrameBatch}

func getVPNFrameBatch(n int) []VPNFrame {
	if n <= hotVPNBatchCap {
		return vpnFrameBatchPool.Get().(*[hotVPNBatchCap]VPNFrame)[:n]
	}
	return make([]VPNFrame, n)
}

func putVPNFrameBatch(b []VPNFrame) {
	if b == nil {
		return
	}
	clear(b) // 清掉 Data 指针，避免池对象把 frame buffer 长期保活
	if cap(b) == hotVPNBatchCap {
		vpnFrameBatchPool.Put((*[hotVPNBatchCap]VPNFrame)(b[:hotVPNBatchCap]))
	}
}

// framePoolSizes 帧缓冲尺寸分档。保留该表供测试/文档核对；真正池对象使用
// *[N]byte，而不是 []byte。把 slice 直接放进 sync.Pool 会在 interface 装箱时
// 让 slice header 逃逸，高 PPS 下这本身会制造显著 GC 压力。
var framePoolSizes = []int{512, 1024, 2048, 4096, 8192, 16384, 32768, 143360}

// defaultFrameSize getFrame() 默认分档。1500 字节以太网帧（含 14B 以太头）
// 是 cloneFrame / FrameScanner 的绝对主流量。
const defaultFrameSize = 2048

func newFrame512() any    { return new([512]byte) }
func newFrame1024() any   { return new([1024]byte) }
func newFrame2048() any   { return new([2048]byte) }
func newFrame4096() any   { return new([4096]byte) }
func newFrame8192() any   { return new([8192]byte) }
func newFrame16384() any  { return new([16384]byte) }
func newFrame32768() any  { return new([32768]byte) }
func newFrame143360() any { return new([143360]byte) }

var (
	framePool512    = sync.Pool{New: newFrame512}
	framePool1024   = sync.Pool{New: newFrame1024}
	framePool2048   = sync.Pool{New: newFrame2048}
	framePool4096   = sync.Pool{New: newFrame4096}
	framePool8192   = sync.Pool{New: newFrame8192}
	framePool16384  = sync.Pool{New: newFrame16384}
	framePool32768  = sync.Pool{New: newFrame32768}
	framePool143360 = sync.Pool{New: newFrame143360}
)

// getFrameAtLeast 取一个容量 >= n 的池缓冲，并保证 len == cap == 分档尺寸。
// 固定数组指针进入 interface 时只是一个机器指针，不会像 []byte slice header
// 那样在每次 Pool.Put 时产生额外堆对象。
func getFrameAtLeast(n int) []byte {
	switch {
	case n <= 512:
		return framePool512.Get().(*[512]byte)[:]
	case n <= 1024:
		return framePool1024.Get().(*[1024]byte)[:]
	case n <= 2048:
		return framePool2048.Get().(*[2048]byte)[:]
	case n <= 4096:
		return framePool4096.Get().(*[4096]byte)[:]
	case n <= 8192:
		return framePool8192.Get().(*[8192]byte)[:]
	case n <= 16384:
		return framePool16384.Get().(*[16384]byte)[:]
	case n <= 32768:
		return framePool32768.Get().(*[32768]byte)[:]
	case n <= 143360:
		return framePool143360.Get().(*[143360]byte)[:]
	default:
		return make([]byte, n)
	}
}

// putFrame 只回收 cap 恰好命中分档的缓冲。把 slice 扩回完整容量后直接转换成
// 固定数组指针；转换不会复制 payload，也不会分配 wrapper。
func putFrame(b []byte) {
	if b == nil {
		return
	}
	switch cap(b) {
	case 512:
		framePool512.Put((*[512]byte)(b[:512]))
	case 1024:
		framePool1024.Put((*[1024]byte)(b[:1024]))
	case 2048:
		framePool2048.Put((*[2048]byte)(b[:2048]))
	case 4096:
		framePool4096.Put((*[4096]byte)(b[:4096]))
	case 8192:
		framePool8192.Put((*[8192]byte)(b[:8192]))
	case 16384:
		framePool16384.Put((*[16384]byte)(b[:16384]))
	case 32768:
		framePool32768.Put((*[32768]byte)(b[:32768]))
	case 143360:
		framePool143360.Put((*[143360]byte)(b[:143360]))
	}
}

// getFrame 取默认 2KB 分档。
func getFrame() []byte { return getFrameAtLeast(defaultFrameSize) }

// cloneFrame 深拷贝一帧负载（优先取池缓冲），供逐后端独立所有权使用
func cloneFrame(data []byte) []byte {
	if data == nil {
		return nil
	}
	buf := getFrame()
	if len(data) > cap(buf) {
		putFrame(buf)
		dst := make([]byte, len(data))
		copy(dst, data)
		return dst
	}
	dst := buf[:len(data)]
	copy(dst, data)
	return dst
}

// freeFrames 释放一批帧的缓冲（所有权归调用方时使用）
func freeFrames(batch []VPNFrame) {
	for i := range batch {
		if batch[i].Data != nil {
			putFrame(batch[i].Data)
			batch[i].Data = nil
		}
	}
}

// Go crypto/tls/uTLS 在大块 Write 内部仍拆 record；过大的单次 Write 会延长
// 单连接发送 goroutine 占用时间，反而损害多路公平性。保持 64KiB 上限，但仍
// 会把多个较小 backend batch 顺手合并到一次 Write。
const maxTLSWriteBatchBytes = 64 * 1024

// appendOwnedFrameBatch 把一个 backend batch 成帧进 sendBuffer，并终结该
// batch 的 payload/描述符所有权。返回帧数与其中填充字节数，供调用方在 Write
// 成功之后批量累加统计。
func appendOwnedFrameBatch(sendBuffer []byte, frames []VPNFrame, ic *innerCipher) ([]byte, int, uint64) {
	n := len(frames)
	var pad uint64
	for _, vf := range frames {
		var p int
		sendBuffer, p = appendPaddedFrame(sendBuffer, vf, ic)
		pad += uint64(p)
	}
	freeFrames(frames)
	putVPNFrameBatch(frames)
	return sendBuffer, n, pad
}

// ======================= 混淆填充策略 =======================
//
// 填充长度按配置选择，支持热更。入参统一为线路负载长度（明文长 + 加密标签长），
// 因为填充的唯一可见效果是改变线路上的总字节数。
//
//	off    不填充（吞吐优先）
//	bucket 把小帧填充到固定长度桶：线路长度分布固定，代价是开销随负载
//	反比上升——1B 负载的记录要补 117B 填充（占 128B 记录的九成），
//	近 1KB 负载才把填充压到个位数百分比。
//
// 历史上的 legacy 模式是小帧加 300-500B 随机填充（200-350% 的额外线路开销），
// 抗流量分析收益有限而带宽代价固定，已随旧协议兼容一并移除。
//
// 注意：填充本身不参与 GCM AAD（AAD 只绑定 [dataLen ‖ seq]），所以填充提供
// 的抗流量分析能力有限；bucket 模式用"固定长度分布"这一更强属性替代随机填充。
const (
	padModeOff    = "off"
	padModeBucket = "bucket"
)

// 发送路径按 int 码分派填充策略（Go 不允许比较函数值）
const (
	padCodeOff    = 0
	padCodeBucket = 1
)

// padBuckets 是完整线路记录（10B 头 + 密文/明文 + padding）的目标长度。
// 1600 覆盖完整 1514B Ethernet 帧、16B GCM tag 与 10B 帧头。
var padBuckets = []int{128, 256, 384, 512, 768, 1024, 1280, 1600, 2048, 4096}

var padModeCode atomic.Int32

// 进程启动时配置尚未加载，先按 bucket 起步：这是唯一的默认值，也保证配置
// 加载前后的填充行为一致，不会出现一段窗口按别的策略发包。
func init() { padModeCode.Store(padCodeBucket) }

// setPadMode 切换填充策略（非法值回落 bucket），返回实际生效的策略名。
// 策略真正变化时清零填充累计：两种策略的线路长度分布完全不同，混在一个
// 累计里会让"填充开销"既不代表旧策略也不代表新策略。
func setPadMode(mode string) string {
	actual := padModeBucket
	if mode == padModeOff {
		actual = padModeOff
	}
	if actual == padModeName() {
		return actual
	}
	padModeCode.Store(padCodeBucket)
	if actual == padModeOff {
		padModeCode.Store(padCodeOff)
	}
	padWireC.v.Store(0)
	padPadC.v.Store(0)
	return actual
}

func padModeName() string {
	if padModeCode.Load() == padCodeOff {
		return padModeOff
	}
	return padModeBucket
}

func currentPadLength(wireLen int) int {
	if padModeCode.Load() == padCodeOff {
		return 0
	}
	return padBucket(wireLen)
}

// padCounter 缓存行隔离的填充开销计数器。每条记录的线路字节与其中填充的字节
// 分置两条缓存行：多连接的发送 goroutine 并发累加时不会在同一行上锁乒乓。
// 两个累计都只在 Write 成功之后累加——写入失败或连接被掐掉的字节不计入。
type padCounter struct {
	v    atomic.Uint64
	_pad [56]byte
}

var (
	padWireC padCounter // 已发出记录的线路字节：10B 帧头 + 负载 + 填充
	padPadC  padCounter // 其中属于混淆填充的字节
)

// recordPadBytes 在 Write 成功之后调用，wire 是整包的线路字节数。
// pad=0（off 模式、或心跳等空帧被调用方跳过）时完全不写计数器，因此 off
// 模式下这条路径与未引入统计前一样热。
func recordPadBytes(wire, pad uint64) {
	if pad == 0 {
		return
	}
	padWireC.v.Add(wire)
	padPadC.v.Add(pad)
}

func padStatsSnapshot() (wire, pad uint64) {
	return padWireC.v.Load(), padPadC.v.Load()
}

// padBucket 小帧填充到固定桶；超出最大桶的大帧（jumbo）只加小额随机填充，
// 避免为抗流量分析付出过大带宽代价。
func padBucket(wireLen int) int {
	recordLen := 10 + wireLen
	for _, b := range padBuckets {
		// 使用严格小于保证 bucket 模式的每条记录都有非零 padding；off 是
		// 唯一允许零填充的模式，测试和运维语义不再含糊。
		if recordLen < b {
			return b - recordLen
		}
	}
	return 1 + mathrand.IntN(100)
}

// appendPaddedFrame 10 字节头部 [4B len][2B padLen][4B seq]
//
// ic 为内层加密器：nil 表示明文；seq=0 的控制/握手帧恒不加密（协议约定，
// 接收端以此区分校验帧与握手帧）。GCM 模式密文后附 16B 标签，线路
// dataLen = 明文长 + tagLen；ic.tagLen() 用于一次性预留缓冲，避免中途扩容。
// 返回实际写入的填充字节数：记账由调用方在 Write 成功之后做，写入失败的字节
// 不能算进填充开销。
func appendPaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) ([]byte, int) {
	dataLen := len(vf.Data)
	encTag := 0
	if ic != nil && vf.Seq != 0 && dataLen > 0 {
		encTag = ic.tagLen()
	}
	wireLen := dataLen + encTag
	padLen := currentPadLength(wireLen)

	// 1. 一次性算出需要的整包新增长度
	needed := 10 + wireLen + padLen
	startIdx := len(buf)

	// 2. 检查容量，不够则一次性扩容，防多次 append 扩容崩溃
	if cap(buf)-startIdx < needed {
		newCap := cap(buf) * 2
		if newCap < startIdx+needed {
			newCap = startIdx + needed
		}
		newBuf := make([]byte, startIdx, newCap)
		copy(newBuf, buf)
		buf = newBuf
	}

	// 改变 slice 的长度属性
	buf = buf[:startIdx+needed]

	// 3. 原址绝对下标写入头信息（dataLen 为线路负载长度，含 GCM 标签）
	binary.BigEndian.PutUint32(buf[startIdx:startIdx+4], uint32(wireLen))
	binary.BigEndian.PutUint16(buf[startIdx+4:startIdx+6], uint16(padLen))
	binary.BigEndian.PutUint32(buf[startIdx+6:startIdx+10], vf.Seq)

	// 4. 拷贝数据负载并加密
	if dataLen > 0 {
		payloadStart := startIdx + 10
		copy(buf[payloadStart:payloadStart+dataLen], vf.Data)

		if ic != nil && vf.Seq != 0 {
			ic.sealInPlace(buf[payloadStart:payloadStart+wireLen], dataLen, vf.Seq, uint32(wireLen))
		}
	}

	// 5. 填补混淆填充
	if padLen > 0 {
		padStart := startIdx + 10 + wireLen
		offset := mathrand.IntN(RandomPoolSize - padLen)
		copy(buf[padStart:padStart+padLen], randomPool[offset:offset+padLen])
	}

	return buf, padLen
}

// writeStreamFrame 发送无需去重的控制帧
func writeStreamFrame(w io.Writer, frame []byte) error {
	streamBuf := getFrame()[:0]
	streamBuf, pad := appendPaddedFrame(streamBuf, VPNFrame{Seq: 0, Data: frame}, nil)
	_, err := w.Write(streamBuf)
	if err == nil {
		recordPadBytes(uint64(len(streamBuf)), uint64(pad))
	}
	putFrame(streamBuf[:cap(streamBuf)])
	return err
}

func generatePadding(min, max int) string {
	length := mathrand.IntN(max-min+1) + min
	offset := mathrand.IntN(RandomPoolSize - length)
	return hex.EncodeToString(randomPool[offset : offset+length])
}

// ======================= 流式帧扫描器 (读取 10 字节头) =======================

const (
	// maxWireDataLen 数据帧线路负载上限（帧头 4B 长度字段的合法性边界）
	maxWireDataLen = 65535 * 2
	// maxHandshakeDataLen 认证前首帧上限。合法握手 JSON < 2KB；不设限的话
	// 攻击者用 10 字节帧头声明 131070 长度即可把扫描缓冲扩到 131KB/连接，
	// 预认证并发连接无上限，构成内存放大。
	maxHandshakeDataLen = 16 * 1024
)

type FrameScanner struct {
	r      io.Reader
	buf    []byte
	offset int
	// maxDataLen 当前允许的帧负载上限：认证前的握手帧用小上限，认证通过后
	// 恢复线路全量上限（见 SetMaxDataLen）。
	maxDataLen int
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	// 初始缓冲 16KB 覆盖典型 MTU 帧的聚合；大帧按需翻倍增长。旧值 70KB 对
	// 1.5KB 帧是 45 倍冗余，多连接下白占内存并放大 GC 扫描。
	return &FrameScanner{r: r, buf: make([]byte, 0, maxHandshakeDataLen), maxDataLen: maxWireDataLen}
}

// SetMaxDataLen 调整帧负载上限（认证前收紧、认证后放开的配对使用）
func (fs *FrameScanner) SetMaxDataLen(n int) { fs.maxDataLen = n }

func (fs *FrameScanner) ReadFrame() ([]byte, uint32, error) {
	const HeaderSize = 10

	for {
		available := len(fs.buf) - fs.offset

		if available >= HeaderSize {
			rawDataLen := binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4])
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			seq := binary.BigEndian.Uint32(fs.buf[fs.offset+6 : fs.offset+10])

			if uint64(rawDataLen) > uint64(fs.maxDataLen) {
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, 0, fmt.Errorf("invalid frame data length: %d", rawDataLen)
			}
			dataLen := int(rawDataLen)
			totalLen := dataLen + padLen

			if available >= HeaderSize+totalLen {
				if dataLen == 0 {
					// 心跳/控制帧：返回给调用方（frame=nil），用于刷新读超时。
					// 旧实现在此静默跳过，导致空闲隧道的 30 秒读超时永不刷新、
					// 每 30 秒被误杀重连一次。
					fs.offset += HeaderSize + totalLen
					return nil, seq, nil
				}

				// 直接按所需长度取 size-class 缓冲。旧路径先拿 2KB，再对
				// jumbo frame 走 make([]byte, dataLen)，绕开了现成的大档内存池。
				frame := getFrameAtLeast(dataLen)[:dataLen]
				copy(frame, fs.buf[fs.offset+HeaderSize:fs.offset+HeaderSize+dataLen])
				fs.offset += HeaderSize + totalLen
				return frame, seq, nil
			}
		}

		if fs.offset > 0 && (fs.offset == len(fs.buf) || fs.offset > 16384) {
			remaining := len(fs.buf) - fs.offset
			if remaining > 0 {
				copy(fs.buf, fs.buf[fs.offset:])
			}
			fs.buf = fs.buf[:remaining]
			fs.offset = 0
		}

		tailStart := len(fs.buf)
		requiredCap := tailStart + 2048

		available = len(fs.buf) - fs.offset
		if available >= HeaderSize {
			rawDataLen := binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4])
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			if uint64(rawDataLen) > uint64(fs.maxDataLen) {
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, 0, fmt.Errorf("invalid frame data length: %d", rawDataLen)
			}
			frameCap := uint64(fs.offset) + HeaderSize + uint64(rawDataLen) + uint64(padLen)
			if frameCap > uint64(requiredCap) {
				requiredCap = int(frameCap)
			}
		}

		if cap(fs.buf) < requiredCap {
			newCap := cap(fs.buf) * 2
			if newCap < requiredCap {
				newCap = requiredCap
			}
			newBuf := make([]byte, len(fs.buf), newCap)
			copy(newBuf, fs.buf)
			fs.buf = newBuf
		}

		fs.buf = fs.buf[:cap(fs.buf)]
		n, err := fs.r.Read(fs.buf[tailStart:])
		fs.buf = fs.buf[:tailStart+n]

		if err != nil {
			if n == 0 || (err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection")) {
				return nil, 0, err
			}
		}
	}
}

// ======================= 协议结构 =======================
type HandshakeReq struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	ClientInstance  string `json:"client_instance,omitempty"`
	ClientID        string `json:"client_id"`
	PSK             string `json:"psk"`
	MAC             string `json:"mac,omitempty"`
	IPv4            string `json:"ipv4,omitempty"`
	IPv6            string `json:"ipv6,omitempty"`
	Padding         string `json:"padding,omitempty"`
	// BrutalGroups advertises total-rate/group semantics: the peer wants one
	// kernel traffic-control group shared across all connections, so the
	// aggregate is split per connection locally.
	BrutalGroups    bool   `json:"brutal_groups,omitempty"`
	BrutalTotalTx   uint64 `json:"brutal_total_tx,omitempty"`
	BrutalTotalRx   uint64 `json:"brutal_total_rx,omitempty"`
	BrutalConns     int    `json:"brutal_conns,omitempty"`
	BrutalConnIndex int    `json:"brutal_conn_index,omitempty"`
	FEC             bool   `json:"fec,omitempty"`
	FecGroup        int    `json:"fec_group,omitempty"`
	Encrypt         bool   `json:"encrypt,omitempty"`
	// EncAlgo：本端声明的内层加密算法（none / AES-256-GCM / AES-128-GCM）。
	// 服务端要求与配置完全相等，不做隐式降级。
	EncAlgo int `json:"enc_algo,omitempty"`
	// SessionToken：客户端回带上一次收到的会话令牌（hex）。
	// 服务端开启 session_token 时，重连既有会话必须携带正确令牌，
	// 仅持有共享 PSK 的第三方无法冒充既有会话（见 computeSessionToken）。
	SessionToken string `json:"session_token,omitempty"`
}

type MacBinding struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type HandshakeResp struct {
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	SessionEpoch    uint64 `json:"session_epoch,omitempty"`
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	SessionID       string `json:"session_id,omitempty"`
	ClientID        string `json:"client_id"`
	IPv4            string `json:"ipv4"`
	IPv6            string `json:"ipv6"`
	GwV4            string `json:"gw_v4,omitempty"`
	GwV6            string `json:"gw_v6,omitempty"`
	Padding         string `json:"padding,omitempty"`
	BrutalGroups    bool   `json:"brutal_groups,omitempty"`
	BrutalTotalTx   uint64 `json:"brutal_total_tx,omitempty"`
	BrutalTotalRx   uint64 `json:"brutal_total_rx,omitempty"`
	FEC             bool   `json:"fec,omitempty"`
	FecGroup        int    `json:"fec_group,omitempty"`
	Encrypt         bool   `json:"encrypt,omitempty"`
	// EncAlgo：协商选定的算法（0=无内层加密，2=AES-256-GCM，4=AES-128-GCM）。
	// 为 GCM 时 EncSalt 为 c2s 方向盐（客户端加密/服务端解密），
	// EncSalt2 为 s2c 方向盐（服务端加密/客户端解密）。
	EncAlgo  int    `json:"enc_algo,omitempty"`
	EncSalt  string `json:"enc_salt,omitempty"`  // hex(8B)：客户端→服务端方向
	EncSalt2 string `json:"enc_salt2,omitempty"` // hex(8B)：服务端→客户端方向
	// SessionToken：本次会话的重连接入令牌（hex），客户端须在下一次握手回带。
	// 仅在服务端开启 session_token 时下发。
	SessionToken string `json:"session_token,omitempty"`
	// TLS 是服务端实际观测到的 ClientHello 与最终协商摘要。新增客户端接受
	// 字段缺失，旧客户端会忽略该可选字段，支持滚动升级与回滚。
	TLS *TLSHandshakeInfo `json:"tls,omitempty"`
}

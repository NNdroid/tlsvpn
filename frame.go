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

// framePoolSizes 帧缓冲尺寸分档。旧实现只有单一 32KB 缓冲，对典型 1500B
// 以太网帧利用率约 5%：整页被标脏、放大 cache 行污染，并让 GC 扫描更大的
// 可达对象图。按尺寸分档后每档都被真正写满。
var framePoolSizes = []int{512, 1024, 2048, 4096, 8192, 16384, 32768, 143360}

// defaultFrameSize getFrame() 默认分档。1500 字节以太网帧（含 14B 以太头）
// 是 cloneFrame / FrameScanner 的绝对主流量，必须落在池内分档；若默认档太小，
// 这两条热路径会每帧走一次 cap 不足分支并直接分配，池形同虚设。
const defaultFrameSize = 2048

// framePools 每个尺寸一档的缓冲池
type framePools struct {
	sizes []int
	pools []*sync.Pool
}

func newFramePools(sizes []int) *framePools {
	p := &framePools{sizes: sizes}
	p.pools = make([]*sync.Pool, len(sizes))
	for i, s := range sizes {
		s := s
		p.pools[i] = &sync.Pool{New: func() any { return make([]byte, s) }}
	}
	return p
}

// getFrameAtLeast 取一个 cap >= n 的池缓冲。
//
// 尺寸严格匹配分档（putFrame 只回收 cap 恰好等于某档的缓冲），因此这里
// 拿到的缓冲容量必然 >= n，不会发生 slice 越界。无合适分档（n 超过最大档）
// 时直接分配，不入池。
func (p *framePools) getFrameAtLeast(n int) []byte {
	for i, s := range p.sizes {
		if s >= n {
			b := p.pools[i].Get().([]byte)
			if cap(b) == s {
				return b
			}
			putFrame(b) // 理论上不可达：尺寸已被 putFrame 约束
			return make([]byte, s)
		}
	}
	return make([]byte, n)
}

// putFrame 归还缓冲。只回收 cap 恰好命中某档的缓冲，保证每档内容同尺寸
// （否则 getFrameAtLeast 可能反复 miss 同一块偏小缓冲）；其余交给 GC。
func (p *framePools) putFrame(b []byte) {
	if b == nil {
		return
	}
	switch c := cap(b); {
	case c <= 0:
		return
	default:
		for i, s := range p.sizes {
			if c == s {
				p.pools[i].Put(b)
				return
			}
		}
	}
}

var framePoolSet = newFramePools(framePoolSizes)

// getFrame 取默认分档缓冲（调用方随后会自行检查容量）
func getFrame() []byte { return framePoolSet.getFrameAtLeast(defaultFrameSize) }

// getFrameAtLeast 取一个 cap >= n 的池缓冲，避免 N > 池容量时的越界崩溃
func getFrameAtLeast(n int) []byte { return framePoolSet.getFrameAtLeast(n) }

func putFrame(b []byte) { framePoolSet.putFrame(b) }

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

// ======================= 混淆填充策略 =======================
//
// 填充长度按配置选择，支持热更。入参统一为线路负载长度（明文长 + 加密标签长），
// 因为填充的唯一可见效果是改变线路上的总字节数。
//
//	off    不填充（吞吐优先）
//	legacy 旧的随机填充：小帧加 300-500B，即 200-350% 的额外线路开销
//	bucket 填充到固定长度桶：小帧开销降到 <30%，且线路长度分布固定
//
// 注意：填充本身不参与 GCM AAD（AAD 只绑定 [dataLen ‖ seq]），所以填充提供
// 的抗流量分析能力有限；bucket 模式用"固定长度分布"这一更强属性替代随机填充。
const (
	padModeOff    = "off"
	padModeLegacy = "legacy"
	padModeBucket = "bucket"
)

// 发送路径按 int 码分派填充策略（Go 不允许比较函数值）
const (
	padCodeOff    = 0
	padCodeLegacy = 1
	padCodeBucket = 2
)

// padBuckets 小帧填充目标桶（覆盖常见 MTU 1500 的帧及其含标签长度）
var padBuckets = []int{128, 256, 384, 512, 768, 1024, 1280, 1514}

var padModeCode atomic.Int32

func init() { padModeCode.Store(padCodeLegacy) }

// setPadMode 切换填充策略（非法值回落 legacy），返回实际生效的策略名
func setPadMode(mode string) string {
	switch mode {
	case padModeOff:
		padModeCode.Store(padCodeOff)
	case padModeBucket:
		padModeCode.Store(padCodeBucket)
	default:
		padModeCode.Store(padCodeLegacy)
		return padModeLegacy
	}
	return mode
}

func padModeName() string {
	switch padModeCode.Load() {
	case padCodeOff:
		return padModeOff
	case padCodeBucket:
		return padModeBucket
	default:
		return padModeLegacy
	}
}

func currentPadLength(wireLen int) int {
	switch padModeCode.Load() {
	case padCodeOff:
		return 0
	case padCodeBucket:
		return padBucket(wireLen)
	default:
		return padLegacy(wireLen)
	}
}

// padLegacy 旧的随机填充（阈值语义与旧实现一致，入参改为线路长度）
func padLegacy(wireLen int) int {
	if wireLen == 0 {
		return 100 + mathrand.IntN(201)
	}
	if wireLen < 200 {
		return 300 + mathrand.IntN(200)
	}
	if wireLen < 800 {
		return 100 + mathrand.IntN(200)
	}
	return mathrand.IntN(100)
}

// padBucket 小帧填充到固定桶；超出最大桶的大帧（jumbo）只加小额随机填充，
// 避免为抗流量分析付出过大带宽代价。
func padBucket(wireLen int) int {
	if wireLen <= 0 {
		return 0
	}
	for _, b := range padBuckets {
		if wireLen <= b {
			return b - wireLen
		}
	}
	return mathrand.IntN(100)
}

// appendPaddedFrame 10 字节头部 [4B len][2B padLen][4B seq]
//
// ic 为内层加密器：nil 表示明文；seq=0 的控制/握手帧恒不加密（协议约定，
// 接收端以此区分校验帧与握手帧）。GCM 模式密文后附 16B 标签，线路
// dataLen = 明文长 + tagLen；ic.tagLen() 用于一次性预留缓冲，避免中途扩容。
func appendPaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) []byte {
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

	return buf
}

// writeStreamFrame 发送无需去重的控制帧
func writeStreamFrame(w io.Writer, frame []byte) error {
	streamBuf := getFrame()[:0]
	streamBuf = appendPaddedFrame(streamBuf, VPNFrame{Seq: 0, Data: frame}, nil)
	_, err := w.Write(streamBuf)
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
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			seq := binary.BigEndian.Uint32(fs.buf[fs.offset+6 : fs.offset+10])
			totalLen := dataLen + padLen

			if dataLen > fs.maxDataLen {
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, 0, fmt.Errorf("invalid frame data length: %d", dataLen)
			}

			if available >= HeaderSize+totalLen {
				if dataLen == 0 {
					// 心跳/控制帧：返回给调用方（frame=nil），用于刷新读超时。
					// 旧实现在此静默跳过，导致空闲隧道的 30 秒读超时永不刷新、
					// 每 30 秒被误杀重连一次。
					fs.offset += HeaderSize + totalLen
					return nil, seq, nil
				}

				var frame []byte
				temp := getFrame()
				if dataLen > cap(temp) {
					putFrame(temp)
					frame = make([]byte, dataLen)
				} else {
					frame = temp[:dataLen]
				}

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
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			if fs.offset+HeaderSize+dataLen+padLen > requiredCap {
				requiredCap = fs.offset + HeaderSize + dataLen + padLen
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
	ClientID string `json:"client_id"`
	PSK      string `json:"psk"`
	MAC      string `json:"mac,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"`
	BrutalRx uint64 `json:"brutal_rx,omitempty"`
	FEC      bool   `json:"fec,omitempty"`
	FecGroup int    `json:"fec_group,omitempty"`
	Encrypt  bool   `json:"encrypt,omitempty"`
	// EncAlgo：本端支持的最高内层加密算法（位集，bit1=GCM）。
	// 旧版 Go/Rust 不发送本字段 → 0（legacy CTR）。
	EncAlgo int `json:"enc_algo,omitempty"`
	// SessionToken：客户端回带上一次收到的会话令牌（hex）。
	// 服务端开启 session_token 时，重连既有会话必须携带正确令牌，
	// 仅持有共享 PSK 的第三方无法冒充既有会话（见 computeSessionToken）。
	// 旧版实现不发送本字段 → 空串，配合服务端开关向后兼容。
	SessionToken string `json:"session_token,omitempty"`
}

type MacBinding struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type HandshakeResp struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	GwV4      string `json:"gw_v4,omitempty"`
	GwV6      string `json:"gw_v6,omitempty"`
	Padding   string `json:"padding,omitempty"`
	BrutalTx  uint64 `json:"brutal_tx,omitempty"`
	BrutalRx  uint64 `json:"brutal_rx,omitempty"`
	FEC       bool   `json:"fec,omitempty"`
	FecGroup  int    `json:"fec_group,omitempty"`
	Encrypt   bool   `json:"encrypt,omitempty"`
	// EncAlgo：协商选定的算法（0=legacy CTR，2=GCM）。仅当双方都支持
	// GCM 时为 2；此时 EncSalt 为 c2s 方向盐（客户端加密/服务端解密），
	// EncSalt2 为 s2c 方向盐（服务端加密/客户端解密）。
	EncAlgo  int    `json:"enc_algo,omitempty"`
	EncSalt  string `json:"enc_salt,omitempty"`  // hex(8B)：客户端→服务端方向
	EncSalt2 string `json:"enc_salt2,omitempty"` // hex(8B)：服务端→客户端方向
	// SessionToken：本次会话的重连接入令牌（hex），客户端须在下一次握手回带。
	// 仅在服务端开启 session_token 时下发；旧服务端不下发 → 空串。
	SessionToken string `json:"session_token,omitempty"`
}

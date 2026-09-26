package main

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// ======================= VSwitch =======================
type Port interface {
	ID() string
	WriteFrame(frame []byte) error
}

// macKey 是 6 字节 MAC 的定长数组形式。作为 map key 时零堆分配，
// 旧实现每帧两次 string([]byte) 转换，每次都会分配并保留一份副本。
type macKey [6]byte

type macEntry struct {
	portID      string
	port        Port // 已学习目标端口；命中单播时省掉第二次 ports map/RWMutex 查找
	updatedTick uint64
	static      bool // session 注册 MAC：随端口生命周期存在，不做动态 refresh/老化
}

const ShardCount = 16

// tapPortID 本机 TAP 在交换机上的端口名（网关侧，可信：豁免源 MAC 校验
// 与广播限速）
const tapPortID = "TAP_LOCAL"

type VSwitchShard struct {
	mu       sync.RWMutex
	macTable map[macKey]*macEntry
}
type VSwitch struct {
	portsMu sync.RWMutex
	ports   map[string]Port
	shards  [ShardCount]*VSwitchShard

	// coarseSec 是 VSwitch 自己的单调粗时钟（约 1 秒粒度）。MAC 学习热路径
	// 每帧只 atomic.Load，不再调用 time.Now/time.Since。时钟调度延迟只会让
	// MAC 项稍晚刷新/过期，不会提前误删。
	coarseSec atomic.Uint64

	// validateMAC 源 MAC 归属校验（可 nil = 不过滤）。共享 PSK 的多客户端
	// 场景下，恶意客户端可以声明他人的 srcMAC 把受害者的 MAC 表项学习到
	// 自己的端口，劫持其下行单播流量。校验函数由服务端注入：会话端口只允许
	// 声明本会话注册的 MAC，可信端口（本机 TAP）豁免。
	validateMAC func(srcPortID string, mac macKey) bool
	trustedPort string // 豁免源 MAC 校验与广播限速的端口（本机 TAP）
	spoofDrops  atomic.Uint64

	// 广播/未知单播洪泛的每端口令牌桶：恶意客户端可以线速广播，洪泛会被
	// 复制到所有端口放大 N 倍。合法 ARP/mDNS 远低于该预算；超预算的广播帧
	// 直接丢弃（单播不受影响）。
	floodMu         sync.Mutex
	floodBudgets    map[string]*floodBudget
	floodBurst      float64 // 桶容量（突发预算）
	floodRatePerSec float64 // 每秒补充令牌数
	floodDrops      atomic.Uint64
}

type floodBudget struct {
	tokens float64
	last   time.Time
}

func NewVSwitch() *VSwitch {
	vs := &VSwitch{
		ports:        make(map[string]Port),
		floodBudgets: make(map[string]*floodBudget),
		// 默认预算覆盖 ~180 Mbps 的纯洪泛流量（1400B 帧）且从不误伤学习后
		// 的单播；线速广播攻击（10万+ fps）仍被削掉 90% 以上。
		floodBurst:      8192,
		floodRatePerSec: 16384,
	}
	for i := 0; i < ShardCount; i++ {
		vs.shards[i] = &VSwitchShard{macTable: make(map[macKey]*macEntry)}
	}
	vs.coarseSec.Store(1)
	go vs.runCoarseClockAndPurge()
	return vs
}

// 快速字符串 Hash
func getShardIdx(mac macKey) int {
	var hash uint32 = 2166136261
	for i := 0; i < len(mac); i++ {
		hash *= 16777619
		hash ^= uint32(mac[i])
	}
	return int(hash % ShardCount)
}
func (vs *VSwitch) runCoarseClockAndPurge() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var purgeTicks uint32
	for range ticker.C {
		now := vs.coarseSec.Add(1)
		purgeTicks++
		if purgeTicks < 300 {
			continue
		}
		purgeTicks = 0
		vs.purgeExpiredMACsAt(now)
	}
}

func (vs *VSwitch) purgeExpiredMACsAt(now uint64) {
	const maxAgeSec = uint64((30 * time.Minute) / time.Second)
	for i := 0; i < ShardCount; i++ {
		shard := vs.shards[i]
		shard.mu.Lock()
		for mac, entry := range shard.macTable {
			if !entry.static && now-entry.updatedTick > maxAgeSec {
				delete(shard.macTable, mac)
			}
		}
		shard.mu.Unlock()
	}
}
func (vs *VSwitch) AddPort(p Port) {
	vs.portsMu.Lock()
	vs.ports[p.ID()] = p
	vs.portsMu.Unlock()
	log.Debugf("[VSwitch] Port UP: %s", p.ID())
}

// AddStaticMAC 把已认证 session 的注册 MAC 一次性固定到端口。该映射的
// 生命周期与 Port 一致，因此数据热路径无需每帧重新学习/刷新，也无需调用
// Server.validateSrcMAC 获取 activeClients 读锁。
func (vs *VSwitch) AddStaticMAC(portID string, mac macKey) {
	if mac == (macKey{}) {
		return
	}
	// 与 RemovePort 保持 portsMu -> shard 的统一锁顺序。持 portsMu.RLock
	// 到 entry 安装完成，保证缓存的 Port 不会在安装过程中被摘除/关闭。
	vs.portsMu.RLock()
	port := vs.ports[portID]
	shard := vs.shards[getShardIdx(mac)]
	shard.mu.Lock()
	shard.macTable[mac] = &macEntry{portID: portID, port: port, static: true}
	shard.mu.Unlock()
	vs.portsMu.RUnlock()
}

func (vs *VSwitch) RemovePort(portID string) {
	vs.portsMu.Lock()
	delete(vs.ports, portID)
	vs.portsMu.Unlock()

	// 回收广播预算槽位，防长期运行下 map 无限增长
	vs.floodMu.Lock()
	delete(vs.floodBudgets, portID)
	vs.floodMu.Unlock()

	// 清理分片表里的 MAC
	for i := 0; i < ShardCount; i++ {
		shard := vs.shards[i]
		shard.mu.Lock()
		for mac, entry := range shard.macTable {
			if entry.portID == portID {
				delete(shard.macTable, mac)
			}
		}
		shard.mu.Unlock()
	}
	log.Debugf("[VSwitch] Port DOWN: %s", portID)
}
func (vs *VSwitch) ProcessFrame(srcPortID string, frame []byte) {
	vs.processFrame(srcPortID, frame, false, nil)
}

// ProcessSessionFrame 是已认证 session 的热路径。registeredMAC 在握手期已经
// 固定并通过 AddStaticMAC 写入交换表，因此这里只做定长比较；不再每包获取
// src shard 与 Server.activeClients 的读锁。
func (vs *VSwitch) ProcessSessionFrame(srcPortID string, registeredMAC macKey, frame []byte) {
	vs.processFrame(srcPortID, frame, false, &registeredMAC)
}

// ProcessOwnedFrame 接管 frame 所有权。单播命中 AsyncPort 时直接把池缓冲转交
// 给目标端口；广播/未知单播仍按现有 copy-to-many 语义发送，最后归还原 buffer。
func (vs *VSwitch) ProcessOwnedFrame(srcPortID string, frame []byte) {
	vs.processFrame(srcPortID, frame, true, nil)
}

func (vs *VSwitch) processFrame(srcPortID string, frame []byte, owned bool, registeredMAC *macKey) {
	if owned {
		defer func() {
			if owned {
				putFrame(frame)
			}
		}()
	}
	if len(frame) < 14 {
		return
	}
	var dstMAC, srcMAC macKey
	copy(dstMAC[:], frame[0:6])
	copy(srcMAC[:], frame[6:12])

	if registeredMAC != nil && *registeredMAC != (macKey{}) {
		// 已认证 session：注册 MAC 是握手状态的一部分，映射已由 AddStaticMAC
		// 固定。热路径只比较 6 字节，冒充帧直接丢弃。
		if srcMAC != *registeredMAC {
			vs.spoofDrops.Add(1)
			return
		}
	} else {
		// TAP / 未上报 MAC 的兼容客户端继续动态学习。
		srcShard := vs.shards[getShardIdx(srcMAC)]
		nowTick := vs.coarseSec.Load()
		srcShard.mu.RLock()
		entry, exists := srcShard.macTable[srcMAC]
		staticElsewhere := exists && entry.static && entry.portID != srcPortID
		needUpdate := !exists || (!entry.static && (entry.portID != srcPortID || nowTick-entry.updatedTick > 5))
		srcShard.mu.RUnlock()

		// 已认证 session 的 MAC 映射不可被其它动态学习端口覆盖。
		// legacy/no-MAC session 仍可学习自己的 MAC，但不能借此劫持已固定映射。
		// 本机 TAP 是可信端口：允许它携带该源 MAC 继续转发，但不修改 static entry。
		if staticElsewhere {
			if srcPortID != vs.trustedPort {
				vs.spoofDrops.Add(1)
				return
			}
			needUpdate = false
		}

		if needUpdate {
			if vs.validateMAC != nil && !vs.validateMAC(srcPortID, srcMAC) {
				vs.spoofDrops.Add(1)
				return
			}

			// 统一 portsMu -> shard 锁顺序，避免学习到一个正被 RemovePort 摘除的
			// stale Port。未注册的测试/兼容端口允许 port=nil，转发时回退旧 lookup。
			vs.portsMu.RLock()
			learnedPort := vs.ports[srcPortID]
			updated := false
			srcShard.mu.Lock()
			if current := srcShard.macTable[srcMAC]; current != nil {
				// 锁外检查到锁内之间可能新建了 static entry；再次保护，避免竞态覆盖。
				if current.static && current.portID != srcPortID {
					srcShard.mu.Unlock()
					vs.portsMu.RUnlock()
					if srcPortID != vs.trustedPort {
						vs.spoofDrops.Add(1)
						return
					}
				} else {
					current.portID = srcPortID
					current.port = learnedPort
					current.updatedTick = nowTick
					updated = true
					srcShard.mu.Unlock()
					vs.portsMu.RUnlock()
				}
			} else {
				srcShard.macTable[srcMAC] = &macEntry{portID: srcPortID, port: learnedPort, updatedTick: nowTick}
				updated = true
				srcShard.mu.Unlock()
				vs.portsMu.RUnlock()
			}
			if updated {
				log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC), srcPortID)
			}
		}
	}

	var targetPortID string
	if (dstMAC[0] & 1) != 1 { // 单播包
		dstShard := vs.shards[getShardIdx(dstMAC)]
		dstShard.mu.RLock()
		if dEntry, dExists := dstShard.macTable[dstMAC]; dExists {
			targetPortID = dEntry.portID
			if targetPortID != "" && targetPortID != srcPortID && dEntry.port != nil {
				// WriteFrame/WriteOwnedFrame 对 AsyncPort 都是有界非阻塞入队。
				// 在 shard RLock 内完成发送，RemovePort 必须等本次发送结束才能
				// 删除 entry，随后才会关闭 session.Port，因此不会命中 stale Port。
				if owned {
					if op, ok := dEntry.port.(interface{ WriteOwnedFrame([]byte) error }); ok {
						_ = op.WriteOwnedFrame(frame)
						owned = false
						dstShard.mu.RUnlock()
						return
					}
				}
				_ = dEntry.port.WriteFrame(frame)
				dstShard.mu.RUnlock()
				return
			}
		}
		dstShard.mu.RUnlock()
	}

	// 只有历史/测试 entry 没缓存 Port 时才回退旧的 ports map 查找。
	if targetPortID != "" && targetPortID != srcPortID {
		if owned && vs.sendOwnedToPort(targetPortID, frame) {
			owned = false
			return
		}
		vs.sendToPort(targetPortID, frame)
	} else if targetPortID == "" {
		vs.flood(srcPortID, frame)
	}
}

func (vs *VSwitch) sendOwnedToPort(targetPortID string, frame []byte) bool {
	vs.portsMu.RLock()
	port, exists := vs.ports[targetPortID]
	vs.portsMu.RUnlock()
	if !exists {
		return false
	}
	if owned, ok := port.(interface{ WriteOwnedFrame([]byte) error }); ok {
		_ = owned.WriteOwnedFrame(frame)
		return true
	}
	return false
}

func (vs *VSwitch) sendToPort(targetPortID string, frame []byte) {
	vs.portsMu.RLock()
	port, exists := vs.ports[targetPortID]
	vs.portsMu.RUnlock()
	if exists {
		port.WriteFrame(frame)
	}
}
func (vs *VSwitch) flood(excludePortID string, frame []byte) {
	// 每源端口广播预算：超预算直接整帧丢弃。可信端口（本机 TAP）豁免——
	// 网关自己发起的广播不受限。
	if excludePortID != vs.trustedPort && !vs.allowFlood(excludePortID) {
		vs.floodDrops.Add(1)
		return
	}
	// WriteFrame 是非阻塞入队；直接在读锁下遍历，避免每个广播/未知单播
	// 为 targets []Port 分配临时切片。Add/RemovePort 是冷路径，可接受短暂等待。
	vs.portsMu.RLock()
	for id, port := range vs.ports {
		if id != excludePortID {
			_ = port.WriteFrame(frame)
		}
	}
	vs.portsMu.RUnlock()
}

// allowFlood 消耗一个广播令牌；令牌按时间线性回充，容量 floodBurst。
// 首次为端口建桶时即消耗一枚（桶满意味着"从此刻起还有 burst 枚预算"）。
func (vs *VSwitch) allowFlood(srcPortID string) bool {
	vs.floodMu.Lock()
	defer vs.floodMu.Unlock()
	now := time.Now()
	b := vs.floodBudgets[srcPortID]
	if b == nil {
		vs.floodBudgets[srcPortID] = &floodBudget{tokens: vs.floodBurst - 1, last: now}
		return true
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(vs.floodBurst, b.tokens+elapsed*vs.floodRatePerSec)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ======================= 服务端 =======================
type ClientSession struct {
	SessionID          string
	Port               *AsyncPort
	IPv4               string
	IPv6               string
	MAC                string
	macBin             macKey // 会话注册 MAC 的二进制形式，VSwitch 源 MAC 归属校验用
	RxReorder          *ReorderBuffer
	FecDec             *fecDecoder       // XOR 奇偶校验解码器（req.FecGroup >= 2 时启用）
	FecEncK            int               // 下行 XOR 分组大小（0 表示未启用）
	FecMode            string            // 面板展示：xor K=d / off
	EncAlgo            int               // 内层加密算法号（none / AES-256-GCM / AES-128-GCM）
	Encrypt            bool              // 建会话时 encrypt 的取值；仅用于面板展示，enc_algo 已足够区分
	SaltA              [encSaltSize]byte // c2s 方向盐（客户端加密/服务端解密）
	SaltB              [encSaltSize]byte // s2c 方向盐（服务端加密/客户端解密）
	icTx               *innerCipher      // s2c 加密器
	icRx               *innerCipher      // c2s 解密器
	pskHash            string            // 创建本会话时的 hashPSK（见 handleConnection 复活分支）
	InstanceID         string            // 客户端进程实例；变化时必须切换密钥代际
	Epoch              uint64            // 当前密钥代际
	ResumeToken        string            // 当前已确认的 CSPRNG 会话持有证明
	PendingResumeToken string            // 两阶段 rollover：先下发、客户端回带后再正式替换 ResumeToken
	CreatedAt          time.Time
	ActiveConns        int
	TxBytes            uint64
	RxBytes            uint64
	TxPackets          uint64
	RxPackets          uint64
	// 会话保活与生命周期控制
	sessionMu    sync.RWMutex
	destroyTimer *time.Timer
	// 该会话的物理连接注册表：Web 面板踢出时逐个关闭，并输出连接明细
	connsMu sync.Mutex
	conns   map[*connInfo]struct{}
}

// connInfo 单条物理连接的运行明细（面板展示 + kick 关闭句柄）
type connInfo struct {
	remote    string
	tcpConn   *net.TCPConn
	rttCache  *uint32 // 微秒（200ms 刷新）
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	brutal    atomic.Pointer[brutalApplyResult] // 内核实际状态；nil=尚未尝试
	linkedAt  int64                             // 建立时间（unix 秒）
	brutalTx  uint64
	brutalRx  uint64
	epoch     uint64
	tls       *TLSHandshakeInfo // 本连接握手观测摘要（SNI/版本/套件，面板展示用）
}

type Server struct {
	psk        string
	v4Net      *net.IPNet
	v6Net      *net.IPNet
	v4Gw       string
	v6Gw       string
	usedV4     map[string]bool
	usedV6     map[string]bool
	mu         sync.RWMutex
	tap        io.ReadWriteCloser
	vswitch    *VSwitch
	brutal     bool
	brutalUp   uint64
	brutalDown uint64
	cfg        atomic.Pointer[Config] // 当前生效配置（面板热更数据源）

	macAddr       string
	activeClients map[string]*ClientSession
	macToIP       map[string]MacBinding

	encrypt   bool
	encAlgo   int // 服务端期望的内层算法；新会话必须与客户端声明完全一致
	startedAt time.Time

	// minEnc 内层加密强度下限（minEncRank 值，0=不限）
	minEnc int
	// maxSessions 并发会话数上限（0=不限）。v6 地址池在 /64 下实际不会枯竭，
	// 无上限的会话创建等于把 OOM 做成持密者可远程触发的功能。
	maxSessions int
	// fecGroupMin/Max 服务端接受的对端 FEC 分组大小 K 区间（默认协议边界
	// [2,64]）。请求 FEC 而越界即拒连，不夹取：对端要的是自己的编码参数，
	// 静默改成别的 K 会让它在不知道的情况下多付 N/K 冗余开销。
	fecGroupMin, fecGroupMax int
	// bootCfg 启动时配置：NeedsRestart 的差异基准（当前 s.cfg 是热更后的值）
	bootCfg *Config
	banned   map[string]int64 // clientID → 封禁到期 unix 毫秒（0=永久）；被 ban 连接直接进焦油坑
	bannedMu sync.Mutex

	// pskFail 按远端地址统计握手 PSK 失败次数，把暴力猜测的代价从
	// "无限连接" 降到 "每地址窗口内若干次"，同时给运维留一条可观测记录。
	pskFailMu sync.Mutex
	pskFail   map[string]*pskFailBucket

	tapWriteErrs atomic.Uint64 // TAP 交付失败帧数（旧实现被静默吞掉）
}

// pskFailBucket 单个远端地址的 PSK 失败计数窗口
type pskFailBucket struct {
	count int
	first time.Time
}

const (
	pskFailLimit     = 5           // 窗口内允许失败次数（第 6 次起直接断链）
	pskFailWindow    = time.Minute // 计数窗口
	pskFailEntryMax  = 1024        // 超此规模触发全表清理，防表无限增长
	pskFailBucketTTL = 10 * time.Minute
)

// pskFailExceeded 记录一次 PSK 校验失败，返回该远端是否已超出预算。
// 超出后调用方应直接关闭连接：焦油坑会挂起 goroutine 到读超时，
// 无限触发等于给攻击者一个零成本的内存放大器。
func (s *Server) pskFailExceeded(remote string) bool {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	s.pskFailMu.Lock()
	if s.pskFail == nil {
		s.pskFail = make(map[string]*pskFailBucket)
	}
	if len(s.pskFail) > pskFailEntryMax {
		now := time.Now()
		for k, b := range s.pskFail {
			if now.Sub(b.first) > pskFailBucketTTL {
				delete(s.pskFail, k)
			}
		}
	}
	now := time.Now()
	b, ok := s.pskFail[remote]
	if !ok || now.Sub(b.first) > pskFailWindow {
		s.pskFail[remote] = &pskFailBucket{count: 1, first: now}
		s.pskFailMu.Unlock()
		return false
	}
	b.count++
	exceeded := b.count > pskFailLimit
	s.pskFailMu.Unlock()
	return exceeded
}

const (
	maxAcceptedConnections = 256
	maxConnectionsPerIP    = 16
)

type connectionLimiter struct {
	mu    sync.Mutex
	total int
	byIP  map[string]int
}

func (l *connectionLimiter) acquire(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxAcceptedConnections || l.byIP[host] >= maxConnectionsPerIP {
		return false
	}
	l.total++
	l.byIP[host]++
	return true
}

func (l *connectionLimiter) release(addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	l.mu.Lock()
	l.total--
	if l.byIP[host] <= 1 {
		delete(l.byIP, host)
	} else {
		l.byIP[host]--
	}
	l.mu.Unlock()
}

// rotateSessionEpochLocked 在客户端进程实例变化时切换完整密钥代际。调用方
// 持有 s.mu；旧物理连接先被关闭，随后同时安装新盐、数据/FEC AEAD、发送
// 序号和接收重放状态，绝不允许“重置 seq 但沿用 key+nonce salt”。
// validSessionTokenFormat 只验证 token 的协议形态，不验证归属。
// 新建 session 时服务端可能刚重启、内存态已丢失；若客户端仍携带上一次由
// 服务端签发的 256-bit token，就沿用它作为新的 current token，避免“服务端
// 重启后首个握手响应丢失 -> 客户端下次进程重启再也无法接回”的锁死窗口。
func validSessionTokenFormat(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// acceptSessionResumeToken 验证 current/pending 两个 token。pending 被客户端
// 真正回带时才提升为 current；这就是 token rollover 的 ACK。旧 current 在
// pending 被确认前始终可用，因此握手响应即使丢失也不会把客户端永久锁死。
// 调用方必须持有 s.mu。
func acceptSessionResumeToken(session *ClientSession, presented string) bool {
	if verifyRandomSessionToken(session.ResumeToken, presented) {
		return true
	}
	if session.PendingResumeToken != "" && verifyRandomSessionToken(session.PendingResumeToken, presented) {
		session.ResumeToken = session.PendingResumeToken
		session.PendingResumeToken = ""
		return true
	}
	return false
}

// ensurePendingResumeToken 为当前 session 准备下一枚 token。若前一次 rollover
// 尚未被客户端 ACK，则复用同一枚 pending token，不能再次覆盖；否则连续丢失
// handshake response 时客户端永远追不上服务端的 token 世代。
func ensurePendingResumeToken(session *ClientSession) error {
	if session.PendingResumeToken != "" {
		return nil
	}
	token, err := newSessionToken()
	if err != nil {
		return err
	}
	session.PendingResumeToken = token
	return nil
}

// responseResumeToken 返回本次握手应该下发的 token：存在 pending 时持续下发
// pending，直到某次后续握手回带它完成 ACK；否则返回 current。
func responseResumeToken(session *ClientSession) string {
	if session.PendingResumeToken != "" {
		return session.PendingResumeToken
	}
	return session.ResumeToken
}

func (s *Server) rotateSessionEpochLocked(session *ClientSession, instanceID, psk string) error {
	session.sessionMu.Lock()
	defer session.sessionMu.Unlock()
	for ci := range session.conns {
		ci.tcpConn.Close()
	}
	saltA, saltB := newRandomSalt(), newRandomSalt()
	var icTx, icRx, fecTx, fecRx *innerCipher
	if session.Encrypt {
		var err error
		icTx, err = newGCMInnerCipherForAlgo(psk, saltB[:], session.EncAlgo)
		if err != nil {
			return err
		}
		icRx, err = newGCMInnerCipherForAlgo(psk, saltA[:], session.EncAlgo)
		if err != nil {
			return err
		}
		fecTx, err = newGCMInnerCipherDomainForAlgo(psk, saltB[:], "fec", session.EncAlgo)
		if err != nil {
			return err
		}
		fecRx, err = newGCMInnerCipherDomainForAlgo(psk, saltA[:], "fec", session.EncAlgo)
		if err != nil {
			return err
		}
	}
	session.SaltA, session.SaltB = saltA, saltB
	session.icTx, session.icRx = icTx, icRx
	session.InstanceID = instanceID
	session.Epoch++
	session.ActiveConns = 0
	session.RxReorder.Reset()
	if session.FecDec != nil {
		session.FecDec.Reset()
	}
	if session.FecEncK > 0 {
		session.FecDec = NewFECDecoder(session.FecEncK, fecRx, session.RxReorder.Insert)
		session.Port.ResetEpoch(session.FecEncK, fecTx)
	} else {
		session.Port.ResetEpoch(0, nil)
	}
	return nil
}

// Ban 封禁客户端。ttl<=0 表示永久；会话若在线则立即断开。
func (s *Server) Ban(clientID string, ttl time.Duration) bool {
	if clientID == "" {
		return false
	}
	s.bannedMu.Lock()
	if ttl <= 0 {
		s.banned[clientID] = 0
	} else {
		s.banned[clientID] = time.Now().Add(ttl).UnixMilli()
	}
	s.bannedMu.Unlock()
	// 已在线则立刻踢下线
	s.mu.RLock()
	session, ok := s.activeClients[clientID]
	s.mu.RUnlock()
	if ok {
		s.kickSession(session)
	}
	log.Infof("[Server] Client %s banned (ttl=%s)", clientID, ttl)
	return true
}

// Unban 解除封禁
func (s *Server) Unban(clientID string) {
	s.bannedMu.Lock()
	delete(s.banned, clientID)
	s.bannedMu.Unlock()
}

// IsBanned 查询 clientID 当前是否被封禁（自动清理过期项）
func (s *Server) IsBanned(clientID string) bool {
	if clientID == "" {
		return false
	}
	s.bannedMu.Lock()
	defer s.bannedMu.Unlock()
	exp, ok := s.banned[clientID]
	if !ok {
		return false
	}
	if exp > 0 && time.Now().UnixMilli() >= exp {
		delete(s.banned, clientID)
		return false
	}
	return true
}

// BanList 返回当前封禁列表快照（clientID → 剩余秒，0=永久）
func (s *Server) BanList() map[string]int64 {
	s.bannedMu.Lock()
	defer s.bannedMu.Unlock()
	out := make(map[string]int64, len(s.banned))
	nowMs := time.Now().UnixMilli()
	for id, exp := range s.banned {
		if exp == 0 {
			out[id] = 0
		} else if exp > nowMs {
			out[id] = (exp - nowMs) / 1000
		} else {
			delete(s.banned, id)
		}
	}
	return out
}

// kickSession 断开一个会话的所有物理连接并停止下行（Web 面板 kick 用）
func (s *Server) kickSession(session *ClientSession) {
	s.mu.Lock()
	clientID := ""
	for id, current := range s.activeClients {
		if current == session {
			clientID = id
			break
		}
	}
	if clientID == "" {
		s.mu.Unlock()
		return
	}
	session.sessionMu.Lock()
	conns := make([]*connInfo, 0, len(session.conns))
	for ci := range session.conns {
		conns = append(conns, ci)
	}
	if session.destroyTimer != nil {
		session.destroyTimer.Stop()
		session.destroyTimer = nil
	}
	session.ActiveConns = 0
	session.sessionMu.Unlock()
	s.destroySessionLocked(session, clientID)
	s.mu.Unlock()
	for _, ci := range conns {
		ci.tcpConn.Close()
	}
}

// IPPoolStatus 地址池使用情况（面板展示）。v6 空间巨大不计算容量。
func (s *Server) IPPoolStatus() (v4Used, v4Total, v6Used int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v4Used, v4Total = len(s.usedV4), ipNetHostCount(s.v4Net)
	v6Used = len(s.usedV6)
	return
}

// ipNetHostCount 估算 IPv4 网段可用主机数（扣网络号/广播，超大网段封顶）
func ipNetHostCount(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 16 {
		return 1 << 16
	}
	cnt := 1 << uint(hostBits)
	if cnt > 2 {
		cnt -= 2
	}
	return cnt
}

// MACEntry 面板展示的 MAC 表条目
type MACEntry struct {
	MAC    string `json:"mac"`
	Port   string `json:"port"`
	AgeSec uint64 `json:"age_sec"`
}

// MACSnapshot 交换机学习到的 MAC→端口 快照（面板展示）
func (s *Server) MACSnapshot() []MACEntry {
	out := []MACEntry{}
	nowTick := s.vswitch.coarseSec.Load()
	for i := 0; i < ShardCount; i++ {
		shard := s.vswitch.shards[i]
		shard.mu.RLock()
		for mac, entry := range shard.macTable {
			var age uint64
			if !entry.static && nowTick >= entry.updatedTick {
				age = nowTick - entry.updatedTick
			}
			out = append(out, MACEntry{MAC: fmtMAC(mac), Port: entry.portID, AgeSec: age})
		}
		shard.mu.RUnlock()
	}
	return out
}

// snapshotServerConns 汇总所有会话的物理连接明细（面板"连接明细"页签）。
// 注意：此方法自行加读锁，不得在已持有 s.mu 时调用。
// avgRTT 当前所有物理连接 RTT 的均值（毫秒）；无连接时 0。供趋势采样使用。
func (s *Server) avgRTT() float64 {
	conns := s.snapshotServerConns()
	if len(conns) == 0 {
		return 0
	}
	var sum uint64
	for _, c := range conns {
		sum += uint64(c.RttMs)
	}
	return float64(sum) / float64(len(conns))
}

// sampleClientTraffic 各客户端会话累计字节的快照：上行=Rx（client→server）、
// 下行=Tx（server→client）。趋势/每客户端流量统计按 60 秒差分取增量。
func (s *Server) sampleClientTraffic() map[string][2]uint64 {
	out := make(map[string][2]uint64, len(s.activeClients))
	s.mu.RLock()
	for id, session := range s.activeClients {
		out[id] = [2]uint64{
			atomic.LoadUint64(&session.RxBytes),
			atomic.LoadUint64(&session.TxBytes),
		}
	}
	s.mu.RUnlock()
	return out
}

func (s *Server) snapshotServerConns() []serverConnSnapshot {	now := time.Now().Unix()
	out := []serverConnSnapshot{}
	s.mu.RLock()
	for id, session := range s.activeClients {
		session.sessionMu.Lock()
		cis := make([]*connInfo, 0, len(session.conns))
		for ci := range session.conns {
			cis = append(cis, ci)
		}
		session.sessionMu.Unlock()
		for _, ci := range cis {
			var sni, tlsVer, tlsCipher, tlsAlpn string
			if ci.tls != nil {
				sni, tlsVer, tlsCipher, tlsAlpn = ci.tls.SNI, ci.tls.Version, ci.tls.CipherSuite, ci.tls.ALPN
			}
			out = append(out, serverConnSnapshot{
				ClientID:  id,
				Remote:    ci.remote,
				RttMs:     atomic.LoadUint32(ci.rttCache) / 1000,
				TxBytes:   atomic.LoadUint64(&ci.txBytes),
				RxBytes:   atomic.LoadUint64(&ci.rxBytes),
				TxPackets: atomic.LoadUint64(&ci.txPackets),
				RxPackets: atomic.LoadUint64(&ci.rxPackets),
				AgeSec:    uint64(now - ci.linkedAt),
				// brutalTx 是本端（服务端）下发方向整形速率，brutalRx 是客户端上行方向
				BrutalApplied: ci.brutal.Load() != nil && ci.brutal.Load().Applied,
				BrutalErr: func() string {
					if br := ci.brutal.Load(); br != nil {
						return br.Error
					}
					return ""
				}(),
				BrutalSrvTx: atomic.LoadUint64(&ci.brutalTx),
				BrutalCliTx: atomic.LoadUint64(&ci.brutalRx),
				Epoch:       ci.epoch,
				SNI:         sni,
				TLSVersion:  tlsVer,
				TLSCipher:   tlsCipher,
				TLSALPN:     tlsAlpn,
			})
		}
	}
	s.mu.RUnlock()
	// 会话级协商结果需要第二个临界区：per-conn 字段在上面已经取到，
	// 这里只补 FEC/加密算法等只在会话上保存的字段。
	type sessSnap struct {
		fec   string
		enc   int
		encOn bool
	}
	s.mu.RLock()
	snaps := make(map[string]*sessSnap, len(s.activeClients))
	for id, session := range s.activeClients {
		session.sessionMu.Lock()
		snaps[id] = &sessSnap{fec: session.FecMode, enc: session.EncAlgo, encOn: session.Encrypt}
		session.sessionMu.Unlock()
	}
	s.mu.RUnlock()
	for i := range out {
		if sn := snaps[out[i].ClientID]; sn != nil {
			out[i].FEC, out[i].EncAlgo, out[i].SessionEnc = sn.fec, sn.enc, sn.encOn
		}
	}
	return out
}

// ApplyConfig 服务端热更。psk/encrypt 即时生效于**新**会话，但会出现在
// needs_restart 里：现有会话的内层密钥在客户端进程内已固定，只有重启双方
// 才算一次完整轮换（见 handleConnection 复活分支的 pskHash 校验）。
// web 段由 WebManager 自行处理。
func (s *Server) ApplyConfig(cfg *Config) []string {
	needsRestart := s.NeedsRestart(cfg)
	s.mu.Lock()
	brutalChanged := s.brutal != cfg.Brutal || s.brutalUp != cfg.BrutalUp || s.brutalDown != cfg.BrutalDown
	s.psk = cfg.PSK
	s.encrypt = cfg.Encrypt
	s.encAlgo = encAlgoFromConfig(cfg.EncAlgo)
	s.brutal, s.brutalUp, s.brutalDown = cfg.Brutal, cfg.BrutalUp, cfg.BrutalDown
	s.minEnc = minEncRank(cfg.MinEnc)
	s.maxSessions = cfg.Server.MaxSessions
	s.fecGroupMin, s.fecGroupMax = cfg.Server.FecGroupMin, cfg.Server.FecGroupMax
	var reconnect []*net.TCPConn
	if brutalChanged {
		for _, session := range s.activeClients {
			session.sessionMu.Lock()
			for ci := range session.conns {
				reconnect = append(reconnect, ci.tcpConn)
			}
			session.sessionMu.Unlock()
		}
	}
	s.mu.Unlock()
	// TCP congestion state is socket-local. Closing physical connections is the
	// only reliable way to apply enable/disable/rate changes while preserving the
	// logical session; clients reconnect immediately with fresh negotiated state.
	for _, conn := range reconnect {
		_ = conn.Close()
	}

	// 填充策略是全局原子量，作用于本进程的全部发送路径
	if actual := setPadMode(cfg.PadMode); actual != cfg.PadMode {
		log.Warnf("Invalid pad_mode %q, using %s", cfg.PadMode, actual)
	}
	s.cfg.Store(cfg)
	return needsRestart
}

// NeedsRestart 计算无法热更、需要重启进程的字段差异。
// 基准是**启动时**配置而不是当前生效配置：否则热更一次后差异立刻消失，
// 面板再也看不到"这个字段改了但没重启"。
func (s *Server) NeedsRestart(cfg *Config) []string {
	o := s.bootCfg
	if o == nil {
		return nil
	}
	var out []string
	if o.Tap != cfg.Tap {
		out = append(out, "tap")
	}
	if o.Mac != cfg.Mac {
		out = append(out, "mac")
	}
	if o.Server.V4CIDR != cfg.Server.V4CIDR || o.Server.V6CIDR != cfg.Server.V6CIDR {
		out = append(out, "server.v4_cidr/v6_cidr")
	}
	if o.Server.Cert != cfg.Server.Cert || o.Server.Key != cfg.Server.Key {
		out = append(out, "server.cert/key")
	}
	// psk/encrypt 对**新**会话已生效，但既有会话的内层密钥在客户端进程里
	// 已固定（客户端无法热改），必须双侧同时重启才算完成一次轮换。
	if o.PSK != cfg.PSK {
		out = append(out, "psk")
	}
	if o.Encrypt != cfg.Encrypt {
		out = append(out, "encrypt")
	}
	if o.EncAlgo != cfg.EncAlgo {
		out = append(out, "enc_algo")
	}
	if o.Client.Conns != cfg.Client.Conns {
		out = append(out, "client.conns")
	}
	if o.Socks5 != cfg.Socks5 {
		out = append(out, "socks5")
	}
	if o.Up != cfg.Up || o.Down != cfg.Down {
		out = append(out, "up/down")
	}
	return out
}

// startServer 以 JSON 配置启动服务端（cfg 已经过 applyDefaults + Validate）
func startServer(ctx context.Context, cfg *Config) (runErr error) {
	log.Infof("Starting TCP TLS server process...")
	hooks := NewLifecycleHooks(cfg.Up, cfg.Down)
	var tapSetupErrs []string
	_, v4net, _ := net.ParseCIDR(cfg.Server.V4CIDR)
	_, v6net, _ := net.ParseCIDR(cfg.Server.V6CIDR)

	srv := &Server{
		psk: cfg.PSK, v4Net: v4net, v6Net: v6net, usedV4: make(map[string]bool), usedV6: make(map[string]bool),
		vswitch: NewVSwitch(), brutal: cfg.Brutal, brutalUp: cfg.BrutalUp, brutalDown: cfg.BrutalDown,
		macAddr: cfg.Mac, activeClients: make(map[string]*ClientSession), macToIP: make(map[string]MacBinding),
		encrypt: cfg.Encrypt, encAlgo: encAlgoFromConfig(cfg.EncAlgo), startedAt: time.Now(),
		banned:       make(map[string]int64),
		pskFail:      make(map[string]*pskFailBucket),
		minEnc: minEncRank(cfg.MinEnc),
		maxSessions: cfg.Server.MaxSessions,
		fecGroupMin: cfg.Server.FecGroupMin, fecGroupMax: cfg.Server.FecGroupMax,
	}
	srv.cfg.Store(cfg)
	srv.bootCfg = cfg
	// 交换机安全策略：会话端口只能声明本会话注册的 MAC（防跨客户端 MAC
	// 冒充劫持下行流量）；本机 TAP 端口可信，豁免校验与广播限速。
	srv.vswitch.validateMAC = srv.validateSrcMAC
	srv.vswitch.trustedPort = tapPortID
	srv.v4Gw, srv.v6Gw = getFirstIP(v4net).String(), getFirstIP(v6net).String()
	srv.usedV4[srv.v4Gw], srv.usedV6[srv.v6Gw] = true, true

	var tap io.ReadWriteCloser
	if cfg.Tap == "mem" {
		// In-memory TAP backend for CI/e2e where no real TAP device can be
		// created (GitHub hosted runners lack CAP_NET_ADMIN). The tunnel
		// (TCP TLS, handshake, FEC, encryption) is exercised exactly the same.
		tap = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		t, err := water.New(newTapConfig(cfg.Tap))
		if err != nil {
			log.Fatalf("Server TAP error: %v", err)
		}
		tap = t
		if err := setTapMac(cfg.Tap, cfg.Mac); err != nil {
			log.Warnf("Server failed to set tap MAC: %v", err)
		}
		if link, err := netlink.LinkByName(cfg.Tap); err != nil {
			// 设备名对不上时整段跳过：网关地址从未落到接口上，隧道网关与
			// web.bind=tunnel 都会对着一个不存在的地址反复失败
			log.Warnf("Server cannot assign gateway addresses: tap %s not found: %v", cfg.Tap, err)
			tapSetupErrs = append(tapSetupErrs, err.Error())
		} else {
			// 先 up 再挂地址：bind 要求 IFF_UP，且 v6 在接口 up 的瞬间会
			// 重新触发一次 DAD —— 顺序反了第一轮 web 绑定就白等一个探测窗口
			if err := netlink.LinkSetUp(link); err != nil {
				log.Errorf("Server failed to bring up tap %s: %v", cfg.Tap, err)
				tapSetupErrs = append(tapSetupErrs, err.Error())
			}
			if err := assignTapGateway(link, "v4", srv.v4Gw, maskSize(v4net.Mask)); err != nil {
				log.Error(err)
				tapSetupErrs = append(tapSetupErrs, err.Error())
			}
			if err := assignTapGateway(link, "v6", srv.v6Gw, maskSize(v6net.Mask)); err != nil {
				log.Error(err)
				tapSetupErrs = append(tapSetupErrs, err.Error())
			}
		}
	}
	srv.tap = tap

	tapBackend := make(chan []VPNFrame, 32)
	tapPort := NewAsyncPort(ctx, tapPortID)
	tapPort.RegisterBackend(tapBackend, new(uint32))
	srv.vswitch.AddPort(tapPort)

	go func() {
		for frames := range tapBackend {
			for _, vf := range frames {
				if len(vf.Data) > 0 {
					if _, werr := srv.tap.Write(vf.Data); werr != nil {
						// 旧实现把这里的错误直接丢掉，TAP 故障表现为"隧道在线但
						// 客户端不通"。计数 + 限频日志让故障可观测。
						n := srv.tapWriteErrs.Add(1)
						if n == 1 || n%1000 == 0 {
							log.Warnf("TAP write failed #%d: %v", n, werr)
						}
					}
					putFrame(vf.Data)
				}
			}
			putVPNFrameBatch(frames)
		}
	}()

	go func() {
		readSize, pooledRead := tapReadBufferSize(cfg.Tap)
		if pooledRead {
			log.Debugf("[Server] TAP zero-copy read enabled (read buffer=%d bytes)", readSize)
		}
		var fallback []byte
		if !pooledRead {
			fallback = make([]byte, 65536)
		}
		for {
			var buf []byte
			if pooledRead {
				buf = getFrameAtLeast(readSize)[:readSize]
			} else {
				buf = fallback
			}
			rn, err := srv.tap.Read(buf)
			if err != nil {
				if pooledRead {
					putFrame(buf)
				}
				return
			}
			if pooledRead {
				srv.vswitch.ProcessOwnedFrame(tapPortID, buf[:rn])
			} else {
				srv.vswitch.ProcessFrame(tapPortID, buf[:rn])
			}
		}
	}()

	tlsConfig := getServerTLSConfig(cfg.Server.Cert, cfg.Server.Key)
	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.Addr)
	if err != nil {
		log.Fatalf("ResolveTCPAddr error: %v", err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("TCP Listen error: %v", err)
	}
	hookEnv := HookEnv{Mode: "server", Dev: cfg.Tap, Config: cfg.SourcePath,
		IPv4:      fmt.Sprintf("%s/%d", srv.v4Gw, maskSize(v4net.Mask)),
		IPv6:      fmt.Sprintf("%s/%d", srv.v6Gw, maskSize(v6net.Mask)),
		GatewayV4: srv.v4Gw, GatewayV6: srv.v6Gw}
	hooks.Activate(hookEnv)
	if hooks.Configured() && len(tapSetupErrs) != 0 {
		if downErr := hooks.Down(); downErr != nil {
			log.Errorf("down hook after interface setup failure also failed: %v", downErr)
		}
		_ = listener.Close()
		log.Fatalf("Server tunnel interface is not ready; refusing to run up hook: %s", strings.Join(tapSetupErrs, "; "))
	}
	if err := hooks.Up(hookEnv); err != nil {
		if downErr := hooks.Down(); downErr != nil {
			log.Errorf("down hook after up failure also failed: %v", downErr)
		}
		_ = listener.Close()
		log.Fatalf("Server lifecycle hook failed: %v", err)
	}
	defer srv.tap.Close()
	defer func() {
		if err := hooks.Down(); err != nil {
			log.Errorf("Server down hook failed: %v", err)
			runErr = err
		}
	}()

	if cfg.Web.Addr != "" {
		go startWebServer(cfg.Web.Addr, srv, nil, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key, cfg)
	}
	log.Infof("VPN Server listening on %s (TCP TLS, ALPN: h2)", cfg.Addr)

	serveListener(ctx, srv, listener, tlsConfig)
	return nil
}

// assignTapGateway 在 tap 上配置一个隧道网关地址。
// 失败必须可见：地址没配上时隧道网关不可达，web.bind=tunnel 也会对着一个
// 不存在的地址反复 bind 失败，否则只能靠"面板连不上"反推。
func assignTapGateway(link netlink.Link, fam, ip string, prefix int) error {
	if ip == "" {
		return nil
	}
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, prefix))
	if err != nil {
		return fmt.Errorf("Server invalid %s gateway address %s/%d: %v", fam, ip, prefix, err)
	}
	if fam == "v6" {
		// ULA 网关由配置指定，不存在需要探测的重复地址：挂上即 permanent，
		// 省掉内核 1~2s 的 DAD 窗口（取不到 RA 时地址会一直 tentative，v6 bind 永久失败）
		addr.Flags = ifaNoDAD
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("Server failed to assign %s gateway %s/%d to %s: %v",
			fam, ip, prefix, link.Attrs().Name, err)
	}
	return nil
}

// serveListener 阻塞接受连接直到 ctx 取消。独立成函数以便测试进程内启动。
func serveListener(ctx context.Context, srv *Server, listener *net.TCPListener, tlsConfig *tls.Config) {
	go func() { <-ctx.Done(); listener.Close() }()
	limiter := &connectionLimiter{byIP: make(map[string]int)}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(15 * time.Second)
		conn.SetNoDelay(true)
		if !limiter.acquire(conn.RemoteAddr()) {
			log.Debugf("connection limiter rejected remote %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		go func(c *net.TCPConn) {
			defer limiter.release(c.RemoteAddr())
			peekBuf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := c.Read(peekBuf)
			c.SetReadDeadline(time.Time{})
			if err != nil || n == 0 {
				log.Debugf("pre-TLS probe failed from %s: n=%d err=%v", c.RemoteAddr(), n, err)
				c.Close()
				return
			}

			prefixConn := &PrefixConn{Conn: c, prefix: peekBuf[:n]}
			if peekBuf[0] != 0x16 {
				// 非 TLS 流量（回退 HTTP / 扫描器）走默认小缓冲
				serveFallbackHTTP(prefixConn, "http/1.1")
				return
			}

			// 不手动设置 SO_RCVBUF/SO_SNDBUF。显式 setsockopt 会锁定
			// TCP socket buffer，关闭 Linux 的 receive/send autotuning；
			// 对高 BDP 隧道让内核按 tcp_rmem/tcp_wmem 自适应更合适。

			// 每条连接使用独立配置副本捕获服务端实际收到的 ClientHello。
			// GetConfigForClient 在证书选择阶段执行；保留已有回调的返回语义。
			connTLSConfig := tlsConfig.Clone()
			previousGetConfig := connTLSConfig.GetConfigForClient
			var helloObservation tlsClientHelloObservation
			connTLSConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				helloObservation = observeTLSClientHello(hello)
				if previousGetConfig != nil {
					return previousGetConfig(hello)
				}
				return nil, nil
			}
			tlsConn := tls.Server(prefixConn, connTLSConfig)
			tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			err = tlsConn.Handshake()
			tlsConn.SetDeadline(time.Time{})
			if err != nil {
				log.Debugf("TLS handshake failed from %s: %v", c.RemoteAddr(), err)
				tlsConn.Close()
				return
			}

			alpn := tlsConn.ConnectionState().NegotiatedProtocol
			peekBuf2 := make([]byte, 1)
			tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n2, err2 := tlsConn.Read(peekBuf2)
			tlsConn.SetReadDeadline(time.Time{})
			if err2 != nil || n2 == 0 {
				log.Debugf("post-TLS protocol probe failed from %s: n=%d err=%v", c.RemoteAddr(), n2, err2)
				tlsConn.Close()
				return
			}

			prefixConn2 := &PrefixConn{Conn: tlsConn, prefix: peekBuf2[:n2]}
			if peekBuf2[0] >= 0x20 {
				serveFallbackHTTP(prefixConn2, alpn)
				return
			}

			tlsInfo := tlsHandshakeInfoFromState(tlsConn.ConnectionState(), helloObservation)
			srv.handleConnection(ctx, prefixConn2, c, tlsInfo)
		}(conn)
	}
}

func (s *Server) handleConnection(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn, tlsInfo *TLSHandshakeInfo) {
	connCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	defer conn.Close()

	scanner := NewFrameScanner(conn)
	// 首帧是握手 JSON（<2KB）：认证前用小上限，防 10 字节帧头声明 131070
	// 长度把扫描缓冲扩到 131KB/连接的内存放大
	scanner.SetMaxDataLen(maxHandshakeDataLen)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, _, err := scanner.ReadFrame()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		camouflageProbe(conn)
		return
	}

	var req HandshakeReq
	if err := json.Unmarshal(reqData, &req); err != nil {
		log.Warnf("Handshake data parse failed; engaging camouflage tar pit.")
		putFrame(reqData)
		camouflageProbe(conn)
		return
	}
	putFrame(reqData)
	log.Debugf("<= handshake request client=%s proto=%d instance=%s fec=%v/%d enc=%v/%d token_present=%v",
		req.ClientID, req.ProtocolVersion, req.ClientInstance, req.FEC, req.FecGroup, req.Encrypt, req.EncAlgo, req.SessionToken != "")

	// 一次性快照鉴权参数（ApplyConfig 会在 s.mu 下改写，无锁读是数据竞争）
	s.mu.RLock()
	psk := s.psk
	pskHash := hashPSK(psk)
	encrypt := s.encrypt
	expectedEncAlgo := s.encAlgo
	minEnc := s.minEnc
	fecGroupMin, fecGroupMax := s.fecGroupMin, s.fecGroupMax
	s.mu.RUnlock()

	// 常量时间比较：Go 字符串 == 逐字节短路，响应时延会泄露匹配前缀长度。
	// pskHash 本身就是握手凭据（线上传 hash 不传 PSK），非恒定时间比较等于
	// 给攻击者一个逐字节重建 pskHash 的远程时序预言机，限流与焦油坑挡不住
	// 换源 IP 的分布式采样。
	if !hmac.Equal([]byte(req.PSK), []byte(pskHash)) {
		// 限流：超限后直接断链而不是进焦油坑——焦油坑会让 goroutine
		// 挂到读超时，无限触发等于给攻击者一个零成本内存放大器。
		if s.pskFailExceeded(tcpConn.RemoteAddr().String()) {
			log.Warnf("PSK verification failed; remote %s exceeded its budget, dropping the connection", tcpConn.RemoteAddr().String())
			return
		}
		log.Warnf("PSK verification failed (hash mismatch), remote %s", tcpConn.RemoteAddr().String())
		camouflageProbe(conn)
		return
	}
	if req.Encrypt != encrypt {
		log.Warnf("Encryption settings mismatch (Client: %v, Server: %v)", req.Encrypt, encrypt)
		camouflageProbe(conn)
		return
	}
	// 强度下限：运维强制 GCM 时拒绝能力不足的客户端。这里刻意**不**走焦油坑——
	// 这是运维侧的期望结果（客户端未启用内层加密），需要一条明确可查的失败记录。
	if encrypt && minEnc > 0 && !isGCMAlgo(req.EncAlgo) {
		log.Warnf("connection refused: client inner cipher (algo=%d) is below the min_enc floor, remote %s",
			req.EncAlgo, tcpConn.RemoteAddr().String())
		return
	}
	if encrypt && req.EncAlgo != expectedEncAlgo {
		log.Warnf("connection refused: client inner cipher %d (%s) does not match server enc_algo %d (%s)",
			req.EncAlgo, encAlgoLabel(req.EncAlgo), expectedEncAlgo, encAlgoLabel(expectedEncAlgo))
		return
	}
	clientID := req.ClientID
	if clientID == "" {
		log.Warnf("connection refused: ClientID is missing")
		return
	}
	// 格式校验：clientID/MAC 会大量进入日志与面板，畸形值既可能是坏客户端，
	// 也可能被用于换行注入伪造日志行。直接断链，刻意不走焦油坑——这不是探测，
	// 无需伪装成服务故障。
	if !isValidClientID(clientID) {
		log.Warnf("connection refused: malformed ClientID (must be a UUID), length %d", len(clientID))
		return
	}
	if !isValidMACString(req.MAC) {
		log.Warnf("[%s] connection refused: MAC must be a non-zero unicast address", clientID)
		return
	}
	if req.ProtocolVersion != 2 {
		log.Warnf("[%s] connection refused: unsupported protocol_version=%d", clientID, req.ProtocolVersion)
		return
	}
	// FEC 分组大小是请求形态，不是能力位：拒绝越界请求而非夹取。自己的客户端
	// 发送前已夹到协议范围，因此这条只拦畸形/第三方 peer；fec_group=0 在
	// fec=false 时合法，必须按 req.FEC 门控，否则所有非 FEC 握手都会被拒。
	if req.FEC && (req.FecGroup < fecGroupMin || req.FecGroup > fecGroupMax) {
		log.Warnf("[%s] connection refused: fec_group=%d outside server policy [%d, %d]",
			clientID, req.FecGroup, fecGroupMin, fecGroupMax)
		return
	}
	if !isValidClientInstance(req.ClientInstance) {
		log.Warnf("[%s] connection refused: invalid client_instance", clientID)
		return
	}
	macKeyValue, _ := parseMACKey(req.MAC)
	req.MAC = fmtMAC(macKeyValue)
	ns := uuid.NewMD5(uuid.NameSpaceURL, []byte("my_vpn_tunnel"))
	expectedID := uuid.NewSHA1(ns, []byte(req.MAC+psk)).String()
	if !hmac.Equal([]byte(clientID), []byte(expectedID)) {
		log.Warnf("[%s] connection refused: client_id is not derived from the authenticated MAC", clientID)
		return
	}
	// 封禁检查：命中直接进焦油坑（与 PSK 错误同等对待，不泄露 ban 状态）
	if s.IsBanned(clientID) {
		log.Warnf("[%s] banned; access denied", clientID)
		camouflageProbe(conn)
		return
	}
	mac := req.MAC

	s.mu.Lock()
	if bind, exists := s.macToIP[mac]; exists && mac != "" {
		req.IPv4, req.IPv6 = bind.IPv4, bind.IPv6
	}

	session, exists := s.activeClients[clientID]
	if exists {
		if !hmac.Equal([]byte(req.MAC), []byte(session.MAC)) {
			log.Warnf("[%s] connection refused: MAC mismatch", clientID)
			s.mu.Unlock()
			camouflageProbe(conn)
			return
		}
		// PSK 轮换检测：会话内层密钥由创建时的 PSK 派生，且已被各连接的收发
		// 协程捕获为局部变量。客户端进程重启（例如轮换 PSK 后）会用新 PSK
		// 重新派生，两者不匹配时 GCM 标签校验全部失败→静默丢帧。此时必须
		// 整体丢弃会话让客户端重建，而不是"复活"。
		if session.pskHash != pskHash {
			log.Warnf("[%s] session key does not match the current PSK; dropping the stale session and forcing a rebuild", clientID)
			s.destroySessionLocked(session, clientID)
			exists = false
		}
		if exists && session.EncAlgo != req.EncAlgo {
			log.Warnf("[%s] existing session uses inner cipher %d (%s), request wants %d (%s); rebuild/restart required",
				clientID, session.EncAlgo, encAlgoLabel(session.EncAlgo), req.EncAlgo, encAlgoLabel(req.EncAlgo))
			s.mu.Unlock()
			return
		}
		if exists && session.InstanceID != req.ClientInstance {
			if !acceptSessionResumeToken(session, req.SessionToken) {
				log.Warnf("[%s] reconnect refused: invalid session token for a new client instance", clientID)
				s.mu.Unlock()
				camouflageProbe(conn)
				return
			}
			if err := s.rotateSessionEpochLocked(session, req.ClientInstance, psk); err != nil {
				log.Errorf("[%s] failed to rotate the session key epoch: %v", clientID, err)
				s.mu.Unlock()
				return
			}
			if err := ensurePendingResumeToken(session); err != nil {
				log.Errorf("[%s] failed to prepare the next session token: %v", clientID, err)
				s.mu.Unlock()
				return
			}
			log.Infof("[%s] rotated session key epoch to %d for a new client process instance", clientID, session.Epoch)
		} else if exists && session.PendingResumeToken != "" &&
			verifyRandomSessionToken(session.PendingResumeToken, req.SessionToken) {
			// 同一 client_instance 的后续物理连接/重拨已经拿到了 pending token：
			// 视为 ACK，正式切换 current token，并废弃旧 token。
			session.ResumeToken = session.PendingResumeToken
			session.PendingResumeToken = ""
		}
	}
	if exists {
		// 检测到老会话，立刻取消销毁倒计时，无缝复活！
		session.sessionMu.Lock()
		if session.destroyTimer != nil {
			session.destroyTimer.Stop()
			session.destroyTimer = nil
			log.Infof("[%s] ⚡ session revived before the destroy countdown expired (seamless handover)", clientID)
		}
		if session.ActiveConns >= maxConnectionsPerIP {
			session.sessionMu.Unlock()
			s.mu.Unlock()
			log.Warnf("[%s] connection refused: per-session physical connection limit reached", clientID)
			return
		}
		session.ActiveConns++
		session.sessionMu.Unlock()

		log.Infof("[%s] 🔗 existing session gained a new physical connection (active connections: %d)", clientID, session.ActiveConns)
	} else {
		// 会话数与地址池双上限：达到任一即按认证失败处理（焦油坑），
		// 不向攻击者泄露服务端内部状态。
		if s.maxSessions > 0 && len(s.activeClients) >= s.maxSessions {
			s.mu.Unlock()
			log.Warnf("connection refused: session limit reached (%d)", s.maxSessions)
			camouflageProbe(conn)
			return
		}
		v4ip, v6ip := s.assignIPsLocked(req.IPv4, req.IPv6)
		if v4ip == "" {
			s.mu.Unlock()
			log.Warnf("connection refused: IPv4 address pool exhausted (%s)", s.v4Net.String())
			camouflageProbe(conn)
			return
		}
		// FEC 协商：客户端请求 FEC 时按 XOR 奇偶校验编码（服务端下行用同参数）。
		// K 直接取请求值——上面的拒连闸已保证它在 [fecGroupMin, fecGroupMax]
		// ⊆ [fecMinGroup, fecMaxGroup] 内，无需再夹取；未请求 FEC 时为 0（不编码）。
		fecEncK := 0
		if req.FEC {
			fecEncK = int(req.FecGroup)
		}
		// 内层加密算法已在锁外按服务端 enc_algo 做了完全一致校验。
		// AES-128/256 共享 wire format，但 KDF label 隔离；绝不静默回退。
		saltA, saltB := newRandomSalt(), newRandomSalt()
		encAlgo := encAlgoNone
		var icTx, icRx, fecTx, fecRx *innerCipher
		if encrypt {
			encAlgo = expectedEncAlgo
			icTx, _ = newGCMInnerCipherForAlgo(psk, saltB[:], encAlgo) // s2c
			icRx, _ = newGCMInnerCipherForAlgo(psk, saltA[:], encAlgo) // c2s
			fecTx, _ = newGCMInnerCipherDomainForAlgo(psk, saltB[:], "fec", encAlgo)
			fecRx, _ = newGCMInnerCipherDomainForAlgo(psk, saltA[:], "fec", encAlgo)
		}
		fecMode := "off"
		if fecEncK > 0 {
			fecMode = fmt.Sprintf("xor K=%d", fecEncK)
		}

		port := NewAsyncPort(parentCtx, clientID)
		if fecEncK > 0 {
			port.AttachFEC(fecEncK, fecTx)
		}
		resumeToken := req.SessionToken
		if !validSessionTokenFormat(resumeToken) {
			var tokenErr error
			resumeToken, tokenErr = newSessionToken()
			if tokenErr != nil {
				delete(s.usedV4, v4ip)
				delete(s.usedV6, v6ip)
				port.Close()
				s.mu.Unlock()
				log.Errorf("[%s] failed to create a session token: %v", clientID, tokenErr)
				return
			}
		}
		session = &ClientSession{
			SessionID: uuid.New().String(), Port: port, IPv4: v4ip, IPv6: v6ip, MAC: req.MAC,
			ActiveConns: 1, FecEncK: fecEncK, FecMode: fecMode,
			EncAlgo: encAlgo, Encrypt: encrypt, SaltA: saltA, SaltB: saltB, pskHash: pskHash, CreatedAt: time.Now(),
			InstanceID: req.ClientInstance, Epoch: 1, ResumeToken: resumeToken,
			conns: make(map[*connInfo]struct{}),
		}
		// 解析失败则保持零值；归属校验对 MAC 为空的会话放行（见 validateSrcMAC）
		session.macBin, _ = parseMACKey(req.MAC)
		session.icTx = icTx
		session.icRx = icRx
		port.SetSequenceExhaustedHandler(func() {
			s.mu.Lock()
			session.sessionMu.Lock()
			session.InstanceID = "exhausted-" + uuid.New().String()
			for old := range session.conns {
				old.tcpConn.Close()
			}
			session.sessionMu.Unlock()
			s.mu.Unlock()
			log.Warnf("[%s] sequence space exhausted; forcing a fresh key epoch", clientID)
		})
		// 初始化服务端重排缓冲区，理顺后交由交换机转发
		session.RxReorder = NewReorderBuffer(func(orderedFrame []byte) {
			if session.macBin != (macKey{}) {
				s.vswitch.ProcessSessionFrame(clientID, session.macBin, orderedFrame)
			} else {
				s.vswitch.ProcessFrame(clientID, orderedFrame)
			}
		})
		if fecEncK > 0 {
			session.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
		}
		s.activeClients[clientID] = session
		if mac != "" {
			s.macToIP[mac] = MacBinding{IPv4: v4ip, IPv6: v6ip}
		}
		s.vswitch.AddPort(port)
		s.vswitch.AddStaticMAC(clientID, session.macBin)
		log.Infof("[%s] new logical client online (FEC=%s EncAlgo=%d), Assigned IPs: %s, %s", clientID, fecMode, encAlgo, v4ip, v6ip)
	}

	v4ip, v6ip, port := session.IPv4, session.IPv6, session.Port
	sessionID := session.SessionID // 提取出来准备发给客户端
	encAlgo := session.EncAlgo
	icTx, icRx := session.icTx, session.icRx
	saltA, saltB := session.SaltA, session.SaltB
	resumeToken := responseResumeToken(session)
	fecEncK := session.FecEncK
	sessionEpoch := session.Epoch
	sessionEncrypt := session.Encrypt
	ci := &connInfo{
		remote:   tcpConn.RemoteAddr().String(),
		tcpConn:  tcpConn,
		linkedAt: time.Now().Unix(),
		epoch:    sessionEpoch,
		tls:      tlsInfo,
	}
	// 注册本物理连接到会话，供 Web 面板踢出/展示明细。清理 defer 必须在
	// 发送握手响应之前安装：响应写失败会直接 return，不能把 ActiveConns 或
	// session.conns 留成“幽灵连接”。
	session.sessionMu.Lock()
	session.conns[ci] = struct{}{}
	session.sessionMu.Unlock()
	defer func() {
		// 从会话连接注册表移除本连接
		session.sessionMu.Lock()
		delete(session.conns, ci)
		session.sessionMu.Unlock()
		s.mu.Lock()
		session.sessionMu.Lock()
		current, stillCurrent := s.activeClients[clientID]
		if !stillCurrent || current != session || ci.epoch != session.Epoch {
			session.sessionMu.Unlock()
			s.mu.Unlock()
			return
		}
		session.ActiveConns--
		if session.ActiveConns <= 0 {
			// 不要立刻删除！给它 120 秒的“僵尸续命期”
			log.Infof("[%s] ⚠️ all physical connections are down; the session enters a 120s retention period...", clientID)

			session.destroyTimer = time.AfterFunc(120*time.Second, func() {
				s.mu.Lock()
				session.sessionMu.Lock()

				// 120 秒后再次检查，如果还是没连上，才彻底销毁
				current, stillCurrent := s.activeClients[clientID]
				if stillCurrent && current == session && session.ActiveConns <= 0 {
					s.destroySessionLocked(session, clientID)
					log.Infof("[%s] 💀 session timed out and was destroyed, releasing its IPs and memory", clientID)
				}

				session.sessionMu.Unlock()
				s.mu.Unlock()
			})
		}
		session.sessionMu.Unlock()
		s.mu.Unlock()
	}()

	// 速率整形参数在锁内快照，避免与 ApplyConfig 的写构成数据竞争
	brutal, brutalUp, brutalDown := s.brutal, s.brutalUp, s.brutalDown
	s.mu.Unlock()

	// serverTxRate = 服务端→客户端（下行），由本端 socket 整形；clientTxRate =
	// 客户端→服务端（上行），客户端自己整形，本端只裁进自己的上行预算内。
	groupOffer := req.BrutalGroups && req.BrutalConns > 0 && req.BrutalConns <= 1<<16 &&
		req.BrutalConnIndex >= 0 && req.BrutalConnIndex < req.BrutalConns &&
		req.BrutalTotalTx <= maxBrutalRateMbps && req.BrutalTotalRx <= maxBrutalRateMbps
	var serverTxRate, clientTxRate, serverLegacyRateBps uint64
	if groupOffer {
		serverTxRate, clientTxRate = negotiateBrutalRates(brutalUp, brutalDown, req.BrutalTotalTx, req.BrutalTotalRx)
		serverLegacyRateBps = splitLegacyBrutalRateBps(serverTxRate, req.BrutalConns, req.BrutalConnIndex)
	} else {
		// 对端未声明 group 语义或字段越界：没有逐连接预算可裁剪，按本端配置整形
		serverTxRate, clientTxRate = negotiateBrutalRates(brutalUp, brutalDown, 0, 0)
		serverLegacyRateBps, _ = brutalMbpsToBps(serverTxRate)
	}
	atomic.StoreUint64(&ci.brutalTx, serverTxRate)
	atomic.StoreUint64(&ci.brutalRx, clientTxRate)

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))
	// 响应带协商结果：FEC XOR 分组大小 + 内层加密算法与两个方向的会话盐。
	// GCM 未启用时不下发盐值（客户端也不启用加密器）。
	encSalt, encSalt2 := handshakeEncSalts(encAlgo, saltA, saltB)
	// 先完成 TLSVPN 应用层握手，再切 TCP congestion control。Brutal 是数据面
	// 优化，不应阻塞/拖死客户端等待握手响应。给响应写入本身也加明确超时。
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	respErr := s.sendResp(conn, true, "OK", clientID, sessionID, v4cidr, v6cidr,
		groupOffer, clientTxRate, serverTxRate,
		req.FEC, uint32(fecEncK), encAlgo, encSalt, encSalt2, resumeToken, sessionEncrypt, req.ProtocolVersion, sessionEpoch, tlsInfo)
	conn.SetWriteDeadline(time.Time{})
	if respErr != nil {
		log.Debugf("[%s] failed to send handshake response: %v", clientID, respErr)
		return
	}

	// HandshakeResp 已成功交给 TLS/TCP 写路径后，再尝试 Brutal。应用失败只降级
	// 为当前 congestion control 并告警，不能把已经完成的 TLSVPN 握手判成失败。
	if brutal && serverTxRate > 0 {
		groupID := uint64(0)
		if groupOffer {
			groupID = brutalGroupID("server", resumeToken)
		}
		br := applyTCPBrutal(tcpConn, serverTxRate, serverLegacyRateBps, groupID)
		ci.brutal.Store(br.clone())
		if !br.Applied {
			log.Warnf("[%s] TCP Brutal shaping skipped after handshake: %s", clientID, br.Error)
		} else if br.Error != "" {
			log.Warnf("[%s] TCP Brutal shaping active with limited observability: %s", clientID, br.Error)
		}
	} else {
		ci.brutal.Store((&brutalApplyResult{}).clone())
	}

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	ci.rttCache = rttCache

	connTxChan := make(chan []VPNFrame, 32)
	port.RegisterBackend(connTxChan, rttCache)
	defer port.UnregisterBackend(connTxChan)

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		keepAliveTicker := time.NewTicker(4 * time.Second)
		defer keepAliveTicker.Stop()

		// 与客户端一致：RTT 采样合并到已有发送 goroutine，避免每个物理连接
		// 额外持有一个 200ms ticker goroutine。代理/非 TCP 场景自动禁用。
		var rttTicker *time.Ticker
		var rttC <-chan time.Time
		writeDeadlineEpoch := currentDeadlineEpoch()
		_ = conn.SetWriteDeadline(time.Now().Add(11 * time.Second))
		refreshWriteDeadline := func() {
			epoch := currentDeadlineEpoch()
			if epoch != writeDeadlineEpoch {
				_ = conn.SetWriteDeadline(time.Now().Add(11 * time.Second))
				writeDeadlineEpoch = epoch
			}
		}
		if tcpConn != nil {
			rttTicker = time.NewTicker(200 * time.Millisecond)
			rttC = rttTicker.C
			defer rttTicker.Stop()
		}

		for {
			select {
			case <-connCtx.Done():
				return
			case <-rttC:
				if rtt, err := getTCPRTT(tcpConn); err == nil && rtt > 0 {
					atomic.StoreUint32(rttCache, rtt)
				}
			case frames := <-connTxChan:
				sendBuffer = sendBuffer[:0]
				txPackets := 0
			drainBatches:
				for {
					var n int
					sendBuffer, n = appendOwnedFrameBatch(sendBuffer, frames, icTx)
					txPackets += n
					if len(sendBuffer) >= maxTLSWriteBatchBytes {
						break
					}
					select {
					case frames = <-connTxChan:
						continue
					default:
						break drainBatches
					}
				}
				refreshWriteDeadline()
				_, werr := conn.Write(sendBuffer)
				if werr != nil {
					log.Debugf("[%s] downstream write failed, closing the connection: %v", clientID, werr)
					conn.Close()
					return
				}
				atomic.AddUint64(&session.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&session.TxPackets, uint64(txPackets))
				atomic.AddUint64(&ci.txBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&ci.txPackets, uint64(txPackets))
				dailyTraffic.Add(0, uint64(len(sendBuffer))) // 下行 = server→client
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil)
				// 心跳写必须带超时：数据帧分支写完即清成 time.Time{}，空闲期写路径上
				// 没有任何 deadline。半开路径会让 Write 挂到 tcp_retries2 耗尽
				// （约 15 分钟才放弃），期间心跳停发，客户端先在自己的读超时上判死
				// 本端连接，而服务端仍自认为在线——"connection lost: i/o timeout"
				// 的唯一成因。加超时后本端 10s 内自发现并断连。
				refreshWriteDeadline()
				if _, err := conn.Write(sendBuffer); err != nil {
					log.Debugf("[%s] keepalive write failed, closing the connection: %v", clientID, err)
					conn.Close()
					return
				}
			}
		}
	}()

	// 认证已通过：恢复数据帧的线路全量上限（jumbo 帧合法）
	scanner.SetMaxDataLen(maxWireDataLen)
	var rxBytesBatch, rxPacketsBatch uint64
	flushRxStats := func() {
		if rxPacketsBatch == 0 {
			return
		}
		atomic.AddUint64(&session.RxBytes, rxBytesBatch)
		atomic.AddUint64(&session.RxPackets, rxPacketsBatch)
		atomic.AddUint64(&ci.rxBytes, rxBytesBatch)
		atomic.AddUint64(&ci.rxPackets, rxPacketsBatch)
		dailyTraffic.Add(rxBytesBatch, 0) // 上行 = client→server
		rxBytesBatch, rxPacketsBatch = 0, 0
	}
	defer flushRxStats()
	readDeadlineEpoch := currentDeadlineEpoch()
	_ = conn.SetReadDeadline(time.Now().Add(16 * time.Second))
	for {
		frame, seq, err := scanner.ReadFrame()
		if err != nil {
			log.Debugf("[%s] connection lost: %v", clientID, err)
			return
		}
		epoch := currentDeadlineEpoch()
		if epoch != readDeadlineEpoch {
			_ = conn.SetReadDeadline(time.Now().Add(16 * time.Second))
			readDeadlineEpoch = epoch
		}

		if frame == nil {
			flushRxStats()
			continue
		}
		if err == nil {
			// 多条物理连接同时收包时这里只读会话 epoch/FEC/reorder 指针；
			// RWMutex 允许并发读，避免原 Mutex 把所有 RX 热路径串行化。
			session.sessionMu.RLock()
			currentEpoch := session.Epoch
			fecDec := session.FecDec
			rxReorder := session.RxReorder
			session.sessionMu.RUnlock()
			if ci.epoch != currentEpoch {
				putFrame(frame)
				return
			}
			rxBytesBatch += uint64(len(frame))
			rxPacketsBatch++
			if rxPacketsBatch >= 64 {
				flushRxStats()
			}
			if seq != 0 && icRx != nil {
				plain, derr := icRx.openInPlace(frame, seq, uint32(len(frame)))
				if derr != nil {
					// GCM 校验失败：篡改或异源注入的帧，直接丢弃
					log.Debugf("[%s] dropped tampered/foreign frame (seq=%d): %v", clientID, seq, derr)
					putFrame(frame)
					continue
				}
				frame = plain
			}
			if seq == 0 && fecDec != nil && len(frame) >= 7 && frame[0] == fecMagic {
				// XOR 校验帧：交给会话级 FEC 解码器
				fecDec.OnParity(frame)
				putFrame(frame)
				continue
			}
			if fecDec != nil {
				fecDec.OnData(seq, frame)
			}
			// 交给重排缓冲区
			rxReorder.Insert(seq, frame)
		}
	}
}

// destroySessionLocked 彻底销毁一个会话：回收地址与 MAC 绑定、摘除交换机口、
// 关闭重排缓冲区与端口。调用方须持有 s.mu。
// 重排缓冲区持有未交付帧的池缓冲，必须 Close 归还，否则泄漏到进程退出。
func (s *Server) destroySessionLocked(session *ClientSession, clientID string) {
	current, ok := s.activeClients[clientID]
	if !ok || current != session {
		return
	}
	delete(s.usedV4, session.IPv4)
	delete(s.usedV6, session.IPv6)
	delete(s.activeClients, clientID)
	s.macToIPCleanLocked(session.MAC, session.IPv4)
	s.vswitch.RemovePort(clientID)
	if session.RxReorder != nil {
		session.RxReorder.Close()
	}
	session.Port.Close()
}

// macToIPCleanLocked 会话销毁时回收其 MAC 绑定，防止表无限增长。
// 调用方须持有 s.mu。
func (s *Server) macToIPCleanLocked(mac, ip string) {
	if mac == "" {
		return
	}
	if bind, ok := s.macToIP[mac]; ok && bind.IPv4 == ip {
		// 仅当绑定仍指向本会话地址时清除（期间 MAC 可能已重新绑定）
		delete(s.macToIP, mac)
	}
}

// validateSrcMAC VSwitch 源 MAC 归属校验回调：会话端口只允许声明本会话
// 注册的 MAC，防止持密者声明他人 MAC 劫持其下行单播流量（学习表翻转攻击）。
// 本机 TAP 端口在 ProcessFrame 处已豁免，不会走到这里。
// MAC 为空的会话（旧客户端未上报）无法核对，放行保持兼容。
func (s *Server) validateSrcMAC(srcPortID string, mac macKey) bool {
	s.mu.RLock()
	session, ok := s.activeClients[srcPortID]
	var registered macKey
	hasMAC := false
	if ok {
		registered, hasMAC = session.macBin, session.macBin != (macKey{})
	}
	s.mu.RUnlock()
	if !ok || !hasMAC {
		return true
	}
	return registered == mac
}

func (s *Server) assignIPsLocked(reqV4, reqV6 string) (string, string) {
	alloc := func(req string, netw *net.IPNet, used map[string]bool) string {
		req = strings.Split(req, "/")[0]
		parsed := net.ParseIP(req)
		if parsed != nil && netw.Contains(parsed) && !used[parsed.String()] {
			used[parsed.String()] = true
			return parsed.String()
		}
		ip := duplicateIP(netw.IP)
		for netw.Contains(ip) {
			ipStr := ip.String()
			if !used[ipStr] && ip[len(ip)-1] != 0 && ip[len(ip)-1] != 255 {
				used[ipStr] = true
				return ipStr
			}
			incrementIP(ip)
		}
		return ""
	}
	v4 := alloc(reqV4, s.v4Net, s.usedV4)
	if v4 == "" {
		return "", ""
	}
	v6 := alloc(reqV6, s.v6Net, s.usedV6)
	if v6 == "" {
		delete(s.usedV4, v4)
		return "", ""
	}
	return v4, v6
}

// negotiateBrutalRates 把客户端申请的上下行速率裁进服务端自己的预算内，返回
// (服务端→客户端的下行整形速率, 客户端→服务端的上行速率)。服务端预算为 0 表示
// 不设上限（直通客户端申请值）；申请值 ≤ 预算时取申请值。
//
// 两个方向的预算绝不能互换：下行受 brutalDown 约束、上行受 brutalUp 约束。曾把
// 两者写反，客户端面板出现"上行 125 Mbps 配 30 Mbps 上行总量"的矛盾读数。抽成纯
// 函数是因为这段逻辑埋在 handleConnection 里、没有任何测试能看到它。
func negotiateBrutalRates(serverUp, serverDown, cliTx, cliRx uint64) (srvTx, cliTxRate uint64) {
	srvTx = serverDown
	if cliRx > 0 && (serverDown == 0 || cliRx < serverDown) {
		srvTx = cliRx
	}
	cliTxRate = serverUp
	if cliTx > 0 && (serverUp == 0 || cliTx < serverUp) {
		cliTxRate = cliTx
	}
	return srvTx, cliTxRate
}

func handshakeEncSalts(encAlgo int, saltA, saltB [encSaltSize]byte) (string, string) {
	if !isGCMAlgo(encAlgo) {
		return "", ""
	}
	return hex.EncodeToString(saltA[:]), hex.EncodeToString(saltB[:])
}

func (s *Server) sendResp(w io.Writer, ok bool, msg, clientID, sessionID, v4cidr, v6cidr string,
	brutalGroups bool, cliTotalTx, srvTotalTx uint64,
	fec bool, fecGroup uint32, encAlgo int, encSalt, encSalt2, sessionToken string, encrypt bool, protocolVersion int, epoch uint64,
	tlsInfo *TLSHandshakeInfo) error {
	resp := HandshakeResp{
		ProtocolVersion: protocolVersion, SessionEpoch: epoch,
		Success: ok, Message: msg, ClientID: clientID, SessionID: sessionID, IPv4: v4cidr, IPv6: v6cidr,
		// BrutalTotalTx/Rx 是客户端视角的上行/下行总量：cliTotalTx 是客户端自己整形的
		// 上行速率，srvTotalTx 是本端整形的下行速率（即客户端的 rx）。本端自己的 tx 是
		// 下行、不是上行，传错方向会让两端视角整个对调——面板表现为上行显示下行预算。
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500),
		BrutalGroups: brutalGroups, BrutalTotalTx: cliTotalTx, BrutalTotalRx: srvTotalTx,
		FEC: fec, FecGroup: int(fecGroup), Encrypt: encrypt, EncAlgo: encAlgo, EncSalt: encSalt, EncSalt2: encSalt2,
		SessionToken: sessionToken, TLS: tlsInfo,
	}
	log.Debugf("[%s] => handshake response session=%s proto=%d epoch=%d fec=%v/%d enc=%v/%d token_present=%v",
		clientID, sessionID, protocolVersion, epoch, fec, fecGroup, encrypt, encAlgo, sessionToken != "")
	d, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal handshake response: %w", err)
	}
	if err := writeStreamFrame(w, d); err != nil {
		return fmt.Errorf("write handshake response: %w", err)
	}
	return nil
}

// ======================= in-memory TAP =======================
// memTap is a no-op TAP backend used when -tap mem is requested (CI/e2e on
// runners that cannot create a real TAP device). Writes are dropped (there is
// no real subnet behind it); reads block until the context is cancelled so the
// stack goroutines terminate cleanly. The actual tunnel (TCP TLS, handshake,
// FEC, encryption) runs identically to the real-TAP path.
//
// e2e 性能测试通过 TxBytes/RxBytes 计数与 onWrite 钩子观测注入帧的回环，
// 等效于真实 TAP 上的 iperf/ping。
type memTapWriteHook struct {
	fn func([]byte)
}

type memTap struct {
	ctx     context.Context
	TxBytes atomic.Uint64 // 写入（即隧道向该 TAP 交付）的字节数
	TxPkts  atomic.Uint64
	// 测试/基准热路径只读。atomic.Pointer 避免每个交付帧都 lock/unlock，
	// 否则 mem-TAP throughput 实际测到的是测试钩子 mutex。
	onWrite atomic.Pointer[memTapWriteHook]
}

func newMemTap(ctx context.Context) *memTap { return &memTap{ctx: ctx} }

// SetOnWrite 注册写入回调（测试观测用，更新是冷路径）
func (m *memTap) SetOnWrite(f func([]byte)) {
	if f == nil {
		m.onWrite.Store(nil)
		return
	}
	m.onWrite.Store(&memTapWriteHook{fn: f})
}

func (m *memTap) Read(p []byte) (int, error) {
	<-m.ctx.Done()
	return 0, io.EOF
}

func (m *memTap) Write(p []byte) (int, error) {
	m.TxBytes.Add(uint64(len(p)))
	m.TxPkts.Add(1)
	if hook := m.onWrite.Load(); hook != nil {
		hook.fn(p)
	}
	return len(p), nil
}

func (m *memTap) Close() error { return nil }

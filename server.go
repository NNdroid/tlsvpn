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

// 隧道连接的 socket 缓冲。旧值读写各 4MB（合计 8MB/连接）是为对抗内核默认
// 16KB 而取的粗值，实际单帧上限 65535*2≈128KB、发送批上界 64KB，留 8 倍余量
// 已足够；同时把缓冲调小必须在确认是对端 TLS 握手**之后**做，否则扫描器
// 和回退 HTTP 连接也会各自占用巨量内核内存。
const (
	connReadBuf  = 1 * 1024 * 1024
	connWriteBuf = 512 * 1024
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
	portID    string
	updatedAt time.Time
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
	go vs.purgeExpiredMACs()
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
func (vs *VSwitch) purgeExpiredMACs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		for i := 0; i < ShardCount; i++ {
			shard := vs.shards[i]
			shard.mu.Lock()
			for mac, entry := range shard.macTable {
				if time.Since(entry.updatedAt) > 30*time.Minute {
					delete(shard.macTable, mac)
				}
			}
			shard.mu.Unlock()
		}
	}
}
func (vs *VSwitch) AddPort(p Port) {
	vs.portsMu.Lock()
	vs.ports[p.ID()] = p
	vs.portsMu.Unlock()
	log.Debugf("[VSwitch] Port UP: %s", p.ID())
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
	if len(frame) < 14 {
		return
	}
	var dstMAC, srcMAC macKey
	copy(dstMAC[:], frame[0:6])
	copy(srcMAC[:], frame[6:12])

	// 计算属于哪一个锁分片
	srcShard := vs.shards[getShardIdx(srcMAC)]

	srcShard.mu.RLock()
	entry, exists := srcShard.macTable[srcMAC]
	needUpdate := !exists || entry.portID != srcPortID || time.Since(entry.updatedAt) > 5*time.Second
	srcShard.mu.RUnlock()

	if needUpdate {
		// 源 MAC 归属校验：端口只能声明自己会话注册的 MAC。冒充帧整帧丢弃
		// （既不学习也不转发——转发等于允许攻击者以受害者身份注入流量）。
		if vs.validateMAC != nil && !vs.validateMAC(srcPortID, srcMAC) {
			vs.spoofDrops.Add(1)
			return
		}
		srcShard.mu.Lock()
		srcShard.macTable[srcMAC] = &macEntry{portID: srcPortID, updatedAt: time.Now()}
		log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC), srcPortID)
		srcShard.mu.Unlock()
	}

	var targetPortID string
	if (dstMAC[0] & 1) != 1 { // 单播包
		dstShard := vs.shards[getShardIdx(dstMAC)]
		dstShard.mu.RLock()
		if dEntry, dExists := dstShard.macTable[dstMAC]; dExists {
			targetPortID = dEntry.portID
		}
		dstShard.mu.RUnlock()
	}

	if targetPortID != "" && targetPortID != srcPortID {
		vs.sendToPort(targetPortID, frame)
	} else if targetPortID == "" {
		vs.flood(srcPortID, frame)
	}
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
	vs.portsMu.RLock()
	var targets []Port
	for id, port := range vs.ports {
		if id != excludePortID {
			targets = append(targets, port)
		}
	}
	vs.portsMu.RUnlock()
	for _, port := range targets {
		port.WriteFrame(frame)
	}
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
	SessionID   string
	Port        *AsyncPort
	IPv4        string
	IPv6        string
	MAC         string
	macBin      macKey // 会话注册 MAC 的二进制形式，VSwitch 源 MAC 归属校验用
	RxReorder   *ReorderBuffer
	FecDec      *fecDecoder       // XOR 奇偶校验解码器（req.FecGroup >= 2 时启用）
	FecEncK     int               // 下行 XOR 分组大小（0 表示未启用）
	FecMode     string            // 面板展示：xor:K / dup / off
	EncAlgo     int               // 内层加密算法号（encAlgoNone / encAlgoGCM）
	Encrypt     bool              // 建会话时 encrypt 的取值；仅用于面板展示，enc_algo 已足够区分
	SaltA       [encSaltSize]byte // c2s 方向盐（客户端加密/服务端解密）
	SaltB       [encSaltSize]byte // s2c 方向盐（服务端加密/客户端解密）
	icTx        *innerCipher      // s2c 加密器
	icRx        *innerCipher      // c2s 解密器
	pskHash     string            // 创建本会话时的 hashPSK（见 handleConnection 复活分支）
	InstanceID  string            // 客户端进程实例；变化时必须切换密钥代际
	Epoch       uint64            // 当前密钥代际
	ResumeToken string            // CSPRNG 会话持有证明
	CreatedAt   time.Time
	ActiveConns int
	TxBytes     uint64
	RxBytes     uint64
	TxPackets   uint64
	RxPackets   uint64
	// 会话保活与生命周期控制
	sessionMu    sync.Mutex
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
	brutalErr string // TCP Brutal 生效结果（""=已生效，非空=失败/跳过原因）
	linkedAt  int64  // 建立时间（unix 秒）
	brutalTx  uint64
	brutalRx  uint64
	epoch     uint64
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
	startedAt time.Time

	// minEnc 内层加密强度下限（minEncRank 值，0=不限）
	minEnc int
	// maxSessions 并发会话数上限（0=不限）。v6 地址池在 /64 下实际不会枯竭，
	// 无上限的会话创建等于把 OOM 做成持密者可远程触发的功能。
	maxSessions int
	// bootCfg 启动时配置：NeedsRestart 的差异基准（当前 s.cfg 是热更后的值）
	bootCfg *Config
	// sessionToken 开启后，重连既有会话必须回带握手响应下发的会话令牌。
	// 令牌只在原会话自己的 TLS 会话内下发一次，因此持密者知道 PSK+MAC
	// 仍无法冒充一个在线会话（否则其隧道流量会被转发给自己）。
	sessionToken bool

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
		icTx, err = newGCMInnerCipher(psk, saltB[:])
		if err != nil {
			return err
		}
		icRx, err = newGCMInnerCipher(psk, saltA[:])
		if err != nil {
			return err
		}
		fecTx, err = newGCMInnerCipherDomain(psk, saltB[:], "fec")
		if err != nil {
			return err
		}
		fecRx, err = newGCMInnerCipherDomain(psk, saltA[:], "fec")
		if err != nil {
			return err
		}
	}
	token, err := newSessionToken()
	if err != nil {
		return err
	}
	session.SaltA, session.SaltB = saltA, saltB
	session.icTx, session.icRx = icTx, icRx
	session.InstanceID = instanceID
	session.Epoch++
	session.ResumeToken = token
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
	for i := 0; i < ShardCount; i++ {
		shard := s.vswitch.shards[i]
		shard.mu.RLock()
		for mac, entry := range shard.macTable {
			out = append(out, MACEntry{MAC: fmtMAC(mac), Port: entry.portID, AgeSec: uint64(time.Since(entry.updatedAt) / time.Second)})
		}
		shard.mu.RUnlock()
	}
	return out
}

// snapshotServerConns 汇总所有会话的物理连接明细（面板"连接明细"页签）。
// 注意：此方法自行加读锁，不得在已持有 s.mu 时调用。
func (s *Server) snapshotServerConns() []serverConnSnapshot {
	now := time.Now().Unix()
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
				BrutalApplied: ci.brutalErr == "",
				BrutalErr:     ci.brutalErr,
				BrutalSrvTx:   ci.brutalTx,
				BrutalCliTx:   ci.brutalRx,
				Epoch:         ci.epoch,
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
	s.psk = cfg.PSK
	s.encrypt = cfg.Encrypt
	s.brutal, s.brutalUp, s.brutalDown = cfg.Brutal, cfg.BrutalUp, cfg.BrutalDown
	s.sessionToken = cfg.Server.SessionToken
	s.minEnc = minEncRank(cfg.MinEnc)
	s.maxSessions = cfg.Server.MaxSessions
	s.mu.Unlock()

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
	if o.Client.Conns != cfg.Client.Conns {
		out = append(out, "client.conns")
	}
	if o.Socks5 != cfg.Socks5 {
		out = append(out, "socks5")
	}
	return out
}

// startServer 以 JSON 配置启动服务端（cfg 已经过 applyDefaults + Validate）
func startServer(ctx context.Context, cfg *Config) {
	log.Infof("Starting TCP TLS server process...")
	_, v4net, _ := net.ParseCIDR(cfg.Server.V4CIDR)
	_, v6net, _ := net.ParseCIDR(cfg.Server.V6CIDR)

	srv := &Server{
		psk: cfg.PSK, v4Net: v4net, v6Net: v6net, usedV4: make(map[string]bool), usedV6: make(map[string]bool),
		vswitch: NewVSwitch(), brutal: cfg.Brutal, brutalUp: cfg.BrutalUp, brutalDown: cfg.BrutalDown,
		macAddr: cfg.Mac, activeClients: make(map[string]*ClientSession), macToIP: make(map[string]MacBinding),
		encrypt: cfg.Encrypt, startedAt: time.Now(),
		banned:       make(map[string]int64),
		pskFail:      make(map[string]*pskFailBucket),
		sessionToken: cfg.Server.SessionToken, minEnc: minEncRank(cfg.MinEnc),
		maxSessions: cfg.Server.MaxSessions,
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
		} else {
			// 先 up 再挂地址：bind 要求 IFF_UP，且 v6 在接口 up 的瞬间会
			// 重新触发一次 DAD —— 顺序反了第一轮 web 绑定就白等一个探测窗口
			if err := netlink.LinkSetUp(link); err != nil {
				log.Errorf("Server failed to bring up tap %s: %v", cfg.Tap, err)
			}
			assignTapGateway(link, "v4", srv.v4Gw, maskSize(v4net.Mask))
			assignTapGateway(link, "v6", srv.v6Gw, maskSize(v6net.Mask))
		}
	}
	srv.tap = tap

	go func() { <-ctx.Done(); srv.tap.Close() }()

	if cfg.Web.Addr != "" {
		go startWebServer(cfg.Web.Addr, srv, nil, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key, cfg)
	}

	tapBackend := make(chan []VPNFrame, 32)
	tapPort := NewAsyncPort(ctx, tapPortID, false)
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
		}
	}()

	go func() {
		buf := make([]byte, 65536)
		for {
			rn, err := srv.tap.Read(buf)
			if err != nil {
				return
			}
			// ProcessFrame 内部会拷贝进独立的池缓冲，直接复用本地缓冲
			srv.vswitch.ProcessFrame(tapPortID, buf[:rn])
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
	log.Infof("VPN Server listening on %s (TCP TLS, ALPN: h2)", cfg.Addr)

	serveListener(ctx, srv, listener, tlsConfig)
}

// assignTapGateway 在 tap 上配置一个隧道网关地址。
// 失败必须可见：地址没配上时隧道网关不可达，web.bind=tunnel 也会对着一个
// 不存在的地址反复 bind 失败，否则只能靠"面板连不上"反推。
func assignTapGateway(link netlink.Link, fam, ip string, prefix int) {
	if ip == "" {
		return
	}
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, prefix))
	if err != nil {
		log.Errorf("Server invalid %s gateway address %s/%d: %v", fam, ip, prefix, err)
		return
	}
	if fam == "v6" {
		// ULA 网关由配置指定，不存在需要探测的重复地址：挂上即 permanent，
		// 省掉内核 1~2s 的 DAD 窗口（取不到 RA 时地址会一直 tentative，v6 bind 永久失败）
		addr.Flags = ifaNoDAD
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		log.Errorf("Server failed to assign %s gateway %s/%d to %s: %v",
			fam, ip, prefix, link.Attrs().Name, err)
	}
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
				c.Close()
				return
			}

			prefixConn := &PrefixConn{Conn: c, prefix: peekBuf[:n]}
			if peekBuf[0] != 0x16 {
				// 非 TLS 流量（回退 HTTP / 扫描器）走默认小缓冲
				serveFallbackHTTP(prefixConn, "http/1.1")
				return
			}

			// 确认是 TLS 握手后才放大 socket 缓冲：扫描与回退连接不占内存。
			// 必须在 tls.Server 开始读取之前设置（内核要求首次 I/O 前）。
			c.SetReadBuffer(connReadBuf)
			c.SetWriteBuffer(connWriteBuf)

			tlsConn := tls.Server(prefixConn, tlsConfig)
			tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			err = tlsConn.Handshake()
			tlsConn.SetDeadline(time.Time{})
			if err != nil {
				tlsConn.Close()
				return
			}

			alpn := tlsConn.ConnectionState().NegotiatedProtocol
			peekBuf2 := make([]byte, 1)
			tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n2, err2 := tlsConn.Read(peekBuf2)
			tlsConn.SetReadDeadline(time.Time{})
			if err2 != nil || n2 == 0 {
				tlsConn.Close()
				return
			}

			prefixConn2 := &PrefixConn{Conn: tlsConn, prefix: peekBuf2[:n2]}
			if peekBuf2[0] >= 0x20 {
				serveFallbackHTTP(prefixConn2, alpn)
				return
			}

			srv.handleConnection(ctx, prefixConn2, c)
		}(conn)
	}
}

func (s *Server) handleConnection(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn) {
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
	minEnc := s.minEnc
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
	if encrypt && minEnc > 0 && req.EncAlgo != encAlgoGCM {
		log.Warnf("connection refused: client inner cipher (algo=%d) is below the min_enc floor, remote %s",
			req.EncAlgo, tcpConn.RemoteAddr().String())
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
		if exists && req.ProtocolVersion >= 2 && session.InstanceID != req.ClientInstance {
			if !verifyRandomSessionToken(session.ResumeToken, req.SessionToken) {
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
			log.Infof("[%s] rotated session key epoch to %d for a new client process instance", clientID, session.Epoch)
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
		// FEC 模式协商：req.FecGroup>=2 表示客户端请求 XOR 奇偶校验模式
		// （服务端对下行也用同参数编码）；否则维持传统逐帧复制模式。
		fecEncK := 0
		if req.ProtocolVersion >= 2 && req.FEC && int(req.FecGroup) >= fecMinGroup {
			fecEncK = clampFecGroup(int(req.FecGroup))
		}
		// 内层加密协商：encrypt 开启且客户端声明 GCM 能力时启用。会话盐每次
		// 建会话随机生成（c2s/s2c 各一个），服务端重启或会话重建即换盐，密钥流
		// 不再跨会话重用。GCM 是唯一内层算法，声明不了的就按明文协商——没有
		// 静默降级路径，面板上能直接看出这条会话到底有没有内层加密。
		saltA, saltB := newRandomSalt(), newRandomSalt()
		encAlgo := encAlgoNone
		var icTx, icRx, fecTx, fecRx *innerCipher
		if encrypt && req.EncAlgo == encAlgoGCM {
			encAlgo = encAlgoGCM
			icTx, _ = newGCMInnerCipher(psk, saltB[:]) // s2c
			icRx, _ = newGCMInnerCipher(psk, saltA[:]) // c2s
			fecTx, _ = newGCMInnerCipherDomain(psk, saltB[:], "fec")
			fecRx, _ = newGCMInnerCipherDomain(psk, saltA[:], "fec")
		}
		fecMode := "off"
		if fecEncK > 0 {
			fecMode = fmt.Sprintf("xor K=%d", fecEncK)
		} else if req.FEC {
			fecMode = "dup"
		}

		port := NewAsyncPort(parentCtx, clientID, req.FEC && fecEncK == 0)
		if fecEncK > 0 {
			port.AttachFEC(fecEncK, fecTx)
		}
		resumeToken, tokenErr := newSessionToken()
		if tokenErr != nil {
			delete(s.usedV4, v4ip)
			delete(s.usedV6, v6ip)
			port.Close()
			s.mu.Unlock()
			log.Errorf("[%s] failed to create a session token: %v", clientID, tokenErr)
			return
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
			s.vswitch.ProcessFrame(clientID, orderedFrame)
		})
		if fecEncK > 0 {
			session.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
		}
		s.activeClients[clientID] = session
		if mac != "" {
			s.macToIP[mac] = MacBinding{IPv4: v4ip, IPv6: v6ip}
		}
		s.vswitch.AddPort(port)
		log.Infof("[%s] new logical client online (FEC=%s EncAlgo=%d), Assigned IPs: %s, %s", clientID, fecMode, encAlgo, v4ip, v6ip)
	}

	v4ip, v6ip, port := session.IPv4, session.IPv6, session.Port
	sessionID := session.SessionID // 提取出来准备发给客户端
	encAlgo := session.EncAlgo
	icTx, icRx := session.icTx, session.icRx
	saltA, saltB := session.SaltA, session.SaltB
	resumeToken := session.ResumeToken
	fecEncK := session.FecEncK
	sessionEpoch := session.Epoch
	sessionEncrypt := session.Encrypt
	ci := &connInfo{
		remote:   tcpConn.RemoteAddr().String(),
		tcpConn:  tcpConn,
		linkedAt: time.Now().Unix(),
		epoch:    sessionEpoch,
	}
	// 注册本物理连接到会话，供 Web 面板踢出/展示明细
	session.sessionMu.Lock()
	session.conns[ci] = struct{}{}
	session.sessionMu.Unlock()
	// 速率整形参数在锁内快照，避免与 ApplyConfig 的写构成数据竞争
	brutal, brutalUp, brutalDown := s.brutal, s.brutalUp, s.brutalDown
	s.mu.Unlock()

	// serverTxRate = 服务端→客户端（下行），由本端 socket 整形；clientTxRate =
	// 客户端→服务端（上行），客户端自己整形，本端只裁进自己的上行预算内。
	serverTxRate, clientTxRate := negotiateBrutalRates(brutalUp, brutalDown, req.BrutalTx, req.BrutalRx)
	ci.brutalTx, ci.brutalRx = serverTxRate, clientTxRate

	if brutal && serverTxRate > 0 {
		if e := applyTCPBrutal(tcpConn, serverTxRate); e != nil {
			ci.brutalErr = e.Error()
			log.Warnf("[%s] TCP Brutal shaping skipped: %v", clientID, e)
		}
	}

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))
	// 响应带协商结果：FEC XOR 分组大小 + 内层加密算法与两个方向的会话盐。
	// GCM 未启用时不下发盐值（客户端也不启用加密器）。
	encSalt, encSalt2 := "", ""
	if encAlgo == encAlgoGCM {
		encSalt = hex.EncodeToString(saltA[:])  // c2s
		encSalt2 = hex.EncodeToString(saltB[:]) // s2c
	}
	// 会话令牌：仅原会话持有者可重连接管（见 handleConnection 的校验分支）
	s.sendResp(conn, true, "OK", clientID, sessionID, v4cidr, v6cidr, clientTxRate, serverTxRate, req.FEC, uint32(fecEncK), encAlgo, encSalt, encSalt2, resumeToken, sessionEncrypt, req.ProtocolVersion, sessionEpoch)

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	ci.rttCache = rttCache
	go startRTTPoller(connCtx, tcpConn, rttCache)

	connTxChan := make(chan []VPNFrame, 32)
	port.RegisterBackend(connTxChan, rttCache)

	defer func() {
		port.UnregisterBackend(connTxChan)
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

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		keepAliveTicker := time.NewTicker(4 * time.Second)
		defer keepAliveTicker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case frames := <-connTxChan:
				sendBuffer = sendBuffer[:0]
				for _, vf := range frames {
					sendBuffer = appendPaddedFrame(sendBuffer, vf, icTx)
				}
				// 副本所有权归本协程：发送后无条件归还（深拷贝分发保证独立）
				freeFrames(frames)
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, werr := conn.Write(sendBuffer)
				conn.SetWriteDeadline(time.Time{})
				if werr != nil {
					log.Debugf("[%s] downstream write failed, closing the connection: %v", clientID, werr)
					conn.Close()
					return
				}
				atomic.AddUint64(&session.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&session.TxPackets, uint64(len(frames)))
				atomic.AddUint64(&ci.txBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&ci.txPackets, uint64(len(frames)))
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil)
				if _, err := conn.Write(sendBuffer); err != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	// 认证已通过：恢复数据帧的线路全量上限（jumbo 帧合法）
	scanner.SetMaxDataLen(maxWireDataLen)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, seq, err := scanner.ReadFrame()
		if err != nil {
			log.Debugf("[%s] connection lost: %v", clientID, err)
			return
		}

		if err == nil && frame != nil {
			session.sessionMu.Lock()
			currentEpoch := session.Epoch
			fecDec := session.FecDec
			rxReorder := session.RxReorder
			session.sessionMu.Unlock()
			if ci.epoch != currentEpoch {
				putFrame(frame)
				return
			}
			atomic.AddUint64(&session.RxBytes, uint64(len(frame)))
			atomic.AddUint64(&session.RxPackets, 1)
			atomic.AddUint64(&ci.rxBytes, uint64(len(frame)))
			atomic.AddUint64(&ci.rxPackets, 1)
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

func (s *Server) sendResp(w io.Writer, ok bool, msg, clientID, sessionID, v4cidr, v6cidr string, cliTx, srvTx uint64, fec bool, fecGroup uint32, encAlgo int, encSalt, encSalt2, sessionToken string, encrypt bool, protocolVersion int, epoch uint64) {
	resp := HandshakeResp{
		ProtocolVersion: protocolVersion, SessionEpoch: epoch,
		Success: ok, Message: msg, ClientID: clientID, SessionID: sessionID, IPv4: v4cidr, IPv6: v6cidr,
		// BrutalTx/Rx 是客户端视角的上行/下行：cliTx 是客户端自己整形的上行速率，
		// srvTx 是本端整形的下行速率（即客户端的 rx）。本端自己的 tx 是下行、不是上行，
		// 传错方向会让两端视角整个对调——面板表现为上行显示下行预算。
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500), BrutalTx: cliTx, BrutalRx: srvTx,
		FEC: fec, FecGroup: int(fecGroup), Encrypt: encrypt, EncAlgo: encAlgo, EncSalt: encSalt, EncSalt2: encSalt2,
		SessionToken: sessionToken,
	}
	log.Debugf("[%s] => handshake response session=%s proto=%d epoch=%d fec=%v/%d enc=%v/%d token_present=%v",
		clientID, sessionID, protocolVersion, epoch, fec, fecGroup, encrypt, encAlgo, sessionToken != "")
	d, _ := json.Marshal(resp)
	writeStreamFrame(w, d)
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
type memTap struct {
	ctx      context.Context
	TxBytes  atomic.Uint64 // 写入（即隧道向该 TAP 交付）的字节数
	TxPkts   atomic.Uint64
	onWrite  func([]byte) // 测试钩子：每帧交付回调（可为 nil）
	onWriteM sync.Mutex
}

func newMemTap(ctx context.Context) *memTap { return &memTap{ctx: ctx} }

// SetOnWrite 注册写入回调（测试观测用）
func (m *memTap) SetOnWrite(f func([]byte)) {
	m.onWriteM.Lock()
	m.onWrite = f
	m.onWriteM.Unlock()
}

func (m *memTap) Read(p []byte) (int, error) {
	<-m.ctx.Done()
	return 0, io.EOF
}

func (m *memTap) Write(p []byte) (int, error) {
	m.TxBytes.Add(uint64(len(p)))
	m.TxPkts.Add(1)
	m.onWriteM.Lock()
	hook := m.onWrite
	m.onWriteM.Unlock()
	if hook != nil {
		hook(p)
	}
	return len(p), nil
}

func (m *memTap) Close() error { return nil }

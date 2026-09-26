package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// evtJSON 面板"事件"页与 SSE 通道共用的事件记录。
// seq 让面板断线后用最后一条 seq 增量续传；time 是服务端格式化的时间戳，
// 面板直接显示，不在浏览器侧做任何时钟换算（本机与服务端时钟可能不一致）。
type evtJSON struct {
	Seq    uint64 `json:"seq"`
	Time   string `json:"time"`
	Type   string `json:"type"`
	Level  string `json:"level"`
	Client string `json:"client,omitempty"`
	Msg    string `json:"msg"`
}

// eventBus 内存事件环形缓冲 + SSE 订阅者集合。
// 与 logRing 同样只留最近 cap 条：面板要的是"刚发生了什么"，长期留痕归日志文件，
// 内存不能随进程运行时长线性增长。
type eventBus struct {
	mu   sync.Mutex
	seq  uint64
	cap  int
	ring []evtJSON
	subs []*eventSub
}

type eventSub struct{ ch chan evtJSON }

func newEventBus(capacity int) *eventBus {
	return &eventBus{cap: capacity}
}

// emit 记一条事件并推给全部订阅者。永不阻塞、永不失败：
// 发射点落在服务端握手与连接清理路径上（部分持有 s.mu），这里必须只碰自己的锁，
// 对跟不上节奏的消费者直接丢弃，绝不能让协议路径去等一个浏览器。
func (b *eventBus) emit(typ, level, client, msg string) {
	b.mu.Lock()
	b.seq++
	e := evtJSON{
		Seq:    b.seq,
		Time:   time.Now().Format("15:04:05.000"),
		Type:   typ,
		Level:  level,
		Client: client,
		Msg:    msg,
	}
	b.ring = append(b.ring, e)
	if len(b.ring) > b.cap {
		b.ring = b.ring[len(b.ring)-b.cap:]
	}
	for _, s := range b.subs {
		select {
		case s.ch <- e:
		default: // 消费者缓冲已满就丢这条，别阻塞生产者
		}
	}
	b.mu.Unlock()
}

// snapshot 返回 seq 大于 after 的事件，供面板首次打开或断线重连时补齐空档。
func (b *eventBus) snapshot(after uint64) []evtJSON {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]evtJSON, 0, 64)
	for _, e := range b.ring {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

// subscribe 返回订阅者与取消函数。带缓冲用于吸收短暂抖动，满则丢最旧。
func (b *eventBus) subscribe() (*eventSub, func()) {
	b.mu.Lock()
	s := &eventSub{ch: make(chan evtJSON, 256)}
	b.subs = append(b.subs, s)
	b.mu.Unlock()
	return s, func() {
		b.mu.Lock()
		for i, x := range b.subs {
			if x == s {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
	}
}

// evBus 进程内唯一实例。事件是给人看的旁路信息，没有跨进程含义。
var evBus = newEventBus(500)

// handleEvents GET /api/events。
// 默认是 SSE 流：先回放 after 之后的积压，再转发实时事件；
// 25 秒一条注释心跳，避免中间的代理或网关把空闲长连接判定超时。
// stream=0 时退化为一次性的 JSON 增量快照——浏览器 EventSource 带不了
// Authorization 头，-web-auth 生效时面板只能走这条轮询路径。
func handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	q := r.URL.Query()
	after := uint64(0)
	if v := q.Get("after"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			after = n
		}
	}
	if q.Get("stream") == "0" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(evBus.snapshot(after))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	for _, e := range evBus.snapshot(after) {
		writeSSE(w, flusher, e)
	}

	sub, cancel := evBus.subscribe()
	defer cancel()

	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-sub.ch:
			if !ok {
				return
			}
			writeSSE(w, flusher, e)
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, e evtJSON) {
	data, _ := json.Marshal(e)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEventBusRingSnapshotSubscribe(t *testing.T) {
	b := newEventBus(5)
	b.emit("connect", "info", "cid-1", "IPv4 10.0.0.2 · IPv6 ::")
	b.emit("ban", "warn", "cid-1", "permanent")

	got := b.snapshot(0)
	if len(got) != 2 {
		t.Fatalf("snapshot returned %d events, want 2", len(got))
	}
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("seqs = %d,%d want 1,2", got[0].Seq, got[1].Seq)
	}
	if got[1].Client != "cid-1" || got[1].Level != "warn" || got[1].Type != "ban" {
		t.Fatalf("event[1] = %+v", got[1])
	}
	if got[0].Time == "" {
		t.Fatal("time stamp empty")
	}

	// 增量续传：只返回 seq 大于 after 的
	if got := b.snapshot(1); len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("snapshot(1) = %+v", got)
	}

	// 环形上限：超出后只留最近 cap 条，最旧的 seq 被挤掉
	b.emit("down", "info", "", "conn 0: eof")
	b.emit("up", "info", "", "conn 1 linked")
	b.emit("deny", "warn", "", "hash mismatch; remote 1.2.3.4:1000")
	b.emit("limit", "warn", "", "remote 1.2.3.4:1001")
	if got := b.snapshot(0); len(got) != 5 || got[0].Seq != 2 || got[len(got)-1].Seq != 6 {
		t.Fatalf("ring after overflow = %d events, first seq %d", len(got), got[0].Seq)
	}

	// 订阅者收到实时事件
	sub, cancel := b.subscribe()
	b.emit("gc", "info", "", "manual memory reclaim")
	select {
	case e := <-sub.ch:
		if e.Type != "gc" || e.Seq != 7 {
			t.Fatalf("subscriber got %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber timed out")
	}

	// 取消后不再收到
	cancel()
	b.emit("kick", "warn", "cid-1", "kicked")
	select {
	case e := <-sub.ch:
		t.Fatalf("subscriber still got %+v after cancel", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// readSSEFrame 从 SSE 流里读一个以空行结尾的 data 帧，超时返回错误。
func readSSEFrame(r io.Reader, timeout time.Duration) (string, error) {
	type result struct {
		data string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		buf := new(bytes.Buffer)
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				ch <- result{"", err}
				return
			}
			if strings.TrimSpace(line) == "" {
				ch <- result{strings.TrimPrefix(buf.String(), "data: "), nil}
				return
			}
			buf.WriteString(line)
		}
	}()
	select {
	case res := <-ch:
		return res.data, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out reading an SSE frame")
	}
}

func TestHandleEventsSnapshotMode(t *testing.T) {
	before := evBus.snapshot(0)
	afterSeq := uint64(0)
	if len(before) > 0 {
		afterSeq = before[len(before)-1].Seq
	}
	evBus.emit("up", "info", "", "conn 0 linked")

	w := httptest.NewRecorder()
	handleEvents(w, httptest.NewRequest("GET",
		"/api/events?stream=0&after="+strconv.FormatUint(afterSeq, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var got []evtJSON
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if len(got) != 1 || got[0].Type != "up" {
		t.Fatalf("snapshot = %+v", got)
	}

	// 非 GET 拒绝
	w2 := httptest.NewRecorder()
	handleEvents(w2, httptest.NewRequest("POST", "/api/events", nil))
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d want 405", w2.Code)
	}
}

func TestHandleEventsSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(handleEvents))
	defer srv.Close()

	// evBus 是全局的：先记下已有 seq，只回放本次用例发射的事件
	before := evBus.snapshot(0)
	afterSeq := uint64(0)
	if len(before) > 0 {
		afterSeq = before[len(before)-1].Seq
	}

	// 连接前就有的事件应作为积压回放
	evBus.emit("connect", "info", "cid-1", "IPv4 10.0.0.2 · IPv6 ::")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/api/events?after="+strconv.FormatUint(afterSeq, 10), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Fatalf("cache-control = %q", cc)
	}

	replay, err := readSSEFrame(resp.Body, 2*time.Second)
	if err != nil {
		t.Fatalf("reading the replay frame: %v", err)
	}
	var e evtJSON
	if err := json.Unmarshal([]byte(replay), &e); err != nil {
		t.Fatalf("replay frame %q: %v", replay, err)
	}
	if e.Type != "connect" || e.Client != "cid-1" {
		t.Fatalf("replay frame = %+v", e)
	}

	// 订阅建立后应收到实时事件；重试发射以跨过回放与订阅之间的极短窗口
	var live evtJSON
	deadline := time.Now().Add(3 * time.Second)
	for {
		evBus.emit("kick", "warn", "cid-1", "kicked")
		chunk, err := readSSEFrame(resp.Body, 500*time.Millisecond)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("no live frame: %v", err)
			}
			continue
		}
		if err := json.Unmarshal([]byte(chunk), &live); err != nil {
			t.Fatalf("live frame %q: %v", chunk, err)
		}
		if live.Type == "kick" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the kick frame")
		}
	}
	if live.Level != "warn" || live.Client != "cid-1" {
		t.Fatalf("live frame = %+v", live)
	}

	// 客户端断开后处理协程要能退出，不能挂着
	cancel()
	if _, err = io.ReadAll(resp.Body); err == nil {
		t.Fatal("response body did not close after the request context was cancelled")
	}
}

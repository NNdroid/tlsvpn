package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dashboardCapture lets the SSE endpoint reuse startWebStatsHandler verbatim so
// the streamed stats and the compatibility /api/stats response can never drift.
type dashboardCapture struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (c *dashboardCapture) Header() http.Header {
	if c.header == nil {
		c.header = make(http.Header)
	}
	return c.header
}
func (c *dashboardCapture) WriteHeader(code int) { c.status = code }
func (c *dashboardCapture) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(p)
}

func dashboardStatsBytes(r *http.Request, srv *Server, cli *Client) ([]byte, error) {
	c := &dashboardCapture{}
	startWebStatsHandler(c, r, srv, cli)
	if c.status >= 400 {
		return nil, fmt.Errorf("stats snapshot status %d", c.status)
	}
	return bytes.TrimSpace(c.body.Bytes()), nil
}

func dashboardTrendSnapshot(rng string) trendSnapshotJSON {
	switch rng {
	case "2m":
		return dailyTraffic.RecentSnapshot()
	case "24h":
		return dailyTraffic.TrendSnapshot(1440)
	default:
		return dailyTraffic.TrendSnapshot(60)
	}
}

func dashboardQueryUint(r *http.Request, key string) uint64 {
	v, _ := strconv.ParseUint(r.URL.Query().Get(key), 10, 64)
	return v
}

func dashboardStreamInterval(r *http.Request) time.Duration {
	ms, _ := strconv.Atoi(r.URL.Query().Get("interval_ms"))
	if ms <= 0 {
		ms = 2000
	}
	if ms < 250 {
		ms = 250
	}
	if ms > 10000 {
		ms = 10000
	}
	return time.Duration(ms) * time.Millisecond
}

func writeDashboardSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload []byte) error {
	if len(payload) == 0 {
		payload = []byte("null")
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func writeDashboardJSON(w http.ResponseWriter, flusher http.Flusher, event string, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeDashboardSSE(w, flusher, event, b)
}

// handleDashboardStream is the browser dashboard's single live transport.
// /api/stats, /api/trend, /api/logs and /api/events remain as compatibility
// APIs for scripts/tests, but the WebUI consumes all periodic data from here.
func handleDashboardStream(w http.ResponseWriter, r *http.Request, srv *Server, cli *Client) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	rng := strings.TrimSpace(r.URL.Query().Get("range"))
	if rng != "2m" && rng != "24h" {
		rng = "1h"
	}
	logAfter := dashboardQueryUint(r, "log_after")
	eventAfter := dashboardQueryUint(r, "event_after")
	if id := r.URL.Query().Get("instance_id"); id != "" && id != dashboardInstanceID {
		logAfter, eventAfter = 0, 0
	}
	interval := dashboardStreamInterval(r)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	emit := func() error {
		stats, err := dashboardStatsBytes(r, srv, cli)
		if err != nil {
			return err
		}
		if err := writeDashboardSSE(w, flusher, "stats", stats); err != nil {
			return err
		}
		if err := writeDashboardJSON(w, flusher, "trend", dashboardTrendSnapshot(rng)); err != nil {
			return err
		}

		logs := logRing.snapshot(logAfter)
		if len(logs) > 0 {
			logAfter = logs[len(logs)-1].Seq
			if err := writeDashboardJSON(w, flusher, "logs", logs); err != nil {
				return err
			}
		}
		events := evBus.snapshot(eventAfter)
		if len(events) > 0 {
			eventAfter = events[len(events)-1].Seq
			if err := writeDashboardJSON(w, flusher, "events", events); err != nil {
				return err
			}
		}
		return nil
	}

	if emit() != nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if emit() != nil {
				return
			}
		}
	}
}

package main

import (
    "os"
    "strings"
    "testing"
)

func TestWebUIUsesUnifiedSSEWithoutPolling(t *testing.T) {
    app, err := os.ReadFile("webui/app.js")
    if err != nil { t.Fatal(err) }
    s := string(app)
    forbidden := []string{
        "fetch(url('/api/stats')", "fetch(url('/api/trend')", "fetch(url('/api/logs')",
        "fetch(url('/api/events')", "setInterval(fetchStats", "setInterval(fetchTrend",
        "setInterval(pollLogs", "EV_POLL_MS",
    }
    for _, x := range forbidden {
        if strings.Contains(s, x) { t.Fatalf("legacy polling marker remains: %s", x) }
    }
    stream, err := os.ReadFile("webui/stream.js")
    if err != nil { t.Fatal(err) }
    ss := string(stream)
    for _, x := range []string{"/api/stream", "EventSource", "applyStats(payload)", "applyTrend(payload)", "applyLogs(payload)", "applyEvents(payload)"} {
        if !strings.Contains(ss, x) { t.Fatalf("stream.js missing %q", x) }
    }
}

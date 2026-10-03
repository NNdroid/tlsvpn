package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpMaxRequestBodyBytes = 1 << 20

type mcpEmptyInput struct{}

type mcpRangeInput struct {
	Range string `json:"range,omitempty" jsonschema:"time range: 2m, 1h, or 24h"`
}

type mcpCursorInput struct {
	After uint64 `json:"after,omitempty" jsonschema:"return records with sequence numbers greater than this cursor"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum records to return; defaults to 200 and is capped at 1000"`
}

type mcpClientInput struct {
	ClientID string `json:"client_id" jsonschema:"tlsvpn client identifier"`
}

type mcpBanInput struct {
	ClientID   string `json:"client_id" jsonschema:"tlsvpn client identifier"`
	TTLMinutes int    `json:"ttl_minutes" jsonschema:"ban duration in minutes; 0 means permanent, otherwise use 1 through 10080"`
}

type mcpLogLevelInput struct {
	Level string `json:"level" jsonschema:"runtime log level such as debug, info, warn, or error"`
}

type mcpConfigInput struct {
	Config map[string]any `json:"config" jsonschema:"complete tlsvpn configuration object; redacted secrets may be left empty to preserve current values"`
}

type mcpConfigSaveInput struct {
	Config map[string]any `json:"config" jsonschema:"complete tlsvpn configuration object; redacted secrets may be left empty to preserve current values"`
	Apply  bool           `json:"apply,omitempty" jsonschema:"apply hot-reloadable settings immediately after saving"`
}

func boolPtr(v bool) *bool { return &v }

func newMCPHTTPHandler(w *WebManager) http.Handler {
	server := newMCPServer(w)
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		MaxRequestBodyBytes:          mcpMaxRequestBodyBytes,
		PropagateRequestCancellation: true,
	})
}

func newMCPServer(w *WebManager) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "tlsvpn", Version: appVersion}, &mcp.ServerOptions{
		Instructions: "Inspect and administer this tlsvpn process. Prefer read-only tools first. Validate configuration before saving it, and only invoke disruptive tools when explicitly requested.",
	})

	registerMCPReadTools(s, w)
	registerMCPWriteTools(s, w)
	registerMCPResources(s, w)
	registerMCPPrompts(s)
	return s
}

func readOnlyTool(name, description string) *mcp.Tool {
	return &mcp.Tool{
		Name:        name,
		Description: description,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func writeTool(name, description string, destructive, idempotent bool) *mcp.Tool {
	return &mcp.Tool{
		Name:        name,
		Description: description,
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: boolPtr(destructive),
			IdempotentHint:  idempotent,
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func registerMCPReadTools(s *mcp.Server, w *WebManager) {
	mcp.AddTool(s, readOnlyTool("tlsvpn_status", "Return the complete live tlsvpn status snapshot for the current server or client process."),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			stats, err := mcpCurrentStats(ctx, w)
			return &mcp.CallToolResult{}, stats, err
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_connections", "Return active client/session/physical-connection information, including bans and MAC table state where available."),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			stats, err := mcpCurrentStats(ctx, w)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{}, map[string]any{
				"mode":           stats.Mode,
				"active_clients": stats.ActiveClients,
				"live_conns":     stats.LiveConns,
				"clients":        stats.Clients,
				"client_conns":   stats.Conns,
				"server_conns":   stats.ServerConns,
				"mac_table":      stats.MACs,
				"banned":         stats.Banned,
				"peer":           stats.Peer,
			}, nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_config_get", "Return the currently effective configuration with PSK, Web authentication and SOCKS5 credentials redacted."),
		func(context.Context, *mcp.CallToolRequest, mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, mcpRedactedConfig(w.Config()), nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_diagnostics", "Return sampled diagnostic history for 2m, 1h or 24h."),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpRangeInput) (*mcp.CallToolResult, any, error) {
			rng, err := mcpRange(in.Range)
			if err != nil {
				return nil, nil, err
			}
			if w.diagnostics == nil {
				return &mcp.CallToolResult{}, map[string]any{"available": false, "range": rng}, nil
			}
			return &mcp.CallToolResult{}, w.diagnostics.snapshot(rng), nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_traffic", "Return throughput and RTT trend samples for 2m, 1h or 24h."),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpRangeInput) (*mcp.CallToolResult, any, error) {
			rng, err := mcpRange(in.Range)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{}, dashboardTrendSnapshot(rng), nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_logs", "Read the in-memory log ring using an incremental sequence cursor."),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpCursorInput) (*mcp.CallToolResult, any, error) {
			limit, err := mcpLimit(in.Limit)
			if err != nil {
				return nil, nil, err
			}
			items := logRing.snapshot(in.After)
			if len(items) > limit {
				items = items[:limit]
			}
			next := in.After
			if len(items) > 0 {
				next = items[len(items)-1].Seq
			}
			return &mcp.CallToolResult{}, map[string]any{"items": items, "next_after": next}, nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_events", "Read tlsvpn lifecycle and administration events using an incremental sequence cursor."),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpCursorInput) (*mcp.CallToolResult, any, error) {
			limit, err := mcpLimit(in.Limit)
			if err != nil {
				return nil, nil, err
			}
			items := evBus.snapshot(in.After)
			if len(items) > limit {
				items = items[:limit]
			}
			next := in.After
			if len(items) > 0 {
				next = items[len(items)-1].Seq
			}
			return &mcp.CallToolResult{}, map[string]any{"items": items, "next_after": next}, nil
		})

	mcp.AddTool(s, readOnlyTool("tlsvpn_config_validate", "Validate a complete configuration without writing or applying it. Empty redacted secrets preserve the current values."),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpConfigInput) (*mcp.CallToolResult, any, error) {
			raw, err := mcpConfigJSON(in.Config)
			if err != nil {
				return nil, nil, err
			}
			cfg, needsRestart, err := mergeAndValidateConfig(w.Config(), raw, false, w.srv, w.cli)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{}, map[string]any{
				"valid":         true,
				"needs_restart": needsRestart,
				"config":        mcpRedactedConfig(cfg),
			}, nil
		})
}

func registerMCPWriteTools(s *mcp.Server, w *WebManager) {
	mcp.AddTool(s, writeTool("tlsvpn_set_log_level", "Change the process runtime log level.", false, true),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpLogLevelInput) (*mcp.CallToolResult, any, error) {
			if err := setRuntimeLogLevel(strings.TrimSpace(in.Level)); err != nil {
				return nil, nil, err
			}
			level := currentLogLevelName()
			log.Infof("[MCP] Log level set to %s", level)
			evBus.emit("loglevel", "info", "", level)
			return &mcp.CallToolResult{}, map[string]any{"level": level}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_force_reconnect", "Client mode only: tear down all current tunnel connections and redial them.", true, false),
		func(context.Context, *mcp.CallToolRequest, mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			if w.cli == nil {
				return nil, nil, fmt.Errorf("force reconnect is only available in client mode")
			}
			w.cli.ForceReconnect()
			log.Infof("[MCP] Forced reconnect triggered")
			evBus.emit("reconnect", "warn", "", "all tunnels torn down and re-dialed by MCP")
			return &mcp.CallToolResult{}, map[string]any{"reconnect_requested": true}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_kick_client", "Server mode only: disconnect one client session.", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpClientInput) (*mcp.CallToolResult, any, error) {
			if w.srv == nil {
				return nil, nil, fmt.Errorf("kick client is only available in server mode")
			}
			id := strings.TrimSpace(in.ClientID)
			if id == "" {
				return nil, nil, fmt.Errorf("client_id is required")
			}
			w.srv.mu.RLock()
			session, exists := w.srv.activeClients[id]
			w.srv.mu.RUnlock()
			if !exists {
				return nil, nil, fmt.Errorf("client %q is not active", id)
			}
			w.srv.kickSession(session)
			log.Infof("[MCP] Kicked client %s", id)
			return &mcp.CallToolResult{}, map[string]any{"client_id": id, "kicked": true}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_ban_client", "Server mode only: ban a client identifier for a bounded TTL and disconnect it if active.", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpBanInput) (*mcp.CallToolResult, any, error) {
			if w.srv == nil {
				return nil, nil, fmt.Errorf("ban client is only available in server mode")
			}
			id := strings.TrimSpace(in.ClientID)
			if id == "" {
				return nil, nil, fmt.Errorf("client_id is required")
			}
			if in.TTLMinutes < 0 || in.TTLMinutes > 7*24*60 {
				return nil, nil, fmt.Errorf("ttl_minutes must be 0 (permanent) or between 1 and 10080")
			}
			ttl := time.Duration(in.TTLMinutes) * time.Minute
			if !w.srv.Ban(id, ttl) {
				return nil, nil, fmt.Errorf("unable to ban client %q", id)
			}
			log.Infof("[MCP] Banned client %s (ttl=%s)", id, ttl)
			return &mcp.CallToolResult{}, map[string]any{"client_id": id, "banned": true, "ttl_minutes": in.TTLMinutes}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_unban_client", "Server mode only: remove a client identifier from the ban list.", false, true),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpClientInput) (*mcp.CallToolResult, any, error) {
			if w.srv == nil {
				return nil, nil, fmt.Errorf("unban client is only available in server mode")
			}
			id := strings.TrimSpace(in.ClientID)
			if id == "" {
				return nil, nil, fmt.Errorf("client_id is required")
			}
			w.srv.Unban(id)
			log.Infof("[MCP] Unbanned client %s", id)
			return &mcp.CallToolResult{}, map[string]any{"client_id": id, "banned": false}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_kick_all_clients", "Server mode only: disconnect every active client session.", true, false),
		func(context.Context, *mcp.CallToolRequest, mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			if w.srv == nil {
				return nil, nil, fmt.Errorf("kick all clients is only available in server mode")
			}
			w.srv.mu.RLock()
			sessions := make([]*ClientSession, 0, len(w.srv.activeClients))
			for _, session := range w.srv.activeClients {
				sessions = append(sessions, session)
			}
			w.srv.mu.RUnlock()
			for _, session := range sessions {
				w.srv.kickSession(session)
			}
			log.Infof("[MCP] Kicked all clients (%d)", len(sessions))
			return &mcp.CallToolResult{}, map[string]any{"kicked": len(sessions)}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_gc", "Force Go to return as much unused memory as possible to the operating system.", false, false),
		func(context.Context, *mcp.CallToolRequest, mcpEmptyInput) (*mcp.CallToolResult, any, error) {
			debug.FreeOSMemory()
			log.Infof("[MCP] Manual GC triggered")
			evBus.emit("gc", "info", "", "manual memory reclaim by MCP")
			return &mcp.CallToolResult{}, map[string]any{"gc_triggered": true}, nil
		})

	mcp.AddTool(s, writeTool("tlsvpn_config_save", "Validate and atomically save a complete configuration. Optionally hot-apply settings that support runtime reload.", true, false),
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpConfigSaveInput) (*mcp.CallToolResult, any, error) {
			raw, err := mcpConfigJSON(in.Config)
			if err != nil {
				return nil, nil, err
			}
			newCfg, needsRestart, err := mergeAndValidateConfig(w.Config(), raw, in.Apply, w.srv, w.cli)
			if err != nil {
				return nil, nil, err
			}
			if err := SaveConfigFile(newCfg); err != nil {
				return nil, nil, err
			}
			if in.Apply {
				if err := setRuntimeLogLevel(newCfg.LogLevel); err != nil {
					return nil, nil, err
				}
				w.SetConfig(newCfg)
				dailyTraffic.OnConfig(newCfg)
				if w.srv != nil {
					w.srv.ApplyConfig(newCfg)
				}
				if w.cli != nil {
					w.cli.ApplyConfig(newCfg)
				}
			}
			log.Infof("[MCP] Config saved (apply=%v, needs_restart=%v)", in.Apply, needsRestart)
			evBus.emit("config", "info", "", fmt.Sprintf("mcp save (apply=%v, needs_restart=%v)", in.Apply, needsRestart))
			return &mcp.CallToolResult{}, map[string]any{
				"saved":         true,
				"applied":       in.Apply,
				"needs_restart": needsRestart,
				"config":        mcpRedactedConfig(newCfg),
			}, nil
		})
}

func registerMCPResources(s *mcp.Server, w *WebManager) {
	addJSONResource := func(uri string, snapshot func(context.Context) (any, error)) {
		s.AddResource(&mcp.Resource{URI: uri, MIMEType: "application/json"},
			func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				value, err := snapshot(ctx)
				if err != nil {
					return nil, err
				}
				text, err := json.MarshalIndent(value, "", "  ")
				if err != nil {
					return nil, err
				}
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(text)}}}, nil
			})
	}

	addJSONResource("tlsvpn://status", func(ctx context.Context) (any, error) {
		return mcpCurrentStats(ctx, w)
	})
	addJSONResource("tlsvpn://connections", func(ctx context.Context) (any, error) {
		stats, err := mcpCurrentStats(ctx, w)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"mode":           stats.Mode,
			"active_clients": stats.ActiveClients,
			"live_conns":     stats.LiveConns,
			"clients":        stats.Clients,
			"client_conns":   stats.Conns,
			"server_conns":   stats.ServerConns,
			"mac_table":      stats.MACs,
			"banned":         stats.Banned,
			"peer":           stats.Peer,
		}, nil
	})
	addJSONResource("tlsvpn://config", func(context.Context) (any, error) {
		return mcpRedactedConfig(w.Config()), nil
	})
	addJSONResource("tlsvpn://diagnostics", func(context.Context) (any, error) {
		if w.diagnostics == nil {
			return map[string]any{"available": false, "range": "1h"}, nil
		}
		return w.diagnostics.snapshot("1h"), nil
	})
	addJSONResource("tlsvpn://traffic", func(context.Context) (any, error) {
		return dashboardTrendSnapshot("1h"), nil
	})
}

func registerMCPPrompts(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{Name: "diagnose_tlsvpn", Arguments: []*mcp.PromptArgument{{Name: "focus", Description: "optional symptom or subsystem to focus on", Required: false}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			focus := strings.TrimSpace(req.Params.Arguments["focus"])
			text := "Diagnose this tlsvpn instance. Read tlsvpn_status, tlsvpn_diagnostics, tlsvpn_events and relevant recent tlsvpn_logs first. Correlate tunnel, FEC, scheduler, TCP, route, TAP, memory and protection signals. Explain evidence, likely root cause and the least disruptive next action. Do not mutate state unless the user explicitly asks."
			if focus != "" {
				text += " Focus especially on: " + focus + "."
			}
			return &mcp.GetPromptResult{Description: "Evidence-driven tlsvpn diagnosis", Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}, nil
		})

	s.AddPrompt(&mcp.Prompt{Name: "optimize_tlsvpn", Arguments: []*mcp.PromptArgument{{Name: "goal", Description: "optional optimization goal such as throughput, latency, reliability, or memory", Required: false}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			goal := strings.TrimSpace(req.Params.Arguments["goal"])
			text := "Optimize this tlsvpn instance conservatively. Inspect tlsvpn_status, tlsvpn_traffic, tlsvpn_diagnostics and tlsvpn_config_get. Separate observed bottlenecks from guesses. For configuration changes, call tlsvpn_config_validate before tlsvpn_config_save, explain any needs_restart fields, and avoid disruptive actions without explicit approval."
			if goal != "" {
				text += " Primary goal: " + goal + "."
			}
			return &mcp.GetPromptResult{Description: "Conservative tlsvpn optimization workflow", Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}, nil
		})

	s.AddPrompt(&mcp.Prompt{Name: "security_audit_tlsvpn", Arguments: []*mcp.PromptArgument{{Name: "scope", Description: "optional security audit scope", Required: false}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			scope := strings.TrimSpace(req.Params.Arguments["scope"])
			text := "Audit this tlsvpn instance for operational security. Inspect the redacted effective configuration, protection counters, bans, connections, recent events and logs. Pay attention to exposed Web/MCP binding, TLS, authentication, PSK failures, spoofing/drop counters and unexpected peers. Do not reveal secrets or change state unless explicitly requested."
			if scope != "" {
				text += " Scope: " + scope + "."
			}
			return &mcp.GetPromptResult{Description: "Read-only tlsvpn security audit", Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}, nil
		})
}

func mcpCurrentStats(ctx context.Context, w *WebManager) (WebStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://tlsvpn.local/api/stats", nil)
	if err != nil {
		return WebStats{}, err
	}
	body, err := dashboardStatsBytes(req, w.srv, w.cli)
	if err != nil {
		return WebStats{}, err
	}
	var stats WebStats
	if err := json.Unmarshal(body, &stats); err != nil {
		return WebStats{}, fmt.Errorf("decode status snapshot: %w", err)
	}
	return stats, nil
}

func mcpRedactedConfig(cfg *Config) Config {
	redacted := *cfg
	redacted.PSK = ""
	redacted.Web.Auth = ""
	redacted.Socks5 = ""
	return redacted
}

func mcpRange(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "1h":
		return "1h", nil
	case "2m":
		return "2m", nil
	case "24h":
		return "24h", nil
	default:
		return "", fmt.Errorf("range must be one of 2m, 1h or 24h")
	}
}

func mcpLimit(v int) (int, error) {
	if v == 0 {
		return 200, nil
	}
	if v < 1 || v > 1000 {
		return 0, fmt.Errorf("limit must be between 1 and 1000")
	}
	return v, nil
}

func mcpConfigJSON(cfg map[string]any) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return b, nil
}

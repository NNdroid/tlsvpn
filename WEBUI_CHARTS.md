# Diagnostic history

The Go WebUI adds six cards below the total throughput chart:

* Per-connection upload/download, with solid/dashed lines. Upload is always client → server.
* Measured per-connection RTT; bootstrap and unavailable RTT are gaps.
* Scheduler assigned payload bytes/s and queued bytes, drawn separately.
* Local TX FEC parity/DATA byte percentage and parity bytes/s; local RX recovered and confirmed unrecovered frames/s are separate plots.
* Local TX padding bytes/s and padding/wire byte percentage, drawn separately.
* Online physical connection count and reconnect attempts, backpressure drops and TAP write errors/s. Server reconnect attempts are unavailable (not measured by its counters).

All cards use the existing 2 minute / 1 hour / 24 hour range. Hovering one diagnostic plot selects the same timestamp in the other plots and exposes values in the legends. Client and connection selectors apply to the first three cards; FEC, padding and anomaly counters remain process-wide. Up to eight recent physical identities are displayed by default, and retained identities can be selected individually.

`WebManager.Run` collects the existing counters approximately every two seconds, independently of browsers. It does not run host diagnostics, serialize the full stats API, or change packet scheduling. Authenticated `/api/diagnostics?range=2m|1h|24h` and the `diagnostics` SSE event read the same history. SSE remains the WebUI's only periodic transport.

Retention is process-local: 60 fine samples, 1440 completed minute aggregates, and the current minute. Each point retains at most 32 connections (stable ID order); a visible notice reports truncation. Longer ranges use duration-weighted observed minute means, with 24 hours grouped into aligned five-minute buckets. Ratios are recomputed from byte rates. Connection queues and online counts are interval means in long ranges. This bounded history is not an exhaustive connection log and is lost on restart.

Rates use actual elapsed server sample time. The first observation of a physical `conn_id`, decreased counters, a padding epoch change, and a sample gap over ten seconds produce missing rate values. Missing/retired connections and unknown RTT are not converted to zero. Process identity changes clear all history and frontend baselines. No samples are invented to fill gaps or time before the process started. Existing application-wire and padding accounting scopes remain as documented in `WEBUI_METRICS.md`.

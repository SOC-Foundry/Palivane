# Gateway capacity baseline (load test)

2026-09-05, measured against the full inspection pipeline (`POST /v1/messages`, auth +
rate-limit + detection + verdict; upstream stubbed so the number is the work Palivane
ADDS per call). Rig: one 4-worker uvicorn instance, SQLite (worse concurrency than the
prod Postgres), local loopback. 300 requests/step, mixed typical-prompt and ~2KB code
paste, zero errors at every step.

| Concurrency | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|
| 1  | 109 req/s | 7.7 ms | 12 ms | 102 ms |
| 8  | 185 req/s | 27 ms | 89 ms | 215 ms |
| 24 | 151 req/s (saturated) | 105 ms | 233 ms | 343 ms |

Reading: a single instance sustains ~150–185 req/s of gateway traffic before queuing —
roughly a fleet of several hundred simultaneously-active Claude Code users per instance —
and Cloud Run scales instances horizontally. Saturation onset is driven by the test rig's
SQLite write path (heartbeats/discovery rows); prod Postgres moves the knee upward.

Availability-criterion evidence: rerun after material gateway changes; keep this file's
history as the trend. Detection-engine-only latency (0.2 ms p50 typical prompt) is
published on /how-it-works with methodology.

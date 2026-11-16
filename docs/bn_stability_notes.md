# Binary Ninja / MCP stability notes (SA2 extraction)

This documents **observed failure modes** during v2 MCP extraction. Many stops are **MCP HTTP listener death** (`127.0.0.1:24642` refused, invalid session), which may coincide with **Binary Ninja GUI crash or hang**—they are not always distinguishable from the client side.

## Failure categories

| Category | Symptoms in cache/logs | Likely cause |
| --- | --- | --- |
| **MCP session loss** | `Missing or invalid MCP-Session-Id`, `10061` connection refused, `mcp_unstable` stop | MCP server restarted/crashed; long runs; BN GUI overload |
| **Analysis wait timeout** | `timed out`, `timeout_after_120s`, duration 600–1200s | `bn_analysis_update_and_wait` or close hung on heavy binaries |
| **Close hang** | `close_failed:TimeoutError` after long `analysis_duration` | Open view not closing after heavy analysis |
| **Partial IL** | `analysis_status: partial`, low/no `bn_il_ops_total` | Forwarder/API-set DLLs, data-heavy PEs, limited code |
| **Corrupt/truncated cache** | JSON decode error on cache file | MCP died mid-write (mitigated by atomic `.tmp` rename) |

## Samples that repeatedly stress or break runs

These SHA-256 values appear in **error** caches or **>100s** runs (re-check before re-queuing):

| SHA-256 (prefix) | Label | Notes |
| --- | --- | --- |
| `11907dd00ef6…` | benign | `.NET` analyzer under `Program Files\dotnet\packs\...\analyzers\dotnet` — **600s+** analysis wait in pilot |
| `0bc70feb553b…` | malicious | **120s** client timeout; ~730 KB |
| `074e6f0bbab4…` | malicious | **120s** timeout; ~3.1 MB |
| `08a8e7cf3bd0…` | malicious | **120s** timeout; ~1.7 MB |
| `1310a249af79…` | benign | Error after MCP session loss (~28s) |
| `0bcb65a9d799…` | malicious | Immediate MCP 400 session error |
| `0031c670f920…`, `e0502e7fb54d…`, `0041ef4e445e…`, `0a1c0ee14c57…` | malicious | MCP session errors during pilot (not necessarily bad PE—often **after** MCP already dying) |

## Large / slow but often **ok**

| Pattern | Example |
| --- | --- |
| Very large malware (~13 MB) | `ca703d739a6f…` — **~502s**, status ok |
| Large benign DLLs | `python310.dll` (~4.5 MB, ~204s), `daxexec.dll` (~887 KB, ~180s) |
| High IL malware | `03e1b46d2f7c…` — **~24k IL ops**, ~73s |

Large size alone does not always crash BN; **long analysis + many back-to-back opens** correlates with MCP death.

## Operational patterns that correlate with crashes

1. **Long uninterrupted batch runs** (~30–45+ minutes, 30–50 files) without restarting BN/MCP.
2. **Back-to-back heavy malware** immediately after slow .NET or large DLL analysis.
3. **120s thread timeout** while BN still analyzing internally (duration logged as 600–1200s on some errors—HTTP/tool timeout vs wall clock mismatch).
4. **Pilot scale**: first failure on `11907dd00ef6` (dotnet analyzer), then cascade of MCP session errors on unrelated files.

## Mitigations in this repo

- `src.ensure_bn_mcp` — start/restart BN GUI, wait for MCP.
- `python -m src.ensure_bn_mcp --reboot` — **force** kill + relaunch BN.
- Scale extract **auto-reboots** BN on MCP session/connection failures (`reboot_on_mcp_failure: true`), then retries the same binary.
- **Accelerated mode**: batch 50 but **stop after 3 consecutive MCP failures**; caches preserved.
- **Atomic cache writes** — avoid corrupt JSON on crash.
- **2s pause** between files; **sequential** MCP only (no parallel opens).
- **Do not cache** transient MCP connection failures (retry on resume).

## Recommended operator workflow when BN “crashes”

1. Close hung Binary Ninja if needed; relaunch GUI and confirm MCP (`python -m src.ensure_bn_mcp`).
2. Resume: `python -m src.bn_scale_extract --accelerated --until-complete --run-pipeline` (skips completed SHA-256).
3. Prefer **smaller batches** (e.g. 15–25) with **BN restart every 1–2 batches** if instability continues.
4. Avoid manual heavy analysis in the same BN instance during bulk extract.
5. **Size/path skip policy** (`experiment.bn_scale`): files **> 4 MB** or paths matching `analyzers\dotnet` are cached as `analysis_status: skipped` (no MCP open).
6. Optional: temporarily **remove** problematic benign roots from inventory if they are not critical to the experiment.

## Where to inspect

- Per-sample: `artifacts/features/bn_v2_cache/<sha>.bn_v2_structured_il.json` → `analysis_status`, `errors`, `analysis_duration_seconds`
- Run progress: `artifacts/evaluations/bn_scale_progress.json`
- Last batch: `artifacts/evaluations/bn_coverage_v2.json` → `stopped_reason`, `monitoring.by_label_status`

*Updated from extraction logs through accelerated run (2026-10-31).*

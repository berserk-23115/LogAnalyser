# Simple Log Analyser (project-v2)

`project-v2` is a compact C reference implementation of a log-analysis pipeline. It ingests traditional text logs, optionally captures live packets through `libpcap`, detects bursty traffic that can indicate a DDoS attack, and provides a scripted demo that showcases the full flow end to end.

## Key Capabilities

- Parse whitespace-delimited log lines into typed `LogEntry` structures.
- Produce severity summaries plus extract suspicious events based on level/keyword heuristics.
- Run a `libpcap`-powered live capture that writes succinct transfer logs while feeding a rolling-window DDoS detector.
- Trigger synthetic traffic via `./loganalyser run demo test1` to observe alerts without touching a network interface.
- Ship with unit tests that cover parsing, suspicious-flagging, and the DDoS detector buckets.

## Project Layout

- `src/log_analyzer.c` – core parsing, summarization, and suspicious-event logic.
- `src/packet_capture.c` – reusable capture loop, IPv4 packet formatting, and capture report printing.
- `src/ddos_detector.c` – windowed packet counter keyed by source IP with alert generation.
- `src/demo.c` – deterministic traffic generator backing `run demo test1`.
- `sample-logs/` – `auth.log`, `web.log`, and demo/live output targets.
- `tests/` – `test_log_analyzer.c` plus CTest wiring.

## Prerequisites

- CMake ≥ 3.16
- A C11 capable compiler
- `libpcap` headers and library (optional; required only for live capture)

macOS already ships `libpcap`. On Linux, install via your package manager (e.g., `sudo apt install libpcap-dev`). If `libpcap` cannot be located at configure time the project still builds, but capture mode is disabled (`LOG_ANALYZER_NO_PCAP=1`).

## Build

```bash
cmake -S project-v2 -B project-v2/build
cmake --build project-v2/build
```

Artifacts:
- `project-v2/build/loganalyser` – CLI entry point
- `project-v2/build/tests/test_log_analyzer` – unit test binary

## CLI Overview

Run all commands from inside `project-v2` so bundled paths resolve cleanly.

### File Analysis (default)

```bash
cd project-v2
./build/loganalyser --input sample-logs/web.log
```

Flags:
- `--input <path>` – log file to parse (defaults to `sample-logs/auth.log`)
- `--list-samples` – enumerates bundled sample logs and exits
- `--help` – prints usage

Output includes a header (`Analysing <file>`), a severity count summary, and a table of suspicious events.

### Live Capture + DDoS Detection

```bash
cd project-v2
./build/loganalyser capture \
	--iface en0 \
	--limit 400 \
	--duration 20 \
	--log sample-logs/live_capture.log \
	--threshold 150 \
	--window 5
```

Options:
- `--iface <name>` – interface handed to `pcap_open_live` (default `en0`)
- `--limit <n>` – hard stop after `n` packets (default 500)
- `--duration <seconds>` – optional wall-clock limit
- `--log <path>` – destination for one-line packet summaries
- `--threshold <count>` – packets per source required to trip the DDoS alert (default 100)
- `--window <seconds>` – sliding window for threshold evaluation (default 5)

The command prints a Live Capture Summary plus any DDoS alerts. Each alert reports the offending IP, packet count, and the timestamps of the first/last packets in the burst.

### Demo Simulation

```bash
cd project-v2
./build/loganalyser run demo test1
```

The demo synthesizes three traffic flows, intentionally causing the `ddos_detector` to raise alerts without listening on a real interface. It writes `sample-logs/demo_test1.log`, logs alerts to stdout, and exits with `0`.

## How DDoS Detection Works

1. `ddos_detector.c` maintains up to `DDOS_MAX_BUCKETS` per-source counters.
2. Each incoming packet (from live capture or the demo) is keyed by source IP; the detector stores the timestamp of the first packet in the current window.
3. When elapsed time exceeds the configured window the bucket resets.
4. Surpassing `threshold` packets within the window produces a `DDoSAlert` containing first/last timestamps and the total count. Alerts are both printed and retained in the capture report for later inspection.

The detector is protocol-agnostic; callers decide what constitutes a "packet" and provide the timestamps.

## Testing

```bash
cmake --build project-v2/build
ctest --test-dir project-v2/build
```

`test_log_analyzer` exercises log parsing, suspicious detection, and the DDoS bucket rollover/reset logic. Add regression cases there when you extend the parser or detector.

## Troubleshooting

- **`libpcap` missing warning** – install `libpcap` headers/libraries, remove the build folder, and re-run CMake. Without it, `capture` subcommand exits immediately.
- **Permission errors running capture** – live capture often requires elevated privileges. On macOS/Linux prepend `sudo` (after ensuring you trust the binary). On macOS you may also need to grant "Full Disk Access" for log writing.
- **`demo log: No such file or directory`** – run the demo from inside `project-v2`. The tool writes relative to `sample-logs/`.
- **No suspicious events** – confirm your input log levels are one of `INFO/WARN/ERROR/CRITICAL` or contain flagged keywords (`FAILED`, `DENIED`, etc.).

## Extending the Tool

- Add parsers for other log formats by extending `parse_log_line`.
- Wire additional capture filters via `pcap_compile` in `packet_capture.c` before entering the loop.
- Introduce richer alerting (e.g., rate-based severity) by expanding `DDoSAlert` and the CLI output.

Pull requests that include updated tests and README instructions are easiest to review.

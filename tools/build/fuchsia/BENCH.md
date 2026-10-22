# FIDL IPC benchmark records

`make -C tools/build/fuchsia check-bench` builds an `-O2` tree
(`build-runtime.py --bench`) and runs `ipc_bench suite` three times, writing
one JSON line per scenario and mode to `/usr/obj/5bsd-fidl-bench/<timestamp>.json`
and printing medians with run-to-run spread (`bench-compare.py`).  Compare two
files with `make -C tools/build/fuchsia check-bench-compare BEFORE=a.json AFTER=b.json`.
Nothing here is part of the system build or publication (`build-bsd` was
checked and has no bench dependency).

## Scenarios

Every scenario runs over one `mac_capability` channel between a forked
provider and the client, in three modes: `raw` (libchannel with pre-encoded
FIDL bytes, no codec), `cpp` (generated C++ bindings) and `c` (generated C
bindings).  `ipc_bench list` prints the matrix.

| name | what one request is | modes |
|---|---|---|
| `roundtrip-8`, `roundtrip-256` | synchronous `Service.RoundTrip` with an 8- or 256-byte string, echoed | raw, cpp, c |
| `pipeline-1`, `-8`, `-64` | `RoundTrip` (8 bytes) with 1, 8 or 64 requests kept outstanding (window; limits are 256 pending) | raw, cpp, c |
| `take-1` | generated `Service.Take`: one read-only descriptor, request only | cpp (moved), c (lent) |
| `fds-N-request-*`, `fds-N-both-*` (N = 1, 8, 32) | `ManyResources` with N descriptors; `request` closes them at the provider, `both` echoes them back; `move` transfers ownership (`CHANNEL_SEND_MOVE`; C++ `Descriptor` fields, C `fidl_bsd_fd_owned()` slots), `borrow` lends them (kernel duplicates; plain C descriptor fields) | raw (move and borrow), cpp (move), c (move and borrow) |
| `events-1000` | one `RoundTrip` that makes the provider send 1,000 `Service.Changed` events before replying; the client drains them.  Sample unit: the burst | raw, cpp, c |
| `large-4096`, `large-14304` | `Large` (vector of bytes) echoed; 14,304 bytes is the 14,336-byte message ceiling | raw, cpp, c |
| `mixed` | one iteration = 4 x RoundTrip(8) + 2 x RoundTrip(256) + 1 x ManyResources(1 fd, echoed) + 1 x Large(14,304) + 1 x burst of 64 events (9 requests).  Sample unit: the iteration | raw (borrow), cpp (move), c (borrow) |

`ManyResources`, `Large` and the burst method have no method in the test
schema (`runtime.fidl`), so the bench dispatches them by ordinal through the
same runtime entry points the generated methods wrap: `Connection::Call` /
`Reply` with natural types for `cpp`, and the generated C wire codecs
(`CWEnc_*`/`CWDec_*`) through `CallRaw`/`ReplyRaw` for `c`.  The `c` server
for those scenarios is therefore hand-dispatched; `roundtrip`, `pipeline`,
`take` and `events` use the generated C server.  In `move` scenarios that
only send descriptors (`request`), the client must `dup(2)` fresh descriptors
for every call and those system calls are part of the measurement; `both`
+ `move` recycles the echoed descriptors and needs no `dup`.

Allocation counts come from link-time `malloc`/`calloc`/`realloc` wrappers in
both processes.  System-call counts come from a separate, untimed phase after
the timed run in which the client turns on `ktrace(2)` (`KTRFAC_SYSCALL`) for
itself and the provider, runs up to 1,000 requests (5 bursts, 100 mixed
iterations), stops tracing and parses the trace file itself; no privilege is
needed.  Counts exclude the `ktrace` calls themselves; the traced phase takes no
timestamps.  If tracing is unavailable the JSON
carries `syscall_trace_error` and a `ktrace`/`kdump` command to run by hand.

## JSON schema (one object per line, `"schema":2`)

| field | meaning |
|---|---|
| `scenario`, `name`, `mode` | scenario family, matrix row (`ipc_bench list`), `raw`/`cpp`/`c` (`-legacy` suffix with `IPC_BENCH_LEGACY=1`) |
| `payload`, `message_bytes` | text or byte payload and the encoded request size including the 16-byte header |
| `window`, `fds`, `fd_direction` (`none`/`request`/`both`), `fd_transfer` (`none`/`borrow`/`move`), `events_per_burst` | scenario parameters |
| `sample_unit` (`call`/`burst`/`iteration`), `requests_per_sample`, `samples`, `calls` | what a latency sample measures; `calls` is the number of requests in the timed run |
| `seconds`, `calls_per_second`, `events_per_second` | timed-run duration and rates (requests per second; events only when events are sent) |
| `p50_us`, `p90_us`, `p99_us`, `max_us` | latency percentiles of the sample unit |
| `client_allocations_per_call`, `client_bytes_per_call`, `server_allocations_per_call`, `server_bytes_per_call` | heap allocations and bytes per request in the timed run |
| `syscall_trace_calls`, `syscall_trace_dropped`, `client_syscalls_per_call`, `server_syscalls_per_call`, `client_syscalls`, `server_syscalls` | requests in the traced phase, whether the kernel dropped records, system calls per request, and the per-request breakdown by name (top 10 + `other`) |
| `client_maxrss_kib`, `trial`, `cpus` | client RSS, trial number from the suite runner, `IPC_BENCH_CPUS` pinning or `null` |

Synchronous scenarios (window 1) issue each request through the one-call
path: `channel_call_request(3)` in `raw`, `fidl_bsd_connection_call(3)` in
`c` and `Connection::CallSync` in `cpp`.  On kernels with
`MAC_CAPABILITY_CHANNEL_CALL` the request and its reply then cost the client
one system call; older kernels, and `IPC_BENCH_NO_CALL=1` (mode suffix
`-nocall`), take the send/wait/receive sequence the baseline measured.
Pipelined scenarios are unchanged: with a window above one the call path is
not used.

Environment: `IPC_BENCH_CPUS=C[,S]` pins the client and server
(`FIDL_BENCH_CPUS` from make); `IPC_BENCH_KTRACE_DIR` holds the trace file;
`IPC_BENCH_LEGACY=1` allowlists only the older channel ioctls;
`IPC_BENCH_NO_CALL=1` disables the one-call path.  Pinning was
tried on 2026-10-22 and rejected as the default: with other builds running,
pinning cut p50 by about 1 us but multiplied stalls (throughput fell 30-80%);
unpinned runs showed a p50 spread of 9.8-10.1 us over three runs.

## 2026-10-22 pre-change baseline

Taken before the direct-send fast path, kernel call ioctl, allocation slabs
and descriptor-move work landed, as the reference those changes are compared
against.

Build: the bench inputs (`lib/libfidl`, `lib/libchannel`, the generators,
`runtime.fidl`) were identical to commit `b2c5fe6715d` (`dev`) when this work
started (2026-10-22T17:57:53Z); other agents began changing them minutes
later, so the baseline was built from a `git archive` of that commit plus the
new `ipc_bench.cc`, kept with its objects under `/usr/obj/5bsd-fidl-bench/`:

    /usr/obj/5bsd-fidl-bench/baseline-src/      HEAD snapshot (+ ipc_bench.cc, SNAPSHOT.txt)
    /usr/obj/5bsd-fidl-bench/baseline-obj/bench/ipc-bench   built 2026-10-22T18:24:58Z..18:25:45Z
    /usr/obj/5bsd-fidl-bench/20261022T182557Z-baseline.json  3 trials x 53 runs, 2026-10-22T18:25:57Z..18:27:12Z

Host: 16 logical CPUs (AMD Ryzen 7 255), 5BSD 16.0-CURRENT kernel
GENERIC-NODEBUG of 2026-10-07 (`n287372-f4db9ce01f15-dirty`), ULE, not
pinned.  Other agents' builds were running: 1-minute load average 20.4 at
the start, 18.9 / 17.0 / 15.9 after trials 1, 2 and 3, with 6, 3, 3 and 2
compiler/make/linker processes at those sample points.  The kernel is the
one running since 2026-10-07, so kernel-side changes are not in this baseline
and will not show in later runs on this host until it is rebooted.

Each run: 20,000 requests after 1,000 warm-up requests (events: 200 bursts
after 10; mixed: 2,222 iterations after 111), then the untimed syscall-trace
phase.  Medians of three trials; the spread is the min..max of the three.
p50, allocation counts and syscall counts are stable under this load; p99
and requests/s are not (single stalls of 0.5-2 ms appear in most rows) and
should be read against the spread.  Columns `c/s` are client / server.

| scenario | mode | unit | bytes | p50 us (spread) | p99 us (spread) | per s | allocs c/s | alloc bytes c/s | syscalls c/s | n |
|---|---|---|---|---|---|---|---|---|---|---|
| roundtrip-8 | raw | call | 40 | 8.15 (7.9..9.9) | 15.68 (14.9..290.0) | 114365 | 0.00 / 0.00 | 0 / 0 | 4.00 / 3.99 | 3 |
| roundtrip-8 | cpp | call | 40 | 9.56 (9.3..10.9) | 20.34 (19.1..94.8) | 85736 | 0.00 / 1.00 | 0 / 424 | 4.00 / 4.00 | 3 |
| roundtrip-8 | c | call | 40 | 9.40 (8.9..10.3) | 19.66 (17.6..72.4) | 95136 | 0.00 / 2.00 | 0 / 440 | 4.00 / 4.00 | 3 |
| roundtrip-256 | raw | call | 288 | 8.17 (8.0..9.2) | 16.70 (15.3..44.6) | 109723 | 0.00 / 0.00 | 0 / 0 | 4.00 / 4.00 | 3 |
| roundtrip-256 | cpp | call | 288 | 10.85 (10.7..13.9) | 21.83 (21.2..771.9) | 83633 | 2.00 / 2.00 | 528 / 688 | 4.00 / 4.00 | 3 |
| roundtrip-256 | c | call | 288 | 9.81 (8.8..13.7) | 19.76 (17.4..588.2) | 92346 | 0.00 / 2.00 | 0 / 440 | 4.00 / 4.00 | 3 |
| pipeline-1 | raw | call | 40 | 8.23 (7.9..10.1) | 16.19 (15.0..176.7) | 111723 | 0.00 / 0.00 | 0 / 0 | 4.00 / 3.99 | 3 |
| pipeline-1 | cpp | call | 40 | 9.78 (9.5..11.7) | 19.84 (19.8..95.8) | 92260 | 0.00 / 1.00 | 0 / 424 | 4.00 / 4.00 | 3 |
| pipeline-1 | c | call | 40 | 9.45 (7.8..14.0) | 18.35 (15.7..660.1) | 96668 | 0.00 / 2.00 | 0 / 440 | 4.00 / 4.00 | 3 |
| pipeline-8 | raw | call | 40 | 10.41 (9.7..30.4) | 28.74 (19.2..1067.2) | 468238 | 0.81 / 0.00 | 39 / 0 | 2.41 / 2.20 | 3 |
| pipeline-8 | cpp | call | 40 | 16.05 (15.9..33.8) | 34.82 (28.8..772.1) | 381953 | 0.70 / 1.00 | 34 / 424 | 2.45 / 2.16 | 3 |
| pipeline-8 | c | call | 40 | 17.44 (16.9..32.6) | 37.36 (33.2..744.0) | 380398 | 0.58 / 2.00 | 28 / 440 | 2.53 / 2.16 | 3 |
| pipeline-64 | raw | call | 40 | 83.57 (72.8..230.5) | 494.99 (212.2..1381.7) | 361768 | 0.98 / 0.00 | 47 / 0 | 2.13 / 2.08 | 3 |
| pipeline-64 | cpp | call | 40 | 107.49 (105.3..278.4) | 306.56 (261.2..1526.7) | 318610 | 0.97 / 1.00 | 46 / 424 | 2.27 / 2.02 | 3 |
| pipeline-64 | c | call | 40 | 171.70 (144.6..285.0) | 655.33 (246.8..1940.5) | 294103 | 0.86 / 2.00 | 41 / 440 | 2.18 / 2.02 | 3 |
| take-1 | cpp | call | 24 | 11.75 (11.0..15.9) | 24.58 (22.5..476.8) | 76864 | 1.00 / 1.00 | 512 / 424 | 10.00 / 6.98 | 3 |
| take-1 | c | call | 24 | 11.06 (10.5..13.7) | 24.73 (20.6..272.4) | 78599 | 0.00 / 2.00 | 0 / 440 | 12.00 / 6.79 | 3 |
| fds-1-request-move | raw | call | 40 | 8.73 (7.8..10.5) | 17.59 (15.1..211.1) | 105038 | 0.00 / 0.00 | 0 / 0 | 6.00 / 4.86 | 3 |
| fds-1-request-move | cpp | call | 40 | 11.27 (10.5..12.3) | 29.56 (21.3..48.4) | 76674 | 2.00 / 2.00 | 516 / 428 | 6.00 / 4.77 | 3 |
| fds-1-request-borrow | raw | call | 40 | 8.69 (8.5..9.7) | 16.89 (16.7..155.5) | 105760 | 0.00 / 0.00 | 0 / 0 | 4.00 / 4.78 | 3 |
| fds-1-request-borrow | c | call | 40 | 10.31 (10.1..11.4) | 54.36 (28.6..57.4) | 73224 | 0.00 / 1.00 | 0 / 424 | 10.00 / 4.77 | 3 |
| fds-1-both-move | raw | call | 40 | 8.85 (8.8..9.0) | 17.87 (17.3..63.6) | 103124 | 0.00 / 0.00 | 0 / 0 | 5.00 / 4.84 | 3 |
| fds-1-both-move | cpp | call | 40 | 11.19 (11.1..11.9) | 22.54 (21.8..34.5) | 82872 | 2.00 / 3.00 | 516 / 940 | 5.00 / 4.87 | 3 |
| fds-1-both-borrow | raw | call | 40 | 8.77 (8.8..9.2) | 17.10 (16.9..69.1) | 104718 | 0.00 / 0.00 | 0 / 0 | 5.00 / 4.88 | 3 |
| fds-1-both-borrow | c | call | 40 | 10.70 (10.4..10.8) | 21.71 (21.1..27.0) | 84737 | 0.00 / 1.00 | 0 / 424 | 11.00 / 10.38 | 3 |
| fds-8-request-move | raw | call | 64 | 9.83 (9.7..9.9) | 17.98 (17.6..19.7) | 94664 | 0.00 / 0.00 | 0 / 0 | 20.00 / 11.37 | 3 |
| fds-8-request-move | cpp | call | 64 | 12.56 (12.2..12.9) | 23.83 (23.8..24.1) | 74457 | 5.00 / 2.00 | 572 / 456 | 20.00 / 11.48 | 3 |
| fds-8-request-borrow | raw | call | 64 | 9.42 (9.0..9.6) | 21.61 (17.0..25.9) | 90949 | 0.00 / 0.00 | 0 / 0 | 4.00 / 11.12 | 3 |
| fds-8-request-borrow | c | call | 64 | 14.77 (14.5..15.8) | 55.40 (42.6..139.3) | 55538 | 0.00 / 1.00 | 0 / 424 | 52.00 / 11.48 | 3 |
| fds-8-both-move | raw | call | 64 | 10.38 (10.1..10.5) | 25.96 (20.8..30.4) | 82609 | 0.00 / 0.00 | 0 / 0 | 12.00 / 11.28 | 3 |
| fds-8-both-move | cpp | call | 64 | 13.51 (12.9..13.8) | 29.42 (27.4..32.7) | 63160 | 2.00 / 3.00 | 544 / 968 | 12.00 / 11.48 | 3 |
| fds-8-both-borrow | raw | call | 64 | 10.83 (10.3..10.9) | 22.31 (20.1..31.5) | 83965 | 0.00 / 0.00 | 0 / 0 | 12.00 / 11.27 | 3 |
| fds-8-both-borrow | c | call | 64 | 18.68 (15.8..21.8) | 64.57 (36.0..324.4) | 42966 | 0.00 / 1.00 | 0 / 424 | 60.00 / 59.50 | 3 |
| fds-32-request-move | raw | call | 160 | 15.16 (12.1..15.7) | 36.80 (19.4..198.5) | 56771 | 0.00 / 0.00 | 0 / 0 | 68.00 / 35.35 | 3 |
| fds-32-request-move | cpp | call | 160 | 19.74 (18.1..21.3) | 60.43 (47.2..187.0) | 42798 | 7.00 / 2.00 | 764 / 552 | 68.00 / 35.42 | 3 |
| fds-32-request-borrow | raw | call | 160 | 10.92 (9.8..11.2) | 22.48 (16.9..27.0) | 82733 | 0.00 / 0.00 | 0 / 0 | 4.00 / 34.97 | 3 |
| fds-32-request-borrow | c | call | 160 | 25.71 (21.6..27.7) | 43.34 (35.2..64.0) | 37143 | 0.00 / 1.00 | 0 / 424 | 196.00 / 35.44 | 3 |
| fds-32-both-move | raw | call | 160 | 13.92 (12.2..14.5) | 25.08 (19.0..34.0) | 68256 | 0.00 / 0.00 | 0 / 0 | 36.00 / 35.23 | 3 |
| fds-32-both-move | cpp | call | 160 | 18.46 (17.1..25.9) | 32.12 (27.6..539.5) | 51839 | 2.00 / 3.00 | 640 / 1064 | 36.00 / 35.21 | 3 |
| fds-32-both-borrow | raw | call | 160 | 17.08 (16.3..21.6) | 27.23 (25.6..523.8) | 55709 | 0.00 / 0.00 | 0 / 0 | 36.00 / 35.25 | 3 |
| fds-32-both-borrow | c | call | 160 | 43.37 (38.8..47.2) | 59.36 (56.5..107.2) | 20830 | 0.00 / 1.00 | 0 / 424 | 228.00 / 227.40 | 3 |
| events-1000 | raw | burst | 40 | 1764.80 (1724.6..1946.0) | 4884.81 (3687.3..7703.5) | 497 | 0.01 / 3.56 | 0 / 1215 | 1307.40 / 1004.00 | 3 |
| events-1000 | cpp | burst | 40 | 2246.26 (2162.2..2466.7) | 4774.29 (4344.7..5294.2) | 423 | 1000.00 / 7.41 | 424000 / 1799 | 1136.40 / 1004.00 | 3 |
| events-1000 | c | burst | 40 | 2268.92 (1585.7..2272.7) | 4702.93 (3229.3..4837.0) | 421 | 1000.00 / 4.27 | 424000 / 1583 | 1132.80 / 1004.00 | 3 |
| large-4096 | raw | call | 4128 | 8.71 (8.6..8.9) | 17.63 (17.1..20.7) | 106360 | 0.00 / 0.00 | 0 / 0 | 4.00 / 4.00 | 3 |
| large-4096 | cpp | call | 4128 | 13.00 (12.5..13.9) | 24.88 (24.5..43.2) | 70771 | 3.00 / 3.00 | 12304 / 8632 | 4.00 / 4.00 | 3 |
| large-4096 | c | call | 4128 | 9.89 (9.7..10.9) | 19.39 (18.5..48.1) | 92805 | 0.00 / 1.00 | 0 / 424 | 4.00 / 3.99 | 3 |
| large-14304 | raw | call | 14336 | 9.74 (9.7..10.4) | 19.40 (18.7..31.8) | 94013 | 0.00 / 0.00 | 0 / 0 | 4.00 / 4.00 | 3 |
| large-14304 | cpp | call | 14336 | 18.79 (18.8..21.1) | 36.59 (33.9..141.0) | 48509 | 3.00 / 3.00 | 42928 / 29048 | 4.00 / 4.00 | 3 |
| large-14304 | c | call | 14336 | 12.62 (11.9..12.8) | 33.37 (22.6..45.4) | 67748 | 0.00 / 1.00 | 0 / 424 | 4.00 / 4.00 | 3 |
| mixed | raw | iteration | 40 | 225.74 (205.7..234.8) | 783.24 (615.6..2218.8) | 38992 | 0.22 / 0.22 | 1774 / 1774 | 13.44 / 11.31 | 3 |
| mixed | cpp | iteration | 40 | 276.50 (274.4..323.6) | 1062.11 (519.4..2435.4) | 30517 | 8.33 / 1.89 | 9734 / 5495 | 12.58 / 11.33 | 3 |
| mixed | c | iteration | 40 | 268.54 (245.9..284.3) | 1388.32 (663.3..1828.7) | 30609 | 7.33 / 1.22 | 4789 / 2198 | 12.96 / 11.96 | 3 |

The six round-trip runs that `build-runtime.py --bench` itself records
(`baseline-obj/bench/bench.json`, 3 x 20,000 calls, load 20 at the end) have
medians within the suite's spread: raw 15.2 / 9.3 us p50 (8 / 256 bytes;
the 8-byte raw median is one 24 us run), C++ 11.2 / 12.2 us, C 10.9 / 10.2 us.

What the baseline shows:

- Steady-state round trips allocate nothing on the client in any mode; the
  provider allocates once (C++, 424 bytes) or twice (C, 440 bytes) per
  request.  Each side makes 4 system calls per call (3 `ioctl`, 1 `kevent`).
  FIDL adds 1.2-1.4 us to the raw 8.2 us p50.
- Pipelining amortizes the wait: 2.1-2.5 system calls per request at windows
  of 8 and 64, with raw reaching 468k requests/s at a window of 8.  The C
  path's per-request latency at a window of 64 (172 us) is worse than C++
  (107 us) and raw (84 us).
- Descriptors: the C bindings' lend path costs 6 client system calls per
  descriptor (`fcntl` duplicate, `pddupfd`, `pdptrace`, `__cap_rights_get`,
  `cap_rights_limit`, `close`), 196 per call at 32 descriptors against 4 for
  raw borrowing; the provider closes each received descriptor (about 35 calls
  per 32 descriptors in every mode).  Moving (C++ `Descriptor`, raw
  `CHANNEL_SEND_MOVE`) costs one `close` per descriptor on the sender plus
  one `dup` when the descriptors are not recycled; the C++ natural types
  allocate the descriptor vector (2-7 allocations per call).
- Events: the generated C and C++ clients allocate once per received event
  (424 bytes, 1,000 per burst); raw allocates nothing.  Draining costs 1.1-1.3
  client system calls per event and the provider 1 per event; a 1,000-event
  burst takes 1.8 ms raw and 2.2-2.3 ms through the bindings.
- Large payloads: the C++ natural types copy the 14 KiB vector (3
  allocations, 43 KB per call; p50 18.8 us) while the C wire codec allocates
  nothing on the client (12.6 us; raw 9.7 us).  The 14,336-byte message is
  only 1.5 us slower than a 40-byte one for raw.

## Re-running and comparing

    make -C /usr/src/tools/build/fuchsia check-bench            # builds the current tree, 3 trials, prints the table
    make -C /usr/src/tools/build/fuchsia check-bench-compare \
        BEFORE=/usr/obj/5bsd-fidl-bench/20261022T182557Z-baseline.json \
        AFTER=/usr/obj/5bsd-fidl-bench/<timestamp>.json
    /usr/obj/5bsd-fidl-runtime/bench/ipc-bench list                  # scenario matrix
    IPC_BENCH_KTRACE_DIR=/usr/obj/5bsd-fidl-bench \
        /usr/obj/5bsd-fidl-runtime/bench/ipc-bench run fds-32-both-move cpp 20000 1000   # one row

To re-take the baseline from the snapshot:

    python3.12 /usr/obj/5bsd-fidl-bench/baseline-src/tools/build/fuchsia/build-runtime.py \
        --src /usr/obj/5bsd-fidl-bench/baseline-src --obj /usr/obj/5bsd-fidl-bench/baseline-obj \
        --tools /usr/obj/5bsd-fidl --bench --bench-calls 20000
    for t in 1 2 3; do IPC_BENCH_KTRACE_DIR=/usr/obj/5bsd-fidl-bench \
        /usr/obj/5bsd-fidl-bench/baseline-obj/bench/ipc-bench suite 20000 1000 $t; done \
        >> /usr/obj/5bsd-fidl-bench/$(date -u +%Y%m%dT%H%M%SZ)-baseline.json

Compare against a build of the same `ipc_bench.cc`; the sample units and the
traced-phase sizes are part of the numbers.  The host kernel must be the same
for kernel-side comparisons.

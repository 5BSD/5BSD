# Build resource accounting

`/usr/bin/time -l bazel ...` measures the client and descendants that it waits
for. A persistent server started by an earlier client is outside that boundary.
The normal `build-bsd bazel-test` stderr timings therefore do **not** establish
build CPU, aggregate peak RAM or physical disk throughput. Its qualification
receipt already excludes performance acceptance.

The `//tools/build/bazel:resource_tree` execution tool measures a complete
controlled descendant lifecycle on FreeBSD:

```
resource_tree /usr/obj/.../resources.json 3600 -- /absolute/build-sequence-script
```

The timeout is in seconds. The JSON report must be a new file. The sequence must
start a private Bazel server, perform its selected clean/incremental builds,
and shut down that server before exiting. The maintained format-5 `build-state`
selection provides a private output-user-root without changing the production
backend. Existing external servers are intentionally excluded. Never reuse a
running server and present this report as complete accounting of its work.
Keep the script, exact commands, build selections and resource-tool identity
with the evidence. Use the same boundary for the Make reference sequence.

The supervisor acquires a process reaper before starting the sequence. It waits
for the command and adopted descendants, including double-fork/setsid daemons.
FreeBSD's exit/wait accounting includes descendants already reaped by each
returned process; those counters are added once. CPU and block-operation totals
cover the full lifecycle, including startup, SDK verification/staging performed
inside the sequence, server idle time and shutdown. They do not attribute
CPU/I/O separately to each build phase. Unreaped descendants keep the measurement
open until they exit or the deadline triggers cleanup. Timeout and SIGINT/
SIGTERM kill the supervisor's reaper subtree, drain it and produce a failed
report (124 for timeout, 128 + signal for interruption). A snapshot error fails
measurement with status 125. Command failure retains its exit status.

Process-only kernel snapshots sample descendant RSS every 50 milliseconds.
Nested reaper membership is followed; threads are not counted as independent
processes. `sampled_peak_rss_sum_bytes` sums simultaneously observed process RSS;
it is **not** exact physical peak RAM. Shared pages count repeatedly, snapshots
are not atomic, and short-lived processes/peaks can be missed. The actual maximum
sample gap and observer CPU cost are reported. Kernel visibility restrictions,
process churn and competing host workloads must be considered when reviewing a
comparison. A controlled VM's memory/device observations remain necessary for
physical resource budgets. `largest_process_maxrss_kib` retains the largest
individual process high-water mark separately; it is not aggregate RAM.

`block_inputs` and `block_outputs` are kernel rusage operation counts, not bytes
or physical device throughput. Collect controlled device counters separately.
Retained SDK/object/cache/package storage, temporary peak storage and compressed
debug-package costs also remain separate measurements. Do not infer them from
RSS or these block-operation counters.

The older `resource_run` target keeps its existing single-command interface for
serial DTrace action measurements. It does not acquire a reaper or sample
aggregate RSS; existing action comparisons retain their narrower limits.

`//tools/build/bazel:resource_tree_test` runs the real helper in the execution
configuration: waited and adopted workers with simultaneous touched allocations,
CPU transfer without double-counting, nested reapers, unrelated-daemon exclusion, timeout and
signal cleanup, command failure, and refusal to overwrite existing evidence.
These tests qualify instrumentation behavior, not whole-system performance.

## Frontend integration

The helper and test are source-owned native Bazel targets. Existing format-5
`targets`, `tests` and `build-state` inputs select them through maintained
`build-bsd bazel-test`; no new CLI or C-frontend dispatch is needed. No build,
staging, signing, publication or security-policy semantics change. Make remains
the production/default backend. This measurement work does not close resource,
bootstrap, sandbox, current-system parity or ARM64 runtime gates.

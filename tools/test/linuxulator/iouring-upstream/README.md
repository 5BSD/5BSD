# Upstream io_uring qualification

This directory adds external validation to the in-tree squeue tests. It builds
pinned liburing 2.12 and fio 3.41 Linux binaries, runs the same payload in Linux
and candidate VMs, exercises native lifecycle stress, and records a bounded
hardware baseline. See [the September 26 results](results-20260926.md).

## Build

`build.py` requires Python 3.12+, GNU make, a compiler, and network access for
checksum-verified source archives. On Linux, use the native compiler. On FreeBSD,
provide an x86_64 static musl sysroot containing development headers, startup
objects, libc, libm, and libpthread; clang/lld and brandelf are required.
For example:

```sh
python3 build.py --output /tmp/iouring-upstream \
    --make /path/to/gmake --linux-sysroot /path/to/musl-sysroot \
    --clang-resource-dir /usr/local/llvm19/lib/clang/19
```

The payload contains 215 unmodified upstream C test binaries, fio, the case
inventory, and the guest harness. C++ coverage is excluded. Fio has one build
adjustment: explicitly including `<linux/falloc.h>` in `linux-blkzoned.c` for
musl's headers. Source archive and executable hashes are recorded. The checked-in
manifest records the actual September 26 binaries; rebuilding with another
compiler/sysroot can change executable hashes.

## Differential and application runs

Use disposable VMs. Stage `payload` on writable storage (copy it off FAT or a
read-only transport first), configure loopback, and run:

```sh
sh /root/payload/guest.sh /root/payload /tmp/upstream
```

Linux needs `ip link set lo up`. The candidate needs linux64 loaded and
`ifconfig lo0 inet 127.0.0.1 up`. The recorded Linux VM used Alpine 3.24.1,
Linux 6.18.35-0-virt, 4 emulated CPUs and 1 GiB RAM; the candidate used 4 CPUs,
1.5 GiB RAM, ZFS, and the WITNESS/INVARIANTS kernel recorded in the manifest.
Linux's test directory was tmpfs. Filesystem and memory-limit differences matter
when interpreting failures. Both used QEMU TCG, not hardware acceleration.

`cases.txt` selects 70 cases; it is not the complete upstream test suite.
Each gets a separate directory with the required `exec-target.t` helper and a
45-second timeout (`CASE_TIMEOUT` overrides it) plus a five-second kill grace period. Exit 77 is a skip and
124 is a timeout. Exit zero can still contain upstream subtest skips; retain the
log. The known candidate `hardlink` assertion is explicitly quarantined after
its first recorded crash, not counted as a pass. Remove that quarantine only
when validating a fix in an isolated VM.

Fio writes and checksum-verifies 16 MiB at 4 KiB blocks and depth 16 in buffered,
direct, registered-file/buffer, and SQPOLL modes. Its explicit `io_uring` engine
fails initialization rather than silently choosing another engine. No raw device
is used. These are application integrity checks, not VM performance claims.

Capture serial output and compare it with:

```sh
python3 analyze.py --candidate candidate.log --oracle linux.log \
    --output differential.json
```

The analyzer exits nonzero for an incomplete/nonpassing qualification. Guest
completion markers mean execution finished, not that all cases passed. Inspect
resource counters and kernel diagnostics independently; zero test exits alone
are insufficient. The September 26 retries raised the per-case timeout to 150
seconds and set the **boot-time** `kern.ipc.maxpipekva=268435456` tunable.

## Native stress

Build `tests/sys/kern/squeue_stress.c`, `squeue_fuzz.c`, and `squeue_soak.c`
with the candidate's native headers/libraries, plus `memory-pressure.c`:

```sh
cc -static -O2 -pthread squeue_stress.c -lexecinfo -lelf -o squeue_stress
cc -static -O2 -pthread squeue_fuzz.c -o squeue_fuzz
cc -static -O2 -pthread squeue_soak.c -o squeue_soak
cc -static -O2 memory-pressure.c -o memory-pressure
```

Stage them with `stress.sh` and run it in a separate disposable candidate VM.
The default is 100 concurrency/lifecycle runs, 100 deterministic fuzz seeds
(600,000 fuzz iterations), 40,000 combinatorial rounds and 40,000 ring
lifecycles, while a helper touches 512 MiB. Each concurrency test creates its own
concurrent threads/rings. Do not launch multiple copies of these native programs
simultaneously: they use fixed temporary filenames. Process exits, cancellation,
poll teardown and descriptor reuse are exercised. Record helper liveness and all
five resource counters after completion. This bounded run does not establish
multi-day endurance or exhaustion/OOM behavior.

## Hardware baseline

`benchmark.py` uses only a newly created regular file in its output directory:

```sh
python3 benchmark.py --fio /path/to/payload/fio --output /tmp/fio-new-run
```

It checksum-verifies a 64 MiB preparation write, then runs three repetitions of
70/30 random read/write at 4 KiB: psync depth 1; io_uring depths 1, 8 and 32; and
SQPOLL with registered files at depth 32. Each timed run has a one-second ramp
and three-second measurement. Total-latency percentiles, CPU use, depth
histograms, commands, limits, kernel identity, filesystem, load, and squeue
submission-counter deltas are saved. Registered buffers are omitted here to
fit the account's 64 KiB memlock limit. The workload file is removed afterward.

These are short, warm-cache measurements of the installed kernel on a shared
host with WITNESS enabled. They are not a comparison with native Linux, a
candidate-kernel hardware qualification, or a sustained device-throughput result.

## Libuv application compatibility

`build-libuv.py` builds unmodified libuv 1.53.0 and `libuv-compat.c` as a static
Linux executable. The archive is pinned by SHA-256. The build uses the Linux
source list from that release's CMakeLists.txt, without requiring
CMake or autotools. Pass a Linux compiler, or the existing musl wrapper:

```sh
python3 build-libuv.py --output /tmp/iouring-libuv \
    --cc /tmp/iouring-upstream/linux-cc
```

Stage `libuv-compat` and `libuv-guest.sh` in disposable Linux and candidate VMs:

```sh
sh libuv-guest.sh /path/to/libuv-compat
```

The same binary runs filesystem, epoll descriptor-reuse, and cancellation-race
checks in default and explicitly enabled SQPOLL modes. File contents and metadata
are checked, each request must complete exactly once, and each loop must close.
Every invocation creates its own temporary directory and has a 45-second limit.
The harness reports failures individually and exits nonzero if any case fails.

The check observes the pinned library's internal ring state without modifying
upstream source. Each filesystem operation reports initial ring/thread-pool
selection and completion path. Required core filesystem operations must use the
ring in SQPOLL mode; a successful retry through the pool is not recorded as a
successful ring operation. Epoll checks require positive ring submission counts.
Default filesystem mode intentionally uses the thread pool and provides a control.

Kernel identity matters: libuv uses version checks in addition to ring feature
bits. Linux 5.15.0 disables ring close, truncate, and synchronous cancellation in
this release. Record the advertised identity and any diagnostic override
separately. A cancellation race may legitimately finish every request before it
can be cancelled; that outcome does not qualify cancellation of blocked I/O.
This harness does not establish Bun, Node, or database compatibility, and does
not cover blocked stream reads or the known stream-teardown problem.

The [September 26 libuv results](libuv-results-20260926.md) record working
filesystem/epoll paths and a reproducible synchronous cancellation mismatch in
the diagnostic newer-version profile.

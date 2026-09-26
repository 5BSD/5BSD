# Running Real Applications

Everything before this chapter describes mechanism and named contracts. This chapter answers the operator's question: what runs, on what evidence, and what do I do when something does not. 5BSD keeps three evidence classes apart and this chapter uses them strictly. **Gate-passed** means the workload ran inside the disposable ZFS-root QEMU gate against the candidate kernel, with the result recorded in a document under `docs/`. **Claimed** means a run on a development host or a source-review argument. **Not qualified** means the documents say it is not, usually with the reason. Anything not listed has never been claimed.

## The qualified list

| Workload | Class | Evidence |
|---|---|---|
| Alpine musl busybox (shell, coreutils, tar, awk, sed, find, nc, 500-fork exec churn, pipe transfer) | gate-passed | `tests/sys/kern/linux_busybox_test.sh`, run in the guest gate with the Alpine root staged; `docs/book/src/compat/linux/syscalls.md` section 9 |
| GDB 16.3 (Alpine 3.24 binary): start a target, read and modify registers, continue to exit | gate-passed | `docs/book/src/compat/linux/sandboxing.md`, `focus9.console.log` and `full1-run/results.json` |
| Linux Python client (Python embedded in that GDB binary, run in batch mode) exercising procfs, sysfs, sockets, epoll, task links and a disposable tmpfs | gate-passed | `tools/test/linuxulator/filesystems-client.py`, `proc-views-client.py`; `docs/book/src/compat/linux/procfs-sysfs.md` (eight checks) |
| libfuse 3.18.3 hello daemon as a Linux64 binary in direct, cached and writeback modes; Linux SQLite WAL, IPC and watch workloads | gate-passed | `docs/book/src/compat/linux/overview.md` batch 7, `docs/book/src/compat/linux/overview.md` |
| jq (C, musl), ripgrep (Rust, musl, threaded), caddy (Go): static binaries trussed end to end, zero unimplemented syscalls | claimed (truss census in a development guest; the procfs files they needed are now gate-covered by `linux_procfs`) | `docs/book/src/compat/linux/syscalls.md` section 11 |
| Bun (musl build): the runtime whose syscall census on the development host drove the pidfd, madvise and `preadv2` batches | claimed | `docs/linuxulator-syscall-coverage.md` section 2; the planned VM run of its test subset is listed in the option review's plan and has no recorded gate artifact |
| Electron, Chromium | not qualified | `docs/book/src/compat/linux/overview.md`: no Electron VM execution completed; the Chromium sandbox needs seccomp filter installation, which HEAD rejects; `--no-sandbox` is a testing switch, not a qualification |
| Docker, Steam, systemd, Wine | never claimed | need namespaces and the new mount API, keyrings, BPF, syscall user dispatch, cgroup controllers; all are separate projects in the missing-syscalls handoff and the implementation gate |

Two cautions travel with the table. The gate counts (1,146 option executions, 477 io_uring cases, 1,184 broad regressions, and so on) certify the named assertions of those tests, not every option of every advertised call. And the production-readiness document is explicit that a release still needs an application matrix, workload-specific soak and resource-growth measurement, and independent review of the shared pseudofs and VFS changes; passing counts alone are not a claim that every Linux workload is supported.

## Running the busybox integration

The test is an ATF script installed with the kernel tests. It requires amd64, the `linux64` module, and Alpine's static busybox at `/compat/linux/bin/busybox` with its loader at `/compat/linux/lib/ld-musl-x86_64.so.1`; it skips rather than fails when those are absent. It has a ten-minute timeout because it forks busybox five hundred times.

```sh
# stage the userland (any Alpine x86_64 root works; only these two files are required)
mkdir -p /compat/linux/bin /compat/linux/lib
cp alpine-root/bin/busybox /compat/linux/bin/
cp alpine-root/lib/ld-musl-x86_64.so.1 /compat/linux/lib/

# run it
kyua test -k /usr/tests/sys/kern/Kyuafile linux_busybox_test
kyua report --verbose
```

What it checks, in order: `busybox` prints its banner, `echo`, `uname -s` reports `Linux`, shell arithmetic and exit-status propagation, `trap` and signal delivery to a shell, killing a background `sleep`, a `tar czf` and `tar xzf` round trip with matching checksums and a symlink, `grep -c`, `sort -k2 -n`, `awk` sums, `sed`, `find`, `chmod` and `stat`, hard links, a TCP echo through `nc -l` and `nc`, `timeout` re-raising the child's signal, `ps -o pid,comm`, five hundred fork-and-exec iterations, and a large pipe transfer checksummed through `dd` and `md5sum`. The same script is one of the workloads the QEMU gate runs; passing it on the host is a useful smoke test but is not the gate.

The other host-runnable ATF tests in `/usr/tests/sys/kern` follow the same shape: each `linux_*_test` compiles or copies a freestanding Linux probe, brands it, and asserts named cases. `kyua list -k /usr/tests/sys/kern/Kyuafile | grep -E 'linux_|squeue_'` shows the inventory.

## Running the QEMU gate

`tools/test/linuxulator/README.md` is the operating manual; the summary here is enough to know what it asks of you. The gate runs only in disposable virtual machines; the host builds artifacts and runs QEMU and nothing else.

1. Build a kernel with `INVARIANTS` and `WITNESS` and matching `linux64`, `linux_common`, `zfs`, `mqueuefs`, `pseudofs`, `linprocfs`, `linsysfs`, `fdescfs`, `nullfs` and `autofs` modules from the current tree in an isolated object directory. Record hashes and the exact patch. A module built against different kernel option headers can fail to load (`sdt_provider_linuxulator` undefined) or panic on thread exit (RACCT mismatch), so the README insists on verifying the staged hash against the boot log.
2. Cross-compile the Linux probes with `clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror`, brand them with `brandelf -t Linux`, and stage them under `/root` in the guest image with `METALOG.minimal` entries; build the native fixtures static. The README lists every binary each batch requires.
3. Stage `guest-gate.sh` as `/root/linuxulator-gate.sh` and set `init_path="/sbin/init"` and `init_rc="/root/linuxulator-gate.sh"` in the last loader override so that capsule does not take PID 1 in the test image. Set `zfs_load="YES"` and `vfs.root.mountfrom="zfs:linuxgate"`.
4. Build private images with `build-zfs-images.sh AMD64_ROOT ARM64_ROOT OUTPUT_DIR`; it uses `makefs -t zfs` without importing a pool on the host and also creates the two 64 MiB swap disks the swap tests need.
5. Run:

```sh
python3 tools/test/linuxulator/qemu-gate.py \
    --amd64-image /tmp/gate/amd64.img \
    --amd64-swap-image /tmp/gate/amd64-swap.img \
    --amd64-swap-image2 /tmp/gate/amd64-swap2.img \
    --qemu-dir /path/to/qemu/bin \
    --firmware-dir /path/to/qemu/share/qemu \
    --output /tmp/gate/results-$(date +%Y%m%d)
```

The output directory must not exist; it receives the serial logs and `results.json`. The full amd64 suite takes over fifteen minutes under TCG. The runner fails on a missing or duplicate result, a timeout, an unsuccessful QEMU exit, a missing completion marker, any recognized kernel diagnostic, a non-zero final resource counter (`GATE_REQUESTS`, `GATE_BUFFER_PAGES`, `GATE_FILES`, `GATE_ISSUERS`) or an unhealthy pool. Run the portable cases against a Linux reference guest too (the documents use Linux 6.18.35 and 7.1.5); a few cases are deliberately BSD-only and the README names them. Dedicated runners (`qemu-filesystems.py`, `qemu-proc-views.py`, `qemu-fuse-*.py`, `qemu-signal-modes.py`, `qemu-rwf-durability.py` and the rest) exercise their own batches with the same fail-closed rules. Keep failed runs: the documents treat retained failures as evidence, and a batch is not closed while one stands.

## Reporting a gap

A gap report is useful when it says which of the three inventories it belongs in and uses that inventory's vocabulary.

| Symptom | Where it goes | What to record |
|---|---|---|
| `ENOSYS` and a console line `syscall N not implemented` | `docs/linuxulator-missing-syscalls-handoff.md` | the syscall, the binary, and which of the four design groups it falls in; the handoff's definition of done applies |
| an implemented call returning `EINVAL`, `EOPNOTSUPP` or the wrong result for a specific flag | `docs/book/src/compat/linux/syscalls.md` (or `-next-phase-options.md` for io_uring) | the flag, the current errno, the Linux reference errno, and the classification: mapped, no-op-hint, rejected-correctly, rejected-unimplementable, BUG (silently wrong) or GAP (mappable, not done) |
| a missing or wrong `/proc` or `/sys` file | `docs/book/src/compat/linux/procfs-sysfs.md` | the path, the reader (which runtime or tool), and whether a native counter exists for it; fabricated values are not accepted |
| a real application failing for an unlisted reason | `docs/book/src/compat/linux/overview.md` application matrix | the application and version, the invocation, the expected output, and the truss census below |

Do not weaken an assertion to match the emulator's behaviour, and do not report a library's fallback as success of the feature it fell back from; both rules come from the implementation gate and apply to reports as much as to fixes.

## Debugging workflow

Every native tracing tool understands the Linux syscall table because truss, kdump and libsysdecode compile the kernel's `linux_syscalls.c`, and `tests/sys/kern/linux_trace_test.sh` proves all four paths on every build. The workflow below goes from cheapest to most detailed.

```sh
# 1. syscall trace with typed arguments and Linux errno names
truss -f -o app.truss /compat/linux/usr/bin/app args...
grep -E "ERR#" app.truss | sort | uniq -c | sort -rn | head

# 2. census of which calls a run makes (compare against the coverage table)
sed -n 's/^\([0-9]*: \)*\(linux_[a-z0-9_]*\)(.*/\2/p' app.truss | sort | uniq -c | sort -rn

# 3. the same from ktrace, when truss perturbs timing
ktrace -f k.out -t c /compat/linux/usr/bin/app args...
kdump -f k.out | grep CALL | awk '{print $2}' | sed 's/(.*//' | sort | uniq -c | sort -rn

# 4. system-wide, without restarting: the DTrace syscall::linux provider
kldload systrace_linux
dtrace -n 'syscall:linux::entry /execname == "app"/ { @[probefunc] = count(); }'
dtrace -n 'syscall:linux::return /execname == "app" && errno != 0/ { @[probefunc, errno] = count(); }'

# 5. semantic events from the linuxulator SDT provider
dtrace -l -P linuxulator | head
dtrace -n 'linuxulator:pidfd::create { printf("pid %d fd %d", arg0, arg1); }'
dtrace -n 'linuxulator:mmap:linux_range_sealed:denied { @[execname] = count(); }'
```

Notes that save time: `dtrace -c` cannot take control of a static Linux binary (libproc waits for an rtld breakpoint that never comes), so run the tracee beside dtrace as the test does; an `UNKNOWN Linux SYSCALL` line in truss output means the tool was built before the table changed, not that the kernel lacks the handler; a DUMMY slot logs once per process, so `dmesg` after a run is a free census; and `/etc/ssl/*` or `/etc/localtime` `ENOENT` errors from a bare test root are a missing userland, not an emulation bug. For io_uring problems, `dtrace -n 'squeue:::submit { @[arg1] = count(); }'` shows the opcodes a ring submits and `sysctl kern.squeue` shows whether workers or wired pages are the limit; `fstat` marks ring descriptors `[squeue]`. For ptrace problems, `linux_tracee` and the sixteen `linux_ptrace_*` programs are small enough to adapt into a reproducer. See [Observability](../../operations/observability.md) for the native tooling these commands build on, and [Testing](../../develop/testing.md) for how to add a case to the gate.

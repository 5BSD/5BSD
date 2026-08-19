# DTrace and Hardware Tracing

5BSD extends FreeBSD's DTrace with broad userland USDT instrumentation, a
hardened cross-build path for USDT providers, and Intel Processor Trace
support in the kernel `hwt(4)` framework. This chapter covers what is
instrumented, how the build was hardened, and how the virtualization test
suites validate their DTrace providers.

## Expanded system instrumentation

Commit `ec932ce37c7` ("dtrace: expand system instrumentation and harden
USDT builds") adds USDT providers across security-relevant base userland:

- `lib/libcasper` and every Casper service (`cap_dns`, `cap_fileargs`,
  `cap_grp`, `cap_net`, `cap_netdb`, `cap_pwd`, `cap_sysctl`,
  `cap_syslog`) gain `casper`/`cap_*` providers around request handling.
- `login(1)`, `su(1)`, `cron(8)`, `inetd(8)`, `jail(8)`, and `syslogd(8)`
  gain providers for authentication, command dispatch, service activation,
  jail lifecycle, and log-path events.
- Kernel SDT probes were added in the VM subsystem (`sys/vm/vm_map.c`,
  `sys/vm/vm_mmap.c`).

The same commit updates the `bsdinstruments` profile catalog to match
(`cddl/usr.sbin/bsdinstruments/profiles/`, e.g. `tcplife.d`, `sctp.d`,
`biosnoop.d`) and adds `tests/sys/kern/dtrace_catalog_test.sh`, which
checks that catalogued probes actually exist on the running system.

## Hardened USDT builds

USDT provider objects are linked with `drti.o` by `dtrace -G`. The same
commit stages the target-ABI copy of `cddl/lib/drti` before the parallel
prebuild-library pass in `Makefile.inc1`, so a clean cross build never
falls back to the host object (or finds none at all). `cddl/lib/libdtrace`
is now a prebuild library with explicit dependencies on `libctf`,
`libelf`, `libproc`, `libthr`, and `librtld_db`, and `drti.c` itself was
fixed (with a regression test, `tst.fdlopen.ksh`) so USDT registration
works for objects loaded via `fdlopen(3)`.

## Hardware tracing: hwt(4) and Intel PT

5BSD carries the kernel HWT (hardware trace) framework, enabled via
`HWT_HOOKS` in the GENERIC kernel configs (commit `63a9474bf47`).
**HWT itself is cross-platform**: the framework is machine-independent
(`sys/dev/hwt/`) with per-architecture backends — Intel Processor Trace
on amd64 (`sys/amd64/pt/`) and ARM SPE on arm64
(`sys/arm64/spe/arm_spe_backend.c`). **Intel PT, by contrast, is an
Intel-only CPU feature**: it requires Intel silicon and is not available
on AMD processors, even on amd64. The kernel-side PT work is committed
in `sys/`:

- `444a9b288eb` completes the PT feature set: TSC enable for timing
  packets, PTWRITE user trace markers, overflow detection delivered as
  `HWT_RECORD_OVERFLOW` records, and per-range TraceStop filters.
- `ba44c3662b8` fixes race conditions, a buffer-position bug, and adds
  timing support.
- `1bc787e4908` extends MMAP records with `pgoff`/`len` so decoders can
  bias JIT and whole-file `PROT_EXEC` mappings, fixes a dropped MUNMAP
  record address, closes a kernel stack infoleak in the MMAP hook, and
  makes the ToPA table `contigmalloc(9)`-allocated (page-aligned and
  physically contiguous — the previous allocation could corrupt memory
  when the default 64 MB buffer wrapped).

The userland consumer is `bsdtrace(8)` (see the
[ObservableBSD](observablebsd.md) chapter), which programs IP-range
filters per the SDM and decodes traces with libipt.

```sh
# Requires an Intel CPU with Intel PT (not AMD) and the hwt/pt kernel support
bsdtrace exec -- ./mybinary
bsdtrace list
```

Note: the record ABI changed with `1bc787e4908`; `hwt.ko` and `pt.ko`
must be rebuilt together with a matching `bsdtrace`.

## Virtio DTrace validation

The bhyve/WASPNest virtio device models are instrumented with `vsock` and
`virtio` USDT providers (`usr.sbin/bhyve/vsock_provider.d`). Because
provider drift would otherwise only surface at `buildworld`, the harness
validates them standalone:

```sh
sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-dtrace.sh
```

The script runs `dtrace -h` over the provider description, extracts every
`DTRACE_PROBE*` wrapper from `pci_virtio_vsock_probes.h` and
`virtio_pci_modern_probes.h`, and fails if any wrapper lacks a matching
provider declaration. It requires `dtrace(1)` but no bhyve build or root
privileges, so it runs in the rootless sanitizer gate. It is invoked from
the device-harness driver, `tests/sys/kern/vsock_device_harness/run.sh`.

## Profiling entry points

For day-to-day use, prefer the bundled profiles over ad-hoc scripts:

```sh
bsdinstruments list                  # 236 catalogued profiles
bsdinstruments run capsicum-audit    # 5BSD-specific providers included
dwatch tcp                           # classic FreeBSD tooling still works
```

## Status

- USDT instrumentation, build hardening, and the catalog test are
  committed (`ec932ce37c7`).
- Kernel hwt/pt support is committed; one overflow-record race in the PT
  NMI enqueue path remains open pending verification on more PT hardware.
- DTrace validation inside 5BSD guest VMs (as opposed to the host-side
  provider checks above) is still an open work item.

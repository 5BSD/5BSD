# 5BSD FIDL handoff

Status as inspected on 2026-10-10 (second pass): **integrated, VM-validated;
not yet declared production ready** (see Remaining production gates). This
file is a navigation map and a list of unfinished work for the next maintainer.
Read the current files and rerun checks before relying on any recorded result.
The worktree has many uncommitted FIDL, BSDTime, package, book, and unrelated
changes; do not reset or commit unrelated edits. Nothing in this work has been
installed on, activated on, or used to reboot the host.

## Where the work lives

| Area | Source or evidence |
| --- | --- |
| Overall import and limits | `/usr/src/contrib/README.5BSD`, `/usr/src/contrib/fuchsia/README.5BSD`, `/usr/src/tools/build/fuchsia/README` |
| Upstream import, licenses, provenance | `/usr/src/contrib/fuchsia/`, `/usr/src/tools/build/fuchsia/sources.json`, `/usr/src/tools/build/fuchsia/patches/`, `/usr/src/contrib/fuchsia/UPSTREAM*.json` |
| Native runtime and public C API | `/usr/src/lib/libfidl/`, especially `runtime.cc`, `runtime_c.cc`, `include/fidl/bsd/`, `README`, `MATURITY` |
| Native IPC transport | `/usr/src/lib/libchannel/`; FIDL attaches real kernel descriptors through this library |
| Compiler and C/C++ generation | `/usr/src/tools/build/fuchsia/build-fidl.py`, `build-generators.py`, `generate-bsd.py`, `generate_bsd_c.py`, `generate_bsd_c_types.py` |
| Checked-in generated bindings | `/usr/src/lib/libfidl/tests/generated/`, `/usr/src/lib/libtimecmp/generated/`; verify with `test-bindings.py` |
| Representative schema, C client, C provider | `/usr/src/lib/libtimecmp/timecmp.fidl`, `/usr/src/lib/libtimecmp/timecmp.c`, `/usr/src/usr.sbin/BSDTime/BSDTime.c` |
| Provider configuration and CLI | `/usr/src/usr.sbin/BSDTime/config.c`, `/usr/src/usr.sbin/BSDTimectl/` |
| Native tests and fuzz target | `/usr/src/lib/libfidl/tests/`, `/usr/src/usr.sbin/BSDTime/tests/`, `/usr/src/tools/build/fuchsia/fuzz-runtime.py` |
| Build/test/package orchestration | `/usr/src/tools/build/fuchsia/Makefile`, `build-runtime.py`, `test-installed.py`, `test-provider.py`, `test-provider-packages.py` |
| Package declarations and manifests | `/usr/src/packages/{libfidl,libfidl-tests,libtimecmp,libtimecmp-tests,bsdtime-tests,runtime}/`, `/usr/src/release/packages/ucl/` |
| Documentation | `/usr/src/docs/book/src/develop/fidl.md`, `/usr/src/docs/book/src/providers/time.md`, `/usr/src/share/man/man7/fidl.7`, `lib/libfidl/libfidl_bsd.3`, `lib/libtimecmp/libtimecmp.3`, `usr.sbin/BSDTime/BSDTime.8` |
| Gate list and validation record | `/usr/src/lib/libfidl/MATURITY`, `/usr/src/tools/build/fuchsia/VALIDATION.json` |
| Standalone Matter/OpenThread imports | `/usr/src/contrib/connectedhomeip/`, `/usr/src/contrib/openthread/`; they are not proof of native radio/commissioning integration |

## What is validated (2026-10-10)

- Native runtime: 67 C++ runtime tests, C11 integration (including destroy
  with a pending call), 36 generator checks (32 compile/link fixtures), eight
  dependency-graph checks, 1,033 upstream GIDL conformance cases, eight
  evolve:1/evolve:2 C peer pairings and the archive closure check. All pass
  ordinary and ASan/UBSan (sanitizer builds pattern-fill locals).
- BSDTime/libtimecmp: 38 host-safe provider/policy/legacy cases, ordinary and
  ASan/UBSan; earlier 602 s native and 302 s sanitizer soaks still apply.
- Complete world and GENERIC-NODEBUG kernel built from this tree. Base and
  hardware packages were built, checked and published as
  `/usr/obj/usr/src/repo/FreeBSD:16:amd64/16.snap20261010074756.complete`
  (`latest`). Nothing was installed on the host.
- Plane-on VM (`vm-provider.sh`, `/usr/obj/5bsd-fidl-vm/run4`): FIDL BSDTime
  activates as a core unit; 41/41 Kyua cases with the real clock gate,
  0 skipped; live-broker reads, EPERM policy refusal, intended core-restart
  denial and 200 sessions; clean guest poweroff.
- Comparative performance: `bench/bench.json` (see the FIDL book chapter).
- Patched import reproduction: 5,028 entries match contents and modes
  (rechecked 2026-10-10 with `fuchsia-natural-encoder-reuse.patch`).

## IPC performance work (2026-10-10, uncommitted)

- libchannel: right-sized receive blocks, cached pid, single-kevent wait,
  queue-status and receive-with-wait flags; FIDL: pooled call records,
  inline decode storage, encoder buffer reuse. Host raw/C++/C p50
  8.99/11.24/11.35 -> 7.24/8.40/8.53 us.
- mac_capability: small/large/fdset message zones and direct delivery
  (`kern.mac_capability.direct_delivery`).
- Descriptor batching: `MAC_CAPABILITY_SENDMSG_V2` checks type/rights
  expectations for every descriptor before acceptance, narrows the delivered
  copies, moves (closes) the originals and locks inheritance in the same call;
  `MAC_CAPABILITY_RECVMSG_V4` reports each descriptor's type and rights.
  libchannel exposes these (`fd_specs`, `CHANNEL_SEND_MOVE`,
  `channel_message_fd_info`) with a userland fallback for older kernels and
  ioctl-allowlisted channels. Measured syscalls per one-descriptor FIDL call
  (VM, ktrace): C++ 13.15 -> 6.15, C 15.15 -> 6.15.
- VM evidence: `/usr/obj/5bsd-fidl-vm/perf2` hour soak (21.4M replies,
  5.5M descriptors, no fd/heap growth); `fd1` 20-minute soak on the
  descriptor-batching kernel (1.23M moved descriptors); `fd2` plane-on
  libchannel/libfidl/libtimecmp/BSDTime 61/61; `off3` plane-off
  sys/mac_capability 432 passed, 1 failed
  (`coalition_test:exit_membership_waits_for_socket_close`, a TCP-linger
  timing case outside this work), 125 skipped.
- Kernel lifetime races fixed (found by the plane-off run with
  `mac_capability_test_kernelstore` loaded, off4/off5 panics in
  `__mtx_lock_sleep` from `channel_txdrain`):
  (1) a channel peer whose close had dropped its count to zero could be
  revived by a lookup before its revoke detached it -- peer lookups in
  `channel_direct_peer`, `channel_txdrain`, the forward handler and
  `channel_revoke` now use `mac_capability_instance_tryhold()`;
  (2) a revoked endpoint's bearer state could be freed by the peer's close
  while the endpoint still called `co_txdrain`/`co_direct_peer` -- those calls
  now run counted in `ci_inflight` and only before revocation, which waits
  for in-flight work. Regression: `channel_test:peer_close_race`. off6:
  sys/mac_capability 462 passed with the three forwarding tests running,
  no panic; two coalition cases belong to another agent's concurrent
  coalition commits (`refattach_confined_descriptors` SIGSYS,
  `removed_jail_retires_membership` committed after the kernel was built).
  fd3 (plane-on, same kernel): 318/319 with libchannel, libfidl, libtimecmp,
  BSDTime, BSDNetwork and libcapbundle; 600 s soak passed.
- Build note: `lib/libfidl/tests/Makefile` now declares runtime-header
  dependencies for its shared binding objects; without them an incremental
  world linked stale class layouts (SIGBUS in `fd1`).
- Packages published as `16.snap20261010074756.complete` predate this work;
  republish before installing it.

See `VALIDATION.json` and `lib/libfidl/MATURITY` for detail and limits.

## IoT import status (separate from the FIDL production gate)

The original request also included Matter and Thread. Their source is under
`/usr/src/contrib/connectedhomeip/` and `/usr/src/contrib/openthread/`;
`/usr/src/contrib/fuchsia/` retains lowpan integration source. The exact
revisions, archive hashes, submodules and licenses are in
`tools/build/fuchsia/sources.json`, `contrib/README.5BSD`, and each import's
`UPSTREAM*.json`. `tools/build/fuchsia/build-openthread.py --test` recorded
84 configured OpenThread CTest passes; `test-matter.py` recorded 120 standalone
Matter IDL passes. OpenThread POSIX/CLI builds were validated without a
physical radio. Native Matter device/controller, BLE, DNS-SD, commissioning,
persistent storage, and Fuchsia lowpan service adaptation remain undone. The
Matter import is primarily Apache-2.0 with file-specific exceptions; do not
treat every contributed file as BSD licensed. Review notices before packaging.

`tools/build/fuchsia/README` is broad import documentation and contains some
older status wording. For the migrated provider and the most recent measured
results, use current source, `VALIDATION.json`, and the evidence paths above.

## Resolved 2026-10-10: invalid boolean vector decode

The UBSan report from `fuzz-6oemkrlv` (uninitialized `bool b` read after an
invalid wire boolean in `natural_coding_traits.h`) is fixed by
`patches/fuchsia-natural-bool.patch`, which value-initializes both
`vector<bool>` decode temporaries. A patched `import.py --patch` into empty
`/usr/obj` staging matched all 4970 `contrib/fuchsia` entries in content and
mode. `Codec.InvalidBooleanVectorClosesDescriptor` sends a malformed
`vector<bool>` with an attached descriptor and proves rejection plus pipe EOF.
Sanitizer/fuzz builds now add `-ftrivial-auto-var-init=pattern`, so this
class of read fails deterministically; the unpatched header fails the new
test under UBSan. Ordinary and ASan/UBSan suites pass 67 runtime cases; the
old crash replays clean; a 301-second fuzz run executed 8,264,571 inputs with
no reports (`/usr/obj/5bsd-fidl-runtime/fuzz-9e_zdeb2/`). A later
3,601-second run executed 97,597,755 inputs with no reports
(`fuzz-nkwpiqem`), and upstream GIDL conformance now passes.

The fuzz harness is `lib/libfidl/tests/codec_fuzz.cc`; its builder is
`tools/build/fuchsia/build-runtime.py --fuzz`; its runner is
`tools/build/fuchsia/fuzz-runtime.py --seconds 300`. The builder links the
instrumented target before `libclang_rt.fuzzer_no_main` to avoid a toolchain
problem where prebuilt uninstrumented libc++ vector methods were selected
(reproducer: `/usr/obj/5bsd-fidl-runtime/fuzzer-link-reproducer/`). Keep ASan
container checks enabled and investigate any new report as a separate issue.

## License review (2026-10-10)

Fuchsia: BSD-2-Clause plus PATENTS, ICU helper in fidlc, no copyleft or
proprietary code; notices fixed (see VALIDATION.json license_review).
OpenThread and Matter are not committed: OpenThread needs its nested
.gitignore/.gitattributes handled so the committed tree matches the pinned
archive; Matter must be trimmed (CSA data_model and vendor files forbid
redistribution) to the py_matter_idl test subset.

## Remaining production gates

1. Release-transaction upgrade and rollback of BSDTime across boot
   environments. This needs the BSDInstall-based software-authority pipeline
   (`tools/test/software-authority`), whose `prepare-root.py` requires a
   committed, clean source tree; the worktree is currently uncommitted.
2. Policy decision: login shells use a USER-domain lookup channel and
   `system.Time` is not `visible = ["user"]`, so `BSDTimectl` from a shell
   gets ENOENT (as do `BSDPowerctl` and `sysctlcmpctl`). The VM validation
   used a test-only overlay. Decide whether operators should reach it.
3. Final review: licensing/notice audit of the world/package closure and the
   remaining MATURITY boxes. Matter/Thread radio and commissioning remain
   separate unfinished integration work.

libchannel's per-message 14 KiB receive allocation was fixed (see
VALIDATION.json libchannel_receive_allocation). The installed qemu and ten
other packages require libusb.so.4 (built against the 5BSD-libusb world),
while the installed base provides libusb.so.3; vm-provider.sh falls back to
an unpatched local QEMU rebuild.

## Useful commands

Run from `/usr/src` on a host booted with a matching 5BSD kernel. The host SDK
is already bootstrapped at `/usr/obj/5bsd-fidl`; rebuild it if its source
changes. Ordinary host checks use installed kernel-matched base libraries to
avoid false `SIGSYS` failures from an unfinished world's libc/libsys.

```sh
python3.12 tools/build/fuchsia/test-bindings.py
make -C tools/build/fuchsia check-native
make -C tools/build/fuchsia check-soak
make -C tools/build/fuchsia check-fuzz
make -C tools/build/fuchsia check-bench
QEMU=/path/to/qemu KYUA_VARS=test_suites.FreeBSD.vm_clock_test=true \
    BSDTIME_USER_VISIBLE=1 sh tools/build/fuchsia/vm-provider.sh \
    /usr/obj/5bsd-fidl-vm/stage /usr/obj/5bsd-fidl-vm/runN \
    "usr.sbin/BSDTime lib/libtimecmp lib/libfidl"
sh docs/book/tools/check-book.sh /usr/src
mandoc -Tlint usr.sbin/BSDTime/BSDTime.8
```

`check-native` and `check-soak` are lengthy. `check-fuzz` passed a bounded
300-second run on 2026-10-10. The package check builds and extracts
validation archives under `/usr/obj`; it does not install them on the host.
For VM/build work, follow the user's `/home/koryheard/AGENTS.md` build-location
rules and repository instructions, and inspect current object/package state
before any publication.

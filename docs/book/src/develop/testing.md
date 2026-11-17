# Testing

5BSD tests are ATF programs run by Kyua, the same framework FreeBSD uses;
the FreeBSD Developers' Handbook and atf-c(3), atf-sh(3), kyua(1) and
Kyuafile(5) cover the basics and this chapter does not repeat them. What is
5BSD-specific is where a test has to run. A capability provider cannot be
tested in the process that tests it, a kernel service test cannot run while
PID 1 owns `/dev/mac_capability`, and a Linux syscall or a virtual device is
only proven in a disposable guest. This chapter maps each kind of test to the
tier it needs, shows the two harness patterns every provider ships, and lists
the suites with the command that runs them.

The tree also records testing mandates in its design documents, and they are
enforced by the runners rather than left as advice. The one to carry around
is from `docs/book/src/develop/testing.md`: a skipped privileged test
is not a pass.

## Four execution tiers

| Tier | What it can prove | How you get there |
|---|---|---|
| In-session | protocol encoding, parsers, client libraries, device models with mocked rings; root cases skip | `kyua test` in the object tree or `/usr/tests` |
| VM, plane on | providers over a real channel, capsule and switchboard lifecycle, software attributes, container reclaim | a guest booted with capsule as PID 1 and `kern.mac_capability_isolation.enforce=0` |
| VM, plane off | kernel `mac_capability` services, isolation-policy denials (enforce=1), TrustedZFS handles, raw provider transports that must own `/dev/mac_capability` | `capability_plane="NO"` in loader.conf, stock init runs, `kern.mac_capability_isolation.enforce=1` |
| QEMU or bhyve gate | Linux ABI, OES, mac_abac, WASPNest devices; the host builds, the guest is the only evidence | `tools/test/*-qemu`, `tools/test/linuxulator`, `tests/waspnest` |

A test is written for one tier and skips cleanly in the others, naming the
missing thing, which is how the plane-on runners can treat a skip as a
failure.

## The provider_test pattern

Every provider directory under `usr.sbin/BSD*/tests` has a `provider_test.c`.
It is a plane-on test, not an in-process one: the daemon source is compiled a
second time with a `*_TESTING` define that guards out `main()` and exports
the per-session worker, the test creates a real channel through
`/dev/mac_capability`, forks, runs the worker in the child on the provider
end, and drives the client end with the provider's own client library
exactly as a consumer would (raw libservice(3) sessions carry hand-built
malformed frames). The core of `usr.sbin/BSDTime/tests/Makefile`:

```make
PACKAGE=	bsdtime-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDTime

ATF_TESTS_C+= provider_test
CFLAGS+= -I${SRCTOP}/lib/libtimecmp -I${FIDLGEN.timecmp}
CFLAGS+= -I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel
CFLAGS+= -I${SRCTOP}/lib/libservice -I${SRCTOP}/sys
SRCS.provider_test= provider_test.c BSDTime.c config.c
CFLAGS.provider_test+= -DBSDTIME_TESTING
LIBADD.provider_test= timecmp fidl_bsd channel service ucl
NO_SHARED.provider_test= yes

.PATH: ${SRCTOP}/usr.sbin/BSDTime
# Bindings generated into the object tree (lib/libfidl/fidl-bindings.mk).
FIDL_BINDINGS+=	timecmp
FIDL_SCHEMAS.timecmp=	lib/libtimecmp/timecmp.fidl
FIDL_LIBRARY.timecmp=	bsd.time.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"
.include <bsd.test.mk>
```

The seam in the daemon is small. `usr.sbin/BSDPower/BSDPower_test.h` declares
`bsdpower_test_serve_session(int fd, const char *label, const struct powercmp_config *)`
plus setters for the two values `main()` would otherwise cache before
entering capability mode (the sleep-state mask and the narrowed `/dev/acpi`
descriptor). The label is passed by the test, so per-label policy is exercised
without a switchboard. BSDTime goes further and mints a real
`SYS_GATE_SETTIME` token through the system service so `SET` reaches the gate.

Requirements are set in source rather than in `TEST_METADATA`:

```c
ATF_TC(states_reports_cached_mask);
ATF_TC_HEAD(states_reports_cached_mask, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(states_reports_cached_mask, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	uint32_t supported = UINT32_MAX;

	require_plane();
	make_config(&config, false, NULL);
	fixture_create(&fixture, &config);	/* real libpowercmp client */
	ATF_REQUIRE_EQ(0, powercmp_states(fixture.client, &supported));
	ATF_CHECK_EQ(TEST_STATES, supported);
	fixture_destroy(&fixture);
}
```

`require_plane()` opens `/dev/mac_capability` and calls `atf_tc_skip` with
the errno text when it cannot. The case names in these files are the
checklist a new provider should copy: `*_denied_by_default_policy`,
`*_allowed_reaches_gate` (or `_reaches_device`), and, for FIDL providers,
hand-built frames for `method_before_negotiation_is_rejected`,
`unknown_method_is_rejected`, `short_frame_is_rejected`,
`trailing_bytes_are_rejected`, `*_missing_body_is_rejected`,
`legacy_wire_is_rejected` and `rejects_attached_fd`, plus an
`evolution_test` pairing with a peer built from the next schema version.
Positive, negative, malformed-wire and
policy cases sit in one program with section banners.

A minimal program in this shape compiles against the installed headers with
`cc -o example_test example_test.c -L/usr/lib/private -lprivateatf-c`
(in the tree, `bsd.test.mk` links it for you) and skips in-session with
"no /dev/mac_capability: needs a plane-on VM":

```c
#include <sys/stat.h>
#include <atf-c.h>

static void
require_plane(void)
{
	struct stat st;

	if (stat("/dev/mac_capability", &st) == -1)
		atf_tc_skip("no /dev/mac_capability: needs a plane-on VM");
}

ATF_TC(hello_ok);
ATF_TC_HEAD(hello_ok, tc) { atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(hello_ok, tc)
{
	require_plane();
	ATF_CHECK_EQ(0, 0);		/* replace: HELLO round trip */
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hello_ok);
	return (atf_no_error());
}
```

## The fake_service harness

The client library of a provider is tested with no plane and no privilege by
replacing libservice at link time. `lib/libcryptocmp/tests/fake_service.c`
re-implements `service_acquire`, `service_open`, `service_session_create`,
`service_session_call` and the rest of the ABI the client uses, and
synthesizes the provider's reply in-process. The test program links
`fake_service.c` and the client source, and leaves `service` out of `LIBADD`:

```make
ATF_TESTS_C+=client_protocol_test
SRCS.client_protocol_test=client_protocol_test.c fake_service.c cryptocmp.c
NO_SHARED.client_protocol_test=yes
LIBADD.client_protocol_test=pthread
```

The harness API is one arm-the-next-fault setter and a few counters
(`lib/libcryptocmp/tests/fake_service.h`): `fake_service_fault_next()` with
faults such as `FAKE_SERVICE_FAULT_TRUNCATE`, `_WRONG_MAGIC`,
`_WRONG_VERSION`, `_WRONG_OPCODE`, `_POSITIVE_STATUS`, `_MISSING_FD` and
`_UNEXPECTED_FD`; `fake_service_status_next()`; and `fake_service_calls()`,
`fake_service_created()`, `fake_service_closed()`, `fake_service_failed()`.
The counters are how a test proves the client neither leaked a session nor
skipped the RPC. Six libraries carry the pattern (libcryptocmp, libtracecmp,
libauditcmp, liblogcmp, libnotify, libnetworkcmp), each with a
`client_lifecycle_test.c` or `client_protocol_test.c`, and five of them share
`fake_service_max_concurrent()` to assert the client never holds two sessions
at once. These cases use `ATF_TC_WITHOUT_HEAD`, need no root, and run
anywhere.

## Tests that need a real plane

The provider tests, the capsule and switchboard suites and the container
proofs need capsule as PID 1. The in-tree guest rig is
`tools/test/capability-containers/rig/build-image-authority.sh`, which stages
a bootable image with `init_path="/sbin/capsule:/sbin/init:/rescue/init"`, and
`boot-qemu.sh IMG [rw]`, which boots it under QEMU TCG with the serial
console on TCP 4321 and a disk snapshot unless `rw` is given.

Capsule claims `/dev/mac_capability` through the isolation service as soon as
the plane starts, and that claim refuses every other process, root included,
both `open(2)` and `stat(2)` (`EACCES`). A provider test opens the device to
make its own channel, so on a normally booted plane it skips with "capability
plane unavailable: /dev/mac_capability: Permission denied". A plane-on test
image therefore also sets `kern.mac_capability_isolation.enforce=0` in
`/boot/loader.conf` (boot-only, see [Boot Knobs](../operations/boot-knobs.md)):
the resource-access denial is traced and allowed, while ownership denials stay
enforced, so a test can open the device but cannot take over or release
Capsule's claim. For the same reason the suites that start a test-local
Capsule and switchboard (`capd_start_stack`, `capd_launch_capsule`) skip with
"claimed by the live plane" in this tier; they run in a guest with no Capsule
running, which is what `run_capsule_switchboard_capability_tests.sh` below
requires.

The focused cross-daemon suite is run by
`usr.sbin/switchboard/tests/run_capsule_switchboard_capability_tests.sh [-o objtop] [-r results-directory]`
as root in the guest. It refuses to start if a capsule or switchboard is
already running, links static copies of the tools from the object tree so a
tainted root exec cannot bind them to stale installed libraries, stages
`CapabilityKyuafile` (thirteen programs, all `is_exclusive=true`), and runs
one Kyua invocation per named case. Its rule is the strictest in the tree: a
`skipped`, `broken` or `failed` result fails the case, a daemon left running
fails the case, and the run stops at the first failure to avoid contaminated
results.

The rules those tests follow are written down in
`docs/book/src/develop/testing.md`. The test owns every process it starts
and stops its stack before passing; `pkill -f`, `killall` and PID guesses are
forbidden; readiness is event-driven with a monotonic deadline, never a fixed
sleep; fixtures are built with the tree, not compiled from heredocs at run
time; a denial test checks the exact errno or protocol status and that no
side effect happened. The compiled fixtures are `capd_test_guardian`
(`usr.sbin/capsule/tests`), which starts a protected capsule with pdfork(2)
and keeps the process descriptor as the only termination authority;
`capd_test_harness.sh` beside it, which supplies guarded start, stop and
bounded wait to shell tests; `capd_service_fixture` (`lib/libservice/tests`),
a scenario-selected managed service that sends its ready record only after
the observed operation has completed; `capd_protocol_fixture`
(`usr.sbin/switchboard/tests`), which sends deliberately malformed control
requests; and `capd_bootstrap_fixture`, a minimal service-manager double for
capsule bootstrap tests.

## Tests that need the plane off

`tests/sys/mac_capability` drives the kernel services directly by opening
`/dev/mac_capability`. It runs under plain `kyua` in the two VM tiers
described below. Boot a guest with `capability_plane="NO"` (at the loader
prompt or in `/boot/loader.conf`) to keep the plane off: capsule still runs
first but hands off to stock `/sbin/init`, the plane never claims the
device, and the kernel services stay compiled in.
`build-image-authority.sh` does this for you with `CAPLANE_OFF=1`. The old
plane-free `run_tests.sh`, which loaded and unloaded services that are now
compiled in, is retired.

The suite's three fixture services, `mac_capability_test_keystore`,
`mac_capability_test_kernelstore` and `mac_capability_test_cleanup`
(sources in `tests/sys/mac_capability/fixtures`), are built by buildkernel
from `sys/modules` when tests are enabled (or with `ALL_MODULES`) and ship
with the `mac-capability-tests` package, never with a kernel package. They
install in `/usr/tests/sys/mac_capability/fixtures`, off the kernel module
path, so nothing outside the suite loads them by name. The cases load them
themselves: a keystore or kernelstore case kldloads its fixture by absolute
path the first time it connects (`require_fixture()`), and it stays loaded;
the unload cases load and unload the cleanup fixture. No loader
configuration is needed, and a fixture that is missing or refused fails the
case. `vm-provider.sh` reports a run in which kyua skipped any case for a
module that is not loaded (`Required kmods are not loaded`) as
`VM_NOT_CLEAN`. The fixtures register test services: run the suite only in
a disposable guest.
`tests/sys/zfshandle/run_tests.sh` is the TrustedZFS plane-free runner and
needs root and a plane-free boot.

The choice between the two VM tiers is therefore made by what the test must
own. A device-suite test that claims `/dev/mac_capability` is plane-off; an
integration test that talks to a running switchboard is plane-on. One guest
image serves both, rebuilt with or without `CAPLANE_OFF=1`.

`tests/sys/mac_capability` runs in both VM tiers with
`tools/build/fuchsia/vm-provider.sh STAGE WORK "sys/mac_capability"`. The
plane-on run is the standard one. Its isolation cases that expect the policy
to refuse an access (all of `mac_capability_isolation_test`'s denial cases
and `mac_capability_system_test:sysctl_isolation_union_and_subtract`) call
`require_isolation_enforced()` and skip there with the token
`DEFERRED_ENFORCED_TIER`, naming `kern.mac_capability_isolation.enforce=0`,
because that tier's test mode only traces such denials.  The runner counts
them in a `DEFERRED_TO_ENFORCED_TIER=N` line: a plane-on result for this
suite is incomplete until the same stage and suites have also passed in the
enforced tier. They run in the enforced tier, the same command with
`PLANE_OFF=1`: the runner boots `capability_plane="NO"` with
`kern.mac_capability_isolation.enforce=1` (the plane-off default of
`ISOLATION_ENFORCE`) and reports `PLANEOFF_READY` only if the booted value
is the one asked for. The enforced tier is an addition to the plane-on run,
never a substitute: run both.

The production combination, plane on with the policy enforcing, is the third
tier: `ISOLATION_ENFORCE=1` without `PLANE_OFF`.  The gate then checks that
root cannot open the claimed `/dev/mac_capability`.  What this tier proves is
that providers, switchboard and the integration suites work as deployed; run
it with those suites (for example `usr.sbin/switchboard usr.sbin/BSDLog
usr.sbin/BSDNotify sys/dq/dq_bootstrap_test`).  `tests/sys/mac_capability`
drives the device itself and is not part of it.  A case of a deployed-tier
suite that needs the device skips with `DEFERRED_DEVICE_TIER`, counted as
`DEFERRED_TO_DEVICE_TIER=N`: it runs in the plane-on test tier.  Cases that
start a test-local Capsule and switchboard skip with any plane on as
`DEFERRED_PLANEOFF_TIER` (`DEFERRED_TO_PLANEOFF_TIER=N`).  Those that launch
no unit run plane-off on any kernel.  Those that launch units need a unit
issuer, which only PID 1 creates on GENERIC; they call
`capd_require_unit_issuer` and skip elsewhere with `DEFERRED_STACK_TIER`
(`DEFERRED_TO_STACK_TIER=N`, not a pass).  They run on the stack tier:
`GENERIC-TEST` booted plane-off with `kern.mac_capability.test_issuer=1`
(`STACK_TIER=1 KERNEL_TIER=test PLANE_OFF=1 LOADER_EXTRA='kern.mac_capability.test_issuer="1"'`).
There a test-local Capsule gets a test issuer until PID 1 anchors the boot
(`options MAC_CAPABILITY_TEST_PERMISSIVE`, mac_capability(4)).  The runner
labels such a run `stack-tier=yes`; `STACK_TIER=1` requires it, so a run that
asks for the stack tier and misses a condition fails (`STACK_TIER_FAIL`)
instead of counting every stack case as deferred.  It passes `stack_tier=1` to the suites so a
missing issuer fails instead of skipping, and fails the run when stack
suites ran and no test issuer was created.  The harness checks the kernel's
TEST MODE line for each stack it starts, prints the issuer's identity, and
fails a case whose stack leaves a test issuer alive.
`sys/mac_capability/authority_test_issuer_anchor_test` anchors the boot, so
it runs only in a guest of its own, with
`KYUA_VARS=test_suites.FreeBSD.authority_anchor=1`; elsewhere it is counted as
`DEFERRED_TO_ANCHOR_RUN=N`.  It and
`sys/mac_capability/authority_issuer_probe_test` read the
`mac_capability:::issuer-decision` probe with dtrace(1); the runner preloads
`dtraceall` for them, since the plane refuses a late kldload.  What happens
when PID 1 itself anchors is the reroot stage: `REROOT=1` with
`KERNEL_TIER=test PLANE_OFF=1` and
`EXTRA_SCRIPT=tests/sys/mac_capability/authority_test_issuer_reroot.sh`.  The
extra script runs with `VM_REROOT=before` on the plane-off boot, the guest
then reroots into Capsule as PID 1 with the plane on (`kenv -u
capability_plane; kenv init_path=/sbin/capsule; reboot -r`), and runs it
again with `VM_REROOT=after` before the suites.  The run is clean only when
both runs exit 0 and Capsule is PID 1 after the reroot.  By default the
script also sets `debug.mac_capability.test_issuer_fail_init`, so PID 1's
create fails after it anchors; `LOADER_EXTRA` with
`vm_reroot_variant="plain"` selects the plain reroot.  The `usr.sbin/bsd-build` cases that read the
source tree need `SRC_IMAGE` (and `PORTS_IMAGE` for package plans); without it
they are counted as `DEFERRED_TO_SOURCE_TIER=N`.  With python, the source and
the ports images, a long bsd-build run fills the default 8 GB guest root:
give it `ROOT_SIZE=16g`.
A `tests/sys/dq` case that needs a fault knob of `options DQ_FAULT_INJECTION`
(`debug.dq.delay_swap_take`, `debug.dq.delay_postop_apply`) calls
`dqt_require_fault_knob` and skips on a kernel without the option with
`DEFERRED_KNOB_TIER`, counted as `DEFERRED_TO_KNOB_TIER=N`: it runs in the
knob tier, `KERNEL_TIER=test` with a GENERIC-TEST stage.
Cases that drive their private SwitchBoard with `switchboardctl` call
`use_private_control` (`usr.sbin/switchboard/tests/test_helpers.sh`): it runs
`switchboardctl` through `capd_lookup_exec`, which installs the private
Capsule's discovery route (control operation `CTL_OP_LOOKUP`) in the process
slot in place of the inherited one, so a test can never drive the system
SwitchBoard.  The private SwitchBoard admits a copy of the shipped control
bundle registered by the test-local issuer.

Each of these tiers also has a kernel tier.  The main tiers (plane on,
`PLANE_OFF=1`, `ISOLATION_ENFORCE=1`) boot a kernel without any test-kernel
option (`GENERIC`); the knob tier boots `GENERIC-TEST`, which carries every
live option of the test-kernel option ledger, `sys/conf/test-options` (today
`DQ_TEST_OPEN`), and whose knobs the loader sets
(`debug.dq.unverified_open="1"` through `LOADER_EXTRA`).  `KERNEL_TIER`
defaults to `main`; the knob tier must be asked for with `KERNEL_TIER=test`,
and the runner refuses a stage whose kernel carries a test-kernel option
otherwise.  The runner proves the tier rather than trusting a configuration
name: on the host it runs `release/scripts/check-test-kernel.sh` on the
stage's `boot/kernel` (a refusal means a test kernel) and on its whole boot
directory, which must agree, and records the kernel file's SHA-256 and
version string; in the guest the booted `kern.bootfile` must have that
hash, `kern.version` must be that version, and the ledger's knobs must
exist exactly on a test kernel.  Only then does it print
`TIER_INFO: TEST_KERNEL=yes` or `=no` and `TEST_KERNEL_PROOF_PASS`; a run
is `VM_CLEAN` only with exactly one such line and no
`TEST_KERNEL_PROOF_FAIL`.  The proof, every knob's value, the plane state
and the loaded MAC policy modules (`kldstat -v`) are written to `tier.txt`
in the results, next to the Kyua database, and the knobs are appended again
after the suites.

The runner's own checks (the tier selection and gate above, the stage root
metadata preflight, the extra-script status) are shell scripts under
`tools/build/fuchsia/tests/`; `make -C tools/build/fuchsia check-runner`
runs them on the build host without booting a guest, and `check` includes it.

The other plane-free runner is `tools/test/capability-qemu/run.sh`, which
stages kernel, modules, libraries and test binaries onto a CD image, boots a
`-snapshot` guest, installs from the CD, reboots into single-user mode and
runs a generated Kyuafile with `kyua -c none -v test_suites.capability.allow_sysctl_side_effects=true test -k Kyuafile`.
The install and run are separate boots so the replacement kernel and modules
start clean, and raw provider-transport tests run before init claims the
device.

## The QEMU gates

Some subsystems are never considered tested on the host. The Linuxulator
gate, `tools/test/linuxulator/README.md`, is explicit: QEMU is the
correctness gate, the host only builds artifacts and runs QEMU, and every
supplied image must boot from ZFS; a UFS-root run fails. The runner is

```sh
python3 tools/test/linuxulator/qemu-gate.py \
    --amd64-image /tmp/gate/amd64.img \
    --amd64-swap-image /tmp/gate/amd64-swap.img \
    --amd64-swap-image2 /tmp/gate/amd64-swap2.img \
    --qemu-dir /path/to/qemu/bin \
    --firmware-dir /path/to/qemu/share/qemu \
    --output /tmp/gate/new-results-directory
```

with images built by `build-zfs-images.sh`. It requires complete named case
sets and fails on a missing or duplicated result, a timeout, an unclean QEMU
exit or a recognized kernel fault string. The ATF wrappers it drives,
`tests/sys/kern/linux_*_test.sh`, compile a freestanding Linux payload in
the guest with `clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static`
and run it; the `linux_break_*` set (epoll, files, futex, mmap, mseal, pidfd,
procvm, signalfd, signals, sockets) is the adversarial half.

The WASPNest gate is `tests/waspnest/waspnest-test.sh`, installed as
`/usr/tests/waspnest/waspnest-test`, with exactly one argument:
`list | status | post-reboot | audit | host | plan | release-ready | run`.
`host` runs the three rootless Kyua corpora (device models in
`tests/sys/kern/vsock_device_harness`, guest transport in `vsock_rx_harness`,
VMM in `tests/sys/vmm`); `run` needs root and, by default, the installed
`/usr/tests` payload (`WASPNEST_ALLOW_UNTRUSTED_SOURCE=yes` permits a reviewed
checkout); `release-ready` refuses while any row in the TSV ledgers
(`waspnest-suite.tsv`, `virtio-feature-activation.tsv`,
`waspnest-nonvirtio-coverage.tsv`) is unresolved. `PROFILE` selects the live
lanes: `qualification`, `full-qualification`, `intel-qualification`,
`nested`, `nested-default`; the default is chosen from
`hw.vmm.vmx.initialized`.

The smaller rigs share one shape: `tools/test/oes-qemu/run.sh IMAGE` and
`tools/test/mac-abac-qemu/run.sh IMAGE` boot a disposable guest under TCG
(no host root, no `/dev/vmm`), attach the current module, library and Kyua
suite on a read-only CD, and run `kyua test -k Kyuafile` inside.
`tools/test/trustedzfs-qemu` ships only the guest-side scripts.

## Fuzz corpora

There is one set of libFuzzer harnesses in the tree,
`tests/usr.sbin/bluetooth/BSDBluetooth/fuzz`. Its Makefile builds 24
`fuzz_*` harnesses over the parsers that consume untrusted bytes (ATT server
and client, advertising data, SMP, L2CAP signalling and data, HCI events,
config, mesh network, transport, provisioning, proxy, friend, SBC audio) with
`-fsanitize=fuzzer,address,undefined`, plus 17 `std_*` replay drivers without
the libFuzzer runtime. It is deliberately not wired into `bsd.test.mk`.
The corpus is not committed: `make corpus`, which `make check` and every
`run-*` target run first, writes the seed inputs of `gen_corpus.sh` into
`corpus/`, and the inputs libFuzzer evolves there stay out of the tree:

```sh
make            # build all harnesses and replay drivers
make corpus     # regenerate the seed corpus
make check      # replay the seed corpus under ASan/UBSan (CI-safe)
make run-att    # coverage-guided fuzz of one harness
make smoke      # brief coverage-guided run of every harness
```

Two harnesses `#include` the kernel L2CAP translation units directly to reach
static handlers, with the kernel-only header guards predefined.

## The -tests packages

Every daemon and library ships its suite as a pkgbase package. `packages/Makefile`
lists 47 of them behind `MK_TESTS`; a package is three files. The program's
tests Makefile names the package and the install directory:

```make
PACKAGE=	bsdlog-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDLog
```

`packages/bsdlog-tests/Makefile` declares the dependencies
(`atf`, `kyua`, `bsdlog`, `switchboardctl`, `set-base`) and points at
`release/packages/ucl/bsdlog-tests-all.ucl`, whose `annotations { set = "tests" }`
puts it in `5BSD-set-tests`. Packaging is covered in
[Packaging and Shipping](packaging.md). On an installed system the suite is
then at the path `TESTSDIR` named:

```sh
pkg install 5BSD-bsdlog-tests
kyua test -k /usr/tests/usr.sbin/BSDLog/Kyuafile
kyua report --verbose
```

`kyua test -k /usr/tests/Kyuafile` runs everything installed; in the object
tree, `kyua test -k` on the generated Kyuafile does the same before
installation. The `run_capsule_switchboard_capability_tests.sh` runner works
in both modes with the same cases and fixtures; only binary paths change.

Some 5BSD packages carry more than one suite: `runtime-tests` holds the
BSDTime and BSDPower tests because those daemons live in the `runtime`
package, and `libsysctlcmp-tests` holds the BSDSysctl provider test.

## Suites and how to run them

This table is the inventory's suite table, corrected where the tree at HEAD
differs (the Bluetooth fuzz count is the Makefile's).

| Suite | Path | Covers | How to run | Approx count |
|---|---|---|---|---|
| Bluetooth ATF | `tests/usr.sbin/bluetooth/BSDBluetooth` | blued/meshd/libble/libmesh vs spec oracles | in-session (`kyua test`); hardware cases skip | 165 programs / ~3,750 cases |
| Bluetooth fuzz | `.../BSDBluetooth/fuzz` | untrusted PDU parsers | in-session `make check` / `make smoke` | 23 harnesses + 17 replay drivers / 5,248 seeds |
| Component libs + ctl tools | `lib/*/tests`, `usr.sbin/*ctl/tests` | protocol, parser, client API | in-session (root cases skip) | ~40 dirs / ~700 cases |
| Daemon suites (BSD*) | `usr.sbin/BSD*/tests` | provider policy, sessions, bundles | in-session unprivileged; full = VM plane-on | 15 dirs / ~600 cases |
| Capsule + switchboard | `usr.sbin/{capsule,switchboard}/tests` | boot, lifecycle, management, rc adoption | VM plane-on (`run_capsule_switchboard_capability_tests.sh`) | 36 programs / ~370 cases |
| mac_capability | `tests/sys/mac_capability` | kernel capability services | VM plane-on (`vm-provider.sh`) plus the enforced plane-off tier (`PLANE_OFF=1`, enforce=1); the cases load their fixtures | 10 programs / ~506 cases |
| zfshandle / tzfs | `tests/sys/{zfshandle,tzfs}` | TrustedZFS handles, config | VM plane-off / trustedzfs-qemu | 11 programs / ~66 cases |
| Capsicum/descriptor rights | `tests/sys/kern`, `tests/sys/capsicum` | new rights + envfd + capmode exec | in-session (root); envfd exclusive | ~10 programs / ~340 cases |
| Linuxulator | `tests/sys/kern/linux_*` + `tools/test/linuxulator` | Linux ABI, ptrace, rseq | QEMU gate (ZFS-root guest) | 58 sh programs; 1,146 option runs |
| OES / mac_abac | `tests/sys/security` | endpoint security, ABAC | QEMU gate (`tools/test/*-qemu`) or VM root | 48 + 3 programs |
| WASPNest models | `tests/sys/kern/vsock_device_harness`, `vsock_rx_harness`, `tests/sys/vmm` | device models, guest vsock, VMM | in-session rootless (`run.sh`, ASan) / `run-vmm-root.sh` | 166 programs / ~2,290 cases |
| WASPNest live | `tests/sys/kern/vsock_e2e`, `tests/waspnest` | guest activation, checkpoint, nested VMX, soak | bhyve host root (`waspnest-test run`) | 11 release gates |
| Container proofs | `tools/test/capability-containers` | reclaim/reconcile model | QEMU rig, plane-on (`run-all.sh`) | 14 proofs |
| DTrace catalog | `tests/sys/kern/dtrace_catalog_test.sh` | shipped D scripts compile | in-session root | 14 scripts |
| DTrace fbt exclusion | `tests/sys/kern/dtrace_fbt_exclusion_test.sh` | fbt keeps out of DTrace itself; every fbt entry probe under kinst, pid, sdt and syscall probes | listing case: in-session root; enabling case: VM root with `allow_dtrace_fbt_selftest=yes` | 2 cases |
| ktest sglist | `tests/sys/kern/sglist_boundary_test.py` | kernel sglist boundaries | in-session root (kmod) | 1 |
| Release integrity | `tests/release` | base-integrity tool | in-session | 2 cases |

Kernel and security suites that need a module or global state say so with
`TEST_METADATA`, the FreeBSD way; `tests/sys/security/mac_abac/Makefile`
sets `required_user="root"`, `required_kmods="mac_abac"` and
`is_exclusive="true"` per program. The 5BSD daemon suites do not use
`TEST_METADATA` at all: requirements live in the C source, in `atf_set` in
shell tests, or in the Kyuafile.

## The mandates

The design documents state what a suite must contain, and the wording is
worth knowing because reviewers apply it. The former Linuxulator option review (since folded
into [System Calls](../compat/linux/syscalls.md)) set the target as a conformance suite where every row has at least one
positive and one negative check, plus adversarial, stress and lifecycle
coverage. The former Linuxulator implementation gate added that tests assert
semantics rather than duplicate implementation branches (an OFD lock test
proves an unrelated close does not release the lock; a seal test attempts the
prohibited write), that a library's fallback must not be mistaken for use of
the new feature, and that infrastructure errors fail the gate.
`docs/book/src/develop/testing.md` states the objective for the plane:
the suite must show that authority is created, confined, transferred, used,
revoked and recovered correctly under success, denial, concurrency, crash and
timeout conditions. `docs/service-discovery-model.md` heads its test matrix
"do NOT skimp".

In practice a new provider's suite has four parts: positive cases for every
op; negative cases for every policy denial with the exact errno; adversarial
cases for every malformed wire shape (short, oversized, wrong magic, wrong
version, unknown opcode, attached descriptor where none belongs); and
lifecycle cases (provider restart, session loss, reclaim of what the provider
owned for an uninstalled bundle). The Bluetooth suite shows what the far end
of this looks like: `spec_requirements.tsv` binds each requirement ID to a
Bluetooth Core citation, a Kyua selector and an independent oracle,
`spec_traceability_audit.sh` refuses a Kyuafile whose cases lack a citation,
and `coverage.sh` fails when any file in `coverage-baseline.txt` drops below
its recorded line or branch coverage.

## Known gaps

Two BSDFilesystem tests are disabled pending a fake-service harness for that
library (`tests/sys/tzfs/Makefile`). The lane metadata
(`quick`, `kernel`, `stack`, `installed`, `stress`, `hardware`) described in
`docs/book/src/develop/testing.md` is a design; CI selection by lane is
not fully implemented. The Linuxulator wrappers compile their
payloads at run time in the guest, which the capability daemon rules forbid
for daemon tests; the two disciplines are scoped to different subsystems.

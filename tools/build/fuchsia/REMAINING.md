# FIDL / IPC work: what is left (2026-10-10 15:45 UTC)

Status 2026-10-10 23:00 UTC: steps 1-3 and 5 DONE.
- 1: libnetgraph fix (1ca64091990); dev builds clean.
- 2: committed (58977d8dfd1) and VM-validated (fd4 on dev d51b2cf8c22).
- 3: MATURITY box checked, HANDOFF gates closed, VALIDATION.json updated.
- 4: HELD by the user until further notice.

Read `/home/koryheard/AGENTS.md` first (build in /usr/obj, all CPUs, never
install or reboot the host, publish only through the maintained /usr/src
package targets). Then `HANDOFF.md`, `VALIDATION.json` and
`lib/libfidl/MATURITY` in this directory for history and evidence.

Branch: `fix/kldload-broker-guidance` in `/usr/src` (shared with other agents;
coalition/daemon-runtime and Starnix agents were still committing at 15:35).
Never commit other agents' uncommitted files; stage paths explicitly.

## 1. Fix the broken build at HEAD (blocks everything)

The PF commit `c445c44591c` ("Retire IPFW engine…") deleted
`sys/netgraph/ng_ipfw.h`, but `lib/libnetgraph/debug.c` at HEAD still has
`#include <netgraph/ng_ipfw.h>` and `COOKIE(IPFW),`. A clean buildworld
fails at `debug.o`. The working tree already removes both lines
(uncommitted). Ask the user whether the PF agent or you commits it, then:

    cd /usr/src && make -j16 buildworld buildkernel KERNCONF=GENERIC-NODEBUG

buildworld stops at the first error; repeat until it passes in case the
IPFW removal left other references (search case-insensitively for `ipfw`).
Commit as e.g. "Remove stale ng_ipfw reference from libnetgraph".

## 2. Validate and commit the shell-visibility change (user-approved)

The user decided operators reach system.Time, system.Power and
system.Sysctl from a login shell. Uncommitted files (all this work):

- `usr.sbin/BSDTime/capbundle/BSDTime.ucl`, `usr.sbin/BSDPower/capbundle/BSDPower.ucl`,
  `usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl`: `visible = ["user"];`
- `usr.sbin/switchboard/tests/service_reachability_test.sh`: time/power/sysctl
  reachable cases
- `docs/book/src/providers/time.md`, `tools/build/fuchsia/HANDOFF.md`
- `tools/build/fuchsia/vm-provider.sh`: removed the BSDTIME_USER_VISIBLE
  overlay (no longer needed; it would now fail)

Validate after step 1 builds:

    S=/usr/obj/5bsd-fidl-vm/stage2
    chflags -R noschg $S; rm -rf $S          # always restage from scratch:
    cd /usr/src && make -j16 installworld distribution DESTDIR=$S -DNO_ROOT \
      && make installkernel DESTDIR=$S -DNO_ROOT KERNCONF=GENERIC-NODEBUG
    cd /usr/obj/5bsd-fidl-vm && cp /usr/src/tools/build/fuchsia/vm-provider.sh vm-provider.fd4.sh
    KYUA_VARS=test_suites.FreeBSD.vm_clock_test=true CPUS=4 sh vm-provider.fd4.sh $S \
      /usr/obj/5bsd-fidl-vm/fd4 "usr.sbin/switchboard usr.sbin/BSDTime lib/libtimecmp \
      usr.sbin/BSDPower usr.sbin/BSDSysctl lib/libfidl lib/libchannel" 7200 > fd4.out 2>&1

Pass criteria: `PLANEON_GATE_PASS`, `BSDTIME_LIFECYCLE_PASS`, the console
`BSDTIME_CONTROL [BSDPowerctl states]` and `[sysctlcmpctl get kern.ostype]`
lines now `ok` (they were ENOENT before), `time_reachable`,
`power_reachable`, `sysctl_reachable` pass, no failed/broken cases
(`tr -d '\r' < fd4/serial.log | grep -aE '\-> +(failed|broken)'`). Then
commit those files only.

## 3. Close the last maturity gate (needs user confirmation)

`lib/libfidl/MATURITY` has one open box: "Final review, source reproduction,
manuals/book, complete validation record". HANDOFF lists a "release
upgrade/rollback VM" gate. The previous agent recommended NOT running the
full software-authority release pipeline for FIDL (hours; mostly re-proves
generic installer/BE behavior). Upgrade compatibility is already covered by
the 8 evolve:1/evolve:2 schema-evolution pairings, the existing
`tools/test/software-authority/software-be-guest.sh` BE candidate/rollback
test (BSDTime is among its checked units), and the plane-on VM runs. If the
user agrees: check the box citing that evidence, remove the gate from
HANDOFF "Remaining production gates", and update `VALIDATION.json`
(`fidl_native_runtime.status` still says VM validation "pending" — stale;
`not_delivered` still lists "production capability-plane VM validation of
migrated FIDL services" and "release-transaction upgrade/rollback VM
validation" — update).

## 4. Republish packages (ask the user first)

The published `/usr/obj/usr/src/repo/FreeBSD:16:amd64/16.snap20261010074756.complete`
predates all of today's work. The user held republishing until other agents
settled. When told to proceed, use the maintained targets with
`PORTSDIR=/usr/obj/5BSD-ports`: `system-packages`, `hardware-packages`,
`hardware-packages-check`, `publish-packages` (see AGENTS.md). Only complete
publication advances `latest`. Do not install.

## 5. Records

After each step update `VALIDATION.json`, `HANDOFF.md`, `lib/libfidl/MATURITY`
and the Desktop checklist `~/Desktop/Fuchsia tests for next VM.txt`
(strike through passed items with VM evidence).

## 6. Capability daemons on FIDL (branch `fidl/daemons`, 2026-10-12)

Nine providers serve FIDL; see `DAEMONS.md` (Progress) and VALIDATION.json
`fidl_daemons`.  Open items:

- User decisions: library layout for the libservice-embedded clients
  (BSDVM, BSDNamespace, BSDExtension, BSDFilesystem); system.Network.PF,
  whose only consumer is the out-of-tree sysutils/5bsd-instruments.
- BSDBluetooth: isolate the plane/controller code its test matrix compiles
  directly, then convert ATTACH and Controller.
- Latency: FIDL calls are 1.0-2.5x slower at p50 in the TCG guest with
  fewer system calls per call; profile the C bridge/codec path on hardware.
  `dtraceall` fails to load in the plane-on guest, which blocks the
  libchannel probe measurements in `vm-daemons.sh`.
- Pre-existing, not FIDL: logctl_test `unavailable`/`severity_names`
  expect no system.Log and fail in any plane-on VM; BSDNetwork resolves
  `localhost` only if BSDFilesystem served /etc/hosts when it started
  (resolver.c netresolve_init).

## Done today (for orientation)

Commits: `9ec24a62c93` IPC speedups, descriptor batching (SENDMSG_V2 /
RECVMSG_V4) and two channel use-after-free fixes; `3c95dbd0267` test
expectations; `7ff512fd7ff` zsh default; `98d6ac1a3b5` installer docs;
`cf97f876797` FIDL + Fuchsia import + BSDTime migration; `a7b358373a7`
OpenThread and license-clean Matter IDL subset. License review of all three
imports recorded in `contrib/README.5BSD` and `VALIDATION.json`.

## Pitfalls seen today

- Incremental world can keep stale objects; `lib/libfidl/tests/Makefile` now
  declares header deps for its shared binding objects. If C tests SIGBUS,
  suspect stale objects.
- Restage into an empty directory every time (NO_ROOT METALOG appends).
- Other agents build in the same /usr/obj world objdir; a test binary can be
  newer than the kernel it runs on.
- Run heavy builds and VMs one at a time (an earlier host hard reset).
- Plane-off VM runs: `PLANE_OFF=1`; load `mac_capability_test_kernelstore`
  via `EXTRA_SCRIPT` (`/usr/obj/5bsd-fidl-vm/extra-kernelstore.sh`) so the
  forwarding tests run.  From integrate/dev-20261011 on, that module (and
  the keystore one) is no longer built or installed with the system
  modules: build it from tests/sys/mac_capability/fixtures, ship it into the
  guest (e.g. vm-provider.sh `EXTRA_DIR`) and point
  `MAC_CAPABILITY_FIXTURE_DIR` at it for the isolated capability tests.
  Coalition-test failures there belong to the
  coalition agent.
- Auto mode treats widening service visibility as a permission grant; the
  user approved it explicitly for these three services.

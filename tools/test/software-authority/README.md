# Software-authority guest acceptance fixtures

These scripts run only inside a disposable `auth-policy-vm` guest. They replace
`tools/test/management-policy` and `tools/tools/anointments`, which exercised the
retired per-user principal-policy and elevation design.

The guest must contain a freshly installed world/kernel, the helper programs
from `tests/sys/mac_capability`, attributed test bundles, libservice and
SwitchBoard test binaries, and a root ZFS boot environment named
`policyvm/ROOT/default`. Stage the guest scripts under `/root` and compile the
terminal and Trace helpers against the same world. `policyuser` has UID/GID
2001; `policy-vm-only` is a disposable test password, never a deployment default.
The terminal driver is installed as `/usr/bin/policy-askpass`.

Run `software-application-guest.sh` from the root serial-console login. It checks
software identity independently of UNIX credentials; password login; password,
keyboard-interactive and public-key SSH; `su` transitions; service admission and
management; cached-handle revocation; untrusted user-agent manifest restrictions;
retired package removal in an inactive BE; and candidate/rollback boot behavior.
`software-trace-guest.sh` adds provider-level Trace descriptor checks. The main
script must remain the serial-login action across the two BE reboots.

The fixtures create and remove test accounts' files, alter test bundle policy,
install retired packages only into an inactive BE, and reboot the guest. Do not
run them on an installed workstation or server. The host harness must require
all expected pass markers, actual QEMU exit, clean poweroff, and no panic or
WITNESS reversal. A passing development overlay is not a clean-build result;
neither replaces testing an actual BSDInstall-created system.

The kernel-only PID-1 fixture (`authority_boot_helper`) separately exercises
issuer restrictions, executable and loader identity, process transitions,
jails, resource gates and teardown. It must never run as the host's init.
It checks that root cannot attach to or become the debugger of a separate
execution sharing its software authority, including a different UNIX UID. Fork
without exec retains the existing debugging boundary; failed exec leaves it
unchanged. Use a GENERIC kernel with WITNESS and INVARIANTS to qualify changes
to these process-lock paths.

The isolation file-token regressions keep software authority distinct from
execution admission. They check software-authority clear/revoke against cached
access, and bind a separate token to kernel-stamped receive metadata. That
admitted process can read; its fork child cannot activate the token or read the
retained file descriptor; the parent remains authorized. Exec of the admitted
process also loses access despite retaining software authority and descriptors.
The harness requires the invocation regression's completion marker. These cases
exercise transient file isolation, not persistent BIP storage boundaries.

The managed-provider shell regression executes the supplied world's `/bin/sh`
with a startup file and deliberately inherited bound endpoint. Returning to the
original constrained executable must leave managed authority invalid and endpoint
use denied; the parent remains authorized. The harness resolves shell ELF
libraries inside the supplied world, records their hashes, and requires the
shell regression marker. This does not qualify bootstrap BIP grants or every
inherited descriptor type. Shell startup commands remain ordinary software.

## Kernel fixture harness

The PID-1 fixture now also runs the production SwitchBoard NSS exchange and
child setup while it holds valid attached authority and an installed kernel
lookup channel. It requires the exec-constructor probe to observe neither
context, an empty environment, no-new-privileges, and closed test descriptors;
the parent must retain its original authority/context and descriptor. The probe
comes from the matching `usr.sbin/switchboard/tests/nss_isolation_probe` build
output, is copied as a test-only executable, and is hashed in result.json.
The runner requires `PASS authority-nss-helper-clears-inherited-authority-and-discovery`;
a skipped empty-context ATF run cannot satisfy this gate.

A second required case registers a separate test executable and first proves
that ordinary exec actually acquires its assigned authority. The stripped NSS
probe then execs that same registered image. Its test entry point must observe
no attached authority or discovery context and retained no-new-privileges before
returning the reply. The runner requires
`PASS authority-nss-helper-cannot-reacquire-registered-authority` as well. The
registration is owned by a temporary fixture issuer and revoked by closing it;
no production executable registration or owner policy is changed.

This check is prepared and syntax-checked, not guest-qualified. It tests the
inherited-state boundary with real kernel objects, not installed account-service
compatibility, hostile NSS plugin behavior, every descriptor type, or Secure
Boot/BIP as a whole. The new re-exec case is prepared but has not run. The
separate NSS integration/transport tests and normal installed workloads remain
required. Do not execute authority_boot_helper as host PID 1.

The authority helper also checks binding ownership: failed target lookup,
wrong descriptor type, foreign issuer and repeated binding must not leak retained
authority references. Closing the issuer revokes bound authority; closing the
endpoint releases its binding. run-kernel.py requires the corresponding
completion marker. This checks shared kernel binding mechanics, not persistent
BIP storage grants or synchronous I/O revocation.

`run-kernel.py` creates an unprivileged UFS image with `makefs`/`mkimg`, boots
it with QEMU in snapshot mode, and records the command, kernel and test hashes,
serial-log hash, exit status, and pass/fail result in a new work directory.
It accepts explicit paths and does not use a home-directory checkout or change
the host installation. For example, after staging the matching world, kernel,
and distribution with `NO_ROOT=yes`:

```sh
python3.12 tools/test/software-authority/run-kernel.py \
    --root /usr/obj/qualification/root \
    --objtop /usr/obj/usr/src/amd64.amd64 \
    --kernconf GENERIC-NODEBUG \
    --workdir /usr/obj/qualification/kernel-vm
```

Use `--qemu` and `--qemu-data` to select a separately built emulator and its
firmware directory. The emulator must start with its normal runtime library
search path (or an explicitly supplied environment). The harness validates
required inputs and matching staged/object kernel configurations before
creating output. A timeout, panic, WITNESS reversal, missing completion marker,
forced termination, or missing clean shutdown fails the run.

This kernel-only result does not qualify login, SSH, services, boot environments,
or installer media. Those require the integrated guest and BSDInstall tests
above. Using existing build inputs validates the harness; only fresh inputs
can provide clean-build evidence.

## BSDInstall target acceptance

`run-installed.py` runs the integrated guest suite in QEMU's temporary snapshot
of a BSDInstall-created target. It requires an installation directory containing
`installed.img`, successful `install-result.json` and `installed-boot/result.json`
evidence, and a fixture directory containing `fixtures.tar` and `fixtures.json`.
The fixture manifest binds the archive to its prerequisite VM result and the
installed kernel identity. These inputs are produced by the installer and
fixture preparation stages; this runner does not create or replace those stages.

```sh
python3.12 tools/test/software-authority/run-installed.py \
    --installation /usr/obj/qualification/installation \
    --fixtures /usr/obj/qualification/fixtures \
    --work /tmp/5bsd-installed-acceptance
```

Use `--qemu`, `--qemu-data`, `--cpus`, and `--timeout` to select the emulator,
firmware, guest CPU count, and run deadline. Keep the output path short enough
for local UNIX-domain serial and QMP sockets. The runner preserves the original
disk, attaches the fixtures read-only, and installs test bundles only into the
VM snapshot. It requires all 30 acceptance markers independently of the
prerequisite result's marker list. `--require-marker` can add requirements.

`qmp_shutdown.py` records lifecycle events without requesting shutdown. Passing
requires a guest-originated shutdown, exit status zero, no forced termination,
all suite markers, and no panic or lock-order reversal. Sequential and parallel
control requests also run; their timings describe QEMU execution, not native
hardware performance. Run with ordinary Python settings: `-O` is rejected
because it disables evidence assertions.

The installer and first-boot gates use the same emulator options:

```sh
python3.12 tools/test/software-authority/run-installer.py \
    --iso /usr/obj/qualification/installer/software-installer-test.iso \
    --work /usr/obj/qualification/installation
python3.12 tools/test/software-authority/boot-installed.py \
    --installation /usr/obj/qualification/installation \
    --expected-kernel /usr/obj/qualification/root/boot/kernel/kernel
```

The installer runner accepts only private automated test media with a matching
`media.json` hash and creates a new 32 GiB sparse disk. It runs without a network
interface and never selects a host block device. Its result alone does not
prove installed boot or service behavior. The first-boot runner uses a temporary
disk snapshot, validates the installed kernel hash and package inventory, and
checks control discovery and the DTrace module. The full suite follows it.
`boot-installed.py --work` allows a separate diagnostic run without overwriting
the prerequisite result used by the full suite.

## Fresh integration input preparation

The portable preparation tools use a frozen source checkout, its fresh object
root, and the disposable `NO_ROOT` staging root. `prepare-root.py` requires a
successful clean kernel VM result, verifies the source revision and clean tree,
and records fixture-source hashes. It adds test accounts only under the build's
`root` directory. `stage-vm.py` makes a separate seed image, preserving installed
control programs and adding explicitly attributed test bundles.

```sh
python3.12 tools/test/software-authority/prepare-root.py \
    --build "$build" --root "$build/root" --source "$build/src" --objtop "$objtop"
python3.12 tools/test/software-authority/stage-vm.py \
    --build "$build" --root "$build/root" --source "$build/src" --objtop "$objtop" \
    --work "$build/integration" --retired-packages "$retired_packages"
python3.12 tools/test/software-authority/run-seed.py --work "$build/integration"
python3.12 tools/test/software-authority/run-vm.py --work "$build/integration"
```

`retired_packages` is an existing pkgbase generation containing the four old
BSDAuth packages, used solely to verify removal in an inactive guest boot
environment. It is not a configured update repository. Both VM runners accept
`--qemu`, `--qemu-data`, `--cpus`, and `--timeout`. Keep build compilation and
acceptance VMs serialized to avoid contaminating timeout-sensitive tests with
compiler load. Preserve failures before retrying.

After integration passes, export only test additions with
`prepare-installed-fixtures.py --vm "$build/integration" --out "$build/fixtures"`.
Prepare private installation media with `prepare-installer.py`, supplying
`--source`, `--build`, `--root`, `--qualified-vm`, `--release-root`, and `--out`.
That tool checks production executable and documentation identities against
the qualified staging root. Private automation media contains disposable test
credentials and must never be published as a release image. Public media needs
its own unmodified boot tests.

The kernel PID 1 fixture also tests an activated, authority-bound isolation
read token. It verifies allowed retained-file I/O before revocation, then denied
reauthorization and denied retained-file I/O after software-authority revocation,
while the claim owner retains access. run-kernel.py requires the corresponding
pass marker. This is transient isolation regression coverage, not persistent BIP.

### Collector startup cleanup regression

Run `python3.12 -B tools/test/software-authority/qmp_cleanup_test.py` from the
source root. It extracts each runner's actual process-start/cleanup block,
substitutes Popen and fails collector startup, requiring termination/wait and
kill fallback. Image setup, installer commands and guest execution never run.
The five runners keep collector startup inside their cleanup scopes, so startup
exceptions cannot bypass child cleanup. This is native cleanup wiring coverage,
not a VM or installed-system qualification.

### Candidate-removal fixture identity checks

The BE rollback fixture records the candidate and original dataset GUIDs after
creation. Before destroying the candidate it requires both identities unchanged,
the original running root, an unmounted candidate, and bootfs selecting the
original. A successful `bectl -r <selected-root> list -H` must also contain
exactly one candidate record with neither an active/next-boot/one-time selection
nor a mountpoint. This prevents silently clearing a one-time selection during
deletion. Afterwards it checks candidate absence from a successful dataset list,
the survivor GUID/bootfs, and the original data. It does not automatically remove
a failed or replaced candidate. This is test admission in a disposable guest,
not atomic authenticated generation retirement or a hostile-root race defense.

Run `python3.12 -B tools/test/software-authority/be_retirement_test.py` from the
source root for native helper checks. These execute the actual shell admission
function with simulated ZFS and bectl query replies, including failed queries that print
plausible output. They perform no storage operations. Full rollback/removal
execution remains a guest gate and is currently on hold.

### Installed-suite scope

`run-installed.py` runs a software-authority fixture suite on a disposable
BSDInstall overlay. It verifies installed identities before adding test programs,
substituting the DTrace executable with an attributed fixture and installing
login profiles that launch the suite. Its SSH tests use real ssh/sshd over guest
loopback with explicit test configurations; the QEMU guest has no network
interface. These checks do not qualify external networking, an unmodified
production userland, verified boot or an immutable hardened generation. The
result records those exclusions explicitly. Separate packaged BIP startup,
networking, upgrade and recovery tests remain required.

### Kernel fixture input evidence

`run-kernel.py` records `staged-inputs.json` before image construction: SHA256
and size for every staged regular file, plus symlink targets without traversing
them. `METALOG` records the image metadata. The result includes hashes of both
records and the completed guest disk image before boot. Individual kernel,
helper and shell hashes also come from that staged record; rebuilding object-tree
inputs during the VM run cannot rewrite the reported binary identities. Snapshot mode preserves
that original disk image during the guest run.

Run `python3.12 -B tools/test/software-authority/input_evidence_test.py` for
native tests of content changes, symlink handling and special-file rejection.
These records identify observed fixture inputs; they do not prove a fresh build,
provide an atomic snapshot against hostile host writers, or qualify an installed
system. This is a test-runner change: build-bsd build inputs, signing policy and
publication targets are unchanged.

## Installed-disk evidence binding (2026-10-22)

The conventional installed-system qualification chain now records the completed
`installed.img` SHA-256 in `run-installer.py`, checks it before `boot-installed.py`
and `run-installed.py`, and records/checks the base disk again after overlay
runs. A result file alone no longer establishes that the tested disk is the one
created by the prior stage. Missing legacy bindings or changed content are
rejected; regenerate installation evidence rather than filling in an old result.
Hashing reads the complete logical image once before and once after an overlay
run. This is qualification overhead, not a production boot cost.

Native checks cover unchanged/modified content, missing/malformed digest inputs
and missing disks; all three tests passed. Runner syntax checks passed. No VM
was run. These checks assume an exclusive test workspace, do not serialize
hostile writers and do not authenticate an installed generation. The installed
suite still substitutes test programs/profiles and uses loopback networking;
it cannot qualify the complete unmodified hardened system or external SSH.

Build frontend review: these historical conventional installed-system runners
are not the production build-bsd hardened-generation workflow. No frontend
option or production policy changed. Their tighter evidence cannot be counted
as a completed normal-boot, Secure Boot or upgrade gate.

## Qualification memory budget

The kernel, software VM, seed, installer, installed-system and installed-boot runners
use 2048 MiB of guest RAM. Run one VM at a time. The native
`python3.12 -B memory_budget_test.py` check guards declared RAM arguments;
it does not qualify boot, disk usage, peak memory or performance. Historical
8192 MiB results do not meet this budget and need reruns.

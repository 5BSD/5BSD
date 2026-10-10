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

## Kernel fixture harness

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

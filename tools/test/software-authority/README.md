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

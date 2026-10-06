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

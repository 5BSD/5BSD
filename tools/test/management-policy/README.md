# Attribute management policy VM test

This builds and tests the opt-in SwitchBoard management policy in an isolated
QEMU guest. The host needs no root privileges. The guest has a test-only root
auto-login and QEMU networking is disabled. Do not deploy the image as a system.

The image is staged from the standard local pkgbase repository, with the
working `/usr/src` tree copied in (excluding Git data). The guest builds
SwitchBoard using every virtual CPU and keeps all objects under `/usr/obj`.
The host output directory contains image staging and evidence, not a published
installation repository. No host credentials, user homes, or live config are
copied into the image. Account and policy fixtures are generated from source.

```sh
python3 stage-vm.py --output /tmp/policy-vm
python3 run-vm.py /tmp/policy-vm/guest.img --log /tmp/policy-vm/serial.log
```

Use the installed Python command (for example `python3.12`). Both tools refuse
to overwrite existing run output. `--cpus` defaults to all host logical CPUs.
If QEMU needs a private shared-library directory, pass `--library-path DIR`.
The serial console is available on localhost port 14323 (`--serial-port` changes
it). The runner terminates only the QEMU process it created.

The guest uses UFS for the root filesystem to keep management authorization
independent of makefs-generated ZFS allocation behavior. The kernel and base
libraries come from the selected pkgbase generation; this test changes no
kernel ABI or external-driver identity checks.

On first login, `guest-build.sh` builds the daemon, policy tests, existing
management-class tests, and test helpers. After tests pass, it enables the
boot flag and reboots into the freshly built daemon. The second login runs
`guest-test.sh` through real BSDAuth sessions and capability control channels.

The integration checks cover ordinary UNIX file/process operations, two
principals sharing a UNIX group but receiving different attribute decisions,
a permitted SYSTEM service, denied targets/operations, CORE protection,
root's inability to bypass the enabled service policy, missing/malformed
policy, and revocation of the next operation on a retained control channel.
The test exports `/usr/obj` and guest logs to a separate artifact disk before
printing the success marker. The runner requires the UNIX compatibility and
completion markers and rejects panic, fatal-trap, and lock-reversal output.
A timeout or incomplete run fails; it is never treated as a pass.

The sibling `*.artifacts.raw` file is a tar stream on a zero-filled raw disk.
Inspect it with `tar -tf` or extract it into a new evidence directory. The serial
log records the installed manager's SHA-256. Host source changes are not
committed, installed, or pushed by these scripts.

## Login and session verification

The expanded integration suite starts a dedicated sshd bound only to the guest's
127.0.0.1:2222. QEMU still has no network device. Host keys, client keys, and
passwords are generated or set exclusively in the disposable guest. The client
pins the generated host key; it does not disable host-key verification.

The suite requires successful public-key SSH for both test users, password SSH,
a password-authenticated login(1) shell through a pseudo-terminal, and an SFTP
upload/download with the expected UNIX owner. Wrong SSH passwords must fail with
SSH's authentication failure status, rather than a timeout. Each successful
login exercises real capability lookups and SwitchBoard operations. UID 2001
receives the trace anointment and a scoped network-management rule; UID 2002
shares its UNIX group but receives neither grant. Both retain the public Notify
endpoint and ordinary shell/file/process operations.

Elevation authenticates with the user's own password, reaches the gated Notify
endpoint, preserves uid 2001, and leaves the parent session unable to reach that
endpoint. Wrong passwords and unapproved elevation names are refused. Test
passwords appear in the fixture scripts and are not suitable for deployed images.

Policy-file tests also cover an untrusted owner, group/world write permission,
a symlink, and a FIFO. These must deny requests promptly without freezing the
manager. A malformed or missing policy must never restore the legacy admin bypass.

This validates compatibility of the current management policy with existing
BSDAuth grants. It does not implement application-specific grants, protected
policy updates, or revocation of arbitrary provider descriptors. The guest uses
UFS and does not qualify desktop workloads or the previously recorded ZFS issue.

A final reboot disables the policy and exercises the same rebuilt manager's
legacy path: the root operator may manage SYSTEM services, the ordinary user
cannot, CORE remains protected, and SSH still supplies that user's endpoint
grants. Completion requires this third boot as well as the policy-enabled checks.

Additional regression coverage checks the policy file's exact size limit,
collection/attribute/equality limits, embedded NULs and invalid UID encodings,
forged runtime attributes, literal (non-wildcard) matching, and reload-only
permissions. Session tests also remove the inherited capability descriptor,
try a process-environment policy override, and attempt unprivileged policy writes.
Concurrent SSH sessions must preserve different grants for users sharing a group;
an unrelated SSH key must be refused with an authentication failure in the server
log. These tests extend Compatible mode coverage; they do not substitute for the
Protected mode and owner-recovery acceptance cases documented in the handbook.

# Principal policy VM qualification

Stage and run a disposable guest from the standard local pkgbase repository:

```sh
python3.12 stage-vm.py --output /tmp/principal-policy-vm
python3.12 run-vm.py /tmp/principal-policy-vm/guest.img --log /tmp/principal-policy-vm/serial.log
```

Pass `--library-path DIR` if QEMU needs private runtime dependencies. The guest
uses all available logical CPUs, /usr/src and /usr/obj. No installation
repository or build objects are relocated into the host home directory.
The guest has fixture accounts, no network device, and test-only automatic root
console login. Never deploy it. Guest SSH tests use loopback and pinned keys.

The first boot builds libcapbundle, BSDAuth, SwitchBoard, policyctl and tests.
The second boot verifies explicit endpoint grants separately from management:
UID 2001 can reach Trace but cannot manage SYSTEM services; UID 2002 can manage
SYSTEM services but cannot reach Trace. Both share a UNIX group. An explicit
root wildcard can manage SYSTEM services but cannot manage CORE.

Tests cover key/password SSH, interactive login, ordinary UNIX operations,
password-gated elevation, wrong passwords/keys, concurrent distinct grants,
and lack of ambient fallback when the session descriptor is removed.
The policy file is replaced and overwritten before fresh logins: the running
snapshot must remain unchanged. A third boot loads the replacement empty policy
and verifies that even root has no gated access or SYSTEM management authority.
Unit tests verify malformed input and snapshot format round trips. Gate tests
verify ADMIN alone cannot mint another user's session. policyctl is exercised
with valid, malformed and formatted policies.

The runner requires completion markers and rejects panic/fatal trap/lock-order
reversal output. Evidence is exported to the separate raw artifact disk.
This UFS guest does not qualify protected ZFS boot-environment publication,
owner recovery, raw-disk/boot bypass resistance, or desktop workloads.
The recorded host ZFS lock-order reversal remains unresolved.

## ZFS boot environments

Use `stage-vm.py --filesystem zfs --output /tmp/principal-policy-zfs` and run
`run-vm.py /tmp/principal-policy-zfs/guest.img --log /tmp/principal-policy-zfs/serial.log --require-zfs`.
The ZFS variant clones `default` to `policy-empty`, validates the empty policy
inside that candidate, and checks that Config and `/var` belong to its root
dataset. It temporarily activates the candidate and verifies that root loses
protected grants. The next reboot returns to `default` and restores its explicit
root grant. The original BE's policy must remain byte-for-byte unchanged.

The guest also generates full, management-only, and empty installer policies,
then uses the real `policyctl` parser to check their effective grants. This
qualifies BE policy separation and activation, not authorization of BE publishing
or rollback against hostile root. Those are distinct protection requirements.

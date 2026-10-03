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

The first boot builds libcapbundle, BSDAuth, BSDFilesystem, SwitchBoard, policyctl and tests.
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

After successful ZFS rollback and diagnostic export, the disposable guest runs
`verified-open-vm` as its final phase. It enrolls test-only fingerprints, enables
and locks veriexec, and calls the real filesystem grant implementation. It
checks a valid verified read, denial of root writes, atomic replacement, and
further enrollment, plus rejection of an unregistered inode published after
unlinking the old name under the default unlink policy. A normal UNIX read still
works. It also checks PID metadata queries, identity inheritance on fork, replacement
on exec, and preservation across UID changes. A registered but untrusted child
executable must lose its parent's integrity-control authority, and ordinary exec
must keep `issetugid()` clear. The helper then emits completion and waits for QEMU termination; it does
not attempt to launch unregistered programs under global enforcement.

This is a narrow enforcement test, not an enrolled production image or proof of
root confinement. Normal login/SSH and BE tests precede global enforcement.
The helper is not installed by the system build and must never be run on a live
machine. Its VM checks are safeguards, not an authorization mechanism.

## Testing a kernel fix against older local packages

When the local repository predates the veriexec executable-identity fix, supply
a matching GENERIC object tree:

```sh
python3.12 stage-vm.py --filesystem zfs --output /tmp/policy-kernel-vm \
    --kernel-objects /usr/obj/usr/src/amd64.amd64/sys/GENERIC
```

Staging requires the cached kernel to match the repository kernel byte for byte.
It copies the cache into the guest's standard `/usr/obj` tree and leaves the host
cache untouched. The first guest boot incrementally rebuilds the kernel using
all logical CPUs, verifies that its embedded GENERIC configuration is unchanged,
and installs it only inside the disposable guest. Subsequent boots exercise the
rebuilt kernel. The exported evidence includes that kernel binary.

The test-only console harness runs once per boot, preventing getty respawns
during shutdown from repeating BE activation or rollback steps.

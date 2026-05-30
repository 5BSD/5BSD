# OracleD Architecture TODO

## Phase 2: Service Launcher (remaining work)

Manifest parser, dependency graph, fork/exec path, and procdesc
monitoring are implemented.  Remaining steps:

1. Write default system service binaries (`/usr/libexec/oracled/`):
   sys-kldload, sys-reboot, sys-sysctl, sys-kenv, sys-swap, sys-acct
2. Route oraclectl kldload/reboot/etc. to system services instead
   of dispatching to commands.c
3. Remove CTL_OP_KLDLOAD, CTL_OP_KLDUNLOAD, CTL_OP_REBOOT from
   the control socket
4. Remove interim code from commands.c

## Richer oraclectl status

`oraclectl status` should report:

- Active resource claims (paths, network, system ops)
- Integrity flags in effect
- Loaded cap_rt modules
- Running services and their state (started, ready, failed)
- Reserved JIDs and their assignments
- Token counts per service

## Reserved Jail IDs

Need to determine:
- How to enforce reserved JID allocation (kernel support or
  convention?)
- Whether JID 1 is a real jail or a logical grouping of jid0
  services
- Policy for JID 2 (Linux compat? audit? TBD)

## Linux Compatibility Security Review

Areas to audit:

- Syscall translation layer — semantic gaps in Linux-to-FreeBSD
  syscall mapping
- ELF loader / branding — confusion between native and Linux
  binaries in security-sensitive paths
- linprocfs / linsysfs — information leaks across jail boundaries
- VDSO — info leaks, ASLR bypass potential
- Interaction with cap_rt — verify MACF hooks fire on
  Linux-emulated syscalls, not just native ones
- pty / devfs exposure inside emulation path
- Privilege boundaries — escalation via Linuxulator-specific
  interfaces inside jails

This review blocks production deployment with Linux jails.

## Cross-Jail Compatibility

Still need to design:
- Whether Linux jails get a shim library or use the pair
  channel directly
- Mapping between Linux syscall semantics and oracle operations
- Whether linprocfs/linsysfs mounts inside jails are managed
  by the oracle or by the jail's own init

## Remove CTL_OP_RELOAD

The reload command is a stub returning ENOTSUP.  Once the
service launcher is fully integrated, reload should:
- Re-read manifests from `/etc/oracled.d/`
- Diff against running services
- Start new, stop removed, restart changed
- Re-read `/etc/oracled.conf` for claim/integrity changes

## Deployment Profiles

Ship multiple config profiles (development, desktop, server,
appliance) in `/usr/share/oracled/`.  Prerequisites:

1. File access tracing — DTrace/cap_rt probes to record
   daemon file dependencies
2. Service capability manifests declaring needs
3. `oraclectl profile` command
4. Dry-run mode (`oracled -n`)

## bhyve VM Capability Gates

Add VMM gates to cap_rt_system:
- `SYS_GATE_VMM_CREATE`, `SYS_GATE_VMM_DESTROY`
- `SYS_GATE_VMM_MEM`, `SYS_GATE_VMM_MEMSEG`

## rctl Rule Manipulation

Add rctl gates to cap_rt_system:
- `SYS_GATE_RCTL_ADD`, `SYS_GATE_RCTL_REMOVE`

Prevents compromised root from removing its own resource limits.

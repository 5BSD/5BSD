# OracleD Architecture TODO

## Phase 2: Service Launcher

The oracle becomes a thin authority layer.  It claims resources,
reads manifests, fork/execs declared services, and passes
capability tokens.  System operations (kldload, reboot, sysctl,
etc.) move out of oracled into separate, replaceable programs.

### Default system services to ship

Each is a standalone binary in `/usr/libexec/oracled/` with a
matching manifest in `/etc/oracled.d/`:

| Service | Binary | Tokens | Operations |
|---------|--------|--------|------------|
| sys-kldload | sys-kldload | kldload, kldunload, kldstat | Load/unload kernel modules |
| sys-reboot | sys-reboot | reboot | Reboot, halt, poweroff |
| sys-sysctl | sys-sysctl | sysctl | Sysctl write operations |
| sys-kenv | sys-kenv | kenv | Kernel env get/set/unset |
| sys-swap | sys-swap | swapon, swapoff | Swap device management |
| sys-acct | sys-acct | acct | Process accounting control |

Developers replace any of these by dropping in their own
manifest with the same `provides` name.  The oracle does not
care what it starts — it passes tokens and monitors the process.

### Steps

1. Manifest parser (`manifest.c`) — read `/etc/oracled.d/*.ucl`
2. Dependency graph — DAG, topological sort, cycle rejection
3. Fork/exec path (`execute.c`) — fd close, env scrub, cred
   setup, token passing, pair channel, execve
4. Procdesc monitoring (`supervisor.c`) — EVFILT_PROCDESC,
   restart policies
5. Write default system service binaries
6. oraclectl routes kldload/reboot/etc. to system services
   instead of dispatching to commands.c
7. Remove CTL_OP_KLDLOAD, CTL_OP_KLDUNLOAD, CTL_OP_REBOOT
   from the control socket
8. Remove interim code from commands.c

### What stays in oracled's control socket

- CTL_OP_STATUS — daemon status (always needed, richer output)
- CTL_OP_SHUTDOWN — stop oracled itself (always needed)
- CTL_OP_RELOAD — reload config and restart changed services

## Richer oraclectl status

`oraclectl status` currently shows only running/uptime.  It
should report:

- Active resource claims (paths, network, system ops)
- Integrity flags in effect
- Loaded cap_rt modules
- Running services and their state (started, ready, failed)
- Reserved JIDs and their assignments
- Token counts per service

## Reserved Jail IDs

Reserve the first JIDs for oracle infrastructure:

- **JID 0** — host / oracle itself
- **JID 1** — system services (default sys-svc set)
- **JID 2** — reserved for future use
- **JID 3+** — user jails

Need to determine:
- How to enforce reserved JID allocation (kernel support or
  convention?)
- Whether JID 1 is a real jail or a logical grouping of jid0
  services
- Policy for JID 2 (Linux compat? audit? TBD)

## Linux Compatibility Security Review

The Linuxulator is always on in 5BSD.  Making it a baseline
system component means its attack surface is always exposed.
We need a thorough security review before shipping.

Areas to audit:

- **Syscall translation layer** — every Linux→FreeBSD syscall
  mapping is a potential semantic gap.  Mismatched error codes,
  flag handling, or side effects can be exploited.
- **ELF loader / branding** — unbranded ELF binaries fall back
  to ELFOSABI_LINUX.  Review whether this creates confusion
  between native and Linux binaries in security-sensitive paths.
- **linprocfs / linsysfs** — these expose kernel state under
  Linux conventions.  Audit what information leaks across jail
  boundaries and whether mount options are restrictive enough.
- **VDSO (virtual dynamic shared object)** — the linux64 module
  builds a VDSO mapped into every Linux process.  Review for
  info leaks and ensure it cannot be used to bypass ASLR.
- **Interaction with cap_rt** — verify that cap_rt MACF hooks
  fire correctly on Linux-emulated syscalls (open, bind, etc.),
  not just native ones.  A Linux process must not be able to
  bypass isolation claims by going through the Linuxulator path.
- **pty / devfs exposure** — the rc script loads the pty module
  and mounts devfs inside the emulation path.  Review device
  visibility and access control.
- **Privilege boundaries** — Linux jails run under the oracle's
  authority.  Verify that a compromised Linux process inside a
  jail cannot escalate via Linuxulator-specific interfaces.

This review blocks any production deployment with Linux jails.

## Cross-Jail Compatibility

The oracle's service abstraction solves FreeBSD/Linux jail
compatibility.  A Linux jail's "reboot" talks to the oracle,
which routes to the right implementation.

Linux compatibility (Linuxulator) is always on in 5BSD —
modules loaded at boot, rc.conf enabled by default.  This is
a baseline assumption the oracle depends on.

Still need to design:
- Whether Linux jails get a shim library or use the pair
  channel directly
- Mapping between Linux syscall semantics and oracle operations
- Whether linprocfs/linsysfs mounts inside jails are managed
  by the oracle or by the jail's own init

## Remove CTL_OP_RELOAD

The reload command is a stub returning ENOTSUP.  Once the
service launcher exists, reload should:
- Re-read manifests from `/etc/oracled.d/`
- Diff against running services
- Start new services, stop removed ones, restart changed ones
- Re-read `/etc/oracled.conf` for claim/integrity changes

## Deployment Profiles

Ship multiple config profiles for different use cases:
development, desktop, server, appliance.  Stored in
`/usr/share/oracled/` and selected at install or first boot.

Before we can ship aggressive profiles, we need:

1. **File access tracing** — use DTrace or cap_rt probes to
   record what files each daemon opens at runtime.  Build a
   database of daemon→file dependencies.
2. **Service capability manifests** — each daemon's manifest
   declares what it needs.  The profile generator verifies
   claims don't conflict with declared needs.
3. **oraclectl profile command** — `oraclectl profile server`
   installs config and validates against running services.
4. **Dry-run mode** — `oracled -n` loads config and reports
   what would be claimed without actually claiming.

Profiles:

- **development** — integrity only, no claims (current default)
- **desktop** — kernel memory, boot, credentials, kldload
- **server** — above + system binaries, logs, ports, sysctl
- **appliance** — everything locked, full integrity hardening

## bhyve VM Capability Gates

Add VMM gates to cap_rt_system:

- `SYS_GATE_VMM_CREATE` — VM creation
- `SYS_GATE_VMM_DESTROY` — VM destruction
- `SYS_GATE_VMM_MEM` — guest memory access
- `SYS_GATE_VMM_MEMSEG` — memory segment access

With these gates, only token holders can create VMs or access
guest memory.

## rctl Rule Manipulation

Add rctl gates to cap_rt_system:

- `SYS_GATE_RCTL_ADD` — add rule
- `SYS_GATE_RCTL_REMOVE` — remove rule

Prevents compromised root from removing its own resource limits.

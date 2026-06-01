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

## cap_rt Kernel Service Gaps

### Isolation service

- `FI_OP_QUERY_NET` (op 6) — reserved but not implemented.
  Needed so `oraclectl status` can verify network claims are
  actually held by the kernel, not just tracked in config.
  Path claims already use `FI_OP_QUERY` for verification.

- Batch claim/release — `cap_rt_reload_claims` does individual
  ioctls in a loop.  A `FI_OP_CLAIM_BATCH` would make reload
  atomic (all-or-nothing) instead of partially-applied on failure.

- Claim enumeration — no way to list all active claims from
  userspace.  A `FI_OP_LIST_CLAIMS` would let status show ground
  truth independent of config state.

### Token narrowing

Tokens currently grant full access to a claim.  No way to mint
a narrowed token (e.g., read-only path access, bind-only on a
port).  The isolation proto has flags fields reserved but unused.

### Instance enumeration

No way to query how many cap_rt instances a service holds or
which services hold instances of which cap_rt services.  Useful
for debugging leaked fds.

## Pair Channel Protocol (Phase 4 prerequisite)

The pair channel is created but `supervisor.c:379` says "not
currently read."  Agents need a defined request/reply protocol
over the pair for:

- Requesting additional capabilities at runtime
- Reporting health/readiness (currently no "ready" handshake)
- Requesting sub-service launches from the oracle

## Jail Service (Phase 3 prerequisite)

Coalitions can enlist jail descriptors, but there is no cap_rt
service for creating jails with capability-enforced parameters.
Currently `jail_set()` is a raw syscall.  A jail service would
let oracled create jails via cap_rt with the same token/authorize
pattern.

### Mount service scoping

The mount service exists but there is no mechanism for oracled
to delegate scoped mount rights (e.g., "this agent can mount
tmpfs inside its jail but not nullfs").  The current
mint/authorize is all-or-nothing.

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

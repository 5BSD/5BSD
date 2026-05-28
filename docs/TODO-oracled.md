# OracleD Architecture TODO

## Move system operations out of oracled

oracled currently implements kldload, kldunload, and reboot
directly in its control socket command handlers (commands.c).
These are system administration operations that do not belong
in the resource authority daemon.

### Current state (interim)

```
oraclectl kldload foo  →  oracled control socket  →  kldload(2)
oraclectl reboot       →  oracled control socket  →  reboot(2)
```

oracled holds the system gate claims AND performs the operations
itself.  This works but violates the architecture: oracled should
claim resources and delegate, not act.

### Target state

```
oraclectl kldload foo  →  system-agent  →  kldload(2)
oraclectl reboot       →  system-agent  →  reboot(2)
```

A **system-agent** (jid0, not jailed) holds cap_rt_system tokens
for kldload, kldunload, kldstat, reboot, swapon, swapoff, sysctl,
kenv, and acct.  oracled mints the tokens and passes them to the
agent at startup.  The agent provides its own control interface
(pair channel from oracled, or its own socket).

oraclectl routes commands to the appropriate agent instead of
to oracled directly.

### Steps

1. Create system-agent binary (`usr.libexec/oracled/system-agent`)
2. Agent receives system tokens via pair from oracled
3. Agent authorizes tokens after exec
4. Agent listens for commands on the pair
5. oraclectl learns to route kldload/reboot to system-agent
6. Remove CTL_OP_KLDLOAD, CTL_OP_KLDUNLOAD, CTL_OP_REBOOT
   from oracled's control socket
7. Remove kldload/reboot code from commands.c

### What stays in oracled's control socket

- CTL_OP_STATUS — daemon status (always needed)
- CTL_OP_SHUTDOWN — stop oracled itself (always needed)

### What moves to agents

- kldload / kldunload → system-agent
- reboot / halt / poweroff → system-agent
- kenv set/unset → system-agent
- sysctl write → system-agent (or a sysctl-agent)
- Future: mount operations → storage-agent
- Future: jail operations → container-agent

### Commands to add to oraclectl

When system-agent exists:

- `oraclectl halt` — reboot with RB_HALT
- `oraclectl poweroff` — reboot with RB_POWEROFF
- `oraclectl kenv set name=value`
- `oraclectl kenv unset name`
- `oraclectl sysctl name=value`

### Dependencies

- Phase 2: manifests + dependency graph (to start system-agent)
- Phase 3: capability passing (to give system-agent tokens)
- Phase 4 not required (system-agent runs in jid0)

## Remove CTL_OP_RELOAD

The reload command is a stub returning ENOTSUP.  Either implement
actual config reload or remove the opcode entirely.  If implemented,
reload should re-read /etc/oracled.conf and apply deltas (new claims,
changed integrity flags).

## Control socket is interim

The control socket (`/var/run/oracled.sock`) is interim infrastructure.
The long-term plan replaces it with cap_rt pair channels when oracled
manages agents.  The socket remains for oraclectl (admin tool) but
agents use pairs exclusively.

Document this in oracled.8 and remove the "interim" comments once
the pair-based architecture is implemented.

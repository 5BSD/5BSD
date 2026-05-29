# Oracled Architecture

## Overview

oracled is a **thin authority layer** — it claims system resources
via the cap_rt capability runtime and delegates them to services
by fork/exec'ing declared programs and passing capability tokens.
The oracle itself is small.  It does not implement system
operations; it starts programs that do.

oracled is built entirely on the cap_rt capability runtime.  It
does not use traditional Unix access control for its core
operations.  Every security-relevant action — resource claims,
process protection, inter-process communication, credential
management — flows through cap_rt kernel services:

- **Isolation service**: claims files, directories, and network
  endpoints.  Mints tokens for authorized access.
- **Capprotect service**: shields oracled from external
  interference (ptrace, signals, visibility).
- **Pair service**: creates authenticated IPC channels to agents
  with no filesystem presence.
- **Coalition service**: groups agents for lifecycle management,
  watchdog timers, and clean termination.
- **Node service**: sets credentials, resource limits, and
  process controls on children via procdesc.
- **Accounting service**: enforces per-agent resource rules.
- **Mount service**: sets up filesystems inside agent jails.
- **Identity service**: verifies process nonces.

The capability runtime provides MACF-enforced security that
root cannot bypass.  oracled uses it for its own protection
and as the mechanism for delegating authority to services.

### Design Principle: The Oracle Abstracts Authority

The oracle does not perform system operations — it authorizes
them.  Operations like kldload, reboot, sysctl, and mount are
performed by **separate programs** that the oracle starts and
grants capability tokens to.  The default 5BSD installation
ships a standard set of these services, but developers are free
to replace any of them with their own implementations.

This separation means:

1. **The oracle stays small** — its job is to read config, claim
   resources, fork/exec services, and pass tokens.
2. **Developers customize the system** by writing their own
   service programs, not by modifying the oracle.
3. **The same interface works across jail types** — a FreeBSD
   jail and a Linux jail both talk to the oracle for authority.
   The oracle starts the right service implementation for each
   context.  Same abstraction, different backends.

### Two-Level Architecture

oracled does not directly start end-user daemons like sshd or
nginx.  It starts **agents** — domain-specific service managers
that each handle their own domain.  Some agents run in jid0 for
core system work, others run in jails where they are PID 1.

```
┌──────────────────────────────────────────────────┐
│                    KERNEL                         │
│  cap_rt · MACF · isolation · capprotect · procdesc│
└─────────────────────┬────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │       oracled          │
          │  (thin authority)      │
          │                        │
          │ 1. Claims resources    │
          │ 2. Reads config        │
          │ 3. Fork/execs services │
          │ 4. Passes cap tokens   │
          └──┬──────┬──────┬──────┘
             │      │      │
        ─────┼──────┼──────┼───── jid0 ──────────
             │      │      │
    ┌────────┤  ┌───┴────┐ │
    │ syslogd│  │sys-svc │ │   sys-svc handles
    │  (jid0)│  │(jid0)  │ │   kldload, reboot,
    └────────┘  │kldload │ │   sysctl, etc.
                │reboot  │ │   (replaceable)
                │sysctl  │ │
                └────────┘ │
                           │
        cap_rt pairs       │
                           │
    ───────────────────────┼─── jail boundary ───
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────┴──┐  ┌─────┴───┐  ┌─────┴───┐
       │net-agent │  │app-agent│  │linux-jail│
       │(FreeBSD  │  │(FreeBSD │  │(Linux    │
       │ jail)    │  │ jail)   │  │ jail)    │
       │          │  │         │  │          │
       │ sshd     │  │ webapp  │  │ systemd  │
       │ nginx    │  │ podman  │  │ docker   │
       └──────────┘  └─────────┘  └──────────┘

Reserved JIDs:
  JID 0 — host / oracle
  JID 1 — system services (default sys-svc)
  JID 2 — reserved for future use
  JID 3+ — user jails
```

---

## Resource Authority

oracled claims system resources at boot via the cap_rt isolation
service.  Once claimed, MACF hooks deny access from all processes
except oracled's nonce or authorized token holders.  Even root
cannot bypass these claims.

```ucl
# /etc/oracled.conf — resource claims

claims {
    paths = [
        "/dev/mem",
        "/dev/kmem",
        "/dev/bpf",
        "/boot/kernel",
    ];
    network = [
        { port = 22;  protocol = "tcp"; direction = "bind"; },
        { port = 80;  protocol = "tcp"; direction = "bind"; },
        { port = 443; protocol = "tcp"; direction = "bind"; },
    ];
}
```

After boot, any process attempting to access these resources
receives `EACCES`.  Agents that need access declare it in their
manifest, and oracled mints isolation tokens.

---

## Two-Level Service Management

### Level 1 — oracled (system scope)

oracled manages:

- **System services** (jid0) — programs that implement system
  operations (kldload, reboot, sysctl, etc.).  These are the
  oracle's interface to the hardware.  The default set ships
  with 5BSD but developers can replace any of them.
- **Core jid0 services** (syslogd, devd, cron) — forked directly
- **Agents** (net-agent, app-agent) — forked into jails or jid0
- Dependency ordering between all of them
- Restart policies

oracled does NOT implement system operations itself.  It claims
the cap_rt gates, then delegates by starting the appropriate
service and passing it the capability tokens.

### Level 2 — agents (domain scope)

Each agent manages its own services:

- net-agent starts sshd, nginx, dhcpd using its own manifests
- app-agent launches containers or bundled applications
- Agent has its own restart logic and supervision
- Agent does NOT communicate with oracled about its children
- If the agent crashes, oracled restarts the entire agent

Cross-domain dependencies are expressed at the agent level:

```ucl
# net-agent depends on syslogd, not on syslogd's internal state
label = "net-agent";
requires = ["syslogd"];
```

### Cross-Jail Compatibility

Because system operations flow through the oracle's service
interface rather than direct syscalls, different jail types
can share the same abstraction.  A FreeBSD jail's "reboot"
and a Linux jail's "reboot" both request the operation from
the oracle — the oracle routes to the right service
implementation for that jail's context.

This cleanly solves compatibility between FreeBSD native jails
and Linux jails without each jail needing to know how the host
kernel implements the operation.

### Linux Compatibility is Always On

5BSD ships with the Linuxulator enabled by default.  The
`linux64` and `linux_common` kernel modules are loaded at
boot (`loader.conf`), and `linux_enable="YES"` is the default
in `rc.conf`.  This is a baseline system assumption, not an
optional feature.

The oracle's cross-jail abstraction depends on Linux
compatibility being present — Linux jails need the Linuxulator
ABI to run, and the oracle needs to be able to start services
inside them.  Making it always-on eliminates a class of
deployment failures where a Linux jail can't start because
someone forgot to enable the Linuxulator.

**Security note**: because the Linuxulator is always exposed,
its attack surface is always present.  A full security review
of the Linux compatibility layer is required before production
deployment with Linux jails — see TODO-oracled.md for the
audit checklist.  Of particular concern is verifying that
cap_rt MACF hooks fire correctly on Linux-emulated syscalls,
so that a Linux process cannot bypass isolation claims by
going through the Linuxulator path instead of native syscalls.

---

## Manifest Format

One format for jid0 services, system services, and agents.
The `jail` key and the `capabilities` section distinguish them.

### System service (replaceable)

System services implement the operations the oracle abstracts.
The default set ships with 5BSD.  A developer replaces one by
dropping a different manifest with the same `provides` name.

```ucl
# /etc/oracled.d/sys-kldload.ucl — default kernel module loader

label = "sys-kldload";
description = "Kernel module load/unload service";
program = "/usr/libexec/oracled/sys-kldload";

provides = ["kldload"];
requires = ["ORACLED"];

user = "root";

restart = "always";

capabilities {
    system = ["kldload", "kldunload", "kldstat"];
}
```

```ucl
# /etc/oracled.d/sys-reboot.ucl — default reboot service

label = "sys-reboot";
description = "System reboot/halt/poweroff service";
program = "/usr/libexec/oracled/sys-reboot";

provides = ["reboot"];
requires = ["ORACLED"];

user = "root";

restart = "always";

capabilities {
    system = ["reboot"];
}
```

A developer who needs custom reboot behavior (e.g., draining
connections before halt, or coordinating with a hypervisor)
replaces `sys-reboot.ucl` with their own manifest pointing
to their own binary.  The oracle does not care — it starts
whatever the config says and passes the tokens.

### jid0 system service

```ucl
# /etc/oracled.d/syslogd.ucl

label = "syslogd";
description = "System logger";
program = "/usr/sbin/syslogd";
arguments = ["-ss"];

provides = ["logging"];
requires = ["FILESYSTEMS"];

user = "root";

restart = "always";
restart_delay = 2;
```

### Jailed agent

```ucl
# /etc/oracled.d/net-agent.ucl

label = "net-agent";
description = "Network services agent";
program = "/usr/libexec/oracled/net-agent";

provides = ["networking"];
requires = ["syslogd", "devd"];

user = "root";
jail = true;

restart = "always";

capabilities {
    network = [
        { port = 22;  protocol = "tcp"; direction = "bind"; },
        { port = 80;  protocol = "tcp"; direction = "bind"; },
        { port = 443; protocol = "tcp"; direction = "bind"; },
    ];
    files = ["/dev/bpf"];
    mounts = [
        { fstype = "devfs"; path = "/dev"; },
        { fstype = "tmpfs"; path = "/var/run"; options = "size=16M"; },
    ];
}

integrity {
    ptrace = true;
    signal = true;
    visible = true;
}

environment {
    PATH = "/sbin:/bin:/usr/sbin:/usr/bin";
    LANG = "C.UTF-8";
}
```

### Third-party application

```ucl
# /etc/oracled.d/myapp.ucl

label = "myapp";
description = "Web application";
program = "/usr/local/bin/myapp";
arguments = ["--config", "/usr/local/etc/myapp.conf"];

requires = ["networking"];

user = "www";
group = "www";
jail = true;

restart = "on-failure";
restart_delay = 5;

capabilities {
    network = [
        { port = 8080; protocol = "tcp"; direction = "bind"; },
    ];
}
```

---

## Cap_rt Services Used

Every cap_rt kernel service plays a role in the architecture:

| Service | Used by | Purpose |
|---------|---------|---------|
| **isolation** | oracled | Claim files/dirs/ports at boot; mint tokens for agents |
| **capprotect** | oracled + agents | oracled shields itself; agents self-shield after exec |
| **coalition** | oracled | Group agent procdesc + jail descriptor; watchdog; clean termination |
| **node** | oracled | SET_CRED on child via procdesc; SET_RLIMIT; reaper ops |
| **accounting** | oracled | Per-agent rctl rules and resource limits |
| **mount** | oracled | Filesystem setup inside agent jails (devfs, tmpfs, nullfs) |
| **pair** | oracled ↔ agents | Authenticated bidirectional channel, no filesystem presence |
| **identity** | agents | Agent verifies its own nonce after exec |

---

## Agent Lifecycle

### Startup

The startup sequence has a critical split at exec.  The process
nonce rotates on exec, so any nonce-scoped operation (isolation
authorize, capprotect shield) MUST happen AFTER exec in the
agent binary, not before.

```
ORACLED SIDE (before fork):

1.  Read /etc/oracled.d/net-agent.ucl
2.  Resolve dependencies — wait for syslogd, devd
3.  If jail = true:
      a. jail_set() — create jail "oracled-{label}"
      b. Mount filesystems from capabilities.mounts
         via cap_rt mount service
      c. Set jail parameters (hostname, allow.*)
4.  Create cap_rt pair → fd_a (oracled), fd_b (agent)
5.  Mint isolation tokens for each capability:
      - FI_OP_MINT for file capabilities
      - FI_OP_MINT_NET for network capabilities
6.  Connect to capprotect service → get shield_fd
    (for agent to self-shield after exec)
7.  Create coalition, set watchdog timeout
8.  pdfork() the agent → get procdesc fd
9.  Enlist agent procdesc + jail in coalition
10. Use cap_rt node (SET_CRED via procdesc) to set uid/gid
11. Use cap_rt accounting to set rctl rules via procdesc

IN THE CHILD (before exec):

12. Close ALL fds except:
      - fd_b (pair channel)
      - token fds (isolation tokens)
      - shield_fd (capprotect, for self-shielding)
      - stdin/stdout/stderr
    Use closefrom() after the highest kept fd.
13. Scrub environment completely (see below)
14. If jail: jail_attach() — enter the jail
15. execve() the agent binary

AGENT BINARY (after exec — new nonce):

16. Read ORACLED_PAIR_FD, ORACLED_TOKEN_FDS, ORACLED_SHIELD_FD
    from environment
17. Call FI_OP_AUTHORIZE on each token fd
    (authorizes the agent's NEW post-exec nonce)
18. Call CP_OP_SHIELD on shield_fd with manifest flags
    (shields the agent's NEW nonce)
19. Close shield_fd (shield persists via refcount)
20. Send "ready" message on pair fd
21. Begin managing domain services

ORACLED SIDE (after fork):

22. Monitor via EVFILT_PROCDESC:
      - NOTE_EXEC → log, expect "ready" on pair
      - NOTE_EXIT → check restart policy
23. Set coalition watchdog — agent must heartbeat
```

### Environment Scrubbing

Children MUST NOT inherit oracled's environment.  oracled holds
cap_rt fds, isolation fds, and capprotect fds.  The child must
not have access to any of these.

Before exec (step 13):

1. **Close all fds** except the explicitly passed ones.
   Use `closefrom(highest_kept_fd + 1)`.

2. **Clear the environment** entirely.  Set only:
   - Variables from the manifest `environment {}` section
   - `PATH` (from manifest or default `/sbin:/bin:/usr/sbin:/usr/bin`)
   - `HOME` (from passwd entry for the configured user)
   - `USER` / `SHELL` (from passwd entry)
   - `ORACLED_PAIR_FD` — the pair channel fd number
   - `ORACLED_TOKEN_FDS` — comma-separated token fd numbers
   - `ORACLED_SHIELD_FD` — capprotect fd for self-shielding

3. **No `ORACLED_CTL_SOCK`** — agents do not know about the
   control socket.  They communicate only via the pair.

4. **No cap_rt device access** — /dev/cap_rt is claimed by
   oracled.  Agents cannot open it directly.

### Jail Lifecycle

Jails are ephemeral — they exist only while the agent runs.
All resources created for a jail are tracked and cleaned up.

**Creation (before fork, step 3)**:

```
jail_set():
  - name = "oracled-{label}"
  - path = "/var/jails/{label}"
  - host.hostname = "{label}.oracled"
  - persist = true
  - allow.raw_sockets (if manifest has network capabilities)

mount via cap_rt mount service:
  - devfs → /dev (restricted ruleset)
  - tmpfs → /var/run
  - nullfs → /usr (read-only)

enlist jail descriptor in coalition (step 9)
```

**Destruction (on agent exit)**:

```
1. Agent exits → NOTE_EXIT on procdesc
2. oracled reaps the agent
3. Coalition watchdog fires if agent missed heartbeat
4. Coalition terminates remaining members:
     - SIGTERM to processes, then SIGKILL after grace period
     - jail_remove() for enlisted jail descriptors
5. oracled unmounts all filesystems in reverse order
6. oracled removes /var/jails/{label}
7. If restart policy says restart:
     - Re-create jail from scratch (clean slate)
     - Re-fork agent with fresh tokens
```

**Why clean slate on restart**: Re-using the jail risks state
leakage from the previous run.  A crashed agent may have left
corrupt files, stale sockets, or compromised state.  Fresh
jail + fresh tokens = known-good starting point.

### Crash Recovery

If oracled crashes:

- All cap_rt fds close automatically (kernel fd cleanup)
- Isolation claims release → resources unprotected (window)
- Capprotect shields drop → agents unshielded (window)
- Pair fds close → agents see ECONNRESET
- Coalition fds close → coalition terminate fires:
  agents and jails are killed/removed by the kernel
- On restart, oracled:
  1. Scans for orphaned jails matching `oracled-*`
  2. Kills processes and removes any found
  3. Re-claims resources
  4. Re-reads manifests, re-forks agents

The coalition watchdog is the key cleanup mechanism.  When
oracled's coalition fd closes, the coalition terminates all
members — including jail descriptors.  This means orphaned
jails are cleaned up by the kernel, not by oracled's restart
logic.  The `oracled-*` scan is a safety net for edge cases.

---

## Communication: Pairs Not Sockets

Agents do NOT use the control socket.  The control socket
is for `oraclectl(8)` (admin tool) only.

Agent-to-oracled communication uses cap_rt pairs:

```
oracled keeps fd_a                agent has fd_b
        │                                │
        ├──→ "tokens on fds 5,6,7" ──→   │
        │                                │
        │   ←── "status: ready" ←────────┤
        │                                │
        │   ←── "heartbeat" ←────────────┤
        │                                │
        ├──→ "shutdown" ──────────────→   │
        │                                │
        │   ←── "shutdown: ack" ←────────┤
```

The pair carries cap_rt messages with kernel-stamped credential
trailers (uid, gid, nonce).  No filesystem socket exists for the
pair — there is no path to attack.

---

## Dependency Resolution

Inspired by rc(8) `PROVIDE`/`REQUIRE` and systemd `After=`/`Requires=`.

- `provides` — symbolic names this job provides
- `requires` — symbolic names that must be running first

oracled builds a DAG at boot and starts in topological order:

```
FILESYSTEMS (implicit)
    └── syslogd (provides: logging)
        ├── devd (provides: devices)
        │   └── net-agent (provides: networking)
        │       └── myapp
        └── cron
```

Circular dependencies are rejected at config load time.
Missing dependencies log a warning and are treated as
satisfied (degraded boot, not a hard failure).

---

## Best Practices from launchd and systemd

### From launchd

1. **Declarative manifests** — services describe what they are,
   not how to start them.  No shell scripts.  The supervisor
   handles fork/exec/restart.

2. **Bootstrap hierarchy** — our two-level model mirrors
   launchd's bootstrap subsystems.  Each agent is a bootstrap
   domain.  Services within an agent register with their
   agent, not with the system.

3. **Keep the daemon small** — launchd's core is one file
   (`core.c`).  The complexity is in the job struct and its
   state machine.  oracled follows this: `job.c` is the heart,
   everything else is plumbing.

4. **Socket activation** — launchd opens sockets before the
   service starts and passes them via bootstrap check-in.
   oracled's equivalent: mint an isolation token for the port,
   pass it pre-exec, agent authorizes and binds.

### From systemd

5. **Dependency graph with topological sort** — systemd's job
   engine resolves dependencies into a transaction, detects
   cycles, and commits atomically.  oracled adopts the DAG
   model but with simpler provides/requires semantics.

6. **Per-service sandboxing** — systemd's `ProtectSystem=`,
   `PrivateTmp=`, `NoNewPrivileges=` are declarative sandbox
   directives.  oracled's `integrity {}` and `capabilities {}`
   sections serve the same role but use MACF instead of
   namespaces.

7. **Clean execution environment** — systemd's `exec-invoke.c`
   methodically sets up the child environment: close fds,
   set credentials, apply sandbox, then exec.  oracled must
   do the same.  The child inherits ONLY what the manifest
   declares.

8. **Separate executor** — systemd uses a dedicated
   `systemd-executor` binary for the sandbox setup path.
   This keeps privileged code out of the main daemon.
   oracled could adopt this pattern later but starts with
   in-process fork/exec.

9. **State serialization** — systemd can re-exec itself
   without losing service state.  Not needed for Phase 1
   but important for live upgrades.

10. **Readiness protocol** — systemd's `sd_notify()` lets
    services signal when they're ready to serve.  oracled's
    pair channel serves this role: the agent sends a "ready"
    message after authorization.

### Unique to oracled

11. **MACF-enforced resource claims** — neither launchd nor
    systemd can deny root access to system resources.
    oracled's isolation claims are kernel-enforced.

12. **Capability tokens** — authority flows through file
    descriptors.  Pass a token, gain access.  Close it,
    lose access.  No ambient authority.

13. **Nonce-based identity** — programs are identified by
    cryptographic nonce (rotates on exec), not by PID or UID.
    Same-nonce processes (fork family) share authority.

14. **Pair channels** — kernel-authenticated IPC with no
    filesystem presence.  No socket to discover, no path
    to race.

---

## Observability

oracled is instrumented with DTrace USDT probes and ships with
ready-to-use DTrace scripts.  The probes are zero-cost when
DTrace is not attached.

### USDT Probes (provider: oracled)

| Probe | Args | Fires when |
|-------|------|------------|
| `startup` | — | daemon initialization complete |
| `shutdown` | reason | daemon shutting down (signal or socket) |
| `config-load` | path | config file parsed |
| `claim-path` | path | file/directory claimed successfully |
| `claim-path-fail` | path | file/directory claim failed |
| `claim-net` | port, proto | network endpoint claimed |
| `claim-net-fail` | port, proto | network endpoint claim failed |
| `integrity` | flags | capprotect integrity activated |
| `ctl-accept` | uid | control socket connection accepted |
| `ctl-cmd` | op, uid | control command dispatched |
| `ctl-deny` | op, uid | control command denied (EPERM) |
| `error` | subsys, msg | notable error |

### DTrace Scripts

| Script | Purpose |
|--------|---------|
| `oracled-lifecycle` | Trace complete startup/shutdown sequence |
| `oracled-claims` | Monitor resource claims with success/failure counts |
| `oracled-control` | Trace control socket commands with UID and timing |

The kernel cap_rt framework also provides DTrace probes
(`cap_rt:::call`, `cap_rt:::send`, `cap_rt:::recv`, etc.)
for tracing the underlying capability operations.

---

## Project Layout

```
lib/liboraclectl/              — client library for control socket
lib/libagent/                  — agent framework library (planned)

usr.sbin/oracled/
    # Core lifecycle (implemented)
    oracled.c                      main, phased lifecycle
    oracled.h                      daemon state
    config.c / config.h            UCL config + resource claims
    event.c                        kqueue event loop
    proc.c                         reaper, subtree

    # Capability runtime (implemented)
    cap_rt.c                       device, isolation claims, shield

    # Control interface — admin only (implemented)
    control.c                      socket server
    commands.c / commands.h        command handlers (interim)
    oracled_ctl.h                  wire protocol

    # Service manager (planned)
    manifest.c / manifest.h        UCL manifest parser
    job.c / job.h                  job struct, state machine
    execute.c / execute.h          fork/exec, env scrub, cred setup
    supervisor.c / supervisor.h    procdesc monitoring, restart
    sandbox.c / sandbox.h          per-job capprotect/isolation/jail

    oracled.conf                   daemon config
    oracled.8                      man page
    tests/

usr.sbin/oraclectl/            — admin CLI tool (implemented)

usr.libexec/oracled/           — system services + agents
    # Default system services (replaceable)
    sys-kldload                    kernel module load/unload
    sys-reboot                     reboot/halt/poweroff
    sys-sysctl                     sysctl write operations
    sys-kenv                       kernel environment get/set
    sys-swap                       swapon/swapoff
    sys-acct                       process accounting control

    # Domain agents (planned)
    net-agent                      network services agent
    storage-agent                  storage services agent
```

---

## Implementation Phases

### Phase 1: Resource Claims (done)

Config-driven claims for files, directories, and network
endpoints at boot.  Foundation for all capability granting.

### Phase 2: Service Launcher

The core of the new architecture.  oracled reads service
manifests from `/etc/oracled.d/*.ucl`, builds a dependency
graph, and fork/execs declared programs in dependency order.

This phase delivers:

- **Manifest parser** — UCL format, one file per service
- **Dependency graph** — DAG with topological sort, cycle
  detection, degraded boot on missing deps
- **Fork/exec path** — close fds, scrub environment, set
  credentials, pass capability tokens + pair, exec
- **Procdesc monitoring** — EVFILT_PROCDESC for exec/exit,
  restart policies
- **Default system services** — `sys-kldload`, `sys-reboot`,
  `sys-sysctl`, etc. in `/usr/libexec/oracled/`

Once this lands, the interim control socket commands (kldload,
reboot in commands.c) are removed.  oraclectl routes those
commands to the appropriate system service instead.

### Phase 3: Jail Agents

Create and destroy jails per manifest.  Agent becomes PID 1
in its jail.  Mount filesystems.  Clean up on exit.

Reserved JIDs:

- **JID 0** — host / oracle
- **JID 1** — system services jail (default sys-svc set)
- **JID 2** — reserved
- **JID 3+** — user jails

Cross-jail compatibility: FreeBSD and Linux jails both
request system operations through the oracle.  The oracle
routes to the right service implementation per jail context.

### Phase 4: Agent Framework

Library (`libagent`) for writing agents and system services.
Common pattern for receiving the pair, authorizing tokens,
loading sub-manifests, supervising children.

### Phase 5: Standard Agents

Ship net-agent, storage-agent, container-agent with the base
system.

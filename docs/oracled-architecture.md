# Oracled Architecture

## Overview

oracled is a **system authority** — the kernel's policy engine
extended into userspace.  It owns system resources and delegates
them to agents via capability tokens.

It is NOT a traditional service manager.  It does not directly
start sshd or nginx.  It starts **agents** — domain-specific
service managers that each handle their own domain.  Some agents
run in jid0 for core system work, others run in jails where they
are PID 1.

```
┌──────────────────────────────────────────────────┐
│                    KERNEL                         │
│  cap_rt · MACF · isolation · capprotect · procdesc│
└─────────────────────┬────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │       oracled          │
          │                        │
          │ 1. Claims resources    │
          │ 2. Manages agents +    │
          │    jid0 system services│
          │ 3. Dependency ordering │
          │ 4. Passes capabilities │
          │    via cap_rt pairs    │
          └──┬──────┬──────┬──────┘
             │      │      │
        ─────┼──────┼──────┼───── jid0 ──────────
             │      │      │
    ┌────────┤      │      │
    │ syslogd │  devd│     │
    │  (jid0) │(jid0)│     │
    └─────────┘      │     │
                     │     │
        cap_rt pairs │     │
                     │     │
    ─────────────────┼─────┼─── jail boundary ───
                     │     │
              ┌──────┴──┐ ┌┴────────┐
              │net-agent │ │app-agent│
              │(jail,    │ │(jail,   │
              │ PID 1)   │ │ PID 1)  │
              │          │ │         │
              │ sshd     │ │ webapp  │
              │ nginx    │ │ podman  │
              │ dhcpd    │ │ ctr     │
              └──────────┘ └─────────┘
```

---

## Resource Authority

oracled claims system resources at boot via the cap_rt isolation
service.  Once claimed, MACF hooks deny access from all processes
except oracled's nonce or authorized token holders.  Even root
cannot bypass these claims.

```ucl
# /etc/oracled.conf — resource claims

isolation {
    cap_rt = true;

    files = [
        "/dev/mem",
        "/dev/kmem",
        "/dev/bpf",
    ];

    directories = [
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

- Core jid0 services (syslogd, devd, cron) — forked directly
- Agents (net-agent, app-agent) — forked into jails or jid0
- Dependency ordering between all of them
- Restart policies

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

---

## Manifest Format

One format for jid0 services and agents.  The `jail` key and
the `capabilities` section distinguish them.

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

shield {
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

## Agent Lifecycle

### Startup

```
1.  oracled reads /etc/oracled.d/net-agent.ucl
2.  Resolves dependencies — waits for syslogd, devd
3.  If jail = true:
      a. jail_create() — creates a new jail
      b. Mount filesystems from capabilities.mounts
      c. Set jail parameters (hostname, IP, allow.*)
4.  Create cap_rt pair → fd_a (oracled), fd_b (agent)
5.  Mint isolation tokens for each capability request:
      - FI_OP_MINT for file capabilities
      - FI_OP_MINT_NET for network capabilities
6.  pdfork() the agent
7.  In the child (before exec):
      a. Close ALL fds except:
         - fd_b (pair channel to oracled)
         - token fds (capability tokens)
         - stdin/stdout/stderr (if configured)
      b. Scrub environment — set only manifest-declared vars
      c. Set credentials (uid, gid, groups)
      d. If jail: jail_attach() — enter the jail
      e. Apply capprotect shield from manifest
      f. Authorize isolation tokens (FI_OP_AUTHORIZE each)
      g. execve() the agent binary
8.  oracled monitors via EVFILT_PROCDESC:
      - NOTE_EXEC → log, mark job running
      - NOTE_EXIT → check restart policy
```

### Environment Scrubbing

Children MUST NOT inherit oracled's environment.  oracled holds
cap_rt fds, isolation fds, and capprotect fds.  The child must
not have access to any of these.

Before exec:

1. **Close all fds** except the explicitly passed ones (pair fd,
   token fds, stdio).  Use `closefrom()` after the highest
   intended fd.

2. **Clear the environment** entirely.  Set only:
   - Variables from the manifest `environment` section
   - `PATH` (from manifest or default `/sbin:/bin:/usr/sbin:/usr/bin`)
   - `HOME` (from passwd entry for the configured user)
   - `USER` (from manifest user)
   - `SHELL` (from passwd entry)
   - `ORACLED_PAIR_FD` — the pair channel fd number
   - `ORACLED_TOKEN_FDS` — comma-separated list of token fd numbers

3. **No `ORACLED_CTL_SOCK`** — agents do not know about the
   control socket.  They communicate only via the pair.

4. **No cap_rt device access** — /dev/cap_rt is claimed by
   oracled.  Agents cannot open it.  They use only the fds
   they were given.

### Jail Lifecycle

When `jail = true`:

**Creation (before fork)**:
```
jail_set():
  - name = "oracled-{label}"  (e.g., "oracled-net-agent")
  - path = "/var/jails/{label}" or tmpfs root
  - host.hostname = "{label}.oracled"
  - persist = true (jail outlives creating process briefly)
  - allow.raw_sockets (if manifest requests network)
  - ip4/ip6 from manifest (if specified)

mount filesystems from capabilities.mounts:
  - devfs → /dev (with restricted ruleset)
  - tmpfs → /var/run
  - nullfs → /usr (read-only host filesystem)
```

**Destruction (on agent exit)**:
```
1. Agent exits → NOTE_EXIT on procdesc
2. oracled reaps the agent process
3. If restart policy says stop:
   a. Kill any remaining processes in the jail
      (jail has its own reaper — agent was PID 1)
   b. Unmount all filesystems in reverse order
   c. jail_remove() the jail
   d. Clean up /var/jails/{label}
4. If restart policy says restart:
   a. Kill remaining processes
   b. Leave jail and mounts intact
   c. Re-fork agent into the same jail
```

Jails are ephemeral — they exist only while the agent runs
(or across restarts).  On `oraclectl shutdown`, all jails are
destroyed in reverse dependency order.

### Crash Recovery

If oracled itself crashes:

- All cap_rt fds close → isolation claims release, shields drop
- Pair fds close → agents see ECONNRESET on their pair
- Jails persist (they are kernel objects)
- On restart, oracled re-claims resources, re-creates pairs
- Agents that are still running in jails can be re-adopted
  (or killed and restarted)

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
   directives.  oracled's `shield {}` and `capabilities {}`
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

## Project Layout

```
lib/liboraclectl/              — client library for control socket
lib/libagent/                  — agent framework library (Phase 5)

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
    commands.c / commands.h        command handlers
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

usr.libexec/oracled/           — standard agent binaries (Phase 6)
    net-agent                      network services agent
    storage-agent                  storage services agent
```

---

## Implementation Phases

### Phase 1: Resource Claims

Extend config to claim files, directories, and network endpoints
at boot.  Foundation for all capability granting.

### Phase 2: Manifests + Dependency Graph

Parse `/etc/oracled.d/*.ucl`.  Build dependency graph.  Start
jid0 services in dependency order with procdesc monitoring.

### Phase 3: Capability Passing + Environment Scrub

Mint isolation tokens per manifest capabilities section.
Clean fork path: close fds, scrub environment, set credentials,
pass tokens + pair, exec.

### Phase 4: Jail Agents

Create and destroy jails per manifest.  Agent becomes PID 1 in
its jail.  Mount filesystems.  Clean up on exit.

### Phase 5: Agent Framework

Library (`libagent`) for writing agents.  Common pattern for
receiving the pair, authorizing tokens, loading sub-manifests,
supervising children.

### Phase 6: Standard Agents

Ship net-agent, storage-agent, container-agent with the base
system.

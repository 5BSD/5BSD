# Service Naming and IPC Registry

## Status: Design — not yet implemented

This document describes the naming and IPC layer that sits on
top of cap_rt pairs.  It provides stable service names for
inter-process communication, service discovery, and capability
exchange.

This work depends on the oracled agent architecture (Phase 2+)
and should be designed alongside it.  The naming service is
what makes agents, system services, and third-party software
able to find and talk to each other.

---

## Problem

cap_rt pairs provide authenticated bidirectional channels, but
there is no way for processes to discover each other.  If sshd
wants to talk to a PAM module, or nginx wants to talk to a
logging daemon, someone must manually arrange the pair fd
passing.  There is no directory, no lookup, no stable name.

Classic Unix solutions (filesystem sockets, D-Bus bus names,
Mach bootstrap ports) all have the same shape: a registry
that maps names to connections.

---

## Naming Convention

Service names follow reverse-DNS convention, scoped by origin:

```
# System services (shipped with 5BSD)
org.freebsd.syslogd
org.freebsd.devd
org.freebsd.sshd
org.freebsd.sshd.auth

# Oracle subsystems
org.5bsd.oracled
org.5bsd.oracled.system
org.5bsd.oracled.network

# Third-party software
com.example.myapp
com.example.myapp.api
com.example.myapp.metrics

# User-scoped services (per-agent)
user.koryheard.editor
```

Hierarchical names allow wildcard lookup and scoped
authorization:

- `org.freebsd.*` — all system services
- `com.example.myapp.*` — all endpoints of myapp

---

## How It Works

### Registration

A service declares names in its manifest:

```ucl
# /etc/oracled.d/syslogd.ucl
label = "syslogd";
program = "/usr/sbin/syslogd";

services {
    register = [
        "org.freebsd.syslogd",
        "org.freebsd.syslogd.log",
    ];
}
```

When syslogd starts, the naming registry records that
`org.freebsd.syslogd` is provided by this process.
The registry holds a pair endpoint connected to syslogd.

### Lookup

A client looks up a service by name:

```c
int fd = oracle_lookup("org.freebsd.syslogd.log");
// fd is a cap_rt pair channel connected to syslogd
// kernel-stamped credentials on every message
```

The registry:
1. Finds the registered provider for the name
2. Creates a new cap_rt pair
3. Hands one end to the provider (via its existing pair)
4. Returns the other end to the client

The client and provider now have a direct authenticated
channel.  The registry is not in the data path — it's
lookup only.

### Authorization

Not every process can look up every name.  The manifest
declares what names a service is allowed to connect to:

```ucl
# nginx can talk to syslogd and its own backend
services {
    register = ["com.example.nginx.status"];
    lookup = [
        "org.freebsd.syslogd.log",
        "com.example.backend.api",
    ];
}
```

The registry checks the caller's manifest (or token)
against the requested name.  Unauthorized lookups are
denied.

---

## Registry Location

Two options:

**A. In oracled itself:**

oracled holds the registry as part of agent management.
When oracled forks an agent, it knows what names the agent
registers.  Lookup requests come through the control socket
or pair channels.

Pro: Simple, centralized, oracled already has the manifests.
Con: Adds complexity to oracled, single point of failure.

**B. Dedicated naming agent:**

A separate `naming-agent` holds the registry.  oracled
gives it a token to create pairs on behalf of other agents.
Lookup requests go through the naming agent's pair channel.

Pro: Separation of concerns, can crash without taking
down the Oracle.
Con: Extra hop for lookups, needs its own pair from oracled.

The launchd model uses option A (bootstrap server is built
into launchd).  D-Bus uses option B (dbus-daemon is
separate from init).

Recommendation: start with A (in oracled), extract to B
if it gets too complex.

---

## Lifecycle

### Provider crashes

When a provider crashes, its pair fds close.  Clients
see ECONNRESET.  The registry marks the name as unavailable.
When oracled restarts the provider (restart policy), the
provider re-registers.  Pending lookups can either fail
or queue.

### On-demand activation

Like launchd, a lookup for a name that isn't running could
trigger the provider to start:

```ucl
# syslogd starts on-demand when someone looks up its name
activation = "on-demand";
services {
    register = ["org.freebsd.syslogd.log"];
}
```

The registry sees a lookup for an unregistered name, checks
if any manifest declares it, and starts the provider.  The
client blocks until the provider registers.

This is socket activation generalized to any service name,
not just network ports.

### Scope

Names are global by default.  Agent-scoped names are visible
only within the agent's jail:

```ucl
services {
    register = [
        "com.example.myapp.internal",  # jail-scoped
    ];
    scope = "jail";  # or "system" (default)
}
```

---

## Transport

The naming service uses cap_rt pairs as transport.  Each
connection is a pair — no filesystem sockets, no abstract
namespace, no port numbers.  The pair provides:

- Kernel-stamped credentials (uid, gid, nonce) on every message
- File descriptor passing (for capability delegation)
- Bidirectional async messaging
- Automatic cleanup on process exit

The naming service adds:
- Stable names (reverse-DNS)
- Discovery (lookup by name)
- Authorization (manifest-declared access)
- Lifecycle (activation, crash handling)

---

## API

### Library (future libcap_rt or liboracle)

```c
/* Look up a service by name.  Returns a pair fd. */
int oracle_lookup(const char *name);

/* Register a service name.  Returns 0 or errno. */
int oracle_register(const char *name);

/* Unregister a service name. */
int oracle_unregister(const char *name);

/* Wait for a name to become available. */
int oracle_wait(const char *name, int timeout_ms);
```

### Wire protocol

The lookup/register operations would be a new cap_rt service
(`cap_rt_naming`) or built into oracled's pair protocol.

---

## Relation to Other Components

```
                 oracled
                    │
            ┌───────┼────────┐
            │       │        │
         naming   agents   claims
         registry
            │
    ┌───────┼────────┐
    │       │        │
  syslogd  sshd   myapp
    │                │
  "org.freebsd     "com.example
   .syslogd"        .myapp"
```

The naming registry is orthogonal to claims and agents.
Claims control WHO can access resources.  The registry
controls HOW processes find each other.

---

## Open Questions

1. Should the registry be persistent across oracled restarts?
   Or rebuilt from manifests on every boot?

2. Should lookup be synchronous (block until provider starts)
   or async (return ENOENT, try again later)?

3. Should names support versioning?  e.g.,
   `org.freebsd.syslogd@2` for protocol version 2.

4. How do agents register names for their children?
   Does the agent register on behalf of sshd, or does sshd
   register itself after exec?

5. Should there be a `oraclectl lookup <name>` command
   for debugging?

6. How does this interact with Capsicum?  A process in
   capability mode can't do lookups (no filesystem, no
   new connections).  The lookup fd must be pre-opened.

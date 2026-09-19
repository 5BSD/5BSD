# BSDTime: the clock broker

`BSDTime` exposes `system.Time` and lets a capability-mode component read the
clock and — policy permitting — set or slew it, without holding the ambient
privilege to call `clock_settime(2)`/`adjtime(2)` for itself. A client holds a
`system.Time` channel; the broker performs the syscall on its behalf after a
per-label policy check.

Like `BSDSysctl`, `BSDTime` is an **ambient-authority provider**: its per-client
workers do *not* enter capability mode, because setting the wall clock is a
privileged operation the Capsicum sandbox strips. It runs outside the sandbox as
the trusted concentration point for time changes, and its security boundary is
the per-label policy, not a sandbox (see [Writing a Service
Provider](../development/writing-components.md) for the ambient-provider
pattern). Each accepted client is still served on its own `pdfork(2)`'d worker
that drops inherited authority; the policy is loaded once before the fork.

## The verbs

A small request/reply exchange over the channel:

- **get** — read the current time (`clock_gettime(2)`). Unprivileged: allowed to
  every holder.
- **set** — set the wall clock (`clock_settime(2)`) to an absolute time.
  Default-deny: refused with `EPERM` unless the caller's label is granted.
- **adjust** — slew the clock (`adjtime(2)`) by a signed delta, the gentle
  correction an NTP-style client makes. Same per-label gate as `set`.

## Policy

Access is scoped per label by `time.conf` in the provider's bundle `Config/`
directory, delivered as a directory descriptor rather than opened by a global
path. The `default` block applies to any label without its own `clients` entry;
a label may set or slew the clock only if granted `set = true`. Reading is
always allowed. A missing or malformed file fails soft to the compiled-in
default — read-only, no setter — rather than opening time changes or taking the
provider down. An unexpected clock jump is a real hazard (it breaks TLS,
Kerberos, and log ordering), so grant `set` only to a trusted time manager.

## Client API

Components link `libtimecmp(3)`: `timecmp_client_open()` acquires the channel
over the lookup path, and `timecmp_get`, `timecmp_set`, and `timecmp_adjust` map
to the three verbs. `BSDTimectl(8)` is the operator front end for the same
surface from the command line.

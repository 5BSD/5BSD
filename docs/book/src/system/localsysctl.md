# localsysctl: the sysctl broker

`localsysctl` exposes `system.Sysctl` and gives a capability-mode component the
ability to read — and, policy permitting, write — kernel sysctl variables by
name, without holding the ambient authority to call `sysctl(3)` for itself.
A client holds a `system.Sysctl` channel and names variables; the broker
performs the `sysctlbyname(3)` on its behalf after a per-label policy check.
There is no Casper `cap_sysctl` helper in the path.

Unlike the other providers, `localsysctl` is a **privileged provider**: its
per-client workers do *not* enter capability mode. In capability mode the
kernel restricts `sysctl(3)` to variables marked `CTLFLAG_CAPRD`/`CTLFLAG_CAPWR`
— which excludes nearly the entire MIB tree — so a sandboxed worker could read
almost nothing. `localsysctl` instead runs outside the Capsicum sandbox as the
trusted concentration point for sysctl access, and its security boundary is the
per-label policy, not a sandbox (see [Writing a Service
Provider](../development/writing-components.md) for the privileged-provider
pattern it shares with the extension and storage brokers). Each accepted client
is still served on its own `pdfork(2)`'d worker; the policy is loaded once
before the fork and every worker inherits it.

## The five verbs

The protocol is a small request/reply exchange over the channel:

- **get** — read a variable's raw value bytes by name. The value is opaque, as
  from `sysctl(3)`; the caller interprets the type.
- **set** — write raw value bytes to a variable, subject to the per-label write
  policy. A variable not granted for the caller's label is refused with
  `EPERM`.
- **oidfmt** — the variable's kind (`CTLTYPE` plus `CTLFLAG_*` bits) and its
  printf-style format string, so a client can decode the opaque value.
- **descr** — the human-readable description (as `sysctl -d`).
- **next** — enumeration. Given a name (or the empty string to start), the
  broker walks `CTL_SYSCTL_NEXT` and returns the *next variable the caller is
  permitted to read*, skipping any the label's policy denies until it finds a
  permitted name or the tree ends (`ENOENT`). Enumeration therefore never
  reveals the existence of a name outside the caller's read policy.

## Policy

Access is scoped per label by `sysctl.conf` in the provider's bundle `Config/`
directory, delivered as a directory descriptor rather than opened by a global
path. The `default` block applies to any label without its own `clients`
entry; `read` and `write` are lists of dotted-path prefixes matched on a
component boundary, so a name is permitted if it equals or lies under a listed
prefix. Reads of unlisted names, and any unlisted write, are refused with
`EPERM`. A missing or malformed file fails soft to the compiled-in default — a
small safe read set and no writes — rather than opening the tree or taking the
provider down.

## Client API

Components link `libsysctlcmp(3)`: `sysctlcmp_client_open()` acquires the
channel over the lookup path, and `sysctlcmp_get`, `sysctlcmp_set`,
`sysctlcmp_oidfmt`, `sysctlcmp_describe`, and `sysctlcmp_next` map to the five
verbs. As with `sysctlbyname(3)`, a `get` with a null buffer queries the size;
a value larger than the transport cap fails with `ENOMEM`. `sysctlcmpctl(8)` is
the operator front end for the same surface from the command line.

Reference: `localsysctl(8)`, `libsysctlcmp(3)`, `sysctlcmpctl(8)`.

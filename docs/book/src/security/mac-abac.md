# The mac_abac Module

`mac_abac` is a label-based mandatory access control policy for 5BSD
implementing attribute-based access control (ABAC). Security labels are
free-form sets of `key=value` attributes stored in filesystem extended
attributes; access decisions come from an ordered, first-match rule
table evaluated in the kernel. It loads as a standard MAC policy module
(`kldload mac_abac`) and lives in `/usr/src/sys/security/mac_abac/`.

## Label model

A label is up to 16 `key=value` pairs (keys ≤ 64 bytes, values ≤ 256
bytes), persisted for files in the system extended-attribute namespace
under the name `mac_abac` as newline-separated pairs. Process
(credential) labels are held in a MACF label slot; socket, pipe, and
IPC-object labels are inherited from the creating credential. Objects
without a label match a default subject/object label. Labels for
vnodes are loaded lazily from the extattr and cached per-vnode in UMA
zones. Exec-time label transitions are supported
(`mpo_vnode_execve_transition`), and a rule action can rewrite the
subject label.

## Rule model

Rules (up to `ABAC_MAX_RULES` = 4096) are evaluated in order with
pf-style first-match semantics. Each rule has:

- **Action**: `allow`, `deny`, or `transition` (allow and switch the
  subject to `vr_newlabel`).
- **Operations bitmask**: which of ~29 operation classes it gates —
  file operations (`exec`, `read`, `write`, `mmap`, `mprotect`, `link`,
  `rename`, `unlink`, `chdir`, `stat`, `readdir`, `create`, `lookup`,
  `open`, `access`, extattr get/set), process operations (`debug`,
  `signal`, `sched`, `wait`), socket operations (`connect`, `bind`,
  `listen`, `accept`, `send`, `receive`, `deliver`), and `audit`.
- **Subject and object patterns**: up to 8 `key=value` pairs matched
  against the caller's and target's labels; a negate flag inverts a
  pattern.
- **Subject and object context assertions**: non-label facts about the
  caller or target — Capsicum capability mode, jail membership,
  effective/real UID, GID, controlling TTY. Example from the header:
  `deny debug * -> * ctx:sandboxed=true` protects capability-mode
  processes from being debugged regardless of labels.

Rules belong to one of 65536 **sets** (IPFW-style). Sets are evaluated
in ascending order and can be enabled, disabled, swapped, or moved
atomically without touching individual rules — the supported mechanism
for hot policy reload and maintenance modes. When no rule matches, the
`security.mac.mac_abac.default_policy` sysctl decides (0 = allow,
1 = deny; permissive default).

## What is gated

Each object family has its own source file: vnodes (`abac_vnode.c` —
the full `mpo_vnode_check_*` surface including ACLs, flags, mode,
owner, times, revoke), credentials (`abac_cred.c` — relabel and the
setuid/setgid/setgroups/setcred/setaudit family), processes
(`abac_proc.c` — debug, signal, scheduling, wait), sockets
(`abac_socket.c` — create/bind/connect/listen/accept/send/receive and
inbound packet delivery), pipes (`abac_pipe.c`), POSIX semaphores and
shared memory (`abac_posixsem.c`, `abac_posixshm.c`), System V IPC
(`abac_sysv.c`), the kernel environment (`abac_kenv.c` — `kenv(2)`
dump/get/set/unset checked against a synthetic `type=kenv` object
label), and system-wide operations (`abac_system.c`).

## Configuration

Policy administration goes through `mac_syscall("mac_abac", ...)`
(root-only) with three userspace consumers:

- **`mac_abac_ctl`** (`/usr/src/usr.sbin/mac_abac_ctl/`) — CLI for
  rules, sets, labels, modes, stats, and loading policy files.
- **`mac_abacd`** (`/usr/src/usr.sbin/mac_abacd/`) — policy daemon
  that loads `/etc/mac_abac.conf`.
- Policy files in UCL/JSON or a simple line format; commented samples
  in `/usr/src/share/examples/mac_abac/` (`sample.ucl`, `sample.json`,
  `sample.rules`, `sample.conf`).

```sh
kldload mac_abac
mac_abac_ctl rule load /etc/mac_abac.conf     # atomic replace (RULE_LOAD)
mac_abacd -c /etc/mac_abac.conf
```

Operational controls:

- **Enforcement mode**: `disabled`, `permissive` (log, do not enforce),
  `enforcing` (`ABAC_SYS_GETMODE`/`SETMODE`).
- **Lock**: `ABAC_SYS_LOCK` is a one-way latch that freezes all policy
  changes until reboot.
- **Log levels**: none / errors / admin actions (default) / denials /
  all checks, to the kernel message buffer and syslog.
- **Counters**: `security.mac.mac_abac.{checks,allowed,denied,rule_count,
  default_policy}` sysctls plus an `abac_stats` struct for tools; a
  built-in `ABAC_SYS_TEST` command dry-runs a decision, and DTrace
  probes are defined in `abac_dtrace.h`.

## Composition with other MAC modules

`mac_abac` registers with `MAC_POLICY_SET(&abac_ops, mac_abac, ...)`
and claims a label slot, so it composes under the standard MAC
framework rule: every loaded policy is consulted and **any denial
wins**. `mac_abac` can therefore only further restrict what
mac_capability's isolation/capprotect/system enforcement, Capsicum, or
other loaded policies (e.g. `mac_bsdextended`) already permit — it can
never re-grant access another module denied. Its labels are private to
its own extattr name and slot and do not conflict with other
label-bearing policies. It is enabled per-object-family only when
rules reference that family (`ABAC_CHECK_ENABLED()` short-circuits
when the module is disabled), keeping overhead near zero with an empty
table.

Packaging: the module is built from `/usr/src/sys/modules` as
`mac_abac`, with pkgbase packages `mac-abac` and `mac-abac-tests`
(`/usr/src/packages/`).

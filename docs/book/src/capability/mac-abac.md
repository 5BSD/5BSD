# Attribute-Based Access Control (mac_abac)

`mac_abac` is a label-based mandatory access control policy compiled into
every 5BSD kernel. Files and processes carry sets of `key=value`
attributes; an ordered rule table decides, per operation, whether a subject
label may act on an object label. 5BSD has it because the capability plane
answers "does this program hold a capability for that?" but says nothing
about the POSIX substrate underneath: which labeled file a labeled process
may read, which process it may signal, whether an executable of one type
may run at all. `mac_abac` answers those questions in the type-enforcement
style of SELinux without a compile-time policy, and it composes with the
plane by the MAC framework's deny-wins rule: it can narrow what Capsicum,
`mac_capability` and capprotect allow, and can never re-grant what they
deny.

Reference pages: mac_abac(4), mac_abac.conf(5), mac_abac_ctl(8),
mac_abacd(8). Source: `sys/security/mac_abac/` (17 files) and
`usr.sbin/mac_abac_ctl`, `usr.sbin/mac_abacd`.

## Labels

A label is up to 16 newline-separated `key=value` pairs (keys at most 64
bytes, values at most 256, the whole label at most 4096). On a file it is
stored in the `system:mac_abac` extended attribute, which means the
filesystem must support extended attributes: ZFS does natively, UFS needs
`multilabel` from tunefs(8). On a process it is a credential label,
inherited across fork and changed only by an exec transition rule. Anything
without an explicit label reads as `type=unlabeled`.

```
# label a binary, then confirm the kernel sees it
mac_abac_ctl label setatomic /usr/local/bin/nginx type=entrypoint,app=nginx
mac_abac_ctl label get /usr/local/bin/nginx
```

`label set` writes the attribute and refreshes the kernel's cached copy;
`label setatomic` does both in one kernel call and is the preferred form on
ZFS. `label setrecursive` walks a tree (`-d` directories only, `-f` files
only) and `label refresh` re-reads an attribute written with setextattr(8).
Keys are arbitrary; the conventions the tools document are `type`,
`domain`, `name`, `sensitivity` and `compartment`.

## The 30 operations

Rules name operations from a fixed vocabulary of 29 plus `all`. The policy
implements about 170 MAC entry points and folds each into one of these
operations, so one operation name covers every hook with that meaning:
`write` is checked for a vnode write, a pipe write, a POSIX shared-memory
write and a truncation alike. The per-subsystem mapping lives in
`sys/security/mac_abac/abac_{vnode,proc,socket,pipe,posixshm,posixsem,sysv,system,cred,kenv}.c`;
the bit assignments are `ABAC_OP_*` in `sys/security/mac_abac/mac_abac.h`.

| Operation | What it controls |
|---|---|
| `exec` | executing a file; also where `transition` rules fire |
| `read`, `write`, `mmap`, `mprotect` | reading, writing, mapping and changing the protection of an object |
| `open`, `create`, `unlink`, `link`, `rename` | opening, creating, deleting, hard-linking and renaming |
| `lookup`, `chdir`, `stat`, `readdir`, `access` | name lookup in a directory, changing directory, status, directory listing, `access(2)` |
| `setextattr`, `getextattr` | setting and reading extended attributes |
| `debug`, `signal`, `sched`, `wait` | ptrace and procfs debugging, signalling, scheduler changes, `wait4(2)` on a process |
| `connect`, `bind`, `listen`, `accept`, `send`, `receive`, `deliver` | socket operations; `deliver` is inbound packet delivery to a socket |
| `audit` | BSM audit operations |
| `all` | every operation |

Process-target operations (`debug`, `signal`, `sched`, `wait`) match the
target process's credential label as the object; file operations match the
vnode label.

## Rules

A rule has an action, an operation set, a subject pattern, an object
pattern, optional context constraints and, for transitions, a new label.
Rules live in numbered sets (0 to 65535) evaluated in ascending order, and
within a set in insertion order; the first match wins, exactly as pf(4)
evaluates its ruleset. If nothing matches, `default_policy` applies. The
table holds at most 4096 rules, and each rule uses about 1.6 KB of kernel
memory.

| Action | Effect |
|---|---|
| `allow` | permit the operation |
| `deny` | refuse it |
| `transition` | on `exec`, permit and replace the process label with `newlabel` |

Patterns are `key=value` pairs joined by AND; `*` matches any label,
`key=*` requires the key with any value, and a leading `!` negates the
whole pattern. A pattern holds at most 8 pairs. Context constraints apply
to the calling process (`subj_ctx`) or, for process-target operations, to
the target (`obj_ctx`):

| Constraint | Meaning |
|---|---|
| `uid = N`, `ruid = N` | effective or real uid (not both in one constraint) |
| `gid = N` | effective gid |
| `jail = "host"`, `"any"`, or a jid | not jailed, in any jail, in that jail |
| `sandboxed = true|false` | in Capsicum capability mode, or not |
| `tty = true|false` | has a controlling terminal, or not |

## The policy file

`/etc/mac_abac.conf` is UCL (JSON is accepted). Three top-level keys:
`mode`, `default_policy` and `rules`.

```
mode = "enforcing";
default_policy = "deny";

rules = [
    # web tier: enter the domain at exec, then stay inside it
    { action = "transition"; operations = ["exec"];
      object = "type=entrypoint,app=nginx";
      newlabel = "domain=web,app=nginx,restricted=true"; },
    { action = "allow"; operations = ["all"];
      subject = { domain = "web"; restricted = "true"; };
      object  = { domain = "web"; }; },
    { action = "deny"; operations = ["read", "write", "exec"];
      subject = { restricted = "true"; }; },

    # admin tools only for root, on the host, at a terminal
    { action = "allow"; operations = ["exec"];
      object = { type = "admin"; };
      subj_ctx = { uid = 0; jail = "host"; tty = true; }; },
    { action = "deny"; operations = ["exec"]; object = { type = "admin"; }; },

    # nobody debugs a sandboxed process
    { action = "deny"; operations = ["debug"]; obj_ctx = { sandboxed = true; }; }
];
```

Each rule may carry an `id` and a `set`. The same rules can be written one
per line for `mac_abac_ctl rule add`:

```
allow exec * -> type=trusted set 0
allow read,write domain=webapp -> domain=webapp set 100
deny debug * -> * ctx:sandboxed=true
```

`ctx:` before the arrow constrains the subject, after it the object.
Samples in all three syntaxes are installed under
`/usr/share/examples/mac_abac/`.

## Operating it

`mac_abacd(8)` loads the policy at boot and reloads it on `SIGHUP`. Its rc
service is off by default because an enforcing policy can lock an operator
out; the recommended sequence is validate, load permissive, watch, then
enforce:

```
mac_abacd -t -c /etc/mac_abac.conf        # parse only
sysrc mac_abacd_enable=YES
service mac_abacd start                    # mode from the file (permissive)
mac_abac_ctl log deny                      # log denials to the message buffer
# ... run the workload, read dmesg ...
mac_abac_ctl mode enforcing
mac_abac_ctl lock                          # no further changes until reboot
```

`mac_abac_ctl(8)` is the runtime surface. Its command groups:

| Group | Commands |
|---|---|
| state | `mode [disabled|permissive|enforcing]`, `default [allow|deny]`, `status`, `stats`, `limits`, `log [none|error|admin|deny|all]` |
| rules | `rule add`, `rule remove ID`, `rule clear`, `rule list`, `rule load FILE` (atomic replace; a parse error leaves the old table), `rule append FILE`, `rule validate FILE`; `-s SET` targets a set |
| sets | `set enable|disable N|A-B|all`, `set swap A B` (atomic, no window without rules), `set move FROM TO`, `set clear N`, `set list [A-B]` |
| labels | `label get|set|setatomic|setrecursive|refresh|remove` |
| protection | `lock` (one-way until reboot) |
| testing | `test OPERATION SUBJECT OBJECT` reports the decision and the matching rule without performing anything |

Rule sets are the hot-reload primitive: prepare the new policy in a
disabled set, then `set swap` it with the live one. The daemon and the
tool both speak to the kernel through `mac_syscall(2)` with the policy name
`mac_abac` and the `ABAC_SYS_*` commands in `mac_abac.h`; rule and mode
changes are root-only, and a credential relabel additionally requires
`PRIV_MAC_PARTITION` and may only narrow the label.

## Sysctls

| Sysctl | Meaning | Default |
|---|---|---|
| `security.mac.mac_abac.enabled` | module on or off; labels are still read and stored when off | 1 |
| `security.mac.mac_abac.mode` | 0 disabled, 1 permissive (decide and log, never deny), 2 enforcing | 1 |
| `security.mac.mac_abac.default_policy` | 0 allow, 1 deny when no rule matches | 0 |
| `security.mac.mac_abac.locked` | read-only; 1 once `lock` has been issued | 0 |
| `security.mac.mac_abac.log_level` | 0 none, 1 error, 2 admin, 3 deny, 4 all; output goes to the kernel message buffer | 2 |
| `security.mac.mac_abac.extattr_name` | loader tunable naming the label attribute | `mac_abac` |
| `security.mac.mac_abac.{checks,allowed,denied,rule_count}` | decision counters and live rule count | read-only |
| `security.mac.mac_abac.{labels_read,labels_default,labels_allocated,labels_freed,parse_errors}` | label cache statistics and malformed-label count | read-only |

## Boot-only and static

`mac_abac` is registered with `MPC_LOADTIME_FLAG_NOTLATE`: it must be present
when the kernel starts and cannot be unloaded, because labels may be
attached to vnodes and credentials that outlive any module lifecycle. In
5BSD the question does not arise: `options MAC_ABAC` is in GENERIC, so the
policy is always present and a `mac_abac_load` line in loader.conf(5) is
unnecessary. Presence is not enforcement: the module starts in permissive
mode (`abac_mode = ABAC_MODE_PERMISSIVE` in `mac_abac.c`, chosen for
safety), so until an administrator loads rules and switches to enforcing it
stores and reports labels, evaluates an empty table, and denies nothing.

## The DTrace provider

The `abac` SDT provider exposes 21 probes so an operator can see why a
decision was made without raising `log_level`:

| Probe | Fires when |
|---|---|
| `abac:rules:check:entry`, `:return`, `:allow`, `:deny` | an access check starts and completes |
| `abac:rules:rule:match`, `:nomatch`, `:add`, `:remove`, `:clear` | a rule matched, the default applied, or the table changed |
| `abac:policy:mode:change`, `:default:change`, `:lock:set`, `:loglevel:change` | administrative state changed |
| `abac:cred:transition:exec` | a transition rule relabeled a process |
| `abac:label:extattr:read`, `:extattr:default`, `:file:set` | a label was read, defaulted, or written |
| `abac:sets:set:enable`, `:disable`, `:swap`, `:move`, `:clear` | rule-set operations |

```
# dtrace -n 'abac:rules:check:deny { printf("%s -> %s", copyinstr(arg0), copyinstr(arg1)); }'
```

The framework-level probe `mac_framework:::policy-decision` reports the
verdict of every loaded policy for a hook, which is how to tell an `abac`
denial from a `mac_capability` one.

## Beside the capability plane, not inside it

`mac_abac` is a MAC policy next to the plane, and three consequences follow.
It knows nothing about channel labels, anointments or bundles; its subject
is the process credential label, which the plane never sets. Its labels do
not flow through the plane's delivered descriptors; a rights-limited file
descriptor from BSDFilesystem is still subject to `read` and `write` rules
on the vnode behind it, because those hooks fire on the vnode regardless of
how the descriptor was obtained. And the ordering is fixed by the MAC
framework: a `mac_abac` `allow` never overrides an isolation claim, a
capprotect shield, a system gate or a Capsicum rights check, while a
`mac_abac` `deny` is final. The practical use inside the plane is therefore
additive confinement of the POSIX side: a site can label the files under a
container's mount and confine a provider's `domain` without touching any
manifest.

One interaction deserves a note. Context constraints can name
`sandboxed = true`, so a rule can say "no process may ptrace a
capability-mode process" or "a sandboxed process may only exec labeled
entry points"; both express plane invariants a second way, at the MAC
layer, for a site that wants defence in depth.

## Tests

| Suite | What it covers |
|---|---|
| `tests/sys/security/mac_abac/parser_test.c` | line-format parsing: allow and deny forms, case folding, subject and object context, invalid input (7 cases, no kernel needed) |
| `tests/sys/security/mac_abac/kernel_test.c` | allow, deny and disabled-set decisions through the live policy, atomic load rollback and exact clear, reserved-set handling, full set range, default-policy validation (9 cases; root, policy present) |
| `tests/sys/security/mac_abac/smoke_test.sh` | end-to-end tool and daemon smoke |
| `tests/sys/mac/mac_test_hooks_test.c` | exercises the new MAC hooks `mac_abac` shares with the other policies |

The parser tests share `parse_line.c` with `mac_abac_ctl`, so the tool and
the tests cannot drift apart.

## Status

Shipped and static in GENERIC, permissive with no rules by default
(`mode = 1`, `default_policy = allow`, `mac_abacd_enable=NO`). No
base-system labels are installed; a policy is
entirely a site decision. The daemon package depends on libucl. Nothing in
the plane's own units is labeled or relies on `mac_abac`, so turning it on
changes nothing until a rule matches, and turning it on with
`default_policy = "deny"` in enforcing mode before labeling the system will
deny everything: use permissive mode first.

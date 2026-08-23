# Attribute-Based Access Control (mac_abac)

`mac_abac(4)` is 5BSD's label-based mandatory access control policy. Security
labels are sets of `key=value` attributes and kernel decisions use an ordered,
first-match rule table. It loads as a normal MAC policy (`kldload mac_abac`),
composes with every other MAC policy, and is implemented under
`sys/security/mac_abac/`.

## Labels

A label contains at most 16 pairs, with keys up to 64 bytes, values up to 256
bytes, and a 4096-byte serialized limit. Vnode labels are stored in the system
extended-attribute namespace as `mac_abac`, using newline-separated pairs.
They are loaded lazily and cached in the vnode's MAC label slot. Credential
labels occupy their own slot; sockets, pipes, POSIX and System V IPC objects
inherit the creating credential's attributes. Unlabelled subjects and objects
use configurable default labels.

Exec is an access check like any other operation. The only rule actions are
`allow` and `deny`; a process label changes only through an explicit,
authorized relabel operation.

`mac_abac_ctl` is also the labeling tool:

```sh
mac_abac_ctl label get /srv/app
mac_abac_ctl label setatomic /srv/app 'domain=web,type=data'
mac_abac_ctl label setrecursive /srv/app 'domain=web,type=data' -v
mac_abac_ctl label refresh /srv/app
mac_abac_ctl label remove /srv/app
```

`set` and `setatomic` use the kernel's atomic set-label operation, which writes
the extattr and publishes the parsed in-memory vnode label as one operation.
This is the safe path for ZFS and other single-label filesystems where a later
`mac_vnode_setlabel()` refresh is not available. Recursive labeling uses a
physical FTS walk, does not follow symbolic links, can select files or
directories, and applies the same atomic operation to every selected object.
`refresh` is for labels written with lower-level extattr tools.

## Rules and enforcement surface

Up to `ABAC_MAX_RULES` (4096) rules are evaluated by set number and then load
order; the first matching rule wins. A rule contains:

- an `allow` or `deny` action;
- an operation mask covering vnode, process, socket, IPC, credential, audit,
  kernel-environment, and system operations;
- subject and object patterns of up to eight `key=value` assertions, with
  wildcards and pattern negation;
- optional subject and target context constraints for effective/real UID,
  GID, jail membership, controlling TTY, and Capsicum mode.

For example, a rule can deny debugging any capability-mode process regardless
of its label. When no rule matches,
`security.mac.mac_abac.default_policy` selects allow (0) or deny (1); the
shipped default is permissive.

Rules are grouped into sets 0–65535. Disabled sets are skipped; sets can be
enabled, disabled, cleared, moved, or atomically swapped. This makes it
possible to prepare a replacement policy in an inactive set and publish it
without an enforcement gap.

The policy gates the full vnode check surface, credential changes, process
debug/signal/scheduling/wait, socket lifecycle and packet delivery, pipes,
POSIX semaphores and shared memory, System V IPC, kernel environment access,
and system-wide operations. The implementation is split by object family in
`sys/security/mac_abac/abac_*.c` so the hook coverage is auditable.

## Policy source, compilation, and loading

Administration uses root-only `mac_syscall("mac_abac", ...)`; untrusted
processes do not receive a policy-management descriptor. Policy can be written
as strict UCL/JSON or as the compact line format. Samples are installed from
`share/examples/mac_abac/`.

```sh
mac_abacd -t -c /etc/mac_abac.conf            # parse and compile only
mac_abac_ctl rule validate -f policy.ucl      # no kernel change
mac_abac_ctl rule validate 'deny debug * -> *'
mac_abac_ctl rule load /etc/mac_abac.conf     # atomic replacement
```

The userspace compiler rejects unknown top-level keys, unsupported actions and
operations, malformed labels/context, invalid set
numbers, duplicate or oversized data, and policy-wide mode/default errors. It
packs validated rules into the pointer-free `ABAC_SYS_RULE_LOAD` format only
when a load is requested. The kernel independently validates every record,
length, reserved field, action, operation, pattern, and context before
publishing the replacement table. Any failure restores the complete previous
table; there is no partially loaded policy. The daemon applies the default
policy after the rule table and switches enforcement mode last.

`mac_abacd(8)` loads `/etc/mac_abac.conf`, supports validation-only mode, and
reloads on signal. `mac_abac_ctl(8)` provides rule add/remove/list/append/load/
validate, set management, labeling, status and limits, and the kernel dry-run
decision command:

```sh
mac_abac_ctl test read 'domain=web' 'domain=database,type=data'
```

## Operational controls and composition

The enforcement modes are `disabled`, `permissive` (calculate and log denials
without enforcing), and `enforcing`. Log levels range from errors through all
checks. Counters expose checks, allows, denials, label loads/defaults, and rule
counts through sysctl and the tool. `ABAC_SYS_LOCK` is a one-way latch that
freezes the rule table, mode, default decision, and set administration until
reboot; the audit log level remains adjustable. DTrace probes cover checks,
decisions, rule matches, label activity, and administrative operations.

MAC composition is deny-wins: `mac_abac` can further restrict Capsicum,
mac_capability, capprotect, and other MAC policies, but cannot re-grant an
operation another policy denied. Its extattr and label slot are private. Empty
or disabled object-family rule masks short-circuit checks to keep the unused
cost small.

## Testing and VM qualification

Parser tests exercise valid allow/deny rules and malformed actions,
operations, labels, contexts, delimiters, duplicate fields, and limits.
Kernel tests exercise strict syscall ABI
validation, atomic load rollback and empty replacement, set ordering and
administration, default/mode behavior, locking, label parsing and matching,
and enforcement hooks. Shell integration tests compile every shipped policy
format, validate UCL without mutation, drive the labeling commands, verify
recursive and atomic label behavior, and cover CLI failure exits.

`tools/test/mac-abac-qemu/` packages the current module, public header,
compiler/daemon, labeling tool, samples, and Kyua suite into a read-only image
for a disposable amd64 QEMU guest. Its runner loads the matching module,
compiles all sample formats, and runs the complete suite. Snapshot mode leaves
the base image unchanged, and TCG permits host-side execution without root or
`/dev/vmm`.

The module and tests ship in the `mac-abac` and `mac-abac-tests` pkgbase
packages.

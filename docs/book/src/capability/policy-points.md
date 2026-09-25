# Policy Points

A 5BSD system answers "may this happen?" in seven places, and each place
decides a different kind of question. This chapter is the single map of
those places: the kernel hooks that see an operation, the gates that stand
in for root privilege, the shields that protect a process, the manifest
fields a bundle author sets, the principal policy that provisions a login
session, the per-provider policy files that scope one broker's clients, and
the sysctls that turn whole mechanisms on or off. FreeBSD spreads the same
decisions across `uid == 0`, file modes and ad hoc checks; 5BSD names them
so an operator can find the one that answers a given question.

Every row below gives the policy point, what it decides, where it is
configured and its shipped default. The mechanisms themselves are explained
in their own chapters, linked from each section. The last section turns
the map around and lists common questions with the point that answers each.

## Layer 1: the MAC hooks

The TrustedBSD MAC framework composes every loaded policy and denies if any
one denies. 5BSD keeps the upstream hook set and adds 62 net-new entry
points to `sys/security/mac/mac_policy.h`, called from the kernel paths
named in `docs/macf-new-hooks.md` (which also records the lock context and
whether each hook may sleep). A hook is only a place where a policy can
look; which policy answers is the interesting part. Four policies are
compiled into GENERIC: the mandatory `mac_capability` plane (see [The MAC
Capability Framework](mac-capability.md)), [mac_abac](mac-abac.md),
[OES](oes.md) and [mac_veriexec](veriexec.md). A fifth, `mac_test_hooks`,
is a loadable test fixture whose `security.mac.test_hooks.deny.<hook>`
sysctls force a denial so the hook can be exercised.

| Group (count) | Hooks | What the group guards | Shipped policies that implement it |
|---|---|---|---|
| vsock (4) | `vsock_provider_init_label`, `_destroy_label`, `_check_attach`, `_check_access` | which program may attach a vsock transport and reach a CID or port | mac_capability isolation (vsock claims) |
| vmm (7) | `vmm_check_create`, `_destroy`, `_reinit`, `_alloc_memseg`, `_mem_access`, `_memseg_access`, `_passthrough` | bhyve VM lifecycle, guest memory mapping, PCI passthrough; called from `sys/dev/vmm/vmm_dev.c` | none shipped; exercised by `mac_test_hooks` |
| ZFS (8) | `zfs_check_dataset_destroy`, `_pool_destroy`, `_pool_export`, `_send`, `_receive`, `_key_load`, `_key_unload`, `_key_change` | destructive and exfiltrating ZFS ioctls and encryption-key operations | none shipped; `mac_test_hooks` |
| mount snapshot (3) | `mount_check_snapshot_create`, `_delete`, `_revert` | filesystem snapshot lifecycle | none shipped; `mac_test_hooks` |
| vnode notify (13) | `vnode_notify_create`, `_open`, `_rename`, `_unlink`, `_link`, `_truncate`, `_setmode`, `_setowner`, `_setflags`, `_setextattr`, `_deleteextattr`, `_setacl`, `_setutimes` | observation only: a policy sees the completed change and cannot deny it | none shipped; `mac_test_hooks` |
| vnode check (4) | `vnode_check_close`, `_truncate`, `_uipc_bind`, `_uipc_connect` | close (observe only), truncation, binding and connecting AF_UNIX sockets by path | OES (close, truncate); isolation (truncate, uipc_connect) |
| execve relabel (2) | `vnode_execve_will_relabel`, `vnode_execve_relabel` | whether exec is an identity change and what the new credential label is | mac_capability label (nonce rotation); OES (exec path capture) |
| proc (9) | `proc_check_fork`, `_core`, `_ktrace`, `_mmap_anon`, `_mprotect`, `_suspend`, `_syscall`; `proc_notify_exec_complete`, `_exit` | forking, core dumps, ktrace attach, anonymous mappings, protection changes, suspension, syscall entry; exec and exit notifications | capprotect (fork, core, ktrace, suspend) |
| file (6) | `file_check_dup`, `_inherit`, `_ioctl`, `_mmap`, `_receive`; `file_notify_close` | descriptor duplication, inheritance across exec, ioctl, mapping, `SCM_RIGHTS` receipt | capprotect (receive: `CP_SF_NOFDRECV`) |
| rctl (2) | `rctl_check_add_rule`, `_remove_rule` | changing resource-control rules; live because GENERIC enables RACCT | none shipped |
| kld (1) | `kld_check_unload` | unloading a kernel module | mac_capability system (`SYS_GATE_KLDUNLOAD`) |
| socket (1) | `socket_check_setsockopt` | setting socket options, including the Linux emulation path | none shipped; `mac_test_hooks` |
| kas_info (1) | `system_check_kas_info` | disclosure of kernel address-space layout | none shipped; `mac_test_hooks` |
| pts (1) | `pts_check_open` | opening a pseudo-terminal slave | none shipped; `mac_test_hooks` |

Two points about this table. First, "none shipped" means the kernel already
calls the hook, so a site policy or a future base policy can veto the
operation without touching the call site. Second, a hook is not the only
guard: the vmm hooks are one layer; the BSDVM broker and the coalition that
owns a VM are the others. The per-policy DTrace probe
`mac_framework:::policy-decision` reports each module's verdict, which is
the tool for "who denied this".

## Layer 2: system gates

Gates replace `PRIV_*` checks for the operations a born-in-capability-mode
broker must perform. A gate is claimed by capsule, minted as a token and
delivered to the broker at launch; the kernel then denies the operation to
every other program while the claim stands. [System Gates](system-gates.md)
describes the mechanism; the table lists the twelve gates from
mac_capability_system(4).

| Gate | What it decides | Where configured | Default |
|---|---|---|---|
| `KLDLOAD`, `KLDUNLOAD` | who may load and unload kernel modules (`mpo_kld_check_load`, `_unload`) | BSDExtension manifest `capabilities { system = ["kldload", "kldunload"] }` | held by BSDExtension |
| `REBOOT` | reboot, halt, poweroff (`mpo_system_check_reboot`) | `claims.system` in capsule.conf(5) | unclaimed; lifecycle goes through capsulectl(8) |
| `SWAPON`, `SWAPOFF` | adding and removing swap | `claims.system` in capsule.conf(5) | unclaimed |
| `SYSCTL` | privileged sysctl writes, per OID when scoped (`mpo_system_check_sysctl`) | BSDSysctl manifest `system = ["sysctl"]; isolate = [...]` | scoped claim on `kern.maxfiles` |
| `KENV`, `KENV_READ` | kernel environment set/unset and get/dump | `claims.system` | unclaimed |
| `ACCT` | process accounting control | `claims.system` | unclaimed |
| `AUDIT` | `auditon(2)` and `auditctl(2)` | `claims.system` | unclaimed |
| `SETTIME` | clock step and slew; perform-only, no MACF hook | BSDTime manifest `system = ["settime"]` | held by BSDTime |
| `JAIL` | jail creation and query; perform-only | BSDNamespace manifest `system = ["jail"]` | held by BSDNamespace |

An unclaimed gate behaves as FreeBSD does for a process outside capability
mode: the kernel's own priv(9) check applies. Inside capability mode an
unclaimed gate is denied, so a sandboxed program never gains ambient
authority from a gate nobody claimed.

## Layer 3: capprotect shields

A shield is a per-process integrity policy applied by the process itself or
by its launcher over a process descriptor. [Descriptor and Process
Protections](descriptor-protections.md) explains the model; the flags come
from mac_capability_capprotect(4). Protection flags block what foreign
processes may do to the shielded process; restriction flags limit what the
shielded process may do itself.

| Flag | What it decides | Where configured | Default |
|---|---|---|---|
| `ptrace` | debugger attach (`mpo_proc_check_debug`) | manifest `protect`, capsule.conf(5) `integrity` | set on every base provider |
| `signal`, `sigkill`, `sigcont` | signals and suspension from foreign processes | same | set on every base provider |
| `wait` | `wait4(2)` by a non-parent | same | set on every base provider |
| `sched` | priority and cpuset changes by foreign processes | same | set on every base provider |
| `core` | core dumps of the protected process | same | set on every base provider |
| `ktrace` | ktrace attach | same | set on every base provider |
| `noprivs`, `nofork`, `noipc`, `nofdrecv`, `noexec`, `nosock` | self-restrictions: every priv(9) check, forking, SysV/POSIX IPC, `SCM_RIGHTS` receipt, exec, socket creation | manifest `protect` | unset |
| `visible` | accepted for compatibility; has no effect in the per-process model | any | ignored |

The aliases `protect`, `restrict` and `all` expand to their flag sets. A
shield outlives exec and is dropped at exit; forked children start
unshielded.

## Layer 4: manifest policy fields

A unit's `Unit.ucl` decides how switchboard launches and manages it. The
full key set is in switchboard(5) and [Bundles and
Manifests](../plane/bundles-and-manifests.md); this table lists the keys
that are policy rather than description.

| Field | What it decides | Default |
|---|---|---|
| `protect` | the capprotect flags switchboard applies over the process descriptor after `pdfork(2)`, before the image runs | none |
| `limits { memory cpu nproc nofile stack fsize core }` | `setrlimit(2)` ceilings applied pre-exec | inherited from switchboard; `core = 0` |
| `umask` | file-creation mask | `0077` |
| `level` | `background`, `standard` or `interactive` nice priority; `interactive` is honoured only for a base-system bundle | `standard` |
| `control` | management class `core`, `system` or `user`: who may stop, restart, unload or disable the unit; `core` is unmanageable by anyone, root included | `system` |
| `visible` | which domain kinds (`user`, `system`) may resolve the unit's open IPC names; absent means SYSTEM-only | absent |
| `domain` | the domain the unit's own lookups run in | by bundle class |
| `holds` | the anointments the unit presents when it looks up a gated endpoint | empty |
| `activation.ipc[].requires` | the anointments a caller must hold to reach this endpoint | open |
| `capabilities { system, isolate }` | the system gates a base broker holds, and the sysctl OIDs it becomes sole writer of | none; stripped from per-user agents |
| `ambient` | launch outside capability mode | `false`; only BSDVM sets it |
| `mint_authority` | the unit is the session mint boundary (BSDAuth); honoured only for a base-system bundle | `false` |
| `user`, `group` | the credential the unit runs as | `capability` |
| `watchdog { interval }` | liveness deadline enforced with `service_heartbeat(3)` | disabled |

The manifest deliberately carries no resource grants: no paths, devices,
network endpoints, storage or jails. Those are acquired at runtime by name
and decided by the provider's own policy file (layer 6). Under
[mac_veriexec](veriexec.md) the manifest is opened `O_VERIFY`, so the
declaration and the grant are the same signed fact.

## Layer 5: the principal policy

`/Capabilities/Config/principal-policy.ucl` is consulted only by BSDAuth,
when login(1), su(1) or sshd(8) mint a session channel and on every
anoint(1) request. It is the one place a uid or group is turned into
capabilities. See [Anointments and Principal
Policy](../plane/anointments.md) and [The Authority
Model](authority-model.md).

| Key | What it decides | Default (shipped file) |
|---|---|---|
| `principals.<name>.uids`, `.groups` | which authenticated principal the entry matches; first match in file order wins | `admin`: uid 0 and group `wheel` |
| `anointments` | the gated endpoints every process in the session can reach without asking; `*` is legal only here | `admin`: `["*"]`; `default`: `[]` |
| `may_elevate` | the anointments the principal may obtain for one command through anoint(1) after re-authenticating | absent (no elevation) |
| `admin_rights` | whether the session's connections carry `SVC_RIGHTS_ADMIN`, the in-endpoint bypass providers honour | true only when `anointments` is `["*"]` |

An absent or malformed file falls back to the same rule as the shipped
default, so a damaged policy cannot lock out root. The `capability` uid
that units run as is never a principal here.

## Layer 6: per-provider policy files

Each broker keeps its own policy, keyed by the caller's unforgeable channel
label, read at startup from the unit's `Config/` directory over a delivered
descriptor. A session carrying `SVC_RIGHTS_ADMIN` bypasses these tables; a
unit never carries that bit.

| Provider and file | What it decides | Default |
|---|---|---|
| BSDNetwork, `Config/bsdnetwork.conf` | per label: `resolve`, `connect`, `udp`, `inet4`, `inet6`, `internal` (loopback, link-local and private ranges) | all true except `internal = false`; a malformed file keeps the compiled-in default |
| BSDTrace, `Config/bsdtrace.allow` | which labels may receive a DTrace consumer descriptor; wildcards rejected; the endpoint additionally requires the `system.trace.client` anointment | default-deny; absent file is an empty policy |
| BSDFilesystem, `open_paths` in `/Capabilities/Config/bsdfilesystem.ucl` (tzfs.conf(5)) | per label: one absolute path, `rights` from `read write exec lookup ioctl`, optional `prefix` matching one trailing component | default-deny; shipped entries cover BSDAuth's identity databases and BSDNetwork's resolver files |
| BSDDevice, `Config/device.conf` | per label and `/dev` leaf: `rights` from `read write ioctl mmap seek event` and an optional `ioctls` allow-list applied with `cap_ioctls_limit(2)` | default-deny |
| BSDSysctl, `Config/sysctl.conf` | per label: `read` and `write` OID name lists | `default`: a short read list (`kern.ostype`, `hw.ncpu`, ...), empty write list |
| BSDTime, `Config/time.conf` | per label: `set` | `default { set = false; }` |
| BSDPower, `Config/power.conf` | per label: `suspend` | `default { suspend = false; }` |

## Layer 7: security sysctls

These knobs change how a whole mechanism behaves. Loader tunables (`RDTUN`)
must be set in loader.conf(5); the rest can be changed at runtime.

| Sysctl | What it decides | Default |
|---|---|---|
| `kern.mac_capability_isolation.enforce` (RDTUN) | enforce isolation denials, or trace and allow resource access (ownership checks stay enforced); test mode | 1 |
| `kern.mac_capability_system.max_auth` | cap on outstanding gate authorizations; 0 is unlimited | 0 |
| `kern.mac_capability_capprotect.max_auth` (RDTUN) | cap on outstanding shield token authorizations | 0 |
| `kern.elf64.capmode_interp` (RWTUN) | may a capability-mode process exec a dynamic image through the brand's own interpreter | 1 |
| `security.mac.mac_abac.enabled`, `.mode`, `.default_policy` | module on/off; 0 disabled, 1 permissive, 2 enforcing; 0 allow or 1 deny when no rule matches | 1; 1 (permissive, no rules); 0 (allow) |
| `security.mac.mac_abac.locked` (read-only), `.log_level`, `.extattr_name` (RDTUN) | lock-until-reboot state; logging verbosity 0 to 4; label attribute name | 0; 2 (admin); `mac_abac` |
| `security.mac.mac_abac.{checks,allowed,denied,rule_count,labels_read,labels_default,labels_allocated,labels_freed,parse_errors}` | counters | read-only |
| `security.oes.require_auth_clients` | deny an AUTH-hooked operation when no AUTH client is subscribed (fail-closed switch) | 0 |
| `security.oes.auth_fail_closed` | deny when OES cannot allocate or deliver required state | 0 |
| `security.oes.default_deadline_ms`, `.default_deadline_miss_mode` | AUTH deadline and what happens when it is missed (0 fail open, 1 fail closed) | 30000; 0 |
| `security.oes.max_clients`, `.default_queue_size`, `.cache_max_entries` | resource limits per system and per client | 64; 1024; 1024 |
| `security.oes.default_self_mute`, `.default_muted_paths`, `.default_muted_paths_literal` | initial noise suppression for new clients | 1; empty; empty |
| `security.mac.veriexec.state`, `.block_unlink` (RDTUN) | verified-execution state (`loaded`, `active`, `enforce`, `locked`); refuse unlink of verified files | inactive; 0 |
| `kern.squeue.max_wired_pages` | memory the Linux io_uring engine may wire (see [io_uring and squeue](../compat/linux/io-uring.md)); the other `kern.squeue.*` nodes are counters | 1/8 of RAM |

## Which point answers which question

| Question | Policy point |
|---|---|
| Can this sandboxed unit open `/dev/x`? | BSDDevice `device.conf` (leaf devices) or BSDFilesystem `open_paths` (paths and device families); the unit itself has no path authority |
| Can this unit see that service name? | provider's `visible` for open endpoints; the caller's `holds` (unit) or `anointments` (session) against the endpoint's `requires` for gated ones; management class does not affect lookup |
| Can this session stop that service? | `control` class of the unit: `core` never; `system` needs `admin_rights`; `user` needs the owning uid or `admin_rights` |
| Why did a root shell get `ENOENT` for `system.Notify.System`? | the session's principal-policy entry does not hold `system.notify.system`; use anoint(1) if `may_elevate` allows it |
| Can this program load a module? | `SYS_GATE_KLDLOAD` is held by BSDExtension; other programs get `EPERM` from `mpo_kld_check_load`; ask through `service_ensure_extension(3)` and BSDExtension's allow-list |
| Can anyone write `kern.maxfiles` directly? | no; the scoped `SYSCTL` claim makes BSDSysctl the sole writer, and its `sysctl.conf` decides which labels may ask |
| Can a debugger attach to a provider? | `protect = ["ptrace", ...]` in its manifest; the launcher (switchboard) and token holders are exempt |
| Can an unfingerprinted program run? | `security.mac.veriexec.state`: only when `enforce` is set does `mpo_vnode_check_exec` refuse it |
| Can a label read a file it is not supposed to? | `mac_abac` rules, when `mode` is enforcing; a first-match `deny` on `read` for that subject and object |
| Can an EDR agent veto an exec? | OES: an AUTH-mode client subscribed to `OES_EVENT_AUTH_EXEC`; with `require_auth_clients = 1` the absence of such a client denies |
| Can a bhyve VM map that memory segment? | `mpo_vmm_check_mem_access` and `_memseg_access`, if a policy implements them; none shipped, so the BSDVM broker and coalition ownership decide |
| Can this process send `SIGKILL` to that one? | capprotect `sigkill` flag on the target; then the ordinary credential check |

## Status

The seven layers are all shipped and compiled into GENERIC. Two are not
yet exercised in production: no shipped policy implements the vmm, ZFS,
snapshot, vnode-notify, rctl, setsockopt, kas_info or pts hooks, and
mac_veriexec is present but not enforcing (see
[Verified Execution](veriexec.md)). The uid-gated fallbacks that remain in
the plane are recorded in [The Authority Model](authority-model.md).

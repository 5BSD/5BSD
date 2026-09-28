# System Calls and Sysctls

What a developer or operator meets at the kernel boundary that FreeBSD does
not have: the native system calls 5BSD adds, the upstream calls it lets a
sandboxed process make, every new sysctl knob and counter, the new MAC
policy entry points, and the new constants in the public headers. Every
row was taken from the tree at HEAD against the baseline `bc301fee4cb`.

## Native system calls

The syscall table is `sys/kern/syscalls.master`. 5BSD introduces one new
flag: a `CAPREQUIRED` syscall is legal only inside capability mode and
returns `ENOTCAPABLE` outside it (`SYF_CAPREQUIRED` in `sys/sys/sysent.h`;
it implies `CAPENABLED`). Today one call carries it.

### New calls

| Number | Name | Flags | Manual page | What it does |
|---|---|---|---|---|
| 603 | `cap_xfer_limit(fd, state)` | CAPENABLED | cap_xfer_limit(2) | Sets a descriptor's transfer state: unlimited, once, or never; monotone |
| 604 | `cap_cloexec_limit(fd, state)` | CAPENABLED | cap_cloexec_limit(2) | Forces close-on-exec regardless of `FD_CLOEXEC`: unlocked, locked, or survive one exec |
| 605 | `cap_clofork_limit(fd, state)` | CAPENABLED | cap_clofork_limit(2) | Forces close-on-fork the same way |
| 606 | `cap_xfer_rights_limit(fd, rights)` | CAPENABLED | cap_xfer_rights_limit(2) | Sets the rights ceiling a descriptor carries when it is passed |
| 607 | `cap_xfer_ioctls_limit(fd, cmds, ncmds)` | CAPENABLED | cap_xfer_rights_limit(2) | Sets the ioctl ceiling applied on transfer |
| 608 | `cap_xfer_fcntls_limit(fd, fcntlrights)` | CAPENABLED | cap_xfer_rights_limit(2) | Sets the fcntl ceiling applied on transfer |
| 609 to 629 | reserved | UNIMPL | | |
| 630 | `pdself(fdp, flags)` | CAPREQUIRED | pdself(2) | Returns a process descriptor for the calling process (`PDF_SELF`); only from capability mode |
| 631 | `pdcmp(fd1, fd2, result)` | CAPENABLED | pdcmp(2) | Tells whether two process descriptors name the same process |
| 632 | reserved | UNIMPL | | |
| 633 | `pdincapmode(fd)` | CAPENABLED | pdincapmode(2) | Reports whether the process behind a descriptor is in capability mode |
| 634 | `cap_mmap_capmode(fd)` | CAPENABLED | cap_mmap_capmode(2) | Marks a descriptor so that mmap on it requires capability mode; one-way |
| 635 | `cap_lookup_capmode(fd)` | CAPENABLED | cap_lookup_capmode(2) | Marks a directory descriptor so that `*at()` lookups through it require capability mode; one-way |
| 636 | `squeue_setup(entries, params)` | CAPENABLED | squeue(2) | Creates a completion ring |
| 637 | `squeue_enter(fd, to_submit, min_complete, flags, arg, argsz)` | CAPENABLED | squeue(2) | Submits entries and waits for completions |
| 638 | `squeue_register(fd, op, arg, nr_args)` | CAPENABLED | squeue(2) | Registers files, buffers, an eventfd or restrictions with a ring |
| dynamic | `mac_capability_channel_create(int fds[2])` | CAPENABLED | none | A `SYSCALL_MODULE` in `sys/dev/mac_capability/mac_capability_channel.c`; returns a self-owned channel pair; `lib/libchannel/channel_syscall.c` finds the number with `modfind("sys/mac_capability_channel_create")` |

Numbers 603 to 608 and 630 to 635 belong to the capability core; 636 to 638
belong to the squeue engine in `sys/kern/sys_squeue.c`. The libc stubs are
exported at `FBSD_1.9`.

### Upstream calls flipped to CAPENABLED

These existed before and were forbidden in capability mode. 5BSD marks them
`CAPENABLED` so that a daemon born in capability mode can make them; the
mac_capability system service then decides, from a held claim, whether the
call succeeds. See [System Gates](../capability/system-gates.md).

| Number | Name | Gate that decides |
|---|---|---|
| 55 | `reboot` | `SYS_GATE_REBOOT` |
| 304 | `kldload` | `SYS_GATE_KLDLOAD` |
| 305 | `kldunload` | `SYS_GATE_KLDUNLOAD` |
| 306 | `kldfind` | none (enumeration is open) |
| 307 | `kldnext` | none |
| 308 | `kldstat` | none (the `KLDSTAT` gate was retired) |
| 309 | `kldfirstmod` | none |
| 444 | `kldunloadf` | `SYS_GATE_KLDUNLOAD` |
| 445 | `audit` | `SYS_GATE_AUDIT` |
| 597 | `jail_attach_jd` | `SYS_GATE_JAIL` with `CAP_JAIL_ATTACH` on the descriptor |
| 598 | `jail_remove_jd` | `SYS_GATE_JAIL` with `CAP_JAIL_REMOVE` on the descriptor |

Separately, `bind` and `connect` on INET sockets now work from capability
mode through `bindat` and `connectat` with a real descriptor, because
`sobindat()` and `soconnectat()` fall back to the protocol's plain bind and
connect when it has no `*at` form (`sys/kern/uipc_socket.c`).

## New sysctl nodes and knobs

Flags: RD is read-only, RW is writable at run time, RDTUN is settable only
from `loader.conf`, RWTUN is both. Counters are 64-bit and read-only.
Per-device `dev.*` statistics added by the VirtIO drivers are summarised at
the end rather than listed one by one.

### kern.

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `kern.mac_capability.services` | counter | | Registered kernel services | `sys/dev/mac_capability/mac_capability_core.c` |
| `kern.mac_capability.instances` | counter | | Active service instances | same |
| `kern.mac_capability.service_names` | string RD | | Newline-separated registered service names | same |
| `kern.mac_capability.service_details` | string RD | | Services with flags, limits and instance counts | same |
| `kern.mac_capability_capprotect.max_auth` | uint RDTUN | 4096 | Cap on outstanding capprotect authorizations (0 = unlimited) | `mac_capability_capprotect.c` |
| `kern.mac_capability_capprotect.auth_count` | uint RD | | Current authorizations | same |
| `kern.mac_capability_coalition.count` | uint RD | | Active coalitions | `mac_capability_coalition.c` |
| `kern.mac_capability_coalition.max` | uint RW | 1024 | Maximum coalitions (0 = unlimited) | same |
| `kern.mac_capability_coalition.max_members` | uint RW | 8192 | Maximum members across all coalitions (0 = unlimited) | same |
| `kern.mac_capability_coalition.members` | uint RD | | Members across all coalitions | same |
| `kern.mac_capability_isolation.max_auth` | uint RDTUN | 4096 | Cap on outstanding isolation tokens (0 = unlimited) | `mac_capability_isolation.c` |
| `kern.mac_capability_isolation.auth_count` | uint RD | | Current tokens | same |
| `kern.mac_capability_isolation.enforce` | int RDTUN | 1 | 0 traces resource-access denials instead of enforcing them; ownership denials stay enforced | same |
| `kern.mac_capability_system.max_auth` | uint RW | 4096 | Cap on outstanding gate authorizations across all nonces (0 = unlimited) | `mac_capability_system.c` |
| `kern.mac_capability_system.auth_count` | uint RD | | Current gate authorizations | same |
| `kern.elf64.capmode_interp`, `kern.elf32.capmode_interp` | bool RWTUN | 1 | Let a capability-mode exec load the brand's own ELF interpreter | `sys/kern/imgact_elf.c` |
| `kern.envfd.max_objects` | ulong RWTUN | 16384 | System-wide envfd objects (0 = unlimited) | `sys/kern/kern_envfd.c` |
| `kern.envfd.max_bytes` | ulong RWTUN | 64 MiB | System-wide envfd kernel bytes (0 = unlimited) | same |
| `kern.envfd.max_user_objects` | ulong RWTUN | 1024 | Objects per real uid | same |
| `kern.envfd.max_user_bytes` | ulong RWTUN | 16 MiB | Bytes per real uid | same |
| `kern.envfd.max_value_size` | ulong RWTUN | 1 MiB | Largest single value | same |
| `kern.envfd.objects`, `kern.envfd.bytes` | ulong RD | | Current object count and bytes | same |
| `kern.squeue.max_workers` | int RWTUN | 8 | System-wide worker threads, 1 to 256 | `sys/kern/sys_squeue.c` |
| `kern.squeue.workers`, `kern.squeue.idle_workers` | int RD | | Live and idle workers | same |
| `kern.squeue.max_wired_pages` | ulong RW | one eighth of physical pages, set at init | Pages rings may wire | same |
| `kern.squeue.wired_pages` | ulong RD | | Pages wired by rings right now | same |
| `kern.squeue.live_requests` | ulong RD | | Allocated requests including linked successors | same |
| `kern.squeue.issuer_tokens`, `kern.squeue.issuer_refs` | ulong RD | | Live task identities and references held by rings | same |
| `kern.squeue.registered_files` | ulong RD | | File references held by registrations | same |
| `kern.squeue.rings`, `.submitted`, `.completed`, `.overflowed` | counter | | Rings created, entries consumed, completions posted, completions backlogged or dropped on a full CQ | same |
| `kern.vsock.guest_cid` | u64 RD | | This machine's guest CID | `sys/kern/uipc_vsock.c` |
| `kern.vsock.cur_connections` | uint RD | | Connected vsock PCBs | same |
| `kern.vsock.max_connections` | uint RW | 16384 | Connected PCBs allowed | same |
| `kern.vsock.max_connections_per_cid` | uint RW | 1024 | Connected PCBs per remote CID (0 = unlimited) | same |
| `kern.vsock.buf_default` | uint RW | 256 KiB | Buffer size for new sockets | same |
| `kern.vsock.buf_min`, `kern.vsock.buf_max` | uint RW | 128, 256 KiB | Bounds on the buffer size | same |
| `kern.vsock.seqpacket_frag_max` | uint RW | 256 | SEQPACKET fragments before RST (0 = unlimited) | same |
| `kern.vsock.tx_packets`, `.tx_bytes`, `.tx_drops`, `.rx_packets`, `.rx_bytes`, `.rx_drops`, `.connections` | counter | | Traffic and connection counters | same |
| `kern.vsock.pcblist` | opaque RD | | Active PCBs for sockstat | same |
| `kern.vsock.userspace_providers` | uint RD | | Attached `/dev/vsock` transport providers | `sys/kern/uipc_vsock_user.c` |
| `kern.crypto.cryptokey_max_objects` | uint RW | 16384 | Named volatile keys system-wide | `sys/opencrypto/cryptodev.c` |
| `kern.crypto.cryptokey_max_owner_objects` | uint RW | 1024 | Named keys per owner label | same |
| `kern.crypto.cryptokey_objects` | uint RD | | Current named keys | same |

### security.

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `security.mac.mac_abac.enabled` | int RW | 1 | Module on or off | `sys/security/mac_abac/mac_abac.c` |
| `security.mac.mac_abac.mode` | int RW | 1 | 0 disabled, 1 permissive (log only), 2 enforcing | same |
| `security.mac.mac_abac.default_policy` | int RW | 0 | Verdict when no rule matches: 0 allow, otherwise deny (`EACCES`) | `abac_rules.c` |
| `security.mac.mac_abac.log_level` | int RW | 2 | Logging verbosity (2 = admin actions) | `mac_abac.c` |
| `security.mac.mac_abac.locked` | int RD | 0 | 1 once locked until reboot: no rule or mode changes | same |
| `security.mac.mac_abac.extattr_name` | string RDTUN | `mac_abac` | Name of the system-namespace extended attribute that stores vnode labels | same |
| `security.mac.mac_abac.rule_count` | int RD | | Active rules | `abac_rules.c` |
| `security.mac.mac_abac.checks`, `.allowed`, `.denied` | u64 RD | | Access-check counters | same |
| `security.mac.mac_abac.labels_read`, `.labels_default`, `.labels_allocated`, `.labels_freed`, `.parse_errors` | u64 RD | | Label counters | `mac_abac.c`, `abac_label.c` |
| `security.mac.test_hooks.counter.<hook>`, `security.mac.test_hooks.deny.<hook>` | int RD, int RW | 0 | Per-hook invocation counter and deny toggle; test module `mac_test_hooks.ko` only | `sys/security/mac_test_hooks/mac_test_hooks.c` |
| `security.oes.debug` | int RW | 0 | Debug output | `sys/security/oes/oes_dev.c` |
| `security.oes.default_deadline_ms` | int RW | 30000 | How long an AUTH client may take before its deadline is missed | same |
| `security.oes.default_deadline_miss_mode` | int RW | 0 | 0 fail-open, 1 fail-closed on a missed deadline | same |
| `security.oes.auth_fail_closed` | int RW | 0 | Deny when the AUTH queue is full | same |
| `security.oes.require_auth_clients` | int RW | 0 | Deny AUTH-hooked operations when no client is subscribed | same |
| `security.oes.default_queue_size` | int RW | 1024 | Events per client | same |
| `security.oes.max_clients` | int RW | 64 | Concurrent clients | same |
| `security.oes.cache_max_entries` | int RW | 1024 | Decision cache size | same |
| `security.oes.default_muted_paths`, `.default_muted_paths_literal` | string RW | empty | Path mutes applied to new clients (`oeslogger -n` clears them) | same |
| `security.oes.default_self_mute` | int RW | 1 | New clients do not see their own events | same |

### vfs.

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `vfs.inotify.paths` | uint RD | | Retained open-path identities | `sys/kern/vfs_inotify.c` |
| `vfs.inotify.parents` | uint RD | | Retained parent-directory identities | same |
| `vfs.zfs.trustedzfs.enum_max_entries` | int RDTUN | 16384 | Bound on entries one `ZFD_LIST_*` enumeration may return | `sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c` |

### hw.

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `hw.vmm.vmx.nested` | int RDTUN | 0 | Permit explicitly configured guests to use nested VMX (with `x86.nested_vmx` per VM) | `sys/amd64/vmm/intel/vmx.c` |
| `hw.vmm.vmx.nested_vpid` | int RDTUN | 0 | Expose nested VPID and INVVPID for live qualification; requires `nested` | same |
| `hw.vmm.pvclock.enabled` | int RDTUN | 0 | Advertise and service the KVM paravirtual clock | `sys/amd64/vmm/io/vpvclock.c` |
| `hw.virtio_iommu.enable` | int RDTUN | 0 | Attach to virtio-iommu devices; the driver does not provide busdma translation | `sys/dev/virtio/iommu/virtio_iommu.c` |
| `hw.virtio_mem.allow_plug` | int RDTUN | 0 | Issue PLUG requests toward the requested size; plugged memory is not onlined | `sys/dev/virtio/mem/virtio_mem.c` |

Per-device nodes under `dev.<driver>.<unit>`: `vtblk` gains
`write_zeroes_delete` (RW) and `num_queues`; `vtscsi` gains `num_queues`;
`vtballoon` gains `poisoned` and `free_page_hint_reported`; `vtiommu` gains
`attach_reqs`, `detach_reqs`, `map_reqs`, `unmap_reqs`, `probe_reqs` and
`faults`; `vtmem` gains `block_size`, `region_size`, `usable_region_size`,
`requested_size`, `plugged_size` and `plugged_blocks`; `vtrtc` gains
`alarm_time_ns` (RW), `alarm_count` and `alarm_observed_time_ns`; `vtnet`
receive statistics gain `hash` and `hash_invalid`; `vtfs` reports its
`tag`.

### net.

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `net.bluetooth.iso.rtx_timeout` | int RW | 60 | ISO retransmission timeout in seconds | `sys/netgraph/bluetooth/common/ng_bluetooth.c` |
| `net.bluetooth.iso.sockets.seq.debug_level` | uint RW | warn | Debug level of SEQPACKET ISO sockets | `sys/netgraph/bluetooth/socket/ng_btsocket_iso.c` |
| `net.bluetooth.iso.sockets.seq.queue_len`, `.queue_maxlen`, `.queue_drops` | uint RD | | Input queue state | same |

### Other prefixes

| Name | Type | Default | Purpose | File |
|---|---|---|---|---|
| `compat.linux.aio.max_wired_pages` | ulong RWTUN | 65536 | Pages Linux legacy AIO rings may wire | `sys/compat/linux/linux_aio.c` |
| `compat.linux.aio.wired_pages` | ulong RD | | Pages wired right now | same |
| `vm.stats.swap.discard_once`, `.discard_pages`, `.discard_errors` | counter | | Swap discard activity (Linux `swapon` discard policies) | `sys/vm/swap_pager.c` |

## New MAC policy entry points

`sys/security/mac/mac_policy.h` gains 65 members of `struct
mac_policy_ops`; three of them (`mpo_mount_check_mount`, `_update`,
`_unmount`) replace 5BSD's early mount hooks with upstream's richer
signatures, so 62 are net new. Each has a matching `mac_*()` entry in
`mac_framework.h` and a call site listed in `docs/macf-new-hooks.md`.
`mac_stub` and `mac_test` implement all of them; `mac_test_hooks.ko`
counts and can deny them. See [Policy Points](../capability/policy-points.md).

| Group | Count | Hooks |
|---|---|---|
| vnode change notification | 13 | `vnode_notify_create`, `_open`, `_rename`, `_unlink`, `_link`, `_truncate`, `_setmode`, `_setowner`, `_setflags`, `_setextattr`, `_deleteextattr`, `_setacl`, `_setutimes` |
| process | 9 | `proc_check_core`, `_fork`, `_mmap_anon`, `_mprotect`, `_ktrace`, `_suspend`, `_syscall`; `proc_notify_exec_complete`, `_exit` |
| ZFS administration | 8 | `zfs_check_send`, `_receive`, `_dataset_destroy`, `_pool_destroy`, `_pool_export`, `_key_load`, `_key_unload`, `_key_change` |
| virtual machines (vmm) | 7 | `vmm_check_create`, `_destroy`, `_reinit`, `_alloc_memseg`, `_mem_access`, `_memseg_access`, `_passthrough` |
| file descriptors | 6 | `file_check_inherit`, `_receive`, `_dup`, `_ioctl`, `_mmap`; `file_notify_close` |
| mount | 6 | `mount_check_snapshot_create`, `_delete`, `_revert` (new); `mount_check_mount`, `_update`, `_unmount` (re-declared) |
| vnode checks | 4 | `vnode_check_close`, `_truncate`, `_uipc_bind`, `_uipc_connect` |
| vsock providers | 4 | `vsock_provider_init_label`, `_destroy_label`, `_check_attach`, `_check_access` |
| exec relabel | 2 | `vnode_execve_will_relabel`, `vnode_execve_relabel` |
| rctl | 2 | `rctl_check_add_rule`, `_remove_rule` |
| kld | 1 | `kld_check_unload` |
| sockets | 1 | `socket_check_setsockopt` |
| system | 1 | `system_check_kas_info` |
| pseudo-terminals | 1 | `pts_check_open` |

The framework itself also gains FPFLAG fast paths on seven hot hooks, a
per-policy `mac_framework:::policy-decision` DTrace probe, and
`MAC_MAX_SLOTS` raised from 4 to 7.

## New constants

### procctl(2)

No new `PROC_*` commands. `sys/sys/procctl.h` is unchanged;
`sys/kern/kern_procctl.c` gains a `procctl` SDT provider (`cmd`, `deny`,
and one probe per command). Process control from the plane goes through
the node service described in mac_capability_node(4) instead.

### Capsicum rights and descriptor states

`sys/sys/capsicum.h`:

| Constant | Meaning |
|---|---|
| `CAP_JAIL_ATTACH`, `CAP_JAIL_REMOVE`, `CAP_JAIL_SET` | Rights on a jail descriptor for `jail_attach_jd`, `jail_remove_jd`, `jail_set` |
| `CAP_TIMERFD_GETTIME`, `CAP_TIMERFD_SETTIME` | Rights on a timerfd |
| `CAP_FCNTL_READAHEAD` | Right to `F_READAHEAD` |
| `CAP_POSIX_FADVISE` | Right to `posix_fadvise` |
| `CAP_XFER_UNLIMITED`, `CAP_XFER_ONCE`, `CAP_XFER_NONE` | States for `cap_xfer_limit(2)` |
| `CAP_CLOEXEC_UNLOCKED`, `CAP_CLOEXEC_LOCKED`, `CAP_CLOEXEC_ONCE` | States for `cap_cloexec_limit(2)` |
| `CAP_CLOFORK_UNLOCKED`, `CAP_CLOFORK_LOCKED`, `CAP_CLOFORK_ONCE` | States for `cap_clofork_limit(2)` |

`CAP_ALL1` widens to cover the new bits. `sys/sys/filedesc.h` adds the
per-descriptor flags `UF_MMAP_CAPMODE` and `UF_LOOKUP_CAPMODE` set by the
two `cap_*_capmode` calls; `<capsicum_helpers.h>` wraps them as
`caph_mmap_capmode()` and `caph_lookup_capmode()`. `sys/sys/sysent.h`
adds `SYF_CAPREQUIRED`; `sys/sys/procdesc.h` adds `PDF_SELF`.

### kqueue(2)

`sys/sys/event.h`:

| Constant | Meaning |
|---|---|
| `EVFILT_ENVFD` (-16) | Readiness on an envfd; notes `NOTE_ENVFD_WRITE`, `NOTE_ENVFD_SEALED` |
| `EVFILT_CRYPTODESC` (-17) | Events on a crypto descriptor; notes `NOTE_CRYPTODESC_RIGHTS`, `_REVOKE`, `_EXPIRE`, `_KEY_ROTATE`, `_KEY_DELETE` |
| `NOTE_CAPMODE`, `NOTE_JAILED`, `NOTE_SETUID`, `NOTE_CHROOT` | `EVFILT_PROCDESC` lifecycle notes (`NOTE_PCTRLMASK` widened to `0xff000000`) |

### Descriptor types

`sys/sys/file.h`: `DTYPE_MAC_CAPABILITY` (17), `DTYPE_ENVFD` (18),
`DTYPE_ZFSHANDLE` (19), `DTYPE_LINUXPIDFD` (20), `DTYPE_LINUXSIGNALFD`
(21), `DTYPE_SQUEUE_POLL` (22, internal), `DTYPE_LINUXPERF` (23),
`DTYPE_IORING` (26). libprocstat, fstat and sysdecode know all of them.

### Sockets

| Header | Constant | Meaning |
|---|---|---|
| `sys/sys/un.h` | `LOCAL_CAP_CONNECT` (4) | Require the peer to be in capability mode to connect and to send descriptors |
| | `LOCAL_CAPMODE_SERVER` (6) | Require the server to be in capability mode |
| | `LOCAL_CAP_REQ` (7) | Require capability mode to use this end |
| | `SUN_ABSTRACT_MAXLEN` (110) | Linux abstract-namespace name length |
| `sys/sys/socket.h` | `AF_VSOCK`, `PF_VSOCK` (46) | The vsock domain; `AF_IPFWLOG` and `AF_MAX` move to 48 |
| | `SOCKCRED2_VERSION` (1) | `sockcred2` now carries `sc_capmode` |

### Files, processes and tracing

| Header | Constant | Meaning |
|---|---|---|
| `sys/sys/fcntl.h` | `F_OFD_GETLK` (25), `F_OFD_SETLK` (26), `F_OFD_SETLKW` (27) | Open-file-description locks |
| | `F_SEAL_FUTURE_WRITE` | No new shared writable mappings on a sealed memfd |
| `sys/sys/wait.h` | `WLINUXALL` | Wait for both kinds of children (Linux `__WALL`) |
| `sys/sys/ptrace.h` | `PTRACE_EXIT` | Stop before process teardown; `PT_KERN_*` are kernel-internal Linux ptrace requests |

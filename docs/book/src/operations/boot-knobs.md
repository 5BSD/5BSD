# Boot Knobs

A 5BSD system is configured at boot by the same three files as FreeBSD:
`/boot/loader.conf` (loader variables and kernel tunables, read before the
kernel runs), `/etc/rc.conf` (rc(8) variables), and `sysctl.conf(5)` for
runtime sysctls. 5BSD changes a small number of defaults in each and adds
tunables for the subsystems it introduces. Because the capability plane and
the security policies are compiled into GENERIC, most of what a FreeBSD
administrator would expect to see as `*_load="YES"` lines is absent on
purpose. This chapter is the complete list: what 5BSD adds or changes, its
default, what it does, and when to touch it. Anything not listed here is
unchanged from FreeBSD and documented in loader.conf(5), rc.conf(5) and the
subsystem's man page.

## Loader variables

Defaults come from `stand/defaults/loader.conf`, installed as
`/boot/defaults/loader.conf`. Override them in `/boot/loader.conf`, or once
at the loader prompt with `set name="value"`.

| Knob | Default | What it does | When to change it |
|---|---|---|---|
| `init_path` | `/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init` | Candidate list for PID 1; the kernel execs the first that works (`kern.init_path` shows it). Capsule first, stock init as fallback. | Never for a normal system. To boot without the plane use `capability_plane`, not this: the memory of a failed capsule exec is not a plane-off boot, and capsule refuses to leave PID 1 dead. |
| `capability_plane` | unset | `NO`, `off` or `0`: capsule reads the kenv at start, logs `capability_plane=NO: handing PID 1 to /sbin/init (plane-free boot)` and execs stock init, forwarding `-s`. The plane never starts; the kernel code is still present. | Recovery; running the kernel capability test suites; the installer media sets it. |
| `zfs_load` | `YES` | Loads `zfs.ko` early on every boot so `/dev/zfs` exists for the PID 1 capability chain before rc runs, even when the root is UFS. | Never; the storage plane assumes it. |
| `linux_common_load`, `linux64_load` | `YES` | 64-bit Linux emulation at boot. There is no `linux_load` (32-bit) line and no 32-bit module. | Set `NO` to disable Linux binaries. |
| `hwt_load` | `YES` | Hardware-trace framework hwt(4). The Intel PT backend pt(4) is not preloaded; bsdtrace(8) needs `kldload pt` (or `pt_load="YES"`). | Set `NO` on machines that will never trace. |
| `splash`, `shutdown_splash` | `/boot/images/5bsd-logo.png` | Boot and shutdown logo. | Cosmetic. |
| `loader_brand` | `5bsd` (`5bsd-install` on media) | Loader menu branding (`stand/lua`). | Cosmetic. |
| `kern.elf64.capmode_interp` | `1` | Lets a process in capability mode exec a dynamically linked binary by loading the brand's own ELF interpreter (`/libexec/ld-elf.so.1`); any other `PT_INTERP` still fails with `ECAPMODE`. Switchboard relies on it to `fexecve` units directly so they carry their own names in ps(1). | Set `0` only to reproduce the old behaviour; units will then fail to launch. Runtime-writable (`RWTUN`). |
| `kern.mac_capability_isolation.enforce` | `1` | Enforce isolation denials on the `system` gates. `0` is permissive test mode: denials are traced but allowed; ownership checks stay enforced. Boot-only (`RDTUN`). | Test images only. Never on a production system. |
| `kern.mac_capability_isolation.max_auth` | `0` (unlimited) | Cap on total isolation authorization entries; `auth_count` is the live count. Boot-only. | Stress testing. |
| `security.mac.mac_abac.extattr_name` | `mac_abac` | Extended-attribute name mac_abac reads labels from. Boot-only. | Only with a matching change to the labelling tools. |
| `hw.vmm.vmx.nested` | `0` | Permit explicitly configured guests to use nested VMX. `hw.vmm.vmx.nested_vpid` additionally exposes nested VPID/INVVPID for live qualification. Boot-only. | Hosting a hypervisor inside a bhyve guest. |
| `hw.virtio_mem.allow_plug` | `0` | virtio-mem driver: issue PLUG requests toward `requested_size`. Plugged memory is not onlined (FreeBSD has no runtime memory add), so plugging only consumes host backing. Boot-only. | Exercising the full PLUG/UNPLUG contract in device tests. |
| `hw.virtio_iommu.enable` | `0` | Attach the virtio-iommu driver. Boot-only. | Guests that need the device model. |
| `kern.squeue.max_workers` | see sysctl | System-wide worker cap (1 to 256) for the squeue completion-ring engine. `RWTUN`. | io_uring-heavy Linux workloads. |

Two notes on what is missing. First, there are no `mac_capability*_load`
lines: every plane component is `standard` in `sys/conf/files`, the only
loadable `mac_capability_*` modules are test fixtures, and preloading one
at boot is wrong. Second, `oes`, `mac_abac`, `mac_veriexec`, `cryptodev` and
`vsock` are likewise compiled in; do not add `_load` lines for them. A
`kldload` of a module the kernel already contains fails with `EEXIST`, which
is the expected answer.

## rc.conf variables

Defaults are in `libexec/rc/rc.conf`, installed as `/etc/defaults/rc.conf`.

| Variable | Default | What it does | When to change it |
|---|---|---|---|
| `zfs_enable` | `YES` | Import pools and mount ZFS filesystems at boot. ZFS is a required 5BSD subsystem; the host may still boot from UFS. | Never. |
| `auditd_enable` | `YES` | Run auditd(8). On by default so the `system.Audit` capability can commit records; audit(4) is compiled in. | Turn off only if you accept that BSDAudit will have no trail to commit to. |
| `linux_enable` | `YES` | Linux binary compatibility at startup (64-bit only). | Off if you disabled the loader modules. |
| `linux_mounts_enable` | `YES` | Mount linprocfs, linsysfs and the rest under `/compat/linux`. | With `linux_enable`. |
| `mac_abacd_enable` | `NO` | Start mac_abacd(8), which loads the rule set from `mac_abacd_config` (default `/etc/mac_abac.conf`) at boot. | When you deploy an ABAC policy; see [mac_abac](../capability/mac-abac.md). |
| `blued_enable` | `NO` | Start the BSDBluetooth host daemon (`rc.d/blued`). | Machines with a Bluetooth controller. |
| `meshd_enable` | `NO` | Start the Bluetooth Mesh daemon. | Mesh deployments. |
| `hostname`, `hostid_enable` | as upstream | The installer media sets `hostname="5bsd-installer"` and `hostid_enable="NO"`; an installed system gets what you typed. | Normal. |

There is no `switchboard_enable` and no `capsule_enable`: the plane is not an
rc service. rc runs as a unit under switchboard, in parallel with the native
boot units; see [rc and service(8)](../compat/rc-and-service.md) for how
`service(8)` and rc.conf variables coexist with the plane. Nothing in
rc.conf can stop switchboard, and the way to keep a bundle from launching is
`switchboardctl disable <bundle>`.

## Runtime sysctls

These are settable while the system runs (and persist through
`/etc/sysctl.conf`). Read-only counters are listed where an operator would
watch them.

### The plane

| Sysctl | Default | Meaning |
|---|---|---|
| `kern.init_path` | as loader | Read-only copy of the PID 1 candidate list. |
| `kern.mac_capability_isolation.auth_count` | live | Number of isolation authorizations held; useful when a gate consumer fails to claim (a stale-module symptom, see [Troubleshooting](troubleshooting.md)). |

### OpenEndpointSecurity (`security.oes.*`)

| Sysctl | Default | Meaning |
|---|---|---|
| `debug` | `0` | Debug output from oes(4). |
| `default_deadline_ms` | `30000` | How long an AUTH event waits for a client verdict. |
| `default_deadline_miss_mode` | `0` | What a missed deadline means: `0` fail open, `1` fail closed. |
| `auth_fail_closed` | `0` | Deny AUTH operations when OES cannot allocate or deliver the state it needs. |
| `require_auth_clients` | `0` | Deny AUTH operations when no AUTH client is consulted. |
| `default_queue_size` | `1024` | Events per client queue. |
| `max_clients` | `64` | Concurrent clients on `/dev/oes`. |
| `cache_max_entries` | `1024` | Decision-cache entries per client. |
| `default_muted_paths` | empty | Colon-separated prefixes muted for new clients. |
| `default_muted_paths_literal` | empty | Same, literal match. |
| `default_self_mute` | `1` | New clients do not see their own events. |

A hardened deployment sets `default_deadline_miss_mode=1`,
`auth_fail_closed=1` and `require_auth_clients=1` together, and only once an
AUTH client is guaranteed to be running; with `require_auth_clients=1` and
no client, every AUTH-gated operation is denied. See
[Endpoint Security](../capability/oes.md).

### mac_abac (`security.mac.mac_abac.*`)

| Sysctl | Default | Meaning |
|---|---|---|
| `enabled` | `0` | Policy on or off. |
| `mode` | `0` | `0` disabled, `1` permissive (log only), `2` enforcing. |
| `default_policy` | `0` | When no rule matches: `0` allow, `1` deny. |
| `log_level` | `2` | `0` none, `1` error, `2` admin, `3` deny, `4` all. |
| `locked` | `0` | Read-only; `1` means the policy is locked until reboot and `mode`, `default_policy` and rule changes return `EPERM`. |
| `rule_count`, `denied`, `labels_read`, `labels_default` | live | Counters. |

mac_abac_ctl(8) is the supported way to change these (`mac_abac_ctl mode
enforcing`, `mac_abac_ctl default deny`); it also loads and validates rule
sets. See [mac_abac](../capability/mac-abac.md).

### squeue (`kern.squeue.*`)

The native completion-ring engine behind Linux io_uring
([io_uring and squeue](../compat/linux/io-uring.md)).

| Sysctl | Default | Meaning |
|---|---|---|
| `max_wired_pages` | one eighth of physical pages | Maximum physical pages all rings together may wire; `wired_pages` is the live count. Raise for large-ring workloads. |
| `max_workers` | see sysctl | 1 to 256 system-wide workers; `workers` and `idle_workers` are live counts. |
| `live_requests`, `registered_files`, `issuer_tokens`, `issuer_refs` | live | Object counts, for leak hunting. |
| `rings`, `submitted`, `completed`, `overflowed` | live | Per-boot counters; a rising `overflowed` means a consumer is not draining its completion ring. |

### Linux emulation (`compat.linux.*`)

Upstream knobs, unchanged, but two matter for 5BSD troubleshooting:
`compat.linux.debug` (default `3`) controls the `linux: jid N pid N (name):
...` warnings the emulator prints for unimplemented or untested calls, and
`compat.linux.osrelease` is what Linux binaries see as the kernel version.
See [Linux Emulation](../compat/linux/overview.md).

## Where the rest of boot policy lives

Several things a FreeBSD administrator would look for in these files are
elsewhere on 5BSD, by design:

| Question | Answer |
|---|---|
| Which units start at boot? | Each unit's manifest (`activation { boot = true; }`); `switchboardctl enable/disable` per bundle. See [Bundles and Manifests](../plane/bundles-and-manifests.md). |
| Who is an administrator of the plane? | `/Capabilities/Config/principal-policy.ucl`, written by the installer. |
| Which pool holds capability storage? | `pool =` in `/Capabilities/Config/bsdfilesystem.ucl`. |
| Who may trace without root? | `Config/bsdtrace.allow` in the Trace bundle; see [Observability](observability.md). |
| What does a capmode unit get to open? | Its manifest's `directories` and `capabilities` keys; nothing from rc.conf. |
| Is veriexec enforcing? | Only after a manifest is loaded and enforcement entered; the option is compiled in but inactive by default. See [Verified Execution](../capability/veriexec.md). |

## Status

All knobs above exist at HEAD and were checked against the source that
defines them. The `pt_load` line is not in the shipped defaults; bsdtrace(8)
requires both `hwt` and `pt` loaded (`kldload pt` before tracing, or add
`pt_load="YES"`). `kern.squeue.max_workers` and
`max_wired_pages` defaults are computed at boot; read them with sysctl(8)
rather than trusting a number written here.

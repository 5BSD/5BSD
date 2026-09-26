# Manual Page Index

Every manual page 5BSD adds relative to the FreeBSD baseline `bc301fee4cb`,
grouped by section and then by subsystem. The description column is the
page's own `.Nd` line. The package column is the pkgbase package the page
ships in, without the `5BSD-` prefix (`switchboard` means the package
`5BSD-switchboard`); `clibs` and `kernel-man` are the packages the system
call and kernel-interface pages fall into by default. Where a page was
renamed during the fork, the names it carried before are listed so that a
search for an old name lands here.

Read the page with `man name` on an installed system, or from the tree with
`man -l path`.

## Section 1: commands

| Page | Description | Package | Source |
|---|---|---|---|
| anoint(1) | run a command holding one additional anointment | runtime | `usr.bin/anoint/anoint.1` |

## Section 2: system calls

All of these are in `lib/libsys` and ship in `clibs`. The
`mac_capability_channel_create(2)` syscall (a `SYSCALL_MODULE` whose number
is assigned at load) has no page of its own; the wrapper is
`lib/libchannel/channel_syscall.c` and
`docs/book/src/plane/discovery-and-lookup.md` describes it.

| Page | Description | Also documents |
|---|---|---|
| cap_cloexec_limit(2) | lock close-on-exec for a file descriptor | |
| cap_clofork_limit(2) | lock close-on-fork for a file descriptor | |
| cap_lookup_capmode(2) | require capability mode for directory fd lookups | |
| cap_mmap_capmode(2) | require capability mode for mmap on a descriptor | |
| cap_xfer_limit(2) | limit descriptor transfer state | |
| cap_xfer_rights_limit(2) | attenuate descriptor rights during transfer | cap_xfer_ioctls_limit(2), cap_xfer_fcntls_limit(2) |
| envfd(2) | create a named, descriptor-backed environment value | envfd_create(2) |
| pdcmp(2) | compare two process descriptors | |
| pdincapmode(2) | query whether a process descriptor's process is in capability mode | |
| pdself(2) | create a process descriptor for the calling process | |
| squeue(2) | shared-queue asynchronous I/O | squeue_setup(2), squeue_enter(2), squeue_register(2) |

## Section 3: libraries

### Kernel-facing capability libraries

| Page | Description | Package | Renamed from |
|---|---|---|---|
| libcapability(3) | invoke synchronous kernel capability services | libcapability | |
| libchannel(3) | asynchronous userspace capability-channel messaging | libchannel | |
| libcapsulert(3) | shared claim types, UCL claim parsers, and capability-plane wire protocols | libcapsulert | |
| libshmring(3) | capability-safe shared-memory transport rings | libshmring | |

### Plane runtime libraries

| Page | Description | Package | Renamed from |
|---|---|---|---|
| libservice(3) | switchboard discovery, provider lifecycle, and on-demand capability access | libservice | |
| libcapbundle(3) | parse and validate capability bundles | libcapbundle | libappbundle.3 |
| capreclaim(3) | reconcile a provider's per-bundle resources against the live set | libcapreclaim | |

### Provider client libraries

| Page | Description | Package | Renamed from |
|---|---|---|---|
| libauditcmp(3) | authenticated BSM audit broker client | libauditcmp | |
| libbsdfilesystem(3) | client interface to the bsdfilesystem storage daemon | runtime | libtzfsd.3 |
| libcryptocmp(3) | public client for the system crypto broker | libcryptocmp | |
| libcryptodesc(3) | mint and manage kernel crypto session descriptors | libcryptodesc | |
| libdevicecmp(3) | public client for the system device broker | libdevicecmp | |
| liblogcmp(3) | structured privacy-aware logging client | liblogcmp | |
| libnetworkcmp(3) | public client for the system network broker | libnetworkcmp | |
| libnotify(3) | bounded capability-component notifications | libnotify | libnotifycmp.3 |
| libpowercmp(3) | client for the system.Power capability | libpowercmp | |
| libsysctlcmp(3) | client interface to the system.Sysctl capability | libsysctlcmp | |
| libtimecmp(3) | client for the system.Time capability | libtimecmp | |
| libtracecmp(3) | explicitly authorized DTrace descriptor delegation | libtracecmp | |
| trustedzfs(3) | capability file descriptors over the ZFS management plane | runtime | |

`trustedzfs(3)` carries MLINKs for every `tzfs_*` function, from
`tzfs_open(3)` to `tzfs_limit_pool_ioctls_by_rights(3)`.

### Bluetooth

| Page | Description | Package |
|---|---|---|
| libble(3) | BLE client library for the blued daemon | bluetooth |
| libblemesh(3) | Bluetooth BLE-mesh protocol library | bluetooth |

### Security and observability

| Page | Description | Package |
|---|---|---|
| liboes(3) | userspace library for Endpoint Security Capabilities | oes |
| libotelexport(3) | shared telemetry exporter layer for the ObservableBSD tools | untagged (default package) |
| dtrace_fdopen(3) | create a DTrace handle from a delegated consumer descriptor | dtrace |
| squeue(3) | ergonomic interface to the squeue completion-ring engine | clibs |

## Section 4: kernel interfaces

### The capability framework

All ten pages ship in `kernel-man`. They were renamed twice during the
fork: first from `cmi*.4` to `cap_rt*.4`, then from `cap_rt*.4` to
`mac_capability*.4`; `mac_capability_channel.4` was `cap_rt_pair.4` before
that.

| Page | Description |
|---|---|
| mac_capability(4) | Capability Message Interface |
| mac_capability_accounting(4) | MAC_CAPABILITY per-process resource accounting and enforcement |
| mac_capability_capprotect(4) | MAC_CAPABILITY capability protection service |
| mac_capability_channel(4) | MAC_CAPABILITY bidirectional capability channel |
| mac_capability_coalition(4) | capability-based resource group management |
| mac_capability_identity(4) | MAC_CAPABILITY program identity queries |
| mac_capability_isolation(4) | MAC_CAPABILITY resource isolation service |
| mac_capability_mount(4) | MAC_CAPABILITY capability-based filesystem mounting |
| mac_capability_node(4) | MAC_CAPABILITY per-process inspection and control service |
| mac_capability_system(4) | MAC_CAPABILITY system operation gating |

### Security policies

| Page | Description | Package |
|---|---|---|
| mac_abac(4) | flexible label-based Mandatory Access Control policy | mac-abac |
| oes(4) | OpenEndpointSecurity event monitoring and authorization framework | kernel-man |

### Virtualization and devices

| Page | Description | Package | Also documents |
|---|---|---|---|
| vsock(4) | virtio socket communication | kernel-man | |
| virtio_fs(4) | VirtIO file system driver | kernel-man | vtfs(4) |
| virtio_iommu(4) | VirtIO IOMMU driver | kernel-man | vtiommu(4) |
| virtio_mem(4) | VirtIO memory device driver | kernel-man | |
| virtio_pmem(4) | VirtIO persistent memory driver | kernel-man | |
| virtio_snd(4) | VirtIO sound driver | kernel-man | |
| ng_hci_virt(4) | virtual HCI controller netgraph node type | kernel-man | |

## Section 5: file formats

| Page | Description | Package | Renamed from |
|---|---|---|---|
| capsule.conf(5) | configuration file for Capsule | capsule | authorityd.conf.5, oracled.conf.5 |
| switchboard(5) | capability bundle and unit manifest format | switchboard | serviced.5 |
| tzfs.conf(5) | configuration file for the bsdfilesystem storage daemon | runtime | moved from `usr.sbin/tzfsd` |
| mac_abac.conf(5) | ABAC policy configuration file | mac-abac | |

## Section 7: overviews

| Page | Description | Package |
|---|---|---|
| component(7) | capability service model for programs managed by switchboard | untagged (default package) |

## Section 8: system programs

### The plane

| Page | Description | Package | Renamed from |
|---|---|---|---|
| capsule(8) | capability-plane root supervisor | capsule | authorityd.8, oracled.8 |
| capsulectl(8) | capability-native control for Capsule | capsulectl | authorityctl.8, oraclectl.8 |
| switchboard(8) | 5BSD capability-based service manager | switchboard | serviced.8 |
| switchboardctl(8) | control and inspect switchboard | switchboardctl | servicectl.8 |
| reclaimstat(8) | show what each capability provider is managing | runtime | |

### Providers

The daemons that live in `runtime` have no package of their own.

| Page | Description | Package | Renamed from |
|---|---|---|---|
| BSDAudit(8) | authenticated BSM audit broker | bsdaudit | auditbrokerd.8 |
| BSDAuth(8) | session-mint boundary broker and elevation authenticator | bsdauth | authagentd.8 |
| BSDBluetooth(8) | general-purpose Bluetooth Low Energy daemon | bluetooth | blued.8 (kept as an MLINK) |
| BSDCrypto(8) | capability-descriptor cryptography broker | bsdcrypto | localcrypto.8 |
| BSDDevice(8) | capability-plane device-node broker | bsddevice | localdevice.8 |
| BSDExtension(8) | system-extension (kernel module) broker | runtime | sysextd.8 |
| BSDFilesystem(8) | [TZFS] storage daemon | runtime | tzfsd.8 |
| BSDLog(8) | capability-mode structured logging component | bsdlog | logd.8 |
| BSDNamespace(8) | namespace (jail) broker | runtime | warden.8 |
| BSDNetwork(8) | capability-mode kernel NetworkCmp provider | bsdnetwork | localnetwork.8, networkcmp.8 |
| BSDNotify(8) | capability-mode publish, subscribe, and timer service | bsdnotify | bsdnotify.8 |
| BSDPower(8) | system.Power capability provider | runtime | |
| BSDSysctl(8) | system.Sysctl capability provider | runtime | localsysctl.8 |
| BSDTime(8) | system.Time capability provider | runtime | |
| BSDTrace(8) | administrator-authorized DTrace descriptor service | bsdtrace-provider | traced.8 |
| BSDVM(8) | virtual-machine component | runtime | waspnest.8, vmd.8 |

### Operator tools for providers

| Page | Description | Package |
|---|---|---|
| BSDPowerctl(8) | operator CLI for the system.Power capability | runtime |
| BSDTimectl(8) | operator CLI for the system.Time capability | runtime |
| logctl(8) | validate and operate the LogCmp service | bsdlog |
| networkcmpctl(8) | inspect an injected NetworkCmp component | bsdnetwork |
| notifyctl(8) | validate and operate the Notify service | bsdnotify |
| sysctlcmpctl(8) | command-line client for the system.Sysctl capability | runtime |
| sysextctl(8) | request kernel extensions through SystemExtension | sysextctl |
| tracectl(8) | validate TraceCmp authorization policy | bsdtrace-provider |
| tzfsctl(8) | inspect and exercise the bsdfilesystem storage daemon | runtime |

### Bluetooth

| Page | Description | Package |
|---|---|---|
| bluedctl(8) | control utility for the blued Bluetooth Low Energy daemon | bluetooth |
| meshd(8) | Bluetooth Mesh node daemon | bluetooth |
| meshctl(8) | control the meshd Bluetooth Mesh daemon | bluetooth |
| vhcitool(8) | userspace virtual Bluetooth HCI controller | bluetooth |

### Security policies

| Page | Description | Package |
|---|---|---|
| mac_abac_ctl(8) | control utility for the ABAC MAC policy module | mac-abac |
| mac_abacd(8) | load and maintain MAC ABAC policy rules | mac-abac |
| oeslogger(8) | log OpenEndpointSecurity events as JSON | oes |

### Observability

| Page | Description | Package |
|---|---|---|
| bsdinstruments(8) | DTrace-backed profiling templates with OpenTelemetry output | bsdinstruments |
| bsdtrace(8) | hardware-assisted execution tracing using Intel Processor Trace | bsdtrace |
| hwtlm(8) | hardware telemetry with OpenTelemetry output | hwtlm |

### Virtualization

| Page | Description | Package |
|---|---|---|
| virtiofsd(8) | capability-confined non-DAX virtio-fs backend for bhyve | bhyve |
| mount_virtiofs(8) | mount a virtio-fs shared directory | runtime |

## Upstream pages 5BSD changed

These pages existed at the baseline and carry 5BSD additions. The note
says what changed where the divergence inventory records it.

| Page | What 5BSD added |
|---|---|
| cap_rights_limit(2) | `CAP_JAIL_*`, `CAP_TIMERFD_*`, `CAP_FCNTL_READAHEAD`, `CAP_POSIX_FADVISE` |
| fcntl(2) | `F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW` and `F_SEAL_FUTURE_WRITE` semantics |
| inotify(2) | deferred `IN_DELETE_SELF`, `IN_IGNORED` on every removal, rename cookies, open-path identity, `vfs.inotify.*` |
| kqueue(2) | `EVFILT_ENVFD`, procdesc notes `NOTE_CAPMODE`, `NOTE_JAILED`, `NOTE_SETUID`, `NOTE_CHROOT` |
| pdfork(2) | `pdself`, `pdcmp`, `pdincapmode`; pdkill and pdwait without ambient credential checks |
| ptrace(2) | `PTRACE_EXIT` |
| socketpair(2), unix(4) | `LOCAL_CAP_CONNECT`, `LOCAL_CAPMODE_SERVER`, `LOCAL_CAP_REQ`, `SO_PEERCAPMODE`, transfer attenuation |
| aio(4) | daemon-run requests present the submitter's pid to fusefs |
| capsicum(4), rights(4), procdesc(4) | the new rights, descriptor states and process-descriptor extensions |
| fdescfs(4) | `/dev/fd/N/child` traversal |
| linux(4) | the `compat.linux.*` knobs of the 64-bit-only Linuxulator |
| ng_btsocket(4) | the 256-bit HCI event mask |
| virtio_balloon(4), virtio_blk(4), virtio_scsi(4), vmm(4) | modern transport, multiqueue and snapshot notes |
| bhyve(8), bhyve_config(5), bhyvectl(8) | new device models, `transport`, `queues`, `packed`, checkpoint manifests, `migrate fd=`, `-R fd` |
| bsdinstall(8) | ZFS-only guided install, `tzfspool`, `capabilitypolicy`, pkgbase-only media |
| reboot(8) | delegation to capsulectl(8) with the signal fallback |
| veriexec(8) | manifest error reporting and fingerprint validation |
| jail(8) | `recallocarray` config strings and the jail USDT provider |
| src.conf(5) | `WITHOUT_BIND_NOW`, `WITHOUT_BHYVE_SNAPSHOT`, 64-bit-only defaults |
| hier(7), release(7) | `/Capabilities`, `/efi/5bsd`, pkgbase-native media |
| sglist(9), syscall_helper_register(9) | `sglist_append_*_boundary`; `SYF_CAPREQUIRED` |
| fstat(1), procstat(1), sockstat(1), libprocstat(3) | the new descriptor types, `AF_VSOCK`, `sockstat -V`, OFD locks |
| audit_submit(3) | `A_GETKAUDIT` tolerance of `ECAPMODE` |
| loader.efi(8), efibootmgr(8), menu.4th(8), splash(4), nuageinit(7) | 5BSD branding and boot paths |

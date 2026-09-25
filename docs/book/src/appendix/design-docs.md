# Design Document Index

The 125 Markdown documents under `docs/` and `docs/security/` are the
tree's working memory: designs written before code, acceptance contracts,
review ledgers, handoffs and status snapshots. They are not a pile to read
in order. This index groups them by subsystem and gives each one a
one-line summary taken from its own opening paragraph, a status, and the
book chapter that draws on it or replaces it.

Status values:

| Status | Meaning |
|---|---|
| design | Describes how the thing works; the code matches it |
| plan | Says what should be built; check the status line in the document for how much has landed |
| record | Evidence from a review, audit, validation or qualification run; the code has usually moved on |
| ledger | Kept current as the source of truth for counts and dispositions |
| superseded | The document says so itself; read the replacement it names |

Documents marked superseded are kept because later documents cite them.
Paths are relative to `/usr/src`.

## The kernel capability core and the authority model

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/mac_capability-architecture.md` | MAC_CAPABILITY: Capability Message Interface | The capability transport, supervision and policy substrate: design, kernel service guide and userspace guide. | design | [The MAC Capability Framework](../capability/mac-capability.md) |
| `docs/isolation-architecture.md` | Isolation architecture | How one launched program is isolated from another after the manifest `capabilities {}` block was removed and capabilities became on-demand, label-scoped services. | design | [The MAC Capability Framework](../capability/mac-capability.md) |
| `docs/capability-authority-model.md` | Capability-authority model | The architecture spec: authority is a held capability, not uid, path, PID or signal; supersedes the authorization framing of three earlier documents. | design | [The Authority Model](../capability/authority-model.md) |
| `docs/capability-plane-vision.md` | The 5BSD Capability Plane: a comprehensive vision | The north star: the plane sits beside BSD and answers "may I?" by asking what the caller holds. | design | [What 5BSD Is](../orientation/what-5bsd-is.md) |
| `docs/capability-ambient-lookup-per-process.md` | Per-process lookup channels (the Darwin model) | The final design for unsharing the ambient discovery channel: one private lookup channel per process, created with `mac_capability_channel_create(2)`. | design | [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) |
| `docs/capability-sysctl-isolation.md` | Capability sysctl isolation | Per-OID sysctl ownership so the plane controls a configurable subset of the sysctl tree; phases 1 and 2 done and VM-verified. | design | [System Gates](../capability/system-gates.md) |
| `docs/capmode-launch-and-casper-removal-plan.md` | Plan: plane-native launch, lazy capabilities, and moving past libcasper | A launch that hands a unit its library directory and lazily acquired services, retiring libcasper from the daemons; the capability-mode interpreter exec has since landed. | plan | [Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md) |
| `docs/macf-new-hooks.md` | 5BSD MACF Hook Additions: Design Reference | Maps XNU MAC hooks that FreeBSD lacks to the 5BSD equivalents, with call site, lock context and sleep rules for each. | design | [Policy Points](../capability/policy-points.md) |
| `docs/envfd-testing.md` | EnvFD Testing Guide | Build-time validation, installation, automated tests, manual smoke tests, observability and rollback for envfd. | design | [Testing](../develop/testing.md) |
| `docs/capability-fork-inventory.md` | Capability-world fork inventory: modified base and contrib programs | The list of upstream programs (OpenSSH, login, su, cron, shutdown) 5BSD modified so authority is a held lookup capability. | record | [The BSD Side](../compat/bsd-side.md) |

## Capsule, switchboard and the plane runtime

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/freebsd-init-behavior-audit.md` | FreeBSD init(8) Source-Complete Behavior Audit | The complete externally meaningful behavior of stock init, recorded as the compatibility baseline for the capsule PID 1 personality. | record | [Capsule, PID 1](../plane/capsule.md) |
| `docs/capsule-todo.md` | Capsule: Implementation TODO | What capsule must retain from init, replace deliberately, test and document; a working checklist. | plan | [Capsule, PID 1](../plane/capsule.md) |
| `docs/capsule-control-abi-design.md` | Capsule lifecycle control ABI: moving PID 1 off the signal interface | The decision to replace the PID 1 signal ABI with an authenticated control ABI shaped by the two-daemon architecture; its authorization model is superseded by the authority model. | superseded | [Capsule, PID 1](../plane/capsule.md) |
| `docs/lifecycle-capability-design.md` | System lifecycle as a capability: design options | The decided architecture for how a principal asks for reboot, halt, poweroff, reroot or single-user in the object-capability model. | design | [Capsule, PID 1](../plane/capsule.md) |
| `docs/lifecycle-capability-port-design.md` | Lifecycle control: from a getpeereid socket to a capability port | A proposal to move lifecycle control off the uid-authenticated socket; superseded by the authority model. | superseded | [Capsule, PID 1](../plane/capsule.md) |
| `docs/capsule-switchboard-layering-cleanup.md` | Layering cleanup: get leaf-daemon work out of capsule and switchboard | Why PID 1 and the service manager must carry no leaf-daemon code, with an audit ledger of what was removed. | plan | [Switchboard](../plane/switchboard.md) |
| `docs/service-architecture-plan.md` | Demand-driven service management plan | The authoritative pre-v1 plan for a demand-driven service manager with no dependency graph; parts are marked superseded inside. | plan | [Switchboard](../plane/switchboard.md) |
| `docs/service-daemon.md` | Service daemon status | A pointer: the dependency-graph proposal is superseded by the service architecture plan. | superseded | [Switchboard](../plane/switchboard.md) |
| `docs/service-discovery-model.md` | Service discovery and management model | The source of truth for the naming, domain and activation mechanism; its uid-based authorization sections are superseded by the authority model. | design | [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) |
| `docs/service-plane-review-brief.md` | Service plane rework: review brief | The entry point for a reviewer of the demand-driven plane rework: goals, commits, invariants, validation, deferred findings. | record | [Switchboard](../plane/switchboard.md) |
| `docs/service-file-delivery.md` | Service file/directory descriptor delivery | The manifest-declared `capabilities.open` file delivery, removed from the code in favor of isolated opens. | superseded | [system.Filesystem](../providers/filesystem.md) |
| `docs/rc-integration-handbook.md` | Integrating Daemons with FreeBSD rc | How rc.d scripts and service(8) really work and how a protected daemon should integrate with them. | design | [rc and service(8)](../compat/rc-and-service.md) |
| `docs/ipc-anointments-design.md` | IPC anointments (v1) | Named grants that units hold and endpoints require, decided by principal policy, with anoint(1) as the sudo replacement. | design | [Anointments and Principal Policy](../plane/anointments.md) |
| `docs/auth-agent-design.md` | Auth-agent design (P1c): the identity to capability mint boundary | Moving the principal-to-bundle decision out of login, su and sshd into one sandboxed daemon, shipped as BSDAuth. | design | [system.Auth](../providers/auth.md) |
| `docs/capability-container-model.md` | The Capability Container Model | The locked spec for per-bundle storage containers, run markers and reconcile; supersedes the installation-authority ledger. | design | [Containers and Storage](../plane/containers-and-storage.md) |

## Providers, client libraries and fleet ledgers

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/capability-api-expansion.md` | Capability-Plane API Expansion: Design Memo | Proposed operation-set additions across the providers; parts (Filesystem transactions, Network LISTEN) have shipped. | plan | [How to Read a Provider Chapter](../providers/overview.md) |
| `docs/capability-daemon-scorecard.md` | Capability daemon scorecard | Source size, test depth and protection-primitive integration per provider, reconciled against the unit files. | ledger | [How to Read a Provider Chapter](../providers/overview.md) |
| `docs/capability-daemon-test-suite.md` | Capability Daemon Test Suite Architecture | The target test architecture with shared fixtures and lane metadata; partly implemented. | plan | [Testing](../develop/testing.md) |
| `docs/capability-components-validation.md` | Capability components validation record | Which tests have actually run and which need a privileged or live system; a skipped privileged test is not a pass. | record | [Testing](../develop/testing.md) |
| `docs/capability-fix-list.md` | Capability plane: fix list | The tracked maturity backlog from the naming and hardening review. | plan | [Troubleshooting](../operations/troubleshooting.md) |
| `docs/logcmp-unified-logging-design.md` | LogCmp unified logging design | The structured logging service behind `liblogcmp`: severities, categories, privacy classes, bounded ingestion; OTLP export deferred. | design | [system.Log](../providers/log.md) |
| `docs/crypto-component-design.md` | [CRYPTO] capability component | The OpenCrypto front end: `libcryptocmp` connects lazily to system.Crypto and receives `DTYPE_CRYPTO` descriptors, never keys. | design | [system.Crypto](../providers/crypto.md) |
| `docs/crypto-keyvault-integration.md` | [CRYPTO] and KeyVault integration | There is no KeyVault; named volatile keys live in the kernel and only descriptors leave it. | design | [system.Crypto](../providers/crypto.md) |
| `docs/crypto-asymmetric-design.md` | [CRYPTO] asymmetric and certificate extension | How RSA, ECDSA and certificate validation would extend the component without widening `DTYPE_CRYPTO`; design only. | plan | [system.Crypto](../providers/crypto.md) |
| `docs/crypto-compliance-readiness.md` | [CRYPTO] compliance readiness | The component is not a validated FIPS module and makes no certification claim; what readiness controls exist. | design | [system.Crypto](../providers/crypto.md) |

## Storage

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/trustedzfs-design.md` | TrustedZFS: a capability API over the ZFS storage API | Dataset and pool handles as first-class descriptors, anonymous mounts, and the code-grounded implementation; its section 6a is superseded by the daemon design. | design | [Containers and Storage](../plane/containers-and-storage.md) |
| `docs/bsdfilesystem-design.md` | bsdfilesystem: the [TZFS] storage daemon | The storage broker built on TrustedZFS handles; the boot-time ready gate remains design only. | design | [system.Filesystem](../providers/filesystem.md) |
| `docs/tzfs-global-mount-and-capmode-centralization-plan.md` | TrustedZFS delegatable mounts and capability-plane centralization | Fixing delegated mounts on the real plane and centralizing capability-mode entry; part 1 fixed, part 2 partly landed. | plan | [system.Filesystem](../providers/filesystem.md) |

## Security modules and hardening

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/security/oes-endpoint-security.md` | OpenEndpointSecurity (oes): base integration | The in-base endpoint-security framework on MAC and Capsicum and how it is wired into the tree. | design | [Endpoint Security (OES)](../capability/oes.md) |
| `docs/security/5bsd-platform-hardening-plan.md` | 5BSD platform hardening implementation plan | Compatible, Protected and Locked modes, ten invariants, sealed updates and verified boot; internal, design only. | plan | [Verified Execution](../capability/veriexec.md) |
| `docs/security/hardenedbsd-import.md` | HardenedBSD import audit and first ports | The compatibility-first triage of the HardenedBSD delta; an engineering ledger, not a claim of HardenedBSD's properties. | record | [The BSD Side](../compat/bsd-side.md) |
| `docs/security/hardenedbsd-defensive-ports.md` | HardenedBSD standalone defensive ports | The independent defensive fixes imported: failed calls, memory exhaustion, safe cleanup; no new runtime restrictions. | record | [The BSD Side](../compat/bsd-side.md) |

## Linux emulation

The Linuxulator documents follow one contract: a syscall table entry is not
evidence, and every claim is qualified in a disposable amd64 ZFS-root QEMU
guest against a Linux reference VM. Read the gate first.

### Gate, coverage and handoffs

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/linuxulator-implementation-gate.md` | Linux binary compatibility: implementation and correctness gate | The acceptance contract: explicit coverage records for every syscall and option, disposable-VM evidence only. | design | [Linux Emulation](../compat/linux/overview.md) |
| `docs/linuxulator-syscall-coverage.md` | Linuxulator syscall coverage (x86_64) | Status of the x86_64 table through slot 472: real handlers, stubs, unimplemented; option tables keep historical notes. | ledger | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-amd64-syscall-audit.md` | amd64 Linux64 syscall dispatch audit | A complete entry-point inventory of the local x86_64 table, recounted from the generated dispatch table. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-option-review.md` | Linuxulator option-level review (x86_64, Linux 7.3 uapi) | For every implemented syscall, which flags and commands are honoured, rejected or wrong. | ledger | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-non-iouring-options-review.md` | Remaining non-io_uring options: amd64 review | The remaining option backlog outside io_uring; its entries are superseded by the signal-modes batch. | superseded | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-next-phase-options.md` | Next phase: options within implemented Linux syscalls | A source-review backlog of options within present syscalls, not a claim they passed. | plan | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-missing-syscalls-handoff.md` | Missing Linux syscalls: handoff for the next implementation stream | The calls still needing work; parts superseded by the peer-events batch. | plan | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-remaining-compat.md` | Linux64 compatibility completion work | The four remaining compatibility groups implemented and VM-tested in the final batch. | record | [Running Real Applications](../compat/linux/running-apps.md) |
| `docs/linuxulator-compat-next.md` | Linux64 compatibility: IPC, notifications, discovery and FUSE | Four batches (abstract sockets, uevent, sock_diag, FUSE parity) implemented and qualified. | record | [Running Real Applications](../compat/linux/running-apps.md) |
| `docs/linuxulator-production-readiness.md` | Linux64 production qualification | What the procfs, sysfs, descriptor, mount-identity and FUSE work qualifies and what it does not. | record | [Running Real Applications](../compat/linux/running-apps.md) |
| `docs/linuxulator-filesystems-handoff.md` | Linux compatibility filesystems | The filesystem-facing batch: openat2, mount identity, xattr, FUSE, procfs. | record | [procfs, sysfs and the Filesystem View](../compat/linux/procfs-sysfs.md) |
| `docs/linuxulator-proc-extra.md` | Linux64 procfs task links, descriptor state and socket tables | Task directories, fdinfo, `/proc/net/unix` and related procfs additions. | record | [procfs, sysfs and the Filesystem View](../compat/linux/procfs-sysfs.md) |

### squeue and io_uring

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/linuxulator-io_uring-design.md` | squeue / io_uring: implementation design | The shared completion-ring engine and the Linux front end: registration, fixed files, locking, workers. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-sqpoll.md` | SQPOLL implementation boundary and oracle | The candidate kernel-thread poller in shared squeue and its Linux oracle. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-iouring-feature-flags.md` | io_uring feature-flag audit | Which `IORING_FEAT_*` bits the shared engine honestly advertises. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-iouring-futex-pending.md` | io_uring pending futex waits | FUTEX_WAIT and FUTEX_WAITV park without a worker; engine owns lifetime, Linuxulator owns keying. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-iouring-futex-waitid-sqe.md` | io_uring FUTEX and WAITID SQE validation | Zero-field validation for the futex and waitid SQEs, as Linux requires. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-waitid-lifecycle.md` | io_uring WAITID lifecycle and pending requests | SQE layout, pidfd resolution at submission and pending-request lifetime for WAITID. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-iouring-rw-attr.md` | io_uring read/write attributes | `IORING_FEAT_RW_ATTR` and why protection-information records need a metadata iterator. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-iouring-zcrx.md` | io_uring zero-copy receive: copied NODEV phase | The `ZCRX_REG_NODEV` copied receive without claiming hardware zero-copy. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-mem-region.md` | io_uring parameter memory regions: shared backing and VM gate | `IORING_REGISTER_MEM_REGION` with kernel-owned and user-pinned regions. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-ring-resize.md` | io_uring ring resize: shared squeue implementation and gate | `IORING_REGISTER_RESIZE_RINGS` in the shared engine for native and Linux rings. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-register-query.md` | io_uring register query: Linux ABI and VM gate | The `IORING_REGISTER_QUERY` discovery command returning the admitted masks. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-min-wait.md` | io_uring minimum wait interval | `min_wait_usec` through both the extended-argument and registered-argument ABIs. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-no-mmap.md` | Caller-owned io_uring rings and registered-fd-only setup | `IORING_SETUP_NO_MMAP` with caller buffers pinned by squeue, and `REGISTERED_FD_ONLY`. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-epoll-wait-async.md` | io_uring EPOLL_WAIT readiness and cancellation | Pending `IORING_OP_EPOLL_WAIT` on an empty set instead of an immediate zero. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-fastpoll-lifetime.md` | io_uring fast-poll file lifetime | A parked request stays bound to the file chosen at submission even if the descriptor number is reused. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-splice-fixed-input.md` | io_uring SPLICE and TEE fixed input files | `SPLICE_F_FD_IN_FIXED` naming a registered slot for the input side. | record | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/linuxulator-splice-offsets.md` | io_uring SPLICE offsets | By-value offsets in the SQE and the current-position convention. | record | [io_uring and squeue](../compat/linux/io-uring.md) |

### Debugging, signals and tracing

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/linuxulator-ptrace-seize.md` | Linux64 PTRACE_SEIZE | SEIZE implemented; focused VM gate passes. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-ptrace-listen.md` | Linux64 PTRACE_LISTEN design and oracle | LISTEN implemented and VM-qualified against Linux 6.18 and 7.1 oracles. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-ptrace-interrupt.md` | Linux64 PTRACE_INTERRUPT | INTERRUPT implemented; Linux-oracle and focused gates pass. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-ptrace-registers.md` | amd64 Linux ptrace register access | GETREGSET and SETREGSET register sets; the XSAVE-read-only contract, later extended. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-ptrace-debugger-options.md` | Linux64 debugger options | Debugger-facing options recorded against a Linux reference; extended by the XSAVE-write batch. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-peer-events-options.md` | Linux64 peer names, multicast deltas and process ptrace events | Peer names, mixed multicast deltas and fork and exec ptrace events; superseded in part by the signal-modes batch. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-signal-modes-options.md` | Linux64 pending signals, tracing relationships and multicast modes | Pending-signal, reattach and multicast mode-transition contracts that passed both reference and BSD VM checks. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-xstate-mcast-options.md` | Linux64 XSAVE writes and multicast source-filter options | XSAVE register writes and multicast source filters; earlier entries superseded for that subset. | record | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |

### Memory, x86 machine-dependent calls and rseq

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/linuxulator-remap-file-pages.md` | Linux remap_file_pages implementation and gate | The handler and the shared VM-map object-offset primitive; gate passed. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-modify-ldt-implementation.md` | Linux64 modify_ldt implementation and gate | Linux `user_desc` decoding over the amd64 LDT backend. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-ioperm-implementation.md` | Linux64 ioperm implementation and gate | Argument validation over the existing amd64 I/O permission bitmap. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-iopl-options.md` | Linux64 iopl privilege-transition option | Privilege required only when raising the I/O level, as on Linux. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-rseq-implementation.md` | Linuxulator restartable-sequences implementation contract | Registration, scheduler and signal abort through the new `sv_schedswitch` callback; amd64 only. | design | [System Calls](../compat/linux/syscalls.md) |

### Swap, quota, perf, namespaces and sockets

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/linuxulator-swapon-flags.md` | Linux swapon flag validation and gate | Validation of the `swap_flags` argument the old table ignored. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-swapon-priority.md` | Linux swapon priority and shared swap-pager allocation | `SWAP_FLAG_PREFER` priority through a shared kernel helper. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-swapon-discard.md` | Linux swap discard policies | The discard, discard-once and discard-pages policies mapped onto the swap pager. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-swapoff-implementation.md` | Linux swapoff implementation and VM gate | `swapoff` over the native backend with Linux errno translation. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-quota.md` | Linux64 quota control on ZFS | The `quotactl` subset implemented on ZFS and gate-passed. | record | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-perf-event.md` | Linux perf_event_open software-counting subset | An event-file implementation of software counters; no PMU, sampling or mmap ring. | design | [System Calls](../compat/linux/syscalls.md) |
| `docs/linuxulator-unshare.md` | Linux unshare implementation contract | The first `unshare` subset (CLONE_FS) and the acceptance work that remains. | design | [Sandboxing and Debugging](../compat/linux/sandboxing.md) |
| `docs/linuxulator-socket-cookie.md` | Linux64 SO_COOKIE | `SO_COOKIE` against Linux-reference and VM checks. | record | [System Calls](../compat/linux/syscalls.md) |

## Virtualization

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/bhyve-virtio-state-nested-architecture.md` | bhyve: Virtio 1.4, VM State, and Nested Virtualization Architecture | The design proposal behind the modern VirtIO transport, portable VM state and Intel nested VMX. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-packed-ring-design.md` | bhyve VirtIO packed-ring implementation plan | Packed rings for every bhyve VirtIO device, opt-in per device, no default advertisement. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-1.4-validation-review.md` | bhyve VirtIO 1.4 implementation validation | The active validation record against the reference corpus. | ledger | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-balloon-design.md` | bhyve modern VirtIO balloon design | The modern balloon device; VM-free qualification passes, live pending. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-fs-design.md` | bhyve non-DAX VirtIO filesystem design | The virtio-fs device over virtiofsd; rootless-tested, live Linux pending. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-gpu-design.md` | bhyve VirtIO GPU 2D design | Protocol, queues, retained 2D state and checkpoint foundation; display qualification pending. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-iommu-design.md` | bhyve VirtIO-IOMMU and ACCESS_PLATFORM design | The opt-in virtio-iommu device with ACPI VIOT publication. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-virtio-rtc-design.md` | bhyve VirtIO RTC design | The modern-only virtio-rtc device with one dense clock. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-pvclock-design.md` | bhyve KVM-compatible paravirtual clock (pvclock) design | The opt-in, default-off KVM clock; model-tested, live pending. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/bhyve-migration-design.md` | bhyve live-migration control plane and cutover design | Checkpoint manifests, `migrate fd=`, `bhyve -R`; loopback-proven, live two-host operation not qualified. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/vmm-bhyve-bugs.md` | VMM / bhyve: Correctness Bug List | The correctness review of vmm and bhyve; complete, all findings closed. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-completion-matrix.md` | WASPNest completion matrix | The current requirement totals, activation dispositions and release-completion rules. | ledger | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-test-readiness-plan.md` | WASPNest test-readiness plan | Execution order for the qualification suites; defers to the matrix for status. | plan | [Testing](../develop/testing.md) |
| `docs/waspnest-kvm-selftests-parity.md` | WaspNest KVM-selftests parity audit | Which KVM selftests have vmm equivalents. | record | [Testing](../develop/testing.md) |
| `docs/waspnest-disk-io-qualification.md` | WASPNest disk-I/O qualification status | Three distinct disk-I/O findings; the root-only ZFS stress case is separate. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-reference-corpus-status.md` | WASPNest reference-corpus status | The catalog of normative inputs the review used; a catalog entry is not an authenticated artifact. | ledger | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-qualification-handoff.md` | WASPNest qualification handoff | Dated qualification runs; counts in them are historical, the matrix is current. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-remaining-work-handoff.md` | WASPNest remaining work: VirtIO, state transfer, and Intel nested VMX | The remaining-work handoff after the driver and nested-VMX waves. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-feature-completion-backlog.md` | WASPNest feature-completion backlog | The feature backlog as of the driver wave. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-review-status.md` | WASPNest VirtIO review status | Immutable dated review snapshots of the VirtIO stack; very long. | record | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/waspnest-virtio-fs-5bsd-driver-plan.md` | 5BSD VirtIO-fs guest-driver integration boundary | Where the guest virtio-fs driver stops and fusefs begins; the driver has shipped. | plan | [A Device Driver Bundle](../develop/device-driver-bundle.md) |

## Bluetooth

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/bluetooth-bugs.md` | Bluetooth Stack: Correctness Bug List | The correctness review of the BLE and mesh code; all 143 findings fixed and committed. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-conformance.md` | Bluetooth standard conformance: state of traceability | How much of the applicable Core specification the suite traces to tests. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-comparison.md` | Bluetooth interoperability comparison: 5BSD against BlueZ, Zephyr and NimBLE | The broad external-reference sweep across ATT, SMP, HCI, GAP and mesh. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-gap.md` | GAP interoperability: 5BSD against BlueZ, Zephyr and NimBLE | The Generic Access Profile sweep: advertising, scanning, privacy, addressing. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-hci.md` | HCI command and event handling: 5BSD against BlueZ, Zephyr and NimBLE | The controller-interface sweep. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-hogp.md` | HID over GATT and GATT client procedures: 5BSD against BlueZ, Zephyr and NimBLE | The keyboard-to-hkbd use case. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-l2cap-iso.md` | L2CAP, EATT and isochronous channels: 5BSD against BlueZ, Zephyr and NimBLE | The L2CAP, EATT and ISO sweep. | record | [system.Bluetooth](../providers/bluetooth.md) |
| `docs/bluetooth-interop-mesh.md` | Bluetooth Mesh: 5BSD against BlueZ, Zephyr and NimBLE | The mesh sweep, the first with the mesh specifications in tree. | record | [system.Bluetooth](../providers/bluetooth.md) |

The interop sweeps carry no "fixed" marks; later commits closed many of the
findings, and the Bluetooth chapter states what remains.

## Build, install, hardware and the inventory

| Document | Title | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/building-5bsd.md` | Building 5BSD | Building from source and producing a USB installer that boots into bsdinstall. | design | [Building](../operations/building.md) |
| `docs/pkgbase-install.md` | Installing and Updating 5BSD With Pkgbase | Installing and updating from a locally built pkgbase repository; there is no public package service. | design | [Installing](../operations/installing.md) |
| `docs/rpi5-bringup-plan.md` | Raspberry Pi 5 bring-up plan for 5BSD | Research-complete plan to boot 5BSD on the BCM2712; implementation not started. | plan | [Building](../operations/building.md) |
| `docs/5bsd-inventory.md` | 5BSD divergence inventory | Everything 5BSD adds to and changes in FreeBSD, section by section, with the defects the inventory found and fixed. | ledger | [How to Read This Book](../orientation/how-to-read.md) |

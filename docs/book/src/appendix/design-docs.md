# Design Document Index

The book is the account of 5BSD. The documents under `docs/` are the few
things that are not prose: the specifications that go deeper than a chapter
can, the ledgers the book takes its numbers from, and the two live work
lists. Everything else that once lived there was folded into the book and
removed; git history keeps it.

| Document | What it is | Summary | Status | Chapter |
|---|---|---|---|---|
| `docs/mac_capability-architecture.md` | MAC_CAPABILITY: Capability Message Interface | The capability transport, supervision and policy substrate: design, kernel service guide and userspace guide. | design | [The MAC Capability Framework](../capability/mac-capability.md) |
| `docs/capability-authority-model.md` | Capability-authority model | The architecture spec: authority is a held capability, not uid, path, PID or signal; supersedes the authorization framing of three earlier documents. | design | [The Authority Model](../capability/authority-model.md) |
| `docs/service-discovery-model.md` | Service discovery and management model | The source of truth for the naming, domain and activation mechanism; its uid-based authorization sections are superseded by the authority model. | design | [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) |
| `docs/trustedzfs-design.md` | TrustedZFS: a capability API over the ZFS storage API | Dataset and pool handles as first-class descriptors, anonymous mounts, and the code-grounded implementation; its section 6a is superseded by the daemon design. | design | [Containers and Storage](../plane/containers-and-storage.md) |
| `docs/bsdfilesystem-design.md` | bsdfilesystem: the [TZFS] storage daemon | The storage broker built on TrustedZFS handles; the boot-time ready gate remains design only. | design | [system.Filesystem](../providers/filesystem.md) |
| `docs/macf-new-hooks.md` | 5BSD MACF Hook Additions: Design Reference | Maps XNU MAC hooks that FreeBSD lacks to the 5BSD equivalents, with call site, lock context and sleep rules for each. | design | [Policy Points](../capability/policy-points.md) |
| `docs/linuxulator-io_uring-design.md` | squeue / io_uring: implementation design | The shared completion-ring engine and the Linux front end: registration, fixed files, locking, workers. | design | [io_uring and squeue](../compat/linux/io-uring.md) |
| `docs/bhyve-virtio-state-nested-architecture.md` | bhyve: Virtio 1.4, VM State, and Nested Virtualization Architecture | The design proposal behind the modern VirtIO transport, portable VM state and Intel nested VMX. | design | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/5bsd-inventory.md` | 5BSD divergence inventory | Everything 5BSD adds to and changes in FreeBSD, section by section, with the defects the inventory found and fixed. | ledger | [How to Read This Book](../orientation/how-to-read.md) |
| `docs/linuxulator-syscall-coverage.md` | Linuxulator syscall coverage (x86_64) | Status of the x86_64 table through slot 472: real handlers, stubs, unimplemented; option tables keep historical notes. | ledger | [System Calls](../compat/linux/syscalls.md) |
| `docs/waspnest-completion-matrix.md` | WASPNest completion matrix | The current requirement totals, activation dispositions and release-completion rules. | ledger | [Virtual Machines](../compat/virtual-machines.md) |
| `docs/linuxulator-missing-syscalls-handoff.md` | Missing Linux syscalls: handoff for the next implementation stream | The calls still needing work; parts superseded by the peer-events batch. | plan | [System Calls](../compat/linux/syscalls.md) |
| `docs/rpi5-bringup-plan.md` | Raspberry Pi 5 bring-up plan for 5BSD | Research-complete plan to boot 5BSD on the BCM2712; implementation not started. | plan | [Building](../operations/building.md) |

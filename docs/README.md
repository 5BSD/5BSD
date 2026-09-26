# docs/

The account of 5BSD is the book, The 5BSD Epic, under [`book/`](book/);
start at [`book/src/introduction.md`](book/src/introduction.md). The
files beside it are the ones that are not prose.

| File | What it is |
|---|---|
| `5bsd-inventory.md` | The divergence ledger: everything 5BSD adds to or changes in its BSD base, by subsystem, with paths, man pages and tests |
| `mac_capability-architecture.md` | Specification of the kernel capability framework |
| `capability-authority-model.md` | The authority model and its migration phases |
| `service-discovery-model.md` | Names, domains, channels and session provisioning |
| `trustedzfs-design.md`, `bsdfilesystem-design.md` | The storage substrate and its broker |
| `macf-new-hooks.md` | Reference for the MAC hooks 5BSD added |
| `linuxulator-io_uring-design.md` | The squeue engine and the io_uring front end |
| `bhyve-virtio-state-nested-architecture.md` | Device state, snapshot and nested virtualization |
| `linuxulator-syscall-coverage.md` | The Linux syscall table, call by call |
| `waspnest-completion-matrix.md` | Virtualization status, requirement by requirement |
| `linuxulator-missing-syscalls-handoff.md`, `rpi5-bringup-plan.md` | Live work lists |
| `pkg/` | Sample pkg repository configurations |

Add a document here only when it is a specification the book cannot
carry, a ledger the book cites, or a work list. Records of past work go
in commit messages.

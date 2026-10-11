# PF parity qualification

These tools stage and run disposable guests for the Desktop PF feature ledger.
They never load rules or install artifacts on the host. Run them from the
maintained `/usr/src` checkout, with all output under `/usr/obj`.

`stage.py SEED DIRECTORY --case program:case ...` copies an existing staged root,
installs the current source-limiter fixtures and the guest driver, and records
source hashes. It explicitly selects the guest driver through `init_rc` to avoid
inheriting a seed's old test entry point. This focused boot is not a normal-boot
qualification. `--refresh-fixtures` updates an existing stage and archives its
previous metadata; previously built images and manifests remain unchanged.
`--pf-module /usr/obj/.../pf.ko` replaces the staged PF module and records its
hash. Confirm its kernel build identity before staging; this option does not
claim ABI compatibility or replace the final clean-build gate.

Build a new immutable image with
`python3.12 /usr/src/tools/test/pf-parity/build.py DIRECTORY TAG`.
Each tag must be new. The wrapper preserves the matching stage metadata, so
later fixture staging cannot change the expected cases of an older image. The resulting manifest covers the kernel, modules,
userland, boot entry point and fixtures listed in the stage's `root/pf-artifacts`.
The seed kernel is explicitly recorded as inherited, not a current-source build.

Run `python3.12 tools/test/pf-parity/run.py DIRECTORY TAG --qemu /path/to/qemu`.
The runner uses snapshot mode, restricted user networking without host forwards,
four guest CPUs and 2 GiB RAM. It records image and emulator identities and
requires complete test enumeration, runtime artifact hashes, clean shutdown and
no kernel panic. It rejects skips and unexpected failures. Use `--attempt NAME`
for a new run of the same immutable image without replacing prior evidence.

`--expect-fail program:case` records a baseline reproduction run rather than a
passing feature qualification. Inspect the reported failure reason against the
intended reproducer; an arbitrary failing test is not proof of the target bug.
Corrected-kernel qualification must run without expected failures.

`qmp.py SOCKET COMMAND [JSON-ARGUMENTS]` controls only sockets below the PF parity
run directory. It is intended for a disposable reference guest's boot console,
not production VM management. OpenBSD installer console interactions and source
identity matching are still being qualified; downloading a snapshot does not
establish that its kernel matches the pinned source revision.

Current local preflight found `/usr/local/bin/qemu-system-x86_64` could not load
`libusb.so.4`. Select a working emulator explicitly and preserve its provenance;
do not change host libraries as a test prerequisite. An emulator substituted
for that failure must be included in later reproducibility/qualification work.

`check-authpf-selection.py --output /usr/obj/5BSD-pf-parity/...` compiles the
actual authpf `change_filter` function into a component harness. Rule-file
lookup and fork/wait are real; NSS, privilege changes, logging, and pfctl exec
are replaced. `--source` accepts the pinned OpenBSD function or a saved baseline
for the same comparison. This is not a full authentication-session test.

In the disposable OpenBSD guest, compile `openbsd-clear-source.c` to
`/root/openbsd-clear-source`, create `/root/pf-parity-disposable`, and run
`openbsd-capacity.sh`. The helper initializes the complete source-delete ioctl;
the pinned OpenBSD pfctl leaves its routing-domain and name fields uninitialized.
The reference test uses routing domain 0 for the filtered server and 1 for the
client. This workaround tests capacity recovery in the kernel, not pfctl's
source-delete command. Never run this reference helper on a production system.

A module build against newer source headers does not establish compatibility
with an inherited kernel. After an upstream sync changes networking layouts,
build a matching kernel and its modules before attempting runtime qualification.
The standard object root remains `/usr/obj`; stage only into disposable guests.

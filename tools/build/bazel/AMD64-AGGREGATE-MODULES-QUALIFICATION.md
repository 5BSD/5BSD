# Complete selected amd64 module aggregate

2026-11-03. One normal maintained `build-bsd bazel-test` request now builds the
current full GENERIC kernel and all 729 selected amd64 module leaves together,
with CTF and separate debug enabled. This closes the aggregate action-success
gate; it does not close full world, installed-system or pkgbase qualification.
Make remains production/default and BIP remains excluded.

## Selection, execution and correction

The fresh maintained Make inventory uses the current independent kernel control
at `/usr/obj/usr/src/bazel-kernel-current-canonical-make-control-r1-20261103/kernel`.
Its 729 leaves contain 691 generic and 38 firmware producers. Explicit format-5
inputs select three targets per module plus four kernel targets: 2,191 targets.
Production targets remain source-owned native Bazel declarations; Make discovery
is an independent migration audit, not a production build action.

The first request failed compiling mac_ntpd because its module variants omitted
the exact capability-header provider already used by its built-in declaration.
The correction adds that existing provider to amd64 and ARM64/RISC-V module
objects. No C source, compiler option, provider visibility, shared rule, SDK or
frontend input changes. Cross declarations are corrected but not qualified by
this amd64 run. The failed profile and its successful partial producers remain
retained, including 761 captured action records and 424 dependency files.

The second request passes through the unchanged normal frontend, Bazel 9.3.1,
the existing explicit prepared SDK and all 16 logical CPUs. Its official compact
execution log is fully drained: 5,055 captured actual records comprise 3,305
compilers, 621 module links, 620 CTF conversions and 509 CTF merges, with zero
failed actions. All of these records report fresh execution. Other successful
outputs may reuse prior cached actions; these are not invented fresh witnesses.
Actual compiler dependency files and link response parameters are captured.

## Captured artifact and installation consistency

The passed receipt binds 2,191 target configurations and 3,649 output records,
deduplicated into 2,191 content-addressed files (1,197,683,691 bytes). The independent
payload review uses the maintained strict qualification-artifact resolver, not
mutable bazel-out paths. It verifies every module producer and install-target
payload hash/size, checks complete selected-target coverage, and binds all four
kernel captures. For each of 729 modules the ELF identity, loader symbols,
separate debug information, debug-link basename and CRC pass.

All 1461 component records are collision-free. Each runtime/debug pair
uses matching package ownership and the declared debug tag. Aliases resolve to
their owning module in the same installation directory. The first inspection
incorrectly assumed links used type `link`; the actual protocol uses `symlink`.
The second incorrectly assumed every module belonged to `kernel`; the test and
mac-abac/oes modules legitimately have distinct packages. Both failed inspection
scripts/logs are retained. The third checks actual protocol types and package
pair consistency. It does not assert independent original Make metadata parity.

These are component manifests with configured default module paths, not proof of
a complete installed kernel package layout. Full original aggregate installation,
directory/linker.hints handling, package selection and payload closure, actual
pkgbase archives and coherent kernel/module placement remain required. Existing
per-family Make comparisons and the current full-kernel parity evidence remain
separate, explicitly bounded results. Standalone DWARF/source lookup, alternate
configurations, ARM64/RISC-V, world/rescue/bootstrap/hardware/publication,
VM/runtime and controlled CPU/memory/disk/cache/sandbox gates remain open.

## Evidence and frontend integration

Under `/usr/obj/usr/src/`:

- `bazel-all-amd64-modules-selection-r1-20261103/amd64.json`: actual selection.
- `bazel-all-amd64-modules-inputs-r1-20261103/`: explicit inputs and plan.
- `bazel-all-amd64-modules-ctf-debug-native-r{1,2}-20261103/`: failed and passed
  normal frontend receipts, commands, logs and immutable artifact capture.
- Corresponding `-actual-capture/` directories: actual actions/dependencies/
  parameter bindings; the passed capture has 3,305 dependency files.
- `bazel-all-amd64-modules-mac-ntpd-correction-r1-20261103/`: exact before/after
  declaration hashes and retained declarations.
- `bazel-all-amd64-modules-payload-review-r{1,2,3}-20261103/`: rejected inspection
  assumptions and final per-module artifact/debug/install consistency report;
  corresponding stdout/stderr files are retained beside them.

The existing frontend/backend format-5 targets and typed CTF/debug settings carry
the entire request; no new CLI, staging, signing, verification or publication
policy is needed. The manual and completion plan record this bounded result.
The disk guard records initial free 167,849,054,208 bytes and minimum observed
165,151,531,008 bytes, without reserve interruption. This is safety accounting,
not a controlled disk-I/O, memory or build-performance comparison. No module was
loaded and no host installation, publication, upgrade or reboot was performed.

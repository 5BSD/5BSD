# Selected AMD64 boot parent construction and normal sys traversal

## Native parents (2026-11-05)

`//stand:production_installation_archives` composes the selected AMD64 stand
traversal from existing native data, EFI, IA32 EFI, BIOS, userboot and kboot
producers. `production_products` also includes the internal userboot harness when
userboot is selected. Each ABI-sensitive producer retains its existing explicit
freestanding boundary. No copied firmware/Make object substitutes for native
construction. Only AMD64 parent construction is qualified here; ARM64/RISC-V
parent traversal remains open, rather than silently assembling an AMD64 image.

Source options select BIOS, userboot, IA32 and PXE contributions along with the
existing EFI/Forth/Lua/ZFS/kboot options. IA32 currently aggregates the implemented
Lua producer and explicitly rejects incompatible default-interpreter selections;
Forth/simple IA32 producers remain work to complete. The userboot directory claim
follows the actual default shared-library alias. Lua's directory claim follows
the configured prefix, not a second literal directory path.

Make installs no normal sys world payload unless MODULES_WITH_WORLD is defined.
The root-owned `sys_world_installation_archives` target represents that empty
contract and joins current world contributions. A new sys/BUILD package would
steal existing repository-root-owned headers, so none is introduced. Selecting
modules_with_world explicitly rejects this empty target; full module installation
must be implemented rather than silently omitted. Kernel/module construction
and installation/package qualification remain separate gates.

## Corrected ownership and metadata

Complete original parent inspection found defects not established by prior
component checks:

- boot2's installation archive included btxld's hosted binary/debug/manual even
  though complete Make stand installation does not install those paths. Those
  extra records and debug directories are removed; the actual btxld source owner
  and world installation remain intact.
- The parent omitted libsa(3). It now includes the existing source-owned manual,
  whose declaration also respects MAN and manual compression.
- Explicit source-owned directory records were missing across data/program
  groups. The complete parent preserves each child's original claims, including
  repeated /boot claims. The existing component-only boot_data_manifest explicitly
  merges identical directories for its single archive and accepts utilities
  directory ownership in its component package layout. The complete parent uses
  separate child archives to retain original directory claim multiplicity.

No repeated directory count is encoded as a fixture constant. The native source
owners and selected program archives supply their records. The configured test
inventory initially caught list.append after a select and duplicate /boot claims
in the merged component target; both were corrected without weakening validators.

## Evidence

All evidence is under `/usr/obj/usr/src/`.

- `bazel-stand-parent-native-r5-20261105`: normal maintained build-bsd bazel-test,
  sixteen jobs. Full selected installed boot construction and internal harness
  pass, together with source-settings, boot-data and userboot runtime tests.
  The explicit empty sys target is accepted by normal frontend output querying.
- `bazel-stand-parent-native-r6-20261105`: the additional boot-data package
  layout consumer passes. All 108 prior target/output content bindings match r5
  exactly, verified through hashed receipt/capture resolution.
- `bazel-world-with-sys-native-r1-20261105`: the current combined world
  contribution build passes with the explicit empty sys contribution connected.
  This establishes construction, not independent complete installed-world parity.
- `bazel-stand-parent-make-r3-20261105`: fresh independent full original stand
  build/install/installconfig, sixteen jobs and final source bindings. Ordinary
  reference mode avoids unsafe metadata logs in NO_OBJ descendants.
- `bazel-stand-parent-review-r5-20261105/review.json`: complete unique installed
  inventory and logical metadata match: 127 non-directory paths and 24 explicit
  directory claims, including their attributes/multiplicity. Original actual
  inode checks establish the userboot.so hardlink even though METALOG records
  it as a file. Empty trailing Make tag separators are parsed as no extra tag.
  107 payloads match exactly; four links are checked. Sixteen raw binary/debug
  payloads differ and are explicitly retained as unresolved. This is NOT fresh
  whole-parent binary equivalence or runtime/firmware acceptance. Earlier
  controlled component parity is separate evidence and must not be silently
  rebound to these raw differences.
- `binary-difference-classification.json` records ELF/PE header presence or raw
  format without asserting equivalence. The differing paths include BIOS/EFI/
  kboot images and userboot shared/debug files.
- The native parent still has one repeated identical loader.help.efi file claim.
  Both payloads and metadata agree, but world integration must canonicalize this
  shared output through declared source ownership/validated merging; silently
  dropping a collision is not accepted. The parent is not yet connected to the
  current world contribution group.
- `bazel-sys-world-make-r1-20261105`: independent normal sys all/install/
  installconfig with no module-world override; source snapshot has 37098 bindings.
  Component METALOG is empty. `bazel-sys-world-review-r1-20261105/review.json`
  binds that result to the empty native target and passed frontend capture.
  The broad independent sys source audit was I/O-heavy; its wall time is not
  reported as native build performance.

Earlier native r1/r2 boot construction passed before complete parent review found
ownership/directory omissions. They are not accepted as parent metadata parity.
Native r3/r4 failed during configured test inventory and remain failed. Original
r1/r2 boot controls remain retained; acceptance uses final-source r3.

## Frontend and remaining work

The existing format-5 settings/target interface and registered schema-2
freestanding SDK already support these contributions. The normal frontend manual
and completion plan are updated; no C dispatcher, signing or publication helper
change is needed. No boot execution, secure-boot/key-policy qualification,
publication, host installation, upgrade or reboot is claimed.

Next resolve shared help ownership and the sixteen binary differences, complete
stand product/option/ABI coverage and join stand to world; finish rescue and
installed tests. Then complete combined current world/kernel/modules,
installation/debug/global directory/pkgbase parity, reproducible bootstrap,
hardware/publication, VM/runtime and CPU/memory/disk/cache/sandbox gates.
Make stays production/default and BIP remains excluded.

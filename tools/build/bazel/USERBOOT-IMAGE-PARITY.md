# Userboot linked-image and Forth-default evidence (2026-11-04)

Both independent original link controls now match the native Lua/Forth ELF
identity, entry, all nine program headers and every allocated section, including
bytes, addresses, flags, sizes and alignment (19 Lua sections, 20 Forth).
The controls use original Make PIC objects, original archive/link recipes,
private archive copies, fresh current Ficl filename controls and the previously
qualified original libsa filename controls.
The userboot disk diagnostic controls remain explicit. Native artifacts and
original references are never rewritten. Whole unstripped/debug bytes differ
and are not normalized or claimed equal.

## Current-source references and reproducible generation

The initial Forth comparison correctly failed. An older Ficl reference predated
the generator's #line directive, and its old softcore filename control targeted
a different generated-file path. Reusing that control was invalid. Fresh original
Ficl and userboot references were built from current source instead. Current
softcore.o matches the native allocated/symbol/relocation contract directly;
fourteen new controls are compiled from current original recipes using all
sixteen build workers; fresh raw softcore matches directly. These controls
compose the independent full-image comparison. The Lua control also retains the
three original libsa filename controls, as does Forth.

The fresh reference exposed a real reproducibility issue: Make's softcore recipe
still inserted the execution host date when MK_REPRODUCIBLE_BUILD was yes.
The Makefile now emits an undated comment in that mode, retaining the previous
date behavior for ordinary developer builds. The fresh original generated C
matches the current native generator byte for byte, including the diagnostic
#line directive. No date or filename is patched into compiler output.

The existing build-bsd Make adapter passes the selected src-conf through SRCCONF,
so WITH_REPRODUCIBLE_BUILD in that file reaches the corrected recipe. Its native
format-5 configuration and the existing explicit Ficl generator metadata remain
unchanged. No new C dispatcher, staging, signing or publication policy is needed.

## Automatic Forth default

A fresh original stage with Lua disabled verifies the three contributions:
Forth shared object, its debug file and the userboot.so hardlink. Native file
modes, ownership and package tags match. The original inode relationship and the
actual native archive's extracted inode, 0444 mode, target and bytes are checked.
All 42 PIC objects plus the image, symbols and debug bytes are identical to the
already checked baseline native Forth products. Finally, the actual extracted
userboot.so alias runs through the original hosted harness and declared SDK
runtime: echo and language replies succeed, with the expected quit status.
This is an empty-root callback test, not a packaged-script or guest-kernel boot.

## Evidence under /usr/obj/usr/src

- bazel-ficl-current-repro-make-r1-20261104
- bazel-userboot-forth-current-make-r2-20261104
- bazel-userboot-image-controls-r4-20261104
- bazel-userboot-forth-default-current-make-r2-20261104
- bazel-userboot-forth-default-native-r1-20261104
- bazel-userboot-default-review-r1-20261104

The failed r1/r2 image controls and older reference stages remain retained and
are not counted as successful whole-image comparisons. The shared-object
construction report remains the record of the earlier 35-target regression.
No new Bazel producer code changed in this checkpoint; the independent current
Make builds and comparisons establish the reproducibility fix and image parity.

Next work returns to the complete-world gaps. Explicit/default/site alternatives,
complete DWARF/source lookup, packaged scripts, disk/guest/VM startup, full
world/kernel/modules/packages/bootstrap and CPU/memory/disk performance remain
required gates. Make remains the production default; BIP stays excluded.

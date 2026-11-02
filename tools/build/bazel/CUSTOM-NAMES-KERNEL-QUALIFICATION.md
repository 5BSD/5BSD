# Custom-named kernel object qualification

## Scope (2026-11-02)

Four amd64 GENERIC objects now have native declarations: BSD radix, OpenBSD PF
radix, and OpenZFS SHA-256/SHA-512 assembly. Thirteen physical prerequisite
contexts preserve source ownership. Production C/assembly is unchanged.

Target policies preserve the actual Make warnings, macros (including duplicate
OpenZFS definitions), language, forced-header order and consumed include roots.
OpenBSD radix retains its compatibility header and warning suppressions without
Werror; ordinary radix and OpenZFS retain their selected Werror policies.

The bsd_object_alias rule uses Bazel's declared symlink action to expose the three
Make final-link filenames without rewriting ELF objects. Original native
compilation and maintained CTF conversion remain the producers. BSD radix needs
no alias. The alias rule accepts a single declared .o/.pico artifact and output.

The maintained build-bsd format-5 target/SDK, CTF and immutable capture workflow
handles these declarations. No frontend C, CLI, staging/signing/verification,
publication or manual-option changes are required. This adds no runtime authority.
Make remains production/default; BIP remains excluded.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-custom-builtins-make-metadata-r1-20261102 retains actual supported
  Make recipes and reference hashes. bazel-kernel-custom-source-bindings-r1-20261102
  independently binds nine custom direct-source recipes, including these four.
- bazel-kernel-custom-names-amd64-ctf-r1-20261102 passes through the maintained
  frontend with 16 jobs and disk-reserve monitoring. Four actual compiler actions
  bind through CTF input/output hashes to immutable captured artifacts.
- bazel-kernel-custom-names-review-r1-20261102 retains declarations and review
  implementations. Actual argv equals final configured argv. Checks bind 308
  physical and eight generated prerequisite occurrences. All four .text and
  .SUNW_ctf payloads are byte-identical to Make; CTF graphs also agree.
- Three objects have identical allocated sections and relocations. OpenBSD radix
  differs only in the complete assertion source filename and associated string
  relocation offsets: Make uses /usr/src/sys/../contrib/openbsd-pf/sys/net/radix.c;
  native uses contrib/openbsd-pf/sys/net/radix.c. The observer resolves the complete
  absolute filename to an independently hash-checked physical input, then compares
  complete canonical string pools and symbolic relocation targets. It does not
  waive substrings or basenames and changes no production artifact. All 260
  non-debug relocations pass this comparison. Full DWARF equality is not claimed.
- The initial observer rejected the lexical sys/../ spelling. Its failure and
  diagnostic are retained alongside the corrected observer. CTF's existing graph
  comparison requires no type/address waiver for these objects.
- alias-review.json verifies all four public link outputs equal their captured
  CTF objects byte-for-byte. The three renamed outputs follow actual configured
  Symlink -> BSDCtfConvert -> CppCompile edges, with original source/argv checked.
- A bounded scan finds no matching call-shaped tracing/audit markers in these four
  source files. This proves neither absent shared hooks nor runtime coverage.

Closure query r44 passes for 2,293 groups and 2,468 compilation actions. The older
basename-only reconciliation r37 is retained but cannot resolve renamed products.
Alias-aware reconciliation r38 uses the proven producer chains and independently
hash-bound Make recipes: of 2,466 selected link products, 2,396 match the source
inventory, nine additional custom products match actual recipe source identities,
57 remain generated-name-only, two object-name-only, and two missing. The audit
preserves original inventory fields and raw compile outputs; it does not rewrite
production inputs to fit expected counts. Of the 57 generated-name matches, 53
have separate KOBJ/RPC artifact proofs. This remains configured analysis with
retained cohort artifact evidence, not a complete compiled or linked kernel.

## Remaining gates

The missing chains are elf-vdso.so.o and force-dynamic-hack.pico. vers.o and
subr_clockcalib.o need stronger identity checks; four other generated identities
need independent resolution. Complete linking/order/post-processing/install,
modules, alternate KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication,
bootstrap, boot and controlled CPU/memory/disk I/O/use comparisons remain open.
Routing/PF behavior and SHA known-answer/live-consumer tests are not covered by
this build-only profile (tests=[]). No managed disk cache, host installation,
upgrade or reboot occurred.

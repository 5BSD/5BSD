# System build options and remaining Make compatibility

This is the configuration checklist for the Bazel migration. An existing flag
or successful GENERIC build does not establish every configuration combination.
Make remains the production backend. The normal frontend documents its current
Make options in `usr.sbin/bsd-build/bsd-build.8`; explicit Bazel qualification uses
format-5 inputs and typed settings under `//tools/build/bazel/config`.

## Three independent meanings of debug

| Choice | What it controls | Current boundary |
| --- | --- | --- |
| GENERIC / GENERIC-NODEBUG | Compiled kernel diagnostics and device/options configuration | Both source configurations exist on AMD64 and ARM64. Native kernel rules currently select GENERIC explicitly; alternate/custom configuration support is not accepted. |
| Compiler debug information / debug packages | DWARF, separate debug files, debugger artifacts and their package installation | Native `kernel_debug` selects kernel debug artifacts and config's `-g`; it does not turn WITNESS or INVARIANTS on/off. Native toolchain debug information is a separate feature. |
| Production / debug malloc | Userland allocator checks and performance | Normal frontend build profiles select Make's MALLOC_PRODUCTION choice. Native qualification selects `malloc_production` explicitly; do not infer it from a qualification action's name. |

GENERIC includes `sys/conf/std.debug` (on ARM64 through `std.arm64`). That file
owns WITNESS, WITNESS_SKIPSPIN, INVARIANTS, INVARIANT_SUPPORT, DDB, GDB,
DEADLKRES, buffer/queue diagnostics and other options. GENERIC-NODEBUG includes
GENERIC followed by `std.nodebug`. Preserve those source-owned configurations;
do not replace them with a second hand-maintained list in the build frontend.
The kernel parser must resolve include/options/nooptions/device/nodevice inputs.
Its resulting inventory must drive compilation and module selection together.

The completed AMD64 candidate's actual packaged kernel was inspected with
`config -x`: identity GENERIC, WITNESS, WITNESS_SKIPSPIN, INVARIANTS,
INVARIANT_SUPPORT, KDB, DDB and DDB_CTF were present. This proves that selected
candidate's options, not a NODEBUG build or every override combination.
Never use `kernel_debug=false` as a substitute for GENERIC-NODEBUG.
For performance comparisons, match diagnostics, allocator mode, optimization,
CTF and debug-package choices explicitly on both build systems.

## Existing native configuration surfaces

- Kernel: source GENERIC configuration/parser and shared checked overrides in
  `kernel_option_settings.bzl`. These cover selected network, MAC, debugger,
  VIMAGE, SMP, ACPI/FDT, DTrace hook and other options. WITNESS/INVARIANTS
  currently come from the source configuration, not independent typed overrides.
- Debug/type metadata: `kernel_debug`, `kernel_ctf`, userland `ctf` and toolchain
  debug/hardening features. CTF is distinct from diagnostic instrumentation.
- World: typed selections include tests/test support, malloc, DTrace, audit,
  crypto/TLS, networking, NLS/iconv, manuals/examples and selected utilities.
  Consumers and output inventories must honor the selection; declarations alone
  are not acceptance of all consumers or combinations.
- Packaging: declared package version, compression threading, split-manpage
  policy, installation directories, ownership/config tags and debug subpackages.
- Cross compilation: explicit target architecture and execution SDK separation.
  Host generators (including FIDL, yacc/lex and DTrace tools) execute on the
  build host; produced objects and packages must match the target ABI.

## Make behavior still requiring completion or explicit disposition

| Area | Required closeout |
| --- | --- |
| Kernel selection | KERNCONF/KERNCONFDIR, GENERIC-NODEBUG and custom includes/options/devices must select the actual native kernel graph, identity, modules and packages. The frontend's Make `--kernel` support does not prove native custom-config support. |
| Module selection | MODULES_OVERRIDE, WITHOUT_MODULES, ALL_MODULES, MODULES_EXTRA and local/external module selection need documented supported behavior or explicit rejection. Verify actual Make semantics in sys/modules/Makefile and sys/conf/kern.post.mk. Keep ports/third-party Make builds supported. |
| World options | Inventory WITH_/WITHOUT_ defaults, dependencies and architecture restrictions from src.opts.mk/bsd.opts.mk and actual component Makefiles; compare each required selection with the declared Bazel closure and package payloads. Do not silently ignore src.conf. |
| Architecture/ABI | Complete ARM64 startup objects, libc/libsys, libthr, rtld, compiler runtime and machine-dependent libraries, then the full portable world. Existing AMD64 CPU constraints and source lists are not an ARM64 implementation. Keep architecture-only tools correctly excluded. RISC-V remains Tier 2. |
| CPU/compiler flags | Account for CPUTYPE/CPU tuning, compiler and linker selection, warning/error policy, optimization, hardening and sanitizers. Provide typed reproducible supported inputs or reject unsupported requests; arbitrary host flags must not bypass dependency tracking. |
| Debug/profiling | Cover debug files, CTF, profiling/instrumented variants, kernel diagnostics and their runtime/performance implications. Retain DTrace/FIDL generation and declared inputs. |
| Installation/pkgbase | Match directories, modes/owners/flags, links, config treatment, generated state, ABI/dependencies, kernel/module/debug layout and package selection. Include metadata-only packages and construction outputs. |
| Build stages | Finish native bootstrap, buildworld/buildkernel/pkgbase frontend integration, dependency ordering, incremental behavior and clean/rebuild behavior. Make is still used as the comparison/SDK seed, not hidden inside native product actions. |
| Reproducibility/resources | Declare source version/time/path inputs; verify used-input invalidation and unrelated-input reuse, sandbox behavior, CPU/RAM/disk I/O, retained objects/cache and scratch cleanup. |
| Hardware/publication | Preserve separate base/hardware builds, identity checks, the combined verified repository and latest/latest-built rules. Signing a repository is distinct from Secure Boot. |

These are parts of the existing six completion gates, not a request to copy
obsolete Make implementation details into Bazel. Every supported choice needs
one documented input, source-owned selection and matching outputs. Unsupported
required choices must stay visible and fail clearly until implemented.

## Minimum acceptance matrix

1. AMD64 and ARM64 GENERIC: complete selected world, kernel, modules and pkgbase;
   inspect the actual kernel's resolved configuration and target ELF ABI.
2. Both Tier 1 platforms with GENERIC-NODEBUG: build/link/package/boot and inspect
   absence of the source-defined diagnostics; do not infer this from debug files.
3. Debug artifacts and CTF on/off, production/debug malloc, tests/test support,
   and representative required feature selections with original Make comparison.
4. Module selectors and custom kernel configurations, with positive and negative
   dependency/unsupported-input cases.
5. Actual installed-system boot, authentication/services and upgrade/rollback,
   followed by resource/cache/sandbox/publication qualification.

Track evidence in COMPLETION-PLAN.md and the qualification records. No matrix
row is accepted merely because it appears in this document.

## Split-debug symbol policy

Separate debug information does not imply removing the runtime symbol table.
Kernel/module loader symbols and source-declared retained-symbol artifacts need
that table. `elf-debug-check.py --retain-symbols` requires an ordinary ELF to
retain it; the default still requires ordinary stripped userland. All modes
check the ELF identity, absence of embedded debug information, separate debug
information, actual debug-link filename and CRC. Native host artifact tests use
both real userboot variants and reject removed symbols, damaged debug data,
wrong filenames and conflicting policies. Candidate policies must match their
reference/source contract; detecting a candidate's symbol table is not authority
to relax its expected policy. This helper change adds no build-bsd option or
production backend change.

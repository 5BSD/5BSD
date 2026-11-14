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

## Installed OS tests remain a required configuration

The full AMD64 R15 capture selected `tests=false` and `tests_support=yes`.
Its 450 packages and 32 verification tests do not establish the installed OS test
suite's build or payload completeness. Refreshed Make references enable tests.
The initial native `tests/sys/kern` contribution covers the two descriptor
programs and 13 cases only; the rest of that directory/suite remains open.
Root cases require disposable VM execution; skipped root cases are not passes.
Bounded AMD64/ARM64 builds now cover the required `libthr`, `libelf`, `libkvm`,
`libjail` and ATF producers. Complete tests-enabled selection, Make payload
parity and target execution remain part of gates 2 and 6.

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

## Native kernel input preservation

Configuration overrides are declarative and idempotent. The native config
parser supplies actual baseline headers; only effective explicit changes produce
an override file. Source defaults are still validated rather than overwritten.
The final output is generated independently at its declared path. Tests cover
unchanged embedded configuration, enable/disable changes, source-default drift,
empty declared tree roots and stale-content rejection on AMD64, ARM64 and RISC-V
source configurations. This is host metadata testing, not cross-platform boot
qualification. Host tools use the standard tools attribute in the test execution
group; target artifact data keeps its own configuration and runfile collisions
remain errors. RISC-V's public configuration input group includes its existing
SoC metadata closure, so callers do not duplicate nested file inventories.

AMD64 built-ins map relative sys source identities to BSD's logical /usr/src/sys
root using the compiler's file-prefix mapping, covering macros and DWARF.
Generated-source overrides retain their own identities. This corrects the
observed relative assertion paths; it does not normalize compiled payloads or
waive kernel/module differences. Complete rebuilt-kernel allocated sections,
loader symbols, CTF, debug pairing and runtime checks remain required.

## ARM64 startup closeout (2026-11-14)

The shared CSU declaration now selects real AMD64 or ARM64 production sources.
The AMD64 preservation audit passes all ten objects and installation records.
ARM64 analysis currently rejects the host ncurses preprocessor's compiler-input
bundle mismatch; declarations do not establish a native ARM64 build or parity.
The component SDK uses an explicitly recorded older Make ARM64 seed plus current
AMD64 execution SDK R5. A current full ARM64 world, ABI closure and runtime remain
required. Keep the compiler-input guard strict while fixing dependency selection.

ARM64 CSU R3 subsequently completes and its original-Make comparison passes all
ten installed startup objects' allocated bytes, symbol/relocation contracts,
AArch64 identity and logical install metadata. This uses the explicitly recorded
older component SDK/profile (WITHOUT_BRANCH_PROTECTION), not the required full
current ARM64 world or every hardening configuration. Debug and runtime remain
outside this component comparison. See bazel-arm64-csu-parity-r1-20261114.

## Compiler-runtime architecture closeout (2026-11-14)

The native compiler-runtime producer selects explicit AMD64/AArch64 source lists.
AArch64 declares all 125 outlined atomic size/model specializations as independent
cc_library compilation actions, preserving their member names and order. Its
276 installed members and AMD64's 165 members pass allocated ELF, symbols,
relocations, archive order and logical install comparison with independent Make
references. Overflow-abort filenames use declared CRTSRC source identity.
The AArch64 reference retains its recorded older SDK/profile. Full DWARF,
current ARM64 world/hardening/runtime remain open; full AMD64 R12 refreshes the
package capture with this correction.

## ARM64 syscall-library closeout (2026-11-14)

Libsys selects real AArch64 syscall assembly/feature notes, compatibility-stub
inventory, generic helpers and version maps. Its two 471-member archives match
original Make's allocated ELF/symbol/relocation contracts and order. Shared ABI,
version/dependency/hardening metadata, logical installation, header/manual payloads
and own debug binding pass. Shared section bytes still differ, so full shared-code
and DWARF equivalence are unproven. The older component SDK/profile does not
qualify current ARM64 world or runtime. AMD64 retains all 424 install records and
242 file payloads exactly against full R12, with both syscall runtime tests passing.

## ARM64 libc component closeout (2026-11-14)

Floating-point headers and gdtoa sources now follow the configured AMD64/AArch64
ABI; AArch64 uses quad precision and generic division while AMD64 keeps its own
implementations. Unsupported floating-point header ABIs are explicitly
incompatible. Gdtoa, stdio and stdlib match independent Make allocated ELF,
symbol and relocation contracts for all 412 regular/PIC object variants per CPU.
Assertion diagnostics use declared logical source identities at compilation.
The ARM64 reference still uses its recorded older SDK/profile. Final libc archive
composition/order, shared linking, DWARF, current full world and runtime remain
open. The source-identity correction postdates full AMD64 R12; full R13 refreshes all
450 selected packages and passes 32 tests, including static/shared libc smoke
probes. Earlier byte-preservation evidence is not final acceptance. The R11
upgrade VM has not been refreshed to this candidate.

## ARM64 context and string components (2026-11-14)

The twelve context/jump source members match original Make in regular/PIC form.
Native optimized strings match all 94 members per variant, including generated
Arm wrappers, MOPS and IFUNC resolver implementations. Explicit
machdep_optimizations=false matches all 87 portable members per variant against
an independently configured Make reference. AMD64's static/PIC libc source
payload digests and string archive bytes remain preserved against full R13;
archive-identity and static/shared runtime smoke checks pass. These are component
results under the recorded older ARM64 SDK/profile. Full libc composition/linking,
DWARF, world/kernel/packages, hardening, runtime and performance remain open.

## ARM64 libc startup and syscall components (2026-11-14)

Libc's relocation input, architecture helpers, vDSO and generated syscall sources
now select the real ARM64 implementations. Static/shared syscall-body variants
remain distinct, and AMD64's source/group ordering is preserved. All 1,057 object
contracts in these component selections match original Make. Cumulative default
component coverage is 841 regular / 840 PIC members against the recorded older
profile's 1,450 / 1,438-member libc reference. This is not complete libc linking,
DWARF, current ARM64 world/hardening, full package or runtime qualification.
AMD64 archive identities and static/shared smoke probes pass, with unchanged
full static/PIC libc source-payload digests against R13.

## ARM64 portable libc groups (2026-11-14)

Seventeen portable groups now select explicit AMD64/AArch64 support without a
fallback to another CPU. All 560 regular/PIC object contracts match independent
Make references on each CPU, with compiler-level assertion source identities
preserved for ordinary, header and copied inputs. Declared-input execpath
expansion avoids hardcoded output directories. AMD64 archive identities and
static/shared smoke tests pass. ARM64 default component coverage is now
1,121 regular / 1,120 PIC members; complete libc linking, DWARF, current full world
and runtime remain open. Full R14 refreshes this identity correction across all 450 selected packages
and passes 32 tests; its 34 portable component archives match the independently
qualified focused AMD64 artifacts. Earlier unchanged-byte claims are not final
acceptance for this correction. Whole-system parity and new VM qualification
remain separate requirements.

## ARM64 libc general helpers (2026-11-14)

Eight ordinary general-helper compiler groups now use portable CPU constraints
and target-correct loader/TLS headers. All 174 regular and 174 PIC object contracts
match independent Make on both CPUs. Imported vis/unvis diagnostics retain the
original logical source identity through compiler flags. AMD64 identity and
static/shared smoke tests pass. The shared DTrace semaphore/NSS/resolver boundary
remains required; no probes were disabled. ARM64 cumulative component coverage is
1,295 regular / 1,294 PIC members. Full linking, DWARF, current world/hardening and
runtime remain open. Full AMD64 R15 refreshes all 450 selected packages and
passes 32 tests; its fourteen helper archives match focused qualified bytes.
Loader-header support alone does not qualify ARM64 rtld.

## ARM64 allocator and iconv components (2026-11-14)

Sized-free, jemalloc and iconv source groups now support explicit AMD64/AArch64
constraints. Production malloc remains a build input; jemalloc's source-owned
FreeBSD header selects CPU-specific address/page/pointer definitions. All 183
regular/PIC/static-wrapper object variants match independent Make on each CPU.
ARM64 comparison uses the explicitly production-malloc Make reference. Debug
malloc and the PIC/hidden libc_nonshared interface remain separate qualifications.
AMD64 archive identities and static/shared smoke tests pass, with unchanged
whole-libc static/PIC source-payload digests against full R15. ARM64 cumulative
component coverage is 1,392 regular / 1,380 PIC members; joint DTrace processing,
full linking, DWARF, current world/hardening and runtime remain open.

### Cross DTrace generator boundary

Libc's ARM64 provider selects a host-executed bootstrap variant whose object
rewriter uses the existing `DTRACE_TARGET_AARCH64` implementation. This target
instruction/relocation selection is separate from the executable's host ABI and
the target-built drti. The internal `dtrace_link_machine` setting is supplied by
the bootstrap transition, not a replacement for the frontend architecture input.
Other provider consumers still require their own cross qualification. Relocatable
DOF validation checks architecture-specific relocations, hidden function bindings,
function bounds and actual patch bytes; it does not prove registration or firing.

### Libc composition across architectures

The native archive recipe selects architecture-owned context, syscall,
long-double and optimized-string order while sharing portable lists. ARM64 uses
its actual symbol map and omits the AMD64-only libsys map. Static/PIC source
membership and order are checked independently; optimized and portable strings
retain separate selections. Debug malloc remains selectable and keeps assertions.
Its source aliases use declared execution paths and physical header contexts so
assertion filenames do not depend on Bazel configuration directories.

Final libc archive/shared construction and core library debug/install output now
support the ARM64 component profile. Public/nonshared/NOSSP interfaces, the current
SDK/hardening profile and normal ARM64 runtime still require qualification.
An older reference drti must be refreshed explicitly; a metadata match does not
permit ignoring its constructor code difference. The six-gate ledger retains
these distinctions and Make remains production/default.

### Public libc and target-only NOSSP

Libc's ARM64 nonshared wrappers and public shared/static link interfaces now
construct target-correct objects and clients. The selected ABI smoke probe uses
the public interface and conditionally exercises iconv's nonshared wrapper when
that feature is enabled. Cross construction is distinct from client execution.
The NOSSP archive and six architecture-selected loader extractions preserve their
own compilation policy; they do not qualify the complete loader.

The host DTrace bootstrap explicitly clears target-only libc NOSSP policy while
retaining its target-object rewriter selection. Configured-graph and artifact
preservation checks establish that boundary, not a performance result. Archive
symbol inspection requests LLVM special symbols so AArch64 cannot hide DTrace
aliases; original Make NOSSP member names remain accepted. The maintained
`archive_symbol_visibility_test` runs real host nm on independent AMD64/ARM64
fixtures and is explicitly permitted as host artifact inspection in cross runs.

### Original Make DTrace runtime references

`install-reference.py --dtrace-runtime-input FILE --make-meta` takes a format-1
JSON object containing `runtime` with `receipt`, `receipt_sha256`, `artifact`
(relative to that receipt), and `artifact_sha256`. The artifact must be the
original Make drti component's regular target ELF64 `drti.o` in its object tree.
The compiler and target must match the selected reference environment.

The helper selects that directory through Make's existing DTrace syslibdir input
and audits completed direct provider-link metadata recipes. It records and
rechecks input hashes; it neither overwrites the SDK nor admits Bazel artifacts
as an original Make runtime. This does not refresh the execution generator or
establish a hermetic reference closure; both remain separately bound inputs.

## Focused C++ cross-architecture checkpoint

ARM64 libcxxrt/libc++/libgcc_s now build with the actual builtin inventory,
architecture-preprocessed ABI map and appropriate frame API/math-header
selections. AMD64 regression builds and five existing runtime programs pass.
Both platforms match original Make archive/symbol/shared metadata, ABI-map
bytes and complete component install metadata. This is a focused component
result; full libm, full target execution, debug/configuration and complete world
qualification remain required. See COMPLETION-PLAN.md for receipts and limits.

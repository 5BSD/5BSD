# LLDB TableGen producer qualification (2026-11-02)

## Qualified scope

The native `//usr.bin/clang/lldb-tblgen:bootstrap` producer builds the four
original TableGen C++ sources against native llvmminimal and declared native
runtime libraries. `//lib/clang/liblldb:generated_headers` produces the 19
original library headers through existing `bsd_tablegen` actions: command
options and nine pairs of property definitions/enumerations. No upstream
program, test, TableGen input or generated binding source was modified.

The source owners are contrib/llvm-project/lldb, usr.bin/clang/lldb-tblgen and
lib/clang/liblldb. A narrow tools/build header owner declares the original
bootstrap stddef wrapper, whose bytes equal Make's legacy include input.
Existing root labels do not cross these new package boundaries.

This qualifies generated-header production and the four compiler objects. It
does not qualify an installed LLDB library/program, the whole bootstrap toolchain,
or equivalence of the complete bootstrap executables. Make remains production.

## Maintained Make context

Read-only maintained BuildEnvironment queries cover lib/clang, usr.bin/clang,
liblldb, llvmminimal and all three LLDB tool directories. Both immediate parent
directories have empty .MAKE.EXPORTED, MAKE_ENV and SUBDIR_ENV. The recorded
world selects MK_LLDB=yes. Root bootstrap-tools orders llvmminimal before
lldb-tblgen and uses the actual BSARGS/TOOLS_PREFIX context.

An ordinary leaf reference was attempted and retained as a failure: it selects
full libprivatellvm.so, which does not export the required TableGen symbols.
That leaf is absent from the normal usr.bin/clang SUBDIR list; the real root
bootstrap path selects llvmminimal. No Makefile was changed to hide the failure.

Fresh independent Make bootstrap archives/tools were built under isolated
/usr/obj roots with the maintained root context, host/static execution inputs
explicitly hashed, and all 19 original liblldb generation recipes invoked with
the resulting tool. The final replay checks every .td input and the tool before
and after generation. This is a bootstrap reference, not a published world.

## Results

- All 19 immutable native header bodies equal fresh original Make output.
- Eight actual regular compiler actions (four target, four execution platform)
  match Make's 14 macros, 22 warning options, optimization, C++17, debug,
  exception/RTTI and stack-protector policy in the explicit bootstrap control.
  All 5,882 consumed Make prerequisite hashes match declared native inputs.
- All four immutable compiler objects have identical executable sections.
  Allocated data and all 789 allocated-target relocations match after resolving
  12 filename bindings to physical files with identical basenames and SHA-256.
  Raw object/debug/string/relocation differences remain recorded; no prefix map
  embeds /usr/src and no artifact is rewritten.
- The first successful native profile has 19 actual uncached processwrapper
  TableGen spawns with exactly LC_ALL=C. Final profiles reuse their identical
  outputs: 437 execution-tool/runtime/input hashes are verified before and after,
  with exact output digest bindings. They are not additional observed executions.
- Four additional PIC compiler records/side artifacts arise when explicitly
  capturing the cc_library. They have no claimed Make bootstrap PIC oracle and
  are not installed.

The default producer uses the existing LLVM settings API. The explicit control
sets only X86 as a backend and the original Make bootstrap DEFAULT_SYSROOT;
its tool/header bytes remain unchanged from the default producer. The native
generator uses declared native dynamic libraries while the actual Make
bootstrap tool is host-static. ELF identity, ordered dependencies and debug
outputs for both are retained. No complete binary/runtime equivalence is claimed.

The new source header owner repairs the strict audit's real missing stddef
bootstrap wrapper. A separate initial observer mapping selected upstream libc++'s
assertion placeholder instead of the existing lib/libc++ config header; that
rejection is preserved and the final mapping uses the real owner/hash.

## Normal frontend and retained evidence

This uses the ordinary format-5 build-bsd workflow, explicit empty tests list,
typed existing LLVM settings, existing selected SDK, existing native rules and
compact execution logging. No frontend C/backend/validation API, signing,
packaging or publication policy changes are required; existing manual APIs apply.
No original maintained Make tests exist in this tool directory. The meaningful
functional checks are the 19 original generation recipes and exact output bodies.
There is no new synthetic test wrapper or disabled upstream test requirement.

Evidence under /usr/obj/usr/src:

- bazel-lldb-make-discovery-20261102.json and
  bazel-lldb-bootstrap-discovery-20261102.json: parent/tool queries and real
  bootstrap arguments. The retained /tmp discovery script additionally records
  the required source MAKESYSPATH after its initial missing-system-rules rejection.
- bazel-lldb-tblgen-make-r1-20261102: failed ordinary full-LLVM reference.
- bazel-lldb-bootstrap-make-r5-20261102 and
  bazel-lldb-generated-make-bound-reference-r5-20261102: fresh actual bootstrap
  archive/tool, original generation recipes and before/after bindings.
- bazel-lldb-generator-native-qualification-r3-20261102 and corresponding r4/r5:
  successful default, explicit policy control and corrected-header captures.
  Required tests:[] was absent in r2; its pre-Bazel rejection remains retained.
- bazel-lldb-generator-action-review-r3-20261102 and r4/r5: verified upstream
  compact conversion and actual compiler/generator/cache records. First run has
  4,614 actual CppCompile records across the full declared tool/runtime closure;
  action progress totals are not treated as executed compilation counts.
- bazel-lldb-generator-compiler-input-review-r4-20261102: retained strict header
  rejection; corresponding r5: eight compiler records, 5,882 hash checks pass.
- bazel-lldb-generator-object-review-r5-20261102: strict object differences,
  four exact code payloads, physical filename and 789-relocation explanation.
- bazel-lldb-generator-final-header-audit-r5-20261102: 19 final immutable outputs,
  actual prior generation bindings, executed-tool copy and ELF records.
- bazel-lldb-generator-native-inputs-r5-20261102 and budget records: ordinary
  frontend invocation, explicit existing settings and disk limits. Selected SDK
  is bazel-posthypertrace-sdk-20261102; prior immutable SDK evidence is preserved.

## Remaining work

The actual private liblldb graph has 756 unique maintained SRCS and 19 DPSRCS.
Its native compilation, shared/static options, generated-source/header closure,
ordered private Clang/LLVM dependencies, tests and package ownership remain open.
Keep checked-in LLDBWrapLua.cpp as Make does; do not introduce SWIG into base.
The lldb/lldb-server programs need two original LLVM-generated option headers,
proper ordered libraries, safe tests and installation qualification. Ancestor
aggregation must preserve MK_LLDB selection and component/package context.
Whole world/packages, exact bootstrap static runtime, other configurations and
architectures, debugger attach/launch, tracing and performance remain open.
No debugger target was attached/launched and nothing was installed on the host.

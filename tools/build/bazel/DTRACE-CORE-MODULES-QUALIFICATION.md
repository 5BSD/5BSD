# Core DTrace module qualification

2026-11-01. Native Bazel component qualification now covers core dtrace, fbt,
kinst and dtraceall on amd64, ARM64 and RISC-V64. Independent Make references
and final artifact/action comparisons passed. Runtime tracing, complete kernels
and controlled performance comparisons remain open.

## Independent Make reference checkpoint

The maintained Make queries select eight source entries for core DTrace on each
supported architecture, including one architecture-specific assembly source.
FBT selects two C sources, kinst three, and the aggregator one. Actual source
paths vary by architecture. Core DTrace additionally generates assym.inc and
offset.inc; native conversion uses genuine target-generated constants and
preserves per-assembly flags, warning policy, compatibility/header precedence,
textual source fragments and original object order.

Initial references under /usr/obj/usr/src/bazel-dtrace-core-make-20261101 passed
18 of 24 builds. All six core DTrace builds failed because the embedded
dtrace_db.c debugger implementation includes linker_if.h, but the module did
not declare this generated interface. AMD64 reaches the fragment through ISA
code; ARM64 and RISC-V reach it through dtrace_immstack.c. The maintained
module SRCS now declares linker_if.h, allowing the original Make generator to
produce it. No source fragment is rewritten or compiled as an extra translation
unit. No C source or runtime ABI was changed.

All 24 fresh corrected Make build/install references passed under
/usr/obj/usr/src/bazel-dtrace-core-make-r2-20261101: four modules, amd64/ARM64/
RISC-V64, plain and CTF/debug modes. Header-only KERNBUILDDIRs contain copied and
hashed genuine GENERIC option headers; no old generated interfaces or kernel
objects can hide the missing dependency. Each module generates its actual
constants/interfaces. Four independent jobs use -j4 each on this sixteen-CPU
host. Original failures and corrected commands/stdout/stderr/install metadata
remain retained. Discovery inputs and helpers are recorded in
/usr/obj/usr/src/bazel-dtrace-core-reference-review-20261101.

The ordinary build-bsd Make backend uses the corrected maintained module rule;
no new frontend C/CLI, source policy, signing, staging or publication input is
needed for this dependency correction. Native declarations and their actual qualification results follow below. No host module,
tracing session, service or installed system state changed. Make remains
production/default; BIP is excluded.


## Native module qualification

Core DTrace, FBT, kinst and the dtraceall aggregation module now have native
Bazel source, generated-interface, layout, object-order and installation targets
for amd64, ARM64 and RISC-V64. Maintained source files and runtime ABIs are
unchanged. Static BUILD declarations are authoritative: the native build does
not query Make or load the development discovery inventory.

The core compiles seven C files plus one target assembly file per architecture.
FBT compiles two C files, kinst three and dtraceall one. Embedded DTrace C
fragments are declared textual/header inputs, never extra translation units.
Explicit source-only compatibility header providers preserve used search-root
order, including the leading x86 decoder/FBT roots where required. Forced
headers retain ccompile.h, opt_global.h, debug_compat.h order; dtraceall uses
ordinary module flags with opt_global.h then debug_compat.h. Original warning
policy, DIS_MEM and assembly-only guards remain explicit.

Layout targets compile the genuine target genassym.c and OFFSET_TEST
compilation of genoffset.c with -fcommon. Existing kernel_constants rules run
original extraction scripts with declared tools, without executing target
code; assym extraction depends on the offset-layout check object. Option
headers come from the actual native GENERIC configuration, never invented
empty files. Per-target object forwarders preserve original Make link order.
Assembly and layout objects remain raw: only the thirteen module C objects per
configuration enter CTF conversion. Unused explicit C-fragment prefix mappings
were removed from assembly/layout actions before the final qualification.

### Evidence

All six final format-5 build-bsd bazel-test profiles passed, selecting four
modules, their four install manifests and two generated-constant outputs.
These profiles have no runtime test targets; success establishes artifact
qualification, not a running tracing subsystem.

- 24 native/Make module comparisons and 36 identical installation records.
- Twelve plain installed modules are byte-identical to Make.
- Twelve CTF installed modules have identical section metadata and payloads
  except build-ID/debuglink sections; .SUNW_ctf matches exactly. Separate debug
  files retain observed DWARF/layout differences; both implementations' actual
  debuglink CRCs verify. Full debug-file identity is not claimed.
- Twelve captured assym.inc/offset.inc files equal the independently generated
  Make files byte for byte.
- All 84 final module compiler actions executed successfully and match actual
  maintained source inventories, target triples, warning and forced-header
  policy. All 468 option-header input hashes match genuine reference headers;
  all 24 captured link parameter lists preserve original source/object order.
- Twelve genuine layout compiles and their offset-check prerequisites passed
  the action audit. All 39 CTF conversion input hashes bind to final C compiler
  outputs, with no assembly/layout object converted. Embedded source hashes
  were checked against the actual declared compiler inputs.

Final immutable captures and execution logs:
/usr/obj/usr/src/bazel-dtrace-core-{amd64,arm64,riscv}-{plain,ctf}-r4-20261101.
Runner commands: bazel-dtrace-core-native-runs-r4-20261101/commands.json.
Artifact, action, constants, layout/assembly and observability review:
/usr/obj/usr/src/bazel-dtrace-core-review-r4-20261101. Each captured payload is
verified through qualification_artifacts.resolve against receipt, manifest and
content hashes. Retained r3 CTF actions are explicitly bound to final compiler
output hashes; link argument captures record whether execution was retained.
Earlier analysis failures and r3 results remain available. The first review
rerun stopped on its own prior-capture symlink assertion; final r4 evidence uses
an independent directory and all comparisons passed there.

The existing frontend accepts these native target/input profiles; no frontend
C, signing, publication or SDK input change is required. Its manual documents
the bounded gate. Make remains production/default. BIP is outside this work.

### Remaining qualification

These are GENERIC component candidates. Full kernel/module aggregation,
additional kernel configurations, provider loading/unloading, actual probe
firing, debugger/stack-walk behavior, concurrency, permissions and fault paths
still require isolated runtime qualification. No module was loaded into the
host and no tracing session or service state was changed. Source auditing is
an instrumentation review queue, not proof of live probes or complete audit
coverage. Controlled CPU, memory and disk performance comparisons remain open;
this build matrix is not a performance benchmark.

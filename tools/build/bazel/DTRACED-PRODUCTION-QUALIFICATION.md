# Dtraced native production candidate (2026-11-05)

## Later native construction checkpoint

The selected normal frontend batch and original comparisons now pass. See
[COMPOSITION-QUALIFICATION-20261105.md](COMPOSITION-QUALIFICATION-20261105.md)
for exact retained receipts, fixes and limits. The configured-only and prepared
request descriptions below record the earlier checkpoint. They do not describe
the current execution status. Runtime, alternate profiles and whole-system
qualification remain open.


## Implementation

The production candidate uses native rules_cc compilation for all eleven original
C++ sources, declared local/source HyperTrace and dttransport headers, and native
CTF/ELF/proc/thread/crypto/util/C++ runtime dependencies. No executable or object
is copied from the SDK as a replacement for the daemon. Its actual compilation
outputs are available for subsequent independent object review.

Original compiler dependency records reveal 71 source headers consumed by
Make's -I sys and -I sys/dev/dttransport. The initial candidate declared only
tracing/transport headers; it was corrected before native compilation. Four
private filegroups expose the seventy source kernel headers to one coherent
virtual include tree, retaining mutually including headers and their original
sys/amd64/include, sys/bsm, sys/dev/vmm and sys/sys spellings. A separate bare
transport header preserves its original include. No installed payload glob or
SDK-header substitute supplies this known source closure.

The original default C++17, PIE, warning and debug-option behavior is represented.
Original recipe inspection removed an unnecessary C-only PIC definition and
preserved the later generic debug flags in robust mode. The existing
`dtrace_optimized` setting enables compile/link full LTO on this AMD64 candidate.
Other architectures are incompatible; RISC-V is not accidentally given LTO, and
cross-platform daemon support remains open.

Four source-owned boolean settings default false: dtraced_asan, dtraced_tsan,
dtraced_robust and dtraced_debug. ASan includes undefined-behavior instrumentation
and takes precedence over TSan, matching Make's if/elif. Robust mode retains its
exception/debug/error options and DTRACED_ROBUST; debug mode defines DTRACED_DEBUG.
These are ordinary typed format-5 build-settings labels under
//tools/build/bazel/config, accepted by the existing frontend/backend. No C schema,
staging/signing or publication-interface change is necessary. Make remains default.

The installation manifest explicitly owns the original program, separate debug
file, manual and two package-tagged debug directories. There is no original
child test-install recursion in this component Makefile. This does not mean the
daemon has complete functional or tracing test coverage.

## Performed checks

All evidence below is relative to /usr/obj/usr/src:

- bazel-dtraced-make-r1-20261105 passes original construction/installation.
- bazel-dtraced-make-r2-20261105 passes after C++ flag corrections.
- bazel-dtraced-make-r3-20261105 passes against the final source-header closure. Source/SDK/compiler guards remain enabled.
- bazel-dtraced-analysis-r3-20261105/metadata-review/review.json binds actual
  configured native analysis to the final original reference. All five metadata
  records match exactly. Native binary/debug/manual payloads remain pending.
- bazel-dtraced-action-profiles-r3-20261105/review.json checks real aquery action
  command lines for default, optimized, robust/debug, ASan+TSan and TSan profiles.
  Each has the eleven real sources represented in both standard regular/PIC
  contexts (22 configured compilation actions), plus one link action. Compile
  and link LTO/sanitizer selections match; robust/debug compile options match.
  Requesting both sanitizers selects address+undefined, never thread.

The final action-profile directory also retains header-input-review/review.json.
It binds the final original .depend records, header hashes and source recipes.
All five profiles declare every one of the 71 original headers as compilation
action inputs and the exact eleven original sources, in each of their regular
and PIC contexts. This is a configured input-closure check against the original
default profile, not executed preprocessing or other Make option dependency
closure. The earlier r1/r2 analyses are retained as intermediate evidence.

The initial action observer in r1 incorrectly expected only eleven configured
compile actions. Its actual output exposed both standard rules_cc variants;
that output is retained. The corrected observer checks both variants and requires
exactly eleven unique sources, each present twice. No production rule or source
was changed to satisfy the count. These are configured action checks, not
executed compilation, sanitizer execution or performance measurements.

## Remaining qualification

The next normal frontend request is retained in
bazel-library-admin-composition-request-r3-20261105/request.json and inputs.json.
It supersedes the retained unstarted r2 request and includes this daemon's actual
program, source objects and installation archive alongside the preceding batch.
It is prepared, not queued or running behind the aggregate frontend lock.

Native compilation/linking, original allocated object/ELF contracts, direct
library ordering, debug CRC and complete archive payload/header comparisons
remain required. LTO and sanitizer runtime builds/execution, robust/debug runtime,
HyperTrace/collector/job/transport behavior, cross-platform closure and performance
also remain open. SDK sanitizer/runtime and bootstrap independence are separate
requirements; selecting flags does not establish them. No host daemon, installation,
upgrade, VM or publication was run for this candidate.

# Core kernel object qualification checkpoint

## Scope (2026-11-01)

Seventy-one previously unmatched physical sys/kern sources now have native
amd64 GENERIC declarations: seventy C translation units and subr_ticks.S.
The normal format-5 build-bsd bazel-test target list builds these objects and
an existing two-source clock-conversion group. This is component build and
inspection evidence, not a complete native kernel, installed system or runtime
qualification. No host installation, module loading or reboot was performed.

The fresh configured amd64 GENERIC Make reference was successfully compiled
with sixteen jobs, including its actual final kernel link. Evidence is
/usr/obj/usr/src/bazel-kernel-amd64-full-make-reference-r1-20261101.
This is a Make reference kernel, not a successful full Bazel kernel build.
The earlier configuration-only inventory remains an explicit earlier snapshot.

## Maintained native implementation

Each source owns an ordinary native compilation target, its required generated
option/interface headers and narrow physical header contexts in their owning
packages. Native analysis and compilation never invoke the migration inventory
or Make to discover these inputs. Existing option extraction rules are reused;
ten missing option outputs are extracted from the actual selected config tree.
No generated option content or private toolchain path is substituted in BUILD
files. Header contexts are per consumer, rather than a union of all seventy-one
sources' extra prerequisites. Existing common kernel contexts are unchanged.

The built-in warning vector preserves Make's trailing WERROR order; existing
callers retain their previous warning ordering. stack_protector.c explicitly
omits stack instrumentation. subr_ticks.S uses assembler-with-cpp and LOCORE.
The dump compressor imports Zstandard's real kernel compatibility include root.
These are actual per-source compiler policies, not qualification-only options.

The shared CTF rule now copies the declared compiler object to a fresh output
and runs the declared converter in place on that copy, using the existing native
static copy/exec tool. This matches Make's conversion semantics. ctfconvert can
succeed without creating a distinct -o file for assembly without C types; the
old rule then failed Bazel output validation. The new action preserves that
object without inventing CTF data, mutating a compiler input or suppressing a
converter failure. CTF remains controlled by its existing typed build setting.

init_sysent.c and syscalls.c here are tracked source files used by Make's actual
recipes. This cohort does not establish a complete native syscall-generation
pipeline or a full native kernel aggregation/link/install rule.

## Checks performed

Retained evidence is under /usr/obj/usr/src:

- bazel-kernel-core-amd64-ctf-r3-20261101: successful normal frontend build,
  immutable captured outputs, compiler/converter execution log and receipt.
  The profile requests seventy-one new object groups plus one existing group;
  tests is empty. No runtime or unittest cases were executed by this profile.
- bazel-kernel-core-review-r1-20261101: retained profile, source/Make recipe
  inventory, review scripts, raw ELF section comparisons and input audits.
- bazel-kernel-core-make-metadata-r2-20261101: supported per-target Make meta
  recipe capture; all seventy-one existing object hashes stayed unchanged.
  nofilemon captures recipes, not a complete dynamic input trace.

All seventy-one original .text sections match Make byte for byte. All seventy
C objects have identical .SUNW_ctf sections. Neither assembly object contains
CTF, and the native converted assembly output's SHA-256 equals its actual
compiler output's digest. The two existing clock-conversion C objects also
retain exact Make .text and CTF sections after the shared helper changes.

The audit verifies 8,615 physical input hashes and 283 consumed generated input
bindings against actual successful compiler actions. Generated bus/device
interface comments differ only in the documented source-path provenance line;
that exact comment transformation is checked separately from raw hashes.
Ordered warning vectors, macro definitions and stack protector selection match
the actual per-target Make recipes for all seventy-one sources.

Incremental local cache reuse means no single execution log contains every
compiler invocation. Successful compiler records from the retained r1/r2/r3
runs are selected by exact output SHA-256, bound to the r3 converter's declared
input digest, then to the final immutable captured output digest. Failed
compiler records are excluded. This does not claim that cached objects were
freshly recompiled in r3.

Forty-four objects have raw runtime-section differences. Their sixty-one
absolute-versus-relative filename expansions refer only to hashed physical
source/header prerequisites. The comparison retains every original section
hash and string. All 29,616 nondebug relocations compare equally by symbolic
target after accounting for those exact filename spellings and corresponding
string offsets. No production file was rewritten to force parity. Debug data,
symbol/string tables and whole object bytes are not claimed identical.

The r1 run correctly failed on the undeclared Zstandard compatibility include
root. The r2 run exposed the assembly CTF output bug. Both remain retained;
only r3 is a successful build receipt. Disk reserve monitoring did not fire.
Build timing/resource records are observations, not controlled performance
comparisons or evidence of complete hermetic execution.

## Stop and resume

This is a committed stopping point for the user's host kernel upgrade. No new
cohort should start before the user resumes. The userland checkpoint is in
USERLAND-UPGRADE-CHECKPOINT-20261101.md. After reboot, confirm host/toolchain
identity and current source/reference hashes before reusing execution evidence.

Remaining gates include other built-in objects/custom recipes, complete kernel
link/version/post-processing/install composition, ARM64 and RISC-V64 built-in
coverage, modules, complete world/pkgbase/hardware publication, matching-kernel
VM/runtime/probe/audit checks, hermetic tool execution and controlled CPU,
memory, disk I/O, disk-use and cache tests. Make stays the production default;
BIP stays out of scope. This checkpoint does not narrow the full-system goal.

# Hosted/freestanding artifact boundary (2026-11-04)

## Design

A world or image graph must contain hosted programs and freestanding boot
producers together. `bsd_freestanding_artifact` applies a one-to-one outgoing
transition that changes only the dependency target platform. Its default CPU
comes from the consumer; explicit architecture supports multi-target images.
The SDK's hosted and three standalone toolchains are registered in MODULE.bazel
and have disjoint environment constraints. Execution tools use their native
execution configurations. The wrapper forwards DefaultInfo files/runfiles,
OutputGroupInfo and typed installation-file/manifest providers. It intentionally
does not export CcInfo or an executable tool/test interface.

The five EFI packages expose freestanding_image and
freestanding_install_manifest. These are component interfaces, not an inventory
of a complete bootloader package or a world aggregate. The Lua archive test
consumes the transitioned typed manifest directly from a hosted graph.

Format-5 source qualification now requires the already-maintained SDK
freestanding_toolchains schema 1 and snapshot-bound toolchain declarations for
all target kinds: the source module registers those declarations. Older SDKs
must be regenerated with the maintained SDK stager; no hosted fallback is used.
The build-bsd C frontend continues to dispatch the same maintained format-5
backend; its CLI and production Make default are unchanged.

## Generator correction

Strict PE comparison first found one changed AMD64 image: Forth embedded
`bazel-out/<configuration>/bin/stand/ficl/generated/softcore.c` in an assertion
message. The transition changes that configuration path. The shared original
AWK generator now starts with `#line 1 "softcore.c"`. This gives generated C its
logical filename in both Make and Bazel, preserving every original body line
number. It changes diagnostic strings and consequent image layout; it does not
patch binary output or relax comparisons. The original Make concatenation/AWK
recipe produces exactly the same body after that one directive is removed.
The maintained softcore recipe test also executes under Bazel.

## Evidence and scope

The final hosted build includes all fifteen program/architecture combinations:
boot1, gptboot, Lua loader, Forth loader and simple loader on AMD64, ARM64 and
RISC-V. Six test wrappers pass, including all three resource-object ABI checks,
the generator recipe, native installation validation and 28 frontend methods.
The actual native, ARM64 and RISC-V object tests validate ELF machine identities;
the source resource compile actions declare freestanding defaults without an
implicit SDK system-header search. The hosted-header negative control must fail
with stdlib.h unavailable below the transition.

Twelve final PE images retain their previous qualified whole-file bytes. The
three Forth images intentionally change with the logical filename correction;
each equals its fixed direct standalone profile exactly. Direct profile artifact
tests also execute. These are firmware artifact checks, not firmware boot tests.
The hosted Lua archive retains exact image bytes, root ownership, expected modes,
help data and the loader.efi hardlink. Existing installation validation runs in
the mixed graph; this is not proof of a complete installed system.

A configured dependency query over all fifteen roots observes the source-built
ELF-copy and protoc tools. Each has exactly one configured identity across those
roots. This checks those two actual execution closures, not every build tool or
full-system performance. The initial prototype overrode extra_toolchains in the
transition and built native tools in additional configurations; the final rule
uses normal module registration and changes only the target platform.

Evidence below /usr/obj/usr/src:

- bazel-freestanding-boundary-r1-20261104: explicit fixture visibility failure.
- bazel-freestanding-boundary-r2-20261104: initial passing mixed build; oversized
  JSON execution log retained. The strict initial image-review failure is in
  bazel-freestanding-boundary-initial-review-failure-r1-20261104.
- bazel-freestanding-boundary-r3-20261104 and
  bazel-freestanding-boundary-review-r1-20261104: fixed-generator prototype.
- bazel-freestanding-boundary-registered-r1-20261104: final fifteen-image build,
  six passing test wrappers and compact execution log.
- bazel-freestanding-boundary-direct-r1-20261104 and
  bazel-freestanding-boundary-direct-{aarch64,riscv64}-r1-20261104: fixed Forth
  direct profiles and artifact tests.
- bazel-freestanding-boundary-registered-graph-r2-20261104: sharing audit. The
  first audit omitted the frontend JAVA_HOME and failed local JDK discovery;
  its logs remain in graph-r1. The corrected query observes two tools; file2c
  is not in that source-built tool closure.
- bazel-freestanding-boundary-registered-negative-r1-20261104: hosted-header
  rejection with final module registration.
- bazel-freestanding-boundary-final-review-r1-20261104: consolidated comparisons,
  input bindings and commit record.

The first review harness also requested the wrong archive output suffix; the
archive is named lua_install_archive.tar. No build assertion was weakened.
Broader runs retain the compact execution-log default rather than expanding all
native tool inputs into gigabytes of JSON. This is a diagnostics policy, not a
CPU, memory or disk performance result.

## Remaining work

Complete world/kernel/install/pkgbase aggregates and inventories, other boot
profiles and options, shared werror policy, full bootstrap/output querying,
filesystem sandboxing, relocation/cache qualification, real VM boot/services and
fair CPU/memory/disk measurements remain open. Separate debug/source lookup and
complete package/publication parity also remain open. Make stays production and
default; BIP remains excluded. No installation into the running system, upgrade,
reboot or publication was performed.

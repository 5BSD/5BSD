# Selected native EFI first-stage programs (2026-11-04)

## Implementation and scope

`stand/efi/boot1/bootstrap.bzl` owns the shared native construction of boot1 and
gptboot. Source-owned profiles select AMD64, ARM64 or RISC-V source rows, headers,
ABI flags, startup assembly, linker scripts and object order. The existing public
entry/full/symbol/debug/image/manifest labels are preserved. These are EFI boot
programs, not qualification of the Bazel compiler bootstrap.

Each profile links six entry objects followed by the native libefi and EFI libsa
archives. gptboot retains its local EFI_DEBUG and ZFS exclusion while its shared
archives retain their original global configuration. Unsupported policy profiles
are incompatible at analysis rather than silently using another configuration.
ARM64/RISC-V images are binary extraction of assembly-authored PE headers; AMD64
uses the native PE writer. Cross PE timestamps are zero as in original Make,
not the configured epoch used by the AMD64 writer.

Original Make references explicitly bind independently built original libefi and
libsa archive receipts through the maintained reference helper. No missing SDK
archive is populated from Bazel. No Make recipe runs inside a Bazel action.

## Completed cross checks

The ARM64 tested qualification and RISC-V qualification each execute two Bazel
host artifact tests, with four unittest methods per program: ELF/PE ABI and entry,
allocated-section preservation and debuglink CRC, absence of unresolved strong
symbols and runtime dependencies, and installation metadata. Target firmware is
inspected, not executed on the host.

All twelve raw entry objects per architecture match original Make allocated bytes
and symbolic relocations, including machine/ABI fields. Raw gptboot PE bytes match
original Make on both architectures. boot1 uses already documented assertion
filename controls in the original EFI/standalone archives. Independently compiled
original filename controls, with original member order retained and no native
object substitutions, establish matching loadable payloads and complete PE bytes
for both programs on both architectures. Full ELF and separate DWARF byte identity
are not claimed. The non-loadable RISC-V attributes offset can differ with debug
layout; the comparison checks the actual referenced section bytes and other fields.
Default installation payloads, owners, groups, modes and package tags match Make.

Targeted configured-action graph audits bind twelve regular object producers,
two ordered links and two binary-image producers to immutable qualification
captures for each cross profile. They account for 738 ARM64 and 740 RISC-V
original consumed dependency names. The graph also registers twelve unused PIC
compiles per architecture; registration is not execution. Architecture aliases
and generated-header name mappings do not prove their payload bytes or cache hits.

Evidence is retained under `/usr/obj/usr/src/`:

- `bazel-cross-efi-bootstrap-aarch64-tested-r1-20261104`
- `bazel-cross-efi-bootstrap-riscv64-r1-20261104`
- `bazel-cross-efi-bootstrap-{aarch64,riscv64}-object-review-r1-20261104`
- `bazel-cross-efi-bootstrap-{aarch64,riscv64}-payload-review-r1-20261104`
- `bazel-cross-efi-bootstrap-<arch>-<program>-controls-r1-20261104`
- `bazel-cross-efi-bootstrap-aarch64-actions-r2-20261104`
- `bazel-cross-efi-bootstrap-riscv64-actions-r1-20261104`

The ARM64 payload review uses the pre-test r2 build; all 27 captured outputs
are byte-identical in the tested build, binding the payload review to it. The
AMD64 regression passes three Bazel wrappers and preserves all 225 prior
qualified artifact bytes. Both MAN=no and raw-manual/split-package cases pass
one gptboot artifact wrapper each. Independent original Make references match
their actual image/manual bytes and complete file metadata (one and two files).

Additional evidence:

- `bazel-cross-efi-bootstrap-aarch64-final-reuse-r1-20261104`
- `bazel-cross-efi-bootstrap-amd64-regression-r1-20261104`
- `bazel-cross-efi-bootstrap-amd64-regression-review-r1-20261104`
- `bazel-cross-efi-bootstrap-{noman,raw-split}-r1-20261104`
- `bazel-cross-efi-bootstrap-options-review-r1-20261104`
- `bazel-cross-efi-bootstrap-final-review-r1-20261104`

The combined review binds source hashes and these receipts. Its nine executed
Bazel wrappers contain four unittest methods each; reports count wrapper cases,
not 36 separately reported Bazel tests.

## Retained failures and remaining gates

The first ARM64 analysis failed on missing linker-script visibility; narrow
source exports correct it. A standalone audit invocation omitted the maintained
frontend's JAVA_HOME environment and selected a bogus host JDK. Its failed query
is retained; corrected read-only queries use the qualified JDK/environment.
The frontend already supplied that environment. This does not resolve the broader
bootstrap/output-query gate.

The configured userland `werror` option is incomplete: standalone profiles still
contain literal `-Werror`, while common toolchain handling does not consistently
remove it for `werror=false`. This needs shared warning-policy integration across
userland, not an appended warning-suppression workaround. Default-profile checks
do not qualify alternate warning policy or all buildworld options.

The maintained build-bsd C frontend was reviewed. Existing format-5 targets,
settings, architecture and jobs inputs cover this component; no new C switch is
needed. Its manual is updated with this contribution's scope. These development
checks use sixteen jobs and existing verified development SDKs. They do not
publish packages, install the host, reboot it, verify a trust chain or run firmware.

Continue complete bootloader aggregation (including shared directory/help policy),
remaining entry/interpreter profiles, firmware execution, full world/kernel and
pkgbase, bootstrap, sandbox/cache and CPU/memory/disk performance qualification.
Make remains production/default; BIP remains excluded.

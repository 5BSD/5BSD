# Native AMD64 Lua kboot loader (2026-11-04)

The selected AMD64 Lua, GELI/disk/ZFS, FDT-disabled kboot consumer now builds
through the maintained explicit format-5 `build-bsd bazel-test` interface. Its
39 C/assembly contexts, version/help generators, ordered static link, install
stripping, two file contributions and archive are native Bazel actions. The
source-owned declarations do not invoke Make or consume exported configuration
metadata during production. The existing standalone toolchain boundary prevents
hosted startup/library injection. Other architectures, interpreters, FDT and
regular verifier profiles remain incomplete; unsupported exposed profiles are
incompatible rather than silently substituted.

## Original construction and installation

The original Make reference uses explicit passed original Lua, libsa and libkboot
archives. Native links retain that order after all 39 entry objects and the
actual AMD64 linker script. The generated revision 3.1 source preserves the
original reproducible version contract; site version metadata still uses the
existing declared input. Lua paths use the existing typed configuration.

Thirty-seven entry object allocated/symbol/relocation contracts match directly.
Two original compiler filename-only controls explain disk.o and hostfs.o. Their
diagnostic string lengths affect both allocated data and relocation addends; the
controls must match the complete object contract. No production filename map,
assertion-disable flag or binary patch is used. A private copy of original libsa
uses its three previously qualified original filename controls. Replaying the
original loader link and actual `install -s` recipes then reproduces the complete
native installed image byte for byte. Whole unstripped/debug bytes are not
claimed equal. Raw original installed loader bytes differ because they retain
absolute diagnostic paths.

Generated help bytes match raw Make. The two original install records retain
root/wheel ownership, 0555 loader and 0444 help modes and package=bootloader tags.
The original /boot directory record remains separate from file contributions.
The archive tests inspect actual file bytes, identity and permissions; the ELF
test verifies a static AMD64 executable with its entry in an executable segment.
The executable is not run on the FreeBSD host: it uses Linux syscall semantics.

## Retained evidence

- Original Make: `/usr/obj/usr/src/bazel-kboot-loader-make-r1-20261104`.
- Native construction: `/usr/obj/usr/src/bazel-kboot-loader-native-r7-20261104`.
- Original controls: `/usr/obj/usr/src/bazel-kboot-loader-controls-r2-20261104`.
- Audit: `/usr/obj/usr/src/bazel-kboot-loader-review-r1-20261104/review.json`.
- Final regression: `/usr/obj/usr/src/bazel-kboot-loader-regression-r2-20261104`.
- Final bindings: the audit directory's `regression.json` and `commit.json`.

The audit binds 39 actual compiler contexts, 1,818 consumed source/header pairs,
original compiler policy, exact object/archive link order and real link, strip,
help and archive producers. Final regression: 33 test targets pass (one executed,
32 cached), 34 previous boot outputs remain exact, and all kboot outputs are
rebound to the passing capture. Three new artifact test methods are one target.
The comparison scope is selected boot artifacts, not the complete OS.

Failed attempts are retained. They exposed new package boundaries crossing prior
owners, duplicate source exports, missing generator access, ambiguous manifest
selection, missing libsa source headers and quote handling in the new copts.
The declarations now retain existing owners and source visibility, select only
the manifest output group after the artifact boundary, declare the headers and
preserve the original quoted macro. An initial control harness incorrectly
assumed filename changes could not affect relocation addends; complete original
filename controls prove both affected object contracts without normalizing them.

The existing frontend dispatcher needs no new C action; its manual is updated.
No signing/staging/publication policy changes. Linux/kexec/VM execution, alternate
profiles, complete world/kernel/modules/packages/bootstrap/debug and system
CPU/memory/disk performance gates remain open. Make remains the production
default; BIP is excluded.

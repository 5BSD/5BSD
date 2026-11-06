# libcapreclaim installed dynamic test qualification

## Correction (2026-11-06)

The original Make installation uses a dynamic PIE test. The native installation
previously selected the separate static host candidate. Installation now selects
the existing shared-test label, linked against native ATF, libcapreclaim and the
native libc public ABI boundary in the original library order. Native cc_binary
owns compilation and linking; the established link-sequence rule preserves final
library precedence. Source-owned C warning/PIE policy matches the original test
configuration. No implementation or original test body is rewritten.

The installed name remains capreclaim_test. All 28 shared-case targets now execute
its exact stripped installation artifact, not the separate static candidate.
Their declared runtime contains native libcapreclaim, ATF, libc and libsys.
Private execution runfiles supply library lookup; no build-tree or qualification
RPATH is embedded in the installed binary. The static host candidate remains an
additional test variant and is not substituted for the installed program.

## Passed checks

- Normal maintained build-bsd format-5 construction and all 28 original program
  bodies pass, with no skips. The first run executes the corrected body/runtime;
  the subsequent capture run preserves the same body and archive hashes and may
  reuse Bazel's test cache. Do not count them as 56 distinct original cases.
- Complete parent comparison matches all 11 file/link paths, seven distinct
  package directory claims across six paths, exact non-ELF contents, owners,
  modes, flags, tags and link identity against independent original Make.
- Native shared library and installed test ELF metadata/ordered-dependency
  contracts match Make. Original static archive member/symbol comparison passes.
- Both sides' library and program debug separation/name/CRC checks pass (four
  checks). Full DWARF/debugger or raw instruction parity is not established.
- Captured installed body hash matches the tar member used in qualification.
  Additional explicit body/runtime captures leave both package archives identical.
  Production library tar is byte-identical to its earlier complete library capture.
- Actual original/native program metadata matches exactly. All 28 discovered
  original case identities equal the 28 passing original case report identities.
- Explicit loader traces for both metadata programs resolve exactly the four
  declared captured native libraries; no extra DSO or host-library fallback is
  accepted. Host rtld/ldd remain execution prerequisites, not qualified boot images.

The tests exercise their original callback-provider fixtures and temporary file
objects, including actual descriptor rights restrictions. The provider's destroy
callback records names; this does not prove real daemon/ZFS resource destruction.
DTRACE_DOF_INIT_DISABLE is explicitly set only for host functional execution;
registration/firing and a matching booted kernel remain separate requirements.

## Evidence

All paths below are under /usr/obj/usr/src:

- bazel-capreclaim-installed-native-abi-request-r1-20261106 and
  bazel-capreclaim-installed-native-abi-r1-20261106: complete parent and 28 body cases.
- bazel-capreclaim-installed-native-abi-request-r2-20261106 and
  bazel-capreclaim-installed-native-abi-r2-20261106: explicit immutable body/runtime
  captures and the same 28 cases plus the source helper. Reported wrapper count is
  29; the source helper is not an original libcapreclaim body.
- bazel-directory-libcapreclaim-make-r1-20261106: independent original Make control.
- bazel-capreclaim-installed-native-abi-review-r1-20261106: complete installation.
- bazel-capreclaim-installed-native-abi-binary-review-r1-20261106: all three binary
  contracts, captured candidate library/program/debug data.
- bazel-capreclaim-installed-native-abi-final-review-r1-20261106: exact case sets,
  native runtime bindings/loader traces, package-body identity, debug controls,
  production archive identity and all input hashes.

The existing frontend format-5 target/test API, utility installation binary label
and immutable capture machinery suffice; no new C/frontend/backend/signing option
is needed. The manual records this scope. Full library generation/directory and
other installed-test/dependency gaps, whole world/kernel/modules/pkgbase, actual
service/VM/tracing, ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility and
controlled CPU/RAM/disk-I/O/footprint/publication gates remain open. Make remains
default and BIP remains excluded.

# Native capability-library installed tests

## Corrections and results (2026-11-06)

The seven libcapbundle and two libcapimage installed C tests now use the original
dynamic PIE linkage rather than their separate static host candidates. Both
libcapsulert test programs also use native ATF/component/libc ABI precedence.
Native cc_binary owns compilation/linking, with original warning/PIE/PIC policy.
Installed bodies have no build-tree or qualification RPATH. Original Make tests
now use TESTS_LD_LIBRARY_PATH for execution-time lookup instead of embedding
OBJTOP paths in installed programs. Fresh original Make controls pass.

The capimage plain client retains its original directly compiled capimage.c,
shared capimage/crypto dependencies and mac_syscall wrapper. Its narrow source
export is explicit. No implementation or test body is rewritten, no duplicate
symbol suppression is added, and kernel/root cases remain retained for VM work.

| Parent | Installed C test programs | Passing host body targets | Registered ATF cases |
| --- | ---: | ---: | ---: |
| libcapbundle | 7 | 179 | 179 |
| libcapimage | 2 | 14 | 21 |
| libcapsulert | 2 | 11 | 11 |

The 204 passing host targets comprise 203 original ATF bodies and the original
plain client. The first and final compiler-policy runs pass with no skips; these
are 204 unique targets, not 408 distinct cases. Eight capimage kernel/root ATF
cases and the separate 17 capbundle shell-format bodies are unexecuted here.
All 211 original C-program ATF registrations match original Make metadata exactly;
registered privileged cases are not counted as passing bodies.

Complete installation comparisons match 70 component file/link records and 22
component directory claims, including exact non-ELF bytes, owners, modes, flags,
tags and link identity. All 11 test and three library ELF metadata/dependency-order
contracts pass. Two full static archive member/symbol comparisons pass. The
existing raw libcapsulert DTrace path-key symbol difference is retained; its
production tar is unchanged from the earlier independently inspected provider.

All 28 native/original library/test debug separation/name/CRC checks pass.
Every ATF body hash matches its captured installed file. The stripped plain client
also executes successfully directly on both native and original sides, retaining
its original mock-kernel fixture behavior. Startup loader traces bind each program's
complete DT_NEEDED closure to the captured native DSO set without extra libraries.
Host rtld/ldd and entropy/configuration remain host execution inputs; this is not
complete sandbox/reproducibility, dynamic-plugin or boot qualification.

All three production library tars are byte-identical to their earlier full-library
captures. The correction concerns test installation and execution policy, not
production implementation changes. Host ATF functional runs explicitly disable
DOF initialization; no live tracing, real handle/trust enforcement or service/VM
acceptance is claimed. Full DWARF/instruction/ABI parity remains separate.

## Evidence

All directories are under /usr/obj/usr/src:

- bazel-capability-installed-tests-request-r{1,2}-20261106 and
  bazel-capability-installed-tests-native-r{1,2}-20261106: explicit maintained
  frontend requests, all original safe bodies, immutable runtimes and final bodies.
  The final report has 205 wrapper cases: 204 body targets plus the source helper.
- bazel-capbundle-portable-tests-make-r1-20261106 and
  bazel-capsulert-portable-tests-make-r1-20261106: fresh original Make controls with
  portable installed runtime policy. Existing bazel-directory-libcapimage-make-r1-
  20261106 supplies the unchanged original capimage Make policy/control.
- bazel-capability-installed-tests-review-r1-20261106: all three complete component
  inventories and original binary comparisons; raw capsulert failure is preserved.
- bazel-capability-installed-tests-final-review-r1-20261106: actual native runtime
  bindings/loader traces, every original case identity, stripped plain execution,
  debug checks, production archive identities and verified input/report hashes.

Together with CAPRECLAIM-NATIVE-TEST-QUALIFICATION.md, this reconciles all ten
static installed-test substitutions identified in the 23-parent cohort. It does
not prove no further gaps exist elsewhere. Direct/ordered DSO dependencies,
full-library generation/directory policy and whole-system/cross/VM/performance/
bootstrap/cache/sandbox/publication gates remain open. Make remains default and
BIP is excluded. The existing format-5 frontend and installation APIs suffice;
C/backend/signing options are unchanged and the manual is updated.

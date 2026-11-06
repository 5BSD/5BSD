# libfidl installation binary comparison

## Recorded scope (2026-11-06)

The completed GoogleTest-disabled installation-parent capture was compared with
its independent original Make control. The complete 120-path namespace matches;
the earlier directory comparison remains separate evidence. This new check uses
hash-verified captured tar/metadata outputs, the original receipt-bound component
METALOG and verified original file hashes. It does not read shared bazel-bin files.

The shared libfidl_bsd.so.1 and four original installed test programs
(c_binding_test, c_wire_test, ipc_bench, sync_call_bench) pass the maintained ELF
metadata comparison: identity, linkage, ordered dependencies, imported/exported
symbols and versions, and the checker's hardening requirements. Section byte
differences are recorded. Five separate debug files are inventoried but not
qualified by this check; earlier debug separation/name/CRC evidence remains
bounded to that contract. No bodies execute in this comparison.

The static libfidl_bsd.a comparison fails. Native group concatenation places
internal.c after scalar.cc; original Make places it immediately after
handle_close_many.cc. Member order is retained as a real difference. The native
member names use .nopic.o, whose existing comparison normalization is explicit;
this is not the reported ordering difference.

A separate actual-object DTrace check validates both static providers against
runtime's own compiled object. Both have one provider, the same 19 probe schemas,
19 resolved DOF relocation bindings, 26 ordinary sites and zero enabled sites.
The existing amd64 ET_REL resolver checks actual function bindings, offsets and
patched instructions independently on each side. No synthetic objects or alias
replacement are used. Raw symbol comparison still differs in generated DTrace
identifiers for runtime and fidl_provider. dt_link.c:hash_obj derives these keys
from object paths; Make's original absolute path and Bazel's explicit relative
path differ. Do not treat this observation as raw symbol or archive parity.
Live probe registration/firing and final static-consumer behavior remain open.

## Evidence

All paths below are under /usr/obj/usr/src:

- bazel-directory-fidl-no-gtest-native-r1-20261106: immutable parent capture.
- bazel-directory-libfidl-no-gtest-make-r1-20261106: independent original control.
- bazel-directory-fidl-no-gtest-review-r1-20261106: earlier namespace/directory/data
  and split-debug contracts.
- bazel-library-fidl-binary-review-r1-20261106: five passing ELF metadata reports,
  the failed archive comparison, captured candidate payloads and audit source.
- bazel-library-fidl-dtrace-review-r1-20261106: both actual provider/runtime members,
  full DOF inventories, original/native orders and unmodified symbol differences.

## Next action and boundaries

Correct the archive's declared object order using the existing component archive
rule, preserving feature selection and every member. Then rebuild through the
maintained build-bsd workflow and repeat the independent archive/DTrace checks.
Do not change library inputs during the active full-library native/Make controls;
their source identities must remain stable. The mismatch is not fixed yet.

Full ELF byte/DWARF/ABI equivalence, archive equality, original bodies, full world,
kernel/module/package/cross-platform/runtime/performance/bootstrap qualification
remain separate gates. Make stays the production default. BIP is excluded.
No frontend schema/backend/signing/manual option changes are required for this
read-only qualification; existing format-5 inputs and capture checks are used.

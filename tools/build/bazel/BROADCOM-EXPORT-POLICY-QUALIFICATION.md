# Broadcom bus module export-policy correction

## Finding (2026-11-02)

The first native Broadcom conversion matched original Make byte for byte, but a
separate strong-import/provider audit found four modules whose default empty
export policies hid their shared public implementation: bcma, bhnd_pci, siba and
bhndb_pci. Five dependent modules required 28 distinct hidden symbols (37 consumer/
provider references), including bus probe/attach operations, shared driver classes,
PCI/PCIe helpers and BWN hardware configuration tables. Make byte parity alone
would have preserved this actual load-time dependency defect.

Add explicit EXPORT_SYMS=YES before the kmod rules in those four Makefiles,
consistent with the adjacent bhnd and bhndb provider modules. Their native Bazel
declarations use the same explicit export-all policy. The global default remains
unchanged. These modules share a public bus implementation, so enumerating only
today's consumers' function names would create an incomplete, fragile API list.

## Evidence

Under /usr/obj/usr/src, bazel-broadcom-module-make-references-r1-20261102 and
bazel-broadcom-modules-review-r1-20261102 retain the original 24 build/install
controls, matching native artifacts, and rejected localized-provider findings.
bazel-broadcom-provider-make-references-r2-20261102 records eight fresh successful
Make controls after the correction (four providers, plain and CTF/debug).

Final native profiles bazel-broadcom-modules-ctf-debug-native-r6-20261102 and
bazel-broadcom-modules-plain-native-r3-20261102 match the corresponding corrected
Make artifacts/metadata. All twelve final plain module files equal Make bytes;
CTF/debug runtime sections match except build-ID/debug-link values. A registered
host artifact test checks actual cross-module bindings, and an intentionally
localized real BCMA provider reproduces the failure in the negative fixture.
The final symbol-closure observer reads actual ELF bindings, including global
IFUNC definitions; an earlier nm-case-only observer incorrectly reported memory
primitives and is retained rather than accepted as final closure evidence.

## Limits

This closes the identified local-only bus-provider defects, not complete module
loadability. The qualified GENERIC kernel and this batch still lack GPIO interface
and gpiobus definitions required by bhnd/BWN. Full module aggregation and runtime
loading need those providers. Other module groups need the same dependency review;
GENERIC built-ins may mask a missing optional-module export. No device loading,
wireless operation, host installation or reboot was performed.

No build-bsd CLI/publication/security-policy input changes are needed for these
explicit source Make policies. The accompanying maintained frontend host-artifact
contract, tests and manual are qualified and committed separately.

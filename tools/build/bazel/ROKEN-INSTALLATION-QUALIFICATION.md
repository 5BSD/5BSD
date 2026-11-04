# Roken native installation and original regular/PIC qualification

## Implementation

kerberos5/lib/libroken/installation.bzl declares the maintained original library
installation contract: static archive, versioned shared library and relative
symlink, eleven public headers (including native-generated roken.h), and separate
debug file. Typed install/archive rules carry original root:wheel ownership,
0444 file and 0755 symlink/directory modes, kerberos dev/lib/dbg tags and the two
original debug directories. Source header visibility is explicit and limited to
the owning library package. The internal vers library remains uninstalled.
A PIC own-object archive target exposes the actual shared-link objects for the
independent comparison; it does not add another installed archive.

## Evidence (2026-11-04, under /usr/obj/usr/src)

- bazel-roken-install-native-r1-20261104/receipt.json passes maintained format-5
  build-bsd bazel-test with 16 jobs, the selected libraries/consumer/installation
  targets and six selected test targets. Results can reuse prior test caches;
  actual generation execution is recorded in its preceding qualification.
- bazel-heimdal-roken-make-r4-20261104/receipt.json passes fresh original Make
  build/stage, metadata, explicit WITHOUT_MITKRB5 and bound original make-roken.
  Component and external source hashes are frozen/rechecked for this comparison;
  stage-review/source-inputs.json retains the external source inventory.
- Native original-library-review/review.json binds all 118 object contexts to
  captured native archives and original Make object paths/hashes. All 59 regular
  and 59 PIC allocated code/data, symbolic relocation and external-symbol
  contracts match: 114 raw exact; resolve and snprintf in each variant require
  exact original compiler recipe controls with -fmacro-prefix-map=/usr/src/=.
  Controls use private object/dependency outputs, preserve originals and check
  recorded inputs before/after. Debug-only bytes are outside these contracts.
- Native stage-review/review.json compares all 17 typed installation records
  against original component.METALOG: path/type, owner/group, mode, tags and link
  targets. Tar payload metadata agrees with those records. All eleven header
  payloads match original staged bytes, including generated roken.h.
- Native stage-review/shared-interface.json compares versioned exports and
  shared ELF identity, SONAME and hardening against the original linked library.
  Ordered NEEDED requirements also match: libcrypt.so.5, libc.so.7. This is not
  full calling-convention or whole linked-byte parity.
- Native stage-review/archive-order-and-original-debug.json verifies all 59
  static archive member names in original order and the original installed
  library/debug CRC pair. The native installed pair also passes CRC validation.
  An initial check against the uninstalled original .so intermediate correctly
  rejected its retained symbol table; the installed original stage is the proper
  comparison for the installed stripped native artifact.

The frontend/backend already support these typed contributions and explicit
qualification targets. No C frontend/schema change is required. The manual and
roadmap are updated with the actual bounded result.

## Remaining work

Original compile_et link/install/generated-output parity still needs explicit
shared-library reference bindings. Complete the other Heimdal components and
parent selection, alternate configurations/architectures, full debug/source lookup,
world/pkgbase/bootstrap/VM/cache/performance gates. Installed archive metadata
parity does not establish complete pkgbase subpackage/publication correctness.
Full regular archive, shared library and DWARF byte equality is not claimed.
Make stays default; BIP remains excluded.

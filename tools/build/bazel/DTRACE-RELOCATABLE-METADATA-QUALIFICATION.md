# Explicit relocatable DTrace metadata inspection

## Interface and scope

`dtrace-dof-inventory.py --relocatable-metadata --binary OBJECT [--symbols CODE]`
inspects amd64 ELF64 little-endian relocatable objects. The default still requires
a linked executable/shared object. The new mode rejects linked-load-address site
claims; it does not establish loader registration, process load addresses or live
probe firing. `--symbols` supplies an explicit matching code object when the
provider's alias is undefined. A defined alias is always resolved from its actual
relocation owner, even if a different companion was supplied.

Every emitted probe requires its actual ELF DOF relocation and compatible user
relocation. The resolver checks the hidden global function symbol, executable
section/file bounds, function range, ordinary NOP/RET sites and enabled XOR/NOP
sites. Missing, duplicate, unsupported and unconsumed relocations fail. Equal
unresolved zero address fields alone are never accepted as site parity.

The supported ELF/user relocation pairs are amd64 PC64/DOFREL and 64/SETX.
Other architectures and unsupported encodings fail explicitly. Production
build-bsd input/staging/security interfaces are unchanged; its existing format-5
native target/test API runs the maintained regression.

## Qualification performed (2026-11-02)

- One normal Bazel test target ran all **19 actual unittest methods**, with the
  retained log distinguishing these methods from its single wrapper XML case.
  Independently constructed ELF/DOF fixtures cover both relocation pairs,
  undefined/matching/wrong companions, defined-owner precedence, incorrect
  aliases/relocations/instructions, symbol/function/site bounds, unconsumed
  relocations, foreign architecture, nonzero unresolved addresses, ordinary
  linked output and the incompatible CLI address-claim combination.
- Actual PAM provider/core controls reject the default-mode relocatable input,
  a changed real relocation kind and a corrupted real instruction patch.
  Original artifact hashes remain unchanged; only disposable negative copies
  were modified.
- The previous and extended inspector produce exactly equal default output for
  the same immutable six-probe linked pam_deny library.
- The final native static PAM candidate and fresh independent Make reference
  have matching 20 provider schemas, 56 probe records, 100 ordinary sites and six
  enabled sites. Every relocation binds matching actual function bytes, value,
  size and offsets. All 1,560 archive member symbols match with multiplicity
  after expressing only independently proven `hash_obj(path)` aliases as their
  exact source-object identities. Both archives retain all 56 members in order
  and all 56 text sections match.

The original strict symbol comparison still fails on generated DTrace path keys
and is retained. The Make tool uses absolute object paths; the declared native
DTrace action uses explicit relative object paths. Each differing decimal key
was recomputed with the original `dt_link.c` FNV algorithm and bound to its
actual selected object path. No general symbol normalization or production
artifact rewriting was introduced.

Evidence under `/usr/obj/usr/src/`:

- `bazel-dtrace-relocatable-test-qualification-r1-20261102`
- `bazel-dtrace-relocatable-real-controls-r1-20261102/report.json`
- `bazel-static-pam-dof-audit-r1-20261102/report.json`
- `bazel-static-pam-archive-audit-r2-20261102/report.json`
- `bazel-static-pam-native-qualification-r10-20261102`
- `bazel-static-pam-make-r3-20261102/receipt.json`

This is metadata/site qualification, not full PAM ABI or authentication
qualification. Remaining PAM work includes final compiler/prerequisite/install
review, reduced configurations, non-DOF relocation/string review and actual
installed authentication/tracing. No host authentication or tracing was changed.

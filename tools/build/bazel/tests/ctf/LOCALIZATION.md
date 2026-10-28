# Module CTF localization regression

`localization-audit.py` is an explicit-tool diagnostic, not a release gate or a
replacement build workflow. It compares two transformation orders against a
baseline whose data and function types must agree with the fixture C sources.
It exits nonzero when either transformation corrupts a type association. The
second transformation is a rejected alternative; fixing the first does not
require making fuzzy matching a supported module build path.

Required inputs are `--cc`, `--ld`, `--objcopy`, `--ctfconvert`, `--ctfmerge`,
`--ctfdump`, and a fresh `--work` directory. Repeat
`--ctf-library-directory` for explicitly selected CTF runtime libraries.
Use the maintained SDK compiler/linker/objcopy and Bazel-built CTF tools for
native qualification. An optional comparison against installed CTF tools must
be labeled separately. Outputs belong under `/usr/obj`.

The fixture retains exports before symbols being localized, forcing a change
in the relative order of function and data symbols. A second translation unit
contains static functions and data with the same names but different types.
The checker identifies fixture symbols by name, kind, section, offset, and size;
it rejects ambiguous identities. This limited diagnostic identity is not a
proposed production symbol-remapping algorithm. Type names, rather than CTF
numeric type IDs, determine correctness.

Retained evidence (2026-10-28):

- `/usr/obj/usr/src/ctf-localization-fixture-r2-20261028`: selected SDK tools
  with installed CTF tools.
- `/usr/obj/usr/src/ctf-localization-native-r2-20261028`: selected SDK tools with
  native Bazel-built CTF tools and explicit runtime library directories.
- Both baselines pass. Both transformation orders fail for data and functions.
  Each directory retains commands, tool hashes, objects, CTF dumps and JSON.

The source LLVM objcopy currently retains symbol objects through its
`SymbolTableSection::updateSymbols` stable partition, but has no `.SUNW_ctf`
rewriter. Preserving CTF associations using those exact symbol identities is a
candidate implementation direction. It is not implemented or qualified.
Any implementation must cover object and variable-length function tables,
compressed input, removal/renaming/localization, byte order, and malformed
input. Do not replace this with name-only matching or accept Make parity as
proof of valid types. The real `nullfs_artifacts_test` remains failing.

Frontend assessment: these diagnostic fixtures do not change build inputs,
packaging or publication interfaces. No build-bsd C change is required. The
existing format-5 frontend still selects the real nullfs Bazel test. When the
production CTF fix lands, update and qualify its declared tool closure and
both maintained Make and native Bazel module actions together.

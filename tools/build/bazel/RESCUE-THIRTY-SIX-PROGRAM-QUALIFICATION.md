# Native thirty-six-application rescue construction

## Source-owned additions (2026-11-05)

The native core adds ls, df, ps, pkill, tail, tee, id, chroot and chown. It now
constructs 36 of the default catalog's 103 applications. Each package declares
its own rescue sources, headers, compiler objects and relevant settings through
the maintained rescue macro. LS_COLORS, PS_CHECK_KEYWORDS and AUDIT definitions
are preserved. Id retains USE_BSM_AUDIT when configured. Tail, tee and chroot
retain Make's RESCUE provider exclusions; tail also omits WITH_CASPER as Make
requires. Df and chown retain their DTrace providers. Original hosted program
rules are unchanged.

The selected core now needs native jail, kvm, elf, tinfo, util, xo, z and m static
archives before libc/compiler_rt. A declared chain of ordinary cc_import targets
retains lazy extraction and the selected original CRUNCH_LIBS order. The actual
application objects remain direct objects, with each original ld-r/crunchide
stage intact. No SDK archive replaces a native library, and normal libraries'
transitive CcInfo does not accidentally expand the parent's own object list.
Libz grants only the rescue package additional access to its static archive.

## Evidence

Retained evidence is under `/usr/obj/usr/src/`.

- `bazel-rescue-36-native-r2-20261105`: maintained build-bsd invocation, sixteen
  jobs, all selected programs/archives/startups captured. The runtime wrapper
  passes 64 actual methods; the source-settings wrapper passes 28. New cases
  exercise private-directory ls, read-only df/ps, numeric id, private tail/tee,
  chown to the test's own numeric identity and usage rejection without signalling
  or changing root. Host tests still do not execute sync or enable DOF startup.
- Native r1 failed analysis because libz's static archive was private. Explicit
  access for the legitimate rescue package fixes that dependency; the failed run
  remains failed. No private-target validation is bypassed.
- `bazel-rescue-nine-more-make-r1-20261105/report.json`: fresh actual original
  generated nine `_make` targets with sixteen workers and isolated object roots.
  4542 source/policy/header/tool bindings are checked before and after. Twenty
  actual C objects retain original nested RESCUE/SSP/non-PIE policy, and two
  provider objects are generated. The original recipes and consumed headers are
  recorded. Fresh original crunchgen/crunchide tool receipts are reused with
  source/tool hash checks, rather than inferred from mutable PATH binaries.
- `bazel-rescue-36-object-review-r1-20261105/review.json`: all 22 compiler/provider
  objects are compared without rewriting bytes. Sixteen C contracts match
  directly. Df/chown differ only in DTrace aliases; ps keyword.o and pkill.o
  retain raw assertion-filename string/relocation differences. Two provider
  objects retain DOF/alias encoding differences. No raw debug equality is claimed.
- `bazel-rescue-36-provider-review-r1-20261105/review.json`: maintained ET_REL DOF
  checks establish schemas, actual symbol-relative probe/function locations,
  metadata and patched sites for diskspace/fileowner providers. Every differing
  function alias hash agrees with the real native relative/original resolved
  object path. All traced C allocated bytes and nondebug relocation contracts
  agree. Raw DOF encoding, live registration and firing remain separate gates.
- `bazel-rescue-36-filename-controls-r1-20261105/review.json`: two isolated
  original compiler recipes, with only executable resolution and the explicit
  `-fmacro-prefix-map=/usr/src/=` control, match native allocated/symbolic object
  contracts. Actual assertions in ps/keyword.c and pkill.c embed __FILE__;
  original Make passes absolute source paths while Bazel passes relative ones.
  Input hashes and untouched original objects are checked before/after. Native
  production flags, native bytes and original baseline bytes are unchanged.
  These controls explain the differences; they do not establish raw baseline
  byte identity or independent DWARF parity.
- `bazel-rescue-36-pipeline-review-r1-20261105/review.json`: fresh original
  crunchgen and generated Make receive identical captured native application,
  ordered archive and startup inputs. Main C and all 74 whole-byte comparisons
  pass: main object, 36 stubs, 36 combined ld-r/crunchide objects and the complete
  executable. AMD64 ET_EXEC, no interpreter/dynamic segment, nonexecutable stack
  and GNU_RELRO checks pass. This proves original pipeline/link behavior with
  identical inputs, not independent reconstruction of all libraries or world.

## Integration and remaining scope

The maintained format-5 build-bsd interface already accepts these targets and
settings. Its manual, completion plan and observability ledger are updated. No
C dispatcher/schema, signing, installation or publication helper change is needed.
No host installation, upgrade or reboot occurred. Make stays production/default;
BIP stays excluded.

Complete the other 67 default applications and their actual rescue library
variants, option/architecture coverage, real rescue installation/aliases/helper
paths and debug/metadata/pkgbase comparisons. Then complete combined world/kernel/
modules, reproducible bootstrap, hardware/combined publication, VM/runtime and
CPU/memory/disk/cache/sandbox acceptance. A passing intermediate core does not
close these full-system gates.

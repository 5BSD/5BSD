# Native twenty-seven-application rescue construction

## Source declarations (2026-11-05)

The native `//rescue/rescue:rescue_core` now includes date, chio, kenv, setfacl,
stty, kill, sync and dd in addition to the previously constructed nineteen
applications. This is 27 of the current 103 default catalog programs. It remains
an AMD64 intermediate contribution, without a complete rescue install target.

Each application owns its sources, headers and compiler-object list. The new
`bsd_rescue_application.bzl` macro shares the already checked nested-child warning
policy; compilation remains normal `cc_library` toolchain actions. These variants
retain RESCUE, ordinary debug/SSP and no PIE/PIC. The parent-only MK_SSP=no is not
mistakenly applied to child programs. Declared DTrace transformations preserve
dd, kill and sync providers. Kenv/setfacl deliberately omit coverage providers
because their original Makefiles exclude RESCUE and BOOTSTRAPPING. Their ordinary
hosted program targets retain their providers.

The selected core still requires DTrace. Full rescue configuration composition,
remaining application/library variants and other target architectures are open.

## Evidence

All evidence below is under `/usr/obj/usr/src/`.

- `bazel-rescue-27-native-r2-20261105` passes normal maintained build-bsd
  qualification with sixteen jobs. The runtime wrapper runs 54 actual methods,
  while the separate source-settings wrapper runs 28. New cases cover read-only
  date formatting/parsing, binary/swab/private sparse dd output, kill signal-name
  parsing without sending signals, nonterminal stty rejection, hardware-free chio
  usage, invalid kenv options and invalid ACL rejection on a private file. Sync is
  constructed and linked but intentionally not executed on the host: its source
  calls global sync even when given apparent options. DOF initialization is
  disabled before child startup; these tests do not establish live probe firing.
- Native r1 compiled/linked but failed one runtime expectation. The test expected
  generic ioctl error text; maintained stty explicitly reports that stdin is not
  a terminal. Only that expectation changed. The failed logs and failure record
  remain rejected, not relabeled as a successful qualification.
- `bazel-rescue-crunchgen-make-r1-20261105` and
  `bazel-rescue-crunchide-make-r1-20261105` are fresh maintained original tool
  builds, with supported recipe metadata and bound source inputs. Earlier tools
  whose evidence had been cleaned up were not silently reused.
- `bazel-rescue-eight-more-make-r1-20261105/report.json` runs the actual original
  generated eight `_make` targets with sixteen workers and isolated object roots.
  It binds 4541 original source/policy/public-header/tool inputs before and after
  compilation and records actual compiler/provider recipes and consumed headers.
  All 25 C objects retain RESCUE, SSP and no PIE/PIC; provider defines match each
  original application's actual rescue condition. Three providers are produced.
- `bazel-rescue-27-object-review-r1-20261105/review.json` records all 28 object
  comparisons without modifying bytes. Twenty-two C objects match allocated ELF
  sections, nondebug symbolic relocations and external symbols directly. Three
  traced C objects differ only in external path-derived aliases. Provider objects
  retain raw DOF encoding/alias differences; full raw debug/DOF equality is not
  claimed.
- `bazel-rescue-27-provider-review-r1-20261105/review.json` uses the maintained
  ET_REL DOF checker on all three provider/function pairs. Schemas, metadata,
  symbol-relative probe locations, bounded actual function definitions and patched
  sites agree. Every differing alias hash is independently checked against the
  real native relative/original resolved object path. All C allocated bytes and
  nondebug relocation contracts match. This does not establish registration or
  event firing, nor complete raw DOF-section encoding equality.
- `bazel-rescue-27-native-r3-20261105` passes and captures every selected program,
  archive and startup input for the independent pipeline comparison. Cached test
  results are reused, not counted as another execution of the same methods.
- `bazel-rescue-27-pipeline-review-r1-20261105/review.json` drives fresh original
  crunchgen and generated Make on those identical captured native inputs. Main C
  matches, and all 56 whole-byte comparisons pass: main object, 27 stubs, 27
  original ld-r/crunchide combined objects and the complete executable. ELF checks
  establish AMD64 ET_EXEC, no interpreter/dynamic segment, nonexecutable stack and
  GNU_RELRO. This proves original pipeline/link behavior with identical inputs;
  it does not independently rebuild all libraries or qualify full rescue.

## Frontend and remaining gates

Existing format-5 targets/settings, SDK declarations and native artifact capture
support the new variants. The frontend manual, completion plan and observability
ledger are updated. No dispatcher/schema, installation, signing or publication
backend change is required. Make stays production/default; no host installation,
upgrade or reboot occurs, and BIP remains excluded.

Continue the other 76 default rescue applications, their actual RESCUE-specific
library dependencies and complete option/ABI selection. Finish the real rescue
installation, aliases, helper paths, debug/metadata/pkgbase parity and runtime.
Then join complete world/kernel/module/package construction and qualify bootstrap,
hardware/combined publication and CPU/memory/disk/cache/sandbox behavior. None of
those full-system gates is closed by this intermediate executable.

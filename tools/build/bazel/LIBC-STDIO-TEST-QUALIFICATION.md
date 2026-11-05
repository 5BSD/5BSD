# Complete native libc stdio-test construction (2026-11-05)

## Implementation

All thirty original stdio ATF C programs (twenty local, ten imported NetBSD)
now build and install through source-owned native declarations. The fopen2 source
alias remains distinct from imported fopen. NetBSD compatibility applies only
to imported programs, libmd only to eintr, and libm only to printfloat/scanfloat.
Native public libc/ATF interfaces and matching native runtime libraries are
explicit. Four original C23 format-test exceptions retain -Wno-format; warning
checks elsewhere remain enabled. No original C test is rewritten or substituted.

The source-owned case table selects 75 original cases: memory streams, getdelim,
mkostemp, integer/floating formats and rounding, C23 narrow/wide print/scan
formats, and interrupted I/O. The installed programs retain every original ATF
case regardless of the selected runtime subset. A single inventory supplies
complete installation, sorted Kyua metadata and split debug: thirty executables,
thirty debug files and one Kyuafile. Typed tar/metadata/directory providers remain
available for future parent composition.

Numeric locale fixtures are actual maintained native outputs. Requested locale
names come from the source tests; canonical source selection follows the shared
numericdef/numericdef_unicode inventories and aliases. Unknown/unsupported
canonical mappings fail instead of resolving against host-installed locales.
Distinct source-owned alias labels preserve requested runtime names even when
canonical files are shared. Only LC_NUMERIC is required by these cases. The
existing ATF adapter places declared files under its private PATH_LOCALE tree;
no system locale installation or program rewrite is needed. Link/runtime library
and source/format/case/data inventories reject unknown program keys.

## Evidence

All directories below are under /usr/obj/usr/src.

- bazel-libc-stdio-native-r1-20261105: maintained build-bsd bazel-test, AMD64,
  sixteen jobs. All thirty programs and the installed archive build. All 75
  selected original ATF cases execute freshly and pass; source-settings is
  cached (76 passing targets). Locale-dependent floating and C23 cases use
  declared native numeric data, not host locale paths. DOF init is explicitly
  disabled. Input: bazel-libc-stdio-request-r1-20261105/inputs.json.
- bazel-libc-stdio-review-r1-20261105/review.json: complete independent comparison
  against the fresh original libc parent at
  bazel-libc-installation-make-r1-20261105. All 61 installed file inventories,
  owner/group/mode/tags/flags and exact Kyuafile bytes agree. Every original
  program/debug payload matches its Make METALOG hash. All thirty native and
  original program ELF identity, PIE/interpreter, ordered NEEDED dependencies,
  dynamic symbols/versions and hardening contracts match; both native/original
  debug filenames and CRCs are checked. Actual original source inputs are
  distinguished from new native declarations and remain checked.
- bazel-libc-stdio-native-r2-20261105: final maintained frontend run also captures
  the numeric_fixtures target. All 76 test targets pass as cache hits. Input:
  bazel-libc-stdio-request-r2-20261105/inputs.json.
- bazel-libc-stdio-final-bindings-r1-20261105/review.json: all three final
  archive/metadata/directory outputs are identical to the independently reviewed
  r1 capture, and four actual native numeric fixture payloads are separately
  resolved from the immutable capture with their receipt/manifest/content hashes.

These results establish selected-profile construction, complete installed file
metadata, bounded ELF/debug coherence and 75 original runtime cases. Raw program/
debug byte equality, full ABI/semantic parity, complete hermetic runtime closure
and other locale categories are not claimed. The Make reference uses its selected
SDK/common libraries; it is not a new independent full-world rebuild.

## Remaining scope and frontend

Other stdio cases, including additional imported/child-process/error behaviors,
need installed-system qualification. Remaining libc and other test roots, parent
Kyua/helper/data traversal and full case-discovery/privilege/PTY execution remain
open. Full test-enabled parent guards remain active. Source-owned archive
ordering, independent whole-world/debug/pkgbase parity, other ABIs/options,
bootstrap, VM/services, hardware/publication and comparative CPU/memory/disk/cache/
sandbox gates remain required. Live DTrace firing and audit delivery remain open.

Existing maintained format-5 targets/tests express construction and all fixture
inputs. No C frontend, backend schema, staging/signing/publication or security
policy change is needed. The manual and completion plan record the contribution.
Make stays production/default; BIP is excluded. No host installation, upgrade,
reboot, locale installation or service reconfiguration occurred.

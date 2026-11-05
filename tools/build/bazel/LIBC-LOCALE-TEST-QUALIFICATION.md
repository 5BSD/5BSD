# Native locale-test construction and bounded host execution (2026-11-05)

## VM follow-up

The later installed-resource VM executes all forty locale cases: thirty-nine pass and iconv_samples retains its original PR 59019 expected failure. The ten pending resource cases below are now exercised for this selected profile. See INSTALLED-ATF-VM-QUALIFICATION.md for final evidence and scope. The remaining sections record the earlier checkpoint.


## Construction

All twenty-eight original selected locale programs now build/install natively:
eighteen local programs and ten imported NetBSD programs. Five _2 aliases retain
their distinct local source identities. NetBSD compatibility headers/archive apply
only to imported programs; the original -Wno-stack-protector diagnostic option
applies only to imported t_wctomb.c. Stack protection remains enabled. No original
C source or test expectation is rewritten. Original disabled io_test remains
disabled, matching Make rather than being counted as a migrated selected program.

All fifty-seven installed regular file records are present: twenty-eight original
programs, twenty-eight split debug files and exact original Kyua. Native ATF/libc
interfaces and runtime libraries are explicit. Typed installation archives remain
available for future full-parent composition; this leaf does not remove guards on
the unfinished full test hierarchy.

Nine logical locale names resolve to eight physical LC_CTYPE payloads. Canonical
selection follows the maintained share/ctypedef LOCALES/ALIASES inventory, rather
than a separately copied canonical map or host locale lookup. Requested names
retain distinct aliases even when en_US.UTF-8 shares C.UTF-8 data. Private runtime
PATH_LOCALE directories contain declared native data. Unknown supported mappings
fail analysis. Native and original Make payloads are byte-identical for all eight
physical fixtures.

## Runtime scope and missing scenarios

The original programs register forty cases. Thirty run in the host qualification
with native libc/libsys/ATF and private LC_CTYPE data. All thirty pass, including
EUC-JP/CN, Shift-JIS, GB18030, Big5, UTF-8, multibyte state, wide-character scans,
wcstod and C/POSIX/C.UTF-8 newlocale behavior.

Ten cases in c16rtomb_test, mbrtoc16_test and iconv_test remain installed-resource
VM work. With the selected ICONV-enabled libc, these require real absolute-path
Citrus modules, encoding databases and charset maps. They are built and installed,
not executed against host-installed resources and not counted as runtime passes.
Existing installed-path iconv fixture/harness work is the starting point for this
remaining qualification; that previous fixture does not prove these ten new cases.

Seven imported passing cases preserve original early returns for unavailable
individual locale scenarios. Their logs name ja_JP.ISO2022-JP,
ja_JP.ISO2022-JP2 or zh_TW.eucTW. Those names are absent from the original maintained
base ctypedef inventory; the review checks absence against that inventory rather
than authorizing missing fixtures through a checker allowlist. The programs still
exercise their supported locales or C vectors, but these unavailable scenarios
are not claimed exercised. No dummy locale is generated to make a lookup succeed.
This is a limit of original base test coverage, not an ATF skipped-case count.

## Evidence

All directories below are under /usr/obj/usr/src:

- bazel-libc-locale-native-r1-20261105: maintained frontend builds all programs,
  complete installation and fixture group. Thirty original host cases pass freshly,
  with two cached policy targets; detailed reports contain thirty-two passes.
- bazel-libc-locale-review-r1-20261105: complete independent original Make file
  inventory/ownership/modes/package/debug tags, exact Kyua and scoped physical
  directories match. All twenty-eight distinct program ELF identity, ordered
  dynamic dependencies/interfaces/versions and hardening contracts pass. Native
  and Make debug filenames/CRCs pass. Original stage/receipt/METALOG come from
  bazel-libc-installation-make-r1-20261105 with its prepared SDK, not a fresh
  independent whole-world toolchain bootstrap.
- bazel-libc-locale-native-r2-20261105: final thirty-two targets pass from cache;
  three actual native runtime DSOs and eight canonical fixture payloads are captured
  along with the installation. Cached outcomes are not labeled fresh executions.
- bazel-libc-locale-data-review-r1-20261105: all eight captured LC_CTYPE payloads
  match the original stage from bazel-shared-ctypedef-make-r2-20261105 byte-for-byte,
  with original METALOG/source/reference hashes checked. All twenty-eight actual
  native and original programs produce identical full -l ATF registration/metadata
  for forty cases, using captured native runtime DSOs. The configured suite selects
  exactly thirty host cases and none of the ten pending resource cases. Detailed
  result/log inspection retains unsupported-scenario messages and asserts that none
  names a maintained available locale. Logs remain byte-preserved, including their
  legitimate non-UTF-8 sequence output. All three final installation outputs retain
  identical hashes to the independently reviewed r1 payloads.

## Maintained integration and next work

Existing explicit-input labels, targets/tests and format-5 artifact captures
express this contribution. build-bsd.c, backend selection, schema, signing and
publication helpers need no change. The manual and completion/audit ledgers record
this checkpoint and its limits in the same change.

Next, qualify the ten installed-resource cases with native Citrus modules/data and
all required LC_CTYPE fixtures at their real installed paths in a disposable VM.
Keep original case outcomes and resource limits; identify every bootstrap runtime
input separately. Then continue remaining libc roots and complete parent traversal.

This checkpoint proves selected AMD64 construction/installation/interface contracts
and thirty bounded host cases, not complete locale runtime coverage, other ABIs/
options, raw ELF/debug equality, full installed hierarchy, live DTrace/audit or
whole-system bootstrap/resource/cache/sandbox/pkgbase/publication acceptance.
Make stays production/default; BIP stays excluded and full-tests guards remain.

# Original AMD64 iconv test installation (2026-11-06)

The original iconvctl_test now contributes its normal program, separate debug
file and Kyuafile through typed installation rules. All three non-directory
records match the independent original Make installation, including ownership,
modes, package/debug tags and directory attributes. Kyuafile bytes match. The
program dynamic ELF contract and both native/Make debug-link filenames and CRCs
pass; raw ELF/debug byte equality is not claimed. The source and Makefile remain
unchanged. Warning policy retains the original WARNS=6. Native ATF and libc ABI
inputs are declared explicitly. The old iconvctl_runtime_program fixture name
remains an alias to the installed program. Selection requires AMD64/FreeBSD and
ICONV enabled; other architectures and the disabled profile are not qualified here.

The first native build passes action execution but independent review rejects
its libc-before-ATF DT_NEEDED order. An explicit final-consumer link sequence with
the native ATF shared-library import restores Make's ATF-before-libc contract.
The failed first review and capture remain retained. The verifier was not weakened.

Actual native and original Make ATF -l output matches for the single
iconvctl_trivialp_test registration. Listing uses explicitly captured native
libc/libsys/ATF DSOs from the preceding gen qualification, independently bound in
the case review. No case body is executed here: the program requires real
absolute-path Citrus modules/data. Earlier prototype runtime evidence remains in
ICONV-RUNTIME-QUALIFICATION.md and does not qualify these newly captured bytes.
The source-settings test passes through the maintained frontend; that helper
result is not reported as an iconv case pass.

Evidence roots under /usr/obj/usr/src:

- bazel-libc-iconv-request-r1-20261106/inputs.json: explicit format-5 request.
- bazel-libc-iconv-native-r1-20261106/: initial build, rejected ELF order.
- bazel-libc-iconv-review-r1-20261106/audit.py: retained initial audit.
- bazel-libc-iconv-native-r2-20261106/receipt.json: final passed build/capture.
- bazel-libc-iconv-review-r2-20261106/review.json: final installation/ELF/debug
  review, hash-bound archives and original Make source/payload checks.
- bazel-libc-iconv-case-review-r1-20261106/review.json: case listings and explicit
  prior runtime-library bindings. Each review retains its audit script.
- bazel-libc-installation-make-r1-20261105/: independent original full libc parent
  installation, with source receipt and METALOG.

The maintained build-bsd format-5 frontend already carries these explicit targets;
no frontend C/schema, signing, staging or publication policy change is needed.
The manual and completion plan are updated together. Full libc parent traversal,
SSP, installed-resource execution and all whole-system qualification gates remain
open. Make stays production/default; BIP remains excluded. No host installation,
upgrade, module load, reboot or VM launch is performed.

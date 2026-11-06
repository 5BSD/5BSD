# Native package file-flag preservation

## Corrected integration (2026-11-06)

The source-owned native pkg driver previously rejected any nonempty file flag.
That prevented packaging such base payloads as libc's schg-marked shared library.
Its temporary tar extraction also attempted to apply flags to the build tree.

The driver now checks archive SCHILY.fflags against the declared installation
record, defers flags during temporary extraction with tar --no-fflags, and passes
the declared flags through pkg's standard fourth plist attribute. Directory plist
entries carry their archive flags too. Newline/parenthesis injection is rejected.
The existing source archive writer remains responsible for its qualified flag
vocabulary. No production file list or package ownership was changed.

The maintained native-package-check tool now compares archive flag bits using
its existing libarchive parser and the source installation archive's flags,
rather than requiring zero. Inspection extraction defers flags; archive flags
are verified independently. Directory payloads are distinguished from regular
files in package partition and extracted-object checks. This does not apply
flags on the host or weaken the flags persisted in the produced package.

The local ports pkg-2.8.4 source confirms this standard interface in
libpkg/pkg_ports.c parse_keyword_args: the fourth plist attribute is passed to
strtofflags. The actual qualification tools are the explicitly selected SDK pkg
and tar, not an arbitrary binary selected from that ports work directory.

## Tests and retained evidence

Both runs use the maintained build-bsd bazel-test frontend, format-5 explicit
inputs and all 16 logical CPUs. The new pkg_create_flags_test invokes the real
driver/pkg/tar with six cases: ordinary, schg file, uchg file, uchg directory,
file-flag mismatch and directory-flag mismatch. Four packages succeed with exact
payload and PAX flag checks; both mismatches are rejected before a package is
produced. The existing six-case pkg_create_directories_test also passes, covering
explicit/file-only/layout-only directory ownership and three invalid inventories.
Two passing Bazel wrappers represent twelve actual fixture cases, not twelve
installed-system or original Make test cases.

The successful package fixtures are preserved in Bazel undeclared test outputs.
The inspection audit freezes 25 emitted files after checking the passed result,
matching logs/XML against the maintained immutable test report, canonical local
BEP paths and source/copy hashes. It independently inspects all four actual pkg
archives through native-package-check, including libarchive flag-bit checks,
configuration and directory inventory, extracted payload bytes/modes and links.
This external inspection uses the host libarchive comparison control; it is not
a hermetic target-platform execution claim. No package is installed.

Evidence under /usr/obj/usr/src:

- bazel-pkg-flags-request-r1-20261106/inputs.json.
- bazel-pkg-flags-native-r1-20261106: passed initial real-pkg tests.
- bazel-pkg-flags-native-r2-20261106: passed tests with retained successful fixtures.
- bazel-pkg-flags-inspection-r1-20261106: retained failed inspection invocation;
  --packages was incorrectly given index.json rather than its containing directory.
- bazel-pkg-flags-inspection-r2-20261106: passed all four independent inspections,
  retained audit, emitted fixtures, command outputs and hash-bound review.

These are synthetic packaging fixtures, not a complete clibs package or original
Make package parity. Whole-world partitioning, complete pkgbase manifests and
scripts, package-driven construction/account preservation, installation, upgrade
and runtime/performance/cross-target/bootstrap gates remain open.

## Root-dependent next checks

This session runs as uid 1001 and has neither sudo nor doas. FreeBSD private jail
creation requires root; rootless package creation above does not establish jailed
construction, installed login/PAM/SSH or account migration behavior.

Once a reviewed candidate, package inventory and initial generated layout exist,
the maintained root-shell commands are:

```sh
build-bsd plan construct --root "$candidate" --inventory "$inventory" \
    --generated "$initial_layout" --output "$qualification_output"
build-bsd construct --root "$candidate" --inventory "$inventory" \
    --generated "$initial_layout" --output "$qualification_output"
```

All four variables must name explicit reviewed qualification inputs/new output
under /usr/obj, with the candidate isolated from the running system and package
archives outside it. These are prepared command forms, not an executed check or
a request to use an existing installed root. Complete native world packages and
initial directory/generated policy must first be produced and reviewed; optional
construction policies must be explicitly passed when their packages require them.
No host installation, upgrade, activation or reboot is authorized or performed.

Frontend review: existing format-5 targets use the corrected maintained package
driver and inspector. BUILD.bazel and the manual are updated in the same change;
no new frontend C option, signing/publication behavior or backend default is
needed. Make remains the production default; BIP remains out of scope.

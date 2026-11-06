# Full selected library installation comparison

## Current directory follow-up (2026-11-06)

The subsequent complete comparison has zero directory claim differences after
source-owned repairs. See LIBRARY-DIRECTORY-CLAIMS-QUALIFICATION.md. The counts
below describe the original r2 comparison; the three account paths, two additional
sanitizer files and seven ncurses data differences remain open. Archive-order and
installed capability-test linkage follow-ups are separately documented in
LIBRARY-STATIC-ORDER-QUALIFICATION.md, CAPRECLAIM-NATIVE-TEST-QUALIFICATION.md,
CAPABILITY-INSTALLED-TEST-QUALIFICATION.md and
LIBRARY-DYNAMIC-DEPENDENCY-QUALIFICATION.md.

## Original results (2026-11-06)

Both the complete selected native lib/ construction and independent original Make
lib/ build/install control pass. The original libpmc JEVENTS command is observed
in its actual metadata recipe and remains bound to its original Make-built tool.
The complete comparison now accounts for all 164 selected parents and 322 unique
installation archives. Native has 12,467 file/link paths; Make has 12,468.

Common file/link owner/group/mode/flags/package metadata matches with zero
mismatches. There are no native nondirectory conflicts, conflicting physical
directory policies, conflicting original duplicate records or hardlink-identity
differences. 10,097 non-ELF/non-static-archive file contents match exactly.
1,900 ELF files and 204 static archives remain outside this full comparison's
binary equivalence scope; earlier bounded binary comparisons remain separate.

The comparison is not passed. All observed differences remain recorded:

- Make emits /etc/passwd, /etc/pwd.db and /etc/spwd.db during libc installconfig;
  these derived account files are absent from the selected native inventory.
  Inspect generation versus stage/package/runtime ownership before implementing
  the correct declared generation policy. Do not copy host account databases.
- Native includes libc ssp/h_raw and its debug file. Original Make skips h_raw
  when its selected SDK lacks the required UBSan runtime; native constructs its
  declared runtime. Obtain a valid positive original runtime/control rather than
  removing native coverage to make the path sets equal.
- Seven ncurses data outputs differ: curses.h, formw.pc, menuw.pc, ncursesw.pc,
  panelw.pc, tinfow.pc and terminfo.5.gz. Inspect actual generated inputs and content;
  no comment/path/header/ABI difference is waived by this result.
- Sixteen directory paths lack original package claims: zfs's /usr/lib/debug/lib;
  fetch/libdwarf/libexecinfo claims on /usr/lib/debug/usr and /usr/lib/debug/usr/lib;
  utilities claims on four debug ancestors through libc/gen;
  five googletest suite directories; libc hash/data, net/getaddrinfo/data and
  regex/data; and the libdiff tests directory. Twenty distinct claims are missing.
  Preserve original component/feature ownership with source declarations.

The separate installation linkage/dependency/archive-order gaps in
LIBRARY-BINARY-COMPARISON-GAPS.md remain independent even where namespace matches.
Original no-DTrace build/install controls now pass for all six archive-order
components (libfidl, liblogcmp, libnetworkcmp, libnotify, libtimecmp, libtracecmp).
Their corrected native feature variants have not been constructed yet.

## Audit correction and evidence

The first full audit failed while comparing immediate hardlink target spellings:
regfree points to regexec in the manifest and directly to regex in the tar, but
regexec itself links to regex. The corrected generic audit follows both complete
chains, rejects missing/cyclic/non-file targets and requires the same canonical
file. It still verifies declared links against actual original Make inode identity.
No source archive or manifest was changed and no path-specific exception is used.

Evidence under /usr/obj/usr/src:

- bazel-library-complete-native-r1-20261106: passed selected construction/capture.
- bazel-library-complete-make-r2-20261106: passed independent original control and
  verified original JEVENTS recipe; failed r1 prerequisite evidence is retained.
- bazel-library-complete-review-r1-20261106 and
  bazel-library-complete-comparison-queue-r1-20261106: initial audit failure retained.
- bazel-library-complete-review-r2-20261106: corrected complete inventory/report,
  every discrepancy and all artifact bindings. Status remains differences-found.
- bazel-library-no-dtrace-make-controls-r1-20261106: all six passed original controls.

Reconcile these actual inputs and outputs, then repeat complete comparisons.
Do not unguard the full-tests root or make Bazel production/default from this
result. Full bodies, ELF/archive/DWARF/debugger, world/kernel/modules/pkgbase,
normal-service VM, ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk-I/O/footprint and combined publication remain open. These concurrent
builds are not controlled performance tests. No host installation occurred.

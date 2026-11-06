# Ncurses generated-data difference review

## Actual differences (2026-11-06)

All seven differences from the complete library installation comparison are
retained as exact unified diffs bound to immutable native artifacts and actual
original Make files. curses.h and terminfo.5 differ only in their generated
source-path comments: Make records absolute source paths, while the native
source-declared generators receive workspace-relative paths. Five pkg-config
files differ only in their first comment: the native template identifies ncurses
metadata, while the original script identifies gen-pkgconfig.

No generation code was changed to insert a false generator name or hardcode
/usr/src. No bytes were normalized in the installation comparison. It still
reports all seven raw data mismatches. The compressed manpage is decompressed
only to display its text diff and feed the manual renderer; original compressed
hashes are retained.

## Consumer evidence and limits

Seventeen comparisons pass with the same hash-recorded host controls:

- C preprocessing of original and native curses.h yields identical output.
- mandoc ASCII rendering of the original and native terminfo manual yields
  identical output.
- For each of formw, menuw, ncursesw, panelw and tinfow, pkgconf --modversion,
  --cflags --libs and --cflags --libs --static yield identical outputs. Each side
  uses a separate directory containing the five captured pkg-config files with
  PKG_CONFIG_PATH empty and PKG_CONFIG_LIBDIR explicit.

All consumer processes exit zero; commands, environment, output and diagnostic
hashes are retained. These host parsers are comparison controls with installed
host runtimes, not hermetic or native source-built qualification tools. C
preprocessing uses common host system headers. These checks establish the
selected consumer results, not all target ABI, terminal behavior, compiler
configurations or downstream options. Native source-built runtime and
cross-architecture qualification remain separate. Raw bytes remain unequal.

## Evidence under /usr/obj/usr/src

- bazel-library-directory-policy-native-r1-20261106: immutable native captures.
- bazel-library-complete-make-r2-20261106: original full library control.
- bazel-ncurses-data-difference-review-r2-20261106: exact seven diffs, audit and
  hashes; earlier r1 retained.
- bazel-ncurses-consumer-review-r1-20261106: passed 17 consumer comparisons,
  isolated file corpora, raw tool outputs, tool hashes and audit.

Frontend review: production generators, frontend C/backend options, packaging,
signing and publication are unchanged. The existing maintained format-5 build
provided the captured artifacts; this follow-up only records comparison evidence.
Make remains production default and all broader system gates remain open.

# Full library directory-claim reconciliation

## Result (2026-11-06)

The complete selected library hierarchy constructs through the maintained
build-bsd bazel-test frontend with all 16 logical CPUs. Independent installation
comparison against the retained complete original Make control now finds zero
directory package-claim differences, down from 20 claims across 16 paths.

The 164 selected installation parents contain 323 unique archives, 12,467
file/link paths and 617 explicit directory claims over 353 paths. File metadata,
hardlink identity and physical directory policy remain conflict-free. All 650
file payloads owned by the affected components match their previous captured
native bytes exactly. This is not a new whole-library ELF equivalence claim.

## Ownership and implementation

- libbe, libfetch, libdwarf and libexecinfo derive debug ancestors from their
  package and installation directory using the existing utility helper.
- libc gen keeps its utilities-owned dummy shared library in a separate archive
  from tests-owned programs. Both original packages retain debug ancestor claims;
  the suite directory remains tests-owned. The public aggregate manifest still
  includes both contributions.
- The test archive helper accepts canonical suite-relative data subdirectories.
  libc hash, getaddrinfo and regex declare their data directories at their source
  owners. Empty, absolute, dot/parent traversal and duplicate names are rejected.
- GoogleTest derives suite directories from the same declared component list as
  its production manifests, conditional on both tests and googletest settings.
  libdiff declares its original test-suite directory.
- Removed invalid libfetch CAM topology test targets referencing nonexistent
  source and labels. The actual libfetch local-file test passes; it exercises
  URI parsing, local stat/read/offset and missing-file errors without networking.

The tests-off profile and the separate GoogleTest-off profile both construct.
Their captured manifests and directory policies contain no tests package claims
or library suite paths. The positive run executes the source-settings wrapper
(28 unit methods) and the real local-file test, both passed. It does not execute
all installed library suites.

## Evidence under /usr/obj/usr/src

- bazel-library-directory-policy-request-r1-20261106/inputs.json: format-5 inputs.
- bazel-library-directory-policy-native-r1-20261106: passed construction, immutable
  outputs and test reports; artifact manifest SHA-256
  13474b2aab8095d05a51db6b7bfa1493c911c0c3aa4960b8537e9d077dcc8bbb.
- bazel-library-complete-make-r2-20261106: retained independent original control.
- bazel-library-directory-policy-review-r1-20261106: full installation comparison.
- bazel-library-directory-policy-no-tests-native-r1-20261106 and
  bazel-library-directory-policy-no-googletest-native-r1-20261106: feature controls;
  corresponding request directories retain explicit inputs.
- bazel-library-directory-policy-final-review-r1-20261106: hash-bound audit and
  passed bounded ownership/payload/feature/runtime result.

The full installation comparison still reports differences: three generated
account files absent from the selected library payload, two additional native
sanitizer-test files and seven ncurses generated data differences. Account
construction already exists separately; inspect composition and construction
versus package ownership before changing it. The ncurses differences inspected
so far are generated path/banner comments; no raw-byte equivalence is claimed.

Existing format-5 frontend inputs and maintained backend rules select these
changes; no new frontend C option, signing or publication policy is required.
Make remains production default and the global full-tests library guard remains.
Full binary/archive/debugger, world/pkgbase, normal native kernel/module boot,
service/authentication runtime, ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility
and CPU/memory/disk-I/O/footprint gates are still open. No publication, verified
boot, compromised-root protection, host installation or reboot was performed.

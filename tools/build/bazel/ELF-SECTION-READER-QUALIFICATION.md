# ELF comparison section reader (2026-11-05)

The maintained elf-artifact-check.py now hashes file ranges described by one
readelf section-table invocation instead of invoking objcopy, copying the full
ELF and writing/unlinking scratch files for each section. It streams chunks of at
most 1 MiB, preserving raw section sizes/hashes, including compressed bytes.
The existing call interface and comparison output schema remain available to
all original drivers. ELF identity, dependency order, symbols/versions and
hardening checks are unchanged. Incomplete/unordered/malformed tables, duplicate
names, out-of-bounds ranges and truncated reads fail explicitly.

The change addresses diagnostic I/O overhead, not generated-system performance.
No compiler/link flags, produced program, kernel, filesystem or security policy
changes follow from it. Existing build-bsd explicit test targets express the new
regression target; no C frontend, staging/signing/publication or input schema
change is needed. Make stays the production default.

## Evidence

All directories below are under /usr/obj/usr/src.

- bazel-elf-section-streaming-review-r2-20261105/review.json verifies exact
  section maps against retained objcopy results for 28 real native/original-Make
  ELF64 programs, and directly compares the prior implementation on a real ELF32
  boot object and a compressed ELF64 split-debug file. Inputs and both helper
  implementations are hash-bound. The previous implementation is the committed
  elf-artifact-check.py at a05672ac763; it is not a modified control algorithm.
- bazel-libc-netbsd-batch-native-r2-20261105 passes the maintained Bazel
  elf_section_reader_test freshly along with 27 cached test targets. Its eight
  methods cover multi-chunk/empty/NOBITS data and reject malformed, incomplete,
  unordered, duplicate and out-of-bounds section records. It checks that one
  external tool call suffices and that no scratch payload copies are created.
- bazel-libc-netbsd-batch-review-r2-20261105 uses the new reader in the complete
  24-program independent Make ELF comparison; all interfaces/hardening agree.

The report retains bounded diagnostic timings, not controlled comparative build
CPU/memory/disk benchmarks. Those system-wide resource gates remain open, as do
full world/tests/pkgbase, bootstrap, other ABI, guest runtime and cache/sandbox
qualification. No host installation, upgrade or reboot occurred; BIP is excluded.

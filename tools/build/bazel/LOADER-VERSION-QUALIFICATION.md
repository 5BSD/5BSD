# Native loader version generation (2026-11-04)

## Inputs and configuration

`//stand/efi/loader:version_reproducible` generates vers.c from the actual loader
version file with metadata suppressed. `version_configured` selects the mode
through the existing format-5 `build-settings` interface:

- `//tools/build/bazel/config:reproducible_build`: boolean, default false, matching
  Make's REPRODUCIBLE_BUILD default.
- `//tools/build/bazel/config:loader_version_metadata`: source-file label. Outside
  reproducible mode it must resolve to exactly one explicit JSON file. Its
  default is an empty filegroup, not a test identity or execution-host fallback.

The JSON object requires string fields `date`, `user`, `host`, with optional
`build_utc` as a decimal string. Date must be nonempty; empty user/host values
are permitted if explicitly supplied. Unknown fields, control characters,
backslashes and double quotes are rejected. The metadata is selected build
information, not a claim that the build or its identity is authenticated.
A site can export its own source file and select that label through format 5.
The metadata fixture is explicitly selected only in qualification profiles.

The rule invokes the maintained stand/common/newvers.sh. Shell, AWK, mktemp,
cat, mv, rm, native runtime and Python are declared inputs; the child script
has an empty PATH. Metadata mode receives only the declared JSON values.
Reproducible mode does not consume that file or call date/hostname. There is
no build-time Makefile parser or replacement version algorithm.

The maintained script retains ordinary Make defaults, adds optional -o output
and namespaced NEWVERS_AWK/MKTEMP/CAT/MV/RM executable overrides. Namespacing
avoids collisions with Make variables such as RM='rm -f'. SOURCE_DATE_EPOCH
remains supported for ordinary Make calls. Missing revision now fails early.

## Evidence

Retained paths below are under /usr/obj/usr/src:

- bazel-loader-version-{amd64,aarch64,riscv64}-r1-20261104: maintained frontend
  qualifications, generated output captures and declared test results. Native
  SDK executables are used even with foreign target configurations.
- bazel-loader-version-controls-r3-20261104: six original/current script byte
  comparisons for three machines, metadata with/without BUILD_UTC and a real
  SOURCE_DATE_EPOCH control; empty-PATH explicit-output and conflicting Make
  variable controls. bazel-comparison.json binds all three Bazel configurations'
  captured outputs to those original-script outputs.
- bazel-loader-version-invalidation-r1-20261104/review.json: changing only the
  logical host metadata reruns only the metadata version action. The reproducible
  output is unchanged; restoring the exact input restores the original bytes.
- bazel-loader-version-configured-metadata-r1-20261104 and
  bazel-loader-version-configured-repro-r1-20261104: latest typed-setting API
  through build-bsd, including the default empty metadata label in reproducible
  mode. configured-mode-review.json compares the metadata output with the
  original script and the configured reproducible output with the explicit mode.
- bazel-loader-version-missing-metadata-review-r1-20261104: the maintained
  frontend rejects missing metadata with the exact analysis diagnostic. The
  initial wrapper-only review omitted backend stderr; both the initial review
  and corrected backend-bound review are retained. No product change or rerun.

These are generator checks, not complete EFI loader builds.

loader_version_test has seven methods covering reproducible output, explicit
metadata, changed inputs, missing values/revision, unsafe metadata and preserving
inputs. Foreign profiles can reuse native test results; a passing cached result
is not another execution. Initial generic tool overrides were changed to
NEWVERS_*; the final RISC-V run uses those names. The first control review's
serialization mistake is retained as invalid-review-metadata in controls-r2;
controls-r3 records independent commands/environments correctly. Production
outputs were not adjusted to accommodate that diagnostic error.

## Remaining scope

Entry objects, native final links, installation/debug parity, firmware execution
and boot remain open. Existing Make EFI reference links still consume world SDK
archives and cannot establish a closed whole-loader comparison. Full world,
kernels/modules, bootstrap/sandbox/cache, packages/hardware/combined publication
and measured CPU/memory/disk I/O/storage remain completion gates. Make remains
production/default. BIP is excluded. No host installation or reboot occurred.

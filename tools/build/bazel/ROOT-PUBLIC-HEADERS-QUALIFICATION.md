# Ordinary public header installation qualification

## Native declarations (2026-11-05)

`//include:root_header_installation_archives` composes five ordinary source-header
contributions. The source-owned `include/root_installation.bzl` declares the 98
ordinary local headers from the maintained include Makefile, plus libc-vis vis.h
and the dttransport ABI header from their owning source packages. Optional
contributions follow iconv, Hesiod and legacy GSS selections; the latter includes
both gssapi.h and gssapi/gssapi.h. The maintained public-header helper takes an
explicit selection condition; its existing callers retain includes-only defaults.
Optional conditions include the includes flag, so disabling includes disables
all these contributions even when their feature flags request them.

These are native Starlark installation declarations using existing typed file,
manifest and archive rules. No Make evaluation, captured installed inventory or
new Python construction code supplies the native source lists. The one-time
editing script used to transcribe the ordinary list is not a build dependency.
Root/wheel 0444 clibs/dev policy matches the original source installation.
Generated osreldate, aliases and kernel header directories remain separate owners.

## Qualification evidence

Evidence is under `/usr/obj/usr/src/`:

- `bazel-root-headers-native-r1-20261105`: normal build-bsd bazel-test, sixteen
  jobs, default optional selections. Source-settings tests pass; the common 100
  files and iconv header are selected.
- `bazel-root-headers-native-r2-20261105`: Hesiod enabled, iconv disabled and MIT
  Kerberos disabled with Kerberos enabled. Source-settings tests pass; 103 files
  are selected, including both legacy GSS headers.
- `bazel-root-headers-native-r3-20261105`: the same alternate selection with
  includes disabled. Source-settings tests pass; all five contributions are empty.
- `bazel-root-headers-make-r{1,2,3}-20261105`: independent complete original Make
  include staging for the corresponding three profiles, sixteen jobs and tests
  disabled, through the maintained reference helper. The recorded SDK/profile
  is retained and only isolated component options change.
- `bazel-root-headers-review-r{1,2,3}-20261105/review.json`: the complete ordinary
  root regular-file set (excluding separately owned osreldate), plus the legacy
  GSS nested header, compared against each full original include stage. Exact
  source payloads, SHA-256, sizes, ownership, modes and package tags match. Native
  tar file uid/gid/mode/epoch are checked; nondirectory entries must equal the
  metadata file set. Remaining tar entries must be ancestor directory scaffolding.
  This does not establish complete directory-policy parity. The verifier binds
  original source hashes, original receipt/METALOG and verified native captures.
- `bazel-root-headers-selection-review-r1-20261105/review.json`: records the
  five-group file counts `[100,1,0,0,0]`, `[100,0,1,1,1]` and `[0,0,0,0,0]`.
  The common archive and metadata stay byte-identical across the first two
  profiles. This is artifact stability, not proof of uncached producer execution.
- `bazel-root-headers-namespace-r1-20261105/review.json`: the default profile
  reconciles with preceding AMD64-selected production captures, totaling 1174
  unique archives and 31093 non-directory paths without conflicts. Empty optional
  archives count as archives; these counts are not program/library counts or a
  combined full-world build. Alternate-profile outputs are not added to this
  default namespace count.

## Frontend and remaining gates

The normal format-5 configured target interface and archive output groups already
support this endpoint; the maintained frontend manual is updated. No C dispatcher,
input schema, signing/staging or publication helper change is required. Make is
used independently for comparison, never hidden inside the native build action.
The earlier comparison script's initial equality check counted parent directory
entries as header payloads; it was corrected to require exact nondirectory sets
and ancestor-only scaffolding before accepting a comparison.

Continue source kernel/architecture header groups and compatibility aliases,
then compose and qualify complete include installation and remaining world roots
and installed tests. Full world/debug/metadata/pkgbase, bootstrap, cross ABI,
runtime/VM and comparative resource/performance gates remain required. These
header installation runs do not establish program runtime, kernel rebuild or
complete SDK bootstrap. No publication, host installation, upgrade or reboot was
performed. Make remains production/default; BIP remains excluded.

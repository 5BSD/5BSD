# Native combined static PAM product

## Scope and architecture (2026-11-02)

`//lib/libpam/static_libpam:pam_archive` now owns the missing combined
`/usr/lib/libpam.a` product. It compiles the original 54 core sources with
OPENPAM_STATIC_MODULES, compiles the original registration source, and partially
links the selected original module archives in maintained Make order with
whole-archive semantics. The source-owned selection.bzl declares the same ordered
conditional groups as modules.inc; it is shared with the registry test. Production
actions do not interpret Make. Existing native archive, DTrace and relocatable
link rules own the transformations; no linked artifacts are rewritten for parity.

The existing kerberos, openssh and radius_support bool settings select modules
independently of unrelated OpenSSL/crypt conditions, matching modules.inc.
DTrace remains enabled in the baseline comparison and is explicitly disabled in
the separate reduced configuration. Source/header visibility additions are
limited to the actual core, registration and provider consumers.

The native install manifest/archive owns `/usr/lib/libpam.a`, root:wheel, 0444,
with package=pam,dev. Shared PAM's existing producer does not own this archive.
No package repository, authentication policy, or host installation was changed.

## Baseline proof

Evidence is retained under `/usr/obj/usr/src/`:

- `bazel-static-pam-make-r3-20261102` uses original Make with 24 independently
  built module archives, recorded exact partial-link order and supported original
  compiler metadata. Parent export context was independently checked.
- `bazel-static-pam-native-qualification-r10-20261102` captures the native archive
  immutably. Its SHA256 is
  `8787f5380a1ea789b1a1ebec05025cc26d99a08cec797ac555aff4dae7debbf1`.
  The later registry build reproduces exactly those archive bytes after the
  readable selection refactor.
- `bazel-static-pam-archive-audit-r2-20261102/report.json`: all 56 ordered member
  identities and text sections match Make (54 core, provider, registration/module
  aggregate). Native .nopic.o versus Make .o member spellings are explicit.
- `bazel-static-pam-dof-audit-r1-20261102/report.json`: 20 providers, 56 probe
  records, 100 ordinary and six enabled sites preserve schemas, source-proven FNV
  path identities, actual bound function bytes and relocation/site semantics.
  All 1,560 member symbol occurrences match in name/kind after that bounded
  path-key comparison. The original strict alias-name failure is retained.
- `bazel-static-pam-relocation-audit-r5-20261102/report.json`: 6,485 non-DWARF
  relocations match by site, kind, symbol/section/value/size/addend, with proven
  DOF record identities. One assertion diagnostic uses absolute versus relative
  prompting.c spelling; its actual assert calls, assert.h macro, complete strings,
  string multiplicities and every reference are checked. No arbitrary string
  or symbol normalization is accepted.
- `bazel-static-pam-configured-action-binding-r3-20261102/report.json` binds all
  149 demanded baseline core/module compiler actions to retained actual argv,
  environment and complete input-path sets. The 55 core/registration actions
  belong to this product; 94 module variants are also described in
  PAM-MODULE-POLICY-QUALIFICATION.md. Exact ordered warning and effective macro,
  language, SSP, optimization and PIC policies match original Make recipes.
- `bazel-static-pam-prerequisite-audit-r4-20261102/report.json` and
  `bazel-static-pam-registration-prerequisites-r1-20261102/report.json` cover
  actual prerequisites. The custom Make registration rule emits no .depend file;
  its original compiler recipe was explicitly replayed in dependency-only mode,
  with 29 strict native-input digest matches. Two MIT generated-header comment
  differences have separate exact proof, not a general header-byte waiver.
- `bazel-static-pam-install-audit-r1-20261102/report.json` checks the new archive
  payload/install record plus the 24 module contexts: 146 records, 25 manuals and
  48 debug CRCs. Directory package tags remain scoped, not flattened.

## Reduced configuration

DTRACE, KERBEROS, OPENSSH and RADIUS_SUPPORT are all explicitly off. Twenty modules
remain; none of the four excluded registrations is silently substituted.

`bazel-static-pam-module-reduced-references-r1-20261102.json` and
`bazel-static-pam-reduced-make-r1-20261102` retain fresh original Make controls.
The reduced native and later registry-build captures reproduce identical archive
bytes. `bazel-static-pam-reduced-archive-contract-r1-20261102/report.json` proves
all 55 member identities/order/symbols and **every non-DWARF member section** equal
Make. All 20 shared module ELF contracts pass separately. Installation checks
cover 122 records, 21 manual payloads and 40 debug CRCs.

`bazel-static-pam-reduced-configured-action-binding-r1-20261102/report.json`
binds 103 demanded production compiles, distinguishing 103 unused analyzed
counterparts. All 103 text sections, compiler policies and output hashes pass;
private copies are retained. The prerequisite reviews check 3,881 exact occurrences
plus 29 registration preprocessing dependencies.

## Static consumer runtime

The ordinary native cc_test imports the actual combined archive. Tacplus's real
archive is imported separately to avoid introducing a second PAM implementation
through its ordinary PAM dependency; all other actual library dependencies remain
declared. There are no unresolved-symbol stubs or handler replacements.

The test checks original openpam_static lookup, exact ordered linker-set membership,
non-null handler pointers, null dynamic-loader handles and an unknown-module lookup.
It never invokes an authentication, credential, session or password handler.

Both executables were built first and checked from immutable captures as AMD64
ET_EXEC with no PT_INTERP/PT_DYNAMIC. Only then were tests enabled. Fully static
execution avoids host DSO/loader dependencies. The original drti initialization
opt-out is set before exec and verified on the actual test action. Helper registration and live probes remain unqualified.

- `bazel-static-pam-registry-test-qualification-r1-20261102`: one actual passing
  test checking 24 baseline modules; actual execution/program/environment/log
  bindings are in `bazel-static-pam-registry-runtime-audit-r5-20261102`.
- `bazel-static-pam-reduced-registry-test-qualification-r1-20261102`: one actual
  passing test checking 20 reduced modules; bindings are in
  `bazel-static-pam-reduced-registry-runtime-audit-r1-20261102`.

These are two test cases, not 44 separately reported tests. Test setup execution
is distinguished from Bazel's separate XML protocol action. Earlier observer
path/format assumptions and failed comparisons are retained.

## Remaining scope and frontend integration

Make remains production/default. All builds use normal build-bsd bazel-test,
format-5 typed settings, 16 jobs and the existing disk reserve guard. Existing
staging/verification helpers handle the new ordinary install manifest; no new
frontend input, signing policy or CLI/manual API is required. This proves neither
verified boot nor protection against compromised root.

Qualification uses the recorded amd64 SDK/profile, including baseline /usr/local,
NIS off and the inherited experimental section-archive setting for dependency
libraries. Arbitrary LOCALBASE/option combinations and other userland architectures
are not qualified. Full PAM family aggregation (including pam.d), original installed
login/PAM/SSH/authentication suites, live tracing, bootstrap/world/pkgbase creation
and system performance remain gates. Development SDK use does not qualify a
publication world. Earlier failures and byte-level diagnostic/DOF layout differences
remain documented; component passes do not establish complete system correctness.

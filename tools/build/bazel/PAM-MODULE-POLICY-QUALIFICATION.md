# PAM module compiler and dependency order qualification

## Scope (2026-11-02)

This correction covers the existing 24 default amd64 PAM modules, their shared
and static object variants, and their individual installation archives. It does
not qualify the new combined static libpam product, authentication, or a complete
system. Make remains the production default. No host PAM files were installed.

The source-owned module rule now matches each maintained Make WARNS level,
`-std=gnu17`, format diagnostics, PIC defines and effective `-fpic` policy.
The Kerberos module retains its distinct base flags and effective unoptimized
compilation. The original LIBADD order is represented on the source library as
well as its wrapper; this fixes the actual configured link traversal instead of
injecting ineffective linker prefixes. In particular, pam_unix keeps PAM before
util/crypt, while other modules retain their own maintained library order.
Production PAM C sources, provider definitions and authentication policy are
unchanged.

## Evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-static-pam-module-references-r3-20261102.json`: 24 successful independent
  Make references with original `.meta` compiler commands. Twenty-one unchanged
  references were verified and retained; krb5, passwdqc and unix were freshly
  built after their declaration corrections. Parent export context was checked.
- `bazel-static-pam-native-qualification-r10-20261102`: immutable target output
  captures from the maintained 16-job frontend. This profile also included a
  candidate static product; its presence is not a qualification claim.
- `bazel-static-pam-module-elf-audit-r7-20261102/report.json`: all 24 shared
  objects pass the maintained strict ELF contract, including SONAME, **ordered**
  NEEDED entries, exports and symbol versions, against current Make receipts.
- `bazel-static-pam-configured-action-binding-r3-20261102/report.json`: 149
  demanded compiler executions match the final configured argv, environment and
  complete input-path sets. Of these, 94 are module object variants and 55 belong
  to the separately pending combined static product. Another 149 regular/PIC
  counterpart actions are analyzed only; they were not claimed as executions.
- `bazel-static-pam-compiler-policy-audit-r3-20261102/report.json`: the same
  retained execution records match exact ordered warning vectors and effective
  language, stack protection, definitions, optimization, pipe/common and PIC
  policy in original Make commands. Independent SSP flag placement and explicit
  versus implicit default optimization are reported separately from warning order.
- `bazel-static-pam-prerequisite-audit-r4-20261102/report.json`: 4,964 module
  prerequisite occurrences match actual input digests exactly. Two additional
  occurrences consume generated MIT profile headers whose sole difference is a
  complete generated-filename comment. Exact byte-level proof, both original
  headers and compiler digest bindings are preserved in
  `bazel-static-pam-profile-header-proof-r1-20261102/report.json`; no general
  comment stripping or basename-only input matching is used.
- `bazel-static-pam-object-code-audit-r1-20261102/report.json`: all 94 module
  object variants have byte-identical `.text` to Make. DTrace transformations
  are bound through retained actual producer inputs and outputs. Hash-verified
  private object copies survive configuration changes in
  `bazel-static-pam-object-evidence-capture-r1-20261102/`.
- `bazel-static-pam-install-audit-r1-20261102/report.json`: the module subset has
  145 exact scoped install records, 25 matching uncompressed manual payloads and
  48 checked debug CRCs. Individual PAM/Kerberos package directory contexts are
  retained; conflicting directory tags are not flattened.

The final profile executed only two compiler actions. Producer records from
r5/r8/r9/r10 contain 149/47/60/2 compiler entries respectively; the latest retained
records are bound to final actions and object hashes. No cached producer was
invented. Full compact logs and receipts remain available. Earlier failed ELF
order checks, ineffective prefix attempts, observer parsing failures and strict
header-byte mismatches are retained.

## Limits and follow-up

Shared libraries are not byte-identical: section-layout, diagnostic-string and
path-keyed DTrace alias differences remain recorded. Exact `.text` and strict ELF
contracts do not prove complete relocation/ABI equivalence. Preserve the open
full relocation review, reduced option matrix, installed authentication/login/
PAM/SSH tests, live probe firing, cross-userland builds and final package creation.

The candidate combined static archive remains separate work. Its custom Make
registration recipe does not emit a dependency file, so that prerequisite proof
is still open. Its provider/site and archive reviews do not establish static
consumer runtime correctness.

No new frontend input or backend API is introduced. The existing typed format-5
settings, build-bsd frontend, immutable captures and installation helpers were
used. Existing manual routes remain applicable; no CLI/manual change is needed
for these component-local corrections.

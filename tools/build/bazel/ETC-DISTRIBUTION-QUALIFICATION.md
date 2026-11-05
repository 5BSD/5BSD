# Native etc distribution phase

## Declared construction (2026-11-05)

`//etc:distribution_archives` implements the maintained etc/Makefile distribution
phase for a fresh stage. It installs GSS configuration, configured mtree
specifications, mail configuration, compatibility links, COPYRIGHT and target
architecture device hints. Standard source inputs and typed installation records
supply payloads, ownership, modes and package/configuration tags. No staged Make
inventory supplies the native list. Account initialization, etc installconfig,
termcap.small installation and afterinstall manual databases remain separate.

Sendmail configuration uses the existing native m4 rule with optional ordered
prefix inputs and directory definitions anchored to declared source files. The
source-owned sendmail m4 closure is declared as a filegroup. `_NO_MAKEINFO_` matches
Make's own invocation and avoids its host/time discovery script. Target hints
select AMD64/ARM64/RISC-V source inputs explicitly; only AMD64 is qualified here.
LIB32 is marked unconditionally broken in maintained src.opts.mk and its spec is
absent. No compatibility spec or working LIB32 configuration is invented.

The Make reference helper now accepts a restricted `--phase` enum: install
(default) or distribution. Both build the selected component and create an
isolated fresh stage with explicit DESTDIR/SDESTDIR. Install retains installconfig;
distribution runs its actual maintained target without implying installconfig or
afterinstall. Receipts record the selected phase. This Python change extends the
independent comparison tool; native construction remains Starlark and m4.

## Accepted evidence

Evidence is below `/usr/obj/usr/src/`; builds use sixteen jobs.

- `bazel-etc-distribution-native-r3-20261105` and
  `bazel-etc-distribution-make-r3-20261105`: complete sendmail-enabled distribution
  profile, tests disabled. Exact comparison in
  `bazel-etc-distribution-review-r3-20261105/review.json` passes 23 files, five
  symlinks and two explicit directory claims.
- `bazel-etc-distribution-native-r4-20261105` and
  `bazel-etc-distribution-make-r4-20261105`: mail/sendmail, boot, unbound, Kerberos
  and MIT Kerberos disabled; test mtree specification enabled. Its complete
  comparison passes nine files, three symlinks and two directories. The Heimdal
  GSS files are selected, following the original distribution target even with
  Kerberos disabled. Installing the test specification is not running the complete
  installed test suites.
- Both native runs use maintained build-bsd bazel-test and pass source-settings
  and installation-reference-options tests. Original comparisons bind the complete
  selected source tree, receipts and metadata. Native captures are hash-verified;
  file bytes/SHA-256/sizes, ownership/modes/tags, link text and explicit directory
  claim multiplicity match. Additional tar directory entries must be ancestors
  of installed claims. This is not complete global directory or pkgbase parity.
- `bazel-etc-m4-inputs-review-r1-20261105/review.json`: two completed uncached m4
  actions each declare 153 current source inputs, including the source m4 closure,
  configuration file and directory anchor. Input digests and generated output
  digests bind to the final passing installed configuration bytes. Those actions
  were observed in the failed initial archive attempt r2; that run remains failed.
  Runner evidence is processwrapper-sandbox, not proof of complete OS isolation.

## Corrected phase ownership

The earlier rmt utility manifest incorrectly included /etc/rmt. The original
rmt Makefile creates that link only through etc-rmt, called by etc distribution.
The typed link remains in its source owner and is now consumed solely by the
etc distribution manifest. Normal rmt installation loses only that misplaced link.

`bazel-rmt-phase-review-r1-20261105/review.json` proves the remaining metadata
records and all three prior binary/debug/manual payloads are unchanged.
`original-metadata.json` compares complete nondirectory metadata against the fresh
`bazel-rmt-phase-make-r1-20261105` default-install reference and confirms no
/etc/rmt claim. It does not assert independently equal ELF bytes or full directory
parity. Namespace reconciliation must explicitly supersede the prior rmt archive;
it cannot merge two claims or silently ignore the collision.

`bazel-etc-distribution-namespace-r1-20261105/review.json` records 1266 archives and 32324 non-directory paths without conflicts, with the
phase-corrected rmt replacement explicitly checked. This remains
selected construction evidence, not a combined world build.

## Rejected attempts and remaining gates

The initial r1 native attempt failed on etc/mail package-boundary labels. Its
Make reference was stopped at the user's request. The resumed native r2 attempt
failed on the nonexistent lib32 spec; metadata comparison also established the
proper utilities package and explicit GSS/mtree directory records. Source-owned
labels, supported policy and metadata were corrected, then fresh runs passed.
No failed or interrupted run is accepted as a complete qualification.

The existing format-5 configured-target/archive interface supports this phase;
normal frontend documentation is updated. No C dispatcher/schema, signing or
publication helper change is needed. Existing m4 callers retain empty defaults
for the added optional inputs. Custom sendmail MC/CF overrides, additional MC
files, SENDMAIL_SET_USER_ID, alternate layouts, existing installed-system migration
and other ABIs remain unqualified. The endpoint covers the tested source-default
configurations; it is not the complete etc parent.

Continue etc install/afterinstall, remaining rescue/sys/stand/world roots and
installed tests, then full installation/debug/pkgbase, reproducible bootstrap,
cross/runtime and resource/performance gates. Make remains production/default and
available for ports. BIP stays excluded. No publication, host installation, upgrade
or reboot occurred.

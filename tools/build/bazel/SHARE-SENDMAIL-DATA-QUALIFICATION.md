# Sendmail shared configuration data qualification

## Native construction (2026-11-05)

The maintained `share/sendmail/Makefile` installs the vendor `cf` subtree as
read-only source data. Native source-owned globs in `contrib/sendmail/BUILD.bazel`
select that same subtree and prune CVS/.svn directories. They declare each file
and directory using existing typed installation rules. The share/sendmail parent
uses the existing archive implementation and standard output groups. No new
Python implementation, runtime source-tree walk, Make invocation or captured
filename inventory is introduced. Vendor file additions and empty directories
are visible to Bazel's source glob evaluation.

This implements Make's production `SHARED=copies` layout. The developer
`SHARED=symlinks` layout depends on a source checkout at runtime and is not
implemented or qualified by this endpoint. The endpoint has no setting that
silently accepts that alternate layout. Relocated SHAREDIR and runtime m4/mail
configuration behavior remain outside this checkpoint.

## Evidence

All evidence is below `/usr/obj/usr/src/`:

- `bazel-share-sendmail-native-r1-20261105`: normal maintained frontend
  `bazel-test`, AMD64, sixteen jobs, source-settings test passing.
- `bazel-share-sendmail-make-r1-20261105`: independent maintained Make component
  build/stage, sixteen jobs, tests disabled, unchanged recorded SDK/profile.
- `bazel-share-sendmail-original-review-r1-20261105/review.json`: complete exact
  comparison, with retained audit source, original receipt/METALOG hashes and
  native receipt/manifest/artifact bindings.
- `bazel-share-sendmail-namespace-r1-20261105/review.json`: cross-capture production
  file namespace reconciliation, including the preceding timezone checkpoint:
  1147 unique archives, 28889 non-directory paths, zero conflicting file claims.
  This is not a combined full-world build or directory/pkgbase reconciliation.

The complete comparison passes 200 installation records: 190 regular files and
10 directories. File bytes match independent original staging, METALOG size/hash
and the current vendor source. All declared paths, root/wheel ownership,
0444/0755 modes, flags and package=sendmail tags agree. Archive inventory,
entry types, numeric ownership and zero timestamp are also checked. There are
no extra/missing source files and no unexpected archive members.

The maintained format-5 frontend and its standard installation output groups
already support this component. No dispatcher, stage/signing, verification or
publication helper change is necessary; the manual now states the data layout.
This qualification is unsigned development work. No host installation, package
publication, upgrade or reboot was performed.

## Remaining work

Installed source files are not proof of generated configuration correctness,
SMTP/mail delivery, service operation or upgrades. Whole share/world composition,
installed tests, complete metadata/debug/pkgbase acceptance, other ABIs,
bootstrap/runtime and comparative CPU/memory/disk qualification remain open.
The component uses the selected existing SDK; it does not prove a reproducible
compiler bootstrap. Make remains production/default and ports keep Make. BIP is
excluded.

# Complete configured public include installation

## Native composition (2026-11-05)

`//include:installation_archives` composes the maintained ordinary headers,
fixed children, RPC headers/schemas, generated osreldate, kernel ABI headers,
architecture companions and compatibility aliases. The selected AMD64 endpoint
contains 104 installation archives, including empty configured contributions.
This is a complete selected include parent, not complete world construction.

Kernel ABI groups use bounded flat source globs or explicit source lists in
79 existing Bazel source packages. No new package boundaries are introduced
beneath existing header providers. The three source groups owned by the repository
root remain bounded globs there. Explicit audit headers keep their audit package;
other headers use clibs/dev. Optional Bluetooth, CUSE, USB, bhyve, CDDL and mlx5
selections are declared in the native graph. Architecture selections cover AMD64,
ARM64 and RISC-V declarations, with no unsupported-platform fallback. Only AMD64
is qualified here; source declarations do not establish cross-build acceptance.

Compatibility link text comes from maintained installed layout policy. Root include
aliases follow includes; /usr/lib/include remains independent. The original
compat phase and companion child both claim i386 when includes are enabled; with
includes disabled only the child retains its directory claim. The public-header
helper supports directories that follow their selection separately from child
beforeinstall directories. This distinction is observable in the Make comparison.

## Accepted comparisons

All evidence below is under `/usr/obj/usr/src/` and uses sixteen build jobs.

- `bazel-complete-include-native-r5-20261105` and
  `bazel-include-parent-make-r5-20261105`: final complete default native endpoint
  and independent full Make include build/stage. Review
  `bazel-include-parent-review-r5-20261105/review.json` verifies 1417 regular files,
  fourteen symlinks and three explicit directory claims (two distinct directories).
- `bazel-complete-include-native-r4-20261105` and
  `bazel-include-parent-make-r4-20261105`: includes and optional kernel families
  disabled. Review `bazel-include-parent-review-r4-20261105/review.json` verifies
  zero files, one library include symlink and the companion i386 directory.
- `bazel-complete-include-native-r6-20261105` and
  `bazel-include-parent-make-r6-20261105`: includes enabled with the six optional
  kernel families disabled. Review
  `bazel-include-parent-review-r6-20261105/review.json` verifies 1343 files, fourteen symlinks and three directory claims. This profile exercises feature selection without masking
  it behind includes disabled.

Native runs use maintained build-bsd bazel-test and pass the source-settings test.
Independent originals retain the selected SDK/profile and override isolated
component options; installed tests remain disabled in these profiles. The full
original reference uses explicit DESTDIR/SDESTDIR and its staged-object guard.
Each comparison binds original source hashes, receipt/METALOG and immutable native
captures, requires the complete multiset of metadata claims, compares exact
payload bytes/hashes/sizes and link text, and checks uid/gid/mode/epoch in native
tar members. Explicit directory claim attributes and multiplicity match. Additional
tar directory entries must be ancestors of actual claims; whole-world directory
ownership and physical global mtree reconciliation are not established here.

## Dependency and stability evidence

`bazel-include-parent-inputs-review-r2-20261105/review.json` decodes the compact
execution log with the bound upstream converter. It observes 95 actual archive
actions from the earlier passing default r2 build, checking 1368 selected file
input paths/digests against captured payloads and every observed archive output
digest against its captured tar. Nine locally up-to-date actions are explicitly
unobserved; this is not evidence of their uncached execution. The final default
r5 capture has all 312 archive/metadata/directory outputs byte-identical to r2,
bound by `bazel-include-parent-default-stability-r1-20261105/review.json`.
This establishes bounded dependency and artifact stability evidence, not full
bootstrap hermeticity, complete sandbox isolation or comparative performance.

`bazel-include-parent-namespace-r2-20261105/review.json` reconciles the final default
endpoint with preceding AMD64-selected production captures: 1265 unique archives,
32297 non-directory paths, no conflicts. Empty optional archives count as archives;
these are not counts of programs or libraries. This remains cross-capture namespace
evidence, not one complete world build or pkgbase acceptance.

## Rejected attempts and remaining work

The initial native r1 failed on a noncanonical repository-root package label;
its failure is retained. Native r3 built but failed original parity because the
copy phase was incorrectly assumed independent of includes. Its rejected review
is retained. Normal install reaches copies through bsd.incs.mk's conditional
realinstall dependency; a named target existing in include/Makefile does not make
it run. Native selection and directory policy were fixed and independently
requalified. Default r2 parity passed; final r5 also verifies the corrected source.

The maintained format-5 target/settings interface and archive output groups
support this parent directly; the manual and completion plan are updated. No C
frontend/input schema, signing/staging or publication helper change is required.
Native construction does not evaluate Make or consume original staged inventories.
Current comparisons cover the normal copy layout and default includedir/libdir;
source-checkout symlink layout, relocated include/library roots and other ABIs
remain unqualified.

Continue remaining etc/rescue/sys/stand/world composition and installed tests,
then complete installation/debug/pkgbase, bootstrap, cross configurations,
runtime/VM and CPU/memory/disk comparison gates. No program runtime, kernel rebuild,
publication, host installation, upgrade or reboot is claimed by these header runs.
Make stays production/default and available for ports; BIP remains excluded.

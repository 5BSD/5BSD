# Public RPC header installation qualification

## Native include-tree contribution (2026-11-05)

`//include:rpc_installation_archives` composes the complete maintained include/rpc
and include/rpcsvc installation groups. It is explicitly an RPC contribution,
not a complete include/world parent. Source-owned header/schema lists and typed
installation rules preserve clibs/dev ownership tags and mode 0444. The new
includes setting selects these installed payloads without removing headers used
by native builds. Other existing installation families still need their own
include-setting audit before whole-world policy acceptance.

The existing native rpcgen actions already generated fourteen service headers
for librpcsvc. Seven additional public service protocols and the rpcbind header
complete these public groups. NIS declares its included nis_object.x schema.
The same generated key_prot.h is installed as regular files in both rpcsvc and
rpc, matching Make. Sources, generator, preprocessor, flags and include inputs
are declared; preprocessing disables implicit system includes. There is no Make
invocation, captured installation inventory or Python implementation change.

Archives resolve ancestor policy from the maintained BSD.root.dist, BSD.usr.dist
and BSD.include.dist. These are policy inputs, not invented directory records.
The first native attempt correctly failed because the generic script archive
helper omitted include-directory policy. The fix supplies the actual include
mtree to the standard archive rule; validation was not relaxed. Native r1 remains
failed; r2 is the accepted normal capture.

## Complete comparison and tests

Evidence directories below are under `/usr/obj/usr/src/`.

- `bazel-public-rpc-native-r2-20261105`: normal maintained build-bsd bazel-test,
  sixteen jobs. The source-settings test and existing native rpcgen XDR
  round-trip test both pass. The latter checks generated serialization code,
  not every public protocol's service runtime.
- `bazel-public-rpc-make-r1-20261105` and
  `bazel-public-rpcsvc-make-r3-20261105`: independent original component builds
  and stages, sixteen jobs, tests disabled, unchanged recorded SDK/profile.
- `bazel-public-rpc-original-review-r1-20261105/review.json`: complete exact
  comparison of 28 RPC and 49 RPC-service installation records. It checks all
  inventories, file contents, METALOG size/hash, owner/group, mode, flags,
  package/dev tags and archive serialization. Audit source and receipt/manifest/
  artifact hashes are retained. Generated contents are compared byte for byte;
  no filename-comment or header-guard normalization is used.
- `bazel-public-rpc-disabled-native-r1-20261105`, both
  `bazel-public-<rpc|rpcsvc>-disabled-make-r1-20261105` references and
  `bazel-public-rpc-disabled-review-r1-20261105/review.json`: includes=no
  matches both complete original empty installation inventories. The selected
  source-settings Bazel test passes.

The original RPC-service references were refreshed as native declarations and
mtree policy changed, retaining strict source-hash checks. The r3 reference is
used for the final normal comparison. Makefiles and schemas were not modified.

## Fresh generation and declared dependencies

`bazel-public-rpc-cold-native-r1-20261105` uses an explicitly new build-state
root and initially absent action-cache directory, selected through the maintained
format-5 interface. Both selected tests pass. It reuses the verified SDK/compiler
and repository inputs; this is not an independent compiler/bootstrap build.

`bazel-public-rpc-dependency-review-r1-20261105/review.json` binds the actual
compact execution log, verified upstream decoder, decoded log and audit source.
All 22 public RPC generation actions execute uncached. They use the requested
-C/-DWANT_NFS3 generation flags and preprocessor -nostdinc. The NIS action declares
both nis.x and nis_object.x with their current digests. All 23 installed generated
paths (key_prot.h has two destinations) match their producer output digests.
The two archives and all four metadata outputs are byte-identical to the normal
Make-qualified capture. The normal reused and disabled logs have no RPC generation
records. The observed runner is processwrapper-sandbox; complete OS isolation,
all input-mutation cases and comparative performance are not established here.

`bazel-public-rpc-namespace-r1-20261105/review.json` reconciles this contribution
with preceding production captures: 1163 unique installation archives and 30943
non-directory paths, no conflicting claims. This is cross-capture namespace
evidence, not one combined world build or complete directory/pkgbase acceptance.

## Frontend and remaining work

The maintained format-5 target/scalar settings and standard archive output groups
already support this contribution. The build-bsd manual documents its scope.
No C dispatcher/schema, staging/signing/verification or publication-helper change
is needed. Runs are unsigned development qualification; no package publication,
host installation, upgrade or reboot occurred.

Continue complete include installation: ordinary and architecture headers,
source kernel-header groups, generated osreldate and remaining child groups,
copy/symlink policy and relevant options. Complete etc/rescue/sys/stand/world
composition, installed tests, installation/debug/pkgbase metadata, other ABIs,
reproducible bootstrap/package inputs, runtime/VM and comparative CPU/memory/disk
gates remain open. Make remains production/default and available for ports.
BIP stays excluded.

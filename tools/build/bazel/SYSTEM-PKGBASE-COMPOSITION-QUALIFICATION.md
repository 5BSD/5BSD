# Current AMD64 native system pkgbase composition

Date: 2026-11-06. This qualifies the selected package graph and archive contents,
not a normally booted, upgraded or published system.

## Native graph

`//sys/amd64/conf:kernel_packages` projects the complete typed kernel installation
into a KERNCONF-named kernel family and a separate world-module contribution.
`bsd_kernel_package_installation` preserves every selected File, destination and
metadata field except the intended package-name projection from kernel to
kernel-<lowercase configuration>. It validates the supplied configuration filename,
rejects ambiguous owners and unsupported DTB composition, and preserves physical
directory policy through typed providers and output groups. The current GENERIC
profile has four non-kernel module records owned by oes/mac-abac. Both projections
together partition every original complete-installation record exactly.

The generic family rule accepts an explicit UCL generator family and a template
flavor variable. Kernel metadata uses generator family kernel, retaining the
maintained generator's kernel dependency exception, and binds KERNEL_FLAVOR to
empty or -dbg. This preserves the original template's comments/descriptions and
does not invent a dependency from kernel debug to the base kernel package.
Metadata uses the unchanged maintained kernel-all.ucl and generate-ucl.lua.

`//:amd64_system_packages` composes the actual source-selected world family set
with kernel families. Nested typed family sets preserve leaf declarations and
reject duplicate family/package names or differing package identities. The system
installation joins fresh world contributions with both kernel projections; the
existing inventory/reconciliation gates and native package actions create the
complete archives. World construction declarations share a single source helper.
Per-package actions retain only their actual payload/inspection inputs. The
standalone kernel and combined system endpoints have separate output namespaces;
requesting both explicitly can create both sets, without a private reuse cache.
Normal future system builds can request the combined endpoint alone.

## Payload identity and evidence interfaces

Archive providers expose their actual payload output group. The system's
`amd64_system_packages_payloads` filegroup makes those Files directly inspectable.
`amd64_system_packages_payload_inventory` hashes those same declared Files under
their execution paths. Bazel expands declared TreeArtifacts through Args; the
Python action receives a multiline argument file, preserves repository aliases,
rejects duplicate/unsafe/missing paths, and streams hashes. It never inventories
an installed filesystem, guesses program names or reads adjacent build outputs.

This matters for symlink repositories: BEP reports an imported license using its
canonical source name, while a typed installation record retains the external
repository execution path. The declared-input digest inventory bridges those
identities through verified content, rather than hardcoding a repository alias or
resolving a mutable bazel-bin symlink after qualification. All 19,393 execution
paths (2,611,720,363 source bytes, including repeated content) match captured bytes.

`qualification_artifacts.resolve_many(..., exact=True)` selects complete captured
output names with an index. Default suffix selection still rejects ambiguity;
full-name mode also rejects duplicate complete names, corrupt content and changed
metadata. This resolves real LICENSE suffix collisions without choosing a first
match. The helper retains receipt/manifest/content binding and does not cache
mutable lookup results.

## Qualification and reproduction

All result paths below are beneath `/usr/obj/usr/src`. Maintained frontend commands
use explicit format-5 input files and 16 jobs:

```
build-bsd bazel-test --arch amd64 --jobs 16 \
  --bazel-inputs /usr/obj/usr/src/<request>/inputs.json \
  --output /usr/obj/usr/src/<fresh-output>
```

The requests use the declared world-pkg SDK/JDK, Bazel 9.3.1, production malloc,
the same selected world feature profile, CTF/debug GENERIC and explicit kernel
source revision 03d81acf6e1-dirty. This is a test package version, not publication.
The historical candidate executable filename does not select BIP or ZFS behavior.

- Kernel-only native: bazel-kernel-pkgbase-default-native-r2-20261106, request
  bazel-kernel-pkgbase-default-request-r1-20261106. All 22 selected tests pass,
  including an actual local pkg catalogue and dependency/conflict solver dry-run.
- Combined final native: bazel-system-pkgbase-default-native-r4-20261106, request
  bazel-system-pkgbase-default-request-r3-20261106. All 25 selected tests pass;
  two executed and 23 cached in this final pass. The initial combined r2 executed
  the real complete-system solver. All 447 declared archives are indexed and the
  solver reports zero conflicts and no installed packages.
- Exact lookup helper: bazel-system-pkgbase-artifact-api-native-r1-20261106, request
  bazel-system-pkgbase-artifact-api-request-r1-20261106. One native Bazel target
  runs 20 unit cases, including exact-name/collision/corruption checks.
- Declared payload contract: bazel-system-pkgbase-payload-contract-native-r2-20261106,
  request bazel-system-pkgbase-payload-contract-request-r1-20261106. The actual full
  input hash inventory builds, and two native tests pass five unit cases covering
  source aliases/path rejection and archive flags plus wide numeric IDs.

These are selected tests with honest cache reuse, not a claim of 28 new test
executions. Minimal analysis fixtures exercise name/duplicate guards without
pulling a full kernel through an analysis-test transition. The real full package
build and archive audit independently cover complete products.

## Independent inspection

`bazel-kernel-pkgbase-default-review-r6-20261106/review.json` binds the final system
capture and checks original Make UCL generation plus independently serialized pkg
metadata, every kernel archive file/alias/directory/owner/mode/flag and payload,
and exhaustive partition of the complete original installation. Its SHA-256 is
b21e638eabebaab191b090263f48ce513e42db397eb88e1a5854d9bcc521e262.
The kernel package has 725 non-directory claims; its debug package has 727.
The four world-module records are retained separately.

`bazel-system-pkgbase-default-review-r5-20261106/review.json` checks every archive
against the actual immutable source capture and declared-input identity contract.
It proves every baseline world claim and construction record survives, with only
the declared kernel/world-module additions. All 447 packages and 33,968 file claims
pass payload SHA-256, aliases, owner/group names, numeric encoding, modes/flags,
complete ancestor/owned directory coverage and configuration upgrade markers.
The source-selected pf-dev package remains intentionally metadata-only and its
empty archive is inspected too. No package or percent-bearing i18n table is filtered.
Report SHA-256:
91547d4647db103038a1d52a067c719c178b3d4f84a48949399984f302f2c9d4.
Observers are retained next to the reports; temporary extracted payloads are removed.

Pkg URL-encodes percent/non-ASCII bytes in JSON manifest paths while storing literal
archive member names. The observer decodes manifest keys once with collision
rejection and compares every literal archive path and source byte. It does not
interpret %25 names as changed on-disk filenames.

The archive reader now exposes signed 64-bit UID/GID fields. Pkg 2.9.0 deliberately
stores nobody numeric placeholders for reproducibility (libpkg/packing.c) and
resolves uname/gname on installation (pkg_add.c/get_uid_from_uname and related
helpers). The observer compares numeric encoding with the hash-bound prior
Make-created acct package using the same declared SDK pkg, and validates every
owner/group name against captured target account files. It does not rewrite
package headers or mistake numeric placeholders for installed ownership. Actual
installed UID/GID remains a separate VM requirement. The earlier 445-package VM
qualification checked installed ownership/modes/flags; it is not 447-package proof.

The earlier full world Make oracle is unchanged: original recipes over the same
native payload corpus, not independently compiled Make world machine-code parity.
This work does not broaden that claim.

## Retained failures and corrections

Initial kernel analysis rejected package-test helper visibility outside the root
package; the existing helpers now explicitly allow source kernel package consumers.
Initial combined analysis rejected a missing directory_metadata output group in
projection; the typed output contract is now preserved. A full-kernel analysis
fixture exceeded Bazel's dependency safeguard; the name guard now uses a minimal
typed fixture, with the actual kernel qualified separately. No limit was raised.

The first exhaustive observer used ambiguous suffix names; strict full-name lookup
and tests fix that interface. The next observer could not directly equate an
external repository execution path with BEP's canonical source name; the declared
hash inventory now binds both to the same verified bytes. Earlier observer attempts
incorrectly expected target numeric IDs in pkg headers or literal JSON percent
paths. Source inspection and hash-bound Make controls established the correct pkg
contract. No producer metadata was weakened or rewritten to make these checks pass.
A focused request initially named an unregistered archive-header test; that existing
regression now runs as a maintained native Bazel target.

## Frontend and remaining work

The frontend's existing format-5 targets/settings/test interface carries the new
source graphs and policy. `build-bsd.c` needs no new option or bypass; its maintained
manual is updated in this change. Signing, verified-boot, installation and repository
publication policy are unchanged, and these unsigned fixtures establish none of them.
Make remains the production/default backend; this is not a production switch.

Next: actual full-system installation, normal startup/authentication/services and
new-version/boot-environment upgrades. The no-separate-debug and relocated complete
installation archives passed the preceding milestone; final package variants still
need original Make parity. Original mtree-to-plist.awk's fixed /usr/lib/debug/boot
kernel-debug classification needs source-policy correction before general layouts
are accepted. FDT/MMCCAM/TESTS root branches, alternative module-selection modes,
custom/cross completeness, bootstrap/cache/incremental/sandbox/reproducibility,
debugger behavior, CPU/RAM/disk I/O/space comparisons, separate hardware builds and
verified combined publication remain acceptance gates. No host install, module load,
upgrade or reboot ran. BIP remains excluded.

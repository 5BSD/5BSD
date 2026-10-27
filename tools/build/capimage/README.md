# Signing a staged system

Programs declare `CAPIMAGE_MANIFEST` in their Makefiles. The standard program
rules link the exact UCL bytes into a non-allocated `.5bsd.policy` build-input
section. Final signing emits the ELF-native `.note.5bsd.signature` container. A manifest may
be a unit policy, or a `profiles` object whose keys are `bundle_id/unit_name`.
Each profile contains the complete policy for that unit. Signed bundles derive
policy exclusively from their executable; Unit.ucl is not opened or parsed as
runtime policy. Each signed unit has exactly one regular program in its bin
directory. Unit.ucl remains a build or unsigned-development input.

Signing covers the entire final executable, with only the signature field
itself zeroed while hashing. It therefore includes ELF headers, all loadable
sections, dependency metadata, and the embedded policy. Strip, debug-link,
and install transformations must finish before signing. Changing even an
unloaded byte afterwards invalidates the signature.

`sign-stage.sh` finalizes a private NO_ROOT stage. It signs every system unit
program, verifies them, seals each bundle inventory, and provisions the public key.
A fresh signing stage must have an empty trust catalogue. `verify-stage.sh`
requires exactly the externally requested code key in that catalogue and
rejects additional, missing, substituted or symlinked entries. This workflow
supports one system code signer per stage; multiple signers require an explicit
authenticated catalogue policy before they can be accepted.


```sh
CAPSIGN=/path/to/native/capsign \
  sh tools/build/capimage/sign-stage.sh -e \
  -r /usr/obj/usr/src/private-stage -k /secure/release-private.pem
```

Package staging supports the same operation through `CAPIMAGE_SIGNING_KEY`,
`CAPSIGN_HOST`. The host tools must be native to the signing machine;
cross-built target programs are not host tools. Package signing and combined
repository publication remain separate steps. This hook does not advance
`latest`, install an upgrade, or reboot anything.

## Construction compatibility aliases

The maintained `build-bsd construct --installation-policy FILE` input accepts
format 3 in addition to formats 1 and 2. Regular entries retain format-2
`create`/`replace` semantics. An alias entry has exactly `operation: "alias"`,
`target`, `package` and `requirement` fields. Its destination key must match the
named package state requirement. The destination must be absent and unowned,
with existing directory parents; it cannot collide with generated outputs.
The target is a canonical absolute candidate path. Resolution uses the candidate
inventory, never the host filesystem, and rejects cycles and nondirectory
traversal. Existing targets must match the declared state type; missing targets
are permitted for boot-created state. Links are root-owned, mode 0777, flags zero,
and become explicit generated objects bound to the installation policy digest.

This operation does not provision mutable storage or grant runtime access.
Package requirements and compatibility links cannot substitute for authenticated
runtime mapping. Root-builder materialization passed in `bip-alias-install-v1`
(26 installation tests, no skips); protected service compatibility and normal
startup remain pending VM qualification.

## Build and installation signing modes

`make capimage-stage NO_ROOT=yes DESTDIR=/usr/obj/usr/src/private-stage`
finalizes a private stage after `installworld`, `distribution`, and
`installkernel`. It never signs a live root. Package staging uses the same
workflow automatically, including through `system-packages`.

- `CAPIMAGE_SIGNING_MODE=unsigned` retains unsigned development programs and
  external unit manifests. It needs no key or native signing tools and does not
  finalize a signed stage. It refuses a previously finalized signed stage.
- `CAPIMAGE_SIGNING_MODE=signed CAPIMAGE_SIGNING_KEY=/secure/release.pem`
  uses an existing Ed25519 key. Missing keys are errors; no replacement identity
  is generated. The key and its containing directory must have private/safe
  permissions, and the private key must be outside the staged tree.
- `CAPIMAGE_SIGNING_MODE=development` generates a private Ed25519 key on demand
  at `/usr/obj/usr/src/signing-keys/development.pem` and reuses it on later
  builds. `CAPIMAGE_DEVELOPMENT_KEY` selects another persistent location outside
  the staged tree. Existing keys are never overwritten. Preserve this key to
  preserve the development signing identity; use a separately managed release
  key for distribution.

The default `auto` mode uses signed mode when `CAPIMAGE_SIGNING_KEY` is supplied,
otherwise unsigned mode. Signed/development stages require signatures by default.
`CAPIMAGE_REQUIRE_SIGNATURES=no` explicitly omits the bundle-enforcement marker
for a signed test stage. It does not disable the kernel's rejection of recognized
invalid signatures. A fresh unsigned build is the normal way to test without
signing; changing this setting does not unsign existing binaries.

Only public keys enter the image and package metadata. Private keys remain on
the build machine, outside the install/repository trees. Executable signing keys
are distinct from package-repository signing keys; these options do not replace
repository authentication.
Examples after staging a fresh generation:

```sh
make -C /usr/src capimage-stage NO_ROOT=yes \
  DESTDIR=/usr/obj/usr/src/private-stage CAPIMAGE_SIGNING_MODE=unsigned

make -C /usr/src capimage-stage NO_ROOT=yes \
  DESTDIR=/usr/obj/usr/src/another-stage CAPIMAGE_SIGNING_MODE=development \
  CAPSIGN_HOST=/path/to/native/capsign
```

For publication, first build world with `WITH_MALLOC_PRODUCTION=yes`. Use the
maintained `system-packages` workflow (or its base/hardware/publish targets),
with the same signing options. Standard output remains under `/usr/obj`, with
combined publication at `/usr/obj/usr/src/repo`; base-only output does not advance
`latest`. Building or signing does not install an upgrade or reboot the host.

The key catalogue lives at `/etc/capability/keys/<key-id>.pub`.
`capsign key-id -p public.pem` prints the identifier. All keys provisioned in
that catalogue are system policy signing authorities, not delegated user
signers. The `/etc`, `capability`, and `keys` directories and public keys must
be root-owned and not group/other writable; symlink components are refused.
The root-owned regular `/etc/capability/require-signatures` marker requires
trusted embedded image signatures and sealed bundle inventories.
Without it, legacy external manifests and unsigned development
policy sections remain usable. An unsigned build policy is never accepted as authenticated
policy. Signed images are checked again after the kernel pins their contents
and before their authority is installed or registered for ordinary exec.

The kernel mmap implementation under validation checks recognized embedded
signatures before creating ordinary file mappings whose maximum permissions
allow execution, including mappings initially created without execute access.
Verification and acquisition of a vnode text pin occur in one locked interval.
Kernel signed-image checks and executable authority constraints admit only UFS
and ZFS for text pinning. Signed images on tmpfs and other unaudited filesystems
are rejected with `EOPNOTSUPP`; unsigned ordinary execution remains available.
This also covers mappings created read-only that can later become executable.
Offline userspace signature inspection does not require such a pin.
An internal mapping owner retains that pin and the original open description
through descriptor closure, fork, partial unmap, and final unmap. Failed
insertions release the temporary owner.

This protects signed file contents, not all memory in a running process.
Private writable data remains private, unsigned development mappings remain
permitted, and data-only mappings can inspect a damaged image when their maximum
protection excludes execution. Missing signature locators still require an
external signed-identity requirement to distinguish removal from unsigned code.
The new kernel path and its mmap_integrity regression require VM validation;
a successful object compilation alone is not runtime evidence.

The bundle inventory includes metadata, unit policies, native programs,
resource files, directory structure, and modes. Symlinks and non-regular
objects are refused. `Signature/Seal` is the only excluded signature entry.
Base-system debug files are installed under `/usr/lib/debug/Capabilities`
instead of inside runtime bundles, so optional debug-package installation
does not alter a sealed runtime inventory.


## Standalone and recursive tooling

A prebuilt ELF does not need a rebuild:

```sh
capsign sign -k private.pem -m manifest.ucl -o program.signed program
capsign verify -p public.pem program.signed
capsign show -p public.pem program.signed
capsign sign --recursive -k private.pem -o Signed.cap Input.cap
capsign verify --recursive -p public.pem Signed.cap
```

Post-link signing emits a bounded ELF signature note, preserves the original
ELF load offsets and authenticates the entire file.
Base-system signing uses this same final representation. The unsigned input
section is never an alternate signature location. Recursive signing and stage
finalization remove Unit.ucl from their private outputs after embedding it,
so deployed bundles do not carry a second policy file. Source trees are retained. Recursive
signing copies a quiescent unsealed input into a new private tree, processes
each declared unit with its own policy, then seals nested bundles inside out.
A recursive global manifest override is rejected. A failed output is incomplete
and must be discarded. This operation does not activate or publish the tree.

The CLI designs were compared with Apple's
[codesign guidance](https://developer.apple.com/library/archive/technotes/tn2206/_index.html),
[codesign_allocate manual](https://github.com/apple-oss-distributions/cctools/blob/main/man/codesign_allocate.1),
Apple's allocator is Mach-O-specific; our post-link format needs no Mach-O
rewriter. Signing nested code inside out and preserving distinct entitlements
are the relevant practices, not applying a single entitlement set recursively.
The historical codesign(1) source also distinguishes signing, verification,
display, detached signatures and entitlement extraction. Our explicit command
names avoid the ambiguous historical `-v` sign/verify/verbosity interface.

Fuchsia provides useful comparisons in
[cmc](https://fuchsia.dev/reference/tools/sdk/cmc),
[ffx package tools](https://fuchsia.dev/reference/tools/sdk/ffx), and
[software delivery](https://fuchsia.dev/fuchsia-src/get-started/learn/intro/packages).
Its manifest compiler validates component/package references; package tools
list, inspect, hash and extract artifacts, and repository trust uses signed
metadata. Our unit-inventory validation and whole-bundle seal serve related
local purposes, but are not a TUF implementation or a package-update rollback
policy.

Current scope: binary sign/verify/policy extraction, detached artifact seals,
recursive unit/bundle signing and verification, key identifiers, release-stage
integration. Certificate chains, notarization,
network timestamps, arbitrary identity requirements and automatic activation
are not implemented. A signature's validity is separate from the runtime's
permission to grant authority. Filesystem extraction does not establish that
an artifact is appropriate to install.

Every executable signature is in a non-loadable ELF note, located through
consistent section and program-header metadata. See the
[ELF signing specification](../../../docs/elf-code-signing.md).


Fuchsia's [loader protocol](https://fuchsia.dev/reference/fidl/fuchsia.ldsvc)
returns library VMO handles through a process's loader-service connection.
For 5BSD, granted directory descriptors continue to control library lookup.

Standalone stripping before signing must preserve the build input with
`strip --keep-section=.5bsd.policy program`, or supply `capsign sign -m policy`
after stripping. The maintained base install rules prepare a stripped install
image while retaining that section. All stripping must precede final signing.

### Unified build frontend

`build-bsd` wraps the maintained world, kernel, stage, signing, and system
package targets. Preview with `build-bsd plan stage --signing development`;
run the same command without `plan` to build. `build-bsd build` builds world
and kernel with production malloc and publishes pkgbase; `build-bsd packages --signing signed
--key /secure/release.pem` uses production malloc and the maintained combined
publication workflow. Private staging and logs stay under `/usr/obj`; packages
remain under `/usr/obj/usr/src/repo`. Build commands do not install a host upgrade. The explicit `bsdinstall` command
opens the interactive disk installer and can replace a system through its disk
selections. No command reboots. See `build-bsd(8)` for options, logs, and key modes.

Signing modes bootstrap native host tools from source before the build. They
do not assume that the host has the target version of capsign installed.
Text and JSON plans report their verification scope as `system-bundles`, with
boot and compromised-root verification `not-performed`. These describe command
coverage, not firmware state or passing results. The production build profile
selects malloc behavior; it does not select a protected boot mode. The
[system security design](../../../docs/book/src/capability/system-security.md)
defines the additional build, boot, authorization and recovery gates. Each
implementation step must update this frontend and its maintained backends when
inputs, staging, verification or publication requirements change.

The frontend uses every logical CPU and serializes its own builds; independent
manual builds must not run against the same object tree concurrently.

Signed package catalogues can be copied for offline use with
`release/scripts/hardware-packages.py copy-signed-repository --repository GENERATION
--output NEW_DIRECTORY --public-key REPOSITORY_PUBLIC_KEY --abi TARGET_ABI
--osversion TARGET_OSVERSION`. This preserves the complete catalogue and its
signature, verifies the result using an isolated pkg database, and refuses an
existing destination or symlinked repository contents. It requires no private
key. It also fetches every archive into a temporary isolated cache to verify
payload checksums against the authenticated catalogue; allow scratch space for
one additional copy of the packages during this check.
This repository-copy command only prepares the repository, not bootable media.
Use `build-bsd media` below to invoke the bootable release-image targets.

`build-bsd bsdinstall --repository GENERATION --pkg-public-key REPO_PUBLIC_KEY
--public-key CODE_PUBLIC_KEY --kernel GENERIC` prepares a verified private
repository snapshot, then opens the native interactive installer. Use the
`plan` prefix to review the invocation without launching it. Both private keys
remain outside this workflow. This path has lifecycle tests but still requires
full installer VM validation; media generation is exposed separately through `build-bsd media`.

For an already assembled live-media root, the release helper also provides
`hardware-packages.py stage-signed-media --repository GENERATION --media ROOT
--public-key REPOSITORY_PUBLIC_KEY --code-public-key CODE_PUBLIC_KEY`.
It requires matching live kernel bytes and a publication containing pkg and
the base set. It writes the unchanged, verified offline repository and both
public trust files, records them in METALOG, and installs live firmware using
repository authentication. A partial media root is retained on failure and
must not be packaged as a completed image. The release targets use this helper when `PKGBASE_SIGNED_REPOSITORY` and
both public trust keys are supplied. The helper alone does not create an image.

`build-bsd media --repository GENERATION --pkg-public-key REPOSITORY_PUBLIC_KEY
--public-key CODE_PUBLIC_KEY --media-format all --output /usr/obj/usr/src/media/NEW`
invokes the maintained release targets for ISO and memory-stick images, using
the existing target world/kernel and signed publication. `iso` and `memstick`
select one artifact. Release staging uses a new directory while recursive
world operations retain the standard object tree. Output checksums accompany
the images. Orchestration and signed repository/firmware tests pass; actual
image boot and installation validation remain pending.

A signed release uses two explicit steps:

```sh
build-bsd packages --kernel GENERIC-NODEBUG --signing signed \
    --key /secure/code-private.pem --pkg-key /secure/pkg-private.pem
build-bsd media --kernel GENERIC-NODEBUG \
    --repository /usr/obj/usr/src/repo/FreeBSD:16:amd64/latest \
    --pkg-public-key /secure/pkg-public.pem --public-key /secure/code-public.pem \
    --media-format all --output /usr/obj/usr/src/media/release-NEW
```

Use `plan` before each action to review without building or opening disks.
Replace the repository ABI and kernel with the matching publication inputs.
The second command consumes signed published packages and needs public
verification keys, not private signing keys. The output directory must be new. `--media-format iso` produces the ISO; `memstick` produces the USB image;
`all` produces both. Creating media never launches the host's disk installer.
An image is not considered release-tested until a disposable VM boots it,
installs onto an empty virtual disk, and boots and verifies the installed system.


## Package-derived generation inventory

The maintained deploy backend records `package-inventory.json` from the exact
archives fetched through the verified package catalogue, before creating a
destination or boot environment. `package_inventory.py` uses the system
libarchive reader without extraction or package-script execution. It inventories
all selected package payloads (including hardware), actual hashes, metadata and
links; it does not consult the live package database or enumerate known programs.
Duplicate/ambiguous paths, manifest disagreement and cross-package ownership
conflicts are errors. Deployment also requires every selected package and every
declared dependency in the fetched set before creating the destination. Fetch
diagnostics are fatal even if pkg returns success. Unsupported ACL/xattr/special-object metadata is rejected,
not discarded. Every directory declaration is validated even when an archive
header or another package already supplies that directory. Header and manifest
assertions, and assertions across packages, must agree on permissions, ownership
and flags; package order cannot select an answer. Manifest directory attributes
support `uname`, `gname`, octal `perm` and native libarchive `fflags`; unknown or
malformed attributes fail. Equivalent permission spellings are compared by value.
Partial declarations may obtain missing metadata from agreeing headers or other
packages, but reconciliation requires complete ownership and permissions. Without
any explicit flag assertion or header, a declared directory has no flags. Named
archive owners may have placeholder numeric IDs within the same header; a
separate numeric-only owner assertion cannot be discarded for a name and is
rejected as ambiguous. Directory build timestamps are not conflicting assertions.
Manifest pathnames are decoded
once using pkg's percent-encoding semantics; archive header paths remain raw.
Traversal and duplicate aliases after decoding are rejected. Configuration
pathnames use the same decoding; the original full manifest is retained.

Local repository definitions use pkg's literal `file://` path syntax. The pkg
file transport does not percent-decode path components; URI percent-encoding
would change paths such as the standard `FreeBSD:16:amd64` repository directory.
Definitions are JSON-serialized so spaces, quotes and other path characters
cannot change configuration fields. Signed catalogue and archive verification
remain mandatory regardless of the repository path.

Deploy first copies the publication and explicit public keys into its private
run directory. Verification, inventory and installation use this snapshot.
Later source publication or key changes do not replace accepted inputs. This
assumes a trusted release builder and does not implement a protected updater.

Raw numeric and named archive ownership are both retained. pkg archives may use
placeholder numeric IDs, so the generation reconciler must resolve owner names
from generation account inputs, never the builder's account database. The full
manifest preserves dependency, configuration, account and package-script
provenance; script contents remain data to this reader.

The inventory reader itself does not authenticate an archive. Deployment calls
it only after authenticated pkg fetch and records that boundary. An inventory
does not establish a BIP generation: completed-filesystem reconciliation,
generated-file provenance, explicit storage/writer policy, owner additions,
generation authentication and installed-system qualification are still required.


### Package-owned construction declarations

Package manifests may carry a `5bsd.construction` annotation containing a JSON
string with `format: 1` and a nonempty `actions` array. Each action has exactly:

- `name`: an identifier unique within its package.
- `argv`: explicit argument strings, beginning with an absolute packaged executable.
- `inputs`: absolute regular-file inputs supplied by selected package payloads or
  another declared action.
- `outputs`: absolute paths mapped to `type: "file"`, numeric `uid`, `gid`, `mode`,
  `flags_set`, and boolean `replace`.

This initial format describes finite regular-file outputs. It does not describe
mutable trees, directory creation, in-place input changes, or replacing a payload
with hardlink aliases. Replacement requires an explicit declaration and ownership
by the declaring package. Conflicts, unsafe paths, missing inputs, non-executable
commands and dependency cycles fail inventory before deployment creates a target.
Inputs and executables bind to actual archive payload hashes; action ordering
follows declared producer dependencies. No host executable or account lookup
supplies a missing input.

Extraction preflight resolves archive ownership names from bounded, hash-checked
package account payloads before checking library directories. It shares the
account parser used for filesystem reconciliation, preserves numeric identities
where no name is supplied, and rejects unknown or ambiguous names. It does not
consult host NSS or relax ownership checks. Full extraction still resolves and
checks the actual candidate account files before applying ownership.

The utilities package declares its login-class database producer beside its
existing post-install hook. The normal package generator combines source and
build annotation objects, preserves equal values and rejects conflicting values.
The normal deploy inventory records the resulting plan with
`status: "declared-not-executed"` and `outputs_approved: false`. This is automatic
backend validation; it adds no frontend option or runtime writer grant.

The login-class generator uses text-only capability traversal. Existing compiled
`.db` files cannot supply records or `tc` expansions during a rebuild. World
bootstrapping builds cap_mkdb with its matching source reader, including on hosts
whose libc lacks cgetusedb; it does not reuse the host's older generator. The
Secure Boot fixture exercises the matching target generator and libc as an
unprivileged user, including stale-cache and oversized-name regressions.

A declaration is not an execution receipt. It does not authenticate a package,
execute a generator, approve its output, or replace `--generated`. The remaining
builder must verify the executable's complete loading dependencies and input
closure, run with a controlled environment and filesystem, check declared outputs
and all other filesystem changes, and bind receipts to the final generation.
Account migrations, package database creation and authenticated site policy
still need construction contracts. Explicit certificate construction is described below. A caller-written `source` string in the current
generated manifest is descriptive, not verified provenance.

The same boundary applies to PAM stacks and their includes, modules, NSS and
account data, login classes, and every referenced authorization/launch/provider
policy. Package `config` status grants no writable exception; site changes need
explicit authenticated inputs and protected writer policy.

### Required deployment reconciliation

A direct `deploy --root` destination must have a root-owned mode-0700 parent.
The backend checks this before fetching packages or creating the candidate.
Package extraction can restore public directory modes, so making only the new
root initially private is insufficient. BE staging already uses the private
run directory. This isolates incomplete staging from other local users; it is
not a boundary against a hostile builder/root or a production update service.


`build-bsd deploy` now requires `--generated FILE` for both a new root and an
inactive boot environment. It snapshots that explicit manifest with its other
inputs. It validates generated metadata and exact package replacement hashes
against the authenticated fetch before creating a target. An external `--inventory`
is not accepted for deploy. After pkg installation and bundle verification, it
removes transient installation inputs, unmounts devfs, and reconciles every object
while the candidate remains mounted. Only a zero-difference result followed by
successful unmount can print `DEPLOYMENT_VERIFIED`, with scope
`packages-bundles-and-filesystem`. Differences retain the candidate and the run's
`reconciliation.json`, including input hashes and package authentication context.
The report's `deployment_target` records the candidate dataset, GUID and origin
(or a directory destination path). Candidate identity is checked immediately
before and after scanning; an observed replacement prevents report publication.
This remains a trusted-builder consistency check, not serialized ZFS authority.
A reconciliation PASS alone does not prove successful unmount or activation.

The manifest uses the schema below. Package database contents, generated account
files and site policy need explicit construction provenance just as other
non-package outputs do. The backend does not scan them into an exemption list or
accept all files created by package scripts. A complete production manifest and
verified generator pipeline are still required; no successfully reconciled full
installed generation has been qualified. This stricter gate intentionally refuses
an ordinary installation whose generated outputs remain unexplained.

Reconciliation does not authenticate the supplied generated manifest or the
completed generation, classify storage/writer authority, or make the trusted
builder a protected runtime updater. `bsdinstall` and media remain separate
workflows; this deploy gate does not imply their completed roots were reconciled.


## Offline filesystem reconciliation

`build-bsd reconcile --root ... --inventory ... --generated ... --output ...`
checks the complete supplied filesystem against package payload expectations and
explicit generated-input records. Its libarchive disk traversal does not follow
symlinks, ignores no pathname prefixes, and refuses nested filesystems, unsupported
special objects, ACLs and extended attributes. It records file bytes, ownership,
modes, flags, timestamps, symlink targets and complete hardlink sets. Unexpected
links outside the generation fail. It never executes target code or consults the
installed package database. Package `config` membership grants no exception.

The generated-input JSON schema is `{ "format": 1, "entries": { ... } }`. Keys
are canonical absolute paths, including `/` when the package set does not declare
root metadata. Each object requires `type`, numeric `uid`, `gid`, `mode`,
`flags_set`, a nonempty `source`, and `replaces`. Files add `size` and `sha256`;
symlinks add `target`; directories add nothing. `replaces` is the exact set of
archive SHA256 hashes owning that path, or an empty list for a new object.
This guards against silently overriding a changed package input. Unknown fields,
missing metadata and ambiguous replacement declarations fail. Records must come
from declared generation construction or approved site inputs; the checker does
not turn unknown files observed on disk into accepted records. The `source`
description alone is not cryptographic evidence of a generator execution.

Named archive owners resolve against `/etc/master.passwd` and `/etc/group` in
the candidate only after those files match their declared content hashes.
Declared compatibility aliases are supported only when the expected and observed
lookup chains agree and resolve to a regular file in the candidate. The resolved
physical path is opened beneath the candidate root with symlink traversal disabled
at every component; bytes are hashed again before deriving ownership. Absolute
alias targets refer to the candidate namespace, never to the host filesystem.
There is no host account fallback. Directory build timestamps may differ between
packages and change as children are installed; these are measured without a
comparison. Other package object timestamps are compared. Generated timestamps
are measured without prescribed values. Every observed timestamp is retained.

`reconciliation.json` reports all ordinary missing, extra and mismatched objects;
those differences produce a nonzero exit. Unsafe traversal or unsupported inputs
fail before a report can be completed. Output must be a new directory outside the
candidate, including after parent symlink resolution. Inputs and output are
hashed/reported without granting authentication status. Reconciliation requires
trusted expectations and quiescent staging. It is not a hostile-live-filesystem
verifier. Storage classification, approved mount/link boundaries, writer authority,
input authentication, generated-output provenance verification, final sealing and
real installed-system/upgrade VM qualification remain separate mandatory gates.


### Explicit offline package-manager input

`build-bsd packages --pkg-package /usr/obj/path/pkg-version.pkg
--pkg-package-sha256 <expected-sha256>` adds the selected `pkg` archive to the
combined base/hardware publication before catalogue signing. Both arguments are
required together. Maintained `publish-packages` accepts the corresponding
`PKGBASE_PKG_PACKAGE` and `PKGBASE_PKG_SHA256` inputs. The publisher checks the
copied bytes, package identity, exact ABI and minimum OS requirement, then includes
the archive in dependency-closure and signed-catalogue verification. Failure
leaves `latest` unchanged. It does not fetch an unspecified bootstrap or install
anything on the host. Supply an independently prepared, approved archive; the
hash is an input pin, not upstream provenance authentication. Omit both inputs
when base packages already contain `pkg`.

This removes a repository-construction prerequisite for offline installation.
It does not establish installed-system integrity, normal startup or an upgrade.


`--candidate-publication` keeps the complete verified generation under the same
standard repository without moving `latest`. The backend input is
`PUBLISH_ADVANCE_LATEST=no`; its only accepted values are `yes` and `no`.
Use the resulting directory explicitly for VM validation. All normal publication
checks still run, and the legacy hardware staging path refuses any completed
publication, including a candidate that is not the current channel. Candidate
creation is not installed-system qualification or authorization to boot it on the
host. Normal publication retains its atomic `latest` update after verification.


The native host-tools makefile also provides an explicit `pwd_mkdb` target.
`build-bsd secureboot-test` builds and supplies it for synthetic PAM account
assembly, separately from the target generator exercised inside the guest.
Account data is an input to that tool, not imported from the builder's accounts.
This is fixture construction support; complete production generated-file
provenance and account-writer authorization remain unfinished.

## Explicit package inventory

`build-bsd inventory --package-selection FILE --output NEW_DIRECTORY` writes
`inventory.json` for construction. The format-1 selection contains an `archives`
array of objects with exactly `path` (absolute filename) and `sha256` (lowercase
SHA-256). These are explicit inputs, normally derived from a verified snapshot.
The reader measures payloads without extraction/scripts, checks expected hashes,
requires declared dependencies and advertised shared-library providers, rejects
explicit conflicts between selected packages, and binds the original selection bytes. Existing output is never overwritten.

Format 2 takes `repository` (a canonical absolute physical directory) and
`roots` (a nonempty unique array of package names), instead of `archives`.
Dependencies are traversed from archive manifests, with cycle handling and
missing/duplicate identity rejection. Selected archives are fully inventoried
and their manifests compared with the selection pass. The inventory records
roots and measured archive digests. Unselected payloads are not inventoried.
Choose base, kernel, hardware and additional roots as explicit policy inputs.
The reader uses pkg's fixed catalogue filenames only to distinguish catalogues
from package archives; no program inventory is hardcoded.

This does not authenticate the publisher, approve versions, solve alternative
or version constraints, infer writable paths or construct a filesystem.
A format-2 repository must have one already selected version per package name.
Both modes assume a trusted exclusive builder with quiescent inputs. Snapshot verification
remains separate. The standalone inventory library still supports partial-set
audits. Native CLI cases cover malformed/duplicate selections, changed hashes,
missing dependencies, existing output and nonblocking FIFO rejection.

## Package-declared construction on a trusted builder

`build-bsd construct --root ... --inventory ... --generated ... --output ...`
re-reads archive-bound declarations, checks selected package dependency origins
and advertised shared-library providers, reconciles the initial candidate, and
runs each declared generator in a temporary jail. Image construction repeats
these input checks through the same reader. Deployment uses the same dependency
validator and additionally requires the exact closure of its selected roots.
Dependency versions are build metadata, not exact pins; these checks are not
publisher authentication, version approval or runtime ELF dependency analysis. It requires a root shell on
a trusted builder; a disposable VM can provide that privilege without host
installation. `--construction-timeout` bounds each action (default 300 seconds).
Jail removal and descendant exit precede output acceptance. Output metadata is
applied from the declaration, and full filesystem comparison rejects changes
outside the declared outputs. Output-parent timestamps and the ZFS archive
bookkeeping bit are handled explicitly; unrelated metadata remains checked.

`construction.json` records the action, explicit inputs, measured whole-tree
hashes and outputs. `generated.json` supplies the resulting expectations to
reconciliation. These records are unsigned and do not authenticate their inputs
or grant activation authority. They do not establish every internal read of an
arbitrary program. The host kernel and exclusive access to the candidate remain
trusted. Package installation hooks in deploy are not automatically replaced
by this command. Complete account/certificate/package-database contracts,
authenticated policy and sealing, and the protected live updater remain open.

Real jail execution is tested by `tools/test/construction/run.py`, with explicit
world, Python distribution, object tree and kernel inputs. Its ordinary-kernel
VM tests the builder mechanism; Secure Boot/BIP and whole-system upgrade
qualification have separate required gates.

### Runtime account and service databases

The runtime package now owns declarations for `pwd_mkdb` and `services_mkdb`.
They consume the selected `/etc/master.passwd` and `/etc/services` bytes and
produce finite, metadata-bound outputs: passwd/pwd.db/services.db are 0644,
and spwd.db is 0600. Owner and group are the system root/wheel numeric IDs;
the account identities and service entries themselves remain input data.
An explicit site override must name the replaced package hash and new content
hash. Generating these databases does not authenticate an account change, grant
a user a broker role, or implement a runtime credential writer.

`pwd_mkdb` now avoids changing mode when its input is already 0600, preserving
ZFS bookkeeping flags. Required permission changes must succeed before output
installation. Native and Secure Boot account tests cover in-place generation;
the construction VM consumes the actual runtime archive's recipes and generator
bytes, reads the resulting database indexes directly, varies site inputs and
checks public/secure database access. Supply `--runtime-package` to that VM
runner. Complete PAM/NSS and certificate closure, kernel hints, package
registration and upgrade migrations remain open; these two actions do not
replace runtime.ucl's legacy upgrade hooks or complete the protected updater.

Certificate utility qualification additionally requires the construction VM's
explicit `--certctl` input. The normal world/package targets build this utility;
the existing world bootstrap-tools target builds its host-compatible variant.
Input and output errors now propagate from certctl, so package construction must
reject its nonzero status. Error handling alone does not supply a certificate-store
construction
declaration or authorize default/local/legacy certificate inputs. Those still
need explicit package/site policy and derived output provenance before sealing.

For explicit certificate construction, `certctl -E` reads only repeated `-T`
(trusted file) and `-X` (untrusted file) arguments, including multi-certificate
PEMs. Directory discovery, environment search paths and the legacy blacklist do
not supply additional certificate inputs. Input paths are literal and are not
prefixed by `-D`; the builder must select them from verified inventory and explicit
site policy. Existing directory-discovery invocations retain their compatibility
behavior. `-n -U -M plan.mtree` encodes outputs in memory and reports their actual
names and sizes without creating the store. The plan is not authenticated or
approved merely because certctl emitted it.

The construction VM additionally requires `--caroot-package` and
`--certificate-policy`. It derives its complete certificate corpus from that
archive and those role-prefix rules, rejecting unclassified payloads. This
qualifies the explicit-selection and output-planning interface; it does not yet
bind site-policy approval or integrate certificate generation into protected
runtime updates. The production compiler below supplies trusted-builder receipts.


### Explicit certificate policy compiler

`build-bsd construct --certificate-policy /path/to/policy.json` adds certificate
construction after the package-declared actions. The optional policy is a regular
JSON file, at most 1 MiB, with duplicate/unknown fields rejected. The maintained
`certificate-policy.json` example is installed with the build-bsd examples. It is
an explicit starting input, not automatically enrolled trust policy.

Format 1 has these required fields:

- `name`: action identifier (1–64 ASCII letters, digits, underscores, dots or
  hyphens, starting with a letter or digit).
- `program`: absolute path of the packaged executable, bound to its archive and
  payload hash in the reconciled candidate.
- `selections`: up to 64 rules, each with `package`, `prefix` and `role`.
  Every non-directory payload below that prefix must be a regular file; empty
  matches and duplicate selections fail. Roles are `trusted` or `untrusted`.
- `files`: explicit additional `{ "path": ..., "role": ... }` inputs, already
  reconciled against package or generated-input expectations.
- `overrides`: explicit `{ "path": ..., "role": ... }` changes to selected files.
  Unknown paths and duplicate overrides fail. No implicit local/legacy source
  is consulted. At most 1024 files may be selected in total.
- `outputs`: `trusted_directory`, `untrusted_directory`, `bundle`, and numeric
  `uid`, `gid`, `mode`, `flags_set`. JSON mode 292 means octal 0444. Locations
  must not overlap, and output paths must be representable without mtree escapes.

The two index directories and bundle parent must be verified existing directories;
index directories must be empty and the bundle absent. This constructs a fresh
store, not a migration of an installed store. Explicit `certctl -E -C ... -R ...
-b ...` arguments fix the output locations. The planner runs the same packaged
generator in a temporary jail with `-n -U -M -`; the entire candidate must remain
unchanged. Its bounded, strictly parsed output permits only the bundle and hash
index files inside the selected directories. No observed installation output is
used as an allowlist.

The actual invocation must produce exactly the declared regular outputs with
planned sizes. Existing constructor checks reject all other changes, aliases,
execution failures and cleanup failures. Policy metadata is applied and measured
before the final reconciliation and receipt. The record binds the policy,
resolved paths/roles/content hashes, executable archive, plan and actual outputs.
Input authentication is explicitly false: selection is supplied by the trusted
builder, not authorized by root on a running protected system.

Generic declaration arguments now allow at most 4096 entries, 4096 UTF-8 bytes
per entry and 128 KiB in total including NUL terminators. Certificate planning
reserves space within those bounds for its extra arguments. Plans are limited
to 2 MiB and 1024 outputs. Oversized inputs fail instead of bypassing limits.

Complete dependency/configuration closure, authenticated policy approval,
package-database construction, generation sealing and protected update activation
remain required. TLS certificate selection does not authorize boot or code signing.


### Kernel module hints prerequisite

World and bootstrap targets build the changed kldxref from maintained sources.
Detected input/metadata and output failures must be fatal to generation
construction. Its temporary hints file is not installed after a detected failure;
prior directories in the same invocation may already have been updated. The
construction VM takes explicit `--kldxref` and `--module` inputs and runs the eight
maintained real-module checks without root privileges. No new build-bsd option is
needed for normal world/bootstrap compilation; the frontend manual and VM inputs
are updated together.

This does not add a package-construction declaration. Module selection is still
directory-based. Inventory-bound selection, complete ELF/PNP validation,
hardware/media binding to a qualified generator, and generated output provenance
must precede acceptance as part of an authenticated generation.

The PNP parser additionally checks descriptor delimiters/type-buffer bounds,
nonnegative table counts and positive strides, size arithmetic and field extents,
and propagates referenced-string read failures. Fatal exits remove unfinished
hints. A missing metadata section in a valid relocatable ELF object remains a
legitimate no-record input. The maintained construction Makefile and VM include
seven real synthetic ELF cases covering these distinctions. This is a tested
parser improvement, not a claim of complete hostile ELF validation or authenticated
module selection; those construction and runtime gates remain open.


### Media generator binding

The maintained host-tools Makefile has a kldxref target that invokes the normal
bootstrap Makefile in a separate object subdirectory. `build-bsd media` requests
that target and passes its executable through `HARDWARE_KLDXREF`; both release
staging variants forward `--kldxref`. The backend validates the explicit tool,
uses its absolute path, checks for a changed executable and logs executable/output
hashes after successful generation. A failed generator cannot append a successful
hints METALOG entry. Direct release callers must supply the explicit tool input.
This closes ambient PATH selection for this operation, not inventory-derived
selection or authenticated generation construction.


### Explicit module inputs prerequisite

`kldxref -o /directory/linker.hints /directory/module.ko ...` generates a fixed
output from only selected files, in argument order. It requires canonical
absolute paths, unique regular inputs and an output in the same directory so
recorded basenames retain their loader meaning. At least one input is required;
all-no-metadata input produces a version-only index. Architecture compatibility
includes files without metadata. Malformed selected inputs fail and leave the
prior output intact; unselected ambient files are ignored.

Normal world/bootstrap and build-bsd media host-tool builds consume this source
change. The construction VM stages the new maintained twenty-case audit without
an additional frontend option. Production media still selects files through its
existing directory mode: an inventory-to-recipe compiler and receipt integration
remain necessary before claiming package-derived module hints. The explicit
interface alone does not authenticate inputs or authorize module loading.


### Package-derived module construction

`build-bsd construct --module-policy FILE` uses `module_policy.py` to compile
explicit `kldxref -o` actions. The installed `module-policy.json` is an example
input, not an automatically trusted default. Each group selects immediate-child
payloads using package-name and basename patterns. Required empty selections
fail; optional empty selections are recorded without invoking the generator.
Policy permits at most 64 groups and 1024 selected inputs, with existing command
argument limits enforced. Exceeding a bound fails without truncation.

The generator and selected inputs must match unaliased regular package payloads.
Output metadata and replacement intent are explicit. `replace: false` requires
an absent destination. `replace: true` requires the existing destination to match
its owning package and content hash; replacement with an empty selection fails.
Outputs cannot overlap selected inputs or the generator. This supports kernel
packages that already own linker.hints without adopting arbitrary existing files.

The constructor rechecks bound inputs before execution, runs the action in its
restricted temporary jail, reconciles the complete candidate, and records
policy/selection/output hashes and replacement ownership in unsigned receipts.
These receipts establish construction provenance within the trusted builder;
package/policy authentication, generation sealing, full module coverage and
runtime loading authorization remain separate gates. Production media's legacy
directory mode is not converted to this compiler by supplying construct policy.

### pkg plugin configuration boundary

Deployment (both builder fetch and target install) and the shared signed-catalogue
verifier explicitly pass `PKG_ENABLE_PLUGINS=no`. The shorter `ENABLE_PLUGINS`
spelling is not the supported option and does not override an ambient enabled
plugin setting in dynamic pkg. Static pkg independently disables plugins and
would conceal this regression. The deployment and hardware tests use an explicit
`BSD_BUILD_DYNAMIC_PKG` executable (default `/usr/local/sbin/pkg`) and require a
positive enabled baseline before checking the backend's actual disabling option.
These tests query configuration only; they do not load a test plugin or establish
complete isolation of all pkg environment/configuration inputs.


### Advertised shared-library closure

The shared `package_closure.py` checker requires every `shlibs_required` name to
appear in `shlibs_provided` within the exact selected manifest set. Deployment
runs it after authenticated fetch and before destination creation. Combined
publication runs it after merging base/hardware and before publication or latest
advancement. Malformed library lists fail; architecture suffixes remain distinct.
No builder-installed library or root-writable pkg database supplies a provider.

This checks advertised metadata. It does not infer absent declarations from ELF,
resolve loader paths or plugins, select providers automatically, or approve code.
The construction VM stages the production hardware backend and shared helper at
their maintained relative paths. The installed deploy test files include the
helper so tests do not accidentally use another checkout's implementation.


## Package database preflight (incomplete generation verification)

`database_preflight.py --database /candidate/var/db/pkg/local.sqlite
--sqlite /absolute/path/to/sqlite3 --contract /path/to/expected.json` checks an
offline, quiescent database without modifying it. The version-1 contract has scope
`pkg-database-preflight-contract`, an explicit `engine_sha256`, `schema_version`
(42 or 1000), `schema_sha256`, and a nonempty `packages` array. Each package
has exactly `name`, `origin`, `version`, `abi`, `automatic`, `locked` and `vital`;
policy flags are integer 0 or 1. The SQL column named arch stores pkg's ABI and is
compared as abi. Duplicate names, unknown fields and unsupported schemas reject.

The schema digest covers canonical JSON of the ordered type/name/table/SQL schema
rows, using the helper's digest convention. It must come from the selected trusted
engine's schema contract. Never generate an approval contract from the candidate
being checked. Engine identity is recorded, not authenticated by this helper.
The helper checks schema, SQLite integrity and foreign keys, exact package control
state, and empty lock/process state. Every package-owned row must have an
existing owner, every dictionary link must have an existing target, conflict
references must name installed packages, and dictionary rows must be referenced.
These explicit checks also reject NULL links that foreign_key_check permits.
All four shared-library relations and both annotation roles count as owners.
This contract is for a freshly constructed generation database; it does not
approve retired, unowned dictionary records from an in-place package history. Nonempty WAL/journal files reject. Immutable
read-only SQLite access avoids sidecar writes; this does not make hostile live
filesystem races safe. Use the trusted builder's quiescent candidate.

A PASS covers only these preflight checks. Full archive record/all-table semantic
verification, authenticated contract generation, construction receipts and wiring
into generation sealing remain required. Current build-bsd commands do not treat
this standalone helper as completed generation acceptance. The maintained
bsd-build ATF suite includes real SQLite positive and adversarial cases; SQLite
and Python are explicit test prerequisites.


World package coverage also rejects contradictory repeated directory declarations
within a staged plist before pkg archive creation. Exact repeated declarations
are permitted; this does not waive whole-filesystem or archive ownership checks.
The top-level `create-packages-sets` target forwards to the maintained set backend
for resuming a candidate whose world/kernel archives are already complete. Keep
PKG_VERSION, build options, pkg executable and REPODIR consistent across those
steps. This target does not sign or promote a complete repository.


Staged ELF inspection qualification: run
`tools/test/construction/pkg-stage-elf-test.py --pkg <selected-pkg-static>
--cc <compiler> --abi <target-abi> --work <new-directory-under-/usr/obj/usr/src>`
before accepting a replacement packaging engine. The test builds distinct ELF
fixtures, creates a package containing an absolute alias and requires that host
ELF dependencies do not contaminate its manifest. It never installs a package.
The previous pkg 2.8.4_1 fails this test; its license-export fix does
not establish staged ELF inspection correctness. The maintained 2.8.4_2 port
corrects stage-namespace resolution and its archived executable passed eleven
positive/negative cases. Qualify each replacement engine, then supply its rebuilt
archive and digest through the existing build-bsd
`--pkg-package` and `--pkg-package-sha256` inputs. Do not waive library closure
or add compatibility symlinks to hide this failure.


## Archive-derived database payload records

`database_payload.py --database <candidate-local.sqlite> --sqlite <sqlite3>
--contract <trusted-preflight-contract.json> --inventory <archive-inventory.json>`
runs the structural preflight and then compares every stored file record,
directory record, directory ownership/removal-policy row, and dependency row
against the selected archive manifests. It checks checksums, named ownership,
permissions, flags, timestamps, symlink targets, dependency origin/version, exact
row multiplicity, and shared-directory agreement. Manifest paths are decoded with
the maintained inventory parser. Unknown file attributes, unsupported directory
forms and conflicting shared directory metadata reject. Immutable read-only
queries and before/after hashes are used on a quiescent trusted-builder database;
WAL/journal checks also run after the record phase.

The same expected schema/engine and explicit installation-policy contract used by
preflight is required. Inventory identities must match that contract exactly.
Neither contract nor inventory is authenticated by this helper. A PASS deliberately
retains complete_archive_records_verified=false: configuration
contents and remaining package metadata/dictionary values and installation-time policy
are not yet fully checked. Generation construction/sealing integration also remains
open. Do not turn this result alone into generation approval.

The maintained build-bsd test package now includes the helper, its real SQLite
mutation tests and the database_payload ATF entry. There is no new build-bsd
frontend option: these remain incomplete construction-verification components.
Existing 16.snap20261018214625 archives predate this source change; a subsequent
stage/package build is required to ship the new helper/test coverage.


Lua hook persistence qualification is available as
`tools/test/construction/pkg-lua-order-test.py --pkg <pkg-static> --abi <ABI>
--osversion <OSVERSION> --work <new-directory-under-/usr/obj/usr/src>`.
It uses real payload-free archives and a private database with scripts/triggers
and plugins disabled. The current 2.8.4_2 engine preserves distinct-hook order in
the observed fixture, but rejects repeated bodies and identical bodies across
phases. Qualifying future database construction requires preserving every hook's
phase, sequence position and multiplicity; unordered comparison is insufficient.
The correction must ship through the maintained port and existing explicit
build-bsd bootstrap archive/hash inputs. This test does not approve an installed
generation or exercise hook execution.


The maintained pkg 2.8.4_3 correction uses incompatible schema 1000 for ordered
Lua occurrences and enables SQLite CHECK constraints. The archive persistence
regression now passes all four cases. Migration qualification is available as
`tools/test/construction/pkg-lua-migration-test.py --pkg <new-engine>
--old-pkg <schema-42-engine> --sqlite <sqlite3> --database <legacy-fixture-db>
--fresh-database <fresh-schema-1000-db> --abi <ABI> --osversion <OSVERSION>
--work <new-object-root-directory>`. It uses private copies, checks exact stored
occurrences and matching Lua table DDL, rejects malformed phases with rollback,
and requires old-engine write refusal. It does not establish original archive
order for legacy data, prevent old read-only queries, or enforce BIP authority.

Schema-1000 occurrence preflight, direct hook comparison and new-engine
multi-hook VM execution have now passed the qualification described below.
Complete generation verification remains required. The new bootstrap archive is qualified as an input through the
existing explicit archive/hash interface, not automatically adopted or promoted.


Schema-1000 preflight now verifies integer phase/position values and contiguous
positions within each package/phase, in addition to existing ownership checks.
The payload-record helper compares shell bodies (one pkg percent-decoding pass)
and reviewed phase identifiers, plus every Lua occurrence's body, phase and
position. Repeated bodies and reuse across phases remain distinct occurrences.
Legacy schema 42 is still supported for non-Lua checks; any Lua occurrences require
schema 1000 for ordered verification. Unknown phases, invalid bodies and NUL reject.

The maintained build-bsd tests include hook mutation cases. The registration VM
now registers and deletes a private fixture package inside construction jails:
with hooks enabled, registration and database-loaded deletion both emit A–B–A;
with hooks disabled neither emits markers. Exported hook metadata preserves both
phases and all occurrences. The fixture confirms payload retention during
registration and explicit payload deletion afterward. It is not full system
installation, Secure Boot, or protected boot-environment deletion acceptance.
Current source/test changes postdate the archived system candidate and need a
subsequent stage/package build when shipping this coverage.


The payload-record helper now also compares categories, licenses, declared users
and groups, provides/requires, all four shared-library declaration roles, options
and annotation key/value pairs against the archive manifests. Values and owning
packages must match exactly; missing, extra and duplicate rows reject. Boolean
manifest options map to pkg's on/off values; other non-string map values reject.
Library roles are checked separately, and annotation pairing is preserved even
when the same dictionary text is used as both a key and a value.

The maintained build-bsd database_payload test covers each metadata family and
relationship mutation. The helper still does not verify all package-row fields,
conflicts, configuration contents or installation-time policy, and does not
approve a generation. Source review identified pkg's existing PKG_INSTALL_EPOCH
input for an explicit construction epoch; producer plumbing, policy validation
and timestamp verification remain to be implemented and tested. Expected policy
must never be copied from the candidate database. No new frontend input is added
until the complete construction contract is defined.


Database preflight contract format 2 adds required `install_epoch`, an integer in
0..2^63-1, to the format-1 fields. It compares every installed package timestamp
with that explicit expected value. Format 1 remains a partial legacy check and
reports installation_epoch_verified=false. Epoch values must come from trusted
construction inputs, never from the database being approved. The epoch supports
reproducible construction; it does not enforce a rollback floor.

The payload verifier also compares comment, description, maintainer, website,
prefix, flat size, license logic and dependency formula with archive fields.
Description text receives pkg's single percent-decoding pass. Omitted license
logic remains unset (0), distinct from explicit single (1), and (38), or (124).
Messages, conflicts, remaining internal fields and configuration contents still
need verification; full generation acceptance remains unavailable.

The construction VM runner now requires `--pkg-install-epoch <epoch>` alongside
`--pkg-registration`, `--pkg-abi` and `--pkg-osversion`. It records that input in
the identity file, stages env from the selected world, and passes PKG_INSTALL_EPOCH
explicitly to jailed package commands. The guest checks the exported timestamp
against the input in both hook-control cases. This interface is a qualification
fixture; the full build-bsd generation constructor still needs epoch/contract
plumbing. No public build-bsd installation command gains implicit authority from
these checks. Source/test changes must be staged and packaged before shipping.


The maintained construction runner's `--boot-environments` mode also verifies
that mounted environments and environments with held snapshots refuse deletion.
It checks retained dataset identity/content and retries after unmount/release,
then verifies deletion and preservation of surviving environments and shared data.
This uses a newly created private pool in a disposable VM. It tests storage
mechanics; authenticated retention policy, crash recovery, and normal Secure Boot
and SSH after an upgrade and deletion remain separate required gates.


Configuration baseline verification now compares database content bytes, owner
and pathname with the original archive inventory's regular-file size and SHA-256.
Empty text is accepted only for an empty archive payload; NULL and non-text
storage reject. Candidate/site configuration must never replace the original
merge baseline. Configuration declarations must agree with inventory; unsupported
link-based baselines reject. The production construction recipe must explicitly
retain these bytes: manifest-only registration currently leaves NULL baselines.
Encoded config-path parsing also remains an observed pkg correction gate. This
helper remains partial and is not yet authenticated generation acceptance.


The custom pkg `2.8.4_4` corrects encoded configuration-path parsing. Qualify a
selected executable with `tools/test/construction/pkg-config-path-test.py` using
explicit `--pkg`, `--sqlite`, `--abi`, `--osversion` and a fresh `--work` under
`/usr/obj/usr/src`. The test builds and reads a real archive and registers metadata
in a private database without installing archive payloads. Literal percent, UTF-8,
space, plus and plain names must round trip. This does not repair or qualify NULL
configuration baselines from manifest-only registration. Archive-based
`install --register-only --local-only` is the existing operation to qualify next
inside construction jails before integrating baseline construction.


The registration VM now verifies archive-based `install --register-only
--local-only --yes <archive>` with original and empty config baselines. Candidate
site config must remain unchanged and absent payloads must remain absent. Shell
and Lua hooks must not run even with RUN_SCRIPTS enabled; the exact selected
package and explicit epoch must match. This mechanism passed with the corrected
pkg archive, but production database construction, dependency/failure handling,
full metadata verification and receipt integration remain required. No direct SQL
baseline writer is needed. The test uses a dedicated archive-inputs directory;
pkg's root-level plist parent-path edge case remains separately recorded.


Database record verification now includes package messages and conflict
relationships. Message order, repetition, type and upgrade bounds must match
archive declarations; literal percent sequences remain unchanged. Conflict owners
and targets must match exactly. This does not authorize coinstallation of
conflicting packages. Unknown/ambiguous message fields reject. Internal digest
and reserved fields, complete schema coverage, and constructor receipt integration
remain required before treating database verification as complete.


Populated database solver digests are now recomputed from archive manifests using
the reviewed pkg local-archive version-2/type-2 profile. SQL NULL is a separately
reported absent cache state; it is not authentication. Unknown formats and
mismatched digests reject. Reserved mtree_id and pkg_format_version values must be
NULL. The constructor must enforce populated-cache counts if its policy requires
them. Repository/partial-load profiles and final table/column coverage review
remain unqualified; the helper still reports incomplete archive-record coverage.


The verifier now rejects table/column surfaces beyond the reviewed schema-42 and
schema-1000 formats, independently of the supplied schema hash. Hidden/generated
columns reject. Run `tools/test/construction/database-coverage-test.py` with
explicit `--database`, `--sqlite`, `--contract`, `--inventory`, `--helper` and fresh
`--work` inputs to test a baseline and four schema mutations. Negative tests
recompute schema hashes only to prove independent coverage rejection; those test
contracts must not be used as production policy. This guard does not replace
constructor provenance, epoch/cache policy, receipt or generation reconciliation.


Registration VM coverage now includes missing-dependency refusal and retry with
both explicit archives. Refusal must preserve the logical database; retry must
produce exactly the selected package set at the explicit epoch without changing
candidate files. Jail cleanup is checked on expected failure as well as success.
This does not qualify crash recovery or arbitrary partial-install failures, and a
separate dependency metadata update binding concern remains under investigation.


Custom pkg `2.8.4_5` corrects the confirmed dependency-update binding defect and
rejects SQL argument-count/binding failures. Use the maintained
`tools/test/construction/pkg-dependency-update-test.py` with explicit `--pkg`,
`--sqlite`, `--abi`, `--osversion` and fresh `--work` to check real archive upgrade
and rollback metadata in a private database. Archives are payload-free and hooks
are disabled. The test also preserves an unrelated dependency whose numeric name
matches the new version. This is metadata qualification, not application-data
rollback or complete generation-update acceptance. The archive remains an explicit
bootstrap input; it has not been automatically published or installed.

The dependency test also constructs fresh databases using one local-only,
register-only install transaction for both unchanged and upgraded dependencies.
It checks the selected installed versions independently from the consumer's
recorded build dependency version. The qualified pkg preserves that archive
metadata during fresh registration, while sequential replacement updates existing
dependency rows. Do not turn recorded build versions into exact solver pins.
The database constructor checks dependency origins and exact selected archive
identities against its contract without requiring recorded build versions to
equal selected dependency versions.
For the constructor preflight regression, pass the paired `--constructor`
(path to database_construction.py) and `--contract` (reviewed engine/schema
contract) to pkg-dependency-update-test.py. The fixture supplies its own exact
selected package identities and requires a deliberately altered selected version
to be rejected. These inputs authorize neither a production selection nor an
installed-system update. The maintained constructor passed this regression after the earlier VM reached
a terminal result. Full-system VM qualification of the change remains required.


Database preflight contract format 3 adds required construction_profile with the
single reviewed value `local-archive-registration-v1`. It requires install_epoch
and schema 1000, retaining explicit engine/schema hashes and per-package control
policy. The payload verifier requires populated matching solver digests for every
selected package and reports database_profile_verified=true only for this format.
Formats 1/2 remain inspection profiles. This field check does not authenticate
producer provenance: constructor execution, actual executable hashing, archive
selection and receipt integration remain required, and generation authentication
is still false.


`database_construction.py` constructs a fresh database in a separate restricted
jail using explicit --pkg, --sqlite, --inventory, --contract, --osversion and new
--work inputs. --plan performs read-only input checks without root. Execution
requires root for jail creation; use a disposable builder VM. The format-3 profile
and exact archive closure are required; current initial automatic/locked policy
is zero. Verification and input revalidation precede accepted database/receipt
publication. Failures retain diagnostics and publish no accepted output.

The registration VM can qualify this helper with paired --database-contract and
--sqlite inputs. Both construction and daemon VM runners accept --root-mib for
explicit filesystem capacity; the constructor fixture currently uses 384 MiB.
Successful construction and wrong-schema refusal passed in the disposable VM.
The helper's receipt is not authenticated, and its accepted database still needs
generated-file metadata and full generation assembly/reconciliation integration.


`build-bsd construct` and `construction.py` now accept all five database inputs
together: --database-pkg, --database-sqlite, --database-contract,
--database-policy and --database-osversion. The output policy explicitly names
the new database pathname and uid/gid/mode/flags_set; see
`database-output-policy.json`. The parent must already be verified and the output
must be absent. The backend constructs separately, re-verifies receipt/input/hash
bindings, installs through a verified parent descriptor with exclusive no-follow
creation, applies metadata, and performs full reconciliation before accepting the
outer generated manifest. This integration passed in a disposable VM fixture;
full selected-system and authenticated generation qualification remain open.

The separate `tools/test/construction/run.py --system-inventory <inventory>` case
qualifies database construction for the complete explicit package selection.
It requires the existing explicit pkg executable, ABI, OSVERSION, install epoch,
format-3 database contract and SQLite inputs. The inventory supplies archive
paths and hashes; metadata is re-read from those archives. Use `--root-mib`,
`--memory-mib`, `--constructor-timeout` and `--vm-timeout` to describe the builder
fixture's resources. The guest rejects conflicting identity inputs and captures
registration diagnostics on the serial console even when construction fails.
This case does not boot the selected packages as an installed operating system.

The selected-system case exposed an extra timestamp argument passed to the
five-column directory INSERT in pkg. The custom port revision 2.8.4_6 removes
that argument while retaining strict SQL argument-count and binding checks.
Directory timestamps remain filesystem inventory metadata; this database schema
does not store them. Run `tools/test/construction/pkg-directory-registration-test.py`
with explicit `--pkg`, `--sqlite`, `--abi`, `--osversion` and a fresh `--work`
under `/usr/obj/usr/src`. It builds real directory archives and checks exact
metadata and shared-directory ownership in a private registration database,
without installing payloads. The selected engine hash remains an explicit
construction-contract input; building this port does not publish or authorize it.

World package generation now invokes `release/scripts/mtree-to-plist.awk` with
`complete_dirs=yes`. Each package receives the declared parent directories needed
by its payloads, using the build METALOG's owner, group, mode and flags. Shared
ancestors may be declared by multiple packages with identical metadata; explicit
declarations are not duplicated. This does not select additional packages merely
because they own scaffolding. The filesystem root remains an explicit generation
layout input. Missing/incomplete parent records and contradictory directory
metadata stop packaging. Neither the staged filesystem nor the builder's umask
supplies missing policy. Kernel-only conversion retains its separate metadata
path; complete selected-generation reconciliation remains required.

The existing production stage currently fails this new requirement: debug bundle
ancestors and some license/data directories lack METALOG records. Correct the
maintained directory installation rules and restage before repackaging. Do not
backfill an approval manifest by scanning that stage. The maintained
`release/tests/world_package_coverage_test.py` covers positive shared ancestry,
explicit declarations and adversarial missing/conflicting/incomplete/symlink
parent inputs.

Debug installation now records all ancestors below configured DEBUGDIR using the
existing debug ownership policy, even during restaging. The common license root
is declared in BSD.usr.dist; Zsh declares its data root through DIRS. Per-package
license ancestors still need explicit source declarations before the existing
stage can be rebuilt and pass directory closure. Native debug installation tests
are in `release/tests/debug_directory_metadata_test.py`; their PASS is not a
full-world restaging result.

Nested license notice groups now declare their parent through DIRS, deriving the
path from the group's NOTICEDIR and preserving its package tags. Inside a native
buildenv, run `release/tests/license_directory_metadata_test.py --source /usr/src
--work <fresh-directory-under-/usr/obj/usr/src>` to exercise their actual directory
installation targets in private rootless stages. This test complements the full
METALOG closure gate; it does not replace restaging or archive reconciliation.

Shared base debug directories use DEBUGDIROWN/DEBUGDIRGRP/DEBUGDIRMODE, defaulting
to root/wheel/0755. DEBUGOWN/DEBUGGRP still govern individual debug files; a
program's special binary group must not change shared hierarchy ownership.
A fresh production stage now passes complete parent-directory conversion and
active package-target coverage. Rebuild archive inputs from that stage before
claiming package-derived filesystem closure; previous archives remain stale.

`build-bsd construct --extract-tar <explicit-regular-executable>` can now
materialize the complete selected archive payloads before executing declared
generators. Supply an empty root beneath a root-owned mode-0700 private builder
parent and a generated-input manifest declaring the root directory
(see `root-layout.json`). It may also declare otherwise unowned directories,
with explicit metadata, provenance and empty replacement lists. Package-owned
objects cannot be replaced by this extraction layout, even with matching archive
hashes. Files and symlinks must come from packages or subsequent declared
construction steps. All parent directories must be declared by packages or the
layout; extraction never invents missing parents. These declarations establish
directories, not writable mount policy or runtime access grants. The existing inventory reader rejects traversal, conflicting
objects, nondirectory ancestors and unsupported ACLs/xattrs before extraction.

The selected libarchive-based tar extracts without consulting host account names
and without applying ACLs, xattrs or file flags. Candidate account inputs are
checked against package hashes before resolving owner/group names. Metadata and
flags are applied, inputs are rehashed, and the entire tree must reconcile before
an extraction receipt can be included in the construction report. No package
scripts run during extraction. Partial trees from failure remain private and are
not accepted generations; use a new empty destination for retry. The builder and
kernel are trusted, and hostile concurrent host mutation is outside this helper's
contract. No archive/catalogue authentication or runtime update authorization is
claimed.

The full-selection constructor VM accepts an explicit `--system-layout` together
with `--system-inventory` to exercise this path plus declared generators and
verified pkg database installation. Its mechanism image is still separate from
the resulting candidate: passing it does not prove normal candidate boot or SSH.

The quiescent reconciler hashes each regular inode once per scan, retaining
per-path metadata checks and complete hardlink-set verification. The cache never
crosses scan boundaries, so each generator's result is checked against freshly
read contents. This does not extend the verifier's contract to a hostile live
filesystem. CLI payload extraction and construction emit phase diagnostics for
failure/timeout analysis; a partial private tree or phase marker is not an
accepted generation.

### Complete generation image materialization

`build-bsd image` invokes generation_image.py with explicit root, inventory,
final generated manifest, completed construction receipt and makefs/mdconfig/
mount/umount tools. The tools must be outside the candidate. It re-reads archives,
checks receipt bindings and the complete source observation, creates UFS2 without
fixture ownership overrides, then mounts it read-only and compares the full
observation before producing an unsigned image receipt. The tool runs as root in
a trusted builder; it is not a protected live updater. There is no signing,
activation, installation or reboot operation in this action.

The maintained image VM covers actual materialization and stale-observation
refusal; the native preflight tests use actual archives and construction receipts.
The independent retained-system verifier has also passed construction, read-back
and export of the full selected 281-package image. Normal boot, SSH and Secure
Boot integration remain unqualified.
The new tool and corrected makefs must be included in staged/published tool parity
before release qualification. Image receipts remain untrusted until the separate
generation signing/approval policy authenticates their inputs and outputs.


`build-bsd image --image-boot-archive` additionally exports the complete `/boot`
namespace from the same verified candidate as `boot.tar` and `boot.json`. It does
not maintain a second list of programs or use a kernel from another object tree.
The source is rescanned before and after serialization; archive names, contents,
links, ownership, modes and nanosecond timestamps are read back and compared.
The image receipt binds the transport hash and full observation inventory.

The archive is a transport, not an installable or authenticated boot tree. Its
bound observations retain flags and full hardlink sets, including aliases outside
`/boot`; reconstruction must apply and verify those relationships. Each regular
file alias carries its bytes, so an external alias never causes a path read outside
`/boot`. No extraction or link traversal occurs during archive verification.
The next boot-media step still needs explicit boot policy, coherent signing,
firmware enrollment and tests using the generation's normal PID 1 and rc.


`build-bsd boot-check --boot-image IMAGE --boot-archive ARCHIVE
--image-receipt RECEIPT` independently checks the collected files before boot-media
reconstruction. It validates all boot observations, parent types, hardlink sets,
archive members and file contents, including metadata and timestamps. It rejects
unexpected extensions and trailing data even when the outer archive digest has
been updated. The check never extracts paths or dereferences archive symlinks.
Both artifacts and the unsigned receipt are hashed; the full image digest and
source/read-back observation binding must agree. This checks consistency only;
metadata reconstruction, signing approval and actual boot tests remain required.


`build-bsd boot-stage` takes the same inputs as `boot-check` and a new `--output`
directory. It prepares `filesystem.mtree`, private payload files and `stage.json`
for makefs. Actual boot metadata comes from verified observations, not host
ownership. Internal regular hardlinks share source inodes so makefs preserves
them. External aliases are excluded from this separate boot filesystem and remain
in the installed root image. Symlinks are manifest entries, never host links;
hardlinked symlinks explicitly reject until supported. The synthetic outer root
is root:wheel, mode 0755, flags zero and epoch zero. Image read-back must match all
`expected_observations` before the filesystem can be accepted for boot-media work.
Without explicit signing inputs, this action prepares unsigned transport.
With signing inputs it produces the existing loader-manifest signature and,
when requested, a signed EFI loader; this is not a complete qualified installed
system or release approval. Signing rejects every input object occupying
`/boot/manifest`, `/boot/manifest.sig` or `/boot/manifest.certs`, including empty
directories and directory aliases, before output creation or signer invocation.
These names belong to the loader's signing format, not a list of OS programs.


### EFI verifier in ordinary world and pkgbase builds

UEFI verification is now enabled by default through `LOADER_EFI_SECUREBOOT`.
EFI has private `libsaefi`, `libluaefi` and `ficlefi` libraries, alongside its
existing IA32 variants. Its Makefile context enables the required BearSSL and
verifier code locally; ordinary BIOS libraries keep their existing options.
Normal world/install/package rules therefore select the verifier without copying
an independently built EFI executable into a generation after packaging.
`WITHOUT_LOADER_EFI_SECUREBOOT=yes` remains an explicit unprotected build choice;
it cannot establish a protected BIP boot chain.

The maintained build-bsd test set includes an amd64 configuration regression for
both EFI architectures, BIOS libraries and explicit disabling. The Secure Boot
fixture parser now links the same EFI library objects as the tested loader.
A clean EFI build, ordinary BIOS build and private top-level stageworld install
have passed. Publication parity and firmware qualification of the resulting
packaged generation remain separate requirements. The existing bootstrap test
scope is unchanged; its results do not prove normal installed-system startup.

Boot-stage receipts also expose `file_payloads`: each observed regular `/boot`
file maps to its staged payload path, size and SHA256. Internal hardlink aliases
have their own logical entries; directories and symlinks are excluded. Media
construction can use this mapping to locate packaged loader bytes without parsing
mtree text. Consumers must verify the selected payload against its binding before
use. The mapping is unsigned construction evidence, not release authorization.

`generation_boot.loader_manifest` renders the EFI verifier's literal line format
from explicit relative path/SHA256 bindings, in deterministic order. It rejects
whitespace, control/non-ASCII characters, traversal, oversized loader paths,
invalid digests and the manifest's own three signature files. There is no quoting
scheme in the verifier that would safely represent those inputs. This is a
serialization primitive: it does not discover the completed boot tree, resolve
aliases, authenticate inputs or sign. Media assembly must bind every final regular
file and resolvable file alias, including generated configuration and root-image
bytes, before invoking it. Those integration checks remain required.

`generation_boot.manifest_bindings` derives the complete file namespace from boot
observations, resolving file and directory symlink aliases entirely within that
inventory. It refuses dangling targets, escapes, non-directory traversal, cyclic
directory aliases and symlink chains exceeding the filesystem traversal limit.
The link count applies to each complete logical pathname, including all directory
aliases traversed before the final filename; it is not reset per directory.
Hardlink names remain separate manifest entries. It validates all resulting paths
with the loader serializer. This helper does not mutate the staged tree or add
root-image/configuration inputs: the media assembler must supply observations of
the completed tree. Its twelve tests include alias and failure cases; the retained
full-generation inventory produced 824 original file bindings. That unsigned
manifest lacks generated boot inputs and is not a boot-media acceptance result.

### Explicit library search construction

`build-bsd construct --library-policy FILE` accepts an explicit format-1 JSON
object with `program`, ordered `directories`, and `output` fields. For example,
a site can select its packaged `/sbin/ldconfig`, approved library directories,
and a new output beneath a packaged directory. There is no automatically enabled
search list. The selected generator must implement `-S`; old packages fail the
construction action rather than falling back to tolerant mode.

`library_policy.py` binds the generator to its package payload and binds every
selected directory and ancestor to reconciled root-owned directory metadata.
It rejects undeclared directories, aliases, unsafe modes, duplicates, delimiter
injection and preexisting output. The ordered ELF hints v1 bytes are specified
before execution; the constructor compares the complete actual output hash
before issuing a receipt. The resulting output is root:wheel mode 0444. A changed
directory, partial search list or unexpected generator output cannot be accepted.

This is trusted-builder construction. It does not classify runtime storage,
authenticate the policy, make the hints path the runtime linker's default, or
provision protected writable state. Those integration gates remain mandatory;
placing hints under a writable runtime overlay is not an acceptable substitute.


## Explicit final-phase file relocation

Installation policy format 4 adds entries of this form:

```json
{"format":4,"entries":{"/etc/example":{"operation":"relocate","target":"/state/example","package":"selected-package","requirement":"declared-file-requirement"}}}
```

The source must match a package-declared file state requirement. Relocation runs
only after package generators and database construction. Every source must then
be a reconciled regular nonexecutable file without flags or other hardlinks.
Destinations must be absent and unowned; physical parent directories must exist.
The constructor preflights all moves, stages aliases with explicit metadata,
moves each file preserving content and metadata, installs its public alias, syncs
the affected files/directories, and reconciles the complete tree. Generated
records name exact package replacements; receipts retain original observations
and policy identity. This grants no runtime authority and does not relax the
storage layout's configuration restrictions.

The candidate is private and unpublished throughout. Failure can leave partial
moves for diagnosis, but construction records FAIL and emits no successful
generated manifest. Discard that candidate; no automatic resume or atomic
multi-file rollback is claimed. VM transport preserves candidate paths verbatim
and never reads them as host input filenames. The retained verifier reconstructs the pre-relocation generated manifest from
initial inputs, installation records and hashed construction receipts. It reverses
the declared moves in the measured final tree and restores recorded parent
directory timestamps, permitting no other parent-metadata difference. It checks
the preceding filesystem digest, source content and metadata against prior
package/generated declarations, exact relocation records and the final manifest.
Unexpected or missing relocation receipts fail. These are consistency checks,
not authentication. Full-generation post-shutdown qualification remains required.

## Package-owned storage requirement inventory

A package manifest may contain a `5bsd.state-requirements` annotation whose
value is a JSON string. Format 1 contains exactly `format` and `requirements`:

```json
{"format":1,"requirements":[{"name":"queue","program":"/usr/sbin/example","path":"/var/spool/example","type":"directory","lifetime":"persistent","purpose":"Queued work retained across restart"}]}
```

Each requirement has exactly the six illustrated fields. Names are bounded
identifiers; program/path are canonical absolute non-root paths; type is file
or directory, or a Unix-domain socket; lifetime is boot, persistent or cache.
Sockets must have boot lifetime: an endpoint is recreated by a live process,
not restored as persistent data. These are required object types, not a request
to place sockets in immutable package payloads. Purpose is bounded text.
The program must resolve through package-local hardlinks to an executable
regular payload owned by the declaring package. The inventory binds its bytes,
the package archive and the declaration by SHA256. Symlink consumers and foreign
program ownership are rejected. Duplicate JSON keys, unknown fields, unsupported
versions and malformed declarations fail inventory construction.

Format 2 retains those required fields and permits `directory_mapping` only on
`directory` requirements. It names a canonical absolute non-root path distinct
from the fallback `path`. This represents a directory selector implemented by
the declared consumer, not a general override of program behavior. For example:

```json
{"format":2,"requirements":[{"name":"workspace","program":"/usr/sbin/example","path":"/etc","directory_mapping":"/etc/example-state","type":"directory","lifetime":"persistent","purpose":"Optional configured directory for updates"}]}
```

The completed-tree checker requires physical mapping parents. Absence selects
the fallback; a present mapping must resolve to a directory. Dangling links,
cycles and non-directory targets fail instead of selecting the fallback.
Reports preserve the declared path, mapping, selected path and resolved target.
The selected target still requires a layout boundary and all configuration,
executable and hardlink restrictions apply. Installation policy format 3 may
create the declared mapping as an alias at an absent, unowned path. Neither the
annotation nor the alias grants authority or authorizes relocating owned files.
Format 1 continues to reject the extra field.

Completed generation reconciliation rechecks every declared consumer against
its observed executable bytes. It emits `state_consumer_bindings` and rejects
missing, nonexecutable, redirected or byte-replaced consumers, even when an
explicit generated-object declaration otherwise permits that replacement.
Package-local hardlink consumers remain valid when the completed named file has
the declared bytes. These checks do not authenticate input packages or grant
state access; they prevent a replacement from inheriting stale requirements.

Reconciliation also emits `state_layout_review` from its completed-filesystem
scan. For each declared state path it records missing components, non-directory
ancestors (including symlinks), leaf type mismatches, covered objects, and
hardlinks crossing the proposed boundary. Object references point into the
report's measured `objects` map. A separate `alias_review` records the symlink
chain and candidate-tree destination, or a missing target, cycle/limit,
non-directory component or attempted traversal above the generation root.
Components are processed in filesystem lookup order, including `link/..`;
absolute targets remain inside the scanned candidate, never the builder host.
This does not change the coverage result for aliased ancestors, infer writable
paths, create missing state, approve mount coverage, or assign writer authority.
A successful filesystem reconciliation can still contain state-layout conflicts:
those require explicit policy decisions before state provisioning. No declarations
means no inferred writable boundaries, not proof that programs need no writes.

This is a requirements inventory, not a runtime permission schema. Paths are
requested locations and may conflict with immutable content or other packages;
policy review must resolve them before materialization. Package ownership grants
no writer authority. No mounts, directories, ACLs or exceptions are created by
this annotation. Configurable paths, reader/writer delegation, quotas, migration
and compatibility mounts need separate authenticated system policy integration.
Format 1 describes only literal locations; do not encode unevaluated variables
as if they were resolved configuration inputs.

The maintained package inventory emits `state_requirements`, with
`authority_assigned=false`, `runtime_paths_complete=false`, and packages lacking
the annotation listed explicitly. An explicit empty requirements list differs
from missing metadata but never proves runtime completeness. The maintained `tools/build/capimage/inventory_audit.py` backend rederives this
information from package manifests rather than trusting a supplied approval flag.
Run `build-bsd inventory-audit --inventory /usr/obj/package-inventory.json
--output /usr/obj/package-review` to write `inventory-review.json` into a new
output directory. `build-bsd plan inventory-audit` accepts the same inputs without
creating output. The old construction-test entry point remains a compatibility
wrapper. This review does not authenticate the supplied inventory or qualify
program behavior. Run `make -C /usr/src/tools/test/construction
inventory-audit-test` for declaration and report regressions.


State requirements also include `path_review`, keyed by declared absolute path.
Each entry lists package/name/program consumers, distinct object types and
lifetimes, and lexical declared ancestors. Conflicting types or lifetimes and
file ancestors are explicit review findings. Shared paths are not automatically
split into per-program datasets, and agreement does not authorize sharing.
An ancestor directory declaration does not grant access to descendants. Path
ancestry uses component boundaries; it does not resolve symlinks, mounts,
configuration-selected locations or existing filesystem objects. These findings
must be resolved by authenticated storage policy and generation reconciliation
before provisioning. They do not make the current inventory a policy compiler.


The review report also emits `packages[NAME].state_review`, listing each
executable candidate's exact-path declaration names and candidates without
such declarations. A declaration for one program does not cover other programs
in its package or hardlink aliases. Explicitly empty package metadata does not
clear these review gaps. Even candidates with declarations retain unverified
runtime completeness and functional coverage; candidate enumeration uses the
existing executable-bit heuristic. Candidate grouping visits recorded object
owners once rather than rescanning every object for every package. Exact-path
and hardlink-alias review semantics remain unchanged; missing declarations are
review gaps, not proof that each program writes state. This is a report over maintained build-bsd
inventory output, with no new authority, build option or acceptance waiver.

The runtime package declares login's three accounting files for the shipped
PAM lastlog session stack: active sessions, last-login records and history.
These are shared with utx, not private per-program storage. The runtime-specific
UCL retains its construction annotations; common subpackage metadata does not
inherit login's declarations. These cover only accounting, not all login or
configured PAM module state. In particular, declarations do not resolve PAM
session failure policy or grant arbitrary invocations accounting authority.

The SSH payload package declares the three terminal-accounting files for
`/usr/libexec/sshd-session`, where the monitor and session cleanup perform the
writes. These are shared with the login and utx requirements. The listening
`sshd` executable is not substituted for this consumer identity. Common SSH
metadata is separate from the payload annotation so debug, development and
manual subpackages do not declare a consumer they do not contain. This covers
terminal accounting only: host keys, PID files, user files, configured PAM
modules and other SSH state still need their own review and resolved policy.

The maintained inventory review also emits `state_inventory_review` for each
declared state path. It references an exact package object when present, lists
non-directory package ancestors (including links), lists contained package
objects, and classifies declared generator overlaps as exact, ancestor or
descendant. Referenced objects retain their ownership, configuration and link
metadata in the report's existing object tables. Component boundaries prevent
`/var/state` from matching `/var/stateful`. This exposes potential replacement
or shadowing of packaged content without choosing writable exceptions. All rows
remain `policy_review=required` and `filesystem_resolution_verified=false`;
links, actual mounts and configured locations need generation reconciliation.
Absent declarations produce no inferred writable paths. Generator declarations
do not establish that an output was created. This report is not a state-policy
compiler and supplies no runtime grants.


### NFS default writable-state declarations

The main `nfs` package declares mountd PID/client records, nfsd PID and stable
restart primary/backup state, the rpc.lockd local socket and rpc.statd status
database. Shared package descriptions do not carry these executable requirements.
The real generator tests compare defaults with source and verify subpackage
exclusion; maintained main/debug manifest generation is retained under
`bip-nfs-state-manifests-v2` (seven declarations, four consumers).

These declarations feed the existing inventory/reconciliation review. They do
not select an ordinary or protected dataset, authorize writers, or prove NFS
operation. Configuration-selected exports, overrides and security-sensitive
inputs require separate explicit policy. Existing published packages do not
acquire the new metadata until rebuilt and verified.


### Explicit storage partition input

`build-bsd reconcile --storage-layout-policy FILE` accepts:

```json
{"format": 1, "boundaries": [
  {"path": "/site-selected-state", "content": "ordinary"}
]}
```

Paths are inputs, not a built-in directory list. The boundary and its ancestors
must be existing physical directories in the exactly reconciled candidate.
Disjoint boundaries partition objects into immutable content and mutable seed
manifests; all observed seed metadata is retained. Each package state requirement
must resolve into a boundary. Crossing hardlinks fail. Ordinary mutable boundaries
may contain configuration and executables; membership in a package does not
make their runtime contents trusted. Explicit protected-consumer inputs must
remain immutable, including their alias traversal.
Protected boundaries are an explicit classification, not a writer grant.
Protected state requirements must not traverse ordinary storage on their way to
a protected boundary. This includes the namespace of an optional directory
mapping even when that mapping is absent: creating it later must not let an
ordinary writer redirect protected state. Immutable aliases and absent mappings
in the immutable namespace remain supported.

Format 2 additionally requires `protected_consumers`. Each entry contains
`consumer` (an absolute direct regular-file package payload),
`package_archive_sha256` (the selected verified inventory archive digest), and a
nonempty `inputs` array. Each input has an absolute `path` and `presence` equal to
`required` or `optional`. For example, owner policy can declare both the text
configuration and its generated database as inputs to the selected PAM module;
these paths are supplied by policy, not inferred from the `.db` suffix.

Format 3 adds the required `target_elf` object: `elf_class` (32/64),
`byte_order` (`little`/`big`), `machine` (ELF machine number), and `page_size`
(a positive power of two representable by native getpagesize). These are explicit
target inputs, not inferred from the builder. A consumer can additionally declare
`"code_loading": "bip"`. This requires matching native FreeBSD ELF identification,
one correctly sized ABI note, one feature-control note with `biprestrict`,
bounded program headers and kernel-sized/count-limited note segments. The
required contract version and note limits are protocol constants; a native test
cross-checks the public C definitions against the Python verifier.

The declaration checks image metadata; it does not rewrite package bytes or
assign authority. Missing/ambiguous markers and scripts fail this declaration.
`bip_image_admission` reports `required_contract_version` and
`runtime_enforcement_verified: false`; the enclosing code report also explicitly
sets `configured_manager_coverage_complete: false`. Matching the actual Capsule
configuration, validating executable placement/permissions for its handoff,
proving the selected kernel supports the declared target, and qualifying the
interpreter/dependency closure remain separate incomplete build gates. Do not
promote `metadata_valid` into a complete manager or generation acceptance claim.

For declared BIP consumers, interpreter inspection now rereads the resolved
candidate file through directory descriptors and checks its reconciled hash.
Its ELF class, byte order and machine must match the explicit target, with
nonempty, bounded program headers. The interpreter does not require a BIP
feature mark; the selected executable establishes that restriction. This rejects
corrupt/non-ELF and wrong-target inputs before image creation but is not proof
of runtime loading, kernel brand substitution or transitive library closure.

The consumer's completed-file digest must match that exact package payload.
Generated replacements and aliases cannot inherit the package declaration.
Consumers and every declared input must stay in immutable storage, including all
alias traversal. An optional input may be absent only at the final component,
with an immutable parent namespace; it cannot later be created by an ordinary
writer to override protected policy. Resolved inputs must be regular files with
reconciled digests. Protected mutable storage is also rejected for these inputs:
scoped mutable-policy writers require a separate completed authority contract.
Alias lookup follows the target kernel MAXSYMLINKS limit (currently 32), not
the host platform limit. Required and optional protected inputs exceeding that
limit are rejected; optional does not convert an invalid lookup into absence.
A source-alignment regression checks the limit against sys/sys/param.h.

The version-2 partition records `protected_inputs` with consumer/package/input
hashes and lookup observations. It explicitly leaves
`dependency_coverage_complete` and `runtime_enforcement_verified` false. The
caller still must supply the complete dependency set, obtain authenticated owner
approval, and enforce that contract at runtime. Generated-output provenance is
checked by the existing full filesystem reconciliation before partitioning.
Ordinary mutable configuration and executables remain allowed by the approved
simplification. This extension does not make version-1 policies prove
protected-input coverage. Construct, reconcile,
image and retained image verification consume the same validator through the
existing `--storage-layout-policy` input; no separate frontend flag is needed.

The report binds the policy input hash and marks seed installation, attachment
construction and runtime authority false. This is an offline construction check;
it neither authenticates input nor proves a complete dependency audit.
Current Capsule attachments still need empty immutable slots and actual dataset
identities. Generation splitting, seed installation and boot integration must
consume the validated plan before claiming a usable installed layout. Ordinary
executable third-party installations need their own completed design.

Qualification: 52 reconciliation tests and the frontend reconciliation-plan case
pass. `bip-layout-frontend-v1/result-v2` records a real frontend invocation on a
disposable tree, with partition completeness and seed/policy hashes checked.
The first fixture failure is retained; no package publication or host mutation
was performed.


The `image` action also accepts `--storage-layout-policy`: it consumes the exact
reconciled tree and builds a base image plus separate state seeds. Complete mtree
inputs select objects; no candidate contents are removed. The root-owned empty
attachment directories are explicitly recorded projections, while seed roots
keep their original metadata. All images undergo read-only mounted readback.
The aggregate receipt is unsigned and does not authorize activation or install
state. Immutable partition boot archive export is now supported; mutable seed
installation and activation remain unfinished.

Native coverage: 12 image tests and the maintained frontend image-plan case
pass. VM `bip-partition-image-vm-v2` passed guest image comparisons but failed
shutdown with a UFS/tmpfs WITNESS lock-order reversal. This is not a passing VM
qualification. See system-security.md for evidence and remaining gates.


Partition image construction now re-reads and validates its retained image set
before success, writing `verification.json`. `verify_layout` takes explicitly
selected observations, inventory, policy and input bindings; it re-derives the
expected projections instead of trusting receipt path/class claims. It verifies
child and aggregate receipts, image sizes/digests, mtree digests and recorded
readback digests. This is transport consistency, not input authentication or
repeated filesystem readback. Seventeen native tests pass, including corruption,
missing/reordered entries, symlink substitution and false scope/readback claims.
The real UFS path completed in bip-partition-image-vm-v3, but that VM still FAILED
the shutdown WITNESS gate. See bip-partition-image-validation-v3.json.


With `--image-boot-archive`, partition image construction exports `base/boot.tar`
and binds it to `base/receipt.json`. All /boot observations must remain unchanged
in the immutable base. Mutable partition receipts are rejected by boot transport
verification. Pass the base image/archive/receipt to boot-check or boot-stage and
retain the aggregate image set and seeds for later installation. This does not
install seeds or activate attachments. Native image tests: 18 pass; boot transport:
22 pass, 1 environment-dependent skip; frontend combined plan: pass. Guest
construction completed in bip-partition-boot-vm-v1, but overall VM qualification
still FAILS on the retained shutdown WITNESS issue. It is not an installed boot.


### Empty state initialization

`seed_initialize.initialize` is an internal offline construction primitive.
It requires explicit disjoint physical source/destination directories, an empty
exclusively owned destination, expected source observations, an external archive
tool and a fresh work directory. It refuses existing data, archives and restores
children with numeric ownership, applies root metadata last, and scans the result
for exact equality. It preserves partial output on failure instead of deleting
or merging data. Dataset provisioning/identity, authenticated policy, activation
and upgrades are not implemented by this helper; its receipt says so explicitly.

22 image tests pass. VM bip-seed-init-vm-v3 passed mounted-seed initialization and
existing-data refusal but still failed shutdown WITNESS qualification. v1/v2
retain the discovered root-timestamp failure; the fix applies metadata after
child extraction, without weakening observations. No host installation occurred.


### Fresh ZFS state dataset primitive

`seed_dataset.provision` takes explicit selected seed observations, new child
name, pool/parent GUIDs, external tools and a new work directory. It checks
identities before creating the child, verifies the mounted dataset and initializes
it exactly, then leaves it unmounted with legacy mountpoint/noauto. Existing
names and wrong identity reject. Failure retains the new dataset; this helper
never creates pools, destroys datasets, merges existing state, signs policy or
activates boot. It requires an exclusively owned offline builder. Public
build-bsd install/activation integration remains unfinished.

ZFS requires explicit restoration of zero flags omitted by archive extraction.
Flags are restored once per inode so hardlink aliases do not repeat metadata
updates that reset UF_ARCHIVE. Native before/after regression logs are
bip-seed-flags-regression-before.log and bip-seed-flags-regression-after.log.
25 image/seed tests pass. bip-seed-dataset-vm-v5 passed provisioning, exact copy,
existing-name/wrong-pool refusal and remount persistence, but overall VM status
remains FAIL on shutdown WITNESS. It does not establish cross-boot upgrades.


Construction records now fsync the parent directory after rename. New dataset
provisioning records its GUID before population and calls zpool sync on the
selected pool before its success receipt. Crash/power-loss recovery still needs
qualification. The two-VM seed persistence test retains actual identities and
full observations, imports the original disk read-only in a new boot and checks
exact state. The separate readback VM passed cleanly; the creating VM retains
its shutdown WITNESS failure. See system-security.md and
bip-seed-persistence-readback-validation-v1.json for the scope of this evidence.


### Native Capsule static configuration validation

`build-bsd compose-config` can take `--capsule-validator` and
`--capsule-validator-sha256` together. It invokes the selected matching Capsule
with `-n -f` on the composed file before receipt publication. The candidate and
validator hashes must remain unchanged. Invalid static policy or wrong selected
hash leaves no success receipt. The recorded scope is syntax/static constraints,
not source authentication, live resource checking or runtime authority. The
builder must provide matching runtime dependencies for its selected executable.

Native CLI and maintained frontend plan tests pass. Real frontend evidence in
bip-compose-native-validate-v1 includes valid policy, invalid content-class and
wrong-validator-hash cases, with selected executable/dependency hashes. This
mechanism does not bind provisioning receipts into authenticated boot policy yet.


### Immutable policy/storage consistency

`image --storage-bindings FILE` requires an explicit storage layout. Its format-1
input has policy_path (a regular immutable candidate JSON file) and bindings
(path plus selected provisioning receipt). It requires exact attachment coverage
between policy, layout and receipts, matching content classes and pool/dataset
identities, synchronized successful provisioning and exact seed readback hashes.
Changed policy bytes, stale seeds, incomplete receipts and reused identities
reject before output. The retained image verifier repeats these checks.

This currently supports attachment-only storage arrays; unattached providers
reject pending separate binding support. Receipts are trusted-builder consistency
evidence, not authentication or runtime authority. Native policy validation,
live identity verification and authenticated activation remain separate.
32 image/seed tests and the frontend plan pass. bip-storage-binding-vm-v1 passed
real ZFS/image assertions but overall FAILS shutdown WITNESS qualification.


### Native policy gate for bound images

The public image command requires --capsule-validator and
--capsule-validator-sha256 whenever --storage-bindings is selected. After
reconciliation and binding checks, the selected native Capsule validates the
actual candidate policy before image construction. Its receipt is included in
image input bindings. Validation logs are outside the candidate; policy hash
and complete candidate observations must remain unchanged. The trusted builder
must provide matching runtime dependencies for the explicitly selected tool.

35 image tests, nine composition tests and two frontend cases pass. Actual
Capsule acceptance/rejection is recorded in bip-native-image-parser-v1.json,
using synthetic provisioning evidence. This does not qualify authenticated
startup or upgrades; internal API mechanism tests remain separately scoped.

### Protected authentication default

The shipped `/etc/pam.d/5bsd-authenticate` denies authentication and account
management until the owner supplies an authenticated generation policy. It must
not silently use the running system's ordinary NSS accounts to establish
protected user authority. Normal login, sshd and su PAM service files are
unchanged. An owner-selected protected policy must bind its account inputs,
modules and authorization mapping to the authenticated generation; selecting
`pam_unix protected_passwd=/absolute/path` alone does not prove that whole closure.

The normal world/package targets consumed by build-bsd install this default.
Existing published repositories retain their previous payloads until rebuilt.
Construction must carry any explicitly selected replacement policy through the
existing generated-file contract and final filesystem reconciliation. No default
account path or signing key is invented, and no new frontend bypass is provided.
The secureboot fixture preserves ordinary NSS password checks under an explicitly
named `vm-ordinary-password` policy and tests the shipped service's denial
separately. These are mechanism tests, not production authenticator enrollment.

### Package-derived boot-environment traversal checks

Deployment now derives private traversal directories from validated package and
explicit generated objects. The remaining fixed directory tuple is the set of
paths the backend itself creates/uses (including its private package database and
temporary devfs mountpoint); the creation loop uses that same tuple. It is not
an inventory of OS programs or BIP policy. New package locations therefore enter
the checks without editing a maintained directory allowlist.

Source mounts covering these directories are refused. After mounting the clone,
all nested mounts are refused before any package script runs: scripts may write
outside their declared payloads. Existing traversal components must be physical
directories on the clone filesystem. Legitimate separate datasets require an
explicit future construction/migration design; this check does not grant script
sandboxing or protect against a hostile trusted builder. Frozen authenticated
activation and live update authorization remain separate unfinished work.

The 35 lightweight deployment tests pass, including a new package location,
a parent symlink and a nested mount outside the inventory. The existing BE VM
fixture caller is updated, but VM qualification is on hold at the user's request.

### Composed filesystem topology validation

The shared `expected_objects` validator now rejects a declared non-directory
root and any object beneath a declared file, hardlink or symlink. The check runs
after explicit generated replacements are composed, so authenticated replacement
provenance cannot override filesystem structure. Leaf symlinks remain valid;
this check does not prove that their targets or consumers are safe. It rejects
known parent conflicts, not missing-parent declarations (the extraction path has
its separate complete-layout check).

Normal build-bsd deployment uses this validator before BE creation or chroot;
construction and reconciliation share it. No new flag or policy exception is
introduced. Adversarial tests first reproduced four accepted invalid cases.
After the fix, 64 reconciliation and 37 deployment tests pass, including rejection
before BE creation. These lightweight tests do not qualify a real upgrade.

The composed-input check also resolves archive hardlinks after generated
replacements. Every chain must terminate at a regular file; cycles and targets
replaced by directories or symlinks fail before construction. Package-level
validation alone cannot establish this property after replacements. Reconciliation
uses the same resolver and retains its existing metadata and actual-inode checks.
Resolution caches completed chains; it does not repeatedly walk each suffix.
Two adversarial tests reproduced the old acceptance. After the correction,
66 reconciliation and 37 deployment tests pass, without builds or VMs.

### Deployment cleanup failure regression coverage

The deployment unit suite now has 39 passing tests. Its failed-devfs-unmount
assertion recognizes `bectl -r <root> unmount`; a temporary premature-unmount
mutation is rejected by that assertion. Additional cases check failed BE creation
and final BE unmount: neither emits DEPLOYMENT_VERIFIED, and the helper does not
activate or destroy a candidate. Filesystem reconciliation PASS alone cannot
hide an unmount failure. Lifecycle commands are mocked in this suite; real BE
upgrade, interruption, rollback and deletion still require VM qualification.

### Source identity during boot-environment creation

The deployment helper now compares the selected source dataset GUID immediately
before clone creation and again before making the candidate writable. An observed
replacement aborts; an already created candidate is retained for investigation.
The 42 deployment tests pass, including replacement before and during creation.
ZFS/package commands are mocked: this is consistency-check evidence, not a live
upgrade or protection from a hostile concurrent administrator. These checks do
not pin a snapshot object or serialize ZFS writers. The existing build-bsd deploy
backend consumes the change without new inputs or an alternative workflow.

### Explicit source snapshot identity

For `--clone-from BE@snapshot`, deployment now records that snapshot's GUID and
rechecks it before creation and before making the candidate writable. Invalid,
missing or changed snapshot identity aborts without automatic candidate deletion.
The native suite covers stable identity, replacement before/during creation and
malformed GUID responses. Queries are mocked; this does not pin objects or close
races with concurrent ZFS changes. Recursive child snapshot identities are not
covered by this root snapshot check. The existing build-bsd deployment backend
and VM clone fixture use the updated helper; no new build inputs are introduced.

## Preparing motd for an immutable configuration tree

The rc package declares `motd-output`, `motd-compatibility` and
`motd-temporary-workspace`. With `/etc/motd.template` and the `/etc/motd` alias
already present, the existing startup function generates `/var/run/motd`
without migrating configuration under `/etc`. Supply template bytes through the
existing explicit installation `create` operation, with their size/hash and
ownership, and select a format-3-or-later alias entry such as:

```json
"/etc/motd": {
  "operation": "alias", "target": "/var/run/motd",
  "package": "5BSD-rc", "requirement": "motd-compatibility"
}
```

This is an entry within the installation policy, not a complete policy or a
special image-builder rule. The named package requirement must exist in the
selected inventory. Creation requires an absent, unowned destination; an
existing legacy message must be preserved and migrated explicitly, never
silently overwritten. Writable runtime and temporary storage still require
selected layout policy and runtime provisioning. TMPDIR overrides need separate
reconciliation. A native startup-function test validates the prepared layout. Planner tests
check the immutable template/alias partition, ordinary output boundary and
rejection of occupied destinations without mutation. These checks do not
establish constructed-generation or installed BIP acceptance.

#### Ordinary storage policy

Ordinary writable configuration and executables are permitted in explicitly
selected ordinary boundaries. The planner grants no protected authority to
those bytes. Protected input and cross-boundary hardlink checks remain enforced.

### Manifest signing certificate custody

The boot-stage signing certificate input must be a certificate-only PEM chain,
with the signer certificate first. Mixed private-key/certificate PEM, other PEM
objects and non-whitespace material outside certificate blocks are rejected
before any input bytes are written into staging. Each certificate is parsed
through the explicit OpenSSL tool and emitted as canonical public PEM; malformed
later certificates also fail. Receipts record both the input certificate hash
and the emitted chain hash. This is syntax/public-material validation, not trust
chain validation, firmware enrollment or release authorization.

The normal build-bsd boot-stage backend consumes this validation. No new CLI
input or signing-key copy is introduced. Native regressions use throwaway keys
and real OpenSSL; they do not establish production key custody or verified boot.

### Public trust input custody

The shared hardware backend validates copied public trust inputs for catalogue
verification, signed media, deployment and interactive installer preparation.
Each input must be a bounded regular nonsymlink file containing one PUBLIC KEY
or RSA PUBLIC KEY PEM block. It is parsed with /usr/bin/openssl and only canonical
public-key output is written to a new destination. Mixed private-key material,
extra PEM objects and malformed keys fail before destination creation.

This prevents accidental copying of combined PEM files through public-key inputs;
it does not inspect every package payload for secrets or establish production
key custody. The existing build-bsd media/deploy/bsdinstall backends use the shared
helper without new CLI inputs. Lifecycle unit tests mock this hardware dependency;
the hardware suite covers real parsing and mixed-PEM media rejection.

### ELF metadata and declared interpreter binding

`elf_dependencies.py` inspects supplied reconciled ELF bytes without executing
an image or consulting the host library search path. Program headers drive the
inspection, including for objects without section headers. It records interpreter,
NEEDED, SONAME, RPATH/RUNPATH, filter, auxiliary and audit names, retaining search
expressions for a later target-specific resolver. Both ELF classes and byte
orders are handled; malformed bounds, duplicate singleton tags, ambiguous
file-backed string mappings and unterminated strings/tables are rejected.
Extended program-header counts and non-UTF-8/control-character names currently
fail explicitly. It is not a complete ELF/ABI validator.

The maintained `elf_dependency_metadata` build test includes synthetic malformed
and cross-format objects and a real compiled shared object. The reader does not
resolve dependencies, model libmap/hints/dlopen, authenticate inputs or grant
runtime authority. With storage layout policy, construct and reconcile now emit
`protected_consumer_code`: direct metadata for each explicitly selected protected
consumer, tied to its package archive and completed-file digests. Each consumer
is reopened through directory descriptors without following intervening symlinks;
bytes are checked against the reconciled digest before inspection. Malformed ELF
fails this inspection. Non-ELF inputs are recorded as unsupported dependency
formats, never as an empty verified closure. This assumes a quiescent trusted
builder and is not protection against a hostile concurrent host.

No receipt gains dependency-coverage credit. Target lookup resolution and runtime
enforcement remain pending, and image-layout receipts do not yet attest a
resolved dependency set. No new build-bsd CLI or signing-format input is needed:
existing construct/reconcile actions and `--storage-layout-policy` select this
metadata step. The metadata is evidence, not a grant or an authenticated policy.

The ELF reader checks that PT_DYNAMIC's file offset agrees with its file-backed
virtual mapping, matching the target loader's use of p_vaddr. Dynamic/string
metadata must have one unambiguous file-backed mapping; even partial overlapping
load or zero-fill regions are rejected. Wrapped target virtual address ranges
are rejected. Empty RPATH/RUNPATH strings are preserved distinctly from absent
search tags. These checks do not model page-rounded loader mappings or replace
full target ELF/ABI validation. Maintained regressions exercise these cases.

Declared PT_INTERP references of protected consumers are additionally resolved
against reconciled candidate observations. Missing/non-file targets, mutable
lookup components (including symlinks that later return to immutable storage),
and mutable hardlink aliases fail construct/reconcile. `interpreter_reference`
records the selected path, resolved path, traversed aliases and observed digest.
No host path is consulted and no interpreter is executed. This checks the
reconciled reference, not interpreter ABI validity or concurrent host changes.
Kernel brand substitution/fallback, loader libraries and later dynamic loading
remain unqualified; dependency_coverage_complete stays false. Normal applications
outside the explicit protected-consumer declarations are unaffected.

ELF metadata also retains `dynamic_flags` (DT_FLAGS) and `dynamic_flags_1`
(DT_FLAGS_1). Repeated entries accumulate by bitwise OR, matching the target
rtld digest routine; unknown bits are preserved. Omitting these would lose
ORIGIN, filter-loading and NODEFLIB behavior relevant to dependency resolution.
Synthetic tests cover both widths and byte orders, repeated flags and unknown
bits; a real linked shared object checks `-z origin` and `-z nodefaultlib`.
These fields flow through existing construct/reconcile reports without a new
build-bsd input. They do not establish a resolved closure or runtime enforcement.

### Candidate boot-environment identity consistency

`deploy` retains the newly created candidate GUID and clone origin, rechecks them
before readonly=off, before/after mounting and before devfs and BE cleanup unmount. An observed
replacement or query failure prevents the next named operation and no deployment
success marker is emitted. A candidate whose identity cannot be verified is
retained for operator diagnosis; the helper does not destroy it automatically.
The native deployment suite mocks ZFS and exercises replacement before the
writable transition, mount, installation admission and cleanup, plus changed
origin and query failure. This is consistency checking in an exclusive builder,
not an atomic object pin or a compromised-root defense. Concurrent mutation
between queries and operations remains outside this backend's guarantee.
Dataset-property queries reject duplicate or missing fields, non-ASCII, zero or
out-of-range GUIDs, unknown readonly values, empty origins and diagnostics.
The deployment suite has 54 passing native tests; ZFS/package commands are mocked.
Detected replacement prevents devfs cleanup after both success and installation
failure. Temporary devfs has a separate device/inode/filesystem identity checked
before unmount, along with mount topology and canonical-path checks. Missing or
changed identity retains both mounts for diagnosis. These are exclusive-builder
consistency checks, not atomic mount binding against a hostile root. The scratch
path is resolved once after creation to support an existing build-root symlink.
The normal build-bsd deploy backend consumes the change without a new CLI input.

The direct `sign-stage.sh` entry point enforces the same private-key mode and
parent-directory write-permission checks as prepare-stage/frontend planning:
keys must not grant group/other access, must be readable by the signer, and their
canonical parent must not permit group/other writes. Existing rejection of
symlink keys and keys inside the staged image remains. The packaged
`signing_custody` test exercises preflight only, with non-key bytes and no signer
execution. These UNIX checks do not provide custody against compromised root on
the signing host; owner key isolation and enrollment/rotation remain separate.

`capsign key-id`, used by stage trust-catalogue verification, now requires a
bounded regular nonsymlink file containing one public-key-only PEM object.
It rejects mixed public/private PEM files, additional keys and unrelated prefix
or suffix data. Whitespace around the public block is accepted. Rebuild the
selected native CAPSIGN tool to obtain this check; an old installed signer does
not acquire it merely from a source update. The capsign CLI regression uses only
fresh disposable fixture keys. This format check is not key enrollment authority
and does not establish verified boot or private-key isolation from host root.

The maintained capsign `verify_stage` regression includes mixed public/private
PEM inputs in both the enrolled catalogue and the external trust-file argument.
It checks refusal and recovery with the original public-only file. Native
`verify_stage` and `stage_sign` passed against current capsign/libcapbundle/
libcapimage sources in a local tool; no installed-system or verified-boot claim
follows from these helper results.

### ELF feature-control evidence

The construct/reconcile consumer metadata includes
`freebsd_feature_control_notes`: every FreeBSD feature-control occurrence with
its value, file offset and containing segment size. Unknown bits and duplicates
are preserved. Truncated/misaligned notes and invalid feature descriptor sizes
are rejected for inspected consumers. This records the new `biprestrict` feature bit (0x80) like other bits; it does
not establish effective kernel feature state; brand selection, target page size
and kernel note-parser limits require separate validation. Ordinary package
membership still grants no protected authority. The native suite also compares
feature-note edits made by elfctl, including setting/removing `biprestrict`, on
an unexecuted temporary executable. The packaged test requires python3.12, cc
and a current elfctl; its `elfctl` configuration parameter selects the tool for
object-tree runs (`BSD_BUILD_ELFCTL` for the Python suite). Declarative `ELF_FEATURES` marking now happens in the standard link rules;
configured-manager generation admission remains incomplete. The additive kernel/rtld
restriction does not complete handoff admission or replace the existing loader
selectors; construction must not claim protected-manager coverage from note
presence alone.

### Manager marking and handoff admission

Standard program link rules apply declared `ELF_FEATURES` through `ELFCTL`
before debug splitting, stripped install artifacts, signing and package
inventory. SwitchBoard declares `biprestrict`; other managers can declare the
same loading contract. No stage-tree rewrite, automatic authority grant or
manager-path whitelist is involved. The owner still chooses `service_manager`
in Capsule configuration. Parsed source makefile changes trigger relinking;
command-line setting changes require a clean rebuild outside meta tracking.
A marker failure removes the new link output to prevent reuse on retry.

Capsule now requires the native `bootstrap_check_manager_elf(fd)` validator and
exact supported kernel `image_restriction_version` before BIP manager exec.
Unmarked/unsupported binaries fail closed; normal-mode launch remains separate.
The generation verifier still needs a configured-manager/loader compatibility
gate: runtime failure is not proof that a publishable image is usable.

The packaged `elf_feature_build` test builds disposable programs through the
maintained rules and verifies feature retention through debug splitting and
stripped capimage install artifacts, per-program selection, failed marking
cleanup, incremental changes and unchanged rebuilds. It accepts `source` and
`elfctl` configuration inputs. The native mechanism tests use
`make -C tools/test/secureboot manager-elf-test manager-image-test
ELFCTL=/path/to/current/elfctl`. These tests do not qualify a BIP boot.

### BIP process-control contract version 2

Capsule requires version 2 before creating its BIP manager. The enforcing kernel
provides a pre-publication guard for children of PID 1 and guarded images;
successful exec commits image-selected protection after descriptor cleanup.
An ordinary image can regain normal process control, while explicit permanent
PD_PROTECTED and independent service protections remain unchanged. Older kernel
contracts fail manager startup. The normal world/kernel rules include this
change; a partially rebuilt image is not sufficient.

The maintained Secure Boot runner now requires both permanent-protection and
ordinary-exec guard-transition evidence. Guest compilation and native state/
evidence tests passed; the new guest assertions have not run. This does not
replace configured-manager generation validation or prove arbitrary descriptor
handoffs safe. Signing and boot verification alone do not prove compatibility.

### Immutable installation templates

Installation policy format 5 adds `replace-template`, using the same explicit
source/hash/size/metadata and exact `replaces` archive digest as `replace`.
Eligibility comes from the owning package's `5bsd.installation-templates`
annotation, a JSON string such as
`{"format":1,"paths":["/boot/capsule.conf"]}`. Paths must be canonical,
unique, directly owned regular nonexecutable payloads without file flags and
must not be mutable pkg configuration. Inventory validation checks declarations;
constructor validation retains existing source, alias, parent, hardlink,
metadata and generated-output conflict restrictions. No path is special-cased
in the constructor. Capsule declares its boot policy template only in its main
package; split debug/manual packages do not own it.

This is trusted offline construction eligibility, not runtime write authority.
The selected authenticated package must actually carry the declaration; older
published archives do not gain it from a newer source checkout. The maintained
`build-bsd construct --installation-policy` input supports the new format through
its existing backend, without a new frontend option.

### Native Capsule configuration validator

`bsd-capsule-validate` is installed with build-bsd under
`/usr/libexec/bsd-build`. It statically links Capsule's production parser and
shares the effective-policy JSON report with `capsule -n -j`. The maintained
`host-tools.mk` also provides a native `bsd-capsule-validate` target for builds
under `/usr/obj`. Pass the executable and its SHA256 through existing
`--capsule-validator` and `--capsule-validator-sha256` inputs. No staged-library
environment or host library installation is needed. Static validation does not
establish mounted storage identity, runtime authority or successful startup.
The build-bsd native_capsule_validation test reuses the production Capsule CLI
contract, including invalid policies and validation without daemon effects.

The disposable construction `state_allocation.py` guest accepts an optional
`execution` object per explicit dataset binding and passes it through the same
state-storage validation used by build-bsd. Omission retains exec/setuid off;
ordinary UNIX storage may explicitly select both on. These flags do not grant
protected authority. The guest allocates and exports a new pool only; allocation
is not initialized state or installed-system qualification.
The independent `state_readback.py` guest checks those receipted execution flags
after importing the disk read-only. Invalid explicit policy is rejected; legacy
receipts without execution fields retain off/off expectations. Readback checks
dataset identities and properties, not seed contents or runtime enforcement.

## Disk-backed integrity component (not yet integrated)

`verity_tree.py` implements internal bounded tree construction and individual
block read verification for the dm-verity v1 layout, SHA-256, equal data/hash
block sizes and no superblock. It accepts power-of-two block sizes from 512 to
65536 bytes, at least two complete data blocks, salt up to 256 bytes and signed
64-bit file offsets. Unsupported geometries fail explicitly. The caller owns
input consistency and authenticates the root digest, geometry and salt.

`make -C /usr/src/tools/test/construction verity-tree-test` checks fixed upstream
cryptsetup root vectors, tampering, truncated inputs, offsets and block-sized I/O.
These are component tests, not an RSS measurement, kernel test or VM qualification.

The module has no standalone CLI. The maintained image backend now invokes it
when build-bsd image selects --image-verity-policy with a storage layout. This
constructs unsigned artifacts; boot-stage does not yet consume them. Authenticated
boot handoff and installed-root integration remain unfinished. Component test
success is not proof of those missing steps.

The companion C core in `sys/geom/verity/g_verity_verify.[ch]` verifies one block
using caller-provided exact-read callbacks and private buffers. Its host tests
compare nonzero data with this builder and verify output remains unchanged on
corruption/I/O errors. It is not yet a registered GEOM provider or a kernel-tested
boot path. Authentication, provider lifecycle and I/O synchronization are caller
integration requirements, not properties supplied by the core alone.

### BIP root descriptor v1 (internal, not activated)

The unsigned encoder and C structural decoder use exactly 384 bytes, big-endian
integers, and these offsets:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 8 | BIPROOT followed by NUL |
| 8 | 4 | Descriptor version 1 |
| 12 | 4 | Total length 384 |
| 16 | 4 | dm-verity format 1 |
| 20 | 4 | Hash algorithm 1 (SHA-256) |
| 24 | 4 | Filesystem 1 (UFS2) |
| 28 | 4 | Equal data/hash block size |
| 32 | 8 | Data length in bytes |
| 40 | 8 | Computed tree length in bytes |
| 48 | 32 | Root digest |
| 80 | 4 | Salt length, 0–256 |
| 84 | 256 | Salt and zero padding |
| 340 | 44 | Reserved zero bytes |

A descriptor contains no trusted device path and no signature of its own. Its
complete bytes must be covered by the existing authenticated boot manifest and
received through the verified loader handoff. Structural decoding does not grant
trust or update authority. Location, generation selection and writable-state
bindings must be authenticated by the encompassing boot/update configuration.
Data and tree reads in the current core start at offset zero in separate logical
read sources; any combined backing layout must supply checked bounded views.

The loader raw type `bip_root_descriptor` requires VE_MUST in the VECTX path;
the non-VECTX Veriexec path already requires verification for raw files. The
kernel has a parsing helper but mountroot does not yet consume this type.
Image construction can emit the descriptor through the explicit verity policy;
boot-stage does not authenticate or consume it yet. There is no enabled disk-root
boot option.

The internal C verifier also supports arbitrary byte ranges with constant
block-sized scratch storage. It verifies full backing blocks before returning
slices and clears the requested output on verification/I/O failure, which must
be propagated as an error. This does not enable a disk-backed build-bsd backend;
GEOM request/lifetime handling and authenticated boot integration remain open.

The initial GEOM backing adapter expects a single backing object with the exact
filesystem extent followed immediately by the root-first hash tree, without a
superblock or trailing bytes. Geometry comes from the authenticated descriptor.
Its read callback supplies scratch bytes to the verifier, not directly to UFS.
Image construction now emits this representation when selected. Provider/boot
integration remains unfinished; artifact tests do not establish an installed root.

`verity_tree.build_image` now emits that combined layout into an empty distinct
regular file. It requires the expected SHA-256 of the completed filesystem,
checks the copied bytes before building the tree from the private output, and
returns the root digest. Inputs and output must remain quiescent; failure leaves
partial output to discard. Signing, durable/atomic publication and provenance of
the expected digest remain caller responsibilities. Reads/writes are bounded by
the supplied block size. Image construction consumes this primitive; boot-stage
does not yet consume the result and cannot claim a working disk-backed root.


Kernel descriptor parsing checkpoint: g_verity_preload_decode now provides
unique, bounded preload parsing with a private copy, tested through maintained
construction verity-preload-test and compiled/linked as part of the explicit
verifier component. It is not wired into mountroot and does not establish
generation trust from a metadata type name. The parser change itself did not
enable boot; enabling a verified root still requires coordinated
artifact emission, generation authentication, backing binding and root admission.


Layout receipt failure handling: materialize_layout removes the top-level and
all planned partition receipt.json markers, plus verification.json, if the
operation fails after partial receipt publication. Image bytes remain available
for diagnosis; construction.json records FAIL. This applies to the existing
build-bsd image backend without a new option. The maintained construction
image-publication-test injects receipt-write, final-verification and final-record
failures and checks that no success markers remain; successful publication keeps
its receipts. This is exception cleanup, not crash-atomic publication or a proof
against SIGKILL/power loss. Durable candidate publication remains a separate gate.


### Optional verity image artifacts

Pass --image-verity-policy /absolute/policy.json to build-bsd image together with
--storage-layout-policy. The JSON object has exactly these fields:

    {"format":1,"block_size":4096,"salt_hex":"aabb"}

Block size is a power of two from 512 to 65536; salt_hex is lowercase hex for
0–256 bytes. Both are explicit inputs. The block size selects makefs -R size
rounding for the immutable base, preserving normal UFS sector/block geometry.
The normal mounted filesystem readback still precedes
artifact construction. Only the immutable base produces system.verity and
root.descriptor; writable seeds retain system.ufs. Input bindings record the
selected policy and file hash. Partition receipts bind source image digest,
combined bytes/size, descriptor digest and root digest; retained layout
verification rechecks those artifacts and rejects unselected verity receipts.
The outputs are unsigned, not crash-atomically published, and not yet consumed by
boot-stage. Never substitute the combined file for the legacy preloaded UFS image.

The maintained verity-artifacts-test exercises actual synthetic byte construction,
source mismatch, policy validation, changed artifacts/descriptors and symlinks.
The frontend image-plan case checks argument routing without execution. These
tests do not demonstrate full mounted image readback or VM startup with this
new option; that qualification remains pending. A separate verity-makefs-test
now builds real regular-file UFS2 images at every supported verification block
size, compares their geometry to an ordinary baseline, runs fsck_ffs -f -n and
checks that fsck did not change the bytes, then constructs/verifies the combined
artifacts. All eight sizes pass with explicit source-built tools. This uses no
mounts or devices and is not a complete packaged-generation readback test.


Layout transport now includes both verity files when the base receipt records
them. It rejects verity entries on writable seeds. The legacy boot verifier
rejects verity receipts explicitly while the authenticated disk-backed handoff
is unfinished; it does not silently preload the corresponding plain UFS file.


Loader-reader checkpoint: the shared verifier now has a compile-tested bounded
libsa file adapter with real-file replay/truncation regression coverage. It still
needs a loader device strategy and authenticated generation binding before UFS
and executable parsing can use it. Artifact construction does not enable that
boot path; boot-stage continues to reject verity receipts.

### Production loader compilation

`build-bsd loader-build --loader-anchors /absolute/public-certificates.pem`
uses `loader_build.py` and the maintained stand `efi-loader` target. Its native
amd64 profile builds into a fresh `/usr/obj` tree with compiled generation
anchors and no firmware-db manifest fallback. Public certificates are validated
and snapshotted before compilation; the generated PEM trust header must match.
The result records build arguments, sanitized environment, make/parser hashes,
anchor hashes, loader size/hash and generated-header hash. It is unsigned and
explicitly does not attest the complete source/toolchain, bind staging, verify
firmware execution or authorize activation. `loader_production_test.py` tests
input rejection and planning; a successful real build is separate evidence.

EFI staging now requires `--loader-build-receipt` and `--loader-build-sha256`
(frontend: `--boot-loader-build` and `--boot-loader-build-sha256`). The exact
record is checked against its selected pin and the staged loader's size/hash
before either signer runs. The record is retained under `efi/loader-build.json`.
This consistency binding does not follow record paths or elevate record claims
to source attestation, release authority or firmware verification. The staging
regressions include altered pins, artifact mismatch, unsupported profiles,
invalid scalar types, and proof that rejected inputs never reach a signer.

`loader-build` now produces a paired `loader-manifest-verify` native executable
from maintained libsecureboot/BearSSL sources. The backend checks its generated
anchor PEM against the same snapshot as the EFI loader and records both hashes.
EFI staging now invokes this companion through an explicitly selected path
after checking its hash against the pinned loader-build record. It uses no ambient CA store or firmware transport and does not
claim firmware revocation or independent attestation. Certificate expiry follows
the existing loader library default, with enforcement disabled.

EFI staging requires `--manifest-verifier` (frontend `--boot-manifest-verifier`).
The selected executable is copied and hashed against the build record before
execution. The staged manifest/signature/certificate hashes are checked before
and after the native verification. An affirmative result is required before
EFI signing or successful stage publication. Results report compiled generation
trust separately from firmware revocation, expiry enforcement and boot execution.
The real paired-artifact test requires explicit BSD_BUILD_MANIFEST_VERIFIER,
BSD_BUILD_GENERATION_KEY and BSD_BUILD_GENERATION_CERTIFICATE, together with the
loader/build-record inputs; it skips rather than fabricating native acceptance.

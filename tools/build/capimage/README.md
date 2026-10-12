# Signing a staged system

Programs declare `CAPIMAGE_MANIFEST` in their Makefiles. The standard program
rules link the exact UCL bytes into a non-allocated `.5bsd.policy` build-input
section. Final signing always emits the same bounded EOF signature container. A manifest may
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
The optional `-c` flag also builds and verifies a signed system library cache. It appends the
new files to METALOG with package tags. It never copies the private key into
the stage. `-e` also provisions the strict-signature enforcement marker.
On any error, discard the incomplete private stage. The script refuses
already sealed bundles, existing cache outputs, and an existing enforcement
marker. Before modifying programs, it rejects symlinked staging ancestors,
bundle entries, metadata, and output paths, and rejects a private key inside
the stage. Keep the private staging tree exclusive to the build while signing;
these checks do not make a concurrently modified tree safe.

```sh
CAPSIGN=/path/to/native/capsign ELFCACHE=/path/to/native/elfcache \
  sh tools/build/capimage/sign-stage.sh -c -e \
  -r /usr/obj/usr/src/private-stage -k /secure/release-private.pem
```

Package staging supports the same operation through `CAPIMAGE_SIGNING_KEY`,
`CAPSIGN_HOST`, and optionally `ELFCACHE_HOST`. Set the key and signing tool
when invoking the maintained package workflow. Set `CAPIMAGE_BUILD_CACHE=yes`
and `ELFCACHE_HOST` explicitly to include the experimental cache.
`CAPIMAGE_CACHE_LIST` selects a reviewed library list; the standalone script
accepts `-c -l library-list` (or `ELFCACHE_LIST`). The host tools must be native to the signing machine;
cross-built target programs are not host tools. Package signing and combined
repository publication remain separate steps. This hook does not advance
`latest`, install an upgrade, or reboot anything.

## Build and installation signing modes

`make capimage-stage NO_ROOT=yes DESTDIR=/usr/obj/usr/src/private-stage`
finalizes a private stage after `installworld`, `distribution`, and
`installkernel`. It never signs a live root. Package staging uses the same
workflow automatically, including through `system-packages`.

- `CAPIMAGE_SIGNING_MODE=unsigned` retains unsigned development programs and
  external unit manifests. It needs no key or native signing tools and does not
  enable the shared cache. It refuses a previously finalized signed stage.
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
repository authentication. `CAPIMAGE_BUILD_CACHE=yes` requires signed or
development mode and remains experimental.

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
An internal mapping owner retains that pin and the original open description
through descriptor closure, fork, partial unmap, and final unmap. Failed
insertions release the temporary owner. Cache descriptors already carry their
own immutable backing lifetime; per-library signature containers remain absent
from cache payloads.

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

This is an experimental implementation under active validation. The
library cache preserves private relocations and verifies byte equality with
source libraries; it does not prebind them. Existing ELF text mappings were
already shared. Initial VM trials have not shown a memory or startup saving.
Do not interpret alias deduplication in the builder's input totals as disk
savings: the original library aliases may already be symlinks or hard links,
and this format retains the ordinary library files for fallback. The cache
must remain opt-in until its deployment and performance tradeoffs are accepted.


## Standalone and recursive tooling

A prebuilt ELF does not need a rebuild:

```sh
capsign sign -k private.pem -m manifest.ucl -o program.signed program
capsign verify -p public.pem program.signed
capsign show -p public.pem program.signed
capsign sign --recursive -k private.pem -o Signed.cap Input.cap
capsign verify --recursive -p public.pem Signed.cap
```

Post-link signing appends a bounded policy/signature/footer representation;
it preserves the original ELF load offsets and authenticates the entire file.
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
and [dyld_shared_cache_util commands](https://github.com/apple-oss-distributions/dyld/blob/main/other-tools/dyld_shared_cache_util.cpp).
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
integration, cache build/list/map/info/verify/authenticated extraction, and
separate dependency and runtime-use reports. Certificate chains, notarization,
network timestamps, arbitrary identity requirements and automatic activation
are not implemented. A signature's validity is separate from the runtime's
permission to grant authority. Filesystem extraction does not establish that
an artifact is appropriate to install.

Every executable signature is in the appended policy/signature container,
located through its fixed-size EOF footer and outside every ELF segment.
The cache only selects shared-library candidates; it does not collect program
signatures. Its signature is the separate `/usr/libdata/5bsd/cache/elf.cache.sig` file. Cache format v2 excludes the entire per-library signature/policy container.
It retains the unsigned ELF prefix and records source and payload lengths
separately. Extraction produces unsigned libraries; it cannot reconstruct the
original signed files. The original source library remains the lookup and
authority boundary. The signature container contains no runtime capability
descriptors or process-private library state.

Fuchsia's [loader protocol](https://fuchsia.dev/reference/fidl/fuchsia.ldsvc)
returns library VMO handles through a process's loader-service connection.
For 5BSD, granted directory descriptors continue to control lookup. Cache
substitution follows that lookup and requires byte-identical library contents;
selecting a cache does not add library-search authority to a process.

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

A release with the shared library cache uses two explicit steps:

```sh
build-bsd packages --kernel GENERIC-NODEBUG --signing signed \
    --key /secure/code-private.pem --pkg-key /secure/pkg-private.pem --cache
build-bsd media --kernel GENERIC-NODEBUG \
    --repository /usr/obj/usr/src/repo/FreeBSD:16:amd64/latest \
    --pkg-public-key /secure/pkg-public.pem --public-key /secure/code-public.pem \
    --media-format all --output /usr/obj/usr/src/media/release-NEW
```

Use `plan` before each action to review without building or opening disks.
Replace the repository ABI and kernel with the matching publication inputs.
The second command consumes the already signed cache in the published packages;
it needs public verification keys, not private signing keys. `--cache` therefore
belongs to the package-building step, not `media`. The output directory must be
new. `--media-format iso` produces the ISO; `memstick` produces the USB image;
`all` produces both. Creating media never launches the host's disk installer.
An image is not considered release-tested until a disposable VM boots it,
installs onto an empty virtual disk, and boots and verifies the installed system.

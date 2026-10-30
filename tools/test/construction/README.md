
## Current verity scope after BIP removal (2026-10-24)

This dated audit supersedes the historical integration claims below. BIP and
its md0 admission gate have been removed. The retained verity component shares
a descriptor format between the Python image builder, loader and C verifier.
The BIPROOT magic and bip_root_descriptor/bip_root_transition module strings
are historical wire identifiers; they do not activate a MAC policy.

Current source searches find no kernel callers of g_verity_provider_create,
g_verity_preload_transition, g_verity_preload_decode or g_verity_check_ufs_root
outside their definitions/declarations. The optional component module exists;
it is not selected by the default GENERIC configuration or GEOM module list.
Consequently, the retained parsers/provider are not a functioning kernel
verified-root boot path. Loader authentication/attachment mechanisms remain
separate, and generated artifacts are not proof of runtime enforcement.

The maintained build-bsd frontend still exposes image and boot verity inputs
and the generation helpers can construct artifacts. Historical assertions
that the frontend universally rejects this mode are not current evidence.
No supported end-to-end verified disk-root publication or boot is established
by this audit. Do not restore BIP root admission within the current goal.

31 native cases pass across verity-core, transition, preload, mount and provider
targets. The latter kernel-facing tests use injected objects, not a running
kernel; no live mount/GEOM race, performance, Secure Boot or VM proof follows.
Evidence and selected-source hashes: /usr/obj/usr/src/verity-retained-audit-20261024.

# Trusted-builder construction VM

This gate runs the production constructor in a disposable ordinary-kernel VM.
It supplies explicit synthetic package declarations and checks real `cap_mkdb`
output, stale-cache avoidance, receipts, undeclared-output rejection, jail
filesystem/network/mount/system-flag restrictions and rejection of user-flag changes, descendant termination and timeout
cleanup. The runtime package is an explicit input: its exact generator bytes and
construction declaration are used, with ELF dependencies from the selected
world. Account and service databases are read directly without flat-file/NSS
fallback, including name/UID and service/alias/port indexes. Tests vary explicit
site inputs, reject unapproved changes and malformed accounts, and require
public database access while denying an unprivileged read of spwd.db. A
root-owned, mode-0644 password input also checks that an unprivileged generator
fails before installing outputs when the required permission change is denied.
The explicit `--certctl` executable and the selected world's OpenSSL utility
also run certificate regressions as UID/GID 65534 with no supplementary groups.
These exercise real parsing, unreadable inputs, traversal errors, certificate
exclusion/collisions, file-size limits and output deletion failures. This is
utility qualification. The explicit `--caroot-package` supplies a complete real
certificate corpus: every regular payload is classified by the explicit
`--certificate-policy` prefix rules, extracted without running hooks, and checked
against its inventory hash. Unclassified or ambiguous payloads fail staging.
The VM compares dry-run names/sizes with actual files, rejects selected malformed
inputs, ignores unselected ambient inputs and changes one trust decision
explicitly. No individual certificate names are maintained in the fixture.
The root constructor tests additionally run the production certificate-policy
compiler and generator in actual temporary jails. Exact certificate payloads
from the supplied archive and the explicit executable/ELF dependencies are
repackaged into a synthetic fixture. Tests check default and overridden roles,
planned versus actual names/sizes, output metadata, receipts, and malformed-input
rejection without a final receipt or generated store. Fixture output locations
are explicitly different from the example policy, exercising path inputs.
This is not a complete installation of the original package or authentication
of its release. Authenticated selection of trust inputs remains separate work.
No executor or jail lifecycle call is mocked. The ATF wrapper acts as
a process reaper while the constructor waits for jail descendants to exit.

Build matching world libraries and static fixtures first, using all logical
CPUs inside the normal world build environment:

```sh
make -C /usr/src/usr.sbin/certctl -j$(sysctl -n hw.ncpu) all
make -C /usr/src/tools/test/construction -j$(sysctl -n hw.ncpu) all
```

The daemon-runtime runner also requires its static runtime_init,
libservice_api_test and BSDFilesystem namespace_test from the selected object
tree. Supply the matching world, Python 3.12 distribution and kernel explicitly:

```sh
python3.12 /usr/src/tools/test/construction/run.py \
    --world /usr/obj/usr/src/amd64.amd64/worldstage \
    --caroot-package /usr/obj/path/to/5BSD-caroot-version.pkg \
    --certificate-policy /usr/src/tools/test/construction/certificate-policy.json \
    --certctl /usr/obj/usr/src/amd64.amd64/usr.sbin/certctl/certctl \
    --kldxref /usr/obj/usr/src/amd64.amd64/usr.sbin/kldxref/kldxref \
    --module /usr/obj/path/to/selected-module.ko \
    --runtime-package /usr/obj/path/to/5BSD-runtime-version.pkg \
    --python-prefix /usr/local \
    --objtop /usr/obj/usr/src/amd64.amd64 \
    --kernconf GENERIC-NODEBUG \
    --work /usr/obj/usr/src/construction-vm-new \
    --qemu /usr/local/bin/qemu-system-x86_64 \
    --qemu-data /usr/local/share/qemu
```

The runtime archive must carry the maintained account/service construction
declarations. It is an explicit fixture input, not an authenticated release
merely because this gate accepts its contents. Source archive, executable,
library, certificate-policy and generated fixture hashes are recorded.
The supplied certificate policy is a test input, not an enrolled trust policy.
This runner's prefix-selection fixture schema is distinct from the production
`tools/build/capimage/certificate-policy.json` schema: the fixture constructs
explicit production policies using its synthetic package name and store paths.
Both source policy and resolved production policy/selection hashes are recorded.

The caller must supply any host QEMU dependency environment required by its
installation. ELF dependencies come only from the explicit world and Python
prefix; missing or ambiguous libraries fail staging. Standard-library files
and extensions are copied, excluding installed site packages, bytecode caches
and the development config directory. All selected file hashes are retained.

The runner uses private image files, no guest networking, and a temporary
in-guest filesystem. It does not mount an input root on the host, install host
packages, change host firmware, activate a boot environment or reboot the host.
The ordinary kernel and fixture PID 1 deliberately test trusted-builder jail
execution. This gate does not qualify Secure Boot, runtime BIP, normal startup,
SSH, complete package installation, authentication or system-generation updates.
Those remain separate mandatory acceptance gates.


## Module-hints input and output gate

`audit-kldxref.py` requires `--kldxref`, `--module` and a new `--work` directory.
Supply a matching built executable and a real kernel module from the selected
build; supply its matching library environment if required. It creates private
fixtures, never loads a module and never writes the installed module directory.
Eight cases cover valid module indexing, mixed valid/malformed input, malformed-only
input, explicit malformed input, buffered write failure, rename failure, a missing
directory and successful obsolete-hint removal for an empty directory. Detected
failures must return nonzero, preserve existing hints and remove temporary files in these
tested paths. Normal fatal parser exits now also remove unfinished output.
A timeout or failed positive control cannot count as a successful rejection.

The construction VM requires explicit `--kldxref` and `--module` inputs, stages
the selected executable and ELF dependencies, records hashes, and runs this gate
as UID/GID 65534 without supplementary groups. These are utility/error-handling
checks, not inventory-bound module generation or runtime module loading.

The earlier built tool failed all three input-rejection cases; those results are
retained. The fixed tool propagates module/record errors and checks traversal,
close, rename and removal. Each directory is installed separately, so a later
failure can leave earlier directories updated. Candidate construction must reject
any failure. Deeper ELF/PNP parser validation, explicit inventory selection,
output provenance and hardware/media generator binding remain separate gates.
The normal world/bootstrap builds consume the source change; no runtime writer
permission is added.


### PNP metadata fixtures

The maintained Makefile builds seven `pnp-*.ko` objects from `pnp_fixture.c` with
the selected target compiler and system metadata definitions. They are synthetic
ELF inputs for kldxref, never kernel-loadable test programs. `audit-pnp.py` requires
explicit `--kldxref`, `--fixtures` and a new `--work` directory. It checks valid
integer/string metadata, missing colon, an eight-character type, too-short rows,
negative count, an invalid string pointer, and a valid object without metadata.
Negative cases must exit nonzero without a signal or timeout, preserve previous
hints and remove temporary files. The positive case checks actual encoded string
content; the no-metadata case checks normal obsolete-hint removal.

The VM stages these built objects from its explicit object tree with hashes and
runs the seven cases without root privileges alongside the existing eight module
input/output cases. These tests cover selected parser defects, not every ELF
layout, architecture or malformed relocation. Real-module compatibility runs
must name their build corpus explicitly: different object subtrees can contain
different same-name modules and must not be silently combined.


### Media generator binding fixture

The VM stages the production hardware staging backend and runs
`media_hints_fixture.py` as UID/GID 65534. It supplies the explicit selected
kldxref, a real module and an empty package set, exercises a conflicting PATH
tool, and requires malformed input to preserve hints and METALOG. It does not
run a package installer or construct complete boot media in the guest. Native
hardware tests separately exercise actual pkg staging and repository signatures.
Supply the host-native kldxref produced by host-tools.mk to qualify the exact
media generator; the runner records its hash and selected ELF dependencies.


### Explicit module-file inputs

`audit-module-inputs.py` takes explicit `--kldxref`, `--fixtures` and a new
`--work` directory. Twenty checks exercise `kldxref -o output file ...`: matching
normal index bytes, ignoring ambient malformed files, rejecting explicitly
selected malformed/non-regular/duplicate/noncanonical inputs, mode conflicts,
output aliasing, same-directory requirements, version-only output and mixed
architectures after a no-metadata input. Cases require controlled rejection,
preserved previous output and temporary cleanup. The maintained VM runs them
without root privileges using its built PNP fixtures. This is utility selection
evidence; the package-inventory-to-recipe compiler remains a separate requirement.


### Package-derived module recipe fixture

The runner stages `module_policy.py` and `module_construction.py`. The fixture
packages the explicitly supplied real module, generator and ELF dependencies
into a synthetic package alongside a previous hints file and malformed ambient
file. The production construction CLI consumes an explicit module-policy input,
replaces the package-owned hints inside a temporary jail, and must produce bytes
matching an independent invocation on the same selected module. Receipts bind
the replaced package, exact selected input, output hash and metadata; an optional
empty group is recorded. Selecting the malformed file must fail while preserving
the previous hints, with no generated manifest, temporary hints or surviving jail.
Changing a package payload before construction must fail before execution.

This qualifies the compiler and jailed recipe integration, not a complete kernel
package installation, module loading, Secure Boot, normal startup or SSH.


The hardware backend fixture now preserves its source-tree relative location
under `/usr/src` in the guest, alongside `package_closure.py`. These are explicitly
hashed fixture inputs, not an installed source tree. The existing media fixture
continues to exercise the actual backend after this shared-helper dependency.
Native publication tests separately cover advertised-library closure rejection
and preservation of latest; the media fixture does not claim that coverage.

### Boot-environment clone and removal mechanics

Add `--boot-environments` to the construction runner to stage the selected world's
ZFS tools and matching kernel module, plus build-bsd's `be_vm_test.py` and deployment
helper. ELF dependencies come from the explicit world input. The guest loads that
module and runs the test against a newly created private file-backed pool. It
checks writable clones of a read-only source, explicit obsolete-clone removal,
surviving environments and origin snapshot, and shared persistent data. Mounted
and snapshot-held environments must refuse deletion without changing identity or
content; unmounting/releasing the hold must allow retry. After deletion, the test
syncs and exports the private pool, then imports that exact GUID with automatic
mounting disabled. It checks persistent deletion, surviving dataset and origin
snapshot GUIDs, and surviving/shared contents after explicitly mounting them.
This is clean export/import durability, not a power-loss test. Pool GUID
validation gates final cleanup. The fixture also creates a separate property
source and recursively clones it under both normal import and a second import
with an explicit alternate root. It requires exact quota/refquota byte counts,
ordinary, `none` and `legacy` mountpoints, and `canmount=noauto`. Removal must
remove every clone descendant while retaining the source descendants. These
assertions are prepared but have not been run under the current VM hold.
The fixture also creates a deliberate snapshot-name conflict that the inspected
ZFS promotion check rejects. Failed activation must preserve bootfs, candidate
GUID and origin. After removing the conflict, activation must succeed; the prior
selection must then be restored before the candidate is retired. Both normal
and alternate-root imports exercise this path, confined to the private pool.
These datasets test selection mechanics, not a bootable installed generation.
Use a world containing the rebuilt libbe and BE tools. Guest RAM is 2048 MiB
for this mode.

This mode selects the separate `boot_environments` ATF case (120-second limit);
the default selects `execution` (240-second limit). Qualification requires both
BE_VM_PASS assertions and a successful boot_environments case and runner result. A failed test or missing prerequisite fails qualification;
there is no skip for absent ZFS. The fixture provenance records this mode. This
remains a networkless mechanism test with a temporary pool, not booting into a new
BE, authenticated removal authorization, protected recovery retention, Secure Boot,
or normal system startup/SSH qualification. Those acceptance gates remain required.

`--fixture-objtop` forwards the daemon runner's existing explicit static fixture
selection. Use a retained, hash-verified fixture tree when a concurrent clean
world build has removed default test binaries. The selected tree must remain
under `/usr/obj/usr/src` and contain the runner initializer, its baseline static
tests, and the construction ATF wrapper at their normal object-relative paths.
The result records that fixture tree separately from the selected kernel/object
tree. Such a run qualifies only its recorded inputs, not the world being rebuilt.

The BE test accepts `--work-root` (default `/var/tmp`). This harness explicitly
selects `/tmp`, its writable temporary filesystem, while keeping the guest root
read-only. The pool backing file and mountpoints stay below a newly created
private directory there. The wrapper uses `kldload -n` because the selected loader
configuration may already have loaded the staged ZFS module.

The BE fixture supplies an empty `/etc/fstab` because `mount -p` consults that
file even when only listing mounts. Deployment still rejects stderr from mount
inventory. The BE test logs commands and preserves failure output in the serial
transcript; successful assertions require actual dataset and content checks.


## Package registration controls

Select `--pkg-registration /absolute/path/to/pkg-static`, with explicit
`--pkg-abi` and `--pkg-osversion`, to run the independent `pkg_registration`
case. It is mutually exclusive with `--boot-environments`. The selected binary
must be static; its bytes and the selected world's shell dependency closure are
recorded as fixture inputs. Both enabled and disabled shell/Lua hooks run against
fresh private databases in real construction jails. The trusted static pkg
executable uses its existing `-j` entry path: startup opens its null descriptor
before attachment, while configuration, manifest analysis and database operations
occur inside the jail. No device node or devfs mount is supplied. The constructor's
shared lifecycle waits for jail destruction before returning. Hooks print markers and test that an existing file outside the jail is not
visible. The selected runtime package's account recipe builds real account
databases from explicit synthetic root/nobody inputs, so pkg info's normal
privilege drop is exercised. The test does not substitute host NSS data.
The test requires the enabled controls to execute, disabled controls to stay
silent, existing payload bytes/metadata to remain unchanged, and package file
and script records to survive registration and raw export.

This is a prerequisite test, not a bounded database construction implementation.
It does not qualify triggers, plugins, arbitrary metadata, schema compatibility,
authenticated package selection or runtime update authority. In particular,
`pkg register -r` outside a jail is not equivalent: a preliminary probe showed
file analysis inspecting the host filesystem despite the alternate-root option.


## Raw package-database export coverage

`audit-pkg-database.py --database /path/to/local.sqlite --pkg /path/to/pkg-static
--sqlite /path/to/sqlite3 --work /usr/obj/usr/src/path/to/new-audit` checks a
quiescent, checkpointed schema-42 database through private copies. It changes
automatic-install state, lock state, schema, file ownership (invalid and NULL),
script links, unowned script records and conflict targets in separate copies,
then compares real raw exports and SQLite checks. Each mutation must change
exactly one row; NULL-link cases also demonstrate SQLite's foreign-key semantics. All executable
inputs and the unchanged source database are hashed. Nonempty WAL files reject
this copy-based audit. This is a deliberately failing-acceptance demonstration:
PASS means the blind spots were reproduced, not that the database is qualified.
The complete verifier must reject these mutations before generation signing.

### Complete selected filesystem case

`--system-layout` selects the separate `system_filesystem` ATF case. This
extracts every selected archive, executes the declared generators and installs
the independently verified package database. Supply `--system-certificate-policy`
and `--system-module-policy` explicitly to include those production construction
policies; both require filesystem mode. These are separate from the small
fixture's certificate prefix-selection policy. Requested policies are recorded
in settings/provenance, hashed when staged, forwarded to the maintained
constructor, and required to produce receipts. Missing policy inputs cannot
silently reduce coverage. Each ATF case requires its matching construction mode.

The database-only case retains its 1200-second limit. Full filesystem construction
has a 3600-second case limit because every generator requires fresh whole-tree
content checks. Set `--vm-timeout` above that limit plus boot/shutdown overhead
(for example 4200). Individual constructor subprocesses retain their separately
specified `--constructor-timeout`. Two earlier 1200-second filesystem runs timed
out and remain failures; a larger budget is not proof of completion. Action
verification emits scan/metadata/reconciliation phase boundaries, and retained
action logs are discovered from actual outputs rather than a fixed action count.
This remains a trusted-builder mechanism test, not normal boot, SSH, Secure Boot,
archive authentication or runtime BIP qualification.

### Retaining builder artifacts

The daemon-runtime runner supports explicit `--retain-disk-writes` for its newly
created private guest.img. Default snapshot mode still discards guest writes.
Retained disks are hashed after QEMU exits, including failed or partial runs;
their presence or hash is not proof of an accepted generation. The maintained
`tools/test/daemon-runtime/disk_retention_test.py` exercises default discard and
explicit retention by booting each private disk twice and checking a sentinel
outside tmpfs. Its VM-only probe explicitly remounts the discovered fixture UFS
root writable, checks the mount state, and synchronizes the sentinel.

The construction fixture currently puts its work under /tmp, which the runtime
init mounts as tmpfs. Retaining guest.img does not retain that candidate. Moving
construction to an explicit disk-backed work directory, retaining its receipts,
and independently verifying/exporting that completed artifact remain necessary
before using it for installed-system boot/SSH qualification. The full filesystem
VM already in progress retains its original inputs and snapshot behavior.

`--builder-storage --builder-work-directory '/root/explicit builder workspace'`
qualifies real workspace preparation and refuses occupied/root/tmpfs/symlinked
paths. The VM must discover a UFS root; setup explicitly remounts it writable,
checks the mount state and creates root-owned mode-0700 work. No backing device
name is assumed. This case retains the private guest disk.

For full construction, supply `--system-work-directory /root/retained-system`
alongside the full inventory/layout/database/policy inputs. The runner selects
retained_system_filesystem (3600 seconds) and retains its private disk. The wrapper
prepares that explicit workspace, invokes the unchanged full constructor below
it, and writes retained-builder.json only after successful construction. Its
receipt hashes the construction/generated/database records but is unsigned.
Failure leaves private partial state; neither disk existence nor hashes authorize
a generation. Existing workspaces are never reused. Independent post-shutdown
verification/export and normal candidate boot remain required.

### Independent read-only artifact attachment

The daemon-runtime runner accepts paired `--input-disk` and
`--input-disk-sha256` inputs. It checks the expected hash before staging and again
before launch, attaches the regular image read-only, and requires its final hash
to match. The input exclusively occupies the second virtio slot and cannot be
combined with a scratch disk. Filenames use QEMU block-device JSON. The verifier
root has an explicit device/boot priority and strict boot selection, so an input
artifact cannot silently replace the verifier at boot.

The maintained daemon-runtime/readonly_disk_test.py gate copies an explicitly
hashed artifact to a private punctuation-containing path, rejects a wrong hash
before staging, then boots a VM that reads the raw disk and attempts an identical
block write. Success requires refusal and unchanged source/copy hashes. This
qualifies attachment only: mounting/reconciling the candidate, validating its
receipts and authenticating a generation remain separate checks.

`verify_retained.py` performs independent post-shutdown consistency checks on an
already mounted read-only artifact. Supply its mounted root, original
`--work-directory`, trusted verifier `--helpers`, trusted `--sqlite`, and a new
`--output` outside the artifact. It rejects artifact-supplied verifier tools and
symlink/mount-boundary escapes, binds the expected retained receipt layout,
re-reads every archive, restores original archive names only for receipt-digest
comparison, reconciles all candidate objects and independently rechecks the
installed database against its explicit profile. It compares the final filesystem
observation and database hashes to construction receipts. It does not execute
programs from the artifact. The input disk hash must be bound separately by the
VM runner; retained records are unsigned and do not establish policy approval.

The maintained native checks are run with:

```sh
make -C /usr/src/tools/test/construction retained-verification-test
```

This runs the verifier boundary, state-review and report-transport tests, plus
installation-policy binding tests. Native tests do not establish VM read-only
mounting or installed-system operation. The retained
`candidate-v9-retained-verifier-v2-vm` completed whole-candidate consistency and
image readback verification with an unchanged read-only input and unforced
shutdown. Its installed-boot diagnostic subsequently failed to establish useful
startup; see system-security.md for the qualification boundary.

`verify-retained-vm.py` now stages a fresh verifier from explicit `--world`,
`--python-prefix`, `--sqlite`, `--boot-root`, object/fixture trees and QEMU inputs.
It requires `--input-disk`, its expected `--input-disk-sha256`, an explicit GPT
`--input-partition`, and the original `--retained-work`. Disk capacity, guest
memory and the outer time limit are inputs. `--cpus` selects one through four
guest vCPUs (default four), is recorded in provenance, and is forwarded to the
runtime runner. The verifier work directory is created mode 0700, independent
of the caller's umask, because exported installation content may be private.
`--input-mount-directory` selects a canonical absolute guest path (default
`/mnt/retained-input`), created in the fixture before boot. The guest requires
an empty, nonsymlink directory on the root filesystem before mounting the selected
partition read-only. It requires file-creation refusal, invokes only verifier-side
code and unmounts before shutdown. The positive ATF case has a 1800-second limit.
Using the fixture root avoids adding a tmpfs parent to this particular check;
it does not resolve the separately recorded UFS/tmpfs shutdown lock-order issue.
A guest PASS followed by a WITNESS failure or forced termination is not accepted.

`--expect-incomplete` selects a distinct 120-second negative case: it requires the
workspace to exist and the success receipt to be missing, and never reports a
verified candidate. That case passed on the retained workspace fixture, with an
unchanged disk hash. Both runners use fixture_stage.py for the same explicit copy,
ELF-library and Python staging rules. The existing workspace VM passed again
after this refactor. The verifier stages all maintained backend Python modules;
it does not maintain a separate selected-program inventory for the candidate.

Before verification, the fresh VM emits RETAINED_DIAGNOSTICS as one JSON-escaped
line. It reads at most the last 4096 bytes of each known builder receipt/log,
records missing outputs and tail hashes, and refuses symlink/boundary crossings.
These are untrusted diagnostic contents, never acceptance markers or executable
inputs. This permits examination of retained partial builds after a timeout.
The retained-diagnostics-vm negative test passed with an unchanged input-disk hash,
a read-only mount, file-creation refusal and missing-success-receipt refusal.
No new build-bsd input or authorization is introduced by this diagnostic output.

### Retained verification report and state review

On positive verification, the runner saves `verification.json` after checking
that the VM finished without forced termination, the input stayed read-only and
unchanged, and the serial hash matches the VM result. Exactly one guest report
is required. Existing output is never overwritten. The negative
`--expect-incomplete` case does not produce a positive verification artifact.

The artifact retains the guest report and hashes of the VM result, serial log
and input disk. Its `state_review` binds validated package declarations,
undeclared-package coverage, executable payload bindings and observed filesystem
layout to the verified inventory and filesystem hashes. A missing path or
symlink ancestor remains a finding for policy review. Missing declarations do
not mean that a package needs no writable state. The verifier does not assign
write permissions, approve mount coverage, authenticate a generation or authorize
activation. These remain explicit false fields.

The report and state-review additions have native regression coverage and a
completed full-candidate execution in `candidate-v9b-retained-verifier-v1-vm`.
That VM checked 521 packages and 35,231 objects, verified image readback and shut
down without forced termination. The earlier v9 result predates these additions
and must not be represented as testing them. Neither run establishes normal
installed-service operation or persistent BIP enforcement.

### Filesystem image metadata preservation

Build image_vm_test with the maintained construction Makefile. The
image-roundtrip-vm.py runner takes explicit --boot-root, --world, --python-prefix,
--objtop, --fixture-objtop, --work, --qemu, --qemu-data, --kernconf and --makefs
inputs. VM capacity, memory and timeout have overridable limits. It stages a
fresh verifier and the selected makefs with its ELF dependencies.

The guest creates a private filesystem fixture, builds UFS1 and UFS2 images
without metadata overrides, mounts each read-only and compares every scanner
observation. Cases include non-root ownership, directory/file modes, immutable
flags, hardlinks, absolute/relative symlinks, names with spaces, content and
nanosecond modification timestamps. The source must remain unchanged; writing to
the mounted image must fail. Allocated memory disks are unmounted and detached.
This is an image-format mechanism test, not an authenticated installed generation.

The original native makefs failed by discarding nanosecond timestamps. Native
makefs.h lacked the feature definitions for existing timestamp preservation code;
cross builds already supply them through nbtool_config.h. With the native
features enabled, image-roundtrip-vm-v3 passed both formats and shut down cleanly.
The staged/publication makefs remains older: rebuild/stage/package parity is
required before claiming the normal release workflow uses this correction.

### Exporting a retained generation image

verify-retained-vm.py requires --image-makefs, --output-disk-mib and
--image-work-directory together for image export
for positive verification. This cannot be combined with --expect-incomplete.
The distinct retained_image ATF case has a 3600-second limit; supply an adequate
outer --vm-timeout (for example 4200). Use the explicit qualified makefs binary
and a new static fixture snapshot containing that case.

After verifying the retained generation, the guest materializes UFS2, verifies
its read-only mount against the same filesystem observation, and exports to the
new output disk. Geometry and capacity are checked before writing. Unused output
space is zero-filled; the complete device is flushed and read back. On shutdown,
the host requires clean PASS/readonly-input evidence, matching raw disk size/hash,
and exactly one completed export. It copies only the declared image bytes into
new mode-0600 image.ufs and requires the image digest to match before writing
image.json. These receipts are unsigned and confer no activation authority.

The image-roundtrip fixture can exercise this export path with the paired input
file/hash and output capacity options. image-export-vm passed end to end with its
seven-object UFS fixture. Seven native collector tests cover changed bytes,
missing bindings, failed VM, duplicate export and existing-output preservation.
The initial missing-hash refusal regression is preserved; the hardened collector
also passed against actual VM output. The separate full retained-generation
image export has passed; see full-generation-image-validation.json.


Add `--boot-archive` to the retained-image runner to export the image, complete
boot archive, and common image receipt together in a standard tar transport.
The image backend is the same one exposed by `build-bsd image
--image-boot-archive`. The output disk remains private and is read back in full.
The host collector accepts exactly three regular members in fixed order:
`image.ufs`, `boot.tar`, and `image-receipt.json`. It checks both payload digests,
sizes and the common source-observation binding before creating the private
`generation` output directory. It copies streams into fixed filenames; it never
extracts tar paths or follows links. Receipt parsing rejects duplicate keys and
limits receipt size to 64 MiB; payloads are streamed. Success writes `bundle.json`.
The inner boot archive remains opaque at this stage and still requires metadata
reconstruction and reconciliation before signing boot media.

The image-roundtrip runner selects the small end-to-end bundle case using
`--export-bundle` with its explicit input disk/hash and output capacity. The
first attempt failed because isolated Python could not import the staged helper;
the guest now loads it by its explicit `/tests` path. That failed run is retained
as `boot-bundle-export-vm`. Native bundle tests cover exact collection, source and
receipt mismatches, altered payload bytes, unsafe member names/types, duplicate
members, preservation of existing output and the post-shutdown collector path.
These transport checks do not qualify normal boot, SSH or authenticated updates.
For retained full-generation verification, pass `--image-work-directory` on
the private verifier root disk and size that disk for the materialized tree,
UFS image, boot archive and outer tar. The verifier validates this workspace
through `builder_storage.py`; the source generation remains mounted read-only.
These artifacts are retained for diagnosis. The separate image-roundtrip fixture
has its own workspace requirements.

## Library-hints strict-construction audit

`audit-ldconfig.py --ldconfig /explicit/tool --directory /existing/library/dir
--work /new/private/work` checks whether the supplied generator alone provides
strict generation-construction semantics. The existing directory is read only;
all output files are created in the new work directory. The positive control
checks the actual hints search list. Missing-only and mixed valid/missing input
cases require a normal nonzero exit and preservation of the previous output.
Timeouts, signals and failed positive controls cannot pass. The report records
commands, diagnostics, parsed output and the executable hash.

The current utility is tolerant: this audit intentionally fails its strict
construction gate. It does not redefine ordinary ldconfig compatibility behavior
as a bug. The production constructor must validate all approved directory inputs
and compare the exact ordered output, or use a separately qualified strict mode.
Do not accept a partial result merely because ldconfig exits zero. This audit
is not runtime BIP, immutable-startup or installed-system qualification.

The explicit `--strict` audit option now exercises `ldconfig -S`. It additionally
checks writable directories, aliases, directory-list files, duplicates, relative
paths, incompatible insecure/merge options and an empty directory request.
Use the newly built utility explicitly; an older staged candidate does not
acquire this mode when its source tree changes. Without `--strict`, the audit
continues to measure the utility's ordinary tolerant behavior.

For VM qualification, pass `--ldconfig /explicit/newly-built/ldconfig` to
`run.py` with the default execution case. The runner stages that exact executable
and its dependencies, records the input hashes, and runs the strict audit as
UID/GID 65534 without supplementary groups. The fixture explicitly selects
`/usr/lib` as its valid directory. It records `library_hints_strict` in the input
report and emits `CONSTRUCTION_VM_PASS library_hints_strict_inputs` only after
all audit cases pass. The option rejects selection of the storage, package,
system-construction or boot-environment cases, which would not execute this audit.

The same explicit `--ldconfig` execution fixture now also stages a synthetic
package containing that generator, its actual ELF dependency closure and
explicit directory metadata. `library_construction.py` invokes the production
constructor CLI in real temporary jails. It verifies ordered and reversed search
policies, ignores an ambient search-list file, checks receipt/output metadata,
and rejects undeclared directories and changed generator payloads before
execution. It does not mock the executor or jail lifecycle. This fixture does
not establish an installed runtime storage policy or normal system startup.

The retained-image verifier requires an explicit `--image-work-directory`, for
example `/root/retained-image-work`, inside its disposable guest. The existing
builder-storage helper verifies that its canonical parent is on the private
UFS root, remounts only that verifier root writable if necessary, and creates
private mode-0700 storage. The retained input remains mounted read-only and is
rechecked after storage preparation. Full images and archives are not created
on the fixture's `/tmp` tmpfs. Choose `--root-mib` for the image and archive
workspace as well as `--output-disk-mib` for the exported payload; increasing
only guest memory is not a disk-workspace configuration.

## Installation configuration replacement

The input also supports format-2 regular-file create/replace operations and
format-3 package-declared compatibility aliases. Alias entries retain their
candidate target, package and requirement verbatim during VM transport; only
regular-file source paths are translated. No host file is read for an alias.
The production constructor validates package ownership, parent directories,
target resolution and collisions. Transport itself grants no authority.
The `bip-alias-install-v1` ordinary builder VM passed all 26 installation tests,
including alias materialization, with no skips. Twelve native transport tests
cover mixed and alias-only policies, invalid source fields and target tampering.
Full-system runtime mapping and protected service compatibility remain separate
unqualified gates.

The execution fixture now runs installation_policy_test.py as actual guest root
before the generator tests. It requires successful replacement with a bound
receipt, preservation of the original package inventory, and rejection of
changed source bytes without a successful generated manifest. Native runs as
an ordinary user explicitly skip these two root-only cases. Validation cases
also exercise package configuration membership, exact replacement provenance,
source aliases/FIFOs, destination aliases/flags, unsafe metadata and generator
conflicts. This is trusted-builder evidence, not runtime writer authorization.

The maintained `build-bsd construct --installation-policy FILE` input is
format-1 JSON with an `entries` mapping. Each destination maps to `source`
(canonical absolute external input), `sha256`, `size`, `uid`, `gid`, `mode`
(JSON integer) and `replaces` (exact package archive SHA256 list). Destination
selection is derived from package configuration declarations. The input does
not create directories or replace executable code. Original package database
configuration bytes remain the merge baseline; local content is recorded in
the generation manifest. The private builder parent must be root-owned 0700.

The VM runner stages the helper and tests from maintained sources and records
their hashes. Full-system installation inputs still need explicit staging and
path translation into the builder VM; this mechanism fixture does not supply
machine identity, storage GUIDs or a deployment policy on an operator's behalf.

Full-system construction now accepts `--system-installation-policy FILE` and
`--system-library-policy FILE`, both requiring `--system-layout`. The former
preserves the original JSON, copies each canonical regular source with its
explicit size/hash, and emits a separate policy whose only changes are source
paths into `/tests/installation-inputs`. The guest verifies original/translated
policy hashes and unchanged destination/authority fields before invoking the
maintained constructor. It checks the resulting policy receipt and retains a
transport receipt alongside construction output. The retained success record
hashes that receipt; independent verification repeats transport and package
configuration checks and compares generated content with the declared policy.

Run `python3.12 -B installation_transport_test.py` for native transport boundary
checks. These tests do not qualify the full selected system or policy approval.
The library-policy input is passed unchanged to `construct --library-policy`
and its receipt is required when requested. Neither option supplies implicit
machine identities, storage GUIDs, writer grants or signing authority.

Before selecting storage-enabled installation inputs, the Capsule and
BSDFilesystem `config_test:installation_policy` cases can validate explicit
policy through their production parsers. Supply `installation_policy`, `pool`
and `dataset` ATF variables to both. Capsule also requires `hostuuid`,
`recipient`, `pool_guid` and `dataset_guid`; Filesystem requires `persistent`,
`ephemeral` and `sync`. Without an explicit policy the cases skip. These
parser checks do not import pools, start services or validate runtime grants.

`python3.12 -B retained_installation_test.py` exercises the retained verifier's
installation bindings using real transport files and package metadata. It
checks changed generated permissions, receipt/source mappings, package
configuration membership, transport receipts and input bytes, including
equal-length corruption. The full verifier still separately requires a
read-only artifact mount, complete archive/database checks and filesystem
reconciliation; these native component cases do not replace that VM gate.


## Package configuration adoption regression

`pkg-config-adoption-test.py` exercises local-archive installation with a private
package database and exact validated synthetic payload paths. Supply `--pkg`,
`--sqlite`, `--baseline`, `--local`, `--abi`, `--osversion`, and a new `--work`
directory beneath `/usr/obj/usr/src`. The baseline and local inputs must differ.
It checks adoption, independent package baseline, downgrade and re-upgrade.
Hooks, plugins, triggers and repositories are disabled. It does not install
host system packages or authorize BIP activation. The current reviewed engine
fails the downgrade-retains-local-config assertion; retain that failure until
a reviewed migration design supplies the required preservation. Do not treat
package downgrade as a test of authenticated boot-environment rollback.


## Package-derived review inventory

`inventory_audit.py --inventory INVENTORY.json --output NEW-REPORT.json` reads
the package inventory produced by the maintained deployment/construction
backend. It records all selected package objects and owners, configuration
membership, executable candidates including hardlink aliases, links requiring
review, and package-declared generator outputs. It uses the backend's directory
metadata rules and records the exact input SHA256. It follows no host filesystem
symlinks and executes no package payloads. Existing output files are refused.

Run `make -C /usr/src/tools/test/construction inventory-audit-test` for the
native regression suite. The report is a review aid, not a build acceptance
receipt: authentication, filesystem reconciliation, policy assignment, runtime
path completeness and functional coverage remain explicitly unverified.
Executable candidates are a permission-bit heuristic, not a complete entry-point
inventory; symlink targets and interpreters require further review. Declared
generator outputs cover package construction declarations only, not every
additional selected constructor generator or runtime-created object. Compare
with final generated manifests and observed runtime behavior in subsequent
qualification. No path receives writer authorization from this report.

This consumes existing normal build-bsd backend output and changes no build,
policy, staging or publication input. No additional build-bsd action is needed
for this read-only review tool. An enforced coverage gate, when implemented,
must be integrated separately with build-bsd and its acceptance ledger.

## Explicit installation-specific configuration

The maintained build-bsd construct action's installation-policy input accepts
format 1 (package configuration replacements) or format 2 (an explicit create
or replace operation on every entry). A create entry has an empty replaces
array and an absent, unowned destination beneath already declared directories.
It supplies the same canonical external source, content hash, size and safe
root-owned metadata as a replacement. No fstab, rc.conf or machine-secret
content is synthesized. The resulting file belongs to the generation's declared
installation inputs; it is not retroactively added to a package payload or
granted runtime writer access. The constructor VM runs both the native policy
checks and actual root-owned installation/reconciliation tests.


The review report also emits `packages[NAME].state_review`, listing each
executable candidate's exact-path declaration names and candidates without
such declarations. A declaration for one program does not cover other programs
in its package or hardlink aliases. Explicitly empty package metadata does not
clear these review gaps. Even candidates with declarations retain unverified
runtime completeness and functional coverage; candidate enumeration uses the
existing executable-bit heuristic. This is a report over maintained build-bsd
inventory output, with no new authority, build option or acceptance waiver.

## Explicit full-construction case budget

`--case-timeout SECONDS` supplies an explicit harness deadline for the selected
full-filesystem case. It requires `--system-layout`, accepts 1..86400 seconds,
and must be below `--vm-timeout`. Omitting it preserves the declared ATF deadline.
The outer VM timeout still bounds the whole run, including supporting tests and
shutdown; provide enough additional time for those steps.

The runner forwards an exact selected source/case budget through daemon-runtime's
`--atf-case-budget SOURCE:CASE=SECONDS`. Runtime input/result metadata records the
original `declared_timeout`, effective `timeout`, and literal `budget_input`.
Unknown, ambiguous and duplicate selections are rejected. Cleanup and failed-body
acceptance rules are unchanged. A larger budget never changes a previous timeout
into a passing result; rerun in a fresh workspace and retain failed evidence.

### Explicit partition image readback

The image round-trip guest now also exercises generation_image.materialize_layout:
an immutable base plus ordinary and protected seed images, source preservation,
rebased hardlinks, seed-root ownership and explicit root-owned attachment slots.
The maintained `build-bsd image --storage-layout-policy` entry point uses the
same backend after package archive and construction receipt reconciliation.
This does not install seeds or activate attachments. The immutable partition
now supports boot transport export with unchanged /boot observations.

Evidence: `bip-partition-image-vm-v2` passed the guest comparisons but FAILED
qualification on a UFS/tmpfs shutdown WITNESS lock-order reversal. Do not treat
its guest PASS marker as a passing VM result. The retained independent check is
`bip-partition-image-validation-v2.json`; v1 failed the kernel-identity preflight.

### Minimal UFS/tmpfs unmount regression

`image-roundtrip-vm.py --test-case unmount_order` selects a minimal ATF case:
create one UFS2 image, mount it read-only under the VM's tmpfs /tmp, verify one
payload, unmount and detach, then require clean shutdown through the ordinary
runner. It does not call generation construction or partition code. The default
remains image_roundtrip; export/boot-transport options require that default case.
Build the static image_vm_test through the maintained construction Makefile and
stage it in a new explicit fixture object root before selecting the new case.

`bip-unmount-order-vm-v1` reproduces the shutdown lock-order warning on GENERIC
without BIP. It remains FAIL. The runner's WITNESS rejection is unchanged.


The image_roundtrip case now stages the selected world's archive tool and
initializes a new state directory from the ordinary seed image. It checks exact
metadata/content/hardlink preservation and refusal to initialize existing data.
This is not yet ZFS provisioning or an upgrade test. bip-seed-init-vm-v3 passed
these guest checks but the unchanged shutdown WITNESS gate failed; use the
independent bip-seed-init-validation-v3.json evidence with that limitation.


`image-roundtrip-vm.py --seed-dataset-tests --scratch-disk-mib 256` stages ZFS
from the selected root/kernel and attaches a fresh private scratch disk through
the maintained daemon runner. The guest creates its fixture pool only on the
runner-supplied scratch device, checks fresh dataset initialization and GUID
refusal, remounts for exact state readback, then exports the pool. This mode
cannot share an input/export disk. Root/world dependencies must agree.
Explicit hash-identical ZFS dependencies may be shared with the extra fixture;
all other collisions still reject. Seven sharing tests pass.

bip-seed-dataset-vm-v5 passes guest provisioning and remount assertions but FAILS
the unchanged shutdown WITNESS gate. Earlier v1/v2 fixture overlap failures and
v3/v4 flag-preservation failures remain retained. Independent evidence is in
bip-seed-dataset-validation-v5.json. Cross-boot persistence and actual installed
startup/upgrade are still required.


### Seed dataset cold-boot persistence

With --seed-dataset-tests, the runner retains seed-dataset-evidence.json after
the guest exports its private pool. It binds the observed provisioning receipt,
seed objects, scratch disk hash and serial hash, retaining the VM result even
when shutdown fails. No failed VM is promoted to PASS.

Select --test-case seed_readback with --seed-receipt, --input-disk and
--input-disk-sha256 to boot a new VM against that disk read-only. This mode cannot
create a scratch disk or export another image. The guest verifies all three GUIDs
and full state observations, then unmounts/exports. The normal clean-shutdown
checks remain required. No initializer runs in the readback case.

bip-seed-persistence-create-vm-v1 failed shutdown after synced initialization;
bip-seed-persistence-readback-vm-v1 passed read-only cold-boot verification and
clean shutdown. Independent validation also proves the retained disk unchanged.
These are persistence mechanism results, not installed startup or upgrades.


The optional seed-dataset VM scenario now also provisions protected state,
constructs candidate JSON policy using both actual dataset identities, and
rebuilds the immutable base with complete storage bindings. It checks wrong-GUID
refusal before output. bip-storage-binding-vm-v1 passed those guest checks but
still failed the existing shutdown WITNESS gate. This is construction consistency,
not actual Capsule policy activation or installed-system acceptance.

The boot-environment mechanics fixture additionally selects `bootfs` only on its
new private pool and requires refusal to delete that default environment. It
checks the retained dataset identity/content and default selection, including
selection persistence after export/import. This is not a running-root deletion
test or authenticated retention policy. In particular, libbe can clear a
`bootonce` selection during deletion; a protected updater must enforce pending
activation and recovery retention separately.

The BE mechanics fixture requires Python assertions and refuses `-O`, `-OO` or
an effective `PYTHONOPTIMIZE` setting before any action. The maintained guest
launcher uses isolated Python (`-I -S -B`); the refusal also protects direct
invocations. The native deployment tests verify this without running pool commands.

Inventory overlap review includes both default state paths and declared
`directory_mapping` alternatives. These are candidate namespaces only; selection
requires completed-filesystem reconciliation. Missing mapped package objects do
not imply that construction has created them or authorized their writers.

### Format-5 installation transport

The VM transport accepts the same formats 1–5 as the maintained constructor.
Format-5 `replace-template` entries retain their operation and exact package
replacement identities; only external source paths are translated. Candidate
`relocate` targets in formats 4 and 5 remain candidate paths and are never
opened as host inputs. The constructor still decides package template ownership,
allowed replacement metadata and reconciliation. Transport acceptance grants no
runtime write authority. The regression covers mixed template/relocation input
and rejects an operation change even when the transport digest is refreshed.
No build-bsd option changes are required: this repairs the VM transport of its
existing format-5 installation-policy input.

### Private builder artifacts

Construction and daemon-runtime VM runners create their new work directories
with mode 0700 before copying inputs. Installation configuration can include
private machine credentials, so the entire staging tree, fixture media, writable
state and retained output must remain private to the builder. A fixture is not
an installed-system image: its selected test files and permissions do not
establish normal-system privacy or startup behavior. Deployment image metadata
comes from the reconciled generation and storage projections. Do not publish
builder work directories or instance-specific writable-state seeds.

The construction runner accepts `--cpus 1..4` and records and forwards the
selection to the maintained runtime VM runner. The compatibility default is
four vCPUs; use `--cpus 2 --memory-mib 2048` for the currently selected resource
budget. These are VM test resources, independent of build-bsd's compilation
parallelism. No product build options change.

### Provider-only dataset allocation

`state_allocation.py` accepts format 2 with the existing `parent`, `layout` and
`bindings` inputs plus a `providers` list. Each provider row has `recipient` and
`dataset`, and optionally the existing `execution` object. The layout and
attachment bindings may both be empty when only provider datasets are selected.
Provider roots are direct children of the selected parent and cannot duplicate
another dataset or recipient. The result records separate `providers` receipts;
the maintained readback helper checks both attachment and provider identities.
Recipient strings here are bookkeeping, not authority approval. Capsule's native
policy validation and runtime recipient admission still apply. Allocation uses
the existing build-bsd state-storage backend and does not create a global mount,
initialize contents or qualify a provider. Native checks:
`python3.12 -B state_allocation_test.py`.

Allocation emits flushed `STATE_ALLOCATION_PROGRESS` records with monotonic
elapsed times around backend import, validation, tool hashing, commands and
dataset allocation. These diagnostics locate stalls; only the final
`STATE_ALLOCATION_RESULT` plus the runner outcome and subsequent readback can
support acceptance. A progress record never substitutes for a receipt.

### Complete-candidate state initialization (in progress)

`state_initialization.py` selects ordinary seed projections from the finalized
layout and requires exact coverage by exported allocation receipts. Before
importing the private output disk it checks each source directory against its
rebased observation. The candidate must remain mounted read-only. It imports
only `/dev/vtbd2` by explicit pool GUID, requires the exact dataset inventory,
and invokes the maintained `seed_dataset.initialize_allocated` backend. Each
successful dataset receipt is retained; aggregate success follows pool sync
and export. Failure preserves partial state and never destroys or reseeds it.

The retained-verifier wrapper now exposes this mode with --state-allocation,
--state-disk, --state-disk-sha256, --state-work-directory, --storage-layout-policy
and --output-disk-mib. Select an explicit root capacity for disk-backed archive
work. The source state disk must exactly match the supplied hash and output
capacity. It is copied, never attached writable; the candidate input stays
read-only. The wrapper retains the private guest root for partial diagnostics.
It stages selected world tools and the ZFS module matching its fixture kernel.

The declared ATF timeout is 3600 seconds; --state-case-timeout can select a
separate harness budget, which must be below --vm-timeout. Both remain recorded.
The guest independently verifies the retained candidate before initialization.
The host collects state-initialization.json only after clean unforced shutdown,
unchanged source/input disks, an exported pool and an initialization success
report. That transport record does not prove populated-state cold readback.
No VM has yet qualified this mode. Run `make state-initialization-test` for
native mapping checks.
The production entry remains `build-bsd state-storage`; these fixture helpers
add no installation or runtime authority.

The state_readback guest case also accepts initialized-state-vm-transport
records. It imports the selected pool read-only and checks dataset identity and
properties. For initialized state it mounts each dataset read-only, requires
EROFS on attempted creation, and compares the full scanned observation digest
with the initialized seed digest. Empty allocation records continue to report
contents_verified=false. The host must match expected_disk_sha256 in the guest
report to the runner input/final disk hashes and require clean unforced shutdown.
A guest report alone is not accepted artifact evidence. Native input-selection
checks run with make state-initialization-test; populated-state VM qualification
is still pending.

Backend fixture completeness
----------------------------
Construction and retained verification stage every regular top-level Python
module from the explicitly selected capimage backend directory and record its
source/staged hash. They do not maintain separate dependency-name lists.
fixture_stage_test.py checks inclusion of newly added modules and loads the
actual layout reader plus ELF inspector from the staged directory under isolated
Python. This is fixture tooling completeness, not installed-OS payload coverage.
A full construction run on 2026-10-23 failed at final storage classification
because the prior helper list omitted elf_dependencies.py; that failed disk and
result remain evidence of failure, despite completed generator/database steps.

## Split-image transport (native checks only)

`export_layout.py` transports the complete base/seed image set, manifests,
partition receipts and optional base boot archive. Collection checks all bytes
against the transported layout receipt, rejects missing/extra/unsafe members,
and never extracts archive paths. It does not verify selected policy or trust;
callers still need `generation_image.verify_layout` with independently selected
inputs and actual normal-boot qualification. `make layout-transport-test` covers
round trip and adversarial transport inputs. VM export wiring remains pending.
The production `build-bsd image` layout/binding interface is unchanged.

The output-disk exporter/collector accepts `kind="layout"` and retains every
partition under `layout/`, with `layout.tar` and `layout.json` transport evidence.
It requires a successful unforced VM exit, unchanged read-only input and matching
full output-disk and payload hashes. Eleven collector tests (including four split
layout cases) pass. These use synthetic bytes, not UFS or VM evidence. Guest
materialize-layout selection and independent selected-input review remain to be
wired before this path can qualify an installed system.

Split image VM selection is now wired: use `--image-makefs`,
`--image-work-directory`, `--output-disk-mib`, `--storage-layout-policy`,
`--storage-bindings`, `--capsule-validator` and `--capsule-validator-sha256`.
The guest verifies the retained generation, runs native bound-policy validation,
then invokes maintained `materialize_layout` and transports every image. Host
collection binds the complete layout receipt to the guest verifier report.
This wiring has native argument/refusal checks; no split-image VM pass is claimed.
Independent host selected-input review and normal boot remain outstanding.

Collect populated-state cold readback using `collect_state_readback.py` with
`--vm-work`, `--initialization`, `--input-disk` and a new `--output`. It requires
clean unforced completion, the selected unchanged read-only disk, one report,
matching initialization receipt bytes, dataset count and content verification.
It independently hashes the disk after shutdown. Nine synthetic native refusal
and binding tests pass; no ZFS, normal boot or signature qualification is implied.
This is VM evidence tooling; production build-bsd inputs are unchanged.

`readback-state-vm.py` stages the selected world/Python/ZFS module and backend
helpers, binds an initialized-state receipt to its exact read-only input disk,
runs state_readback with explicit case/VM budgets, and collects `readback.json`.
It defaults to two CPUs and 2048 MiB. It never attaches a writable state disk.
The three native CLI tests cover refusal before staging; real VM execution
awaits accepted initialization. Production build-bsd state-storage is unchanged.

### State fixture dependencies and readback identity checks

Both state VM wrappers stage the selected world /bin/sh and its ELF dependencies,
because the ATF module-loading step uses system(). The initial dynamic-storage
initialization run failed before copying state when this dependency was absent;
its clean shutdown does not turn that failed case into initialization acceptance.

Cold readback rejects duplicate dataset identities/names and duplicate or
noncanonical initialized writable boundaries before import. Counts therefore
cannot be satisfied by repeating one dataset. These are evidence checks; they do
not grant runtime authority or establish successful boot.

The populated-state wrapper also stages the selected world libarchive.so and its
ELF dependencies explicitly: the filesystem scanner loads it through Python at
runtime, so the Python executable's ELF dependency list alone is insufficient.
The first populated-state VM exposed this omission and remains failed evidence.
Production build-bsd policy and inputs are unchanged by this fixture correction.

### Compact split-layout receipt transport

Split-image verification sends an `image_receipt` binding (format, scope, byte
count and SHA-256) over serial. Before emitting the binding, the guest compares
the parsed receipt to the image materializer return and hashes those same bytes.
The complete layout receipt and every partition
remain on the export disk. After normal export collection validates the archive
and individual image artifacts, the host checks the collected receipt against
that exact binding. Missing, malformed or changed bindings fail collection.
This replaces redundant full-layout JSON on the slow serial path; image readback,
source reconciliation and artifact retention remain required. Native adversarial
binding tests pass; a fresh split-image VM still must qualify this transport.
The existing build-bsd image inputs and maintained backend interfaces are unchanged.

## Installation policy preflight

Before copying selected archives or launching a guest, the runner validates the
installation policy against the inventory's expected object graph and checks
its source bytes. The maintained construction backend runs the same preflight
before extraction. Exact replacement ownership remains mandatory: a policy
bound to an earlier archive is rejected even if the new archive carries the
same configuration bytes. Updating that input requires an explicit review of
template content and security metadata; the runner never substitutes current
hashes automatically. Real filesystem reconciliation and source revalidation
remain required in the guest. An early preflight pass is not construction,
authentication, runtime authorization or service qualification.

### Disk-integrity tree component

Run `make -C /usr/src/tools/test/construction verity-tree-test` for host-only
construction/read-verification tests. Fixed numeric root-hash vectors are sourced
from cryptsetup v2.7.5 `tests/verity-compat-test`; no upstream implementation is
copied. Test corruption after a successful read, hash padding, truncation and
invalid bounds. The bounded-I/O test is not a measured memory-usage guarantee.
Kernel/boot/provider tests and live veritysetup interoperability remain pending.

`make -C /usr/src/tools/test/construction MAKEOBJDIRPREFIX=/usr/obj obj` followed
by the same make invocation with `verity-core-test` builds the C verifier as a
host-only test shared object under /usr/obj. Five tests check valid nonzero data,
level boundaries, unchanged output on corruption/I/O failure, repeated reads after
mutation and pre-I/O bounds rejection. No kernel module is loaded and no VM runs.
The test callback is a file reader, not proof of GEOM locking or BIO completion.

### Verity range reads and kernel compilation

`verity-core-test` now includes byte-range checks for unaligned requests, tree
boundaries, full-block verification outside the returned slice, later-block
failure, output guards and empty/out-of-range reads. Sixteen core tests pass,
including request-local authenticated leaf reuse and malicious backing changes. On an I/O/hash failure the range helper
zeros the requested output and returns an error; consumers must propagate it.

`make verity-kernel-compile VERITY_KERNEL_OBJDIR=/usr/obj/usr/src/amd64.amd64/sys/GENERIC`
uses that existing configured kernel's flags and generated headers, with -Werror,
to compile g_verity_verify.check.o in its object directory. It does not link,
install, load a module or boot. The check passed for the configured GENERIC tree.
A GEOM provider and boot integration are still required.

### GEOM backing adapter checks

`make verity-io-test` compiles actual backing bind/read functions and the actual
geometry verifier against injected GEOM BIO operations. It checks exact backing
size, read access and alignment, data/tree offsets, bounds before allocation,
short completion, propagated errors and cleanup. It passes. The kernel compile
target now compiles both g_verity_verify.check.o and g_verity_io.check.o using the
configured kernel's flags. No live provider, orphan/teardown race or boot is
qualified by these checks.

### Combined-image construction checks

The tree suite now has eleven passing tests and the C-core suite thirteen.
Combined filesystem/tree bytes match separate-tree construction. The actual C
verifier accepts all 129 blocks in the combined fixture and rejects data and
hash-tree corruption. Additional checks cover source digest mismatch, inode
aliasing, existing output, block-sized I/O and total extent overflow before file
access. This is component evidence; no normal build-bsd generation or VM boot
is qualified by these checks.

### Verifier callback cost probe

`verity_read_cost.py --library /absolute/path/to/libverity_verify_test.so
--scratch-directory /usr/obj/... --data-bytes N --block-size N --request-bytes N
[--offset N]` records actual callback counts/bytes and unique backing blocks for
a synthetic zero-filled image using the C verifier. It cleans up temporary
fixtures and records source/library hashes. This is not a disk IOPS, throughput,
RSS or application benchmark; Python callback timing must not be used as kernel
performance evidence. A 65 MiB, 4 KiB-block fixture measured 32 data and 96 hash
callbacks for a 128 KiB request, with only three distinct hash blocks.

### Authenticated leaf reuse

Range verification retains one root-authenticated leaf block using its existing
third scratch buffer. Each data block is freshly read and hashed against these
private bytes. Leaf boundaries authenticate a new path; every request starts
without cached state. Tests check that altered data and a matching malicious
backing leaf cannot bypass retained trusted bytes, and later requests do not
reuse stale state. There is no additional allocation. Callback counts from
`verity_read_cost.py` describe verifier work, not physical I/O or throughput.

### Native verifier timing harness

`make -j$(sysctl -n hw.ncpu) verity-bench-build` builds `verity_bench` in the
standard object directory without running a workload. Its explicit arguments are:

```text
verity_bench data tree descriptor request_bytes iterations stride_blocks baseline|baseline-range|verified|cached starting_slot [cache_entries]
```

Inputs are regular files matching the decoded descriptor geometry. The descriptor
is a benchmark input, not a boot authentication assertion. Requests are aligned
and strides wrap within valid starting blocks. Baseline mode performs the same
block-sized data callbacks and copies, omitting verification; verified mode calls
the actual range verifier. A compiler memory barrier preserves output copies.
JSON reports elapsed/process CPU time, callback counts and process maximum RSS
(FreeBSD KiB). Failures exit nonzero instead of publishing successful timings.

Use separate processes and alternate mode order across repetitions. Report file
cache state, fixture/source/binary hashes and the workload. This userspace harness
uses libmd and regular-file pread; it does not model GEOM scheduling, kernel crypto,
concurrency, physical I/O or full-system overhead. No cache eviction is performed.
The `baseline` mode retains block-sized reads and copies to isolate verifier
cost with the same callback granularity. `baseline-range` reads each complete
request directly into its output buffer; compare both so per-block syscall and
copy costs are visible rather than buried in the baseline. Neither bypass mode
provides integrity. Reports include data/hash callback counts and byte totals;
these are logical regular-file reads, not physical disk I/O or cache-miss counts.
Do not equate either baseline with a conventional installed-system benchmark.

### Optional retained authenticated hash cache

The core exposes `g_verity_cache_init` and `g_verity_cached_read_range` for a
caller-owned, externally serialized cache. Initialization structurally validates
and copies the root descriptor, clearing every offset tag. It does not authenticate
the descriptor. Each entry uses one block plus a uint64 tag; there is no allocation
and zero entries is supported. A miss verifies from root toward leaf before
retaining bytes. Hits never stand in for validation of newly read data.

The 21-test core suite includes eviction, mutable backing, failures and generation/
salt rebinding. Calls, reinitialization and destruction must be serialized by the
future provider; no provider lifecycle or concurrency qualification is supplied by
these tests. Invalid initialization leaves the previous binding unchanged and must
be handled as an error. The original range API remains available and unchanged.

Cached benchmark mode requires an explicit entry count, including zero. Each entry
uses `block_size + sizeof(uint64_t)` bytes, excluding the fixed descriptor and
scratch/output buffers. Each process starts with an empty cache. The cache API
also retains the authenticated leaf in request scratch until crossing its boundary,
avoiding repeated path hashing when a tiny direct-mapped cache evicts parents.
The 22-test core suite checks this with zero, one and two entries.

## Ordinary filesystem compatibility suite (partial, not yet VM-qualified)

Build with `make -C /usr/src/tools/test/construction -j16 filesystem-test-build`.
The standard object directory receives `mmap_data_test` and
`Kyuafile.filesystem`. Stage both together in the disposable VM and run
`kyua test -k /explicit/staged/path/Kyuafile.filesystem`; retain the Kyua results,
source/binary hashes and selected image/policy/filesystem configuration. Run as
an ordinary user on an executable writable dataset, with Kyua temporary work
directories on that dataset. Do not override noexec or execution policy silently
if the selected deployment forbids this; record the applicable policy and use
separate denial cases. This suite specifically qualifies the supported ordinary
unsigned-software configuration, in conventional and hardened systems.

Six cases currently cover repeated read mappings with a later ordinary writer,
rename replacement while old mappings remain live, mapping after unlink through
an open descriptor, unsigned R-to-RX promotion, truncation invalidation with SIGBUS, and 64
coordinated cross-process pathname replacements. Promotion tests permission
behavior without executing arbitrary fixture bytes. Cases use fresh ATF work
directories and explicitly populated files. These are functional compatibility
checks, not disk-throughput measurements, signed-executable tamper checks or
exhaustive concurrent race stress. Compilation and test listing are not executed cases.

The broader roadmap remains required: signed-file mutation and promotion,
noexec denial, concurrent mapping/write/truncate/replacement, sparse and large
files, page faults after memory pressure, filesystem/metadata and fio workloads,
ZFS lifecycle and upgrade operations. Do not count this six-case suite as those
unimplemented tests. Existing construction fixtures are not normal-system boot
qualification; the final system runner must collect these results from the exact
packaged conventional/hardened generation.

Host execution checkpoint: six cases passed without skips on the existing
October 7 GENERIC-NODEBUG kernel. The new veriexec_capimage_mmap feature oid is
absent on that host. This validates test execution and ordinary semantics only;
it does not qualify the changed kernel. Kyua records, source/binary hashes and
host identification are retained in filesystem-mmap-host-review.json under the
review evidence directory. Repeat against the exact packaged candidate in VMs.

Signed mmap coverage belongs to the existing packaged libcapimage tests.
The new `capimage_test:signed_mmap_lifetime` case checks two direct signed
mappings, alias/unlink operations, R-to-RX promotion, write denial until the last
mapping closes, mutation after release, rejection on both R and RX remapping,
and absence of a leaked pin after rejection. It builds but has not run against
the candidate kernel. It requires the mmap feature and a UFS/ZFS work directory;
a missing-feature skip must not count as successful hardened qualification.
Existing handle lifetime cases and tmpfs rejection remain separately required.

### Standalone verifier compile check

`make -C /usr/src/tools/test/construction -j16 verity-standalone-compile`
compiles the shared verifier using the real stand/libsa Makefile, standalone
headers and compiler flags. The check object is written to the standard libsa
object directory; it is not added to libsa or a loader. An existing configured
standalone build tree is required. This proves compile compatibility only,
not authenticated descriptor admission, a device strategy, firmware execution,
verified ELF reads, or performance. Those integration gates remain required.

### Disk read workload matrix (execution pending)

`disk_read.fio` uses fio's portable `psync` engine with one outstanding read per
worker. Separate sequential 128 KiB and random 4 KiB jobs use concurrency
1/2/8/32, with stonewall barriers and per-worker JSON reporting. This is the first
read-only part of the required disk matrix, not filesystem or release
qualification. fio is in the maintained ports checkout at `benchmarks/fio`;
it need not become a base-system runtime dependency. fio 3.43 was built with the
maintained port (NO_DEPENDS=yes, MAKE_JOBS_NUMBER=16) without installation.
--readonly --parse-only and --showcmd succeeded with explicit inputs and a
nonexistent fixture path, which remained absent. This validates option parsing,
not actual I/O or performance. VM execution remains pending. The local check
binary is /usr/obj/5BSD-ports/benchmarks/fio/work/fio-3.43/fio; use an explicitly
recorded fio executable in each test VM. Do not execute --showcmd output as a
substitute for the documented command: that output omits the --readonly guard.

In the disposable test VM, supply these inputs explicitly:

```
export BIP_FIO_FILE=/absolute/path/to/existing/benchmark-file
export BIP_FIO_BYTES=8589934592
export BIP_FIO_SECONDS=60
export BIP_FIO_RAMP_SECONDS=10
export BIP_FIO_SEED=74219
fio --readonly --parse-only /usr/src/tools/test/construction/disk_read.fio
fio --readonly --output-format=json --output=/absolute/new/results.json \
    /usr/src/tools/test/construction/disk_read.fio
```

The values above are examples, not acceptance budgets. Prepare the same real,
non-sparse, incompressible fixture in each candidate using maintained generation
inputs; establish its content digest and allocated size separately before the
run. Do not generate a fixture inside an immutable base after sealing. Use a
filename without fio's colon-list syntax. Require positive explicit sizes and
durations, sufficient space, an existing regular file and a new results path.
Run one VM at a time with 2 GiB RAM and identical CPU/storage/cache settings.
This job neither writes nor creates fixture files; `--readonly` is mandatory.

Collect ordinary ZFS, unverified read-only image, and verified image runs with
identical inputs. The unverified image is a benchmark baseline only. Retain raw
JSON and exact fio version/binary hash, job hash, kernel/generation hashes, mount
and dataset properties, backing chain, fixture digest/allocated bytes, VM
configuration, and execution order. Record read bytes, throughput, IOPS, total
latency percentiles/max, CPU, queue/lock costs, physical device traffic and memory
separately; fio alone does not supply every required measurement. Check every
job's error and completed I/O before treating output as evidence.

For the backing-transport comparison, run this same regular-file workload inside
identical read-only UFS images on file-backed MD and GEOM-mode zvol. Include
unverified transports as explicitly labelled benchmark baselines, then verified
transports when integration exists; never count an unverified run as hardened
qualification. Record MD_CACHE on/off, zvol volblocksize/volsize/refreservation,
compression, actual allocated bytes and backing consumer flags. Require exact
image extent compatibility: a zvol must have volsize divisible by volblocksize,
while the current verification adapter rejects trailing padding. Do not change
image bytes or shrink the fixture between candidates to bypass that constraint.
The zvol path uses existing shared read-range locks/task queues but has not been
measured; it is a comparison candidate, not an established performance fix.

The job uses buffered I/O and does not flush caches. Explicitly label cache
conditions; ramp time does not prove cold or warm cache state. Fixture hashing
warms caches, and guest reboot does not necessarily clear host backing caches.
Use repeated runs and counterbalanced order. Do not derive disk speed from a
cache-resident result or adopt thresholds after seeing results. Synchronous
writes, mixed I/O, metadata, mmap, application workloads, attacks under load,
capacity limits and power-loss cases remain separate required work.

Option semantics reference: https://fio.readthedocs.io/en/latest/fio_doc.html

### Writable-state disk matrix (execution pending)

`disk_state.fio` overwrites the explicit `BIP_FIO_FILE`. Use only a disposable,
existing regular scratch file in the selected VM's writable test dataset, never
a host device, base image, database, or retained user data. It uses the same
explicit environment inputs as disk_read.fio and refuses to create missing
files. All workers share that file; same-vnode contention is intentional.

The jobs cover sequential 128 KiB writes, random 4 KiB writes at 1/8/32 workers,
4 KiB writes with fsync after each block, and eight-worker 70% read/30% write
random traffic. Buffered I/O, refilled buffers and zero requested compressibility
are explicit. Verify actual allocation/compression/dedup effects; a fio option
alone is not evidence that the storage workload is incompressible. Refill CPU
cost is part of the client cost and must be recorded consistently.

Parser checks with the built fio 3.43 passed; --readonly correctly rejected this
write job. No write workload has run. In a disposable VM, after preparing the
scratch file and recording all inputs, use:

```
fio --parse-only /usr/src/tools/test/construction/disk_state.fio
fio --output-format=json --output=/absolute/new/state-results.json \
    /usr/src/tools/test/construction/disk_state.fio
```

Use the same writable-state dataset layout for conventional and hardened runs.
For comparisons against a verified base workload, run read traffic against base
and this traffic against its writable sibling, then measure interference in a
separate explicitly concurrent run. Do not interpret failed base writes as a
write-throughput benchmark. Restore/recreate disposable fixtures consistently
between repetitions and record preparation and cache history.

Report write completion latency and fio's sync latency independently. Adding
percentiles from separate distributions does not produce transaction percentiles.
The fsync job is not a power-loss durability test. Mixed jobs report read and
write throughput/latency separately. The README's resource, raw-evidence and
baseline requirements for disk_read.fio also apply here. Metadata, mmap, database
transactions, crash recovery and actual durability still require separate tests.

### fio workload result validation

`make -C /usr/src/tools/test/construction fio-result-check-test` runs synthetic
validator tests only. For an actual completed run, retain fio's original exit
status and use:

```
python3.12 -B fio_result_check.py --job-file disk_read.fio \
    --result /absolute/results.json --fio-exit-status 0 \
    --minimum-runtime-ms 59000
```

Supply the actual saved process status, not a literal zero after a failed run.
Choose the minimum runtime before running the workload; 59000 is an example for
a 60-second measured run. Job names, worker counts, required I/O directions, fsync activity and
requested percentiles come from the selected job file. Missing/extra worker results,
I/O errors, zero work, short/dropped I/O, unexpected write/trim traffic and absent
latency data fail validation. Both active directions in mixed jobs must complete
work for each worker. Duplicate JSON keys are rejected. The maintained jobs use
group_reporting=0; grouped job specifications are rejected. Multiple workers
share the job name, and their result count must exactly match numjobs.

The report hashes the job and raw result and explicitly sets
performance_qualified=false and provenance_verified=false. This validates report
structure and completed workload counters, not source authenticity, concurrency,
cache conditions, regression budgets, VM limits or physical disk behavior.
Each worker must meet the minimum job and active-direction runtimes separately.
This does not prove simultaneous execution, worker identity, or authentic output;
the external measurement/evidence ledger remains required. These are completion
checks, not a measurement of kernel queue concurrency or performance acceptance.
Synthetic fixtures are not measured results. Real VM-output compatibility of the
validator is still pending.

### Request-local backing read batching

The optional g_verity_read_window adapter batches adjacent data blocks within an
explicit nonempty request. The caller supplies a private buffer, sized in whole
verification blocks and no larger than maxphys, and initializes the window anew
for each request. It must not overlap verifier scratch/output buffers. There is
no allocation of the window in this helper and no automatic capacity selection.
Each worker would need its own buffer; include that memory in the provider budget.

The fetched extent is bounded by the request rounded to verification blocks,
not the entire image or an arbitrary read-ahead distance. Tree reads retain their
existing behavior. Window bytes remain unverified: the unchanged C core hashes
and authenticates every consumed data block. The caller must pin the backing
consumer, serialize use and drain I/O before teardown as before.

`make verity-io-test` runs actual adapter/core code with injected GEOM functions
and real SHA256. A 128 KiB request uses 32 data + 2 hash BIOs on the reference
adapter and 1 data + 2 hash BIOs with a 128 KiB window; an 8 KiB window needs
16 data BIOs. Partial-boundary reads fetch only touched blocks. Tests also cover
last-byte access, corruption, invalid bounds, short/error fills, invalidation and
BIO disposal. Kernel-object compilation with -Werror passes. This is not live
GEOM I/O, parallelism, disk latency, throughput, root binding or boot evidence.
No provider or frontend path automatically selects the optional adapter yet.

### Verifier provider component (not enabled for boot)

`verity-kernel-compile` now also compiles g_verity_provider.c with configured
kernel headers and -Werror. The internal constructor takes an already
authenticated root and explicit worker count, cache entries, read window size
and allocation budget. It does not authenticate that input, expose a root gate,
register a taste routine, or offer a user control interface. No kernel config,
loader or build-bsd runtime option enables this component yet.

Large read compatibility: provider admission accepts mapped in-bounds BIOs larger
than maxphys when their length fits size_t. GEOM's g_io_check does not impose a
universal maxphys limit on upstream requests. The existing read window bounds
each backing request instead; private worker memory does not grow with the BIO.
A 256 KiB admission case passes. The actual core/backing-adapter test authenticates
a 516 KiB request through five data fills of at most 128 KiB, and a final-block
mutation clears the complete request output. These are injected BIO counts, not
disk throughput results. Long-request fairness, teardown latency during a large
read and total upstream memory pressure remain live-system qualification items.

Workers own their cache/scratch/window buffers and perform verification outside
the queue lock. The provider queues upstream BIOs without new payload buffers;
its budget counts requested worker records and buffer bytes, not thread stacks,
allocator overhead, upstream queues or filesystem caches. Overall bounded-memory
qualification still requires those costs under pressure. Writes/deletes and
write opens are denied; controls are not forwarded. A backing read/exclusive
consumer remains held until workers drain. Orphan/resize stops new work and
cancels queued work; unopened explicit destruction uses the same path. Open
providers cannot be explicitly destroyed. This is not a complete BIP seal.

`make verity-provider-test` executes the actual read-admission, worker, stop and
drain methods with injected GEOM/kernel operations. It covers successful and
failed in-flight verification followed by queued cancellation, both provider-gone
orderings relative to drain, write/control denial, invalid reads, destroy while
open, repeated stop, and backing orphan/resize. Constructor injection additionally
covers attach/open/bind errors, orphan during backing open, failure to start each
of three workers, invalid resource inputs, duplicate provider names, and successful
publication/destruction. Failed construction must preserve the output pointer,
publish nothing, retain backing until started workers drain, and release all
tracked worker/buffer allocations. The compiled mutant with the open-time orphan
guard removed fails the expected constructor error assertion.

These tests schedule workers sequentially after construction returns. They do
not establish real topology/queue races, thread startup interleavings, allocation
pressure, actual BIO completion, authenticated bytes or performance. Core
authentication has its separate native suite. Required next qualification
includes real concurrent reads/removal, exactly-once completion and complete
resource accounting, including kernel thread stacks and allocator overhead.
The provider is not enabled in normal kernel/boot configuration. The maintained
verity-provider-module-build target now links the real provider, adapter and core
through sys/modules/geom/geom_verity and bsd.kmod.mk:

    make -C /usr/src/tools/test/construction -j16 verity-provider-module-build \
        VERITY_KERNEL_OBJDIR=/usr/obj/usr/src/amd64.amd64/sys/GENERIC

The target requires the configured kernel object directory explicitly and builds
under the standard /usr/obj root. It does not load or install the module. The
initial -Werror build produced geom_verity.ko; all 54 undefined symbols were found
in that configured kernel, with no unresolved internal g_verity symbols. Symbol
presence does not prove runtime ABI compatibility, successful loading, provider
registration, boot authentication or performance. This component Makefile is not
included in the default GEOM module list. Trusted root binding and live lifecycle
qualification remain prerequisites for enabling it through normal build/staging.


### Kernel preload descriptor parsing

verity-preload-test compiles the actual g_verity_preload_decode and root format
decoder with injected preload enumeration. It covers one valid descriptor among
unrelated modules, missing descriptors/types, duplicates (including malformed
duplicates), short/long descriptors, null addresses, malformed reserved fields,
null output and output preservation. The private decoded root is independent of
later changes to the input bytes. The loader metadata type is not authentication;
the eventual boot caller must establish the loader/generation trust chain first.
The decoder is in the explicit component module/compile targets and is not
invoked by mountroot. Actual metadata lifetime, backing selection and final root
admission still need integrated qualification.


### Optional verity artifact integration checks

verity-artifacts-test exercises real image/tree/descriptor bytes on synthetic
payloads, selected policy validation, source digest mismatch, retained corruption,
descriptor disagreement, symlinks and refusal by the legacy boot verifier.
layout-transport-test includes both verity artifacts in its base round trip and
rejects writable-seed verity entries. The build-bsd image-plan test checks the
new policy argument routing; generation_image_test.SourceGuards checks that only
the immutable base receives it. These are not full makefs/readback or VM tests.


### Real makefs alignment test

verity-makefs-test requires explicit VERITY_MAKEFS, VERITY_FSCK and VERITY_DUMPFS
paths. It creates regular-file UFS2 images for all supported verity block sizes
and uses the actual backend makefs_options helper (-R size rounding). Compared
with the ordinary baseline, bsize/fsize/frag/fsbtodb must stay unchanged; image
length must align. It runs fsck_ffs -f -n, requires phase 5 and successful exit,
checks unchanged bytes and builds/verifies the combined artifacts. No mount,
mdconfig, VM or block-device operation is used. The fixture includes a directory,
hardlink and symlink but is not a full packaged generation or a mounted-content
readback test. No disk performance conclusions follow from this check.


### Loader file-reader component

verity-loader-read-test compiles the actual stand/libsa/verity_read.c and shared
verifier against native POSIX file I/O. It tests authentic replay, changed replay
after a valid prefix, full-output clearing and guards, restoration, failed init
preserving a prior binding, recursive-use rejection, bounds and truncated media.
verity-standalone-compile also compiles that adapter with real libsa headers.
The adapter requires a caller-authenticated root and caller-owned private
cache/scratch buffers and file descriptor; it allocates nothing. It is not yet
registered as a loader device or used by UFS/ELF loading. These tests therefore
do not establish firmware trust or repair the existing VECTX loading path.


### Loader verified-device component

The internal stand/common/veritydev wrapper now exposes the bounded reader as a
read-only loader disk strategy. Attachment requires a caller-authenticated root,
checks an explicit heap budget and transfers the backing descriptor only on
success. Units are never reused within a loader session. Open pins the attachment
before partition parsing; detach rejects open or active readers. Sector offsets
are checked before arithmetic. Authentication failure reports zero completed
bytes. Detach retires the unit even if libsa close reports an error, and returns
that error rather than hiding it.

verity-loader-device-test compiles the actual wrapper, reader and verifier with
real temporary files and injected loader partition operations. It passes budget,
overflow, write rejection, changed replay, output clearing, partition offset,
open/detach lifetime, stale unit, failed open and close-error retirement checks.
verity-standalone-compile also passes with real loader headers and -Werror.
These are component checks, not actual partition parsing, firmware or disk
performance tests. The device is not registered in normal loader builds and does
not yet repair the VECTX path. Descriptor authentication, device selection and
kernel root admission remain integration work. The existing build-bsd artifact
inputs and explicit refusal of unsupported verity boot remain unchanged; no new
frontend switch or boot claim is appropriate for this internal component.
Evidence: verity-loader-device-review.json.

Loader parser integration follow-up: the real disk parser rejected verity device
names because disk_parsedev recognized only disk/vdisk. A native test reproduced
that failure before the fix. disk_parsedev_named now shares the existing suffix
parser with an explicit expected device name; the existing entry point preserves
disk/vdisk syntax and the verified device selects verity. This is loader setup
code and adds no running-kernel filesystem check.

The maintained verity-loader-partition-test uses actual disk.c, part.c, veritydev,
reader and verifier with native file I/O. It passes raw extent and MBR slice
opening, offset and media-size checks, existing disk/vdisk/MBR/GPT name parsing,
wrong-device rejection and partition-read failure after backing corruption.
The payloads are synthetic extents, not UFS filesystems; GPT name parsing is not
a GPT image test. Only native type declarations and pager output are substituted,
not partition parsing. Existing part.c unused parameters are permitted by the
native compile flags. The shared disk object also compiles under the real EFI
loader flags with -Werror after the maintained beforebuild header setup.

This does not register the new device, authenticate descriptor selection, fix
VECTX loading, boot a system or establish performance. build-bsd inputs and its
refusal of unsupported verity boot remain unchanged; the shared parser fix needs
no new frontend option. Evidence: verity-loader-partition-review.json.

Shared descriptor authentication and attachment: verified_root_read now contains
the existing manifest verification plus private-buffer authentication sequence;
file_readroot uses it for descriptor preload. The shared source is included in
the normal loader.mk build. verity_dev_attach_verified authenticates and decodes
through that same helper, then attaches the backing descriptor. It publishes the
exact authenticated wire bytes only after successful attachment, so the eventual
kernel handoff need not reopen a mutable descriptor file. The caller retains the
descriptor-file handle; failure leaves the backing handle and outputs untouched.
The new attachment entry point is internal and is not yet called by boot selection.

root-descriptor-load-test passes with verification enabled/disabled and now checks
shared-output preservation. verity-loader-attach-test passes actual helper/device/
decoder code with native files and injected manifest decisions: verification off,
unverified input, changed bytes, authenticated malformed format, insufficient
budget, and descriptor mutation after buffer authentication. It is not a real
signature-chain test. The EFI module.o and verified_root.o compile with -Werror;
verity-standalone-compile covers the new attachment adapter. Neither loader
registration nor authenticated kernel root admission is complete.

The private buffer is bounded, but the maintained verify_file manifest/payload
verification call performs its own I/O first; these checks do not establish a
bound on all verification I/O or boot latency. Keep that distinction in the
remaining loader integration/performance review. build-bsd uses the maintained
loader build and needs no new input for this refactor. Unsupported verity boot
remains explicitly rejected by its backend. No VM or performance qualification
is claimed. Evidence: verity-loader-attachment-review.json.

Loader filesystem-path follow-up: a test using verityN:/boot/kernel/kernel
reproduced another integration failure: disk suffix parsing selected an automatic
partition although the base artifact is a whole filesystem image. The verified
device now defaults an unqualified unit to the whole authenticated extent;
explicit partition syntax remains available. Ordinary disk/vdisk parsing is
unchanged. The partition test now includes file paths. Its native strategy flags
also now match stand.h (F_MASK and F_NORA).

verity-loader-ufs-test requires explicit VERITY_MAKEFS and builds a real UFS2
fixture with the backend's normal -R alignment helper, then builds its verity
artifacts. It compiles the actual loader UFS, disk/partition, device, reader,
verifier and FFS superblock routines against native allocation/file I/O. File
contents, hardlink and symlink access, backward seeking, and rejection after
primary-superblock corruption pass. It substitutes native open-file declarations,
pager/spinner/panic glue; it does not substitute filesystem parsing or hashes.
Existing UFS sign/unused-variable warnings are permitted in this native harness.
The test is a small real filesystem, not a complete packaged system, a loader
binary execution, firmware trust, kernel root admission or performance evidence.
No mount, VM or host policy change is involved.

The fix requires no build-bsd option change: its backend already constructs whole
filesystem images. Normal boot selection still does not use the verified device,
and the backend continues rejecting the unsupported verity boot route. Keep the
remaining integration gate open. Evidence: verity-loader-ufs-review.json.

EFI loader build integration: verifier-enabled EFI loader builds now compile the
shared hash verifier, file reader, verified device and authenticated attachment
adapter, and register the device in devsw. The normal EFI Makefile derives this
from MK_LOADER_VERIEXEC; there is no new independent security switch. Disabled
loader-verification builds exclude the verified device. The shared descriptor
reader remains in the common loader build and refuses authentication when
verification is disabled.

The maintained build-bsd loader-build regression probes the actual make graph
for amd64/IA32 EFI source inclusion and disabled-mode exclusion. It passes. The
complete native amd64 EFI loader built and linked after rebuilding its stale
libsa dependency (initial link lacked verify_buf). The resulting PE32+ EFI image
has no undefined symbols in its symbol image; verity_dev, authenticated attach,
shared descriptor reader and cached range verifier are linked. This supersedes
earlier notes that the device was not registered. No image was installed or
executed and no IA32 runtime/build qualification follows from the graph probe.

There is still no boot-selection caller for authenticated attachment or kernel
root handoff/admission. Registration alone establishes neither trust nor a
working hardened boot. The normal build-bsd boot backend must keep rejecting
unsupported verity boot until those pieces are complete. No frontend argument
change is needed; normal loader build dependencies and the maintained build-graph
test were updated together. Firmware, VM, compatibility and performance gates
remain open. Evidence: verity-loader-link-review.json.

Kernel provider identity prerequisite: g_verity_provider_root copies the immutable
constructor root from the exact live verifier provider while the caller holds
GEOM topology and a reference keeping that provider alive. It checks class object
identity, the softc's exact output provider and non-stopping state. Foreign or
aliased provider objects and stopped providers are rejected without changing
caller output. It uses the existing immutable worker root copy, adds no new
allocation and is not called on the read path. A returned root is not proof of
signature authority or a BIP admission token.

The actual provider constructor/lifecycle tests now exercise successful query,
caller-copy mutation independence, null arguments, foreign class, mismatched
provider object and query after stopping, with output preservation. Both native
provider test cases pass; configured-kernel -Werror compilation and explicit
geom_verity module linking pass. These tests inject kernel operations and use
sequential scheduling; they do not prove a live GEOM/mount race property.

Admission must next follow the busy UFS mount's actual um_cp->provider and compare
that verifier root with the authenticated preload before accepting the final
root. Names and read-only flags alone cannot substitute. The existing BIP md0
gate remains intact; no staged-root fallback or broad mount exception was enabled.
There is no new frontend input for this internal query, and maintained build-bsd
boot publication still rejects the incomplete verity mode. VM and performance
gates remain open. Evidence: verity-provider-identity-review.json.

Mounted UFS identity prerequisite: g_verity_check_ufs_root validates a structurally
valid expected root, requires a read-only UFS root mount, follows that busy
mount's um_cp->provider under GEOM topology, and compares all defined identity
fields from the exact live verifier. It does not compare structure padding,
pathnames or mount-source strings. Missing consumers, absent read holds, writable
consumers, foreign/stopped providers and mismatched roots fail. The caller must
hold the mount busy, exclude mount updates during admission, and authenticate
the expected root independently. This query creates no lasting storage seal and
is not called on the I/O path.

verity-mount-test executes the actual check with the actual verifier's expected-
root validation and injected mount/GEOM objects. It passes valid identity plus
hash/salt/salt-length/filesystem/geometry mismatches, invalid expected root,
foreign filesystem/provider, writable/non-root mounts, missing mount private
state or consumer/provider, absent read hold, writable consumer, provider failure,
and topology-lock balance. Configured-kernel -Werror compilation and explicit
module linking pass. Live mount lifetime/remount races are not qualified by this
sequential harness.

The helper is not yet called from final mountroot admission. Authenticated staged
boot construction, final mandatory admission, topology protection and fail-closed
fallback behavior still need integration. The existing BIP md0 gate remains
unchanged, and build-bsd still rejects unsupported verity boot publication. No
new frontend input or normal-image behavior follows from this internal helper.
No VM or performance qualification is claimed. Evidence:
verity-mounted-root-identity-review.json.

Mountroot construction mechanism: GEOM_VERITY is now an explicit optional kernel
configuration that includes the verifier, provider, preload decoder and mount
identity check. No default kernel configuration selects it. Its .verity directive
accepts an existing backing provider name, output name, worker count, hash-cache
block count, read-window bytes and heap-budget bytes. It structurally decodes the
unique root preload and calls the provider constructor under GEOM topology.
Missing/trailing/malformed/overflow arguments, preload errors, missing providers
and constructor failures are returned; token allocations and topology lock are
released. Names locate objects and establish no root authority.

verity-mountroot-test runs the actual tokenizer/directive with injected preload
and GEOM operations and passes these cases. The configured-kernel compile target
now compiles the enabled mountroot path with -Werror. The real config tool also
accepted a GENERIC-derived VERITY_CONFIG_CHECK under the standard /usr/obj root;
its generated opt_geom.h and Makefile include all five verifier sources. This is
configuration/translation-unit evidence, not a full newly linked or booted kernel.

The conventional mountroot parser can continue to later root candidates after a
directive failure. This directive deliberately does not claim mandatory root
admission: the final verified-root gate must reject all such fallbacks before
userspace. The current BIP md0 gate and disabled staged-config reading remain
unchanged. No runtime user ioctl was added. The mount.conf and build-bsd manuals
explain that these are mechanisms, not supported hardened boot publication;
existing build-bsd kernel configuration selection needs no new flag and its boot
backend still rejects the incomplete verity mode. No VM or performance evidence
is claimed. Evidence: verity-mountroot-construction-review.json.

Final mountroot identity gate connected: GEOM_VERITY kernels now inspect the
unique root preload after the staged mount loop and before time initialization,
prison0 root assignment, root_mount_complete publication and mountroot callbacks.
When the descriptor is present, the final root must pass the actual UFS/verifier
identity check with a busy mount reference. Attempting .verity also records that
a descriptor is required, even if its arguments or construction fail. Missing,
invalid, duplicate or mismatched requested roots panic before userspace admission;
a conventional fallback to the backing root cannot satisfy the check. With no
descriptor and no .verity attempt, conventional boot behavior is unchanged.

verity-admission-test runs the actual final gate with injected preload/mount
operations: conventional absence, requested absence, malformed/duplicate preload,
missing root vnode/mount, busy-reference failure, identity failure and success.
It checks release of the busy reference on a failed identity check. A source
placement guard checks ordering before completion publication and callbacks.
Both pass, along with the directive and mounted-root component tests; the enabled
mountroot translation unit compiles with -Werror. This is not a live staged mount
or kernel boot test and does not qualify concurrency or persistent sealing.

This supersedes earlier notes that no final identity gate is connected. It does
not authenticate the descriptor signer by itself. The earlier MAC_SYSTEM_INTEGRITY
entry gate still forces immutable md0 and blocks staged-config reading, so the
full authenticated disk-backed BIP boot path is not yet enabled. It must bind the
firmware/loader authority, staged layout and final identity while preserving
mandatory runtime protection. The mount.conf and build-bsd manuals are updated;
normal build-bsd boot publication remains rejected for this incomplete mode.
No VM or performance evidence is claimed. Evidence: verity-final-admission-review.json.

### File-backed mountroot setup regression

`make md-mountroot-test` compiles the actual `parse_dir_md` function against the
current MD ioctl definitions with injected metadata/open/ioctl operations. A
16 GiB declared backing file must select `MD_VNODE`, `MD_READONLY` and
`MD_AUTOUNIT`, with `MD_CACHE` absent. Its setup allocation must depend only on
the ioctl structure and pathname, not image length. Stat/open/attach failures
and rejected unit cleanup are also checked. No file of that size is created,
no device is attached, and no VM runs. This checks setup choices and cleanup,
not kernel MD working-set size, authenticated root admission, throughput or the
required actual 2 GiB VM boot.

The .verity backing argument also accepts exact md# to refer to the unit allocated
by a preceding .md directive. It fails without a supported allocated unit;
explicit provider names remain literal. verity-mountroot-test covers this
resolution with injected GEOM operations. This does not establish boot authority.

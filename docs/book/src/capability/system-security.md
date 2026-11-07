# System build and security roadmap

## Current scope — 2026-10-24

The user explicitly dropped BIP. Finish BSDFoundry (currently implemented as
`build-bsd`), Secure Boot, veriexec/code signing, and incremental Bazel support
BIP and root-resistant immutability are outside the active scope. The former six-gate BIP goal
is paused, not completed. No host installation or reboot is authorized.

### Execution order

1. Remove experimental BIP from active build/security work. Preserve
   ordinary UNIX compatibility, existing capability services, mac_abac and openES.
   Review shared changes individually; do not revert unrelated work wholesale.
2. Make the maintained build frontend dependable for conventional systems:
   declarative configuration and overrides, local/remote source inputs, ports
   and repositories, all-CPU compilation, cross builds, board/image selection,
   local/server updates, boot-environment deployment/rollback/retirement and
   default/USB installation images. Separate persistent application data from
   OS rollback. Use standard /usr/obj objects and the combined repository.
3. Qualify the real Secure Boot chain in QEMU: positive and negative signature
   cases, owner-key enrollment, rotation/revocation and recovery, update failures,
   and a factory-key/shim strategy. Native signature checks do not prove firmware
   enforcement. Keep firmware, release, application and repository trust roles
   explicit even where an organization chooses to reuse key material.
4. Qualify veriexec and embedded code signing independently: normal UNIX and
   capability applications, libraries, interpreter dependencies, signed/unsigned
   policy, trust changes and tampering. Compiled-in support is not enforcement.
5. Introduce Bazel through the same maintained frontend and artifact contracts.
   Keep Make supported. Require real world/kernel/package/image builds, dependency
   correctness, cross-build evidence and output comparisons before making Bazel
   the default. Imported Bazel files are not an integrated BSD build backend.
6. Run the full compatibility and resource suites. Include base services, login,
   PAM, su, SSH, NFS, capability daemons, mac_abac/openES and popular third-party
   software. Compare disk I/O and memory consumption as well as throughput and
   latency. No fixture success substitutes for a packaged installed-system test.

The complete earlier requirements, application matrix, toolbox/jail requests,
policy discussions, evidence chronology and BIP roadmap are preserved in the
checkpoint below; they have not been declared fulfilled or discarded.

## Product targets: workstation first, embedded next — 2026-10-24

The first complete deliverable is an installable 5BSD workstation image with KDE
Plasma, a Wayland session, working graphics drivers/firmware and Mesa, and the Dart
SDK. Use this machine as a reference for functionality, not as an implicit source
of installed files, secrets, package versions or site configuration. The inspected
local ports tree contains x11/kde, x11/plasma6-plasma and lang/dart; the host has
Plasma6/Mesa and matching 5BSD hardware packages. This establishes available
inputs only, not a reproducible desktop build or qualified image.

Forge/BSDFoundry must produce both workstation and embedded systems through one
maintained frontend, configuration schema, dependency resolver and publication
pipeline. Ship maintained, versioned profiles with explicit user overrides:

- Workstation profile: declared desktop/application package roots, desktop
  service/session defaults, graphics hardware profile, user provisioning and
  disk/USB installer outputs. Packages resolve from local builds or configured
  signed binary repositories, with their complete dependencies recorded.
- Embedded profiles: explicit target architecture, board, kernel, boot firmware,
  hardware/driver selection, package roots and board-appropriate image format.
  Do not impose desktop packages or workstation disk layout on embedded targets.
  Cross compilation and unavailable target dependencies must be explicit.
- Shared configuration: sources/ports/repositories, signing and trust inputs,
  build backend/jobs, services/site overrides, image outputs and update channel.
  Profile data belongs in maintained files; do not hardcode workstation package
  names or host hardware in the frontend. Keep base/hardware identity checks and
  the standard combined publication path. General application packages remain
  ordinary ports packages, not hardware packages renamed to fit that publisher.

Prioritize the workstation vertical slice after builder/package prerequisites:
produce packages, publish, create installer, install, boot a real graphical
session, run Dart and update the installed system. The same pipeline must then
produce an explicit supported embedded-board image. This orders the work without
replacing the Secure Boot, veriexec, Bazel or broader compatibility requirements.
Bazel remains gated on parity; image production must also work through Make.

Acceptance includes normal login/logout and lock/unlock/PAM, actual Wayland
session identification, input devices, display modes, graphics rendering and
acceleration identification, networking, audio, persistent home data, Dart
execution/compilation, application installation and signed-repository updates,
new boot-environment upgrade/rollback and old-environment deletion. Run disk-backed
QEMU qualification with 2 GiB RAM, measuring disk I/O and memory. Record software
rendering separately from acceleration; virtual GPU results do not qualify AMD,
Intel or NVIDIA physical hardware. Physical graphics and board boot checks need
separate evidence. No desktop or embedded image is declared complete today.

## Binary repository requirements — 2026-10-24

This extends execution step 2; multi-repository Foundry support is a completion
requirement, not a claim of implemented or qualified behavior.

- Keep the existing combined base/kernel/hardware publication. Build base and
  hardware separately under /usr/obj, then publish one verified generation under
  /usr/obj/usr/src/repo. Only complete publication advances latest; base-only
  packages use latest-built. Retain kernel identity, ABI, dependency and shared
  library checks. Graphics drivers selected by the hardware profile belong in
  this combined generation.
- Distribute ordinary pkg binary repositories. Official applications may share
  a catalogue with system packages or use a separate application catalogue;
  repository boundaries must not determine executable trust. General ports
  packages need an explicit publication input, not a hardware-package disguise.
  Separate architecture/release channels and retain versioned snapshots.
- Declare named repositories in Foundry configuration: local directory or server
  URL, enabled state, target/channel, trusted key or fingerprint paths and
  selection priority. Use pkg's repository verification and installed repository
  configuration conventions. Support official, organization and administrator-
  selected third-party sources without embedding site URLs or keys in code.
- Define explicit source selection/replacement rules for package identities,
  especially base, kernel and matching modules. Priority alone does not authorize
  a third-party source to replace system packages. Record chosen repository,
  version, archive digest and dependency closure in the resolved build/update
  inputs; do not re-resolve a moving channel halfway through a transaction.
- Require authenticated catalogues and verified payloads for distributed release
  inputs. Keep repository signing distinct from code-signing entitlements,
  veriexec trust and firmware trust. A repository signer does not automatically
  become a firmware or executable authority. Installing a trusted package can
  execute privileged package scripts; repository admission is a real trust grant.
- Keep local and remote update paths equivalent after verification. Stage base,
  kernel and driver upgrades together in a new boot environment. Support ordinary
  application updates with explicit restart and rollback semantics; database
  data/schema migration is separate from package or boot-environment rollback.
- Qualify official plus custom repositories, duplicate names/source restrictions,
  missing dependencies, ABI/kernel mismatches, tampered catalogues and payloads,
  wrong/rotated/revoked keys, stale snapshots, interrupted fetch/publication,
  offline use, upgrade/rollback and removal of obsolete boot environments.
  Define freshness and intentional downgrade policy rather than assuming a
  signature alone prevents rollback attacks.

### Local network repository qualification

Use a real signed pkg repository served over HTTP from a VNET jail inside the
disposable 2 GiB QEMU guest. A separate client VNET jail uses an epair link and
explicit test addresses; no external networking or host network configuration
is required. The repository is ordinary pkg output, not a fake catalogue or
mock verifier. Serve a read-only published snapshot; publish the next candidate
separately and atomically switch the advertised channel. Capture server requests
and client outcomes to distinguish network fetches from accidental cache hits.

Start after ordinary offline package installation works. Exercise the maintained
Foundry server-input path and real pkg verification: initial fetch/install,
updated catalogue/package, additional organization repository and source-selection
rules, wrong signer, changed payload, key rotation/revocation, interrupted download,
server unavailable, stale snapshot policy, cache/offline behavior, and unchanged
installed state on rejected updates. Add HTTPS with an explicit test CA separately;
a valid TLS connection does not replace repository signature verification.
Derive addresses, ports, keys, repository paths and selected package identities
from explicit fixture inputs. Verify jail/epair teardown after success and failure.
Base-update boot-environment activation and rollback still require subsequent
whole-guest reboot tests; a client jail cannot establish those properties.

This is a planned qualification fixture. GENERIC enables VIMAGE, but the exact
selected guest kernel, epair support, server and client payloads must be checked
before execution. No host jail or network changes are authorized by this plan.

Implementation must update build-bsd.c, maintained publication/snapshot/deploy
helpers, configuration examples, manual and tests together. The existing
publisher optionally signs and verifies its combined catalogue when a signing
key is supplied; this does not establish mandatory signing or a qualified
multi-repository updater today. This change records the design only.

## Recoverable BIP checkpoint

- Repository: `/usr/src`, original branch `dev`.
- Archive branch: `archive/bip-context-20261024T044334Z`.
- Archive commit: `9edc8078a6a8d1e88cef420c8b455a94dcd13769`.
- Parent commit: `ab0cebcd051c7a90e193dc1d7f301796864fa5f3`.
- Receipts and original index/patches:
  `/usr/obj/usr/src/bip-deferred-20261024T044334Z`.
- Historical test evidence was recorded in the
  `stage-20261022-reviewed` review stage.

The archive captures the **complete shared dirty worktree**, including unrelated
in-progress work. It was created with a separate Git index; the original branch,
index and working files were unchanged at checkpoint creation. Do not merge or
cherry-pick the whole checkpoint into ongoing development.

To inspect/resume it without overwriting active work:

```
git -C /usr/src worktree add --detach \
    /usr/obj/usr/src/bip-resume-20261024 \
    9edc8078a6a8d1e88cef420c8b455a94dcd13769
```

Consult `storage-retirement.json`, `policy-retirement.json` and
`retired-policy-tests.json` beside the checkpoint receipt when recovering selected
changes. The archived `docs/book/src/capability/system-security.md` contains the
full prior roadmap. Future system builds still use /usr/src and /usr/obj; the
recovery worktree is an inspection workspace, not a publication-path override.

## Separation performed

- Restored conventional MD, mountroot, GEOM VFS and GEOM diagnostic-override code
  from the parent commit. Removed the experimental kernel-only MD request API.
- Removed GENERIC-INTEGRITY, the MAC_SYSTEM_INTEGRITY kernel option/registration
  and implementation, and BIP-only conditional restrictions in exec/fork and
  capability system/isolation code. Conventional capability changes are retained.
- Moved the associated native tests and unfinished MD/zvol benchmark draft into
  the archive. No benchmark result is claimed.
- Retained shared storage protocol declarations required by Capsule/SwitchBoard.
  Those declarations do not imply an available BIP enforcing provider.
- Retained loader verification, signing and generation tooling pending dependency
  review. Some of this is shared with the deferred immutable-image design.
  This is not yet a claim that every BIP-origin change has been separated.

## Evidence and limits

The affected conventional kernel objects compile with -Werror and -j16; see
`bip-retirement-kernel-build.log`. This is not a complete kernel or system build.
The current frontend builds, and conventional world/packages plans use GENERIC,
bsd-make, standard object/repository paths and production malloc for publication.
They do not invoke BIP construction and explicitly report boot/root protection
verification as not performed. Bazel is not yet accepted as a backend.

The 2 GiB/two-vCPU QEMU smoke test completed before retirement, using the retained
conventional GENERIC kernel; it shut down cleanly. It does not qualify the newly
edited tree, Secure Boot, BIP, upgrades or storage performance. No VM remains
running from that test. QEMU execution is authorized one VM at a time.

BIP's archived implementation was incomplete: disk-backed authenticated root
admission, backing-storage protection, compatibility, upgrades, key lifecycle and
performance all had outstanding gates. Secure Boot and veriexec are useful
independent protections; neither alone supplies a root-resistant immutable OS.
BIP is dropped, with no scheduled return. The existing archive remains historical
recovery material. Remaining mixed dependencies must be removed without losing
independent capability, Secure Boot or veriexec functionality.

## BIP removal follow-up — 2026-10-24

BIP is dropped rather than deferred. Removed the unused process guard and its
fork/control branches, ordinary-state sysctl classifications, device-open
classifications, and BIP runtime-linker policy. Ordinary runtime-linker hints,
libmap and library lookup are restored; existing ELF signature verification is
retained. BIP-only lifecycle and runtime-linker source tests were retired.
Preimages and receipts are in `/usr/obj/usr/src/bip-removal-20261024-runtime`.

Verification: affected capability/fork/descriptor kernel objects and build-bsd
compiled. The runtime linker built successfully through the maintained world
buildenv, including its ELF signature object. A direct host-header build first
failed because installed headers lack sys/capimage.h; that failure is retained
in rtld-build.log, with the successful build in rtld-buildenv.log. No installation,
boot, or runtime qualification was performed for these edits.

Removal is not complete. Remaining work includes Capsule/SwitchBoard protected
storage/bootstrap interfaces, BIP ELF markers and admission, loader/generation
integration, protected authentication/configuration paths, and mixed fixtures,
build actions and documentation. Review each against the independent capability
and signing requirements before removal. The build frontend was inspected and
rebuilt for this cleanup; conventional build inputs were not changed.

### ELF and bootstrap removal

Removed the BIP ELF feature/auxiliary flags, executable/interpreter admission
state, elfctl option, and SwitchBoard build marking. Capsule no longer probes
BIP enforcement or requires an immutable marked manager; it uses normal exec.
Removed BIP-only console/runtime delegation from bootstrap. Kept capability
handoff confinement (CLOFORK_LOCKED and CLOEXEC_ONCE) and independent ELF note
parser fixes. The bootstrap helper now contains only descriptor confinement.

Maintained ELF_FEATURES rules remain available for ordinary supported ELF flags.
Their build tests now exercise wxneeded, including debug splitting, per-program
selection, installation-image generation, rebuilds and tool failure. Four build
rule tests and eleven ELF inspection tests passed using the rebuilt elfctl.
The real native manager-handoff test passed, observing confinement in a child
constructor and through fork/exec. This does not qualify full system startup.

The changed ELF kernel object, elfctl and Capsule compile. Logs/preimages are
under `/usr/obj/usr/src/bip-removal-20261024-elf`. No host installation occurred.
The normal build frontend's backend rules and tests were updated together;
its command-line inputs do not change for these removals.

Still pending: protected storage/runtime configuration machinery in Capsule and
SwitchBoard, BIP-only policy files and authentication changes, generation/loader
integration and mixed Secure Boot fixtures. Legacy generation tests still refer
to the removed BIP marker and must be retired or separated with that machinery;
they are not passing qualification evidence for the active design.

### Capsule configuration and runtime removal

Removed the BIP-only Capsule runtime helper and package-installed /boot policy
copy. PID 1 and daemon configuration use /etc/capsule.conf. Configuration reports
now give that path for both boot and normal operation. Removed the immutable
configuration input mode and kernel enforcement queries, plus BIP's single-user
recovery and reroot prohibitions. Ordinary parser validation, ownership checks,
explicit-path errors and atomic configuration replacement remain.

The Capsule build (including tests) passed in the maintained world buildenv.
Six selected native parser cases passed: selected inputs, atomic rejection,
external-input rejection, descriptor validation, shipped policy and examples.
They ran directly with temporary working directories, not as an isolated Kyua
system suite. The first descriptor test run exposed an obsolete pre-success
snapshot; it now captures the successfully loaded state before exercising
rejections and passes. Eleven configuration-composition tests passed using the
normal policy path. Receipts and logs are under
/usr/obj/usr/src/bip-removal-20261024-config. No host settings were modified.

Storage schema/provider grants, SwitchBoard runtime admission, protected crypto
and authentication paths, loader/generation integration and mixed VM fixtures
remain to be separated. Existing generation tests expecting /boot/capsule.conf
are obsolete BIP tests, not evidence for normal installation or upgrades.

### SwitchBoard startup removal

Removed BIP enforcement discovery and its inherited runtime-token admission,
tmpfs requirement, immutable identity-snapshot selection, isolated-NSS selection
and BIP-only OpenSSL initialization wrapper from SwitchBoard startup. The
ordinary startup signature verification path remains. Removed the retired
runtime descriptor from inherited-descriptor bookkeeping. Console units use the
normal controlling terminal again; removed BIP-only console validation and the
associated launch rejection test. The separate capability descriptor locks and
ordinary launch credential checks remain.

SwitchBoard and its test programs compile through the maintained world buildenv
with -j16 and -Werror. Build output and preimages are under
/usr/obj/usr/src/bip-removal-20261024-switchboard. This is compilation evidence,
not service runtime or installed-system qualification. The normal build frontend
was reviewed: these sources are reached through its maintained world/package
backends, with no new frontend inputs. No host services were started or changed.

Remaining BIP-only state and branches in session/authority/account helpers must
still be removed; removal of startup enforcement selection does not establish
that those dependencies have been eliminated. Storage protocols, schema and
package policy, authentication changes, generation/loader paths and legacy VM
fixtures likewise remain under review. No immutable-system claim is supported.

### PAM removal and component qualification

Removed BIP file-provenance traversal from OpenPAM, the protected_passwd and
protected_login_conf backends/options in pam_unix, and the BIP authenticator
policy template. Removed their API declaration, manual, package entries and
BIP-only tests. Ordinary NSS authentication and login classes remain. Retained
independent fixes for module candidate errors/version suffixes, include-cycle
and expansion limits, null crypt results, empty-token rejection and resolver
result handling. The legacy Secure Boot fixture no longer compiles the removed
credential backend or invokes its BIP credential tests.

The maintained PAM build and tests compile through world buildenv. Eighteen
selected native cases passed against the rebuilt libpam and pam_unix: seven
module-resolution cases, nine include-policy cases, password hashes and account
resolver behavior. They use disposable policies and process-local account/
resolver fixtures; no host account or PAM configuration was modified. These are
component checks, not integrated login/su/SSH qualification. Receipts, build log,
full test output and tested artifact hashes are under
/usr/obj/usr/src/bip-removal-20261024-pam.

Build frontend integration review: normal world/package backends pick up the
PAM source, manual and policy removals through maintained Makefiles. Remaining
BIP generation/VM assemblers still reference obsolete policy inputs and require
separate removal; they are not an active qualified image-build path.

### Login-class API cleanup

Removed cgetentfd and login_getclassfd, introduced for the now-removed protected
PAM backend and left without production callers. Removed their declarations,
symbol exports, manual entries and descriptor-only tests. Retained cgetusedb,
which cap_mkdb uses to avoid consuming an old compiled database during rebuild,
and retained capability-name overflow checks and login capability allocation
fixes. The allocation tests now exercise ordinary login_getcaplist directly,
without requiring the removed descriptor APIs.

libutil and its tests build; the changed libc getcap object/PIC object and
cap_mkdb build successfully through world buildenv. Three native allocation
cases pass: ordinary list decoding, copy-allocation failure and array-allocation
failure. Logs and preimages are under
/usr/obj/usr/src/bip-removal-20261024-login-api. This is component evidence,
not complete world, boot or login qualification. Build frontend integration uses
the existing maintained world/package targets; their sources, exported APIs,
manuals and test rules were updated together.

### Account layout cleanup

Removed the BIP-layout implicit /etc/accounts redirection, pw_defaultdir helper
and exported API. Default password/group updates again use the conventional
/etc paths; explicit alternate directories retain their established semantics.
Removed the BIP account-layout fixture. Updated libutil, pwd_mkdb, their manuals,
exports and construction-tool source lists together.

Retained pwd_mkdb fixes that consult the selected destination database for
single-user/duplicate-UID updates and check input permission changes. libutil
and pwd_mkdb compile. All five native alternate-directory cases pass against the
rebuilt tool: updates, duplicate UIDs, malformed-update preservation, metadata,
and explicit directory aliases. Tests touched temporary account databases only.
Evidence and preimages: /usr/obj/usr/src/bip-removal-20261024-account-layout.
The maintained build frontend continues to reach these via world/package rules;
legacy BIP generation layout/fixtures remain pending removal and must not be
used to claim a working normal installed system.

### ZFS mount admission cleanup

Reviewed the remaining VFS hooks against actual policy consumers. File-handle
traversal admission is used by mac_capability_isolation and is retained. Removed
the BIP-only mac_mount_check_zfs hook, its policy ABI slot and ZFS mount caller;
no active policy consumed it. ZFS mounts no longer collect ancestry or hold the
additional pool configuration lock for that callback. Other ZFS handle-policy
interfaces remain pending dependency review.

Regenerated MAC tracing metadata from the policy ABI (351 hook contracts);
the generator's consistency check passes. mac_vfs, mac_capability_isolation and
the restored zfs_vfsops objects compile against the maintained GENERIC object
tree. No modules were installed or loaded. Logs/preimages are under
/usr/obj/usr/src/bip-removal-20261024-zfs-mount. This proves compilation and
metadata consistency, not runtime correctness or a measured performance gain.
The frontend's conventional kernel/module backends use the updated sources;
no new build input is required. Disk I/O and memory regression qualification
remain required. The older persistent-state design is explicitly historical.

### ZFS topology cleanup

Removed BIP-only rename/promotion lineage admission and dataset-destruction
notification. Neither hook had an active policy consumer after BIP removal.
Deleted the before/after ancestry allocation helper, callback declarations,
policy slots and DSL callers. Retained capability count-limit enforcement and
the receive-stream adapter; these serve independent capability operations.

The affected mac_system and ZFS dsl_dataset/dsl_destroy/dsl_dir/zfs_handle objects
compile against GENERIC. Tracing metadata was regenerated (349 hook contracts).
Preimages/build logs: /usr/obj/usr/src/bip-removal-20261024-zfs-topology.
No kernel or module was installed. Removal eliminates these specific BIP code
paths; runtime and performance effects are not yet measured. Remaining handle
classification, issuer and ancestry checks still require dependency review.
Normal build frontend kernel/module targets use these maintained sources; no
new frontend configuration input was introduced.

### ZFS handle dispatch cleanup

Removed the generic BIP pre-dispatch handle admission and its shared-to-exclusive
ancestry retry. Removed the unused BIP property-value admission callback and
associated ABI/data declarations. The normal handle rights checks, mutating-
operation namespace serialization and native ZFS property validation pipeline
remain. Per-object BIP admission and issuer/classification paths still require
removal; no claim is made that all handle overhead has been eliminated.

mac_system and zfs_handle objects compile against GENERIC. MAC tracing metadata
was regenerated for 348 hook contracts. Logs/preimages are under
/usr/obj/usr/src/bip-removal-20261024-dispatch. No kernel/module was installed,
and no runtime or performance result is claimed. Maintained kernel/module build
backends consume these changes without additional frontend options.

### ZFS operand admission cleanup

Removed the remaining BIP per-operand check calls and the check/resolved/parent/
identity helpers used only by those calls, plus the associated MAC callback ABI.
This removes the redundant ancestry collection for child publication, clone,
rename, destruction, send, receive and rollback admission. Existing capability
rights, ordinary snapshot/send/receive/destroy MAC hooks, and receive-stream
identity pinning/revalidation remain. Ancestry routines still used by BIP issuer
interfaces remain until those interfaces are removed; this is not complete
storage cleanup.

mac_system and zfs_handle objects compile. Regenerated tracing metadata passes
consistency checking at 347 hook contracts. Receipts/preimages and build logs:
/usr/obj/usr/src/bip-removal-20261024-per-object. No runtime, race or performance
qualification is claimed from compilation. The maintained kernel/module targets
used by the frontend consume the updated ABI and source together; there are no
new build options. BIP classification and grant factories remain outstanding.

### BIP kernel factory removal

Removed the BIP reserve/ordinary-classification and data/management grant
factories from ZFS handle dispatch, along with the MAC factory callbacks and
ancestry capture/free helpers. No enforcing provider remained. Legacy BIP ioctl
requests now reach the normal unsupported-operation path; no stub reports
success. Userspace ABI declarations/wrappers and service callers remain pending
removal and do not constitute supported interfaces.

mac_system, mac_capability_isolation and zfs_handle objects compile against
GENERIC. Tracing metadata regenerates and checks at 339 hook contracts. No BIP
factory/admission identifiers remain in the ZFS handle implementation or MAC
framework implementation reviewed here. This is source/compile evidence, not a
whole-kernel boot or runtime test. Receipts/logs are under
/usr/obj/usr/src/bip-removal-20261024-factories. Maintained frontend kernel/module
backends consume the source/ABI updates; no new configuration input is needed.
Next storage cleanup covers userspace wrappers, shared headers and Capsule/
SwitchBoard/BSDFilesystem policy consumers before normal-system qualification.

### BIP account snapshot removal

Removed SwitchBoard's separate immutable account database, runtime reader and
snapshot compiler. Service credentials, supplementary groups, default service
identity validation and UNIX socket ownership now use the retained NSS backend.
The independent NSS helper and error checks remain. Removed the build-bsd
`--service-identities` option, its manual entry and compiler tests; the fixture
assembler no longer installs or requires that snapshot. Snapshot-only native
and construction tests were retired, not counted as passing tests.

SwitchBoard (including test programs) and build-bsd compile through the maintained
buildenv targets. Twelve native account-NSS and activation tests passed, including
socket listening, restart preservation and conflicting addresses; fifteen assembler
tests passed. These are host mechanism tests, not normal-system or VM qualification.
Preimages/change hashes and build logs are in
/usr/obj/usr/src/bip-removal-20261024-identities.

BIP removal remains incomplete. Storage classification/grant consumers in Capsule,
SwitchBoard and BSDFilesystem, their shared ABI, and the old BIP VM runner/evidence
cases remain pending. In particular the old capsule-identities-* rejection cases
no longer describe supported behavior and must be removed before reusing the suite.
No complete Secure Boot, veriexec, performance or installed-system claim follows
from these removal checks. The prior archive is historical; BIP is dropped.

### BIP identity fixture and Capsule endpoint retirement

Removed the obsolete capsule-identities-* VM cases, fixture policies, and their
identity-rejection evidence rules. The ordinary runner and evidence unit suites
pass (37 and 21 cases). This does not qualify current firmware or a booted system;
other BIP fixture dependencies still prevent treating that suite as an acceptance
gate. The retired cases are not passing cases. Preimages are under
/usr/obj/usr/src/bip-removal-20261024-identity-vms.

Capsule no longer dispatches the BIP storage-management, storage-data or immutable
storage-policy requests. They reach the existing ENOTSUP protocol response.
The shared boot-request validator also rejects those retired operations. Ordinary
BOOT_STORAGE and BOOT_CRYPTO delegation retain their existing validation, rights
and lifecycle. Capsule and its tests compile; all four request-validation cases
pass, including explicit retired-operation rejection. Preimages and build log:
/usr/obj/usr/src/bip-removal-20261024-capsule-endpoints.

Automatic approval review rejected a broader storage/configuration rewrite because
it could remove ordinary capability behavior along with BIP; that rewrite did not
run. The smaller endpoint removal was approved. Configuration parsing, storage
preparation and ordinary handles were not changed by it. BIP storage producers,
consumer wrappers, shared ABI and configuration are still pending removal. The
build frontend's maintained backend compiles these protocol changes directly; no
new build input is introduced. Existing BIP-dependent state/image/VM workflows
remain unqualified and require separation, not a successful-status substitute.

### Unused BIP handoff and personal namespace removal

Deleted the three now-unreachable Capsule handoff functions for BIP management
issuers, data scopes and immutable provider policy, with their declarations and
obsolete test calls. Reviewed the exact diff: only those three function bodies
(49 lines), their comments and references were removed. Ordinary acquisition,
handle derivation and storage preparation remain intact; preparation still has
BIP dependencies pending removal. Capsule and its maintained tests compile;
no_ambient_anchor and import_admission pass. No scratch-pool test was run.
Preimages/hashes/build log: /usr/obj/usr/src/bip-removal-20261024-storage-entrypoints.

Removed SwitchBoard's BIP-only personal-namespace selection by authority/session
identity. It now consistently retains the ordinary path: the kernel-observed
sender UID selects a personal namespace, and missing sender metadata selects none.
The existing personal_namespace_uses_sender test passes, including conflicting
legacy domain UID, another user, UID zero and absent sender cases. SwitchBoard
and its tests compile. The host lacks the required libservice ABI; this test was
run with explicitly selected build-tree libservice, libchannel, libcapsulert,
libcapability, libcapbundle and libsys. It is broker unit coverage with the existing
channel test doubles, not live-kernel authentication or a packaged-system test.
Preimages/hashes/build log: /usr/obj/usr/src/bip-removal-20261024-personal-uid.

The frontend/backends were checked: these changes introduce no new build inputs;
the maintained component targets build the changed sources and tests. BIP removal
is still incomplete, particularly storage preparation/configuration, broker and
provider grants, shared ABI and BIP-specific build/VM paths. Secure Boot, veriexec,
full system startup and performance remain independently unqualified for the
current source state. No installation, reboot or VM run occurred in this step.

### BIP broker branch removal

Removed BIP-specific session-role gates, session-derived control UID selection,
invocation binding for ordinary non-sendable endpoints, and the BIP-only provider
ADMIN suppression from SwitchBoard naming/control paths. The retained ordinary
rights/attribute checks, UID checks, software-authority binding and provider ADMIN
expressions match HEAD. Existing session validity checks and Core management
restrictions remain. Current production startup zero-initializes sd and has no
integrity_enforcing setter; this removes inactive alternate BIP behavior rather
than adding a new ordinary authorization path.

Approval review initially refused the patch pending evidence of ordinary security
preservation. After inspection of initialization, all flag references and HEAD,
the reviewed patch was approved with assertions against the baseline. Source hashes
prevented overwriting concurrent edits. SwitchBoard and its maintained test programs
compile. Results: anoint_test 34 passed/4 failed, sctl_gate_test 6 passed,
management_enforce_test 13 passed. The four real-channel failures terminate with
SIGSYS; tracing one identifies syscall 1002 (cap_clofork_limit) returning ENOSYS on
the running October 7 kernel. They are not skipped or counted as passing. These
cases require a matching-current-source kernel/VM. The passing tests do not prove
the full live control protocol or kernel authorization.

Preimages, build log, all test results, failure trace and tested binary/library
hashes are under /usr/obj/usr/src/bip-removal-20261024-broker-branches. Tests selected
build-tree libraries explicitly; no host libraries were installed. The build
frontend uses the maintained component targets; no build inputs changed. Remaining
BIP storage/session consumers and build/VM coupling are still pending removal;
this is not overall qualification or completion.

### Matching-kernel build and unused helper cleanup

Started the maintained build-bsd kernel action with GENERIC, 16 logical CPUs and
/usr/obj. Plan inspection confirmed ordinary bsd-make buildkernel and no BIP
kernel profile. The generated GENERIC options contain no MAC_SYSTEM_INTEGRITY;
veriexec/CAPIMAGE options remain in the source configuration. Build run:
/usr/obj/usr/src/build-runs/20261024T054519Z-4402. At this update the build is still
running through kernel modules; this is not a successful-build or VM-boot claim.
No host installation, reboot, firmware change or VM launch was performed.

Removed unused session_permits/session_uid helpers after confirming no callers
remain in the source tree. In Capsule, folded the sole proto_reply wrapper into
its implementation and removed the unused BIP forwardable-policy argument. Every
remaining reply still applies CAP_XFER_ONCE to attached authority descriptors;
no transfer restriction was weakened. Capsule and SwitchBoard, including their
maintained test programs, compile. Preimages/hashes/build logs:
/usr/obj/usr/src/bip-removal-20261024-unused-helpers. No additional runtime test
claim is made for this dead-code cleanup. The frontend needs no new inputs:
current kernel compilation uses build-bsd itself, and the normal component
backend targets consume the helper changes.

The next matching-kernel VM work must use explicit current artifacts and 2 GiB
RAM, distinguish disk-backed mechanism fixtures from full packaged-system tests,
and rerun the four real-channel cases previously failing with SIGSYS. Existing
BIP-dependent image/VM paths still need separation before any overall acceptance
claim. All broader BSDFoundry, upgrade, Secure Boot, veriexec, Bazel and performance
qualification requirements remain open as recorded above.

### Current GENERIC build and real-channel VM result

The maintained build-bsd kernel run 20261024T054519Z-4402 completed successfully:
GENERIC plus modules, 16 logical CPUs, 218 seconds. No BIP kernel option was
configured; veriexec/CAPIMAGE remain configured but enforcement is not established
by this build. Kernel SHA256:
785a65a10d230a47a868d5619d1fa8765253e9593ad2e1abfc57e0334a033003.

Rebuilt private static runtime, libservice API, filesystem namespace and
SwitchBoard tests through source buildenv targets under
/usr/obj/usr/src/security-qualification/bip-removal-channel-fixtures-20261024.
The filesystem binary's direct target initially omitted FIDL generation in the
fresh object tree; the maintained all target generated bindings and built the
suite successfully. No generated headers or tests were fabricated. A first VM
preflight refused a missing boot/defaults/loader.conf accidentally excluded by
the staging copy filter; restoring the explicit input resolved it before QEMU
started. Both failed attempts remain in the build/progress record.

One disk-backed QEMU VM with 2048 MiB RAM, two vCPUs, a 512 MiB fixture root and
no networking passed the four previously host-failing real-channel tests:
minted_channel_carries_set, session_reach_over_minted_channel,
registered_private_channel_keeps_set, lookup_helper_names_over_minted_channel.
The runner's prerequisite daemon/filesystem checks also completed. The result
is PASS, QEMU exit 0, forced_termination false. Kernel/staged-kernel matching,
test hashes and requested cases are recorded by the maintained runner. Evidence:
/usr/obj/usr/src/security-qualification/bip-removal-channel-vm-20261024/result.json
and serial.log. Explicit boot-support provenance and additional input/QEMU hashes
are in the sibling fixture directory. The old boot-support files were reused;
this was not a newly built or accepted complete world.

This resolves those four broker/channel tests on a matching kernel. The PID 1
fixture is not normal Capsule startup, has no network and does not demonstrate
Secure Boot enforcement, SSH, full package compatibility, upgrades or performance
acceptance. The 2 GiB limit and disk-backed root are observed configuration, not
measured memory or I/O regression results. No host installation or reboot occurred.
BIP cleanup and the broader goal remain incomplete. Build frontend integration
was exercised directly by the kernel action; test compilation used maintained
backend targets without adding alternate system-build paths.

### Retired immutable provider-policy file handling

Removed Capsule's storage.policy member/parser input and the unreachable immutable
provider-policy reader, descriptor array and associated cleanup. The handoff had
already been removed. Old storage.policy keys now fail strict configuration
validation; they are not silently ignored or converted into ordinary files.
Ordinary storage handles, rights, imports, attachments and the remaining grant
preparation were not changed in this step. The other BIP preparation paths still
require removal; this is not a functional protected-storage implementation.

Capsule and its maintained tests compile. Nine selected native configuration
cases pass, including retired-key rejection with atomic preservation, ordinary
storage inputs/conflicts, dynamic allocation/lifetime, allocation failure,
descriptor input and malformed/external-input handling. Eleven maintained
configuration-composition tests pass. Preimages, build log, native results and
binary hashes: /usr/obj/usr/src/bip-removal-20261024-policy-files.

Frontend integration was checked: build-bsd passes the explicit Capsule validator
and its hash to the maintained image/configuration helpers. The current validator
therefore rejects retired keys; generic composition still reports that output
requires service validation. No new option or alternate builder is introduced.
The Capsule manual no longer advertises storage.policy. The legacy BIP
storage-attachment-failure fixture in tools/test/secureboot/storage/storage_init.c
still references the removed member and must be retired with that obsolete case;
the BIP suite remains unbuildable/unqualified pending its broader separation.
Do not bypass validation or substitute an old validator to make those cases pass.
No VM or system-acceptance claim is made for this change.

### Retired BIP policy-open failure fixture

Removed storage-attachment-failure from the secureboot runner's case choices,
staging/dispatch and evidence predicates. Deleted its C fixture function and
obsolete harness tests; the function depended on the already-removed
storage.policy field and BIP reservation enforcement. This is retired coverage,
not a pass. The secureboot C sources no longer reference that deleted member.
The fixture README now identifies the historical case as retired and keeps
ordinary import/mount cleanup qualification outstanding.

The remaining runner/evidence unit suites pass: 36 and 20 cases respectively.
These tests validate host harness logic only; they do not establish that the
remaining BIP fixture suite builds or boots. Other BIP dependencies remain.
Preimages and change hashes: /usr/obj/usr/src/bip-removal-20261024-attachment-case.
Frontend integration was checked: build-bsd forwards the explicit --test-case
input to the maintained runner; that runner now rejects the retired name through
its supported-case choices. No alternate path or success stub was added. No VM,
host installation, firmware change or reboot occurred in this step.

### Capsule BIP grant producer removal

Removed Capsule's management/data storage ceilings, their parser structures and
helper parsers, issuer/data-scope factories, reservation entry points and bootstrap
grant validation. The previously removed handoff endpoints had no remaining
production consumers for these factories. The strict configuration parser now
rejects storage.management and storage.data, including formerly valid complete
objects. The existing retired-key test also verifies that rejection preserves the
active configuration. Removed tests of retired grant semantics are not passes.

Ordinary ZFS acquisition/derivation, native rights, import checks and descriptor
transfer/fork/exec limits remain. Bootstrap now always applies native ioctl limits
to retained ordinary handles; the special BIP-only ioctl list is gone. Existing
mount classification/attachment behavior remains pending separate removal. No
compromised-root protection is claimed for it. Config/header no longer depend on
MAC_SYSTEM_INTEGRITY declarations. The remaining Capsule BIP ioctl calls are the
ordinary/reserved classification pair in the mount path.

Capsule and maintained test programs compile. Seventeen native cases pass:
retired policy-key rejection, storage inputs/conflicts and memory lifetime,
allocation failure, parser atomicity/external/descriptor handling, existing
attachment/classification parser cases, host identity, crypto boot policy,
no-ambient acquisition and import admission. These are parser/helper checks,
not live mount or grant qualification. Eleven configuration-composition cases
pass. Preimages, hashes, build log and native results:
/usr/obj/usr/src/bip-removal-20261024-grant-producers.

Updated capsule.conf(5) to remove retired field documentation. The maintained
build-bsd image/configuration paths select the Capsule validator explicitly;
they consume its new schema through that backend, with no new frontend option.
Generic configuration composition does not grant authority or bypass native
validation. Historical BIP image inputs using retired fields must be removed,
not silently translated. Broker/provider BIP consumers, shared ABI, remaining
mount handling and old qualification paths are still pending. The broader
BSDFoundry/Secure Boot/veriexec/Bazel/upgrade/performance goal remains incomplete.

### BIP removal: mount consumer audit (2026-10-24)

BIP is dropped from the requested implementation, not scheduled for resumption.
The archive is historical evidence only. Removal is not yet complete.

The remaining Capsule attachment/content removal is prepared but unapplied.
Automatic approval review rejected applying it independently because
`generation_image.py` and the maintained `build-bsd image --storage-bindings`
path still consume the attachment schema. These are active consumers, not just
historical descriptions. Remove that BIP binding path and its obsolete tests
in coordination with Capsule; retain independent package inventory, ordinary
image construction, configuration composition and Secure Boot mechanisms.
Do not silently translate old BIP configuration into an unprotected equivalent.

The unapplied candidate preserves `protected_storage_acquire` verbatim and
retains native ZFS identity/rights checks and anchor descriptor restrictions.
An isolated Capsule executable build against the existing world sysroot passed;
this does not qualify runtime behavior. The initial isolated all-target builds
failed on object-root resolution and test loader-defaults setup, respectively.
The test suite has not passed for this candidate. Candidate and hashes are in
`/tmp/bip-mount-removal`; build logs are
`/tmp/bip-mount-candidate-build.log` and
`/tmp/bip-mount-candidate-program-build.log`. No source implementation change
from this candidate was applied and no VM or host installation was performed.

Next dependency order: retire BIP image binding entry points, remove Capsule
mount classification, remove broker/provider grant consumers and their shared
ABI, then retire remaining BIP fixtures and stale documentation. Rebuild and
qualify ordinary functionality at each boundary. Secure Boot and veriexec
remain separate work and must not be described as protection from compromised
root merely because signing succeeds.

### BIP removal: Capsule mounts and image bindings removed (2026-10-24)

Supersedes the unapplied status in the preceding audit. Coordinated removal
passed approval after the active image consumers were removed together.
Capsule no longer classifies or attaches datasets for BIP. The attachment and
content keys are rejected alongside the previously retired grant/policy keys.
Ordinary acquisition retains the existing pool/dataset identity checks, rights
limits and retained-anchor descriptor restrictions. Named mounts belong to
ordinary system startup.

The maintained build-bsd frontend no longer accepts --storage-bindings. The image
backend no longer consumes BIP attachment receipts, validates BIP manager
placement, or invokes Capsule for BIP image policy. Format-3 BIP layouts are
explicitly rejected before image creation rather than treated as ordinary
layouts. Configuration composition retains its independent native validator.
Old binding-specific construction fixture calls and tests were removed;
remaining legacy BIP qualification runners and layout schemas still require
retirement. This is not complete BIP removal.

Capsule and build-bsd all-target builds passed in the standard object tree.
Thirteen native Capsule cases passed: retired-key rejection, storage inputs and
conflicts, allocation and lifetime, parser atomicity/input handling, host identity,
crypto boot policy, no-ambient acquisition and import admission. The image plan
ATF case passed, including rejection of the removed option. Forty image helper
tests passed through the maintained ATF wrapper. Configuration composition tests
passed through its wrapper. Initial wrapper attempts selected nonexistent
object-tree or source-tree test locations; the final run supplies the actual
maintained helper/test paths explicitly. These are native checks, not installed
startup, filesystem mount, Secure Boot, upgrade or performance qualification.
No VM or host installation was performed in this step.

Preimages, changed-file hashes, build logs and per-case native results:
/usr/obj/usr/src/bip-removal-20261024-mounts.
Next remove broker/provider BIP grant consumers and their shared ABI; then finish
retiring obsolete image/layout/security fixtures and current documentation.

### BIP removal: broker storage authority removed (2026-10-24)

Removed SwitchBoard's BIP storage management, policy, data and worker-prepare
request handlers, BIP client associations, grant factories, worker/claim state
and their event/revocation bookkeeping. Removed corresponding declarations and
record fields. Requests without descriptors now follow the ordinary unsupported
operation response; unsolicited descriptors are rejected by the common request
validator. No replacement grants or fallback issuer were introduced.

Ordinary authority issuance, resolution, channel binding and revocation remain.
Client notifications retain their existing zero initialization; the retired
storage association identifier is no longer assigned. The internal naming helper
no longer takes the request parameter used solely for BIP associations; observed
sender information still comes from the channel message. The BIP worker cleanup
tests were retired while preserving the two independent authority-registry tests
for failed revocation and exact launch selection. These tests use an explicit
syscall double and actual owned descriptors, not live kernel grant enforcement.

SwitchBoard and tests build successfully. The first build identified the unused
naming parameter, corrected before the successful rebuild. Twenty-one native
cases pass: two registry revocation, six sctl gates, and thirteen management
checks. These do not prove live daemon protocol or kernel behavior. No VM ran.
Preimages, hashes, build logs and results:
/usr/obj/usr/src/bip-removal-20261024-broker-storage.

Frontend integration review: this step changes internal broker endpoints, with
no new build inputs, packaging or signing requirements. build-bsd already builds
this component through its maintained world/stage backend. The legacy BIP
secureboot-test and provider fixtures remain unqualified and need retirement;
shared protocol definitions/client helpers are retained temporarily until the
remaining BSDFilesystem consumers are removed. Session BIP policy, provider
code, shared ABI and obsolete documentation still require cleanup. BIP removal
and the broader goal are incomplete.

### BIP removal: filesystem-provider startup (2026-10-24)

Removed BSDFilesystem's BIP sysctl query and policy/management/data grant startup
requests. Ordinary startup retains delivered-directory configuration access,
explicit configuration ownership/mode checks, bounded regular-file parsing,
existing imported-pool acquisition, and closure of the acquisition descriptors
before serving. Missing default configuration still permits defaults; malformed
or unreadable supplied configuration remains fatal. Existing isolated-path-only
operation without a pool is preserved. No new acquisition fallback was added.

Removed the immutable-policy loader API from libcapsulert and retained its
ordinary descriptor loader implementation. Retired its dedicated native and
BIP VM tests, source files, build list, runner source inventory and completion
markers. The remaining legacy secureboot suite is still BIP-dependent and is
not qualified. No weaker replacement test or success marker was added.

libcapsulert and BSDFilesystem all-target builds pass. The configuration test
was explicitly relinked against the rebuilt object-tree libcapsulert to avoid
using an old staged static library. Seven native configuration cases pass,
including descriptor ownership/size handling, atomic parsing, no external
expansion and the actual packaged default policy. The installation-policy case
skips because no separate installation-policy/expected-layout input was selected;
that case is not qualification evidence. The initial temporary ATF source setup
lacked a test-program entry and was corrected by linking the rebuilt executable
alongside the exact packaged policy input. Thirty-six runner tests pass.
No VM or host installation was performed.

Frontend/backend review: no new build input or command was introduced. The
maintained Secure Boot backend source list and fixture wiring were updated with
the removed helper. Normal world/package paths compile the changed provider and
library. Evidence and preimages:
/usr/obj/usr/src/bip-removal-20261024-provider-startup.

Remaining provider work includes BIP request/claim controls, worker admission,
policy access declarations and their tests; these were not enabled or broadened
by this startup removal. Shared protocol definitions, session policy, other old
fixtures and stale documentation still require removal. BIP removal and the
broader BSDFoundry/Secure Boot/veriexec/Bazel goal remain incomplete.

### BIP removal: filesystem requests and workers (2026-10-24)

Removed BSDFilesystem BIP claim-control identifiers, ceilings, broker nomination
and worker-attachment paths, plus the integrity-mode state. Ordinary mount
anchors, close/replacement ordering, request rights, quotas, selected-view lookup
restrictions, worker protection and openES dispatch remain. Retired BIP-only
claim-lifetime and missing-selection tests; retained ordinary namespace and
sender-attribution cases. The initial build found an accidentally truncated
anchor signature; it was corrected before the successful complete provider/test
build. This is a removal, not a new protected-storage design.

Native tests: 47 pass, worker_shutdown fails on the host kernel's unsupported
PD_NOWAITPID flag, descriptor-hardening skips for absent host syscalls, and the
real OES device case skips for unavailable privileged device access. These host
limitations are recorded, not counted as passes. A single matching-kernel QEMU
run then passed worker_shutdown and delivery_hardening_failure, plus three
libservice mechanism cases. It used 2048 MiB RAM, two vCPUs and a disk-backed
512 MiB root, exited zero, and shut down without forced termination. The first
VM preflight failed before launch because copied fixture modes were not
executable; copying the original modes fixed staging. Input hashes and both
attempts are retained. The boot support and runtime-init/libservice fixtures
were explicitly reused from the earlier qualification input; filesystem tests
are freshly built. This is not full-world startup or performance qualification.

Evidence: /usr/obj/usr/src/bip-removal-20261024-provider-requests and
/usr/obj/usr/src/security-qualification/bip-provider-requests-vm-20261024-retry1.
The real openES device case remains unqualified. No host installation occurred.

Frontend review: ordinary component builds and the maintained daemon-runtime VM
runner suffice for this internal removal; no new build-bsd input or backend is
needed. BIP policy declarations, client APIs/shared ABI, session policy and
remaining fixtures/documentation still need removal. The broader goal remains
incomplete.

### BIP removal: obsolete storage client APIs (2026-10-24)

Removed libservice's BIP storage management/policy/data, worker admission and
claim-control client functions and public declarations. Removed their dedicated
storage_claim_test and manual links. Removed unused SwitchBoard Capsule clients
for BIP management, data and immutable policy. The remaining old secureboot
storage-client fixture no longer invokes these APIs or reports their retired
denial check; the corresponding observer field and runner assertion are removed.
This does not qualify that still-BIP-dependent fixture for current use.

libservice and SwitchBoard all-target builds pass. Thirty-five runner tests pass.
The existing static libservice argument-validation case passes, a narrow check
rather than proof of daemon behavior or current-library runtime integration.
Symbol inspection confirms removed BIP APIs are absent from the rebuilt
libservice archive; ordinary service_capability_open remains. Ordinary
service_storage_open and related operations are in libfilesystemcmp, untouched
by this removal. A source search finds no remaining C callers of the removed
functions in lib, usr.sbin or tools. No VM or host installation occurred.

Preimages, hashes and build/test evidence:
/usr/obj/usr/src/bip-removal-20261024-clients.
Frontend review: no new input, signing or package requirement. The maintained
world/package backend builds these libraries and broker; removed manpage links
and test build entries were updated in the same change. BIP wire definitions,
kernel-facing ABI, unused policy declarations/session issuance and remaining
obsolete fixtures/documentation still need removal. Goal remains incomplete.

### BIP removal: unused storage policy declarations (2026-10-24)

Removed the unused BIP filesystem access-ceiling model, parser, matcher and
storage-data action parser. The obsolete `access` key now rejects, including an
empty array, and rejection leaves prior configuration intact. Removed the unused
broker namespace-issuer helper and its dedicated test. Ordinary open-path,
layout, quota and namespace policy remains. The packaged BSDFilesystem default
contains no retired access key. The manual describes rejection explicitly.

libcapsulert and SwitchBoard builds pass. BSDFilesystem and tests pass a forced
rebuild with normal flags. Early verification commands overriding LDFLAGS dropped
required static/test flags and were invalid verification setups; those logs are
retained. The rebuilt library was then staged into the standard isolated
/usr/obj/usr/src/amd64.amd64/tmp sysroot. Ownership-changing install failed without
root; explicit install -U with NO_ROOT completed unprivileged staging. No host
installation or home-directory build relocation occurred. The subsequent normal
rebuild restored static tests and uses the current library/policy structure.

Seven configuration tests pass, including retired-access rejection, parser
atomicity, input/descriptor checks and packaged default loading. The separate
installation-policy case skips without selected policy/layout inputs. Of fifty
namespace/quota cases, forty-seven pass; worker_shutdown fails on this host's
unsupported PD_NOWAITPID, and OES device/hardening cases skip for host capability
limitations. Prior matching-kernel VM evidence applies to the preceding source
state; no new VM qualification is claimed here. The initial candidate preparation
and stale temporary-manifest application both stopped at assertions without
source writes; a uniquely staged, checked candidate was subsequently applied.

Evidence and preimages:
/usr/obj/usr/src/bip-removal-20261024-storage-policy.
Frontend integration: no new build option or staging policy was introduced;
normal world/package builds consume the updated library and provider. The
removed helper's test build entry and current manual were updated together.
Remaining BIP cleanup includes shared protocol/kernel interfaces, session code,
old image policy/fixtures and stale docs. Full goal remains incomplete.

### BIP removal: session issuance and installed policy (2026-10-24)

Removed SwitchBoard's BIP session-policy loader, session issuer and authenticated
route constructor, along with the SESSION_CREATE request handler. Requests now
reach the existing unsupported-operation response. Removed the packaged empty
session-policy.ucl, its install-list entry and obsolete management-right macros.
The obsolete integrity_enforcing state field is gone. Ordinary channel sessions
created through service_session_create and the domain session-channel constructor
are unchanged; they are not BIP user-session issuance.

SwitchBoard and native tests build successfully. Twenty-one revocation/sctl/
management cases pass. These are helper tests, not full login/PAM or live broker
protocol qualification. No VM or host installation was performed. Preimages,
hashes, build log and results:
/usr/obj/usr/src/bip-removal-20261024-session-issuance.

The remaining session-record validation/cleanup plumbing has no issuance path
and must still be removed with its references. The legacy libservice user-session
client and BIP fixture policies are also pending retirement. Do not interpret
those fixtures or build-bsd's old session-policy test input as functioning human
authentication qualification. Frontend integration for ordinary builds uses the
maintained world/package backend; the package install list and manual were
updated together. Legacy secureboot fixture/options need a coordinated cleanup,
not a replacement authentication workaround. Goal remains incomplete.

### BIP removal: broker session records (2026-10-24)

Removed unreachable BIP session records, expiry/revocation hooks, route IDs,
channel lease binding and issuer-liveness helper/test. Updated internal control
and on-demand signatures and their callers. Ordinary service channel sessions
remain. No-principal notification state retains a zero kind and UINT32_MAX UID.
Software-authority resolution, UID matching and live owner checks remain.

Automatic approval initially rejected the broad routing edit. No source change
was applied then. The exact diff was reviewed; isolated candidate compilation
found and prompted removal of an argument used only to copy the BIP route ID.
The isolated build subsequently passed. Exact body comparisons confirmed
ordinary domain minting (three constructors), authority issuance/binding
(three functions) and on-demand launch unchanged. This evidence supported the
subsequently approved coordinated edit. Seventeen files changed or retired,
with hash-checked preimages retained.

The maintained SwitchBoard all-target build passes. Fifty-five native tests
pass: thirty-four attribute/discovery cases plus twenty-one revocation/control/
management cases. Four real-channel cases were excluded from host execution
because this host lacks the required kernel support, then all four passed with
the matching kernel in QEMU: minted_channel_carries_set,
session_reach_over_minted_channel, registered_private_channel_keeps_set and
lookup_helper_names_over_minted_channel. The runner's three service checks and
descriptor-hardening baseline also passed. VM result PASS, exit zero, clean
shutdown, no forced termination. Configuration: 2048 MiB RAM, two vCPUs,
disk-backed 512 MiB root. No host installation occurred.

The broker test executable was newly built static from the changed source.
Boot support, runtime-init, libservice and filesystem baseline fixtures were
explicitly reused and hashed. This is mechanism coverage, not a current full
world, production daemon startup, Secure Boot, upgrade or performance result.
Evidence: /usr/obj/usr/src/bip-removal-20261024-session-records and
/usr/obj/usr/src/security-qualification/bip-session-records-vm-20261024.

Frontend integration: no new build input; maintained component/test source lists
were updated. The remaining legacy BIP client/wire interfaces and fixture paths
still need retirement before the build-bsd security qualification workflow can
be called current. Broader goal remains incomplete.

### BIP removal: retired storage wire layouts (2026-10-24)

Removed unused BIP storage-management, data, worker and claim request layouts
from switchboard_svc_proto.h and retired Capsule BIP grant opcode names. Their
numeric ranges remain explicitly reserved (service 17–25, Capsule 31–33), so no
existing number is reassigned. Ordinary message layouts and opcode numbers are
unchanged. Capsule's validator tests use the retired numeric values directly to
prove they are rejected after the names disappear. The BIP session request is
still marked retired pending removal of remaining legacy client fixtures.

Capsule, SwitchBoard and libservice all-target builds pass. Four request-validator
cases pass, including retired-op rejection, strict wire shapes and current
Bluetooth/network/service requests. No VM or host installation was performed.
Preimages, hashes, logs and results:
/usr/obj/usr/src/bip-removal-20261024-wire.

A current C-source search finds the remaining BIP storage ioctls only in
sys/sys/zfshandle.h, the retired integrity ABI header, and four files in the old
secureboot/storage fixture. Remove those fixture consumers and their build/
runner wiring with the remaining ioctl ABI. Other BIP session, image-policy and
fixture cleanup remains. Frontend review: no build input changed; the maintained
world/package backend builds the shared headers and consumers, and validator
coverage was updated in the same change. Goal remains incomplete.


### BIP removal: obsolete native harnesses (2026-10-24)

BIP is dropped, not deferred for implementation under the active goal. Removed
five native source-extraction harnesses and their Make targets: attachment
execution policy, ancestry capture, classification locking, promotion admission,
and Capsule storage preparation. Their production entry points have already
been removed; retaining the harnesses would advertise nonexistent coverage.
Removed their obsolete README descriptions and marked the remaining combined
BIP/Secure Boot harness documentation as historical and unqualified.

The independent receive revalidation, property binding, boot-environment and
firmware tests remain. No frontend option invoked these five targets; the
maintained backend Makefile is updated in the same change. Remaining BIP VM
fixtures, ABI declarations, session clients and qualification options still
require coordinated removal. This is not completion or renewed Secure Boot
qualification. Preimages and hashes are in
/usr/obj/usr/src/bip-removal-20261024-obsolete-harnesses.

Verification for this removal: receive revalidation (one case), EFI staging
(one case), and boot-environment destruction cleanup (two cases) pass. The
retained Make targets resolve in a dry run. No VM was run; these native checks
do not qualify firmware boot, real ZFS concurrency, or whole-system upgrades.


### BIP removal: frontend qualification options (2026-10-24)

Removed the ten legacy BIP storage/session/provider qualification inputs from
build-bsd, their validation, forwarding and conditional I/O-fixture build step.
Updated the manual and retired their successful-plan assertions. A replacement
negative test checks that every removed option is rejected as unknown; it does
not claim runtime security coverage. The ordinary Secure Boot signing, loader,
firmware and explicit-case inputs are retained. The legacy runner/assembler
still requires coordinated cleanup and end-to-end requalification. Preimages
and hashes: /usr/obj/usr/src/bip-removal-20261024-frontend-options.

Frontend build passes. Four native ATF cases pass: retired_bip_options (all
ten options rejected on CLI and in config files), plans, configuration, and
invalid_options. The negative test diagnostic expectations were corrected to
match the existing parsers; production parsing behavior was not changed.
No VM ran. The secureboot_plan fixture was not run because the configured
virt-fw-vars executable is absent. This does not block further source cleanup
or establish Secure Boot qualification.


### BIP removal: independent firmware-variable fixture (2026-10-24)

Retired secureboot_init.c, the combined PID 1 BIP fixture, from the maintained
Makefile. Its firmware-variable state and unauthenticated mutation checks are
retained in firmware_init.c with distinct FIRMWARE_VARIABLES result markers.
It refuses non-PID-1 execution. The bootstrap target builds the new name;
old runner references are not aliases and cannot claim a combined-suite pass.
This removes the BIP namespace/sysctl/process/runtime assertions from that
fixture; it does not qualify the new firmware fixture or retire all remaining
legacy tests. The old fixture remains in the historical archive/preimage only.
The independent loader, EFI database, and veriexec implementations are unchanged.
Preimages: /usr/obj/usr/src/bip-removal-20261024-firmware-fixture.

Verification: isolated static candidate build and maintained firmware_init
Makefile build both pass. The three firmware functions and GUIDs were compared
verbatim, allowing only marker-prefix changes. Non-PID-1 execution returns 64.
Automatic review initially required the isolated build; the verified retry was
approved. No VM or firmware-variable test ran. The old runner still references
the retired fixture and must be replaced/cleaned before this workflow is usable.
Frontend review: build-bsd uses the maintained bootstrap/fixture Make targets;
this change updates those backend targets, without claiming the still-incomplete
runner integration is ready.


### BIP removal: unreferenced policy fixture helpers (2026-10-24)

Removed the BIP rtld policy mount/replacement helper and the SwitchBoard
immutable session-policy mount helper (C and header pairs). Their only caller
was the retired combined PID 1 fixture. Removed their compiler settings and
runner input inventory entries, including the already-deleted broker session.c
input. Ordinary rtld/veriexec implementation and firmware fixture are unchanged.
The remaining assembler/probe and legacy runner need further retirement or
separation; this change does not establish a working combined suite.
Build frontend review: build-bsd uses the maintained secureboot Makefile,
updated here; no frontend input or independent backend target changed.
Preimages: /usr/obj/usr/src/bip-removal-20261024-unused-policy-fixtures.

Verification: isolated candidate firmware build passes; all 35 runner native
unit tests pass both before application on the candidate and after application
in the source tree. No live fixture caller remains for the deleted helpers.
The runner input comparison adds no missing paths; secureboot_init.c and the
capsule_policy_test C/header pair were already absent. The legacy runner thus
remains unusable for current end-to-end qualification. Automatic review
required the isolated build/input comparison; the evidenced retry was approved.
No VM ran, and deleted BIP coverage is not counted as a pass.


### Retained Secure Boot workflow: tools and next integration gate (2026-10-24)

The previously missing default virt-fw-vars pathname is not a missing tool:
the existing qualification environment provides version 26.10 at
/usr/obj/usr/src/security-qualification/python-env/bin/virt-fw-vars.
Its --secure-boot spelling is a supported alias of --sb (confirmed in the
installed parser). The working QEMU executable is
/usr/obj/5bsd-qemu-fstt/qemu-system-x86_64-fstt-fixed (11.1.2).
Secure Boot OVMF code and variable templates are available in
/usr/local/share/qemu. Use explicit tool inputs; do not silently change defaults
or recreate environments to conceal an unavailable default command.

With the actual enrollment-tool path and the existing explicitly selected boot
support fixture, secureboot_plan and secureboot_generation_plan both pass.
These exercise the retained ordinary and independent generation-signing plans
after removal of BIP options. They neither execute those plans nor qualify the
retired runner. Logs and input hashes:
/usr/obj/usr/src/bip-removal-20261024-retained-secureboot-plans.

The next integration gate is a maintained runner independent of the retired
combined BIP fixture. It must keep firmware enforcement, loader authentication,
and veriexec results separate, use explicit tool/key/image inputs, stage a disk
root with 2048 MiB guest RAM, and reject missing or ambiguous evidence. Positive
boot alone cannot prove rejection of untrusted or revoked images. Preserve
negative cases and key lifecycle qualification as requirements. The firmware_init
probe only covers variable state and unauthenticated mutation attempts; it must
not substitute for authenticated-kernel boot or whole-system compatibility.
This is still mechanism preparation. No VM, enrollment or host installation was
performed in this turn. BIP removal and the broader active goal remain incomplete.


### BIP removal: retired authenticated-session client (2026-10-24)

Removed service_user_session_create from libservice, its installed declaration,
manual entry and obsolete wire request. Opcode 16 remains reserved alongside
17–25. The ordinary service_session_create/call/listener and discovery APIs
are unchanged. The principal notification wire width is retained at 64 bytes;
this does not restore principal session issuance in the broker.

Retired the legacy session, personal, session-storage, session-revoke and
session-storage-observer fixtures and removed their bootstrap build commands.
Their old runner/assembler modes remain unqualified and require removal; the
remaining native fixture checks retired opcode 16 with a raw request and expects
ENOTSUP. This is retirement of the BIP issuer model, not completed PAM/login
qualification. The maintained build frontend already rejects the removed BIP
options; its bootstrap backend is updated here. Preserve independent PAM and
ordinary UNIX/service tests. Preimages and evidence:
/usr/obj/usr/src/bip-removal-20261024-session-client.

Verification: isolated libservice build, maintained libservice/test build and
maintained SwitchBoard/test build all pass. Twenty-one native broker cases pass
covering launch revocation, service-control gates and ordinary management roles.
The retired session API/request names have no remaining live code references in
lib, usr.sbin or tools. Library symbol inspection retains service_session_create,
service_session_call and service_capability_open and removes the retired API.
No VM ran. The legacy assembler/runner still names the removed fixture paths;
those modes are not runnable qualification and remain the next cleanup work.


### BIP removal: native fixture session assembly (2026-10-24)

Removed the native assembler's retired session issuer, principal provider,
personal bundles and their BIP PAM/account scaffolding. Removed corresponding
session activation, PAM-result polling, logout and UID-impersonation assertions
from the native software-service probe. Independent PAM/login qualification is
still required; this retired fixture no longer supplies it. The separate
session-storage assembler mode still awaits retirement.

The retained probe checks notification, control channels and cryptographic
operations. Its completion marker is NATIVE_SOFTWARE_SERVICE_PASS, deliberately
distinct from the old combined result. Runner and report parsing use the new
scope; old markers cannot qualify the reduced fixture. Native report entries
no longer imply session authentication. Updated the marker unit test with an
explicit historical-marker rejection check. Maintained build-bsd bootstrap
consumes the changed probe and Python tests; no new frontend option is added.
Preimages and evidence: /usr/obj/usr/src/bip-removal-20261024-native-session.

Verification: isolated candidate and maintained native probe builds pass.
All 36 runner tests and 15 assembler tests pass against both the candidate and
applied source tree, including rejection of the former native completion
marker. These are compilation and parser checks; no guest probe ran. The
remaining combined runner still depends on other retired BIP paths and cannot
qualify current firmware/loader/system behavior. Source removal does not count
as successful authentication, PAM, account, personal-service or logout testing.


### BIP removal: orphaned principal-provider fixture (2026-10-24)

Removed the five-file principal-provider test fixture after its session issuer,
assembler installation and report handling were retired. Removed its bootstrap
build commands and runner inventory entries together. This synthetic provider
was not a production daemon; no ordinary provider implementation is removed.
The build-bsd bootstrap backend is updated in the same change.

The dependency audit also found remaining principal-notification APIs in
libservice and SwitchBoard, including listener negotiation and wire metadata.
These now have no working authenticated-session issuer and need coordinated
retirement next. Do not interpret retained metadata as established human
identity. Ordinary software identity, listener queues and capability discovery
must be preserved during that removal.
Preimages and evidence: /usr/obj/usr/src/bip-removal-20261024-principal-fixture.

Verification: candidate runner syntax and 36 native runner tests pass; the
updated bootstrap script passes sh -n. No compiled production code changed;
the only remaining C edit removes a reference in a comment. No VM ran.
The next principal-metadata removal must include libservice listener queues,
accept/expose APIs, shared claim flag/opcode, SwitchBoard naming and on-demand
negotiation, plus their tests. Reserve retired wire identifiers and prove that
ordinary software identity and SENDABLE claim behavior are unchanged.


### BIP removal: principal notification API and negotiation (2026-10-24)

Removed the remaining BIP principal metadata from libservice listener queues,
accept/expose APIs and validation, and from SwitchBoard name-claim negotiation
and delivery. Removed the public principal structure, extended notification
wire structure and unused validator test. Opcode 130 and claim bit 0x2 remain
reserved; broker request and internal claim validation reject the retired bit.
Ordinary software identity structures and their wire layout are unchanged.
SENDABLE claim behavior remains, with a regression case checking rejection of
the retired bit without changing claim state, followed by a valid SENDABLE claim.

Before application, isolated libservice and SwitchBoard builds and 61 native
cases pass: ordinary broker authority/management, claim handling, software
identity layout and descriptor cleanup. Four channel tests needing the matching
kernel were excluded from host execution and still need current VM coverage.
The first candidate compile identified a remaining request-parser reference;
it was removed. Another isolated build needed the unchanged sibling
switchboardctl source used by its tests. Neither failure was treated as a pass.
The ordinary public and wire identity structures were compared byte-for-byte.

Frontend integration: no new build inputs; the existing build-bsd world/package
backends build the changed libraries, broker and tests. Updated their source
lists and manuals together. No host installation or VM execution is claimed.
Evidence: /usr/obj/usr/src/bip-removal-20261024-principal-api.

Applied-source verification: maintained libservice and SwitchBoard builds pass.
Staged current libservice into the world build sysroot only (install -U, no host
installation), then built fresh static runtime-init, libservice_api_test and
anoint_test. Matching-kernel QEMU passed four real-channel cases:
minted_channel_carries_set, session_reach_over_minted_channel,
registered_private_channel_keeps_set and lookup_helper_names_over_minted_channel.
Three ordinary libservice cases and the descriptor-hardening baseline also pass.
VM result PASS, exit zero, no forced termination, clean guest poweroff;
2048 MiB RAM, two vCPUs, 512 MiB disk-backed root. Explicit prior boot support
and namespace_test were reused and hashed; this is not a rebuilt full world,
production daemon startup, Secure Boot, upgrade or performance qualification.
VM evidence: /usr/obj/usr/src/security-qualification/bip-principal-api-vm-20261024.

In parallel, user-authorized Bazel work is proceeding under tools/build/bazel.
The requested end state includes Bazel in default base images with its runtime
closure, while retaining Make for third-party projects and ports. The current
pilot is not a selectable world/kernel backend or proof of base availability.


### Bazel dependency licensing gate (2026-10-24)

The default-installed Bazel requirement includes GPL runtime components:
OpenJDK21 and Bash, alongside permissively licensed Bazel and Python. The
current OpenJDK port also brings X11, font, audio and image libraries. The full
transitive and bundled license audit remains incomplete. Before publication,
the system-software composition must preserve component identities, notices,
license combinations and applicable corresponding-source delivery. See
`tools/build/bazel/README.md` for the checked scope and remaining gates.
Bazel remains experimental; no new frontend option or backend is enabled by
this documentation change. Existing build-bsd publication must eventually carry
this composition gate when general system-software packaging is implemented.
No build, package publication or VM result is claimed by this review.


### BIP removal: storage ioctl ABI and obsolete fixture (2026-10-24)

Removed the remaining BIP storage ioctl definitions and retired storage grant
header. Ioctl numbers 0x26 through 0x2e remain reserved. All ordinary zfshandle
header content is byte-for-byte unchanged outside the removed BIP block.
Removed the dependent storage PID1 fixture, ordinary probes embedded in that
BIP fixture, and BIP I/O test module. Retired the four corresponding runner
cases, their bootstrap build, completion parser and positive evidence tests.
The verifier explicitly rejects retired case receipts; a negative regression
checks all four names. The old anchor suite profile is rejected as well.

Isolated verification: 50 runner/verifier tests pass; retained ordinary ZFS
handle tests compile/link through maintained buildenv with the candidate header
first in the include path and 16 jobs. Bootstrap shell syntax passes. These
are compilation and native parser checks, not ZFS runtime or VM qualification.
The legacy combined runner still has other BIP dependencies and is unqualified.
Preimages and evidence: /usr/obj/usr/src/bip-removal-20261024-storage-abi.

Frontend integration: updated build-bsd's maintained build-bootstrap.sh backend
in the same change. The corresponding frontend BIP options were already removed;
no new frontend option is needed. The ordinary world/package workflow retains
its ZFS interfaces and tests. No host installation, firmware change or VM ran.


### BIP removal: unused storage probes in loader assembler (2026-10-24)

Removed the optional ordinary_probe and startup_probe inputs from the legacy
loader fixture assembler after their only caller and binaries were retired.
The remaining call supplies only the world, object and output roots. Removed
the private-library DT_NEEDED exception that existed solely for startup_probe.
Dependency lookup for the remaining fixture retains its strict checks.
This does not restore or qualify the legacy BIP loader-policy fixture; its
remaining probe, assembler and completion assertions still need retirement
as the combined runner is separated. No production rtld behavior changes.
Frontend review: build-bsd's bootstrap caller was already updated with storage
fixture retirement; this removes unused Python inputs, not frontend options.


### BIP removal: session-storage runner and lifecycle fixture (2026-10-24)

Retired the session-storage assembler mode, runner case/options, completion
parser and report field. Its issuer APIs and source fixtures were already gone.
Old case receipts and session-storage metadata are explicitly rejected by the
verifier. Removed the lifecycle-observation provider fixture and its bootstrap
build, plus six BSDFILESYSTEM_LIFECYCLE_TEST conditional blocks in request.c.
All production source outside those conditional blocks is unchanged. Ordinary
provider/crash assembly and cross-boot continuity checking remain.

Candidate verification: maintained buildenv with 16 jobs builds BSDFilesystem
and its install-format policy-bearing executable. 62 native runner, verifier
and capsule-assembler tests pass; bootstrap shell syntax passes. These checks
do not prove running provider behavior, authentication, full startup or Secure
Boot. Session-policy installation/rejection fixtures and other legacy BIP runner
dependencies remain for subsequent removal; the combined runner is unqualified.
Preimages/logs: /usr/obj/usr/src/bip-removal-20261024-session-mode.

Frontend integration: build-bsd's bootstrap backend no longer builds the retired
lifecycle provider. Its frontend options were already rejected, and that test
is retained. No new build frontend options or production authority are added.


### BIP removal: session-enrollment policy fixtures (2026-10-24)

Removed the legacy runner session-policy input, baseline installation, malformed
policy images and their four UCL fixtures. Removed the assembler's session-policy
argument and wrapper. The shared SwitchBoard policy installer remains for ordinary
boot-authority policy, with its existing hard-link replacement, source-boundary,
symlink, mode, nonfile and size checks retained in tests using that policy path.
Old session-policy case receipts/classifications are rejected explicitly.

63 candidate native runner/verifier/assembler tests pass. No compiled production
code changes and no VM ran. This retires obsolete session coverage; it does not
qualify ordinary authentication or restore the remaining legacy Secure Boot
runner. Frontend review: build-bsd already rejects session-policy; its runner
backend now removes the corresponding unused option and fixture dependencies.
Preimages and test log: /usr/obj/usr/src/bip-removal-20261024-session-policy.

The user confirmed that separately licensed GPL dependencies are acceptable for
Bazel integration; 5BSD's own BSD-licensed code keeps its license. Maintain the
package/source/license obligations recorded in tools/build/bazel/README.md.
Default Bazel availability remains requested; no GPL-free installation gate is
being introduced. The user-authorized background Bazel agent continues.


### Retained verity boundary audit (2026-10-24)

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



### BIP removal: unused host account generator (2026-10-24)

Removed the unused pwd_mkdb assembler argument and runner option/precondition.
The build-bsd secureboot-test plan no longer builds or passes this host tool.
The ordinary guest pwd_mkdb binary and account tests remain; other construction
uses of host account generators are unchanged. Updated the plan assertion and
manual together. Candidate frontend compiles with -Wall -Wextra -Werror; the
secureboot_plan ATF case passes with explicit root and vars-tool inputs.
63 native runner/verifier/assembler cases pass. These are plan/parser checks,
not a working Secure Boot VM; the legacy runner still depends on removed BIP
fixtures. Preimages/evidence: /usr/obj/usr/src/bip-removal-20261024-host-account.


### Bazel/Make static runtime pilot (2026-10-24)

The maintained tools/build/bazel runtime helper passed three cases in a single
2 GiB QEMU VM: real base echo built by Bazel and by Make (four output/status/
stderr checks each), plus the Bazel C++ vector/iostream pilot. Exact r4 output
hashes match r5. Guest root is disk-backed, 512 MiB; clean shutdown, exit zero,
no forced termination. Four library/descriptor baseline cases also pass.
Initial attempt failed after a staging permission error and is retained, not
counted. Corrected inputs were verified before the separate accepted run.
Evidence: /usr/obj/usr/src/security-qualification/bazel-declared-runtime-20261024.

Frontend integration review: this remains a static toolchain pilot, not a
selectable build-bsd backend. Full-system, Bazel9, cross, shared-library and
performance qualification remain open; Make remains the production backend.
The Bash audit is recorded in tools/build/bazel/SHELLS.md; replacing Bash with
Zsh is not qualified and the real dependency is retained.


### Bootstrap reference correction (2026-10-24)

The group-level fixture inventory found a missed invocation of the deleted
provider-lifecycle/profile_test.py in build-bootstrap.sh. Removed that obsolete
invocation. Shell syntax checking had not detected the missing input. The
remaining literal $source_root paths in the script exist; dynamic loop targets
and successful builds are separate checks. This fixes a maintained frontend
backend reference, not the remaining legacy Secure Boot runner.
Evidence: /usr/obj/usr/src/bip-removal-20261024-bootstrap-reference.


### Archive runtime VM qualification (2026-10-24)

The amd64 static archive pilot now passes runtime qualification in a single
QEMU guest with 2048 MiB RAM and a disk-backed 512 MiB fixture root. Eight
ATF cases passed: four existing library/namespace controls, Bazel echo,
Make echo, C++ vector/iostream, and the new C/assembly archive behavior.
The new case checks signed div quotient/remainder and bounded strnlen results;
the compile receipt separately verifies the archive supplied both symbols.
QEMU exited zero after guest poweroff, without forced termination.

Evidence: /usr/obj/usr/src/security-qualification/bazel-archive-runtime-20261024,
including runtime-receipt.json binding the staged inputs, compile receipt,
VM result and serial transcript. Compile-only results remain unmodified.
The guest harness supplies per-case directories and deadlines; raw ATF warnings
about running outside kyua do not mean these controls were omitted.

Frontend review: no production backend or build input contract changes. Make
remains selected by build-bsd. This does not qualify Bazel9, world/kernel,
cross builds, shared libraries, package parity, Secure Boot, or performance.


### Independent firmware probe candidate (2026-10-24)

A standalone EFI probe built using the maintained loader startup/relocation
code, EFI headers, linker script and PE converter. It does not load a kernel
or a root image. In separate sequential 2048 MiB QEMU guests, the unsigned
probe executed in setup mode (SecureBoot=0, SetupMode=1) and the db-signed
probe executed with enforcement enabled (SecureBoot=1, SetupMode=0). Both
powered off cleanly. All keys and variable-store changes were VM-private.

With the same enrolled store, OVMF reported Access Denied for the unsigned
probe's sole EFI disk and did not execute the probe. This observation is
retained as a failing candidate-runner result: its negative matcher has not
yet been qualified, and the firmware menu required bounded termination.
A timeout alone is never rejection evidence.

Candidate source, build logs, input/result hashes and the next integration
gates are preserved at
/usr/obj/usr/src/security-qualification/firmware-independent-20261024.
No candidate runner has replaced the maintained workflow. Frontend review
confirms build-bsd secureboot-test still invokes the legacy BIP-dependent
runner; the independent build, runner, tests and manual must be integrated
together before claiming that workflow works. Loader verification, key
rotation/recovery, veriexec and installed-system startup remain separate gates.


### Firmware rejection verifier qualification (2026-10-24)

The independent candidate now pairs rejection with a signed enabled control
using identical initial variable-store, firmware, QEMU, runner and evidence
module hashes. It requires one matching boot attempt and Access Denied diagnostic,
followed by no bootable device, with no starting or probe execution messages.
Boot numbers and PCI addresses are read from the attempted target, not fixed
in the matcher. Ten parser tests cover missing, contradictory, duplicate,
misordered and wrong-target evidence. Six CLI preflight checks reject missing
or mismatched controls before staging or starting QEMU.

Fresh sequential 2048 MiB VMs passed signed enabled execution and rejection of
unsigned, untrusted-signer and post-signing payload-tampered probes. Rejection
VMs are explicitly terminated after matching firmware evidence; their receipts
record forced termination and firmware-rejection-observed, not a clean shutdown
or a timeout pass. The earlier unsigned-observation failure remains retained.

Evidence and candidate revision:
/usr/obj/usr/src/security-qualification/firmware-independent-20261024/review-r2.json.
This remains a candidate pending maintained frontend/backend/manual integration.
The legacy build-bsd secureboot-test is still not qualified. dbx, authenticated
key changes, recovery, loader verification and actual OS startup remain open.


### Maintained firmware-only workflow (2026-10-24)

`build-bsd secureboot-test --test-case firmware` now builds and runs the
independent firmware suite through maintained source. Explicit
`--test-firmware-code` and `--test-firmware-vars` select the OVMF code and
setup-mode template. Native OpenSSL, uefisign, makefs and mkimg defaults can be
overridden with the corresponding `--test-*` options. Existing QEMU and
variable-tool options remain available. A staged OS root is not used.

The maintained frontend completed the isolated loader-support build, probe
build, ten evidence-parser tests and five sequential 2048 MiB QEMU cases:
setup execution, trusted execution, unsigned rejection, unknown-signer
rejection and signed-payload tamper rejection. The firmware and legacy plan
ATF cases both passed. Fresh private keys and private variable copies were
used; host firmware and installation were untouched. Source preimages and
qualification receipt: /usr/obj/usr/src/firmware-integration-20261024.
VM evidence: /usr/obj/usr/src/security-qualification/firmware-frontend-20261024.

This supersedes the earlier candidate-only integration status. It does not
qualify the legacy combined runner, loader execution, veriexec, key rotation,
dbx lifecycle, recovery, factory-key/shim support or installed-system boot.
Those gates remain open. No BIP enforcement was restored.


### Certificate revocation enforcement (2026-10-24)

The maintained firmware suite now includes eight sequential 2048 MiB VM
cases. Both enrolled signing certificates execute before revocation. Adding
the first certificate to dbx makes firmware reject its previously accepted
image, while an image signed by the second certificate still executes with
SecureBoot=1 and SetupMode=0. The rejection control uses the exact same
revoked variable-store input. Offline inspection confirms only dbx changed,
both certificates remain in db, and only the first certificate is in dbx.
The full build-bsd firmware workflow passed, including the ten parser tests.

Evidence: /usr/obj/usr/src/security-qualification/firmware-revocation-frontend-20261024.
Preimages, log and reviewed receipt: /usr/obj/usr/src/firmware-revocation-20261024.
Frontend review: no new C options or plan steps are needed; the maintained
suite called by the existing firmware action and its manual were updated.

This qualifies certificate dbx enforcement using offline-prepared private
variable stores. Authenticated SetVariable, replay rejection, PK/KEK/db
rotation and recovery remain open. The installed virt-fw-vars authfiles
writer uses an empty/dummy authentication header; its output-auth option
must not be treated as a signed runtime update or rotation proof.


### Maintained firmware store audit (2026-10-24)

The firmware suite now automatically exports and audits its private trust stores
before any VM starts. Its bounded EFI_SIGNATURE_LIST parser preserves signature
type, header, owner and payload. The only permitted change is an exact append
of the enrolled primary certificate to dbx; both certificates remain in db,
the surviving signer is not revoked, and authenticated-write attributes remain.
Duplicate variable records, malformed/truncated lists, unexpected attribute
changes and wrong revocations are rejected. Suite source hashes are captured
before execution and checked afterward.

The frontend discovers both maintained verifier test modules: 18 cases passed.
The full build-bsd firmware workflow and its plan test passed; all eight
sequential 2048 MiB VM cases passed with the new preflight audit.
Evidence: /usr/obj/usr/src/security-qualification/firmware-store-audit-20261024.
Preimages and qualification receipt: /usr/obj/usr/src/firmware-store-audit-20261024.
Authenticated variable updates, replay handling and recovery remain unqualified.


### Shared-library VM runtime qualification (2026-10-24)

The current Bazel shared/PIC outputs passed in one 2048 MiB QEMU guest with
a disk-backed 512 MiB root. Eleven cases passed: four existing library/namespace
controls, Bazel and Make echo, C++ vector/iostream, static archive behavior,
Bazel shared-library behavior, Make shared-library behavior and an actual
missing-library failure. The dynamic checker uses dlopen/dlsym and verifies
each function's library with dladdr and realpath before testing its behavior.
Resolution from libc cannot satisfy the requested-library check.

The guest interpreter and dependencies were derived from ELF metadata: the
matching object-tree ld-elf.so.1 plus SDK libc.so.7 and libsys.so.7. No host
runtime library was substituted. The VM shut down cleanly, exit zero, without
forced termination. New static output hashes are covered by this receipt;
old receipts remain bound to their old artifacts. Compile-only result files
retain their original runtime_qualified=false scope.

Evidence: /usr/obj/usr/src/security-qualification/bazel-shared-runtime-20261024,
including runtime-receipt.json binding source, artifact and VM evidence.
Frontend review: these are primitive toolchain/runtime pilots. No production
Bazel backend is selected by build-bsd. Bazel9, full world/kernel, complete ABI
and symbol-version parity, cross compilation, installation/package parity
and performance remain open. Make remains the production backend.


### Authenticated db replacement candidate (2026-10-24)

A new candidate EFI client exercised real SetVariable calls with SecureBoot=1
and SetupMode=0. An unauthorized signer was rejected with
EFI_SECURITY_VIOLATION and unchanged db bytes/attributes. A KEK-signed
replacement installed the exact requested db bytes. Replaying the same
non-append update was rejected with unchanged replacement bytes. The guest
powered off cleanly. Subsequent separate 2048 MiB VMs used the exact persisted
firmware-produced variable store: the remaining enrolled signer booted and
the removed signer was rejected. The persisted db export equals the requested
payload. No host firmware variables were accessed.

The candidate signer follows UEFI 2.11 section 8.2.6, using a detached PKCS#7
signature without authenticated attributes over the variable name, GUID,
attributes, timestamp and payload. Four native tests cover serialization,
invalid inputs, changed signed fields and mismatched private keys.
Specification: https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html#using-the-efi-variable-authentication-2-descriptor

Evidence and candidate source:
/usr/obj/usr/src/security-qualification/firmware-auth-update-20261024.
This candidate is not yet integrated into build-bsd: the fixture build,
public-only update inputs, signer tool input, suite, verifier tests and manual
must be updated together before claiming the maintained action covers it.
The candidate retires one of two already-enrolled db signers. It does not yet
qualify first enrollment of a new signer, PK/KEK rotation, rollback/recovery,
power-loss behavior or authenticated updates from a running OS.


### Maintained authenticated db replacement (2026-10-24)

The build-bsd firmware action now builds the EFI update client and integrates
the authenticated-update signer, public payload staging, evidence checks and
subsequent boots. OpenSSL selection also reaches the native signer tests.
Twenty-three native tests, the maintained frontend plan test and all twelve
sequential 2048 MiB VM cases passed.

A newly generated replacement signer is rejected against the initial store.
The EFI client rejects an unauthorized update without mutation, accepts a
KEK-signed db replacement and rejects replay without mutation. It checks
exact db bytes and attributes after each call. After clean shutdown, the
new signer boots with enforcement enabled and the retired signer is rejected;
both later guests use the exact firmware-produced store. The final store
export is checked against the requested db payload. Private keys never enter
the guest; only public payloads and detached signatures do.

Evidence: /usr/obj/usr/src/security-qualification/firmware-auth-frontend-20261024.
Preimages and source-bound receipt: /usr/obj/usr/src/firmware-auth-integration-20261024.
This supersedes the preceding candidate-only integration status. It qualifies
this db replacement and same-boot replay case, not PK/KEK rotation, recovery,
power-loss behavior, cross-reboot replay, OS runtime updates, or the complete
Secure Boot/loader/system-startup chain. Those gates remain open.


### Cross-reboot authenticated db replay (2026-10-24)

The maintained build-bsd firmware workflow passed 24 native tests and thirteen
sequential 2048 MiB firmware VM cases; the frontend plan test also passed.
The added guest boots an update client signed by the newly enrolled signer,
using the exact persisted variable store from the successful db replacement.
It rejects the byte-identical original authenticated update after reboot,
accepts a KEK-authorized update carrying a newer timestamp, then rejects
replay of that newer update. Each operation checks exact db bytes and
attributes. The guest shuts down cleanly without forced termination.

Evidence: /usr/obj/usr/src/security-qualification/firmware-replay-frontend-20261024.
Preimages and qualification receipt: /usr/obj/usr/src/firmware-replay-integration-20261024.
The frontend C needs no additional option or build step: its maintained update
client build and suite invocation include this case. The backend, evidence
tests and manual were updated together.

This extends the preceding same-boot replay evidence. PK/KEK rotation, recovery,
power-loss behavior, OS runtime updates and the complete OS boot chain remain
unqualified. The older combined Secure Boot runner still references removed
BIP fixtures; it is not covered by this firmware-only qualification. Remaining
BIP test/documentation cleanup must not restore the removed enforcement code.


### Retired BIP GEOM diagnostic test (2026-10-24)

Removed geom_override_test.py and the geom-override-test target: they expected
the deleted g_footshooting policy helper and MAC_SYSTEM_INTEGRITY behavior.
Removed the corresponding hardened-storage claim from the build-bsd manual.
The retained kernel uses ordinary GEOM diagnostic behavior. This is retirement
of BIP coverage, not a new storage protection or performance qualification.
No kernel code changed in this cleanup.

Preimages and exact change hashes: /usr/obj/usr/src/bip-geom-test-retirement-20261024.
Frontend review: build-bsd.c has no reference to this native target; its manual
and the maintained test Makefile changed together. The legacy combined runner
and protected rtld fixtures still require cleanup. BIP remains dropped.


### Retired protected rtld fixture (2026-10-24)

Removed the BIP-only assemble_rtld.py, rtld_probe.c and libbipprobe sources,
their Makefile entries and build-bootstrap invocation. The legacy runner no
longer imports or assembles them and rejects a MAC_SYSTEM_INTEGRITY kernel.
Historical rtld evidence predicates remain unchanged: no assertion was weakened
to manufacture a passing legacy result. The combined legacy runner still
depends on other removed fixtures and is not an operational OS qualification
path. Its remaining BIP dependencies need further removal/replacement.

The retained runner-evidence tests (29) and signing tests (7) pass; shell syntax
and Makefile program selection were checked. These are native checks only,
not a guest dynamic-loader or installed-system qualification. No VM was run.
Frontend review: build-bsd.c has no direct protected-rtld fixture reference;
the invoked backend and its Makefile were updated together. The manual now
explicitly marks the retired test mode. Preimages and change hashes are at
/usr/obj/usr/src/bip-rtld-retirement-20261024.


### Real libsbuf runtime qualification (2026-10-24)

A single 2048 MiB QEMU guest with a 512 MiB disk-backed root passed thirteen
cases: four baseline cases, seven previous Bazel/Make runtime cases and new
sbuf_bazel/sbuf_make cases. The dynamic probe resolves each exercised API by
its FBSD_1.2 symbol version and verifies the requested library supplies it.
It checks buffer growth, formatting and content, finish/reuse, fixed-buffer
overflow and recovery, repeated partial drains and drain-error propagation.
Both the Bazel-built and independently Make-built libsbuf.so.6 pass.

Artifacts match the declared-build receipt and the guest's staged-input hashes.
The runtime uses matching object-tree ld-elf.so.1 and SDK libc/libsys, with no
host library substitution. The guest exits cleanly, QEMU status zero, without
forced termination. Sources were checked unchanged after execution.

Evidence: /usr/obj/usr/src/security-qualification/bazel-libsbuf-runtime-20261024,
including runtime-receipt.json. Compile-only pilot receipts retain their original
runtime_qualified=false scope; this separate receipt supplies guest evidence.
Full ABI coverage, Bazel9, cross compilation, world/kernel and packaging parity,
and performance qualification remain open. Make is still the production backend.
Frontend review: this extends the declared toolchain pilot and existing generic
runtime runner; no production backend selection changes in build-bsd.c.


### Bazel qualification frontend integration in progress (2026-10-24)

The maintained build-bsd frontend now has a bazel-test action taking an explicit
--bazel executable, --jobs and --output. It invokes the maintained
tools/build/bazel/qualify.py with /usr/src and the standard native object tree.
The frontend rejects cross targets, unused Bazel options, nonexecutable tools,
incremental reuse and custom comparison configuration. Existing frontend build
locking and logs apply. Make remains the production build backend.

The standard frontend build, new plan/negative-input test and existing firmware
plan test pass. Evidence: /usr/obj/usr/src/bazel-frontend-20261024.
The helper execution and complete frontend workflow are still under qualification;
this receipt proves frontend compilation/planning only. Earlier independent
Bazel/Make VM results retain their separate artifact-bound scope.


### Maintained Bazel qualification action passed (2026-10-24)

The complete build-bsd bazel-test action passed with explicit /usr/local/bin/bazel,
a fresh /usr/obj/usr/src/bazel-frontend-qualified-20261024 output and all16 CPUs.
The helper derives the staged compiler target/resource version, verifies Make
buildenv object identity, builds fresh private Make reference libraries with
/dev/null Make configurations, runs the declared Bazel pilot and seven metadata
tests, and rechecks its recorded source/tool hashes before accepting results.
Four helper boundary tests were also run separately. The frontend plan tests
cover argument forwarding and rejection of missing/nonexecutable Bazel, foreign
architecture, incremental reuse and custom comparison configuration.

Evidence: /usr/obj/usr/src/bazel-frontend-qualified-20261024/receipt.json and
frontend-receipt.json. Referenced source snapshots and frontend logs are retained.
This supersedes the preceding helper-unqualified status for this native compile
workflow only. No VM or installation occurred in this run; prior VM receipts
remain separate. The installed Bazel5 pilot does not establish Bazel9, complete
world/kernel builds, packaging/install parity, cross compilation or performance.
Make remains the production backend. BIP remains dropped.


### Open veriexec tmpfs compatibility gate (2026-10-24)

The maintained elf_signature_test:locator_parity was compiled statically and
run in a single 2048 MiB disk-backed VM against kernel SHA256
785a65a10d230a47a868d5619d1fa8765253e9593ad2e1abfc57e0334a033003.
It failed: userland accepted the valid signed ELF, while kernel required-fd
verification and PREPARE returned EOPNOTSUPP. The runtime harness places its
case workspace on tmpfs. Current vn_text_pin_supported permits UFS/ZFS only.
The failed evidence is retained at
/usr/obj/usr/src/security-qualification/veriexec-elf-20261024, with assessment.json.

This is a real unsupported-filesystem boundary, not a passing integrity test.
The successful unsigned baseline cases do not establish signed-exec support.
Next: exercise the unchanged positive corpus on actual UFS/ZFS storage and
retain an explicit tmpfs rejection case; independently review tmpfs text/write
exclusion before extending support. Do not bypass the stable-text check or
change signature expectations merely to make this result pass. A supported-
filesystem pass would not close the tmpfs compatibility requirement.
No frontend inputs changed; the maintained generic VM runner was used.

## Qualification continuation — 2026-10-24

Commit `793a0c1f76b` fixes six software-authority VM runners that still requested
4 or 8 GiB: kernel, software VM, seed, installer, installed-system and installed
boot now request 2048 MiB. The new native RAM declaration check and existing
QMP startup/cleanup check pass. No guest was launched in this continuation;
historical higher-memory results require reruns. The declaration check does not
measure actual guest/host memory, disk I/O or performance. These are direct test
runners; build-bsd.c does not call them, and no build frontend input changed.

The Bazel builder now has a payload-validated selection of 334 packages (279
base plus 55 ports) from conventional GENERIC-NODEBUG generation
`16.snap20261010074756.complete` and explicit ports/bootstrap archives. Evidence:
`/usr/obj/bazel9-bootstrap-packages-20261024/builder-selection-20261010.json`
and `builder-inventory-20261010.json`. Existing package, shared-library, conflict
and payload checks pass. This is input consistency, not release authentication,
current-source qualification or a boot result. October 12 was rejected for
switchboardctl requiring libcapbundle.so.1 while that generation supplies .so.2;
its failure remains recorded rather than excluding the affected package.

Next: supply an explicit real pkg bootstrap archive (the base selection only
contains the network bootstrap stub), construct the package database and normal
filesystem layout on disk, and exercise the selected Java/Bazel build inputs in
one 2 GiB VM. No host package installation or new publication was performed.

### Offline Bazel builder transport — 2026-10-24

The explicit pkg-2.8.4_8 archive from standard repository generation
16.snap20261023125743.complete passes the maintained inventory and dependency
checks with the prior builder selection: 335 packages total. Selection,
inventory, log and validation receipt are under
`/usr/obj/bazel9-bootstrap-packages-20261024/` as
`builder-selection-with-pkg.json`, `builder-inventory-with-pkg.json`,
`builder-inventory-with-pkg.log` and `builder-pkg-validation.json`.

`input-transport/input.ufs` is a 768 MiB disk transport of those exact archives,
a manifest and the payload-verified static pkg executable. Its receipt binds
image and transport hashes. It is intended for a read-only guest disk attachment;
it is not a boot image or whole-system RAM preload. No host package installation,
publication or VM launch occurred. Guest filesystem readback remains untested.

Construction review found the legacy selected packages have no declared
construction actions, while ordinary installation scripts supply necessary
initialization (including account databases). Extraction plus register-only
construction therefore cannot qualify this builder. Next use ordinary pkg
installation with scripts inside the disposable disk-backed guest, retain logs
and partial failures, and check resulting package records and normal Java/Bash
paths before attempting Bazel. A dedicated fixture is being implemented; no
runtime or build success is claimed. Build frontend options are unchanged in
this input-preparation turn; any new supported build workflow must be integrated
through the maintained frontend and backend before acceptance.

### Ordinary builder fixture preparation — 2026-10-24

A new test-only ordinary package installer is under review in
`tools/test/bazel-builder`. It extracts the complete selected payload set to
supply the legacy packages' bootstrap shell, then uses actual pkg chroot
installation with scripts/triggers enabled. The fixture must compare the final
package database to all selected identities, check payload integrity and exercise
normal installed Java/Bash paths. Native path/transport/mount guards passed;
these are not installation or boot results.

The private workspace is
`/usr/obj/usr/src/security-qualification/bazel-builder-install-20261024`.
`bootstrap-inputs.json` binds the test interpreter, libraries, base utilities,
backend modules and nullfs kernel module. The separate
`/usr/obj/bazel9-bootstrap-packages-20261024/input-transport-v2/input.ufs`
adds full inventory.json and root-layout.json to the prior read-only package
transport. Its manifest format remains 1, with both files explicitly hash-bound.

No VM has run this fixture yet. Required execution remains one 2048 MiB guest,
read-only input disk and a new retained writable output disk, with no target
installation onto the host or tmpfs. This fixture is not yet a supported
build-bsd action; its inputs and findings must feed the maintained builder
workflow before that integration can be declared complete.

The first ordinary-builder guest run failed before installation creating
mountpoints on the bootstrap read-only root. Retry2 used mountpoint directories
under /tmp and actual separate virtio UFS payload disks; it failed before
extraction because the ctypes libarchive runtime dependency was absent under the
name discovered by the bootstrap interpreter. This dependency is now explicitly
staged, but the correction is not yet VM-qualified. Retry2 also reported a
UFS/tmpfs WITNESS lock-order reversal during shutdown. The run is FAIL regardless
of package outcome; the kernel warning is not waived. Its captured chain differs
from the recorded October3 ZFS/filedesc issue, with no shared cause established.
See `retry2-assessment.json`, `ufs-tmpfs-witness.txt` and `vm-retry2/serial.log` in
the builder workspace. No usable builder or Bazel runtime is claimed. No VM
remains running from these attempts.

### Ordinary builder retry3 and isolated fixture commit — 2026-10-24

Committed the new test fixture as `28a28ded041`, with eight native guard tests
passing. It supports guarded precreated empty root-owned mountpoint directories
on a read-only bootstrap filesystem. The maintained build frontend is unchanged:
this is qualification tooling, not a production builder backend or completed
Foundry integration.

The next 2048 MiB guest ran for 107 seconds and exited cleanly, but the test
FAILED before extraction: `missing declared parent directory: /usr/local/bin`.
The explicit libarchive runtime dependency now loads. Package payload/dependency
inventory success did not establish complete directory-layout policy for these
legacy ports inputs. Investigate ordinary pkg/ports mtree metadata and report all
missing ancestors before designing a general correction; do not add a one-path
exception just to pass. See `retry3-assessment.json` and `vm-retry3/result.json`
in the builder workspace. No package installation or Java/Bazel runtime success
is claimed. This transcript contains no lock-order warning, but the prior
UFS/tmpfs warning remains open because the mount layout changed. No VM remains
running from these attempts.

### Inventory-derived ordinary pkg directory layout — 2026-10-24

Commit `ad6bbf1feb3` adds test-only layout planning with an explicit pkg2.8.4
parent-directory policy. The full335 selection lacks2746 declared ancestors;
base/ports mtree coverage accounts for284 of these and cannot cover arbitrary
application trees. Actual pkg source creates missing parents with root/wheel
ownership and0755 mode. The producer derives those ancestors, preserves declared
metadata, rejects conflicting objects/replacements, and binds inventory, initial
layout, policy, source and output hashes. Shared extraction validation is unchanged.

Fourteen native installation/layout tests pass. Read-only extraction preparation
and account planning pass for all66576 resulting objects. Artifacts are under
`/usr/obj/bazel9-bootstrap-packages-20261024/implicit-directory-layout`.
The new768MiB `input-transport-v3/input.ufs` carries the derived layout and receipts.
These are planning/input checks, not successful installation evidence.

At this checkpoint retry4 is running in one2048MiB QEMU guest with the unchanged
installer, read-only input disk and fresh8GiB output disk. Session command and
logs are `launch-retry4.json`, `launch-retry4.log` and `vm-retry4/serial.log` under
the builder workspace. Inspect its result before any subsequent VM launch;
do not restart an active test. No Java/Bazel runtime acceptance or kernel-warning
resolution is claimed. This fixture artifact uses the existing generated-layout
schema accepted by maintained construction; no production frontend option changed.

### Explicit application publication integration — 2026-10-24

The working tree now wires build-bsd `--application-selection` (configuration
`application_selection`) through APPLICATION_PACKAGE_SELECTION and the maintained
system-packages/publish-packages targets. The input is an existing format-1
hash-bound archive selection. Applications retain original names and bytes and
are validated with base/hardware before catalogue creation/signing. Duplicate or
reserved identities, /boot additions, incompatible ABI/OS requirements, wrong
hashes, dependency origins, missing dependencies/libraries and payload conflicts
are rejected. Ordinary .ko test data outside /boot is allowed. The publication
receipt records the selection hash and application identities. Atomic latest
advancement is retained. Format-2 repository-root resolution is explicitly
unsupported here; this is not a completed remote-repository workflow.

The frontend compiles with warnings as errors. Application plan/configuration/
Make-forwarding tests and existing bootstrap/general plans pass. Seven focused
publication tests pass, including real signed catalogue creation and failure
atomicity; two namespace-affected tests pass again after review. Evidence and
source hashes are under `/usr/obj/usr/src/application-publication-20261024`.
No production repository was published, no desktop image was built, and no host
installation occurred. This integration is not committed yet: it depends on
pre-existing untracked inventory/closure helpers, which need their own reviewed
commits rather than inclusion through a broad dirty-tree commit.


### Package publication prerequisites committed — 2026-10-24

Commit `e2a8adc2f17` records the standalone selected-package dependency-origin,
advertised-library and explicit-name-conflict checker with eight native tests
and a passing maintained ATF case. It does not solve versions, inspect actual
ELF loading, authenticate inputs or certify runtime compatibility. Evidence:
`/usr/obj/usr/src/package-closure-qualification-20261024`.

Commit `176db95f6b6` records the package inventory helper and 67-test suite with
its passing maintained ATF case. Review found and fixed a publication gap: pkg's
catalogue builder reads +COMPACT_MANIFEST, while validation used +MANIFEST.
The reader now rejects disagreement in catalogue metadata, including omitted
or changed dependencies, origins, ABI and advertised libraries. Two existing
real-pkg publication regressions also pass with the fix. Evidence:
`/usr/obj/usr/src/security-qualification/package-inventory-review-20261024`.

The inventory remains a read-only archive reader. Retained construction/state
annotations describe inputs for review; they grant no runtime authority and do
not restore BIP enforcement. ACL/xattr and special payload objects remain
unsupported and are rejected. Raw archive timestamps do not certify installed
metadata: pkg may honor manifest timestamp overrides, and package scripts may
change installed files. No installed-system equivalence is claimed.

Both commits use isolated HEAD-based registration changes; unrelated shared
worktree changes remain intact. The application-publication feature itself still
needs its focused commit after these prerequisites. The existing retry4 VM was
polled and remains running; no builder installation success is claimed. These
helper/qualification changes require no new build-bsd command or build input;
the maintained test packaging and ATF registration were updated together.


### Application publication committed — 2026-10-24

Commit `3dc53000589` records the explicit application selection across
build-bsd, configuration/manual, maintained Make targets and combined publisher.
The isolated HEAD-based commit candidates passed warnings-as-errors compilation,
application-selection and existing-plan ATF cases, four application-publication
tests and four existing publication regressions. The candidate Make target also
forwards the explicit selection in a dry run. This commit depends on the two
inventory/closure commits above and excludes unrelated bootstrap/channel/media
changes still in the shared worktree. Evidence and exact candidate hashes:
`/usr/obj/usr/src/application-publication-20261024/application-commit.json`.

Original application identities and archive bytes are preserved. The complete
candidate with applications is checked for payload/metadata collisions and
manifest closure before catalogue signing and latest publication. No production
repository or desktop image was published by these tests. Remote repository
resolution, workstation image construction and installed-system qualification
remain required. The running builder VM remains a separate pending test.


### Offline builder installation passed — 2026-10-24

The existing retry4 completed with PASS, QEMU exit0, no forced termination and
1097.274 seconds elapsed. One2048MiB guest with two virtual CPUs installed all335
selected packages on the separate8GiB virtio UFS disk, with scripts and triggers
enabled. Exact installed names/versions and pkg check passed; Bash5.3.20 and
OpenJDK21.0.12 ran in the installed root. Required account/pkg databases exist,
devfs/nullfs cleanup passed, and the read-only input disk hash is unchanged.
No VM remains running from this attempt.

The retained report and all15 command stdout/stderr pairs were recovered using
read-only fsdb inode/block mappings and dumpfs geometry, without a host mount.
The output image hash still matches the VM receipt. Evidence:
`/usr/obj/usr/src/security-qualification/bazel-builder-install-20261024/retry4-assessment.json`
and `retry4-report/`. The installer log contains an already-registered JavaVM
warning; no hook failure was detected. No lock-order-reversal or panic appears
in this serial transcript. The earlier retry2 UFS/tmpfs reversal remains open;
a different mount layout cannot establish a kernel fix.

This is ordinary offline installation plus Bash/Java runtime evidence, not a
Bazel9 build or a normal boot of the installed system. Inputs include explicitly
identified host-exported test packages and are not authenticated release inputs.
The assessment records post-install UFS data allocation; it does not establish
IO throughput/latency, peak guest memory or performance parity. Next qualify the
pinned Bazel9.3.1 port/build inputs against this installed disk with explicit
resource measurements. Do not substitute the existing Bazel5 pilot result.

### Offline package-manager publication committed — 2026-10-24

Commit `ecdc9310f46` integrates --pkg-package and --pkg-package-sha256 through
build-bsd configuration/manual, maintained Make targets and combined publication.
The target pkg archive is checked for hash, identity, ABI and OS compatibility;
bootstrap-only publication now also validates complete payload and dependency
origin/library/conflict closure before signing. Applications and the bootstrap
can coexist, but cannot supply duplicate pkg identities. Make-interpreted archive
paths are constrained and tested, including dollar signs and whitespace.

Five focused publication tests pass, plus a repeated real signed offline snapshot
check preserving every repository file byte-for-byte. The isolated frontend
compiles with warnings as errors and its expanded ATF case passes CLI/config
forwarding, override, missing-pair/hash, symlink and unsafe-path checks. Candidate
Make forwarding passes. Evidence and candidate hashes:
`/usr/obj/usr/src/bootstrap-publication-20261024/commit.json`.
This publishes explicit inputs; it neither installs a host upgrade nor certifies
provenance from a digest. Unrelated channel/media changes remain uncommitted.


### Next Bazel port build: resource and disk setup — 2026-10-24

Commit `708b9f07c20` adds test-only command resource supervision and ten passing
native tests. Budgets are explicit inputs, not post-hoc acceptance thresholds.
The wrapper fails on exceeded limits, unavailable selected-device measurements
or command errors, kills its command group and retains reports. It records raw
memory counters, filesystem allocation, cumulative iostat, child CPU/RSS and block
operation counts. Sampling and process-tree accounting limits remain explicit;
no IO latency distribution, host memory or performance parity is claimed.

The working-tree daemon-runtime runner now accepts a separate explicit workspace
disk at vtbd3. This preserves the exact8GiB initialized-root copy and its source
hash rather than resizing or reformatting it. A32GiB workspace is the proposed
first Bazel trial capacity, not a measured minimum. Host preflight budgets the
workspace, private root copy, both boot-image files and a configurable reserve.
The workspace is exclusively created0600, attached as a writable block device,
and retained/hash-bound after completion. Four native tests pass, including real
runner rejection before staging when input/output disks are absent. No VM has
qualified this new attachment yet. Evidence:
`/usr/obj/usr/src/bazel-builder-resource-tests-20261024/workspace-receipt.json`.

Workspace changes remain uncommitted because earlier runner input/output disk,
ATF metadata and timeline helpers also remain uncommitted; review those as
prerequisites instead of committing a broad shared diff. The separate initialized
builder fixture is being prepared against the actual pinned ports make package
path. Original blank-disk installation checks stay intact. Source transport,
initialized-fixture review, host QEMU resource measurement and the next2GiB VM
execution remain pending. These are qualification harness changes; production
build-bsd retains its existing package and publication interface.


### Initialized Bazel port build submitted — 2026-10-24

Commit `78d002543ee` adds the host QEMU RSS/VSZ/CPU sampler with five passing
native tests, including an actual live native process measurement and retained
budget violations. Working runner integration requires an explicit host RSS cap
for workspace builds, records samples, and treats observation/budget errors as
failures. Sampling excludes between-sample peaks and host page cache.

Commit `6be4d75f2bc` adds the separate initialized port-build fixture and static
ATF launcher. Six build guards and eight existing installation guards pass; the
launcher builds through the maintained world buildenv. Review tightened source
archive graph checks against non-directory ancestors and link-chain escape.
The initialized root is never formatted. Workspace pre-unmount results explicitly
cannot prove cleanup; final serial and ATF status must establish that separately.

The full pinned ports snapshot and Bazel9.3.1 distfile are in a512MiB UFS input
image, SHA25691e9ed8a2a5d81536cdb9958cc83b51dd6b33fa20f15d92a94fd68b08b729cf7.
The prior successful8GiB installed image is an immutable source for a fresh private
copy. The selected trial adds a32GiB workspace,2048MiB guest RAM, two guest CPUs
(all available guest CPUs used by Make),4096MiB host RSS limit and1GiB host disk
reserve. Build resource budgets are fixed before launch:82800seconds,16MiB free
memory reserve,256MiB available disk reserve and24GiB maximum filesystem growth;
ATF gets86400seconds and outer VM86700seconds for setup/cleanup overhead. These
are trial limits, not measured requirements or performance acceptance baselines.

The runner has been submitted and was observed alive in preflight. No build or
VM PASS is claimed. Command/source bindings, logs and subsequent result are under
`/usr/obj/usr/src/security-qualification/bazel931-port-build-20261024/`.
Launch uses the explicitly staged matching nullfs module at /boot/modules/nullfs.ko;
that configuration correction and both settings hashes are recorded separately.
Do not restart an active process solely because a tool observation returns no
output. Runner prerequisite review/commits remain separate ongoing work. No host
package installation, firmware modification or reboot is authorized by this test.


Follow-up observation: the submitted runner progressed to a live QEMU process
and the guest reached the separate vtbd3 workspace formatting step. Host resource
samples are being retained (an early sample recorded832176128 RSS bytes). This
establishes startup of the test, not successful source extraction or compilation.
Continue polling the existing process/session before considering another VM.


### VM prerequisite helper commits — 2026-10-24

Commit `922dd965041` records the independently reviewed ATF metadata/cleanup
contract parser, serial timing observer, exact-capacity hash-bound disk copier
and additive fixture-root staging helper, with25passing native tests. These
stdlib-only helpers do not certify a system or confer input authentication.
Evidence: `/usr/obj/usr/src/daemon-runner-prerequisite-review-20261024/helper-commit.json`.
The existing Bazel VM's helper bytes were not changed by committing them.
Atomic runtime-init/runner metadata integration is being isolated next; disk,
resource and unrelated ZFS/OES changes must remain distinguishable.

Follow-up guard requirement: the running command explicitly uses2048MiB, but the
runner currently only enforces a512MiB minimum. Before future qualification
launches, add an upper2048MiB preflight bound and a rejection test so an enlarged
RAM input cannot bypass this task's constraint. Do not mutate the active run's
source snapshot or claim that the present generic CLI already enforces that cap.
The existing VM remains under its explicit2GiB guest and4GiB host budgets.

### Bazel builder mountpoint correction (2026-10-24)

The first initialized Bazel 9.3.1 build VM completed with FAIL before compilation.
The fixture incorrectly required mode 0700/0755 for existing mountpoints; the
packaged /dev directory is legitimately mode 0555 (etc/mtree/BSD.root.dist).
The validator now checks root ownership, owner read/search permission, and
absence of group/other write and special permission bits. Canonical-path,
empty-directory, and already-mounted checks remain. Package permissions are
not rewritten to satisfy the fixture. Fourteen native builder/install guard
tests passed, including read-only directories and unsafe permission negatives.
Evidence: security-qualification/bazel931-port-build-20261024/vm under
/usr/obj/usr/src. This is not a Bazel compilation or runtime success.
Frontend review: this fixes the maintained qualification fixture only; no build
input or production backend contract changes require build-bsd options.

Mountpoint correction committed as 54427ad7d4c. A fresh retry is running under
security-qualification/bazel931-port-build-20261024-retry2, using the same
successful installation disk as an immutable source for a new private copy.
The runner now rejects guest memory outside 512..2048 MiB; three native CLI
tests covering thirteen values passed. This supersedes the earlier pending
maximum-RAM guard note. The retry explicitly requests 2048 MiB, two guest CPUs,
and the existing guest resource and host RSS budgets. No compilation success
is established yet. Source hashes and the exact command are in launch.json.

### Qualification runner commits (2026-10-24)

Committed fab46b9dd04 atomically updates the runner and PID1 helper to consume
ATF timeout/cleanup metadata, retain explicit deadline overrides, and require
cleanup success independently of body success. Static compilation and eight
native metadata tests passed. Four deliberate lifecycle probes are included;
their actual VM negative-control execution remains pending. Process groups do
not contain descendants that create new sessions.

Committed fdc3ac8d8a9 enforces 512..2048 MiB in the runner. Three native CLI tests
cover thirteen values and verify rejection before image creation. Both commits
were staged from isolated candidates, without changing the active retry's
working source files. Hash-verified runner snapshots are retained in the retry's
runner-source directory. The retry was observed live at workspace preparation;
that observation does not establish compilation success.

Frontend review: these commits improve the maintained VM qualification backend;
production build-bsd world/kernel/package actions remain Make-backed. No new
production input or build-backend selection is introduced.

### Bazel system graph prerequisites (2026-10-24)

Source review of the current pilot found WORKSPACE-only setup and native C/C++
rule calls. These are not evidence of Bazel 9 compatibility. The pinned 9.3.1
distribution contains rules_cc 0.2.17 registry metadata and its source archive
in the content-addressed cache. Offline inspection verified the registry hashes
against MODULE.bazel.lock and the archive against source.json integrity. Actual
public export files are retained under
/usr/obj/usr/src/bazel9-rules-cc-audit-20261024 with receipt.json. This establishes
source/API availability only; the consumer module closure and actual Bazel 9
analysis/build remain unqualified. No compatibility bypass flags are proposed.

The source-audited next graph plan is
/usr/obj/usr/src/bazel-system-graph-plan-20261024/plan.json. After module migration,
the next real component is libmd with maintained source selection, generated
mdXhl sources, assembly, per-file flags, symbol versions and installation
metadata. A staged Make-built SDK must remain identified as a bootstrap input;
a partial library graph is neither a complete world nor a complete pkgbase
package. Kernel compilation requires a separate freestanding toolchain/action
configuration and its real config/generated-header dependency graph.
Frontend review: keep existing build-bsd world/kernel/package actions Make-backed
until a complete supported graph and install/package comparisons pass.

### Offline Bazel dependency cache export (2026-10-24)

The maintained tools/build/bazel/repository-cache.py accepts an explicit pinned
distribution archive and exports its content-addressed repository cache. It
verifies each entry, rejects duplicate/unsafe members, and preserves failed
exports separately from the completed cache. Five native tests passed. An
actual export of the pinned Bazel9.3.1 distribution verified 451 entries totaling
98,192,124 bytes; receipt and commit binding are under
/usr/obj/usr/src/bazel9-offline-cache-20261024. This supplies cache inputs only.
It does not establish that a new consumer module graph resolves offline or that
Bazel9 executes successfully. No module versions are selected by this helper.
Frontend review: qualification input preparation is documented alongside the
maintained Bazel helpers. Production build-bsd backend selection remains Make;
module/toolchain inputs must be integrated before exposing a Bazel9 system build.

Bazel build retry2 reached ordinary ports extraction, patching, dependency checks
and the do-build recipe, then failed before javac: env interpreted -J-Xms128m
as the executable. The port's BAZEL_JAVAC_OPTS assignment is not shell-quoted
when an unquoted multiword make-variable override is supplied. This is a port
argument-transport bug, not a memory-budget failure. Command stdout/stderr and
resource receipt were extracted read-only from retained workspace.img into
retry2/command-evidence using fsdb block mappings. Guest cleanup and shutdown
completed. Compilation/runtime qualification is still incomplete.

The ports argument-transport fix is committed in the selected 5BSD ports tree as
d4fe05d37. BAZEL_JAVAC_OPTS now uses Make's :Q at the shell boundary; the aarch64
default stores arguments without embedded shell quoting. Native checks of the
actual do-build dry-run assignment plus env transport passed for empty and
multiword overrides. A new committed ports archive and manifest binding must
be constructed for the next VM; the failed retry's inputs are retained. The
runner finished with exit1, and no VM is running from that retry.

### Updated ports input and third Bazel build attempt (2026-10-24)

Retry2 final evidence confirms unchanged input and builder-source disks, clean
shutdown, no resource-budget failure, and the diagnosed environment quoting
error before Java compilation. VM elapsed430.844seconds; the measured ports
command lasted40.792seconds. Maximum observed QEMU RSS was2,343,120,896bytes
within its4GiB host budget; these samples exclude host page cache and can miss
between-sample peaks. This is failure diagnostics, not performance acceptance.

A fresh complete ports archive from committed fix d4fe05d37 was validated and
packaged into a new512MiB read-only input disk under
/usr/obj/usr/src/bazel931-build-plan-20261024-quoted-options. preparation.json
binds ports commit, archive, original Bazel distfile, manifest and input disk.
The next run is security-qualification/bazel931-port-build-20261024-retry3;
launch.json records the exact command and source hashes. It retains the same
2048MiB guest, two CPUs,32GiB workspace and explicit resource budgets.
No prior failed artifacts were overwritten. The run is pending, not qualified.
Frontend review: the production port is fixed at its actual recipe boundary;
no one-off compile command or Make dependency bypass was introduced.

Libmd candidate review is in progress under
/usr/obj/usr/src/bazel-libmd-graph-20261024. Native generator comparisons cover
16 generated C/manual outputs in both profiles; selected source sets contain
28 sources with assembly and23 without. These checks are not Bazel compilation.
Root review found a fixed include-directory list that discarded maintained
source include flags. Before integration, derive those mappings from actual
metadata, retain ordering, reject unsupported paths, and exercise an added
include directory. Matching buildenv/objtop and Make include-closure binding
are also required. The candidate has not replaced production source or frontend
backend selection. Retry3 QEMU was observed live after boot-image preparation.

### Installation artifact and offline closure review (2026-10-24)

The maintained bsd.lib.mk contract uses SHLIB_NAME_FULL with MK_DEBUG_FILES=yes:
objcopy extracts DEBUGFILE and creates the installed SHLIB_NAME with a GNU
debug link. A raw Bazel cc_binary shared output cannot be treated as the final
installed library. These transformations, header/manual installation and package
tags must precede signing and match independent Make staging. Source hashes and
requirements are recorded in
/usr/obj/usr/src/bazel-installation-contract-review-20261024/review.json.

The pinned distribution cache is not a standalone consumer closure: its lock
records protobuf33.4 source metadata, but not protobuf27.0 requested minimally
by rules_cc; features1.28/platforms0.0.10 have module metadata but no source
records, while the distribution selected newer versions. Resolve and explicitly
pin the actual consumer dependency set, acquiring missing inputs as necessary.
Do not infer offline build success from the451 verified cache entries.
Retry3 remains live under its original handle and budgets. These reviews do not
change production build-bsd backend selection or claim compilation success.

### Maintained builder disk/resource runner integration (2026-10-24)

Committed ef890425674 integrates read-only pinned input disks, private blank or
source-seeded output disks, blank workspace disks, retained fixture writes,
additive fixture roots, host RSS budgets and serial observations. Thirty-seven
native checks and a static build of runtime/probe binaries passed; evidence is
/usr/obj/usr/src/daemon-runner-disks-review-20261024/review.json. Staging used
isolated candidates and verified all active working files unchanged. ZFS and
anonymous-mount experiments were excluded. Existing successful package-builder
VM evidence and failed Bazel attempts remain scoped as recorded above. Explicit
retention, raw-write refusal, output-byte and ATF lifecycle negative-control
VM cases remain queued after the active Bazel run; native tests do not replace
those controls. Frontend review: this commits the maintained qualification
backend already used for build inputs, without adding a production build-bsd
backend or changing publication/signing semantics.

### Java bootstrap crash and controlled emulation diagnostic (2026-10-24)

Retry3 passed ports extraction/patch/dependency checks and started javac. It
failed with a JVM SIGBUS in C1 CompilerThread0, then aborted and dumped core.
The JDK report records approximately500MiB free guest memory; the resource
wrapper reports command failure, not a budget violation. The cause remains
unresolved. The guest shut down cleanly; original input and builder source
disks were unchanged. Retained command logs, samples and hs_err_pid386.log were
extracted read-only using fsdb mappings into retry3/command-evidence; assessment
records their hashes. No Java/Bazel runtime or package acceptance is claimed.

A single controlled run is started at
security-qualification/bazel931-port-build-20261024-tcg-single. It changes only
TCG threading to single, keeping two guestCPUs,2048MiB guestRAM, JDK/JVM options,
sources and budgets unchanged. This tests sensitivity to emulator threading; it
is not a production default change or permission to disable JIT. Even a passing
diagnostic would require explanation and qualification of the normal runtime.

Generator review also rejected rewriting make -n shell text. Shared libmd
generator helpers are being compared against original maintained outputs before
integration. The inactive md2.3 rule was observed to fail already in the original
source because md2.copyright is absent; it is not part of the current MAN set.
No removal or success claim for that inactive target is made.

### Bazel bootstrap error propagation — 2026-10-24

The pinned Bazel 9.3.1 bootstrap quiet-mode run helper lost compiler failure
status by reading `$?` after shell negation. The ports patch now captures the
original status in an ordinary if/else branch. The maintained
`tools/build/bazel/bootstrap-status-test.py` reproduces the original failure
and passes eight verbose/quiet status cases after applying the real patch.
Evidence: `/usr/obj/usr/src/bazel-bootstrap-exit-status-20261024/`.
This fixes error reporting, not the observed JVM C1 compiler crash.
The existing single-thread TCG diagnostic remains separate and uses its
frozen pre-fix inputs. Production build-bsd/backend selection remains Make;
no new frontend option or production build contract is introduced here.
Full Bazel world, kernel, installation and package parity remain unqualified.

### Shared Make/Bazel generator review — 2026-10-24

The libmd shared-generator candidate compiled and linked `libmd.a` and
`libmd.so.7.full` with the maintained native amd64 Make buildenv, using all
16 logical CPUs in isolated output. Source copies were hashed before and
rechecked after the build. Evidence and commands:
`/usr/obj/usr/src/libmd-shared-generators-compile-20261024/receipt.json`.
This is Make compile/link evidence only, not Bazel compilation, installed
package parity or runtime qualification. Candidate changes are still under
review before landing. The frontend continues selecting the Make backend;
shared generation requires no new build-bsd option or signing policy.

A separate ports input snapshot containing bootstrap status fix c434504e0
was prepared at `/usr/obj/usr/src/bazel931-build-plan-20261024-bootstrap-status/`.
Its receipt binds the full committed ports archive, pinned distribution,
input manifest and transport image. It has not been used for a VM build yet;
the running single-thread TCG diagnostic retains its original inputs.

The reviewed shared libmd generators are now landed with their standalone
regression test and README usage. Frozen candidate hashes matched the actual
Make compile/link inputs. Both profiles retained all 16 generated-file hashes;
three standalone failure/retry tests and two path guards passed. The Bazel
graph remains separate and unqualified; production build-bsd stays on Make.

### libmd Make installation baseline — 2026-10-24

`/usr/obj/usr/src/libmd-make-install-20261024-r3/` records successful
all-target compilation (16 CPUs), maintained distrib-dirs, and private
component installation from the actual landed `/usr/src/lib/libmd` layout.
The install command is queried from Makefile.inc1 IMAKE_INSTALL with NO_ROOT,
DB_FROM_SRC and BUILD_PKGS, retaining source account metadata and SHA256.
All 169 payload files matched METALOG hashes/sizes; three symlink targets
matched. Headers, manuals, static/shared libraries, separate debug files and
tests retain their package tags. The shared object contains its debuglink,
and tests land under `/usr/tests/lib/libmd`. This is not a pkg archive build,
Bazel parity or runtime result. NO_ROOT logical ownership remains metadata;
host staging files are deliberately owned by the builder.

Earlier attempts are retained: r1 omitted the top-level install flags and
failed chown; r2 staged from a copied source directory and produced incorrect
test RELDIR paths. Neither is accepted as the installation baseline. Future
Bazel installation must preserve source-derived layout and top-level install
configuration. No production frontend/backend change was required for this
qualification; build-bsd continues to select Make.

### Reusable Make installation reference candidate — 2026-10-24

`install-reference.py` and `install-reference-test.py` are review candidates
under `/usr/obj/usr/src/bazel-libmd-graph-20261024/commit-candidates/tools/build/bazel/`.
They reuse the candidate BuildEnvironment profile/SDK checks and query actual
top-level install settings. The native build/install passed at
`/usr/obj/usr/src/libmd-maintained-install-reference-20261024/receipt.json`.
Its 2435 path/type/owner/group/mode/flags/tags/link metadata entries match r3;
this comparison excludes contents, sizes and timestamps. Four CLI guards
passed for evidence reuse, copied source, mismatched profile and invalid jobs.
These candidates are not landed or exposed by build-bsd yet; frontend/manual
integration and review remain required before treating them as supported.
They establish a Make reference only, not a Bazel artifact adapter or full
hermetic input closure, package archive or runtime qualification.

The installation-reference candidate was revised after review: receipts now
bind both the main script and imported environment helper, and recursive
source directories receive separate private object directories. The initial
fixed MAKEOBJDIR flattened library/test objects, so its success must not be
used as evidence for arbitrary recursive components. The corrected candidate
passed at `/usr/obj/usr/src/libmd-maintained-install-reference-20261024-r2/`;
library and test object directories were checked separately and all 2435
non-content installation metadata entries still matched the baseline. Six
CLI guards passed, including output symlink escape and Make/control-character
paths. Frontend integration and landing remain pending.

The Make installation reference is now integrated into maintained
`build-bsd bazel-test`, with distinct plan/result metadata and manual updates.
End-to-end installed Bazel5 pilot plus Make-reference staging passed at
`/usr/obj/usr/src/bazel-install-reference-frontend-run-20261024/receipt.json`;
inputs were rechecked and the nested reference receipt is hash-bound.
Four qualifier boundary tests and six installation-reference guards passed.
Both working-tree and exact-commit frontend plan ATF cases passed.
Bazel9, runtime, complete world/kernel/package and install parity remain
unqualified. No host installation or backend default change occurred.


### Bazel 9 toolchain runtime declarations — 2026-10-24

The isolated libmd graph candidate now declares each execution tool's inspected
runtime separately and includes awk runtime files in version-map generation.
A fresh source/profile export and SDK stage is recorded at
`/usr/obj/usr/src/bazel9-libmd-runtime-r3-20261024/validation.json`:
5405 input hashes and 5326 toolchain files were verified; three native runtime
inspection/declaration tests passed. The compiler, linker and archiver were
observed to be static; shell/generator tools have dynamic runtime dependencies.
Staging those libraries does not redirect the execution host's ELF loader.
The previously observed guest libc/libsys/loader mismatch remains an execution
qualification concern, not a reason to replace guest libraries silently.

This is fresh staging evidence, not Bazel 9 analysis, compilation or package
parity. Actual aquery must confirm toolchain selection and action input size;
cc_toolchain all_files is still broad. Use --strip=never and inspect raw ELF
debug sections before the maintained Make debug-splitting/install step.
The Bazel 9 port build remains running in the existing 2 GiB QEMU guest; no
second VM was started. No successful Bazel 9 build is established by this entry.

The maintained build-bsd bazel-test frontend and Make installation reference
remain the supported qualification path. The candidate graph is not yet a
production backend; this preparation does not change frontend inputs, backend
selection, signing or publication. The next integration gates are actual
Bazel 9 resolution/analysis/build, the external-artifact install bridge and
comparison against Make installation/package metadata and transformed bytes.


### Static generator tools and test installation coverage — 2026-10-24

Six generator executables (sh, sed, cat, mv, rm and awk) were built with the
maintained Make component rules, NO_SHARED=yes, WITHOUT_TESTS=yes and all 16
host logical CPUs. They remain under /usr/obj; nothing was installed on the
host. Their static native execution generated all 16 planned libmd C/manual
outputs byte-for-byte equal to the maintained Make reference, recorded in
`/usr/obj/usr/src/bazel-static-execution-tools-20261024/generator-comparison.json`.
This initial build is preparation evidence, not a supported frontend action.

Explicit tool configuration selects those binaries in a fresh workspace at
`/usr/obj/usr/src/bazel9-libmd-static-tools-20261024/`. Its validation.json binds
5405 checked inputs and 5325 staged files. Three runtime-declaration tests
passed with this selection and also with the earlier dynamic-tool selection.
Tests now compare recorded runtime sets without requiring dynamic awk or a
particular LLVM library basename. All six generator runtime sets are empty;
llvm-objdump still has dynamic dependencies. No full toolchain hermeticity,
guest runtime, Bazel9 build or performance claim follows from these checks.

The same workspace's test-install-contract.json is derived from maintained
lib/libmd/tests Make metadata. Installation requires 14 digest drivers, the
libmd_test ATF harness, reference files and debug handling under
/usr/tests/lib/libmd. The candidate graph currently lacks those test targets.
They must be covered before full component installation parity; silently
omitting the tests or asking Make to compile missing drivers is not parity.
Make remains the production backend and normal frontend behavior is unchanged.

The reusable isolated static-execution-tools.py candidate now accepts an explicit
format-1 JSON mapping from tool names to maintained source components/binaries.
A real cat build passed at
/usr/obj/usr/src/static-execution-builder-review-20261024/cat-build-r2/receipt.json,
including before/after checks of the actual static-build Make include closure
in its private object directory. Five rejection/ELF tests passed. This helper
is still a candidate; it is not exposed as a normal frontend action and has not
qualified a complete transitive source/header/SDK closure or guest execution.


### Bazel action-cache review — 2026-10-24

The cache acceptance matrix is now maintained in
`tools/build/bazel/CACHE-QUALIFICATION.md`, linked from the Bazel README. It
requires actual action/execution evidence for no-change rebuilds, cache restore,
source/header/generator/tool/profile changes, workspace relocation and resource
costs. Repository download caching is explicitly separate from action caching.

Candidate fixes from review: high-level C generators no longer declare unused
cat executable/runtime inputs; custom generation/version-map actions set
LC_ALL=C without inheriting the default shell environment; the library rule
accepts the .inc/.def header types already supported by the exporter. The
candidate rejects unsupported ARFLAGS before emission; the maintained -crsD
policy matches pinned rules_cc's rcsD archive semantics. The candidate toolchain
no longer unconditionally injects -znow/-zrelro; maintained LDFLAGS controls
those options. Three runtime-declaration tests and two archive/link-policy
tests passed, including disabled/enabled hardening and unsupported archives.

These edits are isolated candidates, not yet a qualified Bazel9 action graph.
Existing staged workspaces predate these edits. Actual aquery/action-cache runs
remain required; no caching or performance improvement is claimed from native
syntax/declaration tests. The source snapshot exporter also needs maintained
frontend refresh/invalidation integration before it can serve incremental
user builds. Make remains the production backend; no normal frontend inputs,
installation, signing or publication behavior changed in this review.


### Larger Bazel builder authorized — 2026-10-24

The user superseded the old 2 GiB limit for Bazel bootstrap builds: 8 vCPUs and
24 GiB guest RAM, or native host builds, are permitted. The shared runner now
has an explicit bazel-builder resource profile; default fixture bounds remain
2 GiB/four CPUs. Four CLI tests and eleven builder resource-budget tests passed.
The old single-thread diagnostic was stopped with its evidence retained. The
replacement launch is recorded under
/usr/obj/usr/src/security-qualification/bazel931-port-build-20261024-eight-24g/.
This is a capacity change, not a JVM crash fix or a completed build result.
The prior crash resolves to Method::klass_name(), dereferencing corrupted JVM
metadata during C1 compilation; its origin remains unresolved.

Normal build-bsd production backend selection and secureboot qualification
limits are unchanged. This change updates the maintained builder runner,
budget helper, their tests and documentation; it does not enable a Bazel world,
kernel or package backend in the frontend.

The eight-vCPU/24-GiB builder failed after about102 seconds in the measured
package command; the guest shut down cleanly after about427 seconds total.
Retained stderr reports OpenJDK21 SIGILL in C1-compiled
ZipFileSystem$IndexNode.normalize. The resource report says measured command
failed, without a budget violation. Thus extra RAM/CPUs did not resolve JVM
stability. Logs and assessment are retained under the eight-24g run directory.
The next discriminating step is a native host comparison with the same JDK
and source, already authorized by the user; no native build success is claimed.


### Native Bazel bootstrap comparison — 2026-10-24

The user-authorized host comparison is running under
/usr/obj/usr/src/bazel931-native-comparison-20261024, using the same verified
ports/source snapshot as the eight-CPU guest and staged OpenJDK 21.0.12+8-2.
The maintained ports framework passed STRICT_DEPENDS=yes checks without
installing dependencies. All 16 host logical CPUs are selected, with a 4 GiB
javac heap and 12 GiB Bazel action-memory input. The Java bootstrap completed
and the Bazel self-build began executing actions. Final build success remains
pending in receipt.json/build.log; host and guest kernels differ, so this does
not by itself prove an emulation defect.

The explicit JAVA_HOME points at the staged JDK under /usr/obj. This is a
native diagnostic/qualification executable, not a redistributable package
configuration. No host installation or publication is authorized by this run.
The new guest hs_err_pid384.log was extracted read-only with retained inode/
block mappings. Its SIGILL occurs at entry+4 inside a newly patched jump;
matching the exact observed instruction bytes against HotSpot patching and
QEMU translation is the next crash investigation step.

### Native Bazel 9 library milestone — 2026-10-24

Bazel 9.3.1 self-built on the host in 661 seconds using 16 CPUs. Actual libmd
analysis and compilation then passed (88 actions), with results under
/usr/obj/usr/src/bazel9-libmd-host-20261024/. The comparison against existing
Make objects found matching archive members and 251 versioned exports, with
raw debug information retained. An unchanged rebuild reported 87 local
action-cache hits and no executed compiler/linker actions. Runtime, mutation,
cache restoration, installation, world/kernel and package parity remain open.

Candidate fixes: valid Starlark load ordering, explicit staged JAVA_HOME, and
optimized configuration for both archive variants. General archive-variant
handling remains unfinished. Broad module-extension resolution exposed an
unavailable Python 3.11 runtime; actual target closure resolved through aquery
and the build enforced the resulting lock. No offline-host claim is made.

The trailing bootstrap host_platform error was its output-directory query,
which omitted the build's explicit platform flags and silently fell back. Two
maintained ports patches now forward those flags and propagate query failure.
Focused argument/status tests pass; full bootstrap with these patches remains
pending. No installed software was changed. The normal build-bsd production
backend remains Make; these candidate checks do not yet justify changing it.

### Native libmd runtime and cache checks — 2026-10-24

All 14 existing maintained Make-built digest drivers passed against the
Bazel-built shared library. Loader traces verified selection of the private
library. This is runtime evidence, not Bazel-built test/package coverage.

Private MD4 source and RIPEMD included-header mutations each rebuilt exactly
two consuming object variants, two archives and the shared library; the digest
output changed as expected. Inputs were restored and rebuilt. Adding an
unrelated workspace file executed no build actions. All 14 digest drivers
passed again after restoration. Original /usr/src sources were not mutated.

A new output base seeded an explicit action disk cache (79 executed actions).
A second fresh output base restored all 79 from disk cache; structured execution
logs identify every action as a disk cache hit. Both archives and shared-library
SHA256 values matched. This is distinct from the earlier unchanged local cache
check. It does not qualify remote cache, workspace relocation, all mutation
classes, source-export refresh or complete performance/resource regressions.

Evidence: /usr/obj/usr/src/bazel9-libmd-host-20261024/{runtime-r1,
source-mutation-r1.json,header-mutation-r1.json,post-mutation-runtime.json,
disk-cache-comparison-r1.json} and the corresponding execution/event logs.
Qualification command scripts are retained alongside results; these explicit
local evidence configurations are not a replacement build frontend. No new
production input or backend is exposed; build-bsd remains on maintained Make.
Archive variants outside optimized mode are still being addressed separately.

### Repeatable digest runtime qualification — 2026-10-24

Added tools/build/bazel/libmd-runtime-check.py with explicit library, SONAME,
Make-derived driver inventory, test directory and output inputs. It verifies
loader selection, exact digest outputs and input stability, retaining a failure
receipt when a test fails. All 14 existing drivers passed; a wrong-reference
negative control failed as intended. Bazel-built driver/test graph and packaging
remain unfinished; the helper is not presented as their replacement. Frontend
integration stays coupled to actual candidate-library integration.

### Bazel-built digest drivers — 2026-10-24

The maintained libmd tests Makefile now exposes LIBMD_TEST_SOURCE_<program>
and uses that mapping in its existing copy rule. Actual Make generation of
MD4 and SHA-512/256 driver sources was checked in a private object directory.
The candidate libmd-test-plan.py queries the selected Make build environment
for PROGS and each driver's source, effective flags, LIBADD and BINDIR. Its
14-driver/four-source export binds profile/compiler/Make-include/source inputs;
five rejection guards passed. No family list or source recipe is scraped.

The candidate graph emitter accepts --test-plan, revalidates metadata/source
hashes and emits the 14 binaries. Drivers preserve maintained PIE and dynamic
linking to the candidate shared library, with a declared SONAME symlink. An
initial static-archive attempt failed PIE relocation checks and was corrected;
failed logs remain. All 14 Bazel-built drivers now pass maintained reference
outputs, both with explicit loader verification and with Bazel's generated
runtime paths without LD_LIBRARY_PATH. An unchanged build reports 138 action-cache
hits and no compilation/linking. Evidence:
/usr/obj/usr/src/bazel9-libmd-drivers-20261024/ and
/usr/obj/usr/src/bazel9-libmd-drivers-runtime-20261024/.

The maintained runtime helper accepts optional --references for reference
files kept separately from Bazel-built binaries. Reference-file and ATF harness
generation are still Make-provided; no installation/package parity is claimed.
Candidate frontend integration follows complete artifact/staging qualification;
normal build-bsd remains on Make. Test source metadata is consumed by normal
Make now, so the existing workflow retains the same source-copy behavior.

### Shared digest test data and generator — 2026-10-24

Converted 14 libmd test references from Make echo recipes into maintained .ref
source files. They were generated first using the original recipes in a fresh
private object directory and copied byte-for-byte. Make's private file-install
stage retains identical reference bytes and logical ownership metadata using
the top-level IMAKE_INSTALL/NO_ROOT contract. References are no longer CLEANFILES.
All 14 Bazel-built drivers also pass these source references.

The ATF echo loop is now gen-tests.sh, taking the maintained DIGESTS list as
explicit arguments. Make uses LIBMD_TEST_GENERATOR to name it; its emitted .sh
body matches the original byte-for-byte and invalid digest names fail. The
normal bsd.test.mk interpreter wrapper remains distinct from this body.

Candidate test inventory now derives reference paths from the package FILES
metadata and verifies original/staged hashes. Kyuafile is recorded separately
from static reference data. Generator export and Bazel harness actions remain
in progress; this does not establish full test installation or package parity.
Evidence: /usr/obj/usr/src/bazel-libmd-reference-conversion-20261024/ and
/usr/obj/usr/src/bazel9-libmd-source-refs-runtime-20261024/.
Normal Make uses the shared data/generator now; build-bsd needs no new user
option for this source refactoring. Its Bazel production backend remains gated
on complete candidate staging and installation qualification.

### Declared Bazel ATF harness body — 2026-10-24

The candidate now exports the shared gen-tests.sh path/hash, maintained DIGESTS
arguments and ATF target/body/install metadata. The graph declares its shell,
runtime and stdout-redirect tool as inputs, generates the ATF body through a
BSDLibmdTestBody action, and includes the source references in test_references.
Metadata and snapshot hashes are revalidated before emission.

Actual Bazel execution generated a body byte-identical to the maintained Make
output. All 14 cases passed through the real host ATF interpreter using the
Bazel-generated body, Bazel-built drivers and declared source references. The
first run exposed ATF's requirement that the harness itself be present in its
source directory; the second private staging included it and passed. Both
results remain under /usr/obj/usr/src/bazel9-libmd-drivers-20261024/
(atf-runtime and atf-runtime-r2). No host installation or VM was performed.

This validates test execution, not final test installation. bsd.test.mk's
executable interpreter wrapper, Kyuafile, debug splitting, modes/ownership,
package tags and complete installed inventory still need the installation
bridge. Runtime interpreter is the installed host ATF implementation, explicitly
recorded in commands. No Bazel-native test rule or hermetic ATF runtime is
claimed. Frontend remains on Make until the complete candidate install contract
is verified; shared test inputs continue working in the normal Make workflow.

### Base-system Bazel end state — 2026-10-24

The intended endpoint is Bazel ownership of base/world and kernel compilation,
linking, artifact transformations and staging. Maintained make buildworld and
make buildkernel may serve as compatibility entry points delegating to that
qualified graph; make packages must consume its complete staged artifacts.
BSDFoundry will drive the same backend. Ports retain their Make build workflows.
Those world/kernel delegations are not implemented by the libmd pilot.

Make metadata queries and installation comparisons are migration tools, not
the final native Bazel architecture. Production Make remains selected until
complete parity and resource/performance gates pass. Current work therefore
implements declared Bazel objcopy/strip actions, with explicit tools, inputs,
outputs and debug output groups, rather than completing a permanent Make
installation backend. Existing Make rules remain authoritative comparisons.

The library debug extraction/debuglink outputs already match maintained Make
transformations byte-for-byte when both consume the same verified raw library.
The comparison marked only that raw artifact .MADE and disabled compiler/linker
commands. Evidence: /usr/obj/usr/src/bazel-libmd-debug-parity-20261024/.

Install review also removed Bazel-generated runfile search paths from the
candidate toolchain. Explicit maintained LDFLAGS remain authoritative. The
initial rule-level feature disable was rejected by rules_cc because its legacy
action config implies that feature; the configured toolchain now supplies the
feature without automatic runfile flags. Actual relink passed, all 14 drivers
have no RPATH/RUNPATH, and all 14 runtime tests pass with explicit candidate
library selection. The earlier runtime receipt following failed analysis was
marked as testing old artifacts, not qualification of the new policy.

### Native libmd installation artifacts — 2026-10-24

The isolated candidate now emits explicit debug extraction, debuglink, and
installation-strip actions for the library and all 14 maintained digest drivers.
Driver names and debug/strip choices come from the checked Make configuration
export. Tool executables and runtime inputs are declared. Debug files are exposed
through output groups. Unsupported transformation policies remain errors.

Evidence: `/usr/obj/usr/src/bazel-libmd-native-artifacts-20261024/`.
The fresh native Bazel 9.3.1 build passed with 16 jobs. All 15 artifact sets
matched maintained Make debug transformations and actual `install -s` bytes
using identical raw inputs. Compilation/linking commands were disabled during
that transformation comparison. All 14 stripped drivers passed the maintained
reference vectors with loader tracing proving selection of the stripped Bazel
library. Installed ELF outputs have no automatic RPATH/RUNPATH, no `.symtab` or
`.debug_info` sections, and retain their debuglink. Full installation ownership, links,
package metadata, and ATF executable-wrapper parity remain pending.

An unchanged build reported 225 action-cache hits and no external actions.
`time -l` recorded the fresh build at 6.15 seconds, 49.31 user CPU seconds,
10.82 system CPU seconds, 1,060,296 KiB maximum RSS, and 3/2478 block input/output
operations. Warm execution was 3.45 seconds, 28.52/5.06 CPU seconds, 849,800 KiB
maximum RSS, and 2/269 block operations. These are single-run process accounting
observations, not aggregate memory measurements or a Make performance comparison.
Disk accounting is recorded separately and includes the staged SDK/toolchain.

Frontend review: build-bsd still selects the maintained bsd-make backend;
its existing bazel-test action is separate qualification. No production backend
switch is justified by this component-only evidence. Native staging/metadata,
full world/kernel builds, pkgbase and hardware publication qualification remain
required before selecting Bazel by default. No host installation or VM was run.

### Native ATF executable wrapper — 2026-10-24

The candidate now builds the ATF executable wrapper as a declared Bazel action,
using a declared cat executable/runtime and stdout launcher. The target-system
interpreter is exported from `ATF_TESTS_SH_INTERPRETER` in maintained atf.test.mk;
its default remains `/usr/libexec/atf-sh`. The change preserves existing Make
output byte-for-byte. Exported script ownership/mode/destination remain available
for the forthcoming native installation manifest. Configured sed transforms
still fail explicitly until supported.

Evidence: `/usr/obj/usr/src/bazel-libmd-wrapper-20261024/`. A fresh native build
passed. Its executable wrapper matches both the prechange installed Make wrapper
and a newly generated Make wrapper. All 14 ATF cases passed through the executable
wrapper with the stripped candidate library selected via a private loader path.
The installed host ATF interpreter and utilities were used: this is not yet a
hermetic `bazel test` runtime. The launcher regression test covers ordinary and
executable outputs, literal arguments, missing generators, partial-output failure
status propagation, and usage errors.

The stdout launcher gained a backward-compatible `--executable` option; existing
body/version-map generation passed in the same fresh build. Frontend assessment:
this remains candidate qualification, with no new production build input or
backend selection. build-bsd remains on bsd-make pending full integration gates.
Next work remains native installation/metadata/Kyuafile support, a declared ATF
test runtime, complete world/kernel coverage, and packaging/publication parity.

### Bazel completion plan clarification — 2026-10-24

The maintained tools/build/bazel/README.md now explicitly requires native
`bazel test` integration and enforced FreeBSD sandbox qualification, including
negative isolation tests and CPU/memory/disk-I/O/disk-footprint comparisons.
Processwrapper action success is not proof of host filesystem/network isolation.
The next-version milestone follows a working system build on selected 9.3.1;
the request mentioning Bazel 6 needs clarification before choosing an older
compatibility target or a newer release. These gates precede a production default
switch. Current standalone ATF tests remain comparison evidence, not Bazel test
completion. Host-only work continues; BIP remains out of scope.

Version clarification: the requested subsequent target is the latest stable
Bazel release at qualification time, after the system builds with the current
selected release. No Bazel 6 downgrade/compatibility milestone is requested.
Bhyve VM qualification is permitted when needed; privileged host setup still
requires a root-run helper because the current agent account is uid 1001.

### Native test installation payload metadata — 2026-10-24

The isolated candidate exports effective no-root Make installation policy and
emits typed Bazel installation-file providers, a manifest with declared payload
files, and a native Kyuafile. All 44 test payload destinations, owners, groups,
modes and package/debug tags match the actual maintained Make METALOG. All 16
non-ELF payloads also match byte-for-byte (references, wrapper, Kyuafile).
Evidence: `/usr/obj/usr/src/bazel-libmd-wrapper-20261024/install-manifest-parity.json`.
This does not yet stage a complete installation: directory metadata, library
payloads, links, complete staging and package output remain pending. The first
analysis rejected an attempted `tags` attribute because Bazel reserves it;
installation tags now use the separate `install_tags` attribute. The failed run
is preserved, and the corrected real build passed. build-bsd remains Make-only
for production; this candidate adds no production frontend backend selection.

### Native Bazel ATF tests and cache qualification — 2026-10-24

The libmd candidate now has 14 real Bazel test targets and a `libmd_tests` suite.
Both `bazel test //:libmd_tests` and `bazel test //...` passed. The latter found
all 14 tests plus 161 non-test targets in this component workspace; this is not
system-wide test coverage. A static native runner uses Bazel test environment
and temporary storage, launches one ATF case, and propagates process/status-file
failure. Non-pass ATF statuses currently fail conservatively: general skip,
expected-failure and richer ATF metadata semantics need qualification before
expanding to arbitrary suites.

Each case declares its body, driver, reference, shared-library inputs and
runtime tools through runfiles. Static ATF interpreter/checker, dirname, tr and
diff were built from maintained Make sources in private object directories.
The static shell is the previously qualified execution tool. This Make-built
runtime is bootstrap input, not final Bazel coverage of those base programs.
Loader traces for all 14 drivers confirmed every reported shared library came
from declared runfiles. The host ELF interpreter/kernel remain execution
prerequisites, and processwrapper execution does not establish enforced host
filesystem/network isolation.

Evidence: `/usr/obj/usr/src/bazel-libmd-wrapper-20261024/atf-test-*.events.json`,
`atf-cache-qualification.json`, `atf-loader-selection.json`; static runtime build:
`/usr/obj/usr/src/bazel-atf-runtime-20261024/receipt.json`.
An unchanged run reused all 14 test results. Mutating only the staged MD4
reference reran/faulted only MD4 (Bazel exit 3), with the other 13 cached.
The fixture was restored in a finally block; the restored suite passed.
Build Event Protocol summaries were checked for exact case/status/cache counts.
CPU, memory and block-I/O accounting accompanies the actual test runs.

Frontend review: production remains bsd-make. The isolated candidate test
staging/emission still needs consolidation into the maintained qualification
frontend; this new test suite is not yet run by build-bsd's existing bazel-test
command. Native installation directories/library payloads, full world/kernel,
packages/publication, sandbox enforcement and subsequent latest-stable release
qualification remain open gates. No VM or host installation was performed.

### Integrated candidate ATF emission — 2026-10-24

`libmd-build.py` now accepts `--test-runtime` alongside `--plan`, `--test-plan`
and `--install-plan`, so normal candidate graph regeneration retains native
Bazel tests. The runtime configuration is JSON with `format: 1`, an absolute
`receipt` path for the verified static tool build, and explicit absolute
`libraries` paths within the selected SDK. Runtime SDK/target/profile must
match the library plan. Tool build inputs, include closures, tool bytes and
staged copies are hash-checked. The old standalone append-only helper was
retired; its original source remains with the earlier qualification evidence.

Regeneration initially exposed a real read-only SDK copy failure; the fixed
staging copies into a temporary file and atomically replaces each managed
output, preserving source file permissions. Repeated full graph emission now
produces an identical BUILD hash. `bazel test //...` then passed with all 14
test results cached and 325 action-cache hits. Evidence:
`/usr/obj/usr/src/bazel-libmd-wrapper-20261024/atf-emission-idempotence.json`,
`atf-integrated-r2.events.json` and `atf-integration-inputs.json`.

Reusable `atf-runtime-test.py` rejects boolean schema versions, libraries outside
the selected SDK, duplicate library names, mismatched target profiles and
altered runtime tool hashes before a test fragment is published. Five checks
passed at `runtime-guards-maintained/receipt.json` in the same evidence directory.
This consolidation is the isolated candidate interface, not yet the production
build-bsd frontend; the latter remains on Make until the maintained end-to-end
qualification path is integrated. Library installation policy coverage is being
implemented separately without modifying the test graph. BIP remains excluded.

During parallel library-policy work, a filename collision overwrote the test
payload exporter and its same-name temporary copy. The library helper was moved
to `libmd-library-install-plan.py`. The test exporter was restored byte-for-byte;
its SHA256 matches the original `test-install-plan.json` input binding. Graph
regeneration then passed. Recovery evidence and retained source copies are at
`/usr/obj/usr/src/bazel-libmd-wrapper-20261024/exporter-collision-recovery.json`
and `qualified-source-snapshot/`. No test inventory hash was rewritten to accept
the replacement, and no host installation was involved.

### Native library payload graph — 2026-10-24

The candidate graph generator now accepts `--library-install-plan` and
`--compression-tools` for the reconciled library policy and a verified static
gzip build receipt. Both are explicit inputs. Common build/install metadata and
SDK profiles must agree; compiler/tool inputs and source bytes are checked.
The graph represents all 126 exported library payloads: archive, shared library,
debug file, shared-library symlink, 13 headers, seven compressed manuals, and
102 manual hardlinks. Compression runs as seven declared Bazel actions using
maintained `gzip -cn` policy and the explicitly staged static tool.

All 126 native manifest records match maintained Make ownership, mode, tags,
destinations and link targets. All 20 header/compressed-manual payloads match
Make bytes exactly. Hardlinks must reference a regular manifest file and agree
on inode ownership/mode; actual Bazel negative analysis tests reject a missing
target and inconsistent mode. A conflicting library/install mode is also
rejected during generation. The restored full graph passed `bazel test //...`
with all 14 tests passing and 333 action-cache hits.

Evidence: `/usr/obj/usr/src/bazel-libmd-wrapper-20261024/`:
`library-manifest-parity.json`, `link-rejection-qualification.json`,
`library-policy-mismatch.json`, `library-install-graph-r2.events.json`, and
`library-graph-inputs.json`. Source snapshots are retained. The initial policy
exporter's extra-payload rejection evidence is separately retained under
`/usr/obj/usr/src/bazel-libmd-library-install-policy-negative-20261024/`.

These are native artifact and manifest results. The manifest does not yet
materialize an installed filesystem. Directory policy, actual staged link inode
identity, complete native staging, pkgbase package creation and publication
remain pending. No Bazel-built pkgbase package is claimed. Frontend assessment:
these options currently belong to the isolated candidate generator; production
build-bsd remains Make-only. Integrating the complete qualification workflow is
still required before a production backend change. No host install or VM ran.

### Native libmd filesystem staging — 2026-10-24

The isolated native `bsd_stage` action now uses a declared static BSD xinstall
and shell to emit a tree artifact and NO_ROOT METALOG. All 17 required directory
policies are derived from maintained mtree/Make inputs (including overlays),
then checked against the Make installation reference; no implicit directory
permissions are used. Both library and test manifests feed the same action.

Qualification in `/usr/obj/usr/src/bazel-libmd-wrapper-20261024`:
- `native-stage-parity.json`: 170 payloads and 17 directories; exact selected
  metadata parity with Make; copied bytes match declared Bazel inputs; actual
  hardlink inode identity and symlink targets; no unexplained stage paths.
- `native-stage-negative.json`: missing parent policy and overlapping payload
  manifests rejected by actual Bazel analysis. An earlier duplicate-label test
  was rejected by Bazel before reaching our rule; the corrected overlap test
  uses distinct manifests and reaches our destination guard.
- `native-stage-r1` / `native-stage-restored`: actual `bazel test //...` passes,
  all 14 digest tests cached; restored run reports 335 action-cache hits.
  time -l records CPU, maximum RSS, block I/O and other resource counters.
- `native-stage-qualified-source/`: frozen rule, graph, exporter, and check
  scripts. Directory exporter evidence is separately in
  `/usr/obj/usr/src/bazel-libmd-directory-policy-20261024-r2`.

This is isolated qualification wiring; integration into the graph emitter and
maintained frontend remains pending. The frontend remains bsd-make-only and
must not advertise native package support yet. No pkgbase package has been
created from this stage. Physical modes in Bazel's managed output tree are not
package installation policy: the verified METALOG supplies that metadata.
Independent Make/Bazel compiled-byte identity, complete sandbox enforcement,
whole-system coverage, and comparative performance remain unproven.

### Reproducible native staging graph inputs — 2026-10-24

The isolated `libmd-build.py` now accepts `--directory-policy` and
`--install-tools` together, requiring both library and test installation plans.
`stage_install.py` checks all directory-export build environments, the installer
build profile, source/tool hashes, and the binding to the selected payload
policies. It snapshots the static installer atomically and emits `bsd_stage`;
manual BUILD append wiring is no longer required.

`bazel-libmd-wrapper-20261024/integrated-stage-r1` passed actual `bazel test //...`
with 14 cached passing tests and 335 action-cache hits. Stage parity remains
170 payloads/17 directories. `stage-input-guards.json` records rejection before
staging for wrong target, changed installer digest, unbound payload policy,
and boolean format version; repeated emission is deterministic. Source is
preserved in `integrated-stage-source/` alongside those receipts.

The maintained Make `create-world-packages` route validates METALOG, generates
plists, checks package coverage, and invokes `packages` stagepackages. A libmd
subset cannot constitute the complete runtime/dev/tests packages it belongs
to. Complete package contents remain required before claiming usable pkgbase
packages. Build frontend review: `build-bsd.c` remains bsd-make-only; candidate
staging is not yet exposed as a production backend. No publication, installation,
or reboot occurred.

### Native rules promoted to maintained source — 2026-10-24

26 native graph/export/install/test helpers now reside in `tools/build/bazel`.
The qualified native toolchain and version-map rules use the names
`native_cc_toolchain_config.bzl` and `native_version_map.bzl`; the original
pilot rules remain intact for existing `qualify.py`/`build-bsd bazel-test` users.
The native staging helper copies these into the generated workspace's expected
rule filenames. This separation is for the legacy/native API transition.

Using maintained `libmd-build.py` to regenerate the existing qualified workspace
passed actual `bazel test //...` (14 cached tests, 335 action-cache hits), followed
by 170-payload/17-directory staging parity. Ten focused checks passed: three
runtime-input checks, two linker-policy checks, five static execution-tool
checks. Evidence and file hashes: `bazel-libmd-wrapper-20261024/maintained-promotion.json`,
`maintained-promotion-check.json`, and `maintained-stage-r1.*` under `/usr/obj/usr/src`.

This reuses the existing SDK/workspace and input receipts; it does not prove a
fresh bootstrap or world/kernel coverage. `build-bsd.c` integration review:
its current `bazel-test` still dispatches the old pilot. Next frontend work must
accept explicit native qualification inputs, run graph/build/test/stage checks,
and report their actual scope; no production backend switch is justified yet.

### Maintained frontend native qualification — 2026-10-24

`build-bsd bazel-test --bazel PATH --bazel-inputs CONFIG --output NEW_PATH`
now invokes `tools/build/bazel/native-qualify.py`; omission of `--bazel-inputs`
retains the existing pilot. Native configuration fields are documented in
`bsd-build(8)`. The runner verifies prepared toolchain input/snapshot hashes,
checks source/object identity, locks the workspace, regenerates the graph,
runs actual `bazel test //...`, compares test summaries with the selected
inventory, checks stage outputs exist and rechecks bound inputs. Evidence
includes the commands, resource counters and scope limitations.

Actual frontend run `/usr/obj/usr/src/bazel-native-frontend-20261024/receipt.json`
passed with all 16 CPUs selected, 14 passing cached tests and 335 action-cache
hits. Bazel warm-run counters: 3.43 s wall, 30.28 s user, 3.52 s system,
855128 KiB maximum RSS, 3 block inputs and 388 block outputs. These are warm
qualification measurements, not a Make/Bazel performance comparison.
Frontend compiled with `-Wall -Wextra`; legacy/native plan dispatch, no plan
output creation, preservation of bsd-make backend and wrong-action rejection
passed. Matching assertions are added to the maintained `bazel_plan` ATF case;
the full ATF suite was not run on this turn. Frozen source is under the result's
`source/` directory.

This path requires prepared plans, tool receipts, SDK/workspace and a resolved
module lockfile. It does not independently rerun installation parity or create
complete packages. Source-to-fresh-workspace orchestration, parity verification
inside the frontend, world/kernel/package expansion, sandbox and performance
gates remain required. No production backend switch, installation or publication.

### Installation parity required by native frontend — 2026-10-24

`native-qualify.py` now requires `stage_verify.py` success before emitting a
passing receipt. Verification covers the complete selected path inventory,
Make METALOG metadata, actual regular-file type/size/digests, byte identity
against declared Bazel outputs, actual hardlink inode identity, and symlink
targets. The source-derived directory policy binds the selected payload
policies and the existing Make reference by hash. Escaped mtree syntax remains
explicitly unsupported by this libmd candidate; it is rejected, not guessed.

Actual `build-bsd bazel-test --bazel-inputs ...` passed through this gate with
16 jobs: `/usr/obj/usr/src/bazel-native-frontend-parity-20261024/receipt.json`
and `stage-parity.json`. Counts: 17 directories, 170 payloads, 102 hardlinks,
one symlink; all 14 digest tests passed. `stage-verifier-tests.json` records
four negative checks (owner, duplicate record, broken hardlink, corrupted
payload) and positive verification of an independent disposable stage copy.
The verifier and negative test are maintained source; source snapshots are
preserved under that evidence directory. The manual describes the new gate.

This supersedes the prior note that native frontend invocation only checks
stage existence. It still uses the pre-existing hash-bound Make reference;
no fresh reference rebuild or independent Make/Bazel compiled-byte equivalence
is claimed. The frontend remains qualification-only, with Make production.
Fresh-workspace orchestration and complete world/kernel/package expansion
remain outstanding, together with sandbox and comparative resource gates.

### Fresh workspace qualification — 2026-10-24

A new native workspace was exported entirely using maintained helpers:
`libmd-plan.py`, `libmd-stage-tools.py`, `libmd-test-plan.py`,
`libmd-install-plan.py`, `libmd-library-install-plan.py`, and
`libmd-directory-plan.py`. It contains a new source/SDK snapshot and fresh
library/test/directory policies. `build-bsd bazel-test --bazel-inputs` then
regenerated the graph and used a new Bazel output root (no old action cache).
The explicitly supplied existing module lock and download cache were reused;
no old build outputs were copied. Existing SDK, static tools and hash-bound
Make installation reference were reused and are not a fresh bootstrap claim.

Evidence: `/usr/obj/usr/src/bazel-native-fresh-qualification-20261024/receipt.json`.
All 14 tests executed and passed; 170 payloads/17 directories passed required
installation parity. Bazel reported 336 total actions, with 154 internal and
196 processwrapper-sandbox processes (the process categories need not sum to
unique actions). This is not sandbox-enforcement evidence.
Bazel command resource counters: 7.47 s wall, 55.50 s user, 11.93 s system,
1119368 KiB peak RSS, 4 block inputs, 4324 block outputs. `disk-usage.txt`
records 1067529 KiB workspace and 795674 KiB Bazel output root at measurement.
These figures exclude reusable SDK/tool builds and metadata preparation and
are not a Make comparison or full-system performance claim.

Prepared inputs are in `/usr/obj/usr/src/bazel-native-fresh-20261024/qualification-inputs.json`;
`module-lock-input.json` records the lockfile origin/hash. This validates fresh
workspace construction through the maintained helpers; preparation still
needs consolidation into the normal frontend's explicit configuration flow.
Make remains production/default. Complete world, kernel, packages, sandbox,
bootstrap and comparative performance gates remain outstanding.

### Fresh preparation through build-bsd — 2026-10-24

Native qualification input format 2 now invokes maintained `native_prepare.py`
through the existing `build-bsd bazel-test --bazel-inputs` entry point. It
validates exact configuration fields and output/input separation, exports a
new source/SDK/test/library/directory workspace, copies the explicitly supplied
module lock, creates format-1 qualification inputs and runs the same native
build/test/stage-parity gates. No manual intermediate command invocation is
required. Failure leaves FAILED.json and per-step logs; success requires
unchanged bound configuration and implementation inputs. The manual documents
both input modes. Make remains production/default.

Actual single-command evidence:
`/usr/obj/usr/src/bazel-native-preparation-20261024/receipt.json`.
Preparation, all 14 tests and 170-payload/17-directory parity passed. Six
validation rejection checks passed (boolean format, unknown field, empty
distdirs, relative tool path, object-root output and input overlap), without
creating a workspace. Source snapshots and checks are in that evidence root.
Each preparation command records time -l counters; disk usage is recorded
separately. Metadata preparation remains expensive (approximately 48 seconds
for test inventory and 58 seconds for directory export on this run); this must
be consolidated before scaling the current many-query strategy across world.

This builds a fresh workspace from existing explicitly selected SDK/tools and
Make reference; it does not bootstrap them. Next graph implementation is the
complete bzip2 package family, using reusable library/program/configuration
rules and the maintained package pipeline. World/kernel coverage, complete
publication, enforced sandboxing and comparative performance gates remain.

### First native package-family graph: bzip2 — 2026-10-24

Maintained `component-plan.py` exports selected libraries/programs through one
shared BuildEnvironment with batched metadata queries and per-program/per-file
flags. The explicit three-component bzip2 selection took 6.26 seconds and 12
queries; nine C sources resolved. This is not complete world/package discovery.
`component-build.py` and `native_cc.bzl` now emit native regular/PIC archives,
shared-library/SONAME-alias and program dependency actions. Source hashes and
the selected SDK snapshots are checked. Unsupported generation, version maps,
CTF, non-C/per-file options or unresolved library dependencies fail explicitly.

Actual Bazel build evidence is under
`/usr/obj/usr/src/bazel-bzip2-components-20261024`: `build-r2-command.json`,
`build-r2.events.json`, execution/stdout/stderr logs. The graph built libbz2
archives/shared library, bzip2 and bzip2recover. Run: 42 actions, 4.79 seconds
wall, 37.07 user, 6.18 system, 860396 KiB max RSS, 447 block inputs and 798
block outputs. These are component-build measurements, not Make comparisons.
`runtime-samples.json` passes all six maintained compression/decompression
comparisons and records loader selection of the new native libbz2. The recovery
program was built but its runtime is not qualified. Source snapshots and a
byte-identical graph re-emission with source hash checks are retained.

The shared `lib/libbz2/gen-pc.sh` is now used by maintained Make. Explicit
configuration/tool inputs and original-recipe byte parity passed, including
invalid input/failure cleanup tests; evidence is
`/usr/obj/usr/src/bzip2-pc-generation-20261024/receipt.json`. Wiring this generator
into Bazel remains pending, alongside installation/debug/package parity and
native Bazel test rules. No bzip2 package was created and none was installed.

Frontend review: `build-bsd` native qualification remains libmd-only. The generic
component graph is not yet promoted to that qualified action. Preserve the
existing profile/toolchain/test/parity gates when adding family selection;
complete selected package contents and shared-library dependency metadata must
be verified before package publication. Make remains the production backend.

### Declared bzip2 pkg-config generation — 2026-10-24

The component exporter now reads maintained `PC_GENERATOR`, `PC_TEMPLATE`,
`PC_TOOLS`, `PC_ARGS` and `PC_DEPENDENCIES` metadata for each PCFILES entry.
The Make recipe and native Bazel template action share the generator, template
and argument values. The version-bearing bzlib.h is now a Make prerequisite
and a declared generation input. Generator tools and their runtime closures
come from the selected toolchain; missing metadata/tool mappings are rejected.

Fresh native build and independent Make generation passed byte parity:
`/usr/obj/usr/src/bazel-bzip2-generated-r2-20261024/pkg-config-parity.json`.
The graph built 43 actions (including library/programs and pkg-config output).
`template-incremental.json` records actual Bazel execution logs proving that a
template-only mutation executes exactly BSDTemplateGenerate, with no compile
or link actions. Restoration returned the generated file to exact Make bytes.
The shared generator regression checks passed again. Inputs and source snapshots
are retained in that evidence directory.

Frontend review: normal Make uses the same maintained generation recipe;
libmd qualification through build-bsd is unchanged. Generic family selection
is still pending in the frontend and must include bzip2 native tests and full
installation/package parity first. No bzip2 package was created or published.
Complete world/kernel, sandbox and performance gates remain outstanding.

### Native bzip2 tests — 2026-10-24

The maintained Make test cases and compression/decompression flags now supply
native Bazel test configuration. Declared static bintrans and gzip tools decode
the checked-in fixtures as build actions. A native C test runner invokes the
selected program with declared runtime libraries and compares output bytes.
These fixture tools and the SDK still come from Make; this is not a complete
native bootstrap or enforced sandbox claim.

Actual `bazel test //...` executed all six cases successfully. Deliberately
selecting the wrong reference caused exactly that test to fail; restoring the
reference returned all six to passing. Evidence and source snapshots are under
`/usr/obj/usr/src/bazel-bzip2-tests-20261024`, including
`test-failure-qualification.json`. The Make recipe dry-run command sequence was
also checked before/after extracting shared test metadata.

Frontend review: the qualified build-bsd native path remains libmd-only.
The generic bzip2 graph now includes tests, but installation/debug/package parity
is still required before exposing this family through that qualification path.
No complete bzip2 package, world or kernel build is claimed. Make remains the
production backend. Recovery-program runtime qualification remains pending.

### Complete selected bzip2 Make staging reference — 2026-10-24

Fresh maintained Make builds and NO_ROOT installations succeeded for lib/libbz2,
usr.bin/bzip2 and usr.bin/bzip2recover, using 16 jobs and private /usr/obj
reference directories. No host installation occurred. The three receipts are
under `/usr/obj/usr/src/bazel-bzip2-{library,program,recover}-reference-20261024`.

`/usr/obj/usr/src/bazel-bzip2-tests-20261024/make-family-inventory.json` records
16 package-tagged payload paths derived from those METALOGs, with staged file
hashes and symlink targets checked. They include separate debug files, program
aliases, compressed manuals, the header and pkg-config metadata. This is the
comparison baseline; it does not yet establish native installation parity,
complete package dependency closure, hardlink parity or package creation.

Next: map these maintained installation contracts to native artifacts and
verify debug splitting, links, metadata and complete package construction.
The frontend/backend decision is unchanged: Make remains production, and the
bzip2 graph is not yet a qualified build-bsd package backend.

### Generic native debug artifacts — 2026-10-24

`component-build.py` now emits the existing declared debug extraction and strip
rules for selected libraries and programs, using their MK_DEBUG_FILES, DEBUGFILE
and STRIP metadata. Unsupported settings fail explicitly. The fresh bzip2 graph
built all three installed runtime/debug pairs and passed all six native tests.
`elf-debug-check.py` checks ELF identity, stripped runtime sections, separate
debug information, debug-link basename and CRC. All three pairs passed, and
corrupting each debug file caused CRC rejection.

Evidence: `/usr/obj/usr/src/bazel-bzip2-debug-20261024`, including
`debug-checks.json`, test events, command logs and frozen source. Measured build:
5.62 seconds wall, 43.55 user, 7.03 system; 966820 KiB maximum RSS; 608 block
inputs and 1805 block outputs. These are component measurements, not a Make
performance comparison. The tests still exercise the linked build artifacts;
installed-runtime tests and full destination/metadata/package parity remain.

Frontend review: this extends the generic artifact graph only. The maintained
build-bsd native qualification remains libmd-only until complete family staging
and package checks pass. Make remains production; no package publication,
host installation, world/kernel completion or sandbox guarantee is claimed.

### Selected library installation policy and native manifest — 2026-10-24

The maintained library installation exporter accepts an explicit source-relative
component from the configured component plan. Its existing libmd default remains
supported. Pkg-config installation derives LIBDATADIR, owner/group/mode and
package tags from maintained Make policy and requires declared generation.
The library graph emitter accepts explicit native artifact labels, allowing the
generic component graph to reuse the same installation rules.

Fresh libbz2 policy reconciliation covered all six payloads. The actual native
manifest build passed; all six destinations and metadata records match Make,
all declared file payloads exist, and header/pkg-config bytes match the reference.
All six native bzip2 tests passed. Re-exporting libmd produced identical policy
for all 126 existing payloads. Evidence and frozen source:
`/usr/obj/usr/src/bazel-bzip2-library-manifest-20261024/manifest-parity.json`.

This checks a library manifest, not physical staged directories, program
installation, complete packages or publication. Those remain required. Frontend
review: build-bsd's libmd qualification retains its existing inputs and default
component; the generic component CLI now accepts --library-install-plan and
--compression-tools. Whole-family frontend selection remains gated on complete
staging/package parity. Make remains the production backend.

### Native bzip2 family installation manifests — 2026-10-24

The shared installation exporter now handles selected ordinary programs as well
as libraries. BINDIR/PROGNAME, debug settings, LINKS, manual groups, package tags,
ownership and modes come from maintained Make queries. The exporter reconciles
actual Make METALOG payload coverage and verifies reference hardlink identity.
Unsupported scripts, signing transformations, internal/precious programs and
additional payload classes still fail explicitly instead of being omitted.

The generic graph accepts repeated --component-install-plan inputs. Its shared
manifest emitter uses explicit artifact labels and separate component target
names. All 16 selected bzip2-family records built and matched the Make reference
inventory, including program/manual hardlinks. Header, pkg-config and compressed
manual bytes match Make; all six native tests passed. Evidence:
`/usr/obj/usr/src/bazel-bzip2-family-manifests-20261024/manifest-parity.json`.
Source snapshots and build/test logs are retained alongside it.

These are manifests and declared payloads, not a completed staged filesystem or
package archive. Next are directory policy, physical staging, installed runtime
checks and package construction/dependencies. Frontend review: the maintained
libmd path retains its default; full-family build-bsd selection remains gated
on those checks. Make stays production; no host installation occurred.

Regression check: the extended exporter reproduced all 126 existing libmd
payload policies unchanged; evidence is included in the family manifest receipt.

### Native bzip2 family physical staging — 2026-10-24

The maintained directory exporter accepts explicit component policies and derives
required ancestors from configured source mtree files, DIRS and debug-directory
settings. All 14 required directories reconciled with the selected Make
references. The existing native staging action and verifier now accept explicit
component policies/manifests; the legacy libmd API/defaults remain available.

Actual Bazel staging produced all 16 payloads in 14 directories, including five
hardlinks and one symlink. The verifier checked complete filesystem/METALOG path
coverage, Make-derived ownership/modes/tags, declared-output bytes and actual
link identities. Negative tests rejected changed ownership, duplicate records,
broken hardlinks and corrupted payload bytes after first validating a disposable
copy. All six native tests passed. The stripped staged bzip2 also passed all six
sample comparisons with loader tracing confirming the staged libbz2 was used.

Evidence: `/usr/obj/usr/src/bazel-bzip2-family-stage-20261024`:
`stage-parity.json`, `stage-negative.json`, `staged-runtime.json`, build/test logs
and frozen source. SDK libc/libsys and the host loader/kernel remain external
runtime dependencies. Bazel physical output modes are not package installation
policy; METALOG carries logical ownership/modes. This is not host installation,
full bootstrap, sandbox enforcement or a complete installable package claim.

Frontend review: generic component graph options now include --directory-policy
and --install-tools alongside component payload policies. The normal build-bsd
qualification remains libmd-only. Fresh legacy frontend regression after these
shared-helper changes, recovery runtime, package creation/dependency checks and
family frontend selection remain required. Make remains production/default.

### First native-payload pkgbase archives and frontend regression — 2026-10-25

The configured bzip2 family now has four actual pkgbase archives: bzip2, lib,
dev and dbg. Their payloads come from the verified native Bazel stage; packaging
uses maintained metalog validation, mtree-to-plist and packages/bzip2 Make rules.
The selected build profile supplies the package list, and the staged executable
supplies target ABI detection. Make still packages these Bazel-produced inputs.
Private archive objects reside under
`/usr/obj/usr/src/bazel-bzip2-packages-r2-20261024/objects`; nothing was copied to
the published repository and no latest pointer or host installation changed.

Initial package creation exposed a real converter defect: mtree's `flags=none`
was emitted as a literal pkg file flag. The maintained converter now maps this
empty flag set to an empty field, retaining actual flags such as schg. All 21
world-package coverage tests passed, including the added regression. This fixes
the normal Make/build-bsd packaging pipeline as well as the candidate.

Archive extraction verified all 16 selected payload paths and bytes against
the native stage, with all five hardlinks preserved. Metadata advertises
libbz2.so.4 from the library package and requires it plus libc.so.7 for the
program package. Evidence: `receipt.json`, `archive-inspection.json`, command
logs and frozen source in the private archive directory. These are selected
archives, not a qualified complete repository or dependency installation test.
The qualification driver remains an evidence script; maintained frontend family
orchestration, package installation/solver tests and publication gates remain.

A fresh format-2 run through the maintained build-bsd bazel-test frontend passed
after the shared exporter/staging changes: all 14 libmd tests, 170 payloads,
17 directories, 102 hardlinks and one symlink. Evidence:
`/usr/obj/usr/src/bazel-family-frontend-regression-20261024/receipt.json`.
Frontend review: production Make remains default; generic bzip2 family selection
has not yet been exposed through the qualified frontend. Complete world/kernel,
bootstrap, enforced sandbox and comparative performance qualification remain.

### Packaged recovery-program runtime — 2026-10-25

The maintained `bzip2-recovery-check.py` exercises explicit program, recovery
program, shared library and runtime-library paths. Actual binaries extracted
from the candidate pkgbase archives recovered a deterministic 384000-byte,
four-block stream exactly. Corrupting the first block CRC caused whole-stream
and first-block decompression failures; all three remaining recovered blocks
matched their healthy counterparts byte-for-byte. Missing recovery input also
failed. Loader tracing confirmed the supplied packaged libbz2 was selected.
Executable/library hashes were rechecked after execution.

Evidence: `/usr/obj/usr/src/bazel-bzip2-packages-r2-20261024/recovery-runtime.json`
and the frozen checker source. This closes the selected recovery runtime gap;
it does not establish package-manager installation, dependency solving or a
complete runtime root. External selected libc/libsys and host loader/kernel
are still used. The host uid is 1001; any root-only package installation checks
must use an explicitly isolated root and database, with no host package changes.

Frontend review: this adds a maintained runtime qualification helper, not a new
production build mode. Wiring the complete family build/stage/package/runtime
sequence into build-bsd remains outstanding. Make remains production/default.

### Maintained selected-component packaging driver — 2026-10-25

`tools/build/bazel/component-packages.py` replaces the one-off package build
experiment with a maintained driver. Inputs explicitly select source/object
profile, native workspace, reconciled component/directory policies, manifest
names, package component, target ABI file and execution tools. It verifies the
stage before and after packaging, queries package/version/ABI settings through
the maintained build environment, validates METALOG, invokes the maintained
plist converter and runs the selected package Make rules with the requested
job count in a fresh private object directory. It never invokes publication,
installation or stagepackages and retains the standard repository setting.

All four configured bzip2 archives built through this driver. Independent
extraction again matched all 16 payloads and preserved five hardlinks. Selecting
packages/zlib against the bzip2 stage was rejected before archive creation.
Unexpected non-directory payloads fail; the generated clibs-dev plist contains
only directory scaffolding and is explicitly recorded in the receipt.

Evidence: `/usr/obj/usr/src/bazel-bzip2-maintained-packages-20261025`:
`receipt.json`, `archive-inspection.json`, `package-selection-negative.json`,
command logs and frozen source. These selected archive checks do not prove
package-manager installation, dependency solving, hermetic packaging execution
or complete-world/package coverage.

Frontend review: this maintained helper is ready for the family qualification
orchestrator; build-bsd does not yet expose that complete family workflow.
Production Make, separate hardware builds and combined publication are unchanged.
Next remains the family orchestrator/frontend integration and isolated package
installation/dependency qualification, followed by broader world/kernel coverage.

### Maintained frontend component qualification — 2026-10-25

The existing build-bsd bazel-test --bazel-inputs entry point now supports format 3
through maintained component_qualify.py. Explicit prepared inputs select the
component graph, SDK, test configuration, all installation policies, directory
policy, package component and execution tools. Every component must have a
policy. Native test labels are emitted from maintained suite metadata and must
match the actual successful Bazel event inventory. The workflow builds, tests,
checks physical staging and invokes component-packages.py. Input hashes are
rechecked; failures leave FAILED.json rather than a success receipt.

Actual frontend run `/usr/obj/usr/src/bazel-component-frontend-20261025/receipt.json`
passed six native tests, 16 payloads in 14 directories, and created four private
pkgbase archives. The C frontend compiled with -Wall -Wextra; its JSON plan
retains bsd-make as production backend and creates no output. Scope reporting
now says native-configured-qualification rather than assuming every native
configuration is libmd. The maintained frontend regression expectation and
manual were updated. Three invalid configurations (unknown field, missing
component policy, absolute package path) were rejected before output creation;
evidence is under `/usr/obj/usr/src/bazel-component-config-checks-20261025`.

This is prepared-input orchestration, not fresh system bootstrap or complete
world/kernel coverage. Format 3 currently uses the maintained bzip2 native test
adapter; other suites require explicit adapters. Runtime/recovery checks were
qualified separately and are not rerun by this format. Package-manager install,
solver/dependency tests, archive inspection integration, broader graph coverage,
sandbox and comparative performance gates remain. No publication or host
installation occurred; Make remains production/default.

### Archive inspection required by frontend packaging — 2026-10-25

Maintained archive_verify.py is now a required component-packages.py gate, so
format-3 build-bsd qualification cannot report success based only on archive
existence. It checks ABI/version and unique package identities, package-manifest
member coverage, complete selected payload coverage, extracted staged bytes,
regular-file and directory modes, symlinks and actual hardlink identity. It
validates inventory before extracting into a private directory and rechecks
archive hashes afterward. Logical archive ownership is not yet checked; the
extractor intentionally retains the executing user's ownership.

The full maintained frontend passed again: six native tests, 16 staged and
archived payloads, 14 staged directories, five preserved hardlinks and four
pkgbase archives. Evidence:
`/usr/obj/usr/src/bazel-component-archives-20261025/receipt.json` and
`packages/archive-inspection/receipt.json`. Missing-package and wrong-version
negative checks rejected inputs before extraction; evidence is under
`/usr/obj/usr/src/bazel-archive-gates-20261025`. Sources and commands are frozen.

Frontend review: the mandatory gate is reached through the existing format-3
workflow; no new options or production backend changes were needed. The manual
now describes archive coverage and remaining ownership/install limitations.
Dependency-solver installation, recovery/runtime orchestration, broader native
graph coverage, bootstrap, sandbox and performance gates remain outstanding.
Nothing was published or installed into the host package database.

### Archive ownership/header validation — 2026-10-25

The mandatory archive gate now reads headers through the system libarchive
public interface, via maintained archive_headers.py. Before extraction it checks
owner/group names, modes, types and symbolic/hardlink targets against the native
stage METALOG and actual staged hardlink identity. It also requires agreement
between the archive reader and bsdtar member inventories. The package receipt
binds the inspector source and selected libarchive binary as execution inputs.

Full format-3 frontend qualification passed again under
`/usr/obj/usr/src/bazel-component-ownership-20261025`: six tests, 16 payloads,
14 staged directories and four inspected pkgbase archives. A disposable archive
with an altered owner failed before extraction; evidence is
`/usr/obj/usr/src/bazel-archive-owner-negative-20261025/receipt.json`.
The earlier archive-owner-name validation gap is closed. Numeric ID mapping,
package database installation, scripts and dependency solving are still unproven.
The session runs as uid 1001 and has no sudo/doas command available; root-only
installation qualification requires an authorized isolated root-shell run.

Frontend review: this strengthens the existing mandatory format-3 package gate;
no bypass or new production backend was added. The manual now distinguishes
verified header owner/group names from pending installation ID mapping.
Nothing was published or installed into the host package database.

### Configured world discovery and missing loader input — 2026-10-25

Maintained world-inventory.py queries world SUBDIR selection and library phase
lists, then invokes the real configured Make print-dir traversal with the
selected CPU count. It records exact commands, output, elapsed time and resource
counters. Optional repeated --trust-anchor arguments explicitly bind public PEM
certificate inputs; the tool never disables loader verification or substitutes
a generated certificate to make traversal succeed.

The current recorded profile enables EFI secure boot while disabling the EFI
trust database, but .src_opts does not record the required TRUST_ANCHORS input.
The actual full-world traversal fails at lib/libsecureboot/Makefile.inc:65.
The maintained discovery tool correctly exits nonzero and labels its 341
observed directories incomplete. This is not a complete world inventory and
must not be used to claim all components are represented. Evidence:
`/usr/obj/usr/src/bazel-world-inventory-20261025/inventory.json` and raw logs.
The intended public trust-anchor paths have been requested from the builder.

This exposes a gap in the prepared component model: boolean profile flags alone
are insufficient to reproduce a full configured world. World orchestration must
carry explicit non-boolean build inputs and their hashes as well. Frontend review:
no existing production path or secure-boot policy was changed. The current
format-3 selected-component workflow remains bounded; full-world graph promotion
requires complete discovery with the intended trust input. Generated actions,
bootstrap phases and dependency edges remain additional requirements beyond
this recursion inventory.

### Native library graph expansion: libnv and libnvmf — 2026-10-25

The generic exporter now binds checked-in VERSION_MAP files by hash. The graph
passes those as declared linker inputs and requires the matching configured
version-script option. Generated symbol maps remain explicitly unsupported by
the generic graph (the existing specialized libmd generator remains separate).
Native library rules now propagate selected CcInfo compilation/link dependencies;
static-only libraries are supported without inventing shared outputs.

Actual libnv/libnvmf compilation exposed an exporter omission: source-specific
CWARNFLAGS were not captured. The exporter now captures source warning flags
and regular/PIC object-specific flag values. Supported library source flags are
applied to that source only; unsupported object-specific variants and per-file
include changes fail explicitly. The maintained libnvmf CRC source now receives
its declared -Wno-cast-align option without a global suppression.

Native regular/PIC archives for both libraries and libnv's versioned shared and
debug artifacts built successfully. Versioned exported symbols and shared-object
metadata match the existing Make-built libnv artifact (not a fresh Make build).
Evidence: `/usr/obj/usr/src/bazel-nv-nvmf-flags-20261025`, including build logs,
`version-parity.json`, configured flags and frozen source. This is compilation
and interface evidence only: a linked consumer, runtime tests, static-only
installation handling and dependency-cache qualification remain required.

Frontend review: the maintained generic backend used by format 3 gains these
capabilities. Existing prepared plans must be regenerated because exporter
hashes changed; historical receipts remain evidence for their recorded sources.
No production backend or package publication behavior changed. Full-world
loader discovery still awaits the intended public trust-anchor input.

### Native linked-consumer and dependency invalidation qualification — 2026-10-25

The component graph now accepts an explicit native-c test suite in test-config.
Its format-1 document contains suite=native-c and a nonempty tests array; each
entry declares name, source-relative C source, selected library dependencies and
C flags. Header includes must already be represented by the selected graph.
Tests use native cc_test and fully static linking, with their labels emitted
into the same inventory checked by format-3 orchestration. Unsupported suite
names and undeclared library/header inputs fail explicitly.

Maintained nvmf_dependency_test.c declares only libnvmf as its library dependency.
It exercises transport metadata serialization using the transitive libnv,
verifies unpacked values, checks propagated NV-list errors and a transport name.
The native Bazel test passed; readelf confirmed no ELF interpreter or NEEDED
libraries. Removing the libnvmf-to-libnv edge in the disposable generated graph
caused unresolved nvlist symbols; restoring it passed. Mutating only the copied
libnvmf transport source caused the expected test failure. Execution logs show
only that source was recompiled, with unchanged libnv compilation avoided;
restoring the source passed again.

Evidence: `/usr/obj/usr/src/bazel-nvmf-consumer-20261025`, including
`dependency-qualification.json`, `incremental-qualification.json`, actual Bazel
test/action logs and frozen source. These are real-library linked-consumer and
incremental checks, not NVMe device/network transport qualification. Static-only
installation policy and broader dependency patterns remain to be implemented.

Frontend review: the existing test-config field selects this adapter; no new
frontend flag or production backend change is needed. Format-3 requires matching
installation policies for all components, so the internal libnvmf pair is not yet
a complete format-3 package-family qualification. Full-world loader discovery
still awaits the builder's intended public trust-anchor paths.

### Correct configured library variants — 2026-10-25

The generic component exporter now records Make's `_LIBS`, `PICFLAG`,
`PIEFLAG` and `SHARED_CFLAGS`. Native library rules emit the requested regular,
PIC and PIE variants with the configured flags. A populated `SHLIB_NAME` alone
is insufficient: internal libnvmf retains that metadata although Make requests
only libnvmf.a and libnvmf_pie.a. Earlier generic evidence included unwanted
libnvmf PIC/shared outputs and omitted its required PIE archive; it did not
establish correct internal-library variant coverage. This corrects that result.

Fresh native qualification in
`/usr/obj/usr/src/bazel-library-variants-r2-20261025` passed. The checked execution
log contains five regular and five PIC libnv compilations, six regular and six
PIE libnvmf compilations, exactly the four corresponding archives, and no
libnvmf shared output. Archive members and explicit -fpic/-fpie and -DPIC flags
were checked. The regular linked-consumer test passed. Evidence is recorded in
`variant-qualification.json`; a final PIE-linked consumer remains unqualified.
The run used 16 jobs: 5.17 seconds wall, 39.84 user, 6.85 system, 945976 KiB peak
RSS, 240 block input operations and 1696 block output operations. These are
single-run observations, not a Make comparison or a system performance claim.

Frontend review: format-3 component qualification consumes the same maintained
exporter and native rules; no new frontend option is required. Prepared plans
must be regenerated after exporter changes. Make remains the production backend;
full world/kernel, internal-library consumer selection and installation coverage
remain unfinished.

The unresolved production-certificate question does not block build-only
qualification. Existing loader inputs use a public certificate whose subject is
`CN=5BSD DISPOSABLE generation`. It may be supplied explicitly for disposable
build discovery, with that scope recorded; it is not an approved production
trust anchor, and no host trust store or installed loader is changed.

With that explicit disposable certificate input, maintained Make world recursion
completed successfully and discovered 2101 configured directories. Evidence:
`/usr/obj/usr/src/bazel-world-inventory-disposable-20261025/inventory.json`.
This resolves the earlier incomplete 341-directory observation for qualification;
it is directory discovery, not proof of native Bazel coverage or a world build.

### World component metadata coverage — 2026-10-25

Maintained `world-components.py` consumes a successful `world-inventory.py`
receipt and queries every discovered directory through the same configured
world BuildEnvironment. It binds the inventory, recorded profile, explicit
trust inputs and Make include files, preserves library/program/test/data and
recursive-directory metadata, and retains failed queries as named records.
A partial traversal is rejected before creating output. Each successful query
is repeated to detect configuration changes; the final status remains incomplete
if any directory failed. No directory is inferred to have native Bazel support
merely because its metadata can be read. Multi-program expansion and declared
source/generator/action coverage are separate subsequent work.

Invocation uses explicit `--src`, `--inventory`, `--output` and `--jobs` inputs.
The first complete-world survey under
`/usr/obj/usr/src/bazel-world-components-20261025` finished with 2100 queried
components and one failure, bin/zsh, in 301.16 seconds with 16 workers. The
incomplete earlier world inventory was rejected as expected. Investigation of
the ambiguous bin/zsh output found an extra buildenv notice, not multiline
metadata. That distinction matters: dropping a diagnostic in the exporter would
hide a real problem in the maintained Make command interface.

Frontend review: this is a developer discovery diagnostic feeding component
migration, not a new build, staging or publication backend. The maintained
`build-bsd bazel-test` path still qualifies explicit component plans; no claim
is made that it can consume a complete world graph yet. Production remains Make.


### Make buildenv command detection correction — 2026-10-25

Makefile.inc1 previously printed the Zsh CPUTYPE notice whenever any part of
BUILDENV_SHELL matched *zsh*. A normal Make metadata query whose -C argument
named bin/zsh therefore gained an unrelated stdout line. The condition now
checks the command executable basename. No exporter output filtering or
component exception was added.

Maintained buildenv-command-test.py reproduced the old failure and passed after
the correction: a plain zsh argument and a bin/zsh path argument emit no notice;
an executable named zsh retains it; child exit 23 produces a nonzero Make exit;
and the actual bin/zsh PROG/MACHINE_ARCH query is exactly zsh/amd64. The named
executable fixture uses /bin/sh to test dispatch, not Zsh runtime behavior.
Evidence: `/usr/obj/usr/src/bazel-buildenv-command-20261025`, including the
before-failure log, after receipt and source snapshots.

Frontend review: this fixes maintained Make buildenv used by the qualification
backend, with no new build-bsd options or change to production build selection.
The configuration closure changed, so world inventory and subsequent component
plans must be regenerated; old receipts describe their original source state.


After the buildenv correction, fresh directory discovery again completed with
2101 directories in `/usr/obj/usr/src/bazel-world-inventory-buildenv-fixed-20261025`.
The corresponding full metadata recheck is running in
`/usr/obj/usr/src/bazel-world-components-buildenv-fixed-20261025`; its terminal
summary is still required. The prior survey observed 322 library records,
752 records with PROG, and 227 with PROGS/PROGS_CXX (overlapping metadata
categories, not unique binary counts). Twenty-two library records request
generated symbol maps, a concrete remaining generic-graph capability needed
for libc, libsys, libthr and other base libraries.


### Complete metadata survey and generic symbol-map generation — 2026-10-25

The corrected survey completed: all 2101 configured directories queried, zero
failed components, 289.97 seconds with 16 workers. Terminal evidence is
`/usr/obj/usr/src/bazel-world-components-buildenv-fixed-20261025/summary.json`.
This establishes metadata query coverage only, not native world build coverage.

The generic component exporter now records ordered SYMBOL_MAPS, VERSION_DEF,
the actual selected version_gen.awk, the configured CPP command and Clang
resource directory. Inputs are hashed; an unresolved/generated input or a
preprocessor differing from the selected staged Clang is rejected. The generic
backend uses declared concatenate, preprocess and AWK actions. Configured CFLAGS
and CPP flags are preserved, with explicit SDK path relocation. Concatenated
input reaches the preprocessor through stdin as in maintained bsd.symver.mk.
The existing specialized libmd version-map rule remains separate.

stdout_redirect now optionally accepts --stdin. The maintained launcher test
passes binary byte preservation, ordinary/executable outputs, missing input,
missing generator, partial output and child-exit propagation. This changes a
recorded SDK input, so a new SDK snapshot was materialized through the maintained
libmd-plan/libmd-stage-tools helpers at
`/usr/obj/usr/src/bazel-sdk-refresh-20261025`; stale receipts were not edited.

Native libsbuf generation/build passed in
`/usr/obj/usr/src/bazel-sbuf-generated-map-r2-20261025`. Its 534-byte generated
symbol map is identical to fresh maintained Make generation in the first run's
make-map-reference directory. Its versioned exports/ELF metadata match the
existing Make libsbuf.so.6.full (that library was not rebuilt). Receipts:
`symbol-map-parity.json` and `version-parity.json`. The first analysis failure
from missing executable-label allow_single_file attributes is retained in
`/usr/obj/usr/src/bazel-sbuf-generated-map-20261025`; the maintained rule was
corrected before fresh regeneration.

The successful native run used 16 jobs, 4.24 seconds wall, 30.37 user, 4.69
system, 841824 KiB peak RSS, 330 block input and 1256 block output operations.
These single-run observations are not a matched Make performance comparison.
Multiple-map ordering, conditional flags and generator cache invalidation remain
to be qualified; this result does not establish all 22 generated-map libraries.

Frontend review: format-3 build-bsd qualification uses the updated component
plan/backend automatically, with no added user option. Prepared plans must be
regenerated to bind the new exporter/helper. Full world/kernel builds, package
and installation coverage remain incomplete; Make is still production/default.


### Symbol-map ordering and incremental qualification — 2026-10-25

Maintained configured-version-map-test.py exercises the real declared Bazel
rule in a fresh disposable component workspace, retaining every command, action
log and independent Make reference. Two synthetic maps share a macro across
the concatenation boundary and use configured preprocessor flags. All cases
passed in `/usr/obj/usr/src/bazel-version-map-qualification-20261025/checks`:

* Initial output matches fresh maintained Make generation byte for byte.
* An unchanged rebuild executes no fixture generator actions or C compilations.
* Changing the first map executes concatenate, preprocess and AWK exactly once,
  changes the expected exported name, and causes no library C recompilation.
* Changing only a compiler definition executes preprocess and AWK, reuses the
  concatenation, and removes the conditional symbol as Make does.
* Reversed map order fails in preprocessing with the intended diagnostic.
* A missing declared map fails; restoring the inputs restores Make byte parity.

The driver restores the disposable BUILD file and fixture sources on exit.
Its receipt and per-case logs preserve the tested configurations. These tests
qualify the generator contract, not all library source selections or complete
world/kernel builds. The format-3 frontend consumes the same maintained rule;
no new frontend options or production backend changes were needed.

The world survey also identifies a separate libutil requirement: DTrace provider
header and object generation. bsd.dep.mk generates the header with dtrace -h
and provider objects for the configured object variants with dtrace -G, using
the selected sysroot's drti object. This must be represented explicitly in the
native graph; using a stale generated header or disabling DTrace is not a
qualification path. Zlib additionally needs its existing pkg-config generation
represented through the shared declared-template contract.


### DTrace and FIDL generation requirements — 2026-10-25

Both generators are required for the native world graph. They must not be
bypassed with stale generated files, disabled features or opaque Make actions.
The next generation work covers:

1. DTrace provider headers, declared tool/runtime inputs, selected SDK drti.o,
   and regular/PIC/PIE provider objects as requested by Make. dtrace -G rewrites
   its input objects: the Bazel action must receive copies and declare both the
   rewritten objects and provider object as outputs. Multiple providers, static
   anchors, failure propagation and incremental behavior require qualification.
2. FIDL host compiler/bootstrap dependencies, selected Python runtime, ordered
   schemas/imports, generator modules/templates, platform availability and
   per-binding flags. Native actions must declare the generated C++ sources and
   C/C++ headers and compile against declared runtime headers. Schema, template,
   compiler, flag and runtime-header changes require invalidation tests; normal
   and cross builds must distinguish host tools from target libraries.
3. Zlib pkg-config generation through the shared declared-template contract,
   followed by broader library/program migration and installation/package gates.

Maintained bsd.dep.mk now exposes DTRACE_PROVIDERS and each provider's header
before removing .d inputs from SRCS. Component plans record those source hashes,
flags and object lists. lib/libfidl/fidl-bindings.mk exposes FIDLGEN_HEADERS per
binding and uses that same list in its Make dependencies. The component exporter
records ordered FIDL schemas, library/version/flags,  generator/template hashes,
and configured generated source/header lists. Native component emission rejects
these components explicitly until their generation/C++ actions are implemented.

Evidence: `/usr/obj/usr/src/bazel-dtrace-contract-maintained-20261025/receipt.json`
shows real Make header generation, regular/PIC input mutation on copies,
unchanged original objects and DOF sections in provider outputs. The maintained
`dtrace-input-contract-test.py` takes explicit source/object/profile/output
arguments. This is offline host-tool evidence, not native Bazel DTrace support
or installed probe activation. Provider metadata was checked against libutil's
regular/PIC selections, and its generated header remained byte-identical.

The real liblogcmp plan in
`/usr/obj/usr/src/bazel-logcmp-generators-plan-20261025/components.json` captures
both generator families: two ordered FIDL schemas, twenty generator/template
inputs, three generated sources, six generated headers, and logcmp_provider.d.
Fresh maintained Make generation produced exactly the nine declared FIDL files
and the DTrace header; `make-generator-parity.json` records the comparison.
This verifies the inventory, not native FIDL execution or runtime compatibility.

Frontend review: the maintained component backend used by build-bsd format 3
receives these records and fails explicitly on unimplemented generation. No new
frontend option is needed yet. Existing prepared plans/SDK receipts must be
regenerated after the common Make metadata changes. Make remains production;
complete native world/kernel/package/runtime qualification is still outstanding.

### Native DTrace action qualification — 2026-10-25

The candidate `bsd_dtrace.bzl` rules generate provider headers and copied,
rewritten objects through declared Bazel actions. `copy_then_exec.c` refuses
existing destinations before running the mutating generator. The library rule
exposes regular/PIC/PIE object output groups for this qualification. This is not
yet integrated into complete library archive construction: production archives
must consume rewritten objects and provider objects, with normal CcInfo
propagation, before the component frontend can enable DTrace components.

`libmd-stage-tools.py` now accepts explicitly selected additional execution tools
and records their binary/runtime inputs. It also stages the SDK cpp executable
under its actual driver name. Passing plain clang to DTrace's cpppath failed
because DTrace supplies preprocessor arguments through stdin; keeping the cpp
invocation name fixes the driver selection without a shell workaround.

Evidence in `/usr/obj/usr/src/bazel-dtrace-native-r2-20261025/`:

- `native-generation-parity.json`: the real libutil provider header matches
  maintained Make byte for byte; regular/PIC/PIE provider objects contain DOF;
  rewritten objects differ, while original compiler objects still match their
  input digests recorded in Bazel's generation execution log.
- `consumer-command.json`, `consumer.events.json`: three native Bazel cc_test
  consumers link and execute the probe call successfully. This does not prove
  installed probe registration or tracing activation.
- `build.stderr`: initial successful native graph, 4.19 seconds elapsed,
  30.07 user seconds, 4.91 system seconds, 844604 KiB peak RSS, 150 block input
  operations and 1364 block output operations. These are a small fixture's
  process accounting, not a Make performance comparison or disk throughput.

The fixture uses explicit tools and a processwrapper sandbox. Host ELF loading
and DTrace's internal shell execution still prevent a hermetic-runtime claim.
Remaining gates include maintained reusable qualification, toolchain/provider
integration, configured preprocessor inputs, multiple providers/static anchors,
failure and cache invalidation tests, full libutil integration and installed
tracing. FIDL still has inventory/Make parity only; native generation and C++
consumer integration remain open.

For both generator families, completion requires idiomatic Bazel dependencies:
execution-platform tools distinct from target artifacts; declared schemas,
imports, templates, options and outputs; typed providers and CcInfo for normal
consumers; and observable rebuild/cache behavior when each input class changes.
No discovery of generated outputs during execution or wrapper around a whole
Make component substitutes for that graph.

Frontend review: build-bsd's component backend still rejects unimplemented
DTrace/FIDL components. The SDK staging improvement is in the maintained helper;
no new frontend switch is necessary. Make remains the production backend.

### DTrace dependency and executable-provider checks — 2026-10-25

The maintained `dtrace-action-test.py` accepts an explicit prepared workspace,
Bazel test command, provider source, changed provider input, Java home and fresh
output directory. It restores the source even on failure and retains execution
logs. `/usr/obj/usr/src/bazel-dtrace-actions-runfiles-20261025/receipt.json`
records passing no-op, provider-change, invalid-syntax and recovery checks.
The no-op executed no actions. The provider mutation executed one header action,
three compiler actions and three DTrace object actions; original compiler
objects matched the hashes recorded as generation inputs. Consumers linked and
passed. This checks provider-source invalidation, not the complete flags/tools/
includes invalidation matrix or remote cache portability.

The rules now pass `DefaultInfo.files_to_run` for executable tools, including
nested DTrace tools and the copying runner. A separate executable-target fixture
requires runfile data before invoking DTrace. Header and regular/PIC/PIE object
actions and their consumers passed; the fixture and command are retained in
`/usr/obj/usr/src/bazel-dtrace-native-r2-20261025/runfiles-command.json`, with
`runfiles.execution.json` and `runfiles.events.json`. This is a sandbox runfile
check; host shell/ELF runtime closure remains an outstanding gate.

Earlier invalidation runs are retained. One test mutation used a void probe
argument that generated invalid C; another added a separate unused provider,
which DTrace rejected because it had no probe sites. The passing mutation adds
a probe to the existing provider. These fixture corrections do not weaken the
rule's error propagation or enable a fallback.

Frontend review: these changes affect maintained candidate action rules/tests;
component emission still rejects DTrace and FIDL until full consumer integration
is implemented. No build-bsd interface or production backend change is needed.

### Native library DTrace provider integration — 2026-10-25

`BSDDTraceInfo` now connects the header rule to `bsd_library`. The library
consumes declared generated headers, registers copy/rewrite actions for each
requested regular/PIC/PIE variant, and archives rewritten objects together with
the provider ELF. Consumers use the existing CcInfo dependency. The standalone
object rule and integrated library share the same action registration helper.
The maintained component emitter copies the newly required rule module even for
libraries without instrumentation; it still rejects full DTrace components.

`/usr/obj/usr/src/bazel-dtrace-library-20261025/receipt.json` records passing
no-op, provider invalidation, original-object preservation, syntax failure and
restoration tests with an archive consumer. `archive-parity.json` verifies that
all three archive variants contain exactly the declared rewritten/provider
object bytes. This is an integration fixture, not a complete libutil build,
Make library parity, package qualification or installed tracing test.

Multiple-provider composition is explicitly rejected until qualified. Static
DOF anchor/retention support remains unfinished: a successful ordinary archive
consumer link does not prove that the linker retains the provider's DOF.
Full configured preprocessor/toolchain inputs and FIDL integration also remain
open. Make remains production, and no frontend selection was enabled by these
candidate rule changes.

### Optional DTrace archive anchor — 2026-10-25

`bsd_dtrace.bzl` now supports an explicit `static_anchor` boolean. When selected,
a separate `BSDDTraceAnchor` action runs the configured objcopy on the provider
ELF and declares a new output containing the Make-compatible hidden global
`__bsd_dof_anchor_<provider-file>` symbol in `.SUNW_dof`. It never modifies the
preceding action's output. Libraries archive this final provider object.

Qualification used the same `used, retain` reference pattern as base tracing
headers. `/usr/obj/usr/src/bazel-dtrace-native-r2-20261025/anchor-retention.json`
records `.SUNW_dof` and anchor symbols retained in regular/PIC/PIE archive
consumers linked with `--gc-sections`; all three Bazel tests executed. The
`anchor-command.json` and execution/event logs retain the command and results.
`/usr/obj/usr/src/bazel-dtrace-anchor-checks-20261025/receipt.json` records byte
parity with Make's in-place objcopy recipe on each matching input object. Turning
off the anchor caused the expected undefined-hidden-symbol link error; restoring
it passed. This establishes fixture ELF retention, not installed probe activation
or full-library Make parity. Tests do not install anything on the host.

Frontend review: component plans already record DTRACE_STATIC_ANCHOR, but native
component emission remains gated. When enabling it, preserve Make's *defined*
semantics, including an explicitly empty value; a nonempty-string check is not
equivalent. Multi-provider composition, configured preprocessing, toolchain
selection and complete libutil/FIDL integration are still open. The standalone
anchor qualification driver is currently diagnostic, not yet a maintained
fixture-construction entry point. Make remains production.

### Configured DTrace inputs for component emission — 2026-10-25

The maintained component exporter now records `dtrace_configuration`: the
executable resolved through the configured Make PATH and its hash, target
syslibdir's drti.o and hash, ordered flags, actual generated-header directory,
and a boolean derived from Make's defined-variable semantics for the anchor.
It rejects ambiguous command wrappers and missing target runtime selection,
rechecks the search path/object directory/anchor setting and verifies file hashes.
This supplies explicit inputs for the forthcoming component emitter; it does
not enable DTrace components or complete the preprocessor/toolchain closure.

`/usr/obj/usr/src/bazel-dtrace-configured-inputs-r2-20261025/components.json`
records real libutil and libfetch configuration: the former disables the anchor,
the latter enables it, both selecting the staged target drti.o.
`/usr/obj/usr/src/bazel-dtrace-anchor-defined-semantics-20261025.json` records
configured Make queries for absent, empty, literal no and yes anchor values.
Only absent disables the anchor, matching the existing Make recipe exactly.

Frontend review: build-bsd's maintained component-plan helper owns this new
inventory; no CLI option or alternate workflow was added. Component emission
remains gated until tool snapshot mapping, generated-header include remapping,
full library compilation, packaging and runtime checks are qualified.

### Generated include mapping groundwork — 2026-10-25

`libmd_paths.rewrite_includes` now accepts explicit object-directory to workspace
relative mappings. Only these declared generated directories may be absent in a
cold object tree; existing contents are never returned as source-header inputs.
Unknown object directories and escaping/absolute destination mappings fail.
Include ordering and split/joined -I spelling remain intact. The component path
mapping now derives its source-relative directory instead of spelling lib/libmd.

The maintained `include-mapping-test.py` covers cold and populated generated
directories, a stale object header, unknown directories, unsafe mappings,
non-libmd component paths and missing -I arguments. Six tests pass; retained
output: `/usr/obj/usr/src/bazel-include-mapping-20261025.log`.

Frontend review: this is a backward-compatible helper extension. The component
emitter has not yet enabled generated include mappings or DTrace components.
Its next integration must connect mapped directories to declared Bazel header
outputs and preserve configured search order; a relative path alone does not
establish that dependency. Full libutil compilation remains unqualified.

### Full native libutil graph — 2026-10-25

The maintained component emitter now handles a single configured DTrace provider
for C libraries with the qualified `-C -x nolibs` option set. It validates the
selected DTrace executable and target drti.o against the SDK receipt, snapshots
the provider source and emits the header rule/copy runner/library dependency.
Generated header source entries are consumed through that declared rule, not
copied from the Make object directory. Configured object includes map to
`$(GENDIR)/generated/<library>`; native compilation and version preprocessing
expand Bazel's standard make variable at analysis time. Unknown options,
multiple providers and unsupported generated-header flags fail explicitly.

`/usr/obj/usr/src/bazel-libutil-native-20261025/` contains a successful full
libutil graph emitted from a fresh maintained component plan: 34 C sources in
regular/PIC variants, header generation, object rewrites, two 35-member archives,
version map, shared library and debug splitting. `artifact-parity.json` records
matching generated header and version-map bytes, all 306 dynamic symbol records
matching the existing Make library, DOF present in the shared library, and exact
archive member parity with the declared rewritten/provider outputs. The Make
library reference was not rebuilt in this run; its hash is recorded.

`build.stderr` records 6.64 seconds elapsed, 49.17 user seconds, 11.32 system
seconds, 1133340 KiB peak RSS, 940 block input and 2941 block output operations.
This is build process accounting, not a comparative disk benchmark. The run used
16 jobs and did not install or publish anything. Runtime behavior, staging,
package parity and installed tracing still need qualification for libutil.

Frontend review: this is in the component backend used by build-bsd format 3;
its existing explicit SDK tool configuration selects DTrace. No one-off frontend
or new CLI option was introduced. FIDL/C++ and multiple DTrace providers remain
unsupported, full toolchain/preprocessor hermeticity is unfinished, and Make
remains the production backend. Earlier entries saying all DTrace components
are rejected describe the prior state and are superseded by this bounded support.

### Libutil runtime comparison — 2026-10-25

The native-c test configuration now accepts an optional `args` string list,
passed directly to native cc_test. Existing configurations remain valid. The
maintained emitter used this to compile the unchanged base
`lib/libutil/tests/humanize_number_test.c` against the native libutil archive,
with both default arguments and `-n -E`. No test expectations were modified.

`/usr/obj/usr/src/bazel-libutil-runtime-20261025/runtime-comparison.json`
records exact per-case output parity with a freshly Make-built static test using
existing SDK libraries (hashes retained). Both executables have no ELF NEEDED
entries. Default: 228 pass, 31 upstream skips, no failures. Extended: 252 pass,
no skips, seven failures (167, 175, 227, 228, 254, 255, 256). The extended Bazel
test remains failed; the identical Make failures are an unresolved baseline
issue, not grounds to remove or silently accept those cases. An earlier dynamic
Make test also matched but is not the controlled static comparison.

The native test run compiled the full library and tests with 16 jobs; resource
accounting in build.stderr is 6.83 seconds elapsed, 50.45 user seconds, 11.03
system seconds, 1285760 KiB peak RSS, 5001 block input and 3117 block output
operations. This is not a comparable Make performance benchmark.

Frontend review: the optional arguments are handled in the maintained native-c
adapter used by build-bsd format 3, so no alternate test runner or frontend
option is needed. This is humanize_number coverage only. Other TAP tests must
use a TAP-aware runner: some return zero even when they print failures. ATF,
credential, process/PTY, installation/package and tracing qualification remain
open. No host installation or service changes occurred.

### Native TAP testing through Kyua — 2026-10-25

The maintained native test adapter now accepts `suite: native-tap`, using the
same explicit source/dependency/C-flag fields as native-c. It compiles each test
as a native Bazel C binary and registers `bsd_kyua_tap_test`. The test rule
declares its program, generated Kyuafile, selected Kyua executable and runtime
inputs as runfiles; Kyua parses TAP and supplies the test exit status. Its config
is disabled explicitly, and its log/results database go into Bazel's undeclared
output directory. TAP argument lists are rejected until modeled through Kyua.
The SDK tools file selects Kyua through `additional_execution_tools.kyua`.

All six unchanged libutil TAP programs passed in
`/usr/obj/usr/src/bazel-libutil-tap-20261025/`: flopen, grp, humanize_number,
pidfile, trimdomain and trimdomain-nodomain. `build.events.json` and each Bazel
test log retain the results; Kyua results databases are retained as test outputs.
These are default upstream invocations, including upstream internal skips.
The separately recorded seven optional humanize_number failures remain open.

`negative-receipt.json` in the same directory proves that a diagnostic TAP
program printing `not ok` and exiting zero produces a failing Bazel test (exit
3) through Kyua. The fixture source/rule, command and Kyua failure are retained;
the fixture was removed from the normal graph afterward. No custom TAP parser
or conversion of failures to success is used.

The six-suite build/test run used 16 jobs: 7.15 seconds elapsed, 51.58 user,
12.57 system, 1230248 KiB peak RSS, 2705 block input and 4166 block output
operations. These are process counters, not a comparative throughput benchmark.

Frontend review: build-bsd format 3 uses the maintained component/test adapter
and emitted test inventory for this suite. No new CLI option is required.
The runner currently requires the native host /bin/sh and Kyua's host ELF
runtime; staged runtime bytes do not redirect the loader, so hermetic execution
is not claimed. ATF integration and remaining system/package qualification are
still open. Make remains production; no host installation or reboot occurred.

### Native ATF library and libutil tests — 2026-10-25

The component plan now records Make's LIB_PRIVATE, and bsd_library accepts the
configured archive basename. The emitter preserves `libprivateatf-c.a` while
keeping `atf-c` as its logical dependency target. This removes the previous
assumption that every archive basename is simply lib plus the logical name.
The Kyua rule now supports an explicit tap/atf interface; test configuration can
select `native-atf`. Existing TAP defaults remain available.

`/usr/obj/usr/src/bazel-libutil-atf-20261025/atf-runtime-receipt.json` records
four unchanged base test programs linked against Bazel-built libutil and ATF C
libraries. Ten cases passed with no skips: cpuset (4), expand_number (4), forkpty
failure handling (1), getlocalbase environment behavior (1). Logs, Kyua databases,
execution logs and test events are retained. This does not establish normal
interactive PTY/login operation. The two remaining login test programs require
multi-source and linker-wrap declarations before they can join the suite.

The build/test run used 16 jobs: 8.34 seconds elapsed, 56.46 user seconds, 13.57
system seconds, 1288564 KiB peak RSS, 4764 block input and 4523 block output
operations. ATF installation/generated metadata and package parity remain
unqualified; this is native library/test coverage only.

Frontend review: private names and ATF test selection are implemented in the
maintained plan/emitter/test adapter used by build-bsd format 3. No separate
frontend or host installation was introduced. Make remains production. FIDL,
world/kernel completeness, sandbox/runtime closure and broader package/runtime
qualification remain open.

### Libutil login tests and test-input declarations — 2026-10-25

The maintained native test adapter accepts exactly one of `source` or a nonempty
unique `sources` list, plus optional `linkopts`. Every source is snapshotted and
hashed. Explicit source include directories supply declared additional compiler
inputs, including test-only private headers; conflicting snapshots and inputs
escaping the source tree fail. The existing single-source schema still works.
The two login tests use their maintained multi-source/linker-wrap arrangements;
these compile selected implementation sources into the test, as Make does.

The first complete six-program ATF run exposed a shared test defect, reproduced
in a fresh static Make build: login_cap_list_test enabled its realloc injection
before cgetstr had finished decoding. cgetstr calls reallocf, which calls realloc,
so the injection failed the decoder before the temporary existed. The test now
injects only after __wrap_cgetstr has returned that decoded temporary. No library
implementation or expected ownership/errno assertions were weakened.

`/usr/obj/usr/src/bazel-libutil-all-atf-r2-20261025/atf-runtime-receipt.json`
records all 20 ATF cases passing without skips. The corrected ownership test
also passes all three cases in a fresh static Make build under
`/usr/obj/usr/src/bazel-login-cap-make-r2-20261025/`. Earlier failing runs are
retained. `ownership-negative-receipt.json` in the Bazel run proves that omitting
the temporary release in a disposable source copy makes the ownership tests
fail; restoring the source passes. The maintained library source was not mutated.

The full Bazel run used 16 jobs: 9.11 seconds elapsed, 61.11 user seconds, 15.48
system seconds, 1339576 KiB peak RSS, 482 block input and 5067 block output
operations. This is test/build process accounting, not a Make benchmark.

Frontend review: multi-source inputs and link options flow through the existing
build-bsd format-3 native test adapter. The six TAP and six ATF programs now have
native execution evidence, but this is not complete authentication/session,
installed tracing or package qualification. The separate optional humanize_number
baseline failures remain open. Make stays production; no host services changed.

### Native FIDL schema compilation — 2026-10-25

`bsd_fidl.bzl` introduces a native `bsd_fidl_ir` action and typed BSDFidlIrInfo.
It takes ordered schema inputs, explicit platform availability/flags, an
execution-platform compiler and runtime inputs. An explicit --available flag
wins over the default, matching the maintained generator's selection rule.
The action declares its JSON output and uses FilesToRunProvider for the compiler.
It does not wrap Make or the whole binding-generation pipeline.

`/usr/obj/usr/src/bazel-fidl-sdk-20261025/` records successful Bazel compilation
of the real zx and BSDLog schemas at bsd:1 with the selected, snapshotted
Make-bootstrap fidlc. This does not qualify building fidlc itself with Bazel.
`ir-binding-parity.json` records that passing the native IR through the existing
Python generator produced all nine binding files byte for byte identical to the
recorded Make generation. The Python generation in this check ran directly;
it is not yet a native Bazel binding action or compiled C++ consumer test.

`build.stderr` records 4.54 seconds elapsed, 31.77 user seconds, 4.68 system
seconds, 823152 KiB peak RSS, 14 block input and 1072 block output operations.
This is a small action fixture's process accounting, not world performance.

Frontend review: the maintained SDK helper accepts fidlc through explicit
additional_execution_tools input. The component frontend still rejects FIDL
components until binding generation, declared Python/template/runtime closure,
C++ compilation, invalidation and package/runtime tests are implemented. No
new CLI or alternate build workflow is enabled. Make remains production.

### Separate FIDL IR and binding generation — 2026-10-25

The maintained fidlgen-build.py now accepts either schema inputs (the existing
Make path) or `--ir` for an already compiled intermediate representation.
Both modes share generate_from_ir; templates may be selected explicitly.
Compiler options in IR mode are rejected rather than silently ignored. Optional
repeated --expected-output arguments enforce an exact generated-file inventory
before publish, including rejecting undeclared extra files and missing files.
Existing Make invocations and default fidlc/platform selection are preserved.

The candidate `bsd_fidl_bindings` rule consumes BSDFidlIrInfo, explicit generator
modules/templates, interpreter/runtime inputs and named source/header outputs.
It returns BSDFidlBindingsInfo and source/header output groups for subsequent
C++ compilation. It passes the exact output contract to the maintained helper;
it does not discover output files after an opaque build command.

`/usr/obj/usr/src/bazel-fidl-separated-helper-r2-20261025/receipt.json` records
both helper modes matching all nine recorded Make binding files byte for byte.
Missing and extra declarations fail before publish; compiler options supplied
with IR also fail. This verifies the shared helper change, not native execution
of the new binding rule. Explicit Python interpreter/standard-library/runtime
staging and native binding execution are the next qualification gate, followed
by C++ consumers and invalidation tests.

Frontend review: Make/build-bsd continue using the maintained helper's existing
schema mode. Native component emission still rejects FIDL until its remaining
actions and consumers are qualified. No alternate frontend or completion claim
was introduced. Make remains production.

### Staged Python and native FIDL bindings — 2026-10-25

The SDK tools configuration accepts an optional absolute `python_stdlib` with an
explicit `additional_execution_tools.python`. The maintained staging helper
checks the interpreter major/minor version, inventories/hashes/copies the
standard library and inspects native-extension ELF dependencies. User packages
and bytecode caches are excluded. Unsupported directory symlinks and escaping
file symlinks fail explicitly. Runtime provenance stays in the receipt; the
runtime marker contains only the version to avoid host-path cache differences.
Four maintained python-runtime-test.py checks pass, recorded in
`/usr/obj/usr/src/bazel-python-runtime-tests-20261025.log`.

The binding action selects its declared Python home, uses -S and disables user
site initialization and bytecode writing. Its inputs include the standard
library and inspected extension dependencies. The host ELF loader remains an
execution dependency; staging bytes alone does not redirect host shared-library
loading or prove full hermeticity.

`/usr/obj/usr/src/bazel-fidl-python-sdk-20261025/native-binding-parity.json`
records successful separate native Bazel FIDL compilation and binding actions.
All nine generated BSDLog binding files match the recorded Make outputs byte for
byte. The execution log confirms the selected Python home and declared stdlib
inputs. The staged standard library has 2478 files (including its marker),
90737740 bytes of content and 56048640 allocated bytes on this filesystem.
The native run preceded the marker/provenance separation and inventory traversal
cleanup; new SDK receipts must be refreshed after those helper changes.

Build accounting: 4.12 seconds elapsed, 31.56 user, 3.90 system, 836304 KiB peak
RSS, 24 block input and 1135 block output operations. This is a small generator
fixture, not a world-build or throughput benchmark.

Frontend review: explicit Python inputs are implemented in build-bsd's maintained
SDK staging helper, with no alternate frontend. Component emission still gates
FIDL pending C++ consumer support, complete schema/template/tool/runtime
invalidation tests and package/runtime qualification. Make remains production.

### Native FIDL C++ consumer qualification (2026-10-25)

`/usr/obj/usr/src/bazel-fidl-cxx-20261025/cxx-consumer-receipt.json`
records nine generated BSDLog files matching the Make reference, three objects
in each regular/PIC archive, and a passing native Bazel C++ consumer test. The
consumer exercises construction, copying, accessors and equality of generated
natural types. Its runtime dependency is the real FIDL coding_errors.cc source;
this does not qualify the complete libfidl library or channel transport.

The library rule consumes BSDFidlBindingsInfo and exports CcInfo. Generated
sources compile through cc_common with configured C++ flags, declared headers
and include roots. The consumer uses the selected compiler's C++ driver for
runtime library selection. Full configured C++ linking and FIDL component
emission remain gated pending broader integration and qualification.

This exposed and corrected the shared Make runtime-includes.mk path for
zircon-assert, whose headers are directly beneath its package root. The source
header collector now includes conventional textual headers such as .inc;
otherwise the generated bindings could not find availability_levels.inc.
The snapshot still contains 8266 source headers from configured include roots.
That conservative closure is not evidence of efficient dependency discovery or
optimal cache invalidation. Narrower exported header dependencies, compiler
input discovery and rebuild measurements remain required.

The successful run used 16 jobs: 8.71 seconds elapsed, 57.84 user, 10.12 system,
1071704 KiB peak RSS, 40632 block input and 882 block output operations. These
are fixture measurements with cache reuse, not a clean-build performance claim.
The current driver remains a diagnostic fixture; a maintained end-to-end FIDL
qualification entry point and input-invalidation matrix are still outstanding.

Frontend review: build-bsd and its maintained component emitter retain the
production Make backend and reject unqualified FIDL components. No new CLI or
package format is introduced by this change.

### Make and Bazel integration acceptance criteria

Make entry points must preserve configured build options, generated inputs,
installation metadata and pkgbase/hardware publication semantics while native
Bazel targets own compilation, generation, linking and tests. Whole-build Make
commands inside Bazel actions do not qualify as migration. Ports retain Make.

Qualification must cover explicit execution/target toolchains, typed generator
providers, transitive CcInfo, sandbox input closure, deterministic outputs,
no-op builds, selective invalidation and clean-versus-incremental equivalence.
Cache reuse across workspace locations and concurrent builds must be measured;
host tools and libraries still used implicitly must be removed or explicitly
reported before hermeticity or remote-execution support is claimed. Production
backend selection remains gated on world, kernel, install, package and runtime
parity, including DTrace and FIDL, plus disk I/O and memory measurements.

### Maintained FIDL action-invalidation checks (2026-10-25)

`tools/build/bazel/fidl-action-test.py` now accepts an explicit prepared private
workspace, Bazel command, Java home, expected test labels and JSON mutation
cases. Each case specifies one exact input replacement and required/forbidden
executed action mnemonics. Inputs are restored on failure. The runner retains
commands, Bazel event/execution logs, time/resource accounting and a receipt;
it refuses external mutation paths and multiply linked input files. Successful
commands must contain exactly the expected passing test summaries.

The original four-case run is retained under
`/usr/obj/usr/src/bazel-fidl-invalidation-20261025`. It established no-op cache
reuse, schema changes propagating through bindings and C++ compilation,
template changes leaving the schema compiler cached, a generator-module
comment edit rerunning binding generation without C++ recompilation when the
outputs were unchanged, and invalid FIDL failing before binding generation.
Restored inputs build successfully. This first run predates the added exact
test-inventory check; the strengthened run is recorded separately.

This is a maintained runner for a prepared graph, not yet a complete graph/SDK
preparation path. Compiler/Python runtime and flags invalidation, cross-workspace
cache equivalence, full libfidl/channel behavior and integrated package tests
remain outstanding. Build-bsd's existing qualification helpers and production
backend selection are unchanged; full FIDL component emission remains gated.

The strengthened five-case run passed:
`/usr/obj/usr/src/bazel-fidl-invalidation-r2-20261025/receipt.json`.
Every successful invocation reported the expected //:type_consumer test as
PASSED. An unrelated declared ARM header change caused no executed actions,
and neither did restoration of that header. This demonstrates selective input
invalidation for this graph despite its broad declared header snapshot; it does
not remove the snapshot's staging/analysis cost or prove world-scale behavior.
The receipt binds the maintained runner hash and records original input hashes.


### FIDL configured tool and output contract (2026-10-25)

The maintained component planner now records the FIDL compiler and Python
executable selected through Make's configured PATH, their hashes, and the
component object directory. Each binding records its configured generation
root, generator input, template directory, and source/header paths relative to
that root. Paths and tool commands are validated; embedded executable arguments
are rejected pending an explicit mapping, rather than silently discarded.
Conventional .C sources now query per-file CXXFLAGS alongside .cc/.cpp/.cxx.

`/usr/obj/usr/src/bazel-fidl-configured-tools-r2-20261025/configuration-check.json`
checks the fresh real BSDLog plan against the staged SDK: both executable paths
and hashes match, all nine output paths map correctly, and generator/schema/tool
source hashes match. This is configuration evidence, not a new component build.
Earlier component plans need regeneration because the planner hash changed.

Frontend review: these fields extend the maintained build-bsd component-planning
backend. The component emitter still rejects FIDL until the full C++ and runtime
dependency graph is integrated and tested. No alternate build frontend, host
installation or production-backend switch is introduced. Next work is to consume
this explicit contract in native graph emission and qualify complete selected
libraries, followed by installation/package and runtime parity.


### Native FIDL emission and C++ library integration (2026-10-25)

The maintained component emitter now consumes the explicit FIDL contract through
configured_fidl.py. It checks staged compiler/Python identities and the declared
Python runtime, accounts for every generator input, emits native IR/binding
rules, and maps configured generated include directories. Generated outputs have
explicit ownership; conflicting FIDL/DTrace output paths are rejected. Libraries
compile C++ using their configured CXXFLAGS and per-file CXXFLAGS, and pass the
generated bindings provider into the native library rule. C++ program emission
and unknown languages remain explicit errors.

Shared-library driver selection now follows Make's expanded _LD value compared
with CC/CXX. This preserves BSDLog's C driver with its explicit cplusplus library
dependency and libfidl's C++ driver. Custom link drivers require explicit support.
All library dependencies must still be present in the selected component graph;
this integration does not silently import missing runtime libraries from the
host or drop dependency edges.

`/usr/obj/usr/src/bazel-fidl-emission-check-20261025/receipt.json` records the
maintained metadata-derived FIDL rules running in the prepared C++ consumer
graph: nine generated files match Make and //:type_consumer passes. Four negative
cases reject a wrong compiler, missing Python runtime, escaping output and an
unmapped generator input. This fixture uses the emitted generator rules, not yet
the complete emitted liblogcmp/libfidl dependency graph. Its driver remains a
diagnostic script; end-to-end maintained preparation is still required.

Fresh metadata under
`/usr/obj/usr/src/bazel-fidl-emission-plan-r2-20261025` records CC selection for
liblogcmp/libshmring and CXX selection for libfidl. A separate real libshmring plan
and unmodified maintained component emitter produced
`/usr/obj/usr/src/bazel-shmring-emission-20261025`: all native targets built,
including DTrace, regular/PIC archives, shared library and debug/strip outputs.
The build-command.json and Bazel event/execution logs retain the result. At 16
jobs it took 4.63 seconds elapsed, 32.99 user, 5.12 system, 854728 KiB peak RSS,
2532 block inputs and 1376 block outputs. No install or runtime/package parity
claim follows from this build.

Frontend review: build-bsd's maintained component-emission backend now exposes
these candidate library capabilities through its existing qualification path.
Production remains Make. Complete libfidl/liblogcmp dependency closure, native
runtime tests, package parity and broader C++ linking qualification remain gates;
older statements that the emitter rejects all FIDL are superseded by this entry.


### Configured library aliases and final link order (2026-10-25)

The component planner now exports each LIBADD entry's LIB*SRCDIR, LDADD_* and
DPADD_* values from Make. The native component emitter resolves dependency labels
through these source identities using library_dependencies.py. It no longer
assumes that logical LIBADD names equal a library's output name. In particular,
pthread maps to lib/libthr (target thr), and cplusplus maps to lib/libc++
(target c++); no hand-maintained alias table is used.

The first real-config check exposed Make's intentional final reordering of
pthread/c/sys in bsd.libnames.mk. The resolver now uses final LDADD order rather
than LIBADD order. For libfidl the resulting direct targets are channel, c++,
thr. Eight maintained library-dependencies-test.py checks pass, including
reordering, aliases, missing/ambiguous components, extra linker options, groups
and repeated libraries. Repetitions/groups are rejected until typed linker
sequence support exists; CcInfo set merging must not silently deduplicate them.

Evidence: `/usr/obj/usr/src/bazel-runtime-dependencies-20261025/dependency-check.json`
and `/usr/obj/usr/src/bazel-library-dependencies-test-20261025.log`.
This verifies mapping, not the final complete link command or full library build.
The six-component inventory still lacks libc, libsys, libcxxrt, libcapability,
libcapsulert, libshmring and libtrustedzfs, plus their further dependencies.

The planner also records SHLIB_LDSCRIPT. Native emission explicitly rejects a
configured shared-library linker script until its build/install/consumer-link
semantics are implemented. libc++ uses such a script to bring in libcxxrt;
ignoring it would be incorrect. This is a concrete remaining runtime dependency
gate, alongside generated sources and complete library closure.

Frontend review: changes are in build-bsd's maintained planning/emission helpers,
with fresh-plan requirements when dependency records are absent. Make remains
production/default. Prior component snapshots need regeneration; no fallback to
host libraries, omitted dependency edges, installation or publication occurred.


### Native shared-library linker-script generation (2026-10-25)

shared_link_script.py now exports the maintained bsd.lib.mk transformation using
SHLIB_LDSCRIPT, SHLIB_LINK, SHLIB_NAME, _LIBDIR and _SHLIBDIR. Template bytes are
hashed; the output name, substitutions and installed pathname are explicit
configuration. Source escapes and directory values whose sed replacement
semantics would differ from literal substitution are rejected.

bsd_link_script.bzl uses ctx.actions.expand_template, with a declared template,
substitution map and output. No shell, sed executable or hidden host-file lookup
is required for the Bazel action. The component planner records this contract
under shared_link_script and binds the exporter helper hash.

`/usr/obj/usr/src/bazel-cxx-link-script-20261025/receipt.json` records a native
Bazel generation matching a fresh isolated Make libc++.ld target byte for byte:
`GROUP ( /lib/libc++.so.1 /usr/lib/libcxxrt.so )`.
The configured plan is under
`/usr/obj/usr/src/bazel-cxx-link-script-plan-20261025`; the Make command receipt,
Bazel command/event/execution logs and generated artifacts are retained. The
Bazel fixture used 1.92 seconds elapsed, 7.56 user, 0.55 system, 441352 KiB peak
RSS, 2 block inputs and 777 block outputs. These are small-artifact measurements,
not system-build performance results.

Make installs this generated script as a regular libc++.so file with development
package tags, rather than a shared-library symlink. Full native integration must
represent that install role and qualify consumers resolving both the versioned
C++ library and libcxxrt through the selected sysroot. The existing component
emitter/install-policy linker-script gates remain intentionally in place until
those semantics pass. This turn qualifies generation only; the diagnostic driver
is not yet a maintained end-to-end preparation entry point.

Frontend review: build-bsd's maintained component planner includes the new
contract; no production backend or installation behavior changes. Remaining work
is script installation/consumer-link integration, the runtime dependency closure,
and world/kernel/package/runtime qualification. Make remains production/default.


### Linker-script installation policy and libc++ Make stage (2026-10-25)

The maintained installation-policy exporter now recognizes shared_link_script as
a generated regular development-package file. It re-exports the configured
transformation, compares it with the component plan, and verifies installed
bytes against the template/substitutions. library_install.py maps that role to
an explicitly supplied generated artifact label. Additional linker-script links
and full native consumer linkage remain gated.

A fresh 16-job Make build and private staging completed at
`/usr/obj/usr/src/bazel-libcxx-install-reference-20261025/receipt.json`.
No host installation occurred. The reference occupies approximately 39 MiB on
this filesystem. A candidate batched-query exporter reconciled all 1671 libc++
payloads under
`/usr/obj/usr/src/bazel-libcxx-install-policy-batched-candidate-20261025/inventory.json`.
It recorded 147 buildenv calls. The existing exporter reparses Make per header;
its original comparison run remains pending at the end of this update (exec
session 51718, process 48525). Do not restart it merely because observation times
out. The maintained exporter has not yet adopted query batching. Candidate
source: /tmp/libmd-library-install-plan-batched.py; original snapshot:
/tmp/libmd-library-install-plan-before-batching.py. Compare payloads, metadata
and queried_groups before accepting the batching change.

`/usr/obj/usr/src/bazel-cxx-link-script-manifest-20261025/receipt.json` verifies
native generated script bytes and a native install manifest against the actual
Make stage. /usr/lib/libc++.so is a regular root:wheel 0444 file tagged
package=clibs,dev. This is one native payload/manifest check, not complete native
libc++ staging, package production or consumer-link qualification.

Frontend review: the normal maintained installation-policy/artifact helpers are
updated, while build-bsd's production backend remains Make. Native component
emission still rejects linker-script libraries pending consumer-link integration.
The outstanding original-versus-batched comparison is a performance check, not
permission to omit headers or weaken payload reconciliation.


### Installed linker-script sysroot consumption check (2026-10-25)

LLD's ScriptParser::addFile rebases absolute script inputs only when the script
is inside the selected sysroot. Passing an installed script as an arbitrary
outside-sysroot linker input would therefore be unsafe: it can resolve absolute
paths against the build host. Full native graph integration must preserve the
selected sysroot or represent the script's dependency semantics explicitly.

`/usr/obj/usr/src/bazel-cxx-script-consumer-20261025/receipt.json` records a direct
staged-compiler test using an installed script byte-identical to the native
Bazel-generated artifact. The link trace resolves libc++.so.1 and libcxxrt.so
inside the private staged SDK. A C++ exception/string consumer runs successfully
with that SDK's library paths. A deliberately missing runtime path in the private
script fails with LLD's selected-sysroot diagnostic; restoration rebuilds and runs
successfully. Original script bytes and mode were restored. The selected target
is checked against the recorded SDK receipt.

This is not bazel test or qualification of Bazel-built libc++: it uses existing
Make-built SDK libraries and the host ELF loader. No host installation occurred.
The full native component/linker-script gate remains. The original per-header
policy-export session 51718 remains active; batched-export adoption is still
pending comparison with its result. No restart was performed on observation
timeouts. Build-bsd production remains Make; frontend behavior did not change
in this consumption-check turn.


### C/C++ include-search semantics corrected (2026-10-25)

Runtime-library review found that the toolchain forced explicit system header
paths even when components requested -nostdinc++ or -nostdinc. Replacing only
the C++ path with -stdlib++-isystem exposed another ordering problem: manually
injected C paths preceded libc++ and broke cstdio/cerrno. Those failed candidate
logs are retained under bazel-cxx-include-policy-20261025.

The maintained native_cc_toolchain_config.bzl now lets the selected FreeBSD
Clang driver order its headers, with an explicit staged --sysroot and staged
-resource-dir. It no longer forces -nostdinc plus explicit C/C++ -isystem paths.
The driver's supported flags now control standard/builtin header inclusion.
libmd_paths.py also maps -isystem, -iquote and -idirafter source/generated include
paths while preserving their search classes, order and split/attached syntax.
Nine maintained include-mapping tests pass in
`/usr/obj/usr/src/bazel-include-classes-test-20261025.log`.

`/usr/obj/usr/src/bazel-cxx-include-policy-r3-20261025/receipt.json` records the old
policy failing the maintained -nostdinc++ probe and the corrected policy passing
that probe plus the generated FIDL C++ consumer. The C/DTrace graph and both
maintained C header probes pass under
`/usr/obj/usr/src/bazel-c-include-policy-r2-20261025/receipt.json`; the old policy
fails the -nostdinc probe. -nostdlibinc retains a verified Clang resource header
while excluding target stdio.h. The initial C fixture incorrectly assumed that
stddef.h lived in Clang's resource directory; BSD supplies it in the target
system headers, so the retained corrected probe uses an actual resource header.
All private workspace changes were restored. Tests use 16 jobs. These are
component/toolchain checks, not a complete runtime/world qualification.

Frontend review: build-bsd's maintained SDK staging helper copies and hashes
native_cc_toolchain_config.bzl, so new SDKs receive this policy. Existing SDK
receipts must be regenerated; stale snapshots must not be accepted as current
qualification. No CLI or production-backend change is needed. The original
per-header installation exporter (session 51718) remains active; its pending
comparison still gates adoption of query batching. Full runtime dependencies,
linker-script native integration and world/kernel/package gates remain open.


### Batched policy queries adopted; complete native libcxxrt candidate (2026-10-25)

The original libc++ policy export completed successfully. Its 1671 payloads,
metadata, queried header overrides, package selection, excluded payloads and
Make include closure exactly match the batched candidate. The maintained
libmd-library-install-plan.py now batches queries; calls fell from 1771 to 147.
Evidence: `/usr/obj/usr/src/bazel-libcxx-install-policy-batching-20261025.json`.
This is a query-count reduction, not a measured whole-system speedup. The former
pending session 51718 is complete and must not be restarted.

lib/libcxxrt/Makefile now declares VERSION_MAP_TEMPLATE.* and
VERSION_MAP_SED_ARGS.* for its generated maps, and its existing Make recipes use
those same values. configured_version_filter.py exports the selected template
and inline substitution arguments without parsing recipes or guessing ABI size.
Unsupported file-reading/writing sed commands are rejected. bsd_version_filter.bzl
runs the explicitly staged sed and stdout redirect tools as a native declared
action. The maintained component planner/emitter carries that generated map into
the shared-library link. The amd64 64-bit map is qualified here; other target ABIs
and the powerpc64le substitution remain separate cross-build gates.

Fresh native staging uses the corrected driver header policy at
`/usr/obj/usr/src/bazel-cxxrt-sdk-20261025`. The maintained emitter built all nine
libcxxrt sources, regular/PIC archives, generated map, shared library and debug/
strip outputs under `/usr/obj/usr/src/bazel-cxxrt-native-20261025`.
`artifact-runtime-receipt.json` records matching version-map bytes and all 375
dynamic-symbol records against the fresh Make build/stage at
`/usr/obj/usr/src/bazel-cxxrt-make-reference-20261025`. Both archives contain nine
objects. A C++ exception/string consumer ran with the native library; the retained
loader trace confirms that libcxxrt.so.1 came from the native output directory.
Other runtime libraries remain Make-built. This direct consumer check is not yet
a maintained bazel test entry point, and native install/package parity is open.

The 16-job native build used 5.26 seconds elapsed, 37.68 user, 6.55 system,
984084 KiB peak RSS, 1392 block inputs and 1585 block outputs. The whole native
qualification directory uses 1848149 KiB, including 1186374 KiB for its copied SDK
and 652285 KiB for Bazel's user root. The separate Make reference uses 3213 KiB;
these directory scopes are not comparable build-output measurements. SDK and
Bazel cache overhead must be accounted for and amortized in system-scale tests,
not presented as library artifact size or ignored.

Frontend review: all generation and query changes are in maintained Make metadata
and build-bsd planning/emission/staging helpers. Make remains production/default.
Remaining work includes full libc++ generation/linker-script integration, complete
FIDL runtime dependencies, maintained native runtime tests, install/package parity,
and world/kernel/bootstrap/cache/sandbox/performance qualification.


### Maintained C++ ABI tests and libcxxrt native staging (2026-10-25)

native_c_tests.py and the maintained component emitter now accept the explicit
native-cxx suite for C++ source extensions. Test flags/link options remain explicit
configuration inputs, and dependencies must select native library targets. Existing
C/TAP/ATF suites keep their source-language checks. The maintained
`tests/cxxrt_abi.cc` exercises exception-copy/destructor lifetimes, typed catches,
successful/failed dynamic_cast and one-time local-static initialization without
libc++ headers. A volatile pointer prevents constant folding of the dynamic type.

The libcxxrt install policy reconciles four package payloads, and the directory
policy derives six ancestors from maintained Make/mtree inputs. The first emit
attempt rejected the stale gzip receipt's Makefile.inc1 hash. Fresh static gzip
and installer tools were built with maintained static-execution-tools.py at
bazel-cxxrt-gzip-20261025 and bazel-cxxrt-installer-20261025; their receipts passed.
The failed generated workspace was removed only after retaining its rejection
record; checks were not relaxed and no stale hash was rewritten.

`/usr/obj/usr/src/bazel-cxxrt-stage-20261025` now contains the normal emitted build,
maintained native C++ test and native installation action. Bazel test reports
//:cxxrt_abi PASSED. stage-parity.json verifies all four payloads, six directories,
one symlink, metadata and native payload-byte identity against reconciled Make
policy. Independent Make/Bazel compiled-byte identity is not asserted. The test
object has unresolved __dynamic_cast, __cxa_throw and __cxa_guard_acquire calls,
showing that the intended runtime operations survived compilation.

`dependency-check/receipt.json` records a negative test: removing only the test's
native cxxrt archive dependency produces undefined ABI symbols, and restoring it
passes. Private graph changes were restored. The negative driver is diagnostic;
the ABI source and native test emission are maintained.

At 16 jobs the native build/test/stage used 5.46 seconds elapsed, 38.35 user,
7.36 system, 1005580 KiB peak RSS, 4829 block inputs and 1696 block outputs. Its
package tags belong to the shared clibs family. No libcxxrt-only archive is being
claimed as a complete clibs package: complete family inventory and contributions
must be qualified before package-family completion/publication claims. No package
archive, host installation, publication or reboot occurred in this step.

Frontend review: build-bsd's existing qualification path consumes native-cxx via
the maintained emitter. The normal staging helpers and policy checks were used;
no alternative frontend or production-backend switch was introduced. Remaining
work includes full libc++/FIDL dependencies and linker-script integration, complete
pkgbase family coverage, world/kernel and broader runtime/performance gates.


### Native build integration audit (2026-10-25)

The maintained Bazel README now records the Make/Bazel integration contract and
remaining qualification gates. A libc++ audit identified static-only runtime
objects and inherited per-source C++ flags; unsupported archive additions are
rejected during native emission. Effective charconv.cpp compile-context export
matched Make's dry-run command after separately accounting for Make dependency
file options. The context helper is not yet integrated into native emission.
This establishes neither a full libc++ native build nor world/kernel completion.
Make remains the production backend; sandbox and portable cache qualification
remain outstanding. No installation, publication or security-policy change was
performed. See tools/build/bazel/README.md for evidence paths and next gates.


### C/C++ variant correction verified (2026-10-25)

Native archive emission now distinguishes C and C++ shared/PIC/PIE flags using
maintained Make metadata. Six real Make compile-context comparisons passed, and
a freshly emitted native libcxxrt build passed its ABI test. Evidence and resource
measurements are recorded in tools/build/bazel/README.md. Source-context integration
and full world/kernel qualification remain incomplete. The production frontend
still selects Make; this change performs no installation or security-policy change.


### Static archive source inventory (2026-10-25)

libc++ now shares its static-only source alias/origin mapping between maintained
Make rules and component-plan export. Nine actual Make aliases and nine effective
compile contexts passed verification; invalid mappings were rejected. Native
STATICOBJS emission remains gated pending complete action integration. Evidence
and limits are documented in tools/build/bazel/README.md. This is build metadata
work, with no change to runtime security policy or the production backend.


### Static-only native actions qualified (2026-10-25)

Native Bazel source providers now preserve configured static-only aliases and
compiler flags. A real nine-source runtime qualification passed ABI tests and
proved those objects appear only in the regular archive. The first run exposed
omitted extensionless C++ headers; the maintained generic header collector was
corrected and the failed evidence retained. Full libc++ and world/kernel remain
unqualified. See tools/build/bazel/README.md for test paths, cache/resource scope
and remaining gates. Runtime security policy and production Make selection are
unchanged.


### Effective ordinary-source flags integrated (2026-10-25)

Native library actions now consume effective source/object compiler contexts.
A fresh libcxxrt build passed its ABI test and all 18 compiler-command comparisons.
The full libc++ context inventory exported successfully, including inherited
charconv flags, but its 130-second query cost needs improvement before world-scale
use. Full libc++ build/stage and world/kernel qualification remain outstanding.
See tools/build/bazel/README.md for evidence and scope. Production remains Make;
no installation, publication or runtime policy change was performed.


### Full native libc++ build; host fallback caught and corrected (2026-10-25)

The selected native libc++/libcxxrt graph now builds and passes static and dynamic
consumer tests. Loader checks initially exposed host-library fallback despite a
green dynamic test. A test-only toolchain runtime-path feature and mandatory
declared-library checks in component qualification correct that gap. The checker
rejects the earlier host-fallback binary. Installed shared artifacts retain their
normal runtime-path policy. Host system runtime/loader dependencies remain, so
hermetic execution is not claimed. Full libc++ stage/package and world/kernel
qualification remain open. Evidence and limitations are in the Bazel README.
No host installation, publication or reboot occurred.


### Fresh native library staging parity (2026-10-25)

Fresh Make references and package-derived policies now reconcile native libc++
and libcxxrt staging: 1675 payloads, 93 directories and one symlink. Static/dynamic
consumer tests and declared-library loader checks passed. ELF metadata and dynamic
symbol records match the fresh Make libraries; complete ABI or compiled-byte
identity is not asserted. The broader clibs package remains incomplete, so no
package-family completion or publication is claimed. The Bazel README records
evidence, resource measurements and next gates. Production remains Make, with no
host installation, upgrade or reboot.


### Bazel configuration export performance (2026-10-25)

Bounded parallel ordinary-source context queries preserve the same configured
libc++ graph and all 248 query records in a serial/16-worker comparison. Elapsed
time decreased from 123.52 to 28.60 seconds; CPU consumption increased. The
maintained comparison checker rejects omitted queries and changed configuration
and has negative regression coverage. Aggregate concurrent memory and world-scale
performance remain unqualified. See the Bazel README for evidence and limitations.
No runtime security policy, installation or production backend changed; Make
remains production and BIP remains out of scope.


### Native assembly configuration progress (2026-10-25)

Existing .S library sources now have explicit compiler contexts in the generic
Bazel planner/emitter. Twelve assembly recipe comparisons and six C/C++ regression
comparisons passed against maintained Make. Full libsys export exposed and fixed
an argument-size problem by batching configuration queries without reducing
coverage. Its 450 generated sources and static compiler-runtime linkage still
need native graph support. No libsys native-build or broader system qualification
is claimed. Evidence and limitations are recorded in the Bazel README. The normal
build-bsd helper path incorporates the changes; production remains Make.


### Native compiler runtime built (2026-10-25)

The complete selected 165-source compiler_rt archive now builds through native
Bazel actions; a direct arithmetic/assembly conversion consumer test passed.
Three assembly action flag comparisons and independent Make archive-member order
comparison passed. Metadata-driven static-only dependency selection is implemented,
but static-in-shared runtime qualification remains pending. Installation policy
correctly rejects an unsupported generic compatibility symlink, so no package or
stage completion is claimed. See the Bazel README for evidence and measurements.
Native-build coverage is ten libraries and two utilities; production remains Make.


### Compiler runtime compatibility link staged (2026-10-25)

Generic configured SYMLINKS are now derived from maintained Make policy and
reconciled against actual installation metadata. The compiler_rt native stage
passed checks for its archive, compatibility symlink and three directories;
the arithmetic/conversion test executed successfully again. This fixes the
previous explicit symlink-policy rejection without a component-specific exception.
The Bazel README records evidence and resource measurements. Package installation,
static-in-shared behavior and whole-system qualification remain pending. Production
remains Make and no running-system installation was performed.


### Static-in-shared native runtime qualification (2026-10-25)

A maintained test mode now exercises metadata-selected static archives inside a
shared wrapper and checks actual loader identity. The compiler runtime fixture
passed direct arithmetic/assembly conversion tests, defines seven selected runtime
symbols and has no dynamic dependencies. Removing its native archive makes the
strict link fail. This is bounded mixed-link/runtime evidence, not libsys or whole
system completion. The Bazel README records receipts and resource measurements;
Make remains production and native component coverage is unchanged.


### Syscall generation shared with Make (2026-10-25)

All 450 configured amd64 syscall stubs now generate through declared native Bazel
actions using a maintained script shared with Make. Every output matches fresh
pre-refactor Make generation byte-for-byte. Missing source include paths are
preserved without dummy directories. The actual libsys build remains FAILED on
an undeclared textual C include (memcpy.c includes bcopy.c); no runtime test ran.
This is generator qualification, not a converted library. The Bazel README records
failures, receipts and remaining dependency work. Production remains Make.


### Native libsys build and runtime checks passed (2026-10-25)

Explicit Make-consumed textual dependencies fix the missing bcopy.c input, with
private native compiler edges. The complete selected libsys/compiler_rt graph now
builds and executes static/dynamic syscall smoke tests. Loader identity, all 450
generated stubs, 954 compile input sets, two 477-member archive inventories and
1271 dynamic symbol records passed bounded checks against Make/evidence.

An artifact-hash audit exposed transient sandbox paths in DWARF despite earlier
successful cache tests. The toolchain now uses a stable debug compilation directory;
the strengthened cache test proves exact restoration of both archives, the shared
library and both test executables after a meaningful textual-input mutation.
This does not establish remote-cache or whole-system reproducibility. The Bazel
README records receipts, failed intermediate claims' limits and resource costs.
Native coverage is eleven libraries/two utilities. Libsys staging/pkgbase and
whole-system qualification remain incomplete; production stays Make.


### 2026-10-25: selected libsys native stage qualified

The native libsys/compiler_rt stage now verifies all 426 selected payloads,
11 directories, 181 hardlinks and two symlinks against reconciled Make policy.
Both native runtime tests execute and the dynamic loader selects the emitted
libsys. PIC archive installation follows configured Make definition semantics.
Existing precious-library schg flags are preserved in METALOG while private
unprivileged staging files remain writable. Archive-header flag verification has
a real serialization fixture; actual flagged pkgbase archive qualification is
still pending. These are packaging semantics, not BIP or compromised-root
protection. Complete clibs and whole-system qualification remain incomplete.
The Bazel README records evidence, resource observations and remaining gates.


### 2026-10-25: libm native build qualification

All 280 configured libm sources now build natively. Static/dynamic smoke tests,
actual native loader identity, bounded Make ELF/archive comparisons and debug-link
checks pass. Explicit C/assembly fragment dependencies are shared with Make;
all 560 compile actions pass dependency checks. A fragment mutation rebuilds only
the ten expected actions and restoration returns selected artifacts to their
original bytes. Evidence and failed initial assembly-dependency attempt are
recorded in the Bazel README. This raises native-build coverage to twelve libraries
and two utilities, without claiming libm installation/package or full math-suite
qualification. Full-system and performance gates remain open; Make stays default.


### 2026-10-25: libm staging verified; math suite still open

Libm staging verifies 315 payloads, ten directories, 241 hardlinks and one symlink
against Make policy and actual native outputs. Native loader identity and both
smoke tests pass. The full 47-program math suite is inventoried but has not run
against native libraries. Its internal libnetbsd dependency now builds both
configured archive variants with explicit header inputs; runtime qualification
remains open. Link selection respects actual Make outputs even when a default
SONAME exists for a static-only internal library. The Bazel README records the
changes, evidence and outstanding framework-link and full-system requirements.


### 2026-10-25: math-suite framework inputs made explicit

ATF library aliases now drive both maintained Make assignments and native planner
metadata. All 47 math-test Make configurations retain their previous source,
compiler and linker inputs. The native graph still rejects the internal PIE
archive dependency until it can represent that exact selected artifact; no regular
archive or host-library substitution is permitted. Full math-suite execution
remains unfinished. The Bazel README records evidence and the next integration
steps. This is build integration, not additional system protection.


### 2026-10-25: 47-program native math suite qualified through build-bsd

The maintained build-bsd frontend now runs the full configured msun suite using
native Bazel libraries: 47 programs and 463 passing cases, with no skips or expected
failures. Typed PIE dependency selection, loader identity checks inside each test
runner, separate test-only runtime paths, unchanged ordinary binary search paths,
and a negative host-library fallback check are recorded in the Bazel README.
Declarative input format 4 supports build/test-only qualification of multi-program
components; it does not claim installation or packaging coverage. Format 3 retains
those additional gates. Host runtime/kernel, broader test-policy metadata, full
world/kernel/package/bootstrap, cache/sandbox and performance qualification remain
unfinished. Make remains the default. No additional BIP work was introduced.


### 2026-10-25: declared test policy preserved; libc gaps inventoried

Native test plans now capture suite names, per-program Kyua metadata and test
environment policy from maintained Make inputs. Literal supported policy reaches
the generated runners; custom loader paths and custom Kyuafiles fail explicitly.
Exclusive programs also receive Bazel scheduler exclusion. Eleven policy checks
and three framework tests pass; the maintained frontend math run again passes
47 programs and 463 cases. Nondefault policy coverage is currently fixture-based.
The Bazel README records evidence and limits, including separate outer deadlines.

Libc remains unqualified: its thirteen static-only source mappings, archive
variants, shared stubs, archive linker-group dependency and DTrace composition
need native representation. No host or Make-built object substitution is allowed.
These are build-system changes; Make remains production/default and BIP stays out
of scope. Full-system and matched performance qualification remain outstanding.


### 2026-10-25: libc static-source mappings follow maintained inventories

All thirteen regular-only libc source mappings now export from shared Make lists.
A before/after audit preserves Make source/object/link inventories and compiler
contexts, and verifies source origins against Make's search order. Disabling iconv
correctly removes its eleven entries. This closes the metadata mapping gap only;
libc's additional archive and linker semantics remain unqualified. Details and
receipts are in the Bazel README. Make remains the production build backend.


### 2026-10-25: native archive source membership qualified in a rule fixture

The native library rule and maintained emitter now represent per-source archive
variant membership. A native fixture verifies exact regular/PIC/PIE archive
contents and three passing linked consumers; four invalid inventory forms are
rejected. This supports libc's differing object sets but does not qualify libc.
The Bazel README records the evidence and remaining integration work.


### 2026-10-25: NOSSP PIC archive support and libc generation inventory

The libc metadata export completed and exposed 88 generated/aliased inputs still
requiring native rules, plus a shared-only stub missing from the source inventory.
It is not a native libc build. Details are recorded in the Bazel README.

Native NOSSP PIC archives now use effective flag definitions shared with Make.
Unchanged Make recipes and exporter parity pass for C, C++ and assembly. A native
mixed-language archive, its linked consumer, actual compile-action flags and
invalid-input rejection pass focused qualification. These bounded results do not
establish libc, world, kernel, packaging or performance completion. Make remains
the production backend; BIP remains out of scope.


### 2026-10-25: 81 libc source aliases declared without a second file list

Make alias recipes and the native planner now share origin declarations for
cancellation, gdtoa, C99_Exit and jemalloc sources. Metadata/recipe parity and
alias-sensitive flag checks pass. A corrected native output-label rule passes
three archive/runtime fixture checks; the initial failure is retained in the
Bazel evidence. Seven generated-source entries and libc's other linker/object
requirements remain unfinished. The README records evidence and the fresh libc
export. These are build integration changes, not new system protections.


### 2026-10-25: RPC generation validated independently of libc integration

A declared native RPC action produces three files byte-identical to fresh Make
outputs and passes a generated-code XDR roundtrip. Actual actions use the selected
staged rpcgen and preprocessor. The initial dynamic fixture-loading failure and
subsequent explicit static fixture linkage are recorded in the Bazel README.
Automatic RPC metadata/emission through build-bsd remains unfinished; this is
rule-level evidence, not libc, network RPC or full-system qualification.


### 2026-10-25: maintained RPC metadata/emitter path implemented

Libc's RPC recipes and native export now consume shared output, schema, mode and
dependency declarations. Actual Make recipes remain unchanged. The exported record
feeds the maintained native emitter and generated-header path; generated output
byte parity and XDR roundtrip pass. Six policy validation tests pass. The prior
full alias/NOSSP export also completed; it is historical metadata evidence and must
be regenerated after these changes. Complete libc and system qualification remain
unfinished. The Bazel README and build-bsd manual record the boundaries.


### 2026-10-25: lexer/parser generation uses shared Make metadata

The component backend now captures and emits library lexer/parser generation with
selected lex/yacc/m4 identities, declared outputs and generated-header inputs.
Original and updated Make outputs match exactly. Native generated content matches
Make with only enumerated #line path mappings; regular/PIC compilation passes.
Five generator-policy tests pass. These checks do not establish NSS runtime or
whole-libc behavior. Remaining variants and libc linker/object gates are recorded
in the Bazel README; Make remains the production backend.


### 2026-10-25: exact archive order and shared-only source mapping

Native component emission now follows Make's exact archive member order and
rejects incomplete or inconsistent inventories. Reordered archive/runtime fixtures
and a real libnetbsd regular/PIE regression pass. Libc's shared-only stub is mapped
from its maintained Make source list; metadata, recipe and compiler-context parity
pass. This does not qualify the complete libc or its dynamic filter behavior.
A fresh dependency export is running; linker groups and DTrace composition remain
unfinished. Detailed evidence and limitations are in the Bazel README.


### 2026-10-25: DTrace composition passes; reproducibility remains blocked

Native DTrace rewriting now excludes regular-only static objects, matching Make.
The maintained parameterized fixture passes three consumers and verifies exact
regular/PIC membership, compiler-input preservation and linked DOF sections.
Provider-change, invalid-syntax and restoration checks also pass functionally.
These results do not qualify active tracing or complete libc.

A separate restored-byte check exposed different instrumented archive bytes after
restoring the same source. DTrace hashes absolute object paths into symbols;
Bazel sandbox paths vary. The uninstrumented static-only archive remains identical.
The maintained invalidation test now supports explicit restored-output checks and
fails on this difference. Reproducibility remains an open gate; it must not be
hidden by disabling sandboxing or normalizing output comparisons. Detailed inputs,
evidence and remaining libc/linker requirements are in the Bazel README.
The normal build-bsd backend uses the composition change; no new CLI or security
policy is introduced, and Make remains the production backend.


The full libc metadata export exposed a stale assumption that every source has a
regular object. The planner now permits explicitly configured PIC-only sources
while rejecting sources with no object variants. Mapping-policy tests pass; the
replacement full export is pending. The DTrace reproducibility regression also
fails as intended and records both archive hashes without a passing receipt.


### 2026-10-25: explicit reproducible DTrace object identity

An opt-in DTrace linkpath=relative mode removes build-root identity from generated
symbols while retaining object path identity. Direct maintained tests pass across
two roots, distinguish different paths, reject ambiguous path spellings and
preserve default absolute behavior. The native Bazel rule exposes the selector;
fresh-SDK Bazel qualification and normal component-emitter selection are still
pending. No active tracing or system-wide reproducibility is claimed. The rebuilt
private tool was not installed. See the Bazel README for evidence and limitations.


Fresh-SDK native qualification now passes the three composition consumers and
strict provider mutation/restoration checks: regular/PIC instrumented archives
and the static-only archive restore identical bytes. The component backend now
requires relative identities and rejects old unsupported tools through the tool
failure; it retains configured-tool/SDK identity checks. Full component runtime,
active tracing, symbol-composition and broader reproducibility gates remain open.
The libc closure export is still running. Evidence is in the Bazel README.


### 2026-10-25: mixed linker-group inventory and native-rule groundwork

A typed resolver now maps ordered linker GROUP members to configured artifacts;
six rejection/mapping checks pass. A native rule preserves GROUP semantics and
declares every member as an input. The first mixed shared/archive consumer ran,
but its negative control exposed LLD's permissive default archive behavior. The
maintained fixture now enables strict backward-reference diagnostics to distinguish
GROUP from INPUT. Component lowering and runtime dependency propagation remain
unfinished; the normal backend's shared-only guard is still in place. Evidence
and limits are recorded in the Bazel README.


The corrected strict mixed-group fixture now passes: GROUP links and runs, INPUT
fails on the intended backward reference, and restoration recovers. Execution logs
confirm all three native members and the script are declared link inputs. Normal
component lowering remains open; the ongoing libc export is not build evidence.


### 2026-10-25: libc closure exported; group lowering reaches normal backend

The complete selected libc dependency metadata export passed, including the
PIC-only stub and the configured libc.so.7/libc_nonshared.a group. The maintained
backend emitted the selected graph and now preserves mixed GROUP semantics;
installed scripts remain separate. Group-only runtime dependency traversal has
three passing checks, with dependency/test-policy regressions also passing.
No native libc compile, runtime, install or package completion is claimed.

Plan generation now accepts explicit, hash-bound Make execution-tool overrides.
This allows the rebuilt DTrace to be selected without changing the host install
or substituting a tool behind a plan's identity checks. Four validation tests pass;
a fresh full export with the override is running. Old plans are historical after
the exporter change. Details, evidence and outstanding gates are in the README.


### 2026-10-25: native GROUP runtime metadata and shared test dependency checks

Native GROUPs now expose interface/shared-library metadata to Bazel, including
shared members reachable only through the group. The enhanced fixture passes
runtime and strict group-semantics checks without an explicit test RPATH. Generic
native consumers now share the group-aware runtime closure used by ATF; four
traversal/emission tests and eleven policy regressions pass.

Static/dynamic libc smoke sources and maintained frontend inputs are prepared,
including auxiliary-filter, allocation, stdio, mmap and process checks. They have
not yet run against native libc and do not replace the full libc suites. The r3
metadata export remains active. Evidence and limitations are in the README.


### 2026-10-25: explicit-tool libc plan completed; native build launched

The fresh libc dependency export passed and selects the rebuilt DTrace explicitly.
The maintained build-bsd frontend has started the selected native build and both
smoke consumers with sixteen jobs and the matching staged SDK. Graph emission is
running; no libc compilation/runtime success is claimed yet. Evidence paths and
remaining gates are recorded in the README. Nothing was installed or published.


The first native libc attempt reached Bazel analysis and exposed incorrect archive
path handling in the emitter. Configured subdirectory object paths must become
archive basenames under ar -crsD. The correction preserves strict coverage/order
checks; all 165 compiler-rt members match Make's archive inventory. A second
maintained frontend run is active. Native libc compilation/runtime remain unproven.


The second libc run passed analysis and began compiling, then exposed missing
quoted-header search for generated static aliases. The headers were declared;
the compiler searched the alias directory instead of the configured source origin.
The maintained emitter now restores that origin's quoted-header directory per
source. A third frontend run is active; terminal qualification remains pending.


### 2026-10-25: textual libc sources and measured input-size concern

The three static iconv aliases now compile successfully. The next failure exposed
arc4random's undeclared chacha.c fragment. Shared Make TEXTUAL_SRCS declarations
now cover the selected literal C/assembly fragments; source/object inventories and
global flags are unchanged. Validation corrected an initially wrong chacha path;
the invalid export was stopped and a corrected fresh export is running. No libc
runtime success is claimed.

The failed run's action audit records a median 4,314 compile inputs, maximum
14,182, and time reports roughly 5.8 GiB peak RSS. This is a concrete input-size
and memory concern for later matched performance work, not a Make regression
measurement or performance qualification. Detailed evidence is in the README.


### 2026-10-25: per-source header ownership replaces accidental global exposure

The input audit traced much of libc's oversized input set to a per-file kernel
include root being attached to all sources and exported to consumers. The emitter
now keeps extra roots private per source and shares one public context per library.
Variant/runtime/rejection checks pass. A dedicated native test proves private
input isolation, denied consumer access, one-source invalidation and byte-identical
restoration. No required include root or sandbox check was dropped. Full-libc and
matched performance qualification remain open; the export and generated-header
regression are still running. Evidence is recorded in the README.


### 2026-10-25: native libc consumers pass; diagnostic overhead remains open

The libc closure now builds through build-bsd with both static and dynamic smoke
consumers passing. The runtime checker confirms the emitted libc.so.7 and
libsys.so.7 are loaded. This does not qualify all libc tests, installation,
packages, full world/kernel, security mechanisms or performance parity.
The completed r5 receipt and resource evidence are recorded in the Bazel README.
Execution-log finalization exhibited large memory and disk costs. Maintained
qualification now disables log sorting, retaining all action records; a fresh
run is measuring the effect. Compact logging and matched I/O/memory testing
remain open. BIP remains out of scope.


The unsorted-log verification run has now passed both consumers and native
library identity checks. Recorded peak RSS was about 2.4 GiB versus 12.0 GiB
with sorting. JSON disk/output overhead remains; cache state was not controlled,
so this is not a Make comparison or a matched I/O benchmark. See the Bazel README
for exact resource values and receipts.


### 2026-10-25: explicit libc test runtime selection

The normal configured program path previously left compiler-implicit libc to the
prepared SDK. It must not be counted as testing the newly built libc merely
because libc is selected elsewhere in the graph. Qualification inputs now allow
explicit program-runtime-libraries, wired to native link dependencies and ATF
runtime identity checks. Focused dependency/policy regressions pass; actual
maintained libc-suite qualification remains pending. Startup objects still come
from the explicit SDK. See the Bazel README and build frontend manual.


### 2026-10-25: ATF case coverage becomes a maintained qualification gate

Configured ATF qualification now requires an explicit, digest-bound SQLite tool
and reconciles the in-test case listing with Kyua's complete result inventory.
Missing or failed cases reject the run. Skips and expected failures remain
visible, with all_cases_passed false. The new auditor rechecked the existing
47-program/463-case msun evidence successfully; this is an audit of prior results,
not another execution. The libc string closure export remains in progress and
will use this gate. Backend, tests and frontend manual were updated together.


### 2026-10-25: full libc string export completed; emission rejected libmd gap

The closure export completed in 1,238.25 seconds. Graph emission then failed
before compilation on libmd's generated sys/md5.h mapping. Its 14 digest helper
sources also need the standalone libmd generator support integrated into the
generic emitter. No string-suite pass or native compilation is claimed. Both
processes are terminal; retained failure and the next implementation step are
recorded in the Bazel README. The frontend already fails closed on this missing
support; its backend error now names the component and header.


### 2026-10-25: generic libmd generator integration under qualification

The generic component path now exports shared Make declarations for libmd digest
helper generation and header mapping, reusing the existing native generator rule.
Metadata and rejection tests pass; real Make regenerated all 14 helper sources
without changing source/object/flag inventories. Native build parity is pending.
The old SDK receipt correctly rejected the changed Makefile, so SDK plans are
being regenerated normally. No hashes were rewritten or host outputs substituted.
Backend, standalone exporter and frontend manual were updated together.


### 2026-10-25: generic libmd build passed; complete string suite restarted

The corrected generic graph builds libmd successfully. All 14 generated sources
match Make byte-for-byte; the header mapping and exact 28-member regular/PIC
archive order also pass. Effective compile-context capture now includes the new
generated-source kind, and the shared generator declares an explicit Bazel output.
A fresh SDK was staged instead of altering receipt hashes. The full 42-program
libc string export/test run has restarted in r2 outputs; no suite result is yet
claimed. Detailed evidence and retained failures are recorded in the Bazel README.


### 2026-10-25: fresh native bootstrap with output-query patches underway

A fresh current-port Bazel 9.3.1 build is running with strict dependency checks,
cached distribution inputs and the explicit staged JDK. Dependency/checksum
phases passed; applied query patches are present and eight bootstrap helper status
checks pass. The full build remains pending. Current untracked port patches are
included in the input hashes. No host installation or package redistribution
claim is made; concurrent work prevents matched performance conclusions. Evidence
is under /usr/obj/usr/src/bazel931-bootstrap-query-20261025.


### 2026-10-25: configuration-overhead diagnostic

Reusing Make's own exported compiler/linker cache entries preserved three sampled
source/variant contexts and default/alternate tool metadata in an isolated
experiment. This is a candidate optimization, not a production exporter change or
performance qualification. Full-plan parity and binary-identity invalidation are
required before adoption. The active libc export and fresh Bazel bootstrap remain
running with unchanged inputs; detailed evidence is recorded in the Bazel README.


Current-port Bazel bootstrap passed (2026-10-25)
----------------------------------------------
The fresh /usr/obj/usr/src/bazel931-bootstrap-query-20261025/receipt.json now
records passed dependency, checksum and build phases. The patched output query
completed successfully after 5,611 build actions; output/bazel reports bazel
9.3.1. Recorded port/Mk/Templates and staged JDK inputs remained unchanged.
The binary SHA256 is
d8f767a0e193f762c113a84d98f7b50eba12c3c44c299dd742e0e43e87900352.

The build observed 1095.17 seconds elapsed, 2,032,448 KiB maximum resident set,
3,094 block input and 434,990 block output operations. These are time(1)
observations, not aggregate concurrent memory or matched performance results;
the libc configuration export overlapped this run. No host installation occurred.
This closes the fresh bootstrap/output-query check, not package redistribution,
hermetic dependency closure, full-world/kernel or sandbox qualification. The
maintained ports targets were used; build-bsd defaults and CLI remain unchanged.
The separate full libc string-suite run remains pending.


Upstream compact-log converter build (2026-10-25)
------------------------------------------------
Bazel 9.3.1 built its maintained //src/tools/execlog:converter target using the
freshly verified bootstrap binary. Evidence:
/usr/obj/usr/src/bazel931-execlog-converter-r3-20261025/receipt.json.
The 1,381-action build passed with repository downloads disabled. The Go SDK
location was queried from the maintained devel/bazel9 port. Earlier diagnostic
failures are retained: the first selected an incorrect output/cache directory;
the second assumed an unversioned Go path. Neither was a bootstrap failure.

A separate compact-log diagnostic is running at
/usr/obj/usr/src/bazel-libc-compact-log-20261025. It copies and hashes the prior
qualified libc workspace snapshot, uses fresh Bazel outputs and the verified
9.3.1 binary, and repeats native static/dynamic smoke and runtime-library checks.
The compact-log diagnostic passed its two smoke tests and native libc/libsys
runtime checks. The compact file is 2,345,305 bytes; the previous unsorted JSON
file was 7,619,789,822 bytes. Observed build time was 79.99 seconds, peak RSS
1,932,544 KiB, with 253 block input and 41,415 block output operations. A complete
streamed reconstruction/action comparison is running; do not treat log size as
proof of equivalent evidence until that audit passes. This is a logging
experiment, not qualification of current source changes. Concurrent runs are not
matched benchmarks. The maintained frontend continues to use unsorted JSON
logging; no build-bsd default or backend input contract changes have been made
for this experiment. The full libc string suite export also remains pending.


Bootstrap redistribution boundary (2026-10-25 inspection)
--------------------------------------------------------
The explicit staged JAVA_HOME used for bootstrap diagnostics is substituted into
src/main/cpp/blaze_util_bsd.cc as STANDARD_JAVABASE. The maintained Uses/java.mk
also derives DEPEND_JAVA from JAVA, so the diagnostic RUN_DEPENDS contains that
same staged /usr/obj path. This explains the existing non-redistribution limit;
a passing bootstrap binary must not be published as a normal package as-is.
Qualify the port in a standard isolated package-build environment with Java and
other dependencies installed at their intended paths, then verify staged package
metadata and execution outside the build tree. Do not hide the staged path by
rewriting receipts, bypassing dependency checks, or adding a runtime fallback.
No port/frontend behavior was changed by this inspection.


Compact-log audit and string-test textual inputs (2026-10-25)
------------------------------------------------------------
/usr/obj/usr/src/bazel-libc-compact-log-20261025/compact-audit.json passed:
all reconstructed action inventories, build-output digests and the complete
5,474-action compiler-input inventories match the previous unsorted JSON run.
TestRunner output digests are excluded because logs contain run/timing metadata;
their action inventories remain checked. The upstream converter streamed JSON
through stdout; no expanded 7.62 GB file was written. The complete comparison
observed 253.66 seconds and 727,648 KiB peak RSS (time(1), including converter).
These are diagnostic observations, not matched Make/Bazel performance results.

Maintained component qualification formats 3 and 4 now accept the optional
execution-log-format field (json or compact). JSON remains the compatibility
default. Successful receipts bind log format, path, SHA256 and size. Invalid
format values are rejected before graph work; six malformed values were checked.
The build-bsd backend and manual changed together; no new C CLI option is needed.
Full frontend compact-mode qualification remains pending in the run below.

The complete libc string r2 export passed, but its native build failed because
flsl_test.c includes fls_test.c without a declared sandbox input. Inspection found
eight shared-body inclusions in the maintained string tests. Their Makefile now
declares TEXTUAL_SRCS and normal/PIE object prerequisites. The generic emitter
passes program-local textual fragments via cc_binary additional_compiler_inputs;
it does not add separate compiled sources or export these inputs to consumers.
All eight Make source/object/textual inventories passed inspection at
/usr/obj/usr/src/bazel-libc-string-textual-metadata-20261025.json. Existing textual
edge checks pass four cases. The first diagnostic assertion assumed .o; observed
Make selection is .pieo and the declaration/check now covers configured PIE.

Fresh complete export and build-bsd execution are running as
bazel-libc-string-closure-plan-r3-20261025 and bazel-libc-string-native-r3-20261025
under /usr/obj/usr/src, with the verified fresh Bazel binary and compact logs.
All 42 maintained test programs remain selected. No source hashes were rewritten
to reuse the failed plan. Native build, ATF cases and runtime identity checks are
pending; r2's failed evidence remains available. Full-system qualification is not
established by this work.


Next libc suite textual-dependency audit (2026-10-25)
----------------------------------------------------
The stdbit and sys test Makefiles now declare their observed textual C inputs:
all 14 maintained stdbit programs include the shared framework and its nested
kernel, and wait_noproc_wnohang_test includes the common wait body. These files
were confirmed absent from the active string r2 plan's input inventory before
editing; no active string/export helper inputs were changed.

/usr/obj/usr/src/bazel-libc-next-textual-metadata-20261025.json records passed
Make SRCS/OBJS/TEXTUAL_SRCS checks for all 15 programs. Declared paths match the
complete observed quoted-C include closure and do not create extra compiled
objects. Normal and PIE object prerequisites are explicit. This is metadata
qualification only, not native build or execution evidence. The existing generic
component exporter/program compiler-input support handles these declarations;
no additional frontend options, path exceptions or build bypasses were added.
The 42-program string r3 export remains live and pending.


OpenJDK package inputs for isolated qualification (2026-10-25)
-------------------------------------------------------------
The existing OpenJDK 21 package was inspected recursively against exact package
name/version/origin requirements in explicitly recorded local directories. The
first audit found 50 packages and one missing javavmwrapper-2.7.10_2 dependency.
The maintained java/javavmwrapper port then passed package, stage-qa and check-plist
with STRICT_DEPENDS=yes, fresh /usr/obj staging and no host installation.

The first diagnostic incorrectly looked for the result in packages/All. Its
failed receipt remains retained. The corrected artifact check queries the port's
WRKDIR_PKGFILE instead of assuming layout; it verifies the package manifest and
unchanged recorded sources. Evidence:
/usr/obj/usr/src/bazel-javavmwrapper-package-20261025/package-verification.json.

/usr/obj/usr/src/bazel-jdk-package-input-audit-r2-20261025.json now records all 51
packages in the exact recursive JDK dependency closure, with artifact hashes and
no missing versions. This proves local input availability, not repository trust,
installation, package-script execution, ABI compatibility or Java/Bazel operation
in an isolated root. No repository was published and latest was not changed.
Package execution still needs a standard isolated environment with dependencies
at their intended paths; root privileges are required to create/run a jail on
this host. The current session is unprivileged and no sudo/doas/poudriere command
was found. Other native qualification work remains active and unblocked.

This used maintained ports package/stage targets and does not introduce a new
build-bsd action or bypass its backend. The ongoing string-suite source inputs
were unchanged; r3 remains live and has not produced a native test result yet.


Full native libc string suite passed (2026-10-25)
------------------------------------------------
/usr/obj/usr/src/bazel-libc-string-native-r3-20261025/receipt.json records all
42 configured ATF programs passing. The maintained case audit found 138 cases,
all passed, with no skips or expected failures. Recorded in-test runtime receipts
and complete declared/listed/database case inventories were verified. Explicit
program-runtime-libraries=["c"] selected native libc and its native libsys GROUP
runtime, rather than allowing implicit SDK libc to satisfy the test claim.
The selected libraries include libc, libsys, compiler_rt, libc_nonshared,
atf-c, libnetbsd and libmd. The prepared SDK and other host runtime libraries
remain explicit limitations.

The native build completed 11,176 actions. Observed time(1) measurements were
80.62 seconds, 2,119,268 KiB peak RSS, 351 block input and 52,006 block output
operations. These are observations, not a matched Make/Bazel performance claim.
The maintained frontend compact-log option passed; the receipt binds the
2,596,214-byte execution.compact file and its SHA256. Source/configuration bindings
were rechecked. Earlier missing-generator and textual-body failures are retained.
No installation, package, publication, complete libc suite, world or kernel
qualification is implied. Next: expand remaining suites/fixtures and complete
libc installation/debug/package comparisons, then the rest of world and kernel.


Independent component-plan composition (2026-10-25)
-------------------------------------------------
Maintained component-build accepts repeated --additional-plan files. build-bsd
qualification formats 3/4 expose the same facility as additional-plans. The shared
component_plans module validates every original input digest, original plan file
hash, source root, environment/profile/compiler identity and tool override list.
It rejects conflicting digests, duplicate component/program records and duplicate
plan files. It composes records in memory without rewriting input plans or
removing bindings. Workspace provenance retains every source plan pathname/hash;
frontend bindings include all selected plan files. Existing single-plan input
remains supported and was checked against the original completed r3 plan.

Nine focused checks passed: valid union/provenance, duplicate record, duplicate
file, stale source, conflicting hash, environment mismatch, source-root mismatch,
unbound environment input and differing tool selection. The backend and manual
were updated together; no new C frontend option is needed because this is a
qualification input-file field. Native composed-graph qualification is pending.

The next maintained run is at
/usr/obj/usr/src/bazel-libc-stdbit-composed-20261025. It exports all 14 stdbit
programs with the same profile and tool selections, then combines that plan with
the unchanged 42-program string/library plan and runs build-bsd using compact
logs and explicit native libc runtime selection. It does not drop the string
suite or substitute SDK libraries. This avoids repeating configuration export
for unchanged libraries while preserving input validation; no full-world or
performance qualification is claimed.


Composed stdbit/string qualification passed (2026-10-25)
-------------------------------------------------------
/usr/obj/usr/src/bazel-libc-stdbit-composed-20261025/native/receipt.json reports
56 test programs and 208 ATF cases, all passed, with no skips or expected failures.
Runtime identities and complete case inventories passed the maintained frontend
audits. Workspace provenance binds both unchanged original component plans.
Native build: 11,540 actions, 88.79 seconds, 2,037,008 KiB peak RSS, 1,156 block
inputs and 55,689 block outputs; compact log 2,704,442 bytes. These are observations,
not matched performance qualification. Installation/packages remain separate.

The configured libc recursion audit at
/usr/obj/usr/src/bazel-libc-suite-inventory-20261025.json inventoried all visited
34 test/helper directories without query failures and found 353 ATF programs.
It follows Make SUBDIR with the recorded world profile, captures test interfaces,
Make metadata, file-group declarations and helper directories, and rechecks input
hashes. This is a coverage inventory, not execution evidence or a complete runtime
fixture description (some requirements are supplied by test bodies at runtime).

The next run is /usr/obj/usr/src/bazel-libc-stdio-composed-20261025: export libmsun
and all 30 stdio programs, then compose with both qualified string/stdbit plans.
The complete selected suites remain enabled. The existing additional-plans and
compact-log frontend inputs suffice; no new backend/CLI behavior was needed for
this expansion. Native results remain pending. Full libc, world, kernel, package,
sandbox and matched performance qualification remain open.


Libc installation reference started (2026-10-25)
------------------------------------------------
The maintained install-reference.py helper is building libc and its configured
recursive test directories with Make using 16 jobs. Output is private at
/usr/obj/usr/src/bazel-libc-make-reference-20261025. If the build succeeds, the
helper will run maintained distrib-dirs/install with DESTDIR, NO_ROOT,
DB_FROM_SRC and BUILD_PKGS, recording the METALOG and rechecking inputs.
This does not install on the host or publish packages. It prepares an independent
Make installation reference; native installation/debug/package parity still
requires reconciliation and verification. No helper/frontend behavior changed.
The separate composed stdio/libm native qualification is still exporting.
Both jobs are live; their overlapping timings are not performance comparisons.


Composed stdio run and installation gap (2026-10-25)
--------------------------------------------------
/usr/obj/usr/src/bazel-libc-stdio-composed-20261025/native/receipt.json reports
86 selected programs and 399 cases: 396 passed, two expected failures and one
skipped. all_cases_passed is false. The case/runtime audits and native build
passed; they do not convert skips/expected failures into successful cases.
fflush_err and sscanf_whitespace use existing atf_tc_expect_fail declarations in
the maintained NetBSD-derived tests. snprintf_float declares require.user=root
and was skipped by the unprivileged runner. No test source or expectation was
changed to obtain these results. Privileged isolated execution remains required.
The build completed 13,178 actions; observed 91.22 seconds, 1,936,088 KiB peak RSS,
4,848 block inputs and 66,708 block outputs. Compact log: 2,930,313 bytes.
These overlapping-run observations are not a matched performance comparison.

The independent Make libc build, distrib-dirs and private install all passed at
/usr/obj/usr/src/bazel-libc-make-reference-20261025/receipt.json, with inputs
rechecked and host_installed=false. Reconciliation then failed explicitly on
unsupported installation policy CONFS. Libc owns configured account templates,
network/RPC/MAC defaults and an object-directory nsswitch.conf copy. These cannot
be omitted from the installation inventory. Next implement generic maintained
configuration-group/source mapping and generated-copy declarations, preserving
per-file permissions, ownership, destinations and pkgbase config tags. Derive
these from Make, not a libc-specific pathname list. Native installation and
package parity remain unqualified. No source-helper changes were made during
the completed stdio run.


Configuration payload implementation and reference correction (2026-10-25)
-------------------------------------------------------------------------
Generic configuration_install export now consumes bsd.confs.mk's effective
per-file PREFIX/NAME/OWN/GRP/MODE and group TAG_ARGS, retaining configuration and
pkgbase tags. Source payloads are resolved through maintained source search;
object-directory configuration requires declared template generation. Library
installation emits configuration sources/generator artifacts as ordinary declared
Bazel payloads. Stage verification additionally requires configuration bytes to
match the independent Make reference, even if native outputs/METALOG agree with
each other. Two positive/negative configuration-stage checks passed.

Libc NSS generation is now a shared script selected through CONF_GENERATED and
per-output CONF_GENERATOR/TEMPLATE/TOOLS/ARGS metadata. It preserves the existing
MK_NIS=no sed transformations; MK_NIS=yes retains template bytes. Both modes
matched the old recipe byte-for-byte and invalid mode was rejected. Template
outputs use component namespaces to avoid basename collisions. The maintained
build-bsd backend helpers and manual were updated in the same implementation.

The first metadata test found that the old Make reference lacked all configs:
install-reference.py previously ran install but omitted the separate installconfig
phase used by distribution. It now queries configured groups and invokes that
maintained phase when nonempty. A fresh reference passed build, directory setup,
install and installconfig at bazel-libc-make-reference-r2-20261025. All 11 libc
configuration metadata records matched, including master.passwd mode 0600, at
bazel-libc-config-contract-r2-20261025/receipt.json. No host install occurred.
The earlier failed metadata diagnostic and old reference remain retained.

Fresh plans and reconciliation are running under
/usr/obj/usr/src/bazel-libc-config-plans-20261025. Source/implementation changes
invalidate the earlier plans; their hashes were not rewritten. The refreshed
selection is the same libraries and 86 string/stdbit/stdio programs, exported into
independent component plans, followed by maintained build-bsd qualification.
Full libc installation-policy reconciliation, native config generation/staging,
package config behavior and privileged test execution remain pending. This work
does not establish complete system or publication qualification.

Package configuration registration follow-up: archive_verify.py now requires
pkg manifest config entries to match the staged config-tagged file set exactly.
Payload bytes and permissions alone cannot prove upgrade handling. Seven
archive-configuration-test.py cases passed (valid/no-config, missing/extra,
outside-package, duplicate normalized paths, and malformed inventories).
The maintained format-3 build-bsd backend uses this verifier automatically;
its manual now describes the stronger check. Actual upgrade/merge behavior
remains a separate unqualified requirement. Fresh Make references for libsys,
compiler_rt and libc_nonshared all passed under
/usr/obj/usr/src/bazel-libc-dependency-references-20261025; host_installed=false
for all three. The libc configuration export remains live.

The refreshed libc component export passed. Its next installation-policy gate
failed explicitly on NLS (libc message catalogues), so the pipeline stopped
before refreshing other components or rerunning the 86-program suite. Evidence:
/usr/obj/usr/src/bazel-libc-config-plans-20261025/commands.json and
libc-install-policy.log. No catalogue payloads were omitted and the failed
result is retained. Next: model bsd.nls.mk catalogue generation, including its
source/prebuild metadata, declared gencat tool, bsd.files.mk installation groups
and symlinks; compare generated bytes with the fresh Make reference. A private
static gencat build has started at /usr/obj/usr/src/bazel-gencat-tool-20261025.
Native configuration/NLS staging and package qualification remain pending.

The declared static gencat tool build passed at
/usr/obj/usr/src/bazel-gencat-tool-20261025/receipt.json. All 27 configured libc
catalogues generated with it match the independent Make stage byte-for-byte:
/usr/obj/usr/src/bazel-libc-catalogue-parity-20261025/receipt.json. The check
queries the configured catalogue list and effective destination/name metadata,
binds source/tool/reference hashes, and installs nothing on the host. This
qualifies generator output parity only; Bazel NLS action, file-group installation,
cache invalidation, and package coverage remain to be implemented/qualified.

NLS implementation follow-up: configured_nls.py exports bsd.nls.mk catalogue
inventory, selected GENCAT identity, source files and ordered NLSSRCFILES inputs.
bsd_nls.bzl provides separate native concatenation and catalogue actions; the
component exporter/emitter and explicit tool-override interface now use them.
file_install.py exports effective bsd.files.mk file-group metadata. Installation
policy carries catalogue provenance and stage verification requires file-group
byte parity with Make. Four real-Make NLS metadata tests and four configuration/
file-group stage checks passed. This uses the maintained build-bsd backend; its
manual was updated, and no additional C CLI switch is required.
A fresh SDK with gencat passed staging at bazel-nls-sdk-20261025. Component plan
refresh/reconciliation and the 86-program frontend rerun are underway at
bazel-libc-config-plans-r3-20261025 (still no complete native installation claim).
Focused native action qualification is at bazel-native-nls-r2-20261025. Its cold
run matched all 27 Make catalogues; the unchanged run had an empty execution log.
The invalidation fixture initially selected set 999 beyond NL_SETMAX; this failed
as expected and is retained. Valid mutation/restoration and concatenation checks
are being completed; these are not full sandbox or performance qualification.

Native NLS rule qualification passed at
/usr/obj/usr/src/bazel-native-nls-r2-20261025/receipt.json: all 27 catalogues match
Make; action logs show 27 cold executions, zero unchanged executions, one for a
valid private source mutation, and one on restoration. Separate concatenation
also matches gencat on the ordered combined input. The invalid set-999 failure
and an unused-set assertion remain retained; the final fixture selects a new set
from actual source IDs within the maintained NL_SETMAX limit. Evidence audit
binds logs/reference hashes and verifies the copied SDK and native rule bytes.
Cold/cached observations were 3.47/2.97 seconds, peak RSS 655072/701532 KiB,
block inputs 166/2 and block outputs 1059/270. These are concurrent-host
observations, not a matched Make performance comparison or sandbox qualification.
The full component plan refresh remains live; installation/package parity is
still pending, and no host installation or publication has occurred.

Installation-source follow-up: install_sources.py now resolves explicit template
and catalogue declarations before looking for source files, for both relative
output names and the selected absolute object directory. Stale generated objects
are neither consumed nor allowed to veto a declared generator. Undeclared object
files and source symlinks escaping the source tree remain rejected. Six maintained
install-sources-test.py cases passed. The installation policy binds this helper;
no component-plan input was changed during the active export. The existing
build-bsd backend and manual reflect this behavior without a new CLI option.

The libc stdlib test component is being exported independently at
/usr/obj/usr/src/bazel-libc-stdlib-plan-20261025 using the same profile and tool
overrides as the active libc refresh. Its Makefile also declares shell tests,
helper programs, pthread/C++/BlocksRuntime dependencies and helper subdirectories;
exporting native program records alone will not qualify the complete directory.
Those requirements must be accounted for before claiming stdlib suite coverage.
The 86-program string/stdbit/stdio requalification and installation reconciliation
remain active under bazel-libc-config-plans-r3-20261025.

The stdlib export stopped on duplicate program inventory. A maintained-Make audit
at /usr/obj/usr/src/bazel-stdlib-program-selection-audit-20261025.json confirms
36 configured programs including two C++ programs. bsd.progs.mk already folds
PROGS_CXX into PROGS, so concatenating the two lists in component-plan.py is
incorrect. Make also passes PROG_CXX for those recursive selections. The current
source lists happen to match because ATF declares .cc sources explicitly; that
does not justify ignoring Make's C++ recursion contract. This is a confirmed
exporter gap, not a passing stdlib qualification. Fix and regression-test selection
after the active libc refresh boundary; changing the shared exporter while that
run is live would invalidate its recorded inputs. Shell tests and helper
subdirectories remain part of the complete stdlib work.

The r3 libc export completed, but its installation gate rejected
SHLIB_LDSCRIPT_LINKS (libc declares libxnet.so as an alias of its linker script).
This failure is retained in bazel-libc-config-plans-r3-20261025. The generic
installation exporter now models that maintained variable and validates
INSTALL_LIBSYMLINK/LSYMLINK, using LIBOWN/LIBGRP/LIBMODE and LIB_TAG_ARGS exactly
as bsd.lib.mk does. Four linker-script-alias-test.py cases passed. Reconciliation
is rerunning against the valid r3 plan at bazel-libc-install-policy-r4-20261025;
no filenames were substituted for the configured alias list. The maintained
build-bsd backend and manual include this installation behavior.
The mixed C/C++ selection fix remains prepared outside the source tree with four
passing real-Make regression checks; it has not invalidated the current plan.

Libc installation-policy reconciliation passed at
/usr/obj/usr/src/bazel-libc-install-policy-r4-20261025/inventory.json: 1,475
selected payloads, including static/PIC/shared/debug/linker-script artifacts,
libxnet.so alias, eleven configs, 27 catalogues, 459 manuals and 972 manual
hardlinks. The alias uses library mode 0444 and package=clibs, matching Make.
This establishes complete selected library payload metadata/coverage against the
independent Make reference, not native stage or full package installation parity.
The existing r3 export remains hash-valid. Remaining exports and the 86-program
build-bsd test run resumed with /tmp/resume-libc-config-plans-r3.py; their logs
are resume-commands.json and resume-export-*.log under the r3 output directory.
Directory derivation/reconciliation started at bazel-libc-directory-policy-20261025.

archive-configuration-integration-test.py now builds real private pkg archives
from maintained mtree-to-plist.awk output. The normal config archive passed full
archive inspection; removing only its config designation produced an archive
that the verifier rejected. Evidence:
/usr/obj/usr/src/bazel-config-archive-integration-r2-20261025/receipt.json.
The first negative fixture removed plist attribute syntax incorrectly and was
rejected by pkg create; its logs remain at the original output path. The corrected
fixture preserves ownership/mode syntax. No package was installed/published;
this does not qualify configuration merging during upgrades. The existing
build-bsd package verifier uses the checked registration rule automatically.

Libc directory reconciliation passed: 41 required ancestors match maintained
mtree/component directory policy and the independent Make stage. Evidence:
/usr/obj/usr/src/bazel-libc-directory-policy-20261025/inventory.json.

Packaging follow-up: libc-owned payloads span clibs, locales and runtime package
families. component-packages.py currently accepts one maintained package directory
and requires its configured archive/plist coverage. Do not suppress that gate or
omit configs/catalogues to package only clibs. Multi-family construction must use
maintained package inventories, and complete installable families require all their
producers (not merely libc's contribution). A partial runtime fixture must never
be published or represented as the complete runtime package. Native selected
staging can be checked independently; full package installation/publication stays
unqualified until producer and package coverage are established.

The refreshed plans for libc, libsys, compiler_rt and libc_nonshared completed
under bazel-libc-config-plans-r3-20261025/plan-{0,1,2,3}. A native closure staging
qualification is now running at /usr/obj/usr/src/bazel-libc-family-stage-20261025
via /tmp/qualify-libc-family-stage.py. It uses maintained policy/directory/graph
helpers, fresh independent Make references for all dependencies, explicit static
installer/compressor receipts, the declared NLS SDK, native static/dynamic smoke
tests, ELF runtime identity checks, and stage_verify. No package is constructed,
installed or published by this run; it cannot establish complete package-family
coverage. The separate maintained build-bsd 86-program rerun continues after
remaining component exports. All backend Python/Starlark files are bound at the
start of the staging qualification; leave them unchanged until its terminal result.
The mixed C/C++ selection change remains prepared but unapplied for that reason.

The libc-family staging run reconciled dependency policies (libsys 424 payloads,
compiler_rt 2, libc_nonshared 1) and combined directory policy, for 1,902 distinct
selected payloads. Graph generation then correctly rejected stale compressor
receipt metadata for /usr/src/share/mk/bsd.dep.mk. Evidence and failure remain at
bazel-libc-family-stage-20261025; no validation was disabled. Fresh static gzip
and install builds passed under bazel-libc-stage-tools-20261025 using maintained
static-execution-tools.py and explicit selections. The native staging retry at
bazel-libc-family-stage-r2-20261025 rechecks all successful policy input hashes and
uses the new tool receipts. Native build/stage/runtime completion is pending.
The normal frontend suite export continues separately; backend source remains
unchanged while these runs bind it. No new frontend input or CLI switch was
introduced by this tool-receipt refresh.


Native libc frontend refresh and hardlink chains (2026-10-25)
-----------------------------------------------------------
The refreshed maintained build-bsd run completed at
/usr/obj/usr/src/bazel-libc-config-plans-r3-20261025/native/receipt.json.
All 86 configured programs built and ran with checked native libc/libsys loader
identities: 399 cases, 396 passed, two expected failures, one root-required skip.
all_cases_passed remains false. No test expectation was weakened. Bazel reported
13,206 actions; /usr/bin/time recorded 92.68 seconds elapsed, 788.57 user,
511.60 system, 2,062,136 KiB peak RSS, 1,533 block inputs and 66,762 block outputs.
These are observations, not a matched Make performance comparison.

The r2 libc-family native stage failed on a valid manual-page hardlink chain.
The installation rules had incorrectly required every alias to reference a
regular file directly. bsd_install.bzl now resolves the declared graph with a
bounded queue in linear time, rejecting missing/symlink targets, cycles and
inconsistent inode metadata. bsd_stage.bzl uses the resolved regular source after
staging regular files; manifests retain literal link relationships. No pathname
exception or flattened package inventory is used. The component emitter and
stage helper bind the installation rule source. Existing build-bsd input formats
and CLI suffice; production remains Make.

Real Bazel hardlink-chain/rejection fixtures and the r3 1,902-payload native
libc-family stage are in qualification. Initial fixture failures (argument name,
offline dependency input, executable layout, unrequested manifest output) are
retained; they are not successful qualification. Full world/kernel/packages,
privileged tests, bootstrap packaging and matched performance remain open.


Hardlink stage qualification completed; mixed-program export next (2026-10-25)
----------------------------------------------------------------------------
The maintained install-hardlinks-test.py passed all six real Bazel scenarios at
/usr/obj/usr/src/bazel-hardlink-analysis-r6-20261025/receipt.json: an out-of-order
branched chain stages as the same inode, with literal manifest relationships
preserved; cycle, self-cycle, missing target, symlink target and mode mismatch
are rejected. stage-hardlinks-test.py adds four independent verifier tests,
including same bytes/different inode and a cyclic manifest over matching inodes.
The four configuration/file-group byte-parity verifier tests still pass.

The r3 libc-family Bazel build, smoke tests, runtime identity checks and physical
stage completed. The original independent verifier then rejected valid chained
hardlinks; its failure is retained. After fixing the verifier graph validation,
re-verification passed at bazel-libc-family-stage-r3-20261025/stage-reverification/
receipt.json: 1,902 payloads, 42 directories, 1,153 hardlinks and three symlinks.
Policy and generated-workspace input bindings were checked before verification.
This verifies Make metadata, native output bytes, config/catalogue reference
bytes, inode relationships and selected path coverage. It does not assert
compiled-byte reproducibility, complete package families or installed upgrades.

The stage build recorded 10,638 actions, 80.82 seconds elapsed, 660.40 user,
409.83 system, 2,038,864 KiB peak RSS, 2,334 block inputs and 46,916 block outputs.
Measured trees occupied 2,611,451 KiB (stage run) and 3,369,296 KiB (86-program
frontend run), including copied SDKs and Bazel state. These observations are not
a matched Make performance comparison or aggregate process memory bound.

The next exporter fix follows bsd.progs.mk's effective PROGS inventory, which
already includes PROGS_CXX. configured_programs.py selects each once and supplies
both PROG and PROG_CXX for C++ recursive queries, retaining that selection for
all metadata queries. Four tests pass against maintained Make defaults and
invalid-inventory cases. The new helper and PROG_CXX metadata are hash-bound.
The real libc stdlib export is running at bazel-libc-stdlib-plan-r2-20261025;
no stdlib native build/test claim is made. Changing the exporter means earlier
plans are historical snapshots and need fresh export before reuse. Existing
build-bsd backend integration consumes the fix without new CLI/config options.
Make remains production; world/kernel/package/runtime/performance gates remain.


Native per-source program compilation (2026-10-25)
-------------------------------------------------
The stdlib r2 export completed with 36 compiled programs: 34 ATF tests including
two C++ programs, plus h_getopt and h_getopt_long. SCRIPTS also declares getopt_test;
SUBDIR declares dynthr_mod and libatexit. Neither the shell test nor the child
components may be omitted when qualifying the full suite. Export also exposes
repeated -lprivateatf-c in the C++ link sequence; the native resolver still rejects
repeated libraries until order/repetition semantics are represented explicitly.
Required dependencies include ATF C/C++, libnetbsd, libutil, libm, libthr and
BlocksRuntime. This is inventory evidence, not stdlib build/test completion.

component-plan.py now captures effective contexts for program OBJS as well as
library variants, including configured .pieo suffix recipes. Four ordinary and
four PIE C/C++ contexts matched actual Make dry-run recipes at
bazel-program-make-contexts-20261025 and bazel-program-pie-make-contexts-20261025.
bsd_program.bzl uses cc_common.compile with per-source flags and private textual
inputs. program_compile.py checks exact OBJS membership/order and driver choice.
The existing component emitter links object outputs directly through cc_binary,
reusing them for normal and test binaries, and preserves Make's link-driver flags.
Four object inventory/driver rejection tests pass. This is integrated in the
maintained build-bsd backend without a new frontend switch.

program-objects-test.py takes explicit SDK configuration, Bazel and output inputs.
Its maintained run at bazel-program-objects-maintained-20261025 passes mixed C/C++
flag isolation, constructor-only translation-unit retention, runtime behavior,
link object order and execution-log checks. Cold build: three compiles/one link;
unchanged: zero/zero; one-source flag change: one/one; restoration: one/one.
This primitive fixture uses the explicit SDK and host runtime; it is not another
converted base program or proof of full-system hermeticity.

A fresh bzip2-family regression through build-bsd passed at
bazel-bzip2-program-contexts-20261025/native/receipt.json: both utilities, libbz2
and six sample tests. The fixture decoder was rebuilt with maintained Make;
no receipt hash was rewritten. Bazel reported 118 actions, 5.86 seconds elapsed,
43.28 user, 7.64 system, 866,292 KiB peak RSS, 619 block inputs and 1,702 block
outputs. These observations are not a matched performance comparison. New
installation/package/runtime parity beyond the sample suite is not claimed.
The r3 stdlib export is running with all program contexts; earlier plans precede
this exporter change. Source remains frozen until its terminal result.


The r3 stdlib export completed successfully: all 36 compiled program records
carry one configured PIE source/object context. Inspection confirms free_sized
retains its final -std=c2x, bsearch_b retains -fblocks, and the C++ test retains
-std=gnu++17. This exports actual configuration; native stdlib execution remains
unqualified. bazel-libc-stdlib-dependencies-20261025 now refreshes each declared
transitive library dependency, preserving the prior explicit native libc runtime
selection. Progress is in commands.json and selection.json. Linker-script/runtime
closure, repeated-library semantics, shell/helper fixtures and child directories
remain required before full-suite completion. No native artifact is substituted
with a historical plan or host library to bypass those requirements.


Ordered program linking and stdlib expansion (2026-10-25)
-------------------------------------------------------
library_link_sequence.py resolves plain-library aliases using maintained source
mappings, verifies compound primary archive identity and preserves final LDADD
order/repetition. bsd_link_sequence.bzl supplies an ordered user_link_flags list
and a separate declared input depset to Bazel's native linking context. It does
not deduplicate the argument sequence or manufacture an archive/linker script.
Program object compilation retains CcInfo header dependencies; its binary links
the explicit sequence and requested native runtimes. Ten resolver/runtime tests,
28 existing dependency tests and five explicit-runtime tests pass. Unsupported
link-control groups and compound searched aliases remain explicit errors.

The maintained link-sequence-test.py passed at bazel-link-sequence-runtime-20261025:
actual A/B/A/shared-library argument order, runtime source mutation/restoration,
invalid-index/unused-member/empty-sequence rejection, and exact execution-log
counts. Cold: five compiles, two archives, two links; unchanged: zero; one-source
change and restoration: one compile, one archive, one link each. Loader checks
passed for direct and suite-symlink invocation with no LD_LIBRARY_PATH. Declared
sibling libraries are found by a test-only origin-relative path; installed
programs do not gain that path. The earlier candidate's missing cc_library
implicit archive label was a fixture error, retained; the corrected fixture uses
the declared archive output group.

The bzip2-family maintained frontend regression passed all six sample tests at
bazel-bzip2-link-sequence-20261025/receipt.json. Observations: 117 actions, 13.49s
elapsed, 48.49 user, 8.15 system, 829,060 KiB peak RSS, 367 block inputs and
1,710 block outputs. These overlap configuration exports and are not a matched
performance comparison. The runtime link fixture's cold build recorded 4.00s,
843,156 KiB RSS, 375 block inputs and 1,083 block outputs; it is a primitive test,
not another converted base component or whole-system performance evidence.

All twelve selected stdlib dependency library exports completed. The first
maintained 36-program/12-library build reached native analysis/compilation but
failed libthr's strict archive member inventory: _umtx_op_err.o was an explicit
Make OBJS entry without a declared source. lib/libthr/Makefile now shares its
architecture-selected assembly/C source origin with VARIANT_SOURCE metadata,
retaining the original OBJS position. Independent amd64 Make inventories and
regular/PIC dry-run recipes are unchanged at bazel-libthr-source-declaration-
20261025/receipt.json. An initial recipe comparison used different private object
directories and failed on those paths; a same-directory comparison passed without
normalizing compiler arguments. The original native failure remains at
bazel-libc-stdlib-native-20261025/FAILED.json; no stdlib native success is claimed.

Review also found an absolute sibling-object -L directory in libatf-c++ shared
link flags. Component plans now export actual .OBJDIR. native_link_options.py
translates only dependency-backed artifact/object directories for both programs
and shared libraries, retaining other flags and rejecting ambient/indirect
searches and unmapped source/object inputs. Seven dedicated path tests pass.
The normal build-bsd backend uses this helper and binds it into graph provenance;
no new frontend CLI setting or one-off build replacement is introduced.

Fresh program and dependency plans plus frontend qualification are running under
bazel-libc-stdlib-refresh-r4-20261025. Earlier plan hashes are not rewritten.
Shell/helper runtime fixtures and child shared modules remain required for the
complete stdlib suite. Full world/kernel/package/bootstrap/runtime and matched
performance gates remain open. Make remains production/default; no installation,
publication, upgrade or reboot occurred.


World identity and stdlib fixture audit (2026-10-25)
-------------------------------------------------
The current fixture audit at bazel-stdlib-fixture-audit-20261025/inventory.json
confirms that dynthr_mod and libatexit are shared-only components: LIB is empty
and _LIBS contains only the configured shared module. They must gain a genuine
shared-only object/link path; inventing a regular archive would misrepresent
Make's build. The getopt shell test is generated from the configured
ATF_TESTS_SH_SRC_getopt_test=t_getopt.sh and installed with the maintained ATF
interpreter header. Its two helper programs and both dlopen modules are runtime
requirements, not optional test exclusions. ATF's interpreter exposes existing
ATF_PKGDATADIR, ATF_LIBEXECDIR and ATF_SHELL configuration for explicit tool/data
selection. No test-source rewrite or test-name dispatch table is proposed.

bazel-world-target-identity-audit-20261025/receipt.json records 110 colliding
primary target names across 163 components in the stored 2,101-directory world
metadata inventory, plus 93 shared-only records and 473 script-bearing records.
Those census counts are from the bound earlier inventory, not a fresh world
build. Current maintained Make queries independently confirmed auditd (library
and executable), bsddialog (library and executable), and build_test (ATF C and
C++ test directories). The current flat target namespace cannot represent the
whole system. The roadmap now requires source-component Bazel packages and typed
output kinds before broad expansion. Existing configured names must be retained
inside those packages; dependency labels, runtime artifacts, install manifests
and frontend evidence must carry the source identity end to end. Namespace
collision/invalidation tests are a required gate, not permission to rename
user-facing commands or deduplicate unrelated components.

The active r4 stdlib refresh has exported its 36 programs and both affected
libraries (libthr and ATF C++). Inspection confirms libthr's extra source maps
to the maintained amd64 _umtx_op_err.S for both regular and PIC objects, and
.OBJDIR is the queried /usr/obj path. The libc/dependency refresh and subsequent
frontend build remain running; no new native stdlib pass is claimed. Backend
source remains unchanged during that qualification. Documentation-only roadmap
changes require no build-bsd CLI change; the upcoming namespace implementation
must update its existing backend, verifiers, tests and manual together.

Bazel expansion audit (2026-10-25): the stored world inventory has five repeated
library names across 14 source components. Current resolver contract probes show
that dependency selection loses the source-component identity after resolving it.
The flat graph currently rejects ambiguous target names; no silent mislink is
claimed. Component-based package migration must preserve identity through links,
runtime checks and installation artifacts. Evidence is
`/usr/obj/usr/src/bazel-library-identity-contract-audit-20261025/receipt.json`;
this is metadata/contract evidence, not additional converted build coverage.

Bazel stdlib follow-up (2026-10-25): the selected 36-program/12-library graph
compiled, but its full ATF run remains failed (31 programs passed, three failed;
127 cases passed, one expected failure, two skips, six failures). Two programs
lack shared-only fixture modules. The generic clean runner's missing PWD caused
the remaining two case failures; deriving PWD from the actual working directory
now passes all eight actual clearenv cases in a fresh graph. Evidence:
`/usr/obj/usr/src/bazel-libc-stdlib-refresh-r4-20261025/result-audit.json` and
`/usr/obj/usr/src/bazel-stdlib-clean-environment-20261025/receipt.json`.
Dependency selections now preserve source identity and reject conflicting
same-name aliases; component-package and downstream identity migration remain
unfinished. No security protection, system-wide build, package installation or
complete stdlib pass is inferred from this work.

Bazel source identity propagation (2026-10-25): ordinary/ordered artifact selection
and runtime dependency/GROUP traversal now preserve declared source components.
Distinct-source SONAME collisions are rejected. The 66 focused checks and all
eight actual clearenv cases pass; receipts are under
`/usr/obj/usr/src/bazel-library-component-identity-tests-20261025` and
`/usr/obj/usr/src/bazel-library-component-identity-native-20261025`.
Component-qualified BUILD packages and installation/result paths remain unfinished.
The flat graph still rejects duplicate target names; no whole-world or complete
stdlib qualification is claimed.

Bazel GROUP catalogue follow-up (2026-10-25): catalogue and member lookups now use
source-component identity, and explicit runtime/test consumers retain validated
selections. All 68 focused checks pass. A freshly emitted graph has identical
BUILD rules and test inventory to the previous native clearenv graph; no native
rerun is claimed. Evidence is under
`/usr/obj/usr/src/bazel-group-component-identity-tests-20261025` and
`/usr/obj/usr/src/bazel-group-component-identity-graph-20261025`.
Component-qualified packages and artifact paths remain pending; production Make
and existing publication/installation authorization boundaries remain in effect.

Bazel package-source identity follow-up (2026-10-25): native compile rules and the
maintained emitter now use explicit source metadata mappings, independent of
package paths. Nested-package native tests verify identical target names,
generated sources, private input isolation, archive membership and exact cache
invalidation. The latest receipt is
`/usr/obj/usr/src/bazel-source-identity-nested-r2-20261025/receipt.json`.
The actual clearenv target also passed with emitter-supplied mappings, before a
later indexed-membership optimization. Main emitter package migration and full
system qualification remain incomplete. Fixture log relocation was corrected to
prevent compact-log commands from targeting reference evidence; the rerun verifies
reference log hashes are unchanged. No broader security claim follows.

Bazel result-path follow-up (2026-10-25): ATF verification and frontend runtime
evidence now support normalized nested identities while preserving binary,
library, driver and case-inventory checks. Real Kyua evidence copies passed flat
and nested verification, with 12 corruption/path controls rejected and the source
database unchanged. The maintained frontend also passed its explicit 12-library
build and dynamic libc smoke regression, checking native libc/libsys identities.
Receipts are under `bazel-atf-nested-artifact-audit-20261025` and
`bazel-runtime-evidence-layout-20261025/native` in `/usr/obj/usr/src`.
This is not full stdlib or whole-system qualification; the main BUILD graph is
still flat and installed-system/package/security claims remain unchanged.

Bazel main package migration (2026-10-25): the maintained emitter now uses
source-component BUILD packages and qualified dependency/test/install artifacts.
The bzip2 family passes all six sample tests, 16-payload staging parity and four
pkgbase archives through build-bsd. Evidence:
`/usr/obj/usr/src/bazel-component-packages-stage-r2-20261025/native/receipt.json`.
Stale installation policies were regenerated from current Make metadata and bound
reference stages. No publication or installation occurred. The fresh libc/stdlib
and real auditd collision qualifications remain pending; this does not establish
whole-system, generator-family, or duplicate-name cache qualification. Make is
still the production/default backend.

Bazel collision result (2026-10-25): the actual libauditd and auditd targets now
build together in distinct source-component packages through maintained build-bsd.
Bazel output-group records confirm their separate artifacts and hashes. A separate
postcheck's incorrect nonprivate archive-name assumption was corrected by auditing
declared outputs, without changing the successful frontend receipt. Evidence:
`/usr/obj/usr/src/bazel-component-collision-auditd-20261025/collision-build.json`.
No daemon was started. Runtime/service and duplicate-name cache isolation remain
separate qualification work; libc/stdlib package migration is still being checked.

### Libc package-layout regression — 2026-10-25

The r5 libc/stdlib qualification failed during native compilation: the static
source emitter interpreted an absolute Bazel label as a filesystem path, producing
`-iquote /:sources/lib/libc/iconv` for generated iconvlist.c. Bazel rejected the
include outside its execution root. `static_sources.py` now derives the quoted
include directory from the source origin and workspace snapshot layout, separately
from the label. `static-source-labels-test.py` checks both relative and absolute
labels preserve the correct include path; it passes. Production compiler flags
and sandbox checks were not relaxed.

The maintained build-bsd format-4 rerun is under
`/usr/obj/usr/src/bazel-libc-stdlib-packages-r6-20261025/native`, using the unchanged
verified r5 plans and all 16 CPUs. The first launch lacked the required parent
output directory and stopped before emitting a workspace; the parent was then
created and the command rerun. This run is pending, not passing evidence.
The shared emitter fix needs no frontend CLI or configuration change. Shared-only
stdlib fixtures and shell tests remain open, as do full world/kernel qualification.

### Native suite loader origin — 2026-10-25

The r6 libc/stdlib graph completed native compilation (12,215 total actions),
clearing the static-source include regression. All 34 ATF runners then failed
before test-case execution because the strict loader check found host ATF
libraries. The retained abs_test loader trace shows libprivateatf-c.so.1 resolving
to /usr/lib. FreeBSD resolves the executable symlink to its original component,
so the suite's sibling libraries were outside its effective $ORIGIN directory.
Earlier flat layouts concealed this dependency on physical executable placement.

`bsd_kyua.bzl` now uses a declared Python execution action to copy native ATF
executables into their suite directory, with declared source/runtime inputs and
an executable output. Runtime library symlinks and strict loader identity checks
remain unchanged. Non-native suites retain their existing behavior. The maintained
build-bsd qualification rerun is active under
`/usr/obj/usr/src/bazel-libc-stdlib-packages-r7-20261025/native`; it is not yet
passing evidence. The frontend CLI is unchanged and its manual now describes the
suite staging. No host library is accepted as a substitute for a selected artifact.

Shared-only fixture metadata has also been exported directly from maintained
Make at `bazel-stdlib-shared-module-plans-20261025/components.json`. Both modules
have empty LIB/PROG, explicit SHLIB_NAME and SOBJS; libatexit selects the C++ link
driver and dynthr_mod declares pthread. Native support remains unfinished.

### Libc suite staging qualification result — 2026-10-25

The r7 run completed: 32 ATF programs passed and two failed. All 34 native loader
checks passed and their executable/library digests were independently reconciled
against the emitted artifacts. Case totals are 129 passed, four failed, two skipped
and one expected failure. The four failures are in cxa_atexit_test and dynthr_test,
which require the still-unmodeled shared-only fixture modules. This is not a suite
qualification pass. Evidence: `bazel-libc-stdlib-packages-r7-20261025/result-audit.json`
and retained frontend FAILED.json, events and per-test loader/database outputs.

The declared suite executable copy therefore fixes the namespace migration's
loader-origin defect without accepting host replacements. Shared-only module
support remains next. The existing direct-object rule now has an explicit
position_independent attribute that selects cc_common PIC compilation outputs;
ordinary programs retain the default. `program-objects-test.py --pic` exercises
mixed C/C++ flags, constructor retention, declared object order and runtime/cache
invalidation with that mode. PIC and ordinary regression runs are pending under
`bazel-direct-objects-{pic,ordinary}-20261025`. This is preparation for module
linking, not a claim that the missing fixtures have been converted. The frontend
still uses the maintained component backend; no CLI/default changes are required.

### Shared-only module build support — 2026-10-25

The component exporter now captures PIC-only compile contexts for components
that declare SHLIB_NAME without LIB/PROG. The emitter accepts that configured
identity, uses ordered direct PIC objects, and shares native shared-link,
SONAME, debug extraction and strip actions with ordinary libraries. It does not
create a static archive. The configured SONAME is used explicitly. The new
`shared_modules.py` validates output basenames, exact _LIBS inventory, unique
SOBJS order, exact PIC contexts and source coverage. Six focused validation tests
pass. Actual module build/runtime/installation qualification remains pending.

Fresh plans are exporting under `bazel-libc-stdlib-modules-r8-20261025`; child
components are taken from the selected suite's maintained SUBDIR metadata, and
library dependencies are recursively included. The export driver stops after
creating the input configuration: it does not claim a passing suite or omit the
still-required runtime fixture placement. Exporter changes intentionally
invalidate older plan bindings; hashes are not rewritten.

The maintained build-bsd backend consumes this emitter automatically. No new
frontend switches or default changes are required. Shared-only installation and
pkgbase policy qualification are still required, alongside suite-file placement,
dynamic module dependency checks and shell fixtures.

### Declared shared-module suite placement — 2026-10-25

Configured ATF suites now select shared-only modules whose maintained SHLIBDIR
matches the test program's BINDIR. No test/module filename list is used. Duplicate
module destinations, traversal and invalid suite directories are rejected. Module
library dependencies are resolved through the existing component graph and added
to suite files only when they are not already declared program runtime libraries;
conflicting artifacts fail emission.

The native emitter produces a separate module test variant with $ORIGIN loader
search, leaving the configured installable output unchanged. The Kyua rule stages
explicit suite-file artifacts with declared copy actions, including the module
itself, so FreeBSD's resolved loader origin stays inside the suite. Each target
must provide exactly one artifact, and names may not collide with the program,
Kyuafile or program runtime libraries. Five module-selection tests and twelve
existing program/GROUP runtime tests pass. Native build/suite qualification and
independent verification of dynamically loaded module dependencies are pending;
this is not a module runtime qualification claim.

The r8 metadata export remains active. No frontend option is required: maintained
build-bsd consumes the extended configured-test emitter. Shell fixtures, complete
installation/package parity and world/kernel qualification remain open.

### Shared-module loader receipt checks — 2026-10-25

The native ATF runner now traces each staged module before running the suite,
using its declared runtime-library closure. `elf-runtime-check.py --trace-only`
performs the same strict loader-path/artifact comparison without executing a shared
object. Its receipt explicitly records trace-only mode; execution arguments are
rejected in that mode. Ordinary consumer checks still execute the consumer.

Module inventories are carried in configured runtime checks. The ATF result
auditor verifies module and dependency hashes, driver identity, exact dependency
sets, trace-only mode and receipt uniqueness alongside the existing program/case
checks. Six new receipt tests, six existing ATF-result tests and five suite-selection
tests pass. A real trace-only probe of explicitly selected host libthr/libc/libsys
passes, and a negative probe rejects host libc when the native-built libc artifact
is declared. Evidence: `bazel-module-trace-host-20261025` and
`bazel-module-trace-negative-20261025` under `/usr/obj/usr/src`. These probes qualify
the verifier behavior only, not the pending native modules or their test outcomes.
The r8 export is still active; build-bsd uses the extended runner and verifier
through its existing backend, without new CLI inputs or changed defaults.

### ATF module runner integration probe — 2026-10-25

`suite-module-runtime-test.py` builds a small real ATF consumer, a shared module
using direct PIC objects, and a shared dependency. The test uses dlopen/dlsym to
check a constructor-derived result. It runs cold/unchanged/dependency-mutated/
restored phases, requiring the mutated case to fail, both loader receipts to pass,
only the changed source to recompile, and restored artifacts to match. SDK runtime
libraries are explicit fixture inputs, not newly converted base components.

The first native run exposed a real indirect-dependency issue: the suite's libc
loaded but libsys resolved on the host. ELF RUNPATH does not apply transitively.
The configured test executable/module variants now request --disable-new-dtags
with their suite-relative $ORIGIN path, producing transitive RPATH for the declared
suite closure. Installable outputs retain their configured flags. Strict loader
identity verification remains unchanged. The fresh r2 fixture run is pending at
`bazel-suite-module-runtime-r2-20261025`; the failed first run is retained.
This change is in the backend used by maintained build-bsd, without new CLI inputs.

The module runner's r2 probe confirmed that transitive RPATH fixes the executable
closure, then exposed two additional issues. Copied suite dependencies must be
compared against their staged copies (the result auditor separately checks their
bytes against declared artifacts). Also, FreeBSD ldd's default shared-object mode
uses dlopen(RTLD_TRACE) in the ldd process, inheriting host runtime mappings.
The local usr.bin/ldd/ldd.c implementation selects a fresh rtld -d invocation when
explicit output formats are supplied. Trace-only verification now uses that mode,
with standard object/path/address formatting. It retains exact-path verification
and does not accept host replacements or weaken dependency matching. The fresh r3
native fixture is pending at `bazel-suite-module-runtime-r3-20261025`; the failed
r1/r2 evidence remains available.

### Frontend post-test suite invocation — 2026-10-25

Integration review found that component_qualify's post-test loader check still
invoked the original component executable rather than the declared suite copy.
Configured ATF runtime inventories now record both built binary and suite
invocation. `atf_results.runtime_binary` validates normalized paths and requires
identical bytes before the maintained frontend invokes the suite executable.
Ordinary checks retain their declared original executable. Eight case/path/runtime
invocation tests pass, including rejection of a substituted suite executable and
traversal. Full maintained frontend qualification with modules remains pending
on the active r8 export; standalone runner success is not used as its substitute.

A maintained Make reference for shell-test generation was also produced in an
isolated object directory at `bazel-stdlib-shell-make-reference-20261025`.
Its receipt binds the actual sources, Make includes, effective interpreter/sed
metadata and generated artifacts. It is a generation reference only, not Bazel
shell generation or runtime evidence.

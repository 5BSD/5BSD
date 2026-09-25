# 5BSD platform hardening implementation plan

Status: internal engineering plan. This file is deliberately outside the 5BSD
book and is not installed as end-user documentation. The book must describe
only security properties present in a released image.

## Decision

5BSD needs two useful operating modes, not a cosmetic “rootless” switch:

| Mode | Root authority | Executable policy | Intended result |
|---|---|---|---|
| Compatible | Traditional BSD root plus the configured capability session | Arbitrary local software may execute | Current development and compatibility behavior |
| Protected | Root administers users, networking, mutable data, FreeBSD packages, and ordinary services; root cannot alter the trusted base, core services, enforcement, recovery policy, or the next trusted boot | The 5BSD base must verify; software outside the platform boundary may be unsigned by 5BSD | A macOS-like workstation/server boundary |
| Locked | UID 0 receives no implicit platform authority; operations are capability grants | All executable code must be accepted by platform or application policy | An iOS-style appliance boundary |

The eventual general-purpose default should be Protected. Compatible remains
available as an explicit developer and migration choice. Locked is selected by
an image owner or deployment profile, not by an application.

“Unsigned” in this plan means “not signed by a 5BSD platform key.” The FreeBSD
ports repository may retain its own repository signatures. A locally built
package may also be deliberately unsigned. In Protected mode either can install
below `/usr/local`; neither can replace a base file, become a core service,
install an accepted kernel module, or modify boot policy.

Apple's relevant security properties are that System Integrity Protection
applies independently of administrator privilege and that the system volume is
cryptographically verified. Locked mode adds an iOS-style requirement for
accepted executable code and a recovery/developer transition that the running
system cannot silently authorize. These are design comparisons, not claims of
Apple certification:

- https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web
- https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web
- https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web

## Security invariants

A Protected or Locked image is not complete until a hostile process with UID 0
in the normal boot cannot:

1. change any byte used by a later trusted boot;
2. select an unverified boot environment;
3. load an unaccepted kernel module or unload an enforcement module;
4. stop, replace, signal, debug, or live-reconfigure a core service;
5. release a protected kernel gate by killing its owner;
6. remount or shadow a protected path;
7. write a raw system disk or change protected ZFS properties;
8. disable executable verification, audit, MAC policy, or rollback protection;
9. mint recovery/update authority; or
10. erase the evidence of a denied attempt.

The hardware or hypervisor owner remains outside this boundary. On a VM, the
host controls virtual firmware, disks, snapshots, and enrolled Secure Boot
keys.

## Current substrate

The tree already contains useful pieces:

- mandatory `mac_capability` enforcement and descriptor-backed authority;
- system-operation gates for module load/unload, reboot, swap, selected sysctl,
  kernel environment, accounting, and audit control;
- capprotect shields against signals, ptrace, scheduling changes, core dumps,
  ktrace, and other process operations;
- explicit switchboard management classes for packaged capability units, external
  process shields for the initial core set, and fail-closed live reload of core
  manifests;
- ZFS boot environments and one-boot activation;
- a distinct `/usr/local` dataset on new ZFS installations;
- pkgbase repositories with support for repository signing keys;
- loader veriexec, UEFI trust-anchor integration, MAC veriexec, and a loader
  path that passes a verified manifest into the kernel; and
- separate 5BSD base and FreeBSD ports repository identities.

## Confirmed gaps

The current system is Compatible, not Protected:

- both GENERIC kernels (amd64 and arm64) contain MAC veriexec, but enforcement has no generated
  signed base manifest and the build defaults leave loader veriexec and EFI
  Secure Boot integration disabled;
- a system gate becomes ambiently available again when its last claim
  disappears, so killing the claiming authority is fail-open;
- system gates do not cover mount/update/unmount, raw-device write, ZFS
  administration, boot-environment selection, or veriexec control;
- there is no signed per-generation filesystem manifest produced by release
  tooling;
- no boot-time verifier binds a ZFS root generation, its dataset layout, and
  its anti-rollback version to the verified kernel;
- no core updater owns staging and one-boot activation; and
- a locally produced pkgbase repository is unsigned unless
  `PKG_REPO_SIGNING_KEY` is explicitly supplied.

These gaps must remain visible in qualification. Enabling securelevel alone or
setting ZFS `readonly=on` does not close them.

## Filesystem and package boundary

Protected installations use this logical layout:

```
zroot/ROOT/5bsd-<generation>  /                 verified base generation
zroot/etc                    /etc              mutable host configuration
zroot/var                    /var              mutable system state
zroot/home                   /home             user data
zroot/tmp                    /tmp              temporary data
zroot/local                  /usr/local        third-party software
zroot/capdata                /Capabilities/Data capability-owned persistent data
zroot/policy                 protected policy  update/recovery writable only
```

The seal covers the loader-facing boot artifacts, kernel, modules, base
executables and libraries, `/Capabilities/System`, core manifests, default
configuration, trust anchors, and the verification policy. Mutable datasets
must not be able to shadow a sealed path.

`/usr/local` is executable in Protected mode and is outside the 5BSD seal.
It should default to `setuid=off`. Software there can use the normal BSD
userspace and request capability services, but it cannot publish a core unit or
receive a system gate merely because its process has UID 0.

Locked mode sets executable data datasets to `exec=off`. Accepted
applications live in a separately verified application generation. Developer
mode may permit unsigned execution, but it is a distinct measured boot state
with a persistent warning and no Locked attestation.

`/etc` may remain mutable for BSD compatibility, but no file there can be the
sole authority for weakening the Protected boundary. Security-critical policy
belongs to the protected policy dataset. Mutable configuration is parsed by
the owning core service and cannot grant an authority that service does not
already hold.

## Verified boot and execution

The implementation uses one signed generation identity from firmware to
userspace:

1. UEFI Secure Boot verifies the EFI loader.
2. Loader veriexec verifies the kernel, modules, and the signed generation
   manifest against an enrolled trust anchor.
3. The kernel accepts the manifest identity and root dataset identity from the
   verified loader path, not from a mutable environment file.
4. Static MAC veriexec consumes the manifest before ordinary userspace starts
   and locks its database.
5. The root dataset and every protected mount are bound to the manifest.
6. Core service readiness confirms the same generation identity.

The existing global MAC veriexec enforcement cannot be enabled unchanged for
Protected mode: it rejects unlisted executables and rtld libraries on
`/usr/local` too. Add a protected-mount policy:

- a mismatched or unlisted executable/library on a registered protected mount
  is denied;
- an executable on an unregistered third-party mount is permitted in Protected
  mode;
- kernel modules always require an accepted fingerprint;
- mount and ZFS gates prevent an unregistered filesystem from shadowing a
  protected path; and
- Locked mode retains global enforcement.

This policy needs direct tests for binaries, interpreters, shared libraries,
hard links, nullfs and other stacking filesystems, mount shadows, file
descriptors opened before enforcement, and mappings that become executable.

## Root and capability policy

Protected root receives ordinary administration capabilities: account
management, network configuration, package management below `/usr/local`,
mutable storage, diagnostics, and lifecycle control for `management =
"system"` units.

Protected root does not receive:

- system-generation mutation or seal authority;
- core-service lifecycle or manifest replacement authority;
- kernel extension load/unload authority;
- protected mount, raw-disk, ZFS-property, or boot-selection authority;
- veriexec or MAC-policy control;
- audit destruction authority; or
- recovery key enrollment and rollback-floor authority.

One small sealed updater may receive the generation-staging and candidate-boot
capabilities. Recovery receives the stronger policy/key authority, and is not
available in a normal boot. “Root requested this update” is never evidence that
the bytes are trusted.

Locked mode also removes root and wheel from SYSTEM discovery. Applications
receive only their named services and per-application storage. UID 0 remains a
POSIX compatibility value, not a source of platform authority.

## System gate changes

Add a boot-latched policy to `mac_capability_system`:

- Compatible keeps today's default-open behavior.
- Protected and Locked start with the required gates claimed by the kernel.
  A provider exit revokes its token but never releases the boot claim.
- Only a verified boot policy can choose the mode. A runtime sysctl may report
  it but cannot lower it.

Add gates for:

- mount, remount, unmount, and mount-point shadowing;
- ZFS create/clone/snapshot/property/destroy operations on protected roots;
- raw writes to system disks and pool-label boot metadata;
- boot environment activation and UEFI boot-variable mutation;
- veriexec database/control and security-policy mutation;
- process memory access to core programs; and
- security-sensitive clock and audit-log operations not already covered.

Gate checks must occur in the kernel operation itself. Hiding `/dev/zfs` or a
command pathname is not an authorization boundary.

## Core services

The initial core set is:

- capsule/Capsule and switchboard;
- bsdauth;
- bsdfilesystem;
- bsdextension;
- bsdsysctl;
- bsdaudit; and
- bsdlog.

Every packaged unit must explicitly say `management = "core"|"system"|"user"`.
Core units receive launcher-applied external protection. Runtime reload must
reject removal or any manifest/program/protection change for a running core
unit. A core update occurs only by booting a newly verified generation.

Network, device, crypto, notification, trace, Bluetooth, VM, and namespace
providers begin as `system` unless a later threat analysis proves they are
required to maintain the platform boundary.

## Sealed update transaction

Implement a core `system.Update` provider. Its transaction is:

1. Fetch signed channel metadata over an untrusted transport.
2. Reject wrong product, ABI, architecture, channel, key generation, and
   rollback generation.
3. Create or clone an inactive boot environment.
4. Install 5BSD pkgbase packages only into that inactive generation.
5. Run migrations in a constrained staging environment with no user-data or
   active-root authority.
6. Normalize metadata and compute the canonical filesystem manifest.
7. Match it to the release-signed generation identity.
8. snapshot and mark the candidate read-only;
9. arm it for one boot, preserving the known-good generation;
10. boot-verify it and require a nonce-bound core health acknowledgement;
11. promote it only after success; otherwise roll back automatically; and
12. retain failure evidence and at least one known-good generation.

The private release-signing key never exists on an installed system. Update and
recovery authority can select only artifacts accepted by enrolled public keys.
FreeBSD ports packages and local packages on `/usr/local` are not copied into
or blessed as part of the base generation.

### State and boot-artifact versioning

The base package database is generation-owned.  The FreeBSD/local package
database and its package scripts are mutable state, and cannot authorize or
describe the sealed base.  Rolling back the base must therefore never roll
back, merge, or silently reinterpret the local package database.

Shared state needs an explicit compatibility contract:

- base services must tolerate the previous and next supported `/var` schema,
  or keep generation-specific state and promote it with the candidate;
- security-relevant configuration and migrations are generation-owned;
- mutable `/etc` changes cannot select trust anchors, weaken verification, add
  core code, or cause a core process to load an unverified plug-in;
- rollback must account for a newer `/usr/local` package set running on the
  older base ABI; and
- pool feature activation is deferred until every retained recovery and
  rollback generation can import the pool.

The EFI System Partition is outside a ZFS boot environment.  Loader, trust
database, and boot-policy updates therefore need two signed slots (or an
equivalent atomic signed artifact), a one-boot selector, and recovery fallback.
The updater must not overwrite the only bootable loader in place.

### Adversarial and fault-injection matrix

Qualification covers more than a successful update and reboot:

- power loss before and after every durable transaction boundary;
- a full pool, quota exhaustion, degraded or faulted vdev, and failed snapshot;
- stale, replayed, revoked, wrong-product, wrong-architecture, and mixed-channel
  metadata, including systems whose trusted clock is wrong;
- key rotation with old-key removal, threshold-key loss, and recovery-key
  enrollment without giving normal root signing authority;
- one modified protected byte, two individually valid generations mixed
  together, and a valid generation paired with the wrong root dataset;
- symlink, hard-link, nullfs/union/FUSE, mount-namespace, jail, devfs, and raw
  device attempts to shadow or mutate a protected object;
- executable mappings and file descriptors opened before enforcement, scripts
  using a sealed interpreter, JIT mappings, `LD_PRELOAD`, library search paths,
  NSS/PAM modules, and plug-ins loaded by privileged or core processes;
- unsigned kernel modules, firmware, microcode, and device-option ROM inputs;
- package pre/post-install scripts attacking protected paths or core-service
  inputs while installing otherwise permitted `/usr/local` software;
- core-service crash or timeout during candidate health confirmation, forged
  health acknowledgements, repeated boot loops, and candidate quarantine;
- irreversible `/etc` or `/var` migrations, base/local package-database skew,
  and a newer local package set after base rollback;
- ZFS send/receive and clone origins, encryption-key availability, pool-feature
  upgrades, boot-environment garbage collection, and loss of the last known-good
  generation; and
- audit-log deletion, log exhaustion, crash-dump/swap disclosure, and recovery
  actions that accidentally bless the compromised active system.

Release tests must distinguish the software boundary from the platform owner:
a physical attacker with firmware keys, or a VM host that can replace disks and
firmware, remains able to control the machine unless a separate hardware trust
and attestation model is deployed.

## Work that can land now

These changes improve the current system without claiming Protected mode:

1. Make the arm64 GENERIC match amd64 for static mandatory policy selection.
2. Compile MAC veriexec and SHA-256 support into GENERIC, while leaving enforcement
   disabled until manifests exist.
3. Explicitly classify every packaged unit; shield the initial core set.
4. Refuse live core-manifest changes.
5. Create a separate `/usr/local` ZFS dataset on new installations.
6. Add release checks that a “Protected” artifact cannot be built without a
   repository signing key, loader verification, EFI Secure Boot integration,
   a generation manifest, and a root-adversary test result.
7. Keep the installer profile labeled Compatible until all Protected release
   gates pass.

## Delivery order and acceptance gates

### P0: honest baseline

Land unit classification, core reload refusal, process shields, ARM64 policy
parity, the third-party dataset, and machine-readable gap tests.

Gate: a source/installed-package test proves every unit is explicit; a root VM
cannot stop, signal, or live-replace a core unit through supported paths.

### P1: boot-latched runtime boundary

Implement persistent system gates and the missing mount, storage, boot, and
verification hooks. Put protected policy outside root-writable configuration.

Gate: killing capsule, switchboard, bsdfilesystem, bsdextension, or the updater never grants
ambient access. UID 0 receives `EPERM` at every protected kernel operation.

### P2: signed generations

Enable loader/Secure Boot integration, generate and sign canonical manifests,
add protected-mount veriexec policy, and bind the root dataset to the manifest.

Gate: modifying one protected byte, mixing two valid generations, shadowing a
mount, or selecting an unsigned BE prevents trusted boot. Unsigned
`/usr/local` software still runs in Protected mode.

### P3: atomic updater and recovery

Implement staging, boot-once, health confirmation, automatic rollback,
anti-rollback floors, owner-controlled recovery, and explicit developer mode.

Gate: injected power loss at every transaction boundary leaves a verified old
or new generation bootable. Normal root cannot bless arbitrary bytes.

### P4: Locked application policy

Add signed application generations, per-app capability policy, executable-data
denial, JIT authority, revocation, and locked-device recovery rules.

Gate: unsigned code cannot execute outside explicit developer mode, and a
compromised UID-0 app cannot modify the platform or another app.

## Release claims

No image is called Protected or Locked based on configuration alone. The release
pipeline must attach exact-image VM evidence for boot verification, root
adversary denials, update interruption, rollback, core health, logs, and
recovery. 5BSD may compare its authority model with macOS, iOS, QNX, or seL4,
but must not claim their certification or formal assurance.

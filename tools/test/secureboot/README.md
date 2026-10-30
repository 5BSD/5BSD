# Secure Boot qualification harness: cleanup in progress

BIP has been dropped. The former BIP runtime enforcement, Capsule storage
classification and broker grant mechanisms have been removed. This legacy
harness still contains dependent fixture and runner paths awaiting removal;
it is not a currently qualified end-to-end Secure Boot workflow.
The independent firmware-only case is maintained and qualified as described
in the final dated section; it does not run the legacy combined harness.

The remaining historical sections below are not evidence for the current tree.
Independent firmware, loader, veriexec and ordinary filesystem checks must be
qualified separately against the retained implementation. Removing obsolete
BIP tests is retirement of coverage, not a passing test result.

## Native NFS handle checks

The lock-manager case also compiles actual NLM admission and cleanup: mandatory
denials cannot fall through to legacy VWRITE permission fallback, ordinary
access keeps that fallback, and cancellation/unlock cleanup remains possible.
Credential, vnode and mount releases are checked for these paths. This does not
qualify daemon admission, export updates or an operating NFS service.

`make -C /usr/src/tools/test/secureboot nfs-handle-test` compiles the current
server handle-issuance and handle-resolution functions with MAC/VOP/export
seams. It checks denial before handle issuance and denial preservation across
NFSv4 export fallback, including address-less requests, with and without MAC.
It also compiles the full pathname-resolution function to check mandatory
admission before public-lookup symlink reads and reference/buffer cleanup on
rejection. The create/truncate function is also exercised for parent/target
admission before mutation, including missing leaves and parent/leaf aliases.
The separate NFSv4 open path is tested for create and no-create admission,
cleanup and protocol error precedence without passing a denied vnode to state
lookup. Directory, symlink and special-file creation functions are checked for
parent admission before mutation and cleanup on denial. Successful filesystem
creation, pNFS, other mutation operations and complete directory traversal remain
outside this native test's coverage. File/directory removal checks cover parent
and target denial before mutation, delegation recall or pNFS setup, plus cleanup;
they do not demonstrate successful runtime removal. Hardlink tests check locked
source/parent admission and caller reference retention. Rename tests check source
admission before destination lookup and locked destination admission before
replacement. These use filesystem/protocol seams, not a mounted NFS service.
Traversal checks cover NFS selecting the internal handle-traversal flag and
selected/unselected degenerate lookups, including mandatory denial despite
NOMACCHECK. Empty-path rejection also checks release of the consumed start-vnode
reference for policy, type and operation errors. Full component walks,
dot-dot across mounts and concurrent mount
changes are not established by this native coverage.
It does not start NFS, change exports, or qualify mounted storage. Ordinary NFS
administration remains unqualified while the broad BIP daemon/mount gates remain.

## Run through the system build tool

Use a matching development world/kernel staged by the maintained build tools
under `/usr/obj`. The kernel in that root must match the selected kernel object.
Do not use a published repository as a writable test stage.

```sh
build-bsd secureboot-test \
    --root /usr/obj/usr/src/security-qualification/root \
    --kernel GENERIC-NODEBUG \
    --uefi-vars-tool /usr/obj/usr/src/security-qualification/python-env/bin/virt-fw-vars \
    --output /usr/obj/usr/src/security-qualification/secureboot-run
```

The output must not exist. `plan secureboot-test` prints commands without
creating keys or images. The command cleans and rebuilds the EFI loader and
its dependencies in a private object subtree below its build-run directory,
using all logical CPUs. Firmware-verification options never change shared
world/BIOS loader objects. The runner receives the selected loader explicitly
and records its hash. The command rebuilds Capsule/SwitchBoard and the
native provider fixtures through `make buildenv` against the world sysroot,
builds a native host signer with the maintained helper, and tests the actual
loader parser objects, and boots the complete VM matrix. Compilation changes
objects under `/usr/obj`; it does not install or boot the host. Do not overlap
manual builds of the same objects with this command.

Prerequisites: native amd64, Python 3.12, QEMU/OVMF supporting Secure Boot and
SMM, `uefisign`, OpenSSL, `makefs`, `mkimg`, and `virt-fw-vars`. The tested firmware
is QEMU's `edk2-x86_64-secure-code.fd` with `edk2-i386-vars.fd`, and the tested
variable-store tool is `virt-firmware==26.10`. The frontend does not install host
dependencies. A private Python virtual environment under the qualification
object directory can hold the variable-store tool.

Private PK, KEK, database and negative-test keys are newly generated for each
run, expire after seven days, and remain in a mode-0700 directory on the host.
Only certificates and signatures enter disk or variable-store images. These
credentials must never become production trust anchors. Production signing
keys and recovery authority must be outside the target root's control.

## BIP bootstrap profile

Build `GENERIC-INTEGRITY` through `build-bsd kernel --kernel GENERIC-INTEGRITY`,
then stage that matching kernel into the disposable qualification root. Pass
`--kernel GENERIC-INTEGRITY` to `secureboot-test`. This experimental profile
requires immutable md0 root and enforcing firmware, denies raw-device opens,
mount changes, sysctl writes and interference with PID 1 from a root child,
and blocks kernel-memory and runtime-module privileges. Public devices and an
explicitly inherited EFI descriptor remain usable. It is not a production
world or persistent-system-generation profile.

The runner reads the actual embedded kernel configuration. With this policy it
requires `SYSTEM_INTEGRITY_PASS` in the static PID 1 fixtures and adds three
boot-policy cases:
an authenticated but mutable preload must panic before PID 1; offline removal
of the VM's PK must leave the kernel refusing non-enforcing firmware; and a
signed alternate-root setting must still boot the fixed immutable root.
Only the two specific rejection diagnostics count as kernel rejection. A
timeout, unrelated panic, missing device, or missing policy is not success.

The protected profile also requires exactly one complete `PROTECTED_SIGIO_PASS`
result. Its guest regression uses socket asynchronous notification against direct
and process-group targets, with an ordinary exec child as a delivery control for
each protected exec child. Protected registration must fail with EPERM or delivery
must be suppressed; an ordinary target must actually receive SIGIO. Each target
also triggers and consumes its own SIGIO before the outside attempt, so a fix
that disables protected-process asynchronous I/O cannot pass. All four cases
also run with a separate registering process that exits and is reaped before
data is sent through the inherited shared socket. Ordinary delivery must survive
origin exit; protected delivery must remain denied. The exact success marker
includes live and exited origins, so earlier four-case evidence is insufficient.
The extended eight-case fixture still awaits VM execution.

The protected profile also requires `PROTECTED_SPAWN_PASS`. The fixture attacks
a `PD_PROTECTED` child before allowing initialization, repeats attacks after
exec from another root process, checks inherited protection and `PT_TRACE_ME`,
and verifies that the creator can still terminate it through its original
process descriptor. A normal child must produce a core dump in writable scratch
storage; a protected child must not. This exercises the kernel primitive used
by Capsule's protected handoff, not the complete service-manager runtime.

## Protected runtime loader policy

The maintained bootstrap build also builds the actual runtime linker.
Both the baseline probe and Capsule/native-service assembly use that rebuilt
linker. Private staging replaces existing read-only regular entries rather
than reopening their inodes, and rejects symlink parents, symlink leaves and
non-file destinations. The bootstrap step runs adversarial assembler checks. With a
BIP kernel, the baseline image contains a dynamically linked setuid probe and
its ELF dependency closure from the supplied world, plus that rebuilt linker.
The probe is root-owned only inside the disposable image; nothing is installed
setuid on the host. PID 1 drops a child to UID/GID 65534 before exec. Successful
entry requires real UID 65534, effective UID 0 and `issetugid()`.

The fixture accepts authenticated-root libmap policy and rejects root-owned
mode-0444 replacements on writable and unrelated read-only tmpfs mounts. It
checks the main file, included file and include directory separately, restores
and rechecks the approved root after each mount, and rejects a FIFO without
blocking. Protected exec also receives an invalid `LD_PRELOAD`, which must be
ignored. Negative cases require the actual loader's provenance diagnostic and
exit status 1; signals and timeouts are failures. The probe uses `dlinfo` to
require the fixture-only directory from the hints file, so successful exec alone cannot hide a missing or ignored hints input.
Identical hints bytes on writable and foreign read-only mounts are rejected,
as is a FIFO replacement. Hints bytes are explicitly encoded from elf-hints.h
for this mechanism fixture; production generation continues to use the actual
ldconfig constructor. The runner requires all thirty-three named check markers
exactly once, the final marker and clean guest shutdown.

A separately built shared test library is loaded and its function executed
through hints-based name lookup, an absolute pathname and `fdlopen`. Identical
bytes substituted on writable and foreign read-only mounts must be rejected
through all three routes, as must a FIFO. Restoring the authenticated root must
restore successful loading. This checks the actual common object-load path,
including caller-supplied descriptors; a signature alone grants no foreign
storage exception. An identical non-setuid probe must have real/effective UID
65534 with `issetugid()` clear and successfully load and execute the same
library from the root, writable and foreign read-only storage through all three
APIs. This control checks the intended ordinary-loading behavior alongside
protected rejection; it does not qualify all ordinary application behavior.

Protected BIP execution selects `/boot/ld-elf.so.hints` and optional
`/boot/libmap.conf`; the fixture also requires successful protected execution
with a FIFO at ordinary `/etc/libmap.conf`. Ordinary execution
retains `/var/run/ld-elf.so.hints`. A FIFO at the ordinary-cache path must not
block or redirect the protected probe, even with LD_ELF_HINTS_PATH pointing
there. The constructor's shipped explicit `library-policy.json` produces the
protected file from verified package-declared directories using strict ldconfig.
The fixture's encoded hints are only mechanism inputs, not production output.

This qualifies libmap, hints and these object-loading routes for
credential-tainted exec in the authenticated-root profile. Authority-only
taint, broader ordinary-exec behavior, service-generation mount attestation and
complete installed-service compatibility remain separate gates.

## System-operation authority

The protected static fixture requires `SYSTEM_GATE_PASS`. Only the original
PID 1 may create a system claim or mint/release tokens; a forked root child
cannot obtain owner authority through its inherited nonce or owner descriptor.
The test checks denial before any clock claim exists, after fork and after exec.
It also checks all four raw clock-write entry points, explicit token use for a
zero clock adjustment, and loss of authorization after the final token closes.
The original PID 1 separately verifies that a module claim cannot override BIP's
runtime module prohibition. Accepted Capsule cases require the same root denial
checks from the actual manager's rc child (`SYSTEM_GATE_DENY_PASS`). When
Capsule has already isolated the dispatcher device, that child records
`SYSTEM_GATE_ACCESS_DENIED`; it still checks all raw clock-write denials.
The static fixture requires dispatcher access and exercises the actual claim,
mint and release operations, so an outer denial cannot mask those checks.

The Capsule rc child also verifies that raw poweroff is denied. It reports
completion and stays alive; the host stops QEMU only after all guest checks and
authenticated manager READY have been observed. Reports distinguish this cleanup
from timeout and policy rejection. It does not qualify an authorized guest
shutdown. Static PID 1 cases continue to require firmware-confirmed shutdown.

These probes exercise kernel authority. Provider policy, normal NTP operation,
and independent user authorization require their own acceptance evidence.

## Evidence

`result.json` identifies the input binaries and firmware by SHA256, lists the
QEMU command for each case, and records results. `RUNNING`, a missing report,
a process failure, or a partial `--case` run is not complete qualification.
The build frontend requires all cases; the runner's `--case` option is for
diagnosis. Each guest has its own variable-store copy, private disk writes,
read-only firmware code, SMM protection, and no network interface. The boot disk
uses a QEMU snapshot; the storage case writes only its private disk copy.

The static positive fixtures require actual guest `SecureBoot=1`, `SetupMode=0`, denied root
mutations, eight root-image checks, the authority-bearing execution-family
debug checks, an EFI shutdown request, and clean QEMU exit. Negative cases require
an explicit rejection at the tested boundary. Firmware, loader and mutable-root
rejections must precede PID 1. The signed-bundle rejection described below
occurs in the real manager after PID 1 starts and must precede rc and READY.
A timeout is never rejection evidence. Retain serial,
firmware, build and result logs when investigating a failure.

The matrix covers approved boot, unsigned/altered/untrusted/revoked EFI images,
missing/altered/untrusted manifests, kernel and module tampering, omitted kernel
hashes, modified configuration, ignored unsigned overrides and ESP settings, `no_hash`,
compatibility verification-disable directives, untrusted firmware load options,
secondary trusted certificates and secondary certificate/hash revocations.
An unlisted hard-link alias must not inherit an inode's prior verification.
It also removes required policy, defaults, configuration and modules; supplies
invalid and returning signed policies; and injects console commands. The signed
startup policy must boot successfully or fail explicitly without a shell.
`build-bsd` supplies the maintained `stand/lua/secureboot.lua` policy explicitly.
Guest root attempts replacement and deletion of trust variables, removal of
authenticated-write attributes, and changes to SecureBoot and SetupMode.

`efi_database_test` links the production loader's parser objects with a mock
firmware transport and native allocation adapters. It checks list lengths,
entry sizes, multiple entries, absent variables, read failures, and bounded DER
framing. It does not substitute a second parser for the code under test.

## Remaining boundary

Most cases use a small static PID 1 fixture in a 16 MiB UFS image loaded as
`md_image_ro`. The signed manifest hashes the complete image, including
filesystem metadata. Tampering, an omitted hash, or a missing image must stop
boot before PID 1. The boot disk itself contains no copy of the fixture.
Guest root verifies the read-only mount, denied file/metadata/raw writes, and
denied forced detach and resize.

The authenticated PID 1 registers its own image for software attribution and
launches a root process which forks and execs that same image. Cross-execution
`PT_ATTACH` and `PT_TRACE_ME` must fail, while an unchanged fork family may debug
its child. This requires the current kernel; an older kernel intentionally fails.

The memory-disk boundary does not block privileged kernel-memory access,
namespace replacement or process injection. Those require mandatory MAC policy
before this can claim protection against compromised root. The image is a useful
initial bootstrap/recovery root; loading an entire production system into RAM is
not a requirement or an established deployment design. Authenticated persistent
generations and rollback state remain separate implementation gates.

The VM host controls keys, firmware and snapshots and is trusted. QEMU can
exercise enforcement against guest root; it cannot demonstrate resistance to a
host administrator or physical firmware attacks.

## Actual Capsule bootstrap

With `MAC_SYSTEM_INTEGRITY`, the matrix also includes `capsule-bootstrap`.
The kernel directly executes `/sbin/capsule` as PID 1; Capsule launches the real
SwitchBoard with `PD_PROTECTED`. The 32 MiB image contains both dynamic binaries,
the staged runtime linker, recursively resolved ELF dependencies, installed
account records, an empty bundle catalogue, and a bounded `/etc/rc` probe.
No staged binary runs on the host, and dependencies never resolve against host
libraries. The report hashes all copied input files.

The root probe verifies PID 1 and its manager parent, attempts ptrace, signals,
scheduling changes and PID-based procdesc acquisition, and checks that the
binaries, runtime linker, libc and Capsule configuration cannot be overwritten.
It verifies that delegated console output works while a new console open is
denied. Protected rc has `/dev/null` input. The output descriptor permits only
write and stat; root reads, terminal ioctls, flag changes and rights widening
must fail, including after descriptor duplication. This requires
`CONSOLE_OUTPUT_ONLY_PASS`. Shared diagnostic output is not a trusted login
display, and protected interactive maintenance still needs a separate path.
The probe allows the rc oneshot to finish; the runner separately requires
Capsule's authenticated READY receipt and a normal EFI shutdown. An empty
catalogue and a test rc script do not qualify a complete installed world,
protected native providers, other writable data mounts, login or recovery.

The mandatory sysctl policy permits the exact `sysctl.name2oid` query node,
whose input buffer is query text rather than a mutation. The ordinary integrity
fixture checks named/numeric reads and denial of both named/numeric writes.
No blanket `CTLFLAG_ANYBODY` exemption is used.

The current firmware path uses direct enrollment of disposable test keys, not
Microsoft-signed shim. This establishes no factory-key PC compatibility.

## Protected runtime storage

Capsule now prepares `/Capabilities/Run` as a 64 MiB `nosuid,noexec` tmpfs,
claims its root vnode using the existing isolation service, and retains that
claim independently of the service-manager lifecycle. SwitchBoard receives a
scoped grant and locks it against inheritance and transfer before authorizing
its current kernel nonce. The actual-daemon probe checks root namespace attacks
and absence of the grant in the rc child; the runner requires successful runtime
storage preparation with no reclaim-directory errors.

The `storage-anchor` case also requires a real named ZFS mount lifecycle:
bootstrap reserves the selected dataset and mounts it at an immutable fixture
slot; a root child cannot read, cover, remount or force-unmount it. Anonymous
mounting of the same dataset must return EBUSY. Bootstrap cleanup precedes the
existing anonymous grant tests. `bip-named-mount-v1` passes (115 files verified).
This is mechanism evidence, not production legacy-path policy or service access.

The named-mount fixture now uses Capsule's internal `protected_storage_attach`.
`bip-attach-v2` passes identity mismatch, missing mount right and nonbootstrap
rejection, then the complete storage tests (115 files verified). An earlier
attempt failed strict flag validation; explicit ZFS noexec/nosetuid options
were required in addition to generic nmount flags. No configuration-driven
production attachment or consumer authorization is implied.

`bip-named-access-v1` further checks a token-bearing process before and after an
invocation-bound grant on the named mount. Reads/writes succeed with the grant;
forked access is denied; closing the grant denies fresh opens and retained-file
I/O. The complete storage-anchor case passes with 115 files verified. This
qualifies the grant mechanism, not production service launch policy.

`bip-slot-v1` exercises Capsule's internal destination validator before the
named mount. It accepts the empty immutable slot and rejects root/noncanonical
paths, nonempty directories, `/dev`, an already-mounted slot and an ordinary
root child. The runner requires its result marker; the full storage-anchor case
passes with 115 files verified. Production attachment-policy wiring remains open.

`bip-slot-ancestors-v1` adds authenticated fixture symlinks and unsafe ancestor
metadata. Ordinary lookup through the symlink succeeds, but the destination
validator rejects symlink leaves/ancestors, writable ancestors and foreign-owned
ancestors; a safe nested slot succeeds. The full storage case and 115 files
verify. These fixture paths do not define production protection policy.

`capsule-rc-authority-missing` removes the rc authority policy from an otherwise
authenticated bootstrap image. It requires the real supervisor's protected
launch refusal and rc launch failure, and rejects rc probe completion or an
interactive recovery shell. The basic positive fixture copies the boot policy
from the supplied system root; it does not manufacture a permissive policy.
Native/provider cases retain their explicit fixture policy inputs.
`bip-rc-admission-v2` passed this negative case and the `capsule-bootstrap`
control, with two cases and 142 files verified. These are bounded boot probes,
not normal installed-system or shutdown acceptance.

`capsule-run-nonempty` and `capsule-run-owner` authenticate invalid runtime
mountpoints and require the specific preparation failure. All runtime-layout
rejection cases also require Capsule's explicit denial of legacy single-user
recovery, with no manager/rc launch or shell prompt. The valid bootstrap case
remains the positive control. Under BIP, ordinary single-user recovery is denied
before forking a shell; the existing fatal path requests a reboot. These tests
stop after the explicit refusal and do not qualify the subsequent reboot or an
owner-authorized recovery generation.

`capsule-isolation-off` signs a boot configuration requesting permissive
isolation. The mandatory profile ignores that compatibility tunable, and all
runtime storage checks must still pass. Both cases use an empty native catalogue.
The full installed catalogue and restart/load behavior require further qualification;
the populated fixture below covers two production providers.

The ordinary mandatory-policy probe uses a valid file handle obtained and
validated by PID 1 to verify that root children cannot bypass traversal through
file-handle APIs. NFS server administration is also denied. Normal path-based
reads are checked separately. No global root exception is used.

The protected PID 1 cannot re-exec after its initial image is installed, and
`RB_REROOT` is denied. Both are exercised by the real kernel fixture to ensure
runtime claim descriptors survive until shutdown. Ordinary child exec and EFI
poweroff must still work. Capsule rejects protected-mode reroot requests before
starting teardown; production lifecycle RPC qualification remains separate.

### Populated service fixture

`capsule-native` adds the production BSDAudit, BSDNotify and BSDCrypto bundles, built in the
same world environment as Capsule and SwitchBoard. It uses install-format ELF
images and the maintained `sign-stage.sh` and `verify-stage.sh` helpers. The
native host signer is built through `host-tools.mk`; target executables are never
run on the host for signing. A separate disposable Ed25519 code key stays outside
the image; only its public key and the signature-enforcement marker are installed.
Direct runner calls selecting this case require `--capsign PATH` to that host tool
and `--pwd-mkdb PATH` to the explicitly built native host account generator.
`build-bsd secureboot-test` prepares and supplies both automatically. The assembler
records the generator hash and never resolves it through the host PATH.

The bounded rc client receives the fixture's Notify and session activation
endpoints and a management software attribute, but no authenticated session
or administrative rights. It checks a real subscribe/publish/receive round trip, denial of protected
topic operations and denial of the gated endpoint despite running as UID 0.
Success also requires all existing Capsule root-attack checks, authenticated
READY, and normal EFI shutdown. This exercises boot software authority; it does
not qualify independent user authentication, production audit persistence,
manager restart, or the full installed service set.

The supplied root's `boot/capsule.conf` must explicitly select the Crypto unit
through `crypto_recipient`; the assembler copies that input and does not invent
a production grant. The fixture's separate `policy/boot-authority.ucl` explicitly
allows its rc client to discover `system.Crypto`. UID zero is not a substitute
for either grant. The client obtains an ephemeral Ed25519 descriptor from the
real provider, signs and verifies a message, and requires rejection of a corrupt
signature and a control-derivation request on the key descriptor. It also requires
root's direct `/dev/crypto` open to fail. Exactly one `CRYPTO_BOOTSTRAP_PASS`
completion line is required. These checks do not qualify enrollment of a code
signing key, provider restart/revocation or the normal installed system.

The fixture inventory preserves file modes, including mode 0600 account databases,
instead of assigning executable/readable-by-all permissions to every file.

`capsule-native-tampered` flips a byte in the signed Notify executable after
bundle sealing, then authenticates the resulting root image through the normal
boot manifest. It must reach the real manager's explicit invalid-signature
rejection and abort catalogue initialization before rc or READY. A timeout alone
never passes this case. This separates runtime code eligibility from boot-image
provenance.

The positive native case also inspects the running Notify broker and router:
both must run as the staged service account in capability mode, ambient root
ptrace/signal attempts must fail, and exactly the broker must have OOM exclusion.
SwitchBoard applies that setting within its trusted child launcher before
credential drop and capmode, rather than using ambient PID-based scheduling
against a protected child. No kernel exception was added for the manager.

## Invocation-bound control channels

The ordinary kernel fixture requires `INVOCATION_PASS` after testing
`CAP_AUTH_BIND_INVOCATION`. The issuer binds a fresh channel to the software
authority plus the kernel-stamped process identity and execution nonce from a
request. Binding is immutable and must precede delivery. Missing stamps do not
fall back to software-wide authority.

The fixture checks issuer ownership, reserved fields, nonzero identities,
re-binding denial, owner use and duplication, credential changes, failed exec,
forked-handle reuse, successful same-image exec and software revocation. Raw
ioctls establish kernel denial independently of libservice's PID guard. Existing
software-bound channels provide a positive control for deliberate delegation.
The populated native-service fixture checks the actual SwitchBoard endpoint:
owner status queries succeed, forked-handle reuse fails, the child can obtain
its own status channel, and UID 0 without management attributes cannot reload.

These checks run through the existing `build-bsd secureboot-test` build and VM
steps. Invocation binding does not authenticate a human, supply roles, define
session expiry, or authorize administrative operations independently of software
attributes. Those remain acceptance gates.

## Independent session authorization

The native fixture now includes a signed **test-only** Core issuer. It exercises
the real `service_user_session_create` API and broker policy, using the same
approved software under operator, reader and lifecycle principals. UID 0 with
the management attribute but no session is denied. The route is inherited
separately from software authority; clearing software authority still denies a
session holder. Private lookup registrations preserve the session association.

The authenticator retains a nontransferable lease locked against fork and exec.
The fixture tests last-duplicate closure, cached control/lifecycle denial after
logout, monotonic expiry, maximum lifetime and unlisted-principal rejection.
It also checks that Core management restrictions survive an operator role.
The native rc probe retrieves the test result through Notify and requires
`SESSION_AUTHORITY_PASS`; the fixture is never installed as a production
program and authenticates no human.

The signed malformed-policy cases consume explicit files under `policy/`:
`capsule-session-policy-invalid` has duplicate keys,
`capsule-session-policy-nul-key` has an embedded-NUL field name,
`capsule-session-policy-unknown-right` has an unknown role, and
`capsule-session-policy-include` attempts to include another file.
Each must report `invalid protected session policy` before rc or authenticated
READY. The standard protected-profile matrix includes all four cases. Normal system builds install an empty session policy; no production
human authenticator is enrolled by these tests. Protected input, login/SSH/su,
mutable personal storage, provider operation authorization and session recovery
remain separate acceptance work.

## PAM verification prerequisite

The populated guest also exercises the installed `5bsd-authenticate` policy
using the staged OpenPAM and `pam_unix` implementations. The test issuer starts
outside capability mode to load PAM policy, modules and account records from
the authenticated image, then enters capability mode for the existing session
checks. This is a test-only launch configuration; it enrolls no production
human authenticator.

Synthetic accounts cover wrong/empty passwords (both empty fields and stored
hashes of an empty string), missing and locked accounts,
account expiration and expired passwords. Correct credentials still need a
separate broker enrollment. A child impersonating the target UNIX UID checks
that the `pam_self` shortcut accepts its identity without a password, while
`5bsd-authenticate` rejects the wrong password. The fixture uses an in-process
conversation with a public test password; it establishes no trusted human input.
The runner requires `PAM_AUTHENTICATION_PASS` as well as all session, native
provider, bootstrap and console markers.

Normal builds install the verification policy through `lib/libpam/pam.d`.
It has no `pam_self`, `pam_rootok`, `nullok` or included legacy auth stack.
The backend rebuilds `pam_unix` and assembles that matching module into the
guest. `PAM_DISALLOW_NULL_AUTHTOK` must reject an explicitly supplied empty token
even when it matches a nonempty stored hash; a call without that flag provides
the positive control. Both authentication and account management must succeed before requesting a
role; `PAM_NEW_AUTHTOK_REQD` does not authorize a session. This verification
service denies password mutation and PAM session setup: protected account
updates and session launch remain separate work. The existing login, su and SSH
policies have not been switched to this service.

## Personal service ownership

The native case installs two unsigned personal bundles under UIDs 31001 and
31002. They deliberately share a label and request Core management and root
credentials. Registry ownership must force User management and the owning
account. A UID-0 test issuer obtains separate `manage_self` sessions; each can
start its own registered IPC-only unit, while foreign targets and System/Core
management remain denied. Closing the lease also denies a cached management
channel. Foreign personal targets return ENOENT; expired sessions return EPERM
before any target lookup.

The rc probe independently finds both processes under their owning UIDs in
capability mode and checks that ambient root and same-UID processes cannot
attach a debugger or signal them. Each personal program must reject attempted
session issuance before reporting readiness. The runner requires both readiness
receipts and `PERSONAL_SESSION_PASS`, alongside all prior native markers.
The maintained bootstrap backend builds the fixture, and the assembler records
guest ownership through METALOG. No host users or ownership are changed.
This read-only root fixture does not qualify mutable personal bundle storage,
protected human login, or general provider operation authorization.

## Authenticated personal discovery

Protected discovery selects a personal namespace from the live authenticated
session. Without a session, only a managed personal service's registry owner
supplies personal scope; application software identity and a changed UNIX UID
do not. Development mode retains kernel-credential namespace selection.
Immediate lookup, endpoint policy selection and on-demand activation must use
the same owner. Refreshing software authority across asynchronous activation
must preserve the broker route's independent session association.

The native test's rc grant explicitly permits `test.Personal`, so software
eligibility cannot explain an impersonation denial. Child processes change to
UIDs 31001 and 31002 without a session and must fail discovery. The enrolled
issuer remains UID 0 and obtains the correct provider through each owner's
session. The second owner's lookup activates its dormant provider. Each fixture
provider emits its UID over the resulting channel; the client checks the payload
and kernel credential trailer. New personal lookups after logout must fail.
`PERSONAL_NAMESPACE_PASS` is required in addition to all previous native markers.

The lifetime checks below cover already-delivered channels. General provider
operation policy and mutable personal bundle storage remain separate gates.

## Kernel-enforced session lifetime

SwitchBoard binds both ends of each provider channel obtained through an
authenticated session to one immutable kernel lease. The broker holds the
control descriptor; the original authenticator receives the owner descriptor
once. Both are locked against fork and exec. Last close of either file, loss of
the broker issuer, or the monotonic deadline invalidates all bound endpoints.
Duplicating an endpoint cannot remove the lease. Duplicating the owner retains
the lifetime until its last close. Software and invocation restrictions remain
independent prerequisites. This binding applies to direct messaging channels;
it does not expose a way to mint an unbound derivative through a kernel service.

`lease_test.c` runs in the static PID 1 fixture. `LEASE_PASS` is required for each
accepted static boot. The fixture exercises both binding orders with software
authority, invalid and foreign-issuer requests, immutable binding, both message
directions, queued messages, duplicate owners, forced inheritance restrictions,
kqueue EOF, receives blocked during logout and expiry, issuer/control closure,
and 128 repeated teardown cycles. WITNESS and INVARIANTS remain enabled.

The actual enrolled session issuer retains personal provider endpoints and
duplicates, then requires GETINFO, SENDMSG and RECVMSG to fail with EPERM after
logout. A separate live connection must expire while its owner remains open.
The result format is version 2 and requires `SESSION_LEASE_PASS`, so an older
issuer fixture cannot satisfy this gate. Management and lifecycle control
channels keep their existing per-request session checks and protocol errors.

Revocation prevents subsequent channel use. An operation admitted before
revocation may already have performed work; cancellation or rollback of that
work belongs to each provider's operation protocol. The fixture does not qualify
production human login, job cleanup, provider-specific operation policy, or
persistent storage/update/recovery/rollback protection.

Accepted boot cases must contain no `panic:` line, including after a success
marker. Negative loader and mandatory-integrity cases may intentionally panic
with the expected policy rejection before userspace; those are recorded as
rejections rather than successful boots. Fatal traps and WITNESS reversals
remain failures in every case.

## Writable scratch and program evidence

The protected Capsule cases now mount `/tmp` before manager launch as a 64 MiB,
mode-1777, nosuid/noexec tmpfs. This is public scratch, separate from the existing
claimed `/Capabilities/Run`. The fixture checks its actual flags and capacity,
system-file attacks through aliases, root unmount denial, execution and
executable-mapping denial. A child irreversibly drops to UID 65534 and runs
staged sh, cat, cp, mv, rm, mkdir, mktemp and sort, validating each operation's
result. It also demonstrates that reading a script through an interpreter is
allowed; noexec is not a script-input authorization policy.

`capsule-tmp-missing` and `capsule-tmp-nonempty` authenticate malformed layouts.
Capsule must explicitly reject scratch preparation before launching rc or READY.
Persistent `/var/tmp`, user homes, service databases and third-party package
installation remain separate gates; this implementation does not hide them
under ephemeral mounts.

`result.json` includes the actual ELF program inventory and per-case observations;
`programs.txt` presents those results for inspection. A READY-only BSDAudit is
reported as started, not as a durable audit-storage pass. Negative cases record
programs not reached. An accepted case requires all eight utility operation
markers and STORAGE_PASS as well as the existing bootstrap/service assertions.
The runner records the QEMU executable hash/version and dynamic-loader overrides.
The VM host and its libraries are test infrastructure, not guest trust anchors.


## Principal-aware providers

The populated native guest requires `PROVIDER_PRINCIPAL_PASS` and session result
version 3. A separate test provider opts into the new principal notification and
enforces explicit operation/object policy. The same UID-0 client is denied
without a session and with an unrelated broker management role. Two principals
mapped to UID 31001 receive different read/write permissions; the reader sees
the writer's updated object but cannot mutate it. Another owner cannot access
that object. Software-only provider ADMIN bypass is disabled under BIP.
Legacy provider notification and public software identity layouts are unchanged.
These fixture permissions do not replace production provider policies or trusted
human authentication. The build helper rebuilds the provider fixture and the
runner records its source and artifact inputs.


## Storage policy parser and immutable input

The Capsule fixture copies the shipped BSDFilesystem policy into its authenticated
root and exercises the production parser from a child in capability mode.
`STORAGE_POLICY_PASS` requires the read-only policy to load, a mutable policy fd
to be rejected, and the constant BIP status to be readable but unwritable inside
Capsicum. The runner requires this marker for accepted Capsule cases. This is
parser and kernel mechanism coverage; it does not start BSDFilesystem or qualify
persistent dataset delegation. The native `config_test` in the daemon's maintained
test suite covers varied policy, malformed schema, external input rejection,
derived paths and file-descriptor validation.

## Capsule configuration rejection

The matrix includes correctly signed images with missing Capsule policy,
duplicate and embedded-NUL keys, unknown fields, wrong field types and include
directives. PID 1 must emit its explicit configuration rejection before rc or
manager READY, without entering single-user shell recovery. These cases test
policy validation independently of image-signature verification. Accepted
Capsule cases consume the shipped policy from the authenticated read-only root.
The maintained bootstrap rebuild and assembler include the current libcapsulert
claim parser alongside Capsule. Native tests check varied accepted values,
atomic rejection, file limits and malformed port/CIDR syntax.

These added VM cases remain pending qualification with the new build. They do
not establish full installed-system policy coverage, owner-authenticated recovery
or a usable networked system.

The native fixture's temporary rc software grants are an explicit versioned
input, `policy/boot-authority.ucl`, copied into the authenticated image and hashed
in the run inputs. SwitchBoard rejects ambiguous/NUL field names, duplicate
fields or grants, external includes and invalid schemas. Native parser tests
cover those rejections and input bounds; the accepted native VM case exercises
the valid grant path. Fixture permissions are not shipping authorization defaults.


## BIP dataset acquisition and anonymous-mount release

The optional `storage-anchor` case requires explicit `--storage-disk` and
`--storage-policy` inputs. The disk must be a regular virtual disk image, not a
host device. The runner copies it privately, checks the input hash, authenticates
the policy and static fixture in the root image, and preloads the matching signed
ZFS module. The BIP kernel independently requires Secure Boot and an immutable
root before PID 1 can run. The case uses 2 GiB RAM and four virtual CPUs.

Build `tools/test/secureboot/storage` within the matching world buildenv. The
maintained build-bsd bootstrap backend does this automatically. Prepare a new
exported pool with the maintained daemon-runtime runner, adding:

```
--zfs --memory-mib 2048 --scratch-disk-mib 1024 --timeout 360
--atf-suite tools/test/secureboot/storage/prepare_test
```

This preparation fixture deliberately retains its exported pool in its private
`scratch.img`; it never touches a host pool. Require the preparation report to
pass with clean shutdown. The serial `BOOT_STORAGE_INPUT` record supplies the
actual pool and dataset GUIDs. Use those quoted decimal strings in an explicit
Capsule policy, along with a separately provisioned stable `hostuuid`.
This particular disposable fixture creates pool `bipfixture`,
dataset `bipfixture/provider`, and sibling `bipfixture/outside`. Its private disk
occupies guest `/dev/vtbd1`. A suitable test recipient is `test.Store/provider`;
the test grant needs only `props_read`, `event` and `mount`. These are fixture
choices, not installed policy defaults or production enrollment.

Run the Secure Boot runner with the usual explicit root, kernel, loader,
firmware and vars-tool arguments, plus:

```
--case storage-anchor
--storage-disk /usr/obj/usr/src/<preparation-work>/scratch.img
--storage-policy /usr/obj/usr/src/<qualification-work>/storage.ucl
```

The build-bsd frontend accepts the same two storage inputs for `secureboot-test`
and adds this case to its normal matrix. Its plan validates the paired inputs and
preserves their paths; it does not invent identities or discover host pools.

The static PID 1 fixture calls the production Capsule prepare/derive functions.
It checks actual BIP enforcement and policy acquisition, delegates bounded
handles, and verifies root and UID65534 consumers. Both reject raw devices,
ambient unmount by filesystem ID, sibling traversal and ungranted snapshots.
One creates and syncs a file; the next reads it. The parent independently checks
that the mount has disappeared after each last close, covering both the dataset
handle and root-directory descriptor closing last. Every assertion and clean
firmware shutdown is required. The runner rejects missing/duplicate evidence,
panics, WITNESS reversals and forced termination.

This proves selected acquisition and lifetime mechanisms under BIP. It does not
prove the real manager RPC, verified bundle delivery, provider restart, persistence
across reboot, a complete compatibility namespace or an installed-system upgrade.
The source disk remains unchanged, while each case retains its written copy and
before/after hashes. Failed setup, test assumptions and product regressions must
remain in their original result directories.


## Actual Capsule and filesystem-provider integration

Add `--filesystem-policy <file>` alongside the explicit storage disk and Capsule
policy to select `capsule-storage` in `build-bsd secureboot-test`. The direct
runner also accepts `--case capsule-storage`. The maintained bootstrap backend
builds BSDFilesystem and the signed storage client/console observer with the
matching world. Both policies and the source disk are hashed inputs. The source
disk is never attached directly.

The Capsule storage assignment must select the provider policy using its
`policy` field. `--filesystem-policy-destination` selects the matching image
path (default `/Capabilities/Config/bsdfilesystem.ucl`); `build-bsd` forwards
this input to the runner. Use a canonical absolute path. The assembler rejects
symlink components and collisions outside the historical default config path.
Capsule authenticates and retains this file, and SwitchBoard forwards that same
read-only object to the provider. This handoff does not grant data access.
Both the manager and provider parse it using libcapsulert's shared filesystem
policy parser; the bootstrap build installs that library before its consumers.
The runner binds the shared parser and header as inputs to its evidence.

The storage mechanism suite also requires `BOOT_STORAGE_NAMED_DERIVE_PASS`:
it tests atomic expected-name management derivation, mismatched objects,
malformed names, mandatory leases and parent scope. This does not establish
broker namespace selection or complete provider data access.
`BOOT_STORAGE_NAMED_DATA_PASS` additionally checks the data-issuer counterpart,
including rename/restoration before exact derivation. The resulting issuer is
used by the existing file-data checks. The maintained build-bsd fixture path
builds these tests, and runner acceptance requires their markers. These checks
do not establish claim-specific broker authorization or full service operation.
The real-provider fixture now exercises broker selection using the authenticated
policy roots and observed client identity. Its positive worker-management path
does not qualify malicious-provider nominations or data access; those remain
separate acceptance requirements.

For the disposable pool prepared above, the Capsule policy must name the real
pool/dataset GUIDs and recipient `system.Filesystem/bsdfilesystem`. The current
provider needs the full set of explicitly named dataset rights for provisioning,
versioning and cleanup; the minimal `storage-anchor` grant is insufficient. The
provider policy must specify pool `bipfixture`, base `bipfixture/provider`,
persistent root `bipfixture/provider/Data`, and ephemeral root
`bipfixture/provider/ephemeral`. These names describe the preparation fixture;
production identities remain deployment inputs. `open_paths=[]` suffices for
this case. See capsule.conf(5) and BSDFilesystem.8 for the production schemas.

The real Capsule imports the exported pool, SwitchBoard delivers the configured
bounded grant to the verified Core provider, and a separately signed test client
uses the normal filesystem protocol. The client has no `storage-root` grant or
ambient `/dev/zfs` access. It writes and syncs distinct contents under the same
claim name in UNIT, CACHE, SHARED and an explicitly declared GROUP scope, releases
each twice, then reopens and compares all contents. It also rejects traversal
and an undeclared group, and checks claim statistics. The private UNIT descriptor
is retained by a child that clears software authority and verifies invalid
membership. Both a one-byte read and same-byte write must then be denied. The
admitted parent keeps working and finishes the functional checks. The observer
reports both results; the host requires exact EACCES/EPERM denials alongside the
functional result, rejecting old, missing or duplicate evidence.

**Current failure:** the enforcing Secure Boot VM reproduces successful retained
read and write after authority clear (storage-retained-vm-v3). Mandatory
persistent storage grants are not implemented. This strengthened case is
expected to fail until that implementation exists; do not downgrade or skip its
denial assertions to recover the older functionality-only pass. Its group membership is an
explicit disposable Bundle.ucl input. The console observer receives the result
through the manager-authenticated client endpoint; no production console or log
access exception is needed.

Require the operation result, both application-ready records, and the ordinary
Capsule/bootstrap/root-denial checks. Readiness alone cannot pass. Client or
provider exit, failed operations, panic and WITNESS reversal reject the run.
Accepted Capsule cases currently end with host cleanup after completion; they
do not qualify authorized guest shutdown. This case proves persistence across
release/reopen in one boot, not restart/reboot, complete principal authorization,
normal rc, SSH, pkgbase generation sealing or upgrade into a new boot environment.
Missing/misdirected-grant integration, provider/manager restart and cross-boot
storage qualification remain separate required gates.


## PAM module resolution

The maintained bootstrap backend rebuilds `libpam`; the assembler records and
copies that library instead of its staged predecessor. Native PAM resolution
fixtures are explicit inputs in `policy/pam-resolution.json` and the referenced
policy files. They place real staged modules in the standard search directories,
with deliberately unsafe first candidates or malformed ELF content and valid
later candidates. A missing first candidate is a positive fallback control;
an explicitly versioned module is a positive exact-selection control. Optional
malformed entries must remain fatal. The guest exercises ordinary `pam_start`
and `pam_authenticate`, using the production resolver and `fdlopen`.

The populated case requires the `PAM_MODULE_RESOLUTION_PASS` marker and the
updated issuer result version, alongside its previous password, account, broker,
provider and bootstrap evidence. An old fixture or a readiness-only service
cannot supply this new result. Native ATF tests in `lib/libpam/tests` additionally
exercise static fallback through the production registration macro and lookup,
and reject search-path overflow. `pam_module` is an explicit ATF input for the
real loadable module used by those tests; its default is the installed pam_deny.

This is module-selection qualification, not authenticated PAM dependency closure.
Ordinary ownership checks still trust root-owned writable storage. Search paths,
includes and fallback policy, module dependencies, NSS backends, account caches,
login classes and authorized credential writers remain part of the full BIP
contract. A copied policy list or this selected fixture is not a generation
inventory and cannot qualify normal SSH or a protected production authenticator.


### PAM include graphs

`policy/pam-includes.json` supplies the disposable include graphs and combined
pam.conf contents. The assembler copies these explicit inputs into the
whole-image authenticated fixture. The normal backend already rebuilds and
stages libpam; no additional frontend option or production policy exception is
needed. The populated guest now requires `PAM_INCLUDE_GRAPH_PASS` and the updated
fixture result version, in addition to module resolution and authentication.

The real parser rejects direct, indirect, optional and fallback cycles, a cycle
between services in one pam.conf, excessive nesting and an exponentially
expanding acyclic graph. Positive transactions follow failures and require
valid repeated includes, distinct combined-file services, the supported nesting
boundary and a smaller expansion to remain usable. Native tests additionally
exercise hard-link and symlink aliases and facility-specific reuse. They run
through production pam_start/parser code with isolated policy search paths.

The implementation tracks active opened-file identities per transaction rather
than globally rejecting previously visited paths. It caps active parses at 64
and total file parses at 1024; these are parser resource bounds, not site grants.
It does not authenticate files or their resolution namespaces, impose a total
policy-byte budget, or qualify remote NSS/account backends and credential writers.


## Alternate account database generation

The bootstrap build recompiles the target pwd_mkdb and statically builds the
maintained usr.sbin/pwd_mkdb account tests from the same source. The authenticated
image runs those tests as UID 65534, with databases confined to separate temporary
directories. The checks compare binary name and UID records in pwd.db and spwd.db
against a full rebuild from the declared target input. They cover updating a user
absent from the host database, preserving the first target record for a shared
UID even when host root has different ownership, and retaining the previous
databases after a malformed update. A flat-file-only query would miss the stale
UID-record regression and is not used for these comparisons.

The runner requires the pwd_mkdb operation marker alongside the other program
checks; merely including or starting the executable does not pass. This validates
alternate database generation in a Secure Boot/BIP fixture. It does not provide
production authenticator enrollment, protected persistent account storage, an
atomic credential-update service, or a complete installed-system generation.


### Storage across protected boots

The supplied Capsule storage policy must include an explicit top-level
`hostuuid`: a stable nonnil canonical lowercase UUID. PID 1 establishes the
kernel host UUID and standard derived ZFS host ID before acquiring the pool.
Provision a unique identity for the disposable machine and retain it for both
boots. The assembler and runner do not generate it. This is host coordination,
not cryptographic machine authentication; an active foreign pool or unsafe MMP
state still fails admission. Policy cannot change this identity during reload.

The capsule-storage selection now expands to a first boot and a dependent
capsule-storage-reboot record. The runner creates a fresh random challenge and
places it in the authenticated root image. The observer sends that input over
its manager-authenticated client channel. In the first boot, the signed client
requires absent records, creates distinct challenge-tagged data in unit, cache,
bundle-shared and declared-group scopes, fsyncs each file and directory, releases
the anchors, and verifies the contents on reopen.

The second boot uses the same provider root image and the first boot's private
storage disk. It starts from a byte-for-byte copy of the first boot's final
firmware-variable state. Existing data selects the recovered phase, which reads
and compares all four records before any data write. The runner requires created
then recovered markers with the same challenge, matching root-image hashes,
matching disk handoff hashes and matching firmware-variable handoff hashes.
A fresh or reset disk cannot count as recovery merely by creating new records.
The source preparation disk is copied only for the first boot and is never
attached to either guest.

Acceptance requires both case results and storage_reboot_continuity=PASS. A
failed first boot leaves the second unqualified. The host terminates each VM only
after complete assertion evidence; this is two cold boots with synchronized
writes, not an authorized guest shutdown or a physical power-loss test. Cache
retention is measured under this fixture's policy, without promising that
production caches cannot be reclaimed. Cross-principal access, missing/wrong
bootstrap grants, rolling back backing storage, protected upgrades and full
installed-world startup remain separate gates.


### Host-identity startup and inherited stream rights

The provider fixture now runs the actual `rc.d/hostid` and `rc.d/hostid_save`
scripts with the maintained rc library and defaults before requesting storage.
The explicit root stage must supply `/etc/hostid` (the policy UUID plus newline)
and `/etc/machine-id` (that UUID without hyphens plus newline). Build-bsd and the
runner reject missing inputs. The assembler authenticates these files as supplied;
it does not parse UCL a second way to invent or repair deployment identity.

The guest must verify both startup services, reject runtime reset and direct root
writes to the identity sysctls and files, then verify the unchanged values. Both
provider boots require `RC_HOSTID_PASS startup caches reset kernel-and-file-denials`
as well as their existing storage and bootstrap evidence. The script and utility
report distinguishes these operations from mere inclusion in the image. This
executes two real rc services; it does not claim normal whole-system rc startup.

The initial run exposed md5 rejecting the inherited console grant when its
Capsicum stream helper attempted to install broader default rights. The helper
now intersects existing descriptor rights, ioctl commands and fcntl commands with
the stream ceiling. No console right was added. Its consumers need recompilation:
the maintained bootstrap stages the header and rebuilt libc in its object sysroot,
then builds md5, sysctl and cmp and uses those exact artifacts in the fixture. The existing
public `cap_rights_intersect` function is now exported by shared libc as well as
available through static linking. The VM result determines qualification; native
helper tests alone cannot establish normal service startup or installed coverage.

The status check depends on sysctl reporting errors accurately. Its `-i` option
now ignores only an unknown OID (ENOENT at name lookup), and explicit variable
reads return failure for unsuccessful format, size or value queries. Native
fault-injection tests execute the actual command entry point and retain both the
before and after results. Query failures cannot silently select ordinary host-ID
startup behavior. VM execution uses the rebuilt target sysctl, not the stage's
older copy.


## Login-class generator input qualification

The maintained bootstrap build rebuilds libc and cap_mkdb, installs their headers
and library only into the matching private world sysroot, and builds the same
`usr.bin/cap_mkdb/tests` cases statically for the VM. The authenticated fixture
contains the matching dynamic target generator and libc. Its unprivileged program
probe checks all six maintained cases in isolated scratch directories and requires
`PROGRAM_PASS /usr/bin/cap_mkdb text-input-database-construction`.

The cases cover a different output basename with a stale input database, tc
inheritance across inputs with stale caches, ordinary output rebuilding, explicit
reader selection and its restoration, and oversized direct/continued names.
Database records are read back; a successful process exit alone is insufficient.
Ordinary readers retain their default compiled-database preference.

`cap-input-vm/result.json` under the qualification directory passes capsule-native
with these checks, 119 PAM assertions and 273 session assertions. This selected
fixture proves these mechanisms; it does not execute a complete pkg transaction,
normal installed-system startup, SSH, or a protected new-BE upgrade.

The integrity-enabled `approved` case also tests the production BSDFilesystem
policy reader against real mount identities. It accepts a policy from the
immutable root and rejects a valid policy on a separate tmpfs remounted
read-only, preserving the prior configuration and closing the descriptor.
This is a reader-boundary test, not installed-provider or update qualification.

The same approved case exercises Capsule's production configuration reader:
authenticated-root acceptance, rejection of a valid root-owned policy on a
separate read-only tmpfs, unchanged configuration and descriptor closure. A
control parses that same tmpfs file without immutable-source enforcement.
The fixture compiles the production config.c in a separate translation unit
to avoid its basename collision with BSDFilesystem's config.c.

Switchboard's production session_policy_init is also exercised at its actual
policy pathname. The test accepts the authenticated root policy, mounts a
separate tmpfs over that directory, writes the identical policy, remounts it
read-only, proves O_VERIFY open succeeds, then requires reader rejection and
an empty issuance-policy table. Unused session operations are removed through
linker section collection; none are replaced with success stubs. This directly
tests the startup reader, not the complete service/session lifecycle.

## EFI staging growth regression

`make -C /usr/src/tools/test/secureboot efi-staging-test` compiles the current
loader allocation functions with simulated EFI services. It checks large-load
copy bounds, exact-size fallback in fragmented memory, allocation refusal,
overflow, extension above staging, post-ExitBootServices behavior and actual
small-payload bytes/offsets after relocation. Large copies are counted rather
than performed. This native regression does not qualify firmware, signatures
or boot. Rebuild the real EFI loader through the normal source build and run
the signed positive/adversarial VM cases before accepting a loader change.

Fixture input roots must preserve executable modes as well as bytes. The
Capsule assembler rejects ELF programs without execute permission before
staging their dependencies; it does not chmod them into working programs.
This check is part of assembler_test.py, invoked by the maintained bootstrap
build step. A copied mechanism-test root is not a package-derived generation
merely because its selected files pass these checks.


## Crypto boot-recipient qualification

The default integrity suite includes capsule-native-crypto-absent and
capsule-native-crypto-wrong. Both use correctly authenticated native fixture
images with an explicitly empty or nonmatching Crypto recipient. These are
disposable test policy variants, not production policy defaults. The real rc
client must reach Notify, fail Crypto connection with ECONNRESET, and fail a
direct /dev/crypto open with EPERM. The runner also requires the actual Crypto
startup-check-13 exit, rejects provider readiness or registration, and requires
the remaining generic Capsule assertions. A timeout alone never proves denial.
The positive native case still requires key generation, signing and verification.
Host termination after completed assertions is not clean guest shutdown proof.

Crypto probe result markers include delimiters in one bounded console write.
Short writes and interleaved or truncated marker lines fail qualification; the
runner never repairs a damaged line into passing evidence.

The system-gate probe also checks current/legacy audit condition queries,
denies state changes without administrative authority, and reads back unchanged
state. This status test does not establish enabled or durable audit output.

The Capsule system-gate probe also repeats 512 refused auditctl calls against
a private /tmp file. It records NAMEI live/free counters, requires pathname
cleanup, and verifies file identity/content and audit condition before removing
the file. A retained run on the unfixed kernel detected 512 leaked buffers.
This is denial-path cleanup qualification, not successful audit trail activation.


The integrity PID 1 fixture also requires `ISOLATION_IO_PASS`: root foreign-exec
read/mmap denial through inherited descriptors, an explicitly delivered bounded
read token, write/execute escalation refusal, unchanged content and claim-release
behavior. The normal build-bsd backend includes this probe. A backend invocation
with `--case approved` is focused qualification only; it does not replace the
full suite or normal installed-service acceptance. Preexisting mappings and
mount-wide persistent protection are not established by this probe.

## Retained image archives

Completed qualification disks may be retained as lossless gzip archives to
recover build space. An archive manifest records original and compressed
SHA-256, original size and basic file metadata. Before removing a raw guest
image, compare it with the recorded case `disk_sha256`, verify decompression
against the original hash, and ensure the owning runner/QEMU has terminated.
Keep result, serial/firmware logs, inputs and key material in place. Archival
must not change case outcomes or make old artifacts qualify new source.

To replay archived inputs, restore into a fresh work location, verify the
archive hash, decompress, then verify the original hash and size before use.
Restore recorded permissions as appropriate. Do not overwrite a newer run or
reuse an old run's success result. These image-content archives do not certify
preservation of filesystem extended attributes; retain original source/stage
metadata and qualification manifests separately. Replaying the complete suite
through build-bsd with fresh keys remains the current-source acceptance path.

### Retained evidence verification

`build-bsd secureboot-test` runs `verify_evidence.py --require-complete` after
successful VM execution. It rehashes recorded inputs, case logs, disk images,
firmware variables and root images, checks exact requested case coverage, and
verifies the shared-disk/firmware handoff when provider reboot cases are present.
The verifier writes `evidence-verification.json` exclusively; it never overwrites
an earlier receipt. Run `python3.12 verify_evidence.py --work WORK` to verify a
selected-case run, or add `--require-complete` to require the complete suite.
`make evidence-test` exercises rejection of changed and incomplete evidence.

This receipt verifies consistency of retained artifacts from a trusted runner.
It is not a signed attestation, installed-system acceptance, or proof of mandatory
persistent-storage enforcement. A changed source or input must be investigated;
do not regenerate hashes simply to make an old run appear current.

Completeness is checked against the runner's shared canonical case plan, not
just `complete_suite=true`. Reports must record the integrity/storage suite
profile; the actual ordered cases must match that profile, including both boots
when provider storage is selected. Old reports without a profile remain eligible
for retained-file verification without `--require-complete`, but cannot pass the
new completeness gate. Changing input scripts after a run invalidates a fresh
input-hash verification; preserve the original receipt instead of relabeling
historical results as execution of newer code.


## Bootstrap backing reservation gate

The storage-anchor fixture retains its existing delegated I/O checks and then
exercises ZFD_BIP_RESERVE. It closes the earlier bootstrap anchors, checks that a
root child cannot register, registers twice as original PID 1, mounts and reads,
closes every storage descriptor, unmounts, and verifies denial of info/mount after
reopen for root and non-root children. Bootstrap access remains usable. The host
requires BOOT_STORAGE_RESERVATION_PASS in addition to the original checks and
actual firmware shutdown. The ordinary-kernel ATF case
storage/prepare_test:reservation_without_policy requires EOPNOTSUPP and continued
ordinary handle use when BIP is absent.

This explicitly invoked registration is not wired into production Capsule. It
quarantines TrustedZFS pool management until scoped grants exist; it does not
mediate existing vnode descriptors or prove full subtree/raw-storage protection.
The real-provider retained-read/write failure remains required and unresolved.
Use matching rebuilt kernel and modules: this change advances MAC ABI to 13.


### Retained vnode and mapping gates

The anchor profile now includes storage-anchor and storage-mapped. The former
requires positive read/write/sendfile before reservation and EPERM afterwards on
the retained descriptors, metadata and namespace operations, and new mappings.
Bootstrap retains ordinary I/O but cannot create a reserved-storage mapping.
The latter uses a separate fresh disk copy to demonstrate that mapping exposure
makes registration fail with EBUSY even after unmap/close/unmount. Neither test
claims to revoke existing mappings or drain in-flight I/O.

Both cases require real firmware shutdown. The evidence verifier recomputes
storage completion, including the distinct mapping marker. Kernel/modules must
match MAC ABI 14. This is still explicit whole-pool quarantine without production
activation or scoped grants; it does not resolve the real-provider milestone.

### Bootstrap data-grant regression

The storage-anchor case now requires storage_grant_test.c to complete real
read-only and read/write namespace operations under an exact-dataset grant.
It checks scope, fork denial, final control close, software/issuer revocation,
authority clear, descriptor inspection and locked control inheritance. The
storage-mapped case still checks the independent mapping-exposure quarantine.
These are mechanism tests of asynchronous admission loss; they do not prove
I/O draining or a protected BSDFilesystem service. The maintained build-bootstrap
path builds the new fixture source, and run.py records its source/header hashes
and requires its completion marker. No shipping policy enables these grants.

The same storage case now requires the lease-bound grant marker. Three additional
recipient runs retain valid software authority and the storage-control descriptor
while ending the lease through owner close, control close or kernel-observed
deadline expiry. Retained I/O is then denied. Foreign-issuer and wrong-descriptor
requests are rejected. This is a lifetime constraint; authenticated session policy,
resource delegation and synchronous I/O draining remain separate required gates.

### Content-I/O drain regression

The anchor case additionally requires BOOT_STORAGE_IO_DRAIN_PASS. It preloads
mac_bip_io_test.ko from tools/test/secureboot/io-fixture, built against the selected
kernel. This non-granting MAC policy pauses real reads/writes after BIP admission;
PID 1 selects the actual vnode by descriptor. The test observes an active operation,
checks that explicit drain cannot return while it is paused, releases it, then
checks zero active operations and denied subsequent access. It also tests signal
interruption/retry, last-control close while I/O is active, and unsupported-mask
rejection without loss of existing admission. The module is authenticated in the
anchor manifest and is absent from provider and ordinary approved-boot cases.

build-bsd secureboot-test builds this module for the anchor storage profile.
For direct runner use, build through buildenv with KERNBUILDDIR set to the selected
kernel's object directory. The runner records the module and fixture source hashes.
No production policy gains a delay control. This qualifies READ/WRITE-only grant
content draining; broader masks return EOPNOTSUPP. Software/session loss and final
close remain asynchronous. Namespace/backing drains, production consumers and
real-provider acceptance remain unfinished. Untracked sendfile and directory/link
reads under these grants are denied. Completion is not a durability guarantee.

### ZFS handle identity regression

The anchor profile also requires BOOT_STORAGE_IDENTITY_PASS. Its existing
non-granting MAC observer records the actual held-object tuple, pool/dataset kind,
command and clone-operand role. storage_identity_test.c checks these against ZFS
INFO/objsetid, performs and removes a real snapshot/clone, and confirms that a
nonbootstrap root process remains denied. The dataset and containing pool are
resolved from the supplied storage policy. The runner hashes the new sources;
existing build-bsd bootstrap and observer-module steps build them. No new frontend
option or production permission is added. The test does not establish subtree
inheritance, management delegation, service activation or installed-system use.

### Resolved-object and publication checks

BOOT_STORAGE_RESOLVED_PASS additionally requires actual selected-snapshot and
published-child identities, successful pool-root/openat/create/clone operations,
and denials at those precise MAC phases. The test-only observer may deny those
phases; it cannot grant permission. Denial tests check unchanged descriptor count
and absence of the destination after create/clone cleanup. These are enforcement
and cleanup mechanism tests, not delegation or crash-recovery acceptance. Existing
build-bsd bootstrap/module targets build the updated helper and matching module;
no production switch, policy permission or new frontend option is introduced.

### Namespace checks before mutation

BOOT_STORAGE_NAMESPACE_PASS requires real nested-dataset create/clone, rename
between different parents, and destroy. The observer verifies actual parent and
source identities. Independent denials at each new pre-mutation phase must leave
the namespace and caller descriptor count unchanged. The VM-only denial policy
never grants access. Existing build-bsd fixture/module steps build the changes;
production delegation, subtree inheritance and backing-operation draining remain
separate gates.

### Selected snapshot mutation checks

BOOT_STORAGE_SNAPSHOT_PASS requires real-file rollback tests for both an explicit
snapshot and implicit latest selection. Denied rollback must preserve newer data;
successful rollback must restore saved data. Snapshot deletion is tested with
both denial and success, using observed actual snapshot identities. The helper
releases its anonymous mount before rollback. This does not qualify busy-mounted
rollback or full provider lifecycle behavior. Existing build-bsd fixture/module
steps build the changes; the observer's deny control remains VM-only.


### Full and incremental stream admission

BOOT_STORAGE_STREAM_PASS requires actual full/incremental send and receive with
file-data verification. Denied snapshot/base admission must leave output empty
and one-shot send eligibility intact. New-target parent denial must leave the
destination absent; existing-target EACCES and ENOENT policy denials must leave
its data unchanged without a parent fallback. Successful receive restores both
versions of the file without force. Verification mounts are read-only to avoid
dirtying the received head before an incremental receive. Each receive attempt
rewinds its stream because libtrustedzfs consumes BEGIN before the ioctl.

These are bootstrap mechanism tests, not production management delegation,
forced receive, cancellation/drain or provider lifecycle qualification. The
existing build-bsd bootstrap/module steps build the tests; the observer remains
VM-only and cannot grant access.


### Real-provider invocation inheritance

The storage client result protocol version 4 records retained pread/pwrite after
fork while software attribution is still valid, then again after CAP_AUTH_CLEAR.
The authorized parent still completes all four scope data/reopen/stat checks.
Provider completion requires independent AFTER_FORK and AFTER_CLEAR denials;
software attribution alone must not admit a new invocation. The actual provider
currently fails both checks (bip-provider-admission-vm-v1). Reboot acceptance is
not run after that first-boot failure. Existing build-bsd bootstrap steps rebuild
the client and observer together; this is a private test protocol, not a service
wire-format change.


### Typed dataset-property admission

BOOT_STORAGE_PROPERTY_PASS requires actual quota/mountpoint changes and readback,
with policy-denied values leaving state unchanged. PID 1 supplies the VM observer's
property names and ceilings; no fixture rule is a production permission. Tests
check exact dataset identity, integer/string selection, inactive-field isolation
and malformed-payload rejection before admission. The runner now hashes the
relevant kernel MAC/ZFS sources and generated hook metadata alongside artifacts.
Existing build-bsd bootstrap/module steps build the matching MAC-21 observer and
fixture. Production property ceilings and scoped provisioning grants remain open.


### Concurrent pipe streaming

storage-anchor now also requires BOOT_STORAGE_PIPE_PASS. Two threads of PID 1
send a real snapshot through a bounded pipe into a receive. Success requires
both operations to finish within the progress deadline, whole-file comparison
of 4 MiB of deterministic payload, and dataset cleanup. Timeout records operation
state, pipe occupancy and guest thread wait states before failing the case.
The heap context stays alive for blocked threads until the failed VM is stopped.

bip-pipe-vm-v1 reproduces a namespace-gate/pipe deadlock: send waits on pipe output
while holding the gate that receive needs to drain the pipe. File-backed stream
success does not cover this. The regression is required by the standard fixture
and existing build-bsd bootstrap target; there is no bypass flag or expected-pass
exception. The sender-side cycle is repaired by numeric-object streaming with pinned snapshots;
typed receive input progress and parent replacement are covered by the subsequent
bip-recv-gate-vm-v2 regression below.


BOOT_STORAGE_PIPE_IDENTITY_PASS additionally requires failed-output pin cleanup,
EBUSY on deleting an in-flight snapshot, and successful source rename/replacement
before the consumer starts. BOOT_STORAGE_PIPE_PASS then verifies all original
payload bytes. bip-send-pin-vm-v1 passes this strengthened regression and the
existing storage checks.

BOOT_STORAGE_RECEIVE_PASS requires a direct ZFD_RECV blocked on kernel pipe input,
unrelated namespace create/destroy progress, resumed payload verification,
truncated-input cleanup and parent rename/replacement rejection. A replacement's
sentinel data must survive and the abandoned receive must disappear from the
renamed parent. The test requests subtree rights explicitly; v1 exposed a missing
fixture rights request and failed. bip-recv-gate-vm-v2 passes the corrected test
and all three requested Secure Boot cases with clean firmware shutdown.
The standard storage build includes storage_receive_test.c; runner acceptance
requires exactly one completion marker, and evidence binds receive-core sources.
Existing-target incremental replacement, signal cancellation, complete management
drain and production data grants remain unqualified.


The real-provider client/observer protocol is version 5. Besides retained
pread/pwrite, it requires openat, create, ftruncate and fchmod denial independently
after fork and after authority clear. Each namespace/metadata result is emitted
as STORAGE_NAMESPACE_AFTER_FORK/CLEAR with operation, result and errno. Acceptance
requires one EPERM/EACCES denial per operation and phase; unexpected success and
EBADF cannot count as protection. Parent-side cleanup preserves the recorded
failure. bip-provider-namespace-v1 currently fails all these checks under Secure
Boot. This is a production integration blocker, not an expected-success case.


BOOT_STORAGE_ISSUER_PASS is required by the storage-anchor case. It exercises a
real bootstrap-created data-issuance ceiling transferred once to a nonbootstrap
manager, then issuance in capability mode to an independently observed recipient.
It rejects widened actions, missing required leases, unregistered resources and
onward transfer; fork/exec closure is locked. Positive data access and out-of-scope
denial run before testing last-close, explicit issuer revoke and lease loss with
the issued grant descriptor still open. bip-data-issuer-vm-v2 passes these checks
and existing regressions in all three requested Secure Boot cases. The first run's
missing fileops passability flag is retained as failed evidence. This mechanism
is not yet activated by the actual provider or authenticated state policy.


BOOT_STORAGE_ANCESTRY_PASS requires live identity chains for typed operations,
including rename/name reuse, reparenting and snapshot owning-head relationships.
It distinguishes unavailable shared-read ancestry from a complete empty root
chain. The ABI22 observer reports truncation explicitly; its eight-entry capture
buffer is not a production depth limit. bip-ancestry-vm-v1 passes this and the
existing storage regressions in all three requested Secure Boot cases. BIP still
denies reserved-pool management to nonbootstrap actors; this test does not prove
subtree grant enforcement or production service activation.


BOOT_STORAGE_READ_ANCESTRY_PASS requires policy-requested exclusive retry for
INFO and GET_ONE_PROP, actual ancestry after rename/name reuse and reparenting,
second-check denial, and a bounded failure for repeated retry requests. The
nonbootstrap root test additionally proves a real BIP denial dominates the retry
request without another callback. bip-read-ancestry-vm-v1 passes these and existing
regressions in all three requested Secure Boot cases. This mechanism does not
activate scoped management grants or repair every legacy shared-read race.


BOOT_STORAGE_MANAGEMENT_PASS exercises a real nonbootstrap invocation-bound
management grant: filesystem provisioning, integer/string property ceilings,
metadata and snapshot operations, rename, live reparenting scope, fork rejection,
issuer revocation and separation from file-data access. It rejects volume creation,
raw block access and unsupported factory operations. Policy rules are copied:
changing their original input array cannot widen authority. bip-management-vm-v1
passes this and the existing regressions in all three requested Secure Boot cases.
The observer uses MAC ABI23. This is not production provider activation, full
management-operation coverage, complete resource budgeting or synchronous drain.

The storage-anchor case also requires
`BOOT_STORAGE_MOUNT_GRANTS_PASS independent-admission retained-revoke cleanup`.
It checks separate management/data admission for an existing anonymous mount,
retained-descriptor denial after the data grant closes, continued management
cleanup, and denied first-mount publication of a new child without data authority.
Later child destruction checks cleanup of that failed mount. Successful dynamic
child admission and real-provider activation remain separate unfinished gates.

`BOOT_STORAGE_PREMOUNT_PASS reserved-handle first-mount data-scope fork revoke cleanup`
is required for storage-anchor. Bootstrap obtains a data issuer from an exactly
reserved, never-mounted ZFS child handle. The admitted recipient first mounts it,
creates and verifies file content, and exercises independent parent/child grants,
fork denial and issuer revocation. It rejects absent exact reservation, subtree
factory flags, missing required lease and nonbootstrap factory use. This is
bootstrap-selected exact child admission, not delegated child policy or actual
provider activation. MAC ABI24 requires the matching observer module; the existing
build-bsd bootstrap build compiles it.

The real-provider request adapter preserves per-request kernel process/software
attribution and requires complete attribution under BIP. This does not replace
the retained-descriptor denial checks: `bip-provider-actor-v2` still fails those
checks after normal container operations complete. Metadata-negative coverage is
in BSDFilesystem's `quota_test:bip_sender_required`; the VM demonstrates the valid
request path. Failed provider runs remain failures and skip reboot acceptance.


### Invocation-bound client channels and worker admission (2026-10-20)

Under BIP, non-forwardable authenticated SwitchBoard client endpoints are bound
to the software and invocation observed on lookup. Workers must obtain their own
client sessions after fork and before dropping lookup authority. BSDNotify,
BSDCrypto, BSDNetwork and BSDLog now follow this rule for Audit connections;
compilation passes, while Network/Log runtime coverage remains outstanding.

Storage client/observer protocol 6 adds a paired parent/fork check using
MAC_CAPABILITY_GETINFO. It verifies descriptor presence and valid software
attribution in the child before requiring EPERM/EACCES, and checks successful
parent access before and after. FIONBIO with an unchanged setting is unsuitable:
the generic ioctl path can return without invoking the channel operation.
The retained v1 failure records that test mistake; v2 uses the actual channel
operation and passes this isolated check. The full provider run remains FAIL:
all twelve unauthorized retained-storage operations still succeed, cleanup is
forced, and the second boot is skipped. Channel binding is not storage admission.

Native compatibility follow-up `bip-channel-native-v3` passes all three cases:
normal Audit/Notify/Crypto operation and missing/wrong Crypto boot recipient
rejection. The separate input stage contains the maintained base Capsule policy;
the runtime supplies no implicit Crypto grant. Evidence verification checks
169 files. `bip-channel-validation-v1.json` records these bounded results and the
still-failing provider run. Network/Log runtime qualification remains pending.


### Management issuer before first mount (2026-10-20)

The production handoff requires reservation before any provider directory is
published. The directory-based management factory alone could not establish that
ordering without a bootstrap mount. `ZFD_BIP_MANAGEMENT_ISSUER` now prepares the
same bounded management issuer from an exactly reserved live filesystem handle.
It is available only to original bootstrap; it does not admit the provider or
register descendants. Actions, subtree scope, required lease and typed property
rules remain explicit inputs. Property copying/validation is shared with the
mounted factory. No data rights follow from management authority.

ZFS resolves the live filesystem under the exclusive namespace gate and releases
DSL holds before the policy callback. The framework installs the prepared file
only after all policies succeed, dropping it on error. The result retains the
existing one-transfer and locked fork/exec restrictions. Kernel MAC ABI is 25;
trace metadata has 344 hooks, maximum eight arguments. Both maintained kernels
and the matching fixture/observer build with 16 jobs. The standard build targets
consume these sources; no alternate kernel or test-only authorization path was
introduced.

The extended management test creates a fresh dataset, rejects issuance before
reservation and malformed ceilings, obtains the issuer before any mount, then
uses that issuer for independently bound recipient provisioning and property,
ancestry, fork and revocation checks. The old mounted factory remains exercised.
The first run used the provider's broader policy by mistake and failed an earlier
narrow-grant check; that evidence remains at bip-management-premount-vm-v1.
V2 used the recorded anchor policy but reused bootstrap's mount-owning handle
for the recipient; EBUSY preceded the BIP assertion. V3 uses independent handles
and passes all three cases (storage-anchor, storage-mapped, approved), preserving
the EPERM assertion and requiring clean guest shutdown. Evidence verification
passes. Receipt: bip-management-premount-validation-v1.json. This is not production
activation: Capsule policy ceilings, reservation/issuer retention, post-exec
provider/worker activation and dynamic client data admission still need wiring.


### Explicit management policy parsing; activation unfinished (2026-10-20)

Capsule's storage assignments can now represent a `management` object with
explicit operation names, subtree/lease booleans and bounded typed property
rules. Integer limits use canonical unsigned decimal strings through UINT64_MAX;
string limits use exact values. The parser rejects unknown/duplicate fields and
operations, unsupported operations, duplicate property names, malformed types,
inverted/overflowed bounds and inconsistent set-property ceilings atomically.
Property order is canonicalized for immutable boot-policy comparison. No provider
name or property value is inferred from an executable or writable database.

This is preparatory policy support, **not activated protection**. Both original
bootstrap preparation and direct acquisition reject a supplied management ceiling
with EOPNOTSUPP before device access/import until reservation, retained issuers
and observed-invocation activation are integrated. Existing assignments without
this field retain their current behavior and do not establish complete BIP state
protection. The shipped policy is not changed to claim unsupported activation.

Capsule and tests build with 16 jobs through the maintained targets. Nine focused
configuration cases pass, including the new ceiling/atomicity case and existing
storage, identity, Crypto and shipped-policy regressions. The direct acquisition
rejection test passes without opening devices. The installation-specific case
skips for missing explicit installation inputs and is not counted as a pass.
These are direct ATF runs in disposable working directories, not VM or installed
system qualification. Receipt: bip-management-policy-validation-v1.json.


### Bootstrap consumes the ceiling; handoff still unfinished (2026-10-20)

Original Capsule preparation now acquires the verified handle privately, checks
its identity against the selected configuration, reserves it and validates the
configured management issuer before any mount or delivery. The validation issuer
is closed immediately. Capsule retains the handle with only derive/factory ioctls
and locked transfer/fork/exec restrictions; a separate internal lookup creates a
fresh issuer for each future manager handoff. Thus the bootstrap handle does not
keep a delivered issuer alive. Ordinary derived handles from this private anchor
receive native ioctl restrictions. Existing ordinary anchors preserve their
previous derivation behavior.

A reservation survives all subsequent failures until reboot; acquisition failure
is fatal and cannot roll back to unprotected access. Direct acquisition continues
to reject management policy. The new helper verifies the complete selected held
identity before reservation. These changes supersede the preceding entry's
blanket preparation refusal, but do not supply manager protocol handoff, final
provider/worker activation or client data grants. Existing provider fixture policy
still omits a ceiling and its retained-storage gate remains failed.

The VM fixture now exercises the actual Capsule reservation helper using an
explicitly selected fresh dataset, rejects mismatched identity and nonbootstrap
calls, and checks copied ceilings through subsequent real recipient operations.
Full ceiling-configured Capsule startup and manager-restart issuer lifetime are
not yet qualified. VM v1 failed an earlier ordinary-anchor assertion because an
extra descriptor filter changed the denial path; the filter is now confined to
private management anchors. Its inputs changed before exit, so the harness
rejected that run as unstable evidence. V2 timed out in storage-anchor; storage-mapped and approved passed. V3 reran
only the failed anchor case with progress markers and a 300-second observation
limit. It passed all assertions and clean shutdown; verification checks one case
and 87 files. Receipt: bip-boot-management-validation-v1.json. Host tests: 37 PASS.
This does not qualify full ceiling-configured startup or manager restart.


### Manager issuer protocol; activation consumer pending (2026-10-20)

CAPSULE_OP_BOOT_STORAGE_MANAGEMENT (31) now requests a fresh configured management
issuer through the existing exclusive nonce-bound Capsule/manager channel. The
recipient remains an exact authenticated policy key. Capsule closes its reply
copy; it does not retain the delivered issuer. The SwitchBoard client helper
shares boot-grant RPC framing with storage and Crypto. No issuer is added to a
provider bootstrap descriptor list. Service launch does not yet call the helper.

All three boot operations share strict request validation: exact length, allowed
operation, nonempty terminated recipient and zero trailing bytes. Focused direct
ATF tests exercise accepted operations, every truncated size, oversize, NULL,
unterminated/empty recipients, nonzero trailing bytes and an unknown operation.
The test passes. The maintained bootstrap build refreshed the matching sysroot
and consumers after the initial SwitchBoard link found newer libcapbundle fts
symbols against an older staged libc; no host libraries or linker bypass were
used. Native regression passes normal operation and absent/wrong Crypto policy
rejection. Verification checks three cases and 169 files; 37 host runner/evidence
tests pass. Receipt: bip-issuer-protocol-validation-v1.json. These regressions do
not qualify a positive management handoff: its activation consumer remains absent.

Lifecycle review identifies the existing authority_record as the appropriate
owner for an invocation's issuer/grant: it is keyed by software identity and
launch identity, survives service-array relocation, and is removed by unit
revocation and manager teardown. This avoids adding bare descriptor ownership to
relocatable runtime slots. Admission must use kernel-observed control-message
identity after exec and before layout provisioning; SVC_OP_READY is too late.
Worker/client admission and data grants remain separate unfinished requirements.


### Original provider management admission (2026-10-20)

The production provider now requests management admission after service_acquire
and before layout provisioning. SVC_OP_STORAGE_MANAGEMENT carries an explicit
operation mask with a zero reserved field. SwitchBoard validates the exact wire
shape, resolves the kernel sender/software metadata and requires the original
launched PID. Core/system bundle provenance, installation owner and launch
identity are checked again before acquiring the boot-policy issuer.

The issuer and grant belong to the existing authority_record, whose software
identity and launch ID survive service-array relocation. They are never sent to
the provider. Successful issuance binds the actual process identity and execution
nonce; removal closes grant and issuer before revoking the software token. Failed
issuance closes its fresh issuer without publishing record state. One successful
admission per record is permitted. A ceiling requiring an additional lease fails;
this path uses launch/invocation lifetime and invents no renewal deadline.

BSDFilesystem requests only the management operations used for initial layout.
Workers and clients remain unadmitted, and management does not confer file-data
access. The explicit disposable policy provider-management-policy-v1.ucl selects
the existing test dataset and allows only the requested operations, subtree scope
and exact mountpoint=none, canmount=0 and sync=0 values. It explicitly selects no
additional lease. These are deployment inputs, not kernel/program name exceptions.
The real provider VM bip-provider-activation-v2 reaches readiness, establishing
that the mandatory management admission and initial layout path completed. The
first legitimate client storage open fails EPERM because workers remain
unadmitted; the full gate is FAIL, forced cleanup occurs, and reboot is skipped.
Protocol 7 verifies unsupported-mask and unassigned-Core denials through the
observer and explicitly marks unexecuted namespace tests -2. Neither unexecuted
checks nor blocked legitimate work count as acceptance. Receipt:
bip-provider-activation-validation-v2.json; all recorded inputs match, and 38
host runner/evidence tests pass. Restart/lifecycle qualification remains open.

The maintained build-bootstrap.sh now installs the rebuilt libservice into its
matching /usr/obj sysroot before linking capability images. Otherwise those links
could resolve the old library despite a successful library rebuild. All changed
consumers build with 16 jobs. VM input hashes now include both protocols, API and
policy headers, dispatchers and the maintained build script. No host installation
or reboot occurred.

### Scoped management issuer derivation (2026-10-20)

The kernel now implements `ZFD_BIP_MANAGEMENT_DERIVE` on a held live ZFS
filesystem. It takes a parent management issuer descriptor, operation mask and
flags as inputs. It does not infer scope from a name, UID, package, or provider
label. The parent descriptor must permit `CAP_IOCTL` and this derivation command
in its ioctl allowlist. Data issuers cannot be converted to management issuers.
The resulting issuer grants no actor access by itself.

ZFS resolves the target and complete live ancestry under exclusive namespace
serialization, releases DSL holds, and calls the dedicated MAC factory. Every
MAC policy must approve before the framework installs the returned issuer file.
This factory has its own authority check; it does not require an existing actor
management grant. Pool handles, snapshots and volumes are not valid targets.
MAC ABI is now 26; the maintained trace metadata describes 345 hooks.

Derivation can remove operations and subtree coverage, and can add a lease
requirement. It cannot add operations, widen an exact scope to a subtree, or
remove a required lease. Typed property rules are inherited unchanged. Every
operation checks the complete issuer chain for revocation and intersects all
ancestor dataset scopes against current live ancestry. Moving a derived root
outside its original ceiling denies access even through previously held handles.
Moving it back can restore access if no independent revocation occurred.

Child issuers retain parent state, never the parent's file. Explicit revocation
or final parent-file close therefore invalidates descendant grants and prevents
new grants. Closing one duplicate does not close the file while another owner
reference remains. Already admitted operations retain the existing admission
semantics; derivation does not add synchronous management-operation draining.
Issuer chains are limited to 32 levels to bound kernel work and reference storage;
this is a resource limit, not a limit on filesystem ancestry or an implicit path
policy. Further derivation returns `E2BIG`.

Bounded mechanism qualification passes. Both GENERIC and GENERIC-INTEGRITY
build; the matching observer and storage probe build; the 38 runner/evidence
tests pass. `bip-management-derive-vm-v2` passes storage-anchor, storage-mapped
and approved with SecureBoot=1, SetupMode=0 and WITNESS/INVARIANTS. The maintained
verifier binds all three cases and 108 files. Summary receipt:
`/usr/obj/usr/src/security-qualification/bip-management-derive-validation-v1.json`.
The first VM run rejected a test recipient's reuse of a previously installed
software token; it remains a failed historical attempt. The passing test uses
an independently issued token and exercises capability-mode derivation before
actor admission. Its recipient has no broad grant that could mask failed scope
checks. The runner requires the derivation marker exactly once and rejects
missing or duplicate evidence. This is mechanism qualification only.

This primitive does not yet admit actual BSDFilesystem workers or the reaper.
The last real-service result remains provider-ready followed by `EPERM` on the
first legitimate client open. Next work must bind selected held scopes to an
independently observed worker invocation and lifecycle, then integrate separate
data admission. Do not substitute the provider's broad grant for that work.

### Selected worker namespace views (2026-10-20)

The provider now prepares an explicit namespace view from the manager-stamped
container, group memberships and resource owner before forking a BIP filesystem
worker. Selection covers unit/shared/group persistent and cache roots plus the
current boot-owner root. It validates the complete selection before ZFS work,
deduplicates identical selections, and closes acquired handles on partial
failure. Empty namespace roots may be provisioned at connection time, including
for a later readonly request; this does not create claims or permit readonly
claim creation. Newly created empty roots are not destructively rolled back on
partial acquisition failure, since another connection may already use them.

`worker_namespace_open` is now the common acquisition path for claim requests,
listing, stat/quota/destroy/release, versioning, transactions and ephemeral
cleanup. Under BIP it requires an exact namespace kind/name entry and derives a
fresh handle from that selected object. Missing entries never fall back to
walking the provider's broad ancestors. The stat path retains its narrower
`ZH_PROPS_READ` native rights. The child closes its inherited persistent,
ephemeral, boot and lease parent handles and clears their descriptor slots;
backend availability is separate metadata, so closed descriptor numbers cannot
later refer to unrelated reused descriptors. The provider closes its own view
copy after fork; the worker retains its own handles. OES/path-open policy is a
separate interface and is not claimed covered by these ZFS namespace views.

This is namespace plumbing, not a new authorization mechanism. The selected
handles still require independent invocation-bound management grants, and data
access requires separate data grants. Broad root grants have not been added.
Authenticated session/lease namespace selection is unfinished: BIP BeginSession
explicitly returns `EOPNOTSUPP`, rather than using a client-supplied session string
to traverse the global ephemeral root. Legacy non-BIP session handling remains
available, including the previously tested transactional replacement fix.

The provider and maintained tests build through the existing buildenv targets;
no alternate build or repository path was introduced. The namespace suite reports
38 passed, 2 skipped, 0 failed. Skips require host root or descriptor-hardening
syscalls absent from the host kernel. The new request-level regression uses a
real failing ioctl target to prove that BIP missing-selection rejection occurs
before any broad-parent access, for boot/lease opens and unit/shared listing.
It does not prove positive access to a real selected dataset.

The real-service Secure Boot run `bip-worker-view-service-v1` remains **FAIL**:
the provider reaches readiness, then the first legitimate client open fails
`EPERM`; later storage checks are unexecuted and the reboot case is skipped.
All bound input hashes were verified when recording
`/usr/obj/usr/src/security-qualification/bip-worker-view-validation-v1.json`.
No new service or installed-system acceptance is claimed. Next: manager-held
worker nomination/admission, direct stamped worker identity and process-exit
observation, scoped management grants, separate data grants, and lifecycle tests.

### Direct worker management admission (2026-10-20)

SwitchBoard now implements a separate storage-worker nomination/admission flow.
The original provider invocation submits selected held namespace descriptors and
an operation mask on its authenticated control channel. That opcode alone allows
these attachments; other control RPCs still reject attached descriptors. The
manager derives narrowed issuers from the provider launch's retained boot-policy
issuer. Kernel derivation checks live ancestry and the independent operation,
property and lease ceilings. Preparing a worker issues no actor grants.

The reply carries one admission endpoint, restricted by libservice against
forwarding and exec and to a single fork. After process protection and removal
of inherited control authority, the worker sends a restricted `pdself` descriptor
on that endpoint. Software identity, process identity and execution nonce come
from the direct kernel-stamped message, never numeric request fields. The manager
rejects the original provider process, foreign software/launch records, mismatched
process descriptors, exited processes and processes outside capability mode.
A held live process descriptor pins the checked process lifetime; exec after the
message independently invalidates grants bound to its earlier nonce.

The manager installs an exit watch before issuing invocation-bound management
grants for the selected scopes. Controls remain in SwitchBoard; workers receive
no issuer/grant descriptors. A rejected admission closes all partially issued
grants before replying. Success ends the admission transport after the reply is
flushed; its endpoint is not retained as an authorization lifetime witness.
Worker exit closes the controls through the process-descriptor event. Provider
record revocation closes pending/admitted worker records. Manager exit closes
its descriptors. Retained process descriptors are restricted to identity/event
rights and locked against transfer, fork and exec. These lifecycle paths are
implemented, but their complete adversarial VM qualification remains outstanding.
There is no new claim of synchronous draining for management operations.

The wire interface bounds one nomination to 16 scopes; SwitchBoard bounds pending
plus admitted workers to 4096 and checks its descriptor budget. These are resource
bounds, not namespace policy. Original provider code remains trusted to select
namespaces from the manager-stamped client assignment. This flow does not yet
bind an independent client authorization/session record to data issuance. A boot
ceiling requiring an additional authorization lease rejects the current flow;
no arbitrary deadline or implicit lease is created to satisfy it.

BSDFilesystem now nominates the prepared namespace view before fork, consumes
admission in the protected worker, and only then starts handling requests. The
worker requests its supported management verbs. The VM deployment input
`provider-worker-management-policy-v1.ucl` explicitly supplies those verbs and
retains typed property ceilings, including refquota from 1 MiB through 1 GiB.
This is a fixture policy input, not a compiled daemon exception or a replacement
for production policy. Native clone/stream verbs remain outside the supported
BIP management ceiling.

The maintained bootstrap build passes with the matching libservice installed
into its normal object-tree sysroot. The runner binds the new event-dispatch and
authority headers as inputs. The client/observer protocol is version 8: root
nomination denial and successful unit/shared/authorized-group listing are
separate evidence fields. The host parser requires each success marker exactly
once and rejects missing, duplicate or invalid values; all 39 runner/evidence
tests pass.

Both real-service VM attempts reached successful worker management. Latest run:
`bip-worker-admission-service-v2`. Two workers were admitted with seven scopes
each, and the client successfully listed its unit, shared and authorized group
namespaces. Core/UID-zero nomination without a storage assignment was denied.
The overall run remains **FAIL**: the first file-data open returns EPERM, later
retained-data and namespace checks are unexecuted, and reboot is skipped. The
observation receipt verifies 183 input hashes plus retained VM artifacts; summary:
`/usr/obj/usr/src/security-qualification/bip-worker-admission-validation-v1.json`.
This is successful real-worker management evidence, not full service acceptance.

Next requirements:

- Qualify foreign/exited process descriptors, replay, post-exec and fork denial,
  partial admission failure, worker exit, and provider/manager loss in VMs.
- Add independently authorized data issuance for newly created claims. The
  current exact-dataset data factory remains bootstrap-only and requires an
  exact reservation; management permission must not be converted into data
  permission. Bind client grants to direct trusted client evidence or a
  manager-owned connection record, not worker-forwarded PID/nonce claims.
- Complete authenticated session namespace replacement and separate cleanup
  authority; then pass the unchanged functional/retained-descriptor/reboot gate.

### Terminal worker admission rejection (2026-10-20)

A follow-up ownership review found that rejected admission released grants and
issuers but retained its process descriptor/exit watch while the reply drained.
The callback also failed to exclude an already rejected record at entry. Another
valid-looking queued request could therefore re-enter admission and replace the
stored process descriptor. Rejection now immediately releases the process
descriptor (which removes its exit watch), clears admitted state, and resets
owned descriptor slots. The callback rejects admitted, rejected and dead records
before taking another request descriptor or installing another watch.

The maintained `worker_cleanup_test` exercises the actual broker cleanup code.
The pre-fix descriptor-preservation test failed two assertions; after the fix,
three native tests pass without skips:

- Rejection releases all owned controls immediately. Repeated rejection and
  final cleanup leave unrelated descriptors occupying reused slots intact.
- Parent revocation removes only matching issuer/identity records and preserves
  another parent's records and descriptors.
- The actual admission callback is driven through second-scope issuance failure,
  followed by a valid-looking queued request before reply flush. No second
  descriptor is consumed, process watch installed, or issuance attempted.

The callback test uses deterministic transport/kernel doubles and real pipe
file descriptors for ownership checks. It does not prove the kernel metadata,
grant revocation, process-exit delivery, or queued transport semantics. VM
qualification of those failure/lifecycle paths remains required. The broker and
maintained tests build through the ordinary source targets. Receipt:
`/usr/obj/usr/src/security-qualification/bip-worker-cleanup-validation-v1.json`.
No new VM run or full-service acceptance is claimed for this fix; the latest
real-service evidence remains successful management listing followed by denied
file-data access in `bip-worker-admission-service-v2`.


### BIP data-scope prerequisite

The storage-anchor case now requires the data-scope marker as well as existing
storage checks. Under MAC ABI 27 it derives data authority for a live child
without an exact reservation, verifies real first-mount write/read and fork
denial, and verifies parent-factory-close revocation of retained data access.
Scope factories cannot issue actor grants or convert management authority into
data authority. The fixture also checks movement: exact data grants follow the
object, while new derivation through a scope moved outside its ancestor ceiling
is denied. A separate dataset retains exact bootstrap-factory validation.

Latest bounded evidence: `bip-data-scope-vm-v2`, three cases PASS, 110 files checked
by `verify_evidence.py`. This does not qualify the real provider's client data
admission, normal installed startup or upgrades. Build through the existing
storage/observer targets used by build-bsd; the observer must match MAC ABI 27.


### Current invocation observation gate

The approved case requires INVOCATION_CURRENT_PASS from the PID 1 fixture.
It exercises issuer/token ownership, fixed request fields, observed process/exec
identity, descriptor rights, a foreign process, revocation and exit. A handshake
forces successful re-exec before installing the process watch; the old invocation
must fail and the newly observed invocation must pass. The fixture obtains child
descriptors with pdfork: ambient post-exec acquisition remains prohibited.

build-bootstrap.sh now rebuilds secureboot_init as well as service components.
The full build-bsd flow still builds EFI probes using its selected loader object
tree. A source hash alone does not establish that a binary executed a new test;
the required marker prevents an older invocation fixture satisfying this gate.


### Independent client lifetime for storage grants

`--provider-crash` explicitly selects a separate BSDFilesystem fault build;
build-bsd forwards it only for secureboot-test with filesystem policy inputs.
The normal provider has no crash-hook symbols. The fault build exits the parent
with status 75 during a validated claim-stat request, while its requesting worker
stays blocked. Ordinary process-descriptor and supervisor cleanup must retire
the worker and its grants. No production stop permission or policy exception
is added. The fixture client retains descriptors, requires read/write denial,
reconnects and verifies the original data through the replacement provider.

Completion requires one expected parent exit, two distinct parent PIDs and two
READY events, plus a complete `STORAGE_PROVIDER_RESTART` result. Unexpected exits
remain failures. Fixture wire version is 10. `bip-provider-crash-v2` passes both
boots (212 bound files), and `bip-normal-provider-v10` passes the ordinary pair
(209 files). The evidence verifier independently replays provider assertions;
receipts are `evidence-verification-provider-v2.json`. The frontend plan test
and 53 host tests pass. This is controlled parent-crash recovery, not proof of
every crash timing, client lifecycle or authenticated-session policy.

Session enrollment is an explicit input: run.py and `build-bsd secureboot-test`
accept `--session-policy FILE`. The assembler copies those bytes into the signed
root and includes the source in evidence hashes. Without an override, baseline
and native session fixtures use the checked-in files under `session/`; role
assignments are no longer embedded in Python. This option does not launch an
authenticator or authenticate a human by itself. Invalid-policy cases still
deliberately replace the policy with their named negative fixtures.

`bip-session-input-service-v1` passes both creation/recovery boots with explicit
`sessions=[]` input, verifying two cases and 209 files. The staged policy matches
the input byte for byte. This qualifies independent managed-service access and
the input pipeline, not positive authenticated-session storage. The build-bsd
plan test passes with forwarding and wrong-action rejection; 50 host tests pass.

The provider fixture now retains delivered file and directory descriptors across
claim release and requires read/write/lookup denial in all four scopes, before
reacquisition. `STORAGE_AFTER_RELEASE` supplies all 12 operation results; missing,
duplicate, successful or EBADF results cannot satisfy completion. Both boots of
`bip-release-service-v1` pass with EPERM and subsequent authorized reopen/data
recovery; two cases and 208 files are verified. That run used fixture wire version 9. The
48 host assembler/runner/evidence tests pass. This tests subsequent admission,
not an in-flight I/O drain guarantee.

Earlier real-provider baseline: `bip-provider-claims-service-v3` passes both
creation and recovery boots; `verify_evidence.py` verifies two cases and 208
files. The provider uses broker policy-ceiling queries and exact claim grants,
retaining grant IDs with dataset anchors. Four explicitly authorized managed
service scopes persist across reboot. Fork/clear probes deny retained file I/O
and namespace/metadata operations. The truncate wrapper now tracks synchronous
completion while retaining the independent truncate permission check.

The test inputs are `provider-service-claims-policy-v1.ucl` and
`provider-service-claims-access-v2.ucl` under the qualification directory. They
explicitly select service-owned state without a human lease; the original
mandatory-session fixture is unchanged. Software names use bundle-ID/unit,
while this implementation's namespace layout uses installed bundle-name/unit.
These are test inputs, not production defaults. This fixture still substitutes
an /etc/rc probe and does not prove normal installed startup, SSH, provider
restart, upgrades or authenticated-session authorization. build-bsd's maintained
bootstrap build already rebuilds the affected provider and libraries.

The storage-anchor fixture uses separate client and worker processes. It issues
BIP_STORAGE_ISSUE_FOR_CLIENT through a real resource ceiling and session lease,
then keeps the worker's file and grant open across client clear, exit, successful
exec, software revocation and session-owner loss. Each transition must deny later
retained I/O. Fork/child exit, failed exec and closing the observer's process
descriptor must preserve an otherwise live invocation. Invalid identities,
foreign descriptors/tokens, restricted descriptor rights and missing mandatory
leases must fail issuance. The required BOOT_STORAGE_CLIENT_DEPENDENCY_PASS
marker appears only after the checks complete. This is a kernel mechanism gate;
it does not demonstrate broker resource authorization or full-service operation.
# Session-storage qualification

`bip-revoke-failure-regression-v1` passes the lifecycle case after fixing ignored
kernel token-revocation errors in the broker; 214 files verify. Eight native
broker cleanup tests include failure injection that requires issuer closure and
broker termination. Those doubles are not VM proof of issuer-triggered
revocation while a client and its independent session remain live; that gate
is still outstanding. Normal lifecycle behavior remains covered by the VM run.

`provider-lifecycle/` now builds a separate observation provider from the normal
provider sources. Conditional hooks monitor real worker-held storage after a
positive access check and collect records over a parent pipe. Worker teardown
waits for this bounded observation before releasing mount anchors. Production
builds contain none of these hooks. The bootstrap builder builds the fixture;
the observation endpoint now accepts read-only queries from the authenticated
test controller. Its embedded profile is derived from the production manifest
using the strict UCL normalizer, adding only `test.StorageLifecycle`.
Consumer queries, image selection, runner/frontend selection and evidence replay
are connected in version 5. `bip-worker-lifecycle-v1` passes its Secure Boot VM
case with 214 files verified. The controller checks positive provider access
before allowing the exact kernel-stamped client invocation to exec or exit.
The new executable stays alive until exec-related denial is observed; exit is
tested separately. Both require EPERM/EACCES on the provider's held read/write/open
operations. Use explicit `--provider-lifecycle` with the three principal and
policy inputs. The mode excludes `--provider-crash`. All 58 host tests, two
profile tests and the rebuilt frontend forwarding test pass. Issuer revocation
and normal login/su/SSH remain unqualified.

**Historical failed approach (version 4).** The successful
exec probe reaches the new signed image but fails its descriptor-presence check:
provider delivery uses enforced close-on-exec. `bip-client-exec-v3` is a failed
qualification run, not a retained-grant revocation pass. Version 5 uses a
provider-side observer; descriptor hardening stays intact. Historical
version-3 passes below cover their stated scope only. EBADF never satisfies
the provider-held access denial checks.

`session-storage/session_storage` is a test-only enrolled issuer, never a human
authenticator. `session-storage-observer/session_storage_probe` accepts three
principal names (two authorized, one enrolled without storage permission) and
reads the image's `/etc/storage-test-challenge`. Both are built by the maintained
bootstrap script. The assembler selects them with `session_storage_principals`
and requires explicit storage, filesystem and session policy inputs. The runner
accepts `--session-storage-principals AUTHORIZED_A AUTHORIZED_B DENIED` and
selects the separate `capsule-session-storage` case. `build-bsd secureboot-test`
accepts `--storage-principal-a`, `--storage-principal-b` and
`--storage-principal-denied` alongside the policy inputs. This single-boot mode
does not claim cross-boot recovery or permit the controlled-crash provider.

The fixture requests real broker sessions, explicitly connects through each
ambient route, and uses the production filesystem FIDL transport. Its checks
cover principal-specific denial, retention of channel identity across route
changes, independent live sessions, and read/write/open denial on held
descriptors after each final logout-lease close. Mandatory lease requirements
must remain enabled when qualifying this path. Signed session enrollment and
filesystem access policy must be supplied as inputs; the program creates
neither policy nor synthetic kernel grants. Runner completion and evidence
replay require all six retained-access denials and the challenge-bound success
marker. `bip-session-storage-v2` passes in a Secure Boot VM, with 44 fixture
checks and 209 bound files verified. All 58 assembler/runner/evidence host tests
and the rebuilt frontend forwarding plan pass. The original v1 run was stopped
after discovering a runner case-classification omission and is not a pass.
Normal login, su and SSH are not qualified by this test-only issuer.

The version-2 fixture also checks duplicate logout-lease references and expiry:
closing one duplicate must preserve access, and holding the final lease open
must not extend its deadline. `bip-session-expiry-v1` passes in a Secure Boot
VM with 209 files verified. Serial acceptance requires three additional
`SESSION_STORAGE_EXPIRED` denials (read/write/open); successful access, EBADF,
missing results and duplicates are rejected. Polling is bounded, and the
assertion count varies with timing. No exact expiry latency or I/O-drain claim
is made. This runs through the existing session-storage mode and policies.

Version 3 additionally admits a child through a fresh real-provider connection,
proves read/write, then clears that child's software authority while the parent
keeps the session lease live. It requires three `SESSION_STORAGE_CLIENT_CLEAR`
denials on held descriptors; the parent receives the observations through a
pipe. `bip-client-clear-v1` passes in a Secure Boot VM with 209 bound files
verified and 58 host tests passing. This is stronger than clearing authority in
a child already denied access to its parent's grants. It does not yet qualify
provider-side retained access after client exit or exec, or token revocation.

Version 5 requires the separate `--provider-lifecycle` fixture. Its actual
provider workers retain independent descriptor witnesses, report successful
initial operations and subsequently report read/write/open authorization errors
after client exec or exit. For exec, the new executable remains alive until the
controller has observed the denials. Client descriptors closed by exec are not
accepted as evidence of access revocation. The controller checks kernel-stamped
client identity and execution nonce, worker identity and observation ordering.
The runner requires all `SESSION_STORAGE_WORKER_AFTER_EXEC` and
`SESSION_STORAGE_WORKER_AFTER_EXIT` results as well as logout, expiry and clear
results. See system-security.md for the distinct scope of each retained run.

`bip-session-route-v1` additionally exercises the existing private lookup
registration protocol before the clear test. The original issued route is
non-forwardable; a newly registered route preserves its session association and
can be delivered to the child. The child drops inherited route references and
clears its lookup slot before receiving that endpoint. Mandatory-lease storage
operations succeed through the delivered route before software clear makes held
access fail. The full case passes with 214 files verified. Build integration
uses the existing session-storage target and options. Separate managed-client
token revocation, normal installed boot and human authentication remain open
gates; this test does not qualify them.

Version 6 adds the separate `session-revoke` managed actor to this case and
requires six additional `SESSION_STORAGE_CLIENT_AFTER_REVOKE` and
`SESSION_STORAGE_WORKER_AFTER_REVOKE` observations. Its explicit filesystem
policy needs a session rule for `test.SessionRevoke/client`, namespace
`SessionRevoke/client/persistent`, using the enrolled controller's issuer and
authorized principal. The builder does not manufacture this permission.
The initial `bip-session-revoke-v1` run failed: a pending blocking receive kept
the actor's control channel alive after its descriptor was closed.
`bip-session-revoke-v2` instead uses the existing instance-termination ioctl
while retaining libservice's descriptor ownership. It passes with 221 evidence
files verified: the client and worker lose held-object access, the controller's
same-session connection remains usable, and a fresh actor response precedes
permission to exit. This is scoped asynchronous token-revocation evidence, not
general in-flight I/O draining or installed-system qualification. Version-5
successes do not satisfy the new acceptance requirements; consult
system-security.md for current evidence.

### Configuration-driven boot attachments

Run `--case storage-attached` with an explicit `--storage-policy` whose single
storage entry includes `attachment`, plus the matching `--storage-disk`. The
slot must already be an empty immutable directory in the fixture image (the
qualification input uses `/scratch`). The runner copies the supplied policy
unchanged; it does not insert attachment policy or infer a production path.
This case cannot be combined with provider cases requiring anonymous mounts.

The actual PID 1 fixture calls production `protected_storage_prepare`, verifies
mounted identity and noexec/nosetuid flags, rejects a changed boot policy,
checks anonymous-mount EBUSY, creates disposable test content, exercises
invocation-bound access and revocation, and checks mount persistence after
consumer descriptors close. Acceptance requires its own exact markers and
normal guest shutdown; helper-only storage-anchor evidence cannot substitute.
`bip-attachment-policy-v2` passes with 115 files independently verified.
The first run's guest passed, but the verifier lacked the new case dispatch;
that rejected result is retained. All 61 runner/assembler/verifier tests pass.
Failure cleanup and normal service startup remain separate qualification gates.
No build-bsd flag is needed: the existing installation-policy transport carries
Capsule configuration as explicit input. Package mapping is still unfinished.

The historical `storage-attachment-failure` case has been retired with Capsule's
BIP-only immutable provider-policy input. Its earlier results do not qualify the
current system. Ordinary import/mount cleanup needs independent qualification
without BIP reservations or the removed provider-policy handoff.

### Exact ordinary-content classification

The storage-anchor fixture now requires `BOOT_STORAGE_ORDINARY_PASS`. Original
PID 1 explicitly classifies a test dataset, then ordinary root and uid 65534
perform file I/O, shared mmap and file creation/removal without actor grants.
An unclassified child remains inaccessible; storage management and changing
classification remain denied. Snapshot and volume assignments are rejected.
The second MAC test policy vetoes a proposed assignment; retained descriptor
reads remain denied after that veto. The test retains the same mount through
rejection and subsequent successful classification.

`bip-ordinary-content-v4` passes with 115 files verified. v3's fixture attempted
a second anonymous mount and failed EBUSY; that result remains retained. This
is kernel mechanism evidence. Capsule's content-policy wiring still needs its
own VM test. The test-only dataset names are not production classification rules.


### Configuration-driven ordinary writable attachment

Run `--case storage-ordinary` with an explicit `--storage-policy` whose storage
entry has `content: "ordinary"`, the real dataset identity/device and an
attachment. The runner transports that input unchanged through the authenticated
fixture image. It uses production Capsule configuration and preparation code.
No ordinary provider handle is published.

The fixture checks exact filesystem identity and noexec/nosetuid flags,
immutable boot policy, and fresh path access from root and uid 65534 without
inherited data descriptors or storage grants: read/write, shared writable mmap,
and create/remove. Root unmount and configured backing-device writes must fail.
Consumer descriptor closure must preserve the mount and its flags.
Acceptance requires the distinct `BOOT_STORAGE_ORDINARY_POLICY_PASS` record,
preparation and completion records, clean shutdown, and no failure/panic/WITNESS
records. The independent verifier rejects ordinary-anchor evidence substituted
for this case.

`bip-ordinary-policy-v1` passes with one case and 115 independently verified
files. All 65 runner/assembler/verifier tests pass. This is writable-state
attachment qualification, not normal installed startup, executable third-party
installation, general mount/NFS compatibility or upgrade acceptance.

The follow-up `bip-ordinary-policy-v2` adds root tmpfs mount-over and ZFS
remount attacks (exec/setuid and read-only requests). Each must return EPERM,
with subsequent ordinary root/user writes succeeding and mount flags unchanged.
Its expanded marker includes `mount-mutations-denied`; one case and 115 files
are independently verified. The initial fixture build caught discarded const
qualifiers in iovec buffers; the corrected mutable-buffer build passed.


### Remount MAC dispatch

The storage-anchor case now requires
`BOOT_STORAGE_MOUNT_DISPATCH_PASS once original-options`. A disposable MAC
observer enabled by original PID 1 counts remount callbacks and rejects a NULL
option list. A successful bootstrap remount must produce exactly one callback
with options present. Observation is disabled before the existing root-denial
checks. This catches the former second invocation with NULL without permitting
any operation denied by another MAC policy.

`bip-mount-dispatch-v2` passes the full storage-anchor regression with 115 files
independently verified; 65 host harness tests pass. v1 stopped before boot after
a staging command followed symlinks; v2 preserves them. No ordinary mount or NFS
permissions were broadened by the VFS dispatch correction.


### Ordinary local file-handle access

The storage-anchor case requires `BOOT_STORAGE_HANDLE_PASS` after real getfhat,
fhopen read/write, fhstat/fhstatfs, fhreadlink, fhlinkat and AT_EMPTY_PATH linkat.
Bootstrap supplies known handles to both protected and unclassified datasets;
root must fail each protected operation while equivalent ordinary operations
succeed. Nonroot callers retain the native privilege denials. The approved case
separately retains immutable-root getfh/getfhat and known-handle denial checks.

`bip-filehandle-v1` passes both cases, with 120 files independently verified.
MAC ABI 30 requires matching rebuilt kernels/modules. A source-edit placement
error was found and corrected before the qualifying VM; no acceptance is claimed
for the earlier build. These are local syscall tests, not NFS service acceptance.

The maintained frontend accepts `build-bsd secureboot-test --test-case NAME`
with the usual explicit root/storage/policy inputs. For example, select
`storage-ordinary` with an ordinary attachment policy. Omitting the option
retains complete-suite verification; specifying it produces partial-case
evidence and cannot establish a full-suite pass. The runner owns case-name and
input-combination validation.


The storage-ordinary case also runs an unsigned static application copied into
the actual ordinary attachment. Both root and UID 65534 use execve and fexecve
without inherited storage handles. The application checks ordinary file I/O,
nosuid suppression despite a root-owned setuid bit, immutable policy write denial
and unmount denial. The new BOOT_STORAGE_ORDINARY_EXEC_PASS marker is mandatory.
Capsule selects exec,nosetuid for ordinary state and noexec,nosetuid for protected
state. bip-ordinary-exec-v1 and bip-ordinary-exec-protected-v1 passed with clean
shutdown and independent evidence verification. Dynamic dependencies, protected
authority transitions and full third-party package lifecycle remain separate gates.


storage-ordinary additionally requires BOOT_STORAGE_ORDINARY_DYNAMIC_PASS.
Its dynamically linked program loads the private copied library by name, path
and fdlopen, runs its symbol, and verifies the selected object's identity. Name
and pathname routes use dladdr plus device/inode; fdlopen has no loader pathname
and instead checks the descriptor identity. The program still tests nosuid,
ordinary writes and protected-operation refusal as root and nonroot through both
exec interfaces. assemble_rtld derives the actual interpreter/dependency closure
from the selected ELF and rejects a static substitute.

bip-ordinary-dynamic-v1/v2 failed the test's invalid fdlopen pathname assumption;
retain their failure evidence. v3 passed storage-ordinary and approved (privileged
loader regression), both with clean shutdown; independent verification checked
two cases and 125 files. This does not qualify private DT_NEEDED startup paths,
package updates, protected-authority exec transitions or a full installed system.


storage-ordinary now also requires BOOT_STORAGE_ORDINARY_STARTUP_PASS. The
ordinary_startup_probe has a real private DT_NEEDED dependency and calls its
symbol, checking the loaded object's device/inode against the writable copy.
Both users and exec interfaces run with LD_LIBRARY_PATH selecting that copy.
The assembler rejects a missing dependency. build-bootstrap.sh builds the
fixture library before storage; Makefile LDADD/DPADD bind the selected object.
bip-ordinary-startup-v1 passed ordinary and approved cases with clean shutdown;
independent verification checked two cases and 127 files. RPATH/RUNPATH coverage,
real package lifecycle and full installed startup remain unqualified.


storage-ordinary additionally requires BOOT_STORAGE_ORDINARY_AUTHORITY_PASS.
The real kernel constrains/registers the immutable parent image; the issuer checks
its stamped software/process/nonce before granting protected file access. Failed
exec preserves that access. execve/fexecve into the unsigned ordinary copy must
invalidate software authority and deny protected I/O on still-open inherited FDs,
while ordinary I/O remains usable. The issuer retains the grant until completion.
bip-ordinary-authority-v1 passed both ordinary and approved cases with clean
shutdown; independent verification checked two cases and 130 files. This is root
software/data-grant transition coverage, not human authentication, arbitrary
capability transfer, normal installed services or package lifecycle acceptance.


### Retired BIP service identity snapshots

The BIP account snapshot loader, compiler and `--service-identities` input
have been removed. SwitchBoard resolves service accounts and socket ownership
through ordinary NSS. The assembler no longer requires or installs an account
snapshot. The `capsule-identities-*` cases and their evidence rules have been retired.
Historical results do not qualify the current system. Other BIP dependencies
in this fixture suite still require removal before using it for acceptance.

## Protected authority and changed roots

The static fixture's process-isolation stage now requires
`RUNTIME_PROCESS_NAMESPACE_PASS`. With a registered executable, two separate
children change root to an existing immutable image directory: one must lose
valid authority immediately; the other executes the same pinned static image
with fexecve and must not acquire authority in the substituted namespace.
Each child first verifies that ordinary chdir and a failed chroot preserve
valid authority. The selected root is an explicit fixture argument; this is not
a production path-protection list. Closing issuer/token descriptors in the
children leaves only the registered-image acquisition path under test.

These regressions are pending kernel remediation and guest execution. A strict
C syntax check passed; no runtime result is claimed. The runner requires the new
markers, so an older fixture cannot supply a qualifying result. Two additional
workers exercise rfork with shared and copied roots: the child changes root,
then the parent checks both its actual root identity and authority validity.
Shared roots must invalidate both processes; copied roots must preserve the
unchanged parent's authority. waitpid orders observations after the transition;
the child does not close shared descriptors. The runner additionally requires
`RUNTIME_PROCESS_NAMESPACE_SHARING_PASS`.

All four scenarios are pending guest execution. ABI roots, concurrent
transitions, approved sandbox launches and protected-storage invocation
revocation still need separate coverage. This fixture does not establish
whole-system or dynamic-loader acceptance.

## Native System authorization regression

Run `make -C /usr/src/tools/test/secureboot system-authorization-test` to check
the three System permission functions against cached invalid authorization,
a later valid entry, invalidation and caller mismatch, with BIP enabled and
disabled. The test compiles those functions from current kernel source and
uses explicit kernel seams. It does not test real lease timers, revocation
concurrency, lock order or installed-kernel behavior. VM qualification remains
required; this target does not launch a VM.

The guest System gate fixture additionally requires successful authorization
before testing software authority revocation and clearing while token descriptors
remain open. Its `SYSTEM_GATE_AUTHORITY_PASS` marker is required by the boot
case. This fixture checks the ordinary sysctl path and a separate service
connection, in addition to the bound token ioctl. It does not use a lease:
`CAP_AUTH_LEASE_BIND` supports direct message channels, not System tokens.

Repeated System activation is also covered by the native target: the same nonce
succeeds, a different nonce receives EALREADY and must obtain a fresh token.
The guest fixture re-execs with the token open to check this distinction and
requires `SYSTEM_GATE_REAUTHORIZE_PASS`. Native coverage uses kernel seams;
the guest regression must run before claiming real fork/exec verification.

The storage client-dependency fixture also requires worker read/write denial
after its separate client changes root and loses current software authority.
The worker retains its grant and file descriptors. This scenario was added for
an unresolved namespace/dependency revocation gap and has only been syntax
checked during the VM hold; do not record it as a passing guest regression.

### Process-title compatibility coverage (2026-10-21)

The integrity fixture checks numeric `kern.proc.args` self-writes for root,
an unprivileged process and an unprivileged process in capability mode. Outside
capability mode it reads back the exact bytes. Root must still receive EPERM
when attempting to change its parent's title. The kernel definition classifies
this self-scoped operation as ordinary; its handler retains PGET_ISCURRENT.
These new guest assertions have passed syntax checking only and await VM
execution. They do not establish SSH or general daemon compatibility. Source
evidence includes `sys/kern/kern_proc.c`; normal kernel/fixture builds apply.

### Native sysctl boundary regression

Run `make -C tools/test/secureboot sysctl-policy-test` from the source root.
It compiles the current BIP sysctl policy function with simulated kernel
structures and bootstrap state, using current header constants. Assertions
cover unknown/ANYBODY write denial, exact NAME2OID identification, absence of
inherited ordinary classification, and ordinary/read/bootstrap decisions.
This does not execute kernel privilege checks, handlers or guest workloads.

### Simplified clock administration

The System fixture now expects ordinary root clock APIs to work before any clock
gate is claimed, while self-issuing System authority remains denied. With an
explicit clock claim, foreign raw writes remain denied. The native
`system-authorization-test` exercises the actual privilege-dispatch hook with
simulated credentials/claims. Guest clock calls are prepared only; they must not
be executed on the host. These assertions supersede older blanket-clock-denial
expectations. No full service or NTP qualification is implied.

### Ordinary accounting coverage

The System fixture prepares a disposable-guest test of ordinary root accounting
start/stop, a recorded worker exit, disk-space threshold/check-interval
read/write/restore, rejection of a zero check interval, and unprivileged control
and tunable-write denial. It is called
by the required System test and emits SYSTEM_ACCOUNTING_PASS only after success.
Native System tests cover unclaimed, capability-mode and explicitly claimed
accounting decisions. Guest execution remains pending; never run these global
accounting operations on the host as a substitute for VM qualification.

### Native reboot boundary checks

`system-authorization-test` extracts both the System reboot admission hook and
BIP's reboot hook. It checks ordinary unclaimed allowance, capability-mode and
explicit-claim denial, and retained RB_REROOT denial (alone and combined with
poweroff). It never calls reboot. It does not replace an installed guest's
shutdown/reboot and verified boot-environment activation tests.

### Native mount cleanup boundary

`make -C /usr/src/tools/test/secureboot mount-policy-test` compiles the actual BIP
mount admission functions and dounmount's early capability-release guard with
simulated structures. It checks that the last-anchor exception requires an
anonymous, uncovered, non-root mount and rejects recursive teardown while
releasing the rejected call's mount reference. Ordinary callers still receive
no general mount/remount/unmount permission from this test. No kernel teardown,
user syscall flag rejection, mount operation or concurrency is exercised.
The broad BIP mount restrictions remain under review for simplification.

### Native manager image binding

Run `make -C /usr/src/tools/test/secureboot manager-image-test`.
The actual Capsule helper is exercised with real directory/file descriptors and
fexecve, while root ownership and BIP mount metadata are simulated. Rejected
paths include symlinks, noncanonical components, writable ancestors, wrong
ownership/mount flags and scripts. Replacement after open must still execute
the original ELF, with its descriptor closed across exec. Failed validation
must not leak descriptors. This does not qualify authenticated mounts, complete
Capsule startup, dependency loading or restart. Normal-mode pathname execution
remains unchanged. VM checks remain on hold.

### Manager descriptor handoff before constructors

`make -C /usr/src/tools/test/secureboot manager-handoff-test` builds two small
native programs and uses the applied Capsule helper with an ordinary temporary
file descriptor. The launcher sets CLOFORK_LOCKED and CLOEXEC_ONCE after remapping.
The first exec consumes ONCE in the kernel. A constructor checks that the handle
exists, both locks resist downgrading, a forked child lacks the descriptor, and a
second exec closes it. The constructor also makes aliases with dup, dup2,
F_DUPFD and F_DUPFD_CLOEXEC, clears their ordinary descriptor flags, and verifies
that none can escape through fork or exec. An unrestricted control descriptor
must survive both transitions. An invalid descriptor must fail preparation. The running
kernel and libc must support the existing confinement syscalls; failure is not
silently skipped. No issuer, service or production descriptor is used.

This proves a native descriptor propagation boundary, not authenticated manager
startup or safe dependencies. A hostile constructor could still use its own
held handle; interpreter/library enforcement remains necessary. Capsule applies
this to every mapped manager delegate. Console stderr is not a manager delegate
and retains its intended diagnostic inheritance. SwitchBoard retains startup
checks as defense in depth. Normal build-bsd world builds consume the helper;
no new frontend input or security policy format is introduced.

### BIP initial-process code admission

`make -C /usr/src/tools/test/secureboot init-code-test` compiles the actual BIP
exec hook with simulated vnode, process, mount and attribute inputs. It checks
PID 1 initial executable/interpreter admission on read-only root; rejection of
writable/foreign/no mount, wrong ownership/type and unsafe write permissions;
continued PID 1 re-exec denial; ordinary-process allowance; and storage-error
propagation. This does not run kernel exec or boot an image. Real interpreter
brand/fallback, initial startup and ordinary exec pairing still need guest tests.

### PID 1 loader policy selection

`make -C /usr/src/tools/test/secureboot init-loader-test` compiles the actual rtld
startup selector and policy initialization with simulated PID, credential taint
and sysctl responses. It checks BIP PID 1 restriction without a credential
transition, preserved normal-mode behavior when the BIP sysctl is absent,
ordinary tainted-process environment filtering without selecting BIP solely for
a credential transition, explicit BIP image marking, and fail-closed malformed
or failed policy reads for selected images. The matrix covers 84 combinations.
This does not execute rtld, map libraries or exercise constructors in a BIP guest.
PID 1 now receives existing immutable loader-policy/library checks before loader
environment processing. SwitchBoard selection remains a separate open issue.

### Ordinary dataset observations

`make -C /usr/src/tools/test/secureboot storage-observation-test` compiles the
actual admission prefix before delegated-grant evaluation with simulated
identity, reservation and classification state. It checks the complete operation
bit space: only INFO, STAT, GET_PROPS, GET_ONE_PROP and same-object DERIVE receive ambient BIP admission for the
exact registered ordinary dataset in a reserved pool. Unknown/zero/mixed mutation
operations, changed identities, pending classifications and property mutations
remain denied by that prefix. Existing unreserved-pool behavior is preserved.
The regression does not exercise delegated grants, ZFS operations or races.
GET_ONE_PROP now reads native properties through dsl_prop_get_ds on the held
dataset. Its separate property-binding-test compiles the changed native-property
branch with simulated ZFS holds/reads, checking string/numeric values, source
classification and balanced release on errors. It rejects a regression to name
lookup. It does not exercise ZFS concurrency or the other property branches.

Ordinary DERIVE admission preserves the held dataset identity and cannot bypass
ZFS rights/operation attenuation. OPENAT, mounting, namespace mutation and pool
operations remain outside this allowance. The existing guest derive_narrows case
now also checks pool/dataset GUID equality and that a derived handle with snapshot
rights cannot recover a snapshot operation removed from the source ceiling.
Those guest assertions are syntax-checked only; VM execution is still held.
This does not complete BSDFilesystem's ordinary-storage protocol simplification.

### Ordinary dataset enumeration coverage

`make storage-observation-test` checks the actual BIP management-admission prefix
with simulated identity/locking state. Ordinary child/snapshot name enumeration
is allowed; mutation masks, pending classifications and mismatched identities
remain denied. The storage guest fixture also exercises both calls as root and
an unprivileged holder, unknown-child denial, and operation-ceiling attenuation.
The runner requires the dedicated `BOOT_STORAGE_ENUMERATION_PASS` marker after
both consumer passes; missing and duplicate markers fail acceptance. Its 37
native runner tests pass. Those guest checks are prepared and syntax-checked,
not executed. This does not
qualify ordinary provider startup or removal of per-client content grants.

### Receive revalidation native check

`make receive-revalidation-test` compiles the actual TrustedZFS receive
revalidation/read helpers with simulated identity lookup, input and locking.
It checks replacement and interruption while the namespace gate is released,
including new receive targets. It starts no VM and provides no evidence of
real ZFS concurrency or inherited BIP boundary enforcement.

### Boundary resolution native check

`make storage-classification-test` exercises the production registry and boundary
resolver with allocation and locking seams, including nearest declarations,
pending/stale identities and missing ancestry. Runtime ordinary access remains
exact-only until mount and namespace lifecycle integration is complete. These
tests do not establish mounted-file behavior or ZFS concurrency.

### Ordinary boundary reparenting

The storage fixture now requires `BOOT_STORAGE_REPARENT_PASS same-boundary
cross-boundary-denied mounted-identity` (one serial line). It tests a mounted
child's rejected escape from its ordinary boundary and accepted move within it.
The existing capability scope-escape assertions remain required. These additions
are compiled but await VM execution; older logs without the new marker do not
qualify current storage behavior. Native classification and ancestry harnesses
cover the policy/helper portions without executing a ZFS rename.

### Replacement identity evidence

The snapshot marker now includes `head-identity`; the stream marker includes
`head-identity snapshot-guids`. Existing content checks remain required. The
fixture checks stable head identities across rollback/incremental receive and
imported snapshot GUIDs on distinct objects. These are compiled assertions, not
executed VM evidence. Neither a stable head GUID nor an imported snapshot GUID
authenticates dataset contents.

### Separate immutable boot policy

BIP Capsule now selects `/boot/capsule.conf`; normal installations retain
`/etc/capsule.conf`. Rebuild and stage the capsule package before running these
fixtures: the assembler requires both supplied files and replaces only the
hardened policy for explicit storage test cases. It does not copy mutable normal
configuration as a fallback. Missing-policy, parser-rejection and immutable-file
checks target the hardened path. No existing VM result qualifies this transition.

The native validation report is format 2 and identifies both paths. The image
backend rejects older reports and still requires the hardened policy to be
immutable. `BSD_BUILD_CAPSULE_VALIDATOR` selects the executable for the image
suite's writable-etc integration check; the ATF `image_validation` case exposes
this as `image_capsule_validator`. This check uses a real selected parser with
synthetic dataset receipts and a disabled manager: it proves placement acceptance
and rejection, not dataset initialization, boot, service readiness or authority.

### Native boot-environment deletion cleanup

`make be-destroy-cleanup-test` compiles the production libbe deletion function
with ZFS seams and checks handle ownership on refusal, promotion/origin errors,
and destroy success/failure. It performs no ZFS operations and is not evidence
of authenticated retirement, atomic selection protection, or recovery. Run it
explicitly; a normal build does not imply this test has run.

The same native target checks snapshot callback open/destroy errors and closes
opened snapshot handles after success or failure. The build-bsd disposable BE
fixture includes real held-snapshot refusal; native success does not imply that
VM case has executed.

Recursive deletion coverage also checks iterator-owned child handles on success
and failure, while retaining the caller-owned top-level handle. A temporary
mutation omitting the child close was detected by the native regression.

### Shared verifier input reads

`make verifier-read-test` compiles the production read_fd/read_file functions.
It checks EOF, interrupted/error reads, overflow and metadata failures with
seams, plus real temporary regular files and nonblocking FIFO rejection. It does
not establish signature acceptance, updater authorization or firmware behavior.

`make signature-path-test` checks the production verify_sig path parser with a
protected memory page before the input string. It rejects short/malformed names
before signer lookup and checks the normal .sig-to-.certs derivation. Certificate
verification is a seam in this test; it is not cryptographic qualification.

`make signature-decode-test` compiles the production RSA/ECDSA control flow with
I/O, PEM-decoder and crypto seams to check allocation ownership and malformed
input rejection. The separate native manifest trust suite uses actual BearSSL
verification and also rejects empty/duplicate signatures; it is not firmware
qualification.

### Native boot-environment activation error checks

`make be-activation-test` extracts the actual libbe activation/deactivation
functions and supplies libzfs test seams. It checks early path-error propagation
and handle cleanup when deactivation fails, without touching a pool or boot
selection. It does not qualify atomic activation, protected updates or recovery.

`make be-clone-test` checks the actual libbe clone entry point with native test
seams: rejected inputs, source-open failure and handle cleanup after callback
success/failure. It performs no ZFS operations and does not prove recursive
clone atomicity or partial-candidate recovery.

The clone target also runs `be_clone_cleanup_test.py`: 20 root/child fault
scenarios check snapshot/property cleanup and iterator-handle ownership using
the actual recursive functions. These native seams do not establish real ZFS
clone recovery or concurrency behavior.

The clone target includes `be_clone_path_test.py` for root component boundaries
and destination buffer limits. Recursive tests also reject truncated snapshot
names before lookup. These checks do not establish concurrent dataset identity.

Clone fault scenarios distinguish an absent child snapshot from a failed
snapshot lookup. A missing root snapshot and child lookup errors must fail;
only an actual absent child snapshot may be skipped. This remains seam-based
qualification, without real-pool concurrent replacement tests.


Recursive filesystem iteration also translates negative libzfs failures to
`BE_ERR_UNKNOWN`, preserving positive errors returned by clone callbacks. The
native cleanup regression now injects libzfs's actual negative failure shape at
both root and child depth instead of a synthetic positive value. All four clone
regression programs passed again, and be.o rebuilt successfully. This prevents
invalid error values reaching the public libbe formatter; it does not make clone
creation atomic or establish completeness under concurrent dataset changes.

Clone property allocation failures now return `BE_ERR_NOMEM` rather than raw
`-1`. The old value reached libbe's error-description switch, which asserts for
unknown codes (or reports "no error" if assertions are disabled). The callback's
only `ZPROP_INVAL` path is a failed nvlist insertion. Existing recursive fault
injection now requires the defined error at both root and child depths and
continues to check handle/nvlist cleanup. All four maintained clone regression
programs passed; the changed be.o compiled in the standard world buildenv with
warnings treated as errors. No real pool or VM was used. Build-bsd deployment
uses the normal bectl/libbe build; no frontend input changes are required. A
linked/rebuilt selected world is still needed before runtime qualification.

`be_clone_property_test.py`, included in `be-clone-test`, checks the real
property callback's insertion failures, local/received copying, mountpoint
adjustment and intentional exclusions. It does not prove real-pool property
read completeness or encrypted dataset behavior.

Property checks also require exact local/received quota strings through the
literal-read API. They model the distinction between display and literal output;
real-pool quota/reservation preservation is still required in VM qualification.

`make be-altroot-test` checks the actual alternate-root initialization block and
mountpoint helper, including short strings against a protected memory page. It
performs no pool import or mount and does not qualify concurrent altroot changes.

`make manifest-registration-test` tests the actual manifest registrar and loader
under allocation failures. It verifies failure propagation, ownership and no
false loaded state using native signature/allocation seams; it is not a signature
or firmware qualification test.

Activation checks include delayed bootfs publication, promotion/open failures
and repeated promotion rounds. They establish call ordering in the real libbe
function through seams, not atomic ZFS activation or recovery after power loss.

The activation target also runs `be_promotion_test.py`, which checks ownership
of iterator-supplied handles through three dataset levels and promotion/iterator
errors. It does not perform real promotion or qualify recovery of partial changes.

`make manifest-lookup-test` exercises actual lookup functions in ordinary and
legacy-prefix modes. It rejects truncated and empty names, checks scan bounds
and retains exact-fit lookup behavior. It does not verify firmware execution.

`make hash-token-test` checks exact digest token boundaries and lengths using
the real renderer/comparison with a hash-output seam. It does not constitute
cryptographic or firmware qualification.

`make stream-completion-test` runs actual streaming read/seek/close functions
with controlled I/O. It requires completion before hash comparison and covers
known/unknown sizes, EOF and errors; it does not boot firmware or test real media.

Streaming tests also simulate counts and hashed offsets above INT_MAX, and
verify that failed backward seeks preserve the tracked position. They use small
buffers and controlled I/O rather than reading multi-gigabyte files.

Streaming tests include checked relative-offset conversion, negative/empty-file
bounds, unsupported unknown-end offsets and valid relative seek sequences.
Rejected requests must perform no backend I/O or offset update.

The stream test includes the actual open function and checks rewind, prefix
hashing, invalid offsets and successful zero/interior/end initialization. On
failure the context is released; descriptor ownership stays with the caller.

`make direct-verifier-io-test` checks actual direct verification with failed
rewind/restore/read operations and valid offset restoration. It uses native I/O
seams and does not qualify real-media or firmware behavior.

### Native direct-verifier integration (2026-10-22)

The maintained `native-verifier-test` target requires an explicit
`VERIFIER_TEST_PROG` naming `lib/libsecureboot/tests/tvo`. It checks real files
and BearSSL SHA-256 through `verify_open`: six sizes (0, 1, 4095, 4096, 4097,
65537), each with a valid digest, changed content, extended digest token and
short digest token. All 24 checks passed. Assertions inspect verification
results, since the legacy test program does not return failure for every
verification rejection.

These are raw test manifests, not authenticated manifests. This does not
qualify streaming verification, firmware, BIP, system startup or upgrades.
The streaming API correctly requires additional signed-manifest setup; its
native fault-injection tests remain separate evidence.

The build used explicit public test-certificate inputs (`TRUST_ANCHORS` and
`TA_PEM_LIST`), `WITH_BEARSSL=yes`, `VE_SELF_TESTS=no`, and the standard object-tree
BearSSL static archive via `LDADD`, without host installation. Disabling
self-tests exposed an invalid empty hash command in `Makefile.inc`; known-answer
hash generation now occurs only when self-tests are enabled. Test manifest
registration callers also check allocation/registration failure.

Build frontend review: no new build-bsd option or security-policy input is
required. Its ordinary loader build consumes the corrected make rule; release
trust still requires explicitly configured release inputs. This native test
binary is not a release trust artifact. VM qualification remains on hold.

### Signed-file native integration (2026-10-22)

`make native-signed-verifier-test VERIFIER_TEST_PROG=/absolute/path/to/tvo
VERIFIER_TEST_OPENSSL=/absolute/path/to/openssl` runs the maintained signing
helper and native verifier with real files, signatures and BearSSL. Both inputs
are required. A temporary RSA test key and certificate are generated locally;
the verifier receives this disposable certificate through its test-only `-T`
option. No production key or firmware variable is used.

All 30 checks passed: for sizes 0, 1, 4095, 4096, 4097 and 65537, loader-style
verification accepts the signed payload, streaming open/seek/read/close verifies
it, and loader-style verification rejects an unenrolled signer, modified payload
and modified manifest. Each case runs in a fresh process. Tests require the
actual verified result, not merely a successful process exit or a nonnegative
unverified status. The direct real-file suite also remains separate.

This closes the previously noted signed-manifest setup gap in native streaming
integration. It does not establish EFI Secure Boot, immutable storage, update
authorization, normal startup, services or VM behavior. The temporary private key
is removed with the test directory. Build-bsd review: no new frontend input is
needed; this uses its maintained generation signing backend and ordinary
libsecureboot build. VM qualification remains on hold.

### Required verification native qualification (2026-10-22)

The native `tvo` driver now exposes `-R` to latch `verify_require()` before
loading test files. This is a test-driver option, not a loader policy override.
The maintained signed-file integration suite now passes 58 checks. In addition
to the earlier ordinary-mode and streaming checks, required mode accepts valid
signed payloads and rejects unenrolled signers, modified payloads and modified
manifests at all six sizes. It also rejects correctly signed manifests containing
`no_hash`, an extended `no_hash_extra` token, an unsupported fingerprint, or no
entry for the payload. Negative required-mode cases must produce the explicit
Secure Boot verification-failure diagnostic as well as a nonverified result.

Native `verify_file.c` maps `panic` to a warning under `UNIT_TEST`. These checks
prove the rejection branch and result with real cryptography; they do not prove
firmware halting behavior or prevent a native test caller from continuing.
Firmware enforcement remains a separate VM gate, currently on hold. No
production semantics or build-bsd inputs changed in this pass; the added switch
is confined to the maintained native driver.

Streaming read requests greater than `SSIZE_MAX` now fail with `EINVAL` before
I/O in both hashing and pass-through modes. This prevents an unrepresentable
successful count from wrapping the public `ssize_t` result. The native stream
regression checks that rejected requests leave file/hash offsets and read/hash
call counts unchanged; existing large representable reads remain covered.
The regression passed and the actual EFI vectx.o compiled with warnings treated
as errors. No VM or firmware execution was performed. The normal build-bsd loader
build consumes this source change; no policy input or frontend option changed.


The protected-process fixture also checks rejected F_SETOWN process/group
registrations against the kernel SIGIO allocator count, including missing
targets and live targets in another session. A valid self registration
must first increment that count and release it again. This requires a quiescent
disposable VM because allocator statistics are global; inability to read counters
or unexpected counter changes fails qualification. SIGIO_CLEANUP_PASS is required
exactly once, and SIGIO_CLEANUP_FAIL rejects the result. This regression uses
libmemstat through the maintained fixture build; it has not yet passed in a VM.

The basic integrity mechanism image provisions a bounded 64 MiB mode-1777
tmpfs at /tmp before tests that create temporary files, including process
accounting. This fixture has no normal rc startup. Its temporary mount is test
setup, not qualification of installed-system writable-state provisioning.

### Raw-loader verification cleanup (2026-10-23)

`make raw-loader-cleanup-test` compiles the actual file_loadraw function with
fault-injected I/O and verifier stubs. It checks one context release and one
file close on success, verifier-open rejection, read failure, verifier-close
rejection and allocation failure, with no failed load publication. The verifier
stub follows vectx_close's consuming ownership contract; stream-completion-test
separately exercises the actual verifier implementation. The old duplicate free
fails the cleanup test. Both native tests passed; the loader object also compiled
with and without LOADER_VERIEXEC_VECTX. No signature, firmware or root-handoff
qualification is implied. No VM was launched or loader installed.

### Verified replay regression (updated 2026-10-24)

Run `make verified-replay-test VERIFIER_BEARSSL_LIBRARY=/absolute/path/to/libbearssl.a`.
The default library location is `${OBJTOP}/lib/libbearssl/libbearssl.a`.
The harness compiles actual vectx record/replay/read/seek/close functions with
real file I/O and BearSSL SHA-256. Twenty-two cases now pass: unchanged and altered
replays, restoration, partial reads, known/unknown-size suffix completion,
page crossings, table growth and allocation failures. A 300-page-plus-17-byte
fixture checks table capacity, at most two page reads for each selected 7-byte
replay, and no backing reads at close after complete hashing. This test supplies
the trusted digest directly; manifest trust and firmware are outside its scope.

The implementation retains a digest per completed page and one partial page.
The digest array grows geometrically; it does not retain a whole-file payload.
It adds a page hash during first-pass reads. Resource counts do not establish
acceptable firmware CPU, heap or storage performance. Allocation failure remains
a sticky verification failure, including when growing an existing table.

### Buffer verification (2026-10-23)

`make verify-buffer-test VERIFIER_BEARSSL_LIBRARY=/absolute/path/to/libbearssl.a`
compiles the actual verify_buf, shared fingerprint parser and digest comparison
with real BearSSL algorithms. Sixty checks pass across SHA-1/256/384/512, including
changed bytes, truncation/extension, missing or unsupported entries, no_hash and
NULL/nonempty buffer rejection. Manifest lookup is stubbed; these tests do not
establish manifest authentication, loader handoff or resolution of the separate
verified-replay-test (corrected separately on 2026-10-24). The existing direct-verifier-io-test also passes.

### Bounded root descriptor reader (2026-10-23)

`make root-descriptor-load-test` compiles the actual file_readroot helper in both
verification-enabled and disabled configurations. Thirteen enabled scenarios
exercise positive and nonverified results, read/seek failures, short reads,
mutation before reading, undersized/oversized input, mutation of backing bytes
after buffer checking, and copy failure. The disabled configuration rejects the
reserved descriptor. All pass. Verifier and architecture functions are injected;
this is not a signed-manifest, firmware or kernel-root integration test. The
raw-loader cleanup test now uses md_image_ro to continue exercising its original
generic raw-loader path. Kernel/module replay remains an independent failing gate.

### Vnode authority snapshot scope

`make storage-snapshot-test` compiles the actual BIP vnode admission function
with lock and authority test seams. It checks that ordinary/unreserved operations
avoid authority snapshots, that protected grant checks retain revocation/action
checks, and that classification is recomputed after the snapshot. It also checks
unconditional mapping denial and bootstrap behavior. This is a native component
test, not kernel concurrency, VM or performance qualification. Ordinary boundary
list scans and the global mutex remain; protected grant admission reacquires the
mutex after obtaining the actor snapshot.

### Storage-client collection

`make client-collection-test` compiles actual SwitchBoard client remove, discard,
collect and issuer-revoke functions with session/worker/descriptor test seams.
It checks survivor preservation and exactly-once cleanup across adjacent removals
and repeated calls. It does not exercise live kernel revocation or worker channel
teardown and is not a daemon performance benchmark. Worker-list scans remain.

### Mount classification reuse

`storage-classification-test` also exercises the actual mount classification cache
across pending/accepted boundaries, destruction, reused identities and exhausted
generation counters. Mutations invalidate under the same storage lock used by
readers. This cache retains classification only, never actor grants or inherited
namespace admission. `storage-snapshot-test` checks admission flow with a classifier
seam; neither test establishes live concurrency or throughput.

The descriptor preload helper now delegates to stand/common/verified_root.c;
root-descriptor-load-test exercises both functions and checks that failures do
not modify the shared helper output. The manifest decisions remain injected.

Preload-buffer handoff prerequisite: source review found file_addbuf ignored the
arch_copyin result, could publish an incomplete copy, and leaked its control
structure when a name/type allocation failed. A native failure-injection test
reproduced the allocation leak before the fix. The maintained helper now rejects
address/alignment overflow and lengths beyond the copy return type, requires an
exact copy, and frees all newly allocated control data on failure. The preload
list and load address advance only after success. Failed copy bytes may remain
in load memory but are not published as a preloaded file.

preload-buffer-test compiles the actual function with injected allocator/copy
operations. It passes normal publication, no kernel, control allocation failure,
both string failures, negative and short copy, length overflow and alignment
wrap, with allocation counts and unchanged list/load address on every failure.
root-descriptor-load-test also passes; the complete amd64 EFI loader relinks.
This protects the existing entropy/trace buffer callers as well as the planned
retained-descriptor handoff. It does not implement boot selection or establish
firmware/kernel admission. No new build-bsd input is required: this is a shared
loader correction in the maintained build; unsupported verity boot publication
remains disabled. Evidence: preload-buffer-publication-review.json.

Current-device selection prerequisite: the existing environment setter freed an
old value before duplicating its replacement, did not check new-node/name/value
allocation failures, and could report success without the requested value.
mount_currdev also ignored the setter result after releasing the old mount.
The setter now prepares fallible allocations before replacing a value or linking
a new node, handles null volatile values, and transfers dynamic ownership only
on success. Existing hook dispatch and explicit NOKENV override propagation are
preserved; arbitrary hook side effects are not made transactional by this change.

mount_currdev retains a copy of the old device name, mounts the new device,
checks the environment commit, and only then releases the old mount. A failed
commit releases the newly acquired mount reference and keeps the old selection.
This adds setup-time allocation only; no read/write or disk-I/O hook is added.

loader-environment-test compiles the actual setter and current-device hook with
injected allocation/mount operations. It passes all new-entry allocation failure
positions, failed replacement preserving old value/flags, copying from the old
value, null replacement, sorted list links, and current-device name allocation,
new mount and environment commit failures with balanced references. The actual
EFI libsa and loader build/link pass. This is component lifecycle evidence, not
actual firmware mount rollback or a verified boot selection implementation.
The maintained build-bsd loader path picks up these shared changes without new
inputs; unsupported verity boot remains rejected. No VM or performance
qualification is claimed. Evidence: loader-environment-transaction-review.json.

Loader selection operations: verifier-enabled EFI loaders now include
verity-select (image, descriptor, cache-block count and heap-byte budget),
verity-preload and verity-clear. Selection authenticates/decodes the descriptor,
attaches the reader, uses the existing currdev mount hook, and retains the exact
wire bytes privately. It rejects an existing selection or already loaded code.
Preload requires a kernel, the selected current device, and no prior root
preload; it publishes retained bytes via the corrected file_addbuf. Release
requires unloaded code, restores the prior device and supports retry if other
open files keep the image busy. No trust decision is exported as an environment
flag. These commands supersede the earlier absence of an attachment caller.

verity-commands-test compiles the actual controller with injected external
operations. It passes allocation/open/authentication/descriptor-close/device-set
failures, malformed/overflow numeric input, duplicate selection/preload, changed
current device, failed preload copy, busy release/retry, restoration failure and
close-error retirement. It is not signature-chain or actual firmware execution.
During integration, loader mount bookkeeping failure was found to dereference a
null mount-list iterator instead of the filesystem that had just opened. The
native loader-mount-test reproduced SIGSEGV before the fix; it now passes all
three allocation failure points with filesystem release and ordinary reference
counting. Actual EFI libsa and loader build/link pass.

The commands do not enforce provenance of every loaded executable, choose the
kernel backing provider, perform kernel root admission, or define a complete
fail-closed boot script. Those remain necessary integration work. In particular,
preload success alone is not a hardened-mode admission signal. The loader manual
documents these limits. The maintained build-bsd loader build-graph test includes
the command source, but its boot backend continues rejecting verity receipts;
no unsupported publication path or new frontend switch was enabled. VM and
performance qualification remain open. Evidence: verity-loader-commands-review.json.

### Streaming verification cost and sequential consumers (2026-10-24)

`make vectx-cost VECTX_COST_WORK=/usr/obj
VERIFIER_BEARSSL_LIBRARY=/absolute/path/to/libbearssl.a` creates a unique retained
scratch directory with its generated C harness, payload, binary and results.json.
Set VECTX_COST_BYTES, VECTX_COST_ITERATIONS and VECTX_COST_REPLAYS to change the
workload. Defaults are 32 MiB, five rotated repetitions, and 1024 deterministic
17-byte rereads. Fixture creation uses a bounded buffer. Modes compare a direct
single-pass SHA-256 baseline, actual vectx sequential reading, vectx plus replay,
and vectx with its enforced sequential restriction. All modes validate the same
payload digest; the replay mode also checks each returned byte. The baseline
has no random-access security contract and must not replace the replay verifier.

vectx_set_sequential is available only before verified input has been consumed.
It permanently disables replay recording, and backward verified reads/seeks
latch failure. Forward seeks still hash skipped input; close still authenticates
the whole stream. Loader Lua's non-seeking stdio wrapper selects this restriction;
the actual fopen regression asserts it. Random-access ELF callers retain replay
checks. This is a caller contract, not a user-controlled verification bypass.

The 32 MiB native host probe measured median CPU seconds of 0.088026 (baseline),
0.171393 (replay-capable sequential), 0.182928 (with 1024 rereads), and 0.088284
(enforced sequential). The replay table used 262144 bytes; the restricted mode
used no table. Context size was 4416 bytes in this native build. Cache state was
not controlled; this is not a cold-disk, firmware, peak-heap or boot measurement.
No performance acceptance follows from these numbers. Raw results are recorded
in the security evidence receipt vectx-sequential-cost-review.json.

### Verifier ownership on abandoned loads (2026-10-24)

vectx_discard releases the context and its replay table without performing I/O,
verifying the input, or closing the caller-owned file descriptor. vectx_close
still authenticates successful consumption and releases the same resources.
Raw, ELF and Lua error paths use discard. The three ELF finalization blocks now
also discard contexts when image loading has already failed, rather than only
closing contexts on success. ELF header verification failure releases its
first-page allocation as well.

`make elf-verifier-cleanup-test` executes the actual three finalization blocks
with injected ownership operations: 24 combinations cover context presence,
load failure and verification failure. This is not a complete ELF load test.
verified-replay-test additionally allocates an actual digest table and asserts
that discard frees it and the context exactly once, performs no backing read,
and leaves the fd usable. raw-loader-cleanup-test retains its error injection.
A fresh EFI build with WITH_LOADER_VERIEXEC_VECTX compiles the conditional ELF
paths; this test build does not change the normal build-bsd loader defaults.

### Raw preload sequential contract (2026-10-24)

file_loadraw now selects vectx_set_sequential before calling arch_readin when
streaming verification is enabled. Its read loop and the current EFI, i386,
userboot, U-Boot and kboot readin callbacks consume input forward; libofw's
readin helper also reads forward. A rewind remains a sticky verifier failure.
ELF consumers still retain replay metadata because they need random access.
The separately authenticated fixed-size root-descriptor path is unchanged.

raw-loader-cleanup-test now exercises six cases and asserts selection before
readin. Failure to select the restriction aborts before reading or publishing a
preload, with one context discard and fd close. Actual sequential verification
and no-table behavior are covered separately by verified-replay-test and the
native cost probe. Both recorded EFI configurations (VECTX enabled and disabled)
build. These component checks do not prove complete raw loading in firmware.

Review also found that kboot/libofw readin allocation failures return zero, and
libofw does the same on mapping failure. Raw callers interpret zero as EOF. Their
read-error paths can also return a consumed prefix. This pre-existing callback
error contract needs correction and fault-injected tests; the EFI allocation
failure path already returns -1. No claim of those platform paths being qualified
follows from the EFI builds or the sequential-contract change.

### kboot/OFW readin error propagation (2026-10-24)

The callback issue recorded above is corrected: allocation failure returns -1
with ENOMEM, OFW mapping failure returns -1 with the mapping error, and any read
failure returns -1 even after a prefix was copied. Cleanup preserves the read
error. Genuine EOF still returns the bytes copied; a zero-length request performs
no allocation, mapping or read.

`make readin-failure-test` compiles both actual callback bodies with injected
allocation/mapping/read operations. Fifteen cases cover full and empty/partial
EOF reads, errors before/after a prefix, allocation failure, mapping failure and
zero length. The cleanup seam deliberately changes errno to verify preservation;
output sentinels and allocation-release counts are checked. Both unmodified
callbacks failed the regression before the correction. raw-loader-cleanup-test
also passes. This is native callback testing, not a platform boot test.

The maintained amd64 kboot build passes. An amd64 top-level OFW target is not
available; the generic OFW source object compiles via its own Makefile after
obj/beforebuild prepares the object directory and architecture links. A complete
OFW loader/platform build is not established. Evidence records both unsuccessful
setup attempts and the subsequent prepared-object compile separately.

### Explicit release trust profiles and rotation (2026-10-24)

`make loader-trust-rotation-test TRUST_WORK=/usr/obj TRUST_MAKE=/usr/bin/make
TRUST_OPENSSL=/usr/bin/openssl TRUST_JOBS=16` creates a private, uniquely named
scratch directory. It generates disposable firmware, old/new generation,
application and repository signers. It builds three independent native probes
from production manifest/EFI trust code: old generation only, both generations,
and new generation only. Each profile retains the exact build argv, public
anchor hashes, generated ta.h hash, probe hash and build log. Keys stay in the
private fixture directory; no enrolled or installed trust is changed.

Twenty-one cases test acceptance sets, rejection of other signer roles, explicit
revocation in every profile, and continued acceptance of the other overlap key.
The test uses real signatures and compiled anchor tables, with injected firmware
variable transport. It does not boot an EFI loader or prove firmware enrollment,
installed upgrade/recovery, or kernel disk-root admission. Profiles are native
qualification artifacts, not a production staging attestation.

Removing an old anchor from the new loader does not invalidate a previously
signed loader that still contains it. Tests deliberately show old-profile
acceptance separately from revocation. Deployment must qualify its firmware
revocation and authenticated boot-selection/rollback policy; an overlap rollout
alone must not be reported as system-wide old-key revocation.

### Authenticode digest ordering (2026-10-24)

uefisign now hashes nonempty sections in ascending file-offset order while
retaining the original section table. The previous digest routine used table
order. Its certificate-size subtraction is also checked before computing the
trailing hash range. Sorting is bounded by MAX_SECTIONS and runs in the signing
tool, not filesystem or runtime I/O.

`make uefi-digest-test` uses the actual digest routines with OpenSSL and compares
five vectors against independently specified Python SHA-256 byte ranges. These
cover ordinary/reversed section order, empty sections, certificate exclusion,
and an excessive certificate-size rejection. Before the change, reversed order
produced the wrong digest and empty-section cases failed the range checks.

The generation_boot_test BootCheck.test_efi_signer_orders_sections_by_file_offset
case additionally reorders a real EFI fixture's section headers and compares the
rebuilt signer's reported digest against an independent Python calculation.
This synthetic reorder checks hashing, not firmware acceptance of the altered
image layout. Existing staging/inventory and separate-credential cases pass with
the rebuilt signer selected through BSD_BUILD_UEFISIGN. The native signer builds
under /usr/obj; it was not installed. Production boot-stage can select that
artifact through its existing --boot-efi-signer input.

Reference: https://learn.microsoft.com/en-gb/windows/win32/debug/pe-format
(Signature calculation orders sections before hashing.) uefisign -V still only
detects signature presence. Neither these digest tests nor signing establish full
Authenticode verification, enrolled firmware trust or successful boot.

Storage classification cache regression (2026-10-24):
`make storage-classification-test` instruments entries into the extracted real
exact lookup body. It checks reuse across 10,000 positive and 10,000 negative
cache hits and refresh after actual-destruction notification. The mutex is a
sequential test seam: these counts establish neither kernel contention nor
concurrency safety, and are not throughput measurements.

Pool-scoped classification invalidation (2026-10-24): the same target also checks
that another pool's registration, approval and destruction do not refresh cached
positive or negative decisions. Same-pool destruction, object identity reuse and
saturating generation counters remain covered. Kernel-object compilation is
separate from this native harness; runtime contention still needs VM qualification.

`make geom-override-test` compiles the actual g_footshooting kernel policy helper
in conventional and MAC_SYSTEM_INTEGRITY modes. It checks 256 flag combinations
and flag changes; it does not issue actual storage operations, load modules or
establish concurrent topology safety. All existing GEOM override consumers must
use the kernel helper, including loadable partition and mirror implementations.

The GEOM override test also executes the extracted access-conflict decision
block across 864 combinations per kernel configuration. It covers both conflict
directions, read admission, release deltas and provider errors. These are decision
inputs rather than a simulation of complete valid consumer lifetimes. A restored
direct-flag bypass was verified to fail the hardened case without editing source.

`make loader-manifest-verify-test LOADER_MANIFEST_VERIFIER=/absolute/tool
LOADER_MANIFEST_FIXTURES=/absolute/fixtures` exercises the paired production
native helper against prepared generation/firmware/application/repository
signatures and tampered inputs. Supply fixtures from manifest-trust-prepare and
a verifier compiled for that generation certificate. Seven cryptographic cases
are checked; no firmware variables, mounted root or VM is involved.

### Retired BIP immutable-policy fixture (2026-10-24)

`storage_policy_test.c/.h` and their two calls have been removed with the BIP
immutable-policy loader. Earlier `STORAGE_POLICY_PASS` / mount-source results
are historical only. The runner no longer requires those retired markers.
Remaining BIP fixture code is not evidence that the current ordinary system or
Secure Boot path is qualified. See the active system-security roadmap.

### Retired BIP storage-management client check (2026-10-24)

The BIP storage-management/data/policy/worker client APIs and their dedicated
native test were removed after broker/provider removal. The legacy storage-client
fixture and observer no longer emit `STORAGE_MANAGEMENT_DENIAL_CHECK`, and the
runner no longer asserts it. Historical results for that marker do not apply to
the current implementation. Other BIP fixture dependencies remain unqualified.

## Retired BIP storage fixture (2026-10-24)

The storage-anchor, storage-mapped, storage-attached and storage-ordinary cases
are removed, along with their PID1 fixture and BIP I/O test module. The runner
rejects these case selections and the verifier rejects their old receipts.
The anchor full-suite profile is also rejected. Ordinary ZFS handle operations
and tests under tests/sys/zfshandle remain. This does not restore the legacy
combined runner: its provider/session and general BIP dependencies still need
removal before independent Secure Boot VM qualification.

## Retired session-storage mode (2026-10-24)

The capsule-session-storage case and its principal/lifecycle options are removed.
The assembler no longer accepts those inputs; the verifier rejects old case
receipts and metadata. The obsolete lifecycle provider and its conditional
BSDFilesystem hooks are removed together. Remaining session-policy and general
BIP paths in this legacy runner are still pending cleanup, not usable proof
of authentication or Secure Boot.


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

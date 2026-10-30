> Historical BIP design: BIP has been dropped. This document does not describe
> supported enforcement in the active tree. The BIP kernel provider and ZFS
> mount-admission hook have been removed. See system-security.md for active
> scope, cleanup status and evidence.

# Persistent BIP state: implementation contract

## Scope after the compatibility architecture decision

User-approved direction, 2026-10-20: this contract applies to **explicitly
protected mutable resources**, not all writable state. This is a historical
architecture decision. The current [system security roadmap](system-security.md)
records BIP removal and takes precedence over the integration language below.

Ordinary logs, caches, temporary files and application state retain conventional
filesystem access unless a documented security dependency requires protection.
Third-party software must not need a new capability protocol for ordinary state.
Base components may be adapted to manage narrowly classified security-critical
resources. Package inventory and authenticated policy select those boundaries;
base package membership alone does not confer authority.

The earlier syslog/Casper admission proposal is conditional work for explicitly
protected resources, not the next universal compatibility requirement. Do not
weaken the existing scoped-worker API to force it into ordinary daemon startup.
The unused no-client preparation wrapper has been removed; the supported worker
API requires an observed client ID. Libservice and the maintained storage client
build successfully after that API cleanup; no new runtime acceptance is implied.

Kernel/default-policy reconciliation, installed-system testing and update
qualification remain open. Existing protected-state tests below do not prove
compatibility of the complete installed system under the new architecture.


Status: implementation contract, 2026-10-20. The complete persistent boundary and
system-wide consumer integration described here are not implemented. The real
BSDFilesystem consumer now passes two bootstrap Secure Boot cases with four
storage scopes, data recovery across reboot, and retained-descriptor/namespace
denials after fork and authority clearing (`bip-provider-claims-service-v3`,
two cases and 208 files verified). Subsequent scoped cases cover provider restart,
authenticated sessions, logout/expiry, client clear/exec/exit and live-client
unit-token revocation (`bip-session-revoke-v2`, 221 files verified). These remain
bootstrap cases; package-derived state policy and usable installed-system
coverage are open. A bootstrap-only backing reservation
registry, mount identity labels, retained-vnode quarantine and experimental exact-dataset
admission grants with a lease-bound variant and limited content-I/O draining now exist; their bounded qualification
is described below. This document narrows engineering
decisions, not the full system-security goal. See [system security](system-security.md)
for current qualification and the first real-service acceptance milestone.

## Ordinary content integration status

Exact ordinary-content classification now exists in the kernel, with all-policy
approval before activation and immutable assignment for the boot. The full
`bip-ordinary-content-v4` Secure Boot regression and 115 evidence files verify
ordinary root/nonroot I/O/mmap/namespace operations alongside denied management,
unknown-child access, type/reclassification rejection and second-policy veto.
It grants no privileged writer or pool-management authority.

Capsule's optional `content` field defaults to protected. Ordinary entries must
be attached and cannot deliver protected-provider policy or issuer capabilities.
Native configuration tests pass. The configuration-driven
`bip-ordinary-policy-v1` Secure Boot VM and 115 independently verified evidence
files now demonstrate conventional root/user path I/O, mmap and namespace
operations without grants, with immutable policy, no derived provider handle,
and denied root unmount/backing-device writes. Package-derived mappings and
installed-system qualification remain pending. See the current system-security status
for retained failures, exact evidence and unfinished compatibility gates.

## Two independent lifetimes

Unix-socket connection admission is distinct from filesystem content access.
BIP's open hook maps connectat's synthetic socket VREAD|VWRITE check to
FI_FS_UIPC_CONNECT, followed by the dedicated connect hook's independent check.
`bip-socket-connect-v2` verifies datagram delivery, denial of permission
substitution in both directions, and denial of new connection after grant close
(115 files verified). This does not establish revocation of traffic on an
already-connected socket. Endpoint ownership, message authorization and
connection lifetime need separate qualification when integrating logging and
other Unix-socket services.

A **boundary** is the mandatory classification of protected storage. A **grant**
is permission for a particular admitted execution to perform specified operations
within that boundary. Closing a provider, revoking a grant, losing an issuer, or
unmounting a filesystem must never change protected storage into unprotected
storage. A read-only generation and mutable protected state are separate classes.

The boundary registry belongs to the built-in integrity policy, not the provider.
Boot establishes it from authenticated policy before storage handles or namespace
attachments become available to ordinary processes. A filesystem mount carries a
reference to its boundary; the boundary outlives individual mounts. Destruction
of a mount label must not perform filesystem I/O or remove persistent policy.
Reboot reconstructs classification from authenticated generation policy before
exposing persistent storage. Persistent data or the online pkg database cannot
supply authoritative policy labels.

Dataset identity uses the full pool GUID, dataset object and dataset GUID. The
fsid is only a lookup aid. A protected subtree requires checks against verified
ZFS ancestry and inheritance when children are created, opened, received or
cloned. Pathname prefixes and caller-supplied dataset names do not establish
membership. Unknown or conflicting classification inside a protected subtree
must fail closed. A failed mount attempt must not acquire ownership of or destroy
an unrelated mount. The new identity check and collision regression cover that
last invariant; they do not implement boundary inheritance.

## Policy relationships and compiler obligations

### Verified enforcement granularity and the installed-system gap

Current data grants authorize actions across one complete mounted ZFS dataset.
`storage_directory_identity` requires a dataset-root vnode (`VV_ROOT`), and
`storage_vnode_check` matches pool GUID, dataset object and dataset GUID. Neither
the grant nor that check selects a file, inode or subdirectory. Create/rename/
unlink hooks check the parent and applicable existing object against that same
dataset authority; they do not interpret the requested basename as a policy key.
The bootstrap-owned tmpfs runtime claim is a different mechanism and does not
provide this persistent storage grant API for arbitrary tmpfs state.

The temporary `/tmp/bip-state-policy.py` draft describes object-scoped operation
sets within a state backing. Those sets cannot be enforced by the current data
grant API. It must not be promoted to a runtime compiler or used to generate
apparently narrow grants over a shared dataset. Its syntax is not a supported
format. A syslog PID-file requirement must not become authority over cron's PID
file simply because both live below `/var/run`.

`bip-dataset-scope-v1` adds an actual-kernel delegation check using an opened
subdirectory of the protected dataset. The call must fail ENOTDIR; accepting it
would silently widen the claimed scope. The Secure Boot storage-anchor case
passes and 115 bound files verify. The existing storage test target builds with
16 jobs, and the public grant-header comment now documents the dataset scope.
No kernel behavior or runtime permission was relaxed. This test establishes a
scope limit, not file-level enforcement.

Before assigning runtime permissions to legacy shared paths, implementation
must choose and qualify an enforceable mapping. A whole dataset can represent
a state boundary only when every granted operation genuinely applies throughout
that dataset. Independently protected sibling objects instead need object-level
enforcement, including prospective names before creation, retained descriptors,
replacement, cross-boundary links/renames and object-identity reuse. Alternatively,
separate backing boundaries require verified compatibility attachments whose
normal application operations still work. A pathname-prefix allowlist, broad
directory grant or UID-based exception does not satisfy either design. Package
requirements must remain non-authorizing until this mapping, launch bindings and
completed-filesystem reconciliation are enforced together.

Keep these records distinct:

- Package requirement: owning archive, executable payload identity, declared
  state need, expected path/type/lifetime and source declaration hash.
- State object: stable policy identity, backing identity, object scope, lifecycle,
  initialization, quota, schema and migration/retention rules.
- Launch authorization: admitted service/session context, eligible verified
  executable, resource identity and permitted operations.

Many requirements may resolve to one shared object. One requirement may have
several independently authorized launch contexts. Permission is never inferred
from package membership, signed-program status or UID. Conflicting mappings and
unknown launch references are errors, not automatic permission unions.

The compiler must reconcile package requirements with the completed generation,
including generated objects, links and compatibility attachments. It must bind
its output and the validated launch policy into the authenticated generation.
Missing declarations are an audit gap, not proof of no state needs. The existing
temporary compiler draft does not meet these requirements and is not a public
format. A format is not ready until its kernel and supervisor consumers agree
on the operation and lifecycle semantics below.

## Issuance, activation and revocation

### Boot attachment policy integration status

Capsule's `storage[].attachment` now wires the internal attachment helper into
authenticated preparation. Destinations are explicit policy inputs; equal or
nested slots and missing mount rights are parser errors. Preparation retains
mounted-root descriptors privately across manager launches, and boot-policy
comparison rejects reload changes. This does not assign writers or reconcile
package requirements. Native parser cases pass. The `storage-attached` case in
`bip-attachment-policy-v2` passes under Secure Boot with 115 files verified:
policy-driven preparation, exact mounted identity and flags, immutable boot
policy, grant/fork/revocation behavior, and close-independent mount lifetime.
`bip-attachment-failure-v1` additionally qualifies cleanup after a later
policy-open failure (115 files verified): immutable slot restored, no anchor
published, and the dataset reservation still denies ordinary root access.
Other failure branches and real service integration remain open.

### Legacy service launch prerequisites

General package-to-service namespace attachment remains incomplete.
`BSDFilesystem/layout.c` sets `mountpoint=none` and `canmount=off`; its request
path returns descriptors from `tzfs_mount` anonymous mounts. An admitted client
can use those descriptors, but that does not make a global pathname available
for an immutable compatibility symlink. A policy compiler must not equate a
successful claim with a published legacy path. Boot-owned namespace attachments
need authenticated destination slots, exact backing identity, replacement/mount
stacking protection and lifetime rules independent of any one client. No such
general legacy attachment path is established by the existing alias installer.

`bip-named-mount-v1` now verifies the initial VFS mechanism: original PID 1
reserves the selected dataset, mounts it at an authenticated fixture slot and
reads existing content. An ordinary root child cannot read by path or retained
descriptor, cover/remount the slot or force-unmount it. `tzfs_mount` returns
EBUSY for that dataset while its named mount exists; bootstrap cleanup restores
the later anonymous-mount tests. The Secure Boot case and 115 input/evidence
files verify. This establishes that the existing provider must not be expected
to reuse a named mount. Nonbootstrap grants on named mounts, general destination
validation and production boot-policy integration remain unqualified.

The subsequent `bip-named-access-v1` case qualifies invocation-bound grants on
the named mount: pathname read/write succeeds only after issuance, a forked
child is denied, and grant close denies fresh opens and retained descriptor
read/write. The bootstrap issuer uses a kernel-stamped invocation; no PID-only
or pathname-based admission is used. The Secure Boot case and 115 files verify.
This resolves the nonbootstrap grant mechanism gate above, while production
destination validation, package mapping and service admission remain open.

The mount enforcement audit narrows the initial implementation choice.
`protected_storage_attach` now implements the internal serialized-bootstrap
sequence using a validated specification and an already acquired handle.
`bip-attach-v2` qualifies its identity/right checks, named mount creation,
noexec/nosetuid postconditions and nonbootstrap refusal alongside the grant
lifecycle (115 files verified). It does not create consumer grants, and closing
the returned directory does not detach the namespace mount. The policy parsing
and retained-attachment integration described above supersede this initial
helper-only milestone. Package mapping and service admission remain open.

The internal `protected_storage_slot_open` helper now implements bootstrap-only
destination validation against the immutable root, with per-component no-follow
directory opens and an empty-leaf check. `bip-slot-v1` verifies canonical-path,
nonempty, mounted-filesystem and nonbootstrap rejection alongside the positive
named-mount case (115 files verified). The subsequent boot attachment policy
uses this helper. `bip-slot-ancestors-v1` additionally passes
symlink-leaf, symlink-ancestor, writable-ancestor and foreign-owner rejection,
plus safe nested acceptance (115 files verified). The complete
generation-to-runtime mapping remains open.

`mac_system_integrity.c:mount_new` and `mount_update` currently admit only
bootstrap; `mount_unmount` has only the additional kernel-originated final
anonymous-anchor release exception. `bootstrap()` identifies proc0 or initproc,
not UID zero. ZFS mount creation independently records pool GUID, object and
dataset GUID through `mac_mount_check_zfs`. Thus initial global attachments
should be constructed by authenticated bootstrap, before starting ordinary
processes, while keeping the existing denial of subsequent namespace mounts.
Do not add a general service/root mount exception to implement legacy paths.

Before implementing that path, verify the lifecycle with a real named ZFS mount:
reserve the backing identity first; validate an empty directory slot on the
authenticated immutable generation without following aliases; mount the exact
reserved dataset; confirm the resulting mounted identity; retain the attachment
for the boot. Failure must stop startup before consumers run. The fixture must
then prove normal access with an exact grant and root denial of mount-over,
remount, forced unmount and backing replacement. Named mounts may not satisfy
the current anonymous-mount reuse contract in `zfs_handle.c`; the provider must
not silently reuse or replace them. That compatibility is an explicit gate,
not an assumed consequence of both paths using the same dataset GUID.

The current SwitchBoard command path (`svc_exec_command`) forks and execs rc
commands without a service control-channel handshake. The managed-service path
has a pre-exec launch gate, but that gate precedes the executable's new execution
nonce. Existing storage issuance binds a current process identity and nonce;
granting to the launcher cannot authorize the later executable. No pending-exec
storage grant is implemented. A legacy-service integration must establish a
post-exec, kernel-observed admission before its first protected state operation,
or implement and qualify a separate kernel-mediated launch binding. Passing a
PID or trusting an executable name is insufficient. Do not stretch the current
pre-exec gate into a claim that this is already solved.

Syslogd illustrates the additional process boundaries. It opens its PID file
and sockets before normal daemonization, then ordinarily forks in `waitdaemon`.
Foreground execution avoids that daemonization step but does not solve grant
issuance. Casper is a required build option; `syslogd_cap_enter` starts its
services and `casper_readconfigfile` opens configuration-selected resources.
The log descriptors then return to syslogd. Config reload repeats resource
selection. Both opener and writer need independently admitted, lifetime-bound
access to the selected log storage. Disabling Casper, inheriting authority
across arbitrary forks, or granting the entire shared runtime dataset would
bypass these requirements. Console, kernel-log input, network forwarding and
pipe destinations need their own operation/consumer treatment.

The next runtime implementation must therefore cover the post-exec admission
barrier, helper lifecycle, configured output reconciliation and reload/restart
as one service flow. The existing socket/PID alias test establishes only layout
compatibility. It is not evidence for any of these authority transitions.

### Syslog and Casper implementation boundary audit (2026-10-20)

This is a source audit and an implementation requirement, not runtime acceptance.
The following call sites were checked against the current tree:

| Boundary | Current behavior | Required integration |
|---|---|---|
| `usr.sbin/syslogd/syslogd.c:main` | Opens PID file, kernel log input and listening sockets before `waitdaemon`; ordinary daemon mode forks afterwards | Admit the final supervised executable before its first protected operation; use an explicit foreground launch for that supervised mode and qualify it |
| `syslogd_cap_enter` | `cap_init`, then `cap_service_open` for `syslogd.casper` and `system.net`, then Capsicum entry | Separate the log helper's storage authority from the network helper; neither service name alone nor a root caller authorizes storage |
| `lib/libcasper/libcasper/libcasper.c:cap_init` | `casper_pdfork` creates the broker | Do not inherit the daemon's actor grant into the broker |
| `libcasper_service.c:casper_main_loop` and `zygote.c:zygote_init` | Broker starts a zygote using another fork | Do not give the zygote blanket log-data authority |
| `zygote.c:zygote_main`, `libcasper_service.c:service_execute` | Zygote creates the final helper, then receives the selected service and process descriptor | Authenticate and bind the final helper before dispatching any protected operation; bind the helper to the requesting service launch and exact permitted resources |
| `service.c:service_start/service_clean` | Sanitizes descriptors, normally retaining only the channel and process descriptor | Any admission/control endpoint needs an explicit bounded lifecycle; do not use `CASPER_SERVICE_FD` to preserve arbitrary inherited descriptors |
| `syslogd_cap_config.c:casper_readconfigfile` | Checks the configured path, invokes `readconfigfile`, and exports opened log descriptors | Reconcile selected destinations with authenticated storage ceilings before opening; returned descriptors do not authorize the daemon by themselves |
| `syslogd.c:init` | Reload closes old outputs and asks the helper to open the current configuration again | Define and test reload failure behavior, authority retirement and continued handling of previously admitted output; do not expand ceilings from mutable configuration |

The current `service_storage_worker_prepare_for_client` API cannot simply be
threaded through those forks. In `lib/libservice/libservice.c` it locks endpoint
transfer to `CAP_XFER_NONE`, fork handling to `CAP_CLOFORK_ONCE`, and exec handling
to `CAP_CLOEXEC_LOCKED`. In `switchboard/authority.c`,
`svc_authority_storage_worker_prepare` requires a matching admitted storage
client and provider launch, resolves namespace ceilings, and later observes the
worker's kernel-stamped invocation. Its client-zero convenience wrapper does
not establish a general daemon admission facility. Existing tests of rejection
or filesystem-provider workers do not prove Casper integration.

The next implementation must provide a separately reviewed supervised-service
admission flow with these properties:

1. The final syslog executable completes post-exec admission before PID/socket
   creation. Admission identifies the actual launch and execution nonce.
2. The final log helper completes its own admission before `readconfigfile` or
   any output-opening command. The broker and zygote receive no actor grants.
3. Helper association is established through bounded launch authority and
   kernel-observed process identity. A caller-supplied PID, service string,
   executable path or reused numeric descriptor is insufficient.
4. Both writer and opener are limited to authenticated storage boundaries and
   operation ceilings. Configuration supplies requested destinations, not new
   authority. The network helper receives no log-storage grant.
5. Helper/daemon exit, exec, control loss and supervisor restart retire the
   corresponding grants. Failed admission must prevent resource operations.
6. Qualification includes normal logging, both local sockets, rotation, reload,
   daemon restart, helper loss, missing/wrong admission, root substitution,
   retained descriptors, unrelated helpers and fork/exec denial. Pipe outputs,
   console, kernel log input and forwarding need explicit coverage or an honest
   unsupported configuration result; silently dropping them is not acceptance.

Existing compatibility-alias tests remain useful layout evidence. They do not
exercise this admission flow. The build must retain Casper; disabling it or
making a shared runtime dataset generally writable would avoid the required
security boundary rather than implement it.

Only authenticated bootstrap establishes boundaries. A delegated supervisor may
issue grants only within explicitly delegated resource and operation ceilings;
it cannot remove a boundary or expand its own ceiling. An ordinary root process
must have neither capability. Recovery and policy replacement require the
separate authenticated owner/update path.

Grant activation binds to kernel-observed process identity and execution nonce,
verified software and the admitted service incarnation or authenticated session.
These values cannot come solely from request payloads. Automatic executable
attribution is eligibility, not admission. Descriptor transfer does not transfer
execution admission. Fork and exec require explicit new admission unless a
particular supervised inheritance rule is implemented and tested.

Use existing authority/session lifetime machinery where its semantics apply;
do not silently reinterpret transient isolation claims as persistent boundaries.
In particular, CAP_AUTH_BIND_INVOCATION currently binds capability-service
instances; it does not by itself protect TrustedZFS handles or all vnode I/O.
A provider restart gets a new incarnation and new grants. Old descriptors and
replayed activation messages remain denied even when the executable is identical.

Every operation checks current grant validity at an explicit admission point.
A successful synchronous revocation must stop new admissions and drain or cancel
in-flight protected operations before returning. Already committed writes and
bytes already copied to a caller cannot be retracted. Asynchronous loss marks
admission revoked immediately; outstanding operations require tracked cleanup.
Do not wait for I/O while holding the registry or policy mutex. Long-running
send/receive operations need cancellation/drain semantics; a check only at stream
creation does not establish completed revocation.

## Grant integration review: lifetime and launch ordering (2026-10-20)

This is a source-review decision, not an implemented grant interface or VM
qualification. Do not implement a persistent grant by retaining an arbitrary
capability-service endpoint as its authorization witness.

The reviewed call paths establish these constraints:

| Source | Observed behavior | Consequence for storage grants |
|---|---|---|
| mac_capability_dev.c: mac_capability_instance_close | Final file close marks the instance closed, then waits for internal references before freeing it | Retaining the file delays the close callback; retaining the instance can block close waiting for that reference. Neither is a suitable independent persistent-grant lifetime |
| mac_capability_kern.c: mac_capability_instance_authorization_allows | Permits intentionally unbound instances as well as software-bound and invocation-bound instances | This generic helper alone cannot establish mandatory invocation binding for BIP |
| mac_capability_authority.c: cap_authority_lease_valid and lease_close | Internal lease references do not keep the owner file open; owner/control close marks the lease revoked | Reuse this separation of object lifetime from admission lifetime; retaining a lease must not retain its owner descriptor |
| switchboard/execute.c: svc_launch_finish | Storage descriptors are prepared before fork and final exec; some backend workers inherit them | Possession before exec cannot establish permission for the final invocation. Workers need explicit admission rather than an inherited blanket grant |
| switchboard/authority.c: svc_authority_resolve and svc_authority_bind_invocation | Resolve software to the current launch record and obtain process identity and execution nonce from kernel-stamped channel metadata | Reuse this observed post-exec identity path; never accept a client-supplied process identity as admission |
| switchboard/supervisor.c: service teardown | Revokes unit software authority before dropping the process-protection lease | Storage admission must observe the same authority loss while keeping the backing boundary intact |

### Required implementation shape

A BIP grant must own its own resource scope, operation ceiling and cancellation
state. It may retain the software-authority object and an applicable session
lease object, with immutable process identity and execution nonce captured by an
authorized issuer. It must not retain a messaging file or instance to simulate
this lifetime. Copying identity numbers alone is insufficient: software and
session revocation must remain observable. The existing authority implementation
has issuer/token ownership and prison checks; shared binding support belongs
there rather than exposing its private token file implementation to BIP.

Resource issuance also needs a separate, bootstrap-created delegation ceiling.
Possession of the existing software issuer is not, by itself, permission to
issue arbitrary storage grants. A delegated supervisor can narrow resource and
operation scope, never enlarge it or remove mandatory classification. A data
permission cannot authorize dataset lifecycle or raw backing operations.

For the first provider, boundary registration precedes handle delivery. A
recipient can receive an inert handle before exec, then request admission over
its authenticated route after exec and before touching protected state. This
requires a real Capsule/SwitchBoard/provider protocol change. Pre-exec binding,
PID lookup, executable-name exceptions and permission for every process with
the same software stamp are not acceptable substitutes. A worker fork requires
its own observed admission and policy relationship to its supervising service.

The grant needs an operation guard, not just a Boolean check in a MAC admission
hook. Guard acquisition checks scope, operations and live authority and records
an admitted operation; all completion/error paths release it. Explicit synchronous
revocation first closes admission, then drains or cancels admitted operations
outside policy locks. Issuer/session loss closes admission immediately and
schedules cleanup. Existing CAP_AUTH_REVOKE only changes authority state: its
return is not evidence that protected VFS I/O has drained. Existing channel
ci_inflight tracks channel handlers/calls, not VFS operations or sendfile output.

Before publishing a production ABI, implement and review the first real service's paired
admission/completion paths, cancellation owner, reference ownership and lock
order. Reject mappings and unsupported backing effects explicitly. Qualification
must include close/revoke during I/O, authority/lease loss, grant-control loss,
worker admission, provider restart, stale handles and boundary persistence.
The current reservation and vnode quarantine do not implement these grants.

No build-bsd option or shipping policy format is added by this review. Its next
integration must build the actual consumers and run their positive and denial
cases; a new fixture-only permission path cannot satisfy the service milestone.

### Reusable software/invocation binding (2026-10-20)

The kernel now provides cap_authority_binding, an immutable owned record of the
software-authority object, process identity and execution nonce. Existing channel
binding, send/ioctl admission and isolation-accessor checks consume this record.
Acquisition verifies issuer/token ownership and prison membership, retains the
authority object, and drops temporary descriptor references before returning.
Publication transfers ownership under the instance mutex. Failed publication
and final instance destruction release that reference outside the instance mutex.
No channel, file or process reference is retained by the binding itself.

This preserves the existing software-only binding form and its userspace ABI.
BIP must require an invocation binding and separately validate a resource ceiling;
this helper grants neither storage authority nor delegation. Session leases still
have their existing independent lifetime. No data-grant ABI, grant-control file,
paired VFS operation guard or synchronous drain is implemented by this change.

Qualification: bip-binding-authority-vm-v1 passed 1,650 checks using the rebuilt
GENERIC WITNESS/INVARIANTS kernel and a new binding-ownership regression. Invalid
and wrong-type target descriptors, a foreign issuer and repeated duplicate
binding leave no authority references behind. Issuer close revokes the retained
authority, and endpoint close returns it to the token-only reference count.
The maintained run-kernel.py now requires this regression's completion marker.

bip-binding-secureboot-v1 passed approved, storage-anchor and storage-mapped with
the rebuilt GENERIC-INTEGRITY WITNESS/INVARIANTS kernel. Invocation replay and
lease revocation tests passed, as did the existing retained-vnode and mapping
quarantine checks. All four guests shut down cleanly without forced termination;
the three EFI guests report SecureBoot=1 and SetupMode=0. Retained evidence was
revalidated (3 cases, 66 files). The bounded receipt is
/usr/obj/usr/src/security-qualification/bip-binding-validation-v1.json.

Both kernels and the helper were built through the maintained /usr/src targets
under /usr/obj using 16 compilation jobs. The first kernel attempt failed on a
missing declaration include; v2 fixed it and completed. These are incremental
builds using an existing staged world, not a clean installed-generation build.
build-bsd's existing kernel and Secure Boot paths consume the changed sources;
no new runtime input, build option or shipping policy format is introduced.
The real BSDFilesystem retained-access regression remains unresolved.

### Experimental exact-dataset admission grants (2026-10-20)

MAC_SYSTEM_INTEGRITY now has a bootstrap-only BIP_STORAGE_GRANT mechanism.
Original PID 1 supplies a mounted root-directory descriptor, its software issuer
and token, kernel-observed recipient process identity/exec nonce, and an operation
mask. The kernel obtains the full pool GUID/dataset object/dataset GUID from the
verified mount label and requires an exact existing reservation. Names, fsids,
UIDs and executable paths cannot substitute for those identities.

The grant owns the independent authority binding. Each covered vnode check
compares current software authority and invocation, exact backing identity and
all requested action bits. Read-only access does not imply writes or metadata
changes; access to one dataset does not include another dataset in the same
reserved pool. Namespace operations check their affected parent/object pairs.
The reused FI_FS action vocabulary does not reuse isolation-claim lifetime.
Append-only and executable grants are not supported by this interface. Existing
DAC and other MAC policies still apply. Backing-handle management remains denied
to nonbootstrap callers, even when they have a data grant.

A nontransferable control descriptor owns the grant. It has locked fork/exec
states; clearing ordinary fcntl flags does not undo those states. Duplicate
control descriptors share one lifetime. Final close removes the grant under the
policy mutex. Final destruction waits for tracked I/O references and releases
authority through a taskqueue outside that mutex. Installation failure
publishes no grant. Software revocation, issuer loss and authority clear prevent
new matching admissions independently of control lifetime. The mandatory backing
reservation remains intact. Mappings remain denied, including for bootstrap.

This is an experimental admission interface, not the production grant ABI.
The initial version had no synchronous revoke operation. The content-I/O extension
below adds a limited drain for READ/WRITE-only grants; close and software/session
loss remain asynchronous. Deferred sendfile under a data grant is now denied.
The full operation-guard/drain requirement remains unfinished. Authenticated session policy,
delegated resource ceilings, authenticated state-policy consumption, descendant
classification and management grants are also unfinished. The only userspace
caller is the disposable storage fixture; Capsule/SwitchBoard/BSDFilesystem have
not been wired to it. No real-service acceptance is claimed.

Qualification: bip-data-grant-vm-v2 passed storage-anchor and storage-mapped
under the corrected GENERIC-INTEGRITY WITNESS/INVARIANTS kernel. The grant fixture
performs real read/stat/open, write/fsync, create/rename/unlink operations and
checks denial for a valid-software fork child and a different dataset in the same
pool. Four separate recipient runs exercise final control close, token revoke,
issuer close and authority clear. It also checks invalid requests, descriptor
enumeration, duplicate control lifetime and locked inheritance. Both guests
report SecureBoot=1/SetupMode=0 and perform firmware shutdown without forced
termination, panic or WITNESS reversal. Evidence revalidation checked 2 cases and
63 files; 34 runner/evidence tests passed. The receipt is
/usr/obj/usr/src/security-qualification/bip-data-grant-validation-v1.json.

The initial fixture build exposed missing declarations/header dependencies,
which were corrected. Source review after the first passing VM found a missing
descriptor-information callback; it was added with an enumeration regression
before accepting v2. The kernel builds and fixture use the maintained /usr/src
targets under /usr/obj with 16 jobs. These are incremental builds and staged-world
fixtures, not a clean installed-system build. build-bsd secureboot-test already
builds this fixture through build-bootstrap.sh; its storage acceptance now
requires the grant marker and hashes the new test sources. No production policy
or new frontend option is introduced. The real provider regression remains open.

Next implementation gates are complete operation admission/completion and draining,
session/delegation ceilings, and the actual supervisor/provider handoff. This
prototype must not be promoted as the finished persistent boundary/grant model.

### Lease-bound dataset admission (2026-10-20)

The experimental bootstrap interface now has BIP_STORAGE_SESSION_GRANT, a
separate fixed-width request containing the existing exact-dataset/invocation
request and a lease-control descriptor. The original BIP_STORAGE_GRANT layout
is unchanged. The new operation requires a valid lease from the same software
issuer and prison; a wrong object, owner descriptor or foreign issuer is rejected.
There is no fallback from a failed lease check to an unleased grant.

cap_authority_lease_acquire retains only the kernel lease object. The storage
grant owns this reference and releases it outside its policy mutex on close or
creation failure. It does not retain an owner/control file or a channel instance.
Each data admission requires both the existing software/invocation/object/action
checks and live lease state. Last owner/control close, issuer loss or monotonic
expiry therefore denies new access even if software authority and the storage
grant control remain alive. Dropping one storage grant does not revoke the lease
or other grants. Lease validity is an atomic/deadline check under the storage
mutex; destruction continues through the existing deferred lease cleanup path.

This supplies a session-lifetime constraint, not human authentication, roles,
resource delegation or authenticated session policy. Only original bootstrap
can issue these experimental grants. Policy must still establish which resources
require a session and which authenticated session can receive them; the separate
unleased bootstrap operation must not become a way for a delegated issuer to
omit a mandatory session constraint. No production caller is enabled. Loss of
admission remains asynchronous; outstanding I/O is not drained by this change.

Qualification: bip-session-grant-vm-v1 passed storage-anchor, storage-mapped and
approved under GENERIC-INTEGRITY with WITNESS/INVARIANTS. Three additional real
storage-recipient runs exercise owner close, control close and kernel-observed
deadline expiry while keeping software authority valid and the storage control
open. They deny retained read/write/open after lease loss. Foreign-issuer and
wrong-descriptor requests fail, and a revoked/expired control cannot issue a new
session storage grant. Read-only/read-write grant replacement within the same
lease remains functional. Existing dataset-scope, fork, namespace and mapping
checks pass, as do the approved profile's channel-lease and invocation checks.
All three guests report SecureBoot=1/SetupMode=0 and perform firmware shutdown
without forced termination, panic or WITNESS reversal. Revalidation checked
3 cases and 68 files; 34 runner/evidence tests passed. Receipt:
/usr/obj/usr/src/security-qualification/bip-session-grant-validation-v1.json.

GENERIC and GENERIC-INTEGRITY plus the storage fixture built through maintained
/usr/src targets under /usr/obj using 16 compilation jobs. build-bsd's existing
Secure Boot fixture path builds this source, and storage acceptance now requires
the lease-grant marker. These are incremental kernel/staged-world mechanism
results. In-flight draining, delegated policy ceilings, the actual supervised
provider handoff and installed-system qualification remain unfinished.

### Limited content-I/O drain (2026-10-20)

The experimental grant control now accepts BIP_STORAGE_REVOKE_IO only when its
mask contains READ and/or WRITE, with no other permissions. It atomically closes
admission and sleeps until that grant's tracked content operations finish.
BIP_STORAGE_IO_STATUS exposes the active count and explicit controller revocation
state. The status flag does not report aggregate software or session validity.
An unsupported mask returns EOPNOTSUPP without changing admission. An interrupted
wait leaves admission revoked; the controller can retry. Final close remains
asynchronous and keeps the grant object alive until its last tracked operation
finishes. Software/lease loss also remains asynchronous, independently closing
new admissions. Original bootstrap remains the only grant issuer/controller.

The existing stack-scoped vn_file_context now owns completion guards. The normal
fo_read/fo_write wrapper marks a synchronous content operation and releases every
guard after vn_io_fault, including fault retries and error exits. Admission and
active-count increment are serialized with revocation under the storage mutex.
Repeated checks in one context share a guard. Completion decrements the count,
wakes drain waiters, and queues final cleanup if the control was already closed.
No filesystem work or authority destruction occurs under the storage mutex, and
msleep drops it while waiting. A failed nonblocking guard allocation denies the
operation; it never falls back to an untracked successful admission.

Only the paired read/write context can admit grant-mediated content I/O. Untracked
sendfile and direct vnode content paths fail closed. Directory/link reads remain
denied to recipients until paired completion exists. Mappings stay denied.
Opening a descriptor may pass an eligibility check, but subsequent content I/O
needs its own live admission. Broader masks still support existing point-in-time
namespace/metadata checks; they cannot claim the new drain guarantee. A completed
drain is not fsync, durable-media completion, erasure of copied bytes, or a drain
of all grants in a session. Deferred, namespace, metadata and separately delegated
backing operations still need their own reviewed completion semantics.

Qualification: bip-io-drain-vm-v1 passed storage-anchor, storage-mapped and approved
under GENERIC-INTEGRITY with WITNESS/INVARIANTS and SecureBoot=1/SetupMode=0.
A VM-only preloaded MAC module delays real vnode reads/writes after built-in BIP
has admitted and counted them. It cannot grant permission. The controller arms
it with an actual vnode descriptor and observes both the delay state and the
kernel grant count; no pathname identifies the target and no sleep duration is
treated as proof that an operation is active. Tests establish that read and write
drains remain pending at active count one, succeed after release at count zero,
and deny subsequent access. A signal-interrupted wait leaves revocation set and
successfully drains on retry. Last-control close during a paused read preserves
object lifetime through completion. Unsupported-mask rejection leaves the
existing positive operations working. All prior storage/session cases still run.

The fixture module lives only under tools/test/secureboot/io-fixture, registers
after static MAC policies, and is signed into the anchor VM's boot manifest.
It is absent from the provider and approved cases and from production module
installation. The maintained build-bsd secureboot-test plan builds it only for
the anchor storage profile against the selected kernel object directory. Its
plan regression checks this distinction. The MAC compatibility version is 15;
matching kernels/modules were rebuilt under /usr/obj with all 16 CPUs. These
remain incremental kernels with an existing staged world.

All three guests performed unforced firmware shutdown. No panic or WITNESS
reversal was observed. Retained evidence revalidation checked 3 cases/72 files;
34 host runner/evidence tests, the build-bsd Secure Boot plan test and the
341-hook tracing contract check passed. The bounded receipt is
/usr/obj/usr/src/security-qualification/bip-io-drain-validation-v1.json.
This does not fix or qualify the real BSDFilesystem retained-access regression,
production launch/session policy, restart/reboot persistence, installed startup,
updates or recovery. Full draining and the actual supervisor/provider handoff
remain required gates.

### Production handoff review and exact handle operands (2026-10-20)

The production path still cannot safely turn on reservation and reuse existing
handle delivery. Capsule protected_storage_prepare opens and retains bootstrap
anchors; protected_storage_derive returns a narrowed TrustedZFS handle over its
private, nonce-bound manager channel. SwitchBoard prepares these descriptors
before final exec and permits storage worker inheritance. Its authority resolver
can obtain the actual request process identity/exec nonce after exec. These are
different phases: descriptor delivery cannot substitute for post-exec admission.
SwitchBoard owns the software issuer; forwarding a process ID to Capsule alone
would not establish a resource or session ceiling. The current bootstrap-only
mac_syscall interface is also unavailable in capability mode, so a production
supervisor interface must be deliberately descriptor-scoped rather than opening
arbitrary policy syscalls to confined providers.

A further kernel prerequisite was missing: mac_zfs_check_handle received only a
pool GUID. It now receives the immutable full pool/object/dataset-GUID tuple
from the held handle, a pool-operand flag, the command, and a distinct clone-source
role. Both clone operands are checked independently with the active actor before
credential substitution. The namespace gate spans admission and the operation;
effectful operations retain their existing liveness validation. The MAC ABI is
16, and tracing argument metadata is regenerated. BIP validates the tuple shape
and still quarantines the whole reserved pool. No scoped management exception is
introduced by this change.

This is the **held operand**, not proof of every affected object. In particular,
OPENAT resolves a different child, CREATE mints a new child, and rename/receive/
clone can affect additional parents or descendants. The clone source tuple names
the source handle's dataset; when the request selects a named snapshot, it does
not by itself identify that snapshot. Pool operands have object zero and their
pool GUID in the guid field. Do not interpret a valid dataset tuple as a grant to
all descendants, to an ancestor pool, or to every snapshot of the dataset.

The remaining production handoff must address these dependencies together:

- Authenticated boundary policy must be installed before ordinary delivery and
  reconstruct subtree classification before exposing stored data after reboot.
- Management and data-issuance delegation need distinct, immutable resource and
  operation ceilings. A software issuer alone must not confer either authority.
  Mandatory session constraints cannot be omitted by selecting an unleased path.
- Relative-target operations must resolve actual affected identities/ancestry
  and preserve classification before publication. Checking the original handle
  alone does not authorize child creation, rename, receive or destruction.
- SwitchBoard must admit the observed final invocation and explicitly admitted
  workers. Provider teardown/restart must invalidate old grants while keeping
  boundaries intact. PID lookup and executable-name exceptions are insufficient.
- The actual BSDFilesystem request/reply path must bind delivered data access to
  that admission and its session/launch lifetime. Current retained-directory and
  backing-handle delivery still lack this mandatory grant consumer.

The identity regression observes the real hook without overriding policy. It
compares dataset identity with ZFS INFO/objsetid, distinguishes a pool handle,
and checks both operands of a real snapshot/clone into a separate dataset in the
same supplied pool. It closes/destroys the clone and destroys the snapshot. A
nonbootstrap UID-zero process still receives EPERM and its denied operand is
observed. The first run failed because the test mistakenly expected clone to
return zero instead of its new descriptor; the implementation was not relaxed.
The failed run remains retained. The corrected bip-handle-identity-vm-v2 passed
storage-anchor, storage-mapped and approved under GENERIC-INTEGRITY with
WITNESS/INVARIANTS. All three guests report SecureBoot=1/SetupMode=0 and complete
unforced firmware shutdown without panic or WITNESS reversal. Evidence validation
checked 3 cases/74 files; 34 host runner/evidence tests and the 341-hook tracing
contract check passed. GENERIC and GENERIC-INTEGRITY plus the matching observer
module/helper were built through maintained /usr/src targets under /usr/obj with
16 compilation jobs. Existing build-bsd bootstrap/module steps consume the updated
sources; no new option is needed. The bounded receipt is
/usr/obj/usr/src/security-qualification/bip-handle-identity-validation-v1.json.
This does not qualify production management delegation or resolve the real
BSDFilesystem retained-access failure.

### Resolved snapshots and child publication (2026-10-20)

The handle hook now distinguishes resolved objects and descriptor publication.
OPENAT and the shared child-mint path check the actual new handle's full identity
before fd installation. The latter covers pool-root opening, CREATE and CLONE.
On denial, the unpublished handle is freed. Existing create/clone error paths
attempt to remove the newly created dataset; successful cleanup is tested, but
arbitrary cleanup failure and crash recovery remain separate required work.
A descriptor-publication check occurs after creation: it does not replace
mandatory authorization of the actual destination parent before mutation, or
classification/inheritance before any other path can expose that object.

Clone now also resolves its selected source snapshot and checks that distinct
object before the clone operation. The earlier source-handle check remains.
Identity comes from a held ZFS object, with a pool-identity consistency check;
ZFS holds are released before the MAC callback. The exclusive namespace gate
spans resolution, policy admission and the operation. The MAC compatibility
version is 17. No identity or authority is accepted from numeric fields in a
userspace request, and reserved-pool management remains denied to nonbootstrap.

The VM observer can now additionally deny resolved-snapshot or publication phases.
These controls exist only in the signed disposable anchor fixture. They cannot
grant access or suppress another MAC policy's error, and are never installed in
a production image. Tests compare the resolved snapshot and published child's
identities with real ZFS INFO/objsetid values. Positive cases exercise OPENAT,
pool-root opening, CREATE, and snapshot/CLONE. Denial cases require the observed
resolved phase, unchanged caller descriptor count, and no returned descriptor.
Denied create/clone publication and denied source-snapshot admission are followed
by actual OPENAT checks establishing that the destination does not exist. Existing
root-denial, grant, session, content-drain and mapping tests remain required.

The first VM attempt failed in the test's descriptor-count query: KERN_PROC_NFDS
requires its zero self selector, not PID 1. The fixture was corrected to the
inspected kernel API without changing policy, and that failed attempt is retained.
The corrected bip-resolved-vm-v2 passed storage-anchor, storage-mapped and
approved under GENERIC-INTEGRITY with WITNESS/INVARIANTS. All three guests report
SecureBoot=1/SetupMode=0 and perform unforced firmware shutdown without panic or
WITNESS reversal. Retained evidence validation checks 3 cases/74 files; 34 host
runner/evidence tests and the 341-hook tracing contract check pass. GENERIC and
GENERIC-INTEGRITY plus the matching observer/helper were built under /usr/obj
with 16 compilation jobs. Existing build-bsd bootstrap/module steps consume the
changed sources. Receipt:
/usr/obj/usr/src/security-qualification/bip-resolved-validation-v1.json.
These checks do not establish subtree inheritance, management delegation, paired
management draining, the real provider handoff or installed-system acceptance.

### Namespace checks before mutation (2026-10-20)

CREATE and CLONE now resolve and check the actual immediate destination parent
before invoking the mutating ZFS operation. A subtree handle naming a nested
child does not stand in for that parent. RENAME additionally checks the affected
source dataset and both source/destination parents; DESTROY checks the affected
dataset and its parent. These checks use the active actor before capability-backed
credential substitution. The exclusive namespace gate spans resolution, policy
checks and mutation, while ZFS holds are released before MAC callbacks. Identity
resolution holds DSL dataset metadata directly; it does not open the object set
or require filesystem contents merely to identify the object. This was corrected
after the first passing VM run and is included in the final rerun.

The parent name is derived only after existing handle-relative validation; its
identity is then obtained from the actual ZFS object. New parent/source role flags
make the operands distinct. A pool root has no dataset parent and is rejected by
this dataset-parent helper; pool destruction needs its separate administrative
path. This changes the MAC compatibility version to 18. BIP still denies ordinary
management of reserved pools. These enforcement points add no delegated permission.

The nested-dataset regression checks actual parent identities against INFO and
objsetid, independently of the broader original handle. It exercises successful
CREATE/CLONE, a move between different parents, and DESTROY. A separate VM-only
MAC policy denies destination-parent admission for create/clone and independently
denies the source object, source parent and destination parent of rename, plus
the object/parent of destroy. Observations must identify the exact denied phase;
subsequent real lookups establish unchanged source/destination names and caller
fd counts remain unchanged. Publication/snapshot denials and previous grant,
session, drain, quarantine and mapping regressions remain required.

Qualification: bip-namespace-vm-v2 passed storage-anchor, storage-mapped and
approved under GENERIC-INTEGRITY with WITNESS/INVARIANTS. All three guests report
SecureBoot=1/SetupMode=0 and complete unforced firmware shutdown, with no panic or
WITNESS reversal. Evidence validation checked 3 cases/74 files; 34 host runner/
evidence tests and the 341-hook contract check pass. GENERIC and GENERIC-INTEGRITY
plus the matching fixture/module were built under /usr/obj with 16 jobs. Receipt:
/usr/obj/usr/src/security-qualification/bip-namespace-validation-v1.json.

The existing build-bsd bootstrap/module steps build these updated sources against
the selected kernel; there is no new frontend option or production test control.
Subtree classification/inheritance, snapshot/rollback/receive and other backing
operation closure, paired management draining, immutable delegation ceilings and
the production supervisor/provider handoff remain unfinished. Parent checks alone
do not prove that moving a subtree preserves all descendant boundaries. No real
BSDFilesystem, installed-system, update/recovery or key-lifecycle acceptance is
claimed by this mechanism work.

### Snapshot mutation and live ancestry requirements (2026-10-20)

Snapshot deletion and rollback now present the selected snapshot's actual full
identity to the handle MAC hook before mutation. They retain the existing named
MAC checks as well. The new snapshot-source role is distinct from the head dataset
and clone source roles. Missing explicit rollback snapshots retain the DSL ESRCH
convention. The MAC compatibility version is 19.

For implicit "latest" rollback, ZFS holds the actual head, obtains its previous
snapshot under the pool configuration lock, and captures that snapshot's name
before admission. It then passes the explicit checked target to the existing DSL
rollback transaction, which still verifies that it is the most recent eligible
target. A later change cannot silently substitute a different snapshot. The
namespace gate spans selection/admission and the operation; no ZFS hold spans the
MAC callback. Existing snapshot/clone eligibility rules remain in the DSL layer.

The VM regression writes and fsyncs real file data, snapshots it, then writes
newer data. Independent denial of named and implicit-latest rollback preserves
the newer contents. Both successful rollback forms restore the saved contents.
Denied snapshot deletion preserves the actual snapshot; successful deletion makes
it unavailable. Observed identities match INFO/objsetid, and missing/latest-without-
snapshot requests are checked. File and directory descriptors are closed and the
anonymous mount is released before rollback; this does not qualify busy-mounted
rollback, concurrent snapshot replacement or all lifecycle edge cases.

The ancestry review also establishes a constraint for the remaining delegation
work: immutable mount identity is valid, but a cached list of mount ancestors
must not decide current authority. Dataset moves and later nested reservations
can make such a list stale. A scoped operation must resolve live DSL ancestry
under the namespace gate, release ZFS holds before policy callbacks, and check
current boundary policy before mutation/publication. Reservation changes use the
same exclusive gate. Neither pathname prefixes nor a prior successful mount can
substitute for this check. No live ancestry consumer or subtree inheritance is
implemented by the snapshot change.

Qualification: bip-snapshot-vm-v1 passed storage-anchor, storage-mapped and approved
under GENERIC-INTEGRITY with WITNESS/INVARIANTS. All three guests report
SecureBoot=1/SetupMode=0 and complete unforced firmware shutdown without panic or
WITNESS reversal. Retained evidence validation checks 3 cases/74 files; 34 host
runner/evidence tests and the 341-hook contract check pass. GENERIC and
GENERIC-INTEGRITY plus the matching fixture/module were built under /usr/obj with
16 jobs. Existing build-bsd bootstrap/module steps consume the changed sources;
no new option or production test control is added. Receipt:
/usr/obj/usr/src/security-qualification/bip-snapshot-validation-v1.json.

These are incremental-kernel/staged-world mechanism results. Receive/send effects,
remaining backing operations, live ancestry and subtree classification, paired
management draining, immutable delegation ceilings and production provider/session
integration remain unfinished. The real BSDFilesystem retained-access failure
and installed-system/update/recovery/trust-lifecycle gates remain unresolved.

### Stream object admission (2026-10-20)

Send now checks the actual selected snapshot and, for an incremental stream,
its actual base snapshot. The checks precede stream output and one-shot send
consumption. Receive checks the existing destination dataset, or the actual
immediate parent when the destination is absent. Each operand carries the full
pool/object/GUID identity obtained from DSL metadata under the namespace gate;
ZFS holds are released before MAC callbacks. MAC compatibility version 20 adds
incremental-base and receive-target roles. Existing name checks remain.

Lookup and policy results are deliberately separate: ENOENT from policy for an
existing destination is a denial, never permission to try the parent instead.
The VM observer injects both EACCES and ENOENT at this phase and verifies no
parent fallback, no new snapshot and unchanged file contents. Missing-target
parent denial leaves the target absent. Denied full/incremental sends leave
empty output and retain one-shot eligibility; successful sends consume it.
Actual full receive restores A; incremental receive restores B without force.

The first run, bip-stream-vm-v1, failed the successful incremental receive with
ETXTBSY. Its verification helper mounted the destination writable to read data,
which dirtied the received head. Verification now mounts read-only. The rerun
uses fresh disk copies, retains the failure evidence, and does not force receive
or weaken the data assertions. libtrustedzfs consumes the BEGIN record before
issuing the receive ioctl; callers must account for that on denial. The fixture
explicitly rewinds before each attempt and claims no input-offset preservation.

Qualification: bip-stream-vm-v2 passes storage-anchor, storage-mapped and approved
with SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS, unforced firmware shutdown and
no panic or WITNESS reversal. Evidence validation checks 3 cases/74 files;
34 host runner/evidence tests and the 341-hook contract check pass. Both kernels
and the matching observer/fixture were built with 16 jobs under /usr/obj.
Receipt: /usr/obj/usr/src/security-qualification/bip-stream-validation-v1.json.
Existing build-bsd bootstrap and observer steps consume the changes, and the
runner requires the stream marker. No new build option or runtime exception is
needed.

This is admission qualification for non-forced full/incremental streams, not
complete receive authorization. Forced receive can affect additional snapshots;
clone-origin/replacement effects, cancellation/drain, live ancestry, nested
boundaries and production scoped management grants remain unfinished. The
reserved-pool quarantine is unchanged. The real-provider retained-access failure
and installed-system/update/recovery/trust-lifecycle gates remain open.

### Typed dataset-property admission (2026-10-20)

The first-provider audit identified ZFD_SET_PROP as requiring finer policy than
a command bit. MAC ABI 21 adds zfs_check_setprop with the actual dataset
pool/object/GUID, property name and selected value. A NULL string pointer selects
the integer; a non-NULL string selects the string and the integer is zero. The
arguments are bounded, validated, kernel-owned copies valid for the synchronous
callback. The normal ZFS property pipeline consumes the same selected input;
its validation, special setters and accounting remain authoritative. The kernel
property-name matcher accepts canonical native names rather than userland column
aliases; policy must still reject unknown or disallowed names/values explicitly.

The call occurs after handle/name resolution and read-only-property validation,
before property mutation, using active caller credentials. The exclusive
TrustedZFS namespace gate spans it and the operation. No ZFS hold is retained
across the callback. BIP supplies a separate conservative consumer: nonbootstrap
property mutation in a reserved pool remains denied. No data grant or generic
handle permission enables it. This is not yet a production property ceiling or
resource-delegation API.

The VM-only second MAC policy takes its test rule as PID-1-controlled input,
with no compiled-in property names or limits. The test admits a quota value,
denies both a higher quota and zero (removing the limit), and reads back the
unchanged actual quota. It admits mountpoint=none, rejects a different path,
and reads back none. Observed identity matches INFO/objsetid and the actor.
Inactive union-like fields are populated with unrelated data to verify only the
selected type reaches policy; a malformed reserved field never reaches the new
hook. Test rules only add denials and cannot override BIP or another policy.

bip-property-vm-v1 passes storage-anchor, storage-mapped and approved with
SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS, unforced firmware shutdown and no
panic or WITNESS reversal. Evidence validation checks 3 cases/82 files, including
kernel policy sources and generated hook metadata. Both kernels, observer and
fixture build under /usr/obj with 16 jobs; 35 host runner/evidence tests and the
342-hook tracing contract check pass. Existing build-bsd bootstrap/module steps
consume the changes. Receipt:
/usr/obj/usr/src/security-qualification/bip-property-validation-v1.json.

Limits: this hook covers typed TrustedZFS dataset setters, not pool bootfs or
legacy raw ZFS ioctls. Those paths retain their existing quarantine; future scoped
grants must not expose bypasses. Live resource ancestry, immutable delegated
property/value ceilings, post-exec provider/worker activation, client grants,
paired management drain and authenticated policy consumption remain required.
The real provider's fork/authority-clear access failure remains unresolved. No
installed-system, update, recovery or production trust qualification follows.

### Concurrent-stream deadlock baseline (2026-10-20)

The resource-scope review examined dsl_dir.dd_parent (protected by the pool
configuration lock), the TrustedZFS namespace gate, and the recorded ZFS/filedesc
WITNESS report. It found a separate concrete liveness defect: zfshandle_ioctl takes
the namespace gate exclusively for send and receive and retains it throughout
zfshandle_ioc/ZFS streaming. Name-to-object atomicity cannot justify retaining a
global namespace lock over arbitrary blocking stream I/O.

bip-pipe-vm-v1 reproduces the cycle with two threads of the original bootstrap
process, so software/fork admission is not involved. The fixture writes and
fsyncs 4 MiB of deterministic data, snapshots it, and feeds a real send directly
into a real receive through a bounded pipe. At the 15-second progress deadline,
both operations had started and neither had finished; FIONREAD reported 65,536
pending bytes. Kernel thread observations report the sender in pipewr and the
receiver waiting on TrustedZFS namespace. Earlier file-backed stream tests finish
because the file can absorb the stream; they did not qualify this concurrency.

The regression is now part of storage-anchor, built by the maintained storage
Makefile and existing build-bsd bootstrap step. The runner requires
BOOT_STORAGE_PIPE_PASS and rejects the observed failure. A passing run must
complete both operations, compare the entire received file and clean up the
created datasets. It is not enough to lift the deadline, enlarge the pipe or
substitute a temporary file. At this baseline storage-anchor failed; historical
subset receipts remain historical evidence, not current-suite acceptance.

The locking repair must preserve identity and lifetime. In the reviewed OpenZFS
implementation, numeric-object send (dmu_send_obj / legacy ZFS_IOC_SEND) and
long dataset holds provide a possible way to pin the admitted source/base while
releasing namespace serialization for blocking output. This is a candidate,
not an implemented fix: verify GUID/object binding, pool lifetime, flags,
permission ordering, cancellation and every error cleanup. Receive also needs
separate admission, streaming and commit reasoning; simply unlocking around the
existing name-based receive permits target replacement between check and effect.
A passing producer/consumer pair alone must not conceal a receive that still
blocks unrelated namespace work indefinitely.

The same review found that legacy device ioctls take the namespace gate shared,
as do typed read operations. Live ancestry observed under a shared gate cannot
be advertised as stable against all concurrent legacy namespace mutations after
releasing the DSL configuration lock. Resolve this before ancestry becomes an
authorization witness. No ancestry cache, resource-delegation API, or production
permission was added during this review. The recorded host ZFS/filedesc WITNESS
issue remains undiagnosed; this stream cycle is a distinct finding.

Evidence: /usr/obj/usr/src/security-qualification/bip-pipe-validation-v1.json.
The fixture builds with 16 jobs and 35 host runner/evidence tests pass. The guest
reports SecureBoot=1/SetupMode=0 with no panic/WITNESS reversal, but acceptance
fails and host cleanup is required; no successful guest shutdown is claimed.
Repair this lock/lifetime problem as part of the resource-delegation work, then
resume the real-provider fork/authority-clear, restart and reboot gates. The
full installed-system/update/recovery/trust-lifecycle objective remains open.

### Pinned send outside namespace serialization (2026-10-20)

zfshandle_send_pinned now holds the selected source and optional incremental base
under the existing exclusive namespace gate, checks the pool GUID and snapshot
types, and takes long dataset holds before releasing the pool/configuration hold.
The preceding actual-object MAC checks and name resolution occur under the same
namespace gate, so the pinned objects are the admitted objects. It then drops the
namespace gate and invokes numeric-object ZFS_IOC_SEND, which drives dmu_send_obj
and the normal output-descriptor, feature and zone checks. The four supported
send flag bits match that native ABI, enforced by compile-time assertions.

A rename cannot redirect the object numbers, and the long holds prevent their
destruction/reuse during streaming. Snapshot references are released on completion
or error outside the namespace gate; the function reacquires the gate before
returning to the dispatcher. Pin-setup failures unwind their dataset and pool
holds. Existing one-shot state transitions remain: denial/setup/output failure
leaves the send reusable; successful send consumes it. This does not turn that
state machine into synchronous BIP grant revocation or cancellation.

The strengthened VM test starts a send without its consumer, waits for real pipe
data, and performs namespace operations while output is pending. Snapshot deletion
returns EBUSY. Renaming the source and creating an empty replacement snapshot under
its former name succeeds. The subsequent receive completes and its entire 4 MiB
file matches the original deterministic payload, not the replacement. A prior
invalid-output-FD send returns EBADF and the snapshot can then be deleted and
recreated, checking pin cleanup. The normal full/incremental stream, one-shot,
admission-denial and quota/property regressions remain passing.

bip-send-pin-vm-v1 passes storage-anchor, storage-mapped and approved with
SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS, unforced firmware shutdown and no
panic/WITNESS reversal. Evidence validation checks 3 cases/84 files. Both kernels
and the fixture build under /usr/obj with 16 jobs; 35 host runner/evidence tests
and the 342-hook metadata check pass. Existing build-bsd bootstrap steps build the
new helper and the runner requires both pipe completion and identity/lifetime
markers. Receipt: /usr/obj/usr/src/security-qualification/bip-send-pin-validation-v1.json.

### Typed receive input lifetime (2026-10-20)

Typed receive now supplies an explicit kernel-only input context through the
ordinary ioctl dispatcher. Native vector validation, security policy and feature
checks remain in place; ordinary device receives have no callback. This context
is never accepted from a user nvlist or pointer. Every input read drops the
namespace gate and reacquires it on success, EOF or error. Before processing the
bytes, it resolves the root handle and compares the root name, parent object/GUID
and target object/GUID with their admission bindings. An initially absent target
must remain absent until receive creates it; thereafter the owned receive dataset
is the expected target. Pool identity is checked as well. Any mismatch returns
ESTALE. Existing name-based commit and cleanup execute with serialization restored.
Typed receive does not accept property lists; there is no property rollback onto
a replacement. Native failure cleanup drains its writer and destroys the owned
staging object using its current name under the gate.

The maintained test consumes BEGIN itself and enters ZFD_RECV directly, then
observes the receiver thread blocked on kernel pipe input before doing namespace
work. This avoids confusing a userspace BEGIN read with the lock release being
tested. The producer resumes only after unrelated create/destroy succeeds.
Successful receive verifies the complete 4 MiB payload. Closing the producer
without more data fails and leaves no child. Renaming/replacing the parent while
input is paused causes ESTALE; replacement sentinel data remains unchanged and
the abandoned receive is removed from the renamed parent. Stream bytes are
prepared in a fixture-owned dataset solely to control producer timing; the tested
transport remains a bounded pipe.

bip-recv-gate-vm-v2 passes all three requested cases (storage-anchor,
storage-mapped, approved), SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS, unforced
firmware shutdown, no panic or lock-order reversal. Evidence checks 90 files;
35 host tests and 342 hook contracts pass. Both kernels and the fixture compile
through maintained targets, with 16 compilation jobs. The storage Makefile adds
the receive helper to the existing build-bsd bootstrap path. Runner acceptance
requires its marker and hashes the additional helper and receive-core sources.
Receipt: /usr/obj/usr/src/security-qualification/bip-recv-gate-validation-v2.json.
The first run failed a fixture rights assertion (parent lacked ZHF_SUBTREE);
that failure remains recorded, and no production permission check was relaxed.

This does not qualify every receive phase or stream type. Existing-target
incremental replacement, signals/cancellation/drain, encrypted/raw streams, live
ancestry classification and production scoped management remain open. The real
provider, installed system, update and recovery acceptance gates remain open.

### Expanded real-service failure evidence (2026-10-20)

bip-provider-namespace-v1 runs the actual signed StorageClient through
Capsule/SwitchBoard/BSDFilesystem on the receive-fixed Secure Boot kernel. The
client retains both a file and its delivered directory. Its forked child first
verifies software authority is valid, then probes content read/write, openat of
the existing file, creation of a separate file, same-size ftruncate and unchanged
fchmod. It clears authority, verifies that clear, and repeats every operation.
All twelve unauthorized operations succeed. This is an explicit failed first
service gate, not a passed negative test or evidence of usable protected state.

The admitted parent verifies the original challenge and all four storage scopes,
and cleans unexpected creations after recording them. Same-byte writes,
same-size truncation and unchanged mode avoid corrupting the parent's challenge
while still exercising the actual access checks. Probe protocol 5 reports results
and errno for each operation; acceptance rejects missing/duplicate observations,
unexecuted cases, EBADF and successful unauthorized operations. Both probe builds
and 36 host parser/evidence tests pass. The standard build-bootstrap script already
builds both probes. No production permissions were weakened to make tests pass.
The failed VM is terminated by the harness and second boot is skipped. Receipt:
/usr/obj/usr/src/security-qualification/bip-provider-namespace-validation-v1.json.

Source review reconfirms the production boundary: protected_storage_prepare never
reserves anchors, svc_launch_finish delivers storage-root before final exec,
BSDFilesystem provisions before readiness, and pdfork workers inherit handles.
svc_authority_resolve can obtain kernel-stamped process identity/nonce, but neither
the storage delivery path nor the provider's sender-only request adapter consumes
a mandatory persistent grant. The next implementation must provide an independent
bootstrap-issued resource ceiling, runtime admission of the provider and workers,
and per-client data issuance tied to the observed invocation/session. Reservation
must precede exposing backing storage; grants must precede provisioning or data
publication. Failure must unwind admission without removing the boundary. Merely
reserving the pool, admitting every signed executable, or treating a service label
as resource authority would not satisfy this contract.

### Independent data-issuance ceiling (2026-10-20)

BIP_STORAGE_DELEGATE is an original-PID-1-only factory for a data-issuance
descriptor. It resolves the actual mount-root directory to its full registered
pool/object/GUID tuple. An unregistered dataset or ordinary file is rejected.
The descriptor fixes that resource, an action mask and whether every issued grant
must carry a live software-issuer-owned lease. There is no user-supplied resource
identity on the issuance ioctl, no management permission and no subdelegation.

The descriptor is transferable once, with locked close-on-fork and close-on-exec
states. This transfers issuance authority within a fixed ceiling; it does not
admit the holder to the data. The final supervisor can receive it after exec and
use BIP_STORAGE_ISSUE inside capability mode. Each issuance separately requires a
software issuer/token pair and the recipient's process identity/execution nonce;
the supervisor must derive those from authenticated kernel metadata. Possession
of a software issuer alone cannot manufacture a resource ceiling. Required lease
policy cannot be removed by selecting the older bootstrap-only grant syscall.

Issued grants retain a refcounted ceiling state, not its file. Last file close or
BIP_STORAGE_REVOKE_ISSUER marks it revoked, affecting every issued grant on later
admission checks. These events leave the permanent boundary registry intact.
Issuer revocation is asynchronous; it does not claim to drain all operations.
Existing individual READ/WRITE grant controls retain their limited synchronous
I/O drain. The ceiling cannot be widened or have its lease requirement changed.
Concurrent explicit revocation is checked again before grant publication; failed
installation never publishes transient access. This remains a kernel integration
interface, not a qualified production policy or complete service ABI.

bip-data-issuer-vm-v2 passes storage-anchor, storage-mapped and approved with
SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS and unforced firmware shutdown.
The issuer test transfers the real descriptor to a nonbootstrap manager, closes
the bootstrap copy, and issues grants in capability mode to a separately observed
recipient. It verifies readonly and writable operations, exclusion of another
dataset in the same pool, action ceilings, mandatory leases, malformed requests,
software-issuer type checking, no onward transfer, locked fork/exec flags,
duplicate-close lifetime, last-close revocation, explicit revocation and lease
owner loss. Recipient fork remains unauthorized and surviving grant descriptors
do not defeat revocation. An ordinary UID-zero process cannot create a ceiling.
The initial v1 run failed because the new issuer fileops lacked DFLAG_PASSABLE;
the corrected file type permits the one transfer while per-descriptor limits
still reject subsequent transfer and inheritance.

Both kernel profiles and the maintained storage fixture build with 16 compilation
jobs. The existing build-bsd bootstrap path consumes the fixture; no optional
bypass is added. Host tests: 36 runner/evidence checks and 342 hook contracts.
Evidence verifies 3 cases/90 files. Receipt:
/usr/obj/usr/src/security-qualification/bip-data-issuer-validation-v2.json.
The production retained-access failure remains open. Dynamic child provisioning
still needs verified ancestry/classification and bounded management authority;
Capsule/SwitchBoard must consume authenticated policy, deliver ceilings and admit
the provider/workers before protected operations. The actual provider must issue
and retain client controls before publishing data descriptors. None of those
production lifecycle steps is supplied by this bounded kernel qualification.

### Live ancestry for serialized typed operations (2026-10-20)

mac_zfs_check_handle now receives an optional mac_zfs_ancestry (MAC ABI 22).
For an exclusive namespace-gate operation, ZFS walks actual dsl_dir parent
objects while holding the DSL configuration lock, resolves each head dataset's
object number and GUID, then releases all ZFS holds before invoking policy.
The exclusive outer gate prevents namespace replacement between this snapshot,
the policy callback and the operation. The array is dynamically sized from the
actual chain, ordered immediate parent through pool-root dataset. For snapshots,
the first ancestor is the owning head. It is valid only during the synchronous
callback; a policy must not cache it as future authorization.

A non-NULL zero-length chain means a complete pool-root dataset ancestry.
NULL means unavailable: pool handles have no dataset ancestry, and shared-gate
reads can overlap legacy mutations, so they do not claim a stable chain. The
existing exact held identity is still supplied. This explicit distinction is
required for future grant consumers: neither missing ancestry nor a matching
pathname permits a subtree grant. BIP continues whole-reserved-pool quarantine;
this change adds evidence to admission, not a management exception. Completing
shared-read stability is still required before general subtree delegation.

All existing resolved-object checks now carry this snapshot, including selected
snapshot and receive-target checks. Receive's initial presence lookup remains
separate from policy errors so a policy ENOENT cannot become a missing-target
create path. Failed ancestry lookup unwinds its holds and allocation before
returning; no partial chain is published. The observer records up to eight entries
with explicit availability, full count and truncation fields; that test-only
capture limit does not limit production ancestry or grant authority.

bip-ancestry-vm-v1 passes storage-anchor, storage-mapped and approved with
SecureBoot=1/SetupMode=0, WITNESS/INVARIANTS and unforced firmware shutdown. Tests
compare every expected ancestor's pool/object/GUID with independently queried
handles. They cover nested creation/publication, ancestor rename plus name reuse,
reparenting through a retained child handle, owning-head snapshot ancestry,
complete empty root ancestry and explicitly unavailable shared-read ancestry.
Existing property, namespace, stream, issuer, grant, lease and drain checks pass.
Both kernels, the matching ABI22 observer and the maintained fixture build with
16 compilation jobs. Host checks: 36 runner/evidence tests and 342 hook contracts.
Evidence verifies 3 cases/90 files. Receipt:
/usr/obj/usr/src/security-qualification/bip-ancestry-validation-v1.json.

Next integration work remains bounded management/property delegation and
classification/issuance for dynamically provisioned children, followed by the
actual authenticated Capsule/SwitchBoard/provider handoff. This ancestry callback
alone does not supply persistent boundary inheritance, subtree data grants,
resource quotas, session policy, post-exec admission or complete revocation drain.

### Policy-required ancestry on typed reads (2026-10-20)

The callback contract now provides MAC_ZFS_REQUIRE_ANCESTRY, an internal retry
result for checks that cannot authorize with unavailable ancestry. A shared typed
read receiving that result releases shared mode, acquires the namespace gate
exclusively, resolves current objects and reruns all MAC policies. Prior approval
is not carried over the unlocked interval. The requested read, handle-rights
checks and any capability-backed credential substitution follow successful fresh
admission. The exclusive gate then spans the read. This supplies stable ancestry
on demand without forcing all ordinary reads into the exclusive path or changing
native stream locking.

There is at most one retry. An unsatisfied request on the exclusive path, including
an unsupported pool relationship, returns EOPNOTSUPP rather than leaking an internal
restart result or looping. Existing MAC error precedence preserves real denials:
EPERM/EACCES dominate a retry request from another policy. A policy that grants
subtree access must request the stronger check when the initial ancestry is NULL;
it must not authorize from absence. This is not a general repair for unprotected
shared reads racing legacy namespace mutations. The earlier namespace comment
incorrectly claimed shared mode excluded every writer; it now states this limit.

bip-read-ancestry-vm-v1 passes all three requested Secure Boot cases with
WITNESS/INVARIANTS, unforced firmware shutdown and no panic or lock-order reversal.
The observer requests ancestry for real INFO and GET_ONE_PROP reads and records
the initial unavailable chain followed by a complete chain under exclusive mode.
Tests compare the ancestors with actual handles after name reuse and reparenting,
reject a second-check denial, and require a repeatedly unsatisfied retry to stop
after two callbacks. A nonbootstrap UID-zero process remains denied by BIP with
only one callback despite the observer requesting a retry. Existing namespace,
property, stream, issuer, grant and drain checks pass. The tests do not separately
force a mutation into the interval between shared release and exclusive acquisition.

Both kernels, the ABI22 observer and fixture build through maintained targets with
16 compilation jobs. The existing build-bsd bootstrap path includes the new tests.
Host checks: 36 runner/evidence tests and 342 hook contracts. Evidence verifies
3 cases/90 files. Receipt:
/usr/obj/usr/src/security-qualification/bip-read-ancestry-validation-v1.json.
No production management exception is enabled. The next grant implementation must
consume this ancestry contract, separately enforce property/value ceilings, and
classify dynamic descendants before the actual authenticated service handoff.

### Scoped management and property ceilings (2026-10-20)

BIP_STORAGE_DELEGATE_MANAGEMENT creates a distinct management issuer from an
actual registered mounted dataset. Bootstrap supplies immutable operation bits,
an optional subtree flag, an optional mandatory-lease flag and typed property
rules. The kernel copies and validates the rules; later edits to caller memory
cannot widen them. Integer rules specify an inclusive range; string rules require
an exact value. Duplicate names, invalid types/ranges/reserved fields, noncanonical
string padding and inconsistent rule/SET_PROP declarations are rejected. Native
ZFS property validation still applies at use. The rule-count bound is a protocol
allocation limit, not a path or software allowlist.

BIP_STORAGE_ISSUE interprets operation bits according to the issuer's immutable
kind. Management and data grants remain disjoint even where their numeric masks
overlap. A management grant never satisfies vnode data admission, and a data grant
never satisfies management admission. Both retain invocation/software binding,
applicable lease validity and independent issuer lifetime. Management grants have
no synchronous operation drain: BIP_STORAGE_REVOKE_IO returns EOPNOTSUPP without
revoking or claiming to drain them. Close and issuer revocation stop new admission.

Management checks match the actual object or, only when explicitly delegated,
its live ancestors against the issuer's pool/object/GUID. Read checks request the
bounded exclusive retry when ancestry is unavailable. Every resolved operand
still passes policy, and existing native handle rights/operation limits remain
in force. The command-to-operation mapping now lives once in zfshandle.h and is
used by both handle dispatch and BIP. Property admission separately receives the
same ancestry plus a typed kernel-owned property context. MAC ABI is 23; tracing
metadata and the test observer were updated. An initial compile exposed the old
aggregate tracing probe's argument limit; the typed context fixes that interface
without dropping any property or ancestry input.

The initial management mask covers selected metadata, filesystem namespace,
snapshot, rollback and anonymous mount operations. It excludes send/receive,
clone, promotion, property inheritance, bookmarks/holds, raw block access and pool
operations until their complete effects are bounded. ZFD_CREATE also accepts
volumes, whose size enters through the create request rather than SET_PROP.
The initial admission now distinguishes volume creation and denies it for these
management grants. Filesystem CREATE does not silently authorize unbounded volume
parameters. These exclusions are unfinished capabilities, not a replacement for
the complete system-security goal. Property rules constrain permitted setters;
they do not initialize an aggregate quota or dataset-count budget on their own.

bip-management-vm-v1 passes all three requested Secure Boot cases with
WITNESS/INVARIANTS and unforced firmware shutdown, without panic or lock-order
reversal. A real nonbootstrap capability-mode recipient receives an
invocation-bound management grant, creates nested filesystems, sets an allowed
refquota, rejects zero/above-ceiling quotas, and reads back the unchanged value.
It accepts the exact permitted mountpoint string and rejects a different value
and an undeclared property. Copying is verified by widening the original caller
rule array after factory creation: the kernel ceiling remains unchanged.
Filesystem creation, metadata reads, snapshot open/delete, rename and cleanup
work; volume creation and raw block access are denied. Another dataset in the
same pool remains outside scope. Bootstrap moves a retained child outside the
granted subtree and back; its reads/setters are denied outside and work after
return. A fork with valid software authority is denied. Explicit issuer revocation
stops management while its grant descriptor remains open. File pread/pwrite are
denied throughout, proving management does not imply data authority.

Both kernels, the ABI23 observer and maintained fixture build with 16 compilation
jobs. Existing build-bsd bootstrap steps consume the changes. Host checks: 36
runner/evidence tests and 342 hook contracts. Evidence verifies 3 cases/91 files,
now including the shared zfshandle.h mapping. Receipt:
/usr/obj/usr/src/security-qualification/bip-management-validation-v1.json.
This run does not individually qualify every bit in the initial management mask,
notably mounted-state lifecycle, rollback and enumeration under such a grant.
Production policy consumers, dynamic child data issuance/classification, provider
and client handoff, restart/reboot recovery and full draining remain unfinished.
The actual provider's retained-access failure remains open.

## Data admission before the first mount (2026-10-20)

Review of the actual provisioning path found a dependency that must be removed
before provider activation. ZFD_MOUNT authorizes the management operation, then
opens the root directory using the active recipient's credentials. BIP separately
requires data authority for that open. This is necessary: permission to manage a
dataset must not implicitly grant permission to read its files. The current
BIP_STORAGE_DELEGATE and bootstrap grant interfaces obtain resource identity
from an already mounted root directory and require an exact reservation. They
cannot admit a provider to a newly created, unmounted child. A subtree management
grant alone does not solve this dependency.

The next resource-issuance interface must accept a held TrustedZFS dataset handle
and obtain its live full identity and ancestry inside the kernel before mount
publication. It must validate a separate data-issuance ceiling, action subset,
required lease and observed recipient invocation. A management grant must not
manufacture data-issuance authority. A client-supplied GUID, cached INFO result,
path prefix, temporarily writable mount or implicit permission for the creating
process cannot stand in for that check. Descriptor references must be acquired
without introducing filedesc/namespace-lock inversion; ZFS holds must be released
before policy allocation and authority binding.

Child classification and the effect of subsequent movement must be implemented
with that interface. Do not publish a descendant grant based on a one-time
ancestry check while claiming that it follows live subtree membership. Existing
vnode admission reads immutable mount identity and policy state; it does not walk
ZFS ancestry under vnode locks. Classification must remain protected after parent
issuer loss, and reboot must reconstruct it from authenticated policy. Provider
restart and stale child descriptors remain required acceptance cases.

The maintained storage fixture now exercises management/data composition on an
existing registered dataset. A capability-mode recipient with only management
permission cannot obtain its root directory through ZFD_MOUNT. A separate
invocation-bound, lease-bound READ/LOOKUP/STAT grant permits joining the anonymous
mount, opening the existing file and reading it. Writes and file creation remain
denied. Closing only the data grant immediately denies retained directory stat
and file reads; the still-valid management grant permits dropping its mount
anchor. A later mount attempt is denied again. These are actual kernel checks,
not fixture-side permission simulation.

bip-mount-grants-vm-v1 passes storage-anchor, storage-mapped and approved. The
follow-up bip-mount-grants-vm-v2 runs the affected storage-anchor case with an
additional first-mount denial on a newly created child; later destruction proves
that failed directory publication did not leave a busy mount anchor. This is a
negative child test, not successful child admission. Each run uses Secure Boot,
WITNESS/INVARIANTS and clean firmware shutdown. Evidence and source bindings are
recorded in bip-mount-grants-validation-v2.json. The existing build-bsd bootstrap
step builds the changed fixture; the runner requires the new completion marker
exactly once, and 36 host runner/evidence tests pass. No new kernel exception or
shipping policy format is introduced. Dynamic child issuance and actual service
activation remain unimplemented, and the real provider failure remains open.

## Exact data issuance from a reserved handle (2026-10-20)

ZFD_BIP_DATA_ISSUER now lets the original bootstrap process create an exact-dataset
data issuer before mounting the dataset. ZFS resolves the held live filesystem
under the exclusive namespace gate and releases DSL holds before invoking policy.
The request supplies action bits and flags, never a dataset GUID or pathname.
Snapshots, volumes and pool handles cannot use this factory. The BIP consumer
requires an exact existing reservation and accepts only data action bits and the
optional mandatory-lease constraint. Subtree flags are rejected. The resulting
issuer uses the same invocation-bound grant creation, separate lease lifetime,
once-only transfer, fork/exec restrictions and revocation state as the existing
data issuer. Both factories share one issuer-file allocator.

Policy prepares an uninstalled file. The MAC framework installs its descriptor
only after every policy succeeds; a denial or installation failure drops the file.
A kernel without a consumer returns EOPNOTSUPP. Management grants do not authorize
this command; even a valid nonbootstrap manager is denied. MAC ABI is 24; the
observer and tracing contracts were rebuilt. The operation does not mount,
classify descendants, or automatically register its target. It does not bypass a
handle's Capsicum ioctl limit: bootstrap acquisition must create the needed
issuer before handing out an ordinarily restricted handle.

bip-premount-vm-v1 passes storage-anchor, storage-mapped and approved under Secure
Boot and WITNESS/INVARIANTS, with clean firmware shutdown and no observed panic or
lock-order reversal. The bootstrap fixture creates a fresh child and proves that
issuer creation fails before exact reservation and rejects a subtree flag. It
then creates the issuer without ever mounting the child. A separately admitted
recipient performs its first anonymous mount, creates a file, writes and reads
verified content. The child data grant cannot authorize writes to the parent
dataset. A fork with valid software attribution remains denied. Revoking the
parent's distinct data grant does not revoke the child grant; revoking the child
issuer then denies retained child reads/writes and a new mount. Management still
permits cleanup and destruction. Required-lease omission and nonbootstrap issuer
creation are denied. The maintained runner requires the new marker exactly once.

The two kernels, fixture and observer build with 16 jobs. Existing build-bsd
kernel/bootstrap steps consume them; no test-only permission switch or new
shipping policy is introduced. Host checks: 36 runner/evidence tests and 343 hook
contracts. The receipt is bip-premount-validation-v1.json, with source and VM
bindings. These remain mechanism tests. They establish first-mount admission for
a bootstrap-selected, exactly registered child, not delegated dynamic child
classification or production provider activation.

The next production path must select/register child state from authenticated
policy and bind the actual provider, worker and client invocations. It must also
resolve how child movement affects a delegated issuance ceiling. This factory
has exact object scope, so it makes no claim of live subtree data authority.
Capsule's prepare/derive path does not yet consume it, and the real provider's
retained-access failure remains open. Installed startup, upgrade/rollback/removal,
recovery, key lifecycle and hardware qualification remain unfinished.

## Production request attribution (2026-10-20)

BSDFilesystem now captures the kernel's BIP enforcing state at startup and carries
that immutable startup decision into workers. There is no policy-file override.
Its real FIDL adapter preserves the native channel's process identity, execution
nonce and software-authority stamp alongside UID/GID. Before any storage, open,
list or version dispatch, BIP requires nonzero process/nonce/issuer/identity/
generation and a valid supported software stamp with reserved fields clear.
Missing or inconsistent attribution is rejected with EACCES, including for UID
zero. The provider copies the attribution for the current request, rather than
retaining pointers to the transport message or reusing the first connection's
invocation. Both denied dispatch and unrepresentable FIDL input clear old actor
state. Mutable UID/GID continue to describe file ownership; they need not equal
the software stamp's UID and do not supply BIP authorization.

This is request attribution, not a storage grant or proof of current authority
liveness. A queued stamp can outlive the authority state it described. Grant
creation must still obtain the actual live issuer/token/lease binding. A provider
forwarding these copied fields to SwitchBoard does not make them kernel-stamped
metadata on that second channel. Production client activation must use an
independently observed client invocation or a kernel-verified delegation witness;
it must not trust identity numbers merely because they arrived in an RPC payload.

The actual daemon and focused tests build with 16 jobs. sender_required and
bip_sender_required pass. The latter covers eleven absent/malformed attribution
forms across all four dispatch shapes (44 negative combinations), with UID zero,
then verifies successive invocation capture, copied stamp ownership and clearing
on an invalid FIDL representation. These negative metadata tests use synthetic
transport inputs against the real dispatch/adapter functions; they are not claims
of adversarial kernel-metadata injection in a running VM. The existing 36 runner/
evidence tests pass, and the maintained VM input manifest now includes the actual
provider startup, state and request sources. Existing build-bootstrap.sh compiles
the changed daemon; no test-only permission option is introduced.

bip-provider-actor-v2 runs the real signed provider under Capsule and SwitchBoard
on the MAC-24 Secure Boot kernel. The normal UNIT/CACHE/SHARED/GROUP creation,
write/fsync, release, reopen, byte verification and stat checks complete before
the unchanged client fails its first namespace-denial assertion. All twelve
unauthorized retained read/write/open/create/truncate/mode operations still
succeed after fork and after authority clear. The run is FAIL, cleanup is forced,
and reboot qualification is skipped. No panic or WITNESS reversal is observed.
The receipt bip-provider-actor-validation-v2.json retains hashes and explicitly
records failure. This demonstrates the valid attribution path in production;
it does not establish working mandatory storage grants.

Next integration still requires authenticated resource/property ceilings,
Capsule reservation before delivery, observed provider/worker admission, trusted
child selection/registration and independently bound client data grants before
publication. Exact pre-mount issuer creation is available in the kernel but is
not yet consumed by this path. The real-service milestone remains open.

## Enforcement map against the current source

| Surface | Current source/interface | Required integration |
|---|---|---|
| Boot storage delivery | capsule/protected_storage.c prepare/derive | Register authenticated boundaries before deriving recipients; grants tied to admitted recipient incarnation |
| Handle operations | zfs_handle.c zfshandle_ioctl, cmd_op, cmd_right | Check live grant and boundary for every affected backing identity in addition to immutable handle rights/op ceiling |
| Child/open/create | zfshandle_op_openat, child minting, create | Resolve actual target identity, preserve classification, publish no handle before checks finish |
| Clone | zfshandle_op_clone | Check both source snapshot and destination namespace; ZH_CLONE_SRC/ZFD_OP_CLONE_SOURCE alone are not revocable BIP authorization |
| Rename/promote | rename/promote operations and namespace gate | Check all affected parents, datasets and classification changes; no movement across protection boundaries by ordinary handles |
| Send/receive | zfshandle_op_send/recv and existing name-based MAC hooks | Identity-bound source/destination checks, derived stream effects, replacement flags, cancellation and inheritance |
| Snapshot/rollback/destroy | snapshot and lifecycle operations | Separate management authority; ordinary data-write authority cannot restore old policy/data or delete retained state |
| Pool/raw/volume paths | pool operations, BLKOPEN, device admission | Prevent alternate backing access; account for descriptors issued before confinement and imported/received storage |
| Anonymous mounts | new mount admission, cached join, orphan adoption | Establish/check boundary before any root descriptor or compatibility attachment is published |
| File content and metadata | MAC vnode hooks and active credentials | Check current invocation/grant on descriptor operations, not only pathname lookup or open |
| Namespace effects | link/unlink/rename/create hooks | Check source and destination objects/parents; preserve child boundary membership |
| Mappings and file handles | mmap, swap, fhopen/NFS paths | Reject unsupported bypasses; mapping revocation cannot be claimed from a one-time mmap check |
| Provider teardown | supervisor lifecycle, token/lease close | Revoke access while retaining storage classification; restart requires new admission |

Existing zfshandle_ioctl validates fixed rights and operation ceilings but does
not attach these operations to a live service/session grant. Several individual
verbs call name-based MAC hooks. A new generic handle check alone would still
miss clone's second handle and descendant targets unless those are integrated.
The namespace gate protects object-to-name resolution, not user authorization.

The regular file isolation implementation checks active credentials on reads
and writes, but claims disappear when their owner is revoked/closed, directory
claims are not recursive, and already-readable mappings cannot be retracted.
Reusing its action vocabulary may be appropriate; reusing that lifetime model
for persistent BIP is not.

## Execution-membership regression status

The CAP_AUTH_CLEAR cache bypass was reproduced: a process that cleared its
software authority could still read through a retained file descriptor after
activating a bound isolation token. The implementation now captures a kernel-only
software/invocation snapshot before taking isolation locks and compares cached
grants to it. This avoids adding a process-lock acquisition inside the claim or
authorization-table lookup. Issuer and authority identities are never recycled;
no process/authority pointers survive in the snapshot. Token/issuer revocation
and lease lifetime are checked when the snapshot is compared with the instance.

The unchanged regression fails on the previous kernel and passes on the fixed
GENERIC-NODEBUG kernel, including the unaffected parent's continued access and
subsequent authority revocation. Evidence is isolation-context-validation-v1.json.
A subsequent WITNESS/INVARIANTS VM also passed without lock warnings;
isolation-context-validation-v2.json records the corrected issuer allocator and
that result. Issuer IDs now come from a non-reusing boot-local counter, with
exhaustion rejected; the prior random allocator did not prove nonreuse.
Invocation-bound file-token fork/exec now has direct coverage: an unchanged
helper reproduces a retained-read bypass after fork on the prior kernel and
passes on the fixed WITNESS/INVARIANTS kernel. Both transitions deny activation
and retained reads while software authority remains valid; the admitted parent
still reads after the denied fork. Evidence is isolation-invocation-validation-v1.json.
Other isolation resource types require additional direct coverage. These snapshots
admit an operation at a point in time; they do not drain already admitted I/O
when a concurrent authority transition completes. Persistent boundary retention
and the stronger lifecycle contract remain separate unfinished requirements.

## Backing reservation implementation

ZFD_BIP_RESERVE is an explicit bootstrap operation on a held subtree dataset
handle. The kernel resolves the held full identity under the TrustedZFS namespace
gate; the caller supplies no name or GUID. Only the original PID 1 may register
under BIP. With no policy consumer the framework returns EOPNOTSUPP, never a
false success. The built-in policy stores pool GUID, dataset object and dataset
GUID in records that survive descriptor closure and unmount until reboot.
Duplicate identity is idempotent; conflicting object/GUID reuse returns ESTALE.
Records hold no filesystem references. The policy mutex spans no filesystem I/O.

At this stage a reserved pool's TrustedZFS management operations are denied to
nonbootstrap actors, including through earlier handles. Clone checks its second
operand separately. This is deliberately a management quarantine pending
explicit grants, not a subtree data-access policy. Descriptor housekeeping and
rights attenuation remain possible. The production Capsule path does not call
registration yet. Registering there before management grants and lifecycle integration
exist would stop the provider;
do not hide that missing integration with a UID, signature or executable-name
exception.

The Secure Boot WITNESS/INVARIANTS fixture passes original functional storage
checks first, then closes its bootstrap anchors, tests rejection of child
registration, registers twice, mounts and reads as bootstrap, closes all storage
descriptors and unmounts, reopens, and checks root/non-root management denial.
An ordinary-kernel VM separately requires EOPNOTSUPP without BIP and continued
ordinary handle use. Both guests terminate cleanly without lock warnings.
Evidence: bip-reservation-validation-v1.json. That qualification used MAC ABI 13;
the later mount-label work below uses ABI 14 and rebuilt matching modules.

The initial reservation result alone did not establish retained-vnode mediation.
The subsequent vnode/mapping gates below provide bounded additional coverage.
Complete raw/pool path coverage, ancestry-based classification, management
grants, concurrent teardown and production policy consumption remain open. The
real provider's retained read/write regression remains an open failure. No part
of the complete boundary/grant gate is marked finished from this fixture.

## Mount identity and retained-vnode quarantine

ZFS now supplies its full pool/dataset object/dataset GUID tuple to MAC before
mount publication, including anonymous mounts. BIP copies those values into a
mount label, with a reference to its permanent in-memory pool record. Destruction
frees only mount metadata; it performs no filesystem I/O and never removes the
reservation. Every checked vnode operation consults current reservation state,
so a previously mounted filesystem or retained descriptor is not grandfathered.
An unlabelled ZFS mount is denied under BIP rather than treated as ordinary data.

The initial data policy quarantined the entire reserved pool for nonbootstrap
actors. The experimental grants described above now provide exact-dataset
exceptions; final descendant classification and production grants remain open.
Checks cover content and metadata, traversal, new opens, namespace changes,
execution and mapping admission. sendfile also invokes the MAC source-read
check before obtaining pages; its former path checked only the output socket.
The fixture verifies positive transfer before reservation and denial afterwards.

New mappings of reserved storage are denied even to bootstrap. Before reservation,
mapping admission records exposure permanently for that boot. Registration then
returns EBUSY, including after unmap/unmount, because the kernel does not prove
all previous mappings have disappeared. This conservative rule is not mapping
revocation. Bootstrap must classify storage before publishing it. Registration
and mapping admission serialize on the same policy mutex. Already admitted I/O
is not drained by this mechanism; the stronger grant-revocation contract remains.

bip-vnode-vm-v1 passes the retained-vnode and separate storage-mapped Secure Boot
cases with WITNESS/INVARIANTS and actual firmware shutdown. The unchanged helper
fails its first retained-read denial on the preserved MAC-13 kernel. The ordinary
kernel still rejects unsupported registration and permits ordinary handle use.
Evidence: bip-vnode-validation-v1.json. MAC ABI 14 requires matching modules.
The full build-bsd anchor test profile includes both cases; the independent
verifier rechecks their operation markers and shutdown rather than treating them
as host-terminated Capsule cases.

There are still no production registration callers or scoped service/session
grants. The real provider regression below remains unresolved. In-flight drain,
provider restart, full backing/alias coverage and complete namespace/mapping
coverage require further implementation and tests; the exercised operations are
not an all-path proof.

## Real provider baseline

storage-retained-vm-v3 runs the production Capsule, SwitchBoard and BSDFilesystem
with a signed test client under enforcing Secure Boot. Its child retains a file
descriptor into private UNIT state, clears software authority, verifies invalid
membership, then attempts pread and same-byte pwrite. Both return one byte. The
parent remains admitted and completes the four storage-scope functional checks.
The acceptance test fails at the required denial assertion; evidence is
storage-retained-validation-v1.json. This fixture now prevents a functionality
pass from concealing the missing persistent authorization layer. It is not a
passing BIP service or a complete restart/revocation qualification.

### Real provider integration audit and fork baseline (2026-10-20)

bip-provider-admission-vm-v1 repeats the real Capsule/SwitchBoard/BSDFilesystem
workflow on the MAC-20 kernel. The child first proves its inherited software
attribution is valid, then attempts retained pread/pwrite before CAP_AUTH_CLEAR,
clears authority and repeats both operations. All four unauthorized operations
return one byte. The authorized parent completes actual UNIT/CACHE/SHARED/GROUP
creation, fsync, release, reopen, content verification and stat before the first
required denial assertion fails. This is a strengthened failing acceptance gate,
not permission to treat software inheritance as invocation admission. The
observer reports each phase independently; completion requires both denials and
rejects missing, duplicate or contradictory evidence. No second boot is accepted
after a failed first boot.

The same audit found a UID/GID-zero fallback when BSDFilesystem's internal request
adapter lacks sender metadata. Request dispatch now rejects that condition with
EACCES before all request variants. The focused test exercises the real dispatch
function with missing attribution for ordinary, open, list and version requests,
and verifies a stamped ping still succeeds and supplies its actual credentials.
This fixes fail-open error handling; it does not implement BIP authorization.
Normal FIDL requests already carry transport attribution, so no claim of a
remotely reachable missing-metadata exploit is made.

| Actual first-service path | Current behavior | Required production integration |
|---|---|---|
| capsule/protected_storage.c: prepare/derive | Retains and derives the configured handle; does not reserve a persistent BIP boundary | Register the authenticated root before delivery; keep a separate bounded delegation capability |
| BSDFilesystem/bsdfilesystem.c: startup | Acquires storage-root after service_acquire, then provisions before service readiness | Admit the observed final provider invocation before layout I/O; readiness is too late |
| BSDFilesystem/layout.c: layout_provision_fd | INFO/STAT, mountpoint/canmount, child open/create, ephemeral sync and generation reconciliation | Live subtree scope plus property/value-specific ceilings and lifecycle policy |
| BSDFilesystem/request.c: serve/worker | pdfork per client; inherited handles remain; worker shields and drops service descriptors | Explicit worker admission tied to its supervisor and connection, before protected management |
| libservice.c: service_worker_drop_inherited_authority | Closes inherited service control/capability descriptors; does not CAP_AUTH_CLEAR software attribution | Do not confuse descriptor cleanup with software revocation or worker BIP admission |
| BSDFilesystem/request.c: fs_run/grant | Adapter now preserves and checks request attribution under BIP; opens/creates the claim, sets refquota, mounts/chowns and delivers a directory without a data grant | Independently observe the client at the issuer; issue data grant before publication; provider management and client data rights are distinct |
| BSDFilesystem/layout.c: reaper and cleanup | Separate child reconciles persistent namespaces; boot cleanup destroys ephemeral/staging objects | Explicit lifecycle actor/ceiling and worker admission, not blanket inheritance of provider power |

At the time of this integration audit, the generic ZFS handle admission hook
carried command, identity and role but no property name/value. The typed property
hook added above now supplies those inputs; production ceilings remain absent. zfshandle_op_set_prop delegates to the normal ZFS
property pipeline, which validates property semantics but does not enforce a BIP
resource issuer's permitted properties/values. Granting ZFD_SET_PROP wholesale
would not establish the required ceiling. This must be fixed before enabling
provider management. Likewise promotion affects other objects; its current
single-handle check cannot establish complete scoped transaction authority.

Implementation order stays focused on this service: bounded resource delegation
and live ancestry; property/value admission for its provisioning operations;
post-exec provider/worker activation and independently bound client data grants;
then real retained-access/restart/reboot qualification. Broader stream mechanism
coverage must not substitute for these missing consumers. Unsupported operations
must fail explicitly until their effects are covered, and that restriction must
be reported as missing functionality rather than silently disabling an acceptance
test. Authenticated compiler/runtime policy and complete operation draining remain
required gates.

Receipt: /usr/obj/usr/src/security-qualification/bip-provider-admission-validation-v1.json.
SecureBoot=1/SetupMode=0, no panic/WITNESS reversal; host cleanup was forced after
the failed acceptance assertion. The production daemon and client/observer were
rebuilt under /usr/obj with 16 jobs; focused sender_required and 35 host evidence
tests pass. Existing build-bsd bootstrap steps build the daemon and both test
programs; no new option or test exception is added. This does not qualify normal
installed startup, shutdown, upgrades, recovery or production key lifecycle.

## First implementation and review gates

1. Define kernel boundary ownership, lock ordering and destruction rules, with
   identity/ancestry registration before descriptor publication. The recorded
   ZFS/filedesc WITNESS issue remains unresolved and must inform lock review.
2. Implement boundary retention and a bounded grant lifecycle using the actual
   supervisor identity path. Test loss/restart, stale grants and retained FDs.
3. Integrate all backing effects reachable by the first service, including its
   alternate/multi-object paths. Unsupported effects are denied explicitly.
4. Compile and authenticate the matching state/launch policy; integrate its
   consumers into build-bsd's normal generation and boot workflows.
5. Run the real BSDFilesystem persistent-container operation and client I/O in
   Secure Boot VMs, alongside denial and failure/recovery tests. Then extend to
   legacy startup paths and the full installed-system workflow matrix.

Do not add a production-disable switch or a writable whole-/var fallback to get
the first service running. A mechanism fixture can supply controlled faults and
identity stimuli, but cannot replace the actual service milestone. No gate above
is complete merely because this contract has been written.


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


### Worker scope review: prerequisite to admission (2026-10-20)

The worker failure in bip-provider-activation-v2 cannot be resolved by repeating
the original-provider grant for every fork. request.c forks with the complete
bsdfilesystem_state and keeps its global storage handles. Its scoped_ns and
container_ns functions restrict normal requests in userland, but those checks
are not a kernel boundary against a compromised worker. A provider-root grant
would authorize that worker over other clients' datasets. This is an unresolved
compartment boundary, not merely a missing RPC.

The current private worker channel is also not an admission route to the manager.
handle_worker_channel returns both ends to the provider, and libservice attenuates
one end for a single fork. SwitchBoard retains neither endpoint. Reusing this
operation as if it authenticated a worker to SwitchBoard would be incorrect.
Workers need an explicitly nominated admission route, an independently observed
invocation and exit/teardown tracking. A PID copied through a provider message is
not the required observation. A typed process descriptor may supply exit tracking;
its relationship to the kernel-stamped sender must be verified before admission.

The existing identity inputs already determine the allowed namespace shapes:

| Namespace | Authoritative selection | Required management boundary |
|---|---|---|
| Unit durable/cache | Stamped bundle/unit container | That unit's persistent/cache roots |
| Bundle shared | Stamped bundle | That bundle's shared roots |
| Group durable/cache | Stamped membership list, validated group component | Only the selected authorized group roots |
| Boot/session ephemeral | Stamped resource owner and current generation/session | That owner's selected ephemeral roots |
| Reconciliation/reaper | Separate supervisor lifecycle policy | Explicit cleanup roots; never inferred from a client grant |

These names select objects during trusted provisioning; runtime protection must
use held identities and live ancestry, not pathname-prefix comparisons. The
supervisor must create/open the selected roots before granting management to the
worker. No bundle or group membership may be inferred from UID zero, the worker's
executable name, or strings in its untrusted requests.

At the time of this initial review, management grants could not be narrowed to
a descendant issuer. The scoped management issuer implementation and VM evidence
below supersede that gap. Worker admission and selected namespace views are
still unfinished. Every
operation must remain inside both the derived scope and its original scope under
current ancestry. Moving the derived root outside the original scope must stop
access; retaining a parent state reference must not keep its owner file alive.
A bounded ancestry/issuer chain is necessary for resource accounting. Data
issuance remains separate and must not be implied by this management attenuation.

Required qualification before calling worker admission complete: legitimate
operations in the selected unit/shared/group/ephemeral roots; sibling and
unassigned-group denial; copied/stale identity rejection; operation/property
attenuation; fork/exec rejection; worker exit and provider/manager loss;
reparenting/replacement; retained handles after revocation; and independent
client file-data admission. The existing failed client-open test stays enabled.
No worker-root bypass, automatic software-wide grant, or removal of worker
isolation has been implemented. This review changes the next implementation
step; it does not claim new runtime protection or a passing service gate.

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

### Worker namespace integration review (2026-10-20)

Source review after the scoped-issuer VM pass found a second integration
requirement: worker operations start from broad parent handles. Adding a narrow
grant alone still denies the initial parent traversal. The implementation order
is therefore selected namespace views, independent worker admission, then data
admission and lifecycle qualification. Source hashes and native regression
results are recorded in
`/usr/obj/usr/src/security-qualification/bip-worker-integration-review-v1.json`.
This review is not a passing real-service test.

| Request path | Existing broad traversal | Required change |
|---|---|---|
| Request/open/create | `grant` selects persistent, boot or lease parent and walks names | Supervisor prepares selected namespace handles; worker creates/opens claims directly under them |
| List | `grant_list` and `list_collect_ns` reopen persistent/cache paths from Data | Enumerate only the two selected scope handles; preserve missing namespace semantics |
| Stat, quota, destroy, unmount | `tzfs_request` reopens a namespace from Data or lease parent | Use the same selected namespace resolver as claim creation |
| Snapshot, rollback, version open | `open_own_claim`, plus lease traversal for version clones | Resolve source and destination from independently authorized selected handles |
| Transactions | `open_own_ns` supplies a broad-path-derived parent for sibling operations | Restrict source, staging and destination to the selected namespace; separately qualify currently unsupported clone operations |
| BeginSession | `bsdfilesystem_session_begin` creates beneath the global ephemeral parent | Supervision validates lifecycle selection; a client hex string is not an authorization lease |
| Connection cleanup | `conn_reap_ephemeral` reopens from the broad lease parent | Retain selected cleanup scope with independent lifetime; client revocation cannot preserve client access for cleanup |
| Background reconciliation | `bsdfilesystem_start_reaper` creates a distinct forked actor | Separate explicit cleanup admission, never a client or provider software-wide grant |

A namespace view must cover unit/shared/group durable and cache roots, plus the
selected boot/session owner roots. Source identity is the manager-stamped client
assignment. Names select objects during provisioning; live held identities and
issuer ancestry enforce runtime access. Invalid/unassigned entries must fail;
there is no broad-root fallback. The change must preserve readonly-open and
missing-namespace behavior and close partially prepared views on failure.

The existing worker channel cannot serve as manager admission: SwitchBoard sends
both endpoints to the provider, and libservice disallows creating it after the
provider enters its sandbox. Add a distinct nomination/admission flow tied to
one provider launch and client assignment. Worker identity must come directly
from kernel-stamped messages. Match a held process descriptor to that sender
and watch exit before enabling grants; reject foreign, exited, replayed and
post-exec identities. Test the existing process-descriptor primitives before
adding a new kernel identity API. Keep FD counts and types specific to each
new opcode; do not remove the existing global framing rejection for other RPCs.

During review, a concrete session-transition bug was fixed: failed replacement
previously closed the old lease handle while retaining its old name. The code
now acquires the replacement before committing the descriptor/name switch.
`session_failure_preserves_state` reproduced four failed preservation assertions
before the fix and passes afterward against the actual production function.
The production provider builds. This native failed-ioctl regression does not
prove successful ZFS session replacement or authenticated session policy.

The next integrated VM gate must exercise all namespace families and operations,
worker exit, provider/manager loss, retained descriptors, partial admission
failure, session replacement failure and independent cleanup. The latest real
service run still fails its first legitimate open; it is not superseded by this
source review or native regression.

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


### Data admission review and next implementation gates (2026-10-20)

Status: reviewed design requirements; the mechanisms proposed in this section
are not implemented or qualified. The real-service gate remains failed at its
first data open. This section does not authorize a broader management grant as
a workaround.

The source review establishes three distinct facts:

- `storage_vnode_check()` in `mac_system_integrity.c` consults the reserved pool
  on every protected vnode operation and accepts only an exact data grant for
  the mount's pool/object/GUID and current invocation. Pool reservation already
  quarantines newly created children. A separate child reservation is not needed
  merely to deny unauthorized data access; fine-grained classification remains
  unfinished.
- `storage_create_data_issuer()` only accepts bootstrap and an exactly registered
  filesystem. Management derivation cannot produce a data issuer. Capsule's
  storage configuration currently has management ceilings but no independently
  expressed data delegation policy. Dynamic child admission therefore needs an
  explicit policy and a new factory path, not an exemption from quarantine.
- `naming.c` binds the client channel to the directly observed invocation and
  session, then forwards the provider endpoint and lifecycle notification.
  Worker preparation currently supplies selected handles and management verbs;
  it does not reference a manager-owned client data authorization record.
  Forwarded numeric process identities or copied notification fields cannot
  substitute for that missing record.

Implement and qualify these gates in order:

1. **Independent data delegation.** Define an explicit authenticated data scope
   and operation ceiling alongside management policy. Absence denies delegation.
   A data-scope factory must be a distinct issuer kind: it may derive narrower
   factories or exact data issuers, but cannot directly create actor grants.
   A management issuer must never convert into either. Bootstrap creates the
   root factory only on an exactly reserved held live filesystem. Derivation
   checks actual ZFS ancestry under the namespace gate, every ancestor ceiling,
   operation attenuation, mandatory lease propagation and revocation. Validate
   the issuer's descriptor rights and ioctl allowlist from one retained snapshot.
   Reject snapshots, volumes, unknown modes and unknown flags. Return no installed
   descriptor until every mandatory policy approves.
2. **Trusted client association.** At actual broker lookup, retain a bounded
   record of the directly observed client software/invocation, authorization
   session, provider launch and permitted resource selection. Give the provider
   a connection reference whose use is checked against that provider launch;
   numeric record IDs alone confer no authority. Worker nomination must refer
   to this record. Verify that nominated scopes and requested operations are
   within its policy. Do not accept worker assertions of client PID or nonce.
   Define record retirement and resource exhaustion before enabling this path.
3. **Separate actor admission.** Derive exact claim issuers only after checking
   the connection assignment. Admit the worker and client independently, each
   with the minimum needed data operations and its own observed invocation.
   Retain grant controls in the manager. Required session leases must be real
   authorization leases; no fabricated deadline or unleased fallback. A failed
   multi-grant operation must unwind every partial grant and descriptor.
4. **Lifecycle and movement semantics.** Exact data grants currently follow
   object identity, while management grants recheck live ancestry. Before
   enabling delegated data scopes, decide and test whether moving a claim
   preserves existing data grants or requires their revocation. Do not promise
   live ancestry enforcement from a creation-time check, and do not introduce
   ZFS ancestry traversal under vnode/storage locks without a locking design.
   Define behavior for worker/client exit, exec, session cancellation, provider
   restart, manager loss, dataset destruction and object-number reuse.
5. **Build and evidence.** Update the shared ABI, policy parser, Capsule,
   SwitchBoard, libservice, provider and maintained build/test inputs together.
   Compile both kernels and matching probes. First qualify the new factory and
   denial paths under Secure Boot; then run the existing real-service test
   unchanged through write/read, unauthorized retained descriptors, restart and
   reboot. Keep failed runs and input hashes. A new mechanism pass cannot replace
   this service gate or the later installed-system and update gates.

Required adversarial cases include management-to-data conversion, direct grant
issuance from a scope factory, scope/action/lease widening, wrong-pool and
out-of-scope handles, reparenting, revoked intermediate factories, final parent
close, restricted ioctl rights, stale or foreign connection references, provider
replacement, client fork/exec/exit, partial issuance failure, manager loss and
object reuse. Positive tests must demonstrate legitimate persistent access
alongside each applicable denial. No build tool change is needed for this review
alone; production consumer changes must update the maintained build path when
implemented.


### Data-scope kernel factory (2026-10-20; qualification in progress)

MAC ABI 27 adds `ZFD_BIP_DATA_SCOPE` and `ZFD_BIP_DATA_DERIVE`. The former
is bootstrap-only on an exactly reserved live filesystem. The latter consumes
a held live filesystem and a data-scope issuer, with an explicit result mode:
a narrower scope factory or an exact data issuer. Scope factories cannot issue
actor grants; exact data issuers cannot derive. Management issuers cannot enter
this path. This is a kernel mechanism; Capsule data policy and production
broker/client consumers remain unimplemented.

Derivation shares the existing descriptor/attenuation implementation with
management derivation. It checks the source descriptor's ioctl rights from the
retained file-capability snapshot, full live ancestry under the exclusive ZFS
namespace gate, all ancestor ceilings, actions, mandatory leases and depth.
A copied immutable parent-state reference keeps ancestry valid without keeping
the parent file open: final parent-file close or explicit revocation invalidates
descendants. All MAC policies must approve before a descriptor is installed.
Snapshots and volumes are excluded; invalid modes, flags and reserved fields
are rejected. Pool quarantine remains independent of issuer lifetime.

Data grant scope is explicitly object-bound. Derivation checks membership at
that instant; a subsequent rename or reparent does not itself revoke an exact
issuer or data grant. New derivation through a moved scope still checks all
original ancestors. This differs from management operation admission, which
checks live ancestry on every operation. A policy that intends a move to withdraw
existing data access must revoke the relevant issuer before that move; it cannot
rely on path movement alone. Production move/transfer policy remains unfinished.
No ancestry lookup is introduced into the vnode data-admission lock path.

Both kernels and the matching storage probe/observer build through maintained
targets using all 16 logical CPUs. Generated tracing metadata checks 347 hook
contracts. All 39 runner/evidence tests pass, including omission/duplication
checks for the new marker. VM qualification is in progress; no pass is claimed
in this entry. No host installation or reboot has occurred.


### Data-scope VM qualification (2026-10-20)

`bip-data-scope-vm-v2` passes `storage-anchor`, `storage-mapped` and `approved`
with Secure Boot and the MAC-27 kernel. The maintained verifier checks 110 files,
including source inputs, kernel/module/probe artifacts and retained VM evidence.
The guests shut down normally; the storage run reports no panic, fatal trap or
WITNESS lock-order reversal. This does not resolve the separately recorded host
ZFS/filedesc reversal.

The fixture creates a child without an exact reservation, derives a narrower
scope and exact issuer using its held identity, and admits a nonbootstrap
recipient. That recipient mounts it for the first time, creates a file and
writes/reads its contents. A fork cannot use the parent's data authority. Closing
the root factory denies retained reads/writes and further issuance while
management remains available for cleanup. Direct issuance from scope factories,
management/data conversion, operation/lease/subtree widening, out-of-scope
selection and restricted ioctl use are rejected. Nonbootstrap root-factory
creation is denied. Exact bootstrap-factory validation remains on a separate
dataset, so it cannot mask the dynamic-child path.

A held mounted child is moved outside the original scope. Existing exact data
reads/writes still succeed, management access is denied, and new derivation
through the moved intermediate scope is denied. Moving it back restores
management and permits derivation. This qualifies the documented object-bound
data semantics; it does not implement production transfer policy.

V1 also passed and was verified before further edits, but its fixture added an
exact child reservation before actual data use. V2 removes that coverage gap and
adds the movement checks. V1's retained receipt remains historical evidence;
its recorded probe/runner inputs are intentionally superseded by V2.

The build-bsd Secure Boot path already invokes the maintained storage fixture
and matching observer build. No additional target or alternate build location
was introduced. Summary receipt:
`/usr/obj/usr/src/security-qualification/bip-data-scope-validation-v1.json`.

This remains a kernel prerequisite. Capsule data-scope policy, independent
client association and production worker/client grants are not implemented.
Additional data-specific adversarial cases include capability-mode delegation,
explicit intermediate revocation, races and wrong-object/reuse cases. Shared
management tests do not substitute for those data cases. No new real-service,
installed-system, update or hardware acceptance follows from this result.


### Capsule data policy and handoff (2026-10-20; qualification in progress)

Storage assignments now accept an independent optional `data` object:

```ucl
data = {
    operations = [lookup, stat, read, write, create];
    subtree = true;
    require_lease = true;
};
```

This illustrates syntax, not a default grant. All three fields are required when
`data` is present. Omission grants no data delegation. Operations name individual
supported data actions: lookup, stat, read, write, create, delete, rename_from,
rename_to, link, setattr, truncate and uipc_connect. Exec, append, management
verbs, duplicate operations, unknown fields and malformed boolean values are
rejected. The parser applies changes atomically, and the authenticated boot-policy
comparison includes the data ceiling. Data and management operations/flags do
not inherit from each other. A data-only assignment is valid.

Bootstrap validates the selected pool/dataset GUIDs, name, held native rights
and subtree-handle type before reserving storage and creating the factory. It
validates configured factories before completing preparation; partial failure
closes handles but cannot undo reservations. Private anchors retain the factory
ioctl; ordinary derived handles receive their native ioctl limits. No issuer
file is retained just to validate acquisition, so it cannot extend a later
manager's grant lifetime.

`CAPSULE_OP_BOOT_STORAGE_DATA` uses the existing exact recipient request shape
on the exclusive manager channel. It returns a fresh independent data-scope
factory for that boot assignment, never an actor grant. Missing data policy
returns no factory. Request shape, trailing bytes and dispatch are validated
alongside existing boot operations. Original bootstrap remains the only process
allowed to acquire these factories through Capsule's helpers.

The parser, preparation and Capsule-side handoff are implemented. SwitchBoard's
production consumer, client association and grant issuance remain unfinished;
no provider receives data permission merely because this policy exists. Native
checks pass 17 cases, with one installation-policy test skipped because explicit
installation inputs were not supplied. The maintained bootstrap build and all
39 runner/evidence tests pass. The VM now invokes the actual identity-checking
Capsule acquisition helper; its qualification result is pending in this entry.


Qualification update: `bip-data-policy-vm-v1` passes storage-anchor,
storage-mapped and approved; the verifier checks 110 files. The storage case
uses the production Capsule acquisition helper with a selected policy identity,
rejects a mismatched GUID, verifies that caller-side policy changes do not alter
the kernel ceiling, and rejects acquisition by a nonbootstrap recipient.
Existing dynamic-child access, reparenting and revocation checks also pass.
The new marker is mandatory and subject to missing/duplicate-marker rejection.

This VM does not exercise the entire configured preparation path or the new
Capsule-to-manager RPC. Those remain integration tests for the forthcoming
broker consumer; native parsing plus direct helper coverage is not end-to-end
policy qualification. Summary receipt:
`/usr/obj/usr/src/security-qualification/bip-data-policy-validation-v1.json`.
The real provider first-open failure remains unresolved.


### Broker retains the independent data ceiling (2026-10-20)

`service_storage_data_prepare()` now asks the broker to retain the original
provider's separate authenticated boot data scope. It accepts no recipient,
process identity, operation mask or returned descriptor. The service-control
handler checks the direct sender against the original service process. Both
management and data preparation use one shared verified-system-Core and launch
record check. Missing assignments return ENOENT; repeated preparation returns
EALREADY. Application records and foreign launches cannot use the path.

SwitchBoard obtains a fresh factory through `CAPSULE_OP_BOOT_STORAGE_DATA`,
limits it to derivation/revocation ioctl operations, and locks transfer, fork
and exec. The launch record owns it. Failed descriptor restriction closes the
partial result; launch revocation/removal closes the retained factory alongside
management controls, and manager exit closes its descriptors. Preparation does
not issue an actor grant, create a lease or relax a mandatory lease ceiling.
BSDFilesystem requires this preparation before layout provisioning/readiness
under BIP, so missing data policy is an explicit startup failure.

The maintained bootstrap build passes, including libservice installation into
the matching object-tree sysroot. Four native cleanup tests pass without skips.
The new test calls actual launch-record removal with real descriptors and a
revocation syscall double: it verifies all owned controls close, unrelated FDs
survive, and the software revocation request names the expected token. It is
ownership evidence, not kernel or process-exit delivery qualification. All 39
runner/evidence tests pass.

The deployment input `provider-worker-data-policy-v1.ucl` adds explicit data
operations, subtree scope and `require_lease=true` independently of its existing
management ceiling. No production recipient or data ceiling is compiled into
the broker. `bip-broker-data-service-v1` reaches actual worker admission and
unit/shared/group listing after the provider's mandatory data-preparation call
succeeds. The Core client without a storage assignment receives ENOENT from
data preparation. This exercises the real preparation/RPC/startup path missing
from the earlier direct-helper test.

The overall VM result remains **FAIL** at the first file-data open (EPERM).
Later retained-data checks remain unexecuted and reboot is skipped. Input and
retained-artifact hashes were checked without turning the failure into a pass.
Summary: `/usr/obj/usr/src/security-qualification/bip-broker-data-validation-v1.json`.
A trusted broker-owned client association, session/resource authorization,
separate worker/client grants and their adversarial lifetimes remain required.
The factory retained by the launch record is not itself client authorization.


### Observed client associations and worker nomination (2026-10-20)

Lookup can now carry one restricted process descriptor for the actual caller.
Both managed and ambient library transports send it; normal and on-demand broker
paths retain the original request metadata. The library uses pdself in capability
mode and pdopenpid for its own PID outside that mode, without changing caller
mode. Only identity/event rights are sent. A kernel lacking the descriptor API
may send no descriptor; a BIP provider with a data ceiling rejects such lookup
rather than creating an unauthenticated association.

For providers with a retained data scope, the broker checks the descriptor's
live PID against direct kernel-stamped process metadata and records software
identity, invocation/nonce, session, provider launch and the manager-computed
container/group selection. It assigns a non-reused ID and retains the process
descriptor, not a channel reference. Repeated lookups with the same observation
reuse the association. The registry is bounded at 4096 records; exhaustion fails
closed. A newly created record is discarded if provider notification fails.

Notifications carry the ID through libservice to BSDFilesystem. The provider
nominates workers with that ID; the broker checks its provider launch and live
session before admission. The legacy nomination helper supplies no ID and cannot
nominate a BIP worker. Client exit/exec events, client/provider authority removal
and expired sessions discard associations and their owned workers. Event cookies
use non-reused IDs, not freed object addresses. Session-associated management
grants receive the actual existing session lease, so its kernel revocation does
not depend on the broker's periodic collection. Boot-only associations create no
lease and cannot satisfy a data ceiling requiring one.

The lookup transports also now clean up process descriptors, reply descriptors
and private sessions if cancellation is delivered when an inner RPC restores
cancellation state. A native thread-cancellation regression with real pipe FDs
passes; it tests descriptor ownership, not kernel authorization.

**This association is observed metadata, not completed data authorization.**
Before issuing data grants, the manager must validate selected resources and
operations against that record and explicit policy. A lookup-to-exec race before
the process watch is installed needs an authoritative current-invocation check;
PID/liveness and an eventual exec event alone do not prove the recorded nonce is
still current. Recipient invocation checks protect old client grants from use by
a new execution, but do not establish independent client authorization for a
worker. The current-invocation check described below addresses pre-watch staleness;
independent client lifetime enforcement remains a gate before data issuance.
Foreign/stale descriptor, replay, exec, session-loss and provider/manager-loss VM
qualification also remains outstanding.

The private notification layout currently grows to 760 bytes (896 with principal
metadata); the public service_identity remains 760 bytes, with its reserved word
now holding the association ID. Matching bootstrap components are rebuilt by the
maintained build path. Mixed-version/static-provider compatibility is unqualified
and needs an explicit version/negotiation solution before usable-system or upgrade
acceptance. No claim of compatibility follows from a matching fixture build.

Evidence:

- Maintained bootstrap build passes; runner binds the new helper and both lookup
  implementations, domain/on-demand code and session header. All 39 host runner
  and evidence tests pass.
- Broker regressions: 47 passed, 16 skipped because root is required. Five cleanup
  cases pass, including actual association retirement and selective worker FD
  cleanup with an injected exec event. Kernel event delivery is not simulated
  evidence of a real exec.
- Native wire/cancellation cases: 2 passed. The standalone descriptor-mode case
  failed on the host, whose syscall numbering differs from the built kernel
  (pdself 630 versus 1006). It is retained as failed evidence, not relabeled a
  pass. Matching-kernel execution of that standalone case remains required.
- VM v1 failed at the ambient observer lookup because pdself is capability-mode
  only. V2 corrected that path and reached worker listing. V3, after cancellation
  cleanup, again creates one association reused by two workers and passes actual
  unit/shared/group listing. Ambient observer and capability-mode client lookup
  both operate in that matching Secure Boot VM.
- `bip-client-association-service-v3` remains **FAIL** at the first file-data open
  with EPERM; later retained-data tests are unexecuted and reboot is skipped.
  Inputs and retained artifacts were checked while preserving the failure.
  Receipt: `/usr/obj/usr/src/security-qualification/bip-client-association-validation-v1.json`.


### Current invocation observation (2026-10-20)

`CAP_AUTH_CHECK_INVOCATION` is issuer-only and takes a fixed-width request with
an owned software token, held process descriptor and nonzero observed process
identity/exec nonce. Reserved fields must be zero. The kernel validates issuer
ownership and prison, requires CAP_PDGETPID, resolves the held process under
proctree_lock, and checks software validity and both identities under PROC_LOCK.
Exiting processes are rejected. File references are released outside those locks.
There is no pathname, PID lookup, UID-zero exception or supplied identity override.

SwitchBoard checks after installing the client exec/exit watch and before
association reuse, worker nomination and worker admission. An exec before the
watch was installed is rejected by the current check; a later exec is covered
by the watch and recipient invocation binding. This is not atomic client-lifetime
authorization for another process: separate worker data grants still need a
kernel-enforced client authorization lifetime, as well as selected-resource and
operation policy. Data issuance remains disabled.

Build/evidence corrections:

- Both kernels build using 16 CPUs. Five native broker cleanup cases and 39
  runner/evidence cases pass. Callback tests use explicit kernel doubles.
- The first mechanism VM (`bip-invocation-check-vm-v1`) passed its existing gate
  with an old PID 1 fixture. Its 77-file verification proves artifact consistency,
  **not execution of the newly added checks**. That run is not accepted as evidence
  for this operation.
- The complete build-bsd flow already builds the mechanism fixture separately.
  The bootstrap helper now also builds secureboot_init, avoiding stale fixtures
  when that maintained helper is used directly. The runner requires exactly one
  INVOCATION_CURRENT_PASS marker, emitted only after the new checks complete.
- V2 ran the new fixture and failed because it attempted pdopenpid on an already
  executed protected child. The corrected fixture acquires the child descriptor
  through pdfork, preserving the denial of ambient post-exec acquisition.
- The actual provider run `bip-invocation-check-service-v1` uses the new broker
  checks and still creates/reuses its client association, admits scoped workers
  and lists unit/shared/group containers. It remains FAIL at the first file-data
  open (EPERM); later data checks are unexecuted and reboot is skipped. Input and
  artifact verification preserved this failure in worker-management-observation.json.

Corrected mechanism result: `bip-invocation-check-vm-v3` passes the approved
Secure Boot case. The serial log contains the actual current-invocation checks
and exactly one required marker; the maintained verifier checks 77 files. This
qualifies the bounded observation operation, not independent client lifetime or
full service operation. Consolidated receipt:
`/usr/obj/usr/src/security-qualification/bip-invocation-check-validation-v1.json`.


### Independent client invocation dependency (bounded kernel implementation)

A worker's invocation binding answers which process may act. A separate client
invocation dependency answers whether that work is still authorized by the
observed client. `BIP_STORAGE_ISSUE_FOR_CLIENT` retains both restrictions, plus
any existing mandatory session lease. The client dependency never substitutes
for that lease, a resource-selection check, or the bootstrap resource ceiling.
The original issuance interface remains for grants which have no separate client.
The broker has not yet enabled data issuance through the new interface.

The kernel lazily attaches a refcounted state object to an observed invocation.
Acquisition validates issuer/token ownership and the held process descriptor's
current identity and nonce under PROC_LOCK. Grants retain this state, not the
process, process descriptor or messaging channel. Successful exec, authority
replacement/clear, prison transition and exit invalidate the state permanently;
fork starts with no dependency state and failed exec preserves the current one.
Token and issuer revocation are checked independently. Later data and management
admissions check the dependency without acquiring another process lock while
holding the storage policy lock. This avoids a cross-process lock ordering path.

Revocation is admission-only: already admitted I/O is governed by the existing
limited drain contract. Closing the observer's process descriptor does not end
the observed invocation. This mechanism deliberately creates no timeout, session,
role, resource mapping or new root privilege. The new
fixture uses separate client and worker processes and retains the worker's open
file across client invalidation. Resource-policy integration and the real service
first-open failure remain unfinished.

The exit path invalidates at P_WEXIT under PROC_LOCK, before waiting for VM-space
holds or invoking later exit cleanup. An invalidated state cannot be revived by
a subsequent token installation or another execution; a new observation acquires
a new state object. There is one lazily allocated object per observed invocation,
with old objects retained only by their consumers. No process-reference cycle is
created and no consumer can extend the process lifetime.

Initial evidence: `bip-client-dependency-vm-v1` passes storage-anchor,
storage-mapped and approved; the maintained verifier checks 120 files. The new
client dependency tests execute in storage-anchor only. They require actual
separate processes, valid software observations, positive retained reads and
EPERM after each invalidation. They also reject foreign client descriptors and
tokens, stale nonces, zero identity, malformed requests, missing CAP_PDGETPID and
omitted mandatory leases. Fork/child exit and failed exec preserve the parent's
admission; successful re-exec confirms software authority remains valid while the
old invocation's dependency is denied. Closing the observer's descriptor does
not end the client. Existing storage and Secure Boot cases also pass.

Not yet qualified: authority replacement and jail transition through this new
dependency interface; concurrent issuance/invalidation stress; dependency-specific
management operations and broader data action masks. Existing asynchronous
revocation and limited drain semantics remain in force. Broker resource mapping,
mandatory use of the dependency for client-directed work, separate client grants
and the first real-service data operation remain unfinished.

Read/write expansion: `bip-client-dependency-vm-v2` passes storage-anchor; the
maintained verifier checks 110 files. The worker first proves both pread and
pwrite denied without a grant, then proves both succeed under the dependent
grant, and finally proves both return EPERM after each client/session transition.
The earlier three-case run remains retained. All 39 runner/evidence tests pass;
they reject missing/duplicate required markers. Both maintained kernel targets
build with all 16 CPUs; the existing bootstrap helper builds the updated storage
fixture and the observer is rebuilt against the matching kernel. Receipt:
`/usr/obj/usr/src/security-qualification/bip-client-dependency-validation-v1.json`.
This does not change the failed real-service or installed-system acceptance.


### Authenticated provider policy handoff (2026-10-20)

#### Remaining data-authorization gate

Claim-grant implementation update (not yet qualified end to end): the retained
worker control protocol now accepts a fixed-width claim-grant request with a
nomination slot, exact claim component, explicit action mask and one held dataset
descriptor. The broker rechecks the original attached worker through its process
descriptor, checks the independent client invocation/session, resolves the slot
through its verified namespace mapping and rejects actions outside the recorded
access ceiling. It constructs the expected full claim name itself.

Worker preparation now derives a separate data scope on each selected namespace
object whose access ceiling is nonzero. These scopes inherit the boot data ceiling
and required session constraint. Later exact named derivation uses this retained
scope, not the provider's broad data root; replacing the old namespace pathname
therefore cannot redirect a worker to an unrelated object. A zero access ceiling
creates no scope. Failure rolls back all prepared scopes and management issuers.

Successful claim derivation produces separate grants for worker and client. Each
recipient grant has an independent dependency on the other invocation, plus the
actual client-session lease when present. The broker retains all three controls
(exact issuer and two grants); it returns only a non-reused worker-local ID.
The worker has a limit of 64 live claims. Release consumes its own ID and closes
the controls; repeated release returns ENOENT. Worker rejection, disconnect,
exit/exec and record cleanup close all claims. Failed paired issuance closes
every partial control. A failed reply retires the worker via the existing dead
channel handling. Closing controls stops later admission, not synchronous I/O
drain.

Builds succeed. `bip-claim-grants-tests-v1` passes eight native selection/cleanup
cases. The new case invokes the actual broker handler with controlled kernel
responses, checks the narrowed parent and exact name, both invocation directions,
action-denial preservation, rollback after second-grant failure, and release of
real descriptor stand-ins. It does not prove kernel integration or lease behavior.
The library/provider call path is not connected yet, no positive claim-grant VM
is claimed, and production resource authorization remains unfinished. Existing
deployment policy is unchanged and continues to deny the sessionless data case.

Worker mapping update: named namespace admission now returns the selected
client-namespace index for every nominated descriptor. The worker record retains
those indices in descriptor order. Later claim requests must resolve their slot
through this broker-produced mapping before selecting the client's data-action
ceiling; provider order cannot stand in for authorization. On partial failure,
the helper closes all created issuers and resets every index to SIZE_MAX.
`bip-worker-mapping-build-v1` succeeds and all seven native selection/cleanup
tests pass in `bip-worker-mapping-tests-v1`; the reversed-order regression checks
the mapping and the duplicate-nomination regression checks complete rollback.
No new VM qualification or data-grant issuance is claimed by this change.

Exact-object prerequisite: `ZFD_BIP_DATA_DERIVE_NAMED` extends data derivation
with the same expected-name condition used by management derivation. It compares
the held live filesystem's current full name under the exclusive namespace gate
and derives before releasing that gate. It performs no lookup by that name.
Wrong names fail ESTALE; empty/unterminated names fail EINVAL. Existing parent
membership, supported modes/actions, mandatory leases and revocation remain
mandatory. The prior data-derivation ABI is unchanged. Exact issuers still follow
object identity after admission; this operation does not freeze pathnames.
The broker does not yet invoke it for claim requests.

Both kernels, the storage fixture and I/O observer build with 16 jobs. The new
fixture exercises wrong/malformed names, mandatory lease and outside-parent
denial, plus rename/restoration before successful exact derivation. Its exact
issuer feeds the existing real file-data tests. `bip-named-data-vm-v1` passes the
storage-anchor mechanism case under SecureBoot=1/SetupMode=0 with clean shutdown;
evidence verification checks one case and 114 files. All 47 Python tests pass.
Concurrent rename stress and full service qualification remain outstanding.
Remaining broker work includes preserving the selected namespace/action mapping
for each worker slot, checking claim-specific requests against that mapping,
and transactionally retaining separate worker/client grants. Read-only client
access must not silently authorize provider ownership changes or other metadata
work; required initialization needs an explicit authorized operation path.

Worker-control update: `service_storage_worker_attach` uses a distinct private
opcode with the existing fixed admission frame. It consumes the nomination
endpoint and returns a worker-owned service_session after successful admission.
The broker retains this connection instead of discarding it after the reply,
records the directly observed worker process identity/nonce, and watches both
exit and exec. Channel loss, worker lifecycle events and record revocation close
owned controls. The provider closes its retained session during namespace cleanup.
The older one-shot admit operation keeps its previous behavior. Neither API
supplies a user lease or data authority. Admission now installs cancellation
cleanup for its process descriptor, endpoint and session.

Bootstrap build v1 succeeds. The new native attached-worker regression exercises
the real admission callback with controlled transport/kernel responses, verifies
retained invocation metadata and closes actual descriptor stand-ins through the
worker-exec event path. All seven selection/cleanup tests pass. This is ownership
evidence, not kernel or concurrent cancellation proof. Claim-specific data
operations, grant retention and positive/negative lifecycle VMs remain required.
`bip-worker-control-service-v1` starts both seven-scope workers using attach and
passes their real management checks. The overall result remains FAIL at first
file-data open, with later data/reboot checks unexecuted. Observation verification
checks 197 inputs and runtime artifacts; 47 Python tests pass. The existing
build-bsd bootstrap path builds the changed library, provider and manager
together; no frontend option is needed. Older managers cannot accept the new
opcode, and mixed-version upgrade compatibility remains unqualified.

Implementation update: the existing authenticated filesystem policy now accepts
an optional `access` array. Each bounded row names exact software, subject
(`service` or `session`), namespace kind (`durable` or `boot`), relative namespace
and explicit data operations. Session rows require an exact authenticator/principal
pair; service rows forbid those fields. Missing rules deny all. Unknown fields,
duplicate match tuples, traversal/glob names, empty/duplicate/unsupported actions
are rejected atomically by the shared parser. Capsule and access rules now share
parse_storage_data_actions, preserving the Capsule spelling and operation set.

The broker records these action ceilings alongside its observed client selection.
A session subject comes only from the arriving session route. A service subject
requires an existing managed system launch and no session; application records,
personal installation ownership and UID zero do not supply that subject. No
session-to-service fallback occurs. These fields are not yet consumed by a
production data-grant path: grant issuance, lease enforcement on that path and
independent worker/client lifecycle integration remain unfinished. No deployment
policy is loosened or assigned implicit rules.

Build v2 passes. Filesystem parser/evaluator tests pass 9/9 with explicit default
and deployment inputs; Capsule configuration tests pass 13 with one installation
test skipped. The evaluator tests distinguish software, issuer, principal and
namespace kind, reject cross-subject fallback and check failure-atomic parsing.
The existing native principal fixture is still a synthetic hardcoded test;
it is not the implementation of this policy. Positive authenticated-session and
service-owned storage VM qualification is still required.
`bip-access-policy-service-v1` retains the existing deployment input without
access rows. The actual provider and both seven-scope workers start and management
checks pass; the complete run remains FAIL at file-data open (line 242, EPERM),
with later data/reboot checks unexecuted. Its observation receipt verifies 197
inputs and runtime artifacts. This is a regression check, not evidence that the
new access ceilings enforce data operations. The 47 runner/evidence tests pass.

Review of the current caller and session implementation establishes these
requirements before enabling worker/client data grants:

| Question | Current evidence | Required implementation |
|---|---|---|
| Does the storage fixture have an authenticated session? | Its client uses its ordinary service context; its association has no session. The explicit data ceiling requires a lease. | Retain this as a denial case. Add a separate session-authenticated positive path; do not invent a lease or remove the requirement to make it pass. |
| Does a live session authorize this resource? | Session policy currently describes manage_system, manage_self and lifecycle rights. Kernel lease validity establishes lifetime, not permission to read/write a dataset. | Evaluate authenticated principal, software, resource and requested operations together before grant issuance. No implicit storage permission from UID, Core class, session presence or management rights. |
| Can unattended services store state? | System services cannot depend on a human login session. | Explicit service-owned resource policy may authorize the verified service invocation without a human session, bounded by provider/client lifetime. This is a separate policy choice and qualification case; it must never bypass a ceiling requiring a session. |
| Can a worker request claim-specific data authority after admission? | The broker handler is implemented; the library/provider path and real-kernel qualification remain missing. | Connect and qualify exact-object requests, paired invocation dependencies, mandatory sessions and close/restart/revocation cleanup. |

The current EPERM result is not evidence that this authorization model is
complete. Resource selection, principal authorization, actor grants and lease
lifetime are separate gates. The positive service test must satisfy all applicable
gates, while the sessionless test continues to demonstrate denial. No policy was
relaxed in this review.

The broker's named-selection loop now lives in the internal
storage_namespace_admission.h helper with transactional descriptor cleanup.
Its native regression invokes the production helper with a deterministic ioctl
double and tests custom roots, reversed order, duplicates, similar prefixes,
another unit, truncation and no fallback after EPERM. A partial success followed
by failure closes the real pipe descriptor standing in for an issuer and clears
all outputs. This tests broker selection and ownership, not kernel enforcement.
`bip-namespace-admission-native-v1` passes this case and all five existing worker
cleanup cases; broker build v2 and 47 Python tests pass. Earlier test builds
failed because the test target appeared after bsd.test.mk and because the ioctl
double's name collided with a local variable; those logs remain retained.
The runner now hashes this helper as an input, maintaining build-bsd evidence
coverage. The previous real-service VM result remains bounded evidence for the
pre-extraction path; no new VM result is claimed for this refactor.

Object-binding prerequisite: `ZFD_BIP_MANAGEMENT_DERIVE_NAMED` compares a
caller-supplied expected full dataset name against the held live filesystem
while holding the TrustedZFS namespace gate exclusively, then runs the existing
management-issuer derivation before releasing that gate. It performs no pathname
lookup. Empty and unterminated expected names fail EINVAL, a different live name
fails ESTALE, and the original parent issuer, action/property/lease ceilings and
live ancestry checks remain mandatory. The new fixed-width request wraps the
existing request; the previous ABI is unchanged. Success binds object identity,
not an eternally fixed pathname. Revocation and subsequent ancestor enforcement
are unchanged. Broker selection must still construct expected names from its
authenticated roots and observed client identity, not provider-supplied names.
The broker integration described below uses this operation for worker management;
it grants no file-data authority.
GENERIC and GENERIC-INTEGRITY, the storage fixture and I/O observer build through
the maintained /usr/src targets with 16 jobs. `bip-named-derive-vm-v1` passes
storage-anchor with SecureBoot=1/SetupMode=0 and clean shutdown. It exercises
matching and mismatched objects, empty/unterminated names, mandatory lease and
outside-parent rejection. Evidence verification checks one case and 113 files;
47 runner/evidence tests pass. The maintained runner now requires the named
derivation marker, so build-bsd's existing storage qualification includes it.
This is mechanism evidence. Concurrent rename stress and full real-service
acceptance are still outstanding.

Broker integration: worker preparation now requires the retained parsed policy
and rechecks the original provider through the held process descriptor. It
constructs expected full names from that policy and the broker-owned client
selection, then attempts named derivation. Only ESTALE permits trying the next
candidate; other errors abort and close all partially derived issuers. A logical
name cannot be selected twice in one request, and an unmatched handle fails
EACCES. This admits subsets; it does not require unused client namespaces.
The provider and manager share storage_namespace_boot_name, which validates
the kernel boot-time response and bounds the existing generation spelling.
No pool name, deployment root or recipient is compiled into this selection.

`bip-namespace-binding-service-v1` starts the actual provider and admits two
seven-scope workers through this path. Management listing passes; the first data
open still fails EPERM, later data checks are unexecuted, and reboot is skipped.
The observation receipt verifies 196 inputs and runtime artifacts while retaining
overall FAIL. Bootstrap compilation, five worker-cleanup tests and 47 Python
tests pass. These cleanup tests verify ownership, not malicious nominations.
Dedicated malicious-provider, duplicate/replaced-object and concurrent-rename
tests remain required. Names select objects at admission; continued authority
uses object identity and existing live-ancestor rules, not a permanent path
binding. Data authority and its independent client/session lifecycle remain
unfinished.

The optional Capsule storage `policy` field names a canonical absolute file path.
Before committing storage preparation, original PID 1 opens it with O_VERIFY,
requires a root-owned regular file up to 1 MiB without group/other writes on
the authenticated read-only root, and retains the opened object. Preparation
failure closes pending descriptors; reload cannot change the assignment.
Capsule's private manager channel delivers a read-only duplicate for the exact
recipient. Only this policy response remains forwardable: authority descriptors
retain their single-hop transfer restriction.

SwitchBoard checks verified system Core provenance, launch identity and the
original invocation through its held process descriptor, and retains the file
in the launch record. `service_storage_policy` returns a duplicate to that
provider. Teardown closes the retained descriptor. BIP BSDFilesystem requires
this assignment, rejects a command-line policy override, and rechecks the file
before parsing. It does not independently reopen a default pathname. Outside
BIP the existing explicit/default configuration behavior remains.

The subsequent shared-parser implementation moves the existing provider parser
and configuration model into libcapsulert/filesystem_policy.c and .h. The broker
parses a duplicate of the retained immutable file before returning it to the
provider. It commits the descriptor and configuration together only after a
successful parse and frees the configuration on launch teardown. Both consumers
use pread through this single implementation, independent of their shared file
offset. The model retains existing field layouts and configuration semantics.
The subsequent named-derivation integration checks nominated namespace objects
against these configured roots at admission, as described above. Shared logical
selection alone is insufficient for issuing data grants. No data grant is
enabled by this step.

`build-bsd secureboot-test` and the runner accept
`--filesystem-policy-destination`; the assembler rejects noncanonical paths,
symlink components and unintended collisions. The explicit policy assignment
must match this destination. The fixture still includes its historical default
configuration, so the successful custom-path startup exercises the assignment.

Qualification: bootstrap v3 builds; Capsule native tests have 18 PASS/2 SKIP,
worker cleanup has 5 PASS, build-bsd's configured plan regression has 1 PASS,
and assembler/runner/evidence tests have 47 PASS. Broker domain/anoint native
tests are BROKEN on the older host ABI (`pdopenpid@FBSD_1.9` unavailable), not
passes. The first VM attempt failed during assembly because METALOG did not
escape the space in the custom filename; the writer now escapes pathname bytes
and has a regression test. The second VM failed provider startup because the
generic Capsule reply removed onward transfer from the policy descriptor.

`bip-policy-handoff-service-v3` starts the provider using
`/Config/custom storage.ucl`, admits two seven-scope workers and passes actual
management listing and denial checks. The run remains FAIL at the first data
open (client line 242, EPERM); later data checks do not execute and reboot is
skipped. Its worker-management-observation.json verifies the recorded inputs
and runtime artifacts without converting this failure into a passing service
qualification. Normal installed startup, SSH, restart/reboot and updates remain
unqualified. All runs are under /usr/obj/usr/src/security-qualification.

Shared-parser qualification: bootstrap build v1 succeeds and 47 Python tests
pass. The descriptor-offset regression parses two duplicates at different
offsets, checks identical configurations and verifies neither parse advances the
shared offset. The initial native run lacked the packaged storage-policy.ucl
fixture (one failure); the first isolated staging attempt included a Kyuafile
listing unstaged test binaries and did not execute. These are retained separately.
The corrected staged run `bip-shared-policy-tests-v3` passes all eight parser
tests with the packaged default and explicit deployment policy supplied.
`bip-shared-policy-service-v1` starts the actual provider and passes both scoped
worker management checks after the manager's parse. It remains FAIL at first
data open, with later data/reboot checks unexecuted. Its observation receipt
verifies 196 input hashes and runtime artifacts. Object binding, data admission
and lifecycle qualification remain unfinished.

### Shared logical namespace selection (2026-10-20)

libcapsulert now owns the common component, container, scope and selection
implementation. BSDFilesystem uses it both to prepare worker namespace views and
to resolve request scopes. SwitchBoard validates and retains the same computed
selection alongside the directly observed client association. The existing
transaction-version classifier is shared too; claim/group names cannot alias
reserved transaction names. Unit/shared/group layout rules now have one source.

The selection contains relative names, not dataset roots or grant authority.
Pool names and root layout remain explicit configuration inputs. Unknown durable
lifetimes fail rather than selecting persistent storage implicitly. Unsafe owner
components, missing termination, reserved bundle/unit aliases and undeclared
groups are rejected. Duplicate group selections coalesce; a bundleless client
has no durable namespace even if group fields are present. Failure clears the
selection before returning, so partial output cannot be consumed as policy.

This is only the logical part of broker resource validation. The broker still
must bind these names to the same authenticated root policy used by the provider,
verify actual held object identities and enforce operation policy before data
issuance. It does not currently perform that object check. Existing provider
management nomination remains bounded by its bootstrap ancestor ceiling, which
alone does not prove client ownership of a nominated child. Data grants remain
disabled; no selected-program allowlist or root-path guess was added.

Build integration now installs the freshly built libcapsulert and its headers
into the matching world sysroot before rebuilding consumers. This updates the
maintained bootstrap helper used by build-bsd, without installing on the host.
Two direct selection tests pass; the existing namespace suite reports 38 passed,
2 skipped and no failures. The skips are host/root-dependent, not qualification.
Two initial builds failed on a removed local helper and tests calling its old
name; those logs are retained and subsequent builds pass. VM evidence follows.

VM `bip-shared-selection-service-v1` creates one observed association, admits two
workers with seven selected scopes each, and passes actual unit/shared/group
listing and management-denial checks. It remains **FAIL** at first file-data open
(line 240, EPERM); later data tests are unexecuted and reboot is skipped. Source,
binary and retained VM artifact hashes were checked while preserving the failure.
All 39 runner/evidence tests pass. Consolidated receipt:
`/usr/obj/usr/src/security-qualification/bip-shared-selection-validation-v1.json`.

# Installation retirement implementation

Switchboard consumes committed removal records and automatically schedules cleanup
through authenticated provider channels. The installation authority remains a
small registry inside the existing manager; there is no additional daemon.

## Authority and identities

The installation ledger authorizes retirement. A missing executable, stopped
service, or absent inventory label cannot authorize resource deletion. Keep four
identities separate: canonical service label for policy/audit, random installation
ID, source reference, and random operation ID. New private resource ownership keys
are `install.<installation-ID>`. Legacy adoption preserves the canonical ownership
key. Restarts and upgrades retain the installation ID; reinstall after retirement
creates a distinct ID, even while old cleanup remains pending.

A source reference identifies an immutable bundle version (`bundle:ID@SEQUENCE`)
or an installed package slot (`pkg:directory/metadata-name`). The ledger stores a
128-bit SHA-256 prefix of that source string. Several live source references may
share an installation. Removing one reference retires the owner only when the last
live reference is removed. Package upgrades replace the same slot.

Every staged operation records its operation ID, source reference, and exact
installation ID durably. Completion resolves that operation, never the newest
installation with the same label. Duplicate completion is idempotent; cancellation
and completion are mutually exclusive. A delayed old removal remains harmless
even while its replacement is itself being removed. Pending operations serialize
changes to a label. Multi-label CLI updates commit together or are discarded.

## Publication and recovery

`switchboardctl install` verifies a private staged bundle, persists install intent,
publishes the immutable directory, fsyncs the parent, then commits the reference.
The owner is INSTALLING until completion; activation and new sessions are blocked.
The database lock spans publication and completion. A failure before publication
cancels the intent when possible. A crash can leave intent pending, deliberately
requiring recovery. `recover-install OPERATION PUBLISHED_BUNDLE` verifies the
canonical published bundle, root-owned tree permissions, and its exact
source/operation before completing it.
An unpublished transaction can be cancelled after confirming it was abandoned.

Managed package invocations run through `switchboardctl lifecycle run ROOT pkg ...`.
The wrapper supplies one operation ID and selected root to every hook and serializes
cooperating invocations. Pre-install stages the source; post-install commits it.
Pre-deinstall prepares removal; post-deinstall commits that exact removal.
Upgrade deinstall hooks do nothing; install hooks retain the existing owner and
source slot. An upgrade can explicitly adopt legacy ownership before staging.
Hooks without the wrapper's operation ID refuse to mutate lifecycle state.
Offline hooks update only the selected root, without contacting the host manager.

This is a recoverable protocol, not an atomic transaction inside pkg. A failed or
missing hook can leave pkg/files and the ledger disagreeing. Pending intent stays
blocked until an operator checks package/file state and finishes or cancels the
recorded operation. No process guesses completion from filesystem absence.
The wrapper reports the operation ID and propagates the command's exit status;
it reports unfinished operation records even when pkg returns zero, but does not
automatically reconcile pkg state. The coordinator and helper must
already be available for pre-install, including bootstrap and chroot use. Existing
package metadata needs migration; unwrapped pkg and arbitrary file copying are
outside the managed contract. The old label-only reclaim endpoint returns ENOTSUP.

## Provider obligations

Before handing a new installation's session to a cleanup-capable provider,
SwitchBoard durably records that provider as a possible holder. Retirement queues
only those providers; a failed handoff can conservatively leave an extra holder.
Older owners, including modern keys created before tracking, retain a broad
fallback covering installed stateful builtins and registered providers. New
OWNER records carry `cleanup-tracked` in their previously unused reference field.
A queued batch carries `cleanup-pending`; acknowledged or empty batches carry
`cleanup-complete`. These use the existing version-4 record layout. Existing
batches are repaired idempotently and are never expanded after preparation.

A one-second timer observes registry changes. Idle ticks reuse the validated
query cache. Changed state or provider registration triggers replay; ordinary
pending batches retry after 30 seconds, full 32-message batches after one second.
Database transactions use nonblocking locks and close before provider activation
or sends. Early read-only boot defers builtin registration without preventing rc
from remounting the root. A stopped, enabled provider is activated on demand. Provider identity
comes from its authenticated control channel; receipts name the exact generation.
A receipt means durable provider cleanup, not message delivery. Lost receipts are
safe to replay. An unavailable provider stays pending. There is no manual
provider-resolution or force-acknowledge command.
See [operations and rollout](installation-retirement-operations.md).

Fork-per-client providers fence the owner, terminate and wait for retained workers,
then clean persistent names. Process descriptors omit PD_DAEMON, so provider death
also terminates those workers. Live descriptor tests exercise the kernel guarantees that named-key deletion
invalidates leases and closing an anonymous mount anchor invalidates client
file/directory descriptors; destroying a dataset invalidates its old GUID handle. Logd instead durably seals the owner in
its serialized storage process; an already-open session cannot append afterward.
The replacement's distinct owner continues working in the same pool. Application
records become invisible; physical segment removal remains a retention decision.

## Persistence and validation

The ledger at `/Capabilities/Config/switchboard/lifecycle` uses a stable flock,
checksummed records, fsynced temporary publication and parent-directory fsync.
Corrupt or missing initialized state fails closed. The current authority format is
4; version 3 is readable, while earlier experimental formats require explicit
migration. Recent issued transactions are bounded at 256. Pending cleanup keeps
its owner identity, holdings, and deliveries even when older transactions expire.
Completed metadata expires with its retained owner history. One last-known owner
per label remains. The 262,144-record limit still fails writes at capacity; pending
work cannot be discarded to make room. Back up the registry together with the
corresponding installation and provider state.

The dispatcher closes queued old-owner client sessions before publishing the
retirement fence. Each accepting thread retains one accepted-session admission;
forking must use that admission before another accept. Completed fences can be
collected after those handoffs drain. Replayed requests may invoke cleanup again,
so every callback must be idempotent. Parent-side allocation must also serialize
with cleanup and check the accepted owner's fence. Non-forking providers must
fence their own retained sessions before acknowledging.

## Ownership and retention policy

The retirement ledger says an installation has ended. Each provider decides how
that affects the resource it owns; an acknowledgement does not mean that every
byte associated with an application has been erased.

| Resource | Current uninstall behavior | Ownership boundary |
| --- | --- | --- |
| tzfsd persistent and cache claims | Destroy the retired installation's private namespace | Resource ownership key, hashed into the namespace |
| localcrypto named keys | Delete keys owned by the retired installation | Kernel key owner; shared or user credentials need a separate owner |
| warden jail | Remove the retired installation's jail | Jail name derived from its resource owner |
| waspnest port allocation | Stop old workers and release their window | Parent registry entry for the resource owner |
| logd application records | Seal the retired owner and hide its records; retention later removes physical segments | Application log owner, independent of audit records |
| Security audit trail | No installation-retirement deletion | auditbrokerd submits to the system audit facility |
| User documents outside the private namespace | Not targeted by this cleanup | The user or document service owns them |
| Shared application state | No shared-owner lifecycle implemented yet | Requires an explicit shared identity and membership policy |

Files placed inside a private tzfsd namespace are currently all treated as private
installation state, even if an application calls them documents. Preserving
user-created documents requires placing them under a user/document owner; their
contents or filenames cannot establish a different retention policy.

Shared state must not be represented by one member's private installation key.
Membership retirement, retained empty containers, and explicit user/account
deletion need a separate ownership policy. None is inferred from a missing
executable. No shared-container or credential-retention API is introduced here.

Provider processes keep at most 256 pending retirement jobs in memory. Excess
deliveries receive no completion receipt and remain in the authority's durable
backlog for retry. Completed jobs leave memory after any accepted session has
released its fence; this bound does not discard pending authority records.

Cleanup replay stops during manager shutdown. Built-in provider registration
defers while the boot filesystem is read-only, then retries after remount.
Reload preserves each retained service's bundle origin so a restarted system
provider retains the appropriate lookup domain.

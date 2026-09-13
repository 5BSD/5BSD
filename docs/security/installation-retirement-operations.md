# Installation authority operations

The current scope is the [small installation authority](installation-authority.md).
The broader provider cleanup and recovery rollout is deferred. Automatic cleanup
is disabled by default; removal records do not imply provider data deletion.
`SWITCHBOARD_EXPERIMENTAL_RECLAIM=1` opts switchboard into the unqualified consumer
for isolated testing only. Do not use it to reconstruct unrecorded past holdings.

Inspect state with `switchboardctl lifecycle query ROOT LABEL [INSTALLATION_ID]`
and inspect source and operation history with `switchboardctl lifecycle status ROOT`.
Queries require an existing trusted store and never initialize one.

Run managed package operations through
`switchboardctl lifecycle run ROOT pkg ...`, supplying pkg's root arguments as
appropriate. Bootstrap switchboardctl and `/usr/libexec/switchboard-pkg-reclaim`
before using managed packages. The helper must also be available inside a chroot
when hooks execute there. Unwrapped managed hooks fail rather than inventing a
transaction. The wrapper reports pending operations as exit status 75 even when
pkg itself returns zero after a failed hook.

For an upgrade from the earlier prototype, inventory the actual installed packages
and bundles before restarting switchboard. Explicitly adopt each unrecorded source:
`switchboardctl lifecycle adopt ROOT SOURCE LABEL ...`. This preserves a known
active ID and legacy resource ownership while adding source provenance. Runtime
startup and client connections no longer create missing registrations. The
runtime package registers `org.5bsd.user-session`; when migrating an existing
root manually, adopt it with source `pkg:runtime/runtime` as well. Verify these
registrations with query/status before restarting. Managed package upgrades keep
their active IDs and use explicit installer adoption for older package slots.

After interruption, inspect both package/bundle files and the recorded operation.
Use its original operation ID and source with the matching finish or cancel
command. Do not issue a fresh label-only removal to recover an old operation.
`recover-install OPERATION PUBLISHED_BUNDLE` verifies a published bundle before
finishing its recorded publication. None of these commands rolls back pkg files.

Preserve the ledger together with the corresponding installation state when
backing up or restoring a root. Stop writers while taking a consistent backup.
Do not delete an unreadable ledger to make the system continue: that discards
installation identities and pending-operation history. Missing, corrupt, and
unsupported-format stores require repair or an explicit migration.

Recent history is collected automatically (256 issued transactions, plus pending
work and its dependencies). Use `switchboardctl lifecycle prune ROOT [KEEP]` to
discard older history sooner. This preserves current/last-known label state and
live sources; old exact-identity queries can become unknown. New manual
transactions obtain an ID with `switchboardctl lifecycle issue ROOT`. Expired
IDs fail instead of starting a new operation; do not replace an expired retry
with a fresh ID without inspecting the current installation.

Before a planned snapshot of legacy state, run `lifecycle prune ROOT` to establish
issued-operation enforcement.

Use the [ZFS recovery contract](installation-authority-qualification.md#zfs-recovery-contract)
for system snapshots and rollback. Restore the registry, package database, and
corresponding programs together, including provider data when rolling it back.

There are no `verify`, `compact`, or `resolve-provider` lifecycle commands.
Provider receipts and resource cleanup are part of an earlier unqualified
prototype; their operational policy and full-stack qualification remain deferred.

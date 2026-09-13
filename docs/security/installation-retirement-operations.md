# Installation authority operations

Switchboard automatically schedules private-resource cleanup after committed
removal. The installer records facts; provider callbacks enforce each resource's
retention policy. Removal and cleanup completion are separately observable.

Use `switchboardctl lifecycle cleanup ROOT [LABEL [INSTALLATION_ID]]` to inspect
progress and each provider receipt. Exit status 75 means work remains or a
concurrent writer holds the registry lock; retry a busy query. Exit status 66
means the selected identity is unknown. A label alone selects its latest incarnation,
so use the saved ID when diagnosing cleanup of an older installation.

A stopped, enabled provider is started on demand. A disabled, absent, failing, or
unready provider leaves its delivery pending. Repair or restore it; do not erase
records or fabricate acknowledgements. Retries are bounded and survive restart.
`SWITCHBOARD_TRACE_INSTALLATION=1` in Capsule's startup environment enables
`cleanup-send` and `cleanup-ack` diagnostics through switchboard's syslog path.

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
Use its original operation ID and exact recorded source with the matching finish
or cancel command. Bundle publication records a zero-padded 20-digit sequence
in its source string; use the value from `lifecycle status` rather than
reconstructing it from a display version. Do not issue a fresh label-only removal to recover an old operation.
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

A retained snapshot can prevent tzfsd from destroying retired private storage.
The filesystem receipt stays pending and the manager retries; it does not delete
snapshots to force cleanup. Resolve snapshot retention under the system backup
policy, then check the exact retired identity again. A pending receipt survives
a normal reboot and does not authorize deletion of a replacement installation.

There are no `verify`, `compact`, or `resolve-provider` lifecycle commands.
New installations require the matching runtime to be running before their
transactions begin. Older recorded owners conservatively target all registered
providers. Already-pruned identities and never-registered custom providers need
explicit migration; no filesystem-absence scan reconstructs them.

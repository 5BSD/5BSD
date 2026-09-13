# Installation Identity and Lifecycle

The installation authority lets a service ask whether a particular installation
still exists. It records installer decisions in switchboard's durable registry
and exposes queries through the existing authenticated service channel. It does
not add a daemon. Veriexec continues to check executable integrity; it does not
establish installation ownership or decide when application data should disappear.

Use this feature when a provider keeps resources on behalf of another service.
A service label alone is insufficient: uninstalling and reinstalling the same
program must not give the replacement ownership of the previous installation's
resources. The authority associates each label with a random 128-bit installation
ID. Upgrades and additional live sources preserve that ID. Reinstallation after
removal receives a new ID.

## Register through the installer

The base-system installer runs its package installation inside an authority
transaction. Fresh installation and upgrade therefore use the package hooks
automatically; a failed post-install hook stops installation with a recorded
operation to inspect and recover.

Runtime discovery does not register programs. A manifest found on disk, a running
process, or a successful integrity check is not an installation transaction.
An unregistered label cannot start through switchboard. Registration belongs in
the package or bundle installation path, before the runtime needs the identity.

For capability bundles, use the bundle installer:

```sh
switchboardctl install /path/to/Example.cap
```

It obtains service labels from verified manifests, records installation intent,
publishes the bundle, and records completion after syncing publication. Do not
substitute copying a bundle into the discovery directory for this transaction.

A managed package declares its stable source and all service labels in its
lifecycle hooks. For example, the hook commands for a package slot
`pkg:applications/example` and service `org.example.App/main` are:

| Package hook | Command |
| --- | --- |
| pre-install | `/usr/libexec/switchboard-pkg-reclaim begin-install pkg:applications/example org.example.App/main` |
| post-install | `/usr/libexec/switchboard-pkg-reclaim install pkg:applications/example org.example.App/main` |
| pre-deinstall | `/usr/libexec/switchboard-pkg-reclaim prepare pkg:applications/example org.example.App/main` |
| post-deinstall | `/usr/libexec/switchboard-pkg-reclaim retire pkg:applications/example org.example.App/main` |

Despite its historical name, this helper records installation transitions;
it does not delete provider data. Supply every label owned by that package as
additional arguments, consistently across hooks. Use a stable package slot as
the source across upgrades. The helper handles upgrade semantics so an upgrade
preserves installation identity rather than becoming an uninstall and reinstall.

Run managed package operations through the transaction wrapper:

```sh
switchboardctl lifecycle run / pkg add /path/to/example.pkg
switchboardctl lifecycle run / pkg upgrade
switchboardctl lifecycle run / pkg delete example
```

For a repository upgrade, use `pkg upgrade`. Its upgrade context also lets the
new package hooks adopt a pre-authority installation while preserving the legacy
resource-owner key. `pkg add -f` does not supply that upgrade context.

The wrapper persists an operation ID and supplies it and the target root to the
hooks. Hooks fail without that context. For another root, pass the root to both
the wrapper and pkg, and make the helper available wherever hooks execute.
Check the wrapper's exit status: status 75 means pending work remains, even if
pkg returned success. Do not continue as though the installation completed.

## Query the authenticated installation

`service_listener_accept()` supplies a `struct service_identity` with the client's
`client_label`, `installation`, and `resource_owner`. Keep these authenticated
values with resources allocated for that client. Do not accept a substitute
installation ID from the client's request body. Preserve `resource_owner` where
the provider's ownership protocol uses it; the installation ID does not replace
resource-specific authorization.

After normal libservice provider initialization, query the exact identity with
`service_installation_query()`. This helper illustrates the error contract:

```c
#include <libservice.h>

static int
installation_state(const struct service_identity *client,
    enum service_installation_state *state)
{
        *state = SERVICE_INSTALLATION_UNKNOWN;
        return service_installation_query(client->client_label,
            client->installation, state);
}
```

A return value of -1 is an error, with `errno` explaining the failure. Keep the
resources and retry later as appropriate. In particular, `EWOULDBLOCK` means a
writer holds the registry lock; readers do not wait for an installer. Use bounded
backoff between retries rather than a tight polling loop. A busy response can
persist for the duration of a batch of installation transactions. Missing,
unreadable, or corrupt registry state is also an error. The API leaves the output
state `SERVICE_INSTALLATION_UNKNOWN` on failure.

On success, interpret the enum as follows:

| State suffix (`SERVICE_INSTALLATION_…`) | Meaning for this exact ID |
| --- | --- |
| `UNKNOWN` | No retained record; there is no evidence of removal. |
| `INSTALLED` | The installation is active. |
| `INSTALLING` | Publication or upgrade is unfinished. |
| `REMOVING` | A source removal is unfinished; another source may still exist. |
| `REMOVED` | The installation ended, or its initial publication was cancelled. |

These are installation facts, not a general authorization to erase data. A
provider still needs a defined retention policy for user documents, shared
resources, credentials, and other persistent state. Switchboard automatically
schedules private-resource cleanup after committed removal. Queries themselves do not revoke already delegated channels.

Always query the saved ID when examining old resources. Looking up the latest
installation by label could answer for a replacement. For operator inspection:

```sh
switchboardctl lifecycle query / org.example.App/main
switchboardctl lifecycle query / org.example.App/main SAVED_32_HEX_DIGIT_ID
switchboardctl lifecycle status /
```

The query RPC is synchronous. Switchboard retains one validated registry
snapshot, checks trusted paths and file identity on every request, and discards
the snapshot after filesystem changes. Cold queries and queries after updates
still validate the whole file; warm exact-ID queries search a compact index. Avoid
querying repeatedly on a latency-sensitive request path; plan when facts need
to be refreshed and test the expected load. Writer contention returns
`EWOULDBLOCK` immediately. Changes during validation can return `EAGAIN` after
bounded retries; apply backoff and keep the result unknown until a read succeeds.

Ordinary services receive installation state. The root-only status command also
shows source references and operation history.

## Implement private-resource cleanup

A provider opts in by calling `service_set_reclaim_handler(callback, context)`
once, before announcing readiness. The authenticated registration records the
provider; switchboard then records it as a possible holder before delivering a
client session. This can conservatively record a session that never completed.

The callback receives the exact opaque `resource_owner`, runs on a dedicated
thread, and must return zero only after its cleanup policy is durable. Return a
positive errno on failure. Make the callback idempotent: retries, lost receipts,
and provider restarts can invoke it repeatedly. Delete only resources owned by
that key. A missing path or an `UNKNOWN` installation query cannot substitute for
an authenticated cleanup request.

Fork-per-client providers must call `service_reclaim_fork(identity.resource_owner)`
on the accepting thread before accepting another session. It registers the worker
with a process descriptor. Retirement closes queued old sessions, blocks accepted
old handoffs, and terminates and waits for existing workers before the callback.
Provider death also terminates its workers. Parent-side resource allocation must
serialize with the callback and check `service_reclaim_owner_retired()` for its
accepted session. Completed fences are released after accepted handoffs drain;
they are not a permanent provider-side history database.

Providers serving sessions without child workers must close or fence those
sessions themselves before acknowledging. Logd does this with a durable owner
seal in its serialized storage process, so held sessions cannot append later.

The builtin policies cover private tzfsd namespaces, localcrypto named keys,
warden jails, waspnest port windows, and logd application records. Logd seals and
hides records; physical segment removal follows log retention. User documents,
shared state, and audit records require their own ownership and retention policy.
Files in a private namespace are private installation state regardless of name.

Inspect asynchronous progress separately from installation state:

```sh
switchboardctl lifecycle cleanup / org.example.App/main SAVED_32_HEX_DIGIT_ID
```

Exit status 75 means removal, dispatch, or provider work is pending, or the
registry is temporarily locked by a writer. Retry a busy query. A stopped,
enabled provider is started on demand for cleanup. Unavailable providers and
failed acknowledgements remain pending across manager restarts. The consumer
uses bounded batches and retry intervals; it never treats timeout as completion.
There is no force-acknowledge command. Repair or restore the responsible provider.

## Upgrades and interrupted operations

Deploy matching switchboard and service libraries together: the query uses
control protocol version 12 and libservice ABI 3. Rebuild providers and other
libservice consumers together; an older ABI 2 binary is not an upgraded provider.
Restart the runtime with the matching manager before allowing new installation
transactions; an old manager does not implement the new holding contract.
Before migrating an older root to explicit
registration, inspect its installed packages and bundles, then adopt each real
source using the installer tools:

```sh
switchboardctl lifecycle adopt / pkg:applications/example org.example.App/main
switchboardctl lifecycle adopt / pkg:runtime/runtime org.5bsd.user-session
```

Adoption preserves an existing active identity and adds source provenance.
The runtime principal in the second command is needed for ambient login-session
connections. Bootstrap matching installer tools and hooks, register the actual
installed sources, and verify query/status output before restarting the runtime.
Do not use adoption to bypass a pending operation or resurrect a removed identity.

Older recorded owners, including `install.*` keys created before tracking, use
a conservative cleanup batch covering registered providers and installed stateful
builtins. New installations use their recorded possible holders. Already-pruned
identities or never-registered custom providers cannot be reconstructed this way;
reconcile those resources explicitly during migration. A prepared batch is fixed
so later provider registration cannot silently change what completion means.

An interrupted transaction remains pending. Inspect its operation ID and source,
then reconcile the package database and installed files before finishing or
cancelling that same operation. Cancellation records a decision; it does not
restore files. Bundle publication has a specific recovery entry point:

```sh
switchboardctl recover-install OPERATION_ID /path/to/published/Example.cap
```

Custom installers must persist intent before changing files and finish only
after durable publication. Use `lifecycle issue ROOT` to obtain a persisted
operation ID and the matching begin/finish or prepare/retire/cancel commands
documented in switchboardctl(8). Keep the original ID for retries. Issuing a new
transaction to retry an old uninstall can target the wrong installation.

## History and system recovery

The registry keeps a recent window of 256 issued transactions, plus pending
operations and unfinished cleanup, their dependencies, live sources, and the
last-known installation for each label. This bounds repeated-operation history; it does not bound the
number of distinct labels or pending operations. Older exact-ID queries can
become `UNKNOWN`. The registry is operational history, not a permanent audit log.

`switchboardctl lifecycle prune ROOT [KEEP]` can retain a smaller window for that
invocation (1 through 256). Pruning also establishes rejection of unknown
operation IDs, including on legacy stores that previously accepted caller-chosen
IDs. Retained exact retries remain valid; discarded IDs fail with `ESTALE`.
Establish this policy before creating a recovery checkpoint with older state.
The fixed record limit can still be reached by live or pending state; treat a
capacity error as a failed transaction, never as permission to discard ownership.

Provider safety metadata is distinct from retained operation history. Log storage
keeps compact retirement fences so held old sessions cannot write again. The
persisted format currently caps this metadata at 1,048,576 entries per store. New fences stop at that limit with `ENOSPC`; existing entries and retries
remain usable. This failure must remain an unacknowledged cleanup
obligation, rather than writing metadata that cannot be reopened.

The current format is version 4. Version 3 is readable and becomes version 4 on
a changed commit without resetting installation IDs. Versions 1 and 2 require
an explicit migration. A downgrade to a version-3-only reader requires its
matching system snapshot.

For ZFS recovery, quiesce installation writers and snapshot the registry, package
database, and corresponding programs consistently. Include provider data in the
same recovery plan when it also needs rollback. Restore with the capability
runtime stopped, and boot the matching checkpoint before admitting new sessions.
Restore these together; rolling
back only `/Capabilities/Config/switchboard/lifecycle` can make installation
facts disagree with files and package state. A snapshot taken during an unfinished
operation restores that pending operation and still needs reconciliation. Do not
delete the registry to recover from corruption or copy it over a running writer.

For diagnosis, set `SWITCHBOARD_TRACE_INSTALLATION=1` in Capsule's environment
before starting the stack. It forwards the setting to switchboard, which logs
installation actions, labels, IDs, states, and errors through syslog. This is
opt-in tracing, not a replacement for retained operation records or audit policy.

## Exercising automatic cleanup

The installed test suite includes an explicit soak for a disposable VM booted
with `capability_plane="YES"`. Run it from an administrator login after startup.
If an early shell reports no administrator discovery channel, wait for providers
to become ready and log in again; that shell does not gain the channel later.
The test allocates resources through all five stateful providers, updates and replaces programs,
checks delayed cleanup and isolation, and retires each round's test resources:

```sh
sh /usr/tests/usr.sbin/switchboard/installation_cleanup_soak.sh \
    /usr/tests/usr.sbin/switchboard/installation_cleanup_fixture \
    /var/tmp/installation-soak /var/tmp/installation-soak-evidence
```

The defaults require at least 200 rounds, two hours, and ten normal reboots.
Exit status 85 requests a normal reboot; log in afterward and repeat the same
command with the same paths. Status 0 means the configured run completed; other
statuses require investigation. The evidence directory retains progress and
failure markers. Each round's `results.log` includes request stage, result and
elapsed time; inspect it when a provider fails to supply resources. Filesystem
allocation follows the production storage API's wait behavior because creating
private ZFS datasets can span multiple transaction syncs. The harness still
bounds its wait for resource readiness.

`CLEANUP_SOAK_ROUNDS`, `CLEANUP_SOAK_SECONDS`,
`CLEANUP_SOAK_REBOOTS`, and `CLEANUP_SOAK_REBOOT_INTERVAL` allow shorter harness
trials. A shortened trial does not establish sustained release qualification.

For a separate new run, use new work/evidence paths and set
`CLEANUP_QUALIFICATION_PREFIX` to an unused service-label prefix. Keep that prefix
unchanged across the run's reboots. Completed labels retain a minimal identity
fence, so reusing the default prefix does not create a fresh qualification run.

# Capability resource cleanup

The installation authority records removal; it does not decide what provider
data to delete. Automatic cleanup is disabled by default. The earlier cleanup
prototype described below requires an explicit experimental opt-in and remains
unqualified. Executable absence, stop, disable, or an uncertain inventory scan
never authorizes deletion. See the [authority contract](security/installation-authority.md)
for current behavior and the [experimental design](security/installation-retirement-design.md)
for the deferred provider work.

Normal bundle installation uses `switchboardctl install App.cap`, which stages,
verifies, publishes, and records the bundle version in one recoverable protocol.
For an offline root set `SWITCHBOARD_LIFECYCLE_ROOT=/target/root`; the default
bundle destination is then `/target/root/Capabilities`.

Managed package operations must use the wrapper:

```
switchboardctl lifecycle run / pkg delete example
switchboardctl lifecycle run /target/root pkg -r /target/root install example
```

The wrapper supplies `SWITCHBOARD_LIFECYCLE_OPERATION` and binds the selected root.
It does not add pkg root options itself. The coordinator and helper must already
be available, including inside a chroot. Package metadata uses a stable source
name and all its service labels in each hook:

```
pre-install:    switchboard-pkg-reclaim begin-install pkg:example/example org.example.App/main
post-install:   switchboard-pkg-reclaim install pkg:example/example org.example.App/main
pre-deinstall:  switchboard-pkg-reclaim prepare pkg:example/example org.example.App/main
post-deinstall: switchboard-pkg-reclaim retire pkg:example/example org.example.App/main
```

Upgrade removal hooks preserve state. Install hooks stage and finish the same
source reference and owner. Unwrapped hooks fail without modifying the ledger.
Hook failure does not establish rollback of pkg files; inspect both pkg state and
the ledger before recovering. Earlier installed metadata requires migration.

For recovery, reuse the exact operation ID printed by the wrapper or installer:

```
switchboardctl lifecycle status /target/root
switchboardctl lifecycle retire /target/root OPERATION_ID pkg:example/example org.example.App/main
switchboardctl lifecycle cancel /target/root OPERATION_ID pkg:example/example org.example.App/main
SWITCHBOARD_LIFECYCLE_ROOT=/target/root switchboardctl recover-install OPERATION_ID /target/root/Capabilities/ID@SEQUENCE.cap
```

Finish removal only after confirming the source was removed; cancel only if it
remains intact. For abandoned unpublished installs use `cancel-install` with the
operation, source and labels. `finish-install` is a root recovery attestation that
publication succeeded; prefer `recover-install` for bundles because it verifies
the published tree. Never recover by resolving a label to its latest installation.
`lifecycle install ROOT SOURCE LABEL...` records an already-published fresh source;
`adopt` explicitly preserves legacy ownership. These are administrative migration
operations, not substitutes for the normal bundle installer.

Retirement success means durable queuing, not that all providers have finished.
New installations target recorded holders; legacy installations use a conservative
provider fallback. A stateful provider registers `service_set_reclaim_handler()`
before readiness, returns zero only after durable cleanup, and uses its supplied
resource owner rather than the canonical policy label. No provider may use
`service_label_is_live()` as permission to delete data. The label-only reclaim
endpoint is disabled because it cannot identify the removal transaction.

The private service protocol is version 12 and libservice has SONAME 3. Rebuild
manager, libraries and consumers together. Veriexec signature enforcement is
unchanged; unsigned metadata does not become trusted through lifecycle tracking.

The active scope is the [small installation authority](security/installation-authority.md).
See its [operations notes](security/installation-retirement-operations.md) for
package wrappers, pending-operation recovery, and consistent backup/restore.
The broader cleanup prototype described above is not qualified for deployment.

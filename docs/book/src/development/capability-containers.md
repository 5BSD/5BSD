# Capability Data and Cleanup

A capability's runtime data lives in a container keyed by its stable label,
and cleanup happens by deleting that container. There is no installation
registry, no generation, and no reclaim protocol — the filesystem is the
record. This is the iOS container model: the container is the capability's
whole world, and removing the capability removes it.

The full design is in
[`docs/capability-container-model.md`](https://); this chapter is the working
summary.

## The layout

```
/Capabilities/
  System/   installed base bundles      pkg, read-only, veriexec
  Apps/     installed non-system bundles pkg, read-only
  Data/     runtime data                reclaimable, not pkg-owned
    <bundle>/<unit>/{persistent,cache,log}
    <bundle>/shared/                     shared between a bundle's units
    Shared/<group>/                      cross-capability group container
  Config/   static admin config
  Run/      ephemeral, cleared each boot; a marker per running unit
```

`System/` and `Apps/` are the installed set — the single source of truth for
what is installed. `Data/` holds everything a capability accumulates that pkg
never touches. A bundle is the unit of install and of cleanup; its units share
the bundle container and are reaped together.

## Capability mode: directories are delivered

A provider runs sandboxed and never opens a `/Capabilities` path. switchboard
hands each unit descriptors for the container(s) it may use — its private
`Data/<bundle>/<unit>/`, an optional bundle `shared/`, an optional group
container — and the unit only `openat`s under those. Shared configuration is a
shared descriptor delivered read-only.

## Cleanup: reconcile, not react

Cleanup is an asynchronous reconcile against the installed-plus-running set,
never a reflex to a filesystem event:

- **Install:** pkg drops a bundle into `System/`/`Apps/`; switchboard loads its
  units.
- **Uninstall:** pkg removes the bundle; switchboard notices, **unloads** the
  units (as launchd unloads a program), clears their `Run/` markers, and kicks
  a reconcile.
- **Upgrade:** pkg replaces the bundle; the data is never touched and the units
  are reloaded — no cleanup fires.

The reconcile is the shared `libcapreclaim(3)` primitive. A provider supplies
`enumerate()` (the owner keys it holds) and `destroy(owner)`; the library reads
the live set (`System/ ∪ Apps/ ∪ Run/`, i.e. installed **or** running) from
delivered read-only descriptors, and destroys the orphans — at **boot**
immediately (a settled state), on a **timer** only after an owner has been
orphaned on two consecutive passes (the grace that makes an upgrade's momentary
absence safe). tzfsd reaps `Data/` containers; a provider whose state is not in
the container tree (localcrypto's kernel keys) runs the same reconcile against
its own store. Everything else stores under its container and is oblivious to
cleanup.

## Writing a provider

Store per-capability state only under the delivered container, keyed by the
owner switchboard gives you, and — if your state is not purely files under that
container — become a `libcapreclaim(3)` client by supplying the two callbacks.
Anything stored per-owner and enumerable is reclaimed automatically; anything
stored unlabeled leaks.

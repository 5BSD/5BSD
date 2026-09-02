# Service file/directory descriptor delivery

Status: **superseded.** This document described an earlier, manifest-declared
mechanism (`capabilities.open`) in which a service listed the files and
directories it needed and `serviced` opened them and delivered the descriptors
at launch. That manifest capability has been **removed from the code** — along
with the never-used `capabilities.files` MAC-grant block — and is no longer a
way to obtain a file.

## Current model

A service that needs an existing file, directory, or device obtains it at
runtime by calling `service_open_isolated(3)`. The filesystem daemon (`tzfsd`)
opens the path under its own **per-label `open_paths` policy** and returns a
rights-limited descriptor. Nothing is declared in the unit manifest: the grant
lives in `tzfsd`'s policy, keyed on the requesting service's label, not on the
unit's `Unit.ucl`.

This keeps the capsicum-clean property the old mechanism was built for — a
service in capability mode never has to `open()` an ambient path — while moving
the grant out of the manifest and behind the filesystem authority that already
owns path resolution and per-vnode rights.

## See also

- `service_open_isolated(3)` — the consumer entry point.
- `service_storage_open(3)`, `service_open_config(3)` — related
  descriptor-acquisition APIs (all by-name, on-demand; `service_capability_open(3)`
  has been removed).
- `tzfsd(8)` / `system.Filesystem` — the daemon that opens paths under policy.
- docs/book/src/security/capability-bundles.md — background on the (now removed)
  manifest capability model; capabilities are acquired on demand, by name, and
  are no longer declared in the manifest.

# Capability container proofs

End-to-end proofs of the capability container model
(`docs/capability-container-model.md`) on a real guest: a fresh image is built
from an installed guest root, booted under qemu, driven over its serial
console, and asserted on from the outside (datasets, mounts, markers, the
units' own result files).  These are the runs behind every "proven on the VM"
statement in the spec and the commit log.

## Layout

| Path | What |
|------|------|
| `rig/` | the guest rig: `build-image-authority.sh` (image from `$VM/guestroot` + METALOG), `boot-qemu.sh`, `vcmd.sh` (console command bridge) |
| `lib/vmlib.sh` | shared helpers: `boot`, `V` (run a guest command), `build_image`, staging of test bundles, snapshot-clone observation of anonymous mounts |
| `probes/` | the throwaway units the proofs install (`reclaimprobe`, `envprobe`, `jailprobe`, `groupprobe`, `logprobe`, `cryptoprobe`) and `keyowners`; `probes/build.sh` builds them in a buildenv |
| `pkgbuild/` | the skeleton of the test package `pkgflow` builds with `pkg-static create` |
| `scripts/` | one proof per file, see below |
| `run-all.sh` | run every proof, summarize PASS/FAIL |

## Prerequisites

- A guest root at `$VM/guestroot` (default `~/vm`) from
  `make -DNO_ROOT -DDB_FROM_SRC DESTDIR=... installworld distribution installkernel`,
  with `Capabilities/Config/{tzfsd,sysextd,principal-policy}.ucl` in place.
- qemu (no root needed; see `rig/boot-qemu.sh`), `makefs`, `mkimg`, and for
  `pkgflow` a static `pkg-static` (`PKG_STATIC`, default `/usr/local/sbin/pkg-static`).
- Probes: `make buildenv BUILDENV_SHELL="sh tools/test/capability-containers/probes/build.sh"`.

Never rebuild the image while a booted guest is running: the builder stops any
guest first and replaces the image atomically, because an in-place rewrite
under a running guest corrupts the new image (the boot blocks then stop at
`boot:` with "Can't find /boot/loader").

## The proofs

| Proof | Shows |
|-------|-------|
| `sharedenv` | two units hold one shared store over one mount; read-only view enforced (every mutation `ENOTCAPABLE`); mount survives the writer's exit and goes with the last holder; a unit keeps its persistent store after claiming its cache; crash-restart churn re-claims every time |
| `labelreuse` | reinstall within the grace inherits the container, after a confirmed reap starts fresh; cache claimed and reaped; a snapshotted container is reaped (snapshots swept), a clone-pinned one fails soft; a half-extracted System bundle is quarantined and admitted by the settled retry |
| `groupreap` | group container survives while any member is installed, non-member refused, reaped when the last member goes |
| `pkgflow` | install and remove through `pkg(8)`: watch loads the unit, `pkg delete` removes the directory, watch unloads, next boot reaps |
| `folderwatch` | move System→Apps and remove with no reload: relaunch, unload, `Run/live` markers, container and log owner reaped |
| `logreap` | logd maps an emitting unit's owner to its bundle and seals it after removal |
| `cryptoreap` | localcrypto drops a removed bundle's kernel keys |
| `timerreap` | the timer path live, with short cadences: a removal undone within one interval is never reaped; a confirmed one is kept through one interval (grace) and reaped by the second, across tzfsd, logd and localcrypto |
| `providerdeath` | tzfsd killed under running units: stores stay mounted, the reader keeps reading, switchboard relaunches it, a later install claims from the new instance, no processes leak |
| `burst` | twelve bundles installed in one burst and removed in one: all loaded, marked and claimed; all unloaded; all reaped in one boot pass |
| `jailreap` | warden as a reconcile client: two bundles enter persistent jails; uninstalling one has the next boot pass remove its jail (attributed through warden's owner map) while the live bundle's jail survives |

Each proof prints `..._PASS` / `..._FAIL` verdict lines; `run-all.sh` counts them.
Units in capability mode cannot reach syslog, so the probes report through
files in their own persistent store, read back by the scripts through a
snapshot clone (`OBS`/`DROP_OBS` in `vmlib.sh`).

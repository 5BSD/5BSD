# Upgrading

5BSD has no public package server. Base-system updates come from a pkgbase
repository you build on disk and publish over `file://`; third-party
software keeps coming from the FreeBSD ports repositories. That split is the
whole upgrade model, and it has one rule that must never be broken: base
packages come from a 5BSD repository, never from `FreeBSD-base`. This chapter
covers configuring the local repository, the 5BSD-to-5BSD upgrade loop, the
one-time migration from a FreeBSD pkgbase system, and what to verify after
the reboot. Building the repository is in [Building](building.md); pkg(8)
itself, boot environments and `bectl` are FreeBSD Handbook material.

## Hardware telemetry package rename (2026-10-08)

Existing `5BSD-hwtlm`, `-man`, `-dbg`, and `-tests` packages require an
explicit transition to `5BSD-hwstat`. After publishing the combined
repository and creating the usual boot environment snapshot, run
`pkg update -r 5BSD-base`, then
`sh /usr/src/tools/build/migrate-hwstat-packages.sh` before the normal
`pkg upgrade -n -r 5BSD-base` preview and `pkg upgrade -r 5BSD-base`.
These commands require root in the installation being upgraded.

The helper checks all installed old packages before renaming their database
identities and dependency references. It refuses missing replacements,
equal or older replacement versions, locked packages, or an installation
containing both names. Publish a strictly newer `PKG_VERSION` before this
transition; a database rename alone does not force file replacement.
An interrupted migration is checked again, including already renamed
entries whose installed origin still identifies the old package. The following
upgrade replaces the old files and package origins; no command or manual
alias remains. Repeating the helper is safe. Fresh installations do not
need this step. This migration does not install an upgrade or reboot by itself.

## Why the rule exists

`pkg upgrade` resolves by package name and version across every enabled
repository. The ABI string is `FreeBSD:16:amd64` on purpose, so an enabled
`FreeBSD-base` repository would offer `FreeBSD-*` packages that pkg considers
unrelated to your `5BSD-*` ones; it would not overwrite them by name, but a
`pkg install FreeBSD-runtime` or a metapackage pull would happily lay a
FreeBSD kernel or libc beside the 5BSD one. There is no kernel without the
plane compiled in, no `capability` identity in a foreign `master.passwd`,
and no `/Capabilities` in a foreign runtime package. Disabling
`FreeBSD-base` is therefore the first step everywhere below;
`FreeBSD-ports` stays enabled. Keep `FreeBSD-ports-kmods` disabled;
kernel-bound drivers come from the combined `5BSD-base` repository.

## The standard repository needs no configuration

`/etc/pkg/5BSD.conf`, shipped by `usr.sbin/pkg/5BSD.conf.in`, already names
the repository produced by a standard build from `/usr/src`:

```
5BSD-base: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: no
}
```

`pkg update -r 5BSD-base` and `pkg upgrade -r 5BSD-base` explicitly select
this entry even when `enabled` is `no`. No new repository file or enable
step is required. The disabled default keeps ordinary ports operations
from trying to read a build repository before one exists. The path does not
scan `/usr/obj`: it must contain the catalogue and package archives under
`repo/${ABI}/latest` (`${ABI}` is `FreeBSD:16:amd64` on amd64).

These defaults are included in world and release images. The installer uses
its separate offline repository on installation media when present. A new
installation does not thereby acquire future updates or a populated build
tree: build or publish a repository at the standard path before upgrading.
The native book is installed under `/usr/share/doc/5bsd`, including this
chapter and [Building](building.md).

### Custom paths and existing overrides

Only a nonstandard location or repository name needs configuration.
`MAKEOBJDIRPREFIX`, a different source path, or `REPODIR` can change where
packages land. Check `pkg -vv` against the actual output path. You may keep
objects elsewhere and publish with `make packages REPODIR=/usr/obj/usr/src/repo`
(using the same object prefix as the build); this retains the standard URL.
Publishing there requires write access to that directory.

For a different URL, copy `docs/pkg/5BSD.conf.sample` to
`/usr/local/etc/pkg/repos/5BSD.conf` and adjust it. Keep the name `5BSD-base`
so the commands below stay the same. The sample enables unqualified updates
as an optional choice; explicit `-r` commands do not need it. Keep
`FreeBSD-base` and `FreeBSD-ports-kmods` disabled, as the shipped defaults do.
Older overrides can replace the shipped URL, so inspect the effective
configuration before relying on the default.

If publishing to another machine, copy the complete version directory,
including catalogue files and the archives they reference, then update
`latest` after the copy succeeds. A complete existing repository can be
published at the standard path without recompiling world or the kernel.
If package contents change, regenerate the catalogue with `pkg repo`.

## The 5BSD-to-5BSD loop

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel WITH_MALLOC_PRODUCTION=yes
make -j$(sysctl -n hw.ncpu) packages PKG_CMD=/usr/local/sbin/pkg-static
```

A world that will be published is built with `WITH_MALLOC_PRODUCTION=yes`:
development worlds keep the debugging malloc(3), and `make publish-packages`
and `make system-packages` refuse a base built from one (see
[Production malloc for publication](building.md#production-malloc-for-publication)).

`make packages` writes `repo/${ABI}/<version>/` and updates `latest-built`.
It does **not** change the published `latest` pointer. Build matching hardware
separately, then publish the complete generation as described below before
running an upgrade. A failed build or publication leaves the previous update
repository selected.

With the default ZFS layout, the root boot environment contains the base
system, `/Capabilities/System`, and `/var/db/pkg`. The parent `zroot/var`
has `canmount=off`; its existence does not mean all of `/var` is shared.
Only `/var/audit`, `/var/cache`, `/var/crash`, `/var/log`, `/var/mail`, and `/var/tmp` are
separate shared datasets under `/var`. `/usr/local` and home are shared too.
`/Capabilities/Run` is transient. `bectl create` therefore preserves the
package database with base; do not restore it separately after BE rollback.
Check `df /var/db/pkg` and `zfs list -o name,mountpoint,canmount,mounted` for
custom layouts. A BE does not roll back ports files in shared `/usr/local`.

### Storage requirements for a future immutable base

The immutable-base mechanism is not implemented. The current boot environment
layout is a starting point, not a complete read-only system layout.

A base generation must keep its files and package metadata consistent. The
current shared `/usr/local` is outside BE rollback, while `/var/db/pkg` is
inside it. If ports are changed after a snapshot, rolling back that database
can disagree with the surviving ports files. A future layout must either
separate base and ports package state, including dependency handling, or
coordinate their files and metadata within the same rollback operation.
Moving the entire package database to a shared dataset would instead separate
base files from their metadata and does not solve this problem.

Configuration and durable application data need explicit compatibility and
migration rules across generations. `/etc` cannot simply become read-only
without providing for local configuration changes. Likewise, `/var/db` mixes
package metadata with writable service state; sharing or freezing that entire
tree is not a substitute for identifying its owners. Caches, logs, runtime
state, temporary files, and update staging need writable locations and space
policies. Fresh installer defaults and release VM images keep `/usr/obj`,
including the local package repository, outside the base boot environment.
They also give `/var/cache` its own shared dataset. Cache contents must remain
reconstructible and consumers must validate formats across upgrades and rollback.
This layout does not authorize deleting caches currently used by an application
or package transaction. Existing installations require a separate migration;
changing installer defaults does not move their directories.

Reclamation must preserve installed generations, rollback targets, active
updates, and resources held by users of either generation. Age or a missing
path alone cannot establish that storage is unused. The future shared reaper
must coordinate with installation and storage ownership before deleting it.

Acceptance requires a disposable installed VM: exercise package changes,
upgrade and rollback, interrupted updates, low-space recovery, and a read-only
base trial while checking configuration and application data remain usable.
These requirements do not prescribe or authorize repartitioning existing
systems; migration remains separate work.

### Publish base and matching hardware together

Use the maintained build targets with the custom ports checkout selected by
`PORTSDIR`. When base packages already exist:

```sh
cd /usr/src
make hardware-packages KERNCONF=GENERIC-NODEBUG \
    PORTSDIR=/usr/ports
make publish-packages
```

Use the kernel configuration that was built. The hardware step uses unprivileged ports staging and does not install
anything on the host. External build prerequisites must be prepared separately. See
[Building](building.md) for the read-only preflight and path overrides.
`make system-packages` combines base packaging, hardware packaging and
publication after world and kernel have been built.

Publication checks the kernel identity, merges hardware archives with base,
rebuilds the catalogue, and atomically changes `latest` only after verification
succeeds. Inputs remain untouched. Set `HARDWARE_SIGNING_KEY` to sign the final
repository. Installer images can consume the resulting matching hardware
repository through their existing `HARDWARE_REPO` setting.

On a system previously using a separate `5BSD-hardware` repository, disable
that entry (including any local override). Keep the base repository's standard
URL. Both kernel and driver updates now use one transaction:

```sh
bectl create pre-upgrade
pkg update -f -r 5BSD-base
pkg upgrade -n -r 5BSD-base
pkg upgrade -r 5BSD-base
reboot
```

The exact-kernel identity dependency remains mandatory. Review the transaction
for matching kernel/driver versions and unexpected removals. Do not substitute
upstream FreeBSD kernel modules. Publishing does not install or reboot.

The reboot is not optional after a kernel or switchboard upgrade. The
kernel package replaces `/boot/kernel`, and switchboard, capsule and the
provider bundles under `/Capabilities/System` are replaced in place while
the old processes keep running from their held descriptors. Switchboard's
install-folder watch notices the changed bundles and reloads the registry
(`registry: install folders changed; reloading` in `/var/log/messages`),
which restarts units whose bundle manifest changed and logs `reload: N new,
N changed, N removed`; but PID 1 and the
service manager itself only pick up new binaries at boot, and a kernel from
a different build than the modules and the `mac_capability` gate consumers
is exactly the skew [Troubleshooting](troubleshooting.md) warns about. Reboot
once, immediately.

Verify after the reboot:

```sh
uname -i                      # GENERIC
pkg info 5BSD-kernel-generic  # the version you built
pkg query '%n' | grep '^FreeBSD-'   # investigate any upstream base packages
ps -p 1 -o comm=              # capsule
switchboardctl services
```

To roll back, `bectl activate pre-upgrade && reboot`.

Ports packages upgrade independently and at any time:

```sh
pkg upgrade -r FreeBSD-ports
pkg upgrade -r FreeBSD-ports codex     # one package and its dependencies
```

## Migrating from FreeBSD pkgbase

A FreeBSD 16-CURRENT pkgbase system can be converted in one operation. The
package names differ (`FreeBSD-*` to `5BSD-*`), so `pkg upgrade` cannot do
it; the base set is deleted and reinstalled from the 5BSD repository inside
one boot environment. Build the repository, install the repository sample
as a `5BSD-base` entry on the FreeBSD host, and disable `FreeBSD-base`
with `docs/pkg/FreeBSD.conf.sample`, then:

```sh
bectl create pre-5bsd-migration
pkg update -f -r 5BSD-base
pkg delete -fa
pkg install -r 5BSD-base 5BSD-set-base 5BSD-kernel-generic
reboot
```

`pkg delete -fa` removes every package, ports included, so expect to
reinstall third-party software afterwards from `FreeBSD-ports`. The `runtime`
package's scripts create the `capability` user and group (uid and gid 976)
in your existing `master.passwd` during the install, regenerate `pwd.db`,
and refuse to complete if the name does not resolve. `/Capabilities` is
created by the mtree in the same package, but nothing adds the
`/Capabilities/Run` tmpfs line to an existing fstab, nor configures the `pool =` line in
`/Capabilities/Config/bsdfilesystem.ucl`; configure both before the reboot,
following [Installing](installing.md). Software attributes are supplied by
installed bundle manifests; no principal-policy file is required. The old `init_path` in
`/boot/loader.conf`, if you had set one, must go: the new default starts
`/sbin/capsule` first.

After the reboot, `uname -i` shows `GENERIC`, `ps -p 1 -o comm=` shows
`capsule`, and `pkg query '%n' | head` shows `5BSD-*` names. The plane is
compiled in, so there is no `mac_capability.ko` to look for in `kldstat`;
`kldstat -m mac_capability` still reports it because static modules register
too. Roll back with `bectl activate pre-5bsd-migration && reboot`.

## Older installations and custom repository names

An older installation may still point `5BSD-base` at `pkg.5bsd.org`.
Replace that URL with the local URL using `docs/pkg/5BSD.conf.sample`;
explicit `-r` selects a disabled entry, so disabling a stale URL alone does
not fix a command that names it. If you deliberately keep a custom
repository named `5BSD`, use `-r 5BSD` for that entry instead. Inspect
`pkg -vv` to avoid selecting the wrong generation. Source template changes
reach an installed system through `5BSD-pkg-bootstrap` and configuration
merging; local overrides continue to take precedence.

## Checklist

| Step | Command | Why |
|---|---|---|
| Build kernel and world together | `make buildworld buildkernel WITH_MALLOC_PRODUCTION=yes` | Modules are packaged from the kernel tree; a world-only build ships stale modules. Publication refuses a debug-malloc world |
| Package with the static pkg | `make -j$(sysctl -n hw.ncpu) packages PKG_CMD=/usr/local/sbin/pkg-static` | The dynamic ports pkg can fail on libc symbol versions |
| Confirm repository set | `pkg -vv` | `5BSD-base` has the expected local URL; upstream base and kmods disabled |
| Checkpoint | `bectl create pre-upgrade` | Rollback for the whole base generation |
| Upgrade base only from 5BSD | `pkg update -f -r 5BSD-base; pkg upgrade -r 5BSD-base` | Never from a FreeBSD repository |
| Reboot at once | `reboot` | Kernel, capsule and switchboard binaries are only replaced at boot |
| Verify | `uname -i`, `ps -p 1 -o comm=`, `switchboardctl services` | GENERIC, capsule, all expected units |

## What does not upgrade this way

Applications upgrade separately from `FreeBSD-ports`. External kernel
modules come from the matching `5BSD-hardware` collection, not
`FreeBSD-ports-kmods`. The `5BSD-*-tests` packages and `5BSD-set-tests` upgrade
with the base but are not installed by default. A custom `KERNCONF` produces
a `5BSD-kernel-<name>` package that `pkg install` accepts; keep
`5BSD-kernel-generic` installed alongside it as the recovery kernel. Finally,
there is no signing of the local repository unless you set
`PKG_REPO_SIGNING_KEY` at build time, so the trust in this loop is the trust
you place in the disk the repository sits on.

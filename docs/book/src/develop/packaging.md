# Packaging and Shipping

5BSD is pkgbase-native and has no public package service. A bundle reaches
a machine as a `5BSD-<name>` package built from the source tree, published
into a local `file://` repository, and installed with pkg(8); switchboard
notices the new directory under `/Capabilities/System` or
`/Capabilities/Apps` and loads the units without a reload. This chapter
walks the path from a bundle in the tree to a running unit on another
machine: the `PACKAGE=` tags that decide which package a file lands in, the
`packages/<name>` definition and its UCL, why bundle directories must be
owned by the package, what the folder watch does when pkg writes, the
local repository loop, and how versions are computed and compared.

## Where a file's package is decided

Every install rule in `share/mk` tags what it installs with
`package=${PACKAGE}`, and `PACKAGE` unset means `utilities` (for kernel
modules, `kernel`). The tag lands in the staged METALOG and
`release/scripts/mtree-to-plist.awk` turns each tagged line into an entry
of `<package>.plist`; a file with no tag is dropped. So a program Makefile
sets `PACKAGE=` once, and every group it installs can override it.
`usr.sbin/BSDLog/Makefile` is the full shape for a bundle:

```make
PACKAGE=	bsdlog
PROG=		BSDLog
MAN=		BSDLog.8

DIRS+=		LOGCMP_CAP LOGCMP_CAP_UNITS LOGCMP_CAP_UNIT LOGCMP_CAP_BIN \
		LOGCMP_CAP_CONFIG
LOGCMP_CAP=	/Capabilities/System/Log.cap
LOGCMP_CAPPACKAGE=	bsdlog
LOGCMP_CAP_UNITS=	${LOGCMP_CAP}/Units
LOGCMP_CAP_UNIT=	${LOGCMP_CAP_UNITS}/bsdlog.unit
LOGCMP_CAP_BIN=	${LOGCMP_CAP_UNIT}/bin
LOGCMP_CAP_CONFIG=	${LOGCMP_CAP_UNIT}/Config
LOGCMP_CAP_UNITSPACKAGE=	bsdlog
LOGCMP_CAP_UNITPACKAGE=	bsdlog
LOGCMP_CAP_BINPACKAGE=	bsdlog
LOGCMP_CAP_CONFIGPACKAGE=	bsdlog
BINDIR=		${LOGCMP_CAP_BIN}

FILESGROUPS=	CAP_BUNDLE CAP_UNIT
CAP_BUNDLE=	capbundle/Bundle.ucl
CAP_BUNDLEDIR=	${LOGCMP_CAP}
CAP_BUNDLEMODE=	0444
CAP_UNIT=	capbundle/bsdlog.ucl
CAP_UNITDIR=	${LOGCMP_CAP_UNIT}
CAP_UNITNAME=	Unit.ucl
CAP_UNITMODE=	0444

CONFS=		capbundle/bsdlog.conf
CONFSDIR=	${LOGCMP_CAP_CONFIG}
CONFSPACKAGE=	bsdlog
CONFSDIRPACKAGE=	bsdlog

.include <bsd.prog.mk>

_proginstall: installdirs-LOGCMP_CAP_BIN
```

Three details carry the design. `capbundle/` is a data directory, not a
subdirectory build: it holds `Bundle.ucl`, the unit manifest (installed
under its unit directory as `Unit.ucl` through `CAP_UNITNAME`) and the
config file, and the parent Makefile installs them. `BINDIR` points inside
the bundle, so the program lands at `Log.cap/Units/bsdlog.unit/bin/BSDLog`
and never in `/usr/sbin`; the final line orders directory creation before
the program install. And every `DIRS` entry carries its own `PACKAGE`
suffix, which is what the next section is about. Libraries use
`PACKAGE=lib${LIB}` so `liblogcmp` becomes `5BSD-liblogcmp` with `-dev`,
`-dbg` and `-man` subpackages split off by `bsd.lib.mk`.

## Owning the bundle directories

The mtree files declare only the roots. `etc/mtree/BSD.root.dist` lists
`/Capabilities`, `Config`, `Run` (mode 0700), `State`, `State/switchboard`
and `System`, all `package=runtime`; no `.cap` directory appears in any
mtree, and `/Capabilities/Apps` is in none either (pkg creates it with the
first application bundle, and switchboard watches for it to appear). Bundle
directories therefore come from `DIRS=` in the bundle's own Makefile.
`bsd.dirs.mk` installs each one with `install -T package=<name> -d`, the
METALOG records a `type=dir` line with that tag, and the plist gets
`@dir(root,wheel,0755,) /Capabilities/System/Log.cap` and its children.

This is a rule, not a convenience. `docs/book/src/plane/containers-and-storage.md`
states it: a package must own its bundle directories so that removing the
package removes the directory and not only the files. The folder watch
reacts to the bundle directory disappearing; a package that leaves an empty
`Log.cap` behind is noticed by the one-level bundle watch, but the clean
signal is the `@dir` removal. The `bsdlog` manifest lists `Log.cap`,
`Units/`, `bsdlog.unit/`, `bin/` and `Config/` for exactly this reason.

## The package definition

A package is three files plus one line. `packages/bsdlog/Makefile`:

```make
WORLDPACKAGE=	bsdlog
PKG_SETS=	minimal
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=	${SRCTOP}/release/packages/ucl/bsdlog-all.ucl
UCLSRC.bsdlog=	bsdlog.ucl

PKG_DEPS.bsdlog+=	bsdaudit
PKG_DEPS.bsdlog+=	libauditcmp
PKG_DEPS.bsdlog+=	libchannel
PKG_DEPS.bsdlog+=	liblogcmp
PKG_DEPS.bsdlog+=	libservice
PKG_DEPS.bsdlog+=	libucl
PKG_DEPS.bsdlog+=	libshmring
PKG_DEPS.bsdlog+=	switchboard
PKG_DEPS.bsdlog+=	switchboardctl

.include <bsd.pkg.mk>
```

`release/packages/ucl/bsdlog-all.ucl` carries `comment` and `desc` and
applies to every subpackage; `packages/bsdlog/bsdlog.ucl` applies to the
base package only and is where dependencies with scripts and install hooks
belong (`release/packages/ucl/README` gives the policy: no dependency for a
shared library pkg detects on its own, no dependency on `rc` or `devd` for
scripts, a dependency on `runtime` for `/bin/sh`). The one line is the
entry in `packages/Makefile`, in `SUBDIR` or the matching
`SUBDIR.${MK_FOO}+=` list. `bsd.pkg.mk` refuses to build a package whose
plist has no non-directory entries, and its comment names the usual cause:
the package was not excluded in `packages/Makefile` for a `src.conf` option
that turned its contents off.

| Variable | Meaning |
|---|---|
| `WORLDPACKAGE` | the package's base name; `5BSD-` is prefixed from `PKG_NAME_PREFIX` |
| `PKG_SETS` | the `set` annotation; `minimal` is the plane metapackage `5BSD-set-minimal`, `tests` selects `5BSD-set-tests`, default `optional optional-jail` |
| `SUBPACKAGES` | which of `dbg`, `dev`, `man`, `lib` to split; default `dbg man` |
| `PKG_DEPS.<pkg>` | dependencies, emitted with the build's own `PKG_VERSION` |
| `UCLSRC`, `UCLSRC.<pkg>` | the `-all` UCL and the per-subpackage UCL |
| `PKG_LICENSES` | default `BSD2CLAUSE` |
| `PKG_VITAL.<pkg>` | marks the package vital (only `runtime`) |

The pipeline in `bsd.pkg.mk` appends the generated name, origin, version,
maintainer, sets and dependencies to the UCL, runs
`release/packages/generate-ucl.lua` to rewrite subpackage names and sets
(`-dev` and `lib*-man` go to `devel`, `-dbg` to `<set>-dbg`), calls
`pkg create` against the world stage, and `stagepackages` copies the result
to `${REPODIR}/${PKG_ABI}/${PKG_VERSION}`.

## Runtime or an own package

The base providers split two ways. BSDFilesystem, BSDPower, BSDTime,
BSDExtension, BSDNamespace and BSDVM set `PACKAGE= runtime` and ship inside
`5BSD-runtime` with the rest of the core system; BSDAudit,
BSDCrypto, BSDDevice, BSDLog, BSDNetwork, BSDNotify, BSDTrace (as
`bsdtrace-provider`) and BSDBluetooth have packages of their own, as do
capsule, switchboard and every client library. The tree does not record a
written rule for the split; the observable one is that a provider without
which the plane cannot store, load modules, tell time or come up at all
travels with `runtime`, and anything an operator might plausibly leave out
or replace gets its own package. A new bundle should get its own package.
`5BSD-set-minimal` pulls capsule, switchboard and the system providers, so a
plane boots from that set; `5BSD-set-base` boots plain `/sbin/init`.

Install hooks live in the per-package UCL. `packages/runtime/runtime.ucl`
creates the `capability` user and group (uid and gid 976) in `pre-install`
and again in `post-install` after bootstrapping `pwd.db` on a fresh root,
then verifies both with `pw -V`; `packages/switchboard/switchboard.ucl`'s
`post-install` removes retired bundle trees, because a removed system
bundle left installed is boot-fatal on a plane that fails closed on
invalid system policy. A bundle package normally needs no hooks at all.

## Kernel modules travel with their tools

`sys/conf/kmod.mk` installs a module with `-T ${KMODTAGS}`, which defaults
to `package=${PACKAGE:Ukernel}`. A module Makefile that sets `PACKAGE=`
therefore puts its `.ko` in that pkgbase package; `sys/modules/oes/Makefile`
sets `PACKAGE= oes` and `sys/modules/mac_capability_test_keystore/Makefile`
sets `PACKAGE= mac-capability-tests`. `Makefile.inc1`'s `create-world-packages`
copies every module whose tag is not `kernel` or `dtb` from the kernel stage
into the world stage, concatenates the two METALOGs, and runs the plist
script over both, so one package can hold the module, the daemon that loads
it and the tests. The module still has to be on BSDExtension's
allow-list to load (see [A Kernel Extension](kernel-extension.md)).

## Tests are a package too

Each suite is its own package so an installed system can run it without
the source tree. The tests Makefile names it and the install directory:

```make
PACKAGE=	bsdlog-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDLog
```

`packages/bsdlog-tests/Makefile` sets `PKG_SETS= tests`, no subpackages,
and depends on `atf`, `kyua`, `bsdlog`, `switchboardctl` and `set-base`;
`release/packages/ucl/bsdlog-tests-all.ucl` adds
`annotations { set = "tests" }`. The 47 test packages are listed behind
`MK_TESTS` in `packages/Makefile` and collected by `5BSD-set-tests`.
Running them is in [Testing](testing.md).

## Install: pkg writes, switchboard sees it

Installing a bundle package is `pkg install` and nothing else. Switchboard
keeps an edge-triggered `EVFILT_VNODE` watch on each install root
(`/Capabilities/System` and `/Capabilities/Apps`) and one level down on
every `<Name>.cap` directory (`usr.sbin/switchboard/registry_watch.c`). A
pkg extraction touches the root many times; the events coalesce and a
one-shot settle timer (`SWITCHBOARD_REGISTRY_WATCH_SETTLE`, 1 to 60
seconds, default 2) runs a single registry rescan after the last change,
the same rescan `switchboardctl reload` would run. New units are loaded and
started according to their `activation`; removed units are unloaded.

Because the files below `Units/` are two levels down and invisible to the
watch, a rescan can catch a bundle still extracting. A bundle not yet
registered that fails validation is quarantined, counted and skipped
without displacing anything; an already registered bundle caught half
written keeps its previous registration, marked stale, so its units are
never stopped for a transient state. The watch then retries a bounded eight
settled times and admits the bundle once it is whole; a bundle that stays
malformed is left out until the folder changes again, and only a change
restarts the budget. A user bundle that conflicts with the registry
(shadowing a system `bundle_id`, a duplicate unit label or provided name)
is quarantined with the reason and never fails the scan. An edit deep
inside an installed bundle is not an install event and still needs an
explicit reload. The log line to look for is
`registry: install folders changed; reloading`.

Uninstall is the same path in reverse: pkg removes the directory, the watch
unloads the units and clears their `Run/live` markers, and only then is the
bundle's data an orphan. The providers reap it on their next reconcile
pass, and on a timer they destroy only what was already orphaned at the
previous pass (seen-gone-twice), so the seconds a bundle is absent during
`pkg upgrade` never confirm a reap; an in-place upgrade keeps the bundle's
persistent container and its data. There is no pkg lifecycle hook; the
watch and the reconcile grace are the whole mechanism. The proofs are
`tools/test/capability-containers/scripts/pkgflow.sh` (a real `.pkg` added
with `pkg-static add`, no reload, then deleted), `folderwatch.sh` (a bundle
moved from `System/` to `Apps/` with no reload) and `upgradeflow.sh` (same
`bundle_id`, bumped `sequence`, data intact across upgrade and reboot).

## The local repository loop

The shipped `5BSD-base` entry already points at a standard `/usr/src`
build's repository under `/usr/obj/usr/src/repo/${ABI}/latest`. Explicit
`-r 5BSD-base` works with its disabled default; no override file is required.

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel
make packages PKG_CMD=/usr/local/sbin/pkg-static
bectl create pre-upgrade
pkg update -f -r 5BSD-base
pkg upgrade -n -r 5BSD-base
pkg upgrade -r 5BSD-base
reboot
```

`make packages` creates the catalogue and updates `latest`. The repository
is `${REPODIR}/${PKG_ABI}/${PKG_VERSION}`, with `REPODIR` defaulting to
`${OBJROOT}repo`. Set `REPODIR=/usr/obj/usr/src/repo` when publishing a build
whose objects live elsewhere, or use the optional repository override
sample for a custom URL. The ABI remains `FreeBSD:16:amd64` on amd64 for
ports compatibility. Keep upstream base and kernel-module repositories
disabled.

The complete procedure, including matching hardware packages, boot
environments and FreeBSD-to-5BSD migration, is in
[Upgrading](../operations/upgrading.md). Applications upgrade separately
with `pkg upgrade -r FreeBSD-ports`. For a single bundle,
`pkg install -r 5BSD-base 5BSD-<name>` deploys it; the registry watch handles
the lifecycle change.

## Versioning

Two version numbers exist and mean different things. The package version
is computed in `Makefile.inc1` from `sys/conf/newvers.sh`: on a `CURRENT`
tree `PKG_VERSION` is `<major>.snap<YYYYMMDDHHMMSS>` (for example
`16.snap20260925121500`), on a release branch it is the revision with
`p<n>`, and `SOURCE_DATE_EPOCH` for reproducible contents is the commit time
of `HEAD`. Every package in one build carries the same version and every
generated dependency pins it, so a repository is a coherent set.
`update-packages` compares the content checksum (`pkg query %X`) of each new
package with the previous `latest` and keeps the old file when only the
version differs, so a rebuild does not force clients to refetch unchanged
packages.

The bundle version is in `Bundle.ucl` and is switchboard's concern:

```
bundle_id = "system.Log";
version = "1.0.0";
sequence = 1;
```

`version` is informational. `sequence` is what the registry compares:
installed versions are immutable directories named by identity, and
`usr.sbin/switchboard/bundle_registry.c` keeps exactly the highest
`sequence` for a `bundle_id`, logging `selecting '<id>' sequence N over M`.
A user bundle may never shadow a system bundle with the same identity, and
a duplicate sequence is a conflict. An upgrade is therefore the same
`bundle_id` with a bumped `sequence`, in place; bump both numbers in
`Bundle.ucl` when you cut a release, and let the package version track the
build.

## Release hardware packages

External drivers and firmware must be released with the 5BSD kernel they were
built against. `FreeBSD:16:amd64` and `__FreeBSD_version` alone do not describe
the fork's kernel interfaces. FreeBSD's binary kmods repository is disabled by
default; ordinary userland ports remain available.

`release/scripts/hardware-packages.py build` builds a hardware profile from a
pinned ports tree in a **disposable native-architecture build root**. Prepare
that root with the release world, pkg, the exact source snapshot and retained
kernel build directory used to produce the kernel package, and the ports tree.
Mount devfs in the build root and provide DNS for fetching distfiles. Do not use
the installed system as the build root. The script rejects preinstalled ports
other than pkg, checks the build kernel against the packaged kernel, and sets
`SRC_BASE`, `OSVERSION` and `KERNBUILDDIR` for recursive ports builds. Preserve
the source snapshot unchanged throughout the kernel and hardware builds.

For amd64 the default profile is `release/tools/hardware-ports.amd64`. It builds
DRM and the full graphics and Wi-Fi firmware metaports, including USB Wi-Fi,
plus Intel and Realtek Bluetooth firmware. The inclusion and qualification
policy is in `release/tools/hardware-amd64.md`.
Extend the profile for other device families; use a separate validated profile
for other architectures. The build checks the literal package names in all
fwget providers against the produced dependency closure. A missing dependency
or supported-device package fails the build instead of fetching a binary module.
Firmware already shipped in the base kernel remains part of the base packages.
Raw board firmware (for example the RPi profile's boot firmware) retains its
board-specific staging process; its compatibility is not inferred from a kernel
version number. Additional raw firmware ports can also be included in a profile.

Example, with paths inside the build root for `--source` and `--kernel-build`,
and host paths for the other arguments:

```sh
python3 release/scripts/hardware-packages.py build \
    --root /build/5bsd-hardware-root \
    --source /usr/src \
    --kernel-build /usr/obj/usr/src/amd64.amd64/sys/GENERIC \
    --kernel-package /build/base/5BSD-kernel-generic-RELEASE_VERSION.pkg \
    --port-list release/tools/hardware-ports.amd64 \
    --epoch "$SOURCE_DATE_EPOCH" \
    --output /build/hardware-repo
make -C release HARDWARE_REPO=/build/hardware-repo release
```

Python 3.11 or later is required only on the build host. `--epoch` must be a
positive, monotonically increasing release timestamp and remain fixed when
reproducing a release. The ports revision, source snapshot, kernel configuration
and build toolchain should be retained with the release artifacts. The output
must be a new empty directory; failed builds are not published.

The tool gives packages `5BSD-hw-` names and rewrites their runtime dependency
closure. This avoids replacing them with same-named FreeBSD binaries. Kernel modules, support packages, metapackages and the repackaged kernel depend
on a package named for the SHA-256 of the kernel. Data-only firmware packages
retain their upstream version and have no exact-kernel dependency. Those identity packages own the same file, so pkg cannot
install two kernel identities together. The kernel is marked vital. This makes
kernel and hardware updates a single compatible transaction, or a transaction
that explicitly removes unsupported hardware packages. Modules, data-only firmware, metapackages and other support packages are
recorded separately in `hardware.json`. Raw firmware is still selected and
tested with the driver release, but does not require compilation or acquire a
kernel ABI dependency.

GPU firmware produced by the pinned ports tree is converted from kernel module
wrappers to byte-identical data under `/boot/firmware`, retaining its firmware
name and license files. The release tool rejects unexpected payloads or missing
binary symbols. Only DRM driver code remains tied to the exact kernel identity.
On installed systems, the `kld_list` startup service uses `sysextctl` and the
explicit SystemExtension allowlist. The broker policy, rather than a GPU-name
list in the startup script, decides which modules are permitted. A broker denial
is not retried through `kldload`. Early boot module helpers keep their existing
direct-loading path until the filesystems and services needed by the broker
are available.
The kernel permits an authorized module-loading capability holder to request
firmware during driver attachment, while retaining the securelevel restriction.


The release makefile verifies the kernel identity, replaces the kernel package
in its base repository, and stages hardware on disc, DVD and bootonly media.
Wi-Fi, graphics and Bluetooth firmware are installed into the live image as well as carried
as packages for the target. Kernel modules are never loaded by the build tool.
`WITHOUT_HARDWARE_PACKAGES=yes` explicitly builds media without this external
hardware support; the normal build fails if `HARDWARE_REPO` is missing or wrong.

### Installing the hardware collection on an existing system

The same offline collection serves bsdinstall and an already installed system.
Use a collection built for the installed kernel; the shared installer verifies
that identity before installing driver packages. A firmware package alone does
not supply a missing driver. In particular, MT7925 still requires completion of
its LinuxKPI/mt76 driver support.

With the current fwget providers and hardware-install helper installed, root can
copy the collection to the standard location using bsdinstall's helper, then
install packages selected for the machine:

```sh
BSDINSTALL_CHROOT=/ BSDINSTALL_HARDWARE_MEDIA=/build/hardware-repo \
    /usr/libexec/bsdinstall/firmware-fetch --auto
```

The source collection must be outside `/usr/5bsd-packages/hardware` for this
copying step. Subsequent runs can use `fwget` directly. Successful GPU package
installation records the selected driver in `/etc/rc.conf.d/kld`, preserving
other module selections. During bsdinstall it instead writes the temporary
`rc.conf.hardware` fragment for the target configuration. Neither path loads
modules immediately; startup requests them through SystemExtension. A failed
package transaction does not configure GPU startup.

When provisioning an older installation whose kernel package has not yet been
sealed with the hardware identity dependency, reinstall the **matching sealed
kernel package** from the collection as part of provisioning. This preserves
the coordinated kernel/module upgrade behavior described above. Do not substitute
a collection for a different kernel, or use the media-staging command on `/`:
media staging installs the full live firmware selection and writes a METALOG.

Publish the **repackaged** base kernel, identity package and complete hardware
repository together. Do not publish the original unsealed kernel package over
this repository. Sign the final pkg repositories with the release signing key
and configure `5BSD-hardware` with that URL and signature verification on
installed systems. The installer defaults to a retained offline repository,
which supports later fwget use but does not receive new releases automatically.
Use a boot environment for upgrades. Existing systems with upstream module
packages need a reviewed replacement transaction; the new installer does not
force-remove conflicting installed packages.

Validation:

```sh
python3 release/tests/hardware_packages_test.py
make -C usr.sbin/bsdinstall/tests obj all
# Run firmware_fetch_test with kyua from the resulting object directory.
```

The tests use real pkg archives and an isolated package database to exercise
matching and mismatched kernels, dependency closure, firmware classification,
media staging and coordinated updates. Installer tests cover PCI graphics plus
USB Wi-Fi selection, offline persistence, rejected mismatches and missing
dependencies, and catalogue retry with revalidation. Device initialization still
requires boot tests on the supported hardware before publishing a release.

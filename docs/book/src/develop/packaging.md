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

This is a rule, not a convenience. `docs/capability-container-model.md`
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
`5BSD-runtime` with the rest of the core system; BSDAudit, BSDAuth,
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

There is no remote base repository; `usr.sbin/pkg/5BSD.conf.in` ships the
`5BSD-base` entry disabled with a comment saying so. The loop from
`docs/pkgbase-install.md` is:

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel packages \
    PKG_CMD=/usr/local/sbin/pkg-static
pkg repo /usr/obj/usr/src/repo/${ABI}/<version>
ln -snf <version> /usr/obj/usr/src/repo/${ABI}/latest
```

`buildkernel` is part of the same invocation because `create-world-packages`
reads the kernel stage's METALOG for module packaging; `PKG_CMD` names the
static pkg because the dynamic ports pkg can predate the freshly built libc.
The repository is `${REPODIR}/${PKG_ABI}/${PKG_VERSION}`, with `REPODIR`
defaulting to `${OBJROOT}repo`. The ABI stays `FreeBSD:16:amd64`: uname's
type is `FreeBSD` for ports compatibility while `BRAND` is `5BSD`.

On the consuming machine, `docs/pkg/5BSD.conf.sample` becomes
`/usr/local/etc/pkg/repos/5BSD.conf`, disabling the template entry and
pointing at the tree:

```
5BSD-base: { enabled: no }

5BSD: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: yes,
  priority: 100
}
```

and `FreeBSD-base` is disabled in `FreeBSD.conf` so a `pkg upgrade` can
never replace 5BSD packages with upstream ones. Then, under a boot
environment:

```sh
bectl create pre-upgrade
pkg update -f -r 5BSD
pkg upgrade -r 5BSD
reboot
```

A first migration from FreeBSD pkgbase is
`pkg install -r 5BSD 5BSD-set-base 5BSD-kernel-generic` after
`pkg delete -fa`; rollback is `bectl activate` of the saved environment.
Third-party software keeps coming from the FreeBSD ports repositories
(`pkg upgrade -r FreeBSD-ports`). For a single bundle, `pkg install -r 5BSD 5BSD-<name>`
is the whole deployment: the watch does the rest.

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

# Pkgbase Packaging

5BSD distributes its base system as pkgbase packages named `5BSD-*`
(FreeBSD upstream uses `FreeBSD-*`). Every base component — libraries,
daemons, the kernel, tests, debug symbols — is a package, so upgrades,
partial installs, and rollbacks all go through `pkg(8)` and boot
environments.

## How components are tagged into packages

Source Makefiles tag their installed files with `PACKAGE=<name>`; the
package build collects everything carrying that tag. Package metadata
lives in two places:

- `packages/<name>/Makefile` — the package definition: `WORLDPACKAGE`,
  `PKG_SETS` (e.g. `optional`), `SUBPACKAGES` (commonly `dbg man`, giving
  separate debug-symbol and manual-page packages), dependencies via
  `PKG_DEPS.<name>`, and licenses.
- `release/packages/ucl/<name>-all.ucl` — the human-facing comment and
  description.

Example, `packages/hwtlm/Makefile`:

```makefile
WORLDPACKAGE=	hwtlm
PKG_SETS=	optional
SUBPACKAGES=	dbg man
PKG_LICENSES=	BSD2CLAUSE
UCLSRC=		${SRCTOP}/release/packages/ucl/hwtlm-all.ucl

.include <bsd.pkg.mk>
```

The master list is `packages/Makefile`; build-option-conditional packages
are added there (e.g. `SUBDIR.${MK_DTRACE}+= bsdinstruments ctf dtrace
dwatch`). Packages install in sets: `5BSD-set-base`, `5BSD-set-kernels`,
`5BSD-set-tests`, with `-dbg` variants carrying debug files and kernel
symbols.

Notable 5BSD packages:

- **bhyve** (`packages/bhyve/Makefile`): the hypervisor. The plan of
  record is to rename the VMM to WASPNest, so `usr.sbin/bhyve/Makefile`
  installs a transitional symlink `${BINDIR}/waspnest -> bhyve` and a
  `waspnest.8` man link inside the bhyve package; tooling can already
  reference the new name. `packages/waspnest-tests` is the sole owner of the
  WASPNest VMM, AF_VSOCK, VirtIO, live-guest, checkpoint, and nested-VM test
  payloads; its `-dbg` subpackage carries their symbols.
- **tzfs-flavors** (`PACKAGE=tzfs-flavors` in
  `usr.sbin/tzfs-flavors/Makefile`): the TrustedZFS
  OS-image flavor catalog, deliberately decoupled from the `tzfsd`
  storage broker. It ships `flavors.ucl` as a drop-in for
  `/etc/capability/tzfsd.d/` declaring linux (Rocky) and freebsd flavors,
  plus `tzfs-flavor-linux.sh` and `tzfs-flavor-freebsd.sh` producers and a
  `tzfs-flavors(7)` manual page. It can be installed, versioned, or
  removed independently of the broker.
- **Observability tools**: `bsdinstruments`, `hwtlm`, and `bsdtrace` are
  individually packaged (see the ObservableBSD chapter); commit
  `bb9f5be0208` wired them into release package builds.

## Building the repository

Build world and kernel, then the packages, in one pass:

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel KERNCONF=VBSD \
    packages PKG_CMD=/usr/local/sbin/pkg-static
```

The result is a signed repository under
`/usr/obj/usr/src/repo/${ABI}/<version>` with the `latest` symlink
updated to it; `${ABI}` is e.g. `FreeBSD:16:amd64`.

### Always package with `pkg-static`

`PKG_CMD=/usr/local/sbin/pkg-static` is not optional here, and it matters
because of a version-skew trap:

- The `packages` target invokes `pkg` to create the individual packages
  and to sign the repository catalog. The default is the **dynamic**
  `pkg(8)` bootstrapped from the ports repo, which tracks the **newest**
  FreeBSD `__FreeBSD_version` (e.g. `1600020`).
- The 5BSD source tree may sit a step behind that (e.g. `1600018`,
  `sys/sys/param.h`). When upstream bumps a libc symbol to a newer version
  node that the tree has not yet adopted — the concrete case is `fts_open`,
  `fts_read`, `fts_close`, `fts_set` moving to `FBSD_1.9` — the dynamic pkg
  is linked against `fts_open@FBSD_1.9` while the tree's libc still exports
  those symbols only at `FBSD_1.5`. Packaging then dies with:

  ```
  ld-elf.so.1: pkg: Undefined symbol "fts_open@FBSD_1.9"
  *** [real-sign-packages] Error code 1
  ```

  (Working around it by forcing the dynamic pkg onto a mismatched libc
  produces a `Bus error` instead — a second dead end.)
- `pkg-static` is **statically linked**: it carries its own `fts`/libc and
  has no dynamic dependency on base libc, so it is immune to this skew and
  produces the repository cleanly regardless of the tree-vs-pkg ABI gap.

> **Do not** patch base `libc` (e.g. re-versioning `fts_*` at `FBSD_1.9`)
> to satisfy the dynamic pkg. Nothing the OS itself builds needs those
> `FBSD_1.9` symbols — every base binary uses `fts_*@FBSD_1.5`, and the
> tree is internally consistent. The mismatch is a property of the foreign
> pkg tool, not of libc; `pkg-static` is the correct fix. If you instead
> intend to move the whole tree to the newer ABI, bump `__FreeBSD_version`
> — that is a deliberate ABI decision, not a packaging workaround.

## Installing and migrating

Full instructions are in `/usr/src/docs/pkgbase-install.md`. Fresh
installs should use the USB installer, which carries an offline `5BSD-*`
pkgbase repo. Migrating a FreeBSD 16-CURRENT pkgbase system is a one-time
operation because the package names differ:

```sh
bectl create pre-5bsd-migration
pkg update
pkg delete -fa
pkg install -r 5BSD-base 5BSD-set-base 5BSD-kernel-vbsd
reboot
```

Roll back with `bectl activate pre-5bsd-migration` if anything goes wrong.

## Repository configuration

Base updates must come from a local 5BSD repo so `pkg upgrade` never
replaces 5BSD packages with upstream FreeBSD ones. Sample configurations
ship in the tree:

`docs/pkg/5BSD.conf.sample` → `/usr/local/etc/pkg/repos/5BSD.conf`:

```
5BSD: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: yes,
  priority: 100
}
```

`docs/pkg/FreeBSD.conf.sample` → `/usr/local/etc/pkg/repos/FreeBSD.conf`:

```
FreeBSD-base: { enabled: no }
```

Priority 100 prefers local packages over any remote FreeBSD-base repo;
the FreeBSD-ports repos remain enabled for third-party software.

## Upgrading 5BSD to 5BSD

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel packages \
    PKG_CMD=/usr/local/sbin/pkg-static      # see "Building the repository"
# packages already builds+signs the repo and updates latest; the two lines
# below are only needed to (re)sign a hand-assembled repo directory:
#   pkg-static repo /usr/obj/<srcdir>/repo/${ABI}/<new-version>
#   ln -snf <new-version> /usr/obj/<srcdir>/repo/${ABI}/latest
bectl create pre-upgrade
pkg update -f
pkg upgrade
reboot
```

Verify after reboot: `uname -i` shows `VBSD`, and
`pkg query '%n' | head` shows `5BSD-*` names.

## Status

The `waspnest` binary name is transitional — the rename of the hypervisor
from bhyve to WASPNest is planned but not complete; today `waspnest` is a
symlink shipped in the bhyve package.

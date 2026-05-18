# Installing 5BSD

5BSD is installed over a stock FreeBSD 16-CURRENT system using
pkgbase.  You build packages from the 5BSD source tree and use
`pkg upgrade` to replace the upstream base system.  ZFS boot
environments provide rollback.

The process works because FreeBSD's base system is split into
hundreds of individual packages (kernel, runtime, utilities, libs,
etc.) via pkgbase.  5BSD builds the same packages from its own
source tree -- same package names, same structure, but with the
5BSD kernel, cap_rt modules, MACF hooks, and modified headers
compiled in.  When pkg sees your locally-built packages, it treats
them as upgrades to the upstream ones and swaps them in place.

## 1. Start with FreeBSD 16-CURRENT

Install FreeBSD 16-CURRENT with ZFS root (the default installer
layout) and pkgbase enabled.

This gives you a working system with the base system managed as
packages.  5BSD replaces these packages with its own builds.

## 2. Configure pkg repos

FreeBSD's pkgbase repo (`FreeBSD-base`) provides stock kernel and
world packages.  If left enabled, `pkg upgrade` will pull upstream
packages and overwrite 5BSD's kernel and modified binaries.  This
is how we lost the 5BSD kernel in the first place.

Disable it and point pkg at your local build output instead.
Do this **before** running any pkg commands:

```sh
mkdir -p /usr/local/etc/pkg/repos

cat > /usr/local/etc/pkg/repos/FreeBSD.conf <<'EOF'
FreeBSD-base: { enabled: no }
EOF

cat > /usr/local/etc/pkg/repos/5BSD.conf <<'EOF'
5BSD: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: yes,
  priority: 100
}
EOF
```

Adjust the URL to match where your source tree lives.  For a tree
at `/home/user/5BSD`, use `file:///usr/obj/home/user/5BSD/repo/${ABI}/latest`.

FreeBSD-ports and FreeBSD-ports-kmods remain enabled -- those are
third-party packages (Firefox, vim, etc.) that don't conflict with
5BSD.

## 3. Build and package

FreeBSD's build system compiles everything from source and then
packages the result into `.pkg` files organized in a local repo.
The process has three phases: build, stage, package.

```sh
cd /path/to/5BSD

# Build world (userspace) and kernel from the 5BSD source tree.
# This compiles everything including the modified headers
# (DTYPE_CAP_RT, Capsicum rights) and the 5BSD kernel config.
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD

# Stage the build output into a layout that mirrors an installed
# system, then create .pkg files from that layout.
make stage-packages KERNCONF=5BSD
make create-packages KERNCONF=5BSD
```

World and kernel must be staged in the same make invocation so they
get the same version timestamp.  Running them as separate commands
gives each a different timestamp, which causes version mismatches
during `pkg upgrade`.

`create-packages` builds world and kernel packages into a single
version directory, generates the pkg repo catalog, and creates the
`latest` symlink that the repo URL points to.

**Known issue:** `create-packages` also tries to build source
packages at the end.  If `stage-packages-source` was not run, it
will fail with a `sourcestage/src.plist: No such file` error.
The world and kernel packages are already written at that point.
Finish the repo manually:

```sh
# Find the version directory that was just created
ls /usr/obj/<srcdir>/repo/${ABI}/

# Generate the catalog and symlink
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest
```

After this, your local repo at `/usr/obj/.../repo/${ABI}/latest/`
contains ~500 packages that match the upstream names but carry
your 5BSD code.

## 4. Install

Before changing the running system, create a ZFS boot environment.
This is a snapshot of the root filesystem -- if the upgrade breaks
anything, you can boot back into it from the loader menu.

```sh
# Snapshot the current system
bectl create pre-5bsd-install

# Refresh the package catalog so pkg sees your local repo
pkg update

# The upstream kernel is a different package name
# (FreeBSD-kernel-generic) than the 5BSD kernel
# (FreeBSD-kernel-5bsd), so you need to remove one and
# install the other.  World packages share the same names
# and are handled by pkg upgrade.
pkg delete FreeBSD-kernel-generic FreeBSD-kernel-generic-dbg
pkg install FreeBSD-kernel-5bsd

# Upgrade all world packages to the 5BSD-built versions.
# Since FreeBSD-base is disabled, everything comes from
# your local repo.
pkg upgrade

reboot
```

After reboot, verify:

```sh
uname -i              # VBSD
kldstat | grep cap_rt # modules loaded via loader.conf
```

Cap_rt modules load automatically because `stand/defaults/loader.conf`
in the 5BSD source tree includes `cap_rt_load="YES"` entries.  This
file is installed as part of the world packages.

## 5. Upgrading

After pulling changes or making modifications, rebuild, repackage,
and upgrade.  Always create a boot environment first.

```sh
cd /path/to/5BSD

# Rebuild
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD

# Repackage
make stage-packages KERNCONF=5BSD
make create-packages KERNCONF=5BSD

# If create-packages fails on source packages, finish manually:
# pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
# ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest

# Snapshot and upgrade
bectl create pre-upgrade-$(date +%Y%m%d)
pkg update
pkg upgrade
reboot
```

If the upgrade breaks, select the previous boot environment from
the loader menu or run `bectl activate <name>` and reboot.

Clean up old boot environments with `bectl destroy <name>`.
They are cheap (ZFS clones) but accumulate over time.

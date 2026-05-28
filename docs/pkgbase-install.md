# Installing 5BSD With Pkgbase

Use this path when upgrading an existing FreeBSD 16-CURRENT pkgbase
system to locally built 5BSD packages. For fresh installs, prefer the
USB installer described in `building-5bsd.md`.

## Repository Policy

Base system updates must come from a local 5BSD repo so `pkg upgrade`
never replaces 5BSD packages with upstream FreeBSD ones.  Third-party
packages continue to come from the normal FreeBSD ports repos.

Two things are required:

1. **Disable upstream FreeBSD-base** so it cannot override local packages.
2. **Add a local 5BSD repo** pointing at the build output, with a high
   priority so it wins over any remote source.

Sample config files are provided in `docs/pkg/`:

```sh
mkdir -p /usr/local/etc/pkg/repos
cp docs/pkg/FreeBSD.conf.sample /usr/local/etc/pkg/repos/FreeBSD.conf
cp docs/pkg/5BSD.conf.sample    /usr/local/etc/pkg/repos/5BSD.conf
```

Edit `/usr/local/etc/pkg/repos/5BSD.conf` and set the `url` to match
your source tree.  The path must point at the repo directory created by
`make create-packages`.  For example, if your source is in
`/home/user/5BSD`:

```
url: "file:///usr/obj/home/user/5BSD/repo/${ABI}/latest"
```

Verify both repos are visible and that `FreeBSD-base` is disabled:

```sh
pkg -vv | sed -n '/Repositories:/,$p'
```

## Build Packages

```sh
cd /path/to/5BSD
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) stage-packages KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) create-packages KERNCONF=5BSD
```

After `create-packages` finishes, build the repo catalog and update
the `latest` symlink.  Find the newest snapshot directory under the
repo output:

```sh
ls /usr/obj/<srcdir>/repo/${ABI}/
```

Then generate the catalog and point `latest` at it:

```sh
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest
```

For example, with source in `/usr/src`:

```sh
pkg repo /usr/obj/usr/src/repo/FreeBSD:16:aarch64/16.snap20260528233101
ln -snf 16.snap20260528233101 /usr/obj/usr/src/repo/FreeBSD:16:aarch64/latest
```

## Install Or Upgrade

Create a boot environment before changing the base system:

```sh
bectl create pre-5bsd-install
pkg update
pkg delete FreeBSD-kernel-generic FreeBSD-kernel-generic-dbg
pkg install FreeBSD-kernel-5bsd
pkg upgrade
reboot
```

Install third-party packages normally:

```sh
pkg install vim tmux git
```

After reboot:

```sh
uname -i
kldstat | grep cap_rt
```

For later updates, rebuild packages, regenerate the catalog, create a
new boot environment, then upgrade:

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) stage-packages KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) create-packages KERNCONF=5BSD
pkg repo /usr/obj/usr/src/repo/FreeBSD:16:aarch64/<new-version>
ln -snf <new-version> /usr/obj/usr/src/repo/FreeBSD:16:aarch64/latest
bectl create pre-upgrade
pkg update -f
pkg upgrade
reboot
```

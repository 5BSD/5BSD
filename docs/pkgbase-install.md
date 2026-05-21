# Installing 5BSD With Pkgbase

Use this path when upgrading an existing FreeBSD 16-CURRENT pkgbase
system to locally built 5BSD packages. For fresh installs, prefer the
USB installer described in `building-5bsd.md`.

## Repository Policy

Base system updates must come from a 5BSD repo. Leave normal FreeBSD
third-party package repos enabled, but disable upstream `FreeBSD-base`
so `pkg upgrade` cannot replace the 5BSD kernel or world.

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

Adjust the repo URL for your source tree. For
`/home/user/5BSD`, use:

```sh
file:///usr/obj/home/user/5BSD/repo/${ABI}/latest
```

Verify:

```sh
pkg -vv | sed -n '/Repositories:/,$p'
```

## Build Packages

```sh
cd /path/to/5BSD
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD
make stage-packages KERNCONF=5BSD
make create-packages KERNCONF=5BSD
```

If `create-packages` fails after world/kernel packages are written
because source packages were not staged, finish the repo manually:

```sh
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest
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

For later updates, rebuild packages, create a new boot environment,
then run `pkg update && pkg upgrade`.

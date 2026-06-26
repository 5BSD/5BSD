# Installing 5BSD With Pkgbase

## Fresh Install

For fresh installs, prefer the USB installer described in
`building-5bsd.md`.  The installer ships an offline pkgbase repo
with `5BSD-*` packages and handles everything.

## Migrating From FreeBSD Pkgbase

If you are running a FreeBSD 16-CURRENT pkgbase system and want to
switch to 5BSD packages, this is a one-time migration.  The package
names change from `FreeBSD-*` to `5BSD-*`, so `pkg upgrade` alone
cannot do it — pkg sees them as different packages.

### 1. Build 5BSD packages

```sh
cd /path/to/5BSD
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel
make -j$(sysctl -n hw.ncpu) packages
```

Build the repo catalog:

```sh
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest
```

### 2. Set up the local 5BSD repo

```sh
mkdir -p /usr/local/etc/pkg/repos
```

Disable the upstream FreeBSD-base repo:

```sh
cat > /usr/local/etc/pkg/repos/FreeBSD.conf <<'EOF'
FreeBSD-base: { enabled: no }
EOF
```

Add the local 5BSD repo:

```sh
cat > /usr/local/etc/pkg/repos/5BSD.conf <<'EOF'
5BSD-base: {
  url: "file:///usr/obj/<srcdir>/repo/${ABI}/latest",
  enabled: yes
}
EOF
```

Edit the `url` to match your build output path.

### 3. Create a boot environment and migrate

```sh
bectl create pre-5bsd-migration
pkg update
```

Remove the old FreeBSD base packages and install 5BSD replacements.
This replaces the entire base system in one operation:

```sh
pkg delete -fa
pkg install -r 5BSD-base 5BSD-set-base 5BSD-kernel-vbsd
reboot
```

After reboot, verify:

```sh
uname -i          # should show VBSD
kldstat | grep mac_capability
pkg query '%n' | head
```

If anything goes wrong, roll back:

```sh
bectl activate pre-5bsd-migration
reboot
```

## Upgrading 5BSD to 5BSD

Once you are on 5BSD packages, subsequent upgrades are straightforward:

```sh
cd /path/to/5BSD
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel
make -j$(sysctl -n hw.ncpu) packages
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<new-version>
ln -snf <new-version> /usr/obj/<srcdir>/repo/${ABI}/latest
bectl create pre-upgrade
pkg update -f
pkg upgrade
reboot
```

## Repository Policy

Base system updates must come from a local 5BSD repo so `pkg upgrade`
never replaces 5BSD packages with upstream FreeBSD ones.  Third-party
packages continue to come from the normal FreeBSD ports repos.

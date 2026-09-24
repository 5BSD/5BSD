# Installing and Updating 5BSD With Pkgbase

5BSD currently has no public package service or separate ports collection.
Base system updates come from locally built 5BSD pkgbase packages on disk.
Applications such as Codex and ripgrep come from the FreeBSD ports package
repositories. Building the base system does not require building those
applications.

The shipped `5BSD-base` repository template is disabled by default. Enable
a local repository only after its package files and catalogue exist. The
installer uses its own offline repository on the installation media.

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
5BSD-base: { enabled: no }

5BSD: {
  url: "file:///usr/obj/<srcdir>/repo/${ABI}/latest",
  enabled: yes,
  priority: 100
}
EOF
```

Edit the `url` to match your build output path. The same configuration is
available in `docs/pkg/5BSD.conf.sample`. The repository name `5BSD` is used
for local upgrades below; `5BSD-base` is disabled to override the remote
entry shipped by older installations.

### 3. Create a boot environment and migrate

```sh
bectl create pre-5bsd-migration
pkg update
```

Remove the old FreeBSD base packages and install 5BSD replacements.
This replaces the entire base system in one operation:

```sh
pkg delete -fa
pkg install -r 5BSD 5BSD-set-base 5BSD-kernel-vbsd
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

Once you are on 5BSD packages, configure the local `5BSD` repository as
shown above, then build and upgrade from disk:

```sh
cd /path/to/5BSD
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel
make -j$(sysctl -n hw.ncpu) packages
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<new-version>
ln -snf <new-version> /usr/obj/<srcdir>/repo/${ABI}/latest
bectl create pre-upgrade
pkg update -f -r 5BSD
pkg upgrade -r 5BSD
reboot
```

The local repository may also be copied to a persistent directory on the
target machine. Set its `file://` URL to that directory, preserving the
catalogue and the package paths it references. Keep the repository on disk
and regenerate its catalogue whenever you publish new packages.

Upgrade applications independently with:

```sh
pkg upgrade -r FreeBSD-ports
# Or just one application and its dependencies:
pkg upgrade -r FreeBSD-ports codex
```

## Existing Installations With a Remote Base Entry

Older installations may try to reach `pkg.5bsd.org` during `pkg update` or
`pkg upgrade`, producing DNS errors even when application upgrades succeed.
If your local repository is already named `5BSD`, add this override:

```sh
mkdir -p /usr/local/etc/pkg/repos
cat > /usr/local/etc/pkg/repos/5BSD-base-disabled.conf <<'EOF'
5BSD-base: { enabled: no }
EOF
```

If your local repository is named `5BSD-base`, instead keep that local
entry enabled and ensure its URL is `file://` with the correct directory;
use `-r 5BSD-base` for base updates. Do not disable your working local
repository. `pkg -vv` shows the effective repository configuration.

A source-tree change does not update an existing machine's configuration
until installed and merged; apply the override there to stop the remote
lookups now.

## Repository Policy

Base system updates must come from a local 5BSD repo so `pkg upgrade`
never replaces 5BSD packages with upstream FreeBSD ones.  Third-party
packages continue to come from the normal FreeBSD ports repos.

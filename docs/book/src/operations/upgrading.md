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
`FreeBSD-ports` and `FreeBSD-ports-kmods` stay enabled.

## Repository configuration

`/etc/pkg/5BSD.conf` (from `usr.sbin/pkg/5BSD.conf.in`) ships with the base
entry disabled:

```
5BSD-base: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: no
}
```

Leave it alone. Configuration goes in `/usr/local/etc/pkg/repos/`, and the
tree ships both files you need as `docs/pkg/5BSD.conf.sample` and
`docs/pkg/FreeBSD.conf.sample`:

```sh
mkdir -p /usr/local/etc/pkg/repos
cat > /usr/local/etc/pkg/repos/FreeBSD.conf <<'EOF'
FreeBSD-base: { enabled: no }
EOF
cat > /usr/local/etc/pkg/repos/5BSD.conf <<'EOF'
5BSD-base: { enabled: no }

5BSD: {
  url: "file:///usr/obj/usr/src/repo/${ABI}/latest",
  enabled: yes,
  priority: 100
}
EOF
```

Adjust the `url` to your object tree (`${ABI}` expands to
`FreeBSD:16:amd64`). The `5BSD-base: { enabled: no }` line overrides the
remote entry that some older installations carried and stops the DNS lookups
for `pkg.5bsd.org` they produced. `priority: 100` makes the local packages
win any tie. `pkg -vv` prints the effective repository set; confirm that
`5BSD` is enabled, `5BSD-base` and `FreeBSD-base` are not, and the ports
repositories are.

If the build host and the target are different machines, copy the whole
`repo/${ABI}/<version>` directory (catalogue files and the package files
they reference, paths preserved) somewhere persistent on the target and
point the `url` there. Regenerate the catalogue with `pkg repo <dir>` after
every publish.

## The 5BSD-to-5BSD loop

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel
make packages PKG_CMD=/usr/local/sbin/pkg-static
```

`make packages` writes `repo/${ABI}/<version>/` and moves the `latest`
symlink; if you hand-built with `create-packages` instead, run `pkg repo` on
the directory and move the symlink yourself. Then, on the target:

```sh
bectl create pre-upgrade
pkg update -f -r 5BSD
pkg upgrade -r 5BSD
reboot
```

A `bectl` checkpoint costs nothing on ZFS and is the rollback path: the
whole base generation, `/Capabilities/System` bundles included, lives in
the boot environment, and `/Capabilities/Run` is tmpfs so no stale launch
state crosses the reboot. `/usr/local`, `/home` and `/var` are separate
datasets and are not rolled back.

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
pkg query '%n' | grep -vc '^5BSD-'   # 0 base packages from anywhere else
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
one boot environment. Build the repository and configure the repositories as
above (the `FreeBSD.conf` override is essential here), then:

```sh
bectl create pre-5bsd-migration
pkg update
pkg delete -fa
pkg install -r 5BSD 5BSD-set-base 5BSD-kernel-generic
reboot
```

`pkg delete -fa` removes every package, ports included, so expect to
reinstall third-party software afterwards from `FreeBSD-ports`. The `runtime`
package's scripts create the `capability` user and group (uid and gid 976)
in your existing `master.passwd` during the install, regenerate `pwd.db`,
and refuse to complete if the name does not resolve. `/Capabilities` is
created by the mtree in the same package, but nothing adds the
`/Capabilities/Run` tmpfs line to an existing fstab, nor writes
`/Capabilities/Config/principal-policy.ucl` or the `pool =` line in
`/Capabilities/Config/bsdfilesystem.ucl`; do those three by hand before the
reboot, following [Installing](installing.md). The old `init_path` in
`/boot/loader.conf`, if you had set one, must go: the new default starts
`/sbin/capsule` first.

After the reboot, `uname -i` shows `GENERIC`, `ps -p 1 -o comm=` shows
`capsule`, and `pkg query '%n' | head` shows `5BSD-*` names. The plane is
compiled in, so there is no `mac_capability.ko` to look for in `kldstat`;
`kldstat -m mac_capability` still reports it because static modules register
too. Roll back with `bectl activate pre-5bsd-migration && reboot`.

## Older installations with a remote base entry

Installations made before the local-repository template may carry an
enabled `5BSD-base` entry with a remote URL and fail `pkg update` with DNS
errors even when ports upgrades succeed. If your local repository is named
`5BSD`, add the override:

```sh
cat > /usr/local/etc/pkg/repos/5BSD-base-disabled.conf <<'EOF'
5BSD-base: { enabled: no }
EOF
```

If your local repository is itself named `5BSD-base`, keep that entry
enabled with its `file://` URL and use `-r 5BSD-base` in the commands
above instead of `-r 5BSD`. Do not disable the entry that works. Editing the
source tree changes nothing on an installed machine until the `pkg` package
is upgraded and its configuration merged; apply the override directly.

## Checklist

| Step | Command | Why |
|---|---|---|
| Build kernel and world together | `make buildworld buildkernel` | Modules are packaged from the kernel tree; a world-only build ships stale modules |
| Package with the static pkg | `make packages PKG_CMD=/usr/local/sbin/pkg-static` | The dynamic ports pkg can fail on libc symbol versions |
| Confirm repository set | `pkg -vv` | `5BSD` enabled, `5BSD-base` and `FreeBSD-base` disabled |
| Checkpoint | `bectl create pre-upgrade` | Rollback for the whole base generation |
| Upgrade base only from 5BSD | `pkg update -f -r 5BSD; pkg upgrade -r 5BSD` | Never from a FreeBSD repository |
| Reboot at once | `reboot` | Kernel, capsule and switchboard binaries are only replaced at boot |
| Verify | `uname -i`, `ps -p 1 -o comm=`, `switchboardctl services` | GENERIC, capsule, all expected units |

## What does not upgrade this way

Ports and kernel modules from `FreeBSD-ports-kmods` follow FreeBSD's rules
and their own ABI. The `5BSD-*-tests` packages and `5BSD-set-tests` upgrade
with the base but are not installed by default. A custom `KERNCONF` produces
a `5BSD-kernel-<name>` package that `pkg install` accepts; keep
`5BSD-kernel-generic` installed alongside it as the recovery kernel. Finally,
there is no signing of the local repository unless you set
`PKG_REPO_SIGNING_KEY` at build time, so the trust in this loop is the trust
you place in the disk the repository sits on.

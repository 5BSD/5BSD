#!/bin/sh
# Install a published pkgbase generation into an unprivileged NO_ROOT tree with
# a METALOG (INSTALL_AS_USER + METALOG, as release/tools/vmimage.subr does).
# Adapted from hostfix-work/vm/pkgroot.sh. Runs as an ordinary user.
# usage: pkgroot.sh REPO_DIR DESTDIR [packages...]
set -eu
repo=$1 dest=$2; shift 2
pkgs=${*:-5BSD-set-base 5BSD-set-kernels 5BSD-pkg-bootstrap}
case "$dest" in /usr/obj/*) ;; *) echo "pkgroot: DESTDIR must be under /usr/obj" >&2; exit 2 ;; esac
[ -f "$repo/meta.conf" ] || { echo "pkgroot: $repo is not a pkg repository" >&2; exit 2; }
rm -rf "$dest" "$dest.repos" "$dest.cache"; mkdir -p "$dest" "$dest.repos"
cat > "$dest.repos/base.conf" <<EOC
5BSD-base: { url: "file://$repo", signature_type: "none", enabled: yes }
EOC
cd "$dest"
osv=$(sysctl -n kern.osreldate 2>/dev/null || echo 1600027)
P="pkg --rootdir $dest --repo-conf-dir $dest.repos -o ASSUME_ALWAYS_YES=yes
  -o IGNORE_OSVERSION=yes -o ABI=FreeBSD:16:amd64 -o OSVERSION=$osv -o INSTALL_AS_USER=yes
  -o SYSLOG=no -o METALOG=METALOG -o PKG_DBDIR=$dest/var/db/pkg -o PKG_CACHEDIR=$dest.cache"
$P update
$P install -U -r 5BSD-base $pkgs
echo "./var/db/pkg/local.sqlite type=file uname=root gname=wheel mode=0644" >> METALOG
# Record the generation this root was built from.
$P query -g '%v' '5BSD-kernel-*' | head -1 > "$dest.generation"
sha256 -q "$dest/boot/kernel/kernel" > "$dest.kernel.sha256"
echo "root $dest generation $(cat "$dest.generation")"

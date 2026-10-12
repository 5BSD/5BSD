#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Build a disposable 5BSD DUT disk image (UFS, GPT) for the OpenBSD-regress
# topology from an already completed buildworld/buildkernel, without root:
# installworld/installkernel/distribution use -DNO_ROOT and the METALOG.
#
# usage: image-5bsd.sh SRCTOP MAKEOBJDIRPREFIX OUTDIR PKGDIR [KERNCONF]
#   PKGDIR holds FreeBSD:16:amd64 packages fetched (and catalogue-verified)
#   by pkg(8): perl5, p5-Socket6, p5-Net-Flow, oksh, python312, py312-scapy
#   and their dependencies.  They are test tools only.
set -eu
[ $# -ge 4 ] || { echo "usage: $0 SRCTOP OBJPREFIX OUTDIR PKGDIR [KERNCONF]" >&2; exit 64; }
src=$1 objp=$2 out=$3 pkgdir=$4 kernconf=${5:-GENERIC}
here=$(cd "$(dirname "$0")" && pwd)
case $out in /usr/obj/5BSD-pf-parity/*) ;; *) echo "OUTDIR must be below /usr/obj/5BSD-pf-parity" >&2; exit 64;; esac
[ ! -e "$out/root" ] || { echo "$out/root exists; use a new OUTDIR" >&2; exit 73; }
mkdir -p "$out/root"
R=$out/root
export MAKEOBJDIRPREFIX=$objp
make -C "$src" -j"${JOBS:-8}" -DNO_ROOT -DDB_FROM_SRC DESTDIR="$R" \
    installworld distribution > "$out/install.log" 2>&1
make -C "$src" -DNO_ROOT -DDB_FROM_SRC DESTDIR="$R" KERNCONF="$kernconf" \
    installkernel >> "$out/install.log" 2>&1

meta=$R/METALOG
add()   # path type mode [extra]
{
	echo "./$1 type=$2 uname=root gname=wheel mode=$3${4:+ $4}" >> "$meta"
}
put()   # path mode  (content from stdin)
{
	mkdir -p "$R/$(dirname "$1")"
	rm -f "$R/$1"
	cat > "$R/$1"
	grep -q "^\./$1 " "$meta" || add "$1" file "$2"
}

# Test tools from packages: extract payload only (no scripts are run).
for p in "$pkgdir"/*.pkg; do
	tar -xf "$p" -C "$R" --exclude '+*'
done
awk '{print $1}' "$meta" | sed 's|^\./||' | sort -u > "$out/metalog.paths"
( cd "$R" && find usr/local | sort ) | comm -13 "$out/metalog.paths" - |
while read -r f; do
	if [ -L "$R/$f" ]; then
		add "$f" link 0755 "link=$(readlink "$R/$f")"
	elif [ -d "$R/$f" ]; then
		add "$f" dir 0755
	else
		add "$f" file "$(stat -f %Lp "$R/$f")"
	fi
done
ln -sf python3.12 "$R/usr/local/bin/python3"; add usr/local/bin/python3 link 0755 link=python3.12
ln -sf /usr/local/bin/oksh "$R/bin/ksh"; add bin/ksh link 0755 link=/usr/local/bin/oksh

put etc/fstab 0644 <<'EOF'
/dev/ufs/root	/	ufs	rw	1	1
tmpfs		/tmp	tmpfs	rw,mode=1777	0	0
EOF
put boot/loader.conf 0644 <<'EOF'
console="comconsole"
autoboot_delay="1"
beastie_disable="YES"
# The capability plane denies late kldload; preload PF modules at boot.
pf_load="YES"
EOF
put etc/rc.conf 0644 <<'EOF'
hostname="pf-dut-5bsd"
ifconfig_vtnet0="DHCP"
sshd_enable="YES"
sendmail_enable="NONE"
dumpdev="NO"
inetd_enable="NO"
ldconfig_paths="/usr/lib/compat /usr/local/lib /usr/local/lib/perl5/5.42/mach/CORE"
EOF
sed -i '' 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/; s/^#*UseDNS.*/UseDNS no/' \
    "$R/etc/ssh/sshd_config"
mkdir -p "$R/root/.ssh"
add root/.ssh dir 0700
cp /usr/obj/5BSD-pf-parity/keys/id_ed25519.pub "$R/root/.ssh/authorized_keys"
add root/.ssh/authorized_keys file 0600
put root/pf-parity-disposable 0644 < /dev/null
# OpenBSD regress Makefiles include <bsd.regress.mk>; provide it (plumbing).
mkdir -p "$R/usr/local/share/pf-parity/mk"
add usr/local/share/pf-parity dir 0755
add usr/local/share/pf-parity/mk dir 0755
sed -f "$src/tests/sys/netpfil/pf/openbsd/bsd.regress.mk.sed" "$src/contrib/openbsd-pf/share/mk/bsd.regress.mk" | put usr/local/share/pf-parity/mk/bsd.regress.mk 0644

( cd "$R" && makefs -t ffs -B little -s 16g -o version=2,label=root,softupdates=1 \
    -D "$out/root.ufs" METALOG ) > "$out/makefs.log" 2>&1
mkimg -s gpt -f raw -b "$R/boot/pmbr" -p freebsd-boot:="$R/boot/gptboot" \
    -p freebsd-ufs:="$out/root.ufs" -o "$out/disk.img"
rm -f "$out/root.ufs"
sha256 -q "$out/disk.img" > "$out/disk.img.sha256"
echo "$out/disk.img"

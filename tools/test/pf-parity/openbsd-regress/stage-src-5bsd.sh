#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Stage the imported OpenBSD tree on a disposable 5BSD DUT in the upstream
# layout the regress Makefiles expect (/usr/src/regress, /usr/src/sbin/pfctl,
# /usr/src/sys/net, ...), plus the pfctl userland compatibility header and
# the 5BSD "jail" option glue that pf-changerule links with (regress.py
# passes them as CFLAGS/LDADD).  Plumbing only.
#
# usage: stage-src-5bsd.sh SRCTOP [SSH_HOST]
set -eu
[ $# -ge 1 ] || { echo "usage: $0 SRCTOP [dut|dut2]" >&2; exit 64; }
src=$1 host=${2:-dut}
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config $host"
C=/usr/local/share/pf-parity/pfctl-compat

$S '[ -f /root/pf-parity-disposable ]' || { echo "not a disposable guest" >&2; exit 1; }
tar -C "$src/contrib/openbsd-pf" -cf - regress sbin sys share usr.sbin etc |
    $S 'mkdir -p /usr/src && tar -C /usr/src -xf -'
tar -C "$src/sys/netpfil/openbsd-pf/user" -cf - openbsd_compat.h util.h sys pfctl_jail.c |
    $S "rm -rf $C && mkdir -p $C && tar -C $C -xf - &&
	cc -c -O2 -o $C/pfctl_jail.o $C/pfctl_jail.c && echo STAGED"

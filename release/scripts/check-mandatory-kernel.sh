#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Refuse a kernel that lacks an option 5BSD requires: every option of the
# mandatory-option ledger, sys/conf/mandatory-options (AUDIT,
# CAPABILITY_MODE, CAPABILITIES, RACCT, RCTL).  Such a kernel does not
# build from this tree (sys/kern/kern_mandatory.c); this catches one built
# elsewhere or before, wherever it is about to be booted or published.
#
# usage: check-mandatory-kernel.sh [-l ledger] -k kernel | -o kernel-objdir |
#	    -d root | -i root | -a archive | -r repository
#        check-mandatory-kernel.sh [-l ledger] -L
#
#   -l  The ledger to read (default: sys/conf/mandatory-options in the
#       source tree this script belongs to).  A ledger that is missing,
#       unreadable, malformed, empty or a symbolic link is a refusal.
#   -L  Print the ledger's options, one per line, and check nothing.
#   -k  One kernel file.
#   -o  A kernel build directory (${OBJTOP}/sys/${KERNCONF}): its kernel.
#   -d  A staged or installed tree: every <root>/boot/*/kernel.  At least
#       one must exist.
#   -i  An image root, which may carry no kernel: every <root>/boot/*/kernel
#       there is.
#   -a  One archive (a kernel package): every member boot/*/kernel.  At
#       least one must exist.
#   -r  A repository directory: every member boot/*/kernel of every *.pkg
#       below it.  At least one kernel must exist.
#
# The modes may be repeated and combined; every argument is checked.  A
# kernel passes when its symbol table holds, for every ledger row, the
# kern.features sysctl the option registers (sysctl___kern_features_<name>):
# the evidence that the option's code is compiled in, however the kernel
# was configured.  It fails closed: a kernel without a symbol table, or
# anything that cannot be read, listed or extracted, is a refusal, and
# there is no override.

set -eu
LC_ALL=C
export LC_ALL

usage()
{
	echo "usage: ${0##*/} [-l ledger] -k kernel | -o kernel-objdir |" \
	    "-d root | -i root | -a archive | -r repository" >&2
	echo "       ${0##*/} [-l ledger] -L" >&2
	exit 2
}

refuse()
{
	cat >&2 <<EOM
ERROR: $*
Every 5BSD kernel must be built with the options of
sys/conf/mandatory-options (AUDIT, CAPABILITY_MODE, CAPABILITIES, RACCT,
RCTL).  They are in sys/<arch>/conf/DEFAULTS; do not remove them with
nooptions.  There is no override.
EOM
	exit 1
}

work=
cleanup()
{
	if [ -n "${work}" ] && [ -d "${work}" ]; then
		chmod -R u+rwx "${work}" 2>/dev/null || true
		rm -rf "${work}"
	fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# load_ledger file: the rows "option header feature" into ${work}/rows.
load_ledger()
{
	[ ! -L "$1" ] ||
	    refuse "the mandatory-option ledger is a symbolic link: $1"
	[ -f "$1" ] && [ -r "$1" ] ||
	    refuse "the mandatory-option ledger cannot be read: $1"
	awk '
	    function bad(why) {
		printf "line %d: %s\n", NR, why > "/dev/stderr"; failed = 1
	    }
	    /^#/ || /^[ \t]*$/ { next }
	    {
		if (NF != 3) { bad("expected 3 fields"); next }
		if ($1 !~ /^[A-Z][A-Z0-9_]*$/) bad("bad option name")
		if ($1 in seen) bad("duplicate option " $1)
		seen[$1] = 1
		if ($2 !~ /^opt_[a-z0-9_]+\.h$/) bad("bad header")
		if ($3 !~ /^[a-z][a-z0-9_]*$/) bad("bad feature")
		print $1, $2, $3
		n++
	    }
	    END {
		if (n == 0) { printf "no rows\n" > "/dev/stderr"; failed = 1 }
		exit failed
	    }' "$1" > "${work}/rows" 2> "${work}/ledger.err" ||
	    refuse "the mandatory-option ledger $1 is malformed:" \
	    "$(head -n 1 "${work}/ledger.err")"
}

# check_kernel file description
check_kernel()
{
	[ -f "$1" ] || refuse "$2 is not a file"
	syms=${work}/symbols
	readelf -sW "$1" > "${syms}" 2> "${work}/readelf.err" ||
	    refuse "$2 cannot be read: $(head -n 1 "${work}/readelf.err")"
	grep -q 'sysctl___kern_features_' "${syms}" ||
	    refuse "$2 has no symbol table to check"
	missing=
	while read -r option header feature; do
		awk -v s="sysctl___kern_features_${feature}" \
		    '$8 == s { found = 1 } END { exit !found }' "${syms}" ||
		    missing="${missing} ${option}"
	done < "${work}/rows"
	[ -z "${missing}" ] ||
	    refuse "$2 was built without options${missing}"
	kernels=$((kernels + 1))
}

check_objdir()
{
	[ -d "$1" ] || refuse "kernel build directory does not exist: $1"
	check_kernel "$1/kernel" "kernel build directory $1"
}

# check_root root required|optional
check_root()
{
	if [ "$2" = optional ]; then
		[ -d "$1" ] || refuse "image root does not exist: $1"
		[ -d "$1/boot" ] || return 0
	fi
	[ -d "$1/boot" ] || refuse "tree has no boot directory: $1"
	found=0
	for k in "$1"/boot/*/kernel; do
		[ -e "${k}" ] || continue
		check_kernel "${k}" "${k}"
		found=$((found + 1))
	done
	[ "${found}" -gt 0 ] || [ "$2" = optional ] ||
	    refuse "no kernel under $1/boot"
}

# check_archive archive: every boot/*/kernel member.
check_archive()
{
	[ -f "$1" ] || refuse "archive does not exist: $1"
	tar -tf "$1" > "${work}/names" 2> "${work}/tar.err" ||
	    refuse "cannot list $1: $(head -n 1 "${work}/tar.err")"
	grep -E '^(\./|/)?boot/[^/]+/kernel$' "${work}/names" \
	    > "${work}/selected" || return 1
	out=${work}/members
	rm -rf "${out}"
	mkdir "${out}"
	tar -xf "$1" -C "${out}" -T "${work}/selected" \
	    2> "${work}/tar.err" ||
	    refuse "cannot extract from $1: $(head -n 1 "${work}/tar.err")"
	while IFS= read -r member; do
		path=${member#/}
		path=${path#./}
		check_kernel "${out}/${path}" "$1: ${path}"
	done < "${work}/selected"
	return 0
}

check_repository()
{
	[ -d "$1" ] || refuse "repository does not exist: $1"
	find "$1" -type f -name '*.pkg' -print > "${work}/packages" ||
	    refuse "cannot list repository $1"
	before=${kernels}
	while IFS= read -r package; do
		check_archive "${package}" || true
	done < "${work}/packages"
	[ "${kernels}" -gt "${before}" ] ||
	    refuse "no kernel in any package of repository $1"
}

[ $# -gt 0 ] || usage
case "$0" in
*/*)	ledger=${0%/*}/../../sys/conf/mandatory-options ;;
*)	ledger=../../sys/conf/mandatory-options ;;
esac
list=no
modes=0
while getopts "a:d:i:k:l:Lo:r:" opt; do
	case "${opt}" in
	l)	ledger=${OPTARG} ;;
	L)	list=yes ;;
	[adikor]) modes=$((modes + 1)) ;;
	*)	usage ;;
	esac
done
[ "${OPTIND}" -gt $# ] || usage
if [ "${list}" = yes ]; then
	[ "${modes}" -eq 0 ] || usage
elif [ "${modes}" -eq 0 ]; then
	usage
fi
OPTIND=1
work=$(mktemp -d "${TMPDIR:-/tmp}/check-mandatory-kernel.XXXXXXXX")
load_ledger "${ledger}"
if [ "${list}" = yes ]; then
	awk '{ print $1 }' "${work}/rows"
	exit 0
fi
kernels=0
while getopts "a:d:i:k:l:Lo:r:" opt; do
	case "${opt}" in
	l|L)	continue ;;
	a)	check_archive "${OPTARG}" ||
		    refuse "no boot/*/kernel member in archive ${OPTARG}" ;;
	d)	check_root "${OPTARG%/}" required ;;
	i)	check_root "${OPTARG%/}" optional ;;
	k)	check_kernel "${OPTARG}" "kernel ${OPTARG}" ;;
	o)	check_objdir "${OPTARG%/}" ;;
	r)	check_repository "${OPTARG%/}" ;;
	*)	usage ;;
	esac
done
echo "check-mandatory-kernel: ${kernels} kernel(s) carry" \
    "$(awk '{ printf "%s%s", sep, $1; sep = " " }' "${work}/rows")"

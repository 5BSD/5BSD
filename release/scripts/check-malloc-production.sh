#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Refuse to publish a world whose libc was built with -CURRENT's debug
# malloc(3).  5BSD release and package builds use production jemalloc
# (WITH_MALLOC_PRODUCTION); development builds keep the debug default.
#
# usage: check-malloc-production.sh [-a] -o libc-objdir
#        check-malloc-production.sh [-a] -r base-repository [-p pkg-prefix]
#
#   -o  Check a libc object directory: the malloc-production.stamp marker
#       written by lib/libc/stdlib/malloc/jemalloc/Makefile.inc must be
#       present, and libc.so.7 must not contain jemalloc debug code.
#   -r  Check the libc.so.7 inside <pkg-prefix>-clibs in a base repository.
#   -a  Allow a debug-malloc world (ALLOW_DEBUG_MALLOC=yes): warn only.

set -eu

# Only built when config_debug is true; production builds compile the
# assertion out entirely.
DEBUG_SIGNATURE='<jemalloc>: %s:%d: Failed assertion'
MARKER=malloc-production.stamp

allow=no
objdir=
repo=
prefix=5BSD

usage()
{
	echo "usage: ${0##*/} [-a] -o libc-objdir | -r base-repository [-p pkg-prefix]" >&2
	exit 2
}

while getopts "ao:p:r:" opt; do
	case "${opt}" in
	a) allow=yes ;;
	o) objdir=${OPTARG} ;;
	p) prefix=${OPTARG} ;;
	r) repo=${OPTARG} ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage
if [ -n "${objdir}" ] && [ -n "${repo}" ] || [ -z "${objdir}${repo}" ]; then
	usage
fi

fail()
{
	if [ "${allow}" = yes ]; then
		echo "WARNING: $*" >&2
		echo "WARNING: ALLOW_DEBUG_MALLOC=yes: continuing with debug malloc(3);" \
		    "do not use this output as a release or update publication." >&2
		exit 0
	fi
	cat >&2 <<EOF
ERROR: $*
5BSD release and package publication requires production malloc(3).
Rebuild world with:

    make -j\$(sysctl -n hw.ncpu) buildworld WITH_MALLOC_PRODUCTION=yes

(or set WITH_MALLOC_PRODUCTION=yes in src.conf(5)), then package again.
For a test publication only, set ALLOW_DEBUG_MALLOC=yes.
EOF
	exit 1
}

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

# check_libc file description
check_libc()
{
	if [ ! -s "$1" ]; then
		die "$2: libc.so.7 not found"
	fi
	if grep -a -q -F -e "${DEBUG_SIGNATURE}" "$1"; then
		fail "$2: libc.so.7 contains debug malloc(3) (built without WITH_MALLOC_PRODUCTION)"
	fi
}

if [ -n "${objdir}" ]; then
	if [ ! -f "${objdir}/libc.so.7" ]; then
		die "${objdir}: no libc.so.7; build world first"
	fi
	if [ ! -f "${objdir}/${MARKER}" ]; then
		fail "${objdir}: world was built without WITH_MALLOC_PRODUCTION (no ${MARKER})"
	fi
	check_libc "${objdir}/libc.so.7" "${objdir}"
	echo "==> ${objdir}: libc built with production malloc(3)"
	exit 0
fi

[ -d "${repo}" ] || die "${repo}: no such base repository"
pkgs=$(find "${repo}/" -maxdepth 1 -name "${prefix}-clibs-[0-9]*.pkg")
case "${pkgs}" in
"")
	die "${repo}: no ${prefix}-clibs package found" ;;
*"
"*)
	die "${repo}: more than one ${prefix}-clibs package found" ;;
esac
tmp=$(mktemp -t check-malloc-production)
trap 'rm -f "${tmp}"' EXIT
tar -xOf "${pkgs}" /lib/libc.so.7 > "${tmp}" 2>/dev/null ||
    tar -xOf "${pkgs}" lib/libc.so.7 > "${tmp}" 2>/dev/null || :
check_libc "${tmp}" "${pkgs}"
echo "==> ${pkgs##*/}: libc built with production malloc(3)"

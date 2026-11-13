#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Refuse to publish a kernel or kernel module built with the dq(4) test
# option (options DQ_TEST_OPEN, sys/dev/dq/dq_testopen.c).  A kernel with
# the option is for the test suite only: with the loader setting it opens
# the supervisor queue to test access.
#
# usage: check-kernel-no-dq-test.sh -r repository | -a archive |
#	    -o kernel-objdir | -d root | -i root
#
#   -r  Every archive below a repository directory (*.pkg, *.txz, *.tzst,
#       *.tbz, *.tgz, *.tar), whatever package it claims to be: each
#       member under boot/, and each member anywhere named kernel,
#       kernel.*, *.ko or *.ko.*.
#   -a  One archive, whatever its name (a boot archive, a single package):
#       the same members as -r.  It need not carry a kernel.
#   -o  A kernel build directory (${OBJTOP}/sys/${KERNCONF}): the kernel and
#       every module built there.
#   -d  A staged or installed tree: every regular file under <root>/boot.
#   -i  An image root, which may legitimately carry no kernel: every regular
#       file under <root>/boot if that exists, and every file anywhere in
#       the root named kernel, kernel.*, *.ko or *.ko.*.
#
# The modes may be repeated and combined; every argument is checked.  The
# check looks at the binaries themselves, for either of two signatures, so
# it does not depend on how they were configured or named.  It fails
# closed: anything it cannot read, list or extract is a refusal, a tree or
# repository with no kernel in it is a refusal (except with -a and -i),
# and there is no override.
#
# This catches an accident.  It does not stop someone who removes both
# signatures on purpose, and it says nothing about the boot chain of an
# installed system.

set -eu

# Both are defined in sys/dev/dq/dq_testopen.c; keep the three in step.
MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOLS='dq_testopen_'

usage()
{
	echo "usage: ${0##*/} -r repository | -a archive | -o kernel-objdir |" \
	    "-d root | -i root" >&2
	exit 2
}

refuse()
{
	cat >&2 <<EOM
ERROR: $*
A kernel or module built with options DQ_TEST_OPEN (the dq(4) test
option, for example GENERIC-DQTEST) must not be published or placed on
release media, and nothing that cannot be checked for it is published.
Build the kernel from a configuration without the option.  There is no
override.
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

# is_kernel_name basename: a kernel or module by name.
is_kernel_name()
{
	case "$1" in
	kernel|kernel.*|*.ko|*.ko.*) return 0 ;;
	esac
	return 1
}

# A compressed kernel or module cannot be searched.
refuse_compressed()
{
	case "${1##*/}" in
	*.gz|*.xz|*.zst|*.bz2|*.lz4|*.Z|*.lzma)
		refuse "$2: compressed kernel or module cannot be checked: $1" ;;
	esac
}

# scan_file file description: grep status 0 refuses, 1 passes, anything
# else refuses.
scan_file()
{
	status=0
	grep -a -q -F -e "${MARKER}" -e "${SYMBOLS}" -- "$1" || status=$?
	case "${status}" in
	0)	refuse "$2 was built with the dq(4) test option" ;;
	1)	;;
	*)	refuse "$2 could not be read (grep status ${status})" ;;
	esac
	scanned=$((scanned + 1))
}

# scan_tree directory root description all|named|others
# Every regular file below a directory (all), only those with a kernel or
# module name (named), or only the rest (others).  Files are reported
# relative to root.  Adds to kernels the number of files named "kernel"
# that were checked.
scan_tree()
{
	list=${work}/tree.list
	find "$1" -type f -print > "${list}" ||
	    refuse "$3: cannot list $1"
	while IFS= read -r file; do
		base=${file##*/}
		if is_kernel_name "${base}"; then
			[ "$4" != others ] || continue
			refuse_compressed "${file#"$2"/}" "$3"
		elif [ "$4" = named ]; then
			continue
		fi
		scan_file "${file}" "$3: ${file#"$2"/}"
		if [ "${base}" = kernel ]; then
			kernels=$((kernels + 1))
		fi
	done < "${list}"
}

check_objdir()
{
	[ -d "$1" ] || refuse "kernel build directory does not exist: $1"
	kernels=0
	scan_tree "$1" "$1" "kernel build directory $1" named
	[ "${kernels}" -gt 0 ] ||
	    refuse "no kernel in the kernel build directory $1"
}

check_root()
{
	[ -d "$1/boot" ] || refuse "staged tree has no boot directory: $1"
	kernels=0
	scan_tree "$1/boot" "$1" "staged tree $1" all
	[ "${kernels}" -gt 0 ] ||
	    refuse "no kernel under $1/boot"
}

check_image_root()
{
	[ -d "$1" ] || refuse "image root does not exist: $1"
	kernels=0
	scan_tree "$1" "$1" "image root $1" named
	if [ -d "$1/boot" ]; then
		scan_tree "$1/boot" "$1" "image root $1" others
	fi
}

# check_package archive noun: select the members in scope, extract them
# once, then search the extracted files.
check_package()
{
	pkg=$1
	noun=$2
	names=${work}/names
	selected=${work}/selected
	out=${work}/members

	tar -tf "${pkg}" > "${names}" 2> "${work}/tar.err" ||
	    refuse "cannot list ${noun} ${pkg}: $(head -n 1 "${work}/tar.err")"
	: > "${selected}"
	while IFS= read -r member; do
		path=${member}
		while :; do
			case "${path}" in
			/*)	path=${path#/} ;;
			./*)	path=${path#./} ;;
			*)	break ;;
			esac
		done
		case "${path}" in
		*/)	continue ;;
		esac
		base=${path##*/}
		case "${path}" in
		boot/*)	;;
		*)	is_kernel_name "${base}" || continue ;;
		esac
		if is_kernel_name "${base}"; then
			refuse_compressed "${path}" "${noun} ${pkg}"
		fi
		printf '%s\n' "${member}" >> "${selected}"
	done < "${names}"
	[ -s "${selected}" ] || return 0

	chmod -R u+rwx "${out}" 2>/dev/null || true
	rm -rf "${out}"
	mkdir "${out}"
	tar -xf "${pkg}" -C "${out}" -T "${selected}" 2> "${work}/tar.err" ||
	    refuse "cannot extract from ${noun} ${pkg}:" \
	    "$(head -n 1 "${work}/tar.err")"
	chmod -R u+rwX "${out}" ||
	    refuse "cannot read members extracted from ${pkg}"
	# Every selected name must now be a file that was searched: a member
	# that extracted as nothing (a hard link to an unselected member, a
	# name tar altered) is a refusal, not a pass.
	while IFS= read -r member; do
		path=${member}
		while :; do
			case "${path}" in
			/*)	path=${path#/} ;;
			./*)	path=${path#./} ;;
			*)	break ;;
			esac
		done
		file=${out}/${path}
		if [ -L "${file}" ] || [ -d "${file}" ]; then
			continue
		fi
		[ -f "${file}" ] ||
		    refuse "${noun} ${pkg}: member ${member} did not extract"
		scan_file "${file}" "${noun} ${pkg}: ${path}"
		if [ "${path##*/}" = kernel ]; then
			kernels=$((kernels + 1))
		fi
	done < "${selected}"
}

check_repository()
{
	[ -d "$1" ] || refuse "repository does not exist: $1"
	packages=${work}/packages
	find "$1/" -type f \( -name '*.pkg' -o -name '*.txz' -o \
	    -name '*.tzst' -o -name '*.tbz' -o -name '*.tgz' -o \
	    -name '*.tar' \) -print > "${packages}" ||
	    refuse "cannot list repository $1"
	[ -s "${packages}" ] || refuse "no package in repository $1"
	kernels=0
	while IFS= read -r package; do
		check_package "${package}" package
	done < "${packages}"
	[ "${kernels}" -gt 0 ] ||
	    refuse "no kernel in any package of repository $1"
}

check_archive()
{
	[ -f "$1" ] || refuse "archive does not exist: $1"
	kernels=0
	check_package "$1" archive
}

[ $# -gt 0 ] || usage
work=$(mktemp -d "${TMPDIR:-/tmp}/check-kernel-no-dq-test.XXXXXXXX")
scanned=0
checked=0
while getopts "a:d:i:o:r:" opt; do
	case "${opt}" in
	a)	check_archive "${OPTARG}" ;;
	d)	check_root "${OPTARG%/}" ;;
	i)	check_image_root "${OPTARG%/}" ;;
	o)	check_objdir "${OPTARG%/}" ;;
	r)	check_repository "${OPTARG%/}" ;;
	*)	usage ;;
	esac
	checked=$((checked + 1))
done
shift $((OPTIND - 1))
[ $# -eq 0 ] && [ "${checked}" -gt 0 ] || usage
echo "check-kernel-no-dq-test: ${scanned} kernel and boot files checked," \
    "no dq(4) test option"

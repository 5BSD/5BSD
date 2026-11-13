#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Refuse to publish a kernel or kernel module built with the dq(4) test
# option (options DQ_TEST_OPEN, sys/dev/dq/dq_testopen.c).  A kernel with
# the option is for the test suite only: with the loader setting it opens
# the supervisor queue to test access.
#
# usage: check-kernel-no-dq-test.sh -r repository | -p package-directory |
#	    -a archive | -o kernel-objdir | -d root | -i root
#
#   -r  Every archive below a repository directory (*.pkg, *.txz, *.tzst,
#       *.tbz, *.tgz, *.tar), whatever package it claims to be: each
#       member under boot/, and each member anywhere named kernel,
#       kernel.*, *.ko or *.ko.*.  At least one archive must carry a
#       kernel.
#   -p  Every archive below a directory, as -r, but the directory need not
#       hold a kernel or any archive (the package store of release media).
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
# repository with no kernel in it is a refusal (except with -a, -i and
# -p), and there is no override.
#
# Symbolic links.  A directory argument is resolved once and may itself be
# a link.  A link to an archive in a repository is read through.  A link
# with a kernel or module name is read through when it leads to a file: in
# a staged tree, an image root or an archive an absolute target is taken
# inside that root, and a target outside it, or none, is a refusal; in a
# kernel build directory it is taken as the host resolves it.  A link to
# a directory is never followed, because its contents are read where
# they are: such a link with a kernel or module name, or any such link
# under a boot directory, is a refusal when it leads outside the
# directory being read.  Other links are not followed.
#
# Limits.  A file that is not under boot/ and has no kernel or module name
# is not read.  A file under boot/ is searched as bytes: a signature
# inside compressed or otherwise encoded content there is not seen (a
# compressed file with a kernel or module name is refused instead).  A
# member name that tar(1) reads as a pattern, or one holding a newline,
# does not extract under its own name and is refused.
#
# This catches an accident.  It does not stop someone who removes both
# signatures on purpose, and it says nothing about the boot chain of an
# installed system.

set -eu
# File names and kernel contents are bytes.
LC_ALL=C
export LC_ALL

# Both are defined in sys/dev/dq/dq_testopen.c; keep the three in step.
MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOLS='dq_testopen_'

usage()
{
	echo "usage: ${0##*/} -r repository | -p package-directory |" \
	    "-a archive | -o kernel-objdir | -d root | -i root" >&2
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

# resolve_directory path description: the directory itself, links
# resolved, in resolved.
resolve_directory()
{
	[ -d "$1" ] || refuse "$2 does not exist: $1"
	resolved=$(realpath "$1" 2>/dev/null) && [ -d "${resolved}" ] ||
	    refuse "$2 cannot be resolved: $1"
}

# link_target link root: where a symbolic link leads, one step, in target.
# An absolute target is taken inside root when root is not empty.
link_target()
{
	target=$(readlink "$1") && [ -n "${target}" ] ||
	    refuse "cannot read the symbolic link $1"
	case "${target}" in
	/*)	target=$2${target} ;;
	*)	target=${1%/*}/${target} ;;
	esac
}

# scan_tree directory root description all|named|others host|rooted
# Every file below a directory (all), only those with a kernel or module
# name (named), or only the rest (others).  The directory and root are
# resolved paths; files are reported relative to root.  Symbolic links
# are handled as the header says: rooted takes absolute targets inside
# root and refuses a target outside it.  Adds to kernels the number of
# files named "kernel" that were checked.
scan_tree()
{
	list=${work}/tree.list
	find "$1" \( -type f -o -type l \) -print > "${list}" ||
	    refuse "$3: cannot list $1"
	while IFS= read -r file; do
		base=${file##*/}
		name=${file#"$2"/}
		if is_kernel_name "${base}"; then
			[ "$4" != others ] || continue
			refuse_compressed "${name}" "$3"
			named=yes
		elif [ "$4" = named ]; then
			continue
		else
			named=no
		fi
		if [ -L "${file}" ]; then
			if [ "$5" = rooted ]; then
				link_target "${file}" "$2"
			else
				target=${file}
			fi
			real=$(realpath "${target}" 2>/dev/null) || real=
			if [ -n "${real}" ] && [ -d "${real}" ]; then
				# Its contents are read where they are.
				case "${real}/" in
				"$1"/*)	continue ;;
				esac
				refuse "$3: ${name} is a link to a directory" \
				    "that is not read"
			elif [ -n "${real}" ] && [ -f "${real}" ]; then
				case "$5:${real}" in
				host:*|rooted:"$2"/*) ;;
				*)	[ "${named}" = no ] ||
					    refuse "$3: ${name} is a link" \
					    "that leaves the tree"
					continue ;;
				esac
				file=${real}
			else
				[ "${named}" = no ] ||
				    refuse "$3: ${name} is a link that does" \
				    "not lead to a file"
				continue
			fi
		fi
		scan_file "${file}" "$3: ${name}"
		if [ "${base}" = kernel ]; then
			kernels=$((kernels + 1))
		fi
	done < "${list}"
}

check_objdir()
{
	resolve_directory "$1" "kernel build directory"
	kernels=0
	scan_tree "${resolved}" "${resolved}" "kernel build directory $1" \
	    named host
	[ "${kernels}" -gt 0 ] ||
	    refuse "no kernel in the kernel build directory $1"
}

check_root()
{
	[ -d "$1/boot" ] || refuse "staged tree has no boot directory: $1"
	resolve_directory "$1" "staged tree"
	root=${resolved}
	resolve_directory "$1/boot" "boot directory"
	case "${resolved}" in
	"${root}"/*) ;;
	*)	refuse "staged tree $1: boot is a link that leaves the tree" ;;
	esac
	kernels=0
	scan_tree "${resolved}" "${root}" "staged tree $1" all rooted
	[ "${kernels}" -gt 0 ] ||
	    refuse "no kernel under $1/boot"
}

check_image_root()
{
	resolve_directory "$1" "image root"
	root=${resolved}
	kernels=0
	scan_tree "${root}" "${root}" "image root $1" named rooted
	if [ -d "${root}/boot" ]; then
		resolve_directory "${root}/boot" "boot directory"
		case "${resolved}" in
		"${root}"/*) ;;
		*)	refuse "image root $1: boot is a link that leaves" \
			    "the root" ;;
		esac
		scan_tree "${resolved}" "${root}" "image root $1" others rooted
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
	out=$(realpath "${out}")
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
		if [ -L "${file}" ]; then
			# A link with a kernel or module name must lead to a
			# member that was extracted, and so searched under
			# its own name; other links are not followed.
			is_kernel_name "${path##*/}" || continue
			link_target "${file}" "${out}"
			real=$(realpath "${target}" 2>/dev/null) || real=
			case "${real}" in
			"${out}"/*)	[ -f "${real}" ] && continue ;;
			esac
			refuse "${noun} ${pkg}: ${path} is a link to a member" \
			    "that is not checked"
		fi
		if [ -d "${file}" ]; then
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

# check_repository directory repository|store: a store may be empty and
# need not carry a kernel.
check_repository()
{
	resolve_directory "$1" "repository"
	packages=${work}/packages
	find "${resolved}" \( -type f -o -type l \) \( -name '*.pkg' -o \
	    -name '*.txz' -o -name '*.tzst' -o -name '*.tbz' -o \
	    -name '*.tgz' -o -name '*.tar' \) -print > "${packages}" ||
	    refuse "cannot list repository $1"
	[ "$2" = store ] || [ -s "${packages}" ] ||
	    refuse "no package in repository $1"
	kernels=0
	while IFS= read -r package; do
		[ -f "${package}" ] ||
		    refuse "repository $1: ${package} is a link that does" \
		    "not lead to an archive"
		check_package "${package}" package
	done < "${packages}"
	[ "$2" = store ] || [ "${kernels}" -gt 0 ] ||
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
while getopts "a:d:i:o:p:r:" opt; do
	case "${opt}" in
	a)	check_archive "${OPTARG}" ;;
	d)	check_root "${OPTARG%/}" ;;
	i)	check_image_root "${OPTARG%/}" ;;
	o)	check_objdir "${OPTARG%/}" ;;
	p)	check_repository "${OPTARG%/}" store ;;
	r)	check_repository "${OPTARG%/}" repository ;;
	*)	usage ;;
	esac
	checked=$((checked + 1))
done
shift $((OPTIND - 1))
[ $# -eq 0 ] && [ "${checked}" -gt 0 ] || usage
echo "check-kernel-no-dq-test: ${scanned} kernel and boot files checked," \
    "no dq(4) test option"

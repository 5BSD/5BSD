#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Shared by fwget and bsdinstall. Check the target kernel, not the host kernel.
set -eu
: ${FWGET_ROOT:=/}
: ${FWGET_REPOSITORY:=5BSD-hardware}
: ${FWGET_PKG:=pkg}
[ "$#" -gt 0 ] || exit 0

pkg_target()
{
	"${FWGET_PKG}" -c "${FWGET_ROOT}" "$@"
}

kernel="${FWGET_ROOT%/}/boot/kernel/kernel"
if [ ! -f "${kernel}" ]; then
	echo "Cannot identify target kernel: ${kernel}" >&2
	exit 1
fi
expected=$(sha256 -q "${kernel}")
selected=
for name in "$@"; do
	case "${name}" in
	''|*[!a-zA-Z0-9_+.-]*|-*)
		echo "Invalid hardware package: ${name}" >&2; exit 1 ;;
	esac
	selected="${selected} 5BSD-hw-${name}"
done

validate()
{
	pending=${selected}
	checked=
	while [ -n "${pending}" ]; do
		set -- ${pending}
		name=$1
		shift
		pending="$*"
		case " ${checked} " in *" ${name} "*) continue ;; esac
		case "${name}" in
		5BSD-hw-*|"5BSD-hardware-abi-${expected}") ;;
		*) echo "Unexpected hardware dependency: ${name}" >&2; return 1 ;;
		esac
		annotations=$(pkg_target rquery -U -r "${FWGET_REPOSITORY}" \
		    '%At=%Av' "${name}") || return 1
		actual=$(printf '%s\n' "${annotations}" | \
		    sed -n 's/^5BSD_kernel_sha256=//p')
		kind=$(printf '%s\n' "${annotations}" | \
		    sed -n 's/^5BSD_hardware_kind=//p')
		if [ "${kind}" != firmware ] && [ "${actual}" != "${expected}" ]; then
			echo "${name} is unavailable or does not match the target 5BSD kernel." >&2
			return 1
		fi
		deps=$(pkg_target rquery -U -r "${FWGET_REPOSITORY}" '%dn' "${name}") || return 1
		pending="${pending} ${deps}"
		# Strip whitespace so an empty dependency list terminates the loop.
		set -- ${pending}
		pending="$*"
		checked="${checked} ${name}"
	done
}

# A rotated catalogue gets one retry. Revalidate every dependency after each
# refresh, and freeze the catalogue during installation with -U.
for attempt in 1 2; do
	pkg_target update -fq -r "${FWGET_REPOSITORY}" >&2 || true
	if validate && pkg_target install -U -qy -r "${FWGET_REPOSITORY}" ${selected} >&2; then
		exit 0
	fi
done
echo "Unable to install matching 5BSD hardware packages: $*" >&2
exit 1

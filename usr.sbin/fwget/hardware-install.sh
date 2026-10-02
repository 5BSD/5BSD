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

# Use the same activation policy for an installed system and bsdinstall's
# rc.conf fragment. Do this only after the entire package transaction succeeds.
configure_boot()
{
	local name module fragment line
	fragment=${FWGET_RC_CONF:-${FWGET_ROOT%/}/etc/rc.conf.d/kld}
	if [ -d "${fragment}" ]; then
		fragment="${fragment}/5bsd-hardware"
	fi
	for name in "$@"; do
		case "${name}" in
		gpu-firmware-intel-*) module=i915kms ;;
		gpu-firmware-amd-*) module=amdgpu ;;
		gpu-firmware-radeon-*) module=radeonkms ;;
		*) continue ;;
		esac
		mkdir -p "${fragment%/*}" || return 1
		line='kld_list="${kld_list} '"${module}"'"'
		if [ ! -f "${fragment}" ] || ! grep -qFx "${line}" "${fragment}"; then
			printf '%s\n' "${line}" >>"${fragment}" || return 1
		fi
	done
}

# Never let the base pkg stub open a bootstrap prompt behind an installer
# dialog. bsdinstall supplies the release media's pkg-static when needed.
# -N also fails for a usable pkg with an empty database on live media.
# A version probe needs no database; closed stdin and an explicit no prevent
# the base stub from bootstrapping or prompting.
if ! ASSUME_ALWAYS_YES=no "${FWGET_PKG}" -v </dev/null >/dev/null 2>&1; then
	echo "Hardware installation requires pkg; set FWGET_PKG to the release pkg-static executable." >&2
	exit 1
fi

# A rotated catalogue gets one retry. Revalidate every dependency after each
# refresh, and freeze the catalogue during installation with -U.
for attempt in 1 2; do
	pkg_target update -fq -r "${FWGET_REPOSITORY}" >&2 || true
	if validate && pkg_target install -U -qy -r "${FWGET_REPOSITORY}" ${selected} >&2; then
		if ! configure_boot "$@"; then
			echo "Hardware packages installed, but saving GPU boot activation failed." >&2
			exit 1
		fi
		exit 0
	fi
done
echo "Unable to install matching 5BSD hardware packages from ${FWGET_REPOSITORY}: $*" >&2
echo "Use release media containing /usr/5bsd-packages/hardware, or configure a 5BSD hardware repository for this release. FreeBSD binary modules are not a fallback." >&2
exit 1

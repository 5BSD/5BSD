#!/usr/bin/env atf-sh

firmware_fetch()
{
	if [ -n "${FIRMWARE_FETCH:-}" ]; then
		printf '%s' "${FIRMWARE_FETCH}"
	else
		printf '%s' @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch
	fi
}

make_chroot_stub()
{
	mkdir -p bin root state
	cat >bin/chroot <<-'EOF'
	#!/bin/sh
	shift
	printf '%s\n' "$*" >>"${TEST_STATE}/calls"
	case "$*" in
	*"install -qy -r FreeBSD-ports-kmods retry-firmware"*)
		count_file="${TEST_STATE}/retry-count"
		count=0
		[ ! -f "${count_file}" ] || count=$(cat "${count_file}")
		count=$((count + 1))
		printf '%s\n' "${count}" >"${count_file}"
		[ "${count}" -gt 1 ] && exit 0 || exit 1
		;;
	*"install -qy -r FreeBSD-ports-kmods broken-firmware"*)
		exit 1
		;;
	esac
	exit 0
	EOF
	chmod 0755 bin/chroot
}

atf_test_case stale_catalog_is_refreshed_and_retried
stale_catalog_is_refreshed_and_retried_body()
{
	make_chroot_stub
	atf_check -s exit:0 -o empty -e empty env \
	    PATH="$(pwd)/bin:/bin:/usr/bin" \
	    TEST_STATE="$(pwd)/state" \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    /bin/sh "$(firmware_fetch)" retry-firmware
	atf_check -s exit:0 -o inline:'2\n' cat state/retry-count
	atf_check -s exit:0 -o inline:'2\n' grep -c \
	    '^pkg update -fq -r FreeBSD-ports-kmods$' state/calls
}

atf_test_case permanent_failure_is_reported
permanent_failure_is_reported_body()
{
	make_chroot_stub
	atf_check -s exit:1 -o inline:' broken-firmware\n' -e empty env \
	    PATH="$(pwd)/bin:/bin:/usr/bin" \
	    TEST_STATE="$(pwd)/state" \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    /bin/sh "$(firmware_fetch)" broken-firmware
	atf_check -s exit:0 -o inline:'2\n' grep -c \
	    '^pkg update -fq -r FreeBSD-ports-kmods$' state/calls
}

atf_init_test_cases()
{
	atf_add_test_case stale_catalog_is_refreshed_and_retried
	atf_add_test_case permanent_failure_is_reported
}

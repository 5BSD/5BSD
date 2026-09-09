#!/usr/bin/env atf-sh

config_script()
{
	if [ -n "${BSDINSTALL_CONFIG_SCRIPT:-}" ]; then
		printf '%s' "$BSDINSTALL_CONFIG_SCRIPT"
	else
		printf '%s' /usr/libexec/bsdinstall/config
	fi
}

atf_test_case installer_state_is_not_copied_to_etc
installer_state_is_not_copied_to_etc_body()
{
	mkdir -p root/etc root/boot root/var/log state boot-state bin
	: >root/etc/sysctl.conf
	printf '%s\n' 'hostname="fivebsd"' >state/rc.conf.hostname
	printf '%s\n' 'kern.randompid=1' >state/sysctl.conf.hardening
	printf '%s\n' alice >state/capability-policy.users
	printf '%s\n' operators >state/capability-policy.groups
	printf '%s\n' custompool >state/tzfsd.pool
	printf '%s\n' 'autoboot_delay="3"' >boot-state/loader.conf.install
	cat >bin/chroot <<-EOF
	#!/bin/sh
	exit 0
	EOF
	chmod 0755 bin/chroot

	atf_check -s exit:0 env \
	    PATH="$(pwd)/bin:/bin:/usr/bin" \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_TMPBOOT="$(pwd)/boot-state" \
	    /bin/sh "$(config_script)"

	atf_check -s exit:1 test -e root/etc/capability-policy.users
	atf_check -s exit:1 test -e root/etc/capability-policy.groups
	atf_check -s exit:1 test -e root/etc/tzfsd.pool
	atf_check -s exit:0 -o match:'hostname="fivebsd"' \
	    grep hostname root/etc/rc.conf
}

atf_init_test_cases()
{
	atf_add_test_case installer_state_is_not_copied_to_etc
}

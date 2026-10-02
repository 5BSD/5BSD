#!/usr/bin/env atf-sh

config_script()
{
	if [ -n "${BSDINSTALL_CONFIG_SCRIPT:-}" ]; then
		printf '%s' "$BSDINSTALL_CONFIG_SCRIPT"
	else
		printf '%s' @SRCTOP@/usr.sbin/bsdinstall/scripts/config
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
	printf '%s\n' custompool >state/bsdfilesystem.pool
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
	atf_check -s exit:1 test -e root/etc/bsdfilesystem.pool
	atf_check -s exit:0 -o match:'hostname="fivebsd"' \
	    grep hostname root/etc/rc.conf
}

atf_test_case configuration_copy_failure_is_reported
configuration_copy_failure_is_reported_body()
{
	mkdir -p root/etc root/boot state boot-state bin
	: >root/etc/sysctl.conf
	echo 'hostname="fivebsd"' >state/rc.conf.hostname
	echo 'kern.randompid=1' >state/sysctl.conf.hardening
	echo 'autoboot_delay="3"' >boot-state/loader.conf.install
	cat >bin/cp <<-'EOF'
	#!/bin/sh
	echo 'simulated configuration write failure' >&2
	exit 23
	EOF
	chmod +x bin/cp
	atf_check -s exit:1 -o empty -e match:'configuration write failure' env \
	    PATH="$(pwd)/bin:/bin:/usr/bin" \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_TMPBOOT="$(pwd)/boot-state" \
	    /bin/sh "$(config_script)"
}

atf_init_test_cases()
{
	atf_add_test_case configuration_copy_failure_is_reported
	atf_add_test_case installer_state_is_not_copied_to_etc
}

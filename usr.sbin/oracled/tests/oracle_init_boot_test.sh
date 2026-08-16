#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Verify the fresh-install loader handoff without altering the running boot
# environment.  The bsdinstall config step is intentionally exercised against
# a disposable target root.

oracle_init_path='init_path="/sbin/oracle-init:/sbin/init:/sbin/init.bak:/rescue/init"'
oracle_init_test_tmp=

atf_test_case bsdinstall_sets_oracle_init
bsdinstall_sets_oracle_init_head()
{
	atf_set "descr" "bsdinstall selects oracle-init when it is installed"
}
bsdinstall_sets_oracle_init_body()
{
	local src installer root tmp

	src="$(atf_get_srcdir)"
	installer="$src/bsdinstall-config.sh"
	[ -f "$installer" ] || atf_fail "bsdinstall config script not found"

	tmp="$(mktemp -d -t oracle-init-test)" || atf_fail "mktemp"
	oracle_init_test_tmp="$tmp"
	root="$tmp/root"
	mkdir -p "$root/etc" "$root/boot" "$root/sbin" "$tmp/etc" \
	    "$tmp/boot" || atf_fail "mkdir"
	install -m 555 /usr/bin/true "$root/sbin/oracle-init" || atf_fail "install init"
	install -m 644 /dev/null "$root/etc/sysctl.conf" || atf_fail "install sysctl"
	install -m 644 /dev/null "$tmp/etc/rc.conf.base" || atf_fail "install rc"
	install -m 644 /dev/null "$tmp/etc/sysctl.conf.base" || atf_fail "install temp sysctl"
	install -m 644 /dev/null "$tmp/boot/loader.conf.base" || atf_fail "install loader"

	atf_check -s exit:0 -e empty env BSDINSTALL_CHROOT="$root" \
	    BSDINSTALL_TMPETC="$tmp/etc" BSDINSTALL_TMPBOOT="$tmp/boot" \
	    sh "$installer"
	atf_check -s exit:0 -o match:"^${oracle_init_path}$" \
	    grep -Fx "$oracle_init_path" "$root/boot/loader.conf"
}
bsdinstall_sets_oracle_init_cleanup()
{
	if [ -n "$oracle_init_test_tmp" ]; then
		rm -rf "$oracle_init_test_tmp"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case bsdinstall_sets_oracle_init
}

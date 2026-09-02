#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Verify the fresh-install loader handoff without altering the running boot
# environment.  The bsdinstall config step is intentionally exercised against
# a disposable target root.

capsule_path='init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"'
capsule_test_tmp=

atf_test_case bsdinstall_sets_capsule
bsdinstall_sets_capsule_head()
{
	atf_set "descr" "bsdinstall selects capsule when it is installed"
}
bsdinstall_sets_capsule_body()
{
	local src installer root tmp

	src="$(atf_get_srcdir)"
	installer="$src/bsdinstall-config.sh"
	[ -f "$installer" ] || atf_fail "bsdinstall config script not found"

	tmp="$(mktemp -d -t capsule-test)" || atf_fail "mktemp"
	capsule_test_tmp="$tmp"
	root="$tmp/root"
	mkdir -p "$root/etc" "$root/boot" "$root/sbin" "$tmp/etc" \
	    "$tmp/boot" || atf_fail "mkdir"
	install -m 555 /usr/bin/true "$root/sbin/capsule" || atf_fail "install init"
	install -m 644 /dev/null "$root/etc/sysctl.conf" || atf_fail "install sysctl"
	install -m 644 /dev/null "$tmp/etc/rc.conf.base" || atf_fail "install rc"
	install -m 644 /dev/null "$tmp/etc/sysctl.conf.base" || atf_fail "install temp sysctl"
	install -m 644 /dev/null "$tmp/boot/loader.conf.base" || atf_fail "install loader"

	atf_check -s exit:0 -e empty env BSDINSTALL_CHROOT="$root" \
	    BSDINSTALL_TMPETC="$tmp/etc" BSDINSTALL_TMPBOOT="$tmp/boot" \
	    sh "$installer"
	atf_check -s exit:0 -o match:"^${capsule_path}$" \
	    grep -Fx "$capsule_path" "$root/boot/loader.conf"
}
bsdinstall_sets_capsule_cleanup()
{
	if [ -n "$capsule_test_tmp" ]; then
		rm -rf "$capsule_test_tmp"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case bsdinstall_sets_capsule
}

#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Verify the platform loader defaults without altering the running boot
# environment.  Installer and image builders intentionally rely on this single
# source of truth rather than appending per-image overrides.

capsule_path='init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"'
zfs_load='zfs_load="YES"'

atf_test_case platform_boot_defaults
platform_boot_defaults_head()
{
	atf_set "descr" "5BSD defaults to Capsule PID 1 and early ZFS loading"
}
platform_boot_defaults_body()
{
	local defaults src

	src="$(atf_get_srcdir)"
	defaults="$src/loader-defaults.conf"
	[ -f "$defaults" ] || atf_fail "loader defaults fixture not found"

	atf_check -s exit:0 -o match:"^${capsule_path}$" \
	    grep -Fx "$capsule_path" "$defaults"
	atf_check -s exit:0 -o match:"^${zfs_load}$" \
	    grep -Fx "$zfs_load" "$defaults"
}

atf_init_test_cases()
{
	atf_add_test_case platform_boot_defaults
}

#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Verify the platform loader defaults without altering the running boot
# environment.  Installer and image builders intentionally rely on this single
# source of truth rather than appending per-image overrides.

capsule_path='init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"'
required_block='###  5BSD always-present subsystems  ########################'

atf_test_case platform_boot_defaults
platform_boot_defaults_head()
{
	atf_set "descr" "5BSD defaults to Capsule PID 1 and leaves the base" \
	    "subsystems to the kernel and the loader's required modules"
}
platform_boot_defaults_body()
{
	local defaults src

	src="$(atf_get_srcdir)"
	defaults="$src/loader-defaults.conf"
	[ -f "$defaults" ] || atf_fail "loader defaults fixture not found"

	atf_check -s exit:0 -o match:"^${capsule_path}$" \
	    grep -Fx "$capsule_path" "$defaults"
	# ZFS and the other base subsystems are compiled in or loaded by the
	# loader's required set (stand/lua/config.lua); the defaults document
	# that and carry no *_load line that could turn one of them off.
	atf_check -s exit:0 -o ignore grep -Fx "$required_block" "$defaults"
	atf_check -s exit:0 -o match:'required_modules="NO"' \
	    sed -n "/^${required_block}\$/,/^\$/p" "$defaults"
	atf_check -s exit:1 -o empty grep -E \
	    '^(zfs|dtraceall|pf|vmm|linux64|linux_common|hypertrace)_load=' \
	    "$defaults"
}

atf_init_test_cases()
{
	atf_add_test_case platform_boot_defaults
}

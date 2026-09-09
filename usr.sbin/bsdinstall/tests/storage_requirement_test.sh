#!/usr/bin/env atf-sh

atf_test_case installer_states_zfs_requirement
installer_states_zfs_requirement_body()
{
	start="@SRCTOP@/usr.sbin/bsdinstall/startbsdinstall"
	auto="@SRCTOP@/usr.sbin/bsdinstall/scripts/auto"
	manual="@SRCTOP@/usr.sbin/bsdinstall/bsdinstall.8"

	atf_check -s exit:0 -o ignore grep \
	    "OpenZFS is .*required system filesystem" "$start"
	atf_check -s exit:0 -o ignore grep \
	    'Guided Root-on-ZFS (required)' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required system filesystem for a fully functional 5BSD' "$manual"
}

atf_init_test_cases()
{
	atf_add_test_case installer_states_zfs_requirement
}

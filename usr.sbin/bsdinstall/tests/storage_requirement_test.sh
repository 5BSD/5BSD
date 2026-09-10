#!/usr/bin/env atf-sh

atf_test_case installer_places_zfs_requirement_at_partitioning
installer_places_zfs_requirement_at_partitioning_body()
{
	start="@SRCTOP@/usr.sbin/bsdinstall/startbsdinstall"
	auto="@SRCTOP@/usr.sbin/bsdinstall/scripts/auto"
	manual="@SRCTOP@/usr.sbin/bsdinstall/bsdinstall.8"

	atf_check -s exit:1 -o empty -e empty grep \
	    -E 'OpenZFS|tzfsd' "$start"
	atf_check -s exit:0 -o ignore grep \
	    'Guided Root-on-ZFS (required)' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required 5BSD system filesystem; tzfsd' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required system filesystem for a fully functional 5BSD' "$manual"
}

atf_init_test_cases()
{
	atf_add_test_case installer_places_zfs_requirement_at_partitioning
}

#!/usr/bin/env atf-sh

# Source-only fixtures (the manual page source and the release tooling) are
# installed beneath srctree/ next to this program; the installer scripts are
# checked where bsdinstall installs them.
srctree()
{
	printf '%s' "$(atf_get_srcdir)/srctree"
}

atf_test_case installer_places_zfs_requirement_at_partitioning
installer_places_zfs_requirement_at_partitioning_body()
{
	start="/usr/libexec/bsdinstall/startbsdinstall"
	auto="/usr/libexec/bsdinstall/auto"
	manual="$(srctree)/usr.sbin/bsdinstall/bsdinstall.8"

	atf_check -s exit:1 -o empty -e empty grep \
	    -E 'OpenZFS|bsdfilesystem' "$start"
	atf_check -s exit:0 -o ignore grep \
	    'Guided Root-on-ZFS (required)' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required 5BSD system filesystem; bsdfilesystem' "$auto"
	atf_check -s exit:0 -o ignore grep \
	    'required system filesystem for a fully functional 5BSD' "$manual"
}

atf_test_case third_party_software_has_separate_dataset
third_party_software_has_separate_dataset_body()
{
	zfsboot="/usr/libexec/bsdinstall/zfsboot"
	manual="$(srctree)/usr.sbin/bsdinstall/bsdinstall.8"
	vmimage="$(srctree)/release/tools/vmimage.subr"

	atf_check -s exit:0 -o ignore grep -Eq \
	    '^[[:space:]]*/usr/local[[:space:]]+mountpoint=/usr/local$' \
	    "$zfsboot"
	atf_check -s exit:0 -o ignore grep -F \
	    'fs=zroot/usr/local\;mountpoint=/usr/local' "$vmimage"
	atf_check -s exit:0 -o ignore grep -F \
	    "Third-party and locally built software is outside the base generation" \
	    "$zfsboot"
	atf_check -s exit:0 -o ignore grep -Eq \
	    '^/usr/local[[:space:]]+mountpoint=/usr/local$' \
	    "$manual"
}


atf_test_case capability_runtime_is_ephemeral
capability_runtime_is_ephemeral_body()
{
	zfsboot="/usr/libexec/bsdinstall/zfsboot"

	atf_check -s exit:0 -o ignore grep -F \
	    'tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0' "$zfsboot"
}

atf_init_test_cases()
{
	atf_add_test_case installer_places_zfs_requirement_at_partitioning
	atf_add_test_case third_party_software_has_separate_dataset
	atf_add_test_case capability_runtime_is_ephemeral
}

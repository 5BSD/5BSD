#!/usr/bin/env atf-sh
require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/BSDNotify/capbundle/bsdnotify.ucl" ||
	    atf_skip "source tree (@SRCTOP@) required for this contract check"
}


manifest_inventory()
{
	find @SRCTOP@/usr.sbin -type f \
	    \( -path '*/capbundle/*.ucl' -o \
	    -path '*/bluetooth/BSDBluetooth/blued.ucl' \) \
	    ! -name Bundle.ucl |
	    sed 's,^@SRCTOP@/,,' |
	    sort
}

write_expected_inventory()
{
	cat >expected <<'EOF'
usr.sbin/BSDAudit/capbundle/bsdaudit.ucl
usr.sbin/BSDAuth/capbundle/authagentd.ucl
usr.sbin/bluetooth/BSDBluetooth/blued.ucl
usr.sbin/BSDNotify/capbundle/bsdnotify.ucl
usr.sbin/BSDCrypto/capbundle/crypto.ucl
usr.sbin/BSDDevice/capbundle/device.ucl
usr.sbin/BSDNetwork/capbundle/bsdnetwork.ucl
usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl
usr.sbin/BSDLog/capbundle/bsdlog.ucl
usr.sbin/BSDExtension/capbundle/bsdextension.ucl
usr.sbin/BSDTrace/capbundle/traced.ucl
usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl
usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl
usr.sbin/BSDVM/capbundle/waspnest.ucl
EOF
}

atf_test_case every_shipped_unit_is_explicit
every_shipped_unit_is_explicit_body()
{
	require_srctree
	write_expected_inventory
	manifest_inventory >actual
	atf_check -s exit:0 cmp expected actual

	while read -r manifest; do
		count=$(grep -Ec \
		    '^[[:space:]]*management = "(core|system|user)";' \
		    "@SRCTOP@/$manifest")
		if [ "$count" -ne 1 ]; then
			atf_fail "$manifest must declare exactly one management class"
		fi
	done <actual
}

atf_test_case trust_spine_is_core_and_shielded
trust_spine_is_core_and_shielded_body()
{
	require_srctree
	for manifest in \
	    usr.sbin/BSDAudit/capbundle/bsdaudit.ucl \
	    usr.sbin/BSDAuth/capbundle/authagentd.ucl \
	    usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl \
	    usr.sbin/BSDLog/capbundle/bsdlog.ucl \
	    usr.sbin/BSDExtension/capbundle/bsdextension.ucl \
	    usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl
	do
		path="@SRCTOP@/$manifest"
		atf_check -s exit:0 -o ignore grep -Fx \
		    'management = "core";' "$path"
		for flag in ptrace signal wait sigkill sigcont sched core ktrace; do
			atf_check -s exit:0 -o ignore grep -Fw "$flag" "$path"
		done
	done
}

atf_test_case non_tcb_units_are_system_managed
non_tcb_units_are_system_managed_body()
{
	require_srctree
	for manifest in \
	    usr.sbin/bluetooth/BSDBluetooth/blued.ucl \
	    usr.sbin/BSDNotify/capbundle/bsdnotify.ucl \
	    usr.sbin/BSDCrypto/capbundle/crypto.ucl \
	    usr.sbin/BSDDevice/capbundle/device.ucl \
	    usr.sbin/BSDNetwork/capbundle/bsdnetwork.ucl \
	    usr.sbin/BSDTrace/capbundle/traced.ucl \
	    usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl \
	    usr.sbin/BSDVM/capbundle/waspnest.ucl
	do
		atf_check -s exit:0 -o ignore grep -Fx \
		    'management = "system";' "@SRCTOP@/$manifest"
	done
}

atf_test_case live_core_change_reaches_management_gate
live_core_change_reaches_management_gate_body()
{
	require_srctree
	reload=@SRCTOP@/usr.sbin/switchboard/reload.c
	atf_check -s exit:0 -o ignore grep -F \
	    'A core image and its launch policy belong to the' "$reload"
	atf_check -s exit:0 -o ignore grep -F \
	    '"changed at runtime") != 0' "$reload"
}

atf_init_test_cases()
{
	atf_add_test_case every_shipped_unit_is_explicit
	atf_add_test_case trust_spine_is_core_and_shielded
	atf_add_test_case non_tcb_units_are_system_managed
	atf_add_test_case live_core_change_reaches_management_gate
}

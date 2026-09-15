#!/usr/bin/env atf-sh
require_srctree()
{
	test -r "@SRCTOP@/usr.sbin/bsdnotify/capbundle/bsdnotify.ucl" ||
	    atf_skip "source tree (@SRCTOP@) required for this contract check"
}


manifest_inventory()
{
	find @SRCTOP@/usr.sbin -type f \
	    \( -path '*/capbundle/*.ucl' -o \
	    -path '*/bluetooth/blued/blued.ucl' \) \
	    ! -name Bundle.ucl |
	    sed 's,^@SRCTOP@/,,' |
	    sort
}

write_expected_inventory()
{
	cat >expected <<'EOF'
usr.sbin/auditbrokerd/capbundle/auditbrokerd.ucl
usr.sbin/authagentd/capbundle/authagentd.ucl
usr.sbin/bluetooth/blued/blued.ucl
usr.sbin/bsdnotify/capbundle/bsdnotify.ucl
usr.sbin/localcrypto/capbundle/crypto.ucl
usr.sbin/localdevice/capbundle/device.ucl
usr.sbin/localnetwork/capbundle/localnetwork.ucl
usr.sbin/localsysctl/capbundle/localsysctl.ucl
usr.sbin/logd/capbundle/logd.ucl
usr.sbin/sysextd/capbundle/sysextd.ucl
usr.sbin/traced/capbundle/traced.ucl
usr.sbin/tzfsd/capbundle/tzfsd.ucl
usr.sbin/warden/capbundle/warden.ucl
usr.sbin/waspnest/capbundle/waspnest.ucl
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
	    usr.sbin/auditbrokerd/capbundle/auditbrokerd.ucl \
	    usr.sbin/authagentd/capbundle/authagentd.ucl \
	    usr.sbin/localsysctl/capbundle/localsysctl.ucl \
	    usr.sbin/logd/capbundle/logd.ucl \
	    usr.sbin/sysextd/capbundle/sysextd.ucl \
	    usr.sbin/tzfsd/capbundle/tzfsd.ucl
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
	    usr.sbin/bluetooth/blued/blued.ucl \
	    usr.sbin/bsdnotify/capbundle/bsdnotify.ucl \
	    usr.sbin/localcrypto/capbundle/crypto.ucl \
	    usr.sbin/localdevice/capbundle/device.ucl \
	    usr.sbin/localnetwork/capbundle/localnetwork.ucl \
	    usr.sbin/traced/capbundle/traced.ucl \
	    usr.sbin/warden/capbundle/warden.ucl \
	    usr.sbin/waspnest/capbundle/waspnest.ucl
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

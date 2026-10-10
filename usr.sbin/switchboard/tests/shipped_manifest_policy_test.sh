#!/usr/bin/env atf-sh

# The test package installs the shipped manifests (and reload.c) beneath
# srctree/, so the installed test needs no build machine source tree.
require_srctree()
{
	SRCTREE="$(atf_get_srcdir)/srctree"
	test -r "${SRCTREE}/usr.sbin/BSDNotify/capbundle/bsdnotify.ucl" ||
	    atf_skip "staged source files (${SRCTREE}) required for this contract check"
}


manifest_inventory()
{
	find "${SRCTREE}/usr.sbin" -type f \
	    \( -path '*/capbundle/*.ucl' -o \
	    -path '*/bluetooth/BSDBluetooth/blued.ucl' \) \
	    ! -name Bundle.ucl |
	    sed "s,^${SRCTREE}/,," |
	    LC_ALL=C sort
}

write_expected_inventory()
{
	cat >expected <<'EOF'
usr.sbin/BSDAudit/capbundle/bsdaudit.ucl
usr.sbin/BSDCrypto/capbundle/crypto.ucl
usr.sbin/BSDDevice/capbundle/device.ucl
usr.sbin/BSDExtension/capbundle/bsdextension.ucl
usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl
usr.sbin/BSDLog/capbundle/bsdlog.ucl
usr.sbin/BSDMemory/capbundle/Unit.ucl
usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl
usr.sbin/BSDNetwork/capbundle/bsdnetwork.ucl
usr.sbin/BSDNotify/capbundle/bsdnotify.ucl
usr.sbin/BSDPower/capbundle/BSDPower.ucl
usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl
usr.sbin/BSDTime/capbundle/BSDTime.ucl
usr.sbin/BSDTrace/capbundle/bsdtrace.ucl
usr.sbin/BSDVM/capbundle/bsdvm.ucl
usr.sbin/bluetooth/BSDBluetooth/blued.ucl
usr.sbin/capsulectl/capbundle/Unit.ucl
usr.sbin/networkcmpctl/capbundle/Unit.ucl
usr.sbin/switchboardctl/capbundle/Unit.ucl
EOF
}

atf_test_case every_shipped_unit_is_explicit
every_shipped_unit_is_explicit_body()
{
	require_srctree
	write_expected_inventory
	manifest_inventory >actual
	atf_check -s exit:0 cmp expected actual

	# A supervised unit names exactly one management class.  An exec
	# application (activation { exec = true; }, e.g. capsulectl and
	# switchboardctl) is executable policy, not a supervised daemon:
	# libcapbundle's exec-application key set has no "control" and rejects
	# one, so such a manifest must declare none.
	while read -r manifest; do
		path="${SRCTREE}/$manifest"
		if grep -Eq \
		    '^activation[[:space:]]*\{[[:space:]]*exec[[:space:]]*=[[:space:]]*true;[[:space:]]*\}' \
		    "$path"; then
			if grep -Eq '^[[:space:]]*control[[:space:]]*=' "$path"; then
				atf_fail "$manifest is an exec application and must not declare a control class"
			fi
			continue
		fi
		count=$(grep -Ec \
		    '^[[:space:]]*control = "(core|system|user)";' "$path")
		if [ "$count" -ne 1 ]; then
			atf_fail "$manifest must declare exactly one control class"
		fi
	done <actual
}

atf_test_case trust_spine_is_core_and_shielded
trust_spine_is_core_and_shielded_body()
{
	require_srctree
	# BSDAuth left the spine when software attributes replaced
	# login-principal grants (2026-10-05): admission is decided from
	# kernel-attributed software identity and no core provider took its
	# place.
	cat >spine <<'EOF'
usr.sbin/BSDAudit/capbundle/bsdaudit.ucl
usr.sbin/BSDExtension/capbundle/bsdextension.ucl
usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl
usr.sbin/BSDLog/capbundle/bsdlog.ucl
usr.sbin/BSDPower/capbundle/BSDPower.ucl
usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl
usr.sbin/BSDTime/capbundle/BSDTime.ucl
EOF
	# The spine is exactly the shipped core set, so a unit cannot become
	# (or stop being) core without this list changing with it.
	manifest_inventory >inventory
	while read -r manifest; do
		if grep -Fqx 'control = "core";' "${SRCTREE}/$manifest"; then
			echo "$manifest"
		fi
	done <inventory >core
	atf_check -s exit:0 cmp spine core

	for manifest in $(cat spine); do
		path="${SRCTREE}/$manifest"
		atf_check -s exit:0 -o ignore grep -Fx \
		    'control = "core";' "$path"
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
	    usr.sbin/BSDTrace/capbundle/bsdtrace.ucl \
	    usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl \
	    usr.sbin/BSDVM/capbundle/bsdvm.ucl
	do
		atf_check -s exit:0 -o ignore grep -Fx \
		    'control = "system";' "${SRCTREE}/$manifest"
	done
}

atf_test_case live_core_change_reaches_management_gate
live_core_change_reaches_management_gate_body()
{
	require_srctree
	reload="${SRCTREE}/usr.sbin/switchboard/reload.c"
	atf_check -s exit:0 -o ignore grep -F \
	    'A core image and its launch policy belong to the' "$reload"
	atf_check -s exit:0 -o ignore grep -F \
	    '"changed at runtime", (uid_t)-1, true) != 0' "$reload"
}

atf_init_test_cases()
{
	atf_add_test_case every_shipped_unit_is_explicit
	atf_add_test_case trust_spine_is_core_and_shielded
	atf_add_test_case non_tcb_units_are_system_managed
	atf_add_test_case live_core_change_reaches_management_gate
}

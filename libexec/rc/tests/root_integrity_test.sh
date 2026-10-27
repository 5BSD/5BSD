# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	# Load the maintained start function with command dependencies intercepted.
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d; s,/sbin/nextboot,./nextboot,g' \
	    "${rc_source}/rc.d/root" > root.sh
	cat > nextboot <<-'EOF'
	#!/bin/sh
	echo nextboot >> operations
	EOF
	chmod +x nextboot
	cat > seams.sh <<-'EOF'
	SYSCTL=test_sysctl
	test_sysctl() {
		[ "$*" = '-i -n security.mac.system_integrity.enforcing' ] || exit 99
		[ "${MODE}" = error ] && return 1
		printf '%s\n' "${MODE}"
	}
	mount() { echo mount >> operations; }
	umount() { echo umount >> operations; }
	stop_boot() { echo stopped >> operations; }
	EOF
}

atf_test_case protected
protected_body()
{
	setup
	for rw in YES NO ''; do
		atf_check -s exit:0 -o empty -e empty env MODE=1 root_rw_mount="$rw" sh -c \
		    '. ./seams.sh; . ./root.sh; root_start'
	done
	[ ! -e operations ] || atf_fail 'protected startup changed mounts or boot state'
}

atf_test_case query_failure
query_failure_body()
{
	setup
	for mode in error invalid 2; do
		rm -f operations
		atf_check -s exit:1 -o match:'startup aborted' -e empty env MODE="$mode" root_rw_mount=YES sh -c \
		    '. ./seams.sh; . ./root.sh; root_start'
		printf 'stopped\n' > expected
		atf_check cmp expected operations
	done
}

atf_test_case ordinary
ordinary_body()
{
	setup
	for mode in 0 ''; do
		for rw in YES NO; do
			rm -f operations
			atf_check -s exit:0 -o empty -e empty env MODE="$mode" root_rw_mount="$rw" sh -c \
			    '. ./seams.sh; . ./root.sh; root_start'
			: > expected
			[ "$rw" = NO ] || echo mount >> expected
			printf 'umount\nnextboot\n' >> expected
			atf_check cmp expected operations
		done
	done
}

atf_init_test_cases()
{
	atf_add_test_case protected
	atf_add_test_case query_failure
	atf_add_test_case ordinary
}

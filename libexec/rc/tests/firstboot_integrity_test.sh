# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	sed -n '/^# Remove the firstboot sentinel,/,/^echo /p' \
	    "${rc_source}/rc" > cleanup-range.sh
	grep -q '^echo ' cleanup-range.sh || atf_fail 'cleanup block boundary missing'
	sed '$d' cleanup-range.sh > cleanup.sh
	# Intercept host-affecting commands; exercise the maintained shell logic.
	sed 's,/sbin/shutdown -r now,test_shutdown -r now,' cleanup.sh > exercise-body.sh
	cat > seams.sh <<-'SEAMS'
	SYSCTL=test_sysctl
	test_sysctl() {
		echo query >> operations
		[ "$*" = '-i -n security.mac.system_integrity.enforcing' ] || return 99
		[ "$MODE" = error ] && return 1
		printf '%s\n' "$MODE"
	}
	checkyesno() { [ "$root_rw_mount" = YES ]; }
	mount() { echo "mount $*" >> operations; [ "${FAIL_MOUNT}" != "$1" ]; }
	chflags() { echo flags >> operations; [ "${FAIL_FLAGS}" != YES ]; }
	rm() {
		echo remove >> operations
		[ "${FAIL_REMOVE}" != YES ] || return 1
		command rm "$@"
	}
	kill() { echo "kill $*" >> operations; }
	test_shutdown() { echo "shutdown $*" >> operations; [ "${FAIL_SHUTDOWN}" != YES ]; }
	SEAMS
	printf '. ./seams.sh\n. ./exercise-body.sh\n' > exercise.sh
	mkdir -p state
	firstboot_sentinel="$PWD/state/firstboot"
	export firstboot_sentinel
}

reset_state()
{
	rm -f operations "$firstboot_sentinel" "$firstboot_sentinel-reboot"
	: > "$firstboot_sentinel"
}

atf_test_case absent
absent_body()
{
	setup
	atf_check -s exit:0 -o empty -e empty env MODE=error sh exercise.sh
	atf_check test ! -e operations
}

atf_test_case protected
protected_body()
{
	setup
	for rw in YES NO; do
		for reboot in YES NO; do
			reset_state
			[ "$reboot" = NO ] || : > "$firstboot_sentinel-reboot"
			atf_check -s exit:0 -o empty -e empty env MODE=1 root_rw_mount="$rw" sh exercise.sh
			printf 'query\nflags\nremove\n' > expected
			[ "$reboot" = NO ] || printf 'flags\nremove\nshutdown -r now\n' >> expected
			atf_check cmp expected operations
			atf_check test ! -e "$firstboot_sentinel"
			atf_check test ! -e "$firstboot_sentinel-reboot"
		done
	done
}

atf_test_case quoted_path
quoted_path_body()
{
	setup
	mkdir 'state space'
	firstboot_sentinel="$PWD/state space/firstboot"
	reset_state
	atf_check -s exit:0 -o empty -e empty env MODE=1 root_rw_mount=NO sh exercise.sh
	printf 'query\nflags\nremove\n' > expected
	atf_check cmp expected operations
	atf_check test ! -e "$firstboot_sentinel"
}

atf_test_case ordinary
ordinary_body()
{
	setup
	for mode in 0 ''; do
		for rw in YES NO; do
			reset_state
			: > "$firstboot_sentinel-reboot"
			atf_check -s exit:0 -o empty -e empty env MODE="$mode" root_rw_mount="$rw" sh exercise.sh
			printf 'query\n' > expected
			[ "$rw" = YES ] || printf 'mount -uw /\n' >> expected
			printf 'flags\nremove\nflags\nremove\n' >> expected
			[ "$rw" = YES ] || printf 'mount -ur /\n' >> expected
			printf 'kill -INT 1\n' >> expected
			atf_check cmp expected operations
			atf_check test ! -e "$firstboot_sentinel"
			atf_check test ! -e "$firstboot_sentinel-reboot"
		done
	done
}

atf_test_case query_failure
query_failure_body()
{
	setup
	for mode in error invalid 2; do
		reset_state
		atf_check -s exit:1 -o match:'startup aborted' -e empty env MODE="$mode" sh exercise.sh
		printf 'query\n' > expected
		atf_check cmp expected operations
		atf_check test -e "$firstboot_sentinel"
	done
}

atf_test_case removal_failure
removal_failure_body()
{
	setup
	for mode in 0 1; do
		for failure in FAIL_FLAGS FAIL_REMOVE; do
			reset_state
			: > "$firstboot_sentinel-reboot"
			atf_check -s exit:1 -o match:'Cannot remove firstboot sentinel' -e empty \
			    env MODE="$mode" root_rw_mount=NO "$failure=YES" sh exercise.sh
			atf_check test -e "$firstboot_sentinel"
			atf_check test -e "$firstboot_sentinel-reboot"
			atf_check -s exit:1 -o empty -e empty grep -E '^(kill|shutdown)' operations
			if [ "$mode" = 0 ]; then
				atf_check -o inline:'mount -ur /\n' tail -n 1 operations
			fi
		done
	done
}

atf_test_case shutdown_failure
shutdown_failure_body()
{
	setup
	reset_state
	: > "$firstboot_sentinel-reboot"
	atf_check -s exit:1 -o empty -e empty env MODE=1 root_rw_mount=NO FAIL_SHUTDOWN=YES sh exercise.sh
	atf_check -o inline:'shutdown -r now\n' tail -n 1 operations
}

atf_test_case mount_failure
mount_failure_body()
{
	setup
	reset_state
	atf_check -s exit:1 -o empty -e empty env MODE=0 root_rw_mount=NO FAIL_MOUNT=-uw sh exercise.sh
	printf 'query\nmount -uw /\n' > expected
	atf_check cmp expected operations
	atf_check test -e "$firstboot_sentinel"
	# A failure restoring read-only root must also prevent the reboot request.
	reset_state
	: > "$firstboot_sentinel-reboot"
	atf_check -s exit:1 -o empty -e empty env MODE=0 root_rw_mount=NO FAIL_MOUNT=-ur sh exercise.sh
	printf 'query\nmount -uw /\nflags\nremove\nflags\nremove\nmount -ur /\n' > expected
	atf_check cmp expected operations
}

atf_init_test_cases()
{
	atf_add_test_case absent
	atf_add_test_case protected
	atf_add_test_case ordinary
	atf_add_test_case quoted_path
	atf_add_test_case query_failure
	atf_add_test_case removal_failure
	atf_add_test_case shutdown_failure
	atf_add_test_case mount_failure
}

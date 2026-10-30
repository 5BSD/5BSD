# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	cp "${rc_source}/hostid.subr" ./hostid.subr
	for script in hostid hostid_save; do
		sed '/^\. \/etc\/rc.subr$/d; /^\. \/etc\/hostid.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
		    "${rc_source}/rc.d/${script}" > "${script}.sh"
	done
	cat > seams.sh <<-'EOF'
	. ./hostid.subr
	SYSCTL=test_sysctl
	SYSCTL_N='test_sysctl -n'
	uuid_fixture=57061ee3-7587-4a12-9447-2ac2b0e947fe
	hostid_file=hostid.cache
	machine_id_file=machine-id.cache
	test_sysctl() {
		case "$*" in
		'-i -n security.mac.system_integrity.enforcing')
			[ "${MODE:-1}" = error ] && return 1
			printf '%s\n' "${MODE-1}" ;;
		'-n kern.hostuuid') printf '%s\n' "${UUID-${uuid_fixture}}" ;;
		'-n kern.hostid') printf '%s\n' "${ID-1852121507}" ;;
		kern.hostuuid=*|kern.hostid=*) echo "$*" >> writes ;;
		*) return 1 ;;
		esac
	}
	warn() { echo "$*" >&2; }
	startmsg() { :; }
	kenv() { echo unexpected-hardware-query >&2; return 1; }
	uuidgen() { echo unexpected-generation >&2; return 1; }
	EOF
	printf '%s\n' 57061ee3-7587-4a12-9447-2ac2b0e947fe > hostid.cache
	printf '%s\n' 57061ee375874a1294472ac2b0e947fe > machine-id.cache
	cp hostid.cache hostid.before
	cp machine-id.cache machine-id.before
}

atf_test_case protected_start
protected_start_body()
{
	setup
	atf_check -s exit:0 -o empty -e empty sh -c \
	    '. ./seams.sh; . ./hostid.sh; hostid_start'
	atf_check -s exit:0 -o empty -e empty sh -c \
	    '. ./seams.sh; . ./hostid_save.sh; hostid_save'
	[ ! -e writes ] || atf_fail 'protected startup wrote sysctls'
	atf_check cmp hostid.cache hostid.before
	atf_check cmp machine-id.cache machine-id.before
	# No file or hardware fallback can repair an unset/mismatched kernel ID.
	for id in 0 1852121508 invalid 999999999999999999999999; do
		atf_check -s exit:1 -o empty -e match:'host ID' env ID="$id" sh -c \
		    '. ./seams.sh; . ./hostid.sh; hostid_start'
	done
	for uuid in '' bad 00000000-0000-0000-0000-000000000000; do
		atf_check -s exit:1 -o empty -e match:'UUID' env UUID="$uuid" sh -c \
		    '. ./seams.sh; . ./hostid.sh; hostid_start'
	done
	[ ! -e writes ] || atf_fail 'invalid kernel identity was repaired'
}

atf_test_case cache_rejection
cache_rejection_body()
{
	setup
	for path in hostid.cache machine-id.cache; do
		cp "$path" before
		for fault in missing wrong extra symlink; do
			rm -f "$path"
			case "$fault" in
			missing) ;;
			wrong) echo wrong > "$path" ;;
			extra) cat before > "$path"; echo extra >> "$path" ;;
			symlink) ln -s before "$path" ;;
			esac
			atf_check -s exit:1 -o empty -e match:'file missing or inconsistent' sh -c \
			    '. ./seams.sh; . ./hostid_save.sh; hostid_save'
			case "$fault" in
			missing) [ ! -e "$path" ] || atf_fail 'created absent cache' ;;
			wrong) [ "$(cat "$path")" = wrong ] || atf_fail 'repaired wrong cache' ;;
			extra) [ "$(tail -1 "$path")" = extra ] || atf_fail 'removed extra record' ;;
			symlink) [ -L "$path" ] || atf_fail 'replaced cache symlink' ;;
			esac
		done
		rm "$path"
		cp before "$path"
	done
	[ ! -e writes ] || atf_fail 'cache verification wrote sysctls'
}

atf_test_case reset_and_query_failure
reset_and_query_failure_body()
{
	setup
	atf_check -s exit:1 -o empty -e match:'authenticated boot policy' sh -c \
	    '. ./seams.sh; . ./hostid.sh; hostid_reset'
	for mode in error invalid 2; do
		for action in hostid_start hostid_reset hostid_save; do
			atf_check -s exit:1 -o empty -e match:'protection' env MODE="$mode" sh -c \
			    '. ./seams.sh; . ./hostid.sh; . ./hostid_save.sh; "$1"' sh "$action"
		done
	done
	[ ! -e writes ] || atf_fail 'query failure fell back to identity writes'
	atf_check cmp hostid.cache hostid.before
	atf_check cmp machine-id.cache machine-id.before
}

atf_test_case ordinary_start
ordinary_start_body()
{
	setup
	for mode in 0 ''; do
		rm -f writes
		atf_check -s exit:0 -o empty -e empty env MODE="$mode" sh -c \
		    '. ./seams.sh; . ./hostid.sh; hostid_start'
		printf '%s\n' 'kern.hostuuid=57061ee3-7587-4a12-9447-2ac2b0e947fe' \
		    'kern.hostid=0x6e6521a3' > expected
		atf_check cmp writes expected
		printf 'stale\n' > machine-id.cache
		atf_check -s exit:0 -o empty -e empty env MODE="$mode" sh -c \
		    '. ./seams.sh; . ./hostid_save.sh; hostid_save'
		atf_check cmp machine-id.cache machine-id.before
	done
}

atf_init_test_cases()
{
	atf_add_test_case protected_start
	atf_add_test_case cache_rejection
	atf_add_test_case reset_and_query_failure
	atf_add_test_case ordinary_start
}

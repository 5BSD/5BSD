#
# SPDX-License-Identifier: BSD-2-Clause
#
# rc.d/ntpd must start a non-root ntpd without su(1): su -m runs root's login
# shell, which switchboard's ntpd grant does not pin, so mac_ntpd(4) would
# refuse the clock to that ntpd.  daemon(8) -u executes ntpd directly.  With
# the capability plane, settings that put another program in front of ntpd,
# or keep ntpd root, are warned about, and a start that leaves no ntpd fails.

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "$(atf_config_get rc_script "${rc_source}/rc.d/ntpd")" > ntpd.sh
	printf 'server 127.127.1.0\n' > ntp.conf
	cat > seams.sh <<-'EOF'
	checkyesno() { eval '[ "${'"$1"'}" = yes ]'; }
	kenv() { echo "${PLANE-YES}"; }
	warn() { echo "ntpd: WARNING: $*" >&2; }
	ntpd_config=./ntp.conf
	ntp_db_leapfile=NO
	EOF
}

atf_test_case nonroot_uses_daemon
nonroot_uses_daemon_head()
{
	atf_set descr "a non-root ntpd starts through daemon -u ntpd, not su"
}
nonroot_uses_daemon_body()
{
	setup
	atf_check -s exit:0 -o inline:'user=<> prepend=</usr/sbin/daemon -u ntpd>\n' \
	    -e empty sh -c '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 0; };
	     _user=; _prepend=; ntpd_precmd || exit;
	     printf "user=<%s> prepend=<%s>\n" "$_user" "$_prepend"'
	atf_check -s exit:0 -o match:'-f /var/db/ntp/ntpd.drift' -e empty sh -c \
	    '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 0; };
	     ntpd_precmd || exit; printf "%s\n" "$command_args"'
	# An administrator's ntpd_prepend still runs first.  Without the
	# plane nothing is said; with it, nice ends the grant: warned.
	atf_check -s exit:0 -o inline:'<nice -n 5 /usr/sbin/daemon -u ntpd>\n' \
	    -e empty env PLANE=NO sh -c '. ./seams.sh; . ./ntpd.sh;
	     can_run_nonroot() { return 0; };
	     _prepend="nice -n 5"; ntpd_precmd || exit; printf "<%s>\n" "$_prepend"'
	atf_check -s exit:0 -o inline:'<nice -n 5 /usr/sbin/daemon -u ntpd>\n' \
	    -e match:'refused the clock.*ntpd_prepend \(nice\)' sh -c \
	    '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 0; };
	     _prepend="nice -n 5"; ntpd_precmd || exit; printf "<%s>\n" "$_prepend"'
}

atf_test_case helpers_warn
helpers_warn_head()
{
	atf_set descr "with the plane, programs rc.subr runs before ntpd are warned about"
}
helpers_warn_body()
{
	local helper var value what

	setup
	for helper in '_nice|5|ntpd_nice .nice.' '_fib|1|ntpd_fib .setfib.' \
	    '_cpusetcmd|cpuset -l 0|ntpd_cpuset .cpuset.' \
	    '_setauditcmd|setaudit -U -a x|audit_user .setaudit.' \
	    '_chroot|/var/empty|ntpd_chroot .chroot.'; do
		var=${helper%%|*}
		value=${helper#*|}
		what=${value#*|}
		value=${value%|*}
		atf_check -s exit:0 -o empty -e match:"refused the clock.*${what}" \
		    sh -c '. ./seams.sh; . ./ntpd.sh;
		     can_run_nonroot() { return 0; }; '"${var}"'="$1";
		     ntpd_precmd' sh "${value}"
		atf_check -s exit:0 -o empty -e empty env PLANE=NO \
		    sh -c '. ./seams.sh; . ./ntpd.sh;
		     can_run_nonroot() { return 0; }; '"${var}"'="$1";
		     ntpd_precmd' sh "${value}"
	done
}

atf_test_case root_unchanged
root_unchanged_head()
{
	atf_set descr "an ntpd that must run as root (ntpd_user, file options) is not wrapped"
}
root_unchanged_body()
{
	setup
	atf_check -s exit:0 -o inline:'user=<> prepend=<>\n' -e empty \
	    env PLANE=NO sh -c \
	    '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 1; };
	     _user=; _prepend=; ntpd_precmd || exit;
	     printf "user=<%s> prepend=<%s>\n" "$_user" "$_prepend"'
}

atf_test_case root_warned
root_warned_head()
{
	atf_set descr "with the plane, an ntpd kept root is warned about, with the reason"
}
root_warned_body()
{
	setup
	atf_check -s exit:0 -o inline:'prepend=<>\n' \
	    -e match:'runs as root \(ntpd_user is set\).*refuses the clock' \
	    sh -c '. ./seams.sh; . ./ntpd.sh; ntpd_user=root; _prepend=;
	     ntpd_precmd || exit; printf "prepend=<%s>\n" "$_prepend"'
	printf 'logfile /var/log/ntp.log\n' >> ntp.conf
	atf_check -s exit:0 -o empty \
	    -e match:'runs as root \(\./ntp\.conf names a file' \
	    sh -c '. ./seams.sh; . ./ntpd.sh; ntpd_precmd'
	atf_check -s exit:0 -o empty -e empty env PLANE=NO \
	    sh -c '. ./seams.sh; . ./ntpd.sh; ntpd_precmd'
}

atf_test_case start_waits_for_ntpd
start_waits_for_ntpd_head()
{
	atf_set descr "start fails when no ntpd is left running after daemon(8)"
}
start_waits_for_ntpd_body()
{
	setup
	# check_pidfile finds ntpd after UP_AFTER waits; sleep only counts.
	cat >> seams.sh <<-'EOF'
	sleep() { echo slept >> sleeps; }
	check_pidfile() {
		[ "$1" = /var/db/ntp/ntpd.pid ] && [ "$2" = /usr/sbin/ntpd ] &&
		    [ -f sleeps ] &&
		    [ "$(wc -l < sleeps)" -ge "${UP_AFTER:-99}" ] && echo 4242
	}
	EOF
	atf_check -s exit:0 -o empty -e empty env UP_AFTER=2 \
	    sh -c '. ./seams.sh; . ./ntpd.sh;
	     [ "$start_postcmd" = ntpd_poststart ] && ntpd_poststart'
	atf_check -o match:'^ *2 sleeps$' wc -l sleeps
	rm -f sleeps
	atf_check -s exit:1 -o empty -e match:'ntpd did not start' \
	    sh -c '. ./seams.sh; . ./ntpd.sh; ntpd_poststart'
	atf_check -o match:'^ *10 sleeps$' wc -l sleeps
}

atf_test_case no_su_in_script
no_su_in_script_head()
{
	atf_set descr "rc.d/ntpd never selects rc.subr's su path (_user=ntpd)"
}
no_su_in_script_body()
{
	setup
	if grep -E '^[[:space:]]*_user=' ntpd.sh; then
		atf_fail "rc.d/ntpd sets _user: rc.subr would run ntpd through su -m"
	fi
}

atf_init_test_cases()
{
	atf_add_test_case nonroot_uses_daemon
	atf_add_test_case helpers_warn
	atf_add_test_case root_unchanged
	atf_add_test_case root_warned
	atf_add_test_case start_waits_for_ntpd
	atf_add_test_case no_su_in_script
}

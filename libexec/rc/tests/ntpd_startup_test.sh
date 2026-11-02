#
# SPDX-License-Identifier: BSD-2-Clause
#
# rc.d/ntpd must start a non-root ntpd without su(1): su -m runs root's login
# shell, which switchboard's ntpd grant does not pin, so mac_ntpd(4) would
# refuse the clock to that ntpd.  daemon(8) -u executes ntpd directly.

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "$(atf_config_get rc_script "${rc_source}/rc.d/ntpd")" > ntpd.sh
	printf 'server 127.127.1.0\n' > ntp.conf
	cat > seams.sh <<-'EOF'
	checkyesno() { eval '[ "${'"$1"'}" = yes ]'; }
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
	# An administrator's ntpd_prepend still runs first.
	atf_check -s exit:0 -o inline:'<nice -n 5 /usr/sbin/daemon -u ntpd>\n' \
	    -e empty sh -c '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 0; };
	     _prepend="nice -n 5"; ntpd_precmd || exit; printf "<%s>\n" "$_prepend"'
}

atf_test_case root_unchanged
root_unchanged_head()
{
	atf_set descr "an ntpd that must run as root (ntpd_user, file options) is not wrapped"
}
root_unchanged_body()
{
	setup
	atf_check -s exit:0 -o inline:'user=<> prepend=<>\n' -e empty sh -c \
	    '. ./seams.sh; . ./ntpd.sh; can_run_nonroot() { return 1; };
	     _user=; _prepend=; ntpd_precmd || exit;
	     printf "user=<%s> prepend=<%s>\n" "$_user" "$_prepend"'
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
	atf_add_test_case root_unchanged
	atf_add_test_case no_su_in_script
}

# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	rc_source=$(atf_config_get rc_source /etc)
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${rc_source}/rc.d/syslogd" > syslogd.sh
	cat > seams.sh <<-'EOF'
	check_jail() { return 0; }
	checkyesno() { eval '[ "${'"$1"'}" = yes ]'; }
	# Never touch the host's /var/run/log in these script tests.
	rm() { [ "${FAIL_REMOVE}" != yes ]; }
	EOF
}

atf_test_case prepare_failure
prepare_failure_body()
{
	setup
	mkdir blocked
	atf_check -s exit:1 -o empty -e ignore sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile=blocked; syslogd_precmd'
	atf_check -s exit:1 -o empty -e empty env FAIL_REMOVE=yes sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile=list; syslogd_precmd'
	[ ! -e list ] || atf_fail 'continued after socket cleanup failed'
}

atf_test_case list_read_failure
list_read_failure_body()
{
	setup
	atf_check -s exit:1 -o empty -e ignore sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile=missing; set_socketlist'
	atf_check -s exit:1 -o empty -e empty sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile=list; altlog_proglist=ntpd;
	     ntpd_enable=yes; ntpd_chrootdir=/jail; cat() { return 1; }; syslogd_precmd'
}

atf_test_case default_and_chroot
default_and_chroot_body()
{
	setup
	atf_check -s exit:0 -o inline:'-s\n' -e empty sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile="socket list"; rc_flags=-s;
	     syslogd_precmd || exit; printf "%s\n" "$rc_flags"'
	[ -f 'socket list' ] && [ ! -s 'socket list' ] || atf_fail 'incorrect empty list'
	atf_check -s exit:0 -o inline:'<-l>\n</var/run/log>\n<-l>\n</jail/var/run/log>\n<-s>\n' -e empty sh -c \
	    '. ./seams.sh; . ./syslogd.sh; sockfile="socket list"; rc_flags=-s;
	     altlog_proglist=ntpd; ntpd_enable=yes; ntpd_chrootdir=/jail;
	     syslogd_precmd || exit; capture() { printf "<%s>\n" "$@"; }; eval "capture $rc_flags"'
	printf '/jail/var/run/log\n/var/run/log\n' > expected
	atf_check cmp expected 'socket list'
}

atf_test_case explicit_paths
explicit_paths_body()
{
	setup
	cat > paths.sh <<-'EOF'
	. ./seams.sh
	. ./syslogd.sh
	syslogd_pidfile="${PWD}/pid 'file"
	syslogd_socket="${PWD}/socket \$(touch INJECTED)"
	syslogd_privsocket="${PWD}/private socket"
	syslogd_socketlist="${PWD}/socket list"
	syslogd_configure_paths || exit 1
	[ "$pidfile" = "$syslogd_pidfile" ] || exit 2
	[ "$sockfile" = "$syslogd_socketlist" ] || exit 3
	[ "$logsocket" = "$syslogd_socket" ] || exit 4
	check_args() {
	    [ "$#" -eq 6 ] && [ "$1" = -P ] && [ "$2" = "$syslogd_pidfile" ] &&
	    [ "$3" = -p ] && [ "$4" = "$syslogd_socket" ] &&
	    [ "$5" = -S ] && [ "$6" = "$syslogd_privsocket" ]
	}
	eval "check_args $command_args" || exit 5
	[ ! -e INJECTED ] || exit 6
	rm() { [ "$1" = -f ] && [ "$2" = "$syslogd_socket" ]; }
	syslogd_precmd || exit 7
	[ -f "$syslogd_socketlist" ] || exit 8
	altlog_proglist=ntpd
	ntpd_enable=yes
	ntpd_chrootdir="${PWD}/jail 'directory"
	syslogd_precmd || exit 9
	check_extra() { [ "$#" -eq 2 ] && [ "$1" = -l ] && [ "$2" = "$ntpd_chrootdir/var/run/log" ]; }
	eval "check_extra $rc_flags" || exit 10
	EOF
	atf_check -s exit:0 -o empty -e empty sh paths.sh
	atf_check -s exit:1 -o empty -e ignore sh -c \
	    '. ./seams.sh; . ./syslogd.sh; warn() { :; }; syslogd_socket=relative; syslogd_configure_paths'
}

atf_init_test_cases()
{
	atf_add_test_case prepare_failure
	atf_add_test_case list_read_failure
	atf_add_test_case default_and_chroot
	atf_add_test_case explicit_paths
}

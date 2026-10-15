#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# authpf(8) (OpenBSD): a login session loads the user's rules into the
# authpf/<user>(<pid>) anchor and adds the client to the authpf_users
# table; the end of the session removes both.

USER=pfauthtest
CLIENT=192.0.2.77

authpf_setup()
{
	kldstat -q -m pf || atf_skip "pf is not loaded"
	[ -u /usr/sbin/authpf ] || atf_skip "authpf is not installed setuid"
	pw userdel ${USER} >/dev/null 2>&1
	pw useradd ${USER} -s /usr/sbin/authpf -d /nonexistent -c "authpf test" ||
	    atf_fail "pw useradd"
	mkdir -p /etc/authpf /var/authpf
	[ -f /etc/authpf/authpf.conf ] && cp /etc/authpf/authpf.conf authpf.conf.saved
	[ -f /etc/authpf/authpf.rules ] && cp /etc/authpf/authpf.rules authpf.rules.saved
	: > /etc/authpf/authpf.conf
	printf '%s\n' \
	    'pass in quick proto tcp from $user_ip to any port 22 label "authpf"' \
	    'pass in quick proto tcp from <authpf_users> to any port 80' \
	    > /etc/authpf/authpf.rules
	printf '%s\n' 'table <authpf_users> persist' 'pass all' 'anchor "authpf/*"' |
	    pfctl -f - || atf_fail "pf.conf"
}

authpf_cleanup()
{
	pkill -f /usr/sbin/authpf >/dev/null 2>&1
	pw userdel ${USER} >/dev/null 2>&1
	if [ -f authpf.conf.saved ]; then
		cp authpf.conf.saved /etc/authpf/authpf.conf
	else
		rm -f /etc/authpf/authpf.conf
	fi
	if [ -f authpf.rules.saved ]; then
		cp authpf.rules.saved /etc/authpf/authpf.rules
	else
		rm -f /etc/authpf/authpf.rules
	fi
	pfctl -f /etc/pf.conf >/dev/null 2>&1
	true
}

atf_test_case "login_logout" "cleanup"
login_logout_head()
{
	atf_set descr 'authpf loads the user rules on login and removes them on logout'
	atf_set require.user root
}
login_logout_body()
{
	authpf_setup

	env SSH_TTY=/dev/null SSH_CLIENT="${CLIENT} 40000 22" \
	    daemon -u ${USER} -p authpf.pid /usr/sbin/authpf
	i=0
	until [ -s authpf.pid ] && [ -f /var/authpf/${CLIENT} ]; do
		i=$((i + 1))
		[ $i -lt 50 ] || atf_fail "authpf did not start a session"
		sleep 0.1
	done
	pid=$(cat /var/authpf/${CLIENT} | head -1)
	anchor="authpf/${USER}(${pid})"

	atf_check -s exit:0 -o match:"from ${CLIENT} to any port = 22" \
	    pfctl -a "${anchor}" -sr
	atf_check -s exit:0 -o match:"${CLIENT}" pfctl -t authpf_users -T show
	atf_check -s exit:0 -o match:"${USER}\\(${pid}\\)" pfctl -a authpf -sA

	# End of session: SIGTERM, as sshd sends on disconnect.
	kill -TERM ${pid}
	i=0
	while [ -f /var/authpf/${CLIENT} ]; do
		i=$((i + 1))
		[ $i -lt 50 ] || atf_fail "authpf did not end the session"
		sleep 0.1
	done
	# The session's anchor is gone with its rules.
	atf_check -s exit:0 -o not-match:"${USER}" pfctl -a authpf -sA
	atf_check -s exit:0 -o not-match:"${CLIENT}" pfctl -t authpf_users -T show
}
login_logout_cleanup()
{
	authpf_cleanup
}

atf_test_case "banned" "cleanup"
banned_head()
{
	atf_set descr 'authpf refuses a banned user and loads nothing'
	atf_set require.user root
}
banned_body()
{
	authpf_setup
	mkdir -p /etc/authpf/banned
	echo "test ban" > /etc/authpf/banned/${USER}

	env SSH_TTY=/dev/null SSH_CLIENT="${CLIENT} 40001 22" \
	    su -m ${USER} -c /usr/sbin/authpf > out 2>&1 < /dev/null
	atf_check -s exit:0 -o match:"test ban" cat out
	atf_check -s exit:0 -o empty pfctl -a authpf -sA
	rm -f /etc/authpf/banned/${USER}
}
banned_cleanup()
{
	rm -f /etc/authpf/banned/${USER}
	authpf_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "login_logout"
	atf_add_test_case "banned"
}

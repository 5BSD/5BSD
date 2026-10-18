#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# Survival tests for the seams between OpenBSD PF and the FreeBSD stack:
# pf and stack operations run concurrently (background loops with fixed
# iteration counts) on an SMP machine, the way the lifecycle races that
# crashed 5BSD were found: interface rename and groups, VNET moves and
# teardown, pfsync, divert, dummynet re-injection, sendfile mbufs through
# route-to.  Operations inside the loops may fail (that is the point of
# racing them); the cases assert what must hold afterwards:
#   - every loop finished (no deadlock; a stuck job is reported with the
#     kernel stacks of the processes involved);
#   - pf still answers pfctl -si, in the host and in each jail;
#   - the expected traffic flows again;
#   - no interface or jail is left behind once the jails are gone;
#   - the kernel logged no new lock order reversal, panic or "pf:" line
#     (integ_dmesg_check).
# The loops are sized for a 4-CPU VM under TCG emulation (each case runs a
# few minutes there).  kyua -v test_suites.FreeBSD.stress_scale=N
# multiplies the iteration counts.  Run in a test VM only (README).

. $(atf_get_srcdir)/integration.subr

SOCKHELPER=$(atf_get_srcdir)/sockhelper
SFHELPER=$(atf_get_srcdir)/../../common/sendfile_helper

# Seconds the churn loops of a case may take before they count as hung,
# and the traffic loops after they are told to stop.
ST_CHURN_SECS=540
ST_TRAFFIC_SECS=90
# Seconds jail teardown may take to return interfaces and free jails.
# A dying jail lasts until its TCP connections to killed peers time out.
ST_LEAK_SECS=300

st_ifs()
{
	ifconfig -l | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort
}

st_jails()
{
	jls -d jid name 2>/dev/null | LC_ALL=C sort
}

# st_init: pft_init plus the snapshots the final checks compare against.
st_init()
{
	pft_init
	integ_require_prog nc ping jls
	st_scale=$(atf_config_get stress_scale 1)
	rm -f st.stop
	: > st_churn.lst
	: > st_traffic.lst
	st_ifs > st.ifs.before
	st_jails > st.jails.before
	integ_dmesg_snapshot
}

st_require_dummynet()
{
	kldstat -q -m dummynet || atf_skip "This test requires dummynet"
	integ_require_prog dnctl
}

# st_n count: an iteration count scaled by stress_scale.
st_n()
{
	echo $(($1 * st_scale))
}

# st_loop name count cmd...: run cmd count times in the background,
# ignoring its failures; st_i is the iteration number.  The output goes to
# name.log; name.done records that the loop ran to the end.
st_loop()
{
	st_lname=$1
	st_lim=$2
	shift 2
	(
		st_i=0
		while [ ${st_i} -lt ${st_lim} ]; do
			"$@"
			st_i=$((st_i + 1))
		done
		echo ${st_i} > ${st_lname}.done
	) < /dev/null >> ${st_lname}.log 2>&1 &
	echo "$! ${st_lname}" >> st_churn.lst
}

# st_traffic name max cmd...: like st_loop, for traffic: it stops after
# max iterations or when st_stop is called, whichever is first.
st_traffic()
{
	st_lname=$1
	st_lim=$2
	shift 2
	(
		st_i=0
		while [ ${st_i} -lt ${st_lim} ] && [ ! -f st.stop ]; do
			"$@"
			st_i=$((st_i + 1))
		done
		echo ${st_i} > ${st_lname}.done
	) < /dev/null >> ${st_lname}.log 2>&1 &
	echo "$! ${st_lname}" >> st_traffic.lst
}

st_running()
{
	_s=$(ps -o stat= -p $1 2>/dev/null) || return 1
	case ${_s} in
	Z*)	return 1 ;;
	esac
	return 0
}

# st_hung jobs seconds: report the processes of stuck jobs with their
# kernel stacks, then fail.
st_hung()
{
	echo "Jobs still running after $2 seconds:$1"
	ps -axd -o pid,ppid,jid,stat,wchan,command
	for _p in $(pgrep -f 'pfctl|ifconfig|jail|jexec|dnctl|sockhelper|sendfile_helper|nc |ping|tcpdump'); do
		procstat -kk ${_p} 2>/dev/null
	done
	atf_fail "stress jobs hung:$1"
}

# st_waitlist list seconds: wait for the jobs of a list, failing if one is
# still running after the given time or did not finish its loop.
st_waitlist()
{
	_end=$(($(date +%s) + $2))
	while :; do
		_alive=
		while read _pid _name; do
			st_running ${_pid} && _alive="${_alive} ${_name}"
		done < $1
		[ -n "${_alive}" ] || break
		[ $(date +%s) -lt ${_end} ] || st_hung "${_alive}" $2
		sleep 1
	done
	while read _pid _name; do
		[ -f ${_name}.done ] ||
		    atf_fail "stress job ${_name} did not finish its loop"
		echo "${_name}: $(cat ${_name}.done) iterations"
	done < $1
}

# st_wait: wait for the churn loops, then stop and wait for the traffic.
st_wait()
{
	st_waitlist st_churn.lst ${ST_CHURN_SECS}
	st_stop
}

st_stop()
{
	touch st.stop
	st_waitlist st_traffic.lst ${ST_TRAFFIC_SECS}
	: > st_traffic.lst
	rm -f st.stop
}

# st_answers jail...: pf answers in each jail (enabled or not).
st_answers()
{
	for _j in "$@"; do
		atf_check -s exit:0 -o match:'^Status: ' -e ignore \
		    jexec ${_j} pfctl -si
	done
}

# st_alive jail...: pf answers in the host and is enabled in each jail.
st_alive()
{
	atf_check -s exit:0 -o match:'^Status: ' -e ignore pfctl -si
	for _j in "$@"; do
		atf_check -s exit:0 -o match:'^Status: Enabled' -e ignore \
		    jexec ${_j} pfctl -si
	done
}

# st_retry count cmd...: run cmd until it succeeds with output, at most
# count times; print that output.
st_retry()
{
	st_tries=$1
	shift
	while [ ${st_tries} -gt 0 ]; do
		_o=$("$@" 2>/dev/null)
		if [ $? -eq 0 ] && [ -n "${_o}" ]; then
			echo "${_o}"
			return 0
		fi
		st_tries=$((st_tries - 1))
		sleep 1
	done
	return 1
}

# st_expect regex cmd...: atf_check for shell functions (atf-check execs
# its command): cmd must succeed and, unless regex is empty, print a line
# matching it.
st_expect()
{
	st_re=$1
	shift
	st_out=$("$@" 2>&1)
	st_rc=$?
	[ ${st_rc} -eq 0 ] || atf_fail "$*: exit status ${st_rc}: ${st_out}"
	[ -z "${st_re}" ] || printf '%s\n' "${st_out}" | grep -Eq -- "${st_re}" ||
	    atf_fail "$*: no output matching ${st_re}: ${st_out}"
}

st_wait_ready()
{
	_i=0
	while ! grep -q READY $1 2>/dev/null; do
		_i=$((_i + 1))
		[ ${_i} -lt 100 ] || atf_fail "helper did not start: $(cat $1)"
		sleep 0.1
	done
}

st_wait_listen()
{
	_i=0
	while ! jexec $1 sockstat -l -P $2 -p $3 | grep -q ":$3"; do
		_i=$((_i + 1))
		[ ${_i} -lt 100 ] || atf_fail "no $2 listener on port $3 in $1"
		sleep 0.1
	done
}

# st_noleaks: once the jails are gone, the host has the interfaces and
# jails it had at st_init.  Teardown is asynchronous, so poll.
st_noleaks()
{
	_end=$(($(date +%s) + ${ST_LEAK_SECS}))
	while :; do
		st_ifs > st.ifs.after
		st_jails > st.jails.after
		# Only additions count: a dying jail of an earlier case may
		# finish dying meanwhile.
		if [ -z "$(LC_ALL=C comm -13 st.ifs.before st.ifs.after)" ] &&
		    [ -z "$(LC_ALL=C comm -13 st.jails.before st.jails.after)" ]
		then
			return 0
		fi
		[ $(date +%s) -lt ${_end} ] || break
		sleep 1
	done
	echo "Interfaces (before, after):"
	diff -u st.ifs.before st.ifs.after
	echo "Jails, including dying ones (before, after):"
	diff -u st.jails.before st.jails.after
	atf_fail "interfaces or jails left behind: $(LC_ALL=C comm -13 \
	    st.ifs.before st.ifs.after | tr '\n' ' ')$(LC_ALL=C comm -13 \
	    st.jails.before st.jails.after | tr '\n' ' ')"
}

# st_finish: remove the jails and interfaces of the case, then check for
# leaks and kernel messages.
st_finish()
{
	pft_cleanup
	st_noleaks
	integ_dmesg_check
}

# st_reap name: an interface the case created in the host and moved into
# a jail comes back when the jail goes; wait for it and destroy it (and
# any second interface of the same name).
st_reap()
{
	_i=0
	while ! ifconfig $1 > /dev/null 2>&1; do
		_i=$((_i + 1))
		[ ${_i} -lt 60 ] || return 0
		sleep 0.5
	done
	_i=0
	while ifconfig $1 > /dev/null 2>&1 && [ ${_i} -lt 4 ]; do
		ifconfig $1 destroy
		_i=$((_i + 1))
	done
}

# st_jail_remove jail: jail -r outside vnet_cleanup (with its interfaces
# still in it), and forget it in created_jails.lst.
st_jail_remove()
{
	atf_check -s exit:0 jail -r $1
	sed -i '' "/^$1 /d; /^$1\$/d" created_jails.lst
}

# st_cleanup: the cleanup of every case.  After a failure, background
# loops and the interfaces and jails they made may remain.
st_cleanup()
{
	touch st.stop
	for _l in st_churn.lst st_traffic.lst; do
		[ -f ${_l} ] || continue
		while read _pid _name; do
			pkill -9 -P ${_pid} 2>/dev/null
			kill -9 ${_pid} 2>/dev/null
		done < ${_l}
	done
	integ_cleanup
	if [ -f st.jails.before ]; then
		for _j in $(st_jails | LC_ALL=C comm -13 st.jails.before -); do
			jail -r ${_j} 2>/dev/null
		done
	fi
	if [ -f st.ifs.before ]; then
		sleep 2
		for _i in $(st_ifs | LC_ALL=C comm -13 st.ifs.before -); do
			ifconfig ${_i} destroy 2>/dev/null
		done
	fi
	return 0
}

# Router topology for the traffic cases:
#
#   stcli ${c}a 192.0.2.2 -- ${c}b 192.0.2.1  stfw  bridge stbr0 198.51.100.1
#                                                     member ${s}a
#                                  stsrv ${s}b 198.51.100.2 -- ${s}a
#
# stfw forwards with pf enabled; stsrv runs inetd's echo (tcp and udp) and
# discard (tcp) services.
st_topo()
{
	integ_require_prog inetd
	vnet_init_bridge
	c=$(vnet_mkepair)
	s=$(vnet_mkepair)
	vnet_mkjail stcli ${c}a
	vnet_mkjail stfw ${c}b ${s}a
	vnet_mkjail stsrv ${s}b
	C=${c}b
	S=${s}a

	jexec stcli ifconfig lo0 127.0.0.1/8 up
	jexec stcli ifconfig ${c}a 192.0.2.2/24 up
	jexec stcli route -q add default 192.0.2.1

	jexec stfw ifconfig lo0 127.0.0.1/8 up
	jexec stfw ifconfig ${C} 192.0.2.1/24 up
	jexec stfw ifconfig bridge create name stbr0 > /dev/null ||
	    atf_fail "cannot create bridge stbr0"
	jexec stfw ifconfig stbr0 addm ${S} up
	jexec stfw ifconfig ${S} up
	jexec stfw ifconfig stbr0 inet 198.51.100.1/24
	jexec stfw sysctl -q net.inet.ip.forwarding=1 \
	    net.link.bridge.pfil_member=1

	jexec stsrv ifconfig lo0 127.0.0.1/8 up
	jexec stsrv ifconfig ${s}b 198.51.100.2/24 up
	jexec stsrv route -q add default 198.51.100.1
	cat > st-inetd.conf <<EOF
echo	stream	tcp	nowait	root	internal
echo	dgram	udp	wait	root	internal
discard	stream	tcp	nowait	root	internal
EOF
	jexec stsrv inetd -p ${PWD}/inetd-stsrv.pid ${PWD}/st-inetd.conf

	pft_set_rules stfw "pass"
	jexec stfw pfctl -e > /dev/null 2>&1
	st_expect '' st_retry 5 jexec stcli ping -c 1 -t 2 198.51.100.2
}

# Traffic through stfw (one iteration each).
st_ping()
{
	jexec stcli ping -c 3 -i 0.2 -t 3 ${1:-198.51.100.2}
}

st_tcp()
{
	echo st | jexec stcli nc -N -w 3 $1 $2
}

st_udp()
{
	echo st | jexec stcli nc -u -w 2 $1 $2
}

st_tcp_bulk()
{
	dd if=/dev/zero bs=16k count=64 2>/dev/null |
	    jexec stcli nc -N -w 3 198.51.100.2 9
}

st_udp_burst()
{
	dd if=/dev/zero bs=512 count=64 2>/dev/null |
	    jexec stcli nc -u -w 1 ${1:-198.51.100.2} ${2:-9}
}

# st_topo_traffic max: the standard traffic loops over st_topo.
st_topo_traffic()
{
	st_traffic ping $1 st_ping
	st_traffic tcp $1 st_tcp 198.51.100.2 7
	st_traffic udp $1 st_udp 198.51.100.2 7
	st_traffic bulk $1 st_tcp_bulk
}

# st_traffic_ok: ICMP, TCP and UDP from stcli reach stsrv again.
st_traffic_ok()
{
	st_expect '' st_retry 5 jexec stcli ping -c 2 -t 5 198.51.100.2
	st_expect '^st$' st_retry 5 st_tcp 198.51.100.2 7
	st_expect '^st$' st_retry 5 st_udp 198.51.100.2 7
}

#
# reload
#

st_reload_rulesets()
{
	cat > rs.0 <<EOF
table <srv> persist { 198.51.100.2 }
match out on stbr0 inet from 192.0.2.0/24 nat-to (stbr0:0)
pass
pass in on ${C} inet proto tcp to 192.0.2.1 port 8007 rdr-to 198.51.100.2 port 7
pass in on ${C} inet proto udp to <srv> port 7 route-to 198.51.100.2
anchor "st/*"
EOF
	cat > rs.1 <<EOF
table <srv> persist { 198.51.100.2 }
pass
pass in on ${C} inet proto icmp to <srv> dnpipe 1
pass in on ${C} inet proto tcp to 192.0.2.1 port 8007 rdr-to 198.51.100.2 port 7
pass out on ${S} inet proto udp dnpipe (1, 2)
pass in on stbr0 inet proto tcp from <srv>
anchor "st/*"
anchor "inline" {
	pass in on ${C} inet proto tcp to port 7
	pass out on stbr0 inet
}
EOF
	cat > rs.2 <<EOF
table <srv> persist { 198.51.100.2 }
table <cli> { 192.0.2.0/24 }
match in on ${C} from <cli> tag CLI
pass
pass in on ${C} inet proto icmp to <srv> route-to 198.51.100.2 dnpipe 2
pass in on ${C} inet proto tcp to 192.0.2.1 port 8007 rdr-to 198.51.100.2 port 7
match out on stbr0 inet tagged CLI nat-to (stbr0:0)
pass out on stbr0 inet proto udp
anchor "st/*"
EOF
}

st_reload()
{
	jexec stfw pfctl -f ${PWD}/rs.$((st_i % 3))
	[ $((st_i % 7)) -ne 6 ] || jexec stfw pfctl -F all
}

st_reload_anchor()
{
	_a=st/a$((st_i % 3))
	case $((st_i % 4)) in
	0)	printf 'table <at> { 192.0.2.2 }\npass in on %s inet proto icmp\npass in from <at>\n' \
		    ${C} | jexec stfw pfctl -a ${_a} -f - ;;
	1)	jexec stfw pfctl -a ${_a} -F rules ;;
	2)	jexec stfw pfctl -a ${_a} -t at -T add 192.0.2.$((st_i % 200 + 10)) ;;
	3)	jexec stfw pfctl -a ${_a} -F all ;;
	esac
}

st_reload_reader()
{
	case $((st_i % 8)) in
	0)	jexec stfw pfctl -sr -v ;;
	1)	jexec stfw pfctl -ss -v ;;
	2)	jexec stfw pfctl -sA ;;
	3)	jexec stfw pfctl -a 'st/*' -sr ;;
	4)	jexec stfw pfctl -sT ;;
	5)	jexec stfw pfctl -vvsI ;;
	6)	jexec stfw pfctl -si -v ;;
	7)	jexec stfw dnctl pipe show ;;
	esac > /dev/null
}

atf_test_case "reload" "cleanup"
reload_head()
{
	atf_set descr 'Ruleset reloads (nat-to, rdr-to, route-to, dnpipe, anchors, tables) under ICMP, TCP and UDP traffic across epairs and a bridge'
	atf_set require.user root
	atf_set timeout 900
}

reload_body()
{
	st_init
	st_require_dummynet
	st_topo
	jexec stfw dnctl pipe 1 config delay 5
	jexec stfw dnctl pipe 2 config bw 20Mbit/s
	st_reload_rulesets
	for i in 0 1 2; do
		atf_check -s exit:0 -e ignore jexec stfw pfctl -nf ${PWD}/rs.${i}
	done
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.0

	n=$(st_n 40)
	st_topo_traffic $((n * 10))
	st_traffic rdr $((n * 10)) st_tcp 192.0.2.1 8007
	st_loop reload ${n} st_reload
	st_loop anchor ${n} st_reload_anchor
	st_loop reader $((n * 2)) st_reload_reader
	st_wait

	st_alive stfw
	st_answers stcli stsrv
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.0
	jexec stfw pfctl -Fs > /dev/null 2>&1
	st_traffic_ok
	st_expect '^st$' st_retry 5 st_tcp 192.0.2.1 8007
	st_finish
}

reload_cleanup()
{
	st_cleanup
}

#
# tables
#

st_tables_files()
{
	for f in 0 1; do
		{
			echo 198.51.100.2
			awk -v f=${f} 'BEGIN { for (i = 0; i < 1000; i++)
			    printf "10.%d.%d.%d\n", f, int(i / 250), i % 250 + 1 }'
		} > big.${f}
	done
	awk 'BEGIN { for (i = 0; i < 200; i++)
	    printf "172.16.%d.0/24\n", i }' > big.extra
}

st_tables_allow()
{
	case $((st_i % 6)) in
	0)	jexec stfw pfctl -t allow -T add 192.0.2.2 ;;
	1)	jexec stfw pfctl -t allow -T delete 192.0.2.2 ;;
	2)	jexec stfw pfctl -t allow -T add 192.0.2.0/24 ;;
	3)	jexec stfw pfctl -t allow -T replace 192.0.2.2 192.0.2.3 ;;
	4)	jexec stfw pfctl -t allow -T flush ;;
	5)	jexec stfw pfctl -t allow -T add 192.0.2.2 192.0.2.128/25 ;;
	esac
}

st_tables_big()
{
	case $((st_i % 6)) in
	0|3)	jexec stfw pfctl -t big -T replace -f ${PWD}/big.$((st_i % 2)) ;;
	1)	jexec stfw pfctl -t big -T add -f ${PWD}/big.extra ;;
	2)	jexec stfw pfctl -t big -T delete -f ${PWD}/big.extra ;;
	4)	jexec stfw pfctl -t big -T expire 1 ;;
	5)	jexec stfw pfctl -t big -T zero ;;
	esac
}

st_tables_anchor()
{
	_a=st/t$((st_i % 2))
	case $((st_i % 4)) in
	0)	jexec stfw pfctl -a ${_a} -t at -T add 10.$((st_i % 250)).0.0/16 ;;
	1)	printf 'table <at> persist { 192.0.2.2 }\npass in from <at> to <big>\n' |
		    jexec stfw pfctl -a ${_a} -f - ;;
	2)	jexec stfw pfctl -a ${_a} -t at -T kill ;;
	3)	jexec stfw pfctl -a ${_a} -F all ;;
	esac
}

st_tables_reader()
{
	case $((st_i % 6)) in
	0)	jexec stfw pfctl -sT ;;
	1)	jexec stfw pfctl -t big -T show ;;
	2)	jexec stfw pfctl -t allow -T test 192.0.2.2 ;;
	3)	jexec stfw pfctl -vvsT ;;
	4)	jexec stfw pfctl -a 'st/*' -sT ;;
	5)	jexec stfw pfctl -t big -T show -v ;;
	esac > /dev/null
}

atf_test_case "tables" "cleanup"
tables_head()
{
	atf_set descr 'Table add/delete/replace/expire/kill loops with matching traffic and -sT/-T show readers'
	atf_set require.user root
	atf_set timeout 900
}

tables_body()
{
	st_init
	st_topo
	st_tables_files
	pft_set_rules stfw \
	    "table <allow> persist" \
	    "table <big> persist" \
	    "block in on ${C}" \
	    "pass in on ${C} from <allow> to <big>" \
	    "pass in on ${C} from <allow> to 192.0.2.1" \
	    "anchor \"st/*\"" \
	    "pass out"
	jexec stfw pfctl -t allow -T add 192.0.2.2
	jexec stfw pfctl -t big -T replace -f ${PWD}/big.0
	st_traffic_ok

	n=$(st_n 60)
	st_topo_traffic $((n * 6))
	st_loop allow ${n} st_tables_allow
	st_loop big ${n} st_tables_big
	st_loop anchor ${n} st_tables_anchor
	st_loop reader1 ${n} st_tables_reader
	st_loop reader2 ${n} st_tables_reader
	st_wait

	st_alive stfw
	atf_check -s exit:0 -e ignore jexec stfw pfctl -t allow -T replace 192.0.2.2
	atf_check -s exit:0 -e ignore \
	    jexec stfw pfctl -t big -T replace -f ${PWD}/big.1
	atf_check -s exit:0 -o ignore -e match:'1/1 addresses match' \
	    jexec stfw pfctl -t big -T test 198.51.100.2
	jexec stfw pfctl -Fs > /dev/null 2>&1
	st_traffic_ok
	# The table decides: without the client, the rule blocks it.
	atf_check -s exit:0 -e ignore jexec stfw pfctl -t allow -T delete 192.0.2.2
	jexec stfw pfctl -Fs > /dev/null 2>&1
	atf_check -s exit:2 -o ignore jexec stcli ping -c 1 -t 3 198.51.100.2
	st_finish
}

tables_cleanup()
{
	st_cleanup
}

#
# ifchurn
#

st_ifchurn_rules()
{
	cat > rs.if <<EOF
table <dyn> persist
pass
pass in quick on stchurn inet proto icmp to (stc0) label stgrp
pass in on stchurn inet proto icmp
pass out on stm0 inet from (stm0) to (stm0:network)
pass in on stm1 inet from (stchurn:network)
pass on stchurn inet from (stc1:0) to any
block in quick on stc2 inet proto udp to port 9
pass in on egress inet proto icmp
pass in on ${C} inet proto icmp to (stbr0)
pass in on stlink inet proto tcp from (stlink:network) keep state (max 1000)
pass in on stc1 inet proto tcp from (stm1)
EOF
}

# In stfw: epairs created, renamed into the rule names, grouped, destroyed.
st_if_create()
{
	_n=$(jexec stfw ifconfig epair create) || return
	_x=stc$((st_i % 3))
	jexec stfw ifconfig ${_n} name ${_x} > /dev/null || _x=${_n}
	jexec stfw ifconfig ${_x} inet 10.20.$((st_i % 3)).1/24 up
	jexec stfw ifconfig ${_x} group stchurn
	jexec stfw ifconfig ${_x} inet 10.20.$((st_i % 3)).9/32 alias
	jexec stfw ifconfig ${_x} inet 10.20.$((st_i % 3)).9 -alias
	jexec stfw ifconfig ${_x} -group stchurn
	jexec stfw ifconfig ${_x} destroy
}

# In stfw: an interface named after the group the rules use.
st_if_groupname()
{
	_n=$(jexec stfw ifconfig epair create) || return
	_x=stchurn
	jexec stfw ifconfig ${_n} name ${_x} > /dev/null || _x=${_n}
	jexec stfw ifconfig ${_x} inet 10.22.0.1/24 up
	jexec stfw ifconfig ${_x} group stchurn
	jexec stfw ifconfig ${_x} group stlink
	jexec stfw ifconfig ${_x} name stg > /dev/null && _x=stg
	jexec stfw ifconfig ${_x} -group stchurn
	jexec stfw ifconfig ${_x} destroy
}

# In stfw: the link traffic uses changes name and groups under it.
st_if_stable()
{
	jexec stfw ifconfig ${C} group stchurn
	jexec stfw ifconfig ${C} group stlink
	if jexec stfw ifconfig ${C} name stlink > /dev/null; then
		sleep 0.2
		jexec stfw ifconfig stlink name ${C} > /dev/null
	fi
	jexec stfw ifconfig ${C} -group stchurn
	jexec stfw ifconfig ${C} -group stlink
	jexec stfw ifconfig stbr0 inet 198.51.100.$((st_i % 50 + 100))/32 alias
	jexec stfw ifconfig stbr0 inet 198.51.100.$((st_i % 50 + 100)) -alias
}

# From the host: epairs moved into stfw under rule names, then out, into
# stcli and back, with traffic over them while they are in stfw.
st_if_move()
{
	_n=$(ifconfig epair create) || return
	_net=10.30.$((st_i % 2))
	_x=stm$((st_i % 2))
	ifconfig ${_n%a}b inet ${_net}.2/24 up
	ifconfig ${_n} vnet stfw
	jexec stfw ifconfig ${_n} name ${_x} > /dev/null || _x=${_n}
	jexec stfw ifconfig ${_x} inet ${_net}.1/24 up
	jexec stfw ifconfig ${_x} group stchurn
	ping -c 3 -i 0.1 -t 2 ${_net}.1
	ifconfig ${_x} -vnet stfw
	ifconfig ${_x} vnet stcli
	ifconfig ${_x} -vnet stcli
	ifconfig ${_x} destroy || ifconfig -j stfw ${_x} destroy ||
	    ifconfig -j stcli ${_x} destroy
}

st_if_reload()
{
	jexec stfw pfctl -f ${PWD}/rs.if
	jexec stfw pfctl -sI -v > /dev/null
	sleep 0.3
}

atf_test_case "ifchurn" "cleanup"
ifchurn_head()
{
	atf_set descr 'Interface create/destroy, rename, groups (also named like interfaces), addresses and VNET moves under rules naming them, with traffic'
	atf_set require.user root
	atf_set timeout 900
}

ifchurn_body()
{
	st_init
	st_topo
	st_ifchurn_rules
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.if

	n=$(st_n 30)
	st_topo_traffic $((n * 10))
	st_loop create ${n} st_if_create
	st_loop groupname ${n} st_if_groupname
	st_loop stable ${n} st_if_stable
	st_loop move ${n} st_if_move
	st_loop reload ${n} st_if_reload
	st_wait

	st_alive stfw
	st_answers stcli
	# The link is back under its name; nothing the loops made is left.
	atf_check -s exit:0 -o ignore jexec stfw ifconfig ${C}
	atf_check -s exit:0 -o not-match:'(^| )(stc[0-9]|stm[0-9]|stchurn|stg|stlink)( |$)' \
	    jexec stfw ifconfig -l
	atf_check -s exit:0 -o not-match:'(^| )(stc[0-9]|stm[0-9]|stchurn|stg|stlink)( |$)' \
	    jexec stcli ifconfig -l
	jexec stfw pfctl -Fs > /dev/null 2>&1
	st_traffic_ok

	# A fresh interface under a churned name and group: pf matches it by
	# group and holds its address in (stc0).
	e=$(vnet_mkepair)
	atf_check -s exit:0 ifconfig ${e}b inet 10.40.0.2/24 up
	vnet_ifmove ${e}a stfw
	vnet_ifrename_jail stfw ${e}a stc0
	atf_check -s exit:0 jexec stfw ifconfig stc0 inet 10.40.0.1/24 up
	atf_check -s exit:0 jexec stfw ifconfig stc0 group stchurn
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.if
	st_expect '' st_retry 5 ping -c 2 -t 3 10.40.0.1
	atf_check -s exit:0 -o match:'^stgrp [0-9]+ [1-9]' jexec stfw pfctl -sl
	st_finish
}

ifchurn_cleanup()
{
	st_cleanup
}

#
# jailchurn
#

# st_jail_cycle tag net: a VNET jail with pf, rules, states, pfsync, pflog
# and pflow interfaces, destroyed while the host still sends to it.
st_jail_cycle()
{
	_j=stj$1${st_i}
	_net=$2
	_e=$(ifconfig epair create) || return
	jail -c name=${_j} vnet persist vnet.interface=${_e%a}b || {
		ifconfig ${_e} destroy
		return
	}
	ifconfig ${_e} inet ${_net}.1/24 up
	jexec ${_j} ifconfig lo0 127.0.0.1/8 up
	jexec ${_j} ifconfig ${_e%a}b inet ${_net}.2/24 up
	jexec ${_j} ifconfig pflog0 create up
	jexec ${_j} ifconfig pfsync0 create
	jexec ${_j} ifconfig pfsync0 syncdev ${_e%a}b maxupd 1 defer up
	jexec ${_j} ifconfig pflow0 create
	jexec ${_j} ifconfig pflow0 flowsrc ${_net}.2 flowdst ${_net}.1:9995 up
	printf '%s\n' \
	    "set state-defaults pflow" \
	    "table <peers> persist { ${_net}.1 }" \
	    "pass log (to pflog0)" \
	    "pass in log (to pflog0) inet proto icmp from <peers>" \
	    "match out on ${_e%a}b inet from 127.0.0.1 nat-to (${_e%a}b:0)" \
	    "anchor \"st/*\"" | jexec ${_j} pfctl -f -
	jexec ${_j} pfctl -e
	if command -v tcpdump > /dev/null; then
		jexec ${_j} daemon -f tcpdump -n -i pflog0 -w /dev/null
	fi
	ping -c 5 -i 0.1 -t 3 ${_net}.2
	echo st | jexec ${_j} nc -w 1 ${_net}.1 9
	jexec ${_j} ping -c 2 -i 0.2 -t 2 ${_net}.1
	# Still sending when the jail goes.
	ping -c 100 -i 0.01 -t 4 ${_net}.2 > /dev/null 2>&1 &
	sleep 0.3
	jail -r ${_j}
	ifconfig ${_e} destroy
	wait
}

st_jail_reader()
{
	pfctl -si > /dev/null
	ifconfig -l > /dev/null
	jls -d > /dev/null
	for _j in $(jls name | grep '^stj'); do
		jexec ${_j} pfctl -ss
		jexec ${_j} ifconfig pfsync0
	done > /dev/null 2>&1
	sleep 0.5
}

atf_test_case "jailchurn" "cleanup"
jailchurn_head()
{
	atf_set descr 'VNET jails with pf, states, pfsync, pflog and pflow interfaces created and destroyed in parallel under traffic'
	atf_set require.user root
	atf_set timeout 900
}

jailchurn_body()
{
	st_init
	for _c in pflog pfsync pflow; do
		integ_has_cloner ${_c} || atf_skip "ifconfig -C does not list ${_c}"
	done

	n=$(st_n 10)
	st_loop cycleA ${n} st_jail_cycle a 10.50.0
	st_loop cycleB ${n} st_jail_cycle b 10.51.0
	st_loop cycleC ${n} st_jail_cycle c 10.52.0
	st_loop reader $((n * 6)) st_jail_reader
	st_wait
	st_alive

	# The same setup still works: states, logging, a pfsync interface.
	e=$(vnet_mkepair)
	vnet_mkjail stjv ${e}b
	atf_check -s exit:0 ifconfig ${e}a inet 10.53.0.1/24 up
	jexec stjv ifconfig ${e}b inet 10.53.0.2/24 up
	atf_check -s exit:0 -o ignore jexec stjv ifconfig pflog0 create up
	atf_check -s exit:0 -o ignore jexec stjv ifconfig pfsync0 create
	atf_check -s exit:0 jexec stjv ifconfig pfsync0 syncdev ${e}b up
	pft_set_rules stjv "pass log (to pflog0)"
	jexec stjv pfctl -e > /dev/null 2>&1
	st_alive stjv
	st_expect '' st_retry 5 ping -c 2 -t 3 10.53.0.2
	atf_check -s exit:0 -o match:'10\.53\.0\.1' jexec stjv pfctl -ss
	st_finish
}

jailchurn_cleanup()
{
	st_cleanup
}

#
# states
#

st_conn_nat()
{
	echo st | jexec stcli nc -N -w 2 198.51.100.2 7
}

st_conn_rdr()
{
	echo st | jexec stcli nc -N -w 2 192.0.2.1 8007
}

st_conn_div()
{
	jexec stcli nc -N -w 2 192.0.2.1 7100 < /dev/null
}

st_conn_udp()
{
	echo st | jexec stcli nc -u -w 1 198.51.100.2 7
}

st_states_kill()
{
	case $((st_i % 8)) in
	0)	jexec stfw pfctl -k 192.0.2.2 ;;
	1)	jexec stfw pfctl -k 192.0.2.0/24 -k 198.51.100.2 ;;
	2)	jexec stfw pfctl -k label rdr ;;
	3)	jexec stfw pfctl -K 192.0.2.2 ;;
	4)	jexec stfw pfctl -F states ;;
	5)	jexec stfw pfctl -F Sources ;;
	6)	jexec stfw pfctl -t bad -T flush ;;
	7)	jexec stfw pfctl -k label div ;;
	esac
	sleep 0.3
}

st_states_reader()
{
	case $((st_i % 4)) in
	0)	jexec stfw pfctl -ss -v ;;
	1)	jexec stfw pfctl -s Sources ;;
	2)	jexec stfw pfctl -si ;;
	3)	jexec stfw pfctl -t bad -T show ;;
	esac > /dev/null
	sleep 0.2
}

atf_test_case "states" "cleanup"
states_head()
{
	atf_set descr 'Short TCP/UDP connections through nat-to, rdr-to and divert-to while states and source nodes are killed, flushed, overloaded and purged'
	atf_set require.user root
	atf_set timeout 900
}

states_body()
{
	st_init
	st_topo
	pft_set_rules stfw \
	    "set timeout interval 2" \
	    "set timeout { tcp.first 5, tcp.closing 2, tcp.finwait 2, tcp.closed 2, udp.first 5, udp.multiple 5 }" \
	    "table <bad> persist" \
	    "match out on stbr0 inet from 192.0.2.0/24 nat-to (stbr0:0)" \
	    "pass" \
	    "pass in on ${C} inet proto tcp to 192.0.2.1 port 8007 rdr-to 198.51.100.2 port 7 keep state (max-src-conn 1000, max-src-conn-rate 40/5, overload <bad> flush global) label rdr" \
	    "pass in on ${C} inet proto tcp to 192.0.2.1 port 7100 divert-to 127.0.0.1 port 7100 label div"
	jexec stfw ${SOCKHELPER} -T 900 tcp-serve -n 1000000 127.0.0.1 7100 \
	    > div.out 2>&1 &
	st_wait_ready div.out
	st_expect '^st$' st_retry 5 st_conn_rdr
	st_expect '^hello from server$' st_retry 5 st_conn_div

	n=$(st_n 100)
	st_loop nat ${n} st_conn_nat
	st_loop rdr ${n} st_conn_rdr
	st_loop div ${n} st_conn_div
	st_loop udp ${n} st_conn_udp
	st_loop kill ${n} st_states_kill
	st_loop reader ${n} st_states_reader
	st_traffic ping $((n * 4)) st_ping
	st_wait

	st_alive stfw
	# Let the overload rate window pass before checking again.
	sleep 6
	jexec stfw pfctl -t bad -T flush > /dev/null 2>&1
	jexec stfw pfctl -F states > /dev/null 2>&1
	jexec stfw pfctl -F Sources > /dev/null 2>&1
	st_traffic_ok
	st_expect '^st$' st_retry 5 st_conn_rdr
	st_expect '^hello from server$' st_retry 5 st_conn_div
	# The purge empties the state table once the traffic stopped.
	_i=0
	while [ "$(jexec stfw pfctl -ss | wc -l)" -gt 0 ] && [ ${_i} -lt 60 ]; do
		sleep 1
		_i=$((_i + 1))
	done
	atf_check -s exit:0 -o empty jexec stfw pfctl -ss
	st_finish
}

states_cleanup()
{
	st_cleanup
}

#
# pfsync
#

st_sync_conn()
{
	echo st | nc -N -w 2 198.51.100.1 7
	ping -c 1 -t 2 198.51.100.1
}

st_sync_ping()
{
	jexec stone ping -c 2 -i 0.2 -t 2 -S 198.51.100.1 198.51.100.254
}

st_sync_kill()
{
	case $((st_i % 5)) in
	0)	jexec stone pfctl -F states ;;
	1)	jexec stone pfctl -k 198.51.100.254 ;;
	2)	jexec sttwo pfctl -F states ;;
	3)	jexec sttwo pfctl -ss -vv ;;
	4)	jexec stone pfctl -k 0.0.0.0/0 ;;
	esac > /dev/null
	sleep 0.5
}

# st_sync_new: replace the sync epair (stsync in both jails).
st_sync_new()
{
	_e=$(ifconfig epair create) || return
	ifconfig ${_e} vnet stone
	ifconfig ${_e%a}b vnet sttwo
	jexec stone ifconfig ${_e} name stsync > /dev/null
	jexec sttwo ifconfig ${_e%a}b name stsync > /dev/null
	jexec stone ifconfig stsync inet 192.0.2.1/24 up
	jexec sttwo ifconfig stsync inet 192.0.2.2/24 up
}

st_sync_churn()
{
	case $((st_i % 4)) in
	0)	# The syncdev goes away under pfsync, in both jails.
		jexec sttwo ifconfig stsync destroy || return
		st_sync_new
		jexec stone ifconfig pfsync0 syncdev stsync up
		jexec sttwo ifconfig pfsync0 syncdev stsync up
		;;
	1)	jexec stone ifconfig pfsync0 -syncdev
		sleep 0.5
		jexec stone ifconfig pfsync0 syncdev stsync up
		;;
	2)	# Destroyed while pfsync is down; the new interface may get
		# the old index.
		jexec sttwo ifconfig pfsync0 down
		jexec stone ifconfig stsync destroy || return
		st_sync_new
		jexec sttwo ifconfig pfsync0 syncdev stsync up
		;;
	3)	jexec sttwo ifconfig pfsync0 destroy
		jexec sttwo ifconfig pfsync0 create
		jexec sttwo ifconfig pfsync0 syncdev stsync maxupd 1 up
		;;
	esac
	sleep 1
}

atf_test_case "pfsync" "cleanup"
pfsync_head()
{
	atf_set descr 'A pfsync pair under state churn while the syncdev and pfsync0 are destroyed and recreated, then the jails are removed under traffic'
	atf_set require.user root
	atf_set timeout 900
}

pfsync_body()
{
	st_init
	integ_has_cloner pfsync || atf_skip "ifconfig -C does not list pfsync"
	integ_require_prog inetd
	sy=$(vnet_mkepair)
	o=$(vnet_mkepair)
	vnet_mkjail stone ${o}a ${sy}a
	vnet_mkjail sttwo ${sy}b
	vnet_ifrename_jail stone ${sy}a stsync
	vnet_ifrename_jail sttwo ${sy}b stsync
	jexec stone ifconfig stsync inet 192.0.2.1/24 up
	jexec sttwo ifconfig stsync inet 192.0.2.2/24 up
	jexec stone ifconfig lo0 127.0.0.1/8 up
	jexec stone ifconfig ${o}a inet 198.51.100.1/24 up
	ifconfig ${o}b inet 198.51.100.254/24 up
	pfsynct_mkif stone
	pfsynct_mkif sttwo
	jexec stone ifconfig pfsync0 syncdev stsync maxupd 1 defer up
	jexec sttwo ifconfig pfsync0 syncdev stsync maxupd 1 up
	for j in stone sttwo; do
		pft_set_rules ${j} "set skip on stsync" "pass"
		jexec ${j} pfctl -e > /dev/null 2>&1
	done
	cat > st-inetd.conf <<EOF
echo	stream	tcp	nowait	root	internal
EOF
	jexec stone inetd -p ${PWD}/inetd-stone.pid ${PWD}/st-inetd.conf
	st_expect '' st_retry 5 st_sync_ping

	n=$(st_n 80)
	st_loop conn ${n} st_sync_conn
	st_loop ping ${n} st_sync_ping
	st_loop kill ${n} st_sync_kill
	st_loop churn $(st_n 16) st_sync_churn
	st_wait
	st_alive stone sttwo

	# Synchronisation works again: a new state on stone shows up on sttwo.
	atf_check -s exit:0 jexec stone ifconfig pfsync0 syncdev stsync up
	atf_check -s exit:0 jexec sttwo ifconfig pfsync0 syncdev stsync up
	jexec stone pfctl -F states > /dev/null 2>&1
	jexec sttwo pfctl -F states > /dev/null 2>&1
	st_expect '' st_retry 5 st_sync_ping
	_i=0
	while ! jexec sttwo pfctl -ss | grep icmp | grep -q 198.51.100.254; do
		_i=$((_i + 1))
		[ ${_i} -lt 15 ] || atf_fail "state not synchronised to sttwo"
		sleep 1
		st_sync_ping > /dev/null 2>&1
	done
	st_expect '^st$' st_retry 5 sh -c \
	    'echo st | nc -N -w 2 198.51.100.1 7'

	# The jails go while the states keep coming.
	st_traffic conn $(st_n 200) st_sync_conn
	st_traffic ping $(st_n 200) st_sync_ping
	sleep 2
	st_jail_remove sttwo
	sleep 1
	st_jail_remove stone
	st_stop
	st_reap stsync
	st_reap ${o}a
	st_finish
}

pfsync_cleanup()
{
	st_cleanup
}

#
# divert
#

st_divert_rules()
{
	cat > rs.div <<EOF
pass
pass in on ${C} inet proto udp to 192.0.2.1 port 9998 divert-packet port 700
pass in on ${C} inet proto icmp to 192.0.2.1 divert-packet port 701
pass in on ${C} inet proto tcp to 198.51.100.2 port 7 divert-packet port 702
pass out on stbr0 inet proto udp to 198.51.100.2 port 7 divert-packet port 703
EOF
	echo pass > rs.nodiv
}

st_divert_churn()
{
	jexec stfw ${SOCKHELPER} -T 300 divert-churn inet $1 $2
}

st_divert_reload()
{
	if [ $((st_i % 2)) -eq 0 ]; then
		jexec stfw pfctl -f ${PWD}/rs.div
	else
		jexec stfw pfctl -f ${PWD}/rs.nodiv
	fi
	[ $((st_i % 5)) -ne 4 ] || jexec stfw pfctl -F states
	sleep 0.5
}

atf_test_case "divert" "cleanup"
divert_head()
{
	atf_set descr 'divert(4) sockets opened, bound and closed in loops, with packets queued, while divert-packet rules send traffic to them'
	atf_set require.user root
	atf_set timeout 900
}

divert_body()
{
	st_init
	st_topo
	st_divert_rules
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.div

	n=$(st_n 100)
	st_loop churn700a 3 st_divert_churn 700 ${n}
	st_loop churn700b 3 st_divert_churn 700 ${n}
	st_loop churn701 3 st_divert_churn 701 ${n}
	st_loop churn702 3 st_divert_churn 702 ${n}
	st_loop churn703 3 st_divert_churn 703 ${n}
	st_loop open ${n} jexec stfw ${SOCKHELPER} divert-open inet
	st_loop reload $((n / 2)) st_divert_reload
	st_topo_traffic $((n * 4))
	st_traffic udp9998 $((n * 4)) st_udp_burst 192.0.2.1 9998
	st_traffic ping1 $((n * 4)) st_ping 192.0.2.1
	st_wait

	st_alive stfw
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.nodiv
	jexec stfw pfctl -Fs > /dev/null 2>&1
	st_traffic_ok

	# A divert socket still gets and reinjects a packet.
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.div
	: > recv.out
	jexec stfw nc -u -l 192.0.2.1 9998 > recv.out 2> /dev/null &
	st_wait_listen stfw udp 9998
	jexec stfw ${SOCKHELPER} divert inet 700 reinject > div.out 2>&1 &
	p=$!
	st_wait_ready div.out
	echo payload | jexec stcli nc -u -w 1 192.0.2.1 9998
	wait ${p}
	atf_check -s exit:0 -o match:'^reinjected=ok$' \
	    -o match:'proto=17 src=192\.0\.2\.2 dst=192\.0\.2\.1 dport=9998 ' \
	    cat div.out
	sleep 1
	atf_check -s exit:0 -o inline:'payload\n' cat recv.out
	pkill -j stfw -x nc
	st_finish
}

divert_cleanup()
{
	st_cleanup
}

#
# dummynet
#

st_dn_rules()
{
	cat > rs.dn.0 <<EOF
pass
pass in on ${C} inet proto icmp to 198.51.100.2 route-to 198.51.100.2 dnpipe 1
pass in on ${C} inet proto udp to 198.51.100.2 route-to 198.51.100.2 dnpipe (1, 2)
pass in on ${C} inet proto tcp to 198.51.100.2 dnpipe 2
EOF
	cat > rs.dn.1 <<EOF
pass
pass in on ${C} inet proto icmp to 198.51.100.2 route-to 198.51.100.2 dnpipe (2, 1)
pass in on ${C} inet proto udp to 198.51.100.2 dnpipe 3
pass out on stbr0 inet proto tcp to 198.51.100.2 dnpipe 1
EOF
}

st_dn_reconf()
{
	case $((st_i % 7)) in
	0)	jexec stfw dnctl pipe 1 config delay 50 ;;
	1)	jexec stfw dnctl pipe 1 config bw 1Mbit/s queue 20 ;;
	2)	jexec stfw dnctl pipe 1 delete ;;
	3)	jexec stfw dnctl pipe 1 config delay 0 ;;
	4)	jexec stfw dnctl pipe 2 config bw 500Kbit/s delay 20 plr 0.05 ;;
	5)	jexec stfw dnctl pipe 2 delete
		jexec stfw dnctl pipe 2 config bw 10Mbit/s ;;
	6)	jexec stfw dnctl -f pipe flush
		jexec stfw dnctl pipe 1 config delay 10
		jexec stfw dnctl pipe 2 config ;;
	esac
	sleep 0.2
}

st_dn_reload()
{
	jexec stfw pfctl -f ${PWD}/rs.dn.$((st_i % 2))
	jexec stfw dnctl pipe show > /dev/null
	sleep 0.5
}

# st_dn_jail: a VNET jail with packets held in its dummynet pipes (both
# directions) when it is removed.
st_dn_jail()
{
	_j=stdq${st_i}
	_e=$(ifconfig epair create) || return
	jail -c name=${_j} vnet persist vnet.interface=${_e%a}b || {
		ifconfig ${_e} destroy
		return
	}
	ifconfig ${_e} inet 10.77.0.1/24 up
	jexec ${_j} ifconfig lo0 127.0.0.1/8 up
	jexec ${_j} ifconfig ${_e%a}b inet 10.77.0.2/24 up
	jexec ${_j} dnctl pipe 1 config delay 2000 bw 1Mbit/s
	jexec ${_j} dnctl pipe 2 config delay 1500
	printf '%s\n' "pass" \
	    "pass out on ${_e%a}b inet route-to 10.77.0.1 dnpipe 1" \
	    "pass in on ${_e%a}b inet dnpipe 2" | jexec ${_j} pfctl -f -
	jexec ${_j} pfctl -e
	ping -c 30 -i 0.02 -t 1 10.77.0.2 > /dev/null 2>&1 &
	dd if=/dev/zero bs=512 count=64 2>/dev/null |
	    jexec ${_j} nc -u -w 1 10.77.0.1 9
	jexec ${_j} ping -c 20 -i 0.02 -t 1 10.77.0.1
	jail -r ${_j}
	ifconfig ${_e} destroy
	wait
}

atf_test_case "dummynet" "cleanup"
dummynet_head()
{
	atf_set descr 'dnctl pipe reconfigure/delete/flush under route-to + dnpipe traffic, and VNET jails removed with packets queued in dummynet'
	atf_set require.user root
	atf_set timeout 900
}

dummynet_body()
{
	st_init
	st_require_dummynet
	st_topo
	st_dn_rules
	jexec stfw dnctl pipe 1 config delay 10
	jexec stfw dnctl pipe 2 config
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.dn.0
	st_traffic_ok

	n=$(st_n 60)
	st_loop reconf ${n} st_dn_reconf
	st_loop reload $((n / 2)) st_dn_reload
	st_loop jails $(st_n 8) st_dn_jail
	st_topo_traffic $((n * 4))
	st_traffic burst $((n * 4)) st_udp_burst
	st_traffic flood $((n * 4)) jexec stcli ping -c 20 -i 0.05 -t 2 198.51.100.2
	st_wait

	st_alive stfw
	atf_check -s exit:0 -o ignore jexec stfw dnctl -f pipe flush
	atf_check -s exit:0 -o ignore jexec stfw dnctl pipe 1 config delay 10
	atf_check -s exit:0 -o ignore jexec stfw dnctl pipe 2 config
	atf_check -s exit:0 -e ignore jexec stfw pfctl -f ${PWD}/rs.dn.0
	jexec stfw pfctl -Fs > /dev/null 2>&1
	st_traffic_ok
	atf_check -s exit:0 -o match:'^0*1[: ]' jexec stfw dnctl pipe show

	# stfw itself goes with packets in its pipes.
	jexec stfw dnctl pipe 1 config delay 2000
	jexec stcli ping -c 10 -i 0.05 -t 1 198.51.100.2 > /dev/null 2>&1
	st_finish
}

dummynet_cleanup()
{
	st_cleanup
}

#
# sendfile
#

# st_sf_link a b net: a fresh epair between jails a and b, named ${a}0 and
# ${b}0, without checksum offload and unmapped mbuf support.
st_sf_link()
{
	_e=$(ifconfig epair create) || return 1
	ifconfig ${_e} -txcsum -txcsum6 -mextpg
	ifconfig ${_e%a}b -txcsum -txcsum6 -mextpg
	ifconfig ${_e} vnet $1
	ifconfig ${_e%a}b vnet $2
	jexec $1 ifconfig ${_e} name ${1}0 > /dev/null
	jexec $2 ifconfig ${_e%a}b name ${2}0 > /dev/null
	jexec $1 ifconfig ${1}0 inet $3.1/24 up
	jexec $2 ifconfig ${2}0 inet $3.2/24 up
}

# st_sf_cycle a b net: sendfile from a to b through a's route-to rule,
# with the link destroyed mid-transfer from either side.
st_sf_cycle()
{
	if ! st_sf_link $1 $2 $3; then
		return
	fi
	jexec $2 timeout 20 nc -d -l 2345 > /dev/null &
	_nc=$!
	sleep 0.5
	jexec $1 timeout 12 ${SFHELPER} -c $3.2 -p 2345 ${PWD}/sf.big 0 0 0 &
	_sf=$!
	sleep $((st_i % 3)).$((st_i % 7))
	if [ $((st_i % 2)) -eq 0 ]; then
		jexec $1 ifconfig ${1}0 destroy
	else
		jexec $2 ifconfig ${2}0 destroy
	fi
	wait ${_sf}
	pkill -j $2 -x nc
	wait ${_nc}
	# If the destroy failed the link is still there.
	jexec $1 ifconfig ${1}0 destroy 2> /dev/null
}

# st_sf_verify a b net: a complete transfer arrives intact.
st_sf_verify()
{
	st_sf_link $1 $2 $3 || atf_fail "cannot link $1 and $2"
	jexec $2 timeout 60 nc -d -l 2345 > sf.out.$1 &
	_nc=$!
	sleep 1
	atf_check -s exit:0 -o ignore \
	    jexec $1 timeout 60 ${SFHELPER} -c $3.2 -p 2345 ${PWD}/sf.small 0 0 0
	wait ${_nc}
	atf_check_equal "$(sha256 -q sf.small)" "$(sha256 -q sf.out.$1)"
	jexec $1 ifconfig ${1}0 destroy
}

atf_test_case "sendfile" "cleanup"
sendfile_head()
{
	atf_set descr 'sendfile(2) through route-to and route-to + dnpipe, with the interface destroyed mid-transfer'
	atf_set require.user root
	atf_set timeout 900
}

sendfile_body()
{
	st_init
	st_require_dummynet
	[ -x ${SFHELPER} ] || atf_skip "sendfile_helper is not installed"
	integ_require_prog timeout sha256
	dd if=/dev/zero of=sf.big bs=1m count=48 2>/dev/null
	dd if=/dev/random of=sf.small bs=64k count=4 2>/dev/null

	# stsa -> stsb: route-to.  stda -> stdb: route-to and dnpipe, and a
	# pipe on the receiver too.
	vnet_mkjail stsa
	vnet_mkjail stsb
	vnet_mkjail stda
	vnet_mkjail stdb
	jexec stda dnctl pipe 1 config bw 20Mbit/s queue 100
	jexec stdb dnctl pipe 1 config delay 20
	pft_set_rules stsa "pass" \
	    "pass out on stsa0 inet proto tcp route-to 10.66.0.2"
	pft_set_rules stsb "pass"
	pft_set_rules stda "pass" \
	    "pass out on stda0 inet proto tcp route-to 10.67.0.2 dnpipe 1"
	pft_set_rules stdb "pass" "pass in on stdb0 inet proto tcp dnpipe 1"
	for j in stsa stsb stda stdb; do
		jexec ${j} pfctl -e > /dev/null 2>&1
	done
	st_sf_verify stsa stsb 10.66.0
	st_sf_verify stda stdb 10.67.0

	n=$(st_n 8)
	st_loop routeto ${n} st_sf_cycle stsa stsb 10.66.0
	st_loop dnpipe ${n} st_sf_cycle stda stdb 10.67.0
	st_wait

	st_alive stsa stsb stda stdb
	st_sf_verify stsa stsb 10.66.0
	st_sf_verify stda stdb 10.67.0
	st_finish
}

sendfile_cleanup()
{
	st_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "reload"
	atf_add_test_case "tables"
	atf_add_test_case "ifchurn"
	atf_add_test_case "jailchurn"
	atf_add_test_case "states"
	atf_add_test_case "pfsync"
	atf_add_test_case "divert"
	atf_add_test_case "dummynet"
	atf_add_test_case "sendfile"
}

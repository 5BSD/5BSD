#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# 5BSD pf extension: "jail <name|jid>" matches the jail of the local
# socket of a TCP or UDP packet, also for jails that share the host's
# addresses.

ADDR=198.51.100.1

jail_init()
{
	kldstat -q -m pf || atf_skip "pf is not loaded"
	ifconfig lo1 create >/dev/null 2>&1 || true
	ifconfig lo1 inet ${ADDR}/32 alias up
	echo lo1 > created_lo
}

jail_cleanup()
{
	pkill -f "nc -l ${ADDR}" >/dev/null 2>&1
	for j in pfjw pfjd pfjo; do
		jail -r $j >/dev/null 2>&1
	done
	pfctl -a regress -Fr >/dev/null 2>&1
	pfctl -Fr >/dev/null 2>&1
	pfctl -f /etc/pf.conf >/dev/null 2>&1
	[ -f created_lo ] && ifconfig lo1 destroy >/dev/null 2>&1
	true
}

# listen <jail> <port>: start a TCP listener in a jail.
listen()
{
	jexec $1 nc -l -k ${ADDR} $2 >/dev/null 2>&1 &
	i=0
	until sockstat -4 -l -p $2 | grep -q nc; do
		i=$((i + 1))
		[ $i -lt 50 ] || atf_fail "no listener on port $2 in $1"
		sleep 0.1
	done
}

load()
{
	printf '%s\n' "$@" | pfctl -f - ||
	    atf_fail "ruleset did not load: $*"
	pfctl -e >/dev/null 2>&1 || true
}

atf_test_case "shared_ip" "cleanup"
shared_ip_head()
{
	atf_set descr 'Jails sharing the same addresses get different policies'
	atf_set require.user root
}
shared_ip_body()
{
	jail_init
	jail -c name=pfjw persist ip4=inherit ip6=inherit
	jail -c name=pfjd persist ip4=inherit ip6=inherit
	jw=$(jls -j pfjw jid)
	jd=$(jls -j pfjd jid)

	listen pfjw 8001
	listen pfjd 8002

	# Inbound: the listening socket's jail decides.
	load "pass all" \
	    "block in quick proto tcp to ${ADDR} jail pfjd" \
	    "pass in quick proto tcp to ${ADDR} jail pfjw"
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8001
	atf_check -s not-exit:0 -e ignore nc -z -w 2 ${ADDR} 8002

	# The rules print with the jail names; numbers work as well.
	atf_check -s exit:0 -o match:'jail = pfjd' -o match:'jail = pfjw' \
	    pfctl -sr
	load "pass all" "block in quick proto tcp to ${ADDR} jail ${jw}"
	atf_check -s not-exit:0 -e ignore nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8002
	load "pass all" "block in quick proto tcp to ${ADDR} jail != ${jw}"
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8001
	atf_check -s not-exit:0 -e ignore nc -z -w 2 ${ADDR} 8002

	# Outbound: the connecting socket's jail decides.
	load "pass all" "block out quick proto tcp to ${ADDR} jail pfjd"
	atf_check -s exit:0 -e ignore jexec pfjw nc -z -w 2 ${ADDR} 8002
	atf_check -s not-exit:0 -e ignore jexec pfjd nc -z -w 2 ${ADDR} 8001
	# jail 0 is the host.
	load "pass all" "block out quick proto tcp to ${ADDR} jail 0"
	atf_check -s not-exit:0 -e ignore nc -z -w 2 ${ADDR} 8001
	atf_check -s exit:0 -e ignore jexec pfjd nc -z -w 2 ${ADDR} 8001
	# A list expands to one rule per jail.
	load "pass all" "block out quick proto tcp to ${ADDR} jail { pfjw pfjd }"
	atf_check -s exit:0 -o match:'jail = pfjw' -o match:'jail = pfjd' \
	    pfctl -sr
	atf_check -s not-exit:0 -e ignore jexec pfjw nc -z -w 2 ${ADDR} 8002
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8002
}
shared_ip_cleanup()
{
	jail_cleanup
}

atf_test_case "nested" "cleanup"
nested_head()
{
	atf_set descr 'A rule for a nested jail matches only that jail'
	atf_set require.user root
}
nested_body()
{
	jail_init
	jail -c name=pfjo persist children.max=2 ip4=inherit ip6=inherit
	jexec pfjo jail -c name=inner persist ip4=inherit ip6=inherit
	listen pfjo 8003

	load "pass all" "block out quick proto tcp to ${ADDR} jail pfjo.inner"
	atf_check -s exit:0 -o match:'jail = pfjo.inner' pfctl -sr
	atf_check -s not-exit:0 -e ignore jexec pfjo.inner nc -z -w 2 ${ADDR} 8003
	atf_check -s exit:0 -e ignore jexec pfjo nc -z -w 2 ${ADDR} 8003
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8003
}
nested_cleanup()
{
	jexec pfjo jail -r inner >/dev/null 2>&1
	jail_cleanup
}

# wait_match <port> <0|1>: wait until a connection to <port> from the
# host is blocked (0) or passes (1); jail events re-resolve rules from a
# task, so allow a moment.
wait_match()
{
	i=0
	while :; do
		if nc -z -w 1 ${ADDR} $1 >/dev/null 2>&1; then r=1; else r=0; fi
		[ $r = $2 ] && return 0
		i=$((i + 1))
		[ $i -lt 30 ] || atf_fail "port $1: expected $2"
		sleep 0.2
	done
}

atf_test_case "removal" "cleanup"
removal_head()
{
	atf_set descr 'A rule naming a jail follows the jail across removal and re-creation'
	atf_set require.user root
}
removal_body()
{
	jail_init
	jail -c name=pfjd persist ip4=inherit ip6=inherit
	jd=$(jls -j pfjd jid)
	jail -c name=pfjw persist ip4=inherit ip6=inherit
	listen pfjw 8004
	listen pfjd 8005

	load "pass all" "block in quick proto tcp to ${ADDR} jail pfjd" \
	    "pass out proto tcp jail pfjd keep state"
	wait_match 8005 0
	# A connection with state from the jail, then remove the jail.
	(sleep 5 | jexec pfjd nc ${ADDR} 8004 >/dev/null 2>&1 &)
	sleep 0.5
	atf_check -s exit:0 jail -r pfjd

	# The rule keeps the name.
	atf_check -s exit:0 -o match:"jail = pfjd" pfctl -sr
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8004

	# Recreated with a new jail id: the rule applies again, no reload.
	jail -c name=pfjd persist ip4=inherit ip6=inherit
	[ "$(jls -j pfjd jid)" != "${jd}" ] || atf_fail "same jail id"
	listen pfjd 8006
	wait_match 8006 0
	atf_check -s exit:0 -o match:"jail = pfjd" pfctl -sr
	pfctl -F states >/dev/null 2>&1
}
removal_cleanup()
{
	jail_cleanup
}

atf_test_case "before_jail" "cleanup"
before_jail_head()
{
	atf_set descr 'A rule loaded before its jail exists applies once the jail appears'
	atf_set require.user root
}
before_jail_body()
{
	jail_init
	jail -r pfjd >/dev/null 2>&1
	load "pass all" "block in quick proto tcp to ${ADDR} jail pfjd"
	atf_check -s exit:0 -o match:"jail = pfjd" pfctl -sr
	jail -c name=pfjd persist ip4=inherit ip6=inherit
	listen pfjd 8007
	wait_match 8007 0
	# A numeric jail id stays literal.
	load "pass all" "block in quick proto tcp to ${ADDR} jail 999999"
	atf_check -s exit:0 -o match:"jail = 999999" pfctl -sr
	wait_match 8007 1
}
before_jail_cleanup()
{
	jail_cleanup
}

atf_test_case "nested_recreate" "cleanup"
nested_recreate_head()
{
	atf_set descr 'A rule naming a nested jail follows its re-creation'
	atf_set require.user root
}
nested_recreate_body()
{
	jail_init
	jail -c name=pfjo persist children.max=2 ip4=inherit ip6=inherit
	listen pfjo 8008
	load "pass all" "block out quick proto tcp to ${ADDR} jail pfjo.inner"
	n=0
	while [ $n -lt 3 ]; do
		jexec pfjo jail -c name=inner persist ip4=inherit ip6=inherit
		i=0
		until ! jexec pfjo.inner nc -z -w 1 ${ADDR} 8008 >/dev/null 2>&1; do
			i=$((i + 1)); [ $i -lt 30 ] || atf_fail "inner not blocked"
			sleep 0.2
		done
		atf_check -s exit:0 -e ignore jexec pfjo nc -z -w 2 ${ADDR} 8008
		jexec pfjo jail -r inner
		n=$((n + 1))
	done
}
nested_recreate_cleanup()
{
	jexec pfjo jail -r inner >/dev/null 2>&1
	jail_cleanup
}

atf_test_case "churn" "cleanup"
churn_head()
{
	atf_set descr 'Many jail create/destroy cycles re-resolve the rule each time'
	atf_set require.user root
	atf_set timeout 600
}
churn_body()
{
	jail_init
	load "pass all" "block in quick proto tcp to ${ADDR} jail pfjc"
	n=0
	while [ $n -lt 40 ]; do
		jail -c name=pfjc persist ip4=inherit ip6=inherit
		listen pfjc $((9000 + n))
		wait_match $((9000 + n)) 0
		pkill -f "nc -l -k ${ADDR} $((9000 + n))"
		jail -r pfjc
		n=$((n + 1))
	done
	atf_check -s exit:0 -o not-match:'lock order reversal|non-sleepable' dmesg
}
churn_cleanup()
{
	jail -r pfjc >/dev/null 2>&1
	jail_cleanup
}

atf_test_case "only_tcp_udp" "cleanup"
only_tcp_udp_head()
{
	atf_set descr 'jail applies to tcp and udp rules only'
	atf_set require.user root
}
only_tcp_udp_body()
{
	echo "block in proto icmp jail 0" |
	    atf_check -s not-exit:0 -e match:'jail only applies to tcp/udp' \
	    pfctl -nf -
	echo "block in proto udp jail 0" |
	    atf_check -s exit:0 -e empty pfctl -nf -
}
only_tcp_udp_cleanup()
{
	true
}

atf_test_case "dtrace" "cleanup"
dtrace_head()
{
	atf_set descr 'pf:rule:jail:match fires with the matching jail id'
	atf_set require.user root
	atf_set require.progs dtrace
}
dtrace_body()
{
	jail_init
	dtrace -l -P pf >/dev/null 2>&1 || atf_skip "DTrace is not available"
	jail -c name=pfjw persist ip4=inherit ip6=inherit
	jw=$(jls -j pfjw jid)
	listen pfjw 8006
	load "pass all" "pass in quick proto tcp to ${ADDR} jail pfjw" \
	    "block in quick proto tcp to ${ADDR} port 1 jail pfjx"
	dtrace -q -n 'pf:rule:jail:match { printf("jid=%d\n", arg1); }' \
	    -n 'pf:rule:jail:resolve { printf("resolve %d -> %d\n", arg1, arg2); }' \
	    -n 'tick-20s { exit(0); }' -o dtrace.out &
	dt=$!
	sleep 8
	nc -z -w 2 ${ADDR} 8006 2>/dev/null
	jail -c name=pfjx persist ip4=inherit ip6=inherit
	wait $dt
	atf_check -s exit:0 -o match:"jid=${jw}" cat dtrace.out
	atf_check -s exit:0 -o match:"resolve -2 -> [0-9]+" cat dtrace.out
}
dtrace_cleanup()
{
	jail -r pfjx >/dev/null 2>&1
	jail_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "shared_ip"
	atf_add_test_case "nested"
	atf_add_test_case "removal"
	atf_add_test_case "before_jail"
	atf_add_test_case "nested_recreate"
	atf_add_test_case "churn"
	atf_add_test_case "only_tcp_udp"
	atf_add_test_case "dtrace"
}

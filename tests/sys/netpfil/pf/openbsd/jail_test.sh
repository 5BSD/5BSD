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

atf_test_case "removal" "cleanup"
removal_head()
{
	atf_set descr 'Removing a jail that rules refer to is harmless'
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
	atf_check -s not-exit:0 -e ignore nc -z -w 2 ${ADDR} 8005
	# A connection with state from the jail, then remove the jail.
	(sleep 5 | jexec pfjd nc ${ADDR} 8004 >/dev/null 2>&1 &)
	sleep 0.5
	atf_check -s exit:0 jail -r pfjd

	# The rule keeps the jail id; it prints as a number now.
	atf_check -s exit:0 -o match:"jail = ${jd}\$" pfctl -sr
	atf_check -s exit:0 -e ignore nc -z -w 2 ${ADDR} 8004
	# Loading a ruleset that names the removed jail fails.
	echo "block in proto tcp jail pfjd" |
	    atf_check -s not-exit:0 -e match:'unknown jail pfjd' pfctl -nf -
	pfctl -F states >/dev/null 2>&1
}
removal_cleanup()
{
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
	kldstat -q -m dtraceall || kldload dtraceall 2>/dev/null ||
	    atf_skip "DTrace is not available"
	jail -c name=pfjw persist ip4=inherit ip6=inherit
	jw=$(jls -j pfjw jid)
	listen pfjw 8006
	load "pass all" "pass in quick proto tcp to ${ADDR} jail pfjw"
	dtrace -q -n 'pf:rule:jail:match { printf("jid=%d\n", arg1); }' \
	    -n 'tick-20s { exit(0); }' -o dtrace.out &
	dt=$!
	sleep 8
	nc -z -w 2 ${ADDR} 8006 2>/dev/null
	wait $dt
	atf_check -s exit:0 -o match:"jid=${jw}" cat dtrace.out
}
dtrace_cleanup()
{
	jail_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "shared_ip"
	atf_add_test_case "nested"
	atf_add_test_case "removal"
	atf_add_test_case "only_tcp_udp"
	atf_add_test_case "dtrace"
}

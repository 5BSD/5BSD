#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Routing domains (rdomain(4)) on FIBs: creation, interface membership,
# address and socket isolation, route -T and ping -V.  Each test runs in
# its own vnet jail (execenv), so routing domains do not outlive it.
#

rdomain_init()
{
	ifconfig lo0 inet 127.0.0.1/8 up
}

atf_test_case "create" "cleanup"
create_head()
{
	atf_set descr 'ifconfig rdomain creates the domain and its loopback'
	atf_set require.user root
}
create_body()
{
	rdomain_init

	atf_check -o save:fibs0 sysctl -n net.fibs
	atf_check ifconfig lo7 rdomain 7 up
	atf_check -o match:'^lo7: flags=.* rdomain 7 ' ifconfig lo7
	atf_check -o match:'^([89]|[1-9][0-9]+)$' sysctl -n net.fibs
	atf_check -o match:'^Routing tables' route -T 7 -n show
	# ifconfig warns (as on OpenBSD) and the loopback stays.
	atf_check -s ignore -e match:'Operation not permitted' \
	    ifconfig lo7 -rdomain
	atf_check -o match:'rdomain 7 ' ifconfig lo7
	# Creating another interface in the domain reuses it.
	atf_check -o ignore ifconfig vether0 create rdomain 7
	atf_check -o match:'rdomain 7 ' ifconfig vether0
	atf_check -o not-match:'rdomain' ifconfig lo0
	# A table with routes cannot become a routing domain.
	atf_check -o ignore route -T 9 add 198.51.100.0/24 127.0.0.1
	atf_check -s ignore -o ignore -e match:'SIOCSIFRDOMAIN' \
	    ifconfig vether1 create rdomain 9
	atf_check -o not-match:'rdomain' ifconfig vether1
}
create_cleanup()
{
	:
}

atf_test_case "destroy" "cleanup"
destroy_head()
{
	atf_set descr 'Empty routing domains can be destroyed and recreated; busy domains stay'
	atf_set require.user root
}
destroy_body()
{
	rdomain_init

	atf_check -s not-exit:0 -e ignore ifconfig lo0 destroy
	atf_check -o ignore ifconfig vether0 create rdomain 7
	atf_check -s not-exit:0 -e match:'Device busy' ifconfig lo7 destroy
	atf_check ifconfig vether0 destroy
	atf_check ifconfig lo7 inet 192.0.2.7/32 up
	atf_check ifconfig lo7 destroy
	atf_check -s not-exit:0 -e match:'no such interface' ifconfig lo7
	# Re-creation must not find a stale domain mapping or old addresses.
	atf_check ifconfig lo7 rdomain 7 up
	atf_check -o match:'rdomain 7 ' ifconfig lo7
	atf_check -o not-match:'192.0.2.7' ifconfig lo7
	atf_check ifconfig lo7 destroy
}
destroy_cleanup()
{
	:
}

atf_test_case "destroy_race" "cleanup"
destroy_race_head()
{
	atf_set descr 'Domain destruction serializes with interface membership changes'
	atf_set require.user root
	atf_set timeout 60
}
destroy_race_body()
{
	rdomain_init
	atf_check -o ignore ifconfig vether0 create rdomain 7
	(
		for i in $(jot 20); do
			ifconfig vether0 rdomain 7 || exit 1
			ifconfig vether0 -rdomain || exit 1
		done
	) > move.out 2> move.err &
	pid=$!
	for i in $(jot 20); do
		ifconfig lo7 destroy 2>> destroy.err || true
		ifconfig lo7 rdomain 7 up || atf_fail 'domain recreation failed'
	done
	wait "$pid" || atf_fail 'interface move failed'
	atf_check -o not-match:'rdomain' ifconfig vether0
	atf_check ifconfig vether0 destroy
	atf_check ifconfig lo7 destroy
	atf_check ifconfig lo7 rdomain 7 up
	atf_check ifconfig lo7 destroy
}
destroy_race_cleanup()
{
	:
}

atf_test_case "move" "cleanup"
move_head()
{
	atf_set descr 'Moving an interface between domains drops its addresses'
	atf_set require.user root
}
move_body()
{
	rdomain_init

	atf_check -o ignore ifconfig vether0 create
	atf_check ifconfig vether0 inet 192.0.2.1/24 up
	atf_check -o match:'inet 192.0.2.1 ' ifconfig vether0
	atf_check ifconfig vether0 rdomain 3
	atf_check -o not-match:'inet 192.0.2.1 ' ifconfig vether0
	atf_check -o match:'flags=.*UP.* rdomain 3 ' ifconfig vether0
	atf_check ifconfig vether0 inet 192.0.2.1/24
	atf_check -o match:'192.0.2.1 .*UHLl .* vether0' route -T 3 -n show
	atf_check -o not-match:'192.0.2.1' route -n show -inet
	atf_check ifconfig vether0 -rdomain
	atf_check -o not-match:'rdomain' ifconfig vether0
	atf_check -o not-match:'192.0.2.1' route -T 3 -n show
}
move_cleanup()
{
	:
}

atf_test_case "address_isolation" "cleanup"
address_isolation_head()
{
	atf_set descr 'The same address in two domains; local only in its domain'
	atf_set require.user root
}
address_isolation_body()
{
	rdomain_init

	atf_check -o ignore ifconfig vether0 create rdomain 1
	atf_check -o ignore ifconfig vether1 create rdomain 2
	atf_check ifconfig vether0 inet 192.0.2.1/24 up
	atf_check ifconfig vether1 inet 192.0.2.1/24 up
	atf_check ifconfig vether1 inet 192.0.2.2/24 alias

	atf_check -o match:'1 packets received' \
	    ping -n -c 1 -t 5 -V 1 192.0.2.1
	atf_check -o match:'1 packets received' \
	    ping -n -c 1 -t 5 -V 2 192.0.2.1
	atf_check -o match:'1 packets received' \
	    ping -n -c 1 -t 5 -V 2 192.0.2.2
	# 192.0.2.2 exists only in domain 2; domain 0 has no route at all.
	atf_check -s not-exit:0 -o ignore -e ignore \
	    ping -n -c 1 -t 2 -V 1 192.0.2.2
	atf_check -s not-exit:0 -o ignore -e ignore \
	    ping -n -c 1 -t 2 192.0.2.1
	# Root nc requests IP_BINDANY, so use an unprivileged client and
	# require the bind error itself rather than a later connect timeout.
	atf_check -s ignore -e match:"bind failed: Can't assign requested address" \
	    route -T 1 exec su -m nobody -c \
	    'nc -z -w 2 -s 192.0.2.2 192.0.2.1 9'
}
address_isolation_cleanup()
{
	:
}

atf_test_case "socket_isolation" "cleanup"
socket_isolation_head()
{
	atf_set descr 'Sockets see only connections of their routing domain'
	atf_set require.user root
}
socket_isolation_body()
{
	rdomain_init

	atf_check ifconfig lo1 rdomain 1
	atf_check ifconfig lo1 inet 127.0.0.1/8 up
	atf_check ifconfig lo2 rdomain 2
	atf_check ifconfig lo2 inet 127.0.0.1/8 up

	# A listener in domain 1 on the address shared by all three domains.
	route -T 1 exec nc -l 127.0.0.1 7777 > out1 &
	echo $! > nc1.pid
	# The same port in domain 2 does not collide with domain 1.
	route -T 2 exec nc -l 127.0.0.1 7777 > out2 &
	echo $! > nc2.pid
	sleep 1

	atf_check -s not-exit:0 nc -z -w 2 127.0.0.1 7777
	echo one | atf_check route -T 1 exec nc -N -w 2 127.0.0.1 7777
	echo two | atf_check route -T 2 exec nc -N -w 2 127.0.0.1 7777
	sleep 1
	atf_check -o inline:'one\n' cat out1
	atf_check -o inline:'two\n' cat out2
}
socket_isolation_cleanup()
{
	for f in nc1.pid nc2.pid; do
		[ -f $f ] && kill $(cat $f) 2>/dev/null
	done
	true
}

atf_test_case "route_exec" "cleanup"
route_exec_head()
{
	atf_set descr 'route -T exec runs a program on a routing table'
	atf_set require.user root
}
route_exec_body()
{
	rdomain_init

	atf_check -s exit:1 -e inline:'route: routing table 42: No such file or directory\n' \
	    route -T 42 -n show
	atf_check -s exit:1 -e match:'routing table 42' \
	    route -T 42 exec true
	atf_check -o ignore route -T 5 add 198.51.100.0/24 127.0.0.1
	atf_check -o inline:'5\n' route -T 5 exec sysctl -n net.my_fibnum
	atf_check -o inline:'0\n' sysctl -n net.my_fibnum
	atf_check -s exit:127 -e ignore route -T 5 exec /nonexistent
	atf_check -o match:'198.51.100/24 +127.0.0.1 +UGS' route -T 5 -n show
	# FIB 5 is a routing table of domain 0: no privilege needed.
	atf_check -o match:'198.51.100/24' \
	    route -T 5 exec su -m nobody -c 'route -n show -inet'
}
route_exec_cleanup()
{
	:
}

atf_test_case "privilege" "cleanup"
privilege_head()
{
	atf_set descr 'Entering another routing domain needs privilege'
	atf_set require.user root
}
privilege_body()
{
	rdomain_init

	atf_check -o ignore route -T 4 add 198.51.100.0/24 127.0.0.1
	atf_check ifconfig lo6 rdomain 6
	# Within routing domain 0: allowed for anyone (FreeBSD setfib).
	atf_check su -m nobody -c 'setfib 4 true'
	# Into routing domain 6: denied.
	# (su does not pass the exit status on here; check the error.)
	atf_check -s ignore -e match:'Operation not permitted' \
	    su -m nobody -c 'setfib 6 true'
	atf_check setfib 6 true
}
privilege_cleanup()
{
	:
}

atf_test_case "vmove" "cleanup"
vmove_head()
{
	atf_set descr 'A routing domain loopback cannot move to another vnet'
	atf_set require.user root
}
vmove_body()
{
	. $(atf_get_srcdir)/../common/vnet.subr

	rdomain_init
	vnet_init
	vnet_mkjail rdvmove

	atf_check ifconfig lo5 rdomain 5 up
	atf_check -s not-exit:0 -e match:'Device busy' \
	    ifconfig lo5 vnet rdvmove
	atf_check -o match:'rdomain 5 ' ifconfig lo5
	atf_check -o match:'^Routing tables' route -T 5 -n show
	# Other members of the domain may move.
	atf_check -o ignore ifconfig vether0 create rdomain 5
	atf_check ifconfig vether0 vnet rdvmove
	atf_check -o match:'^vether0:' jexec rdvmove ifconfig vether0
}
vmove_cleanup()
{
	. $(atf_get_srcdir)/../common/vnet.subr

	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "create"
	atf_add_test_case "destroy"
	atf_add_test_case "destroy_race"
	atf_add_test_case "move"
	atf_add_test_case "address_isolation"
	atf_add_test_case "socket_isolation"
	atf_add_test_case "route_exec"
	atf_add_test_case "privilege"
	atf_add_test_case "vmove"
}

#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# pfsync(4) (OpenBSD protocol) between two firewalls, each a vnet jail with
# its own pf: states created on one appear on the other, and a TCP
# connection survives moving its path from the first firewall to the
# second, which only passes it because of the synchronised state.
#
#   cl --- lan bridge --- fw1, fw2 --- wan bridge --- srv
#                         fw1 <- sync -> fw2

. $(atf_get_srcdir)/../../../common/vnet.subr

pfsync_setup()
{
	vnet_init
	vnet_init_bridge
	kldstat -q -m pf || atf_skip "pf is not loaded"
	which python3 >/dev/null 2>&1 || atf_skip "python3 is required"

	brl=$(vnet_mkbridge)
	brw=$(vnet_mkbridge)
	ecl=$(vnet_mkepair); ef1l=$(vnet_mkepair); ef2l=$(vnet_mkepair)
	esrv=$(vnet_mkepair); ef1w=$(vnet_mkepair); ef2w=$(vnet_mkepair)
	esync=$(vnet_mkepair)
	for e in ${ecl} ${ef1l} ${ef2l}; do
		ifconfig ${brl} addm ${e}a; ifconfig ${e}a up
	done
	for e in ${esrv} ${ef1w} ${ef2w}; do
		ifconfig ${brw} addm ${e}a; ifconfig ${e}a up
	done
	ifconfig ${brl} up; ifconfig ${brw} up

	vnet_mkjail psycl ${ecl}b
	vnet_mkjail psysrv ${esrv}b
	vnet_mkjail psyfw1 ${ef1l}b ${ef1w}b ${esync}a
	vnet_mkjail psyfw2 ${ef2l}b ${ef2w}b ${esync}b

	jexec psycl ifconfig ${ecl}b inet 10.10.1.10/24 up
	jexec psycl route -q add -net 10.10.2.0/24 10.10.1.1
	jexec psysrv ifconfig ${esrv}b inet 10.10.2.10/24 up
	jexec psysrv route -q add -net 10.10.1.0/24 10.10.2.1
	n=1
	for fw in psyfw1 psyfw2; do
		eval l=\${ef${n}l}b w=\${ef${n}w}b
		[ $n = 1 ] && s=${esync}a || s=${esync}b
		jexec ${fw} ifconfig lo0 inet 127.0.0.1/8 up
		jexec ${fw} ifconfig ${l} inet 10.10.1.${n}/24 up
		jexec ${fw} ifconfig ${w} inet 10.10.2.${n}/24 up
		jexec ${fw} ifconfig ${s} inet 10.10.3.${n}/24 up
		jexec ${fw} sysctl -q net.inet.ip.forwarding=1 >/dev/null
		printf '%s\n' \
		    "set skip on { lo0 ${s} }" \
		    'block all' \
		    "pass in on ${l} proto tcp from 10.10.1.0/24 to 10.10.2.0/24 port 7777 flags S/SA" \
		    "pass out on ${w} proto tcp to port 7777 flags S/SA" \
		    'pass proto pfsync' |
		    jexec ${fw} pfctl -f - || atf_fail "pf.conf on ${fw}"
		jexec ${fw} pfctl -e >/dev/null 2>&1
		jexec ${fw} ifconfig pfsync0 create
		jexec ${fw} ifconfig pfsync0 syncdev ${s} up ||
		    atf_fail "pfsync0 on ${fw}"
		n=$((n + 1))
	done

	cat > echo.py <<'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.10.2.10', 7777)); s.listen(1); print('READY', flush=True)
c, _ = s.accept()
while True:
    d = c.recv(100)
    if not d:
        break
    c.sendall(d)
EOF
	cat > client.py <<'EOF'
import os, socket, sys, time
c = socket.create_connection(('10.10.2.10', 7777), timeout=10)
c.sendall(b'one'); assert c.recv(100) == b'one'
print('FIRST', flush=True)
while not os.path.exists(sys.argv[1]):
    time.sleep(0.1)
c.sendall(b'two'); assert c.recv(100) == b'two'
print('SECOND', flush=True)
EOF
	jexec psysrv python3 $(pwd)/echo.py > echo.out 2>&1 &
	i=0
	until grep -q READY echo.out; do
		i=$((i + 1)); [ $i -lt 100 ] || atf_fail "echo server"
		sleep 0.1
	done
}

pfsync_cleanup()
{
	pkill -f "$(pwd)/echo.py" >/dev/null 2>&1
	pkill -f "$(pwd)/client.py" >/dev/null 2>&1
	vnet_cleanup
}

# wait_for <file> <word>
wait_for()
{
	i=0
	until grep -q "$2" "$1" 2>/dev/null; do
		i=$((i + 1)); [ $i -lt 150 ] || atf_fail "no $2 in $1"
		sleep 0.1
	done
}

atf_test_case "sync" "cleanup"
sync_head()
{
	atf_set descr 'States created on one firewall are synchronised to the other'
	atf_set require.user root
}
sync_body()
{
	pfsync_setup
	jexec psycl python3 $(pwd)/client.py $(pwd)/go > client.out 2>&1 &
	wait_for client.out FIRST
	i=0
	until jexec psyfw2 pfctl -ss | grep -q '10.10.2.10:7777'; do
		i=$((i + 1))
		[ $i -lt 100 ] || atf_fail "state not synchronised: $(jexec psyfw1 pfctl -ss)"
		sleep 0.1
	done
	atf_check -s exit:0 -o match:'10.10.1.10:[0-9]+ -> 10.10.2.10:7777' \
	    jexec psyfw2 pfctl -ss
	touch go
	wait_for client.out SECOND
}
sync_cleanup()
{
	pfsync_cleanup
}

atf_test_case "failover" "cleanup"
failover_head()
{
	atf_set descr 'A TCP connection survives moving from one firewall to the other'
	atf_set require.user root
}
failover_body()
{
	pfsync_setup
	jexec psycl python3 $(pwd)/client.py $(pwd)/go > client.out 2>&1 &
	wait_for client.out FIRST
	i=0
	until jexec psyfw2 pfctl -ss | grep -q '10.10.2.10:7777'; do
		i=$((i + 1)); [ $i -lt 100 ] || atf_fail "state not synchronised"
		sleep 0.1
	done
	# Fail over: both ends now route through fw2, which has no rule that
	# passes a packet of an established connection, only the state.
	jexec psycl route -q change -net 10.10.2.0/24 10.10.1.2
	jexec psysrv route -q change -net 10.10.1.0/24 10.10.2.2
	jexec psyfw1 ifconfig $(jexec psyfw1 ifconfig -l | tr ' ' '\n' | grep epair | head -1) down
	touch go
	wait_for client.out SECOND
	# fw2 carried the rest of the connection on the synchronised state.
	atf_check -s exit:0 -o match:'10.10.1.10:[0-9]+ -> 10.10.2.10:7777' \
	    jexec psyfw2 pfctl -ss
}
failover_cleanup()
{
	pfsync_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "sync"
	atf_add_test_case "failover"
}

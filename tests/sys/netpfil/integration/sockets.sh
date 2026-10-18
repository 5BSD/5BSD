#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# The OpenBSD socket interfaces that 5BSD adds to the FreeBSD stack for
# OpenBSD PF: SO_BINDANY, divert-reply transparent proxying, SO_RXQ_OVFL,
# IP_RECVDSTPORT/IPV6_RECVDSTPORT with divert-to, and divert(4) sockets
# (socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT)) for divert-packet.  The
# numbers are 5BSD allocations (docs/book network provenance, "Number
# allocation").  sockhelper.c does the socket calls; everything runs in
# VNET jails.

. $(atf_get_srcdir)/integration.subr

HELPER=$(atf_get_srcdir)/sockhelper

# Wait until a helper started in the background prints READY into $1.
sk_wait_ready()
{
	_i=0
	while ! grep -q READY $1 2>/dev/null; do
		_i=$((_i + 1))
		[ ${_i} -lt 50 ] || atf_fail "helper did not start: $(cat $1)"
		sleep 0.1
	done
}

# Wait for a background job to finish (the helper has its own timeout).
sk_wait_pid()
{
	wait $1
}

sk_wait_listen()
{
	_i=0
	while ! jexec $1 sockstat -l -P $2 -p $3 | grep -q ":$3"; do
		_i=$((_i + 1))
		[ ${_i} -lt 50 ] || atf_fail "no $2 listener on port $3 in $1"
		sleep 0.1
	done
}

# Client jail "cli" behind router jail "fw" on one epair, IPv4 and IPv6.
# The destinations 198.51.100.0/24 and 2001:db8:dead::/48 exist nowhere;
# fw forwards and blackholes them unless pf delivers them locally.
sk_setup_cli_fw()
{
	pft_init
	epair=$(vnet_mkepair)
	vnet_mkjail cli ${epair}a
	vnet_mkjail fw ${epair}b
	jexec cli ifconfig lo0 inet 127.0.0.1/8 up
	jexec fw ifconfig lo0 inet 127.0.0.1/8 up
	jexec fw ifconfig lo0 inet6 ::1/128
	jexec cli ifconfig ${epair}a inet 192.0.2.2/24 up
	jexec cli ifconfig ${epair}a inet6 2001:db8:42::2/64 no_dad
	jexec fw ifconfig ${epair}b inet 192.0.2.1/24 up
	jexec fw ifconfig ${epair}b inet6 2001:db8:42::1/64 no_dad
	jexec cli route -q add -inet default 192.0.2.1
	jexec cli route -q add -inet6 default 2001:db8:42::1
	jexec fw route -q add -inet 198.51.100.0/24 -blackhole 127.0.0.1
	jexec fw route -q add -inet6 2001:db8:dead::/48 -blackhole ::1
	jexec fw sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1
	atf_check -s exit:0 -e ignore jexec fw pfctl -e
}

atf_test_case "constants" "cleanup"
constants_head()
{
	atf_set descr 'The 5BSD numbers of the OpenBSD socket interfaces'
}
constants_body()
{
	atf_check -s exit:0 \
	    -o match:'^SO_BINDANY=0x20000000$' \
	    -o match:'^SO_RXQ_OVFL=0x40000000$' \
	    -o match:'^SCM_RXQ_OVFL=0x0a$' \
	    -o match:'^SO_RTABLE=0x1014$' \
	    -o match:'^SO_FIB=0x1014$' \
	    -o match:'^IP_RECVDSTPORT=33$' \
	    -o match:'^IPV6_RECVDSTPORT=76$' \
	    -o match:'^IPPROTO_DIVERT=258$' \
	    ${HELPER} consts
	# The installed headers carry the same values.
	if [ -f /usr/include/sys/socket.h ]; then
		atf_check -s exit:0 -o match:'SO_BINDANY[[:space:]]+0x20000000' \
		    -o match:'SO_RXQ_OVFL[[:space:]]+0x40000000' \
		    grep -E 'define[[:space:]]+SO_(BINDANY|RXQ_OVFL)[[:space:]]' \
		    /usr/include/sys/socket.h
		atf_check -s exit:0 -o match:'IPPROTO_DIVERT[[:space:]]+258' \
		    -o match:'IP_RECVDSTPORT[[:space:]]+33' \
		    grep -E 'define[[:space:]]+(IPPROTO_DIVERT|IP_RECVDSTPORT)[[:space:]]' \
		    /usr/include/netinet/in.h
	fi
}
constants_cleanup()
{
	:
}

atf_test_case "bindany" "cleanup"
bindany_head()
{
	atf_set descr 'SO_BINDANY lets root bind non-local addresses; unprivileged users get EPERM'
	atf_set require.user root
}
bindany_body()
{
	pft_init
	vnet_mkjail j
	jexec j ifconfig lo0 inet 127.0.0.1/8 up

	# Without the option a foreign address cannot be bound.
	atf_check -s exit:0 -o inline:'bind=EADDRNOTAVAIL\n' \
	    jexec j ${HELPER} bindany -n inet 203.0.113.9
	# With it, root binds the foreign address; the option reads back set.
	atf_check -s exit:0 \
	    -o inline:'setsockopt=ok\ngetsockopt=ok value=1 len=4\nbind=ok\n' \
	    jexec j ${HELPER} bindany inet 203.0.113.9
	atf_check -s exit:0 \
	    -o inline:'setsockopt=ok\ngetsockopt=ok value=1 len=4\nbind=ok\n' \
	    jexec j ${HELPER} bindany inet6 2001:db8:dead::9
	# Unprivileged: EPERM, the option stays clear and the bind fails.
	atf_check -s exit:0 \
	    -o inline:'setsockopt=EPERM\ngetsockopt=ok value=0 len=4\nbind=EADDRNOTAVAIL\n' \
	    jexec -U nobody j ${HELPER} bindany inet 203.0.113.9
	atf_check -s exit:0 -o match:'^setsockopt=EPERM$' \
	    jexec -U nobody j ${HELPER} bindany inet6 2001:db8:dead::9
}
bindany_cleanup()
{
	integ_cleanup
}

atf_test_case "divert_reply" "cleanup"
divert_reply_head()
{
	atf_set descr 'divert-reply: a proxy connects with a foreign source (SO_BINDANY) and gets the replies'
	atf_set require.user root
}
divert_reply_body()
{
	pft_init
	epair=$(vnet_mkepair)
	vnet_mkjail px ${epair}a
	vnet_mkjail srv ${epair}b
	jexec px ifconfig lo0 inet 127.0.0.1/8 up
	jexec px ifconfig ${epair}a 198.51.100.1/24 up
	jexec srv ifconfig ${epair}b 198.51.100.2/24 up
	jexec srv route -q add default 198.51.100.1
	# The client address 203.0.113.50 is not on px; its replies would be
	# forwarded into a blackhole.
	jexec px route -q add -inet 203.0.113.0/24 -blackhole 127.0.0.1
	jexec px sysctl -q net.inet.ip.forwarding=1
	atf_check -s exit:0 -e ignore jexec px pfctl -e

	# Without divert-reply the SYN-ACK never reaches the proxy socket.
	pft_set_rules px "pass all"
	atf_check -s not-exit:0 -o not-match:'reply=hello' \
	    jexec px ${HELPER} tcp-connect -b 203.0.113.50 198.51.100.2 8080

	pft_set_rules px "pass all" \
	    "pass out on ${epair}a inet proto tcp to 198.51.100.2 port 8080 divert-reply"
	jexec srv ${HELPER} tcp-serve 198.51.100.2 8080 > srv.out 2>&1 &
	srv=$!
	sk_wait_ready srv.out
	atf_check -s exit:0 \
	    -o match:'^connect=ok$' \
	    -o match:'^local=203\.0\.113\.50$' \
	    -o match:'^reply=hello from server$' \
	    jexec px ${HELPER} tcp-connect -b 203.0.113.50 198.51.100.2 8080
	sk_wait_pid ${srv}
	# The server saw the original client address.
	atf_check -s exit:0 -o match:'^peer=203\.0\.113\.50$' cat srv.out
	# As on OpenBSD, closing the socket removed its divert-reply state.
	atf_check -s exit:0 -o not-match:'198\.51\.100\.2:8080' \
	    jexec px pfctl -ss
}
divert_reply_cleanup()
{
	integ_cleanup
}

atf_test_case "recvdstport" "cleanup"
recvdstport_head()
{
	atf_set descr 'IP_RECVDSTPORT/IPV6_RECVDSTPORT report the original port of divert-to datagrams'
	atf_set require.user root
}
recvdstport_body()
{
	sk_setup_cli_fw

	# Plain delivery: the port the socket is bound to.
	jexec fw ${HELPER} udp-recvdst inet 192.0.2.1 7400 > plain.out 2>&1 &
	p=$!
	sk_wait_ready plain.out
	echo plain | jexec cli nc -u -w 1 192.0.2.1 7400
	sk_wait_pid $p
	atf_check -s exit:0 \
	    -o match:'from=192\.0\.2\.2 dstaddr=192\.0\.2\.1 dstport=7400 data=plain' \
	    cat plain.out

	pft_set_rules fw "pass all" \
	    "pass in on ${epair}b inet proto udp to port 9999 divert-to 127.0.0.1 port 7000" \
	    "pass in on ${epair}b inet6 proto udp to port 9999 divert-to ::1 port 7000"

	# divert-to: bound to 127.0.0.1:7000, told 198.51.100.53:9999.
	jexec fw ${HELPER} udp-recvdst inet 127.0.0.1 7000 > v4.out 2>&1 &
	p=$!
	sk_wait_ready v4.out
	echo hello4 | jexec cli nc -u -w 1 198.51.100.53 9999
	sk_wait_pid $p
	atf_check -s exit:0 \
	    -o match:'from=192\.0\.2\.2 dstaddr=198\.51\.100\.53 dstport=9999 data=hello4' \
	    cat v4.out

	jexec fw ${HELPER} udp-recvdst inet6 ::1 7000 > v6.out 2>&1 &
	p=$!
	sk_wait_ready v6.out
	echo hello6 | jexec cli nc -6 -u -w 1 2001:db8:dead::53 9999
	sk_wait_pid $p
	atf_check -s exit:0 \
	    -o match:'from=2001:db8:42::2 dstaddr=2001:db8:dead::53 dstport=9999 data=hello6' \
	    cat v6.out
}
recvdstport_cleanup()
{
	integ_cleanup
}

atf_test_case "rxq_ovfl" "cleanup"
rxq_ovfl_head()
{
	atf_set descr 'SO_RXQ_OVFL reports receive-queue drops in an SCM_RXQ_OVFL message'
	atf_set require.user root
}
rxq_ovfl_body()
{
	pft_init
	vnet_mkjail j
	jexec j ifconfig lo0 inet 127.0.0.1/8 up

	# The helper exits 0 only if 0 < drops <= datagrams lost.
	atf_check -s exit:0 -o match:'^option=1$' \
	    -o match:'drops=[1-9][0-9]*$' \
	    jexec j ${HELPER} rxq-ovfl 7300
	# Off by default: no message (drops=-1), the option reads 0.
	atf_check -s exit:0 -o match:'^option=0$' -o match:'drops=-1$' \
	    jexec j ${HELPER} rxq-ovfl -n 7301
}
rxq_ovfl_cleanup()
{
	integ_cleanup
}

atf_test_case "divert_socket" "cleanup"
divert_socket_head()
{
	atf_set descr 'socket(AF_INET[6], SOCK_RAW, IPPROTO_DIVERT) receives divert-packet traffic and reinjects it'
	atf_set require.user root
}
divert_socket_body()
{
	sk_setup_cli_fw

	# Only root may open divert sockets.
	atf_check -s exit:0 -o inline:'socket=ok\n' \
	    jexec fw ${HELPER} divert-open inet
	atf_check -s not-exit:0 -o inline:'socket=EPERM\n' \
	    jexec -U nobody fw ${HELPER} divert-open inet

	pft_set_rules fw "pass all" \
	    "pass in on ${epair}b inet proto udp to 192.0.2.1 port 9998 divert-packet port 700" \
	    "pass in on ${epair}b inet6 proto udp to 2001:db8:42::1 port 9998 divert-packet port 700"

	for af in inet inet6; do
		if [ ${af} = inet ]; then
			me=192.0.2.1; peer=192.0.2.2; ncf=
		else
			me=2001:db8:42::1; peer=2001:db8:42::2; ncf=-6
		fi
		: > recv.${af}
		jexec fw nc ${ncf} -u -l ${me} 9998 > recv.${af} 2>/dev/null &
		sk_wait_listen fw udp 9998
		jexec fw ${HELPER} divert ${af} 700 reinject > div.${af} 2>&1 &
		p=$!
		sk_wait_ready div.${af}
		echo payload-${af} | jexec cli nc ${ncf} -u -w 1 ${me} 9998
		sk_wait_pid $p
		# Inbound: the divert source address is the receiving
		# interface's; the packet is the client's UDP datagram.
		atf_check -s exit:0 \
		    -o match:"^from=${me} proto=17 src=${peer} dst=${me} dport=9998 " \
		    -o match:'^reinjected=ok$' \
		    cat div.${af}
		sleep 1
		# Written back, it reached the local listener (once: pf does
		# not divert a reinjected packet again).
		atf_check -s exit:0 -o inline:"payload-${af}\n" cat recv.${af}
		pkill -f "nc ${ncf} -u -l ${me} 9998"
	done
}
divert_socket_cleanup()
{
	integ_cleanup
}

atf_test_case "divert_packet_unbound" "cleanup"
divert_packet_unbound_head()
{
	atf_set descr 'divert-packet without a divert socket in the VNET drops the packet'
	atf_set require.user root
}
divert_packet_unbound_body()
{
	sk_setup_cli_fw
	pft_set_rules fw "pass all" \
	    "pass in on ${epair}b inet proto udp to 192.0.2.1 port 9997 divert-packet port 701"
	: > recv.out
	jexec fw nc -u -l 192.0.2.1 9997 > recv.out 2>/dev/null &
	sk_wait_listen fw udp 9997
	# A divert socket on the same port in another VNET does not get it.
	jexec cli ${HELPER} divert inet 701 > other.out 2>&1 &
	p=$!
	sk_wait_ready other.out
	echo lost | jexec cli nc -u -w 1 192.0.2.1 9997
	sleep 1
	atf_check -s exit:0 -o empty cat recv.out
	wait $p
	atf_check -s exit:0 -o match:'^timeout$' -o not-match:'^from=' \
	    cat other.out
	# The rule matched.  OpenBSD does not count a diverted packet in the
	# rule's packets, only the state it created.
	atf_check -s exit:0 -o match:'State Creations: [1-9]' \
	    sh -c "jexec fw pfctl -vsr | grep -A2 'divert-packet port 701'"
}
divert_packet_unbound_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "constants"
	atf_add_test_case "bindany"
	atf_add_test_case "divert_reply"
	atf_add_test_case "recvdstport"
	atf_add_test_case "rxq_ovfl"
	atf_add_test_case "divert_socket"
	atf_add_test_case "divert_packet_unbound"
}

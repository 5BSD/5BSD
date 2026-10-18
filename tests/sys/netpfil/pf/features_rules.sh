#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
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

# Rule features of OpenBSD pf with no other regression coverage: socket
# owner matching, OS fingerprints, synproxy towards a forwarded IPv6 server,
# challenge ACKs, SACK demodulation, sloppy state tracking, connection rate
# limits with overload/flush, and tag/rtable/prio carried by match rules.

. $(atf_get_srcdir)/utils.subr

# Packets counted by the rules carrying label $2 in jail $1.
feat_label_pkts()
{
	jexec $1 pfctl -sl | awk -v l="$2" '$1 == l { n += $3 } END { print n + 0 }'
}

# Echo "ping" through the echo service at 192.0.2.2 from jail $1 as user $2.
feat_echo_as()
{
	echo ping | jexec -U $2 $1 nc -N -w 3 192.0.2.2 7 2>/dev/null
}

feat_mac()
{
	# ifconfig prints OpenBSD's "lladdr".
	jexec $1 ifconfig $2 | awk '$1 == "lladdr" || $1 == "ether" { print $2; exit }'
}

# Scapy helper that plays a TCP client on the tester side and a TCP server
# on the (dummy) server side of the router, so both directions of a
# connection through pf can be crafted and checked.
feat_write_helper()
{
	cat > feat_tcp.py <<'__EOF__'
import sys
import time
import scapy.all as sp

sp.conf.verb = 0
M32 = 1 << 32

CLI = '203.0.113.5'
SRV = '198.51.100.2'
SRV_MAC = '00:01:02:03:04:05'
CP = 40001
SP = 9
CISN = 1000000
SISN = 5000000


def fail(msg):
    print('FAIL: ' + msg)
    sys.exit(1)


def tcp_from(src, sport):
    def f(p):
        return (p.haslayer(sp.IP) and p.haslayer(sp.TCP) and
                p[sp.IP].src == src and p[sp.TCP].sport == sport)
    return f


def xmit(l3, send_if, smac, dmac, watch):
    sniffers = []
    for iface, src, sport in watch:
        s = sp.AsyncSniffer(iface=iface, store=True,
                            lfilter=tcp_from(src, sport))
        s.start()
        sniffers.append((iface, s))
    time.sleep(0.5)
    sp.sendp(sp.Ether(src=smac, dst=dmac) / l3, iface=send_if)
    time.sleep(1.0)
    res = {}
    for iface, s in sniffers:
        s.stop()
        res[iface] = list(s.results or [])
    return res


def one(res, iface, what):
    pkts = res[iface]
    if len(pkts) != 1:
        fail('%s: expected 1 packet on %s, got %d' % (what, iface, len(pkts)))
    return pkts[0][sp.TCP]


def osfp(argv):
    iface, dmac, src, dst = argv
    pkts = [
        # 512:64:0:44:M*: -> Linux 2.0.3x in pf.os
        (sp.IP(src=src, dst=dst, ttl=64, flags=0) /
         sp.TCP(sport=4001, dport=9, flags='S', seq=1, window=512,
                options=[('MSS', 1460)]), 44),
        # 4321:64:0:40:. -> no pf.os entry
        (sp.IP(src=src, dst=dst, ttl=64, flags=0) /
         sp.TCP(sport=4002, dport=9, flags='S', seq=1, window=4321), 40),
    ]
    for p, size in pkts:
        if len(sp.raw(p)) != size:
            fail('crafted SYN is %d bytes, not %d' % (len(sp.raw(p)), size))
        sp.sendp(sp.Ether(dst=dmac) / p, iface=iface)
    time.sleep(0.5)


def main():
    mode = sys.argv[1]
    if mode == 'osfp':
        osfp(sys.argv[2:])
        print('OK')
        return
    cli_if, srv_if, rtr_cli_mac, rtr_srv_mac = sys.argv[2:6]
    extra = sys.argv[6] if len(sys.argv) > 6 else ''
    cli_mac = sp.get_if_hwaddr(cli_if)

    def c2s(tcp, more=()):
        return xmit(sp.IP(src=CLI, dst=SRV) / tcp, cli_if, cli_mac,
                    rtr_cli_mac, [(srv_if, CLI, CP)] + list(more))

    def s2c(tcp):
        return xmit(sp.IP(src=SRV, dst=CLI) / tcp, srv_if, SRV_MAC,
                    rtr_srv_mac, [(cli_if, SRV, SP)])

    def handshake(opts=()):
        t = one(c2s(sp.TCP(sport=CP, dport=SP, flags='S', seq=CISN,
                           window=65535, options=list(opts))),
                srv_if, 'SYN')
        cseq = t.seq
        t = one(s2c(sp.TCP(sport=SP, dport=CP, flags='SA', seq=SISN,
                           ack=(cseq + 1) % M32, window=65535,
                           options=list(opts))),
                cli_if, 'SYN+ACK')
        if t.ack != CISN + 1:
            fail('SYN+ACK acks %d, expected %d' % (t.ack, CISN + 1))
        sseq = t.seq
        t = one(c2s(sp.TCP(sport=CP, dport=SP, flags='A', seq=CISN + 1,
                           ack=(sseq + 1) % M32, window=65535)),
                srv_if, 'ACK')
        if t.ack != SISN + 1:
            fail('ACK acks %d at the server, expected %d' %
                 (t.ack, SISN + 1))
        return cseq, sseq

    if mode == 'sack':
        # modulate state: SACK blocks sent by the server refer to the
        # modulated client sequence space and must be demodulated.
        cseq, sseq = handshake([('SAckOK', b'')])
        if cseq == CISN:
            fail('client ISN was not modulated')
        for off in (1, 101):
            t = one(c2s(sp.TCP(sport=CP, dport=SP, flags='PA',
                               seq=CISN + off, ack=(sseq + 1) % M32,
                               window=65535) / sp.Raw(b'x' * 100)),
                    srv_if, 'data')
            if t.seq != (cseq + off) % M32:
                fail('data seq %d, expected %d' % (t.seq, cseq + off))
        blk = ((cseq + 101) % M32, (cseq + 201) % M32)
        t = one(s2c(sp.TCP(sport=SP, dport=CP, flags='A', seq=SISN + 1,
                           ack=(cseq + 1) % M32, window=65535,
                           options=[('NOP', None), ('NOP', None),
                                    ('SAck', blk)])),
                cli_if, 'SACK')
        if t.ack != CISN + 1:
            fail('SACK segment acks %d, expected %d' % (t.ack, CISN + 1))
        sacks = [o[1] for o in t.options if o[0] == 'SAck']
        want = (CISN + 101, CISN + 201)
        if len(sacks) != 1 or tuple(sacks[0]) != want:
            fail('SACK blocks %s, expected %s' % (sacks, want))
    elif mode == 'challenge':
        handshake()
        # A SYN on an established state gets a challenge ACK from pf
        # on behalf of the server and is not forwarded.
        res = c2s(sp.TCP(sport=CP, dport=SP, flags='S', seq=CISN + 70000,
                         window=65535), more=[(cli_if, SRV, SP)])
        if res[srv_if]:
            fail('SYN on an established state was forwarded')
        t = one(res, cli_if, 'challenge ACK')
        if t.flags != 'A':
            fail('challenge has flags %s' % t.flags)
        # pf acks the client's lowest sequence number it has seen
        # (pf_send_challenge_ack(): src->seqlo).
        if t.seq != SISN + 1 or t.ack not in (CISN, CISN + 1):
            fail('challenge ACK seq %d ack %d, expected %d %d' %
                 (t.seq, t.ack, SISN + 1, CISN + 1))
    elif mode == 'oneway':
        # Only the client half crosses the firewall (asymmetric routing).
        one(c2s(sp.TCP(sport=CP, dport=SP, flags='S', seq=CISN,
                       window=65535)), srv_if, 'SYN')
        one(c2s(sp.TCP(sport=CP, dport=SP, flags='A', seq=CISN + 1,
                       ack=777777, window=65535)), srv_if, 'ACK')
        one(c2s(sp.TCP(sport=CP, dport=SP, flags='PA', seq=CISN + 1,
                       ack=777777, window=65535) / sp.Raw(b'y' * 50)),
            srv_if, 'data')
    elif mode == 'oow':
        cseq, sseq = handshake()
        # Data far outside the window: full tracking drops it, sloppy
        # tracking passes it.
        res = c2s(sp.TCP(sport=CP, dport=SP, flags='PA',
                         seq=(CISN + 1 + 0x40000000) % M32,
                         ack=(sseq + 1) % M32, window=65535) /
                  sp.Raw(b'z' * 10))
        n = len(res[srv_if])
        if extra == 'pass' and n != 1:
            fail('out-of-window segment was not forwarded')
        if extra == 'drop' and n != 0:
            fail('out-of-window segment was forwarded')
    else:
        fail('unknown mode ' + mode)
    print('OK')


main()
__EOF__
}

# Router between the tester (host) and a dummy server whose frames the host
# reads and writes on ${epair_server}b.  The client address 203.0.113.5 is
# routed to the tester but not configured on it, so the host's own stack
# never answers the crafted connection with resets.
feat_dummy_setup()
{
	setup_router_dummy_ipv4
	jexec router route add -net 203.0.113.0/24 ${net_tester_host_tester}
	rtr_cli_mac=$(feat_mac router ${epair_tester}b)
	rtr_srv_mac=$(feat_mac router ${epair_server}a)
	feat_write_helper
	atf_check -s exit:0 -o ignore jexec router ping -c 1 ${net_tester_host_tester}
}

feat_tcp()
{
	# scapy warns about the jail's missing resolver on stderr.
	atf_check -s exit:0 -o match:'^OK$' -e ignore python3 ./feat_tcp.py $1 \
	    ${epair_tester}a ${epair_server}b ${rtr_cli_mac} ${rtr_srv_mac} $2
}

# Two jails: alcatraz (client, filtering) and singsing (echo server).
feat_socket_setup()
{
	pft_init

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}a
	vnet_mkjail singsing ${epair}b
	jexec alcatraz ifconfig ${epair}a 192.0.2.1/24 up
	jexec singsing ifconfig ${epair}b 192.0.2.2/24 up
	jexec singsing /usr/sbin/inetd -p ${PWD}/inetd-singsing.pid \
	    $(atf_get_srcdir)/echo_inetd.conf
	jexec alcatraz pfctl -e

	atf_check -s exit:0 -o ignore jexec alcatraz ping -c 1 192.0.2.2
}

atf_test_case "user_match" "cleanup"
user_match_head()
{
	atf_set descr 'Match locally created sockets by owner (user)'
	atf_set require.user root
	atf_set timeout 300
}

user_match_body()
{
	feat_socket_setup

	pft_set_rules alcatraz \
		"pass" \
		"block return out proto tcp user nobody label blk_user"

	[ "$(feat_echo_as alcatraz root)" = "ping" ] ||
	    atf_fail "root connection was blocked by 'user nobody'"
	[ "$(feat_label_pkts alcatraz blk_user)" -eq 0 ] ||
	    atf_fail "root's packets matched 'user nobody'"
	[ "$(feat_echo_as alcatraz nobody)" = "ping" ] &&
	    atf_fail "nobody's connection passed 'block ... user nobody'"
	[ "$(feat_label_pkts alcatraz blk_user)" -ge 1 ] ||
	    atf_fail "'user nobody' rule counted no packets"
	atf_check -s exit:0 -o match:"user = 65534" jexec alcatraz pfctl -sr

	# Range operator: uid >= 1000 covers nobody but not root.
	pft_set_rules alcatraz \
		"pass" \
		"block return out proto tcp user >= 1000 label blk_range"
	[ "$(feat_echo_as alcatraz root)" = "ping" ] ||
	    atf_fail "root connection was blocked by 'user >= 1000'"
	[ "$(feat_echo_as alcatraz nobody)" = "ping" ] &&
	    atf_fail "nobody's connection passed 'user >= 1000'"
	[ "$(feat_label_pkts alcatraz blk_range)" -ge 1 ] ||
	    atf_fail "'user >= 1000' rule counted no packets"

	# Positive match: only root may connect out.
	pft_set_rules alcatraz \
		"block return out proto tcp" \
		"pass out proto tcp user root label pass_root" \
		"pass in"
	[ "$(feat_echo_as alcatraz root)" = "ping" ] ||
	    atf_fail "root connection was not passed by 'user root'"
	[ "$(feat_echo_as alcatraz nobody)" = "ping" ] &&
	    atf_fail "nobody's connection passed 'user root'"
	[ "$(feat_label_pkts alcatraz pass_root)" -ge 1 ] ||
	    atf_fail "'user root' rule counted no packets"
}

user_match_cleanup()
{
	pft_cleanup
}

atf_test_case "group_match" "cleanup"
group_match_head()
{
	atf_set descr 'Match locally created sockets by owner (group)'
	atf_set require.user root
	atf_set timeout 300
}

group_match_body()
{
	feat_socket_setup

	# By number: a group's name may not be its user's primary group (the
	# OpenBSD regress setup moves group nobody to 32767).
	pft_set_rules alcatraz \
		"pass" \
		"block return out proto tcp group $(id -g nobody) label blk_grp"
	[ "$(feat_echo_as alcatraz root)" = "ping" ] ||
	    atf_fail "root connection was blocked by 'group nobody'"
	[ "$(feat_echo_as alcatraz nobody)" = "ping" ] &&
	    atf_fail "nobody's connection passed 'group nobody'"
	[ "$(feat_label_pkts alcatraz blk_grp)" -ge 1 ] ||
	    atf_fail "'group nobody' rule counted no packets"

	# And the other way round: block the wheel group.
	pft_set_rules alcatraz \
		"pass" \
		"block return out proto tcp group $(id -g root) label blk_wheel"
	[ "$(feat_echo_as alcatraz nobody)" = "ping" ] ||
	    atf_fail "nobody's connection was blocked by 'group wheel'"
	[ "$(feat_label_pkts alcatraz blk_wheel)" -eq 0 ] ||
	    atf_fail "nobody's packets matched 'group wheel'"
	[ "$(feat_echo_as alcatraz root)" = "ping" ] &&
	    atf_fail "root's connection passed 'group wheel'"
	[ "$(feat_label_pkts alcatraz blk_wheel)" -ge 1 ] ||
	    atf_fail "'group wheel' rule counted no packets"
}

group_match_cleanup()
{
	pft_cleanup
}

atf_test_case "osfp_match" "cleanup"
osfp_match_head()
{
	atf_set descr 'Match TCP SYNs by passive OS fingerprint'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

osfp_match_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.2/24 up
	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up
	jexec alcatraz pfctl -e

	pft_set_rules alcatraz \
		"set fingerprints \"/etc/pf.os\"" \
		"pass in quick proto tcp from any os \"OpenBSD\" to port 9 no state label os_openbsd" \
		"pass in quick proto tcp from any os \"Linux\" to port 9 no state label os_linux" \
		"pass in quick proto tcp from any os \"unknown\" to port 9 no state label os_unknown" \
		"block in proto tcp to port 9 label os_none"

	atf_check -s exit:0 -o match:"Linux" jexec alcatraz pfctl -s osfp
	atf_check -s exit:0 -o match:'os "Linux"' jexec alcatraz pfctl -sr

	feat_write_helper
	atf_check -s exit:0 -o match:'^OK$' -e ignore python3 ./feat_tcp.py osfp \
	    ${epair}a $(feat_mac alcatraz ${epair}b) 192.0.2.2 192.0.2.1

	jexec alcatraz pfctl -sl
	[ "$(feat_label_pkts alcatraz os_linux)" -eq 1 ] ||
	    atf_fail "Linux 2.0 fingerprint did not match os \"Linux\" once"
	[ "$(feat_label_pkts alcatraz os_unknown)" -eq 1 ] ||
	    atf_fail "unlisted fingerprint did not match os \"unknown\" once"
	[ "$(feat_label_pkts alcatraz os_openbsd)" -eq 0 ] ||
	    atf_fail "a SYN matched os \"OpenBSD\""
	[ "$(feat_label_pkts alcatraz os_none)" -eq 0 ] ||
	    atf_fail "a SYN fell through all os rules"
}

osfp_match_cleanup()
{
	pft_cleanup
}

atf_test_case "synproxy_forward_v6" "cleanup"
synproxy_forward_v6_head()
{
	atf_set descr 'synproxy state for a forwarded IPv6 server'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

synproxy_forward_v6_body()
{
	setup_router_server_ipv6
	jexec router route add -6 2001:db8:44::/64 ${net_tester_host_tester}

	pft_set_rules router \
		"pass in quick on ${epair_tester}b inet6 proto tcp to port 7 synproxy state"

	atf_check -s exit:0 -o ignore ping6 -c 1 ${net_server_host_server}

	reply=$(echo ping | nc -6 -N -w 5 ${net_server_host_server} 7)
	[ "${reply}" = "ping" ] || atf_fail "echo through synproxy failed"
	jexec router pfctl -qss | normalize_pfctl_s |
	    grep -q "2001:db8:43::2\[7\] <- 2001:db8:42::2\[" ||
	    atf_fail "no state for the proxied connection"

	# A lone SYN is answered by pf itself and the state stays in the
	# proxy phase: the server never sees it.
	atf_check -s exit:0 ${common_dir}/pft_ping.py \
	    --sendif ${epair_tester}a --to ${net_server_host_server} \
	    --replyif ${epair_tester}a --fromaddr 2001:db8:44::5 \
	    --ping-type=tcpsyn --send-sport=4321 --send-dport=7
	jexec router pfctl -qss | normalize_pfctl_s |
	    grep -qE "2001:db8:44::5\[4321\] PROXY:SRC" ||
	    atf_fail "SYN-only connection is not in PROXY:SRC"
}

synproxy_forward_v6_cleanup()
{
	pft_cleanup
}

atf_test_case "challenge_ack" "cleanup"
challenge_ack_head()
{
	atf_set descr 'SYN on an established state gets a challenge ACK'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

challenge_ack_body()
{
	feat_dummy_setup

	pft_set_rules router \
		"pass in on ${epair_tester}b inet proto tcp keep state"

	feat_tcp challenge
	# The challenge leaves the state intact.
	jexec router pfctl -ss | normalize_pfctl_s |
	    grep -q "198.51.100.2:9 <- 203.0.113.5:40001 ESTABLISHED:ESTABLISHED" ||
	    atf_fail "state was not kept established after the challenge"
}

challenge_ack_cleanup()
{
	pft_cleanup
}

atf_test_case "modulate_sack" "cleanup"
modulate_sack_head()
{
	atf_set descr 'modulate state rewrites SACK blocks'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

modulate_sack_body()
{
	feat_dummy_setup

	pft_set_rules router \
		"pass in on ${epair_tester}b inet proto tcp modulate state"

	feat_tcp sack
	jexec router pfctl -ss | normalize_pfctl_s |
	    grep -q "198.51.100.2:9 <- 203.0.113.5:40001 ESTABLISHED:ESTABLISHED" ||
	    atf_fail "modulated state not established"
}

modulate_sack_cleanup()
{
	pft_cleanup
}

atf_test_case "sloppy_state" "cleanup"
sloppy_state_head()
{
	atf_set descr 'keep state (sloppy) skips sequence window checks'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

sloppy_state_body()
{
	feat_dummy_setup

	# Control: full tracking drops a segment far outside the window.
	pft_set_rules router \
		"pass in on ${epair_tester}b inet proto tcp keep state"
	feat_tcp oow drop

	pft_set_rules router \
		"pass in on ${epair_tester}b inet proto tcp keep state (sloppy)"
	atf_check -s exit:0 -o match:"\(sloppy\)" \
	    jexec router pfctl -sr
	feat_tcp oow pass
	atf_check -s exit:0 -o match:", sloppy" jexec router pfctl -vss

	# Asymmetric routing: only the client half passes the firewall.
	pft_set_rules router \
		"pass in on ${epair_tester}b inet proto tcp keep state (sloppy)"
	feat_tcp oneway
	atf_check -s exit:0 -o match:"203.0.113.5:40001" jexec router pfctl -ss
}

sloppy_state_cleanup()
{
	pft_cleanup
}

# Router with a client network 2001:db8:44::/64 behind the tester, as in
# src_track.sh, so pft_ping.py can complete handshakes from many sources.
feat_src_setup()
{
	setup_router_server_ipv6
	jexec router route add -6 2001:db8:44::0/64 2001:db8:42::2
	jexec server route add -6 2001:db8:44::0/64 2001:db8:43::1
}

feat_3way()
{
	ping_server_check_reply $1 --ping-type=tcp3way --send-sport=$2 \
	    --fromaddr $3 ${4:+--send-dport=$4}
}

atf_test_case "max_src_conn_rate" "cleanup"
max_src_conn_rate_head()
{
	atf_set descr 'max-src-conn-rate overloads a table and flushes states'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

max_src_conn_rate_body()
{
	feat_src_setup

	pft_set_rules router \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"block in quick on ${epair_tester}b from <bad_hosts>" \
		"pass in on ${epair_tester}b inet6 proto tcp keep state (max-src-conn-rate 3/3600, overload <bad_hosts> flush)" \
		"pass out on ${epair_server}a inet6 proto tcp keep state"

	# Three connections within the rate are fine, the fourth exceeds it.
	# The rate decays over its window: an hour, as each connection takes
	# seconds on a slow test machine.
	feat_3way exit:0 4211 2001:db8:44::1
	feat_3way exit:0 4212 2001:db8:44::1
	feat_3way exit:0 4213 2001:db8:44::1
	jexec router pfctl -T test -t bad_hosts 2001:db8:44::1 &&
	    atf_fail "Host overloaded before exceeding the rate"
	feat_3way exit:0 4214 2001:db8:44::1

	jexec router pfctl -T test -t bad_hosts 2001:db8:44::1 ||
	    atf_fail "Host not found in overload table"
	states=$(jexec router pfctl -qss | normalize_pfctl_s)
	echo "${states}"
	echo "${states}" |
	    grep -qE '2001:db8:44::1\[421[1-4]\] ESTABLISHED:ESTABLISHED' &&
	    atf_fail "States of the overloaded source were not flushed"
	atf_check -s exit:0 -o match:"max-src-conn-rate +[1-9]" \
	    -o match:"overload flush states +[1-9]" jexec router pfctl -vsi

	# The overloaded source is now blocked, others are not.
	feat_3way exit:1 4215 2001:db8:44::1
	feat_3way exit:0 4216 2001:db8:44::2
}

max_src_conn_rate_cleanup()
{
	pft_cleanup
}

atf_test_case "max_src_conn_flush_global" "cleanup"
max_src_conn_flush_global_head()
{
	atf_set descr 'max-src-conn with overload ... flush global kills states of all rules'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

max_src_conn_flush_global_body()
{
	feat_src_setup

	pft_set_rules router \
		"block" \
		"pass inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }" \
		"block in quick on ${epair_tester}b from <bad_hosts>" \
		"pass in on ${epair_tester}b inet6 proto tcp to port 7 keep state" \
		"pass in on ${epair_tester}b inet6 proto tcp to port 9 keep state (max-src-conn 2, overload <bad_hosts> flush global)" \
		"pass out on ${epair_server}a inet6 proto tcp keep state"

	# States from the other rule (port 7), one per source.
	feat_3way exit:0 4301 2001:db8:44::1 7
	feat_3way exit:0 4302 2001:db8:44::2 7
	# Port 9: the third connection exceeds max-src-conn.
	feat_3way exit:0 4311 2001:db8:44::1
	feat_3way exit:0 4312 2001:db8:44::1
	feat_3way exit:0 4313 2001:db8:44::1

	jexec router pfctl -T test -t bad_hosts 2001:db8:44::1 ||
	    atf_fail "Host not found in overload table"
	states=$(jexec router pfctl -qss | normalize_pfctl_s)
	echo "${states}"
	echo "${states}" |
	    grep -qE '2001:db8:44::1\[43[01][0-9]\] ESTABLISHED:ESTABLISHED' &&
	    atf_fail "flush global left a state of the overloaded source"
	echo "${states}" |
	    grep -qE '2001:db8:43::2\[7\] <- 2001:db8:44::2\[4302\] ESTABLISHED:ESTABLISHED' ||
	    atf_fail "flush global killed a state of another source"
	atf_check -s exit:0 -o match:"max-src-conn +[1-9]" \
	    -o match:"overload table insertion +[1-9]" jexec router pfctl -vsi
}

max_src_conn_flush_global_cleanup()
{
	pft_cleanup
}

atf_test_case "tag_rtable_prio" "cleanup"
tag_rtable_prio_head()
{
	atf_set descr 'match rules carry tag, rtable and set prio to later rules'
	atf_set require.user root
	atf_set require.progs python3 scapy
	atf_set timeout 300
}

tag_rtable_prio_body()
{
	setup_router_server_ipv4

	# Make the server reachable only through FIB 1.
	jexec router sysctl net.fibs=2
	jexec router ifconfig ${epair_server}a fib 1
	jexec router route del -net ${net_server}
	jexec router route add -fib 1 -net ${net_server} -iface ${epair_server}a
	# Replies arrive on the FIB 1 interface and are not stateful.
	jexec router route add -fib 1 -net ${net_tester} -iface ${epair_tester}b

	# The match rule tags the request, selects rtable 1 and sets prio 5;
	# the pass rules only accept tagged packets, outbound with prio 5.
	pft_set_rules router \
		"block" \
		"match in on ${epair_tester}b inet proto icmp tag ICMPTAG rtable 1 set prio 5" \
		"pass in on ${epair_tester}b inet proto icmp tagged ICMPTAG no state label t_in" \
		"pass out on ${epair_server}a inet proto icmp tagged ICMPTAG prio 5 no state label t_out" \
		"pass in on ${epair_server}a inet proto icmp icmp-type echorep no state" \
		"pass out on ${epair_tester}b inet proto icmp icmp-type echorep no state"
	ping_server_check_reply exit:0
	[ "$(feat_label_pkts router t_in)" -eq 1 ] ||
	    atf_fail "tagged inbound rule did not count the request"
	[ "$(feat_label_pkts router t_out)" -eq 1 ] ||
	    atf_fail "tagged prio 5 outbound rule did not count the request"

	# A different prio on the outbound rule no longer matches.
	pft_set_rules router \
		"block" \
		"match in on ${epair_tester}b inet proto icmp tag ICMPTAG rtable 1 set prio 5" \
		"pass in on ${epair_tester}b inet proto icmp tagged ICMPTAG no state label t_in" \
		"pass out on ${epair_server}a inet proto icmp tagged ICMPTAG prio 4 no state label t_out" \
		"pass in on ${epair_server}a inet proto icmp icmp-type echorep no state" \
		"pass out on ${epair_tester}b inet proto icmp icmp-type echorep no state"
	ping_server_check_reply exit:1
	[ "$(feat_label_pkts router t_in)" -eq 1 ] ||
	    atf_fail "tagged inbound rule did not count the request"
	[ "$(feat_label_pkts router t_out)" -eq 0 ] ||
	    atf_fail "prio 4 rule matched a prio 5 packet"

	# Without the tag the request is blocked inbound.
	pft_set_rules router \
		"block" \
		"match in on ${epair_tester}b inet proto icmp rtable 1 set prio 5" \
		"pass in on ${epair_tester}b inet proto icmp tagged ICMPTAG no state label t_in" \
		"pass out on ${epair_server}a inet proto icmp no state" \
		"pass in on ${epair_server}a inet proto icmp icmp-type echorep no state" \
		"pass out on ${epair_tester}b inet proto icmp icmp-type echorep no state"
	ping_server_check_reply exit:1
	[ "$(feat_label_pkts router t_in)" -eq 0 ] ||
	    atf_fail "untagged packet matched 'tagged ICMPTAG'"

	# Without the match rule's rtable there is no route to the server.
	pft_set_rules router \
		"block" \
		"match in on ${epair_tester}b inet proto icmp tag ICMPTAG" \
		"pass in on ${epair_tester}b inet proto icmp tagged ICMPTAG no state label t_in" \
		"pass out on ${epair_server}a inet proto icmp no state" \
		"pass in on ${epair_server}a inet proto icmp icmp-type echorep no state" \
		"pass out on ${epair_tester}b inet proto icmp icmp-type echorep no state"
	ping_server_check_reply exit:1
	[ "$(feat_label_pkts router t_in)" -eq 1 ] ||
	    atf_fail "tagged inbound rule did not count the request"
}

tag_rtable_prio_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "user_match"
	atf_add_test_case "group_match"
	atf_add_test_case "osfp_match"
	atf_add_test_case "synproxy_forward_v6"
	atf_add_test_case "challenge_ack"
	atf_add_test_case "modulate_sack"
	atf_add_test_case "sloppy_state"
	atf_add_test_case "max_src_conn_rate"
	atf_add_test_case "max_src_conn_flush_global"
	atf_add_test_case "tag_rtable_prio"
}

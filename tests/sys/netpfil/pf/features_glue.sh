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

# pf glue paths no other test reaches: pfsync input dispatch (DEL, CLR,
# skipped and malformed messages), pfsync/pflow statistics sysctls, the
# pseudo-interfaces' if_output, pflow IPv4/NAT/IPv6/v5 export flushed on
# demand, pflow MTU and receiver validation, per-rule pflog interfaces,
# route-label rules, refused queues and port ranges.

. $(atf_get_srcdir)/utils.subr

# The value of the netstat -s -p <proto> counter whose line contains $2.
# The pfsync and pflow counters are host aggregates (pf_sysctl.c): tests
# only assert that they grow.
glue_stat()
{
	_v=$(netstat -s -p "$1" | awk -v pat="$2" \
	    'index($0, pat) { print $1; exit }')
	echo "${_v:-0}"
}

glue_stat_grew()
{
	_now=$(glue_stat "$1" "$2")
	if [ "${_now}" -le "$3" ]; then
		netstat -s -p "$1"
		atf_fail "$1 counter '$2' did not grow (was $3, now ${_now})"
	fi
}

glue_mac()
{
	jexec "$1" ifconfig "$2" | \
	    awk '$1 == "lladdr" || $1 == "ether" { print $2; exit }'
}

# "id/creatorid" of the first state of jail $1, as pfctl -k id takes it.
glue_state_id()
{
	jexec "$1" pfctl -ss -vv | \
	    awk '$1 == "id:" && $3 == "creatorid:" { print $2 "/" $4; exit }'
}

# Writes inject.py: crafted pfsync(4) frames sent to a pfsync syncdev.
glue_write_injector()
{
	cat > inject.py <<'EOF'
import logging
import struct
import sys
logging.getLogger("scapy").setLevel(logging.CRITICAL)
import scapy.all as sp

PFSYNC_VERSION = 6
STATE_LEN = 264		# sizeof(struct pfsync_state)
CREATORID_OFF = 236	# offsetof(struct pfsync_state, creatorid)

def frame(subs, version=PFSYNC_VERSION):
	body = b"".join(subs)
	return struct.pack("!BBH16s", version, 0, 20 + len(body),
	    b"\0" * 16) + body

def subh(action, dwords, count, payload):
	return struct.pack("!BBH", action, dwords, count) + payload

def clr(creatorid):
	# struct pfsync_clr: ifname[16] (empty: all interfaces), creatorid
	return subh(0, 5, 1, b"\0" * 16 + creatorid)

def delete(sid, creatorid):
	st = bytearray(STATE_LEN)
	st[0:8] = sid
	st[CREATORID_OFF:CREATORID_OFF + 4] = creatorid
	return subh(6, STATE_LEN >> 2, 1, bytes(st))

def skipped():
	# action >= PFSYNC_ACT_MAX, and PFSYNC_ACT_OINS (no handler)
	return [subh(200, 1, 1, b"\xaa" * 4), subh(1, 2, 2, b"\xbb" * 16)]

iface, dmac, src, dst, kind = sys.argv[1:6]
ttl = 255
sid = bytes.fromhex(sys.argv[6]) if len(sys.argv) > 6 else b"\0" * 8
cid = bytes.fromhex(sys.argv[7]) if len(sys.argv) > 7 else b"\0" * 4

if kind == "skip":
	payload = frame(skipped())
elif kind == "skip_clr":
	payload = frame(skipped() + [clr(cid)])
elif kind == "badact":
	payload = frame([subh(201, 0, 0, b"")])
elif kind == "badver":
	payload = frame(skipped(), version=5)
elif kind == "badttl":
	payload = frame(skipped())
	ttl = 64
elif kind == "short":
	payload = b"\x06\x00"
elif kind == "del":
	payload = frame([delete(sid, cid)])
else:
	sys.exit("unknown kind " + kind)

sp.sendp(sp.Ether(dst=dmac) /
    sp.IP(src=src, dst=dst, ttl=ttl, proto=240) / sp.Raw(payload),
    iface=iface, verbose=False)
EOF
}

# One jail with pfsync0 on ${epair_sync}a (192.0.2.1) and an ICMP state
# towards the test vnet (198.51.100.254).  The test vnet plays the peer on
# ${epair_sync}b (192.0.2.2).
glue_pfsync_one()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)

	vnet_mkjail one ${epair_sync}a ${epair_one}a
	pfsynct_mkif one

	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a 198.51.100.1/24 up
	jexec one ifconfig pfsync0 syncdev ${epair_sync}a maxupd 1 up
	ifconfig ${epair_sync}b 192.0.2.2/24 up
	ifconfig ${epair_one}b 198.51.100.254/24 up

	jexec one pfctl -e
	pft_set_rules one \
		"set timeout icmp.error 120" \
		"set skip on ${epair_sync}a" \
		"pass out keep state"

	sync_mac=$(glue_mac one ${epair_sync}a)
	[ -n "${sync_mac}" ] || atf_fail "no MAC address on ${epair_sync}a"
	glue_write_injector
}

glue_one_state()
{
	atf_check -s exit:0 -o ignore \
	    jexec one ping -c 1 -S 198.51.100.1 198.51.100.254
	jexec one pfctl -ss | grep -q 198.51.100.254 || \
	    atf_fail "no state on one"
}

glue_inject()
{
	atf_check -s exit:0 python3 inject.py ${epair_sync}b ${sync_mac} \
	    192.0.2.2 192.0.2.1 "$@"
	sleep 0.5
}

atf_test_case "pfsync_del_peer" "cleanup"
pfsync_del_peer_head()
{
	atf_set descr 'A state killed on one pfsync peer disappears on the other'
	atf_set require.user root
}

pfsync_del_peer_body()
{
	pfsynct_init

	epair_sync=$(vnet_mkepair)
	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)

	vnet_mkjail one ${epair_one}a ${epair_sync}a
	vnet_mkjail two ${epair_two}a ${epair_sync}b
	pfsynct_mkif one
	pfsynct_mkif two

	jexec one ifconfig ${epair_sync}a 192.0.2.1/24 up
	jexec one ifconfig ${epair_one}a 198.51.100.1/24 up
	jexec one ifconfig pfsync0 syncdev ${epair_sync}a maxupd 1 up
	jexec two ifconfig ${epair_sync}b 192.0.2.2/24 up
	jexec two ifconfig ${epair_two}a 198.51.100.2/24 up
	jexec two ifconfig pfsync0 syncdev ${epair_sync}b maxupd 1 up

	for j in one two; do
		jexec ${j} pfctl -e
	done
	pft_set_rules one \
		"set timeout icmp.error 120" \
		"set skip on ${epair_sync}a" \
		"pass out keep state"
	pft_set_rules two \
		"set timeout icmp.error 120" \
		"set skip on ${epair_sync}b" \
		"pass out keep state"

	ifconfig ${epair_one}b 198.51.100.254/24 up

	ipackets=$(glue_stat pfsync "received (IPv4)")

	# pfsync's own transmissions on the sync link (pfsync_sendout).
	jexec two tcpdump -n -l -i ${epair_sync}b ip proto 240 \
	    > sync.txt 2> /dev/null &
	echo $! > tcpdump.pid
	sleep 1

	atf_check -s exit:0 -o ignore \
	    jexec one ping -c 1 -S 198.51.100.1 198.51.100.254
	sleep 2

	jexec two pfctl -ss | grep -q 198.51.100.254 || \
	    atf_fail "state not synced to two"
	id=$(glue_state_id one)
	[ -n "${id}" ] || atf_fail "no state id on one"

	# The peer's copy carries one's id and creator id.
	jexec two pfctl -ss -vv | grep -q "id: ${id%/*} creatorid: ${id#*/}" ||
	    atf_fail "two's state is not one's ${id}"

	atf_check -s exit:0 -o ignore -e match:"killed 1 states" \
	    jexec one pfctl -k id -k ${id}

	i=0
	while jexec two pfctl -ss | grep -q 198.51.100.254; do
		i=$((i + 1))
		[ ${i} -lt 10 ] || atf_fail "two kept the state killed on one"
		sleep 0.5
	done

	kill $(cat tcpdump.pid) 2> /dev/null
	sleep 0.5
	cat sync.txt
	atf_check -o match:"192\.0\.2\.1(: | > 224\.0\.0\.240).*PFSYNC" cat sync.txt
	glue_stat_grew pfsync "received (IPv4)" ${ipackets}
}

pfsync_del_peer_cleanup()
{
	[ -f tcpdump.pid ] && kill $(cat tcpdump.pid) 2> /dev/null
	pfsynct_cleanup
}

atf_test_case "pfsync_in_del" "cleanup"
pfsync_in_del_head()
{
	atf_set descr 'A full PFSYNC_ACT_DEL message removes the named state'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

pfsync_in_del_body()
{
	glue_pfsync_one
	glue_one_state

	id=$(glue_state_id one)
	[ -n "${id}" ] || atf_fail "no state id on one"

	# An id nobody created: a failed lookup, the state stays.
	badstate=$(glue_stat pfsync "failed state lookup")
	glue_inject del 0123456789abcdef ${id#*/}
	glue_stat_grew pfsync "failed state lookup" ${badstate}
	jexec one pfctl -ss | grep -q 198.51.100.254 || \
	    atf_fail "an unknown id removed the state"

	# The state's own id and creator: removed (pfsync_in_del).
	glue_inject del ${id%/*} ${id#*/}
	if jexec one pfctl -ss | grep -q 198.51.100.254; then
		jexec one pfctl -ss -vv
		atf_fail "PFSYNC_ACT_DEL did not remove ${id}"
	fi
}

pfsync_in_del_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "pfsync_in_skip" "cleanup"
pfsync_in_skip_head()
{
	atf_set descr 'Unknown pfsync messages are skipped, malformed frames counted'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

pfsync_in_skip_body()
{
	glue_pfsync_one
	glue_one_state

	id=$(glue_state_id one)
	[ -n "${id}" ] || atf_fail "no state id on one"

	# Unknown actions are skipped by their length (pfsync_in_skip): no
	# counter, no effect on states.
	ipackets=$(glue_stat pfsync "received (IPv4)")
	badact=$(glue_stat pfsync "discarded for bad action")
	glue_inject skip
	glue_stat_grew pfsync "received (IPv4)" ${ipackets}
	[ "$(glue_stat pfsync "discarded for bad action")" -eq ${badact} ] || \
	    atf_fail "skipped messages counted as a bad action"
	jexec one pfctl -ss | grep -q 198.51.100.254 || \
	    atf_fail "skipped messages removed the state"

	# A CLR behind the skipped messages is still reached: the skip
	# consumed exactly the skipped messages' length.
	glue_inject skip_clr 0000000000000000 ${id#*/}
	if jexec one pfctl -ss | grep -q 198.51.100.254; then
		atf_fail "CLR after skipped messages was not processed"
	fi

	# An unknown action without a count cannot be skipped.
	glue_inject badact
	glue_stat_grew pfsync "discarded for bad action" ${badact}

	for c in "badver:discarded for bad version" \
	    "badttl:discarded for bad ttl" \
	    "short:shorter than header"; do
		before=$(glue_stat pfsync "${c#*:}")
		glue_inject ${c%%:*}
		glue_stat_grew pfsync "${c#*:}" ${before}
	done

	# The statistics node itself (pf_sysctl.c) is read-only.
	atf_check -s exit:0 -o ignore sysctl -b net.pfsync.stats
	atf_check -s not-exit:0 -o ignore -e ignore \
	    sysctl net.pfsync.stats=0
}

pfsync_in_skip_cleanup()
{
	pfsynct_cleanup
}

atf_test_case "pseudo_if_output" "cleanup"
pseudo_if_output_head()
{
	atf_set descr 'Packets routed into pflog, pfsync and pflow are refused'
	atf_set require.user root
}

pseudo_if_output_body()
{
	pfsynct_init
	pflog_init
	pflow_init

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}a
	jexec alcatraz ifconfig ${epair}a 192.0.2.1/24 up
	ifconfig ${epair}b 192.0.2.2/24 up

	jexec alcatraz ifconfig pflog0 create up
	jexec alcatraz ifconfig pfsync0 create
	jexec alcatraz ifconfig pfsync0 syncdev ${epair}a up
	jexec alcatraz ifconfig pflow0 create

	n=1
	for ifn in pflog0 pfsync0 pflow0; do
		dst=203.0.113.${n}
		atf_check -s exit:0 -o ignore \
		    jexec alcatraz route add -host ${dst} -iface ${ifn}
		# if_output of these interfaces drops with EAFNOSUPPORT
		# (pflogoutput, pfsync_output, pflow_output).
		atf_check -s not-exit:0 -o ignore -e match:"sendto" \
		    jexec alcatraz ping -c 1 -t 1 -S 192.0.2.1 ${dst}
		n=$((n + 1))
	done

	# The jail's network still works.
	atf_check -s exit:0 -o ignore jexec alcatraz ping -c 1 192.0.2.2
}

pseudo_if_output_cleanup()
{
	pft_cleanup
}

# Writes collector.py: a NetFlow v5 / IPFIX collector printing one line per
# record ("v5 proto= src= dst=", "v10 set=N ...").
glue_write_collector()
{
	cat > collector.py <<'EOF'
import socket
import struct
import sys
import time

addr, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((addr, port))
end = time.time() + secs

def a4(b):
	return socket.inet_ntop(socket.AF_INET, b)

def a6(b):
	return socket.inet_ntop(socket.AF_INET6, b)

# OpenBSD pflow(4) record sizes: IPv4 54, NAT IPv4 66, IPv6 78, v5 48.
while True:
	left = end - time.time()
	if left <= 0:
		break
	s.settimeout(left)
	try:
		data, peer = s.recvfrom(65535)
	except socket.timeout:
		break
	ver = struct.unpack("!H", data[0:2])[0]
	if ver == 5:
		count = struct.unpack("!H", data[2:4])[0]
		for i in range(count):
			r = data[24 + 48 * i:24 + 48 * (i + 1)]
			if len(r) < 48:
				break
			print("v5 proto=%d src=%s dst=%s" %
			    (r[38], a4(r[0:4]), a4(r[4:8])))
	elif ver == 10:
		length = min(struct.unpack("!H", data[2:4])[0], len(data))
		off = 16
		while off + 4 <= length:
			sid, slen = struct.unpack("!HH", data[off:off + 4])
			if slen < 4:
				break
			body = data[off + 4:off + slen]
			if sid == 2:
				print("v10 set=2 template")
			elif sid == 256:
				for i in range(len(body) // 54):
					r = body[54 * i:54 * (i + 1)]
					print("v10 set=256 proto=%d src=%s dst=%s" %
					    (r[53], a4(r[0:4]), a4(r[4:8])))
			elif sid == 257:
				for i in range(len(body) // 66):
					r = body[66 * i:66 * (i + 1)]
					print("v10 set=257 proto=%d src=%s dst=%s "
					    "postsrc=%s postdst=%s" %
					    (r[65], a4(r[0:4]), a4(r[4:8]),
					    a4(r[48:52]), a4(r[52:56])))
			elif sid == 258:
				for i in range(len(body) // 78):
					r = body[78 * i:78 * (i + 1)]
					print("v10 set=258 proto=%d src=%s dst=%s" %
					    (r[77], a6(r[0:16]), a6(r[16:32])))
			else:
				print("v10 set=%d" % sid)
			off += slen
	else:
		print("version %d" % ver)
	sys.stdout.flush()
EOF
}

# glue_collect <addr> <seconds>: collector on port 2055 into flows.txt.
glue_collect()
{
	glue_write_collector
	python3 collector.py "$1" 2055 "$2" > flows.txt &
	echo $! > collector.pid
	sleep 1
}

glue_collected()
{
	wait $(cat collector.pid)
	echo "Collected:"
	cat flows.txt
}

# One jail "alcatraz" (192.0.2.1, 2001:db8::1) exporting to the test vnet
# (192.0.2.2, 2001:db8::2) through pflow0, every state marked for pflow.
glue_pflow_one()
{
	pflow_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.2/24 up
	ifconfig ${epair}a inet6 2001:db8::2/64 up no_dad

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up
	jexec alcatraz ifconfig ${epair}b inet6 2001:db8::1/64 up no_dad

	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	pft_set_rules alcatraz \
		"set state-defaults pflow" \
		"pass"

	jexec alcatraz ifconfig pflow0 create
}

atf_test_case "pflow_v5_flush" "cleanup"
pflow_v5_flush_head()
{
	atf_set descr 'pflow v5 records flushed by reconfiguration, pflow statistics'
	atf_set require.user root
	atf_set require.progs python3
}

pflow_v5_flush_body()
{
	glue_pflow_one
	jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055 pflowproto 5

	flows=$(glue_stat pflow "sent" )
	glue_collect 192.0.2.2 8

	atf_check -s exit:0 -o ignore ping -c 2 192.0.2.1
	# Removing the states exports them (export_pflow, copy_flow_data);
	# setting the protocol flushes the pending datagram (pflow_flush).
	jexec alcatraz pfctl -Fs
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 pflowproto 5

	glue_collected
	atf_check -o match:"v5 proto=1 src=192\.0\.2\.2 dst=192\.0\.2\.1" \
	    -o match:"v5 proto=1 src=192\.0\.2\.1 dst=192\.0\.2\.2" \
	    cat flows.txt
	glue_stat_grew pflow "sent" ${flows}
	atf_check -s exit:0 -o ignore sysctl -b net.pflow.stats
}

pflow_v5_flush_cleanup()
{
	[ -f collector.pid ] && kill $(cat collector.pid) 2> /dev/null
	pft_cleanup
}

atf_test_case "pflow_ipfix_nat" "cleanup"
pflow_ipfix_nat_head()
{
	atf_set descr 'IPFIX NAT44 and IPv4 records for a nat-to state'
	atf_set require.user root
	atf_set require.progs python3
}

pflow_ipfix_nat_body()
{
	pflow_init

	epair=$(vnet_mkepair)
	epair_srv=$(vnet_mkepair)

	vnet_mkjail srv ${epair_srv}a
	vnet_mkjail rtr ${epair_srv}b ${epair}a

	ifconfig ${epair}b 192.0.2.2/24 up
	route add -net 198.51.100.0/24 192.0.2.1

	jexec srv ifconfig ${epair_srv}a 198.51.100.2/24 up
	jexec srv route add default 198.51.100.1

	jexec rtr ifconfig ${epair_srv}b 198.51.100.1/24 up
	jexec rtr ifconfig ${epair}a 192.0.2.1/24 up
	jexec rtr sysctl net.inet.ip.forwarding=1

	jexec rtr pfctl -e
	pft_set_rules rtr \
		"set state-defaults pflow" \
		"match out on ${epair_srv}b inet from 192.0.2.0/24 to any nat-to (${epair_srv}b)" \
		"pass"

	jexec rtr ifconfig pflow0 create
	glue_collect 192.0.2.2 10
	# The templates go out when the receiver is set.
	jexec rtr ifconfig pflow0 flowdst 192.0.2.2:2055 pflowproto 10

	atf_check -s exit:0 -o ignore ping -c 1 198.51.100.2
	jexec rtr pfctl -ss
	jexec rtr pfctl -Fs
	atf_check -s exit:0 jexec rtr ifconfig pflow0 pflowproto 10

	glue_collected
	# The outbound state is translated (copy_flow_ipfix_nat_4_data), the
	# inbound one is not (copy_flow_ipfix_4_data).
	atf_check -o match:"v10 set=2 template" \
	    -o match:"v10 set=257 proto=1 src=192\.0\.2\.2 dst=198\.51\.100\.2 postsrc=198\.51\.100\.1 postdst=198\.51\.100\.2" \
	    -o match:"v10 set=256 proto=1 src=192\.0\.2\.2 dst=198\.51\.100\.2" \
	    cat flows.txt
}

pflow_ipfix_nat_cleanup()
{
	[ -f collector.pid ] && kill $(cat collector.pid) 2> /dev/null
	pft_cleanup
}

atf_test_case "pflow_ipfix_v6" "cleanup"
pflow_ipfix_v6_head()
{
	atf_set descr 'IPFIX IPv6 records sent to an IPv6 collector'
	atf_set require.user root
	atf_set require.progs python3
}

pflow_ipfix_v6_body()
{
	glue_pflow_one
	glue_collect 2001:db8::2 8
	jexec alcatraz ifconfig pflow0 flowdst [2001:db8::2]:2055 pflowproto 10
	atf_check -o match:"receiver: \[2001:db8::2\]:2055 version: 10" \
	    jexec alcatraz ifconfig pflow0

	atf_check -s exit:0 -o ignore ping -6 -c 1 2001:db8::1
	jexec alcatraz pfctl -Fs
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 pflowproto 10

	glue_collected
	atf_check -o match:"v10 set=258 proto=58 src=2001:db8::2 dst=2001:db8::1" \
	    -o match:"v10 set=258 proto=58 src=2001:db8::1 dst=2001:db8::2" \
	    cat flows.txt
}

pflow_ipfix_v6_cleanup()
{
	[ -f collector.pid ] && kill $(cat collector.pid) 2> /dev/null
	pft_cleanup
}

atf_test_case "pflow_mtu" "cleanup"
pflow_mtu_head()
{
	atf_set descr 'pflow MTU follows the protocol record size; lowering it flushes'
	atf_set require.user root
	atf_set require.progs python3
}

pflow_mtu_body()
{
	glue_pflow_one
	jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055

	# v5: 24 header + 28 udpip + n * 48 (at most 30 records).
	atf_check -o match:"mtu 1492" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 mtu 9000
	atf_check -o match:"mtu 1492" jexec alcatraz ifconfig pflow0

	# A lower MTU flushes the pending records first.
	glue_collect 192.0.2.2 6
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1
	jexec alcatraz pfctl -Fs
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 mtu 1400
	atf_check -o match:"mtu 1396" jexec alcatraz ifconfig pflow0
	glue_collected
	atf_check -o match:"v5 proto=1 src=192\.0\.2\.2 dst=192\.0\.2\.1" \
	    cat flows.txt

	# IPFIX (pflow_calc_mtu): 16 + 28 + min(n4 * 66, n6 * 78).
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 pflowproto 10
	atf_check -o match:"mtu 1448" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 mtu 1400
	atf_check -o match:"mtu 1364" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 mtu 9000
	atf_check -o match:"mtu 1994" jexec alcatraz ifconfig pflow0
}

pflow_mtu_cleanup()
{
	[ -f collector.pid ] && kill $(cat collector.pid) 2> /dev/null
	pft_cleanup
}

atf_test_case "pflow_receiver" "cleanup"
pflow_receiver_head()
{
	atf_set descr 'pflow receiver validation, socket teardown and down/up'
	atf_set require.user root
	atf_set require.progs python3
}

pflow_receiver_body()
{
	glue_pflow_one

	# pflowvalidsockaddr(): an unspecified address or a zero port is
	# stored but opens no socket, so the interface does not run.
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 0.0.0.0:2055
	atf_check -o match:"receiver: INVALID:2055" -o not-match:"RUNNING" \
	    jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:0
	atf_check -o match:"receiver: 192\.0\.2\.2:INVALID" \
	    -o not-match:"RUNNING" jexec alcatraz ifconfig pflow0

	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055
	atf_check -o match:"RUNNING" jexec alcatraz ifconfig pflow0

	# Valid to invalid closes the socket; a family change frees the old
	# receiver.
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 flowdst [::]:2055
	atf_check -o match:"receiver: \[INVALID\]:2055" \
	    -o not-match:"RUNNING" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055

	# Multicast receivers are not rejected.
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 224.0.0.1:2055
	atf_check -o match:"receiver: 224\.0\.0\.1:2055" \
	    jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055

	# A sender that is not local cannot be bound.
	atf_check -s exit:1 -e match:"SIOCSETPFLOW" \
	    jexec alcatraz ifconfig pflow0 flowsrc 203.0.113.99
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 -flowsrc
	atf_check -o match:"RUNNING" -o not-match:"sender" \
	    jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 flowsrc 192.0.2.1
	atf_check -o match:"sender: 192\.0\.2\.1 receiver: 192\.0\.2\.2:2055" \
	    -o match:"RUNNING" jexec alcatraz ifconfig pflow0

	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 -flowdst
	atf_check -o match:"receiver: INVALID:INVALID" -o not-match:"RUNNING" \
	    jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 \
	    jexec alcatraz ifconfig pflow0 flowdst 192.0.2.2:2055 pflowproto 10

	# Down: states expire without export.  Up: the templates are sent.
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 down
	atf_check -o not-match:"RUNNING" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1
	jexec alcatraz pfctl -Fs

	glue_collect 192.0.2.2 6
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 up
	atf_check -o match:"RUNNING" jexec alcatraz ifconfig pflow0
	atf_check -s exit:0 jexec alcatraz ifconfig pflow0 pflowproto 10
	glue_collected
	atf_check -o match:"v10 set=2 template" -o not-match:"set=256" \
	    cat flows.txt
}

pflow_receiver_cleanup()
{
	[ -f collector.pid ] && kill $(cat collector.pid) 2> /dev/null
	pft_cleanup
}

atf_test_case "pflog_logif" "cleanup"
pflog_logif_head()
{
	atf_set descr 'log (to pflogN) picks the interface at log time'
	atf_set require.user root
}

pflog_logif_body()
{
	pflog_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.2/24 up
	ifconfig ${epair}a alias 192.0.2.3/24

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	jexec alcatraz ifconfig pflog0 create up
	jexec alcatraz ifconfig pflog1 create up

	jexec alcatraz pfctl -e
	# The last matching rule wins: the logging rules come after "pass".
	pft_set_rules alcatraz \
		"pass" \
		"pass in log (to pflog1) inet proto icmp from 192.0.2.2" \
		"pass in log (to pflog13) inet proto icmp from 192.0.2.3"
	atf_check -o match:"log \(to pflog1\)" -o match:"log \(to pflog13\)" \
	    jexec alcatraz pfctl -sr

	jexec alcatraz tcpdump -n -e -ttt -l -i pflog0 > pflog0.txt 2>&1 &
	echo $! > tcpdump0.pid
	jexec alcatraz tcpdump -n -e -ttt -l -i pflog1 > pflog1.txt 2>&1 &
	echo $! > tcpdump1.pid
	sleep 1

	atf_check -s exit:0 -o ignore ping -c 1 -S 192.0.2.2 192.0.2.1
	# pflog13 does not exist: pflog_getif() finds nothing, the packet
	# passes unlogged.
	atf_check -s exit:0 -o ignore ping -c 1 -S 192.0.2.3 192.0.2.1
	sleep 1

	atf_check -o match:"192\.0\.2\.2 > 192\.0\.2\.1: icmp: echo request" \
	    -o not-match:"192\.0\.2\.3" cat pflog1.txt
	atf_check -o not-match:"192\.0\.2\.[23] >" cat pflog0.txt

	# Created later, without a reload, pflog13 receives its rule's logs.
	jexec alcatraz ifconfig pflog13 create up
	jexec alcatraz tcpdump -n -e -ttt -l -i pflog13 > pflog13.txt 2>&1 &
	echo $! > tcpdump13.pid
	sleep 1
	jexec alcatraz pfctl -Fs
	atf_check -s exit:0 -o ignore ping -c 1 -S 192.0.2.3 192.0.2.1
	sleep 1
	atf_check -o match:"192\.0\.2\.3 > 192\.0\.2\.1: icmp: echo request" \
	    cat pflog13.txt

	# Destroying a rule's pflog interface leaves the rule working.
	kill $(cat tcpdump1.pid) 2> /dev/null
	atf_check -s exit:0 jexec alcatraz ifconfig pflog1 destroy
	jexec alcatraz pfctl -Fs
	atf_check -s exit:0 -o ignore ping -c 1 -S 192.0.2.2 192.0.2.1
	atf_check -o not-match:"192\.0\.2\.2 >" cat pflog0.txt
}

pflog_logif_cleanup()
{
	for p in tcpdump0.pid tcpdump1.pid tcpdump13.pid; do
		[ -f ${p} ] && kill $(cat ${p}) 2> /dev/null
	done
	pft_cleanup
}

atf_test_case "route_label" "cleanup"
route_label_head()
{
	atf_set descr 'Rules matching route labels load, print, never match, free labels'
	atf_set require.user root
}

route_label_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.2/24 up
	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up
	jexec alcatraz pfctl -e

	# FreeBSD routes carry no label (rt_labelid 0): "route" never matches.
	pft_set_rules alcatraz \
		"block in quick inet proto icmp from route \"blue\"" \
		"block in quick inet proto icmp to route \"red\"" \
		"pass"
	atf_check -o match:"from route \"blue\"" -o match:"to route \"red\"" \
	    jexec alcatraz pfctl -sr
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1

	# ... so its negation always does.
	pft_set_rules alcatraz \
		"block in quick inet proto icmp from ! route \"blue\"" \
		"pass"
	atf_check -o match:"from ! route \"blue\"" jexec alcatraz pfctl -sr
	atf_check -s exit:2 -o ignore ping -c 1 -t 2 192.0.2.1
	atf_check -o match:"Evaluations: *[1-9]" -o match:"Packets: *[1-9]" \
	    jexec alcatraz pfctl -vsr

	# Labels shared between rules, anchors and reloads: every load
	# takes references (pf_rtlabel_add), every flush drops them
	# (pf_rtlabel_remove); names come back intact (pf_rtlabel_copyout).
	i=0
	while [ ${i} -lt 60 ]; do
		printf "%s\n" \
		    "block in quick inet proto tcp from route \"l$((i % 7))\"" \
		    "block in quick inet proto udp to route \"shared\"" \
		    "block in quick inet proto udp from route \"shared\" to route \"l$((i % 3))\"" \
		    "pass" | jexec alcatraz pfctl -f - || \
		    atf_fail "load ${i} failed"
		if [ $((i % 10)) -eq 0 ]; then
			echo "pass in from route \"anchored\"" | \
			    jexec alcatraz pfctl -a lbl -f - || \
			    atf_fail "anchor load ${i} failed"
			jexec alcatraz pfctl -a lbl -Fr
		fi
		i=$((i + 1))
	done
	atf_check -o match:"from route \"l3\"" -o match:"to route \"shared\"" \
	    -o match:"from route \"shared\" to route \"l2\"" \
	    -o not-match:"route \"\?\"" jexec alcatraz pfctl -sr

	echo "pass in from route \"anchored\"" | \
	    jexec alcatraz pfctl -a lbl -f -
	atf_check -o match:"from route \"anchored\"" \
	    jexec alcatraz pfctl -a lbl -sr

	jexec alcatraz pfctl -a lbl -Fr
	jexec alcatraz pfctl -Fr
	atf_check -o empty jexec alcatraz pfctl -sr

	pft_set_rules alcatraz \
		"block in quick inet proto icmp from route \"fresh\"" \
		"pass"
	atf_check -o match:"from route \"fresh\"" -o not-match:"\"\?\"" \
	    jexec alcatraz pfctl -sr
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1

	# Labels are limited to RTLABEL_LEN - 1 characters.
	long=$(printf '%040d' 0)
	echo "pass in from route \"${long}\"" > long.conf
	atf_check -s exit:1 -e match:"route label too long" \
	    jexec alcatraz pfctl -n -f ${PWD}/long.conf
}

route_label_cleanup()
{
	pft_cleanup
}

atf_test_case "queue_refused" "cleanup"
queue_refused_head()
{
	atf_set descr 'Queue definitions parse but are refused by the kernel'
	atf_set require.user root
}

queue_refused_body()
{
	pft_init

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}a
	jexec alcatraz ifconfig ${epair}a 192.0.2.1/24 up
	jexec alcatraz pfctl -e

	printf "%s\n" \
	    "queue rootq on ${epair}a bandwidth 10M max 10M" \
	    "queue std parent rootq bandwidth 10M default" \
	    "pass" > hfsc.conf
	printf "%s\n" \
	    "queue fq on ${epair}a flows 1024 qlimit 1024 default" \
	    "pass" > fqcodel.conf
	printf "%s\n" \
	    "queue outq on ${epair}a bandwidth 9M max 9M flows 1024 qlimit 1024 default" \
	    "pass" > hfscfq.conf

	for f in hfsc.conf fqcodel.conf hfscfq.conf; do
		atf_check -s exit:0 jexec alcatraz pfctl -n -f ${PWD}/${f}
		# openbsd_ifq.c: the disciplines report EOPNOTSUPP on commit.
		atf_check -s not-exit:0 -o ignore \
		    -e match:"(DIOCXCOMMIT|not supported)" \
		    jexec alcatraz pfctl -f ${PWD}/${f}
		atf_check -s exit:0 -o not-match:"queue" -e ignore \
		    jexec alcatraz pfctl -sq
	done
}

queue_refused_cleanup()
{
	pft_cleanup
}

atf_test_case "ether_queue" "cleanup"
ether_queue_head()
{
	atf_set descr 'Ether rules carry queue names: their ids are shared and released'
	atf_set require.user root
}

ether_queue_body()
{
	pft_init

	epair=$(vnet_mkepair)
	ifconfig ${epair}a 192.0.2.2/24 up
	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up
	jexec alcatraz pfctl -e

	printf "%s\n" \
	    "ether pass in on ${epair}b queue q1" \
	    "ether pass out on ${epair}b queue q2 tag eqtag" \
	    "ether pass in queue q1" \
	    "pass" > equeue.conf
	# pf_qname2qid() makes the ids, pf_free_eth_rule() drops them on
	# every reload and flush; a leak would run the ids out.
	for i in 1 2 3 4 5; do
		atf_check -s exit:0 jexec alcatraz pfctl -f ${PWD}/equeue.conf
		atf_check -s exit:0 -o ignore ping -c 2 192.0.2.1
	done
	atf_check -s exit:0 -o match:"queue q1" -o match:"queue q2" \
	    jexec alcatraz pfctl -s ether
	atf_check -s exit:0 -e ignore jexec alcatraz pfctl -F ethernet
	atf_check -s exit:0 -o not-match:"queue" jexec alcatraz pfctl -s ether
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.1
}

ether_queue_cleanup()
{
	pft_cleanup
}

atf_test_case "port_range" "cleanup"
port_range_head()
{
	atf_set descr 'Empty and inverted port ranges are rejected, valid ones load'
	atf_set require.user root
}

port_range_body()
{
	pft_init

	vnet_mkjail alcatraz
	for r in "port 1000:999" "port 1000 >< 900" "port 1000 >< 1000" \
	    "port 1000 <> 999"; do
		echo "pass in proto tcp to ${r}" > range.conf
		atf_check -s exit:1 -e match:"invalid port range" \
		    jexec alcatraz pfctl -n -f ${PWD}/range.conf
	done

	printf "%s\n" \
	    "pass in proto tcp to port 900 >< 1000" \
	    "pass in proto tcp from port 1000:1000" \
	    "pass in proto udp to port 1000 <> 1001" > range.conf
	atf_check -s exit:0 jexec alcatraz pfctl -f ${PWD}/range.conf
	atf_check -o match:"port 900 >< 1000" -o match:"port 1000 <> 1001" \
	    jexec alcatraz pfctl -sr
}

port_range_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "pfsync_del_peer"
	atf_add_test_case "pfsync_in_del"
	atf_add_test_case "pfsync_in_skip"
	atf_add_test_case "pseudo_if_output"
	atf_add_test_case "pflow_v5_flush"
	atf_add_test_case "pflow_ipfix_nat"
	atf_add_test_case "pflow_ipfix_v6"
	atf_add_test_case "pflow_mtu"
	atf_add_test_case "pflow_receiver"
	atf_add_test_case "pflog_logif"
	atf_add_test_case "route_label"
	atf_add_test_case "queue_refused"
	atf_add_test_case "ether_queue"
	atf_add_test_case "port_range"
}

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

# dummynet(4) as the traffic shaper of OpenBSD PF on 5BSD.  ALTQ is gone;
# pf rules send packets to dummynet pipes and queues with FreeBSD's
# "dnpipe"/"dnqueue" options (sys/netpfil/openbsd-pf/pf_dummynet.c,
# pf_ether.c for "ether" rules) and dnctl(8) configures the pipes, queues
# and schedulers (sys/netpfil/dummynet).
#
# The cases measure what the shaper does to real traffic: TCP throughput
# timed at the receiver, one-way UDP delays (every jail shares the host's
# CLOCK_MONOTONIC, see dnflow.c), ping round trips and loss.  Test VMs are
# slow and noisy (TCG, WITNESS, INVARIANTS), so each check is either a
# hard bound dummynet guarantees (a pipe never delivers early or faster
# than its bandwidth) or a ratio between two measurements taken under the
# same conditions, with wide margins.
#
# Most cases use three VNET jails: client "dncl" (192.0.2.1,
# 2001:db8:1::1), router "dngw" running pf and dummynet, and server
# "dnsrv" (198.51.100.2, 2001:db8:2::2).  The router's interfaces are
# ${a}b (client side) and ${b}a (server side).
#
# The basic pipe, queue, NAT-mask, match, route-to, fragment and ether
# cases from FreeBSD remain in ../common/dummynet.sh and ../pf/*.sh.

. $(atf_get_srcdir)/integration.subr

DNFLOW=$(atf_get_srcdir)/dnflow

CL4=192.0.2.1
GW4=192.0.2.2
GWS4=198.51.100.1
SRV4=198.51.100.2
CL6=2001:db8:1::1
GW6=2001:db8:1::2
GWS6=2001:db8:2::1
SRV6=2001:db8:2::2

# dn_init: VNET, pf and a loaded dummynet(4); dnctl and the helper.
dn_init()
{
	dummynet_init
	integ_require_prog dnctl
	[ -x ${DNFLOW} ] || atf_skip "${DNFLOW} is not installed"
}

# dn_ctl jail dnctl-args...: configure dummynet in a jail or fail.
dn_ctl()
{
	_j=$1
	shift
	jexec ${_j} dnctl "$@" || atf_fail "dnctl $* failed in ${_j}"
}

# dn_check expr message: fail unless the awk expression is true.  The
# expression's operands must be numbers.
dn_check()
{
	awk "BEGIN { exit !($1) }" < /dev/null ||
	    atf_fail "$2 (failed: $1)"
}

# dn_num value what: fail unless value is a number.
dn_num()
{
	case "$1" in
	''|*[!0-9.]*|*.*.*)
		atf_fail "$2: no measurement ('$1')"
		;;
	esac
}

# dn_field line key: the word after "key" in a helper's output line.
dn_field()
{
	echo "$1" | awk -v k="$2" \
	    '{ for (i = 1; i < NF; i++) if ($i == k) { print $(i + 1); exit } }'
}

# dn_noexpire jail: keep idle dummynet queues and scheduler instances, so
# their counters can be read after the traffic (net.inet.ip.dummynet.expire
# deletes them within about a second of going idle).
dn_noexpire()
{
	jexec $1 sysctl -q net.inet.ip.dummynet.expire=0 > /dev/null 2>&1
}

# dn_router: the client/router/server topology, IPv4 and IPv6, with pf
# enabled on the router and passing everything.
dn_router()
{
	dn_init
	a=$(vnet_mkepair)
	b=$(vnet_mkepair)
	vnet_mkjail dncl ${a}a
	vnet_mkjail dngw ${a}b ${b}a
	vnet_mkjail dnsrv ${b}b

	jexec dncl ifconfig ${a}a ${CL4}/24 up
	jexec dncl ifconfig ${a}a inet6 ${CL6}/64 no_dad
	jexec dncl route -q add default ${GW4}
	jexec dncl route -q -6 add default ${GW6}

	jexec dngw ifconfig ${a}b ${GW4}/24 up
	jexec dngw ifconfig ${a}b inet6 ${GW6}/64 no_dad
	jexec dngw ifconfig ${b}a ${GWS4}/24 up
	jexec dngw ifconfig ${b}a inet6 ${GWS6}/64 no_dad
	jexec dngw sysctl -q net.inet.ip.forwarding=1 \
	    net.inet6.ip6.forwarding=1 > /dev/null

	jexec dnsrv ifconfig ${b}b ${SRV4}/24 up
	jexec dnsrv ifconfig ${b}b inet6 ${SRV6}/64 no_dad
	jexec dnsrv route -q add default ${GWS4}
	jexec dnsrv route -q -6 add default ${GWS6}

	jexec dngw pfctl -e > /dev/null 2>&1
	pft_set_rules dngw "pass"
	dn_noexpire dngw
	dn_noexpire dnsrv

	atf_check -s exit:0 -o ignore jexec dncl ping -c 2 -t 10 ${SRV4}
	atf_check -s exit:0 -o ignore jexec dncl ping -6 -c 2 -t 10 ${SRV6}
}

# dn_gw_rules rule...: replace the router's rules (flushing its states).
dn_gw_rules()
{
	pft_set_rules dngw "$@"
}

# dn_rtt jail ping-args...: "min avg" round trip in ms, empty without
# replies.
dn_rtt()
{
	_j=$1
	shift
	jexec ${_j} ping "$@" 2>/dev/null |
	    sed -n 's/^round-trip .* = \([0-9.]*\)\/\([0-9.]*\)\/.*/\1 \2/p'
}

# dn_ping_min jail ping-args...: the minimum round trip in ms; fails the
# test without replies.
dn_ping_min()
{
	_r=$(dn_rtt "$@")
	[ -n "${_r}" ] || atf_fail "no ping replies: ping $*"
	echo ${_r% *}
}

# dn_wait_udp jail port [-6]: wait for a UDP socket bound to port.
dn_wait_udp()
{
	_f=-4
	[ "$3" = "-6" ] && _f=-6
	_i=0
	while ! jexec $1 sockstat ${_f} -P udp -p $2 | grep -q ":$2 "; do
		_i=$((_i + 1))
		[ ${_i} -lt 100 ] || atf_fail "no UDP socket on port $2 in $1"
		sleep 0.1
	done
}

# dn_echo_start jail port [-6] [extra uecho args]: UDP echo server
# writing its summary to echo.<port>; sets echo_pid.
dn_echo_start()
{
	_j=$1
	_p=$2
	shift 2
	jexec ${_j} ${DNFLOW} uecho -p ${_p} -T 600 "$@" > echo.${_p} &
	echo_pid=$!
	dn_wait_udp ${_j} ${_p} "$1"
}

# dn_echo_stop pid port: stop an echo server, print its packet count and
# the first peer address ("count peer").
dn_echo_stop()
{
	kill -TERM $1 2>/dev/null
	wait $1
	awk '{ print $2, $4 }' echo.$2
}

# dn_probe dst port [uprobe args]: run the UDP prober from the client.
dn_probe()
{
	_d=$1
	_p=$2
	shift 2
	jexec dncl ${DNFLOW} uprobe "$@" ${_d} ${_p}
}

# dn_tcp_rate dst port window: rate in kbit/s of one bulk TCP transfer from
# the client to a sink on the server, over window seconds.
dn_tcp_rate()
{
	_six=
	case $1 in *:*) _six=-6 ;; esac
	jexec dnsrv ${DNFLOW} sink ${_six} -p $2 -n 1 -w $3 \
	    -T $(($3 + 120)) > sink.$2 &
	_spid=$!
	jexec dncl ${DNFLOW} send -t $(($3 + 90)) -T $(($3 + 120)) $1 $2 \
	    > send.$2 2>&1
	wait ${_spid}
	awk '{ if ($3 > 0) printf "%d\n", $2 * 8 / $3; else print 0 }' \
	    sink.$2
}

# dn_bulk_start dst port count window: count concurrent TCP flows from the
# client to one sink on the server; results in sink.<port>.  Sets
# bulk_pids.
dn_bulk_start()
{
	_six=
	case $1 in *:*) _six=-6 ;; esac
	jexec dnsrv ${DNFLOW} sink ${_six} -p $2 -n $3 -w $4 \
	    -T $(($4 + 180)) > sink.$2 &
	bulk_pids=$!
	_i=0
	while [ ${_i} -lt $3 ]; do
		jexec dncl ${DNFLOW} send -t $(($4 + 120)) -T $(($4 + 180)) \
		    $1 $2 > /dev/null 2>&1 &
		bulk_pids="${bulk_pids} $!"
		_i=$((_i + 1))
	done
}

dn_bulk_wait()
{
	for _p in ${bulk_pids}; do
		wait ${_p}
	done
}

# dn_counters jail pipe|queue [nr]: "packets drops" summed over the flows
# dnctl lists (the columns Tot_pkt and Drp).
dn_counters()
{
	jexec $1 dnctl $2 show $3 | awk '
	    /^BKT/ { f = 1; next }
	    /^[0-9q]/ { f = 0 }
	    f && NF >= 8 && $NF ~ /^[0-9]+$/ && $(NF - 4) ~ /^[0-9]+$/ {
		p += $(NF - 4); d += $NF
	    }
	    END { print p + 0, d + 0 }'
}

# dn_wait_pkts jail pipe|queue nr count: wait until dummynet has taken
# count packets into the pipe or queue.
dn_wait_pkts()
{
	_i=0
	while :; do
		_c=$(dn_counters $1 $2 $3)
		[ ${_c% *} -ge $4 ] && return
		_i=$((_i + 1))
		[ ${_i} -lt 150 ] ||
		    atf_fail "dummynet $2 $3 in $1 took only ${_c% *} packets"
		sleep 0.1
	done
}

# dn_dir dst port fwd_lo fwd_hi back_lo back_hi: probe 20 times and check
# the median one-way delays (ms) in each direction against the bounds.  A
# bound of 0 for *_lo or *_hi is not checked.
dn_dir()
{
	_l=$(dn_probe $1 $2 -n 20 -i 50 -W 4000)
	echo "$1 port $2: ${_l}"
	_r=$(dn_field "${_l}" recv)
	dn_num "${_r}" "probes to $1"
	dn_check "${_r} >= 15" "probes to $1 port $2 lost"
	_fm=$(dn_field "${_l}" fwd_min)
	_f=$(dn_field "${_l}" fwd_med)
	_bm=$(dn_field "${_l}" back_min)
	_b=$(dn_field "${_l}" back_med)
	[ $3 -eq 0 ] || dn_check "${_fm} >= $3" "forward delay to $1"
	[ $4 -eq 0 ] || dn_check "${_f} < $4" "forward delay to $1"
	[ $5 -eq 0 ] || dn_check "${_bm} >= $5" "return delay from $1"
	[ $6 -eq 0 ] || dn_check "${_b} < $6" "return delay from $1"
}

# dn_malloc: dummynet's kernel allocations in use (both "dummynet" types).
dn_malloc()
{
	vmstat -m | awk '$1 == "dummynet" { s += $2 } END { print s + 0 }'
}

# --------------------------------------------------------------------------

dn_bandwidth()
{
	dst=$1
	dn_ctl dngw pipe 1 config bw 1Mbit/s
	dn_ctl dngw pipe 2 config bw 4Mbit/s
	dn_gw_rules "pass" \
	    "pass out on ${b}a proto tcp to port 5001 dnpipe 1" \
	    "pass out on ${b}a proto tcp to port 5002 dnpipe 2"

	base=$(dn_tcp_rate ${dst} 5000 6)
	r1=$(dn_tcp_rate ${dst} 5001 6)
	r4=$(dn_tcp_rate ${dst} 5002 6)
	echo "unshaped ${base} kbit/s, 1 Mbit/s pipe ${r1}, 4 Mbit/s pipe ${r4}"
	dn_num "${base}" "unshaped rate"
	dn_num "${r1}" "1 Mbit/s rate"
	dn_num "${r4}" "4 Mbit/s rate"

	# A pipe never sends faster than its bandwidth; allow for timing.
	dn_check "${r1} > 250 && ${r1} <= 1350" "1 Mbit/s pipe"
	dn_check "${r4} <= 5400" "4 Mbit/s pipe exceeded"
	# The faster pipe and the unshaped path are clearly faster.
	dn_check "${r4} >= 2 * ${r1}" "4 Mbit/s pipe vs 1 Mbit/s pipe"
	dn_check "${base} >= 2 * ${r1}" "unshaped vs 1 Mbit/s pipe"

	# Only the shaped transfers went through the pipes.
	c=$(dn_counters dngw pipe 1)
	dn_check "${c% *} > 100" "pipe 1 packet counter"
	c=$(dn_counters dngw pipe 2)
	dn_check "${c% *} > 100" "pipe 2 packet counter"
}

atf_test_case "bandwidth_v4" "cleanup"
bandwidth_v4_head()
{
	atf_set descr 'dnpipe bandwidth: TCP over IPv4 through 1 and 4 Mbit/s pipes is capped and scales with the pipe; unshaped is faster'
	atf_set require.user root
	atf_set timeout 600
}

bandwidth_v4_body()
{
	dn_router
	dn_bandwidth ${SRV4}
}

bandwidth_v4_cleanup()
{
	integ_cleanup
}

atf_test_case "bandwidth_v6" "cleanup"
bandwidth_v6_head()
{
	atf_set descr 'dnpipe bandwidth: TCP over IPv6 through 1 and 4 Mbit/s pipes is capped and scales with the pipe; unshaped is faster'
	atf_set require.user root
	atf_set timeout 600
}

bandwidth_v6_body()
{
	dn_router
	dn_bandwidth ${SRV6}
}

bandwidth_v6_cleanup()
{
	integ_cleanup
}

atf_test_case "delay_icmp" "cleanup"
delay_icmp_head()
{
	atf_set descr 'dnpipe delay raises the ping round trip by the pipe delay once per shaped direction, IPv4 and IPv6; the state carries the pipe to the replies'
	atf_set require.user root
	atf_set timeout 600
}

delay_icmp_body()
{
	dn_router
	dn_ctl dngw pipe 1 config delay 250

	pargs="-c 5 -i 0.3 -t 30"
	b4=$(dn_rtt dncl ${pargs} ${SRV4})
	b6=$(dn_rtt dncl -6 ${pargs} ${SRV6})
	echo "unshaped: IPv4 ${b4}, IPv6 ${b6} (min avg ms)"
	[ -n "${b4}" ] && [ -n "${b6}" ] || atf_fail "unshaped ping failed"

	# One shaped direction: +250 ms.
	dn_gw_rules "pass" "pass out on ${b}a dnpipe 1"
	m4=$(dn_ping_min dncl ${pargs} ${SRV4})
	m6=$(dn_ping_min dncl -6 ${pargs} ${SRV6})
	a4=$(dn_rtt dncl ${pargs} ${SRV4})
	echo "dnpipe 1: IPv4 min ${m4} (${a4}), IPv6 min ${m6}"
	dn_check "${m4} >= ${b4% *} + 225" "IPv4 round trip with 250 ms pipe"
	dn_check "${m6} >= ${b6% *} + 225" "IPv6 round trip with 250 ms pipe"
	dn_check "${a4#* } < ${b4#* } + 250 + 1000" \
	    "IPv4 round trip far above the pipe delay"

	# Both directions through the pipe: the replies match the state of
	# the request and take its second pipe.
	dn_gw_rules "pass" "pass out on ${b}a dnpipe (1, 1)"
	m4=$(dn_ping_min dncl ${pargs} ${SRV4})
	m6=$(dn_ping_min dncl -6 ${pargs} ${SRV6})
	echo "dnpipe (1, 1): IPv4 min ${m4}, IPv6 min ${m6}"
	dn_check "${m4} >= ${b4% *} + 450" "IPv4 round trip with (1, 1)"
	dn_check "${m6} >= ${b6% *} + 450" "IPv6 round trip with (1, 1)"

	# Only the reverse direction.
	dn_gw_rules "pass" "pass out on ${b}a dnpipe (0, 1)"
	m4=$(dn_ping_min dncl ${pargs} ${SRV4})
	echo "dnpipe (0, 1): IPv4 min ${m4}"
	dn_check "${m4} >= ${b4% *} + 225" "IPv4 round trip with (0, 1)"
	dn_check "${m4} < ${b4% *} + 450" "IPv4 round trip with (0, 1)"
}

delay_icmp_cleanup()
{
	integ_cleanup
}

atf_test_case "direction" "cleanup"
direction_head()
{
	atf_set descr 'Rule direction picks the pipe: in vs out rules, dnpipe (a, b) and dnqueue (a, b) pairs, match rules, one pass through dummynet per packet; one-way UDP delays, IPv4 and IPv6'
	atf_set require.user root
	atf_set timeout 900
}

direction_body()
{
	dn_router
	dn_ctl dngw pipe 1 config delay 100
	dn_ctl dngw pipe 2 config delay 400
	dn_ctl dngw pipe 3 config delay 1000
	dn_ctl dngw queue 11 config pipe 1
	dn_ctl dngw queue 12 config pipe 2
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_echo_start dnsrv 7002 -6
	e6=${echo_pid}

	# Unshaped baseline.
	dn_dir ${SRV4} 7001 0 300 0 300

	# Out on the server side: requests take pipe 1 (100 ms), the
	# replies (the state's reverse direction) pipe 2 (400 ms).
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe (1, 2)"
	dn_dir ${SRV4} 7001 90 300 360 0
	dn_dir ${SRV6} 7002 90 300 360 0

	# In on the client side, pipes swapped.
	dn_gw_rules "pass" "pass in on ${a}b proto udp dnpipe (2, 1)"
	dn_dir ${SRV4} 7001 360 0 90 300
	dn_dir ${SRV6} 7002 360 0 90 300

	# A rule for the other direction does not shape these packets.
	dn_gw_rules "pass" "pass in on ${b}a proto udp dnpipe (1, 2)"
	dn_dir ${SRV4} 7001 0 300 0 300

	# A match rule's pipes carry over to the passing rule's state.
	dn_gw_rules "match out on ${b}a proto udp dnpipe (1, 2)" "pass"
	dn_dir ${SRV4} 7001 90 300 360 0

	# Queues work the same way.
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnqueue (11, 12)"
	dn_dir ${SRV4} 7001 90 300 360 0
	dn_dir ${SRV6} 7002 90 300 360 0

	# dnqueue (0, n) shapes only the reverse direction.
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnqueue (0, 12)"
	dn_dir ${SRV4} 7001 0 300 360 0

	# A packet goes through dummynet once (pf.conf(5)): shaped in on the
	# client side (400 ms), it is not shaped again by the outbound rule
	# (1000 ms) of the same router.
	dn_gw_rules "pass" "pass in on ${a}b proto udp dnpipe 2" \
	    "pass out on ${b}a proto udp dnpipe 3"
	dn_dir ${SRV4} 7001 360 900 0 300

	dn_echo_stop ${e4} 7001 > /dev/null
	dn_echo_stop ${e6} 7002 > /dev/null
}

direction_cleanup()
{
	integ_cleanup
}

atf_test_case "loss" "cleanup"
loss_head()
{
	atf_set descr 'dnctl plr drops about the configured fraction of the packets in each shaped direction (UDP, IPv4 and IPv6), and the drops are counted'
	atf_set require.user root
	atf_set timeout 600
}

loss_body()
{
	dn_router
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_echo_start dnsrv 7002 -6
	e6=${echo_pid}

	n=300
	l=$(dn_probe ${SRV4} 7001 -n ${n} -i 10 -W 3000)
	echo "unshaped: ${l}"
	r=$(dn_field "${l}" recv)
	dn_num "${r}" "unshaped probes"
	dn_check "${r} >= ${n} * 0.95" "unshaped probes lost"

	dn_ctl dngw pipe 1 config plr 0.25

	# One direction: 75% expected (sigma 7.5 packets).
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe 1"
	l=$(dn_probe ${SRV4} 7001 -n ${n} -i 10 -W 3000)
	echo "plr 0.25 out, IPv4: ${l}"
	r=$(dn_field "${l}" recv)
	dn_num "${r}" "IPv4 probes"
	dn_check "${r} >= 165 && ${r} <= 265" "IPv4 loss with plr 0.25"

	l=$(dn_probe ${SRV6} 7002 -n ${n} -i 10 -W 3000)
	echo "plr 0.25 out, IPv6: ${l}"
	r=$(dn_field "${l}" recv)
	dn_num "${r}" "IPv6 probes"
	dn_check "${r} >= 165 && ${r} <= 265" "IPv6 loss with plr 0.25"

	c=$(dn_counters dngw pipe 1)
	echo "pipe 1 packets/drops: ${c}"
	dn_check "${c#* } >= 50" "pipe 1 drop counter"

	# Both directions: 56% expected (sigma 8.6 packets).
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe (1, 1)"
	l=$(dn_probe ${SRV4} 7001 -n ${n} -i 10 -W 3000)
	echo "plr 0.25 both ways, IPv4: ${l}"
	r=$(dn_field "${l}" recv)
	dn_num "${r}" "IPv4 probes"
	dn_check "${r} >= 110 && ${r} <= 220" "IPv4 loss with plr 0.25 twice"

	dn_echo_stop ${e4} 7001 > /dev/null
	dn_echo_stop ${e6} 7002 > /dev/null
}

loss_cleanup()
{
	integ_cleanup
}

# dn_weights type: two TCP flows in queues of weight 1 and 4 on one
# 2 Mbit/s pipe with the given scheduler.
dn_weights()
{
	dn_router
	dn_ctl dngw pipe 1 config bw 2Mbit/s
	dn_ctl dngw sched 1 config pipe 1 type $1
	dn_ctl dngw queue 1 config sched 1 weight 1
	dn_ctl dngw queue 2 config sched 1 weight 4
	dn_gw_rules "pass" \
	    "pass out on ${b}a proto tcp to port 5001 dnqueue 1" \
	    "pass out on ${b}a proto tcp to port 5002 dnqueue 2"

	jexec dnsrv ${DNFLOW} sink -p 5001 -n 1 -w 10 -T 200 > sink.5001 &
	p1=$!
	jexec dnsrv ${DNFLOW} sink -p 5002 -n 1 -w 10 -T 200 > sink.5002 &
	p2=$!
	jexec dncl ${DNFLOW} send -t 120 -T 200 ${SRV4} 5001 > /dev/null &
	s1=$!
	jexec dncl ${DNFLOW} send -t 120 -T 200 ${SRV4} 5002 > /dev/null &
	s2=$!
	wait ${p1} ${p2} ${s1} ${s2}
	cat sink.5001 sink.5002
	w1=$(awk '{ print $2 }' sink.5001)
	w4=$(awk '{ print $2 }' sink.5002)
	dn_num "${w1}" "weight 1 flow"
	dn_num "${w4}" "weight 4 flow"

	# 4:1 expected.  The low weight flow is not starved, the pipe is
	# used and not exceeded (2 Mbit/s for 10 s is 2.5 MB).
	dn_check "${w4} >= 2 * ${w1}" "$1: weight 4 vs weight 1"
	dn_check "${w1} > 0.03 * 2500000" "$1: weight 1 flow starved"
	dn_check "${w1} + ${w4} <= 1.35 * 2500000" "$1: pipe exceeded"
	dn_check "${w1} + ${w4} >= 0.4 * 2500000" "$1: pipe underused"
	c=$(dn_counters dngw queue 2)
	dn_check "${c% *} > 100" "$1: queue 2 packet counter"
}

atf_test_case "weights_wf2q" "cleanup"
weights_wf2q_head()
{
	atf_set descr 'dnqueue on a WF2Q+ scheduler: two concurrent TCP flows share the pipe by queue weight (4:1)'
	atf_set require.user root
	atf_set timeout 600
}

weights_wf2q_body()
{
	dn_weights wf2q+
}

weights_wf2q_cleanup()
{
	integ_cleanup
}

atf_test_case "weights_qfq" "cleanup"
weights_qfq_head()
{
	atf_set descr 'dnqueue on a QFQ scheduler: two concurrent TCP flows share the pipe by queue weight (4:1)'
	atf_set require.user root
	atf_set timeout 600
}

weights_qfq_body()
{
	dn_weights qfq
}

weights_qfq_cleanup()
{
	integ_cleanup
}

# dn_loaded_delay: median one-way delay (ms) and count of 40 UDP probes
# sent while two bulk TCP flows fill the router's pipe ("med recv").
dn_loaded_delay()
{
	dn_bulk_start ${SRV4} 5001 2 14
	sleep 4
	_l=$(dn_probe ${SRV4} 7001 -n 40 -i 100 -W 6000)
	dn_bulk_wait
	echo "under load: ${_l}" >&2
	cat sink.5001 >&2
	_m=$(dn_field "${_l}" fwd_med)
	[ "${_m}" = "-" ] && _m=100000
	echo "${_m} $(dn_field "${_l}" recv)"
}

atf_test_case "fq_codel_latency" "cleanup"
fq_codel_latency_head()
{
	atf_set descr 'dnqueue on FQ_CODEL keeps a sparse flow fast under bulk TCP load where a long FIFO queue does not'
	atf_set require.user root
	atf_set timeout 600
}

fq_codel_latency_body()
{
	dn_router
	dn_echo_start dnsrv 7001
	e4=${echo_pid}

	dn_ctl dngw pipe 1 config bw 1Mbit/s queue 100
	dn_ctl dngw sched 1 config pipe 1 type fifo
	dn_ctl dngw queue 1 config sched 1 queue 100
	dn_gw_rules "pass" "pass out on ${b}a proto { tcp udp } dnqueue 1"
	fifo=$(dn_loaded_delay)
	echo "FIFO: median ${fifo% *} ms, ${fifo#* } of 40 probes"

	dn_ctl dngw sched 1 config pipe 1 type fq_codel
	dn_ctl dngw queue 1 config sched 1
	dn_gw_rules "pass" "pass out on ${b}a proto { tcp udp } dnqueue 1"
	fq=$(dn_loaded_delay)
	echo "FQ_CODEL: median ${fq% *} ms, ${fq#* } of 40 probes"

	dn_echo_stop ${e4} 7001 > /dev/null

	dn_num "${fifo% *}" "FIFO delay"
	dn_num "${fq% *}" "FQ_CODEL delay"
	# The FIFO really was loaded (100 packets at 1 Mbit/s is 1.2 s).
	dn_check "${fifo% *} >= 200" "bulk flows did not load the FIFO"
	dn_check "${fq#* } >= 30" "FQ_CODEL dropped the sparse flow"
	dn_check "2 * ${fq% *} < ${fifo% *}" "FQ_CODEL vs FIFO delay"
}

fq_codel_latency_cleanup()
{
	integ_cleanup
}

atf_test_case "priority" "cleanup"
priority_head()
{
	atf_set descr 'dnqueue on a PRIO scheduler: probes in the high priority queue stay fast under bulk TCP in the low one; swapped, they wait or starve'
	atf_set require.user root
	atf_set timeout 600
}

priority_body()
{
	dn_router
	dn_echo_start dnsrv 7001
	e4=${echo_pid}

	# PRIO serves the lowest "weight" first.
	dn_ctl dngw pipe 1 config bw 1Mbit/s
	dn_ctl dngw sched 1 config pipe 1 type prio
	dn_ctl dngw queue 1 config sched 1 weight 1 queue 100
	dn_ctl dngw queue 2 config sched 1 weight 9 queue 100

	dn_gw_rules "pass" \
	    "pass out on ${b}a proto udp dnqueue 1" \
	    "pass out on ${b}a proto tcp dnqueue 2"
	hi=$(dn_loaded_delay)
	echo "probes high priority: median ${hi% *} ms, ${hi#* } of 40"

	dn_gw_rules "pass" \
	    "pass out on ${b}a proto udp dnqueue 2" \
	    "pass out on ${b}a proto tcp dnqueue 1"
	lo=$(dn_loaded_delay)
	echo "probes low priority: median ${lo% *} ms, ${lo#* } of 40"

	dn_echo_stop ${e4} 7001 > /dev/null

	dn_num "${hi% *}" "high priority delay"
	dn_num "${lo% *}" "low priority delay"
	dn_check "${hi#* } >= 30" "high priority probes lost"
	dn_check "${lo#* } < 20 || ${lo% *} > 2 * ${hi% *} + 100" \
	    "low priority probes were not held back"
}

priority_cleanup()
{
	integ_cleanup
}

atf_test_case "many_flows" "cleanup"
many_flows_head()
{
	atf_set descr '16 parallel TCP flows through one pipe with per-flow WF2Q+ queues (mask) all complete and share it fairly; dnctl lists a queue per flow'
	atf_set require.user root
	atf_set timeout 900
}

many_flows_body()
{
	dn_router
	dn_ctl dngw pipe 1 config bw 4Mbit/s
	dn_ctl dngw sched 1 config pipe 1 type wf2q+
	dn_ctl dngw queue 1 config sched 1 mask src-port 0xffff
	dn_gw_rules "pass" "pass out on ${b}a proto tcp to port 5001 dnqueue 1"

	n=16
	dn_bulk_start ${SRV4} 5001 ${n} 12
	sleep 6
	flows=$(jexec dngw dnctl queue show 1 | awk '
	    /^BKT/ { f = 1; next } f && $NF ~ /^[0-9]+$/ { n++ }
	    END { print n + 0 }')
	dn_bulk_wait
	cat sink.5001
	echo "dynamic queues seen: ${flows}"

	got=$(awk 'END { print NR }' sink.5001)
	dn_check "${got} == ${n}" "only ${got} of ${n} flows completed"
	dn_check "${flows} >= ${n}" "per-flow queues"
	stats=$(awk '{ s += $2; if (NR == 1 || $2 < m) m = $2 }
	    END { print s, m, s / NR }' sink.5001)
	set -- ${stats}
	echo "total ${1} bytes, smallest flow ${2}, mean ${3}"
	# 4 Mbit/s for 12 s is 6 MB.
	dn_check "$1 <= 1.35 * 6000000" "pipe exceeded"
	dn_check "$1 >= 0.4 * 6000000" "pipe underused (stalled flows)"
	dn_check "$2 >= 0.2 * $3" "a flow got less than 20% of its share"
}

many_flows_cleanup()
{
	integ_cleanup
}

atf_test_case "nat" "cleanup"
nat_head()
{
	atf_set descr 'nat-to with dnpipe: translated UDP is delayed per direction, TCP is rate limited'
	atf_set require.user root
	atf_set timeout 600
}

nat_body()
{
	dn_router
	dn_ctl dngw pipe 1 config delay 100
	dn_ctl dngw pipe 2 config delay 400
	dn_ctl dngw pipe 3 config bw 1Mbit/s

	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_gw_rules "pass" \
	    "pass out on ${b}a inet proto udp from 192.0.2.0/24 nat-to (${b}a) dnpipe (1, 2)" \
	    "pass out on ${b}a inet proto tcp from 192.0.2.0/24 nat-to (${b}a) dnpipe 3"
	dn_dir ${SRV4} 7001 90 300 360 0
	r=$(dn_echo_stop ${e4} 7001)
	echo "echo server: ${r}"
	atf_check_equal "${GWS4}" "${r#* }"

	rate=$(dn_tcp_rate ${SRV4} 5001 6)
	echo "NAT TCP through 1 Mbit/s: ${rate} kbit/s"
	dn_num "${rate}" "NAT TCP rate"
	dn_check "${rate} > 250 && ${rate} <= 1350" "NAT TCP through 1 Mbit/s"
	atf_check -s exit:0 -o match:"${GWS4}" jexec dngw pfctl -ss
}

nat_cleanup()
{
	integ_cleanup
}

atf_test_case "rdr" "cleanup"
rdr_head()
{
	atf_set descr 'rdr-to with dnpipe: redirected UDP is delayed per direction and keeps its source, TCP is rate limited'
	atf_set require.user root
	atf_set timeout 600
}

rdr_body()
{
	dn_router
	dn_ctl dngw pipe 1 config delay 100
	dn_ctl dngw pipe 2 config delay 400
	dn_ctl dngw pipe 3 config bw 1Mbit/s

	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_gw_rules "pass" \
	    "pass in on ${a}b inet proto udp to ${GW4} port 7000 rdr-to ${SRV4} port 7001 dnpipe (1, 2)" \
	    "pass in on ${a}b inet proto tcp to ${GW4} port 6001 rdr-to ${SRV4} port 5001 dnpipe 3"
	dn_dir ${GW4} 7000 90 300 360 0
	r=$(dn_echo_stop ${e4} 7001)
	echo "echo server: ${r}"
	atf_check_equal "${CL4}" "${r#* }"

	jexec dnsrv ${DNFLOW} sink -p 5001 -n 1 -w 6 -T 130 > sink.5001 &
	sp=$!
	jexec dncl ${DNFLOW} send -t 100 -T 130 ${GW4} 6001 > /dev/null 2>&1
	wait ${sp}
	rate=$(awk '{ if ($3 > 0) printf "%d\n", $2 * 8 / $3; else print 0 }' \
	    sink.5001)
	echo "rdr TCP through 1 Mbit/s: ${rate} kbit/s"
	dn_num "${rate}" "rdr TCP rate"
	dn_check "${rate} > 250 && ${rate} <= 1350" "rdr TCP through 1 Mbit/s"
}

rdr_cleanup()
{
	integ_cleanup
}

atf_test_case "rdr_loopback" "cleanup"
rdr_loopback_head()
{
	atf_set descr 'rdr-to 127.0.0.1 with dnpipe: dummynet delivers the redirected packets locally (pf_dn_output sets rcvif to lo0)'
	atf_set require.user root
	atf_set timeout 600
}

rdr_loopback_body()
{
	dn_router
	jexec dngw ifconfig lo0 inet 127.0.0.1/8 up
	dn_ctl dngw pipe 1 config delay 100
	dn_ctl dngw pipe 2 config delay 400
	dn_echo_start dngw 7005 -b 127.0.0.1
	e=${echo_pid}

	dn_gw_rules "pass" \
	    "pass in on ${a}b inet proto udp to ${GW4} port 7000 rdr-to 127.0.0.1 port 7005"
	l=$(dn_probe ${GW4} 7000 -n 10 -i 50 -W 3000)
	echo "without dummynet: ${l}"
	[ "$(dn_field "${l}" recv)" -gt 0 ] 2>/dev/null ||
	    atf_skip "rdr-to 127.0.0.1 does not work without dummynet either"

	dn_gw_rules "pass" \
	    "pass in on ${a}b inet proto udp to ${GW4} port 7000 rdr-to 127.0.0.1 port 7005 dnpipe (1, 2)"
	dn_dir ${GW4} 7000 90 300 360 0
	dn_echo_stop ${e} 7005 > /dev/null
}

rdr_loopback_cleanup()
{
	integ_cleanup
}

# dn_route_to_setup: the server also has 203.0.113.2 and 2001:db8:3::2,
# which the router can reach only through route-to; its server side link
# has an MTU of 1280.
dn_route_to_setup()
{
	dn_router
	jexec dnsrv ifconfig ${b}b inet 203.0.113.2/32 alias
	jexec dnsrv ifconfig ${b}b inet6 2001:db8:3::2/128 alias no_dad
	jexec dnsrv ifconfig ${b}b mtu 1280
	jexec dngw ifconfig ${b}a mtu 1280
	dn_ctl dngw pipe 1 config delay 150
}

atf_test_case "route_to_v4" "cleanup"
route_to_v4_head()
{
	atf_set descr 'route-to with dnpipe (IPv4): shaped packets reach a destination only route-to knows; after the delay oversized packets are fragmented, or refused with "fragmentation needed" when DF is set'
	atf_set require.user root
	atf_set timeout 600
}

route_to_v4_body()
{
	dn_route_to_setup
	# Without route-to the router has no route to 203.0.113.2.
	atf_check -s exit:2 -o ignore jexec dncl ping -c 1 -t 3 203.0.113.2

	dn_gw_rules "pass" \
	    "pass in on ${a}b inet to 203.0.113.0/24 route-to ${SRV4} dnpipe 1"
	m=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 203.0.113.2)
	echo "route-to, 64 bytes: min ${m} ms"
	dn_check "${m} >= 135" "route-to round trip with a 150 ms pipe"

	# 1428 bytes on a 1280 byte link: fragmented after the delay.
	m=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 -s 1400 203.0.113.2)
	echo "route-to, 1400 bytes: min ${m} ms"
	dn_check "${m} >= 135" "fragmented route-to round trip"

	# With DF: "fragmentation needed" from the router.
	atf_check -s exit:2 -o match:'frag needed and DF set' \
	    jexec dncl ping -D -c 1 -t 5 -s 1400 203.0.113.2

	c=$(dn_counters dngw pipe 1)
	dn_check "${c% *} >= 7" "pipe 1 packet counter"
}

route_to_v4_cleanup()
{
	integ_cleanup
}

atf_test_case "route_to_v6" "cleanup"
route_to_v6_head()
{
	atf_set descr 'route-to with dnpipe (IPv6): shaped packets reach a destination only route-to knows; an oversized packet gets "packet too big" and the client then fragments, still shaped'
	atf_set require.user root
	atf_set timeout 600
}

route_to_v6_body()
{
	dn_route_to_setup
	atf_check -s exit:2 -o ignore jexec dncl ping -6 -c 1 -t 3 2001:db8:3::2

	dn_gw_rules "pass" \
	    "pass in on ${a}b inet6 to 2001:db8:3::/64 route-to ${SRV6} dnpipe 1"
	m=$(dn_ping_min dncl -6 -c 3 -i 0.3 -t 20 2001:db8:3::2)
	echo "route-to, 64 bytes: min ${m} ms"
	dn_check "${m} >= 135" "route-to round trip with a 150 ms pipe"

	# The first 1448 byte packet is refused with "packet too big" after
	# the delay; the client learns the path MTU and fragments the next
	# ones, which pf reassembles and must still shape.
	r=$(dn_rtt dncl -6 -c 6 -i 0.5 -t 30 -s 1400 2001:db8:3::2)
	echo "route-to, 1400 bytes: ${r} (min avg ms)"
	[ -n "${r}" ] ||
	    atf_fail "no replies to 1400 byte pings (no packet too big?)"
	dn_check "${r% *} >= 135" "fragmented IPv6 route-to round trip"
}

route_to_v6_cleanup()
{
	integ_cleanup
}

atf_test_case "route_to_out_pipe" "cleanup"
route_to_out_pipe_head()
{
	atf_set descr 'An inbound route-to packet shaped by the outbound state of its route-to interface still goes to the route-to next hop'
	atf_set require.user root
	atf_set timeout 600
}

route_to_out_pipe_body()
{
	dn_route_to_setup
	dn_gw_rules "pass" \
	    "pass in on ${a}b inet to 203.0.113.0/24 route-to ${SRV4}" \
	    "pass out on ${b}a inet proto icmp dnpipe 1"
	m=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 203.0.113.2)
	echo "route-to, outbound pipe: min ${m} ms"
	dn_check "${m} >= 135" "route-to round trip with a 150 ms out pipe"
}

route_to_out_pipe_cleanup()
{
	integ_cleanup
}

atf_test_case "local_reply" "cleanup"
local_reply_head()
{
	atf_set descr 'dnpipe (a, b) on the end host: the replies the host sends (ICMP echo by the kernel, UDP by a program), IPv4 and IPv6, take the second pipe'
	atf_set require.user root
	atf_set timeout 600
}

local_reply_body()
{
	dn_router
	dn_ctl dnsrv pipe 1 config delay 100
	dn_ctl dnsrv pipe 2 config delay 400
	jexec dnsrv pfctl -e > /dev/null 2>&1
	pft_set_rules dnsrv "pass" "pass in on ${b}b dnpipe (1, 2)"

	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_dir ${SRV4} 7001 90 300 360 0
	dn_echo_stop ${e4} 7001 > /dev/null

	m4=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 ${SRV4})
	m6=$(dn_ping_min dncl -6 -c 3 -i 0.3 -t 20 ${SRV6})
	echo "echo round trips: IPv4 min ${m4} ms, IPv6 min ${m6} ms"
	dn_check "${m4} >= 450" "IPv4 echo reply skipped pipe 2"
	dn_check "${m6} >= 450" "IPv6 echo reply skipped pipe 2"
}

local_reply_cleanup()
{
	integ_cleanup
}

# dn_bridge_setup: jails dnl (192.0.2.1) and dnr (192.0.2.2) bridged by
# ${bridge} in jail dnbr, members ${l}b and ${r}a; pf on in dnbr and a
# 250 ms pipe 1.
dn_bridge_setup()
{
	dn_init
	vnet_init_bridge
	l=$(vnet_mkepair)
	r=$(vnet_mkepair)
	vnet_mkjail dnl ${l}a
	vnet_mkjail dnr ${r}b
	vnet_mkjail dnbr ${l}b ${r}a
	jexec dnl ifconfig ${l}a 192.0.2.1/24 up
	jexec dnr ifconfig ${r}b 192.0.2.2/24 up
	bridge=$(jexec dnbr ifconfig bridge create)
	jexec dnbr ifconfig ${l}b up
	jexec dnbr ifconfig ${r}a up
	jexec dnbr ifconfig ${bridge} addm ${l}b addm ${r}a up
	jexec dnbr pfctl -e > /dev/null 2>&1
	dn_noexpire dnbr
	dn_ctl dnbr pipe 1 config delay 250
}

# dn_bridge_mode member bridge
dn_bridge_mode()
{
	atf_check -s exit:0 -o ignore jexec dnbr sysctl \
	    net.link.bridge.pfil_member=$1 net.link.bridge.pfil_bridge=$2
}

# dn_bridge_check what rule: ping across the bridge with the rule loaded.
dn_bridge_check()
{
	pft_set_rules dnbr "pass" "$2"
	m=$(dn_ping_min dnl -c 3 -i 0.3 -t 20 192.0.2.2)
	echo "$1: min ${m} ms"
	dn_check "${m} >= 225" "$1: round trip with a 250 ms pipe"
}

atf_test_case "bridge" "cleanup"
bridge_head()
{
	atf_set descr 'dnpipe on bridged traffic: in and out on members (pfil_member=1) and on the bridge (pfil_bridge=1); shaped packets are still bridged'
	atf_set require.user root
	atf_set timeout 600
}

bridge_body()
{
	dn_bridge_setup
	dn_bridge_mode 1 0
	pft_set_rules dnbr "pass"
	m=$(dn_ping_min dnl -c 2 -t 10 192.0.2.2)
	echo "unshaped: min ${m} ms"

	dn_bridge_check "in on member" "pass in on ${l}b dnpipe 1"
	dn_bridge_check "out on member" "pass out on ${r}a dnpipe 1"
	dn_bridge_mode 0 1
	dn_bridge_check "in on bridge" "pass in on ${bridge} dnpipe 1"
	dn_bridge_check "out on bridge" "pass out on ${bridge} dnpipe 1"
}

bridge_cleanup()
{
	integ_cleanup
}

atf_test_case "bridge_ether" "cleanup"
bridge_ether_head()
{
	atf_set descr 'ether rules with dnpipe on bridged frames leaving a member (net.link.bridge.pfil_layer2=1); shaped frames are still bridged'
	atf_set require.user root
	atf_set timeout 600
}

bridge_ether_body()
{
	dn_bridge_setup
	atf_check -s exit:0 -o ignore jexec dnbr sysctl \
	    net.link.bridge.pfil_member=0 net.link.bridge.pfil_bridge=0 \
	    net.link.bridge.pfil_layer2=1
	pft_set_rules dnbr "ether pass out on ${r}a dnpipe 1" "pass"
	m=$(dn_ping_min dnl -c 3 -i 0.3 -t 20 192.0.2.2)
	echo "ether out on member: min ${m} ms"
	dn_check "${m} >= 225" "ether out on member: round trip with a 250 ms pipe"

	# Without the link-layer hook the ether rule does not see the frames.
	atf_check -s exit:0 -o ignore jexec dnbr sysctl \
	    net.link.bridge.pfil_layer2=0
	m=$(dn_ping_min dnl -c 3 -i 0.3 -t 20 192.0.2.2)
	echo "pfil_layer2=0: min ${m} ms"
	dn_check "${m} < 200" "pfil_layer2=0: not shaped"
}

bridge_ether_cleanup()
{
	integ_cleanup
}

atf_test_case "ether" "cleanup"
ether_head()
{
	atf_set descr 'Layer-2 "ether" rules with dnpipe delay frames in and out, IPv4 and IPv6; the IP rules still filter the shaped packets'
	atf_set require.user root
	atf_set timeout 600
}

ether_body()
{
	dn_router
	dn_ctl dngw pipe 1 config delay 250

	pft_set_rules dngw "ether pass in on ${a}b dnpipe 1" "pass"
	atf_check -s exit:0 -o match:"dnpipe 1" jexec dngw pfctl -s ethernet
	m4=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 ${SRV4})
	m6=$(dn_ping_min dncl -6 -c 3 -i 0.3 -t 20 ${SRV6})
	echo "ether in: IPv4 min ${m4} ms, IPv6 min ${m6} ms"
	dn_check "${m4} >= 225" "IPv4 round trip, ether in"
	dn_check "${m6} >= 225" "IPv6 round trip, ether in"

	pft_set_rules dngw "ether pass out on ${a}b dnpipe 1" "pass"
	m4=$(dn_ping_min dncl -c 3 -i 0.3 -t 20 ${SRV4})
	echo "ether out: IPv4 min ${m4} ms"
	dn_check "${m4} >= 225" "IPv4 round trip, ether out"

	# Shaped at layer 2, then blocked by an IP rule.
	pft_set_rules dngw "ether pass in on ${a}b dnpipe 1" \
	    "pass" "block in quick on ${a}b inet proto icmp"
	before=$(dn_counters dngw pipe 1)
	atf_check -s exit:2 -o ignore jexec dncl ping -c 2 -t 5 ${SRV4}
	after=$(dn_counters dngw pipe 1)
	echo "pipe 1 packets: ${before% *} -> ${after% *}"
	dn_check "${after% *} >= ${before% *} + 2" "blocked pings not shaped"
}

ether_cleanup()
{
	integ_cleanup
}

atf_test_case "reconfigure" "cleanup"
reconfigure_head()
{
	atf_set descr 'dnctl pipe reconfiguration takes effect at once, also for a transfer in progress'
	atf_set require.user root
	atf_set timeout 600
}

reconfigure_body()
{
	dn_router
	dn_ctl dngw pipe 1 config bw 1Mbit/s
	dn_gw_rules "pass" "pass out on ${b}a proto tcp dnpipe 1"
	r1=$(dn_tcp_rate ${SRV4} 5001 6)
	dn_ctl dngw pipe 1 config bw 4Mbit/s
	r4=$(dn_tcp_rate ${SRV4} 5002 6)
	echo "1 Mbit/s: ${r1} kbit/s, reconfigured to 4 Mbit/s: ${r4} kbit/s"
	dn_num "${r1}" "rate at 1 Mbit/s"
	dn_num "${r4}" "rate at 4 Mbit/s"
	dn_check "${r1} <= 1350" "1 Mbit/s pipe exceeded"
	dn_check "${r4} >= 2 * ${r1}" "faster after reconfiguration"
	atf_check -s exit:0 -o match:'4\.000 Mbit/s' jexec dngw dnctl pipe show 1

	# Back to 1 Mbit/s, then 8 Mbit/s 4 s into a 12 s transfer: about
	# (4 * 1 + 8 * 8) / 12 = 5.7 Mbit/s on average.
	dn_ctl dngw pipe 1 config bw 1Mbit/s
	dn_bulk_start ${SRV4} 5003 1 12
	sleep 4
	dn_ctl dngw pipe 1 config bw 8Mbit/s
	dn_bulk_wait
	cat sink.5003
	rm=$(awk '{ if ($3 > 0) printf "%d\n", $2 * 8 / $3; else print 0 }' \
	    sink.5003)
	echo "reconfigured during the transfer: ${rm} kbit/s"
	dn_num "${rm}" "rate of the reconfigured transfer"
	dn_check "${rm} >= 2 * ${r1}" "transfer in progress not sped up"
}

reconfigure_cleanup()
{
	integ_cleanup
}

atf_test_case "pipe_delete" "cleanup"
pipe_delete_head()
{
	atf_set descr 'Deleting or flushing pipes with packets queued drops them; traffic for a missing pipe is dropped until the pipe exists again'
	atf_set require.user root
	atf_set timeout 600
}

pipe_delete_body()
{
	dn_router
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_ctl dngw pipe 1 config delay 5000
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe 1"

	# Ten probes queued for 5 s; the pipe goes away meanwhile.
	dn_probe ${SRV4} 7001 -n 10 -i 20 -W 7000 > probe.1 &
	pp=$!
	dn_wait_pkts dngw pipe 1 10
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dngw dnctl pipe 1 delete
	wait ${pp}
	r=$(dn_echo_stop ${e4} 7001)
	echo "after delete: $(cat probe.1); server ${r}"
	atf_check_equal 0 "${r% *}"
	atf_check -s exit:0 -o empty jexec dngw dnctl pipe show

	# The rule still names pipe 1, which does not exist: dropped.
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	l=$(dn_probe ${SRV4} 7001 -n 10 -i 20 -W 1000)
	echo "missing pipe: ${l}"
	atf_check_equal 0 "$(dn_field "${l}" recv)"

	# Recreated, it shapes again.
	dn_ctl dngw pipe 1 config delay 50
	dn_dir ${SRV4} 7001 45 0 0 0

	# A flush with packets queued.
	dn_ctl dngw pipe 1 config delay 5000
	dn_probe ${SRV4} 7001 -n 10 -i 20 -W 7000 > probe.2 &
	pp=$!
	dn_wait_pkts dngw pipe 1 10
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dngw dnctl -f pipe flush
	wait ${pp}
	r=$(dn_echo_stop ${e4} 7001)
	echo "after flush: $(cat probe.2); server ${r}"
	# The server saw only the 20 probes of dn_dir.
	dn_check "${r% *} <= 20" "flushed packets were delivered"

	# The router is still fine.
	dn_ctl dngw pipe 1 config delay 10
	atf_check -s exit:0 -o ignore jexec dncl ping -c 2 -t 10 ${SRV4}
}

pipe_delete_cleanup()
{
	integ_cleanup
}

atf_test_case "reload_inflight" "cleanup"
reload_inflight_head()
{
	atf_set descr 'Replacing the ruleset and flushing the states while packets sit in a pipe: they are still delivered, not filtered again'
	atf_set require.user root
	atf_set timeout 600
}

reload_inflight_body()
{
	dn_router
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_ctl dngw pipe 1 config delay 4000
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe 1"

	dn_probe ${SRV4} 7001 -n 10 -i 20 -W 8000 > probe.1 &
	pp=$!
	dn_wait_pkts dngw pipe 1 10
	# pfctl -F all and "block": the queued requests pass when dummynet
	# returns them; the replies are blocked.
	dn_gw_rules "block"
	atf_check -s exit:0 -o empty jexec dngw pfctl -ss
	wait ${pp}
	r=$(dn_echo_stop ${e4} 7001)
	echo "probes: $(cat probe.1); server ${r}"
	atf_check_equal 10 "${r% *}"
	atf_check_equal 0 "$(dn_field "$(cat probe.1)" recv)"

	# New states take the pipe again.
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	dn_ctl dngw pipe 1 config delay 200
	dn_gw_rules "pass" "pass out on ${b}a proto udp dnpipe 1"
	dn_dir ${SRV4} 7001 180 0 0 0
	dn_echo_stop ${e4} 7001 > /dev/null
}

reload_inflight_cleanup()
{
	integ_cleanup
}

# dn_pair jail1 jail2 addr1 addr2: two VNET jails joined by an epair.
dn_pair()
{
	_e=$(vnet_mkepair)
	vnet_mkjail $1 ${_e}a
	vnet_mkjail $2 ${_e}b
	jexec $1 ifconfig ${_e}a $3/24 up
	jexec $2 ifconfig ${_e}b $4/24 up
	jexec $1 pfctl -e > /dev/null 2>&1
	dn_noexpire $1
}

atf_test_case "vnet_isolation" "cleanup"
vnet_isolation_head()
{
	atf_set descr 'Each VNET has its own dummynet configuration: a pipe in one jail is invisible to and does not shape another jail or the host'
	atf_set require.user root
	atf_set timeout 600
}

vnet_isolation_body()
{
	dn_init
	host_before=$(dnctl pipe show)
	dn_pair dnA dnA2 192.0.2.1 192.0.2.2
	dn_pair dnB dnB2 198.51.100.1 198.51.100.2

	dn_ctl dnA pipe 7 config delay 300
	pft_set_rules dnA "pass out dnpipe 7"
	pft_set_rules dnB "pass out dnpipe 7"

	atf_check -s exit:0 -o match:'^00007:' jexec dnA dnctl pipe show
	atf_check -s exit:0 -o empty jexec dnB dnctl pipe show
	m=$(dn_ping_min dnA -c 3 -i 0.3 -t 20 192.0.2.2)
	echo "jail A, its pipe 7: min ${m} ms"
	dn_check "${m} >= 270" "jail A round trip with its 300 ms pipe"
	# Jail B has no pipe 7: its matching packets are dropped.
	atf_check -s exit:2 -o ignore jexec dnB ping -c 2 -t 5 198.51.100.2

	# Same number, own configuration.
	dn_ctl dnB pipe 7 config delay 50
	r=$(dn_rtt dnB -c 3 -i 0.3 -t 20 198.51.100.2)
	echo "jail B, its pipe 7: ${r} (min avg ms)"
	[ -n "${r}" ] || atf_fail "jail B lost its pings"
	dn_check "${r% *} >= 45 && ${r#* } < 250" "jail B round trip"
	m=$(dn_ping_min dnA -c 2 -i 0.3 -t 20 192.0.2.2)
	dn_check "${m} >= 270" "jail A round trip after jail B's change"

	# Deleting A's pipe leaves B's.
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dnA dnctl pipe 7 delete
	atf_check -s exit:2 -o ignore jexec dnA ping -c 2 -t 5 192.0.2.2
	atf_check -s exit:0 -o ignore jexec dnB ping -c 2 -t 10 198.51.100.2
	atf_check -s exit:0 -o match:'^00007:' jexec dnB dnctl pipe show

	# The host's configuration never changed.
	atf_check_equal "${host_before}" "$(dnctl pipe show)"
}

vnet_isolation_cleanup()
{
	integ_cleanup
}

atf_test_case "jail_remove" "cleanup"
jail_remove_head()
{
	atf_set descr 'Removing a VNET jail while its pipes hold packets in both directions frees its dummynet state; dummynet keeps working'
	atf_set require.user root
	atf_set timeout 600
}

jail_remove_body()
{
	dn_init
	before=$(dn_malloc)
	e=$(vnet_mkepair)
	vnet_mkjail dnq ${e}b
	ifconfig ${e}a 192.0.2.1/24 up
	jexec dnq ifconfig ${e}b 192.0.2.2/24 up
	dn_noexpire dnq
	atf_check -s exit:0 -o ignore ping -c 1 -t 5 192.0.2.2

	dn_ctl dnq pipe 1 config delay 3000
	dn_ctl dnq pipe 2 config bw 100Kbit/s delay 3000
	jexec dnq pfctl -e > /dev/null 2>&1
	pft_set_rules dnq "pass dnpipe (1, 2)"

	# The rule's first pipe shapes the direction each state was created
	# in: inbound echo requests and the jail's outbound UDP take pipe 1,
	# the echo replies pipe 2 (after the 3 s delay of their requests).
	ping -c 20 -i 0.05 -t 15 192.0.2.2 > /dev/null 2>&1 &
	hp=$!
	jexec dnq ${DNFLOW} uprobe -n 40 -i 10 -W 100 192.0.2.1 9 \
	    > /dev/null 2>&1 &
	dn_wait_pkts dnq pipe 1 20
	dn_wait_pkts dnq pipe 2 5
	echo "jail dummynet: $(dn_counters dnq pipe 1), $(dn_counters dnq pipe 2)"

	jail -r dnq || atf_fail "cannot remove jail dnq"
	sed -i '' '/^dnq /d' created_jails.lst
	ifconfig ${e}a destroy
	unlist_interface ${e}a
	unlist_interface ${e}b
	wait ${hp}

	# The VNET's dummynet allocations go away with it.
	i=0
	while [ $(dn_malloc) -gt $((before + 2)) ]; do
		i=$((i + 1))
		[ ${i} -lt 120 ] ||
		    atf_fail "dummynet memory in use: $(dn_malloc), before ${before}"
		sleep 0.5
	done
	echo "dummynet allocations: before ${before}, after $(dn_malloc)"

	# A new jail shapes as before.
	dn_pair dnq2 dnq3 198.51.100.1 198.51.100.2
	dn_ctl dnq2 pipe 1 config delay 100
	pft_set_rules dnq2 "pass out dnpipe 1"
	m=$(dn_ping_min dnq2 -c 2 -i 0.3 -t 20 198.51.100.2)
	dn_check "${m} >= 90" "round trip in a new jail"
}

jail_remove_cleanup()
{
	integ_cleanup
}

atf_test_case "accounting" "cleanup"
accounting_head()
{
	atf_set descr 'dnctl pipe and queue counters count the shaped packets per direction; pfctl -sr -vv shows the dnpipe/dnqueue options and counts their packets'
	atf_set require.user root
	atf_set timeout 600
}

accounting_body()
{
	dn_router
	dn_ctl dngw pipe 1 config bw 10Mbit/s
	dn_ctl dngw pipe 2 config delay 10
	dn_ctl dngw pipe 4 config bw 10Mbit/s
	dn_ctl dngw queue 3 config pipe 4 weight 10
	dn_gw_rules "pass" \
	    "pass out on ${b}a proto icmp dnpipe (1, 2)" \
	    "pass out on ${b}a proto udp dnqueue 3"

	atf_check -s exit:0 -o match:'dnpipe\(1, 2\)' \
	    -o match:'dnqueue 3' jexec dngw pfctl -sr -vv
	atf_check -s exit:0 -o match:'^00001: +10\.000 Mbit/s' \
	    -o match:'^00002: .* 10 ms' jexec dngw dnctl pipe show
	atf_check -s exit:0 -o match:'^q00003 ' jexec dngw dnctl queue show

	atf_check -s exit:0 -o ignore jexec dncl ping -c 10 -i 0.1 -t 20 ${SRV4}
	dn_echo_start dnsrv 7001
	e4=${echo_pid}
	l=$(dn_probe ${SRV4} 7001 -n 20 -i 20 -W 2000)
	dn_echo_stop ${e4} 7001 > /dev/null

	p1=$(dn_counters dngw pipe 1)
	p2=$(dn_counters dngw pipe 2)
	q3=$(dn_counters dngw queue 3)
	echo "pipe 1 ${p1}, pipe 2 ${p2}, queue 3 ${q3} (packets drops)"
	# Requests through pipe 1, replies through pipe 2, UDP through
	# queue 3 only.
	dn_check "${p1% *} >= 10" "pipe 1 counts the echo requests"
	dn_check "${p2% *} >= 10" "pipe 2 counts the echo replies"
	dn_check "${q3% *} >= 20" "queue 3 counts the UDP probes"
	dn_check "${p1% *} < 20 && ${p2% *} < 20" "UDP counted in a pipe"

	pkts=$(jexec dngw pfctl -sr -vv | awk '/dnpipe\(1, 2\)/ { getline;
	    for (i = 1; i < NF; i++) if ($i == "Packets:") print $(i + 1) }')
	echo "pfctl rule packets: ${pkts}"
	dn_num "${pkts}" "rule packet counter"
	dn_check "${pkts} >= 15" "dnpipe rule packet counter"
	atf_check -s exit:0 -o match:'icmp' -o match:'udp' jexec dngw pfctl -ss
}

accounting_cleanup()
{
	integ_cleanup
}

atf_test_case "securelevel" "cleanup"
securelevel_head()
{
	atf_set descr 'At a VNET jail securelevel 3 dnctl cannot change pipes (EPERM) but can list them and existing pipes keep shaping; securelevel 2 still allows dnctl'
	atf_set require.user root
	atf_set timeout 600
}

securelevel_body()
{
	dn_init
	dn_pair dnsl dnsl2 192.0.2.1 192.0.2.2
	dn_ctl dnsl pipe 1 config delay 200
	pft_set_rules dnsl "pass out dnpipe 1"

	atf_check -s exit:0 jail -m name=dnsl securelevel=2
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dnsl dnctl pipe 2 config delay 10
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dnsl dnctl pipe 2 delete

	atf_check -s exit:0 jail -m name=dnsl securelevel=3
	atf_check -s exit:0 -o inline:'3\n' jexec dnsl sysctl -n kern.securelevel
	atf_check -s not-exit:0 -o ignore -e match:'not permitted' \
	    jexec dnsl dnctl pipe 1 config delay 10
	atf_check -s not-exit:0 -o ignore -e match:'not permitted' \
	    jexec dnsl dnctl pipe 2 config bw 1Mbit/s
	atf_check -s not-exit:0 -o ignore -e match:'not permitted' \
	    jexec dnsl dnctl pipe 1 delete
	atf_check -s not-exit:0 -o ignore -e match:'not permitted' \
	    jexec dnsl dnctl -f pipe flush
	atf_check -s exit:0 -o match:'^00001: .* 200 ms' \
	    -o not-match:'^00002:' jexec dnsl dnctl pipe show

	m=$(dn_ping_min dnsl -c 3 -i 0.3 -t 20 192.0.2.2)
	echo "securelevel 3: min ${m} ms"
	dn_check "${m} >= 180" "the existing pipe stopped shaping"

	# The other jail is not locked.
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec dnsl2 dnctl pipe 1 config delay 10
	atf_check -s exit:0 -o match:'^00001: .* 10 ms' \
	    jexec dnsl2 dnctl pipe show
}

securelevel_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "bandwidth_v4"
	atf_add_test_case "bandwidth_v6"
	atf_add_test_case "delay_icmp"
	atf_add_test_case "direction"
	atf_add_test_case "loss"
	atf_add_test_case "weights_wf2q"
	atf_add_test_case "weights_qfq"
	atf_add_test_case "fq_codel_latency"
	atf_add_test_case "priority"
	atf_add_test_case "many_flows"
	atf_add_test_case "nat"
	atf_add_test_case "rdr"
	atf_add_test_case "rdr_loopback"
	atf_add_test_case "route_to_v4"
	atf_add_test_case "route_to_v6"
	atf_add_test_case "route_to_out_pipe"
	atf_add_test_case "local_reply"
	atf_add_test_case "bridge"
	atf_add_test_case "bridge_ether"
	atf_add_test_case "ether"
	atf_add_test_case "reconfigure"
	atf_add_test_case "pipe_delete"
	atf_add_test_case "reload_inflight"
	atf_add_test_case "vnet_isolation"
	atf_add_test_case "jail_remove"
	atf_add_test_case "accounting"
	atf_add_test_case "securelevel"
}

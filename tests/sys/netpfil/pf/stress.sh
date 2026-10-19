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

# Concurrency stress for pf: traffic through a router while its rulesets,
# anchors, tables, states, source nodes, interfaces, interface groups,
# addresses, pfsync, pflog and neighbouring VNET jails change under it.
# The kernel must keep forwarding and log no lock order reversal, panic,
# assertion or pf leak report.  ATF variable "duration" (seconds, default
# 120) lengthens a run for soak testing.

. $(atf_get_srcdir)/utils.subr

# A random number (sh(1) has no $RANDOM).
rnd()
{
	jot -r 1 0 32767
}

# Seconds until the workers stop.
stress_deadline()
{
	echo $(( $(date +%s) + $(atf_config_get duration 120) ))
}

# The router's two rulesets, swapped while traffic flows.
stress_rules_a()
{
	cat <<EOF
table <t1> persist { 192.0.2.0/24 }
table <t2> persist
set reassemble yes
match in all scrub (no-df random-id max-mss 1400)
match out on ${epair_two}a inet from 192.0.2.0/24 nat-to (${epair_two}a)
match out on ${epair_two}a inet6 from 2001:db8::/64 nat-to (${epair_two}a)
pass all
pass in on stressgrp proto tcp from <t1> keep state (source-track rule, max-src-conn 2000)
pass in proto udp from <t1> keep state (sloppy)
pass in log proto icmp from (${epair_one}b:network)
anchor "a/*"
anchor "b"
EOF
}

stress_rules_b()
{
	cat <<EOF
table <t1> persist { 192.0.2.0/24 }
table <t3> persist { 10.0.0.0/8 }
set reassemble no
match out on egress inet from 192.0.2.0/24 nat-to (egress:0)
pass all
pass in on ${epair_one}b inet proto tcp to port 8080 rdr-to 198.51.100.2 port 7
pass in on ${epair_one}b proto tcp from <t1> modulate state
block in quick from <t3>
anchor "a/*"
EOF
}

# Run "$@" in a loop until the deadline, in the background.
stress_loop()
{
	(
		while [ $(date +%s) -lt $deadline ]; do
			"$@" >/dev/null 2>&1
		done
	) &
	workers="$workers $!"
}

stress_rules()
{
	if [ $(( $(rnd) % 2)) -eq 0 ]; then
		stress_rules_a | jexec gw pfctl -f -
	else
		stress_rules_b | jexec gw pfctl -f -
	fi
}

stress_anchors()
{
	printf "pass in proto tcp to port %d\nanchor \"c\"\n" $(( $(rnd) % 1000 + 1)) |
	    jexec gw pfctl -a "a/b$(( $(rnd) % 4))" -f -
	printf "block in quick proto udp to port %d\n" $(( $(rnd) % 1000 + 1)) |
	    jexec gw pfctl -a "a/b$(( $(rnd) % 4))/c" -f -
	jexec gw pfctl -a "a/b$(( $(rnd) % 4))" -F all
	jexec gw pfctl -a "b" -F rules
}

stress_tables()
{
	n=$(( $(rnd) % 250 + 1))
	jexec gw pfctl -t t2 -T add 198.51.100.$n 2001:db8:1::$n 10.$n.0.0/16
	jexec gw pfctl -t t2 -T delete 198.51.100.$(( $(rnd) % 250 + 1))
	jexec gw pfctl -t t2 -T replace 10.0.$n.0/24 192.0.2.$n
	jexec gw pfctl -t t2 -T expire 1
	jexec gw pfctl -a "a/b$(( $(rnd) % 4))" -t at -T add 192.0.2.$n
	jexec gw pfctl -t t2 -T flush
}

stress_states()
{
	jexec gw pfctl -k 192.0.2.2
	jexec gw pfctl -K 192.0.2.2
	jexec gw pfctl -F states
	jexec gw pfctl -ss -vv
	jexec gw pfctl -s Sources
	jexec gw pfctl -si -v
	jexec gw pfctl -sI -v
	jexec gw pfctl -F Sources
}

stress_ifaces()
{
	e=$(ifconfig epair create)
	e=${e%a}
	ifconfig ${e}a vnet gw
	jexec gw ifconfig ${e}a 203.0.113.$(( $(rnd) % 250 + 1))/24 up
	jexec gw ifconfig ${e}a group stressgrp
	jexec gw ifconfig ${epair_one}b group stressgrp
	jexec gw ifconfig ${epair_one}b -group stressgrp
	jexec gw ifconfig ${epair_one}b inet 192.0.2.$(( $(rnd) % 200 + 10))/32 alias
	jexec gw ifconfig ${epair_one}b inet6 2001:db8::$(( $(rnd) % 200 + 10))/128 alias
	jexec gw ifconfig ${e}a destroy
	ifconfig ${e}b destroy
	jexec gw ifconfig ${epair_one}b inet 192.0.2.$(( $(rnd) % 200 + 10))/32 -alias
}

stress_logsync()
{
	jexec gw ifconfig pfsync0 syncdev ${epair_sync}a up
	jexec gw ifconfig pflog1 create
	jexec gw ifconfig pfsync0 down
	jexec gw ifconfig pfsync0 -syncdev
	jexec gw ifconfig pflog1 destroy
}

stress_jails()
{
	j=stress$(( $(rnd) % 4))
	e=$(ifconfig epair create)
	e=${e%a}
	jail -c name=$j vnet persist && ifconfig ${e}b vnet $j &&
	    jexec $j ifconfig ${e}b 198.18.0.1/24 up &&
	    jexec $j pfctl -e &&
	    printf "pass all\nblock in proto udp\nanchor \"x/*\"\n" |
	    jexec $j pfctl -f - &&
	    jexec $j pfctl -a x/y -t tt -T add 198.18.0.$(( $(rnd) % 250))
	ping -c 1 -t 1 198.18.0.1
	jail -r $j
	ifconfig ${e}a destroy
}

stress_traffic()
{
	jexec cl ping -q -c 50 -i 0.01 198.51.100.2
	jexec cl ping -q -c 5 -s 3000 198.51.100.2
	jexec cl ping -6 -q -c 20 -i 0.02 2001:db8:1::2
	jexec cl nc -z -w 1 198.51.100.2 7
	jexec cl nc -z -w 1 198.51.100.2 8080
	echo stress | jexec cl nc -u -w 1 198.51.100.2 9
}

atf_test_case "churn" "cleanup"
churn_head()
{
	atf_set descr "Traffic through pf while everything around it changes"
	atf_set require.user root
	atf_set timeout 1800
}

churn_body()
{
	pfsynct_init

	epair_one=$(vnet_mkepair)
	epair_two=$(vnet_mkepair)
	epair_sync=$(vnet_mkepair)

	vnet_mkjail cl ${epair_one}a
	vnet_mkjail gw ${epair_one}b ${epair_two}a ${epair_sync}a
	vnet_mkjail sv ${epair_two}b
	vnet_mkjail peer ${epair_sync}b

	jexec cl ifconfig ${epair_one}a 192.0.2.2/24 up
	jexec cl ifconfig ${epair_one}a inet6 2001:db8::2/64 no_dad
	jexec cl route add default 192.0.2.1
	jexec cl route add -6 default 2001:db8::1
	jexec gw ifconfig ${epair_one}b 192.0.2.1/24 up
	jexec gw ifconfig ${epair_one}b inet6 2001:db8::1/64 no_dad
	jexec gw ifconfig ${epair_two}a 198.51.100.1/24 up
	jexec gw ifconfig ${epair_two}a inet6 2001:db8:1::1/64 no_dad
	jexec gw ifconfig ${epair_sync}a 203.0.113.1/24 up
	jexec gw ifconfig ${epair_two}a group egress
	jexec gw sysctl net.inet.ip.forwarding=1
	jexec gw sysctl net.inet6.ip6.forwarding=1
	jexec sv ifconfig ${epair_two}b 198.51.100.2/24 up
	jexec sv ifconfig ${epair_two}b inet6 2001:db8:1::2/64 no_dad
	jexec sv route add default 198.51.100.1
	jexec sv route add -6 default 2001:db8:1::1
	jexec sv inetd -p /dev/null $(atf_get_srcdir)/echo_inetd.conf
	jexec peer ifconfig ${epair_sync}b 203.0.113.2/24 up
	pfsynct_mkif gw
	pfsynct_mkif peer
	jexec peer ifconfig pfsync0 syncdev ${epair_sync}b up
	jexec peer pfctl -e
	jexec gw pfctl -e
	stress_rules_a | jexec gw pfctl -f - ||
	    atf_fail "loading the router's rules"
	atf_check -s exit:0 -o ignore jexec cl ping -c 2 198.51.100.2

	msgs=$(dmesg | wc -l)
	deadline=$(stress_deadline)
	workers=""
	stress_loop stress_traffic
	stress_loop stress_traffic
	stress_loop stress_rules
	stress_loop stress_anchors
	stress_loop stress_tables
	stress_loop stress_states
	stress_loop stress_ifaces
	stress_loop stress_logsync
	stress_loop stress_jails
	for w in $workers; do
		wait $w
	done

	# Still a router: a known ruleset forwards.
	stress_rules_a | jexec gw pfctl -f - ||
	    atf_fail "loading the router's rules after the churn"
	jexec gw pfctl -a "a/*" -F all
	atf_check -s exit:0 -o ignore jexec cl ping -c 2 -t 10 198.51.100.2
	atf_check -s exit:0 -o ignore jexec cl ping -6 -c 2 -t 10 2001:db8:1::2

	# Nothing the kernel's checks complain about.
	if dmesg | tail -n +$((msgs + 1)) |
	    grep -E "lock order reversal|panic|KASSERT|WARNING|torn down with"; then
		atf_fail "the kernel reported problems during the churn"
	fi
}

churn_cleanup()
{
	for j in stress0 stress1 stress2 stress3; do
		jail -r $j 2>/dev/null
	done
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "churn"
}

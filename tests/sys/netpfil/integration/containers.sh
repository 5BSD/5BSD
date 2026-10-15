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

# Container networking as podman's CNI plugins drive it
# (net/containernetworking-plugins in 5BSD-ports), without podman: a
# container host jail with a bridge, a container jail on an epair member,
# and an outside jail on the host's default route.  The pf input is what
# the plugins and their sample pf.conf use on 5BSD:
#   - the sample ruleset: table <cni-nat>, match ... nat-to (egress:0),
#     anchor "cni-rdr/*";
#   - ipmasq: pfctl -t cni-nat -T add|delete <container address>;
#   - portmap: pfctl -a cni-rdr/<id> -f - with "pass in ... rdr-to" and
#     "pass out on <bridge> ... from (lo0) ... nat-to (<bridge>)", removed
#     with pfctl -a cni-rdr/<id> -F rules.
# Keep these strings in step with the port's patch and pf.conf.sample.

. $(atf_get_srcdir)/integration.subr

# The anchor name portmap derives from a container ID (its first 32 chars).
CNI_ID=0123456789abcdef0123456789abcdef

cni_sample()
{
	cat <<'EOF'
table <cni-nat> persist
match out on egress inet from <cni-nat> to any nat-to (egress:0)
match out on egress inet6 from <cni-nat> to !ff00::/8 nat-to (egress:0)
pass
anchor "cni-rdr/*"
EOF
}

# cni_setup: jail "host" routes between bridge ${br} (10.88.0.1/16,
# fd88::1/64) and ${o}a (198.51.100.1/24, 2001:db8::1/64, default routes
# via jail "out").  Container jail "ctr" is 10.88.0.2/16 and fd88::2/64 on
# ${c}b, whose peer ${c}a is a bridge member.  "out" has no route to the
# container networks, so it only reaches them through translation.
cni_setup()
{
	pft_init
	vnet_init_bridge
	o=$(vnet_mkepair)
	c=$(vnet_mkepair)
	vnet_mkjail host ${o}a ${c}a
	vnet_mkjail out ${o}b
	vnet_mkjail ctr ${c}b

	jexec out ifconfig ${o}b 198.51.100.2/24 up
	jexec out ifconfig ${o}b inet6 2001:db8::2/64 no_dad

	jexec host ifconfig ${o}a 198.51.100.1/24 up
	jexec host ifconfig ${o}a inet6 2001:db8::1/64 no_dad
	jexec host route -q add default 198.51.100.2
	jexec host route -q add -inet6 default 2001:db8::2
	jexec host sysctl -q net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1
	# The bridge plugin: "ifconfig bridge create name ...", an address
	# alias, members, and net.link.bridge.pfil_member=1.
	br=cnitest0
	jexec host ifconfig bridge create name ${br} >/dev/null ||
	    atf_fail "cannot create bridge ${br}"
	jexec host ifconfig ${br} inet alias 10.88.0.1/16
	jexec host ifconfig ${br} inet6 alias fd88::1/64 no_dad
	jexec host ifconfig ${br} addm ${c}a up
	jexec host ifconfig ${c}a up
	jexec host sysctl -q net.link.bridge.pfil_member=1

	jexec ctr ifconfig ${c}b 10.88.0.2/16 up
	jexec ctr ifconfig ${c}b inet6 fd88::2/64 no_dad
	jexec ctr route -q add default 10.88.0.1
	jexec ctr route -q add -inet6 default fd88::1

	cni_sample | jexec host pfctl -f - ||
	    atf_fail "the CNI sample ruleset does not load"
	jexec host pfctl -e >/dev/null 2>&1
}

# cni_portmap rule...: load rules into the container's cni-rdr anchor as
# the portmap plugin does.
cni_portmap()
{
	printf '%s\n' "$@" | atf_check -s exit:0 \
	    jexec host pfctl -a cni-rdr/${CNI_ID} -f -
}

# cni_serve af port: a TCP server in "ctr" answering "hello" on every
# connection.
cni_serve()
{
	jexec ctr daemon -f sh -c \
	    "while :; do echo hello | nc -N -$1 -l $2; done"
	sleep 1
}

atf_test_case "egress_group" "cleanup"
egress_group_head()
{
	atf_set descr 'The egress group the CNI sample uses holds the interface of the default routes'
	atf_set require.user root
}

egress_group_body()
{
	cni_setup
	atf_check -s exit:0 -o match:"${o}a" jexec host ifconfig -g egress
	atf_check -s exit:0 -o not-match:"${br}" jexec host ifconfig -g egress
}

egress_group_cleanup()
{
	pft_cleanup
}

atf_test_case "masquerade" "cleanup"
masquerade_head()
{
	atf_set descr 'Container addresses in <cni-nat> (ipmasq) reach the outside through nat-to (egress:0)'
	atf_set require.user root
}

masquerade_body()
{
	cni_setup

	# Not in the table yet: "out" has no route back to 10.88/16.
	atf_check -s exit:2 -o ignore jexec ctr ping -c 1 -t 2 198.51.100.2

	atf_check -s exit:0 -e ignore \
	    jexec host pfctl -t cni-nat -T add 10.88.0.2
	atf_check -s exit:0 -o ignore jexec ctr ping -c 3 -t 5 198.51.100.2
	atf_check -s exit:0 -o match:"198.51.100.1:[0-9]+ \(10.88.0.2:" \
	    jexec host pfctl -ss

	# TCP, translated the same way: the server sees the host's address.
	jexec out daemon -f sh -c \
	    "nc -l 7000 -v > /dev/null 2> ${PWD}/peer.out"
	sleep 1
	atf_check -s exit:0 jexec ctr nc -w 3 -z 198.51.100.2 7000
	sleep 1
	atf_check -s exit:0 -o match:"198.51.100.1" cat ${PWD}/peer.out

	jexec host pfctl -Fs >/dev/null 2>&1
	atf_check -s exit:0 -e ignore \
	    jexec host pfctl -t cni-nat -T delete 10.88.0.2
	atf_check -s exit:2 -o ignore jexec ctr ping -c 1 -t 2 198.51.100.2
}

masquerade_cleanup()
{
	pft_cleanup
}

atf_test_case "masquerade6" "cleanup"
masquerade6_head()
{
	atf_set descr 'IPv6 container addresses in <cni-nat> are translated to the egress address'
	atf_set require.user root
}

masquerade6_body()
{
	cni_setup
	atf_check -s exit:0 -e ignore \
	    jexec host pfctl -t cni-nat -T add fd88::2
	atf_check -s exit:0 -o ignore jexec ctr ping -6 -c 3 -t 5 2001:db8::2
	atf_check -s exit:0 -o match:"2001:db8::1\[[0-9]+\] \(fd88::2\[" \
	    jexec host pfctl -ss
}

masquerade6_cleanup()
{
	pft_cleanup
}

atf_test_case "portmap" "cleanup"
portmap_head()
{
	atf_set descr 'A published port (portmap: pass in ... rdr-to in cni-rdr/<id>) is reachable from outside'
	atf_set require.user root
}

portmap_body()
{
	cni_setup
	cni_serve 4 80
	cni_portmap \
	    "pass in inet proto tcp from any to self port 8080 rdr-to 10.88.0.2 port 80" \
	    "pass out on ${br} inet proto tcp from (lo0) to 10.88.0.2 port 80 nat-to (${br})"
	atf_check -s exit:0 -o match:"rdr-to 10.88.0.2 port 80" \
	    jexec host pfctl -a cni-rdr/${CNI_ID} -sr
	# The main ruleset reaches the nested anchor through cni-rdr/*.
	atf_check -s exit:0 -o match:"${CNI_ID}" jexec host pfctl -a cni-rdr -s Anchors

	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec out nc -w 3 198.51.100.1 8080
	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec out nc -w 3 198.51.100.1 8080
}

portmap_cleanup()
{
	pft_cleanup
}

atf_test_case "portmap6" "cleanup"
portmap6_head()
{
	atf_set descr 'An IPv6 published port is reachable from outside'
	atf_set require.user root
}

portmap6_body()
{
	cni_setup
	cni_serve 6 80
	cni_portmap \
	    "pass in inet6 proto tcp from any to self port 8080 rdr-to fd88::2 port 80"
	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec out nc -6 -w 3 2001:db8::1 8080
}

portmap6_cleanup()
{
	pft_cleanup
}

atf_test_case "portmap_local" "cleanup"
portmap_local_head()
{
	atf_set descr 'A published port is reachable from the container host itself (lo0 and its own address)'
	atf_set require.user root
}

portmap_local_body()
{
	cni_setup
	cni_serve 4 80
	cni_portmap \
	    "pass in inet proto tcp from any to self port 8080 rdr-to 10.88.0.2 port 80" \
	    "pass out on ${br} inet proto tcp from (lo0) to 10.88.0.2 port 80 nat-to (${br})"
	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec host nc -w 3 127.0.0.1 8080
	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec host nc -w 3 198.51.100.1 8080
}

portmap_local_cleanup()
{
	pft_cleanup
}

atf_test_case "portmap_teardown" "cleanup"
portmap_teardown_head()
{
	atf_set descr 'Removing a container flushes its anchor with -F rules; -F nat does not exist in OpenBSD pfctl'
	atf_set require.user root
}

portmap_teardown_body()
{
	cni_setup
	cni_serve 4 80
	cni_portmap \
	    "pass in inet proto tcp from any to self port 8080 rdr-to 10.88.0.2 port 80"
	atf_check -s exit:0 -o inline:"hello\n" \
	    jexec out nc -w 3 198.51.100.1 8080

	# The FreeBSD plugin's teardown fails here and would leave the
	# redirection behind.
	atf_check -s not-exit:0 -e match:"nat" \
	    jexec host pfctl -a cni-rdr/${CNI_ID} -F nat
	atf_check -s exit:0 -e ignore \
	    jexec host pfctl -a cni-rdr/${CNI_ID} -F rules
	atf_check -s exit:0 -o empty jexec host pfctl -a cni-rdr/${CNI_ID} -sr
	jexec host pfctl -Fs >/dev/null 2>&1
	atf_check -s not-exit:0 -o empty \
	    jexec out nc -w 3 198.51.100.1 8080
}

portmap_teardown_cleanup()
{
	pft_cleanup
}

atf_test_case "freebsd_syntax_refused" "cleanup"
freebsd_syntax_refused_head()
{
	atf_set descr 'The FreeBSD CNI rules (rdr pass ... ->, nat on ... ->, rdr-anchor) are refused, not misread'
	atf_set require.user root
}

freebsd_syntax_refused_body()
{
	pft_init
	vnet_mkjail host
	for r in \
	    "rdr pass inet proto tcp from any to self port 8080 -> 10.88.0.2 port 80" \
	    "nat on lo0 inet proto tcp from (lo0) to 10.88.0.2 port 80 -> (lo0)" \
	    "nat on lo0 inet from <cni-nat> to any -> (lo0)" \
	    'rdr-anchor "cni-rdr/*"' \
	    'nat-anchor "cni-rdr/*"'; do
		echo "${r}" | atf_check -s not-exit:0 -e not-empty \
		    jexec host pfctl -nf -
	done
}

freebsd_syntax_refused_cleanup()
{
	pft_cleanup
}

atf_test_case "local_reset" "cleanup"
local_reset_head()
{
	atf_set descr 'A refused local connection: the TCP reset does not carry the input packet\'s pf state key'
	atf_set require.user root
}

local_reset_body()
{
	# podman pulling from an absent local registry hit this: tcp_respond()
	# reuses the SYN for the RST, and pf logged "state key linking
	# mismatch! dir=OUT, if=lo0".
	pft_init
	vnet_mkjail host
	jexec host ifconfig lo0 inet 127.0.0.1/8 up
	jexec host ifconfig lo0 inet6 ::1/128
	echo "pass" | jexec host pfctl -f - || atf_fail "cannot load rules"
	jexec host pfctl -e >/dev/null 2>&1
	before=$(dmesg | grep -c "state key linking mismatch")
	for i in 1 2 3; do
		atf_check -s not-exit:0 -e ignore \
		    jexec host nc -z -w 2 127.0.0.1 443
		atf_check -s not-exit:0 -e ignore \
		    jexec host nc -6 -z -w 2 ::1 443
	done
	after=$(dmesg | grep -c "state key linking mismatch")
	atf_check_equal "${before}" "${after}"
}

local_reset_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "egress_group"
	atf_add_test_case "masquerade"
	atf_add_test_case "masquerade6"
	atf_add_test_case "portmap"
	atf_add_test_case "portmap6"
	atf_add_test_case "portmap_local"
	atf_add_test_case "portmap_teardown"
	atf_add_test_case "freebsd_syntax_refused"
	atf_add_test_case "local_reset"
}

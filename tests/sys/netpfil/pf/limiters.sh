#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Rubicon Communications, LLC (Netgate)
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

. $(atf_get_srcdir)/utils.subr

# A failed show command or missing counter must not become a passing test.
limiter_counter_nonzero()
{
	atf_check -s exit:0 -o save:limiter.stats -e empty \
	    jexec "$1" pfctl -s "$2"
	value=$(awk -v id="$3" -v name="$4" '
	    NR == 1 { for (i = 1; i <= NF; i++) if ($i == name) col = i; next }
	    $1 == id && col { print $col }
	' limiter.stats)
	case "$value" in
	''|*[!0-9]*) atf_fail "Missing or invalid $4 counter for limiter $3" ;;
	esac
	[ "$value" -gt 0 ] || atf_fail "$4 counter not incremented for limiter $3"
}

atf_test_case "state_basic" "cleanup"
state_basic_head()
{
	atf_set descr 'Basic state limiter test'
	atf_set require.user root
}

state_basic_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	# Allow up to one ICMP state.
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "state limiter \"server\" id 1 limit 1" \
	    "block in proto icmp" \
	    "pass in proto icmp state limiter \"server\" (no-match)"

	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1

	# This should now fail
	atf_check -s exit:2 -o ignore \
	    ping -c 2 192.0.2.1

	limiter_counter_nonzero alcatraz Stlimiters 1 HARDLIM
}

state_basic_cleanup()
{
	pft_cleanup
}

atf_test_case "state_rate" "cleanup"
state_rate_head()
{
	atf_set descr 'State rate limiting test'
	atf_set require.user root
}

state_rate_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	# Allow one ICMP state per 5 seconds
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "state limiter \"server\" id 1 limit 1000 rate 1/5" \
	    "block in proto icmp" \
	    "pass in proto icmp state limiter \"server\" (no-match)"

	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1

	# This should now fail
	atf_check -s exit:2 -o ignore \
	    ping -c 2 192.0.2.1

	limiter_counter_nonzero alcatraz Stlimiters 1 RATELIM

	sleep 6

	# We can now create another state
	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1
}

state_rate_cleanup()
{
	pft_cleanup
}

atf_test_case "state_block" "cleanup"
state_block_head()
{
	atf_set descr 'Test block mode state limiter'
	atf_set require.user root
}

state_block_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	# Allow one ICMP state per 5 seconds
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "state limiter \"server\" id 1 limit 1000 rate 1/5" \
	    "pass" \
	    "pass in proto icmp state limiter \"server\" (block)"

	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1

	# This should now fail
	atf_check -s exit:2 -o ignore \
	    ping -c 2 192.0.2.1

	# However, if we set no-match and exceed the limit we just pass
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "state limiter \"server\" id 1 limit 1000 rate 1/5" \
	    "pass" \
	    "pass in proto icmp state limiter \"server\" (no-match)"

	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1
	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1
}

state_block_cleanup()
{
	pft_cleanup
}

atf_test_case "state_multiple" "cleanup"
state_multiple_head()
{
	atf_set descr 'Create multiple state limiters'
	atf_set require.user root
}

state_multiple_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -c 1 192.0.2.1

	jexec alcatraz pfctl -e
	# Allow up to one ICMP state.
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "state limiter \"server\" id 1 limit 1" \
	    "state limiter \"client\" id 2 limit 1" \
	    "block in proto icmp" \
	    "pass in proto icmp state limiter \"server\" (no-match)"

	atf_check -s exit:0 -o ignore \
	    ping -c 2 192.0.2.1

	# This should now fail
	atf_check -s exit:2 -o ignore \
	    ping -c 2 192.0.2.1

	limiter_counter_nonzero alcatraz Stlimiters 1 HARDLIM
}

state_multiple_cleanup()
{
	pft_cleanup
}

atf_test_case "source_basic" "cleanup"
source_basic_head()
{
	atf_set descr 'Basic source limiter test'
	atf_set require.user root
}

source_basic_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up
	ifconfig ${epair}a inet alias 192.0.2.3/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.2 -c 1 192.0.2.1
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.3 -c 1 192.0.2.1

	jexec alcatraz pfctl -e

	# Allow up to one source for ICMP.
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "source limiter \"server\" id 1 entries 128 limit 1" \
	    "block in proto icmp" \
	    "pass in proto icmp source limiter \"server\" (no-match)"

	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.2 -c 2 192.0.2.1

	# This should now fail
	atf_check -s exit:2 -o ignore \
	    ping -S 192.0.2.2 -c 2 192.0.2.1

	limiter_counter_nonzero alcatraz Srclimiters 1 HARDLIM

	# However, a different source will succeed
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.3 -c 2 192.0.2.1

	atf_check -o match:"192.0.2.2/32 .*hardlim 2 ratelim 0" \
	    -e ignore \
	    jexec alcatraz pfctl -sSrclimiters -v
	atf_check -o match:"192.0.2.3/32 .*hardlim 0 ratelim 0" \
	    -e ignore \
	    jexec alcatraz pfctl -sSrclimiters -v

	# Kill the source entry
	atf_check -s exit:0 -e ignore \
	    jexec alcatraz pfctl -I 1 -k source -k 192.0.2.2
	# Now we can ping again from it
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.2 -c 2 192.0.2.1
}

source_basic_cleanup()
{
	pft_cleanup
}

atf_test_case "out" "cleanup"
out_head()
{
	atf_set descr 'Test limiters on outbound rules'
	atf_set require.user root
}

out_body()
{
	pft_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a 192.0.2.2/24 up
	ifconfig ${epair}a inet alias 192.0.2.3/24 up

	vnet_mkjail alcatraz ${epair}b
	jexec alcatraz ifconfig ${epair}b 192.0.2.1/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.2 -c 1 192.0.2.1
	atf_check -s exit:0 -o ignore \
	    ping -S 192.0.2.3 -c 1 192.0.2.1

	jexec alcatraz pfctl -e

	# Exercise admission on an outbound request.  ICMP reply packets do
	# not create state unless sloppy state tracking is explicitly selected.
	pft_set_rules alcatraz \
	    "set timeout icmp.error 120" \
	    "source limiter \"crash\" id 1 entries 10000 limit 1000" \
	    "block out proto icmp" \
	    "pass out from any to any source limiter \"crash\" keep state"

	atf_check -s exit:0 -o ignore \
	    jexec alcatraz ping -c 2 192.0.2.2

	limiter_counter_nonzero alcatraz Srclimiters 1 ADMIT
	jexec alcatraz pfctl -Fs
}

out_cleanup()
{
	pft_cleanup
}

atf_test_case "show_aliases" "cleanup"
show_aliases_head()
{
	atf_set descr 'OpenBSD limiter names work and obsolete or ambiguous names fail'
	atf_set require.user root
}
show_aliases_body()
{
	pft_init
	vnet_mkjail alcatraz
	pft_set_rules alcatraz \
	    'state limiter "state-test" id 1 limit 5' \
	    'source limiter "source-test" id 2 entries 128 limit 3' \
	    'pass'
	atf_check -s exit:0 -o save:states -e empty jexec alcatraz pfctl -s Stlimiters
	atf_check -s exit:0 -o save:sources -e empty jexec alcatraz pfctl -s Srclimiters
	atf_check -s exit:0 -o match:"1[[:space:]]+0/5" cat states
	atf_check -s exit:0 -o match:"^[[:space:]]*2[[:space:]]+0/128[[:space:]]+3[[:space:]]" cat sources
	atf_check -s exit:0 -o empty -e empty jexec alcatraz pfctl -s Sources
	for name in LimiterStates LimiterSrcs S; do
		atf_check -s exit:1 -o ignore -e ignore \
		    jexec alcatraz pfctl -s "$name"
	done
}
show_aliases_cleanup()
{
	pft_cleanup
}

# Exercise entry capacity, independently of the per-source state limit.
# A later pass rule makes an accidental no-match distinguishable from block.
source_capacity_test()
{
	family=$1
	action=$2
	pft_init
	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}b
	if [ "$family" = inet ]; then
		prefix=192.0.2.
		mask=24
		proto=icmp
		type=icmp-type
		ping_family=-4
	else
		prefix=2001:db8::
		mask=64
		proto=icmp6
		type=icmp6-type
		ping_family=-6
	fi
	for host in 2 3 4; do
		ifconfig ${epair}a $family ${prefix}${host}/${mask} alias up
	done
	jexec alcatraz ifconfig ${epair}b $family ${prefix}1/${mask} up
	if [ "$family" = inet6 ]; then
		while ifconfig ${epair}a inet6 | grep -q tentative; do sleep 1; done
		while jexec alcatraz ifconfig ${epair}b inet6 | grep -q tentative; do sleep 1; done
	fi
	for host in 2 3 4; do
		atf_check -s exit:0 -o ignore ping $ping_family -c 1 -t 3 \
		    -S ${prefix}${host} ${prefix}1
	done
	jexec alcatraz pfctl -e
	option="($action)"
	[ "$action" = default ] && option=""
	pft_set_rules alcatraz \
	    'set timeout icmp.first 600' \
	    'set timeout icmp.error 600' \
	    'set timeout src.track 600' \
	    'source limiter "capacity" id 1 entries 2 limit 100' \
	    "pass in quick $family proto $proto $type echoreq source limiter \"capacity\" $option" \
	    'pass'
	# One and two distinct sources fit; a third exceeds the entry capacity.
	for host in 2 3; do
		atf_check -s exit:0 -o ignore ping $ping_family -c 1 -t 3 \
		    -S ${prefix}${host} ${prefix}1
	done
	atf_check -s exit:0 -o match:'^[[:space:]]*1[[:space:]]+2/2[[:space:]]' \
	    jexec alcatraz pfctl -s Srclimiters
	if [ "$action" = no-match ]; then
		atf_check -s exit:0 -o ignore ping $ping_family -c 1 -t 3 \
		    -S ${prefix}4 ${prefix}1
	else
		atf_check -s not-exit:0 -o ignore -e ignore ping $ping_family -c 1 -t 3 \
		    -S ${prefix}4 ${prefix}1
	fi
	atf_check -s exit:0 -o save:capacity.stats \
	    jexec alcatraz pfctl -s Srclimiters
	atf_check -s exit:0 awk '$1 == 1 && $6 > 0 { found = 1 } END { exit !found }' capacity.stats
	# Capacity exhaustion must not exclude an already tracked source.
	atf_check -s exit:0 -o ignore ping $ping_family -c 1 -t 3 \
	    -S ${prefix}2 ${prefix}1
	# Remove the fallback state admitted by no-match, so the final ping
	# must evaluate the limiter again rather than reuse that state.
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec alcatraz pfctl -k ${prefix}4
	# A different routing domain must not delete this domain's entry.
	atf_check -s exit:1 -e match:"not found" \
	    jexec alcatraz pfctl -V 1 -I 1 -k source -k ${prefix}3
	# Releasing a source entry restores capacity for the third source.
	atf_check -s exit:0 -e ignore \
	    jexec alcatraz pfctl -I 1 -k source -k ${prefix}3
	atf_check -s exit:0 -o ignore ping $ping_family -c 1 -t 3 \
	    -S ${prefix}4 ${prefix}1
	atf_check -s exit:0 -o match:'^[[:space:]]*1[[:space:]]+2/2[[:space:]]' \
	    jexec alcatraz pfctl -s Srclimiters
}

atf_test_case "source_capacity_inet_default" "cleanup"
source_capacity_inet_default_head()
{
	atf_set descr 'inet source entry exhaustion with default action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet_default_body()
{
	source_capacity_test inet default
}
source_capacity_inet_default_cleanup()
{
	pft_cleanup
}

atf_test_case "source_capacity_inet_block" "cleanup"
source_capacity_inet_block_head()
{
	atf_set descr 'inet source entry exhaustion with block action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet_block_body()
{
	source_capacity_test inet block
}
source_capacity_inet_block_cleanup()
{
	pft_cleanup
}

atf_test_case "source_capacity_inet_no_match" "cleanup"
source_capacity_inet_no_match_head()
{
	atf_set descr 'inet source entry exhaustion with no-match action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet_no_match_body()
{
	source_capacity_test inet no-match
}
source_capacity_inet_no_match_cleanup()
{
	pft_cleanup
}

atf_test_case "source_capacity_inet6_default" "cleanup"
source_capacity_inet6_default_head()
{
	atf_set descr 'inet6 source entry exhaustion with default action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet6_default_body()
{
	source_capacity_test inet6 default
}
source_capacity_inet6_default_cleanup()
{
	pft_cleanup
}

atf_test_case "source_capacity_inet6_block" "cleanup"
source_capacity_inet6_block_head()
{
	atf_set descr 'inet6 source entry exhaustion with block action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet6_block_body()
{
	source_capacity_test inet6 block
}
source_capacity_inet6_block_cleanup()
{
	pft_cleanup
}

atf_test_case "source_capacity_inet6_no_match" "cleanup"
source_capacity_inet6_no_match_head()
{
	atf_set descr 'inet6 source entry exhaustion with no-match action'
	atf_set require.user root
	atf_set timeout 300
}
source_capacity_inet6_no_match_body()
{
	source_capacity_test inet6 no-match
}
source_capacity_inet6_no_match_cleanup()
{
	pft_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "source_capacity_inet_default"
	atf_add_test_case "source_capacity_inet_block"
	atf_add_test_case "source_capacity_inet_no_match"
	atf_add_test_case "source_capacity_inet6_default"
	atf_add_test_case "source_capacity_inet6_block"
	atf_add_test_case "source_capacity_inet6_no_match"
	atf_add_test_case "show_aliases"
	atf_add_test_case "state_basic"
	atf_add_test_case "state_rate"
	atf_add_test_case "state_block"
	atf_add_test_case "state_multiple"
	atf_add_test_case "source_basic"
	atf_add_test_case "out"
}

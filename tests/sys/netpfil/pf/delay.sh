# SPDX-License-Identifier: BSD-2-Clause
. $(atf_get_srcdir)/utils.subr

delay_setup()
{
	pft_init
	epair=$(vnet_mkepair)
	vnet_mkjail delayed ${epair}b
	atf_check -s exit:0 -o ignore -e ignore kldload -n dtrace
	atf_check -s exit:0 -o ignore -e ignore kldload -n sdt
	if [ "$1" = inet6 ]; then
		ifconfig ${epair}a inet6 2001:db8::2/64 no_dad up
		jexec delayed ifconfig ${epair}b inet6 2001:db8::1/64 no_dad up
		ping_args="-6 -c 3 2001:db8::2"
		echo_match="inet6 proto icmp6 icmp6-type echoreq"
	else
		ifconfig ${epair}a 192.0.2.2/24 up
		jexec delayed ifconfig ${epair}b 192.0.2.1/24 up
		ping_args="-c 3 192.0.2.2"
		echo_match="inet proto icmp icmp-type echoreq"
	fi
	index=$(jexec delayed ifconfig ${epair}b | awk '$1 == "index" {print $2}')
	[ -n "$index" ] || atf_fail "Missing transmit interface index"
	jexec delayed pfctl -e
	pft_set_rules delayed "pass out quick $echo_match set delay $2" "pass"
}

delay_delivery()
{
	delay_setup "$1" 50
	# Count actual enqueue probes, not elapsed time.  Packet delivery and
	# the exact configured metadata are both required; a no-op cannot pass.
	atf_check -s exit:0 -o match:"3 packets received" -e ignore \
	    dtrace -q -o delay.trace \
	    -n "pf:queue:packet:delay /arg1 == 50 && arg2 == $index/ { n++; } END { printf(\"DELAY_EVENTS=%d\\n\", n); }" \
	    -c "jexec delayed ping $ping_args"
	atf_check -s exit:0 -o ignore grep -x DELAY_EVENTS=3 delay.trace
}

atf_test_case inet cleanup
inet_head()
{
	atf_set descr "Standalone PF delay queues and delivers IPv4 packets"
	atf_set require.user root
	atf_set is.exclusive true
	atf_set require.progs dtrace
}
inet_body() { delay_delivery inet; }
inet_cleanup() { pft_cleanup; }

atf_test_case inet6 cleanup
inet6_head()
{
	atf_set descr "Standalone PF delay queues and delivers IPv6 packets"
	atf_set require.user root
	atf_set is.exclusive true
	atf_set require.progs dtrace
}
inet6_body() { delay_delivery inet6; }
inet6_cleanup() { pft_cleanup; }

atf_test_case teardown cleanup
teardown_head()
{
	atf_set descr "VNET teardown cancels pending PF delay packets"
	atf_set require.user root
	atf_set is.exclusive true
	atf_set require.progs dtrace
	atf_set timeout 30
}
teardown_body()
{
	delay_setup inet 60000
	cat > teardown.sh <<'SCRIPT'
#!/bin/sh
jexec delayed ping -c 1 -t 1 192.0.2.2 >/dev/null
[ "$?" -eq 2 ] || exit 1
jail -r delayed || exit 1
echo DELAY_VNET_REMOVED
SCRIPT
	chmod +x teardown.sh
	atf_check -s exit:0 -o match:DELAY_VNET_REMOVED -e ignore \
	    dtrace -q -o delay.trace \
	    -n "pf:queue:packet:delay /arg1 == 60000 && arg2 == $index/ { n++; } END { printf(\"DELAY_EVENTS=%d\\n\", n); }" \
	    -c ./teardown.sh
	atf_check -s exit:0 -o ignore grep -x DELAY_EVENTS=1 delay.trace
	atf_check -s exit:1 -o empty -e ignore jls -n -j delayed jid
}
teardown_cleanup() { pft_cleanup; }

# Pool limits remain shared and privileged; only this exclusive root test
# changes the limit, and cleanup restores it even when an assertion fails.
restore_delay_limit()
{
	if [ -f delay.limit.original ]; then
		"$(atf_get_srcdir)/delay_pool_limit" "$(cat delay.limit.original)" &&
		    test "$("$(atf_get_srcdir)/delay_pool_limit")" = "$(cat delay.limit.original)"
	fi
}

atf_test_case limit cleanup
limit_head()
{
	atf_set descr "Standalone delay honors pktdelay-pkts and frees it on teardown"
	atf_set require.user root
	atf_set is.exclusive true
	atf_set require.progs dtrace
	atf_set timeout 30
}
limit_body()
{
	"$(atf_get_srcdir)/delay_pool_limit" > delay.limit.original
	original=$(cat delay.limit.original)
	case "$original" in
	''|*[!0-9]*) atf_fail "Missing packet-delay limit" ;;
	esac
	atf_check -s exit:0 -o empty -e empty \
	    "$(atf_get_srcdir)/delay_pool_limit" 1
	delay_setup inet 60000
	atf_check -s exit:2 -o ignore -e match:"No buffer space available" \
	    jexec delayed ping -c 2 -i 0.1 -t 1 192.0.2.2
	# Exactly one queued packet survives; the second allocation is refused.
	atf_check -s exit:0 -o inline:"1\n" sh -c \
	    "vmstat -z | awk '\$1 == \"pfpktdelay:\" {gsub(\",\", \"\", \$4); print \$4}'"
	# A policy reload does not orphan an already queued frame.
	pft_set_rules delayed "pass"
	atf_check -s exit:0 -o inline:"1\n" sh -c \
	    "vmstat -z | awk '\$1 == \"pfpktdelay:\" {gsub(\",\", \"\", \$4); print \$4}'"
	atf_check -s exit:0 -o empty jail -r delayed
	atf_check -s exit:0 -o inline:"0\n" sh -c \
	    "vmstat -z | awk '\$1 == \"pfpktdelay:\" {gsub(\",\", \"\", \$4); print \$4}'"
	restore_delay_limit
}
limit_cleanup()
{
	pft_cleanup
	restore_delay_limit
}

atf_init_test_cases()
{
	atf_add_test_case inet
	atf_add_test_case inet6
	atf_add_test_case teardown
	atf_add_test_case limit
}

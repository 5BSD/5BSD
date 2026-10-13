# SPDX-License-Identifier: BSD-2-Clause
# Observe internal priority on untagged packets after PF, independently of PCP.
# Packet tag 21 is PACKET_TAG_PF from sys/mbuf.h; reject absent/wrong tags.
. $(atf_get_srcdir)/utils.subr

priority_check()
{
	mode=$1
	want=$2
	pft_init
	ep=$(vnet_mkepair)
	vnet_mkjail priority ${ep}b
	ifconfig ${ep}a 192.0.2.2/24 up
	jexec priority ifconfig ${ep}b 192.0.2.1/24 up
	index=$(jexec priority ifconfig ${ep}b | awk '$1 == "index" {print $2}')
	atf_check -s exit:0 -o ignore -e ignore kldload -n dtrace
	atf_check -s exit:0 -o ignore -e ignore kldload -n fbt
	jexec priority pfctl -e
	case "$mode" in
	default) rule='pass out quick inet proto icmp icmp-type echoreq no state' ;;
	zero) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 0' ;;
	four) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 4' ;;
	state) rule='pass out quick inet proto icmp icmp-type echoreq set prio 5' ;;
	transition) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 0' ;;
	esac
	if [ "$mode" = transition ]; then
		pft_set_rules priority 'match out inet proto icmp set prio 4' "$rule" pass
	else
		pft_set_rules priority "$rule" pass
	fi
	cat > priority.d <<SCRIPT
fbt:pf:pf_test:entry
/arg0 == 2 && arg1 == 2 && ((struct ifnet *)arg2)->if_index == $index/
{ self->pp = (struct mbuf **)arg3; }
fbt:pf:pf_test:return
/self->pp != 0/
{
 this->m = *self->pp;
 this->t = this->m != 0 ? this->m->m_pkthdr.tags.slh_first : 0;
 printf("PRIO=%d\\n", this->t != 0 && this->t->m_tag_id == 21 && this->t->m_tag_cookie == 0 ? ((struct pkthdr_pf *)(this->t + 1))->prio : -1);
 self->pp = 0;
}
SCRIPT
	atf_check -s exit:0 -o match:'3 packets received' -e ignore \
	    dtrace -q -o priority.trace -s priority.d \
	    -c 'jexec priority ping -c 3 192.0.2.2'
	cat priority.trace
	atf_check -s exit:0 -o inline:"3\n" grep -cx "PRIO=$want" priority.trace
	atf_check -s exit:0 -o empty awk -v expected="PRIO=$want" \
	    'NF && $0 != expected {exit 1}' priority.trace
	if [ "$mode" = state ]; then
		atf_check -s exit:0 -o match:'current entries[[:space:]]+1[[:space:]]*$' \
		    jexec priority pfctl -si
	fi
}

atf_test_case default cleanup
default_head() { atf_set descr "Untagged PF priority defaults to three"; atf_set require.user root; atf_set is.exclusive true; atf_set require.progs dtrace; }
default_body() { priority_check default 3; }
default_cleanup() { pft_cleanup; }
atf_test_case four cleanup
four_head() { default_head; atf_set descr "PF assigns internal priority four without VLAN tags"; }
four_body() { priority_check four 4; }
four_cleanup() { pft_cleanup; }
atf_test_case zero cleanup
zero_head() { default_head; atf_set descr "PF distinguishes explicit priority zero from no assignment"; }
zero_body() { priority_check zero 0; }
zero_cleanup() { pft_cleanup; }
atf_test_case transition cleanup
transition_head() { default_head; atf_set descr "Final rule action replaces earlier priority four with zero"; }
transition_body() { priority_check transition 0; }
transition_cleanup() { pft_cleanup; }
atf_test_case state cleanup
state_head() { default_head; atf_set descr "PF reuses a single state and its priority on subsequent packets"; }
state_body() { priority_check state 5; }
state_cleanup() { pft_cleanup; }
atf_init_test_cases() {
 atf_add_test_case default
 atf_add_test_case four
 atf_add_test_case zero
 atf_add_test_case transition
 atf_add_test_case state
}

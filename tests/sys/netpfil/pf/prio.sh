#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2022 Kristof Provost <kp@FreeBSD.org>
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

# Test raw TCI bits: tcpdump displays mapped priority rather than raw PCP.
vlan_check()
{
 mode=$1
 want=$2
 pft_init
 ep=$(vnet_mkepair)
 ifconfig ${ep}a.42 create
 echo ${ep}a.42 >> created_interfaces.lst
 ifconfig ${ep}a up
 ifconfig ${ep}a.42 vlandev ${ep}a vlan 42
 ifconfig ${ep}a.42 192.0.2.2/24 up
 vnet_mkjail priority ${ep}b
 jexec priority ifconfig ${ep}b.42 create
 jexec priority ifconfig ${ep}b up
 jexec priority ifconfig ${ep}b.42 vlandev ${ep}b vlan 42
 jexec priority ifconfig ${ep}b.42 192.0.2.1/24 up
 jexec priority pfctl -e
 case "$mode" in
 default) rule='pass out quick inet proto icmp icmp-type echoreq no state' ;;
 four|override6|override0|restore_auto|invalid) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 4' ;;
 zero) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 0' ;;
 one) rule='pass out quick inet proto icmp icmp-type echoreq no state set prio 1' ;;
 esac
 case "$mode" in
 override6) jexec priority ifconfig ${ep}b.42 vlanpcp 6 ;;
 override0) jexec priority ifconfig ${ep}b.42 vlanpcp 0 ;;
 restore_auto) jexec priority ifconfig ${ep}b.42 vlanpcp 6
  atf_check -s exit:0 -o empty -e empty jexec priority ifconfig ${ep}b.42 vlanpcp auto ;;
 invalid) atf_check -s exit:1 -o empty -e match:'out of range' jexec priority ifconfig ${ep}b.42 vlanpcp 8 ;;
 esac
 case "$mode" in
 override6) shown=6 ;;
 override0) shown=0 ;;
 *) shown=auto ;;
 esac
 atf_check -s exit:0 -o match:"vlanpcp: $shown" -e empty jexec priority ifconfig ${ep}b.42
 pft_set_rules priority "$rule" pass
 tcpdump -n -e -i ${ep}a -c 3 -w wire.pcap 'vlan 42 and icmp and src host 192.0.2.1' > wire.out 2> wire.err &
 cap=$!
 echo "$cap" > capture.pid
 ready=0
 for attempt in $(jot 100); do
  if grep -q 'listening on' wire.err; then ready=1; break; fi
  kill -0 "$cap" || break
  sleep 0.1
 done
 [ "$ready" = 1 ] || atf_fail "Capture did not become ready"
 atf_check -s exit:0 -o match:'3 packets received' -e empty jexec priority ping -c 3 192.0.2.2
 wait "$cap" || atf_fail "Capture failed"
 rm capture.pid
 tcpdump -n -e -r wire.pcap
 cat > check-pcp.py <<'PYCODE'
import struct,sys
raw=open("wire.pcap","rb").read()
magic=raw[:4]
assert magic in (b"\xd4\xc3\xb2\xa1",b"\xa1\xb2\xc3\xd4"), magic
endian="<" if magic==b"\xd4\xc3\xb2\xa1" else ">"
assert struct.unpack(endian+"I",raw[20:24])[0]==1
pos=24
values=[]
while pos<len(raw):
    assert len(raw)-pos>=16
    length=struct.unpack(endian+"I",raw[pos+8:pos+12])[0]
    pos+=16
    packet=raw[pos:pos+length]
    assert len(packet)==length and length>=18 and packet[12:14]==b"\x81\x00"
    tci=int.from_bytes(packet[14:16],"big")
    assert tci&4095==42
    values.append(tci>>13)
    pos+=length
print("RAW_PCP="+str(values))
assert values==[int(sys.argv[1])]*3, values
PYCODE
 atf_check -s exit:0 -o match:RAW_PCP python3 check-pcp.py "$want"
}
vlan_cleanup()
{
 if [ -f capture.pid ]; then kill "$(cat capture.pid)" 2>/dev/null || true; fi
 pft_cleanup
}
atf_test_case default cleanup
vlan_head_common() { atf_set require.user root; atf_set is.exclusive true; atf_set timeout 30; atf_set require.progs "tcpdump python3"; }
default_head() { vlan_head_common; atf_set descr "Automatic VLAN PCP keeps best effort PCP 0 at the default priority"; }
default_body() { vlan_check default 0; }
default_cleanup() { vlan_cleanup; }
atf_test_case set_prio cleanup
set_prio_head() { vlan_head_common; atf_set descr "PF priority four reaches the VLAN wire PCP"; }
set_prio_body() { vlan_check four 4; }
set_prio_cleanup() { vlan_cleanup; }
atf_test_case zero cleanup
zero_head() { vlan_head_common; atf_set descr "Internal priority zero maps to wire PCP one"; }
zero_body() { vlan_check zero 1; }
zero_cleanup() { vlan_cleanup; }
atf_test_case one cleanup
one_head() { vlan_head_common; atf_set descr "Internal priority one maps to wire PCP zero"; }
one_body() { vlan_check one 0; }
one_cleanup() { vlan_cleanup; }
atf_test_case override6 cleanup
override6_head() { vlan_head_common; atf_set descr "Explicit native PCP six overrides automatic packet priority"; }
override6_body() { vlan_check override6 6; }
override6_cleanup() { vlan_cleanup; }
atf_test_case override0 cleanup
override0_head() { vlan_head_common; atf_set descr "Explicit native PCP zero remains distinguishable from automatic mode"; }
override0_body() { vlan_check override0 0; }
override0_cleanup() { vlan_cleanup; }
atf_test_case restore_auto cleanup
restore_auto_head() { vlan_head_common; atf_set descr "Automatic mode can be restored after a numeric PCP override"; }
restore_auto_body() { vlan_check restore_auto 4; }
restore_auto_cleanup() { vlan_cleanup; }
atf_test_case invalid cleanup
invalid_head() { vlan_head_common; atf_set descr "Rejected PCP configuration leaves automatic priority unchanged"; }
invalid_body() { vlan_check invalid 4; }
invalid_cleanup() { vlan_cleanup; }


receive_priority_check()
{
	mode=$1
	want=$2
	pft_init
	ep=$(vnet_mkepair)
	ifconfig ${ep}a.42 create
	echo ${ep}a.42 >> created_interfaces.lst
	ifconfig ${ep}a up
	ifconfig ${ep}a.42 vlandev ${ep}a vlan 42
	ifconfig ${ep}a.42 192.0.2.2/24 up
	ifconfig ${ep}a.42 vlanpcp "$mode"
	vnet_mkjail priority ${ep}b
	jexec priority ifconfig ${ep}b.42 create
	jexec priority ifconfig ${ep}b up
	jexec priority ifconfig ${ep}b.42 vlandev ${ep}b vlan 42
	jexec priority ifconfig ${ep}b.42 192.0.2.1/24 up
	index=$(jexec priority ifconfig ${ep}b.42 | awk '$1 == "index" {print $2}')
	atf_check -s exit:0 -o ignore -e ignore kldload -n dtrace
	atf_check -s exit:0 -o ignore -e ignore kldload -n fbt
	jexec priority pfctl -e
	pft_set_rules priority 'pass no state'
	cat > priority.d <<SCRIPT
fbt:pf:pf_test:entry
/arg0 == 2 && arg1 == 1 && ((struct ifnet *)arg2)->if_index == $index/
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
	    -c 'ping -c 3 192.0.2.1'
	cat priority.trace
	atf_check -s exit:0 -o inline:"3\n" grep -cx "PRIO=$want" priority.trace
	atf_check -s exit:0 -o empty awk -v expected="PRIO=$want" \
	    'NF && $0 != expected {exit 1}' priority.trace

}

atf_test_case receive0 cleanup
receive_head_common() { atf_set timeout 30; atf_set require.user root; atf_set is.exclusive true; atf_set require.progs dtrace; }
receive0_head() { receive_head_common; atf_set descr "VLAN receive maps wire PCP zero to internal priority one"; }
receive0_body() { receive_priority_check 0 1; }
receive0_cleanup() { pft_cleanup; }
atf_test_case receive1 cleanup
receive1_head() { receive_head_common; atf_set descr "VLAN receive maps wire PCP one to internal priority zero"; }
receive1_body() { receive_priority_check 1 0; }
receive1_cleanup() { pft_cleanup; }
atf_test_case receive4 cleanup
receive4_head() { receive_head_common; atf_set descr "VLAN receive preserves priority four"; }
receive4_body() { receive_priority_check 4 4; }
receive4_cleanup() { pft_cleanup; }

atf_init_test_cases()
{
	atf_add_test_case default
	atf_add_test_case set_prio
	atf_add_test_case zero
	atf_add_test_case one
	atf_add_test_case override6
	atf_add_test_case override0
	atf_add_test_case restore_auto
	atf_add_test_case invalid
	atf_add_test_case receive0
	atf_add_test_case receive1
	atf_add_test_case receive4
}

#!/usr/bin/env python3
"""Check actual native VLAN priority boundary and allocation failure paths."""
from pathlib import Path
import os,shlex,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[4]
STUBS=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define IFNET_PCP_NONE 255
#define IFT_ETHER 6
#define ETHERMIN 46
#define ETHER_HDR_LEN 14
#define M_VLANTAG 1
#define IFCAP_VLAN_HWTAGGING 2
#define ETHERTYPE_VLAN 0x8100
#define MTAG_8021Q 13241
#define MTAG_8021Q_PCP_OUT 1
#define IFCOUNTER_IERRORS 1
#define EVL_PRIOFTAG(t) (((t)>>13)&7)
#define EVL_MAKETAG(v,p,c) (((v)&4095)|((p)<<13)|((c)<<12))
static unsigned min(unsigned a,unsigned b) {return a<b?a:b;}
struct pkthdr_pf {uint8_t prio;};
struct mbuf {int m_flags;struct {int len;uint16_t ether_vtag;} m_pkthdr;struct pkthdr_pf pf;int freed;};
struct ifnet {int if_type,if_capenable,errors;};
struct ether_8021q_tag {uint16_t proto,vid;uint8_t pcp;};
struct m_tag {int dummy;};
static struct {struct m_tag tag;uint8_t pcp;} override;
static int V_soft_pad,V_vlan_mtag_pcp,has_override,allocation_failure;
static uint16_t encoded;
static const struct pkthdr_pf *m_pf_ro(struct mbuf *m) {return &m->pf;}
static struct pkthdr_pf *m_pf_get(struct mbuf *m) {return allocation_failure?NULL:&m->pf;}
static int m_append(struct mbuf *m,int n,const void *b) {(void)b;m->m_pkthdr.len+=n;return 1;}
static void m_freem(struct mbuf *m) {assert(!m->freed);m->freed=1;}
static void if_printf(struct ifnet *p,const char *s) {(void)p;(void)s;}
static void if_inc_counter(struct ifnet *p,int kind,int n) {assert(kind==IFCOUNTER_IERRORS);p->errors+=n;}
static struct m_tag *m_tag_locate(struct mbuf *m,int c,int type,void *start) {(void)m;(void)c;(void)type;(void)start;return has_override?&override.tag:NULL;}
static struct mbuf *ether_vlanencap_proto(struct mbuf *m,uint16_t tag,uint16_t proto) {assert(proto==ETHERTYPE_VLAN);encoded=tag;return m;}
'''
CHECKS=r'''
int main(void) {
 struct ifnet net={.if_type=IFT_ETHER};
 struct ether_8021q_tag q={.proto=ETHERTYPE_VLAN,.vid=42,.pcp=IFNET_PCP_NONE};
 struct mbuf m={0},*mp=&m;
 for(int hardware=0;hardware<2;hardware++) {
  net.if_capenable=hardware?IFCAP_VLAN_HWTAGGING:0;
  for(int prio=0;prio<8;prio++) {
   m.m_flags=0;m.pf.prio=prio;q.pcp=IFNET_PCP_NONE;
   assert(ether_8021q_frame(&mp,&net,&net,&q));
   uint16_t result=hardware?m.m_pkthdr.ether_vtag:encoded;
   assert((result&4095)==42 && EVL_PRIOFTAG(result)==(prio<=1?!prio:prio));
   /* Numeric PCP is a wire override, including zero. */
   for(int explicit=0;explicit<8;explicit++) {
    m.m_flags=0;q.pcp=explicit;
    assert(ether_8021q_frame(&mp,&net,&net,&q));
    result=hardware?m.m_pkthdr.ether_vtag:encoded;
    assert(EVL_PRIOFTAG(result)==explicit);
   }
  }
 }
 net.if_capenable=0;q.pcp=IFNET_PCP_NONE;m.pf.prio=4;
 m.m_flags=M_VLANTAG;m.m_pkthdr.ether_vtag=EVL_MAKETAG(5,6,0);
 assert(ether_8021q_frame(&mp,&net,&net,&q));assert(EVL_PRIOFTAG(encoded)==4);
 /* A cached inner hardware tag cannot override automatic outer priority. */
 m.m_flags=M_VLANTAG;q.pcp=2;
 assert(ether_8021q_frame(&mp,&net,&net,&q));assert(EVL_PRIOFTAG(encoded)==6);
 m.m_flags=0;V_vlan_mtag_pcp=has_override=1;override.pcp=7;
 assert(ether_8021q_frame(&mp,&net,&net,&q));assert(EVL_PRIOFTAG(encoded)==7);
 for(int pcp=0;pcp<8;pcp++) {
  m.pf.prio=99;receive(&m,&net,EVL_MAKETAG(42,pcp,0));
  assert(m.pf.prio==(pcp<=1?!pcp:pcp) && !m.freed && !net.errors);
 }
 allocation_failure=1;receive(&m,&net,0);
 assert(m.freed && net.errors==1);
 return 0;
}
'''
class VLANPriority(unittest.TestCase):
 def test_wire_mapping_overrides_and_receive_allocation_failure(self):
  s=(ROOT/'sys/net/if_ethersubr.c').read_text();a=s.index('bool\nether_8021q_frame(');b=s.index('\n}',a)+2;output=s[a:b]
  s=(ROOT/'sys/net/if_vlan.c').read_text();a=s.index('\t/* VLAN wire PCP and PF internal priority');b=s.index('\n\tif (V_vlan_mtag_pcp)',a)
  receive='static void receive(struct mbuf *m,struct ifnet *ifp,uint16_t tag) {\n'+s[a:b]+'\n}\n'
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'check.c').write_text(STUBS+output+receive+CHECKS)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'check.c'),'-o',str(p/'check')],check=True)
   subprocess.run([str(p/'check')],check=True)
if __name__=='__main__':unittest.main()

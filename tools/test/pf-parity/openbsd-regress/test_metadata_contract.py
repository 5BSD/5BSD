#!/usr/bin/env python3
"""Compile actual PF metadata helpers against deterministic allocation failures."""
from pathlib import Path
import subprocess,tempfile,unittest,os,shlex
ROOT=Path(__file__).resolve().parents[4]
def function(path,name,rettype):
 s=(ROOT/path).read_text();a=s.index(rettype+'\n'+name+'(');b=s.index('\n}',a)+2;return s[a:b]+'\n'
STUBS=r'''
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define KASSERT assert
struct pf_state_key { int refs; };
struct inpcb { int refs; };
struct pkthdr_pf { int tag; struct pf_state_key *statekey; struct inpcb *inp; };
struct mbuf { struct pkthdr_pf tag; int allocated; struct { unsigned ph_rtableid; } m_pkthdr; };
static int fail_alloc;
static struct pkthdr_pf zero;
static struct pkthdr_pf *m_pf_get(struct mbuf *m) {
 if (!m->allocated && fail_alloc) return NULL;
 m->allocated=1; return &m->tag;
}
#define PF_MTAG_W(m) obsd_pf_mtag_w(m)
static unsigned long failures;
typedef unsigned long *counter_u64_t;
static counter_u64_t pf_fbsd_mtag_nomem=&failures;
static void counter_u64_add(counter_u64_t c,int n) { *c+=n; }
#define PF_MTAG_R(m) ((m)->allocated ? &(m)->tag : &zero)
static struct pf_state_key *pf_state_key_ref(struct pf_state_key *p) {p->refs++;return p;}
static void pf_state_key_unref(struct pf_state_key *p) {assert(p->refs>0);p->refs--;}
static struct inpcb *in_pcbref(struct inpcb *p) {p->refs++;return p;}
static void in_pcbunref(struct inpcb *p) {assert(p->refs>0);p->refs--;}
'''
CHECKS=r'''
int main(void) {
 struct mbuf a={0},b={0};struct pf_state_key sk={0};struct inpcb inp={0};
 fail_alloc=1;
 assert(pf_tag_packet(&a,9,7)==ENOMEM && a.m_pkthdr.ph_rtableid==0);
 assert(pf_mbuf_link_state_key(&a,&sk)==ENOMEM && sk.refs==0);
 assert(pf_mbuf_link_inpcb(&a,&inp)==ENOMEM && inp.refs==0);
 assert(!a.allocated && !b.allocated && zero.tag==0);
 /* Routing-domain-only tagging retains allocation-free behavior. */
 assert(pf_tag_packet(&b,0,4)==0 && b.m_pkthdr.ph_rtableid==4 && !b.allocated);
 fail_alloc=0;
 assert(pf_tag_packet(&a,9,7)==0);
 assert(pf_mbuf_link_state_key(&a,&sk)==0 && sk.refs==1);
 assert(pf_mbuf_link_inpcb(&a,&inp)==0 && inp.refs==1);
 fail_alloc=1;
 assert(pf_tag_packet(&b,11,8)==ENOMEM && a.tag.tag==9);
 /* Existing tags remain writable when new allocations fail. */
 assert(pf_tag_packet(&a,12,9)==0 && a.tag.tag==12);
 pf_mbuf_unlink_state_key(&a);pf_mbuf_unlink_inpcb(&a);
 assert(sk.refs==0 && inp.refs==0 && !a.tag.statekey && !a.tag.inp);
 assert(failures==4);
 pf_mbuf_unlink_state_key(&a);pf_mbuf_unlink_inpcb(&a);
 return 0;
}
'''
class MetadataContract(unittest.TestCase):
 def test_failed_allocation_does_not_publish_metadata_or_take_references(self):
  source=function('sys/netpfil/openbsd-pf/pf_freebsd.c','pf_fbsd_mtag_alloc_failed','static struct pkthdr_pf *')+function('sys/netpfil/openbsd-pf/pf_freebsd.c','obsd_pf_mtag_w','struct pkthdr_pf *')
  source+=''.join(function('contrib/openbsd-pf/sys/net/pf.c',n,t) for n,t in [('pf_tag_packet','int'),('pf_mbuf_link_state_key','int'),('pf_mbuf_unlink_state_key','void'),('pf_mbuf_link_inpcb','int'),('pf_mbuf_unlink_inpcb','void')])
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'test.c').write_text(STUBS+source+CHECKS)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':unittest.main()

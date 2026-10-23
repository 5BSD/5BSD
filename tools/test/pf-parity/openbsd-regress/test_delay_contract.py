#!/usr/bin/env python3
"""Exercise the native PF transmit-delay ownership and teardown contract."""
from pathlib import Path
import subprocess,tempfile,unittest,os,shlex
ROOT=Path(__file__).resolve().parents[4]
STUBS=r'''
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct pkthdr_pf { unsigned delay, qid; };
struct mbuf { struct pkthdr_pf tag; int freed; struct {void *rcvif;} m_pkthdr; };
struct ifnet { unsigned if_index; int refs; int (*if_transmit)(struct ifnet *,struct mbuf *); };
struct timeout { void (*fn)(void *); void *arg; unsigned ms; };
struct epoch_tracker {int unused;};struct mtx {int unused;};
#define VNET_DEFINE_STATIC(t,n) static t n
#define VNET(n) n
#define MTX_SYSINIT(a,b,c,d)
#define NET_EPOCH_ENTER(et) ((void)&(et))
#define NET_EPOCH_EXIT(et) ((void)&(et))
#define PR_NOWAIT 0
#define PR_ZERO 0
static int alloc_fail,tag_fail,allocations,frees,transmits,barriers,V_pf_fbsd_ready=1;
static struct ifnet *indexed;
static int stale_receive, delay_events;
#define PF_SDT3(a,b,c,d,e,f) do {(void)(d);(void)(e);(void)(f);delay_events++;} while (0)
static void m_rcvif_serialize(struct mbuf *m) {assert(m->m_pkthdr.rcvif);m->m_pkthdr.rcvif=(void *)1;}
static struct ifnet *m_rcvif_restore(struct mbuf *m) {assert(m->m_pkthdr.rcvif==(void *)1);return stale_receive?NULL:indexed;}
static struct pkthdr_pf *gettag(struct mbuf *m) {return tag_fail ? NULL : &m->tag;}
#define PF_MTAG_W(m) gettag(m)
struct pool {size_t size;int limit;} pf_pktdelay_pl;
static int pool_locked;
#define PF_LOCK() do {assert(!pool_locked);pool_locked=1;} while (0)
#define PF_UNLOCK() do {assert(pool_locked);pool_locked=0;} while (0)
static void *pool_get(struct pool *p,int flags) {(void)flags;assert(pool_locked);if(alloc_fail || allocations-frees>=p->limit)return NULL;allocations++;return calloc(1,p->size);}
static void pool_put(struct pool *p,void *obj) {(void)p;frees++;free(obj);}
static void m_freem(struct mbuf *m) {assert(!m->freed);m->freed=1;}
static struct ifnet *if_get(unsigned idx) {if(indexed && indexed->if_index==idx){indexed->refs++;return indexed;}return NULL;}
static void if_put(struct ifnet *p) {if(p){assert(p->refs>0);p->refs--;}}
static void mtx_lock(struct mtx *m) {(void)m;}
static void mtx_unlock(struct mtx *m) {(void)m;}
static void timeout_set(struct timeout *t,void(*f)(void *),void *arg) {t->fn=f;t->arg=arg;}
static void timeout_add_msec(struct timeout *t,unsigned ms) {t->ms=ms;}
/* Exercise a callback racing cancellation before the barrier returns. */
static void timeout_del_barrier(struct timeout *t) {t->fn(t->arg);}
static void net_tq_barriers(const char *s) {(void)s;barriers++;}
static int transmit(struct ifnet *p,struct mbuf *m) {(void)p;assert(m->tag.delay==0);transmits++;m_freem(m);return 0;}
'''
CHECKS=r'''
int main(void) {
 struct ifnet original={.if_index=5,.if_transmit=transmit};
 struct ifnet reused={.if_index=5,.if_transmit=transmit};
 struct mbuf packets[9]={0};struct pf_pktdelay *p;
 indexed=&original;TAILQ_INIT(&V_pf_fbsd_delays);
 pf_pktdelay_pl.size=sizeof(struct pf_pktdelay);pf_pktdelay_pl.limit=10000;
 packets[0].tag.delay=37;
 assert(obsd_pf_delay_packet(&packets[0],5)==0);
 assert(!packets[0].freed && transmits==0 && packets[0].tag.delay==0);
 p=TAILQ_FIRST(&V_pf_fbsd_delays);assert(p && p->to.ms==37 && original.refs==1);
 p->to.fn(p->to.arg);
 assert(transmits==1 && packets[0].freed && original.refs==0 && V_pf_fbsd_delay_count==0);
 /* Never transmit through a replacement that reuses the interface index. */
 packets[1].tag.delay=9;assert(obsd_pf_delay_packet(&packets[1],5)==0);
 indexed=&reused;p=TAILQ_FIRST(&V_pf_fbsd_delays);p->to.fn(p->to.arg);
 assert(packets[1].freed && transmits==1 && !original.refs && !reused.refs);
 indexed=&original;alloc_fail=1;
 assert(obsd_pf_delay_packet(&packets[2],5)==ENOBUFS && packets[2].freed);alloc_fail=0;
 tag_fail=1;assert(obsd_pf_delay_packet(&packets[3],5)==ENOBUFS && packets[3].freed);tag_fail=0;
 pf_pktdelay_pl.limit=1;
 packets[5].tag.delay=60000;assert(obsd_pf_delay_packet(&packets[5],5)==0);
 assert(obsd_pf_delay_packet(&packets[4],5)==ENOBUFS && packets[4].freed);
 assert(V_pf_fbsd_delay_count==1 && delay_events==3);pf_pktdelay_pl.limit=10000;
 pf_fbsd_delay_drain();
 assert(packets[5].freed && V_pf_fbsd_delay_count==0 && !original.refs && barriers==1 && transmits==1);
 assert(obsd_pf_delay_packet(&packets[6],5)==ENOBUFS && packets[6].freed);
 V_pf_fbsd_delay_closing=0;indexed=NULL;
 assert(obsd_pf_delay_packet(&packets[7],5)==ENOBUFS && packets[7].freed);
 indexed=&original;packets[8].m_pkthdr.rcvif=&original;
 assert(obsd_pf_delay_packet(&packets[8],5)==0);
 stale_receive=1;p=TAILQ_FIRST(&V_pf_fbsd_delays);p->to.fn(p->to.arg);
 assert(packets[8].freed && transmits==1 && !original.refs);
 assert(allocations==frees && TAILQ_EMPTY(&V_pf_fbsd_delays) && delay_events==4);
 return 0;
}
'''
class DelayContract(unittest.TestCase):
 def test_ownership_identity_allocation_and_teardown(self):
  s=(ROOT/'sys/netpfil/openbsd-pf/pf_freebsd.c').read_text()
  a=s.index('TAILQ_HEAD(pf_fbsd_delay_head');b=s.index('static int\npf_fbsd_delay_transmit(',a)
  header=(ROOT/'contrib/openbsd-pf/sys/net/pfvar.h').read_text();c=header.index('struct pf_pktdelay {');e=header.index('\n};',c)+3
  source=header[c:e]+s[a:b]
  a=s.index('static void\npf_fbsd_delay_drain(');b=s.index('\n}',a)+2;source+=s[a:b]
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'test.c').write_text(STUBS+source+CHECKS)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
 def test_native_dispatch_preserves_zero_delay_and_unloaded_behavior(self):
  s=(ROOT/'sys/net/if.c').read_text();a=s.index('int\nif_transmit(if_t ');b=s.index('\n}',a)+2
  stubs=r'''
#include <assert.h>
#include <stddef.h>
struct pkthdr_pf { unsigned delay, qid; };
struct mbuf {struct pkthdr_pf tag;};
struct ifnet {int (*if_transmit)(struct ifnet *,struct mbuf *);};
typedef struct ifnet *if_t;
static int direct_calls,delay_calls;
static int (*pf_delay_transmit_hook)(struct ifnet *,struct mbuf *);
static const struct pkthdr_pf *m_pf_ro(struct mbuf *m) {return &m->tag;}
static int direct(struct ifnet *p,struct mbuf *m) {(void)p;(void)m;direct_calls++;return 7;}
static int delayed(struct ifnet *p,struct mbuf *m) {(void)p;assert(m->tag.delay==50);delay_calls++;return 9;}
'''
  checks=r'''
int main(void) {
 struct ifnet ifp={.if_transmit=direct};struct mbuf m={0};
 assert(if_transmit(&ifp,&m)==7 && direct_calls==1);
 pf_delay_transmit_hook=delayed;
 assert(if_transmit(&ifp,&m)==7 && direct_calls==2 && delay_calls==0);
 m.tag.delay=50;
 assert(if_transmit(&ifp,&m)==9 && direct_calls==2 && delay_calls==1);
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'test.c').write_text(stubs+s[a:b]+checks)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':unittest.main()

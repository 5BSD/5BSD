/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../../../sys/net80211/ieee80211.h"
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define M_LKPIFM 0
#define GFP_KERNEL 0
#define IFF_UP 1
#define IFCOUNTER_OERRORS 1
#define M_WME_GETAC(m) ((m)->ac)
#define linux_set_current(t) ((void)0)
#define curthread NULL
#define IEEE80211_ELEMID_RSN 48
#define WLAN_CIPHER_SUITE_CCMP 0x000fac04
#define WLAN_AKM_SUITE_PSK 0x000fac02
#define WLAN_AKM_SUITE_8021X 0x000fac01
#define NL80211_WPA_VERSION_2 2
struct lkpi_fullmac;
struct ieee80211com { struct lkpi_fullmac *ic_softc; };
struct ieee80211vap { struct ieee80211com *iv_ic; void *iv_ifp; int refs; };
struct ieee80211_node { struct ieee80211vap *ni_vap; int refs; };
struct mbuf { unsigned ac; struct { void *rcvif; unsigned len; } m_pkthdr; struct mbuf *next; };
struct mbufq { struct mbuf *head; };
struct sk_buff { void *dev; unsigned priority; uint8_t data[32]; };
struct net_device;
struct net_device_ops {
 int (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
 int (*ndo_stop)(struct net_device *);
};
struct net_device { const struct net_device_ops *netdev_ops; unsigned needed_headroom, flags; bool stopped; void *ieee80211_ptr; };
struct wiphy { struct lkpi_fullmac *bsd_fullmac; int locks; };
struct cfg80211_scan_request { struct wiphy *wiphy; };
struct cfg80211_scan_info { bool aborted; };
struct cfg80211_ops { void (*abort_scan)(struct wiphy *, void *); };
struct task { int queued; };
struct taskqueue { int unused; };
struct mtx { int locked; };
struct lkpi_fullmac {
 struct ieee80211com ic;
 struct wiphy *wiphy;
 const struct cfg80211_ops *ops;
 struct net_device *ndev;
 struct mtx lock;
 struct ieee80211vap *vap;
 struct taskqueue *tx_queue;
 struct task tx_task;
 struct mbufq tx_frames;
 struct cfg80211_scan_request *scan;
 struct ieee80211vap *scan_vap;
 bool scan_active, tx_blocked, vap_deleting, stopping, running;
};
struct cfg80211_connect_params { struct { uint32_t cipher_group, wpa_versions; uint32_t *ciphers_pairwise, *akm_suites; int n_ciphers_pairwise, n_akm_suites; } crypto; };
static unsigned le16dec(const uint8_t *p) { return p[0] | ((unsigned)p[1] << 8); }
static uint32_t be32dec(const uint8_t *p) { return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3]; }
static struct lkpi_fullmac fm;
static struct wiphy wiphy;
static struct net_device ndev;
static struct ieee80211_node node;
static int frames, errors, sends, stops, aborts, completions, requests;
static bool detached, synchronous_abort, fail_skb_alloc, deferred_scan;
void linuxkpi_fullmac_scan_done(struct cfg80211_scan_request *, struct cfg80211_scan_info *);
static unsigned waited_refs, last_priority;
static void mtx_lock(struct mtx *m) { assert(!m->locked); m->locked = 1; }
static void mtx_unlock(struct mtx *m) { assert(m->locked); m->locked = 0; }
static void wiphy_lock(struct wiphy *w) { assert(!w->locks); w->locks++; }
static void wiphy_unlock(struct wiphy *w) { assert(w->locks == 1); w->locks--; }
static int netif_queue_stopped(struct net_device *n) { return n->stopped; }
static struct mbuf *mbufq_dequeue(struct mbufq *q) {
 struct mbuf *m = q->head; if (m) q->head = m->next; return m;
}
static int mbufq_enqueue(struct mbufq *q, struct mbuf *m) {
 m->next = q->head; q->head = m; return 0;
}
static struct sk_buff *alloc_skb(unsigned length, unsigned flags) {
 (void)length; (void)flags; return fail_skb_alloc ? NULL : calloc(1, sizeof(struct sk_buff));
}
static void skb_reserve(struct sk_buff *s, unsigned n) { (void)s; (void)n; }
static void *skb_put(struct sk_buff *s, unsigned n) { assert(n <= sizeof(s->data)); return s->data; }
static void m_copydata(struct mbuf *m, int off, unsigned len, void *buf) {
 (void)m; (void)off; memset(buf, 0, len);
}
static void if_inc_counter(void *ifp, int which, int n) {
 (void)which; assert(!detached && ifp == &fm); errors += n;
}
static void ieee80211_free_node(struct ieee80211_node *ni) { assert(!detached && ni->refs > 0); ni->refs--; }
static void m_freem(struct mbuf *m) { assert(frames > 0); frames--; free(m); }
static int taskqueue_enqueue(struct taskqueue *q, struct task *t) { (void)q; t->queued = 1; return 0; }
static void taskqueue_drain(struct taskqueue *, struct task *);
static void ieee80211_com_vdetach(struct ieee80211vap *v) {
 assert(fm.vap == NULL && fm.vap_deleting && !wiphy.locks && !fm.lock.locked);
 if (deferred_scan) {
  /* Driver still owns this request when VAP teardown starts waiting. */
  assert(fm.scan != NULL && requests == 1 && v->refs > 0 && aborts == 1);
  linuxkpi_fullmac_scan_done(fm.scan, NULL);
  assert(requests == 0 && completions == 0);
 }
 /* Finish an RX/event callback that acquired its reference before deletion. */
 while (v->refs != 0) {
  assert(!detached && v->iv_ifp == &fm); waited_refs++; v->refs--;
 }
}
static void ieee80211_vap_detach(struct ieee80211vap *v) {
 assert(v == node.ni_vap && frames == 0 && node.refs == 0 && v->refs == 0);
 detached = true;
}
static void ieee80211_com_vdecref(struct ieee80211vap *v) { assert(v->refs > 0); v->refs--; }
static void ieee80211_scan_done(struct ieee80211vap *v) {
 assert(v == fm.vap && fm.lock.locked); completions++;
}
static void checked_free(void *p) {
 if (p == node.ni_vap) assert(detached && node.ni_vap->refs == 0);
 else { assert(requests > 0); requests--; }
 free(p);
}
#define free(p, type) checked_free(p)
#include "sdt_test.h"
#include "power_functions.h"
#undef free
static void taskqueue_drain(struct taskqueue *q, struct task *t) {
 (void)q; assert(wiphy.locks == 0);
 if (t->queued) { t->queued = 0; lkpi_fullmac_tx_task(&fm, 0); }
}
static int ndo_stop(struct net_device *n) { stops++; n->stopped = true; return 0; }
static int ndo_xmit(struct sk_buff *s, struct net_device *n) {
 (void)n; assert(!detached); sends++; last_priority=s->priority; free(s); return 0;
}
static void abort_scan(struct wiphy *w, void *wdev) {
 (void)wdev; aborts++;
 if (synchronous_abort) linuxkpi_fullmac_scan_done(w->bsd_fullmac->scan, NULL);
}
static const struct net_device_ops netops = { .ndo_stop = ndo_stop, .ndo_start_xmit = ndo_xmit };
static const struct cfg80211_ops cfgops = { .abort_scan = abort_scan };
static void setup(void) {
 memset(&fm, 0, sizeof(fm)); memset(&node, 0, sizeof(node));
 wiphy = (struct wiphy){ .bsd_fullmac = &fm };
 ndev = (struct net_device){ .netdev_ops = &netops, .flags = IFF_UP };
 fm.ic.ic_softc = &fm; fm.wiphy = &wiphy; fm.ndev = &ndev; fm.ops = &cfgops; fm.running = true;
 fm.vap = calloc(1, sizeof(*fm.vap)); fm.vap->iv_ic = &fm.ic; fm.vap->iv_ifp = &fm;
 node.ni_vap = fm.vap;
 detached = false; frames = sends = errors = stops = aborts = completions = requests = 0;
}
static void queue_frame(void) {
 struct mbuf *m = calloc(1, sizeof(*m)); m->m_pkthdr.rcvif = &node; m->m_pkthdr.len = 16;
 frames++; node.refs++; assert(lkpi_fullmac_transmit(&fm.ic, m) == 0);
}
static void start_scan(void) {
 fm.scan = calloc(1, sizeof(*fm.scan)); requests++;
 fm.scan->wiphy = &wiphy; fm.scan_vap = fm.vap; fm.scan_vap->refs++; fm.scan_active = true;
}
static void test_rsn(void) {
 uint8_t ie[44] = {48,18,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2};
 struct cfg80211_connect_params p = {0}; uint32_t pairwise, akm;
 assert(lkpi_fullmac_rsn(ie,20,&p,&pairwise,&akm) == 0);
 for (unsigned n = 2; n < 20; n++) {
  ie[1] = n - 2; assert(lkpi_fullmac_rsn(ie,n,&p,&pairwise,&akm) != 0);
 }
 ie[1] = 19; assert(lkpi_fullmac_rsn(ie,21,&p,&pairwise,&akm) == -EINVAL);
 ie[1] = 20; assert(lkpi_fullmac_rsn(ie,22,&p,&pairwise,&akm) == 0);
 for (unsigned caps = 0x40; caps <= 0xc0; caps += 0x40) {
  ie[20] = caps; assert(lkpi_fullmac_rsn(ie,22,&p,&pairwise,&akm) == -EOPNOTSUPP);
 }
 ie[20] = 0; ie[1] = 22; ie[22] = 1;
 assert(lkpi_fullmac_rsn(ie,24,&p,&pairwise,&akm) == -EINVAL);
 ie[1] = 38; assert(lkpi_fullmac_rsn(ie,40,&p,&pairwise,&akm) == 0);
 ie[1] = 42; assert(lkpi_fullmac_rsn(ie,44,&p,&pairwise,&akm) == -EOPNOTSUPP);
 ie[1] = 18; ie[13] = 2; assert(lkpi_fullmac_rsn(ie,20,&p,&pairwise,&akm) == -EOPNOTSUPP);
}
int main(void) {
 setup(); fm.vap->refs = 1; waited_refs = 0;
 queue_frame(); queue_frame(); ndev.stopped = true;
 taskqueue_drain(fm.tx_queue, &fm.tx_task);
 assert(frames == 2 && sends == 0); /* firmware flow control */
 lkpi_fullmac_vap_delete(fm.vap);
 assert(detached && frames == 0 && node.refs == 0 && errors == 2 && stops == 1);
 assert(waited_refs == 1 && !fm.vap_deleting);
 struct mbuf rejected = {0}; assert(lkpi_fullmac_transmit(&fm.ic, &rejected) == ENETDOWN);
 setup(); queue_frame(); taskqueue_drain(fm.tx_queue, &fm.tx_task);
 assert(sends == 1 && frames == 0); lkpi_fullmac_vap_delete(fm.vap);
 setup(); start_scan(); synchronous_abort = true; sdt_count = 0;
 lkpi_fullmac_scan_end(&fm.ic);
 assert(aborts == 1 && completions == 0 && requests == 0 && fm.vap->refs == 0);
 assert(sdt_count == 2 && strcmp(sdt_events[0].name, "scan__abort") == 0);
 assert(strcmp(sdt_events[1].name, "scan__done") == 0);
 assert((int)sdt_events[1].args[2] == -1 && sdt_events[1].args[3] == 0);
 start_scan(); synchronous_abort = false;
 struct cfg80211_scan_request *old = fm.scan;
 lkpi_fullmac_scan_end(&fm.ic);
 assert(aborts == 2 && requests == 1 && completions == 0);
 /* The native scan has ended; its firmware completion must be silent. */
 linuxkpi_fullmac_scan_done(old, NULL);
 assert(requests == 0 && completions == 0 && fm.vap->refs == 0);
 start_scan();
 struct cfg80211_scan_request stale = {.wiphy = &wiphy};
 linuxkpi_fullmac_scan_done(&stale, NULL);
 assert(strcmp(sdt_events[sdt_count - 1].name, "scan__stale") == 0);
 struct cfg80211_scan_info info = {.aborted = true};
 linuxkpi_fullmac_scan_done(fm.scan, &info);
 assert(sdt_events[sdt_count - 1].args[2] == 1);
 assert(sdt_events[sdt_count - 1].args[3] == 1);
 assert(completions == 1 && requests == 0 && fm.vap->refs == 0);
 lkpi_fullmac_scan_end(&fm.ic); assert(aborts == 2);
 lkpi_fullmac_vap_delete(fm.vap);
 /* Access categories and Linux 802.1D priorities use different numbering. */
 const unsigned categories[]={WME_AC_BE,WME_AC_BK,WME_AC_VI,WME_AC_VO};
 const unsigned priorities[]={0,1,5,6};
 for (unsigned i=0;i<4;i++) {
  setup(); queue_frame(); fm.tx_frames.head->ac=categories[i];
  taskqueue_drain(fm.tx_queue,&fm.tx_task);
  assert(sends==1 && last_priority==priorities[i] && frames==0 && node.refs==0);
  lkpi_fullmac_vap_delete(fm.vap);
 }
 /* Allocation failure releases the native frame/node, then TX can recover. */
 setup(); fail_skb_alloc=true; queue_frame();
 taskqueue_drain(fm.tx_queue,&fm.tx_task);
 assert(errors==1 && sends==0 && frames==0 && node.refs==0);
 fail_skb_alloc=false; queue_frame(); taskqueue_drain(fm.tx_queue,&fm.tx_task);
 assert(errors==1 && sends==1 && frames==0 && node.refs==0);
 lkpi_fullmac_vap_delete(fm.vap);
 /* A stopped interface can still have an accepted scan awaiting completion. */
 setup(); start_scan(); fm.running=false; synchronous_abort=false; deferred_scan=true;
 lkpi_fullmac_vap_delete(fm.vap);
 assert(detached && requests==0 && completions==0 && aborts==1);deferred_scan=false;
 test_rsn();
 puts("PASS: TX allocation recovery, traffic-class mapping, paused TX drain before VAP deletion, canceled/late scan completion, RSN truncation and unsupported security rejection");
 return 0;
}

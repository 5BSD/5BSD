/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>
#define ETH_HLEN 14
#define ETHER_HDR_LEN 14
#define ETHER_MAX_LEN 1518
#define ETHER_VLAN_ENCAP_LEN 4
#define ETH_P_802_3_MIN 1536
#define ETH_P_802_3 1
#define ETH_P_802_2 4
#define ETHERTYPE_PAE 0x888e
#define PACKET_HOST 0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
#define PACKET_OTHERHOST 3
#define IEEE80211_S_RUN 5
#define IEEE80211_NODE_AUTH 1
#define IFCOUNTER_IERRORS 1
#define M_NOWAIT 0
#define MT_DATA 0
#define M_PKTHDR 0
#define mtod(m,t) ((t)((m)->data))
#define NET_EPOCH_ENTER(e) ((void)(e))
#define NET_EPOCH_EXIT(e) ((void)(e))
#define IEEE80211_LOCK(ic) ((void)(ic))
#define IEEE80211_UNLOCK(ic) ((void)(ic))
struct ethhdr { uint8_t h_dest[6],h_source[6];uint16_t h_proto; };
struct ether_header { uint8_t dst[6],src[6];uint16_t ether_type; };
struct epoch_tracker { int unused; };
struct lkpi_fullmac { int unused; };
struct net_device { void *bsd_private;uint8_t dev_addr[6]; };
struct sk_buff { struct net_device *dev;uint8_t *head,*data,*mac;unsigned len,data_len;int pkt_type; };
struct ieee80211_node { unsigned ni_flags; };
struct ieee80211vap { void *iv_ic,*iv_ifp;struct ieee80211_node *iv_bss;int iv_state; };
struct mbuf { unsigned m_len;struct { unsigned len; } m_pkthdr;uint8_t data[1600]; };
static struct ieee80211_node node={.ni_flags=1};
static struct ieee80211vap vap={.iv_bss=&node,.iv_state=IEEE80211_S_RUN};
static struct net_device ndev;
static unsigned refs,noderefs,delivered,freed,errors,allocs;
static bool alloc_fail, no_vap;
static unsigned skb_headlen(struct sk_buff *s) { return s->len-s->data_len; }
static bool skb_is_nonlinear(struct sk_buff *s) { return s->data_len!=0; }
static unsigned skb_headroom(struct sk_buff *s) { return s->data-s->head; }
static uint8_t *skb_mac_header(struct sk_buff *s) { return s->mac; }
static void skb_reset_mac_header(struct sk_buff *s) { s->mac=s->data; }
static void skb_pull(struct sk_buff *s,unsigned n) { assert(n<=skb_headlen(s));s->data+=n;s->len-=n; }
static bool is_broadcast_ether_addr(uint8_t *p) { uint8_t all[6];memset(all,255,6);return !memcmp(all,p,6); }
static bool is_multicast_ether_addr(uint8_t *p) { return p[0]&1; }
static bool ether_addr_equal(uint8_t *a,uint8_t *b) { return !memcmp(a,b,6); }
static struct ieee80211vap *lkpi_fullmac_vap_get(struct lkpi_fullmac *f) { (void)f;if(no_vap)return NULL;refs++;return &vap; }
static void ieee80211_com_vdecref(struct ieee80211vap *v) { assert(v==&vap && refs);refs--; }
static struct ieee80211_node *ieee80211_ref_node(struct ieee80211_node *n) { noderefs++;return n; }
static void ieee80211_free_node(struct ieee80211_node *n) { assert(n==&node && noderefs);noderefs--; }
static struct mbuf *m_get2(unsigned len,int a,int b,int c) { (void)a;(void)b;(void)c;assert(len<=1600);allocs++;return alloc_fail?NULL:calloc(1,sizeof(struct mbuf)); }
static void ieee80211_deliver_data(struct ieee80211vap *v,struct ieee80211_node *n,struct mbuf *m) { assert(v==&vap && n==&node && m->m_len==60);assert(m->data[59]==0xa5);delivered++;free(m); }
static void dev_kfree_skb_any(struct sk_buff *s) { (void)s;freed++; }
static void if_inc_counter(void *p,int which,int n) { (void)p;(void)which;errors+=n; }
#include "power_functions.h"
static void test_header_boundary(void) {
 size_t page=sysconf(_SC_PAGESIZE);
 uint8_t *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(mapping!=MAP_FAILED);
 assert(mprotect(mapping+page,page,PROT_NONE)==0);
 for (unsigned n=0;n<ETH_HLEN;n++) {
  uint8_t *p=mapping+page-n;
  struct sk_buff s={.head=p,.data=p,.len=n};
  assert(eth_type_trans(&s,&ndev)==0 && s.data==p);
 }
 uint8_t *p=mapping+page-ETH_HLEN;
 struct ethhdr *eth=(void *)p;
 memset(p,0,ETH_HLEN);eth->h_proto=htons(20);
 /* The payload exists only in fragments, beyond the linear header. */
 struct sk_buff s={.head=p,.data=p,.len=ETH_HLEN+20,.data_len=20};
 assert(eth_type_trans(&s,&ndev)==htons(ETH_P_802_2));
 assert(s.data==mapping+page && s.pkt_type==PACKET_HOST);
 assert(munmap(mapping,2*page)==0);
}
int main(void) {
 test_header_boundary();
 uint8_t bytes[64]={0};bytes[59]=0xa5;
 struct ethhdr *eth=(void *)bytes;eth->h_proto=htons(0x800);
 struct sk_buff skb={.head=bytes,.data=bytes,.len=60};
 assert(eth_type_trans(&skb,&ndev)==htons(0x800));
 lkpi_fullmac_rx(&skb);assert(delivered==1 && freed==1 && refs==0 && noderefs==0);
 /* Total length cannot authorize reading an Ethernet header outside the head. */
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60,.data_len=50};
 assert(eth_type_trans(&skb,&ndev)==0 && skb.data==bytes);
 /* A linear header followed by fragments must not reach the memcpy. */
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60,.data_len=20};
 assert(eth_type_trans(&skb,&ndev)==htons(0x800));
 unsigned before=allocs;lkpi_fullmac_rx(&skb);
 assert(allocs==before && delivered==1 && refs==0 && noderefs==0);
 /* Closed controlled port rejects ordinary data, but accepts EAPOL. */
 node.ni_flags=0;skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 lkpi_fullmac_rx(&skb);assert(delivered==1);
 eth->h_proto=htons(ETHERTYPE_PAE);skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 lkpi_fullmac_rx(&skb);assert(delivered==2);
 /* Even EAPOL must not pass before association or after disconnect. */
 unsigned saved_state = vap.iv_state;
 for (unsigned authorized=0; authorized<2; authorized++) {
  vap.iv_state=0; node.ni_flags=authorized ? IEEE80211_NODE_AUTH : 0;
  skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
  unsigned prior=freed;lkpi_fullmac_rx(&skb);
  assert(delivered==2 && freed==prior+1 && refs==0 && noderefs==0);
 }
 vap.iv_state=saved_state;node.ni_flags=0;
 alloc_fail=true;skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 lkpi_fullmac_rx(&skb);assert(errors==1 && refs==0 && noderefs==0);
 alloc_fail=false;
 /* VAP absence, invalid MAC placement and oversized frames release ownership. */
 no_vap=true;skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 before=allocs;unsigned freed_before=freed;lkpi_fullmac_rx(&skb);
 assert(freed==freed_before+1 && allocs==before && refs==0 && noderefs==0);no_vap=false;
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);skb.mac++;
 lkpi_fullmac_rx(&skb);assert(allocs==before && refs==0 && noderefs==0);
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);skb.len=UINT32_MAX;
 lkpi_fullmac_rx(&skb);assert(allocs==before && refs==0 && noderefs==0);
 /* Destination classification and the two 802.3 payload formats. */
 eth->h_proto=htons(20);bytes[14]=bytes[15]=0xff;
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};
 assert(eth_type_trans(&skb,&ndev)==htons(ETH_P_802_3));
 bytes[14]=0xaa;memset(eth->h_dest,255,6);
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};
 assert(eth_type_trans(&skb,&ndev)==htons(ETH_P_802_2) && skb.pkt_type==PACKET_BROADCAST);
 memset(eth->h_dest,0,6);eth->h_dest[0]=1;
 skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 assert(skb.pkt_type==PACKET_MULTICAST);
 eth->h_dest[0]=2;skb=(struct sk_buff){.head=bytes,.data=bytes,.len=60};eth_type_trans(&skb,&ndev);
 assert(skb.pkt_type==PACKET_OTHERHOST);
 puts("PASS: guarded header boundaries, RX rejection ownership, packet classification, linear RX delivery, fragmented-header/payload rejection, controlled-port filtering and allocation failure");
 return 0;
}

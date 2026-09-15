/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_WEP_NKID 4
#define IEEE80211_CIPHER_AES_CCM 3
#define IEEE80211_KEY_GROUP 4
#define WLAN_CIPHER_SUITE_CCMP 0x000fac04
struct ieee80211_cipher { unsigned ic_cipher; };
typedef unsigned ieee80211_keyix;
struct ieee80211_key { struct ieee80211_cipher *wk_cipher;unsigned wk_flags,wk_keyix,wk_keylen;uint8_t wk_key[16],wk_macaddr[6];uint64_t wk_keyrsc[16]; };
struct ieee80211_node { unsigned refs; };
struct ieee80211com { void *ic_softc;bool locked,ic_sta; };
struct ieee80211vap { struct ieee80211com *iv_ic;struct ieee80211_node *iv_bss;struct ieee80211_key iv_nw_keys[4]; };
struct wiphy { bool locked; };
struct key_params { uint8_t *key,*seq;unsigned key_len,seq_len,cipher; };
struct net_device { int dummy; };
struct ops {
 int (*add_key)(struct wiphy *,struct net_device *,int,unsigned,bool,const uint8_t *,struct key_params *);
 int (*del_key)(struct wiphy *,struct net_device *,int,unsigned,bool,const uint8_t *);
};
struct lkpi_fullmac { struct wiphy *wiphy;struct net_device *ndev;struct ops *ops;bool running,stopping; };
struct lkpi_fullmac_key_lock { bool ic,nodes;struct ieee80211_node *ni; };
static struct ieee80211com ic;
static struct ieee80211_node node;
static unsigned calls,zeros;
static int firmware_error;
static bool expected_pairwise;
static unsigned expected_index;
static uint8_t expected_key[16],expected_mac[6]={2,4,6,8,10,12};
#define IEEE80211_IS_LOCKED(i) ((i)->locked)
#define IEEE80211_NODE_IS_LOCKED(p) (*(p))
#define IEEE80211_NODE_UNLOCK(p) do { assert(*(p));*(p)=false; } while(0)
#define IEEE80211_NODE_LOCK(p) do { assert(!*(p));*(p)=true; } while(0)
#define IEEE80211_UNLOCK(i) do { assert((i)->locked);(i)->locked=false; } while(0)
#define IEEE80211_LOCK(i) do { assert(!(i)->locked);(i)->locked=true; } while(0)
static struct ieee80211_node *ieee80211_ref_node(struct ieee80211_node *n) { n->refs++;return n; }
static void ieee80211_free_node(struct ieee80211_node *n) { assert(n->refs);n->refs--; }
static void wiphy_lock(struct wiphy *w) { assert(!ic.locked && !ic.ic_sta && !w->locked);w->locked=true; }
static void wiphy_unlock(struct wiphy *w) { assert(w->locked);w->locked=false; }
static void zero_key(void *p,size_t n) { assert(n==16);memset(p,0,n);zeros++; }
#define explicit_bzero zero_key
static void check_call(struct wiphy *w,int link,unsigned index,bool pairwise,const uint8_t *mac) {
 assert(w->locked && !ic.locked && !ic.ic_sta && node.refs==1 && link==-1);
 assert(index==expected_index && pairwise==expected_pairwise);
 assert(pairwise ? mac && !memcmp(mac,expected_mac,6) : mac==NULL);calls++;
}
static int add_key(struct wiphy *w,struct net_device *n,int link,unsigned index,bool pairwise,const uint8_t *mac,struct key_params *p) {
 (void)n;check_call(w,link,index,pairwise,mac);
 const uint8_t seq[]={6,5,4,3,2,1};
 assert(p->cipher==WLAN_CIPHER_SUITE_CCMP && p->key_len==16 && p->seq_len==6);
 assert(!memcmp(p->key,expected_key,16) && !memcmp(p->seq,seq,6));return firmware_error;
}
static int del_key(struct wiphy *w,struct net_device *n,int link,unsigned index,bool pairwise,const uint8_t *mac) {
 (void)n;check_call(w,link,index,pairwise,mac);return firmware_error;
}
#include "power_functions.h"
int main(void) {
 struct wiphy w={0};struct net_device n={0};struct ops ops={add_key,del_key};
 struct lkpi_fullmac fm={&w,&n,&ops,true,false};ic.ic_softc=&fm;
 struct ieee80211vap vap={.iv_ic=&ic,.iv_bss=&node};struct ieee80211_cipher cipher={IEEE80211_CIPHER_AES_CCM};
 struct ieee80211_key key={.wk_cipher=&cipher,.wk_keylen=16,.wk_keyrsc={0x010203040506}};
 for(unsigned i=0;i<16;i++)key.wk_key[i]=expected_key[i]=i+1;
 memcpy(key.wk_macaddr,expected_mac,6);
 for(unsigned locks=0;locks<4;locks++)for(unsigned group=0;group<2;group++)for(unsigned fail=0;fail<2;fail++) {
  ic.locked=locks&1;ic.ic_sta=locks&2;firmware_error=fail?-EIO:0;
  expected_pairwise=!group;expected_index=group?2:0;key.wk_keyix=expected_index;key.wk_flags=group?IEEE80211_KEY_GROUP:0;
  unsigned old_calls=calls,old_zeros=zeros;
  assert(lkpi_fullmac_key_set(&vap,&key)==!fail);
  assert(calls==old_calls+1 && zeros==old_zeros+1 && node.refs==0 && !w.locked);
  assert(ic.locked==!!(locks&1) && ic.ic_sta==!!(locks&2));
  assert(lkpi_fullmac_key_delete(&vap,&key)==!fail);
  assert(calls==old_calls+2 && node.refs==0 && !w.locked);
  assert(ic.locked==!!(locks&1) && ic.ic_sta==!!(locks&2));
 }
 ic.locked=ic.ic_sta=false;firmware_error=0;
 unsigned old_calls=calls;fm.running=false;
 assert(!lkpi_fullmac_key_set(&vap,&key) && lkpi_fullmac_key_delete(&vap,&key));
 assert(calls==old_calls && node.refs==0);fm.running=true;fm.stopping=true;
 assert(!lkpi_fullmac_key_set(&vap,&key) && lkpi_fullmac_key_delete(&vap,&key));fm.stopping=false;
 key.wk_keylen=15;assert(!lkpi_fullmac_key_set(&vap,&key));key.wk_keylen=16;
 key.wk_keyix=4;assert(!lkpi_fullmac_key_set(&vap,&key));assert(calls==old_calls);
 for(unsigned i=0;i<4;i++) {
  vap.iv_nw_keys[i].wk_cipher=&cipher;unsigned tx=99,rx=99;
  assert(lkpi_fullmac_key_alloc(&vap,&vap.iv_nw_keys[i],&tx,&rx) && tx==i && rx==i);
 }
 puts("PASS: key lock restoration, pairwise/group identity, replay-sequence byte order, firmware errors and shutdown exclusion");
 return 0;
}

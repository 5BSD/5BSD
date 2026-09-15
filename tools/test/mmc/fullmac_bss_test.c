/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct ieee80211vap;
struct ieee80211com { struct { struct ieee80211vap *first; } ic_vaps; bool locked; };
struct ieee80211vap { struct ieee80211com *iv_ic; unsigned refs; bool deleting; };
struct lkpi_fullmac { bool stopping,lock; struct ieee80211vap *vap; };
struct lkpi_hw { struct ieee80211com *ic; };
struct wiphy { void *bsd_netdev_ops,*bsd_fullmac; struct lkpi_hw hw; };
struct cfg80211_bss { int unused; };
struct lkpi_cfg80211_bss { unsigned refcnt; struct cfg80211_bss bss; };
struct linuxkpi_ieee80211_channel { int unused; };
enum ieee80211_bss_type { ANY_BSS };
enum ieee80211_privacy { ANY_PRIVACY };
struct lkpi_cfg80211_get_bss_iter_lookup {
 struct wiphy *wiphy;struct linuxkpi_ieee80211_channel *chan;
 const uint8_t *bssid,*ssid;size_t ssid_len;
 enum ieee80211_bss_type bss_type;enum ieee80211_privacy privacy;
 bool match;struct cfg80211_bss *bss;
};
static struct ieee80211com ic;
static struct ieee80211vap vap;
static struct lkpi_fullmac fm;
static bool fail_alloc,match,delete_during_scan;
static unsigned allocations,scans;
static void mtx_lock(bool *lock) { assert(!*lock);*lock=true; }
static void mtx_unlock(bool *lock) { assert(*lock);*lock=false; }
#define IEEE80211_LOCK(ic) mtx_lock(&(ic)->locked)
#define IEEE80211_UNLOCK(ic) mtx_unlock(&(ic)->locked)
#define IEEE80211_IS_LOCKED(ic) ((ic)->locked)
#define TAILQ_FIRST(head) ((head)->first)
#define wiphy_priv(w) (&(w)->hw)
static int ieee80211_com_vincref(struct ieee80211vap *v) {
 assert(fm.lock||v->iv_ic->locked);if(v->deleting)return 1;v->refs++;return 0;
}
static void ieee80211_com_vdecref(struct ieee80211vap *v) { assert(v->refs);v->refs--; }
#define ic_printf(...) ((void)0)
#define IMPROVE(...) ((void)0)
#define M_LKPI80211 0
#define M_NOWAIT 1
#define M_ZERO 2
static void *alloc(size_t n,int type,int flags) {
 (void)type;(void)flags;assert(vap.refs==1);if(fail_alloc)return NULL;
 allocations++;return calloc(1,n);
}
static void release(void *p,int type) { (void)type;assert(allocations);allocations--;free(p); }
#define malloc alloc
#define free release
#define lkpi_cfg80211_get_bss_iterf 0
static void ieee80211_scan_iterate(struct ieee80211vap *v,int callback,void *arg) {
 struct lkpi_cfg80211_get_bss_iter_lookup *lookup=arg;(void)callback;
 assert(v->refs==1);scans++;
 if(delete_during_scan) {
  /* Deletion unpublishes the VAP, but its reference must survive iteration. */
  fm.vap=NULL;ic.ic_vaps.first=NULL;v->deleting=true;
  assert(v->refs==1);
 }
 lookup->match=match;
}
#define refcount_init(p,n) (*(p)=(n))
#include "power_functions.h"
#undef malloc
#undef free
static void reset(void) {
 assert(allocations==0);memset(&ic,0,sizeof(ic));memset(&vap,0,sizeof(vap));memset(&fm,0,sizeof(fm));
 vap.iv_ic=&ic;ic.ic_vaps.first=&vap;fm.vap=&vap;
 fail_alloc=delete_during_scan=false;match=true;scans=0;
}
static struct cfg80211_bss *lookup(struct wiphy *w) {
 return linuxkpi_cfg80211_get_bss(w,NULL,NULL,NULL,0,ANY_BSS,ANY_PRIVACY);
}
int main(void) {
 struct wiphy w={.bsd_netdev_ops=(void *)1,.bsd_fullmac=&fm,.hw={.ic=&ic}};
 for(unsigned backend=0;backend<2;backend++) {
  w.bsd_netdev_ops=backend ? (void *)1 : NULL;
  reset();fail_alloc=true;assert(!lookup(&w)&&vap.refs==0&&!scans);
  reset();match=false;assert(!lookup(&w)&&vap.refs==0&&scans==1&&!allocations);
  reset();vap.deleting=true;assert(!lookup(&w)&&!vap.refs&&!scans);
  reset();delete_during_scan=true;struct cfg80211_bss *bss=lookup(&w);
  assert(bss&&vap.refs==0&&scans==1);
  struct lkpi_cfg80211_bss *owner=(void *)((char *)bss - __builtin_offsetof(struct lkpi_cfg80211_bss,bss));
  assert(owner->refcnt==1);release(owner,0);
 }
 reset();fm.stopping=true;assert(!lookup(&w)&&!scans);
 w.bsd_netdev_ops=NULL;reset();ic.locked=true;match=false;
 assert(!lookup(&w)&&ic.locked&&vap.refs==0);ic.locked=false;
 puts("PASS: FullMAC/SoftMAC BSS lookup holds VAP references through deletion, balances failures and preserves caller locks");
 return 0;
}

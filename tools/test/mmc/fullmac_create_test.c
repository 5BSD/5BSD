/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#define IFNAMSIZ 16
#define IEEE80211_ADDR_LEN 6
#define M_LKPIFM 0
#define M_WAITOK 0
#define M_ZERO 0
#define IFF_UP 1
#define IEEE80211_CLONE_NOBEACONS 1
#define IEEE80211_FEXT_SCAN_OFFLOAD 2
#define IEEE80211_FEXT_SWBMISS 4
#define IEEE80211_ADDR_EQ(a,b) (memcmp(a,b,6)==0)
#define malloc(n,t,f) calloc(1,n)
#define free(p,t) free(p)
#define lkpi_fullmac_newstate 0
#define lkpi_fullmac_key_alloc 0
#define lkpi_fullmac_key_set 0
#define lkpi_fullmac_key_delete 0
#define ieee80211_media_change 0
#define ieee80211_media_status 0
enum ieee80211_opmode { IEEE80211_M_STA };
struct ieee80211com { void *ic_softc; };
struct ieee80211vap { int iv_newstate,iv_flags_ext,iv_key_alloc,iv_key_set,iv_key_delete,iv_max_keyix; };
struct net_device;
struct net_device_ops { int (*ndo_stop)(struct net_device *); };
struct net_device { uint8_t dev_addr[6]; void *bsd_private; unsigned flags; struct net_device_ops *netdev_ops; };
struct wiphy { struct { struct { int unused; } sx; } mtx; };
struct lkpi_fullmac {
 struct ieee80211com ic;
 bool stopping,vap_deleting,vap_creating,attached,running;
 struct ieee80211vap *vap;
 struct net_device *ndev;
 struct wiphy *wiphy;
 pthread_mutex_t lock;
 void *tx_queue;
 int tx_task;
};
struct lkpi_fullmac_vap { struct ieee80211vap vap; int newstate; };
static struct lkpi_fullmac fm;
static struct net_device ndev;
static struct wiphy wiphy;
static pthread_cond_t reservation_cv=PTHREAD_COND_INITIALIZER;
static pthread_mutex_t setup_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t setup_cv=PTHREAD_COND_INITIALIZER;
static bool hold_setup,setup_entered,setup_fail,release_setup;
static unsigned attached,detached;
static struct ieee80211vap *created;
static void mtx_lock(pthread_mutex_t *m) { assert(pthread_mutex_lock(m)==0); }
static void mtx_unlock(pthread_mutex_t *m) { assert(pthread_mutex_unlock(m)==0); }
static void wakeup(void *p) { assert(p==&fm.vap_creating); pthread_cond_broadcast(&reservation_cv); }
static void mtx_sleep(void *p,pthread_mutex_t *m,int pri,const char *name,int ticks) {
 assert(p==&fm.vap_creating); (void)pri;(void)name;(void)ticks;
 assert(pthread_cond_wait(&reservation_cv,m)==0);
}
#define sx_xlocked(s) false
static void wiphy_lock(struct wiphy *w) { assert(w==&wiphy); }
static void wiphy_unlock(struct wiphy *w) { assert(w==&wiphy); }
static void taskqueue_enqueue(void *q,int *t) { (void)q;(void)t; }
static void taskqueue_drain(void *q,int *t) { (void)q;(void)t; }
static void ieee80211_ifdetach(struct ieee80211com *ic) {
 assert(ic==&fm.ic && fm.stopping && !fm.vap_creating);
 assert(setup_fail || fm.vap==created); detached++;
}
static int ieee80211_vap_setup(struct ieee80211com *ic,struct ieee80211vap *v,const char *name,int unit,enum ieee80211_opmode op,int flags,const uint8_t *bssid) {
 (void)ic;(void)v;(void)name;(void)unit;(void)op;(void)flags;(void)bssid;
 assert(fm.vap_creating);
 pthread_mutex_lock(&setup_lock);
 setup_entered=true;
 pthread_cond_broadcast(&setup_cv);
 while (hold_setup && !release_setup) pthread_cond_wait(&setup_cv,&setup_lock);
 pthread_mutex_unlock(&setup_lock);
 return setup_fail ? 1 : 0;
}
static void ieee80211_vap_attach(struct ieee80211vap *v,int a,int b,const uint8_t *mac) {
 (void)a;(void)b;(void)mac; attached++; created=v;
}
#include "power_functions.h"
static struct ieee80211vap *create(void) {
 return lkpi_fullmac_vap_create(&fm.ic,"wlan",0,IEEE80211_M_STA,0,ndev.dev_addr,ndev.dev_addr);
}
static void *create_thread(void *arg) { (void)arg; return create(); }
static void *unregister_thread(void *arg) { (void)arg; lkpi_fullmac_unregister(&ndev); return NULL; }
static void reset(void) {
 memset(&fm,0,sizeof(fm));memset(&ndev,0,sizeof(ndev));
 fm.ndev=&ndev; fm.ic.ic_softc=&fm; fm.wiphy=&wiphy;fm.attached=true;
 ndev.bsd_private=&fm;ndev.dev_addr[0]=2;
 assert(pthread_mutex_init(&fm.lock,NULL)==0);
 attached=detached=0;created=NULL;
 hold_setup=setup_entered=setup_fail=release_setup=false;
}
int main(void) {
 /* A failed setup returns the reserved slot for a later creation. */
 reset();setup_fail=true;
 assert(create()==NULL && !fm.vap_creating && fm.vap==NULL);
 setup_fail=false;struct ieee80211vap *vap=create();
 assert(vap && !fm.vap_creating && fm.vap==vap && attached==1);
 assert(create()==NULL);
 free(vap,M_LKPIFM);pthread_mutex_destroy(&fm.lock);
 for (unsigned failure=0;failure<2;failure++) {
  reset();hold_setup=true;setup_fail=failure!=0;
  pthread_t creator,remover;
  assert(pthread_create(&creator,NULL,create_thread,NULL)==0);
  pthread_mutex_lock(&setup_lock);
  while (!setup_entered) pthread_cond_wait(&setup_cv,&setup_lock);
  pthread_mutex_unlock(&setup_lock);
  /* First creation is asleep in setup: a second must be rejected. */
  assert(create()==NULL);
  assert(pthread_create(&remover,NULL,unregister_thread,NULL)==0);
  for (;;) {
   mtx_lock(&fm.lock);
   bool stopping=fm.stopping;
   if (stopping) assert(fm.vap_creating && detached==0);
   mtx_unlock(&fm.lock);
   if (stopping) break;
   sched_yield();
  }
  assert(create()==NULL);
  pthread_mutex_lock(&setup_lock);release_setup=true;
  pthread_cond_broadcast(&setup_cv);pthread_mutex_unlock(&setup_lock);
  void *result;
  pthread_join(creator,&result);pthread_join(remover,NULL);
  assert(detached==1 && !fm.vap_creating && !fm.attached);
  assert((result==NULL)==setup_fail && attached==!setup_fail);
  free(result,M_LKPIFM);pthread_mutex_destroy(&fm.lock);
 }
 puts("PASS: exclusive VAP reservation, setup rollback and unregister waiting for success/failure");
 return 0;
}

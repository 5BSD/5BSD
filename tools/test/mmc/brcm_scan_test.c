/* SPDX-License-Identifier: BSD-2-Clause */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <stddef.h>
typedef int32_t s32;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
#define BIT(n) (1U << (n))
#define BRCMF_FEAT_SCAN_V2 1
#define BRCMF_C_SCAN 1
#define BRCMF_SCAN_STATUS_BUSY 0
#define BRCMF_SCAN_STATUS_ABORT 1
#define BRCMF_SCAN_STATUS_SUPPRESS 2
#define BRCMF_SCAN_STATUS_COMPLETING 3
#define BRCMF_VIF_STATUS_CONNECTING 0
#define BRCMF_VNDR_IE_PRBREQ_FLAG 0
#define P2PAPI_BSSCFG_DEVICE 0
#define P2PAPI_BSSCFG_PRIMARY 1
#define BRCMF_ESCAN_TIMER_INTERVAL_MS 8000
#define jiffies 0
#define msecs_to_jiffies(n) (n)
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define brcmf_dbg(...) ((void)0)
#define bphy_err(d, ...) ((void)(d))
#define xchg(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define __ffs(v) __builtin_ctz(v)
struct work_struct { bool pending, running; };
struct timer_list { int unused; };
struct brcmf_cfg80211_info;
struct brcmf_pub { struct brcmf_cfg80211_info *config; };
struct brcmf_if { struct brcmf_pub *drvr; int bsscfgidx; };
struct brcmf_event_msg { s32 status; u32 datalen; };
struct brcmf_bss_info_le { u32 length,version,ie_length; u16 capability,ie_offset; uint8_t SSID_len,SSID[32]; };
struct brcmf_escan_result_le { u32 buflen,version;u16 sync_id,bss_count; struct brcmf_bss_info_le bss_info_le; };
struct brcmf_scan_results { u32 buflen,version,count; struct brcmf_bss_info_le bss_info_le[]; };
#define WL_ESCAN_RESULTS_FIXED_SIZE offsetof(struct brcmf_escan_result_le,bss_info_le)
#define BRCMF_ESCAN_BUF_SIZE 256
#define WL_BSS_INFO_MAX 256
#define BRCMF_E_STATUS_ABORT 1
#define BRCMF_E_STATUS_PARTIAL 2
#define BRCMF_E_STATUS_SUCCESS 0
#define WL_ESCAN_STATE_IDLE 0
#define NL80211_IFTYPE_ADHOC 0
#define WLAN_CAPABILITY_IBSS 2
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)
#define timer_container_of(v,t,m) container_of(t,struct brcmf_cfg80211_info,m)
#define mutex_lock(m) assert(pthread_mutex_lock(m)==0)
#define mutex_unlock(m) assert(pthread_mutex_unlock(m)==0)
#include <string.h>
struct wireless_dev { int unused; };
struct brcmf_cfg80211_vif { struct wireless_dev wdev; struct brcmf_if *ifp; unsigned sme_state; };
struct brcmf_scan_params_v2_le { int unused; };
struct brcmf_scan_params_le { int unused; };
struct cfg80211_scan_request { int live; struct wireless_dev *wdev; void *ie; unsigned ie_len; };
struct cfg80211_scan_info { bool aborted; };
struct escan_info { void (*run)(void); struct brcmf_if *ifp; unsigned char *escan_buf; u32 escan_state; };
struct brcmf_cfg80211_info {
 struct brcmf_pub *pub;
 struct cfg80211_scan_request *scan_request;
 struct timer_list escan_timeout;
 pthread_mutex_t scan_mutex;
 u16 escan_sync_id,escan_timeout_id;
 bool scan_stopping;
 struct work_struct escan_timeout_work;
 unsigned int_escan_map, scan_status;
 void *pno;
 struct { struct { struct brcmf_cfg80211_vif *vif; } bss_idx[2]; } p2p;
 struct escan_info escan_info;
};
struct wiphy { struct brcmf_cfg80211_info *cfg; unsigned interface_modes; };
static struct brcmf_cfg80211_info *review_cfg;
static struct wiphy review_wiphy;
static struct brcmf_cfg80211_vif review_vif;
static struct cfg80211_scan_request *next_request;
static int nested_phase, blocked_starts, scan_starts;
static s32 brcmf_cfg80211_scan(struct wiphy *, struct cfg80211_scan_request *);
s32 brcmf_notify_escan_complete(struct brcmf_cfg80211_info *, struct brcmf_if *, bool, bool);
#define READ_ONCE(v) __atomic_load_n(&(v),__ATOMIC_SEQ_CST)
#define WRITE_ONCE(v,n) __atomic_store_n(&(v),(n),__ATOMIC_SEQ_CST)
static bool test_bit(unsigned bit, const unsigned *p) { return (READ_ONCE(*p) & BIT(bit)) != 0; }
static void set_bit(unsigned bit, unsigned *p) { __atomic_fetch_or(p,BIT(bit),__ATOMIC_SEQ_CST); }
static bool test_and_set_bit(unsigned bit, unsigned *p) { return (__atomic_fetch_or(p,BIT(bit),__ATOMIC_SEQ_CST) & BIT(bit)) != 0; }
static void clear_bit(unsigned bit, unsigned *p) { __atomic_fetch_and(p,~BIT(bit),__ATOMIC_SEQ_CST); }
static struct brcmf_cfg80211_info *wiphy_to_cfg(struct wiphy *w) { return w->cfg; }
static bool check_vif_up(struct brcmf_cfg80211_vif *v) { (void)v; return true; }
static void brcmf_run_escan(void) {}
static int brcmf_p2p_scan_prep(struct wiphy *w, struct cfg80211_scan_request *r, struct brcmf_cfg80211_vif *v) { (void)w; (void)r; (void)v; return 0; }
static int brcmf_vif_set_mgmt_ie(struct brcmf_cfg80211_vif *v, int flag, void *ie, unsigned len) { (void)v; (void)flag; (void)ie; (void)len; return 0; }
u16 brcmf_escan_begin(struct brcmf_cfg80211_info *);
static int brcmf_do_escan(struct brcmf_if *i, struct cfg80211_scan_request *r) {
 (void)r; brcmf_escan_begin(i->drvr->config); scan_starts++; return 0;
}
static void mod_timer(struct timer_list *t, int delay) { (void)t; (void)delay; }

static unsigned canceled;
static void cancel_work_sync(struct work_struct *w) {
 struct brcmf_cfg80211_info *cfg=container_of(w,struct brcmf_cfg80211_info,escan_timeout_work);
 assert(pthread_mutex_trylock(&cfg->scan_mutex)==0);
 pthread_mutex_unlock(&cfg->scan_mutex);w->pending=false;canceled++;
}
static unsigned informed;
static void brcmf_inform_bss(struct brcmf_cfg80211_info *cfg) { (void)cfg; informed++; }
static void schedule_work(struct work_struct *w) { w->pending=true; }
static bool brcmf_p2p_scan_finding_common_channel(struct brcmf_cfg80211_info *c,struct brcmf_bss_info_le *b) { (void)c;(void)b;return false; }
static bool brcmf_compare_update_same_bss(struct brcmf_cfg80211_info *c,struct brcmf_bss_info_le *a,struct brcmf_bss_info_le *b) { (void)c;(void)a;(void)b;return false; }
static unsigned completions;
static void timer_delete_sync(struct timer_list *t) { (void)t; }
static void brcmf_escan_prep(struct brcmf_cfg80211_info *c,
    struct brcmf_scan_params_v2_le *p, void *r) { (void)c; (void)p; (void)r; }
static bool brcmf_feat_is_enabled(struct brcmf_if *i, int feature) { (void)i; (void)feature; return true; }
static int brcmf_fil_cmd_data_set(struct brcmf_if *i, int cmd, void *p, size_t n) {
 (void)i; (void)cmd; (void)p; (void)n; return 0;
}
static void brcmf_scan_params_v2_to_v1(struct brcmf_scan_params_v2_le *p,
    struct brcmf_scan_params_le *q) { (void)p; (void)q; }
static void brcmf_scan_config_mpc(struct brcmf_if *i, int on) {
 (void)on;
 if (review_cfg != NULL && nested_phase == 0) {
  nested_phase = 1;
  /* A second firmware completion interrupts the owner before notification. */
  assert(brcmf_notify_escan_complete(review_cfg,i,false,false) == 0);
  assert(test_bit(BRCMF_SCAN_STATUS_BUSY,&review_cfg->scan_status));
 }
}
static u64 brcmf_pno_find_reqid_by_bucket(void *p, u32 bucket) { (void)p; return bucket; }
static struct wiphy *cfg_to_wiphy(struct brcmf_cfg80211_info *c) { (void)c; return &review_wiphy; }
static void cfg80211_sched_scan_results(void *w, u64 reqid) { (void)w; (void)reqid; }
static void cfg80211_scan_done(struct cfg80211_scan_request *r, struct cfg80211_scan_info *i) {
 (void)i; assert(r->live == 1); r->live = 0;
 assert(__atomic_fetch_add(&completions, 1, __ATOMIC_SEQ_CST) == 0);
 free(r);
 if (review_cfg != NULL) {
  assert(brcmf_cfg80211_scan(&review_wiphy,next_request) == -EAGAIN);
  blocked_starts++;
 }
}
#include "power_functions.h"
struct worker { struct brcmf_cfg80211_info *cfg; pthread_barrier_t *barrier; bool abort; };
static void *complete_scan(void *arg) {
 struct worker *w = arg; struct brcmf_if ifp = {0};
 pthread_barrier_wait(w->barrier);
 assert(brcmf_notify_escan_complete(w->cfg, &ifp, w->abort, w->abort) == 0);
 return NULL;
}
int main(void) {
 struct brcmf_pub pub = {0}; struct brcmf_if ifp = {.drvr=&pub};
 unsigned char scan_buf[BRCMF_ESCAN_BUF_SIZE]={0};
 struct brcmf_cfg80211_info cfg = {.pub=&pub,.scan_mutex=PTHREAD_MUTEX_INITIALIZER};
 pub.config=&cfg;cfg.escan_info.ifp=&ifp;cfg.escan_info.escan_buf=scan_buf;
 for (unsigned i=0;i<200;i++) {
  cfg.scan_status=1;
  pthread_barrier_t barrier;pthread_t threads[2];
  cfg.scan_request=calloc(1,sizeof(*cfg.scan_request));cfg.scan_request->live=1;
  completions=0;pthread_barrier_init(&barrier,NULL,2);
  struct worker workers[2]={{&cfg,&barrier,false},{&cfg,&barrier,true}};
  for (unsigned j=0;j<2;j++) assert(pthread_create(&threads[j],NULL,complete_scan,&workers[j])==0);
  for (unsigned j=0;j<2;j++) pthread_join(threads[j],NULL);
  assert(completions==1 && cfg.scan_request==NULL);pthread_barrier_destroy(&barrier);
 }
 review_vif.ifp=&ifp;review_wiphy.cfg=&cfg;
 /* Capture an old timeout, then finish that scan through a firmware event. */
 struct cfg80211_scan_request *request=calloc(1,sizeof(*request));
 request->live=1;request->wdev=&review_vif.wdev;completions=0;
 assert(brcmf_cfg80211_scan(&review_wiphy,request)==0);
 u16 old_id=cfg.escan_sync_id;
 brcmf_escan_timeout(&cfg.escan_timeout);
 assert(cfg.escan_timeout_work.pending && cfg.escan_timeout_id==old_id);
 struct brcmf_escan_result_le event={.sync_id=old_id};
 struct brcmf_event_msg msg={.status=BRCMF_E_STATUS_SUCCESS,.datalen=WL_ESCAN_RESULTS_FIXED_SIZE};
 /* Completion callback attempts reentry while scan_mutex is held. */
 review_cfg=&cfg;
 next_request=calloc(1,sizeof(*next_request));next_request->live=1;next_request->wdev=&review_vif.wdev;
 assert(brcmf_cfg80211_escan_handler(&ifp,&msg,&event)==0);
 assert(completions==1 && cfg.scan_request==NULL && blocked_starts==1);
 review_cfg=NULL;
 assert(brcmf_cfg80211_scan(&review_wiphy,next_request)==0);
 assert(cfg.escan_sync_id!=old_id);completions=0;informed=0;
 /* Queued timeout and queued successful event both belong to the old scan. */
 brcmf_cfg80211_escan_timeout_worker(&cfg.escan_timeout_work);
 assert(brcmf_cfg80211_escan_handler(&ifp,&msg,&event)==0);
 assert(cfg.scan_request==next_request && completions==0 && informed==0);
 /* Truncated and absent identities must not complete the current scan. */
 event.sync_id=cfg.escan_sync_id;msg.datalen=WL_ESCAN_RESULTS_FIXED_SIZE-1;
 assert(brcmf_cfg80211_escan_handler(&ifp,&msg,&event)==0);
 msg.datalen=WL_ESCAN_RESULTS_FIXED_SIZE;
 assert(brcmf_cfg80211_escan_handler(&ifp,&msg,NULL)==0);
 assert(cfg.scan_request==next_request && completions==0);
 /* A genuinely headerless terminal event still has no usable scan identity. */
 msg.datalen=0;
 assert(brcmf_cfg80211_escan_handler(&ifp,&msg,NULL)==0);
 assert(cfg.scan_request==next_request && completions==0);
 /* A genuine timeout for the current scan still aborts it exactly once. */
 brcmf_escan_timeout(&cfg.escan_timeout);
 brcmf_cfg80211_escan_timeout_worker(&cfg.escan_timeout_work);
 assert(completions==1 && cfg.scan_request==NULL && informed==1);
 brcmf_cfg80211_escan_timeout_worker(&cfg.escan_timeout_work);
 assert(completions==1 && informed==1);
 cfg.escan_sync_id=UINT16_MAX;
 assert(brcmf_escan_begin(&cfg)==0);
 /* Teardown retires the current request and queued timeout before freeing state. */
 next_request=calloc(1,sizeof(*next_request));next_request->live=1;next_request->wdev=&review_vif.wdev;
 assert(brcmf_cfg80211_scan(&review_wiphy,next_request)==0);completions=0;
 brcmf_escan_timeout(&cfg.escan_timeout);
 brcmf_cfg80211_scan_quiesce(&cfg);
 assert(cfg.scan_stopping && cfg.scan_request==NULL && completions==1);
 assert(canceled==1 && !cfg.escan_timeout_work.pending);
 brcmf_cfg80211_escan_timeout_worker(&cfg.escan_timeout_work);
 assert(completions==1);
 struct cfg80211_scan_request rejected={.wdev=&review_vif.wdev};
 assert(brcmf_cfg80211_scan(&review_wiphy,&rejected)==-ENODEV);
 /* Firmware offsets cannot escape a BSS record, even with integer overflow. */
 struct brcmf_bss_info_le bi={.length=sizeof(bi)+8,.ie_offset=sizeof(bi),.ie_length=8};
 assert(brcmf_bss_valid(&bi,sizeof(bi)+8));
 assert(!brcmf_bss_valid(&bi,sizeof(bi)-1));
 bi.ie_offset=sizeof(bi)-1;assert(!brcmf_bss_valid(&bi,sizeof(bi)+8));
 bi.ie_offset=sizeof(bi)+9;assert(!brcmf_bss_valid(&bi,sizeof(bi)+8));
 bi.ie_offset=sizeof(bi);bi.ie_length=UINT32_MAX;
 assert(!brcmf_bss_valid(&bi,sizeof(bi)+8));
 bi.ie_length=0;bi.length=sizeof(bi);assert(brcmf_bss_valid(&bi,sizeof(bi)));
 /* Every representable firmware SSID length is checked against its array. */
 for (unsigned length=0;length<=UINT8_MAX;length++) {
  bi.SSID_len=length;
  assert(brcmf_bss_valid(&bi,sizeof(bi))==(length<=32));
 }
 pthread_mutex_destroy(&cfg.scan_mutex);
 puts("PASS: concurrent scan completion, callback reentry, stale firmware/timeout identities current timeout, teardown and BSS bounds");
 return 0;
}

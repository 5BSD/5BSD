/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
typedef int32_t s32;
typedef uint8_t u8;
typedef uint16_t u16;
#define IS_ENABLED(x) 0
#define IS_ERR(p) ((intptr_t)(p)<0)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define brcmf_dbg(...) ((void)0)
#define bphy_err(...) ((void)0)
#define SET_NETDEV_DEV(...) ((void)0)
#define NL80211_IFTYPE_STATION 0
#define NL80211_BAND_2GHZ 0
#define IEEE80211_HT_CAP_SUP_WIDTH_20_40 2
#define REGULATORY_CUSTOM_REG 1
#define BRCMF_C_GET_VERSION 1
#define BRCMF_OBSS_COEX_AUTO 1
#define BRCMF_FEAT_DUMP_OBSS 1
#define BRCMF_FEAT_TDLS 2
#define BRCMF_FEAT_SCAN_RANDOM_MAC 3
#define WIPHY_FLAG_SUPPORTS_TDLS 1
#define BRCMF_E_TDLS_PEER_EVENT 1
#define NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR 1
#define BRCMF_MAX_IFS 2
#define BRCMF_BUS_UP 1
#define BRCMF_BUS_DOWN 0
#define INIT_LIST_HEAD(x) ((void)(x))
#define INIT_WORK(w,f) ((w)->initialized=true)
#define brcmf_debugfs_add_entry(...) ((void)0)
#define debugfs_create_file(...) ((void)0)
#define brcmf_feat_debugfs_create(...) ((void)0)
#define brcmf_proto_debugfs_create(...) ((void)0)
#define brcmf_bus_debugfs_create(...) ((void)0)
#define brcmf_cfg80211_reg_notifier 1
#define brcmf_cfg80211_dump_survey 1
#define brcmf_regdom 1
struct net_device;
struct brcmf_pub;
struct brcmf_cfg80211_info;
struct brcmf_cfg80211_vif { struct { struct net_device *netdev; } wdev; struct brcmf_if *ifp; struct brcmf_cfg80211_info *cfg; };
struct net_device { void *ieee80211_ptr; struct brcmf_if *priv; };
struct brcmf_if { struct net_device *ndev; struct brcmf_cfg80211_vif *vif; };
struct band { struct { u16 cap; } ht_cap; };
struct wiphy { struct band *bands[2]; unsigned reg_notifier, regulatory_flags, flags, features; };
struct cfg80211_ops { unsigned dump_survey; };
struct brcmf_bus { int state; struct brcmf_pub *drvr; };
struct device { struct brcmf_bus *data; };
#define dev_get_drvdata(d) ((d)->data)
struct settings { uint8_t mac[6]; bool p2p_enable,ignore_probe_fail; };
struct brcmf_pub {
 struct wiphy *wiphy; struct brcmf_cfg80211_info *config;
 struct brcmf_if *iflist[2],*mon_if; struct brcmf_bus *bus_if; struct settings *settings;
 struct { bool initialized; } bus_reset;
};
struct brcmf_cfg80211_info {
 struct wiphy *wiphy; struct brcmf_pub *pub; int vif_event,vif_list,p2p;
 struct { u8 io_type; } d11inf;
};
enum stage { SUCCESS, PREINIT, PRECOMMAND, PROTO, CFG_ALLOC, VIF_ALLOC, PRIV_INIT,
 VERSION, WIPHY_SETUP, WIPHY_REGISTER, BANDS, EVENTS_FIRST, P2P, BTCOEX, PNO,
 EVENTS_LAST, NET_ATTACH };
static enum stage failure;
static bool cfg_alive,priv_alive,callbacks,scanning,bus_active;
static unsigned vifs,ifaces,activations,quiesces,net_stops;
static struct brcmf_pub *driver;
static int fault(enum stage s) { return failure==s ? -EIO : 0; }
static void *cfg_alloc(size_t size) {
 if(failure==CFG_ALLOC)return NULL;
 assert(!cfg_alive);cfg_alive=true;return calloc(1,size);
}
#define kzalloc_obj(v) cfg_alloc(sizeof(v))
static void kfree(void *p) {
 assert(cfg_alive && !priv_alive && !vifs && !callbacks);
 cfg_alive=false;free(p);
}
static struct brcmf_if *brcmf_get_ifp(struct brcmf_pub *d,int i) { return d->iflist[i]; }
static void init_vif_event(int *v) { (void)v; }
static struct brcmf_cfg80211_vif *brcmf_alloc_vif(struct brcmf_cfg80211_info *c,int t) {
 (void)t;if(failure==VIF_ALLOC)return (void *)(intptr_t)-ENOMEM;
 struct brcmf_cfg80211_vif *v=calloc(1,sizeof(*v));v->cfg=c;vifs++;return v;
}
static void brcmf_free_vif(struct brcmf_cfg80211_vif *v) {
 assert(cfg_alive && v->cfg && vifs && !callbacks && !scanning);vifs--;free(v);
}
#define netdev_priv(n) ((n)->priv)
static int wl_init_priv(struct brcmf_cfg80211_info *c) {
 (void)c;if(failure==PRIV_INIT)return -ENOMEM;priv_alive=true;return 0;
}
static void brcmf_fweh_quiesce(struct brcmf_pub *d) { (void)d;callbacks=false;quiesces++; }
static void brcmf_cfg80211_scan_quiesce(struct brcmf_cfg80211_info *c) {
 assert(cfg_alive && c && !callbacks);scanning=false;
}
static void wl_deinit_priv(struct brcmf_cfg80211_info *c) {
 assert(priv_alive && !callbacks);brcmf_cfg80211_scan_quiesce(c);priv_alive=false;
}
static int brcmf_fil_cmd_int_get(struct brcmf_if *i,int cmd,s32 *out) { (void)i;(void)cmd;*out=1;return fault(VERSION); }
static void brcmu_d11_attach(void *p) { (void)p; }
static int brcmf_setup_wiphy(struct wiphy *w,struct brcmf_if *i) { (void)w;(void)i;return fault(WIPHY_SETUP); }
static void wiphy_apply_custom_regulatory(struct wiphy *w,const int *r) { (void)w;(void)r; }
static bool brcmf_feat_is_enabled(struct brcmf_if *i,int f) { (void)i;(void)f;return false; }
static int wiphy_register(struct wiphy *w) { (void)w;return fault(WIPHY_REGISTER); }
static int brcmf_setup_wiphybands(struct brcmf_cfg80211_info *c) { (void)c;return fault(BANDS); }
static int brcmf_enable_bw40_2g(struct brcmf_cfg80211_info *c) { (void)c;return 0; }
static int brcmf_fil_iovar_int_set(struct brcmf_if *i,const char *s,int v) { (void)i;(void)s;(void)v;return 0; }
static int brcmf_fweh_activate_events(struct brcmf_if *i) {
 (void)i;callbacks=true;return fault(++activations==1 ? EVENTS_FIRST : EVENTS_LAST);
}
static int brcmf_p2p_attach(struct brcmf_cfg80211_info *c,bool f) { (void)c;(void)f;return fault(P2P); }
static int brcmf_btcoex_attach(struct brcmf_cfg80211_info *c) { (void)c;return fault(BTCOEX); }
static int brcmf_pno_attach(struct brcmf_cfg80211_info *c) { (void)c;return fault(PNO); }
#define brcmf_fweh_register(...) ((void)0)
static void brcmf_pno_detach(struct brcmf_cfg80211_info *c) { (void)c; }
static void brcmf_btcoex_detach(struct brcmf_cfg80211_info *c) { (void)c; }
static void brcmf_p2p_detach(int *p) { (void)p; }
static void wiphy_unregister(struct wiphy *w) { (void)w;assert(!callbacks); }
static void brcmf_free_wiphy(struct wiphy *w) { (void)w; }
static struct brcmf_if *brcmf_add_if(struct brcmf_pub *d,int a,int b,bool p,const char *s,const uint8_t *mac) {
 (void)a;(void)b;(void)p;(void)s;(void)mac;
 struct brcmf_if *i=calloc(1,sizeof(*i));i->ndev=calloc(1,sizeof(*i->ndev));i->ndev->priv=i;
 d->iflist[0]=i;ifaces++;return i;
}
static bool is_valid_ether_addr(uint8_t *p) { (void)p;return true; }
static void brcmf_bus_change_state(struct brcmf_bus *b,int s) { b->state=s; }
static int brcmf_bus_preinit(struct brcmf_bus *b) { (void)b;bus_active=true;return fault(PREINIT); }
static int brcmf_c_preinit_dcmds(struct brcmf_if *i) { (void)i;return fault(PRECOMMAND); }
static void brcmf_feat_attach(struct brcmf_pub *d) { (void)d; }
static int brcmf_proto_init_done(struct brcmf_pub *d) { (void)d;return fault(PROTO); }
static void brcmf_proto_add_if(struct brcmf_pub *d,struct brcmf_if *i) { (void)d;(void)i; }
static int brcmf_net_attach(struct brcmf_if *i,bool b) { (void)i;(void)b;scanning=true;return fault(NET_ATTACH); }
static int brcmf_net_p2p_attach(struct brcmf_if *i) { (void)i;return 0; }
static void brcmf_bus_stop(struct brcmf_bus *b) { assert(b->state==BRCMF_BUS_DOWN);bus_active=false; }
static void brcmf_net_detach(struct net_device *n,bool b) {
 (void)b;assert(!bus_active && !callbacks && !scanning && ifaces);
 if(n->priv->vif)brcmf_free_vif(n->priv->vif);
 else assert(n->ieee80211_ptr==NULL);
 free(n->priv);free(n);ifaces--;net_stops++;
}
static void brcmf_cfg80211_detach(struct brcmf_cfg80211_info *c) {
 assert(!vifs && !callbacks && !ifaces);wl_deinit_priv(c);kfree(c);
}
static void brcmf_remove_interface(struct brcmf_if *i,bool locked) {
 assert(driver->iflist[0]==i);brcmf_net_detach(i->ndev,locked);driver->iflist[0]=NULL;
}
static void brcmf_fweh_detach(struct brcmf_pub *d) { (void)d;assert(!callbacks); }
static void brcmf_proto_detach(struct brcmf_pub *d) { (void)d;assert(!ifaces); }
static void brcmf_fwvid_detach(struct brcmf_pub *d) { (void)d;assert(!cfg_alive && !ifaces); }
#undef brcmf_regdom
static const int brcmf_regdom=1;
#include "power_functions.h"
int main(void) {
 for(enum stage f=PREINIT;f<=NET_ATTACH;f++) {
  struct wiphy w={0};struct cfg80211_ops ops={0};struct settings settings={0};struct brcmf_bus bus={0};
  struct brcmf_pub d={.wiphy=&w,.bus_if=&bus,.settings=&settings};driver=&d;
  failure=f;activations=quiesces=0;bus.drvr=&d;struct device dev={.data=&bus};
  assert(brcmf_bus_started(driver,&ops)<0);
  assert(!cfg_alive && !priv_alive && !callbacks && !scanning && !bus_active);
  assert(!vifs && !ifaces && !d.config && !d.iflist[0] && !d.iflist[1]);
  brcmf_detach(&dev); /* brcmf_attach failure cleanup repeats the bus cleanup. */
 }
 assert(net_stops==NET_ATTACH);
 /* Successful reprobe after the failures must still work, then fully detach. */
 for(unsigned cycle=0;cycle<100;cycle++) {
  struct wiphy w={0};struct cfg80211_ops ops={0};struct settings settings={0};
  struct brcmf_pub d={.wiphy=&w,.settings=&settings};
  struct brcmf_bus bus={.drvr=&d};struct device dev={.data=&bus};d.bus_if=&bus;driver=&d;
  failure=SUCCESS;activations=0;
  assert(brcmf_bus_started(&d,&ops)==0);
  assert(cfg_alive && priv_alive && callbacks && scanning && bus_active);
  assert(vifs==1 && ifaces==1 && d.config && d.iflist[0] && d.bus_reset.initialized);
  brcmf_detach(&dev);
  assert(!cfg_alive && !priv_alive && !callbacks && !scanning && !bus_active);
  assert(!vifs && !ifaces && !d.config && !d.iflist[0]);
  brcmf_detach(&dev); /* The later SDIO removal may repeat core cleanup. */
 }
 puts("PASS: 100 attach/detach/repeated-cleanup cycles after 16 injected attach failures retire callbacks and scans, unlink VIFs before cfg free, and clear published pointers");
 return 0;
}

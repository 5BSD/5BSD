/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "sdt_test.h"
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define M_LKPIFM 0
#define M_WAITOK 0
#define M_ZERO 0
#define IEEE80211_SCAN_ACTIVE 1
struct wiphy { int max_scan_ssids; };
struct cfg80211_ssid { unsigned ssid_len; char ssid[32]; };
struct linuxkpi_ieee80211_channel { int frequency; };
struct cfg80211_scan_request {
 struct wiphy *wiphy; void *wdev; unsigned char bssid[6];
 struct cfg80211_ssid *ssids; unsigned n_channels; int n_ssids;
 struct linuxkpi_ieee80211_channel *channels[];
};
struct ieee80211vap { unsigned refs; bool deleting; };
struct channel { int ic_freq; };
struct ieee80211_scan_state {
 struct ieee80211vap *ss_vap; unsigned ss_last; int ss_nssid, ss_flags;
 struct channel *ss_chans[2]; struct { unsigned len; char ssid[32]; } ss_ssid[1];
};
struct ieee80211com { void *ic_softc; struct ieee80211_scan_state *ic_scan; };
struct net_device { void *ieee80211_ptr; };
struct cfg80211_ops { int (*scan)(struct wiphy *, struct cfg80211_scan_request *); };
struct lkpi_fullmac {
 struct wiphy *wiphy; struct net_device *ndev; struct cfg80211_ops *ops;
 int lock; bool running, stopping, scan_active;
 struct cfg80211_scan_request *scan; struct ieee80211vap *scan_vap;
};
static struct lkpi_fullmac fm;
static struct linuxkpi_ieee80211_channel channel = {2412};
static unsigned locks, wlocks, calls, completions, allocations;
static int driver_error;
static void wiphy_lock(struct wiphy *w) { assert(w == fm.wiphy && wlocks++ == 0); }
static void wiphy_unlock(struct wiphy *w) { assert(w == fm.wiphy && --wlocks == 0); }
static void mtx_lock(int *l) { (void)l; assert(locks++ == 0); }
static void mtx_unlock(int *l) { (void)l; assert(--locks == 0); }
static int ieee80211_com_vincref(struct ieee80211vap *v) { if (v->deleting) return ENXIO; v->refs++; return 0; }
static void ieee80211_com_vdecref(struct ieee80211vap *v) { assert(v->refs-- > 0); }
static void ieee80211_scan_done(struct ieee80211vap *v) { assert(v->refs); completions++; }
static struct linuxkpi_ieee80211_channel *ieee80211_get_channel(struct wiphy *w, int freq) {
 assert(w == fm.wiphy); return freq == 2412 ? &channel : NULL;
}
static void *allocate(size_t n) { allocations++; return calloc(1, n); }
static void deallocate(void *p) { assert(allocations-- > 0); free(p); }
#define malloc(n,t,f) allocate(n)
#define free(p,t) deallocate(p)
static int scan(struct wiphy *w, struct cfg80211_scan_request *r) {
 assert(w == fm.wiphy && fm.scan == r && fm.scan_active && wlocks == 1 && locks == 0);
 assert(strcmp(sdt_events[sdt_count - 1].name, "scan__start") == 0);
 assert(sdt_events[sdt_count - 1].args[1] == (uintptr_t)r);
 calls++;
 if (driver_error) return driver_error;
 /* Model a driver completing synchronously and freeing the accepted request. */
 ieee80211_com_vdecref(fm.scan_vap);
 fm.scan = NULL; fm.scan_vap = NULL; fm.scan_active = false;
 deallocate(r);
 return 0;
}
#include "power_functions.h"
int main(void) {
 struct wiphy wiphy = {.max_scan_ssids = 1}; struct net_device ndev = {0};
 struct cfg80211_ops ops = {.scan = scan}; struct ieee80211vap vap = {0};
 struct channel chan = {.ic_freq = 2412};
 struct ieee80211_scan_state ss = {.ss_vap = &vap, .ss_last = 1, .ss_nssid = 1,
     .ss_flags = IEEE80211_SCAN_ACTIVE, .ss_chans = {&chan}};
 struct ieee80211com ic = {.ic_softc = &fm, .ic_scan = &ss};
 fm.wiphy = &wiphy; fm.ndev = &ndev; fm.ops = &ops; fm.running = true;
 lkpi_fullmac_scan_start(&ic);
 assert(sdt_count == 1 && calls == 1 && allocations == 0 && vap.refs == 0);
 assert(sdt_events[0].args[2] == 1 && sdt_events[0].args[3] == 1);
 driver_error = -EIO; sdt_count = 0;
 lkpi_fullmac_scan_start(&ic);
 assert(sdt_count == 2 && calls == 2 && allocations == 0 && vap.refs == 0);
 assert(strcmp(sdt_events[1].name, "scan__error") == 0);
 assert((int)sdt_events[1].args[2] == -EIO && completions == 1);
 fm.stopping = true; sdt_count = 0;
 lkpi_fullmac_scan_start(&ic);
 assert(sdt_count == 2 && calls == 2 && (int)sdt_events[1].args[2] == -EBUSY);
 assert(allocations == 0 && vap.refs == 0 && completions == 2);
 vap.deleting = true; sdt_count = 0;
 lkpi_fullmac_scan_start(&ic);
 assert(sdt_count == 0 && allocations == 0 && locks == 0 && wlocks == 0);
 puts("PASS: SDT scan rejection/errors and synchronous completion without request reuse");
 return 0;
}

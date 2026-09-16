/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef int32_t s32;
#include "crypto_layout.h"
#define WLAN_CIPHER_SUITE_WEP40 0x000fac01
#define WLAN_CIPHER_SUITE_TKIP 0x000fac02
#define WLAN_CIPHER_SUITE_CCMP 0x000fac04
#define WLAN_CIPHER_SUITE_WEP104 0x000fac05
#define WLAN_CIPHER_SUITE_AES_CMAC 0x000fac06
#define WEP_ENABLED 1
#define TKIP_ENABLED 2
#define AES_ENABLED 4
#define bphy_err(d,...) ((void)(d))
#define brcmf_dbg(...) ((void)0)
struct brcmf_pub { int dummy; };
struct brcmf_if { struct brcmf_pub *drvr; };
struct brcmf_cfg80211_security { uint32_t cipher_pairwise,cipher_group; };
struct brcmf_cfg80211_profile { struct brcmf_cfg80211_security sec; };
struct net_device { struct brcmf_if ifp; struct brcmf_cfg80211_profile profile; };
struct cfg80211_connect_params { struct cfg80211_crypto_settings crypto; void *ie; unsigned ie_len; bool privacy; };
#define netdev_priv(n) (&(n)->ifp)
#define ndev_to_prof(n) (&(n)->profile)
static int error, value, calls;
static bool brcmf_find_wpsie(void *p,unsigned len) { (void)p;(void)len;return false; }
static int brcmf_fil_bsscfg_int_set(struct brcmf_if *ifp,const char *name,int v) {
 assert(ifp && !strcmp(name,"wsec"));value=v;calls++;return error;
}
#include "power_functions.h"
int main(void) {
 struct cfg80211_connect_params p={0};struct brcmf_pub driver={0};
 struct net_device n={.ifp={&driver}};
 _Static_assert(sizeof(p.crypto.ciphers_pairwise)==5*sizeof(uint32_t),"Linux cipher array");
 _Static_assert(sizeof(p.crypto.akm_suites)==10*sizeof(uint32_t),"Linux AKM array");
 assert(brcmf_set_wsec_mode(&n,&p)==0 && value==0 && calls==1);
 assert(n.profile.sec.cipher_pairwise==0 && n.profile.sec.cipher_group==0);
 p.crypto.n_ciphers_pairwise=1;p.crypto.ciphers_pairwise[0]=WLAN_CIPHER_SUITE_CCMP;
 p.crypto.cipher_group=WLAN_CIPHER_SUITE_CCMP;p.privacy=true;
 assert(brcmf_set_wsec_mode(&n,&p)==0 && value==AES_ENABLED && calls==2);
 assert(n.profile.sec.cipher_pairwise==WLAN_CIPHER_SUITE_CCMP);
 error=-EIO;p.crypto.ciphers_pairwise[0]=WLAN_CIPHER_SUITE_TKIP;
 assert(brcmf_set_wsec_mode(&n,&p)==-EIO && calls==3);
 assert(n.profile.sec.cipher_pairwise==WLAN_CIPHER_SUITE_CCMP);
 puts("PASS: real LinuxKPI crypto layout with imported brcmfmac open/WPA2 and firmware-error paths");
}

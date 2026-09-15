/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_80211_FULLMAC_H_
#define _LINUXKPI_80211_FULLMAC_H_
MALLOC_DECLARE(M_LKPI80211);
struct lkpi_cfg80211_bss {
	u_int refcnt;
	struct cfg80211_bss bss;
};
struct wiphy;
struct ieee80211vap;
void linuxkpi_fullmac_init_wiphy(struct wiphy *);
void linuxkpi_fullmac_free(struct wiphy *);
/* Caller releases the reference with ieee80211_com_vdecref(). */
struct ieee80211vap *linuxkpi_fullmac_get_vap(struct wiphy *);
#endif

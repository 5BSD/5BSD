/* SPDX-License-Identifier: BSD-2-Clause */
/* cfg80211 FullMAC station support over net80211. */
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/taskqueue.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>
#include <sys/epoch.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_input.h>
#include <net80211/ieee80211_scan.h>
#define LINUXKPI_NET80211
#include <net/mac80211.h>
#include <linux/etherdevice.h>
#include "linux_80211.h"
#include "linux_80211_fullmac.h"

SDT_PROVIDER_DEFINE(linuxkpi_fullmac);
SDT_PROBE_DEFINE3(linuxkpi_fullmac, fullmac, , tx__enqueue,
    "void *", "int", "int");
SDT_PROBE_DEFINE3(linuxkpi_fullmac, fullmac, , tx__dispatch,
    "void *", "int", "int");
SDT_PROBE_DEFINE4(linuxkpi_fullmac, fullmac, , scan__start,
    "void *", "void *", "unsigned int", "int");
SDT_PROBE_DEFINE3(linuxkpi_fullmac, fullmac, , scan__error,
    "void *", "void *", "int");
SDT_PROBE_DEFINE2(linuxkpi_fullmac, fullmac, , scan__abort,
    "void *", "void *");
SDT_PROBE_DEFINE2(linuxkpi_fullmac, fullmac, , scan__stale,
    "void *", "void *");
SDT_PROBE_DEFINE4(linuxkpi_fullmac, fullmac, , scan__done,
    "void *", "void *", "int", "bool");
SDT_PROBE_DEFINE2(linuxkpi_fullmac, fullmac, , connect__done,
    "void *", "int");
SDT_PROBE_DEFINE3(linuxkpi_fullmac, fullmac, , disconnected,
    "void *", "uint16_t", "bool");

static MALLOC_DEFINE(M_LKPIFM, "lkpifullmac", "LinuxKPI FullMAC");

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
	bool scan_active;
	bool tx_blocked;
	bool vap_deleting;
	bool vap_creating;
	bool attached;
	bool stopping;
	bool running;
};
struct lkpi_fullmac_vap {
	struct ieee80211vap vap;
	int (*newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

static struct ieee80211vap *
lkpi_fullmac_vap_get(struct lkpi_fullmac *fm)
{
	struct ieee80211vap *vap;

	if (fm == NULL)
		return (NULL);
	mtx_lock(&fm->lock);
	vap = fm->stopping ? NULL : fm->vap;
	if (vap != NULL && ieee80211_com_vincref(vap) != 0)
		vap = NULL;
	mtx_unlock(&fm->lock);
	return (vap);
}

static void
lkpi_fullmac_tx_task(void *arg, int pending __unused)
{
	struct lkpi_fullmac *fm = arg;
	struct ieee80211_node *ni;
	struct sk_buff *skb;
	struct mbuf *m;
	bool send;

	linux_set_current(curthread);
	for (;;) {
		wiphy_lock(fm->wiphy);
		mtx_lock(&fm->lock);
		if (!fm->stopping && !fm->tx_blocked &&
		    netif_queue_stopped(fm->ndev))
			m = NULL;
		else
			m = mbufq_dequeue(&fm->tx_frames);
		send = fm->running && !fm->stopping && !fm->tx_blocked;
		mtx_unlock(&fm->lock);
		if (m == NULL) {
			wiphy_unlock(fm->wiphy);
			break;
		}
		ni = (void *)m->m_pkthdr.rcvif;
		skb = send ? alloc_skb(m->m_pkthdr.len + fm->ndev->needed_headroom,
		    GFP_KERNEL) : NULL;
		SDT_PROBE3(linuxkpi_fullmac, fullmac, , tx__dispatch,
		    fm, m->m_pkthdr.len, (skb != NULL ? 0 :
		    (send ? ENOMEM : ENETDOWN)));
		if (skb != NULL) {
			skb_reserve(skb, fm->ndev->needed_headroom);
			m_copydata(m, 0, m->m_pkthdr.len,
			    skb_put(skb, m->m_pkthdr.len));
			skb->dev = fm->ndev;
			skb->priority = WME_AC_TO_TID(M_WME_GETAC(m));
			fm->ndev->netdev_ops->ndo_start_xmit(skb, fm->ndev);
		} else
			if_inc_counter(ni->ni_vap->iv_ifp, IFCOUNTER_OERRORS, 1);
		wiphy_unlock(fm->wiphy);
		ieee80211_free_node(ni);
		m_freem(m);
	}
}

static void
lkpi_fullmac_wake_queue(struct net_device *ndev)
{
	struct lkpi_fullmac *fm = ndev->bsd_private;

	if (fm == NULL)
		return;
	mtx_lock(&fm->lock);
	if (!fm->stopping)
		taskqueue_enqueue(fm->tx_queue, &fm->tx_task);
	mtx_unlock(&fm->lock);
}

static int
lkpi_fullmac_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	int error;

	/* net80211 retains ownership on error and releases the node itself. */
	mtx_lock(&fm->lock);
	error = fm->stopping || fm->tx_blocked ? ENETDOWN :
	    mbufq_enqueue(&fm->tx_frames, m);
	SDT_PROBE3(linuxkpi_fullmac, fullmac, , tx__enqueue,
	    fm, m->m_pkthdr.len, error);
	if (error == 0)
		taskqueue_enqueue(fm->tx_queue, &fm->tx_task);
	mtx_unlock(&fm->lock);
	return (error);
}

static int
lkpi_fullmac_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{

	(void)params;
	ieee80211_free_node(ni);
	m_freem(m);
	return (EOPNOTSUPP);
}

static int
lkpi_fullmac_send_mgmt(struct ieee80211_node *ni, int subtype, int arg)
{

	/* Firmware performs authentication, association and disconnect frames. */
	(void)ni;
	(void)subtype;
	(void)arg;
	return (0);
}

static void
lkpi_fullmac_rx(struct sk_buff *skb)
{
	struct lkpi_fullmac *fm = skb->dev->bsd_private;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	struct epoch_tracker et;
	struct ether_header *eh;
	struct mbuf *m;
	size_t length;
	bool accept;

	vap = lkpi_fullmac_vap_get(fm);
	if (vap == NULL)
		goto out;
	/* eth_type_trans() left the Ethernet header immediately before data. */
	/* SDIO supplies linear frames; do not copy beyond a fragmented head. */
	if (skb_is_nonlinear(skb) || skb_headroom(skb) < ETH_HLEN ||
	    skb_mac_header(skb) != skb->data - ETH_HLEN ||
	    skb->len > ETHER_MAX_LEN - ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN)
		goto put;
	eh = (void *)(skb->data - ETH_HLEN);
	IEEE80211_LOCK(vap->iv_ic);
	ni = ieee80211_ref_node(vap->iv_bss);
	accept = vap->iv_state == IEEE80211_S_RUN &&
	    ((ni->ni_flags & IEEE80211_NODE_AUTH) != 0 ||
	    eh->ether_type == htons(ETHERTYPE_PAE));
	IEEE80211_UNLOCK(vap->iv_ic);
	if (!accept) {
		ieee80211_free_node(ni);
		goto put;
	}
	length = skb->len + ETH_HLEN;
	m = m_get2(length, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m != NULL) {
		m->m_len = m->m_pkthdr.len = length;
		memcpy(mtod(m, void *), eh, length);
		NET_EPOCH_ENTER(et);
		ieee80211_deliver_data(vap, ni, m);
		NET_EPOCH_EXIT(et);
	} else
		if_inc_counter(vap->iv_ifp, IFCOUNTER_IERRORS, 1);
	ieee80211_free_node(ni);
put:
	ieee80211_com_vdecref(vap);
out:
	dev_kfree_skb_any(skb);
}

static void
lkpi_fullmac_channels(struct ieee80211com *ic, int maxchans, int *nchans,
    struct ieee80211_channel channels[])
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	struct ieee80211_supported_band *band;
	struct linuxkpi_ieee80211_channel *channel;
	uint32_t flags;

	*nchans = 0;
	for (unsigned int b = 0; b < NUM_NL80211_BANDS; b++) {
		if (b != NL80211_BAND_2GHZ && b != NL80211_BAND_5GHZ)
			continue;
		band = fm->wiphy->bands[b];
		if (band == NULL)
			continue;
		for (int i = 0; i < band->n_channels; i++) {
			channel = &band->channels[i];
			if (channel->flags & IEEE80211_CHAN_DISABLED)
				continue;
			flags = b == NL80211_BAND_2GHZ ? IEEE80211_CHAN_G : IEEE80211_CHAN_A;
			if (channel->flags & IEEE80211_CHAN_NO_IR)
				flags |= IEEE80211_CHAN_PASSIVE;
			if (channel->flags & IEEE80211_CHAN_RADAR)
				flags |= IEEE80211_CHAN_DFS;
			ieee80211_add_channel(channels, maxchans, nchans,
			    ieee80211_mhz2ieee(channel->center_freq, 0),
			    channel->center_freq, channel->max_power, flags, NULL);
		}
	}
}

static void
lkpi_fullmac_noop(struct ieee80211com *ic)
{
	(void)ic;
}

static void
lkpi_fullmac_scan_curchan(struct ieee80211_scan_state *ss, unsigned long dwell)
{
	/* The cfg80211 scan owns channel progression and calls scan_done(). */
	(void)ss;
	(void)dwell;
}

static void
lkpi_fullmac_scan_mindwell(struct ieee80211_scan_state *ss)
{
	(void)ss;
}

static void
lkpi_fullmac_scan_start(struct ieee80211com *ic)
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	struct cfg80211_scan_request *request;
	struct cfg80211_ssid *ssids;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct ieee80211vap *vap = ss->ss_vap;
	int error;

	if (ieee80211_com_vincref(vap) != 0)
		return;
	request = malloc(sizeof(*request) + ss->ss_last * sizeof(request->channels[0]) +
	    max(1, ss->ss_nssid) * sizeof(*ssids), M_LKPIFM, M_WAITOK | M_ZERO);
	request->wiphy = fm->wiphy;
	request->wdev = fm->ndev->ieee80211_ptr;
	memset(request->bssid, 0xff, sizeof(request->bssid));
	request->ssids = (void *)&request->channels[ss->ss_last];
	for (unsigned int i = 0; i < ss->ss_last; i++) {
		struct linuxkpi_ieee80211_channel *channel;
		channel = ieee80211_get_channel(fm->wiphy, ss->ss_chans[i]->ic_freq);
		if (channel != NULL)
			request->channels[request->n_channels++] = channel;
	}
	if ((ss->ss_flags & IEEE80211_SCAN_ACTIVE) != 0) {
		request->n_ssids = min(max(1, ss->ss_nssid), fm->wiphy->max_scan_ssids);
		for (int i = 0; i < min(request->n_ssids, ss->ss_nssid); i++) {
			request->ssids[i].ssid_len = ss->ss_ssid[i].len;
			memcpy(request->ssids[i].ssid, ss->ss_ssid[i].ssid, ss->ss_ssid[i].len);
		}
	}
	wiphy_lock(fm->wiphy);
	SDT_PROBE4(linuxkpi_fullmac, fullmac, , scan__start,
	    fm, request, request->n_channels, request->n_ssids);
	mtx_lock(&fm->lock);
	if (!fm->running || fm->stopping || fm->scan != NULL ||
	    request->n_channels == 0)
		error = -EBUSY;
	else {
		fm->scan = request;
		fm->scan_vap = vap;
		fm->scan_active = true;
		error = 0;
	}
	mtx_unlock(&fm->lock);
	if (error == 0) {
		error = fm->ops->scan(fm->wiphy, request);
		if (error != 0) {
			mtx_lock(&fm->lock);
			fm->scan = NULL;
			fm->scan_vap = NULL;
			fm->scan_active = false;
			mtx_unlock(&fm->lock);
		}
	}
	wiphy_unlock(fm->wiphy);
	if (error != 0) {
		SDT_PROBE3(linuxkpi_fullmac, fullmac, , scan__error,
		    fm, request, error);
		free(request, M_LKPIFM);
		ieee80211_scan_done(vap);
		ieee80211_com_vdecref(vap);
	}
}

/* Native timeout/cancel must retire its scan before asking firmware to stop. */
static void
lkpi_fullmac_scan_end(struct ieee80211com *ic)
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	bool abort;

	wiphy_lock(fm->wiphy);
	mtx_lock(&fm->lock);
	abort = fm->scan != NULL && fm->scan_active;
	if (abort)
		SDT_PROBE2(linuxkpi_fullmac, fullmac, , scan__abort, fm, fm->scan);
	fm->scan_active = false;
	mtx_unlock(&fm->lock);
	if (abort)
		fm->ops->abort_scan(fm->wiphy, fm->ndev->ieee80211_ptr);
	wiphy_unlock(fm->wiphy);
}

void
linuxkpi_fullmac_scan_done(struct cfg80211_scan_request *request,
    struct cfg80211_scan_info *info)
{
	struct lkpi_fullmac *fm = request->wiphy->bsd_fullmac;
	struct ieee80211vap *vap;

	(void)info;
	if (fm == NULL)
		return;
	/* cfg80211 drivers may report completion while holding the wiphy mutex. */
	mtx_lock(&fm->lock);
	if (fm->scan != request) {
		SDT_PROBE2(linuxkpi_fullmac, fullmac, , scan__stale, fm, request);
		mtx_unlock(&fm->lock);
		return;
	}
	vap = fm->scan_vap;
	SDT_PROBE4(linuxkpi_fullmac, fullmac, , scan__done, fm, request,
	    (info != NULL ? info->aborted : -1),
	    (fm->scan_active && !fm->stopping && vap == fm->vap));
	fm->scan = NULL;
	fm->scan_vap = NULL;
	/* Serialize notification with scan_end; never complete a later scan. */
	if (fm->scan_active && !fm->stopping && vap == fm->vap)
		ieee80211_scan_done(vap);
	fm->scan_active = false;
	mtx_unlock(&fm->lock);
	ieee80211_com_vdecref(vap);
	free(request, M_LKPIFM);
}

/* Parse the selected RSN IE supplied by the supplicant, with bounded reads. */
static int
lkpi_fullmac_rsn(const uint8_t *ie, size_t length,
    struct cfg80211_connect_params *params, uint32_t *pairwise, uint32_t *akm)
{
	const uint8_t *p, *end;
	unsigned int count;

	if (length < 2 || ie[0] != IEEE80211_ELEMID_RSN || ie[1] != length - 2)
		return (-EINVAL);
	p = ie + 2;
	end = ie + length;
	if (end - p < 8 || le16dec(p) != 1)
		return (-EINVAL);
	params->crypto.cipher_group = be32dec(p + 2);
	p += 6;
	count = le16dec(p);
	p += 2;
	/* A connection request selects exactly one pairwise cipher and AKM. */
	if (count != 1 || end - p < 6)
		return (-EOPNOTSUPP);
	*pairwise = be32dec(p);
	p += 4;
	count = le16dec(p);
	p += 2;
	if (count != 1 || end - p < 4)
		return (-EOPNOTSUPP);
	*akm = be32dec(p);
	p += 4;
	/* Optional capabilities, PMKID list and group-management cipher. */
	if (p != end) {
		if (end - p < 2)
			return (-EINVAL);
		/* The bridge cannot install BIP keys or handle protected management. */
		if (le16dec(p) & 0x00c0) /* MFPR | MFPC */
			return (-EOPNOTSUPP);
		p += 2;
	}
	if (p != end) {
		if (end - p < 2)
			return (-EINVAL);
		count = le16dec(p);
		p += 2;
		if ((size_t)(end - p) < count * 16U)
			return (-EINVAL);
		p += count * 16U;
	}
	if (p != end)
		return (end - p == 4 ? -EOPNOTSUPP : -EINVAL);
	/* Limit the initial bridge to WPA2-CCMP with userspace key negotiation. */
	if (*pairwise != WLAN_CIPHER_SUITE_CCMP ||
	    params->crypto.cipher_group != WLAN_CIPHER_SUITE_CCMP ||
	    (*akm != WLAN_AKM_SUITE_PSK && *akm != WLAN_AKM_SUITE_8021X))
		return (-EOPNOTSUPP);
	params->crypto.wpa_versions = NL80211_WPA_VERSION_2;
	params->crypto.ciphers_pairwise = pairwise;
	params->crypto.n_ciphers_pairwise = 1;
	params->crypto.akm_suites = akm;
	params->crypto.n_akm_suites = 1;
	return (0);
}

static int
lkpi_fullmac_connect(struct ieee80211vap *vap)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;
	struct cfg80211_connect_params params = { 0 };
	struct ieee80211_node *ni = vap->iv_bss;
	uint32_t pairwise, akm;
	uint8_t ssid[IEEE80211_NWID_LEN], bssid[IEEE80211_ADDR_LEN];
	uint8_t ie[257];
	int error = 0;

	IEEE80211_LOCK_ASSERT(vap->iv_ic);
	if (ni->ni_esslen > sizeof(ssid))
		return (EINVAL);
	memcpy(ssid, ni->ni_essid, ni->ni_esslen);
	memcpy(bssid, ni->ni_bssid, sizeof(bssid));
	params.ssid = ssid;
	params.ssid_len = ni->ni_esslen;
	params.bssid = bssid;
	params.channel = ieee80211_get_channel(fm->wiphy, ni->ni_chan->ic_freq);
	params.auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	params.privacy = (vap->iv_flags & IEEE80211_F_PRIVACY) != 0;
	if ((vap->iv_flags & IEEE80211_F_WPA2) != 0 && vap->iv_rsn_ie != NULL) {
		params.ie_len = vap->iv_rsn_ie[1] + 2;
		memcpy(ie, vap->iv_rsn_ie, params.ie_len);
		params.ie = ie;
		error = lkpi_fullmac_rsn(ie, params.ie_len, &params, &pairwise, &akm);
	} else if (params.privacy)
		error = -EOPNOTSUPP;
	if (error != 0)
		return (-error);
	IEEE80211_UNLOCK(vap->iv_ic);
	wiphy_lock(fm->wiphy);
	if (fm->running && !fm->stopping)
		error = fm->ops->connect(fm->wiphy, fm->ndev, &params);
	else
		error = -ENETDOWN;
	wiphy_unlock(fm->wiphy);
	IEEE80211_LOCK(vap->iv_ic);
	return (-error);
}

static int
lkpi_fullmac_newstate(struct ieee80211vap *vap, enum ieee80211_state state, int arg)
{
	struct lkpi_fullmac_vap *fv = (void *)vap;
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;
	enum ieee80211_state old = vap->iv_state;
	int error;

	/* The native state machine handles scan selection and user notifications. */
	if (state == IEEE80211_S_INIT || state == IEEE80211_S_SCAN) {
		if (old == IEEE80211_S_RUN || old == IEEE80211_S_AUTH || old == IEEE80211_S_ASSOC) {
			IEEE80211_UNLOCK(vap->iv_ic);
			wiphy_lock(fm->wiphy);
			if (fm->running && !fm->stopping)
				fm->ops->disconnect(fm->wiphy, fm->ndev, IEEE80211_REASON_ASSOC_LEAVE);
			wiphy_unlock(fm->wiphy);
			IEEE80211_LOCK(vap->iv_ic);
		}
	}
	error = fv->newstate(vap, state, arg);
	if (error == 0 && state == IEEE80211_S_AUTH) {
		error = lkpi_fullmac_connect(vap);
		if (error != 0)
			ieee80211_new_state(vap, IEEE80211_S_SCAN, IEEE80211_SCAN_FAIL_STATUS);
	}
	return (error);
}

void
linuxkpi_fullmac_connect_done(struct net_device *ndev,
    struct cfg80211_connect_resp_params *params)
{
	struct lkpi_fullmac *fm = ndev->bsd_private;
	struct ieee80211vap *vap = lkpi_fullmac_vap_get(fm);
	const uint8_t *bssid = params->links[0].bssid;

	SDT_PROBE2(linuxkpi_fullmac, fullmac, , connect__done, ndev, params->status);
	if (vap == NULL)
		return;
	if (bssid == NULL)
		bssid = params->bssid;
	IEEE80211_LOCK(vap->iv_ic);
	if (vap->iv_state == IEEE80211_S_AUTH &&
	    (bssid == NULL || IEEE80211_ADDR_EQ(bssid, vap->iv_bss->ni_bssid))) {
		if (params->status == 0) {
			/* Association was completed in firmware, as net80211 supports. */
			vap->iv_bss->ni_associd = 1;
			ieee80211_new_state(vap, IEEE80211_S_RUN, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
		} else
			ieee80211_new_state(vap, IEEE80211_S_SCAN, IEEE80211_SCAN_FAIL_STATUS);
	}
	IEEE80211_UNLOCK(vap->iv_ic);
	ieee80211_com_vdecref(vap);
}

void
linuxkpi_fullmac_disconnected(struct net_device *ndev, uint16_t reason,
    bool locally_generated)
{
	struct ieee80211vap *vap = lkpi_fullmac_vap_get(ndev->bsd_private);

	(void)reason;
	SDT_PROBE3(linuxkpi_fullmac, fullmac, , disconnected,
	    ndev, reason, locally_generated);
	if (vap == NULL)
		return;
	IEEE80211_LOCK(vap->iv_ic);
	if (!locally_generated && (vap->iv_state == IEEE80211_S_RUN ||
	    vap->iv_state == IEEE80211_S_AUTH))
		ieee80211_new_state(vap, IEEE80211_S_SCAN, IEEE80211_SCAN_FAIL_STATUS);
	IEEE80211_UNLOCK(vap->iv_ic);
	ieee80211_com_vdecref(vap);
}

void
linuxkpi_fullmac_roamed(struct net_device *ndev, struct cfg80211_roam_info *info)
{
	/* Rejoin through net80211 until firmware-roam state/key transfer is supported. */
	(void)info;
	linuxkpi_fullmac_disconnected(ndev, IEEE80211_REASON_ASSOC_LEAVE, false);
}

/* Key callbacks may arrive holding either of net80211's non-sleepable locks. */
struct lkpi_fullmac_key_lock {
	bool ic, nodes;
	struct ieee80211_node *ni;
};

static void
lkpi_fullmac_key_enter(struct ieee80211vap *vap, struct lkpi_fullmac_key_lock *state)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;

	state->ic = IEEE80211_IS_LOCKED(vap->iv_ic);
	state->nodes = IEEE80211_NODE_IS_LOCKED(&vap->iv_ic->ic_sta);
	state->ni = ieee80211_ref_node(vap->iv_bss);
	if (state->nodes)
		IEEE80211_NODE_UNLOCK(&vap->iv_ic->ic_sta);
	if (state->ic)
		IEEE80211_UNLOCK(vap->iv_ic);
	wiphy_lock(fm->wiphy);
}

static void
lkpi_fullmac_key_leave(struct ieee80211vap *vap, struct lkpi_fullmac_key_lock *state)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;

	wiphy_unlock(fm->wiphy);
	ieee80211_free_node(state->ni);
	if (state->ic)
		IEEE80211_LOCK(vap->iv_ic);
	if (state->nodes)
		IEEE80211_NODE_LOCK(&vap->iv_ic->ic_sta);
}

static int
lkpi_fullmac_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *key,
    ieee80211_keyix *tx, ieee80211_keyix *rx)
{

	if (key->wk_cipher->ic_cipher != IEEE80211_CIPHER_AES_CCM)
		return (0);
	*tx = 0;
	for (unsigned int i = 0; i < IEEE80211_WEP_NKID; i++) {
		if (key == &vap->iv_nw_keys[i]) {
			*tx = i;
			break;
		}
	}
	*rx = *tx;
	return (1);
}

static int
lkpi_fullmac_key_set(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;
	struct lkpi_fullmac_key_lock state;
	struct key_params params = { 0 };
	uint8_t bytes[16], seq[6], address[IEEE80211_ADDR_LEN];
	bool pairwise = (key->wk_flags & IEEE80211_KEY_GROUP) == 0;
	unsigned int index = key->wk_keyix;
	int error;

	if (key->wk_cipher->ic_cipher != IEEE80211_CIPHER_AES_CCM ||
	    key->wk_keylen != sizeof(bytes) || index > 3 || fm->ops->add_key == NULL)
		return (0);
	memcpy(bytes, key->wk_key, sizeof(bytes));
	memcpy(address, key->wk_macaddr, sizeof(address));
	for (unsigned int i = 0; i < sizeof(seq); i++)
		seq[i] = key->wk_keyrsc[0] >> (8 * i);
	params.key = bytes;
	params.key_len = sizeof(bytes);
	params.seq = seq;
	params.seq_len = sizeof(seq);
	params.cipher = WLAN_CIPHER_SUITE_CCMP;
	lkpi_fullmac_key_enter(vap, &state);
	error = !fm->running || fm->stopping ? -ENETDOWN :
	    fm->ops->add_key(fm->wiphy, fm->ndev, -1, index, pairwise,
	    pairwise ? address : NULL, &params);
	lkpi_fullmac_key_leave(vap, &state);
	explicit_bzero(bytes, sizeof(bytes));
	return (error == 0);
}

static int
lkpi_fullmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;
	struct lkpi_fullmac_key_lock state;
	uint8_t address[IEEE80211_ADDR_LEN];
	bool pairwise = (key->wk_flags & IEEE80211_KEY_GROUP) == 0;
	unsigned int index = key->wk_keyix;
	int error = 0;

	if (fm->ops->del_key == NULL)
		return (0);
	memcpy(address, key->wk_macaddr, sizeof(address));
	lkpi_fullmac_key_enter(vap, &state);
	if (fm->running && !fm->stopping)
		error = fm->ops->del_key(fm->wiphy, fm->ndev, -1, index,
		    pairwise, pairwise ? address : NULL);
	lkpi_fullmac_key_leave(vap, &state);
	return (error == 0);
}

static void
lkpi_fullmac_parent(struct ieee80211com *ic)
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	bool start = false, drain = false;
	int error;

	linux_set_current(curthread);
	wiphy_lock(fm->wiphy);
	if (ic->ic_nrunning != 0 && !fm->running && !fm->stopping &&
	    !fm->vap_deleting) {
		fm->ndev->flags |= IFF_UP | IFF_ALLMULTI;
		error = fm->ndev->netdev_ops->ndo_open(fm->ndev);
		if (error == 0) {
			fm->running = true;
			mtx_lock(&fm->lock);
			fm->tx_blocked = false;
			mtx_unlock(&fm->lock);
			start = true;
			if (fm->ndev->netdev_ops->ndo_set_rx_mode != NULL)
				fm->ndev->netdev_ops->ndo_set_rx_mode(fm->ndev);
		} else {
			fm->ndev->flags &= ~IFF_UP;
			ic_printf(ic, "could not start firmware interface: %d\n", -error);
		}
	} else if (ic->ic_nrunning == 0 && fm->running) {
		mtx_lock(&fm->lock);
		fm->tx_blocked = true;
		mtx_unlock(&fm->lock);
		drain = true;
		fm->running = false;
		fm->ndev->flags &= ~IFF_UP;
		fm->ndev->netdev_ops->ndo_stop(fm->ndev);
	}
	wiphy_unlock(fm->wiphy);
	if (drain) {
		taskqueue_enqueue(fm->tx_queue, &fm->tx_task);
		taskqueue_drain(fm->tx_queue, &fm->tx_task);
	}
	if (start)
		ieee80211_start_all(ic);
}

static struct ieee80211vap *
lkpi_fullmac_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN], const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct lkpi_fullmac *fm = ic->ic_softc;
	struct lkpi_fullmac_vap *fv;
	struct ieee80211vap *vap;

	/* Reserve the single firmware interface before any allocation can sleep. */
	mtx_lock(&fm->lock);
	if (opmode != IEEE80211_M_STA || fm->stopping || fm->vap_deleting ||
	    fm->vap_creating || fm->vap != NULL ||
	    !IEEE80211_ADDR_EQ(mac, fm->ndev->dev_addr)) {
		mtx_unlock(&fm->lock);
		return (NULL);
	}
	fm->vap_creating = true;
	mtx_unlock(&fm->lock);
	fv = malloc(sizeof(*fv), M_LKPIFM, M_WAITOK | M_ZERO);
	vap = &fv->vap;
	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
	    flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		free(fv, M_LKPIFM);
		mtx_lock(&fm->lock);
		fm->vap_creating = false;
		wakeup(&fm->vap_creating);
		mtx_unlock(&fm->lock);
		return (NULL);
	}
	fv->newstate = vap->iv_newstate;
	vap->iv_newstate = lkpi_fullmac_newstate;
	vap->iv_flags_ext |= IEEE80211_FEXT_SCAN_OFFLOAD;
	vap->iv_flags_ext &= ~IEEE80211_FEXT_SWBMISS;
	vap->iv_key_alloc = lkpi_fullmac_key_alloc;
	vap->iv_key_set = lkpi_fullmac_key_set;
	vap->iv_key_delete = lkpi_fullmac_key_delete;
	vap->iv_max_keyix = 4;
	ieee80211_vap_attach(vap, ieee80211_media_change, ieee80211_media_status, mac);
	mtx_lock(&fm->lock);
	fm->vap = vap;
	fm->vap_creating = false;
	wakeup(&fm->vap_creating);
	mtx_unlock(&fm->lock);
	return (vap);
}

static void
lkpi_fullmac_vap_delete(struct ieee80211vap *vap)
{
	struct lkpi_fullmac *fm = vap->iv_ic->ic_softc;
	bool abort;

	wiphy_lock(fm->wiphy);
	mtx_lock(&fm->lock);
	fm->vap = NULL;
	fm->vap_deleting = true;
	fm->tx_blocked = true;
	abort = fm->scan != NULL;
	fm->scan_active = false;
	mtx_unlock(&fm->lock);
	/* The driver owns the request until scan_done, even after cancellation. */
	if (abort)
		fm->ops->abort_scan(fm->wiphy, fm->ndev->ieee80211_ptr);
	if (fm->running) {
		fm->running = false;
		fm->ndev->flags &= ~IFF_UP;
		fm->ndev->netdev_ops->ndo_stop(fm->ndev);
	}
	wiphy_unlock(fm->wiphy);
	/* Existing RX/event callbacks must finish before net80211 is detached. */
	ieee80211_com_vdetach(vap);
	/* Queued node references do not keep their VAP alive. */
	taskqueue_enqueue(fm->tx_queue, &fm->tx_task);
	taskqueue_drain(fm->tx_queue, &fm->tx_task);
	ieee80211_vap_detach(vap);
	free(vap, M_LKPIFM);
	wiphy_lock(fm->wiphy);
	mtx_lock(&fm->lock);
	fm->vap_deleting = false;
	mtx_unlock(&fm->lock);
	wiphy_unlock(fm->wiphy);
}

static int
lkpi_fullmac_register(struct net_device *ndev)
{
	struct wiphy *wiphy = ndev->ieee80211_ptr->wiphy;
	struct lkpi_fullmac *fm;
	struct ieee80211com *ic;
	const struct cfg80211_ops *ops = WIPHY_TO_LWIPHY(wiphy)->ops;
	int error;

	if (ndev->ieee80211_ptr->iftype != NL80211_IFTYPE_STATION ||
	    ops->scan == NULL || ops->abort_scan == NULL ||
	    ops->connect == NULL || ops->disconnect == NULL ||
	    ndev->netdev_ops == NULL || ndev->netdev_ops->ndo_open == NULL ||
	    ndev->netdev_ops->ndo_stop == NULL || ndev->netdev_ops->ndo_start_xmit == NULL)
		return (-EOPNOTSUPP);
	if (wiphy->bsd_fullmac != NULL)
		return (-EBUSY);
	if (!is_valid_ether_addr(ndev->dev_addr))
		return (-EINVAL);
	fm = malloc(sizeof(*fm), M_LKPIFM, M_WAITOK | M_ZERO);
	fm->wiphy = wiphy;
	fm->ops = ops;
	fm->ndev = ndev;
	fm->tx_blocked = true;
	mtx_init(&fm->lock, "lkpi fullmac", NULL, MTX_DEF);
	mbufq_init(&fm->tx_frames, 256);
	TASK_INIT(&fm->tx_task, 0, lkpi_fullmac_tx_task, fm);
	fm->tx_queue = taskqueue_create("lkpi fullmac tx", M_WAITOK,
	    taskqueue_thread_enqueue, &fm->tx_queue);
	error = taskqueue_start_threads(&fm->tx_queue, 1, PWAIT, "lkpi fullmac tx");
	if (error != 0) {
		taskqueue_free(fm->tx_queue);
		mtx_destroy(&fm->lock);
		free(fm, M_LKPIFM);
		return (-error);
	}
	ic = &fm->ic;
	ic->ic_softc = fm;
	ic->ic_name = dev_name(wiphy_dev(wiphy));
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps = IEEE80211_C_STA | IEEE80211_C_8023ENCAP |
	    IEEE80211_C_SHPREAMBLE | IEEE80211_C_SHSLOT;
	for (int i = 0; i < wiphy->n_cipher_suites; i++) {
		if (wiphy->cipher_suites[i] == WLAN_CIPHER_SUITE_CCMP &&
		    ops->add_key != NULL && ops->del_key != NULL) {
			ic->ic_caps |= IEEE80211_C_WPA2;
			ieee80211_set_hardware_ciphers(ic, IEEE80211_CRYPTO_AES_CCM);
		}
	}
	memcpy(ic->ic_macaddr, ndev->dev_addr, sizeof(ic->ic_macaddr));
	lkpi_fullmac_channels(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans, ic->ic_channels);
	if (ic->ic_nchans == 0) {
		taskqueue_free(fm->tx_queue);
		mtx_destroy(&fm->lock);
		free(fm, M_LKPIFM);
		return (-EINVAL);
	}
	ndev->bsd_private = fm;
	wiphy->bsd_fullmac = fm;
	ieee80211_ifattach(ic);
	ic->ic_parent = lkpi_fullmac_parent;
	ic->ic_transmit = lkpi_fullmac_transmit;
	ic->ic_raw_xmit = lkpi_fullmac_raw_xmit;
	ic->ic_send_mgmt = lkpi_fullmac_send_mgmt;
	ic->ic_vap_create = lkpi_fullmac_vap_create;
	ic->ic_vap_delete = lkpi_fullmac_vap_delete;
	ic->ic_getradiocaps = lkpi_fullmac_channels;
	ic->ic_scan_start = lkpi_fullmac_scan_start;
	ic->ic_scan_end = lkpi_fullmac_scan_end;
	ic->ic_scan_curchan = lkpi_fullmac_scan_curchan;
	ic->ic_scan_mindwell = lkpi_fullmac_scan_mindwell;
	ic->ic_set_channel = lkpi_fullmac_noop;
	ic->ic_update_mcast = lkpi_fullmac_noop;
	ic->ic_update_promisc = lkpi_fullmac_noop;
	ic->ic_updateslot = lkpi_fullmac_noop;
	fm->attached = true;
	return (0);
}

static void
lkpi_fullmac_unregister(struct net_device *ndev)
{
	struct lkpi_fullmac *fm = ndev->bsd_private;
	bool locked;

	if (fm == NULL || !fm->attached)
		return;
	/* Never drain native tasks while holding the wiphy lock they need. */
	locked = sx_xlocked(&fm->wiphy->mtx.sx);
	if (locked)
		wiphy_unlock(fm->wiphy);
	mtx_lock(&fm->lock);
	fm->stopping = true;
	/* An accepted create must finish publishing before ifdetach walks VAPs. */
	while (fm->vap_creating)
		mtx_sleep(&fm->vap_creating, &fm->lock, 0, "fmvap", 0);
	mtx_unlock(&fm->lock);
	wiphy_lock(fm->wiphy);
	if (fm->running) {
		fm->running = false;
		ndev->flags &= ~IFF_UP;
		ndev->netdev_ops->ndo_stop(ndev);
	}
	wiphy_unlock(fm->wiphy);
	taskqueue_enqueue(fm->tx_queue, &fm->tx_task);
	taskqueue_drain(fm->tx_queue, &fm->tx_task);
	ieee80211_ifdetach(&fm->ic);
	fm->attached = false;
	fm->ndev = NULL;
	ndev->bsd_private = NULL;
	if (locked)
		wiphy_lock(fm->wiphy);
}

static const struct lkpi_netdev_ops lkpi_fullmac_netdev_ops = {
	.register_device = lkpi_fullmac_register,
	.unregister_device = lkpi_fullmac_unregister,
	.rx = lkpi_fullmac_rx,
	.wake_queue = lkpi_fullmac_wake_queue,
};

void
linuxkpi_fullmac_init_wiphy(struct wiphy *wiphy)
{

	wiphy->bsd_netdev_ops = &lkpi_fullmac_netdev_ops;
}

void
linuxkpi_fullmac_free(struct wiphy *wiphy)
{
	struct lkpi_fullmac *fm = wiphy->bsd_fullmac;

	if (fm == NULL)
		return;
	KASSERT(!fm->attached, ("freeing a registered FullMAC wiphy"));
	taskqueue_free(fm->tx_queue);
	KASSERT(fm->scan == NULL, ("freeing FullMAC with a pending scan"));
	mtx_destroy(&fm->lock);
	wiphy->bsd_fullmac = NULL;
	free(fm, M_LKPIFM);
}

struct ieee80211vap *
linuxkpi_fullmac_get_vap(struct wiphy *wiphy)
{
	struct lkpi_fullmac *fm = wiphy->bsd_fullmac;

	return (lkpi_fullmac_vap_get(fm));
}

struct cfg80211_bss *
linuxkpi_fullmac_inform_bss(struct wiphy *wiphy,
    struct linuxkpi_ieee80211_channel *channel, const uint8_t *bssid, uint64_t tsf,
    uint16_t cap, uint16_t interval, const uint8_t *ies, size_t ie_len,
    int signal, gfp_t gfp)
{
	struct lkpi_fullmac *fm = wiphy->bsd_fullmac;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	struct ieee80211_channel *native_channel;
	struct ieee80211_scanparams params;
	struct ieee80211_frame *wh;
	struct lkpi_cfg80211_bss *lbss = NULL;
	struct mbuf *m;
	uint8_t *body;
	size_t length;

	(void)gfp;
	if (channel == NULL || bssid == NULL || ies == NULL || ie_len > 2304)
		return (NULL);
	vap = lkpi_fullmac_vap_get(fm);
	if (vap == NULL)
		return (NULL);
	native_channel = ieee80211_find_channel(&fm->ic, channel->center_freq,
	    channel->band == NL80211_BAND_2GHZ ? IEEE80211_CHAN_G : IEEE80211_CHAN_A);
	if (native_channel == NULL)
		goto put;
	length = sizeof(*wh) + 12 + ie_len;
	m = m_get2(length, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		goto put;
	m->m_len = m->m_pkthdr.len = length;
	wh = mtod(m, void *);
	memset(wh, 0, sizeof(*wh));
	wh->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
	memset(wh->i_addr1, 0xff, IEEE80211_ADDR_LEN);
	memcpy(wh->i_addr2, bssid, IEEE80211_ADDR_LEN);
	memcpy(wh->i_addr3, bssid, IEEE80211_ADDR_LEN);
	body = (void *)(wh + 1);
	le64enc(body, tsf);
	le16enc(body + 8, interval);
	le16enc(body + 10, cap);
	memcpy(body + 12, ies, ie_len);
	IEEE80211_LOCK(vap->iv_ic);
	ni = ieee80211_ref_node(vap->iv_bss);
	IEEE80211_UNLOCK(vap->iv_ic);
	if (ieee80211_parse_beacon(ni, m, native_channel, &params) == 0) {
		ieee80211_add_scan(vap, native_channel, &params, wh,
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP, max(0, min(127, (signal / 100 + 96) * 2)), -96);
		lbss = malloc(sizeof(*lbss), M_LKPI80211, M_NOWAIT | M_ZERO);
		if (lbss != NULL) {
			lbss->bss.ies = malloc(sizeof(*lbss->bss.ies) + ie_len,
			    M_LKPI80211, M_NOWAIT | M_ZERO);
			if (lbss->bss.ies == NULL) {
				free(lbss, M_LKPI80211);
				lbss = NULL;
			} else {
				lbss->bss.ies->data = (void *)(lbss->bss.ies + 1);
				lbss->bss.ies->len = ie_len;
				memcpy(lbss->bss.ies->data, ies, ie_len);
				lbss->bss.signal = signal;
				refcount_init(&lbss->refcnt, 1);
			}
		}
	}
	ieee80211_free_node(ni);
	m_freem(m);
put:
	ieee80211_com_vdecref(vap);
	return (lbss != NULL ? &lbss->bss : NULL);
}

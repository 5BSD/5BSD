/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <machine/vmm_snapshot.h>
#include <net/ethernet.h>
#include <net/if.h> /* IFNAMSIZ */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "mevent.h"
#include "virtio.h"
#include "net_utils.h"
#include "net_backends.h"
#include "iov.h"

#define VTNET_RINGSZ	1024

#define VTNET_MAXSEGS	256

/*
 * VirtIO 1.4 section 5.1.9.3 permits a 65,589-byte incoming GSO packet.
 * A backend which supplies the base virtio-net header therefore returns a
 * record up to 65,601 bytes; account for that header at the receive site.
 */
#define VTNET_MAX_PKT_LEN	65589

#define VTNET_MIN_MTU	68
#define VTNET_MAX_MTU	65535
#define VTNET_HDR_GSO_NONE	0
#define VTNET_HDR_GSO_TCPV4	1
#define VTNET_HDR_GSO_UDP	3
#define VTNET_HDR_GSO_TCPV6	4
#define VTNET_HDR_GSO_ECN	0x80
#define VTNET_HDR_GSO_TUNNEL_IPV4	0x20
#define VTNET_HDR_GSO_TUNNEL_IPV6	0x40
#define VTNET_HDR_F_NEEDS_CSUM	0x01
#define VTNET_HDR_F_DATA_VALID	0x02
#define VTNET_HDR_F_UDP_TUNNEL_CSUM	0x08

#define VTNET_S_HOSTCAPS      \
  ( VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | \
    VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_RING_F_INDIRECT_DESC | \
    VIRTIO_RING_F_EVENT_IDX)

#define	VTNET_BACKEND_CAPS	(VIRTIO_NET_F_CSUM | \
    VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_GUEST_TSO4 | \
    VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_ECN | \
    VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_HOST_TSO4 | \
    VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_HOST_ECN | \
    VIRTIO_NET_F_HOST_UFO)

/*
 * PCI config-space "registers"
 */
struct virtio_net_config {
	uint8_t  mac[6];
	uint16_t status;
	uint16_t max_virtqueue_pairs;
	uint16_t mtu;
} __packed;

/*
 * Queue definitions.
 */
#define VTNET_RXQ	0
#define VTNET_TXQ	1
#define VTNET_CTLQ	2	/* NB: not yet supported */

#define VTNET_MAXQ	3

/*
 * Debug printf
 */
static int pci_vtnet_debug;
#define DPRINTF(params) if (pci_vtnet_debug) PRINTLN params
#define WPRINTF(params) PRINTLN params

/*
 * Per-device softc
 */
struct pci_vtnet_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_queues[VTNET_MAXQ - 1];
	pthread_mutex_t vsc_mtx;

	net_backend_t	*vsc_be;

	bool    features_negotiated;	/* protected by rx_mtx */
	bool    tx_features_negotiated;	/* protected by tx_mtx */

	int		resetting;	/* protected by tx_mtx */

	uint64_t	vsc_features;	/* negotiated features */

	pthread_mutex_t	rx_mtx;
	int		rx_merge;	/* merged rx bufs in use */

	pthread_t 	tx_tid;
	pthread_mutex_t	tx_mtx;
	pthread_cond_t	tx_cond;
	int		tx_in_progress;

	size_t		vhdrlen;
	size_t		be_vhdrlen;

	struct virtio_net_config vsc_config;
	struct virtio_consts vsc_consts;
};

/*
 * Modern virtio-net always includes num_buffers in the 12-byte header.
 * Omitting it without MRG_RXBUF is a legacy-interface exception.
 */
static size_t
pci_vtnet_header_len(const struct pci_vtnet_softc *sc, uint64_t features)
{

	if (sc->vsc_vs.vs_transport == VIRTIO_PCI_TRANSPORT_MODERN ||
	    (features & VIRTIO_NET_F_MRG_RXBUF) != 0)
		return (sizeof(struct virtio_net_rxhdr));
	return (sizeof(struct virtio_net_rxhdr) -
	    sizeof(((struct virtio_net_rxhdr *)0)->vrh_bufs));
}

static void pci_vtnet_reset(void *);
static int pci_vtnet_qreset(void *, struct vqueue_info *, uint64_t);
/* static void pci_vtnet_notify(void *, struct vqueue_info *); */
static int pci_vtnet_cfgread(void *, int, int, uint32_t *);
static int pci_vtnet_cfgwrite(void *, int, int, uint32_t);
static bool pci_vtnet_apply_features(struct pci_vtnet_softc *, uint64_t);
static void pci_vtnet_neg_features(void *, uint64_t);
#ifdef BHYVE_SNAPSHOT
static void pci_vtnet_pause(void *);
static void pci_vtnet_resume(void *);
static int pci_vtnet_snapshot(void *, struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtnet_vi_consts = {
	.vc_name =	"vtnet",
	.vc_nvq =	VTNET_MAXQ - 1,
	.vc_cfgsize =	sizeof(struct virtio_net_config),
	.vc_reset =	pci_vtnet_reset,
	.vc_cfgread =	pci_vtnet_cfgread,
	.vc_cfgwrite =	pci_vtnet_cfgwrite,
	.vc_apply_features = pci_vtnet_neg_features,
	.vc_qreset =	pci_vtnet_qreset,
	.vc_hv_caps =	VTNET_S_HOSTCAPS | VIRTIO_F_RING_RESET,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vtnet_pause,
	.vc_resume =	pci_vtnet_resume,
	.vc_snapshot =	pci_vtnet_snapshot,
#endif
};

static void
pci_vtnet_reset(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device reset requested !"));

	/* Acquire the RX lock to block RX processing. */
	pthread_mutex_lock(&sc->rx_mtx);

	/*
	 * Make sure receive operation is disabled at least until we
	 * re-negotiate the features, since receive operation depends
	 * on the value of sc->rx_merge and the header length, which
	 * are both set in pci_vtnet_neg_features().
	 * Receive operation will be enabled again once the guest adds
	 * the first receive buffers and kicks us.
	 */
	sc->features_negotiated = false;
	if (sc->vsc_be != NULL)
		netbe_rx_disable(sc->vsc_be);

	/* Set sc->resetting and give a chance to the TX thread to stop. */
	pthread_mutex_lock(&sc->tx_mtx);
	sc->tx_features_negotiated = false;
	sc->resetting = 1;
	while (sc->tx_in_progress) {
		pthread_mutex_unlock(&sc->tx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->tx_mtx);
	}

	/*
	 * Now reset rings, MSI-X vectors, and negotiated capabilities.
	 * Do that with the TX lock held, since we need to reset
	 * sc->resetting.
	 */
	vi_reset_dev(&sc->vsc_vs);
	sc->vsc_features = 0;
	sc->rx_merge = 0;
	sc->vhdrlen = pci_vtnet_header_len(sc, 0);

	sc->resetting = 0;
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
}

static int
pci_vtnet_qreset(void *vsc, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtnet_softc *sc;

	sc = vsc;
	switch (vq->vq_num) {
	case VTNET_RXQ:
		/*
		 * Serialize with the backend callback and stop new packets.
		 * The queue remains disabled until the re-enabled queue is
		 * kicked, preserving packets in the backend across the reset.
		 */
		pthread_mutex_lock(&sc->rx_mtx);
		if (sc->vsc_be != NULL)
			netbe_rx_disable(sc->vsc_be);
		pthread_mutex_unlock(&sc->rx_mtx);
		return (0);
	case VTNET_TXQ:
		/*
		 * Stop the worker after its current synchronous send.  The
		 * atomic queue-reset flag suppresses an interrupt from that
		 * final pass, and clearing VQ_ALLOC prevents another pass.
		 */
		pthread_mutex_lock(&sc->tx_mtx);
		sc->resetting = 1;
		while (sc->tx_in_progress) {
			pthread_mutex_unlock(&sc->tx_mtx);
			usleep(10000);
			pthread_mutex_lock(&sc->tx_mtx);
		}
		sc->resetting = 0;
		pthread_mutex_unlock(&sc->tx_mtx);
		return (0);
	default:
		return (EINVAL);
	}
}

static __inline struct iovec *
iov_trim_hdr(struct iovec *iov, int *iovcnt, unsigned int hlen)
{
	while (hlen != 0 && *iovcnt != 0) {
		if (iov[0].iov_len <= hlen) {
			hlen -= iov[0].iov_len;
			iov++;
			(*iovcnt)--;
			continue;
		}
		iov[0].iov_base =
		    (void *)((uintptr_t)iov[0].iov_base + hlen);
		iov[0].iov_len -= hlen;
		hlen = 0;
	}
	if (hlen != 0 || *iovcnt == 0)
		return (NULL);
	return (iov);
}

static bool
pci_vtnet_iov_read(const struct iovec *iov, int niov, size_t offset,
    void *buf, size_t len)
{
	uint8_t *dst;
	size_t copy;
	int i;

	dst = buf;
	for (i = 0; i < niov && len != 0; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		copy = MIN(len, iov[i].iov_len - offset);
		memcpy(dst, (const uint8_t *)iov[i].iov_base + offset, copy);
		dst += copy;
		len -= copy;
		offset = 0;
	}
	return (len == 0);
}

static bool
pci_vtnet_iov_write(const struct iovec *iov, int niov, size_t offset,
    const void *buf, size_t len)
{
	const uint8_t *src;
	size_t copy;
	int i;

	src = buf;
	for (i = 0; i < niov && len != 0; i++) {
		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		copy = MIN(len, iov[i].iov_len - offset);
		memcpy((uint8_t *)iov[i].iov_base + offset, src, copy);
		src += copy;
		len -= copy;
		offset = 0;
	}
	return (len == 0);
}

static bool
pci_vtnet_backend_features_valid(uint64_t features)
{
	uint64_t guest_gso, host_gso;

	if ((features & ~VTNET_BACKEND_CAPS) != 0)
		return (false);
	guest_gso = VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |
	    VIRTIO_NET_F_GUEST_UFO;
	host_gso = VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6 |
	    VIRTIO_NET_F_HOST_UFO;
	if ((features & guest_gso) != 0 &&
	    (features & VIRTIO_NET_F_GUEST_CSUM) == 0)
		return (false);
	if ((features & host_gso) != 0 &&
	    (features & VIRTIO_NET_F_CSUM) == 0)
		return (false);
	if ((features & VIRTIO_NET_F_GUEST_ECN) != 0 &&
	    (features & (VIRTIO_NET_F_GUEST_TSO4 |
	    VIRTIO_NET_F_GUEST_TSO6)) == 0)
		return (false);
	if ((features & VIRTIO_NET_F_HOST_ECN) != 0 &&
	    (features & (VIRTIO_NET_F_HOST_TSO4 |
	    VIRTIO_NET_F_HOST_TSO6)) == 0)
		return (false);
	return (true);
}

static bool
pci_vtnet_tx_header_valid(const struct pci_vtnet_softc *sc,
    const struct virtio_net_rxhdr *hdr, size_t packet_len)
{
	uint64_t required_feature;
	uint16_t csum_offset, csum_start;
	uint8_t base_gso, tunnels;

	tunnels = hdr->vrh_gso_type &
	    (VTNET_HDR_GSO_TUNNEL_IPV4 | VTNET_HDR_GSO_TUNNEL_IPV6);
	base_gso = hdr->vrh_gso_type &
	    ~(VTNET_HDR_GSO_ECN | VTNET_HDR_GSO_TUNNEL_IPV4 |
	    VTNET_HDR_GSO_TUNNEL_IPV6);

	/*
	 * DATA_VALID is device-to-driver metadata, and num_buffers is unused
	 * for transmitted packets.  The latter field is absent only from the
	 * ten-byte legacy non-mergeable header.
	 */
	if ((hdr->vrh_flags & VTNET_HDR_F_DATA_VALID) != 0)
		return (false);
	if (sc->vhdrlen == sizeof(*hdr) && le16toh(hdr->vrh_bufs) != 0)
		return (false);

	/*
	 * VirtIO 1.4 5.1.9.2.2 requires the device to reject ambiguous or
	 * internally inconsistent tunnel metadata.  bhyve does not advertise
	 * tunnel GSO, but validating these combinations keeps malformed input
	 * away from backends which consume the common virtio-net header.
	 */
	if (tunnels ==
	    (VTNET_HDR_GSO_TUNNEL_IPV4 | VTNET_HDR_GSO_TUNNEL_IPV6))
		return (false);
	if (tunnels != 0 &&
	    (((hdr->vrh_flags & VTNET_HDR_F_NEEDS_CSUM) == 0) ||
	    (hdr->vrh_flags & VTNET_HDR_F_DATA_VALID) != 0 ||
	    base_gso == VTNET_HDR_GSO_NONE))
		return (false);
	if ((hdr->vrh_flags & VTNET_HDR_F_UDP_TUNNEL_CSUM) != 0 &&
	    tunnels == 0)
		return (false);
	if (tunnels != 0)
		return (false);

	/*
	 * Never pass an offload request to a backend unless the driver
	 * negotiated the feature that makes that metadata meaningful.
	 */
	switch (base_gso) {
	case VTNET_HDR_GSO_NONE:
		required_feature = 0;
		break;
	case VTNET_HDR_GSO_TCPV4:
		required_feature = VIRTIO_NET_F_HOST_TSO4;
		break;
	case VTNET_HDR_GSO_UDP:
		required_feature = VIRTIO_NET_F_HOST_UFO;
		break;
	case VTNET_HDR_GSO_TCPV6:
		required_feature = VIRTIO_NET_F_HOST_TSO6;
		break;
	default:
		return (false);
	}
	if (required_feature != 0 &&
	    (sc->vsc_features & required_feature) == 0)
		return (false);
	if (base_gso != VTNET_HDR_GSO_NONE) {
		if ((hdr->vrh_flags & VTNET_HDR_F_NEEDS_CSUM) == 0 ||
		    le16toh(hdr->vrh_gso_size) == 0)
			return (false);
	}
	if ((hdr->vrh_gso_type & VTNET_HDR_GSO_ECN) != 0 &&
	    ((sc->vsc_features & VIRTIO_NET_F_HOST_ECN) == 0 ||
	    (base_gso != VTNET_HDR_GSO_TCPV4 &&
	    base_gso != VTNET_HDR_GSO_TCPV6)))
		return (false);

	if ((hdr->vrh_flags & VTNET_HDR_F_NEEDS_CSUM) == 0)
		return (true);
	if ((sc->vsc_features & VIRTIO_NET_F_CSUM) == 0)
		return (false);
	csum_start = le16toh(hdr->vrh_csum_start);
	csum_offset = le16toh(hdr->vrh_csum_offset);
	if (csum_start > packet_len ||
	    csum_offset > packet_len - csum_start ||
	    packet_len - csum_start - csum_offset < sizeof(uint16_t))
		return (false);
	return (true);
}

static bool
pci_vtnet_rx_header_valid(const struct pci_vtnet_softc *sc,
    const struct virtio_net_rxhdr *hdr, size_t packet_len)
{
	uint64_t required_feature;
	uint16_t csum_offset, csum_start;
	uint8_t base_gso, tunnels;

	/*
	 * The backend may generate a virtio-net header, but the device remains
	 * responsible for exposing only metadata covered by guest-negotiated
	 * features.
	 */
	if ((hdr->vrh_flags &
	    ~(VTNET_HDR_F_NEEDS_CSUM | VTNET_HDR_F_DATA_VALID)) != 0)
		return (false);
	if (hdr->vrh_flags != 0 &&
	    (sc->vsc_features & VIRTIO_NET_F_GUEST_CSUM) == 0)
		return (false);

	tunnels = hdr->vrh_gso_type &
	    (VTNET_HDR_GSO_TUNNEL_IPV4 | VTNET_HDR_GSO_TUNNEL_IPV6);
	if (tunnels != 0)
		return (false);
	base_gso = hdr->vrh_gso_type & ~VTNET_HDR_GSO_ECN;
	switch (base_gso) {
	case VTNET_HDR_GSO_NONE:
		required_feature = 0;
		break;
	case VTNET_HDR_GSO_TCPV4:
		required_feature = VIRTIO_NET_F_GUEST_TSO4;
		break;
	case VTNET_HDR_GSO_UDP:
		required_feature = VIRTIO_NET_F_GUEST_UFO;
		break;
	case VTNET_HDR_GSO_TCPV6:
		required_feature = VIRTIO_NET_F_GUEST_TSO6;
		break;
	default:
		return (false);
	}
	if (required_feature != 0 &&
	    ((sc->vsc_features & required_feature) == 0 ||
	    (hdr->vrh_flags & VTNET_HDR_F_NEEDS_CSUM) == 0 ||
	    le16toh(hdr->vrh_gso_size) == 0 ||
	    le16toh(hdr->vrh_hdr_len) > packet_len))
		return (false);
	if ((hdr->vrh_gso_type & VTNET_HDR_GSO_ECN) != 0 &&
	    ((sc->vsc_features & VIRTIO_NET_F_GUEST_ECN) == 0 ||
	    (base_gso != VTNET_HDR_GSO_TCPV4 &&
	    base_gso != VTNET_HDR_GSO_TCPV6)))
		return (false);

	if ((hdr->vrh_flags & VTNET_HDR_F_NEEDS_CSUM) == 0)
		return (true);
	csum_start = le16toh(hdr->vrh_csum_start);
	csum_offset = le16toh(hdr->vrh_csum_offset);
	if (csum_start > packet_len ||
	    csum_offset > packet_len - csum_start ||
	    packet_len - csum_start - csum_offset < sizeof(uint16_t))
		return (false);
	return (true);
}

static bool
pci_vtnet_frame_within_mtu(const struct pci_vtnet_softc *sc,
    const struct iovec *iov, int niov, size_t backend_header_len,
    size_t data_len, uint8_t gso_type)
{
	uint8_t type_bytes[2];
	size_t frame_len, header_len, total;
	uint16_t ether_type;

	if ((sc->vsc_features & VIRTIO_NET_F_MTU) == 0)
		return (true);

	/*
	 * Segmented packets may exceed MTU before the backend performs
	 * segmentation.  NONE and ECN without a segmentation type describe
	 * ordinary frames and are subject to the configured limit.
	 */
	switch (gso_type & ~VTNET_HDR_GSO_ECN) {
	case VTNET_HDR_GSO_TCPV4:
	case VTNET_HDR_GSO_UDP:
	case VTNET_HDR_GSO_TCPV6:
		return (true);
	default:
		break;
	}

	total = count_iov(iov, niov);
	if (data_len > total)
		return (false);
	total = data_len;
	if (total < backend_header_len)
		return (false);
	frame_len = total - backend_header_len;
	header_len = MIN(frame_len, (size_t)ETHER_HDR_LEN);
	if (frame_len < ETHER_HDR_LEN ||
	    !pci_vtnet_iov_read(iov, niov,
	    backend_header_len + ETHER_ADDR_LEN * 2, type_bytes,
	    sizeof(type_bytes)))
		return (frame_len <= (size_t)sc->vsc_config.mtu + header_len);

	ether_type = (uint16_t)type_bytes[0] << 8 | type_bytes[1];
	while ((ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ) &&
	    header_len <= frame_len - ETHER_VLAN_ENCAP_LEN) {
		header_len += ETHER_VLAN_ENCAP_LEN;
		if (!pci_vtnet_iov_read(iov, niov,
		    backend_header_len + header_len - ETHER_TYPE_LEN,
		    type_bytes, sizeof(type_bytes)))
			break;
		ether_type = (uint16_t)type_bytes[0] << 8 | type_bytes[1];
	}
	return (frame_len <= (size_t)sc->vsc_config.mtu + header_len);
}

struct virtio_mrg_rxbuf_info {
	uint16_t idx;
	size_t len;
};

static void
pci_vtnet_rx(struct pci_vtnet_softc *sc)
{
	struct virtio_mrg_rxbuf_info info[VTNET_MAXSEGS];
	struct iovec header_iov[VTNET_MAXSEGS + 1];
	struct iovec iov[VTNET_MAXSEGS + 1];
	struct vqueue_info *vq;
	struct vi_req req;
	size_t prepend_hdr_len;

	vq = &sc->vsc_queues[VTNET_RXQ];
	if (sc->vsc_be == NULL)
		return;

	/* Features must be negotiated */
	if (!sc->features_negotiated || !vq_ring_ready(vq)) {
		/*
		 * netbe_rx_disable() prevents future readiness events, but an
		 * event already queued in mevent may run after an RX queue
		 * reset has detached and cleared the guest ring mappings.
		 */
		return;
	}

	/*
	 * Feature application verifies this relationship, but keep the packet
	 * path safe if backend state changes unexpectedly or a future restore
	 * path fails to revalidate derived framing state.
	 */
	if (sc->be_vhdrlen != 0 && sc->be_vhdrlen != sc->vhdrlen) {
		WPRINTF(("vtnet: backend and guest header lengths differ"));
		netbe_rx_disable(sc->vsc_be);
		vi_set_needs_reset(&sc->vsc_vs);
		return;
	}
	prepend_hdr_len = sc->vhdrlen - sc->be_vhdrlen;

	for (;;) {
		struct virtio_net_rxhdr hdr;
		size_t plen;
		size_t riov_bytes;
		struct iovec *riov;
		uint32_t ulen;
		int header_iov_len;
		int riov_len;
		int n_chains;
		ssize_t backend_len;
		ssize_t rlen;

		backend_len = netbe_peek_recvlen(sc->vsc_be);
		if (backend_len <= 0) {
			/*
			 * No more packets (backend_len == 0), or backend
			 * errored (backend_len < 0). Interrupt if needed and
			 * stop.
			 */
			vq_endchains(vq, /*used_all_avail=*/0);
			return;
		}
		if ((size_t)backend_len >
		    VTNET_MAX_PKT_LEN + sc->be_vhdrlen) {
			/*
			 * Do not leave an impossible record permanently at
			 * the head of the backend queue.  All supported
			 * backends discard an entire packet when the receive
			 * iovec is shorter than that packet.
			 */
			WPRINTF(("vtnet: dropping oversized backend packet "
			    "(%zd bytes)", backend_len));
			(void)netbe_rx_discard(sc->vsc_be);
			continue;
		}
		plen = (size_t)backend_len + prepend_hdr_len;

		/*
		 * Get a descriptor chain to store the next ingress
		 * packet. In case of mergeable rx buffers, get as
		 * many chains as necessary in order to make room
		 * for plen bytes.
		 */
		riov_bytes = 0;
		riov_len = 0;
		riov = iov;
		n_chains = 0;
		do {
			int n = vq_getchain(vq, riov, VTNET_MAXSEGS - riov_len,
			    &req);

			if (n == 0) {
				/*
				 * No rx buffers. Enable RX kicks and double
				 * check.
				 */
				vq_kick_enable(vq);
				if (!vq_has_descs(vq)) {
					/*
					 * Still no buffers. Return the unused
					 * chains (if any), interrupt if needed
					 * (including for NOTIFY_ON_EMPTY), and
					 * disable the backend until the next
					 * kick.
					 */
					vq_retchains(vq, n_chains);
					vq_endchains(vq, /*used_all_avail=*/1);
					netbe_rx_disable(sc->vsc_be);
					return;
				}

				/* More rx buffers found, so keep going. */
				vq_kick_disable(vq);
				continue;
			}
			if (n < 0) {
				for (int i = 0; i < n_chains; i++)
					vq_relchain(vq, info[i].idx, 0);
				vq_endchains(vq, 0);
				return;
			}
			if (n > VTNET_MAXSEGS - riov_len ||
			    req.readable != 0 || req.writable != n) {
				DPRINTF(("vtnet: invalid receive descriptor chain"));
				vq_relchain(vq, req.idx, 0);
				continue;
			}
			info[n_chains].idx = req.idx;
			info[n_chains].len = count_iov(riov, n);
			riov_bytes += info[n_chains].len;
			riov_len += n;
			if (!sc->rx_merge) {
				n_chains = 1;
				break;
			}
			riov += n;
			n_chains++;
		} while (riov_bytes < plen &&
		    riov_len < VTNET_MAXSEGS);
		if (riov_bytes < plen ||
		    (sc->rx_merge && info[0].len < sc->vhdrlen)) {
			DPRINTF(("vtnet: receive buffers too small"));
			for (int i = 0; i < n_chains; i++)
				vq_relchain(vq, info[i].idx, 0);
			continue;
		}

		riov = iov;
		header_iov_len = riov_len;
		memcpy(header_iov, iov,
		    header_iov_len * sizeof(header_iov[0]));
		if (prepend_hdr_len > 0) {
			memset(&hdr, 0, sizeof(hdr));
			/*
			 * The frontend uses a virtio-net header, but the
			 * backend does not. We need to prepend a zeroed
			 * header.
			 */
			riov = iov_trim_hdr(riov, &riov_len, prepend_hdr_len);
			if (riov == NULL) {
				/*
				 * The first collected chain is nonsensical,
				 * as it is not even enough to store the
				 * virtio-net header. Just drop it.
				 */
				vq_relchain(vq, info[0].idx, 0);
				vq_retchains(vq, n_chains - 1);
				continue;
			}
			if (!pci_vtnet_iov_write(header_iov, header_iov_len,
			    0, &hdr, prepend_hdr_len)) {
				vq_relchain(vq, info[0].idx, 0);
				vq_retchains(vq, n_chains - 1);
				continue;
			}
		}

		rlen = netbe_recv(sc->vsc_be, riov, riov_len);
		if (rlen != backend_len) {
			/*
			 * If this happens it means there is something
			 * wrong with the backend (e.g., some other
			 * process is stealing our packets).
			 */
			WPRINTF(("netbe_recv: expected %zd bytes, "
				"got %zd", backend_len, rlen));
			vq_retchains(vq, n_chains);
			continue;
		}
		memset(&hdr, 0, sizeof(hdr));
		if (!pci_vtnet_iov_read(header_iov, header_iov_len, 0, &hdr,
		    sc->vhdrlen)) {
			for (int i = 0; i < n_chains; i++)
				vq_relchain(vq, info[i].idx, 0);
			continue;
		}
		if ((size_t)rlen < sc->be_vhdrlen ||
		    !pci_vtnet_rx_header_valid(sc, &hdr,
		    (size_t)rlen - sc->be_vhdrlen)) {
			DPRINTF(("vtnet: invalid receive offload metadata"));
			for (int i = 0; i < n_chains; i++)
				vq_relchain(vq, info[i].idx, 0);
			continue;
		}
		if (!pci_vtnet_frame_within_mtu(sc, riov, riov_len,
		    sc->be_vhdrlen, (size_t)rlen, hdr.vrh_gso_type)) {
			DPRINTF(("vtnet: dropping receive frame larger than MTU"));
			for (int i = 0; i < n_chains; i++)
				vq_relchain(vq, info[i].idx, 0);
			continue;
		}

		ulen = (uint32_t)plen;

		/*
		 * Publish the used buffers to the guest, reporting the
		 * number of bytes that we wrote.
		 */
		if (!sc->rx_merge) {
			uint16_t num_buffers;

			/*
			 * num_buffers is present on every modern packet even
			 * when mergeable receive buffers were not negotiated.
			 */
			if (sc->vhdrlen == sizeof(hdr)) {
				num_buffers = htole16(1);
				if (!pci_vtnet_iov_write(header_iov,
				    header_iov_len,
				    offsetof(struct virtio_net_rxhdr, vrh_bufs),
				    &num_buffers, sizeof(num_buffers))) {
					vq_relchain(vq, info[0].idx, 0);
					continue;
				}
			}
			vq_relchain(vq, info[0].idx, ulen);
		} else {
			uint32_t iolen;
			uint16_t num_buffers;
			int i = 0;

			do {
				iolen = MIN(info[i].len, (size_t)UINT32_MAX);
				if (iolen > ulen) {
					iolen = ulen;
				}
				vq_relchain_prepare(vq, info[i].idx, iolen);
				ulen -= iolen;
				i++;
			} while (ulen > 0 && i < n_chains);

			num_buffers = htole16(i);
			if (!pci_vtnet_iov_write(header_iov, header_iov_len,
			    offsetof(struct virtio_net_rxhdr, vrh_bufs),
			    &num_buffers, sizeof(num_buffers))) {
				WPRINTF(("vtnet: receive header accounting error"));
				return;
			}
			vq_relchain_publish(vq);
			if (ulen != 0)
				WPRINTF(("vtnet: receive chain accounting error"));
		}
	}

}

/*
 * Called when there is read activity on the backend file descriptor.
 * Each buffer posted by the guest is assumed to be able to contain
 * an entire ethernet frame + rx header.
 */
static void
pci_vtnet_rx_callback(int fd __unused, enum ev_type type __unused, void *param)
{
	struct pci_vtnet_softc *sc = param;

	/*
	 * Device status and interrupts are protected by vsc_mtx.  Keep the
	 * established device -> RX lock order so fatal backend framing errors
	 * can set NEEDS_RESET without racing a device or queue reset.
	 */
	VS_LOCK(&sc->vsc_vs);
	pthread_mutex_lock(&sc->rx_mtx);
	pci_vtnet_rx(sc);
	pthread_mutex_unlock(&sc->rx_mtx);
	VS_UNLOCK(&sc->vsc_vs);

}

/* Called on RX kick. */
static void
pci_vtnet_ping_rxq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * A qnotify means that the rx process can now begin.
	 * Enable RX only if features are negotiated.
	 */
	pthread_mutex_lock(&sc->rx_mtx);
	if (!sc->features_negotiated) {
		pthread_mutex_unlock(&sc->rx_mtx);
		return;
	}

	if (sc->vsc_be != NULL) {
		vq_kick_disable(vq);
		netbe_rx_enable(sc->vsc_be);
	}
	pthread_mutex_unlock(&sc->rx_mtx);
}

/* TX virtqueue processing, called by the TX thread. */
static void
pci_vtnet_proctx(struct pci_vtnet_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTNET_MAXSEGS + 1];
	struct iovec send_iov[VTNET_MAXSEGS + 1];
	struct iovec *siov = iov;
	struct vi_req req;
	struct virtio_net_rxhdr hdr;
	uint8_t gso_type;
	size_t total_len;
	int i, n;

	/*
	 * Obtain chain of descriptors. The first descriptor also
	 * contains the virtio-net header.
	 */
	n = vq_getchain(vq, iov, VTNET_MAXSEGS, &req);
	if (n <= 0)
		return;
	if (n > VTNET_MAXSEGS || req.writable != 0 || req.readable != n) {
		DPRINTF(("vtnet: invalid transmit descriptor chain"));
		vq_relchain(vq, req.idx, 0);
		return;
	}
	total_len = count_iov(iov, n);
	if (total_len < sc->vhdrlen) {
		DPRINTF(("vtnet: short transmit header"));
		vq_relchain(vq, req.idx, 0);
		return;
	}
	memset(&hdr, 0, sizeof(hdr));
	if (!pci_vtnet_iov_read(iov, n, 0, &hdr, sc->vhdrlen) ||
	    !pci_vtnet_tx_header_valid(sc, &hdr,
	    total_len - sc->vhdrlen)) {
		DPRINTF(("vtnet: invalid transmit offload metadata"));
		vq_relchain(vq, req.idx, 0);
		return;
	}
	gso_type = hdr.vrh_gso_type;
	/*
	 * Always separate the guest header from the packet.  If the backend
	 * consumes a vnet header, rebuild it from the validated fields so
	 * unknown flag bits are ignored as required by 5.1.9.2.2 and can never
	 * acquire backend-specific meaning.  Do not rewrite the guest's
	 * device-readable descriptors.
	 */
	siov = iov_trim_hdr(siov, &n, sc->vhdrlen);
	if (siov != NULL && sc->be_vhdrlen != 0) {
		hdr.vrh_flags &= VTNET_HDR_F_NEEDS_CSUM;
		send_iov[0] = (struct iovec){
		    .iov_base = &hdr,
		    .iov_len = sc->be_vhdrlen
		};
		for (i = 0; i < n; i++)
			send_iov[i + 1] = siov[i];
		siov = send_iov;
		n++;
	}

	if (siov != NULL && pci_vtnet_frame_within_mtu(sc, siov, n,
	    sc->be_vhdrlen, count_iov(siov, n), gso_type) &&
	    sc->vsc_be != NULL)
		(void)netbe_send(sc->vsc_be, siov, n);

	/*
	 * Return the processed chain to the guest.  Used length is the
	 * number of bytes written by the device, which is zero for an
	 * entirely device-readable transmit chain.
	 */
	vq_relchain(vq, req.idx, 0);
}

/* Called on TX kick. */
static void
pci_vtnet_ping_txq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * Any ring entries to process?
	 */
	if (!vq_has_descs(vq))
		return;

	/* Signal the tx thread for processing */
	pthread_mutex_lock(&sc->tx_mtx);
	vq_kick_disable(vq);
	if (sc->tx_in_progress == 0)
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * Thread which will handle processing of TX desc
 */
static void *
pci_vtnet_tx_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct vqueue_info *vq;
	int error;

	vq = &sc->vsc_queues[VTNET_TXQ];

	/*
	 * Let us wait till the tx queue pointers get initialised &
	 * first tx signaled
	 */
	pthread_mutex_lock(&sc->tx_mtx);
	error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
	assert(error == 0);

	for (;;) {
		/* note - tx mutex is locked here */
		while (sc->resetting || !sc->tx_features_negotiated ||
		    !vq_has_descs(vq)) {
			vq_kick_enable(vq);
			if (!sc->resetting && sc->tx_features_negotiated &&
			    vq_has_descs(vq))
				break;

			sc->tx_in_progress = 0;
			error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
			assert(error == 0);
		}
		vq_kick_disable(vq);
		sc->tx_in_progress = 1;
		pthread_mutex_unlock(&sc->tx_mtx);

		do {
			/*
			 * Run through entries, placing them into
			 * iovecs and sending when an end-of-packet
			 * is found
			 */
			pci_vtnet_proctx(sc, vq);
		} while (vq_has_descs(vq));

		/*
		 * Generate an interrupt if needed.
		 */
		vq_endchains(vq, /*used_all_avail=*/1);

		pthread_mutex_lock(&sc->tx_mtx);
	}
}

#ifdef notyet
static void
pci_vtnet_ping_ctlq(void *vsc, struct vqueue_info *vq)
{

	DPRINTF(("vtnet: control qnotify!"));
}
#endif

static bool
pci_vtnet_mtu_valid(unsigned long mtu)
{

	return (mtu >= VTNET_MIN_MTU && mtu <= VTNET_MAX_MTU);
}

static int
pci_vtnet_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtnet_softc *sc;
	uint64_t backend_features;
	bool intr_initialized;
	const char *value;
	char tname[MAXCOMLEN + 1];
	unsigned long mtu = ETHERMTU;
	int err = 1;

	/*
	 * Allocate data structures for further virtio initializations.
	 * sc also contains a copy of vtnet_vi_consts, since capabilities
	 * change depending on the backend.
	 */
	sc = calloc(1, sizeof(struct pci_vtnet_softc));
	if (sc == NULL)
		return (ENOMEM);
	intr_initialized = false;

	sc->vsc_consts = vtnet_vi_consts;
	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0) {
		free(sc);
		return (ENOMEM);
	}
	if (pthread_mutex_init(&sc->rx_mtx, NULL) != 0) {
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
		return (ENOMEM);
	}
	if (pthread_mutex_init(&sc->tx_mtx, NULL) != 0) {
		pthread_mutex_destroy(&sc->rx_mtx);
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
		return (ENOMEM);
	}
	if (pthread_cond_init(&sc->tx_cond, NULL) != 0) {
		pthread_mutex_destroy(&sc->tx_mtx);
		pthread_mutex_destroy(&sc->rx_mtx);
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
		return (ENOMEM);
	}

	sc->vsc_queues[VTNET_RXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_RXQ].vq_notify = pci_vtnet_ping_rxq;
	sc->vsc_queues[VTNET_TXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_TXQ].vq_notify = pci_vtnet_ping_txq;
#ifdef notyet
	sc->vsc_queues[VTNET_CTLQ].vq_qsize = VTNET_RINGSZ;
        sc->vsc_queues[VTNET_CTLQ].vq_notify = pci_vtnet_ping_ctlq;
#endif

	value = get_config_value_node(nvl, "mac");
	if (value != NULL) {
		err = net_parsemac(value, sc->vsc_config.mac);
		if (err) {
			goto failed;
		}
	} else
		net_genmac(pi, sc->vsc_config.mac);

	value = get_config_value_node(nvl, "mtu");
	if (value != NULL) {
		err = net_parsemtu(value, &mtu);
		if (err) {
			goto failed;
		}

		if (!pci_vtnet_mtu_valid(mtu)) {
			err = EINVAL;
			errno = EINVAL;
			goto failed;
		}
		sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_MTU;
	}
	sc->vsc_config.mtu = mtu;

	/* Permit interfaces without a configured backend. */
	if (get_config_value_node(nvl, "backend") != NULL) {
		err = netbe_init(&sc->vsc_be, nvl, pci_vtnet_rx_callback, sc);
		if (err) {
			goto failed;
		}
	}

	sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_MRG_RXBUF;
	if (sc->vsc_be != NULL) {
		backend_features = netbe_get_cap(sc->vsc_be);
		if (!pci_vtnet_backend_features_valid(backend_features)) {
			EPRINTLN("virtio-net backend returned invalid feature set "
			    "%#jx", (uintmax_t)backend_features);
			err = EINVAL;
			errno = EINVAL;
			goto failed;
		}
		sc->vsc_consts.vc_hv_caps |= backend_features;
	}

	/*
	 * Since we do not actually support multiqueue,
	 * set the maximum virtqueue pairs to 1.
	 */
	sc->vsc_config.max_virtqueue_pairs = 1;

	/* A configured backend provides carrier; an unattached NIC is down. */
	sc->vsc_config.status = sc->vsc_be != NULL ? 1 : 0;

	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto failed;

	/* initialize config space */
	if (vi_pci_is_modern(&sc->vsc_vs))
		vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_NETWORK);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_TRANSITIONAL_NET);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_NETWORK);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);

	/* use BAR 1 to map MSI-X table and PBA, if we're using MSI-X */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	intr_initialized = true;

	if (vi_pci_is_modern(&sc->vsc_vs)) {
		if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
			goto failed;
	} else
		vi_set_io_bar(&sc->vsc_vs, 0);

	sc->resetting = 0;
	sc->rx_merge = 0;
	sc->vhdrlen = pci_vtnet_header_len(sc, 0);

	/*
	 * Initialize tx semaphore & spawn TX processing thread.
	 * As of now, only one thread for TX desc processing is
	 * spawned.
	 */
	sc->tx_in_progress = 0;
	err = pthread_create(&sc->tx_tid, NULL, pci_vtnet_tx_thread, sc);
	if (err != 0)
		goto failed;
	snprintf(tname, sizeof(tname), "vtnet-%d:%d tx", pi->pi_slot,
	    pi->pi_func);
	pthread_set_name_np(sc->tx_tid, tname);

	return (0);

failed:
	netbe_cleanup(sc->vsc_be);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	pthread_cond_destroy(&sc->tx_cond);
	pthread_mutex_destroy(&sc->tx_mtx);
	pthread_mutex_destroy(&sc->rx_mtx);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	return (err != 0 ? err : 1);
}

static int
pci_vtnet_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	/*
	 * VirtIO 1.4 section 5.1.4.2 makes the modern network device
	 * configuration read-only.  The legacy interface in section 5.1.4.3
	 * retains writable MAC bytes for compatibility.
	 */
	if (sc->vsc_vs.vs_transport == VIRTIO_PCI_TRANSPORT_LEGACY &&
	    offset >= 0 && (size == 1 || size == 2 || size == 4) &&
	    (size_t)offset <= sizeof(sc->vsc_config.mac) &&
	    (size_t)size <= sizeof(sc->vsc_config.mac) - (size_t)offset) {
		ptr = &sc->vsc_config.mac[offset];
		memcpy(ptr, &value, size);
	} else {
		/* silently ignore other writes */
		DPRINTF(("vtnet: write to readonly reg %d", offset));
	}

	return (0);
}

static int
pci_vtnet_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	*retval = 0;
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(sc->vsc_config) ||
	    (size_t)size > sizeof(sc->vsc_config) - (size_t)offset)
		return (EINVAL);
	ptr = (uint8_t *)&sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
}

/*
 * Apply feature-dependent frontend and backend state while both rx_mtx and
 * tx_mtx are held.  Feature negotiation normally happens before DRIVER_OK,
 * but the same operation is also needed while snapshot restore has the device
 * paused and already owns both locks.
 */
static bool
pci_vtnet_apply_features(struct pci_vtnet_softc *sc,
    uint64_t negotiated_features)
{
	uint64_t backend_features;
	size_t backend_vhdrlen;

	sc->vsc_features = negotiated_features;

	sc->vhdrlen = pci_vtnet_header_len(sc, negotiated_features);
	sc->rx_merge =
	    (negotiated_features & VIRTIO_NET_F_MRG_RXBUF) != 0;

	/* Tell a configured backend to enable capabilities it advertised. */
	if (sc->vsc_be != NULL) {
		/*
		 * Only backend offload features require a vnet header on the
		 * host interface.  Frontend-only and transport features are
		 * consumed by this device model; passing them to tap or slirp
		 * would incorrectly turn their normal header-stripping path
		 * into a capability-application failure.
		 */
		backend_features = negotiated_features & VTNET_BACKEND_CAPS;
		backend_vhdrlen = backend_features != 0 ? sc->vhdrlen : 0;
		if (netbe_set_cap(sc->vsc_be, backend_features,
		    backend_vhdrlen) != 0) {
			/*
			 * Capability probing happens during device creation,
			 * but applying the selected header format can still
			 * fail later.  Do not mark receive processing live with
			 * a backend whose framing differs from the negotiated
			 * virtio-net contract.
			 */
			sc->be_vhdrlen = 0;
			sc->features_negotiated = false;
			sc->tx_features_negotiated = false;
			vi_set_needs_reset(&sc->vsc_vs);
			return (false);
		}
		sc->be_vhdrlen = netbe_get_vnet_hdr_len(sc->vsc_be);
	} else
		sc->be_vhdrlen = 0;
	if (sc->vsc_be != NULL && sc->be_vhdrlen != backend_vhdrlen) {
		sc->be_vhdrlen = 0;
		sc->features_negotiated = false;
		sc->tx_features_negotiated = false;
		vi_set_needs_reset(&sc->vsc_vs);
		return (false);
	}

	sc->features_negotiated = true;
	sc->tx_features_negotiated = true;
	return (true);
}

static void
pci_vtnet_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtnet_softc *sc = vsc;

	pthread_mutex_lock(&sc->rx_mtx);
	pthread_mutex_lock(&sc->tx_mtx);
	(void)pci_vtnet_apply_features(sc, negotiated_features);
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
}

#ifdef BHYVE_SNAPSHOT
static void
pci_vtnet_pause(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device pause requested !\n"));

	/* Acquire the RX lock to block RX processing. */
	pthread_mutex_lock(&sc->rx_mtx);

	/* Wait for the transmit thread to finish its processing. */
	pthread_mutex_lock(&sc->tx_mtx);
	while (sc->tx_in_progress) {
		pthread_mutex_unlock(&sc->tx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->tx_mtx);
	}
}

static void
pci_vtnet_resume(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device resume requested !\n"));

	if (sc->tx_features_negotiated &&
	    vq_has_descs(&sc->vsc_queues[VTNET_TXQ]))
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
	/* The RX lock should have been acquired in vtnet_pause. */
	pthread_mutex_unlock(&sc->rx_mtx);
}

static int
pci_vtnet_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	int ret;
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device snapshot requested !\n"));

	/*
	 * Queues and consts should have been saved by the more generic
	 * vi_pci_snapshot function. We need to save only our features and
	 * config.
	 */

	SNAPSHOT_VAR_OR_LEAVE(sc->vsc_features, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->features_negotiated, meta, ret, done);

	SNAPSHOT_VAR_OR_LEAVE(sc->vsc_config, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->rx_merge, meta, ret, done);

	SNAPSHOT_VAR_OR_LEAVE(sc->vhdrlen, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->be_vhdrlen, meta, ret, done);

	/*
	 * Force reapplication only after all saved fields have been consumed.
	 * The pause callback already owns rx_mtx and tx_mtx here, so use the
	 * locked helper rather than recursively acquiring either mutex.  This
	 * also overwrites the saved derived header fields with values verified
	 * against the current backend.
	 */
	if (meta->op == VM_SNAPSHOT_RESTORE &&
	    sc->features_negotiated) {
		if (pci_vtnet_apply_features(sc, sc->vsc_features) &&
		    sc->vsc_be != NULL)
			netbe_rx_enable(sc->vsc_be);
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		sc->tx_features_negotiated = false;
	}

done:
	return (ret);
}
#endif

static const struct pci_devemu pci_de_vnet = {
	.pe_emu = 	"virtio-net",
	.pe_init =	pci_vtnet_init,
	.pe_legacy_config = netbe_legacy_config,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	vi_pci_snapshot,
	.pe_pause =	vi_pci_pause,
	.pe_resume =	vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vnet);

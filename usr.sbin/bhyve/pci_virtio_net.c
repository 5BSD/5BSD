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
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*
 * Release-ledger anchors for multiqueue, RSS, and live save-state paths.
 * VIRTIO_ACTIVATION_ASSERTION: mq-control-and-every-tx-queue
 * VIRTIO_ACTIVATION_ASSERTION: rss-control-apply
 * VIRTIO_ACTIVATION_ASSERTION: snapshot-restore-and-rss-reapply
 */
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
#include "virtio_pci_modern_probes.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

#define VTNET_RINGSZ	1024

#define VTNET_MAXSEGS	256
/*
 * Implementation policies, not VirtIO wire limits.  Eight queue pairs bound
 * per-device queue storage and host scheduling work while still covering
 * typical multiqueue guests.  The TX batch limit prevents one continuously
 * busy pair from monopolizing the single TX worker before it rotates.
 */
#define	VTNET_MAX_PAIRS	8
#define	VTNET_FLOW_ENTRIES	1024
#define	VTNET_TX_BUDGET	64
#define	VTNET_RX_BUDGET	64
#ifndef VTNET_QUIESCE_TIMEOUT_SECONDS
#define	VTNET_QUIESCE_TIMEOUT_SECONDS	30
#endif
#define	VTNET_RSS_KEY_SIZE	40
#define	VTNET_RSS_TABLE_SIZE	128
#define	VTNET_TCP_HEADER_MIN	20
#define	VTNET_UDP_HEADER_SIZE	8

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
	uint32_t speed;
	uint8_t duplex;
	uint8_t rss_max_key_size;
	uint16_t rss_max_indirection_table_length;
	uint32_t supported_hash_types;
} __packed;

/*
 * Queue definitions.
 */
#define VTNET_RXQ	0
#define VTNET_TXQ	1
#define	VTNET_MAXQ	(VTNET_MAX_PAIRS * 2 + 1)

#define	VTNET_CTRL_MQ			4
#define	VTNET_CTRL_MQ_VQ_PAIRS_SET	0
#define	VTNET_CTRL_MQ_RSS_CONFIG	1
#define	VTNET_CTRL_MQ_HASH_CONFIG	2
#define	VTNET_CTRL_OK			0
#define	VTNET_CTRL_ERR			1

#define	VTNET_CTRL_CLASS_OFFSET		0
#define	VTNET_CTRL_COMMAND_OFFSET	1
#define	VTNET_CTRL_HEADER_SIZE		2
#define	VTNET_CTRL_MQ_PAIRS_OFFSET	VTNET_CTRL_HEADER_SIZE
#define	VTNET_CTRL_MQ_PAIRS_SIZE		\
	(VTNET_CTRL_HEADER_SIZE + sizeof(uint16_t))

#define	VTNET_RSS_HASH_TYPE_IPV4	(1U << 0)
#define	VTNET_RSS_HASH_TYPE_TCPV4	(1U << 1)
#define	VTNET_RSS_HASH_TYPE_UDPV4	(1U << 2)
#define	VTNET_RSS_HASH_TYPE_IPV6	(1U << 3)
#define	VTNET_RSS_HASH_TYPE_TCPV6	(1U << 4)
#define	VTNET_RSS_HASH_TYPE_UDPV6	(1U << 5)
#define	VTNET_RSS_HASH_TYPES		((1U << 6) - 1)

/*
 * VirtIO 1.4 sections 5.1.6.5.7.1 and 5.1.6.5.7.2 define byte-oriented
 * control commands.  Keep their offsets explicit: these are wire layouts,
 * not native C structure layouts.
 */
#define	VTNET_RSS_HASH_TYPES_OFFSET	VTNET_CTRL_HEADER_SIZE
#define	VTNET_RSS_TABLE_MASK_OFFSET	\
	(VTNET_RSS_HASH_TYPES_OFFSET + sizeof(uint32_t))
#define	VTNET_RSS_UNCLASSIFIED_OFFSET	\
	(VTNET_RSS_TABLE_MASK_OFFSET + sizeof(uint16_t))
#define	VTNET_RSS_TABLE_OFFSET		\
	(VTNET_RSS_UNCLASSIFIED_OFFSET + sizeof(uint16_t))
#define	VTNET_RSS_TRAILER_PREFIX_SIZE	(sizeof(uint16_t) + sizeof(uint8_t))
#define	VTNET_RSS_COMMAND_MIN		\
	(VTNET_RSS_TABLE_OFFSET + sizeof(uint16_t) + \
	    VTNET_RSS_TRAILER_PREFIX_SIZE)
#define	VTNET_RSS_COMMAND_WIRE_MAX	\
	(VTNET_RSS_TABLE_OFFSET + VTNET_RSS_TABLE_SIZE * sizeof(uint16_t) + \
	    VTNET_RSS_TRAILER_PREFIX_SIZE + VTNET_RSS_KEY_SIZE)
/*
 * Linux uses sizeof(struct virtio_net_rss_config_trailer) for both RSS and
 * hash configuration.  The flexible-array trailer has one byte of trailing
 * C-structure padding, so accept that byte only when it is zero.
 */
#define	VTNET_RSS_COMMAND_MAX		(VTNET_RSS_COMMAND_WIRE_MAX + 1)
#define	VTNET_HASH_RESERVED_OFFSET	\
	(VTNET_RSS_HASH_TYPES_OFFSET + sizeof(uint32_t))
#define	VTNET_HASH_RESERVED_SIZE		8
#define	VTNET_HASH_KEY_LENGTH_OFFSET	\
	(VTNET_HASH_RESERVED_OFFSET + VTNET_HASH_RESERVED_SIZE)
#define	VTNET_HASH_KEY_OFFSET		\
	(VTNET_HASH_KEY_LENGTH_OFFSET + sizeof(uint8_t))
#define	VTNET_HASH_COMMAND_MIN		VTNET_HASH_KEY_OFFSET
#define	VTNET_HASH_COMMAND_WIRE_MAX	\
	(VTNET_HASH_KEY_OFFSET + VTNET_RSS_KEY_SIZE)
#define	VTNET_HASH_COMMAND_MAX		(VTNET_HASH_COMMAND_WIRE_MAX + 1)

#define	VTNET_HASH_REPORT_NONE		0
#define	VTNET_HASH_REPORT_IPV4		1
#define	VTNET_HASH_REPORT_TCPV4		2
#define	VTNET_HASH_REPORT_UDPV4		3
#define	VTNET_HASH_REPORT_IPV6		4
#define	VTNET_HASH_REPORT_TCPV6		5
#define	VTNET_HASH_REPORT_UDPV6		6

#define	VTNET_FLOW_HASH_PREFIX_SIZE	128

struct virtio_net_hash_report {
	uint32_t hash_value;
	uint16_t hash_report;
	uint16_t padding;
} __packed;
_Static_assert(sizeof(struct virtio_net_rxhdr) +
    sizeof(struct virtio_net_hash_report) == 20,
    "VirtIO-net HASH_REPORT header must be 20 bytes");

struct pci_vtnet_rss_config {
	uint32_t hash_types;
	uint16_t indirection_mask;
	uint16_t unclassified_queue;
	uint16_t indirection_table[VTNET_RSS_TABLE_SIZE];
	uint16_t max_tx_vq;
	uint16_t enabled_mask;
	uint8_t key_length;
	uint8_t key[VTNET_RSS_KEY_SIZE];
};

struct pci_vtnet_hash_config {
	uint32_t hash_types;
	uint8_t key_length;
	uint8_t key[VTNET_RSS_KEY_SIZE];
};

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
	struct vqueue_info vsc_queues[VTNET_MAXQ];
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
	struct vqueue_info *tx_current_vq;
	bool		tx_control_pause;
	bool		ctl_pending;
	bool		tx_last_control;
	uint16_t	tx_active_pairs;
	uint16_t	tx_next_pair;

	uint16_t	rx_active_pairs;
	uint16_t	rx_enabled_mask;
	uint16_t	vsc_max_pairs;
	uint64_t	vsc_flow_map[VTNET_FLOW_ENTRIES];
	bool		rss_enabled;
	bool		hash_configured;
	uint32_t	rss_hash_types;
	uint16_t	rss_indirection_mask;
	uint16_t	rss_unclassified_queue;
	uint16_t	rss_indirection_table[VTNET_RSS_TABLE_SIZE];
	uint16_t	rss_max_tx_vq;
	uint8_t		rss_key_length;
	uint8_t		rss_key[VTNET_RSS_KEY_SIZE];
	uint8_t		vsc_rx_buf[VTNET_MAX_PKT_LEN +
			    sizeof(struct virtio_net_rxhdr) +
			    sizeof(struct virtio_net_hash_report)];
	size_t		rx_staged_len;
	uint64_t	rx_bad_backend_records;

	size_t		vhdrlen;
	size_t		be_vhdrlen;

	struct virtio_net_config vsc_config;
	struct virtio_consts vsc_consts;
};

static bool
pci_vtnet_bad_backend_record_report(struct pci_vtnet_softc *sc)
{
	uint64_t count;

	/*
	 * A broken or hostile backend can keep a level-triggered descriptor
	 * readable forever.  Retain a lifetime counter, but emit only the first
	 * and power-of-two occurrences so diagnostics stay useful without
	 * turning the mevent thread into a log producer.
	 */
	if (sc->rx_bad_backend_records != UINT64_MAX)
		sc->rx_bad_backend_records++;
	count = sc->rx_bad_backend_records;
	return (count != 0 && (count & (count - 1)) == 0);
}

/*
 * Modern virtio-net always includes num_buffers in the 12-byte header.
 * Omitting it without MRG_RXBUF is a legacy-interface exception.
 */
static size_t
pci_vtnet_header_len(const struct pci_vtnet_softc *sc, uint64_t features)
{

	if ((features & VIRTIO_NET_F_HASH_REPORT) != 0)
		return (sizeof(struct virtio_net_rxhdr) +
		    sizeof(struct virtio_net_hash_report));
	if (sc->vsc_vs.vs_transport == VIRTIO_PCI_TRANSPORT_MODERN ||
	    (features & VIRTIO_NET_F_MRG_RXBUF) != 0)
		return (sizeof(struct virtio_net_rxhdr));
	return (sizeof(struct virtio_net_rxhdr) -
	    sizeof(((struct virtio_net_rxhdr *)0)->vrh_bufs));
}

static uint16_t
pci_vtnet_rxq_index(uint16_t pair)
{

	return (pair * 2);
}

static uint16_t
pci_vtnet_txq_index(uint16_t pair)
{

	return (pair * 2 + 1);
}

static uint16_t
pci_vtnet_ctlq_index(const struct pci_vtnet_softc *sc)
{

	return (sc->vsc_max_pairs * 2);
}

static bool
pci_vtnet_has_ctlq(const struct pci_vtnet_softc *sc)
{

	return (pci_vtnet_ctlq_index(sc) < sc->vsc_consts.vc_nvq);
}

static void
pci_vtnet_configure_transport_features(struct pci_vtnet_softc *sc,
    bool modern)
{
	uint64_t net_caps;

	net_caps = VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_MQ |
	    VIRTIO_NET_F_HASH_REPORT | VIRTIO_NET_F_RSS;
	sc->vsc_consts.vc_hv_caps &= ~net_caps;
	sc->vsc_consts.vc_nvq = 2;
	if (!modern)
		return;

	/* HASH_CONFIG is valid with one RX/TX pair and needs queue 2. */
	sc->vsc_consts.vc_nvq = sc->vsc_max_pairs * 2 + 1;
	sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_CTRL_VQ |
	    VIRTIO_NET_F_HASH_REPORT;
	if (sc->vsc_max_pairs > 1)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_NET_F_MQ |
		    VIRTIO_NET_F_RSS;
}

static bool pci_vtnet_iov_read(const struct iovec *, int, size_t, void *,
    size_t);

static uint32_t
pci_vtnet_hash_bytes(uint32_t hash, const void *data, size_t len)
{
	const uint8_t *bytes;

	bytes = data;
	while (len-- != 0) {
		hash ^= *bytes++;
		hash *= 16777619U;
	}
	return (hash);
}

static uint16_t
pci_vtnet_be16(const uint8_t *bytes)
{

	return ((uint16_t)bytes[0] << 8 | bytes[1]);
}

/*
 * Produce a direction-independent flow key.  Automatic receive steering
 * does not expose a programmable hash, but packets belonging to a flow must
 * stay together and a reverse-direction packet should follow the transmit
 * queue learned for that flow.
 */
static uint32_t
pci_vtnet_flow_hash(const uint8_t *frame, size_t len)
{
	uint8_t endpoints[2][18];
	const uint8_t *first, *second;
	uint32_t hash;
	uint16_t ether_type, frag, port[2];
	size_t addr_len, endpoint_len, l3off;
	uint8_t protocol;
	int cmp;

	hash = 2166136261U;
	if (len < ETHER_HDR_LEN)
		return (pci_vtnet_hash_bytes(hash, frame, len));

	l3off = ETHER_HDR_LEN;
	ether_type = pci_vtnet_be16(frame + 12);
	while ((ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ) &&
	    len >= l3off + ETHER_VLAN_ENCAP_LEN) {
		ether_type = pci_vtnet_be16(frame + l3off + 2);
		l3off += ETHER_VLAN_ENCAP_LEN;
	}

	memset(endpoints, 0, sizeof(endpoints));
	protocol = 0;
	addr_len = 0;
	port[0] = port[1] = 0;
	if (ether_type == ETHERTYPE_IP && len >= l3off + 20 &&
	    (frame[l3off] >> 4) == 4) {
		size_t ihl;

		ihl = (frame[l3off] & 0x0f) * 4;
		if (ihl >= 20 && len >= l3off + ihl) {
			addr_len = 4;
			protocol = frame[l3off + 9];
			memcpy(endpoints[0], frame + l3off + 12, addr_len);
			memcpy(endpoints[1], frame + l3off + 16, addr_len);
			frag = pci_vtnet_be16(frame + l3off + 6);
			if ((frag & 0x3fff) == 0 &&
			    (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) &&
			    len >= l3off + ihl + 4) {
				port[0] = pci_vtnet_be16(frame + l3off + ihl);
				port[1] = pci_vtnet_be16(frame + l3off + ihl + 2);
			}
		}
	} else if (ether_type == ETHERTYPE_IPV6 && len >= l3off + 40 &&
	    (frame[l3off] >> 4) == 6) {
		addr_len = 16;
		protocol = frame[l3off + 6];
		memcpy(endpoints[0], frame + l3off + 8, addr_len);
		memcpy(endpoints[1], frame + l3off + 24, addr_len);
		/*
		 * Hash IPv6 addresses and next-header only.  This remains stable
		 * across extension and fragment headers while still keeping each
		 * host-pair/protocol flow on one receive queue.
		 */
	}
	if (addr_len == 0) {
		addr_len = ETHER_ADDR_LEN;
		memcpy(endpoints[0], frame, addr_len);
		memcpy(endpoints[1], frame + ETHER_ADDR_LEN, addr_len);
	}
	endpoints[0][addr_len] = (uint8_t)(port[0] >> 8);
	endpoints[0][addr_len + 1] = (uint8_t)port[0];
	endpoints[1][addr_len] = (uint8_t)(port[1] >> 8);
	endpoints[1][addr_len + 1] = (uint8_t)port[1];
	endpoint_len = addr_len + 2;
	cmp = memcmp(endpoints[0], endpoints[1], endpoint_len);
	first = endpoints[cmp <= 0 ? 0 : 1];
	second = endpoints[cmp <= 0 ? 1 : 0];
	hash = pci_vtnet_hash_bytes(hash, &ether_type, sizeof(ether_type));
	hash = pci_vtnet_hash_bytes(hash, &protocol, sizeof(protocol));
	hash = pci_vtnet_hash_bytes(hash, first, endpoint_len);
	hash = pci_vtnet_hash_bytes(hash, second, endpoint_len);
	return (hash);
}

static uint32_t
pci_vtnet_iov_flow_hash(const struct iovec *iov, int niov, size_t offset)
{
	uint8_t frame[VTNET_FLOW_HASH_PREFIX_SIZE];
	size_t total, len;

	total = count_iov(iov, niov);
	if (offset >= total)
		return (0);
	len = MIN(sizeof(frame), total - offset);
	if (!pci_vtnet_iov_read(iov, niov, offset, frame, len))
		return (0);
	return (pci_vtnet_flow_hash(frame, len));
}

static void
pci_vtnet_flow_learn(struct pci_vtnet_softc *sc, uint32_t hash,
    uint16_t pair)
{
	uint64_t entry;

	if (hash == 0 || pair >= sc->vsc_max_pairs)
		return;
	entry = (uint64_t)hash << 32 | (uint32_t)pair + 1;
	atomic_store_rel_64(&sc->vsc_flow_map[hash &
	    (VTNET_FLOW_ENTRIES - 1)], entry);
}

static uint16_t
pci_vtnet_flow_pair(struct pci_vtnet_softc *sc, uint32_t hash,
    uint16_t active_pairs)
{
	uint64_t entry;
	uint16_t pair;

	if (active_pairs <= 1)
		return (0);
	entry = atomic_load_acq_64(&sc->vsc_flow_map[hash &
	    (VTNET_FLOW_ENTRIES - 1)]);
	if ((uint32_t)(entry >> 32) == hash && (uint32_t)entry != 0) {
		pair = (uint16_t)((uint32_t)entry - 1);
		if (pair < active_pairs)
			return (pair);
	}
	return ((uint16_t)(hash % active_pairs));
}

static bool
pci_vtnet_rss_toeplitz(const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len, uint32_t *result)
{
	uint32_t hash, window;
	size_t input_bits, key_bits;

	input_bits = input_len * 8;
	key_bits = key_len * 8;
	if (key_len < sizeof(window) || key_bits < input_bits + 31)
		return (false);
	window = (uint32_t)key[0] << 24 | (uint32_t)key[1] << 16 |
	    (uint32_t)key[2] << 8 | key[3];
	hash = 0;
	for (size_t bit = 0; bit < input_bits; bit++) {
		size_t next;

		if ((input[bit / 8] & (0x80U >> (bit % 8))) != 0)
			hash ^= window;
		next = bit + 32;
		window <<= 1;
		if (next < key_bits &&
		    (key[next / 8] & (0x80U >> (next % 8))) != 0)
			window |= 1;
	}
	*result = hash;
	return (true);
}

static bool
pci_vtnet_rss_hash(const struct pci_vtnet_softc *sc, const uint8_t *frame,
    size_t len, uint32_t *hash, uint16_t *report)
{
	uint8_t input[36];
	uint16_t ether_type, frag;
	uint16_t hash_report;
	size_t input_len, l3off, l4off, packet_end;
	uint8_t protocol;
	bool fragmented;

	if (report != NULL)
		*report = VTNET_HASH_REPORT_NONE;
	if (sc->rss_hash_types == 0 || len < ETHER_HDR_LEN)
		return (false);
	l3off = ETHER_HDR_LEN;
	ether_type = pci_vtnet_be16(frame + 12);
	while ((ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ) &&
	    len >= l3off + ETHER_VLAN_ENCAP_LEN) {
		ether_type = pci_vtnet_be16(frame + l3off + 2);
		l3off += ETHER_VLAN_ENCAP_LEN;
	}

	if (ether_type == ETHERTYPE_IP && len >= l3off + 20 &&
	    (frame[l3off] >> 4) == 4) {
		size_t ihl, iplen;

		ihl = (frame[l3off] & 0x0f) * 4;
		iplen = pci_vtnet_be16(frame + l3off + 2);
		if (ihl < 20 || iplen < ihl || len < l3off + iplen)
			return (false);
		memcpy(input, frame + l3off + 12, 8);
		input_len = 8;
		hash_report = VTNET_HASH_REPORT_IPV4;
		protocol = frame[l3off + 9];
		frag = pci_vtnet_be16(frame + l3off + 6);
		/*
		 * A first fragment still contains the transport header even
		 * when more fragments follow.  Only a non-zero fragment offset
		 * makes the four-tuple unavailable.
		 */
		fragmented = (frag & 0x1fff) != 0;
		if (!fragmented && protocol == IPPROTO_TCP &&
		    (sc->rss_hash_types & VTNET_RSS_HASH_TYPE_TCPV4) != 0 &&
		    iplen >= ihl + VTNET_TCP_HEADER_MIN) {
			memcpy(input + input_len, frame + l3off + ihl, 4);
			input_len += 4;
			hash_report = VTNET_HASH_REPORT_TCPV4;
		} else if (!fragmented && protocol == IPPROTO_UDP &&
		    (sc->rss_hash_types & VTNET_RSS_HASH_TYPE_UDPV4) != 0 &&
		    iplen >= ihl + VTNET_UDP_HEADER_SIZE) {
			memcpy(input + input_len, frame + l3off + ihl, 4);
			input_len += 4;
			hash_report = VTNET_HASH_REPORT_UDPV4;
		} else if ((sc->rss_hash_types &
		    VTNET_RSS_HASH_TYPE_IPV4) == 0)
			return (false);
	} else if (ether_type == ETHERTYPE_IPV6 && len >= l3off + 40 &&
	    (frame[l3off] >> 4) == 6) {
		size_t iplen;

		iplen = 40 + pci_vtnet_be16(frame + l3off + 4);
		if (len < l3off + iplen)
			return (false);
		packet_end = l3off + iplen;
		memcpy(input, frame + l3off + 8, 32);
		input_len = 32;
		hash_report = VTNET_HASH_REPORT_IPV6;
		protocol = frame[l3off + 6];
		l4off = l3off + 40;
		fragmented = false;
		/*
		 * VirtIO 1.4 section 5.1.9.4.3.4 says that when none of the
		 * extension-aware hash types is enabled, the device skips IPv6
		 * extension headers and applies the basic IPv6 hash rules.
		 */
		for (;;) {
			size_t extlen;

			if (protocol == IPPROTO_HOPOPTS ||
			    protocol == IPPROTO_ROUTING ||
			    protocol == IPPROTO_DSTOPTS ||
			    protocol == IPPROTO_MH ||
			    protocol == IPPROTO_HIP ||
			    protocol == IPPROTO_SHIM6) {
				if (packet_end < l4off + 2)
					return (false);
				extlen = ((size_t)frame[l4off + 1] + 1) * 8;
			} else if (protocol == IPPROTO_FRAGMENT) {
				if (packet_end < l4off + 8)
					return (false);
				frag = pci_vtnet_be16(frame + l4off + 2);
				fragmented |= (frag & 0xfff8) != 0;
				extlen = 8;
			} else if (protocol == IPPROTO_AH) {
				if (packet_end < l4off + 2)
					return (false);
				extlen = ((size_t)frame[l4off + 1] + 2) * 4;
			} else
				break;
			if (extlen == 0 || packet_end < l4off + extlen)
				return (false);
			protocol = frame[l4off];
			l4off += extlen;
		}
		if (!fragmented && protocol == IPPROTO_TCP &&
		    (sc->rss_hash_types & VTNET_RSS_HASH_TYPE_TCPV6) != 0 &&
		    packet_end >= l4off + VTNET_TCP_HEADER_MIN) {
			memcpy(input + input_len, frame + l4off, 4);
			input_len += 4;
			hash_report = VTNET_HASH_REPORT_TCPV6;
		} else if (!fragmented && protocol == IPPROTO_UDP &&
		    (sc->rss_hash_types & VTNET_RSS_HASH_TYPE_UDPV6) != 0 &&
		    packet_end >= l4off + VTNET_UDP_HEADER_SIZE) {
			memcpy(input + input_len, frame + l4off, 4);
			input_len += 4;
			hash_report = VTNET_HASH_REPORT_UDPV6;
		} else if ((sc->rss_hash_types &
		    VTNET_RSS_HASH_TYPE_IPV6) == 0)
			return (false);
	} else
		return (false);

	if (!pci_vtnet_rss_toeplitz(sc->rss_key, sc->rss_key_length,
	    input, input_len, hash))
		return (false);
	if (report != NULL)
		*report = hash_report;
	return (true);
}

static bool
pci_vtnet_rxq_enabled(const struct pci_vtnet_softc *sc, uint16_t pair)
{

	return (pair < sc->vsc_max_pairs &&
	    (sc->rx_enabled_mask & (1U << pair)) != 0);
}

static void pci_vtnet_reset(void *);
static int pci_vtnet_qenable(void *, struct vqueue_info *);
static int pci_vtnet_qreset(void *, struct vqueue_info *, uint64_t);
/* static void pci_vtnet_notify(void *, struct vqueue_info *); */
static int pci_vtnet_cfgread(void *, int, int, uint32_t *);
static int pci_vtnet_cfgwrite(void *, int, int, uint32_t);
static bool pci_vtnet_apply_features(struct pci_vtnet_softc *, uint64_t);
static int pci_vtnet_neg_features(void *, uint64_t);
static int pci_vtnet_suspend_device(void *);
static int pci_vtnet_resume_device(void *);
static void pci_vtnet_resume_complete(void *);
static bool pci_vtnet_process_ctlq(struct pci_vtnet_softc *,
    struct vqueue_info *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtnet_pause(void *);
static int pci_vtnet_resume(void *);
static int pci_vtnet_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtnet_snapshot_validate(struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtnet_vi_consts = {
	.vc_name =	"vtnet",
	.vc_nvq =	2,
	.vc_cfgsize =	sizeof(struct virtio_net_config),
	.vc_reset =	pci_vtnet_reset,
	.vc_cfgread =	pci_vtnet_cfgread,
	.vc_cfgwrite =	pci_vtnet_cfgwrite,
	.vc_apply_features = pci_vtnet_neg_features,
	.vc_qenable =	pci_vtnet_qenable,
	.vc_qreset =	pci_vtnet_qreset,
	.vc_suspend =	pci_vtnet_suspend_device,
	.vc_resume_device = pci_vtnet_resume_device,
	.vc_resume_complete = pci_vtnet_resume_complete,
	.vc_hv_caps =	VTNET_S_HOSTCAPS | VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vtnet_pause,
	.vc_resume =	pci_vtnet_resume,
	.vc_snapshot =	pci_vtnet_snapshot,
#endif
};

/*
 * Wait for either all transmit work, or work on one particular queue, to
 * leave the lockless backend-send section.  Callers must first prevent the
 * worker from selecting the queue again (device reset, control pause, queue
 * reset, or snapshot pause).
 */
static int
pci_vtnet_wait_tx_idle_locked(struct pci_vtnet_softc *sc,
    const struct vqueue_info *vq, bool bounded)
{
	struct timespec deadline;
	int error;

	if (bounded) {
		if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
			return (errno);
		deadline.tv_sec += VTNET_QUIESCE_TIMEOUT_SECONDS;
	}
	while (sc->tx_in_progress &&
	    (vq == NULL || sc->tx_current_vq == vq)) {
		if (bounded)
			error = pthread_cond_timedwait(&sc->tx_cond,
			    &sc->tx_mtx, &deadline);
		else
			error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
		if (error != 0 && sc->tx_in_progress &&
		    (vq == NULL || sc->tx_current_vq == vq))
			return (error);
	}
	return (0);
}

static void
pci_vtnet_reset(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device reset requested !"));

	/*
	 * Stop the shared TX/control worker before taking rx_mtx.  A control
	 * command can be inside a queue-topology update which itself needs
	 * rx_mtx, so waiting while holding that mutex would deadlock.
	 */
	pthread_mutex_lock(&sc->tx_mtx);
	sc->tx_features_negotiated = false;
	sc->resetting = 1;
	(void)pci_vtnet_wait_tx_idle_locked(sc, NULL, false);
	pthread_mutex_unlock(&sc->tx_mtx);

	/*
	 * Make sure receive operation is disabled at least until we
	 * re-negotiate the features, since receive operation depends
	 * on the value of sc->rx_merge and the header length, which
	 * are both set in pci_vtnet_neg_features().
	 * Receive operation will be enabled again once the guest adds
	 * the first receive buffers and kicks us.
	 */
	pthread_mutex_lock(&sc->rx_mtx);
	sc->features_negotiated = false;
	if (sc->vsc_be != NULL)
		netbe_rx_disable(sc->vsc_be);

	/*
	 * The worker remains fenced by resetting while the common queues and
	 * negotiated state are returned to their initial values.
	 */
	pthread_mutex_lock(&sc->tx_mtx);

	/*
	 * Now reset rings, MSI-X vectors, and negotiated capabilities.
	 * Do that with the TX lock held, since we need to reset
	 * sc->resetting.
	 */
	vi_reset_dev(&sc->vsc_vs);
	sc->vsc_features = 0;
	sc->rx_merge = 0;
	sc->vhdrlen = pci_vtnet_header_len(sc, 0);
	sc->rx_active_pairs = 1;
	sc->rx_enabled_mask = 1;
	sc->tx_active_pairs = 1;
	sc->tx_next_pair = 0;
	sc->tx_current_vq = NULL;
	sc->tx_control_pause = false;
	sc->ctl_pending = false;
	sc->tx_last_control = false;
	sc->rss_enabled = false;
	sc->hash_configured = false;
	sc->rss_hash_types = 0;
	sc->rss_indirection_mask = 0;
	sc->rss_unclassified_queue = 0;
	sc->rss_max_tx_vq = 1;
	sc->rss_key_length = 0;
	memset(sc->rss_indirection_table, 0,
	    sizeof(sc->rss_indirection_table));
	memset(sc->rss_key, 0, sizeof(sc->rss_key));
	sc->rx_staged_len = 0;
	memset(sc->vsc_flow_map, 0, sizeof(sc->vsc_flow_map));

	sc->resetting = 0;
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
}

static int
pci_vtnet_qenable(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc;
	uint16_t pair;

	sc = vsc;
	if (vq->vq_num >= sc->vsc_consts.vc_nvq ||
	    vq != &sc->vsc_queues[vq->vq_num])
		return (EINVAL);
	if (vq->vq_num == pci_vtnet_ctlq_index(sc))
		return (0);
	pair = vq->vq_num / 2;
	if ((vq->vq_num & 1) == 0) {
		if (!pci_vtnet_rxq_enabled(sc, pair))
			return (0);
		/*
		 * Enabling the ring does not imply that receive buffers are
		 * present.  The driver's subsequent kick performs the backend
		 * enable after the common transport publishes the queue.
		 */
		return (0);
	}

	pthread_mutex_lock(&sc->tx_mtx);
	if (pair < sc->tx_active_pairs && sc->tx_features_negotiated)
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
	return (0);
}

static int
pci_vtnet_qreset(void *vsc, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtnet_softc *sc;
	bool all_resetting, another;
	uint16_t pair;

	sc = vsc;
	if (vq->vq_num >= sc->vsc_consts.vc_nvq ||
	    vq != &sc->vsc_queues[vq->vq_num])
		return (EINVAL);
	if (vq->vq_num == pci_vtnet_ctlq_index(sc)) {
		int error;

		pthread_mutex_lock(&sc->tx_mtx);
		sc->ctl_pending = false;
		error = pci_vtnet_wait_tx_idle_locked(sc, vq, true);
		pthread_mutex_unlock(&sc->tx_mtx);
		return (error);
	}
	pair = vq->vq_num / 2;
	if ((vq->vq_num & 1) == 0) {
		/*
		 * Serialize with the backend callback.  Automatic multiqueue
		 * steering reselects another live pair.  RSS instead drops a
		 * packet whose configured destination is being reset.  With no
		 * other live receive queue, stop readiness events until a queue
		 * is re-enabled and kicked.
		 */
		pthread_mutex_lock(&sc->rx_mtx);
		another = false;
		all_resetting = true;
		for (uint16_t i = 0; i < sc->vsc_max_pairs; i++) {
			struct vqueue_info *candidate;

			if (!pci_vtnet_rxq_enabled(sc, i))
				continue;
			candidate = &sc->vsc_queues[pci_vtnet_rxq_index(i)];
			if (!vq_is_resetting(candidate))
				all_resetting = false;
			if (i == pair)
				continue;
			if (vq_ring_ready(candidate) &&
			    !vq_is_resetting(candidate)) {
				another = true;
				break;
			}
		}
		if (!another && sc->vsc_be != NULL)
			netbe_rx_disable(sc->vsc_be);
		if (all_resetting)
			sc->rx_staged_len = 0;
		pthread_mutex_unlock(&sc->rx_mtx);
		return (0);
	}
	if ((vq->vq_num & 1) != 0) {
		int error;

		/*
		 * Stop after the current synchronous send from this queue.
		 * Other active transmit queues remain available to the worker.
		 */
		pthread_mutex_lock(&sc->tx_mtx);
		error = pci_vtnet_wait_tx_idle_locked(sc, vq, true);
		pthread_mutex_unlock(&sc->tx_mtx);
		return (error);
	}
	return (EINVAL);
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
	if (sc->vhdrlen >= sizeof(*hdr) && le16toh(hdr->vrh_bufs) != 0)
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
		return (frame_len <=
		    (size_t)le16toh(sc->vsc_config.mtu) + header_len);

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
	return (frame_len <=
	    (size_t)le16toh(sc->vsc_config.mtu) + header_len);
}

struct virtio_mrg_rxbuf_info {
	struct vi_req req;
	size_t len;
};

static struct vqueue_info *
pci_vtnet_select_rxq(struct pci_vtnet_softc *sc, const uint8_t *frame,
    size_t frame_len, bool *drop, uint32_t *packet_hash,
    uint16_t *hash_report)
{
	struct vqueue_info *vq;
	uint32_t hash;
	uint16_t report;
	uint16_t pair, start;
	bool hashed;

	*drop = false;
	hash = 0;
	report = VTNET_HASH_REPORT_NONE;
	hashed = false;
	if (sc->rss_enabled || sc->hash_configured)
		hashed = pci_vtnet_rss_hash(sc, frame, frame_len, &hash,
		    &report);
	if (packet_hash != NULL)
		*packet_hash = hashed ? hash : 0;
	if (hash_report != NULL)
		*hash_report = hashed ? report : VTNET_HASH_REPORT_NONE;
	if (sc->rx_enabled_mask == 0)
		return (NULL);
	if (sc->rss_enabled) {
		if (hashed)
			pair = sc->rss_indirection_table[
			    hash & sc->rss_indirection_mask];
		else
			pair = sc->rss_unclassified_queue;
		if (!pci_vtnet_rxq_enabled(sc, pair)) {
			*drop = true;
			return (NULL);
		}
		vq = &sc->vsc_queues[pci_vtnet_rxq_index(pair)];
		if (vq_is_resetting(vq)) {
			*drop = true;
			return (NULL);
		}
		if (vq_ring_ready(vq) && vq_has_descs(vq))
			return (vq);
		return (NULL);
	}
	if (sc->rx_active_pairs == 0)
		return (NULL);
	hash = pci_vtnet_flow_hash(frame, frame_len);
	start = pci_vtnet_flow_pair(sc, hash, sc->rx_active_pairs);
	for (uint16_t i = 0; i < sc->rx_active_pairs; i++) {
		pair = (start + i) % sc->rx_active_pairs;
		vq = &sc->vsc_queues[pci_vtnet_rxq_index(pair)];
		if (pci_vtnet_rxq_enabled(sc, pair) &&
		    !vq_is_resetting(vq) && vq_ring_ready(vq) &&
		    vq_has_descs(vq))
			return (vq);
	}
	return (NULL);
}

static bool
pci_vtnet_all_rxqs_resetting(struct pci_vtnet_softc *sc)
{

	if (sc->rx_enabled_mask == 0)
		return (true);
	for (uint16_t i = 0; i < sc->vsc_max_pairs; i++) {
		if (!pci_vtnet_rxq_enabled(sc, i))
			continue;
		if (!vq_is_resetting(
		    &sc->vsc_queues[pci_vtnet_rxq_index(i)]))
			return (false);
	}
	return (true);
}

static void
pci_vtnet_rx(struct pci_vtnet_softc *sc)
{
	struct virtio_mrg_rxbuf_info info[VTNET_MAXSEGS];
	struct iovec iov[VTNET_MAXSEGS + 1];
	struct vi_req req;
	unsigned int backend_budget;

	if (sc->vsc_be == NULL)
		return;

	/*
	 * netbe_rx_disable() prevents new readiness notifications, but one
	 * already queued by mevent can run after suspend or checkpoint pause
	 * has completed.  Do not consume a host packet while the device is
	 * required to leave its observable state unchanged.
	 */
	if (sc->vsc_vs.vs_quiescing || sc->vsc_vs.vs_suspended ||
	    sc->vsc_vs.vs_checkpoint_paused) {
		netbe_rx_disable(sc->vsc_be);
		return;
	}

	/* Features must be negotiated */
	if (!sc->features_negotiated) {
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
	if (sc->be_vhdrlen != 0 &&
	    !((sc->be_vhdrlen == sizeof(struct virtio_net_rxhdr) -
	    sizeof(((struct virtio_net_rxhdr *)0)->vrh_bufs) &&
	    sc->vhdrlen == sc->be_vhdrlen) ||
	    (sc->be_vhdrlen == sizeof(struct virtio_net_rxhdr) &&
	    sc->vhdrlen >= sc->be_vhdrlen))) {
		WPRINTF(("vtnet: invalid backend header length"));
		netbe_rx_disable(sc->vsc_be);
		vi_set_needs_reset(&sc->vsc_vs);
		return;
	}

	backend_budget = VTNET_RX_BUDGET;
	for (;;) {
		struct virtio_net_rxhdr hdr;
		struct virtio_net_hash_report hash_hdr;
		struct vqueue_info *vq;
		struct iovec backend_iov;
		struct iovec frame_iov;
		size_t frame_len;
		size_t plen;
		size_t riov_bytes;
		struct iovec *riov;
		uint32_t ulen;
		int riov_len;
		int n_chains;
		uint16_t chain_budget;
		ssize_t backend_len;
		ssize_t rlen;
		uint32_t packet_hash;
		uint16_t hash_report;
		bool drop;

		if (sc->rx_staged_len == 0) {
			/*
			 * This callback runs on the shared mevent thread while the
			 * device and RX locks are held.  A continuously readable tap
			 * must not prevent reset, timers, or another device callback
			 * from making progress.  Charge only acquisition of a new host
			 * record: an already staged record must remain processable even
			 * after the batch is exhausted, and level-triggered backend
			 * readiness will schedule the remaining host records.
			 */
			if (backend_budget-- == 0)
				return;
			backend_len = netbe_peek_recvlen(sc->vsc_be);
			if (backend_len <= 0) {
				/*
				 * No more packets (backend_len == 0), or backend
				 * errored (backend_len < 0).  Each staged packet
				 * is published before the next backend peek.
				 */
				return;
			}
			if ((size_t)backend_len >
			    VTNET_MAX_PKT_LEN + sc->be_vhdrlen) {
				/*
				 * Do not leave an impossible record permanently
				 * at the head of the backend queue.
				 */
				if (pci_vtnet_bad_backend_record_report(sc))
					WPRINTF(("vtnet: dropping oversized backend "
					    "packet (%zd bytes, count %ju)",
					    backend_len,
					    (uintmax_t)sc->rx_bad_backend_records));
				VIRTIO_PROBE_ERROR(sc->vsc_vs.vs_vc->vc_name,
				    "oversized-backend-record");
				(void)netbe_rx_discard(sc->vsc_be);
				continue;
			}
			if ((size_t)backend_len < sc->be_vhdrlen) {
				if (pci_vtnet_bad_backend_record_report(sc))
					WPRINTF(("vtnet: dropping truncated backend "
					    "header (%zd bytes, count %ju)",
					    backend_len,
					    (uintmax_t)sc->rx_bad_backend_records));
				VIRTIO_PROBE_ERROR(sc->vsc_vs.vs_vc->vc_name,
				    "truncated-backend-header");
				(void)netbe_rx_discard(sc->vsc_be);
				continue;
			}

			/*
			 * Automatic receive steering needs the packet's flow
			 * before a receive queue can be selected.  Consume one
			 * complete record into a bounded device-owned staging
			 * buffer.  If no receive buffer is available, retain
			 * this record until a later queue kick.
			 */
			backend_iov.iov_base = sc->vsc_rx_buf;
			backend_iov.iov_len = (size_t)backend_len;
			rlen = netbe_recv(sc->vsc_be, &backend_iov, 1);
			if (rlen != backend_len) {
				WPRINTF(("netbe_recv: expected %zd bytes, got %zd",
				    backend_len, rlen));
				continue;
			}
			frame_len = (size_t)rlen - sc->be_vhdrlen;
			if (sc->vhdrlen != sc->be_vhdrlen) {
				memmove(sc->vsc_rx_buf + sc->vhdrlen,
				    sc->vsc_rx_buf + sc->be_vhdrlen,
				    frame_len);
				memset(sc->vsc_rx_buf + sc->be_vhdrlen, 0,
				    sc->vhdrlen - sc->be_vhdrlen);
			}
			plen = frame_len + sc->vhdrlen;
			sc->rx_staged_len = plen;
		} else
			plen = sc->rx_staged_len;
		if (plen < sc->vhdrlen) {
			sc->rx_staged_len = 0;
			continue;
		}
		memset(&hdr, 0, sizeof(hdr));
		memcpy(&hdr, sc->vsc_rx_buf, MIN(sc->vhdrlen, sizeof(hdr)));
		if (!pci_vtnet_rx_header_valid(sc, &hdr,
		    plen - sc->vhdrlen)) {
			DPRINTF(("vtnet: invalid receive offload metadata"));
			sc->rx_staged_len = 0;
			continue;
		}
		frame_iov.iov_base = sc->vsc_rx_buf;
		frame_iov.iov_len = plen;
		if (!pci_vtnet_frame_within_mtu(sc, &frame_iov, 1,
		    sc->vhdrlen, plen, hdr.vrh_gso_type)) {
			DPRINTF(("vtnet: dropping receive frame larger than MTU"));
			sc->rx_staged_len = 0;
			continue;
		}
		vq = pci_vtnet_select_rxq(sc, sc->vsc_rx_buf + sc->vhdrlen,
		    plen - sc->vhdrlen, &drop, &packet_hash, &hash_report);
		if (vq == NULL) {
			if (drop || pci_vtnet_all_rxqs_resetting(sc)) {
				sc->rx_staged_len = 0;
				continue;
			}
			netbe_rx_disable(sc->vsc_be);
			return;
		}
		if ((sc->vsc_features & VIRTIO_NET_F_HASH_REPORT) != 0) {
			hash_hdr.hash_value = htole32(packet_hash);
			hash_hdr.hash_report = htole16(hash_report);
			hash_hdr.padding = 0;
			memcpy(sc->vsc_rx_buf + sizeof(hdr), &hash_hdr,
			    sizeof(hash_hdr));
			VIRTIO_PROBE_NET_RX_HASH(sc->vsc_vs.vs_vc->vc_name,
			    vq->vq_num, packet_hash, hash_report,
			    (uint32_t)(plen - sc->vhdrlen));
		}

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
		chain_budget = vq->vq_qsize;
		while (chain_budget != 0 && riov_bytes < plen &&
		    riov_len < VTNET_MAXSEGS) {
			chain_budget--;
			int n = vq_getchain(vq, riov, VTNET_MAXSEGS - riov_len,
			    &req);

			if (n == 0) {
				/*
				 * The staged packet has already been removed
				 * from the backend.  Close the EVENT_IDX race
				 * before returning partial chains: a descriptor
				 * can become visible between the empty dequeue
				 * and enabling guest kicks.
				 */
				vq_kick_enable(vq);
				if (vq_has_descs(vq)) {
					vq_kick_disable(vq);
					continue;
				}
				for (int i = 0; i < n_chains; i++)
					vq_relchain_req(vq, &info[i].req, 0);
				vq_endchains(vq, /*used_all_avail=*/1);
				netbe_rx_disable(sc->vsc_be);
				return;
			}
			if (n < 0) {
				for (int i = 0; i < n_chains; i++)
					vq_relchain_req(vq, &info[i].req, 0);
				vq_endchains(vq, 0);
				netbe_rx_disable(sc->vsc_be);
				return;
			}
			if (n > VTNET_MAXSEGS - riov_len ||
			    req.readable != 0 || req.writable != n) {
				DPRINTF(("vtnet: invalid receive descriptor chain"));
				vq_relchain_req(vq, &req, 0);
				continue;
			}
			info[n_chains].req = req;
			info[n_chains].len = count_iov(riov, n);
			riov_bytes += info[n_chains].len;
			riov_len += n;
			if (!sc->rx_merge) {
				n_chains = 1;
				break;
			}
			riov += n;
			n_chains++;
		}
		if (riov_bytes < plen ||
		    (sc->rx_merge && info[0].len < sc->vhdrlen)) {
			WPRINTF(("vtnet: receive descriptor capacity is too small"));
			for (int i = 0; i < n_chains; i++)
				vq_relchain_req(vq, &info[i].req, 0);
			vq_endchains(vq, 0);
			netbe_rx_disable(sc->vsc_be);
			vi_set_needs_reset(&sc->vsc_vs);
			return;
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
			if (sc->vhdrlen >= sizeof(hdr)) {
				num_buffers = htole16(1);
				memcpy(sc->vsc_rx_buf +
				    offsetof(struct virtio_net_rxhdr, vrh_bufs),
				    &num_buffers, sizeof(num_buffers));
			}
			if (buf_to_iov(sc->vsc_rx_buf, plen, iov,
			    riov_len) != plen) {
				vq_relchain_req(vq, &info[0].req, 0);
				vq_endchains(vq, 0);
				continue;
			}
			vq_relchain_req(vq, &info[0].req, ulen);
		} else {
			struct vi_req complete_reqs[VTNET_MAXSEGS];
			uint32_t complete_lens[VTNET_MAXSEGS];
			uint32_t iolen, remaining;
			uint16_t num_buffers;
			int i = 0;

			remaining = ulen;
			do {
				iolen = MIN(info[i].len, (size_t)UINT32_MAX);
				if (iolen > remaining)
					iolen = remaining;
				remaining -= iolen;
				i++;
			} while (remaining > 0 && i < n_chains);

			num_buffers = htole16(i);
			memcpy(sc->vsc_rx_buf +
			    offsetof(struct virtio_net_rxhdr, vrh_bufs),
			    &num_buffers, sizeof(num_buffers));
			if (buf_to_iov(sc->vsc_rx_buf, plen, iov,
			    riov_len) != plen) {
				WPRINTF(("vtnet: receive header accounting error"));
				for (i = 0; i < n_chains; i++)
					vq_relchain_req(vq, &info[i].req, 0);
				vq_endchains(vq, 0);
				continue;
			}
			remaining = ulen;
			for (i = 0; remaining > 0 && i < n_chains; i++) {
				iolen = MIN(info[i].len, (size_t)UINT32_MAX);
				if (iolen > remaining)
					iolen = remaining;
				complete_reqs[i] = info[i].req;
				complete_lens[i] = iolen;
				remaining -= iolen;
			}
			vq_relchain_group(vq, complete_reqs, complete_lens, i);
			if (remaining != 0)
				WPRINTF(("vtnet: receive chain accounting error"));
		}
		sc->rx_staged_len = 0;
		vq_endchains(vq, /*used_all_avail=*/0);
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
	uint16_t pair;

	/*
	 * A qnotify means that the rx process can now begin.
	 * Enable RX only if features are negotiated.
	 */
	pthread_mutex_lock(&sc->rx_mtx);
	if (!sc->features_negotiated || (vq->vq_num & 1) != 0 ||
	    vq->vq_num >= pci_vtnet_ctlq_index(sc) ||
	    vq != &sc->vsc_queues[vq->vq_num]) {
		pthread_mutex_unlock(&sc->rx_mtx);
		return;
	}
	pair = vq->vq_num / 2;
	if (!pci_vtnet_rxq_enabled(sc, pair)) {
		pthread_mutex_unlock(&sc->rx_mtx);
		return;
	}

	if (sc->vsc_be != NULL) {
		vq_kick_disable(vq);
		if (sc->rx_staged_len != 0)
			pci_vtnet_rx(sc);
		if (sc->rx_staged_len == 0)
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
	uint32_t flow_hash;
	size_t send_len, total_len;
	ssize_t sent;
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
		vq_relchain_req(vq, &req, 0);
		return;
	}
	total_len = count_iov(iov, n);
	if (total_len < sc->vhdrlen) {
		DPRINTF(("vtnet: short transmit header"));
		vq_relchain_req(vq, &req, 0);
		return;
	}
	memset(&hdr, 0, sizeof(hdr));
	if (!pci_vtnet_iov_read(iov, n, 0, &hdr,
	    MIN(sc->vhdrlen, sizeof(hdr))) ||
	    !pci_vtnet_tx_header_valid(sc, &hdr,
	    total_len - sc->vhdrlen)) {
		DPRINTF(("vtnet: invalid transmit offload metadata"));
		vq_relchain_req(vq, &req, 0);
		return;
	}
	gso_type = hdr.vrh_gso_type;
	flow_hash = pci_vtnet_iov_flow_hash(iov, n, sc->vhdrlen);
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

	send_len = siov != NULL ? count_iov(siov, n) : 0;
	if (siov != NULL && pci_vtnet_frame_within_mtu(sc, siov, n,
	    sc->be_vhdrlen, send_len, gso_type) && sc->vsc_be != NULL) {
		sent = netbe_send(sc->vsc_be, siov, n);
		if (sent == (ssize_t)send_len && (vq->vq_num & 1) != 0 &&
		    vq->vq_num < pci_vtnet_ctlq_index(sc))
			pci_vtnet_flow_learn(sc, flow_hash,
			    (vq->vq_num - 1) / 2);
	}

	/*
	 * Return the processed chain to the guest.  Used length is the
	 * number of bytes written by the device, which is zero for an
	 * entirely device-readable transmit chain.
	 */
	vq_relchain_req(vq, &req, 0);
}

/* Called on TX kick. */
static void
pci_vtnet_ping_txq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;
	uint16_t pair;

	if ((vq->vq_num & 1) == 0 ||
	    vq->vq_num >= pci_vtnet_ctlq_index(sc) ||
	    vq != &sc->vsc_queues[vq->vq_num])
		return;
	pair = (vq->vq_num - 1) / 2;

	/* Signal the tx thread for processing */
	pthread_mutex_lock(&sc->tx_mtx);
	if (pair < sc->tx_active_pairs && sc->tx_features_negotiated &&
	    vq_has_descs(vq)) {
		vq_kick_disable(vq);
		pthread_cond_signal(&sc->tx_cond);
	}
	pthread_mutex_unlock(&sc->tx_mtx);
}

static struct vqueue_info *
pci_vtnet_tx_find_work_locked(struct pci_vtnet_softc *sc)
{
	struct vqueue_info *vq;
	uint16_t pair;

	for (uint16_t i = 0; i < sc->tx_active_pairs; i++) {
		pair = (sc->tx_next_pair + i) % sc->tx_active_pairs;
		vq = &sc->vsc_queues[pci_vtnet_txq_index(pair)];
		if (!vq_is_resetting(vq) && vq_ring_ready(vq) &&
		    vq_has_descs(vq)) {
			sc->tx_next_pair = (pair + 1) % sc->tx_active_pairs;
			return (vq);
		}
	}
	return (NULL);
}

/*
 * Control work shares the TX worker so guest kicks remain nonblocking without
 * adding another per-device thread.  Alternate a bounded control batch with
 * packet work whenever both are continuously available.
 */
static struct vqueue_info *
pci_vtnet_find_work_locked(struct pci_vtnet_softc *sc)
{
	struct vqueue_info *ctlq, *txq;
	bool control_ready;

	txq = pci_vtnet_tx_find_work_locked(sc);
	control_ready = false;
	ctlq = NULL;
	if (pci_vtnet_has_ctlq(sc) && sc->ctl_pending) {
		ctlq = &sc->vsc_queues[pci_vtnet_ctlq_index(sc)];
		control_ready = !vq_is_resetting(ctlq) &&
		    vq_ring_ready(ctlq);
	}
	if (control_ready && (txq == NULL || !sc->tx_last_control)) {
		sc->ctl_pending = false;
		sc->tx_last_control = true;
		return (ctlq);
	}
	if (txq != NULL) {
		sc->tx_last_control = false;
		return (txq);
	}
	if (control_ready) {
		sc->ctl_pending = false;
		sc->tx_last_control = true;
		return (ctlq);
	}
	return (NULL);
}

/*
 * Arm guest notifications only for mapped, active queues, then close the
 * EVENT_IDX race by checking for work again before the worker sleeps.
 */
static struct vqueue_info *
pci_vtnet_tx_arm_locked(struct pci_vtnet_softc *sc)
{
	struct vqueue_info *vq;

	if (sc->resetting || sc->tx_control_pause ||
	    !sc->tx_features_negotiated)
		return (NULL);
	for (uint16_t i = 0; i < sc->tx_active_pairs; i++) {
		vq = &sc->vsc_queues[pci_vtnet_txq_index(i)];
		if (vq_ring_ready(vq))
			vq_kick_enable(vq);
	}
	return (pci_vtnet_find_work_locked(sc));
}

/*
 * Thread which will handle processing of TX desc
 */
static void *
pci_vtnet_tx_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct vqueue_info *vq;
	bool control, more, used_all;
	int budget, error;

	pthread_mutex_lock(&sc->tx_mtx);
	for (;;) {
		vq = pci_vtnet_find_work_locked(sc);
		while (sc->resetting || sc->tx_control_pause ||
		    !sc->tx_features_negotiated || vq == NULL) {
			sc->tx_in_progress = 0;
			sc->tx_current_vq = NULL;
			pthread_cond_broadcast(&sc->tx_cond);
			vq = pci_vtnet_tx_arm_locked(sc);
			if (vq != NULL)
				break;
			error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
			assert(error == 0);
			(void)error;
			vq = pci_vtnet_find_work_locked(sc);
		}
		vq_kick_disable(vq);
		control = pci_vtnet_has_ctlq(sc) &&
		    vq->vq_num == pci_vtnet_ctlq_index(sc);
		sc->tx_in_progress = 1;
		sc->tx_current_vq = vq;
		pthread_mutex_unlock(&sc->tx_mtx);

		more = false;
		if (control)
			more = pci_vtnet_process_ctlq(sc, vq);
		else {
			budget = VTNET_TX_BUDGET;
			do {
				/*
				 * Run through entries, placing them into
				 * iovecs and sending when an end-of-packet
				 * is found.
				 */
				pci_vtnet_proctx(sc, vq);
			} while (--budget != 0 && !vq_is_resetting(vq) &&
			    vq_ring_ready(vq) && vq_has_descs(vq));

			/*
			 * Generate an interrupt if needed.  A bounded batch
			 * keeps one continuously busy queue from starving the
			 * other active transmit pairs.
			 */
			if (!vq_is_resetting(vq)) {
				used_all = !vq_has_descs(vq);
				vq_endchains(vq, used_all);
			}
		}

		pthread_mutex_lock(&sc->tx_mtx);
		if (control && more && !sc->resetting &&
		    !sc->tx_control_pause)
			sc->ctl_pending = true;
		sc->tx_in_progress = 0;
		sc->tx_current_vq = NULL;
		pthread_cond_broadcast(&sc->tx_cond);
	}
}

static int
pci_vtnet_set_queue_state(struct pci_vtnet_softc *sc, uint16_t tx_pairs,
    uint16_t rx_mask, uint16_t automatic_pairs,
    const struct pci_vtnet_rss_config *rss)
{
	struct vqueue_info *vq;
	uint16_t old_pairs;
	int error;

	pthread_mutex_lock(&sc->rx_mtx);
	pthread_mutex_lock(&sc->tx_mtx);
	old_pairs = sc->tx_active_pairs;
	if (tx_pairs < old_pairs) {
		/*
		 * The control acknowledgement is the boundary after which the
		 * driver may reclaim disabled queues.  Pause the worker and
		 * retire every packet already made available on a queue being
		 * disabled before publishing that acknowledgement.
		 */
		sc->tx_control_pause = true;
		pthread_cond_signal(&sc->tx_cond);
		/*
		 * Control commands execute on the TX worker.  That worker is
		 * already the sole queue consumer, so it must not wait for its
		 * own control request while changing the data-queue topology.
		 */
		if (sc->tx_in_progress &&
		    sc->tx_current_vq ==
		    &sc->vsc_queues[pci_vtnet_ctlq_index(sc)])
			error = 0;
		else
			error = pci_vtnet_wait_tx_idle_locked(sc, NULL, true);
		if (error != 0) {
			sc->tx_control_pause = false;
			pthread_cond_signal(&sc->tx_cond);
			pthread_mutex_unlock(&sc->tx_mtx);
			pthread_mutex_unlock(&sc->rx_mtx);
			return (error);
		}
		pthread_mutex_unlock(&sc->tx_mtx);
		for (uint16_t i = tx_pairs; i < old_pairs; i++) {
			uint16_t budget;

			vq = &sc->vsc_queues[pci_vtnet_txq_index(i)];
			budget = vq->vq_qsize;
			while (budget-- != 0 && !vq_is_resetting(vq) &&
			    vq_ring_ready(vq) && vq_has_descs(vq))
				pci_vtnet_proctx(sc, vq);
			if (!vq_is_resetting(vq) && vq_ring_ready(vq))
				vq_endchains(vq, !vq_has_descs(vq));
		}
		pthread_mutex_lock(&sc->tx_mtx);
	}

	sc->rx_active_pairs = automatic_pairs;
	sc->rx_enabled_mask = rx_mask;
	sc->tx_active_pairs = tx_pairs;
	if (sc->tx_next_pair >= tx_pairs)
		sc->tx_next_pair = 0;
	sc->rss_enabled = rss != NULL;
	if (rss != NULL) {
		sc->hash_configured =
		    (sc->vsc_features & VIRTIO_NET_F_HASH_REPORT) != 0;
		sc->rss_hash_types = rss->hash_types;
		sc->rss_indirection_mask = rss->indirection_mask;
		sc->rss_unclassified_queue = rss->unclassified_queue;
		memcpy(sc->rss_indirection_table, rss->indirection_table,
		    sizeof(sc->rss_indirection_table));
		sc->rss_max_tx_vq = rss->max_tx_vq;
		sc->rss_key_length = rss->key_length;
		memcpy(sc->rss_key, rss->key, sizeof(sc->rss_key));
	} else {
		sc->rss_indirection_mask = 0;
		sc->rss_unclassified_queue = 0;
		memset(sc->rss_indirection_table, 0,
		    sizeof(sc->rss_indirection_table));
		sc->rss_max_tx_vq = 1;
		if ((sc->vsc_features & VIRTIO_NET_F_HASH_REPORT) == 0) {
			sc->hash_configured = false;
			sc->rss_hash_types = 0;
			sc->rss_key_length = 0;
			memset(sc->rss_key, 0, sizeof(sc->rss_key));
		}
	}
	sc->tx_control_pause = false;
	pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);

	/*
	 * Extra receive queues may already contain buffers because the driver
	 * is required to configure them before issuing PAIRS_SET.
	 */
	if (sc->vsc_be != NULL && sc->features_negotiated) {
		for (uint16_t i = 0; i < sc->vsc_max_pairs; i++) {
			if (!pci_vtnet_rxq_enabled(sc, i))
				continue;
			vq = &sc->vsc_queues[pci_vtnet_rxq_index(i)];
			if (!vq_is_resetting(vq) && vq_ring_ready(vq) &&
			    vq_has_descs(vq)) {
				netbe_rx_enable(sc->vsc_be);
				break;
			}
		}
	}
	pthread_mutex_unlock(&sc->rx_mtx);
	return (0);
}

static void
pci_vtnet_set_hash_config(struct pci_vtnet_softc *sc,
    const struct pci_vtnet_hash_config *config)
{

	pthread_mutex_lock(&sc->rx_mtx);
	sc->rss_hash_types = config->hash_types;
	sc->rss_key_length = config->key_length;
	memset(sc->rss_key, 0, sizeof(sc->rss_key));
	memcpy(sc->rss_key, config->key, config->key_length);
	sc->hash_configured = true;
	pthread_mutex_unlock(&sc->rx_mtx);
}

static int
pci_vtnet_set_active_pairs(struct pci_vtnet_softc *sc, uint16_t pairs)
{

	return (pci_vtnet_set_queue_state(sc, pairs, (1U << pairs) - 1,
	    pairs, NULL));
}

static bool
pci_vtnet_parse_rss_config(struct pci_vtnet_softc *sc,
    const uint8_t *command, size_t command_size,
    struct pci_vtnet_rss_config *rss)
{
	size_t command_end, key_offset, table_entries, trailer_offset;
	uint32_t hash_types;
	uint16_t value;

	/*
	 * The two-byte control header precedes the RSS command-specific data.
	 * Its fixed prefix is hash_types, table mask, and unclassified queue.
	 */
	if (command_size < VTNET_RSS_COMMAND_MIN)
		return (false);
	memcpy(&hash_types, command + VTNET_RSS_HASH_TYPES_OFFSET,
	    sizeof(hash_types));
	rss->hash_types = le32toh(hash_types);
	if ((rss->hash_types & ~VTNET_RSS_HASH_TYPES) != 0)
		return (false);
	memcpy(&value, command + VTNET_RSS_TABLE_MASK_OFFSET, sizeof(value));
	rss->indirection_mask = le16toh(value);
	table_entries = (size_t)rss->indirection_mask + 1;
	if (table_entries > VTNET_RSS_TABLE_SIZE ||
	    !powerof2(table_entries))
		return (false);
	memcpy(&value, command + VTNET_RSS_UNCLASSIFIED_OFFSET, sizeof(value));
	rss->unclassified_queue = le16toh(value);
	if (rss->unclassified_queue >= sc->vsc_max_pairs)
		return (false);

	trailer_offset =
	    VTNET_RSS_TABLE_OFFSET + table_entries * sizeof(uint16_t);
	key_offset = trailer_offset + sizeof(uint16_t) + sizeof(uint8_t);
	if (key_offset > command_size)
		return (false);
	memcpy(&value, command + trailer_offset, sizeof(value));
	rss->max_tx_vq = le16toh(value);
	if (rss->max_tx_vq < 1 || rss->max_tx_vq > sc->vsc_max_pairs)
		return (false);
	rss->key_length = command[trailer_offset + sizeof(uint16_t)];
	if (rss->key_length > VTNET_RSS_KEY_SIZE)
		return (false);
	command_end = key_offset + rss->key_length;
	if (command_size != command_end &&
	    (command_size != command_end + 1 || command[command_end] != 0))
		return (false);

	memset(rss->indirection_table, 0,
	    sizeof(rss->indirection_table));
	rss->enabled_mask = 1U << rss->unclassified_queue;
	for (size_t i = 0; i < table_entries; i++) {
		memcpy(&value, command + VTNET_RSS_TABLE_OFFSET +
		    i * sizeof(value),
		    sizeof(value));
		value = le16toh(value);
		if (value >= sc->vsc_max_pairs)
			return (false);
		rss->indirection_table[i] = value;
		rss->enabled_mask |= 1U << value;
	}
	memset(rss->key, 0, sizeof(rss->key));
	memcpy(rss->key, command + key_offset, rss->key_length);
	return (true);
}

static bool
pci_vtnet_parse_hash_config(const uint8_t *command, size_t command_size,
    struct pci_vtnet_hash_config *config)
{
	size_t command_end;
	uint32_t hash_types;

	if (command_size < VTNET_HASH_COMMAND_MIN ||
	    command_size > VTNET_HASH_COMMAND_MAX)
		return (false);
	memcpy(&hash_types, command + VTNET_RSS_HASH_TYPES_OFFSET,
	    sizeof(hash_types));
	config->hash_types = le32toh(hash_types);
	if ((config->hash_types & ~VTNET_RSS_HASH_TYPES) != 0)
		return (false);
	for (size_t i = VTNET_HASH_RESERVED_OFFSET;
	    i < VTNET_HASH_KEY_LENGTH_OFFSET; i++) {
		if (command[i] != 0)
			return (false);
	}
	config->key_length = command[VTNET_HASH_KEY_LENGTH_OFFSET];
	if (config->key_length > VTNET_RSS_KEY_SIZE)
		return (false);
	command_end = VTNET_HASH_COMMAND_MIN + config->key_length;
	if (command_size != command_end &&
	    (command_size != command_end + 1 || command[command_end] != 0))
		return (false);
	memset(config->key, 0, sizeof(config->key));
	memcpy(config->key, command + VTNET_HASH_KEY_OFFSET,
	    config->key_length);
	return (true);
}

static bool
pci_vtnet_process_ctlq(struct pci_vtnet_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTNET_MAXSEGS];
	struct vi_req req;
	struct pci_vtnet_hash_config hash;
	struct pci_vtnet_rss_config rss;
	uint8_t command[VTNET_RSS_COMMAND_MAX], ack;
	uint16_t pairs;
	size_t insize, outsize;
	bool command_valid;
	int budget, n;

	if (vq->vq_num != pci_vtnet_ctlq_index(sc) ||
	    vq != &sc->vsc_queues[vq->vq_num] ||
	    (sc->vsc_features & VIRTIO_NET_F_CTRL_VQ) == 0)
		return (false);
	DPRINTF(("vtnet: control notify q=%u layout=%s avail=%u "
	    "last-avail=%u next-used=%u", vq->vq_num,
	    vq->vq_layout == VIRTIO_QUEUE_PACKED ? "packed" : "split",
	    vq->vq_layout == VIRTIO_QUEUE_PACKED ?
	    vq->vq_packed_next_avail :
	    vi16_to_cpu(vq->vq_vs,
	    atomic_load_acq_16(&vq->vq_avail->idx)),
	    vq->vq_layout == VIRTIO_QUEUE_PACKED ?
	    vq->vq_packed_next_avail : vq->vq_last_avail,
	    vq->vq_layout == VIRTIO_QUEUE_PACKED ?
	    vq->vq_packed_next_used : vq->vq_next_used));
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
			n = vq_getchain(vq, iov, nitems(iov), &req);
			DPRINTF(("vtnet: control getchain n=%d last-avail=%u",
			    n, vq->vq_last_avail));
			if (n <= 0)
				break;
			if (n > (int)nitems(iov) || !req.ordered ||
			    req.readable == 0 || req.writable == 0 ||
			    req.readable + req.writable != n) {
				DPRINTF(("vtnet: invalid control descriptor chain"));
				vq_relchain_req(vq, &req, 0);
				continue;
			}
			insize = count_iov(iov, req.readable);
			outsize = count_iov(&iov[req.readable], req.writable);
			ack = VTNET_CTRL_ERR;
			command_valid = insize <= sizeof(command) &&
			    insize >= VTNET_CTRL_HEADER_SIZE &&
			    outsize >= sizeof(ack) &&
			    pci_vtnet_iov_read(iov, req.readable, 0, command,
			    insize);
			DPRINTF(("vtnet: control chain idx=%u n=%d readable=%u "
			    "writable=%u input=%zu output=%zu valid=%u class=%u "
			    "command=%u", req.idx, n, req.readable, req.writable,
			    insize, outsize, command_valid,
			    command_valid ?
			    command[VTNET_CTRL_CLASS_OFFSET] : UINT8_MAX,
			    command_valid ?
			    command[VTNET_CTRL_COMMAND_OFFSET] : UINT8_MAX));
			if (command_valid &&
			    command[VTNET_CTRL_CLASS_OFFSET] == VTNET_CTRL_MQ &&
			    command[VTNET_CTRL_COMMAND_OFFSET] ==
			    VTNET_CTRL_MQ_VQ_PAIRS_SET &&
			    insize == VTNET_CTRL_MQ_PAIRS_SIZE &&
			    (sc->vsc_features & VIRTIO_NET_F_MQ) != 0) {
				memcpy(&pairs,
				    &command[VTNET_CTRL_MQ_PAIRS_OFFSET],
				    sizeof(pairs));
				pairs = le16toh(pairs);
				if (pairs >= 1 && pairs <= sc->vsc_max_pairs) {
					if (pci_vtnet_set_active_pairs(sc,
					    pairs) == 0)
						ack = VTNET_CTRL_OK;
				}
			} else if (command_valid &&
			    command[VTNET_CTRL_CLASS_OFFSET] == VTNET_CTRL_MQ &&
			    command[VTNET_CTRL_COMMAND_OFFSET] ==
			    VTNET_CTRL_MQ_RSS_CONFIG &&
			    (sc->vsc_features & VIRTIO_NET_F_RSS) != 0 &&
			    pci_vtnet_parse_rss_config(sc, command, insize,
			    &rss)) {
				DPRINTF(("vtnet: RSS control apply bytes=%zu "
				    "pairs=%u mask=%#x key=%u", insize,
				    rss.max_tx_vq, rss.enabled_mask,
				    rss.key_length));
				if (pci_vtnet_set_queue_state(sc,
				    rss.max_tx_vq, rss.enabled_mask, 0,
				    &rss) == 0) {
					ack = VTNET_CTRL_OK;
					DPRINTF(("vtnet: RSS control applied"));
				}
			} else if (command_valid &&
			    command[VTNET_CTRL_CLASS_OFFSET] == VTNET_CTRL_MQ &&
			    command[VTNET_CTRL_COMMAND_OFFSET] ==
			    VTNET_CTRL_MQ_HASH_CONFIG &&
			    (sc->vsc_features &
			    VIRTIO_NET_F_HASH_REPORT) != 0 &&
			    (sc->vsc_features & VIRTIO_NET_F_RSS) == 0 &&
			    pci_vtnet_parse_hash_config(command, insize,
			    &hash)) {
				pci_vtnet_set_hash_config(sc, &hash);
				ack = VTNET_CTRL_OK;
			}
			if (outsize < sizeof(ack) ||
			    !pci_vtnet_iov_write(&iov[req.readable],
			    req.writable, 0, &ack, sizeof(ack))) {
				vq_relchain_req(vq, &req, 0);
				continue;
			}
			vq_relchain_req(vq, &req, sizeof(ack));
			DPRINTF(("vtnet: control complete idx=%u ack=%u used=%u "
			    "published=%u", req.idx, ack, vq->vq_next_used,
			    vq->vq_layout == VIRTIO_QUEUE_PACKED ?
			    vq->vq_packed_next_used :
			    vi16_to_cpu(vq->vq_vs,
			    atomic_load_acq_16(&vq->vq_used->idx))));
	}

	/*
	 * Linux sends control commands synchronously.  With EVENT_IDX, leaving
	 * avail_event at its reset value suppresses the kick for the next
	 * command.  Arm and recheck after the full barrier, but return after
	 * this bounded batch so data queues get a scheduling turn.
	 */
	vq_kick_enable(vq);
	if (!vq_has_descs(vq)) {
		vq_endchains(vq, 1);
		return (false);
	}
	vq_kick_disable(vq);
	vq_endchains(vq, 0);
	return (true);
}

static void
pci_vtnet_ping_ctlq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc;

	sc = vsc;
	if (vq->vq_num != pci_vtnet_ctlq_index(sc) ||
	    vq != &sc->vsc_queues[vq->vq_num] ||
	    (sc->vsc_features & VIRTIO_NET_F_CTRL_VQ) == 0)
		return;
	pthread_mutex_lock(&sc->tx_mtx);
	sc->ctl_pending = true;
	pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
}

static bool
pci_vtnet_mtu_valid(unsigned long mtu)
{

	return (mtu >= VTNET_MIN_MTU && mtu <= VTNET_MAX_MTU);
}

/*
 * The snapshot stream contains the complete guest-visible configuration, but
 * most of it describes resources fixed when the destination device was
 * created.  Never let an image resize the queue topology or RSS limits, change
 * the destination backend's link/MTU properties, or rewrite a modern
 * read-only MAC address.  A transitional guest may have written the legacy
 * MAC bytes before the snapshot, so those six bytes remain migratable there.
 */
static bool __unused
pci_vtnet_restore_config_valid(const struct pci_vtnet_softc *sc,
    const struct virtio_net_config *saved,
    const struct virtio_net_config *destination)
{

	if (memcmp(&saved->status, &destination->status,
	    sizeof(*saved) - offsetof(struct virtio_net_config, status)) != 0)
		return (false);
	if (sc->vsc_vs.vs_transport == VIRTIO_PCI_TRANSPORT_MODERN &&
	    memcmp(saved->mac, destination->mac, sizeof(saved->mac)) != 0)
		return (false);
	return (true);
}

static int
pci_vtnet_parse_queues(const char *value, uint16_t *pairs,
    const char **errstr)
{
	long parsed;

	*errstr = NULL;
	if (value == NULL) {
		*pairs = 1;
		return (0);
	}
	parsed = strtonum(value, 1, VTNET_MAX_PAIRS, errstr);
	if (*errstr != NULL)
		return (EINVAL);
	*pairs = (uint16_t)parsed;
	return (0);
}

static int
pci_vtnet_configure_ring_format(struct pci_vtnet_softc *sc, bool packed)
{

	if (packed && !vi_pci_is_modern(&sc->vsc_vs))
		return (EINVAL);
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	else
		sc->vsc_consts.vc_hv_caps &= ~VIRTIO_F_RING_PACKED;
	return (0);
}

static int
pci_vtnet_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtnet_softc *sc;
	pthread_condattr_t condattr;
	uint64_t backend_features;
	bool intr_initialized, packed;
	const char *errstr, *value;
	char tname[MAXCOMLEN + 1];
	unsigned long mtu = ETHERMTU;
	uint16_t pairs;
	int err = 1;

	value = get_config_value_node(nvl, "queues");
	if (pci_vtnet_parse_queues(value, &pairs, &errstr) != 0) {
		EPRINTLN("virtio-net queues is %s: %s", errstr, value);
		return (EINVAL);
	}
	packed = get_config_bool_node_default(nvl, "packed", false);
	value = getenv("BHYVE_VIRTIO_DEBUG");
	if (value != NULL) {
		pci_vtnet_debug = atoi(value);
		if (pci_vtnet_debug < 1)
			pci_vtnet_debug = 1;
	}

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
	sc->vsc_max_pairs = pairs;
	/*
	 * Modern HASH_REPORT has an independent HASH_CONFIG command and does
	 * not require MQ or RSS.  Reserve the control queue even for one pair;
	 * legacy transport narrows the visible topology after transport
	 * selection below.
	 */
	sc->vsc_consts.vc_nvq = pairs * 2 + 1;
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
	if (pthread_condattr_init(&condattr) != 0) {
		pthread_mutex_destroy(&sc->tx_mtx);
		pthread_mutex_destroy(&sc->rx_mtx);
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
		return (ENOMEM);
	}
	if (pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC) != 0 ||
	    pthread_cond_init(&sc->tx_cond, &condattr) != 0) {
		pthread_condattr_destroy(&condattr);
		pthread_mutex_destroy(&sc->tx_mtx);
		pthread_mutex_destroy(&sc->rx_mtx);
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
		return (ENOMEM);
	}
	pthread_condattr_destroy(&condattr);

	for (uint16_t i = 0; i < pairs; i++) {
		sc->vsc_queues[pci_vtnet_rxq_index(i)].vq_qsize =
		    VTNET_RINGSZ;
		sc->vsc_queues[pci_vtnet_rxq_index(i)].vq_notify =
		    pci_vtnet_ping_rxq;
		sc->vsc_queues[pci_vtnet_txq_index(i)].vq_qsize =
		    VTNET_RINGSZ;
		sc->vsc_queues[pci_vtnet_txq_index(i)].vq_notify =
		    pci_vtnet_ping_txq;
	}
	sc->vsc_queues[pci_vtnet_ctlq_index(sc)].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[pci_vtnet_ctlq_index(sc)].vq_notify =
	    pci_vtnet_ping_ctlq;

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
	sc->vsc_config.mtu = htole16(mtu);

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

	sc->vsc_config.max_virtqueue_pairs = htole16(pairs);
	sc->vsc_config.speed = htole32(UINT32_MAX);
	sc->vsc_config.duplex = UINT8_MAX;
	sc->vsc_config.rss_max_key_size = VTNET_RSS_KEY_SIZE;
	sc->vsc_config.rss_max_indirection_table_length =
	    htole16(VTNET_RSS_TABLE_SIZE);
	sc->vsc_config.supported_hash_types =
	    htole32(VTNET_RSS_HASH_TYPES);

	/* A configured backend provides carrier; an unattached NIC is down. */
	sc->vsc_config.status = htole16(sc->vsc_be != NULL ? 1 : 0);

	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto failed;
	if (pairs > 1 && !vi_pci_is_modern(&sc->vsc_vs)) {
		EPRINTLN("virtio-net queues requires transport=modern");
		err = EINVAL;
		goto failed;
	}
	pci_vtnet_configure_transport_features(sc,
	    vi_pci_is_modern(&sc->vsc_vs));
	if (pci_vtnet_configure_ring_format(sc, packed) != 0) {
		EPRINTLN("virtio-net packed queues require transport=modern");
		err = EINVAL;
		goto failed;
	}
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
	sc->rx_active_pairs = 1;
	sc->rx_enabled_mask = 1;
	sc->tx_active_pairs = 1;

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

	if (retval != NULL)
		*retval = 0;
	return (vi_config_read_le(&sc->vsc_config, sizeof(sc->vsc_config),
	    offset, size, retval));
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

	/*
	 * VirtIO 1.4 section 5.1.3 requires CTRL_VQ for MQ and RSS, and says
	 * drivers SHOULD NOT negotiate HASH_REPORT without CTRL_VQ.  Linux
	 * rejects all three combinations during feature validation.  Follow
	 * that stricter interoperable subset: without the control queue there
	 * is no way to issue HASH_CONFIG, so accepting HASH_REPORT would leave
	 * the extended receive header permanently reporting no hash.
	 */
	if ((negotiated_features & (VIRTIO_NET_F_MQ |
	    VIRTIO_NET_F_RSS | VIRTIO_NET_F_HASH_REPORT)) != 0 &&
	    (negotiated_features & VIRTIO_NET_F_CTRL_VQ) == 0) {
		sc->features_negotiated = false;
		sc->tx_features_negotiated = false;
		return (false);
	}
	if ((negotiated_features & (VIRTIO_NET_F_MQ |
	    VIRTIO_NET_F_RSS)) != 0 && sc->vsc_max_pairs <= 1) {
		sc->features_negotiated = false;
		sc->tx_features_negotiated = false;
		return (false);
	}

	sc->vsc_features = negotiated_features;

	sc->vhdrlen = pci_vtnet_header_len(sc, negotiated_features);
	sc->rx_merge =
	    (negotiated_features & VIRTIO_NET_F_MRG_RXBUF) != 0;
	if ((negotiated_features &
	    (VIRTIO_NET_F_MQ | VIRTIO_NET_F_RSS)) == 0) {
		sc->rx_active_pairs = 1;
		sc->rx_enabled_mask = 1;
		sc->tx_active_pairs = 1;
		sc->tx_next_pair = 0;
		sc->rss_enabled = false;
		if ((negotiated_features & VIRTIO_NET_F_HASH_REPORT) == 0) {
			sc->hash_configured = false;
			sc->rss_hash_types = 0;
			sc->rss_key_length = 0;
			memset(sc->rss_key, 0, sizeof(sc->rss_key));
		}
		memset(sc->vsc_flow_map, 0, sizeof(sc->vsc_flow_map));
	}

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
		backend_vhdrlen = backend_features != 0 ?
		    pci_vtnet_header_len(sc, negotiated_features &
		    ~VIRTIO_NET_F_HASH_REPORT) : 0;
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

static int
pci_vtnet_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtnet_softc *sc = vsc;
	bool applied;

	pthread_mutex_lock(&sc->rx_mtx);
	pthread_mutex_lock(&sc->tx_mtx);
	applied = pci_vtnet_apply_features(sc, negotiated_features);
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
	return (applied ? 0 : EINVAL);
}

/*
 * Guest-visible VirtIO suspend must not retain pthread mutex ownership:
 * resume may be requested by a different vCPU thread.  The common VirtIO
 * layer has already fenced new queue ownership with vs_quiescing.  Taking
 * RX and TX locks here waits for current callbacks, and tx_control_pause
 * prevents the dedicated TX worker from selecting more work.
 */
static int
pci_vtnet_suspend_device(void *vsc)
{
	struct pci_vtnet_softc *sc;
	int error;

	sc = vsc;
	pthread_mutex_lock(&sc->tx_mtx);
	sc->tx_control_pause = true;
	pthread_cond_signal(&sc->tx_cond);
	error = pci_vtnet_wait_tx_idle_locked(sc, NULL, true);
	if (error != 0) {
		sc->tx_control_pause = false;
		pthread_cond_signal(&sc->tx_cond);
		pthread_mutex_unlock(&sc->tx_mtx);
		return (error);
	}
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_lock(&sc->rx_mtx);
	if (sc->vsc_be != NULL)
		netbe_rx_disable(sc->vsc_be);
	pthread_mutex_unlock(&sc->rx_mtx);
	return (0);
}

/*
 * Resume callbacks run while the common lifecycle fence is still held, so a
 * normal vq_has_descs() check deliberately reports no work.  Once that fence
 * is released, inspect only already-validated split-ring state and restart
 * the host readiness source if a live receive queue has buffers waiting.
 */
static void
pci_vtnet_resume_complete(void *vsc)
{
	struct pci_vtnet_softc *sc;
	struct vqueue_info *vq;

	sc = vsc;
	pthread_mutex_lock(&sc->rx_mtx);
	if (sc->vsc_be != NULL && sc->features_negotiated) {
		for (uint16_t i = 0; i < sc->vsc_max_pairs; i++) {
			if (!pci_vtnet_rxq_enabled(sc, i))
				continue;
			vq = &sc->vsc_queues[pci_vtnet_rxq_index(i)];
			if (vq_ring_ready(vq) && vq_has_descs(vq)) {
				netbe_rx_enable(sc->vsc_be);
				break;
			}
		}
	}
	pthread_mutex_unlock(&sc->rx_mtx);

	pthread_mutex_lock(&sc->tx_mtx);
	if (!sc->tx_control_pause && sc->tx_features_negotiated) {
		if (pci_vtnet_has_ctlq(sc)) {
			vq = &sc->vsc_queues[pci_vtnet_ctlq_index(sc)];
			if (!vq_is_resetting(vq) && vq_ring_ready(vq) &&
			    vq_has_descs(vq))
				sc->ctl_pending = true;
		}
		if (sc->ctl_pending ||
		    pci_vtnet_tx_find_work_locked(sc) != NULL)
			pthread_cond_signal(&sc->tx_cond);
	}
	pthread_mutex_unlock(&sc->tx_mtx);
}

static int
pci_vtnet_resume_device(void *vsc)
{
	struct pci_vtnet_softc *sc;

	sc = vsc;
	pthread_mutex_lock(&sc->rx_mtx);
	pthread_mutex_lock(&sc->tx_mtx);
	sc->tx_control_pause = false;
	pthread_mutex_unlock(&sc->tx_mtx);
	pthread_mutex_unlock(&sc->rx_mtx);
	return (0);
}

#ifdef BHYVE_SNAPSHOT
#define	VTNET_SNAPSHOT_MAGIC	0x3154454eU	/* "NET1" on disk */
#define	VTNET_SNAPSHOT_VERSION	2U

static int
pci_vtnet_pause(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;
	int error;

	DPRINTF(("vtnet: device pause requested !\n"));

	/* Stop the shared TX/control worker before acquiring the RX lock. */
	pthread_mutex_lock(&sc->tx_mtx);
	sc->tx_control_pause = true;
	pthread_cond_signal(&sc->tx_cond);
	error = pci_vtnet_wait_tx_idle_locked(sc, NULL, true);
	if (error != 0) {
		sc->tx_control_pause = sc->vsc_vs.vs_suspended;
		pthread_cond_signal(&sc->tx_cond);
		pthread_mutex_unlock(&sc->tx_mtx);
		return (error);
	}
	pthread_mutex_unlock(&sc->tx_mtx);

	/*
	 * Snapshot callbacks retain both locks through serialization.  Reacquire
	 * them in the established rx-then-tx order after the worker is fenced.
	 */
	pthread_mutex_lock(&sc->rx_mtx);
	if (sc->vsc_be != NULL)
		netbe_rx_disable(sc->vsc_be);
	pthread_mutex_lock(&sc->tx_mtx);
	return (0);
}

static int
pci_vtnet_resume(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device resume requested !\n"));

	/*
	 * Checkpoint ownership is independent of guest-visible suspend.  A
	 * checkpoint taken while the guest has suspended this device still
	 * acquires these locks to serialize staged host state, but releasing the
	 * checkpoint must not restart TX until the guest explicitly resumes.
	 */
	sc->tx_control_pause = sc->vsc_vs.vs_suspended;
	pthread_mutex_unlock(&sc->tx_mtx);
	/* The RX lock should have been acquired in vtnet_pause. */
	pthread_mutex_unlock(&sc->rx_mtx);
	return (0);
}

struct pci_vtnet_snapshot_backup {
	struct virtio_net_config config;
	uint64_t features;
	uint64_t flow_map[VTNET_FLOW_ENTRIES];
	size_t vhdrlen;
	size_t be_vhdrlen;
	size_t rx_staged_len;
	uint32_t rss_hash_types;
	int rx_merge;
	uint16_t tx_active_pairs;
	uint16_t tx_next_pair;
	uint16_t rx_active_pairs;
	uint16_t rx_enabled_mask;
	uint16_t rss_indirection_mask;
	uint16_t rss_unclassified_queue;
	uint16_t rss_indirection_table[VTNET_RSS_TABLE_SIZE];
	uint16_t rss_max_tx_vq;
	uint8_t rss_key_length;
	uint8_t rss_key[VTNET_RSS_KEY_SIZE];
	uint8_t rx_buf[VTNET_MAX_PKT_LEN + sizeof(struct virtio_net_rxhdr) +
	    sizeof(struct virtio_net_hash_report)];
	bool features_negotiated;
	bool tx_features_negotiated;
	bool tx_control_pause;
	bool rss_enabled;
	bool hash_configured;
	struct vqueue_info *tx_current_vq;
};

static void
pci_vtnet_snapshot_backup(struct pci_vtnet_softc *sc,
    struct pci_vtnet_snapshot_backup *backup)
{

	backup->config = sc->vsc_config;
	backup->features = sc->vsc_features;
	memcpy(backup->flow_map, sc->vsc_flow_map, sizeof(backup->flow_map));
	backup->vhdrlen = sc->vhdrlen;
	backup->be_vhdrlen = sc->be_vhdrlen;
	backup->rx_staged_len = sc->rx_staged_len;
	backup->rss_hash_types = sc->rss_hash_types;
	backup->rx_merge = sc->rx_merge;
	backup->tx_active_pairs = sc->tx_active_pairs;
	backup->tx_next_pair = sc->tx_next_pair;
	backup->rx_active_pairs = sc->rx_active_pairs;
	backup->rx_enabled_mask = sc->rx_enabled_mask;
	backup->rss_indirection_mask = sc->rss_indirection_mask;
	backup->rss_unclassified_queue = sc->rss_unclassified_queue;
	memcpy(backup->rss_indirection_table, sc->rss_indirection_table,
	    sizeof(backup->rss_indirection_table));
	backup->rss_max_tx_vq = sc->rss_max_tx_vq;
	backup->rss_key_length = sc->rss_key_length;
	memcpy(backup->rss_key, sc->rss_key, sizeof(backup->rss_key));
	memcpy(backup->rx_buf, sc->vsc_rx_buf, sizeof(backup->rx_buf));
	backup->features_negotiated = sc->features_negotiated;
	backup->tx_features_negotiated = sc->tx_features_negotiated;
	backup->tx_control_pause = sc->tx_control_pause;
	backup->rss_enabled = sc->rss_enabled;
	backup->hash_configured = sc->hash_configured;
	backup->tx_current_vq = sc->tx_current_vq;
}

static void
pci_vtnet_snapshot_restore_backup(struct pci_vtnet_softc *sc,
    const struct pci_vtnet_snapshot_backup *backup)
{

	sc->vsc_config = backup->config;
	sc->vsc_features = backup->features;
	memcpy(sc->vsc_flow_map, backup->flow_map, sizeof(sc->vsc_flow_map));
	sc->vhdrlen = backup->vhdrlen;
	sc->be_vhdrlen = backup->be_vhdrlen;
	sc->rx_staged_len = backup->rx_staged_len;
	sc->rss_hash_types = backup->rss_hash_types;
	sc->rx_merge = backup->rx_merge;
	sc->tx_active_pairs = backup->tx_active_pairs;
	sc->tx_next_pair = backup->tx_next_pair;
	sc->rx_active_pairs = backup->rx_active_pairs;
	sc->rx_enabled_mask = backup->rx_enabled_mask;
	sc->rss_indirection_mask = backup->rss_indirection_mask;
	sc->rss_unclassified_queue = backup->rss_unclassified_queue;
	memcpy(sc->rss_indirection_table, backup->rss_indirection_table,
	    sizeof(sc->rss_indirection_table));
	sc->rss_max_tx_vq = backup->rss_max_tx_vq;
	sc->rss_key_length = backup->rss_key_length;
	memcpy(sc->rss_key, backup->rss_key, sizeof(sc->rss_key));
	memcpy(sc->vsc_rx_buf, backup->rx_buf, sizeof(sc->vsc_rx_buf));
	sc->features_negotiated = backup->features_negotiated;
	sc->tx_features_negotiated = backup->tx_features_negotiated;
	sc->tx_control_pause = backup->tx_control_pause;
	sc->rss_enabled = backup->rss_enabled;
	sc->hash_configured = backup->hash_configured;
	sc->tx_current_vq = backup->tx_current_vq;
}

static int
pci_vtnet_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	int ret;
	struct iovec frame_iov;
	struct virtio_net_rxhdr hdr;
	struct pci_vtnet_softc *sc = vsc;
	struct pci_vtnet_snapshot_backup *backup;
	struct virtio_net_config config, destination_config;
	uint8_t features_negotiated, hash_configured, rss_enabled;
	uint8_t rx_merge;
	bool backend_touched;
	uint32_t be_vhdrlen, magic, rx_staged_len, version, vhdrlen;

	DPRINTF(("vtnet: device snapshot requested !\n"));
	backup = NULL;
	backend_touched = false;
	if (vm_snapshot_is_loading(meta)) {
		backup = malloc(sizeof(*backup));
		if (backup == NULL)
			return (ENOMEM);
		pci_vtnet_snapshot_backup(sc, backup);
	}

	/*
	 * Queues and consts should have been saved by the more generic
	 * vi_pci_snapshot function. We need to save only our features and
	 * config.
	 */

	magic = VTNET_SNAPSHOT_MAGIC;
	version = VTNET_SNAPSHOT_VERSION;
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (magic != VTNET_SNAPSHOT_MAGIC ||
	    version != VTNET_SNAPSHOT_VERSION) {
		ret = ENOTSUP;
		goto done;
	}
	ret = vm_snapshot_identity_string(
	    netbe_checkpoint_identity(sc->vsc_be),
	    NETBE_CHECKPOINT_ID_MAX, meta);
	if (ret != 0)
		goto done;
	SNAPSHOT_LE64_OR_LEAVE(sc->vsc_features, meta, ret, done);
	features_negotiated = sc->features_negotiated;
	SNAPSHOT_U8_OR_LEAVE(features_negotiated, meta, ret, done);

	/*
	 * Deserialize into a temporary object.  Validation must precede
	 * publication: a rejected image must not leave a partially replaced
	 * device configuration behind.
	 */
	destination_config = sc->vsc_config;
	config = destination_config;
	/*
	 * This packed configuration is the exact guest-visible byte string.
	 * Its multibyte fields were encoded for the selected transport before
	 * checkpoint and therefore remain portable as bytes.
	 */
	SNAPSHOT_BUF_OR_LEAVE(&config, sizeof(config), meta, ret, done);
	if (vm_snapshot_is_loading(meta) &&
	    !pci_vtnet_restore_config_valid(sc, &config,
	    &destination_config)) {
		ret = EINVAL;
		goto done;
	}
	sc->vsc_config = config;
	rx_merge = (uint8_t)sc->rx_merge;
	SNAPSHOT_U8_OR_LEAVE(rx_merge, meta, ret, done);
	vhdrlen = (uint32_t)sc->vhdrlen;
	be_vhdrlen = (uint32_t)sc->be_vhdrlen;
	SNAPSHOT_LE32_OR_LEAVE(vhdrlen, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(be_vhdrlen, meta, ret, done);
	sc->vhdrlen = vhdrlen;
	sc->be_vhdrlen = be_vhdrlen;
	SNAPSHOT_LE16_OR_LEAVE(sc->rx_active_pairs, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(sc->rx_enabled_mask, meta, ret, done);
	rss_enabled = sc->rss_enabled;
	hash_configured = sc->hash_configured;
	SNAPSHOT_U8_OR_LEAVE(rss_enabled, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(hash_configured, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(sc->rss_hash_types, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(sc->rss_indirection_mask, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(sc->rss_unclassified_queue, meta, ret, done);
	for (size_t i = 0; i < nitems(sc->rss_indirection_table); i++)
		SNAPSHOT_LE16_OR_LEAVE(sc->rss_indirection_table[i], meta, ret,
		    done);
	SNAPSHOT_LE16_OR_LEAVE(sc->rss_max_tx_vq, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(sc->rss_key_length, meta, ret, done);
	SNAPSHOT_BUF_OR_LEAVE(sc->rss_key, sizeof(sc->rss_key), meta, ret,
	    done);
	if (sc->rx_staged_len > UINT32_MAX) {
		ret = EOVERFLOW;
		goto done;
	}
	rx_staged_len = (uint32_t)sc->rx_staged_len;
	SNAPSHOT_LE32_OR_LEAVE(rx_staged_len, meta, ret, done);
	sc->rx_staged_len = rx_staged_len;
	if (sc->rx_staged_len > sizeof(sc->vsc_rx_buf)) {
		ret = EINVAL;
		goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(sc->vsc_rx_buf, sc->rx_staged_len, meta, ret,
	    done);

	/*
	 * Force reapplication only after all saved fields have been consumed.
	 * The pause callback already owns rx_mtx and tx_mtx here, so use the
	 * locked helper rather than recursively acquiring either mutex.  This
	 * also overwrites the saved derived header fields with values verified
	 * against the current backend.
	 */
	if (vm_snapshot_is_loading(meta)) {
		uint16_t valid_mask;
		size_t expected_backend_vhdrlen, expected_vhdrlen;

		if (features_negotiated > 1 || rx_merge > 1 ||
		    rss_enabled > 1 || hash_configured > 1) {
			ret = EINVAL;
			goto done;
		}
		sc->features_negotiated = features_negotiated;
		sc->rx_merge = rx_merge;
		sc->rss_enabled = rss_enabled;
		sc->hash_configured = hash_configured;
		expected_vhdrlen = pci_vtnet_header_len(sc,
		    sc->vsc_features);
		expected_backend_vhdrlen =
		    sc->vsc_be != NULL &&
		    (sc->vsc_features & VTNET_BACKEND_CAPS) != 0 ?
		    pci_vtnet_header_len(sc, sc->vsc_features &
		    ~VIRTIO_NET_F_HASH_REPORT) : 0;
		valid_mask = (1U << sc->vsc_max_pairs) - 1;
		/*
		 * vsc_features is a device-private cache of the generic transport
		 * value.  Accepting two different saved values would make queue and
		 * header interpretation disagree with the features visible to the
		 * driver after restore.
		 */
		if (sc->vsc_features != sc->vsc_vs.vs_negotiated_caps ||
		    sc->vhdrlen != expected_vhdrlen ||
		    sc->be_vhdrlen != expected_backend_vhdrlen ||
		    sc->rx_merge !=
		    ((sc->vsc_features & VIRTIO_NET_F_MRG_RXBUF) != 0) ||
		    sc->rx_enabled_mask == 0 ||
		    (sc->rx_enabled_mask & ~valid_mask) != 0 ||
		    (sc->hash_configured &&
		    (!sc->features_negotiated ||
		    (sc->vsc_features & (VIRTIO_NET_F_CTRL_VQ |
		    VIRTIO_NET_F_HASH_REPORT)) !=
		    (VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_HASH_REPORT) ||
		    (sc->rss_hash_types & ~VTNET_RSS_HASH_TYPES) != 0 ||
		    sc->rss_key_length > VTNET_RSS_KEY_SIZE)) ||
		    (sc->rss_enabled &&
		    (!sc->features_negotiated ||
		    (sc->vsc_features & (VIRTIO_NET_F_CTRL_VQ |
		    VIRTIO_NET_F_RSS)) !=
		    (VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_RSS) ||
		    sc->rx_active_pairs != 0 ||
		    (sc->rss_hash_types & ~VTNET_RSS_HASH_TYPES) != 0 ||
		    sc->rss_indirection_mask >= VTNET_RSS_TABLE_SIZE ||
		    !powerof2((size_t)sc->rss_indirection_mask + 1) ||
		    sc->rss_unclassified_queue >= sc->vsc_max_pairs ||
		    !pci_vtnet_rxq_enabled(sc,
		    sc->rss_unclassified_queue) ||
		    sc->rss_max_tx_vq < 1 ||
		    sc->rss_max_tx_vq > sc->vsc_max_pairs ||
		    sc->rss_key_length > VTNET_RSS_KEY_SIZE ||
		    ((sc->vsc_features & VIRTIO_NET_F_HASH_REPORT) != 0 &&
		    !sc->hash_configured))) ||
		    (!sc->rss_enabled &&
		    (sc->rx_active_pairs < 1 ||
		    sc->rx_active_pairs > sc->vsc_max_pairs ||
		    sc->rx_enabled_mask !=
		    (uint16_t)((1U << sc->rx_active_pairs) - 1) ||
		    (sc->rx_active_pairs > 1 &&
		    (!sc->features_negotiated ||
		    (sc->vsc_features & (VIRTIO_NET_F_CTRL_VQ |
		    VIRTIO_NET_F_MQ)) !=
		    (VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_MQ)))))) {
			ret = EINVAL;
			goto done;
		}
		if (sc->rss_enabled) {
			uint16_t enabled_mask;

			enabled_mask = 1U << sc->rss_unclassified_queue;
			for (size_t i = 0;
			    i <= sc->rss_indirection_mask; i++) {
				if (!pci_vtnet_rxq_enabled(sc,
				    sc->rss_indirection_table[i])) {
					ret = EINVAL;
					goto done;
				}
				enabled_mask |=
				    1U << sc->rss_indirection_table[i];
			}
			if (enabled_mask != sc->rx_enabled_mask) {
				ret = EINVAL;
				goto done;
			}
		}
		sc->tx_active_pairs = sc->rss_enabled ?
		    sc->rss_max_tx_vq : sc->rx_active_pairs;
		sc->tx_next_pair = 0;
		sc->tx_current_vq = NULL;
		/*
		 * Common VirtIO state is restored before this device-private record.
		 * Preserve a restored guest suspend through the entire transaction,
		 * rather than opening the TX-admission latch until the later generic
		 * resume callback happens to close it again.  The checkpoint locks are
		 * held here, but keeping this invariant local also makes an early
		 * restore failure and future callback ordering safe by construction.
		 */
		sc->tx_control_pause = sc->vsc_vs.vs_suspended;
		memset(sc->vsc_flow_map, 0, sizeof(sc->vsc_flow_map));
		if (sc->features_negotiated &&
		    vm_snapshot_is_restoring(meta)) {
			backend_touched = true;
			if (!pci_vtnet_apply_features(sc, sc->vsc_features)) {
				ret = EINVAL;
				goto done;
			}
		} else if (!sc->features_negotiated &&
		    vm_snapshot_is_restoring(meta))
			sc->tx_features_negotiated = false;

		/*
		 * A staged packet is device state, not opaque snapshot data.
		 * Validate it against the restored feature-dependent header
		 * format before allowing the backend to resume delivery.
		 */
		if (sc->rx_staged_len != 0) {
			struct virtio_net_hash_report hash_hdr;

			if (!sc->features_negotiated ||
			    sc->rx_staged_len < sc->vhdrlen ||
			    sc->rx_staged_len >
			    VTNET_MAX_PKT_LEN + sc->vhdrlen) {
				ret = EINVAL;
				goto done;
			}
			memset(&hdr, 0, sizeof(hdr));
			memcpy(&hdr, sc->vsc_rx_buf,
			    MIN(sc->vhdrlen, sizeof(hdr)));
			if (!pci_vtnet_rx_header_valid(sc, &hdr,
			    sc->rx_staged_len - sc->vhdrlen)) {
				ret = EINVAL;
				goto done;
			}
			if ((sc->vsc_features &
			    VIRTIO_NET_F_HASH_REPORT) != 0) {
				memcpy(&hash_hdr, sc->vsc_rx_buf + sizeof(hdr),
				    sizeof(hash_hdr));
				if (le16toh(hash_hdr.hash_report) >
				    VTNET_HASH_REPORT_UDPV6 ||
				    hash_hdr.padding != 0 ||
				    (hash_hdr.hash_report ==
				    htole16(VTNET_HASH_REPORT_NONE) &&
				    hash_hdr.hash_value != 0)) {
					ret = EINVAL;
					goto done;
				}
			}
			frame_iov.iov_base = sc->vsc_rx_buf;
			frame_iov.iov_len = sc->rx_staged_len;
			if (!pci_vtnet_frame_within_mtu(sc, &frame_iov, 1,
			    sc->vhdrlen, sc->rx_staged_len,
			    hdr.vrh_gso_type)) {
				ret = EINVAL;
				goto done;
			}
		}
	}

done:
	if (vm_snapshot_is_loading(meta) &&
	    (ret != 0 || meta->op == VM_SNAPSHOT_VALIDATE)) {
		/*
		 * Parsing is transactional.  If feature application reached the
		 * external backend, restore its previous framing contract before
		 * publishing the destination's original in-memory state.
		 */
		if (backend_touched && sc->vsc_be != NULL) {
			uint64_t backend_features;
			size_t backend_vhdrlen;

			backend_features = backup->features_negotiated ?
			    backup->features & VTNET_BACKEND_CAPS : 0;
			backend_vhdrlen = backup->features_negotiated ?
			    backup->be_vhdrlen : 0;
			if (netbe_set_cap(sc->vsc_be, backend_features,
			    backend_vhdrlen) != 0) {
				vi_snapshot_restore_incomplete(&sc->vsc_vs);
				ret = EIO;
			}
		}
		pci_vtnet_snapshot_restore_backup(sc, backup);
	}
	free(backup);
	return (ret);
}

/*
 * Restore preflight is backend-side-effect free, but its private codec reads
 * receive staging and TX/control state that independent backend and worker
 * callbacks update.  Checkpoint pause retains rx_mtx followed by tx_mtx
 * through serialization; direct preflight takes that same pair locally.
 *
 * Partial ownership is not a valid snapshot boundary.  Acquiring the missing
 * mutex would invert the established order or serialize only half the record,
 * so reject it without stopping or starting the backend.
 */
static int
pci_vtnet_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtnet_softc *sc;
	bool rx_owned, tx_owned;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);
	rx_owned = pthread_mutex_isowned_np(&sc->rx_mtx);
	tx_owned = pthread_mutex_isowned_np(&sc->tx_mtx);
	if (rx_owned != tx_owned)
		return (EBUSY);
	if (!rx_owned) {
		pthread_mutex_lock(&sc->rx_mtx);
		pthread_mutex_lock(&sc->tx_mtx);
	}
	error = vi_pci_snapshot(meta);
	if (!rx_owned) {
		pthread_mutex_unlock(&sc->tx_mtx);
		pthread_mutex_unlock(&sc->rx_mtx);
	}
	return (error);
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
	.pe_snapshot_validate = pci_vtnet_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause =	vi_pci_pause,
	.pe_resume =	vi_pci_resume,
	/* Common VirtIO DMA leases plus the net backend drain fence. */
	.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS,
#endif
};
PCI_EMUL_SET(pci_de_vnet);

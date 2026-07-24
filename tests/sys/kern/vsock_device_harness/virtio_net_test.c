/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO network device.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"
#include "pci_virtio_net.c"

/*
 * Compile the DUT first, then make all test-side protocol stimuli and
 * expectations resolve to the independent VirtIO 1.4 oracle.
 */
#undef VIRTIO_NET_F_CSUM
#define	VIRTIO_NET_F_CSUM		VIRTIO14_NET_F_CSUM
#undef VIRTIO_NET_F_GUEST_CSUM
#define	VIRTIO_NET_F_GUEST_CSUM		VIRTIO14_NET_F_GUEST_CSUM
#undef VIRTIO_NET_F_MTU
#define	VIRTIO_NET_F_MTU		VIRTIO14_NET_F_MTU
#undef VIRTIO_NET_F_MAC
#define	VIRTIO_NET_F_MAC		VIRTIO14_NET_F_MAC
#undef VIRTIO_NET_F_GUEST_TSO4
#define	VIRTIO_NET_F_GUEST_TSO4	VIRTIO14_NET_F_GUEST_TSO4
#undef VIRTIO_NET_F_GUEST_TSO6
#define	VIRTIO_NET_F_GUEST_TSO6	VIRTIO14_NET_F_GUEST_TSO6
#undef VIRTIO_NET_F_GUEST_ECN
#define	VIRTIO_NET_F_GUEST_ECN		VIRTIO14_NET_F_GUEST_ECN
#undef VIRTIO_NET_F_GUEST_UFO
#define	VIRTIO_NET_F_GUEST_UFO		VIRTIO14_NET_F_GUEST_UFO
#undef VIRTIO_NET_F_HOST_TSO4
#define	VIRTIO_NET_F_HOST_TSO4		VIRTIO14_NET_F_HOST_TSO4
#undef VIRTIO_NET_F_HOST_TSO6
#define	VIRTIO_NET_F_HOST_TSO6		VIRTIO14_NET_F_HOST_TSO6
#undef VIRTIO_NET_F_HOST_ECN
#define	VIRTIO_NET_F_HOST_ECN		VIRTIO14_NET_F_HOST_ECN
#undef VIRTIO_NET_F_HOST_UFO
#define	VIRTIO_NET_F_HOST_UFO		VIRTIO14_NET_F_HOST_UFO
#undef VIRTIO_NET_F_MRG_RXBUF
#define	VIRTIO_NET_F_MRG_RXBUF		VIRTIO14_NET_F_MRG_RXBUF
#undef VIRTIO_NET_F_STATUS
#define	VIRTIO_NET_F_STATUS		VIRTIO14_NET_F_STATUS
#undef VIRTIO_NET_F_CTRL_VQ
#define	VIRTIO_NET_F_CTRL_VQ		VIRTIO14_NET_F_CTRL_VQ
#undef VIRTIO_NET_F_MQ
#define	VIRTIO_NET_F_MQ		VIRTIO14_NET_F_MQ
#undef VIRTIO_NET_F_RSS
#define	VIRTIO_NET_F_RSS		VIRTIO14_NET_F_RSS
#undef VTNET_HDR_F_NEEDS_CSUM
#define	VTNET_HDR_F_NEEDS_CSUM		VIRTIO14_NET_HDR_F_NEEDS_CSUM
#undef VTNET_HDR_F_DATA_VALID
#define	VTNET_HDR_F_DATA_VALID		VIRTIO14_NET_HDR_F_DATA_VALID
#undef VTNET_HDR_F_UDP_TUNNEL_CSUM
#define	VTNET_HDR_F_UDP_TUNNEL_CSUM \
	VIRTIO14_NET_HDR_F_UDP_TUNNEL_CSUM
#undef VTNET_HDR_GSO_NONE
#define	VTNET_HDR_GSO_NONE		VIRTIO14_NET_HDR_GSO_NONE
#undef VTNET_HDR_GSO_TCPV4
#define	VTNET_HDR_GSO_TCPV4		VIRTIO14_NET_HDR_GSO_TCPV4
#undef VTNET_HDR_GSO_UDP
#define	VTNET_HDR_GSO_UDP		VIRTIO14_NET_HDR_GSO_UDP
#undef VTNET_HDR_GSO_TCPV6
#define	VTNET_HDR_GSO_TCPV6		VIRTIO14_NET_HDR_GSO_TCPV6
#undef VTNET_HDR_GSO_ECN
#define	VTNET_HDR_GSO_ECN		VIRTIO14_NET_HDR_GSO_ECN
#undef VTNET_HDR_GSO_TUNNEL_IPV4
#define	VTNET_HDR_GSO_TUNNEL_IPV4	VIRTIO14_NET_HDR_GSO_TUNNEL_IPV4
#undef VTNET_HDR_GSO_TUNNEL_IPV6
#define	VTNET_HDR_GSO_TUNNEL_IPV6	VIRTIO14_NET_HDR_GSO_TUNNEL_IPV6
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_F_NOTIFICATION_DATA
#define	VIRTIO_F_NOTIFICATION_DATA	VIRTIO14_F_NOTIFICATION_DATA
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_F_VERSION_1
#define	VIRTIO_F_VERSION_1		VIRTIO14_F_VERSION_1
#undef VIRTIO_RING_F_EVENT_IDX
#define	VIRTIO_RING_F_EVENT_IDX		VIRTIO14_F_RING_EVENT_IDX
#undef VTNET_RXQ
#define	VTNET_RXQ			VIRTIO14_NET_RECEIVEQ
#undef VTNET_TXQ
#define	VTNET_TXQ			VIRTIO14_NET_TRANSMITQ
#undef VTNET_CTLQ
#define	VTNET_CTLQ			VIRTIO14_NET_CONTROLQ

struct net_backend {
	int unused;
};

struct mock_chain {
	int n;
	struct vi_req req;
	struct iovec iov[4];
};

static struct mock_chain g_chains[4];
static struct net_backend g_backend;
static int g_chain_count;
static int g_chain_next;
static int g_getchain_calls;
static ssize_t g_peek_len;
static ssize_t g_recv_result;
static ssize_t g_send_result;
static int g_recv_calls;
static int g_discard_calls;
static int g_send_calls;
static size_t g_send_bytes;
static struct virtio_net_rxhdr g_send_header;
static bool g_send_header_valid;
static int g_rel_calls;
static uint16_t g_rel_idx[8];
static uint32_t g_rel_len[8];
static int g_prepare_calls;
static uint16_t g_prepare_idx[8];
static uint32_t g_prepare_len[8];
static int g_publish_calls;
static int g_rx_disable_calls;
static int g_rx_enable_calls;
static int g_reset_calls;
static int g_set_cap_calls;
static int g_set_cap_result;
static int g_needs_reset_calls;
static size_t g_backend_header_len;
static uint64_t g_set_cap_features;
static unsigned int g_set_cap_header_len;
static bool g_preserve_backend_header_len;
static bool g_hide_next_getchain;
static bool g_hide_next_has_desc;
static uint8_t g_packet[128];
static uint8_t g_backend_packet[NETBE_MAX_RECORD_SIZE];
static uint64_t g_used_storage[16];
#define	g_used	(*(struct vring_used *)(void *)g_used_storage)

size_t
count_iov(const struct iovec *iov, size_t niov)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

size_t
buf_to_iov(const void *buf, size_t buflen, const struct iovec *iov,
    size_t niov)
{
	const uint8_t *src;
	size_t copy, written;

	src = buf;
	written = 0;
	for (size_t i = 0; i < niov && written < buflen; i++) {
		copy = MIN(iov[i].iov_len, buflen - written);
		memcpy(iov[i].iov_base, src + written, copy);
		written += copy;
	}
	return (written);
}

static void
reset_mocks(void)
{

	memset(g_chains, 0, sizeof(g_chains));
	memset(g_packet, 0, sizeof(g_packet));
	memset(g_backend_packet, 0, sizeof(g_backend_packet));
	memset(g_used_storage, 0, sizeof(g_used_storage));
	g_chain_count = 0;
	g_chain_next = 0;
	g_getchain_calls = 0;
	g_peek_len = 0;
	g_recv_result = 0;
	g_send_result = 0;
	g_recv_calls = 0;
	g_discard_calls = 0;
	g_send_calls = 0;
	g_send_bytes = 0;
	memset(&g_send_header, 0, sizeof(g_send_header));
	g_send_header_valid = false;
	g_rel_calls = 0;
	g_prepare_calls = 0;
	g_publish_calls = 0;
	g_rx_disable_calls = 0;
	g_rx_enable_calls = 0;
	g_reset_calls = 0;
	g_set_cap_calls = 0;
	g_set_cap_result = 0;
	g_needs_reset_calls = 0;
	g_backend_header_len = VIRTIO14_NET_MODERN_HDR_SIZE;
	g_set_cap_features = 0;
	g_set_cap_header_len = 0;
	g_preserve_backend_header_len = false;
	g_hide_next_getchain = false;
	g_hide_next_has_desc = false;
}

static void
setup_softc(struct pci_vtnet_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
	sc->vsc_be = &g_backend;
	sc->features_negotiated = true;
	sc->tx_features_negotiated = true;
	sc->vsc_consts = vtnet_vi_consts;
	sc->vsc_max_pairs = 1;
	sc->rx_active_pairs = 1;
	sc->rx_enabled_mask = 1;
	sc->tx_active_pairs = 1;
	sc->vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc->vsc_queues[VTNET_RXQ].vq_vs = &sc->vsc_vs;
	sc->vsc_queues[VTNET_RXQ].vq_num = VTNET_RXQ;
	vq_set_allocated(&sc->vsc_queues[VTNET_RXQ], true);
	sc->vsc_queues[VTNET_RXQ].vq_used = &g_used;
	sc->vsc_queues[VTNET_TXQ].vq_vs = &sc->vsc_vs;
	sc->vsc_queues[VTNET_TXQ].vq_num = VTNET_TXQ;
	vq_set_allocated(&sc->vsc_queues[VTNET_TXQ], true);
	sc->vsc_queues[VTNET_TXQ].vq_used = &g_used;
}

static void
setup_multiqueue_softc(struct pci_vtnet_softc *sc, uint16_t pairs)
{

	setup_softc(sc);
	ATF_REQUIRE(pairs >= 2 && pairs <= VTNET_MAX_PAIRS);
	sc->vsc_max_pairs = pairs;
	sc->vsc_consts.vc_nvq = pairs * 2 + 1;
	sc->vsc_config.max_virtqueue_pairs = pairs;
	sc->vsc_features = VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_NET_F_MQ;
	for (uint16_t i = 0; i < pairs; i++) {
		struct vqueue_info *rxq, *txq;

		rxq = &sc->vsc_queues[VIRTIO14_NET_RXQ(i)];
		txq = &sc->vsc_queues[VIRTIO14_NET_TXQ(i)];
		rxq->vq_vs = &sc->vsc_vs;
		rxq->vq_num = VIRTIO14_NET_RXQ(i);
		rxq->vq_qsize = VTNET_RINGSZ;
		rxq->vq_used = &g_used;
		vq_set_allocated(rxq, true);
		txq->vq_vs = &sc->vsc_vs;
		txq->vq_num = VIRTIO14_NET_TXQ(i);
		txq->vq_qsize = VTNET_RINGSZ;
		txq->vq_used = &g_used;
		vq_set_allocated(txq, true);
	}
	sc->vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(pairs)].vq_vs =
	    &sc->vsc_vs;
	sc->vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(pairs)].vq_num =
	    VIRTIO14_NET_MQ_CONTROLQ(pairs);
	sc->vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(pairs)].vq_qsize =
	    VTNET_RINGSZ;
	sc->vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(pairs)].vq_used = &g_used;
	vq_set_allocated(
	    &sc->vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(pairs)], true);
	ATF_REQUIRE(pthread_mutex_init(&sc->rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc->tx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc->tx_cond, NULL) == 0);
}

static void
destroy_multiqueue_softc(struct pci_vtnet_softc *sc)
{

	ATF_REQUIRE(pthread_cond_destroy(&sc->tx_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc->tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc->rx_mtx) == 0);
}

static void
add_chain(int n, int readable, int writable, bool ordered,
    void *base, size_t len)
{
	struct mock_chain *chain;

	ATF_REQUIRE(g_chain_count < (int)nitems(g_chains));
	chain = &g_chains[g_chain_count];
	chain->n = n;
	chain->req.idx = 10 + g_chain_count;
	chain->req.readable = readable;
	chain->req.writable = writable;
	chain->req.ordered = ordered;
	chain->iov[0].iov_base = base;
	chain->iov[0].iov_len = len;
	g_chain_count++;
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	if (g_hide_next_has_desc) {
		g_hide_next_has_desc = false;
		return (0);
	}
	return (g_chain_next < g_chain_count);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	struct mock_chain *chain;

	g_getchain_calls++;
	if (g_hide_next_getchain) {
		g_hide_next_getchain = false;
		return (0);
	}
	if (g_chain_next >= g_chain_count)
		return (0);
	chain = &g_chains[g_chain_next++];
	*req = chain->req;
	if (chain->n > 0)
		memcpy(iov, chain->iov,
		    MIN(chain->n, niov) * sizeof(chain->iov[0]));
	return (chain->n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	ATF_REQUIRE(g_rel_calls < (int)nitems(g_rel_idx));
	g_rel_idx[g_rel_calls] = idx;
	g_rel_len[g_rel_calls] = len;
	g_rel_calls++;
}

void
vq_relchain_prepare(struct vqueue_info *vq __unused, uint16_t idx,
    uint32_t len)
{

	ATF_REQUIRE(g_prepare_calls < (int)nitems(g_prepare_idx));
	g_prepare_idx[g_prepare_calls] = idx;
	g_prepare_len[g_prepare_calls] = len;
	g_prepare_calls++;
}

void
vq_relchain_publish(struct vqueue_info *vq __unused)
{

	g_publish_calls++;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count)
{

	ATF_REQUIRE(count <= g_chain_next);
	g_chain_next -= count;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{
}

ssize_t
netbe_peek_recvlen(net_backend_t *be __unused)
{

	return (g_peek_len);
}

ssize_t
netbe_recv(net_backend_t *be __unused, const struct iovec *iov, int niov)
{
	size_t len;

	g_recv_calls++;
	g_peek_len = 0;
	if (g_recv_result > 0) {
		len = MIN((size_t)g_recv_result, sizeof(g_backend_packet));
		(void)buf_to_iov(g_backend_packet, len, iov, niov);
	}
	return (g_recv_result);
}

ssize_t
netbe_rx_discard(net_backend_t *be __unused)
{
	ssize_t len;

	g_discard_calls++;
	len = g_peek_len;
	g_peek_len = 0;
	return (len);
}

ssize_t
netbe_send(net_backend_t *be __unused, const struct iovec *iov, int niov)
{

	g_send_calls++;
	g_send_bytes = count_iov(iov, niov);
	g_send_header_valid = pci_vtnet_iov_read(iov, niov, 0,
	    &g_send_header, VIRTIO14_NET_MODERN_HDR_SIZE);
	return (g_send_result);
}

void
netbe_rx_disable(net_backend_t *be __unused)
{
	g_rx_disable_calls++;
}
void
netbe_rx_enable(net_backend_t *be __unused)
{
	g_rx_enable_calls++;
}

int
netbe_set_cap(net_backend_t *be __unused, uint64_t features,
    unsigned int header_len)
{

	g_set_cap_calls++;
	g_set_cap_features = features;
	g_set_cap_header_len = header_len;
	if (g_set_cap_result == 0 && !g_preserve_backend_header_len)
		g_backend_header_len = header_len;
	return (g_set_cap_result);
}

size_t
netbe_get_vnet_hdr_len(net_backend_t *be __unused)
{

	return (g_backend_header_len);
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	g_needs_reset_calls++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
	g_reset_calls++;
}

ATF_TC_WITHOUT_HEAD(transmit_validation);
ATF_TC_BODY(transmit_validation, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	reset_mocks();
	setup_softc(&sc);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	g_send_result = sizeof(g_packet) - sc.vhdrlen;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK(g_send_bytes == sizeof(g_packet) - sc.vhdrlen);
	ATF_CHECK(g_rel_len[0] == 0);

	reset_mocks();
	setup_softc(&sc);
	add_chain(1, 1, 0, true, g_packet, sc.vhdrlen);
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_rel_len[0] == 0);
}

ATF_TC_WITHOUT_HEAD(transmit_consumes_one_chain);
ATF_TC_BODY(transmit_consumes_one_chain, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t first[VIRTIO14_NET_MODERN_HDR_SIZE + 1] = { 0 };
	uint8_t second[VIRTIO14_NET_MODERN_HDR_SIZE + 1] = { 0 };

	/*
	 * Split-ring processing (section 2.7.8) consumes one available head
	 * for one used-buffer entry.  Give the implementation two independent
	 * heads and invoke the single-chain worker once; this catches an
	 * accidental extra dequeue without deriving the expected count or
	 * indices from the implementation.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_send_result = 1;
	add_chain(1, 1, 0, true, first, sizeof(first));
	add_chain(1, 1, 0, true, second, sizeof(second));

	pci_vtnet_proctx(&sc, &sc.vsc_queues[VIRTIO14_NET_TRANSMITQ]);

	ATF_CHECK_EQ(g_getchain_calls, 1);
	ATF_CHECK_EQ(g_chain_next, 1);
	ATF_CHECK_EQ(g_send_calls, 1);
	ATF_REQUIRE_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_idx[0], 10);
	ATF_CHECK_EQ(g_rel_len[0], 0);
}

ATF_TC_WITHOUT_HEAD(receive_validation);
ATF_TC_BODY(receive_validation, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(-1, 0, 0, true, NULL, 0);
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_chain_next == 1);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_rel_calls == 0);

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(1, 0, 1, true, g_packet, sc.vhdrlen + 8);
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	reset_mocks();
	setup_softc(&sc);
	sc.rx_merge = 1;
	g_peek_len = 64;
	g_recv_result = 64;
	add_chain(1, 0, 1, true, g_packet, (size_t)UINT32_MAX + 1);
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_recv_calls == 1);
	ATF_CHECK(g_prepare_calls == 1);
	ATF_CHECK(g_prepare_len[0] ==
	    64 + VIRTIO14_NET_MODERN_HDR_SIZE);
	ATF_CHECK(g_publish_calls == 1);
	ATF_CHECK(((struct virtio_net_rxhdr *)g_packet)->vrh_bufs == 1);
}

ATF_TC_WITHOUT_HEAD(receive_length_bounds);
ATF_TC_BODY(receive_length_bounds, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t *record;

	/*
	 * Backend framing is derived from negotiated features.  If that
	 * invariant is ever broken, RX must stop and request recovery rather
	 * than underflowing the unsigned header-length subtraction.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.be_vhdrlen = sc.vhdrlen + 1;
	g_peek_len = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK_EQ(g_rx_disable_calls, 1);
	ATF_CHECK_EQ(g_chain_next, 0);
	ATF_CHECK_EQ(g_recv_calls, 0);

	/*
	 * A nonzero backend header must match the negotiated guest header
	 * exactly.  In particular, a stale 10-byte legacy header cannot be
	 * treated as a headerless backend packet for a modern 12-byte device.
	 * Both sizes below come directly from 5.1.6, not from DUT layouts.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
	sc.be_vhdrlen = VIRTIO14_NET_LEGACY_HDR_SIZE;
	g_peek_len = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK_EQ(g_rx_disable_calls, 1);
	ATF_CHECK_EQ(g_chain_next, 0);
	ATF_CHECK_EQ(g_recv_calls, 0);

	/*
	 * The standard's largest advertised MTU still fits the device's
	 * bounded packet buffer.  A backend record beyond that bound is
	 * consumed and dropped without touching guest descriptors.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_peek_len = (ssize_t)VIRTIO14_NET_MTU_MAX + 66;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_chain_next, 0);
	ATF_CHECK_EQ(g_recv_calls, 0);

	/*
	 * Section 5.1.9.3 permits a 65,589-byte incoming GSO packet.
	 * When a backend includes the document's 12-byte base header, the
	 * resulting 65,601-byte record is valid rather than oversized.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_CHECK_EQ(VTNET_MAX_PKT_LEN,
	    VIRTIO14_NET_MAX_GSO_PACKET_SIZE);
	ATF_CHECK_EQ(VTNET_MAX_PKT_LEN + VIRTIO14_NET_MODERN_HDR_SIZE,
	    VIRTIO14_NET_MAX_BASE_RECORD_SIZE);
	record = calloc(1, VIRTIO14_NET_MAX_BASE_RECORD_SIZE);
	ATF_REQUIRE(record != NULL);
	sc.be_vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
	g_peek_len = VIRTIO14_NET_MAX_BASE_RECORD_SIZE;
	g_recv_result = VIRTIO14_NET_MAX_BASE_RECORD_SIZE;
	add_chain(1, 0, 1, true, record,
	    VIRTIO14_NET_MAX_BASE_RECORD_SIZE);
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_NET_MAX_BASE_RECORD_SIZE);
	free(record);
}

ATF_TC_WITHOUT_HEAD(receive_header_layout);
ATF_TC_BODY(receive_header_layout, tc)
{
	struct pci_vtnet_softc sc;
	struct virtio_net_rxhdr *hdr;

	ATF_CHECK_EQ(sizeof(struct virtio_net_rxhdr),
	    VIRTIO14_NET_MODERN_HDR_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_flags),
	    VIRTIO14_NET_HDR_FLAGS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_gso_type),
	    VIRTIO14_NET_HDR_GSO_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_hdr_len),
	    VIRTIO14_NET_HDR_HDR_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_gso_size),
	    VIRTIO14_NET_HDR_GSO_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_csum_start),
	    VIRTIO14_NET_HDR_CSUM_START_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_csum_offset),
	    VIRTIO14_NET_HDR_CSUM_OFFSET_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_rxhdr, vrh_bufs),
	    VIRTIO14_NET_HDR_NUM_BUFFERS_OFF);
	ATF_CHECK_EQ(sizeof(struct virtio_net_config),
	    VIRTIO14_NET_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, mac),
	    VIRTIO14_NET_CONFIG_MAC_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, status),
	    VIRTIO14_NET_CONFIG_STATUS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, max_virtqueue_pairs),
	    VIRTIO14_NET_CONFIG_MAX_PAIRS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, mtu),
	    VIRTIO14_NET_CONFIG_MTU_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, speed),
	    VIRTIO14_NET_CONFIG_SPEED_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, duplex),
	    VIRTIO14_NET_CONFIG_DUPLEX_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, rss_max_key_size),
	    VIRTIO14_NET_CONFIG_RSS_KEY_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config,
	    rss_max_indirection_table_length),
	    VIRTIO14_NET_CONFIG_RSS_TABLE_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_net_config, supported_hash_types),
	    VIRTIO14_NET_CONFIG_HASH_TYPES_OFF);

	memset(&sc, 0, sizeof(sc));
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(pci_vtnet_header_len(&sc, 0),
	    VIRTIO14_NET_LEGACY_HDR_SIZE);
	ATF_CHECK_EQ(pci_vtnet_header_len(&sc, VIRTIO_NET_F_MRG_RXBUF),
	    VIRTIO14_NET_MODERN_HDR_SIZE);
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	ATF_CHECK_EQ(pci_vtnet_header_len(&sc, 0),
	    VIRTIO14_NET_MODERN_HDR_SIZE);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.rx_merge = 0;
	sc.vhdrlen = pci_vtnet_header_len(&sc, 0);
	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_NET_MODERN_HDR_SIZE + 60);
	ATF_CHECK_EQ(hdr->vrh_bufs, VIRTIO14_NET_SINGLE_BUFFER_COUNT);
}

ATF_TC_WITHOUT_HEAD(split_header_descriptors);
ATF_TC_BODY(split_header_descriptors, tc)
{
	struct pci_vtnet_softc sc;
	struct mock_chain *chain;
	uint16_t num_buffers;
	size_t header_len;

	/*
	 * Section 2.7 permits a device-specific header to span descriptor
	 * elements.  Exercise both directions with the split in the middle of
	 * the modern 12-byte virtio-net header.
	 */
	reset_mocks();
	setup_softc(&sc);
	header_len = sc.vhdrlen;
	chain = &g_chains[0];
	chain->n = 3;
	chain->req.idx = 10;
	chain->req.readable = 3;
	chain->req.ordered = true;
	chain->iov[0] = (struct iovec){
		.iov_base = g_packet,
		.iov_len = 5,
	};
	chain->iov[1] = (struct iovec){
		.iov_base = g_packet + 5,
		.iov_len = header_len - 5,
	};
	chain->iov[2] = (struct iovec){
		.iov_base = g_packet + header_len,
		.iov_len = sizeof(g_packet) - header_len,
	};
	g_chain_count = 1;
	g_send_result = sizeof(g_packet) - header_len;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);
	ATF_CHECK_EQ(g_send_bytes, sizeof(g_packet) - header_len);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	setup_softc(&sc);
	memset(g_packet, 0xa5, sizeof(g_packet));
	chain = &g_chains[0];
	chain->n = 2;
	chain->req.idx = 10;
	chain->req.writable = 2;
	chain->req.ordered = true;
	chain->iov[0] = (struct iovec){
		.iov_base = g_packet,
		.iov_len = 5,
	};
	chain->iov[1] = (struct iovec){
		.iov_base = g_packet + 5,
		.iov_len = sizeof(g_packet) - 5,
	};
	g_chain_count = 1;
	g_peek_len = 60;
	g_recv_result = 60;
	pci_vtnet_rx(&sc);
	memcpy(&num_buffers,
	    g_packet + VIRTIO14_NET_HDR_NUM_BUFFERS_OFF,
	    sizeof(num_buffers));
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], header_len + 60);
	ATF_CHECK_EQ(le16toh(num_buffers),
	    VIRTIO14_NET_SINGLE_BUFFER_COUNT);
	for (size_t i = 0; i < VIRTIO14_NET_HDR_NUM_BUFFERS_OFF; i++)
		ATF_CHECK_EQ(g_packet[i], 0);
}

ATF_TC_WITHOUT_HEAD(receive_offload_metadata);
ATF_TC_BODY(receive_offload_metadata, tc)
{
	struct pci_vtnet_softc sc;
	struct virtio_net_rxhdr hdr;

	memset(&sc, 0, sizeof(sc));
	memset(&hdr, 0, sizeof(hdr));
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));

	hdr.vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr.vrh_csum_start = htole16(10);
	hdr.vrh_csum_offset = htole16(10);
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	sc.vsc_features = VIRTIO_NET_F_GUEST_CSUM;
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	hdr.vrh_csum_start = htole16(127);
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));

	memset(&hdr, 0, sizeof(hdr));
	hdr.vrh_flags = VTNET_HDR_F_DATA_VALID;
	sc.vsc_features = 0;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	sc.vsc_features = VIRTIO_NET_F_GUEST_CSUM;
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));

	memset(&hdr, 0, sizeof(hdr));
	hdr.vrh_gso_type = VTNET_HDR_GSO_TCPV4;
	hdr.vrh_gso_size = htole16(32);
	sc.vsc_features = VIRTIO_NET_F_GUEST_CSUM |
	    VIRTIO_NET_F_GUEST_TSO4;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	hdr.vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr.vrh_csum_start = htole16(10);
	hdr.vrh_csum_offset = htole16(10);
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	hdr.vrh_hdr_len = htole16(129);
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	hdr.vrh_hdr_len = htole16(128);
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	sc.vsc_features = VIRTIO_NET_F_GUEST_CSUM;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));

	hdr.vrh_gso_type =
	    VTNET_HDR_GSO_TCPV4 | VTNET_HDR_GSO_TUNNEL_IPV4;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	hdr.vrh_gso_type = VTNET_HDR_GSO_NONE;
	hdr.vrh_flags = 0x80;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
}

ATF_TC_WITHOUT_HEAD(transmit_offload_metadata);
ATF_TC_BODY(transmit_offload_metadata, tc)
{
	struct pci_vtnet_softc sc;
	struct virtio_net_rxhdr *hdr;
	size_t packet_len;

	packet_len = sizeof(g_packet) - VIRTIO14_NET_MODERN_HDR_SIZE;

	/* Unknown flag bits are ignored for an otherwise ordinary packet. */
	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = 0x80;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	/*
	 * A backend which consumes vnet headers receives a rebuilt header with
	 * unknown flags cleared, while the device-readable guest buffer remains
	 * untouched.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.be_vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = 0x80;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);
	ATF_REQUIRE(g_send_header_valid);
	ATF_CHECK_EQ(g_send_header.vrh_flags, 0);
	ATF_CHECK_EQ(hdr->vrh_flags, 0x80);

	/* Recognized receive-only fields are invalid on transmit. */
	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_DATA_VALID;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_bufs = htole16(1);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	/* Partial checksum metadata requires negotiation and in-range output. */
	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr->vrh_csum_start = htole16(16);
	hdr->vrh_csum_offset = htole16(2);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_CSUM;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr->vrh_csum_start = htole16(packet_len);
	hdr->vrh_csum_offset = 0;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_CSUM;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr->vrh_csum_start = htole16(packet_len - 2);
	hdr->vrh_csum_offset = 0;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	/* GSO requires the matching feature and a nonzero segment size. */
	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_gso_type = VTNET_HDR_GSO_TCPV4;
	hdr->vrh_gso_size = htole16(32);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_HOST_TSO4;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_gso_type = VTNET_HDR_GSO_TCPV4;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_HOST_TSO4;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_gso_type = VTNET_HDR_GSO_TCPV4;
	hdr->vrh_gso_size = htole16(32);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO14_NET_F_CSUM | VIRTIO14_NET_F_HOST_TSO4;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VIRTIO14_NET_HDR_F_NEEDS_CSUM;
	hdr->vrh_gso_type = VIRTIO14_NET_HDR_GSO_TCPV4;
	hdr->vrh_gso_size = htole16(32);
	hdr->vrh_csum_start = htole16(16);
	hdr->vrh_csum_offset = htole16(2);
	hdr->vrh_hdr_len = htole16(packet_len + 1);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	/*
	 * VirtIO 1.4 5.1.9.2.2: without GUEST_HDRLEN the field is only a
	 * hint, and the device MUST NOT rely on it being correct.
	 */
	ATF_CHECK_EQ(g_send_calls, 1);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_TSO4;
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_NEEDS_CSUM;
	hdr->vrh_gso_type = VTNET_HDR_GSO_TCPV4;
	hdr->vrh_gso_size = htole16(32);
	hdr->vrh_csum_start = htole16(16);
	hdr->vrh_csum_offset = htole16(2);
	hdr->vrh_hdr_len = htole16(packet_len);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	/* VirtIO 1.4 rejects ambiguous or orphaned tunnel metadata. */
	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_gso_type = VTNET_HDR_GSO_TUNNEL_IPV4 |
	    VTNET_HDR_GSO_TUNNEL_IPV6 | VTNET_HDR_GSO_TCPV4;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	hdr = (struct virtio_net_rxhdr *)g_packet;
	hdr->vrh_flags = VTNET_HDR_F_UDP_TUNNEL_CSUM;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);
}

ATF_TC_WITHOUT_HEAD(offload_type_matrix);
ATF_TC_BODY(offload_type_matrix, tc)
{
	static const struct {
		uint8_t gso_type;
		uint64_t transmit_feature;
		uint64_t receive_feature;
	} cases[] = {
		{
			VIRTIO14_NET_HDR_GSO_TCPV4,
			VIRTIO14_NET_F_HOST_TSO4,
			VIRTIO14_NET_F_GUEST_TSO4,
		},
		{
			VIRTIO14_NET_HDR_GSO_TCPV6,
			VIRTIO14_NET_F_HOST_TSO6,
			VIRTIO14_NET_F_GUEST_TSO6,
		},
		{
			VIRTIO14_NET_HDR_GSO_UDP,
			VIRTIO14_NET_F_HOST_UFO,
			VIRTIO14_NET_F_GUEST_UFO,
		},
	};
	struct pci_vtnet_softc sc;
	struct virtio_net_rxhdr hdr;
	size_t i;

	/*
	 * Exercise every base GSO encoding in 5.1.9.  Testing only TCPv4
	 * would leave the TCPv6 and UDP feature-to-header mapping unchecked.
	 */
	for (i = 0; i < nitems(cases); i++) {
		memset(&sc, 0, sizeof(sc));
		memset(&hdr, 0, sizeof(hdr));
		sc.vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
		hdr.vrh_flags = VIRTIO14_NET_HDR_F_NEEDS_CSUM;
		hdr.vrh_gso_type = cases[i].gso_type;
		hdr.vrh_gso_size = htole16(32);
		hdr.vrh_csum_start = htole16(16);
		hdr.vrh_csum_offset = htole16(2);

		sc.vsc_features = VIRTIO14_NET_F_CSUM |
		    cases[i].transmit_feature;
		ATF_CHECK(pci_vtnet_tx_header_valid(&sc, &hdr, 128));
		sc.vsc_features = VIRTIO14_NET_F_CSUM;
		ATF_CHECK(!pci_vtnet_tx_header_valid(&sc, &hdr, 128));

		sc.vsc_features = VIRTIO14_NET_F_GUEST_CSUM |
		    cases[i].receive_feature;
		ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));
		sc.vsc_features = VIRTIO14_NET_F_GUEST_CSUM;
		ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	}

	/* ECN is valid only for TCPv4/v6 with the matching ECN feature. */
	memset(&sc, 0, sizeof(sc));
	memset(&hdr, 0, sizeof(hdr));
	sc.vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;
	hdr.vrh_flags = VIRTIO14_NET_HDR_F_NEEDS_CSUM;
	hdr.vrh_gso_type = VIRTIO14_NET_HDR_GSO_TCPV6 |
	    VIRTIO14_NET_HDR_GSO_ECN;
	hdr.vrh_gso_size = htole16(32);
	hdr.vrh_csum_start = htole16(16);
	hdr.vrh_csum_offset = htole16(2);
	sc.vsc_features = VIRTIO14_NET_F_CSUM |
	    VIRTIO14_NET_F_HOST_TSO6 | VIRTIO14_NET_F_HOST_ECN;
	ATF_CHECK(pci_vtnet_tx_header_valid(&sc, &hdr, 128));
	sc.vsc_features &= ~VIRTIO14_NET_F_HOST_ECN;
	ATF_CHECK(!pci_vtnet_tx_header_valid(&sc, &hdr, 128));

	sc.vsc_features = VIRTIO14_NET_F_GUEST_CSUM |
	    VIRTIO14_NET_F_GUEST_TSO6 | VIRTIO14_NET_F_GUEST_ECN;
	ATF_CHECK(pci_vtnet_rx_header_valid(&sc, &hdr, 128));
	sc.vsc_features &= ~VIRTIO14_NET_F_GUEST_ECN;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));

	hdr.vrh_gso_type = VIRTIO14_NET_HDR_GSO_UDP |
	    VIRTIO14_NET_HDR_GSO_ECN;
	sc.vsc_features = VIRTIO14_NET_F_CSUM |
	    VIRTIO14_NET_F_HOST_UFO | VIRTIO14_NET_F_HOST_ECN;
	ATF_CHECK(!pci_vtnet_tx_header_valid(&sc, &hdr, 128));
	sc.vsc_features = VIRTIO14_NET_F_GUEST_CSUM |
	    VIRTIO14_NET_F_GUEST_UFO | VIRTIO14_NET_F_GUEST_ECN;
	ATF_CHECK(!pci_vtnet_rx_header_valid(&sc, &hdr, 128));
}

ATF_TC_WITHOUT_HEAD(feature_dependencies);
ATF_TC_BODY(feature_dependencies, tc)
{
	uint64_t features;

	ATF_CHECK(pci_vtnet_backend_features_valid(0));
	features = VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_TSO4 |
	    VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_HOST_UFO |
	    VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_GUEST_TSO4 |
	    VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_UFO;
	ATF_CHECK(pci_vtnet_backend_features_valid(features));
	ATF_CHECK(!pci_vtnet_backend_features_valid(
	    VIRTIO_NET_F_HOST_TSO4));
	ATF_CHECK(!pci_vtnet_backend_features_valid(
	    VIRTIO_NET_F_GUEST_TSO6));
	ATF_CHECK(!pci_vtnet_backend_features_valid(
	    VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_ECN));
	ATF_CHECK(!pci_vtnet_backend_features_valid(
	    VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_GUEST_ECN));
	ATF_CHECK(!pci_vtnet_backend_features_valid(
	    VIRTIO_NET_F_CTRL_VQ));
}

ATF_TC_WITHOUT_HEAD(feature_application_failure);
ATF_TC_BODY(feature_application_failure, tc)
{
	struct pci_vtnet_softc sc;
	uint64_t features;

	features = VIRTIO_NET_F_CSUM | VIRTIO_NET_F_MRG_RXBUF;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.features_negotiated = false;
	sc.tx_features_negotiated = false;
	pci_vtnet_neg_features(&sc, features);
	ATF_CHECK_EQ(g_set_cap_calls, 1);
	ATF_CHECK_EQ(g_set_cap_features, VIRTIO_NET_F_CSUM);
	ATF_CHECK_EQ(g_set_cap_header_len,
	    VIRTIO14_NET_MODERN_HDR_SIZE);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	ATF_CHECK(sc.features_negotiated);
	ATF_CHECK(sc.tx_features_negotiated);
	ATF_CHECK_EQ(sc.be_vhdrlen, VIRTIO14_NET_MODERN_HDR_SIZE);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.features_negotiated = false;
	sc.tx_features_negotiated = false;
	g_set_cap_result = EIO;
	pci_vtnet_neg_features(&sc, features);
	ATF_CHECK_EQ(g_set_cap_calls, 1);
	ATF_CHECK_EQ(g_set_cap_features, VIRTIO_NET_F_CSUM);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK(!sc.features_negotiated);
	ATF_CHECK(!sc.tx_features_negotiated);
	ATF_CHECK_EQ(sc.be_vhdrlen, 0);
	ATF_CHECK((sc.vsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.features_negotiated = false;
	sc.tx_features_negotiated = false;
	g_backend_header_len = VIRTIO14_NET_MODERN_HDR_SIZE - 1;
	g_preserve_backend_header_len = true;
	pci_vtnet_neg_features(&sc, features);
	ATF_CHECK_EQ(g_set_cap_calls, 1);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK(!sc.features_negotiated);
	ATF_CHECK(!sc.tx_features_negotiated);
	ATF_CHECK_EQ(sc.be_vhdrlen, 0);
	ATF_CHECK((sc.vsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.features_negotiated = false;
	sc.tx_features_negotiated = false;
	pci_vtnet_neg_features(&sc, VIRTIO_NET_F_MRG_RXBUF |
	    VIRTIO_F_VERSION_1 | VIRTIO_F_NOTIFICATION_DATA);
	ATF_CHECK_EQ(g_set_cap_calls, 1);
	ATF_CHECK_EQ(g_set_cap_features, 0);
	ATF_CHECK_EQ(g_set_cap_header_len, 0);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	ATF_CHECK(sc.features_negotiated);
	ATF_CHECK(sc.tx_features_negotiated);
	ATF_CHECK_EQ(sc.be_vhdrlen, 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);

	/*
	 * Snapshot restore already owns both device locks.  Its locked helper
	 * must apply and verify backend framing without trying to acquire
	 * either mutex recursively.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.features_negotiated = false;
	sc.tx_features_negotiated = false;
	pthread_mutex_lock(&sc.rx_mtx);
	pthread_mutex_lock(&sc.tx_mtx);
	ATF_CHECK(pci_vtnet_apply_features(&sc, features));
	pthread_mutex_unlock(&sc.tx_mtx);
	pthread_mutex_unlock(&sc.rx_mtx);
	ATF_CHECK(sc.features_negotiated);
	ATF_CHECK(sc.tx_features_negotiated);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(disconnected_backend);
ATF_TC_BODY(disconnected_backend, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_be = NULL;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	/* No backend means no RX callback work or backend dereference. */
	g_peek_len = 60;
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_chain_next == 1);
	ATF_CHECK(g_recv_calls == 0);
}

ATF_TC_WITHOUT_HEAD(config_write_transport_rules);
ATF_TC_BODY(config_write_transport_rules, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t before[VIRTIO14_NET_CONFIG_MAC_SIZE];
	uint32_t value;

	reset_mocks();
	setup_softc(&sc);
	memset(sc.vsc_config.mac, 0xa5, VIRTIO14_NET_CONFIG_MAC_SIZE);
	memcpy(before, sc.vsc_config.mac, VIRTIO14_NET_CONFIG_MAC_SIZE);

	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 2, 4, 0x01020304) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac,
	    VIRTIO14_NET_CONFIG_MAC_SIZE) == 0);

	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 4, 4, 0) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac,
	    VIRTIO14_NET_CONFIG_MAC_SIZE) == 0);
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 0, 3, 0) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac,
	    VIRTIO14_NET_CONFIG_MAC_SIZE) == 0);
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 2, 4, 0x01020304) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac,
	    VIRTIO14_NET_CONFIG_MAC_SIZE) != 0);

	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtnet_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK(value != UINT32_MAX);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtnet_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtnet_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtnet_cfgread(&sc,
	    VIRTIO14_NET_CONFIG_SIZE - 1, 4,
	    &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
}

ATF_TC_WITHOUT_HEAD(mtu_feature_bounds);
ATF_TC_BODY(mtu_feature_bounds, tc)
{

	ATF_CHECK(!pci_vtnet_mtu_valid(VIRTIO14_NET_MTU_MIN - 1));
	ATF_CHECK(pci_vtnet_mtu_valid(VIRTIO14_NET_MTU_MIN));
	ATF_CHECK(pci_vtnet_mtu_valid(VIRTIO14_NET_MTU_MAX));
	ATF_CHECK(!pci_vtnet_mtu_valid(VIRTIO14_NET_MTU_MAX + 1));
	ATF_CHECK(!pci_vtnet_mtu_valid(ULONG_MAX));
}

ATF_TC_WITHOUT_HEAD(mtu_frame_enforcement);
ATF_TC_BODY(mtu_frame_enforcement, tc)
{
	struct pci_vtnet_softc sc;
	size_t frame_limit;

	frame_limit = VIRTIO14_NET_MTU_MIN + ETHER_HDR_LEN;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	add_chain(1, 1, 0, true, g_packet, sc.vhdrlen + frame_limit);
	g_send_result = frame_limit;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);
	ATF_CHECK_EQ(g_send_bytes, frame_limit);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	add_chain(1, 1, 0, true, g_packet,
	    sc.vhdrlen + frame_limit + 1);
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);

	/* Without MTU negotiation the same frame remains accepted. */
	reset_mocks();
	setup_softc(&sc);
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	add_chain(1, 1, 0, true, g_packet,
	    sc.vhdrlen + frame_limit + 1);
	g_send_result = frame_limit + 1;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	/* A real segmentation type may exceed the unsegmented MTU. */
	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_features |= VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_TSO4;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	((struct virtio_net_rxhdr *)g_packet)->vrh_flags =
	    VTNET_HDR_F_NEEDS_CSUM;
	((struct virtio_net_rxhdr *)g_packet)->vrh_gso_type =
	    VTNET_HDR_GSO_TCPV4;
	((struct virtio_net_rxhdr *)g_packet)->vrh_gso_size = htole16(32);
	((struct virtio_net_rxhdr *)g_packet)->vrh_csum_start = htole16(16);
	((struct virtio_net_rxhdr *)g_packet)->vrh_csum_offset = htole16(2);
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	g_send_result = sizeof(g_packet) - sc.vhdrlen;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	/* An 802.1Q tag is part of the low-level Ethernet header. */
	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	g_packet[sc.vhdrlen + ETHER_ADDR_LEN * 2] = 0x81;
	g_packet[sc.vhdrlen + ETHER_ADDR_LEN * 2 + 1] = 0x00;
	add_chain(1, 1, 0, true, g_packet,
	    sc.vhdrlen + frame_limit + ETHER_VLAN_ENCAP_LEN);
	g_send_result = frame_limit + ETHER_VLAN_ENCAP_LEN;
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VTNET_TXQ]);
	ATF_CHECK_EQ(g_send_calls, 1);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	g_peek_len = frame_limit;
	g_recv_result = frame_limit;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], sc.vhdrlen + frame_limit);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO_NET_F_MTU;
	sc.vsc_config.mtu = VIRTIO14_NET_MTU_MIN;
	g_peek_len = frame_limit + 1;
	g_recv_result = frame_limit + 1;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_isolated);
ATF_TC_BODY(queue_reset_isolated, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.vsc_queues[VTNET_RXQ].vq_num = VTNET_RXQ;
	sc.vsc_queues[VTNET_TXQ].vq_num = VTNET_TXQ;

	ATF_CHECK((vtnet_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK((vtnet_vi_consts.vc_hv_caps &
	    VIRTIO_RING_F_EVENT_IDX) != 0);
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &sc.vsc_queues[VTNET_RXQ], 1), 0);
	ATF_CHECK_EQ(g_rx_disable_calls, 1);
	ATF_CHECK(sc.features_negotiated);

	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &sc.vsc_queues[VTNET_TXQ], 2), 0);
	ATF_CHECK_EQ(sc.resetting, 0);
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &(struct vqueue_info){ .vq_num = VTNET_CTLQ }, 3), EINVAL);

	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(stale_rx_callback_after_queue_reset);
ATF_TC_BODY(stale_rx_callback_after_queue_reset, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *vq;

	reset_mocks();
	setup_softc(&sc);
	vq = &sc.vsc_queues[VTNET_RXQ];
	g_peek_len = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));

	/*
	 * Model a readiness callback which was queued before
	 * netbe_rx_disable(), but runs after the common transport completed
	 * queue reset and discarded the ring mappings.
	 */
	vq_set_allocated(vq, false);
	vq->vq_avail = NULL;
	vq->vq_desc = NULL;
	vq->vq_used = NULL;
	pci_vtnet_rx(&sc);

	ATF_CHECK_EQ(g_chain_next, 0);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
}

ATF_TC_WITHOUT_HEAD(device_reset_clears_negotiated_state);
ATF_TC_BODY(device_reset_clears_negotiated_state, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&sc.tx_mtx, NULL) == 0);
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vsc_features = VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_MTU;
	sc.rx_merge = 1;
	sc.vhdrlen = VIRTIO14_NET_MODERN_HDR_SIZE;

	pci_vtnet_reset(&sc);

	ATF_CHECK_EQ(g_reset_calls, 1);
	ATF_CHECK_EQ(g_rx_disable_calls, 1);
	ATF_CHECK(!sc.features_negotiated);
	ATF_CHECK_EQ(sc.vsc_features, 0);
	ATF_CHECK_EQ(sc.rx_merge, 0);
	ATF_CHECK_EQ(sc.vhdrlen, VIRTIO14_NET_MODERN_HDR_SIZE);
	ATF_CHECK_EQ(sc.resetting, 0);

	ATF_REQUIRE(pthread_mutex_destroy(&sc.tx_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(event_idx_rx_enable_recheck);
ATF_TC_BODY(event_idx_rx_enable_recheck, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *vq;

	reset_mocks();
	setup_softc(&sc);
	vq = &sc.vsc_queues[VTNET_RXQ];
	vq->vq_vs = &sc.vsc_vs;
	vq->vq_qsize = 8;
	sc.vsc_vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;

	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));

	/*
	 * Make the first vq_getchain() report an empty ring while leaving a
	 * descriptor visible to the required post-enable vq_has_descs()
	 * recheck.  The RX path must consume it instead of disabling the
	 * backend and sleeping with work pending.
	 */
	g_hide_next_getchain = true;
	pci_vtnet_rx(&sc);

	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rx_disable_calls, 0);
	ATF_CHECK_EQ(g_used.flags, 0);
	ATF_CHECK_EQ(VQ_AVAIL_EVENT_IDX(vq), 7);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtnet_softc sc;
	size_t frame_len;

	/*
	 * Encode a modern transmit header exclusively with the byte offsets in
	 * section 5.1.9.  The production virtio_net_rxhdr layout does not
	 * participate in creating this input.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vsc_features = VIRTIO14_NET_F_CSUM;
	g_packet[VIRTIO14_NET_HDR_FLAGS_OFF] =
	    VIRTIO14_NET_HDR_F_NEEDS_CSUM;
	g_packet[VIRTIO14_NET_HDR_GSO_TYPE_OFF] =
	    VIRTIO14_NET_HDR_GSO_NONE;
	virtio14_store_le16(g_packet + VIRTIO14_NET_HDR_CSUM_START_OFF, 16);
	virtio14_store_le16(g_packet + VIRTIO14_NET_HDR_CSUM_OFFSET_OFF, 2);
	frame_len = sizeof(g_packet) - VIRTIO14_NET_MODERN_HDR_SIZE;
	g_send_result = frame_len;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VIRTIO14_NET_TRANSMITQ]);
	ATF_CHECK_EQ(g_send_calls, 1);
	ATF_CHECK_EQ(g_send_bytes, frame_len);

	/*
	 * For receive, the device must encode num_buffers at byte 10 in the
	 * modern header even when the payload follows in the same descriptor.
	 */
	reset_mocks();
	setup_softc(&sc);
	memset(g_packet, 0xa5, sizeof(g_packet));
	g_peek_len = 60;
	g_recv_result = 60;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_REQUIRE_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(virtio14_load_le16(g_packet +
	    VIRTIO14_NET_HDR_NUM_BUFFERS_OFF),
	    VIRTIO14_NET_SINGLE_BUFFER_COUNT);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_NET_MODERN_HDR_SIZE + 60);
}

ATF_TC_WITHOUT_HEAD(document_feature_advertisement);
ATF_TC_BODY(document_feature_advertisement, tc)
{

	/*
	 * These are feature bits 5 and 16 in section 5.1.3, not values imported
	 * from pci_virtio_net.c.  Advertising the corresponding config fields
	 * without these bits would make their contents undefined to the driver.
	 */
	ATF_CHECK((vtnet_vi_consts.vc_hv_caps & VIRTIO14_NET_F_MAC) != 0);
	ATF_CHECK((vtnet_vi_consts.vc_hv_caps & VIRTIO14_NET_F_STATUS) != 0);
}

static uint8_t
run_mq_pairs_command(struct pci_vtnet_softc *sc, uint16_t pairs,
    uint8_t class, uint8_t command)
{
	struct vqueue_info *ctlq;
	uint8_t ack, request[VIRTIO14_NET_CTRL_MQ_SIZE];

	reset_mocks();
	memset(request, 0, sizeof(request));
	request[VIRTIO14_NET_CTRL_CLASS_OFF] = class;
	request[VIRTIO14_NET_CTRL_COMMAND_OFF] = command;
	virtio14_store_le16(request + VIRTIO14_NET_CTRL_DATA_OFF, pairs);
	ack = 0xff;
	g_chains[0].n = 2;
	g_chains[0].req.idx = 10;
	g_chains[0].req.readable = 1;
	g_chains[0].req.writable = 1;
	g_chains[0].req.ordered = true;
	g_chains[0].iov[0].iov_base = request;
	g_chains[0].iov[0].iov_len = sizeof(request);
	g_chains[0].iov[1].iov_base = &ack;
	g_chains[0].iov[1].iov_len = sizeof(ack);
	g_chain_count = 1;
	ctlq = &sc->vsc_queues[
	    VIRTIO14_NET_MQ_CONTROLQ(sc->vsc_max_pairs)];
	pci_vtnet_ping_ctlq(sc, ctlq);
	ATF_REQUIRE_EQ(g_chain_next, 1);
	ATF_REQUIRE_EQ(g_rel_calls, 1);
	ATF_REQUIRE_EQ(g_rel_len[0], 1);
	return (ack);
}

static const uint8_t rss_test_key[VIRTIO14_NET_RSS_KEY_SIZE_MIN] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

static size_t
build_rss_command(uint8_t *request, size_t request_size, uint16_t table_mask,
    const uint16_t *table, uint16_t unclassified, uint16_t max_tx,
    uint32_t hash_types, const uint8_t *key, uint8_t key_length)
{
	size_t entries, key_offset, trailer_offset, total;

	entries = (size_t)table_mask + 1;
	trailer_offset = VIRTIO14_NET_RSS_TABLE_OFF +
	    entries * sizeof(uint16_t);
	key_offset = trailer_offset + sizeof(uint16_t) + sizeof(uint8_t);
	total = key_offset + key_length;
	ATF_REQUIRE(total <= request_size);
	memset(request, 0, total);
	request[VIRTIO14_NET_CTRL_CLASS_OFF] = VIRTIO14_NET_CTRL_MQ;
	request[VIRTIO14_NET_CTRL_COMMAND_OFF] =
	    VIRTIO14_NET_CTRL_MQ_RSS_CONFIG;
	virtio14_store_le32(request + VIRTIO14_NET_RSS_HASH_TYPES_OFF,
	    hash_types);
	virtio14_store_le16(request + VIRTIO14_NET_RSS_TABLE_MASK_OFF,
	    table_mask);
	virtio14_store_le16(request + VIRTIO14_NET_RSS_UNCLASSIFIED_OFF,
	    unclassified);
	for (size_t i = 0; i < entries; i++)
		virtio14_store_le16(request + VIRTIO14_NET_RSS_TABLE_OFF +
		    i * sizeof(uint16_t), table[i]);
	virtio14_store_le16(request + trailer_offset, max_tx);
	request[trailer_offset + sizeof(uint16_t)] = key_length;
	memcpy(request + key_offset, key, key_length);
	return (total);
}

static uint8_t
run_rss_command(struct pci_vtnet_softc *sc, const uint8_t *request,
    size_t request_size)
{
	struct vqueue_info *ctlq;
	uint8_t ack;

	reset_mocks();
	ack = 0xff;
	g_chains[0].n = 2;
	g_chains[0].req.idx = 10;
	g_chains[0].req.readable = 1;
	g_chains[0].req.writable = 1;
	g_chains[0].req.ordered = true;
	g_chains[0].iov[0].iov_base = __DECONST(void *, request);
	g_chains[0].iov[0].iov_len = request_size;
	g_chains[0].iov[1].iov_base = &ack;
	g_chains[0].iov[1].iov_len = sizeof(ack);
	g_chain_count = 1;
	ctlq = &sc->vsc_queues[
	    VIRTIO14_NET_MQ_CONTROLQ(sc->vsc_max_pairs)];
	pci_vtnet_ping_ctlq(sc, ctlq);
	ATF_REQUIRE_EQ(g_chain_next, 1);
	ATF_REQUIRE_EQ(g_rel_calls, 1);
	ATF_REQUIRE_EQ(g_rel_len[0], 1);
	return (ack);
}

static void
make_ipv4_tcp_flow(uint8_t *frame, bool reverse, uint16_t destination_port)
{
	static const uint8_t mac_a[ETHER_ADDR_LEN] =
	    { 0x02, 0, 0, 0, 0, 1 };
	static const uint8_t mac_b[ETHER_ADDR_LEN] =
	    { 0x02, 0, 0, 0, 0, 2 };
	static const uint8_t ip_a[4] = { 192, 0, 2, 1 };
	static const uint8_t ip_b[4] = { 198, 51, 100, 2 };
	const uint8_t *destination_mac, *destination_ip;
	const uint8_t *source_mac, *source_ip;
	uint16_t source_port;

	memset(frame, 0, 64);
	destination_mac = reverse ? mac_a : mac_b;
	source_mac = reverse ? mac_b : mac_a;
	destination_ip = reverse ? ip_a : ip_b;
	source_ip = reverse ? ip_b : ip_a;
	source_port = reverse ? destination_port : 49152;
	destination_port = reverse ? 49152 : destination_port;
	memcpy(frame, destination_mac, ETHER_ADDR_LEN);
	memcpy(frame + ETHER_ADDR_LEN, source_mac, ETHER_ADDR_LEN);
	frame[12] = 0x08;
	frame[13] = 0x00;
	frame[14] = 0x45;
	frame[17] = 50;
	frame[23] = IPPROTO_TCP;
	memcpy(frame + 26, source_ip, 4);
	memcpy(frame + 30, destination_ip, 4);
	frame[34] = source_port >> 8;
	frame[35] = source_port;
	frame[36] = destination_port >> 8;
	frame[37] = destination_port;
	frame[46] = 0x50;
}

static void
make_ipv6_tcp_flow(uint8_t *frame, bool extension_header)
{
	static const uint8_t source[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	};
	static const uint8_t destination[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 2,
	};
	size_t l4off;

	memset(frame, 0, 88);
	frame[12] = 0x86;
	frame[13] = 0xdd;
	frame[14] = 0x60;
	frame[19] = 34;
	frame[20] = extension_header ? IPPROTO_HOPOPTS : IPPROTO_TCP;
	memcpy(frame + 22, source, sizeof(source));
	memcpy(frame + 38, destination, sizeof(destination));
	l4off = 54;
	if (extension_header) {
		frame[l4off] = IPPROTO_TCP;
		frame[l4off + 1] = 0;
		l4off += 8;
	}
	frame[l4off] = 0xc0;
	frame[l4off + 1] = 0x00;
	frame[l4off + 2] = 0x01;
	frame[l4off + 3] = 0xbb;
	frame[l4off + 12] = 0x50;
}

ATF_TC_WITHOUT_HEAD(multiqueue_policy_and_topology);
ATF_TC_BODY(multiqueue_policy_and_topology, tc)
{
	const char *errstr;
	uint16_t pairs;

	ATF_CHECK_EQ(pci_vtnet_parse_queues(NULL, &pairs, &errstr), 0);
	ATF_CHECK_EQ(pairs, VIRTIO14_NET_CTRL_MQ_PAIRS_MIN);
	ATF_CHECK_EQ(pci_vtnet_parse_queues("8", &pairs, &errstr), 0);
	ATF_CHECK_EQ(pairs, 8);
	ATF_CHECK_EQ(pci_vtnet_parse_queues("0", &pairs, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtnet_parse_queues("9", &pairs, &errstr), EINVAL);
	ATF_CHECK_EQ(pci_vtnet_parse_queues("two", &pairs, &errstr), EINVAL);

	for (uint16_t pair = 0; pair < 8; pair++) {
		ATF_CHECK_EQ(pci_vtnet_rxq_index(pair),
		    VIRTIO14_NET_RXQ(pair));
		ATF_CHECK_EQ(pci_vtnet_txq_index(pair),
		    VIRTIO14_NET_TXQ(pair));
	}
	ATF_CHECK_EQ(VIRTIO14_NET_MQ_CONTROLQ(8), 16);
	ATF_CHECK_EQ(VTNET_MAX_PAIRS, 8);
	ATF_CHECK(VTNET_MAX_PAIRS <= VIRTIO14_NET_CTRL_MQ_PAIRS_MAX);
}

ATF_TC_WITHOUT_HEAD(multiqueue_feature_dependency);
ATF_TC_BODY(multiqueue_feature_dependency, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_max_pairs = 2;
	ATF_CHECK(!pci_vtnet_apply_features(&sc, VIRTIO14_NET_F_MQ));
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK(!sc.features_negotiated);
	ATF_CHECK(!sc.tx_features_negotiated);
	ATF_CHECK_EQ(g_set_cap_calls, 0);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_max_pairs = 2;
	ATF_CHECK(pci_vtnet_apply_features(&sc,
	    VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_NET_F_MQ));
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	ATF_CHECK(sc.features_negotiated);
	ATF_CHECK(sc.tx_features_negotiated);
	ATF_CHECK_EQ(sc.rx_active_pairs,
	    VIRTIO14_NET_CTRL_MQ_PAIRS_MIN);
	ATF_CHECK_EQ(sc.tx_active_pairs,
	    VIRTIO14_NET_CTRL_MQ_PAIRS_MIN);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_max_pairs = 2;
	ATF_CHECK(!pci_vtnet_apply_features(&sc, VIRTIO14_NET_F_RSS));
	ATF_CHECK_EQ(g_needs_reset_calls, 1);

	reset_mocks();
	setup_softc(&sc);
	sc.vsc_max_pairs = 2;
	ATF_CHECK(pci_vtnet_apply_features(&sc,
	    VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_NET_F_RSS));
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_control_commands);
ATF_TC_BODY(multiqueue_control_commands, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t ack;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	ATF_CHECK_EQ(sc.rx_active_pairs,
	    VIRTIO14_NET_CTRL_MQ_PAIRS_MIN);
	ATF_CHECK_EQ(sc.tx_active_pairs,
	    VIRTIO14_NET_CTRL_MQ_PAIRS_MIN);

	ack = run_mq_pairs_command(&sc, 2, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_OK);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);

	ack = run_mq_pairs_command(&sc, 0, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);

	ack = run_mq_pairs_command(&sc, 3, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);

	ack = run_mq_pairs_command(&sc, 1, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET + 1);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);

	ack = run_mq_pairs_command(&sc, 1, VIRTIO14_NET_CTRL_MQ + 1,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);

	ack = run_mq_pairs_command(&sc, 1, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_OK);
	ATF_CHECK_EQ(sc.rx_active_pairs, 1);
	ATF_CHECK_EQ(sc.tx_active_pairs, 1);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(multiqueue_flow_steering);
ATF_TC_BODY(multiqueue_flow_steering, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *vq;
	uint8_t forward[64], reverse[64], other[64];
	uint32_t hash;
	bool drop;

	make_ipv4_tcp_flow(forward, false, 443);
	make_ipv4_tcp_flow(reverse, true, 443);
	make_ipv4_tcp_flow(other, false, 8443);
	ATF_REQUIRE_EQ(pci_vtnet_flow_hash(forward, sizeof(forward)),
	    pci_vtnet_flow_hash(reverse, sizeof(reverse)));
	ATF_CHECK(pci_vtnet_flow_hash(forward, sizeof(forward)) !=
	    pci_vtnet_flow_hash(other, sizeof(other)));

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.rx_active_pairs = 2;
	sc.rx_enabled_mask = 3;
	sc.tx_active_pairs = 2;
	hash = pci_vtnet_flow_hash(forward, sizeof(forward));
	pci_vtnet_flow_learn(&sc, hash, 1);
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	vq = pci_vtnet_select_rxq(&sc, reverse, sizeof(reverse), &drop);
	ATF_REQUIRE(vq != NULL);
	ATF_CHECK(!drop);
	ATF_CHECK_EQ(vq->vq_num, VIRTIO14_NET_RXQ(1));

	vq_set_resetting(&sc.vsc_queues[VIRTIO14_NET_RXQ(1)], true);
	vq = pci_vtnet_select_rxq(&sc, reverse, sizeof(reverse), &drop);
	ATF_REQUIRE(vq != NULL);
	ATF_CHECK(!drop);
	ATF_CHECK_EQ(vq->vq_num, VIRTIO14_NET_RXQ(0));
	vq_set_resetting(&sc.vsc_queues[VIRTIO14_NET_RXQ(0)], true);
	ATF_CHECK(pci_vtnet_select_rxq(&sc, reverse, sizeof(reverse),
	    &drop) == NULL);
	ATF_CHECK(!drop);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(multiqueue_control_descriptor_validation);
ATF_TC_BODY(multiqueue_control_descriptor_validation, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *ctlq;
	uint8_t ack, request[VIRTIO14_NET_CTRL_MQ_SIZE];

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	ctlq = &sc.vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(2)];
	memset(request, 0, sizeof(request));
	request[VIRTIO14_NET_CTRL_CLASS_OFF] = VIRTIO14_NET_CTRL_MQ;
	request[VIRTIO14_NET_CTRL_COMMAND_OFF] =
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET;
	virtio14_store_le16(request + VIRTIO14_NET_CTRL_DATA_OFF, 2);
	ack = 0xff;
	g_chains[0].n = 3;
	g_chains[0].req.idx = 10;
	g_chains[0].req.readable = 2;
	g_chains[0].req.writable = 1;
	g_chains[0].req.ordered = true;
	g_chains[0].iov[0] = (struct iovec){
	    .iov_base = request,
	    .iov_len = 1,
	};
	g_chains[0].iov[1] = (struct iovec){
	    .iov_base = request + 1,
	    .iov_len = sizeof(request) - 1,
	};
	g_chains[0].iov[2] = (struct iovec){
	    .iov_base = &ack,
	    .iov_len = sizeof(ack),
	};
	g_chain_count = 1;
	pci_vtnet_ping_ctlq(&sc, ctlq);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_OK);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);
	ATF_REQUIRE_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], 1);

	reset_mocks();
	g_chains[0].n = 2;
	g_chains[0].req.idx = 10;
	g_chains[0].req.readable = 1;
	g_chains[0].req.writable = 1;
	g_chains[0].req.ordered = false;
	g_chains[0].iov[0] = (struct iovec){
	    .iov_base = request,
	    .iov_len = sizeof(request),
	};
	g_chains[0].iov[1] = (struct iovec){
	    .iov_base = &ack,
	    .iov_len = sizeof(ack),
	};
	g_chain_count = 1;
	pci_vtnet_ping_ctlq(&sc, ctlq);
	ATF_REQUIRE_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], 0);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(multiqueue_tx_learns_reverse_flow);
ATF_TC_BODY(multiqueue_tx_learns_reverse_flow, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t reverse[64];
	uint32_t hash;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.rx_active_pairs = 2;
	sc.rx_enabled_mask = 3;
	sc.tx_active_pairs = 2;
	make_ipv4_tcp_flow(g_packet + VIRTIO14_NET_MODERN_HDR_SIZE, false,
	    443);
	make_ipv4_tcp_flow(reverse, true, 443);
	g_send_result = sizeof(reverse);
	add_chain(1, 1, 0, true, g_packet,
	    VIRTIO14_NET_MODERN_HDR_SIZE + sizeof(reverse));
	pci_vtnet_proctx(&sc, &sc.vsc_queues[VIRTIO14_NET_TXQ(1)]);
	ATF_REQUIRE_EQ(g_send_calls, 1);
	hash = pci_vtnet_flow_hash(reverse, sizeof(reverse));
	ATF_CHECK_EQ(pci_vtnet_flow_pair(&sc, hash, 2), 1);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(staged_receive_waits_for_buffer);
ATF_TC_BODY(staged_receive_waits_for_buffer, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.rx_mtx, NULL) == 0);
	g_backend_packet[0] = 0x5a;
	g_peek_len = 60;
	g_recv_result = 60;
	pci_vtnet_rx(&sc);
	ATF_REQUIRE_EQ(g_recv_calls, 1);
	ATF_REQUIRE_EQ(g_rx_disable_calls, 1);
	ATF_REQUIRE_EQ(sc.rx_staged_len,
	    VIRTIO14_NET_MODERN_HDR_SIZE + 60);

	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	pci_vtnet_ping_rxq(&sc, &sc.vsc_queues[VIRTIO14_NET_RECEIVEQ]);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len[0], VIRTIO14_NET_MODERN_HDR_SIZE + 60);
	ATF_CHECK_EQ(sc.rx_staged_len, 0);
	ATF_CHECK_EQ(g_packet[VIRTIO14_NET_MODERN_HDR_SIZE], 0x5a);
	ATF_CHECK_EQ(g_rx_enable_calls, 1);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.rx_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_all_reset_drops_staged_packet);
ATF_TC_BODY(multiqueue_all_reset_drops_staged_packet, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.rx_active_pairs = 2;
	sc.rx_enabled_mask = 3;
	sc.tx_active_pairs = 2;
	vq_set_resetting(&sc.vsc_queues[VIRTIO14_NET_RXQ(0)], true);
	vq_set_resetting(&sc.vsc_queues[VIRTIO14_NET_RXQ(1)], true);
	g_peek_len = 60;
	g_recv_result = 60;
	pci_vtnet_rx(&sc);
	ATF_CHECK_EQ(g_recv_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_rx_disable_calls, 0);
	ATF_CHECK_EQ(sc.rx_staged_len, 0);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(multiqueue_queue_reset_isolation);
ATF_TC_BODY(multiqueue_queue_reset_isolation, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.rx_active_pairs = 2;
	sc.rx_enabled_mask = 3;
	sc.tx_active_pairs = 2;
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &sc.vsc_queues[VIRTIO14_NET_RXQ(1)], 1), 0);
	ATF_CHECK_EQ(g_rx_disable_calls, 0);
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &sc.vsc_queues[VIRTIO14_NET_TXQ(1)], 2), 0);
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &sc.vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(2)], 3), 0);
	ATF_CHECK_EQ(pci_vtnet_qreset(&sc,
	    &(struct vqueue_info){ .vq_num = 4 }, 4), EINVAL);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(multiqueue_tx_event_idx_recheck);
ATF_TC_BODY(multiqueue_tx_event_idx_recheck, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *vq;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.tx_active_pairs = 1;
	sc.vsc_vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	sc.vsc_queues[VIRTIO14_NET_TXQ(0)].vq_qsize = 8;
	sc.vsc_queues[VIRTIO14_NET_TXQ(1)].vq_qsize = 8;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));

	/*
	 * The first scan misses a descriptor which appears while the worker
	 * enables kicks.  The arm helper must observe it before sleeping.
	 */
	g_hide_next_has_desc = true;
	ATF_REQUIRE(pci_vtnet_tx_find_work_locked(&sc) == NULL);
	vq = pci_vtnet_tx_arm_locked(&sc);
	ATF_REQUIRE(vq != NULL);
	ATF_CHECK_EQ(vq->vq_num, VIRTIO14_NET_TXQ(0));
	destroy_multiqueue_softc(&sc);

	/* Unmapped queues must not dereference a used ring while arming. */
	reset_mocks();
	setup_softc(&sc);
	sc.vsc_queues[VIRTIO14_NET_TXQ(0)].vq_used = NULL;
	vq_set_allocated(&sc.vsc_queues[VIRTIO14_NET_TXQ(0)], false);
	ATF_CHECK(pci_vtnet_tx_arm_locked(&sc) == NULL);
}

ATF_TC_WITHOUT_HEAD(multiqueue_tx_scheduler_rotates);
ATF_TC_BODY(multiqueue_tx_scheduler_rotates, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *first, *second;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.tx_active_pairs = 2;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	first = pci_vtnet_tx_find_work_locked(&sc);
	second = pci_vtnet_tx_find_work_locked(&sc);
	ATF_REQUIRE(first != NULL);
	ATF_REQUIRE(second != NULL);
	ATF_CHECK_EQ(first->vq_num, VIRTIO14_NET_TXQ(0));
	ATF_CHECK_EQ(second->vq_num, VIRTIO14_NET_TXQ(1));
	ATF_CHECK_EQ(VTNET_TX_BUDGET, 64);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(rss_toeplitz_vector);
ATF_TC_BODY(rss_toeplitz_vector, tc)
{
	static const uint8_t tuple[] = {
		192, 0, 2, 1, 198, 51, 100, 2, 0xc0, 0x00, 0x01, 0xbb,
	};
	uint32_t hash;

	/*
	 * Literal oracle generated from the Microsoft RSS key and the
	 * document-defined network-order IPv4/TCP tuple above.
	 */
	ATF_REQUIRE(pci_vtnet_rss_toeplitz(rss_test_key,
	    sizeof(rss_test_key), tuple, sizeof(tuple), &hash));
	ATF_CHECK_EQ(hash, 0x45de0bccU);
	ATF_CHECK(!pci_vtnet_rss_toeplitz(rss_test_key, 4, tuple,
	    sizeof(tuple), &hash));
}

ATF_TC_WITHOUT_HEAD(rss_command_and_steering);
ATF_TC_BODY(rss_command_and_steering, tc)
{
	struct pci_vtnet_softc sc;
	struct vqueue_info *vq;
	uint8_t frame[88], request[VIRTIO14_NET_RSS_COMMAND_MAX];
	uint16_t table[2] = { 1, 0 };
	uint32_t hash;
	size_t request_size;
	bool drop;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	sc.vsc_features |= VIRTIO14_NET_F_RSS;
	request_size = build_rss_command(request, sizeof(request), 1, table,
	    1, 2, VIRTIO14_NET_RSS_HASH_TYPE_TCPV4, rss_test_key,
	    sizeof(rss_test_key));
	ATF_CHECK_EQ(run_rss_command(&sc, request, request_size),
	    VIRTIO14_NET_CTRL_OK);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rx_active_pairs, 0);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rss_key_length, sizeof(rss_test_key));

	make_ipv4_tcp_flow(frame, false, 443);
	ATF_REQUIRE(pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	ATF_CHECK_EQ(hash, 0x45de0bccU);
	frame[20] = 0x20;
	ATF_REQUIRE(pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	ATF_CHECK_EQ(hash, 0x45de0bccU);
	frame[20] = 0;
	frame[21] = 1;
	ATF_CHECK(!pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	frame[21] = 0;
	frame[17] = 20;
	ATF_CHECK(!pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	frame[17] = 50;
	add_chain(1, 0, 1, true, g_packet, sizeof(g_packet));
	vq = pci_vtnet_select_rxq(&sc, frame, sizeof(frame), &drop);
	ATF_REQUIRE(vq != NULL);
	ATF_CHECK(!drop);
	ATF_CHECK_EQ(vq->vq_num, VIRTIO14_NET_RXQ(1));

	vq_set_resetting(&sc.vsc_queues[VIRTIO14_NET_RXQ(1)], true);
	vq = pci_vtnet_select_rxq(&sc, frame, sizeof(frame), &drop);
	ATF_CHECK(vq == NULL);
	ATF_CHECK(drop);

	sc.rss_hash_types = VIRTIO14_NET_RSS_HASH_TYPE_TCPV6;
	make_ipv6_tcp_flow(frame, false);
	ATF_REQUIRE(pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	ATF_CHECK_EQ(hash, 0x22225eecU);
	make_ipv6_tcp_flow(frame, true);
	ATF_REQUIRE(pci_vtnet_rss_hash(&sc, frame, sizeof(frame), &hash));
	ATF_CHECK_EQ(hash, 0x22225eecU);
	destroy_multiqueue_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(rss_command_validation);
ATF_TC_BODY(rss_command_validation, tc)
{
	struct pci_vtnet_rss_config rss;
	struct pci_vtnet_softc sc;
	uint8_t request[VIRTIO14_NET_RSS_COMMAND_MAX];
	uint16_t table[VIRTIO14_NET_RSS_TABLE_SIZE_MIN] = { 0, 1 };
	size_t request_size;

	reset_mocks();
	setup_multiqueue_softc(&sc, 2);
	request_size = build_rss_command(request, sizeof(request), 1, table,
	    0, 2, VIRTIO14_NET_RSS_HASH_TYPES_BASIC, rss_test_key,
	    sizeof(rss_test_key));
	ATF_CHECK(pci_vtnet_parse_rss_config(&sc, request, request_size,
	    &rss));
	ATF_CHECK_EQ(rss.indirection_mask, 1);
	ATF_CHECK_EQ(rss.enabled_mask, 3);

	for (size_t i = 0; i < nitems(table); i++)
		table[i] = i & 1;
	request_size = build_rss_command(request, sizeof(request), 127, table,
	    0, 2, VIRTIO14_NET_RSS_HASH_TYPES_BASIC, rss_test_key,
	    sizeof(rss_test_key));
	ATF_CHECK_EQ(request_size, sizeof(request));
	ATF_CHECK(pci_vtnet_parse_rss_config(&sc, request, request_size,
	    &rss));

	request_size = build_rss_command(request, sizeof(request), 1, table,
	    0, 2, VIRTIO14_NET_RSS_HASH_TYPES_BASIC, rss_test_key,
	    sizeof(rss_test_key));
	virtio14_store_le32(request + VIRTIO14_NET_RSS_HASH_TYPES_OFF,
	    VIRTIO14_NET_RSS_HASH_TYPES_BASIC | (1U << 31));
	ATF_CHECK(!pci_vtnet_parse_rss_config(&sc, request, request_size,
	    &rss));
	virtio14_store_le32(request + VIRTIO14_NET_RSS_HASH_TYPES_OFF,
	    VIRTIO14_NET_RSS_HASH_TYPES_BASIC);
	ATF_CHECK(!pci_vtnet_parse_rss_config(&sc, request,
	    request_size - 1, &rss));

	request_size = build_rss_command(request, sizeof(request), 1, table,
	    2, 2, VIRTIO14_NET_RSS_HASH_TYPES_BASIC, rss_test_key,
	    sizeof(rss_test_key));
	ATF_CHECK(!pci_vtnet_parse_rss_config(&sc, request, request_size,
	    &rss));

	table[0] = 1;
	table[1] = 0;
	request_size = build_rss_command(request, sizeof(request), 1, table,
	    1, 2, VIRTIO14_NET_RSS_HASH_TYPE_TCPV4, rss_test_key,
	    sizeof(rss_test_key));
	sc.vsc_features |= VIRTIO14_NET_F_RSS;
	ATF_REQUIRE_EQ(run_rss_command(&sc, request, request_size),
	    VIRTIO14_NET_CTRL_OK);
	virtio14_store_le32(request + VIRTIO14_NET_RSS_HASH_TYPES_OFF,
	    VIRTIO14_NET_RSS_HASH_TYPE_TCPV4 | (1U << 31));
	ATF_CHECK_EQ(run_rss_command(&sc, request, request_size),
	    VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rss_hash_types,
	    VIRTIO14_NET_RSS_HASH_TYPE_TCPV4);
	ATF_CHECK_EQ(sc.rss_unclassified_queue, 1);
	ATF_CHECK_EQ(sc.rss_indirection_table[0], 1);
	ATF_CHECK_EQ(sc.rss_indirection_table[1], 0);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(run_mq_pairs_command(&sc, 2, VIRTIO14_NET_CTRL_MQ,
	    VIRTIO14_NET_CTRL_MQ_VQ_PAIRS_SET), VIRTIO14_NET_CTRL_OK);
	ATF_CHECK(!sc.rss_enabled);
	ATF_CHECK_EQ(sc.rss_hash_types, 0);
	ATF_CHECK_EQ(sc.rss_key_length, 0);
	ATF_CHECK_EQ(sc.rx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	destroy_multiqueue_softc(&sc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transmit_validation);
	ATF_TP_ADD_TC(tp, transmit_consumes_one_chain);
	ATF_TP_ADD_TC(tp, transmit_offload_metadata);
	ATF_TP_ADD_TC(tp, offload_type_matrix);
	ATF_TP_ADD_TC(tp, feature_dependencies);
	ATF_TP_ADD_TC(tp, feature_application_failure);
	ATF_TP_ADD_TC(tp, receive_validation);
	ATF_TP_ADD_TC(tp, receive_length_bounds);
	ATF_TP_ADD_TC(tp, receive_header_layout);
	ATF_TP_ADD_TC(tp, split_header_descriptors);
	ATF_TP_ADD_TC(tp, receive_offload_metadata);
	ATF_TP_ADD_TC(tp, disconnected_backend);
	ATF_TP_ADD_TC(tp, config_write_transport_rules);
	ATF_TP_ADD_TC(tp, mtu_feature_bounds);
	ATF_TP_ADD_TC(tp, mtu_frame_enforcement);
	ATF_TP_ADD_TC(tp, queue_reset_isolated);
	ATF_TP_ADD_TC(tp, stale_rx_callback_after_queue_reset);
	ATF_TP_ADD_TC(tp, device_reset_clears_negotiated_state);
	ATF_TP_ADD_TC(tp, event_idx_rx_enable_recheck);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, document_feature_advertisement);
	ATF_TP_ADD_TC(tp, multiqueue_policy_and_topology);
	ATF_TP_ADD_TC(tp, multiqueue_feature_dependency);
	ATF_TP_ADD_TC(tp, multiqueue_control_commands);
	ATF_TP_ADD_TC(tp, multiqueue_flow_steering);
	ATF_TP_ADD_TC(tp, multiqueue_control_descriptor_validation);
	ATF_TP_ADD_TC(tp, multiqueue_tx_learns_reverse_flow);
	ATF_TP_ADD_TC(tp, staged_receive_waits_for_buffer);
	ATF_TP_ADD_TC(tp, multiqueue_all_reset_drops_staged_packet);
	ATF_TP_ADD_TC(tp, multiqueue_queue_reset_isolation);
	ATF_TP_ADD_TC(tp, multiqueue_tx_event_idx_recheck);
	ATF_TP_ADD_TC(tp, multiqueue_tx_scheduler_rotates);
	ATF_TP_ADD_TC(tp, rss_toeplitz_vector);
	ATF_TP_ADD_TC(tp, rss_command_and_steering);
	ATF_TP_ADD_TC(tp, rss_command_validation);
	return (atf_no_error());
}

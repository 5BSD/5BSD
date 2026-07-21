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

#include "pci_virtio_net.c"

struct net_backend {
	int unused;
};

struct mock_chain {
	int n;
	struct vi_req req;
	struct iovec iov[4];
};

static struct mock_chain g_chains[4];
static int g_chain_count;
static int g_chain_next;
static ssize_t g_peek_len;
static ssize_t g_recv_result;
static ssize_t g_send_result;
static int g_recv_calls;
static int g_send_calls;
static size_t g_send_bytes;
static int g_rel_calls;
static uint16_t g_rel_idx[8];
static uint32_t g_rel_len[8];
static int g_prepare_calls;
static uint16_t g_prepare_idx[8];
static uint32_t g_prepare_len[8];
static int g_publish_calls;
static uint8_t g_packet[128];
static struct vring_used g_used;

size_t
count_iov(const struct iovec *iov, size_t niov)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

static void
reset_mocks(void)
{

	memset(g_chains, 0, sizeof(g_chains));
	memset(g_packet, 0, sizeof(g_packet));
	memset(&g_used, 0, sizeof(g_used));
	g_chain_count = 0;
	g_chain_next = 0;
	g_peek_len = 0;
	g_recv_result = 0;
	g_send_result = 0;
	g_recv_calls = 0;
	g_send_calls = 0;
	g_send_bytes = 0;
	g_rel_calls = 0;
	g_prepare_calls = 0;
	g_publish_calls = 0;
}

static void
setup_softc(struct pci_vtnet_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
	sc->features_negotiated = true;
	sc->vhdrlen = sizeof(struct virtio_net_rxhdr);
	sc->vsc_queues[VTNET_RXQ].vq_used = &g_used;
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

	return (g_chain_next < g_chain_count);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	struct mock_chain *chain;

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
netbe_recv(net_backend_t *be __unused, const struct iovec *iov __unused,
    int niov __unused)
{

	g_recv_calls++;
	g_peek_len = 0;
	return (g_recv_result);
}

ssize_t
netbe_send(net_backend_t *be __unused, const struct iovec *iov, int niov)
{

	g_send_calls++;
	g_send_bytes = count_iov(iov, niov);
	return (g_send_result);
}

void netbe_rx_disable(net_backend_t *be __unused) {}
void netbe_rx_enable(net_backend_t *be __unused) {}

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

ATF_TC_WITHOUT_HEAD(receive_validation);
ATF_TC_BODY(receive_validation, tc)
{
	struct pci_vtnet_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	add_chain(-1, 0, 0, true, NULL, 0);
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_chain_next == 1);
	ATF_CHECK(g_recv_calls == 0);
	ATF_CHECK(g_rel_calls == 0);

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	add_chain(1, 1, 0, true, g_packet, sizeof(g_packet));
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_recv_calls == 0);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len[0] == 0);

	reset_mocks();
	setup_softc(&sc);
	g_peek_len = 60;
	add_chain(1, 0, 1, true, g_packet, sc.vhdrlen + 8);
	pci_vtnet_rx(&sc);
	ATF_CHECK(g_recv_calls == 0);
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
	    64 + sizeof(struct virtio_net_rxhdr));
	ATF_CHECK(g_publish_calls == 1);
	ATF_CHECK(((struct virtio_net_rxhdr *)g_packet)->vrh_bufs == 1);
}

ATF_TC_WITHOUT_HEAD(config_write_bounds);
ATF_TC_BODY(config_write_bounds, tc)
{
	struct pci_vtnet_softc sc;
	uint8_t before[sizeof(sc.vsc_config.mac)];

	reset_mocks();
	setup_softc(&sc);
	memset(sc.vsc_config.mac, 0xa5, sizeof(sc.vsc_config.mac));
	memcpy(before, sc.vsc_config.mac, sizeof(before));
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 4, 4, 0) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac, sizeof(before)) == 0);
	ATF_CHECK(pci_vtnet_cfgwrite(&sc, 2, 4, 0x01020304) == 0);
	ATF_CHECK(memcmp(before, sc.vsc_config.mac, sizeof(before)) != 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transmit_validation);
	ATF_TP_ADD_TC(tp, receive_validation);
	ATF_TP_ADD_TC(tp, config_write_bounds);
	return (atf_no_error());
}

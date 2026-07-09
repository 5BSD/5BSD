/*
 * Guest-side vsock unit test: drives the REAL kernel socket domain + RX state
 * machine from sys/kern/uipc_vsock.c in userspace (via kmock.h), with a mock
 * vtvsock_transport that captures the packets the guest would emit on the
 * wire.  This is the mirror of vsock_device_harness (which tests the bhyve
 * host device); it covers the guest RX/credit/reset/feature logic that the
 * loopback-only ATF suite and the AF_UNIX-limited e2e suite cannot reach.
 */
#include "kmock.h"
#include "uipc_vsock.c"		/* the DUT: static functions become visible */

#include <atf-c.h>

/* ---- captured emitted packets (guest -> wire) ---- */
struct cap { uint16_t op; uint32_t flags, len; uint64_t dst_cid; uint32_t dst_port; };
static struct cap g_cap[64];
static int g_ncap;
static int g_credit_updates;

static int
mock_send_pkt(struct vtvsock_pcb *pcb, uint16_t op, uint32_t flags,
    const void *payload __unused, size_t len)
{
	struct cap *c = &g_cap[g_ncap++ % 64];
	c->op = op; c->flags = flags; c->len = (uint32_t)len;
	c->dst_cid = pcb->remote.svm_cid; c->dst_port = pcb->remote.svm_port;
	return (0);
}
static int
mock_send_rst(uint64_t scid __unused, uint32_t sport __unused,
    uint64_t dcid, uint32_t dport, uint16_t type __unused)
{
	struct cap *c = &g_cap[g_ncap++ % 64];
	c->op = VIRTIO_VSOCK_OP_RST; c->dst_cid = dcid; c->dst_port = dport;
	return (0);
}
static void mock_send_credit_update(struct vtvsock_pcb *pcb __unused) { g_credit_updates++; }
static int mock_send(struct vtvsock_pcb *p __unused, int f __unused,
    struct mbuf *m, struct sockaddr *a __unused, struct mbuf *c __unused,
    struct thread *t __unused) { m_freem(m); return (0); }
static int mock_disconnect(struct vtvsock_pcb *p __unused) { return (0); }
static int mock_shutdown(struct vtvsock_pcb *p __unused, enum shutdown_how h __unused) { return (0); }
static bool mock_tx_ready(struct vtvsock_pcb *p __unused) { return (true); }

static const struct vtvsock_transport mock_transport = {
	.send = mock_send, .disconnect = mock_disconnect, .shutdown = mock_shutdown,
	.tx_ready = mock_tx_ready, .send_pkt = mock_send_pkt,
	.send_rst = mock_send_rst, .send_credit_update = mock_send_credit_update,
};

static void
reset_state(void)
{
	g_ncap = 0; g_credit_updates = 0;
	/* fresh domain state each test */
	vtvsock_remote_transport = NULL;
	vtvsock_guest_cid = VSOCK_CID_LOCAL;
	vtvsock_remote_features = 0;
}

static void
register_mock(uint64_t cid, uint64_t features)
{
	mtx_lock(&vtvsock_mtx);
	vsock_transport_register_locked(&mock_transport, cid, features);
	mtx_unlock(&vtvsock_mtx);
}

/* Build a fresh socket + attach a pcb (as socreate would). */
static struct socket *
mk_socket(int type)
{
	struct socket *so = calloc(1, sizeof(*so));
	so->so_type = type;
	so->so_vnet = curvnet;
	if (vsock_attach(so, 0, NULL) != 0) { kfree(so); return (NULL); }
	return (so);
}

/* Bind + listen a socket on a port (guest listener). */
static int
bind_listen(struct socket *so, uint32_t port)
{
	struct sockaddr_vm sa;
	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_len = sizeof(sa);
	sa.svm_cid = VSOCK_CID_ANY;
	sa.svm_port = port;
	if (vsock_bind(so, (struct sockaddr *)&sa, NULL) != 0)
		return (-1);
	return (vsock_listen(so, 8, NULL));
}

static void
mkhdr(struct virtio_vsock_hdr *h, uint16_t op, uint16_t type, uint64_t scid,
    uint32_t sport, uint32_t dport, uint32_t len, uint32_t flags,
    uint32_t buf_alloc, uint32_t fwd_cnt)
{
	memset(h, 0, sizeof(*h));
	h->src_cid = htole64(scid); h->dst_cid = htole64(vtvsock_guest_cid);
	h->src_port = htole32(sport); h->dst_port = htole32(dport);
	h->len = htole32(len); h->type = htole16(type); h->op = htole16(op);
	h->flags = htole32(flags); h->buf_alloc = htole32(buf_alloc);
	h->fwd_cnt = htole32(fwd_cnt);
}

static int cap_count(uint16_t op)
{ int n = 0; for (int i = 0; i < g_ncap; i++) if (g_cap[i].op == op) n++; return (n); }

/* ================================================================= */

/* --- reserved CIDs must never become the guest CID (bind safety) --- */
ATF_TC_WITHOUT_HEAD(reserved_cid_sanitized);
ATF_TC_BODY(reserved_cid_sanitized, tc)
{
	reset_state();
	register_mock(VSOCK_CID_HYPERVISOR, 0);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
	register_mock(VSOCK_CID_HOST, 0);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
	register_mock(VSOCK_CID_ANY, 0);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
	register_mock(3, 0);			/* a valid CID is accepted */
	ATF_CHECK(vtvsock_guest_cid == 3);
}

/* --- feature negotiation gates SOCK_SEQPACKET / SOCK_STREAM at attach --- */
ATF_TC_WITHOUT_HEAD(feature_negotiation_gates);
ATF_TC_BODY(feature_negotiation_gates, tc)
{
	struct socket *so;

	/* Stream-only device: SEQPACKET socket must be refused. */
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	so = calloc(1, sizeof(*so));
	so->so_type = SOCK_SEQPACKET; so->so_vnet = curvnet;
	ATF_CHECK(vsock_attach(so, 0, NULL) == EPROTONOSUPPORT);
	kfree(so);

	/* Seqpacket-only + NO_IMPLIED_STREAM: STREAM socket must be refused. */
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_SEQPACKET |
	    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM);
	so = calloc(1, sizeof(*so));
	so->so_type = SOCK_STREAM; so->so_vnet = curvnet;
	ATF_CHECK(vsock_attach(so, 0, NULL) == EPROTONOSUPPORT);
	kfree(so);

	/* A device offering both admits both. */
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	so = mk_socket(SOCK_STREAM);
	ATF_CHECK(so != NULL);
	so = mk_socket(SOCK_SEQPACKET);
	ATF_CHECK(so != NULL);
}

/* --- credit accounting: available = peer_buf_alloc - (tx_cnt - peer_fwd_cnt),
 * wrap-correct, and G4 monotonic clamp on ingest --- */
ATF_TC_WITHOUT_HEAD(credit_arithmetic_and_clamp);
ATF_TC_BODY(credit_arithmetic_and_clamp, tc)
{
	struct socket *so;
	struct vtvsock_pcb *pcb;
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	so = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(so != NULL);
	pcb = so->so_pcb;

	pcb->peer_buf_alloc = 1000;
	pcb->tx_cnt = 700;
	pcb->peer_fwd_cnt = 200;
	/* used = 700 - 200 = 500; avail = 1000 - 500 = 500 */
	ATF_CHECK(vtvsock_credit_available(pcb) == 500);

	/* Full window consumed: no credit. */
	pcb->peer_fwd_cnt = 0; pcb->tx_cnt = 1000;
	ATF_CHECK(vtvsock_credit_available(pcb) == 0);

	/* Free-running wrap: tx_cnt just past 0, peer_fwd_cnt near UINT32_MAX. */
	pcb->tx_cnt = 5; pcb->peer_fwd_cnt = 0xfffffffb; /* used = 10 */
	pcb->peer_buf_alloc = 1000;
	ATF_CHECK(vtvsock_credit_available(pcb) == 990);
}

/* --- guest RX: a peer CREDIT_UPDATE claiming more consumed than we sent
 * (fwd_cnt > tx_cnt) is a protocol violation -> RST + teardown --- */
ATF_TC_WITHOUT_HEAD(rx_peer_fwd_cnt_spoof_rst);
ATF_TC_BODY(rx_peer_fwd_cnt_spoof_rst, tc)
{
	struct socket *lso;
	struct virtio_vsock_hdr h;
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	lso = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(lso != NULL);
	ATF_REQUIRE(bind_listen(lso, 80) == 0);

	/* Inbound OP_REQUEST establishes a child; guest emits OP_RESPONSE. */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
	    2 /* host */, 1234, 80, 0, 0, 65536, 0);
	vsock_rx_packet(&h, sizeof(h));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 1);

	/* Now a spoofed CREDIT_UPDATE: fwd_cnt (5000) > our tx_cnt (0). */
	g_ncap = 0;
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, VIRTIO_VSOCK_TYPE_STREAM,
	    2, 1234, 80, 0, 0, 65536, 5000);
	vsock_rx_packet(&h, sizeof(h));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);	/* teardown with RST */
}

/* sonewconn in the DUT's TU so it can reach static vsock_attach + protosw. */
struct socket *
vsock_kmock_sonewconn(struct socket *head, int connstatus)
{
	struct socket *so = calloc(1, sizeof(*so));
	if (so == NULL) return (NULL);
	so->so_type = head->so_type;
	so->so_vnet = head->so_vnet;
	so->so_rcv.sb_hiwat = head->sol_sbrcv_hiwat ? head->sol_sbrcv_hiwat
	    : head->so_rcv.sb_hiwat;
	so->so_snd.sb_hiwat = so->so_rcv.sb_hiwat;
	if (vsock_attach(so, 0, NULL) != 0) { kfree(so); return (NULL); }
	if (connstatus) soisconnected(so);
	return (so);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reserved_cid_sanitized);
	ATF_TP_ADD_TC(tp, feature_negotiation_gates);
	ATF_TP_ADD_TC(tp, credit_arithmetic_and_clamp);
	ATF_TP_ADD_TC(tp, rx_peer_fwd_cnt_spoof_rst);
	return (atf_no_error());
}

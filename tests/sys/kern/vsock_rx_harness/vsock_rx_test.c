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

/* Every synthetic packet is delivered by the registered mock transport. */
#define	vsock_rx_packet(buf, len) \
	vsock_rx_packet(&mock_transport, (buf), (len))

/* ---- captured emitted packets (guest -> wire) ---- */
struct cap { uint16_t op; uint32_t flags, len; uint64_t dst_cid; uint32_t dst_port; };
static struct cap g_cap[64];
static int g_ncap;
static int g_credit_updates;
static bool g_tx_ready;
static int g_send_calls;
static int g_last_send_flags;
static int g_last_send_mflags;
static int g_last_send_len;
static int g_send_len[4];
static int g_send_error;
int vsock_kmock_sock_lock_calls;
int vsock_kmock_sock_lock_depth;
int vsock_kmock_sndbuf_lock_calls;
int vsock_kmock_sndbuf_lock_depth;
int vsock_kmock_record_pkthdrs;
int vsock_kmock_record_pkthdr_len;
int vsock_kmock_record_len;
int vsock_kmock_record_mflags;

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
static int mock_send(struct vtvsock_pcb *p __unused, int f,
    struct mbuf *m, struct sockaddr *a __unused, struct mbuf *c __unused,
    struct thread *t __unused)
{
	g_send_calls++;
	g_last_send_flags = f;
	g_last_send_mflags = m->m_flags;
	g_last_send_len = m_length(m, NULL);
	if (g_send_calls <= (int)nitems(g_send_len))
		g_send_len[g_send_calls - 1] = g_last_send_len;
	m_freem(m);
	return (g_send_error);
}
static int mock_disconnect(struct vtvsock_pcb *p __unused) { return (0); }
static int mock_shutdown(struct vtvsock_pcb *p __unused, enum shutdown_how h __unused) { return (0); }
static bool mock_tx_ready(struct vtvsock_pcb *p __unused) { return (g_tx_ready); }

static const struct vtvsock_transport mock_transport = {
	.send = mock_send, .disconnect = mock_disconnect, .shutdown = mock_shutdown,
	.tx_ready = mock_tx_ready, .send_pkt = mock_send_pkt,
	.send_rst = mock_send_rst, .send_credit_update = mock_send_credit_update,
};

static void register_mock(uint64_t, uint64_t);
static void mkhdr(struct virtio_vsock_hdr *, uint16_t, uint16_t, uint64_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static struct vtvsock_pcb *establish_remote(int, uint32_t, uint32_t,
    struct socket **);

static void
reset_state(void)
{
	/* The sanitizer runner executes all cases in one process.  Close remote
	 * PCBs left by a successful-path test so counts and tuples cannot leak
	 * into the next case; real ATF runs each case in a fresh process. */
	mtx_lock(&vtvsock_mtx);
	vsock_transport_reset_locked();
	mtx_unlock(&vtvsock_mtx);
	g_ncap = 0; g_credit_updates = 0;
	g_tx_ready = true;
	g_send_calls = 0;
	g_last_send_flags = 0;
	g_send_error = 0;
	g_last_send_mflags = 0;
	g_last_send_len = 0;
	memset(g_send_len, 0, sizeof(g_send_len));
	vsock_kmock_sock_lock_calls = 0;
	vsock_kmock_sock_lock_depth = 0;
	vsock_kmock_sndbuf_lock_calls = 0;
	vsock_kmock_sndbuf_lock_depth = 0;
	vsock_kmock_record_pkthdrs = 0;
	vsock_kmock_record_pkthdr_len = 0;
	vsock_kmock_record_len = 0;
	vsock_kmock_record_mflags = 0;
	/* fresh domain state each test */
	vtvsock_remote_transport = NULL;
	vtvsock_remote_transport_owner = NULL;
	vtvsock_guest_cid = VSOCK_CID_LOCAL;
	vtvsock_remote_features = 0;
}

ATF_TC_WITHOUT_HEAD(seqpacket_rx_eor_follows_wire_flag);
ATF_TC_BODY(seqpacket_rx_eor_follows_wire_flag, tc)
{
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(*h) + 8];

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	pcb = establish_remote(SOCK_SEQPACKET, 94, 1251, NULL);
	ATF_REQUIRE(pcb != NULL);
	h = (struct virtio_vsock_hdr *)pkt;
	memset(pkt + sizeof(*h), 0x6b, 8);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_SEQPACKET,
	    VSOCK_CID_HOST, 1251, 94, 8,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR, 65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK((vsock_kmock_record_mflags & M_EOR) != 0);
}

ATF_TC_WITHOUT_HEAD(rx_mbuf_chain_copy);
ATF_TC_BODY(rx_mbuf_chain_copy, tc)
{
	struct mbuf *m, *n;
	uint8_t payload[MLEN * 2 + 37];
	size_t offset;
	int headers;

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i * 29 + 7);
	m = vsock_mbuf_from_buffer(payload, sizeof(payload));
	ATF_REQUIRE(m != NULL);
	ATF_CHECK(m->m_pkthdr.len == sizeof(payload));
	offset = 0;
	headers = 0;
	for (n = m; n != NULL; n = n->m_next) {
		ATF_CHECK(n->m_len > 0);
		ATF_CHECK(memcmp(n->m_data, payload + offset, n->m_len) == 0);
		offset += n->m_len;
		if ((n->m_flags & M_PKTHDR) != 0)
			headers++;
	}
	ATF_CHECK(offset == sizeof(payload));
	ATF_CHECK(headers == 1);
	m_freem(m);
}

ATF_TC_WITHOUT_HEAD(seqpacket_fragment_mbuf_headers);
ATF_TC_BODY(seqpacket_fragment_mbuf_headers, tc)
{
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(*h) + 32];

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	pcb = establish_remote(SOCK_SEQPACKET, 90, 1247, NULL);
	ATF_REQUIRE(pcb != NULL);
	h = (struct virtio_vsock_hdr *)pkt;
	memset(pkt + sizeof(*h), 0x5a, 32);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_SEQPACKET,
	    VSOCK_CID_HOST, 1247, 90, 32, 0, 65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK(pcb->seqpacket_partial != NULL);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_SEQPACKET,
	    VSOCK_CID_HOST, 1247, 90, 32, VIRTIO_VSOCK_SEQ_EOM,
	    65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK(pcb->seqpacket_partial == NULL);
	ATF_CHECK(vsock_kmock_record_pkthdrs == 1);
	ATF_CHECK(vsock_kmock_record_pkthdr_len == 64);
	ATF_CHECK(vsock_kmock_record_len == 64);
}
static void
register_mock(uint64_t cid, uint64_t features)
{
	mtx_lock(&vtvsock_mtx);
	ATF_REQUIRE(vsock_transport_register_locked(&mock_transport,
	    &mock_transport, cid, features) == 0);
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

static int
bind_listen_cid(struct socket *so, uint32_t cid, uint32_t port)
{
	struct sockaddr_vm sa;

	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_len = sizeof(sa);
	sa.svm_cid = cid;
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

static struct vtvsock_pcb *
establish_remote(int socket_type, uint32_t local_port, uint32_t peer_port,
    struct socket **listenerp)
{
	struct socket *listener;
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr h;
	uint16_t wire_type;

	wire_type = socket_type == SOCK_SEQPACKET ?
	    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM;
	listener = mk_socket(socket_type);
	if (listener == NULL || bind_listen(listener, local_port) != 0)
		return (NULL);
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, wire_type, VSOCK_CID_HOST,
	    peer_port, local_port, 0, 0, 65536, 0);
	vsock_rx_packet(&h, sizeof(h));
	mtx_lock(&vtvsock_mtx);
	pcb = vtvsock_pcb_lookup_connected_locked(VSOCK_CID_HOST, peer_port,
	    vtvsock_guest_cid, local_port);
	mtx_unlock(&vtvsock_mtx);
	if (listenerp != NULL)
		*listenerp = listener;
	return (pcb);
}

/* ================================================================= */

/* --- invalid local CIDs fall back to loopback; HOST is valid for a
 * host-side userspace transport. --- */
ATF_TC_WITHOUT_HEAD(reserved_cid_sanitized);
ATF_TC_BODY(reserved_cid_sanitized, tc)
{
	reset_state();
	register_mock(VSOCK_CID_HYPERVISOR, 0);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
	register_mock(VSOCK_CID_HOST, 0);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_HOST);
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

/* --- guest RX: an established connection whose peer sends more than our
 * advertised receive buffer allows is a flow-control violation -> RST with
 * ECONNRESET (the ONLY established-conn ECONNRESET path; loopback can't reach
 * it, so nothing else covers it). --- */
ATF_TC_WITHOUT_HEAD(rx_flow_control_violation_rst);
ATF_TC_BODY(rx_flow_control_violation_rst, tc)
{
	struct socket *lso;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(struct virtio_vsock_hdr) + 200];
	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	lso = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(lso != NULL);
	/* Small receive buffer so a modest record overflows it; the child
	 * inherits this as its advertised buf_alloc. */
	lso->so_rcv.sb_hiwat = 100;
	lso->sol_sbrcv_hiwat = 100;
	ATF_REQUIRE(bind_listen(lso, 81) == 0);	/* distinct port: tests share
						 * global pcb lists */

	/* Establish a child via OP_REQUEST. */
	h = (struct virtio_vsock_hdr *)pkt;
	mkhdr(h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
	    2, 1235, 81, 0, 0, 65536, 0);
	vsock_rx_packet(pkt, sizeof(*h));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 1);

	/* OP_RW carrying 200 bytes into a 100-byte window: flow-control
	 * violation -> RST.  Payload present so payload_len == 200. */
	g_ncap = 0;
	memset(pkt + sizeof(*h), 'D', 200);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_STREAM,
	    2, 1235, 81, 200, 0, 65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);	/* violation -> RST */
}

/* --- A CID_LOCAL listener is loopback-only: a remote REQUEST cannot match
 * it, and a socket explicitly bound to CID_LOCAL cannot emit a remote wire
 * REQUEST with CID 1 as its source. --- */
ATF_TC_WITHOUT_HEAD(cid_local_wire_isolation);
ATF_TC_BODY(cid_local_wire_isolation, tc)
{
	struct sockaddr_vm local, remote;
	struct socket *listener, *client;
	struct virtio_vsock_hdr h;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	listener = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(listener != NULL);
	ATF_REQUIRE(bind_listen_cid(listener, VSOCK_CID_LOCAL, 82) == 0);

	/* The packet targets the transport-assigned guest CID, not CID_LOCAL. */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1236, 82, 0, 0, 65536, 0);
	vsock_rx_packet(&h, sizeof(h));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 0);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);

	client = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(client != NULL);
	memset(&local, 0, sizeof(local));
	local.svm_family = AF_VSOCK;
	local.svm_len = sizeof(local);
	local.svm_cid = VSOCK_CID_LOCAL;
	local.svm_port = 2082;
	ATF_REQUIRE(vsock_bind(client, (struct sockaddr *)&local, NULL) == 0);
	memset(&remote, 0, sizeof(remote));
	remote.svm_family = AF_VSOCK;
	remote.svm_len = sizeof(remote);
	remote.svm_cid = VSOCK_CID_HOST;
	remote.svm_port = 8082;
	g_ncap = 0;
	ATF_CHECK(vsock_connect(client, (struct sockaddr *)&remote, NULL) ==
	    EADDRNOTAVAIL);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_REQUEST) == 0);
}

/* --- Too many non-EOM SEQPACKET fragments force an RST and report the
 * peer-caused loss as ECONNRESET. --- */
ATF_TC_WITHOUT_HEAD(seqpacket_fragment_limit_rst);
ATF_TC_BODY(seqpacket_fragment_limit_rst, tc)
{
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(struct virtio_vsock_hdr) + 1];
	u_int saved_frag_max;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	pcb = establish_remote(SOCK_SEQPACKET, 83, 1237, NULL);
	ATF_REQUIRE(pcb != NULL);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 1);

	saved_frag_max = vtvsock_seqpacket_frag_max;
	vtvsock_seqpacket_frag_max = 2;
	g_ncap = 0;
	h = (struct virtio_vsock_hdr *)pkt;
	pkt[sizeof(*h)] = 'F';
	for (int i = 0; i < 3; i++) {
		mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_SEQPACKET,
		    VSOCK_CID_HOST, 1237, 83, 1, 0, 65536, 0);
		vsock_rx_packet(pkt, sizeof(pkt));
	}
	vtvsock_seqpacket_frag_max = saved_frag_max;
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);
	ATF_CHECK(pcb->state == VTVSOCK_CLOSED);
	ATF_CHECK(pcb->so->so_error == ECONNRESET);
	ATF_CHECK((pcb->so->so_state & SS_ISDISCONNECTED) != 0);
}

/* --- Full peer shutdown with unread data removes the tuple immediately but
 * defers the final RST until the bounded close callout fires. --- */
ATF_TC_WITHOUT_HEAD(deferred_shutdown_timeout);
ATF_TC_BODY(deferred_shutdown_timeout, tc)
{
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(struct virtio_vsock_hdr) + 4];

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 84, 1238, NULL);
	ATF_REQUIRE(pcb != NULL);
	g_ncap = 0;
	h = (struct virtio_vsock_hdr *)pkt;
	memcpy(pkt + sizeof(*h), "data", 4);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1238, 84, 4, 0, 65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK(pcb->rx_bytes == 4);
	ATF_CHECK(pcb->so->so_rcv.sb_cc == 4);

	mkhdr(h, VIRTIO_VSOCK_OP_SHUTDOWN, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1238, 84, 0,
	    VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND,
	    65536, 0);
	vsock_rx_packet(pkt, sizeof(*h));
	ATF_CHECK(pcb->state == VTVSOCK_ESTABLISHED);
	ATF_CHECK(!pcb->on_connlist);
	ATF_CHECK(callout_active(&pcb->close_callout));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 0);

	pcb->close_callout.active = 0;
	pcb->close_callout.fn(pcb->close_callout.arg);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);
	ATF_CHECK(pcb->state == VTVSOCK_CLOSED);
	ATF_CHECK((pcb->so->so_state & SS_ISDISCONNECTED) != 0);
}

/* --- Transport removal resets every live remote connection and a subsequent
 * registration updates non-local listeners to the replacement guest CID. --- */
ATF_TC_WITHOUT_HEAD(transport_reset_and_reregister);
ATF_TC_BODY(transport_reset_and_reregister, tc)
{
	struct socket *listener;
	struct vtvsock_pcb *pcb;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 85, 1239, &listener);
	ATF_REQUIRE(pcb != NULL);
	ATF_CHECK(pcb->state == VTVSOCK_ESTABLISHED);
	ATF_CHECK(pcb->on_connlist);

	vsock_transport_unregister(&mock_transport);
	ATF_CHECK(vtvsock_remote_transport == NULL);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
	ATF_CHECK(pcb->state == VTVSOCK_CLOSED);
	ATF_CHECK(!pcb->on_connlist);
	ATF_CHECK(pcb->so->so_error == ECONNRESET);
	ATF_CHECK((pcb->so->so_state & SS_ISDISCONNECTED) != 0);

	register_mock(4, VIRTIO_VSOCK_F_STREAM);
	ATF_CHECK(((struct vtvsock_pcb *)listener->so_pcb)->local.svm_cid == 4);
}

/* --- A second transport cannot replace the active transport, and an
 * unrelated detach cannot unregister it. --- */
ATF_TC_WITHOUT_HEAD(transport_registration_is_owner_scoped);
ATF_TC_BODY(transport_registration_is_owner_scoped, tc)
{
	static const int owner1, owner2;

	reset_state();
	ATF_CHECK(vsock_transport_register(&mock_transport, &owner1, 3,
	    VIRTIO_VSOCK_F_STREAM) == 0);
	ATF_CHECK(vsock_transport_register(&mock_transport, &owner2, 4,
	    VIRTIO_VSOCK_F_STREAM) == EBUSY);
	ATF_CHECK(vtvsock_remote_transport == &mock_transport);
	ATF_CHECK(vtvsock_remote_transport_owner == &owner1);
	ATF_CHECK(vtvsock_guest_cid == 3);

	vsock_transport_unregister(&owner2);
	ATF_CHECK(vtvsock_remote_transport == &mock_transport);
	ATF_CHECK(vtvsock_remote_transport_owner == &owner1);
	ATF_CHECK(vtvsock_guest_cid == 3);

	vsock_transport_unregister(&owner1);
	ATF_CHECK(vtvsock_remote_transport == NULL);
	ATF_CHECK(vtvsock_remote_transport_owner == NULL);
	ATF_CHECK(vtvsock_guest_cid == VSOCK_CID_LOCAL);
}

/* --- The non-blocking TX-ring gate must return before m_uiotombuf consumes
 * the caller's uio; otherwise a full transport ring becomes silent loss. --- */
ATF_TC_WITHOUT_HEAD(nonblocking_tx_not_consumed_when_ring_full);
ATF_TC_BODY(nonblocking_tx_not_consumed_when_ring_full, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char data[] = "send";

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 86, 1240, NULL);
	ATF_REQUIRE(pcb != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = sizeof(data) - 1;
	g_tx_ready = false;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL,
	    MSG_DONTWAIT, NULL) == EWOULDBLOCK);
	ATF_CHECK(uio.uio_resid == (ssize_t)(sizeof(data) - 1));
	ATF_CHECK(g_send_calls == 0);

	g_tx_ready = true;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL,
	    MSG_DONTWAIT, NULL) == 0);
	ATF_CHECK(uio.uio_resid == 0);
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK((g_last_send_flags & VTVSOCK_SEND_F_NONBLOCK) != 0);
	ATF_CHECK(g_last_send_len == (int)(sizeof(data) - 1));
}

/* --- Capacity can disappear after tx_ready() when another socket shares the
 * transport.  A post-copy transient error must not advance the caller. --- */
ATF_TC_WITHOUT_HEAD(post_copy_send_error_preserves_uio);
ATF_TC_BODY(post_copy_send_error_preserves_uio, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char data[] = "race";

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 92, 1249, NULL);
	ATF_REQUIRE(pcb != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = sizeof(data) - 1;
	g_tx_ready = true;
	g_send_error = EWOULDBLOCK;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL,
	    MSG_DONTWAIT, NULL) == EWOULDBLOCK);
	ATF_CHECK(uio.uio_resid == (ssize_t)(sizeof(data) - 1));
	ATF_CHECK(iov.iov_len == sizeof(data) - 1);
	ATF_CHECK(g_send_calls == 1);

	g_send_error = 0;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL,
	    MSG_DONTWAIT, NULL) == 0);
	ATF_CHECK(uio.uio_resid == 0);
}

/* --- One remote STREAM transport call carries at most one wire packet, so
 * an error cannot follow an unreportable partially enqueued chunk. --- */
ATF_TC_WITHOUT_HEAD(remote_stream_send_is_packet_atomic);
ATF_TC_BODY(remote_stream_send_is_packet_atomic, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char *data;
	size_t len;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 91, 1248, NULL);
	ATF_REQUIRE(pcb != NULL);
	len = VSOCK_TRANSPORT_MAX_PAYLOAD + 17;
	data = calloc(1, len);
	ATF_REQUIRE(data != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = data;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = len;
	pcb->peer_buf_alloc = len;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL, 0, NULL) == 0);
	ATF_CHECK(uio.uio_resid == 0);
	ATF_CHECK(g_send_calls == 2);
	ATF_CHECK(g_send_len[0] == VSOCK_TRANSPORT_MAX_PAYLOAD);
	ATF_CHECK(g_send_len[1] == 17);
	kfree(data);
}

/* --- Send-side terminal state is read under its owning locks.  In
 * particular, serializing the so_error read-and-clear with asynchronous
 * reset writers prevents a new error store from being erased by a racing
 * clear. --- */
ATF_TC_WITHOUT_HEAD(send_terminal_state_checks_are_locked);
ATF_TC_BODY(send_terminal_state_checks_are_locked, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char data[] = "state";

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 89, 1246, NULL);
	ATF_REQUIRE(pcb != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = sizeof(data) - 1;

	vsock_kmock_sndbuf_lock_calls = 0;
	pcb->so->so_snd.sb_state |= SBS_CANTSENDMORE;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL, 0, NULL) ==
	    EPIPE);
	ATF_CHECK(vsock_kmock_sndbuf_lock_calls == 1);
	ATF_CHECK(vsock_kmock_sndbuf_lock_depth == 0);
	ATF_CHECK(uio.uio_resid == (ssize_t)(sizeof(data) - 1));

	pcb->so->so_snd.sb_state &= ~SBS_CANTSENDMORE;
	pcb->so->so_error = ECONNRESET;
	vsock_kmock_sock_lock_calls = 0;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL, 0, NULL) ==
	    ECONNRESET);
	ATF_CHECK(vsock_kmock_sock_lock_calls == 1);
	ATF_CHECK(vsock_kmock_sock_lock_depth == 0);
	ATF_CHECK(pcb->so->so_error == 0);
	ATF_CHECK(uio.uio_resid == (ssize_t)(sizeof(data) - 1));
}

/* --- VirtIO EOM delimits every message; EOR is present only when the sender
 * supplied MSG_EOR.  M_PROTO1 is the transport marker for that EOR. --- */
ATF_TC_WITHOUT_HEAD(seqpacket_msg_eor_transport_marker);
ATF_TC_BODY(seqpacket_msg_eor_transport_marker, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char data[] = "eor";

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	pcb = establish_remote(SOCK_SEQPACKET, 87, 1241, NULL);
	ATF_REQUIRE(pcb != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = sizeof(data) - 1;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL,
	    MSG_EOR, NULL) == 0);
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK((g_last_send_mflags & M_EOR) != 0);
	ATF_CHECK((g_last_send_mflags & M_PROTO1) != 0);

	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = sizeof(data) - 1;
	g_send_calls = 0;
	g_last_send_mflags = 0;
	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL, 0, NULL) == 0);
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK((g_last_send_mflags & M_EOR) == 0);
	ATF_CHECK((g_last_send_mflags & M_PROTO1) == 0);
}

/* --- Atomic socket records, including empty ones, carry an mbuf packet
 * header.  soreceive relies on the same invariant as the generic send path. --- */
ATF_TC_WITHOUT_HEAD(seqpacket_zero_length_has_packet_header);
ATF_TC_BODY(seqpacket_zero_length_has_packet_header, tc)
{
	struct vtvsock_pcb *pcb;
	struct iovec iov;
	struct uio uio;
	char data;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_SEQPACKET);
	pcb = establish_remote(SOCK_SEQPACKET, 95, 1252, NULL);
	ATF_REQUIRE(pcb != NULL);
	memset(&uio, 0, sizeof(uio));
	iov.iov_base = &data;
	iov.iov_len = 0;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = 0;

	ATF_CHECK(vsock_sosend(pcb->so, NULL, &uio, NULL, NULL, 0, NULL) == 0);
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK(g_last_send_len == 0);
	ATF_CHECK((g_last_send_mflags & M_PKTHDR) != 0);
	ATF_CHECK((g_last_send_mflags & (M_EOR | M_PROTO1)) == 0);
}

/* --- A packet shorter than hdr.len is malformed, not a truncated message. --- */
ATF_TC_WITHOUT_HEAD(rx_truncated_payload_is_rejected);
ATF_TC_BODY(rx_truncated_payload_is_rejected, tc)
{
	struct vtvsock_pcb *pcb;
	struct virtio_vsock_hdr *h;
	uint8_t pkt[sizeof(*h) + 4];

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	pcb = establish_remote(SOCK_STREAM, 93, 1250, NULL);
	ATF_REQUIRE(pcb != NULL);
	h = (struct virtio_vsock_hdr *)pkt;
	memset(pkt + sizeof(*h), 0xa5, 4);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1250, 93, 8, 0, 65536, 0);
	vsock_rx_packet(pkt, sizeof(pkt));
	ATF_CHECK(pcb->so->so_rcv.sb_cc == 0);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);
}

/* --- The guest-side global connection cap rejects excess REQUESTs and a
 * peer RST immediately releases a slot for another connection. --- */
ATF_TC_WITHOUT_HEAD(inbound_connection_cap_reclaims_slot);
ATF_TC_BODY(inbound_connection_cap_reclaims_slot, tc)
{
	struct socket *listener;
	struct virtio_vsock_hdr h;
	u_int saved_max_conn;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	listener = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(listener != NULL);
	ATF_REQUIRE(bind_listen(listener, 88) == 0);
	saved_max_conn = vtvsock_max_conn;
	vtvsock_max_conn = 2;

	for (uint32_t peer_port = 1242; peer_port <= 1244; peer_port++) {
		mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
		    VSOCK_CID_HOST, peer_port, 88, 0, 0, 65536, 0);
		vsock_rx_packet(&h, sizeof(h));
	}
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 2);
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RST) == 1);
	ATF_CHECK(vtvsock_conn_count == 2);

	mkhdr(&h, VIRTIO_VSOCK_OP_RST, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1242, 88, 0, 0, 0, 0);
	vsock_rx_packet(&h, sizeof(h));
	ATF_CHECK(vtvsock_conn_count == 1);
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1245, 88, 0, 0, 65536, 0);
	vsock_rx_packet(&h, sizeof(h));
	ATF_CHECK(cap_count(VIRTIO_VSOCK_OP_RESPONSE) == 3);
	ATF_CHECK(vtvsock_conn_count == 2);
	vtvsock_max_conn = saved_max_conn;
}

ATF_TC_WITHOUT_HEAD(stale_transport_packet_is_dropped);
ATF_TC_BODY(stale_transport_packet_is_dropped, tc)
{
	struct socket *listener;
	struct virtio_vsock_hdr h;
	int stale_owner = 0;

	reset_state();
	register_mock(3, VIRTIO_VSOCK_F_STREAM);
	listener = mk_socket(SOCK_STREAM);
	ATF_REQUIRE(listener != NULL);
	ATF_REQUIRE(bind_listen(listener, 96) == 0);
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, VIRTIO_VSOCK_TYPE_STREAM,
	    VSOCK_CID_HOST, 1253, 96, 0, 0, 65536, 0);
	(vsock_rx_packet)(&stale_owner, &h, sizeof(h));
	ATF_CHECK(vtvsock_conn_count == 0);
	ATF_CHECK(g_ncap == 0);
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
	ATF_TP_ADD_TC(tp, rx_flow_control_violation_rst);
	ATF_TP_ADD_TC(tp, cid_local_wire_isolation);
	ATF_TP_ADD_TC(tp, seqpacket_rx_eor_follows_wire_flag);
	ATF_TP_ADD_TC(tp, rx_mbuf_chain_copy);
	ATF_TP_ADD_TC(tp, seqpacket_fragment_mbuf_headers);
	ATF_TP_ADD_TC(tp, seqpacket_fragment_limit_rst);
	ATF_TP_ADD_TC(tp, deferred_shutdown_timeout);
	ATF_TP_ADD_TC(tp, transport_reset_and_reregister);
	ATF_TP_ADD_TC(tp, transport_registration_is_owner_scoped);
	ATF_TP_ADD_TC(tp, nonblocking_tx_not_consumed_when_ring_full);
	ATF_TP_ADD_TC(tp, post_copy_send_error_preserves_uio);
	ATF_TP_ADD_TC(tp, remote_stream_send_is_packet_atomic);
	ATF_TP_ADD_TC(tp, send_terminal_state_checks_are_locked);
	ATF_TP_ADD_TC(tp, seqpacket_msg_eor_transport_marker);
	ATF_TP_ADD_TC(tp, seqpacket_zero_length_has_packet_header);
	ATF_TP_ADD_TC(tp, rx_truncated_payload_is_rejected);
	ATF_TP_ADD_TC(tp, inbound_connection_cap_reclaims_slot);
	ATF_TP_ADD_TC(tp, stale_transport_packet_is_dropped);
	return (atf_no_error());
}

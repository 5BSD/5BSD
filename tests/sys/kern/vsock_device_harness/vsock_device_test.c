/*
 * Device-level ATF test for the bhyve virtio-vsock TX ingress state machine.
 * Drives the real (static) vtvsock_process_tx_pkt() from pci_virtio_vsock.c
 * with crafted guest headers, mocking the virtio RX ring (to capture packets
 * the device injects back to the guest) and the host-socket syscalls
 * (via ld --wrap).  See README.md and the Makefile knobs in
 * tests/sys/kern/Makefile.
 */
#define WITHOUT_CAPSICUM
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <atf-c.h>

/*
 * The device's SEQPACKET RX probe uses recvmsg(), which is NOT in the tests
 * Makefile's ld --wrap set, so we shadow it with a plain definition below (the
 * program's definition overrides libc's).  AddressSanitizer, however, provides
 * its own recvmsg interceptor as a strong symbol in a static archive, which
 * collides with ours.  When built under ASan (the local run.sh helper), omit
 * the mock and the two recvmsg-dependent cases; the real ATF build (no ASan)
 * exercises them fully.
 */
#if (defined(__has_feature) && __has_feature(address_sanitizer)) || \
    defined(__SANITIZE_ADDRESS__)
#define	VSOCK_HARNESS_NO_RECVMSG_MOCK	1
#endif

/* Device under test (its quote-includes resolve to the mock headers here). */
#include "pci_virtio_vsock.c"

/* ---- captured packets injected toward the guest (RX ring) ---- */
struct cap_pkt { uint16_t op, type; uint32_t src_port, dst_port, len, flags,
    buf_alloc, fwd_cnt; };
static struct cap_pkt g_inject[128];
static int g_ninject;
static int g_rx_descs = 256;
static uint8_t g_rxbuf[64 * 1024 + 128];
/*
 * Descriptor direction reported by the mocked vq_getchain(): defaults to a
 * write-only RX chain (readable=0, writable=1), the shape a well-behaved guest
 * posts on the RX ring.  Tests flip these to exercise the §5.10.6.4 direction
 * checks.  When g_getchain_consumes is set, vq_getchain() decrements g_rx_descs
 * itself so a notify loop that drops every chain still terminates.
 */
static int g_chain_readable = 0;
static int g_chain_writable = 1;
static int g_getchain_consumes;

/* ---- host-socket syscall effects ---- */
static int g_next_fd = 500;
static int g_connectat_result;
static uint8_t g_send_buf[65536];
static size_t g_send_len;
static int g_send_calls;

/* ================= mock virtio RX ring ================= */
int vq_has_descs(struct vqueue_info *vq) { (void)vq; return (g_rx_descs > 0); }
int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{
	(void)vq;
	if (niov < 1 || g_rx_descs <= 0)
		return (0);
	iov[0].iov_base = g_rxbuf;
	iov[0].iov_len = sizeof(g_rxbuf);
	req->idx = 0;
	req->readable = g_chain_readable;
	req->writable = g_chain_writable;
	if (g_getchain_consumes)
		g_rx_descs--;		/* let drop-everything loops terminate */
	return (1);
}
void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t len)
{
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;
	struct cap_pkt *p;

	(void)vq; (void)idx;
	if (len < sizeof(*h))
		return;			/* a drop (relchain with len 0) */
	p = &g_inject[g_ninject++];
	p->op = le16toh(h->op);
	p->type = le16toh(h->type);
	p->src_port = le32toh(h->src_port);
	p->dst_port = le32toh(h->dst_port);
	p->len = le32toh(h->len);
	p->flags = le32toh(h->flags);
	p->buf_alloc = le32toh(h->buf_alloc);
	p->fwd_cnt = le32toh(h->fwd_cnt);
	g_rx_descs--;
}
void vq_endchains(struct vqueue_info *vq, int i) { (void)vq; (void)i; }

/* ================= mock mevent / virtio glue ================= */
static struct mevent { int fd; } g_mev[128];
static int g_nmev;
struct mevent *
mevent_add(int fd, enum ev_type t, void (*cb)(int, enum ev_type, void *),
    void *p)
{
	struct mevent *m;
	(void)t; (void)cb; (void)p;
	m = &g_mev[g_nmev++ % 128];
	m->fd = fd;
	return (m);
}
int mevent_enable(struct mevent *m) { (void)m; return (0); }
int mevent_disable(struct mevent *m) { (void)m; return (0); }
int mevent_delete(struct mevent *m) { (void)m; return (0); }
int mevent_delete_close(struct mevent *m) { if (m) (void)close(m->fd); return (0); }

void vi_softc_linkup(struct virtio_softc *a, struct virtio_consts *b, void *c,
    struct pci_devinst *d, struct vqueue_info *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
int vi_intr_init(struct virtio_softc *a, int b, int c)
{ (void)a; (void)b; (void)c; return (0); }
void vi_set_io_bar(struct virtio_softc *a, int b) { (void)a; (void)b; }
void vi_reset_dev(struct virtio_softc *a) { (void)a; }
uint64_t vi_pci_read(struct pci_devinst *a, int b, uint64_t c, int d)
{ (void)a; (void)b; (void)c; (void)d; return (0); }
void vi_pci_write(struct pci_devinst *a, int b, uint64_t c, int d, uint64_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
void pci_set_cfgdata8(struct pci_devinst *a, int b, uint8_t c)
{ (void)a; (void)b; (void)c; }
void pci_set_cfgdata16(struct pci_devinst *a, int b, uint16_t c)
{ (void)a; (void)b; (void)c; }
int fbsdrun_virtio_msix(void) { return (1); }
const char *get_config_value_node(const nvlist_t *n, const char *k)
{ (void)n; (void)k; return (NULL); }
void set_config_value_node(nvlist_t *n, const char *k, const char *v)
{ (void)n; (void)k; (void)v; }

/* ================= wrapped host-socket syscalls ================= */
int __wrap_socket(int a, int b, int c) { (void)a; (void)b; (void)c; return (g_next_fd++); }
int
__wrap_connectat(int dfd, int s, const struct sockaddr *a, socklen_t l)
{
	(void)dfd; (void)s; (void)a; (void)l;
	if (g_connectat_result < 0)
		errno = ECONNREFUSED;
	return (g_connectat_result);
}
static int g_send_flags;	/* flags from the most recent send() */
ssize_t
__wrap_send(int fd, const void *b, size_t n, int f)
{
	(void)fd;
	if (b != NULL && n <= sizeof(g_send_buf))
		memcpy(g_send_buf, b, n);
	g_send_len = n;
	g_send_flags = f;
	g_send_calls++;
	return ((ssize_t)n);
}
/* Staged host->guest data returned by recv(); default is "no data" (EAGAIN). */
static uint8_t g_recv_data[256 * 1024];
static size_t g_recv_len;	/* total staged bytes (one host message) */
static size_t g_recv_off;	/* bytes already consumed by recv() */
static int g_recv_eof;		/* when set, recv() returns 0 (EOF) once drained */
static int g_recv_zero_dgram;	/* a real 0-length SEQPACKET record is queued */
ssize_t
__wrap_recv(int fd, void *b, size_t n, int f)
{
	size_t avail, take;

	(void)fd;
	avail = g_recv_len - g_recv_off;
	if (avail == 0) {
		if (g_recv_eof)
			return (0);	/* peer closed */
		errno = EAGAIN;
		return (-1);
	}
	take = MIN(n, avail);
	if (b != NULL && (f & MSG_TRUNC) == 0)
		memcpy(b, g_recv_data + g_recv_off, take);
	if (f & MSG_PEEK)			/* SEQPACKET size probe */
		return (f & MSG_TRUNC) ? (ssize_t)avail : (ssize_t)take;
	g_recv_off += take;
	return (ssize_t)take;
}
ssize_t __wrap_sendmsg(int fd, const struct msghdr *m, int f)
{ (void)fd; (void)f; return (m->msg_iovlen ? (ssize_t)m->msg_iov[0].iov_len : 0); }
/*
 * recvmsg() is NOT in the Makefile's ld --wrap set, so this plain definition
 * shadows libc's recvmsg for the whole test binary.  The device's SEQPACKET RX
 * probe (vtvsock_conn_data_cb) uses recvmsg to tell a real EOF from an empty
 * datagram; model both here.  Consuming reads (no MSG_PEEK) dequeue the staged
 * record, mirroring __wrap_recv's staging so the two stay consistent.
 */
#ifndef VSOCK_HARNESS_NO_RECVMSG_MOCK
ssize_t
recvmsg(int fd, struct msghdr *m, int flags)
{
	size_t avail;

	(void)fd;
	avail = g_recv_len - g_recv_off;
	if (avail == 0 && g_recv_zero_dgram) {
		if (m != NULL)
			m->msg_flags = MSG_EOR;	/* empty record: MSG_EOR set */
		if ((flags & MSG_PEEK) == 0)
			g_recv_zero_dgram = 0;	/* consumed */
		return (0);
	}
	if (avail == 0) {
		if (g_recv_eof) {
			if (m != NULL)
				m->msg_flags = 0;	/* EOF: no MSG_EOR */
			return (0);
		}
		errno = EAGAIN;
		return (-1);
	}
	if (m != NULL)
		m->msg_flags = MSG_EOR;		/* a full record boundary */
	if ((flags & MSG_PEEK) == 0)
		g_recv_off += avail;		/* consuming read drains it */
	return ((ssize_t)avail);		/* MSG_TRUNC probe: full size */
}
#endif /* !VSOCK_HARNESS_NO_RECVMSG_MOCK */
int __wrap_shutdown(int fd, int how) { (void)fd; (void)how; return (0); }
int
__wrap_poll(struct pollfd *p, nfds_t n, int t)
{
	nfds_t i;
	(void)t;
	for (i = 0; i < n; i++)
		p[i].revents = POLLOUT;
	return ((int)n);
}
int __wrap_close(int fd) { (void)fd; return (0); }

/* ================= test scaffolding ================= */
static struct pci_vtvsock_softc *
mk_sc(void)
{
	struct pci_vtvsock_softc *sc = calloc(1, sizeof(*sc));
	sc->vsc_guest_cid = 3;
	sc->vsc_next_port = VTVSOCK_PORT_MIN;
	TAILQ_INIT(&sc->vsc_conns);
	TAILQ_INIT(&sc->vsc_ctl_conns);
	pthread_mutex_init(&sc->vsc_mtx, NULL);
	return (sc);
}
static void
reset_caps(void)
{
	g_ninject = 0; g_send_calls = 0; g_send_len = 0;
	g_rx_descs = 256; g_connectat_result = 0;
	g_recv_len = 0; g_recv_off = 0; g_recv_eof = 0;
	g_recv_zero_dgram = 0;
	g_chain_readable = 0; g_chain_writable = 1; g_getchain_consumes = 0;
}
/* Stage a host->guest message that recv() will return to conn_data_cb. */
static void
stage_recv(const void *data, size_t len)
{
	assert(len <= sizeof(g_recv_data));
	if (len > 0)
		memcpy(g_recv_data, data, len);
	g_recv_len = len;
	g_recv_off = 0;
}
static int
nconns(struct pci_vtvsock_softc *sc)
{
	struct vtvsock_conn *c; int k = 0;
	TAILQ_FOREACH(c, &sc->vsc_conns, link) k++;
	return (k);
}
static struct vtvsock_conn *
mk_established(struct pci_vtvsock_softc *sc, uint32_t gport, uint32_t lport,
    uint16_t type)
{
	struct vtvsock_conn *c = vtvsock_conn_alloc(sc, g_next_fd++, gport);
	assert(c != NULL);
	c->local_port = lport;
	c->type = type;
	c->state = CONN_ESTABLISHED;
	c->peer_buf_alloc = 256 * 1024;
	c->peer_fwd_cnt = 0;
	return (c);
}
static void
mkhdr(struct virtio_vsock_hdr *h, uint16_t op, uint16_t type, uint64_t scid,
    uint64_t dcid, uint32_t sp, uint32_t dp, uint32_t len, uint32_t flags,
    uint32_t balloc, uint32_t fcnt)
{
	memset(h, 0, sizeof(*h));
	h->src_cid = htole64(scid); h->dst_cid = htole64(dcid);
	h->src_port = htole32(sp); h->dst_port = htole32(dp);
	h->len = htole32(len); h->type = htole16(type); h->op = htole16(op);
	h->flags = htole32(flags); h->buf_alloc = htole32(balloc);
	h->fwd_cnt = htole32(fcnt);
}

#define STREAM VIRTIO_VSOCK_TYPE_STREAM
#define SEQPACKET VIRTIO_VSOCK_TYPE_SEQPACKET

/* --- adversarial cases against the untrusted TX state machine --- */
ATF_TC_WITHOUT_HEAD(spoofed_src_cid);
ATF_TC_BODY(spoofed_src_cid, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 999 /*spoofed*/, VSOCK_CID_HOST, 5,
	    80, 0, 0, 0, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 0);	/* silently dropped, no reply */
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(unknown_type_rst);
ATF_TC_BODY(unknown_type_rst, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, 99 /*bad type*/, 3, VSOCK_CID_HOST, 5, 80,
	    0, 0, 0, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	/* reset_no_sock must swap src/dst so the guest can match the RST. */
	ATF_CHECK(g_inject[0].src_port == 80 && g_inject[0].dst_port == 5);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(unknown_conn_rst);
ATF_TC_BODY(unknown_conn_rst, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 5, 80, 0, 0, 0, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);	/* no such conn */
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	/* RST addressing swapped from the received header (src<->dst). */
	ATF_CHECK(g_inject[0].src_port == 80 && g_inject[0].dst_port == 5);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(rst_unknown_conn_ignored);
ATF_TC_BODY(rst_unknown_conn_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_RST, STREAM, 3, VSOCK_CID_HOST, 5, 80, 0, 0, 0, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 0);	/* no RST-for-RST loop */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(request_connect_ok);
ATF_TC_BODY(request_connect_ok, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	struct vtvsock_conn *fc;
	reset_caps();
	g_connectat_result = 0;		/* host listener present */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 1);
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RESPONSE);
	fc = TAILQ_FIRST(&sc->vsc_conns);
	ATF_CHECK(fc != NULL && fc->state == CONN_ESTABLISHED);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(request_no_listener_rst);
ATF_TC_BODY(request_no_listener_rst, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	g_connectat_result = -1;	/* no host listener */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	/* RST addressing swapped from the received header (src<->dst). */
	ATF_CHECK(g_inject[0].src_port == 80 && g_inject[0].dst_port == 1234);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(rw_forwards_to_host);
ATF_TC_BODY(rw_forwards_to_host, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t pay[5] = { 'h', 'e', 'l', 'l', 'o' };
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 5, 0,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, 5);
	ATF_CHECK(g_send_calls >= 1);
	ATF_CHECK(g_send_len == 5 && memcmp(g_send_buf, pay, 5) == 0);
	ATF_CHECK(c->fwd_cnt == 5);	/* credit advanced by consumed bytes */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(peer_fwd_cnt_overflow_rst);
ATF_TC_BODY(peer_fwd_cnt_overflow_rst, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);	/* tx_cnt == 0 */
	/* Guest claims to have consumed 100 bytes we never sent. */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST, 1234,
	    80, 0, 0, 256 * 1024, 100);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 0);	/* connection torn down */
	ATF_CHECK(g_ninject >= 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(credit_update_drop_keeps_last_fwd);
ATF_TC_BODY(credit_update_drop_keeps_last_fwd, tc)
{
	/* Regression test for the last_fwd_cnt fix: a dropped CREDIT_UPDATE
	 * must NOT advance last_fwd_cnt (else no future update ever fires). */
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->tx_cnt = 2000;		/* so guest fwd_cnt 0 is valid */
	c->fwd_cnt = 1000;
	c->last_fwd_cnt = 0;

	g_rx_descs = 0;			/* RX ring full -> inject fails */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234,
	    80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(c->last_fwd_cnt == 0);	/* NOT advanced on drop */

	g_rx_descs = 256;		/* ring has room now */
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(c->last_fwd_cnt == 1000);	/* advanced on success */
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(shutdown_both_closes);
ATF_TC_BODY(shutdown_both_closes, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	int i, saw_rst = 0;
	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 0);
	for (i = 0; i < g_ninject; i++)
		if (g_inject[i].op == VIRTIO_VSOCK_OP_RST) saw_rst = 1;
	ATF_CHECK(saw_rst);
	free(sc);
}

/* --- SEQPACKET connection establishment at the device layer --- */
ATF_TC_WITHOUT_HEAD(seqpacket_request_response);
ATF_TC_BODY(seqpacket_request_response, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	struct vtvsock_conn *fc;
	reset_caps();
	g_connectat_result = 0;
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 1);
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RESPONSE);
	fc = TAILQ_FIRST(&sc->vsc_conns);
	ATF_CHECK(fc != NULL && fc->state == CONN_ESTABLISHED);
	ATF_CHECK(fc != NULL && fc->type == VIRTIO_VSOCK_TYPE_SEQPACKET);
	/* RESPONSE must carry the SEQPACKET type back to the guest. */
	ATF_CHECK(g_inject[0].type == VIRTIO_VSOCK_TYPE_SEQPACKET);
	free(sc);
}

/* --- a packet whose dst_cid is not the host CID must be dropped --- */
ATF_TC_WITHOUT_HEAD(wrong_dst_cid_dropped);
ATF_TC_BODY(wrong_dst_cid_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	/* dst_cid 999 is neither VSOCK_CID_HOST nor the guest CID. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, 999, 1234, 80, 0, 0,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 0);	/* silently dropped, no RST */
	ATF_CHECK(nconns(sc) == 1);	/* existing conn untouched */
	free(sc);
}

/* --- half-close: one SHUTDOWN direction keeps the conn; both close it --- */
ATF_TC_WITHOUT_HEAD(shutdown_half_then_full);
ATF_TC_BODY(shutdown_half_then_full, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);

	/* Only the RCV direction: connection must survive. */
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    VIRTIO_VSOCK_SHUTDOWN_RCV, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 1);

	/* Now the SEND direction too: both shut -> tear down with RST. */
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    VIRTIO_VSOCK_SHUTDOWN_SEND, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* --- a colliding guest REQUEST must not abort a pending host connect --- */
ATF_TC_WITHOUT_HEAD(request_collision_keeps_host_connect);
ATF_TC_BODY(request_collision_keeps_host_connect, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	reset_caps();
	/* Host-initiated connect awaiting the guest's OP_RESPONSE. */
	c = vtvsock_conn_alloc(sc, g_next_fd++, 1234 /*guest_port*/);
	assert(c != NULL);
	c->local_port = 5000;
	c->type = STREAM;
	c->state = CONN_CONNECTING;
	c->peer_buf_alloc = 256 * 1024;

	/* Guest REQUEST colliding on (guest_port=1234, local_port=5000). */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 5000,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);

	/* The pending host connect must still be present and CONNECTING. */
	ATF_CHECK(nconns(sc) == 1);
	c = TAILQ_FIRST(&sc->vsc_conns);
	ATF_CHECK(c != NULL && c->state == CONN_CONNECTING);
	free(sc);
}

/* --- host->guest RX generation: host data is injected as OP_RW to guest --- */
ATF_TC_WITHOUT_HEAD(host_rx_forwards_to_guest);
ATF_TC_BODY(host_rx_forwards_to_guest, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);	/* ample peer credit */
	stage_recv("hello", 5);
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(g_inject[0].len == 5);
	ATF_CHECK(c->tx_cnt == 5);	/* device tracks bytes sent to guest */
	free(sc);
}

/* --- host->guest injection must not exceed the guest-advertised credit --- */
ATF_TC_WITHOUT_HEAD(host_rx_respects_credit);
ATF_TC_BODY(host_rx_respects_credit, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t big[100];
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->peer_buf_alloc = 10;		/* guest window = 10 bytes */
	c->peer_fwd_cnt = 0;
	c->tx_cnt = 0;			/* peer_free = 10 */
	memset(big, 'A', sizeof(big));
	stage_recv(big, sizeof(big));	/* host offers 100 bytes */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	/* At most one 10-byte OP_RW may be injected; must not exceed credit. */
	ATF_CHECK(g_ninject >= 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(g_inject[0].len <= 10);	/* must not exceed credit */
	ATF_CHECK(c->tx_cnt <= 10);
	free(sc);
}

/* --- host fd EOF (recv==0) drives a SHUTDOWN toward the guest --- */
ATF_TC_WITHOUT_HEAD(host_eof_sends_shutdown);
ATF_TC_BODY(host_eof_sends_shutdown, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int i, saw_shutdown = 0;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_recv_eof = 1;			/* host peer has closed: recv() -> 0 */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	for (i = 0; i < g_ninject; i++)
		if (g_inject[i].op == VIRTIO_VSOCK_OP_SHUTDOWN)
			saw_shutdown = 1;
	ATF_CHECK(saw_shutdown);	/* guest told both directions shut */
	ATF_CHECK(c->state == CONN_CLOSING);
	free(sc);
}

/* --- guest->host SEQPACKET: fragments are reassembled to the EOM boundary --- */
ATF_TC_WITHOUT_HEAD(seqpacket_reassembles_to_eom);
ATF_TC_BODY(seqpacket_reassembles_to_eom, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);

	/* Fragment 1 (no EOM): buffered, must NOT be delivered yet. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 4,
	    0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, (const uint8_t *)"ABCD", 4);
	ATF_CHECK(g_send_calls == 0);	/* nothing until EOM */

	/* Fragment 2 (EOM|EOR): deliver the whole 7-byte record as one datagram. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 3,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, (const uint8_t *)"EFG", 3);
	ATF_CHECK(g_send_calls == 1);	/* exactly one host datagram */
	ATF_CHECK(g_send_len == 7);	/* both fragments combined */
	ATF_CHECK(memcmp(g_send_buf, "ABCDEFG", 7) == 0);
	ATF_CHECK((g_send_flags & MSG_EOR) != 0);	/* EOR propagated */
	free(sc);
}

/* --- guest->host: a zero-length SEQPACKET record is delivered as an empty datagram --- */
ATF_TC_WITHOUT_HEAD(seqpacket_zero_len_record);
ATF_TC_BODY(seqpacket_zero_len_record, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_send_calls == 1);	/* empty datagram still delivered */
	ATF_CHECK(g_send_len == 0);
	free(sc);
}

/* --- #3: an RX chain with no writable region is rejected (virtio §5.10.6.4) --- */
ATF_TC_WITHOUT_HEAD(rx_chain_not_writable_dropped);
ATF_TC_BODY(rx_chain_not_writable_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int r;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	/* Guest posted an RX chain that is read-only (no device-writable region). */
	g_chain_readable = 1;
	g_chain_writable = 0;
	r = vtvsock_send_ctrl(sc, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
	ATF_CHECK(r == -1);		/* injection refused */
	ATF_CHECK(g_ninject == 0);	/* nothing delivered to the guest */
	free(sc);
}

/* --- #3: a TX chain with no readable region is dropped (virtio §5.10.6.4) --- */
ATF_TC_WITHOUT_HEAD(tx_chain_not_readable_dropped);
ATF_TC_BODY(tx_chain_not_readable_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;
	reset_caps();
	g_connectat_result = 0;		/* a host listener would be present */
	/* A valid OP_REQUEST that WOULD create a conn if the chain were parsed. */
	mkhdr(h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    0, 256 * 1024, 0);
	/* But the TX chain exposes no device-readable region -> must be dropped. */
	g_chain_readable = 0;
	g_chain_writable = 1;
	g_getchain_consumes = 1;	/* so the drop-everything loop terminates */
	g_rx_descs = 1;			/* exactly one chain to hand out */
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(nconns(sc) == 0);	/* header never parsed/acted on */
	ATF_CHECK(g_ninject == 0);	/* no RESPONSE/RST emitted */
	free(sc);
}

/* --- #2: a fragment that would exceed the device-global reassembly budget RSTs --- */
ATF_TC_WITHOUT_HEAD(global_reasm_budget_rst);
ATF_TC_BODY(global_reasm_budget_rst, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t frag[64];
	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);
	/* Pretend the device already holds nearly the entire global budget. */
	sc->vsc_reasm_total = VTVSOCK_MAX_TOTAL_REASM - 8;
	/* A small non-EOM fragment now tips the aggregate over the budget. */
	memset(frag, 'x', sizeof(frag));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 64,
	    0 /* no EOM */, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, frag, sizeof(frag));
	ATF_CHECK(nconns(sc) == 0);	/* connection reset */
	ATF_CHECK(g_ninject >= 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	free(sc);
}

/* --- #4: an empty host SEQPACKET datagram reaches the guest (not misread as EOF) --- */
ATF_TC_WITHOUT_HEAD(seqpacket_host_zero_len_to_guest);
ATF_TC_BODY(seqpacket_host_zero_len_to_guest, tc)
{
#ifndef VSOCK_HARNESS_NO_RECVMSG_MOCK
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	g_recv_zero_dgram = 1;		/* a real 0-length datagram is queued */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	/* Delivered to the guest as a single EOM|EOR OP_RW with len 0. */
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(g_inject[0].len == 0);
	ATF_CHECK((g_inject[0].flags &
	    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR)) ==
	    (uint32_t)(VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR));
	/* Crucially, the empty datagram must NOT be misread as EOF/teardown. */
	ATF_CHECK(nconns(sc) == 1);
	ATF_CHECK(c->state == CONN_ESTABLISHED);
	free(sc);
#endif /* !VSOCK_HARNESS_NO_RECVMSG_MOCK */
}

/* --- #4: a genuine host SEQPACKET EOF still drives a SHUTDOWN toward the guest --- */
ATF_TC_WITHOUT_HEAD(seqpacket_host_eof_sends_shutdown);
ATF_TC_BODY(seqpacket_host_eof_sends_shutdown, tc)
{
#ifndef VSOCK_HARNESS_NO_RECVMSG_MOCK
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int i, saw_shutdown = 0;
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	g_recv_eof = 1;			/* peer closed: recvmsg -> 0, no MSG_EOR */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	for (i = 0; i < g_ninject; i++)
		if (g_inject[i].op == VIRTIO_VSOCK_OP_SHUTDOWN)
			saw_shutdown = 1;
	ATF_CHECK(saw_shutdown);	/* guest told both directions shut */
	ATF_CHECK(c->state == CONN_CLOSING);
	free(sc);
#endif /* !VSOCK_HARNESS_NO_RECVMSG_MOCK */
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, spoofed_src_cid);
	ATF_TP_ADD_TC(tp, unknown_type_rst);
	ATF_TP_ADD_TC(tp, unknown_conn_rst);
	ATF_TP_ADD_TC(tp, rst_unknown_conn_ignored);
	ATF_TP_ADD_TC(tp, request_connect_ok);
	ATF_TP_ADD_TC(tp, request_no_listener_rst);
	ATF_TP_ADD_TC(tp, rw_forwards_to_host);
	ATF_TP_ADD_TC(tp, peer_fwd_cnt_overflow_rst);
	ATF_TP_ADD_TC(tp, credit_update_drop_keeps_last_fwd);
	ATF_TP_ADD_TC(tp, shutdown_both_closes);
	ATF_TP_ADD_TC(tp, seqpacket_request_response);
	ATF_TP_ADD_TC(tp, wrong_dst_cid_dropped);
	ATF_TP_ADD_TC(tp, shutdown_half_then_full);
	ATF_TP_ADD_TC(tp, request_collision_keeps_host_connect);
	ATF_TP_ADD_TC(tp, host_rx_forwards_to_guest);
	ATF_TP_ADD_TC(tp, host_rx_respects_credit);
	ATF_TP_ADD_TC(tp, host_eof_sends_shutdown);
	ATF_TP_ADD_TC(tp, seqpacket_reassembles_to_eom);
	ATF_TP_ADD_TC(tp, seqpacket_zero_len_record);
	ATF_TP_ADD_TC(tp, rx_chain_not_writable_dropped);
	ATF_TP_ADD_TC(tp, tx_chain_not_readable_dropped);
	ATF_TP_ADD_TC(tp, global_reasm_budget_rst);
	ATF_TP_ADD_TC(tp, seqpacket_host_zero_len_to_guest);
	ATF_TP_ADD_TC(tp, seqpacket_host_eof_sends_shutdown);

	return (atf_no_error());
}

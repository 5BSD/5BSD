/*
 * Device-level ATF test for the bhyve virtio-vsock TX ingress state machine.
 * Drives the real (static) vtvsock_process_tx_pkt() from pci_virtio_vsock.c
 * with crafted guest headers, mocking the virtio RX ring (to capture packets
 * the device injects back to the guest) and the host-socket syscalls
 * (via ld --wrap).  See README.md and the Makefile knobs in
 * tests/sys/kern/Makefile.
 */
#ifndef WITHOUT_CAPSICUM		/* the in-tree Makefile also passes -D */
#define WITHOUT_CAPSICUM
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/filio.h>		/* FIONREAD (mocked below) */
#include <poll.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <atf-c.h>

#include "virtio_config_read_test_support.h"
/*
 * The device's SEQPACKET RX path recvmsg()s and ioctl(FIONREAD)s the conn fd.
 * Both are ld --wrap'd (__wrap_recvmsg / __wrap_ioctl below) rather than shadowed
 * by plain definitions, so they coexist with AddressSanitizer's own interceptors
 * (a plain recvmsg shadow collides with ASan's strong symbol).  The recvmsg-
 * dependent SEQPACKET host->guest cases therefore run under BOTH the local
 * run.sh (ASan) build and the in-tree ATF build.
 */

/* Device under test (its quote-includes resolve to the mock headers here). */
#define	BHYVE_SNAPSHOT
#include "pci_virtio_vsock.c"
#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

/* Compile the DUT first, then use only section-cited wire values in tests. */
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_F_VERSION_1
#define	VIRTIO_F_VERSION_1		VIRTIO14_F_VERSION_1
#undef VIRTIO_RING_F_INDIRECT_DESC
#define	VIRTIO_RING_F_INDIRECT_DESC	VIRTIO14_F_RING_INDIRECT_DESC
#undef VIRTIO_VSOCK_F_STREAM
#define	VIRTIO_VSOCK_F_STREAM		VIRTIO14_VSOCK_F_STREAM
#undef VIRTIO_VSOCK_F_SEQPACKET
#define	VIRTIO_VSOCK_F_SEQPACKET	VIRTIO14_VSOCK_F_SEQPACKET
#undef VIRTIO_VSOCK_F_NO_IMPLIED_STREAM
#define	VIRTIO_VSOCK_F_NO_IMPLIED_STREAM \
	VIRTIO14_VSOCK_F_NO_IMPLIED_STREAM
#undef VIRTIO_VSOCK_TYPE_STREAM
#define	VIRTIO_VSOCK_TYPE_STREAM	VIRTIO14_VSOCK_TYPE_STREAM
#undef VIRTIO_VSOCK_TYPE_SEQPACKET
#define	VIRTIO_VSOCK_TYPE_SEQPACKET	VIRTIO14_VSOCK_TYPE_SEQPACKET
#undef VIRTIO_VSOCK_OP_REQUEST
#define	VIRTIO_VSOCK_OP_REQUEST		VIRTIO14_VSOCK_OP_REQUEST
#undef VIRTIO_VSOCK_OP_RESPONSE
#define	VIRTIO_VSOCK_OP_RESPONSE	VIRTIO14_VSOCK_OP_RESPONSE
#undef VIRTIO_VSOCK_OP_RST
#define	VIRTIO_VSOCK_OP_RST		VIRTIO14_VSOCK_OP_RST
#undef VIRTIO_VSOCK_OP_SHUTDOWN
#define	VIRTIO_VSOCK_OP_SHUTDOWN	VIRTIO14_VSOCK_OP_SHUTDOWN
#undef VIRTIO_VSOCK_OP_RW
#define	VIRTIO_VSOCK_OP_RW		VIRTIO14_VSOCK_OP_RW
#undef VIRTIO_VSOCK_OP_CREDIT_UPDATE
#define	VIRTIO_VSOCK_OP_CREDIT_UPDATE	VIRTIO14_VSOCK_OP_CREDIT_UPDATE
#undef VIRTIO_VSOCK_OP_CREDIT_REQUEST
#define	VIRTIO_VSOCK_OP_CREDIT_REQUEST	VIRTIO14_VSOCK_OP_CREDIT_REQUEST
#undef VIRTIO_VSOCK_SHUTDOWN_RCV
#define	VIRTIO_VSOCK_SHUTDOWN_RCV	VIRTIO14_VSOCK_SHUTDOWN_RECEIVE
#undef VIRTIO_VSOCK_SHUTDOWN_SEND
#define	VIRTIO_VSOCK_SHUTDOWN_SEND	VIRTIO14_VSOCK_SHUTDOWN_SEND
#undef VIRTIO_VSOCK_SEQ_EOM
#define	VIRTIO_VSOCK_SEQ_EOM		VIRTIO14_VSOCK_SEQ_EOM
#undef VIRTIO_VSOCK_SEQ_EOR
#define	VIRTIO_VSOCK_SEQ_EOR		VIRTIO14_VSOCK_SEQ_EOR

/* ---- captured packets injected toward the guest (RX ring) ---- */
struct cap_pkt { uint16_t op, type; uint32_t src_port, dst_port, len, flags,
    buf_alloc, fwd_cnt; };
static struct cap_pkt g_inject[128];
static int g_ninject;
static int g_rx_descs = 256;
static struct vqueue_info *g_one_shot_vq;
static bool g_one_shot_vq_consumed;
static uint8_t g_rxbuf[64 * 1024 + 128];
/* Size the guest RX buffer vq_getchain() hands back; tests shrink it to
 * exercise host->guest packet fragmentation to a small (e.g. 4 KiB Linux) RX
 * buffer. */
static size_t g_rxbuf_len = sizeof(g_rxbuf);
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
/*
 * vq_getchain() fault injection for the RX inject_raw error paths.
 * g_getchain_zero: descs present (vq_has_descs true) but getchain returns 0.
 * g_getchain_bign: getchain returns a chain length > VTVSOCK_MAX_IOV.
 * g_iov_null_base: getchain hands back a descriptor whose iov_base is NULL
 * (a guest descriptor addr outside RAM).
 */
static int g_getchain_zero;
static int g_getchain_bign;
static int g_iov_null_base;
static uint32_t g_rel_len;
static int g_endchains;
static int g_endchains_all;

/* ---- host-socket syscall effects ---- */
static int g_next_fd = 500;
static int g_connectat_result;
static int g_socket_calls;
static int g_connectat_calls;
static uint8_t g_send_buf[65536];
static size_t g_send_len;
static int g_send_calls;
static uint8_t g_writev_buf[64 * 1024 + 128];
static size_t g_writev_len;
static int g_writev_calls;
static bool g_writev_override;
static ssize_t g_writev_result;
static int g_writev_errno;
static int g_needs_reset_calls;
static unsigned long g_ioctl_fail_request;
static int g_ioctl_fail_errno;
static unsigned long g_ioctl_last_request;
static uint64_t g_ioctl_features;
static int g_ioctl_feature_calls;
static int g_ioctl_freeze_calls;
static int g_ioctl_thaw_calls;
static bool g_ioctl_freeze_bad_version;
static bool g_ioctl_freeze_bad_reserved;
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;
static bool g_snapshot_validate_saw_owner;

void
vm_snapshot_buf_err(const char *name __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		bytes[0] = *value;
		bytes[1] = *value >> 8;
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint16_t)bytes[0] | (uint16_t)bytes[1] << 8;
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint32_t)bytes[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint64_t)bytes[i] << (i * 8);
	}
	return (error);
}

/* ================= mock virtio RX ring ================= */
int
vq_has_descs(struct vqueue_info *vq)
{
	if (vq == g_one_shot_vq)
		return (!g_one_shot_vq_consumed);
	return (g_rx_descs > 0);
}
int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{
	if (vq == g_one_shot_vq) {
		if (g_one_shot_vq_consumed)
			return (0);
		g_one_shot_vq_consumed = true;
	}
	if (niov < 1 || g_rx_descs <= 0)
		return (0);
	if (g_getchain_zero) {
		if (g_getchain_consumes)
			g_rx_descs--;
		return (0);		/* chain unavailable despite has_descs */
	}
	iov[0].iov_base = g_iov_null_base ? NULL : g_rxbuf;
	iov[0].iov_len = g_rxbuf_len;
	req->idx = 0;
	if (vq == g_one_shot_vq) {
		req->readable = 1;
		req->writable = 0;
	} else {
		req->readable = g_chain_readable;
		req->writable = g_chain_writable;
	}
	if (g_getchain_consumes)
		g_rx_descs--;		/* let drop-everything loops terminate */
	if (g_getchain_bign)
		return (g_getchain_bign);	/* > VTVSOCK_MAX_IOV: over-long */
	return (1);
}
void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t len)
{
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;
	struct cap_pkt *p;

	(void)vq; (void)idx;
	g_rel_len = len;
	if (len < VIRTIO14_VSOCK_HEADER_SIZE)
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
void vq_endchains(struct vqueue_info *vq, int i)
{ (void)vq; g_endchains++; g_endchains_all = i; }

/* ================= mock mevent / virtio glue ================= */
static struct mevent {
	int fd;
	bool enabled;
} g_mev[128];
static int g_nmev;
static int g_mevent_enable_calls;
static int g_mevent_disable_calls;
static int g_mevent_delete_sync_calls;
static int g_mevent_delete_close_sync_calls;
/*
 * mevent_add() fault injection: g_mevent_fail == N makes the N-th subsequent
 * mevent_add() call return NULL (1 == fail the very next one).  A countdown so
 * a specific mevent in a multi-mevent setup (e.g. device init) can be targeted.
 */
static int g_mevent_fail;
struct mevent *
mevent_add(int fd, enum ev_type t, void (*cb)(int, enum ev_type, void *),
    void *p)
{
	struct mevent *m;
	(void)t; (void)cb; (void)p;
	if (g_mevent_fail && --g_mevent_fail == 0)
		return (NULL);
	m = &g_mev[g_nmev++ % 128];
	m->fd = fd;
	m->enabled = true;
	return (m);
}
struct mevent *
mevent_add_disabled(int fd, enum ev_type t,
    void (*cb)(int, enum ev_type, void *), void *p)
{
	struct mevent *m;

	m = mevent_add(fd, t, cb, p);
	if (m != NULL)
		m->enabled = false;
	return (m);
}
struct mevent *
mevent_add_cleanup(int fd, enum ev_type t,
    void (*cb)(int, enum ev_type, void *), void *p,
    mevent_param_cleanup_t cleanup __unused)
{

	return (mevent_add(fd, t, cb, p));
}
int mevent_enable(struct mevent *m)
{ m->enabled = true; g_mevent_enable_calls++; return (0); }
int mevent_disable(struct mevent *m)
{ m->enabled = false; g_mevent_disable_calls++; return (0); }
int mevent_delete(struct mevent *m) { (void)m; return (0); }
int mevent_delete_sync(struct mevent *m)
{ (void)m; g_mevent_delete_sync_calls++; return (0); }
int mevent_delete_close_sync(struct mevent *m)
{ (void)m; g_mevent_delete_close_sync_calls++; return (0); }
int mevent_delete_close(struct mevent *m) { if (m) (void)close(m->fd); return (0); }

static void *
test_vtvsock_event_arg(struct pci_vtvsock_softc *sc, uint64_t id)
{
	struct vtvsock_event_ref *ref;

	ref = calloc(1, sizeof(*ref));
	ATF_REQUIRE(ref != NULL);
	ref->sc = sc;
	ref->id = id;
	return (ref);
}

static void *
test_vtvsock_conn_event_arg(struct pci_vtvsock_softc *sc, int fd)
{
	struct vtvsock_conn *conn;

	TAILQ_FOREACH(conn, &sc->vsc_conns, link) {
		if (conn->fd == fd)
			return (test_vtvsock_event_arg(sc, conn->event_id));
	}
	abort();
}

static void *
test_vtvsock_ctl_event_arg(struct pci_vtvsock_softc *sc, int fd)
{
	struct vtvsock_ctl_conn *conn;

	TAILQ_FOREACH(conn, &sc->vsc_ctl_conns, link) {
		if (conn->fd == fd)
			return (test_vtvsock_event_arg(sc, conn->event_id));
	}
	abort();
}

/* Exercise callbacks with the production immutable identity, not raw sc. */
#define	vtvsock_conn_data_cb(fd, type, sc) \
	vtvsock_conn_data_cb((fd), (type), test_vtvsock_conn_event_arg((sc), (fd)))
#define	vtvsock_conn_write_cb(fd, type, sc) \
	vtvsock_conn_write_cb((fd), (type), test_vtvsock_conn_event_arg((sc), (fd)))
#define	pci_vtvsock_ctl_conn_cb(fd, type, sc) \
	pci_vtvsock_ctl_conn_cb((fd), (type), test_vtvsock_ctl_event_arg((sc), (fd)))

void vi_softc_linkup(struct virtio_softc *a, struct virtio_consts *b, void *c,
    struct pci_devinst *d, struct vqueue_info *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
static int g_vi_transport_fail;	/* make vi_pci_select_transport() fail */
static int g_vi_intr_fail;	/* make vi_intr_init() fail */
int vi_pci_select_transport(struct virtio_softc *a, const nvlist_t *b,
    enum virtio_pci_transport_policy c)
{ (void)a; (void)b; (void)c; return (g_vi_transport_fail ? -1 : 0); }
bool vi_pci_is_modern(const struct virtio_softc *a) { (void)a; return (false); }
int vi_pci_modern_init(struct virtio_softc *a, int b)
{ (void)a; (void)b; return (0); }
void vi_pci_modern_set_identity(struct virtio_softc *a, uint16_t b)
{ (void)a; (void)b; }
int vi_pci_modern_cfgread(struct pci_devinst *a, int b, int c, uint32_t *d)
{ (void)a; (void)b; (void)c; (void)d; return (1); }
int vi_pci_modern_cfgwrite(struct pci_devinst *a, int b, int c, uint32_t d)
{ (void)a; (void)b; (void)c; (void)d; return (1); }
int vi_intr_init(struct virtio_softc *a, int b, int c)
{ (void)a; (void)b; (void)c; return (g_vi_intr_fail ? -1 : 0); }
void vi_set_io_bar(struct virtio_softc *a, int b) { (void)a; (void)b; }
void vi_reset_dev(struct virtio_softc *a) { (void)a; }
int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_vtvsock_softc *sc;

	g_snapshot_validate_calls++;
	sc = ((struct pci_devinst *)meta->dev_data)->pi_arg;
	g_snapshot_validate_saw_lock = pthread_mutex_isowned_np(&sc->vsc_mtx);
	g_snapshot_validate_saw_owner = sc->vsc_checkpoint_lock_held;
	return (g_snapshot_validate_result);
}
void
vi_set_needs_reset(struct virtio_softc *vs)
{

	g_needs_reset_calls++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}
uint64_t vi_pci_read(struct pci_devinst *a, int b, uint64_t c, int d)
{ (void)a; (void)b; (void)c; (void)d; return (0); }
void vi_pci_write(struct pci_devinst *a, int b, uint64_t c, int d, uint64_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; }
void pci_set_cfgdata8(struct pci_devinst *a, int b, uint8_t c)
{ (void)a; (void)b; (void)c; }
void pci_set_cfgdata16(struct pci_devinst *a, int b, uint16_t c)
{ (void)a; (void)b; (void)c; }
int fbsdrun_virtio_msix(void) { return (1); }
/*
 * Referenced only from a per-packet DPRINTF2 trace branch (debug level >= 2).
 * With pci_vtvsock_init() now under test the compiler can no longer prove that
 * branch dead (init sets pci_vtvsock_debug from the environment), so the call
 * must resolve; the harness never enables level-2 tracing, so it is inert. */
int pci_msix_enabled(struct pci_devinst *a) { (void)a; return (0); }
/*
 * Table-driven config mock used to drive pci_vtvsock_init().  Empty by default,
 * so unset keys still return NULL exactly as the original stub did.  Tests call
 * cfg_set()/cfg_reset() to stage the "cid"/"backend"/"path"/"packed" options a
 * real bhyve config node would carry.
 */
#define	CFG_MAX	8
static struct { const char *key; const char *val; } g_cfg[CFG_MAX];
static int g_cfg_n;
static bool g_cfg_packed;			/* value for the "packed" bool key */
static char g_setcfg_key[64];			/* last set_config_value_node key */
static char g_setcfg_val[256];			/* last set_config_value_node val */
static int g_setcfg_calls;
static void
cfg_reset(void)
{
	g_cfg_n = 0;
	g_cfg_packed = false;
	g_setcfg_key[0] = g_setcfg_val[0] = '\0';
	g_setcfg_calls = 0;
}
static void
cfg_set(const char *key, const char *val)
{
	assert(g_cfg_n < CFG_MAX);
	g_cfg[g_cfg_n].key = key;
	g_cfg[g_cfg_n].val = val;
	g_cfg_n++;
}
const char *get_config_value_node(const nvlist_t *n, const char *k)
{
	(void)n;
	for (int i = 0; i < g_cfg_n; i++)
		if (strcmp(g_cfg[i].key, k) == 0)
			return (g_cfg[i].val);
	return (NULL);
}
bool get_config_bool_node_default(const nvlist_t *n, const char *k, bool dflt)
{
	(void)n;
	if (strcmp(k, "packed") == 0)
		return (g_cfg_packed);
	return (dflt);
}
void set_config_value_node(nvlist_t *n, const char *k, const char *v)
{
	(void)n;
	g_setcfg_calls++;
	if (k != NULL)
		strlcpy(g_setcfg_key, k, sizeof(g_setcfg_key));
	if (v != NULL)
		strlcpy(g_setcfg_val, v, sizeof(g_setcfg_val));
}

/* ================= wrapped host-socket syscalls ================= */
void *__real_realloc(void *, size_t);
int __real_socketpair(int, int, int, int [2]);
int __real_fcntl(int, int, ...);
int __real_close(int);
void *__wrap_realloc(void *, size_t);
int __wrap_socket(int, int, int);
ssize_t __wrap_writev(int, const struct iovec *, int);
int __wrap_connectat(int, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_send(int, const void *, size_t, int);
ssize_t __wrap_recv(int, void *, size_t, int);
ssize_t __wrap_sendmsg(int, const struct msghdr *, int);
ssize_t __wrap_recvmsg(int, struct msghdr *, int);
int __wrap_ioctl(int, unsigned long, ...);
int __wrap_shutdown(int, int);
int __wrap_poll(struct pollfd *, nfds_t, int);
int __wrap_close(int);
int __wrap_accept(int, struct sockaddr *, socklen_t *);
int __wrap_socketpair(int, int, int, int [2]);
int __wrap_fcntl(int, int, ...);
int __wrap_setsockopt(int, int, int, const void *, socklen_t);
int __wrap_getsockopt(int, int, int, void *, socklen_t *);
static int g_realloc_fail;
void *
__wrap_realloc(void *ptr, size_t size)
{
	if (g_realloc_fail) {
		g_realloc_fail = 0;
		return (NULL);
	}
	return (__real_realloc(ptr, size));
}

int __real_socket(int, int, int);
static bool g_use_real_socket;	/* init test: return a genuine AF_UNIX fd */
static int g_socket_fail;	/* make the next socket() fail with EMFILE */
int __wrap_socket(int a, int b, int c)
{
	g_socket_calls++;
	if (g_socket_fail) {
		g_socket_fail = 0;
		errno = EMFILE;
		return (-1);
	}
	if (g_use_real_socket)
		return (__real_socket(a, b, c));
	return (g_next_fd++);
}
ssize_t
__wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
	size_t off = 0;

	(void)fd;
	g_writev_calls++;
	for (int i = 0; i < iovcnt; i++) {
		assert(off + iov[i].iov_len <= sizeof(g_writev_buf));
		memcpy(g_writev_buf + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}
	g_writev_len = off;
	if (g_writev_override) {
		errno = g_writev_errno;
		return (g_writev_result);
	}
	return ((ssize_t)off);
}
int
__wrap_connectat(int dfd, int s, const struct sockaddr *a, socklen_t l)
{
	(void)dfd; (void)s; (void)a; (void)l;
	g_connectat_calls++;
	if (g_connectat_result < 0)
		errno = ECONNREFUSED;
	return (g_connectat_result);
}
static int g_send_flags;	/* flags from the most recent send() */
static bool g_send_override;
static ssize_t g_send_result;
static int g_send_errno;
ssize_t
__wrap_send(int fd, const void *b, size_t n, int f)
{
	(void)fd;
	if (b != NULL && n <= sizeof(g_send_buf))
		memcpy(g_send_buf, b, n);
	g_send_len = n;
	g_send_flags = f;
	g_send_calls++;
	if (g_send_override) {
		errno = g_send_errno;
		return (g_send_result);
	}
	return ((ssize_t)n);
}
/* Staged host->guest data returned by recv(); default is "no data" (EAGAIN). */
static uint8_t g_recv_data[256 * 1024];
static size_t g_recv_len;	/* total staged bytes (one host message) */
static size_t g_recv_off;	/* bytes already consumed by recv() */
static size_t g_recv_chunk_max;	/* limit one recv(), 0 means unlimited */
static int g_recv_eof;		/* when set, recv() returns 0 (EOF) once drained */
static int g_recv_zero_dgram;	/* a real 0-length SEQPACKET record is queued */
static int g_recv_no_eor;	/* SEQPACKET record delivered WITHOUT MSG_EOR */
static bool g_sendmsg_override;
static ssize_t g_sendmsg_result;
static int g_sendmsg_errno;
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
	if (g_recv_chunk_max != 0)
		take = MIN(take, g_recv_chunk_max);
	if (b != NULL && (f & MSG_TRUNC) == 0)
		memcpy(b, g_recv_data + g_recv_off, take);
	if (f & MSG_PEEK)			/* SEQPACKET size probe */
		return (f & MSG_TRUNC) ? (ssize_t)avail : (ssize_t)take;
	g_recv_off += take;
	return (ssize_t)take;
}
ssize_t
__wrap_sendmsg(int fd, const struct msghdr *m, int f)
{
	(void)fd;
	(void)f;
	if (g_sendmsg_override) {
		errno = g_sendmsg_errno;
		return (g_sendmsg_result);
	}
	return (m->msg_iovlen ? (ssize_t)m->msg_iov[0].iov_len : 0);
}
/*
 * recvmsg() is in both harness linkers' --wrap sets.  The device's SEQPACKET
 * RX probe (vtvsock_conn_data_cb) uses it to distinguish a real EOF from an
 * empty datagram; model both here.  Consuming reads (no MSG_PEEK) dequeue the
 * staged record, mirroring __wrap_recv's staging so the two stay consistent.
 */
ssize_t
__wrap_recvmsg(int fd, struct msghdr *m, int flags)
{
	size_t avail, cap, take;

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
	if (m != NULL) {
		m->msg_flags = g_recv_no_eor ? 0 : MSG_EOR; /* record boundary */
		/* Consuming reads copy the record into the caller's buffer so
		 * the injected payload is the staged data. */
		if (m->msg_iov != NULL && m->msg_iovlen > 0 &&
		    m->msg_iov[0].iov_base != NULL) {
			cap = m->msg_iov[0].iov_len;
			take = MIN(cap, avail);
			memcpy(m->msg_iov[0].iov_base,
			    g_recv_data + g_recv_off, take);
		}
	}
	if ((flags & MSG_PEEK) == 0)
		g_recv_off += avail;		/* consuming read drains it */
	return ((ssize_t)avail);
}

/*
 * FIONREAD: the SEQPACKET (and STREAM) RX sizing path ioctl()s the conn fd for
 * the queued byte count.  Report the staged record's remaining bytes so the
 * size-then-read path is exercised faithfully (0 -> the recvmsg peek that
 * disambiguates an empty datagram from EOF from no-data).
 */
int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	int *argp;
	struct vsock_transport_features *featuresp;
	struct vsock_transport_checkpoint *checkpoint;

	(void)fd;
	if (request == g_ioctl_fail_request) {
		errno = g_ioctl_fail_errno;
		return (-1);
	}
	if (request == (unsigned long)FIONREAD) {
		va_start(ap, request);
		argp = va_arg(ap, int *);
		va_end(ap);
		if (argp != NULL)
			*argp = (int)(g_recv_len - g_recv_off);
	} else if (request == VSOCK_IOC_TRANSPORT_SET_FEATURES) {
		va_start(ap, request);
		featuresp = va_arg(ap, struct vsock_transport_features *);
		va_end(ap);
		g_ioctl_last_request = request;
		g_ioctl_feature_calls++;
		if (featuresp != NULL && featuresp->version ==
		    VSOCK_TRANSPORT_FEATURES_VERSION && featuresp->flags == 0 &&
		    featuresp->reserved[0] == 0 && featuresp->reserved[1] == 0)
			g_ioctl_features = featuresp->features;
	} else if (request == VSOCK_IOC_TRANSPORT_FREEZE) {
		va_start(ap, request);
		checkpoint = va_arg(ap, struct vsock_transport_checkpoint *);
		va_end(ap);
		g_ioctl_freeze_calls++;
		if (checkpoint != NULL) {
			if (g_ioctl_freeze_bad_version)
				checkpoint->version++;
			checkpoint->flags =
			    VSOCK_TRANSPORT_CHECKPOINT_F_FROZEN;
			checkpoint->queue_count = 0;
			checkpoint->connection_count = 0;
			checkpoint->generation = 7;
			if (g_ioctl_freeze_bad_reserved)
				checkpoint->reserved[0] = 1;
		}
	} else if (request == VSOCK_IOC_TRANSPORT_THAW) {
		g_ioctl_thaw_calls++;
	}
	return (0);
}
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

/* ---- control-socket path mocks ---- */
static int g_socketpair_fail;		/* make socketpair() return -1/ENOMEM */
static int g_accept_fail;		/* one-shot: next accept() fails */
static int g_accept_errno = ECONNABORTED;
int
__wrap_accept(int fd, struct sockaddr *a, socklen_t *l)
{
	(void)fd; (void)a;
	if (g_accept_fail) {
		g_accept_fail = 0;
		errno = g_accept_errno;
		return (-1);
	}
	if (l != NULL) *l = 0;
	return (g_next_fd++);		/* each ctl accept gets a fresh fake fd */
}
int
__wrap_socketpair(int d, int t, int p, int sv[2])
{
	(void)d; (void)t; (void)p;
	if (g_socketpair_fail) { errno = ENOMEM; return (-1); }
	sv[0] = g_next_fd++;
	sv[1] = g_next_fd++;
	return (0);
}
static int g_fcntl_fail;	/* one-shot: next fcntl() fails with EINVAL */
int __wrap_fcntl(int fd, int cmd, ...)
{
	(void)fd; (void)cmd;
	if (g_fcntl_fail) {
		g_fcntl_fail = 0;
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Capture relay-socket buffer sizing (vtvsock_set_relay_bufsize).  Fds here are
 * fake integers, so the real setsockopt/getsockopt would fail; wrap them to
 * record what the device requests and echo it back as if the kernel honored it.
 */
static int g_sndbuf_last;	/* last SO_SNDBUF value requested */
static int g_rcvbuf_last;	/* last SO_RCVBUF value requested */
static int g_sndbuf_calls;	/* count of SO_SNDBUF requests */
static int g_rcvbuf_calls;	/* count of SO_RCVBUF requests */
int
__wrap_setsockopt(int fd, int level, int opt, const void *val, socklen_t len)
{
	(void)fd; (void)len;
	if (level == SOL_SOCKET && val != NULL) {
		if (opt == SO_SNDBUF) { g_sndbuf_last = *(const int *)val;
			g_sndbuf_calls++; }
		else if (opt == SO_RCVBUF) { g_rcvbuf_last = *(const int *)val;
			g_rcvbuf_calls++; }
	}
	return (0);
}
int
__wrap_getsockopt(int fd, int level, int opt, void *val, socklen_t *len)
{
	(void)fd; (void)len;
	if (level == SOL_SOCKET && val != NULL) {
		if (opt == SO_RCVBUF) *(int *)val = g_rcvbuf_last;
		else if (opt == SO_SNDBUF) *(int *)val = g_sndbuf_last;
		else *(int *)val = 0;
	}
	return (0);
}

/* Stage a control message that the next ctl-conn recv() will return. */
static void
stage_ctl_msg(uint32_t cmd, uint32_t port, uint32_t type)
{
	struct vsock_ctl_msg m = { cmd, port, type, 0 };
	memcpy(g_recv_data, &m, sizeof(m));
	g_recv_len = sizeof(m);
	g_recv_off = 0;
}

/* ================= test scaffolding ================= */
static struct pci_vtvsock_softc *
mk_sc(void)
{
	struct pci_vtvsock_softc *sc = calloc(1, sizeof(*sc));
	sc->vsc_guest_cid = 3;
	sc->vsc_next_port = VTVSOCK_PORT_MIN;
	sc->vsc_features = VIRTIO_VSOCK_F_STREAM |
	    VIRTIO_VSOCK_F_SEQPACKET |
	    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;
	TAILQ_INIT(&sc->vsc_conns);
	TAILQ_INIT(&sc->vsc_ctl_conns);
	pthread_mutex_init(&sc->vsc_mtx, NULL);
	for (unsigned int i = 0; i < nitems(sc->vsc_queues); i++)
		sc->vsc_queues[i].vq_qsize = VTVSOCK_RINGSZ;
	return (sc);
}
static void
reset_caps(void)
{
	g_ninject = 0; g_send_calls = 0; g_send_len = 0;
	g_send_override = false; g_send_result = 0; g_send_errno = 0;
	g_rx_descs = 256; g_connectat_result = 0;
	g_one_shot_vq = NULL; g_one_shot_vq_consumed = false;
	g_socket_calls = 0; g_connectat_calls = 0;
	g_rxbuf_len = sizeof(g_rxbuf);
	g_recv_len = 0; g_recv_off = 0; g_recv_chunk_max = 0; g_recv_eof = 0;
	g_recv_zero_dgram = 0; g_recv_no_eor = 0;
	g_sendmsg_override = false; g_sendmsg_result = 0; g_sendmsg_errno = 0;
	g_chain_readable = 0; g_chain_writable = 1; g_getchain_consumes = 0;
	g_getchain_zero = 0; g_getchain_bign = 0; g_iov_null_base = 0;
	g_socket_fail = 0; g_mevent_fail = 0;
	g_accept_fail = 0; g_fcntl_fail = 0; g_socketpair_fail = 0;
	g_rel_len = 0; g_endchains = 0; g_endchains_all = -1;
	g_mevent_enable_calls = 0;
	g_mevent_disable_calls = 0;
	g_mevent_delete_sync_calls = 0;
	g_mevent_delete_close_sync_calls = 0;
	g_realloc_fail = 0;
	g_writev_len = 0; g_writev_calls = 0;
	g_writev_override = false; g_writev_result = 0; g_writev_errno = 0;
	g_needs_reset_calls = 0;
	g_ioctl_fail_request = 0;
	g_ioctl_fail_errno = 0;
	g_ioctl_last_request = 0;
	g_ioctl_features = 0;
	g_ioctl_feature_calls = 0;
	g_ioctl_freeze_calls = 0;
	g_ioctl_thaw_calls = 0;
	g_ioctl_freeze_bad_version = false;
	g_ioctl_freeze_bad_reserved = false;
}

ATF_TC_WITHOUT_HEAD(send_fd_requires_complete_frame);
ATF_TC_BODY(send_fd_requires_complete_frame, tc)
{
	static const char reply[] = "control-reply";

	reset_caps();
	ATF_CHECK(vtvsock_send_fd(10, 11, reply, sizeof(reply)) == 0);

	g_sendmsg_override = true;
	g_sendmsg_result = sizeof(reply) - 1;
	errno = 0;
	ATF_CHECK(vtvsock_send_fd(10, 11, reply, sizeof(reply)) == -1);
	ATF_CHECK(errno == EMSGSIZE);

	g_sendmsg_result = -1;
	g_sendmsg_errno = EAGAIN;
	errno = 0;
	ATF_CHECK(vtvsock_send_fd(10, 11, reply, sizeof(reply)) == -1);
	ATF_CHECK(errno == EAGAIN);
}

ATF_TC_WITHOUT_HEAD(port_allocator_skips_reserved);
ATF_TC_BODY(port_allocator_skips_reserved, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	pthread_mutex_lock(&sc->vsc_mtx);
	sc->vsc_next_port = 0;
	ATF_CHECK(vtvsock_alloc_port(sc) == VTVSOCK_PORT_MIN);
	ATF_CHECK(sc->vsc_next_port == VTVSOCK_PORT_MIN + 1);
	sc->vsc_next_port = UINT32_MAX;
	ATF_CHECK(vtvsock_alloc_port(sc) == VTVSOCK_PORT_MIN);
	sc->vsc_next_port = UINT32_MAX - 1;
	ATF_CHECK(vtvsock_alloc_port(sc) == UINT32_MAX - 1);
	ATF_CHECK(sc->vsc_next_port == VTVSOCK_PORT_MIN);
	pthread_mutex_unlock(&sc->vsc_mtx);
	free(sc);
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

static void
process_tx_wire(struct pci_vtvsock_softc *sc, const uint8_t *wire,
    const void *payload, size_t payload_len)
{

	vtvsock_process_tx_pkt(sc,
	    (const struct virtio_vsock_hdr *)(const void *)wire, payload,
	    payload_len);
}

#define STREAM VIRTIO_VSOCK_TYPE_STREAM
#define SEQPACKET VIRTIO_VSOCK_TYPE_SEQPACKET

/* --- invalid-input cases for the guest-controlled TX state machine --- */
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

/* --- A new flow has tx_cnt == 0, so a nonzero initial fwd_cnt cannot
 * describe bytes consumed by the guest.  Reject both an ordinary forward
 * value and a wrap-looking value rather than creating a self-starved flow. --- */
ATF_TC_WITHOUT_HEAD(request_nonzero_initial_fwd_cnt_rst);
ATF_TC_BODY(request_nonzero_initial_fwd_cnt_rst, tc)
{
	const uint32_t invalid[] = { 1, UINT32_MAX };
	struct pci_vtvsock_softc *sc;
	struct virtio_vsock_hdr h;
	size_t i;

	for (i = 0; i < nitems(invalid); i++) {
		sc = mk_sc();
		reset_caps();
		g_connectat_result = 0;	/* would otherwise establish */
		mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3,
		    VSOCK_CID_HOST, 1234, 80, 0, 0, 256 * 1024,
		    invalid[i]);
		vtvsock_process_tx_pkt(sc, &h, NULL, 0);
		ATF_CHECK(nconns(sc) == 0);
		ATF_CHECK(g_ninject == 1 &&
		    g_inject[0].op == VIRTIO_VSOCK_OP_RST);
		ATF_CHECK(g_socket_calls == 0 && g_connectat_calls == 0);
		free(sc);
	}
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

ATF_TC_WITHOUT_HEAD(stream_eagain_drains_on_writable);
ATF_TC_BODY(stream_eagain_drains_on_writable, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	const uint8_t pay[] = "hello";

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234,
	    80, sizeof(pay) - 1, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay) - 1);

	ATF_CHECK_EQ(c->fwd_cnt, 0);
	ATF_CHECK_EQ(c->tx_buf_len, sizeof(pay) - 1);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, sizeof(pay) - 1);
	ATF_CHECK(c->tx_evp != NULL);

	g_send_override = false;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK_EQ(c->fwd_cnt, sizeof(pay) - 1);
	ATF_CHECK_EQ(c->tx_buf_len, 0);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, 0);
	ATF_CHECK_EQ(nconns(sc), 1);
	ATF_CHECK(g_mevent_disable_calls != 0);
	free(sc);
}

/* A known but connection-mismatched RW type resets the flow.  Silently
 * consuming it would hide guaranteed-delivery loss from both endpoints. */
ATF_TC_WITHOUT_HEAD(rw_type_mismatch_resets);
ATF_TC_BODY(rw_type_mismatch_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t pay[VTVSOCK_CREDIT_UPDATE_THRESHOLD];

	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	memset(pay, 'M', sizeof(pay));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(pay), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay));

	ATF_CHECK(g_send_calls == 0);	/* malformed payload not relayed */
	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(g_ninject == 1 &&
	    g_inject[0].op == VIRTIO_VSOCK_OP_RST);
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

ATF_TC_WITHOUT_HEAD(peer_fwd_cnt_rewind_ignored);
ATF_TC_BODY(peer_fwd_cnt_rewind_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->tx_cnt = 200;
	c->peer_fwd_cnt = 100;

	/* A stale credit update must not move the free-running counter back. */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3,
	    VSOCK_CID_HOST, 1234, 80, 0, 0, 256 * 1024, 50);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK_EQ(c->peer_fwd_cnt, 100);
	ATF_CHECK_EQ(nconns(sc), 1);

	/* A normal advance is accepted. */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3,
	    VSOCK_CID_HOST, 1234, 80, 0, 0, 256 * 1024, 150);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK_EQ(c->peer_fwd_cnt, 150);

	/* Wraparound is an advance when the delta remains in the half-range. */
	c->tx_cnt = 32;
	c->peer_fwd_cnt = UINT32_MAX - 15;
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3,
	    VSOCK_CID_HOST, 1234, 80, 0, 0, 256 * 1024, 16);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK_EQ(c->peer_fwd_cnt, 16);
	ATF_CHECK_EQ(nconns(sc), 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(credit_update_full_ring_parked);
ATF_TC_BODY(credit_update_full_ring_parked, tc)
{
	/* A CREDIT_UPDATE built while the RX ring is full must not be lost
	 * (§5.10.6.1.2): it is parked on the pending-reply ring and flushed
	 * once the guest posts descriptors.  Parking counts as sent, so
	 * last_fwd_cnt advances (delivery is guaranteed while the device
	 * lives); only a pending-ring overflow drops, and that path does NOT
	 * advance last_fwd_cnt. */
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->tx_cnt = 2000;		/* so guest fwd_cnt 0 is valid */
	c->fwd_cnt = 1000;
	c->last_fwd_cnt = 0;

	g_rx_descs = 0;			/* RX ring full -> update is parked */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234,
	    80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(sc->vsc_pend_count == 1);	/* parked, not dropped */
	ATF_CHECK(g_ninject == 0);		/* nothing on the wire yet */
	ATF_CHECK(c->last_fwd_cnt == 1000);	/* parked counts as sent */

	g_rx_descs = 256;		/* guest posted descriptors */
	vtvsock_pend_flush(sc);
	ATF_CHECK(sc->vsc_pend_count == 0);
	ATF_CHECK(g_ninject == 1 &&
	    g_inject[0].op == VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	ATF_CHECK(g_inject[0].fwd_cnt == 1000);	/* real credit on the wire */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(pending_reply_overflow_retries_credit);
ATF_TC_BODY(pending_reply_overflow_retries_credit, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	bool fifo_ok;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->tx_cnt = 2000;
	c->fwd_cnt = VTVSOCK_CREDIT_UPDATE_THRESHOLD;
	c->last_fwd_cnt = 0;
	g_rx_descs = 0;

	/* Fill the bounded out-of-ring reply storage with older packets. */
	for (int i = 0; i < VTVSOCK_PEND_MAX; i++)
		ATF_REQUIRE(vtvsock_send_ctrl(sc, c,
		    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0) == 0);
	ATF_CHECK(sc->vsc_pend_count == VTVSOCK_PEND_MAX);
	ATF_CHECK(sc->vsc_pend_drops == 0);

	/* This reply is dropped; its credit state must remain unreported. */
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_REQUEST, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(sc->vsc_pend_count == VTVSOCK_PEND_MAX);
	ATF_CHECK(sc->vsc_pend_drops == 1);
	ATF_CHECK(c->last_fwd_cnt == 0);
	ATF_CHECK(g_ninject == 0);

	/* Refill drains only the older packets, in FIFO order. */
	g_rx_descs = 256;
	vtvsock_pend_flush(sc);
	ATF_CHECK(sc->vsc_pend_count == 0);
	ATF_CHECK(g_ninject == VTVSOCK_PEND_MAX);
	fifo_ok = true;
	for (int i = 0; i < g_ninject; i++)
		fifo_ok &= g_inject[i].op == VIRTIO_VSOCK_OP_CREDIT_REQUEST;
	ATF_CHECK(fifo_ok);

	/* Because last_fwd_cnt was preserved, the next check retries the update. */
	g_ninject = 0;
	vtvsock_maybe_credit_update(sc, c);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	ATF_CHECK(g_inject[0].fwd_cnt == VTVSOCK_CREDIT_UPDATE_THRESHOLD);
	ATF_CHECK(c->last_fwd_cnt == c->fwd_cnt);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(pending_reply_flush_is_queue_bounded);
ATF_TC_BODY(pending_reply_flush_is_queue_bounded, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	sc->vsc_queues[VTVSOCK_RXQ].vq_qsize = 1;
	sc->vsc_pend_count = 2;
	g_rx_descs = 2;
	vtvsock_pend_flush(sc);
	ATF_CHECK_EQ(g_ninject, 1);
	ATF_CHECK_EQ(sc->vsc_pend_count, 1);
	vtvsock_pend_flush(sc);
	ATF_CHECK_EQ(g_ninject, 2);
	ATF_CHECK_EQ(sc->vsc_pend_count, 0);
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

/*
 * An event may have been selected just before a vCPU closes a host socket.
 * Reusing that numeric descriptor for a new connection must not deliver the
 * old readiness edge to the new port.
 */
ATF_TC_WITHOUT_HEAD(stale_event_identity_rejects_reused_fd);
ATF_TC_BODY(stale_event_identity_rejects_reused_fd, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_conn *old_conn, *new_conn;
	void *stale;
	uint8_t byte = 0x5a;

	sc = mk_sc();
	reset_caps();
	g_next_fd = 77;
	old_conn = mk_established(sc, 7000, 8000, STREAM);
	stale = test_vtvsock_event_arg(sc, old_conn->event_id);
	/* conn_close is normally entered with the device mutex held. */
	pthread_mutex_lock(&sc->vsc_mtx);
	vtvsock_conn_close(sc, old_conn);
	pthread_mutex_unlock(&sc->vsc_mtx);

	/* Simulate immediate descriptor-number reuse by a new guest request. */
	g_next_fd = 77;
	new_conn = mk_established(sc, 7001, 8001, STREAM);
	stage_recv(&byte, sizeof(byte));
	g_ninject = 0;
	(vtvsock_conn_data_cb)(new_conn->fd, EVF_READ, stale);
	ATF_CHECK_EQ(g_ninject, 0);
	ATF_CHECK_EQ(new_conn->tx_cnt, 0);

	pthread_mutex_lock(&sc->vsc_mtx);
	vtvsock_conn_close(sc, new_conn);
	pthread_mutex_unlock(&sc->vsc_mtx);
	free(stale);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

/* --- A SEQPACKET record that fits the peer's whole window but not its
 * current credit is deferred atomically.  Mark that disabled-read interval as
 * a credit stall, request one update, and clear the mark only after the record
 * actually progresses. --- */
ATF_TC_WITHOUT_HEAD(seqpacket_partial_credit_tracks_stall);
ATF_TC_BODY(seqpacket_partial_credit_tracks_stall, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t rec[100];
	time_t stall_started;
	int enable_calls;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	c->peer_buf_alloc = 200;
	c->peer_fwd_cnt = 0;
	c->tx_cnt = 150;		/* current credit 50 < 100-byte record */
	memset(rec, 'C', sizeof(rec));
	stage_recv(rec, sizeof(rec));

	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_recv_off == 0);	/* record remains atomic and queued */
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_CREDIT_REQUEST);
	ATF_CHECK(c->stall_time != 0);
	stall_started = c->stall_time;

	/* A spurious redispatch must not send another request or restart time. */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(c->stall_time == stall_started);

	/* An RX notification may retry, but cannot clear the credit stall. */
	enable_calls = g_mevent_enable_calls;
	pci_vtvsock_notify_rx(sc, NULL);
	ATF_CHECK(g_mevent_enable_calls == enable_calls + 1);
	ATF_CHECK(c->stall_time == stall_started);
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);	/* redispatch sent no duplicate request */

	/* Seeing the queued record proves liveness, not data progress. */
	c->stall_time = 1;		/* force the reaper's five-second probe */
	vtvsock_reap_stale(sc);
	ATF_CHECK(c->stall_time != 0);
	ATF_CHECK(g_recv_off == 0);

	/* Guest consumed 100 prior bytes: credit grows from 50 to 150. */
	enable_calls = g_mevent_enable_calls;
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, SEQPACKET, 3,
	    VSOCK_CID_HOST, 1234, 80, 0, 0, 200, 100);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(vtvsock_peer_credit(c) == 150);
	ATF_CHECK(g_mevent_enable_calls == enable_calls + 1);
	ATF_CHECK(c->stall_time != 0);	/* no progress merely promised */

	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_recv_off == sizeof(rec));
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(c->stall_time == 0);
	free(sc);
}

/*
 * --- a host->guest record larger than one guest RX buffer is FRAGMENTED to
 * fit, not dropped.  The guest posts fixed-size RX buffers (Linux: 4 KiB); a
 * payload bigger than one buffer must be split across successive buffers with
 * EOM/EOR only on the packet carrying the record's final bytes.  Regression
 * guard for the "rx-descriptor-too-small" drop that silently lost every
 * host->guest packet above the buffer size on Linux. ---
 */
ATF_TC_WITHOUT_HEAD(host_rx_fragments_to_small_rx_buffer);
ATF_TC_BODY(host_rx_fragments_to_small_rx_buffer, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[200];
	uint32_t total = 0, cap;
	int i, last;
	reset_caps();
	g_rxbuf_len = 100;		/* header(44) + 56 payload per buffer */
	cap = 100 - VIRTIO14_VSOCK_HEADER_SIZE;	/* == 56 */
	c = mk_established(sc, 1234, 80, SEQPACKET);	/* ample credit */
	memset(rec, 'X', sizeof(rec));
	stage_recv(rec, sizeof(rec));			/* one 200-byte record */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);

	ATF_CHECK(g_ninject >= 4);	/* 200 / 56 -> 4 packets, none dropped */
	last = g_ninject - 1;
	for (i = 0; i < g_ninject; i++) {
		ATF_CHECK(g_inject[i].op == VIRTIO_VSOCK_OP_RW);
		ATF_CHECK(g_inject[i].len <= cap);	/* fits the RX buffer */
		total += g_inject[i].len;
		if (i < last)			/* middle packets: no boundary */
			ATF_CHECK((g_inject[i].flags &
			    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR)) == 0);
	}
	ATF_CHECK(total == sizeof(rec));	/* every byte delivered */
	ATF_CHECK((g_inject[last].flags &		/* only the last packet */
	    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR)) ==
	    (uint32_t)(VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR));
	free(sc);
}

/*
 * --- the same fragment-to-RX-buffer behavior for STREAM: a host->guest byte
 * run larger than one guest RX buffer is split across successive buffers, none
 * dropped, and (STREAM has no records) NO packet carries EOM/EOR. ---
 */
ATF_TC_WITHOUT_HEAD(host_rx_stream_fragments_to_small_rx_buffer);
ATF_TC_BODY(host_rx_stream_fragments_to_small_rx_buffer, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t data[200];
	uint32_t total = 0, cap;
	int i;
	reset_caps();
	g_rxbuf_len = 100;		/* header(44) + 56 payload per buffer */
	cap = 100 - VIRTIO14_VSOCK_HEADER_SIZE;
	c = mk_established(sc, 1234, 80, STREAM);	/* ample credit */
	memset(data, 'S', sizeof(data));
	stage_recv(data, sizeof(data));
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);

	ATF_CHECK(g_ninject >= 4);	/* 200 / 56 -> 4 packets, none dropped */
	for (i = 0; i < g_ninject; i++) {
		ATF_CHECK(g_inject[i].op == VIRTIO_VSOCK_OP_RW);
		ATF_CHECK(g_inject[i].len <= cap);
		ATF_CHECK((g_inject[i].flags &		/* STREAM: never a record */
		    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR)) == 0);
		total += g_inject[i].len;
	}
	ATF_CHECK(total == sizeof(data));	/* every byte delivered */
	free(sc);
}

/*
 * --- latent path: a SEQPACKET record larger than the guest's ENTIRE
 * advertised window can never be reassembled there, so it is reset rather than
 * deferred forever.  Reachable only for a guest advertising a small window
 * (Linux/5BSD default 256 KiB never hits it), so it is otherwise untested. ---
 */
ATF_TC_WITHOUT_HEAD(host_rx_oversized_seqpacket_record_resets);
ATF_TC_BODY(host_rx_oversized_seqpacket_record_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[500];
	int i, saw_rst = 0;
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->peer_buf_alloc = 100;	/* tiny guest window */
	c->peer_fwd_cnt = 0;
	c->tx_cnt = 0;			/* credit = 100 < record */
	memset(rec, 'Y', sizeof(rec));
	stage_recv(rec, sizeof(rec));	/* 500-byte record > 100 window */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);

	for (i = 0; i < g_ninject; i++)
		if (g_inject[i].op == VIRTIO_VSOCK_OP_RST)
			saw_rst = 1;
	ATF_CHECK(saw_rst);		/* undeliverable record -> RST */
	ATF_CHECK(nconns(sc) == 0);	/* connection torn down, not wedged */
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
	ATF_CHECK(saw_shutdown);
	/*
	 * A bare host EOF with the guest still sending is only a half-close:
	 * the connection must stay ESTABLISHED so the guest->host direction
	 * keeps relaying (teardown happens once the guest also shuts SEND).
	 */
	ATF_CHECK(c->state == CONN_ESTABLISHED);
	ATF_CHECK(c->host_eof);
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

ATF_TC_WITHOUT_HEAD(seqpacket_short_send_resets);
ATF_TC_BODY(seqpacket_short_send_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	const uint8_t pay[] = "record";

	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);
	g_send_override = true;
	g_send_result = 3;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(pay) - 1,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay) - 1);

	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_CHECK_EQ(sc->vsc_reasm_total, 0);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO_VSOCK_OP_RST);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpacket_emsgsize_resets);
ATF_TC_BODY(seqpacket_emsgsize_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	const uint8_t pay[] = "record";

	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EMSGSIZE;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(pay) - 1, VIRTIO_VSOCK_SEQ_EOM,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay) - 1);

	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_CHECK_EQ(sc->vsc_reasm_total, 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO_VSOCK_OP_RST);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpacket_deferred_short_send_resets);
ATF_TC_BODY(seqpacket_deferred_short_send_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	const uint8_t pay[] = "record";
	int fd;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	fd = c->fd;
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(pay) - 1,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay) - 1);
	ATF_REQUIRE_EQ(nconns(sc), 1);
	ATF_CHECK_EQ(c->tx_buf_len, sizeof(pay) - 1);

	g_send_result = 3;
	g_send_errno = 0;
	vtvsock_conn_write_cb(fd, EVF_WRITE, sc);
	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_CHECK_EQ(sc->vsc_reasm_total, 0);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO_VSOCK_OP_RST);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpacket_deferred_delivery_returns_credit);
ATF_TC_BODY(seqpacket_deferred_delivery_returns_credit, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	const uint8_t pay[] = "record";

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(pay) - 1,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR,
	    256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, pay, sizeof(pay) - 1);
	ATF_REQUIRE_EQ(nconns(sc), 1);
	ATF_CHECK_EQ(c->tx_buf_len, sizeof(pay) - 1);
	ATF_CHECK_EQ(c->fwd_cnt, 0);

	g_send_result = sizeof(pay) - 1;
	g_send_errno = 0;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK_EQ(nconns(sc), 1);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, 0);
	ATF_CHECK_EQ(c->fwd_cnt, sizeof(pay) - 1);
	ATF_CHECK_EQ(g_ninject, 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpacket_realloc_failure_resets_cleanly);
ATF_TC_BODY(seqpacket_realloc_failure_resets_cleanly, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t payload = 'X';

	reset_caps();
	(void)mk_established(sc, 1234, 80, SEQPACKET);
	g_realloc_fail = 1;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234,
	    80, sizeof(payload), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, &payload, sizeof(payload));

	ATF_CHECK(g_realloc_fail == 0);
	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(sc->vsc_conn_count == 0);
	ATF_CHECK(sc->vsc_reasm_total == 0);
	ATF_CHECK(sc->vsc_txbuf_total == 0);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	free(sc);
}

/*
 * --- guest->host SEQPACKET: fragments consume the advertised receive window
 * until the complete record reaches the host socket.  A sender must keep each
 * record within buf_alloc; accepting a larger record by returning credit for
 * mere reassembly would advertise capacity that is still occupied. ---
 */
ATF_TC_WITHOUT_HEAD(seqpacket_credit_follows_complete_delivery);
ATF_TC_BODY(seqpacket_credit_follows_complete_delivery, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	static uint8_t frag[100 * 1024];
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	memset(frag, 'Z', sizeof(frag));

	/*
	 * The first fragment is retained in the advertised receive window.
	 * It is not consumed, and therefore is not credited, before EOM.
	 */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(frag), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, frag, sizeof(frag));
	ATF_CHECK(g_send_calls == 0);			/* not delivered (no EOM) */
	ATF_CHECK(c->fwd_cnt == 0);			/* still consumes window */

	/*
	 * The complete 200 KiB record is within buf_alloc.  Once delivered as
	 * one datagram, its receive credit is returned exactly once.
	 */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(frag), VIRTIO_VSOCK_SEQ_EOM, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, frag, sizeof(frag));
	ATF_CHECK(g_send_calls == 1);			/* one host datagram */
	ATF_CHECK(g_send_len == 2 * sizeof(frag));	/* full 400 KiB record */
	ATF_CHECK(c->fwd_cnt == 2 * sizeof(frag));	/* credited exactly once */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpacket_record_over_advertised_window_resets);
ATF_TC_BODY(seqpacket_record_over_advertised_window_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	static uint8_t frag[160 * 1024];

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	memset(frag, 'Z', sizeof(frag));
	ATF_REQUIRE_EQ(c->buf_alloc, 256 * 1024);

	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(frag), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, frag, sizeof(frag));
	ATF_REQUIRE_EQ(nconns(sc), 1);
	ATF_CHECK_EQ(c->fwd_cnt, 0);

	/* 320 KiB total is larger than the advertised 256 KiB window. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(frag), VIRTIO_VSOCK_SEQ_EOM, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, frag, sizeof(frag));
	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO_VSOCK_OP_RST);
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
	ATF_CHECK(r == 0);		/* parked for retry, not lost */
	ATF_CHECK(g_ninject == 0);	/* nothing delivered to the guest */
	ATF_CHECK(sc->vsc_pend_count == 1);	/* held on the pending ring */
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
}

/* --- host->guest SEQPACKET EOR must reflect the host peer's MSG_EOR --- */
ATF_TC_WITHOUT_HEAD(seqpacket_host_eor_propagated);
ATF_TC_BODY(seqpacket_host_eor_propagated, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_conn *c;

	/* Record WITH MSG_EOR: final fragment carries EOM and EOR. */
	sc = mk_sc();
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	stage_recv("rec", 3);
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK((g_inject[0].flags & VIRTIO_VSOCK_SEQ_EOM) != 0);
	ATF_CHECK((g_inject[0].flags & VIRTIO_VSOCK_SEQ_EOR) != 0);
	free(sc);

	/*
	 * Record WITHOUT MSG_EOR: the guest must still see the message
	 * boundary (EOM) but NOT a record boundary (EOR).  Regression guard
	 * for the fix that stopped hardcoding EOR on every host->guest record.
	 */
	sc = mk_sc();
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	stage_recv("rec", 3);
	g_recv_no_eor = 1;
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK((g_inject[0].flags & VIRTIO_VSOCK_SEQ_EOM) != 0);
	ATF_CHECK((g_inject[0].flags & VIRTIO_VSOCK_SEQ_EOR) == 0);
	free(sc);
}

/* --- #4: a genuine host SEQPACKET EOF still drives a SHUTDOWN toward the guest --- */
ATF_TC_WITHOUT_HEAD(seqpacket_host_eof_sends_shutdown);
ATF_TC_BODY(seqpacket_host_eof_sends_shutdown, tc)
{
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
	ATF_CHECK(saw_shutdown);
	/*
	 * A bare host EOF with the guest still sending is only a half-close:
	 * the connection must stay ESTABLISHED so the guest->host direction
	 * keeps relaying (teardown happens once the guest also shuts SEND).
	 */
	ATF_CHECK(c->state == CONN_ESTABLISHED);
	ATF_CHECK(c->host_eof);
	free(sc);
}

/*
 * --- guest->host SEQPACKET: the reassembly buffer is FREED after a record is
 * delivered, not retained for the life of the connection.  Regression for the
 * retained-capacity DoS: the device-global reasm budget tracks only live
 * bytes, so retaining peak capacity would let a guest deliver one large record
 * on each of VTVSOCK_MAX_CONNS connections in turn and pin ~1 GiB of unfreed
 * memory while the live aggregate never exceeds a single record. ---
 */
ATF_TC_WITHOUT_HEAD(seqpacket_reasm_freed_after_delivery);
ATF_TC_BODY(seqpacket_reasm_freed_after_delivery, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);

	/* A non-EOM fragment allocates the reassembly buffer. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 4,
	    0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, (const uint8_t *)"ABCD", 4);
	ATF_CHECK(c->rx_reasm_cap >= 4);		/* capacity allocated */
	ATF_CHECK(sc->vsc_reasm_total == 4);

	/*
	 * EOM delivers the whole record; the reassembly buffer must be freed
	 * (rx_reasm == NULL, cap == 0) so an idle connection retains no
	 * capacity, and the global budget must return to zero.
	 */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST, 1234, 80, 3,
	    VIRTIO_VSOCK_SEQ_EOM, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, (const uint8_t *)"EFG", 3);
	ATF_CHECK(g_send_len == 7);			/* record delivered */
	ATF_CHECK(c->rx_reasm == NULL);			/* buffer freed */
	ATF_CHECK(c->rx_reasm_cap == 0);		/* no retained capacity */
	ATF_CHECK(sc->vsc_reasm_total == 0);		/* budget fully released */
	free(sc);
}

/*
 * --- guest half-close of the receive direction (SHUTDOWN_RCV) must NOT be
 * escalated to a full close by a later read wakeup (§5.10.6.5, matches Linux).
 * Regression: a stray conn_data_cb on the SHUT_RD host fd returns recv()==0,
 * which must not be misread as a peer EOF that tears down the still-open
 * guest->host direction. ---
 */
ATF_TC_WITHOUT_HEAD(shutdown_rcv_half_close_not_escalated);
ATF_TC_BODY(shutdown_rcv_half_close_not_escalated, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);

	/* Guest half-closes only the receive direction (legal half-close). */
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 0,
	    VIRTIO_VSOCK_SHUTDOWN_RCV, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 1);			/* connection survives */
	ATF_CHECK(c->peer_shutdown == VIRTIO_VSOCK_SHUTDOWN_RCV);

	/*
	 * A stray read wakeup returns recv()==0 on the SHUT_RD fd.  It must be
	 * ignored: the connection stays ESTABLISHED and NO SHUTDOWN(RCV|SEND)
	 * is emitted to the guest.
	 */
	g_recv_eof = 1;
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(nconns(sc) == 1);
	ATF_CHECK(c->state == CONN_ESTABLISHED);
	ATF_CHECK(g_ninject == 0);			/* no spurious SHUTDOWN */

	/* The still-open guest->host direction continues to deliver data. */
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80, 5,
	    0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, (const uint8_t *)"hello", 5);
	ATF_CHECK(g_send_len == 5 && memcmp(g_send_buf, "hello", 5) == 0);
	free(sc);
}

/*
 * Live-repro regression (e2e t_echo hang): the guest half-closes its SEND
 * direction, the host application reacts by closing its end.  The device
 * must notify the guest with a SHUTDOWN -- otherwise the guest, whose
 * receive direction is still open, waits for EOF forever.
 */
ATF_TC_WITHOUT_HEAD(half_close_send_then_host_eof);
ATF_TC_BODY(half_close_send_then_host_eof, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	int i, saw_shutdown = 0;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);

	/* Guest: shutdown(SHUT_WR) -> OP_SHUTDOWN with only the SEND flag. */
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, VIRTIO_VSOCK_SHUTDOWN_SEND, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == 1);	/* half-close must not tear down */

	/* Host application saw EOF and closed its end. */
	g_recv_eof = 1;
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	for (i = 0; i < g_ninject; i++)
		if (g_inject[i].op == VIRTIO_VSOCK_OP_SHUTDOWN)
			saw_shutdown = 1;
	/* no SHUTDOWN to guest here = guest receive direction hangs forever */
	ATF_CHECK(saw_shutdown);
	free(sc);
}

/*
 * Live-repro regression (e2e instant reply+close): host data and EOF are
 * both pending when the read callback runs.  The data must be forwarded
 * to the guest before the EOF-driven SHUTDOWN -- not dropped.
 */
ATF_TC_WITHOUT_HEAD(host_data_then_eof_same_dispatch);
ATF_TC_BODY(host_data_then_eof_same_dispatch, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int i, rw_at = -1, shut_at = -1;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);

	stage_recv("REPLY", 5);
	g_recv_eof = 1;		/* peer closed right after writing */
	/*
	 * The callback forwards one chunk per dispatch and relies on the
	 * level-triggered kqueue read event re-firing for the pending EOF;
	 * model that by dispatching twice.  The event must still be enabled
	 * after the first dispatch or the second one never happens live.
	 */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);

	for (i = 0; i < g_ninject; i++) {
		if (g_inject[i].op == VIRTIO_VSOCK_OP_RW && rw_at < 0)
			rw_at = i;
		if (g_inject[i].op == VIRTIO_VSOCK_OP_SHUTDOWN && shut_at < 0)
			shut_at = i;
	}
	ATF_CHECK(rw_at >= 0 && g_inject[rw_at].len == 5); /* data not dropped */
	ATF_CHECK(shut_at >= 0);		/* SHUTDOWN follows the final data */
	ATF_CHECK(rw_at < shut_at);	/* and is ordered after it */
	/* Re-delivered EOF must not duplicate the SHUTDOWN (event storm). */
	{
		int j, nshut = 0;
		for (j = 0; j < g_ninject; j++)
			if (g_inject[j].op == VIRTIO_VSOCK_OP_SHUTDOWN)
				nshut++;
		ATF_CHECK(nshut == 1);
	}
	free(sc);
}

/* Insert a bare control connection (as ctl_accept would) for reaper tests. */
static struct vtvsock_ctl_conn *
mk_ctl_conn(struct pci_vtvsock_softc *sc, int fd, time_t created)
{
	struct vtvsock_ctl_conn *cc = calloc(1, sizeof(*cc));
	assert(cc != NULL);
	cc->fd = fd;
	cc->evp = NULL;
	cc->created = created;
	TAILQ_INSERT_TAIL(&sc->vsc_ctl_conns, cc, link);
	sc->vsc_ctl_conn_count++;
	return (cc);
}

static int
nctlconns(struct pci_vtvsock_softc *sc)
{
	struct vtvsock_ctl_conn *cc; int k = 0;
	TAILQ_FOREACH(cc, &sc->vsc_ctl_conns, link) k++;
	return (k);
}

/*
 * --- reaper: a control connection that connected but never sent a
 * VSOCK_CTL_CONNECT is reaped after the idle timeout, so a host process
 * cannot hold ctl slots open indefinitely (a slot-exhaustion DoS). ---
 */
ATF_TC_WITHOUT_HEAD(reaper_reaps_idle_ctl_conn);
ATF_TC_BODY(reaper_reaps_idle_ctl_conn, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	reset_caps();
	(void)mk_ctl_conn(sc, g_next_fd++, 1 /* ancient */);
	ATF_CHECK(nctlconns(sc) == 1 && sc->vsc_ctl_conn_count == 1);

	vtvsock_reap_stale(sc);
	ATF_CHECK(nctlconns(sc) == 0);			/* idle ctl reaped */
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);		/* slot accounted */
	free(sc);
}

/*
 * --- reaper: an idle control connection whose request IS in flight (a
 * vtvsock_conn references its fd) must NOT be reaped -- that conn owns its
 * own connect timeout; reaping the ctl_conn under it would drop the reply
 * path. ---
 */
ATF_TC_WITHOUT_HEAD(reaper_keeps_referenced_ctl_conn);
ATF_TC_BODY(reaper_keeps_referenced_ctl_conn, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vtvsock_conn *c;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 1 /* ancient */);
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	c->ctl_fd = cc->fd;			/* request in flight via this ctl */

	vtvsock_reap_stale(sc);
	ATF_CHECK(nctlconns(sc) == 1);		/* protected while referenced */
	free(sc);
}

/*
 * --- control-socket cap: only VTVSOCK_MAX_CTL_CONNS host control
 * connections are accepted; the next accept is dropped, so a host process
 * cannot exhaust ctl slots.  Drives the real pci_vtvsock_ctl_accept. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_accept_cap);
ATF_TC_BODY(ctl_accept_cap, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	int i;
	reset_caps();
	ATF_REQUIRE_EQ(VTVSOCK_MAX_CTL_CONNS, 16);

	/* Accept exactly the cap: each call takes one ctl slot. */
	for (i = 0; i < VTVSOCK_MAX_CTL_CONNS; i++)
		pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == VTVSOCK_MAX_CTL_CONNS);

	/* One more must be refused: count does not grow. */
	pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == VTVSOCK_MAX_CTL_CONNS);
	free(sc);
}

/*
 * --- control-socket CONNECT: a host VSOCK_CTL_CONNECT drives an outbound
 * host->guest connection -- a CONN_CONNECTING conn is created and an
 * OP_REQUEST is emitted to the guest, referencing the ctl fd for the reply. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_connect_emits_request);
ATF_TC_BODY(ctl_connect_emits_request, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vtvsock_conn *conn;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100 /* not idle */);

	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 1);			/* a conn was created */
	conn = TAILQ_FIRST(&sc->vsc_conns);
	ATF_CHECK(conn != NULL && conn->state == CONN_CONNECTING);
	ATF_CHECK(conn != NULL && conn->ctl_fd == cc->fd);  /* reply path set */
	ATF_CHECK(g_ninject == 1 &&
	    g_inject[0].op == VIRTIO_VSOCK_OP_REQUEST);	/* guest asked to connect */
	ATF_CHECK(g_inject[0].dst_port == 1234);
	free(sc);
}

/*
 * --- control messages arrive over SOCK_STREAM, so a valid 16-byte request
 * can be split across reads.  The first callback must retain the partial frame
 * and the second must complete exactly one connection request. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_connect_accepts_short_reads);
ATF_TC_BODY(ctl_connect_accepts_short_reads, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);

	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	g_recv_chunk_max = 1;
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(g_ninject == 0);
	ATF_CHECK(cc->msg_off == 1);

	g_recv_chunk_max = 0;
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 1);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_REQUEST);
	ATF_CHECK(g_inject[0].dst_port == 1234);
	free(sc);
}

/*
 * --- only the two socket types represented by virtio-vsock are accepted.
 * An invalid kernel socket type gets a deterministic error reply and must not
 * create a relay socket or emit a request to the guest. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_connect_rejects_invalid_type);
ATF_TC_BODY(ctl_connect_rejects_invalid_type, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vsock_ctl_msg reply;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);

	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_DGRAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(g_ninject == 0);
	ATF_REQUIRE(g_send_len == sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK(g_send_calls == 1);
	ATF_CHECK(reply.cmd == VSOCK_CTL_CONNECT);
	ATF_CHECK(reply.port == 1234);
	ATF_CHECK(reply.type == SOCK_DGRAM);
	ATF_CHECK(reply.status == -ESOCKTNOSUPPORT);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(negotiated_socket_types);
ATF_TC_BODY(negotiated_socket_types, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_ctl_conn *cc;
	struct virtio_vsock_hdr h;
	struct vsock_ctl_msg reply;

	ATF_CHECK((vtvsock_vi_consts.vc_hv_caps &
	    VIRTIO14_VSOCK_F_STREAM) != 0);
	ATF_CHECK((vtvsock_vi_consts.vc_hv_caps &
	    VIRTIO14_VSOCK_F_SEQPACKET) != 0);
	ATF_CHECK((vtvsock_vi_consts.vc_hv_caps &
	    VIRTIO14_VSOCK_F_NO_IMPLIED_STREAM) != 0);

	sc = mk_sc();
	ATF_CHECK(vtvsock_type_supported(sc, VIRTIO14_VSOCK_TYPE_STREAM));
	ATF_CHECK(vtvsock_type_supported(sc,
	    VIRTIO14_VSOCK_TYPE_SEQPACKET));

	/* No device feature bits retains the historical implied STREAM. */
	sc->vsc_features = 0;
	ATF_CHECK(vtvsock_type_supported(sc, VIRTIO14_VSOCK_TYPE_STREAM));
	ATF_CHECK(!vtvsock_type_supported(sc,
	    VIRTIO14_VSOCK_TYPE_SEQPACKET));

	/* SEQPACKET can imply STREAM only without NO_IMPLIED_STREAM. */
	sc->vsc_features = VIRTIO14_VSOCK_F_SEQPACKET;
	ATF_CHECK(vtvsock_type_supported(sc, VIRTIO14_VSOCK_TYPE_STREAM));
	ATF_CHECK(vtvsock_type_supported(sc,
	    VIRTIO14_VSOCK_TYPE_SEQPACKET));
	sc->vsc_features = VIRTIO14_VSOCK_F_SEQPACKET |
	    VIRTIO14_VSOCK_F_NO_IMPLIED_STREAM;
	ATF_CHECK(!vtvsock_type_supported(sc,
	    VIRTIO14_VSOCK_TYPE_STREAM));
	ATF_CHECK(vtvsock_type_supported(sc,
	    VIRTIO14_VSOCK_TYPE_SEQPACKET));

	/* A guest request for an unnegotiated type is rejected before I/O. */
	reset_caps();
	mkhdr(&h, VIRTIO14_VSOCK_OP_REQUEST, STREAM, 3,
	    VIRTIO14_VSOCK_CID_HOST, 1234, 80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO14_VSOCK_OP_RST);
	ATF_CHECK_EQ(g_socket_calls, 0);
	ATF_CHECK_EQ(g_connectat_calls, 0);

	/* The host control API observes the same negotiated type policy. */
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_CHECK_EQ(g_ninject, 0);
	ATF_REQUIRE_EQ(g_send_len, sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK_EQ(reply.status, -ESOCKTNOSUPPORT);
	free(sc);
}

/*
 * --- relay socket buffers are enlarged to one advertised window
 * (VTVSOCK_BUF_ALLOC) on connect, so a full-window SEQPACKET record traverses
 * the host<->app Unix socket whole rather than being chopped at the 64 KiB
 * kernel default.  Both socketpair ends must be sized (SND and RCV each), so
 * the sender's outstanding limit and the receiver's capacity line up. ---
 */
ATF_TC_WITHOUT_HEAD(relay_bufsize_enlarged_on_connect);
ATF_TC_BODY(relay_bufsize_enlarged_on_connect, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	reset_caps();
	g_sndbuf_last = g_rcvbuf_last = 0;
	g_sndbuf_calls = g_rcvbuf_calls = 0;
	cc = mk_ctl_conn(sc, g_next_fd++, 100 /* not idle */);

	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_SEQPACKET);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	/* Both socketpair ends sized: SND and RCV each requested >= twice. */
	ATF_CHECK(g_sndbuf_calls >= 2);
	ATF_CHECK(g_rcvbuf_calls >= 2);
	/* Requested exactly one advertised window on both. */
	ATF_CHECK(g_sndbuf_last == 256 * 1024);	/* VTVSOCK_BUF_ALLOC */
	ATF_CHECK(g_rcvbuf_last == 256 * 1024);
	free(sc);
}

/*
 * --- control-socket unknown command: an unrecognized ctl cmd is ignored
 * cleanly -- no connection created, no packet emitted, no crash. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_unknown_cmd_ignored);
ATF_TC_BODY(ctl_unknown_cmd_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);

	stage_ctl_msg(0xdead /* unknown */, 1234, SOCK_STREAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 0);		/* nothing created */
	ATF_CHECK(g_ninject == 0);		/* nothing emitted */
	free(sc);
}

/*
 * --- control-socket CONNECT under socketpair() failure returns an -ENOMEM
 * status reply to the host and creates no connection. ---
 */
ATF_TC_WITHOUT_HEAD(ctl_connect_socketpair_fail);
ATF_TC_BODY(ctl_connect_socketpair_fail, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	g_socketpair_fail = 1;

	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);

	ATF_CHECK(nconns(sc) == 0);		/* no conn on failure */
	ATF_CHECK(g_ninject == 0);		/* no OP_REQUEST to guest */
	g_socketpair_fail = 0;
	free(sc);
}

/*
 * --- connection cap: the (MAX_CONNS+1)th guest OP_REQUEST is refused with
 * RST, and closing a connection frees a slot so a later REQUEST succeeds.
 * The DoS backstop for a guest that opens connections without bound. ---
 */
ATF_TC_WITHOUT_HEAD(conn_cap_refuses_and_reclaims);
ATF_TC_BODY(conn_cap_refuses_and_reclaims, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	struct vtvsock_conn *victim;
	int i;
	reset_caps();
	ATF_REQUIRE_EQ(VTVSOCK_MAX_CONNS, 256);
	g_connectat_result = 0;			/* host listener always present */

	/*
	 * Fill exactly to the cap: MAX_CONNS successful REQUESTs.  Reset the
	 * injected-packet capture each iteration so the 256 RESPONSEs don't
	 * overflow the harness's fixed g_inject[128] array (we only care about
	 * the cap behavior, checked below).
	 */
	for (i = 0; i < VTVSOCK_MAX_CONNS; i++) {
		g_ninject = 0;
		g_rx_descs = 256;	/* replenish RX ring for the RESPONSE */
		mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST,
		    1000 + i, 80, 0, 0, 256 * 1024, 0);
		vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	}
	ATF_CHECK(nconns(sc) == VTVSOCK_MAX_CONNS);

	/* One more must be refused with RST, not crash or over-allocate. */
	g_ninject = 0;
	g_rx_descs = 256;
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST,
	    9999, 80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == VTVSOCK_MAX_CONNS);	/* not exceeded */
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);

	/* Close one, freeing a slot; a fresh REQUEST now succeeds. */
	victim = TAILQ_FIRST(&sc->vsc_conns);
	vtvsock_conn_close(sc, victim);
	ATF_CHECK(nconns(sc) == VTVSOCK_MAX_CONNS - 1);
	g_ninject = 0;
	g_rx_descs = 256;
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST,
	    8888, 80, 0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(nconns(sc) == VTVSOCK_MAX_CONNS);	/* slot reclaimed */
	ATF_CHECK(g_ninject == 1 &&
	    g_inject[0].op == VIRTIO_VSOCK_OP_RESPONSE);
	free(sc);
}

/*
 * --- reaper: a connection stuck in CONN_CLOSING past the timeout is
 * force-RST and freed, so an unacknowledged close cannot leak a slot even
 * if the guest goes silent.  close_time is set ancient so the real-clock
 * delta exceeds the 8 s threshold. ---
 */
ATF_TC_WITHOUT_HEAD(reaper_closes_stuck_closing);
ATF_TC_BODY(reaper_closes_stuck_closing, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CLOSING;
	c->close_time = 1;		/* ancient: now - 1 >> 8 s */

	vtvsock_reap_stale(sc);
	ATF_CHECK(nconns(sc) == 0);			/* reaped */
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	free(sc);
}

/*
 * --- reaper: a host-initiated connect stuck in CONN_CONNECTING past its
 * timeout is torn down (the guest never sent OP_RESPONSE). ---
 */
ATF_TC_WITHOUT_HEAD(reaper_times_out_connecting);
ATF_TC_BODY(reaper_times_out_connecting, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	c->close_time = 1;		/* ancient: now - 1 >> 30 s */

	vtvsock_reap_stale(sc);
	ATF_CHECK(nconns(sc) == 0);			/* reaped */
	free(sc);
}

/*
 * --- malformed guest TX: an OP_RW whose declared len exceeds VTVSOCK_MAX_PKT
 * is dropped without creating/touching a connection (a guest cannot make the
 * device read an over-large packet). ---
 */
ATF_TC_WITHOUT_HEAD(tx_oversized_paylen_dropped);
ATF_TC_BODY(tx_oversized_paylen_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;
	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);

	/* Declared payload 70000 > VTVSOCK_MAX_PKT (65536): must be dropped. */
	mkhdr(h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    70000, 0, 256 * 1024, 0);
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_send_calls == 0);	/* payload never forwarded to host */
	free(sc);
}

/*
 * --- malformed guest TX: control operations are header-only.  Reject a
 * payload-bearing CREDIT_UPDATE before it reaches either backend.  Use the
 * kernel backend here so a regression cannot hand the malformed frame to the
 * host /dev/vsock provider; the validation is shared with the userspace
 * backend. ---
 */
ATF_TC_WITHOUT_HEAD(tx_control_payload_dropped);
ATF_TC_BODY(tx_control_payload_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 1, 0, 256 * 1024, 0);
	g_rxbuf[VIRTIO14_VSOCK_HEADER_SIZE] = 0xa5;
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + 1;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;

	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 0);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_rx_descs == 0);
	ATF_CHECK(g_needs_reset_calls == 0);
	ATF_CHECK(!sc->vsc_kernel_failed);
	free(sc);
}

/*
 * --- malformed guest TX: an OP_RW must supply every byte declared by
 * hdr.len.  A short descriptor chain is dropped rather than forwarded as a
 * truncated message or charged inconsistently against connection credit. ---
 */
ATF_TC_WITHOUT_HEAD(tx_truncated_payload_dropped);
ATF_TC_BODY(tx_truncated_payload_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	mkhdr(h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    8, 0, 256 * 1024, 0);
	memset(g_rxbuf + VIRTIO14_VSOCK_HEADER_SIZE, 0x5a, 4);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + 4;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;

	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(g_writev_calls == 0);
	ATF_CHECK(g_rx_descs == 0);
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_fragments_for_guest_buffers);
ATF_TC_BODY(kernel_rx_fragments_for_guest_buffers, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h;
	uint32_t payload_len = 5000;
	uint16_t budget = 3;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx = calloc(1,
	    VIRTIO14_VSOCK_HEADER_SIZE + payload_len);
	ATF_REQUIRE(sc->vsc_kernel_rx != NULL);
	h = (struct virtio_vsock_hdr *)sc->vsc_kernel_rx;
	mkhdr(h, VIRTIO_VSOCK_OP_RW, SEQPACKET, VSOCK_CID_HOST, 3,
	    80, 1234, payload_len,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + 2048;
	g_rx_descs = 3;
	pthread_mutex_lock(&sc->vsc_mtx);
	vtvsock_kernel_drain_budget(sc, &budget);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(g_ninject == 3);
	ATF_CHECK(g_inject[0].len == 2048);
	ATF_CHECK(g_inject[1].len == 2048);
	ATF_CHECK(g_inject[2].len == 904);
	ATF_CHECK(g_inject[0].flags == 0);
	ATF_CHECK(g_inject[1].flags == 0);
	ATF_CHECK(g_inject[2].flags ==
	    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR));
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_accepts_header_only_packet);
ATF_TC_BODY(kernel_rx_accepts_header_only_packet, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;

	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_rx_descs = 2;
	ATF_CHECK(vtvsock_inject_raw(sc, &h, NULL, 0) == 0);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_rel_len == VIRTIO14_VSOCK_HEADER_SIZE);
	ATF_CHECK(g_inject[0].len == 0);
	ATF_CHECK_EQ(g_endchains_all, 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_large_descriptor_capacity);
ATF_TC_BODY(kernel_rx_large_descriptor_capacity, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t payload = 0xa5;

	reset_caps();
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 1, 0, 65536, 0);
	/* The mock advertises a large chain; only the copied prefix is accessed. */
	g_rxbuf_len = (size_t)UINT32_MAX + VIRTIO14_VSOCK_HEADER_SIZE + 1;
	g_rx_descs = 1;
	ATF_CHECK(vtvsock_inject_raw(sc, &h, &payload, 1) == 1);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_rel_len == VIRTIO14_VSOCK_HEADER_SIZE + 1);
	ATF_CHECK(g_inject[0].len == 1);
	ATF_CHECK(g_rxbuf[VIRTIO14_VSOCK_HEADER_SIZE] == payload);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_reuses_preallocated_buffer);
ATF_TC_BODY(kernel_rx_reuses_preallocated_buffer, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t *buffer;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_rx_descs = 1;
	ATF_REQUIRE(write(sv[1], &h, VIRTIO14_VSOCK_HEADER_SIZE) ==
	    VIRTIO14_VSOCK_HEADER_SIZE);
	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	ATF_CHECK(sc->vsc_kernel_rx_buf == buffer);
	ATF_CHECK(!sc->vsc_kernel_failed);
	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_dispatch_is_queue_bounded);
ATF_TC_BODY(kernel_rx_dispatch_is_queue_bounded, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t *buffer;
	int sv[2];

	reset_caps();
	/* Datagram records model the one-provider-packet-per-read device ABI. */
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc->vsc_queues[VTVSOCK_RXQ].vq_qsize = 1;
	g_rx_descs = 2;
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	mkhdr(&h, VIRTIO_VSOCK_OP_RST, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 0, 0, 0, 0);
	for (int i = 0; i < 2; i++)
		ATF_REQUIRE(write(sv[1], &h, VIRTIO14_VSOCK_HEADER_SIZE) ==
		    VIRTIO14_VSOCK_HEADER_SIZE);

	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK_EQ(g_ninject, 1);
	/* Level-triggered provider readiness schedules the retained packet. */
	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK_EQ(g_ninject, 2);
	ATF_CHECK(!sc->vsc_kernel_failed);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_fragment_dispatch_is_queue_bounded);
ATF_TC_BODY(kernel_rx_fragment_dispatch_is_queue_bounded, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *hdr;
	uint8_t *buffer, *packet;
	const uint32_t payload_len = 5000;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	packet = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + payload_len);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE(packet != NULL);
	hdr = (struct virtio_vsock_hdr *)packet;
	mkhdr(hdr, VIRTIO_VSOCK_OP_RW, SEQPACKET, VSOCK_CID_HOST, 3,
	    80, 1234, payload_len,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR, 65536, 0);

	sc->vsc_kernel = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc->vsc_queues[VTVSOCK_RXQ].vq_qsize = 1;
	g_rx_descs = 3;
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + 2048;
	ATF_REQUIRE(write(sv[1], packet,
	    VIRTIO14_VSOCK_HEADER_SIZE + payload_len) ==
	    VIRTIO14_VSOCK_HEADER_SIZE + payload_len);

	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK_EQ(g_ninject, 1);
	ATF_CHECK_EQ(sc->vsc_kernel_rx_off, 2048);
	ATF_REQUIRE(sc->vsc_kernel_rx != NULL);
	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK_EQ(g_ninject, 2);
	ATF_CHECK_EQ(sc->vsc_kernel_rx_off, 4096);
	ATF_REQUIRE(sc->vsc_kernel_rx != NULL);
	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK_EQ(g_ninject, 3);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	ATF_CHECK_EQ(g_inject[0].len, 2048);
	ATF_CHECK_EQ(g_inject[1].len, 2048);
	ATF_CHECK_EQ(g_inject[2].len, 904);
	ATF_CHECK_EQ(g_inject[0].flags, 0);
	ATF_CHECK_EQ(g_inject[1].flags, 0);
	ATF_CHECK_EQ(g_inject[2].flags,
	    VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR);
	ATF_CHECK(!sc->vsc_kernel_failed);

	free(packet);
	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_pending_and_data_share_queue_budget);
ATF_TC_BODY(kernel_rx_pending_and_data_share_queue_budget, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *hdr;
	uint8_t *packet;
	uint16_t budget;

	reset_caps();
	packet = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + 1);
	ATF_REQUIRE(packet != NULL);
	hdr = (struct virtio_vsock_hdr *)packet;
	mkhdr(hdr, VIRTIO_VSOCK_OP_RW, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 1, 0, 65536, 0);
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx = packet;
	sc->vsc_queues[VTVSOCK_RXQ].vq_qsize = 1;
	sc->vsc_pend_count = 1;
	g_rx_descs = 2;
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + 1;
	budget = 1;
	vtvsock_kernel_drain_budget(sc, &budget);
	ATF_CHECK_EQ(g_ninject, 1);
	ATF_CHECK_EQ(sc->vsc_pend_count, 0);
	ATF_CHECK(sc->vsc_kernel_rx != NULL);
	ATF_CHECK_EQ(budget, 0);
	budget = 1;
	vtvsock_kernel_drain_budget(sc, &budget);
	ATF_CHECK_EQ(g_ninject, 2);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	ATF_CHECK_EQ(g_inject[1].op, VIRTIO_VSOCK_OP_RW);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_refill_pulls_queued_packet);
ATF_TC_BODY(kernel_rx_refill_pulls_queued_packet, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t *buffer;
	int disable_calls, sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = sv[0];
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	mkhdr(&h, VIRTIO_VSOCK_OP_RST, STREAM, VSOCK_CID_HOST, 3,
	    7109, 1234, 0, 0, 0, 0);

	/* The provider becomes readable before the guest posts an RX buffer. */
	g_rx_descs = 0;
	ATF_REQUIRE(write(sv[1], &h, VIRTIO14_VSOCK_HEADER_SIZE) ==
	    VIRTIO14_VSOCK_HEADER_SIZE);
	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK(g_ninject == 0);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	disable_calls = g_mevent_disable_calls;
	ATF_CHECK(disable_calls > 0);

	/* Refilling RX must pull the already-queued RST without a new event. */
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_rx_descs = 1;
	pci_vtvsock_notify_rx(sc, &sc->vsc_queues[VTVSOCK_RXQ]);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	ATF_CHECK(!sc->vsc_kernel_failed);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_fatal_error_disables_event);
ATF_TC_BODY(kernel_rx_fatal_error_disables_event, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	int enable_calls;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vtvsock_kernel_read_cb(-1, EVF_READ, sc);
	ATF_CHECK(g_mevent_disable_calls == 1);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	enable_calls = g_mevent_enable_calls;
	pci_vtvsock_notify_rx(sc, &sc->vsc_queues[VTVSOCK_RXQ]);
	ATF_CHECK(g_mevent_enable_calls == enable_calls);
	ATF_CHECK(g_mevent_disable_calls == 2);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_short_packet_needs_reset);
ATF_TC_BODY(kernel_rx_short_packet_needs_reset, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	uint8_t byte, *buffer;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	g_rx_descs = 1;
	byte = 0xa5;
	ATF_REQUIRE(write(sv[1], &byte, sizeof(byte)) == sizeof(byte));

	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_mevent_disable_calls == 1);
	ATF_CHECK(g_ninject == 0);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_rx_length_mismatch_needs_reset);
ATF_TC_BODY(kernel_rx_length_mismatch_needs_reset, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t *buffer;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	g_rx_descs = 1;
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, VSOCK_CID_HOST, 3,
	    80, 1234, 1, 0, 65536, 0);
	ATF_REQUIRE(write(sv[1], &h, VIRTIO14_VSOCK_HEADER_SIZE) ==
	    VIRTIO14_VSOCK_HEADER_SIZE);

	vtvsock_kernel_read_cb(sv[0], EVF_READ, sc);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_mevent_disable_calls == 1);
	ATF_CHECK(g_ninject == 0);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_reset_success_recovers_backend);
ATF_TC_BODY(kernel_reset_success_recovers_backend, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h;
	uint8_t *buffer;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = sv[0];
	sc->vsc_kernel_failed = true;
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_rx = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE);
	ATF_REQUIRE(sc->vsc_kernel_rx != NULL);
	sc->vsc_kernel_rx_off = 7;
	sc->vsc_kernel_tx = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE);
	ATF_REQUIRE(sc->vsc_kernel_tx != NULL);
	sc->vsc_kernel_tx_len = VIRTIO14_VSOCK_HEADER_SIZE;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_kernel_write_evp = &g_mev[1];
	sc->vsc_features = VIRTIO_VSOCK_F_STREAM |
	    VIRTIO_VSOCK_F_SEQPACKET;

	pci_vtvsock_reset(sc);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(sc->vsc_kernel_rx == NULL);
	ATF_CHECK(sc->vsc_kernel_rx_off == 0);
	ATF_CHECK(sc->vsc_kernel_tx == NULL);
	ATF_CHECK(sc->vsc_kernel_tx_len == 0);
	ATF_CHECK(sc->vsc_features == 0);
	ATF_CHECK(g_mevent_disable_calls == 1);

	ATF_CHECK_EQ(pci_vtvsock_neg_features(sc,
	    VIRTIO_VSOCK_F_STREAM), 0);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(g_ioctl_features == VIRTIO_VSOCK_F_STREAM);

	h = (struct virtio_vsock_hdr *)g_rxbuf;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 0);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_fatal_error_needs_reset);
ATF_TC_BODY(kernel_tx_fatal_error_needs_reset, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 2;
	g_writev_override = true;
	g_writev_result = -1;
	g_writev_errno = ENXIO;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_rx_descs == 1);
	ATF_CHECK(g_endchains == 1);
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(g_rx_descs == 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_short_write_needs_reset);
ATF_TC_BODY(kernel_tx_short_write_needs_reset, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	g_writev_override = true;
	g_writev_result = VIRTIO14_VSOCK_HEADER_SIZE - 1;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_rx_descs == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_backpressure_is_retried);
ATF_TC_BODY(kernel_tx_backpressure_is_retried, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_kernel_write_evp = mevent_add_disabled(700, EVF_WRITE,
	    vtvsock_kernel_write_cb, sc);
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 2;
	g_writev_override = true;
	g_writev_result = -1;
	g_writev_errno = EWOULDBLOCK;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_REQUIRE(sc->vsc_kernel_tx != NULL);
	ATF_CHECK(sc->vsc_kernel_tx_len == VIRTIO14_VSOCK_HEADER_SIZE);
	ATF_CHECK(g_rx_descs == 1);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(g_mevent_enable_calls == 1);

	g_writev_override = false;
	vtvsock_kernel_write_cb(700, EVF_WRITE, sc);
	ATF_CHECK(sc->vsc_kernel_tx == NULL);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(g_rx_descs == 0);
	ATF_CHECK(g_writev_calls == 3);
	ATF_CHECK(g_mevent_disable_calls == 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_retry_short_write_needs_reset);
ATF_TC_BODY(kernel_tx_retry_short_write_needs_reset, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_kernel_write_evp = mevent_add_disabled(700, EVF_WRITE,
	    vtvsock_kernel_write_cb, sc);
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	g_writev_override = true;
	g_writev_result = -1;
	g_writev_errno = EWOULDBLOCK;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_REQUIRE(sc->vsc_kernel_tx != NULL);
	ATF_CHECK(!sc->vsc_kernel_failed);

	g_writev_result = VIRTIO14_VSOCK_HEADER_SIZE - 1;
	g_writev_errno = 0;
	vtvsock_kernel_write_cb(700, EVF_WRITE, sc);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(sc->vsc_kernel_tx != NULL);

	pci_vtvsock_reset(sc);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(sc->vsc_kernel_tx == NULL);
	ATF_CHECK(sc->vsc_features == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_malformed_packet_is_dropped);
ATF_TC_BODY(kernel_tx_malformed_packet_is_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	mkhdr(h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	g_writev_override = true;
	g_writev_result = -1;
	g_writev_errno = EINVAL;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 0);
	ATF_CHECK(g_rx_descs == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_failure_survives_feature_update);
ATF_TC_BODY(kernel_failure_survives_feature_update, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_kernel_failed = true;
	ATF_CHECK_EQ(pci_vtvsock_neg_features(sc,
	    VIRTIO_VSOCK_F_STREAM), EIO);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_feature_update_masks_transport_bits);
ATF_TC_BODY(kernel_feature_update_masks_transport_bits, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	uint64_t negotiated;

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	negotiated = VIRTIO_F_VERSION_1 | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO14_F_SUSPEND | VIRTIO_VSOCK_F_SEQPACKET;
	ATF_CHECK_EQ(pci_vtvsock_neg_features(sc, negotiated), 0);
	ATF_CHECK(g_ioctl_last_request ==
	    VSOCK_IOC_TRANSPORT_SET_FEATURES);
	ATF_CHECK(g_ioctl_features == VIRTIO_VSOCK_F_SEQPACKET);
	ATF_CHECK(sc->vsc_features == negotiated);
	ATF_CHECK(!sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_reset_failure_remains_fatal);
ATF_TC_BODY(kernel_reset_failure_remains_fatal, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_RESET;
	g_ioctl_fail_errno = EIO;
	pci_vtvsock_reset(sc);
	ATF_CHECK(sc->vsc_kernel_failed);

	/* A later successful feature update cannot repair a failed reset. */
	g_ioctl_fail_request = 0;
	ATF_CHECK_EQ(pci_vtvsock_neg_features(sc,
	    VIRTIO_VSOCK_F_STREAM), EIO);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(g_needs_reset_calls == 1);
	ATF_CHECK((sc->vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_forwards_complete_packet);
ATF_TC_BODY(kernel_tx_forwards_complete_packet, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;
	const char payload[] = "kernel-vsock";

	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	mkhdr(h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, sizeof(payload), 0, 65536, 0);
	memcpy(g_rxbuf + VIRTIO14_VSOCK_HEADER_SIZE, payload,
	    sizeof(payload));
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE + sizeof(payload);
	g_chain_readable = 1;
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(g_writev_len ==
	    VIRTIO14_VSOCK_HEADER_SIZE + sizeof(payload));
	ATF_CHECK(memcmp(g_writev_buf + VIRTIO14_VSOCK_HEADER_SIZE, payload,
	    sizeof(payload)) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_tx_pulls_synchronous_reply);
ATF_TC_BODY(kernel_tx_pulls_synchronous_reply, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr *tx = (void *)g_rxbuf;
	struct virtio_vsock_hdr rst_hdr;
	uint8_t *buffer;
	int sv[2];

	reset_caps();
	ATF_REQUIRE(__real_socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_REQUIRE(__real_fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
	buffer = calloc(1, VIRTIO14_VSOCK_HEADER_SIZE + VTVSOCK_MAX_PKT);
	ATF_REQUIRE(buffer != NULL);
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = sv[0];
	sc->vsc_kernel_rx_buf = buffer;
	sc->vsc_kernel_evp = &g_mev[0];
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	/* Guest REQUEST to an unused host port. */
	mkhdr(tx, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST,
	    1234, 7109, 0, 0, 65536, 0);
	g_rxbuf_len = VIRTIO14_VSOCK_HEADER_SIZE;
	g_chain_readable = 0;
	g_chain_writable = 1;
	g_getchain_consumes = 0;
	g_rx_descs = 1;	/* one guest RX chain */
	g_one_shot_vq = &sc->vsc_queues[VTVSOCK_TXQ];

	/* Model the RST that /dev/vsock queues synchronously during writev. */
	mkhdr(&rst_hdr, VIRTIO_VSOCK_OP_RST, STREAM, VSOCK_CID_HOST, 3,
	    7109, 1234, 0, 0, 0, 0);
	ATF_REQUIRE(write(sv[1], &rst_hdr, VIRTIO14_VSOCK_HEADER_SIZE) ==
	    VIRTIO14_VSOCK_HEADER_SIZE);
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(g_writev_calls == 1);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(!sc->vsc_kernel_failed);

	__real_close(sv[1]);
	__real_close(sv[0]);
	free(buffer);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(backend_names_are_userspace_and_kernel);
ATF_TC_BODY(backend_names_are_userspace_and_kernel, tc)
{
	bool is_kernel;

	is_kernel = true;
	ATF_CHECK(vtvsock_parse_backend(NULL, &is_kernel) == 0);
	ATF_CHECK(!is_kernel);
	is_kernel = true;
	ATF_CHECK(vtvsock_parse_backend("userspace", &is_kernel) == 0);
	ATF_CHECK(!is_kernel);
	is_kernel = false;
	ATF_CHECK(vtvsock_parse_backend("kernel", &is_kernel) == 0);
	ATF_CHECK(is_kernel);
	ATF_CHECK(vtvsock_parse_backend("unix", &is_kernel) == -1);
	ATF_CHECK(vtvsock_parse_backend("native", &is_kernel) == -1);
}

ATF_TC_WITHOUT_HEAD(queue_reset_discards_only_selected_queue_work);
ATF_TC_BODY(queue_reset_discards_only_selected_queue_work, tc)
{
	struct pci_vtvsock_softc *sc;
	uint8_t *tx;

	sc = mk_sc();
	reset_caps();
	tx = malloc(4);
	ATF_REQUIRE(tx != NULL);
	memcpy(tx, "test", 4);
	sc->vsc_pend_count = 1;
	sc->vsc_kernel_tx = tx;
	sc->vsc_kernel_tx_len = 4;
	sc->vsc_kernel_write_evp = &g_mev[1];

	/* Resetting RX preserves work owned by TX and device protocol state. */
	sc->vsc_queues[VIRTIO14_VSOCK_RECEIVEQ].vq_num =
	    VIRTIO14_VSOCK_RECEIVEQ;
	ATF_CHECK_EQ(pci_vtvsock_qreset(sc,
	    &sc->vsc_queues[VIRTIO14_VSOCK_RECEIVEQ], 7), 0);
	ATF_CHECK(sc->vsc_pend_count == 1);
	ATF_CHECK(sc->vsc_kernel_tx == tx);
	ATF_CHECK(sc->vsc_kernel_tx_len == 4);
	ATF_CHECK(memcmp(sc->vsc_kernel_tx, "test", 4) == 0);

	/*
	 * Resetting TX discards the copied request that was waiting for host
	 * transport capacity and disables its retry callback.  It must never be
	 * submitted after the driver has replaced the TX virtqueue.
	 */
	sc->vsc_queues[VIRTIO14_VSOCK_TRANSMITQ].vq_num =
	    VIRTIO14_VSOCK_TRANSMITQ;
	ATF_CHECK_EQ(pci_vtvsock_qreset(sc,
	    &sc->vsc_queues[VIRTIO14_VSOCK_TRANSMITQ], 8), 0);
	ATF_CHECK(sc->vsc_pend_count == 1);
	ATF_CHECK(sc->vsc_kernel_tx == NULL);
	ATF_CHECK_EQ(sc->vsc_kernel_tx_len, 0);
	ATF_CHECK_EQ(g_mevent_disable_calls, 1);

	sc->vsc_queues[VIRTIO14_VSOCK_EVENTQ].vq_num =
	    VIRTIO14_VSOCK_EVENTQ;
	ATF_CHECK_EQ(pci_vtvsock_qreset(sc,
	    &sc->vsc_queues[VIRTIO14_VSOCK_EVENTQ], 9), 0);
	ATF_CHECK(sc->vsc_pend_count == 1);
	ATF_CHECK((vtvsock_vi_consts.vc_hv_caps &
	    VIRTIO14_F_RING_RESET) != 0);

	sc->vsc_queues[0].vq_num = VIRTIO14_VSOCK_EVENTQ + 1;
	ATF_CHECK_EQ(pci_vtvsock_qreset(sc, &sc->vsc_queues[0], 10), EINVAL);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{
	struct pci_vtvsock_softc sc;
	struct vtvsock_conn conn;
	struct virtio_vsock_hdr hdr;
	const uint8_t expected[] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
		0x24, 0x23, 0x22, 0x21,
		0x34, 0x33, 0x32, 0x31,
		0x44, 0x43, 0x42, 0x41,
		0x02, 0x00,
		0x05, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x54, 0x53, 0x52, 0x51,
		0x64, 0x63, 0x62, 0x61,
	};
	uint32_t value;

	/* VirtIO 1.4 section 5.10.6. */
	ATF_CHECK_EQ(sizeof(struct virtio_vsock_config),
	    VIRTIO14_VSOCK_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_config, guest_cid),
	    VIRTIO14_VSOCK_CONFIG_GUEST_CID_OFF);
	ATF_CHECK_EQ(sizeof(struct virtio_vsock_hdr),
	    VIRTIO14_VSOCK_HEADER_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, src_cid),
	    VIRTIO14_VSOCK_HDR_SRC_CID_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, dst_cid),
	    VIRTIO14_VSOCK_HDR_DST_CID_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, src_port),
	    VIRTIO14_VSOCK_HDR_SRC_PORT_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, dst_port),
	    VIRTIO14_VSOCK_HDR_DST_PORT_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, len),
	    VIRTIO14_VSOCK_HDR_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, type),
	    VIRTIO14_VSOCK_HDR_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, op),
	    VIRTIO14_VSOCK_HDR_OP_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, flags),
	    VIRTIO14_VSOCK_HDR_FLAGS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, buf_alloc),
	    VIRTIO14_VSOCK_HDR_BUF_ALLOC_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_vsock_hdr, fwd_cnt),
	    VIRTIO14_VSOCK_HDR_FWD_CNT_OFF);

	memset(&sc, 0, sizeof(sc));
	memset(&conn, 0, sizeof(conn));
	sc.vsc_guest_cid = UINT64_C(0x1112131415161718);
	conn.local_port = UINT32_C(0x21222324);
	conn.guest_port = UINT32_C(0x31323334);
	conn.type = VIRTIO14_VSOCK_TYPE_SEQPACKET;
	conn.buf_alloc = UINT32_C(0x51525354);
	conn.fwd_cnt = UINT32_C(0x61626364);
	vtvsock_build_hdr(&sc, &conn, VIRTIO14_VSOCK_OP_RW,
	    VIRTIO14_VSOCK_SEQ_EOM, UINT32_C(0x41424344), &hdr);
	ATF_CHECK(memcmp(&hdr, expected, sizeof(expected)) == 0);

	sc.vsc_config.guest_cid = htole64(4);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtvsock_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 4);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtvsock_cfgread(&sc, -1, 1, &value), -1);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtvsock_cfgread(&sc, 0, 3, &value), -1);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtvsock_cfgread(&sc,
	    VIRTIO14_VSOCK_CONFIG_SIZE - 1, 4, &value), -1);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_vtvsock_cfgread(&sc, 0, 1, NULL), -1);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtvsock_softc *sc;
	uint64_t aligned[(VIRTIO14_VSOCK_HEADER_SIZE +
	    sizeof(uint64_t) - 1) / sizeof(uint64_t)];
	uint8_t *wire;

	/*
	 * Feed the TX state machine a header assembled solely from the wire
	 * offsets in section 5.10.6.  The aligned integer storage avoids
	 * imposing the production structure's layout or alignment on the
	 * vector itself.
	 */
	wire = (uint8_t *)(void *)aligned;
	memset(wire, 0, VIRTIO14_VSOCK_HEADER_SIZE);
	virtio14_store_le64(wire + VIRTIO14_VSOCK_HDR_SRC_CID_OFF, 3);
	virtio14_store_le64(wire + VIRTIO14_VSOCK_HDR_DST_CID_OFF,
	    VIRTIO14_VSOCK_CID_HOST);
	virtio14_store_le32(wire + VIRTIO14_VSOCK_HDR_SRC_PORT_OFF, 1234);
	virtio14_store_le32(wire + VIRTIO14_VSOCK_HDR_DST_PORT_OFF, 80);
	virtio14_store_le32(wire + VIRTIO14_VSOCK_HDR_LEN_OFF, 0);
	virtio14_store_le16(wire + VIRTIO14_VSOCK_HDR_TYPE_OFF,
	    VIRTIO14_VSOCK_TYPE_STREAM);
	virtio14_store_le16(wire + VIRTIO14_VSOCK_HDR_OP_OFF,
	    VIRTIO14_VSOCK_OP_RW);
	virtio14_store_le32(wire + VIRTIO14_VSOCK_HDR_BUF_ALLOC_OFF,
	    256 * 1024);

	sc = mk_sc();
	reset_caps();
	process_tx_wire(sc, wire, NULL, 0);
	ATF_CHECK_EQ(nconns(sc), 0);
	ATF_REQUIRE_EQ(g_ninject, 1);
	ATF_CHECK_EQ(g_inject[0].op, VIRTIO14_VSOCK_OP_RST);
	ATF_CHECK_EQ(g_inject[0].src_port, 80);
	ATF_CHECK_EQ(g_inject[0].dst_port, 1234);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(suspend_fences_and_rearms_host_sources);
ATF_TC_BODY(suspend_fences_and_rearms_host_sources, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_conn *conn, *stale;
	struct vtvsock_ctl_conn *cc;

	sc = mk_sc();
	reset_caps();
	sc->vsc_ctl_evp = mevent_add(40, EVF_READ,
	    pci_vtvsock_ctl_accept, sc);
	sc->vsc_reap_evp = mevent_add(1000, EVF_TIMER,
	    pci_vtvsock_reap_timer, sc);
	stale = vtvsock_conn_alloc(sc, -1, 7000);
	ATF_REQUIRE(stale != NULL);
	stale->state = CONN_CONNECTING;
	stale->close_time = monotonic_seconds() - 100;
	conn = vtvsock_conn_alloc(sc, 41, 7001);
	ATF_REQUIRE(conn != NULL);
	conn->state = CONN_ESTABLISHED;
	conn->peer_buf_alloc = 1;
	conn->evp = mevent_add(conn->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	conn->tx_evp = mevent_add(conn->fd, EVF_WRITE,
	    vtvsock_conn_write_cb, sc);
	conn->tx_buf = malloc(1);
	ATF_REQUIRE(conn->tx_buf != NULL);
	conn->tx_buf[0] = 0x5a;
	conn->tx_buf_len = 1;
	conn->tx_buf_cap = 1;
	sc->vsc_txbuf_total = 1;
	cc = calloc(1, sizeof(*cc));
	ATF_REQUIRE(cc != NULL);
	cc->fd = 42;
	cc->created = monotonic_seconds();
	cc->evp = mevent_add(cc->fd, EVF_READ, pci_vtvsock_ctl_conn_cb, sc);
	TAILQ_INSERT_TAIL(&sc->vsc_ctl_conns, cc, link);
	sc->vsc_ctl_conn_count++;

	ATF_CHECK((vtvsock_vi_consts.vc_hv_caps & VIRTIO14_F_SUSPEND) != 0);
	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_suspend_device(sc), 0);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(sc->vsc_lifecycle_paused);
	ATF_CHECK(!sc->vsc_ctl_evp->enabled);
	ATF_CHECK(!sc->vsc_reap_evp->enabled);
	ATF_CHECK(!conn->evp->enabled);
	ATF_CHECK(!conn->tx_evp->enabled);
	ATF_CHECK(!cc->evp->enabled);

	/* Callbacks selected immediately before disable must observe the fence. */
	pci_vtvsock_reap_timer(-1, EVF_TIMER, sc);
	vtvsock_conn_write_cb(conn->fd, EVF_WRITE, sc);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK_EQ(nconns(sc), 2);
	ATF_CHECK_EQ(conn->tx_buf_len, 1);
	ATF_CHECK_EQ(sc->vsc_ctl_conn_count, 1);

	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_resume_device(sc), 0);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	/* Sources remain stopped until the common queue fence has opened. */
	ATF_CHECK(!sc->vsc_ctl_evp->enabled);
	ATF_CHECK(!sc->vsc_reap_evp->enabled);
	pci_vtvsock_resume_complete(sc);
	ATF_CHECK(sc->vsc_ctl_evp->enabled);
	ATF_CHECK(sc->vsc_reap_evp->enabled);
	ATF_CHECK(conn->evp->enabled);
	ATF_CHECK(conn->tx_evp->enabled);
	ATF_CHECK(cc->evp->enabled);

	/* Once resumed, the same timer is allowed to mutate connection state. */
	pci_vtvsock_reap_timer(-1, EVF_TIMER, sc);
	ATF_CHECK_EQ(nconns(sc), 1);
	pthread_mutex_lock(&sc->vsc_mtx);
	TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
	sc->vsc_ctl_conn_count--;
	vtvsock_conn_close(sc, conn);
	pthread_mutex_unlock(&sc->vsc_mtx);
	free(cc);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_suspend_fences_and_rearms_provider_sources);
ATF_TC_BODY(kernel_suspend_fences_and_rearms_provider_sources, tc)
{
	struct pci_vtvsock_softc *sc;

	sc = mk_sc();
	reset_caps();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 700;
	sc->vsc_kernel_evp = mevent_add(sc->vsc_kernel_fd, EVF_READ,
	    vtvsock_kernel_read_cb, sc);
	sc->vsc_kernel_write_evp = mevent_add_disabled(sc->vsc_kernel_fd,
	    EVF_WRITE, vtvsock_kernel_write_cb, sc);
	sc->vsc_kernel_tx = malloc(1);
	ATF_REQUIRE(sc->vsc_kernel_tx != NULL);
	sc->vsc_kernel_tx[0] = 0xa5;
	sc->vsc_kernel_tx_len = 1;

	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_suspend_device(sc), 0);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(!sc->vsc_kernel_evp->enabled);
	ATF_CHECK(!sc->vsc_kernel_write_evp->enabled);

	/* A preselected writable callback cannot consume the parked packet. */
	vtvsock_kernel_write_cb(sc->vsc_kernel_fd, EVF_WRITE, sc);
	ATF_CHECK_EQ(sc->vsc_kernel_tx_len, 1);
	ATF_CHECK(!sc->vsc_kernel_failed);

	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_resume_device(sc), 0);
	ATF_CHECK(!sc->vsc_kernel_evp->enabled);
	ATF_CHECK(!sc->vsc_kernel_write_evp->enabled);
	/* Guest resume completes while the common status path owns vsc_mtx. */
	pci_vtvsock_resume_complete(sc);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(sc->vsc_kernel_evp->enabled);
	ATF_CHECK(sc->vsc_kernel_write_evp->enabled);

	free(sc->vsc_kernel_tx);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(resume_preserves_checkpoint_owner);
ATF_TC_BODY(resume_preserves_checkpoint_owner, tc)
{
	struct pci_vtvsock_softc *sc;

	sc = mk_sc();
	reset_caps();
	sc->vsc_ctl_evp = mevent_add(40, EVF_READ,
	    pci_vtvsock_ctl_accept, sc);
	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_suspend_device(sc), 0);
	sc->vsc_vs.vs_checkpoint_paused = true;
	ATF_REQUIRE_EQ(pci_vtvsock_resume_device(sc), 0);
	pthread_mutex_unlock(&sc->vsc_mtx);
	pci_vtvsock_resume_complete(sc);
	ATF_CHECK(sc->vsc_lifecycle_paused);
	ATF_CHECK(!sc->vsc_ctl_evp->enabled);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(reset_cancels_suspend_and_reopens_admission);
ATF_TC_BODY(reset_cancels_suspend_and_reopens_admission, tc)
{
	struct pci_vtvsock_softc *sc;

	sc = mk_sc();
	reset_caps();
	sc->vsc_ctl_evp = mevent_add(40, EVF_READ,
	    pci_vtvsock_ctl_accept, sc);
	pthread_mutex_lock(&sc->vsc_mtx);
	ATF_REQUIRE_EQ(pci_vtvsock_suspend_device(sc), 0);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK(sc->vsc_lifecycle_paused);
	ATF_CHECK(!sc->vsc_ctl_evp->enabled);

	pci_vtvsock_reset(sc);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK(sc->vsc_ctl_evp->enabled);
	ATF_CHECK_EQ(sc->vsc_features, 0);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(reset_preserves_transport_mutex_ownership);
ATF_TC_BODY(reset_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtvsock_softc *sc;

	/* Modern status reset calls vc_reset while the aliased vsc_mtx is held. */
	sc = mk_sc();
	reset_caps();
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc->vsc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc->vsc_mtx));
	pci_vtvsock_reset(sc);
	ATF_CHECK(pthread_mutex_isowned_np(&sc->vsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc->vsc_mtx), 0);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_unreconstructible_backend_state);
ATF_TC_BODY(snapshot_rejects_unreconstructible_backend_state, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_conn *conn;

	sc = mk_sc();
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), 0);

	/*
	 * Every userspace-host object excluded from the portable record must
	 * independently close checkpoint admission.  Do not rely on an active
	 * connection incidentally carrying each kind of buffered state: a future
	 * teardown or accounting change could otherwise leave a non-portable
	 * object behind while this test still passes.
	 */
	sc->vsc_ctl_conn_count = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_ctl_conn_count = 0;
	sc->vsc_pend_count = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_pend_count = 0;
	sc->vsc_reasm_total = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_reasm_total = 0;
	sc->vsc_txbuf_total = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_txbuf_total = 0;

	conn = vtvsock_conn_alloc(sc, -1, 7000);
	ATF_REQUIRE(conn != NULL);
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	pthread_mutex_lock(&sc->vsc_mtx);
	vtvsock_conn_close(sc, conn);
	pthread_mutex_unlock(&sc->vsc_mtx);
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), 0);

	sc->vsc_kernel = true;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, false), 0);
	sc->vsc_kernel_frozen = true;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), 0);
	sc->vsc_kernel_failed = true;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_kernel_failed = false;
	sc->vsc_kernel_rx = (uint8_t *)(uintptr_t)1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, false), EBUSY);
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_kernel_rx = NULL;
	sc->vsc_kernel_rx_off = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_kernel_rx_off = 0;
	sc->vsc_kernel_tx = (uint8_t *)(uintptr_t)1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_kernel_tx = NULL;
	sc->vsc_kernel_tx_len = 1;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), EBUSY);
	sc->vsc_kernel_tx_len = 0;
	ATF_CHECK_EQ(vtvsock_snapshot_state_error(sc, true), 0);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.buffer = {
			.buf_start = NULL,
			.buf_size = 0,
			.buf = NULL,
			.buf_rem = 0,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};
	struct pci_vtvsock_softc *sc;

	sc = mk_sc();
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = sc;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = E2BIG;
	g_snapshot_validate_saw_lock = false;
	g_snapshot_validate_saw_owner = false;

	ATF_CHECK_EQ(pci_vtvsock_snapshot_validate(&meta), E2BIG);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK(g_snapshot_validate_saw_owner);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc->vsc_mtx));
	ATF_CHECK_EQ(g_ioctl_freeze_calls, 0);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 0);

	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_CHECK_EQ(pci_vtvsock_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_checkpoint_freezes_and_thaws_provider);
ATF_TC_BODY(kernel_checkpoint_freezes_and_thaws_provider, tc)
{
	struct pci_vtvsock_softc *sc;

	reset_caps();
	sc = mk_sc();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 41;

	/* A failed FREEZE must reopen the source checkpoint fence. */
	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_FREEZE;
	g_ioctl_fail_errno = EIO;
	ATF_CHECK_EQ(pci_vtvsock_pause(sc), EIO);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	/* An abnormal provider failure with no errno must still fail closed. */
	g_ioctl_fail_errno = 0;
	ATF_CHECK_EQ(pci_vtvsock_pause(sc), EIO);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	g_ioctl_fail_request = 0;

	/* Future or malformed kernel checkpoint replies fail closed and thaw. */
	g_ioctl_freeze_bad_version = true;
	ATF_CHECK_EQ(pci_vtvsock_pause(sc), EPROTO);
	ATF_CHECK(!sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 1);
	g_ioctl_freeze_bad_version = false;
	g_ioctl_freeze_bad_reserved = true;
	ATF_CHECK_EQ(pci_vtvsock_pause(sc), EPROTO);
	ATF_CHECK(!sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 2);
	g_ioctl_freeze_bad_reserved = false;

	ATF_REQUIRE_EQ(pci_vtvsock_pause(sc), 0);
	ATF_CHECK(sc->vsc_kernel_frozen);
	ATF_CHECK(sc->vsc_checkpoint_lock_held);
	ATF_CHECK_EQ(g_ioctl_freeze_calls, 3);
	ATF_REQUIRE_EQ(pci_vtvsock_resume(sc), 0);
	ATF_CHECK(!sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK_EQ(g_ioctl_feature_calls, 1);
	ATF_CHECK_EQ(g_ioctl_features, sc->vsc_features &
	    VTVSOCK_DEVICE_FEATURES);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 3);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_checkpoint_malformed_reply_thaw_failure);
ATF_TC_BODY(kernel_checkpoint_malformed_reply_thaw_failure, tc)
{
	struct pci_vtvsock_softc *sc;

	reset_caps();
	sc = mk_sc();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 41;
	g_ioctl_freeze_bad_version = true;
	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_THAW;
	g_ioctl_fail_errno = EIO;

	ATF_CHECK_EQ(pci_vtvsock_pause(sc), EIO);
	ATF_CHECK(sc->vsc_kernel_frozen);
	ATF_CHECK(sc->vsc_kernel_failed);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK_EQ(g_ioctl_freeze_calls, 1);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 0);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(kernel_checkpoint_thaw_failure_is_retryable);
ATF_TC_BODY(kernel_checkpoint_thaw_failure_is_retryable, tc)
{
	struct pci_vtvsock_softc *sc;

	reset_caps();
	sc = mk_sc();
	sc->vsc_kernel = true;
	sc->vsc_kernel_fd = 41;
	ATF_REQUIRE_EQ(pci_vtvsock_pause(sc), 0);

	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_SET_FEATURES;
	g_ioctl_fail_errno = EIO;
	ATF_CHECK_EQ(pci_vtvsock_resume(sc), EIO);
	ATF_CHECK(sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(sc->vsc_lifecycle_paused);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 0);

	g_ioctl_fail_request = 0;
	ATF_REQUIRE_EQ(pci_vtvsock_resume(sc), 0);
	ATF_CHECK(!sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK_EQ(g_ioctl_feature_calls, 1);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 1);

	/* Exercise the independently retryable THAW failure on a new fence. */
	ATF_REQUIRE_EQ(pci_vtvsock_pause(sc), 0);

	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_THAW;
	g_ioctl_fail_errno = EIO;
	ATF_CHECK_EQ(pci_vtvsock_resume(sc), EIO);
	ATF_CHECK(sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(sc->vsc_lifecycle_paused);

	g_ioctl_fail_request = 0;
	ATF_REQUIRE_EQ(pci_vtvsock_resume(sc), 0);
	ATF_CHECK(!sc->vsc_kernel_frozen);
	ATF_CHECK(!sc->vsc_checkpoint_lock_held);
	ATF_CHECK(!sc->vsc_lifecycle_paused);
	ATF_CHECK_EQ(g_ioctl_feature_calls, 3);
	ATF_CHECK_EQ(g_ioctl_thaw_calls, 2);

	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

static int
run_vsock_snapshot(struct pci_vtvsock_softc *sc, uint8_t *image, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf = image,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtvsock_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

ATF_TC_WITHOUT_HEAD(snapshot_portable_identity_and_atomicity);
ATF_TC_BODY(snapshot_portable_identity_and_atomicity, tc)
{
	struct pci_vtvsock_softc *destination, *source;
	uint8_t image[MAXPATHLEN + 128];
	uint8_t *saved_path;
	uint64_t original_features;
	uint32_t original_port, path_len;
	size_t used;

	source = mk_sc();
	source->vsc_path = strdup("/tmp/vsock-snapshot-source");
	ATF_REQUIRE(source->vsc_path != NULL);
	source->vsc_vs.vs_negotiated_caps = source->vsc_features;
	source->vsc_next_port = 43210;
	ATF_REQUIRE_EQ(pci_vtvsock_pause(source), 0);
	source->vsc_features ^= UINT64_C(1);
	ATF_CHECK_EQ(run_vsock_snapshot(source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EINVAL);
	source->vsc_features ^= UINT64_C(1);
	ATF_REQUIRE_EQ(run_vsock_snapshot(source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(pci_vtvsock_resume(source), 0);
	ATF_REQUIRE(used > MAXPATHLEN);
	ATF_CHECK_EQ(image[0], (uint8_t)'V');
	ATF_CHECK_EQ(image[1], (uint8_t)'S');
	ATF_CHECK_EQ(image[2], (uint8_t)'O');
	ATF_CHECK_EQ(image[3], (uint8_t)'1');
	ATF_CHECK_EQ(image[4], 2);
	ATF_CHECK_EQ(image[5], 0);
	ATF_CHECK_EQ(image[6], 0);
	ATF_CHECK_EQ(image[7], 0);

	destination = mk_sc();
	destination->vsc_path = strdup(source->vsc_path);
	ATF_REQUIRE(destination->vsc_path != NULL);
	destination->vsc_vs.vs_negotiated_caps = source->vsc_features;
	destination->vsc_features = 0x55;
	destination->vsc_next_port = 45678;
	original_features = destination->vsc_features;
	original_port = destination->vsc_next_port;

	ATF_REQUIRE_EQ(pci_vtvsock_pause(destination), 0);
	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	free(destination->vsc_path);
	destination->vsc_path = strdup("/tmp/different-vsock-backend");
	ATF_REQUIRE(destination->vsc_path != NULL);
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	free(destination->vsc_path);
	destination->vsc_path = strdup(source->vsc_path);
	ATF_REQUIRE(destination->vsc_path != NULL);
	path_len = (uint32_t)strlen(source->vsc_path);
	saved_path = memmem(image, used, source->vsc_path, path_len);
	ATF_REQUIRE(saved_path != NULL);
	ATF_REQUIRE((size_t)(saved_path - image) + path_len + 1 < used);
	saved_path[path_len + 1] = 0xa5;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);
	saved_path[path_len + 1] = 0;

	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, source->vsc_features);
	ATF_CHECK_EQ(destination->vsc_next_port, source->vsc_next_port);
	/*
	 * Restore may be retried after the common checkpoint layer has decoded
	 * the same image more than once.  The userspace backend identity is
	 * configuration-only, so a second decode while its admission fence is
	 * still held must be an idempotent transaction rather than consuming a
	 * host socket or perturbing the portable allocator cursor.
	 */
	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, source->vsc_features);
	ATF_CHECK_EQ(destination->vsc_next_port, source->vsc_next_port);
	ATF_REQUIRE_EQ(pci_vtvsock_resume(destination), 0);

	free(destination->vsc_path);
	free(source->vsc_path);
	pthread_mutex_destroy(&destination->vsc_mtx);
	pthread_mutex_destroy(&source->vsc_mtx);
	free(destination);
	free(source);
}

ATF_TC_WITHOUT_HEAD(init_failure_detaches_and_retires_child_events);
ATF_TC_BODY(init_failure_detaches_and_retires_child_events, tc)
{
	struct pci_vtvsock_softc *sc;
	struct vtvsock_conn *conn;
	struct vtvsock_ctl_conn *ctl;
	struct vtvsock_conn_list conns;
	struct vtvsock_ctl_conn_list ctls;

	reset_caps();
	sc = mk_sc();
	conn = calloc(1, sizeof(*conn));
	ctl = calloc(1, sizeof(*ctl));
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE(ctl != NULL);
	conn->fd = -1;
	conn->reply_fd = -1;
	conn->ctl_fd = -1;
	conn->evp = mevent_add(41, EVF_READ, vtvsock_conn_data_cb, NULL);
	conn->tx_evp = mevent_add(42, EVF_WRITE, vtvsock_conn_write_cb, NULL);
	conn->rx_reasm = malloc(9);
	conn->rx_reasm_len = 9;
	conn->tx_buf = malloc(11);
	conn->tx_buf_len = 11;
	ctl->fd = -1;
	ctl->evp = mevent_add(43, EVF_READ, pci_vtvsock_ctl_conn_cb, NULL);
	ATF_REQUIRE(conn->evp != NULL);
	ATF_REQUIRE(conn->tx_evp != NULL);
	ATF_REQUIRE(ctl->evp != NULL);
	TAILQ_INSERT_TAIL(&sc->vsc_conns, conn, link);
	TAILQ_INSERT_TAIL(&sc->vsc_ctl_conns, ctl, link);
	sc->vsc_conn_count = 1;
	sc->vsc_ctl_conn_count = 1;
	sc->vsc_reasm_total = conn->rx_reasm_len;
	sc->vsc_txbuf_total = conn->tx_buf_len;
	TAILQ_INIT(&conns);
	TAILQ_INIT(&ctls);

	vtvsock_init_failure_detach(sc, &conns, &ctls);
	ATF_CHECK(sc->vsc_lifecycle_paused);
	ATF_CHECK(TAILQ_EMPTY(&sc->vsc_conns));
	ATF_CHECK(TAILQ_EMPTY(&sc->vsc_ctl_conns));
	ATF_CHECK_EQ(sc->vsc_conn_count, 0);
	ATF_CHECK_EQ(sc->vsc_ctl_conn_count, 0);
	ATF_CHECK_EQ(sc->vsc_reasm_total, 0);
	ATF_CHECK_EQ(sc->vsc_txbuf_total, 0);
	ATF_REQUIRE(!TAILQ_EMPTY(&conns));
	ATF_REQUIRE(!TAILQ_EMPTY(&ctls));

	conn = TAILQ_FIRST(&conns);
	TAILQ_REMOVE(&conns, conn, link);
	vtvsock_conn_destroy_detached(sc, conn);
	ctl = TAILQ_FIRST(&ctls);
	TAILQ_REMOVE(&ctls, ctl, link);
	vtvsock_ctl_conn_destroy_detached(ctl);
	ATF_CHECK_EQ(g_mevent_delete_sync_calls, 1);
	ATF_CHECK_EQ(g_mevent_delete_close_sync_calls, 2);
	ATF_CHECK(g_mevent_disable_calls >= 3);
	ATF_CHECK(TAILQ_EMPTY(&conns));
	ATF_CHECK(TAILQ_EMPTY(&ctls));
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_kernel_backend_validation);
ATF_TC_BODY(snapshot_kernel_backend_validation, tc)
{
	enum {
		VSOCK_STATE_BACKEND_OFF = 8,
		VSOCK_STATE_GUEST_CID_OFF = 9,
		VSOCK_STATE_FEATURES_OFF = 17,
		VSOCK_STATE_NEXT_PORT_OFF = 25,
		VSOCK_STATE_PATH_LEN_OFF = 29,
		VSOCK_STATE_RESERVED_OFF = 33,
		VSOCK_STATE_PATH_OFF = 37,
	};
	struct pci_vtvsock_softc *destination, *source;
	uint8_t image[MAXPATHLEN + 128];
	uint64_t original_features;
	uint32_t original_port;
	size_t used;

	reset_caps();
	source = mk_sc();
	source->vsc_kernel = true;
	source->vsc_vs.vs_negotiated_caps = source->vsc_features;
	source->vsc_next_port = 54321;
	ATF_REQUIRE_EQ(pci_vtvsock_pause(source), 0);
	ATF_REQUIRE_EQ(run_vsock_snapshot(source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(pci_vtvsock_resume(source), 0);

	destination = mk_sc();
	destination->vsc_kernel = true;
	destination->vsc_vs.vs_negotiated_caps = source->vsc_features;
	destination->vsc_features = 0x55;
	destination->vsc_next_port = 45678;
	original_features = destination->vsc_features;
	original_port = destination->vsc_next_port;

	ATF_REQUIRE_EQ(pci_vtvsock_pause(destination), 0);
	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	/*
	 * The kernel provider is reconstructed by its exclusive guest CID.  Check
	 * each private identity/format field independently and require rejected
	 * images to leave the already-attached destination provider untouched.
	 * These are snapshot-format offsets, deliberately not bhyve C structure
	 * offsets, so padding and host byte order cannot make this test agree with
	 * an incorrect native-structure codec.
	 */
	image[VSOCK_STATE_BACKEND_OFF] = 0;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_BACKEND_OFF] = 1;
	ATF_CHECK_EQ(destination->vsc_features, original_features);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	image[VSOCK_STATE_GUEST_CID_OFF] ^= 1;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_GUEST_CID_OFF] ^= 1;
	ATF_CHECK_EQ(destination->vsc_features, original_features);

	image[VSOCK_STATE_FEATURES_OFF] ^= 1;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_FEATURES_OFF] ^= 1;
	ATF_CHECK_EQ(destination->vsc_features, original_features);

	memset(image + VSOCK_STATE_NEXT_PORT_OFF, 0, sizeof(uint32_t));
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	virtio14_store_le32(image + VSOCK_STATE_NEXT_PORT_OFF,
	    source->vsc_next_port);
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	image[VSOCK_STATE_PATH_LEN_OFF] = 1;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_PATH_LEN_OFF] = 0;
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	image[VSOCK_STATE_RESERVED_OFF] = 1;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_RESERVED_OFF] = 0;
	ATF_CHECK_EQ(destination->vsc_features, original_features);

	image[VSOCK_STATE_PATH_OFF] = 1;
	ATF_CHECK_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	image[VSOCK_STATE_PATH_OFF] = 0;
	ATF_CHECK_EQ(destination->vsc_next_port, original_port);

	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, source->vsc_features);
	ATF_CHECK_EQ(destination->vsc_next_port, source->vsc_next_port);
	/* A frozen empty provider has the same repeat-restore contract. */
	ATF_REQUIRE_EQ(run_vsock_snapshot(destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination->vsc_features, source->vsc_features);
	ATF_CHECK_EQ(destination->vsc_next_port, source->vsc_next_port);
	ATF_REQUIRE_EQ(pci_vtvsock_resume(destination), 0);
	ATF_CHECK_EQ(g_ioctl_feature_calls, 2);
	ATF_CHECK_EQ(g_ioctl_features, source->vsc_features &
	    VTVSOCK_DEVICE_FEATURES);

	pthread_mutex_destroy(&destination->vsc_mtx);
	pthread_mutex_destroy(&source->vsc_mtx);
	free(destination);
	free(source);
}

/* =====================================================================
 * pci_vtvsock_ctl_accept(): host control-socket listener error paths.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(ctl_accept_transient_failure_ignored);
ATF_TC_BODY(ctl_accept_transient_failure_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_accept_fail = 1;
	g_accept_errno = EAGAIN;		/* spurious wakeup, nothing to accept */
	pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	/* A hard accept() error is likewise non-fatal to the listener. */
	g_accept_fail = 1;
	g_accept_errno = ECONNABORTED;
	pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(ctl_accept_fcntl_failure_drops);
ATF_TC_BODY(ctl_accept_fcntl_failure_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_fcntl_fail = 1;		/* O_NONBLOCK on the accepted fd fails */
	pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(ctl_accept_mevent_failure_drops);
ATF_TC_BODY(ctl_accept_mevent_failure_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_mevent_fail = 1;		/* arming the ctl-conn read event fails */
	pci_vtvsock_ctl_accept(0, EVF_READ, sc);
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	free(sc);
}

/* =====================================================================
 * pci_vtvsock_ctl_conn_cb(): control-request read/dispatch error paths.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(ctl_conn_eof_removes_conn);
ATF_TC_BODY(ctl_conn_eof_removes_conn, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;

	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	g_recv_len = g_recv_off = 0;
	g_recv_eof = 1;			/* peer closed the control socket */
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK(nctlconns(sc) == 0);		/* torn down on EOF */
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(ctl_conn_wouldblock_keeps_conn);
ATF_TC_BODY(ctl_conn_wouldblock_keeps_conn, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;

	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	g_recv_len = g_recv_off = 0;		/* recv() -> EAGAIN */
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK(nctlconns(sc) == 1);		/* partial frame retained */
	free(sc);
}

/* A negotiated-but-valid socket type the device does not offer is refused. */
ATF_TC_WITHOUT_HEAD(ctl_connect_unnegotiated_type_refused);
ATF_TC_BODY(ctl_connect_unnegotiated_type_refused, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vsock_ctl_msg reply;

	reset_caps();
	sc->vsc_features = VIRTIO_VSOCK_F_STREAM;	/* SEQPACKET not offered */
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_SEQPACKET);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK(nconns(sc) == 0);
	ATF_REQUIRE(g_send_len == sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK(reply.status == -ESOCKTNOSUPPORT);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(ctl_connect_fcntl_failure_replies_error);
ATF_TC_BODY(ctl_connect_fcntl_failure_replies_error, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vsock_ctl_msg reply;

	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	g_fcntl_fail = 1;		/* fcntl(pair[0], O_NONBLOCK) fails */
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_CHECK(nconns(sc) == 0);
	ATF_REQUIRE(g_send_len == sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK(reply.status == -ENOMEM);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(ctl_connect_conn_alloc_failure_replies_error);
ATF_TC_BODY(ctl_connect_conn_alloc_failure_replies_error, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_ctl_conn *cc;
	struct vsock_ctl_msg reply;

	reset_caps();
	cc = mk_ctl_conn(sc, g_next_fd++, 100);
	sc->vsc_conn_count = VTVSOCK_MAX_CONNS;	/* conn_alloc() -> NULL */
	stage_ctl_msg(VSOCK_CTL_CONNECT, 1234, SOCK_STREAM);
	pci_vtvsock_ctl_conn_cb(cc->fd, EVF_READ, sc);
	ATF_REQUIRE(g_send_len == sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK(reply.status == -ENOMEM);
	sc->vsc_conn_count = 0;
	free(sc);
}

/* =====================================================================
 * vtvsock_conn_write_cb(): async guest->host TX backlog drainer.
 * ===================================================================== */
static struct vtvsock_conn *
mk_txbuf_conn(struct pci_vtvsock_softc *sc, uint16_t type,
    const void *data, uint32_t len, bool eor)
{
	struct vtvsock_conn *c = mk_established(sc, 1234, 80, type);

	c->tx_buf = malloc(len);
	assert(c->tx_buf != NULL);
	memcpy(c->tx_buf, data, len);
	c->tx_buf_len = len;
	c->tx_buf_cap = len;
	c->tx_buf_eor = eor;
	sc->vsc_txbuf_total += len;
	c->tx_evp = mevent_add(c->fd, EVF_WRITE, vtvsock_conn_write_cb, sc);
	return (c);
}

ATF_TC_WITHOUT_HEAD(write_cb_no_backlog_disables_drainer);
ATF_TC_BODY(write_cb_no_backlog_disables_drainer, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int disables;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->tx_evp = mevent_add(c->fd, EVF_WRITE, vtvsock_conn_write_cb, sc);
	disables = g_mevent_disable_calls;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);	/* tx_buf_len == 0 */
	ATF_CHECK(g_mevent_disable_calls == disables + 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_stream_drains_backlog);
ATF_TC_BODY(write_cb_stream_drains_backlog, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[32];

	reset_caps();
	memset(d, 'D', sizeof(d));
	c = mk_txbuf_conn(sc, STREAM, d, sizeof(d), false);
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);	/* default send: full */
	ATF_CHECK(c->tx_buf_len == 0);			/* fully drained */
	ATF_CHECK(c->fwd_cnt == sizeof(d));		/* credit returned */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_stream_wouldblock_stays_armed);
ATF_TC_BODY(write_cb_stream_wouldblock_stays_armed, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[32];

	reset_caps();
	memset(d, 'D', sizeof(d));
	c = mk_txbuf_conn(sc, STREAM, d, sizeof(d), false);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK(c->tx_buf_len == sizeof(d));		/* nothing drained */
	ATF_CHECK(nconns(sc) == 1);			/* stays armed, not reset */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_stream_zero_progress_stays_armed);
ATF_TC_BODY(write_cb_stream_zero_progress_stays_armed, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[32];

	reset_caps();
	memset(d, 'D', sizeof(d));
	c = mk_txbuf_conn(sc, STREAM, d, sizeof(d), false);
	g_send_override = true;
	g_send_result = 0;			/* socket accepted nothing */
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK(c->tx_buf_len == sizeof(d));
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_stream_error_resets);
ATF_TC_BODY(write_cb_stream_error_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[32];

	reset_caps();
	memset(d, 'D', sizeof(d));
	c = mk_txbuf_conn(sc, STREAM, d, sizeof(d), false);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = ECONNRESET;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_seqpacket_drains_record);
ATF_TC_BODY(write_cb_seqpacket_drains_record, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[24];

	reset_caps();
	memset(d, 'S', sizeof(d));
	c = mk_txbuf_conn(sc, SEQPACKET, d, sizeof(d), true);
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);	/* default send: full */
	ATF_CHECK(c->tx_buf_len == 0);
	ATF_CHECK(c->fwd_cnt == sizeof(d));
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_seqpacket_wouldblock_stays_armed);
ATF_TC_BODY(write_cb_seqpacket_wouldblock_stays_armed, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[24];

	reset_caps();
	memset(d, 'S', sizeof(d));
	c = mk_txbuf_conn(sc, SEQPACKET, d, sizeof(d), false);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK(c->tx_buf_len == sizeof(d));
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(write_cb_seqpacket_short_send_resets);
ATF_TC_BODY(write_cb_seqpacket_short_send_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[24];

	reset_caps();
	memset(d, 'S', sizeof(d));
	c = mk_txbuf_conn(sc, SEQPACKET, d, sizeof(d), false);
	g_send_override = true;
	g_send_result = sizeof(d) - 1;		/* partial record delivery */
	vtvsock_conn_write_cb(c->fd, EVF_WRITE, sc);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* =====================================================================
 * RX inject_raw() descriptor-validation error paths, driven through
 * vtvsock_send_ctrl() (which injects a control packet via inject_raw).
 * §5.10.6.4: RX chains must be wholly device-writable and large enough
 * for the header; malformed guest descriptors are dropped, not trusted.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(inject_raw_getchain_failure_drops);
ATF_TC_BODY(inject_raw_getchain_failure_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_rx_descs = 1;			/* vq_has_descs() true ... */
	g_getchain_zero = 1;		/* ... but vq_getchain() yields nothing */
	/* Parked for retry (inject failed), nothing delivered. */
	ATF_CHECK(vtvsock_send_ctrl(sc, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(inject_raw_overlong_chain_drops);
ATF_TC_BODY(inject_raw_overlong_chain_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_rx_descs = 1;
	g_getchain_bign = 9999;		/* > VTVSOCK_MAX_IOV: OOB guard drops it */
	ATF_CHECK(vtvsock_send_ctrl(sc, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(inject_raw_bad_descriptor_addr_drops);
ATF_TC_BODY(inject_raw_bad_descriptor_addr_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_rx_descs = 1;
	g_iov_null_base = 1;		/* descriptor addr outside guest RAM */
	ATF_CHECK(vtvsock_send_ctrl(sc, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(inject_raw_undersized_chain_drops);
ATF_TC_BODY(inject_raw_undersized_chain_drops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	g_rx_descs = 1;
	g_rxbuf_len = 10;		/* shorter than the vsock header wire size */
	ATF_CHECK(vtvsock_send_ctrl(sc, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

/* =====================================================================
 * vtvsock_conn_data_cb(): host->guest readiness callback edge states.
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(conn_data_cb_ignored_while_paused);
ATF_TC_BODY(conn_data_cb_ignored_while_paused, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[8] = { 0 };

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	sc->vsc_lifecycle_paused = true;	/* snapshot/pause in progress */
	stage_recv(d, sizeof(d));
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 0);		/* no injection while paused */
	ATF_CHECK(g_recv_off == 0);		/* host socket left untouched */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(conn_data_cb_noop_while_connecting);
ATF_TC_BODY(conn_data_cb_noop_while_connecting, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;		/* still awaiting OP_RESPONSE */
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(conn_data_cb_rcv_shutdown_disables_read);
ATF_TC_BODY(conn_data_cb_rcv_shutdown_disables_read, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[8] = { 0 };
	int disables;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	c->peer_shutdown = VIRTIO_VSOCK_SHUTDOWN_RCV;	/* guest half-closed RX */
	stage_recv(d, sizeof(d));
	disables = g_mevent_disable_calls;
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_mevent_disable_calls == disables + 1);
	ATF_CHECK(g_ninject == 0);		/* no data injected after SHUT_RCV */
	free(sc);
}

/* SEQPACKET host EOF (no MSG_EOR, zero bytes queued) tears down cleanly. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_seqpacket_host_eof);
ATF_TC_BODY(conn_data_cb_seqpacket_host_eof, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	g_recv_len = g_recv_off = 0;		/* FIONREAD == 0 */
	g_recv_eof = 1;				/* recvmsg peek: 0, no MSG_EOR */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	/* host_eof half-closes: a SHUTDOWN is sent to the guest. */
	ATF_CHECK(g_ninject >= 1);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_SHUTDOWN);
	free(sc);
}

/* SEQPACKET empty record (MSG_EOR, 0 bytes) is delivered as an empty OP_RW. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_seqpacket_empty_record);
ATF_TC_BODY(conn_data_cb_seqpacket_empty_record, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	g_recv_len = g_recv_off = 0;		/* FIONREAD == 0 */
	g_recv_zero_dgram = 1;			/* recvmsg peek: 0 bytes, MSG_EOR */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 1);
	ATF_CHECK(g_inject[0].op == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(g_inject[0].len == 0);
	ATF_CHECK((g_inject[0].flags &
	    (VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR)) ==
	    (uint32_t)(VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR));
	free(sc);
}

/* SEQPACKET record larger than the guest's whole receive window resets. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_seqpacket_record_exceeds_window);
ATF_TC_BODY(conn_data_cb_seqpacket_record_exceeds_window, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[300];

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	c->peer_buf_alloc = 100;	/* window < record: unreassemblable */
	c->peer_fwd_cnt = 0;
	c->tx_cnt = 50;			/* leaves 50 credit (< avail) so we peek */
	memset(rec, 'Z', sizeof(rec));
	stage_recv(rec, sizeof(rec));	/* FIONREAD=300 > credit -> full peek */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);	/* connection reset */
	free(sc);
}

/* =====================================================================
 * TX state machine: guest control packets that hit error/edge branches.
 * ===================================================================== */

/* A duplicate OP_REQUEST for an already-ESTABLISHED conn -> RST + close. */
ATF_TC_WITHOUT_HEAD(tx_duplicate_request_resets);
ATF_TC_BODY(tx_duplicate_request_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	(void)c;
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* An OP_REQUEST colliding with a pending host-initiated connect (CONNECTING)
 * is ignored, not torn down. */
ATF_TC_WITHOUT_HEAD(tx_request_collision_ignored);
ATF_TC_BODY(tx_request_collision_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;		/* host connect awaiting RESPONSE */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 0);		/* ignored: no RST, no RESPONSE */
	ATF_CHECK(nconns(sc) == 1);		/* pending connect preserved */
	free(sc);
}

/* OP_REQUEST but the relay socket() fails -> RST so the guest doesn't hang. */
ATF_TC_WITHOUT_HEAD(tx_request_socket_failure_resets);
ATF_TC_BODY(tx_request_socket_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;

	reset_caps();
	g_socket_fail = 1;
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 1 && g_inject[0].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* OP_REQUEST succeeds but arming the read mevent fails -> RST + close. */
ATF_TC_WITHOUT_HEAD(tx_request_mevent_failure_resets);
ATF_TC_BODY(tx_request_mevent_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;

	reset_caps();
	g_connectat_result = 0;		/* host listener present */
	g_mevent_fail = 1;		/* vtvsock_event_add() -> NULL */
	mkhdr(&h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* Any packet's oversized advertised buf_alloc is clamped, not trusted. */
ATF_TC_WITHOUT_HEAD(tx_peer_buf_alloc_clamped);
ATF_TC_BODY(tx_peer_buf_alloc_clamped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	mkhdr(&h, VIRTIO_VSOCK_OP_CREDIT_UPDATE, STREAM, 3, VSOCK_CID_HOST,
	    1234, 80, 0, 0, 0xffffffffu /* absurd buf_alloc */, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(c->peer_buf_alloc == VTVSOCK_MAX_PEER_BUF_ALLOC);
	free(sc);
}

/* OP_RESPONSE for a conn not in CONNECTING state is ignored. */
ATF_TC_WITHOUT_HEAD(tx_response_wrong_state_ignored);
ATF_TC_BODY(tx_response_wrong_state_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);	/* already ESTABLISHED */
	(void)c;
	mkhdr(&h, VIRTIO_VSOCK_OP_RESPONSE, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_ninject == 0);
	free(sc);
}

/* OP_RESPONSE completing a host-initiated connect: reply fd sent to the host
 * control conn, ctl_conn cleaned up, read mevent armed. */
ATF_TC_WITHOUT_HEAD(tx_response_completes_host_connect);
ATF_TC_BODY(tx_response_completes_host_connect, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct vtvsock_ctl_conn *cc;
	struct virtio_vsock_hdr h;
	int ctlfd = g_next_fd++;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	c->ctl_fd = ctlfd;
	c->reply_fd = g_next_fd++;
	cc = mk_ctl_conn(sc, ctlfd, 100);
	(void)cc;
	mkhdr(&h, VIRTIO_VSOCK_OP_RESPONSE, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(c->state == CONN_ESTABLISHED);
	ATF_CHECK(c->ctl_fd == -1 && c->reply_fd == -1);
	ATF_CHECK(nctlconns(sc) == 0);		/* ctl_conn removed */
	free(sc);
}

/* OP_RESPONSE completes, but arming the post-connect read mevent fails. */
ATF_TC_WITHOUT_HEAD(tx_response_mevent_failure_resets);
ATF_TC_BODY(tx_response_mevent_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;		/* no ctl_fd/reply_fd */
	g_mevent_fail = 1;
	mkhdr(&h, VIRTIO_VSOCK_OP_RESPONSE, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* OP_RST on a host-initiated conn replies -ECONNREFUSED to the host app and
 * closes; exercises the conn_close ctl_conn + reply_fd cleanup. */
ATF_TC_WITHOUT_HEAD(tx_rst_host_connect_reports_refused);
ATF_TC_BODY(tx_rst_host_connect_reports_refused, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	int ctlfd = g_next_fd++;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	c->ctl_fd = ctlfd;
	c->reply_fd = g_next_fd++;
	(void)mk_ctl_conn(sc, ctlfd, 100);
	{
		struct virtio_vsock_hdr h;
		mkhdr(&h, VIRTIO_VSOCK_OP_RST, STREAM, 3, VSOCK_CID_HOST, 1234,
		    80, 0, 0, 0, 0);
		vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	}
	ATF_CHECK(g_send_calls >= 1);		/* refusal sent to host app */
	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(nctlconns(sc) == 0);		/* ctl_conn cleaned up */
	free(sc);
}

/* =====================================================================
 * STREAM guest->host forwarding backpressure/error paths.
 * ===================================================================== */

/* A hard send() error on the host fd resets the connection. */
ATF_TC_WITHOUT_HEAD(stream_tx_send_error_resets);
ATF_TC_BODY(stream_tx_send_error_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t data[16];

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	(void)c;
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = ECONNRESET;		/* not EAGAIN -> unrecoverable */
	memset(data, 'D', sizeof(data));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(data), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, data, sizeof(data));
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* When the host fd is not writable (EAGAIN) and the per-conn backlog cap is
 * exceeded, the connection is reset. */
ATF_TC_WITHOUT_HEAD(stream_tx_backlog_overflow_resets);
ATF_TC_BODY(stream_tx_backlog_overflow_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t data[64];

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->buf_alloc = 8;			/* backlog cap smaller than payload */
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;			/* not writable -> must buffer */
	memset(data, 'D', sizeof(data));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(data), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, data, sizeof(data));
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* EAGAIN + append OK, but arming the TX drainer mevent fails -> reset. */
ATF_TC_WITHOUT_HEAD(stream_tx_arm_failure_resets);
ATF_TC_BODY(stream_tx_arm_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct virtio_vsock_hdr h;
	uint8_t data[16];

	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	g_send_override = true;
	g_send_result = -1;
	g_send_errno = EAGAIN;
	g_mevent_fail = 1;			/* tx_arm's mevent_add -> NULL */
	memset(data, 'D', sizeof(data));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(data), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, data, sizeof(data));
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* =====================================================================
 * SEQPACKET guest->host record delivery error paths (vtvsock_seqpkt_rx).
 * A record is delivered atomically on EOM; delivery failures reset.
 * ===================================================================== */
static void
seqpkt_rw(struct pci_vtvsock_softc *sc, struct vtvsock_conn *c,
    const void *data, uint32_t len, uint32_t flags)
{
	struct virtio_vsock_hdr h;

	mkhdr(&h, VIRTIO_VSOCK_OP_RW, SEQPACKET, 3, VSOCK_CID_HOST,
	    c->guest_port, c->local_port, len, flags, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, data, len);
}

ATF_TC_WITHOUT_HEAD(seqpkt_rx_send_error_resets);
ATF_TC_BODY(seqpkt_rx_send_error_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[16];

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	g_send_override = true;			/* SEQPACKET delivery uses send() */
	g_send_result = -1;
	g_send_errno = ECONNRESET;		/* hard error on record delivery */
	memset(rec, 'S', sizeof(rec));
	seqpkt_rw(sc, c, rec, sizeof(rec), VIRTIO_VSOCK_SEQ_EOM);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(seqpkt_rx_arm_failure_resets);
ATF_TC_BODY(seqpkt_rx_arm_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[16];

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	g_send_override = true;			/* SEQPACKET delivery uses send() */
	g_send_result = -1;
	g_send_errno = EAGAIN;			/* not writable -> buffer the record */
	g_mevent_fail = 1;			/* but the TX drainer cannot arm */
	memset(rec, 'S', sizeof(rec));
	seqpkt_rw(sc, c, rec, sizeof(rec), VIRTIO_VSOCK_SEQ_EOM);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* =====================================================================
 * pci_vtvsock_notify_tx(): descriptor-plumbing validation on the TX ring.
 * §5.10.6.4: TX chains must be wholly device-readable; malformed chains
 * are dropped so the ring keeps draining.
 * ===================================================================== */
static void
tx_notify_bad_chain(struct pci_vtvsock_softc *sc)
{
	struct virtio_vsock_hdr *h = (void *)g_rxbuf;

	/* A well-formed OP_REQUEST that WOULD act if the chain parsed. */
	mkhdr(h, VIRTIO_VSOCK_OP_REQUEST, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, 0, 256 * 1024, 0);
	g_chain_readable = 1;			/* TX chains are device-readable */
	g_chain_writable = 0;
	g_getchain_consumes = 1;
	g_rx_descs = 1;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
}

ATF_TC_WITHOUT_HEAD(notify_tx_getchain_failure_stops);
ATF_TC_BODY(notify_tx_getchain_failure_stops, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_getchain_zero = 1;			/* has_descs true, getchain 0 */
	g_rx_descs = 1;
	pci_vtvsock_notify_tx(sc, &sc->vsc_queues[VTVSOCK_TXQ]);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(notify_tx_overlong_chain_dropped);
ATF_TC_BODY(notify_tx_overlong_chain_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_getchain_bign = 9999;
	tx_notify_bad_chain(sc);
	ATF_CHECK(nconns(sc) == 0);		/* over-long chain dropped */
	free(sc);
}

ATF_TC_WITHOUT_HEAD(notify_tx_bad_addr_dropped);
ATF_TC_BODY(notify_tx_bad_addr_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_iov_null_base = 1;
	tx_notify_bad_chain(sc);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(notify_tx_undersized_chain_dropped);
ATF_TC_BODY(notify_tx_undersized_chain_dropped, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	g_rxbuf_len = 10;			/* smaller than the header */
	tx_notify_bad_chain(sc);
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* =====================================================================
 * pci_vtvsock_init() and small device-registration callbacks.
 *
 * These exercise the device entry point exported to bhyve.  CID validation
 * follows VirtIO 1.4 §5.10.4: guest CIDs 0/1/2 are reserved (hypervisor/
 * host), 0xffffffff (VMADDR_CID_ANY / UINT32_MAX) is reserved, so a legal
 * guest CID is 3 <= cid < 0xffffffff.  Assertions below are against those
 * spec-defined bounds, not the implementation's own output.
 * ===================================================================== */

static void
init_reset(void)
{
	reset_caps();
	cfg_reset();
	g_use_real_socket = false;
	g_next_fd = 500;
	g_vi_transport_fail = 0;
	g_vi_intr_fail = 0;
}

/* Kernel backend: /dev/vsock exists in the harness environment; the attach
 * ioctl and mevent registrations are mocked, so init runs to completion. */
ATF_TC_WITHOUT_HEAD(init_kernel_backend_succeeds);
ATF_TC_BODY(init_kernel_backend_succeeds, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(0, pci_vtvsock_init(&pi, NULL));
}

/* Userspace backend: bind a real AF_UNIX control socket in a temp dir. */
ATF_TC_WITHOUT_HEAD(init_userspace_backend_succeeds);
ATF_TC_BODY(init_userspace_backend_succeeds, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_init.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "42");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(0, pci_vtvsock_init(&pi, NULL));
	ATF_CHECK(g_socket_calls >= 1);
	/* Default backend (unset) is treated as userspace per vtvsock_parse. */
	(void)unlink(dir);	/* socket file leaked via no-op close(); dir stays */
}

/* Default (unset) backend == userspace: also drives the packed-vs-legacy
 * check, which rejects packed queues on the legacy transport. */
ATF_TC_WITHOUT_HEAD(init_default_backend_is_userspace);
ATF_TC_BODY(init_default_backend_is_userspace, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_dfl.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "9");
	cfg_set("path", dir);		/* no "backend" key */
	ATF_CHECK_EQ(0, pci_vtvsock_init(&pi, NULL));
}

/* packed=on requires a modern transport; the harness reports legacy, so this
 * must be rejected (goto failed -> cleanup runs). */
ATF_TC_WITHOUT_HEAD(init_packed_requires_modern);
ATF_TC_BODY(init_packed_requires_modern, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_pkd.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	g_cfg_packed = true;
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "7");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_rejects_missing_cid);
ATF_TC_BODY(init_rejects_missing_cid, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("backend", "kernel");	/* no cid */
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_rejects_malformed_cid);
ATF_TC_BODY(init_rejects_malformed_cid, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "12x");		/* trailing junk -> *endptr != '\0' */
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

/* CIDs 0,1,2 are reserved per VirtIO 1.4 §5.10.4. */
ATF_TC_WITHOUT_HEAD(init_rejects_reserved_low_cid);
ATF_TC_BODY(init_rejects_reserved_low_cid, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "2");		/* < 3 */
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

/* 0xffffffff (VMADDR_CID_ANY) and above are reserved. */
ATF_TC_WITHOUT_HEAD(init_rejects_reserved_high_cid);
ATF_TC_BODY(init_rejects_reserved_high_cid, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "4294967295");	/* == UINT32_MAX */
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_rejects_unknown_backend);
ATF_TC_BODY(init_rejects_unknown_backend, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "bogus");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_userspace_requires_path);
ATF_TC_BODY(init_userspace_requires_path, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");	/* no path */
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_kernel_rejects_path);
ATF_TC_BODY(init_kernel_rejects_path, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	cfg_set("path", "/tmp");		/* invalid with kernel backend */
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

/* Userspace path open() failure: a non-directory / missing path. */
ATF_TC_WITHOUT_HEAD(init_userspace_bad_dir_fails);
ATF_TC_BODY(init_userspace_bad_dir_fails, tc)
{
	struct pci_devinst pi;

	init_reset();
	g_use_real_socket = true;
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");
	cfg_set("path", "/nonexistent/vtvsock/path");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

/* Legacy option-string parser turns "k=v,k=v" into config-node calls. */
ATF_TC_WITHOUT_HEAD(legacy_config_parses_pairs);
ATF_TC_BODY(legacy_config_parses_pairs, tc)
{
	init_reset();
	ATF_CHECK_EQ(0, pci_vtvsock_legacy_config(NULL, "cid=3,backend=kernel"));
	ATF_CHECK(g_setcfg_calls == 2);
	/* Last pair wins in the recorded values. */
	ATF_CHECK(strcmp(g_setcfg_key, "backend") == 0);
	ATF_CHECK(strcmp(g_setcfg_val, "kernel") == 0);
}

ATF_TC_WITHOUT_HEAD(legacy_config_rejects_bare_key);
ATF_TC_BODY(legacy_config_rejects_bare_key, tc)
{
	init_reset();
	/* "flag" has no '=' -> val == NULL -> error. */
	ATF_CHECK_EQ(-1, pci_vtvsock_legacy_config(NULL, "cid=3,flag"));
}

/* Guest config space is read-only: cfgwrite always reports "unhandled" (1). */
ATF_TC_WITHOUT_HEAD(cfgwrite_is_readonly);
ATF_TC_BODY(cfgwrite_is_readonly, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	ATF_CHECK_EQ(1, pci_vtvsock_cfgwrite(sc, 0, 4, 0x1234));
	free(sc);
}

/* The event virtqueue is reserved; its notify handler is a no-op that must
 * not touch the ring or crash. */
ATF_TC_WITHOUT_HEAD(notify_event_is_noop);
ATF_TC_BODY(notify_event_is_noop, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	pci_vtvsock_notify_event(sc, &sc->vsc_queues[VTVSOCK_EVENTQ]);
	free(sc);
}

/* mevent cleanup trampoline for per-connection event refs frees its arg. */
ATF_TC_WITHOUT_HEAD(event_ref_destroy_frees_arg);
ATF_TC_BODY(event_ref_destroy_frees_arg, tc)
{
	struct vtvsock_event_ref *ref = calloc(1, sizeof(*ref));

	ATF_REQUIRE(ref != NULL);
	vtvsock_event_ref_destroy(ref);	/* must free without use-after-free */
}

/* =====================================================================
 * pci_vtvsock_init() failure/rollback branches (goto failed cleanup).
 * ===================================================================== */
ATF_TC_WITHOUT_HEAD(init_debug_env_enables_tracing);
ATF_TC_BODY(init_debug_env_enables_tracing, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	setenv("BHYVE_VTVSOCK_DEBUG", "2", 1);
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(0, pci_vtvsock_init(&pi, NULL));
	unsetenv("BHYVE_VTVSOCK_DEBUG");
	pci_vtvsock_debug = 0;			/* don't leak level-2 tracing */
}

ATF_TC_WITHOUT_HEAD(init_transport_select_failure);
ATF_TC_BODY(init_transport_select_failure, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	g_vi_transport_fail = 1;
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_intr_init_failure);
ATF_TC_BODY(init_intr_init_failure, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	g_vi_intr_fail = 1;			/* fails at setup_pci */
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_kernel_attach_ioctl_failure);
ATF_TC_BODY(init_kernel_attach_ioctl_failure, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	g_ioctl_fail_request = VSOCK_IOC_TRANSPORT_ATTACH;
	g_ioctl_fail_errno = EOPNOTSUPP;
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_kernel_read_mevent_failure);
ATF_TC_BODY(init_kernel_read_mevent_failure, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	g_mevent_fail = 1;			/* read-cb mevent_add -> NULL */
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_kernel_write_mevent_failure);
ATF_TC_BODY(init_kernel_write_mevent_failure, tc)
{
	struct pci_devinst pi;

	init_reset();
	memset(&pi, 0, sizeof(pi));
	g_mevent_fail = 2;			/* read ok, write-cb mevent -> NULL */
	cfg_set("cid", "3");
	cfg_set("backend", "kernel");
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_userspace_socket_failure);
ATF_TC_BODY(init_userspace_socket_failure, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_sf.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	g_socket_fail = 1;			/* control socket() fails */
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_userspace_fcntl_failure);
ATF_TC_BODY(init_userspace_fcntl_failure, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_ff.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	g_fcntl_fail = 1;			/* O_NONBLOCK on ctl socket fails */
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_userspace_ctl_mevent_failure);
ATF_TC_BODY(init_userspace_ctl_mevent_failure, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_cm.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	g_mevent_fail = 1;			/* control-socket mevent -> NULL */
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(init_userspace_reap_mevent_failure);
ATF_TC_BODY(init_userspace_reap_mevent_failure, tc)
{
	struct pci_devinst pi;
	char dir[] = "/tmp/vtvsock_rm.XXXXXX";

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	init_reset();
	g_use_real_socket = true;
	g_mevent_fail = 2;			/* ctl mevent ok, reap-timer -> NULL */
	memset(&pi, 0, sizeof(pi));
	cfg_set("cid", "3");
	cfg_set("backend", "userspace");
	cfg_set("path", dir);
	ATF_CHECK_EQ(-1, pci_vtvsock_init(&pi, NULL));
}

/* =====================================================================
 * conn_data_cb host->guest RX residual and injection error paths.
 * ===================================================================== */

/* An RX injection that fails (guest RX buffer too small for even the header)
 * closes the connection with RST. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_inject_failure_resets);
ATF_TC_BODY(conn_data_cb_inject_failure_resets, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t d[32];

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	g_rx_descs = 256;
	g_rxbuf_len = 10;		/* < header: inject_raw drops -> hard fail */
	memset(d, 'D', sizeof(d));
	stage_recv(d, sizeof(d));
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	/* inject_raw drops the undersized chain, so the RST itself parks on the
	 * pending ring rather than reaching the wire; the key outcome is that
	 * the connection is torn down. */
	ATF_CHECK(nconns(sc) == 0);
	free(sc);
}

/* When the guest RX ring empties mid-record, the un-injected tail is parked
 * as rx_resid and re-injected on the next dispatch (no data loss, no reset). */
ATF_TC_WITHOUT_HEAD(conn_data_cb_parks_and_reinjects_residual);
ATF_TC_BODY(conn_data_cb_parks_and_reinjects_residual, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	uint8_t rec[200];

	reset_caps();
	g_rxbuf_len = 100;		/* 56 payload bytes per RX buffer */
	c = mk_established(sc, 1234, 80, STREAM);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	memset(rec, 'X', sizeof(rec));
	stage_recv(rec, sizeof(rec));
	g_rx_descs = 1;			/* only one buffer: ring empties mid-record */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(c->rx_resid != NULL);		/* tail parked */
	ATF_CHECK(g_ninject == 1);		/* one fragment delivered so far */

	g_rx_descs = 256;		/* guest posts more descriptors */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(c->rx_resid == NULL);		/* residual fully drained */
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

/* SEQPACKET: no bytes queued and recvmsg peek would block -> nothing happens. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_seqpacket_wouldblock);
ATF_TC_BODY(conn_data_cb_seqpacket_wouldblock, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	g_recv_len = g_recv_off = 0;		/* FIONREAD 0, recvmsg -> EAGAIN */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 0);
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

/* SEQPACKET empty record but the RX ring is full: delivery is deferred. */
ATF_TC_WITHOUT_HEAD(conn_data_cb_seqpacket_empty_record_ring_full);
ATF_TC_BODY(conn_data_cb_seqpacket_empty_record_ring_full, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;

	reset_caps();
	c = mk_established(sc, 1234, 80, SEQPACKET);
	c->evp = mevent_add(c->fd, EVF_READ, vtvsock_conn_data_cb, sc);
	g_recv_len = g_recv_off = 0;
	g_recv_zero_dgram = 1;			/* empty MSG_EOR record queued */
	g_rx_descs = 0;				/* but the RX ring is full */
	vtvsock_conn_data_cb(c->fd, EVF_READ, sc);
	ATF_CHECK(g_ninject == 0);		/* deferred, not delivered */
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

/* =====================================================================
 * Misc TX state-machine + reaper + device-reset branches.
 * ===================================================================== */

/* OP_SHUTDOWN(SEND) after the host already closed completes the teardown:
 * the connection moves to CLOSING and a full SHUTDOWN is sent to the guest. */
ATF_TC_WITHOUT_HEAD(tx_shutdown_completes_close);
ATF_TC_BODY(tx_shutdown_completes_close, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->host_eof = true;			/* host app already closed */
	mkhdr(&h, VIRTIO_VSOCK_OP_SHUTDOWN, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    0, VIRTIO_VSOCK_SHUTDOWN_SEND, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, NULL, 0);
	ATF_CHECK(c->state == CONN_CLOSING);
	ATF_CHECK(g_inject[g_ninject - 1].op == VIRTIO_VSOCK_OP_SHUTDOWN);
	free(sc);
}

/* OP_RW to a CLOSING connection is credit-accounted but the payload dropped. */
ATF_TC_WITHOUT_HEAD(tx_rw_on_closing_conn_discarded);
ATF_TC_BODY(tx_rw_on_closing_conn_discarded, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t d[16];

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CLOSING;
	memset(d, 'D', sizeof(d));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(d), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, d, sizeof(d));
	ATF_CHECK(c->fwd_cnt == sizeof(d));	/* accounted */
	ATF_CHECK(g_send_calls == 0);		/* but not delivered */
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

/* OP_RW to a still-CONNECTING connection is ignored (no host consumer yet). */
ATF_TC_WITHOUT_HEAD(tx_rw_on_connecting_conn_ignored);
ATF_TC_BODY(tx_rw_on_connecting_conn_ignored, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct virtio_vsock_hdr h;
	uint8_t d[16];

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	memset(d, 'D', sizeof(d));
	mkhdr(&h, VIRTIO_VSOCK_OP_RW, STREAM, 3, VSOCK_CID_HOST, 1234, 80,
	    sizeof(d), 0, 256 * 1024, 0);
	vtvsock_process_tx_pkt(sc, &h, d, sizeof(d));
	ATF_CHECK(g_send_calls == 0);
	ATF_CHECK(nconns(sc) == 1);
	free(sc);
}

/* Reaper times out a stale host-initiated CONNECTING conn and reports
 * -ETIMEDOUT to the waiting host control connection. */
ATF_TC_WITHOUT_HEAD(reaper_times_out_host_connect);
ATF_TC_BODY(reaper_times_out_host_connect, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();
	struct vtvsock_conn *c;
	struct vsock_ctl_msg reply;
	int ctlfd = g_next_fd++;

	reset_caps();
	c = mk_established(sc, 1234, 80, STREAM);
	c->state = CONN_CONNECTING;
	c->close_time = 1;			/* ancient: exceeds the timeout */
	c->ctl_fd = ctlfd;
	(void)mk_ctl_conn(sc, ctlfd, 100);
	vtvsock_reap_stale(sc);
	ATF_CHECK(nconns(sc) == 0);		/* timed-out conn reaped */
	ATF_REQUIRE(g_send_len == sizeof(reply));
	memcpy(&reply, g_send_buf, sizeof(reply));
	ATF_CHECK(reply.status == -ETIMEDOUT);
	free(sc);
}

/* pci_vtvsock_reset() tears down all connections and control connections and
 * discards parked control replies. */
ATF_TC_WITHOUT_HEAD(device_reset_closes_all);
ATF_TC_BODY(device_reset_closes_all, tc)
{
	struct pci_vtvsock_softc *sc = mk_sc();

	reset_caps();
	(void)mk_established(sc, 1234, 80, STREAM);
	(void)mk_established(sc, 1235, 81, SEQPACKET);
	(void)mk_ctl_conn(sc, g_next_fd++, 100);
	(void)mk_ctl_conn(sc, g_next_fd++, 100);
	sc->vsc_pend_count = 1;			/* a parked reply to discard */
	pci_vtvsock_reset(sc);
	ATF_CHECK(nconns(sc) == 0);
	ATF_CHECK(nctlconns(sc) == 0);
	ATF_CHECK(sc->vsc_ctl_conn_count == 0);
	ATF_CHECK(sc->vsc_pend_count == 0);
	free(sc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, tx_shutdown_completes_close);
	ATF_TP_ADD_TC(tp, tx_rw_on_closing_conn_discarded);
	ATF_TP_ADD_TC(tp, tx_rw_on_connecting_conn_ignored);
	ATF_TP_ADD_TC(tp, reaper_times_out_host_connect);
	ATF_TP_ADD_TC(tp, device_reset_closes_all);
	ATF_TP_ADD_TC(tp, init_debug_env_enables_tracing);
	ATF_TP_ADD_TC(tp, init_transport_select_failure);
	ATF_TP_ADD_TC(tp, init_intr_init_failure);
	ATF_TP_ADD_TC(tp, init_kernel_attach_ioctl_failure);
	ATF_TP_ADD_TC(tp, init_kernel_read_mevent_failure);
	ATF_TP_ADD_TC(tp, init_kernel_write_mevent_failure);
	ATF_TP_ADD_TC(tp, init_userspace_socket_failure);
	ATF_TP_ADD_TC(tp, init_userspace_fcntl_failure);
	ATF_TP_ADD_TC(tp, init_userspace_ctl_mevent_failure);
	ATF_TP_ADD_TC(tp, init_userspace_reap_mevent_failure);
	ATF_TP_ADD_TC(tp, conn_data_cb_inject_failure_resets);
	ATF_TP_ADD_TC(tp, conn_data_cb_parks_and_reinjects_residual);
	ATF_TP_ADD_TC(tp, conn_data_cb_seqpacket_wouldblock);
	ATF_TP_ADD_TC(tp, conn_data_cb_seqpacket_empty_record_ring_full);
	ATF_TP_ADD_TC(tp, ctl_accept_transient_failure_ignored);
	ATF_TP_ADD_TC(tp, ctl_accept_fcntl_failure_drops);
	ATF_TP_ADD_TC(tp, ctl_accept_mevent_failure_drops);
	ATF_TP_ADD_TC(tp, ctl_conn_eof_removes_conn);
	ATF_TP_ADD_TC(tp, ctl_conn_wouldblock_keeps_conn);
	ATF_TP_ADD_TC(tp, ctl_connect_unnegotiated_type_refused);
	ATF_TP_ADD_TC(tp, ctl_connect_fcntl_failure_replies_error);
	ATF_TP_ADD_TC(tp, ctl_connect_conn_alloc_failure_replies_error);
	ATF_TP_ADD_TC(tp, write_cb_no_backlog_disables_drainer);
	ATF_TP_ADD_TC(tp, write_cb_stream_drains_backlog);
	ATF_TP_ADD_TC(tp, write_cb_stream_wouldblock_stays_armed);
	ATF_TP_ADD_TC(tp, write_cb_stream_zero_progress_stays_armed);
	ATF_TP_ADD_TC(tp, write_cb_stream_error_resets);
	ATF_TP_ADD_TC(tp, write_cb_seqpacket_drains_record);
	ATF_TP_ADD_TC(tp, write_cb_seqpacket_wouldblock_stays_armed);
	ATF_TP_ADD_TC(tp, write_cb_seqpacket_short_send_resets);
	ATF_TP_ADD_TC(tp, inject_raw_getchain_failure_drops);
	ATF_TP_ADD_TC(tp, inject_raw_overlong_chain_drops);
	ATF_TP_ADD_TC(tp, inject_raw_bad_descriptor_addr_drops);
	ATF_TP_ADD_TC(tp, inject_raw_undersized_chain_drops);
	ATF_TP_ADD_TC(tp, conn_data_cb_ignored_while_paused);
	ATF_TP_ADD_TC(tp, conn_data_cb_noop_while_connecting);
	ATF_TP_ADD_TC(tp, conn_data_cb_rcv_shutdown_disables_read);
	ATF_TP_ADD_TC(tp, conn_data_cb_seqpacket_host_eof);
	ATF_TP_ADD_TC(tp, conn_data_cb_seqpacket_empty_record);
	ATF_TP_ADD_TC(tp, conn_data_cb_seqpacket_record_exceeds_window);
	ATF_TP_ADD_TC(tp, tx_duplicate_request_resets);
	ATF_TP_ADD_TC(tp, tx_request_collision_ignored);
	ATF_TP_ADD_TC(tp, tx_request_socket_failure_resets);
	ATF_TP_ADD_TC(tp, tx_request_mevent_failure_resets);
	ATF_TP_ADD_TC(tp, tx_peer_buf_alloc_clamped);
	ATF_TP_ADD_TC(tp, tx_response_wrong_state_ignored);
	ATF_TP_ADD_TC(tp, tx_response_completes_host_connect);
	ATF_TP_ADD_TC(tp, tx_response_mevent_failure_resets);
	ATF_TP_ADD_TC(tp, tx_rst_host_connect_reports_refused);
	ATF_TP_ADD_TC(tp, stream_tx_send_error_resets);
	ATF_TP_ADD_TC(tp, stream_tx_backlog_overflow_resets);
	ATF_TP_ADD_TC(tp, stream_tx_arm_failure_resets);
	ATF_TP_ADD_TC(tp, seqpkt_rx_send_error_resets);
	ATF_TP_ADD_TC(tp, seqpkt_rx_arm_failure_resets);
	ATF_TP_ADD_TC(tp, notify_tx_getchain_failure_stops);
	ATF_TP_ADD_TC(tp, notify_tx_overlong_chain_dropped);
	ATF_TP_ADD_TC(tp, notify_tx_bad_addr_dropped);
	ATF_TP_ADD_TC(tp, notify_tx_undersized_chain_dropped);
	ATF_TP_ADD_TC(tp, init_kernel_backend_succeeds);
	ATF_TP_ADD_TC(tp, init_userspace_backend_succeeds);
	ATF_TP_ADD_TC(tp, init_default_backend_is_userspace);
	ATF_TP_ADD_TC(tp, init_packed_requires_modern);
	ATF_TP_ADD_TC(tp, init_rejects_missing_cid);
	ATF_TP_ADD_TC(tp, init_rejects_malformed_cid);
	ATF_TP_ADD_TC(tp, init_rejects_reserved_low_cid);
	ATF_TP_ADD_TC(tp, init_rejects_reserved_high_cid);
	ATF_TP_ADD_TC(tp, init_rejects_unknown_backend);
	ATF_TP_ADD_TC(tp, init_userspace_requires_path);
	ATF_TP_ADD_TC(tp, init_kernel_rejects_path);
	ATF_TP_ADD_TC(tp, init_userspace_bad_dir_fails);
	ATF_TP_ADD_TC(tp, legacy_config_parses_pairs);
	ATF_TP_ADD_TC(tp, legacy_config_rejects_bare_key);
	ATF_TP_ADD_TC(tp, cfgwrite_is_readonly);
	ATF_TP_ADD_TC(tp, notify_event_is_noop);
	ATF_TP_ADD_TC(tp, event_ref_destroy_frees_arg);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, suspend_fences_and_rearms_host_sources);
	ATF_TP_ADD_TC(tp, kernel_suspend_fences_and_rearms_provider_sources);
	ATF_TP_ADD_TC(tp, resume_preserves_checkpoint_owner);
	ATF_TP_ADD_TC(tp, reset_cancels_suspend_and_reopens_admission);
	ATF_TP_ADD_TC(tp, reset_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp, snapshot_rejects_unreconstructible_backend_state);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, kernel_checkpoint_freezes_and_thaws_provider);
	ATF_TP_ADD_TC(tp, kernel_checkpoint_malformed_reply_thaw_failure);
	ATF_TP_ADD_TC(tp, kernel_checkpoint_thaw_failure_is_retryable);
	ATF_TP_ADD_TC(tp, snapshot_portable_identity_and_atomicity);
	ATF_TP_ADD_TC(tp, init_failure_detaches_and_retires_child_events);
	ATF_TP_ADD_TC(tp, snapshot_kernel_backend_validation);
	ATF_TP_ADD_TC(tp, backend_names_are_userspace_and_kernel);
	ATF_TP_ADD_TC(tp, queue_reset_discards_only_selected_queue_work);
	ATF_TP_ADD_TC(tp, spoofed_src_cid);
	ATF_TP_ADD_TC(tp, port_allocator_skips_reserved);
	ATF_TP_ADD_TC(tp, send_fd_requires_complete_frame);
	ATF_TP_ADD_TC(tp, unknown_type_rst);
	ATF_TP_ADD_TC(tp, unknown_conn_rst);
	ATF_TP_ADD_TC(tp, rst_unknown_conn_ignored);
	ATF_TP_ADD_TC(tp, request_connect_ok);
	ATF_TP_ADD_TC(tp, request_nonzero_initial_fwd_cnt_rst);
	ATF_TP_ADD_TC(tp, request_no_listener_rst);
	ATF_TP_ADD_TC(tp, rw_forwards_to_host);
	ATF_TP_ADD_TC(tp, stream_eagain_drains_on_writable);
	ATF_TP_ADD_TC(tp, rw_type_mismatch_resets);
	ATF_TP_ADD_TC(tp, peer_fwd_cnt_overflow_rst);
	ATF_TP_ADD_TC(tp, peer_fwd_cnt_rewind_ignored);
	ATF_TP_ADD_TC(tp, credit_update_full_ring_parked);
	ATF_TP_ADD_TC(tp, pending_reply_overflow_retries_credit);
	ATF_TP_ADD_TC(tp, pending_reply_flush_is_queue_bounded);
	ATF_TP_ADD_TC(tp, shutdown_both_closes);
	ATF_TP_ADD_TC(tp, seqpacket_request_response);
	ATF_TP_ADD_TC(tp, wrong_dst_cid_dropped);
	ATF_TP_ADD_TC(tp, shutdown_half_then_full);
	ATF_TP_ADD_TC(tp, request_collision_keeps_host_connect);
	ATF_TP_ADD_TC(tp, host_rx_forwards_to_guest);
	ATF_TP_ADD_TC(tp, host_rx_respects_credit);
	ATF_TP_ADD_TC(tp, stale_event_identity_rejects_reused_fd);
	ATF_TP_ADD_TC(tp, seqpacket_partial_credit_tracks_stall);
	ATF_TP_ADD_TC(tp, host_rx_fragments_to_small_rx_buffer);
	ATF_TP_ADD_TC(tp, host_rx_stream_fragments_to_small_rx_buffer);
	ATF_TP_ADD_TC(tp, host_rx_oversized_seqpacket_record_resets);
	ATF_TP_ADD_TC(tp, host_eof_sends_shutdown);
	ATF_TP_ADD_TC(tp, seqpacket_reassembles_to_eom);
	ATF_TP_ADD_TC(tp, seqpacket_short_send_resets);
	ATF_TP_ADD_TC(tp, seqpacket_emsgsize_resets);
	ATF_TP_ADD_TC(tp, seqpacket_deferred_short_send_resets);
	ATF_TP_ADD_TC(tp, seqpacket_deferred_delivery_returns_credit);
	ATF_TP_ADD_TC(tp, seqpacket_realloc_failure_resets_cleanly);
	ATF_TP_ADD_TC(tp, seqpacket_credit_follows_complete_delivery);
	ATF_TP_ADD_TC(tp, seqpacket_record_over_advertised_window_resets);
	ATF_TP_ADD_TC(tp, seqpacket_zero_len_record);
	ATF_TP_ADD_TC(tp, rx_chain_not_writable_dropped);
	ATF_TP_ADD_TC(tp, tx_chain_not_readable_dropped);
	ATF_TP_ADD_TC(tp, global_reasm_budget_rst);
	ATF_TP_ADD_TC(tp, seqpacket_host_zero_len_to_guest);
	ATF_TP_ADD_TC(tp, seqpacket_host_eor_propagated);
	ATF_TP_ADD_TC(tp, seqpacket_host_eof_sends_shutdown);
	ATF_TP_ADD_TC(tp, seqpacket_reasm_freed_after_delivery);
	ATF_TP_ADD_TC(tp, shutdown_rcv_half_close_not_escalated);
	ATF_TP_ADD_TC(tp, half_close_send_then_host_eof);
	ATF_TP_ADD_TC(tp, host_data_then_eof_same_dispatch);
	ATF_TP_ADD_TC(tp, reaper_reaps_idle_ctl_conn);
	ATF_TP_ADD_TC(tp, ctl_accept_cap);
	ATF_TP_ADD_TC(tp, ctl_connect_emits_request);
	ATF_TP_ADD_TC(tp, ctl_connect_accepts_short_reads);
	ATF_TP_ADD_TC(tp, ctl_connect_rejects_invalid_type);
	ATF_TP_ADD_TC(tp, negotiated_socket_types);
	ATF_TP_ADD_TC(tp, relay_bufsize_enlarged_on_connect);
	ATF_TP_ADD_TC(tp, ctl_unknown_cmd_ignored);
	ATF_TP_ADD_TC(tp, ctl_connect_socketpair_fail);
	ATF_TP_ADD_TC(tp, reaper_keeps_referenced_ctl_conn);
	ATF_TP_ADD_TC(tp, conn_cap_refuses_and_reclaims);
	ATF_TP_ADD_TC(tp, reaper_closes_stuck_closing);
	ATF_TP_ADD_TC(tp, reaper_times_out_connecting);
	ATF_TP_ADD_TC(tp, tx_oversized_paylen_dropped);
	ATF_TP_ADD_TC(tp, tx_control_payload_dropped);
	ATF_TP_ADD_TC(tp, tx_truncated_payload_dropped);
	ATF_TP_ADD_TC(tp, kernel_rx_fragments_for_guest_buffers);
	ATF_TP_ADD_TC(tp, kernel_rx_accepts_header_only_packet);
	ATF_TP_ADD_TC(tp, kernel_rx_large_descriptor_capacity);
	ATF_TP_ADD_TC(tp, kernel_rx_reuses_preallocated_buffer);
	ATF_TP_ADD_TC(tp, kernel_rx_dispatch_is_queue_bounded);
	ATF_TP_ADD_TC(tp, kernel_rx_fragment_dispatch_is_queue_bounded);
	ATF_TP_ADD_TC(tp, kernel_rx_pending_and_data_share_queue_budget);
	ATF_TP_ADD_TC(tp, kernel_rx_refill_pulls_queued_packet);
	ATF_TP_ADD_TC(tp, kernel_rx_fatal_error_disables_event);
	ATF_TP_ADD_TC(tp, kernel_rx_short_packet_needs_reset);
	ATF_TP_ADD_TC(tp, kernel_rx_length_mismatch_needs_reset);
	ATF_TP_ADD_TC(tp, kernel_reset_success_recovers_backend);
	ATF_TP_ADD_TC(tp, kernel_tx_forwards_complete_packet);
	ATF_TP_ADD_TC(tp, kernel_tx_pulls_synchronous_reply);
	ATF_TP_ADD_TC(tp, kernel_tx_fatal_error_needs_reset);
	ATF_TP_ADD_TC(tp, kernel_tx_short_write_needs_reset);
	ATF_TP_ADD_TC(tp, kernel_tx_backpressure_is_retried);
	ATF_TP_ADD_TC(tp, kernel_tx_retry_short_write_needs_reset);
	ATF_TP_ADD_TC(tp, kernel_tx_malformed_packet_is_dropped);
	ATF_TP_ADD_TC(tp, kernel_failure_survives_feature_update);
	ATF_TP_ADD_TC(tp, kernel_feature_update_masks_transport_bits);
	ATF_TP_ADD_TC(tp, kernel_reset_failure_remains_fatal);

	return (atf_no_error());
}

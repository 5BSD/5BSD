/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TU-include ATF harness for bhyve's VirtIO crypto device.
 *
 * The generic virtqueue transport, PCI/virtio plumbing and the bhyve config
 * store are mocked; a flat guest buffer backs the descriptor iovecs so the real
 * OpenSSL backend runs over guest-provided data.  Crypto correctness is checked
 * against published known-answer test vectors (NIST SP800-38A AES-CBC, FIPS 180
 * SHA-256("abc"), RFC 4231 HMAC-SHA-256, McGrew/NIST AES-GCM), never against the
 * implementation's own output.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

static void *test_calloc(size_t, size_t);
static int test_pthread_mutex_init(pthread_mutex_t *,
    const pthread_mutexattr_t *);

#define	calloc		test_calloc
#define	pthread_mutex_init test_pthread_mutex_init
#include "pci_virtio_crypto.c"
#undef calloc
#undef pthread_mutex_init

/* Compile the DUT first, then obtain expectations from the 1.4 oracle. */
#include "virtio_1_4_spec.h"
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED

/* ------------------------------------------------------------------ mocks */

struct nvlist { int unused; };

int raw_stdio;

#define	MOCK_MAXSEG	16

static struct {
	struct iovec iov[MOCK_MAXSEG];
	int n;
	int readable;
	int writable;
	bool ordered;
	int ready;
	uint16_t idx;
} g_chain;

static int g_rel_calls;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_needs_reset;
static int g_reset_dev_calls;

static bool g_calloc_fail_softc;
static bool g_calloc_fail_sessions;
static int g_calloc_calls;
static int g_mutex_init_fail_at;
static int g_mutex_init_calls;

static int g_select_result;
static bool g_modern;
static int g_intr_result;
static int g_modern_init_result;

static const char *g_cfg_queues;
static const char *g_cfg_maxsessions;
static bool g_cfg_packed;

static void
reset_mocks(void)
{

	memset(&g_chain, 0, sizeof(g_chain));
	g_chain.idx = 5;
	g_rel_calls = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_needs_reset = 0;
	g_reset_dev_calls = 0;
	g_calloc_fail_softc = false;
	g_calloc_fail_sessions = false;
	g_calloc_calls = 0;
	g_mutex_init_fail_at = 0;
	g_mutex_init_calls = 0;
	g_select_result = 0;
	g_modern = true;
	g_intr_result = 0;
	g_modern_init_result = 0;
	g_cfg_queues = NULL;
	g_cfg_maxsessions = NULL;
	g_cfg_packed = false;
}

static void *
test_calloc(size_t nmemb, size_t size)
{

	g_calloc_calls++;
	if (g_calloc_fail_softc && g_calloc_calls == 1)
		return (NULL);
	if (g_calloc_fail_sessions && g_calloc_calls == 2)
		return (NULL);
	return (calloc(nmemb, size));
}

static int
test_pthread_mutex_init(pthread_mutex_t *mtx, const pthread_mutexattr_t *attr)
{

	g_mutex_init_calls++;
	if (g_mutex_init_fail_at != 0 && g_mutex_init_calls == g_mutex_init_fail_at)
		return (EAGAIN);
	return (pthread_mutex_init(mtx, attr));
}

int
vi_pci_lifecycle_noop(void *vsc __unused)
{

	return (0);
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (g_chain.ready > 0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	int copied;

	if (g_chain.ready <= 0)
		return (0);
	g_chain.ready--;
	memset(req, 0, sizeof(*req));
	req->idx = g_chain.idx;
	req->readable = g_chain.readable;
	req->writable = g_chain.writable;
	req->ordered = g_chain.ordered;
	if (g_chain.n < 0)
		return (g_chain.n);
	copied = MIN(g_chain.n, niov);
	for (int i = 0; i < copied; i++)
		iov[i] = g_chain.iov[i];
	return (g_chain.n);
}

void
vq_relchain_req(struct vqueue_info *vq __unused, struct vi_req *req __unused,
    uint32_t len)
{

	g_rel_calls++;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{

	g_end_calls++;
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{

	g_reset_dev_calls++;
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	g_needs_reset++;
}

int
vi_config_read_le(const void *config, size_t config_size, int offset, int size,
    uint32_t *value)
{
	const uint8_t *bytes = config;

	if (config == NULL || value == NULL || offset < 0 ||
	    (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > config_size ||
	    (size_t)size > config_size - (size_t)offset)
		return (EINVAL);
	switch (size) {
	case 1:
		*value = bytes[offset];
		break;
	case 2:
		*value = le16dec(bytes + offset);
		break;
	case 4:
		*value = le32dec(bytes + offset);
		break;
	}
	return (0);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *dev_softc, struct pci_devinst *pi, struct vqueue_info *queues)
{

	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	pi->pi_arg = dev_softc;
	for (int i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

int
vi_pci_select_transport(struct virtio_softc *vs, const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy)
{

	ATF_CHECK_EQ(policy, VIRTIO_PCI_MODERN_ONLY);
	vs->vs_transport = g_modern ? VIRTIO_PCI_TRANSPORT_MODERN :
	    VIRTIO_PCI_TRANSPORT_LEGACY;
	return (g_select_result);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t id __unused)
{
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{

	return (g_modern_init_result);
}

int
vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int msix __unused)
{

	return (g_intr_result);
}

void
vi_set_io_bar(struct virtio_softc *vs __unused, int bar __unused)
{
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

/* Symbols referenced only by the pci_devemu vtable; unused at runtime. */
uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *val __unused)
{

	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t val __unused)
{

	return (0);
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

int
vi_pci_snapshot_compat(struct pci_devinst *pi __unused,
    struct pci_snapshot_compat *c __unused)
{

	return (0);
}

int
vi_pci_pause(struct pci_devinst *pi __unused)
{

	return (0);
}

int
vi_pci_resume(struct pci_devinst *pi __unused)
{

	return (0);
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "queues") == 0)
		return (g_cfg_queues);
	if (strcmp(name, "maxsessions") == 0)
		return (g_cfg_maxsessions);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool def)
{

	if (strcmp(name, "packed") == 0)
		return (g_cfg_packed);
	return (def);
}

/* Portable snapshot codec mocks (little-endian byte stream). */
void
vm_snapshot_buf_err(const char *name __unused, const enum vm_snapshot_op op __unused)
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
	uint8_t b[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		b[0] = *value;
		b[1] = *value >> 8;
	}
	error = vm_snapshot_buf(b, sizeof(b), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint16_t)b[0] | (uint16_t)b[1] << 8;
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t b[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		for (unsigned i = 0; i < 4; i++)
			b[i] = *value >> (i * 8);
	error = vm_snapshot_buf(b, sizeof(b), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned i = 0; i < 4; i++)
			*value |= (uint32_t)b[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t b[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		for (unsigned i = 0; i < 8; i++)
			b[i] = *value >> (i * 8);
	error = vm_snapshot_buf(b, sizeof(b), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned i = 0; i < 8; i++)
			*value |= (uint64_t)b[i] << (i * 8);
	}
	return (error);
}

/* -------------------------------------------------------------- utilities */

static uint8_t g_guest[16384];

static size_t
hexdecode(const char *hex, uint8_t *out)
{
	size_t n = 0;

	while (hex[0] != '\0' && hex[1] != '\0') {
		unsigned v;

		if (sscanf(hex, "%2x", &v) != 1)
			break;
		out[n++] = (uint8_t)v;
		hex += 2;
	}
	return (n);
}

struct seg { size_t off; size_t len; };

static void
mock_set_chain(const struct seg *rsegs, int nread, const struct seg *wsegs,
    int nwrite, bool ordered)
{
	int i;

	memset(&g_chain, 0, sizeof(g_chain));
	g_chain.idx = 5;
	g_chain.readable = nread;
	g_chain.writable = nwrite;
	g_chain.ordered = ordered;
	g_chain.n = nread + nwrite;
	g_chain.ready = 1;
	for (i = 0; i < nread; i++) {
		g_chain.iov[i].iov_base = g_guest + rsegs[i].off;
		g_chain.iov[i].iov_len = rsegs[i].len;
	}
	for (int j = 0; j < nwrite; j++, i++) {
		g_chain.iov[i].iov_base = g_guest + wsegs[j].off;
		g_chain.iov[i].iov_len = wsegs[j].len;
	}
}

static int
run_snap(struct pci_vtcrypto_softc *sc, void *buf, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = buf,
			.buf_size = size,
			.buf = buf,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtcrypto_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

static struct pci_vtcrypto_softc *
make_device(const char *queues, const char *maxsessions)
{
	struct pci_devinst *pi;

	pi = calloc(1, sizeof(*pi));
	ATF_REQUIRE(pi != NULL);
	reset_mocks();
	g_cfg_queues = queues;
	g_cfg_maxsessions = maxsessions;
	ATF_REQUIRE_EQ(0, pci_vtcrypto_init(pi, NULL));
	return ((struct pci_vtcrypto_softc *)pi->pi_arg);
}

/*
 * Create a session over the control queue and return the assigned id and the
 * device-reported status.  op_ctrl_req is 72 bytes; optional key follows.
 */
static uint32_t
control_create(struct pci_vtcrypto_softc *sc, uint32_t opcode,
    const uint32_t para[4], size_t npara, uint32_t op_type_at64,
    const uint8_t *key, size_t keylen, uint64_t *idp)
{
	struct seg r[2], w[1];
	uint8_t *req = g_guest;
	uint8_t *input;
	int nread = 1;

	memset(g_guest, 0, sizeof(g_guest));
	st32(req + 0, opcode);
	for (size_t i = 0; i < npara; i++)
		st32(req + 16 + i * 4, para[i]);
	if (op_type_at64 != UINT32_MAX)
		st32(req + 64, op_type_at64);
	r[0].off = 0;
	r[0].len = VTCRYPTO_OP_CTRL_REQ_LEN;
	if (key != NULL) {
		memcpy(g_guest + 72, key, keylen);
		r[1].off = 72;
		r[1].len = keylen;
		nread = 2;
	}
	/* session_input at offset 512 in the writable area. */
	w[0].off = 512;
	w[0].len = VTCRYPTO_SESSION_INPUT_LEN;
	mock_set_chain(r, nread, w, 1, true);
	g_rel_calls = 0;
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	ATF_CHECK_EQ(1, g_rel_calls);
	input = g_guest + 512;
	if (idp != NULL)
		*idp = ld64(input + 0);
	return (ld32(input + 8));
}

static uint8_t
control_destroy(struct pci_vtcrypto_softc *sc, uint32_t opcode, uint64_t id)
{
	struct seg r[1], w[1];

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, opcode);
	st64(g_guest + 16, id);
	r[0].off = 0;
	r[0].len = VTCRYPTO_OP_CTRL_REQ_LEN;
	w[0].off = 512;
	w[0].len = 1;
	g_guest[512] = 0xee;
	mock_set_chain(r, 1, w, 1, true);
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	return (g_guest[512]);
}

/* ------------------------------------------------------------------ tests */

ATF_TC_WITHOUT_HEAD(config_space);
ATF_TC_BODY(config_space, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t v;
	uint64_t v64;

	sc = make_device("2", "128");

	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_STATUS_OFF, 4, &v));
	ATF_CHECK_EQ(VIRTIO_CRYPTO_S_HW_READY, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAX_DATAQUEUES_OFF, 4, &v));
	ATF_CHECK_EQ(2u, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_CRYPTO_SERVICES_OFF, 4, &v));
	ATF_CHECK_EQ((1u << VIRTIO_CRYPTO_SERVICE_CIPHER) |
	    (1u << VIRTIO_CRYPTO_SERVICE_HASH) |
	    (1u << VIRTIO_CRYPTO_SERVICE_MAC) |
	    (1u << VIRTIO_CRYPTO_SERVICE_AEAD), v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_CIPHER_ALGO_L_OFF, 4, &v));
	ATF_CHECK_EQ(1u << VIRTIO_CRYPTO_CIPHER_AES_CBC, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_HASH_ALGO_OFF, 4, &v));
	ATF_CHECK_EQ(1u << VIRTIO_CRYPTO_HASH_SHA_256, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAC_ALGO_L_OFF, 4, &v));
	ATF_CHECK_EQ(1u << VIRTIO_CRYPTO_MAC_HMAC_SHA_256, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_AEAD_ALGO_OFF, 4, &v));
	ATF_CHECK_EQ(1u << VIRTIO_CRYPTO_AEAD_GCM, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAX_CIPHER_KEY_LEN_OFF, 4, &v));
	ATF_CHECK_EQ(VTCRYPTO_MAX_KEYLEN, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAX_AUTH_KEY_LEN_OFF, 4, &v));
	ATF_CHECK_EQ(VTCRYPTO_MAX_KEYLEN, v);

	/* 64-bit max_size read as two 32-bit halves. */
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAX_SIZE_OFF, 4, &v));
	v64 = v;
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_MAX_SIZE_OFF + 4, 4, &v));
	v64 |= (uint64_t)v << 32;
	ATF_CHECK_EQ((uint64_t)VTCRYPTO_MAX_DATALEN, v64);

	/* akcipher advertised as unsupported. */
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_AKCIPHER_ALGO_OFF, 4, &v));
	ATF_CHECK_EQ(0u, v);

	/* Byte and word accesses. */
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc, 0, 1, &v));
	ATF_CHECK_EQ(VIRTIO_CRYPTO_S_HW_READY, v);
	ATF_REQUIRE_EQ(0, pci_vtcrypto_cfgread(sc, 0, 2, &v));
	ATF_CHECK_EQ(VIRTIO_CRYPTO_S_HW_READY, v);

	/* Error branches. */
	ATF_CHECK_EQ(EINVAL, pci_vtcrypto_cfgread(sc, -1, 4, &v));
	ATF_CHECK_EQ(EINVAL, pci_vtcrypto_cfgread(sc, 0, 3, &v));
	ATF_CHECK_EQ(EINVAL, pci_vtcrypto_cfgread(sc,
	    VIRTIO14_CRYPTO_CONFIG_SIZE, 4, &v));
}

ATF_TC_WITHOUT_HEAD(init_and_failures);
ATF_TC_BODY(init_and_failures, tc)
{
	struct pci_devinst pi;

	/* Successful init: defaults. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	ATF_REQUIRE_EQ(0, pci_vtcrypto_init(&pi, NULL));
	{
		struct pci_vtcrypto_softc *sc = pi.pi_arg;

		ATF_REQUIRE(sc != NULL);
		ATF_CHECK_EQ(1, sc->vcs_ndataq);
		ATF_CHECK_EQ(VTCRYPTO_DEFAULT_MAXSESSIONS, sc->vcs_maxsessions);
		ATF_CHECK_EQ(2, sc->vcs_consts.vc_nvq);
		ATF_CHECK_EQ((uint8_t)PCIC_CRYPTO, pi.pi_cfgdata[PCIR_CLASS]);
		pthread_mutex_destroy(&sc->vcs_mtx);
		free(sc->vcs_sessions);
		free(sc);
	}

	/* Packed opt-in. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_cfg_packed = true;
	ATF_REQUIRE_EQ(0, pci_vtcrypto_init(&pi, NULL));
	{
		struct pci_vtcrypto_softc *sc = pi.pi_arg;

		ATF_CHECK((sc->vcs_consts.vc_hv_caps & VIRTIO_F_RING_PACKED) != 0);
		pthread_mutex_destroy(&sc->vcs_mtx);
		free(sc->vcs_sessions);
		free(sc);
	}

	/* Bad queues / maxsessions strings. */
	memset(&pi, 0, sizeof(pi));
	reset_mocks();
	g_cfg_queues = "0";
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));
	reset_mocks();
	g_cfg_queues = "99";
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));
	reset_mocks();
	g_cfg_maxsessions = "bogus";
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Allocation failures. */
	reset_mocks();
	g_calloc_fail_softc = true;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));
	reset_mocks();
	g_calloc_fail_sessions = true;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Mutex init failure. */
	reset_mocks();
	g_mutex_init_fail_at = 1;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Transport selection failure. */
	reset_mocks();
	g_select_result = -1;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Packed requires modern. */
	reset_mocks();
	g_cfg_packed = true;
	g_modern = false;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Interrupt init failure. */
	reset_mocks();
	g_intr_result = 1;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));

	/* Modern PCI init failure (after intr initialized). */
	reset_mocks();
	g_modern_init_result = -1;
	ATF_CHECK_EQ(1, pci_vtcrypto_init(&pi, NULL));
}

ATF_TC_WITHOUT_HEAD(session_lifecycle);
ATF_TC_BODY(session_lifecycle, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[4];
	uint8_t key[32];
	uint64_t id, id2;

	sc = make_device(NULL, NULL);
	memset(key, 0x11, sizeof(key));

	/* CIPHER create (AES-CBC, 16-byte key, encrypt). */
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT;
	para[3] = 0;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &id));
	ATF_CHECK_EQ(1u, sc->vcs_nsessions);
	ATF_CHECK(sc->vcs_sessions[id].used);
	ATF_CHECK_EQ((uint32_t)VIRTIO_CRYPTO_SERVICE_CIPHER,
	    sc->vcs_sessions[id].service);

	/* HASH create. */
	para[0] = VIRTIO_CRYPTO_HASH_SHA_256;
	para[1] = 32;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    &id2));

	/* MAC create (HMAC-SHA256). */
	para[0] = VIRTIO_CRYPTO_MAC_HMAC_SHA_256;
	para[1] = 32;
	para[2] = 20;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, key, 20,
	    NULL));

	/* AEAD create (AES-GCM). */
	para[0] = VIRTIO_CRYPTO_AEAD_GCM;
	para[1] = 16;
	para[2] = VTCRYPTO_GCM_TAGLEN;
	para[3] = 0;		/* aad_len */
	{
		uint32_t apara[5] = { VIRTIO_CRYPTO_AEAD_GCM, 16,
		    VTCRYPTO_GCM_TAGLEN, 0, VIRTIO_CRYPTO_OP_ENCRYPT };

		ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
		    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, apara, 5, UINT32_MAX,
		    key, 16, NULL));
	}
	ATF_CHECK_EQ(4u, sc->vcs_nsessions);

	/* Destroy the cipher session; wrong-service destroy is INVSESS. */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_INVSESS, control_destroy(sc,
	    VIRTIO_CRYPTO_HASH_DESTROY_SESSION, id));
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_destroy(sc,
	    VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION, id));
	ATF_CHECK(!sc->vcs_sessions[id].used);
	ATF_CHECK_EQ(3u, sc->vcs_nsessions);
	/* Destroying an already-freed id is INVSESS. */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_INVSESS, control_destroy(sc,
	    VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION, id));
	/* Out-of-range destroy id. */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_INVSESS, control_destroy(sc,
	    VIRTIO_CRYPTO_HASH_DESTROY_SESSION, 99999));
}

ATF_TC_WITHOUT_HEAD(session_rejects);
ATF_TC_BODY(session_rejects, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[4];
	uint8_t key[32];

	sc = make_device(NULL, "1");
	memset(key, 0x22, sizeof(key));

	/* Unsupported cipher algo. */
	para[0] = 99; para[1] = 16; para[2] = VIRTIO_CRYPTO_OP_ENCRYPT; para[3] = 0;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, NULL));

	/* Non-cipher op_type rejected. */
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING, key, 16, NULL));

	/* Bad key length. */
	para[1] = 17;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 17, NULL));

	/* Bad direction. */
	para[1] = 16; para[2] = 7;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, NULL));

	/* Hash bad algo / result len. */
	para[0] = 99; para[1] = 32;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    NULL));
	para[0] = VIRTIO_CRYPTO_HASH_SHA_256; para[1] = 20;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    NULL));

	/* MAC bad algo / zero key len. */
	para[0] = 99; para[1] = 32; para[2] = 20;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, key, 20,
	    NULL));
	para[0] = VIRTIO_CRYPTO_MAC_HMAC_SHA_256; para[2] = 0;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, key, 1,
	    NULL));

	/* AEAD bad algo. */
	{
		uint32_t apara[5] = { 99, 16, VTCRYPTO_GCM_TAGLEN, 0,
		    VIRTIO_CRYPTO_OP_ENCRYPT };

		ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_create(sc,
		    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, apara, 5, UINT32_MAX,
		    key, 16, NULL));
	}

	/* Unknown opcode -> NOTSUPP (reported via the 1-byte inhdr). */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, control_destroy(sc, 0x7f7f, 0));

	/* Session table exhaustion: maxsessions == 1. */
	para[0] = VIRTIO_CRYPTO_HASH_SHA_256; para[1] = 32;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    NULL));
	ATF_CHECK_EQ(VIRTIO_CRYPTO_ERR, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    NULL));
}

ATF_TC_WITHOUT_HEAD(control_malformed_chains);
ATF_TC_BODY(control_malformed_chains, tc)
{
	struct pci_vtcrypto_softc *sc;
	struct seg r[1], w[1];

	sc = make_device(NULL, NULL);

	/* No writable descriptor -> invalid chain, relchain 0. */
	memset(g_guest, 0, sizeof(g_guest));
	r[0].off = 0; r[0].len = 72;
	mock_set_chain(r, 1, NULL, 0, true);
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	ATF_CHECK_EQ(1, g_rel_calls);
	ATF_CHECK_EQ(0u, g_rel_len);

	/* Truncated request header. */
	r[0].off = 0; r[0].len = 8;
	w[0].off = 512; w[0].len = 16;
	mock_set_chain(r, 1, w, 1, true);
	g_rel_calls = 0;
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	ATF_CHECK_EQ(1, g_rel_calls);
	ATF_CHECK_EQ(0u, g_rel_len);

	/* getchain returns -1: loop breaks, endchains still called. */
	memset(&g_chain, 0, sizeof(g_chain));
	g_chain.n = -1;
	g_chain.ready = 1;
	g_end_calls = 0;
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	ATF_CHECK_EQ(1, g_end_calls);
}

ATF_TC_WITHOUT_HEAD(cipher_kat_roundtrip);
ATF_TC_BODY(cipher_kat_roundtrip, tc)
{
	/* NIST SP800-38A F.2.1/F.2.2, AES-128-CBC, first block. */
	struct pci_vtcrypto_softc *sc;
	uint8_t key[16], iv[16], pt[16], ct[16];
	uint32_t para[4];
	uint64_t enc_id, dec_id;
	struct seg r[3], w[2];
	uint8_t *out;

	sc = make_device(NULL, NULL);
	ATF_REQUIRE_EQ(16u, hexdecode("2b7e151628aed2a6abf7158809cf4f3c", key));
	ATF_REQUIRE_EQ(16u, hexdecode("000102030405060708090a0b0c0d0e0f", iv));
	ATF_REQUIRE_EQ(16u, hexdecode("6bc1bee22e409f96e93d7e117393172a", pt));
	ATF_REQUIRE_EQ(16u, hexdecode("7649abac8119b246cee98e9b12e9197d", ct));

	/* Encrypt session. */
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT;
	para[3] = 0;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &enc_id));

	/* Encrypt data request: hdr, iv, src (read); dst, inhdr (write). */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	st64(g_guest + 8, enc_id);
	st32(g_guest + 24, 16);		/* iv_len */
	st32(g_guest + 28, 16);		/* src_data_len */
	st32(g_guest + 32, 16);		/* dst_data_len */
	memcpy(g_guest + 72, iv, 16);
	memcpy(g_guest + 88, pt, 16);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 16;
	r[2].off = 88; r[2].len = 16;
	w[0].off = 1024; w[0].len = 16;
	w[1].off = 1040; w[1].len = 1;
	g_guest[1040] = 0xff;
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	out = g_guest + 1024;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[1040]);
	ATF_CHECK(memcmp(out, ct, 16) == 0);	/* KAT: independent vector */
	ATF_CHECK_EQ(17u, g_rel_len);

	/* Decrypt session over the known ciphertext yields plaintext. */
	para[2] = VIRTIO_CRYPTO_OP_DECRYPT;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &dec_id));
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_DECRYPT);
	st64(g_guest + 8, dec_id);
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 16);
	st32(g_guest + 32, 16);
	memcpy(g_guest + 72, iv, 16);
	memcpy(g_guest + 88, ct, 16);
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[1040]);
	ATF_CHECK(memcmp(g_guest + 1024, pt, 16) == 0);

	/* Direction mismatch: encrypt op against a decrypt session. */
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);
}

ATF_TC_WITHOUT_HEAD(hash_kat);
ATF_TC_BODY(hash_kat, tc)
{
	/* FIPS 180: SHA-256("abc"). */
	struct pci_vtcrypto_softc *sc;
	uint32_t para[2];
	uint64_t id;
	uint8_t expect[32];
	struct seg r[2], w[2];

	sc = make_device(NULL, NULL);
	ATF_REQUIRE_EQ(32u, hexdecode(
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	    expect));

	para[0] = VIRTIO_CRYPTO_HASH_SHA_256;
	para[1] = 32;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    &id));

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_HASH);
	st64(g_guest + 8, id);
	st32(g_guest + 24, 3);		/* src_data_len */
	st32(g_guest + 28, 32);		/* hash_result_len */
	memcpy(g_guest + 72, "abc", 3);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 3;
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[1056]);
	ATF_CHECK(memcmp(g_guest + 1024, expect, 32) == 0);
}

ATF_TC_WITHOUT_HEAD(mac_kat);
ATF_TC_BODY(mac_kat, tc)
{
	/* RFC 4231 Test Case 1: HMAC-SHA-256. */
	struct pci_vtcrypto_softc *sc;
	uint32_t para[3];
	uint64_t id;
	uint8_t key[20], expect[32];
	struct seg r[2], w[2];

	sc = make_device(NULL, NULL);
	memset(key, 0x0b, sizeof(key));
	ATF_REQUIRE_EQ(32u, hexdecode(
	    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
	    expect));

	para[0] = VIRTIO_CRYPTO_MAC_HMAC_SHA_256;
	para[1] = 32;
	para[2] = 20;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, key, 20,
	    &id));

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_MAC);
	st64(g_guest + 8, id);
	st32(g_guest + 24, 8);		/* "Hi There" */
	st32(g_guest + 28, 32);
	memcpy(g_guest + 72, "Hi There", 8);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 8;
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[1056]);
	ATF_CHECK(memcmp(g_guest + 1024, expect, 32) == 0);
}

ATF_TC_WITHOUT_HEAD(aead_kat);
ATF_TC_BODY(aead_kat, tc)
{
	/* McGrew/NIST GCM Test Case 3: AES-128-GCM, no AAD, 64-byte P. */
	struct pci_vtcrypto_softc *sc;
	uint32_t apara[5];
	uint64_t enc_id, dec_id;
	uint8_t key[16], iv[12], pt[64], ct[64], tag[16];
	struct seg r[4], w[2];

	sc = make_device(NULL, NULL);
	ATF_REQUIRE_EQ(16u, hexdecode("feffe9928665731c6d6a8f9467308308", key));
	ATF_REQUIRE_EQ(12u, hexdecode("cafebabefacedbaddecaf888", iv));
	ATF_REQUIRE_EQ(64u, hexdecode(
	    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
	    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
	    pt));
	ATF_REQUIRE_EQ(64u, hexdecode(
	    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
	    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
	    ct));
	ATF_REQUIRE_EQ(16u, hexdecode("4d5c2af327cd64a62cf35abd2ba6fab4", tag));

	/* Encrypt session. */
	apara[0] = VIRTIO_CRYPTO_AEAD_GCM;
	apara[1] = 16;
	apara[2] = VTCRYPTO_GCM_TAGLEN;
	apara[3] = 0;
	apara[4] = VIRTIO_CRYPTO_OP_ENCRYPT;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, apara, 5, UINT32_MAX, key, 16,
	    &enc_id));

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_AEAD_ENCRYPT);
	st64(g_guest + 8, enc_id);
	st32(g_guest + 24, 12);		/* iv_len */
	st32(g_guest + 28, 0);		/* aad_len */
	st32(g_guest + 32, 64);		/* src_data_len */
	st32(g_guest + 36, 80);		/* dst_data_len = ct + tag */
	memcpy(g_guest + 72, iv, 12);
	memcpy(g_guest + 84, pt, 64);	/* aad_len 0, so src right after iv */
	r[0].off = 0;   r[0].len = 72;
	r[1].off = 72;  r[1].len = 12;
	r[2].off = 84;  r[2].len = 0;	/* empty AAD segment */
	r[3].off = 84;  r[3].len = 64;
	w[0].off = 2048; w[0].len = 80;
	w[1].off = 2128; w[1].len = 1;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[2128]);
	ATF_CHECK(memcmp(g_guest + 2048, ct, 64) == 0);
	ATF_CHECK(memcmp(g_guest + 2048 + 64, tag, 16) == 0);

	/* Decrypt session over ciphertext+tag recovers plaintext. */
	apara[4] = VIRTIO_CRYPTO_OP_DECRYPT;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, apara, 5, UINT32_MAX, key, 16,
	    &dec_id));
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_AEAD_DECRYPT);
	st64(g_guest + 8, dec_id);
	st32(g_guest + 24, 12);
	st32(g_guest + 28, 0);
	st32(g_guest + 32, 80);		/* src = ct + tag */
	st32(g_guest + 36, 64);		/* dst = plaintext */
	memcpy(g_guest + 72, iv, 12);
	memcpy(g_guest + 84, ct, 64);
	memcpy(g_guest + 84 + 64, tag, 16);
	r[3].off = 84; r[3].len = 80;
	w[0].off = 2048; w[0].len = 64;
	w[1].off = 2112; w[1].len = 1;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[2112]);
	ATF_CHECK(memcmp(g_guest + 2048, pt, 64) == 0);

	/* Corrupt the tag: authentication must fail with BADMSG. */
	g_guest[84 + 64] ^= 0x01;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[2112]);
}

ATF_TC_WITHOUT_HEAD(data_malformed);
ATF_TC_BODY(data_malformed, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[4];
	uint8_t key[16];
	uint64_t id;
	struct seg r[3], w[2];

	sc = make_device(NULL, NULL);
	memset(key, 0x33, sizeof(key));
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT;
	para[3] = 0;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &id));

	/* Invalid session id -> INVSESS. */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	st64(g_guest + 8, 4242);
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 16);
	st32(g_guest + 32, 16);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 16;
	r[2].off = 88; r[2].len = 16;
	w[0].off = 1024; w[0].len = 16;
	w[1].off = 1040; w[1].len = 1;
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_INVSESS, g_guest[1040]);

	/* Bad iv_len -> BADMSG. */
	st64(g_guest + 8, id);
	st32(g_guest + 24, 12);		/* iv_len != 16 */
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);

	/* src_data_len not a multiple of block size -> ERR from EVP path. */
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 15);
	st32(g_guest + 32, 15);
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);

	/* Truncated data request header. */
	r[0].len = 8;
	mock_set_chain(r, 3, w, 2, true);
	g_rel_calls = 0;
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(1, g_rel_calls);
	ATF_CHECK_EQ(0u, g_rel_len);
	r[0].len = 72;

	/* Wrong-service data op against a cipher session -> INVSESS. */
	st32(g_guest + 0, VIRTIO_CRYPTO_HASH);
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 32);
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_INVSESS, g_guest[1040]);

	/* Unknown service in opcode -> NOTSUPP. */
	st32(g_guest + 0, VIRTIO_CRYPTO_OPCODE(7, 0));
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_NOTSUPP, g_guest[1040]);

	/* No writable descriptor at all -> invalid chain. */
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	mock_set_chain(r, 3, NULL, 0, true);
	g_rel_calls = 0;
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(1, g_rel_calls);
	ATF_CHECK_EQ(0u, g_rel_len);
}

ATF_TC_WITHOUT_HEAD(reset_frees_sessions);
ATF_TC_BODY(reset_frees_sessions, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[2];
	uint64_t id;

	sc = make_device(NULL, NULL);
	para[0] = VIRTIO_CRYPTO_HASH_SHA_256;
	para[1] = 32;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    &id));
	ATF_CHECK_EQ(1u, sc->vcs_nsessions);

	pci_vtcrypto_reset(sc);
	ATF_CHECK_EQ(0u, sc->vcs_nsessions);
	ATF_CHECK(!sc->vcs_sessions[id].used);
	ATF_CHECK_EQ(1, g_reset_dev_calls);

	/* Session slot is reusable after reset. */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    &id));
	ATF_CHECK_EQ(1u, sc->vcs_nsessions);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_restore);
ATF_TC_BODY(snapshot_save_restore, tc)
{
	struct pci_vtcrypto_softc *src, *dst, *bad;
	uint8_t image[65536], damaged[65536];
	uint32_t para[4];
	uint8_t key[16];
	uint64_t id;
	size_t used;

	src = make_device("2", "16");
	memset(key, 0x5a, sizeof(key));
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT;
	para[3] = 0;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(src,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &id));

	memset(image, 0, sizeof(image));
	ATF_REQUIRE_EQ(0, run_snap(src, image, sizeof(image), VM_SNAPSHOT_SAVE,
	    &used));
	ATF_REQUIRE(used > 16);

	/* Independent byte vector: magic then version, little-endian. */
	ATF_CHECK_EQ((uint8_t)(VTCRYPTO_SNAPSHOT_MAGIC & 0xff), image[0]);
	ATF_CHECK_EQ(1, image[4]);

	/* Restore into a fresh, identically-shaped destination. */
	dst = make_device("2", "16");
	ATF_REQUIRE_EQ(0, run_snap(dst, image, used, VM_SNAPSHOT_RESTORE, NULL));
	ATF_CHECK_EQ(1u, dst->vcs_nsessions);
	ATF_CHECK(dst->vcs_sessions[id].used);
	ATF_CHECK_EQ((uint32_t)VIRTIO_CRYPTO_SERVICE_CIPHER,
	    dst->vcs_sessions[id].service);
	ATF_CHECK_EQ(16u, dst->vcs_sessions[id].keylen);
	ATF_CHECK(memcmp(dst->vcs_sessions[id].key, key, 16) == 0);

	/* Validate op restores nothing but decodes the record. */
	ATF_CHECK_EQ(0, run_snap(dst, image, used, VM_SNAPSHOT_VALIDATE, NULL));

	/* Geometry mismatch is rejected. */
	bad = make_device("1", "16");
	ATF_CHECK_EQ(EINVAL, run_snap(bad, image, used, VM_SNAPSHOT_RESTORE,
	    NULL));

	/* Corrupted magic is rejected as unsupported. */
	memcpy(damaged, image, used);
	damaged[0] ^= 0xff;
	ATF_CHECK_EQ(ENOTSUP, run_snap(dst, damaged, used, VM_SNAPSHOT_RESTORE,
	    NULL));

	/*
	 * A corrupt serialized session count must not be trusted: the field
	 * (magic, version, ndataq, maxsessions, nsessions) puts nsessions at
	 * byte offset 16.  Restore recomputes the count from the used flags, so
	 * the bogus value is ignored and the true count (1) is recovered.
	 */
	{
		struct pci_vtcrypto_softc *dst2 = make_device("2", "16");

		memcpy(damaged, image, used);
		st32(damaged + 16, 0xdeadbeef);
		ATF_CHECK_EQ(0, run_snap(dst2, damaged, used,
		    VM_SNAPSHOT_RESTORE, NULL));
		ATF_CHECK_EQ(1u, dst2->vcs_nsessions);
		ATF_CHECK(dst2->vcs_sessions[id].used);
	}

	/* A too-small save buffer fails once it runs out of room. */
	ATF_CHECK(run_snap(src, image, 4, VM_SNAPSHOT_SAVE, NULL) != 0);
}

/* One-block AES-CBC KAT for a given key length (NIST SP800-38A). */
static void
cbc_block_kat(struct pci_vtcrypto_softc *sc, const char *keyhex,
    const char *ivhex, const char *pthex, const char *cthex)
{
	uint8_t key[32], iv[16], pt[16], ct[16];
	size_t keylen;
	uint32_t para[4];
	uint64_t id;
	struct seg r[3], w[2];

	keylen = hexdecode(keyhex, key);
	ATF_REQUIRE_EQ(16u, hexdecode(ivhex, iv));
	ATF_REQUIRE_EQ(16u, hexdecode(pthex, pt));
	ATF_REQUIRE_EQ(16u, hexdecode(cthex, ct));

	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC;
	para[1] = keylen;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT;
	para[3] = 0;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, keylen, &id));

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	st64(g_guest + 8, id);
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 16);
	st32(g_guest + 32, 16);
	memcpy(g_guest + 72, iv, 16);
	memcpy(g_guest + 88, pt, 16);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 16;
	r[2].off = 88; r[2].len = 16;
	w[0].off = 1024; w[0].len = 16;
	w[1].off = 1040; w[1].len = 1;
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[1040]);
	ATF_CHECK(memcmp(g_guest + 1024, ct, 16) == 0);
}

ATF_TC_WITHOUT_HEAD(cipher_kat_aes192_aes256);
ATF_TC_BODY(cipher_kat_aes192_aes256, tc)
{
	struct pci_vtcrypto_softc *sc = make_device(NULL, NULL);

	/* NIST SP800-38A F.2.3 AES-192-CBC, first block. */
	cbc_block_kat(sc,
	    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	    "000102030405060708090a0b0c0d0e0f",
	    "6bc1bee22e409f96e93d7e117393172a",
	    "4f021db243bc633d7178183a9fa071e8");
	/* NIST SP800-38A F.2.5 AES-256-CBC, first block. */
	cbc_block_kat(sc,
	    "603deb1015ca71be2b73aef0857d7781"
	    "1f352c073b6108d72d9810a30914dff4",
	    "000102030405060708090a0b0c0d0e0f",
	    "6bc1bee22e409f96e93d7e117393172a",
	    "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
}

ATF_TC_WITHOUT_HEAD(aead_kat_with_aad);
ATF_TC_BODY(aead_kat_with_aad, tc)
{
	/* McGrew/NIST GCM Test Case 4: AES-128-GCM, 20-byte AAD, 60-byte P. */
	struct pci_vtcrypto_softc *sc;
	uint32_t apara[5];
	uint64_t id;
	uint8_t key[16], iv[12], aad[20], pt[60], ct[60], tag[16];
	struct seg r[4], w[2];

	sc = make_device(NULL, NULL);
	ATF_REQUIRE_EQ(16u, hexdecode("feffe9928665731c6d6a8f9467308308", key));
	ATF_REQUIRE_EQ(12u, hexdecode("cafebabefacedbaddecaf888", iv));
	ATF_REQUIRE_EQ(20u, hexdecode(
	    "feedfacedeadbeeffeedfacedeadbeefabaddad2", aad));
	ATF_REQUIRE_EQ(60u, hexdecode(
	    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
	    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt));
	ATF_REQUIRE_EQ(60u, hexdecode(
	    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
	    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", ct));
	ATF_REQUIRE_EQ(16u, hexdecode("5bc94fbc3221a5db94fae95ae7121a47", tag));

	apara[0] = VIRTIO_CRYPTO_AEAD_GCM;
	apara[1] = 16;
	apara[2] = VTCRYPTO_GCM_TAGLEN;
	apara[3] = 20;
	apara[4] = VIRTIO_CRYPTO_OP_ENCRYPT;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, apara, 5, UINT32_MAX, key, 16,
	    &id));

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_AEAD_ENCRYPT);
	st64(g_guest + 8, id);
	st32(g_guest + 24, 12);		/* iv_len */
	st32(g_guest + 28, 20);		/* aad_len */
	st32(g_guest + 32, 60);		/* src_data_len */
	st32(g_guest + 36, 76);		/* dst_data_len = ct + tag */
	memcpy(g_guest + 72, iv, 12);
	memcpy(g_guest + 84, aad, 20);
	memcpy(g_guest + 104, pt, 60);
	r[0].off = 0;   r[0].len = 72;
	r[1].off = 72;  r[1].len = 12;
	r[2].off = 84;  r[2].len = 20;
	r[3].off = 104; r[3].len = 60;
	w[0].off = 2048; w[0].len = 76;
	w[1].off = 2124; w[1].len = 1;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_OK, g_guest[2124]);
	ATF_CHECK(memcmp(g_guest + 2048, ct, 60) == 0);
	ATF_CHECK(memcmp(g_guest + 2048 + 60, tag, 16) == 0);
}

/* Build a raw control-create chain with an explicit (possibly short) key. */
static uint32_t
raw_control_create(struct pci_vtcrypto_softc *sc, uint32_t opcode,
    const uint32_t *para, size_t npara, uint32_t op_type_at64,
    size_t keyseglen, size_t winlen)
{
	struct seg r[2], w[1];

	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, opcode);
	for (size_t i = 0; i < npara; i++)
		st32(g_guest + 16 + i * 4, para[i]);
	if (op_type_at64 != UINT32_MAX)
		st32(g_guest + 64, op_type_at64);
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = keyseglen;
	w[0].off = 512; w[0].len = winlen;
	st32(g_guest + 512 + 8, 0xdead);
	mock_set_chain(r, keyseglen > 0 ? 2 : 1, w, 1, true);
	g_rel_calls = 0;
	pci_vtcrypto_controlq_notify(sc, &sc->vcs_vq[sc->vcs_ndataq]);
	return (ld32(g_guest + 512 + 8));
}

ATF_TC_WITHOUT_HEAD(edge_failures);
ATF_TC_BODY(edge_failures, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[5];
	uint64_t cid, aid;
	uint8_t key[16];
	struct seg r[4], w[2];

	sc = make_device(NULL, "32");
	memset(key, 0x44, sizeof(key));

	/* Control create key-pull failure: header claims 16, only 8 supplied. */
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC; para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT; para[3] = 0;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, 8, 16));

	/* MAC key-pull failure. */
	para[0] = VIRTIO_CRYPTO_MAC_HMAC_SHA_256; para[1] = 32; para[2] = 20;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, 8, 16));

	/* AEAD key-pull failure, and AEAD reject branches. */
	para[0] = VIRTIO_CRYPTO_AEAD_GCM; para[1] = 16;
	para[2] = VTCRYPTO_GCM_TAGLEN; para[3] = 0;
	para[4] = VIRTIO_CRYPTO_OP_ENCRYPT;
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, para, 5, UINT32_MAX, 8, 16));
	para[4] = 9;	/* bad direction */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, para, 5, UINT32_MAX, 16, 16));
	para[4] = VIRTIO_CRYPTO_OP_ENCRYPT; para[1] = 17;	/* bad keylen */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, para, 5, UINT32_MAX, 17, 16));
	para[1] = 16; para[2] = 12;	/* bad result_len */
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, raw_control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, para, 5, UINT32_MAX, 16, 16));

	/*
	 * Control create writable too small for session_input -> push fail.
	 * The created session must be rolled back rather than leaked: the guest
	 * never learned the id, so a retained slot would be unreclaimable and a
	 * malicious guest could exhaust the table this way.
	 */
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC; para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT; para[3] = 0;
	ATF_CHECK_EQ(0u, sc->vcs_nsessions);
	raw_control_create(sc, VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, 16, 8);
	ATF_CHECK_EQ(1, g_rel_calls);
	ATF_CHECK_EQ(0u, g_rel_len);
	ATF_CHECK_EQ(0u, sc->vcs_nsessions);	/* no leak */
	/* Repeating the undersized create must not accumulate sessions. */
	raw_control_create(sc, VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, 16, 8);
	ATF_CHECK_EQ(0u, sc->vcs_nsessions);

	/* Establish a real encrypt cipher session for data-path edge cases. */
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &cid));

	/* Cipher IV-pull failure: no IV segment. */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_CIPHER_ENCRYPT);
	st64(g_guest + 8, cid);
	st32(g_guest + 24, 16);
	st32(g_guest + 28, 16);
	st32(g_guest + 32, 16);
	r[0].off = 0; r[0].len = 72;
	w[0].off = 1024; w[0].len = 16;
	w[1].off = 1040; w[1].len = 1;
	mock_set_chain(r, 1, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);

	/* Cipher src-pull failure: IV present, no src segment. */
	r[1].off = 72; r[1].len = 16;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);

	/* Cipher dst-push failure: writable too small for dst_data_len. */
	memcpy(g_guest + 88, key, 16);	/* any 16-byte src */
	r[2].off = 88; r[2].len = 16;
	w[0].off = 1024; w[0].len = 8;	/* < dst_data_len (16) */
	w[1].off = 1032; w[1].len = 1;
	mock_set_chain(r, 3, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1032]);

	/* AEAD encrypt with wrong dst_len and decrypt with too-short src. */
	para[0] = VIRTIO_CRYPTO_AEAD_GCM; para[1] = 16;
	para[2] = VTCRYPTO_GCM_TAGLEN; para[3] = 0;
	para[4] = VIRTIO_CRYPTO_OP_ENCRYPT;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_AEAD_CREATE_SESSION, para, 5, UINT32_MAX, key, 16,
	    &aid));
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_AEAD_ENCRYPT);
	st64(g_guest + 8, aid);
	st32(g_guest + 24, 12);
	st32(g_guest + 28, 0);
	st32(g_guest + 32, 16);
	st32(g_guest + 36, 16);		/* wrong: should be 16 + tag */
	r[0].off = 0;  r[0].len = 72;
	r[1].off = 72; r[1].len = 12;
	r[2].off = 84; r[2].len = 0;
	r[3].off = 84; r[3].len = 16;
	w[0].off = 2048; w[0].len = 16;
	w[1].off = 2064; w[1].len = 1;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[2064]);

	/* AEAD IV-pull failure. */
	r[1].off = 72; r[1].len = 0;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[2064]);

	/*
	 * AEAD oversize dst_len is rejected as BADMSG *before* any allocation
	 * keyed on it, so a guest cannot request a multi-gigabyte host malloc.
	 */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_AEAD_ENCRYPT);
	st64(g_guest + 8, aid);
	st32(g_guest + 24, 12);
	st32(g_guest + 28, 0);
	st32(g_guest + 32, 16);
	st32(g_guest + 36, VTCRYPTO_MAX_DATALEN + VTCRYPTO_GCM_TAGLEN + 1);
	r[1].off = 72; r[1].len = 12;
	r[2].off = 84; r[2].len = 0;
	r[3].off = 84; r[3].len = 16;
	w[0].off = 2048; w[0].len = 16;
	w[1].off = 2064; w[1].len = 1;
	mock_set_chain(r, 4, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[2064]);
}

ATF_TC_WITHOUT_HEAD(hash_mac_edge);
ATF_TC_BODY(hash_mac_edge, tc)
{
	struct pci_vtcrypto_softc *sc;
	uint32_t para[3];
	uint64_t hid, mid;
	uint8_t key[20];
	struct seg r[2], w[2];

	sc = make_device(NULL, NULL);
	memset(key, 0x0b, sizeof(key));

	para[0] = VIRTIO_CRYPTO_HASH_SHA_256; para[1] = 32;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_HASH_CREATE_SESSION, para, 2, UINT32_MAX, NULL, 0,
	    &hid));

	/* Hash src-pull failure: header claims 8 bytes, no src segment. */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_HASH);
	st64(g_guest + 8, hid);
	st32(g_guest + 24, 8);
	st32(g_guest + 28, 32);
	r[0].off = 0; r[0].len = 72;
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 1, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1056]);

	/* Hash result-push failure: writable too small. */
	st32(g_guest + 24, 3);
	memcpy(g_guest + 72, "abc", 3);
	r[0].off = 0; r[0].len = 72;
	r[1].off = 72; r[1].len = 3;
	w[0].off = 1024; w[0].len = 16;	/* < 32 */
	w[1].off = 1040; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);

	/* Hash bad result_len -> BADMSG before hashing. */
	st32(g_guest + 24, 3);
	st32(g_guest + 28, 20);
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1056]);
	st32(g_guest + 28, 32);

	para[0] = VIRTIO_CRYPTO_MAC_HMAC_SHA_256; para[1] = 32; para[2] = 20;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_MAC_CREATE_SESSION, para, 3, UINT32_MAX, key, 20,
	    &mid));

	/* MAC src-pull failure. */
	memset(g_guest, 0, sizeof(g_guest));
	st32(g_guest + 0, VIRTIO_CRYPTO_MAC);
	st64(g_guest + 8, mid);
	st32(g_guest + 24, 8);
	st32(g_guest + 28, 32);
	r[0].off = 0; r[0].len = 72;
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 1, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1056]);

	/* MAC result-push failure and bad result_len. */
	memcpy(g_guest + 72, "Hi There", 8);
	r[1].off = 72; r[1].len = 8;
	w[0].off = 1024; w[0].len = 16;
	w[1].off = 1040; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1040]);
	st32(g_guest + 28, 20);
	w[0].off = 1024; w[0].len = 32;
	w[1].off = 1056; w[1].len = 1;
	mock_set_chain(r, 2, w, 2, true);
	pci_vtcrypto_dataq_notify(sc, &sc->vcs_vq[0]);
	ATF_CHECK_EQ(VIRTIO_CRYPTO_BADMSG, g_guest[1056]);
}

ATF_TC_WITHOUT_HEAD(misc_paths);
ATF_TC_BODY(misc_paths, tc)
{
	struct pci_vtcrypto_softc sc0;
	struct pci_vtcrypto_softc *sc;
	uint8_t image[65536], damaged[65536];
	uint32_t para[4];
	uint8_t key[16];
	uint64_t id;
	size_t used;

	/* reset() with a NULL session table and no mutex is a safe no-op. */
	memset(&sc0, 0, sizeof(sc0));
	sc0.vcs_vs.vs_vc = &sc0.vcs_consts;
	g_reset_dev_calls = 0;
	pci_vtcrypto_reset(&sc0);
	ATF_CHECK_EQ(1, g_reset_dev_calls);

	/* init honours the debug environment variable. */
	{
		struct pci_devinst pi;

		memset(&pi, 0, sizeof(pi));
		reset_mocks();
		setenv("BHYVE_VTCRYPTO_DEBUG", "2", 1);
		ATF_REQUIRE_EQ(0, pci_vtcrypto_init(&pi, NULL));
		ATF_CHECK(pci_vtcrypto_debug > 0);
		pci_vtcrypto_debug = 0;
		unsetenv("BHYVE_VTCRYPTO_DEBUG");
		sc = pi.pi_arg;
		pthread_mutex_destroy(&sc->vcs_mtx);
		free(sc->vcs_sessions);
		free(sc);
	}

	/* Snapshot restore rejects a record whose keylen exceeds the cap. */
	sc = make_device("1", "16");
	memset(key, 0x5a, sizeof(key));
	para[0] = VIRTIO_CRYPTO_CIPHER_AES_CBC; para[1] = 16;
	para[2] = VIRTIO_CRYPTO_OP_ENCRYPT; para[3] = 0;
	ATF_REQUIRE_EQ(VIRTIO_CRYPTO_OK, control_create(sc,
	    VIRTIO_CRYPTO_CIPHER_CREATE_SESSION, para, 4,
	    VIRTIO_CRYPTO_SYM_OP_CIPHER, key, 16, &id));
	memset(image, 0, sizeof(image));
	ATF_REQUIRE_EQ(0, run_snap(sc, image, sizeof(image), VM_SNAPSHOT_SAVE,
	    &used));
	memcpy(damaged, image, used);
	/* Header is 20 bytes; slot 0 keylen field is at offset 20+1+4+4+4. */
	st32(damaged + 33, 999);
	ATF_CHECK_EQ(EINVAL, run_snap(sc, damaged, used, VM_SNAPSHOT_RESTORE,
	    NULL));
}

/*
 * Layout contract: the production struct virtio_crypto_config must match the
 * document-derived VirtIO 1.x spec 5.9.4 oracle offsets bit-for-bit.  This is
 * the one body permitted to assert offsetof(production) == VIRTIO14 oracle.
 */
ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_crypto_config),
	    VIRTIO14_CRYPTO_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, status),
	    VIRTIO14_CRYPTO_CONFIG_STATUS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, max_dataqueues),
	    VIRTIO14_CRYPTO_CONFIG_MAX_DATAQUEUES_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, crypto_services),
	    VIRTIO14_CRYPTO_CONFIG_CRYPTO_SERVICES_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, cipher_algo_l),
	    VIRTIO14_CRYPTO_CONFIG_CIPHER_ALGO_L_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, cipher_algo_h),
	    VIRTIO14_CRYPTO_CONFIG_CIPHER_ALGO_H_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, hash_algo),
	    VIRTIO14_CRYPTO_CONFIG_HASH_ALGO_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, mac_algo_l),
	    VIRTIO14_CRYPTO_CONFIG_MAC_ALGO_L_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, mac_algo_h),
	    VIRTIO14_CRYPTO_CONFIG_MAC_ALGO_H_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, aead_algo),
	    VIRTIO14_CRYPTO_CONFIG_AEAD_ALGO_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, max_cipher_key_len),
	    VIRTIO14_CRYPTO_CONFIG_MAX_CIPHER_KEY_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, max_auth_key_len),
	    VIRTIO14_CRYPTO_CONFIG_MAX_AUTH_KEY_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, akcipher_algo),
	    VIRTIO14_CRYPTO_CONFIG_AKCIPHER_ALGO_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_crypto_config, max_size),
	    VIRTIO14_CRYPTO_CONFIG_MAX_SIZE_OFF);
	ATF_CHECK_EQ(sizeof(((struct virtio_crypto_config *)0)->max_size),
	    VIRTIO14_CRYPTO_CONFIG_MAX_SIZE_SIZE);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, config_space);
	ATF_TP_ADD_TC(tp, init_and_failures);
	ATF_TP_ADD_TC(tp, session_lifecycle);
	ATF_TP_ADD_TC(tp, session_rejects);
	ATF_TP_ADD_TC(tp, control_malformed_chains);
	ATF_TP_ADD_TC(tp, cipher_kat_roundtrip);
	ATF_TP_ADD_TC(tp, hash_kat);
	ATF_TP_ADD_TC(tp, mac_kat);
	ATF_TP_ADD_TC(tp, aead_kat);
	ATF_TP_ADD_TC(tp, data_malformed);
	ATF_TP_ADD_TC(tp, reset_frees_sessions);
	ATF_TP_ADD_TC(tp, snapshot_save_restore);
	ATF_TP_ADD_TC(tp, cipher_kat_aes192_aes256);
	ATF_TP_ADD_TC(tp, aead_kat_with_aad);
	ATF_TP_ADD_TC(tp, edge_failures);
	ATF_TP_ADD_TC(tp, hash_mac_edge);
	ATF_TP_ADD_TC(tp, misc_paths);
	return (atf_no_error());
}

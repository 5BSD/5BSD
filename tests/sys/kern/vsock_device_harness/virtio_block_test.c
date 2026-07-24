/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fault-injection tests for bhyve's VirtIO block device.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"
#include "pci_virtio_block.c"

/* Keep test protocol values independent from the included implementation. */
#undef VBH_OP_READ
#define	VBH_OP_READ			VIRTIO14_BLK_T_IN
#undef VBH_OP_WRITE
#define	VBH_OP_WRITE			VIRTIO14_BLK_T_OUT
#undef VBH_OP_FLUSH
#define	VBH_OP_FLUSH			VIRTIO14_BLK_T_FLUSH
#undef VBH_OP_IDENT
#define	VBH_OP_IDENT			VIRTIO14_BLK_T_GET_ID
#undef VBH_OP_DISCARD
#define	VBH_OP_DISCARD			VIRTIO14_BLK_T_DISCARD
#undef VBH_OP_WRITE_ZEROES
#define	VBH_OP_WRITE_ZEROES		VIRTIO14_BLK_T_WRITE_ZEROES
#undef VBH_FLAG_BARRIER
#define	VBH_FLAG_BARRIER		VIRTIO14_BLK_T_BARRIER
#undef VTBLK_S_OK
#define	VTBLK_S_OK			VIRTIO14_BLK_S_OK
#undef VTBLK_S_IOERR
#define	VTBLK_S_IOERR			VIRTIO14_BLK_S_IOERR
#undef VTBLK_S_UNSUPP
#define	VTBLK_S_UNSUPP			VIRTIO14_BLK_S_UNSUPP
#undef VTBLK_BLK_ID_LEN
#define	VTBLK_BLK_ID_LEN		VIRTIO14_BLK_ID_BYTES
#undef VTBLK_BSIZE
#define	VTBLK_BSIZE			VIRTIO14_BLK_SECTOR_BYTES
#undef VTBLK_F_RO
#define	VTBLK_F_RO			VIRTIO14_BLK_F_RO
#undef VTBLK_F_FLUSH
#define	VTBLK_F_FLUSH			VIRTIO14_BLK_F_FLUSH
#undef VTBLK_F_DISCARD
#define	VTBLK_F_DISCARD			VIRTIO14_BLK_F_DISCARD
#undef VTBLK_F_WRITE_ZEROES
#define	VTBLK_F_WRITE_ZEROES		VIRTIO14_BLK_F_WRITE_ZEROES
#undef VTBLK_WRITE_ZEROES_FLAG_UNMAP
#define	VTBLK_WRITE_ZEROES_FLAG_UNMAP \
	VIRTIO14_BLK_WRITE_ZEROES_FLAG_UNMAP
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET

struct blockif_ctxt {
	int unused;
};

static struct iovec g_iov[BLOCKIF_IOV_MAX + 2];
static struct vi_req g_req;
static int g_chain_n;
static int g_backend_error;
static int g_backend_reads;
static int g_backend_writes;
static int g_backend_write_zeroes;
static int g_backend_flushes;
static int g_backend_deletes;
static int g_backend_readonly;
static int g_backend_candelete;
static int g_cancel_calls;
static int g_cancel_error;
static int g_cancel_saw_unlocked;
static int g_rel_calls;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_reset_calls;
static int g_needs_reset_calls;
static int g_config_changes;
static int g_qreset_complete_calls;
static uint64_t g_qreset_complete_generation;
static int g_qreset_complete_error;

static struct virtio_blk_hdr g_header;
static struct virtio_blk_discard_write_zeroes g_discard;
static uint8_t g_data[VTBLK_BSIZE];
static uint8_t g_status;

static void *
complete_block_request(void *arg)
{
	struct pci_vtblk_ioreq *io;

	io = arg;
	pci_vtblk_done(&io->io_req, 0);
	return (NULL);
}

struct full_reset_ctx {
	struct pci_vtblk_softc *sc;
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	bool entered;
};

static void *
run_full_reset(void *arg)
{
	struct full_reset_ctx *ctx;

	ctx = arg;
	if (pthread_mutex_lock(&ctx->sc->vsc_mtx) != 0)
		return ((void *)(uintptr_t)1);
	if (pthread_mutex_lock(&ctx->mtx) != 0)
		return ((void *)(uintptr_t)2);
	ctx->entered = true;
	if (pthread_cond_broadcast(&ctx->cv) != 0)
		return ((void *)(uintptr_t)3);
	if (pthread_mutex_unlock(&ctx->mtx) != 0)
		return ((void *)(uintptr_t)4);
	pci_vtblk_reset(ctx->sc);
	if (pthread_mutex_unlock(&ctx->sc->vsc_mtx) != 0)
		return ((void *)(uintptr_t)5);
	return (NULL);
}

static void
reset_mocks(void)
{

	memset(g_iov, 0, sizeof(g_iov));
	memset(&g_req, 0, sizeof(g_req));
	memset(&g_header, 0, sizeof(g_header));
	memset(&g_discard, 0, sizeof(g_discard));
	memset(g_data, 0, sizeof(g_data));
	g_status = UINT8_MAX;
	g_chain_n = 3;
	g_req.idx = 7;
	g_req.readable = 1;
	g_req.writable = 2;
	g_req.ordered = true;
	g_iov[0].iov_base = &g_header;
	g_iov[0].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE;
	g_iov[1].iov_base = g_data;
	g_iov[1].iov_len = sizeof(g_data);
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = VIRTIO14_BLK_STATUS_SIZE;
	g_backend_error = 0;
	g_backend_reads = 0;
	g_backend_writes = 0;
	g_backend_write_zeroes = 0;
	g_backend_flushes = 0;
	g_backend_deletes = 0;
	g_backend_readonly = 0;
	g_backend_candelete = 0;
	g_cancel_calls = 0;
	g_cancel_error = 0;
	g_cancel_saw_unlocked = 0;
	g_rel_calls = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_reset_calls = 0;
	g_needs_reset_calls = 0;
	g_config_changes = 0;
	g_qreset_complete_calls = 0;
	g_qreset_complete_generation = 0;
	g_qreset_complete_error = 0;
}

static void
setup_softc(struct pci_vtblk_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
	sc->vbsc_cfg.vbc_capacity = 1024;
	for (int i = 0; i < VTBLK_RINGSZ; i++) {
		sc->vbsc_ios[i].io_sc = sc;
		sc->vbsc_ios[i].io_idx = i;
		sc->vbsc_ios[i].io_req.br_param = &sc->vbsc_ios[i];
	}
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{

	*req = g_req;
	if (g_chain_n > 0)
		memcpy(iov, g_iov,
		    MIN(g_chain_n, niov) * sizeof(g_iov[0]));
	return (g_chain_n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	ATF_CHECK(idx == g_req.idx);
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{

	g_end_calls++;
}

int
blockif_read(struct blockif_ctxt *bc __unused, struct blockif_req *req __unused)
{

	g_backend_reads++;
	return (g_backend_error);
}

int
blockif_write(struct blockif_ctxt *bc __unused, struct blockif_req *req __unused)
{

	g_backend_writes++;
	return (g_backend_error);
}

int
blockif_write_zeroes(struct blockif_ctxt *bc __unused,
    struct blockif_req *req __unused)
{

	g_backend_write_zeroes++;
	return (g_backend_error);
}

int
blockif_flush(struct blockif_ctxt *bc __unused, struct blockif_req *req __unused)
{

	g_backend_flushes++;
	return (g_backend_error);
}

int
blockif_delete(struct blockif_ctxt *bc __unused, struct blockif_req *req __unused)
{

	g_backend_deletes++;
	return (g_backend_error);
}

int
blockif_is_ro(struct blockif_ctxt *bc __unused)
{

	return (g_backend_readonly);
}

int
blockif_candelete(struct blockif_ctxt *bc __unused)
{

	return (g_backend_candelete);
}

int
blockif_cancel(struct blockif_ctxt *bc __unused,
    struct blockif_req *req)
{
	struct pci_vtblk_ioreq *io;

	g_cancel_calls++;
	io = req->br_param;
	if (pthread_mutex_trylock(&io->io_sc->vsc_mtx) == 0) {
		g_cancel_saw_unlocked++;
		pthread_mutex_unlock(&io->io_sc->vsc_mtx);
	}
	return (g_cancel_error);
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{

	g_reset_calls++;
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	g_needs_reset_calls++;
}

void
vi_pci_config_changed(struct virtio_softc *vs __unused)
{

	g_config_changes++;
}

void
vi_pci_modern_queue_reset_complete(struct vqueue_info *vq __unused,
    uint64_t generation, int error)
{

	g_qreset_complete_calls++;
	g_qreset_complete_generation = generation;
	g_qreset_complete_error = error;
}

ATF_TC_WITHOUT_HEAD(malformed_chains);
ATF_TC_BODY(malformed_chains, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_iov[0].iov_len--;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);

	reset_mocks();
	setup_softc(&sc);
	g_req.ordered = false;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == UINT8_MAX);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = BLOCKIF_IOV_MAX + 3;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = -1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_rel_calls == 0);
}

ATF_TC_WITHOUT_HEAD(opcode_layouts);
ATF_TC_BODY(opcode_layouts, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 1);
	ATF_CHECK(g_rel_calls == 0);
	sc.vbsc_ios[g_req.idx].io_req.br_resid = 0;
	pci_vtblk_done_locked(&sc.vbsc_ios[g_req.idx], 0);
	ATF_CHECK(g_status == VTBLK_S_OK);
	ATF_CHECK(g_rel_calls == 1);
	ATF_CHECK(g_rel_len == sizeof(g_data) + 1);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_writes == 1);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_FLUSH);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_flushes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = 1;
	g_header.vbh_type = htole32(0x7fffffff);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);

	reset_mocks();
	setup_softc(&sc);
	memcpy(sc.vbsc_ident, "block-identity", sizeof("block-identity") - 1);
	g_header.vbh_type = htole32(VBH_OP_IDENT);
	g_iov[1].iov_len = VTBLK_BLK_ID_LEN;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_OK);
	ATF_CHECK(g_rel_len == VTBLK_BLK_ID_LEN + 1);
	ATF_CHECK(memcmp(g_data, "block-identity",
	    sizeof("block-identity") - 1) == 0);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ | VBH_FLAG_BARRIER);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);
}

ATF_TC_WITHOUT_HEAD(split_request_fields);
ATF_TC_BODY(split_request_fields, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;
	uint8_t header_bytes[VIRTIO14_BLK_REQUEST_HEADER_SIZE];
	uint8_t writable[sizeof(g_data) + 1];

	/*
	 * Split the request header between two readable descriptors and place
	 * the read data plus its trailing status byte in one writable
	 * descriptor.  Protocol fields are byte ranges in the descriptor
	 * chain, not descriptor-boundary requirements.
	 */
	reset_mocks();
	setup_softc(&sc);
	memset(header_bytes, 0, sizeof(header_bytes));
	virtio14_store_le32(header_bytes + VIRTIO14_BLK_REQUEST_TYPE_OFF,
	    VIRTIO14_BLK_T_IN);
	memset(writable, 0xa5, sizeof(writable));
	g_chain_n = 3;
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[0].iov_base = header_bytes;
	g_iov[0].iov_len = 5;
	g_iov[1].iov_base = header_bytes + 5;
	g_iov[1].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE - 5;
	g_iov[2].iov_base = writable;
	g_iov[2].iov_len = sizeof(writable);

	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_reads, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_iovcnt, 1);
	ATF_CHECK_EQ(io->io_req.br_iov[0].iov_len, sizeof(g_data));
	ATF_CHECK(io->io_req.br_iov[0].iov_base == writable);
	ATF_CHECK(io->io_status == &writable[sizeof(g_data)]);
	io->io_req.br_resid = 0;
	pci_vtblk_done_locked(io, 0);
	ATF_CHECK_EQ(writable[sizeof(g_data)], VTBLK_S_OK);
	ATF_CHECK_EQ(g_rel_len, sizeof(g_data) + 1);

	/* An invalid request still writes status at the final writable byte. */
	reset_mocks();
	setup_softc(&sc);
	g_chain_n = 2;
	g_req.readable = 1;
	g_req.writable = 1;
	g_iov[0].iov_base = header_bytes;
	g_iov[0].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE - 1;
	g_iov[1].iov_base = writable;
	g_iov[1].iov_len = sizeof(writable);
	writable[0] = 0x5a;
	writable[sizeof(writable) - 1] = UINT8_MAX;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(writable[0], 0x5a);
	ATF_CHECK_EQ(writable[sizeof(writable) - 1], VTBLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);

	/*
	 * Section 2.7 does not require a descriptor to have nonzero length.
	 * The status is the final byte of the writable buffer, so a trailing
	 * zero-length descriptor must not move it outside guest memory.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VIRTIO14_BLK_T_IN);
	g_chain_n = 4;
	g_req.readable = 1;
	g_req.writable = 3;
	g_iov[1].iov_base = writable;
	g_iov[1].iov_len = VIRTIO14_BLK_SECTOR_BYTES;
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = 1;
	g_iov[3].iov_base = NULL;
	g_iov[3].iov_len = 0;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_reads, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK(io->io_status == &g_status);
	io->io_req.br_resid = 0;
	pci_vtblk_done_locked(io, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_OK);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_BLK_SECTOR_BYTES + 1);

	/* The invalid-chain completion path follows the same rule. */
	reset_mocks();
	setup_softc(&sc);
	g_chain_n = 3;
	g_req.readable = 1;
	g_req.writable = 2;
	g_iov[0].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE - 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = 1;
	g_iov[2].iov_base = NULL;
	g_iov[2].iov_len = 0;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);
}

ATF_TC_WITHOUT_HEAD(backend_and_range_errors);
ATF_TC_BODY(backend_and_range_errors, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_backend_error = E2BIG;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 1);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_header.vbh_sector = htole64((uint64_t)OFF_MAX / VTBLK_BSIZE + 1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_iov[1].iov_len = VTBLK_BSIZE - 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_cfg.vbc_capacity = 8;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_header.vbh_sector = htole64(7);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_len = 2 * VTBLK_BSIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_writes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_FLUSH);
	g_header.vbh_sector = htole64(1);
	g_chain_n = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_flushes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_IDENT);
	g_iov[1].iov_len = VTBLK_BLK_ID_LEN - 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
}

ATF_TC_WITHOUT_HEAD(discard_validation);
ATF_TC_BODY(discard_validation, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_DISCARD;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(8);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_deletes == 1);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_DISCARD;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.flags = htole32(1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_cfg.vbc_capacity = 8;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_DISCARD;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.sector = htole64(7);
	g_discard.num_sectors = htole32(2);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
}

ATF_TC_WITHOUT_HEAD(write_zeroes_validation);
ATF_TC_BODY(write_zeroes_validation, tc)
{
	struct pci_vtblk_ioreq *io;
	struct pci_vtblk_softc sc;
	struct virtio_blk_discard_write_zeroes ranges[2];

	/* The opcode is unavailable until its independently defined bit is set. */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(8);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_UNSUPP);

	/* One bounded range is translated into an asynchronous backend request. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.sector = htole64(5);
	g_discard.num_sectors = htole32(7);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_write_zeroes, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_offset,
	    5 * VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK_EQ(io->io_req.br_resid,
	    7 * VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK(io->io_full_transfer);
	ATF_CHECK(io->io_is_write);
	ATF_CHECK_EQ(g_rel_calls, 0);

	/*
	 * UNMAP is a valid WRITE ZEROES flag.  The implementation may ignore
	 * the deallocation permission and still write real zeroes.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(1);
	g_discard.flags = htole32(VIRTIO14_BLK_WRITE_ZEROES_FLAG_UNMAP);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 1);

	/* Any flag other than the document-defined UNMAP bit is UNSUPP. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(1);
	g_discard.flags = htole32(
	    VIRTIO14_BLK_WRITE_ZEROES_FLAG_UNMAP << 1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_UNSUPP);

	/* The advertised one-segment limit is enforced defensively. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	memset(ranges, 0, sizeof(ranges));
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = ranges;
	g_iov[1].iov_len = 2 * VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);

	/* A partial segment is malformed even though it is below the limit. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE - 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);

	/* The advertised per-segment maximum is accepted exactly. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_cfg.vbc_capacity = VTBLK_MAX_WRITE_ZEROES_SECT;
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(VTBLK_MAX_WRITE_ZEROES_SECT);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_resid,
	    (ssize_t)VTBLK_MAX_WRITE_ZEROES_SECT *
	    VIRTIO14_BLK_SECTOR_BYTES);

	/* Neither the per-request limit nor device capacity may be crossed. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_cfg.vbc_capacity =
	    (uint64_t)VTBLK_MAX_WRITE_ZEROES_SECT + 2;
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors =
	    htole32(VTBLK_MAX_WRITE_ZEROES_SECT + 1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_cfg.vbc_capacity = 8;
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.sector = htole64(7);
	g_discard.num_sectors = htole32(2);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);

	/* Read-only media never advertise or execute the mutating operation. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_RO;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_IOERR);
}

ATF_TC_WITHOUT_HEAD(backend_capabilities);
ATF_TC_BODY(backend_capabilities, tc)
{
	struct pci_vtblk_softc sc;
	uint64_t caps;

	reset_mocks();
	caps = pci_vtblk_backend_caps(NULL);
	ATF_CHECK((caps & VTBLK_F_RO) == 0);
	ATF_CHECK((caps & VTBLK_F_DISCARD) == 0);
	ATF_CHECK((caps & VTBLK_F_WRITE_ZEROES) != 0);

	g_backend_readonly = 1;
	g_backend_candelete = 1;
	caps = pci_vtblk_backend_caps(NULL);
	ATF_CHECK((caps & VTBLK_F_RO) != 0);
	ATF_CHECK((caps & VTBLK_F_DISCARD) == 0);
	ATF_CHECK((caps & VTBLK_F_WRITE_ZEROES) == 0);

	/* Configuration limits agree with the capabilities exposed to Linux. */
	memset(&sc, 0, sizeof(sc));
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_WRITE_ZEROES;
	pci_vtblk_configure_range_limits(&sc, 512, 4096);
	ATF_CHECK_EQ(sc.vbsc_cfg.max_write_zeroes_sectors,
	    VTBLK_MAX_WRITE_ZEROES_SECT);
	ATF_CHECK_EQ(sc.vbsc_cfg.max_write_zeroes_seg,
	    VTBLK_MAX_WRITE_ZEROES_SEG);
	ATF_CHECK_EQ(sc.vbsc_cfg.write_zeroes_may_unmap, 0);

	memset(&sc, 0, sizeof(sc));
	pci_vtblk_configure_range_limits(&sc, 512, 4096);
	ATF_CHECK_EQ(sc.vbsc_cfg.max_write_zeroes_sectors, 0);
	ATF_CHECK_EQ(sc.vbsc_cfg.max_write_zeroes_seg, 0);
}

ATF_TC_WITHOUT_HEAD(readonly_and_stable_writes);
ATF_TC_BODY(readonly_and_stable_writes, tc)
{
	struct pci_vtblk_ioreq *io;
	struct pci_vtblk_softc sc;

	/* Read-only is enforced before an inconsistent backend can mutate data. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_RO | VTBLK_F_FLUSH;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_writes, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);

	/*
	 * Section 5.2.6.2 requires an unnegotiated DISCARD to return UNSUPP,
	 * including on a read-only backend.  This expectation comes from the
	 * independent VirtIO 1.4 oracle above, not the implementation value.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_RO;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_deletes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_UNSUPP);
	ATF_CHECK_EQ(g_rel_len, 1);

	/*
	 * Keep the read-only boundary defensive even if stale internal state
	 * incorrectly says that DISCARD was negotiated.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_RO;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_DISCARD;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK_EQ(g_backend_deletes, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);

	/*
	 * If FLUSH is offered but declined, a successful write is not stable
	 * until an implicit backend flush has also completed.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_FLUSH;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(io->io_active);
	ATF_CHECK(io->io_stabilizing);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_OK);
	ATF_CHECK_EQ(g_rel_len, 1);
	ATF_CHECK(!io->io_active);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* WRITE ZEROES has the same writethrough stability contract as a write. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_consts.vc_hv_caps =
	    VTBLK_F_FLUSH | VTBLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_WRITE_ZEROES;
	g_header.vbh_type = htole32(VBH_OP_WRITE_ZEROES);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(8);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE_EQ(g_backend_write_zeroes, 1);
	ATF_REQUIRE(io->io_active);
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(io->io_active);
	ATF_CHECK(io->io_stabilizing);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_OK);
	ATF_CHECK_EQ(g_rel_len, 1);
	ATF_CHECK(!io->io_active);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* Negotiated FLUSH selects writeback mode; no implicit flush is needed. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_FLUSH;
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_FLUSH;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_OK);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* A short write is an I/O error and is never stabilized as success. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_FLUSH;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_req.br_resid != 0);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* Failure to enqueue the stabilizing flush fails the guest write. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_FLUSH;
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	io->io_req.br_resid = 0;
	g_backend_error = EIO;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 1);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_CHECK(!io->io_active);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(reset_discards_outstanding_io);
ATF_TC_BODY(reset_discards_outstanding_io, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;
	pthread_t completion_thread;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	ATF_CHECK(io->io_generation == 0);
	ATF_CHECK(g_backend_reads == 1 && g_rel_calls == 0);

	/* A queued request is removed without receiving a callback. */
	g_cancel_error = 0;
	pthread_mutex_lock(&sc.vsc_mtx);
	pci_vtblk_reset(&sc);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(g_cancel_calls == 1 && g_reset_calls == 1);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	ATF_CHECK(sc.vbsc_generation == 1);
	ATF_CHECK(!io->io_active && g_rel_calls == 0);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* An active request reaches its callback after reset and is discarded. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	g_cancel_error = EBUSY;

	/*
	 * Hold the device mutex until reset reaches its condition wait.  This
	 * proves reset does not return before the stale backend callback has
	 * stopped using the request buffers.
	 */
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_create(&completion_thread, NULL,
	    complete_block_request, io) == 0);
	pci_vtblk_reset(&sc);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_join(completion_thread, NULL) == 0);
	ATF_CHECK(!io->io_active);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK(g_rel_calls == 0 && g_end_calls == 0);
	ATF_CHECK(g_status == UINT8_MAX);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

}

ATF_TC_WITHOUT_HEAD(resize_notifies_configuration_change);
ATF_TC_BODY(resize_notifies_configuration_change, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	sc.vbsc_vs.vs_mtx = &sc.vsc_mtx;
	pci_vtblk_resized(NULL, &sc, 4096);
	ATF_CHECK(sc.vbsc_cfg.vbc_capacity == 8);
	ATF_CHECK(g_config_changes == 1);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_drains_async_io);
ATF_TC_BODY(queue_reset_drains_async_io, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	sc.vbsc_vq.vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = EBUSY;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vq, 41), EINPROGRESS);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK_EQ(sc.vbsc_generation, 1);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);

	/* The stale backend completion drains reset without touching the ring. */
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK(!io->io_active);
	ATF_CHECK(!sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 0);
	ATF_CHECK_EQ(g_qreset_complete_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_generation, 41);
	ATF_CHECK_EQ(g_qreset_complete_error, 0);

	/* A late duplicate callback cannot complete the reset twice. */
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_qreset_complete_calls, 1);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(full_reset_waits_for_async_queue_reset);
ATF_TC_BODY(full_reset_waits_for_async_queue_reset, tc)
{
	struct full_reset_ctx ctx;
	struct pci_vtblk_ioreq *io;
	struct pci_vtblk_softc sc;
	pthread_t reset_thread;
	void *result;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	sc.vbsc_vq.vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = EBUSY;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_REQUIRE_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vq, 44),
	    EINPROGRESS);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);

	memset(&ctx, 0, sizeof(ctx));
	ctx.sc = &sc;
	ATF_REQUIRE(pthread_mutex_init(&ctx.mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&ctx.cv, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_lock(&ctx.mtx) == 0);
	ATF_REQUIRE(pthread_create(&reset_thread, NULL, run_full_reset,
	    &ctx) == 0);
	while (!ctx.entered)
		ATF_REQUIRE(pthread_cond_wait(&ctx.cv, &ctx.mtx) == 0);
	ATF_REQUIRE(pthread_mutex_unlock(&ctx.mtx) == 0);

	/*
	 * The full reset owns vsc_mtx and is waiting for the queue-reset owner.
	 * The stale completion must release that owner before the full reset
	 * can publish its own completion.
	 */
	pci_vtblk_done(&io->io_req, 0);
	ATF_REQUIRE(pthread_join(reset_thread, &result) == 0);
	ATF_REQUIRE(result == NULL);
	ATF_CHECK_EQ(g_cancel_calls, 1);
	ATF_CHECK_EQ(g_reset_calls, 1);
	ATF_CHECK(!sc.vbsc_resetting);
	ATF_CHECK(!sc.vbsc_qreset_pending);
	ATF_CHECK(!io->io_active);

	ATF_REQUIRE(pthread_cond_destroy(&ctx.cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&ctx.mtx) == 0);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_cancels_pending_io);
ATF_TC_BODY(queue_reset_cancels_pending_io, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	sc.vbsc_vq.vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = 0;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vq, 42), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(!io->io_active);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK(!sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	ATF_CHECK((vtblk_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_RESET) != 0);

	sc.vbsc_vq.vq_num = 1;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vq, 43), EINVAL);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(config_read_bounds);
ATF_TC_BODY(config_read_bounds, tc)
{
	struct pci_vtblk_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vbsc_cfg.vbc_capacity = htole64(0x1234);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtblk_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 0x1234);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtblk_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtblk_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
	value = UINT32_MAX;
	ATF_CHECK_EQ(pci_vtblk_cfgread(&sc, VIRTIO14_BLK_CONFIG_SIZE - 1, 4,
	    &value), EINVAL);
	ATF_CHECK_EQ(value, 0);
}

ATF_TC_WITHOUT_HEAD(document_wire_vectors);
ATF_TC_BODY(document_wire_vectors, tc)
{
	struct pci_vtblk_ioreq *io;
	struct pci_vtblk_softc sc;
	uint8_t discard[VIRTIO14_BLK_DISCARD_SEGMENT_SIZE];
	uint8_t header[VIRTIO14_BLK_REQUEST_HEADER_SIZE];

	/*
	 * Construct the guest request from the byte offsets in section 5.2.6,
	 * without using struct virtio_blk_hdr to define the input layout.
	 */
	reset_mocks();
	setup_softc(&sc);
	memset(header, 0, sizeof(header));
	virtio14_store_le32(header + VIRTIO14_BLK_REQUEST_TYPE_OFF,
	    VIRTIO14_BLK_T_OUT);
	virtio14_store_le64(header + VIRTIO14_BLK_REQUEST_SECTOR_OFF, 3);
	g_iov[0].iov_base = header;
	g_iov[0].iov_len = sizeof(header);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_writes, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_offset,
	    3 * VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK_EQ(io->io_req.br_resid, VIRTIO14_BLK_SECTOR_BYTES);

	/*
	 * The DISCARD payload is independently encoded from the documented
	 * le64/le32/le32 layout and must reach the backend with the documented
	 * sector and length.
	 */
	reset_mocks();
	setup_softc(&sc);
	memset(header, 0, sizeof(header));
	memset(discard, 0, sizeof(discard));
	virtio14_store_le32(header + VIRTIO14_BLK_REQUEST_TYPE_OFF,
	    VIRTIO14_BLK_T_DISCARD);
	virtio14_store_le64(discard + VIRTIO14_BLK_DISCARD_SECTOR_OFF, 5);
	virtio14_store_le32(discard +
	    VIRTIO14_BLK_DISCARD_NUM_SECTORS_OFF, 7);
	virtio14_store_le32(discard + VIRTIO14_BLK_DISCARD_FLAGS_OFF, 0);
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_DISCARD;
	g_iov[0].iov_base = header;
	g_iov[0].iov_len = sizeof(header);
	g_iov[1].iov_base = discard;
	g_iov[1].iov_len = sizeof(discard);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_deletes, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_offset,
	    5 * VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK_EQ(io->io_req.br_resid,
	    7 * VIRTIO14_BLK_SECTOR_BYTES);

	/*
	 * Linux uses the same document-defined range layout for WRITE ZEROES.
	 * The request header sector remains zero; the range carries the media
	 * offset, length, and optional UNMAP permission.
	 */
	reset_mocks();
	setup_softc(&sc);
	memset(header, 0, sizeof(header));
	memset(discard, 0, sizeof(discard));
	virtio14_store_le32(header + VIRTIO14_BLK_REQUEST_TYPE_OFF,
	    VIRTIO14_BLK_T_WRITE_ZEROES);
	virtio14_store_le64(discard + VIRTIO14_BLK_DISCARD_SECTOR_OFF, 9);
	virtio14_store_le32(discard +
	    VIRTIO14_BLK_DISCARD_NUM_SECTORS_OFF, 3);
	virtio14_store_le32(discard + VIRTIO14_BLK_DISCARD_FLAGS_OFF,
	    VIRTIO14_BLK_WRITE_ZEROES_FLAG_UNMAP);
	sc.vbsc_consts.vc_hv_caps = VIRTIO14_BLK_F_WRITE_ZEROES;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_WRITE_ZEROES;
	g_iov[0].iov_base = header;
	g_iov[0].iov_len = sizeof(header);
	g_iov[1].iov_base = discard;
	g_iov[1].iov_len = sizeof(discard);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_REQUIRE_EQ(g_backend_write_zeroes, 1);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_CHECK_EQ(io->io_req.br_offset,
	    9 * VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK_EQ(io->io_req.br_resid,
	    3 * VIRTIO14_BLK_SECTOR_BYTES);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct vtblk_config),
	    VIRTIO14_BLK_CONFIG_SIZE);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_capacity),
	    VIRTIO14_BLK_CONFIG_CAPACITY_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_size_max),
	    VIRTIO14_BLK_CONFIG_SIZE_MAX_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_seg_max),
	    VIRTIO14_BLK_CONFIG_SEG_MAX_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_geometry),
	    VIRTIO14_BLK_CONFIG_GEOMETRY_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_blk_size),
	    VIRTIO14_BLK_CONFIG_BLK_SIZE_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_topology),
	    VIRTIO14_BLK_CONFIG_TOPOLOGY_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, vbc_writeback),
	    VIRTIO14_BLK_CONFIG_WRITEBACK_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, num_queues),
	    VIRTIO14_BLK_CONFIG_NUM_QUEUES_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, max_discard_sectors),
	    VIRTIO14_BLK_CONFIG_MAX_DISCARD_SECTORS_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, max_discard_seg),
	    VIRTIO14_BLK_CONFIG_MAX_DISCARD_SEG_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, discard_sector_alignment),
	    VIRTIO14_BLK_CONFIG_DISCARD_ALIGN_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, max_write_zeroes_sectors),
	    VIRTIO14_BLK_CONFIG_MAX_WRITE_ZEROES_SECTORS_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, max_write_zeroes_seg),
	    VIRTIO14_BLK_CONFIG_MAX_WRITE_ZEROES_SEG_OFF);
	ATF_CHECK_EQ(offsetof(struct vtblk_config, write_zeroes_may_unmap),
	    VIRTIO14_BLK_CONFIG_WRITE_ZEROES_MAY_UNMAP_OFF);

	ATF_CHECK_EQ(sizeof(struct virtio_blk_hdr),
	    VIRTIO14_BLK_REQUEST_HEADER_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_hdr, vbh_type),
	    VIRTIO14_BLK_REQUEST_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_hdr, vbh_ioprio),
	    VIRTIO14_BLK_REQUEST_RESERVED_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_hdr, vbh_sector),
	    VIRTIO14_BLK_REQUEST_SECTOR_OFF);

	ATF_CHECK_EQ(sizeof(struct virtio_blk_discard_write_zeroes),
	    VIRTIO14_BLK_DISCARD_SEGMENT_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_discard_write_zeroes, sector),
	    VIRTIO14_BLK_DISCARD_SECTOR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_discard_write_zeroes,
	    num_sectors), VIRTIO14_BLK_DISCARD_NUM_SECTORS_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_blk_discard_write_zeroes, flags),
	    VIRTIO14_BLK_DISCARD_FLAGS_OFF);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, malformed_chains);
	ATF_TP_ADD_TC(tp, opcode_layouts);
	ATF_TP_ADD_TC(tp, split_request_fields);
	ATF_TP_ADD_TC(tp, backend_and_range_errors);
	ATF_TP_ADD_TC(tp, discard_validation);
	ATF_TP_ADD_TC(tp, write_zeroes_validation);
	ATF_TP_ADD_TC(tp, backend_capabilities);
	ATF_TP_ADD_TC(tp, readonly_and_stable_writes);
	ATF_TP_ADD_TC(tp, reset_discards_outstanding_io);
	ATF_TP_ADD_TC(tp, resize_notifies_configuration_change);
	ATF_TP_ADD_TC(tp, queue_reset_drains_async_io);
	ATF_TP_ADD_TC(tp, full_reset_waits_for_async_queue_reset);
	ATF_TP_ADD_TC(tp, queue_reset_cancels_pending_io);
	ATF_TP_ADD_TC(tp, config_read_bounds);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	return (atf_no_error());
}

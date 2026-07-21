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

#include "pci_virtio_block.c"

struct blockif_ctxt {
	int unused;
};

static struct iovec g_iov[BLOCKIF_IOV_MAX + 2];
static struct vi_req g_req;
static int g_chain_n;
static int g_backend_error;
static int g_backend_reads;
static int g_backend_writes;
static int g_backend_flushes;
static int g_backend_deletes;
static int g_rel_calls;
static uint32_t g_rel_len;
static int g_end_calls;

static struct virtio_blk_hdr g_header;
static struct virtio_blk_discard_write_zeroes g_discard;
static uint8_t g_data[64];
static uint8_t g_status;

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
	g_iov[0].iov_len = sizeof(g_header);
	g_iov[1].iov_base = g_data;
	g_iov[1].iov_len = sizeof(g_data);
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = sizeof(g_status);
	g_backend_error = 0;
	g_backend_reads = 0;
	g_backend_writes = 0;
	g_backend_flushes = 0;
	g_backend_deletes = 0;
	g_rel_calls = 0;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
}

static void
setup_softc(struct pci_vtblk_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
	for (int i = 0; i < VTBLK_RINGSZ; i++) {
		sc->vbsc_ios[i].io_sc = sc;
		sc->vbsc_ios[i].io_idx = i;
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
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_OK);
	ATF_CHECK(g_rel_len == sizeof(g_data) + 1);
	ATF_CHECK(memcmp(g_data, "block-identity",
	    sizeof("block-identity") - 1) == 0);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ | VBH_FLAG_BARRIER);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);
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
	g_iov[1].iov_len = sizeof(g_discard);
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
	g_iov[1].iov_len = sizeof(g_discard);
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
	g_iov[1].iov_len = sizeof(g_discard);
	g_discard.flags = htole32(1);
	pci_vtblk_proc(&sc, &sc.vbsc_vq);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, malformed_chains);
	ATF_TP_ADD_TC(tp, opcode_layouts);
	ATF_TP_ADD_TC(tp, backend_and_range_errors);
	ATF_TP_ADD_TC(tp, discard_validation);
	return (atf_no_error());
}

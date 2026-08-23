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

#include "virtio_config_read_test_support.h"
#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"
#define	BHYVE_SNAPSHOT
#include "pci_virtio_block.c"
#include "snapshot.h"
#include "snapshot_portable.h"

enum {
	DUT_VTBLK_F_CONFIG_WCE = VTBLK_F_CONFIG_WCE,
	DUT_VTBLK_F_MQ = VTBLK_F_MQ,
};

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
#undef VTBLK_F_CONFIG_WCE
#define	VTBLK_F_CONFIG_WCE		VIRTIO14_BLK_F_CONFIG_WCE
#undef VTBLK_F_MQ
#define	VTBLK_F_MQ			VIRTIO14_BLK_F_MQ
#undef VTBLK_F_DISCARD
#define	VTBLK_F_DISCARD			VIRTIO14_BLK_F_DISCARD
#undef VTBLK_F_WRITE_ZEROES
#define	VTBLK_F_WRITE_ZEROES		VIRTIO14_BLK_F_WRITE_ZEROES
#undef VTBLK_WRITE_ZEROES_FLAG_UNMAP
#define	VTBLK_WRITE_ZEROES_FLAG_UNMAP \
	VIRTIO14_BLK_WRITE_ZEROES_FLAG_UNMAP
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND

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
static int g_backend_stability_flushes;
static int g_backend_deletes;
static int g_backend_readonly;
static int g_backend_candelete;
static int g_cancel_calls;
static int g_cancel_error;
static int g_cancel_saw_unlocked;
static pthread_mutex_t g_cancel_sync_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cancel_sync_cv = PTHREAD_COND_INITIALIZER;
static bool g_completion_wait_for_cancel;
static bool g_cancel_entered;
static int g_rel_calls;
static struct vqueue_info *g_rel_vq;
static uint32_t g_rel_len;
static int g_end_calls;
static int g_reset_calls;
static int g_needs_reset_calls;
static int g_config_changes;
static int g_qreset_complete_calls;
static uint64_t g_qreset_complete_generation;
static int g_qreset_complete_error;
static int g_blockif_pause_depth;
static int g_blockif_suspend_error;
static bool g_modern;
static const char *g_checkpoint_identity;
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;

static int g_has_descs_budget;

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (g_has_descs_budget > 0 ? (g_has_descs_budget--, 1) : 0);
}

static struct virtio_blk_hdr g_header;
static struct virtio_blk_discard_write_zeroes g_discard;
static uint8_t g_data[VTBLK_BSIZE];
static uint8_t g_status;
static struct pci_vtblk_ioreq g_ios[VTBLK_MAXREQ];

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

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le16(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le16(bytes);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le32(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le32(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le64(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le64(bytes);
	return (error);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs __unused)
{

	return (g_modern);
}

static void *
complete_block_request(void *arg)
{
	struct pci_vtblk_ioreq *io;

	io = arg;
	pthread_mutex_lock(&g_cancel_sync_mtx);
	while (g_completion_wait_for_cancel && !g_cancel_entered)
		pthread_cond_wait(&g_cancel_sync_cv, &g_cancel_sync_mtx);
	pthread_mutex_unlock(&g_cancel_sync_mtx);
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
	g_req.outstanding = true;
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
	g_backend_stability_flushes = 0;
	g_backend_deletes = 0;
	g_backend_readonly = 0;
	g_backend_candelete = 0;
	g_cancel_calls = 0;
	g_cancel_error = 0;
	g_cancel_saw_unlocked = 0;
	g_completion_wait_for_cancel = false;
	g_cancel_entered = false;
	g_rel_calls = 0;
	g_rel_vq = NULL;
	g_rel_len = UINT32_MAX;
	g_end_calls = 0;
	g_reset_calls = 0;
	g_needs_reset_calls = 0;
	g_config_changes = 0;
	g_qreset_complete_calls = 0;
	g_qreset_complete_generation = 0;
	g_qreset_complete_error = 0;
	g_blockif_pause_depth = 0;
	g_blockif_suspend_error = 0;
	g_modern = false;
	g_checkpoint_identity = "block-test";
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
}

static void
setup_softc_queues(struct pci_vtblk_softc *sc, uint16_t nqueues)
{

	ATF_REQUIRE(nqueues >= 1 && nqueues <= VTBLK_MAXQ);
	memset(sc, 0, sizeof(*sc));
	sc->vbsc_cfg.vbc_capacity = 1024;
	sc->vbsc_nqueues = nqueues;
	for (uint16_t i = 0; i < nqueues; i++) {
		sc->vbsc_vqs[i].vq_num = i;
		sc->vbsc_vqs[i].vq_qsize = VTBLK_RINGSZ;
	}
	memset(g_ios, 0, sizeof(g_ios));
	sc->vbsc_ios = g_ios;
	for (int i = 0; i < nqueues * VTBLK_RINGSZ; i++) {
		sc->vbsc_ios[i].io_sc = sc;
		sc->vbsc_ios[i].io_req.br_param = &sc->vbsc_ios[i];
	}
}

static void
setup_softc(struct pci_vtblk_softc *sc)
{

	setup_softc_queues(sc, 1);
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtblk_softc *sc;

	pi = meta->dev_data;
	if (pi == NULL || pi->pi_arg == NULL)
		return (EINVAL);
	sc = pi->pi_arg;
	g_snapshot_validate_saw_lock =
	    pthread_mutex_isowned_np(&sc->vsc_mtx);
	g_snapshot_validate_calls++;
	return (g_snapshot_validate_result);
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
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t len)
{

	ATF_CHECK(idx == g_req.idx);
	g_rel_calls++;
	g_rel_vq = vq;
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
blockif_flush_stability(struct blockif_ctxt *bc __unused,
    struct blockif_req *req __unused)
{

	g_backend_stability_flushes++;
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

const char *
blockif_checkpoint_identity(struct blockif_ctxt *bc __unused)
{

	return (g_checkpoint_identity);
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
	pthread_mutex_lock(&g_cancel_sync_mtx);
	g_cancel_entered = true;
	pthread_cond_broadcast(&g_cancel_sync_cv);
	pthread_mutex_unlock(&g_cancel_sync_mtx);
	return (g_cancel_error);
}

int
blockif_suspend(struct blockif_ctxt *bc __unused)
{

	if (g_blockif_suspend_error != 0)
		return (g_blockif_suspend_error);
	g_blockif_pause_depth++;
	return (0);
}

void
blockif_suspend_retain(struct blockif_ctxt *bc __unused)
{

	ATF_REQUIRE(g_blockif_pause_depth > 0);
	g_blockif_pause_depth++;
}

void
blockif_resume(struct blockif_ctxt *bc __unused)
{

	ATF_REQUIRE(g_blockif_pause_depth > 0);
	g_blockif_pause_depth--;
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

/*
 * Initialization-path mocks.  The real bhyve build strips pci_vtblk_init(),
 * pci_vtblk_notify(), and pci_vtblk_pause() with --gc-sections because no
 * other test references them; the coverage build keeps every section, so the
 * common VirtIO, blockif, and PCI helpers those functions call are stubbed
 * here.  Each stub is a thin, independently controllable spy.
 */
static int g_open_return_null;
static off_t g_open_size = 4096;
static int g_open_sectsz = 512;
static int g_open_psts = 512;
static int g_open_psto = 0;
static int g_select_transport_error;
static int g_intr_init_error;
static int g_modern_init_error;
static int g_add_boot_error;
static int g_resize_register_error;
static const char *g_cfg_queues;
static bool g_cfg_packed;
static bool g_cfg_resize;
static const char *g_cfg_serial;
static const char *g_cfg_path = "/dev/null-backing";
static int g_boot_device_calls;
static int g_resize_register_calls;
static int g_linkup_calls;
static struct blockif_ctxt g_init_bc;

extern void *__real_calloc(size_t, size_t);
static int g_calloc_fail_after = -1;	/* -1: never fail */

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (g_calloc_fail_after == 0) {
		g_calloc_fail_after = -1;
		return (NULL);
	}
	if (g_calloc_fail_after > 0)
		g_calloc_fail_after--;
	return (__real_calloc(nmemb, size));
}

struct blockif_ctxt *
blockif_open(nvlist_t *nvl __unused, const char *ident __unused)
{

	return (g_open_return_null ? NULL : &g_init_bc);
}

off_t
blockif_size(struct blockif_ctxt *bc __unused)
{

	return (g_open_size);
}

int
blockif_sectsz(struct blockif_ctxt *bc __unused)
{

	return (g_open_sectsz);
}

void
blockif_psectsz(struct blockif_ctxt *bc __unused, int *sts, int *sto)
{

	*sts = g_open_psts;
	*sto = g_open_psto;
}

int
blockif_close(struct blockif_ctxt *bc __unused)
{

	return (0);
}

int
blockif_add_boot_device(struct pci_devinst *pi __unused,
    struct blockif_ctxt *bc __unused)
{

	g_boot_device_calls++;
	return (g_add_boot_error);
}

int
blockif_register_resize_callback(struct blockif_ctxt *bc __unused,
    blockif_resize_cb *cb __unused, void *arg __unused)
{

	g_resize_register_calls++;
	return (g_resize_register_error);
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "queues") == 0)
		return (g_cfg_queues);
	if (strcmp(name, "serial") == 0)
		return (g_cfg_serial);
	if (strcmp(name, "ser") == 0)
		return (NULL);
	if (strcmp(name, "path") == 0)
		return (g_cfg_path);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused, const char *name,
    bool def __unused)
{

	if (strcmp(name, "packed") == 0)
		return (g_cfg_packed);
	if (strcmp(name, "resize") == 0)
		return (g_cfg_resize);
	return (def);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc __unused,
    void *arg, struct pci_devinst *pi, struct vqueue_info *vqs)
{

	g_linkup_calls++;
	vs->vs_queues = vqs;
	pi->pi_arg = arg;
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy def __unused)
{

	return (g_select_transport_error);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t id __unused)
{
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int nbars __unused)
{

	return (g_modern_init_error);
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (g_intr_init_error != 0)
		return (g_intr_init_error);
	(void)pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

void
vi_set_io_bar(struct virtio_softc *vs __unused, int barnum __unused)
{
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t val)
{

	pi->pi_cfgdata[offset] = val;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t val)
{

	memcpy(&pi->pi_cfgdata[offset], &val, sizeof(val));
}

static void
init_reset_controls(void)
{

	g_open_return_null = 0;
	g_open_size = 4096;
	g_open_sectsz = 512;
	g_open_psts = 512;
	g_open_psto = 0;
	g_select_transport_error = 0;
	g_intr_init_error = 0;
	g_modern_init_error = 0;
	g_add_boot_error = 0;
	g_resize_register_error = 0;
	g_cfg_queues = NULL;
	g_cfg_packed = false;
	g_cfg_resize = false;
	g_cfg_serial = NULL;
	g_cfg_path = "/dev/null-backing";
	g_boot_device_calls = 0;
	g_resize_register_calls = 0;
	g_linkup_calls = 0;
	g_calloc_fail_after = -1;
}

static void
destroy_softc(struct pci_vtblk_softc *sc)
{

	pthread_cond_destroy(&sc->vbsc_reset_cond);
	pthread_mutex_destroy(&sc->vsc_mtx);
	pthread_mutex_destroy(&sc->vbsc_vs.vs_isr_mtx);
	free(sc->vbsc_ios);
	free(sc);
}

ATF_TC_WITHOUT_HEAD(malformed_chains);
ATF_TC_BODY(malformed_chains, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_iov[0].iov_len--;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);

	reset_mocks();
	setup_softc(&sc);
	g_req.ordered = false;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_status == UINT8_MAX);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = BLOCKIF_IOV_MAX + 3;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 0);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = -1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_rel_calls == 0);
}

ATF_TC_WITHOUT_HEAD(opcode_layouts);
ATF_TC_BODY(opcode_layouts, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_req.readable = 2;
	g_req.writable = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_writes == 1);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_FLUSH);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_flushes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_chain_n = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = 1;
	g_header.vbh_type = htole32(0x7fffffff);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);

	reset_mocks();
	setup_softc(&sc);
	memcpy(sc.vbsc_ident, "block-identity", sizeof("block-identity") - 1);
	g_header.vbh_type = htole32(VBH_OP_IDENT);
	g_iov[1].iov_len = VTBLK_BLK_ID_LEN;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_status == VTBLK_S_OK);
	ATF_CHECK(g_rel_len == VTBLK_BLK_ID_LEN + 1);
	ATF_CHECK(memcmp(g_data, "block-identity",
	    sizeof("block-identity") - 1) == 0);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ | VBH_FLAG_BARRIER);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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

	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_reads == 1);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
	ATF_CHECK(g_rel_calls == 1 && g_rel_len == 1);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_header.vbh_sector = htole64((uint64_t)OFF_MAX / VTBLK_BSIZE + 1);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_reads == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_iov[1].iov_len = VTBLK_BSIZE - 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_flushes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);

	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_IDENT);
	g_iov[1].iov_len = VTBLK_BLK_ID_LEN - 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_UNSUPP);

	/*
	 * Secure erase is an independent optional command (VirtIO 1.4 section
	 * 5.2.6.2), not an alias for DISCARD or WRITE ZEROES.  Since the backend
	 * deliberately does not advertise the secure-erase guarantee, a raw
	 * request must complete UNSUPP and reach neither mutating backend path.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VIRTIO14_BLK_T_SECURE_ERASE);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_deletes, 0);
	ATF_CHECK_EQ(g_backend_write_zeroes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_UNSUPP);

	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_vs.vs_negotiated_caps = VTBLK_F_DISCARD;
	g_header.vbh_type = htole32(VBH_OP_DISCARD);
	g_req.readable = 2;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_discard;
	g_iov[1].iov_len = VIRTIO14_BLK_DISCARD_SEGMENT_SIZE;
	g_discard.num_sectors = htole32(8);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK(g_backend_deletes == 0);
	ATF_CHECK(g_status == VTBLK_S_IOERR);
}

ATF_TC_WITHOUT_HEAD(flush_requires_negotiation);
ATF_TC_BODY(flush_requires_negotiation, tc)
{
	struct pci_vtblk_ioreq *io;
	struct pci_vtblk_softc sc;

	/* A valid wire request cannot exercise an unnegotiated operation. */
	reset_mocks();
	setup_softc(&sc);
	g_chain_n = 2;
	g_req.readable = 1;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = VIRTIO14_BLK_STATUS_SIZE;
	g_header.vbh_type = htole32(VIRTIO14_BLK_T_FLUSH);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_UNSUPP);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_BLK_STATUS_SIZE);

	/* Negotiating the independent specification bit enables the command. */
	reset_mocks();
	setup_softc(&sc);
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_FLUSH;
	g_chain_n = 2;
	g_req.readable = 1;
	g_req.writable = 1;
	g_iov[1].iov_base = &g_status;
	g_iov[1].iov_len = VIRTIO14_BLK_STATUS_SIZE;
	g_header.vbh_type = htole32(VIRTIO14_BLK_T_FLUSH);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_flushes, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	pci_vtblk_done_locked(io, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_OK);
	ATF_CHECK_EQ(g_rel_len, VIRTIO14_BLK_STATUS_SIZE);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	/*
	 * VirtIO 1.4 secure erase is an optional guarantee.  blockif's delete
	 * operation cannot establish that guarantee, so a writable backend must
	 * not advertise the feature merely because it can discard or zero data.
	 */
	ATF_CHECK((caps & VIRTIO14_BLK_F_SECURE_ERASE) == 0);
	ATF_CHECK((caps & VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK((caps & VIRTIO_F_SUSPEND) != 0);

	g_backend_readonly = 1;
	g_backend_candelete = 1;
	caps = pci_vtblk_backend_caps(NULL);
	ATF_CHECK((caps & VTBLK_F_RO) != 0);
	ATF_CHECK((caps & VTBLK_F_DISCARD) == 0);
	ATF_CHECK((caps & VTBLK_F_WRITE_ZEROES) == 0);
	ATF_CHECK((caps & VIRTIO14_BLK_F_SECURE_ERASE) == 0);
	ATF_CHECK((caps & VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK((caps & VIRTIO_F_SUSPEND) != 0);

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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_backend_stability_flushes, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(io->io_active);
	ATF_CHECK(io->io_stabilizing);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_OK);
	ATF_CHECK_EQ(g_backend_stability_flushes, 1);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE_EQ(g_backend_write_zeroes, 1);
	ATF_REQUIRE(io->io_active);
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_backend_stability_flushes, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(io->io_active);
	ATF_CHECK(io->io_stabilizing);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_status, VIRTIO14_BLK_S_OK);
	ATF_CHECK_EQ(g_backend_stability_flushes, 1);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	io->io_req.br_resid = 0;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_backend_stability_flushes, 0);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_req.br_resid != 0);
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_backend_stability_flushes, 0);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	io->io_req.br_resid = 0;
	g_backend_error = EIO;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK_EQ(g_backend_flushes, 0);
	ATF_CHECK_EQ(g_backend_stability_flushes, 1);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	ATF_CHECK(io->io_device_generation == 0);
	ATF_CHECK(io->io_queue_generation == 0);
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
	ATF_CHECK(!io->io_vreq.outstanding);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

	/* An active request reaches its callback after reset and is discarded. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	g_cancel_error = EBUSY;
	g_completion_wait_for_cancel = true;

	/*
	 * Hold the device mutex until reset starts.  The explicit cancellation
	 * barrier prevents the completion thread from winning the unlocked
	 * interval before the mock has observed it; relying on scheduler order
	 * here made this assertion fail nondeterministically under ThreadSanitizer.
	 * Reset must still wait until the stale backend callback has stopped using
	 * the request buffers.
	 */
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_create(&completion_thread, NULL,
	    complete_block_request, io) == 0);
	pci_vtblk_reset(&sc);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_join(completion_thread, NULL) == 0);
	ATF_CHECK(!io->io_active);
	ATF_CHECK(!io->io_vreq.outstanding);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK(g_rel_calls == 0 && g_end_calls == 0);
	ATF_CHECK(g_status == UINT8_MAX);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);

}

ATF_TC_WITHOUT_HEAD(reset_drain_timeout_is_bounded);
ATF_TC_BODY(reset_drain_timeout_is_bounded, tc)
{
	struct pci_vtblk_softc sc;
	struct timespec expired = { 0, 0 };

	(void)tc;
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);
	sc.vbsc_ios[0].io_active = true;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK(!pci_vtblk_wait_requests_drained_until(&sc, &expired));
	ATF_CHECK(!sc.vbsc_reset_waiting);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	sc.vbsc_ios[0].io_active = false;
	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.vbsc_reset_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
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

	/* Capacity is in 512-byte sectors; never publish a truncated size. */
	pci_vtblk_resized(NULL, &sc, 4097);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 8);
	ATF_CHECK_EQ(g_config_changes, 1);

	/* A backend media size is signed; do not reinterpret a bad value. */
	pci_vtblk_resized(NULL, &sc, -512);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 8);
	ATF_CHECK_EQ(g_config_changes, 1);

	/*
	 * Configuration fields are frozen while guest suspend is complete.
	 * Preserve the old capacity, latch the newest backend value, and
	 * publish it only after the common resume fence opens.
	 */
	sc.vbsc_vs.vs_suspended = true;
	pci_vtblk_resized(NULL, &sc, 8192);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 8);
	ATF_CHECK(sc.vbsc_capacity_pending);
	ATF_CHECK_EQ(sc.vbsc_pending_capacity, 16);
	ATF_CHECK_EQ(g_config_changes, 2);
	sc.vbsc_vs.vs_suspended = false;
	pci_vtblk_resume_complete(&sc);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 16);
	ATF_CHECK(!sc.vbsc_capacity_pending);
	ATF_CHECK_EQ(g_config_changes, 3);

	/* Checkpoint ownership uses the same deferred-publication boundary. */
	sc.vbsc_vs.vs_checkpoint_paused = true;
	pci_vtblk_resized(NULL, &sc, 16384);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 16);
	ATF_CHECK_EQ(sc.vbsc_pending_capacity, 32);
	sc.vbsc_vs.vs_checkpoint_paused = false;
	pci_vtblk_resume_complete(&sc);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 32);
	ATF_CHECK(!sc.vbsc_capacity_pending);
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
	sc.vbsc_vqs[0].vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = EBUSY;
	/* The modern transport advances the queue epoch before this callback. */
	sc.vbsc_vqs[0].vq_generation++;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 41), EINPROGRESS);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK_EQ(sc.vbsc_generation, 0);
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
	sc.vbsc_vqs[0].vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = EBUSY;
	sc.vbsc_vqs[0].vq_generation++;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_REQUIRE_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 44),
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
	sc.vbsc_vqs[0].vq_num = 0;
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);

	g_cancel_error = 0;
	sc.vbsc_vqs[0].vq_generation++;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 42), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(!io->io_active);
	ATF_CHECK_EQ(g_cancel_saw_unlocked, 1);
	ATF_CHECK(!sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	ATF_CHECK((vtblk_vi_consts.vc_hv_caps &
	    VIRTIO_F_RING_RESET) != 0);

	sc.vbsc_vqs[0].vq_num = 1;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 43), EINVAL);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_reset_isolation);
ATF_TC_BODY(multiqueue_reset_isolation, tc)
{
	struct pci_vtblk_ioreq *io0, *io1;
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc_queues(&sc, 2);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);
	g_header.vbh_type = htole32(VBH_OP_READ);

	/*
	 * The same descriptor index in different request queues denotes two
	 * different requests.  Submit both before resetting queue zero.
	 */
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[1]);
	io0 = &sc.vbsc_ios[g_req.idx];
	io1 = &sc.vbsc_ios[VTBLK_RINGSZ + g_req.idx];
	ATF_REQUIRE(io0 != io1);
	ATF_REQUIRE(io0->io_active);
	ATF_REQUIRE(io1->io_active);
	ATF_CHECK(io0->io_vq == &sc.vbsc_vqs[0]);
	ATF_CHECK(io1->io_vq == &sc.vbsc_vqs[1]);

	/*
	 * A busy request holds queue zero in reset.  Completing queue one's
	 * request must publish only to queue one and must not finish queue
	 * zero's asynchronous reset.
	 */
	g_cancel_error = EBUSY;
	sc.vbsc_vqs[0].vq_generation++;
	ATF_REQUIRE(pthread_mutex_lock(&sc.vsc_mtx) == 0);
	ATF_REQUIRE_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 71),
	    EINPROGRESS);
	ATF_REQUIRE(pthread_mutex_unlock(&sc.vsc_mtx) == 0);
	ATF_CHECK(sc.vbsc_qreset_pending);
	ATF_CHECK(io1->io_active);

	pci_vtblk_done(&io1->io_req, 0);
	ATF_CHECK(!io1->io_active);
	ATF_CHECK(sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(g_rel_vq == &sc.vbsc_vqs[1]);

	/* The stale queue-zero completion drains only queue zero's reset. */
	pci_vtblk_done(&io0->io_req, 0);
	ATF_CHECK(!io0->io_active);
	ATF_CHECK(!sc.vbsc_qreset_pending);
	ATF_CHECK_EQ(g_qreset_complete_calls, 1);
	ATF_CHECK_EQ(g_qreset_complete_generation, 71);
	ATF_CHECK_EQ(g_rel_calls, 1);

	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_document_contract);
ATF_TC_BODY(multiqueue_document_contract, tc)
{
	struct pci_vtblk_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vbsc_nqueues = VTBLK_MAXQ;
	sc.vbsc_cfg.num_queues = sc.vbsc_nqueues;
	sc.vbsc_consts.vc_hv_caps = VTBLK_F_MQ;

	ATF_CHECK_EQ(DUT_VTBLK_F_MQ, VIRTIO14_BLK_F_MQ);
	ATF_CHECK_EQ(sc.vbsc_cfg.num_queues, VTBLK_MAXQ);
	ATF_CHECK_EQ(VTBLK_MAXQ, 8);
	ATF_CHECK_EQ(VTBLK_MAXREQ, 1024);
	ATF_CHECK(VTBLK_MAXREQ <= BLOCKIF_RING_MAX);
	ATF_CHECK((vtblk_vi_consts.vc_hv_caps & VIRTIO14_BLK_F_MQ) == 0);
}

ATF_TC_WITHOUT_HEAD(multiqueue_option_validation);
ATF_TC_BODY(multiqueue_option_validation, tc)
{
	const char *errstr;
	uint16_t queues;

	queues = 0;
	ATF_REQUIRE_EQ(pci_vtblk_parse_queues(NULL, &queues, &errstr), 0);
	ATF_CHECK_EQ(queues, 1);
	ATF_CHECK(errstr == NULL);

	ATF_REQUIRE_EQ(pci_vtblk_parse_queues("1", &queues, &errstr), 0);
	ATF_CHECK_EQ(queues, 1);
	ATF_REQUIRE_EQ(pci_vtblk_parse_queues("8", &queues, &errstr), 0);
	ATF_CHECK_EQ(queues, 8);

	ATF_CHECK_EQ(pci_vtblk_parse_queues("0", &queues, &errstr), EINVAL);
	ATF_CHECK(errstr != NULL);
	ATF_CHECK_EQ(pci_vtblk_parse_queues("9", &queues, &errstr), EINVAL);
	ATF_CHECK(errstr != NULL);
	ATF_CHECK_EQ(pci_vtblk_parse_queues("two", &queues, &errstr),
	    EINVAL);
	ATF_CHECK(errstr != NULL);
}

ATF_TC_WITHOUT_HEAD(packed_ring_option_validation);
ATF_TC_BODY(packed_ring_option_validation, tc)
{
	struct pci_vtblk_softc sc;

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	sc.vbsc_consts = vtblk_vi_consts;
	g_modern = true;
	ATF_REQUIRE_EQ(pci_vtblk_configure_ring_format(&sc, true), 0);
	ATF_CHECK((sc.vbsc_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED) != 0);
	ATF_REQUIRE_EQ(pci_vtblk_configure_ring_format(&sc, false), 0);
	ATF_CHECK_EQ(sc.vbsc_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED, 0);

	g_modern = false;
	ATF_CHECK_EQ(pci_vtblk_configure_ring_format(&sc, true), EINVAL);
	ATF_CHECK_EQ(sc.vbsc_consts.vc_hv_caps &
	    VIRTIO14_F_RING_PACKED, 0);
}

ATF_TC_WITHOUT_HEAD(write_cache_configuration);
ATF_TC_BODY(write_cache_configuration, tc)
{
	struct pci_vtblk_softc sc;
	const int offset = VIRTIO14_BLK_CONFIG_WRITEBACK_OFF;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(pthread_mutex_init(&sc.vsc_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&sc.vbsc_reset_cond, NULL) == 0);

	ATF_CHECK_EQ(DUT_VTBLK_F_CONFIG_WCE,
	    VIRTIO14_BLK_F_CONFIG_WCE);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);
	ATF_CHECK_EQ(pci_vtblk_cfgwrite(&sc, offset, 1, 1), EINVAL);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);

	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO14_BLK_F_CONFIG_WCE | VIRTIO14_BLK_F_FLUSH;
	pci_vtblk_neg_features(&sc, sc.vbsc_vs.vs_negotiated_caps);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);
	ATF_REQUIRE_EQ(pci_vtblk_cfgwrite(&sc, offset, 1, 1), 0);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 1);
	ATF_CHECK(!pci_vtblk_write_needs_stabilization(&sc));
	ATF_CHECK_EQ(pci_vtblk_cfgwrite(&sc, offset, 2, 0), EINVAL);
	ATF_CHECK_EQ(pci_vtblk_cfgwrite(&sc, offset, 1, 2), EINVAL);
	ATF_CHECK_EQ(pci_vtblk_cfgwrite(&sc, offset + 1, 1, 0), EINVAL);

	ATF_REQUIRE_EQ(pci_vtblk_cfgwrite(&sc, offset, 1, 0), 0);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);
	ATF_CHECK(pci_vtblk_write_needs_stabilization(&sc));

	ATF_REQUIRE_EQ(pci_vtblk_cfgwrite(&sc, offset, 1, 1), 0);
	pthread_mutex_lock(&sc.vsc_mtx);
	pci_vtblk_reset(&sc);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback,
	    VTBLK_DEFAULT_WRITEBACK);
	ATF_CHECK(!pci_vtblk_write_needs_stabilization(&sc));

	pci_vtblk_neg_features(&sc, VIRTIO14_BLK_F_CONFIG_WCE);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback,
	    VTBLK_DEFAULT_WRITEBACK);
	ATF_CHECK(!pci_vtblk_write_needs_stabilization(&sc));

	/*
	 * VirtIO 1.4 section 5.2.5.3: a legacy DRIVER_OK transition must
	 * preserve a writeback value selected before DRIVER_OK whenever
	 * CONFIG_WCE was selected.
	 */
	sc.vbsc_cfg.vbc_writeback = 0;
	pci_vtblk_neg_features(&sc,
	    VIRTIO14_BLK_F_CONFIG_WCE | VIRTIO14_BLK_F_FLUSH);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);

	/* The corresponding modern initialization rule is section 5.2.5.2. */
	g_modern = true;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_CONFIG_WCE;
	sc.vbsc_cfg.vbc_writeback = VTBLK_DEFAULT_WRITEBACK;
	pci_vtblk_neg_features(&sc, VIRTIO14_BLK_F_CONFIG_WCE);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);
	ATF_CHECK(pci_vtblk_write_needs_stabilization(&sc));
	g_modern = false;

	ATF_REQUIRE(pthread_cond_destroy(&sc.vbsc_reset_cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&sc.vsc_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(config_read_bounds);
ATF_TC_BODY(config_read_bounds, tc)
{
	struct pci_vtblk_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vbsc_cfg.vbc_capacity = 0x1234;
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
	ATF_CHECK_EQ(pci_vtblk_cfgread(&sc, 0, 1, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(snapshot_backing_identity);
ATF_TC_BODY(snapshot_backing_identity, tc)
{
	struct pci_vtblk_softc sc;
	struct vtblk_config dst_config, saved;
	char dst_ident[VTBLK_BLK_ID_BYTES], saved_ident[VTBLK_BLK_ID_BYTES];

	reset_mocks();
	setup_softc(&sc);
	memset(&dst_config, 0, sizeof(dst_config));
	dst_config.vbc_capacity = 4096;
	dst_config.vbc_seg_max = 126;
	dst_config.vbc_blk_size = 512;
	dst_config.vbc_writeback = VTBLK_DEFAULT_WRITEBACK;
	dst_config.num_queues = 1;
	memset(dst_ident, 0, sizeof(dst_ident));
	memcpy(dst_ident, "destination-disk", sizeof("destination-disk"));
	saved = dst_config;
	memcpy(saved_ident, dst_ident, sizeof(saved_ident));

	g_modern = true;
	sc.vbsc_vs.vs_negotiated_caps = 0;
	ATF_CHECK(pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	saved.vbc_capacity++;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	saved = dst_config;
	saved.num_queues = 2;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	saved = dst_config;
	saved_ident[0] ^= 1;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	memcpy(saved_ident, dst_ident, sizeof(saved_ident));
	saved_ident[VIRTIO14_BLK_ID_BYTES] = 1;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	memcpy(saved_ident, dst_ident, sizeof(saved_ident));

	/* CONFIG_WCE makes either document-defined cache mode migratable. */
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_CONFIG_WCE;
	saved.vbc_writeback = 0;
	ATF_CHECK(pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	saved.vbc_writeback = 2;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));

	/* Without CONFIG_WCE the mode is implied by transport/features. */
	saved.vbc_writeback = 0;
	sc.vbsc_vs.vs_negotiated_caps = 0;
	ATF_CHECK(!pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	g_modern = false;
	ATF_CHECK(pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_FLUSH;
	saved.vbc_writeback = VTBLK_DEFAULT_WRITEBACK;
	ATF_CHECK(pci_vtblk_restore_state_valid(&sc, &saved, saved_ident,
	    &dst_config, dst_ident));
}

static int
run_block_snapshot(struct pci_vtblk_softc *sc, void *buffer, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = buffer,
			.buf_size = size,
			.buf = buffer,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtblk_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vtblk_softc sc;
	struct vm_snapshot_meta meta = {
		.dev_data = &pi,
		.op = VM_SNAPSHOT_VALIDATE,
	};

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;

	/* Direct preflight excludes completion and resize callbacks. */
	ATF_REQUIRE_EQ(pci_vtblk_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);

	/* The non-recursive mutex retained by checkpoint pause is reused. */
	pthread_mutex_lock(&sc.vsc_mtx);
	g_snapshot_validate_saw_lock = false;
	ATF_REQUIRE_EQ(pci_vtblk_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	pthread_mutex_unlock(&sc.vsc_mtx);

	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vtblk_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 2);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_and_version);
ATF_TC_BODY(snapshot_wire_and_version, tc)
{
#define	BLOCK_TEST_ID		"block-test"
#define	BLOCK_TEST_ID_LENGTH	(sizeof(BLOCK_TEST_ID) - 1)
	struct pci_vtblk_softc destination, source;
	struct vtblk_config original;
	uint8_t expected[85 + 4 + BLOCK_TEST_ID_LENGTH], image[512],
	    obsolete[512];
	size_t used;

	reset_mocks();
	setup_softc(&source);
	source.vbsc_cfg.vbc_capacity = UINT64_C(0x0807060504030201);
	source.vbsc_cfg.vbc_size_max = 0x0c0b0a09;
	source.vbsc_cfg.vbc_seg_max = 0x100f0e0d;
	source.vbsc_cfg.vbc_geometry.cylinders = 0x1211;
	source.vbsc_cfg.vbc_geometry.heads = 0x13;
	source.vbsc_cfg.vbc_geometry.sectors = 0x14;
	source.vbsc_cfg.vbc_blk_size = 0x18171615;
	source.vbsc_cfg.vbc_topology.physical_block_exp = 0x19;
	source.vbsc_cfg.vbc_topology.alignment_offset = 0x1a;
	source.vbsc_cfg.vbc_topology.min_io_size = 0x1c1b;
	source.vbsc_cfg.vbc_topology.opt_io_size = 0x201f1e1d;
	source.vbsc_cfg.vbc_writeback = 1;
	source.vbsc_cfg.num_queues = 0x2322;
	source.vbsc_cfg.max_discard_sectors = 0x27262524;
	source.vbsc_cfg.max_discard_seg = 0x2b2a2928;
	source.vbsc_cfg.discard_sector_alignment = 0x2f2e2d2c;
	source.vbsc_cfg.max_write_zeroes_sectors = 0x33323130;
	source.vbsc_cfg.max_write_zeroes_seg = 0x37363534;
	source.vbsc_cfg.write_zeroes_may_unmap = 0x38;
	source.vbsc_vs.vs_negotiated_caps = VIRTIO14_BLK_F_CONFIG_WCE;
	memcpy(source.vbsc_ident, "portable-block", 14);
	ATF_REQUIRE_EQ(run_block_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(used, sizeof(expected));

	/*
	 * Independent version-3 wire fixture: the 8-byte record header is
	 * followed by 56 logical configuration bytes and the 21-byte identity.
	 * The final record is a little-endian bounded length and the explicit
	 * backend identity.  No production structure offsets or native scalar
	 * copies are used.
	 */
	memset(expected, 0, sizeof(expected));
	memcpy(expected, (const uint8_t[]){
	    'B', 'L', 'K', '1', 3, 0, 0, 0
	}, 8);
	for (size_t i = 0; i < 56; i++)
		expected[8 + i] = (uint8_t)(i + 1);
	/* writeback is constrained to 0/1, not the sequential fixture byte. */
	expected[8 + 32] = 1;
	memcpy(expected + 64, source.vbsc_ident,
	    sizeof(source.vbsc_ident));
	expected[85] = (uint8_t)BLOCK_TEST_ID_LENGTH;
	memcpy(expected + 89, BLOCK_TEST_ID, BLOCK_TEST_ID_LENGTH);
	ATF_CHECK(memcmp(image, expected, sizeof(expected)) == 0);

	setup_softc(&destination);
	destination.vbsc_cfg = source.vbsc_cfg;
	destination.vbsc_vs.vs_negotiated_caps =
	    VIRTIO14_BLK_F_CONFIG_WCE;
	memcpy(destination.vbsc_ident, source.vbsc_ident,
	    sizeof(destination.vbsc_ident));
	original = destination.vbsc_cfg;
	ATF_REQUIRE_EQ(run_block_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	ATF_CHECK_EQ(run_block_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	ATF_REQUIRE_EQ(run_block_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	g_checkpoint_identity = "different-backend";
	ATF_CHECK_EQ(run_block_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	g_checkpoint_identity = BLOCK_TEST_ID;

	/* Every obsolete pre-release encoding is rejected transactionally. */
	memcpy(obsolete, image, used);
	for (uint8_t obsolete_version = 1; obsolete_version <= 2;
	    obsolete_version++) {
		obsolete[4] = obsolete_version;
		ATF_CHECK_EQ(run_block_snapshot(&destination, obsolete, used,
		    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
		ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
		    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	}

	original = destination.vbsc_cfg;
	image[4] = 4;
	ATF_CHECK_EQ(run_block_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	ATF_CHECK_EQ(run_block_snapshot(&destination, image, 3,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);

	/*
	 * A record whose header is valid but whose body is truncated fails
	 * inside the logical-configuration decode rather than the identity
	 * record, exercising the mid-config error unwinding.  Restore the
	 * version byte first: an earlier case deliberately corrupted it.
	 */
	image[4] = 3;	/* VTBLK_SNAPSHOT_VERSION */
	ATF_CHECK_EQ(run_block_snapshot(&destination, image, 20,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
	    VIRTIO14_BLK_CONFIG_SIZE) == 0);

	/*
	 * A structurally complete image whose logical configuration does not
	 * match the destination backing store (here, a differing capacity) is
	 * rejected during load by the restore-validation guard.
	 */
	{
		uint8_t corrupt[512];

		memcpy(corrupt, image, used);
		/* Perturb the capacity field (config offset 0, image offset 8). */
		corrupt[8] ^= 0xff;
		ATF_CHECK_EQ(run_block_snapshot(&destination, corrupt, used,
		    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
		ATF_CHECK(memcmp(&destination.vbsc_cfg, &original,
		    VIRTIO14_BLK_CONFIG_SIZE) == 0);
	}

#undef BLOCK_TEST_ID_LENGTH
#undef BLOCK_TEST_ID
}

ATF_TC_WITHOUT_HEAD(modern_config_wire_endian);
ATF_TC_BODY(modern_config_wire_endian, tc)
{
	struct pci_vtblk_softc sc;
	uint8_t expected[VIRTIO14_BLK_CONFIG_SIZE];
	uint8_t actual[VIRTIO14_BLK_CONFIG_SIZE];
	uint32_t value;
	size_t offset;

	memset(&sc, 0, sizeof(sc));
	memset(expected, 0, sizeof(expected));
	memset(actual, 0, sizeof(actual));
	g_modern = true;
	sc.vbsc_cfg.vbc_capacity = UINT64_C(0x0102030405060708);
	sc.vbsc_cfg.vbc_size_max = UINT32_C(0x11121314);
	sc.vbsc_cfg.vbc_seg_max = UINT32_C(0x21222324);
	sc.vbsc_cfg.vbc_geometry.cylinders = UINT16_C(0x3132);
	sc.vbsc_cfg.vbc_blk_size = UINT32_C(0x41424344);
	sc.vbsc_cfg.vbc_topology.min_io_size = UINT16_C(0x5152);
	sc.vbsc_cfg.vbc_topology.opt_io_size = UINT32_C(0x61626364);
	sc.vbsc_cfg.num_queues = UINT16_C(0x7172);
	sc.vbsc_cfg.max_discard_sectors = UINT32_C(0x81828384);
	sc.vbsc_cfg.max_discard_seg = UINT32_C(0x91929394);
	sc.vbsc_cfg.discard_sector_alignment = UINT32_C(0xa1a2a3a4);
	sc.vbsc_cfg.max_write_zeroes_sectors = UINT32_C(0xb1b2b3b4);
	sc.vbsc_cfg.max_write_zeroes_seg = UINT32_C(0xc1c2c3c4);

	/*
	 * These offsets and encodings come from the section 5.2.4 wire
	 * layout, not from the implementation's structure representation.
	 */
	virtio14_store_le64(expected + 0, UINT64_C(0x0102030405060708));
	virtio14_store_le32(expected + 8, UINT32_C(0x11121314));
	virtio14_store_le32(expected + 12, UINT32_C(0x21222324));
	virtio14_store_le16(expected + 16, UINT16_C(0x3132));
	virtio14_store_le32(expected + 20, UINT32_C(0x41424344));
	virtio14_store_le16(expected + 26, UINT16_C(0x5152));
	virtio14_store_le32(expected + 28, UINT32_C(0x61626364));
	virtio14_store_le16(expected + 34, UINT16_C(0x7172));
	virtio14_store_le32(expected + 36, UINT32_C(0x81828384));
	virtio14_store_le32(expected + 40, UINT32_C(0x91929394));
	virtio14_store_le32(expected + 44, UINT32_C(0xa1a2a3a4));
	virtio14_store_le32(expected + 48, UINT32_C(0xb1b2b3b4));
	virtio14_store_le32(expected + 52, UINT32_C(0xc1c2c3c4));

	for (offset = 0; offset < sizeof(actual); offset += sizeof(value)) {
		ATF_REQUIRE_EQ(pci_vtblk_cfgread(&sc, offset, sizeof(value),
		    &value), 0);
		memcpy(actual + offset, &value,
		    MIN(sizeof(value), sizeof(actual) - offset));
	}
	ATF_CHECK(memcmp(actual, expected, sizeof(actual)) == 0);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
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

ATF_TC_WITHOUT_HEAD(suspend_backend_lifecycle);
ATF_TC_BODY(suspend_backend_lifecycle, tc)
{
	struct blockif_ctxt bc;
	struct pci_vtblk_softc sc;
	int error;

	reset_mocks();
	setup_softc(&sc);
	sc.bc = &bc;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);

	ATF_CHECK((vtblk_vi_consts.vc_hv_caps & VIRTIO_F_SUSPEND) != 0);
	ATF_CHECK(vtblk_vi_consts.vc_suspend == pci_vtblk_suspend_device);
	ATF_CHECK(vtblk_vi_consts.vc_resume_device ==
	    pci_vtblk_resume_device);
	ATF_CHECK(vtblk_vi_consts.vc_restore_suspended ==
	    pci_vtblk_restore_suspended);
	ATF_CHECK(vtblk_vi_consts.vc_restore_resumed ==
	    pci_vtblk_restore_resumed);

	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	error = pci_vtblk_suspend_device(&sc);
	ATF_CHECK_EQ(error, 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);

	/* Checkpoint ownership nests without releasing guest ownership. */
	ATF_REQUIRE_EQ(blockif_suspend(&bc), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 2);
	blockif_resume(&bc);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);
	pci_vtblk_restore_suspended(&sc);
	ATF_CHECK_EQ(g_blockif_pause_depth, 2);
	blockif_resume(&bc);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);

	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vtblk_resume_device(&sc), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);

	/*
	 * A runnable image can replace a destination that was guest-suspended
	 * when checkpoint pause began.  Its old guest owner is released before
	 * checkpoint resume drops the independent checkpoint owner.
	 */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(pci_vtblk_suspend_device(&sc), 0);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);
	ATF_REQUIRE_EQ(blockif_suspend(&bc), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 2);
	/* A future checkpoint device need not retain vsc_mtx around restore. */
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_REQUIRE_EQ(pci_vtblk_resume(&sc), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);
	pci_vtblk_restore_resumed(&sc);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);

	/* Failed quiesce does not leave backend ownership behind. */
	g_blockif_suspend_error = EIO;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(pci_vtblk_suspend_device(&sc), EIO);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);

	/* Reset is the recovery path from a suspended/failed-resume state. */
	g_blockif_suspend_error = 0;
	g_blockif_pause_depth = 1;
	sc.vbsc_vs.vs_suspended = true;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	pci_vtblk_reset(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);

	pthread_cond_destroy(&sc.vbsc_reset_cond);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(notify_drains_queue_budget);
ATF_TC_BODY(notify_drains_queue_budget, tc)
{
	struct pci_vtblk_softc sc;

	/*
	 * pci_vtblk_notify() must process available descriptors up to the
	 * queue-size budget and then end the chains.  Present three ready
	 * READ requests behind the same descriptor index and confirm each is
	 * handed to the backend exactly once.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_has_descs_budget = 3;
	pci_vtblk_notify(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 1);
	ATF_CHECK(g_end_calls >= 1);

	/* An empty queue still publishes an end-of-chains notification. */
	reset_mocks();
	setup_softc(&sc);
	g_has_descs_budget = 0;
	pci_vtblk_notify(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
}

ATF_TC_WITHOUT_HEAD(pause_acquires_device_lock);
ATF_TC_BODY(pause_acquires_device_lock, tc)
{
	struct blockif_ctxt bc;
	struct pci_vtblk_softc sc;

	reset_mocks();
	setup_softc(&sc);
	sc.bc = &bc;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);

	/* A successful quiesce leaves the device mutex held for the caller. */
	ATF_REQUIRE_EQ(pci_vtblk_pause(&sc), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 1);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), EBUSY);
	ATF_CHECK_EQ(pci_vtblk_resume(&sc), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);

	/* A failed quiesce reports the error and never takes the lock. */
	g_blockif_suspend_error = EIO;
	ATF_CHECK_EQ(pci_vtblk_pause(&sc), EIO);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);

	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(device_init_success_paths);
ATF_TC_BODY(device_init_success_paths, tc)
{
	struct pci_devinst pi;
	struct pci_vtblk_softc *sc;

	/*
	 * Legacy transport, MD5-derived identity, no resize monitoring.  The
	 * debug environment variable enables the verbose log path.
	 */
	reset_mocks();
	init_reset_controls();
	g_modern = false;
	ATF_REQUIRE_EQ(setenv("BHYVE_VTBLK_DEBUG", "1", 1), 0);
	memset(&pi, 0, sizeof(pi));
	pi.pi_slot = 3;
	pi.pi_func = 1;
	ATF_REQUIRE_EQ(pci_vtblk_init(&pi, NULL), 0);
	ATF_REQUIRE_EQ(unsetenv("BHYVE_VTBLK_DEBUG"), 0);
	pci_vtblk_debug = 0;
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vbsc_nqueues, 1);
	ATF_CHECK_EQ(sc->vbsc_cfg.vbc_capacity,
	    (uint64_t)g_open_size / VIRTIO14_BLK_SECTOR_BYTES);
	ATF_CHECK_EQ(sc->vbsc_cfg.vbc_blk_size, g_open_sectsz);
	/* seg_max is clamped below the ring size, per the Linux invariant. */
	ATF_CHECK_EQ(sc->vbsc_cfg.vbc_seg_max,
	    MIN(VTBLK_RINGSZ - 2, BLOCKIF_IOV_MAX));
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps & VTBLK_F_CONFIG_WCE) == 0);
	ATF_CHECK_EQ(g_boot_device_calls, 1);
	ATF_CHECK_EQ(g_resize_register_calls, 0);
	/* Legacy transitional identity is written to PCI config space. */
	ATF_CHECK_EQ(pi.pi_cfgdata[PCIR_CLASS], PCIC_STORAGE);
	ATF_CHECK(strncmp(sc->vbsc_ident, "BHYVE-", 6) == 0);
	destroy_softc(sc);

	/* Modern transport, explicit serial, multiqueue, resize monitoring. */
	reset_mocks();
	init_reset_controls();
	g_modern = true;
	g_cfg_queues = "4";
	g_cfg_serial = "SERIAL123";
	g_cfg_resize = true;
	g_open_psts = 4096;
	g_open_psto = 512;
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtblk_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vbsc_nqueues, 4);
	ATF_CHECK_EQ(sc->vbsc_cfg.num_queues, 4);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps & VTBLK_F_MQ) != 0);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps & VTBLK_F_CONFIG_WCE) != 0);
	ATF_CHECK_EQ(g_resize_register_calls, 1);
	ATF_CHECK(strcmp(sc->vbsc_ident, "SERIAL123") == 0);
	/* physical_block_exp reflects the 4096/512 backing ratio. */
	ATF_CHECK_EQ(sc->vbsc_cfg.vbc_topology.physical_block_exp, 3);
	destroy_softc(sc);

	/* Modern packed ring format negotiates the packed feature bit. */
	reset_mocks();
	init_reset_controls();
	g_modern = true;
	g_cfg_packed = true;
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtblk_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) != 0);
	destroy_softc(sc);
}

ATF_TC_WITHOUT_HEAD(device_init_failure_paths);
ATF_TC_BODY(device_init_failure_paths, tc)
{
	struct pci_devinst pi;

	/* An invalid queue count is rejected before the backend is opened. */
	reset_mocks();
	init_reset_controls();
	g_cfg_queues = "0";
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* A backend that cannot be opened fails initialization. */
	reset_mocks();
	init_reset_controls();
	g_open_return_null = 1;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* The first calloc (softc) failing takes the early-cleanup path. */
	reset_mocks();
	init_reset_controls();
	g_calloc_fail_after = 0;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* The second calloc (ioreq array) failing takes failed_early. */
	reset_mocks();
	init_reset_controls();
	g_calloc_fail_after = 1;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* Transport selection failure unwinds through the failed label. */
	reset_mocks();
	init_reset_controls();
	g_select_transport_error = EINVAL;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* Multiqueue on a legacy transport is rejected. */
	reset_mocks();
	init_reset_controls();
	g_modern = false;
	g_cfg_queues = "2";
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* Packed ring on a legacy transport is rejected. */
	reset_mocks();
	init_reset_controls();
	g_modern = false;
	g_cfg_packed = true;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* Interrupt setup failure unwinds without the boot-device call. */
	reset_mocks();
	init_reset_controls();
	g_intr_init_error = ENOSPC;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);
	ATF_CHECK_EQ(g_boot_device_calls, 0);

	/* Modern transport BAR setup failure unwinds. */
	reset_mocks();
	init_reset_controls();
	g_modern = true;
	g_modern_init_error = EIO;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);

	/* An invalid boot device unwinds after interrupt setup. */
	reset_mocks();
	init_reset_controls();
	g_add_boot_error = ENXIO;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);
	ATF_CHECK_EQ(g_boot_device_calls, 1);

	/* Resize-callback registration failure unwinds a fully-built device. */
	reset_mocks();
	init_reset_controls();
	g_cfg_resize = true;
	g_resize_register_error = EPERM;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtblk_init(&pi, NULL), 1);
	ATF_CHECK_EQ(g_resize_register_calls, 1);
}

ATF_TC_WITHOUT_HEAD(iov_helpers_and_edge_paths);
ATF_TC_BODY(iov_helpers_and_edge_paths, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;
	struct iovec in[3], out[8];
	uint8_t a[4] = { 1, 2, 3, 4 }, b[4] = { 5, 6, 7, 8 };
	uint8_t dst[8];
	size_t length;
	int count, error;

	/* iov_length overflows deterministically at SIZE_MAX. */
	in[0].iov_base = a;
	in[0].iov_len = SIZE_MAX;
	in[1].iov_base = b;
	in[1].iov_len = 1;
	ATF_CHECK_EQ(pci_vtblk_iov_length(in, 2, &length), EOVERFLOW);

	/* iov_read walks a leading skip across multiple segments. */
	in[0].iov_base = a;
	in[0].iov_len = 4;
	in[1].iov_base = b;
	in[1].iov_len = 4;
	ATF_CHECK(pci_vtblk_iov_read(in, 2, 2, dst, 4));
	ATF_CHECK_EQ(dst[0], 3);
	ATF_CHECK_EQ(dst[2], 5);
	/* A request longer than the mapped bytes cannot be satisfied. */
	ATF_CHECK(!pci_vtblk_iov_read(in, 2, 6, dst, 4));

	/* iov_slice returns E2BIG when the output vector is exhausted. */
	in[0].iov_base = a;
	in[0].iov_len = 2;
	in[1].iov_base = b;
	in[1].iov_len = 2;
	in[2].iov_base = a;
	in[2].iov_len = 2;
	error = pci_vtblk_iov_slice(in, 3, 0, 6, out, 1, &count);
	ATF_CHECK_EQ(error, E2BIG);
	/*
	 * iov_slice returns EINVAL when the source is shorter than requested
	 * even though the output vector has room for every segment.
	 */
	error = pci_vtblk_iov_slice(in, 3, 0, 100, out, 8, &count);
	ATF_CHECK_EQ(error, EINVAL);

	/*
	 * status_ptr is defensive against malformed chains that proc rejects
	 * earlier; exercise both refusal paths directly.  A chain whose
	 * readable+writable count disagrees returns no status pointer.
	 */
	{
		struct vi_req req;
		struct iovec sv[2];
		uint8_t byte = 0;
		uint8_t *status = NULL;

		memset(&req, 0, sizeof(req));
		req.readable = 1;
		req.writable = 1;
		sv[0].iov_base = &byte;
		sv[0].iov_len = 1;
		sv[1].iov_base = &byte;
		sv[1].iov_len = 1;
		ATF_CHECK(!pci_vtblk_status_ptr(&req, sv, 3, &status));
		/* A writable section that is entirely zero-length has no status. */
		req.readable = 1;
		req.writable = 1;
		sv[1].iov_len = 0;
		ATF_CHECK(!pci_vtblk_status_ptr(&req, sv, 2, &status));
	}

	/* A deadline of NULL is an immediate, unsuccessful drain. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);
	sc.vbsc_ios[0].io_active = true;
	ATF_CHECK(!pci_vtblk_wait_requests_drained_until(&sc, NULL));
	sc.vbsc_ios[0].io_active = false;
	/* With nothing outstanding the top-level wait returns success. */
	ATF_CHECK(pci_vtblk_wait_requests_drained(&sc));
	/*
	 * A future deadline with no outstanding request returns success without
	 * blocking, clearing the reset-waiting flag.
	 */
	{
		struct timespec future;

		ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &future), 0);
		future.tv_sec += 3600;
		ATF_CHECK(pci_vtblk_wait_requests_drained_until(&sc, &future));
		ATF_CHECK(!sc.vbsc_reset_waiting);
	}
	pthread_cond_destroy(&sc.vbsc_reset_cond);
	pthread_mutex_destroy(&sc.vsc_mtx);

	/*
	 * A stale backend completion arriving while a reset owner is blocked in
	 * the drain wait must wake that owner via the reset condition variable.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	/* Advance the device generation so the completion is treated as stale. */
	sc.vbsc_generation++;
	sc.vbsc_reset_waiting = true;
	pci_vtblk_done(&io->io_req, 0);
	ATF_CHECK(!io->io_active);
	ATF_CHECK_EQ(g_rel_calls, 0);
	pthread_cond_destroy(&sc.vbsc_reset_cond);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(proc_and_reset_error_branches);
ATF_TC_BODY(proc_and_reset_error_branches, tc)
{
	struct pci_vtblk_softc sc;
	struct pci_vtblk_ioreq *io;

	/* A queue index beyond the configured count is rejected. */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	sc.vbsc_vqs[0].vq_num = 5;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 0);
	/* A well-formed chain still gets a status byte written by the reject. */
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);

	/* A descriptor index at or beyond the ring size is rejected. */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_req.idx = VTBLK_RINGSZ;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 0);

	/* A request slot already in flight cannot be reused. */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	sc.vbsc_ios[g_req.idx].io_active = true;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);
	ATF_CHECK_EQ(g_rel_len, 1);

	/* A write whose writable section is not exactly the status byte fails. */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_WRITE);
	g_chain_n = 3;
	g_req.readable = 1;
	g_req.writable = 2;
	g_iov[1].iov_base = g_data;
	g_iov[1].iov_len = VTBLK_BSIZE;
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_writes, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);

	/* backend_caps advertises DISCARD only when the backend can delete. */
	g_backend_readonly = 0;
	g_backend_candelete = 1;
	ATF_CHECK((pci_vtblk_backend_caps(NULL) & VTBLK_F_DISCARD) != 0);

	/*
	 * A READ whose writable data span exceeds SSIZE_MAX is rejected before
	 * the backend is reached.  The oversized length is a pure arithmetic
	 * value describing a data descriptor that is only ever pointer-sliced,
	 * never dereferenced; the real status byte sits in a valid tail
	 * descriptor so completion can record the error safely.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_READ);
	g_chain_n = 3;
	g_req.readable = 1;
	g_req.writable = 2;
	g_iov[0].iov_base = &g_header;
	g_iov[0].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE;
	g_iov[1].iov_base = g_data;
	g_iov[1].iov_len = (size_t)SSIZE_MAX + 1;
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_backend_reads, 0);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);

	/*
	 * A GET_ID whose writable span exceeds the 32-bit used-length range is
	 * rejected; the response length must fit the transport counter.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_header.vbh_type = htole32(VBH_OP_IDENT);
	g_chain_n = 3;
	g_req.readable = 1;
	g_req.writable = 2;
	g_iov[0].iov_base = &g_header;
	g_iov[0].iov_len = VIRTIO14_BLK_REQUEST_HEADER_SIZE;
	g_iov[1].iov_base = g_data;
	g_iov[1].iov_len = (size_t)UINT32_MAX;
	g_iov[2].iov_base = &g_status;
	g_iov[2].iov_len = 1;
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	ATF_CHECK_EQ(g_status, VTBLK_S_IOERR);

	/*
	 * Legacy cache-mode selection at DRIVER_OK (section 5.2.5.3): without
	 * CONFIG_WCE, negotiating FLUSH implies writeback and its absence
	 * implies writethrough.  These oracles are the specification rule, not
	 * the implementation output.
	 */
	reset_mocks();
	setup_softc(&sc);
	g_modern = false;
	sc.vbsc_cfg.vbc_writeback = 0;
	pci_vtblk_neg_features(&sc, VTBLK_F_FLUSH);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, VTBLK_DEFAULT_WRITEBACK);
	sc.vbsc_cfg.vbc_writeback = VTBLK_DEFAULT_WRITEBACK;
	pci_vtblk_neg_features(&sc, 0);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, 0);

	/*
	 * Modern initialization (section 5.2.5.2): any negotiation other than
	 * CONFIG_WCE-without-FLUSH starts in writeback.
	 */
	g_modern = true;
	sc.vbsc_cfg.vbc_writeback = 0;
	pci_vtblk_neg_features(&sc, VTBLK_F_CONFIG_WCE | VTBLK_F_FLUSH);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_writeback, VTBLK_DEFAULT_WRITEBACK);
	g_modern = false;

	/*
	 * A full reset whose cancellation returns an unexpected error marks
	 * the device as needing a reset.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	g_cancel_error = EIO;
	pthread_mutex_lock(&sc.vsc_mtx);
	pci_vtblk_reset(&sc);
	pthread_mutex_unlock(&sc.vsc_mtx);
	ATF_CHECK(g_needs_reset_calls >= 1);
	pthread_cond_destroy(&sc.vbsc_reset_cond);
	pthread_mutex_destroy(&sc.vsc_mtx);

	/*
	 * A queue reset whose cancellation returns an unexpected error is
	 * surfaced verbatim and leaves the reset owner released.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.vbsc_reset_cond, NULL), 0);
	g_header.vbh_type = htole32(VBH_OP_READ);
	pci_vtblk_proc(&sc, &sc.vbsc_vqs[0]);
	io = &sc.vbsc_ios[g_req.idx];
	ATF_REQUIRE(io->io_active);
	g_cancel_error = EIO;
	sc.vbsc_vqs[0].vq_generation++;
	pthread_mutex_lock(&sc.vsc_mtx);
	ATF_CHECK_EQ(pci_vtblk_qreset(&sc, &sc.vbsc_vqs[0], 99), EIO);
	ATF_CHECK(!sc.vbsc_resetting);
	pthread_mutex_unlock(&sc.vsc_mtx);
	io->io_active = false;
	pthread_cond_destroy(&sc.vbsc_reset_cond);
	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(restore_resumed_holds_lock);
ATF_TC_BODY(restore_resumed_holds_lock, tc)
{
	struct blockif_ctxt bc;
	struct pci_vtblk_softc sc;

	/*
	 * When restore_resumed runs with the device mutex already held it must
	 * drop it across blockif_resume() and reacquire it before returning.
	 */
	reset_mocks();
	setup_softc(&sc);
	sc.bc = &bc;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	g_blockif_pause_depth = 1;
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vsc_mtx), 0);
	pci_vtblk_restore_resumed(&sc);
	/* The lock is held again on return. */
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), EBUSY);
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vsc_mtx), 0);
	ATF_CHECK_EQ(g_blockif_pause_depth, 0);
	pthread_mutex_destroy(&sc.vsc_mtx);

	/*
	 * resume_complete may run without the mutex held (checkpoint resume);
	 * it must then take and release the VirtIO lock itself while publishing
	 * a deferred capacity.
	 */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vbsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vbsc_capacity_pending = true;
	sc.vbsc_pending_capacity = 64;
	pci_vtblk_resume_complete(&sc);
	ATF_CHECK_EQ(sc.vbsc_cfg.vbc_capacity, 64);
	ATF_CHECK(!sc.vbsc_capacity_pending);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vsc_mtx), 0);
	pthread_mutex_unlock(&sc.vsc_mtx);
	pthread_mutex_destroy(&sc.vsc_mtx);

	/* snapshot_validate rejects a device instance with no softc. */
	{
		struct pci_devinst pi;
		struct vm_snapshot_meta meta = {
			.dev_data = &pi,
			.op = VM_SNAPSHOT_VALIDATE,
		};
		memset(&pi, 0, sizeof(pi));
		pi.pi_arg = NULL;
		ATF_CHECK_EQ(pci_vtblk_snapshot_validate(&meta), EINVAL);
		meta.op = VM_SNAPSHOT_SAVE;
		meta.dev_data = &pi;
		pi.pi_arg = &sc;
		ATF_CHECK_EQ(pci_vtblk_snapshot_validate(&meta), EINVAL);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, malformed_chains);
	ATF_TP_ADD_TC(tp, opcode_layouts);
	ATF_TP_ADD_TC(tp, split_request_fields);
	ATF_TP_ADD_TC(tp, backend_and_range_errors);
	ATF_TP_ADD_TC(tp, discard_validation);
	ATF_TP_ADD_TC(tp, flush_requires_negotiation);
	ATF_TP_ADD_TC(tp, write_zeroes_validation);
	ATF_TP_ADD_TC(tp, backend_capabilities);
	ATF_TP_ADD_TC(tp, readonly_and_stable_writes);
	ATF_TP_ADD_TC(tp, reset_discards_outstanding_io);
	ATF_TP_ADD_TC(tp, reset_drain_timeout_is_bounded);
	ATF_TP_ADD_TC(tp, resize_notifies_configuration_change);
	ATF_TP_ADD_TC(tp, queue_reset_drains_async_io);
	ATF_TP_ADD_TC(tp, full_reset_waits_for_async_queue_reset);
	ATF_TP_ADD_TC(tp, queue_reset_cancels_pending_io);
	ATF_TP_ADD_TC(tp, multiqueue_reset_isolation);
	ATF_TP_ADD_TC(tp, multiqueue_document_contract);
	ATF_TP_ADD_TC(tp, multiqueue_option_validation);
	ATF_TP_ADD_TC(tp, packed_ring_option_validation);
	ATF_TP_ADD_TC(tp, write_cache_configuration);
	ATF_TP_ADD_TC(tp, config_read_bounds);
	ATF_TP_ADD_TC(tp, snapshot_backing_identity);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, snapshot_wire_and_version);
	ATF_TP_ADD_TC(tp, modern_config_wire_endian);
	ATF_TP_ADD_TC(tp, document_wire_vectors);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, suspend_backend_lifecycle);
	ATF_TP_ADD_TC(tp, notify_drains_queue_budget);
	ATF_TP_ADD_TC(tp, pause_acquires_device_lock);
	ATF_TP_ADD_TC(tp, device_init_success_paths);
	ATF_TP_ADD_TC(tp, device_init_failure_paths);
	ATF_TP_ADD_TC(tp, iov_helpers_and_edge_paths);
	ATF_TP_ADD_TC(tp, proc_and_reset_error_branches);
	ATF_TP_ADD_TC(tp, restore_resumed_holds_lock);
	return (atf_no_error());
}

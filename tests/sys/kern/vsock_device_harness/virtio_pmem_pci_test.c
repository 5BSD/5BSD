/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct composition and lifecycle tests for the VirtIO 1.4 PMEM device.
 */
#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "pci_emul.h"
#undef PCI_EMUL_SET
#define PCI_EMUL_SET(name)

/* Exercise the production timeout path without making this unit case wait
 * for the production thirty-second lifecycle bound. */
#define	VTPMEM_DRAIN_TIMEOUT_MS	50U

#define virtio_pmem_worker_defer_reset test_worker_defer_reset
#include "pci_virtio_pmem.c"
#undef virtio_pmem_worker_defer_reset
#include "virtio_1_4_spec.h"
#include "virtio_config_read_test_support.h"

int	virtio_pmem_worker_defer_reset(struct virtio_pmem_worker *, bool);

#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define VIRTIO_CONFIG_S_NEEDS_RESET VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_ID_PMEM
#define VIRTIO_ID_PMEM VIRTIO14_PMEM_DEVICE_ID

#define	PMEM_TEST_IDENTITY	"pmem-test"
#define	PMEM_SNAPSHOT_FIXED_SIZE	16U
#define	SNAPSHOT_META_INITIALIZER(OP, BUFFER, LENGTH) \
	{ \
		.buffer = { \
			.buf_start = (BUFFER), \
			.buf_size = (LENGTH), \
			.buf = (BUFFER), \
			.buf_rem = (LENGTH), \
		}, \
		.op = (OP), \
	}

static unsigned int g_needs_reset_calls;
static int g_worker_defer_reset_error;

int
test_worker_defer_reset(struct virtio_pmem_worker *worker, bool resume)
{

	if (g_worker_defer_reset_error != 0)
		return (g_worker_defer_reset_error);
	return (virtio_pmem_worker_defer_reset(worker, resume));
}

static void
snapshot_meta_reset(struct vm_snapshot_meta *meta, enum vm_snapshot_op op,
    void *buffer, size_t length)
{

	meta->op = op;
	meta->buffer.buf = buffer;
	meta->buffer.buf_rem = length;
}

void
vm_snapshot_buf_err(const char *name __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (meta == NULL || size > meta->buffer.buf_rem)
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
		bytes[0] = (uint8_t)*value;
		bytes[1] = (uint8_t)(*value >> 8);
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
			bytes[i] = (uint8_t)(*value >> (i * 8));
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
			bytes[i] = (uint8_t)(*value >> (i * 8));
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint64_t)bytes[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused,
    void **addr __unused, size_t length __unused, bool restore_null __unused,
    struct vm_snapshot_meta *meta __unused)
{

	return (ENOTSUP);
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	g_needs_reset_calls++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

void
vi_pci_notify_ready_queues(struct virtio_softc *vs __unused)
{
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov __unused,
    int niov __unused, struct vi_req *req __unused)
{

	return (0);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t index __unused,
    uint32_t length __unused)
{
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{
}

static void
create_backing(char path[static 32], struct pci_vtpmem_softc *sc)
{
	int fd;

	strlcpy(path, "/tmp/virtio-pmem-pci.XXXXXX", 32);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 8192), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	memset(sc, 0, sizeof(*sc));
	virtio_pmem_backing_init(&sc->vsc_backing);
	ATF_REQUIRE_EQ(virtio_pmem_backing_open(&sc->vsc_backing, path), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->vsc_mtx, NULL), 0);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	sc->vsc_consts = vtpmem_vi_consts;
	sc->vsc_vs.vs_vc = &sc->vsc_consts;
	sc->vsc_identity = strdup(PMEM_TEST_IDENTITY);
	ATF_REQUIRE(sc->vsc_identity != NULL);
}

static void
destroy_backing(const char *path, struct pci_vtpmem_softc *sc)
{

	if (sc->vsc_worker != NULL)
		ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(sc->vsc_worker, 1000),
		    0);
	virtio_pmem_backing_close(&sc->vsc_backing);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc->vsc_mtx), 0);
	free(sc->vsc_identity);
	ATF_REQUIRE_EQ(unlink(path), 0);
}

static void
create_worker(struct pci_vtpmem_softc *sc)
{
	struct virtio_pmem_worker_ops ops;

	ops = (struct virtio_pmem_worker_ops) {
		.flush = pci_vtpmem_flush,
		.complete = pci_vtpmem_complete,
		.arg = sc,
	};
	ATF_REQUIRE_EQ(virtio_pmem_worker_create(4, &ops, &sc->vsc_worker), 0);
}

struct blocked_worker_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool entered;
	bool release;
};

static int
blocked_worker_flush(void *arg)
{
	struct blocked_worker_context *context;

	context = arg;
	pthread_mutex_lock(&context->mutex);
	context->entered = true;
	pthread_cond_broadcast(&context->condition);
	while (!context->release)
		pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
	return (0);
}

static void
blocked_worker_complete(void *arg __unused, uintptr_t token __unused,
    uint64_t epoch __unused, int error __unused)
{
}

static void
blocked_worker_wait_entered(struct blocked_worker_context *context)
{

	pthread_mutex_lock(&context->mutex);
	while (!context->entered)
		pthread_cond_wait(&context->condition, &context->mutex);
	pthread_mutex_unlock(&context->mutex);
}

ATF_TC_WITHOUT_HEAD(pci_contract);
ATF_TC_BODY(pci_contract, tc)
{
	struct pci_devinst pi;
	struct pci_vtpmem_softc sc;
	uint32_t value;
	uint64_t bar_size;

	memset(&sc, 0, sizeof(sc));
	memset(&pi, 0, sizeof(pi));
	sc.vsc_backing.size = 8192;
	sc.vsc_vs.vs_pi = &pi;
	pi.pi_bar[VTPMEM_SHMEM_BAR].type = PCIBAR_MEM64;
	pi.pi_bar[VTPMEM_SHMEM_BAR].addr = UINT64_C(0x12345678000);
	ATF_CHECK_EQ(VIRTIO_ID_PMEM, VIRTIO14_PMEM_DEVICE_ID);
	ATF_CHECK_EQ(VTPMEM_SHMEM_REGION_ID, VIRTIO14_PMEM_SHMEM_REGION_ID);
	ATF_CHECK_EQ(vtpmem_vi_consts.vc_nvq, 1);
	ATF_CHECK_EQ(vtpmem_vi_consts.vc_cfgsize,
	    VIRTIO14_PMEM_CONFIG_SIZE);
	ATF_CHECK_EQ(VTPMEM_RINGSZ, 128);
	ATF_CHECK_EQ(vtpmem_vi_consts.vc_hv_caps,
	    (UINT64_C(1) << VIRTIO14_PMEM_F_SHMEM_REGION) |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND);
	ATF_CHECK((vtpmem_vi_consts.vc_hv_caps & VIRTIO14_F_IN_ORDER) == 0);
	ATF_CHECK_EQ(pci_vtpmem_apply_features(&sc,
	    UINT64_C(1) << VIRTIO14_PMEM_F_SHMEM_REGION), 0);
	ATF_CHECK_EQ(pci_vtpmem_apply_features(&sc, 0), 0);
	sc.vsc_vs.vs_negotiated_caps =
	    UINT64_C(1) << VIRTIO14_PMEM_F_SHMEM_REGION;
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 12, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	sc.vsc_vs.vs_negotiated_caps = 0;
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x45678000));
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 4, 4, &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x123));
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 8, 4, &value), 0);
	ATF_CHECK_EQ(value, 8192);
	ATF_REQUIRE_EQ(pci_vtpmem_cfgread(&sc, 12, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_vtpmem_cfgread(&sc, 16, 1, &value), EINVAL);
	ATF_REQUIRE_EQ(pci_vtpmem_bar_size(4097, &bar_size), 0);
	ATF_CHECK_EQ(bar_size, 8192);
	ATF_CHECK_EQ(pci_vtpmem_bar_size(0, &bar_size), EINVAL);
	if (SIZE_MAX == UINT64_MAX)
		ATF_CHECK_EQ(pci_vtpmem_bar_size(SIZE_MAX, &bar_size), EOVERFLOW);
	else {
		ATF_REQUIRE_EQ(pci_vtpmem_bar_size(SIZE_MAX, &bar_size), 0);
		ATF_CHECK_EQ(bar_size, UINT64_C(1) << 32);
	}
}

ATF_TC_WITHOUT_HEAD(lifecycle_flush_is_durable);
ATF_TC_BODY(lifecycle_flush_is_durable, tc)
{
	struct pci_vtpmem_softc sc;
	uint8_t actual[32], expected[32];
	char path[32];
	int fd;

	create_backing(path, &sc);
	create_worker(&sc);
	memset(expected, 0x5a, sizeof(expected));
	memcpy((uint8_t *)sc.vsc_backing.mapping + 4096, expected,
	    sizeof(expected));
	VS_LOCK(&sc.vsc_vs);
	ATF_REQUIRE_EQ(pci_vtpmem_stabilize_locked(&sc), 0);
	VS_UNLOCK(&sc.vsc_vs);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(pread(fd, actual, sizeof(actual), 4096),
	    (ssize_t)sizeof(actual));
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_CHECK_EQ(memcmp(actual, expected, sizeof(actual)), 0);
	destroy_backing(path, &sc);
}

ATF_TC_WITHOUT_HEAD(lifecycle_failure_is_reported_and_recoverable);
ATF_TC_BODY(lifecycle_failure_is_reported_and_recoverable, tc)
{
	struct pci_vtpmem_softc sc;
	char path[32];
	int fd;

	create_backing(path, &sc);
	create_worker(&sc);
	fd = open(path, O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 4096), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	VS_LOCK(&sc.vsc_vs);
	ATF_CHECK_EQ(pci_vtpmem_stabilize_locked(&sc), EINVAL);
	VS_UNLOCK(&sc.vsc_vs);
	ATF_REQUIRE_EQ(virtio_pmem_worker_abort_pause(sc.vsc_worker), 0);
	fd = open(path, O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 8192), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	VS_LOCK(&sc.vsc_vs);
	ATF_CHECK_EQ(pci_vtpmem_stabilize_locked(&sc), 0);
	VS_UNLOCK(&sc.vsc_vs);
	destroy_backing(path, &sc);
}

ATF_TC_WITHOUT_HEAD(lifecycle_rollback_failure_needs_reset);
ATF_TC_BODY(lifecycle_rollback_failure_needs_reset, tc)
{
	struct blocked_worker_context context;
	struct virtio_pmem_worker_ops ops;
	struct pci_vtpmem_softc sc;
	uint64_t epoch;

	memset(&sc, 0, sizeof(sc));
	memset(&context, 0, sizeof(context));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&context.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context.condition, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	ops = (struct virtio_pmem_worker_ops) {
		.flush = blocked_worker_flush,
		.complete = blocked_worker_complete,
		.arg = &context,
	};
	ATF_REQUIRE_EQ(virtio_pmem_worker_create(1, &ops, &sc.vsc_worker), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(sc.vsc_worker, 1, &epoch), 0);
	blocked_worker_wait_entered(&context);
	ATF_REQUIRE_EQ(virtio_pmem_worker_reset(sc.vsc_worker, 1, true),
	    ETIMEDOUT);
	ATF_REQUIRE_EQ(virtio_pmem_worker_defer_reset(sc.vsc_worker, true), 0);
	g_needs_reset_calls = 0;

	ATF_CHECK_EQ(pci_vtpmem_pause(&sc), EIO);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	pthread_mutex_lock(&context.mutex);
	context.release = true;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(sc.vsc_worker, 1000), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&context.condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&context.mutex), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(deferred_reset_failure_needs_reset);
ATF_TC_BODY(deferred_reset_failure_needs_reset, tc)
{
	struct pci_vtpmem_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_consts.vc_name = "vtpmem-test";
	g_needs_reset_calls = 0;
	g_worker_defer_reset_error = EIO;
	pci_vtpmem_defer_reset_after_timeout(&sc);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	g_worker_defer_reset_error = 0;
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_is_canonical_and_repeatable);
ATF_TC_BODY(snapshot_wire_is_canonical_and_repeatable, tc)
{
	static const uint8_t expected[] = {
		0x50, 0x4d, 0x4d, 0x31,	/* magic, little endian */
		0x01, 0x00, 0x00, 0x00,	/* version */
		0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, 0x00,
		'p', 'm', 'e', 'm', '-', 't', 'e', 's', 't'
	};
	struct pci_vtpmem_softc sc;
	uint8_t record[sizeof(expected)];
	struct vm_snapshot_meta meta = SNAPSHOT_META_INITIALIZER(
	    VM_SNAPSHOT_SAVE, record, sizeof(record));
	char path[32];

	create_backing(path, &sc);
	memset(record, 0xa5, sizeof(record));
	snapshot_meta_reset(&meta, VM_SNAPSHOT_SAVE, record, sizeof(record));
	ATF_REQUIRE_EQ(pci_vtpmem_snapshot(&sc, &meta), 0);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
	ATF_CHECK_EQ(memcmp(record, expected, sizeof(record)), 0);

	for (unsigned int i = 0; i < 2; i++) {
		snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, record,
		    sizeof(record));
		ATF_REQUIRE_EQ(pci_vtpmem_snapshot(&sc, &meta), 0);
		ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
		snapshot_meta_reset(&meta, VM_SNAPSHOT_RESTORE, record,
		    sizeof(record));
		ATF_REQUIRE_EQ(pci_vtpmem_snapshot(&sc, &meta), 0);
		ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
		ATF_CHECK_EQ(sc.vsc_backing.size, 8192);
		ATF_CHECK_STREQ(sc.vsc_identity, PMEM_TEST_IDENTITY);
	}
	destroy_backing(path, &sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_mismatch_and_truncation);
ATF_TC_BODY(snapshot_rejects_mismatch_and_truncation, tc)
{
	enum {
		RECORD_SIZE = PMEM_SNAPSHOT_FIXED_SIZE + 4 +
		    sizeof(PMEM_TEST_IDENTITY) - 1
	};
	struct pci_vtpmem_softc sc;
	uint8_t altered[RECORD_SIZE], record[RECORD_SIZE];
	struct vm_snapshot_meta meta = SNAPSHOT_META_INITIALIZER(
	    VM_SNAPSHOT_SAVE, record, sizeof(record));
	char path[32];

	create_backing(path, &sc);
	snapshot_meta_reset(&meta, VM_SNAPSHOT_SAVE, record, sizeof(record));
	ATF_REQUIRE_EQ(pci_vtpmem_snapshot(&sc, &meta), 0);

	memcpy(altered, record, sizeof(altered));
	altered[0] ^= 1;
	snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, altered,
	    sizeof(altered));
	ATF_CHECK_EQ(pci_vtpmem_snapshot(&sc, &meta), EINVAL);

	memcpy(altered, record, sizeof(altered));
	altered[4] = 2;
	snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, altered,
	    sizeof(altered));
	ATF_CHECK_EQ(pci_vtpmem_snapshot(&sc, &meta), EINVAL);

	/* The common magic/version prefix alone must reject an unknown format. */
	memcpy(altered, record, 8);
	altered[4] = 2;
	snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, altered, 8);
	ATF_CHECK_EQ(pci_vtpmem_snapshot(&sc, &meta), EINVAL);

	memcpy(altered, record, sizeof(altered));
	altered[8] ^= 1;
	snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, altered,
	    sizeof(altered));
	ATF_CHECK_EQ(pci_vtpmem_snapshot(&sc, &meta), EINVAL);

	memcpy(altered, record, sizeof(altered));
	altered[PMEM_SNAPSHOT_FIXED_SIZE + 4] ^= 1;
	snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, altered,
	    sizeof(altered));
	ATF_CHECK_EQ(pci_vtpmem_snapshot(&sc, &meta), EINVAL);

	for (size_t length = 0; length < sizeof(record); length++) {
		snapshot_meta_reset(&meta, VM_SNAPSHOT_VALIDATE, record, length);
		ATF_CHECK_MSG(pci_vtpmem_snapshot(&sc, &meta) == E2BIG,
		    "truncated PMEM snapshot accepted at length %zu", length);
	}
	ATF_CHECK_EQ(sc.vsc_backing.size, 8192);
	ATF_CHECK_STREQ(sc.vsc_identity, PMEM_TEST_IDENTITY);
	destroy_backing(path, &sc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pci_contract);
	ATF_TP_ADD_TC(tp, lifecycle_flush_is_durable);
	ATF_TP_ADD_TC(tp, lifecycle_failure_is_reported_and_recoverable);
	ATF_TP_ADD_TC(tp, lifecycle_rollback_failure_needs_reset);
	ATF_TP_ADD_TC(tp, deferred_reset_failure_needs_reset);
	ATF_TP_ADD_TC(tp, snapshot_wire_is_canonical_and_repeatable);
	ATF_TP_ADD_TC(tp, snapshot_rejects_mismatch_and_truncation);
	return (atf_no_error());
}

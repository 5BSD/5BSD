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
#define virtio_pmem_worker_destroy test_worker_destroy
#include "pci_virtio_pmem.c"
#undef virtio_pmem_worker_defer_reset
#undef virtio_pmem_worker_destroy
#include "virtio_1_4_spec.h"
#include "virtio_config_read_test_support.h"

int	virtio_pmem_worker_defer_reset(struct virtio_pmem_worker *, bool);
int	virtio_pmem_worker_destroy(struct virtio_pmem_worker *, uint32_t);

/*
 * Fault injection for pci_vtpmem_init().  The production worker-destroy in the
 * init failure path only fails when a flush is wedged in the backend, which
 * cannot be arranged during init (no request is ever submitted there).  Force
 * the return value so the deliberate-leak / no-teardown path is exercised.
 */
static bool g_force_worker_destroy_error;

int
test_worker_destroy(struct virtio_pmem_worker *worker, uint32_t timeout_ms)
{

	if (g_force_worker_destroy_error)
		return (EBUSY);
	return (virtio_pmem_worker_destroy(worker, timeout_ms));
}

/*
 * calloc(3) wrapper (installed via -Wl,--wrap=calloc).  The arm flag is
 * thread-local, so it diverts only the next allocation made on the thread that
 * armed it -- the device model's synchronous request-object allocation on the
 * notify/caller thread.  The profiling runtime, ATF, and the async worker
 * threads' own bookkeeping run on other threads and are never perturbed.  This
 * keeps the stimulus independent of any production struct layout while letting
 * the ENOMEM admission branches be reached deterministically.
 */
static _Thread_local bool g_fail_request_calloc;

void	*__real_calloc(size_t, size_t);
void	*__wrap_calloc(size_t, size_t);

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (g_fail_request_calloc) {
		g_fail_request_calloc = false;
		return (NULL);
	}
	return (__real_calloc(nmemb, size));
}

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

/*
 * Scripted virtqueue feeder.  When g_vq.active is false the mocks report an
 * empty ring (the historical behaviour every existing case relies on).  When
 * active, vq_getchain hands back one crafted chain per call and records the
 * relchain/endchains publications so a case can assert what the device model
 * did with a request.
 */
static struct {
	bool active;
	int descs;		/* chains still available */
	int getchain_ret;	/* <= 0: returned verbatim (error/empty) */
	uint8_t reqbuf[16];
	uint8_t respbuf[16];
	struct iovec iov[VTPMEM_MAX_IOV];
	int niov;
	int readable;
	int writable;
	bool ordered;
	uint64_t queue_generation;
	unsigned int relchain_calls;
	uint32_t last_relchain_len;
	unsigned int endchains_calls;
} g_vq;

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	if (!g_vq.active)
		return (0);
	return (g_vq.descs > 0);
}

int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{

	if (!g_vq.active || g_vq.descs <= 0)
		return (0);
	g_vq.descs--;
	if (g_vq.getchain_ret <= 0)
		return (g_vq.getchain_ret);
	memset(req, 0, sizeof(*req));
	for (int i = 0; i < g_vq.niov && i < niov; i++)
		iov[i] = g_vq.iov[i];
	req->readable = g_vq.readable;
	req->writable = g_vq.writable;
	req->ordered = g_vq.ordered;
	req->idx = 1;
	req->queue_generation = g_vq.queue_generation;
	if (vq != NULL)
		vq->vq_generation = g_vq.queue_generation;
	return (g_vq.getchain_ret);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t index __unused,
    uint32_t length)
{

	g_vq.relchain_calls++;
	g_vq.last_relchain_len = length;
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all __unused)
{

	g_vq.endchains_calls++;
}

/*
 * Transport / config mocks used only by the pci_vtpmem_init() composition
 * tests.  pci_de_vtpmem is unreferenced in this TU (PCI_EMUL_SET is nulled),
 * so init and every helper it names are dead-code-eliminated unless a case
 * calls init directly; these stubs supply that call graph and let each
 * initialization step be individually failed.
 */
static struct {
	const char *path;
	const char *id;
	bool packed;
	int fail_select_transport;
	int fail_intr_init;
	int fail_modern_init;
	int fail_alloc_bar;
	int fail_add_shmem;
	int fail_set_backing;
} g_init;

const char *
get_config_value_node(const nvlist_t *parent __unused, const char *name)
{

	if (strcmp(name, "path") == 0)
		return (g_init.path);
	if (strcmp(name, "id") == 0)
		return (g_init.id);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *parent __unused,
    const char *name __unused, bool def __unused)
{

	return (g_init.packed);
}

int
fbsdrun_virtio_msix(void)
{

	return (0);
}

void
pci_set_cfgdata8(struct pci_devinst *pi __unused, int offset __unused,
    uint8_t value __unused)
{
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc, void *sc,
    struct pci_devinst *pi, struct vqueue_info *queues)
{

	vs->vs_vc = vc;
	vs->vs_pi = pi;
	pi->pi_arg = sc;
	(void)queues;
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy)
{

	ATF_REQUIRE_EQ(policy, VIRTIO_PCI_MODERN_ONLY);
	return (g_init.fail_select_transport);
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (g_init.fail_intr_init != 0)
		return (g_init.fail_intr_init);
	ATF_REQUIRE_EQ(pthread_mutex_init(&vs->vs_isr_mtx, NULL), 0);
	return (0);
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int barnum __unused)
{

	return (g_init.fail_modern_init);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t device_id __unused)
{
}

int
vi_pci_modern_add_shared_memory(struct virtio_softc *vs __unused,
    uint8_t region_id __unused, uint8_t barnum __unused, uint64_t offset __unused,
    uint64_t length __unused)
{

	return (g_init.fail_add_shmem);
}

int
vi_pci_modern_set_shared_memory_backing(struct virtio_softc *vs __unused,
    uint8_t region_id __unused, void *mapping __unused, uint64_t length __unused,
    bool writable __unused)
{

	return (g_init.fail_set_backing);
}

void
vi_pci_modern_seal_shared_memory(struct virtio_softc *vs __unused)
{
}

int
pci_emul_alloc_bar(struct pci_devinst *pdi __unused, int idx __unused,
    enum pcibar_type type __unused, uint64_t size __unused)
{

	return (g_init.fail_alloc_bar);
}

static void
init_defaults(const char *path)
{

	memset(&g_init, 0, sizeof(g_init));
	g_init.path = path;
	g_init.id = PMEM_TEST_IDENTITY;
	g_force_worker_destroy_error = false;
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

static void
vq_script_flush_chain(uint32_t type)
{

	memset(&g_vq, 0, sizeof(g_vq));
	g_vq.active = true;
	g_vq.descs = 1;
	g_vq.getchain_ret = 2;
	le32enc(g_vq.reqbuf, type);
	g_vq.iov[0].iov_base = g_vq.reqbuf;
	g_vq.iov[0].iov_len = BHYVE_VIRTIO_PMEM_REQUEST_SIZE;
	g_vq.iov[1].iov_base = g_vq.respbuf;
	g_vq.iov[1].iov_len = BHYVE_VIRTIO_PMEM_RESPONSE_SIZE;
	g_vq.niov = 2;
	g_vq.readable = 1;
	g_vq.writable = 1;
	g_vq.ordered = true;
}

/*
 * A well-formed FLUSH descriptor is submitted to the worker, executed against
 * the durable backing, and its response descriptor is published exactly once.
 */
ATF_TC_WITHOUT_HEAD(notify_flush_request_round_trip);
ATF_TC_BODY(notify_flush_request_round_trip, tc)
{
	struct pci_vtpmem_softc sc;
	struct vqueue_info vq;
	char path[32];

	create_backing(path, &sc);
	create_worker(&sc);
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = 8;
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	g_needs_reset_calls = 0;

	pci_vtpmem_notify(&sc, &vq);
	/* Drain so the asynchronous completion publishes before we assert. */
	ATF_REQUIRE_EQ(virtio_pmem_worker_reset(sc.vsc_worker, 1000, true), 0);

	ATF_CHECK_EQ(g_vq.relchain_calls, 1);
	ATF_CHECK_EQ(g_vq.last_relchain_len, BHYVE_VIRTIO_PMEM_RESPONSE_SIZE);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	/* The device must write the spec's success code (0) into the response. */
	ATF_CHECK_EQ(le32dec(g_vq.respbuf), 0);
	memset(&g_vq, 0, sizeof(g_vq));
	destroy_backing(path, &sc);
}

/* Malformed and unadmittable chains are each rejected on their own path. */
ATF_TC_WITHOUT_HEAD(notify_rejects_malformed_and_unadmittable);
ATF_TC_BODY(notify_rejects_malformed_and_unadmittable, tc)
{
	struct pci_vtpmem_softc sc;
	struct vqueue_info vq;
	char path[32];

	create_backing(path, &sc);
	create_worker(&sc);
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = 8;

	/* vq_getchain hard error must request a device reset. */
	memset(&g_vq, 0, sizeof(g_vq));
	g_vq.active = true;
	g_vq.descs = 1;
	g_vq.getchain_ret = -1;
	g_needs_reset_calls = 0;
	pci_vtpmem_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);

	/* Writable-before-readable ordering violation. */
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	g_vq.ordered = false;
	g_needs_reset_calls = 0;
	g_vq.relchain_calls = 0;
	pci_vtpmem_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);
	ATF_CHECK_EQ(g_vq.relchain_calls, 1);
	ATF_CHECK_EQ(g_vq.last_relchain_len, 0);

	/* Request buffer shorter than the 4-byte header. */
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	g_vq.iov[0].iov_len = 2;
	g_needs_reset_calls = 0;
	g_vq.relchain_calls = 0;
	pci_vtpmem_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);

	/* Unknown request type: completed with an error, no reset. */
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH + 1);
	g_needs_reset_calls = 0;
	g_vq.relchain_calls = 0;
	pci_vtpmem_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);
	ATF_CHECK_EQ(g_vq.relchain_calls, 1);
	ATF_CHECK_EQ(le32dec(g_vq.respbuf), UINT32_MAX);

	/* Request-object allocation failure is completed with ENOMEM. */
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	g_vq.relchain_calls = 0;
	g_fail_request_calloc = true;
	pci_vtpmem_notify(&sc, &vq);
	g_fail_request_calloc = false;
	ATF_CHECK_EQ(g_vq.relchain_calls, 1);

	/* Worker refusing admission (paused) is completed with an error. */
	ATF_REQUIRE_EQ(virtio_pmem_worker_pause(sc.vsc_worker, 0), 0);
	vq_script_flush_chain(VIRTIO14_PMEM_REQ_TYPE_FLUSH);
	g_vq.relchain_calls = 0;
	pci_vtpmem_notify(&sc, &vq);
	ATF_CHECK_EQ(g_vq.relchain_calls, 1);
	ATF_REQUIRE_EQ(virtio_pmem_worker_resume(sc.vsc_worker), 0);

	memset(&g_vq, 0, sizeof(g_vq));
	destroy_backing(path, &sc);
}

/*
 * pci_vtpmem_complete()'s guest-request branches are driven directly so the
 * generation/epoch fence and the response-publication failure path are both
 * deterministic rather than racing the worker.
 */
ATF_TC_WITHOUT_HEAD(complete_guest_request_fence);
ATF_TC_BODY(complete_guest_request_fence, tc)
{
	struct pci_vtpmem_softc sc;
	struct vqueue_info vq;
	struct pci_vtpmem_request *request;
	uint8_t respbuf[BHYVE_VIRTIO_PMEM_RESPONSE_SIZE];

	memset(&sc, 0, sizeof(sc));
	memset(&vq, 0, sizeof(vq));
	memset(&g_vq, 0, sizeof(g_vq));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);
	sc.vsc_vs.vs_mtx = &sc.vsc_mtx;
	sc.vsc_consts.vc_name = "vtpmem-test";
	vq.vq_generation = 5;

	/* Matching epoch and generation: response is published. */
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->vq = &vq;
	request->queue_generation = 5;
	request->epoch = 7;
	request->chain.response[0].iov_base = respbuf;
	request->chain.response[0].iov_len = sizeof(respbuf);
	request->chain.response_count = 1;
	g_vq.relchain_calls = 0;
	g_vq.endchains_calls = 0;
	pci_vtpmem_complete(&sc, (uintptr_t)request, 7, 0);
	ATF_CHECK_EQ(g_vq.relchain_calls, 1);
	ATF_CHECK_EQ(g_vq.endchains_calls, 1);
	ATF_CHECK_EQ(le32dec(respbuf), 0);

	/* Publication failure (no response iovec): discard + needs reset. */
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->vq = &vq;
	request->queue_generation = 5;
	request->epoch = 7;
	request->chain.response_count = 0;
	g_needs_reset_calls = 0;
	pci_vtpmem_complete(&sc, (uintptr_t)request, 7, 0);
	ATF_CHECK_EQ(g_needs_reset_calls, 1);

	/* Stale generation: silently discarded. */
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->vq = &vq;
	request->queue_generation = 4;
	request->epoch = 7;
	g_needs_reset_calls = 0;
	pci_vtpmem_complete(&sc, (uintptr_t)request, 7, 0);
	ATF_CHECK_EQ(g_needs_reset_calls, 0);

	/* Abandoned lifecycle completion frees the request itself. */
	request = calloc(1, sizeof(*request));
	ATF_REQUIRE(request != NULL);
	request->lifecycle_flush = true;
	request->lifecycle_abandoned = true;
	pci_vtpmem_complete(&sc, (uintptr_t)request, 0, EIO);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

/* Reset, queue reset, suspend and the resume family exercise the worker. */
ATF_TC_WITHOUT_HEAD(reset_and_lifecycle_transitions);
ATF_TC_BODY(reset_and_lifecycle_transitions, tc)
{
	struct pci_vtpmem_softc sc;
	struct vqueue_info vq;
	char path[32];

	create_backing(path, &sc);
	create_worker(&sc);
	memset(&vq, 0, sizeof(vq));
	memset(&g_vq, 0, sizeof(g_vq));

	VS_LOCK(&sc.vsc_vs);
	pci_vtpmem_reset(&sc);
	VS_UNLOCK(&sc.vsc_vs);

	VS_LOCK(&sc.vsc_vs);
	ATF_CHECK_EQ(pci_vtpmem_qreset(&sc, &vq, 0), 0);
	VS_UNLOCK(&sc.vsc_vs);

	VS_LOCK(&sc.vsc_vs);
	ATF_CHECK_EQ(pci_vtpmem_suspend(&sc), 0);
	VS_UNLOCK(&sc.vsc_vs);

	sc.vsc_vs.vs_checkpoint_paused = true;
	ATF_CHECK_EQ(pci_vtpmem_resume_device(&sc), 0);
	sc.vsc_vs.vs_checkpoint_paused = false;
	ATF_CHECK_EQ(pci_vtpmem_resume_device(&sc), 0);

	pci_vtpmem_resume_complete(&sc);

	sc.vsc_vs.vs_suspended = true;
	ATF_CHECK_EQ(pci_vtpmem_resume(&sc), 0);
	sc.vsc_vs.vs_suspended = false;
	ATF_CHECK_EQ(pci_vtpmem_resume(&sc), 0);

	destroy_backing(path, &sc);
}

/*
 * A reset whose drain times out must fall back to installing a deferred ledger
 * reset instead of silently proceeding.
 */
ATF_TC_WITHOUT_HEAD(reset_timeout_defers);
ATF_TC_BODY(reset_timeout_defers, tc)
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
	sc.vsc_consts.vc_name = "vtpmem-test";
	ops = (struct virtio_pmem_worker_ops) {
		.flush = blocked_worker_flush,
		.complete = blocked_worker_complete,
		.arg = &context,
	};
	ATF_REQUIRE_EQ(virtio_pmem_worker_create(1, &ops, &sc.vsc_worker), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(sc.vsc_worker, 1, &epoch), 0);
	blocked_worker_wait_entered(&context);

	/* Drain cannot complete within the bounded timeout; reset defers. */
	g_needs_reset_calls = 0;
	VS_LOCK(&sc.vsc_vs);
	pci_vtpmem_reset(&sc);
	VS_UNLOCK(&sc.vsc_vs);

	pthread_mutex_lock(&context.mutex);
	context.release = true;
	pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(sc.vsc_worker, 1000), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&context.condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&context.mutex), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vsc_mtx), 0);
}

/* Config read rejects a missing BAR and an unencodable range. */
ATF_TC_WITHOUT_HEAD(cfgread_error_paths);
ATF_TC_BODY(cfgread_error_paths, tc)
{
	struct pci_devinst pi;
	struct pci_vtpmem_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	memset(&pi, 0, sizeof(pi));

	/* No shared-memory feature and no MEM64 BAR: ENXIO. */
	sc.vsc_vs.vs_negotiated_caps = 0;
	sc.vsc_vs.vs_pi = NULL;
	ATF_CHECK_EQ(pci_vtpmem_cfgread(&sc, 0, 4, &value), ENXIO);

	/* BAR present but zero-size range fails config encoding. */
	sc.vsc_vs.vs_pi = &pi;
	pi.pi_bar[VTPMEM_SHMEM_BAR].type = PCIBAR_MEM64;
	pi.pi_bar[VTPMEM_SHMEM_BAR].addr = 0x1000;
	sc.vsc_backing.size = 0;
	ATF_CHECK_EQ(pci_vtpmem_cfgread(&sc, 0, 4, &value), EINVAL);
}

/* Full device composition: success plus every initialization failure branch. */
ATF_TC_WITHOUT_HEAD(init_composition_and_failures);
ATF_TC_BODY(init_composition_and_failures, tc)
{
	struct pci_devinst pi;
	char path[32];
	int fd;

	strlcpy(path, "/tmp/virtio-pmem-init.XXXXXX", sizeof(path));
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(ftruncate(fd, 8192), 0);
	ATF_REQUIRE_EQ(close(fd), 0);

	/* Missing/empty path and id are rejected before any allocation. */
	init_defaults(path);
	g_init.path = NULL;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.path = "";
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.id = NULL;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);

	/* Each post-allocation step failure must unwind to failure. */
	init_defaults(path);
	g_init.fail_select_transport = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.fail_intr_init = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.fail_modern_init = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.fail_alloc_bar = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.fail_add_shmem = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
	init_defaults(path);
	g_init.fail_set_backing = 1;
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);

	/*
	 * Worker-destroy failure in the unwind path (review-loop UAF fix):
	 * init must leak deliberately and still report failure rather than
	 * tearing down state the still-running worker owns.
	 */
	{
		char leak_path[32];
		int leak_fd;

		/*
		 * Use a private file: the deliberate leak keeps the backing fd
		 * (and its exclusive flock) alive, which would otherwise block
		 * every later open of the shared path.
		 */
		strlcpy(leak_path, "/tmp/virtio-pmem-leak.XXXXXX",
		    sizeof(leak_path));
		leak_fd = mkstemp(leak_path);
		ATF_REQUIRE(leak_fd >= 0);
		ATF_REQUIRE_EQ(ftruncate(leak_fd, 8192), 0);
		ATF_REQUIRE_EQ(close(leak_fd), 0);
		init_defaults(leak_path);
		memset(&pi, 0, sizeof(pi));
		g_init.fail_intr_init = 1;
		g_force_worker_destroy_error = true;
		ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);
		g_force_worker_destroy_error = false;
		(void)unlink(leak_path);
	}

	/* Backing open failure (path is a directory, cannot be a pmem file). */
	init_defaults(path);
	g_init.path = "/";
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 1);

	/*
	 * Clean success, both split and packed layouts.  A successful init
	 * retains the backing fd (and its exclusive flock) by design, so each
	 * success uses its own file.
	 */
	init_defaults(path);
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 0);

	{
		char packed_path[32];
		int packed_fd;

		strlcpy(packed_path, "/tmp/virtio-pmem-packed.XXXXXX",
		    sizeof(packed_path));
		packed_fd = mkstemp(packed_path);
		ATF_REQUIRE(packed_fd >= 0);
		ATF_REQUIRE_EQ(ftruncate(packed_fd, 8192), 0);
		ATF_REQUIRE_EQ(close(packed_fd), 0);
		init_defaults(packed_path);
		g_init.packed = true;
		memset(&pi, 0, sizeof(pi));
		ATF_CHECK_EQ(pci_vtpmem_init(&pi, NULL), 0);
		(void)unlink(packed_path);
	}

	ATF_REQUIRE_EQ(unlink(path), 0);
}

/* The lifecycle-flush admission failure paths in stabilize are covered. */
ATF_TC_WITHOUT_HEAD(stabilize_request_alloc_failure);
ATF_TC_BODY(stabilize_request_alloc_failure, tc)
{
	struct pci_vtpmem_softc sc;
	char path[32];

	create_backing(path, &sc);
	create_worker(&sc);
	memset(&g_vq, 0, sizeof(g_vq));

	/* The lifecycle-only request object fails to allocate. */
	g_fail_request_calloc = true;
	VS_LOCK(&sc.vsc_vs);
	ATF_CHECK_EQ(pci_vtpmem_stabilize_locked(&sc), ENOMEM);
	VS_UNLOCK(&sc.vsc_vs);
	g_fail_request_calloc = false;
	ATF_REQUIRE_EQ(virtio_pmem_worker_abort_pause(sc.vsc_worker), 0);

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
	ATF_TP_ADD_TC(tp, notify_flush_request_round_trip);
	ATF_TP_ADD_TC(tp, notify_rejects_malformed_and_unadmittable);
	ATF_TP_ADD_TC(tp, complete_guest_request_fence);
	ATF_TP_ADD_TC(tp, reset_and_lifecycle_transitions);
	ATF_TP_ADD_TC(tp, reset_timeout_defers);
	ATF_TP_ADD_TC(tp, cfgread_error_paths);
	ATF_TP_ADD_TC(tp, init_composition_and_failures);
	ATF_TP_ADD_TC(tp, stabilize_request_alloc_failure);
	return (atf_no_error());
}

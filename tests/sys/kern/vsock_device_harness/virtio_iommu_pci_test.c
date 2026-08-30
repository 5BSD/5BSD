/*
 * Independent VirtIO 1.4 sections 2.6.4 and 5.13 PCI callback-lifecycle
 * tests.  The IOMMU receives DMA-idle and fault edges from other device
 * threads, so those paths must obey the same suspend/checkpoint gate as a
 * guest queue notification.
 */
#include <sys/param.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "pci_emul.h"
#include "virtio_1_4_spec.h"
#undef PCI_EMUL_SET
#define	PCI_EMUL_SET(name)

#include <pci_virtio_iommu.c>

/* Expectations below must not silently inherit the DUT's wire constants. */
#undef	VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef	VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef	VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER		VIRTIO14_F_IN_ORDER
#undef	VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND
#undef	VIRTIO_ID_IOMMU
#define	VIRTIO_ID_IOMMU		VIRTIO14_DEVICE_IOMMU

/*
 * Independent VirtIO 1.4 section 5.13 request-type, status, and fault-reason
 * oracles.  The device under test is checked against these constants rather
 * than against its own enum so a divergent renumbering cannot self-certify.
 */
#define	SPEC_IOMMU_T_ATTACH		1U
#define	SPEC_IOMMU_T_DETACH		2U
#define	SPEC_IOMMU_T_MAP		3U
#define	SPEC_IOMMU_T_UNMAP		4U
#define	SPEC_IOMMU_T_PROBE		5U
#define	SPEC_IOMMU_S_OK			0U
#define	SPEC_IOMMU_S_IOERR		1U
#define	SPEC_IOMMU_S_UNSUPP		2U
#define	SPEC_IOMMU_S_DEVERR		3U
#define	SPEC_IOMMU_S_INVAL		4U
#define	SPEC_IOMMU_S_RANGE		5U
#define	SPEC_IOMMU_S_NOENT		6U
#define	SPEC_IOMMU_S_FAULT		7U
#define	SPEC_IOMMU_S_NOMEM		8U
#define	SPEC_IOMMU_FAULT_R_UNKNOWN	0U
#define	SPEC_IOMMU_FAULT_R_DOMAIN	1U
#define	SPEC_IOMMU_FAULT_R_MAPPING	2U

static int mock_has_descs;
static int mock_getchain_result;
static int mock_getchain_calls;
static int mock_endchains_calls;
static int mock_needs_reset_calls;

/*
 * Keep PCI topology data outside the device under test.  The production
 * post-init routine discovers peers through pci_next(), rather than through
 * a bhyve-private array, so this small fixture proves its publication and
 * rollback ordering without sharing its traversal implementation.
 */
#define	MOCK_PCI_DEVICE_MAX	4
static struct pci_devinst *mock_pci_devices[MOCK_PCI_DEVICE_MAX];
static struct virtio_softc *mock_pci_softcs[MOCK_PCI_DEVICE_MAX];
static size_t mock_pci_device_count;
static unsigned int mock_pci_iteration;
static bool mock_pci_grow_on_second_pass;
static int mock_topology_error;
static int mock_endpoint_register_error_at;
static int mock_endpoint_register_calls;
static int mock_endpoint_unregister_calls;
static int mock_dma_bind_error_at;
static int mock_dma_bind_calls;
static int mock_dma_clear_calls;

/*
 * Additional controls used to drive the init, config-space, notify, reset,
 * drain-processing, fault/idle callback, and DMA-domain-op surfaces.  All
 * default to a benign value so pre-existing cases observe no change.
 */
static bool mock_packed;
static int mock_select_transport_error;
static int mock_state_create_error;
static int mock_intr_init_error;
static int mock_modern_init_error;
static int mock_config_encode_error;
static int mock_config_write_result;
static int mock_config_write_calls;
static int mock_getchain_readable;
static int mock_getchain_writable;
static bool mock_getchain_ordered;
static bool mock_first_iov_zero_len;
static uint8_t mock_request_type;
static int mock_event_result;
static size_t mock_event_used;
static int mock_event_calls;
static int mock_queue_result;
static size_t mock_queue_used;
static int mock_queue_calls;
static bool mock_queue_saw_ordered;
static uint8_t mock_chain_buf[VTIOMMU_RINGSZ];
static bool mock_state_reset_called;
static int mock_dma_acquire_result;
static int mock_dma_release_calls;
static void *mock_translate_result;
static uint64_t mock_generation_result;
/* Allocation and mutex fault injection via ld --wrap. */
/* Fail a calloc by ordinal (count allowed before failing), not by struct size. */
static int mock_calloc_fail_after = -1;
static bool mock_malloc_fail_armed;
static int mock_mutex_init_fail_which;
static int mock_mutex_init_calls;

extern void *__real_calloc(size_t, size_t);
extern void *__real_malloc(size_t);
extern int __real_pthread_mutex_init(pthread_mutex_t *,
    const pthread_mutexattr_t *);
void *__wrap_calloc(size_t, size_t);
void *__wrap_malloc(size_t);
int __wrap_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (mock_calloc_fail_after == 0) {
		mock_calloc_fail_after = -1;
		return (NULL);
	}
	if (mock_calloc_fail_after > 0)
		mock_calloc_fail_after--;
	return (__real_calloc(nmemb, size));
}

void *
__wrap_malloc(size_t size)
{

	if (mock_malloc_fail_armed) {
		mock_malloc_fail_armed = false;
		return (NULL);
	}
	return (__real_malloc(size));
}

int
__wrap_pthread_mutex_init(pthread_mutex_t *mtx, const pthread_mutexattr_t *attr)
{

	mock_mutex_init_calls++;
	if (mock_mutex_init_fail_which != 0 &&
	    mock_mutex_init_calls == mock_mutex_init_fail_which) {
		mock_mutex_init_fail_which = 0;
		return (EINVAL);
	}
	return (__real_pthread_mutex_init(mtx, attr));
}

#ifdef BHYVE_SNAPSHOT
static uint8_t mock_snapshot_payload[VTIOMMU_STATE_MIN_SIZE];
static struct virtio_iommu_state *mock_prepared_state;
static int mock_snapshot_calls;
static int mock_restore_calls;
static int mock_prepare_calls;
static int mock_destroy_calls;
static int mock_prepare_error;
static int mock_snapshot_size_error;
static int mock_snapshot_error;
#endif

#ifdef BHYVE_SNAPSHOT
static int run_snapshot(struct pci_vtiommu_softc *, uint8_t *, size_t,
    enum vm_snapshot_op, size_t *);

struct validation_thread_arg {
	struct pci_vtiommu_softc *sc;
	struct virtio_iommu_state *observed;
	struct pci_devinst *pi;
	uint8_t *image;
	size_t image_size;
	int error;
};

static void *
validation_thread_observe(void *argument)
{
	struct validation_thread_arg *arg;

	arg = argument;
	arg->observed = pci_vtiommu_domain_state(arg->sc);
	return (NULL);
}

static void *
validation_thread_restore(void *argument)
{
	struct validation_thread_arg *arg;

	arg = argument;
	arg->error = run_snapshot(arg->sc, arg->image, arg->image_size,
	    VM_SNAPSHOT_VALIDATE, NULL);
	return (NULL);
}

static void *
validation_thread_cleanup(void *argument)
{
	struct validation_thread_arg *arg;

	arg = argument;
	pci_vtiommu_snapshot_validate_cleanup(arg->pi);
	return (NULL);
}
#endif

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (mock_has_descs);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov,
    int niov, struct vi_req *request)
{
	int total;

	mock_getchain_calls++;
	mock_has_descs = 0;
	memset(request, 0, sizeof(*request));
	if (mock_getchain_result <= 0)
		return (mock_getchain_result);
	request->readable = mock_getchain_readable;
	request->writable = mock_getchain_writable;
	request->ordered = mock_getchain_ordered;
	request->idx = 0;
	total = mock_getchain_result;
	if (total > niov)
		total = niov;
	mock_chain_buf[0] = mock_request_type;
	for (int i = 0; i < total; i++) {
		iov[i].iov_base = &mock_chain_buf[i];
		iov[i].iov_len = (i == 0 && mock_first_iov_zero_len) ? 0 : 1;
	}
	return (mock_getchain_result);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t index __unused,
    uint32_t used __unused)
{
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all_avail __unused)
{

	mock_endchains_calls++;
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	mock_needs_reset_calls++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

int
virtio_iommu_event_process(struct virtio_iommu_state *state __unused,
    const struct iovec *iov __unused, size_t niov __unused, size_t *used)
{

	mock_event_calls++;
	if (used != NULL)
		*used = mock_event_used;
	return (mock_event_result);
}

int
virtio_iommu_queue_process(struct virtio_iommu_state *state __unused,
    const struct virtio_iommu_request_options *options __unused,
    const struct iovec *iov __unused, size_t niov __unused,
    size_t readable __unused, size_t writable __unused,
    bool ordered, size_t *used)
{

	mock_queue_calls++;
	mock_queue_saw_ordered = ordered;
	if (used != NULL)
		*used = mock_queue_used;
	return (mock_queue_result);
}

int
vi_pci_lifecycle_noop(void *argument __unused)
{

	return (0);
}

/*
 * pci_de_vtiommu retains these callbacks in its immutable registration
 * record.  Supply inert transport/configuration hooks so the test links the
 * real post-init routine without importing bhyve's process-wide runtime.
 */
void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *softc, struct pci_devinst *pi, struct vqueue_info *queues)
{

	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	if (pi != NULL)
		pi->pi_arg = softc;
	if (vc != NULL) {
		for (int i = 0; i < vc->vc_nvq; i++) {
			queues[i].vq_vs = vs;
			queues[i].vq_num = i;
		}
	}
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy)
{

	ATF_CHECK_EQ(policy, VIRTIO_PCI_MODERN_ONLY);
	return (mock_select_transport_error);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t type __unused)
{
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{

	return (mock_modern_init_error);
}

int
vi_intr_init(struct virtio_softc *vs, int bar __unused, int use_msix __unused)
{

	if (mock_intr_init_error != 0)
		return (mock_intr_init_error);
	(void)pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

void
vi_set_io_bar(struct virtio_softc *vs __unused, int bar __unused)
{
}

void
vi_reset_dev(struct virtio_softc *vs)
{

	vs->vs_status = 0;
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *value __unused)
{

	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t value __unused)
{

	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{

	pi->pi_cfgdata[offset] = value;
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{

	return (pi->pi_cfgdata[offset]);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool def)
{

	if (name != NULL && strcmp(name, "packed") == 0)
		return (mock_packed);
	return (def);
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t address __unused,
    size_t length __unused)
{

	return (NULL);
}

int
vi_config_read_le(const void *config __unused, size_t config_size __unused,
    int offset __unused, int size __unused, uint32_t *value __unused)
{

	return (EINVAL);
}

int
virtio_iommu_config_encode(const struct virtio_iommu_config_values *values __unused,
    uint64_t caps __unused, bool bypass __unused,
    uint8_t bytes[BHYVE_VIOMMU_CONFIG_SIZE] __unused)
{

	return (mock_config_encode_error);
}

int
virtio_iommu_config_write(struct virtio_iommu_state *state __unused,
    uint64_t caps __unused, size_t offset __unused, size_t size __unused,
    uint32_t value __unused)
{

	mock_config_write_calls++;
	return (mock_config_write_result);
}

bool
virtio_iommu_default_bypass(struct virtio_iommu_state *state __unused)
{

	return (false);
}

int
virtio_iommu_state_create(const struct virtio_iommu_limits *limits __unused,
    const struct virtio_iommu_ops *ops __unused,
    struct virtio_iommu_state **state)
{

	if (mock_state_create_error != 0)
		return (mock_state_create_error);
	*state = NULL;
	return (0);
}

void
virtio_iommu_state_reset(struct virtio_iommu_state *state __unused)
{

	mock_state_reset_called = true;
}

#ifdef BHYVE_SNAPSHOT
int
vi_pci_snapshot(struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

int
vi_pci_snapshot_compat(struct pci_devinst *pi __unused,
    struct pci_snapshot_compat *compat __unused)
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
#endif

struct pci_devinst *
pci_next(struct pci_devinst *pi)
{
	size_t i;

	if (pi == NULL) {
		mock_pci_iteration++;
		if (mock_pci_grow_on_second_pass && mock_pci_iteration == 2) {
			ATF_REQUIRE(mock_pci_device_count <
			    nitems(mock_pci_devices));
			mock_pci_device_count++;
		}
		return (mock_pci_device_count == 0 ? NULL : mock_pci_devices[0]);
	}
	for (i = 0; i < mock_pci_device_count; i++) {
		if (mock_pci_devices[i] != pi)
			continue;
		return (i + 1 == mock_pci_device_count ? NULL :
		    mock_pci_devices[i + 1]);
	}
	return (NULL);
}

struct virtio_softc *
vi_pci_get_softc(struct pci_devinst *pi)
{
	for (size_t i = 0; i < mock_pci_device_count; i++) {
		if (mock_pci_devices[i] == pi)
			return (mock_pci_softcs[i]);
	}

	return (NULL);
}

bool
vi_pci_is_modern(const struct virtio_softc *vs)
{

	return (vs != NULL && vs->vs_modern != NULL);
}

bool
vi_pci_access_platform_eligible(const struct virtio_softc *vs)
{

	return (vi_pci_is_modern(vs) &&
	    !vs->vs_vc->vc_access_platform_ineligible);
}

int
vi_set_dma_domain(struct virtio_softc *vs __unused,
    const struct virtio_dma_domain_ops *ops __unused, void *arg __unused,
    uint32_t endpoint __unused)
{

	mock_dma_bind_calls++;
	if (mock_dma_bind_error_at != 0 && mock_dma_bind_calls ==
	    mock_dma_bind_error_at)
		return (EIO);
	return (0);
}

int
vi_clear_dma_domain(struct virtio_softc *vs __unused)
{

	mock_dma_clear_calls++;
	return (0);
}

int
virtio_iommu_topology_build(const struct virtio_iommu_topology_entry *entries,
    size_t entry_count, uint16_t *iommu_requester_id, uint16_t *endpoints,
    size_t endpoint_capacity, size_t *endpoint_count)
{
	size_t count;

	if (mock_topology_error != 0)
		return (mock_topology_error);
	if (entries == NULL || iommu_requester_id == NULL || endpoints == NULL ||
	    endpoint_count == NULL || entry_count == 0)
		return (EINVAL);
	count = 0;
	for (size_t i = 0; i < entry_count; i++) {
		if (entries[i].iommu) {
			*iommu_requester_id = entries[i].requester_id;
			continue;
		}
		if (!entries[i].access_platform_ineligible) {
			if (count == endpoint_capacity)
				return (E2BIG);
			endpoints[count++] = entries[i].requester_id;
		}
	}
	if (count == 0)
		return (ENODEV);
	*endpoint_count = count;
	return (0);
}

enum virtio_iommu_status
virtio_iommu_endpoint_register(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused)
{

	mock_endpoint_register_calls++;
	if (mock_endpoint_register_error_at != 0 &&
	    mock_endpoint_register_calls == mock_endpoint_register_error_at)
		return (BHYVE_VIOMMU_S_INVAL);
	return (BHYVE_VIOMMU_S_OK);
}

enum virtio_iommu_status
virtio_iommu_endpoint_unregister(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused)
{

	mock_endpoint_unregister_calls++;
	return (BHYVE_VIOMMU_S_OK);
}

bool
virtio_iommu_dma_acquire(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused)
{

	return (mock_dma_acquire_result != 0);
}

void
virtio_iommu_dma_release(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused)
{

	mock_dma_release_calls++;
}

#ifdef BHYVE_SNAPSHOT
void
vm_snapshot_buf_err(const char *name __unused,
    enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (meta == NULL || meta->buffer.buf == NULL ||
	    meta->buffer.buf_rem < size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf = (uint8_t *)meta->buffer.buf + size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le32dec(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le64enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le64dec(bytes);
	return (error);
}

int
virtio_iommu_state_snapshot_size(struct virtio_iommu_state *state __unused,
    size_t *size)
{

	if (mock_snapshot_size_error != 0)
		return (mock_snapshot_size_error);
	*size = sizeof(mock_snapshot_payload);
	return (0);
}

int
virtio_iommu_state_snapshot(struct virtio_iommu_state *state __unused,
    void *buffer, size_t size)
{

	if (mock_snapshot_error != 0)
		return (mock_snapshot_error);
	if (size != sizeof(mock_snapshot_payload))
		return (EINVAL);
	mock_snapshot_calls++;
	memcpy(buffer, mock_snapshot_payload, size);
	return (0);
}

int
virtio_iommu_state_restore_prepare(struct virtio_iommu_state *state __unused,
    const void *buffer, size_t size, struct virtio_iommu_state **prepared)
{

	if (size != sizeof(mock_snapshot_payload) ||
	    memcmp(buffer, mock_snapshot_payload, size) != 0)
		return (EINVAL);
	mock_prepare_calls++;
	if (mock_prepare_error != 0)
		return (mock_prepare_error);
	*prepared = mock_prepared_state;
	return (0);
}

int
virtio_iommu_state_restore(struct virtio_iommu_state *state __unused,
    const void *buffer, size_t size)
{

	if (size != sizeof(mock_snapshot_payload) ||
	    memcmp(buffer, mock_snapshot_payload, size) != 0)
		return (EINVAL);
	mock_restore_calls++;
	return (0);
}

void
virtio_iommu_state_destroy(struct virtio_iommu_state *state __unused)
{

	if (state != NULL)
		mock_destroy_calls++;
}

static int
run_snapshot(struct pci_vtiommu_softc *sc, uint8_t *image, size_t size,
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

	error = pci_vtiommu_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}
#endif

void *
virtio_iommu_translate(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused, uint64_t address __unused,
    size_t length __unused, enum virtio_dma_direction direction __unused)
{

	return (mock_translate_result);
}

uint64_t
virtio_iommu_generation(struct virtio_iommu_state *state __unused)
{

	return (mock_generation_result);
}

static void
reset_extra_mocks(void)
{

	mock_packed = false;
	mock_select_transport_error = 0;
	mock_state_create_error = 0;
	mock_intr_init_error = 0;
	mock_modern_init_error = 0;
	mock_config_encode_error = 0;
	mock_config_write_result = 0;
	mock_config_write_calls = 0;
	mock_getchain_readable = 0;
	mock_getchain_writable = 0;
	mock_getchain_ordered = false;
	mock_first_iov_zero_len = false;
	mock_request_type = 0;
	mock_event_result = 0;
	mock_event_used = 0;
	mock_event_calls = 0;
	mock_queue_result = 0;
	mock_queue_used = 0;
	mock_queue_calls = 0;
	mock_queue_saw_ordered = false;
	memset(mock_chain_buf, 0, sizeof(mock_chain_buf));
	mock_state_reset_called = false;
	mock_dma_acquire_result = 0;
	mock_dma_release_calls = 0;
	mock_translate_result = NULL;
	mock_generation_result = 0;
	mock_calloc_fail_after = -1;
	mock_malloc_fail_armed = false;
	mock_mutex_init_fail_which = 0;
	mock_mutex_init_calls = 0;
#ifdef BHYVE_SNAPSHOT
	mock_snapshot_size_error = 0;
	mock_snapshot_error = 0;
#endif
}

static void
setup_softc(struct pci_vtiommu_softc *sc)
{

	memset(sc, 0, sizeof(*sc));
#ifdef BHYVE_SNAPSHOT
	atomic_init(&sc->vsc_validation_state, NULL);
	atomic_init(&sc->vsc_validation_owner, NULL);
#endif
	sc->vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	for (unsigned int i = 0; i < nitems(sc->vsc_vq); i++)
		sc->vsc_vq[i].vq_qsize = VTIOMMU_RINGSZ;
	mock_has_descs = 0;
	mock_getchain_result = 0;
	mock_getchain_calls = 0;
	mock_endchains_calls = 0;
	mock_needs_reset_calls = 0;
	memset(mock_pci_devices, 0, sizeof(mock_pci_devices));
	memset(mock_pci_softcs, 0, sizeof(mock_pci_softcs));
	mock_pci_device_count = 0;
	mock_pci_iteration = 0;
	mock_pci_grow_on_second_pass = false;
	mock_topology_error = 0;
	mock_endpoint_register_error_at = 0;
	mock_endpoint_register_calls = 0;
	mock_endpoint_unregister_calls = 0;
	mock_dma_bind_error_at = 0;
	mock_dma_bind_calls = 0;
	mock_dma_clear_calls = 0;
	reset_extra_mocks();
}

static void
mock_pci_add(struct pci_devinst *pi, struct virtio_softc *vs)
{

	ATF_REQUIRE(mock_pci_device_count < nitems(mock_pci_devices));
	mock_pci_devices[mock_pci_device_count] = pi;
	mock_pci_softcs[mock_pci_device_count] = vs;
	mock_pci_device_count++;
}

static void
setup_modern_peer(struct pci_devinst *pi, struct virtio_softc *vs,
    struct virtio_consts *vc, int bus, int slot)
{

	memset(pi, 0, sizeof(*pi));
	memset(vs, 0, sizeof(*vs));
	pi->pi_bus = bus;
	pi->pi_slot = slot;
	vs->vs_vc = vc;
	/* Only the non-NULL transport identity is relevant to this fixture. */
	vs->vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
}

ATF_TC_WITHOUT_HEAD(descriptor_parser_failure_requires_reset);
ATF_TC_BODY(descriptor_parser_failure_requires_reset, tc)
{
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	mock_has_descs = 1;
	mock_getchain_result = -1;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_getchain_calls, 1);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	setup_softc(&sc);
	mock_has_descs = 1;
	mock_getchain_result = -1;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_getchain_calls, 1);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

ATF_TC_WITHOUT_HEAD(empty_queue_race_is_not_an_error);
ATF_TC_BODY(empty_queue_race_is_not_an_error, tc)
{
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	mock_has_descs = 1;
	mock_getchain_result = 0;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_getchain_calls, 1);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);

	setup_softc(&sc);
	mock_has_descs = 1;
	mock_getchain_result = 0;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_getchain_calls, 1);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK((sc.vsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
}

ATF_TC_WITHOUT_HEAD(callback_ready_contract);
ATF_TC_BODY(callback_ready_contract, tc)
{
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	ATF_CHECK(pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_REQUESTQ]));
	ATF_CHECK(!sc.vsc_vq[VTIOMMU_REQUESTQ].vq_notify_pending);

	sc.vsc_vs.vs_suspended = true;
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_REQUESTQ]));
	ATF_CHECK(sc.vsc_vq[VTIOMMU_REQUESTQ].vq_notify_pending);

	setup_softc(&sc);
	sc.vsc_vs.vs_checkpoint_paused = true;
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_EVENTQ]));
	ATF_CHECK(sc.vsc_vq[VTIOMMU_EVENTQ].vq_notify_pending);

	setup_softc(&sc);
	sc.vsc_vs.vs_quiescing = 1;
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_REQUESTQ]));
	ATF_CHECK(sc.vsc_vq[VTIOMMU_REQUESTQ].vq_notify_pending);

	setup_softc(&sc);
	sc.vsc_vs.vs_status = 0;
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_EVENTQ]));
	ATF_CHECK(sc.vsc_vq[VTIOMMU_EVENTQ].vq_notify_pending);
}

ATF_TC_WITHOUT_HEAD(device_lifecycle_contract);
ATF_TC_BODY(device_lifecycle_contract, tc)
{
	struct virtio_iommu_limits limits;
	uint64_t expected_caps;

	ATF_CHECK_STREQ(vtiommu_vi_consts.vc_name, "vtiommu");
	ATF_CHECK_EQ(vtiommu_vi_consts.vc_nvq, VTIOMMU_NUM_QUEUES);
	ATF_CHECK_EQ(VIRTIO_ID_IOMMU, VIRTIO14_DEVICE_IOMMU);
	ATF_CHECK_EQ(BHYVE_VIOMMU_CONFIG_SIZE, VIRTIO14_IOMMU_CONFIG_SIZE);
	ATF_CHECK_EQ(BHYVE_VIOMMU_CONFIG_BYPASS_OFFSET,
	    VIRTIO14_IOMMU_CONFIG_BYPASS_OFF);
	ATF_CHECK_EQ(BHYVE_VIOMMU_F_INPUT_RANGE,
	    VIRTIO14_IOMMU_F_INPUT_RANGE);
	ATF_CHECK_EQ(BHYVE_VIOMMU_F_DOMAIN_RANGE,
	    VIRTIO14_IOMMU_F_DOMAIN_RANGE);
	ATF_CHECK_EQ(BHYVE_VIOMMU_F_MAP_UNMAP, VIRTIO14_IOMMU_F_MAP_UNMAP);
	ATF_CHECK_EQ(BHYVE_VIOMMU_F_PROBE, VIRTIO14_IOMMU_F_PROBE);
	ATF_CHECK_EQ(BHYVE_VIOMMU_F_BYPASS_CONFIG, VIRTIO14_IOMMU_F_BYPASS);
	expected_caps = VIRTIO14_IOMMU_F_INPUT_RANGE |
	    VIRTIO14_IOMMU_F_DOMAIN_RANGE | VIRTIO14_IOMMU_F_MAP_UNMAP |
	    VIRTIO14_IOMMU_F_PROBE | VIRTIO14_IOMMU_F_BYPASS |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND;
	ATF_CHECK_EQ(vtiommu_vi_consts.vc_hv_caps, expected_caps);
	ATF_CHECK((vtiommu_vi_consts.vc_hv_caps &
	    VIRTIO_F_SUSPEND) != 0);
	ATF_CHECK((vtiommu_vi_consts.vc_hv_caps &
	    VIRTIO_F_IN_ORDER) == 0);
	/*
	 * State mutation is synchronous and foreign-device callbacks pass
	 * through pci_vtiommu_callback_ready_locked().  Consequently the common
	 * lifecycle fence owns the drain today.  Keep that premise visible so
	 * a future asynchronous invalidation backend cannot silently inherit
	 * no-op lifecycle hooks.
	 */
	ATF_CHECK(vtiommu_vi_consts.vc_suspend == vi_pci_lifecycle_noop);
	ATF_CHECK(vtiommu_vi_consts.vc_resume_device ==
	    vi_pci_lifecycle_noop);
	ATF_CHECK(vtiommu_vi_consts.vc_pause == vi_pci_lifecycle_noop);
	ATF_CHECK(vtiommu_vi_consts.vc_resume == vi_pci_lifecycle_noop);

	pci_vtiommu_limits_init(&limits);
	ATF_REQUIRE_EQ(limits.max_endpoints, 256U);
	ATF_REQUIRE_EQ(limits.max_domains, 256U);
	ATF_REQUIRE_EQ(limits.max_mappings, 8192U);
	ATF_REQUIRE_EQ(limits.max_faults, 256U);
	ATF_CHECK((vtiommu_vi_consts.vc_hv_caps &
	    BHYVE_VIOMMU_F_BYPASS_CONFIG) != 0);
	ATF_CHECK(limits.bypass_domains);
	ATF_CHECK(!limits.default_bypass);
}

ATF_TC_WITHOUT_HEAD(provider_is_not_a_translated_endpoint);
ATF_TC_BODY(provider_is_not_a_translated_endpoint, tc)
{

	ATF_CHECK(vtiommu_vi_consts.vc_access_platform_ineligible);
}

ATF_TC_WITHOUT_HEAD(post_init_binds_only_eligible_modern_endpoints);
ATF_TC_BODY(post_init_binds_only_eligible_modern_endpoints, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_a_pi, peer_b_pi, skipped_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 }, ineligible = {
		.vc_access_platform_ineligible = true,
	};
	struct virtio_softc peer_a, peer_b, skipped;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	iommu_pi.pi_bus = 0;
	iommu_pi.pi_slot = 2;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	setup_modern_peer(&peer_a_pi, &peer_a, &eligible, 0, 3);
	peer_a_pi.pi_d = &ordinary;
	setup_modern_peer(&peer_b_pi, &peer_b, &eligible, 0, 4);
	peer_b_pi.pi_d = &ordinary;
	setup_modern_peer(&skipped_pi, &skipped, &ineligible, 0, 5);
	skipped_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_a_pi, &peer_a);
	mock_pci_add(&peer_b_pi, &peer_b);
	mock_pci_add(&skipped_pi, &skipped);

	ATF_REQUIRE_EQ(pci_vtiommu_post_init(&iommu_pi), 0);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 2U);
	ATF_CHECK_EQ(sc.vsc_endpoints[0], pci_vtiommu_rid(&peer_a_pi));
	ATF_CHECK_EQ(sc.vsc_endpoints[1], pci_vtiommu_rid(&peer_b_pi));
	ATF_CHECK_EQ(mock_endpoint_register_calls, 2);
	ATF_CHECK_EQ(mock_dma_bind_calls, 2);
	ATF_CHECK_EQ(mock_dma_clear_calls, 0);
}

ATF_TC_WITHOUT_HEAD(post_init_registration_failure_rolls_back);
ATF_TC_BODY(post_init_registration_failure_rolls_back, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_a_pi, peer_b_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 };
	struct virtio_softc peer_a, peer_b;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	setup_modern_peer(&peer_a_pi, &peer_a, &eligible, 0, 3);
	peer_a_pi.pi_d = &ordinary;
	setup_modern_peer(&peer_b_pi, &peer_b, &eligible, 0, 4);
	peer_b_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_a_pi, &peer_a);
	mock_pci_add(&peer_b_pi, &peer_b);
	mock_endpoint_register_error_at = 2;

	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), EINVAL);
	ATF_CHECK_EQ(mock_endpoint_register_calls, 2);
	ATF_CHECK_EQ(mock_endpoint_unregister_calls, 1);
	ATF_CHECK_EQ(mock_dma_bind_calls, 0);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
}

ATF_TC_WITHOUT_HEAD(post_init_topology_growth_fails_safely);
ATF_TC_BODY(post_init_topology_growth_fails_safely, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_a_pi, peer_b_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 };
	struct virtio_softc peer_a, peer_b;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	setup_modern_peer(&peer_a_pi, &peer_a, &eligible, 0, 3);
	peer_a_pi.pi_d = &ordinary;
	setup_modern_peer(&peer_b_pi, &peer_b, &eligible, 0, 4);
	peer_b_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_a_pi, &peer_a);
	/* Stage a peer which becomes visible only on the second pass. */
	mock_pci_devices[mock_pci_device_count] = &peer_b_pi;
	mock_pci_softcs[mock_pci_device_count] = &peer_b;
	mock_pci_grow_on_second_pass = true;

	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), EAGAIN);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
	ATF_CHECK_EQ(mock_endpoint_register_calls, 0);
	ATF_CHECK_EQ(mock_dma_bind_calls, 0);
	ATF_CHECK_EQ(mock_dma_clear_calls, 0);
}

/*
 * Topology validation is intentionally completed before either the provider
 * fabric or peer DMA domains are touched.  Keep that ordering explicit: a
 * rejected duplicate-provider, requester-ID, or capacity topology must not
 * leave a partly registered endpoint behind for a later device instance.
 */
ATF_TC_WITHOUT_HEAD(post_init_topology_failure_has_no_side_effects);
ATF_TC_BODY(post_init_topology_failure_has_no_side_effects, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 };
	struct virtio_softc peer;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	setup_modern_peer(&peer_pi, &peer, &eligible, 0, 3);
	peer_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_pi, &peer);

	mock_topology_error = EEXIST;
	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), EEXIST);
	ATF_CHECK_EQ(mock_endpoint_register_calls, 0);
	ATF_CHECK_EQ(mock_endpoint_unregister_calls, 0);
	ATF_CHECK_EQ(mock_dma_bind_calls, 0);
	ATF_CHECK_EQ(mock_dma_clear_calls, 0);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
}

ATF_TC_WITHOUT_HEAD(post_init_binding_failure_rolls_back);
ATF_TC_BODY(post_init_binding_failure_rolls_back, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_a_pi, peer_b_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 };
	struct virtio_softc peer_a, peer_b;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	setup_modern_peer(&peer_a_pi, &peer_a, &eligible, 0, 3);
	peer_a_pi.pi_d = &ordinary;
	setup_modern_peer(&peer_b_pi, &peer_b, &eligible, 0, 4);
	peer_b_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_a_pi, &peer_a);
	mock_pci_add(&peer_b_pi, &peer_b);
	mock_dma_bind_error_at = 2;

	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), EIO);
	ATF_CHECK_EQ(mock_endpoint_register_calls, 2);
	ATF_CHECK_EQ(mock_dma_bind_calls, 2);
	ATF_CHECK_EQ(mock_dma_clear_calls, 1);
	ATF_CHECK_EQ(mock_endpoint_unregister_calls, 2);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
}

ATF_TC_WITHOUT_HEAD(fatal_or_reset_edge_is_not_replayed);
ATF_TC_BODY(fatal_or_reset_edge_is_not_replayed, tc)
{
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	sc.vsc_vs.vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_REQUESTQ]));
	ATF_CHECK(!sc.vsc_vq[VTIOMMU_REQUESTQ].vq_notify_pending);

	setup_softc(&sc);
	atomic_store_explicit(&sc.vsc_vs.vs_resetting, true,
	    memory_order_release);
	ATF_CHECK(!pci_vtiommu_callback_ready_locked(&sc,
	    &sc.vsc_vq[VTIOMMU_EVENTQ]));
	ATF_CHECK(!sc.vsc_vq[VTIOMMU_EVENTQ].vq_notify_pending);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_wire_validation_and_restore);
ATF_TC_BODY(snapshot_wire_validation_and_restore, tc)
{
	struct pci_devinst pi;
	struct pci_vtiommu_softc source, destination;
	struct virtio_iommu_state *live, *prepared;
	uint8_t damaged[sizeof(mock_snapshot_payload) + 20];
	uint8_t image[sizeof(damaged)];
	uintptr_t live_token, prepared_token;
	size_t used;

	setup_softc(&source);
	setup_softc(&destination);
	live_token = 1;
	prepared_token = 2;
	live = (struct virtio_iommu_state *)(void *)&live_token;
	prepared = (struct virtio_iommu_state *)(void *)&prepared_token;
	source.vsc_state = live;
	destination.vsc_state = live;
	mock_prepared_state = prepared;
	mock_snapshot_calls = 0;
	mock_restore_calls = 0;
	mock_prepare_calls = 0;
	mock_destroy_calls = 0;
	mock_prepare_error = 0;
	for (size_t i = 0; i < sizeof(mock_snapshot_payload); i++)
		mock_snapshot_payload[i] = (uint8_t)(i ^ 0xa5);

	/* The wire header is portable LE, not a native struct image. */
	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, 20 + sizeof(mock_snapshot_payload));
	ATF_CHECK_EQ(mock_snapshot_calls, 1);
	ATF_CHECK_EQ(image[0], 'I');
	ATF_CHECK_EQ(image[1], 'O');
	ATF_CHECK_EQ(image[2], 'M');
	ATF_CHECK_EQ(image[3], '1');
	ATF_CHECK_EQ(le32dec(&image[4]), VTIOMMU_SNAPSHOT_VERSION);
	ATF_CHECK_EQ(le32dec(&image[8]), 0U);
	ATF_CHECK_EQ(le64dec(&image[12]), sizeof(mock_snapshot_payload));

	/* VALIDATE prepares only this thread's alternate fabric. */
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(mock_prepare_calls, 1);
	ATF_CHECK_EQ(mock_restore_calls, 0);
	ATF_CHECK(pci_vtiommu_domain_state(&destination) == prepared);

	/* A malformed image must be rejected before it changes prepared state. */
	memcpy(damaged, image, used);
	damaged[0] ^= 1;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(mock_prepare_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&destination) == prepared);
	/* The fixed discriminator rejects an unknown version without a body. */
	damaged[0] = image[0];
	damaged[4] = 2;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, 8,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(mock_prepare_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&destination) == prepared);

	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &destination;
	pci_vtiommu_snapshot_validate_cleanup(&pi);
	ATF_CHECK_EQ(mock_destroy_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&destination) == live);

	ATF_CHECK_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(mock_restore_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&destination) == live);
}

ATF_TC_WITHOUT_HEAD(prepared_restore_fabric_is_validation_thread_scoped);
ATF_TC_BODY(prepared_restore_fabric_is_validation_thread_scoped, tc)
{
	struct validation_thread_arg arg;
	struct pci_vtiommu_softc sc;
	struct virtio_iommu_state *live, *prepared;
	pthread_t thread;
	uintptr_t live_token, prepared_token;

	setup_softc(&sc);
	live_token = 1;
	prepared_token = 2;
	live = (struct virtio_iommu_state *)(void *)&live_token;
	prepared = (struct virtio_iommu_state *)(void *)&prepared_token;
	sc.vsc_state = live;
	atomic_store_explicit(&sc.vsc_validation_owner,
	    pci_vtiommu_validation_owner_token(), memory_order_release);
	atomic_store_explicit(&sc.vsc_validation_state, prepared,
	    memory_order_release);

	/* The restore-preflight owner validates endpoint DMA against the image. */
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == prepared);

	/* Runtime callbacks on every other thread must retain the live fabric. */
	memset(&arg, 0, sizeof(arg));
	arg.sc = &sc;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL,
	    validation_thread_observe, &arg), 0);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK(arg.observed == live);

	/* Cleanup withdraws owner visibility before it can destroy the image. */
	atomic_store_explicit(&sc.vsc_validation_owner, NULL,
	    memory_order_release);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == live);
	ATF_CHECK(atomic_exchange_explicit(&sc.vsc_validation_state, NULL,
	    memory_order_acq_rel) == prepared);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == live);
}

ATF_TC_WITHOUT_HEAD(prepared_restore_fabric_has_exclusive_owner);
ATF_TC_BODY(prepared_restore_fabric_has_exclusive_owner, tc)
{
	struct validation_thread_arg arg;
	struct pci_devinst pi;
	struct pci_vtiommu_softc sc;
	struct virtio_iommu_state *live, *prepared;
	uint8_t image[sizeof(mock_snapshot_payload) + 20];
	uintptr_t live_token, prepared_token;
	pthread_t thread;
	size_t used;

	setup_softc(&sc);
	live_token = 1;
	prepared_token = 2;
	live = (struct virtio_iommu_state *)(void *)&live_token;
	prepared = (struct virtio_iommu_state *)(void *)&prepared_token;
	sc.vsc_state = live;
	mock_prepared_state = prepared;
	mock_prepare_calls = 0;
	mock_destroy_calls = 0;
	mock_prepare_error = 0;
	for (size_t i = 0; i < sizeof(mock_snapshot_payload); i++)
		mock_snapshot_payload[i] = (uint8_t)(i ^ 0x5a);
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == prepared);

	/* A different validator cannot steal or retire the live owner view. */
	memset(&arg, 0, sizeof(arg));
	arg.sc = &sc;
	arg.image = image;
	arg.image_size = used;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL,
	    validation_thread_restore, &arg), 0);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(arg.error, EBUSY);
	ATF_CHECK_EQ(mock_prepare_calls, 2);
	ATF_CHECK_EQ(mock_destroy_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == prepared);

	/* Cleanup is likewise scoped to the publishing thread. */
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;
	arg.pi = &pi;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL,
	    validation_thread_cleanup, &arg), 0);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(mock_destroy_calls, 1);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == prepared);

	pci_vtiommu_snapshot_validate_cleanup(&pi);
	ATF_CHECK_EQ(mock_destroy_calls, 2);
	ATF_CHECK(pci_vtiommu_domain_state(&sc) == live);
}
#endif

ATF_TC_WITHOUT_HEAD(protocol_constants_match_spec);
ATF_TC_BODY(protocol_constants_match_spec, tc)
{

	/* Status codes are placed on the wire and must match section 5.13.6. */
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_OK, SPEC_IOMMU_S_OK);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_IOERR, SPEC_IOMMU_S_IOERR);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_UNSUPP, SPEC_IOMMU_S_UNSUPP);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_DEVERR, SPEC_IOMMU_S_DEVERR);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_INVAL, SPEC_IOMMU_S_INVAL);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_RANGE, SPEC_IOMMU_S_RANGE);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_NOENT, SPEC_IOMMU_S_NOENT);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_FAULT, SPEC_IOMMU_S_FAULT);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_S_NOMEM, SPEC_IOMMU_S_NOMEM);
	/* Fault reasons carried on the event queue. */
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_FAULT_UNKNOWN,
	    SPEC_IOMMU_FAULT_R_UNKNOWN);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_FAULT_DOMAIN,
	    SPEC_IOMMU_FAULT_R_DOMAIN);
	ATF_CHECK_EQ((unsigned)BHYVE_VIOMMU_FAULT_MAPPING,
	    SPEC_IOMMU_FAULT_R_MAPPING);
	/* The advertised probe size fits the bounded response contract. */
	ATF_CHECK(VTIOMMU_PROBE_SIZE <= BHYVE_VIOMMU_MAX_PROBE_SIZE);
	/* Silence unused request-type oracles while documenting them. */
	ATF_CHECK(SPEC_IOMMU_T_ATTACH == 1U && SPEC_IOMMU_T_DETACH == 2U &&
	    SPEC_IOMMU_T_MAP == 3U && SPEC_IOMMU_T_UNMAP == 4U &&
	    SPEC_IOMMU_T_PROBE == 5U);
}

ATF_TC_WITHOUT_HEAD(device_init_success_and_failures);
ATF_TC_BODY(device_init_success_and_failures, tc)
{
	struct pci_devinst pi;
	struct pci_vtiommu_softc *sc;

	/* Split-ring success establishes the base-peripheral IOMMU identity. */
	reset_extra_mocks();
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtiommu_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi, PCIR_CLASS), PCIC_BASEPERIPH);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi, PCIR_SUBCLASS),
	    PCIS_BASEPERIPH_IOMMU);
	ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) == 0);
	ATF_CHECK_EQ(sc->vsc_request_options.probe_size, VTIOMMU_PROBE_SIZE);
	ATF_CHECK_EQ(sc->vsc_config.probe_size, VTIOMMU_PROBE_SIZE);
	pthread_mutex_destroy(&sc->vsc_mtx);
	pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	free(sc->vsc_vs.vs_modern);
	free(sc);

	/* An opt-in packed ring is negotiated per-instance, not globally. */
	reset_extra_mocks();
	mock_packed = true;
	memset(&pi, 0, sizeof(pi));
	ATF_REQUIRE_EQ(pci_vtiommu_init(&pi, NULL), 0);
	sc = pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) != 0);
	ATF_CHECK((vtiommu_vi_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) == 0);
	pthread_mutex_destroy(&sc->vsc_mtx);
	pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	free(sc->vsc_vs.vs_modern);
	free(sc);

	/* Softc allocation failure (first calloc). */
	reset_extra_mocks();
	mock_calloc_fail_after = 0;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), ENOMEM);

	/* Device-mutex initialization failure is surfaced verbatim. */
	reset_extra_mocks();
	mock_mutex_init_fail_which = 1;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), EINVAL);

	/* A modern-only transport that cannot be selected aborts init. */
	reset_extra_mocks();
	mock_select_transport_error = EINVAL;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), EINVAL);

	/* Translation-state creation failure unwinds cleanly. */
	reset_extra_mocks();
	mock_state_create_error = ENOMEM;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), ENOMEM);

	/* Interrupt allocation failure maps to ENXIO. */
	reset_extra_mocks();
	mock_intr_init_error = -1;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), ENXIO);

	/* Modern BAR wiring failure maps to ENXIO after intr teardown. */
	reset_extra_mocks();
	mock_modern_init_error = -1;
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK_EQ(pci_vtiommu_init(&pi, NULL), ENXIO);
}

ATF_TC_WITHOUT_HEAD(config_space_and_features);
ATF_TC_BODY(config_space_and_features, tc)
{
	struct pci_vtiommu_softc sc;
	uint32_t value;

	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;

	value = 0;
	/* Read encodes the config then defers to the LE window reader. */
	ATF_CHECK_EQ(pci_vtiommu_cfgread(&sc, 0, 4, &value), EINVAL);
	/* A config-encode failure short-circuits the read. */
	mock_config_encode_error = EIO;
	ATF_CHECK_EQ(pci_vtiommu_cfgread(&sc, 0, 4, &value), EIO);
	mock_config_encode_error = 0;

	/* Negative offset or size is rejected before reaching the state. */
	ATF_CHECK_EQ(pci_vtiommu_cfgwrite(&sc, -1, 4, 0), EINVAL);
	ATF_CHECK_EQ(pci_vtiommu_cfgwrite(&sc, 0, -1, 0), EINVAL);
	ATF_CHECK_EQ(mock_config_write_calls, 0);
	/* A well-formed write reaches the state config writer. */
	ATF_CHECK_EQ(pci_vtiommu_cfgwrite(&sc,
	    BHYVE_VIOMMU_CONFIG_BYPASS_OFFSET, 1, 1), 0);
	ATF_CHECK_EQ(mock_config_write_calls, 1);
	mock_config_write_result = EINVAL;
	ATF_CHECK_EQ(pci_vtiommu_cfgwrite(&sc, 0, 4, 0), EINVAL);

	/* MAP_UNMAP alone enables only map/unmap request handling. */
	ATF_CHECK_EQ(pci_vtiommu_apply_features(&sc,
	    VIRTIO14_IOMMU_F_MAP_UNMAP), 0);
	ATF_CHECK(sc.vsc_request_options.map_unmap);
	ATF_CHECK(!sc.vsc_request_options.probe);
	ATF_CHECK(!sc.vsc_request_options.bypass_config);
	/* PROBE|BYPASS enable those and clear the un-negotiated MAP_UNMAP. */
	ATF_CHECK_EQ(pci_vtiommu_apply_features(&sc,
	    VIRTIO14_IOMMU_F_PROBE | VIRTIO14_IOMMU_F_BYPASS), 0);
	ATF_CHECK(!sc.vsc_request_options.map_unmap);
	ATF_CHECK(sc.vsc_request_options.probe);
	ATF_CHECK(sc.vsc_request_options.bypass_config);

	/* Reset rewinds device state and clears every negotiated option. */
	sc.vsc_request_options.map_unmap = true;
	sc.vsc_request_options.probe = true;
	sc.vsc_request_options.bypass_config = true;
	sc.vsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	pci_vtiommu_reset(&sc);
	ATF_CHECK(mock_state_reset_called);
	ATF_CHECK(!sc.vsc_request_options.map_unmap);
	ATF_CHECK(!sc.vsc_request_options.probe);
	ATF_CHECK(!sc.vsc_request_options.bypass_config);
	ATF_CHECK_EQ(sc.vsc_vs.vs_status, 0);
}

ATF_TC_WITHOUT_HEAD(notify_routes_by_queue_index);
ATF_TC_BODY(notify_routes_by_queue_index, tc)
{
	struct pci_vtiommu_softc sc;
	struct vqueue_info bad;

	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	sc.vsc_vq[VTIOMMU_EVENTQ].vq_num = VTIOMMU_EVENTQ;
	sc.vsc_vq[VTIOMMU_REQUESTQ].vq_num = VTIOMMU_REQUESTQ;

	pci_vtiommu_notify(&sc, &sc.vsc_vq[VTIOMMU_EVENTQ]);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);

	pci_vtiommu_notify(&sc, &sc.vsc_vq[VTIOMMU_REQUESTQ]);
	ATF_CHECK_EQ(mock_endchains_calls, 2);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);

	/* A notification on an unknown queue index is a fatal protocol error. */
	memset(&bad, 0, sizeof(bad));
	bad.vq_num = VTIOMMU_NUM_QUEUES + 5;
	pci_vtiommu_notify(&sc, &bad);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);
}

ATF_TC_WITHOUT_HEAD(request_queue_processing_outcomes);
ATF_TC_BODY(request_queue_processing_outcomes, tc)
{
	struct pci_vtiommu_softc sc;

	/* A well-formed chain is handed to the executor and released. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 2;
	mock_getchain_readable = 1;
	mock_getchain_writable = 1;
	mock_getchain_ordered = true;
	mock_request_type = SPEC_IOMMU_T_MAP;
	mock_queue_result = 0;
	mock_queue_used = 16;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 1);
	ATF_CHECK(mock_queue_saw_ordered);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);

	/* EAGAIN returns the chain to the ring for a later idle edge. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 1;
	mock_getchain_writable = 0;
	mock_queue_result = EAGAIN;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);

	/* ENOMEM from the executor forces a device reset. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 1;
	mock_getchain_writable = 0;
	mock_queue_result = ENOMEM;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);

	/* A descriptor count mismatch is rejected without reaching the executor. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 2;
	mock_getchain_readable = 1;
	mock_getchain_writable = 0;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 0);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);

	/* An over-long chain that exceeds the iovec budget is rejected. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = VTIOMMU_RINGSZ + 1;
	mock_getchain_readable = 1;
	mock_getchain_writable = VTIOMMU_RINGSZ;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 0);

	/* A leading zero-length readable segment is skipped when sniffing type. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 2;
	mock_getchain_readable = 2;
	mock_getchain_writable = 0;
	mock_first_iov_zero_len = true;
	mock_request_type = SPEC_IOMMU_T_PROBE;
	mock_queue_result = 0;
	mock_queue_used = 8;
	pci_vtiommu_drain_requests_locked(&sc);
	ATF_CHECK_EQ(mock_queue_calls, 1);
}

ATF_TC_WITHOUT_HEAD(event_queue_processing_outcomes);
ATF_TC_BODY(event_queue_processing_outcomes, tc)
{
	struct pci_vtiommu_softc sc;

	/* A write-only chain is filled with one pending fault record. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 0;
	mock_getchain_writable = 1;
	mock_event_result = 0;
	mock_event_used = 24;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_event_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);

	/* EAGAIN retains the chain until another fault edge arrives. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 0;
	mock_getchain_writable = 1;
	mock_event_result = EAGAIN;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_event_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);

	/* ENOMEM forces a device reset. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 0;
	mock_getchain_writable = 1;
	mock_event_result = ENOMEM;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_event_calls, 1);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);

	/* A readable event descriptor violates the device-writes-only contract. */
	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	mock_has_descs = 1;
	mock_getchain_result = 1;
	mock_getchain_readable = 1;
	mock_getchain_writable = 1;
	pci_vtiommu_drain_events_locked(&sc);
	ATF_CHECK_EQ(mock_event_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
}

ATF_TC_WITHOUT_HEAD(async_callbacks_obey_lifecycle_fence);
ATF_TC_BODY(async_callbacks_obey_lifecycle_fence, tc)
{
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vsc_mtx, NULL), 0);

	/* A ready device drains the event ring on a fault edge. */
	pci_vtiommu_fault(&sc, 5, BHYVE_VIOMMU_FAULT_DOMAIN, 0x1000,
	    VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	/* A DMA-idle edge retries deferred requests. */
	pci_vtiommu_dma_idle(&sc, 5);
	ATF_CHECK_EQ(mock_endchains_calls, 2);

	/* A suspended device converts the edge into a pending notification. */
	mock_endchains_calls = 0;
	sc.vsc_vs.vs_suspended = true;
	pci_vtiommu_fault(&sc, 5, BHYVE_VIOMMU_FAULT_MAPPING, 0x2000,
	    VIRTIO_DMA_DEVICE_WRITE);
	ATF_CHECK_EQ(mock_endchains_calls, 0);
	ATF_CHECK(sc.vsc_vq[VTIOMMU_EVENTQ].vq_notify_pending);
	pci_vtiommu_dma_idle(&sc, 5);
	ATF_CHECK_EQ(mock_endchains_calls, 0);
	ATF_CHECK(sc.vsc_vq[VTIOMMU_REQUESTQ].vq_notify_pending);

	pthread_mutex_destroy(&sc.vsc_mtx);
}

ATF_TC_WITHOUT_HEAD(dma_domain_ops_delegate_to_state);
ATF_TC_BODY(dma_domain_ops_delegate_to_state, tc)
{
	struct pci_vtiommu_softc sc;
	uint8_t token;

	setup_softc(&sc);
	sc.vsc_consts = vtiommu_vi_consts;
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;

	mock_dma_acquire_result = 1;
	ATF_CHECK(pci_vtiommu_domain_acquire(&sc, 3));
	mock_dma_acquire_result = 0;
	ATF_CHECK(!pci_vtiommu_domain_acquire(&sc, 3));

	pci_vtiommu_domain_release(&sc, 3);
	ATF_CHECK_EQ(mock_dma_release_calls, 1);

	mock_translate_result = &token;
	ATF_CHECK(pci_vtiommu_domain_map(&sc, 3, 0x1000, 64,
	    VIRTIO_DMA_BIDIRECTIONAL) == &token);
	mock_translate_result = NULL;
	ATF_CHECK(pci_vtiommu_domain_map(&sc, 3, 0x1000, 64,
	    VIRTIO_DMA_DEVICE_READ) == NULL);

	mock_generation_result = 0x99;
	ATF_CHECK_EQ(pci_vtiommu_domain_generation(&sc), UINT64_C(0x99));

	/* The published op table wires the state to the DMA request owner. */
	ATF_CHECK(vtiommu_dma_ops.vddo_acquire == pci_vtiommu_domain_acquire);
	ATF_CHECK(vtiommu_dma_ops.vddo_release == pci_vtiommu_domain_release);
	ATF_CHECK(vtiommu_dma_ops.vddo_map == pci_vtiommu_domain_map);
	ATF_CHECK(vtiommu_dma_ops.vddo_generation ==
	    pci_vtiommu_domain_generation);
}

ATF_TC_WITHOUT_HEAD(guest_memory_translation_hooks);
ATF_TC_BODY(guest_memory_translation_hooks, tc)
{
	struct pci_vtiommu_softc sc;
	struct pci_devinst pi;

	setup_softc(&sc);
	memset(&pi, 0, sizeof(pi));
	sc.vsc_vs.vs_pi = &pi;

	/* A zero-length window is rejected before any host translation. */
	ATF_CHECK(!pci_vtiommu_validate_gpa(&sc, 0x1000, 0, 0));
	/* A real window defers to paddr_guest2host (mocked unmapped here). */
	ATF_CHECK(!pci_vtiommu_validate_gpa(&sc, 0x1000, 64, 0));
	ATF_CHECK(pci_vtiommu_map_gpa(&sc, 0x1000, 64,
	    VIRTIO_DMA_DEVICE_READ) == NULL);
}

ATF_TC_WITHOUT_HEAD(viot_info_reports_topology);
ATF_TC_BODY(viot_info_reports_topology, tc)
{
	struct pci_devinst pi;
	struct pci_vtiommu_softc sc;
	uint16_t bdf;
	const uint16_t *endpoints;
	size_t count;

	setup_softc(&sc);
	memset(&pi, 0, sizeof(pi));

	/* Missing out-parameters are rejected. */
	ATF_CHECK_EQ(pci_vtiommu_viot_info(NULL, &bdf, &endpoints, &count),
	    EINVAL);
	ATF_CHECK_EQ(pci_vtiommu_viot_info(&pi, NULL, &endpoints, &count),
	    EINVAL);

	/* A device that is not the IOMMU provider has no VIOT record. */
	pi.pi_d = NULL;
	ATF_CHECK_EQ(pci_vtiommu_viot_info(&pi, &bdf, &endpoints, &count),
	    ENODEV);

	/* The provider without a completed topology also reports none. */
	pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	pi.pi_arg = &sc;
	sc.vsc_endpoint_count = 0;
	ATF_CHECK_EQ(pci_vtiommu_viot_info(&pi, &bdf, &endpoints, &count),
	    ENODEV);

	/* A published topology is returned to the VIOT builder. */
	pi.pi_bus = 0;
	pi.pi_slot = 6;
	pi.pi_func = 0;
	sc.vsc_endpoint_count = 2;
	sc.vsc_endpoints[0] = 0x0100;
	sc.vsc_endpoints[1] = 0x0108;
	ATF_CHECK_EQ(pci_vtiommu_viot_info(&pi, &bdf, &endpoints, &count), 0);
	ATF_CHECK_EQ(bdf, pci_vtiommu_rid(&pi));
	ATF_CHECK(endpoints == sc.vsc_endpoints);
	ATF_CHECK_EQ(count, 2U);
}

ATF_TC_WITHOUT_HEAD(post_init_requires_a_modern_peer);
ATF_TC_BODY(post_init_requires_a_modern_peer, tc)
{
	struct pci_devinst iommu_pi;
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	/* No modern transport anywhere: nothing to translate. */
	sc.vsc_vs.vs_modern = NULL;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);

	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), ENODEV);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
}

ATF_TC_WITHOUT_HEAD(post_init_topology_allocation_failure);
ATF_TC_BODY(post_init_topology_allocation_failure, tc)
{
	struct pci_devinst iommu_pi;
	struct pci_vtiommu_softc sc;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);

	/* Topology-entry allocation failure (first calloc in post_init). */
	mock_calloc_fail_after = 0;
	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), ENOMEM);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
}

ATF_TC_WITHOUT_HEAD(post_init_wrong_provider_identity);
ATF_TC_BODY(post_init_wrong_provider_identity, tc)
{
	struct pci_devemu ordinary = { 0 };
	struct pci_devinst iommu_pi, peer_pi, provider_pi, legacy_pi;
	struct pci_vtiommu_softc sc;
	struct virtio_consts eligible = { 0 };
	struct virtio_softc peer, provider, legacy;

	setup_softc(&sc);
	sc.vsc_state = (struct virtio_iommu_state *)(uintptr_t)1;
	sc.vsc_consts = vtiommu_vi_consts;
	memset(&iommu_pi, 0, sizeof(iommu_pi));
	iommu_pi.pi_arg = &sc;
	iommu_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	iommu_pi.pi_bus = 0;
	iommu_pi.pi_slot = 2;
	sc.vsc_vs.vs_vc = &sc.vsc_consts;
	sc.vsc_vs.vs_modern = (struct virtio_pci_modern *)(uintptr_t)1;
	/* An eligible endpoint so topology_build returns a non-empty set. */
	setup_modern_peer(&peer_pi, &peer, &eligible, 0, 3);
	peer_pi.pi_d = &ordinary;
	/* A second provider whose requester id differs from this instance. */
	setup_modern_peer(&provider_pi, &provider, &eligible, 0, 5);
	provider_pi.pi_d = (struct pci_devemu *)(uintptr_t)&pci_de_vtiommu;
	/* A non-modern function is skipped by both discovery passes. */
	memset(&legacy_pi, 0, sizeof(legacy_pi));
	memset(&legacy, 0, sizeof(legacy));
	legacy.vs_vc = &eligible;
	legacy.vs_modern = NULL;
	legacy_pi.pi_bus = 0;
	legacy_pi.pi_slot = 7;
	legacy_pi.pi_d = &ordinary;
	mock_pci_add(&iommu_pi, &sc.vsc_vs);
	mock_pci_add(&peer_pi, &peer);
	mock_pci_add(&legacy_pi, &legacy);
	mock_pci_add(&provider_pi, &provider);

	ATF_CHECK_EQ(pci_vtiommu_post_init(&iommu_pi), EEXIST);
	ATF_CHECK_EQ(sc.vsc_endpoint_count, 0U);
	ATF_CHECK_EQ(mock_endpoint_register_calls, 0);
	ATF_CHECK_EQ(mock_dma_bind_calls, 0);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_owner_helpers_reject_null);
ATF_TC_BODY(snapshot_owner_helpers_reject_null, tc)
{
	struct pci_vtiommu_softc sc;
	struct pci_devinst pi;
	struct virtio_iommu_state *replaced;

	setup_softc(&sc);
	mock_destroy_calls = 0;
	/* Publishing rejects NULL arguments without touching ownership. */
	ATF_CHECK_EQ(pci_vtiommu_validation_publish(NULL,
	    (struct virtio_iommu_state *)(uintptr_t)1, &replaced), EINVAL);
	ATF_CHECK_EQ(pci_vtiommu_validation_publish(&sc, NULL, &replaced),
	    EINVAL);
	ATF_CHECK_EQ(pci_vtiommu_validation_publish(&sc,
	    (struct virtio_iommu_state *)(uintptr_t)1, NULL), EINVAL);

	/* Cleanup is a no-op for a NULL instance or an unlinked softc. */
	pci_vtiommu_snapshot_validate_cleanup(NULL);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = NULL;
	pci_vtiommu_snapshot_validate_cleanup(&pi);
	ATF_CHECK_EQ(mock_destroy_calls, 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_allocation_and_backend_faults);
ATF_TC_BODY(snapshot_allocation_and_backend_faults, tc)
{
	struct pci_vtiommu_softc sc;
	uint8_t image[sizeof(mock_snapshot_payload) + 20];
	uintptr_t live_token;
	size_t used;

	setup_softc(&sc);
	live_token = 1;
	sc.vsc_state = (struct virtio_iommu_state *)(void *)&live_token;
	for (size_t i = 0; i < sizeof(mock_snapshot_payload); i++)
		mock_snapshot_payload[i] = (uint8_t)i;

	/* A payload buffer allocation failure aborts the save. */
	mock_malloc_fail_armed = true;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), ENOMEM);

	/* A backend sizing failure is surfaced before the envelope is written. */
	mock_snapshot_size_error = EIO;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), EIO);
	mock_snapshot_size_error = 0;

	/* A backend copy failure is surfaced after the header. */
	mock_snapshot_error = EIO;
	ATF_CHECK_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), EIO);
	mock_snapshot_error = 0;

	/* Build a valid envelope, then corrupt individual header fields. */
	ATF_REQUIRE_EQ(run_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	/* A non-zero reserved word is rejected. */
	image[8] = 1;
	ATF_CHECK_EQ(run_snapshot(&sc, image, used, VM_SNAPSHOT_VALIDATE,
	    NULL), EINVAL);
	image[8] = 0;
	/* An out-of-range payload length is rejected. */
	le64enc(&image[12], UINT64_C(1));
	ATF_CHECK_EQ(run_snapshot(&sc, image, used, VM_SNAPSHOT_VALIDATE,
	    NULL), EINVAL);
}
#endif

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, callback_ready_contract);
	ATF_TP_ADD_TC(tp, descriptor_parser_failure_requires_reset);
	ATF_TP_ADD_TC(tp, empty_queue_race_is_not_an_error);
	ATF_TP_ADD_TC(tp, device_lifecycle_contract);
	ATF_TP_ADD_TC(tp, provider_is_not_a_translated_endpoint);
	ATF_TP_ADD_TC(tp, post_init_binds_only_eligible_modern_endpoints);
	ATF_TP_ADD_TC(tp, post_init_registration_failure_rolls_back);
	ATF_TP_ADD_TC(tp, post_init_topology_growth_fails_safely);
	ATF_TP_ADD_TC(tp, post_init_topology_failure_has_no_side_effects);
	ATF_TP_ADD_TC(tp, post_init_binding_failure_rolls_back);
	ATF_TP_ADD_TC(tp, fatal_or_reset_edge_is_not_replayed);
	ATF_TP_ADD_TC(tp, protocol_constants_match_spec);
	ATF_TP_ADD_TC(tp, device_init_success_and_failures);
	ATF_TP_ADD_TC(tp, config_space_and_features);
	ATF_TP_ADD_TC(tp, notify_routes_by_queue_index);
	ATF_TP_ADD_TC(tp, request_queue_processing_outcomes);
	ATF_TP_ADD_TC(tp, event_queue_processing_outcomes);
	ATF_TP_ADD_TC(tp, async_callbacks_obey_lifecycle_fence);
	ATF_TP_ADD_TC(tp, dma_domain_ops_delegate_to_state);
	ATF_TP_ADD_TC(tp, guest_memory_translation_hooks);
	ATF_TP_ADD_TC(tp, viot_info_reports_topology);
	ATF_TP_ADD_TC(tp, post_init_requires_a_modern_peer);
	ATF_TP_ADD_TC(tp, post_init_topology_allocation_failure);
	ATF_TP_ADD_TC(tp, post_init_wrong_provider_identity);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_owner_helpers_reject_null);
	ATF_TP_ADD_TC(tp, snapshot_allocation_and_backend_faults);
	ATF_TP_ADD_TC(tp, snapshot_wire_validation_and_restore);
	ATF_TP_ADD_TC(tp,
	    prepared_restore_fabric_is_validation_thread_scoped);
	ATF_TP_ADD_TC(tp,
	    prepared_restore_fabric_has_exclusive_owner);
#endif
	return (atf_no_error());
}

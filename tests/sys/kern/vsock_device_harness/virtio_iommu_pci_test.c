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

#ifdef BHYVE_SNAPSHOT
static uint8_t mock_snapshot_payload[VTIOMMU_STATE_MIN_SIZE];
static struct virtio_iommu_state *mock_prepared_state;
static int mock_snapshot_calls;
static int mock_restore_calls;
static int mock_prepare_calls;
static int mock_destroy_calls;
static int mock_prepare_error;
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
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov __unused,
    int niov __unused, struct vi_req *request)
{

	mock_getchain_calls++;
	mock_has_descs = 0;
	memset(request, 0, sizeof(*request));
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
    const struct iovec *iov __unused, size_t niov __unused,
    size_t *used __unused)
{

	ATF_REQUIRE_MSG(false, "an invalid/empty chain reached event parsing");
	return (EINVAL);
}

int
virtio_iommu_queue_process(struct virtio_iommu_state *state __unused,
    const struct virtio_iommu_request_options *options __unused,
    const struct iovec *iov __unused, size_t niov __unused,
    size_t readable __unused, size_t writable __unused,
    bool ordered __unused, size_t *used __unused)
{

	ATF_REQUIRE_MSG(false, "an invalid/empty chain reached request parsing");
	return (EINVAL);
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
vi_softc_linkup(struct virtio_softc *vs __unused,
    struct virtio_consts *vc __unused, void *softc __unused,
    struct pci_devinst *pi __unused, struct vqueue_info *queues __unused)
{
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy __unused)
{

	return (0);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t type __unused)
{
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{

	return (0);
}

int
vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int use_msix __unused)
{

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

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name __unused, bool def)
{

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

	return (0);
}

int
virtio_iommu_config_write(struct virtio_iommu_state *state __unused,
    uint64_t caps __unused, size_t offset __unused, size_t size __unused,
    uint32_t value __unused)
{

	return (0);
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

	*state = NULL;
	return (0);
}

void
virtio_iommu_state_reset(struct virtio_iommu_state *state __unused)
{
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

	return (false);
}

void
virtio_iommu_dma_release(struct virtio_iommu_state *state __unused,
    uint32_t endpoint __unused)
{
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

	*size = sizeof(mock_snapshot_payload);
	return (0);
}

int
virtio_iommu_state_snapshot(struct virtio_iommu_state *state __unused,
    void *buffer, size_t size)
{

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

	return (NULL);
}

uint64_t
virtio_iommu_generation(struct virtio_iommu_state *state __unused)
{

	return (0);
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
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_wire_validation_and_restore);
	ATF_TP_ADD_TC(tp,
	    prepared_restore_fabric_is_validation_thread_scoped);
	ATF_TP_ADD_TC(tp,
	    prepared_restore_fabric_has_exclusive_owner);
#endif
	return (atf_no_error());
}

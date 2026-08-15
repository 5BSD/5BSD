/*
 * Independent VirtIO 1.4 section 5.13 translation-state tests.
 */
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_state.c"

#define	DOC_MAP_READ		(1U << 0)
#define	DOC_MAP_WRITE		(1U << 1)
#define	DOC_MAP_MMIO		(1U << 2)
#define	DOC_ATTACH_BYPASS	(1U << 0)
#define	DOC_OK			0
#define	DOC_INVAL		4
#define	DOC_RANGE		5
#define	DOC_NOENT		6
#define	DOC_NOMEM		8
#define	DOC_BUSY		0xff

struct fixture {
	uint8_t memory[0x10000];
	uint64_t last_gpa;
	size_t last_length;
	enum virtio_dma_direction last_direction;
	uint32_t fault_endpoint;
	uint64_t fault_address;
	enum virtio_iommu_fault_reason fault_reason;
	unsigned int faults;
	unsigned int idle_notifications;
	uint32_t idle_endpoint;
	bool reject_gpa;
	bool block_map;
	bool map_entered;
	bool release_map;
	pthread_mutex_t map_mutex;
	pthread_cond_t map_cv;
};

static bool
validate_gpa(void *arg, uint64_t address, uint64_t length,
    uint32_t flags __unused)
{
	struct fixture *fixture;

	fixture = arg;
	if (fixture->reject_gpa)
		return (false);
	return (address <= sizeof(fixture->memory) &&
	    length <= sizeof(fixture->memory) - address);
}

static void *
map_gpa(void *arg, uint64_t address, size_t length,
    enum virtio_dma_direction direction)
{
	struct fixture *fixture;

	fixture = arg;
	fixture->last_gpa = address;
	fixture->last_length = length;
	fixture->last_direction = direction;
	if (fixture->block_map) {
		pthread_mutex_lock(&fixture->map_mutex);
		fixture->map_entered = true;
		pthread_cond_broadcast(&fixture->map_cv);
		while (!fixture->release_map)
			pthread_cond_wait(&fixture->map_cv,
			    &fixture->map_mutex);
		pthread_mutex_unlock(&fixture->map_mutex);
	}
	if (address > sizeof(fixture->memory) ||
	    length > sizeof(fixture->memory) - address)
		return (NULL);
	return (fixture->memory + address);
}

static void
record_fault(void *arg, uint32_t endpoint,
    enum virtio_iommu_fault_reason reason, uint64_t address,
    enum virtio_dma_direction direction __unused)
{
	struct fixture *fixture;

	fixture = arg;
	fixture->fault_endpoint = endpoint;
	fixture->fault_reason = reason;
	fixture->fault_address = address;
	fixture->faults++;
}

static void
record_dma_idle(void *arg, uint32_t endpoint)
{
	struct fixture *fixture;

	fixture = arg;
	fixture->idle_notifications++;
	fixture->idle_endpoint = endpoint;
}

static struct virtio_iommu_state *
new_state(struct fixture *fixture, bool bypass, uint32_t domains,
    uint32_t endpoints, uint32_t mappings)
{
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct virtio_iommu_state *state;

	limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1) << 12,
		.input_start = 0,
		.input_end = UINT32_MAX,
		.domain_start = 1,
		.domain_end = 100,
		.max_domains = domains,
		.max_endpoints = endpoints,
		.max_mappings = mappings,
		.max_faults = 2,
		.default_bypass = bypass,
		.bypass_domains = true,
		.allow_mmio = false,
	};
	ops = (struct virtio_iommu_ops) {
		.validate_gpa = validate_gpa,
		.map_gpa = map_gpa,
		.fault = record_fault,
		.dma_idle = record_dma_idle,
		.arg = fixture,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	return (state);
}

ATF_TC_WITHOUT_HEAD(table_extent_is_portable);
ATF_TC_BODY(table_extent_is_portable, tc)
{
	size_t length;
	int expected;

	(void)tc;
#if SIZE_MAX <= UINT32_MAX
	expected = UINT32_MAX > SIZE_MAX / sizeof(struct viommu_endpoint) ?
	    EOVERFLOW : 0;
#else
	expected = 0;
#endif
	ATF_CHECK_EQ(viommu_array_size(UINT32_MAX,
	    sizeof(struct viommu_endpoint), &length), expected);
	if (expected == 0) {
		ATF_CHECK_EQ(length,
		    (size_t)UINT32_MAX * sizeof(struct viommu_endpoint));
	}
	ATF_CHECK_EQ(viommu_array_size(1, 0, &length), EINVAL);
	ATF_CHECK_EQ(viommu_array_size(1, 1, NULL), EINVAL);
}

struct translate_thread_ctx {
	struct virtio_iommu_state *state;
	void *result;
	bool acquired;
};

struct restore_validate_thread_ctx {
	struct virtio_iommu_state *state;
	const void *snapshot;
	size_t snapshot_size;
	int error;
};

static void *
translate_thread(void *argument)
{
	struct translate_thread_ctx *ctx;

	ctx = argument;
	ctx->acquired = virtio_iommu_dma_acquire(ctx->state, 8);
	if (!ctx->acquired)
		return (NULL);
	ctx->result = virtio_iommu_translate(ctx->state, 8, 0x1000, 64,
	    VIRTIO_DMA_DEVICE_READ);
	virtio_iommu_dma_release(ctx->state, 8);
	return (NULL);
}

static void *
restore_validate_thread(void *argument)
{
	struct restore_validate_thread_ctx *ctx;

	ctx = argument;
	ctx->error = 0;
	for (unsigned int i = 0; i < 10000; i++) {
		ctx->error = virtio_iommu_state_restore_validate(ctx->state,
		    ctx->snapshot, ctx->snapshot_size);
		if (ctx->error != 0)
			break;
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(attach_detach_and_domain_lifetime);
ATF_TC_BODY(attach_detach_and_domain_lifetime, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 6);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 9), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 8), DOC_INVAL);
	ATF_CHECK_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_attach(state, 1, 9, 0), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_detach(state, 2, 8), DOC_INVAL);
	ATF_CHECK_EQ(virtio_iommu_detach(state, 1, 8), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_detach(state, 1, 9), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_endpoint_unregister(state, 8), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_endpoint_unregister(state, 8), DOC_NOENT);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(mapping_permissions_and_translation);
ATF_TC_BODY(mapping_permissions_and_translation, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	void *mapping;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 8);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	mapping = virtio_iommu_translate(state, 8, 0x1180, 64,
	    VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(mapping, fixture.memory + 0x4180);
	ATF_CHECK_EQ(fixture.last_gpa, 0x4180);
	ATF_CHECK_EQ(fixture.last_length, 64);
	ATF_CHECK_EQ(fixture.last_direction, VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1180, 64,
	    VIRTIO_DMA_DEVICE_WRITE), NULL);
	ATF_CHECK_EQ(fixture.faults, 1);
	ATF_CHECK_EQ(fixture.fault_reason, BHYVE_VIOMMU_FAULT_MAPPING);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1ff0, 32,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(fixture.faults, 2);
	ATF_CHECK_EQ(fixture.fault_address, 0x1ff0);

	/*
	 * A device DMA transaction may cross separately installed adjacent
	 * mappings.  Coalesce them when both IOVA and GPA are contiguous, but
	 * never manufacture a single host pointer across a physical gap.
	 */
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x2000, 0x2fff, 0x5000,
	    DOC_MAP_READ), DOC_OK);
	mapping = virtio_iommu_translate(state, 8, 0x1ff0, 32,
	    VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(mapping, fixture.memory + 0x4ff0);
	ATF_CHECK_EQ(fixture.last_gpa, 0x4ff0);
	ATF_CHECK_EQ(fixture.last_length, 32);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x3000, 0x3fff, 0x7000,
	    DOC_MAP_READ), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x2ff0, 32,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(fixture.faults, 3);
	ATF_CHECK_EQ(fixture.fault_address, 0x2ff0);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x5000, 0x5fff, 0x9000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x4000, 0x4fff, 0x8000,
	    DOC_MAP_READ), DOC_OK);
	mapping = virtio_iommu_translate(state, 8, 0x4ff0, 32,
	    VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(mapping, fixture.memory + 0x8ff0);
	ATF_CHECK_EQ(fixture.last_gpa, 0x8ff0);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x6000, 0x6fff, 0xa000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x7000, 0x7fff, 0xb000,
	    DOC_MAP_WRITE), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x6ff0, 32,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(fixture.faults, 4);
	ATF_CHECK_EQ(fixture.fault_address, 0x6ff0);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(map_validation_is_atomic);
ATF_TC_BODY(map_validation_is_atomic, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 2);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1001, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_RANGE);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4001,
	    DOC_MAP_READ), DOC_RANGE);
	fixture.reject_gpa = true;
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_RANGE);
	fixture.reject_gpa = false;
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x10000,
	    DOC_MAP_READ), DOC_RANGE);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_MMIO), DOC_INVAL);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ | DOC_MAP_WRITE), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x0000, 0x2fff, 0x6000,
	    DOC_MAP_READ), DOC_INVAL);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(byte_granularity_rejects_single_byte_mapping);
ATF_TC_BODY(byte_granularity_rejects_single_byte_mapping, tc)
{
	struct fixture fixture;
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct virtio_iommu_state *state;
	uint8_t *corrupt, *snapshot;
	size_t snapshot_size;

	memset(&fixture, 0, sizeof(fixture));
	/*
	 * A page-size mask with bit zero permits byte alignment, but VirtIO 1.4
	 * section 5.13.6.5.1 independently requires virt_end to be strictly
	 * greater than virt_start.  Keep these values literal so the minimum
	 * legal mapping boundary is independent of implementation constants.
	 */
	limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1),
		.input_start = 0,
		.input_end = UINT32_MAX,
		.domain_start = 1,
		.domain_end = 1,
		.max_domains = 1,
		.max_endpoints = 1,
		.max_mappings = 2,
		.max_faults = 2,
	};
	ops = (struct virtio_iommu_ops) {
		.validate_gpa = validate_gpa,
		.map_gpa = map_gpa,
		.fault = record_fault,
		.arg = &fixture,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x80, 0x80, 0x100,
	    DOC_MAP_READ), DOC_RANGE);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x80, 0x81, 0x100,
	    DOC_MAP_READ), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 2,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x100);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 3,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	/*
	 * Runtime and portable-state range validation must agree.  Otherwise a
	 * device can accept and use a mapping that its own checkpoint cannot
	 * restore.
	 */
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &snapshot_size),
	    0);
	snapshot = malloc(snapshot_size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(state, snapshot,
	    snapshot_size), 0);
	corrupt = malloc(snapshot_size);
	ATF_REQUIRE(corrupt != NULL);
	memcpy(corrupt, snapshot, snapshot_size);
	/*
	 * The current VIMS encoding uses a 96-byte header, a 12-byte endpoint,
	 * a 16-byte domain, then virtual_start and virtual_end as little-endian
	 * u64s.
	 * Make the encoded range one byte long and refresh its corruption
	 * detector.  Restore must apply the same strict range rule as MAP.
	 */
	le64enc(corrupt + 96 + 12 + 16 + 8, 0x80);
	le64enc(corrupt + 88, viommu_state_digest(corrupt, snapshot_size));
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, corrupt,
	    snapshot_size), EPROTO);
	free(corrupt);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore(state, snapshot,
	    snapshot_size), 0);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 2,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x100);
	free(snapshot);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x80, 0x81), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(unmap_whole_mappings_only);
ATF_TC_BODY(unmap_whole_mappings_only, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 4);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x3000, 0x3fff, 0x6000,
	    DOC_MAP_READ), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1800, 0x3fff),
	    DOC_RANGE);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 2);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0, 0x4fff), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0, 0x4fff), DOC_OK);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(unmap_multiple_mappings_stays_within_storage);
ATF_TC_BODY(unmap_multiple_mappings_stays_within_storage, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 3);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x3000, 0x3fff, 0x6000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x5000, 0x5fff, 0x8000,
	    DOC_MAP_READ), DOC_OK);

	/*
	 * Removing N entries clears exactly N vacated slots.  The harness runs
	 * this under AddressSanitizer, so an oversized clear crosses the
	 * three-entry allocation immediately.
	 */
	ATF_REQUIRE_EQ(virtio_iommu_unmap(state, 1, 0, 0x5fff), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_fault_dropped(state), 0);
	ATF_CHECK_EQ(fixture.faults, 0);

	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(concurrent_unmap_linearizes_active_translation);
ATF_TC_BODY(concurrent_unmap_linearizes_active_translation, tc)
{
	struct translate_thread_ctx ctx;
	struct fixture fixture;
	struct virtio_iommu_state *state;
	pthread_t thread;

	memset(&fixture, 0, sizeof(fixture));
	ATF_REQUIRE_EQ(pthread_mutex_init(&fixture.map_mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&fixture.map_cv, NULL), 0);
	fixture.block_map = true;
	state = new_state(&fixture, false, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ctx = (struct translate_thread_ctx) {
		.state = state,
	};
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, translate_thread, &ctx),
	    0);
	pthread_mutex_lock(&fixture.map_mutex);
	while (!fixture.map_entered)
		pthread_cond_wait(&fixture.map_cv, &fixture.map_mutex);
	pthread_mutex_unlock(&fixture.map_mutex);

	/*
	 * The device accepted this DMA before UNMAP.  VirtIO 1.4 requires
	 * revocation to be effective when the request completes, so the
	 * internal scheduler keeps UNMAP pending instead of publishing an OK
	 * status while the old transaction still owns a host pointer.
	 */
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1000, 0x1fff),
	    DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_detach(state, 1, 8), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_attach(state, 2, 8, 0), DOC_BUSY);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &(size_t){ 0 }),
	    0);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state,
	    (uint8_t[VIOMMU_STATE_HEADER_SIZE + VIOMMU_STATE_ENDPOINT_SIZE +
	    VIOMMU_STATE_DOMAIN_SIZE + VIOMMU_STATE_MAPPING_SIZE]){ 0 },
	    VIOMMU_STATE_HEADER_SIZE + VIOMMU_STATE_ENDPOINT_SIZE +
	    VIOMMU_STATE_DOMAIN_SIZE + VIOMMU_STATE_MAPPING_SIZE), EBUSY);
	pthread_mutex_lock(&fixture.map_mutex);
	fixture.release_map = true;
	pthread_cond_broadcast(&fixture.map_cv);
	pthread_mutex_unlock(&fixture.map_mutex);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_REQUIRE(ctx.acquired);
	ATF_CHECK_EQ(ctx.result, fixture.memory + 0x4000);
	ATF_CHECK_EQ(fixture.idle_notifications, 1);
	ATF_CHECK_EQ(fixture.idle_endpoint, 8);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1000, 0x1fff), DOC_OK);
	fixture.block_map = false;
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1000, 64,
	    VIRTIO_DMA_DEVICE_READ), NULL);

	virtio_iommu_state_destroy(state);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&fixture.map_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&fixture.map_mutex), 0);
}

ATF_TC_WITHOUT_HEAD(domain_revocation_waits_for_every_endpoint);
ATF_TC_BODY(domain_revocation_waits_for_every_endpoint, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 2, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 9), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 9, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);

	/*
	 * UNMAP revokes a domain mapping, not merely the requester which
	 * submitted the control command.  An outstanding lease on either
	 * attached endpoint must therefore retain the mapping.  The release
	 * callback identifies the endpoint which made the domain idle and is
	 * the event-driven retry edge for the returned control descriptor.
	 */
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 9));
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1000, 0x1fff),
	    DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_CHECK_EQ(fixture.idle_notifications, 0);
	virtio_iommu_dma_release(state, 9);
	ATF_CHECK_EQ(fixture.idle_notifications, 1);
	ATF_CHECK_EQ(fixture.idle_endpoint, 9);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1000, 0x1fff), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);

	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(bypass_reset_and_capacity);
ATF_TC_BODY(bypass_reset_and_capacity, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	uint64_t generation;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, true, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 9), DOC_NOMEM);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 8,
	    VIRTIO_DMA_DEVICE_WRITE), fixture.memory + 0x80);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8,
	    DOC_ATTACH_BYPASS), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x88, 8,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x88);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_INVAL);
	/*
	 * A one-slot domain table can still move its sole endpoint because the
	 * old domain ceases to exist as part of the operation.
	 */
	ATF_CHECK_EQ(virtio_iommu_attach(state, 2, 8,
	    DOC_ATTACH_BYPASS), DOC_OK);
	generation = virtio_iommu_generation(state);
	virtio_iommu_state_reset(state);
	ATF_CHECK(virtio_iommu_generation(state) > generation);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x90, 4,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x90);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(bypass_transition_linearizes_future_dma);
ATF_TC_BODY(bypass_transition_linearizes_future_dma, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	uint8_t *authorized;
	uint64_t generation, transition_generation;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, true, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);

	/*
	 * The first lease linearizes while the unattached endpoint bypasses
	 * translation.  Disabling bypass affects later translations and
	 * advances the cache epoch, but cannot invalidate the already pinned
	 * guest-RAM pointer retained by the first request.
	 */
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	authorized = virtio_iommu_translate(state, 8, 0x80, 8,
	    VIRTIO_DMA_DEVICE_WRITE);
	ATF_REQUIRE_EQ(authorized, fixture.memory + 0x80);
	generation = virtio_iommu_generation(state);
	virtio_iommu_set_default_bypass(state, false);
	ATF_CHECK(virtio_iommu_generation(state) > generation);
	transition_generation = virtio_iommu_generation(state);
	authorized[0] = 0x5a;
	ATF_CHECK_EQ(fixture.memory[0x80], 0x5a);

	/*
	 * A second overlapping request joins the endpoint's existing lease
	 * epoch.  It must not observe a different address space halfway
	 * through the active set.
	 */
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 8,
	    VIRTIO_DMA_DEVICE_WRITE), fixture.memory + 0x80);
	virtio_iommu_dma_release(state, 8);
	virtio_iommu_dma_release(state, 8);
	ATF_CHECK(virtio_iommu_generation(state) > transition_generation);

	/* The first request after the old active set drains sees the write. */
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x80, 8,
	    VIRTIO_DMA_DEVICE_WRITE), NULL);
	virtio_iommu_dma_release(state, 8);

	virtio_iommu_set_default_bypass(state, true);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x88, 8,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x88);
	virtio_iommu_dma_release(state, 8);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(deferred_reset_fences_control_plane);
ATF_TC_BODY(deferred_reset_fences_control_plane, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	uint64_t generation;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 2);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	generation = virtio_iommu_generation(state);

	/*
	 * Reset cannot revoke a mapping from an already accepted DMA request,
	 * so it becomes pending.  Until the final release performs the reset,
	 * no new control operation may mutate the state which is waiting to be
	 * discarded.
	 */
	virtio_iommu_state_reset(state);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 9), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_endpoint_unregister(state, 8), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_attach(state, 2, 8, 0), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_detach(state, 1, 8), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0x2000, 0x2fff, 0x5000,
	    DOC_MAP_READ), DOC_BUSY);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1, 0x1000, 0x1fff),
	    DOC_BUSY);
	ATF_CHECK(!virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	/*
	 * The reset fences new work but cannot revoke the DMA lease accepted
	 * before it became pending.  That request must still translate through
	 * the address space it pinned, otherwise deferred reset would turn a
	 * legal in-flight descriptor into a use-after-unmap.
	 */
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1100, 64,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);
	ATF_CHECK_EQ(fixture.faults, 0);

	virtio_iommu_dma_release(state, 8);
	ATF_CHECK_EQ(fixture.idle_notifications, 1);
	ATF_CHECK_EQ(fixture.idle_endpoint, 8U);
	ATF_CHECK(virtio_iommu_generation(state) > generation);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_endpoint_register(state, 9), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_attach(state, 2, 8, 0), DOC_OK);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(portable_snapshot_is_transactional);
ATF_TC_BODY(portable_snapshot_is_transactional, tc)
{
	struct fixture fixture;
	struct virtio_iommu_fault fault;
	struct virtio_iommu_state *prepared, *state;
	uint8_t *snapshot, *corrupt;
	uint64_t generation;
	size_t size;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 4);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 9), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 7, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 7, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ | DOC_MAP_WRITE), DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x3000, 16,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	generation = virtio_iommu_generation(state);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	ATF_CHECK_EQ(size, 96 + 2 * 12 + 16 + 40 + 24);
	snapshot = malloc(size);
	corrupt = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(state, snapshot, size), 0);
	ATF_CHECK_EQ(le32dec(snapshot + 0), UINT32_C(0x534d4956));
	ATF_CHECK_EQ(le16dec(snapshot + 4), 1);
	ATF_CHECK_EQ(le16dec(snapshot + 6), 96);
	ATF_CHECK_EQ(le64dec(snapshot + 8), size);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore_validate(state, snapshot,
	    size), 0);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1100, 16,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);

	virtio_iommu_state_reset(state);
	generation = virtio_iommu_generation(state);
	prepared = NULL;
	ATF_REQUIRE_EQ(virtio_iommu_state_restore_prepare(state, snapshot,
	    size, &prepared), 0);
	ATF_REQUIRE(prepared != NULL);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(prepared), 1);
	ATF_CHECK_EQ(virtio_iommu_translate(prepared, 8, 0x1100, 16,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);
	{
		unsigned int faults;

		faults = fixture.faults;
		ATF_CHECK_EQ(virtio_iommu_translate(prepared, 8, 0x3000, 16,
		    VIRTIO_DMA_DEVICE_READ), NULL);
		ATF_CHECK_EQ(fixture.faults, faults);
	}
	virtio_iommu_state_destroy(prepared);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore(state, snapshot, size), 0);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation + 1);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_REQUIRE(virtio_iommu_fault_pop(state, &fault));
	ATF_CHECK_EQ(fault.endpoint, 8);
	ATF_CHECK_EQ(fault.address, 0x3000);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1100, 16,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);
	generation = virtio_iommu_generation(state);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore(state, snapshot, size), 0);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation + 1);

	memcpy(corrupt, snapshot, size);
	corrupt[size - 1] ^= 1;
	generation = virtio_iommu_generation(state);
	prepared = (struct virtio_iommu_state *)(uintptr_t)1;
	ATF_CHECK_EQ(virtio_iommu_state_restore_prepare(state, corrupt, size,
	    &prepared), EPROTO);
	ATF_CHECK_EQ(prepared, NULL);
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(state, corrupt, size),
	    EPROTO);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, corrupt, size), EPROTO);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, snapshot, size - 1),
	    EPROTO);

	memcpy(corrupt, snapshot, size);
	corrupt[76] = 1;
	le64enc(corrupt + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(corrupt, size));
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, corrupt, size), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);

	/*
	 * A structurally invalid attachment must still be rejected after its
	 * corruption detector is recomputed, and must not alter live state.
	 */
	memcpy(corrupt, snapshot, size);
	le32enc(corrupt + 96 + 4, 99);
	le64enc(corrupt + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(corrupt, size));
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, corrupt, size), EPROTO);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1100, 16,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);
	free(corrupt);
	free(snapshot);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(restore_preflight_serializes_live_config);
ATF_TC_BODY(restore_preflight_serializes_live_config, tc)
{
	struct fixture source_fixture, target_fixture;
	struct restore_validate_thread_ctx ctx;
	struct virtio_iommu_state *source, *target;
	uint8_t *snapshot;
	pthread_t thread;
	size_t size;

	(void)tc;
	memset(&source_fixture, 0, sizeof(source_fixture));
	memset(&target_fixture, 0, sizeof(target_fixture));
	source = new_state(&source_fixture, true, 1, 1, 1);
	target = new_state(&target_fixture, false, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(source, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(target, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(source, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(source, snapshot, size), 0);
	ctx = (struct restore_validate_thread_ctx) {
		.state = target,
		.snapshot = snapshot,
		.snapshot_size = size,
	};
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, restore_validate_thread,
	    &ctx), 0);
	for (unsigned int i = 0; i < 10000; i++)
		virtio_iommu_set_default_bypass(target, (i & 1) != 0);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(ctx.error, 0);
	free(snapshot);
	virtio_iommu_state_destroy(target);
	virtio_iommu_state_destroy(source);
}

ATF_TC_WITHOUT_HEAD(snapshot_mapping_order_is_canonical);
ATF_TC_BODY(snapshot_mapping_order_is_canonical, tc)
{
	struct fixture fixture_a, fixture_b;
	struct virtio_iommu_state *a, *b;
	uint8_t temporary[VIOMMU_STATE_MAPPING_SIZE];
	uint8_t *cursor, *image_a, *image_b;
	size_t size_a, size_b;

	memset(&fixture_a, 0, sizeof(fixture_a));
	memset(&fixture_b, 0, sizeof(fixture_b));
	a = new_state(&fixture_a, false, 2, 3, 4);
	b = new_state(&fixture_b, false, 2, 3, 4);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(a, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(a, 9), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(b, 9), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(b, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(a, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(a, 2, 9, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(b, 2, 9, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(b, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(a, 1, 0x3000, 0x3fff, 0x6000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(a, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(b, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(b, 1, 0x3000, 0x3fff, 0x6000,
	    DOC_MAP_READ), DOC_OK);
	/*
	 * The cache invalidation generation is destination-local and must not
	 * make two otherwise equivalent portable images differ.
	 */
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(a, 10), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_unregister(a, 10), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(a, &size_a), 0);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(b, &size_b), 0);
	ATF_REQUIRE_EQ(size_a, size_b);
	image_a = malloc(size_a);
	image_b = malloc(size_b);
	ATF_REQUIRE(image_a != NULL);
	ATF_REQUIRE(image_b != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(a, image_a, size_a), 0);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(b, image_b, size_b), 0);
	ATF_CHECK(memcmp(image_a, image_b, size_a) == 0);

	/* The sole accepted format requires its destination-local slot zero. */
	le64enc(image_b + 16, 1);
	le64enc(image_b + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(image_b, size_b));
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(a, image_b, size_b),
	    EPROTO);
	memcpy(image_b, image_a, size_a);

	/* Every variable-length record class is encoded in canonical order. */
	cursor = image_b + VIOMMU_STATE_HEADER_SIZE;
	memcpy(temporary, cursor, VIOMMU_STATE_ENDPOINT_SIZE);
	memcpy(cursor, cursor + VIOMMU_STATE_ENDPOINT_SIZE,
	    VIOMMU_STATE_ENDPOINT_SIZE);
	memcpy(cursor + VIOMMU_STATE_ENDPOINT_SIZE, temporary,
	    VIOMMU_STATE_ENDPOINT_SIZE);
	le64enc(image_b + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(image_b, size_b));
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(a, image_b, size_b),
	    EPROTO);
	memcpy(image_b, image_a, size_a);

	cursor = image_b + VIOMMU_STATE_HEADER_SIZE +
	    2 * VIOMMU_STATE_ENDPOINT_SIZE;
	memcpy(temporary, cursor, VIOMMU_STATE_DOMAIN_SIZE);
	memcpy(cursor, cursor + VIOMMU_STATE_DOMAIN_SIZE,
	    VIOMMU_STATE_DOMAIN_SIZE);
	memcpy(cursor + VIOMMU_STATE_DOMAIN_SIZE, temporary,
	    VIOMMU_STATE_DOMAIN_SIZE);
	le64enc(image_b + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(image_b, size_b));
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(a, image_b, size_b),
	    EPROTO);
	memcpy(image_b, image_a, size_a);

	cursor = image_b + VIOMMU_STATE_HEADER_SIZE +
	    2 * VIOMMU_STATE_ENDPOINT_SIZE + 2 * VIOMMU_STATE_DOMAIN_SIZE;
	memcpy(temporary, cursor, VIOMMU_STATE_MAPPING_SIZE);
	memcpy(cursor, cursor + VIOMMU_STATE_MAPPING_SIZE,
	    VIOMMU_STATE_MAPPING_SIZE);
	memcpy(cursor + VIOMMU_STATE_MAPPING_SIZE, temporary,
	    VIOMMU_STATE_MAPPING_SIZE);
	le64enc(image_b + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(image_b, size_b));
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(a, image_b, size_b),
	    EPROTO);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(a), 2);
	free(image_b);
	free(image_a);
	virtio_iommu_state_destroy(b);
	virtio_iommu_state_destroy(a);
}

ATF_TC_WITHOUT_HEAD(active_dma_fences_every_state_transfer_phase);
ATF_TC_BODY(active_dma_fences_every_state_transfer_phase, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *prepared, *state;
	uint8_t *snapshot;
	uint64_t generation;
	size_t size;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 7, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 7, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(state, snapshot, size), 0);

	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	generation = virtio_iommu_generation(state);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, snapshot, size), EBUSY);
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(state, snapshot, size),
	    EBUSY);
	prepared = (struct virtio_iommu_state *)(uintptr_t)1;
	ATF_CHECK_EQ(virtio_iommu_state_restore_prepare(state, snapshot, size,
	    &prepared), EBUSY);
	ATF_CHECK_EQ(prepared, NULL);
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, snapshot, size), EBUSY);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1100, 16,
	    VIRTIO_DMA_DEVICE_READ), fixture.memory + 0x4100);

	virtio_iommu_dma_release(state, 8);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore_validate(state, snapshot,
	    size), 0);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore(state, snapshot, size), 0);
	free(snapshot);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(fault_fifo_is_bounded_and_portable);
ATF_TC_BODY(fault_fifo_is_bounded_and_portable, tc)
{
	struct fixture fixture;
	struct virtio_iommu_fault fault;
	struct virtio_iommu_state *state;
	uint64_t generation;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	generation = virtio_iommu_generation(state);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1000, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x2000, 8,
	    VIRTIO_DMA_DEVICE_WRITE), NULL);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x3000, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(virtio_iommu_fault_dropped(state), 1);
	ATF_CHECK_EQ(virtio_iommu_generation(state), generation);
	ATF_REQUIRE(virtio_iommu_fault_pop(state, &fault));
	ATF_CHECK_EQ(fault.reason, BHYVE_VIOMMU_FAULT_DOMAIN);
	ATF_CHECK_EQ(fault.flags, BHYVE_VIOMMU_FAULT_F_READ |
	    BHYVE_VIOMMU_FAULT_F_ADDRESS);
	ATF_CHECK_EQ(fault.endpoint, 8);
	ATF_CHECK_EQ(fault.address, 0x1000);
	ATF_REQUIRE(virtio_iommu_fault_pop(state, &fault));
	ATF_CHECK_EQ(fault.flags, BHYVE_VIOMMU_FAULT_F_WRITE |
	    BHYVE_VIOMMU_FAULT_F_ADDRESS);
	ATF_CHECK_EQ(fault.address, 0x2000);
	ATF_CHECK(!virtio_iommu_fault_pop(state, &fault));
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(fault_loss_counter_saturates);
ATF_TC_BODY(fault_loss_counter_saturates, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 1, 1, 1);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);

	/* Fill the bounded FIFO before forcing losses. */
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x1000, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x2000, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	state->fault_dropped = UINT64_MAX;
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8, 0x3000, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	ATF_CHECK_EQ(virtio_iommu_fault_dropped(state), UINT64_MAX);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(snapshot_output_alias_is_rejected);
ATF_TC_BODY(snapshot_output_alias_is_rejected, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	uint8_t *snapshot;
	size_t size;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 2);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, state, size), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, state->endpoints, size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(state, state, size),
	    EINVAL);
	ATF_CHECK_EQ(virtio_iommu_state_restore(state, state->endpoints, size),
	    EINVAL);
	ATF_CHECK_EQ(state->endpoint_count, 0);
	ATF_CHECK_EQ(state->domain_count, 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, snapshot, size), 0);
	free(snapshot);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(snapshot_internal_accounting_is_rejected);
ATF_TC_BODY(snapshot_internal_accounting_is_rejected, tc)
{
	struct fixture fixture;
	struct virtio_iommu_state *state;
	struct viommu_domain *domains;
	struct viommu_endpoint *endpoints;
	struct viommu_mapping *mappings;
	struct virtio_iommu_fault *faults;
	uint8_t *snapshot;
	size_t size;

	memset(&fixture, 0, sizeof(fixture));
	state = new_state(&fixture, false, 2, 2, 2);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x1000, 0x1fff, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	snapshot = malloc(size);
	ATF_REQUIRE(snapshot != NULL);

	/*
	 * White-box corruption models a violated live bookkeeping invariant.  The
	 * serializer must reject it before a cached count becomes a temporary
	 * allocation size or cursor bound, and must leave the caller's output
	 * untouched.
	 */
	endpoints = state->endpoints;
	state->endpoints = NULL;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->endpoints = endpoints;
	domains = state->domains;
	state->domains = NULL;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->domains = domains;
	mappings = state->mappings;
	state->mappings = NULL;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->mappings = mappings;
	faults = state->faults;
	state->faults = NULL;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->faults = faults;

	memset(snapshot, 0xa5, size);
	state->endpoint_count = 0;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, snapshot, size), EPROTO);
	for (size_t i = 0; i < size; i++)
		ATF_CHECK_EQ(snapshot[i], 0xa5);
	state->endpoint_count = 1;

	state->domain_count = 0;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->domain_count = 1;

	state->mapping_scan_limit = 0;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->mapping_scan_limit = 1;

	state->mappings[0].domain = 2;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->mappings[0].domain = 1;

	state->mappings[0].virtual_start++;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->mappings[0].virtual_start--;

	state->mappings[0].present = false;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->mappings[0].present = true;

	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1, 0x3000, 0x3fff, 0x6000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	{
		struct viommu_mapping temporary;

		temporary = state->mappings[0];
		state->mappings[0] = state->mappings[1];
		state->mappings[1] = temporary;
	}
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	{
		struct viommu_mapping temporary;

		temporary = state->mappings[0];
		state->mappings[0] = state->mappings[1];
		state->mappings[1] = temporary;
	}
	ATF_REQUIRE_EQ(virtio_iommu_unmap(state, 1, 0x3000, 0x3fff), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);

	state->fault_count = state->limits.max_faults + 1;
	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), EPROTO);
	state->fault_count = 0;

	ATF_CHECK_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	ATF_CHECK_EQ(virtio_iommu_state_snapshot(state, snapshot, size), 0);
	free(snapshot);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(final_iova_page_maps_and_restores);
ATF_TC_BODY(final_iova_page_maps_and_restores, tc)
{
	struct fixture fixture;
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct virtio_iommu_state *state;
	uint8_t *corrupt, *mapping, *snapshot;
	size_t size;

	memset(&fixture, 0, sizeof(fixture));
	limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1) << 12,
		.input_start = 0,
		.input_end = UINT64_MAX,
		.domain_start = 1,
		.domain_end = 1,
		.max_domains = 1,
		.max_endpoints = 1,
		.max_mappings = 1,
		.max_faults = 2,
	};
	ops = (struct virtio_iommu_ops) {
		.validate_gpa = validate_gpa,
		.map_gpa = map_gpa,
		.fault = record_fault,
		.arg = &fixture,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 8), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 1, 8, 0), DOC_OK);
	/* An inclusive span of 2^64 bytes has no representable byte length. */
	ATF_CHECK_EQ(virtio_iommu_map(state, 1, 0, UINT64_MAX, 0,
	    DOC_MAP_READ), DOC_RANGE);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 0);
	/*
	 * Section 5.13.6.5 defines alignment using (virt_end + 1).  For the
	 * final inclusive page, unsigned addition wraps to zero, which is page
	 * aligned.  The production input_range advertises this exact upper
	 * bound, so MAP, translation, snapshot, and restore must agree on it.
	 */
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 1,
	    UINT64_MAX - UINT64_C(0xfff), UINT64_MAX, 0x4000,
	    DOC_MAP_READ), DOC_OK);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8,
	    UINT64_MAX - UINT64_C(0x7f), 128, VIRTIO_DMA_DEVICE_READ),
	    fixture.memory + 0x4f80);
	virtio_iommu_dma_release(state, 8);

	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot_size(state, &size), 0);
	snapshot = malloc(size);
	corrupt = malloc(size);
	ATF_REQUIRE(snapshot != NULL);
	ATF_REQUIRE(corrupt != NULL);
	ATF_REQUIRE_EQ(virtio_iommu_state_snapshot(state, snapshot, size), 0);
	/* Restore must reject the same unrepresentable full-span mapping. */
	memcpy(corrupt, snapshot, size);
	mapping = corrupt + VIOMMU_STATE_HEADER_SIZE +
	    VIOMMU_STATE_ENDPOINT_SIZE + VIOMMU_STATE_DOMAIN_SIZE;
	le64enc(mapping + 0, 0);
	le64enc(mapping + 8, UINT64_MAX);
	le64enc(mapping + 16, 0);
	le64enc(corrupt + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(corrupt, size));
	ATF_CHECK_EQ(virtio_iommu_state_restore_validate(state, corrupt, size),
	    EPROTO);
	ATF_CHECK_EQ(virtio_iommu_mapping_count(state), 1);
	virtio_iommu_state_reset(state);
	ATF_REQUIRE_EQ(virtio_iommu_state_restore(state, snapshot, size), 0);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 8));
	ATF_CHECK_EQ(virtio_iommu_translate(state, 8,
	    UINT64_MAX - UINT64_C(0xfff), 4096, VIRTIO_DMA_DEVICE_READ),
	    fixture.memory + 0x4000);
	virtio_iommu_dma_release(state, 8);
	ATF_CHECK_EQ(virtio_iommu_unmap(state, 1,
	    UINT64_MAX - UINT64_C(0xfff), UINT64_MAX), DOC_OK);

	free(corrupt);
	free(snapshot);
	virtio_iommu_state_destroy(state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, table_extent_is_portable);
	ATF_TP_ADD_TC(tp, attach_detach_and_domain_lifetime);
	ATF_TP_ADD_TC(tp, mapping_permissions_and_translation);
	ATF_TP_ADD_TC(tp, map_validation_is_atomic);
	ATF_TP_ADD_TC(tp, byte_granularity_rejects_single_byte_mapping);
	ATF_TP_ADD_TC(tp, unmap_whole_mappings_only);
	ATF_TP_ADD_TC(tp, unmap_multiple_mappings_stays_within_storage);
	ATF_TP_ADD_TC(tp, concurrent_unmap_linearizes_active_translation);
	ATF_TP_ADD_TC(tp, domain_revocation_waits_for_every_endpoint);
	ATF_TP_ADD_TC(tp, bypass_reset_and_capacity);
	ATF_TP_ADD_TC(tp, bypass_transition_linearizes_future_dma);
	ATF_TP_ADD_TC(tp, deferred_reset_fences_control_plane);
	ATF_TP_ADD_TC(tp, portable_snapshot_is_transactional);
	ATF_TP_ADD_TC(tp, restore_preflight_serializes_live_config);
	ATF_TP_ADD_TC(tp, snapshot_mapping_order_is_canonical);
	ATF_TP_ADD_TC(tp, active_dma_fences_every_state_transfer_phase);
	ATF_TP_ADD_TC(tp, fault_fifo_is_bounded_and_portable);
	ATF_TP_ADD_TC(tp, fault_loss_counter_saturates);
	ATF_TP_ADD_TC(tp, snapshot_output_alias_is_rejected);
	ATF_TP_ADD_TC(tp, snapshot_internal_accounting_is_rejected);
	ATF_TP_ADD_TC(tp, final_iova_page_maps_and_restores);
	return (atf_no_error());
}

/*
 * Independent VirtIO 1.4 section 5.13 event-virtqueue tests.
 */
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_state.c"
#include "virtio_iommu_protocol.c"
#include "virtio_iommu_event.c"

static uint8_t event_guest_memory[0x10000];

static void *
event_map_gpa(void *arg __unused, uint64_t address, size_t length,
    enum virtio_dma_direction direction __unused)
{

	if (address > sizeof(event_guest_memory) ||
	    length > sizeof(event_guest_memory) - address)
		return (NULL);
	return (event_guest_memory + address);
}

static struct virtio_iommu_state *
event_state(void)
{
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct virtio_iommu_state *state;

	limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1) << 12,
		.input_start = 0,
		.input_end = UINT32_MAX,
		.domain_start = 0,
		.domain_end = UINT32_MAX,
		.max_domains = 1,
		.max_endpoints = 1,
		.max_mappings = 1,
		.max_faults = 2,
	};
	ops = (struct virtio_iommu_ops) {
		.map_gpa = event_map_gpa,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 0x108), 0);
	return (state);
}

ATF_TC_WITHOUT_HEAD(short_buffer_does_not_consume);
ATF_TC_BODY(short_buffer_does_not_consume, tc)
{
	struct virtio_iommu_state *state;
	struct iovec iov;
	uint8_t output[24];
	size_t used;

	state = event_state();
	ATF_CHECK_EQ(virtio_iommu_translate(state, 0x108, 0x1234, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	iov = (struct iovec) {
		.iov_base = output,
		.iov_len = sizeof(output) - 1,
	};
	ATF_CHECK_EQ(virtio_iommu_event_process(state, &iov, 1, &used),
	    EMSGSIZE);
	ATF_CHECK_EQ(used, 0);
	iov.iov_len = sizeof(output);
	ATF_REQUIRE_EQ(virtio_iommu_event_process(state, &iov, 1, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], 1);
	ATF_CHECK_EQ(le32dec(output + 4), UINT32_C(0x101));
	ATF_CHECK_EQ(le32dec(output + 8), UINT32_C(0x108));
	ATF_CHECK_EQ(le64dec(output + 16), UINT64_C(0x1234));
	ATF_CHECK_EQ(virtio_iommu_event_process(state, &iov, 1, &used),
	    EAGAIN);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(fragmented_event_scatter);
ATF_TC_BODY(fragmented_event_scatter, tc)
{
	struct virtio_iommu_state *state;
	struct iovec iov[3];
	uint8_t output[24];
	size_t used;

	state = event_state();
	ATF_CHECK_EQ(virtio_iommu_translate(state, 0x108, 0x5678, 8,
	    VIRTIO_DMA_DEVICE_WRITE), NULL);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec) { .iov_base = output, .iov_len = 3 };
	iov[1] = (struct iovec) { .iov_base = output + 3, .iov_len = 7 };
	iov[2] = (struct iovec) { .iov_base = output + 10, .iov_len = 14 };
	ATF_REQUIRE_EQ(virtio_iommu_event_process(state, iov, 3, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(le32dec(output + 4), UINT32_C(0x102));
	ATF_CHECK_EQ(le64dec(output + 16), UINT64_C(0x5678));
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(alias_rejection_preserves_fault);
ATF_TC_BODY(alias_rejection_preserves_fault, tc)
{
	struct virtio_iommu_state *state;
	struct iovec iov[2];
	uint8_t output[24];
	size_t used;

	state = event_state();
	ATF_CHECK_EQ(virtio_iommu_translate(state, 0x108, 0x9876, 8,
	    VIRTIO_DMA_DEVICE_READ), NULL);
	memset(output, 0xa5, sizeof(output));
	used = SIZE_MAX;
	iov[0] = (struct iovec) {
		.iov_base = output,
		.iov_len = 16,
	};
	iov[1] = (struct iovec) {
		.iov_base = output + 8,
		.iov_len = 16,
	};
	ATF_CHECK_EQ(virtio_iommu_event_process(state, iov, 2, &used),
	    EINVAL);
	ATF_CHECK_EQ(used, SIZE_MAX);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	iov[0].iov_len = sizeof(output);
	ATF_CHECK_EQ(virtio_iommu_event_process(state, iov, 1,
	    (size_t *)(void *)output), EINVAL);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	ATF_REQUIRE_EQ(virtio_iommu_event_process(state, iov, 1, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(le64dec(output + 16), UINT64_C(0x9876));
	virtio_iommu_state_destroy(state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, alias_rejection_preserves_fault);
	ATF_TP_ADD_TC(tp, short_buffer_does_not_consume);
	ATF_TP_ADD_TC(tp, fragmented_event_scatter);
	return (atf_no_error());
}

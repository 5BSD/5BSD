/*
 * Independent VirtIO 1.4 section 5.13 request-virtqueue tests.
 */
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_protocol.c"
#include "virtio_iommu_state.c"
#include "virtio_iommu_request.c"
#include "virtio_iommu_queue.c"

#define	DOC_ATTACH	1
#define	DOC_PROBE	5
#define	DOC_OK		0
#define	DOC_INVAL	4

static uint8_t queue_guest_memory[0x10000];

static void *
queue_map_gpa(void *arg __unused, uint64_t address, size_t length,
    enum virtio_dma_direction direction __unused)
{

	if (address > sizeof(queue_guest_memory) ||
	    length > sizeof(queue_guest_memory) - address)
		return (NULL);
	return (queue_guest_memory + address);
}

static struct virtio_iommu_state *
queue_state(void)
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
		.max_domains = 4,
		.max_endpoints = 4,
		.max_mappings = 8,
		.bypass_domains = true,
	};
	ops = (struct virtio_iommu_ops) {
		.map_gpa = queue_map_gpa,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 0x108), DOC_OK);
	return (state);
}

ATF_TC_WITHOUT_HEAD(fragmented_request_and_response);
ATF_TC_BODY(fragmented_request_and_response, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	struct iovec iov[4];
	uint8_t input[20], output[4];
	size_t used;

	state = queue_state();
	options = (struct virtio_iommu_request_options) { 0 };
	memset(input, 0, sizeof(input));
	input[0] = DOC_ATTACH;
	le32enc(input + 4, 7);
	le32enc(input + 8, 0x108);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec) { .iov_base = input, .iov_len = 3 };
	iov[1] = (struct iovec) { .iov_base = input + 3, .iov_len = 17 };
	iov[2] = (struct iovec) { .iov_base = output, .iov_len = 1 };
	iov[3] = (struct iovec) { .iov_base = output + 1, .iov_len = 3 };
	ATF_REQUIRE_EQ(virtio_iommu_queue_process(state, &options, iov, 4, 2,
	    2, true, &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_OK);
	ATF_CHECK_EQ(output[1], 0);
	ATF_CHECK_EQ(output[2], 0);
	ATF_CHECK_EQ(output[3], 0);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(chain_validation_and_bounded_unknown);
ATF_TC_BODY(chain_validation_and_bounded_unknown, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	struct iovec iov[2];
	uint8_t *input;
	uint8_t output[4];
	size_t used;

	state = queue_state();
	options = (struct virtio_iommu_request_options) { 0 };
	input = malloc(1024 * 1024);
	ATF_REQUIRE(input != NULL);
	memset(input, 0xa5, 1024 * 1024);
	input[0] = 0xff;
	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = 1024 * 1024,
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), 0);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, false, &used), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 2,
	    0, true, &used), EINVAL);
	free(input);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(probe_capacity_and_short_tail);
ATF_TC_BODY(probe_capacity_and_short_tail, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	struct iovec iov[2];
	uint8_t input[72], output[20];
	size_t used;

	state = queue_state();
	memset(input, 0, sizeof(input));
	input[0] = DOC_PROBE;
	le32enc(input + 4, 0x108);
	memset(output, 0xa5, sizeof(output));
	options = (struct virtio_iommu_request_options) {
		.probe = true,
		.probe_size = 16,
	};
	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = sizeof(input),
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = sizeof(output),
	};
	ATF_REQUIRE_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[16], DOC_OK);

	iov[1].iov_len = 3;
	ATF_REQUIRE_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), 0);
	ATF_CHECK_EQ(used, 0);
	options.probe_size = BHYVE_VIOMMU_MAX_PROBE_SIZE + 1;
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), EINVAL);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	struct iovec iov[3];
	uint8_t input[20], output[8];
	size_t original_length, used;

	state = queue_state();
	options = (struct virtio_iommu_request_options) { 0 };
	memset(input, 0, sizeof(input));
	input[0] = DOC_ATTACH;
	le32enc(input + 4, 7);
	le32enc(input + 8, 0x108);
	memset(output, 0xa5, sizeof(output));
	iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = sizeof(input),
	};
	iov[1] = (struct iovec) {
		.iov_base = output,
		.iov_len = 4,
	};
	original_length = iov[0].iov_len;
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &iov[0].iov_len), EINVAL);
	ATF_CHECK_EQ(iov[0].iov_len, original_length);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	used = 99;
	iov[1].iov_base = iov;
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	iov[1].iov_base = &options;
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	iov[1].iov_base = state;
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	iov[1].iov_base = output;
	iov[2] = (struct iovec) {
		.iov_base = output + 2,
		.iov_len = 4,
	};
	ATF_CHECK_EQ(virtio_iommu_queue_process(state, &options, iov, 3, 1,
	    2, true, &used), EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	ATF_REQUIRE_EQ(virtio_iommu_queue_process(state, &options, iov, 2, 1,
	    1, true, &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	virtio_iommu_state_destroy(state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fragmented_request_and_response);
	ATF_TP_ADD_TC(tp, chain_validation_and_bounded_unknown);
	ATF_TP_ADD_TC(tp, probe_capacity_and_short_tail);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}

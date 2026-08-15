/*
 * Independent VirtIO 1.4 section 5.13 request execution tests.
 */
#include <sys/endian.h>
#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_protocol.c"
#include "virtio_iommu_state.c"
#include "virtio_iommu_request.c"

#define	DOC_ATTACH	1
#define	DOC_MAP		3
#define	DOC_UNMAP	4
#define	DOC_PROBE	5
#define	DOC_OK		0
#define	DOC_UNSUPP	2
#define	DOC_INVAL	4
#define	DOC_NOENT	6
#define	TEST_PROBE_LIMIT	4096U
#define	ALIAS_STORAGE_SIZE	128U

static uint8_t guest_memory[0x10000];

static void *
request_map_gpa(void *arg __unused, uint64_t address, size_t length,
    enum virtio_dma_direction direction __unused)
{

	if (address > sizeof(guest_memory) ||
	    length > sizeof(guest_memory) - address)
		return (NULL);
	return (guest_memory + address);
}

static struct virtio_iommu_state *
request_state(void)
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
		.map_gpa = request_map_gpa,
	};
	ATF_REQUIRE_EQ(virtio_iommu_state_create(&limits, &ops, &state), 0);
	ATF_REQUIRE_EQ(virtio_iommu_endpoint_register(state, 0x108), DOC_OK);
	return (state);
}

ATF_TC_WITHOUT_HEAD(executes_state_requests);
ATF_TC_BODY(executes_state_requests, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[36], output[4];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) {
		.map_unmap = true,
	};
	memset(input, 0, sizeof(input));
	input[0] = DOC_ATTACH;
	le32enc(input + 4, 7);
	le32enc(input + 8, 0x108);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input, 20,
	    output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_OK);

	memset(input, 0, sizeof(input));
	input[0] = DOC_MAP;
	le32enc(input + 4, 7);
	le64enc(input + 8, 0x1000);
	le64enc(input + 16, 0x1fff);
	le64enc(input + 24, 0x4000);
	le32enc(input + 32, 3);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input, 36,
	    output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_translate(state, 0x108, 0x1200, 16,
	    VIRTIO_DMA_DEVICE_WRITE), guest_memory + 0x4200);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(malformed_and_unknown_requests);
ATF_TC_BODY(malformed_and_unknown_requests, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[20], output[8];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) { 0 };
	memset(input, 0, sizeof(input));
	memset(output, 0xa5, sizeof(output));
	input[0] = DOC_ATTACH;
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input, 19,
	    output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_INVAL);
	ATF_CHECK_EQ(output[4], 0xa5);

	input[0] = 0xff;
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	input[0] = DOC_ATTACH;
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, 3, &used), 0);
	ATF_CHECK_EQ(used, 0);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(probe_feature_and_output_size);
ATF_TC_BODY(probe_feature_and_output_size, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[72], output[20];
	size_t used;

	state = request_state();
	memset(input, 0, sizeof(input));
	input[0] = DOC_PROBE;
	le32enc(input + 4, 0x108);
	memset(output, 0xa5, sizeof(output));
	options = (struct virtio_iommu_request_options) {
		.probe = false,
		.probe_size = 16,
	};
	memset(output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	options.probe = true;
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0);

	le32enc(input + 4, 0x109);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[16], DOC_NOENT);

	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, 19, &used), 0);
	ATF_CHECK_EQ(used, 4);
	ATF_CHECK_EQ(output[0], DOC_INVAL);

	/* Direct users of the shared executor retain the queue's response bound. */
	options.probe_size = TEST_PROBE_LIMIT + 1;
	used = SIZE_MAX;
	memset(output, 0xa5, sizeof(output));
	ATF_CHECK_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), EINVAL);
	ATF_CHECK_EQ(used, SIZE_MAX);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(map_unmap_requires_negotiated_feature);
ATF_TC_BODY(map_unmap_requires_negotiated_feature, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[36], output[4];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) { 0 };
	memset(input, 0, sizeof(input));
	input[0] = DOC_MAP;
	le32enc(input + 4, 7);
	le64enc(input + 8, 0x1000);
	le64enc(input + 16, 0x1fff);
	le64enc(input + 24, 0x4000);
	le32enc(input + 32, 3);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_UNSUPP);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(unnegotiated_bypass_attach_is_fail_closed);
ATF_TC_BODY(unnegotiated_bypass_attach_is_fail_closed, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[BHYVE_VIOMMU_ATTACH_INPUT_SIZE];
	uint8_t output[BHYVE_VIOMMU_REQUEST_TAIL_SIZE];
	size_t used;

	state = request_state();
	memset(input, 0, sizeof(input));
	input[0] = DOC_ATTACH;
	le32enc(input + 4, 7);
	le32enc(input + 8, 0x108);
	le32enc(input + 12, BHYVE_VIOMMU_ATTACH_F_BYPASS);
	options = (struct virtio_iommu_request_options) { 0 };
	memset(output, 0xff, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_INVAL);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 0);

	options.bypass_config = true;
	memset(output, 0xff, sizeof(output));
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_OK);
	ATF_CHECK_EQ(virtio_iommu_domain_count(state), 1);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(revocation_retries_after_active_dma);
ATF_TC_BODY(revocation_retries_after_active_dma, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[36], output[4];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) {
		.map_unmap = true,
	};
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 7, 0x108, 0), DOC_OK);
	ATF_REQUIRE_EQ(virtio_iommu_map(state, 7, 0x1000, 0x1fff, 0x4000,
	    3), DOC_OK);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 0x108));

	memset(input, 0, sizeof(input));
	input[0] = DOC_UNMAP;
	le32enc(input + 4, 7);
	le64enc(input + 8, 0x1000);
	le64enc(input + 16, 0x1fff);
	memset(output, 0xa5, sizeof(output));
	used = SIZE_MAX;
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input, 28,
	    output, sizeof(output), &used), EAGAIN);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	virtio_iommu_dma_release(state, 0x108);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input, 28,
	    output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_OK);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(reset_pending_request_is_retried);
ATF_TC_BODY(reset_pending_request_is_retried, tc)
{
	struct virtio_iommu_request_options options;
	struct virtio_iommu_state *state;
	uint8_t input[20], output[4];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) { 0 };
	ATF_REQUIRE_EQ(virtio_iommu_attach(state, 7, 0x108, 0), DOC_OK);
	ATF_REQUIRE(virtio_iommu_dma_acquire(state, 0x108));
	virtio_iommu_state_reset(state);

	memset(input, 0, sizeof(input));
	input[0] = DOC_ATTACH;
	le32enc(input + 4, 9);
	le32enc(input + 8, 0x108);
	memset(output, 0xa5, sizeof(output));
	used = SIZE_MAX;
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), EAGAIN);
	ATF_CHECK_EQ(used, 0);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	/*
	 * The release edge completes reset and is the event which makes the
	 * returned descriptor runnable.  Retrying the unchanged request then
	 * observes the clean endpoint topology and succeeds.
	 */
	virtio_iommu_dma_release(state, 0x108);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options, input,
	    sizeof(input), output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_OK);
	virtio_iommu_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(execution_outputs_are_transactional);
ATF_TC_BODY(execution_outputs_are_transactional, tc)
{
	union {
		max_align_t alignment;
		uint8_t bytes[ALIAS_STORAGE_SIZE];
	} input;
	struct virtio_iommu_request_options options, saved_options;
	struct virtio_iommu_state *state;
	uint8_t before[ALIAS_STORAGE_SIZE], output[4];
	size_t used;

	state = request_state();
	options = (struct virtio_iommu_request_options) { 0 };
	memset(input.bytes, 0, sizeof(input.bytes));
	input.bytes[0] = DOC_ATTACH;
	le32enc(input.bytes + 4, 7);
	le32enc(input.bytes + 8, 0x108);
	memcpy(before, input.bytes, sizeof(before));
	ATF_CHECK_EQ(virtio_iommu_request_execute(state, &options,
	    input.bytes, 20, output, sizeof(output),
	    (size_t *)(void *)input.bytes), EINVAL);
	ATF_CHECK(memcmp(input.bytes, before, sizeof(before)) == 0);

	saved_options = options;
	used = SIZE_MAX;
	ATF_CHECK_EQ(virtio_iommu_request_execute(state, &options,
	    input.bytes, 20, &options, sizeof(output), &used), EINVAL);
	ATF_CHECK(memcmp(&options, &saved_options, sizeof(options)) == 0);
	ATF_CHECK_EQ(used, SIZE_MAX);

	ATF_CHECK_EQ(virtio_iommu_request_execute(state, &options,
	    input.bytes, 20, state, sizeof(output), &used), EINVAL);
	ATF_CHECK_EQ(used, SIZE_MAX);
	ATF_REQUIRE_EQ(virtio_iommu_request_execute(state, &options,
	    input.bytes, 20, output, sizeof(output), &used), 0);
	ATF_CHECK_EQ(used, sizeof(output));
	ATF_CHECK_EQ(output[0], DOC_OK);
	virtio_iommu_state_destroy(state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, execution_outputs_are_transactional);
	ATF_TP_ADD_TC(tp, executes_state_requests);
	ATF_TP_ADD_TC(tp, malformed_and_unknown_requests);
	ATF_TP_ADD_TC(tp, probe_feature_and_output_size);
	ATF_TP_ADD_TC(tp, map_unmap_requires_negotiated_feature);
	ATF_TP_ADD_TC(tp, unnegotiated_bypass_attach_is_fail_closed);
	ATF_TP_ADD_TC(tp, revocation_retries_after_active_dma);
	ATF_TP_ADD_TC(tp, reset_pending_request_is_retried);
	return (atf_no_error());
}

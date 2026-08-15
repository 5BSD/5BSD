/*
 * Independent VirtIO 1.4 section 5.7 descriptor-boundary tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_gpu_2d_protocol.c"
#include "virtio_gpu_2d_state.c"
#include "virtio_gpu_2d_queue.c"

#define	DOC_GET_DISPLAY_INFO	0x0100U
#define	DOC_GET_EDID		0x010aU
#define	DOC_RESOURCE_CREATE_2D	0x0101U
#define	DOC_RESOURCE_CREATE_BLOB 0x010cU
#define	DOC_RESOURCE_MAP_BLOB	0x0208U
#define	DOC_UPDATE_CURSOR	0x0300U
#define	DOC_RESP_OK_NODATA	0x1100U
#define	DOC_RESP_OK_DISPLAY_INFO 0x1101U
#define	DOC_RESP_OK_EDID	0x1104U
#define	DOC_RESP_ERR_UNSPEC	0x1200U
#define	DOC_RESP_ERR_RESOURCE	0x1203U
#define	DOC_RESP_ERR_PARAMETER	0x1205U
#define	DOC_FLAG_FENCE		0x00000001U
#define	DOC_F_EDID		(UINT64_C(1) << 1)
#define	DOC_F_RESOURCE_BLOB	(UINT64_C(1) << 3)

static uint8_t guest_memory[8192];

static int
dma_validate(void *arg __unused, uint64_t address, size_t length,
    enum virtio_gpu_2d_dma_access access __unused)
{

	if (address > sizeof(guest_memory) ||
	    length > sizeof(guest_memory) - address)
		return (EFAULT);
	return (0);
}

static int
dma_read(void *arg __unused, uint64_t address, void *output, size_t length)
{
	int error;

	error = dma_validate(NULL, address, length,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ);
	if (error != 0)
		return (error);
	memcpy(output, guest_memory + address, length);
	return (0);
}

static const struct virtio_gpu_2d_ops test_ops = {
	.dma_validate = dma_validate,
	.dma_read = dma_read,
};

static struct virtio_gpu_2d_state *
new_state(void)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_state *state;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 4,
		.max_host_bytes = 1024 * 1024,
		.scanout_width = 1024,
		.scanout_height = 768,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &test_ops, &state),
	    0);
	return (state);
}

ATF_TC_WITHOUT_HEAD(guest_blob_map_is_rejected);
ATF_TC_BODY(guest_blob_map_is_rejected, tc)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_segment segments[2];
	struct virtio_gpu_2d_state *state;
	uint8_t create[72], map[40], response[32];
	size_t used;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 1,
		.max_blob_bytes = 4096,
		.blob_alignment = 4096,
		.scanout_width = 1,
		.scanout_height = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &test_ops, &state),
	    0);
	memset(create, 0, sizeof(create));
	le32enc(create, DOC_RESOURCE_CREATE_BLOB);
	le32enc(create + 24, 1);
	le32enc(create + 28, 1);
	le32enc(create + 32, 2);
	le32enc(create + 36, 1);
	le64enc(create + 48, 4096);
	le64enc(create + 56, 0x1000);
	le32enc(create + 64, 4096);
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = create,
		.length = sizeof(create),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = 24,
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1, 1, &used), 0);
	ATF_REQUIRE_EQ(le32dec(response), DOC_RESP_OK_NODATA);

	memset(map, 0, sizeof(map));
	le32enc(map, DOC_RESOURCE_MAP_BLOB);
	le32enc(map + 24, 1);
	segments[0].base = map;
	segments[0].length = sizeof(map);
	segments[1].length = sizeof(response);
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1, 1, &used), 0);
	ATF_CHECK_EQ(used, 24);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_PARAMETER);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(unnegotiated_optional_commands_are_fail_closed);
ATF_TC_BODY(unnegotiated_optional_commands_are_fail_closed, tc)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_segment segments[2];
	struct virtio_gpu_2d_state *state;
	uint8_t blob[72], edid[32], response[1056];
	size_t used;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 1,
		.max_host_bytes = 4096,
		.max_blob_bytes = 4096,
		.blob_alignment = 4096,
		.scanout_width = 1024,
		.scanout_height = 768,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &test_ops, &state),
	    0);

	memset(edid, 0, sizeof(edid));
	le32enc(edid, DOC_GET_EDID);
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = edid,
		.length = sizeof(edid),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = sizeof(response),
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process_features(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1024, 768, 0, &used), 0);
	ATF_CHECK_EQ(used, 24);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_UNSPEC);
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process_features(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1024, 768, DOC_F_EDID,
	    &used), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_EDID);

	memset(blob, 0, sizeof(blob));
	le32enc(blob, DOC_RESOURCE_CREATE_BLOB);
	le32enc(blob + 24, 1);
	le32enc(blob + 28, 1);
	le32enc(blob + 32, 2);
	le32enc(blob + 36, 1);
	le64enc(blob + 48, 4096);
	le64enc(blob + 56, 0);
	le32enc(blob + 64, 4096);
	segments[0].base = blob;
	segments[0].length = sizeof(blob);
	segments[1].length = 24;
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process_features(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1024, 768, 0, &used), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_UNSPEC);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process_features(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 1024, 768,
	    DOC_F_RESOURCE_BLOB, &used), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	virtio_gpu_2d_state_destroy(state);
}

static void
create_request(uint8_t request[40], uint32_t resource_id)
{

	memset(request, 0, 40);
	le32enc(request, DOC_RESOURCE_CREATE_2D);
	le32enc(request + 24, resource_id);
	le32enc(request + 28, 1);
	le32enc(request + 32, 4);
	le32enc(request + 36, 2);
}

ATF_TC_WITHOUT_HEAD(fragmented_command_and_response);
ATF_TC_BODY(fragmented_command_and_response, tc)
{
	struct virtio_gpu_2d_segment segments[5];
	struct virtio_gpu_2d_state *state;
	uint8_t request[40], response[24];
	size_t used;

	state = new_state();
	create_request(request, 1);
	memset(response, 0xa5, sizeof(response));
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = 7,
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = request + 7,
		.length = 13,
	};
	segments[2] = (struct virtio_gpu_2d_segment) {
		.base = request + 20,
		.length = 20,
	};
	segments[3] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = 5,
		.writable = true,
	};
	segments[4] = (struct virtio_gpu_2d_segment) {
		.base = response + 5,
		.length = 19,
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 5, 1024, 768, &used), 0);
	ATF_CHECK_EQ(used, 24);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 5, 1024, 768, &used), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_RESOURCE);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(display_info_scatter);
ATF_TC_BODY(display_info_scatter, tc)
{
	struct virtio_gpu_2d_segment segments[3];
	struct virtio_gpu_2d_state *state;
	uint8_t request[24], response[408];
	size_t used;

	state = new_state();
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_GET_DISPLAY_INFO);
	memset(response, 0xa5, sizeof(response));
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = 203,
		.writable = true,
	};
	segments[2] = (struct virtio_gpu_2d_segment) {
		.base = response + 203,
		.length = sizeof(response) - 203,
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 3, 800, 600, &used), 0);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_DISPLAY_INFO);
	ATF_CHECK_EQ(le32dec(response + 32), 800);
	ATF_CHECK_EQ(le32dec(response + 36), 600);
	for (size_t i = 48; i < sizeof(response); i++)
		ATF_CHECK_EQ(response[i], 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(edid_scatter_and_short_response);
ATF_TC_BODY(edid_scatter_and_short_response, tc)
{
	struct virtio_gpu_2d_segment segments[4];
	struct virtio_gpu_2d_state *state;
	uint8_t request[32], response[1056];
	size_t used;

	state = new_state();
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_GET_EDID);
	memset(response, 0xa5, sizeof(response));
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = 31,
		.writable = true,
	};
	segments[2] = (struct virtio_gpu_2d_segment) {
		.base = response + 31,
		.length = 513,
		.writable = true,
	};
	segments[3] = (struct virtio_gpu_2d_segment) {
		.base = response + 544,
		.length = sizeof(response) - 544,
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 4, 1024, 768, &used), 0);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_EDID);
	ATF_CHECK_EQ(le32dec(response + 24), 128);
	segments[3].length--;
	memset(response, 0xa5, sizeof(response));
	used = 99;
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 4, 1024, 768, &used), 0);
	ATF_CHECK_EQ(used, 24);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_PARAMETER);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(chain_validation_is_atomic);
ATF_TC_BODY(chain_validation_is_atomic, tc)
{
	struct virtio_gpu_2d_segment segments[3];
	struct virtio_gpu_2d_state *state;
	uint8_t request[40], response[24];
	size_t used;

	state = new_state();
	create_request(request, 1);
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = 20,
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = sizeof(response),
		.writable = true,
	};
	segments[2] = (struct virtio_gpu_2d_segment) {
		.base = request + 20,
		.length = 20,
	};
	used = 99;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 3, 800, 600, &used),
	    EPROTO);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	segments[0].length = 0;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 3, 800, 600, &used),
	    EINVAL);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(short_response_does_not_execute);
ATF_TC_BODY(short_response_does_not_execute, tc)
{
	struct virtio_gpu_2d_segment segments[2];
	struct virtio_gpu_2d_state *state;
	uint8_t request[40], response[23];
	size_t used;

	state = new_state();
	create_request(request, 1);
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = sizeof(response),
		.writable = true,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used),
	    EMSGSIZE);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(malformed_command_gets_error_response);
ATF_TC_BODY(malformed_command_gets_error_response, tc)
{
	struct virtio_gpu_2d_segment segments[2];
	struct virtio_gpu_2d_state *state;
	uint8_t request[40], response[24];
	size_t used;

	state = new_state();
	create_request(request, 1);
	/* A zero width makes the complete RESOURCE_CREATE_2D malformed. */
	le32enc(request + 32, 0);
	le32enc(request + 4, DOC_FLAG_FENCE);
	le64enc(request + 8, UINT64_C(0x1122334455667788));
	memset(response, 0xa5, sizeof(response));
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = sizeof(response),
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used), 0);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_PARAMETER);
	ATF_CHECK_EQ(le32dec(response + 4), DOC_FLAG_FENCE);
	ATF_CHECK_EQ(le64dec(response + 8),
	    UINT64_C(0x1122334455667788));
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(linux_cursor_has_no_response_descriptor);
ATF_TC_BODY(linux_cursor_has_no_response_descriptor, tc)
{
	struct virtio_gpu_2d_segment segment;
	struct virtio_gpu_2d_state *state;
	uint8_t request[56];
	size_t used;

	state = new_state();
	memset(request, 0, sizeof(request));
	le32enc(request, DOC_UPDATE_CURSOR);
	segment = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	used = 99;
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CURSOR_QUEUE, &segment, 1, 800, 600, &used), 0);
	ATF_CHECK_EQ(used, 0);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(unknown_control_command_returns_fenced_error);
ATF_TC_BODY(unknown_control_command_returns_fenced_error, tc)
{
	struct virtio_gpu_2d_segment segments[2];
	struct virtio_gpu_2d_state *state;
	const uint64_t fence_id = UINT64_C(0x0123456789abcdef);
	uint8_t request[24], response[24];
	size_t used;

	state = new_state();
	memset(request, 0, sizeof(request));
	memset(response, 0xa5, sizeof(response));
	le32enc(request, 0xdeadU);
	le32enc(request + 4, DOC_FLAG_FENCE);
	le64enc(request + 8, fence_id);
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = sizeof(response),
		.writable = true,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used), 0);
	ATF_CHECK_EQ(used, sizeof(response));
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_ERR_UNSPEC);
	ATF_CHECK_EQ(le32dec(response + 4), DOC_FLAG_FENCE);
	ATF_CHECK_EQ(le64dec(response + 8), fence_id);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_gpu_2d_segment segments[3];
	struct virtio_gpu_2d_state *state;
	uint8_t request[40], response[48];
	size_t original_length, used;

	state = new_state();
	create_request(request, 1);
	memset(response, 0xa5, sizeof(response));
	segments[0] = (struct virtio_gpu_2d_segment) {
		.base = request,
		.length = sizeof(request),
	};
	segments[1] = (struct virtio_gpu_2d_segment) {
		.base = response,
		.length = 24,
		.writable = true,
	};
	original_length = segments[0].length;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600,
	    &segments[0].length), EINVAL);
	ATF_CHECK_EQ(segments[0].length, original_length);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);

	used = 99;
	segments[1].base = segments;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used),
	    EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);

	segments[1].base = &used;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used),
	    EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);

	segments[1].base = state;
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used),
	    EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);

	segments[1].base = response;
	segments[2] = (struct virtio_gpu_2d_segment) {
		.base = response + 8,
		.length = 24,
		.writable = true,
	};
	ATF_CHECK_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 3, 800, 600, &used),
	    EINVAL);
	ATF_CHECK_EQ(used, 99);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 0);

	ATF_REQUIRE_EQ(virtio_gpu_2d_queue_process(state,
	    VIRTIO_GPU_2D_CONTROL_QUEUE, segments, 2, 800, 600, &used), 0);
	ATF_CHECK_EQ(used, 24);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_NODATA);
	ATF_CHECK_EQ(virtio_gpu_2d_state_resource_count(state), 1);
	virtio_gpu_2d_state_destroy(state);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fragmented_command_and_response);
	ATF_TP_ADD_TC(tp, guest_blob_map_is_rejected);
	ATF_TP_ADD_TC(tp, unnegotiated_optional_commands_are_fail_closed);
	ATF_TP_ADD_TC(tp, display_info_scatter);
	ATF_TP_ADD_TC(tp, edid_scatter_and_short_response);
	ATF_TP_ADD_TC(tp, chain_validation_is_atomic);
	ATF_TP_ADD_TC(tp, short_response_does_not_execute);
	ATF_TP_ADD_TC(tp, malformed_command_gets_error_response);
	ATF_TP_ADD_TC(tp, linux_cursor_has_no_response_descriptor);
	ATF_TP_ADD_TC(tp, unknown_control_command_returns_fenced_error);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}

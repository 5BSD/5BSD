/*
 * Independent VirtIO 1.4 section 5.7 2D command framing tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_gpu_2d_protocol.c"

#define	DOC_HEADER_SIZE			24U
#define	DOC_MEM_ENTRY_SIZE		16U
#define	DOC_FLAG_FENCE			1U
#define	DOC_FLAG_INFO_RING_IDX		2U
#define	DOC_GET_DISPLAY_INFO		0x0100U
#define	DOC_GET_EDID			0x010aU
#define	DOC_RESOURCE_CREATE_2D		0x0101U
#define	DOC_RESOURCE_ATTACH_BACKING	0x0106U
#define	DOC_RESOURCE_CREATE_BLOB	0x010cU
#define	DOC_SET_SCANOUT_BLOB		0x010dU
#define	DOC_RESOURCE_MAP_BLOB		0x0208U
#define	DOC_RESOURCE_UNMAP_BLOB		0x0209U
#define	DOC_BLOB_MEM_GUEST		0x0001U
#define	DOC_BLOB_MEM_HOST3D		0x0002U
#define	DOC_BLOB_FLAG_MAPPABLE		0x0001U
#define	DOC_BLOB_FLAG_SHAREABLE		0x0002U
#define	DOC_UPDATE_CURSOR		0x0300U
#define	DOC_MOVE_CURSOR			0x0301U
#define	DOC_RESP_OK_NODATA		0x1100U
#define	DOC_RESP_OK_DISPLAY_INFO	0x1101U
#define	DOC_RESP_OK_EDID		0x1104U
#define	DOC_EDID_RESPONSE_SIZE		1056U

static void
command(uint8_t *bytes, size_t length, uint32_t type)
{

	memset(bytes, 0, length);
	le32enc(bytes, type);
}

ATF_TC_WITHOUT_HEAD(fixed_command_layouts);
ATF_TC_BODY(fixed_command_layouts, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t bytes[56];

	command(bytes, sizeof(bytes), DOC_GET_DISPLAY_INFO);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, DOC_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.type, DOC_GET_DISPLAY_INFO);
	command(bytes, sizeof(bytes), DOC_RESOURCE_CREATE_2D);
	le32enc(bytes + 24, 7);
	le32enc(bytes + 28, 1);
	le32enc(bytes + 32, 640);
	le32enc(bytes + 36, 480);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 40, DOC_HEADER_SIZE,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.resource_id, 7);
	command(bytes, sizeof(bytes), DOC_UPDATE_CURSOR);
	le32enc(bytes + 24, 0);
	le32enc(bytes + 40, 8);
	le32enc(bytes + 44, 3);
	le32enc(bytes + 48, 4);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CURSOR_QUEUE, bytes, 56, DOC_HEADER_SIZE,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.hot_x, 3);
	ATF_CHECK_EQ(decoded.hot_y, 4);
	le32enc(bytes + 40, 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CURSOR_QUEUE, bytes, 56, 0, &decoded), 0);
	command(bytes, sizeof(bytes), DOC_MOVE_CURSOR);
	le32enc(bytes + 36, 0x0badf00d);
	le32enc(bytes + 40, 0xdeadbeef);
	le32enc(bytes + 44, 0xcafebabe);
	le32enc(bytes + 48, 0x12345678);
	le32enc(bytes + 52, 0xfeedface);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CURSOR_QUEUE, bytes, 56, 0, &decoded), 0);
	ATF_CHECK_EQ(decoded.type, DOC_MOVE_CURSOR);
	ATF_CHECK_EQ(decoded.resource_id, 0);
	ATF_CHECK_EQ(decoded.hot_x, 0);
	ATF_CHECK_EQ(decoded.hot_y, 0);
}

ATF_TC_WITHOUT_HEAD(variable_backing_layout);
ATF_TC_BODY(variable_backing_layout, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t bytes[32 + 2 * DOC_MEM_ENTRY_SIZE];

	command(bytes, sizeof(bytes), DOC_RESOURCE_ATTACH_BACKING);
	le32enc(bytes + 24, 9);
	le32enc(bytes + 28, 2);
	le64enc(bytes + 32, 0x1000);
	le32enc(bytes + 40, 4096);
	le64enc(bytes + 48, 0x3000);
	le32enc(bytes + 56, 8192);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.resource_id, 9);
	ATF_CHECK_EQ(decoded.entry_count, 2);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes) - 1,
	    DOC_HEADER_SIZE, &decoded), EPROTO);
	le32enc(bytes + 28, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 32, DOC_HEADER_SIZE,
	    &decoded), EPROTO);
	le32enc(bytes + 28, 1);
	le64enc(bytes + 32, UINT64_MAX);
	le32enc(bytes + 40, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes,
	    32 + DOC_MEM_ENTRY_SIZE, DOC_HEADER_SIZE, &decoded), EPROTO);
}

ATF_TC_WITHOUT_HEAD(blob_wire_layout_and_bounds);
ATF_TC_BODY(blob_wire_layout_and_bounds, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t bytes[56 + 2 * DOC_MEM_ENTRY_SIZE];

	command(bytes, sizeof(bytes), DOC_RESOURCE_CREATE_BLOB);
	le32enc(bytes + 24, 17);
	le32enc(bytes + 28, DOC_BLOB_MEM_GUEST);
	le32enc(bytes + 32,
	    DOC_BLOB_FLAG_MAPPABLE | DOC_BLOB_FLAG_SHAREABLE);
	le32enc(bytes + 36, 2);
	le64enc(bytes + 40, UINT64_C(0x1122334455667788));
	le64enc(bytes + 48, 6144);
	le64enc(bytes + 56, 0x1000);
	le32enc(bytes + 64, 4096);
	le64enc(bytes + 72, 0x3000);
	le32enc(bytes + 80, 2048);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.resource_id, 17);
	ATF_CHECK_EQ(decoded.blob_memory, DOC_BLOB_MEM_GUEST);
	ATF_CHECK_EQ(decoded.blob_flags,
	    DOC_BLOB_FLAG_MAPPABLE | DOC_BLOB_FLAG_SHAREABLE);
	ATF_CHECK_EQ(decoded.entry_count, 2);
	ATF_CHECK_EQ(decoded.blob_id, UINT64_C(0x1122334455667788));
	ATF_CHECK_EQ(decoded.blob_size, 6144);

	le64enc(bytes + 48, 6145);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), EPROTO);
	le64enc(bytes + 48, 6144);
	le32enc(bytes + 28, DOC_BLOB_MEM_HOST3D);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), EPROTO);
	le32enc(bytes + 28, DOC_BLOB_MEM_GUEST);
	le32enc(bytes + 32, 8);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), EPROTO);
	le32enc(bytes + 32, 0);
	le32enc(bytes + 36, 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 56,
	    DOC_HEADER_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.entry_count, 0);
	ATF_CHECK_EQ(decoded.blob_size, 6144);

	command(bytes, sizeof(bytes), DOC_RESOURCE_MAP_BLOB);
	le32enc(bytes + 24, 17);
	le64enc(bytes + 32, UINT64_C(0x200000));
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 40,
	    DOC_HEADER_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.resource_id, 17);
	ATF_CHECK_EQ(decoded.offset, UINT64_C(0x200000));
	le32enc(bytes + 28, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 40,
	    DOC_HEADER_SIZE, &decoded), EPROTO);

	command(bytes, sizeof(bytes), DOC_RESOURCE_UNMAP_BLOB);
	le32enc(bytes + 24, 17);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 32,
	    DOC_HEADER_SIZE, &decoded), 0);
	le32enc(bytes + 28, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 32,
	    DOC_HEADER_SIZE, &decoded), EPROTO);
}

ATF_TC_WITHOUT_HEAD(blob_scanout_wire_layout);
ATF_TC_BODY(blob_scanout_wire_layout, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t bytes[96];

	command(bytes, sizeof(bytes), DOC_SET_SCANOUT_BLOB);
	le32enc(bytes + 24, 10);
	le32enc(bytes + 28, 20);
	le32enc(bytes + 32, 640);
	le32enc(bytes + 36, 480);
	le32enc(bytes + 40, 0);
	le32enc(bytes + 44, 17);
	le32enc(bytes + 48, 1024);
	le32enc(bytes + 52, 768);
	le32enc(bytes + 56, VIRTIO_GPU_2D_FORMAT_B8G8R8X8_UNORM);
	le32enc(bytes + 64, 4096);
	le32enc(bytes + 80, 8192);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.type, DOC_SET_SCANOUT_BLOB);
	ATF_CHECK_EQ(decoded.resource_id, 17);
	ATF_CHECK_EQ(decoded.x, 10);
	ATF_CHECK_EQ(decoded.y, 20);
	ATF_CHECK_EQ(decoded.width, 640);
	ATF_CHECK_EQ(decoded.height, 480);
	ATF_CHECK_EQ(decoded.resource_width, 1024);
	ATF_CHECK_EQ(decoded.resource_height, 768);
	ATF_CHECK_EQ(decoded.strides[0], 4096);
	ATF_CHECK_EQ(decoded.plane_offsets[0], 8192);
	ATF_CHECK_EQ(decoded.strides[1], 0);

	le32enc(bytes + 60, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), EPROTO);
	le32enc(bytes + 60, 0);
	le32enc(bytes + 44, 0);
	memset(bytes + 24, 0, sizeof(bytes) - 24);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), 0);
	le32enc(bytes + 68, 4);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, sizeof(bytes),
	    DOC_HEADER_SIZE, &decoded), EPROTO);
}

ATF_TC_WITHOUT_HEAD(header_and_queue_rejection);
ATF_TC_BODY(header_and_queue_rejection, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t bytes[56];

	command(bytes, sizeof(bytes), DOC_GET_DISPLAY_INFO);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 23, DOC_HEADER_SIZE,
	    &decoded), EMSGSIZE);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, DOC_HEADER_SIZE, 23,
	    &decoded), EMSGSIZE);
	le32enc(bytes + 4, DOC_FLAG_INFO_RING_IDX);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, DOC_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), EPROTO);
	le32enc(bytes + 4, 0);
	le64enc(bytes + 8, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, DOC_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), EPROTO);
	le64enc(bytes + 8, 0);
	le32enc(bytes + 16, 0x12345678);
	bytes[20] = 0x3f;
	bytes[21] = 0xa5;
	bytes[22] = 0x5a;
	bytes[23] = 0xff;
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, DOC_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), 0);
	ATF_CHECK_EQ(decoded.context_id, 0x12345678);
	memset(bytes + 16, 0, 8);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CURSOR_QUEUE, bytes, DOC_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), EPROTO);
	command(bytes, sizeof(bytes), DOC_UPDATE_CURSOR);
	le32enc(bytes + 40, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 56, DOC_HEADER_SIZE,
	    &decoded), EPROTO);
	le32enc(bytes, 0xdead);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 56, DOC_HEADER_SIZE,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.type, 0xdead);
	command(bytes, sizeof(bytes), DOC_RESOURCE_CREATE_2D);
	le32enc(bytes + 24, 1);
	le32enc(bytes + 28, 0xffffffff);
	le32enc(bytes + 32, 1);
	le32enc(bytes + 36, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 40, DOC_HEADER_SIZE,
	    &decoded), EPROTO);
	le32enc(bytes + 28, 1);
	le32enc(bytes + 32, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, bytes, 40, DOC_HEADER_SIZE,
	    &decoded), EPROTO);
}

ATF_TC_WITHOUT_HEAD(fence_response_correlation);
ATF_TC_BODY(fence_response_correlation, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t request[DOC_HEADER_SIZE], response[DOC_HEADER_SIZE];

	command(request, sizeof(request), DOC_GET_DISPLAY_INFO);
	le32enc(request + 4, DOC_FLAG_FENCE);
	le64enc(request + 8, UINT64_C(0x1122334455667788));
	le32enc(request + 16, 0x12345678);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE, &decoded), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_response_encode(&decoded,
	    DOC_RESP_OK_DISPLAY_INFO, response), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_DISPLAY_INFO);
	ATF_CHECK_EQ(le32dec(response + 4), DOC_FLAG_FENCE);
	ATF_CHECK_EQ(le64dec(response + 8), decoded.fence_id);
	ATF_CHECK_EQ(le32dec(response + 16), decoded.context_id);
	ATF_CHECK_EQ(virtio_gpu_2d_response_encode(&decoded, 0xdead,
	    response), EINVAL);
	decoded.fenced = false;
	ATF_REQUIRE_EQ(virtio_gpu_2d_response_encode(&decoded,
	    DOC_RESP_OK_NODATA, response), 0);
	ATF_CHECK_EQ(le32dec(response + 4), 0);
	ATF_CHECK_EQ(le64dec(response + 8), 0);
}

ATF_TC_WITHOUT_HEAD(configuration_and_display_info);
ATF_TC_BODY(configuration_and_display_info, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t request[DOC_HEADER_SIZE];
	uint8_t config[BHYVE_VIRTIO_GPU_CONFIG_SIZE];
	uint8_t response[BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE];

	ATF_REQUIRE_EQ(virtio_gpu_2d_config_encode(0, 0, 0, config), 0);
	ATF_CHECK_EQ(le32dec(config), 0);
	ATF_CHECK_EQ(le32dec(config + 4), 0);
	ATF_CHECK_EQ(le32dec(config + 8), 1);
	ATF_CHECK_EQ(le32dec(config + 12), 0);
	ATF_CHECK_EQ(le32dec(config + 16), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_config_encode(1, 1, 4096, config), 0);
	ATF_CHECK_EQ(le32dec(config + 16), 4096);
	ATF_CHECK_EQ(virtio_gpu_2d_config_encode(2, 0, 0, config), EINVAL);

	command(request, sizeof(request), DOC_GET_DISPLAY_INFO);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    sizeof(response), &decoded), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_display_info_encode(&decoded, 1024, 768,
	    response), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_DISPLAY_INFO);
	ATF_CHECK_EQ(le32dec(response + 24), 0);
	ATF_CHECK_EQ(le32dec(response + 28), 0);
	ATF_CHECK_EQ(le32dec(response + 32), 1024);
	ATF_CHECK_EQ(le32dec(response + 36), 768);
	ATF_CHECK_EQ(le32dec(response + 40), 1);
	ATF_CHECK_EQ(le32dec(response + 44), 0);
	for (size_t i = 48; i < sizeof(response); i++)
		ATF_CHECK_EQ(response[i], 0);
	ATF_CHECK_EQ(virtio_gpu_2d_display_info_encode(&decoded, 0, 768,
	    response), EINVAL);
}

ATF_TC_WITHOUT_HEAD(edid_layout_timing_and_checksum);
ATF_TC_BODY(edid_layout_timing_and_checksum, tc)
{
	struct virtio_gpu_2d_command decoded;
	uint8_t request[32], response[DOC_EDID_RESPONSE_SIZE];
	const uint8_t *edid;
	uint32_t hactive, vactive;
	unsigned int sum;

	command(request, sizeof(request), DOC_GET_EDID);
	ATF_REQUIRE_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    sizeof(response), &decoded), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_edid_encode(&decoded, 1024, 768,
	    response), 0);
	ATF_CHECK_EQ(le32dec(response), DOC_RESP_OK_EDID);
	ATF_CHECK_EQ(le32dec(response + 24), 128);
	ATF_CHECK_EQ(le32dec(response + 28), 0);
	edid = response + 32;
	ATF_CHECK_EQ(edid[0], 0);
	for (size_t i = 1; i < 7; i++)
		ATF_CHECK_EQ(edid[i], 0xff);
	ATF_CHECK_EQ(edid[7], 0);
	ATF_CHECK_EQ(edid[18], 1);
	ATF_CHECK_EQ(edid[19], 4);
	hactive = edid[56] | (uint32_t)(edid[58] & 0xf0) << 4;
	vactive = edid[59] | (uint32_t)(edid[61] & 0xf0) << 4;
	ATF_CHECK_EQ(hactive, 1024);
	ATF_CHECK_EQ(vactive, 768);
	sum = 0;
	for (size_t i = 0; i < 128; i++)
		sum += edid[i];
	ATF_CHECK_EQ(sum & 0xff, 0);
	for (size_t i = 160; i < sizeof(response); i++)
		ATF_CHECK_EQ(response[i], 0);

	le32enc(request + 24, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    sizeof(response), &decoded), EPROTO);
	le32enc(request + 24, 0);
	le32enc(request + 28, 1);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    sizeof(response), &decoded), EPROTO);
	le32enc(request + 28, 0);
	ATF_CHECK_EQ(virtio_gpu_2d_command_decode(
	    VIRTIO_GPU_2D_CONTROL_QUEUE, request, sizeof(request),
	    sizeof(response) - 1, &decoded), EMSGSIZE);

	ATF_CHECK(virtio_gpu_2d_dimensions_valid(1, 1));
	ATF_CHECK(virtio_gpu_2d_dimensions_valid(1920, 1080));
	ATF_CHECK(!virtio_gpu_2d_dimensions_valid(0, 768));
	ATF_CHECK(!virtio_gpu_2d_dimensions_valid(1024, 0));
	ATF_CHECK(!virtio_gpu_2d_dimensions_valid(4096, 768));
	ATF_CHECK(!virtio_gpu_2d_dimensions_valid(4095, 4095));
	ATF_CHECK_EQ(virtio_gpu_2d_edid_encode(&decoded, 4095, 4095,
	    response), ERANGE);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fixed_command_layouts);
	ATF_TP_ADD_TC(tp, variable_backing_layout);
	ATF_TP_ADD_TC(tp, blob_wire_layout_and_bounds);
	ATF_TP_ADD_TC(tp, blob_scanout_wire_layout);
	ATF_TP_ADD_TC(tp, header_and_queue_rejection);
	ATF_TP_ADD_TC(tp, fence_response_correlation);
	ATF_TP_ADD_TC(tp, configuration_and_display_info);
	ATF_TP_ADD_TC(tp, edid_layout_timing_and_checksum);
	return (atf_no_error());
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_gpu_2d_protocol.h"

#define	GPU_FLAG_FENCE			(UINT32_C(1) << 0)
#define	GPU_EVENT_DISPLAY		(UINT32_C(1) << 0)

#define	GPU_OFF_TYPE			0U
#define	GPU_OFF_FLAGS			4U
#define	GPU_OFF_FENCE_ID		8U
#define	GPU_OFF_CONTEXT_ID		16U
#define	GPU_OFF_RING_INDEX		20U
#define	GPU_OFF_RESOURCE_ID		24U
#define	GPU_OFF_ENTRY_COUNT		28U
#define	GPU_MAX_SCANOUTS		16U
#define	GPU_EDID_VBLANK			45U

bool
virtio_gpu_2d_format_valid(uint32_t format)
{

	return (format == VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_B8G8R8X8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_A8R8G8B8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_X8R8G8B8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_R8G8B8A8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_X8B8G8R8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_A8B8G8R8_UNORM ||
	    format == VIRTIO_GPU_2D_FORMAT_R8G8B8X8_UNORM);
}

static bool
virtio_gpu_2d_rect_valid(const struct virtio_gpu_2d_command *command)
{

	return (command->width != 0 && command->height != 0 &&
	    command->x <= UINT32_MAX - command->width &&
	    command->y <= UINT32_MAX - command->height);
}

static bool
virtio_gpu_2d_zero32(const uint8_t *bytes, size_t offset)
{

	return (le32dec(bytes + offset) == 0);
}

static int
virtio_gpu_2d_fixed_length(uint32_t type, size_t *length)
{

	switch (type) {
	case VIRTIO_GPU_2D_GET_DISPLAY_INFO:
		*length = 24;
		break;
	case VIRTIO_GPU_2D_GET_EDID:
		*length = 32;
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNREF:
	case VIRTIO_GPU_2D_RESOURCE_DETACH_BACKING:
		*length = 32;
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE:
		*length = 40;
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT:
	case VIRTIO_GPU_2D_RESOURCE_FLUSH:
		*length = 48;
		break;
	case VIRTIO_GPU_2D_TRANSFER_TO_HOST:
	case VIRTIO_GPU_2D_UPDATE_CURSOR:
	case VIRTIO_GPU_2D_MOVE_CURSOR:
		*length = 56;
		break;
	case VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING:
		*length = 32;
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB:
		*length = 56;
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT_BLOB:
		*length = 96;
		break;
	case VIRTIO_GPU_2D_RESOURCE_MAP_BLOB:
		*length = 40;
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNMAP_BLOB:
		*length = 32;
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

int
virtio_gpu_2d_command_decode(enum virtio_gpu_2d_queue queue,
    const void *request, size_t request_len, size_t response_capacity,
    struct virtio_gpu_2d_command *command)
{
	const uint8_t *bytes;
	struct virtio_gpu_2d_command decoded;
	size_t expected;
	int error;

	if (request == NULL || command == NULL ||
	    (queue != VIRTIO_GPU_2D_CONTROL_QUEUE &&
	    queue != VIRTIO_GPU_2D_CURSOR_QUEUE))
		return (EINVAL);
	if (request_len < BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE ||
	    (queue == VIRTIO_GPU_2D_CONTROL_QUEUE &&
	    response_capacity < BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE))
		return (EMSGSIZE);
	bytes = request;
	decoded = (struct virtio_gpu_2d_command) {
		.type = le32dec(bytes + GPU_OFF_TYPE),
		.flags = le32dec(bytes + GPU_OFF_FLAGS),
		.fence_id = le64dec(bytes + GPU_OFF_FENCE_ID),
		.context_id = le32dec(bytes + GPU_OFF_CONTEXT_ID),
	};
	decoded.fenced = (decoded.flags & GPU_FLAG_FENCE) != 0;
	/*
	 * Publish the parsed common header before validating command-specific
	 * fields.  The queue layer can then return the mandatory GPU error
	 * response, including fence correlation, without executing malformed
	 * input.
	 */
	*command = decoded;
	/*
	 * ctx_id is used only by 3D commands, so it has no semantics for this
	 * 2D-only device.  Likewise, ring_idx is meaningful only when the
	 * unadvertised CONTEXT_INIT feature and INFO_RING_IDX flag are in use.
	 * Do not turn either field (or its padding) into an extra wire rule.
	 */
	if ((decoded.flags & ~GPU_FLAG_FENCE) != 0 ||
	    ((decoded.flags & GPU_FLAG_FENCE) == 0 &&
	    decoded.fence_id != 0))
		return (EPROTO);
	error = virtio_gpu_2d_fixed_length(decoded.type, &expected);
	if (error == ENOTSUP) {
		/*
		 * The control header is common to optional commands not
		 * advertised by this device.  Preserve it so the queue returns
		 * RESP_ERR_UNSPEC and echoes any fence instead of silently
		 * consuming an otherwise well-formed command.
		 */
		*command = decoded;
		return (0);
	}
	if (error != 0)
		return (error);
	if (decoded.type == VIRTIO_GPU_2D_GET_DISPLAY_INFO &&
	    response_capacity < BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE)
		return (EMSGSIZE);
	if (decoded.type == VIRTIO_GPU_2D_GET_EDID &&
	    response_capacity < BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE)
		return (EMSGSIZE);
	if ((queue == VIRTIO_GPU_2D_CURSOR_QUEUE) !=
	    (decoded.type == VIRTIO_GPU_2D_UPDATE_CURSOR ||
	    decoded.type == VIRTIO_GPU_2D_MOVE_CURSOR))
		return (EPROTO);
	decoded.entry_count = 0;
	if (decoded.type == VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING ||
	    decoded.type == VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB) {
		if (request_len < expected)
			return (EPROTO);
		decoded.entry_count = le32dec(bytes +
		    (decoded.type == VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB ?
		    36 : GPU_OFF_ENTRY_COUNT));
		if ((decoded.type ==
		    VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING &&
		    decoded.entry_count == 0) ||
		    decoded.entry_count > BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES)
			return (EPROTO);
		if (decoded.entry_count >
		    (SIZE_MAX - expected) / BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE)
			return (EOVERFLOW);
		expected += (size_t)decoded.entry_count *
		    BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
	}
	if (request_len != expected)
		return (EPROTO);
	decoded.resource_id = 0;
	decoded.scanout_id = 0;
	decoded.format = 0;
	decoded.x = 0;
	decoded.y = 0;
	decoded.width = 0;
	decoded.height = 0;
	decoded.hot_x = 0;
	decoded.hot_y = 0;
	memset(decoded.strides, 0, sizeof(decoded.strides));
	memset(decoded.plane_offsets, 0, sizeof(decoded.plane_offsets));
	decoded.offset = 0;
	decoded.blob_memory = 0;
	decoded.blob_flags = 0;
	decoded.blob_id = 0;
	decoded.blob_size = 0;
	switch (decoded.type) {
	case VIRTIO_GPU_2D_GET_EDID:
		decoded.scanout_id = le32dec(bytes + 24);
		if (decoded.scanout_id >= 1 ||
		    !virtio_gpu_2d_zero32(bytes, 28))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE:
		decoded.resource_id = le32dec(bytes + 24);
		decoded.format = le32dec(bytes + 28);
		decoded.width = le32dec(bytes + 32);
		decoded.height = le32dec(bytes + 36);
		if (decoded.resource_id == 0 ||
		    !virtio_gpu_2d_format_valid(decoded.format) ||
		    !virtio_gpu_2d_rect_valid(&decoded))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNREF:
	case VIRTIO_GPU_2D_RESOURCE_DETACH_BACKING:
		decoded.resource_id = le32dec(bytes + 24);
		if (decoded.resource_id == 0 || !virtio_gpu_2d_zero32(bytes, 28))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT:
		decoded.x = le32dec(bytes + 24);
		decoded.y = le32dec(bytes + 28);
		decoded.width = le32dec(bytes + 32);
		decoded.height = le32dec(bytes + 36);
		decoded.scanout_id = le32dec(bytes + 40);
		decoded.resource_id = le32dec(bytes + 44);
		if (decoded.scanout_id >= GPU_MAX_SCANOUTS ||
		    (decoded.resource_id == 0 ?
		    (decoded.x != 0 || decoded.y != 0 ||
		    decoded.width != 0 || decoded.height != 0) :
		    !virtio_gpu_2d_rect_valid(&decoded)))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_FLUSH:
		decoded.x = le32dec(bytes + 24);
		decoded.y = le32dec(bytes + 28);
		decoded.width = le32dec(bytes + 32);
		decoded.height = le32dec(bytes + 36);
		decoded.resource_id = le32dec(bytes + 40);
		if (decoded.resource_id == 0 ||
		    !virtio_gpu_2d_zero32(bytes, 44) ||
		    !virtio_gpu_2d_rect_valid(&decoded))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_TRANSFER_TO_HOST:
		decoded.x = le32dec(bytes + 24);
		decoded.y = le32dec(bytes + 28);
		decoded.width = le32dec(bytes + 32);
		decoded.height = le32dec(bytes + 36);
		decoded.offset = le64dec(bytes + 40);
		decoded.resource_id = le32dec(bytes + 48);
		if (decoded.resource_id == 0 ||
		    !virtio_gpu_2d_zero32(bytes, 52) ||
		    !virtio_gpu_2d_rect_valid(&decoded))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING:
		decoded.resource_id = le32dec(bytes + GPU_OFF_RESOURCE_ID);
		if (decoded.resource_id == 0)
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB:
		decoded.resource_id = le32dec(bytes + 24);
		decoded.blob_memory = le32dec(bytes + 28);
		decoded.blob_flags = le32dec(bytes + 32);
		decoded.entry_count = le32dec(bytes + 36);
		decoded.blob_id = le64dec(bytes + 40);
		decoded.blob_size = le64dec(bytes + 48);
		/*
		 * This 2D-only model has no VIRGL renderer.  Section 5.7.6.8
		 * permits GUEST blobs without VIRGL, while HOST3D and
		 * HOST3D_GUEST require it.  Keep those memory types rejected
		 * until a renderer with an explicit ownership contract exists.
		 */
		if (decoded.resource_id == 0 ||
		    decoded.blob_memory != VIRTIO_GPU_2D_BLOB_MEM_GUEST ||
		    (decoded.blob_flags & ~VIRTIO_GPU_2D_BLOB_FLAGS_MASK) != 0 ||
		    decoded.blob_size == 0)
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT_BLOB:
		decoded.x = le32dec(bytes + 24);
		decoded.y = le32dec(bytes + 28);
		decoded.width = le32dec(bytes + 32);
		decoded.height = le32dec(bytes + 36);
		decoded.scanout_id = le32dec(bytes + 40);
		decoded.resource_id = le32dec(bytes + 44);
		decoded.resource_width = le32dec(bytes + 48);
		decoded.resource_height = le32dec(bytes + 52);
		decoded.format = le32dec(bytes + 56);
		for (uint32_t i = 0; i < 4; i++) {
			decoded.strides[i] = le32dec(bytes + 64 + i * 4);
			decoded.plane_offsets[i] =
			    le32dec(bytes + 80 + i * 4);
		}
		if (decoded.resource_id == 0) {
			for (uint32_t i = 0; i < 4; i++) {
				if (decoded.strides[i] != 0 ||
				    decoded.plane_offsets[i] != 0)
					return (EPROTO);
			}
		}
		if (decoded.scanout_id >= GPU_MAX_SCANOUTS ||
		    !virtio_gpu_2d_zero32(bytes, 60) ||
		    (decoded.resource_id == 0 ?
		    (decoded.x != 0 || decoded.y != 0 ||
		    decoded.width != 0 || decoded.height != 0 ||
		    decoded.resource_width != 0 ||
		    decoded.resource_height != 0 || decoded.format != 0) :
		    (!virtio_gpu_2d_rect_valid(&decoded) ||
		    decoded.resource_width == 0 ||
		    decoded.resource_height == 0 ||
		    !virtio_gpu_2d_format_valid(decoded.format))))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_MAP_BLOB:
		decoded.resource_id = le32dec(bytes + 24);
		decoded.offset = le64dec(bytes + 32);
		if (decoded.resource_id == 0 || !virtio_gpu_2d_zero32(bytes, 28))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNMAP_BLOB:
		decoded.resource_id = le32dec(bytes + 24);
		if (decoded.resource_id == 0 || !virtio_gpu_2d_zero32(bytes, 28))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_UPDATE_CURSOR:
		decoded.scanout_id = le32dec(bytes + 24);
		decoded.x = le32dec(bytes + 28);
		decoded.y = le32dec(bytes + 32);
		decoded.resource_id = le32dec(bytes + 40);
		decoded.hot_x = le32dec(bytes + 44);
		decoded.hot_y = le32dec(bytes + 48);
		if (decoded.scanout_id >= GPU_MAX_SCANOUTS ||
		    !virtio_gpu_2d_zero32(bytes, 36) ||
		    !virtio_gpu_2d_zero32(bytes, 52))
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_MOVE_CURSOR:
		/*
		 * Section 5.7.6.10 defines only pos for MOVE_CURSOR and says
		 * every other field in virtio_gpu_update_cursor is ignored.
		 * Decode only that position.  In particular, do not turn the
		 * two padding words or stale UPDATE_CURSOR fields into an
		 * undocumented wire requirement.
		 */
		decoded.scanout_id = le32dec(bytes + 24);
		decoded.x = le32dec(bytes + 28);
		decoded.y = le32dec(bytes + 32);
		if (decoded.scanout_id >= GPU_MAX_SCANOUTS)
			return (EPROTO);
		break;
	case VIRTIO_GPU_2D_GET_DISPLAY_INFO:
		break;
	default:
		return (ENOTSUP);
	}
	if (decoded.type == VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING ||
	    decoded.type == VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB) {
		uint64_t address;
		uint64_t backing_size;
		uint32_t length;
		size_t offset;

		backing_size = 0;
		for (uint32_t i = 0; i < decoded.entry_count; i++) {
			offset = (decoded.type ==
			    VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB ? 56 : 32) +
			    (size_t)i *
			    BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
			address = le64dec(bytes + offset);
			length = le32dec(bytes + offset + 8);
			if (length == 0 ||
			    !virtio_gpu_2d_zero32(bytes, offset + 12) ||
			    address > UINT64_MAX - length ||
			    backing_size > UINT64_MAX - length)
				return (EPROTO);
			backing_size += length;
		}
		if (decoded.type == VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB &&
		    decoded.entry_count != 0 &&
		    backing_size < decoded.blob_size)
			return (EPROTO);
	}
	*command = decoded;
	return (0);
}

int
virtio_gpu_2d_response_encode(const struct virtio_gpu_2d_command *command,
    uint32_t response_type,
    uint8_t output[BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE])
{

	if (command == NULL || output == NULL ||
	    (response_type != VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    response_type != VIRTIO_GPU_2D_RESP_OK_DISPLAY_INFO &&
	    response_type != VIRTIO_GPU_2D_RESP_OK_EDID &&
	    (response_type < VIRTIO_GPU_2D_RESP_ERR_UNSPEC ||
	    response_type > VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER)))
		return (EINVAL);
	memset(output, 0, BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE);
	le32enc(output + GPU_OFF_TYPE, response_type);
	if (command->fenced) {
		le32enc(output + GPU_OFF_FLAGS, GPU_FLAG_FENCE);
		le64enc(output + GPU_OFF_FENCE_ID, command->fence_id);
		le32enc(output + GPU_OFF_CONTEXT_ID, command->context_id);
	}
	return (0);
}

static bool
virtio_gpu_2d_timing(uint32_t width, uint32_t height, uint32_t *hblankp,
    uint32_t *hfrontp, uint32_t *hsyncp, uint32_t *pixel_clockp)
{
	uint32_t hblank, hfront, hsync, pixel_clock;
	uint64_t total;

	if (width == 0 || height == 0 || width > 4095 || height > 4095)
		return (false);
	/*
	 * A bounded virtual-monitor timing: 20% horizontal blanking rounded to
	 * eight pixels, at least 160 pixels; 45 vertical lines; 60 Hz.  All
	 * fields fit the EDID detailed-timing representation by construction.
	 */
	hblank = (width + 4) / 5;
	hblank = (hblank + 7) & ~UINT32_C(7);
	if (hblank < 160)
		hblank = 160;
	if (hblank > 4095)
		return (false);
	hfront = (hblank / 4 + 7) & ~UINT32_C(7);
	hsync = (hblank / 2 + 7) & ~UINT32_C(7);
	if (hfront > 1023 || hsync > 1023)
		return (false);
	total = (uint64_t)(width + hblank) *
	    (height + GPU_EDID_VBLANK) * 60;
	pixel_clock = (uint32_t)((total + 5000) / 10000);
	if (pixel_clock == 0 || pixel_clock > UINT16_MAX)
		return (false);
	if (hblankp != NULL)
		*hblankp = hblank;
	if (hfrontp != NULL)
		*hfrontp = hfront;
	if (hsyncp != NULL)
		*hsyncp = hsync;
	if (pixel_clockp != NULL)
		*pixel_clockp = pixel_clock;
	return (true);
}

bool
virtio_gpu_2d_dimensions_valid(uint32_t width, uint32_t height)
{

	return (virtio_gpu_2d_timing(width, height, NULL, NULL, NULL, NULL));
}

/*
 * Encode a single-block EDID 1.4 image with one preferred detailed timing.
 * The display has no physical-size claim, extension block, audio capability,
 * or host-endian field.  Timing values are deliberately derived from the
 * configured scanout instead of being copied from a fixed host monitor.
 */
int
virtio_gpu_2d_edid_encode(const struct virtio_gpu_2d_command *command,
    uint32_t width, uint32_t height,
    uint8_t output[BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE])
{
	uint8_t *edid;
	uint32_t hblank, hfront, hsync, pixel_clock, sum;
	int error;

	if (command == NULL || output == NULL ||
	    command->type != VIRTIO_GPU_2D_GET_EDID ||
	    command->scanout_id != 0)
		return (EINVAL);
	if (!virtio_gpu_2d_timing(width, height, &hblank, &hfront, &hsync,
	    &pixel_clock))
		return (ERANGE);

	memset(output, 0, BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE);
	error = virtio_gpu_2d_response_encode(command,
	    VIRTIO_GPU_2D_RESP_OK_EDID, output);
	if (error != 0)
		return (error);
	le32enc(output + BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE,
	    BHYVE_VIRTIO_GPU_EDID_DATA_SIZE);
	edid = output + BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE + 8;
	edid[0] = 0x00;
	memset(edid + 1, 0xff, 6);
	edid[7] = 0x00;
	/* EISA manufacturer "WSP", product 1, deterministic serial 1. */
	edid[8] = 0x5e;
	edid[9] = 0x70;
	edid[10] = 0x01;
	edid[12] = 0x01;
	edid[16] = 1;
	edid[17] = 36;		/* 1990 + 36 = 2026. */
	edid[18] = 1;
	edid[19] = 4;
	edid[20] = 0x80;	/* Digital input, parameters unspecified. */
	edid[23] = 120;		/* Display gamma 2.2. */
	edid[24] = 0x02;	/* Preferred timing is the first DTD. */
	for (size_t i = 38; i < 54; i += 2) {
		edid[i] = 0x01;
		edid[i + 1] = 0x01;
	}
	edid[54] = (uint8_t)pixel_clock;
	edid[55] = (uint8_t)(pixel_clock >> 8);
	edid[56] = (uint8_t)width;
	edid[57] = (uint8_t)hblank;
	edid[58] = (uint8_t)(((width >> 8) << 4) | (hblank >> 8));
	edid[59] = (uint8_t)height;
	edid[60] = GPU_EDID_VBLANK;
	edid[61] = (uint8_t)((height >> 8) << 4);
	edid[62] = (uint8_t)hfront;
	edid[63] = (uint8_t)hsync;
	edid[64] = 0x36;	/* Vertical front porch 3, sync width 6. */
	edid[65] = (uint8_t)(((hfront >> 8) << 6) |
	    ((hsync >> 8) << 4));
	edid[71] = 0x1a;	/* Digital separate sync, positive polarities. */
	/* Monitor-name descriptor, padded with spaces and newline terminated. */
	edid[72 + 3] = 0xfc;
	memset(edid + 72 + 5, ' ', 13);
	memcpy(edid + 72 + 5, "WASPNest", 8);
	edid[72 + 17] = '\n';
	/* Two explicit dummy descriptors complete the base block. */
	edid[90 + 3] = 0x10;
	edid[108 + 3] = 0x10;
	edid[126] = 0;
	sum = 0;
	for (size_t i = 0; i < 127; i++)
		sum += edid[i];
	edid[127] = (uint8_t)(0U - sum);
	return (0);
}

int
virtio_gpu_2d_config_encode(uint32_t events_read, uint32_t events_clear,
    uint32_t blob_alignment,
    uint8_t output[BHYVE_VIRTIO_GPU_CONFIG_SIZE])
{

	if (output == NULL ||
	    ((events_read | events_clear) & ~GPU_EVENT_DISPLAY) != 0)
		return (EINVAL);
	memset(output, 0, BHYVE_VIRTIO_GPU_CONFIG_SIZE);
	le32enc(output, events_read);
	le32enc(output + 4, events_clear);
	le32enc(output + 8, 1);	/* one baseline scanout */
	/* num_capsets stays zero: no rendering context is advertised. */
	le32enc(output + 16, blob_alignment);
	return (0);
}

int
virtio_gpu_2d_display_info_encode(
    const struct virtio_gpu_2d_command *command, uint32_t width,
    uint32_t height, uint8_t output[BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE])
{
	int error;

	if (command == NULL || output == NULL ||
	    command->type != VIRTIO_GPU_2D_GET_DISPLAY_INFO ||
	    width == 0 || height == 0)
		return (EINVAL);
	memset(output, 0, BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE);
	error = virtio_gpu_2d_response_encode(command,
	    VIRTIO_GPU_2D_RESP_OK_DISPLAY_INFO, output);
	if (error != 0)
		return (error);
	/* pmodes[0]: x=0, y=0, width, height, enabled=1, flags=0. */
	le32enc(output + BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE + 8, width);
	le32enc(output + BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE + 12, height);
	le32enc(output + BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE + 16, 1);
	return (0);
}

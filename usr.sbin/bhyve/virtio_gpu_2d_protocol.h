/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_GPU_2D_PROTOCOL_H_
#define	_BHYVE_VIRTIO_GPU_2D_PROTOCOL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE	24U
#define	BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE		16U
#define	BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES	4096U
#define	BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE	408U
#define	BHYVE_VIRTIO_GPU_EDID_DATA_SIZE		128U
#define	BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE	1056U
#define	BHYVE_VIRTIO_GPU_CONFIG_SIZE		20U

enum virtio_gpu_2d_command_type {
	VIRTIO_GPU_2D_GET_DISPLAY_INFO = 0x0100U,
	VIRTIO_GPU_2D_RESOURCE_CREATE = 0x0101U,
	VIRTIO_GPU_2D_RESOURCE_UNREF = 0x0102U,
	VIRTIO_GPU_2D_SET_SCANOUT = 0x0103U,
	VIRTIO_GPU_2D_RESOURCE_FLUSH = 0x0104U,
	VIRTIO_GPU_2D_TRANSFER_TO_HOST = 0x0105U,
	VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING = 0x0106U,
	VIRTIO_GPU_2D_RESOURCE_DETACH_BACKING = 0x0107U,
	VIRTIO_GPU_2D_GET_EDID = 0x010aU,
	VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB = 0x010cU,
	VIRTIO_GPU_2D_SET_SCANOUT_BLOB = 0x010dU,
	VIRTIO_GPU_2D_RESOURCE_MAP_BLOB = 0x0208U,
	VIRTIO_GPU_2D_RESOURCE_UNMAP_BLOB = 0x0209U,
	VIRTIO_GPU_2D_UPDATE_CURSOR = 0x0300U,
	VIRTIO_GPU_2D_MOVE_CURSOR = 0x0301U,
};

enum virtio_gpu_2d_response_type {
	VIRTIO_GPU_2D_RESP_OK_NODATA = 0x1100U,
	VIRTIO_GPU_2D_RESP_OK_DISPLAY_INFO = 0x1101U,
	VIRTIO_GPU_2D_RESP_OK_EDID = 0x1104U,
	VIRTIO_GPU_2D_RESP_ERR_UNSPEC = 0x1200U,
	VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY = 0x1201U,
	VIRTIO_GPU_2D_RESP_ERR_INVALID_SCANOUT = 0x1202U,
	VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE = 0x1203U,
	VIRTIO_GPU_2D_RESP_ERR_INVALID_CONTEXT = 0x1204U,
	VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER = 0x1205U,
};

enum virtio_gpu_2d_queue {
	VIRTIO_GPU_2D_CONTROL_QUEUE = 0,
	VIRTIO_GPU_2D_CURSOR_QUEUE,
};

enum virtio_gpu_2d_format {
	VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM = 1,
	VIRTIO_GPU_2D_FORMAT_B8G8R8X8_UNORM = 2,
	VIRTIO_GPU_2D_FORMAT_A8R8G8B8_UNORM = 3,
	VIRTIO_GPU_2D_FORMAT_X8R8G8B8_UNORM = 4,
	VIRTIO_GPU_2D_FORMAT_R8G8B8A8_UNORM = 67,
	VIRTIO_GPU_2D_FORMAT_X8B8G8R8_UNORM = 68,
	VIRTIO_GPU_2D_FORMAT_A8B8G8R8_UNORM = 121,
	VIRTIO_GPU_2D_FORMAT_R8G8B8X8_UNORM = 134,
};

enum virtio_gpu_2d_blob_memory {
	VIRTIO_GPU_2D_BLOB_MEM_GUEST = 0x0001U,
	VIRTIO_GPU_2D_BLOB_MEM_HOST3D = 0x0002U,
	VIRTIO_GPU_2D_BLOB_MEM_HOST3D_GUEST = 0x0003U,
};

#define	VIRTIO_GPU_2D_BLOB_FLAG_USE_MAPPABLE	0x0001U
#define	VIRTIO_GPU_2D_BLOB_FLAG_USE_SHAREABLE	0x0002U
#define	VIRTIO_GPU_2D_BLOB_FLAG_USE_CROSS_DEVICE	0x0004U
#define	VIRTIO_GPU_2D_BLOB_FLAGS_MASK		0x0007U
#define	BHYVE_VIRTIO_GPU_F_EDID			1U
#define	BHYVE_VIRTIO_GPU_F_RESOURCE_BLOB	3U
#define	BHYVE_VIRTIO_GPU_F_BLOB_ALIGNMENT	5U

struct virtio_gpu_2d_command {
	uint32_t type;
	uint32_t flags;
	uint64_t fence_id;
	uint32_t context_id;
	uint32_t resource_id;
	uint32_t entry_count;
	uint32_t scanout_id;
	uint32_t format;
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
	uint32_t resource_width;
	uint32_t resource_height;
	uint32_t hot_x;
	uint32_t hot_y;
	uint32_t strides[4];
	uint32_t plane_offsets[4];
	uint64_t offset;
	uint32_t blob_memory;
	uint32_t blob_flags;
	uint64_t blob_id;
	uint64_t blob_size;
	bool fenced;
};

bool	virtio_gpu_2d_format_valid(uint32_t);
int	virtio_gpu_2d_command_decode(enum virtio_gpu_2d_queue,
	    const void *, size_t, size_t, struct virtio_gpu_2d_command *);
int	virtio_gpu_2d_response_encode(
	    const struct virtio_gpu_2d_command *, uint32_t,
	    uint8_t[BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE]);
int	virtio_gpu_2d_config_encode(uint32_t, uint32_t, uint32_t,
	    uint8_t[BHYVE_VIRTIO_GPU_CONFIG_SIZE]);
int	virtio_gpu_2d_display_info_encode(
	    const struct virtio_gpu_2d_command *, uint32_t, uint32_t,
	    uint8_t[BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE]);
int	virtio_gpu_2d_edid_encode(const struct virtio_gpu_2d_command *,
	    uint32_t, uint32_t,
	    uint8_t[BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE]);
bool	virtio_gpu_2d_dimensions_valid(uint32_t, uint32_t);

#endif

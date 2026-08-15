/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_MEM_HOST_H_
#define	_BHYVE_VIRTIO_MEM_HOST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VTMEM_REQUEST_SIZE	24U
#define	BHYVE_VTMEM_RESPONSE_SIZE	10U
#define	BHYVE_VTMEM_CONFIG_SIZE		56U

enum virtio_mem_response {
	BHYVE_VTMEM_RESP_ACK = 0,
	BHYVE_VTMEM_RESP_NACK = 1,
	BHYVE_VTMEM_RESP_BUSY = 2,
	BHYVE_VTMEM_RESP_ERROR = 3,
};

enum virtio_mem_block_state {
	BHYVE_VTMEM_STATE_PLUGGED = 0,
	BHYVE_VTMEM_STATE_UNPLUGGED = 1,
	BHYVE_VTMEM_STATE_MIXED = 2,
};

struct virtio_mem_host;

struct virtio_mem_host_config {
	uint64_t block_size;
	uint64_t address;
	uint64_t region_size;
	uint64_t usable_region_size;
	uint64_t plugged_size;
	uint64_t requested_size;
};

struct virtio_mem_host_limits {
	uint64_t block_size;
	uint64_t address;
	uint64_t region_size;
	uint64_t usable_region_size;
	uint64_t requested_size;
	uint32_t max_blocks;
};

struct virtio_mem_host_ops {
	/*
	 * A non-zero result must leave the complete requested range unchanged.
	 * Restore recovery relies on this per-call transactional contract.
	 */
	int (*set_range)(void *, uint64_t, uint64_t, bool);
	/*
	 * Publish a device-configuration change after requested_size or
	 * usable_region_size changes outside UNPLUG_ALL.  The callback runs
	 * without either host mutex held and receives the configuration which
	 * caused the notification.  Callbacks must not re-enter the host model.
	 */
	void (*config_changed)(void *, const struct virtio_mem_host_config *);
	void *arg;
};

/*
 * Every public operation retains the model through any external callback it
 * invokes.  destroy closes admission and waits for those operations to leave;
 * callers must not begin a new operation after they have handed ownership to
 * destroy.
 */

int	virtio_mem_host_create(const struct virtio_mem_host_limits *,
	    const struct virtio_mem_host_ops *, struct virtio_mem_host **);
void	virtio_mem_host_destroy(struct virtio_mem_host *);
int	virtio_mem_host_set_requested_size(struct virtio_mem_host *, uint64_t);
void	virtio_mem_host_get_config(struct virtio_mem_host *,
	    struct virtio_mem_host_config *);
int	virtio_mem_host_config_encode(struct virtio_mem_host *,
	    uint8_t[BHYVE_VTMEM_CONFIG_SIZE]);
int	virtio_mem_host_request(struct virtio_mem_host *, const void *, size_t,
	    void *, size_t, size_t *);
int	virtio_mem_host_reset(struct virtio_mem_host *);
int	virtio_mem_host_system_reset(struct virtio_mem_host *);
int	virtio_mem_host_snapshot_size(struct virtio_mem_host *, size_t *);
int	virtio_mem_host_snapshot(struct virtio_mem_host *, void *, size_t);
int	virtio_mem_host_restore_validate(struct virtio_mem_host *,
	    const void *, size_t);
int	virtio_mem_host_restore(struct virtio_mem_host *, const void *, size_t);
bool	virtio_mem_host_restore_incomplete(struct virtio_mem_host *);

#endif

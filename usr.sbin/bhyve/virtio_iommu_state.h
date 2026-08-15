/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_STATE_H_
#define	_BHYVE_VIRTIO_IOMMU_STATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_dma.h"

#define	BHYVE_VIOMMU_MAP_F_READ		(1U << 0)
#define	BHYVE_VIOMMU_MAP_F_WRITE		(1U << 1)
#define	BHYVE_VIOMMU_MAP_F_MMIO		(1U << 2)
#define	BHYVE_VIOMMU_MAP_F_MASK		(BHYVE_VIOMMU_MAP_F_READ | \
	BHYVE_VIOMMU_MAP_F_WRITE | BHYVE_VIOMMU_MAP_F_MMIO)

#define	BHYVE_VIOMMU_ATTACH_F_BYPASS	(1U << 0)

enum virtio_iommu_status {
	BHYVE_VIOMMU_S_OK = 0,
	BHYVE_VIOMMU_S_IOERR = 1,
	BHYVE_VIOMMU_S_UNSUPP = 2,
	BHYVE_VIOMMU_S_DEVERR = 3,
	BHYVE_VIOMMU_S_INVAL = 4,
	BHYVE_VIOMMU_S_RANGE = 5,
	BHYVE_VIOMMU_S_NOENT = 6,
	BHYVE_VIOMMU_S_FAULT = 7,
	BHYVE_VIOMMU_S_NOMEM = 8,
	/*
	 * Internal scheduling result.  It is never placed on the wire: the
	 * request remains device-owned until prior endpoint DMA drains.
	 */
	BHYVE_VIOMMU_S_BUSY = 0xff,
};

enum virtio_iommu_fault_reason {
	BHYVE_VIOMMU_FAULT_UNKNOWN = 0,
	BHYVE_VIOMMU_FAULT_DOMAIN = 1,
	BHYVE_VIOMMU_FAULT_MAPPING = 2,
};

#define	BHYVE_VIOMMU_FAULT_F_READ	(1U << 0)
#define	BHYVE_VIOMMU_FAULT_F_WRITE	(1U << 1)
#define	BHYVE_VIOMMU_FAULT_F_ADDRESS	(1U << 8)

struct virtio_iommu_fault {
	uint8_t reason;
	uint32_t flags;
	uint32_t endpoint;
	uint64_t address;
};

struct virtio_iommu_state;

/*
 * Object lifetime is owned by the device that publishes this raw state
 * pointer.  The state API deliberately does not retain callers: mapping and
 * fault callbacks execute outside the state mutex, and an internal reference
 * count could not protect a caller that begins with a stale raw pointer.
 *
 * Before virtio_iommu_state_destroy(), that owner must close admission to new
 * DMA-domain operations and drain every lease acquired through
 * virtio_iommu_dma_acquire().  The common virtio_dma request owner provides
 * that fence for production devices.  Snapshot-validation views are private
 * to their validation owner and likewise must be unpublished before destroy.
 * No state API may be called concurrently with destruction.
 */

struct virtio_iommu_limits {
	uint64_t page_size_mask;
	uint64_t input_start;
	uint64_t input_end;
	uint32_t domain_start;
	uint32_t domain_end;
	uint32_t max_domains;
	uint32_t max_endpoints;
	uint32_t max_mappings;
	uint32_t max_faults;
	bool default_bypass;
	bool bypass_domains;
	bool allow_mmio;
};

struct virtio_iommu_ops {
	bool (*validate_gpa)(void *, uint64_t, uint64_t, uint32_t);
	void *(*map_gpa)(void *, uint64_t, size_t,
	    enum virtio_dma_direction);
	void (*fault)(void *, uint32_t, enum virtio_iommu_fault_reason,
	    uint64_t, enum virtio_dma_direction);
	void (*dma_idle)(void *, uint32_t);
	void *arg;
};

int	virtio_iommu_state_create(const struct virtio_iommu_limits *,
	    const struct virtio_iommu_ops *, struct virtio_iommu_state **);
void	virtio_iommu_state_destroy(struct virtio_iommu_state *);
void	virtio_iommu_state_reset(struct virtio_iommu_state *);
bool	virtio_iommu_default_bypass(struct virtio_iommu_state *);
void	virtio_iommu_set_default_bypass(struct virtio_iommu_state *, bool);
int	virtio_iommu_state_snapshot_size(struct virtio_iommu_state *,
	    size_t *);
int	virtio_iommu_state_snapshot(struct virtio_iommu_state *, void *,
	    size_t);
int	virtio_iommu_state_restore_validate(struct virtio_iommu_state *,
	    const void *, size_t);
int	virtio_iommu_state_restore_prepare(struct virtio_iommu_state *,
	    const void *, size_t, struct virtio_iommu_state **);
int	virtio_iommu_state_restore(struct virtio_iommu_state *, const void *,
	    size_t);
bool	virtio_iommu_state_storage_overlaps(struct virtio_iommu_state *,
	    const void *, size_t);

enum virtio_iommu_status virtio_iommu_endpoint_register(
	    struct virtio_iommu_state *, uint32_t);
enum virtio_iommu_status virtio_iommu_endpoint_unregister(
	    struct virtio_iommu_state *, uint32_t);
bool	virtio_iommu_endpoint_registered(struct virtio_iommu_state *,
	    uint32_t);
enum virtio_iommu_status virtio_iommu_attach(
	    struct virtio_iommu_state *, uint32_t, uint32_t, uint32_t);
enum virtio_iommu_status virtio_iommu_detach(
	    struct virtio_iommu_state *, uint32_t, uint32_t);
enum virtio_iommu_status virtio_iommu_map(
	    struct virtio_iommu_state *, uint32_t, uint64_t, uint64_t,
	    uint64_t, uint32_t);
enum virtio_iommu_status virtio_iommu_unmap(
	    struct virtio_iommu_state *, uint32_t, uint64_t, uint64_t);

bool	virtio_iommu_dma_acquire(struct virtio_iommu_state *, uint32_t);
void	virtio_iommu_dma_release(struct virtio_iommu_state *, uint32_t);
void	*virtio_iommu_translate(struct virtio_iommu_state *, uint32_t,
	    uint64_t, size_t, enum virtio_dma_direction);
bool	virtio_iommu_fault_pop(struct virtio_iommu_state *,
	    struct virtio_iommu_fault *);
uint64_t virtio_iommu_fault_dropped(struct virtio_iommu_state *);
uint64_t virtio_iommu_generation(struct virtio_iommu_state *);
size_t	virtio_iommu_domain_count(struct virtio_iommu_state *);
size_t	virtio_iommu_mapping_count(struct virtio_iommu_state *);

#endif

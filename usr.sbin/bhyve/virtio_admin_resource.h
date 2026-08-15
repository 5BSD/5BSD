/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_RESOURCE_H_
#define	_BHYVE_VIRTIO_ADMIN_RESOURCE_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

struct virtio_admin_owner;
struct virtio_admin_resource_manager;
struct virtio_admin_resource_restore_stage;

typedef int (*virtio_admin_resource_validate_cb)(void *, uint64_t,
	    const void *, size_t, uint32_t *);
typedef bool (*virtio_admin_resource_match_cb)(void *, uint64_t,
	    const void *, size_t);

#define	BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE		8
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE	16
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_TYPES		32
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_DEPENDENCIES	8
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_OBJECT_SIZE	(1024 * 1024)
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE	32
#define	BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE	32

struct virtio_admin_resource_type {
	uint16_t type;
	uint32_t limit;
	size_t minimum_size;
	size_t maximum_size;
	uint64_t valid_flags;
	virtio_admin_resource_validate_cb validate;
	void *validate_argument;
};

int	virtio_admin_resource_manager_create(
	    struct virtio_admin_resource_manager **);
void	virtio_admin_resource_manager_destroy(
	    struct virtio_admin_resource_manager *);
void	virtio_admin_resource_manager_reset(
	    struct virtio_admin_resource_manager *);

/*
 * Resource types are registered before administration queues start and remain
 * immutable until the manager is destroyed.  The configured limit is both the
 * maximum object count and the exclusive upper bound for driver-assigned IDs.
 * The manager and registered command bindings remain alive until every
 * administration queue has stopped.  An optional validation callback may
 * further lower the exclusive ID limit based on object-specific data and
 * negotiated capabilities.  It runs under the resource-manager mutex and
 * must not reenter this manager.  Its nonzero errno is preserved by create
 * and modify so a policy callback can distinguish malformed input from a
 * temporary or permanent resource-policy refusal.
 */
int	virtio_admin_resource_register_type(
	    struct virtio_admin_resource_manager *,
	    const struct virtio_admin_resource_type *);

int	virtio_admin_resource_create(struct virtio_admin_resource_manager *,
	    uint16_t, uint32_t, uint64_t, const void *, size_t);
int	virtio_admin_resource_modify(struct virtio_admin_resource_manager *,
	    uint16_t, uint32_t, const void *, size_t);
int	virtio_admin_resource_query(struct virtio_admin_resource_manager *,
	    uint16_t, uint32_t, uint64_t *, void *, size_t, size_t *);
int	virtio_admin_resource_destroy_object(
	    struct virtio_admin_resource_manager *, uint16_t, uint32_t);
int	virtio_admin_resource_count(
	    struct virtio_admin_resource_manager *, uint16_t,
	    virtio_admin_resource_match_cb, void *, uint32_t *);
int	virtio_admin_resource_usage(
	    struct virtio_admin_resource_manager *, uint16_t,
	    virtio_admin_resource_match_cb, void *, uint32_t *, uint32_t *);

/*
 * Establish a dependency from a newer object to an already-existing object
 * of another type.  This creation-order rule makes dependency cycles
 * impossible and permits deterministic reverse-order teardown.
 */
int	virtio_admin_resource_add_dependency(
	    struct virtio_admin_resource_manager *, uint16_t, uint32_t,
	    uint16_t, uint32_t);

/*
 * Register the four generic resource-object commands on an administration
 * owner.  This self-group adapter validates the exact little-endian wire
 * headers and maps errno values to VirtIO administration status values.
 * The complete family is published atomically exactly once; later calls
 * return EALREADY, and type registration returns EBUSY after publication.
 */
int	virtio_admin_resource_register_commands(
	    struct virtio_admin_resource_manager *, struct virtio_admin_owner *);

int	virtio_admin_resource_snapshot_size(
	    struct virtio_admin_resource_manager *, size_t *);
int	virtio_admin_resource_snapshot(struct virtio_admin_resource_manager *,
	    void *, size_t);
bool	virtio_admin_resource_snapshot_overlaps(
	    struct virtio_admin_resource_manager *, const void *, size_t);
/*
 * Prepare parses, allocates, and validates an entire replacement without
 * changing live state.  Commit only swaps prevalidated storage and cannot
 * allocate.  Registrations remain immutable after queue startup.  A stage is
 * bound to the manager generation observed by prepare; commit returns EBUSY
 * if an intervening registration, reset, object mutation, or dependency
 * mutation made it stale.  External quiescence is still required when the
 * resource payload names state owned outside this manager.  Destroy releases
 * either the prepared replacement or, after commit, the replaced old state.
 */
int	virtio_admin_resource_restore_prepare(
	    struct virtio_admin_resource_manager *, const void *, size_t,
	    struct virtio_admin_resource_restore_stage **);
int	virtio_admin_resource_restore_commit(
	    struct virtio_admin_resource_manager *,
	    struct virtio_admin_resource_restore_stage *);
int	virtio_admin_resource_restore_stage_count(
	    struct virtio_admin_resource_restore_stage *, uint16_t,
	    virtio_admin_resource_match_cb, void *, uint32_t *);
int	virtio_admin_resource_restore_stage_query(
	    struct virtio_admin_resource_restore_stage *, uint16_t, uint32_t,
	    uint64_t *, void *, size_t, size_t *);
void	virtio_admin_resource_restore_stage_destroy(
	    struct virtio_admin_resource_restore_stage *);
int	virtio_admin_resource_restore(struct virtio_admin_resource_manager *,
	    const void *, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_RESOURCE_H_ */

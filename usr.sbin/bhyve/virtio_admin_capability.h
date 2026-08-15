/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_CAPABILITY_H_
#define	_BHYVE_VIRTIO_ADMIN_CAPABILITY_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_admin_capability_manager;
struct virtio_admin_owner;

#define	BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_ID	0x0fff
#define	BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT	32
#define	BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_SIZE	(1024 * 1024)
#define	BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE	32
#define	BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE	16

typedef int (*virtio_admin_capability_validate_cb)(void *, const void *,
	    size_t, const void *, size_t);
typedef void (*virtio_admin_capability_apply_cb)(void *, const void *,
	    size_t, bool);

struct virtio_admin_capability_config {
	uint16_t id;
	const void *device_data;
	size_t size;
	virtio_admin_capability_validate_cb validate;
	void *validate_argument;
	virtio_admin_capability_apply_cb apply;
	void *apply_argument;
};

int	virtio_admin_capability_manager_create(
	    struct virtio_admin_capability_manager **);
void	virtio_admin_capability_manager_destroy(
	    struct virtio_admin_capability_manager *);
void	virtio_admin_capability_manager_reset(
	    struct virtio_admin_capability_manager *);

/*
 * Registration is immutable and completes before administration queues start.
 * The manager and its registered command bindings remain alive until every
 * administration queue has stopped.  Validation and post-commit apply
 * callbacks execute under the manager mutex and must not reenter the manager.
 * Validation is side-effect-free and may return a policy errno, such as EBUSY
 * while related resource operations or objects remain active; the generic
 * DRIVER_CAP_SET command preserves that errno at its wire boundary.  Apply
 * publishes an already-committed driver value (or an unset zero value during
 * reset) to dependent code.
 *
 * Portable state records capability identity, size, the driver-set bit, and
 * the driver value.  Device capability bytes remain destination policy and
 * are not serialized.  Restore validates every staged driver value against
 * that policy before replacing any live value.
 */
int	virtio_admin_capability_register(
	    struct virtio_admin_capability_manager *,
	    const struct virtio_admin_capability_config *);
int	virtio_admin_capability_set_driver(
	    struct virtio_admin_capability_manager *, uint16_t,
	    const void *, size_t);
/*
 * Publish an exact-size value without allocating.  This is intended for the
 * final step of a larger transaction whose caller has already staged and
 * validated all related state.  The normal validation and apply callbacks
 * still run, so a successful preflight must remain valid until this call.
 */
int	virtio_admin_capability_set_driver_exact(
	    struct virtio_admin_capability_manager *, uint16_t,
	    const void *, size_t);
int	virtio_admin_capability_get_driver(
	    struct virtio_admin_capability_manager *, uint16_t,
	    void *, size_t, size_t *, bool *);
/*
 * Atomically publish all three generic capability commands exactly once.
 * Later publication returns EALREADY and freezes the registered schema.
 */
int	virtio_admin_capability_register_commands(
	    struct virtio_admin_capability_manager *, struct virtio_admin_owner *);
int	virtio_admin_capability_snapshot_size(
	    struct virtio_admin_capability_manager *, size_t *);
int	virtio_admin_capability_snapshot(
	    struct virtio_admin_capability_manager *, void *, size_t);
bool	virtio_admin_capability_snapshot_overlaps(
	    struct virtio_admin_capability_manager *, const void *, size_t);
int	virtio_admin_capability_restore(
	    struct virtio_admin_capability_manager *, const void *, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_CAPABILITY_H_ */

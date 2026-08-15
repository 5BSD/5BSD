/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_GROUP_H_
#define	_BHYVE_VIRTIO_ADMIN_GROUP_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_admin.h"

struct virtio_admin_group_fabric;
struct virtio_admin_owner;

#define	BHYVE_VIRTIO_ADMIN_GROUP_MAX	8
#define	BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE	32
#define	BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE	48

typedef bool (*virtio_admin_group_available_cb)(void *);
typedef int (*virtio_admin_group_begin_cb)(void *, uint16_t *);
typedef void (*virtio_admin_group_end_cb)(void *);
typedef void (*virtio_admin_group_reset_cb)(void *);

struct virtio_admin_group_config {
	uint16_t group_type;
	virtio_admin_group_available_cb available;
	virtio_admin_member_validate_cb member_valid;
	virtio_admin_group_begin_cb begin;
	virtio_admin_group_end_cb end;
	virtio_admin_group_reset_cb reset;
	void *argument;
};

/*
 * Group registrations and their command registrations are immutable once
 * administration queues can execute.  The owner returned by register(), or
 * later by owner(), is therefore only for initialization-time registration
 * and quiesced inspection; calling owner mutation or state APIs directly
 * while the fabric is live bypasses the fabric lock.
 *
 * destroy() requires all administration queue workers to have stopped.
 * reset(), snapshot(), and restore() exclude process() across every group.
 * reset() first restores each owner's assumed command set and then invokes
 * the optional group reset callback for associated capabilities, resource
 * objects, and member-control state.
 *
 * A group whose membership can change while the device is running must
 * provide paired begin/end callbacks.  begin() acquires the external
 * lifecycle lease and revalidates availability; end() releases it after the
 * command has completed.  available() alone is only a preliminary check.
 */
int	virtio_admin_group_fabric_create(
	    struct virtio_admin_group_fabric **);
void	virtio_admin_group_fabric_destroy(
	    struct virtio_admin_group_fabric *);
/*
 * Permanently freeze the group and command topology.  process() seals on its
 * first call; transports may seal earlier, before publishing queue state.
 */
int	virtio_admin_group_fabric_seal(
	    struct virtio_admin_group_fabric *);
void	virtio_admin_group_fabric_reset(
	    struct virtio_admin_group_fabric *);
int	virtio_admin_group_register(struct virtio_admin_group_fabric *,
	    const struct virtio_admin_group_config *,
	    struct virtio_admin_owner **);
struct virtio_admin_owner *virtio_admin_group_owner(
	    struct virtio_admin_group_fabric *, uint16_t);
int	virtio_admin_group_process(struct virtio_admin_group_fabric *,
	    const void *, size_t, void *, size_t, size_t *);
int	virtio_admin_group_snapshot_size(
	    struct virtio_admin_group_fabric *, size_t *);
int	virtio_admin_group_snapshot(
	    struct virtio_admin_group_fabric *, void *, size_t);
bool	virtio_admin_group_snapshot_overlaps(
	    struct virtio_admin_group_fabric *, const void *, size_t);
int	virtio_admin_group_restore(
	    struct virtio_admin_group_fabric *, const void *, size_t);
int	virtio_admin_group_restore_validate(
	    struct virtio_admin_group_fabric *, const void *, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_GROUP_H_ */

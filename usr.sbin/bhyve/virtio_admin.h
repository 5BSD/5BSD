/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_H_
#define	_BHYVE_VIRTIO_ADMIN_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_ADMIN_CMD_LIST_QUERY	0x0000
#define	BHYVE_VIRTIO_ADMIN_CMD_LIST_USE		0x0001
#define	BHYVE_VIRTIO_ADMIN_CMD_CAP_ID_LIST_QUERY	0x0007
#define	BHYVE_VIRTIO_ADMIN_CMD_DEVICE_CAP_GET		0x0008
#define	BHYVE_VIRTIO_ADMIN_CMD_DRIVER_CAP_SET		0x0009
#define	BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE	0x000a
#define	BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_QUERY	0x000b
#define	BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_MODIFY	0x000c
#define	BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY	0x000d
#define	BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET	0x000e
#define	BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_GET		0x000f
#define	BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_SET		0x0010
#define	BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET		0x0011
#define	BHYVE_VIRTIO_ADMIN_CMD_RESERVED_0012		0x0012
#define	BHYVE_VIRTIO_ADMIN_CMD_FIRST_DEVICE_SPECIFIC	0x0013

#define	BHYVE_VIRTIO_ADMIN_GROUP_SELF		0x0000
#define	BHYVE_VIRTIO_ADMIN_GROUP_SRIOV		0x0001

#define	BHYVE_VIRTIO_ADMIN_STATUS_OK		0
#define	BHYVE_VIRTIO_ADMIN_STATUS_ENXIO		6
#define	BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN	11
#define	BHYVE_VIRTIO_ADMIN_STATUS_ENOMEM	12
#define	BHYVE_VIRTIO_ADMIN_STATUS_EBUSY		16
#define	BHYVE_VIRTIO_ADMIN_STATUS_EEXIST	17
#define	BHYVE_VIRTIO_ADMIN_STATUS_EINVAL	22
#define	BHYVE_VIRTIO_ADMIN_STATUS_ENOSPC	28

#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_OK			0x0000
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_COMMAND	0x0001
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_OPCODE	0x0002
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_FIELD	0x0003
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP	0x0004
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_MEMBER	0x0005
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_NORESOURCE		0x0006
#define	BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN		0x0007

#define	BHYVE_VIRTIO_ADMIN_HEADER_SIZE		24
#define	BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE	8
#define	BHYVE_VIRTIO_ADMIN_LIST_SIZE		8
#define	BHYVE_VIRTIO_ADMIN_STATE_SIZE		32

struct virtio_admin_owner;

struct virtio_admin_command_result {
	uint16_t status;
	uint16_t qualifier;
	size_t result_length;
};

typedef void (*virtio_admin_command_cb)(void *, uint64_t, const void *,
	    size_t, void *, size_t, struct virtio_admin_command_result *);
typedef bool (*virtio_admin_member_validate_cb)(void *, uint64_t);

struct virtio_admin_command_registration {
	uint16_t opcode;
	virtio_admin_command_cb handler;
	void *argument;
};

int	virtio_admin_owner_create(struct virtio_admin_owner **);
/*
 * The owner of registered callback arguments must keep them alive until all
 * administration queues have stopped and virtio_admin_owner_destroy() has
 * returned.  Registration is permanent for the lifetime of the owner.
 * A callback initializes min(result_length, output_length) command-specific
 * result bytes.  The common core forces status_qualifier to zero when status
 * is OK and converts private status or qualifier values to the standard
 * INVALID_COMMAND result.  A callback may be invoked concurrently from
 * distinct admin queues.
 */
void	virtio_admin_owner_destroy(struct virtio_admin_owner *);
/*
 * Reset closes admission, drains callbacks already dispatched by this owner,
 * and then restores the specification-defined assumed command set.  New
 * commands observed during the drain complete with EAGAIN/TRYAGAIN and have
 * no side effects.
 */
void	virtio_admin_owner_reset(struct virtio_admin_owner *);
int	virtio_admin_owner_register_command(struct virtio_admin_owner *,
	    uint16_t, virtio_admin_command_cb, void *);
int	virtio_admin_owner_register_commands(struct virtio_admin_owner *,
		    const struct virtio_admin_command_registration *, size_t);
/*
 * Permanently close command registration before an owner becomes visible to
 * an administration queue.  Sealing is idempotent.  A retained initialization
 * pointer remains safe to inspect, but later registrations fail with EBUSY.
 */
int	virtio_admin_owner_seal(struct virtio_admin_owner *);
uint16_t virtio_admin_status_from_errno(int);

/*
 * Process one already-linearized administration command.  The caller
 * preserves virtqueue ordering and supplies the device-readable and
 * device-writable portions separately.
 */
int	virtio_admin_process(struct virtio_admin_owner *, const void *, size_t,
	    void *, size_t, size_t *);
int	virtio_admin_process_group(struct virtio_admin_owner *, uint16_t,
	    virtio_admin_member_validate_cb, void *, const void *, size_t,
	    void *, size_t, size_t *);
/*
 * Side-effect-free validation used by a dynamic group fabric before it
 * acquires an external lifecycle lease.  This preserves the specification's
 * invalid-group, invalid-opcode, invalid-member precedence without invoking
 * begin/end callbacks for a malformed command.  process_group() validates
 * again after the lease is held, so changing membership cannot bypass the
 * stable check.
 */
bool	virtio_admin_prevalidate_group(struct virtio_admin_owner *, uint16_t,
	    virtio_admin_member_validate_cb, void *, const void *, size_t,
	    uint16_t *, uint16_t *);

int	virtio_admin_snapshot(struct virtio_admin_owner *, void *, size_t);
bool	virtio_admin_snapshot_overlaps(struct virtio_admin_owner *,
	    const void *, size_t);
int	virtio_admin_restore_validate(struct virtio_admin_owner *,
	    const void *, size_t);
int	virtio_admin_restore(struct virtio_admin_owner *, const void *, size_t);
/*
 * Validate and restore a set of distinct owners as one transaction.  Owners
 * are locked in an internal canonical order so overlapping transactions
 * cannot deadlock when their caller-visible state order differs.
 */
int	virtio_admin_restore_many(struct virtio_admin_owner *const *,
	    const void *const *, size_t, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_H_ */

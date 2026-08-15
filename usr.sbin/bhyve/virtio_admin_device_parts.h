/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_H_
#define	_BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_admin_device_parts;
struct virtio_admin_owner;
struct virtio_device_parts_handler;

#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID		0
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE	0
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_GET		0
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_SET		1
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE	8
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE	48
#define	BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE	16

/*
 * Compose the VirtIO 1.4 device-parts capability with its resource-object
 * limits.  The returned managers remain owned by this object.  Command
 * registration is deliberately separate: device-parts handling commands are
 * SR-IOV-group commands and must not be exposed through a self-only owner.
 */
int	virtio_admin_device_parts_create(struct virtio_admin_device_parts **,
	    uint8_t, uint8_t);
void	virtio_admin_device_parts_destroy(struct virtio_admin_device_parts *);
void	virtio_admin_device_parts_reset(struct virtio_admin_device_parts *);
int	virtio_admin_device_parts_set_driver(
	    struct virtio_admin_device_parts *, const void *, size_t);
int	virtio_admin_device_parts_resource_create(
	    struct virtio_admin_device_parts *, uint32_t, uint64_t,
	    const void *, size_t);
int	virtio_admin_device_parts_resource_create_for_member(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t, uint64_t,
	    const void *, size_t);
int	virtio_admin_device_parts_resource_modify(
	    struct virtio_admin_device_parts *, uint32_t, const void *, size_t);
int	virtio_admin_device_parts_resource_modify_for_member(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t,
	    const void *, size_t);
int	virtio_admin_device_parts_resource_query(
	    struct virtio_admin_device_parts *, uint32_t, uint64_t *,
	    void *, size_t, size_t *);
int	virtio_admin_device_parts_resource_query_for_member(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t, uint64_t *,
	    void *, size_t, size_t *);
int	virtio_admin_device_parts_resource_destroy(
	    struct virtio_admin_device_parts *, uint32_t);
int	virtio_admin_device_parts_resource_destroy_for_member(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t);
int	virtio_admin_device_parts_resource_member(
	    struct virtio_admin_device_parts *, uint32_t, uint64_t *);
int	virtio_admin_device_parts_get_driver(
	    struct virtio_admin_device_parts *, void *, size_t, size_t *,
	    bool *);
int	virtio_admin_device_parts_resource_usage(
	    struct virtio_admin_device_parts *, uint8_t, uint32_t *,
	    uint32_t *);
/*
 * Bind a non-owning member-device handler during initialization, before any
 * resource object exists.  Handling calls hold the composition lock across
 * resource validation and the handler callback, so the object cannot be
 * modified or destroyed while it authorizes an operation.  Handler callbacks
 * must not reenter this composition.
 */
int	virtio_admin_device_parts_bind_handler(
	    struct virtio_admin_device_parts *,
	    struct virtio_device_parts_handler *);
int	virtio_admin_device_parts_metadata(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t, uint8_t,
	    void *, size_t, size_t *);
int	virtio_admin_device_parts_get(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t, uint8_t,
	    const void *, size_t, void *, size_t, size_t *);
int	virtio_admin_device_parts_set(
	    struct virtio_admin_device_parts *, uint64_t, uint32_t,
	    const void *, size_t);
int	virtio_admin_device_parts_mode_set(
	    struct virtio_admin_device_parts *, uint64_t, uint8_t);
/*
 * Atomically publish the complete eight-command SR-IOV device-parts family.
 * Publication succeeds once per composition; a later attempt returns
 * EALREADY.  The owner and this composition must remain alive until all
 * administration queues stop.
 */
int	virtio_admin_device_parts_register_commands(
	    struct virtio_admin_device_parts *, struct virtio_admin_owner *);
int	virtio_admin_device_parts_snapshot_size(
	    struct virtio_admin_device_parts *, size_t *);
int	virtio_admin_device_parts_snapshot(
	    struct virtio_admin_device_parts *, void *, size_t);
int	virtio_admin_device_parts_restore(
	    struct virtio_admin_device_parts *, const void *, size_t);

#endif /* _BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_H_ */

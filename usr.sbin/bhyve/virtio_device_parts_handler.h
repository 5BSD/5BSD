/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_DEVICE_PARTS_HANDLER_H_
#define	_BHYVE_VIRTIO_DEVICE_PARTS_HANDLER_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_device_parts_handler;

#define	BHYVE_VIRTIO_DEVICE_PARTS_MAX_SIZE	(1024U * 1024U)

#define	BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE		0
#define	BHYVE_VIRTIO_DEVICE_PARTS_METADATA_COUNT	1
#define	BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST		2
#define	BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED		0
#define	BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL		1
#define	BHYVE_VIRTIO_DEVICE_MODE_STOPPED		0x01U

/*
 * The provider owns member-device mechanics.  schema() emits header-only
 * records.  capture() emits complete records, either all records or the
 * selected records plus any mandatory predecessors.  prepare_restore() must
 * validate and allocate one or more complete parts without side effects,
 * including verification rather than mutation of DEV_FEATURES;
 * commit_restore() cannot fail; discard_restore() releases the transaction
 * in both paths and must accept NULL after a failed prepare.
 * set_mode(STOPPED) returns only after transport communication and observed
 * buffers are fully quiesced.  All callbacks run under the handler mutex and
 * must not reenter the same handler.
 *
 * GET capture is performed into maximum_parts_size bytes so the handler can
 * validate the complete logical result.  The caller receives as many leading
 * bytes as fit and the returned used length describes the complete result,
 * as required by the generic administration-command short-buffer rule.
 */
struct virtio_device_parts_member_ops {
	int (*schema)(void *, uint64_t, void *, size_t, size_t *);
	int (*capture)(void *, uint64_t, uint8_t, const void *, size_t,
	    void *, size_t, size_t *);
	int (*mode_get)(void *, uint64_t, bool *);
	int (*mode_set)(void *, uint64_t, bool);
	int (*prepare_restore)(void *, uint64_t, const void *, size_t, void **);
	void (*commit_restore)(void *, uint64_t, void *);
	void (*discard_restore)(void *, uint64_t, void *);
};

struct virtio_device_parts_handler_config {
	struct virtio_device_parts_member_ops ops;
	void *argument;
	uint32_t maximum_parts_size;
	uint32_t maximum_part_count;
};

int	virtio_device_parts_handler_create(
	    struct virtio_device_parts_handler **,
	    const struct virtio_device_parts_handler_config *);
void	virtio_device_parts_handler_destroy(
	    struct virtio_device_parts_handler *);
int	virtio_device_parts_handler_metadata(
	    struct virtio_device_parts_handler *, uint64_t, uint8_t,
	    void *, size_t, size_t *);
int	virtio_device_parts_handler_get(
	    struct virtio_device_parts_handler *, uint64_t, uint8_t,
	    const void *, size_t, void *, size_t, size_t *);
int	virtio_device_parts_handler_set(
	    struct virtio_device_parts_handler *, uint64_t,
	    const void *, size_t);
int	virtio_device_parts_handler_mode_set(
	    struct virtio_device_parts_handler *, uint64_t, uint8_t);

#endif /* _BHYVE_VIRTIO_DEVICE_PARTS_HANDLER_H_ */

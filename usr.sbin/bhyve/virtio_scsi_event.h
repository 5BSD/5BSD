/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_SCSI_EVENT_H_
#define	_BHYVE_VIRTIO_SCSI_EVENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VTSCSI_EVENT_CAPACITY_MAX	1024U
#define	BHYVE_VTSCSI_EVENT_MISSED	UINT32_C(0x80000000)

struct virtio_scsi_event_record {
	uint64_t source_sequence;
	uint32_t event;
	uint32_t reason;
	uint8_t lun[8];
};

struct virtio_scsi_event_state {
	struct virtio_scsi_event_record *records;
	size_t capacity;
	size_t head;
	size_t count;
	uint64_t next_source_sequence;
	bool sequence_initialized;
	bool missed;
};

int	virtio_scsi_event_state_init(struct virtio_scsi_event_state *,
	    struct virtio_scsi_event_record *, size_t);
void	virtio_scsi_event_state_reset(struct virtio_scsi_event_state *,
	    bool);
int	virtio_scsi_event_state_push(struct virtio_scsi_event_state *,
	    const struct virtio_scsi_event_record *);
int	virtio_scsi_event_state_skip(struct virtio_scsi_event_state *,
	    uint64_t);
bool	virtio_scsi_event_state_pop(struct virtio_scsi_event_state *,
	    struct virtio_scsi_event_record *);
bool	virtio_scsi_event_state_pending(
	    const struct virtio_scsi_event_state *);
size_t	virtio_scsi_event_state_count(const struct virtio_scsi_event_state *);

#endif

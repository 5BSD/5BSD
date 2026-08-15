/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright Rusty Russell IBM Corporation 2007.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef VIRTIO_RING_H
#define	VIRTIO_RING_H

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT       1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE      2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT      1

/*
 * Packed virtqueue descriptor ownership and event-suppression values from
 * VirtIO 1.4 section 2.8.  Packed descriptors deliberately retain the same
 * 16-byte size as split descriptors, but replace the linked-list next field
 * with a driver-selected completion identifier.
 */
#define	VRING_PACKED_DESC_F_AVAIL	(1U << 7)
#define	VRING_PACKED_DESC_F_USED	(1U << 15)

#define	VRING_PACKED_EVENT_FLAG_ENABLE	0
#define	VRING_PACKED_EVENT_FLAG_DISABLE	1
#define	VRING_PACKED_EVENT_FLAG_DESC	2
#define	VRING_PACKED_EVENT_OFF_MASK	0x7fff
#define	VRING_PACKED_EVENT_WRAP_CTR	0x8000

/* VirtIO ring descriptors: 16 bytes.
 * These can chain together via "next". */
struct vring_desc {
        /* Address (guest-physical). */
        uint64_t addr;
        /* Length. */
        uint32_t len;
        /* The flags as indicated above. */
        uint16_t flags;
        /* We chain unused descriptors via this, too. */
        uint16_t next;
};

struct vring_avail {
        uint16_t flags;
        uint16_t idx;
        uint16_t ring[0];
};

/* uint32_t is used here for ids for padding reasons. */
struct vring_used_elem {
        /* Index of start of used descriptor chain. */
        uint32_t id;
        /* Total length of the descriptor chain which was written to. */
        uint32_t len;
};

struct vring_used {
        uint16_t flags;
        uint16_t idx;
        struct vring_used_elem ring[0];
};

struct vring_packed_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t id;
	uint16_t flags;
};

struct vring_packed_event {
	uint16_t off_wrap;
	uint16_t flags;
};

/*
 * Packed-ring cursor and ownership helpers.  Keep these transport-neutral and
 * side-effect free so both kernel users and the independent userspace contract
 * tests exercise the exact wrap arithmetic used by the driver.
 */
static inline bool
vring_packed_advance(unsigned int num, uint16_t *offset, bool *wrap,
    unsigned int count)
{
	unsigned int next;

	if (num == 0 || num > VRING_PACKED_EVENT_OFF_MASK + 1 ||
	    *offset >= num || count > num)
		return (false);
	next = *offset + count;
	if (next >= num) {
		next -= num;
		*wrap = !*wrap;
	}
	*offset = next;
	return (true);
}

static inline uint16_t
vring_packed_off_wrap(uint16_t offset, bool wrap)
{

	return (offset | (wrap ? VRING_PACKED_EVENT_WRAP_CTR : 0));
}

static inline bool
vring_packed_desc_is_used(uint16_t flags, bool used_wrap)
{
	bool avail, used;

	avail = (flags & VRING_PACKED_DESC_F_AVAIL) != 0;
	used = (flags & VRING_PACKED_DESC_F_USED) != 0;
	return (avail == used && used == used_wrap);
}

static inline uint16_t
vring_packed_indirect_flags(bool device_writable)
{

	return (device_writable ? VRING_DESC_F_WRITE : 0);
}

/*
 * Apply the same modulo-2N event test described by VirtIO 1.4 section 2.8.10.
 * Invalid device event offsets conservatively request a notification.
 */
static inline bool
vring_packed_need_event(unsigned int num, uint16_t event_off_wrap,
    uint16_t new_offset, bool new_wrap, unsigned int added)
{
	unsigned int cycle, event, new_position, old_position;

	if (num == 0 || num > VRING_PACKED_EVENT_OFF_MASK + 1 ||
	    (event_off_wrap & VRING_PACKED_EVENT_OFF_MASK) >= num ||
	    new_offset >= num || added > num)
		return (true);
	cycle = 2 * num;
	event = (event_off_wrap & VRING_PACKED_EVENT_OFF_MASK) +
	    ((event_off_wrap & VRING_PACKED_EVENT_WRAP_CTR) != 0 ? num : 0);
	new_position = new_offset + (new_wrap ? num : 0);
	old_position = (new_position + cycle - added) % cycle;
	return (((new_position + cycle - event - 1) % cycle) <
	    ((new_position + cycle - old_position) % cycle));
}

struct vring {
	unsigned int num;

	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;

	vm_paddr_t desc_paddr;
	vm_paddr_t avail_paddr;
	vm_paddr_t used_paddr;
};

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16
#define	VRING_PACKED_DESC_ALIGN_SIZE	16
#define	VRING_PACKED_EVENT_ALIGN_SIZE	4

static inline int
vring_packed_size(unsigned int num)
{

	return (num * sizeof(struct vring_packed_desc) +
	    2 * sizeof(struct vring_packed_event));
}

static inline void
vring_packed_init(unsigned int num, uint8_t *p, vm_paddr_t paddr,
    struct vring_packed_desc **desc, struct vring_packed_event **driver_event,
    struct vring_packed_event **device_event, vm_paddr_t *desc_paddr,
    vm_paddr_t *driver_paddr, vm_paddr_t *device_paddr)
{
	size_t driver_offset, device_offset;

	driver_offset = num * sizeof(struct vring_packed_desc);
	device_offset = driver_offset + sizeof(struct vring_packed_event);
	*desc = (void *)p;
	*driver_event = (void *)(p + driver_offset);
	*device_event = (void *)(p + device_offset);
	*desc_paddr = paddr;
	*driver_paddr = paddr + driver_offset;
	*device_paddr = paddr + device_offset;
}

/* The standard layout for the ring is a continuous chunk of memory which
 * looks like this.  We assume num is a power of 2.
 *
 * struct vring {
 *      // The actual descriptors (16 bytes each)
 *      struct vring_desc desc[num];
 *
 *      // A ring of available descriptor heads with free-running index.
 *      __u16 avail_flags;
 *      __u16 avail_idx;
 *      __u16 available[num];
 *      __u16 used_event_idx;
 *
 *      // Padding to the next align boundary.
 *      char pad[];
 *
 *      // A ring of used descriptor heads with free-running index.
 *      __u16 used_flags;
 *      __u16 used_idx;
 *      struct vring_used_elem used[num];
 *      __u16 avail_event_idx;
 * };
 *
 * NOTE: for VirtIO PCI, align is 4096.
 */

/*
 * We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility.
 */
#define vring_used_event(vr)	((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr)	(*(uint16_t *)&(vr)->used->ring[(vr)->num])

static inline int
vring_size(unsigned int num, unsigned long align)
{
	int size;

	size = num * sizeof(struct vring_desc);
	size += sizeof(struct vring_avail) + (num * sizeof(uint16_t)) +
	    sizeof(uint16_t);
	size = (size + align - 1) & ~(align - 1);
	size += sizeof(struct vring_used) +
	    (num * sizeof(struct vring_used_elem)) + sizeof(uint16_t);
	return (size);
}

static inline void
vring_init(struct vring *vr, unsigned int num, uint8_t *p, vm_paddr_t paddr,
    unsigned long align)
{
	unsigned long avail_offset;
	unsigned long used_offset;

	avail_offset = num * sizeof(struct vring_desc);
	used_offset = (avail_offset + sizeof(struct vring_avail) +
	    sizeof(uint16_t) * num + align - 1) & ~(align - 1);

	vr->num = num;
	vr->desc = (void *)p;
	vr->avail = (void *)(p + avail_offset);
	vr->used = (void *)(p + used_offset);

	vr->desc_paddr = paddr;
	vr->avail_paddr = paddr + avail_offset;
	vr->used_paddr = paddr + used_offset;
}

/*
 * The following is used with VIRTIO_RING_F_EVENT_IDX.
 *
 * Assuming a given event_idx value from the other size, if we have
 * just incremented index from old to new_idx, should we trigger an
 * event?
 */
static inline int
vring_need_event(uint16_t event_idx, uint16_t new_idx, uint16_t old)
{

	return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old);
}
#endif /* VIRTIO_RING_H */

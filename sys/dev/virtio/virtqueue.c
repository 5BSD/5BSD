/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Implements the virtqueue interface as basically described
 * in the original VirtIO paper.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sdt.h>
#include <sys/sglist.h>
#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/cpu.h>
#include <machine/bus.h>
#include <machine/atomic.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ring.h>

#include "virtio_bus_if.h"

struct virtqueue {
	device_t		 vq_dev;
	struct mtx		 vq_ring_mtx;
	struct mtx		 vq_indirect_mtx;
	uint16_t		 vq_queue_index;
	uint16_t		 vq_nentries;
	uint32_t		 vq_flags;
#define	VIRTQUEUE_FLAG_MODERN	 0x0001
#define	VIRTQUEUE_FLAG_INDIRECT	 0x0002
#define	VIRTQUEUE_FLAG_EVENT_IDX 0x0004
#define	VIRTQUEUE_FLAG_PACKED	 0x0008
#define	VIRTQUEUE_FLAG_IN_ORDER	 0x0010

	int			 vq_max_indirect_size;
	bus_size_t		 vq_notify_offset;
	virtqueue_intr_t	*vq_intrhand;
	void			*vq_intrhand_arg;

	struct vring		 vq_ring;
	struct vring_packed_desc *vq_packed_desc;
	struct vring_packed_event *vq_packed_driver_event;
	struct vring_packed_event *vq_packed_device_event;
	vm_paddr_t		 vq_packed_desc_paddr;
	vm_paddr_t		 vq_packed_driver_paddr;
	vm_paddr_t		 vq_packed_device_paddr;
	uint16_t		 vq_packed_next_avail;
	uint16_t		 vq_packed_next_used;
	uint16_t		 vq_packed_free_id;
	bool			 vq_packed_avail_wrap;
	bool			 vq_packed_used_wrap;
	u_int			 vq_broken;
	uint16_t		 vq_in_order_next_used;
	uint16_t		 vq_in_order_batch_last;
	uint32_t		 vq_in_order_batch_len;
	uint16_t		 vq_free_cnt;
	uint32_t		 vq_queued_cnt;
	/*
	 * Head of the free chain in the descriptor table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 */
	uint16_t		 vq_desc_head_idx;
	/*
	 * Last consumed descriptor in the used table,
	 * trails vq_ring.used->idx.
	 */
	uint16_t		 vq_used_cons_idx;

	void			*vq_ring_mem;
	bus_dmamap_t		 vq_ring_mapp;
	vm_paddr_t		 vq_ring_paddr;

	int			 vq_indirect_mem_size;
	int			 vq_alignment;
	int			 vq_ring_size;
	char			 vq_name[VIRTQUEUE_MAX_NAME_SZ];

	bus_dma_tag_t		 vq_ring_dmat;
	bus_dma_tag_t		 vq_indirect_dmat;

	struct vq_desc_extra {
		void		  *cookie;
		struct vring_desc *indirect;
		vm_paddr_t	   indirect_paddr;
		bus_dmamap_t	   mapp;
		uint16_t	   ndescs;
		uint16_t	   packed_last_id;
		uint16_t	   packed_next_id;
		uint32_t	   writable_len;
	} vq_descx[0];
};

/*
 * The maximum virtqueue size is 2^15. Use that value as the end of
 * descriptor chain terminator since it will never be a valid index
 * in the descriptor table. This is used to verify we are correctly
 * handling vq_free_cnt.
 */
#define VQ_RING_DESC_CHAIN_END 32768

#define VQASSERT(_vq, _exp, _msg, ...)				\
    KASSERT((_exp),("%s: %s - "_msg, __func__, (_vq)->vq_name,	\
	##__VA_ARGS__))

#define VQ_RING_ASSERT_VALID_IDX(_vq, _idx)			\
    VQASSERT((_vq), (_idx) < (_vq)->vq_nentries,		\
	"invalid ring index: %d, max: %d", (_idx),		\
	(_vq)->vq_nentries)

#define VQ_RING_ASSERT_CHAIN_TERM(_vq)				\
    VQASSERT((_vq), (_vq)->vq_desc_head_idx ==			\
	VQ_RING_DESC_CHAIN_END,	"full ring terminated "		\
	"incorrectly: head idx: %d", (_vq)->vq_desc_head_idx)

static int	virtqueue_init_indirect(struct virtqueue *vq, int);
static void	virtqueue_free_indirect(struct virtqueue *vq);
static void	virtqueue_init_indirect_list(struct virtqueue *,
		    struct vring_desc *);

static void	vq_ring_init(struct virtqueue *);
static void	vq_packed_init(struct virtqueue *);
static void	vq_packed_advance(struct virtqueue *, uint16_t *, bool *,
		    uint16_t);
static bool	vq_packed_desc_used(struct virtqueue *, uint16_t, bool);
static uint16_t	vq_packed_desc_flags(struct virtqueue *, bool, uint16_t);
static uint16_t	vq_packed_outstanding(struct virtqueue *);
static bool	vq_packed_more_used(struct virtqueue *);
static uint16_t	vq_packed_nused(struct virtqueue *);
static int	vq_packed_enqueue(struct virtqueue *, void *,
		    struct sglist *, int, int);
static int	vq_packed_enqueue_indirect(struct virtqueue *, void *,
		    struct sglist *, int, int);
static void	*vq_packed_dequeue(struct virtqueue *, uint32_t *);
static void	*vq_split_in_order_dequeue(struct virtqueue *, uint32_t *);
static int	vq_validate_segments(struct sglist *, int, int, uint32_t *);
static bool	vq_in_order_batch_load(struct virtqueue *, uint16_t,
		    uint32_t, uint16_t);
static bool	vq_is_broken(struct virtqueue *);
static void	vq_mark_broken(struct virtqueue *, const char *);
static uint16_t	vq_packed_alloc_ids(struct virtqueue *, uint16_t,
		    uint16_t *);
static void	vq_packed_free_ids(struct virtqueue *, uint16_t);
static void	vq_ring_update_avail(struct virtqueue *, uint16_t);
static uint16_t	vq_ring_enqueue_segments(struct virtqueue *,
		    struct vring_desc *, uint16_t, struct sglist *, int, int);
static bool	vq_ring_use_indirect(struct virtqueue *, int);
static void	vq_ring_enqueue_indirect(struct virtqueue *, void *,
		    struct sglist *, int, int);
static int	vq_ring_enable_interrupt(struct virtqueue *, uint16_t);
static int	vq_ring_must_notify_host(struct virtqueue *);
static void	vq_ring_notify_host(struct virtqueue *);
static void	vq_ring_free_chain(struct virtqueue *, uint16_t);

SDT_PROVIDER_DEFINE(virtqueue);
SDT_PROBE_DEFINE6(virtqueue, , enqueue_segments, entry, "struct virtqueue *",
    "struct vring_desc *", "uint16_t", "struct sglist *", "int", "int");
SDT_PROBE_DEFINE1(virtqueue, , enqueue_segments, return, "uint16_t");

#define vq_modern(_vq) 		(((_vq)->vq_flags & VIRTQUEUE_FLAG_MODERN) != 0)
#define	vq_packed(_vq)		(((_vq)->vq_flags & VIRTQUEUE_FLAG_PACKED) != 0)
#define	vq_in_order(_vq)	(((_vq)->vq_flags & VIRTQUEUE_FLAG_IN_ORDER) != 0)
#define vq_htog16(_vq, _val) 	virtio_htog16(vq_modern(_vq), _val)
#define vq_htog32(_vq, _val) 	virtio_htog32(vq_modern(_vq), _val)
#define vq_htog64(_vq, _val) 	virtio_htog64(vq_modern(_vq), _val)
#define vq_gtoh16(_vq, _val) 	virtio_gtoh16(vq_modern(_vq), _val)
#define vq_gtoh32(_vq, _val) 	virtio_gtoh32(vq_modern(_vq), _val)
#define vq_gtoh64(_vq, _val) 	virtio_gtoh64(vq_modern(_vq), _val)

static void
virtqueue_ring_load_callback(void *arg, bus_dma_segment_t *segs,
    int nsegs, int error)
{
	struct virtqueue *vq;

	if (error != 0)
		return;

	KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

	vq = (struct virtqueue *)arg;
	vq->vq_ring_paddr = segs[0].ds_addr;
}

int
virtqueue_alloc(device_t dev, uint16_t queue, uint16_t size,
    bus_size_t notify_offset, int align, vm_paddr_t highaddr,
    struct vq_alloc_info *info, struct virtqueue **vqp)
{
	struct virtqueue *vq;
	int error, i;

	*vqp = NULL;
	error = 0;

	if (size == 0) {
		device_printf(dev,
		    "virtqueue %d (%s) does not exist (size is zero)\n",
		    queue, info->vqai_name);
		return (ENODEV);
	} else if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_F_RING_PACKED) != 0 &&
	    !virtio_packed_queue_size_valid(size)) {
		device_printf(dev,
		    "packed virtqueue %d (%s) size is invalid: %d\n",
		    queue, info->vqai_name, size);
		return (ENXIO);
	} else if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_F_RING_PACKED) == 0 &&
	    !powerof2(size)) {
		device_printf(dev,
		    "virtqueue %d (%s) size is not a power of 2: %d\n",
		    queue, info->vqai_name, size);
		return (ENXIO);
	} else if (info->vqai_maxindirsz > VIRTIO_MAX_INDIRECT) {
		device_printf(dev, "virtqueue %d (%s) requested too many "
		    "indirect descriptors: %d, max %d\n",
		    queue, info->vqai_name, info->vqai_maxindirsz,
		    VIRTIO_MAX_INDIRECT);
		return (EINVAL);
	}

	vq = malloc(sizeof(struct virtqueue) +
	    size * sizeof(struct vq_desc_extra), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (vq == NULL) {
		device_printf(dev, "cannot allocate virtqueue\n");
		return (ENOMEM);
	}

	vq->vq_dev = dev;
	strlcpy(vq->vq_name, info->vqai_name, sizeof(vq->vq_name));
	vq->vq_queue_index = queue;
	vq->vq_notify_offset = notify_offset;
	vq->vq_alignment = align;
	vq->vq_nentries = size;
	vq->vq_free_cnt = size;
	vq->vq_packed_free_id = 0;
	vq->vq_in_order_batch_last = VQ_RING_DESC_CHAIN_END;
	vq->vq_intrhand = info->vqai_intr;
	vq->vq_intrhand_arg = info->vqai_intr_arg;
	for (i = 0; i < size; i++) {
		vq->vq_descx[i].packed_last_id = VQ_RING_DESC_CHAIN_END;
		vq->vq_descx[i].packed_next_id = i + 1 < size ? i + 1 :
		    VQ_RING_DESC_CHAIN_END;
	}

	if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_F_VERSION_1) != 0)
		vq->vq_flags |= VIRTQUEUE_FLAG_MODERN;
	if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_EVENT_IDX) != 0)
		vq->vq_flags |= VIRTQUEUE_FLAG_EVENT_IDX;
	if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_F_RING_PACKED) != 0)
		vq->vq_flags |= VIRTQUEUE_FLAG_PACKED;
	if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_F_IN_ORDER) != 0)
		vq->vq_flags |= VIRTQUEUE_FLAG_IN_ORDER;

	vq->vq_ring_size = round_page(vq_packed(vq) ?
	    vring_packed_size(size) : vring_size(size, align));

	mtx_init(&vq->vq_ring_mtx, device_get_nameunit(dev),
	    "VirtIO Queue Lock", MTX_DEF);

	error = bus_dma_tag_create(
	    bus_get_dma_tag(dev),			/* parent */
	    align,					/* alignment */
	    0,						/* boundary */
	    BUS_SPACE_MAXADDR,				/* lowaddr */
	    BUS_SPACE_MAXADDR,				/* highaddr */
	    NULL, NULL,					/* filter, filterarg */
	    vq->vq_ring_size,				/* max request size */
	    1,						/* max # segments */
	    vq->vq_ring_size,				/* maxsegsize */
	    BUS_DMA_COHERENT,				/* flags */
	    busdma_lock_mutex,				/* lockfunc */
	    &vq->vq_ring_mtx,				/* lockarg */
	    &vq->vq_ring_dmat);
	if (error) {
		device_printf(dev, "cannot create bus_dma_tag\n");
		goto fail;
	}

#ifdef __powerpc__
	/*
	 * Virtio uses physical addresses rather than bus addresses, so we
	 * need to ask busdma to skip the iommu physical->bus mapping.  At
	 * present, this is only a thing on the powerpc architectures.
	 */
	bus_dma_tag_set_iommu(vq->vq_ring_dmat, NULL, NULL);
#endif

	if (info->vqai_maxindirsz > 1) {
		error = virtqueue_init_indirect(vq, info->vqai_maxindirsz);
		if (error)
			goto fail;
	}

	error = bus_dmamem_alloc(vq->vq_ring_dmat, &vq->vq_ring_mem,
	    BUS_DMA_NOWAIT | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &vq->vq_ring_mapp);
	if (error) {
		device_printf(dev, "bus_dmamem_alloc failed\n");
		goto fail;
	}

	error = bus_dmamap_load(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    vq->vq_ring_mem, vq->vq_ring_size, virtqueue_ring_load_callback,
	    vq, BUS_DMA_NOWAIT);
	if (error) {
		device_printf(dev, "vq->vq_ring_mapp load failed\n");
		goto fail;
	}

	if (vq_packed(vq))
		vq_packed_init(vq);
	else
		vq_ring_init(vq);
	virtqueue_disable_intr(vq);

	*vqp = vq;

fail:
	if (error)
		virtqueue_free(vq);

	return (error);
}

static void
virtqueue_indirect_load_callback(void *arg, bus_dma_segment_t *segs,
    int nsegs, int error)
{
	struct vq_desc_extra *dxp;

	if (error != 0)
		return;

	KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

	dxp = (struct vq_desc_extra *)arg;
	dxp->indirect_paddr = segs[0].ds_addr;
}

static int
virtqueue_init_indirect(struct virtqueue *vq, int indirect_size)
{
	device_t dev;
	struct vq_desc_extra *dxp;
	int i, size;
	int error;
	int align;

	dev = vq->vq_dev;

	if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_INDIRECT_DESC) == 0) {
		/*
		 * Indirect descriptors requested by the driver but not
		 * negotiated. Return zero to keep the initialization
		 * going: we'll run fine without.
		 */
		if (bootverbose)
			device_printf(dev, "virtqueue %d (%s) requested "
			    "indirect descriptors but not negotiated\n",
			    vq->vq_queue_index, vq->vq_name);
		return (0);
	}

	size = indirect_size * sizeof(struct vring_desc);
	vq->vq_max_indirect_size = indirect_size;
	vq->vq_indirect_mem_size = size;
	vq->vq_flags |= VIRTQUEUE_FLAG_INDIRECT;

	mtx_init(&vq->vq_indirect_mtx, device_get_nameunit(dev),
	    "VirtIO Indirect Queue Lock", MTX_DEF);

	align = size;
	error = bus_dma_tag_create(
	    bus_get_dma_tag(dev),			/* parent */
	    roundup_pow_of_two(align),			/* alignment */
	    0,						/* boundary */
	    BUS_SPACE_MAXADDR,				/* lowaddr */
	    BUS_SPACE_MAXADDR,				/* highaddr */
	    NULL, NULL,					/* filter, filterarg */
	    size,					/* max request size */
	    1,						/* max # segments */
	    size,					/* maxsegsize */
	    BUS_DMA_COHERENT,				/* flags */
	    busdma_lock_mutex,				/* lockfunc */
	    &vq->vq_indirect_mtx,			/* lockarg */
	    &vq->vq_indirect_dmat);
	if (error) {
		device_printf(dev, "cannot create indirect bus_dma_tag\n");
		return (error);
	}

#ifdef __powerpc__
	/*
	 * Virtio uses physical addresses rather than bus addresses, so we
	 * need to ask busdma to skip the iommu physical->bus mapping.  At
	 * present, this is only a thing on the powerpc architectures.
	 */
	bus_dma_tag_set_iommu(vq->vq_indirect_dmat, NULL, NULL);
#endif

	for (i = 0; i < vq->vq_nentries; i++) {
		dxp = &vq->vq_descx[i];

		error = bus_dmamem_alloc(vq->vq_indirect_dmat,
		    (void **)&dxp->indirect,
		    BUS_DMA_NOWAIT | BUS_DMA_ZERO | BUS_DMA_COHERENT,
		    &dxp->mapp);
		if (error) {
			panic("dxp->mapp alloc failed\n");
			return (error);
		}

		error = bus_dmamap_load(vq->vq_indirect_dmat, dxp->mapp,
		    dxp->indirect, size, virtqueue_indirect_load_callback, dxp,
		    BUS_DMA_NOWAIT);
		if (error) {
			panic("dxp->mapp load failed\n");
			bus_dmamem_free(vq->vq_indirect_dmat, dxp->indirect,
			    dxp->mapp);
			dxp->indirect = NULL;
			return (error);
		}

		virtqueue_init_indirect_list(vq, dxp->indirect);
	}

	return (0);
}

static void
virtqueue_free_indirect(struct virtqueue *vq)
{
	struct vq_desc_extra *dxp;
	int i;

	for (i = 0; i < vq->vq_nentries; i++) {
		dxp = &vq->vq_descx[i];

		if (dxp->indirect == NULL)
			break;

		bus_dmamap_unload(vq->vq_indirect_dmat, dxp->mapp);
		bus_dmamem_free(vq->vq_indirect_dmat, dxp->indirect, dxp->mapp);
		dxp->indirect = NULL;
		dxp->indirect_paddr = 0;
	}

	vq->vq_flags &= ~VIRTQUEUE_FLAG_INDIRECT;
	vq->vq_indirect_mem_size = 0;
}

static void
virtqueue_init_indirect_list(struct virtqueue *vq,
    struct vring_desc *indirect)
{
	int i;

	bzero(indirect, vq->vq_indirect_mem_size);

	for (i = 0; i < vq->vq_max_indirect_size - 1; i++)
		indirect[i].next = vq_gtoh16(vq, i + 1);
	indirect[i].next = vq_gtoh16(vq, VQ_RING_DESC_CHAIN_END);
}

int
virtqueue_reinit(struct virtqueue *vq, uint16_t size)
{
	struct vq_desc_extra *dxp;
	int i;

	if (vq->vq_nentries != size) {
		device_printf(vq->vq_dev,
		    "%s: '%s' changed size; old=%hu, new=%hu\n",
		    __func__, vq->vq_name, vq->vq_nentries, size);
		return (EINVAL);
	}

	/* Warn if the virtqueue was not properly cleaned up. */
	if (vq->vq_free_cnt != vq->vq_nentries) {
		device_printf(vq->vq_dev,
		    "%s: warning '%s' virtqueue not empty, "
		    "leaking %d entries\n", __func__, vq->vq_name,
		    vq->vq_nentries - vq->vq_free_cnt);
	}

	vq->vq_desc_head_idx = 0;
	vq->vq_used_cons_idx = 0;
	vq->vq_queued_cnt = 0;
	vq->vq_free_cnt = vq->vq_nentries;
	vq->vq_packed_next_avail = 0;
	vq->vq_packed_next_used = 0;
	vq->vq_packed_free_id = 0;
	vq->vq_packed_avail_wrap = true;
	vq->vq_packed_used_wrap = true;
	atomic_store_int(&vq->vq_broken, 0);
	vq->vq_in_order_next_used = 0;
	vq->vq_in_order_batch_last = VQ_RING_DESC_CHAIN_END;
	vq->vq_in_order_batch_len = 0;

	/* To be safe, reset all our allocated memory. */
	bzero(vq->vq_ring_mem, vq->vq_ring_size);
	for (i = 0; i < vq->vq_nentries; i++) {
		dxp = &vq->vq_descx[i];
		dxp->cookie = NULL;
		dxp->ndescs = 0;
		dxp->packed_last_id = VQ_RING_DESC_CHAIN_END;
		dxp->packed_next_id = i + 1 < vq->vq_nentries ? i + 1 :
		    VQ_RING_DESC_CHAIN_END;
		dxp->writable_len = 0;
		if (vq->vq_flags & VIRTQUEUE_FLAG_INDIRECT)
			virtqueue_init_indirect_list(vq, dxp->indirect);
	}

	if (vq_packed(vq))
		vq_packed_init(vq);
	else
		vq_ring_init(vq);
	virtqueue_disable_intr(vq);

	return (0);
}

void
virtqueue_free(struct virtqueue *vq)
{

	if (vq->vq_free_cnt != vq->vq_nentries) {
		device_printf(vq->vq_dev, "%s: freeing non-empty virtqueue, "
		    "leaking %d entries\n", vq->vq_name,
		    vq->vq_nentries - vq->vq_free_cnt);
	}

	if (vq->vq_flags & VIRTQUEUE_FLAG_INDIRECT)
		virtqueue_free_indirect(vq);

	if (vq->vq_ring_mem != NULL) {
		bus_dmamap_unload(vq->vq_ring_dmat, vq->vq_ring_mapp);
		bus_dmamem_free(vq->vq_ring_dmat, vq->vq_ring_mem,
		    vq->vq_ring_mapp);
		vq->vq_ring_size = 0;
	}

	if (vq->vq_ring_dmat != NULL) {
		bus_dma_tag_destroy(vq->vq_ring_dmat);
	}

	free(vq, M_DEVBUF);
}

vm_paddr_t
virtqueue_paddr(struct virtqueue *vq)
{

	return (vq->vq_ring_paddr);
}

vm_paddr_t
virtqueue_desc_paddr(struct virtqueue *vq)
{

	return (vq_packed(vq) ? vq->vq_packed_desc_paddr :
	    vq->vq_ring.desc_paddr);
}

vm_paddr_t
virtqueue_avail_paddr(struct virtqueue *vq)
{

	return (vq_packed(vq) ? vq->vq_packed_driver_paddr :
	    vq->vq_ring.avail_paddr);
}

vm_paddr_t
virtqueue_used_paddr(struct virtqueue *vq)
{

	return (vq_packed(vq) ? vq->vq_packed_device_paddr :
	    vq->vq_ring.used_paddr);
}

uint16_t
virtqueue_index(struct virtqueue *vq)
{

	return (vq->vq_queue_index);
}

int
virtqueue_size(struct virtqueue *vq)
{

	return (vq->vq_nentries);
}

int
virtqueue_nfree(struct virtqueue *vq)
{

	return (vq->vq_free_cnt);
}

bool
virtqueue_empty(struct virtqueue *vq)
{

	return (vq->vq_nentries == vq->vq_free_cnt);
}

bool
virtqueue_full(struct virtqueue *vq)
{

	return (vq->vq_free_cnt == 0);
}

void
virtqueue_notify(struct virtqueue *vq)
{
	if (vq_is_broken(vq))
		return;
	/* Ensure updated avail->idx is visible to host. */
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	/*
	 * The queue implementation is shared by every architecture.  Preserve
	 * the descriptor-before-notification ordering even on weakly ordered
	 * non-x86 hosts.
	 */
	mb();
	if (vq_is_broken(vq))
		return;

	if (vq_ring_must_notify_host(vq))
		vq_ring_notify_host(vq);
	vq->vq_queued_cnt = 0;
}

int
virtqueue_nused(struct virtqueue *vq)
{
	uint16_t nused, used_idx;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_POSTREAD);
	if (vq_is_broken(vq))
		return (0);

	if (vq_packed(vq))
		return (vq_packed_nused(vq));

	used_idx = vq_htog16(vq, vq->vq_ring.used->idx);

	nused = (uint16_t)(used_idx - vq->vq_used_cons_idx);
	if (nused > vq->vq_nentries) {
		vq_mark_broken(vq, "split used index advanced beyond queue");
		return (0);
	}

	return (nused);
}

int
virtqueue_intr_filter(struct virtqueue *vq)
{
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_POSTREAD);
	if (vq_is_broken(vq))
		return (0);

	if (vq_packed(vq)) {
		if (!vq_packed_more_used(vq))
			return (0);
	} else if (vq->vq_used_cons_idx ==
	    vq_htog16(vq, vq->vq_ring.used->idx))
		return (0);

	virtqueue_disable_intr(vq);

	return (1);
}

void
virtqueue_intr(struct virtqueue *vq)
{

	if (!vq_is_broken(vq))
		vq->vq_intrhand(vq->vq_intrhand_arg);
}

int
virtqueue_enable_intr(struct virtqueue *vq)
{

	return (vq_ring_enable_interrupt(vq, 0));
}

int
virtqueue_postpone_intr(struct virtqueue *vq, vq_postpone_t hint)
{
	uint16_t ndesc, avail_idx;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_POSTREAD);

	if (vq_packed(vq))
		ndesc = vq_packed_outstanding(vq);
	else {
		avail_idx = vq_htog16(vq, vq->vq_ring.avail->idx);
		ndesc = (uint16_t)(avail_idx - vq->vq_used_cons_idx);
	}

	switch (hint) {
	case VQ_POSTPONE_SHORT:
		ndesc = ndesc / 4;
		break;
	case VQ_POSTPONE_LONG:
		ndesc = (ndesc * 3) / 4;
		break;
	case VQ_POSTPONE_EMPTIED:
		break;
	}

	return (vq_ring_enable_interrupt(vq, ndesc));
}

/*
 * Note this is only considered a hint to the host.
 */
void
virtqueue_disable_intr(struct virtqueue *vq)
{
	if (vq_packed(vq)) {
		atomic_store_rel_16(&vq->vq_packed_driver_event->flags,
		    vq_gtoh16(vq, VRING_PACKED_EVENT_FLAG_DISABLE));
		bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
		    BUS_DMASYNC_PREWRITE);
		return;
	}

	if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) {
		vring_used_event(&vq->vq_ring) = vq_gtoh16(vq,
		    vq->vq_used_cons_idx - vq->vq_nentries - 1);
		bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
		    BUS_DMASYNC_PREWRITE);
		return;
	}

	vq->vq_ring.avail->flags |= vq_gtoh16(vq, VRING_AVAIL_F_NO_INTERRUPT);

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
}

static int
vq_validate_segments(struct sglist *sg, int readable, int writable,
    uint32_t *writable_len)
{
	uint64_t total, writable_total;
	int i, needed;

	if (readable < 0 || writable < 0 || readable > INT_MAX - writable)
		return (EINVAL);
	needed = readable + writable;
	total = 0;
	writable_total = 0;
	for (i = 0; i < needed; i++) {
		if (sg->sg_segs[i].ss_len > UINT32_MAX)
			return (EFBIG);
		total += sg->sg_segs[i].ss_len;
		if (i >= readable)
			writable_total += sg->sg_segs[i].ss_len;
	}
	/*
	 * Section 2.7.5.2 forbids a chain longer than 2^32 bytes.  The
	 * completion length is itself only 32 bits, so a device-writable span
	 * of exactly 2^32 bytes cannot be represented for an IN_ORDER skipped
	 * buffer and is rejected as well.
	 */
	if (total > (1ULL << 32) || writable_total > UINT32_MAX)
		return (EFBIG);
	*writable_len = (uint32_t)writable_total;
	return (0);
}

int
virtqueue_enqueue(struct virtqueue *vq, void *cookie, struct sglist *sg,
    int readable, int writable)
{
	struct vq_desc_extra *dxp;
	uint32_t writable_len;
	int error, needed;
	uint16_t head_idx, idx;

	if (readable < 0 || writable < 0 || readable > INT_MAX - writable)
		return (EINVAL);
	needed = readable + writable;

	VQASSERT(vq, cookie != NULL, "enqueuing with no cookie");
	VQASSERT(vq, needed == sg->sg_nseg,
	    "segment count mismatch, %d, %d", needed, sg->sg_nseg);
	VQASSERT(vq,
	    needed <= vq->vq_nentries || needed <= vq->vq_max_indirect_size,
	    "too many segments to enqueue: %d, %d/%d", needed,
	    vq->vq_nentries, vq->vq_max_indirect_size);

	if (needed < 1)
		return (EINVAL);
	if (vq_is_broken(vq))
		return (EIO);
	error = vq_validate_segments(sg, readable, writable, &writable_len);
	if (error != 0)
		return (error);
	if (vq->vq_free_cnt == 0)
		return (ENOSPC);

	if (vq_packed(vq)) {
		if (vq_ring_use_indirect(vq, needed))
			return (vq_packed_enqueue_indirect(vq, cookie, sg,
			    readable, writable));
		if (vq->vq_free_cnt < needed)
			return (EMSGSIZE);
		return (vq_packed_enqueue(vq, cookie, sg, readable,
		    writable));
	}

	if (vq_ring_use_indirect(vq, needed)) {
		vq_ring_enqueue_indirect(vq, cookie, sg, readable, writable);
		return (0);
	} else if (vq->vq_free_cnt < needed)
		return (EMSGSIZE);

	head_idx = vq->vq_desc_head_idx;
	VQ_RING_ASSERT_VALID_IDX(vq, head_idx);
	dxp = &vq->vq_descx[head_idx];

	VQASSERT(vq, dxp->cookie == NULL,
	    "cookie already exists for index %d", head_idx);
	dxp->cookie = cookie;
	dxp->ndescs = needed;
	dxp->writable_len = writable_len;

	idx = vq_ring_enqueue_segments(vq, vq->vq_ring.desc, head_idx,
	    sg, readable, writable);

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);

	vq->vq_desc_head_idx = idx;
	vq->vq_free_cnt -= needed;
	if (vq->vq_free_cnt == 0 && !vq_in_order(vq))
		VQ_RING_ASSERT_CHAIN_TERM(vq);
	else if (vq->vq_free_cnt != 0)
		VQ_RING_ASSERT_VALID_IDX(vq, idx);

	vq_ring_update_avail(vq, head_idx);

	return (0);
}

void *
virtqueue_dequeue(struct virtqueue *vq, uint32_t *len)
{
	struct vring_used_elem *uep;
	void *cookie;
	uint16_t used_idx, desc_idx;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_POSTREAD);

	if (vq_packed(vq))
		return (vq_packed_dequeue(vq, len));
	if (vq_in_order(vq))
		return (vq_split_in_order_dequeue(vq, len));
	if (vq_is_broken(vq))
		return (NULL);

	if (vq->vq_used_cons_idx ==
	    vq_htog16(vq, atomic_load_16(&vq->vq_ring.used->idx)))
		return (NULL);

	used_idx = vq->vq_used_cons_idx++ & (vq->vq_nentries - 1);
	uep = &vq->vq_ring.used->ring[used_idx];

	rmb();
	if (vq_htog32(vq, uep->id) >= vq->vq_nentries) {
		vq_mark_broken(vq,
		    "split completion identifier is out of range");
		vq->vq_used_cons_idx--;
		return (NULL);
	}
	desc_idx = (uint16_t)vq_htog32(vq, uep->id);
	if (vq->vq_descx[desc_idx].cookie == NULL ||
	    vq->vq_descx[desc_idx].ndescs == 0) {
		vq_mark_broken(vq,
		    "split completion does not name a live buffer");
		vq->vq_used_cons_idx--;
		return (NULL);
	}
	if (vq_htog32(vq, uep->len) >
	    vq->vq_descx[desc_idx].writable_len) {
		vq_mark_broken(vq,
		    "split used length exceeds writable capacity");
		vq->vq_used_cons_idx--;
		return (NULL);
	}
	if (len != NULL)
		*len = vq_htog32(vq, uep->len);

	vq_ring_free_chain(vq, desc_idx);

	cookie = vq->vq_descx[desc_idx].cookie;
	VQASSERT(vq, cookie != NULL, "no cookie for index %d", desc_idx);
	vq->vq_descx[desc_idx].cookie = NULL;

	return (cookie);
}

static void *
vq_split_in_order_dequeue(struct virtqueue *vq, uint32_t *len)
{
	struct vring_used_elem *uep;
	struct vq_desc_extra *dxp;
	void *cookie;
	uint32_t marker32, used_len;
	uint16_t available, head, ndescs, used_idx;

	if (vq_is_broken(vq))
		return (NULL);
	used_idx = vq_htog16(vq,
	    atomic_load_16(&vq->vq_ring.used->idx));
	available = (uint16_t)(used_idx - vq->vq_used_cons_idx);
	if (available == 0)
		return (NULL);
	if (available > vq->vq_nentries) {
		vq_mark_broken(vq, "split used index advanced beyond queue");
		return (NULL);
	}
	if (vq->vq_in_order_batch_last == VQ_RING_DESC_CHAIN_END) {
		uep = &vq->vq_ring.used->ring[
		    vq->vq_used_cons_idx & (vq->vq_nentries - 1)];
		rmb();
		marker32 = vq_htog32(vq, atomic_load_32(&uep->id));
		used_len = vq_htog32(vq, atomic_load_32(&uep->len));
		if (marker32 >= vq->vq_nentries ||
		    !vq_in_order_batch_load(vq, (uint16_t)marker32,
		    used_len, available)) {
			vq_mark_broken(vq,
			    "unreachable split IN_ORDER batch marker");
			return (NULL);
		}
	}
	head = vq->vq_in_order_next_used;
	dxp = &vq->vq_descx[head];
	if (dxp->cookie == NULL || dxp->ndescs == 0) {
		vq_mark_broken(vq,
		    "split IN_ORDER completion has no live owner");
		return (NULL);
	}
	cookie = dxp->cookie;
	ndescs = dxp->ndescs;
	if (head == vq->vq_in_order_batch_last) {
		used_len = vq->vq_in_order_batch_len;
		vq->vq_in_order_batch_last = VQ_RING_DESC_CHAIN_END;
		vq->vq_in_order_batch_len = 0;
	} else
		used_len = dxp->writable_len;
	if (used_len > dxp->writable_len) {
		vq_mark_broken(vq,
		    "split IN_ORDER used length exceeds writable capacity");
		return (NULL);
	}
	if (len != NULL)
		*len = used_len;
	dxp->cookie = NULL;
	vq_ring_free_chain(vq, head);
	vq->vq_in_order_next_used =
	    (vq->vq_in_order_next_used + ndescs) % vq->vq_nentries;
	vq->vq_used_cons_idx++;
	return (cookie);
}

void *
virtqueue_poll(struct virtqueue *vq, uint32_t *len)
{
	void *cookie;

	while ((cookie = virtqueue_dequeue(vq, len)) == NULL) {
		if (vq_is_broken(vq))
			return (NULL);
		cpu_spinwait();
	}

	return (cookie);
}

void *
virtqueue_drain(struct virtqueue *vq, int *last)
{
	void *cookie;
	int idx;

	cookie = NULL;
	idx = *last;

	while (idx < vq->vq_nentries && cookie == NULL) {
		if ((cookie = vq->vq_descx[idx].cookie) != NULL) {
			vq->vq_descx[idx].cookie = NULL;
			/* Free chain to keep free count consistent. */
			if (vq_packed(vq)) {
				VQASSERT(vq, vq->vq_descx[idx].ndescs != 0,
				    "packed drain owner has no descriptors");
				vq->vq_free_cnt +=
				    vq->vq_descx[idx].ndescs;
				if (vq_in_order(vq)) {
					vq->vq_descx[idx].ndescs = 0;
					vq->vq_descx[idx].writable_len = 0;
				} else
					vq_packed_free_ids(vq, idx);
			} else
				vq_ring_free_chain(vq, idx);
		}
		idx++;
	}

	*last = idx;

	return (cookie);
}

void
virtqueue_dump(struct virtqueue *vq)
{

	if (vq == NULL)
		return;

	if (vq_packed(vq)) {
		printf("VQ: %s - packed size=%d; free=%d; used=%d; "
		    "queued=%u; next_avail=%d/%d; next_used=%d/%d\n",
		    vq->vq_name, vq->vq_nentries, vq->vq_free_cnt,
		    virtqueue_nused(vq), vq->vq_queued_cnt,
		    vq->vq_packed_next_avail, vq->vq_packed_avail_wrap,
		    vq->vq_packed_next_used, vq->vq_packed_used_wrap);
		return;
	}
	printf("VQ: %s - size=%d; free=%d; used=%d; queued=%u; "
	    "desc_head_idx=%d; avail.idx=%d; used_cons_idx=%d; "
	    "used.idx=%d; used_event_idx=%d; avail.flags=0x%x; used.flags=0x%x\n",
	    vq->vq_name, vq->vq_nentries, vq->vq_free_cnt, virtqueue_nused(vq),
	    vq->vq_queued_cnt, vq->vq_desc_head_idx,
	    vq_htog16(vq, vq->vq_ring.avail->idx), vq->vq_used_cons_idx,
	    vq_htog16(vq, vq->vq_ring.used->idx),
	    vq_htog16(vq, vring_used_event(&vq->vq_ring)),
	    vq_htog16(vq, vq->vq_ring.avail->flags),
	    vq_htog16(vq, vq->vq_ring.used->flags));
}

static void
vq_ring_init(struct virtqueue *vq)
{
	struct vring *vr;
	char *ring_mem;
	int i, size;

	ring_mem = vq->vq_ring_mem;
	size = vq->vq_nentries;
	vr = &vq->vq_ring;

	vring_init(vr, size, ring_mem, vq->vq_ring_paddr, vq->vq_alignment);

	for (i = 0; i < size - 1; i++)
		vr->desc[i].next = vq_gtoh16(vq, i + 1);
	vr->desc[i].next = vq_gtoh16(vq, vq_in_order(vq) ? 0 :
	    VQ_RING_DESC_CHAIN_END);

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
}

static void
vq_packed_init(struct virtqueue *vq)
{

	vring_packed_init(vq->vq_nentries, vq->vq_ring_mem,
	    vq->vq_ring_paddr, &vq->vq_packed_desc,
	    &vq->vq_packed_driver_event, &vq->vq_packed_device_event,
	    &vq->vq_packed_desc_paddr, &vq->vq_packed_driver_paddr,
	    &vq->vq_packed_device_paddr);
	vq->vq_packed_next_avail = 0;
	vq->vq_packed_next_used = 0;
	vq->vq_packed_free_id = 0;
	vq->vq_packed_avail_wrap = true;
	vq->vq_packed_used_wrap = true;
	vq->vq_in_order_next_used = 0;
	vq->vq_in_order_batch_last = VQ_RING_DESC_CHAIN_END;
	vq->vq_in_order_batch_len = 0;
	vq->vq_packed_driver_event->off_wrap =
	    vq_gtoh16(vq, vring_packed_off_wrap(0, true));
	vq->vq_packed_driver_event->flags =
	    vq_gtoh16(vq, VRING_PACKED_EVENT_FLAG_DISABLE);
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
}

static void
vq_packed_advance(struct virtqueue *vq, uint16_t *offset, bool *wrap,
    uint16_t count)
{
	bool advanced;

	VQASSERT(vq, *offset < vq->vq_nentries && count <= vq->vq_nentries,
	    "invalid packed cursor %u + %u", *offset, count);
	/*
	 * vring_packed_advance() performs the cursor mutation.  Do not put that
	 * side effect in VQASSERT(): production kernels compile VQASSERT() out
	 * when INVARIANTS is disabled.
	 */
	advanced = vring_packed_advance(vq->vq_nentries, offset, wrap, count);
	VQASSERT(vq, advanced, "packed cursor advance rejected");
	if (__predict_false(!advanced))
		vq_mark_broken(vq, "packed cursor advance rejected");
}

static bool
vq_is_broken(struct virtqueue *vq)
{

	return (atomic_load_int(&vq->vq_broken) != 0);
}

static void
vq_mark_broken(struct virtqueue *vq, const char *reason)
{

	/* Only the first observer publishes failure and reports the defect. */
	if (!atomic_cmpset_int(&vq->vq_broken, 0, 1))
		return;
	device_printf(vq->vq_dev, "%s: malformed used ring: %s\n",
	    vq->vq_name, reason);
	virtqueue_disable_intr(vq);
	VIRTIO_BUS_FAIL(vq->vq_dev);
}

static uint16_t
vq_packed_alloc_ids(struct virtqueue *vq, uint16_t count, uint16_t *lastp)
{
	struct vq_desc_extra *dxp;
	uint16_t head, id, last;

	head = id = vq->vq_packed_free_id;
	last = VQ_RING_DESC_CHAIN_END;
	while (count-- != 0) {
		VQASSERT(vq, id < vq->vq_nentries,
		    "packed identifier free list exhausted");
		dxp = &vq->vq_descx[id];
		last = id;
		id = dxp->packed_next_id;
	}
	vq->vq_packed_free_id = id;
	*lastp = last;
	return (head);
}

static void
vq_packed_free_ids(struct virtqueue *vq, uint16_t id)
{
	struct vq_desc_extra *dxp;
	uint16_t last;

	VQASSERT(vq, id < vq->vq_nentries,
	    "invalid packed identifier %u", id);
	dxp = &vq->vq_descx[id];
	last = dxp->packed_last_id;
	VQASSERT(vq, last < vq->vq_nentries && dxp->ndescs != 0,
	    "invalid packed identifier chain %u", id);
	vq->vq_descx[last].packed_next_id = vq->vq_packed_free_id;
	vq->vq_packed_free_id = id;
	dxp->packed_last_id = VQ_RING_DESC_CHAIN_END;
	dxp->ndescs = 0;
	dxp->writable_len = 0;
}

/*
 * Validate an IN_ORDER batch marker before changing any ownership.  The
 * marker names the head of the final buffer, not the final descriptor.  A
 * bounded walk proves that it is a currently owned head reachable from the
 * oldest outstanding buffer.
 */
static bool
vq_in_order_batch_load(struct virtqueue *vq, uint16_t marker,
    uint32_t marker_len, uint16_t available)
{
	struct vq_desc_extra *dxp;
	uint16_t count, cursor;

	if (marker >= vq->vq_nentries)
		return (false);
	cursor = vq->vq_in_order_next_used;
	for (count = 1; count <= available && count <= vq->vq_nentries;
	    count++) {
		dxp = &vq->vq_descx[cursor];
		if (dxp->cookie == NULL || dxp->ndescs == 0)
			return (false);
		if (cursor == marker) {
			if (marker_len > dxp->writable_len)
				return (false);
			vq->vq_in_order_batch_last = marker;
			vq->vq_in_order_batch_len = marker_len;
			return (true);
		}
		cursor = (cursor + dxp->ndescs) % vq->vq_nentries;
	}
	return (false);
}

static uint16_t
vq_packed_desc_flags(struct virtqueue *vq, bool wrap, uint16_t flags)
{

	if (wrap)
		flags |= VRING_PACKED_DESC_F_AVAIL;
	else
		flags |= VRING_PACKED_DESC_F_USED;
	return (vq_gtoh16(vq, flags));
}

static bool
vq_packed_desc_used(struct virtqueue *vq, uint16_t offset, bool wrap)
{
	uint16_t flags;

	VQ_RING_ASSERT_VALID_IDX(vq, offset);
	flags = vq_htog16(vq,
	    atomic_load_acq_16(&vq->vq_packed_desc[offset].flags));
	return (vring_packed_desc_is_used(flags, wrap));
}

static uint16_t
vq_packed_outstanding(struct virtqueue *vq)
{

	return (vq->vq_nentries - vq->vq_free_cnt);
}

static bool
vq_packed_more_used(struct virtqueue *vq)
{

	if (vq_is_broken(vq))
		return (false);
	if (vq_in_order(vq) &&
	    vq->vq_in_order_batch_last != VQ_RING_DESC_CHAIN_END)
		return (true);
	return (vq_packed_desc_used(vq, vq->vq_packed_next_used,
	    vq->vq_packed_used_wrap));
}

static uint16_t
vq_packed_nused(struct virtqueue *vq)
{
	struct vq_desc_extra *dxp;
	uint16_t id, idx, last, nused;
	bool have_batch, wrap;

	if (vq_is_broken(vq))
		return (0);
	idx = vq->vq_packed_next_used;
	wrap = vq->vq_packed_used_wrap;
	have_batch = vq_in_order(vq) &&
	    vq->vq_in_order_batch_last != VQ_RING_DESC_CHAIN_END;
	last = have_batch ? vq->vq_in_order_batch_last :
	    VQ_RING_DESC_CHAIN_END;
	for (nused = 0; nused < vq->vq_nentries;) {
		if (!have_batch) {
			if (!vq_packed_desc_used(vq, idx, wrap))
				break;
			rmb();
			id = vq_htog16(vq,
			    atomic_load_16(&vq->vq_packed_desc[idx].id));
			if (vq_in_order(vq)) {
				if (id >= vq->vq_nentries) {
					vq_mark_broken(vq,
					    "packed batch marker is out of range");
					return (0);
				}
				last = id;
				have_batch = true;
			} else {
				if (id >= vq->vq_nentries ||
				    vq->vq_descx[id].cookie == NULL ||
				    vq->vq_descx[id].ndescs == 0) {
					vq_mark_broken(vq,
					    "packed used scan has no owner");
					return (0);
				}
				vq_packed_advance(vq, &idx, &wrap,
				    vq->vq_descx[id].ndescs);
				nused++;
				continue;
			}
		}
		/* IN_ORDER identifiers are descriptor-chain heads. */
		id = idx;
		dxp = &vq->vq_descx[id];
		if (dxp->cookie == NULL || dxp->ndescs == 0) {
			vq_mark_broken(vq,
			    "packed IN_ORDER used scan has no owner");
			return (0);
		}
		vq_packed_advance(vq, &idx, &wrap, dxp->ndescs);
		nused++;
		if (id == last)
			have_batch = false;
	}
	if (have_batch && nused == vq->vq_nentries) {
		vq_mark_broken(vq, "packed IN_ORDER batch marker is unreachable");
		return (0);
	}
	return (nused);
}

static int
vq_packed_enqueue(struct virtqueue *vq, void *cookie, struct sglist *sg,
    int readable, int writable)
{
	struct vq_desc_extra *dxp;
	struct sglist_seg *seg;
	struct vring_packed_desc *desc;
	uint32_t writable_len;
	uint16_t flags, head, id, last_id, position;
	bool head_wrap, wrap;
	int i, needed;

	needed = readable + writable;
	head = position = vq->vq_packed_next_avail;
	head_wrap = wrap = vq->vq_packed_avail_wrap;
	if (vq_in_order(vq)) {
		id = last_id = head;
	} else
		id = vq_packed_alloc_ids(vq, needed, &last_id);
	dxp = &vq->vq_descx[id];
	VQASSERT(vq, dxp->cookie == NULL,
	    "cookie already exists for packed identifier %u", id);

	/*
	 * Populate every descriptor before transferring ownership of the head.
	 * Later descriptors may become driver-owned first; the device cannot
	 * consume them until the head's release store makes the chain visible.
	 */
	for (i = 0, seg = sg->sg_segs; i < needed; i++, seg++) {
		desc = &vq->vq_packed_desc[position];
		desc->addr = vq_gtoh64(vq, seg->ss_paddr);
		desc->len = vq_gtoh32(vq, seg->ss_len);
		desc->id = vq_gtoh16(vq, id);
		flags = i + 1 < needed ? VRING_DESC_F_NEXT : 0;
		if (i >= readable)
			flags |= VRING_DESC_F_WRITE;
		if (i != 0)
			atomic_store_rel_16(&desc->flags,
			    vq_packed_desc_flags(vq, wrap, flags));
		vq_packed_advance(vq, &position, &wrap, 1);
	}
	dxp->cookie = cookie;
	dxp->ndescs = needed;
	dxp->packed_last_id = last_id;
	(void)vq_validate_segments(sg, readable, writable, &writable_len);
	dxp->writable_len = writable_len;
	vq->vq_free_cnt -= needed;
	vq->vq_queued_cnt += needed;
	vq->vq_packed_next_avail = position;
	vq->vq_packed_avail_wrap = wrap;

	position = head;
	flags = needed > 1 ? VRING_DESC_F_NEXT : 0;
	if (readable == 0)
		flags |= VRING_DESC_F_WRITE;
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	atomic_store_rel_16(&vq->vq_packed_desc[position].flags,
	    vq_packed_desc_flags(vq, head_wrap, flags));
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	return (0);
}

static int
vq_packed_enqueue_indirect(struct virtqueue *vq, void *cookie,
    struct sglist *sg, int readable, int writable)
{
	struct vq_desc_extra *dxp;
	struct vring_packed_desc *desc, *indirect;
	struct sglist_seg *seg;
	uint16_t head, id, last_id;
	bool wrap;
	int i, needed;

	needed = readable + writable;
	head = vq->vq_packed_next_avail;
	wrap = vq->vq_packed_avail_wrap;
	if (vq_in_order(vq)) {
		id = last_id = head;
	} else
		id = vq_packed_alloc_ids(vq, 1, &last_id);
	dxp = &vq->vq_descx[id];
	desc = &vq->vq_packed_desc[head];
	VQASSERT(vq, dxp->cookie == NULL,
	    "cookie already exists for packed identifier %u", id);

	/*
	 * Unlike a split indirect table, a packed indirect table is a
	 * sequential array.  Section 2.8.7 requires every entry to contain
	 * no flag except WRITE; in particular NEXT is forbidden.
	 */
	for (i = 0, indirect = (void *)dxp->indirect, seg = sg->sg_segs;
	    i < needed; i++, indirect++, seg++) {
		indirect->addr = vq_gtoh64(vq, seg->ss_paddr);
		indirect->len = vq_gtoh32(vq, seg->ss_len);
		indirect->id = 0;
		indirect->flags = vq_gtoh16(vq,
		    vring_packed_indirect_flags(i >= readable));
	}
	bus_dmamap_sync(vq->vq_indirect_dmat, dxp->mapp, BUS_DMASYNC_PREWRITE);
	desc->addr = vq_gtoh64(vq, dxp->indirect_paddr);
	desc->len = vq_gtoh32(vq,
	    needed * sizeof(struct vring_packed_desc));
	desc->id = vq_gtoh16(vq, id);
	dxp->cookie = cookie;
	dxp->ndescs = 1;
	dxp->packed_last_id = last_id;
	(void)vq_validate_segments(sg, readable, writable,
	    &dxp->writable_len);
	vq->vq_free_cnt--;
	vq->vq_queued_cnt++;
	vq_packed_advance(vq, &vq->vq_packed_next_avail,
	    &vq->vq_packed_avail_wrap, 1);
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	atomic_store_rel_16(&desc->flags, vq_packed_desc_flags(vq, wrap,
	    VRING_DESC_F_INDIRECT));
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	return (0);
}

static void *
vq_packed_dequeue(struct virtqueue *vq, uint32_t *len)
{
	struct vq_desc_extra *dxp;
	struct vring_packed_desc *desc;
	void *cookie;
	uint32_t used_len;
	uint16_t head, id, ndescs;

	head = vq->vq_packed_next_used;
	if (!vq_packed_more_used(vq))
		return (NULL);
	desc = &vq->vq_packed_desc[head];
	if (vq_in_order(vq)) {
		if (vq->vq_in_order_batch_last == VQ_RING_DESC_CHAIN_END) {
			rmb();
			id = vq_htog16(vq, atomic_load_16(&desc->id));
			used_len = vq_htog32(vq,
			    atomic_load_32(&desc->len));
			if (!vq_in_order_batch_load(vq, id, used_len,
			    vq->vq_nentries)) {
				vq_mark_broken(vq,
				    "unreachable packed IN_ORDER batch marker");
				return (NULL);
			}
		}
		id = head;
	} else {
		rmb();
		id = vq_htog16(vq, atomic_load_16(&desc->id));
		if (id >= vq->vq_nentries) {
			vq_mark_broken(vq,
			    "packed completion identifier is out of range");
			return (NULL);
		}
	}
	dxp = &vq->vq_descx[id];
	cookie = dxp->cookie;
	ndescs = dxp->ndescs;
	if (cookie == NULL || ndescs == 0) {
		vq_mark_broken(vq,
		    "packed completion does not name a live buffer");
		return (NULL);
	}
	if (vq_in_order(vq) && id != vq->vq_in_order_batch_last)
		used_len = dxp->writable_len;
	else if (vq_in_order(vq)) {
		used_len = vq->vq_in_order_batch_len;
		vq->vq_in_order_batch_last = VQ_RING_DESC_CHAIN_END;
		vq->vq_in_order_batch_len = 0;
	} else
		used_len = vq_htog32(vq, atomic_load_32(&desc->len));
	if (used_len > dxp->writable_len) {
		vq_mark_broken(vq,
		    "packed used length exceeds writable capacity");
		return (NULL);
	}
	if (len != NULL)
		*len = used_len;
	dxp->cookie = NULL;
	vq->vq_free_cnt += ndescs;
	vq_packed_advance(vq, &vq->vq_packed_next_used,
	    &vq->vq_packed_used_wrap, ndescs);
	if (vq_in_order(vq)) {
		dxp->ndescs = 0;
		dxp->writable_len = 0;
		vq->vq_in_order_next_used = vq->vq_packed_next_used;
	} else
		vq_packed_free_ids(vq, id);
	return (cookie);
}

static void
vq_ring_update_avail(struct virtqueue *vq, uint16_t desc_idx)
{
	uint16_t avail_idx, avail_ring_idx;

	/*
	 * Place the head of the descriptor chain into the next slot and make
	 * it usable to the host. The chain is made available now rather than
	 * deferring to virtqueue_notify() in the hopes that if the host is
	 * currently running on another CPU, we can keep it processing the new
	 * descriptor.
	 */
	avail_idx = vq_htog16(vq, vq->vq_ring.avail->idx);
	avail_ring_idx = avail_idx & (vq->vq_nentries - 1);
	vq->vq_ring.avail->ring[avail_ring_idx] = vq_gtoh16(vq, desc_idx);

	wmb();
	vq->vq_ring.avail->idx = vq_gtoh16(vq, avail_idx + 1);

	/* Keep pending count until virtqueue_notify(). */
	vq->vq_queued_cnt++;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
}

static uint16_t
vq_ring_enqueue_segments(struct virtqueue *vq, struct vring_desc *desc,
    uint16_t head_idx, struct sglist *sg, int readable, int writable)
{
	struct sglist_seg *seg;
	struct vring_desc *dp;
	int i, needed;
	uint16_t idx;

	SDT_PROBE6(virtqueue, , enqueue_segments, entry, vq, desc, head_idx,
	    sg, readable, writable);

	needed = readable + writable;

	for (i = 0, idx = head_idx, seg = sg->sg_segs;
	     i < needed;
	     i++, idx = vq_htog16(vq, dp->next), seg++) {
		VQASSERT(vq, idx != VQ_RING_DESC_CHAIN_END,
		    "premature end of free desc chain");

		dp = &desc[idx];
		dp->addr = vq_gtoh64(vq, seg->ss_paddr);
		dp->len = vq_gtoh32(vq, seg->ss_len);
		dp->flags = 0;

		if (i < needed - 1)
			dp->flags |= vq_gtoh16(vq, VRING_DESC_F_NEXT);
		if (i >= readable)
			dp->flags |= vq_gtoh16(vq, VRING_DESC_F_WRITE);
	}

	SDT_PROBE1(virtqueue, , enqueue_segments, return, idx);
	return (idx);
}

static bool
vq_ring_use_indirect(struct virtqueue *vq, int needed)
{

	if ((vq->vq_flags & VIRTQUEUE_FLAG_INDIRECT) == 0)
		return (false);

	if (vq->vq_max_indirect_size < needed)
		return (false);

	if (needed < 2)
		return (false);

	return (true);
}

static void
vq_ring_enqueue_indirect(struct virtqueue *vq, void *cookie,
    struct sglist *sg, int readable, int writable)
{
	struct vring_desc *dp;
	struct vq_desc_extra *dxp;
	int needed;
	uint16_t head_idx;

	needed = readable + writable;
	VQASSERT(vq, needed <= vq->vq_max_indirect_size,
	    "enqueuing too many indirect descriptors");

	head_idx = vq->vq_desc_head_idx;
	VQ_RING_ASSERT_VALID_IDX(vq, head_idx);
	dp = &vq->vq_ring.desc[head_idx];
	dxp = &vq->vq_descx[head_idx];

	VQASSERT(vq, dxp->cookie == NULL,
	    "cookie already exists for index %d", head_idx);
	dxp->cookie = cookie;
	dxp->ndescs = 1;
	(void)vq_validate_segments(sg, readable, writable,
	    &dxp->writable_len);

	dp->addr = vq_gtoh64(vq, dxp->indirect_paddr);
	dp->len = vq_gtoh32(vq, needed * sizeof(struct vring_desc));
	dp->flags = vq_gtoh16(vq, VRING_DESC_F_INDIRECT);

	vq_ring_enqueue_segments(vq, dxp->indirect, 0,
	    sg, readable, writable);

	bus_dmamap_sync(vq->vq_indirect_dmat, dxp->mapp, BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);

	vq->vq_desc_head_idx = vq_htog16(vq, dp->next);
	vq->vq_free_cnt--;
	if (vq->vq_free_cnt == 0 && !vq_in_order(vq))
		VQ_RING_ASSERT_CHAIN_TERM(vq);
	else if (vq->vq_free_cnt != 0)
		VQ_RING_ASSERT_VALID_IDX(vq, vq->vq_desc_head_idx);

	vq_ring_update_avail(vq, head_idx);
}

static int
vq_ring_enable_interrupt(struct virtqueue *vq, uint16_t ndesc)
{
	uint16_t offset;
	bool wrap;

	/* A failed queue stays quiesced until explicit reinitialization. */
	if (vq_is_broken(vq))
		return (0);

	if (vq_packed(vq)) {
		offset = vq->vq_packed_next_used;
		wrap = vq->vq_packed_used_wrap;
		vq_packed_advance(vq, &offset, &wrap,
		    MIN(ndesc, vq_packed_outstanding(vq)));
		vq->vq_packed_driver_event->off_wrap = vq_gtoh16(vq,
		    vring_packed_off_wrap(offset, wrap));
		atomic_store_rel_16(&vq->vq_packed_driver_event->flags,
		    vq_gtoh16(vq,
		    (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) != 0 ?
		    VRING_PACKED_EVENT_FLAG_DESC :
		    VRING_PACKED_EVENT_FLAG_ENABLE));
		bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
		    BUS_DMASYNC_PREWRITE);
		/*
		 * Publish the event-suppression update before rechecking the
		 * packed ring on every architecture.  The second observation is
		 * what closes the enable-versus-completion race, so restricting
		 * this barrier to strongly ordered hosts can lose an interrupt.
		 */
		mb();
		if (vq_is_broken(vq)) {
			virtqueue_disable_intr(vq);
			return (0);
		}
		bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
		    BUS_DMASYNC_POSTREAD);
		/* Any observed completion closes the arm-versus-use race. */
		return (vq_packed_more_used(vq));
	}

	/*
	 * Enable interrupts, making sure we get the latest index of
	 * what's already been consumed.
	 */
	if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) {
		vring_used_event(&vq->vq_ring) =
		    vq_gtoh16(vq, vq->vq_used_cons_idx + ndesc);
	} else {
		vq->vq_ring.avail->flags &=
		    vq_gtoh16(vq, ~VRING_AVAIL_F_NO_INTERRUPT);
	}

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
	/*
	 * Publish the event suppression update before rechecking the ring on
	 * every supported architecture.
	 */
	mb();
	if (vq_is_broken(vq)) {
		virtqueue_disable_intr(vq);
		return (0);
	}

	/*
	 * Enough items may have already been consumed to meet our threshold
	 * since we last checked. Let our caller know so it processes the new
	 * entries.
	 */
	if (virtqueue_nused(vq) > ndesc)
		return (1);

	return (0);
}

static int
vq_ring_must_notify_host(struct virtqueue *vq)
{
	uint16_t new_idx, prev_idx, event_idx, flags;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_POSTREAD);

	if (vq_packed(vq)) {
		flags = vq_htog16(vq, atomic_load_acq_16(
		    &vq->vq_packed_device_event->flags));
		if (flags == VRING_PACKED_EVENT_FLAG_DISABLE)
			return (0);
		if (flags == VRING_PACKED_EVENT_FLAG_ENABLE ||
		    (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) == 0)
			return (1);
		if (flags != VRING_PACKED_EVENT_FLAG_DESC)
			return (1);

		event_idx = vq_htog16(vq, atomic_load_16(
		    &vq->vq_packed_device_event->off_wrap));
		return (vring_packed_need_event(vq->vq_nentries, event_idx,
		    vq->vq_packed_next_avail, vq->vq_packed_avail_wrap,
		    vq->vq_queued_cnt));
	}

	if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) {
		new_idx = vq_htog16(vq, vq->vq_ring.avail->idx);
		prev_idx = new_idx - vq->vq_queued_cnt;
		event_idx = vq_htog16(vq, vring_avail_event(&vq->vq_ring));

		return (vring_need_event(event_idx, new_idx, prev_idx) != 0);
	}

	flags = vq->vq_ring.used->flags;
	return ((flags & vq_gtoh16(vq, VRING_USED_F_NO_NOTIFY)) == 0);
}

static void
vq_ring_notify_host(struct virtqueue *vq)
{
	uint16_t avail_idx;

	if (vq_packed(vq))
		avail_idx = vring_packed_off_wrap(
		    vq->vq_packed_next_avail, vq->vq_packed_avail_wrap);
	else
		avail_idx = vq_htog16(vq, vq->vq_ring.avail->idx);
	VIRTIO_BUS_NOTIFY_VQ(vq->vq_dev, vq->vq_queue_index,
	    vq->vq_notify_offset, avail_idx);
}

static void
vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
	struct vring_desc *dp;
	struct vq_desc_extra *dxp;

	VQ_RING_ASSERT_VALID_IDX(vq, desc_idx);
	dp = &vq->vq_ring.desc[desc_idx];
	dxp = &vq->vq_descx[desc_idx];

	if (vq->vq_free_cnt == 0 && !vq_in_order(vq))
		VQ_RING_ASSERT_CHAIN_TERM(vq);

	vq->vq_free_cnt += dxp->ndescs;
	dxp->ndescs--;

	if ((dp->flags & vq_gtoh16(vq, VRING_DESC_F_INDIRECT)) == 0) {
		while (dp->flags & vq_gtoh16(vq, VRING_DESC_F_NEXT)) {
			uint16_t next_idx = vq_htog16(vq, dp->next);
			VQ_RING_ASSERT_VALID_IDX(vq, next_idx);
			dp = &vq->vq_ring.desc[next_idx];
			dxp->ndescs--;
		}
	}

	VQASSERT(vq, dxp->ndescs == 0,
	    "failed to free entire desc chain, remaining: %d", dxp->ndescs);
	dxp->writable_len = 0;
	if (vq_in_order(vq))
		return;

	/*
	 * We must append the existing free chain, if any, to the end of
	 * newly freed chain. If the virtqueue was completely used, then
	 * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
	 */
	dp->next = vq_gtoh16(vq, vq->vq_desc_head_idx);
	vq->vq_desc_head_idx = desc_idx;

	bus_dmamap_sync(vq->vq_ring_dmat, vq->vq_ring_mapp,
	    BUS_DMASYNC_PREWRITE);
}

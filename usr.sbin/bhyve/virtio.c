/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 * Copyright (c) 2019 Joyent, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <machine/atomic.h>

#include <dev/virtio/pci/virtio_pci_legacy_var.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <pthread_np.h>

#include "bhyverun.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"

/*
 * Functions for dealing with generalized "virtual devices" as
 * defined by <https://www.google.com/#output=search&q=virtio+spec>
 */

/*
 * In case we decide to relax the "virtio softc comes at the
 * front of virtio-based device softc" constraint, let's use
 * this to convert.
 */
#define	DEV_SOFTC(vs) ((void *)(vs))

/*
 * Link a virtio_softc to its constants, the device softc, and
 * the PCI emulation.
 */
void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
		void *dev_softc, struct pci_devinst *pi,
		struct vqueue_info *queues)
{
	int i;

	/* vs and dev_softc addresses must match */
	assert((void *)vs == dev_softc);
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	pi->pi_arg = vs;

	vs->vs_queues = queues;
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	for (i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

/*
 * Reset device (device-wide).  This erases all queues, i.e.,
 * all the queues become invalid (though we don't wipe out the
 * internal pointers, we just clear the VQ_ALLOC flag).
 *
 * It resets negotiated features to "none".
 *
 * If MSI-X is enabled, this also resets all the vectors to NO_VECTOR.
 */
void
vi_reset_dev(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	int i, nvq;

	if (vs->vs_mtx)
		assert(pthread_mutex_isowned_np(vs->vs_mtx));

	nvq = vs->vs_vc->vc_nvq;
	for (vq = vs->vs_queues, i = 0; i < nvq; vq++, i++) {
		vq->vq_flags = 0;
		vq->vq_last_avail = 0;
		vq->vq_next_used = 0;
		vq->vq_save_used = 0;
		vq->vq_pfn = 0;
		vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	}
	vs->vs_negotiated_caps = 0;
	vs->vs_curq = 0;
	/* vs->vs_status = 0; -- redundant */
	(void)vi_isr_read(vs);
	vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	vi_pci_modern_reset(vs);
}

void
vi_pci_notify_queue(struct virtio_softc *vs, uint64_t qidx)
{
	struct vqueue_info *vq;
	struct virtio_consts *vc;

	vc = vs->vs_vc;
	if (qidx >= (unsigned int)vc->vc_nvq) {
		EPRINTLN("%s: queue %ju notify out of range", vc->vc_name,
		    (uintmax_t)qidx);
		return;
	}
	vq = &vs->vs_queues[qidx];
	if (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN &&
	    (!vq->vq_enabled ||
	    (vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0))
		return;
	/* A malformed ring is fatal until the driver performs a real reset. */
	if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	if (vq->vq_notify != NULL)
		(*vq->vq_notify)(DEV_SOFTC(vs), vq);
	else if (vc->vc_qnotify != NULL)
		(*vc->vc_qnotify)(DEV_SOFTC(vs), vq);
	else
		EPRINTLN("%s: qnotify queue %ju: missing vq/vc notify",
		    vc->vc_name, (uintmax_t)qidx);
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		vi_interrupt(vs, VIRTIO_PCI_ISR_CONFIG, vs->vs_msix_cfg_idx);
}

/*
 * Set I/O BAR (usually 0) to map PCI config registers.
 */
void
vi_set_io_bar(struct virtio_softc *vs, int barnum)
{
	size_t size;

	/*
	 * ??? should we use VIRTIO_PCI_CONFIG_OFF(0) if MSI-X is disabled?
	 * Existing code did not...
	 */
	size = VIRTIO_PCI_CONFIG_OFF(1) + vs->vs_vc->vc_cfgsize;
	pci_emul_alloc_bar(vs->vs_pi, barnum, PCIBAR_IO, size);
}

/*
 * Initialize interrupt-state serialization and MSI-X vector capabilities if
 * we're to use MSI-X, or MSI capabilities if not.
 *
 * We assume we want one MSI-X vector per queue, here, plus one
 * for the config vec.
 */
int
vi_intr_init(struct virtio_softc *vs, int barnum, int use_msix)
{
	int nvec;

	if (pthread_mutex_init(&vs->vs_isr_mtx, NULL) != 0)
		return (1);

	if (use_msix) {
		vs->vs_flags |= VIRTIO_USE_MSIX;
		VS_LOCK(vs);
		vi_reset_dev(vs); /* set all vectors to NO_VECTOR */
		VS_UNLOCK(vs);
		nvec = vs->vs_vc->vc_nvq + 1;
		if (pci_emul_add_msixcap(vs->vs_pi, nvec, barnum)) {
			pthread_mutex_destroy(&vs->vs_isr_mtx);
			return (1);
		}
	} else
		vs->vs_flags &= ~VIRTIO_USE_MSIX;

	/* Only 1 MSI vector for bhyve */
	pci_emul_add_msicap(vs->vs_pi, 1);

	/* Legacy interrupts are mandatory for virtio devices */
	pci_lintr_request(vs->vs_pi);

	return (0);
}

/*
 * Initialize the currently-selected virtio queue (vs->vs_curq).
 * The guest just gave us a page frame number, from which we can
 * calculate the addresses of the queue.
 */
static void
vi_vq_init(struct virtio_softc *vs, uint32_t pfn)
{
	struct vqueue_info *vq;
	uint64_t phys;
	size_t size;
	char *base;

	vq = &vs->vs_queues[vs->vs_curq];
	if (pfn == 0) {
		vq->vq_flags = 0;
		vq->vq_pfn = 0;
		vq->vq_desc = NULL;
		vq->vq_avail = NULL;
		vq->vq_used = NULL;
		vq->vq_last_avail = 0;
		vq->vq_next_used = 0;
		vq->vq_save_used = 0;
		return;
	}
	phys = (uint64_t)pfn << VRING_PFN;
	size = vring_size_aligned(vq->vq_qsize);
	base = paddr_guest2host(vs->vs_pi->pi_vmctx, phys, size);
	if (base == NULL) {
		EPRINTLN("%s: virtqueue %u maps outside guest memory",
		    vs->vs_vc->vc_name, vq->vq_num);
		vq->vq_flags = 0;
		vq->vq_pfn = 0;
		vq->vq_desc = NULL;
		vq->vq_avail = NULL;
		vq->vq_used = NULL;
		vq->vq_last_avail = 0;
		vq->vq_next_used = 0;
		vq->vq_save_used = 0;
		vi_set_needs_reset(vs);
		return;
	}
	vq->vq_pfn = pfn;

	/* First page(s) are descriptors... */
	vq->vq_desc = (struct vring_desc *)base;
	base += vq->vq_qsize * sizeof(struct vring_desc);

	/* ... immediately followed by "avail" ring (entirely uint16_t's) */
	vq->vq_avail = (struct vring_avail *)base;
	base += (2 + vq->vq_qsize + 1) * sizeof(uint16_t);

	/* Then it's rounded up to the next page... */
	base = (char *)roundup2((uintptr_t)base, VRING_ALIGN);

	/* ... and the last page(s) are the used ring. */
	vq->vq_used = (struct vring_used *)base;

	/* Mark queue as allocated, and start at 0 when we use it. */
	vq->vq_flags = VQ_ALLOC;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
}

/*
 * Helper inline for vq_getchain(): record the i'th "real"
 * descriptor.
 */
static inline bool
_vq_record(int i, struct vring_desc *vd, struct vmctx *ctx, struct iovec *iov,
    int n_iov, struct vi_req *reqp)
{
	void *base;
	uint32_t len;
	uint64_t addr;

	len = atomic_load_32(&vd->len);
	addr = atomic_load_64(&vd->addr);
	base = paddr_guest2host(ctx, addr, len);
	if (base == NULL)
		return (false);
	if (i < n_iov) {
		iov[i].iov_len = len;
		iov[i].iov_base = base;
	}
	if ((vd->flags & VRING_DESC_F_WRITE) == 0) {
		if (reqp->writable != 0)
			reqp->ordered = false;
		reqp->readable++;
	} else
		reqp->writable++;
	return (true);
}
#define	VQ_MAX_DESCRIPTORS	512	/* see below */

/*
 * Examine the chain of descriptors starting at the "next one" to
 * make sure that they describe a sensible request.  If so, return
 * the number of "real" descriptors that would be needed/used in
 * acting on this request.  This may be smaller than the number of
 * available descriptors, e.g., if there are two available but
 * they are two separate requests, this just returns 1.  Or, it
 * may be larger: if there are indirect descriptors involved,
 * there may only be one descriptor available but it may be an
 * indirect pointing to eight more.  We return 8 in this case,
 * i.e., we do not count the indirect descriptors, only the "real"
 * ones.
 *
 * Basically, this vets the "flags" and "next" field of each
 * descriptor and tells you how many are involved.  Since some may
 * be indirect, this also needs the vmctx (in the pci_devinst
 * at vs->vs_pi) so that it can find indirect descriptors.
 *
 * As we process each descriptor, we copy and adjust it (guest to
 * host address wise, also using the vmtctx) into the given iov[]
 * array (of the given size).  If the array overflows, we stop
 * placing values into the array but keep processing descriptors,
 * up to VQ_MAX_DESCRIPTORS, before giving up and returning -1.
 * So you, the caller, must not assume that iov[] is as big as the
 * return value (you can process the same thing twice to allocate
 * a larger iov array if needed, or supply a zero length to find
 * out how much space is needed).
 *
 * If some descriptor(s) are invalid, this prints a diagnostic message
 * and returns -1.  If no descriptors are ready now it simply returns 0.
 *
 * You are assumed to have done a vq_ring_ready() if needed (note
 * that vq_has_descs() does one).
 */
int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
	    struct vi_req *reqp)
{
	int i;
	u_int ndesc, n_indir;
	u_int idx, next;
	uint64_t chain_len;
	struct vi_req req;
	struct vring_desc *vdir, *vindir, *vp;
	struct vmctx *ctx;
	struct virtio_softc *vs;
	const char *name;

	vs = vq->vq_vs;
	name = vs->vs_vc->vc_name;
	memset(&req, 0, sizeof(req));
	req.ordered = true;
	chain_len = 0;

	/*
	 * Note: it's the responsibility of the guest not to
	 * update vq->vq_avail->idx until all of the descriptors
         * the guest has written are valid (including all their
         * "next" fields and "flags").
	 *
	 * Compute (vq_avail->idx - last_avail) in integers mod 2**16.  This is
	 * the number of descriptors the device has made available
	 * since the last time we updated vq->vq_last_avail.
	 *
	 * We just need to do the subtraction as an unsigned int,
	 * then trim off excess bits.
	 */
	idx = vq->vq_last_avail;
	ndesc = (uint16_t)((u_int)vq->vq_avail->idx - idx);
	if (ndesc == 0)
		return (0);
	if (ndesc > vq->vq_qsize) {
		EPRINTLN(
		    "%s: ndesc (%u) out of range, driver confused?",
		    name, (u_int)ndesc);
		goto bad;
	}

	/*
	 * Now count/parse "involved" descriptors starting from
	 * the head of the chain.
	 *
	 * To prevent loops, we could be more complicated and
	 * check whether we're re-visiting a previously visited
	 * index, but we just abort if the count gets excessive.
	 */
	ctx = vs->vs_pi->pi_vmctx;
	req.idx = next = vq->vq_avail->ring[idx & (vq->vq_qsize - 1)];
	vq->vq_last_avail++;
	for (i = 0; i < VQ_MAX_DESCRIPTORS; next = vdir->next) {
		if (next >= vq->vq_qsize) {
			EPRINTLN(
			    "%s: descriptor index %u out of range, "
			    "driver confused?",
			    name, next);
			goto bad;
		}
		vdir = &vq->vq_desc[next];
		if ((vdir->flags & VRING_DESC_F_INDIRECT) == 0) {
			if (vdir->len > UINT32_MAX - chain_len) {
				EPRINTLN("%s: descriptor chain exceeds 2^32-1 "
				    "bytes", name);
				goto bad;
			}
			chain_len += vdir->len;
			if (!_vq_record(i, vdir, ctx, iov, niov, &req)) {
				EPRINTLN("%s: descriptor maps outside guest memory",
				    name);
				goto bad;
			}
			i++;
		} else if ((vs->vs_negotiated_caps &
		    VIRTIO_RING_F_INDIRECT_DESC) == 0) {
			EPRINTLN(
			    "%s: descriptor has forbidden INDIRECT flag, "
			    "driver confused?",
			    name);
			goto bad;
		} else {
			if ((vdir->flags & VRING_DESC_F_NEXT) != 0) {
				EPRINTLN("%s: descriptor has both INDIRECT and NEXT "
				    "flags", name);
				goto bad;
			}
			n_indir = vdir->len / 16;
			if ((vdir->len & 0xf) || n_indir == 0) {
				EPRINTLN(
				    "%s: invalid indir len 0x%x, "
				    "driver confused?",
				    name, (u_int)vdir->len);
				goto bad;
			}
			vindir = paddr_guest2host(ctx,
			    vdir->addr, vdir->len);
			if (vindir == NULL) {
				EPRINTLN("%s: indirect descriptor table maps outside "
				    "guest memory", name);
				goto bad;
			}
			/*
			 * Indirects start at the 0th, then follow
			 * their own embedded "next"s until those run
			 * out.  Each one's indirect flag must be off
			 * (we don't really have to check, could just
			 * ignore errors...).
			 */
			next = 0;
			for (;;) {
				vp = &vindir[next];
				if (vp->flags & VRING_DESC_F_INDIRECT) {
					EPRINTLN(
					    "%s: indirect desc has INDIR flag,"
					    " driver confused?",
					    name);
					goto bad;
				}
				if (vp->len > UINT32_MAX - chain_len) {
					EPRINTLN("%s: indirect descriptor chain "
					    "exceeds 2^32-1 bytes", name);
					goto bad;
				}
				chain_len += vp->len;
				if (!_vq_record(i, vp, ctx, iov, niov, &req)) {
					EPRINTLN("%s: indirect descriptor maps "
					    "outside guest memory", name);
					goto bad;
				}
				if (++i > VQ_MAX_DESCRIPTORS)
					goto loopy;
				if ((vp->flags & VRING_DESC_F_NEXT) == 0)
					break;
				next = vp->next;
				if (next >= n_indir) {
					EPRINTLN(
					    "%s: invalid next %u > %u, "
					    "driver confused?",
					    name, (u_int)next, n_indir);
					goto bad;
				}
			}
		}
		if ((vdir->flags & VRING_DESC_F_NEXT) == 0)
			goto done;
	}

loopy:
	EPRINTLN(
	    "%s: descriptor loop? count > %d - driver confused?",
	    name, i);

bad:
	vi_set_needs_reset(vs);
	return (-1);

done:
	*reqp = req;
	return (i);
}

/*
 * Return the first n_chain request chains back to the available queue.
 *
 * (These chains are the ones you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_retchains(struct vqueue_info *vq, uint16_t n_chains)
{

	vq->vq_last_avail -= n_chains;
}

void
vq_relchain_prepare(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	struct vring_used *vuh;
	struct vring_used_elem *vue;
	uint16_t mask;

	/*
	 * Notes:
	 *  - mask is N-1 where N is a power of 2 so computes x % N
	 *  - vuh points to the "used" data shared with guest
	 *  - vue points to the "used" ring entry we want to update
	 */
	mask = vq->vq_qsize - 1;
	vuh = vq->vq_used;

	vue = &vuh->ring[vq->vq_next_used++ & mask];
	vue->id = idx;
	vue->len = iolen;
}

void
vq_relchain_publish(struct vqueue_info *vq)
{
	/*
	 * Ensure the used descriptor is visible before updating the index.
	 * This is necessary on ISAs with memory ordering less strict than x86
	 * (and even on x86 to act as a compiler barrier).
	 */
	atomic_thread_fence_rel();
	vq->vq_used->idx = vq->vq_next_used;
}

/*
 * Return specified request chain to the guest, setting its I/O length
 * to the provided value.
 *
 * (This chain is the one you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	vq_relchain_prepare(vq, idx, iolen);
	vq_relchain_publish(vq);
}

/*
 * Driver has finished processing "available" chains and calling
 * vq_relchain on each one.  If driver used all the available
 * chains, used_all should be set.
 *
 * If the "used" index moved we may need to inform the guest, i.e.,
 * deliver an interrupt.  Even if the used index did NOT move we
 * may need to deliver an interrupt, if the avail ring is empty and
 * we are supposed to interrupt on empty.
 *
 * Note that used_all_avail is provided by the caller because it's
 * a snapshot of the ring state when he decided to finish interrupt
 * processing -- it's possible that descriptors became available after
 * that point.  (It's also typically a constant 1/True as well.)
 */
void
vq_endchains(struct vqueue_info *vq, int used_all_avail)
{
	struct virtio_softc *vs;
	uint16_t event_idx, new_idx, old_idx;
	int intr;

	/*
	 * Interrupt generation: if we're using EVENT_IDX,
	 * interrupt if we've crossed the event threshold.
	 * Otherwise interrupt is generated if we added "used" entries,
	 * but suppressed by VRING_AVAIL_F_NO_INTERRUPT.
	 *
	 * In any case, though, if NOTIFY_ON_EMPTY is set and the
	 * entire avail was processed, we need to interrupt always.
	 */
	vs = vq->vq_vs;
	old_idx = vq->vq_save_used;
	vq->vq_save_used = new_idx = vq->vq_used->idx;

	/*
	 * Use full memory barrier between "idx" store from preceding
	 * vq_relchain() call and the loads from VQ_USED_EVENT_IDX() or
	 * "flags" field below.
	 */
	atomic_thread_fence_seq_cst();
	if (used_all_avail &&
	    (vs->vs_negotiated_caps & VIRTIO_F_NOTIFY_ON_EMPTY))
		intr = 1;
	else if (vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) {
		event_idx = VQ_USED_EVENT_IDX(vq);
		/*
		 * This calculation is per docs and the kernel
		 * (see src/sys/dev/virtio/virtio_ring.h).
		 */
		intr = (uint16_t)(new_idx - event_idx - 1) <
			(uint16_t)(new_idx - old_idx);
	} else {
		intr = new_idx != old_idx &&
		    !(vq->vq_avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
	}
	if (intr)
		vq_interrupt(vs, vq);
}

/* Note: these are in sorted order to make for a fast search */
static struct config_reg {
	uint16_t	cr_offset;	/* register offset */
	uint8_t		cr_size;	/* size (bytes) */
	uint8_t		cr_ro;		/* true => reg is read only */
	const char	*cr_name;	/* name of reg */
} config_regs[] = {
	{ VIRTIO_PCI_HOST_FEATURES,	4, 1, "HOST_FEATURES" },
	{ VIRTIO_PCI_GUEST_FEATURES,	4, 0, "GUEST_FEATURES" },
	{ VIRTIO_PCI_QUEUE_PFN,		4, 0, "QUEUE_PFN" },
	{ VIRTIO_PCI_QUEUE_NUM,		2, 1, "QUEUE_NUM" },
	{ VIRTIO_PCI_QUEUE_SEL,		2, 0, "QUEUE_SEL" },
	{ VIRTIO_PCI_QUEUE_NOTIFY,	2, 0, "QUEUE_NOTIFY" },
	{ VIRTIO_PCI_STATUS,		1, 0, "STATUS" },
	{ VIRTIO_PCI_ISR,		1, 0, "ISR" },
	{ VIRTIO_MSI_CONFIG_VECTOR,	2, 0, "CONFIG_VECTOR" },
	{ VIRTIO_MSI_QUEUE_VECTOR,	2, 0, "QUEUE_VECTOR" },
};

static inline struct config_reg *
vi_find_cr(int offset) {
	u_int hi, lo, mid;
	struct config_reg *cr;

	lo = 0;
	hi = sizeof(config_regs) / sizeof(*config_regs) - 1;
	while (hi >= lo) {
		mid = (hi + lo) >> 1;
		cr = &config_regs[mid];
		if (cr->cr_offset == offset)
			return (cr);
		if (cr->cr_offset < offset)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return (NULL);
}

/*
 * Handle pci config space reads.
 * If it's to the MSI-X info, do that.
 * If it's part of the virtio standard stuff, do that.
 * Otherwise dispatch to the actual driver.
 */
uint64_t
vi_pci_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct virtio_softc *vs = pi->pi_arg;
	struct virtio_consts *vc;
	struct config_reg *cr;
	uint64_t virtio_config_size, max;
	const char *name;
	uint32_t newoff;
	uint32_t value;
	int error;

	if (vs->vs_flags & VIRTIO_USE_MSIX) {
		if (baridx == pci_msix_table_bar(pi) ||
		    baridx == pci_msix_pba_bar(pi)) {
			return (pci_emul_msix_tread(pi, offset, size));
		}
	}
	if (vi_pci_is_modern(vs))
		return (vi_pci_modern_read(pi, baridx, offset, size));

	/* XXX probably should do something better than just assert() */
	assert(baridx == 0);

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	vc = vs->vs_vc;
	name = vc->vc_name;
	value = size == 1 ? 0xff : size == 2 ? 0xffff : 0xffffffff;

	if (size != 1 && size != 2 && size != 4)
		goto bad;

	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to underlying driver.
		 * If that fails, fall into general code.
		 */
		newoff = offset - virtio_config_size;
		max = vc->vc_cfgsize ? vc->vc_cfgsize : 0x100000000;
		if (newoff + size > max)
			goto bad;
		if (vc->vc_cfgread != NULL)
			error = (*vc->vc_cfgread)(DEV_SOFTC(vs), newoff, size, &value);
		else
			error = 0;
		if (!error)
			goto done;
	}

bad:
	cr = vi_find_cr(offset);
	if (cr == NULL || cr->cr_size != size) {
		if (cr != NULL) {
			/* offset must be OK, so size must be bad */
			EPRINTLN(
			    "%s: read from %s: bad size %d",
			    name, cr->cr_name, size);
		} else {
			EPRINTLN(
			    "%s: read from bad offset/size %jd/%d",
			    name, (uintmax_t)offset, size);
		}
		goto done;
	}

	switch (offset) {
	case VIRTIO_PCI_HOST_FEATURES:
		value = vc->vc_hv_caps;
		break;
	case VIRTIO_PCI_GUEST_FEATURES:
		value = vs->vs_negotiated_caps;
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		if (vs->vs_curq < vc->vc_nvq)
			value = vs->vs_queues[vs->vs_curq].vq_pfn;
		break;
	case VIRTIO_PCI_QUEUE_NUM:
		value = vs->vs_curq < vc->vc_nvq ?
		    vs->vs_queues[vs->vs_curq].vq_qsize : 0;
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		value = vs->vs_curq;
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		value = 0;	/* XXX */
		break;
	case VIRTIO_PCI_STATUS:
		value = vs->vs_status;
		break;
	case VIRTIO_PCI_ISR:
		value = vi_isr_read(vs);
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		value = vs->vs_msix_cfg_idx;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		value = vs->vs_curq < vc->vc_nvq ?
		    vs->vs_queues[vs->vs_curq].vq_msix_idx :
		    VIRTIO_MSI_NO_VECTOR;
		break;
	}
done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);
	return (value);
}

/*
 * Handle pci config space writes.
 * If it's to the MSI-X info, do that.
 * If it's part of the virtio standard stuff, do that.
 * Otherwise dispatch to the actual driver.
 */
void
vi_pci_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct virtio_softc *vs = pi->pi_arg;
	struct vqueue_info *vq;
	struct virtio_consts *vc;
	struct config_reg *cr;
	uint64_t virtio_config_size, max;
	const char *name;
	uint32_t newoff;
	uint8_t old_status;
	int error;

	if (vs->vs_flags & VIRTIO_USE_MSIX) {
		if (baridx == pci_msix_table_bar(pi) ||
		    baridx == pci_msix_pba_bar(pi)) {
			pci_emul_msix_twrite(pi, offset, size, value);
			return;
		}
	}
	if (vi_pci_is_modern(vs)) {
		vi_pci_modern_write(pi, baridx, offset, size, value);
		return;
	}

	/* XXX probably should do something better than just assert() */
	assert(baridx == 0);

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	vc = vs->vs_vc;
	name = vc->vc_name;

	if (size != 1 && size != 2 && size != 4)
		goto bad;

	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to underlying driver.
		 */
		newoff = offset - virtio_config_size;
		max = vc->vc_cfgsize ? vc->vc_cfgsize : 0x100000000;
		if (newoff + size > max)
			goto bad;
		if (vc->vc_cfgwrite != NULL)
			error = (*vc->vc_cfgwrite)(DEV_SOFTC(vs), newoff, size, value);
		else
			error = 0;
		if (!error)
			goto done;
	}

bad:
	cr = vi_find_cr(offset);
	if (cr == NULL || cr->cr_size != size || cr->cr_ro) {
		if (cr != NULL) {
			/* offset must be OK, wrong size and/or reg is R/O */
			if (cr->cr_size != size)
				EPRINTLN(
				    "%s: write to %s: bad size %d",
				    name, cr->cr_name, size);
			if (cr->cr_ro)
				EPRINTLN(
				    "%s: write to read-only reg %s",
				    name, cr->cr_name);
		} else {
			EPRINTLN(
			    "%s: write to bad offset/size %jd/%d",
			    name, (uintmax_t)offset, size);
		}
		goto done;
	}

	switch (offset) {
	case VIRTIO_PCI_GUEST_FEATURES:
		vs->vs_negotiated_caps = value & vc->vc_hv_caps;
		if (vc->vc_apply_features)
			(*vc->vc_apply_features)(DEV_SOFTC(vs),
			    vs->vs_negotiated_caps);
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		vi_vq_init(vs, value);
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		/*
		 * Note that the guest is allowed to select an
		 * invalid queue; we just need to return a QNUM
		 * of 0 while the bad queue is selected.
		 */
		vs->vs_curq = value;
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		vi_pci_notify_queue(vs, value);
		break;
	case VIRTIO_PCI_STATUS:
		old_status = vs->vs_status;
		if (value != 0)
			value |= old_status & VIRTIO_CONFIG_S_NEEDS_RESET;
		vs->vs_status = value;
		if (value == 0)
			(*vc->vc_reset)(DEV_SOFTC(vs));
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		vs->vs_msix_cfg_idx = value;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		vq = &vs->vs_queues[vs->vs_curq];
		vq->vq_msix_idx = value;
		break;
	}
	goto done;

bad_qindex:
	EPRINTLN(
	    "%s: write config reg %s: curq %d >= max %d",
	    name, cr->cr_name, vs->vs_curq, vc->vc_nvq);
done:
	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);
}

#ifdef BHYVE_SNAPSHOT
int
vi_pci_pause(struct pci_devinst *pi)
{
	struct virtio_softc *vs;
	struct virtio_consts *vc;

	vs = pi->pi_arg;
	vc = vs->vs_vc;

	vc = vs->vs_vc;
	assert(vc->vc_pause != NULL);
	(*vc->vc_pause)(DEV_SOFTC(vs));

	return (0);
}

int
vi_pci_resume(struct pci_devinst *pi)
{
	struct virtio_softc *vs;
	struct virtio_consts *vc;

	vs = pi->pi_arg;
	vc = vs->vs_vc;

	vc = vs->vs_vc;
	assert(vc->vc_resume != NULL);
	(*vc->vc_resume)(DEV_SOFTC(vs));

	return (0);
}

static int
vi_pci_snapshot_softc(struct virtio_softc *vs, struct vm_snapshot_meta *meta)
{
	int ret;

	SNAPSHOT_VAR_OR_LEAVE(vs->vs_flags, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(vs->vs_negotiated_caps, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(vs->vs_curq, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(vs->vs_status, meta, ret, done);
	VS_ISR_LOCK(vs);
	SNAPSHOT_VAR_OR_LEAVE(vs->vs_isr, meta, ret, done_isr);
done_isr:
	VS_ISR_UNLOCK(vs);
	if (ret != 0)
		goto done;
	SNAPSHOT_VAR_OR_LEAVE(vs->vs_msix_cfg_idx, meta, ret, done);

done:
	return (ret);
}

static int
vi_pci_snapshot_consts(struct virtio_consts *vc, struct vm_snapshot_meta *meta)
{
	int ret;

	SNAPSHOT_VAR_CMP_OR_LEAVE(vc->vc_nvq, meta, ret, done);
	SNAPSHOT_VAR_CMP_OR_LEAVE(vc->vc_cfgsize, meta, ret, done);
	SNAPSHOT_VAR_CMP_OR_LEAVE(vc->vc_hv_caps, meta, ret, done);

done:
	return (ret);
}

static int
vi_pci_snapshot_queues(struct virtio_softc *vs, struct vm_snapshot_meta *meta)
{
	int i;
	int ret;
	struct virtio_consts *vc;
	struct vqueue_info *vq;
	struct vmctx *ctx;
	uint64_t addr_size;

	ctx = vs->vs_pi->pi_vmctx;
	vc = vs->vs_vc;

	/* Save virtio queue info */
	for (i = 0; i < vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];

		SNAPSHOT_VAR_CMP_OR_LEAVE(vq->vq_qsize, meta, ret, done);
		SNAPSHOT_VAR_CMP_OR_LEAVE(vq->vq_num, meta, ret, done);

		SNAPSHOT_VAR_OR_LEAVE(vq->vq_flags, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vq->vq_last_avail, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vq->vq_next_used, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vq->vq_save_used, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vq->vq_msix_idx, meta, ret, done);

		SNAPSHOT_VAR_OR_LEAVE(vq->vq_pfn, meta, ret, done);

		if (!vq_ring_ready(vq))
			continue;

		addr_size = vq->vq_qsize * sizeof(struct vring_desc);
		SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(ctx, vq->vq_desc, addr_size,
			false, meta, ret, done);

		addr_size = (2 + vq->vq_qsize + 1) * sizeof(uint16_t);
		SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(ctx, vq->vq_avail, addr_size,
			false, meta, ret, done);

		addr_size  = (2 + 2 * vq->vq_qsize + 1) * sizeof(uint16_t);
		SNAPSHOT_GUEST2HOST_ADDR_OR_LEAVE(ctx, vq->vq_used, addr_size,
			false, meta, ret, done);

		SNAPSHOT_BUF_OR_LEAVE(vq->vq_desc,
			vring_size_aligned(vq->vq_qsize), meta, ret, done);
	}

done:
	return (ret);
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	int ret;
	struct pci_devinst *pi;
	struct virtio_softc *vs;
	struct virtio_consts *vc;

	pi = meta->dev_data;
	vs = pi->pi_arg;
	vc = vs->vs_vc;
	/* The existing serializer describes only bhyve's legacy transport. */
	if (vi_pci_is_modern(vs))
		return (EOPNOTSUPP);

	/* Save virtio softc */
	ret = vi_pci_snapshot_softc(vs, meta);
	if (ret != 0)
		goto done;

	/* Save virtio consts */
	ret = vi_pci_snapshot_consts(vc, meta);
	if (ret != 0)
		goto done;

	/* Save virtio queue info */
	ret = vi_pci_snapshot_queues(vs, meta);
	if (ret != 0)
		goto done;

	/* Save device softc, if needed */
	if (vc->vc_snapshot != NULL) {
		ret = (*vc->vc_snapshot)(DEV_SOFTC(vs), meta);
		if (ret != 0)
			goto done;
	}

done:
	return (ret);
}
#endif

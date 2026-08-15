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
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <machine/atomic.h>

#include <dev/virtio/pci/virtio_pci_legacy_var.h>

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <pthread_np.h>
#include <unistd.h>

#include "bhyverun.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_admin_pci.h"
#include "virtio_pci_modern_probes.h"

/* VIRTIO_ACTIVATION_ASSERTION: transport-descriptor-chain */
/* VIRTIO_ACTIVATION_ASSERTION: transport-event-idx */

/*
 * Keep incremental bhyve-only builds working when the installed vmmapi
 * header predates the matching source/library declaration.  A buildworld
 * sees the same compatible prototype through vmmapi.h.
 */
vm_paddr_t vm_rev_map_gpa(struct vmctx *, void *);

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

static void *
vi_pci_map_dma(void *arg, uint64_t address, size_t len,
    enum virtio_dma_direction direction __unused)
{
	struct pci_devinst *pi;

	pi = arg;
	return (paddr_guest2host(pi->pi_vmctx, address, len));
}

static size_t
vi_pci_ram_page_size(void *arg __unused)
{

	return ((size_t)getpagesize());
}

static int
vi_pci_reverse_ram(void *arg, void *mapping, size_t len, uint64_t *address)
{
	struct pci_devinst *pi;
	vm_paddr_t gpa;

	if (mapping == NULL || len == 0 || address == NULL)
		return (EINVAL);
	pi = arg;
	gpa = vm_rev_map_gpa(pi->pi_vmctx, mapping);
	if (gpa == (vm_paddr_t)-1 ||
	    paddr_guest2host(pi->pi_vmctx, gpa, len) != mapping)
		return (EFAULT);
	*address = gpa;
	return (0);
}

static void
vi_pci_mark_dma_dirty(void *arg, void *mapping, size_t len)
{
	const struct pci_dma_dirty_ops *ops;
	struct pci_devinst *pi;
	uint64_t gpa;
	int error;

	if (mapping == NULL || len == 0)
		return;
	pi = arg;
	ops = pi->pi_dma_dirty_ops;
	if (ops == NULL || ops->pddo_mark == NULL)
		return;
	error = vi_pci_reverse_ram(pi, mapping, len, &gpa);
	if (error == 0)
		error = ops->pddo_mark(pi->pi_dma_dirty_arg, gpa, len);
	if (error != 0 && ops->pddo_fail != NULL)
		ops->pddo_fail(pi->pi_dma_dirty_arg, error);
}

static int
vi_pci_discard_ram(void *arg, uint64_t address, size_t len)
{
	struct pci_devinst *pi;
	void *mapping;

	pi = arg;
	mapping = paddr_guest2host(pi->pi_vmctx, address, len);
	if (mapping == NULL)
		return (EFAULT);
	if (madvise(mapping, len, MADV_FREE) != 0)
		return (errno);
	return (0);
}

static int
vi_pci_undiscard_ram(void *arg, uint64_t address, size_t len)
{
	struct pci_devinst *pi;
	void *mapping;

	pi = arg;
	mapping = paddr_guest2host(pi->pi_vmctx, address, len);
	if (mapping == NULL)
		return (EFAULT);
	if (madvise(mapping, len, MADV_WILLNEED) != 0)
		return (errno);
	return (0);
}

static bool
vi_pci_msix_enabled(void *arg)
{

	return (pci_msix_enabled(arg));
}

static void
vi_pci_raise_msix(void *arg, uint16_t vector)
{

	pci_generate_msix(arg, vector);
}

static void
vi_pci_raise_msi(void *arg)
{

	pci_generate_msi(arg, 0);
}

static void
vi_pci_set_intx(void *arg, bool asserted)
{

	if (asserted)
		pci_lintr_assert(arg);
	else
		pci_lintr_deassert(arg);
}

static const struct virtio_platform_ops vi_pci_platform_ops = {
	.vpo_map_dma = vi_pci_map_dma,
	.vpo_reverse_ram = vi_pci_reverse_ram,
	.vpo_mark_dma_dirty = vi_pci_mark_dma_dirty,
	.vpo_ram_page_size = vi_pci_ram_page_size,
	.vpo_discard_ram = vi_pci_discard_ram,
	.vpo_undiscard_ram = vi_pci_undiscard_ram,
	.vpo_msix_enabled = vi_pci_msix_enabled,
	.vpo_raise_msix = vi_pci_raise_msix,
	.vpo_raise_msi = vi_pci_raise_msi,
	.vpo_set_intx = vi_pci_set_intx,
};

struct virtio_softc *
vi_pci_get_softc(struct pci_devinst *pi)
{
	struct virtio_softc *vs;

	if (pi == NULL || pi->pi_d == NULL ||
	    pi->pi_d->pe_barwrite != vi_pci_write)
		return (NULL);
	vs = pi->pi_arg;
	if (vs == NULL || vs->vs_pi != pi)
		return (NULL);
	return (vs);
}

bool
vi_pci_access_platform_eligible(const struct virtio_softc *vs)
{

	return (vs != NULL && vs->vs_vc != NULL && vi_pci_is_modern(vs) &&
	    !vs->vs_vc->vc_access_platform_ineligible);
}

void
vi_set_platform_ops(struct virtio_softc *vs,
    const struct virtio_platform_ops *ops, void *arg)
{

	assert(ops != NULL);
	assert(ops->vpo_map_dma != NULL);
	vs->vs_platform_ops = ops;
	vs->vs_platform_arg = arg;
}

static bool
vi_dma_queues_inactive(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	size_t count;

	count = vi_pci_queue_storage_count(vs);
	for (size_t i = 0; i < count; i++) {
		vq = vi_pci_queue_at(vs, i);
		/*
		 * Queue configuration is deliberately accepted before FEATURES_OK for
		 * compatibility with older guests.  Status can consequently still be
		 * zero while an enabled queue caches translations from the current DMA
		 * address space.  Domain publication is safe because the queue refreshes
		 * mappings against the new generation before use; domain removal has no
		 * replacement translation source and must wait for queue teardown.
		 */
		if (vq == NULL || vq->vq_enabled != 0 || vq_is_allocated(vq) ||
		    vq_is_resetting(vq))
			return (false);
	}
	return (true);
}

int
vi_set_dma_domain(struct virtio_softc *vs,
    const struct virtio_dma_domain_ops *ops, void *arg, uint32_t endpoint)
{
	const struct virtio_dma_domain_ops *installed;
	int error;

	if (vs == NULL || vs->vs_vc == NULL || ops == NULL ||
	    ops->vddo_map == NULL || ops->vddo_generation == NULL ||
	    ((ops->vddo_acquire == NULL) != (ops->vddo_release == NULL)))
		return (EINVAL);
	/*
	 * Modern status writes hold vs_mtx.  Keep the complete publication
	 * transaction under that same lock so a guest cannot start the device
	 * between the inactive-state check and the domain publication below.
	 * vs_dma_detaching separately fences lock-free request lease acquisition.
	 */
	VS_LOCK(vs);
	if (vs->vs_vc->vc_access_platform_ineligible)
		goto unsupported;
	if (vs->vs_transport != VIRTIO_PCI_TRANSPORT_MODERN)
		goto unsupported;
	/*
	 * Serialize publication against both detach and another publisher.
	 * The domain is normally installed during single-threaded device
	 * construction, but this API also backs hot-plug topology plumbing and
	 * must not lose a binding if two lifecycle operations overlap.
	 */
	if (atomic_exchange_explicit(&vs->vs_dma_detaching, true,
	    memory_order_acq_rel)) {
		error = EBUSY;
		goto unlock;
	}
	error = EBUSY;
	installed = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	if (installed != NULL)
		goto done;
	if (atomic_load_explicit(&vs->vs_dma_active_requests,
	    memory_order_acquire) != 0)
		goto done;
	if (atomic_load_explicit(&vs->vs_status, memory_order_acquire) != 0 ||
	    atomic_load_explicit(&vs->vs_resetting, memory_order_acquire) ||
	    atomic_load_explicit(&vs->vs_quiescing, memory_order_acquire) != 0)
		goto done;
	vs->vs_dma_domain_arg = arg;
	vs->vs_dma_endpoint = endpoint;
	vs->vs_dma_access_platform_added =
	    (vs->vs_vc->vc_hv_caps & VIRTIO_F_ACCESS_PLATFORM) == 0;
	vs->vs_vc->vc_hv_caps |= VIRTIO_F_ACCESS_PLATFORM;
	atomic_store_explicit(&vs->vs_dma_domain_ops, ops,
	    memory_order_release);
	error = 0;
done:
	atomic_store_explicit(&vs->vs_dma_detaching, false,
	    memory_order_release);
unlock:
	VS_UNLOCK(vs);
	return (error);

unsupported:
	VS_UNLOCK(vs);
	return (EOPNOTSUPP);
}

static bool
vi_dma_acquire_common(struct virtio_softc *vs, bool *acquired)
{
	const struct virtio_dma_domain_ops *ops;
	uint32_t active, previous;

	if (*acquired)
		return (false);
	/*
	 * Count direct-DMA requests too.  Installing an ACCESS_PLATFORM domain
	 * after status returns to zero must not change the address space under a
	 * completion which was accepted before reset.  The publisher closes
	 * vs_dma_detaching and requires this count to be zero, so increment before
	 * observing the current binding just as the detach path requires.
	 */
	active = atomic_load_explicit(&vs->vs_dma_active_requests,
	    memory_order_acquire);
	do {
		if (active == UINT32_MAX)
			return (false);
	} while (!atomic_compare_exchange_weak_explicit(
	    &vs->vs_dma_active_requests, &active, active + 1,
	    memory_order_acq_rel, memory_order_acquire));
	if (atomic_load_explicit(&vs->vs_dma_detaching,
	    memory_order_acquire)) {
		previous = atomic_fetch_sub_explicit(
		    &vs->vs_dma_active_requests, 1, memory_order_acq_rel);
		assert(previous != 0);
		(void)previous;
		return (false);
	}
	ops = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	/*
	 * Rechecking both values closes publication between the gate check and
	 * binding load.  A NULL binding is a valid direct-DMA lease and remains
	 * stable because domain installation now observes the active count.
	 */
	if (atomic_load_explicit(&vs->vs_dma_detaching,
	    memory_order_acquire) ||
	    atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire) != ops) {
		previous = atomic_fetch_sub_explicit(
		    &vs->vs_dma_active_requests, 1, memory_order_acq_rel);
		assert(previous != 0);
		(void)previous;
		return (false);
	}
	if (ops != NULL && ops->vddo_acquire != NULL &&
	    !ops->vddo_acquire(vs->vs_dma_domain_arg,
	    vs->vs_dma_endpoint)) {
		previous = atomic_fetch_sub_explicit(
		    &vs->vs_dma_active_requests, 1, memory_order_acq_rel);
		assert(previous != 0);
		(void)previous;
		return (false);
	}
	*acquired = true;
	return (true);
}

bool
vi_dma_acquire(struct virtio_softc *vs, struct virtio_dma_lease *lease)
{

	if (vs == NULL || lease == NULL)
		return (false);
	return (vi_dma_acquire_common(vs, &lease->acquired));
}

static bool
vi_req_dma_acquire(struct virtio_softc *vs, struct vi_req *req)
{

	return (vi_dma_acquire_common(vs, &req->dma_acquired));
}

bool
vq_split_owners_empty(const struct vqueue_info *vq)
{

	if (vq->vq_split_owners == NULL)
		return (true);
	for (uint16_t i = 0; i < vq->vq_split_owner_count; i++) {
		if (atomic_load_8(&vq->vq_split_owners[i]) != 0)
			return (false);
	}
	return (true);
}

static int
vq_split_owners_init(struct vqueue_info *vq)
{
	uint8_t *owners;

	if (vq->vq_qsize == 0)
		return (EINVAL);
	if (vq->vq_split_owners != NULL &&
	    vq->vq_split_owner_count >= vq->vq_qsize) {
		if (!vq_split_owners_empty(vq))
			return (EBUSY);
		memset(vq->vq_split_owners, 0, vq->vq_split_owner_count);
		return (0);
	}
	if (!vq_split_owners_empty(vq))
		return (EBUSY);
	owners = calloc(vq->vq_qsize, sizeof(*owners));
	if (owners == NULL)
		return (ENOMEM);
	free(vq->vq_split_owners);
	vq->vq_split_owners = owners;
	vq->vq_split_owner_count = vq->vq_qsize;
	return (0);
}

static bool
vq_split_owner_claim(struct vqueue_info *vq, uint16_t head)
{

	if (vq->vq_split_owners == NULL ||
	    vq->vq_split_owner_count < vq->vq_qsize) {
		if (vq_split_owners_init(vq) != 0)
			return (false);
	}
	if (head >= vq->vq_qsize)
		return (false);
	return (atomic_cmpset_8(&vq->vq_split_owners[head], 0, 1));
}

static bool
vq_split_owner_consume(struct vqueue_info *vq, const struct vi_req *req)
{

	if (req->idx >= vq->vq_qsize || vq->vq_split_owners == NULL ||
	    req->idx >= vq->vq_split_owner_count)
		return (false);
	return (atomic_cmpset_8(&vq->vq_split_owners[req->idx], 1, 0));
}

static uint8_t
vq_packed_owner_state(bool wrap)
{

	return (wrap ? 2 : 1);
}

static bool
vq_packed_owner_claim(struct vqueue_info *vq, uint16_t head, bool wrap)
{
	struct virtio_packed_completion *completion;

	if (head >= vq->vq_qsize || vq->vq_packed_completions == NULL ||
	    vq->vq_packed_completion_count != vq->vq_qsize)
		return (false);
	completion = &vq->vq_packed_completions[head];
	if (completion->valid)
		return (false);
	return (atomic_cmpset_8(&completion->owner_state, 0,
	    vq_packed_owner_state(wrap)));
}

static bool
vq_packed_owner_consume(struct vqueue_info *vq, const struct vi_req *req)
{
	struct virtio_packed_completion *completion;
	uint8_t state;

	if (req->packed_head >= vq->vq_qsize ||
	    vq->vq_packed_completions == NULL ||
	    vq->vq_packed_completion_count != vq->vq_qsize)
		return (false);
	completion = &vq->vq_packed_completions[req->packed_head];
	state = vq_packed_owner_state(req->packed_wrap);
	return (atomic_cmpset_8(&completion->owner_state, state, 0));
}

static bool
vq_request_owner_consume(struct vqueue_info *vq, const struct vi_req *req)
{

	if (req->queue_layout == VIRTIO_QUEUE_PACKED)
		return (vq_packed_owner_consume(vq, req));
	if (req->queue_layout == VIRTIO_QUEUE_SPLIT)
		return (vq_split_owner_consume(vq, req));
	return (false);
}

static void
vi_dma_release_common(struct virtio_softc *vs, bool *acquired)
{
	const struct virtio_dma_domain_ops *ops;
	uint32_t previous;

	if (!*acquired)
		return;
	ops = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	*acquired = false;
	if (ops != NULL && ops->vddo_release != NULL)
		ops->vddo_release(vs->vs_dma_domain_arg,
		    vs->vs_dma_endpoint);
	previous = atomic_fetch_sub_explicit(&vs->vs_dma_active_requests, 1,
	    memory_order_acq_rel);
	assert(previous != 0);
	(void)previous;
}

void
vi_dma_release(struct virtio_softc *vs, struct virtio_dma_lease *lease)
{

	if (vs == NULL || lease == NULL)
		return;
	vi_dma_release_common(vs, &lease->acquired);
}

static void
vi_req_dma_release(struct virtio_softc *vs, struct vi_req *req)
{

	vi_dma_release_common(vs, &req->dma_acquired);
}

int
vi_clear_dma_domain(struct virtio_softc *vs)
{
	const struct virtio_dma_domain_ops *ops;
	int error;

	if (vs == NULL || vs->vs_vc == NULL)
		return (EINVAL);
	/*
	 * vi_modern_status_write() holds vs_mtx for all status transitions.
	 * Serializing removal with it closes the otherwise possible transition
	 * from reset status to DRIVER_OK after the inactive check but before the
	 * domain is cleared.  vs_dma_detaching remains necessary because DMA
	 * lease acquisition deliberately does not take the device mutex.
	 */
	VS_LOCK(vs);
	if (atomic_exchange_explicit(&vs->vs_dma_detaching, true,
	    memory_order_acq_rel)) {
		error = EBUSY;
		goto done;
	}
	if (atomic_load_explicit(&vs->vs_status, memory_order_acquire) != 0 ||
	    atomic_load_explicit(&vs->vs_resetting, memory_order_acquire) ||
	    atomic_load_explicit(&vs->vs_quiescing, memory_order_acquire) != 0 ||
	    !vi_dma_queues_inactive(vs)) {
		error = EBUSY;
		goto reopen;
	}
	ops = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	if (ops == NULL) {
		error = ENOENT;
		goto reopen;
	}
	/*
	 * A completion may still use a domain mapping or need its callbacks
	 * after device status has reached zero.  Keep the domain and callback
	 * table valid until every common-core request lease has been released.
	 */
	if (atomic_load_explicit(&vs->vs_dma_active_requests,
	    memory_order_acquire) != 0) {
		error = EBUSY;
		goto reopen;
	}
	atomic_store_explicit(&vs->vs_dma_domain_ops, NULL,
	    memory_order_release);
	vs->vs_dma_domain_arg = NULL;
	vs->vs_dma_endpoint = 0;
	if (vs->vs_dma_access_platform_added)
		vs->vs_vc->vc_hv_caps &= ~VIRTIO_F_ACCESS_PLATFORM;
	vs->vs_dma_access_platform_added = false;
	error = 0;
reopen:
	atomic_store_explicit(&vs->vs_dma_detaching, false,
	    memory_order_release);
done:
	VS_UNLOCK(vs);
	return (error);
}

void *
vi_map_dma(struct virtio_softc *vs, uint64_t address, size_t len,
    enum virtio_dma_direction direction)
{
	static uint8_t zero_length_dma;
	const struct virtio_dma_domain_ops *ops;
	void *mapping;

	if (len == 0)
		/*
		 * A zero-length descriptor names no guest bytes.  The common
		 * VirtIO descriptor formats do not reserve a zero length, so
		 * neither direct guest-memory validation nor an IOMMU mapping
		 * is required.  Return stable non-NULL storage: callers may
		 * retain it in a zero-length iovec, but must never dereference
		 * it because the corresponding length is zero.
		 */
		return (&zero_length_dma);
	ops = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	if (ops != NULL)
		mapping = ops->vddo_map(vs->vs_dma_domain_arg,
		    vs->vs_dma_endpoint, address, len, direction);
	else if (vs->vs_platform_ops == NULL ||
	    vs->vs_platform_ops->vpo_map_dma == NULL)
		return (NULL);
	else
		mapping = vs->vs_platform_ops->vpo_map_dma(vs->vs_platform_arg,
		    address, len, direction);
	if (mapping != NULL && direction != VIRTIO_DMA_DEVICE_READ)
		vi_mark_dma_dirty(vs, mapping, len);
	return (mapping);
}

/*
 * Refresh cached queue-ring mappings after a revocable DMA domain changes.
 * Payload and indirect-table mappings are request-scoped and already pass
 * through vi_map_dma() for each request.  Queue rings live for the enabled
 * lifetime of a queue, so they need an explicit generation check.
 *
 * Map into temporary pointers and commit only after one stable generation
 * spans all translations.  A guest which continuously mutates its IOMMU
 * mappings cannot make the device spin indefinitely.
 */
static bool
vq_refresh_dma_mappings(struct vqueue_info *vq)
{
	struct virtio_packed_desc *packed_desc;
	struct virtio_packed_event *driver_event, *device_event;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	struct virtio_softc *vs;
	const struct virtio_dma_domain_ops *ops;
	uint64_t before, after;
	size_t desc_size, driver_size, device_size;
	unsigned int attempt;

	vs = vq->vq_vs;
	ops = atomic_load_explicit(&vs->vs_dma_domain_ops,
	    memory_order_acquire);
	if (ops == NULL || ops->vddo_generation == NULL)
		return (true);
	for (attempt = 0; attempt < 4; attempt++) {
		before = ops->vddo_generation(vs->vs_dma_domain_arg);
		if (vq->vq_dma_generation_valid &&
		    vq->vq_dma_generation == before)
			return (true);
		if (vq->vq_qsize == 0)
			break;
		if (vq->vq_layout == VIRTIO_QUEUE_PACKED) {
			desc_size = sizeof(*packed_desc) * vq->vq_qsize;
			packed_desc = vi_map_dma(vs, vq->vq_desc_gpa,
			    desc_size, VIRTIO_DMA_BIDIRECTIONAL);
			driver_event = vi_map_dma(vs, vq->vq_driver_gpa,
			    sizeof(*driver_event), VIRTIO_DMA_DEVICE_READ);
			device_event = vi_map_dma(vs, vq->vq_device_gpa,
			    sizeof(*device_event), VIRTIO_DMA_DEVICE_WRITE);
			after = ops->vddo_generation(vs->vs_dma_domain_arg);
			if (packed_desc == NULL || driver_event == NULL ||
			    device_event == NULL)
				break;
			if (before != after)
				continue;
			vq->vq_packed_desc = packed_desc;
			vq->vq_packed_driver_event = driver_event;
			vq->vq_packed_device_event = device_event;
		} else {
			desc_size = sizeof(*desc) * vq->vq_qsize;
			driver_size = offsetof(struct vring_avail, ring) +
			    sizeof(uint16_t) * vq->vq_qsize;
			device_size = offsetof(struct vring_used, ring) +
			    sizeof(struct vring_used_elem) * vq->vq_qsize;
			if ((vs->vs_negotiated_caps &
			    VIRTIO_RING_F_EVENT_IDX) != 0) {
				driver_size += sizeof(uint16_t);
				device_size += sizeof(uint16_t);
			}
			desc = vi_map_dma(vs, vq->vq_desc_gpa, desc_size,
			    VIRTIO_DMA_DEVICE_READ);
			avail = vi_map_dma(vs, vq->vq_driver_gpa, driver_size,
			    VIRTIO_DMA_DEVICE_READ);
			used = vi_map_dma(vs, vq->vq_device_gpa, device_size,
			    VIRTIO_DMA_DEVICE_WRITE);
			after = ops->vddo_generation(vs->vs_dma_domain_arg);
			if (desc == NULL || avail == NULL || used == NULL)
				break;
			if (before != after)
				continue;
			vq->vq_desc = desc;
			vq->vq_avail = avail;
			vq->vq_used = used;
		}
		vq->vq_dma_generation = before;
		vq->vq_dma_generation_valid = true;
		return (true);
	}
	vi_set_needs_reset(vs);
	return (false);
}

size_t
vi_platform_ram_page_size(struct virtio_softc *vs)
{
	size_t page_size;

	if (vs == NULL || vs->vs_platform_ops == NULL ||
	    vs->vs_platform_ops->vpo_ram_page_size == NULL)
		return (0);
	page_size = vs->vs_platform_ops->vpo_ram_page_size(
	    vs->vs_platform_arg);
	if (page_size == 0 || !powerof2(page_size))
		return (0);
	return (page_size);
}

int
vi_platform_reverse_ram(struct virtio_softc *vs, void *mapping, size_t len,
    uint64_t *address)
{

	if (vs == NULL || vs->vs_platform_ops == NULL ||
	    vs->vs_platform_ops->vpo_reverse_ram == NULL)
		return (EOPNOTSUPP);
	return (vs->vs_platform_ops->vpo_reverse_ram(
	    vs->vs_platform_arg, mapping, len, address));
}

void
vi_mark_dma_dirty(struct virtio_softc *vs, void *mapping, size_t len)
{

	if (vs == NULL || mapping == NULL || len == 0 ||
	    vs->vs_platform_ops == NULL ||
	    vs->vs_platform_ops->vpo_mark_dma_dirty == NULL)
		return;
	vs->vs_platform_ops->vpo_mark_dma_dirty(vs->vs_platform_arg, mapping,
	    len);
}

int
vi_config_read_le(const void *config, size_t config_size, int offset, int size,
    uint32_t *value)
{
	const uint8_t *bytes;

	if (config == NULL || value == NULL || offset < 0 ||
	    (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > config_size ||
	    (size_t)size > config_size - (size_t)offset)
		return (EINVAL);
	bytes = config;
	switch (size) {
	case 1:
		*value = bytes[offset];
		break;
	case 2:
		*value = le16dec(bytes + offset);
		break;
	case 4:
		*value = le32dec(bytes + offset);
		break;
	}
	return (0);
}

static int
vi_platform_ram_range_validate(struct virtio_softc *vs, uint64_t address,
    size_t len)
{
	size_t page_size;

	/*
	 * These helpers are part of the common device-facing platform contract.
	 * Reject a malformed caller before consulting platform callbacks rather
	 * than turning an optional balloon hint into a host-process fault.
	 */
	if (vs == NULL || len == 0 || address > UINT64_MAX - len)
		return (EINVAL);
	page_size = vi_platform_ram_page_size(vs);
	if (page_size == 0 || address % page_size != 0 ||
	    len % page_size != 0)
		return (EINVAL);
	return (0);
}

int
vi_platform_discard_ram(struct virtio_softc *vs, uint64_t address, size_t len)
{
	int error;

	error = vi_platform_ram_range_validate(vs, address, len);
	if (error != 0)
		return (error);
	if (vs->vs_platform_ops->vpo_discard_ram == NULL)
		return (EOPNOTSUPP);
	return (vs->vs_platform_ops->vpo_discard_ram(
	    vs->vs_platform_arg, address, len));
}

int
vi_platform_undiscard_ram(struct virtio_softc *vs, uint64_t address,
    size_t len)
{
	int error;

	error = vi_platform_ram_range_validate(vs, address, len);
	if (error != 0)
		return (error);
	if (vs->vs_platform_ops->vpo_undiscard_ram == NULL)
		return (EOPNOTSUPP);
	return (vs->vs_platform_ops->vpo_undiscard_ram(
	    vs->vs_platform_arg, address, len));
}

bool
vi_platform_msix_enabled(struct virtio_softc *vs)
{

	if (vs == NULL)
		return (false);
	if (vs->vs_platform_ops != NULL &&
	    vs->vs_platform_ops->vpo_msix_enabled != NULL)
		return (vs->vs_platform_ops->vpo_msix_enabled(
		    vs->vs_platform_arg));
	return (vs->vs_pi != NULL && pci_msix_enabled(vs->vs_pi));
}

void
vi_platform_raise_msix(struct virtio_softc *vs, uint16_t vector)
{

	if (vs == NULL)
		return;
	if (vs->vs_platform_ops != NULL &&
	    vs->vs_platform_ops->vpo_raise_msix != NULL)
		vs->vs_platform_ops->vpo_raise_msix(vs->vs_platform_arg, vector);
	else if (vs->vs_pi != NULL)
		pci_generate_msix(vs->vs_pi, vector);
}

void
vi_platform_raise_msi(struct virtio_softc *vs)
{

	if (vs == NULL)
		return;
	if (vs->vs_platform_ops != NULL &&
	    vs->vs_platform_ops->vpo_raise_msi != NULL)
		vs->vs_platform_ops->vpo_raise_msi(vs->vs_platform_arg);
	else if (vs->vs_pi != NULL)
		pci_generate_msi(vs->vs_pi, 0);
}

void
vi_platform_set_intx(struct virtio_softc *vs, bool asserted)
{

	if (vs == NULL)
		return;
	if (vs->vs_platform_ops != NULL &&
	    vs->vs_platform_ops->vpo_set_intx != NULL)
		vs->vs_platform_ops->vpo_set_intx(vs->vs_platform_arg, asserted);
	else if (vs->vs_pi != NULL) {
		if (asserted)
			pci_lintr_assert(vs->vs_pi);
		else
			pci_lintr_deassert(vs->vs_pi);
	}
}

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
	(void)dev_softc;
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vi_set_platform_ops(vs, &vi_pci_platform_ops, pi);
	pi->pi_arg = vs;

	vs->vs_queues = queues;
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	for (i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
		queues[i].vq_layout = VIRTIO_QUEUE_SPLIT;
	}
}

static bool
vi_queue_storage_overlaps(const struct vqueue_info *left, size_t left_count,
    const struct vqueue_info *right, size_t right_count)
{
	uintptr_t left_begin, left_end, right_begin, right_end;
	size_t left_size, right_size;

	if (left == NULL || right == NULL || left_count == 0 || right_count == 0)
		return (false);
	if (__builtin_mul_overflow(left_count, sizeof(*left), &left_size) ||
	    __builtin_mul_overflow(right_count, sizeof(*right), &right_size))
		return (true);
	left_begin = (uintptr_t)left;
	right_begin = (uintptr_t)right;
	if (__builtin_add_overflow(left_begin, left_size, &left_end) ||
	    __builtin_add_overflow(right_begin, right_size, &right_end))
		return (true);
	return (left_begin < right_end && right_begin < left_end);
}

int
vi_pci_stage_admin_queues(struct virtio_softc *vs,
    struct vqueue_info *queues, uint32_t index, uint32_t count)
{
	uint32_t ordinary;

	if (vs == NULL || vs->vs_vc == NULL || queues == NULL ||
	    vs->vs_vc->vc_nvq < 0)
		return (EINVAL);
	ordinary = (uint32_t)vs->vs_vc->vc_nvq;
	if (ordinary > UINT16_MAX || count == 0 || count > UINT16_MAX ||
	    index > UINT16_MAX || index < ordinary ||
	    count > 0x10000U - index ||
	    (ordinary != 0 && vs->vs_queues == NULL) ||
	    vi_queue_storage_overlaps(vs->vs_queues, ordinary, queues, count))
		return (EINVAL);
	if (vs->vs_transport != VIRTIO_PCI_TRANSPORT_MODERN ||
	    vs->vs_modern != NULL || vs->vs_status != 0 ||
	    vs->vs_admin_queues != NULL)
		return (EBUSY);
	for (uint32_t i = 0; i < count; i++) {
		if (queues[i].vq_vs != NULL || queues[i].vq_enabled != 0 ||
		    queues[i].vq_flags != 0 || queues[i].vq_resetting != 0)
			return (EBUSY);
	}
	for (uint32_t i = 0; i < count; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = (uint16_t)(index + i);
		queues[i].vq_layout = VIRTIO_QUEUE_SPLIT;
	}
	vs->vs_admin_queues = queues;
	vs->vs_admin_queue_index = (uint16_t)index;
	vs->vs_admin_queue_count = (uint16_t)count;
	return (0);
}

static void
vq_clear_ring_state(struct vqueue_info *vq, bool clear_split_addresses)
{

	vq_set_allocated(vq, false);
	vq->vq_layout = VIRTIO_QUEUE_SPLIT;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
	vq->vq_pfn = 0;
	vq->vq_notify_pending = false;
	/* Every disabled incarnation must revalidate its DMA-domain binding. */
	vq->vq_dma_generation = 0;
	vq->vq_dma_generation_valid = false;
	if (clear_split_addresses) {
		vq->vq_desc = NULL;
		vq->vq_avail = NULL;
		vq->vq_used = NULL;
	}
	vq->vq_packed_desc = NULL;
	vq->vq_packed_driver_event = NULL;
	vq->vq_packed_device_event = NULL;
	vq->vq_packed_next_avail = 0;
	vq->vq_packed_next_used = 0;
	vq->vq_packed_save_used = 0;
	vq->vq_packed_avail_wrap = true;
	vq->vq_packed_used_wrap = true;
	vq->vq_packed_save_used_wrap = true;
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
	size_t i, nvq;

	if (vs->vs_mtx)
		assert(pthread_mutex_isowned_np(vs->vs_mtx));
	vs->vs_restore_incomplete = false;

	nvq = vi_pci_queue_storage_count(vs);
	for (i = 0; i < nvq; i++) {
		vq = vi_pci_queue_at(vs, i);
		assert(vq != NULL);
		/*
		 * Fence late callbacks for both legacy and modern transports.
		 * Modern reset used to do this in its transport helper, leaving
		 * legacy asynchronous requests able to match the new incarnation.
		 */
		vq->vq_generation++;
		vq_clear_ring_state(vq, false);
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
	vq = qidx <= UINT32_MAX ? vi_pci_queue_lookup(vs, (uint32_t)qidx) : NULL;
	if (vq == NULL) {
		EPRINTLN("%s: queue %ju notify out of range", vc->vc_name,
		    (uintmax_t)qidx);
		return;
	}
	if (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN &&
	    (!vq->vq_enabled || vq_is_resetting(vq)))
		return;
	/* A malformed ring is fatal until the driver performs a real reset. */
	if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	/*
	 * A lifecycle owner may fence queue consumption after the driver has
	 * published descriptors but before its kick reaches this callback.
	 * Preserve the hint so resume can inspect the ring.  Device reset clears
	 * the latch with the rest of the queue incarnation.
	 */
	if (vs->vs_quiescing || vs->vs_suspended ||
	    vs->vs_checkpoint_paused) {
		vq->vq_notify_pending = true;
		return;
	}
	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0) {
		vq->vq_notify_pending = true;
		return;
	}
	vq->vq_notify_pending = false;
	VIRTIO_PROBE_QUEUE_NOTIFY(vc->vc_name, (uint16_t)qidx);
	if (vq->vq_notify != NULL)
		(*vq->vq_notify)(DEV_SOFTC(vs), vq);
	else if (vc->vc_qnotify != NULL)
		(*vc->vc_qnotify)(DEV_SOFTC(vs), vq);
	else
		EPRINTLN("%s: qnotify queue %ju: missing vq/vc notify",
		    vc->vc_name, (uintmax_t)qidx);
}

/*
 * Lifecycle callback for a device whose entire request path is synchronous.
 * Guest-visible suspend reaches it with vs_mtx held after publishing the
 * queue-ownership fence.  Checkpoint pause reaches it after the coordinator
 * has stopped all vCPUs and published the same fence.  In either case no
 * independent backend worker can retain a request.
 */
int
vi_pci_lifecycle_noop(void *vsc __unused)
{

	return (0);
}

void
vi_pci_quiesce_enter(struct virtio_softc *vs)
{

	atomic_fetch_add(&vs->vs_quiescing, 1);
}

void
vi_pci_quiesce_exit(struct virtio_softc *vs)
{
	unsigned int owners;

	owners = atomic_fetch_sub(&vs->vs_quiescing, 1);
	assert(owners != 0);
	(void)owners;
}

/*
 * Publish one full-device reset transaction for every PCI transport.  The
 * odd reset epoch closes new request acquisition before the backend drains;
 * status zero is not visible until the callback has relinquished ownership.
 */
void
vi_pci_reset_device(struct virtio_softc *vs)
{
	const struct virtio_consts *vc;
	uint8_t old_status;

	vc = vs->vs_vc;
	old_status = vs->vs_status;
	VIRTIO_PROBE_RESET(vc->vc_name);
	vs->vs_reset_failed = false;
	vs->vs_restore_incomplete = false;
	atomic_fetch_add(&vs->vs_reset_epoch, 1);
	vi_pci_quiesce_enter(vs);
	vs->vs_resetting = true;
	(*vc->vc_reset)(DEV_SOFTC(vs));
	vs->vs_status = 0;
	vs->vs_suspended = false;
	vs->vs_config_deferred = false;
	vi_pci_quiesce_exit(vs);
	vs->vs_resetting = false;
	atomic_fetch_add(&vs->vs_reset_epoch, 1);
	VIRTIO_PROBE_STATUS(vc->vc_name, old_status, 0);
}

/*
 * A driver can make buffers available before setting DRIVER_OK, but the
 * device must not consume them until DRIVER_OK.  Replay notifications that
 * arrived early once the device becomes live so those buffers are not
 * stranded.
 */
void
vi_pci_notify_ready_queues(struct virtio_softc *vs)
{
	struct vqueue_info *vq;
	size_t count, i;

	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0)
		return;
	count = vi_pci_queue_storage_count(vs);
	for (i = 0; i < count; i++) {
		vq = vi_pci_queue_at(vs, i);
		assert(vq != NULL);
		if (vi_pci_queue_is_admin(vs, vq) &&
		    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) == 0)
			continue;
		if (vq->vq_notify_pending)
			vi_pci_notify_queue(vs, vq->vq_num);
	}
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{
	uint64_t epoch, epoch_after;
	uint8_t old_status;

	epoch = atomic_load(&vs->vs_reset_epoch);
	if ((epoch & 1) != 0 || vs->vs_resetting) {
		/*
		 * A device reset must finish with status zero.  Remember a
		 * backend reinitialization failure and expose NEEDS_RESET when
		 * the driver starts the next initialization attempt.
		 */
		vs->vs_reset_failed = true;
		return;
	}
	old_status = atomic_fetch_or(&vs->vs_status,
	    VIRTIO_CONFIG_S_NEEDS_RESET);
	/*
	 * The worker cannot take vs_mtx here: reset callbacks hold it while
	 * waiting for workers to drain.  If a reset crossed the atomic status
	 * update, preserve the failure for the driver's next initialization.
	 * Re-assert NEEDS_RESET as well in case that reset has already finished;
	 * if it is still active, reset_failed survives its required status-zero
	 * transition.
	 */
	epoch_after = atomic_load(&vs->vs_reset_epoch);
	if (epoch_after != epoch) {
		vs->vs_reset_failed = true;
		vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
		if ((epoch_after & 1) != 0 || vs->vs_resetting)
			return;
	}
	if ((old_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	if ((atomic_load(&vs->vs_status) &
	    VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		vi_interrupt(vs, VIRTIO_PCI_ISR_CONFIG, vs->vs_msix_cfg_idx);
}

void
vi_snapshot_restore_incomplete(struct virtio_softc *vs)
{

	/*
	 * This latch is runtime ownership state, not portable device state.  The
	 * outer snapshot transaction observes it after the device callback and
	 * reasserts NEEDS_RESET after restoring its common-state backup.
	 */
	vs->vs_restore_incomplete = true;
	vi_set_needs_reset(vs);
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
	size_t queue_count;
	int nvec;

	if (pthread_mutex_init(&vs->vs_isr_mtx, NULL) != 0)
		return (1);

	if (use_msix) {
		queue_count = vi_pci_queue_storage_count(vs);
		if (queue_count > INT_MAX - 1) {
			pthread_mutex_destroy(&vs->vs_isr_mtx);
			return (1);
		}
		vs->vs_flags |= VIRTIO_USE_MSIX;
		VS_LOCK(vs);
		vi_reset_dev(vs); /* set all vectors to NO_VECTOR */
		VS_UNLOCK(vs);
		/* One vector for every stored queue plus the configuration vector. */
		nvec = (int)queue_count + 1;
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
	char *avail, *base, *used;

	vq = &vs->vs_queues[vs->vs_curq];
	/*
	 * A full device reset can leave a generation-fenced backend callback
	 * holding ownership after the guest-visible queue has been disabled.
	 * Do not let a new legacy QueuePFN incarnation discard either layout's
	 * owner store before that callback retires its lease.
	 */
	if (!vq_packed_completions_empty(vq) ||
	    !vq_split_owners_empty(vq)) {
		vi_set_needs_reset(vs);
		return;
	}
	vq_packed_completions_fini(vq);
	vq_clear_ring_state(vq, true);
	if (pfn == 0)
		return;
	if (vq_split_owners_init(vq) != 0) {
		goto map_failure;
	}
	phys = (uint64_t)pfn << VRING_PFN;
	size = vring_size_aligned(vq->vq_qsize);
	base = vi_map_dma(vs, phys, size, VIRTIO_DMA_BIDIRECTIONAL);
	if (base == NULL) {
		EPRINTLN("%s: virtqueue %u maps outside guest memory",
		    vs->vs_vc->vc_name, vq->vq_num);
		goto map_failure;
	}

	/*
	 * vi_map_dma() may eventually be backed by an IOMMU mapping rather than
	 * a direct VM memory pointer.  The guest physical layout is aligned, but
	 * do not turn that into an unstated host-pointer alignment assumption.
	 * Validate every typed ring address before publishing any of them.
	 */
	avail = base + vq->vq_qsize * sizeof(struct vring_desc);
	used = (char *)roundup2((uintptr_t)(avail +
	    (2 + vq->vq_qsize + 1) * sizeof(uint16_t)), VRING_ALIGN);
	if (((uintptr_t)base % _Alignof(struct vring_desc)) != 0 ||
	    ((uintptr_t)avail % _Alignof(struct vring_avail)) != 0 ||
	    ((uintptr_t)used % _Alignof(struct vring_used)) != 0) {
		EPRINTLN("%s: virtqueue %u returned unaligned DMA mapping",
		    vs->vs_vc->vc_name, vq->vq_num);
		goto map_failure;
	}
	vq->vq_pfn = pfn;

	/* First page(s) are descriptors, followed by the avail ring. */
	vq->vq_desc = (struct vring_desc *)(void *)base;
	vq->vq_avail = (struct vring_avail *)(void *)avail;

	/* The last page(s) hold the used ring. */
	vq->vq_used = (struct vring_used *)(void *)used;

	/* Mark queue as allocated, and start at 0 when we use it. */
	vq_set_allocated(vq, true);
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
	return;

map_failure:
	vq_clear_ring_state(vq, true);
	vi_set_needs_reset(vs);
}

static inline void
vi_req_classify_descriptor(struct vi_req *req, bool writable, uint32_t length)
{

	if (!writable) {
		if (req->writable != 0)
			req->ordered = false;
		req->readable++;
	} else {
		req->writable++;
		req->writable_bytes += length;
	}
}

/*
 * Helper inline for vq_getchain(): record the i'th "real"
 * descriptor.
 */
static inline bool
_vq_record(int i, struct vring_desc *vd, struct virtio_softc *vs,
    struct iovec *iov,
    int n_iov, struct vi_req *reqp)
{
	void *base;
	uint32_t len;
	uint16_t flags;
	uint64_t addr;

	len = vi32_to_cpu(vs, atomic_load_32(&vd->len));
	addr = vi64_to_cpu(vs, atomic_load_64(&vd->addr));
	flags = vi16_to_cpu(vs, atomic_load_16(&vd->flags));
	base = vi_map_dma(vs, addr, len,
	    (flags & VRING_DESC_F_WRITE) != 0 ?
	    VIRTIO_DMA_DEVICE_WRITE : VIRTIO_DMA_DEVICE_READ);
	if (base == NULL)
		return (false);
	if (i < n_iov) {
		iov[i].iov_len = len;
		iov[i].iov_base = base;
	}
	vi_req_classify_descriptor(reqp,
	    (flags & VRING_DESC_F_WRITE) != 0, len);
	return (true);
}

int
vq_has_descs(struct vqueue_info *vq)
{
	struct vi_req guard;
	uint16_t flags;
	int result;

	memset(&guard, 0, sizeof(guard));
	/*
	 * A fatal ring error sets NEEDS_RESET.  A callback may already be
	 * draining a batch when that happens, so stop the current drain before
	 * it can consume another descriptor from the poisoned ring.
	 */
	if ((vq->vq_vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 ||
	    !vq_ring_ready(vq) ||
	    !vi_req_dma_acquire(vq->vq_vs, &guard))
		return (0);
	result = 0;
	if (!vq_refresh_dma_mappings(vq))
		goto done;
	if (vq->vq_layout == VIRTIO_QUEUE_SPLIT) {
		result = vq->vq_last_avail !=
		    vi16_to_cpu(vq->vq_vs,
		    atomic_load_acq_16(&vq->vq_avail->idx));
		goto done;
	}
	if (vq->vq_packed_desc == NULL ||
	    vq->vq_packed_next_avail >= vq->vq_qsize) {
		vi_set_needs_reset(vq->vq_vs);
		goto done;
	}
	flags = le16toh(atomic_load_acq_16(
	    &vq->vq_packed_desc[vq->vq_packed_next_avail].flags));
	result = vi_packed_desc_available(flags, vq->vq_packed_avail_wrap);
done:
	vi_req_dma_release(vq->vq_vs, &guard);
	return (result);
}

void
vq_kick_enable(struct vqueue_info *vq)
{
	struct vi_req guard;
	uint16_t off_wrap;

	memset(&guard, 0, sizeof(guard));
	if (!vi_req_dma_acquire(vq->vq_vs, &guard))
		return;
	if (!vq_refresh_dma_mappings(vq))
		goto done;
	if (vq->vq_layout == VIRTIO_QUEUE_PACKED) {
		if (vq->vq_packed_device_event == NULL) {
			vi_set_needs_reset(vq->vq_vs);
			goto done;
		}
		if ((vq->vq_vs->vs_negotiated_caps &
		    VIRTIO_RING_F_EVENT_IDX) != 0) {
			if (vi_packed_event_encode(vq->vq_packed_next_avail,
			    vq->vq_packed_avail_wrap, vq->vq_qsize,
			    &off_wrap) != 0) {
				vi_set_needs_reset(vq->vq_vs);
				goto done;
			}
			vi_mark_dma_dirty(vq->vq_vs, vq->vq_packed_device_event,
			    sizeof(*vq->vq_packed_device_event));
			vq->vq_packed_device_event->off_wrap =
			    htole16(off_wrap);
			atomic_store_rel_16(
			    &vq->vq_packed_device_event->flags,
			    htole16(VIRTIO_PACKED_EVENT_F_DESC));
		} else {
			vi_mark_dma_dirty(vq->vq_vs, vq->vq_packed_device_event,
			    sizeof(*vq->vq_packed_device_event));
			atomic_store_rel_16(
			    &vq->vq_packed_device_event->flags,
			    htole16(VIRTIO_PACKED_EVENT_F_ENABLE));
		}
	} else {
		vi_mark_dma_dirty(vq->vq_vs, &vq->vq_used->flags,
		    sizeof(vq->vq_used->flags));
		if ((vq->vq_vs->vs_negotiated_caps &
		    VIRTIO_RING_F_EVENT_IDX) != 0) {
			/*
			 * Ask for a notification when the driver publishes its
			 * next available entry.  With EVENT_IDX, flags remain zero.
			 */
			vq->vq_used->flags = vi16_from_cpu(vq->vq_vs, 0);
			vq_set_avail_event_idx(vq, vq->vq_last_avail);
		} else
			vq->vq_used->flags = vi16_from_cpu(vq->vq_vs, 0);
	}
	/*
	 * Ensure the suppression update is visible before a subsequent
	 * availability recheck, closing the enable-and-recheck race.
	 */
	atomic_thread_fence_seq_cst();
done:
	vi_req_dma_release(vq->vq_vs, &guard);
}

void
vq_kick_disable(struct vqueue_info *vq)
{
	struct vi_req guard;

	memset(&guard, 0, sizeof(guard));
	if (!vi_req_dma_acquire(vq->vq_vs, &guard))
		return;
	if (!vq_refresh_dma_mappings(vq))
		goto done;
	if (vq->vq_layout == VIRTIO_QUEUE_PACKED) {
		if (vq->vq_packed_device_event == NULL) {
			vi_set_needs_reset(vq->vq_vs);
			goto done;
		}
		vi_mark_dma_dirty(vq->vq_vs, vq->vq_packed_device_event,
		    sizeof(*vq->vq_packed_device_event));
		atomic_store_rel_16(&vq->vq_packed_device_event->flags,
		    htole16(VIRTIO_PACKED_EVENT_F_DISABLE));
		goto done;
	}
	vi_mark_dma_dirty(vq->vq_vs, &vq->vq_used->flags,
	    sizeof(vq->vq_used->flags));
	if ((vq->vq_vs->vs_negotiated_caps &
	    VIRTIO_RING_F_EVENT_IDX) != 0) {
		vq->vq_used->flags = vi16_from_cpu(vq->vq_vs, 0);
		vq_set_avail_event_idx(vq, vq->vq_last_avail - 1);
	} else
		vq->vq_used->flags = vi16_from_cpu(vq->vq_vs,
		    VRING_USED_F_NO_NOTIFY);
done:
	vi_req_dma_release(vq->vq_vs, &guard);
}

static int
vq_getchain_packed(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *reqp)
{
	struct virtio_packed_desc *desc, *indirect;
	struct virtio_softc *vs;
	struct vi_req req;
	uint64_t address, chain_len;
	uint32_t length, indirect_count;
	uint16_t flags, indirect_flags, position;
	bool wrap;
	int i, j;

	vs = vq->vq_vs;
	if (vq->vq_packed_desc == NULL || vq->vq_qsize == 0 ||
	    vq->vq_packed_next_avail >= vq->vq_qsize) {
		vi_set_needs_reset(vs);
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.ordered = true;
	req.lengths_known = true;
	req.queue_layout = VIRTIO_QUEUE_PACKED;
	req.packed_head = position = vq->vq_packed_next_avail;
	req.packed_wrap = wrap = vq->vq_packed_avail_wrap;
	req.idx = position;
	req.queue_generation = vq->vq_generation;
	chain_len = 0;

	if (!vi_req_dma_acquire(vs, &req))
		return (0);
	if (!vq_refresh_dma_mappings(vq))
		goto bad;
	flags = le16toh(atomic_load_acq_16(
	    &vq->vq_packed_desc[position].flags));
	if (!vi_packed_desc_available(flags, wrap)) {
		vi_req_dma_release(vs, &req);
		return (0);
	}
	for (i = 0; i < vq->vq_qsize; i++) {
		void *base;

		desc = &vq->vq_packed_desc[position];
		if (i != 0)
			flags = le16toh(atomic_load_16(&desc->flags));
		if (!vi_packed_desc_available(flags, wrap)) {
			EPRINTLN("%s: inconsistent packed descriptor ownership",
			    vs->vs_vc->vc_name);
			goto bad;
		}
		length = le32toh(atomic_load_32(&desc->length));
		address = le64toh(atomic_load_64(&desc->address));
		if ((flags & VRING_DESC_F_INDIRECT) != 0) {
			if ((vs->vs_negotiated_caps &
			    VIRTIO_RING_F_INDIRECT_DESC) == 0) {
				EPRINTLN("%s: packed descriptor has forbidden "
				    "INDIRECT flag", vs->vs_vc->vc_name);
				goto bad;
			}
			if (i != 0 ||
			    (flags & VRING_DESC_F_NEXT) != 0 ||
			    length == 0 ||
			    length % sizeof(*indirect) != 0) {
				EPRINTLN("%s: packed indirect descriptor is "
				    "mixed with a direct chain or malformed",
				    vs->vs_vc->vc_name);
				goto bad;
			}
			indirect_count = length / sizeof(*indirect);
			if (indirect_count > vq->vq_qsize) {
				EPRINTLN("%s: packed indirect table exceeds queue "
				    "size", vs->vs_vc->vc_name);
				goto bad;
			}
			indirect = vi_map_dma(vs, address, length,
			    VIRTIO_DMA_DEVICE_READ);
			if (indirect == NULL) {
				EPRINTLN("%s: packed indirect table maps outside "
				    "guest memory", vs->vs_vc->vc_name);
				goto bad;
			}
			for (j = 0; j < (int)indirect_count; j++) {
				indirect_flags = le16toh(atomic_load_16(
				    &indirect[j].flags));
				/*
				 * Packed indirect entries are a sequential
				 * array.  VirtIO 1.4 section 2.8.7 makes
				 * WRITE the only meaningful flag and requires
				 * the device to ignore every other reserved
				 * flag, including NEXT, INDIRECT, and the
				 * ownership bits.
				 */
				indirect_flags &= VRING_DESC_F_WRITE;
				length = le32toh(atomic_load_32(
				    &indirect[j].length));
				address = le64toh(atomic_load_64(
				    &indirect[j].address));
				if (chain_len + length >
				    (UINT64_C(1) << 32)) {
					EPRINTLN("%s: packed indirect chain "
					    "exceeds 2^32 bytes",
					    vs->vs_vc->vc_name);
					goto bad;
				}
				chain_len += length;
				base = vi_map_dma(vs, address, length,
				    (indirect_flags & VRING_DESC_F_WRITE) != 0 ?
				    VIRTIO_DMA_DEVICE_WRITE :
				    VIRTIO_DMA_DEVICE_READ);
				if (base == NULL) {
					EPRINTLN("%s: packed indirect entry maps "
					    "outside guest memory",
					    vs->vs_vc->vc_name);
					goto bad;
				}
				if (j < niov) {
					iov[j].iov_base = base;
					iov[j].iov_len = length;
				}
				vi_req_classify_descriptor(&req,
				    (indirect_flags & VRING_DESC_F_WRITE) != 0,
				    length);
			}
			req.completion_id = le16toh(atomic_load_16(
			    &desc->id));
			req.descriptor_count = 1;
			if (!vq_packed_owner_claim(vq, req.packed_head,
			    req.packed_wrap)) {
				EPRINTLN("%s: packed descriptor head %u/%u is "
				    "already outstanding", vs->vs_vc->vc_name,
				    req.packed_head, req.packed_wrap);
				goto bad;
			}
			if (vi_packed_advance(&position, &wrap,
			    vq->vq_qsize, 1) != 0) {
				(void)vq_packed_owner_consume(vq, &req);
				goto bad;
			}
			vq->vq_packed_next_avail = position;
			vq->vq_packed_avail_wrap = wrap;
			req.outstanding = true;
			*reqp = req;
			VIRTIO_PROBE_DESCRIPTOR_CHAIN(vs->vs_vc->vc_name,
			    vq->vq_num, 1, 1, indirect_count);
			return ((int)indirect_count);
		}
		if (chain_len + length > (UINT64_C(1) << 32)) {
			EPRINTLN("%s: packed descriptor chain exceeds 2^32 bytes",
			    vs->vs_vc->vc_name);
			goto bad;
		}
		chain_len += length;
		base = vi_map_dma(vs, address, length,
		    (flags & VRING_DESC_F_WRITE) != 0 ?
		    VIRTIO_DMA_DEVICE_WRITE : VIRTIO_DMA_DEVICE_READ);
		if (base == NULL) {
			EPRINTLN("%s: packed descriptor maps outside guest memory",
			    vs->vs_vc->vc_name);
			goto bad;
		}
		if (i < niov) {
			iov[i].iov_base = base;
			iov[i].iov_len = length;
		}
		vi_req_classify_descriptor(&req,
		    (flags & VRING_DESC_F_WRITE) != 0, length);
		req.completion_id = le16toh(atomic_load_16(&desc->id));
		if (vi_packed_advance(&position, &wrap, vq->vq_qsize, 1) !=
		    0)
			goto bad;
		if ((flags & VRING_DESC_F_NEXT) == 0) {
			req.descriptor_count = i + 1;
			if (!vq_packed_owner_claim(vq, req.packed_head,
			    req.packed_wrap)) {
				EPRINTLN("%s: packed descriptor head %u/%u is "
				    "already outstanding", vs->vs_vc->vc_name,
				    req.packed_head, req.packed_wrap);
				goto bad;
			}
			vq->vq_packed_next_avail = position;
			vq->vq_packed_avail_wrap = wrap;
			req.outstanding = true;
			*reqp = req;
			VIRTIO_PROBE_DESCRIPTOR_CHAIN(vs->vs_vc->vc_name,
			    vq->vq_num, 1, 0, req.descriptor_count);
			return (i + 1);
		}
	}
	EPRINTLN("%s: packed descriptor chain exceeds queue size",
	    vs->vs_vc->vc_name);
bad:
	vi_req_dma_release(vs, &req);
	vi_set_needs_reset(vs);
	return (-1);
}
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
 * descriptor and tells you how many are involved.  Indirect tables are
 * resolved through the queue's platform/DMA-domain operations in the
 * request's negotiated DMA address space.
 *
 * As we process each descriptor, we copy and translate it into the given iov[]
 * array (of the given size).  If the array overflows, we stop
 * placing values into the array but keep processing descriptors,
 * up to the queue size, before giving up and returning -1.
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
	struct virtio_softc *vs;
	const char *name;
	bool indirect_chain;

	vs = vq->vq_vs;
	name = vs->vs_vc->vc_name;
	if (vq->vq_layout == VIRTIO_QUEUE_PACKED)
		return (vq_getchain_packed(vq, iov, niov, reqp));
	memset(&req, 0, sizeof(req));
	req.ordered = true;
	req.lengths_known = true;
	req.queue_layout = VIRTIO_QUEUE_SPLIT;
	req.queue_generation = vq->vq_generation;
	chain_len = 0;
	indirect_chain = false;
	if (!vi_req_dma_acquire(vs, &req))
		return (0);
	if (!vq_refresh_dma_mappings(vq))
		goto bad;

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
	/*
	 * The driver publishes descriptors and available-ring entries before
	 * its release-ordered idx update.  The acquire load both samples the
	 * producer index once and orders every subsequent ring/descriptor read
	 * after that publication.
	 */
	ndesc = (uint16_t)((u_int)vi16_to_cpu(vs, atomic_load_acq_16(
	    &vq->vq_avail->idx)) - idx);
	if (ndesc == 0) {
		vi_req_dma_release(vs, &req);
		return (0);
	}
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
	req.idx = next = vi16_to_cpu(vs,
	    vq->vq_avail->ring[idx & (vq->vq_qsize - 1)]);
	vq->vq_last_avail++;
	req.split_avail_next = vq->vq_last_avail;
	for (i = 0; i < vq->vq_qsize;
	    next = vi16_to_cpu(vs, vdir->next)) {
		if (next >= vq->vq_qsize) {
			EPRINTLN(
			    "%s: descriptor index %u out of range, "
			    "driver confused?",
			    name, next);
			goto bad;
		}
		vdir = &vq->vq_desc[next];
		if ((vi16_to_cpu(vs, vdir->flags) &
		    VRING_DESC_F_INDIRECT) == 0) {
			if (chain_len + vi32_to_cpu(vs, vdir->len) >
			    (UINT64_C(1) << 32)) {
				EPRINTLN("%s: descriptor chain exceeds 2^32 "
				    "bytes", name);
				goto bad;
			}
			chain_len += vi32_to_cpu(vs, vdir->len);
			if (!_vq_record(i, vdir, vs, iov, niov, &req)) {
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
			indirect_chain = true;
			if ((vi16_to_cpu(vs, vdir->flags) &
			    VRING_DESC_F_NEXT) != 0) {
				EPRINTLN("%s: descriptor has both INDIRECT and NEXT "
				    "flags", name);
				goto bad;
			}
			n_indir = vi32_to_cpu(vs, vdir->len) / 16;
			if ((vi32_to_cpu(vs, vdir->len) & 0xf) ||
			    n_indir == 0 || n_indir > vq->vq_qsize) {
				EPRINTLN(
				    "%s: invalid indir len 0x%x, "
				    "driver confused?",
				    name, (u_int)vi32_to_cpu(vs, vdir->len));
				goto bad;
			}
			vindir = vi_map_dma(vs, vi64_to_cpu(vs, vdir->addr),
			    vi32_to_cpu(vs, vdir->len),
			    VIRTIO_DMA_DEVICE_READ);
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
				if (vi16_to_cpu(vs, vp->flags) &
				    VRING_DESC_F_INDIRECT) {
					EPRINTLN(
					    "%s: indirect desc has INDIR flag,"
					    " driver confused?",
					    name);
					goto bad;
				}
				if (chain_len + vi32_to_cpu(vs, vp->len) >
				    (UINT64_C(1) << 32)) {
					EPRINTLN("%s: indirect descriptor chain "
					    "exceeds 2^32 bytes", name);
					goto bad;
				}
				chain_len += vi32_to_cpu(vs, vp->len);
				if (!_vq_record(i, vp, vs, iov, niov, &req)) {
					EPRINTLN("%s: indirect descriptor maps "
					    "outside guest memory", name);
					goto bad;
				}
				if (++i > vq->vq_qsize)
					goto loopy;
				if ((vi16_to_cpu(vs, vp->flags) &
				    VRING_DESC_F_NEXT) == 0)
					break;
				next = vi16_to_cpu(vs, vp->next);
				if (next >= n_indir) {
					EPRINTLN(
					    "%s: invalid next %u > %u, "
					    "driver confused?",
					    name, (u_int)next, n_indir);
					goto bad;
				}
			}
		}
		if ((vi16_to_cpu(vs, vdir->flags) &
		    VRING_DESC_F_NEXT) == 0)
			goto done;
	}

loopy:
	EPRINTLN(
	    "%s: descriptor loop? count > %u - driver confused?",
	    name, vq->vq_qsize);

bad:
	vi_req_dma_release(vs, &req);
	vi_set_needs_reset(vs);
	return (-1);

done:
	req.descriptor_count = (uint16_t)i;
	req.completion_id = (uint16_t)req.idx;
	if (!vq_split_owner_claim(vq, (uint16_t)req.idx)) {
		EPRINTLN("%s: split descriptor head %u is already outstanding",
		    name, req.idx);
		goto bad;
	}
	req.outstanding = true;
	*reqp = req;
	VIRTIO_PROBE_DESCRIPTOR_CHAIN(name, vq->vq_num, 0, indirect_chain, i);
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

	assert(vq->vq_layout == VIRTIO_QUEUE_SPLIT);
	vq->vq_last_avail -= n_chains;
}

/*
 * Returning a packed request is only possible while it is the tail of the
 * device's acquired range.  Moving the packed cursor back across a later
 * outstanding request would expose that later request to the device twice.
 * The return API is therefore only for an immediately rejected request, not
 * general asynchronous cancellation.
 */
static bool
vq_packed_request_is_avail_tail(const struct vqueue_info *vq,
    const struct vi_req *req)
{
	uint16_t position;
	bool wrap;

	if (req->descriptor_count == 0 ||
	    req->descriptor_count > vq->vq_qsize ||
	    req->packed_head >= vq->vq_qsize)
		return (false);
	position = req->packed_head;
	wrap = req->packed_wrap;
	if (vi_packed_advance(&position, &wrap, vq->vq_qsize,
	    req->descriptor_count) != 0)
		return (false);
	return (position == vq->vq_packed_next_avail &&
	    wrap == vq->vq_packed_avail_wrap);
}

static bool
vq_split_request_is_avail_tail(const struct vqueue_info *vq,
    const struct vi_req *req)
{

	return (req->split_avail_next == vq->vq_last_avail);
}

void
vq_retchain_req(struct vqueue_info *vq, struct vi_req *req)
{

	if (!req->outstanding) {
		vi_set_needs_reset(vq->vq_vs);
		return;
	}
	if (!vq_request_owner_consume(vq, req)) {
		vi_set_needs_reset(vq->vq_vs);
		req->outstanding = false;
		req->dma_acquired = false;
		return;
	}
	if (req->queue_generation != vq->vq_generation) {
		req->outstanding = false;
		vi_req_dma_release(vq->vq_vs, req);
		return;
	}
	if (req->queue_layout != vq->vq_layout) {
		/* A layout transition without a generation fence is unrecoverable. */
		vi_set_needs_reset(vq->vq_vs);
		req->outstanding = false;
		vi_req_dma_release(vq->vq_vs, req);
		return;
	}
	if (vq->vq_layout == VIRTIO_QUEUE_SPLIT) {
		if (!vq_split_request_is_avail_tail(vq, req)) {
			vi_set_needs_reset(vq->vq_vs);
			req->outstanding = false;
			vi_req_dma_release(vq->vq_vs, req);
			return;
		}
		vq_retchains(vq, 1);
	} else {
		if (!vq_packed_request_is_avail_tail(vq, req)) {
			vi_set_needs_reset(vq->vq_vs);
			req->outstanding = false;
			vi_req_dma_release(vq->vq_vs, req);
			return;
		}
		vq->vq_packed_next_avail = req->packed_head;
		vq->vq_packed_avail_wrap = req->packed_wrap;
	}
	req->outstanding = false;
	vi_req_dma_release(vq->vq_vs, req);
}

/*
 * Permanently retire backend ownership without publishing a used entry.
 * Reset and cancellation paths use this after the queue generation has been
 * invalidated.  This is distinct from vq_retchain_req(), which makes an
 * unconsumed request available to the driver again.
 */
void
vq_discard_req(struct vqueue_info *vq, struct vi_req *req)
{

	if (!req->outstanding) {
		vi_set_needs_reset(vq->vq_vs);
		return;
	}
	if (!vq_request_owner_consume(vq, req)) {
		vi_set_needs_reset(vq->vq_vs);
		req->outstanding = false;
		req->dma_acquired = false;
		return;
	}
	req->outstanding = false;
	vi_req_dma_release(vq->vq_vs, req);
}

static void
vq_relchain_prepare(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	struct vring_used *vuh;
	struct vring_used_elem *vue;
	uint16_t mask;

	assert(vq->vq_layout == VIRTIO_QUEUE_SPLIT);
	if (!vq_refresh_dma_mappings(vq))
		return;
	/*
	 * Notes:
	 *  - mask is N-1 where N is a power of 2 so computes x % N
	 *  - vuh points to the "used" data shared with guest
	 *  - vue points to the "used" ring entry we want to update
	 */
	mask = vq->vq_qsize - 1;
	vuh = vq->vq_used;

	vue = &vuh->ring[vq->vq_next_used++ & mask];
	vi_mark_dma_dirty(vq->vq_vs, vue, sizeof(*vue));
	vue->id = vi32_from_cpu(vq->vq_vs, idx);
	vue->len = vi32_from_cpu(vq->vq_vs, iolen);
}

static void
vq_relchain_publish(struct vqueue_info *vq)
{
	assert(vq->vq_layout == VIRTIO_QUEUE_SPLIT);
	if ((vq->vq_vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 ||
	    !vq_refresh_dma_mappings(vq))
		return;
	/*
	 * Publish every used-ring element before the driver can observe the
	 * new used index.  A release store expresses both the compiler and CPU
	 * ordering required by VirtIO 1.4 section 2.7.8.
	 */
	vi_mark_dma_dirty(vq->vq_vs, &vq->vq_used->idx,
	    sizeof(vq->vq_used->idx));
	atomic_store_rel_16(&vq->vq_used->idx,
	    vi16_from_cpu(vq->vq_vs, vq->vq_next_used));
}

/*
 * Return specified request chain to the guest, setting its I/O length
 * to the provided value.
 *
 * (This chain is the one you handled when you called vq_getchain()
 * and used its positive return value.)
 */
static void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	vq_relchain_prepare(vq, idx, iolen);
	vq_relchain_publish(vq);
}

int
vq_packed_completions_init(struct vqueue_info *vq)
{
	struct virtio_packed_completion *completions;

	if (vq->vq_qsize == 0 ||
	    vq->vq_qsize > VIRTIO_PACKED_QUEUE_SIZE_MAX)
		return (EINVAL);
	if (vq->vq_packed_completions != NULL) {
		if (vq->vq_packed_completion_count == vq->vq_qsize &&
		    vq_packed_completions_empty(vq))
			return (0);
		if (!vq_packed_completions_empty(vq))
			return (EBUSY);
		vq_packed_completions_fini(vq);
	}
	completions = calloc(vq->vq_qsize, sizeof(*completions));
	if (completions == NULL)
		return (ENOMEM);
	vq->vq_packed_completions = completions;
	vq->vq_packed_completion_count = vq->vq_qsize;
	return (0);
}

void
vq_packed_completions_fini(struct vqueue_info *vq)
{

	free(vq->vq_packed_completions);
	vq->vq_packed_completions = NULL;
	vq->vq_packed_completion_count = 0;
}

void
vq_packed_completions_reset(struct vqueue_info *vq)
{
	struct virtio_packed_completion *completion;
	uint8_t owner_state;
	bool owners;
	uint16_t i;

	if (vq->vq_packed_completions == NULL)
		return;
	/*
	 * Published-but-not-yet-contiguous completions are host cursor state
	 * and can be dropped by reset.  A nonzero owner_state represents an
	 * asynchronous backend lease, so preserve only that state until its
	 * generation-fenced callback retires it.
	 */
	owners = false;
	for (i = 0; i < vq->vq_packed_completion_count; i++) {
		completion = &vq->vq_packed_completions[i];
		owner_state = atomic_load_8(&completion->owner_state);
		if (owner_state != 0) {
			/*
			 * The late callback needs only its atomic lease: all request
			 * identity and completion data lives in the vi_req it retained.
			 * Do not preserve stale reorder metadata across the generation
			 * boundary.  In particular, a corrupt or half-published valid bit
			 * must not keep a post-reset packed setup permanently busy after
			 * that callback consumes its lease.  Do not memset this object:
			 * owner_state is concurrently consumed by that callback.
			 */
			completion->iolen = 0;
			completion->descriptor_count = 0;
			completion->completion_id = 0;
			completion->group_count = 0;
			completion->group_prev_head = 0;
			completion->group_prev_wrap = false;
			completion->packed_wrap = false;
			completion->valid = false;
			owners = true;
			continue;
		}
		memset(completion, 0, sizeof(*completion));
	}
	if (!owners)
		vq_packed_completions_fini(vq);
}

bool
vq_packed_completions_empty(const struct vqueue_info *vq)
{
	uint16_t i;

	if (vq->vq_packed_completions == NULL)
		return (vq->vq_packed_completion_count == 0);
	for (i = 0; i < vq->vq_packed_completion_count; i++) {
		if (vq->vq_packed_completions[i].valid ||
		    atomic_load_8(
		    &vq->vq_packed_completions[i].owner_state) != 0)
			return (false);
	}
	return (true);
}

static int
vq_relchain_packed_publish(struct vqueue_info *vq, const struct vi_req *req,
    uint32_t iolen)
{
	struct virtio_packed_desc *desc;
	uint16_t flags;

	if (req->descriptor_count == 0 ||
	    req->descriptor_count > vq->vq_qsize ||
	    req->packed_head >= vq->vq_qsize ||
	    vq->vq_packed_desc == NULL)
		return (EINVAL);
	desc = &vq->vq_packed_desc[req->packed_head];
	vi_mark_dma_dirty(vq->vq_vs, desc, sizeof(*desc));
	desc->length = htole32(iolen);
	desc->id = htole16(req->completion_id);
	flags = req->packed_wrap ?
	    VIRTIO_PACKED_DESC_F_AVAIL | VIRTIO_PACKED_DESC_F_USED : 0;
	/*
	 * In a packed used descriptor WRITE reports whether the device wrote
	 * any part of the complete buffer, not whether the overwritten head
	 * descriptor was originally writable.  The used length is the exact
	 * amount written, so it is also the authoritative source for this bit.
	 */
	if (iolen != 0)
		flags |= VRING_DESC_F_WRITE;
	/*
	 * Publish completion payload before transferring descriptor ownership
	 * to the driver through the USED bit.
	 */
	atomic_store_rel_16(&desc->flags, htole16(flags));
	return (0);
}

static bool
vq_packed_request_outstanding(const struct vqueue_info *vq,
    const struct vi_req *req)
{
	uint32_t avail, cycle, head, used;
	uint32_t avail_distance, head_distance;

	if (vq->vq_qsize == 0 || req->packed_head >= vq->vq_qsize)
		return (false);
	cycle = 2U * vq->vq_qsize;
	used = vq->vq_packed_next_used +
	    (vq->vq_packed_used_wrap ? vq->vq_qsize : 0);
	avail = vq->vq_packed_next_avail +
	    (vq->vq_packed_avail_wrap ? vq->vq_qsize : 0);
	head = req->packed_head +
	    (req->packed_wrap ? vq->vq_qsize : 0);
	avail_distance = (avail + cycle - used) % cycle;
	head_distance = (head + cycle - used) % cycle;
	return (avail_distance != 0 && avail_distance <= vq->vq_qsize &&
	    head_distance < avail_distance &&
	    req->descriptor_count <= avail_distance - head_distance);
}

static void
vq_relchain_packed_flush(struct vqueue_info *vq)
{
	struct virtio_packed_completion *completion;
	struct vi_req completed_req;
	bool previous_wrap, wrap;
	uint16_t count, head, position, previous_head;
	uint16_t tail_head;
	bool tail_wrap;
	unsigned int i;

	for (;;) {
		head = vq->vq_packed_next_used;
		completion = &vq->vq_packed_completions[head];
		/*
		 * An absent head is the ordinary asynchronous completion gap.  A
		 * present head for the other wrap generation cannot be a later
		 * request: the outstanding window is at most one ring traversal.
		 * Leaving it staged would permanently prevent used-ring progress.
		 */
		if (!completion->valid)
			break;
		if (completion->packed_wrap != vq->vq_packed_used_wrap) {
			vi_set_needs_reset(vq->vq_vs);
			return;
		}
		count = completion->group_count;
		if (count == 0)
			count = 1;
		position = head;
		wrap = vq->vq_packed_used_wrap;
		tail_head = head;
		tail_wrap = wrap;
		/*
		 * A group is visible only after every member is staged.  Validate
		 * its complete contiguous shape before publishing any ownership.
		 */
		for (i = 0; i < count; i++) {
			completion = &vq->vq_packed_completions[position];
			if (!completion->valid ||
			    completion->packed_wrap != wrap ||
			    completion->descriptor_count == 0 ||
			    completion->descriptor_count > vq->vq_qsize) {
				/*
				 * A group is staged as one serialized operation.  Unlike a
				 * missing head, a missing or malformed member can never be an
				 * ordinary out-of-order completion gap.  Returning silently
				 * would leave the valid group head permanently blocking the
				 * used cursor.
				 */
				vi_set_needs_reset(vq->vq_vs);
				return;
			}
			tail_head = position;
			tail_wrap = wrap;
			if (vi_packed_advance(&position, &wrap, vq->vq_qsize,
			    completion->descriptor_count) != 0) {
				vi_set_needs_reset(vq->vq_vs);
				return;
			}
		}
		/*
		 * Transfer ownership from the last chain toward the first.
		 * Packed-ring drivers consume in order, so publishing the head
		 * last makes the entire logical group observable together.
		 */
		position = tail_head;
		wrap = tail_wrap;
		for (i = count; i > 0; i--) {
			completion = &vq->vq_packed_completions[position];
			previous_head = completion->group_prev_head;
			previous_wrap = completion->group_prev_wrap;
			memset(&completed_req, 0, sizeof(completed_req));
			completed_req.descriptor_count =
			    completion->descriptor_count;
			completed_req.completion_id =
			    completion->completion_id;
			completed_req.packed_head = position;
			completed_req.packed_wrap = wrap;
			if (vq_relchain_packed_publish(vq, &completed_req,
			    completion->iolen) != 0) {
				vi_set_needs_reset(vq->vq_vs);
				return;
			}
			position = previous_head;
			wrap = previous_wrap;
		}
		for (i = 0; i < count; i++) {
			head = vq->vq_packed_next_used;
			completion = &vq->vq_packed_completions[head];
			if (vi_packed_advance(&vq->vq_packed_next_used,
			    &vq->vq_packed_used_wrap, vq->vq_qsize,
			    completion->descriptor_count) != 0) {
				vi_set_needs_reset(vq->vq_vs);
				return;
			}
			memset(completion, 0, sizeof(*completion));
		}
	}
}

static void
vq_retire_request(struct vqueue_info *vq, struct vi_req *req)
{

	req->outstanding = false;
	vi_req_dma_release(vq->vq_vs, req);
}

static void
vq_fail_request(struct vqueue_info *vq, struct vi_req *req)
{

	vi_set_needs_reset(vq->vq_vs);
	vq_retire_request(vq, req);
}

void
vq_relchain_req(struct vqueue_info *vq, struct vi_req *req,
    uint32_t iolen)
{
	struct virtio_packed_completion *completion;

	if (!req->outstanding) {
		vi_set_needs_reset(vq->vq_vs);
		return;
	}
	if (!vq_request_owner_consume(vq, req)) {
		vi_set_needs_reset(vq->vq_vs);
		req->outstanding = false;
		req->dma_acquired = false;
		return;
	}
	if (req->queue_generation != vq->vq_generation) {
		vq_retire_request(vq, req);
		return;
	}
	/*
	 * Ownership was consumed from the token's acquisition layout.  A normal
	 * layout transition advances generation and retires above as stale; a
	 * same-generation mismatch is malformed and must not select a different
	 * publication format for the consumed ownership.
	 */
	if (req->queue_layout != vq->vq_layout) {
		vq_fail_request(vq, req);
		return;
	}
	if (!vq_refresh_dma_mappings(vq)) {
		vq_retire_request(vq, req);
		return;
	}
	if (req->lengths_known && iolen > req->writable_bytes) {
		vq_fail_request(vq, req);
		return;
	}
	if (vq->vq_layout == VIRTIO_QUEUE_SPLIT) {
		vq_relchain(vq, req->idx, iolen);
		vq_retire_request(vq, req);
		return;
	}
	if (req->descriptor_count == 0 ||
	    req->descriptor_count > vq->vq_qsize ||
	    req->packed_head >= vq->vq_qsize ||
	    vq->vq_packed_completions == NULL ||
	    vq->vq_packed_completion_count != vq->vq_qsize ||
	    !vq_packed_request_outstanding(vq, req)) {
		vq_fail_request(vq, req);
		return;
	}
	/*
	 * A packed descriptor offset can be reused after a complete ring
	 * traversal.  The wrap bit and queue generation distinguish that new
	 * ownership from a duplicate or stale asynchronous completion.
	 */
	completion = &vq->vq_packed_completions[req->packed_head];
	if (completion->valid) {
		vq_fail_request(vq, req);
		return;
	}
	completion->iolen = iolen;
	completion->descriptor_count = req->descriptor_count;
	completion->completion_id = req->completion_id;
	completion->group_count = 1;
	completion->packed_wrap = req->packed_wrap;
	completion->valid = true;

	vq_relchain_packed_flush(vq);
	vq_retire_request(vq, req);
}

/*
 * Complete a set of request chains which together describe one logical
 * operation.  Split rings publish one used index after all elements are
 * written.  Packed rings validate and stage the whole set before transferring
 * any descriptor ownership, so a polling driver cannot observe a partial
 * mergeable-buffer packet merely because the device uses several chains.
 */
void
vq_relchain_group(struct vqueue_info *vq, struct vi_req *reqs,
    const uint32_t *iolens, unsigned int nreqs)
{
	struct virtio_packed_completion *completion;
	bool expected_wrap, owners_valid;
	uint16_t expected_head;
	unsigned int i, j;

	if (nreqs == 0)
		return;
	/*
	 * Ring ownership is queue state, not token state.  Consume every head
	 * before checking the generation so stale groups and partially malformed
	 * groups cannot wedge ownership across reset.  This must also precede the
	 * group-size check: an oversized internal request is invalid, but every
	 * independently acquired member still has to retire its lease.  Keep
	 * examining the full group after a duplicate so independently owned
	 * members are retired.
	 */
	owners_valid = true;
	for (i = 0; i < nreqs; i++) {
		if (!reqs[i].outstanding) {
			owners_valid = false;
			continue;
		}
		if (!vq_request_owner_consume(vq, &reqs[i])) {
			/*
			 * A copied token shares the original lease; the successful
			 * consumer is responsible for releasing it.
			 */
			reqs[i].dma_acquired = false;
			owners_valid = false;
		}
	}
	if (nreqs > vq->vq_qsize) {
		vi_set_needs_reset(vq->vq_vs);
		goto release;
	}
	if (!owners_valid) {
		vi_set_needs_reset(vq->vq_vs);
		goto release;
	}
	for (i = 0; i < nreqs; i++) {
		if (!reqs[i].outstanding) {
			vi_set_needs_reset(vq->vq_vs);
			goto release;
		}
		if (reqs[i].queue_generation != vq->vq_generation)
			goto release;
		/*
		 * A generation mismatch is a normal stale-token retirement.  Only a
		 * same-generation layout change is unrecoverable: ownership was
		 * consumed using the token's acquisition layout, while publication
		 * would otherwise select the current layout.
		 */
		if (reqs[i].queue_layout != vq->vq_layout) {
			vi_set_needs_reset(vq->vq_vs);
			goto release;
		}
		if (reqs[i].lengths_known &&
		    iolens[i] > reqs[i].writable_bytes) {
			vi_set_needs_reset(vq->vq_vs);
			goto release;
		}
	}
	if (!vq_refresh_dma_mappings(vq))
		goto release;
	if (vq->vq_layout == VIRTIO_QUEUE_SPLIT) {
		for (i = 0; i < nreqs; i++)
			vq_relchain_prepare(vq, reqs[i].idx, iolens[i]);
		vq_relchain_publish(vq);
		goto release;
	}
	if (vq->vq_packed_completions == NULL ||
	    vq->vq_packed_completion_count != vq->vq_qsize) {
		vi_set_needs_reset(vq->vq_vs);
		goto release;
	}
	expected_head = reqs[0].packed_head;
	expected_wrap = reqs[0].packed_wrap;
	/*
	 * Validate the complete group before mutating the reorder table.  The
	 * duplicate-head check also prevents one malformed group from
	 * overwriting its own staged completion.
	 */
	for (i = 0; i < nreqs; i++) {
		if (reqs[i].packed_head != expected_head ||
		    reqs[i].packed_wrap != expected_wrap ||
		    reqs[i].descriptor_count == 0 ||
		    reqs[i].descriptor_count > vq->vq_qsize ||
		    reqs[i].packed_head >= vq->vq_qsize ||
		    !vq_packed_request_outstanding(vq, &reqs[i]) ||
		    vq->vq_packed_completions[reqs[i].packed_head].valid) {
			vi_set_needs_reset(vq->vq_vs);
			goto release;
		}
		for (j = 0; j < i; j++) {
			if (reqs[j].packed_head == reqs[i].packed_head) {
				vi_set_needs_reset(vq->vq_vs);
				goto release;
			}
		}
		if (vi_packed_advance(&expected_head, &expected_wrap,
		    vq->vq_qsize, reqs[i].descriptor_count) != 0) {
			vi_set_needs_reset(vq->vq_vs);
			goto release;
		}
	}
	for (i = 0; i < nreqs; i++) {
		completion =
		    &vq->vq_packed_completions[reqs[i].packed_head];
		completion->iolen = iolens[i];
		completion->descriptor_count = reqs[i].descriptor_count;
		completion->completion_id = reqs[i].completion_id;
		completion->group_count = i == 0 ? nreqs : 0;
		if (i != 0) {
			completion->group_prev_head = reqs[i - 1].packed_head;
			completion->group_prev_wrap = reqs[i - 1].packed_wrap;
		}
		completion->packed_wrap = reqs[i].packed_wrap;
		completion->valid = true;
	}
	vq_relchain_packed_flush(vq);
release:
	for (i = 0; i < nreqs; i++) {
		reqs[i].outstanding = false;
		vi_req_dma_release(vq->vq_vs, &reqs[i]);
	}
}

static void
vq_endchains_packed(struct vqueue_info *vq)
{
	struct virtio_packed_position event, new, old;
	struct virtio_softc *vs;
	uint16_t event_flags, off_wrap;
	bool intr;

	vs = vq->vq_vs;
	if (vq->vq_packed_driver_event == NULL ||
	    vq->vq_packed_save_used >= vq->vq_qsize ||
	    vq->vq_packed_next_used >= vq->vq_qsize) {
		vi_set_needs_reset(vs);
		return;
	}
	old.offset = vq->vq_packed_save_used;
	old.wrap = vq->vq_packed_save_used_wrap;
	new.offset = vq->vq_packed_next_used;
	new.wrap = vq->vq_packed_used_wrap;
	vq->vq_packed_save_used = new.offset;
	vq->vq_packed_save_used_wrap = new.wrap;

	/*
	 * Order used-descriptor publication before observing driver event
	 * suppression.  This is the packed equivalent of the split EVENT_IDX
	 * barrier.
	 */
	atomic_thread_fence_seq_cst();
	off_wrap = 0;
	event_flags = le16toh(atomic_load_acq_16(
	    &vq->vq_packed_driver_event->flags));
	if (!vi_packed_event_flags_valid(event_flags) ||
	    (event_flags == VIRTIO_PACKED_EVENT_F_DESC &&
	    (vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) == 0)) {
		vi_set_needs_reset(vs);
		return;
	}
	if (event_flags == VIRTIO_PACKED_EVENT_F_DISABLE)
		intr = false;
	else if (event_flags == VIRTIO_PACKED_EVENT_F_ENABLE)
		intr = old.offset != new.offset || old.wrap != new.wrap;
	else {
		off_wrap = le16toh(atomic_load_16(
		    &vq->vq_packed_driver_event->off_wrap));
		event.offset = off_wrap & VIRTIO_PACKED_EVENT_OFFSET_MASK;
		event.wrap = (off_wrap & VIRTIO_PACKED_EVENT_WRAP) != 0;
		if (vi_packed_need_event(event, old, new, vq->vq_qsize,
		    &intr) != 0) {
			vi_set_needs_reset(vs);
			return;
		}
	}
	VIRTIO_PROBE_PACKED_EVENT_IDX(vs->vs_vc->vc_name, vq->vq_num,
	    off_wrap, new.offset |
	    (new.wrap ? VIRTIO_PACKED_EVENT_WRAP : 0), intr);
	if (intr)
		vq_interrupt(vs, vq);
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
	struct vi_req guard;
	struct virtio_softc *vs;
	uint16_t event_idx, new_idx, old_idx;
	int intr;

	memset(&guard, 0, sizeof(guard));
	if (!vi_req_dma_acquire(vq->vq_vs, &guard))
		return;
	if (!vq_refresh_dma_mappings(vq))
		goto done;
	if (vq->vq_layout == VIRTIO_QUEUE_PACKED) {
		vq_endchains_packed(vq);
		goto done;
	}
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
	/*
	 * vq_next_used is the device-owned producer index.  Do not reread the
	 * shared used index for interrupt accounting: a conforming driver never
	 * writes it, but using host-owned state also makes this path robust
	 * against a confused guest.
	 */
	vq->vq_save_used = new_idx = vq->vq_next_used;

	/*
	 * Use full memory barrier between "idx" store from preceding
	 * vq_relchain() call and the loads from vq_used_event_idx() or
	 * "flags" field below.
	 */
	atomic_thread_fence_seq_cst();
	if (used_all_avail &&
	    (vs->vs_negotiated_caps & VIRTIO_F_NOTIFY_ON_EMPTY))
		intr = 1;
	else if (vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) {
		event_idx = vq_used_event_idx(vq);
		/*
		 * This calculation is per docs and the kernel
		 * (see src/sys/dev/virtio/virtio_ring.h).
		 */
		intr = (uint16_t)(new_idx - event_idx - 1) <
			(uint16_t)(new_idx - old_idx);
		VIRTIO_PROBE_EVENT_IDX(vs->vs_vc->vc_name, vq->vq_num,
		    event_idx, new_idx, intr);
	} else {
		intr = new_idx != old_idx &&
		    !(vi16_to_cpu(vq->vq_vs, vq->vq_avail->flags) &
		    VRING_AVAIL_F_NO_INTERRUPT);
	}
	vi_req_dma_release(vq->vq_vs, &guard);
	if (intr)
		vq_interrupt(vs, vq);
	return;
done:
	vi_req_dma_release(vq->vq_vs, &guard);
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

static uint64_t
vi_pci_bad_value(int size)
{

	switch (size) {
	case 1:
		return (UINT8_MAX);
	case 2:
		return (UINT16_MAX);
	case 4:
		return (UINT32_MAX);
	default:
		return (UINT64_MAX);
	}
}

static inline struct config_reg *
vi_find_cr(uint64_t offset)
{
	size_t hi, lo, mid;
	struct config_reg *cr;

	lo = 0;
	hi = nitems(config_regs);
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		cr = &config_regs[mid];
		if (cr->cr_offset == offset)
			return (cr);
		if (cr->cr_offset < offset)
			lo = mid + 1;
		else
			hi = mid;
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
	uint64_t config_offset, virtio_config_size, max;
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

	if (baridx != 0)
		return (vi_pci_bad_value(size));

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	vc = vs->vs_vc;
	name = vc->vc_name;
	value = size == 1 ? 0xff : size == 2 ? 0xffff : 0xffffffff;
	if (vs->vs_resetting || vs->vs_quiescing) {
		/*
		 * Checkpoint callbacks may drop vs_mtx while draining backend
		 * work.  Status polling remains harmless and useful, but no
		 * other legacy register or device-configuration read may enter
		 * the backend until lifecycle ownership is released.
		 */
		if (offset == VIRTIO_PCI_STATUS && size == 1)
			value = vs->vs_status;
		goto done;
	}

	if (size != 1 && size != 2 && size != 4)
		goto bad;

	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to the underlying driver.
		 * Do not reinterpret a rejected device-configuration access as
		 * a transport register.  In the non-MSI-X layout, device
		 * configuration starts at the same numeric offsets used for the
		 * MSI-X vector registers in the MSI-X layout.
		 */
		config_offset = offset - virtio_config_size;
		max = vc->vc_cfgsize;
		if (config_offset > INT_MAX || config_offset > max ||
		    (uint64_t)size > max - config_offset) {
			EPRINTLN("%s: read from bad device config "
			    "offset/size %ju/%d", name,
			    (uintmax_t)config_offset, size);
			goto done;
		}
		newoff = config_offset;
		error = vc->vc_cfgread == NULL ? 0 :
		    (*vc->vc_cfgread)(DEV_SOFTC(vs), newoff, size, &value);
		if (error != 0)
			value = vi_pci_bad_value(size);
		else
			value &= vi_pci_bad_value(size);
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
		/*
		 * QueueNotify is a driver-write-only register.  Legacy PCI
		 * assigns no read semantics, so return a deterministic zero
		 * without exposing queue state through an accidental extension.
		 */
		value = 0;
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
	uint64_t config_offset, virtio_config_size, max;
	const char *name;
	uint32_t newoff;
	uint8_t old_status;

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

	if (baridx != 0)
		return;

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	vc = vs->vs_vc;
	name = vc->vc_name;
	/*
	 * Legacy devices do not negotiate guest-visible suspend, but the
	 * checkpoint lifecycle uses the same ownership fence.  In particular,
	 * reject a status-zero reset while a callback has dropped vs_mtx to
	 * wait for active work; otherwise two lifecycle owners can mutate the
	 * same backend concurrently.
	 */
	if (vs->vs_resetting || vs->vs_quiescing)
		goto done;

	if (size != 1 && size != 2 && size != 4)
		goto bad;
	/*
	 * The PCI emulation normally supplies a value already limited to the
	 * access width.  Keep this entry point self-contained as well: callers
	 * such as snapshot restore and unit harnesses must not be able to place
	 * high bits into a narrower legacy register.
	 */
	value &= vi_pci_bad_value(size);

	virtio_config_size = VIRTIO_PCI_CONFIG_OFF(pci_msix_enabled(pi));

	if (offset >= virtio_config_size) {
		/*
		 * Subtract off the standard size (including MSI-X
		 * registers if enabled) and dispatch to the underlying driver.
		 * A rejected access remains a device-configuration access; see
		 * the matching read path for the overlapping-offset rationale.
		 */
		config_offset = offset - virtio_config_size;
		max = vc->vc_cfgsize;
		if (config_offset > INT_MAX || config_offset > max ||
		    (uint64_t)size > max - config_offset) {
			EPRINTLN("%s: write to bad device config "
			    "offset/size %ju/%d", name,
			    (uintmax_t)config_offset, size);
			goto done;
		}
		newoff = config_offset;
		if (vc->vc_cfgwrite != NULL)
			(void)(*vc->vc_cfgwrite)(DEV_SOFTC(vs), newoff, size,
			    value);
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
		/*
		 * Legacy devices have no FEATURES_OK handshake.  DRIVER_OK is
		 * therefore the last unambiguous initialization boundary.
		 * Record feature-register writes here, but do not apply their
		 * device-specific effects yet.  In particular, the legacy
		 * virtio-blk rules prohibit changing cache mode merely because
		 * the driver rewrote its feature bits.  Finalize the selected
		 * features on the transition to DRIVER_OK below, and do not let
		 * a later write change a live backend's interpretation of
		 * descriptors.
		 */
		if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
			break;
		vs->vs_negotiated_caps = value & vc->vc_hv_caps;
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
			break;
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
	{
		int error;

		old_status = vs->vs_status;
		if (value == 0) {
			vi_pci_reset_device(vs);
		} else {
			value &= VIRTIO_CONFIG_STATUS_ACK |
			    VIRTIO_CONFIG_STATUS_DRIVER |
			    VIRTIO_CONFIG_STATUS_DRIVER_OK |
			    VIRTIO_CONFIG_S_FEATURES_OK |
			    VIRTIO_CONFIG_STATUS_FAILED;
			value |= old_status &
			    (VIRTIO_CONFIG_STATUS_ACK |
			    VIRTIO_CONFIG_STATUS_DRIVER |
			    VIRTIO_CONFIG_STATUS_DRIVER_OK |
			    VIRTIO_CONFIG_S_FEATURES_OK |
			    VIRTIO_CONFIG_STATUS_FAILED |
			    VIRTIO_CONFIG_S_NEEDS_RESET);
			if (vs->vs_reset_failed)
				value |= VIRTIO_CONFIG_S_NEEDS_RESET;
			vs->vs_status = (uint8_t)value;
			if ((old_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0 &&
			    (value & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0) {
				error = 0;
				if (vc->vc_apply_features != NULL)
					error = (*vc->vc_apply_features)(
					    DEV_SOFTC(vs),
					    vs->vs_negotiated_caps);
				if (error != 0) {
					/*
					 * Transitional devices have no
					 * FEATURES_OK handshake.  Refuse to
					 * become live and request a full reset
					 * when the backend cannot apply the
					 * selected legacy feature set.
					 */
					vs->vs_status &=
					    ~VIRTIO_CONFIG_STATUS_DRIVER_OK;
					vs->vs_status |=
					    VIRTIO_CONFIG_S_NEEDS_RESET;
				} else {
					VIRTIO_PROBE_FEATURES(vc->vc_name,
					    vs->vs_negotiated_caps);
					vi_pci_notify_ready_queues(vs);
				}
			}
			VIRTIO_PROBE_STATUS(vc->vc_name, old_status,
			    vs->vs_status);
		}
		break;
	}
	case VIRTIO_MSI_CONFIG_VECTOR:
		if (value == VIRTIO_MSI_NO_VECTOR ||
		    value < (uint64_t)vs->vs_pi->pi_msix.table_count)
			vs->vs_msix_cfg_idx = value;
		else
			vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		if (vs->vs_curq >= vc->vc_nvq)
			goto bad_qindex;
		vq = &vs->vs_queues[vs->vs_curq];
		if (value == VIRTIO_MSI_NO_VECTOR ||
		    value < (uint64_t)vs->vs_pi->pi_msix.table_count)
			vq->vq_msix_idx = value;
		else
			vq->vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
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
#define	VIRTIO_MODERN_COMMON_SNAPSHOT_MAGIC	0x56544331U	/* "VTC1" */
#define	VIRTIO_MODERN_COMMON_SNAPSHOT_VERSION	2U

static int vi_snapshot_compat_append(char *, size_t, size_t *, const char *, ...)
    __printflike(4, 5);

static int
vi_snapshot_compat_append(char *buffer, size_t capacity, size_t *used,
    const char *format, ...)
{
	va_list ap;
	int length;

	if (*used >= capacity)
		return (EOVERFLOW);
	va_start(ap, format);
	length = vsnprintf(buffer + *used, capacity - *used, format, ap);
	va_end(ap);
	if (length < 0 || (size_t)length >= capacity - *used)
		return (EOVERFLOW);
	*used += (size_t)length;
	return (0);
}

int
vi_pci_snapshot_compat(struct pci_devinst *pi,
    struct pci_snapshot_compat *compat)
{
	struct virtio_pci_modern *modern;
	struct virtio_softc *vs;
	size_t queue_used, shared_used;
	int error;

	if (pi == NULL || compat == NULL || pi->pi_arg == NULL)
		return (EINVAL);
	vs = pi->pi_arg;
	if (vs->vs_vc == NULL || vs->vs_queues == NULL ||
	    vs->vs_vc->vc_nvq < 0 || pi->pi_msix.table_count < 0)
		return (EINVAL);

	memset(compat, 0, sizeof(*compat));
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = (uint32_t)vs->vs_transport;
	compat->queue_count = (uint32_t)vs->vs_vc->vc_nvq;
	compat->msix_table_count = (uint32_t)pi->pi_msix.table_count;
	compat->config_size = vs->vs_vc->vc_cfgsize;
	if (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN)
		compat->offered_features =
		    vi_modern_device_features(vs);
	else
		compat->offered_features = vs->vs_vc->vc_hv_caps;
	compat->negotiated_features = vs->vs_negotiated_caps;

	queue_used = 0;
	for (int i = 0; i < vs->vs_vc->vc_nvq; i++) {
		error = vi_snapshot_compat_append(compat->queue_sizes,
		    sizeof(compat->queue_sizes), &queue_used, "%s%u",
		    i == 0 ? "" : ",", vs->vs_queues[i].vq_qsize_max);
		if (error != 0)
			return (error);
	}
	/*
	 * queue_count deliberately remains the PCI common-configuration count
	 * of ordinary device queues.  Administration queues can occupy a later,
	 * gapped selector range, but their selector base, count, and queue sizes
	 * are nevertheless part of the checkpointed queue topology.  Append
	 * them after the ordinary sizes as decimal values:
	 *
	 *   <ordinary sizes>,<admin selector base>,<admin count>,<admin sizes>
	 *
	 * The scalar queue_count gives the ordinary prefix its unambiguous
	 * boundary.  Older records without an administration suffix fail the
	 * equality preflight safely when restored to an administration-capable
	 * destination instead of deferring the mismatch until queue restore.
	 */
	if (vs->vs_admin_queue_count != 0) {
		if (vs->vs_admin_queues == NULL ||
		    vs->vs_admin_queue_index < (uint32_t)vs->vs_vc->vc_nvq ||
		    vs->vs_admin_queue_count >
		    UINT16_MAX + 1U - vs->vs_admin_queue_index)
			return (EINVAL);
		error = vi_snapshot_compat_append(compat->queue_sizes,
		    sizeof(compat->queue_sizes), &queue_used, "%s%u,%u",
		    queue_used == 0 ? "" : ",", vs->vs_admin_queue_index,
		    vs->vs_admin_queue_count);
		if (error != 0)
			return (error);
		for (uint16_t i = 0; i < vs->vs_admin_queue_count; i++) {
			error = vi_snapshot_compat_append(compat->queue_sizes,
			    sizeof(compat->queue_sizes), &queue_used, ",%u",
			    vs->vs_admin_queues[i].vq_qsize_max);
			if (error != 0)
				return (error);
		}
	}

	modern = vs->vs_modern;
	shared_used = 0;
	if (modern != NULL) {
		if (modern->shared_memory_count >
		    VIRTIO_PCI_SHARED_MEMORY_MAX)
			return (EINVAL);
		for (uint8_t i = 0; i < modern->shared_memory_count; i++) {
			const struct virtio_pci_shared_memory_region *region;

			region = &modern->shared_memory[i];
			error = vi_snapshot_compat_append(
			    compat->shared_memory,
			    sizeof(compat->shared_memory), &shared_used,
			    "%s%u:%u:%ju:%ju", i == 0 ? "" : ",",
			    region->id, region->bar,
			    (uintmax_t)region->offset,
			    (uintmax_t)region->length);
			if (error != 0)
				return (error);
		}
	}
	return (0);
}

int
vi_pci_pause(struct pci_devinst *pi)
{
	struct virtio_softc *vs;
	struct virtio_consts *vc;
	bool admin_quiesced;
	int error;

	vs = pi->pi_arg;
	vc = vs->vs_vc;

	if (vs->vs_checkpoint_paused)
		return (0);
	/*
	 * Checkpoint pause transfers backend ownership to the matching resume
	 * callback.  Admit the pair atomically: accepting a one-sided callback
	 * would leave a successfully paused device permanently fenced when the
	 * common cleanup path later attempts its inverse.
	 */
	if (vc->vc_pause == NULL || vc->vc_resume == NULL)
		return (EOPNOTSUPP);
	vi_pci_quiesce_enter(vs);
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-pause", "begin", 0);
	/*
	 * Guest suspend drains virtqueues, but checkpoint pause also establishes
	 * backend-specific serialization for state which can change without a
	 * guest queue operation (for example a staged network packet or a media
	 * resize event).  Always take that independent checkpoint ownership.
	 * The backend pause/resume pair must preserve guest-suspend ownership
	 * when the two lifecycles are nested.
	 */
	admin_quiesced = false;
	error = 0;
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		error = virtio_admin_pci_binding_quiesce(
		    vs->vs_admin_binding);
	if (error == 0 &&
	    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		admin_quiesced = true;
	if (error == 0)
		error = (*vc->vc_pause)(DEV_SOFTC(vs));
	if (error != 0) {
		if (admin_quiesced) {
			int rollback_error;

			rollback_error = virtio_admin_pci_binding_unquiesce(
			    vs->vs_admin_binding);
			if (rollback_error != 0) {
				/*
				 * The ordinary backend rejected pause, but the
				 * administration command fence could not be reopened.
				 * Claiming that the source is runnable would strand future
				 * administration commands behind an ownership state which
				 * no longer has a matching checkpoint resume.  Quarantine
				 * the device and report the rollback failure instead.
				 */
				vi_set_needs_reset(vs);
				error = EIO;
			}
		}
		vi_pci_quiesce_exit(vs);
		/*
		 * A failed checkpoint leaves the source device running.  A
		 * guest kick or backend configuration event may have raced the
		 * lifecycle fence, so replay both coalesced hints after restoring
		 * ownership.  A failed administration rollback is terminal and
		 * retains deferred state for the required full reset.
		 */
		if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0 &&
		    vs->vs_config_deferred) {
			vs->vs_config_deferred = false;
			vi_pci_config_changed(vs);
		}
		vi_pci_notify_ready_queues(vs);
		VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-pause",
		    "fail", error);
		return (error);
	}
	vs->vs_checkpoint_paused = true;
	vi_pci_quiesce_exit(vs);
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-pause", "end", 0);

	return (0);
}

int
vi_pci_resume(struct pci_devinst *pi)
{
	struct virtio_softc *vs;
	struct virtio_consts *vc;
	int error;

	vs = pi->pi_arg;
	vc = vs->vs_vc;

	/*
	 * vm_pause_devices() can stop after a device reports an error, while
	 * its cleanup path resumes the complete PCI list.  Do not invoke a
	 * backend resume callback unless this instance actually acquired
	 * checkpoint ownership.
	 */
	if (!vs->vs_checkpoint_paused)
		return (0);
	/* A genuinely paused device still needs a matching backend inverse. */
	if (vc->vc_resume == NULL)
		return (EOPNOTSUPP);
	vi_pci_quiesce_enter(vs);
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-resume", "begin", 0);
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0)
		error = virtio_admin_pci_binding_resume(vs->vs_admin_binding,
		    vc->vc_resume, DEV_SOFTC(vs));
	else
		error = (*vc->vc_resume)(DEV_SOFTC(vs));
	if (error != 0) {
		vi_pci_quiesce_exit(vs);
		VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-resume",
		    "fail", error);
		return (error);
	}
	vs->vs_checkpoint_paused = false;
	vi_pci_quiesce_exit(vs);
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, "checkpoint-resume", "end", 0);
	if (!vs->vs_suspended && vc->vc_resume_complete != NULL)
		(*vc->vc_resume_complete)(DEV_SOFTC(vs));
	if (vs->vs_config_deferred) {
		vs->vs_config_deferred = false;
		vi_pci_config_changed(vs);
	}
	if (!vs->vs_suspended)
		vi_pci_notify_ready_queues(vs);

	return (0);
}

static int
vi_pci_snapshot_softc_modern(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	uint64_t negotiated_caps;
	uint32_t curq, flags, magic, version;
	uint16_t msix_cfg_idx;
	uint8_t config_deferred, isr, reset_failed, status, suspended;
	int ret;

	magic = VIRTIO_MODERN_COMMON_SNAPSHOT_MAGIC;
	version = VIRTIO_MODERN_COMMON_SNAPSHOT_VERSION;
	flags = (uint32_t)vs->vs_flags;
	negotiated_caps = vs->vs_negotiated_caps;
	curq = (uint32_t)vs->vs_curq;
	status = vs->vs_status;
	reset_failed = vs->vs_reset_failed;
	suspended = vs->vs_suspended;
	config_deferred = vs->vs_config_deferred;
	VS_ISR_LOCK(vs);
	isr = vs->vs_isr;
	VS_ISR_UNLOCK(vs);
	msix_cfg_idx = vs->vs_msix_cfg_idx;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (magic != VIRTIO_MODERN_COMMON_SNAPSHOT_MAGIC ||
	    version != VIRTIO_MODERN_COMMON_SNAPSHOT_VERSION) {
		ret = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(flags, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(negotiated_caps, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(curq, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(status, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(reset_failed, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(suspended, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(config_deferred, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(isr, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(msix_cfg_idx, meta, ret, done);

	if (vm_snapshot_is_loading(meta)) {
		const uint8_t valid_status = VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_STATUS_DRIVER_OK |
		    VIRTIO_CONFIG_S_FEATURES_OK |
		    VIRTIO_CONFIG_STATUS_FAILED |
		    VIRTIO_CONFIG_S_NEEDS_RESET |
		    VIRTIO_CONFIG_STATUS_SUSPEND;

		if (reset_failed > 1 || suspended > 1 ||
		    config_deferred > 1 ||
		    flags > INT_MAX || curq > INT_MAX ||
		    (flags & ~VIRTIO_USE_MSIX) != 0 ||
		    (isr & ~(VIRTIO_PCI_ISR_INTR |
		    VIRTIO_PCI_ISR_CONFIG)) != 0 ||
		    (msix_cfg_idx != VIRTIO_MSI_NO_VECTOR &&
		    msix_cfg_idx >=
		    vs->vs_pi->pi_msix.table_count) ||
		    (status & ~valid_status) != 0 ||
		    /*
		     * A snapshot is not a new status-write request: it restores an
		     * already accepted transport state.  Require the monotonic
		     * initialization prefix that vi_modern_status_write() publishes,
		     * rather than accepting a combination which a live device could
		     * never have reached.  FAILED and NEEDS_RESET are deliberately
		     * orthogonal device/driver failure indications and do not relax
		     * these dependencies when the corresponding progress bit is set.
		     */
		    ((status & VIRTIO_CONFIG_STATUS_DRIVER) != 0 &&
		    (status & VIRTIO_CONFIG_STATUS_ACK) == 0) ||
		    ((status & VIRTIO_CONFIG_S_FEATURES_OK) != 0 &&
		    (status & (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER)) !=
		    (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER)) ||
		    ((status & VIRTIO_CONFIG_S_FEATURES_OK) != 0 &&
		    (negotiated_caps & VIRTIO_F_VERSION_1) == 0) ||
		    ((status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0 &&
		    (status & (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_S_FEATURES_OK)) !=
		    (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_S_FEATURES_OK)) ||
		    suspended !=
		    ((status & VIRTIO_CONFIG_STATUS_SUSPEND) != 0) ||
		    (suspended &&
		    ((status & (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_S_FEATURES_OK)) !=
		    (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_S_FEATURES_OK) ||
		    (status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0 ||
		    (negotiated_caps & VIRTIO_F_SUSPEND) == 0)) ||
		    ((status & VIRTIO_CONFIG_S_FEATURES_OK) == 0 &&
		    negotiated_caps != 0) ||
		    (reset_failed &&
		    (status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)) {
			EPRINTLN("%s: inconsistent restored common status",
			    vs->vs_vc->vc_name);
			ret = EINVAL;
			goto done;
		}
		vs->vs_flags = (int)flags;
		vs->vs_negotiated_caps = negotiated_caps;
		vs->vs_curq = (int)curq;
		vs->vs_status = status;
		vs->vs_reset_failed = reset_failed;
		vs->vs_suspended = suspended;
		vs->vs_config_deferred = config_deferred;
		VS_ISR_LOCK(vs);
		vs->vs_isr = isr;
		VS_ISR_UNLOCK(vs);
		vs->vs_msix_cfg_idx = msix_cfg_idx;
	}

done:
	return (ret);
}

static int
vi_pci_snapshot_softc(struct virtio_softc *vs, struct vm_snapshot_meta *meta)
{
	uint32_t curq, flags, legacy_negotiated_caps;
	uint16_t msix_cfg_idx;
	uint8_t isr, status;
	int ret;

	/*
	 * The transitional interface has only the 32-bit legacy feature window.
	 * Do this check before emitting any bytes: truncating here would both make
	 * a malformed live state appear checkpointable and, historically, write
	 * the truncated value back into the running device during SAVE.
	 */
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    (vs->vs_negotiated_caps & ~UINT64_C(0xffffffff)) != 0)
		return (EINVAL);
	flags = (uint32_t)vs->vs_flags;
	legacy_negotiated_caps = (uint32_t)vs->vs_negotiated_caps;
	curq = (uint32_t)vs->vs_curq;
	status = vs->vs_status;
	VS_ISR_LOCK(vs);
	isr = vs->vs_isr;
	VS_ISR_UNLOCK(vs);
	msix_cfg_idx = vs->vs_msix_cfg_idx;

	SNAPSHOT_LE32_OR_LEAVE(flags, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(legacy_negotiated_caps, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(curq, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(status, meta, ret, done);
	SNAPSHOT_U8_OR_LEAVE(isr, meta, ret, done);
	SNAPSHOT_LE16_OR_LEAVE(msix_cfg_idx, meta, ret, done);

	if (vm_snapshot_is_loading(meta)) {
		const uint8_t valid_status = VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER |
		    VIRTIO_CONFIG_STATUS_DRIVER_OK |
		    VIRTIO_CONFIG_S_FEATURES_OK |
		    VIRTIO_CONFIG_STATUS_FAILED |
		    VIRTIO_CONFIG_S_NEEDS_RESET;

		if (flags > INT_MAX || curq > INT_MAX ||
		    (flags & ~VIRTIO_USE_MSIX) != 0 ||
		    (status & ~valid_status) != 0 ||
		    (isr & ~(VIRTIO_PCI_ISR_INTR |
		    VIRTIO_PCI_ISR_CONFIG)) != 0 ||
		    (msix_cfg_idx != VIRTIO_MSI_NO_VECTOR &&
		    msix_cfg_idx >= vs->vs_pi->pi_msix.table_count) ||
		    ((status & VIRTIO_CONFIG_STATUS_DRIVER) != 0 &&
		    (status & VIRTIO_CONFIG_STATUS_ACK) == 0) ||
		    ((status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0 &&
		    (status & (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER)) !=
		    (VIRTIO_CONFIG_STATUS_ACK |
		    VIRTIO_CONFIG_STATUS_DRIVER))) {
			ret = EINVAL;
			goto done;
		}
		vs->vs_flags = (int)flags;
		vs->vs_negotiated_caps = legacy_negotiated_caps;
		vs->vs_curq = (int)curq;
		vs->vs_status = status;
		VS_ISR_LOCK(vs);
		vs->vs_isr = isr;
		VS_ISR_UNLOCK(vs);
		vs->vs_msix_cfg_idx = msix_cfg_idx;
	}

done:
	return (ret);
}

static int
vi_pci_snapshot_consts_modern(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	struct virtio_consts *vc;
	uint64_t cfgsize, current_hv_caps, snapshot_hv_caps;
	uint32_t nvq;
	int ret;

	if (vs == NULL || vs->vs_vc == NULL)
		return (EINVAL);
	vc = vs->vs_vc;
	nvq = (uint32_t)vc->vc_nvq;
	cfgsize = vc->vc_cfgsize;
	/*
	 * Common modern transport bits are part of the guest-visible offer just
	 * as device-model bits are.  Keep the device-local record in step with
	 * vi_pci_snapshot_compat(), rather than treating VERSION_1 (or a later
	 * transport feature) as an impossible negotiated bit during restore.
	 */
	current_hv_caps = vi_modern_device_features(vs);
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    (vs->vs_negotiated_caps & ~current_hv_caps) != 0) {
		EPRINTLN("%s: cannot save modern device with unoffered "
		    "negotiated features %#jx", vc->vc_name,
		    (uintmax_t)(vs->vs_negotiated_caps & ~current_hv_caps));
		return (EINVAL);
	}
	snapshot_hv_caps = current_hv_caps;
	SNAPSHOT_LE32_OR_LEAVE(nvq, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(cfgsize, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(snapshot_hv_caps, meta, ret, done);
	if (vm_snapshot_is_loading(meta)) {
		if (nvq != (uint32_t)vc->vc_nvq ||
		    cfgsize != vc->vc_cfgsize) {
			EPRINTLN("%s: restored modern device shape differs",
			    vc->vc_name);
			ret = EINVAL;
			goto done;
		}
		/*
		 * The outer compatibility envelope checks this for a complete
		 * checkpoint, but this decoder is also used by the per-device
		 * validation pass.  Do not let a malformed device section claim a
		 * negotiated feature that its own saved offer could never have
		 * selected merely because the destination happens to support it.
		 */
		if ((vs->vs_negotiated_caps & ~snapshot_hv_caps) != 0) {
			EPRINTLN("%s: restored modern device negotiated unoffered "
			    "features %#jx", vc->vc_name,
			    (uintmax_t)(vs->vs_negotiated_caps &
			    ~snapshot_hv_caps));
			ret = EINVAL;
			goto done;
		}
		if ((snapshot_hv_caps & ~current_hv_caps) != 0) {
			EPRINTLN("%s: restored modern device lacks saved "
			    "features %#jx", vc->vc_name,
			    (uintmax_t)(snapshot_hv_caps &
			    ~current_hv_caps));
			ret = ENOTSUP;
		}
	}

done:
	return (ret);
}

static int
vi_pci_snapshot_consts(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	struct virtio_consts *vc;
	uint64_t cfgsize;
	uint64_t current_legacy_hv_caps, snapshot_legacy_hv_caps;
	uint32_t nvq;
	int ret;

	if (vs == NULL || vs->vs_vc == NULL)
		return (EINVAL);
	vc = vs->vs_vc;
	nvq = (uint32_t)vc->vc_nvq;
	cfgsize = vc->vc_cfgsize;
	/*
	 * Keep the established 64-bit snapshot slot, but compare only the
	 * legacy-visible feature set and permit the destination to offer a
	 * superset.  New optional legacy features such as EVENT_IDX do not
	 * change the interpretation of a restored device unless the saved
	 * negotiated-feature word selected them.
	 */
	current_legacy_hv_caps = vc->vc_hv_caps & UINT32_MAX;
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    (vs->vs_negotiated_caps & ~current_legacy_hv_caps) != 0) {
		EPRINTLN("%s: cannot save legacy device with unoffered "
		    "negotiated features %#jx", vc->vc_name,
		    (uintmax_t)(vs->vs_negotiated_caps &
		    ~current_legacy_hv_caps));
		return (EINVAL);
	}
	SNAPSHOT_LE32_OR_LEAVE(nvq, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(cfgsize, meta, ret, done);
	snapshot_legacy_hv_caps = current_legacy_hv_caps;
	SNAPSHOT_LE64_OR_LEAVE(snapshot_legacy_hv_caps, meta, ret, done);
	if (vm_snapshot_is_loading(meta)) {
		if (nvq != (uint32_t)vc->vc_nvq ||
		    cfgsize != vc->vc_cfgsize) {
			ret = EINVAL;
			goto done;
		}
		/* See the corresponding modern decoder above. */
		if ((vs->vs_negotiated_caps & ~snapshot_legacy_hv_caps) != 0) {
			EPRINTLN("%s: restored legacy device negotiated unoffered "
			    "features %#jx", vc->vc_name,
			    (uintmax_t)(vs->vs_negotiated_caps &
			    ~snapshot_legacy_hv_caps));
			ret = EINVAL;
		} else if ((snapshot_legacy_hv_caps &
		    ~current_legacy_hv_caps) != 0) {
			EPRINTLN("%s: restored VirtIO device lacks saved features %#jx",
			    __func__, (uintmax_t)(snapshot_legacy_hv_caps &
			    ~current_legacy_hv_caps));
			ret = ENOTSUP;
		}
	}

done:
	return (ret);
}

static int
vi_pci_snapshot_queue_mapping(struct virtio_softc *vs, void **mapping,
    uint64_t gpa, size_t len, enum virtio_dma_direction direction,
    struct vm_snapshot_meta *meta)
{
	uint64_t wire_gpa;
	void *expected;
	int ret;

	/*
	 * Preserve the established address slot, but make the queue's
	 * architecture-neutral DMA address canonical.  Deriving this slot from
	 * a host pointer would encode a guest physical address and become
	 * incorrect once ACCESS_PLATFORM translates an IOVA.
	 */
	wire_gpa = gpa;
	SNAPSHOT_LE64_OR_LEAVE(wire_gpa, meta, ret, done);
	if (wire_gpa != gpa) {
		ret = EINVAL;
		goto done;
	}
	expected = vi_map_dma(vs, gpa, len, direction);
	if (expected == NULL) {
		ret = EFAULT;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (*mapping != expected) {
			ret = EINVAL;
			goto done;
		}
	} else if (vm_snapshot_is_loading(meta)) {
		*mapping = expected;
	} else {
		ret = EINVAL;
	}
done:
	return (ret);
}

/* Validate and reconstruct the three DMA mappings owned by one live queue. */
static int
vi_pci_snapshot_queue_rings_modern(struct virtio_softc *vs,
    struct vqueue_info *saved, bool packed, bool *completion_owned,
    struct vm_snapshot_meta *meta)
{
	size_t avail_size, desc_size, used_size;
	int ret;

	if ((saved->vq_desc_gpa & 15) != 0 ||
	    (saved->vq_driver_gpa & (packed ? 3 : 1)) != 0 ||
	    (saved->vq_device_gpa & 3) != 0 ||
	    (packed && vi_packed_cursors_validate(saved->vq_qsize,
	    saved->vq_last_avail, saved->vq_next_used,
	    saved->vq_save_used) != 0))
		return (EINVAL);
	if (packed && vm_snapshot_is_loading(meta)) {
		if (saved->vq_packed_completions != NULL &&
		    !vq_packed_completions_empty(saved))
			return (EBUSY);
		if (saved->vq_packed_completions == NULL ||
		    saved->vq_packed_completion_count != saved->vq_qsize) {
			saved->vq_packed_completions = calloc(saved->vq_qsize,
			    sizeof(*saved->vq_packed_completions));
			if (saved->vq_packed_completions == NULL)
				return (ENOMEM);
			saved->vq_packed_completion_count = saved->vq_qsize;
			*completion_owned = true;
		}
	}

	if (packed) {
		desc_size = (size_t)saved->vq_qsize *
		    sizeof(struct virtio_packed_desc);
		avail_size = sizeof(struct virtio_packed_event);
		used_size = sizeof(struct virtio_packed_event);
	} else {
		desc_size = (size_t)saved->vq_qsize * sizeof(struct vring_desc);
		avail_size = offsetof(struct vring_avail, ring) +
		    (size_t)saved->vq_qsize * sizeof(uint16_t);
		used_size = offsetof(struct vring_used, ring) +
		    (size_t)saved->vq_qsize * sizeof(struct vring_used_elem);
		if ((vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) != 0) {
			avail_size += sizeof(uint16_t);
			used_size += sizeof(uint16_t);
		}
	}
	if (packed) {
		ret = vi_pci_snapshot_queue_mapping(vs,
		    (void **)&saved->vq_packed_desc, saved->vq_desc_gpa,
		    desc_size, VIRTIO_DMA_BIDIRECTIONAL, meta);
		if (ret == 0)
			ret = vi_pci_snapshot_queue_mapping(vs,
			    (void **)&saved->vq_packed_driver_event,
			    saved->vq_driver_gpa, avail_size,
			    VIRTIO_DMA_DEVICE_READ, meta);
		if (ret == 0)
			ret = vi_pci_snapshot_queue_mapping(vs,
			    (void **)&saved->vq_packed_device_event,
			    saved->vq_device_gpa, used_size,
			    VIRTIO_DMA_DEVICE_WRITE, meta);
	} else {
		ret = vi_pci_snapshot_queue_mapping(vs,
		    (void **)&saved->vq_desc, saved->vq_desc_gpa, desc_size,
		    VIRTIO_DMA_DEVICE_READ, meta);
		if (ret == 0)
			ret = vi_pci_snapshot_queue_mapping(vs,
			    (void **)&saved->vq_avail, saved->vq_driver_gpa,
			    avail_size, VIRTIO_DMA_DEVICE_READ, meta);
		if (ret == 0)
			ret = vi_pci_snapshot_queue_mapping(vs,
			    (void **)&saved->vq_used, saved->vq_device_gpa,
			    used_size, VIRTIO_DMA_DEVICE_WRITE, meta);
	}
	return (ret);
}

/* Atomically publish one fully validated staged queue on the destination. */
static void
vi_pci_restore_queue_modern(struct vqueue_info *vq,
    const struct vqueue_info *saved, bool packed, uint64_t generation)
{

	vq->vq_qsize = saved->vq_qsize;
	vq->vq_flags = saved->vq_flags;
	vq->vq_last_avail = saved->vq_last_avail;
	vq->vq_next_used = saved->vq_next_used;
	vq->vq_save_used = saved->vq_save_used;
	vq->vq_msix_idx = saved->vq_msix_idx;
	vq->vq_enabled = saved->vq_enabled;
	vq->vq_reset = saved->vq_reset;
	vq->vq_resetting = 0;
	vq->vq_notify_pending = saved->vq_notify_pending;
	/* Owner generations are destination-local and never restored. */
	vq->vq_generation = generation;
	vq->vq_desc_gpa = saved->vq_desc_gpa;
	vq->vq_driver_gpa = saved->vq_driver_gpa;
	vq->vq_device_gpa = saved->vq_device_gpa;
	/* Force revalidation against the destination DMA-domain generation. */
	vq->vq_dma_generation = 0;
	vq->vq_dma_generation_valid = false;
	if (packed) {
		vq->vq_layout = VIRTIO_QUEUE_PACKED;
		vq->vq_packed_next_avail = saved->vq_last_avail;
		vq->vq_packed_next_used = saved->vq_next_used;
		vq->vq_packed_save_used = saved->vq_save_used;
		vq->vq_packed_avail_wrap = saved->vq_packed_avail_wrap;
		vq->vq_packed_used_wrap = saved->vq_packed_used_wrap;
		vq->vq_packed_save_used_wrap = saved->vq_packed_save_used_wrap;
		vq->vq_packed_desc = saved->vq_packed_desc;
		vq->vq_packed_driver_event = saved->vq_packed_driver_event;
		vq->vq_packed_device_event = saved->vq_packed_device_event;
		vq->vq_packed_completions = saved->vq_packed_completions;
		vq->vq_packed_completion_count =
		    saved->vq_packed_completion_count;
		vq->vq_desc = NULL;
		vq->vq_avail = NULL;
		vq->vq_used = NULL;
	} else {
		vq->vq_layout = VIRTIO_QUEUE_SPLIT;
		vq->vq_desc = saved->vq_desc;
		vq->vq_avail = saved->vq_avail;
		vq->vq_used = saved->vq_used;
		vq->vq_packed_desc = NULL;
		vq->vq_packed_driver_event = NULL;
		vq->vq_packed_device_event = NULL;
		/* A packed completion cache has no split-ring meaning. */
		vq->vq_packed_completions = NULL;
		vq->vq_packed_completion_count = 0;
	}
}

static int
vi_pci_snapshot_queue_bank_modern(struct virtio_softc *vs,
    struct vqueue_info *queues, int queue_count,
    struct vm_snapshot_meta *meta)
{
	struct virtio_consts *vc;
	struct vqueue_info *saved, *staged, *vq;
	bool *completion_owned;
	uint64_t *restore_generations;
	uint16_t flags, resetting;
	uint8_t notify_pending, packed_wraps;
	bool packed;
	int i, ret;

	vc = vs->vs_vc;
	if (queue_count < 0 || (queue_count != 0 && queues == NULL))
		return (EINVAL);
	if (queue_count == 0)
		return (0);
	packed = (vs->vs_negotiated_caps & VIRTIO_F_RING_PACKED) != 0;
	staged = calloc((size_t)queue_count, sizeof(*staged));
	if (staged == NULL)
		return (ENOMEM);
	completion_owned = calloc((size_t)queue_count,
	    sizeof(*completion_owned));
	if (completion_owned == NULL) {
		free(staged);
		return (ENOMEM);
	}
	restore_generations = NULL;
	if (vm_snapshot_is_loading(meta)) {
		for (i = 0; i < queue_count; i++) {
			if (queues[i].vq_generation == UINT64_MAX) {
				ret = EOVERFLOW;
				goto done;
			}
		}
		restore_generations = calloc((size_t)queue_count,
		    sizeof(*restore_generations));
		if (restore_generations == NULL) {
			ret = ENOMEM;
			goto done;
		}
		for (i = 0; i < queue_count; i++)
			restore_generations[i] =
			    queues[i].vq_generation + 1;
	}
	for (i = 0; i < queue_count; i++) {
		vq = &queues[i];
		if (meta->op == VM_SNAPSHOT_SAVE && vq_is_allocated(vq) &&
		    !vq_refresh_dma_mappings(vq)) {
			ret = EFAULT;
			goto done;
		}
		if (meta->op == VM_SNAPSHOT_SAVE &&
		    vq->vq_layout != (packed ? VIRTIO_QUEUE_PACKED :
		    VIRTIO_QUEUE_SPLIT)) {
			ret = EINVAL;
			goto done;
		}
		if (vq_is_resetting(vq)) {
			EPRINTLN("%s: cannot snapshot resetting queue %d",
			    vc->vc_name, vq->vq_num);
			ret = EBUSY;
			goto done;
		}
		if (!vq_packed_completions_empty(vq)) {
			EPRINTLN("%s: cannot snapshot queue %d with pending "
			    "packed requests or completions", vc->vc_name,
			    vq->vq_num);
			ret = EBUSY;
			goto done;
		}
		/*
		 * Save cannot encode transient request ownership.  Restore also
		 * requires a clean destination queue; otherwise destination-local
		 * owner bits could collide with the restored cursor state.
		 */
		/*
		 * Ownership belongs to the queue incarnation that acquired the
		 * request, not to the layout selected by the incoming snapshot.
		 * A late split completion can therefore coexist with a currently
		 * packed queue after reset (and vice versa).  Require both owner
		 * stores to be empty before replacing any cursor state.
		 */
		if (!vq_split_owners_empty(vq)) {
			EPRINTLN("%s: cannot snapshot queue %d with pending "
			    "split requests", vc->vc_name, vq->vq_num);
			ret = EBUSY;
			goto done;
		}
		saved = &staged[i];
		*saved = *vq;
		if (packed) {
			/*
			 * Preserve the established three-counter slots.  Their
			 * packed interpretation is selected by the negotiated
			 * RING_PACKED feature, which older snapshots could not
			 * legitimately contain.
			 */
			saved->vq_last_avail = saved->vq_packed_next_avail;
			saved->vq_next_used = saved->vq_packed_next_used;
			saved->vq_save_used = saved->vq_packed_save_used;
		}

		SNAPSHOT_LE16_OR_LEAVE(saved->vq_qsize, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_qsize_max, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_num, meta, ret, done);
		flags = saved->vq_flags;
		SNAPSHOT_LE16_OR_LEAVE(flags, meta, ret, done);
		saved->vq_flags = flags;
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_last_avail, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_next_used, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_save_used, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_msix_idx, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_enabled, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(saved->vq_reset, meta, ret, done);
		resetting = saved->vq_resetting;
		SNAPSHOT_LE16_OR_LEAVE(resetting, meta, ret, done);
		if (resetting != 0) {
			ret = EBUSY;
			goto done;
		}
		saved->vq_resetting = 0;
		/*
		 * Keep the existing one-byte snapshot slot, but deserialize into
		 * an integer so a corrupt image cannot create a non-canonical
		 * _Bool representation.
		 */
		notify_pending = saved->vq_notify_pending;
		SNAPSHOT_U8_OR_LEAVE(notify_pending, meta, ret, done);
		if (notify_pending > 1) {
			ret = EINVAL;
			goto done;
		}
		saved->vq_notify_pending = notify_pending;
		if (packed) {
			packed_wraps = vi_packed_wraps_encode(
			    saved->vq_packed_avail_wrap,
			    saved->vq_packed_used_wrap,
			    saved->vq_packed_save_used_wrap);
			SNAPSHOT_U8_OR_LEAVE(packed_wraps, meta, ret, done);
			if (vi_packed_wraps_decode(packed_wraps,
			    &saved->vq_packed_avail_wrap,
			    &saved->vq_packed_used_wrap,
			    &saved->vq_packed_save_used_wrap) != 0) {
				ret = EINVAL;
				goto done;
			}
		}
		SNAPSHOT_LE64_OR_LEAVE(saved->vq_desc_gpa, meta, ret, done);
		SNAPSHOT_LE64_OR_LEAVE(saved->vq_driver_gpa, meta, ret, done);
		SNAPSHOT_LE64_OR_LEAVE(saved->vq_device_gpa, meta, ret, done);

		/*
		 * A device is allowed to expose an unavailable queue by
		 * reporting Queue Size zero.  Preserve that state across a
		 * snapshot, but require it to remain completely disabled.
		 */
		if (saved->vq_qsize_max != vq->vq_qsize_max ||
		    saved->vq_num != vq->vq_num) {
			ret = EINVAL;
			goto done;
		}
		if (saved->vq_qsize_max == 0) {
			if (saved->vq_qsize != 0 || saved->vq_enabled != 0 ||
			    saved->vq_reset != 0 || vq_is_allocated(saved) ||
			    saved->vq_notify_pending ||
			    (saved->vq_msix_idx != VIRTIO_MSI_NO_VECTOR &&
			    saved->vq_msix_idx >=
			    vs->vs_pi->pi_msix.table_count)) {
				ret = EINVAL;
				goto done;
			}
			saved->vq_desc = NULL;
			saved->vq_avail = NULL;
			saved->vq_used = NULL;
			saved->vq_packed_desc = NULL;
			saved->vq_packed_driver_event = NULL;
			saved->vq_packed_device_event = NULL;
			continue;
		}
		if (saved->vq_qsize == 0 ||
		    (!packed && !powerof2(saved->vq_qsize)) ||
		    saved->vq_qsize > saved->vq_qsize_max ||
		    (saved->vq_flags & ~VQ_ALLOC) != 0 ||
		    (saved->vq_enabled != 0 && saved->vq_enabled != 1) ||
		    saved->vq_reset != 0 ||
		    (saved->vq_enabled != 0) != vq_is_allocated(saved) ||
		    (saved->vq_notify_pending &&
		    saved->vq_enabled == 0) ||
		    (saved->vq_msix_idx != VIRTIO_MSI_NO_VECTOR &&
		    saved->vq_msix_idx >= vs->vs_pi->pi_msix.table_count)) {
			ret = EINVAL;
			goto done;
		}
		if (!vq_is_allocated(saved)) {
			saved->vq_desc = NULL;
			saved->vq_avail = NULL;
			saved->vq_used = NULL;
			saved->vq_packed_desc = NULL;
			saved->vq_packed_driver_event = NULL;
			saved->vq_packed_device_event = NULL;
			continue;
		}
		ret = vi_pci_snapshot_queue_rings_modern(vs, saved, packed,
		    &completion_owned[i], meta);
		if (ret != 0)
			goto done;
	}
	if (vm_snapshot_is_loading(meta)) {
		for (i = 0; i < queue_count; i++) {
			vi_pci_restore_queue_modern(&queues[i], &staged[i], packed,
			    restore_generations[i]);
		}
	}
	ret = 0;

done:
	if (ret != 0 || !vm_snapshot_is_loading(meta)) {
		for (i = 0; i < queue_count; i++) {
			if (completion_owned[i])
				vq_packed_completions_fini(&staged[i]);
		}
	}
	free(restore_generations);
	free(completion_owned);
	free(staged);
	return (ret);
}

static int
vi_pci_snapshot_queues_modern(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	struct virtio_dma_lease lease;
	int ret;

	/*
	 * Queue pointers are destination-local mappings, even though the wire
	 * record contains only their architecture-neutral DMA addresses.  Hold a
	 * request-style lease while either serializing the current mappings or
	 * reconstructing them on the destination.  In particular, an
	 * ACCESS_PLATFORM domain must not be detached or have its address-space
	 * selection changed between the descriptor, driver, and device mappings
	 * of one checkpoint operation.
	 */
	lease = (struct virtio_dma_lease) { 0 };
	if (!vi_dma_acquire(vs, &lease))
		return (EBUSY);
	ret = vi_pci_snapshot_queue_bank_modern(vs, vs->vs_queues,
	    vs->vs_vc->vc_nvq, meta);
	if (ret == 0 &&
	    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0) {
		ret = vi_pci_snapshot_queue_bank_modern(vs,
		    vs->vs_admin_queues, vs->vs_admin_queue_count, meta);
	}
	vi_dma_release(vs, &lease);
	return (ret);
}

static int
vi_pci_snapshot_queues(struct virtio_softc *vs, struct vm_snapshot_meta *meta)
{
	void *validation_image;
	size_t ring_size;
	int i;
	int ret;
	struct virtio_consts *vc;
	struct vqueue_info *vq;
	struct vmctx *ctx;
	uint64_t addr_size;
	uint16_t qsize, qnum;
	uint8_t notify_pending;

	ctx = vs->vs_pi->pi_vmctx;
	vc = vs->vs_vc;
	ret = 0;

	/*
	 * Queue generations fence asynchronous completions and are therefore
	 * destination-local runtime state, not portable device state.  Legacy
	 * snapshots predate an on-wire generation slot, but a successful
	 * restore must still create a new queue incarnation.  Validate every
	 * increment before mutating any queue; vi_pci_snapshot() supplies the
	 * outer transaction if a later device-specific restore fails.
	 */
	if (vm_snapshot_is_loading(meta)) {
		for (i = 0; i < vc->vc_nvq; i++) {
			if (vs->vs_queues[i].vq_generation == UINT64_MAX)
				return (EOVERFLOW);
		}
	}

	/* Save virtio queue info */
	for (i = 0; i < vc->vc_nvq; i++) {
		vq = &vs->vs_queues[i];

		qsize = vq->vq_qsize;
		qnum = vq->vq_num;
		SNAPSHOT_LE16_OR_LEAVE(qsize, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(qnum, meta, ret, done);
		if (qsize != vq->vq_qsize || qnum != vq->vq_num) {
			ret = EINVAL;
			goto done;
		}

		SNAPSHOT_LE16_OR_LEAVE(vq->vq_flags, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(vq->vq_last_avail, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(vq->vq_next_used, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(vq->vq_save_used, meta, ret, done);
		SNAPSHOT_LE16_OR_LEAVE(vq->vq_msix_idx, meta, ret, done);
		notify_pending = vq->vq_notify_pending;
		SNAPSHOT_U8_OR_LEAVE(notify_pending, meta, ret, done);
		if (notify_pending > 1) {
			ret = EINVAL;
			goto done;
		}
		vq->vq_notify_pending = notify_pending;

		SNAPSHOT_LE32_OR_LEAVE(vq->vq_pfn, meta, ret, done);

		if (!vq_is_allocated(vq))
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

		ring_size = vring_size_aligned(vq->vq_qsize);
		if (meta->op == VM_SNAPSHOT_VALIDATE) {
			/*
			 * Preflight runs before destination RAM is replaced.  Loading the
			 * redundant legacy ring image directly into vq_desc would corrupt
			 * a still-runnable destination merely by validating a checkpoint;
			 * the outer queue-structure backup cannot undo guest-memory bytes.
			 * Consume the historical wire field into scratch storage instead.
			 */
			validation_image = malloc(ring_size);
			if (validation_image == NULL) {
				ret = ENOMEM;
				goto done;
			}
			ret = vm_snapshot_buf(validation_image, ring_size, meta);
			free(validation_image);
			if (ret != 0) {
				vm_snapshot_buf_err("legacy virtqueue image", meta->op);
				goto done;
			}
		} else {
			SNAPSHOT_BUF_OR_LEAVE(vq->vq_desc, ring_size, meta, ret,
			    done);
		}
	}
	if (vm_snapshot_is_restoring(meta)) {
		for (i = 0; i < vc->vc_nvq; i++)
			vs->vs_queues[i].vq_generation++;
	}

done:
	return (ret);
}

#define	VIRTIO_ADMIN_PCI_STATE_MAX	(16U * 1024U * 1024U)

static int
vi_pci_snapshot_admin_controller(struct virtio_softc *vs,
    struct vm_snapshot_meta *meta)
{
	uint8_t *image;
	uint64_t wire_length;
	size_t expected;
	int error;

	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) == 0)
		return (0);
	if (vs->vs_admin_binding == NULL)
		return (EINVAL);
	error = virtio_admin_pci_binding_state_size(vs->vs_admin_binding,
	    &expected);
	if (error != 0)
		return (error);
	if (expected == 0 || expected > VIRTIO_ADMIN_PCI_STATE_MAX)
		return (EOVERFLOW);
	wire_length = expected;
	SNAPSHOT_LE64_OR_LEAVE(wire_length, meta, error, done);
	if (wire_length != expected) {
		error = ENOTSUP;
		goto done;
	}
	image = malloc(expected);
	if (image == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_admin_pci_binding_state_save(
		    vs->vs_admin_binding, image, expected);
		if (error == 0)
			error = vm_snapshot_buf(image, expected, meta);
		goto free_image;
	}
	error = vm_snapshot_buf(image, expected, meta);
	if (error != 0)
		goto free_image;
	if (meta->op == VM_SNAPSHOT_VALIDATE)
		error = virtio_admin_pci_binding_state_restore_validate(
		    vs->vs_admin_binding, image, expected);
	else
		error = virtio_admin_pci_binding_state_restore(
		    vs->vs_admin_binding, image, expected);
free_image:
	free(image);
done:
	return (error);
}

static int
vi_pci_snapshot_admin_backup(struct virtio_softc *vs, uint8_t **imagep,
    size_t *lengthp)
{
	uint8_t *image;
	size_t length;
	int error;

	*imagep = NULL;
	*lengthp = 0;
	if ((vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) == 0)
		return (0);
	if (vs->vs_admin_binding == NULL)
		return (EINVAL);
	error = virtio_admin_pci_binding_state_size(vs->vs_admin_binding,
	    &length);
	if (error != 0)
		return (error);
	if (length == 0 || length > VIRTIO_ADMIN_PCI_STATE_MAX)
		return (EOVERFLOW);
	image = malloc(length);
	if (image == NULL)
		return (ENOMEM);
	error = virtio_admin_pci_binding_state_save(vs->vs_admin_binding,
	    image, length);
	if (error != 0) {
		free(image);
		return (error);
	}
	*imagep = image;
	*lengthp = length;
	return (0);
}

static int
vi_pci_snapshot_admin_rollback(struct virtio_softc *vs,
    const uint8_t *image, size_t length)
{

	if (image == NULL)
		return (0);
	return (virtio_admin_pci_binding_state_restore(vs->vs_admin_binding,
	    image, length));
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct virtio_pci_modern modern_backup;
	struct vqueue_info *queue_backup;
	uint8_t *admin_backup;
	uint8_t *admin_end;
	uint8_t *admin_start;
	size_t queue_backup_count;
	size_t admin_backup_length;
	size_t admin_end_remaining;
	size_t admin_start_remaining;
	int ret;
	struct pci_devinst *pi;
	struct virtio_softc *vs;
	struct virtio_consts *vc;
	const char *operation;
	uint64_t negotiated_caps_backup;
	int curq_backup, flags_backup;
	uint16_t msix_cfg_idx_backup;
	uint8_t config_deferred_backup, isr_backup, reset_failed_backup;
	uint8_t status_backup, suspended_backup;
	bool admin_restored, have_backup, restore_incomplete;

	pi = meta->dev_data;
	vs = pi->pi_arg;
	vc = vs->vs_vc;
	admin_backup = NULL;
	admin_backup_length = 0;
	admin_end = NULL;
	admin_end_remaining = 0;
	admin_start = NULL;
	admin_start_remaining = 0;
	admin_restored = false;
	queue_backup = NULL;
	queue_backup_count = vi_pci_queue_storage_count(vs);
	have_backup = vm_snapshot_is_loading(meta);
	restore_incomplete = false;
	if (vs->vs_restore_incomplete)
		return (EIO);
	if (have_backup) {
		if (queue_backup_count > SIZE_MAX / sizeof(*queue_backup))
			return (EOVERFLOW);
		if (queue_backup_count != 0) {
			queue_backup = malloc(queue_backup_count *
			    sizeof(*queue_backup));
			if (queue_backup == NULL)
				return (ENOMEM);
			for (size_t i = 0; i < queue_backup_count; i++) {
				struct vqueue_info *vq;

				vq = vi_pci_queue_at(vs, i);
				if (vq == NULL) {
					free(queue_backup);
					return (EINVAL);
				}
				queue_backup[i] = *vq;
			}
		}
		flags_backup = vs->vs_flags;
		negotiated_caps_backup = vs->vs_negotiated_caps;
		curq_backup = vs->vs_curq;
		status_backup = vs->vs_status;
		reset_failed_backup = vs->vs_reset_failed;
		suspended_backup = vs->vs_suspended;
		config_deferred_backup = vs->vs_config_deferred;
		VS_ISR_LOCK(vs);
		isr_backup = vs->vs_isr;
		VS_ISR_UNLOCK(vs);
		msix_cfg_idx_backup = vs->vs_msix_cfg_idx;
		if (vs->vs_modern != NULL)
			modern_backup = *vs->vs_modern;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		operation = "snapshot-save";
	} else if (meta->op == VM_SNAPSHOT_VALIDATE) {
		operation = "snapshot-validate";
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		operation = "snapshot-restore";
	} else {
		operation = "snapshot-invalid";
	}
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, operation, "begin", 0);

	/* Save virtio softc */
	if (vi_pci_is_modern(vs))
		ret = vi_pci_snapshot_softc_modern(vs, meta);
	else
		ret = vi_pci_snapshot_softc(vs, meta);
	if (ret != 0)
		goto done;

	/* Save virtio consts */
	if (vi_pci_is_modern(vs))
		ret = vi_pci_snapshot_consts_modern(vs, meta);
	else
		ret = vi_pci_snapshot_consts(vs, meta);
	if (ret != 0)
		goto done;
	if (!vi_pci_is_modern(vs) && vm_snapshot_is_loading(meta) &&
	    (vs->vs_negotiated_caps & ~vc->vc_hv_caps) != 0) {
		EPRINTLN("%s: restored VirtIO negotiated unsupported features "
		    "%#jx", __func__, (uintmax_t)(vs->vs_negotiated_caps &
		    ~vc->vc_hv_caps));
		ret = ENOTSUP;
		goto done;
	}

	/* Save virtio queue info */
	if (vi_pci_is_modern(vs)) {
		ret = vi_pci_modern_snapshot_transport(vs, meta);
		if (ret != 0)
			goto done;
		ret = vi_pci_snapshot_queues_modern(vs, meta);
	} else
		ret = vi_pci_snapshot_queues(vs, meta);
	if (ret != 0)
		goto done;

	/*
	 * The wire format places device-private state before the optional
	 * administration-controller section.  During restore, first validate a
	 * copy of the device section to find the latter without publishing device
	 * state.  Restore the administration controller from that copied cursor,
	 * retaining its destination image for rollback, and only then publish the
	 * device-private state through the original cursor.  Consequently there
	 * is no fallible external restore after a device callback commits.
	 */
	if (meta->op == VM_SNAPSHOT_RESTORE &&
	    (vs->vs_negotiated_caps & VIRTIO_F_ADMIN_VQ) != 0) {
		struct vm_snapshot_meta admin_meta = {
			.dev_data = meta->dev_data,
			.dev_name = meta->dev_name,
			.dev_req = meta->dev_req,
			.buffer = {
				.buf_start = meta->buffer.buf_start,
				.buf_size = meta->buffer.buf_size,
				.buf = meta->buffer.buf,
				.buf_rem = meta->buffer.buf_rem,
			},
			.op = VM_SNAPSHOT_VALIDATE,
		};

		if (vc->vc_snapshot != NULL) {
			ret = (*vc->vc_snapshot)(DEV_SOFTC(vs), &admin_meta);
			if (ret != 0)
				goto done;
		}
		admin_start = admin_meta.buffer.buf;
		admin_start_remaining = admin_meta.buffer.buf_rem;
		ret = vi_pci_snapshot_admin_backup(vs, &admin_backup,
		    &admin_backup_length);
		if (ret != 0)
			goto done;
		admin_meta.op = VM_SNAPSHOT_RESTORE;
		ret = vi_pci_snapshot_admin_controller(vs, &admin_meta);
		if (ret != 0) {
			if (vi_pci_snapshot_admin_rollback(vs, admin_backup,
			    admin_backup_length) != 0) {
				vi_snapshot_restore_incomplete(vs);
				ret = EIO;
			}
			goto done;
		}
		admin_restored = true;
		admin_end = admin_meta.buffer.buf;
		admin_end_remaining = admin_meta.buffer.buf_rem;
	}

	/* Save device softc, if needed. */
	if (vc->vc_snapshot != NULL) {
		ret = (*vc->vc_snapshot)(DEV_SOFTC(vs), meta);
		if (ret != 0) {
			if (admin_restored &&
			    vi_pci_snapshot_admin_rollback(vs, admin_backup,
			    admin_backup_length) != 0) {
				vi_snapshot_restore_incomplete(vs);
				ret = EIO;
			}
			goto done;
		}
		if (admin_restored &&
		    (meta->buffer.buf != admin_start ||
		    meta->buffer.buf_rem != admin_start_remaining)) {
			/*
			 * VALIDATE and RESTORE must consume the identical device wire
			 * section.  The device may already have published state, so a
			 * disagreement cannot be compensated generically; quarantine
			 * the destination even when controller rollback succeeds.
			 */
			(void)vi_pci_snapshot_admin_rollback(vs, admin_backup,
			    admin_backup_length);
			vi_snapshot_restore_incomplete(vs);
			ret = EPROTO;
			goto done;
		}
	}
	if (admin_restored) {
		/* Consume the already validated and restored admin wire section. */
		meta->buffer.buf = admin_end;
		meta->buffer.buf_rem = admin_end_remaining;
	} else {
		ret = vi_pci_snapshot_admin_controller(vs, meta);
		if (ret != 0)
			goto done;
	}
	/*
	 * A destination which was already guest-suspended already owns its
	 * backend freeze.  Retaining another owner here would leak one reference
	 * on every repeated restore of the same image: checkpoint resume drops
	 * only the checkpoint owner.  The hook is therefore a transition, not a
	 * general "restored state is suspended" notification.
	 */
	if (vm_snapshot_is_restoring(meta) && !suspended_backup &&
	    vs->vs_suspended && vc->vc_restore_suspended != NULL)
		(*vc->vc_restore_suspended)(DEV_SOFTC(vs));
	/*
	 * The inverse transition is equally important.  Checkpoint pause may
	 * have nested above a destination's old guest-suspend owner.  If the
	 * restored image is runnable, drop that old owner first; the subsequent
	 * common checkpoint resume then drops only its own owner.  Otherwise an
	 * external backend can remain permanently quiesced after a successful
	 * restore of a runnable image.
	 */
	if (vm_snapshot_is_restoring(meta) && suspended_backup &&
	    !vs->vs_suspended && vc->vc_restore_resumed != NULL)
		(*vc->vc_restore_resumed)(DEV_SOFTC(vs));

done:
	if (meta->op == VM_SNAPSHOT_RESTORE)
		restore_incomplete = vs->vs_restore_incomplete;
	/*
	 * A restore record is a transaction.  Parsing and compatibility checks
	 * may fail after an earlier common or transport section was accepted.
	 * Put the destination back exactly as it was so callers may report the
	 * failure, retry, or resume the source configuration safely.
	 */
	if ((ret != 0 || meta->op == VM_SNAPSHOT_VALIDATE) && have_backup) {
		for (size_t i = 0; i < queue_backup_count; i++) {
			struct vqueue_info *vq;

			vq = vi_pci_queue_at(vs, i);
			if (vq->vq_packed_completions !=
			    queue_backup[i].vq_packed_completions)
				vq_packed_completions_fini(vq);
		}
		vs->vs_flags = flags_backup;
		vs->vs_negotiated_caps = negotiated_caps_backup;
		vs->vs_curq = curq_backup;
		vs->vs_status = status_backup;
		vs->vs_reset_failed = reset_failed_backup;
		vs->vs_suspended = suspended_backup;
		vs->vs_config_deferred = config_deferred_backup;
		VS_ISR_LOCK(vs);
		vs->vs_isr = isr_backup;
		VS_ISR_UNLOCK(vs);
		vs->vs_msix_cfg_idx = msix_cfg_idx_backup;
		for (size_t i = 0; i < queue_backup_count; i++)
			*vi_pci_queue_at(vs, i) = queue_backup[i];
		if (vs->vs_modern != NULL)
			*vs->vs_modern = modern_backup;
		if (restore_incomplete) {
			vs->vs_restore_incomplete = true;
			vi_set_needs_reset(vs);
		}
	} else if (ret == 0 && have_backup) {
		/*
		 * A packed restore may transactionally replace an empty
		 * destination reorder cache when the saved queue size differs.
		 * The old cache remained alive for rollback; retire it only
		 * after the device-specific restore has also committed.
		 */
		for (size_t i = 0; i < queue_backup_count; i++) {
			struct vqueue_info *vq;

			vq = vi_pci_queue_at(vs, i);
			if (vq->vq_packed_completions !=
			    queue_backup[i].vq_packed_completions)
				vq_packed_completions_fini(&queue_backup[i]);
		}
	}
	free(admin_backup);
	free(queue_backup);
	VIRTIO_PROBE_LIFECYCLE(vc->vc_name, operation, "end", ret);
	return (ret);
}
#endif

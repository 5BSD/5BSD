/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_DMA_H_
#define	_BHYVE_VIRTIO_DMA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Direction is named from the device's point of view.  Keep this contract
 * independent of PCI and of any particular host architecture so transports,
 * IOMMUs, and device models can share it.
 */
enum virtio_dma_direction {
	VIRTIO_DMA_DEVICE_READ,
	VIRTIO_DMA_DEVICE_WRITE,
	VIRTIO_DMA_BIDIRECTIONAL,
};

/*
 * Device-private DMA which is not naturally enclosed by a descriptor request
 * must hold one of these leases across every translation and memory access.
 * In particular, a device shared-memory BAR may be accessed by a vCPU while
 * another vCPU changes the guest IOMMU control plane.
 */
struct virtio_dma_lease {
	bool acquired;
};

/*
 * A DMA domain maps an endpoint's device-visible address.  The endpoint ID
 * is transport-defined; PCI uses the requester ID.  The callback must not
 * retain a transient mapping beyond the device request that obtained it.
 */
struct virtio_dma_domain_ops {
	/*
	 * Bracket one descriptor request.  Dynamic translation domains use
	 * this lifetime to order revoking control operations after DMA which
	 * the device accepted earlier.  The callbacks are optional, but they
	 * must be supplied as a pair.  The common VirtIO core holds its own
	 * request lease for every installed domain, including a static domain
	 * without callbacks, so the domain cannot be detached while a request
	 * still uses one of its mappings.  A successful provider acquire is
	 * released exactly once, including malformed, returned, reset-stale,
	 * and normally completed requests.
	 *
	 * A domain without these callbacks promises that its translations do
	 * not change while it remains installed.  A revocable domain must
	 * supply the callbacks and update its generation when queue mappings
	 * change.
	 */
	bool (*vddo_acquire)(void *, uint32_t);
	void (*vddo_release)(void *, uint32_t);
	void *(*vddo_map)(void *, uint32_t, uint64_t, size_t,
	    enum virtio_dma_direction);
	/*
	 * Return a monotonically changing translation generation.  Every
	 * domain provides this callback (a static domain may always return
	 * zero) so long-lived queue mappings can never silently opt out of
	 * revocation checks.
	 */
	uint64_t (*vddo_generation)(void *);
};

#endif

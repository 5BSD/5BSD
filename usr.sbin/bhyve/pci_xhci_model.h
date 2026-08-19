/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PCI_XHCI_MODEL_H_
#define	_PCI_XHCI_MODEL_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/*
 * Monotonic deadline arithmetic for the xHCI checkpoint drain fence.  Kept
 * here, libc-only, so the rootless model tests can exercise the carry and
 * comparison edges an in-tree caller would only hit under scheduler pressure.
 */
static inline struct timespec
pci_xhci_drain_deadline(struct timespec now, uint64_t timeout_ns)
{

	now.tv_sec += (time_t)(timeout_ns / 1000000000ULL);
	now.tv_nsec += (long)(timeout_ns % 1000000000ULL);
	if (now.tv_nsec >= 1000000000L) {
		now.tv_sec++;
		now.tv_nsec -= 1000000000L;
	}
	return (now);
}

static inline bool
pci_xhci_drain_deadline_expired(struct timespec now, struct timespec deadline)
{

	if (now.tv_sec != deadline.tv_sec)
		return (now.tv_sec > deadline.tv_sec);
	return (now.tv_nsec >= deadline.tv_nsec);
}

/*
 * An ERST entry is guest memory.  Once the event ring has been mapped, its
 * geometry is immutable until the guest reprograms ERSTBA.  Event delivery
 * must use the cached mapping geometry and reject a guest mutation rather
 * than using a larger live table size to index past the mapped ring.
 */
static inline bool
pci_xhci_event_ring_geometry_matches(uint32_t mapped_count,
    uint64_t mapped_base, uint32_t table_count, uint64_t table_base)
{

	return (mapped_count != 0 && table_count == mapped_count &&
	    table_base == mapped_base);
}

#endif /* _PCI_XHCI_MODEL_H_ */

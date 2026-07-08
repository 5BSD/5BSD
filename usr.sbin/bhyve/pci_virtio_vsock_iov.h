/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bounded scatter/gather copy helpers for the virtio-vsock device, extracted
 * to a header so they can be unit-tested (tests/sys/kern/vsock_iov_test.c)
 * without the bhyve device's virtio/vmmapi/mevent dependencies.
 *
 * Every helper is bounded by BOTH the byte length and the descriptor count
 * niov.  The caller MUST pass the real descriptor count already clamped to the
 * iov[] array size: vq_getchain() can report more descriptors than it stored
 * in iov[] (it caps the fill but keeps counting), so the device checks
 * "n > VTVSOCK_MAX_IOV" before calling any of these.  These helpers never read
 * or write past iov[niov - 1].
 */

#ifndef _PCI_VIRTIO_VSOCK_IOV_H_
#define	_PCI_VIRTIO_VSOCK_IOV_H_

#include <sys/param.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Return true if any of the first niov descriptors has a NULL base.  A guest
 * descriptor whose address falls outside guest RAM yields a NULL iov_base
 * (paddr_guest2host() -> vm_map_gpa() returns NULL); copying to/from it would
 * SIGSEGV the host process.  Callers reject such chains before copying.
 */
static inline bool
iov_has_null_base(const struct iovec *iov, int niov)
{
	for (int i = 0; i < niov; i++)
		if (iov[i].iov_base == NULL)
			return (true);
	return (false);
}

/*
 * Copy up to <len> bytes of <src> into the scatter/gather list <iov>/<niov>,
 * starting at byte offset <*offp> within the iov.  Advances *offp.
 * Returns the number of bytes actually written.
 */
static inline size_t
iov_copyout(const void *src, size_t len, const struct iovec *iov, int niov,
    size_t *offp)
{
	size_t skip = *offp;
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		uint8_t *base = (uint8_t *)iov[i].iov_base;
		size_t   cap  = iov[i].iov_len;

		if (skip >= cap) {
			skip -= cap;
			continue;
		}
		base += skip;
		cap  -= skip;
		skip  = 0;

		size_t n = MIN(cap, len - done);
		memcpy(base, (const uint8_t *)src + done, n);
		done += n;
	}
	*offp += done;
	return (done);
}

/*
 * Total byte capacity of an iov array.
 */
static inline size_t
iov_total(const struct iovec *iov, int niov)
{
	size_t total = 0;
	for (int i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

/*
 * Copy bytes out of an iov array into a flat buffer, starting from the
 * beginning of the iov.  Returns the number of bytes copied.
 */
static inline size_t
iov_copyin(void *dst, size_t len, const struct iovec *iov, int niov)
{
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		size_t n = MIN(iov[i].iov_len, len - done);
		memcpy((uint8_t *)dst + done, iov[i].iov_base, n);
		done += n;
	}
	return (done);
}

/*
 * Copy bytes out of an iov array into a flat buffer, starting from byte
 * offset <skip> within the iov.  Returns the number of bytes copied.
 */
static inline size_t
iov_copyin_offset(void *dst, size_t len, const struct iovec *iov, int niov,
    size_t skip)
{
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		uint8_t *base = (uint8_t *)iov[i].iov_base;
		size_t   cap  = iov[i].iov_len;

		if (skip >= cap) {
			skip -= cap;
			continue;
		}
		base += skip;
		cap  -= skip;
		skip  = 0;

		size_t n = MIN(cap, len - done);
		memcpy((uint8_t *)dst + done, base, n);
		done += n;
	}
	return (done);
}

#endif /* _PCI_VIRTIO_VSOCK_IOV_H_ */

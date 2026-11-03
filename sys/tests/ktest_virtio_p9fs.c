/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Scatter lists built by the virtio 9P transport for physically fragmented
 * message buffers.  p9fs_buf_zone items are virtually contiguous only, so a
 * guest with fragmented memory hands the transport a buffer with one
 * physical range per page.  These tests map separately allocated pages in
 * descending physical order, so no two neighbouring pages can coalesce, and
 * run the result through the driver's vt9p_req_sglist().
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sglist.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include <fs/p9fs/p9_client.h>
#include <dev/virtio/p9fs/virtio_p9fs.h>

#include <tests/ktest.h>

#define	CHECK(ctx, condition, ...) do {                              \
	if (!(condition)) {                                           \
		KTEST_ERR((ctx), __VA_ARGS__);                          \
		error = EINVAL;                                         \
		goto out;                                               \
	}                                                              \
} while (0)

/* Start the buffers inside their first page so they touch one more page. */
#define	SCATTER_OFFSET	512

struct scattered_buf {
	vm_page_t	pages[VT9P_BUF_NSEGS(P9FS_MTU)];
	int		npages;
	char		*kva;
};

static int
page_paddr_descending(const void *a, const void *b)
{
	vm_paddr_t pa, pb;

	pa = VM_PAGE_TO_PHYS(*(const vm_page_t *)a);
	pb = VM_PAGE_TO_PHYS(*(const vm_page_t *)b);
	return (pa < pb ? 1 : pa > pb ? -1 : 0);
}

/* Map npages separately allocated pages, highest physical address first. */
static void
scattered_buf_alloc(struct scattered_buf *buf, int npages)
{
	int i;

	MPASS(npages <= nitems(buf->pages));
	buf->npages = npages;
	for (i = 0; i < npages; i++)
		buf->pages[i] = vm_page_alloc_noobj(VM_ALLOC_WIRED |
		    VM_ALLOC_WAITOK);
	qsort(buf->pages, npages, sizeof(buf->pages[0]),
	    page_paddr_descending);
	buf->kva = kva_alloc(ptoa(npages));
	pmap_qenter(buf->kva, buf->pages, npages);
}

static void
scattered_buf_free(struct scattered_buf *buf)
{
	int i;

	if (buf->kva == NULL)
		return;
	pmap_qremove(buf->kva, buf->npages);
	kva_free(buf->kva, ptoa(buf->npages));
	for (i = 0; i < buf->npages; i++) {
		vm_page_unwire_noq(buf->pages[i]);
		vm_page_free(buf->pages[i]);
	}
	buf->kva = NULL;
}

/* Check that segments [first, first + buf->npages) are exactly its pages. */
static bool
segments_match(struct sglist *sg, int first, struct scattered_buf *buf,
    size_t len)
{
	struct sglist_seg *seg;
	vm_paddr_t expected;
	size_t seglen;
	int i;

	for (i = 0; i < buf->npages; i++) {
		seg = &sg->sg_segs[first + i];
		expected = VM_PAGE_TO_PHYS(buf->pages[i]);
		seglen = PAGE_SIZE;
		if (i == 0) {
			expected += SCATTER_OFFSET;
			seglen -= SCATTER_OFFSET;
		}
		seglen = MIN(seglen, len);
		if (seg->ss_paddr != expected || seg->ss_len != seglen)
			return (false);
		len -= seglen;
	}
	return (len == 0);
}

/*
 * Build a request of msize bytes and a response of msize bytes in buffers
 * that touch one page more than msize needs, into a list of nsegs segments.
 */
static int
run_scattered_request(struct ktest_test_context *ctx, u_int msize, int nsegs)
{
	struct scattered_buf tc_buf, rc_buf;
	struct p9_req_t req;
	struct sglist *sg;
	int error, npages, readable, writable;

	bzero(&tc_buf, sizeof(tc_buf));
	bzero(&rc_buf, sizeof(rc_buf));
	sg = NULL;
	error = 0;

	npages = VT9P_BUF_NSEGS(msize);
	CHECK(ctx, npages <= nitems(tc_buf.pages),
	    "msize %u exceeds P9FS_MTU", msize);
	scattered_buf_alloc(&tc_buf, npages);
	scattered_buf_alloc(&rc_buf, npages);
	sg = sglist_alloc(nsegs, M_WAITOK);

	bzero(&req, sizeof(req));
	req.tc.sdata = tc_buf.kva + SCATTER_OFFSET;
	req.tc.size = msize;
	req.tc.capacity = msize;
	req.rc.sdata = rc_buf.kva + SCATTER_OFFSET;
	req.rc.capacity = msize;

	error = vt9p_req_sglist(sg, &req, &readable, &writable);
	CHECK(ctx, error == 0,
	    "%u-byte request and response in %d scattered pages each did not "
	    "fit %d segments: error %d", msize, npages, nsegs, error);
	CHECK(ctx, readable == npages && writable == npages,
	    "expected %d readable and %d writable segments, got %d and %d",
	    npages, npages, readable, writable);
	CHECK(ctx, segments_match(sg, 0, &tc_buf, msize),
	    "request segments do not follow its scattered pages");
	CHECK(ctx, segments_match(sg, readable, &rc_buf, msize),
	    "response segments do not follow its scattered pages");
out:
	if (sg != NULL)
		sglist_free(sg);
	scattered_buf_free(&rc_buf);
	scattered_buf_free(&tc_buf);
	return (error);
}

static int
test_scattered_mtu_request(struct ktest_test_context *ctx)
{

	return (run_scattered_request(ctx, P9FS_MTU, VT9P_MAX_NSEGS));
}

/*
 * Without indirect descriptors attach offers VT9P_NSEGS_MSIZE(queue size);
 * messages of that size must fit a list of queue-size segments.
 */
static int
test_queue_limited_msize(struct ktest_test_context *ctx)
{
	static const int qsizes[] = { 4, 5, 16, 32, 65 };
	int error, i;

	for (i = 0; i < nitems(qsizes); i++) {
		error = run_scattered_request(ctx,
		    VT9P_NSEGS_MSIZE(qsizes[i]), qsizes[i]);
		if (error != 0)
			return (error);
	}
	return (0);
}

static const struct ktest_test_info tests[] = {
	{
		.name = "scattered_mtu_request",
		.desc = "P9FS_MTU request and response in scattered pages fit the transport scatter list",
		.func = test_scattered_mtu_request,
	},
	{
		.name = "queue_limited_msize",
		.desc = "the msize offered for a small queue fits that many segments",
		.func = test_queue_limited_msize,
	},
};

KTEST_MODULE_DECLARE(ktest_virtio_p9fs, tests);
KTEST_MODULE_DEPEND(ktest_virtio_p9fs, virtio_p9fs);

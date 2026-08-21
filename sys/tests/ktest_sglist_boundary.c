/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/sglist.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <tests/ktest.h>

#define	CHECK(ctx, condition, ...) do {                              \
	if (!(condition)) {                                           \
		KTEST_ERR((ctx), __VA_ARGS__);                          \
		return (EINVAL);                                        \
	}                                                              \
} while (0)

static int
test_virtual_adjacent_boundary(struct ktest_test_context *ctx)
{
	struct sglist_seg boundary_segs[4], ordinary_segs[4];
	struct sglist boundary, ordinary;
	char buffer[128] __aligned(128);
	int error;

	sglist_init(&ordinary, nitems(ordinary_segs), ordinary_segs);
	error = sglist_append(&ordinary, buffer, 64);
	CHECK(ctx, error == 0, "first ordinary append failed: %d", error);
	error = sglist_append(&ordinary, buffer + 64, 64);
	CHECK(ctx, error == 0, "second ordinary append failed: %d", error);
	CHECK(ctx, ordinary.sg_nseg == 1,
	    "physically adjacent ordinary buffers did not coalesce: %u",
	    ordinary.sg_nseg);

	sglist_init(&boundary, nitems(boundary_segs), boundary_segs);
	error = sglist_append(&boundary, buffer, 64);
	CHECK(ctx, error == 0, "first boundary-list append failed: %d", error);
	error = sglist_append_boundary(&boundary, buffer + 64, 64);
	CHECK(ctx, error == 0, "boundary append failed: %d", error);
	CHECK(ctx, boundary.sg_nseg == 2,
	    "boundary append collapsed adjacent buffers: %u", boundary.sg_nseg);
	CHECK(ctx, boundary.sg_segs[0].ss_len == 64 &&
	    boundary.sg_segs[1].ss_len == 64,
	    "boundary append produced lengths %zu,%zu",
	    boundary.sg_segs[0].ss_len, boundary.sg_segs[1].ss_len);
	CHECK(ctx, boundary.sg_segs[0].ss_paddr + 64 ==
	    boundary.sg_segs[1].ss_paddr,
	    "test buffers are not physically adjacent");

	return (0);
}

static int
test_physical_boundary_and_zero_length(struct ktest_test_context *ctx)
{
	struct sglist_seg segs[3];
	struct sglist sg;
	int error;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append_phys(&sg, 0x1000, 0x100);
	CHECK(ctx, error == 0, "initial physical append failed: %d", error);
	error = sglist_append_phys_boundary(&sg, 0x1100, 0x80);
	CHECK(ctx, error == 0, "physical boundary append failed: %d", error);
	CHECK(ctx, sg.sg_nseg == 2,
	    "physical boundary was coalesced: %u", sg.sg_nseg);
	error = sglist_append_phys_boundary(&sg, 0x1180, 0);
	CHECK(ctx, error == 0 && sg.sg_nseg == 2,
	    "zero-length boundary changed list: error=%d nseg=%u", error,
	    sg.sg_nseg);
	return (0);
}

static int
test_boundary_failure_is_atomic(struct ktest_test_context *ctx)
{
	struct sglist_seg seg;
	struct sglist sg;
	vm_paddr_t original_paddr;
	size_t original_len;
	char byte;
	int error;

	sglist_init(&sg, 1, &seg);
	error = sglist_append_phys(&sg, 0x2000, 0x40);
	CHECK(ctx, error == 0, "initial append failed: %d", error);
	original_paddr = sg.sg_segs[0].ss_paddr;
	original_len = sg.sg_segs[0].ss_len;
	error = sglist_append_boundary(&sg, &byte, sizeof(byte));
	CHECK(ctx, error == EFBIG, "full list returned %d, expected EFBIG", error);
	CHECK(ctx, sg.sg_nseg == 1 &&
	    sg.sg_segs[0].ss_paddr == original_paddr &&
	    sg.sg_segs[0].ss_len == original_len,
	    "failed boundary append mutated the original list");
	return (0);
}

static int
test_vmpages_boundary_straddle(struct ktest_test_context *ctx)
{
	struct sglist_seg segs[4];
	struct sglist sg;
	vm_page_t pages[2];
	vm_offset_t address;
	vm_paddr_t first;
	void *allocation;
	u_short nseg;
	size_t first_len, second_len;
	vm_paddr_t second_paddr;
	int error;

	allocation = contigmalloc(2 * PAGE_SIZE, M_TEMP, M_WAITOK | M_ZERO,
	    0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	CHECK(ctx, allocation != NULL, "contiguous allocation failed");
	address = (vm_offset_t)allocation;
	pages[0] = PHYS_TO_VM_PAGE(pmap_kextract(address));
	pages[1] = PHYS_TO_VM_PAGE(pmap_kextract(address + PAGE_SIZE));
	if (pages[0] == NULL || pages[1] == NULL) {
		contigfree(allocation, 2 * PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "could not resolve allocation pages");
		return (EINVAL);
	}
	first = VM_PAGE_TO_PHYS(pages[0]) + PAGE_SIZE - 16;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append_phys(&sg, first - 16, 16);
	if (error != 0) {
		contigfree(allocation, 2 * PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "initial physical append failed: %d", error);
		return (EINVAL);
	}
	error = sglist_append_vmpages_boundary(&sg, pages, PAGE_SIZE - 16, 32);
	nseg = sg.sg_nseg;
	first_len = sg.sg_segs[0].ss_len;
	second_paddr = nseg > 1 ? sg.sg_segs[1].ss_paddr : 0;
	second_len = nseg > 1 ? sg.sg_segs[1].ss_len : 0;
	contigfree(allocation, 2 * PAGE_SIZE, M_TEMP);
	CHECK(ctx, error == 0, "VM-page boundary append failed: %d", error);
	CHECK(ctx, nseg == 2,
	    "VM-page boundary collapsed or split incorrectly: %u", nseg);
	CHECK(ctx, first_len == 16 && second_paddr == first && second_len == 32,
	    "VM-page straddle produced unexpected segments");
	return (0);
}

static int
test_vmpages_partial_failure_is_atomic(struct ktest_test_context *ctx)
{
	struct sglist_seg segs[2];
	struct sglist sg;
	vm_page_t pages[2];
	vm_offset_t address;
	vm_paddr_t original_paddr, restored_paddr;
	void *allocation;
	size_t original_len;
	u_short nseg;
	int error;

	allocation = contigmalloc(3 * PAGE_SIZE, M_TEMP, M_WAITOK | M_ZERO,
	    0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	CHECK(ctx, allocation != NULL, "contiguous allocation failed");
	address = (vm_offset_t)allocation;
	pages[0] = PHYS_TO_VM_PAGE(pmap_kextract(address));
	pages[1] = PHYS_TO_VM_PAGE(pmap_kextract(address + 2 * PAGE_SIZE));
	if (pages[0] == NULL || pages[1] == NULL) {
		contigfree(allocation, 3 * PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "could not resolve allocation pages");
		return (EINVAL);
	}

	sglist_init(&sg, nitems(segs), segs);
	original_paddr = VM_PAGE_TO_PHYS(pages[0]) + PAGE_SIZE - 32;
	error = sglist_append_phys(&sg, original_paddr, 16);
	if (error != 0) {
		contigfree(allocation, 3 * PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "initial physical append failed: %d", error);
		return (EINVAL);
	}
	original_len = sg.sg_segs[0].ss_len;
	error = sglist_append_vmpages_boundary(&sg, pages, PAGE_SIZE - 16, 32);
	nseg = sg.sg_nseg;
	restored_paddr = sg.sg_segs[0].ss_paddr;
	original_len = sg.sg_segs[0].ss_len;
	contigfree(allocation, 3 * PAGE_SIZE, M_TEMP);

	CHECK(ctx, error == EFBIG,
	    "partially appended VM pages returned %d, expected EFBIG", error);
	CHECK(ctx, nseg == 1 && restored_paddr == original_paddr &&
	    original_len == 16,
	    "partial failure did not restore original list: nseg=%u paddr=%#jx len=%zu",
	    nseg, (uintmax_t)restored_paddr, original_len);
	return (0);
}

static int
test_bio_boundary_direction_split(struct ktest_test_context *ctx)
{
	struct sglist_seg segs[3];
	struct sglist sg;
	struct bio bio;
	char buffer[128] __aligned(128);
	int error;

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, buffer, 64);
	CHECK(ctx, error == 0, "request append failed: %d", error);
	bzero(&bio, sizeof(bio));
	bio.bio_data = buffer + 64;
	bio.bio_bcount = 64;
	error = sglist_append_bio_boundary(&sg, &bio);
	CHECK(ctx, error == 0, "BIO boundary append failed: %d", error);
	CHECK(ctx, sg.sg_nseg == 2,
	    "BIO boundary collapsed adjacent request and data: %u", sg.sg_nseg);
	return (0);
}

static int
test_unmapped_bio_boundary_and_ordinary_compatibility(
    struct ktest_test_context *ctx)
{
	struct sglist_seg boundary_segs[3], ordinary_segs[3];
	struct sglist boundary, ordinary;
	struct bio bio;
	vm_page_t page;
	vm_offset_t address;
	vm_paddr_t paddr;
	void *allocation;
	int error;

	allocation = contigmalloc(PAGE_SIZE, M_TEMP, M_WAITOK | M_ZERO,
	    0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	CHECK(ctx, allocation != NULL, "contiguous allocation failed");
	address = (vm_offset_t)allocation;
	page = PHYS_TO_VM_PAGE(pmap_kextract(address));
	if (page == NULL) {
		contigfree(allocation, PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "could not resolve allocation page");
		return (EINVAL);
	}
	paddr = VM_PAGE_TO_PHYS(page);
	bzero(&bio, sizeof(bio));
	bio.bio_flags = BIO_UNMAPPED;
	bio.bio_ma = &page;
	bio.bio_ma_offset = 64;
	bio.bio_bcount = 64;

	sglist_init(&ordinary, nitems(ordinary_segs), ordinary_segs);
	error = sglist_append_phys(&ordinary, paddr, 64);
	if (error == 0)
		error = sglist_append_bio(&ordinary, &bio);
	if (error != 0) {
		contigfree(allocation, PAGE_SIZE, M_TEMP);
		KTEST_ERR(ctx, "ordinary unmapped BIO append failed: %d", error);
		return (EINVAL);
	}
	sglist_init(&boundary, nitems(boundary_segs), boundary_segs);
	error = sglist_append_phys(&boundary, paddr, 64);
	if (error == 0)
		error = sglist_append_bio_boundary(&boundary, &bio);
	contigfree(allocation, PAGE_SIZE, M_TEMP);
	CHECK(ctx, error == 0, "boundary unmapped BIO append failed: %d", error);
	CHECK(ctx, ordinary.sg_nseg == 1,
	    "ordinary VM-page append no longer coalesces: %u", ordinary.sg_nseg);
	CHECK(ctx, boundary.sg_nseg == 2,
	    "unmapped BIO boundary was coalesced: %u", boundary.sg_nseg);
	return (0);
}

static int
test_zero_capacity_is_rejected(struct ktest_test_context *ctx)
{
	struct sglist sg;
	struct bio bio;
	char byte;

	sglist_init(&sg, 0, NULL);
	bzero(&bio, sizeof(bio));
	bio.bio_data = &byte;
	bio.bio_bcount = sizeof(byte);
	CHECK(ctx, sglist_append_boundary(&sg, &byte, sizeof(byte)) == EINVAL,
	    "virtual boundary accepted a zero-capacity list");
	CHECK(ctx, sglist_append_phys_boundary(&sg, 0x1000, 1) == EINVAL,
	    "physical boundary accepted a zero-capacity list");
	CHECK(ctx, sglist_append_bio_boundary(&sg, &bio) == EINVAL,
	    "BIO boundary accepted a zero-capacity list");
	return (0);
}

static const struct ktest_test_info tests[] = {
	{
		.name = "virtual_adjacent_boundary",
		.desc = "adjacent virtual buffers retain a forced descriptor boundary",
		.func = test_virtual_adjacent_boundary,
	},
	{
		.name = "physical_boundary_and_zero_length",
		.desc = "physical ranges split only for non-empty boundary appends",
		.func = test_physical_boundary_and_zero_length,
	},
	{
		.name = "boundary_failure_is_atomic",
		.desc = "capacity failure leaves the original scatter/gather list intact",
		.func = test_boundary_failure_is_atomic,
	},
	{
		.name = "vmpages_boundary_straddle",
		.desc = "a boundary survives while contiguous pages coalesce internally",
		.func = test_vmpages_boundary_straddle,
	},
	{
		.name = "vmpages_partial_failure_is_atomic",
		.desc = "a failure after the first new segment restores the whole list",
		.func = test_vmpages_partial_failure_is_atomic,
	},
	{
		.name = "bio_boundary_direction_split",
		.desc = "BIO data cannot merge with the preceding request descriptor",
		.func = test_bio_boundary_direction_split,
	},
	{
		.name = "unmapped_bio_boundary_and_ordinary_compatibility",
		.desc = "unmapped BIOs split only when the boundary API requests it",
		.func = test_unmapped_bio_boundary_and_ordinary_compatibility,
	},
	{
		.name = "zero_capacity_is_rejected",
		.desc = "all boundary entry points reject a zero-capacity list",
		.func = test_zero_capacity_is_rejected,
	},
};

KTEST_MODULE_DECLARE(ktest_sglist_boundary, tests);

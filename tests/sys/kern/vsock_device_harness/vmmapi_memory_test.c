/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>

#include "vmmapi_memory.c"

ATF_TC_WITHOUT_HEAD(domain_distribution);
ATF_TC_BODY(domain_distribution, tc)
{
	size_t sizes[8];

	ATF_REQUIRE_EQ(vm_distribute_memory_domains(12 * PAGE_SIZE, 3,
	    PAGE_SIZE, sizes, nitems(sizes)), 0);
	ATF_CHECK_EQ(sizes[0], 4 * PAGE_SIZE);
	ATF_CHECK_EQ(sizes[1], 4 * PAGE_SIZE);
	ATF_CHECK_EQ(sizes[2], 4 * PAGE_SIZE);

	ATF_REQUIRE_EQ(vm_distribute_memory_domains(14 * PAGE_SIZE, 3,
	    PAGE_SIZE, sizes, nitems(sizes)), 0);
	ATF_CHECK_EQ(sizes[0], 5 * PAGE_SIZE);
	ATF_CHECK_EQ(sizes[1], 5 * PAGE_SIZE);
	ATF_CHECK_EQ(sizes[2], 4 * PAGE_SIZE);
	ATF_CHECK_EQ(sizes[0] + sizes[1] + sizes[2], 14 * PAGE_SIZE);
	for (size_t i = 0; i < 3; i++)
		ATF_CHECK_EQ(sizes[i] % PAGE_SIZE, 0);
}

ATF_TC_WITHOUT_HEAD(device_memory_segment_namespace);
ATF_TC_BODY(device_memory_segment_namespace, tc)
{

	(void)tc;
	ATF_CHECK(!vmmapi_devmem_segid_valid(VM_SYSMEM));
	ATF_CHECK(vmmapi_devmem_segid_valid(VM_BOOTROM));
	ATF_CHECK(vmmapi_devmem_segid_valid(VM_MEMSEG_END - 1));
	ATF_CHECK(!vmmapi_devmem_segid_valid(VM_MEMSEG_END));
}

ATF_TC_WITHOUT_HEAD(domain_distribution_rejects_invalid);
ATF_TC_BODY(domain_distribution_rejects_invalid, tc)
{
	size_t sizes[3] = { 11, 22, 33 };

	ATF_CHECK_EQ(vm_distribute_memory_domains(0, 1, PAGE_SIZE,
	    sizes, nitems(sizes)), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(PAGE_SIZE, 0,
	    PAGE_SIZE, sizes, nitems(sizes)), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(PAGE_SIZE, 1, 0,
	    sizes, nitems(sizes)), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(PAGE_SIZE, 1,
	    PAGE_SIZE, NULL, nitems(sizes)), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(3 * PAGE_SIZE, 3,
	    PAGE_SIZE, sizes, 2), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(PAGE_SIZE + 1, 1,
	    PAGE_SIZE, sizes, nitems(sizes)), EINVAL);
	ATF_CHECK_EQ(vm_distribute_memory_domains(2 * PAGE_SIZE, 3,
	    PAGE_SIZE, sizes, nitems(sizes)), EINVAL);

	/* Rejections are transactional. */
	ATF_CHECK_EQ(sizes[0], 11);
	ATF_CHECK_EQ(sizes[1], 22);
	ATF_CHECK_EQ(sizes[2], 33);
}

ATF_TC_WITHOUT_HEAD(layout_boundaries);
ATF_TC_BODY(layout_boundaries, tc)
{
	struct vmmapi_memory_layout layout;
	const size_t below[] = { 1 * 1024 * 1024, 2 * 1024 * 1024 };
	const size_t split[] = { 3ULL * 1024 * 1024 * 1024,
	    1ULL * 1024 * 1024 * 1024 };

	ATF_REQUIRE_EQ(vmmapi_memory_layout_calculate(below, nitems(below),
	    3ULL << 30, 4ULL << 30, 4ULL << 20, UINT64_MAX, &layout), 0);
	ATF_CHECK_EQ(layout.guest_size, 3ULL << 20);
	ATF_CHECK_EQ(layout.address_span, 3ULL << 20);
	ATF_CHECK_EQ(layout.reservation_size, 11ULL << 20);

	ATF_REQUIRE_EQ(vmmapi_memory_layout_calculate(split, nitems(split),
	    3ULL << 30, 4ULL << 30, 4ULL << 20, UINT64_MAX, &layout), 0);
	ATF_CHECK_EQ(layout.guest_size, 4ULL << 30);
	ATF_CHECK_EQ(layout.address_span, 5ULL << 30);
	ATF_CHECK_EQ(layout.reservation_size,
	    (5ULL << 30) + (8ULL << 20));
}

ATF_TC_WITHOUT_HEAD(layout_rejects_invalid_and_overflow);
ATF_TC_BODY(layout_rejects_invalid_and_overflow, tc)
{
	struct vmmapi_memory_layout layout;
	const size_t zero[] = { 0 };
	const size_t one[] = { 1 };
	const size_t huge[] = { SIZE_MAX, 1 };

	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(NULL, 1, 0, 0, 0,
	    UINT64_MAX, &layout), EINVAL);
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(one, 0, 0, 0, 0,
	    UINT64_MAX, &layout), EINVAL);
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(zero, nitems(zero), 0, 0,
	    0, UINT64_MAX, &layout), EINVAL);
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(one, nitems(one), 2, 1, 0,
	    UINT64_MAX, &layout), EINVAL);
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(huge, nitems(huge), 0, 0,
	    0, UINT64_MAX, &layout), EOVERFLOW);

	/* Model a 32-bit host without depending on the test compiler ABI. */
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(one, nitems(one), 0,
	    UINT32_MAX, 1, UINT32_MAX, &layout), EOVERFLOW);

	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(one, nitems(one), 0,
	    UINT64_MAX, 0, UINT64_MAX, &layout), EOVERFLOW);
	ATF_CHECK_EQ(vmmapi_memory_layout_calculate(one, nitems(one), 0, 0,
	    UINT64_MAX, UINT64_MAX, &layout), EOVERFLOW);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, domain_distribution);
	ATF_TP_ADD_TC(tp, device_memory_segment_namespace);
	ATF_TP_ADD_TC(tp, domain_distribution_rejects_invalid);
	ATF_TP_ADD_TC(tp, layout_boundaries);
	ATF_TP_ADD_TC(tp, layout_rejects_invalid_and_overflow);
	return (atf_no_error());
}

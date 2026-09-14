/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdlib.h>
#include <string.h>
#include <atf-c.h>

ATF_TC_WITHOUT_HEAD(sized_deallocation);
ATF_TC_BODY(sized_deallocation, tc)
{
	void *p;
	size_t size;

	(void)tc;
	free_sized(NULL, 0);
	free_aligned_sized(NULL, 64, 0);
	for (size = 1; size <= 65536; size *= 2) {
		p = malloc(size);
		ATF_REQUIRE(p != NULL);
		memset(p, 0xa5, size);
		free_sized(p, size);
	}
	for (size = 64; size <= 65536; size *= 2) {
		p = aligned_alloc(64, size);
		ATF_REQUIRE(p != NULL);
		memset(p, 0x5a, size);
		free_aligned_sized(p, 64, size);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sized_deallocation);
	return (atf_no_error());
}

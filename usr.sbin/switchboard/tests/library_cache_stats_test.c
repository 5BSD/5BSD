/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <atf-c.h>
#include <string.h>
#include "library_cache_stats.h"

ATF_TC_WITHOUT_HEAD(identity_and_execution);
ATF_TC_BODY(identity_and_execution, tc)
{
	struct kinfo_vmentry maps[5] = {0};
	struct library_cache_stats stats = {0};

	(void)tc;
	for (unsigned i = 0; i < 5; i++) {
		maps[i].kve_type = KVME_TYPE_VNODE;
		maps[i].kve_vn_fsid = 19;
		maps[i].kve_vn_fileid = 42;
		maps[i].kve_start = 0x1000;
		maps[i].kve_end = 0x2000;
		maps[i].kve_protection = KVME_PROT_READ | KVME_PROT_EXEC;
	}
	/* The index is mapped but contains no executable code. */
	maps[1].kve_protection = KVME_PROT_READ;
	/* A new generation may use the same pathname but a different inode. */
	maps[2].kve_vn_fileid++;
	maps[3].kve_type = KVME_TYPE_SWAP;
	/* A renamed backing file still has the selected generation's identity. */
	strlcpy(maps[4].kve_path, "/renamed-cache", sizeof(maps[4].kve_path));
	ATF_REQUIRE_EQ(0, library_cache_stats_collect(maps, 5, 19, 42, &stats));
	ATF_CHECK_EQ(2, stats.executable_mappings);
	ATF_CHECK_EQ(8192, stats.executable_virtual_bytes);
	ATF_REQUIRE_EQ(0, library_cache_stats_collect(maps, 5, 20, 42, &stats));
	ATF_CHECK_EQ(0, stats.executable_mappings);
	ATF_CHECK_EQ(0, stats.executable_virtual_bytes);
}

ATF_TC_WITHOUT_HEAD(invalid_snapshot);
ATF_TC_BODY(invalid_snapshot, tc)
{
	struct kinfo_vmentry maps[2] = {0};
	struct library_cache_stats stats = {7, 8};

	(void)tc;
	ATF_CHECK_EQ(EINVAL, library_cache_stats_collect(NULL, -1, 0, 0, &stats));
	for (unsigned i = 0; i < 2; i++) {
		maps[i].kve_type = KVME_TYPE_VNODE;
		maps[i].kve_protection = KVME_PROT_EXEC;
	}
	maps[0].kve_start = 2;
	maps[0].kve_end = 1;
	ATF_CHECK_EQ(EFTYPE, library_cache_stats_collect(maps, 2, 0, 0, &stats));
	maps[0].kve_start = 0;
	maps[0].kve_end = UINT64_MAX;
	maps[1].kve_end = 1;
	ATF_CHECK_EQ(EOVERFLOW, library_cache_stats_collect(maps, 2, 0, 0, &stats));
	ATF_CHECK_EQ(7, stats.executable_mappings);
	ATF_CHECK_EQ(8, stats.executable_virtual_bytes);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, identity_and_execution);
	ATF_TP_ADD_TC(tp, invalid_snapshot);
	return (atf_no_error());
}

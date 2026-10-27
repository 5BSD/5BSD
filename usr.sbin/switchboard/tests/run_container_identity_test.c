/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include "run_container_identity.h"

ATF_TC_WITHOUT_HEAD(distinct_labels_and_scopes);
ATF_TC_BODY(distinct_labels_and_scopes, tc)
{
	const char *labels[] = {"system/a.b", "system/a_b", "system_a.b", "system_a_b"};
	uid_t owners[] = {(uid_t)-1, 0, 1001, 1002};
	char names[16][128];
	unsigned n = 0;
	for (unsigned i = 0; i < 4; i++) {
		for (unsigned j = 0; j < 4; j++) {
			ATF_REQUIRE_EQ(0, sb_run_container_leaf(labels[i], owners[j], names[n], sizeof(names[n])));
			ATF_REQUIRE(strchr(names[n], '/') == NULL);
			for (unsigned k = 0; k < n; k++) ATF_CHECK(strcmp(names[n], names[k]) != 0);
			n++;
		}
	}
}
ATF_TC_WITHOUT_HEAD(full_label_and_repeatability);
ATF_TC_BODY(full_label_and_repeatability, tc)
{
	char label[512], first[128], second[128], again[128];
	memset(label, 'a', sizeof(label)); label[sizeof(label) - 1] = '\0';
	ATF_REQUIRE_EQ(0, sb_run_container_leaf(label, 1001, first, sizeof(first)));
	ATF_REQUIRE_EQ(0, sb_run_container_leaf(label, 1001, again, sizeof(again)));
	ATF_CHECK_STREQ(first, again);
	label[sizeof(label) - 2] = 'b';
	ATF_REQUIRE_EQ(0, sb_run_container_leaf(label, 1001, second, sizeof(second)));
	ATF_CHECK(strcmp(first, second) != 0);
}
ATF_TC_WITHOUT_HEAD(reject_truncation_and_empty);
ATF_TC_BODY(reject_truncation_and_empty, tc)
{
	char name[128], small[4] = "old";
	ATF_REQUIRE_EQ(0, sb_run_container_leaf("system/test", (uid_t)-1, name, sizeof(name)));
	ATF_REQUIRE_ERRNO(ENAMETOOLONG, sb_run_container_leaf("system/test", (uid_t)-1, small, sizeof(small)) == -1);
	ATF_CHECK_EQ('\0', small[0]);
	ATF_REQUIRE_ERRNO(ENAMETOOLONG, sb_run_container_leaf("system/test", (uid_t)-1, NULL, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, sb_run_container_leaf("", 0, name, sizeof(name)) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, sb_run_container_leaf(NULL, 0, name, sizeof(name)) == -1);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, distinct_labels_and_scopes);
	ATF_TP_ADD_TC(tp, full_label_and_repeatability);
	ATF_TP_ADD_TC(tp, reject_truncation_and_empty);
	return (atf_no_error());
}

/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "libcapbundle_internal.h"

ATF_TC_WITHOUT_HEAD(stable_vectors);
ATF_TC_BODY(stable_vectors, tc)
{
	char key[ORT_STORAGE_DATASET_MAX];

	ATF_REQUIRE_EQ(0, capbundle_storage_dataset_key(key, "org.test.app",
	    "worker", "data", ORT_STORAGE_SCOPE_UNIT));
	ATF_CHECK_STREQ("u-2991b6664e707f365cff7bb09de37545679e53daca9de81f", key);
	ATF_CHECK_EQ(50, strlen(key));
	ATF_REQUIRE_EQ(0, capbundle_storage_dataset_key(key, "org.test.app",
	    "ignored", "data", ORT_STORAGE_SCOPE_SHARED));
	ATF_CHECK_STREQ("s-8e562bcc3c3a0800e1b33fb1721d8f9ef2ad5c45fa06aa24", key);
}

ATF_TC_WITHOUT_HEAD(domain_separation);
ATF_TC_BODY(domain_separation, tc)
{
	char base[ORT_STORAGE_DATASET_MAX], changed[ORT_STORAGE_DATASET_MAX];

	ATF_REQUIRE_EQ(0, capbundle_storage_dataset_key(base, "org.test.app",
	    "worker", "data", ORT_STORAGE_SCOPE_UNIT));
#define CHECK_DISTINCT(bundle, unit, name, scope) do { \
	ATF_REQUIRE_EQ(0, capbundle_storage_dataset_key(changed, (bundle), \
	    (unit), (name), (scope))); \
	ATF_CHECK(strcmp(base, changed) != 0); \
} while (0)
	CHECK_DISTINCT("org.test.other", "worker", "data",
	    ORT_STORAGE_SCOPE_UNIT);
	CHECK_DISTINCT("org.test.app", "other", "data",
	    ORT_STORAGE_SCOPE_UNIT);
	CHECK_DISTINCT("org.test.app", "worker", "other",
	    ORT_STORAGE_SCOPE_UNIT);
	CHECK_DISTINCT("org.test.app", "worker", "data",
	    ORT_STORAGE_SCOPE_SHARED);
#undef CHECK_DISTINCT
}

ATF_TC_WITHOUT_HEAD(invalid_arguments);
ATF_TC_BODY(invalid_arguments, tc)
{
	char key[ORT_STORAGE_DATASET_MAX];

	ATF_CHECK_ERRNO(EINVAL, capbundle_storage_dataset_key(NULL,
	    "org.test.app", "worker", "data", ORT_STORAGE_SCOPE_UNIT) == -1);
	ATF_CHECK_ERRNO(EINVAL, capbundle_storage_dataset_key(key, "", "worker",
	    "data", ORT_STORAGE_SCOPE_UNIT) == -1);
	ATF_CHECK_ERRNO(EINVAL, capbundle_storage_dataset_key(key, "org.test.app",
	    NULL, "data", ORT_STORAGE_SCOPE_UNIT) == -1);
	ATF_CHECK_ERRNO(EINVAL, capbundle_storage_dataset_key(key, "org.test.app",
	    "worker", "", ORT_STORAGE_SCOPE_UNIT) == -1);
	ATF_CHECK_ERRNO(EINVAL, capbundle_storage_dataset_key(key, "org.test.app",
	    "worker", "data", 99) == -1);
	ATF_REQUIRE_EQ(0, capbundle_storage_dataset_key(key, "org.test.app", NULL,
	    "data", ORT_STORAGE_SCOPE_SHARED));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stable_vectors);
	ATF_TP_ADD_TC(tp, domain_separation);
	ATF_TP_ADD_TC(tp, invalid_arguments);
	return (atf_no_error());
}

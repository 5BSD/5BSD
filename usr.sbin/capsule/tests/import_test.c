/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <libzfs.h>
#include <atf-c.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "protected_storage.h"

static nvlist_t *
candidate(uint64_t state, nvlist_t *load)
{
	nvlist_t *result;
	ATF_REQUIRE_EQ(0, nvlist_alloc(&result, NV_UNIQUE_NAME, 0));
	ATF_REQUIRE_EQ(0, nvlist_add_uint64(result, ZPOOL_CONFIG_POOL_STATE, state));
	ATF_REQUIRE_EQ(0, nvlist_add_nvlist(result, ZPOOL_CONFIG_LOAD_INFO, load));
	return (result);
}

ATF_TC_WITHOUT_HEAD(import_admission);
ATF_TC_BODY(import_admission, tc)
{
	nvlist_t *load, *pool;
	uint64_t local = (unsigned long)gethostid() & HOSTID_MASK;
	uint64_t foreign = local ^ 1;
	char env[32];
	(void)tc;

	ATF_REQUIRE_EQ(0, nvlist_alloc(&load, NV_UNIQUE_NAME, 0));
	pool = candidate(POOL_STATE_EXPORTED, load);
	ATF_CHECK(protected_storage_import_allowed(pool)); nvlist_free(pool);
	pool = candidate(POOL_STATE_ACTIVE, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	ATF_REQUIRE_EQ(0, nvlist_add_uint64(load, ZPOOL_CONFIG_HOSTID, local));
	pool = candidate(POOL_STATE_ACTIVE, load);
	ATF_CHECK_EQ(local != 0, protected_storage_import_allowed(pool));
	nvlist_free(pool);

	/* An environment string cannot impersonate the foreign pool's host. */
	ATF_REQUIRE_EQ(0, nvlist_add_uint64(load, ZPOOL_CONFIG_HOSTID, foreign));
	snprintf(env, sizeof(env), "%" PRIu64, foreign);
	ATF_REQUIRE_EQ(0, setenv("ZFS_HOSTID", env, 1));
	pool = candidate(POOL_STATE_ACTIVE, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	ATF_REQUIRE_EQ(0, unsetenv("ZFS_HOSTID"));

	/* A clean export needs no host match, but multihost safety still applies. */
	pool = candidate(POOL_STATE_EXPORTED, load);
	ATF_CHECK(protected_storage_import_allowed(pool)); nvlist_free(pool);
	const uint64_t states[] = { MMP_STATE_ACTIVE, MMP_STATE_NO_HOSTID, UINT64_MAX };
	for (unsigned i = 0; i < nitems(states); i++) {
		ATF_REQUIRE_EQ(0, nvlist_add_uint64(load, ZPOOL_CONFIG_MMP_STATE, states[i]));
		pool = candidate(POOL_STATE_EXPORTED, load);
		ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	}
	ATF_REQUIRE_EQ(0, nvlist_add_uint64(load, ZPOOL_CONFIG_MMP_STATE, MMP_STATE_INACTIVE));
	pool = candidate(POOL_STATE_EXPORTED, load);
	ATF_CHECK(protected_storage_import_allowed(pool)); nvlist_free(pool);
	pool = candidate(POOL_STATE_DESTROYED, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	pool = candidate(UINT64_MAX, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);

	/* Malformed metadata must not become a default or a fallback host match. */
	ATF_REQUIRE_EQ(0, nvlist_add_string(load, ZPOOL_CONFIG_HOSTID, "1"));
	pool = candidate(POOL_STATE_EXPORTED, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	ATF_REQUIRE_EQ(0, nvlist_remove_all(load, ZPOOL_CONFIG_HOSTID));
	ATF_REQUIRE_EQ(0, nvlist_add_string(load, ZPOOL_CONFIG_MMP_STATE, "inactive"));
	pool = candidate(POOL_STATE_EXPORTED, load);
	ATF_CHECK(!protected_storage_import_allowed(pool)); nvlist_free(pool);
	ATF_REQUIRE_EQ(0, nvlist_remove_all(load, ZPOOL_CONFIG_MMP_STATE));
	pool = candidate(POOL_STATE_ACTIVE, load);
	ATF_REQUIRE_EQ(0, nvlist_add_uint64(pool, ZPOOL_CONFIG_HOSTID, local));
	ATF_CHECK_EQ(local != 0, protected_storage_import_allowed(pool));
	ATF_REQUIRE_EQ(0, nvlist_remove_all(pool, ZPOOL_CONFIG_LOAD_INFO));
	ATF_CHECK(!protected_storage_import_allowed(pool));
	nvlist_free(pool); nvlist_free(load);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, import_admission);
	return (atf_no_error());
}

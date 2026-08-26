/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <atf-c.h>

#include "serviced.h"

static struct ort_storage_claim
claim(const char *dataset, uint8_t lifetime)
{
	struct ort_storage_claim sc;

	memset(&sc, 0, sizeof(sc));
	strlcpy(sc.name, "data", sizeof(sc.name));
	strlcpy(sc.dataset, dataset, sizeof(sc.dataset));
	sc.lifetime = lifetime;
	return (sc);
}

ATF_TC_WITHOUT_HEAD(single_holder);
ATF_TC_BODY(single_holder, tc)
{
	struct ort_storage_claim sc = claim("s-one", ORT_STORAGE_LEASE);

	storage_lifecycle_reset();
	ATF_REQUIRE_EQ(0, storage_lease_acquire(&sc));
	ATF_CHECK_EQ(1, storage_lease_release(&sc));
	ATF_CHECK_ERRNO(ENOENT, storage_lease_release(&sc) == -1);
}

ATF_TC_WITHOUT_HEAD(shared_last_holder);
ATF_TC_BODY(shared_last_holder, tc)
{
	struct ort_storage_claim sc = claim("s-shared", ORT_STORAGE_LEASE);
	unsigned i;

	storage_lifecycle_reset();
	for (i = 0; i < 100; i++)
		ATF_REQUIRE_EQ(0, storage_lease_acquire(&sc));
	for (i = 0; i < 99; i++)
		ATF_CHECK_EQ(0, storage_lease_release(&sc));
	ATF_CHECK_EQ(1, storage_lease_release(&sc));
}

ATF_TC_WITHOUT_HEAD(independent_and_reset);
ATF_TC_BODY(independent_and_reset, tc)
{
	struct ort_storage_claim a = claim("u-a", ORT_STORAGE_LEASE);
	struct ort_storage_claim b = claim("u-b", ORT_STORAGE_LEASE);

	storage_lifecycle_reset();
	ATF_REQUIRE_EQ(0, storage_lease_acquire(&a));
	ATF_REQUIRE_EQ(0, storage_lease_acquire(&b));
	ATF_CHECK_EQ(1, storage_lease_release(&a));
	ATF_CHECK_EQ(1, storage_lease_release(&b));
	ATF_REQUIRE_EQ(0, storage_lease_acquire(&a));
	storage_lifecycle_reset();
	ATF_CHECK_ERRNO(ENOENT, storage_lease_release(&a) == -1);
}

ATF_TC_WITHOUT_HEAD(invalid_claims);
ATF_TC_BODY(invalid_claims, tc)
{
	struct ort_storage_claim persistent = claim("p", ORT_STORAGE_PERSISTENT);
	struct ort_storage_claim empty = claim("", ORT_STORAGE_LEASE);
	struct ort_storage_claim unterminated = claim("x", ORT_STORAGE_LEASE);

	memset(unterminated.dataset, 'x', sizeof(unterminated.dataset));
	storage_lifecycle_reset();
	ATF_CHECK_ERRNO(EINVAL, storage_lease_acquire(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, storage_lease_acquire(&persistent) == -1);
	ATF_CHECK_ERRNO(EINVAL, storage_lease_acquire(&empty) == -1);
	ATF_CHECK_ERRNO(EINVAL, storage_lease_acquire(&unterminated) == -1);
	ATF_CHECK_ERRNO(EINVAL, storage_lease_release(&persistent) == -1);
}

ATF_TC_WITHOUT_HEAD(capacity_and_reuse);
ATF_TC_BODY(capacity_and_reuse, tc)
{
	struct ort_storage_claim sc;
	unsigned i;

	storage_lifecycle_reset();
	for (i = 0; i < SERVICED_MAX_SERVICES * SERVICED_MAX_CAP_STORAGE; i++) {
		char dataset[ORT_STORAGE_DATASET_MAX];

		snprintf(dataset, sizeof(dataset), "u-%u", i);
		sc = claim(dataset, ORT_STORAGE_LEASE);
		ATF_REQUIRE_EQ(0, storage_lease_acquire(&sc));
	}
	sc = claim("overflow", ORT_STORAGE_LEASE);
	ATF_CHECK_ERRNO(ENOSPC, storage_lease_acquire(&sc) == -1);
	sc = claim("u-1024", ORT_STORAGE_LEASE);
	ATF_CHECK_EQ(1, storage_lease_release(&sc));
	sc = claim("replacement", ORT_STORAGE_LEASE);
	ATF_CHECK_EQ(0, storage_lease_acquire(&sc));
	ATF_CHECK_EQ(1, storage_lease_release(&sc));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, single_holder);
	ATF_TP_ADD_TC(tp, shared_last_holder);
	ATF_TP_ADD_TC(tp, independent_and_reset);
	ATF_TP_ADD_TC(tp, invalid_claims);
	ATF_TP_ADD_TC(tp, capacity_and_reuse);
	return (atf_no_error());
}

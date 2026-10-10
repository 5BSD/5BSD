/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "switchboard.h"

static bool fail_alloc;
static void *
test_reallocarray(void *ptr, size_t n, size_t size)
{
	if (fail_alloc) {
		errno = ENOMEM;
		return (NULL);
	}
	return (reallocarray(ptr, n, size));
}
#define reallocarray test_reallocarray
#include "../reclaim_publish.c"
#undef reallocarray

struct switchboard_state sd;
const char *switchboard_run_dir = "run";
struct capbundle *bundle_registry_get(unsigned idx __unused)
{
	return ((struct capbundle *)(uintptr_t)1);
}
unsigned bundle_registry_count(void) { return (0); }
const char *capbundle_name(const struct capbundle *b __unused)
{
	return ("Owner.cap");
}
unsigned capbundle_ngroups(const struct capbundle *b __unused) { return (0); }
const char *capbundle_group(const struct capbundle *b __unused,
    unsigned idx __unused) { return (NULL); }

ATF_TC_WITHOUT_HEAD(incomplete_publication_preserves_owners);
ATF_TC_BODY(incomplete_publication_preserves_owners, tc)
{
	struct svc_runtime svc = { 0 };

	sd.services = &svc;
	sd.nservices = 1;
	svc.state = SVC_STATE_RUNNING;
	svc_reclaim_publish_live();
	ATF_REQUIRE_EQ(0, access("run/live/Owner", F_OK));
	fail_alloc = true;
	svc_reclaim_publish_live();
	ATF_CHECK_EQ(0, access("run/live/Owner", F_OK));
	ATF_CHECK(publish_dirty);
	fail_alloc = false;
	svc_reclaim_publish_if_dirty();
	ATF_CHECK(!publish_dirty);
	svc.state = SVC_STATE_STOPPING;
	svc_reclaim_publish_live();
	ATF_CHECK_EQ(0, access("run/live/Owner", F_OK));
	svc.state = SVC_STATE_STOPPED;
	svc_reclaim_publish_live();
	ATF_CHECK_EQ(-1, access("run/live/Owner", F_OK));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, incomplete_publication_preserves_owners);
	return (atf_no_error());
}

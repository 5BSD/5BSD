/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/*
 * This test includes the implementation so it can exercise the deliberately
 * private pending-lookup invariants.  Function/data sections let the linker
 * discard unrelated serviced integration paths and their dependencies.
 */
#include "../on_demand.c"

struct serviced_state sd;
int serviced_kq = -1;

static void
runtime_init(struct svc_runtime *runtime, const char *label, pid_t pid,
    uint64_t launch_id)
{

	memset(runtime, 0, sizeof(*runtime));
	strlcpy(runtime->manifest.label, label,
	    sizeof(runtime->manifest.label));
	runtime->pid = pid;
	runtime->launch_id = launch_id;
}

static void
pending_init(struct pending_lookup *pending,
    const struct svc_runtime *provider, const char *name)
{

	memset(pending, 0, sizeof(*pending));
	strlcpy(pending->name, name, sizeof(pending->name));
	strlcpy(pending->provider_label, provider->manifest.label,
	    sizeof(pending->provider_label));
	pending->provider_pid = provider->pid;
	pending->provider_launch_id = provider->launch_id;
}

ATF_TC(provider_incarnation);
ATF_TC_HEAD(provider_incarnation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pending lookups match an exact provider process incarnation");
}
ATF_TC_BODY(provider_incarnation, tc)
{
	struct pending_lookup pending;
	struct svc_runtime original, replacement;

	runtime_init(&original, "org.test.provider", 101, 7);
	pending_init(&pending, &original, "org.test.endpoint");
	ATF_CHECK(pending_provider_matches(&pending, &original));

	runtime_init(&replacement, "org.test.provider", 102, 8);
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
	replacement.pid = original.pid;
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
	replacement.launch_id = original.launch_id;
	ATF_CHECK(pending_provider_matches(&pending, &replacement));
	strlcpy(replacement.manifest.label, "org.test.other",
	    sizeof(replacement.manifest.label));
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
}

ATF_TC(provider_name_filter);
ATF_TC_HEAD(provider_name_filter, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "same-name waiters remain isolated across provider incarnations");
}
ATF_TC_BODY(provider_name_filter, tc)
{
	struct pending_lookup old_pending, new_pending;
	struct svc_runtime old_provider, new_provider;

	runtime_init(&old_provider, "org.test.provider", 201, 10);
	runtime_init(&new_provider, "org.test.provider", 202, 11);
	pending_init(&old_pending, &old_provider, "org.test.endpoint");
	pending_init(&new_pending, &new_provider, "org.test.endpoint");
	old_pending.next = &new_pending;
	pending_list = &old_pending;
	npending = 2;

	ATF_CHECK(pending_for_provider_name(&old_provider,
	    "org.test.endpoint"));
	ATF_CHECK(pending_for_provider_name(&new_provider,
	    "org.test.endpoint"));
	ATF_CHECK(!pending_for_provider_name(&new_provider,
	    "org.test.unrelated"));
	old_pending.next = NULL;
	ATF_CHECK(!pending_for_provider_name(&new_provider,
	    "org.test.endpoint"));

	pending_list = NULL;
	npending = 0;
}

ATF_TC(timer_identifiers);
ATF_TC_HEAD(timer_identifiers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "timer identifiers preserve their range, wrap, and avoid collisions");
}
ATF_TC_BODY(timer_identifiers, tc)
{
	struct pending_lookup pending;
	uintptr_t first, second;

	memset(&pending, 0, sizeof(pending));
	pending.timeout_ident = ON_DEMAND_TIMER_BIT | 1;
	pending_list = &pending;
	npending = 1;
	od_timer_next = pending.timeout_ident;
	first = next_timeout_ident();
	ATF_CHECK_EQ(ON_DEMAND_TIMER_BIT | 2, first);
	ATF_CHECK(on_demand_is_timer(first));

	pending_list = NULL;
	npending = 0;
	od_timer_next = (ON_DEMAND_TIMER_BIT << 1) - 1;
	first = next_timeout_ident();
	second = next_timeout_ident();
	ATF_CHECK_EQ((ON_DEMAND_TIMER_BIT << 1) - 1, first);
	ATF_CHECK_EQ(ON_DEMAND_TIMER_BIT | 1, second);
	ATF_CHECK(on_demand_is_timer(first));
	ATF_CHECK(on_demand_is_timer(second));
}

ATF_TC(timer_registration_failure);
ATF_TC_HEAD(timer_registration_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "an unusable kqueue makes timeout registration fail immediately");
}
ATF_TC_BODY(timer_registration_failure, tc)
{
	struct pending_lookup pending;

	memset(&pending, 0, sizeof(pending));
	pending_list = NULL;
	npending = 0;
	od_timer_next = ON_DEMAND_TIMER_BIT | 1;
	errno = 0;
	ATF_CHECK_EQ(-1, arm_timeout(-1, &pending));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK(on_demand_is_timer(pending.timeout_ident));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_incarnation);
	ATF_TP_ADD_TC(tp, provider_name_filter);
	ATF_TP_ADD_TC(tp, timer_identifiers);
	ATF_TP_ADD_TC(tp, timer_registration_failure);
	return (atf_no_error());
}

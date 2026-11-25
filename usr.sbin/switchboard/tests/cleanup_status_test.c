/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <sys/param.h>
#include <atf-c.h>
#include "../sctl.c"

struct switchboard_state sd;
int switchboard_kq = -1;

void
switchboard_fd_budget_get_stats(struct switchboard_fd_budget_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

#include "../management.c"

static unsigned stop_calls, launch_calls, acknowledge_calls;
static bool launch_allowed;

const char *
svc_boot_id(char *buffer, size_t capacity)
{
	strlcpy(buffer, "test", capacity);
	return (buffer);
}

struct svc_runtime *
svc_by_label(const char *label)
{
	for (unsigned i = 0; i < sd.nservices; i++)
		if (strcmp(sd.services[i]->manifest.label, label) == 0)
			return (sd.services[i]);
	return (NULL);
}

int
supervisor_reload(int kq, char *summary, size_t capacity)
{
	(void)kq; (void)summary; (void)capacity;
	atf_tc_fail("unexpected reload");
	return (-1);
}

void
svc_cancel_restart(struct svc_runtime *svc, int kq)
{
	(void)svc; (void)kq;
	if (!launch_allowed)
		atf_tc_fail("unexpected restart cancellation");
}

int
svc_exec(struct svc_runtime *svc, int kq)
{
	(void)kq;
	if (!launch_allowed)
		atf_tc_fail("cleanup permitted unexpected launch");
	ATF_REQUIRE(!svc->cleanup.pending);
	launch_calls++;
	svc->state = SVC_STATE_STARTING;
	return (0);
}

/* What supervisor.c does with an accepted failed cleanup, for these cases. */
bool
supervisor_cleanup_acknowledge(struct svc_runtime *svc)
{
	acknowledge_calls++;
	svc->cleanup.pending = false;
	svc->cleanup.error = 0;
	svc->state = SVC_STATE_STOPPED;
	return (false);
}

void
svc_graceful_stop(struct svc_runtime *svc, int kq)
{
	(void)kq;
	ATF_REQUIRE(svc->cleanup.pending);
	stop_calls++;
}

const char *
svc_responsibility_name(const struct svc_responsible *responsible,
    char *buffer, size_t capacity)
{
	(void)responsible;
	strlcpy(buffer, "test", capacity);
	return (buffer);
}

ATF_TC_WITHOUT_HEAD(cleanup_status);
ATF_TC_BODY(cleanup_status, tc)
{
	struct svc_runtime *svc;
	struct sctl_reply reply;
	char summary[2048], small[16];

	(void)tc;
	svc = calloc(1, sizeof(*svc));
	ATF_REQUIRE(svc != NULL);
	strlcpy(svc->manifest.label, "org.test.cleanup", sizeof(svc->manifest.label));
	svc->state = SVC_STATE_STOPPING;
	sd.services = &svc;
	sd.nservices = 1;
	svc->cleanup.pending = true;
	svc->cleanup.child_pending = true;
	svc->cleanup.fd = -1;
	svc->cleanup.coalition_complete = true;
	sctl_cmd_status(&reply, summary, sizeof(summary));
	ATF_CHECK(strstr(summary, "cleanup=pending child=waiting coalition=complete observed=no") != NULL);
	ATF_CHECK_EQ(strlen(summary), reply.flags);
	svc->cleanup.error = ETIMEDOUT;
	svc->cleanup.child_pending = false;
	svc->cleanup.coalition_complete = false;
	svc->cleanup.fd = 123;
	sctl_cmd_status(&reply, summary, sizeof(summary));
	ATF_CHECK(strstr(summary, "cleanup=blocked child=exited coalition=unconfirmed observed=yes") != NULL);
	ATF_CHECK(strstr(summary, "cleanup-error=") != NULL);
	memset(small, 'x', sizeof(small));
	sctl_cmd_status(&reply, small, sizeof(small));
	ATF_CHECK_EQ(0, small[sizeof(small) - 1]);
	svc->cleanup.pending = false;
	sctl_cmd_status(&reply, summary, sizeof(summary));
	ATF_CHECK(strstr(summary, " cleanup=") == NULL);
	free(svc);
	sd.services = NULL;
}

ATF_TC_WITHOUT_HEAD(cleanup_commands);
ATF_TC_BODY(cleanup_commands, tc)
{
	struct svc_runtime *svc;
	struct sctl_reply reply;
	char summary[2048];

	(void)tc;
	svc = calloc(1, sizeof(*svc));
	ATF_REQUIRE(svc != NULL);
	strlcpy(svc->manifest.label, "org.test.cleanup", sizeof(svc->manifest.label));
	svc->manifest.management = SVC_MGMT_SYSTEM;
	svc->owner_uid = (uid_t)-1;
	svc->state = SVC_STATE_STOPPING;
	svc->cleanup.pending = true;
	sd.services = &svc;
	sd.nservices = 1;
	/* Management authorization still precedes the pending-cleanup branch. */
	sctl_execute_op(SCTL_OP_STOP_SVC, svc->manifest.label,
	    strlen(svc->manifest.label) + 1, false, 1001, &reply, summary, sizeof(summary));
	ATF_CHECK_EQ(EPERM, reply.status);
	ATF_CHECK_EQ(0, stop_calls);
	sctl_execute_op(SCTL_OP_STOP_SVC, svc->manifest.label,
	    strlen(svc->manifest.label) + 1, true, 1001, &reply, summary, sizeof(summary));
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(1, stop_calls);
	ATF_CHECK(strstr(summary, "restart suppressed") != NULL);
	sctl_execute_op(SCTL_OP_START_SVC, svc->manifest.label,
	    strlen(svc->manifest.label) + 1, true, 1001, &reply, summary, sizeof(summary));
	ATF_CHECK_EQ(EBUSY, reply.status);
	ATF_CHECK(strstr(summary, "replacement blocked") != NULL);
	ATF_CHECK(svc->cleanup.pending);
	free(svc);
	sd.services = NULL;
}

/*
 * A cleanup whose coalition reported failure leaves the unit with nothing
 * observing it: status calls that failed, and an operator start accepts it
 * and starts the unit.
 */
ATF_TC_WITHOUT_HEAD(cleanup_failed_operator_start);
ATF_TC_BODY(cleanup_failed_operator_start, tc)
{
	struct svc_runtime *svc;
	struct sctl_reply reply;
	char summary[2048];

	(void)tc;
	svc = calloc(1, sizeof(*svc));
	ATF_REQUIRE(svc != NULL);
	strlcpy(svc->manifest.label, "org.test.cleanup", sizeof(svc->manifest.label));
	svc->manifest.management = SVC_MGMT_SYSTEM;
	svc->owner_uid = (uid_t)-1;
	/* As supervisor_cleanup_progress() leaves a failed cleanup. */
	svc->state = SVC_STATE_STOPPING;
	svc->cleanup.pending = true;
	svc->cleanup.error = EIO;
	svc->cleanup.fd = -1;
	sd.services = &svc;
	sd.nservices = 1;
	sctl_cmd_status(&reply, summary, sizeof(summary));
	ATF_CHECK_MSG(strstr(summary, " cleanup=failed ") != NULL,
	    "status: %s", summary);

	launch_allowed = true;
	launch_calls = acknowledge_calls = 0;
	sctl_execute_op(SCTL_OP_START_SVC, svc->manifest.label,
	    strlen(svc->manifest.label) + 1, true, 1001, &reply, summary,
	    sizeof(summary));
	ATF_CHECK_EQ_MSG(0, reply.status, "start: %s", summary);
	ATF_CHECK_EQ(1, launch_calls);
	ATF_CHECK(!svc->cleanup.pending);
	launch_allowed = false;
	free(svc);
	sd.services = NULL;
	sd.nservices = 0;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cleanup_status);
	ATF_TP_ADD_TC(tp, cleanup_commands);
	ATF_TP_ADD_TC(tp, cleanup_failed_operator_start);
	return (atf_no_error());
}

struct svc_runtime *
svc_by_label_scoped(const char *name, uid_t owner)
{
 struct svc_runtime *svc=svc_by_label(name);
 return svc != NULL && svc->owner_uid == owner ? svc : NULL;
}

/* These runtime-only tests have an empty installed catalogue. Unexpected
 * access beyond its count is a test failure; lazy loading is exercised by
 * the real-registry Secure Boot VM fixture. */
unsigned bundle_registry_count(void) { return (0); }
uid_t bundle_registry_owner_uid(unsigned index) { (void)index; abort(); }
struct capbundle *bundle_registry_get(unsigned index) { (void)index; abort(); }
void svc_slot_apply_bundle_policy(struct svc_runtime *svc, unsigned index)
{ (void)svc; (void)index; abort(); }

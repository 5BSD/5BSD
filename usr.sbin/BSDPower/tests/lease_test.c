/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Drive BSDPower's real bsd.power.v1 method handlers directly, with the
 * generated reply functions replaced by recorders, without any ACPI
 * descriptor or transport: lease ownership, suspend blocking and cleanup.
 */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <service_runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* What the handler replied: an errno (0 for success) or a count. */
static int reply_status;
static uint32_t reply_count;
static bool send_failure;

#define bsd_power_v1_Power_Inhibit_reply	 fake_inhibit_reply
#define bsd_power_v1_Power_Uninhibit_reply	 fake_uninhibit_reply
#define bsd_power_v1_Power_Suspend_reply	 fake_suspend_reply
#define bsd_power_v1_Power_Inhibitors_reply	 fake_inhibitors_reply
#define BSDPOWER_TESTING
#include "../BSDPower.c"

#define RECORD(name, type)                                                \
	int name(struct fidl_bsd_connection *c, struct fidl_bsd_request *r, \
	    const struct type *v)                                         \
	{                                                                 \
		(void)c;                                                  \
		(void)r;                                                  \
		reply_status = v->tag == type##_err_tag ? (int)v->value.err : 0; \
		return (send_failure ? EPIPE : 0);                        \
	}
RECORD(fake_inhibit_reply, bsd_power_v1_Power_Inhibit_Result)
RECORD(fake_uninhibit_reply, bsd_power_v1_Power_Uninhibit_Result)
RECORD(fake_suspend_reply, bsd_power_v1_Power_Suspend_Result)
int
fake_inhibitors_reply(struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, const struct bsd_power_v1_InhibitorCount *v)
{
	(void)c;
	(void)r;
	reply_status = 0;
	reply_count = v->count;
	return (send_failure ? EPIPE : 0);
}

enum op { INHIBIT, UNINHIBIT, INHIBITORS, SUSPEND };
static int
request(struct session *s, enum op op)
{
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_power_v1_SleepState state = { 3 };
	reply_status = -999;
	s->negotiated = true;
	switch (op) {
	case INHIBIT:
		inhibit(s, NULL, NULL, &empty);
		break;
	case UNINHIBIT:
		uninhibit(s, NULL, NULL, &empty);
		break;
	case INHIBITORS:
		inhibitors(s, NULL, NULL, &empty);
		break;
	case SUSPEND:
		suspend(s, NULL, NULL, &state);
		break;
	}
	return (reply_status);
}
ATF_TC_WITHOUT_HEAD(lease_blocks_suspend_until_owner_disconnect);
ATF_TC_BODY(lease_blocks_suspend_until_owner_disconnect, tc)
{
	struct powercmp_config config = { 0 };
	struct session a = { .label = "inhibitor",
		.owner = 1,
		.config = &config };
	struct session b = { .label = "controller",
		.owner = 2,
		.config = &config };
	config.nclients = 2;
	strlcpy(config.clients[0].label, "inhibitor",
	    sizeof(config.clients[0].label));
	config.clients[0].may_inhibit = true;
	strlcpy(config.clients[1].label, "controller",
	    sizeof(config.clients[1].label));
	config.clients[1].may_suspend = true;
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &g_leases));
	ATF_CHECK_EQ(EPERM, request(&b, INHIBIT));
	ATF_REQUIRE_EQ(0, request(&a, INHIBIT));
	ATF_CHECK_EQ(EALREADY, request(&a, INHIBIT));
	ATF_CHECK_EQ(ENOENT, request(&b, UNINHIBIT));
	ATF_CHECK_EQ(0, request(&b, INHIBITORS));
	ATF_CHECK_EQ(1, reply_count);
	ATF_CHECK_EQ(EBUSY, request(&b, SUSPEND));
	session_close(&a);
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	ATF_CHECK_EQ(ENODEV, request(&b, SUSPEND));
	service_lease_set_destroy(g_leases);
	g_leases = NULL;
}
ATF_TC_WITHOUT_HEAD(release_and_failed_reply_cleanup);
ATF_TC_BODY(release_and_failed_reply_cleanup, tc)
{
	struct powercmp_config config = { .default_inhibit = true };
	struct session s = { .label = "a", .owner = 1, .config = &config };
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &g_leases));
	ATF_REQUIRE_EQ(0, request(&s, INHIBIT));
	ATF_REQUIRE_EQ(0, request(&s, UNINHIBIT));
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	/* A lease whose grant could not be delivered still dies with its
	 * session: the reactor reclaims the failed connection. */
	send_failure = true;
	(void)request(&s, INHIBIT);
	ATF_CHECK_EQ(1, service_lease_count(g_leases));
	session_close(&s);
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	service_lease_set_destroy(g_leases);
	g_leases = NULL;
	send_failure = false;
}
ATF_TC_WITHOUT_HEAD(methods_require_negotiation);
ATF_TC_BODY(methods_require_negotiation, tc)
{
	struct powercmp_config config = { .default_inhibit = true };
	struct session s = { .label = "a", .owner = 1, .config = &config };
	struct fidl_bsd_empty empty = { 0 };
	ATF_REQUIRE_EQ(0, service_lease_set_create(2, &g_leases));
	reply_status = -999;
	inhibit(&s, NULL, NULL, &empty);
	/* Refused before any reply or lease. */
	ATF_CHECK_EQ(-999, reply_status);
	ATF_CHECK_EQ(0, service_lease_count(g_leases));
	service_lease_set_destroy(g_leases);
	g_leases = NULL;
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lease_blocks_suspend_until_owner_disconnect);
	ATF_TP_ADD_TC(tp, release_and_failed_reply_cleanup);
	ATF_TP_ADD_TC(tp, methods_require_negotiation);
	return (atf_no_error());
}

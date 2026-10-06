/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include "../probes.h"
#undef CAPSULE_PROBE_DYN_RELEASE_SYSTEM
#define CAPSULE_PROBE_DYN_RELEASE_SYSTEM(gates, released, error) \
    do { (void)(gates); (void)(released); (void)(error); } while (0)
#include "../capsule_proto_claims.c"

struct capsule_state od;
static int injected_error, reply_status;
static uint32_t attempted;
int
mac_capability_release_system_gates(uint32_t gates)
{
	attempted = gates;
	if (injected_error != 0)
		return (errno = injected_error, -1);
	return (0);
}
int mac_capability_release_system_sysctl(void) { return (0); }
int
proto_reply(int status, uint64_t token __unused, int *fds __unused,
    int nfds __unused)
{
	reply_status = status;
	return (0);
}
static void
setup(void)
{
	memset(&od, 0, sizeof(od));
	od.cfg.claim_system = od.cfg.claim_system_service =
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD;
	od.cfg.claim_system_refcount[0] = 1;
	od.cfg.claim_system_refcount[1] = 2;
	injected_error = attempted = 0;
	reply_status = -1;
}
ATF_TC_WITHOUT_HEAD(explicit_error_and_retry);
ATF_TC_BODY(explicit_error_and_retry, tc)
{
	struct capsule_system_req req = { .gates =
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD };
	(void)tc;
	setup();
	injected_error = EIO;
	handle_release_system(&req, sizeof(req), 1);
	ATF_CHECK_EQ(reply_status, EIO);
	ATF_CHECK_EQ(attempted, SYS_GATE_KLDLOAD);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[0], 1);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[1], 2);
	ATF_CHECK_EQ(od.cfg.claim_system_service, req.gates);
	injected_error = 0;
	handle_release_system(&req, sizeof(req), 2);
	ATF_CHECK_EQ(reply_status, 0);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[0], 0);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[1], 1);
	ATF_CHECK_EQ(od.cfg.claim_system, SYS_GATE_KLDUNLOAD);
}
ATF_TC_WITHOUT_HEAD(auto_error_and_shared_reference);
ATF_TC_BODY(auto_error_and_shared_reference, tc)
{
	(void)tc;
	setup();
	injected_error = EIO;
	release_auto_claim_system(SYS_GATE_KLDLOAD);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[0], 1);
	ATF_CHECK_EQ(od.cfg.claim_system_service,
	    SYS_GATE_KLDLOAD | SYS_GATE_KLDUNLOAD);
	attempted = 0;
	release_auto_claim_system(SYS_GATE_KLDUNLOAD);
	ATF_CHECK_EQ(attempted, 0);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[1], 1);
}
ATF_TC_WITHOUT_HEAD(sweep_preserves_policy_and_failed_claims);
ATF_TC_BODY(sweep_preserves_policy_and_failed_claims, tc)
{
	uint32_t released;
	(void)tc;
	setup();
	od.cfg.claim_system_policy = SYS_GATE_KLDLOAD;
	injected_error = EIO;
	ATF_REQUIRE_EQ(-1, release_system_references(UINT32_MAX, true, &released));
	ATF_CHECK_EQ(released, 0);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[1], 2);
	injected_error = 0;
	ATF_REQUIRE_EQ(0, release_system_references(UINT32_MAX, true, &released));
	ATF_CHECK_EQ(released, SYS_GATE_KLDUNLOAD);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[1], 0);
	ATF_CHECK_EQ(od.cfg.claim_system_refcount[0], 1);
	ATF_CHECK_EQ(od.cfg.claim_system, SYS_GATE_KLDLOAD);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, explicit_error_and_retry);
	ATF_TP_ADD_TC(tp, auto_error_and_shared_reference);
	ATF_TP_ADD_TC(tp, sweep_preserves_policy_and_failed_claims);
	return (atf_no_error());
}

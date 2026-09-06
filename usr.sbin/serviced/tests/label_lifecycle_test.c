/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Foundation tests for capability resource-cleanup
 * (docs/capability-lifecycle-cleanup.md): the SVC_OP_LABEL_IS_LIVE /
 * SVC_OP_RECLAIM_LABEL wire contract and the bundle-registry liveness answer
 * that backs the pull query.  The reclaim broadcast is driven by the admin
 * SCTL_OP_RECLAIM control op (pkg deinstall hook), not a reload diff.  Pure
 * logic only — no plane, no mac_capability device.
 */

#include <sys/types.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "serviced.h"
#include "serviced_svc_proto.h"

/*
 * bundle_registry.c references these; serviced.c defines them in the daemon.
 * The test never scans a directory, so their values are inert.
 */
const char *serviced_bundle_dir_system = "/nonexistent/System";
const char *serviced_bundle_dir_user = "/nonexistent/User";

/*
 * The proto is versioned so peers rebuild together; the two labels are 64 bytes
 * to match svc_new_client_msg.client_label.  A silent drift here would let a
 * mismatched serviced and libservice misparse the new messages.
 */
ATF_TC_WITHOUT_HEAD(proto_contract);
ATF_TC_BODY(proto_contract, tc)
{
	struct svc_label_query_req q;
	struct svc_reclaim_label_msg r;
	struct svc_new_client_msg nc;

	ATF_CHECK_EQ(9, SERVICED_SVC_PROTO_VERSION);
	ATF_CHECK_EQ(12u, (unsigned)SVC_OP_LABEL_IS_LIVE);
	ATF_CHECK_EQ(130u, (unsigned)SVC_OP_RECLAIM_LABEL);

	/* Query and reclaim labels match the client_label width exactly. */
	ATF_CHECK_EQ(sizeof(nc.client_label), sizeof(q.label));
	ATF_CHECK_EQ(sizeof(nc.client_label), sizeof(r.label));
	ATF_CHECK_EQ(64u, (unsigned)sizeof(q.label));

	/* Fixed header layout: op then flags, both 32-bit, before the label. */
	ATF_CHECK_EQ(0u, (unsigned)offsetof(struct svc_label_query_req, op));
	ATF_CHECK_EQ(4u, (unsigned)offsetof(struct svc_label_query_req, flags));
	ATF_CHECK_EQ(8u, (unsigned)offsetof(struct svc_label_query_req, label));
	ATF_CHECK_EQ(0u, (unsigned)offsetof(struct svc_reclaim_label_msg, op));
	ATF_CHECK_EQ(4u, (unsigned)offsetof(struct svc_reclaim_label_msg, flags));
	ATF_CHECK_EQ(8u, (unsigned)offsetof(struct svc_reclaim_label_msg, label));

	/* The two message sizes are distinct so the dispatcher can discriminate
	 * a reclaim notification from every other control message by length. */
	ATF_CHECK(sizeof(struct svc_reclaim_label_msg) !=
	    sizeof(struct svc_quiesce_msg));
	ATF_CHECK(sizeof(struct svc_reclaim_label_msg) !=
	    sizeof(struct svc_new_client_msg));
	ATF_CHECK(sizeof(struct svc_reclaim_label_msg) !=
	    sizeof(struct svc_activate_name_msg));
}

/*
 * The liveness predicate is the authoritative answer behind SVC_OP_LABEL_IS_LIVE.
 * It must fail closed: an empty registry and
 * degenerate inputs answer "not installed" (which serviced maps to ENOENT ==
 * not live), never a spurious "live".
 */
ATF_TC_WITHOUT_HEAD(label_installed_fail_closed);
ATF_TC_BODY(label_installed_fail_closed, tc)
{

	/* No registry has been built: nothing is installed. */
	ATF_CHECK(!bundle_registry_label_installed("system.Filesystem/tzfsd"));
	/* Degenerate inputs are never live. */
	ATF_CHECK(!bundle_registry_label_installed(NULL));
	ATF_CHECK(!bundle_registry_label_installed(""));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proto_contract);
	ATF_TP_ADD_TC(tp, label_installed_fail_closed);

	return (atf_no_error());
}

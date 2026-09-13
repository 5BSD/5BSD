/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Foundation tests for capability resource-cleanup
 * (docs/capability-lifecycle-cleanup.md): the SVC_OP_LABEL_IS_LIVE /
 * SVC_OP_RECLAIM_LABEL wire contract and the bundle-registry liveness answer
 * that backs the pull query.  The reclaim broadcast is driven by the admin
 * SCTL_OP_RECLAIM control op (pkg deinstall hook), not a reload diff.
 * Disk fixtures exercise the real scanner without a plane or capability device.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "switchboard.h"
#include "switchboard_svc_proto.h"

/*
 * bundle_registry.c references these; switchboard.c defines them in the daemon.
 * Disk cases redirect them to fixtures in the ATF work directory.
 */
const char *switchboard_bundle_dir_system = "/nonexistent/System";
const char *switchboard_bundle_dir_user = "/nonexistent/User";

/*
 * The proto is versioned so peers rebuild together; the two labels are 64 bytes
 * to match svc_new_client_msg.client_label.  A silent drift here would let a
 * mismatched switchboard and libservice misparse the new messages.
 */
ATF_TC_WITHOUT_HEAD(proto_contract);
ATF_TC_BODY(proto_contract, tc)
{
	struct svc_label_query_req q;
	struct svc_reclaim_label_msg r;
	struct svc_new_client_msg nc;

	ATF_CHECK_EQ(11, SWITCHBOARD_SVC_PROTO_VERSION);
	ATF_CHECK_EQ(12u, (unsigned)SVC_OP_LABEL_IS_LIVE);
	ATF_CHECK_EQ(13u, (unsigned)SVC_OP_REGISTER_LOOKUP);
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

/* Unknown installation state must preserve resources. */
ATF_TC_WITHOUT_HEAD(label_installed_unknown);
ATF_TC_BODY(label_installed_unknown, tc)
{

	ATF_CHECK(bundle_registry_label_installed("system.Filesystem/tzfsd"));
	ATF_CHECK(!bundle_registry_label_installed(NULL));
	ATF_CHECK(!bundle_registry_label_installed(""));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
	bundle_registry_teardown();
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
}

static void
write_file(const char *path, const char *text)
{
	FILE *f;

	ATF_REQUIRE((f = fopen(path, "w")) != NULL);
	ATF_REQUIRE(fputs(text, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
}

static void
setup_inventory(void)
{

	ATF_REQUIRE_EQ(0, mkdir("System", 0755));
	ATF_REQUIRE_EQ(0, mkdir("User", 0755));
	switchboard_bundle_dir_system = "System";
	switchboard_bundle_dir_user = "User";
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_DISABLED_PATH", "disabled", 1));
}

static void
make_bundle(const char *name, const char *id, const char *unit, unsigned seq)
{
	char path[1024], text[1024];

	ATF_REQUIRE_EQ(0, mkdir(name, 0755));
	snprintf(path, sizeof(path), "%s/Bundle.ucl", name);
	snprintf(text, sizeof(text),
	    "schema = \"org.5bsd.capability-bundle\"; schema_version = 1;\n"
	    "bundle_id = \"%s\"; version = \"1.0\"; sequence = %u;\n"
	    "author = \"Test\"; publisher = \"org.test\"; units = [\"%s\"];\n",
	    id, seq, unit);
	write_file(path, text);
	snprintf(path, sizeof(path), "%s/Units", name);
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));
	snprintf(path, sizeof(path), "%s/Units/%s.unit", name, unit);
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));
	snprintf(path, sizeof(path), "%s/Units/%s.unit/Unit.ucl", name, unit);
	write_file(path, "activation { boot = true; }\n");
	snprintf(path, sizeof(path), "%s/Units/%s.unit/bin", name, unit);
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));
	snprintf(path, sizeof(path), "%s/Units/%s.unit/bin/%s", name, unit, unit);
	write_file(path, "#!/bin/sh\nexit 0\n");
	ATF_REQUIRE_EQ(0, chmod(path, 0555));
}

ATF_TC(installed_disabled_and_superseded);
ATF_TC_HEAD(installed_disabled_and_superseded, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(installed_disabled_and_superseded, tc)
{

	setup_inventory();
	make_bundle("System/Old.cap", "org.test.app", "old", 1);
	make_bundle("System/New.cap", "org.test.app", "new", 2);
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(1, bundle_registry_count());
	ATF_CHECK(bundle_registry_label_installed("org.test.app/old"));
	ATF_CHECK(bundle_registry_label_installed("org.test.app/new"));
	ATF_CHECK(!bundle_registry_label_installed("org.test.absent/worker"));

	write_file("disabled", "org.test.app\n");
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK_EQ(0, bundle_registry_count());
	ATF_CHECK(bundle_registry_label_installed("org.test.app/old"));
	ATF_CHECK(bundle_registry_label_installed("org.test.app/new"));
	ATF_CHECK(!bundle_registry_label_installed("org.test.absent/worker"));
	bundle_registry_teardown();
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
}

ATF_TC(installed_incomplete_scan);
ATF_TC_HEAD(installed_incomplete_scan, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(installed_incomplete_scan, tc)
{

	setup_inventory();
	make_bundle("System/Good.cap", "org.test.good", "worker", 1);
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(!bundle_registry_label_installed("org.test.absent/worker"));

	/* Quarantine cannot establish absence of labels in a malformed bundle. */
	ATF_REQUIRE_EQ(0, mkdir("User/Bad.cap", 0755));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
	ATF_REQUIRE_EQ(0, rmdir("User/Bad.cap"));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(!bundle_registry_label_installed("org.test.absent/worker"));

	/* A failed system refresh retains activation state, but not absence. */
	ATF_REQUIRE_EQ(0, mkdir("System/Bad.cap", 0755));
	ATF_REQUIRE_EQ(-1, bundle_registry_init());
	ATF_CHECK_EQ(1, bundle_registry_count());
	ATF_CHECK(bundle_registry_label_installed("org.test.good/worker"));
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
	ATF_REQUIRE_EQ(0, rmdir("System/Bad.cap"));

	/* A missing optional root is still an incomplete installation view. */
	ATF_REQUIRE_EQ(0, rmdir("User"));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.absent/worker"));
	bundle_registry_teardown();
}

ATF_TC(installed_empty_and_removed);
ATF_TC_HEAD(installed_empty_and_removed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(installed_empty_and_removed, tc)
{

	setup_inventory();
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.removed/worker"));
	make_bundle("System/Keep.cap", "org.test.keep", "worker", 1);
	make_bundle("User/Remove.cap", "org.test.removed", "worker", 1);
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.removed/worker"));
	ATF_REQUIRE_EQ(0, rename("User/Remove.cap", "Removed.cap"));
	/* Queries are snapshots, and must not be treated as deletion authority. */
	ATF_CHECK(bundle_registry_label_installed("org.test.removed/worker"));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(!bundle_registry_label_installed("org.test.removed/worker"));
	ATF_CHECK(bundle_registry_label_installed("org.test.keep/worker"));
	ATF_REQUIRE_EQ(0, rename("Removed.cap", "User/Remove.cap"));
	ATF_REQUIRE_EQ(0, bundle_registry_init());
	ATF_CHECK(bundle_registry_label_installed("org.test.removed/worker"));
	bundle_registry_teardown();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proto_contract);
	ATF_TP_ADD_TC(tp, label_installed_unknown);
	ATF_TP_ADD_TC(tp, installed_disabled_and_superseded);
	ATF_TP_ADD_TC(tp, installed_incomplete_scan);
	ATF_TP_ADD_TC(tp, installed_empty_and_removed);

	return (atf_no_error());
}

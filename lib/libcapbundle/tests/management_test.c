/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Manifest parsing, verification, and accessor coverage for the §5 service
 * management class (management = "core|system|user").  Exercises
 * capbundle_parse_unit_ucl(), capbundle_verify(), the public accessor, and
 * capbundle_svc_fill_manifest() at their boundaries with no daemon or
 * capability kernel required.
 */

#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "libcapbundle_internal.h"

/*
 * Write a Unit.ucl body to a temp file in the test's cwd and parse it.  Every
 * body must carry a real activation trigger; boot=true keeps these focused on
 * the management key.  Returns the capbundle_parse_unit_ucl() result.
 */
static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.management",
	    sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

/* --- Parsing --- */

ATF_TC_WITHOUT_HEAD(management_absent_defaults_system);
ATF_TC_BODY(management_absent_defaults_system, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* No management key: zero-init default must be system, not core. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.management);
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, capbundle_svc_management_class(&svc));
}

ATF_TC_WITHOUT_HEAD(management_system_parses);
ATF_TC_BODY(management_system_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nmanagement = \"system\";\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.management);
}

ATF_TC_WITHOUT_HEAD(management_core_parses);
ATF_TC_BODY(management_core_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nmanagement = \"core\";\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_MGMT_CORE, svc.management);
	ATF_CHECK_EQ(SVC_MGMT_CORE, capbundle_svc_management_class(&svc));
}

ATF_TC_WITHOUT_HEAD(management_user_parses);
ATF_TC_BODY(management_user_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nmanagement = \"user\";\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_MGMT_USER, svc.management);
}

ATF_TC_WITHOUT_HEAD(management_garbage_string_rejected);
ATF_TC_BODY(management_garbage_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* "root" is not a class; the parser must fail closed with a diagnostic. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nmanagement = \"root\";\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "management") != NULL);
}

ATF_TC_WITHOUT_HEAD(management_empty_string_rejected);
ATF_TC_BODY(management_empty_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nmanagement = \"\";\n", &svc,
	    err, sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(management_non_string_rejected);
ATF_TC_BODY(management_non_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* An integer (or any non-string) is not a valid class. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nmanagement = 1;\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "management") != NULL);
}

/* --- fill_manifest round-trip --- */

ATF_TC_WITHOUT_HEAD(management_fill_manifest_roundtrip);
ATF_TC_BODY(management_fill_manifest_roundtrip, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nmanagement = \"core\";\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(SVC_MGMT_CORE, m.management);

	/* Default (system == 0) must survive fill_manifest's memset, too. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, m.management);
}

/* --- Verification --- */

/*
 * Build a one-unit capbundle on disk in the test cwd and parse its unit so
 * capbundle_verify() has a real tree (executable program, valid activation) to
 * walk.  The management class is then overridden to *mgmt* for the bounds test.
 */
static void
build_verifiable_bundle(struct capbundle *b, int mgmt)
{
	int fd;

	memset(b, 0, sizeof(*b));
	strlcpy(b->path, ".", sizeof(b->path));
	strlcpy(b->name, "Management.cap", sizeof(b->name));
	strlcpy(b->bundle_id, "org.test.management", sizeof(b->bundle_id));

	ATF_REQUIRE(mkdir("bin", 0755) == 0 || errno == EEXIST);
	fd = open("bin/worker", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, close(fd));

	{
		struct capbundle_service *svc = &b->services[0];
		char err[256];

		err[0] = '\0';
		ATF_REQUIRE_EQ_MSG(0, capbundle_parse_unit_ucl("Unit.ucl", ".",
		    b, "worker", svc, err, sizeof(err)),
		    "parse failed: %s", err);
		/* Program resolves to ./bin/worker, created above. */
		svc->management = mgmt;
	}
	b->nservices = 1;
	strlcpy(b->unit_names[0], "worker", sizeof(b->unit_names[0]));
	b->nunit_names = 1;
}

ATF_TC_WITHOUT_HEAD(verify_accepts_valid_classes);
ATF_TC_BODY(verify_accepts_valid_classes, tc)
{
	struct capbundle b;
	char err[256];
	FILE *f;
	int classes[] = { SVC_MGMT_SYSTEM, SVC_MGMT_CORE, SVC_MGMT_USER };
	unsigned i;

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs("activation { boot = true; }\n", f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	for (i = 0; i < nitems(classes); i++) {
		build_verifiable_bundle(&b, classes[i]);
		err[0] = '\0';
		ATF_CHECK_EQ_MSG(0, capbundle_verify(&b, err, sizeof(err)),
		    "class %d rejected: %s", classes[i], err);
	}
}

ATF_TC_WITHOUT_HEAD(verify_rejects_out_of_range_class);
ATF_TC_BODY(verify_rejects_out_of_range_class, tc)
{
	struct capbundle b;
	char err[256];
	FILE *f;

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs("activation { boot = true; }\n", f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	/* A value no parser would produce must still be caught by verify. */
	build_verifiable_bundle(&b, 99);
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(&b, err, sizeof(err)));
	ATF_CHECK(strstr(err, "management") != NULL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, management_absent_defaults_system);
	ATF_TP_ADD_TC(tp, management_system_parses);
	ATF_TP_ADD_TC(tp, management_core_parses);
	ATF_TP_ADD_TC(tp, management_user_parses);
	ATF_TP_ADD_TC(tp, management_garbage_string_rejected);
	ATF_TP_ADD_TC(tp, management_empty_string_rejected);
	ATF_TP_ADD_TC(tp, management_non_string_rejected);
	ATF_TP_ADD_TC(tp, management_fill_manifest_roundtrip);
	ATF_TP_ADD_TC(tp, verify_accepts_valid_classes);
	ATF_TP_ADD_TC(tp, verify_rejects_out_of_range_class);

	return (atf_no_error());
}

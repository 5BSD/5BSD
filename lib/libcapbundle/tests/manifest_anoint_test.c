/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * IPC anointments in a bundle's policy file (docs/ipc-anointments-design.md):
 * the object form of activation.ipc entries ({ name; requires }) and the
 * top-level `anointments` key.  Exercises capbundle_parse_unit_ucl() at the
 * parser boundary plus the accessors and svc_manifest conversion -- no daemon
 * or capability kernel required.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "libcapbundle_internal.h"

static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.anoint", sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

#define	PARSE_OK(body, svc)						\
	do {								\
		char _err[512];						\
		ATF_REQUIRE_EQ_MSG(0, parse_unit((body), (svc), _err,	\
		    sizeof(_err)), "unexpected error: %s", _err);	\
	} while (0)

/* Parse must fail and the message must mention `needle`. */
#define	PARSE_FAILS(body, needle)					\
	do {								\
		struct capbundle_service _svc;				\
		char _err[512];						\
		ATF_REQUIRE_EQ_MSG(-1, parse_unit((body), &_svc, _err,	\
		    sizeof(_err)), "accepted: %s", (body));		\
		ATF_CHECK_MSG(strstr(_err, (needle)) != NULL,		\
		    "error '%s' lacks '%s'", _err, (needle));		\
	} while (0)

/* Build "activation { ipc = [ ... ]; }" around an ipc list body. */
static const char *
ipc_unit(const char *list)
{
	static char buf[8192];

	snprintf(buf, sizeof(buf), "activation { ipc = [ %s ]; }\n", list);
	return (buf);
}

/* A name of exactly `len` bytes: "a.bbbb...". */
static const char *
long_name(size_t len)
{
	static char buf[512];

	ATF_REQUIRE(len >= 3 && len < sizeof(buf));
	memset(buf, 'b', len);
	buf[0] = 'a';
	buf[1] = '.';
	buf[len] = '\0';
	return (buf);
}

/* ---- ipc: string form unchanged ------------------------------------ */

ATF_TC_WITHOUT_HEAD(string_ipc_unchanged);
ATF_TC_BODY(string_ipc_unchanged, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("\"org.test.a\", \"org.test.b\""), &svc);
	ATF_CHECK_EQ(2U, svc.nprovides);
	ATF_CHECK_STREQ("org.test.a", svc.provides[0]);
	ATF_CHECK_STREQ("org.test.b", svc.provides[1]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[1]);
	ATF_CHECK_EQ(0U, svc.nanointments);
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 0));
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 1));
	ATF_CHECK_EQ(0U, capbundle_svc_nanointments(&svc));
}

ATF_TC_WITHOUT_HEAD(string_ipc_bare_scalar);
ATF_TC_BODY(string_ipc_bare_scalar, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation { ipc = \"org.test.solo\"; }\n", &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ("org.test.solo", svc.provides[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
}

/* ---- ipc: object form ---------------------------------------------- */

ATF_TC_WITHOUT_HEAD(object_ipc_one_require);
ATF_TC_BODY(object_ipc_one_require, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"system.Notify.System\"; "
	    "requires = [\"system.notify.system\"]; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ("system.Notify.System", svc.provides[0]);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);
	ATF_CHECK_STREQ("system.notify.system", svc.requires[0][0]);
	ATF_CHECK_EQ(1U, capbundle_svc_nrequires(&svc, 0));
	ATF_CHECK_STREQ("system.notify.system",
	    capbundle_svc_requires(&svc, 0, 0));
	ATF_CHECK(capbundle_svc_requires(&svc, 0, 1) == NULL);
}

ATF_TC_WITHOUT_HEAD(object_ipc_several_requires);
ATF_TC_BODY(object_ipc_several_requires, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"system.X.Both\"; "
	    "requires = [\"a.one\", \"a.two\", \"a.three\"]; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_EQ(3U, svc.nrequires[0]);
	ATF_CHECK_STREQ("a.one", svc.requires[0][0]);
	ATF_CHECK_STREQ("a.two", svc.requires[0][1]);
	ATF_CHECK_STREQ("a.three", svc.requires[0][2]);
	ATF_CHECK_STREQ("a.three", capbundle_svc_requires(&svc, 0, 2));
	ATF_CHECK(capbundle_svc_requires(&svc, 0, 3) == NULL);
}

ATF_TC_WITHOUT_HEAD(object_ipc_requires_scalar_string);
ATF_TC_BODY(object_ipc_requires_scalar_string, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"org.test.gated\"; "
	    "requires = \"org.test.key\"; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);
	ATF_CHECK_STREQ("org.test.key", svc.requires[0][0]);
}

ATF_TC_WITHOUT_HEAD(object_ipc_without_requires_is_open);
ATF_TC_BODY(object_ipc_without_requires_is_open, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"org.test.open\"; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ("org.test.open", svc.provides[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
}

ATF_TC_WITHOUT_HEAD(object_ipc_empty_requires_is_open);
ATF_TC_BODY(object_ipc_empty_requires_is_open, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"org.test.open\"; requires = []; }"),
	    &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
}

ATF_TC_WITHOUT_HEAD(object_ipc_max_requires_accepted);
ATF_TC_BODY(object_ipc_max_requires_accepted, tc)
{
	struct capbundle_service svc;
	char list[1024];
	unsigned i;

	snprintf(list, sizeof(list), "{ name = \"org.test.gated\"; requires = [");
	for (i = 0; i < CAPBUNDLE_MAX_REQUIRES; i++) {
		char one[64];

		snprintf(one, sizeof(one), "%s\"r.k%u\"", i ? ", " : "", i);
		strlcat(list, one, sizeof(list));
	}
	strlcat(list, "]; }", sizeof(list));
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_REQUIRES, svc.nrequires[0]);
	ATF_CHECK_STREQ("r.k0", svc.requires[0][0]);
	ATF_CHECK_STREQ("r.k7", svc.requires[0][CAPBUNDLE_MAX_REQUIRES - 1]);
}

ATF_TC_WITHOUT_HEAD(object_ipc_max_length_name_accepted);
ATF_TC_BODY(object_ipc_max_length_name_accepted, tc)
{
	struct capbundle_service svc;
	char list[512];

	snprintf(list, sizeof(list), "{ name = \"org.test.gated\"; "
	    "requires = [\"%s\"]; }", long_name(SWITCHBOARD_LABEL_MAX - 1));
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);
	ATF_CHECK_EQ((size_t)SWITCHBOARD_LABEL_MAX - 1,
	    strlen(svc.requires[0][0]));
}

/* ---- ipc: object form rejections ----------------------------------- */

ATF_TC_WITHOUT_HEAD(object_ipc_unknown_key_rejected);
ATF_TC_BODY(object_ipc_unknown_key_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; require = [\"a.b\"]; }"),
	    "unknown key");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; rights = 7; }"),
	    "unknown key");
}

ATF_TC_WITHOUT_HEAD(object_ipc_missing_name_rejected);
ATF_TC_BODY(object_ipc_missing_name_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ requires = [\"a.b\"]; }"), "name");
	PARSE_FAILS(ipc_unit("{ }"), "name");
}

ATF_TC_WITHOUT_HEAD(object_ipc_name_not_string_rejected);
ATF_TC_BODY(object_ipc_name_not_string_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = 42; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = [\"org.test.a\"]; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = \"\"; }"), "activation.ipc");
}

ATF_TC_WITHOUT_HEAD(object_ipc_name_star_rejected);
ATF_TC_BODY(object_ipc_name_star_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"*\"; }"), "*");
	PARSE_FAILS(ipc_unit("\"*\""), "*");
}

ATF_TC_WITHOUT_HEAD(object_ipc_name_invalid_rejected);
ATF_TC_BODY(object_ipc_name_invalid_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"nodots\"; }"), "reverse-domain");
	PARSE_FAILS(ipc_unit("{ name = \"org..test\"; }"), "reverse-domain");
	PARSE_FAILS(ipc_unit("{ name = \"org/test\"; }"), "reverse-domain");
}

ATF_TC_WITHOUT_HEAD(requires_star_rejected);
ATF_TC_BODY(requires_star_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"*\"]; }"),
	    "*");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = \"*\"; }"),
	    "*");
	/* Mixed with a legal name it is still refused. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\", \"*\"]; }"), "*");
}

ATF_TC_WITHOUT_HEAD(requires_invalid_name_rejected);
ATF_TC_BODY(requires_invalid_name_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"nodot\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\".a.b\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b.\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a..b\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b c\"]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b/c\"]; }"),
	    "requires");
}

ATF_TC_WITHOUT_HEAD(requires_wrong_type_rejected);
ATF_TC_BODY(requires_wrong_type_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = 7; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = true; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = { x = 1 }; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b\", 3]; }"),
	    "requires");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [[\"a.b\"]]; }"), "requires");
}

ATF_TC_WITHOUT_HEAD(requires_duplicate_rejected);
ATF_TC_BODY(requires_duplicate_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\", \"a.c\", \"a.b\"]; }"), "duplicate");
}

ATF_TC_WITHOUT_HEAD(requires_too_many_rejected);
ATF_TC_BODY(requires_too_many_rejected, tc)
{
	char list[1024];
	unsigned i;

	snprintf(list, sizeof(list), "{ name = \"org.test.gated\"; requires = [");
	for (i = 0; i < CAPBUNDLE_MAX_REQUIRES + 1; i++) {
		char one[64];

		snprintf(one, sizeof(one), "%s\"r.k%u\"", i ? ", " : "", i);
		strlcat(list, one, sizeof(list));
	}
	strlcat(list, "]; }", sizeof(list));
	PARSE_FAILS(ipc_unit(list), "more than");
}

ATF_TC_WITHOUT_HEAD(requires_name_too_long_rejected);
ATF_TC_BODY(requires_name_too_long_rejected, tc)
{
	char list[512];

	snprintf(list, sizeof(list), "{ name = \"org.test.gated\"; "
	    "requires = [\"%s\"]; }", long_name(SWITCHBOARD_LABEL_MAX));
	PARSE_FAILS(ipc_unit(list), "requires");
}

ATF_TC_WITHOUT_HEAD(object_ipc_entry_wrong_type_rejected);
ATF_TC_BODY(object_ipc_entry_wrong_type_rejected, tc)
{

	PARSE_FAILS(ipc_unit("42"), "activation.ipc");
	PARSE_FAILS(ipc_unit("true"), "activation.ipc");
	PARSE_FAILS(ipc_unit("[\"org.test.a\"]"), "activation.ipc");
	PARSE_FAILS(ipc_unit("\"org.test.a\", 42"), "activation.ipc");
	PARSE_FAILS("activation { ipc = { name = \"org.test.a\"; }; }\n",
	    "activation.ipc");
	PARSE_FAILS("activation { ipc = 42; }\n", "activation.ipc");
}

/* ---- ipc: mixing forms --------------------------------------------- */

ATF_TC_WITHOUT_HEAD(mixed_string_and_object_list);
ATF_TC_BODY(mixed_string_and_object_list, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("\"system.Notify\", "
	    "{ name = \"system.Notify.System\"; "
	    "requires = [\"system.notify.system\"]; }, "
	    "{ name = \"system.Notify.Open\"; }, "
	    "\"system.Notify.Tail\""), &svc);
	ATF_CHECK_EQ(4U, svc.nprovides);
	ATF_CHECK_STREQ("system.Notify", svc.provides[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_STREQ("system.Notify.System", svc.provides[1]);
	ATF_CHECK_EQ(1U, svc.nrequires[1]);
	ATF_CHECK_STREQ("system.notify.system", svc.requires[1][0]);
	ATF_CHECK_STREQ("system.Notify.Open", svc.provides[2]);
	ATF_CHECK_EQ(0U, svc.nrequires[2]);
	ATF_CHECK_STREQ("system.Notify.Tail", svc.provides[3]);
	ATF_CHECK_EQ(0U, svc.nrequires[3]);
	/* Accessors agree with the raw fields. */
	ATF_CHECK_EQ(1U, capbundle_svc_nrequires(&svc, 1));
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 3));
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 4));
	ATF_CHECK(capbundle_svc_requires(&svc, 4, 0) == NULL);
}

ATF_TC_WITHOUT_HEAD(duplicate_endpoint_across_forms_rejected);
ATF_TC_BODY(duplicate_endpoint_across_forms_rejected, tc)
{

	PARSE_FAILS(ipc_unit("\"org.test.a\", { name = \"org.test.a\"; }"),
	    "duplicate");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; }, \"org.test.a\""),
	    "duplicate");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"x.y\"]; }, "
	    "{ name = \"org.test.a\"; }"), "duplicate");
	/* The plain string-form rule is unchanged. */
	PARSE_FAILS(ipc_unit("\"org.test.a\", \"org.test.a\""), "duplicate");
}

ATF_TC_WITHOUT_HEAD(ipc_too_many_entries_rejected);
ATF_TC_BODY(ipc_too_many_entries_rejected, tc)
{
	char list[1024] = "";
	unsigned i;

	for (i = 0; i < CAPBUNDLE_MAX_PROVIDES + 1; i++) {
		char one[64];

		snprintf(one, sizeof(one), "%s{ name = \"org.test.n%u\"; }",
		    i ? ", " : "", i);
		strlcat(list, one, sizeof(list));
	}
	PARSE_FAILS(ipc_unit(list), "more than");
}

ATF_TC_WITHOUT_HEAD(ipc_empty_list_still_rejected);
ATF_TC_BODY(ipc_empty_list_still_rejected, tc)
{

	PARSE_FAILS("activation { ipc = []; }\n", "empty");
}

ATF_TC_WITHOUT_HEAD(helper_prefix_rejected_in_object_form);
ATF_TC_BODY(helper_prefix_rejected_in_object_form, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"helper.org.test.victim.worker\"; }"),
	    "helper.");
	PARSE_FAILS(ipc_unit("{ name = \"helper.org.test.victim.worker\"; "
	    "requires = [\"a.b\"]; }"), "helper.");
	/* A "helper." *requirement* is a valid name; only endpoints are
	 * reserved. */
	{
		struct capbundle_service svc;

		PARSE_OK(ipc_unit("{ name = \"org.test.a\"; "
		    "requires = [\"helper.org.test.x\"]; }"), &svc);
		ATF_CHECK_STREQ("helper.org.test.x", svc.requires[0][0]);
	}
}

ATF_TC_WITHOUT_HEAD(helper_unit_with_object_ipc_rejected);
ATF_TC_BODY(helper_unit_with_object_ipc_rejected, tc)
{

	PARSE_FAILS("activation { helper = true; "
	    "ipc = [{ name = \"org.test.a\"; }]; }\n", "helper");
	PARSE_FAILS("activation { helper = true; ipc = [\"org.test.a\"]; }\n",
	    "helper");
}

ATF_TC_WITHOUT_HEAD(helper_synthesis_leaves_nrequires_zero);
ATF_TC_BODY(helper_synthesis_leaves_nrequires_zero, tc)
{
	struct capbundle_service svc;

	/* Poison the field: synthesis must reset it, not inherit garbage. */
	PARSE_OK("activation { helper = true; }\n", &svc);
	ATF_CHECK(svc.is_helper);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ("helper.org.test.anoint.worker", svc.provides[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 0));
	ATF_CHECK_EQ(0, capbundle_svc_provides_index(&svc,
	    "helper.org.test.anoint.worker"));
}

/* ---- anointments ---------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(anointments_absent_is_empty);
ATF_TC_BODY(anointments_absent_is_empty, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation { boot = true; }\n", &svc);
	ATF_CHECK_EQ(0U, svc.nanointments);
	ATF_CHECK_EQ(0U, capbundle_svc_nanointments(&svc));
	ATF_CHECK(capbundle_svc_anointment(&svc, 0) == NULL);
}

ATF_TC_WITHOUT_HEAD(anointments_string_form);
ATF_TC_BODY(anointments_string_form, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation { boot = true; }\n"
	    "anointments = \"system.notify.system\";\n", &svc);
	ATF_CHECK_EQ(1U, svc.nanointments);
	ATF_CHECK_STREQ("system.notify.system", svc.anointments[0]);
	ATF_CHECK_EQ(1U, capbundle_svc_nanointments(&svc));
	ATF_CHECK_STREQ("system.notify.system",
	    capbundle_svc_anointment(&svc, 0));
	ATF_CHECK(capbundle_svc_anointment(&svc, 1) == NULL);
}

ATF_TC_WITHOUT_HEAD(anointments_array_form);
ATF_TC_BODY(anointments_array_form, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation { boot = true; }\n"
	    "anointments = [\"a.one\", \"a.two\", \"system.storage.admin\"];\n",
	    &svc);
	ATF_CHECK_EQ(3U, svc.nanointments);
	ATF_CHECK_STREQ("a.one", svc.anointments[0]);
	ATF_CHECK_STREQ("a.two", svc.anointments[1]);
	ATF_CHECK_STREQ("system.storage.admin", svc.anointments[2]);
	ATF_CHECK_STREQ("a.two", capbundle_svc_anointment(&svc, 1));
}

ATF_TC_WITHOUT_HEAD(anointments_empty_array);
ATF_TC_BODY(anointments_empty_array, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation { boot = true; }\nanointments = [];\n", &svc);
	ATF_CHECK_EQ(0U, svc.nanointments);
}

ATF_TC_WITHOUT_HEAD(anointments_star_rejected);
ATF_TC_BODY(anointments_star_rejected, tc)
{
	struct capbundle_service svc;
	char err[512];

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "anointments = [\"*\"];\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "anointments") != NULL, "err: %s", err);
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "anointments = \"*\";\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "anointments") != NULL, "err: %s", err);
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "anointments = [\"a.b\", \"*\"];\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);
}

ATF_TC_WITHOUT_HEAD(anointments_duplicates_rejected);
ATF_TC_BODY(anointments_duplicates_rejected, tc)
{

	PARSE_FAILS("activation { boot = true; }\n"
	    "anointments = [\"a.b\", \"c.d\", \"a.b\"];\n", "duplicate");
}

ATF_TC_WITHOUT_HEAD(anointments_max_accepted_over_max_rejected);
ATF_TC_BODY(anointments_max_accepted_over_max_rejected, tc)
{
	struct capbundle_service svc;
	char body[4096];
	unsigned i;

	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "anointments = [");
	for (i = 0; i < CAPBUNDLE_MAX_ANOINTMENTS; i++) {
		char one[64];

		snprintf(one, sizeof(one), "%s\"n.k%u\"", i ? ", " : "", i);
		strlcat(body, one, sizeof(body));
	}
	strlcat(body, "];\n", sizeof(body));
	PARSE_OK(body, &svc);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_ANOINTMENTS, svc.nanointments);
	ATF_CHECK_STREQ("n.k31",
	    svc.anointments[CAPBUNDLE_MAX_ANOINTMENTS - 1]);

	/* One more tips it over. */
	body[strlen(body) - 3] = '\0';	/* strip "];\n" */
	strlcat(body, ", \"n.kmore\"];\n", sizeof(body));
	PARSE_FAILS(body, "more than");
}

ATF_TC_WITHOUT_HEAD(anointments_invalid_rejected);
ATF_TC_BODY(anointments_invalid_rejected, tc)
{
	char body[512];

	PARSE_FAILS("activation { boot = true; }\nanointments = [\"nodot\"];\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = [\"\"];\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = [\"a..b\"];\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = [\"a.b!\"];\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = 7;\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = [7];\n",
	    "anointments");
	PARSE_FAILS("activation { boot = true; }\nanointments = { a = 1 };\n",
	    "anointments");
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "anointments = [\"%s\"];\n", long_name(SWITCHBOARD_LABEL_MAX));
	PARSE_FAILS(body, "anointments");
}

ATF_TC_WITHOUT_HEAD(anointments_max_length_accepted);
ATF_TC_BODY(anointments_max_length_accepted, tc)
{
	struct capbundle_service svc;
	char body[512];

	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "anointments = [\"%s\"];\n", long_name(SWITCHBOARD_LABEL_MAX - 1));
	PARSE_OK(body, &svc);
	ATF_CHECK_EQ((size_t)SWITCHBOARD_LABEL_MAX - 1,
	    strlen(svc.anointments[0]));
}

ATF_TC_WITHOUT_HEAD(anointments_inside_activation_rejected);
ATF_TC_BODY(anointments_inside_activation_rejected, tc)
{

	/* It is a top-level key, not an activation source. */
	PARSE_FAILS("activation { boot = true; anointments = [\"a.b\"]; }\n",
	    "unknown key");
}

/* ---- provider and consumer together -------------------------------- */

ATF_TC_WITHOUT_HEAD(provider_and_consumer_in_one_unit);
ATF_TC_BODY(provider_and_consumer_in_one_unit, tc)
{
	struct capbundle_service svc;

	PARSE_OK("activation {\n"
	    "    ipc = [\n"
	    "        \"system.Notify\",\n"
	    "        { name = \"system.Notify.System\";\n"
	    "          requires = [\"system.notify.system\"]; }\n"
	    "    ];\n"
	    "}\n"
	    "anointments = [\"system.log.client\"];\n", &svc);
	ATF_CHECK_EQ(2U, svc.nprovides);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_EQ(1U, svc.nrequires[1]);
	ATF_CHECK_EQ(1U, svc.nanointments);
	ATF_CHECK_STREQ("system.log.client", svc.anointments[0]);
}

/* ---- accessors ------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(provides_index_accessor);
ATF_TC_BODY(provides_index_accessor, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("\"org.test.a\", { name = \"org.test.b\"; "
	    "requires = [\"k.b\"]; }, \"org.test.c\""), &svc);
	ATF_CHECK_EQ(0, capbundle_svc_provides_index(&svc, "org.test.a"));
	ATF_CHECK_EQ(1, capbundle_svc_provides_index(&svc, "org.test.b"));
	ATF_CHECK_EQ(2, capbundle_svc_provides_index(&svc, "org.test.c"));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, "org.test.d"));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, "org.test"));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, ""));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, NULL));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(NULL, "org.test.a"));
	/* Case-sensitive, exact match only. */
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, "ORG.TEST.A"));
	/* Chaining index -> requires. */
	ATF_CHECK_STREQ("k.b", capbundle_svc_requires(&svc,
	    (unsigned)capbundle_svc_provides_index(&svc, "org.test.b"), 0));
}

ATF_TC_WITHOUT_HEAD(accessors_null_safe_and_bounded);
ATF_TC_BODY(accessors_null_safe_and_bounded, tc)
{
	struct capbundle_service svc;

	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(NULL, 0));
	ATF_CHECK(capbundle_svc_requires(NULL, 0, 0) == NULL);
	ATF_CHECK_EQ(0U, capbundle_svc_nanointments(NULL));
	ATF_CHECK(capbundle_svc_anointment(NULL, 0) == NULL);

	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; requires = [\"k.a\"]; }"),
	    &svc);
	/* Out-of-range provides index, including beyond the array itself. */
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 1));
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, CAPBUNDLE_MAX_PROVIDES));
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, UINT_MAX));
	ATF_CHECK(capbundle_svc_requires(&svc, 0, UINT_MAX) == NULL);
	ATF_CHECK(capbundle_svc_requires(&svc, UINT_MAX, 0) == NULL);
	ATF_CHECK(capbundle_svc_anointment(&svc, UINT_MAX) == NULL);
	/* Corrupted counts are clamped, never trusted. */
	svc.nrequires[0] = CAPBUNDLE_MAX_REQUIRES + 5;
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_REQUIRES,
	    capbundle_svc_nrequires(&svc, 0));
	svc.nanointments = CAPBUNDLE_MAX_ANOINTMENTS + 5;
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_ANOINTMENTS,
	    capbundle_svc_nanointments(&svc));
}

/* ---- svc_manifest conversion --------------------------------------- */

ATF_TC_WITHOUT_HEAD(fill_manifest_round_trips);
ATF_TC_BODY(fill_manifest_round_trips, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;
	unsigned i, j;

	PARSE_OK("activation { ipc = [\n"
	    "  \"system.Notify\",\n"
	    "  { name = \"system.Notify.System\"; "
	    "requires = [\"system.notify.system\"]; },\n"
	    "  { name = \"system.X.Both\"; requires = [\"a.one\", \"a.two\"]; }\n"
	    "]; }\n"
	    "anointments = [\"system.log.client\", \"system.trace.client\"];\n",
	    &svc);
	memset(&m, 0xa5, sizeof(m));
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(3U, m.nprovides);
	ATF_CHECK_EQ(0U, m.nrequires[0]);
	ATF_CHECK_EQ(1U, m.nrequires[1]);
	ATF_CHECK_STREQ("system.notify.system", m.requires[1][0]);
	ATF_CHECK_EQ(2U, m.nrequires[2]);
	ATF_CHECK_STREQ("a.one", m.requires[2][0]);
	ATF_CHECK_STREQ("a.two", m.requires[2][1]);
	for (i = 0; i < SWITCHBOARD_MAX_PROVIDES; i++)
		for (j = m.nrequires[i]; j < SWITCHBOARD_MAX_REQUIRES; j++)
			ATF_CHECK_EQ('\0', m.requires[i][j][0]);
	for (i = m.nprovides; i < SWITCHBOARD_MAX_PROVIDES; i++)
		ATF_CHECK_EQ(0U, m.nrequires[i]);
	ATF_CHECK_EQ(2U, m.nanointments);
	ATF_CHECK_STREQ("system.log.client", m.anointments[0]);
	ATF_CHECK_STREQ("system.trace.client", m.anointments[1]);
	ATF_CHECK_EQ('\0', m.anointments[2][0]);
	/* The parallel index survives the conversion. */
	for (i = 0; i < m.nprovides; i++)
		ATF_CHECK_STREQ(svc.provides[i], m.provides[i]);
}

ATF_TC_WITHOUT_HEAD(fill_manifest_rejects_overflowed_counts);
ATF_TC_BODY(fill_manifest_rejects_overflowed_counts, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;

	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; requires = [\"k.a\"]; }"),
	    &svc);
	svc.nrequires[0] = SWITCHBOARD_MAX_REQUIRES + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(EOVERFLOW, errno);

	svc.nrequires[0] = 1;
	svc.nanointments = SWITCHBOARD_MAX_ANOINTMENTS + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(EOVERFLOW, errno);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, string_ipc_unchanged);
	ATF_TP_ADD_TC(tp, string_ipc_bare_scalar);
	ATF_TP_ADD_TC(tp, object_ipc_one_require);
	ATF_TP_ADD_TC(tp, object_ipc_several_requires);
	ATF_TP_ADD_TC(tp, object_ipc_requires_scalar_string);
	ATF_TP_ADD_TC(tp, object_ipc_without_requires_is_open);
	ATF_TP_ADD_TC(tp, object_ipc_empty_requires_is_open);
	ATF_TP_ADD_TC(tp, object_ipc_max_requires_accepted);
	ATF_TP_ADD_TC(tp, object_ipc_max_length_name_accepted);
	ATF_TP_ADD_TC(tp, object_ipc_unknown_key_rejected);
	ATF_TP_ADD_TC(tp, object_ipc_missing_name_rejected);
	ATF_TP_ADD_TC(tp, object_ipc_name_not_string_rejected);
	ATF_TP_ADD_TC(tp, object_ipc_name_star_rejected);
	ATF_TP_ADD_TC(tp, object_ipc_name_invalid_rejected);
	ATF_TP_ADD_TC(tp, requires_star_rejected);
	ATF_TP_ADD_TC(tp, requires_invalid_name_rejected);
	ATF_TP_ADD_TC(tp, requires_wrong_type_rejected);
	ATF_TP_ADD_TC(tp, requires_duplicate_rejected);
	ATF_TP_ADD_TC(tp, requires_too_many_rejected);
	ATF_TP_ADD_TC(tp, requires_name_too_long_rejected);
	ATF_TP_ADD_TC(tp, object_ipc_entry_wrong_type_rejected);
	ATF_TP_ADD_TC(tp, mixed_string_and_object_list);
	ATF_TP_ADD_TC(tp, duplicate_endpoint_across_forms_rejected);
	ATF_TP_ADD_TC(tp, ipc_too_many_entries_rejected);
	ATF_TP_ADD_TC(tp, ipc_empty_list_still_rejected);
	ATF_TP_ADD_TC(tp, helper_prefix_rejected_in_object_form);
	ATF_TP_ADD_TC(tp, helper_unit_with_object_ipc_rejected);
	ATF_TP_ADD_TC(tp, helper_synthesis_leaves_nrequires_zero);
	ATF_TP_ADD_TC(tp, anointments_absent_is_empty);
	ATF_TP_ADD_TC(tp, anointments_string_form);
	ATF_TP_ADD_TC(tp, anointments_array_form);
	ATF_TP_ADD_TC(tp, anointments_empty_array);
	ATF_TP_ADD_TC(tp, anointments_star_rejected);
	ATF_TP_ADD_TC(tp, anointments_duplicates_rejected);
	ATF_TP_ADD_TC(tp, anointments_max_accepted_over_max_rejected);
	ATF_TP_ADD_TC(tp, anointments_invalid_rejected);
	ATF_TP_ADD_TC(tp, anointments_max_length_accepted);
	ATF_TP_ADD_TC(tp, anointments_inside_activation_rejected);
	ATF_TP_ADD_TC(tp, provider_and_consumer_in_one_unit);
	ATF_TP_ADD_TC(tp, provides_index_accessor);
	ATF_TP_ADD_TC(tp, accessors_null_safe_and_bounded);
	ATF_TP_ADD_TC(tp, fill_manifest_round_trips);
	ATF_TP_ADD_TC(tp, fill_manifest_rejects_overflowed_counts);
	return (atf_no_error());
}

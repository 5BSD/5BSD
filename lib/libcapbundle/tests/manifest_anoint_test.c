/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * IPC anointments in a bundle's policy file (docs/book/src/plane/anointments.md):
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
	    "holds = \"system.notify.system\";\n", &svc);
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
	    "holds = [\"a.one\", \"a.two\", \"system.storage.admin\"];\n",
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

	PARSE_OK("activation { boot = true; }\nholds = [];\n", &svc);
	ATF_CHECK_EQ(0U, svc.nanointments);
}

ATF_TC_WITHOUT_HEAD(anointments_star_rejected);
ATF_TC_BODY(anointments_star_rejected, tc)
{
	struct capbundle_service svc;
	char err[512];

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "holds = [\"*\"];\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "holds") != NULL, "err: %s", err);
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "holds = \"*\";\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "holds") != NULL, "err: %s", err);
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);

	ATF_REQUIRE_EQ(-1, parse_unit("activation { boot = true; }\n"
	    "holds = [\"a.b\", \"*\"];\n", &svc, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "*") != NULL, "err: %s", err);
}

ATF_TC_WITHOUT_HEAD(anointments_duplicates_rejected);
ATF_TC_BODY(anointments_duplicates_rejected, tc)
{

	PARSE_FAILS("activation { boot = true; }\n"
	    "holds = [\"a.b\", \"c.d\", \"a.b\"];\n", "duplicate");
}

ATF_TC_WITHOUT_HEAD(anointments_max_accepted_over_max_rejected);
ATF_TC_BODY(anointments_max_accepted_over_max_rejected, tc)
{
	struct capbundle_service svc;
	char body[4096];
	unsigned i;

	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [");
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

	PARSE_FAILS("activation { boot = true; }\nholds = [\"nodot\"];\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = [\"\"];\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = [\"a..b\"];\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = [\"a.b!\"];\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = 7;\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = [7];\n",
	    "holds");
	PARSE_FAILS("activation { boot = true; }\nholds = { a = 1 };\n",
	    "holds");
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [\"%s\"];\n", long_name(SWITCHBOARD_LABEL_MAX));
	PARSE_FAILS(body, "holds");
}

ATF_TC_WITHOUT_HEAD(anointments_max_length_accepted);
ATF_TC_BODY(anointments_max_length_accepted, tc)
{
	struct capbundle_service svc;
	char body[512];

	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [\"%s\"];\n", long_name(SWITCHBOARD_LABEL_MAX - 1));
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
	    "holds = [\"system.log.client\"];\n", &svc);
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
	    "holds = [\"system.log.client\", \"system.trace.client\"];\n",
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

/* ==== edge cases and negative paths ================================== */

/*
 * A unique name of exactly `len` bytes: "<tag>.bbbb...".  `tag` keeps the
 * result distinct from long_name() and from other tagged names.
 */
static const char *
tagged_name(char *buf, size_t bufsz, const char *tag, size_t len)
{
	size_t tl = strlen(tag);

	ATF_REQUIRE(len > tl + 1 && len < bufsz);
	memset(buf, 'b', len);
	memcpy(buf, tag, tl);
	buf[tl] = '.';
	buf[len] = '\0';
	return (buf);
}

/*
 * Names that fail capbundle_valid_service_name(): leading/trailing/doubled
 * dot, empty, no dot, whitespace, control bytes, UTF-8, the wildcard and
 * wildcard fragments.  Written as UCL double-quoted string bodies (JSON
 * escapes are decoded by libucl), so no entry may contain a bare '"'.
 */
static const char *const bad_names[] = {
	".a.b", "a.b.", "a..b", "", "nodot", "a b.c", "a.b c", " a.b", "a.b ",
	"a\\tb.c", "a.b\\n", "org.t\xc3\xa9st", "a.\xe2\x80\x8b.b",
	"\xef\xbc\x8a", "*", "system.*", "*.system", "a.*.b", "a.b*", "**",
	"a.b/c", "a.b:c", "a.b@c", "a.b+c", "a.b,c", "a,b", "a.b;c", "a.b=c",
	"a.b#c", "a.b$c", "a.b~c", "a.b\\\\c", ".", "..", "...",
};

static void
check_requires_name_rejected(const char *name)
{
	char list[512];

	snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
	    "requires = [\"%s\"]; }", name);
	PARSE_FAILS(ipc_unit(list), "requires");
	snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
	    "requires = \"%s\"; }", name);
	PARSE_FAILS(ipc_unit(list), "requires");
	/* Buried after a legal name it is still refused. */
	snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
	    "requires = [\"a.ok\", \"%s\"]; }", name);
	PARSE_FAILS(ipc_unit(list), "requires");
}

static void
check_anointment_name_rejected(const char *name)
{
	char body[512];

	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [\"%s\"];\n", name);
	PARSE_FAILS(body, "holds");
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = \"%s\";\n", name);
	PARSE_FAILS(body, "holds");
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [\"a.ok\", \"%s\"];\n", name);
	PARSE_FAILS(body, "holds");
}

static void
check_endpoint_name_rejected(const char *name)
{
	char list[512];

	snprintf(list, sizeof(list), "{ name = \"%s\"; }", name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	snprintf(list, sizeof(list), "{ name = \"%s\"; requires = [\"a.b\"]; }",
	    name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	snprintf(list, sizeof(list), "\"%s\"", name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	/* After a legal entry: the whole list is refused. */
	snprintf(list, sizeof(list), "\"org.test.ok\", { name = \"%s\"; }",
	    name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
}

/* ---- length boundaries: 63 accepted, 64 rejected, everywhere --------- */

ATF_TC_WITHOUT_HEAD(endpoint_name_length_boundary);
ATF_TC_BODY(endpoint_name_length_boundary, tc)
{
	struct capbundle_service svc;
	char name[128], list[512];

	/* 63: accepted in both forms, stored intact. */
	tagged_name(name, sizeof(name), "e", SWITCHBOARD_LABEL_MAX - 1);
	snprintf(list, sizeof(list), "\"%s\"", name);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ(name, svc.provides[0]);
	ATF_CHECK_EQ((size_t)SWITCHBOARD_LABEL_MAX - 1, strlen(svc.provides[0]));
	ATF_CHECK_EQ(0, capbundle_svc_provides_index(&svc, name));

	snprintf(list, sizeof(list), "{ name = \"%s\"; requires = [\"a.b\"]; }",
	    name);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_STREQ(name, svc.provides[0]);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);

	/* 64: rejected in both forms, gated or not. */
	tagged_name(name, sizeof(name), "e", SWITCHBOARD_LABEL_MAX);
	snprintf(list, sizeof(list), "\"%s\"", name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	snprintf(list, sizeof(list), "{ name = \"%s\"; }", name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	snprintf(list, sizeof(list), "{ name = \"%s\"; requires = [\"a.b\"]; }",
	    name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
	/* Well past the limit, but under CAPBUNDLE_NAME_MAX: still rejected. */
	tagged_name(name, sizeof(name), "e", 100);
	snprintf(list, sizeof(list), "{ name = \"%s\"; }", name);
	PARSE_FAILS(ipc_unit(list), "activation.ipc");
}

ATF_TC_WITHOUT_HEAD(requires_name_length_boundary);
ATF_TC_BODY(requires_name_length_boundary, tc)
{
	struct capbundle_service svc;
	char name[128], list[512];

	tagged_name(name, sizeof(name), "r", SWITCHBOARD_LABEL_MAX - 1);
	snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
	    "requires = [\"%s\"]; }", name);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_STREQ(name, svc.requires[0][0]);
	ATF_CHECK_STREQ(name, capbundle_svc_requires(&svc, 0, 0));
	snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
	    "requires = \"%s\"; }", name);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_STREQ(name, svc.requires[0][0]);

	tagged_name(name, sizeof(name), "r", SWITCHBOARD_LABEL_MAX);
	check_requires_name_rejected(name);
	tagged_name(name, sizeof(name), "r", SWITCHBOARD_LABEL_MAX + 1);
	check_requires_name_rejected(name);
}

ATF_TC_WITHOUT_HEAD(anointments_name_length_boundary);
ATF_TC_BODY(anointments_name_length_boundary, tc)
{
	struct capbundle_service svc;
	char name[128], body[512];

	tagged_name(name, sizeof(name), "n", SWITCHBOARD_LABEL_MAX - 1);
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [\"a.b\", \"%s\"];\n", name);
	PARSE_OK(body, &svc);
	ATF_CHECK_EQ(2U, svc.nanointments);
	ATF_CHECK_STREQ(name, svc.anointments[1]);
	ATF_CHECK_STREQ(name, capbundle_svc_anointment(&svc, 1));
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = \"%s\";\n", name);
	PARSE_OK(body, &svc);
	ATF_CHECK_STREQ(name, svc.anointments[0]);

	tagged_name(name, sizeof(name), "n", SWITCHBOARD_LABEL_MAX);
	check_anointment_name_rejected(name);
	tagged_name(name, sizeof(name), "n", SWITCHBOARD_LABEL_MAX + 1);
	check_anointment_name_rejected(name);
}

/* ---- count boundaries ------------------------------------------------ */

/* An ipc list of `neps` open endpoints with `nreq` requires on endpoint `at`. */
static void
build_ipc_with_requires(char *buf, size_t bufsz, unsigned neps, unsigned at,
    unsigned nreq)
{
	unsigned i, j;

	buf[0] = '\0';
	for (i = 0; i < neps; i++) {
		char one[1024];

		snprintf(one, sizeof(one), "%s{ name = \"org.test.n%u\"",
		    i ? ", " : "", i);
		strlcat(buf, one, bufsz);
		if (i == at) {
			strlcat(buf, "; requires = [", bufsz);
			for (j = 0; j < nreq; j++) {
				snprintf(one, sizeof(one), "%s\"r.k%u\"",
				    j ? ", " : "", j);
				strlcat(buf, one, bufsz);
			}
			strlcat(buf, "]", bufsz);
		}
		strlcat(buf, "; }", bufsz);
	}
}

ATF_TC_WITHOUT_HEAD(requires_count_boundary);
ATF_TC_BODY(requires_count_boundary, tc)
{
	struct capbundle_service svc;
	char list[4096];
	unsigned i;

	/* Exactly the maximum, on a non-first endpoint, accepted. */
	build_ipc_with_requires(list, sizeof(list), 4, 2,
	    CAPBUNDLE_MAX_REQUIRES);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ(4U, svc.nprovides);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[1]);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_REQUIRES, svc.nrequires[2]);
	ATF_CHECK_EQ(0U, svc.nrequires[3]);
	for (i = 0; i < CAPBUNDLE_MAX_REQUIRES; i++) {
		char want[32];

		snprintf(want, sizeof(want), "r.k%u", i);
		ATF_CHECK_STREQ(want, svc.requires[2][i]);
	}
	/* One more, on the same non-first endpoint, rejected. */
	build_ipc_with_requires(list, sizeof(list), 4, 2,
	    CAPBUNDLE_MAX_REQUIRES + 1);
	PARSE_FAILS(ipc_unit(list), "requires");
	PARSE_FAILS(ipc_unit(list), "more than");
	/* And on the last endpoint of a full list. */
	build_ipc_with_requires(list, sizeof(list), CAPBUNDLE_MAX_PROVIDES,
	    CAPBUNDLE_MAX_PROVIDES - 1, CAPBUNDLE_MAX_REQUIRES + 1);
	PARSE_FAILS(ipc_unit(list), "more than");
	build_ipc_with_requires(list, sizeof(list), CAPBUNDLE_MAX_PROVIDES,
	    CAPBUNDLE_MAX_PROVIDES - 1, CAPBUNDLE_MAX_REQUIRES);
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_REQUIRES,
	    svc.nrequires[CAPBUNDLE_MAX_PROVIDES - 1]);
}

ATF_TC_WITHOUT_HEAD(anointments_count_boundary);
ATF_TC_BODY(anointments_count_boundary, tc)
{
	struct capbundle_service svc;
	char body[8192], name[128], tag[16];
	unsigned i;

	/* 32 names, every one at the 63-byte limit: max count x max length. */
	snprintf(body, sizeof(body), "activation { boot = true; }\n"
	    "holds = [");
	for (i = 0; i < CAPBUNDLE_MAX_ANOINTMENTS; i++) {
		char one[128];

		snprintf(tag, sizeof(tag), "n%02u", i);
		tagged_name(name, sizeof(name), tag, SWITCHBOARD_LABEL_MAX - 1);
		snprintf(one, sizeof(one), "%s\"%s\"", i ? ", " : "", name);
		strlcat(body, one, sizeof(body));
	}
	strlcat(body, "];\n", sizeof(body));
	PARSE_OK(body, &svc);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_ANOINTMENTS, svc.nanointments);
	for (i = 0; i < CAPBUNDLE_MAX_ANOINTMENTS; i++) {
		snprintf(tag, sizeof(tag), "n%02u", i);
		tagged_name(name, sizeof(name), tag, SWITCHBOARD_LABEL_MAX - 1);
		ATF_CHECK_STREQ(name, svc.anointments[i]);
	}
	/* 33 rejected. */
	body[strlen(body) - 3] = '\0';
	strlcat(body, ", \"n.more\"];\n", sizeof(body));
	PARSE_FAILS(body, "holds");
	PARSE_FAILS(body, "more than");
}

/* ---- case sensitivity ----------------------------------------------- */

ATF_TC_WITHOUT_HEAD(names_are_case_sensitive);
ATF_TC_BODY(names_are_case_sensitive, tc)
{
	struct capbundle_service svc;

	/* Two anointments differing only in case are two anointments. */
	PARSE_OK("activation { boot = true; }\n"
	    "holds = [\"system.Notify.x\", \"system.notify.x\", "
	    "\"SYSTEM.NOTIFY.X\"];\n", &svc);
	ATF_CHECK_EQ(3U, svc.nanointments);
	ATF_CHECK_STREQ("system.Notify.x", svc.anointments[0]);
	ATF_CHECK_STREQ("system.notify.x", svc.anointments[1]);
	ATF_CHECK_STREQ("SYSTEM.NOTIFY.X", svc.anointments[2]);

	/* A requires list with both is not a duplicate. */
	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"system.Notify.x\", \"system.notify.x\"]; }"), &svc);
	ATF_CHECK_EQ(2U, svc.nrequires[0]);
	ATF_CHECK_STREQ("system.Notify.x", svc.requires[0][0]);
	ATF_CHECK_STREQ("system.notify.x", svc.requires[0][1]);

	/* Two endpoints differing only in case are two endpoints. */
	PARSE_OK(ipc_unit("\"system.Notify\", { name = \"system.notify\"; }"),
	    &svc);
	ATF_CHECK_EQ(2U, svc.nprovides);
	ATF_CHECK_EQ(0, capbundle_svc_provides_index(&svc, "system.Notify"));
	ATF_CHECK_EQ(1, capbundle_svc_provides_index(&svc, "system.notify"));
	ATF_CHECK_EQ(-1, capbundle_svc_provides_index(&svc, "System.Notify"));
}

/* ---- malformed names, everywhere a name can appear -------------------- */

ATF_TC_WITHOUT_HEAD(malformed_requires_names_rejected);
ATF_TC_BODY(malformed_requires_names_rejected, tc)
{
	size_t i;

	for (i = 0; i < nitems(bad_names); i++)
		check_requires_name_rejected(bad_names[i]);
}

ATF_TC_WITHOUT_HEAD(malformed_anointments_names_rejected);
ATF_TC_BODY(malformed_anointments_names_rejected, tc)
{
	size_t i;

	for (i = 0; i < nitems(bad_names); i++)
		check_anointment_name_rejected(bad_names[i]);
}

ATF_TC_WITHOUT_HEAD(malformed_endpoint_names_rejected);
ATF_TC_BODY(malformed_endpoint_names_rejected, tc)
{
	size_t i;

	for (i = 0; i < nitems(bad_names); i++)
		check_endpoint_name_rejected(bad_names[i]);
}

/*
 * libucl decodes "\u0000" into a NUL byte inside the string; the C-string
 * view stops there.  Pin what the parser does with it so a change is
 * noticed: the name is taken up to the NUL and everything after is dropped
 * -- "a.b\u0000.tail" is the name "a.b", validated and recorded as such.
 */
ATF_TC_WITHOUT_HEAD(nul_escape_in_name_documented);
ATF_TC_BODY(nul_escape_in_name_documented, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\\u0000.tail\"]; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);
	ATF_CHECK_STREQ("a.b", svc.requires[0][0]);
	PARSE_OK("activation { boot = true; }\n"
	    "holds = [\"c.d\\u0000junk\"];\n", &svc);
	ATF_CHECK_EQ(1U, svc.nanointments);
	ATF_CHECK_STREQ("c.d", svc.anointments[0]);
	PARSE_OK(ipc_unit("{ name = \"org.test.a\\u0000.tail\"; }"), &svc);
	ATF_CHECK_STREQ("org.test.a", svc.provides[0]);
	/* So two names differing only after the NUL are duplicates. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\\u0000x\", \"a.b\\u0000y\"]; }"), "duplicate");
	/* A NUL right at the front leaves an empty name: always rejected. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"\\u0000a.b\"]; }"), "requires");
	PARSE_FAILS(ipc_unit("{ name = \"\\u0000org.test.a\"; }"),
	    "activation.ipc");
	PARSE_FAILS("activation { boot = true; }\nholds = [\"\\u0000\"];\n",
	    "holds");
}

/* ---- wrong types ------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(requires_wrong_types_rejected);
ATF_TC_BODY(requires_wrong_types_rejected, tc)
{
	static const char *const bad[] = {
		"42", "[42]", "[{}]", "[null]", "null", "[true]", "false",
		"[1.5]", "1.5", "{}", "[{ name = \"a.b\" }]", "[[\"a.b\"]]",
		"[\"a.b\", null]", "[\"a.b\", {}]", "[\"a.b\", [\"c.d\"]]",
	};
	char list[512];
	size_t i;

	for (i = 0; i < nitems(bad); i++) {
		snprintf(list, sizeof(list), "{ name = \"org.test.a\"; "
		    "requires = %s; }", bad[i]);
		PARSE_FAILS(ipc_unit(list), "requires");
	}
}

ATF_TC_WITHOUT_HEAD(anointments_wrong_types_rejected);
ATF_TC_BODY(anointments_wrong_types_rejected, tc)
{
	static const char *const bad[] = {
		"true", "[[]]", "[null]", "null", "[{}]", "{}", "1.5", "[1.5]",
		"[[\"a.b\"]]", "[\"a.b\", null]", "[\"a.b\", true]",
		"[\"a.b\", [\"c.d\"]]", "[\"a.b\", { x = 1 }]",
	};
	char body[512];
	size_t i;

	for (i = 0; i < nitems(bad); i++) {
		snprintf(body, sizeof(body), "activation { boot = true; }\n"
		    "holds = %s;\n", bad[i]);
		PARSE_FAILS(body, "holds");
	}
}

ATF_TC_WITHOUT_HEAD(object_entry_shape_rejected);
ATF_TC_BODY(object_entry_shape_rejected, tc)
{

	/* name of the wrong type. */
	PARSE_FAILS(ipc_unit("{ name = 42; requires = [\"a.b\"]; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = null; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = true; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = 1.5; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = {}; }"), "name");
	PARSE_FAILS(ipc_unit("{ name = []; }"), "name");
	/* name missing, with and without other keys. */
	PARSE_FAILS(ipc_unit("{ requires = [\"a.b\"]; }"), "name");
	PARSE_FAILS(ipc_unit("{ requires = []; }"), "name");
	PARSE_FAILS(ipc_unit("{}"), "name");
	PARSE_FAILS(ipc_unit("\"org.test.ok\", {}"), "name");
	/* Unknown keys, including near-misses and case variants. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; foo = 1; }"),
	    "unknown key");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; Requires = [\"a.b\"]; }"),
	    "unknown key");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; Name = \"x.y\"; }"),
	    "unknown key");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; anointments = [\"a.b\"]; }"),
	    "unknown key");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; resolvable_by = [\"user\"]; }"),
	    "unknown key");
	/*
	 * A repeated key: the unit parser runs with explicit arrays, so two
	 * `name` keys become an array and are refused as a non-string name,
	 * and two `requires` keys become an array of arrays.
	 */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; name = \"org.test.b\"; }"),
	    "name");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\"]; requires = [\"c.d\"]; }"), "requires");
}

ATF_TC_WITHOUT_HEAD(requires_scalar_string_equals_one_element_list);
ATF_TC_BODY(requires_scalar_string_equals_one_element_list, tc)
{
	struct capbundle_service a, b;
	struct svc_manifest ma, mb;

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; requires = \"single.name\"; }"),
	    &a);
	PARSE_OK(ipc_unit("{ name = \"org.test.a\"; requires = [\"single.name\"]; }"),
	    &b);
	ATF_CHECK_EQ(1U, a.nrequires[0]);
	ATF_CHECK_STREQ("single.name", a.requires[0][0]);
	ATF_CHECK_EQ(0, memcmp(a.requires, b.requires, sizeof(a.requires)));
	ATF_CHECK_EQ(0, memcmp(a.nrequires, b.nrequires, sizeof(a.nrequires)));
	ATF_CHECK_EQ(0, memcmp(a.provides, b.provides, sizeof(a.provides)));
	memset(&ma, 0, sizeof(ma));
	memset(&mb, 0, sizeof(mb));
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&a, &ma));
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&b, &mb));
	ATF_CHECK_EQ(0, memcmp(ma.requires, mb.requires, sizeof(ma.requires)));
	ATF_CHECK_EQ(0, memcmp(ma.nrequires, mb.nrequires,
	    sizeof(ma.nrequires)));

	/* The same for anointments. */
	PARSE_OK("activation { boot = true; }\nholds = \"single.name\";\n",
	    &a);
	PARSE_OK("activation { boot = true; }\nholds = [\"single.name\"];\n",
	    &b);
	ATF_CHECK_EQ(1U, a.nanointments);
	ATF_CHECK_EQ(0, memcmp(a.anointments, b.anointments,
	    sizeof(a.anointments)));
}

/* ---- mixed lists ------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(mixed_forms_interleaved_full_list);
ATF_TC_BODY(mixed_forms_interleaved_full_list, tc)
{
	struct capbundle_service svc;
	char list[4096] = "";
	unsigned i;

	/* Even entries are bare strings, odd ones are gated by two names. */
	for (i = 0; i < CAPBUNDLE_MAX_PROVIDES; i++) {
		char one[256];

		if (i % 2 == 0)
			snprintf(one, sizeof(one), "%s\"org.test.n%u\"",
			    i ? ", " : "", i);
		else
			snprintf(one, sizeof(one), "%s{ name = \"org.test.n%u\"; "
			    "requires = [\"g.k%u\", \"g.k%u\"]; }",
			    i ? ", " : "", i, i, i + 100);
		strlcat(list, one, sizeof(list));
	}
	PARSE_OK(ipc_unit(list), &svc);
	ATF_CHECK_EQ((unsigned)CAPBUNDLE_MAX_PROVIDES, svc.nprovides);
	for (i = 0; i < CAPBUNDLE_MAX_PROVIDES; i++) {
		char want[64];

		snprintf(want, sizeof(want), "org.test.n%u", i);
		ATF_CHECK_STREQ(want, svc.provides[i]);
		ATF_CHECK_EQ((int)i, capbundle_svc_provides_index(&svc, want));
		if (i % 2 == 0) {
			ATF_CHECK_EQ(0U, svc.nrequires[i]);
			ATF_CHECK(capbundle_svc_requires(&svc, i, 0) == NULL);
		} else {
			ATF_CHECK_EQ(2U, svc.nrequires[i]);
			snprintf(want, sizeof(want), "g.k%u", i);
			ATF_CHECK_STREQ(want, svc.requires[i][0]);
			snprintf(want, sizeof(want), "g.k%u", i + 100);
			ATF_CHECK_STREQ(want, svc.requires[i][1]);
		}
	}
}

ATF_TC_WITHOUT_HEAD(duplicate_endpoint_far_apart_rejected);
ATF_TC_BODY(duplicate_endpoint_far_apart_rejected, tc)
{
	char list[4096] = "";
	unsigned i;

	/* First and last entries of a full list collide, across forms. */
	for (i = 0; i < CAPBUNDLE_MAX_PROVIDES; i++) {
		char one[256];

		if (i == 0)
			snprintf(one, sizeof(one), "\"org.test.dup\"");
		else if (i == CAPBUNDLE_MAX_PROVIDES - 1)
			snprintf(one, sizeof(one), ", { name = \"org.test.dup\"; "
			    "requires = [\"a.b\"]; }");
		else
			snprintf(one, sizeof(one), ", \"org.test.n%u\"", i);
		strlcat(list, one, sizeof(list));
	}
	PARSE_FAILS(ipc_unit(list), "duplicate");
	/* Two gated objects with different requires are still the same name. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"x.y\"]; }, "
	    "\"org.test.b\", "
	    "{ name = \"org.test.a\"; requires = [\"z.w\"]; }"), "duplicate");
}

ATF_TC_WITHOUT_HEAD(requires_same_name_twice_in_entry_rejected);
ATF_TC_BODY(requires_same_name_twice_in_entry_rejected, tc)
{

	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\", \"a.b\"]; }"), "duplicate");
	/* Far apart in a full list. */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b\", "
	    "\"a.c\", \"a.d\", \"a.e\", \"a.f\", \"a.g\", \"a.h\", \"a.b\"]; }"),
	    "duplicate");
	/* Through a repeated key (explicit-array conversion). */
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = \"a.b\"; requires = \"a.b\"; }"), "duplicate");
	/* The same name on two different endpoints is fine. */
	{
		struct capbundle_service svc;

		PARSE_OK(ipc_unit("{ name = \"org.test.a\"; requires = [\"a.b\"]; }, "
		    "{ name = \"org.test.b\"; requires = [\"a.b\"]; }"), &svc);
		ATF_CHECK_STREQ("a.b", svc.requires[0][0]);
		ATF_CHECK_STREQ("a.b", svc.requires[1][0]);
	}
}

/*
 * Nothing forbids an endpoint from requiring its own name, or a sibling
 * endpoint's name: endpoint names and anointment names are separate
 * namespaces that merely share a syntax.  Document that it parses.
 */
ATF_TC_WITHOUT_HEAD(endpoint_may_require_its_own_name_documented);
ATF_TC_BODY(endpoint_may_require_its_own_name_documented, tc)
{
	struct capbundle_service svc;

	PARSE_OK(ipc_unit("{ name = \"system.notify\"; "
	    "requires = [\"system.notify\"]; }"), &svc);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_EQ(1U, svc.nrequires[0]);
	ATF_CHECK_STREQ("system.notify", svc.requires[0][0]);

	PARSE_OK(ipc_unit("\"system.notify\", { name = \"system.notify.Gate\"; "
	    "requires = [\"system.notify\"]; }"), &svc);
	ATF_CHECK_EQ(2U, svc.nprovides);
	ATF_CHECK_STREQ("system.notify", svc.requires[1][0]);

	/* Declaring the name one gates on is also legal (self-reach). */
	PARSE_OK("activation { ipc = [{ name = \"org.test.a\"; "
	    "requires = [\"k.self\"]; }]; }\nholds = [\"k.self\"];\n",
	    &svc);
	ATF_CHECK_STREQ("k.self", svc.requires[0][0]);
	ATF_CHECK_STREQ("k.self", svc.anointments[0]);
}

/* ---- helpers ------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(helper_unit_with_anointments);
ATF_TC_BODY(helper_unit_with_anointments, tc)
{
	struct capbundle_service svc;

	/* A helper may hold names; it just publishes no gated endpoint. */
	memset(&svc, 0xa5, sizeof(svc));
	PARSE_OK("activation { helper = true; }\n"
	    "holds = [\"a.b\", \"c.d\"];\n", &svc);
	ATF_CHECK(svc.is_helper);
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK_STREQ("helper.org.test.anoint.worker", svc.provides[0]);
	ATF_CHECK_EQ(0U, svc.nrequires[0]);
	ATF_CHECK_EQ(0U, capbundle_svc_nrequires(&svc, 0));
	ATF_CHECK_EQ(2U, svc.nanointments);
	ATF_CHECK_STREQ("a.b", svc.anointments[0]);
	ATF_CHECK_STREQ("c.d", svc.anointments[1]);
	/* The wildcard and bad names are refused for helpers too. */
	PARSE_FAILS("activation { helper = true; }\nholds = [\"*\"];\n",
	    "*");
	PARSE_FAILS("activation { helper = true; }\nholds = [\"nodot\"];\n",
	    "holds");
}

/* ---- svc_manifest conversion at the limits ------------------------------ */

ATF_TC_WITHOUT_HEAD(fill_manifest_max_counts_round_trip);
ATF_TC_BODY(fill_manifest_max_counts_round_trip, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;
	char body[16384], name[128], tag[16];
	unsigned i, j;

	/* 8 endpoints x 8 requires + 32 anointments, all names 63 bytes. */
	snprintf(body, sizeof(body), "activation { ipc = [");
	for (i = 0; i < CAPBUNDLE_MAX_PROVIDES; i++) {
		char one[256];

		snprintf(one, sizeof(one), "%s{ name = \"org.test.n%u\"; "
		    "requires = [", i ? ", " : "", i);
		strlcat(body, one, sizeof(body));
		for (j = 0; j < CAPBUNDLE_MAX_REQUIRES; j++) {
			snprintf(tag, sizeof(tag), "r%u-%u", i, j);
			tagged_name(name, sizeof(name), tag,
			    SWITCHBOARD_LABEL_MAX - 1);
			snprintf(one, sizeof(one), "%s\"%s\"", j ? ", " : "",
			    name);
			strlcat(body, one, sizeof(body));
		}
		strlcat(body, "]; }", sizeof(body));
	}
	strlcat(body, "]; }\nholds = [", sizeof(body));
	for (i = 0; i < CAPBUNDLE_MAX_ANOINTMENTS; i++) {
		char one[128];

		snprintf(tag, sizeof(tag), "a%u", i);
		tagged_name(name, sizeof(name), tag, SWITCHBOARD_LABEL_MAX - 1);
		snprintf(one, sizeof(one), "%s\"%s\"", i ? ", " : "", name);
		strlcat(body, one, sizeof(body));
	}
	strlcat(body, "];\n", sizeof(body));
	ATF_REQUIRE(strlen(body) < sizeof(body) - 1);
	PARSE_OK(body, &svc);
	ATF_REQUIRE_EQ((unsigned)CAPBUNDLE_MAX_PROVIDES, svc.nprovides);
	ATF_REQUIRE_EQ((unsigned)CAPBUNDLE_MAX_ANOINTMENTS, svc.nanointments);

	memset(&m, 0xa5, sizeof(m));
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ((unsigned)SWITCHBOARD_MAX_PROVIDES, m.nprovides);
	for (i = 0; i < SWITCHBOARD_MAX_PROVIDES; i++) {
		ATF_CHECK_STREQ(svc.provides[i], m.provides[i]);
		ATF_CHECK_EQ((unsigned)SWITCHBOARD_MAX_REQUIRES, m.nrequires[i]);
		for (j = 0; j < SWITCHBOARD_MAX_REQUIRES; j++) {
			snprintf(tag, sizeof(tag), "r%u-%u", i, j);
			tagged_name(name, sizeof(name), tag,
			    SWITCHBOARD_LABEL_MAX - 1);
			ATF_CHECK_STREQ(name, svc.requires[i][j]);
			ATF_CHECK_STREQ(name, m.requires[i][j]);
			ATF_CHECK_EQ((size_t)SWITCHBOARD_LABEL_MAX - 1,
			    strlen(m.requires[i][j]));
		}
	}
	ATF_CHECK_EQ((unsigned)SWITCHBOARD_MAX_ANOINTMENTS, m.nanointments);
	for (i = 0; i < SWITCHBOARD_MAX_ANOINTMENTS; i++) {
		snprintf(tag, sizeof(tag), "a%u", i);
		tagged_name(name, sizeof(name), tag, SWITCHBOARD_LABEL_MAX - 1);
		ATF_CHECK_STREQ(name, svc.anointments[i]);
		ATF_CHECK_STREQ(name, m.anointments[i]);
	}
	/* Byte-exact: the manifest arrays equal the service arrays. */
	ATF_CHECK_EQ(0, memcmp(svc.requires, m.requires, sizeof(m.requires)));
	ATF_CHECK_EQ(0, memcmp(svc.anointments, m.anointments,
	    sizeof(m.anointments)));
	ATF_CHECK_EQ(0, memcmp(svc.nrequires, m.nrequires, sizeof(m.nrequires)));
}

/* ---- capbundle_verify on an in-memory bundle -------------------------- */

/*
 * A minimal on-disk shape (a directory holding an executable) and an
 * in-memory bundle that verifies cleanly, so each corruption below is the
 * only thing wrong.
 */
static struct capbundle *
make_verifiable_bundle(void)
{
	struct capbundle *b;
	struct capbundle_service *s;
	char cwd[PATH_MAX];
	FILE *f;

	ATF_REQUIRE_EQ(0, mkdir("v.cap", 0755));
	ATF_REQUIRE_EQ(0, mkdir("v.cap/bin", 0755));
	f = fopen("v.cap/bin/prog", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs("#!/bin/sh\nexit 0\n", f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE_EQ(0, chmod("v.cap/bin/prog", 0755));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);

	b = calloc(1, sizeof(*b));
	ATF_REQUIRE(b != NULL);
	snprintf(b->path, sizeof(b->path), "%s/v.cap", cwd);
	strlcpy(b->name, "v.cap", sizeof(b->name));
	strlcpy(b->bundle_id, "org.test.verify", sizeof(b->bundle_id));
	strlcpy(b->version, "1.0", sizeof(b->version));
	b->sequence = 1;
	b->nservices = 1;
	s = &b->services[0];
	snprintf(s->program, sizeof(s->program), "%s/v.cap/bin/prog", cwd);
	strlcpy(s->label, "org.test.verify/worker", sizeof(s->label));
	strlcpy(s->provides[0], "org.test.Verify", sizeof(s->provides[0]));
	s->nprovides = 1;
	strlcpy(s->requires[0][0], "k.one", sizeof(s->requires[0][0]));
	s->nrequires[0] = 1;
	strlcpy(s->anointments[0], "h.one", sizeof(s->anointments[0]));
	s->nanointments = 1;
	s->activation_boot = true;
	s->management = SVC_MGMT_SYSTEM;
	return (b);
}

ATF_TC_WITHOUT_HEAD(verify_rejects_overflowed_in_memory_counts);
ATF_TC_BODY(verify_rejects_overflowed_in_memory_counts, tc)
{
	struct capbundle *b;
	struct capbundle_service *s;
	char err[512];

	b = make_verifiable_bundle();
	s = &b->services[0];
	err[0] = '\0';
	ATF_REQUIRE_EQ_MSG(0, capbundle_verify(b, err, sizeof(err)),
	    "baseline does not verify: %s", err);

	/* nrequires over the cap on the only endpoint. */
	s->nrequires[0] = CAPBUNDLE_MAX_REQUIRES + 1;
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "too many requires") != NULL, "err: %s", err);
	s->nrequires[0] = UINT_MAX;
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	s->nrequires[0] = CAPBUNDLE_MAX_REQUIRES;	/* exactly max: fine */
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));
	s->nrequires[0] = 1;

	/* nanointments over the cap. */
	s->nanointments = CAPBUNDLE_MAX_ANOINTMENTS + 1;
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "too many anointments") != NULL, "err: %s",
	    err);
	s->nanointments = UINT_MAX;
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	s->nanointments = CAPBUNDLE_MAX_ANOINTMENTS;
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));
	s->nanointments = 1;

	/* An overflow on a second, otherwise clean endpoint is caught too. */
	strlcpy(s->provides[1], "org.test.Second", sizeof(s->provides[1]));
	s->nprovides = 2;
	s->nrequires[1] = CAPBUNDLE_MAX_REQUIRES + 1;
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "org.test.Second") != NULL, "err: %s", err);
	s->nrequires[1] = 0;
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));

	/* A NULL errbuf must not crash on the failure path. */
	s->nanointments = CAPBUNDLE_MAX_ANOINTMENTS + 1;
	ATF_CHECK_EQ(-1, capbundle_verify(b, NULL, 0));
	free(b);
}

ATF_TC_WITHOUT_HEAD(verify_rejects_unterminated_in_memory_names);
ATF_TC_BODY(verify_rejects_unterminated_in_memory_names, tc)
{
	struct capbundle *b;
	struct capbundle_service *s;
	char err[512];

	b = make_verifiable_bundle();
	s = &b->services[0];
	ATF_REQUIRE_EQ(0, capbundle_verify(b, err, sizeof(err)));

	/* A requires slot filled to the brim (no NUL inside 64 bytes). */
	memset(s->requires[0][0], 'x', sizeof(s->requires[0][0]));
	memset(s->requires[0][1], 0, sizeof(s->requires[0][1]));
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "requires name too long") != NULL, "err: %s",
	    err);
	memset(s->requires[0][0], 0, sizeof(s->requires[0][0]));
	strlcpy(s->requires[0][0], "k.one", sizeof(s->requires[0][0]));
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));

	/* The same for an anointment slot. */
	memset(s->anointments[0], 'y', sizeof(s->anointments[0]));
	memset(s->anointments[1], 0, sizeof(s->anointments[1]));
	err[0] = '\0';
	ATF_CHECK_EQ(-1, capbundle_verify(b, err, sizeof(err)));
	ATF_CHECK_MSG(strstr(err, "anointment name too long") != NULL,
	    "err: %s", err);
	memset(s->anointments[0], 0, sizeof(s->anointments[0]));
	strlcpy(s->anointments[0], "h.one", sizeof(s->anointments[0]));
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));

	/* Exactly 63 bytes is the longest a slot may hold. */
	memset(s->anointments[0], 'z', SWITCHBOARD_LABEL_MAX - 1);
	s->anointments[0][SWITCHBOARD_LABEL_MAX - 1] = '\0';
	ATF_CHECK_EQ(0, capbundle_verify(b, err, sizeof(err)));
	free(b);
}

/*
 * The unit parser runs libucl with UCL_PARSER_NO_IMPLICIT_ARRAYS, under
 * which a key given twice in one object is a parse error rather than a
 * silently merged or silently dropped value.  Pin that for every key the
 * anointment feature adds, in both scalar and array forms.
 */
ATF_TC_WITHOUT_HEAD(repeated_keys_are_parse_errors);
ATF_TC_BODY(repeated_keys_are_parse_errors, tc)
{

	PARSE_FAILS("activation { boot = true; }\n"
	    "holds = \"a.b\";\nholds = \"c.d\";\n",
	    "duplicate element");
	PARSE_FAILS("activation { boot = true; }\n"
	    "holds = [\"a.b\"];\nholds = [\"c.d\"];\n",
	    "duplicate element");
	PARSE_FAILS("activation { boot = true; }\n"
	    "holds = \"a.b\";\nholds = \"a.b\";\n",
	    "duplicate element");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = \"a.b\"; requires = \"c.d\"; }"), "duplicate element");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; "
	    "requires = [\"a.b\"]; requires = [\"c.d\"]; }"), "duplicate element");
	PARSE_FAILS(ipc_unit("{ name = \"org.test.a\"; name = \"org.test.b\"; }"),
	    "duplicate element");
	PARSE_FAILS("activation { ipc = [\"org.test.a\"]; ipc = [\"org.test.b\"]; }\n",
	    "duplicate element");
	PARSE_FAILS("activation { boot = true; }\nactivation { boot = true; }\n",
	    "duplicate element");
}

/*
 * Names that look odd but satisfy the rule -- [A-Za-z0-9._-], at least one
 * dot, no leading, trailing or doubled dot -- are accepted everywhere.
 * Pinned so a future tightening of the charset is a deliberate change.
 */
ATF_TC_WITHOUT_HEAD(odd_but_valid_names_accepted);
ATF_TC_BODY(odd_but_valid_names_accepted, tc)
{
	static const char *const odd[] = {
		"-.-", "_._", "0.0", "a.b", "A.B", "-a.b-", "a-.-b", "a_.b_",
		"1.2.3.4", "a.b.c.d.e.f.g.h.i.j", "UPPER.lower.MiXeD-1_2",
	};
	struct capbundle_service svc;
	char body[512], list[512];
	size_t i;

	for (i = 0; i < nitems(odd); i++) {
		snprintf(list, sizeof(list), "{ name = \"%s\"; "
		    "requires = [\"%s\"]; }", odd[i], odd[i]);
		PARSE_OK(ipc_unit(list), &svc);
		ATF_CHECK_STREQ(odd[i], svc.provides[0]);
		ATF_CHECK_STREQ(odd[i], svc.requires[0][0]);
		snprintf(body, sizeof(body), "activation { boot = true; }\n"
		    "holds = [\"%s\"];\n", odd[i]);
		PARSE_OK(body, &svc);
		ATF_CHECK_STREQ(odd[i], svc.anointments[0]);
	}
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
	ATF_TP_ADD_TC(tp, endpoint_name_length_boundary);
	ATF_TP_ADD_TC(tp, requires_name_length_boundary);
	ATF_TP_ADD_TC(tp, anointments_name_length_boundary);
	ATF_TP_ADD_TC(tp, requires_count_boundary);
	ATF_TP_ADD_TC(tp, anointments_count_boundary);
	ATF_TP_ADD_TC(tp, names_are_case_sensitive);
	ATF_TP_ADD_TC(tp, malformed_requires_names_rejected);
	ATF_TP_ADD_TC(tp, malformed_anointments_names_rejected);
	ATF_TP_ADD_TC(tp, malformed_endpoint_names_rejected);
	ATF_TP_ADD_TC(tp, nul_escape_in_name_documented);
	ATF_TP_ADD_TC(tp, requires_wrong_types_rejected);
	ATF_TP_ADD_TC(tp, anointments_wrong_types_rejected);
	ATF_TP_ADD_TC(tp, object_entry_shape_rejected);
	ATF_TP_ADD_TC(tp, requires_scalar_string_equals_one_element_list);
	ATF_TP_ADD_TC(tp, mixed_forms_interleaved_full_list);
	ATF_TP_ADD_TC(tp, duplicate_endpoint_far_apart_rejected);
	ATF_TP_ADD_TC(tp, requires_same_name_twice_in_entry_rejected);
	ATF_TP_ADD_TC(tp, endpoint_may_require_its_own_name_documented);
	ATF_TP_ADD_TC(tp, helper_unit_with_anointments);
	ATF_TP_ADD_TC(tp, fill_manifest_max_counts_round_trip);
	ATF_TP_ADD_TC(tp, verify_rejects_overflowed_in_memory_counts);
	ATF_TP_ADD_TC(tp, verify_rejects_unterminated_in_memory_names);
	ATF_TP_ADD_TC(tp, repeated_keys_are_parse_errors);
	ATF_TP_ADD_TC(tp, odd_but_valid_names_accepted);
	return (atf_no_error());
}

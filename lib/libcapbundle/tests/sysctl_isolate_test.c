/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Manifest parsing coverage for the per-OID sysctl isolation set
 * (docs/book/src/capability/system-gates.md, Phase 2): capabilities.isolate.
 * Exercises capbundle_parse_unit_ucl() and capbundle_svc_fill_manifest() at
 * their boundaries — no daemon or capability kernel required.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <dev/mac_capability/mac_capability_system_proto.h>

#include "libcapbundle_internal.h"

/* Write a Unit.ucl body to the test cwd and parse it. */
static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.sysctl", sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

/* --- Happy path --- */

ATF_TC_WITHOUT_HEAD(isolate_absent_is_empty);
ATF_TC_BODY(isolate_absent_is_empty, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(0u, svc.n_sysctl_isolate);
	ATF_CHECK_EQ(0u, svc.cap_system);
}

ATF_TC_WITHOUT_HEAD(isolate_parses_with_sysctl_gate);
ATF_TC_BODY(isolate_parses_with_sysctl_gate, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; "
	    "isolate = [\"kern.maxfiles\", \"vm.overcommit\"]; }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK((svc.cap_system & SYS_GATE_SYSCTL) != 0);
	ATF_REQUIRE_EQ(2u, svc.n_sysctl_isolate);
	ATF_CHECK_STREQ("kern.maxfiles", svc.sysctl_isolate[0]);
	ATF_CHECK_STREQ("vm.overcommit", svc.sysctl_isolate[1]);
}

/* fill_manifest carries the list verbatim into the wire manifest. */
ATF_TC_WITHOUT_HEAD(isolate_fill_manifest_roundtrip);
ATF_TC_BODY(isolate_fill_manifest_roundtrip, tc)
{
	struct capbundle_service svc;
	struct svc_manifest m;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; "
	    "isolate = [\"kern.maxfiles\"]; }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK((m.cap_system & SYS_GATE_SYSCTL) != 0);
	ATF_REQUIRE_EQ(1u, m.n_sysctl_isolate);
	ATF_CHECK_STREQ("kern.maxfiles", m.sysctl_isolate[0]);

	/* A unit with no isolate list must survive fill_manifest's memset. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(0, capbundle_svc_fill_manifest(&svc, &m));
	ATF_CHECK_EQ(0u, m.n_sysctl_isolate);
}

/* --- Fail-closed validation --- */

ATF_TC_WITHOUT_HEAD(isolate_requires_sysctl_gate);
ATF_TC_BODY(isolate_requires_sysctl_gate, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* isolate without the "sysctl" gate is rejected. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { isolate = [\"kern.maxfiles\"]; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(err[0] != '\0');
}

ATF_TC_WITHOUT_HEAD(isolate_empty_entry_rejected);
ATF_TC_BODY(isolate_empty_entry_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; isolate = [\"\"]; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(err[0] != '\0');
}

ATF_TC_WITHOUT_HEAD(isolate_non_string_rejected);
ATF_TC_BODY(isolate_non_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; isolate = [42]; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(err[0] != '\0');
}

ATF_TC_WITHOUT_HEAD(isolate_too_long_name_rejected);
ATF_TC_BODY(isolate_too_long_name_rejected, tc)
{
	struct capbundle_service svc;
	char body[SWITCHBOARD_SYSCTL_NAME_MAX + 256];
	char longname[SWITCHBOARD_SYSCTL_NAME_MAX + 8];
	char err[256];

	memset(longname, 'a', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	snprintf(body, sizeof(body),
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; isolate = [\"%s\"]; }\n",
	    longname);
	ATF_CHECK_EQ(-1, parse_unit(body, &svc, err, sizeof(err)));
	ATF_CHECK(err[0] != '\0');
}

ATF_TC_WITHOUT_HEAD(isolate_unknown_cap_key_rejected);
ATF_TC_BODY(isolate_unknown_cap_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A stray capabilities key must still be rejected (allow-list). */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { system = [\"sysctl\"]; bogus = [\"x\"]; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(err[0] != '\0');
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, isolate_absent_is_empty);
	ATF_TP_ADD_TC(tp, isolate_parses_with_sysctl_gate);
	ATF_TP_ADD_TC(tp, isolate_fill_manifest_roundtrip);
	ATF_TP_ADD_TC(tp, isolate_requires_sysctl_gate);
	ATF_TP_ADD_TC(tp, isolate_empty_entry_rejected);
	ATF_TP_ADD_TC(tp, isolate_non_string_rejected);
	ATF_TP_ADD_TC(tp, isolate_too_long_name_rejected);
	ATF_TP_ADD_TC(tp, isolate_unknown_cap_key_rejected);

	return (atf_no_error());
}

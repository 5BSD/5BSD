/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Manifest parsing for the launchd-style pre-exec policy vocabulary:
 * limits{} (setrlimit ceilings), umask, band (scheduling class), and the
 * calendar / queue_directory / on_mount activation sources, plus the relaxed
 * (optional-path) execution jail.  Exercises capbundle_parse_unit_ucl()
 * directly at the parser boundary — no daemon or capability kernel required.
 */

#include <sys/stat.h>
#include <sys/socket.h>

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
	strlcpy(bundle.bundle_id, "org.test.policy", sizeof(bundle.bundle_id));

	f = fopen("Unit.ucl", "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(body, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));

	if (errbuf != NULL && errlen > 0)
		errbuf[0] = '\0';
	return (capbundle_parse_unit_ucl("Unit.ucl", ".", &bundle, "worker",
	    svc, errbuf, errlen));
}

/* ---- limits{} --------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(limits_defaults_when_absent);
ATF_TC_BODY(limits_defaults_when_absent, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	/* Unspecified rlimits inherit; core defaults to 0 (no dumps). */
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.mem);
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.cpu);
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.nproc);
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.nofile);
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.stack);
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.fsize);
	ATF_CHECK_EQ(0, svc.limits.core);
	/* And the other policy defaults. */
	ATF_CHECK_EQ(-1, svc.umask_val);
	ATF_CHECK_EQ(SVC_BAND_STANDARD, svc.band);
}

ATF_TC_WITHOUT_HEAD(limits_integers_parse);
ATF_TC_BODY(limits_integers_parse, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "limits { cpu = 30; nproc = 64; nofile = 1024; core = 0; }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(30, svc.limits.cpu);
	ATF_CHECK_EQ(64, svc.limits.nproc);
	ATF_CHECK_EQ(1024, svc.limits.nofile);
	ATF_CHECK_EQ(0, svc.limits.core);
	/* Untouched fields still inherit. */
	ATF_CHECK_EQ(SVC_LIMIT_UNSET, svc.limits.mem);
}

ATF_TC_WITHOUT_HEAD(limits_size_suffixes_parse);
ATF_TC_BODY(limits_size_suffixes_parse, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "limits { memory = \"512M\"; stack = \"8M\"; fsize = \"2G\"; }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ((int64_t)512 * 1024 * 1024, svc.limits.mem);
	ATF_CHECK_EQ((int64_t)8 * 1024 * 1024, svc.limits.stack);
	ATF_CHECK_EQ((int64_t)2 * 1024 * 1024 * 1024, svc.limits.fsize);
}

ATF_TC_WITHOUT_HEAD(limits_negative_rejected);
ATF_TC_BODY(limits_negative_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nlimits { nproc = -5; }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "nproc") != NULL);
}

ATF_TC_WITHOUT_HEAD(limits_bad_suffix_rejected);
ATF_TC_BODY(limits_bad_suffix_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nlimits { memory = \"512Q\"; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "memory") != NULL);
}

ATF_TC_WITHOUT_HEAD(limits_unknown_key_rejected);
ATF_TC_BODY(limits_unknown_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nlimits { bogus = 1; }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(limits_size_overflow_rejected);
ATF_TC_BODY(limits_size_overflow_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* 1e12 * 1024^4 overflows int64_t — must be rejected, not wrapped. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nlimits { memory = \"999999999999T\"; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "overflow") != NULL);
}

/* ---- umask ------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(umask_octal_string_parses);
ATF_TC_BODY(umask_octal_string_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\numask = \"0077\";\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(0077, svc.umask_val);
}

ATF_TC_WITHOUT_HEAD(umask_out_of_range_rejected);
ATF_TC_BODY(umask_out_of_range_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\numask = \"1000\";\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "umask") != NULL);
}

ATF_TC_WITHOUT_HEAD(umask_bad_octal_rejected);
ATF_TC_BODY(umask_bad_octal_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\numask = \"09\";\n", &svc, err,
	    sizeof(err)));
}

/* ---- band ------------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(band_names_parse);
ATF_TC_BODY(band_names_parse, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nband = \"background\";\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_BAND_BACKGROUND, svc.band);

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\nband = \"interactive\";\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(SVC_BAND_INTERACTIVE, svc.band);
}

ATF_TC_WITHOUT_HEAD(band_unknown_rejected);
ATF_TC_BODY(band_unknown_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\nband = \"turbo\";\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "band") != NULL);
}

/* ---- activation.schedule (calendar) ----------------------------------- */

ATF_TC_WITHOUT_HEAD(schedule_cron_parses);
ATF_TC_BODY(schedule_cron_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { schedule = \"30 3 * * *\"; }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK(svc.has_calendar);
	ATF_CHECK_EQ(30, svc.calendar.minute);
	ATF_CHECK_EQ(3, svc.calendar.hour);
	ATF_CHECK_EQ(SVC_CAL_ANY, svc.calendar.mday);
	ATF_CHECK_EQ(SVC_CAL_ANY, svc.calendar.month);
	ATF_CHECK_EQ(SVC_CAL_ANY, svc.calendar.wday);
	ATF_CHECK(!svc.calendar_persistent);
}

ATF_TC_WITHOUT_HEAD(schedule_aliases_parse);
ATF_TC_BODY(schedule_aliases_parse, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { schedule = \"daily\"; persistent = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK(svc.has_calendar);
	ATF_CHECK_EQ(0, svc.calendar.minute);
	ATF_CHECK_EQ(0, svc.calendar.hour);
	ATF_CHECK_EQ(SVC_CAL_ANY, svc.calendar.mday);
	ATF_CHECK(svc.calendar_persistent);

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { schedule = \"weekly\"; }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK_EQ(0, svc.calendar.wday);

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { schedule = \"monthly\"; }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK_EQ(1, svc.calendar.mday);
}

ATF_TC_WITHOUT_HEAD(schedule_out_of_range_rejected);
ATF_TC_BODY(schedule_out_of_range_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* hour 25 is out of range. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { schedule = \"0 25 * * *\"; }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "schedule") != NULL);
}

ATF_TC_WITHOUT_HEAD(schedule_wrong_field_count_rejected);
ATF_TC_BODY(schedule_wrong_field_count_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { schedule = \"0 3 *\"; }\n", &svc, err, sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(persistent_without_schedule_rejected);
ATF_TC_BODY(persistent_without_schedule_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; persistent = true; }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "persistent") != NULL);
}

ATF_TC_WITHOUT_HEAD(timer_and_schedule_mutually_exclusive);
ATF_TC_BODY(timer_and_schedule_mutually_exclusive, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* One timer slot: a monotonic interval and a calendar can't coexist. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { interval = 60; }; schedule = \"daily\"; }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "mutually exclusive") != NULL);
}

/* ---- activation.queue_directory / on_mount ---------------------------- */

ATF_TC_WITHOUT_HEAD(queue_directory_absolute_parses);
ATF_TC_BODY(queue_directory_absolute_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { queue_directory = \"/var/spool/out\"; }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_STREQ("/var/spool/out", svc.queue_directory);
}

ATF_TC_WITHOUT_HEAD(queue_directory_relative_rejected);
ATF_TC_BODY(queue_directory_relative_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { queue_directory = \"spool/out\"; }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "queue_directory") != NULL);
}

ATF_TC_WITHOUT_HEAD(on_mount_parses);
ATF_TC_BODY(on_mount_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { on_mount = true; }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK(svc.activation_on_mount);
}

/* ---- execution jail: path is now optional ----------------------------- */

ATF_TC_WITHOUT_HEAD(jail_without_path_parses);
ATF_TC_BODY(jail_without_path_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* path omitted: serviced roots the jail at the managed container. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "jail { name = \"log\"; hostname = \"log\"; }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK(svc.has_jail);
	ATF_CHECK_EQ('\0', svc.jail_path[0]);
	ATF_CHECK_STREQ("log", svc.jail_hostname);
}

ATF_TC_WITHOUT_HEAD(jail_relative_path_rejected);
ATF_TC_BODY(jail_relative_path_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A path, when given, must still be absolute. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "jail { name = \"log\"; path = \"relative/root\"; }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "path") != NULL);
}

/* ---- private helper units --------------------------------------------- */

ATF_TC_WITHOUT_HEAD(helper_unit_parses);
ATF_TC_BODY(helper_unit_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* helper=true is a complete activation: no boot/ipc/timer needed. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { helper = true; }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK(svc.is_helper);
	ATF_CHECK(!svc.activation_boot);
	/*
	 * A helper publishes no ipc name, but the parser injects a synthetic
	 * bundle-local provider name ("helper.<bundle-id>.<unit>") into
	 * provides[] so the on-demand registry can resolve service_helper_open().
	 */
	ATF_CHECK_EQ(1U, svc.nprovides);
	ATF_CHECK(strncmp(svc.provides[0], "helper.", 7) == 0);
}

ATF_TC_WITHOUT_HEAD(helper_with_ipc_rejected);
ATF_TC_BODY(helper_with_ipc_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A private helper must not publish a system.* name. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { helper = true; ipc = [\"system.Thing\"]; }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "helper") != NULL);
}

ATF_TC_WITHOUT_HEAD(non_helper_defaults_false);
ATF_TC_BODY(non_helper_defaults_false, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit("activation { boot = true; }\n", &svc,
	    err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK(!svc.is_helper);
}

/* ---- capabilities.open (serviced-delivered file/dir descriptors) ------ */

ATF_TC_WITHOUT_HEAD(open_file_and_dir_parse);
ATF_TC_BODY(open_file_and_dir_parse, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities {\n"
	    "  open = [\n"
	    "    { path = \"/Capabilities/Config/principal-policy.ucl\";\n"
	    "      name = \"principal-policy\"; type = \"file\"; rights = \"r\"; },\n"
	    "    { path = \"/var/db/state\";\n"
	    "      name = \"state\"; type = \"file\"; rights = \"rw\"; },\n"
	    "    { path = \"/Capabilities/Config\";\n"
	    "      name = \"config\"; type = \"dir\"; rights = \"rl\"; },\n"
	    "  ]\n"
	    "}\n", &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(3u, svc.ncap_open);

	ATF_CHECK_STREQ("/Capabilities/Config/principal-policy.ucl",
	    svc.cap_open[0].path);
	ATF_CHECK_STREQ("principal-policy", svc.cap_open[0].name);
	ATF_CHECK_EQ(0, svc.cap_open[0].is_dir);
	ATF_CHECK_EQ(SVC_OPEN_READ, svc.cap_open[0].rights);

	ATF_CHECK_STREQ("state", svc.cap_open[1].name);
	ATF_CHECK_EQ(0, svc.cap_open[1].is_dir);
	ATF_CHECK_EQ(SVC_OPEN_READ | SVC_OPEN_WRITE, svc.cap_open[1].rights);

	ATF_CHECK_STREQ("config", svc.cap_open[2].name);
	ATF_CHECK_EQ(1, svc.cap_open[2].is_dir);
	ATF_CHECK_EQ(SVC_OPEN_READ | SVC_OPEN_LOOKUP, svc.cap_open[2].rights);
}

ATF_TC_WITHOUT_HEAD(open_type_defaults_to_file);
ATF_TC_BODY(open_type_defaults_to_file, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { open = [ { path = \"/etc/thing\";"
	    " name = \"thing\"; rights = \"r\"; } ] }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(1u, svc.ncap_open);
	ATF_CHECK_EQ(0, svc.cap_open[0].is_dir);
}

ATF_TC_WITHOUT_HEAD(open_relative_path_rejected);
ATF_TC_BODY(open_relative_path_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { open = [ { path = \"etc/thing\";"
	    " name = \"thing\"; rights = \"r\"; } ] }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "open path") != NULL);
}

ATF_TC_WITHOUT_HEAD(open_missing_rights_rejected);
ATF_TC_BODY(open_missing_rights_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { open = [ { path = \"/etc/thing\";"
	    " name = \"thing\"; } ] }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "rights") != NULL);
}

ATF_TC_WITHOUT_HEAD(open_bad_name_rejected);
ATF_TC_BODY(open_bad_name_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* Uppercase is outside the [a-z0-9-] capability-name charset. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { open = [ { path = \"/etc/thing\";"
	    " name = \"Thing\"; rights = \"r\"; } ] }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "open name") != NULL);
}

ATF_TC_WITHOUT_HEAD(open_bad_type_rejected);
ATF_TC_BODY(open_bad_type_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { boot = true; }\n"
	    "capabilities { open = [ { path = \"/etc/thing\";"
	    " name = \"thing\"; type = \"socket\"; rights = \"r\"; } ] }\n",
	    &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "file or dir") != NULL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, helper_unit_parses);
	ATF_TP_ADD_TC(tp, helper_with_ipc_rejected);
	ATF_TP_ADD_TC(tp, non_helper_defaults_false);
	ATF_TP_ADD_TC(tp, limits_defaults_when_absent);
	ATF_TP_ADD_TC(tp, limits_integers_parse);
	ATF_TP_ADD_TC(tp, limits_size_suffixes_parse);
	ATF_TP_ADD_TC(tp, limits_negative_rejected);
	ATF_TP_ADD_TC(tp, limits_bad_suffix_rejected);
	ATF_TP_ADD_TC(tp, limits_unknown_key_rejected);
	ATF_TP_ADD_TC(tp, limits_size_overflow_rejected);
	ATF_TP_ADD_TC(tp, umask_octal_string_parses);
	ATF_TP_ADD_TC(tp, umask_out_of_range_rejected);
	ATF_TP_ADD_TC(tp, umask_bad_octal_rejected);
	ATF_TP_ADD_TC(tp, band_names_parse);
	ATF_TP_ADD_TC(tp, band_unknown_rejected);
	ATF_TP_ADD_TC(tp, schedule_cron_parses);
	ATF_TP_ADD_TC(tp, schedule_aliases_parse);
	ATF_TP_ADD_TC(tp, schedule_out_of_range_rejected);
	ATF_TP_ADD_TC(tp, schedule_wrong_field_count_rejected);
	ATF_TP_ADD_TC(tp, persistent_without_schedule_rejected);
	ATF_TP_ADD_TC(tp, timer_and_schedule_mutually_exclusive);
	ATF_TP_ADD_TC(tp, queue_directory_absolute_parses);
	ATF_TP_ADD_TC(tp, queue_directory_relative_rejected);
	ATF_TP_ADD_TC(tp, on_mount_parses);
	ATF_TP_ADD_TC(tp, jail_without_path_parses);
	ATF_TP_ADD_TC(tp, jail_relative_path_rejected);
	ATF_TP_ADD_TC(tp, open_file_and_dir_parse);
	ATF_TP_ADD_TC(tp, open_type_defaults_to_file);
	ATF_TP_ADD_TC(tp, open_relative_path_rejected);
	ATF_TP_ADD_TC(tp, open_missing_rights_rejected);
	ATF_TP_ADD_TC(tp, open_bad_name_rejected);
	ATF_TP_ADD_TC(tp, open_bad_type_rejected);

	return (atf_no_error());
}

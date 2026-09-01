/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Hermetic unit tests for curated rc.d adoption (rc_adopt.c).
 *
 * The selection and unit-building logic is pure: it reads candidate scripts
 * from a caller-supplied directory and produces svc_runtime units, touching no
 * daemon state.  These tests drive it against a synthetic rc.d directory.  The
 * sd.services/kqueue integration (rc_adopt_register) is exercised in the VM
 * boot test, not here — the linker garbage-collects it out of this unit.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "serviced.h"
#include "rc_ingest.h"
#include "rc_adopt.h"

static void
write_script(const char *path, const char *body, mode_t mode)
{
	FILE *f = fopen(path, "w");

	ATF_REQUIRE(f != NULL);
	fputs(body, f);
	fclose(f);
	ATF_REQUIRE(chmod(path, mode) == 0);
}

/* A realistic cron rc.d header (matches libexec/rc/rc.d/cron). */
static const char cron_script[] =
    "#!/bin/sh\n"
    "# PROVIDE: cron\n"
    "# REQUIRE: LOGIN FILESYSTEMS\n"
    "# BEFORE: securelevel\n"
    "# KEYWORD: shutdown\n"
    "\n"
    ". /etc/rc.subr\n"
    "name=cron\n";

ATF_TC_WITHOUT_HEAD(allowlist_membership);
ATF_TC_BODY(allowlist_membership, tc)
{
	const char *const *names;
	unsigned n;

	n = rc_adopt_allowlist(&names);
	ATF_CHECK(n >= 1);
	ATF_CHECK(rc_adopt_is_allowed("cron"));
	/* Not (yet) adopted — proves the allow-list actually gates. */
	ATF_CHECK(!rc_adopt_is_allowed("sshd"));
	ATF_CHECK(!rc_adopt_is_allowed("nosuchsvc"));
}

ATF_TC_WITHOUT_HEAD(selects_only_allowlisted);
ATF_TC_BODY(selects_only_allowlisted, tc)
{
	struct rc_unit units[8];
	int n;

	ATF_REQUIRE(mkdir("rcd", 0755) == 0);
	write_script("rcd/cron", cron_script, 0755);
	/* Non-allow-listed services, each a perfectly valid rc.d service. */
	write_script("rcd/sshd",
	    "#!/bin/sh\n# PROVIDE: sshd\n# REQUIRE: LOGIN\n", 0755);
	write_script("rcd/syslogd",
	    "#!/bin/sh\n# PROVIDE: syslogd\n", 0755);

	n = rc_adopt_select("rcd", units, 8);
	ATF_CHECK_EQ(1, n);		/* ONLY cron, though sshd/syslogd qualify */
	if (n == 1)
		ATF_CHECK_STREQ("cron", units[0].name);
}

ATF_TC_WITHOUT_HEAD(absent_cron_zero_units);
ATF_TC_BODY(absent_cron_zero_units, tc)
{
	struct rc_unit units[8];
	int n;

	/* A directory with only non-allow-listed scripts: nothing adopted. */
	ATF_REQUIRE(mkdir("empty_rcd", 0755) == 0);
	write_script("empty_rcd/sshd",
	    "#!/bin/sh\n# PROVIDE: sshd\n", 0755);

	n = rc_adopt_select("empty_rcd", units, 8);
	ATF_CHECK_EQ(0, n);		/* absent cron -> zero units, no crash */
}

ATF_TC_WITHOUT_HEAD(missing_dir_zero_units);
ATF_TC_BODY(missing_dir_zero_units, tc)
{
	struct rc_unit units[8];

	/* A non-existent rc.d directory must not crash and adopts nothing. */
	ATF_CHECK_EQ(0, rc_adopt_select("no/such/dir", units, 8));
	ATF_CHECK(!rc_adopt_present("no/such/dir", "cron", &units[0]));
}

ATF_TC_WITHOUT_HEAD(nostart_and_nonexec_rejected);
ATF_TC_BODY(nostart_and_nonexec_rejected, tc)
{
	struct rc_unit u;

	/* KEYWORD nostart: present but not auto-started -> not adopted. */
	ATF_REQUIRE(mkdir("ns", 0755) == 0);
	write_script("ns/cron",
	    "#!/bin/sh\n# PROVIDE: cron\n# KEYWORD: nostart\n", 0755);
	ATF_CHECK(!rc_adopt_present("ns", "cron", &u));

	/* A cron script with no PROVIDE is not an orderable service. */
	ATF_REQUIRE(mkdir("np", 0755) == 0);
	write_script("np/cron", "#!/bin/sh\n# REQUIRE: LOGIN\n", 0755);
	ATF_CHECK(!rc_adopt_present("np", "cron", &u));

	/* A non-executable cron script is skipped (like rc_ingest_scan). */
	ATF_REQUIRE(mkdir("nx", 0755) == 0);
	write_script("nx/cron", cron_script, 0644);
	ATF_CHECK(!rc_adopt_present("nx", "cron", &u));
}

ATF_TC_WITHOUT_HEAD(build_unit_shape);
ATF_TC_BODY(build_unit_shape, tc)
{
	struct rc_unit u;
	struct svc_runtime svc;

	memset(&u, 0, sizeof(u));
	strlcpy(u.name, "cron", sizeof(u.name));

	memset(&svc, 0, sizeof(svc));
	rc_adopt_build_unit(&u, &svc);

	/* An adopted rc.d service is a supervised RC unit whose label is the
	 * rc.d name, management class system (root-manageable, not core),
	 * restart on-failure, and STOPPED so the boot loop launches it. */
	ATF_CHECK_EQ(SVC_KIND_RC, svc.kind);
	ATF_CHECK_STREQ("cron", svc.manifest.label);
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.manifest.management);
	ATF_CHECK_EQ(SVC_RESTART_ON_FAILURE, svc.manifest.restart);
	ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
	/* A non-zero onestop backstop deadline: 0 would fire the backstop
	 * immediately and force-stop before onestop could complete. */
	ATF_CHECK(svc.manifest.stop_timeout > 0);
	/* fds initialised to the "absent" sentinel, never a live 0. */
	ATF_CHECK_EQ(-1, svc.pd_fd);
	ATF_CHECK_EQ(-1, svc.channel_fd);
	ATF_CHECK_EQ(-1, svc.coalition_fd);
}

ATF_TC_WITHOUT_HEAD(select_and_build_end_to_end);
ATF_TC_BODY(select_and_build_end_to_end, tc)
{
	struct rc_unit units[8];
	struct svc_runtime svc;
	int n;

	ATF_REQUIRE(mkdir("e2e", 0755) == 0);
	write_script("e2e/cron", cron_script, 0755);

	n = rc_adopt_select("e2e", units, 8);
	ATF_REQUIRE_EQ(1, n);
	memset(&svc, 0, sizeof(svc));
	rc_adopt_build_unit(&units[0], &svc);
	ATF_CHECK_EQ(SVC_KIND_RC, svc.kind);
	ATF_CHECK_STREQ("cron", svc.manifest.label);
	ATF_CHECK_EQ(SVC_MGMT_SYSTEM, svc.manifest.management);
}

ATF_TC_WITHOUT_HEAD(launch_argv_uses_onestart);
ATF_TC_BODY(launch_argv_uses_onestart, tc)
{
	const char *argv[4];

	/*
	 * The RC launch path (svc_exec_rc) builds exactly this argv via the
	 * shared builder: service(8) is invoked with "onestart", not
	 * "faststart".  "onestart" ignores the rc.conf <name>_enable rcvar, so
	 * serviced starts the very service /etc/rc was told to skip
	 * (<name>_enable="NO") with no double-start.
	 */
	rc_adopt_launch_argv("cron", argv);
	ATF_CHECK_STREQ("/usr/sbin/service", argv[0]);
	ATF_CHECK_STREQ("cron", argv[1]);
	ATF_CHECK_STREQ("onestart", argv[2]);
	ATF_CHECK(argv[3] == NULL);
	/* Guard against a silent regression back to faststart. */
	ATF_CHECK(strcmp(argv[2], "faststart") != 0);
	ATF_CHECK_STREQ("onestart", rc_adopt_start_verb);
}

ATF_TC_WITHOUT_HEAD(stop_argv_uses_onestop);
ATF_TC_BODY(stop_argv_uses_onestop, tc)
{
	const char *argv[4];

	/*
	 * The RC stop path (svc_exec_rc_stop) builds exactly this argv via the
	 * shared builder: service(8) is invoked with "onestop", not a plain
	 * "stop".  Like onestart, "onestop" ignores the rc.conf <name>_enable
	 * rcvar, so serviced can stop the very service /etc/rc was told to skip
	 * (<name>_enable="NO"); a plain "stop" would refuse it as disabled and
	 * never signal the daemon.  onestop reads the pidfile and signals the
	 * real (init-reparented) process — the only correct way to stop it.
	 */
	rc_adopt_stop_argv("cron", argv);
	ATF_CHECK_STREQ("/usr/sbin/service", argv[0]);
	ATF_CHECK_STREQ("cron", argv[1]);
	ATF_CHECK_STREQ("onestop", argv[2]);
	ATF_CHECK(argv[3] == NULL);
	/* Never a plain "stop": it honors the rcvar and refuses a disabled
	 * service, leaving the daemon running. */
	ATF_CHECK(strcmp(argv[2], "stop") != 0);
	ATF_CHECK_STREQ("onestop", rc_adopt_stop_verb);
}

ATF_TC_WITHOUT_HEAD(verb_argv_layout);
ATF_TC_BODY(verb_argv_layout, tc)
{
	const char *argv[4];

	/* The shared verb builder places prog/label/verb/NULL for any verb, and
	 * the start/stop wrappers are exactly it with the two live verbs. */
	rc_adopt_verb_argv("cron", "onestart", argv);
	ATF_CHECK_STREQ(rc_adopt_service_prog, argv[0]);
	ATF_CHECK_STREQ("cron", argv[1]);
	ATF_CHECK_STREQ("onestart", argv[2]);
	ATF_CHECK(argv[3] == NULL);

	rc_adopt_verb_argv("cron", "onestop", argv);
	ATF_CHECK_STREQ("onestop", argv[2]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, allowlist_membership);
	ATF_TP_ADD_TC(tp, launch_argv_uses_onestart);
	ATF_TP_ADD_TC(tp, stop_argv_uses_onestop);
	ATF_TP_ADD_TC(tp, verb_argv_layout);
	ATF_TP_ADD_TC(tp, selects_only_allowlisted);
	ATF_TP_ADD_TC(tp, absent_cron_zero_units);
	ATF_TP_ADD_TC(tp, missing_dir_zero_units);
	ATF_TP_ADD_TC(tp, nostart_and_nonexec_rejected);
	ATF_TP_ADD_TC(tp, build_unit_shape);
	ATF_TP_ADD_TC(tp, select_and_build_end_to_end);
	return (atf_no_error());
}

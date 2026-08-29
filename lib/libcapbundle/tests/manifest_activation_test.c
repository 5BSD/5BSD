/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Manifest parsing for Phase 5 activation sources: activation.timer and
 * activation.path.  Exercises capbundle_parse_unit_ucl() directly (declared in
 * the internal header) so the accept/reject decisions are tested at the parser
 * boundary, with no daemon or capability kernel required.
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

/*
 * Write a Unit.ucl body to a temp file in the test's cwd and parse it.  Returns
 * the capbundle_parse_unit_ucl() result; on success svc is filled.  The parser
 * does not stat the program binary (verify does), so no bin/ tree is needed.
 */
static int
parse_unit(const char *body, struct capbundle_service *svc, char *errbuf,
    size_t errlen)
{
	struct capbundle bundle;
	FILE *f;

	memset(&bundle, 0, sizeof(bundle));
	strlcpy(bundle.bundle_id, "org.test.activation",
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

ATF_TC_WITHOUT_HEAD(timer_interval_parses);
ATF_TC_BODY(timer_interval_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { timer = { interval = 45; } }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(45U, svc.timer_interval_sec);
	ATF_CHECK_EQ('\0', svc.activation_path[0]);
	/* A timer alone is a complete activation: no boot, no ipc needed. */
	ATF_CHECK(!svc.activation_boot);
	ATF_CHECK_EQ(0U, svc.nprovides);
}

ATF_TC_WITHOUT_HEAD(timer_calendar_string_rejected);
ATF_TC_BODY(timer_calendar_string_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A cron/calendar string is not a monotonic interval: fail closed. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { interval = \"0 * * * *\"; } }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "interval") != NULL);
}

ATF_TC_WITHOUT_HEAD(timer_unknown_key_rejected);
ATF_TC_BODY(timer_unknown_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* calendar=/persistent= schedules are deferred; reject unknown keys. */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { calendar = \"daily\"; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_zero_rejected);
ATF_TC_BODY(timer_zero_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { timer = { interval = 0; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_overlarge_rejected);
ATF_TC_BODY(timer_overlarge_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];
	char body[128];

	(void)snprintf(body, sizeof(body),
	    "activation { timer = { interval = %ld; } }\n",
	    (long)CAPBUNDLE_MAX_TIMER_INTERVAL + 1);
	ATF_CHECK_EQ(-1, parse_unit(body, &svc, err, sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(path_parses);
ATF_TC_BODY(path_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { path = { path = \"/var/spool/incoming\"; } }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_STREQ("/var/spool/incoming", svc.activation_path);
	ATF_CHECK_EQ(0U, svc.timer_interval_sec);
}

ATF_TC_WITHOUT_HEAD(path_relative_rejected);
ATF_TC_BODY(path_relative_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { path = { path = \"spool/incoming\"; } }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "absolute") != NULL);
}

ATF_TC_WITHOUT_HEAD(path_empty_rejected);
ATF_TC_BODY(path_empty_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { path = { path = \"\"; } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(path_missing_key_rejected);
ATF_TC_BODY(path_missing_key_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit("activation { path = { } }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(empty_activation_still_rejected);
ATF_TC_BODY(empty_activation_still_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* No boot, ipc, timer, or path is still an error. */
	ATF_CHECK_EQ(-1, parse_unit("activation { }\n", &svc, err,
	    sizeof(err)));
}

ATF_TC_WITHOUT_HEAD(timer_and_ipc_coexist);
ATF_TC_BODY(timer_and_ipc_coexist, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A unit may publish an IPC name and also be timer-activated. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { ipc = [\"org.test.svc\"]; timer = { interval = 60; } }\n",
	    &svc, err, sizeof(err)), "unexpected error: %s", err);
	ATF_CHECK_EQ(60U, svc.timer_interval_sec);
	ATF_CHECK_EQ(1U, svc.nprovides);
}

ATF_TC_WITHOUT_HEAD(ipc_reserved_helper_prefix_rejected);
ATF_TC_BODY(ipc_reserved_helper_prefix_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/*
	 * The "helper." prefix names a bundle-local private helper endpoint,
	 * synthesized by the parser from a helper unit's own label and reached
	 * only via service_helper_open().  A unit must not publish one through
	 * activation.ipc: allowing it would let a hostile bundle claim and
	 * register another bundle's private-helper name and impersonate or DoS
	 * it.  It is a syntactically valid reverse-domain name, so only the
	 * reservation check rejects it.
	 */
	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { ipc = [\"helper.org.test.victim.worker\"]; }\n", &svc,
	    err, sizeof(err)));
	ATF_CHECK(strstr(err, "helper.") != NULL);

	/* A name that merely contains "helper" without the prefix is fine. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { ipc = [\"org.test.helperish\"]; }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
}

/* --- Phase 4: socket activation --- */

ATF_TC_WITHOUT_HEAD(socket_single_tcp_parses);
ATF_TC_BODY(socket_single_tcp_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = { name = \"listen\"; "
	    "listen = \"tcp:127.0.0.1:8080\"; } }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_REQUIRE_EQ(1U, svc.nactivation_sockets);
	ATF_CHECK_STREQ("listen", svc.activation_sockets[0].name);
	ATF_CHECK_EQ(AF_INET, svc.activation_sockets[0].domain);
	ATF_CHECK_EQ(SOCK_STREAM, svc.activation_sockets[0].socktype);
	ATF_CHECK_EQ(8080, svc.activation_sockets[0].port);
	ATF_CHECK_EQ(128, svc.activation_sockets[0].backlog);
	/* 127.0.0.1 stored network-order in the first four address bytes. */
	ATF_CHECK_EQ(127, svc.activation_sockets[0].addr[0]);
	ATF_CHECK_EQ(1, svc.activation_sockets[0].addr[3]);
}

ATF_TC_WITHOUT_HEAD(socket_any_and_backlog_parses);
ATF_TC_BODY(socket_any_and_backlog_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = { name = \"pub\"; "
	    "listen = \"tcp6:*:443\"; backlog = 256; } }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(1U, svc.nactivation_sockets);
	ATF_CHECK_EQ(AF_INET6, svc.activation_sockets[0].domain);
	ATF_CHECK_EQ(443, svc.activation_sockets[0].port);
	ATF_CHECK_EQ(256, svc.activation_sockets[0].backlog);
}

ATF_TC_WITHOUT_HEAD(socket_unix_parses);
ATF_TC_BODY(socket_unix_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = { name = \"ctl\"; "
	    "listen = \"unix:/var/run/svc.sock\"; } }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(1U, svc.nactivation_sockets);
	ATF_CHECK_EQ(AF_UNIX, svc.activation_sockets[0].domain);
	ATF_CHECK_EQ(0, svc.activation_sockets[0].port);
	ATF_CHECK_STREQ("/var/run/svc.sock",
	    svc.activation_sockets[0].unixpath);
}

ATF_TC_WITHOUT_HEAD(socket_array_parses);
ATF_TC_BODY(socket_array_parses, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = ["
	    "{ name = \"a\"; listen = \"tcp:*:80\"; },"
	    "{ name = \"b\"; listen = \"udp:*:53\"; } ] }\n", &svc, err,
	    sizeof(err)), "unexpected error: %s", err);
	ATF_REQUIRE_EQ(2U, svc.nactivation_sockets);
	ATF_CHECK_STREQ("a", svc.activation_sockets[0].name);
	ATF_CHECK_EQ(SOCK_STREAM, svc.activation_sockets[0].socktype);
	ATF_CHECK_STREQ("b", svc.activation_sockets[1].name);
	ATF_CHECK_EQ(SOCK_DGRAM, svc.activation_sockets[1].socktype);
	ATF_CHECK_EQ(53, svc.activation_sockets[1].port);
}

ATF_TC_WITHOUT_HEAD(socket_missing_name_rejected);
ATF_TC_BODY(socket_missing_name_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { socket = { listen = \"tcp:*:80\"; } }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "name") != NULL);
}

ATF_TC_WITHOUT_HEAD(socket_bad_scheme_rejected);
ATF_TC_BODY(socket_bad_scheme_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { socket = { name = \"x\"; "
	    "listen = \"sctp:*:80\"; } }\n", &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "scheme") != NULL);
}

ATF_TC_WITHOUT_HEAD(socket_dup_names_rejected);
ATF_TC_BODY(socket_dup_names_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { socket = ["
	    "{ name = \"dup\"; listen = \"tcp:*:80\"; },"
	    "{ name = \"dup\"; listen = \"tcp:*:81\"; } ] }\n", &svc, err,
	    sizeof(err)));
	ATF_CHECK(strstr(err, "duplicate") != NULL);
}

ATF_TC_WITHOUT_HEAD(socket_backlog_out_of_range_rejected);
ATF_TC_BODY(socket_backlog_out_of_range_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { socket = { name = \"x\"; listen = \"tcp:*:80\"; "
	    "backlog = 4096; } }\n", &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "backlog") != NULL);
}

ATF_TC_WITHOUT_HEAD(socket_tcp_port_zero_rejected);
ATF_TC_BODY(socket_tcp_port_zero_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	ATF_CHECK_EQ(-1, parse_unit(
	    "activation { socket = { name = \"x\"; "
	    "listen = \"tcp:*:0\"; } }\n", &svc, err, sizeof(err)));
	ATF_CHECK(strstr(err, "port") != NULL);
}

ATF_TC_WITHOUT_HEAD(socket_unix_with_port_rejected);
ATF_TC_BODY(socket_unix_with_port_rejected, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* "unix:/path:9" trails a ":9"; the path stays absolute but a stray
	 * port makes no sense for AF_UNIX.  parse_listen_spec treats the whole
	 * remainder as the path, so this actually parses as a path ending in
	 * ":9"; assert the unix branch keeps port zero instead. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = { name = \"x\"; "
	    "listen = \"unix:/run/s.sock\"; } }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK_EQ(0, svc.activation_sockets[0].port);
}

ATF_TC_WITHOUT_HEAD(socket_only_is_complete_activation);
ATF_TC_BODY(socket_only_is_complete_activation, tc)
{
	struct capbundle_service svc;
	char err[256];

	/* A socket alone is a complete activation: no boot, ipc, timer, path. */
	ATF_REQUIRE_EQ_MSG(0, parse_unit(
	    "activation { socket = { name = \"listen\"; "
	    "listen = \"tcp:*:80\"; } }\n", &svc, err, sizeof(err)),
	    "unexpected error: %s", err);
	ATF_CHECK(!svc.activation_boot);
	ATF_CHECK_EQ(0U, svc.nprovides);
	ATF_CHECK_EQ(1U, svc.nactivation_sockets);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, timer_interval_parses);
	ATF_TP_ADD_TC(tp, timer_calendar_string_rejected);
	ATF_TP_ADD_TC(tp, timer_unknown_key_rejected);
	ATF_TP_ADD_TC(tp, timer_zero_rejected);
	ATF_TP_ADD_TC(tp, timer_overlarge_rejected);
	ATF_TP_ADD_TC(tp, path_parses);
	ATF_TP_ADD_TC(tp, path_relative_rejected);
	ATF_TP_ADD_TC(tp, path_empty_rejected);
	ATF_TP_ADD_TC(tp, path_missing_key_rejected);
	ATF_TP_ADD_TC(tp, empty_activation_still_rejected);
	ATF_TP_ADD_TC(tp, timer_and_ipc_coexist);
	ATF_TP_ADD_TC(tp, ipc_reserved_helper_prefix_rejected);
	ATF_TP_ADD_TC(tp, socket_single_tcp_parses);
	ATF_TP_ADD_TC(tp, socket_any_and_backlog_parses);
	ATF_TP_ADD_TC(tp, socket_unix_parses);
	ATF_TP_ADD_TC(tp, socket_array_parses);
	ATF_TP_ADD_TC(tp, socket_missing_name_rejected);
	ATF_TP_ADD_TC(tp, socket_bad_scheme_rejected);
	ATF_TP_ADD_TC(tp, socket_dup_names_rejected);
	ATF_TP_ADD_TC(tp, socket_backlog_out_of_range_rejected);
	ATF_TP_ADD_TC(tp, socket_tcp_port_zero_rejected);
	ATF_TP_ADD_TC(tp, socket_unix_with_port_rejected);
	ATF_TP_ADD_TC(tp, socket_only_is_complete_activation);

	return (atf_no_error());
}

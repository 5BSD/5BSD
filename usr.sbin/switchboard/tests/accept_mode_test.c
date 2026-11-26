/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * Accept-per-connection socket activation pins of
 * switchboard-init-rescope.md (slice SR0; SR5 implements the mode, 10.1).
 * They run in the stack tier with the other switchboard suites and need
 * neither a plane nor root: the manifest is read by libcapbundle, the
 * parser SwitchBoard loads every bundle with.
 *
 *   accept_manifest_parsed  (new interface, fails on dev: the socket
 *                           object has no "accept" key, so the bundle is
 *                           refused with "unknown key 'accept'")
 *   listener_mode_unchanged (regression: a socket without "accept" is
 *                           today's listener hand-off, one socket with its
 *                           address and backlog, and keeps parsing)
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libcapbundle.h"
#include "switchboard_manifest.h"

/*
 * Write a one-unit system bundle under ./name.cap whose Unit.ucl carries
 * the activation block given.
 */
static void
write_bundle(const char *name, const char *activation)
{
	char path[PATH_MAX];
	FILE *f;
	int fd;

	snprintf(path, sizeof(path), "%s.cap", name);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s.cap/Bundle.ucl", name);
	ATF_REQUIRE((f = fopen(path, "w")) != NULL);
	fprintf(f,
	    "schema = \"org.5bsd.capability-bundle\";\n"
	    "bundle_id = \"org.test.%s\";\n"
	    "version = \"1.0.0\";\n"
	    "sequence = 1;\n"
	    "author = \"test\";\n"
	    "publisher = \"org.test\";\n"
	    "units = [\"%s\"];\n", name, name);
	ATF_REQUIRE(fclose(f) == 0);
	snprintf(path, sizeof(path), "%s.cap/Units", name);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s.cap/Units/%s.unit", name, name);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s.cap/Units/%s.unit/bin", name, name);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s.cap/Units/%s.unit/Unit.ucl", name,
	    name);
	ATF_REQUIRE((f = fopen(path, "w")) != NULL);
	fprintf(f, "%s\n", activation);
	ATF_REQUIRE(fclose(f) == 0);
	snprintf(path, sizeof(path), "%s.cap/Units/%s.unit/bin/%s", name,
	    name, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "#!/bin/sh\n", 10) == 10);
	ATF_REQUIRE(close(fd) == 0);
}

static struct capbundle *
open_bundle(const char *name, char *err, size_t errlen)
{
	char path[PATH_MAX];
	struct capbundle *b;

	snprintf(path, sizeof(path), "%s.cap", name);
	b = NULL;
	err[0] = '\0';
	if (capbundle_open(path, &b, err, errlen) != 0)
		return (NULL);
	return (b);
}

static const struct svc_activation_socket *
only_socket(struct capbundle *b)
{
	struct capbundle_service *s;

	ATF_REQUIRE_EQ(1, capbundle_nservices(b));
	s = capbundle_service(b, 0);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ_MSG(1, capbundle_svc_nactivation_sockets(s),
	    "the unit declares one activation socket");
	return (capbundle_svc_activation_socket(s, 0));
}

ATF_TC_WITHOUT_HEAD(accept_manifest_parsed);
ATF_TC_BODY(accept_manifest_parsed, tc)
{
	const struct svc_activation_socket *sock;
	struct capbundle *b;
	char err[512];

	write_bundle("acceptor", "activation { socket { name = \"conn\"; "
	    "listen = \"tcp:127.0.0.1:2222\"; accept = true; } }");
	b = open_bundle("acceptor", err, sizeof(err));
	if (b == NULL)
		atf_tc_fail("a socket with accept = true is refused "
		    "(no accept mode): %s", err);
	sock = only_socket(b);
	ATF_CHECK_EQ(AF_INET, sock->domain);
	ATF_CHECK_EQ(SOCK_STREAM, sock->socktype);
	ATF_CHECK_EQ(2222, sock->port);
	capbundle_close(b);
}

ATF_TC_WITHOUT_HEAD(listener_mode_unchanged);
ATF_TC_BODY(listener_mode_unchanged, tc)
{
	const struct svc_activation_socket *sock;
	struct capbundle *b;
	char err[512];

	write_bundle("listener", "activation { socket { name = \"conn\"; "
	    "listen = \"tcp:127.0.0.1:2223\"; backlog = 16; } }");
	b = open_bundle("listener", err, sizeof(err));
	if (b == NULL)
		atf_tc_fail("a listener socket is refused: %s", err);
	sock = only_socket(b);
	ATF_CHECK_STREQ("conn", sock->name);
	ATF_CHECK_EQ(AF_INET, sock->domain);
	ATF_CHECK_EQ(SOCK_STREAM, sock->socktype);
	ATF_CHECK_EQ(2223, sock->port);
	ATF_CHECK_EQ(16, sock->backlog);
	ATF_CHECK_EQ(127, sock->addr[0]);
	ATF_CHECK_EQ(1, sock->addr[3]);
	capbundle_close(b);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, accept_manifest_parsed);
	ATF_TP_ADD_TC(tp, listener_mode_unchanged);
	return (atf_no_error());
}

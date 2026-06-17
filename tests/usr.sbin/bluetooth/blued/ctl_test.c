/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for blued control socket dispatch (ctl.c).
 *
 * Uses socketpair(2) to mock client connections, so no real
 * Bluetooth hardware is required.
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "blued.h"
#include "ble_util.h"
#include "hci_util.h"
#include "ctl.h"

/* ================================================================
 * Stubs for external symbols referenced by ctl.c and conn.c
 * ================================================================ */

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_periph_listen_tag;

/* Stub for central setup thread — ctl.c spawns this via pthread_create */
void *
blued_conn_setup_central(void *arg __unused)
{

	return (NULL);
}

/* Stub for peripheral setup thread */
void *
blued_conn_setup_peripheral(void *arg __unused)
{

	return (NULL);
}

/* ble_util.h globals — extern declared in ble_util.h, defined here */
int blued_verbose;
int blued_daemonized;

/* hci_util.c stubs — called by ctl_cmd_scan() */
int
hci_le_scan(int hci_fd __unused, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults)
{

	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

int
hci_le_ext_scan(int hci_fd __unused, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults)
{

	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

/*
 * Reinitialize blued_g to a clean state before each test.
 */
static void
test_init(void)
{

	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
}

/*
 * Create a socketpair and set up a blued_ctl_client on sp[0].
 * The test writes commands on sp[1] and reads responses from sp[1].
 * Returns the client pointer; caller must free it.
 */
static struct blued_ctl_client *
make_client(int sp[2])
{
	struct blued_ctl_client *client;
	int ret;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	ATF_REQUIRE(ret == 0);

	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sp[0];
	return (client);
}

/*
 * Read all available data from fd into buf (up to bufsz-1 bytes).
 * Returns the number of bytes read.
 */
static ssize_t
drain_response(int fd, char *buf, size_t bufsz)
{
	ssize_t total, n;
	struct timeval tv;

	/* Set a short timeout so we don't block forever */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	total = 0;
	while ((size_t)total < bufsz - 1) {
		n = recv(fd, buf + total, bufsz - 1 - (size_t)total, 0);
		if (n <= 0)
			break;
		total += n;
	}
	buf[total] = '\0';
	return (total);
}

/* ================================================================
 * Test: blued_ctl_respond sends formatted text to the client fd.
 *
 * Since blued_ctl_respond is static, we test it indirectly by
 * dispatching a STATUS command on an empty daemon context and
 * verifying the formatted response arrives on the peer socket.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_respond);
ATF_TC_BODY(test_ctl_respond, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Send a STATUS command which exercises blued_ctl_respond */
	ret = (int)send(sp[1], "STATUS\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "adapters=0") != NULL,
	    "expected 'adapters=0' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "connections=0") != NULL,
	    "expected 'connections=0' in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: STATUS command returns adapter/connection counts
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_status);
ATF_TC_BODY(test_ctl_status, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	/* Add one active adapter */
	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "STATUS\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "adapters=1") != NULL,
	    "expected 'adapters=1' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "connections=0") != NULL,
	    "expected 'connections=0' in response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: ADAPTERS command lists adapter names
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_adapters);
ATF_TC_BODY(test_ctl_adapters, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	/* Leave addr as all zeros */
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "ADAPTERS\n", 9, 0);
	ATF_REQUIRE(ret == 9);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ADAPTERS") != NULL,
	    "expected 'ADAPTERS' header in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "ubt0") != NULL,
	    "expected 'ubt0' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected 'END' in response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: unknown command returns ERROR
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_unknown_cmd);
ATF_TC_BODY(test_ctl_unknown_cmd, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	ret = (int)send(sp[1], "FOOBAR\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected 'ERROR' in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: clean disconnect (recv returns 0) yields dispatch returning -1
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_disconnect);
ATF_TC_BODY(test_ctl_disconnect, tc)
{
	struct blued_ctl_client *client;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Close the writing end to simulate clean disconnect */
	close(sp[1]);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, -1);

	close(sp[0]);
	free(client);
}

/* ================================================================
 * Test: blued_ctl_send_fd sends a file descriptor via SCM_RIGHTS,
 * and the received fd has correct cap_rights.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_send_fd);
ATF_TC_BODY(test_ctl_send_fd, tc)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	cap_rights_t rights;
	int sp[2], fd_pair[2], recv_fd, ret;

	test_init();

	/* sp is the client<->daemon channel for fd passing */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	ATF_REQUIRE(ret == 0);

	/* fd_pair: we'll send fd_pair[0] through the channel */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd_pair);
	ATF_REQUIRE(ret == 0);

	/* Send fd_pair[0] over sp[0] -> sp[1] */
	blued_ctl_send_fd(sp[0], fd_pair[0]);

	/*
	 * Receive the fd on sp[1].  cap_ambient_limit() may fail
	 * outside capability mode, in which case blued_ctl_send_fd
	 * sends an error text response instead of an fd.  Handle
	 * both cases.
	 */
	{
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		(void)setsockopt(sp[1], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
	}
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	ret = (int)recvmsg(sp[1], &msg, 0);
	ATF_REQUIRE(ret >= 1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg != NULL &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS) {
		/* fd transfer succeeded — verify cap_rights */
		memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
		ATF_REQUIRE(recv_fd >= 0);

		ret = cap_rights_get(recv_fd, &rights);
		ATF_REQUIRE(ret == 0);
		ATF_CHECK(cap_rights_is_set(&rights, CAP_SEND));
		ATF_CHECK(cap_rights_is_set(&rights, CAP_RECV));
		ATF_CHECK(cap_rights_is_set(&rights, CAP_EVENT));

		close(recv_fd);
	} else {
		/*
		 * cap_ambient_limit failed (expected outside cap mode);
		 * blued_ctl_send_fd sent an error response instead.
		 * Just verify we got something (the ERROR text).
		 */
		ATF_CHECK(ret >= 1);
	}

	close(fd_pair[0]);
	close(fd_pair[1]);
	close(sp[0]);
	close(sp[1]);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_ctl_respond);
	ATF_TP_ADD_TC(tp, test_ctl_status);
	ATF_TP_ADD_TC(tp, test_ctl_adapters);
	ATF_TP_ADD_TC(tp, test_ctl_unknown_cmd);
	ATF_TP_ADD_TC(tp, test_ctl_disconnect);
	ATF_TP_ADD_TC(tp, test_ctl_send_fd);

	return (atf_no_error());
}

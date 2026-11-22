/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Minimal service-manager double for capsule bootstrap tests.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <capsule_svc_proto.h>

static volatile sig_atomic_t reload_requested;

static void
handle_reload(int signo)
{
	(void)signo;
	reload_requested = 1;
}

static int
send_op(int channel_fd, uint32_t op)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct capsule_req_hdr req;
	struct capsule_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = op;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = op;
	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return (-1);

	memset(&ra, 0, sizeof(ra));
	ra.payload = &reply;
	ra.payload_len = sizeof(reply);
	if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1)
		return (-1);
	return (reply.status);
}

/*
 * Send PAYLOAD (LEN bytes, optional descriptors) with TOKEN and wait,
 * without a deadline, for the reply carrying TOKEN, as SwitchBoard does.
 * Returns the reply's status, or -1 (errno set; ECONNRESET when the channel
 * went away).  Replies are received whole; stray descriptors are closed.
 */
/* Far above any queue's hard limit (queue depth 4096 at most, times the TX hard multiplier). */
#define	MAC_CAPABILITY_MAX_QUEUE_DEPTH_FIXTURE	(1u << 20)

static char rx_payload[MAC_CAPABILITY_MAX_MSG];
static int rx_fds[MAC_CAPABILITY_MAX_FDS];

static int
wait_reply(int channel_fd, uint64_t token)
{
	struct mac_capability_recvmsg_args ra;
	struct capsule_reply reply;
	uint32_t i;

	for (;;) {
		memset(&ra, 0, sizeof(ra));
		ra.payload = rx_payload;
		ra.payload_len = sizeof(rx_payload);
		ra.fds = rx_fds;
		ra.nfds = nitems(rx_fds);
		ra.flags = MAC_CAPABILITY_RECV_F_WAIT;
		ra._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
		if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		for (i = 0; i < ra.nfds; i++)
			close(rx_fds[i]);
		if (ra.payload_len == 0 && ra.nfds == 0 && ra.reply_token == 0) {
			errno = ECONNRESET;
			return (-1);
		}
		if (ra.reply_token != token ||
		    ra.payload_len < sizeof(reply))
			continue;
		memcpy(&reply, rx_payload, sizeof(reply));
		return (reply.status);
	}
}

static void	write_file(const char *, const char *);

/*
 * Receive one message from the discovery route Capsule handed over
 * (SWITCHBOARD_DISCOVERY_FD), as SwitchBoard does, and keep what it carries
 * without answering: for a registration, the client's private endpoint,
 * whose other end the client waits on for the ACK.  Writes
 * switchboard-lookup-held.out once held.
 */
static int
hold_lookup(void)
{
	struct mac_capability_recvmsg_args ra;
	const char *fd_string;
	int discovery_fd;

	fd_string = getenv("SWITCHBOARD_DISCOVERY_FD");
	if (fd_string == NULL) {
		syslog(LOG_ERR, "SWITCHBOARD_DISCOVERY_FD not set");
		return (-1);
	}
	discovery_fd = atoi(fd_string);
	for (;;) {
		memset(&ra, 0, sizeof(ra));
		ra.payload = rx_payload;
		ra.payload_len = sizeof(rx_payload);
		ra.fds = rx_fds;
		ra.nfds = nitems(rx_fds);
		ra.flags = MAC_CAPABILITY_RECV_F_WAIT;
		ra._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
		if (ioctl(discovery_fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
			break;
		if (errno != EINTR) {
			syslog(LOG_ERR, "discovery recvmsg: %m");
			return (-1);
		}
	}
	/* The received descriptors stay open until this process dies. */
	syslog(LOG_INFO, "holding a lookup message with %u descriptors",
	    ra.nfds);
	write_file("switchboard-lookup-held.out", "held\n");
	return (0);
}

static int
send_raw(int channel_fd, const void *payload, uint32_t len, const int *fds,
    uint32_t nfds, uint64_t token)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = len;
	sa.fds = fds;
	sa.nfds = nfds;
	sa.reply_token = token;
	return (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa));
}

static void
write_file(const char *path, const char *line)
{
	FILE *fp;

	fp = fopen(path, "w");
	if (fp != NULL) {
		fputs(line, fp);
		fclose(fp);
	}
}

static void
write_result(const char *line)
{

	write_file("switchboard-answers.out", line);
}

/*
 * A request Capsule cannot serve (SHAPE: short, oversized or extra
 * descriptors) must be answered, and a PING behind it too.
 */
static int
malformed_then_ping(int channel_fd, const char *shape)
{
	static char big[MAC_CAPABILITY_MAX_MSG];
	struct capsule_req_hdr req;
	char line[128];
	int st, ping, p[2];

	memset(&req, 0, sizeof(req));
	req.op = CAPSULE_OP_PING;
	if (strcmp(shape, "short") == 0) {
		if (send_raw(channel_fd, "x", 1, NULL, 0, 101) == -1)
			return (1);
	} else if (strcmp(shape, "oversized") == 0) {
		memcpy(big, &req, sizeof(req));
		if (send_raw(channel_fd, big, sizeof(big), NULL, 0, 101) == -1)
			return (1);
	} else {
		if (pipe(p) == -1 ||
		    send_raw(channel_fd, &req, sizeof(req), p, 2, 101) == -1)
			return (1);
		close(p[0]);
		close(p[1]);
	}
	st = wait_reply(channel_fd, 101);
	if (st == -1)
		st = -errno;
	if (send_raw(channel_fd, &req, sizeof(req), NULL, 0, 102) == -1)
		return (1);
	ping = wait_reply(channel_fd, 102);
	snprintf(line, sizeof(line), "%s status=%d ping=%d\n", shape, st, ping);
	write_result(line);
	return (0);
}

/*
 * Fill this end's queue of unread replies with PINGs, never reading them,
 * waiting for each reply to be queued on EVFILT_READ (no deadline).  Once
 * the queue is at its hard limit Capsule cannot queue the next reply, not
 * even status-only.  It must not drop it silently: the channel ends instead
 * (Capsule closes it and kills this process).  On a Capsule that drops it,
 * the wait for that reply never ends.
 */
static int
flood(int channel_fd)
{
	struct capsule_req_hdr req;
	struct kevent kev;
	uint64_t i;
	int kq;

	kq = kqueue();
	if (kq == -1)
		return (1);
	EV_SET(&kev, channel_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		return (1);
	memset(&req, 0, sizeof(req));
	req.op = CAPSULE_OP_PING;
	write_result("flooding\n");
	/*
	 * Send as fast as Capsule's receive queue takes requests (EAGAIN: it
	 * is full), then wait for replies to be queued before sending more.
	 */
	for (i = 1; i <= MAC_CAPABILITY_MAX_QUEUE_DEPTH_FIXTURE;) {
		if (send_raw(channel_fd, &req, sizeof(req), NULL, 0, i) == 0) {
			i++;
			continue;
		}
		if (errno != EAGAIN)
			return (1);
		if (kevent(kq, NULL, 0, &kev, 1, NULL) != 1)
			return (1);
		if (kev.flags & EV_EOF)
			break;
	}
	write_result("flood: no reply was refused\n");
	return (0);
}

static const char *
read_mode(void)
{
	static char mode[64];
	FILE *fp;
	size_t len;

	fp = fopen("mock-mode", "r");
	if (fp == NULL)
		return ("ready-then-sleep");
	if (fgets(mode, sizeof(mode), fp) == NULL) {
		fclose(fp);
		return ("ready-then-sleep");
	}
	fclose(fp);
	len = strlen(mode);
	if (len > 0 && mode[len - 1] == '\n')
		mode[len - 1] = '\0';
	return (mode[0] == '\0' ? "ready-then-sleep" : mode);
}

static void
write_started(int channel_fd, const char *mode)
{
	FILE *fp;

	fp = fopen("switchboard-started.out", "w");
	if (fp != NULL) {
		fprintf(fp, "pid=%d\nchannel_fd=%d\nmode=%s\n", getpid(),
		    channel_fd, mode);
		fclose(fp);
	}
}

int
main(void)
{
	struct sigaction act;
	const char *fd_string, *mode;
	FILE *fp;
	int channel_fd;

	openlog("capd_bootstrap_fixture", LOG_PID, LOG_DAEMON);
	fd_string = getenv("CAPSULE_CHANNEL_FD");
	if (fd_string == NULL) {
		syslog(LOG_ERR, "CAPSULE_CHANNEL_FD not set");
		return (1);
	}
	channel_fd = atoi(fd_string);
	mode = read_mode();
	if (strcmp(mode, "wait-for-reload") == 0) {
		memset(&act, 0, sizeof(act));
		act.sa_handler = handle_reload;
		sigemptyset(&act.sa_mask);
		if (sigaction(SIGHUP, &act, NULL) == -1)
			return (1);
	}
	write_started(channel_fd, mode);

	if (strcmp(mode, "crash-immediately") == 0)
		return (1);
	if (strcmp(mode, "close-channel-then-sleep") == 0) {
		close(channel_fd);
		for (;;)
			pause();
	}
	if (strcmp(mode, "ping-then-sleep") == 0) {
		if (send_op(channel_fd, CAPSULE_OP_PING) != 0) {
			syslog(LOG_ERR, "PING failed");
			return (1);
		}
		fp = fopen("switchboard-ping-ok.out", "w");
		if (fp != NULL) {
			fputs("ok\n", fp);
			fclose(fp);
		}
		for (;;)
			pause();
	}
	if (strcmp(mode, "short-then-ping") == 0 ||
	    strcmp(mode, "oversized-then-ping") == 0 ||
	    strcmp(mode, "fds-then-ping") == 0) {
		char shape[16];

		strlcpy(shape, mode, sizeof(shape));
		shape[strcspn(shape, "-")] = '\0';
		if (malformed_then_ping(channel_fd, shape) != 0)
			return (1);
		for (;;)
			pause();
	}
	if (strcmp(mode, "hold-lookup-then-flood") == 0) {
		if (hold_lookup() != 0 || flood(channel_fd) != 0)
			return (1);
		for (;;)
			pause();
	}
	if (strcmp(mode, "flood") == 0) {
		if (flood(channel_fd) != 0)
			return (1);
		for (;;)
			pause();
	}
	if (strcmp(mode, "wait-for-reload") == 0) {
		if (send_op(channel_fd, CAPSULE_OP_READY) != 0)
			return (1);
		while (!reload_requested)
			pause();
		fp = fopen("switchboard-reload.out", "w");
		if (fp == NULL)
			return (1);
		fputs("reloaded\n", fp);
		fclose(fp);
		for (;;)
			pause();
	}
	if (strcmp(mode, "ready-then-sleep") == 0) {
		if (send_op(channel_fd, CAPSULE_OP_READY) != 0)
			syslog(LOG_WARNING, "READY failed");
		for (;;)
			pause();
	}
	syslog(LOG_ERR, "unknown mode: %s", mode);
	return (1);
}

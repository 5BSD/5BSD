/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal service-manager double for authorityd bootstrap tests.
 */

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

#include <authorityd_svc_proto.h>

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
	struct authority_req_hdr req;
	struct authority_reply reply;

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

	fp = fopen("serviced-started.out", "w");
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
	fd_string = getenv("AUTHORITYD_CHANNEL_FD");
	if (fd_string == NULL) {
		syslog(LOG_ERR, "AUTHORITYD_CHANNEL_FD not set");
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
		if (send_op(channel_fd, AUTHORITY_OP_PING) != 0) {
			syslog(LOG_ERR, "PING failed");
			return (1);
		}
		fp = fopen("serviced-ping-ok.out", "w");
		if (fp != NULL) {
			fputs("ok\n", fp);
			fclose(fp);
		}
		for (;;)
			pause();
	}
	if (strcmp(mode, "wait-for-reload") == 0) {
		if (send_op(channel_fd, AUTHORITY_OP_READY) != 0)
			return (1);
		while (!reload_requested)
			pause();
		fp = fopen("serviced-reload.out", "w");
		if (fp == NULL)
			return (1);
		fputs("reloaded\n", fp);
		fclose(fp);
		for (;;)
			pause();
	}
	if (strcmp(mode, "ready-then-sleep") == 0) {
		if (send_op(channel_fd, AUTHORITY_OP_READY) != 0)
			syslog(LOG_WARNING, "READY failed");
		for (;;)
			pause();
	}
	syslog(LOG_ERR, "unknown mode: %s", mode);
	return (1);
}

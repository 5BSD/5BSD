/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

int servicectl_program_main(int, char **);
#define main servicectl_program_main
#include "../servicectl.c"
#undef main

#include <sys/wait.h>

#include <atf-c.h>

static int
listen_control(char *path, size_t path_size)
{
	struct sockaddr_un address;
	int fd;

	ATF_REQUIRE(snprintf(path, path_size,
	    "/tmp/servicectl.transport.%ld.sock", (long)getpid()) > 0);
	(void)unlink(path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(fd >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	ATF_REQUIRE_EQ(bind(fd, (struct sockaddr *)&address, sizeof(address)), 0);
	ATF_REQUIRE_EQ(listen(fd, 1), 0);
	return (fd);
}

static int
accept_request(int listener)
{
	struct sctl_request request;
	ssize_t amount;
	int fd;

	fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	amount = recv(fd, &request, sizeof(request), MSG_WAITALL);
	ATF_REQUIRE_EQ(amount, (ssize_t)sizeof(request));
	ATF_REQUIRE_EQ(request.version, SERVICED_CTL_VERSION);
	return (fd);
}

static void
send_reply_header(int fd, uint32_t status, uint32_t length)
{
	struct sctl_reply reply;

	reply.status = status;
	reply.flags = length;
	ATF_REQUIRE_EQ(send(fd, &reply, sizeof(reply), MSG_NOSIGNAL),
	    (ssize_t)sizeof(reply));
}

static void
wait_exit(pid_t pid, int expected)
{
	int status;

	ATF_REQUIRE_EQ(waitpid(pid, &status, 0), pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), expected);
}

ATF_TC_WITHOUT_HEAD(valid_reply);
ATF_TC_BODY(valid_reply, tc)
{
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	char summary[8];
	pid_t pid;
	int fd, listener;

	(void)tc;
	listener = listen_control(path, sizeof(path));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		fd = accept_request(listener);
		send_reply_header(fd, 0, 3);
		ATF_REQUIRE_EQ(send(fd, "ok\n", 3, MSG_NOSIGNAL), 3);
		_exit(0);
	}
	sockpath = path;
	ATF_REQUIRE_EQ(sctl_rpc(SCTL_OP_STATUS, 0, NULL, summary,
	    sizeof(summary)), 0);
	ATF_REQUIRE_STREQ(summary, "ok\n");
	wait_exit(pid, 0);
	close(listener);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(oversized_reply_rejected);
ATF_TC_BODY(oversized_reply_rejected, tc)
{
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	pid_t client;
	int fd, listener;

	(void)tc;
	listener = listen_control(path, sizeof(path));
	client = fork();
	ATF_REQUIRE(client != -1);
	if (client == 0) {
		char summary[8];

		sockpath = path;
		(void)sctl_rpc(SCTL_OP_STATUS, 0, NULL, summary,
		    sizeof(summary));
		_exit(0);
	}
	fd = accept_request(listener);
	send_reply_header(fd, 0, SERVICED_CTL_SUMMARY_MAX + 1);
	close(fd);
	wait_exit(client, 1);
	close(listener);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(truncated_reply_rejected);
ATF_TC_BODY(truncated_reply_rejected, tc)
{
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	struct sctl_reply partial;
	pid_t client;
	int fd, listener;

	(void)tc;
	listener = listen_control(path, sizeof(path));
	client = fork();
	ATF_REQUIRE(client != -1);
	if (client == 0) {
		char summary[8];

		sockpath = path;
		(void)sctl_rpc(SCTL_OP_STATUS, 0, NULL, summary,
		    sizeof(summary));
		_exit(0);
	}
	fd = accept_request(listener);
	memset(&partial, 0, sizeof(partial));
	ATF_REQUIRE_EQ(send(fd, &partial, sizeof(partial) - 1,
	    MSG_NOSIGNAL), (ssize_t)sizeof(partial) - 1);
	close(fd);
	wait_exit(client, 1);
	close(listener);
	unlink(path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, valid_reply);
	ATF_TP_ADD_TC(tp, oversized_reply_rejected);
	ATF_TP_ADD_TC(tp, truncated_reply_rejected);
	return (atf_no_error());
}

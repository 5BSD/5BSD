/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* All children stay in the ATF work directory and inherit declared libraries. */
static int
wait_bounded(pid_t pid)
{
	int status;
	for (unsigned i = 0; i < 100; i++) {
		pid_t result = waitpid(pid, &status, WNOHANG);
		if (result == pid)
			return (WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		if (result < 0 && errno != EINTR)
			return (-1);
		usleep(50000);
	}
	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return (-1);
}

static bool
configuration(const char *location, bool startup)
{
	FILE *f = fopen("config", "w");
	if (f == NULL)
		return (false);
	fprintf(f, "%%snmpd\n");
	if (startup)
		fprintf(f, "begemotSnmpdCommunityString.0.1 = \"test-read\"\n"
		    "begemotSnmpdLocalPortStatus.\"s\" = 1\n"
		    "begemotSnmpdLocalPortType.\"s\" = 4\n");
	fprintf(f, "sysLocation = \"%s\"\n", location);
	return (fclose(f) == 0);
}

static bool
query(const char *client, const char *expected)
{
	pid_t pid = fork();
	if (pid < 0)
		return (false);
	if (pid == 0) {
		int fd = open("response", O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
			_exit(125);
		close(fd);
		execl(client, "bsnmpget", "-n", "-v", "2", "-r", "0",
		    "-t", "1", "-s", "stream::test-read@s", "-o", "quiet",
		    "1.3.6.1.2.1.1.6.0", (char *)NULL);
		_exit(126);
	}
	if (wait_bounded(pid) != 0)
		return (false);
	char buf[128];
	FILE *f = fopen("response", "r");
	if (f == NULL)
		return (false);
	bool ok = fgets(buf, sizeof(buf), f) != NULL &&
	    strncmp(buf, expected, strlen(expected)) == 0 &&
	    strcmp(buf + strlen(expected), "\n") == 0;
	fclose(f);
	return (ok);
}

ATF_TC_WITHOUT_HEAD(private_request);
ATF_TC_BODY(private_request, tc)
{
	const char *daemon = atf_tc_get_config_var(tc, "daemon");
	const char *client = atf_tc_get_config_var(tc, "client");
	ATF_REQUIRE(configuration("bazel-private-test", true));
	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(daemon, "bsnmpd", "-d", "-c", "config", "-p", "pid",
		    "-e", "engine", "-I", ".", (char *)NULL);
		_exit(126);
	}
	/* Do not use fatal assertions until the child has been terminated/reaped. */
	struct stat st;
	bool ready = false;
	for (unsigned i = 0; i < 100; i++) {
		if (stat("s", &st) == 0 && S_ISSOCK(st.st_mode)) {
			ready = true;
			break;
		}
		usleep(50000);
	}
	bool initial = ready && query(client, "bazel-private-test");
	bool reloaded = false;
	if (initial && configuration("bazel-reloaded", false) && kill(pid, SIGHUP) == 0) {
		for (unsigned i = 0; i < 20 && !reloaded; i++) {
			reloaded = query(client, "bazel-reloaded");
			if (!reloaded)
				usleep(50000);
		}
	}
	kill(pid, SIGTERM);
	int status = wait_bounded(pid);
	ATF_CHECK_MSG(initial, "private SNMP GET failed");
	ATF_CHECK_MSG(reloaded, "SIGHUP did not expose updated sysLocation");
	ATF_CHECK_EQ(0, status);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, private_request);
	return (atf_no_error());
}

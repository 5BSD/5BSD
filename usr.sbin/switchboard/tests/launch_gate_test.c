/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <errno.h>
#include <inttypes.h>
#include <login_cap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atf-c.h>

static int fault, registrations, releases, revoked, channels_closed, cleanup;
static int
fault_kevent(int kq, const struct kevent *changes, int nc,
    struct kevent *events, int ne, const struct timespec *timeout)
{
	registrations++;
	if (fault == 1 || fault == 3) {
		if (fault == 3)
			ATF_REQUIRE_EQ(0, kevent(kq, changes, 1, NULL, 0, NULL));
		return (errno = EIO, -1);
	}
	return (kevent(kq, changes, nc, events, ne, timeout));
}
static ssize_t
fault_write(int fd, const void *bytes, size_t length)
{
	releases++;
	if (fault == 2)
		return (errno = EPIPE, -1);
	return (write(fd, bytes, length));
}
#define kevent(...) fault_kevent(__VA_ARGS__)
#define write(...) fault_write(__VA_ARGS__)
#include "../execute.c"
#undef write
#undef kevent

struct switchboard_state sd;
const char *switchboard_run_dir = "run";
void
svc_authority_revoke_unit(const struct svc_runtime *svc __unused)
{
	revoked++;
}
void
domain_unit_channels_close(const struct svc_runtime *svc __unused)
{
	channels_closed++;
}
int
capsule_release_manifest(int fd __unused, const struct svc_manifest *m __unused)
{
	/* Also prove a cleanup error cannot replace the launch error. */
	return (errno = ENOTCONN, -1);
}
void
supervisor_cleanup_failed_launch(struct svc_runtime *svc)
{
	ATF_REQUIRE(svc->launch == NULL);
	ATF_REQUIRE(svc->pid > 0);
	ATF_REQUIRE(fcntl(svc->pd_fd, F_GETFD) >= 0);
	ATF_REQUIRE(fcntl(svc->coalition_fd, F_GETFD) >= 0);
	cleanup++;
}

/* Leaf symbols svc_exec_command() reaches; the command case needs none. */
int
svc_user_manifest_credentials(struct svc_runtime *svc __unused)
{
	return (0);
}
int
svc_user_credentials_match(uid_t owner __unused, uid_t selected __unused,
    bool have_creds __unused)
{
	return (0);
}
int
svc_authority_issue_boot(struct svc_runtime *svc __unused, int *out __unused)
{
	return (errno = ENOTSUP, -1);
}
int
svc_authority_issue_service(struct svc_runtime *svc __unused,
    int *out __unused)
{
	return (errno = ENOTSUP, -1);
}
int
account_nss_user(const char *name __unused,
    struct service_account_identity *user __unused)
{
	return (errno = ENOENT, -1);
}
int
account_nss_group(const char *name __unused, gid_t *gid __unused)
{
	return (errno = ENOENT, -1);
}
int
account_nss_groups(const char *name __unused, gid_t gid __unused,
    gid_t *groups __unused, int *ngroups __unused)
{
	return (errno = ENOENT, -1);
}
int
service_authority_clear(void)
{
	return (0);
}
int
service_authority_install(int fd __unused)
{
	return (0);
}
int
service_clear_ambient_lookup(void)
{
	return (0);
}
int
service_install_ambient_lookup(int fd __unused)
{
	return (0);
}

/*
 * An RC or oneshot command starts as init(8) starts /etc/rc: none of
 * SwitchBoard's environment, only what the login.conf "daemon" class sets
 * (LOGIN_SETENV: no PATH, which /etc/rc sets itself), and that class's limits
 * rather than SwitchBoard's own.
 */
ATF_TC(command_environment_and_class);
ATF_TC_HEAD(command_environment_and_class, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "20");
	atf_tc_set_md_var(tc, "descr",
	    "an rc/oneshot command gets a clean environment and the daemon "
	    "login class, not SwitchBoard's environment and descriptor limit");
}
ATF_TC_BODY(command_environment_and_class, tc)
{
	char *argv[] = { __DECONST(char *, "/bin/sh"),
	    __DECONST(char *, "-c"),
	    __DECONST(char *, "env > command.env; ulimit -n > command.nofile"),
	    NULL };
	struct svc_runtime svc;
	struct kevent event;
	struct rlimit limit;
	login_cap_t *lc;
	char line[256];
	FILE *input;
	rlim_t expected_nofile;
	int kq, status, report[2];
	pid_t probe;

	/* The descriptor limit the daemon class gives a process. */
	lc = login_getclassbyname("daemon", NULL);
	ATF_REQUIRE_MSG(lc != NULL, "no login.conf daemon class");
	login_close(lc);
	ATF_REQUIRE_EQ(0, pipe(report));
	probe = fork();
	ATF_REQUIRE(probe >= 0);
	if (probe == 0) {
		close(report[0]);
		lc = login_getclassbyname("daemon", NULL);
		if (lc == NULL || setusercontext(lc, NULL, 0,
		    LOGIN_SETRESOURCES) == -1 ||
		    getrlimit(RLIMIT_NOFILE, &limit) == -1)
			_exit(1);
		dprintf(report[1], "%ju\n", (uintmax_t)limit.rlim_cur);
		_exit(0);
	}
	close(report[1]);
	input = fdopen(report[0], "r");
	ATF_REQUIRE(input != NULL);
	ATF_REQUIRE(fgets(line, sizeof(line), input) != NULL);
	fclose(input);
	ATF_REQUIRE_EQ(probe, waitpid(probe, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	{
		uintmax_t value;

		ATF_REQUIRE_EQ(1, sscanf(line, "%ju", &value));
		expected_nofile = (rlim_t)value;
	}

	/* SwitchBoard's own state, which the command must not inherit. */
	ATF_REQUIRE_EQ(0, setenv("CAPSULE_CHANNEL_FD", "3", 1));
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_TEST_SHIELD_NO_SIGKILL", "1", 1));
	ATF_REQUIRE_EQ(0, setenv("PATH", "/nonexistent/switchboard", 1));
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	limit.rlim_cur = 64;
	ATF_REQUIRE(limit.rlim_cur != expected_nofile);
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));

	fault = 0;
	memset(&svc, 0, sizeof(svc));
	svc.kind = SVC_KIND_ONESHOT;
	svc.owner_uid = (uid_t)-1;
	svc.state = SVC_STATE_STOPPED;
	strlcpy(svc.manifest.label, "org.test.command",
	    sizeof(svc.manifest.label));
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, svc_exec_command(&svc, kq, argv, false));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, NULL));
	ATF_REQUIRE_EQ(EVFILT_PROCDESC, event.filter);
	ATF_REQUIRE((event.fflags & NOTE_EXIT) != 0);
	ATF_REQUIRE_MSG(WIFEXITED(event.data) && WEXITSTATUS(event.data) == 0,
	    "command status %#jx", (uintmax_t)event.data);
	close(svc.pd_fd);
	close(kq);

	input = fopen("command.env", "r");
	ATF_REQUIRE(input != NULL);
	while (fgets(line, sizeof(line), input) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		ATF_CHECK_MSG(strncmp(line, "CAPSULE_", 8) != 0 &&
		    strncmp(line, "SWITCHBOARD_", 12) != 0 &&
		    strstr(line, "/nonexistent/switchboard") == NULL,
		    "inherited %s", line);
	}
	fclose(input);
	input = fopen("command.nofile", "r");
	ATF_REQUIRE(input != NULL);
	ATF_REQUIRE(fgets(line, sizeof(line), input) != NULL);
	fclose(input);
	line[strcspn(line, "\n")] = '\0';
	if (expected_nofile == RLIM_INFINITY)
		ATF_CHECK_STREQ("unlimited", line);
	else
		ATF_CHECK_EQ_MSG((uintmax_t)expected_nofile,
		    strtoumax(line, NULL, 10),
		    "descriptor limit %s, daemon class %ju", line,
		    (uintmax_t)expected_nofile);
}

ATF_TC(launch_gate_failures);
ATF_TC_HEAD(launch_gate_failures, tc)
{
	atf_tc_set_md_var(tc, "timeout", "20");
	atf_tc_set_md_var(tc, "descr",
	    "Actual execute.c gate failure retains child and coalition for cleanup");
}
ATF_TC_BODY(launch_gate_failures, tc)
{
	struct svc_runtime svc;
	int gate[2], coalition[2], proof[2], kq, status, result, lease;
	char byte;

	for (fault = 0; fault <= 3; fault++) {
		memset(&svc, 0, sizeof(svc));
		registrations = releases = revoked = channels_closed = cleanup = 0;
		svc.manifest.unix_protocol = true;
		strlcpy(svc.manifest.label, "org.test.launch", sizeof(svc.manifest.label));
		ATF_REQUIRE_EQ(0, pipe(gate));
		ATF_REQUIRE_EQ(0, pipe(coalition));
		ATF_REQUIRE_EQ(0, pipe(proof));
		kq = kqueue();
		ATF_REQUIRE(kq >= 0);
		svc.coalition_fd = coalition[0];
		svc.channel_fd = -1;
		svc.launch = calloc(1, sizeof(*svc.launch));
		ATF_REQUIRE(svc.launch != NULL);
		lease = svc.launch->capprotect_fd = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(lease >= 0);
		svc.pid = pdfork(&svc.pd_fd, PD_CLOEXEC);
		ATF_REQUIRE(svc.pid >= 0);
		if (svc.pid == 0) {
			close(gate[1]);
			close(proof[0]);
			if (read(gate[0], &byte, 1) == 1 && byte == 'R')
				(void)write(proof[1], "X", 1);
			_exit(0);
		}
		close(gate[0]);
		close(proof[1]);
		result = svc_launch_release(&svc, kq, gate[1]);
		if (fault == 0) {
			ATF_REQUIRE_EQ(0, result);
			ATF_CHECK_EQ(1, read(proof[0], &byte, 1));
			ATF_CHECK_EQ('X', byte);
			ATF_CHECK_EQ(0, cleanup);
			ATF_CHECK(svc.launch != NULL);
			free(svc.launch);
			close(lease);
		} else {
			ATF_CHECK_EQ(fault == 2 ? EPIPE : EIO, errno);
			ATF_REQUIRE_EQ(-1, result);
			ATF_CHECK_EQ(0, read(proof[0], &byte, 1));
			ATF_CHECK_EQ(1, revoked);
			ATF_CHECK_EQ(1, channels_closed);
			ATF_CHECK_EQ(1, cleanup);
			ATF_CHECK_ERRNO(EBADF, fcntl(lease, F_GETFD) == -1);
		}
		ATF_CHECK_EQ(1, registrations);
		ATF_CHECK_EQ(fault == 1 || fault == 3 ? 0 : 1, releases);
		ATF_CHECK_ERRNO(EBADF, fcntl(gate[1], F_GETFD) == -1);
		do {
			result = pdwait(svc.pd_fd, &status, WEXITED, NULL, NULL);
		} while (result == -1 && errno == EINTR);
		ATF_CHECK_MSG(result == 0 || (result == -1 &&
		    (errno == ECHILD || errno == ESRCH)),
		    "pdwait result=%d errno=%d", result, errno);
		close(svc.pd_fd);
		close(coalition[0]);
		close(coalition[1]);
		close(proof[0]);
		close(kq);
	}
}
ATF_TC(launch_abort_containers);
ATF_TC_HEAD(launch_abort_containers, tc)
{
	atf_tc_set_md_var(tc, "timeout", "20");
	atf_tc_set_md_var(tc, "descr",
	    "Actual launch abort removes pre-fork storage but retains post-fork storage");
}
ATF_TC_BODY(launch_abort_containers, tc)
{
	struct svc_runtime svc;
	struct stat st;
	char leaf[NAME_MAX + 1], byte;
	int parent, container, fresh, gate[2], proof[2], pd, status;
	pid_t child;

	fault = 0;
	ATF_REQUIRE_EQ(0, mkdir("run", 0700));
	parent = open("run", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(parent >= 0);
	for (unsigned forked = 0; forked != 2; forked++) {
		memset(&svc, 0, sizeof(svc));
		strlcpy(svc.manifest.label, "org.test.abort", sizeof(svc.manifest.label));
		svc.owner_uid = (uid_t)-1;
		ATF_REQUIRE_EQ(0, sb_run_container_leaf(svc.manifest.label,
		    svc.owner_uid, leaf, sizeof(leaf)));
		container = svc_run_container_open(svc.manifest.label,
		    svc.owner_uid, getuid(), getgid());
		ATF_REQUIRE(container >= 0);
		svc.launch = calloc(1, sizeof(*svc.launch));
		ATF_REQUIRE(svc.launch != NULL);
		svc.launch->capsule_end = svc.launch->child_end = -1;
		svc.launch->coalition_fd = svc.launch->capprotect_fd = -1;
		svc.launch->nservices = 1;
		svc.launch->service_fds[0] = container;
		svc.launch->forked = forked != 0;
		if (forked) {
			ATF_REQUIRE_EQ(0, pipe(gate));
			ATF_REQUIRE_EQ(0, pipe(proof));
			child = pdfork(&pd, PD_CLOEXEC);
			ATF_REQUIRE(child >= 0);
			if (child == 0) {
				int output;
				close(gate[1]);
				close(proof[0]);
				if (read(gate[0], &byte, 1) != 1)
					_exit(1);
				output = openat(container, "child-state",
				    O_CREAT | O_EXCL | O_WRONLY, 0600);
				if (output == -1)
					_exit(2);
				close(output);
				if (write(proof[1], "X", 1) != 1)
					_exit(3);
				_exit(0);
			}
			close(gate[0]);
			close(proof[1]);
		}
		svc_launch_abort(&svc, EIO, -1);
		ATF_REQUIRE(svc.launch == NULL);
		ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
		ATF_REQUIRE_ERRNO(EBADF, fcntl(container, F_GETFD) == -1);
		if (forked) {
			ATF_REQUIRE_EQ(0, fstatat(parent, leaf, &st, 0));
			ATF_REQUIRE_ERRNO(EEXIST, svc_run_container_open(
			    svc.manifest.label, svc.owner_uid, getuid(), getgid()) == -1);
			ATF_REQUIRE_EQ(1, write(gate[1], "R", 1));
			ATF_REQUIRE_EQ(1, read(proof[0], &byte, 1));
			ATF_CHECK_EQ('X', byte);
			ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
			ATF_REQUIRE(WIFEXITED(status));
			ATF_CHECK_EQ(0, WEXITSTATUS(status));
			close(pd);
			close(gate[1]);
			close(proof[0]);
			/* Model only the call after confirmed child exit, not coalition
			 * completion: that is covered by the supervisor integration gate. */
			svc_run_container_remove(svc.manifest.label, svc.owner_uid);
		}
		ATF_REQUIRE_ERRNO(ENOENT, fstatat(parent, leaf, &st, 0) == -1);
		fresh = svc_run_container_open(svc.manifest.label,
		    svc.owner_uid, getuid(), getgid());
		ATF_REQUIRE(fresh >= 0);
		close(fresh);
		svc_run_container_remove(svc.manifest.label, svc.owner_uid);
	}
	close(parent);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, launch_gate_failures);
	ATF_TP_ADD_TC(tp, launch_abort_containers);
	ATF_TP_ADD_TC(tp, command_environment_and_class);
	return (atf_no_error());
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The unit program of subset_stack_test (NS0 pins NR3 and NR7, the unit
 * half).  SwitchBoard launches it, born in capability mode, with one
 * writable result directory (the test's work directory); every scenario
 * writes its result file there in one write, ending with "end=1".
 *
 *   provider RESULT NAME plain|sendable
 *	expose NAME (sendable or not), report READY, accept clients until
 *	SwitchBoard quiesces the unit.
 *   claimer RESULT OWN NAME...
 *	claim each NAME (none of them in provides[]), then OWN, report
 *	READY, serve OWN until quiesced.
 *   declared RESULT SYSNAME OWN
 *	claim both (both in provides[]), report READY; at the first client
 *	of OWN, record whether a client of SYSNAME was ever delivered, and
 *	serve until quiesced.
 *   requester RESULT NAME...
 *	look each NAME up as this unit (service_connect) and record what
 *	the end it receives allows: its transfer state, passing it on, and
 *	its use by a fork child that cleared its software authority.
 *   requester-exec RESULT PROBE NAME...
 *	LA0 (launch-authority-reshape.md): look each NAME up and record
 *	what the end allows here, from a fork child, and from a fork child
 *	that executed PROBE (launch_authority_probe in the result
 *	directory: another image, so the unit's grant is invalid there;
 *	static, since the unit is in capability mode).
 *
 * No step waits on time: accept() sleeps until SwitchBoard delivers a client
 * or quiesces the unit (ECANCELED), and children are waited for.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <service_bootstrap.h>

#define	MAX_HELD	64

static struct service_context *context;
static struct service_provider *provider;
static int result_dir = -1;
static char result_text[8192];
static size_t result_len;

/* The one writable directory SwitchBoard granted (the test's work dir). */
static int
open_result_dir(void)
{
	char path[PATH_MAX];
	const char *env, *eq;
	size_t len;
	int fd;

	env = getenv(SERVICE_DIR_FDS_ENV);
	if (env == NULL)
		return (-1);
	/* Paths may hold ':'; try each '=' as the end of the path. */
	for (eq = strchr(env, '='); eq != NULL; eq = strchr(eq + 1, '=')) {
		len = (size_t)(eq - env);
		if (len == 0 || len >= sizeof(path))
			continue;
		memcpy(path, env, len);
		path[len] = '\0';
		if (service_resource_dir(path, &fd) == 0)
			return (fd);
	}
	return (-1);
}

static void
add(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(result_text + result_len,
	    sizeof(result_text) - result_len, fmt, ap);
	va_end(ap);
	if (n > 0)
		result_len = MIN(result_len + (size_t)n,
		    sizeof(result_text) - 1);
}

/* Write the result file in one write, so a reader sees it whole. */
static void
flush_result(const char *name)
{
	int fd;

	add("end=1\n");
	fd = openat(result_dir, name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		(void)write(fd, result_text, result_len);
		(void)close(fd);
	}
	result_len = 0;
	result_text[0] = '\0';
}

static const char *
errname(int error)
{
	static char buf[16];

	switch (error) {
	case 0:			return ("0");
	case EACCES:		return ("EACCES");
	case EBADF:		return ("EBADF");
	case EEXIST:		return ("EEXIST");
	case EINVAL:		return ("EINVAL");
	case ENOENT:		return ("ENOENT");
	case ENOTCAPABLE:	return ("ENOTCAPABLE");
	case ENOTSUP:		return ("ENOTSUP");
	case EPERM:		return ("EPERM");
	case ECANCELED:		return ("ECANCELED");
	default:
		snprintf(buf, sizeof(buf), "%d", error);
		return (buf);
	}
}

static int
init(void)
{

	if (service_acquire(&context) == -1)
		return (errno);
	if (service_provider_create(&provider) == -1)
		return (errno);
	return (0);
}

static int
ready(void)
{

	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (errno);
	return (0);
}

static int
expose(const char *name, bool sendable, struct service_listener **l)
{
	int rv;

	*l = NULL;
	rv = sendable ? service_provider_expose_sendable(provider, name, l) :
	    service_provider_expose(provider, name, l);
	return (rv == -1 ? errno : 0);
}

/*
 * Accept clients and keep their ends until SwitchBoard quiesces the unit,
 * then confirm the quiesce and exit.
 */
static void __dead2
serve(struct service_listener *listener, struct service_listener *watch,
    const char *result)
{
	struct service_identity identity;
	int held[MAX_HELD], i, nheld, session;
	char byte;
	bool first;

	nheld = 0;
	first = true;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity,
		    &session) == -1)
			break;
		if (first && watch != NULL) {
			/*
			 * One control channel delivers every client in order:
			 * a client of `watch` sent before this one has already
			 * signalled its listener's event pipe.
			 */
			add("own_client=%s\n", identity.client_label);
			add("sys_pending=%d\n", read(service_listener_fd(watch),
			    &byte, 1) == 1 ? 1 : 0);
			flush_result(result);
		}
		first = false;
		if (nheld == MAX_HELD) {
			(void)close(held[0]);
			memmove(held, held + 1, sizeof(held[0]) * --nheld);
		}
		held[nheld++] = session;
	}
	for (i = 0; i < nheld; i++)
		(void)close(held[i]);
	(void)service_provider_quiesce_complete(provider, 0);
	_exit(0);
}

static int
scenario_provider(const char *result, const char *name, const char *kind)
{
	struct service_listener *listener;
	int error;

	error = init();
	add("init=%s\n", errname(error));
	if (error == 0) {
		error = expose(name, strcmp(kind, "sendable") == 0,
		    &listener);
		add("expose=%s\n", errname(error));
	}
	if (error == 0) {
		error = ready();
		add("ready=%s\n", errname(error));
	}
	flush_result(result);
	if (error != 0)
		return (1);
	serve(listener, NULL, result);
}

static int
scenario_claimer(const char *result, const char *own, int n, char **names)
{
	struct service_listener *listener;
	int error, i;

	error = init();
	add("init=%s\n", errname(error));
	if (error != 0) {
		flush_result(result);
		return (1);
	}
	for (i = 0; i < n; i++)
		add("claim %s=%s\n", names[i],
		    errname(expose(names[i], false, &listener)));
	error = expose(own, false, &listener);
	add("claim own %s=%s\n", own, errname(error));
	if (error == 0) {
		error = ready();
		add("ready=%s\n", errname(error));
	}
	flush_result(result);
	if (error != 0)
		return (1);
	serve(listener, NULL, result);
}

static int
scenario_declared(const char *result, const char *sysname, const char *own)
{
	struct service_listener *sys, *listener;
	int error, sys_error;

	error = init();
	add("init=%s\n", errname(error));
	if (error != 0) {
		flush_result(result);
		return (1);
	}
	sys_error = expose(sysname, false, &sys);
	add("claim %s=%s\n", sysname, errname(sys_error));
	error = expose(own, false, &listener);
	add("claim own %s=%s\n", own, errname(error));
	if (error == 0) {
		error = ready();
		add("ready=%s\n", errname(error));
	}
	flush_result(result);
	if (error != 0)
		return (1);
	serve(listener, sys_error == 0 ? sys : NULL, result);
}

static int
scm_send(int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))], byte = 'x';
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int error, sp[2];

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == -1)
		return (errno);
	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	error = sendmsg(sp[0], &msg, 0) == -1 ? errno : 0;
	(void)close(sp[0]);
	(void)close(sp[1]);
	return (error);
}

static int
chan_send(int fd)
{
	struct mac_capability_sendmsg_args sa;
	int error, pair[2];

	if (mac_capability_channel_create(pair) == -1)
		return (errno);
	memset(&sa, 0, sizeof(sa));
	sa.payload = "x";
	sa.payload_len = 1;
	sa.fds = &fd;
	sa.nfds = 1;
	error = ioctl(pair[0], MAC_CAPABILITY_SENDMSG, &sa) == -1 ? errno : 0;
	(void)close(pair[0]);
	(void)close(pair[1]);
	return (error);
}

static int
getinfo(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1 ? errno : 0);
}

/* GETINFO on fd from a fork child, before and after CAP_AUTH_CLEAR. */
static void
child_use(int fd, int *before, int *after)
{
	pid_t pid;
	int p[2], v[2];

	*before = *after = -1;
	if (pipe(p) == -1)
		return;
	pid = fork();
	if (pid == 0) {
		v[0] = getinfo(fd);
		(void)cap_process(CAP_AUTH_CLEAR, -1, 0, NULL);
		v[1] = getinfo(fd);
		_exit(write(p[1], v, sizeof(v)) == sizeof(v) ? 0 : 1);
	}
	(void)close(p[1]);
	if (pid > 0 && read(p[0], v, sizeof(v)) == sizeof(v)) {
		*before = v[0];
		*after = v[1];
	}
	(void)close(p[0]);
	if (pid > 0)
		(void)waitpid(pid, NULL, 0);
}

/*
 * GETINFO on fd from another image: a fork child makes fd inheritable and
 * fexecve()s probe (launch_authority_probe), whose exit status is the
 * errno GETINFO gave it.  254: the descriptor could not be made
 * inheritable; 253: the exec returned; -1: no child.
 */
static int
exec_use(int probe, int fd)
{
	char num[16];
	char *argv[3], *envp[] = { NULL };
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0) {
		snprintf(num, sizeof(num), "%d", fd);
		argv[0] = __DECONST(char *, "launch_authority_probe");
		argv[1] = num;
		argv[2] = NULL;
		if (fcntl(fd, F_SETFD, 0) == -1)
			_exit(254);
		(void)fexecve(probe, argv, envp);
		_exit(253);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

/*
 * LA0 pins (launch-authority-reshape.md section 3, rewritten by LA3):
 * the end a unit is handed, used by the unit, by its fork child (same
 * grant) and by its fork child after an exec of another image (the grant
 * is invalid there: a grant-bound end answers EPERM, an unbound one 0;
 * an invocation-bound end, SwitchBoard's own control name, refuses the
 * fork child too).
 */
static int
scenario_requester_exec(const char *result, const char *probe_name, int n,
    char **names)
{
	struct cap_authority_info auth;
	int before, after, error, fd, i, probe;

	error = init();
	add("init=%s\n", errname(error));
	if (error != 0) {
		flush_result(result);
		return (1);
	}
	probe = openat(result_dir, probe_name, O_EXEC | O_CLOEXEC);
	add("probe_open=%s\n", errname(probe == -1 ? errno : 0));
	error = ready();
	add("ready=%s\n", errname(error));
	if (error != 0 || probe == -1) {
		flush_result(result);
		return (1);
	}
	memset(&auth, 0, sizeof(auth));
	add("authority_valid=%d\n", cap_process(CAP_AUTH_INFO, -1, 0,
	    &auth) == 0 ? (int)auth.valid : -1);
	for (i = 0; i < n; i++) {
		fd = -1;
		error = service_connect(context, names[i], &fd) == -1 ?
		    errno : 0;
		add("%s connect=%s\n", names[i], errname(error));
		if (fd < 0)
			continue;
		add("%s getinfo=%s\n", names[i], errname(getinfo(fd)));
		child_use(fd, &before, &after);
		add("%s child_getinfo=%s\n", names[i], errname(before));
		add("%s child_cleared_getinfo=%s\n", names[i], errname(after));
		add("%s exec_getinfo=%s\n", names[i],
		    errname(exec_use(probe, fd)));
		(void)close(fd);
	}
	flush_result(result);
	return (0);
}

static int
scenario_requester(const char *result, int n, char **names)
{
	struct cap_authority_info auth;
	int before, after, error, fd, i;

	error = init();
	add("init=%s\n", errname(error));
	if (error != 0) {
		flush_result(result);
		return (1);
	}
	error = ready();
	add("ready=%s\n", errname(error));
	if (error != 0) {
		flush_result(result);
		return (1);
	}
	memset(&auth, 0, sizeof(auth));
	add("authority_valid=%d\n", cap_process(CAP_AUTH_INFO, -1, 0,
	    &auth) == 0 ? (int)auth.valid : -1);
	for (i = 0; i < n; i++) {
		fd = -1;
		error = service_connect(context, names[i], &fd) == -1 ?
		    errno : 0;
		add("%s connect=%s\n", names[i], errname(error));
		if (fd < 0)
			continue;
		/* Passing it on first: the limits below tighten it. */
		add("%s scm_send=%s\n", names[i], errname(scm_send(fd)));
		add("%s chan_send=%s\n", names[i], errname(chan_send(fd)));
		add("%s xfer_once=%s\n", names[i],
		    errname(cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 ? errno :
		    0));
		add("%s xfer_none=%s\n", names[i],
		    errname(cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ? errno :
		    0));
		add("%s getinfo=%s\n", names[i], errname(getinfo(fd)));
		child_use(fd, &before, &after);
		add("%s child_getinfo=%s\n", names[i], errname(before));
		add("%s child_cleared_getinfo=%s\n", names[i], errname(after));
		(void)close(fd);
	}
	flush_result(result);
	return (0);
}

int
main(int argc, char **argv)
{

	result_dir = open_result_dir();
	if (result_dir == -1)
		return (2);
	if (argc == 5 && strcmp(argv[1], "provider") == 0)
		return (scenario_provider(argv[2], argv[3], argv[4]));
	if (argc >= 4 && strcmp(argv[1], "claimer") == 0)
		return (scenario_claimer(argv[2], argv[3], argc - 4, argv + 4));
	if (argc == 5 && strcmp(argv[1], "declared") == 0)
		return (scenario_declared(argv[2], argv[3], argv[4]));
	if (argc >= 3 && strcmp(argv[1], "requester") == 0)
		return (scenario_requester(argv[2], argc - 3, argv + 3));
	if (argc >= 4 && strcmp(argv[1], "requester-exec") == 0)
		return (scenario_requester_exec(argv[2], argv[3], argc - 4,
		    argv + 4));
	return (64);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bootstrap supervisor for serviced.
 *
 * The oracle starts serviced as its single child via pdfork().
 * The child inherits one end of a cap_rt pair on fd 3.  The oracle
 * monitors the process descriptor and restarts serviced on crash
 * with exponential backoff.
 */

#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_svc_proto.h"

/* Restart policy constants. */
#define	BOOTSTRAP_MIN_UPTIME	5	/* seconds before reset */
#define	BOOTSTRAP_BASE_DELAY	1	/* initial restart delay (seconds) */
#define	BOOTSTRAP_MAX_DELAY	30	/* max restart delay (seconds) */
#define	BOOTSTRAP_MAX_FAILURES	10	/* circuit breaker threshold */

/* Well-known fds for serviced. */
#define	SERVICED_PAIR_FD	3	/* pair channel to oracled */
#define	SERVICED_PAIR_SVC_FD	4	/* pair service instance (mintable) */
#define	SERVICED_COALITION_SVC_FD 5	/* coalition service instance (mintable) */
#define	SERVICED_CAPPROTECT_FD	6	/* capprotect service instance */
#define	SERVICED_LAST_FD	6	/* highest well-known fd */

static struct {
	pid_t		pid;
	int		pd_fd;		/* process descriptor */
	int		pair_fd;	/* oracle's end of pair */
	unsigned	restart_count;
	struct timespec	last_start;
	bool		started;
	uintptr_t	timer_ident;	/* kevent timer ident */
} bs;

static uintptr_t next_timer_ident = 90000;

/*
 * Child setup and exec for serviced.
 * Runs in the post-fork child — async-signal-safe only.
 */
/*
 * Fds to delegate to serviced: pair_svc (pair factory), coalition_svc
 * (coalition factory), capprotect (shield).  -1 if unavailable.
 */
struct bootstrap_delegate_fds {
	int	pair_svc_fd;
	int	coalition_svc_fd;
	int	capprotect_fd;
};

static void __dead2
bootstrap_child_exec(int child_pair_fd, const struct bootstrap_delegate_fds *d)
{
	char pair_env[64];
	char pair_svc_env[64], coalition_svc_env[64], capprotect_env[64];
	char manifest_env[PATH_MAX + 32];
	char ctlsock_env[PATH_MAX + 32];
	char *env[9];
	char *argv[2];
	int nullfd, fd, safe_base;
	int src_fds[4], dst_fds[4];
	unsigned envc, i, nfds;

	/*
	 * Redirect stdio to /dev/null.  In foreground mode, preserve
	 * stderr so serviced's LOG_PERROR output reaches the same
	 * destination as oracled's (useful for test log capture).
	 */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd == -1)
		_exit(126);
	if (dup2(nullfd, STDIN_FILENO) == -1 ||
	    dup2(nullfd, STDOUT_FILENO) == -1)
		_exit(126);
	if (!od.foreground) {
		if (dup2(nullfd, STDERR_FILENO) == -1)
			_exit(126);
	}
	if (nullfd > STDERR_FILENO)
		(void)close(nullfd);

	/*
	 * Collect source→dest fd mappings, then move all sources
	 * above the reserved range to avoid clobbering.
	 */
	nfds = 0;
	src_fds[nfds] = child_pair_fd;
	dst_fds[nfds] = SERVICED_PAIR_FD;
	nfds++;
	if (d->pair_svc_fd >= 0) {
		src_fds[nfds] = d->pair_svc_fd;
		dst_fds[nfds] = SERVICED_PAIR_SVC_FD;
		nfds++;
	}
	if (d->coalition_svc_fd >= 0) {
		src_fds[nfds] = d->coalition_svc_fd;
		dst_fds[nfds] = SERVICED_COALITION_SVC_FD;
		nfds++;
	}
	if (d->capprotect_fd >= 0) {
		src_fds[nfds] = d->capprotect_fd;
		dst_fds[nfds] = SERVICED_CAPPROTECT_FD;
		nfds++;
	}

	safe_base = SERVICED_LAST_FD + 1;
	for (i = 0; i < nfds; i++) {
		if (src_fds[i] < safe_base) {
			fd = fcntl(src_fds[i], F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(src_fds[i]);
			src_fds[i] = fd;
		}
	}

	/* Place fds at well-known positions. */
	for (i = 0; i < nfds; i++) {
		if (dup2(src_fds[i], dst_fds[i]) == -1)
			_exit(126);
		(void)close(src_fds[i]);
	}

	/* Close everything above the reserved range. */
	closefrom(SERVICED_LAST_FD + 1);

	/* Clear CLOEXEC on inherited fds. */
	for (i = 0; i < nfds; i++) {
		if (fcntl(dst_fds[i], F_SETFD, 0) == -1)
			_exit(126);
	}

	/* Build minimal environment. */
	envc = 0;
	env[envc++] = __DECONST(char *,
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

	(void)snprintf(pair_env, sizeof(pair_env),
	    "ORACLED_PAIR_FD=%d", SERVICED_PAIR_FD);
	env[envc++] = pair_env;

	if (d->pair_svc_fd >= 0) {
		(void)snprintf(pair_svc_env, sizeof(pair_svc_env),
		    "SERVICED_PAIR_SVC_FD=%d", SERVICED_PAIR_SVC_FD);
		env[envc++] = pair_svc_env;
	}
	if (d->coalition_svc_fd >= 0) {
		(void)snprintf(coalition_svc_env, sizeof(coalition_svc_env),
		    "SERVICED_COALITION_SVC_FD=%d",
		    SERVICED_COALITION_SVC_FD);
		env[envc++] = coalition_svc_env;
	}
	if (d->capprotect_fd >= 0) {
		(void)snprintf(capprotect_env, sizeof(capprotect_env),
		    "SERVICED_CAPPROTECT_FD=%d", SERVICED_CAPPROTECT_FD);
		env[envc++] = capprotect_env;
	}

	if (od.cfg.manifest_dir[0] != '\0') {
		(void)snprintf(manifest_env, sizeof(manifest_env),
		    "SERVICED_MANIFEST_DIR=%s", od.cfg.manifest_dir);
		env[envc++] = manifest_env;
	}

	if (od.cfg.serviced_control_socket[0] != '\0') {
		(void)snprintf(ctlsock_env, sizeof(ctlsock_env),
		    "SERVICED_CONTROL_SOCKET=%s",
		    od.cfg.serviced_control_socket);
		env[envc++] = ctlsock_env;
	}

	env[envc] = NULL;

	/* Reset signal dispositions. */
	for (i = 1; (int)i < NSIG; i++)
		(void)signal((int)i, SIG_DFL);
	{
		sigset_t emptyset;
		sigemptyset(&emptyset);
		(void)sigprocmask(SIG_SETMASK, &emptyset, NULL);
	}

	argv[0] = strrchr(od.cfg.service_manager, '/');
	if (argv[0] != NULL)
		argv[0]++;
	else
		argv[0] = od.cfg.service_manager;
	argv[1] = NULL;

	execve(od.cfg.service_manager, argv, env);
	_exit(127);
}

/*
 * Start serviced.  Creates a pair, pdforks, and registers the
 * process descriptor and pair fd on the kqueue.
 * Returns 0 on success, -1 on failure.
 */
int
bootstrap_start(int kq)
{
	struct bootstrap_delegate_fds dfds;
	struct kevent kev[2];
	int oracle_end, child_end;
	int pd_fd;
	pid_t pid;

	if (od.cfg.service_manager[0] == '\0') {
		syslog(LOG_INFO, "bootstrap: no service_manager configured");
		return (0);
	}

	if (access(od.cfg.service_manager, X_OK) != 0) {
		syslog(LOG_ERR, "bootstrap: %s not executable: %m",
		    od.cfg.service_manager);
		return (-1);
	}

	/* Create pair channel. */
	if (cap_rt_create_pair(&oracle_end, &child_end) == -1) {
		syslog(LOG_ERR, "bootstrap: failed to create pair");
		return (-1);
	}

	/*
	 * Create service instance fds so serviced can create pairs,
	 * coalitions, and shield itself without round-tripping through
	 * the oracle protocol.  These are mintable service instances —
	 * serviced calls CAP_RT_MINT_INSTANCE on them to get fresh
	 * instances for each service it launches.
	 */
	dfds.pair_svc_fd = cap_rt_connect_for_delegate("pair");
	if (dfds.pair_svc_fd == -1)
		syslog(LOG_WARNING, "bootstrap: pair service not available, "
		    "serviced will use oracle protocol");
	dfds.coalition_svc_fd = cap_rt_connect_for_delegate("coalition");
	if (dfds.coalition_svc_fd == -1)
		syslog(LOG_WARNING, "bootstrap: coalition service not "
		    "available");
	dfds.capprotect_fd = cap_rt_connect_for_delegate("capprotect");
	if (dfds.capprotect_fd == -1)
		syslog(LOG_WARNING, "bootstrap: capprotect service not "
		    "available");

	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "bootstrap: pdfork: %m");
		close(oracle_end);
		close(child_end);
		if (dfds.pair_svc_fd >= 0) close(dfds.pair_svc_fd);
		if (dfds.coalition_svc_fd >= 0) close(dfds.coalition_svc_fd);
		if (dfds.capprotect_fd >= 0) close(dfds.capprotect_fd);
		return (-1);
	}

	if (pid == 0) {
		/* Child — does not return. */
		bootstrap_child_exec(child_end, &dfds);
		/* NOTREACHED */
	}

	/* Parent — close delegated fds (child inherited them). */
	close(child_end);
	if (dfds.pair_svc_fd >= 0) close(dfds.pair_svc_fd);
	if (dfds.coalition_svc_fd >= 0) close(dfds.coalition_svc_fd);
	if (dfds.capprotect_fd >= 0) close(dfds.capprotect_fd);

	bs.pid = pid;
	bs.pd_fd = pd_fd;
	bs.pair_fd = oracle_end;
	bs.started = true;
	clock_gettime(CLOCK_MONOTONIC, &bs.last_start);

	/* Tell the protocol handler about the pair fd. */
	oracle_proto_init(oracle_end);

	/* Register procdesc and pair channel on kqueue. */
	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT, 0, NULL);
	EV_SET(&kev[1], oracle_end, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, kev, 2, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "bootstrap: kevent register: %m");
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		close(pd_fd);
		close(oracle_end);
		bs.started = false;
		bs.pid = 0;
		bs.pd_fd = -1;
		bs.pair_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "bootstrap: started serviced pid %jd",
	    (intmax_t)pid);
	return (0);
}

/*
 * Schedule a delayed restart via EVFILT_TIMER.
 */
static void
bootstrap_schedule_restart(int kq, unsigned delay_sec)
{
	struct kevent kev;

	bs.timer_ident = next_timer_ident++;
	EV_SET(&kev, bs.timer_ident, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    0, (int)(delay_sec * 1000), NULL);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_ERR, "bootstrap: timer schedule: %m");
	else
		syslog(LOG_INFO, "bootstrap: scheduling restart in %us",
		    delay_sec);
}

/*
 * Handle serviced process exit.
 * Implements restart with exponential backoff and circuit breaker.
 */
void
bootstrap_handle_exit(struct kevent *kev, int kq)
{
	struct timespec now;
	int status;
	long uptime;
	unsigned delay;

	status = (int)kev->data;

	if (WIFEXITED(status))
		syslog(LOG_WARNING, "bootstrap: serviced exited status %d",
		    WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		syslog(LOG_WARNING, "bootstrap: serviced killed by signal %d",
		    WTERMSIG(status));

	/* Clean up. */
	close(bs.pd_fd);
	bs.pd_fd = -1;
	if (bs.pair_fd >= 0) {
		close(bs.pair_fd);
		bs.pair_fd = -1;
	}
	bs.pid = 0;
	bs.started = false;
	oracle_proto_reset();

	if (od.shutting_down)
		return;

	/* Check uptime for backoff. */
	clock_gettime(CLOCK_MONOTONIC, &now);
	uptime = now.tv_sec - bs.last_start.tv_sec;

	if (uptime >= BOOTSTRAP_MIN_UPTIME) {
		/* Healthy run — reset counter, restart immediately. */
		bs.restart_count = 0;
		if (bootstrap_start(kq) != 0)
			syslog(LOG_ERR, "bootstrap: restart failed");
		return;
	}

	/* Fast crash — apply backoff. */
	bs.restart_count++;

	if (bs.restart_count >= BOOTSTRAP_MAX_FAILURES) {
		syslog(LOG_CRIT,
		    "bootstrap: serviced failed %u times, giving up",
		    bs.restart_count);
		return;
	}

	delay = BOOTSTRAP_BASE_DELAY << (bs.restart_count - 1);
	if (delay > BOOTSTRAP_MAX_DELAY)
		delay = BOOTSTRAP_MAX_DELAY;

	bootstrap_schedule_restart(kq, delay);
}

/*
 * Handle restart timer expiry.
 */
void
bootstrap_handle_timer(struct kevent *kev __unused, int kq)
{

	syslog(LOG_INFO, "bootstrap: restart timer fired");
	if (bootstrap_start(kq) != 0)
		syslog(LOG_ERR, "bootstrap: restart failed");
}

/*
 * Send a signal to serviced via its process descriptor.
 */
void
bootstrap_signal(int sig)
{

	if (!bs.started || bs.pd_fd < 0)
		return;
	if (pdkill(bs.pd_fd, sig) == -1)
		syslog(LOG_WARNING, "bootstrap: pdkill(%d): %m", sig);
}

/*
 * Gracefully stop serviced.
 */
void
bootstrap_stop(void)
{

	if (!bs.started || bs.pd_fd < 0)
		return;

	syslog(LOG_INFO, "bootstrap: stopping serviced");
	pdkill(bs.pd_fd, SIGTERM);
}

bool
bootstrap_is_stopped(void)
{

	return (!bs.started);
}

bool
bootstrap_is_procdesc(struct kevent *kev)
{

	return (kev->filter == EVFILT_PROCDESC &&
	    (int)kev->ident == bs.pd_fd);
}

bool
bootstrap_is_pair(struct kevent *kev)
{

	return (kev->filter == EVFILT_READ &&
	    (int)kev->ident == bs.pair_fd);
}

bool
bootstrap_is_timer(struct kevent *kev)
{

	return (kev->filter == EVFILT_TIMER &&
	    kev->ident == bs.timer_ident &&
	    kev->udata == NULL);
}

pid_t
bootstrap_pid(void)
{

	return (bs.pid);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bootstrap supervisor for serviced.
 *
 * The authority starts serviced as its single child via pdfork().
 * The child inherits one end of a mac_capability channel on fd 3.  The authority
 * monitors the process descriptor and restarts serviced on crash
 * with exponential backoff.
 */

#include <sys/capsicum.h>
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

#include "authorityd.h"
#include "authorityd_svc_proto.h"
#include "probes.h"

/* Restart policy constants. */
#define	BOOTSTRAP_MIN_UPTIME	5	/* seconds before reset */
#define	BOOTSTRAP_BASE_DELAY	1	/* initial restart delay (seconds) */
#define	BOOTSTRAP_MAX_DELAY	30	/* max restart delay (seconds) */
#define	BOOTSTRAP_MAX_FAILURES	10	/* circuit breaker threshold */

/* Well-known fds for serviced. */
#define	SERVICED_CHANNEL_FD	3	/* channel to authorityd */
#define	SERVICED_CHANNEL_SVC_FD	4	/* channel service instance (mintable) */
#define	SERVICED_COALITION_SVC_FD 5	/* coalition service instance (mintable) */
#define	SERVICED_CAPPROTECT_FD	6	/* capprotect service instance */
#define	SERVICED_IDENTITY_FD	7	/* identity service instance */
#define	SERVICED_LAST_FD	7	/* highest well-known fd */

static struct {
	pid_t		pid;
	int		pd_fd;		/* process descriptor */
	int		channel_fd;	/* authority's end of channel */
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
 * Fds to delegate to serviced: channel_svc (channel factory), coalition_svc
 * (coalition factory), capprotect (shield).  -1 if unavailable.
 */
struct bootstrap_delegate_fds {
	int	channel_svc_fd;
	int	coalition_svc_fd;
	int	capprotect_fd;
	int	identity_fd;
	/*
	 * Bundle-directory overrides forwarded to serviced.  Captured from
	 * authorityd's environment in the parent (getenv is not async-signal-safe,
	 * so it must not run in the post-fork child).  NULL when unset, which
	 * is the normal production case — serviced then uses its compiled
	 * /Capabilities defaults.  These are a live override in any environment,
	 * not test-only: whoever controls authorityd's environment (root) can point
	 * serviced's bundle scan elsewhere.  In practice only test harnesses do.
	 */
	const char	*bundle_dir_system;
	const char	*bundle_dir_user;
	/*
	 * "1" opts serviced out of running /etc/rc.  Forwarded like the
	 * bundle-directory overrides; test harnesses must be able to start a
	 * fixture serviced without replaying the host's rc sequence.
	 */
	const char	*skip_rc;
	/* "1" drops CP_SF_SIGKILL from serviced's shield (test-only). */
	const char	*test_no_sigkill;
};

static void __dead2
bootstrap_child_exec(int child_channel_fd, const struct bootstrap_delegate_fds *d)
{
	char channel_env[64];
	char channel_svc_env[64], coalition_svc_env[64], capprotect_env[64];
	char identity_env[64];
	char bundle_sys_env[PATH_MAX + 32], bundle_usr_env[PATH_MAX + 32];
	char skip_rc_env[32], no_sigkill_env[40];
	char *env[14];
	char *argv[2];
	int nullfd, fd, safe_base;
	int src_fds[5], dst_fds[5];
	unsigned envc, i, nfds;

	/*
	 * Redirect stdio to /dev/null.  In foreground mode, preserve
	 * stderr so serviced's LOG_PERROR output reaches the same
	 * destination as authorityd's (useful for test log capture).
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
	src_fds[nfds] = child_channel_fd;
	dst_fds[nfds] = SERVICED_CHANNEL_FD;
	nfds++;
	if (d->channel_svc_fd >= 0) {
		src_fds[nfds] = d->channel_svc_fd;
		dst_fds[nfds] = SERVICED_CHANNEL_SVC_FD;
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
	if (d->identity_fd >= 0) {
		src_fds[nfds] = d->identity_fd;
		dst_fds[nfds] = SERVICED_IDENTITY_FD;
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

	/*
	 * Close unused slots in the reserved range.  In particular, identity
	 * is optional; without this pass an unrelated authorityd descriptor that
	 * happened to occupy fd 7 could survive the exec.
	 */
	for (fd = SERVICED_CHANNEL_FD; fd <= SERVICED_LAST_FD; fd++) {
		bool delegated;

		delegated = false;
		for (i = 0; i < nfds; i++) {
			if (dst_fds[i] == fd) {
				delegated = true;
				break;
			}
		}
		if (!delegated)
			(void)close(fd);
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

	(void)snprintf(channel_env, sizeof(channel_env),
	    "AUTHORITYD_CHANNEL_FD=%d", SERVICED_CHANNEL_FD);
	env[envc++] = channel_env;

	if (d->channel_svc_fd >= 0) {
		(void)snprintf(channel_svc_env, sizeof(channel_svc_env),
		    "SERVICED_CHANNEL_SVC_FD=%d", SERVICED_CHANNEL_SVC_FD);
		env[envc++] = channel_svc_env;
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
	if (d->identity_fd >= 0) {
		(void)snprintf(identity_env, sizeof(identity_env),
		    "SERVICED_IDENTITY_FD=%d", SERVICED_IDENTITY_FD);
		env[envc++] = identity_env;
	}

	/* Forward bundle-directory overrides when present (see struct comment). */
	if (d->bundle_dir_system != NULL) {
		(void)snprintf(bundle_sys_env, sizeof(bundle_sys_env),
		    "SERVICED_BUNDLE_DIR_SYSTEM=%s", d->bundle_dir_system);
		env[envc++] = bundle_sys_env;
	}
	if (d->bundle_dir_user != NULL) {
		(void)snprintf(bundle_usr_env, sizeof(bundle_usr_env),
		    "SERVICED_BUNDLE_DIR_USER=%s", d->bundle_dir_user);
		env[envc++] = bundle_usr_env;
	}
	if (d->skip_rc != NULL && d->skip_rc[0] == '1') {
		(void)snprintf(skip_rc_env, sizeof(skip_rc_env),
		    "SERVICED_SKIP_RC=1");
		env[envc++] = skip_rc_env;
	}
	if (d->test_no_sigkill != NULL && d->test_no_sigkill[0] == '1') {
		(void)snprintf(no_sigkill_env, sizeof(no_sigkill_env),
		    "SERVICED_TEST_SHIELD_NO_SIGKILL=1");
		env[envc++] = no_sigkill_env;
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
 * Start serviced.  Creates a channel, pdforks, and registers the
 * process descriptor and channel fd on the kqueue.
 * Returns 0 on success, -1 on failure.
 */
int
bootstrap_start(int kq)
{
	struct bootstrap_delegate_fds dfds;
	struct kevent kev[2];
	cap_rights_t rights;
	int authority_end, child_end;
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

	/* Create channel. */
	if (mac_capability_create_channel(&authority_end, &child_end) == -1) {
		syslog(LOG_ERR, "bootstrap: failed to create channel");
		return (-1);
	}

	/*
	 * Create service instance fds so serviced can create channels,
	 * coalitions, and shield itself without round-tripping through
	 * the authority protocol.  These are mintable service instances —
	 * serviced calls MAC_CAPABILITY_MINT_INSTANCE on them to get fresh
	 * instances for each service it launches.
	 */
	dfds.channel_svc_fd = mac_capability_connect_for_delegate("channel");
	if (dfds.channel_svc_fd == -1) {
		syslog(LOG_ERR, "bootstrap: channel service not available");
		close(authority_end);
		close(child_end);
		return (-1);
	}
	dfds.coalition_svc_fd = mac_capability_connect_for_delegate("coalition");
	if (dfds.coalition_svc_fd == -1) {
		syslog(LOG_ERR, "bootstrap: coalition service not available");
		close(authority_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		return (-1);
	}
	dfds.capprotect_fd = mac_capability_connect_for_delegate("capprotect");
	if (dfds.capprotect_fd == -1) {
		syslog(LOG_ERR, "bootstrap: capprotect service not available");
		close(authority_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		return (-1);
	}
	dfds.identity_fd = mac_capability_connect_for_delegate("identity");
	if (dfds.identity_fd == -1) {
		/* Identity is optional — on-demand attribution is degraded. */
		syslog(LOG_WARNING,
		    "bootstrap: identity service not available, "
		    "on-demand attribution disabled");
	}

	/* Capture bundle-dir overrides here — getenv is not safe post-fork. */
	dfds.bundle_dir_system = getenv("SERVICED_BUNDLE_DIR_SYSTEM");
	dfds.bundle_dir_user = getenv("SERVICED_BUNDLE_DIR_USER");
	dfds.skip_rc = getenv("SERVICED_SKIP_RC");
	dfds.test_no_sigkill = getenv("SERVICED_TEST_SHIELD_NO_SIGKILL");

	/*
	 * These descriptors cross exactly one fork edge into serviced.  They
	 * must never be transferable by either side.  CLOFORK/CLOEXEC cannot be
	 * locked yet because the descriptors intentionally cross this fork and
	 * the subsequent exec; serviced locks both dimensions immediately after
	 * exec.
	 */
	if (cap_xfer_limit(child_end, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.channel_svc_fd, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.coalition_svc_fd, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.capprotect_fd, CAP_XFER_NONE) == -1 ||
	    (dfds.identity_fd >= 0 &&
	    cap_xfer_limit(dfds.identity_fd, CAP_XFER_NONE) == -1)) {
		syslog(LOG_ERR, "bootstrap: confine delegated fd: %m");
		close(authority_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0)
			close(dfds.identity_fd);
		return (-1);
	}

	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "bootstrap: pdfork: %m");
		AUTHORITYD_PROBE_ERROR("bootstrap", "pdfork failed");
		close(authority_end);
		close(child_end);
		if (dfds.channel_svc_fd >= 0) close(dfds.channel_svc_fd);
		if (dfds.coalition_svc_fd >= 0) close(dfds.coalition_svc_fd);
		if (dfds.capprotect_fd >= 0) close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0) close(dfds.identity_fd);
		return (-1);
	}

	if (pid == 0) {
		/* Child — does not return. */
		bootstrap_child_exec(child_end, &dfds);
		/* NOTREACHED */
	}

	/* Parent — close delegated fds (child inherited them). */
	close(child_end);
	if (dfds.channel_svc_fd >= 0)
		close(dfds.channel_svc_fd);
	if (dfds.coalition_svc_fd >= 0)
		close(dfds.coalition_svc_fd);
	if (dfds.capprotect_fd >= 0)
		close(dfds.capprotect_fd);
	if (dfds.identity_fd >= 0)
		close(dfds.identity_fd);

	/*
	 * The process descriptor is authorityd's explicit and exclusive authority
	 * over this serviced instance.  pdkill(2) intentionally bypasses ambient
	 * credential and MAC signal checks, so this descriptor must not escape
	 * through transfer, fork, or exec.  Failure to freeze that topology is a
	 * bootstrap failure, not a condition in which supervision may continue.
	 */
	cap_rights_init(&rights, CAP_PDKILL, CAP_EVENT);
	if (cap_rights_limit(pd_fd, &rights) == -1 ||
	    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "bootstrap: confine serviced procdesc: %m");
		(void)pdkill(pd_fd, SIGKILL);
		close(pd_fd);
		close(authority_end);
		return (-1);
	}

	/* Authority's channel endpoint is equally exclusive and fail-closed. */
	if (cap_xfer_limit(authority_end, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(authority_end, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(authority_end, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "bootstrap: confine authority channel: %m");
		(void)pdkill(pd_fd, SIGKILL);
		close(pd_fd);
		close(authority_end);
		return (-1);
	}

	bs.pid = pid;
	bs.pd_fd = pd_fd;
	bs.channel_fd = authority_end;
	bs.started = true;
	clock_gettime(CLOCK_MONOTONIC, &bs.last_start);

	/* Tell the protocol handler about the channel fd. */
	authority_proto_init(authority_end);

	/* Register procdesc and channel on kqueue. */
	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT, 0, NULL);
	EV_SET(&kev[1], authority_end, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, kev, 2, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "bootstrap: kevent register: %m");
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		close(pd_fd);
		close(authority_end);
		bs.started = false;
		bs.pid = 0;
		bs.pd_fd = -1;
		bs.channel_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "bootstrap: started serviced pid %jd",
	    (intmax_t)pid);
	AUTHORITYD_PROBE_BOOTSTRAP_START(pid);
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
 * Tear down all serviced resources and restart with backoff.
 * Called only from the EVFILT_PROCDESC path — process exit is
 * the single source of truth for lifecycle.
 */
static void
bootstrap_teardown_and_restart(int kq, int status)
{
	struct timespec now;
	long uptime;
	unsigned delay;

	if (WIFEXITED(status))
		syslog(LOG_WARNING, "bootstrap: serviced exited status %d",
		    WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		syslog(LOG_WARNING, "bootstrap: serviced killed by signal %d",
		    WTERMSIG(status));

	AUTHORITYD_PROBE_BOOTSTRAP_EXIT(bs.pid, status);

	/*
	 * Tear down this instance's fds.  The channel-EOF path may have
	 * already closed channel_fd, so each fd is guarded individually.
	 */
	if (bs.pd_fd >= 0) {
		struct kevent kev_del;

		EV_SET(&kev_del, bs.pd_fd, EVFILT_PROCDESC,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev_del, 1, NULL, 0, NULL);
		close(bs.pd_fd);
		bs.pd_fd = -1;
	}
	if (bs.channel_fd >= 0) {
		close(bs.channel_fd);
		bs.channel_fd = -1;
	}
	bs.pid = 0;
	bs.started = false;
	authority_proto_reset();

	if (od.shutting_down)
		return;

	/* Check uptime for backoff. */
	clock_gettime(CLOCK_MONOTONIC, &now);
	uptime = now.tv_sec - bs.last_start.tv_sec;

	if (uptime >= BOOTSTRAP_MIN_UPTIME) {
		bs.restart_count = 0;
		if (bootstrap_start(kq) == 0)
			return;
		syslog(LOG_ERR, "bootstrap: restart failed");
		/* Fall through to backoff. */
	}

	bs.restart_count++;
	if (bs.restart_count >= BOOTSTRAP_MAX_FAILURES) {
		syslog(LOG_CRIT,
		    "bootstrap: serviced failed %u times, giving up",
		    bs.restart_count);
		AUTHORITYD_PROBE_ERROR("bootstrap", "circuit breaker tripped");
		return;
	}

	delay = BOOTSTRAP_BASE_DELAY << (bs.restart_count - 1);
	if (delay > BOOTSTRAP_MAX_DELAY)
		delay = BOOTSTRAP_MAX_DELAY;

	AUTHORITYD_PROBE_BOOTSTRAP_RESTART(bs.restart_count, delay);
	bootstrap_schedule_restart(kq, delay);
}

/*
 * Handle channel EOF.
 *
 * The procdesc remains the lifecycle source of truth, but loss of the
 * exclusive authority channel is an integrity failure: a live serviced can
 * no longer obtain or release capabilities.  Force that instance to exit and
 * let EVFILT_PROCDESC drive teardown/restart.
 */
void
bootstrap_handle_channel_eof(void)
{

	if (bs.channel_fd >= 0) {
		close(bs.channel_fd);
		bs.channel_fd = -1;
	}
	if (bs.started && bs.pd_fd >= 0)
		(void)pdkill(bs.pd_fd, SIGKILL);
}

/*
 * Handle serviced process exit (EVFILT_PROCDESC).
 */
void
bootstrap_handle_exit(struct kevent *kev, int kq)
{

	bootstrap_teardown_and_restart(kq, (int)kev->data);
}

/*
 * Handle restart timer expiry.  If bootstrap_start still fails
 * (e.g. binary missing, mac_capability unavailable), reschedule with
 * backoff rather than leaving serviced permanently dead.
 */
void
bootstrap_handle_timer(int kq)
{
	unsigned delay;

	syslog(LOG_INFO, "bootstrap: restart timer fired");
	if (bootstrap_start(kq) == 0)
		return;

	syslog(LOG_ERR, "bootstrap: restart failed");

	bs.restart_count++;
	if (bs.restart_count >= BOOTSTRAP_MAX_FAILURES) {
		syslog(LOG_CRIT,
		    "bootstrap: serviced failed %u times, giving up",
		    bs.restart_count);
		AUTHORITYD_PROBE_ERROR("bootstrap", "circuit breaker tripped");
		return;
	}

	delay = BOOTSTRAP_BASE_DELAY << (bs.restart_count - 1);
	if (delay > BOOTSTRAP_MAX_DELAY)
		delay = BOOTSTRAP_MAX_DELAY;

	AUTHORITYD_PROBE_BOOTSTRAP_RESTART(bs.restart_count, delay);
	bootstrap_schedule_restart(kq, delay);
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

/*
 * True once the restart circuit breaker has tripped: serviced has failed
 * BOOTSTRAP_MAX_FAILURES times and will not be restarted again.  This is
 * the definitive "serviced is permanently dead" signal (as opposed to a
 * transient stop during a restart backoff).
 */
bool
bootstrap_has_given_up(void)
{

	return (!bs.started && bs.restart_count >= BOOTSTRAP_MAX_FAILURES);
}

bool
bootstrap_is_procdesc(struct kevent *kev)
{

	return (kev->filter == EVFILT_PROCDESC &&
	    (int)kev->ident == bs.pd_fd);
}

bool
bootstrap_is_channel(struct kevent *kev)
{

	return (kev->filter == EVFILT_READ &&
	    (int)kev->ident == bs.channel_fd);
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

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/procctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

void
reap_children(void)
{
	int saved_errno, status;
	pid_t pid;

	saved_errno = errno;
	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid <= 0)
			break;
		if (WIFEXITED(status)) {
			syslog(LOG_INFO, "reaped child %jd exit %d",
			    (intmax_t)pid, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			syslog(LOG_INFO, "reaped child %jd signal %d",
			    (intmax_t)pid, WTERMSIG(status));
		} else {
			syslog(LOG_INFO, "reaped child %jd", (intmax_t)pid);
		}
	}
	errno = saved_errno;
}

void
kill_subtree(void)
{
	struct procctl_reaper_kill rk;

	memset(&rk, 0, sizeof(rk));
	rk.rk_sig = SIGTERM;
	rk.rk_flags = 0;
	if (procctl(P_PID, getpid(), PROC_REAP_KILL, &rk) == -1) {
		if (errno != ESRCH)
			syslog(LOG_WARNING, "PROC_REAP_KILL: %m");
	} else if (rk.rk_killed > 0) {
		syslog(LOG_INFO, "sent SIGTERM to %u descendant(s)",
		    rk.rk_killed);
		usleep(100000);
		reap_children();
	}
}

void
apply_procctl_self_policy(void)
{
	struct procctl_reaper_status rs;
	int ctl;

	if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == -1) {
		syslog(LOG_WARNING, "PROC_REAP_ACQUIRE failed: %m");
	} else {
		syslog(LOG_INFO, "acquired process subtree reaper status");
	}

	memset(&rs, 0, sizeof(rs));
	if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs) == -1) {
		syslog(LOG_WARNING, "PROC_REAP_STATUS failed: %m");
	} else if ((rs.rs_flags & REAPER_STATUS_OWNED) == 0) {
		syslog(LOG_WARNING,
		    "process is not reported as reaper; reaper pid %jd",
		    (intmax_t)rs.rs_reaper);
	} else {
		syslog(LOG_INFO,
		    "reaper status confirmed: children=%u descendants=%u",
		    rs.rs_children, rs.rs_descendants);
	}

	ctl = PPROT_SET;
	if (procctl(P_PID, getpid(), PROC_SPROTECT, &ctl) == -1)
		syslog(LOG_WARNING, "PROC_SPROTECT failed: %m");
	else
		syslog(LOG_INFO, "enabled OOM protection");

	ctl = PROC_TRACE_CTL_DISABLE_EXEC;
	if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &ctl) == -1)
		syslog(LOG_WARNING, "PROC_TRACE_CTL failed: %m");
	else
		syslog(LOG_INFO, "disabled tracing and core dumps");

	ctl = PROC_LOGSIGEXIT_CTL_FORCE_ENABLE;
	if (procctl(P_PID, getpid(), PROC_LOGSIGEXIT_CTL, &ctl) == -1)
		syslog(LOG_WARNING, "PROC_LOGSIGEXIT_CTL failed: %m");
	else
		syslog(LOG_INFO, "enabled signal-exit logging");
}

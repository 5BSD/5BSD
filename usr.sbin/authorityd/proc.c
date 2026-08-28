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

#include "authorityd.h"

void
reap_children(void)
{
	int status;
	pid_t pid;

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
}

void
kill_subtree(void)
{
	struct procctl_reaper_kill rk;
	struct procctl_reaper_status rs;

	memset(&rk, 0, sizeof(rk));
	rk.rk_sig = SIGTERM;
	rk.rk_flags = 0;
	if (procctl(P_PID, getpid(), PROC_REAP_KILL, &rk) == -1) {
		if (errno != ESRCH)
			syslog(LOG_WARNING, "PROC_REAP_KILL: %m");
		return;
	}
	if (rk.rk_killed == 0)
		return;

	syslog(LOG_INFO, "sent SIGTERM to %u descendant(s)", rk.rk_killed);
	reap_children();

	/* Escalate to SIGKILL if any descendants remain. */
	memset(&rs, 0, sizeof(rs));
	if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs) == 0 &&
	    rs.rs_descendants > 0) {
		int attempts;

		syslog(LOG_WARNING, "%u descendant(s) still alive, "
		    "sending SIGKILL", rs.rs_descendants);
		memset(&rk, 0, sizeof(rk));
		rk.rk_sig = SIGKILL;
		(void)procctl(P_PID, getpid(), PROC_REAP_KILL, &rk);

		/* Wait for all descendants to actually exit. */
		for (attempts = 0; attempts < 50; attempts++) {
			reap_children();
			memset(&rs, 0, sizeof(rs));
			if (procctl(P_PID, getpid(), PROC_REAP_STATUS,
			    &rs) != 0 || rs.rs_descendants == 0)
				break;
			usleep(10000); /* 10ms */
		}
	}
}

int
apply_procctl_self_policy(void)
{
	struct procctl_reaper_status rs;
	int ctl;

	if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == -1) {
		syslog(LOG_ERR, "PROC_REAP_ACQUIRE failed: %m");
		return (-1);
	}
	syslog(LOG_INFO, "acquired process subtree reaper status");

	memset(&rs, 0, sizeof(rs));
	if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs) == -1) {
		syslog(LOG_ERR, "PROC_REAP_STATUS failed: %m");
		return (-1);
	}
	if ((rs.rs_flags & REAPER_STATUS_OWNED) == 0) {
		syslog(LOG_ERR,
		    "process is not reported as reaper; reaper pid %jd",
		    (intmax_t)rs.rs_reaper);
		return (-1);
	}
	syslog(LOG_INFO,
	    "reaper status confirmed: children=%u descendants=%u",
	    rs.rs_children, rs.rs_descendants);

	ctl = PPROT_SET;
	if (procctl(P_PID, getpid(), PROC_SPROTECT, &ctl) == -1) {
		syslog(LOG_ERR, "PROC_SPROTECT failed: %m");
		return (-1);
	}
	syslog(LOG_INFO, "enabled OOM protection");

	ctl = PROC_TRACE_CTL_DISABLE_EXEC;
	if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &ctl) == -1) {
		syslog(LOG_ERR, "PROC_TRACE_CTL failed: %m");
		return (-1);
	}
	syslog(LOG_INFO, "disabled tracing and core dumps");

	ctl = PROC_LOGSIGEXIT_CTL_FORCE_ENABLE;
	if (procctl(P_PID, getpid(), PROC_LOGSIGEXIT_CTL, &ctl) == -1)
		syslog(LOG_WARNING, "PROC_LOGSIGEXIT_CTL failed: %m");
	else
		syslog(LOG_INFO, "enabled signal-exit logging");

	return (0);
}

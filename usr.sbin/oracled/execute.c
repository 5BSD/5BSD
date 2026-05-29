/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service fork/exec for oracled.
 *
 * Creates a pair channel, mints capability tokens, pdfork()s a
 * child, scrubs its environment and fds, sets credentials, and
 * exec()s the program from the manifest.  Registers the process
 * descriptor and pair channel on the kqueue for supervision.
 */

#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

#define	SVC_PAIR_FD	3	/* well-known fd for the pair channel */
#define	SVC_TOKEN_BASE	4	/* tokens start at fd 4 */
#define	SVC_MAX_TOKENS	(ORACLED_MAX_CAP_PATHS + 2)	/* paths + net + system */
#define	SVC_MAX_ENV	16

/*
 * Build the token fd list string for ORACLED_TOKEN_FDS env var.
 * Format: "4,5,6" (comma-separated).
 */
static void
build_token_fds_str(char *buf, size_t bufsz, unsigned ntokens)
{
	unsigned i;
	size_t off;

	off = 0;
	for (i = 0; i < ntokens && off < bufsz - 1; i++) {
		if (i > 0 && off < bufsz - 1)
			buf[off++] = ',';
		off += (size_t)snprintf(buf + off,
		    off < bufsz ? bufsz - off : 0,
		    "%u", SVC_TOKEN_BASE + i);
		if (off >= bufsz)
			off = bufsz - 1;
	}
	buf[off] = '\0';
}

/*
 * Child process setup and exec.  Does not return on success.
 * All functions called here must be async-signal-safe or safe
 * in a post-fork child (no malloc, no syslog).
 */
static void __dead2
child_exec(struct svc_manifest *m, int child_pair_fd,
    int *token_fds, unsigned ntokens,
    uid_t uid, gid_t gid, bool have_creds, const char *homedir)
{
	char pair_env[64], token_env[256], label_env[128];
	char user_env[128], home_env[PATH_MAX + 8];
	char fds_str[128];
	char *env[SVC_MAX_ENV];
	char *argv[2];
	int nullfd, fd;
	unsigned i, envc;

	/* Redirect stdio to /dev/null. */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd == -1)
		_exit(126);
	if (dup2(nullfd, STDIN_FILENO) == -1 ||
	    dup2(nullfd, STDOUT_FILENO) == -1 ||
	    dup2(nullfd, STDERR_FILENO) == -1)
		_exit(126);
	if (nullfd > STDERR_FILENO)
		(void)close(nullfd);

	/* Place pair channel at well-known fd 3. */
	if (child_pair_fd != SVC_PAIR_FD) {
		if (dup2(child_pair_fd, SVC_PAIR_FD) == -1)
			_exit(126);
		(void)close(child_pair_fd);
	}

	/* Place token fds at 4..N. */
	for (i = 0; i < ntokens; i++) {
		fd = (int)(SVC_TOKEN_BASE + i);
		if (token_fds[i] != fd) {
			if (dup2(token_fds[i], fd) == -1)
				_exit(126);
			(void)close(token_fds[i]);
		}
	}

	/* Close everything above our fds. */
	closefrom(SVC_TOKEN_BASE + (int)ntokens);

	/* Clear close-on-exec for the fds we keep. */
	if (fcntl(SVC_PAIR_FD, F_SETFD, 0) == -1)
		_exit(126);
	for (i = 0; i < ntokens; i++) {
		if (fcntl(SVC_TOKEN_BASE + (int)i, F_SETFD, 0) == -1)
			_exit(126);
	}

	/* Build minimal environment. */
	envc = 0;
	env[envc++] = __DECONST(char *,
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

	(void)snprintf(pair_env, sizeof(pair_env),
	    "ORACLED_PAIR_FD=%d", SVC_PAIR_FD);
	env[envc++] = pair_env;

	if (ntokens > 0) {
		build_token_fds_str(fds_str, sizeof(fds_str), ntokens);
		(void)snprintf(token_env, sizeof(token_env),
		    "ORACLED_TOKEN_FDS=%s", fds_str);
		env[envc++] = token_env;
	}

	(void)snprintf(label_env, sizeof(label_env),
	    "ORACLED_LABEL=%s", m->label);
	env[envc++] = label_env;

	if (m->user[0] != '\0') {
		(void)snprintf(user_env, sizeof(user_env),
		    "USER=%s", m->user);
		env[envc++] = user_env;
		(void)snprintf(home_env, sizeof(home_env),
		    "HOME=%s", homedir != NULL ? homedir : "/var/empty");
		env[envc++] = home_env;
	}

	env[envc] = NULL;

	/* Set credentials if specified.  Failures are fatal — running
	 * as root when the manifest requested an unprivileged user
	 * is a privilege escalation.  Always drop group before user;
	 * if only user is set, gid comes from the user's passwd entry. */
	if (have_creds) {
		if (initgroups(m->user[0] != '\0' ? m->user : "nobody",
		    gid) == -1)
			_exit(126);
		if (setgid(gid) == -1)
			_exit(126);
		if (setuid(uid) == -1)
			_exit(126);
	}

	/* Reset signal dispositions. */
	for (i = 1; i < NSIG; i++)
		(void)signal(i, SIG_DFL);

	/* Exec. */
	argv[0] = strrchr(m->program, '/');
	if (argv[0] != NULL)
		argv[0]++;
	else
		argv[0] = m->program;
	argv[1] = NULL;

	execve(m->program, argv, env);
	_exit(127);
}

int
svc_exec(struct svc_runtime *svc, int kq)
{
	struct svc_manifest *m;
	struct kevent kev[3];
	struct passwd *pw;
	struct group *gr;
	char homedir[PATH_MAX];
	int oracle_end, child_end, coalition_fd;
	int token_fds[SVC_MAX_TOKENS];
	unsigned ntokens;
	uid_t uid;
	gid_t gid;
	bool have_creds;
	pid_t pid;
	int pd_fd;
	unsigned i;

	m = &svc->manifest;

	if (svc->state != SVC_STATE_STOPPED) {
		syslog(LOG_WARNING, "svc_exec %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}

	/* Test mode: validate but don't fork. */
	if (od.test_mode) {
		syslog(LOG_INFO, "service %s: test mode, skipping exec",
		    m->label);
		return (0);
	}

	if (access(m->program, X_OK) != 0) {
		syslog(LOG_ERR, "svc_exec %s: %s not executable: %m",
		    m->label, m->program);
		return (-1);
	}

	/* Resolve credentials before fork. */
	uid = 0;
	gid = 0;
	have_creds = false;
	homedir[0] = '\0';
	if (m->user[0] != '\0') {
		pw = getpwnam(m->user);
		if (pw == NULL) {
			syslog(LOG_ERR, "svc_exec %s: unknown user: %s",
			    m->label, m->user);
			return (-1);
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		strlcpy(homedir, pw->pw_dir, sizeof(homedir));
		have_creds = true;
	}
	if (m->group[0] != '\0') {
		gr = getgrnam(m->group);
		if (gr == NULL) {
			syslog(LOG_ERR, "svc_exec %s: unknown group: %s",
			    m->label, m->group);
			return (-1);
		}
		gid = gr->gr_gid;
		have_creds = true;
		if (m->user[0] == '\0') {
			pw = getpwnam("nobody");
			if (pw == NULL) {
				syslog(LOG_ERR, "svc_exec %s: group-only "
				    "manifest requires user nobody",
				    m->label);
				return (-1);
			}
			uid = pw->pw_uid;
			strlcpy(homedir, pw->pw_dir, sizeof(homedir));
		}
	}

	if (m->jail[0] != '\0')
		syslog(LOG_WARNING, "svc_exec %s: jail '%s' requested "
		    "but jail support not yet implemented",
		    m->label, m->jail);

	/* Create pair channel. */
	if (cap_rt_create_pair(&oracle_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create pair",
		    m->label);
		return (-1);
	}

	/* Create coalition. */
	coalition_fd = cap_rt_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_WARNING, "svc_exec %s: failed to create coalition",
		    m->label);
		/* Continue without coalition — not fatal. */
	}

	/* Mint tokens. */
	ntokens = 0;
	for (i = 0; i < m->ncap_paths; i++) {
		int tfd = cap_rt_mint_path_token(m->cap_paths[i]);
		if (tfd == -1) {
			syslog(LOG_WARNING, "svc_exec %s: failed to mint "
			    "token for %s", m->label, m->cap_paths[i]);
			continue;
		}
		token_fds[ntokens++] = tfd;
	}
	if (m->ncap_net > 0) {
		int tfd = cap_rt_mint_net_token();
		if (tfd == -1)
			syslog(LOG_WARNING, "svc_exec %s: failed to mint "
			    "network token", m->label);
		else
			token_fds[ntokens++] = tfd;
	}
	if (m->cap_system != 0) {
		int tfd = cap_rt_mint_system_token(m->cap_system);
		if (tfd == -1)
			syslog(LOG_WARNING, "svc_exec %s: failed to mint "
			    "system token", m->label);
		else
			token_fds[ntokens++] = tfd;
	}

	if (ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens",
		    m->label, ntokens);

	/* Fork via pdfork for process descriptor. */
	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "svc_exec %s: pdfork: %m", m->label);
		close(oracle_end);
		close(child_end);
		if (coalition_fd >= 0)
			close(coalition_fd);
		for (i = 0; i < ntokens; i++)
			close(token_fds[i]);
		return (-1);
	}

	if (pid == 0) {
		/* Child — does not return. */
		child_exec(m, child_end, token_fds, ntokens,
		    uid, gid, have_creds,
		    homedir[0] != '\0' ? homedir : NULL);
		/* NOTREACHED */
	}

	/* Parent. */
	close(child_end);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);

	/* Enlist in coalition and set as leader. */
	if (coalition_fd >= 0) {
		if (cap_rt_coalition_enlist(coalition_fd, pd_fd) != 0)
			syslog(LOG_WARNING, "svc_exec %s: coalition "
			    "enlist: %m", m->label);
		if (cap_rt_coalition_set_leader(coalition_fd, pd_fd) != 0)
			syslog(LOG_WARNING, "svc_exec %s: coalition "
			    "set_leader: %m", m->label);
	}

	/* Store state. */
	svc->pid = pid;
	svc->pd_fd = pd_fd;
	svc->pair_fd = oracle_end;
	svc->coalition_fd = coalition_fd;
	svc->state = SVC_STATE_STARTING;
	clock_gettime(CLOCK_MONOTONIC, &svc->last_start);

	/* Register on kqueue. */
	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT | NOTE_EXEC, 0, svc);
	EV_SET(&kev[1], oracle_end, EVFILT_READ, EV_ADD, 0, 0, svc);
	if (coalition_fd >= 0)
		EV_SET(&kev[2], coalition_fd, EVFILT_READ, EV_ADD, 0, 0,
		    svc);

	if (kevent(kq, kev, coalition_fd >= 0 ? 3 : 2, NULL, 0, NULL) ==
	    -1) {
		syslog(LOG_ERR, "svc_exec %s: kevent register: %m",
		    m->label);
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		close(svc->pd_fd); svc->pd_fd = -1;
		close(svc->pair_fd); svc->pair_fd = -1;
		if (svc->coalition_fd >= 0) {
			close(svc->coalition_fd);
			svc->coalition_fd = -1;
		}
		svc->state = SVC_STATE_STOPPED;
		return (-1);
	}

	syslog(LOG_INFO, "service %s: started pid %jd",
	    m->label, (intmax_t)pid);
	ORACLED_PROBE_SVC_START(m->label, pid);
	return (0);
}

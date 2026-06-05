/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service fork/exec for serviced.
 *
 * Creates a pair channel, mints capability tokens, pdfork()s a
 * child, scrubs its environment and fds, sets credentials, and
 * exec()s the program from the manifest.  Registers the process
 * descriptor and pair channel on the kqueue for supervision.
 *
 * Unlike oracled, serviced does not hold /dev/cap_rt directly.
 * Pair and coalition creation use the delegated cap_rt fd
 * (caprt_direct.c).  Token minting goes through the oracle
 * pair channel (oracle_client.c).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/jail.h>
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
#include <time.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_probes.h"

#define	SVC_PAIR_FD	3	/* well-known fd for the pair channel */
#define	SVC_TOKEN_BASE	4	/* tokens start at fd 4 */
#define	SVC_MAX_TOKENS	(SERVICED_MAX_CAP_PATHS + SERVICED_MAX_CAP_FILES + \
			    SERVICED_MAX_CAP_NET + SERVICED_MAX_CAP_JAIL + 1)
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
    int *token_fds, unsigned ntokens, int jail_fd,
    uid_t uid, gid_t gid, bool have_creds, const char *homedir,
    gid_t *groups, int ngroups)
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

	/*
	 * Remap fds into their well-known positions.  First move all
	 * source fds above the reserved range to avoid clobbering a
	 * source fd that occupies a target slot (e.g., child_pair_fd
	 * could be 4 which is SVC_TOKEN_BASE, or token_fds[0] could
	 * be 3 which is SVC_PAIR_FD).
	 */
	{
		int safe_base;

		safe_base = SVC_TOKEN_BASE + (int)ntokens + 1;
		if (child_pair_fd < safe_base) {
			fd = fcntl(child_pair_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(child_pair_fd);
			child_pair_fd = fd;
		}
		for (i = 0; i < ntokens; i++) {
			if (token_fds[i] < safe_base) {
				fd = fcntl(token_fds[i], F_DUPFD, safe_base);
				if (fd == -1)
					_exit(126);
				(void)close(token_fds[i]);
				token_fds[i] = fd;
			}
		}
	}

	/* Now safe to map into final positions. */
	if (dup2(child_pair_fd, SVC_PAIR_FD) == -1)
		_exit(126);
	(void)close(child_pair_fd);

	for (i = 0; i < ntokens; i++) {
		fd = (int)(SVC_TOKEN_BASE + i);
		if (dup2(token_fds[i], fd) == -1)
			_exit(126);
		(void)close(token_fds[i]);
	}

	/* Attach to jail descriptor before closefrom() destroys it.
	 * Must also happen before credential drop since jail_attach_jd
	 * requires root. */
	if (jail_fd >= 0) {
		if (jail_attach_jd(jail_fd) == -1)
			_exit(126);
		(void)close(jail_fd);
		jail_fd = -1;
	}

	closefrom(SVC_TOKEN_BASE + (int)ntokens);

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
		if (setgroups(ngroups, groups) == -1)
			_exit(126);
		if (setgid(gid) == -1)
			_exit(126);
		if (setuid(uid) == -1)
			_exit(126);
	}

	/* Reset signal dispositions and unblock all signals. */
	for (i = 1; i < NSIG; i++)
		(void)signal(i, SIG_DFL);
	{
		sigset_t emptyset;
		sigemptyset(&emptyset);
		(void)sigprocmask(SIG_SETMASK, &emptyset, NULL);
	}

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
	struct timespec exec_start;
	char homedir[PATH_MAX];
	int oracle_end, child_end, coalition_fd;
	int token_fds[SVC_MAX_TOKENS];
	unsigned ntokens;
	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	bool have_creds;
	pid_t pid;
	int pd_fd;
	unsigned i;

	m = &svc->manifest;
	clock_gettime(CLOCK_MONOTONIC, &exec_start);

	if (svc->state != SVC_STATE_STOPPED) {
		syslog(LOG_WARNING, "svc_exec %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}

	if (access(m->program, X_OK) != 0) {
		syslog(LOG_ERR, "svc_exec %s: %s not executable: %m",
		    m->label, m->program);
		return (-1);
	}

	/* Resolve credentials before fork. */
	uid = 0;
	gid = 0;
	ngroups = 0;
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

	/* Build supplementary group list in the parent (async-signal-safe
	 * setgroups() is used in the child instead of initgroups()). */
	if (have_creds) {
		ngroups = NGROUPS_MAX + 1;
		if (getgrouplist(m->user[0] != '\0' ? m->user : "nobody",
		    gid, groups, &ngroups) == -1) {
			syslog(LOG_ERR, "svc_exec %s: getgrouplist: %m",
			    m->label);
			return (-1);
		}
	}

	/* Create pair channel via oracle. */
	if (caprt_create_pair(
	    &oracle_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create pair",
		    m->label);
		SERVICED_PROBE_CAP_PAIR(m->label, -1);
		return (-1);
	}
	SERVICED_PROBE_CAP_PAIR(m->label, 0);

	/* Create coalition via oracle. */
	coalition_fd = caprt_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create coalition",
		    m->label);
		SERVICED_PROBE_CAP_COALITION(m->label, -1);
		close(oracle_end);
		close(child_end);
		return (-1);
	}
	SERVICED_PROBE_CAP_COALITION(m->label, 0);

	/* Mint tokens via oracle. */
	ntokens = 0;
	for (i = 0; i < m->ncap_paths; i++) {
		int tfd = oracle_mint_path(sd.oracle_pair_fd,
		    m->cap_paths[i]);
		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "token for %s", m->label, m->cap_paths[i]);
			SERVICED_PROBE_CAP_MINT(m->label, "path", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "path", 0);
		token_fds[ntokens++] = tfd;
	}
	for (i = 0; i < m->ncap_files; i++) {
		int tfd = oracle_mint_file(sd.oracle_pair_fd,
		    m->cap_files[i].path, m->cap_files[i].actions);
		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "file token for %s", m->label,
			    m->cap_files[i].path);
			SERVICED_PROBE_CAP_MINT(m->label, "file", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "file", 0);
		token_fds[ntokens++] = tfd;
	}
	for (i = 0; i < m->ncap_net; i++) {
		int tfd = oracle_mint_net(sd.oracle_pair_fd, &m->cap_net[i]);
		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "network token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "net", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "net", 0);
		token_fds[ntokens++] = tfd;
	}
	for (i = 0; i < m->ncap_jail; i++) {
		int tfd = oracle_mint_jail(sd.oracle_pair_fd,
		    &m->cap_jail[i]);
		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "jail token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "jail", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "jail", 0);
		token_fds[ntokens++] = tfd;
	}
	if (m->cap_system != 0) {
		int tfd = oracle_mint_system(sd.oracle_pair_fd,
		    m->cap_system);
		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "system token", m->label);
			SERVICED_PROBE_CAP_MINT(m->label, "system", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "system", 0);
		token_fds[ntokens++] = tfd;
	}

	if (ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens",
		    m->label, ntokens);

	/* Create jail via oracle if manifest specifies one. */
	svc->jail_fd = -1;
	if (m->has_jail) {
		svc->jail_fd = oracle_create_jail(sd.oracle_pair_fd,
		    m->jail_name, m->jail_path,
		    m->jail_hostname, m->jail_ip4_addr);
		if (svc->jail_fd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to create jail %s: %m",
			    m->label, m->jail_name);
			SERVICED_PROBE_CAP_MINT(m->label, "jail-create", -1);
			goto fail_tokens;
		}
		syslog(LOG_INFO, "svc_exec %s: created jail %s jd=%d",
		    m->label, m->jail_name, svc->jail_fd);
		SERVICED_PROBE_CAP_MINT(m->label, "jail-create", 0);
	}

	/* Fork via pdfork for process descriptor. */
	pid = pdfork(&pd_fd, PD_CLOEXEC);
	if (pid == -1) {
		syslog(LOG_ERR, "svc_exec %s: pdfork: %m", m->label);
		goto fail_tokens;
	}

	if (pid == 0) {
		/* Child — does not return. */
		child_exec(m, child_end, token_fds, ntokens,
		    svc->jail_fd,
		    uid, gid, have_creds,
		    homedir[0] != '\0' ? homedir : NULL,
		    groups, ngroups);
		/* NOTREACHED */
	}

	/* Parent. */
	close(child_end);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);

	/* Enlist in coalition and set as leader. */
	if (caprt_coalition_enlist(coalition_fd, pd_fd) != 0) {
		syslog(LOG_ERR, "svc_exec %s: coalition enlist: %m",
		    m->label);
		goto fail_postfork;
	}
	if (caprt_coalition_set_leader(coalition_fd, pd_fd) != 0) {
		syslog(LOG_ERR, "svc_exec %s: coalition set_leader: %m",
		    m->label);
		goto fail_postfork;
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
	EV_SET(&kev[2], coalition_fd, EVFILT_READ, EV_ADD, 0, 0, svc);

	if (kevent(kq, kev, 3, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "svc_exec %s: kevent register: %m",
		    m->label);
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		close(svc->pd_fd);
		svc->pd_fd = -1;
		close(svc->pair_fd);
		svc->pair_fd = -1;
		close(svc->coalition_fd);
		svc->coalition_fd = -1;
		if (svc->jail_fd >= 0) {
			jail_remove_jd(svc->jail_fd);
			close(svc->jail_fd);
			svc->jail_fd = -1;
		}
		svc->pid = 0;
		svc->state = SVC_STATE_STOPPED;
		return (-1);
	}

	syslog(LOG_INFO, "service %s: started pid %jd",
	    m->label, (intmax_t)pid);
	SERVICED_PROBE_SVC_START(m->label, pid);

	{
		struct timespec exec_end;
		uint64_t dur;

		clock_gettime(CLOCK_MONOTONIC, &exec_end);
		dur = (uint64_t)(exec_end.tv_sec - exec_start.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(exec_end.tv_nsec - exec_start.tv_nsec);
		SERVICED_PROBE_SVC_EXEC_DONE(m->label, dur, ntokens);
	}
	return (0);

fail_postfork:
	/* child_end and token_fds already closed by parent path above. */
	SERVICED_PROBE_SVC_EXEC_FAIL(m->label, errno);
	pdkill(pd_fd, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	close(pd_fd);
	close(oracle_end);
	close(coalition_fd);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);

fail_tokens:
	close(oracle_end);
	close(child_end);
	close(coalition_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);
}

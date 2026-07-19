/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service fork/exec for serviced.
 *
 * Creates a channel, mints capability tokens, pdfork()s a
 * child, scrubs its environment and fds, sets credentials, and
 * exec()s the program from the manifest.  Registers the process
 * descriptor and channel on the kqueue for supervision.
 *
 * Unlike oracled, serviced does not hold /dev/mac_capability directly.
 * Channel and coalition creation use the delegated mac_capability fd
 * (mac_cap_direct.c).  Token minting goes through the oracle
 * channel (oracle_client.c).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
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
#include "serviced_audit.h"
#include "serviced_probes.h"

#define	SVC_CHANNEL_FD	3	/* well-known fd for the channel */
#define	SVC_CAPPROTECT_FD	4	/* capprotect service instance */
#define	SVC_TOKEN_BASE	5	/* tokens start after service plumbing */
#define	SVC_MAX_TOKENS	(SERVICED_MAX_CAP_PATHS + SERVICED_MAX_CAP_FILES + \
				    SERVICED_MAX_CAP_NET + SERVICED_MAX_CAP_JAIL + 1)
#define	SVC_MAX_ENV	16

/*
 * Worst-case size of the comma-separated ORACLED_TOKEN_FDS list: every
 * token contributes a decimal fd number (up to 10 digits for INT_MAX) plus
 * a separator, and one trailing NUL.  Sizing from SVC_MAX_TOKENS ensures a
 * fully-populated manifest never truncates the list (which would silently
 * strip capabilities from, or mis-number a token for, the child).
 */
#define	SVC_TOKEN_FDS_STRLEN	(SVC_MAX_TOKENS * 12 + 1)

/*
 * Build the token fd list string for ORACLED_TOKEN_FDS env var.
 * Format: "5,6,7" (comma-separated).
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
child_exec(struct svc_manifest *m, int child_channel_fd,
    int capprotect_fd, int *token_fds, unsigned ntokens, int jail_fd,
    uid_t uid, gid_t gid, bool have_creds, const char *homedir,
    gid_t *groups, int ngroups)
{
	char channel_env[64], capprotect_env[64], label_env[128];
	char token_env[SVC_TOKEN_FDS_STRLEN + sizeof("ORACLED_TOKEN_FDS=")];
	char user_env[128], home_env[PATH_MAX + 8];
	char fds_str[SVC_TOKEN_FDS_STRLEN];
	char *env[SVC_MAX_ENV];
	char *argv[2];
	int nullfd, fd;
	bool have_capprotect;
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
	 * source fd that occupies a target slot (e.g., child_channel_fd
	 * could be 5 which is SVC_TOKEN_BASE, or token_fds[0] could
	 * be 3 which is SVC_CHANNEL_FD).
	 */
	{
		int safe_base;

		safe_base = SVC_TOKEN_BASE + (int)ntokens + 1;
		if (child_channel_fd < safe_base) {
			fd = fcntl(child_channel_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(child_channel_fd);
			child_channel_fd = fd;
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
		if (capprotect_fd >= 0 && capprotect_fd < safe_base) {
			fd = fcntl(capprotect_fd, F_DUPFD, safe_base);
			if (fd == -1)
				_exit(126);
			(void)close(capprotect_fd);
			capprotect_fd = fd;
		}
	}

	/* Now safe to map into final positions. */
	if (dup2(child_channel_fd, SVC_CHANNEL_FD) == -1)
		_exit(126);
	(void)close(child_channel_fd);
	have_capprotect = capprotect_fd >= 0;
	if (capprotect_fd >= 0) {
		if (dup2(capprotect_fd, SVC_CAPPROTECT_FD) == -1)
			_exit(126);
		(void)close(capprotect_fd);
		capprotect_fd = SVC_CAPPROTECT_FD;
	} else {
		/*
		 * No capprotect instance for this service.  closefrom() below
		 * starts at the first token slot, so nothing else scrubs the
		 * reserved capprotect slot — close it explicitly so no fd the
		 * child happened to inherit at fd 4 survives into execve().
		 */
		(void)close(SVC_CAPPROTECT_FD);
	}

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

	if (fcntl(SVC_CHANNEL_FD, F_SETFD, 0) == -1)
		_exit(126);
	if (have_capprotect && fcntl(SVC_CAPPROTECT_FD, F_SETFD, 0) == -1)
		_exit(126);
	for (i = 0; i < ntokens; i++) {
		if (fcntl(SVC_TOKEN_BASE + (int)i, F_SETFD, 0) == -1)
			_exit(126);
	}

	/* Build minimal environment. */
	envc = 0;
	env[envc++] = __DECONST(char *,
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

	(void)snprintf(channel_env, sizeof(channel_env),
	    "ORACLED_CHANNEL_FD=%d", SVC_CHANNEL_FD);
	env[envc++] = channel_env;
	if (have_capprotect) {
		(void)snprintf(capprotect_env, sizeof(capprotect_env),
		    "ORACLED_CAPPROTECT_FD=%d", SVC_CAPPROTECT_FD);
		env[envc++] = capprotect_env;
	}

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
	struct svc_manifest minted_manifest;
	int oracle_end, child_end, coalition_fd, capprotect_fd;
	int token_fds[SVC_MAX_TOKENS];
	unsigned ntokens;
	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX + 1];
	int ngroups;
	bool have_creds;
	pid_t pid;
	int pd_fd;
	int saved_errno __unused = 0;	/* consumed only by the DTrace probe */
	unsigned expected_tokens, i;

	m = &svc->manifest;
	memset(&minted_manifest, 0, sizeof(minted_manifest));
	strlcpy(minted_manifest.label, m->label, sizeof(minted_manifest.label));
	clock_gettime(CLOCK_MONOTONIC, &exec_start);

	if (svc->state != SVC_STATE_STOPPED) {
		syslog(LOG_WARNING, "svc_exec %s: not stopped (state %d)",
		    m->label, svc->state);
		return (-1);
	}

	if (m->program[0] != '/') {
		syslog(LOG_ERR, "svc_exec %s: program must be absolute: %s",
		    m->label, m->program);
		return (-1);
	}
	if (strstr(m->program, "/../") != NULL ||
	    strstr(m->program, "/..") == m->program + strlen(m->program) - 3) {
		syslog(LOG_ERR, "svc_exec %s: path traversal in program: %s",
		    m->label, m->program);
		return (-1);
	}
	if (access(m->program, X_OK) != 0) {
		syslog(LOG_ERR, "svc_exec %s: %s not executable: %m",
		    m->label, m->program);
		return (-1);
	}

	/*
	 * One token is delivered for every path, file, network, and jail
	 * capability.  System gates are deliberately combined into one token.
	 * Check the total before acquiring any launch resources so a malformed
	 * manifest can never overrun token_fds[] or reach pdfork() partially
	 * provisioned.
	 */
	if (m->ncap_paths > SERVICED_MAX_CAP_PATHS ||
	    m->ncap_files > SERVICED_MAX_CAP_FILES ||
	    m->ncap_net > SERVICED_MAX_CAP_NET ||
	    m->ncap_jail > SERVICED_MAX_CAP_JAIL) {
		syslog(LOG_ERR, "svc_exec %s: invalid capability counts",
		    m->label);
		return (-1);
	}
	expected_tokens = m->ncap_paths + m->ncap_files + m->ncap_net +
	    m->ncap_jail + (m->cap_system != 0 ? 1u : 0u);
	if (expected_tokens > SVC_MAX_TOKENS) {
		syslog(LOG_ERR, "svc_exec %s: too many capability tokens: %u",
		    m->label, expected_tokens);
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

	capprotect_fd = -1;
	svc->jail_fd = -1;

	/* Ensure required kernel modules are loaded before launch. */
	if (m->nkmod_requires > 0) {
		if (kldmgr_ensure_loaded(m,
		    bundle_registry_is_system(svc->bundle_idx), kq) != 0) {
			syslog(LOG_ERR, "svc_exec %s: kmod_requires failed",
			    m->label);
			return (-1);
		}
	}

	/* Create channel via oracle. */
	if (mac_cap_create_channel(
	    &oracle_end, &child_end) == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create channel",
		    m->label);
		SERVICED_PROBE_CAP_CHANNEL(m->label, -1);
		return (-1);
	}
	if (cap_xfer_limit(oracle_end, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(child_end, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: channel confinement: %m",
		    m->label);
		close(oracle_end);
		close(child_end);
		return (-1);
	}
	SERVICED_PROBE_CAP_CHANNEL(m->label, 0);

	/* Create coalition via oracle. */
	coalition_fd = mac_cap_create_coalition();
	if (coalition_fd == -1) {
		syslog(LOG_ERR, "svc_exec %s: failed to create coalition",
		    m->label);
		SERVICED_PROBE_CAP_COALITION(m->label, -1);
		close(oracle_end);
		close(child_end);
		return (-1);
	}
	if (cap_xfer_limit(coalition_fd, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: coalition confinement: %m",
		    m->label);
		close(oracle_end);
		close(child_end);
		close(coalition_fd);
		return (-1);
	}
	SERVICED_PROBE_CAP_COALITION(m->label, 0);

	capprotect_fd = mac_cap_mint_capprotect();
	if (capprotect_fd == -1 && errno != ENOTSUP) {
		syslog(LOG_WARNING, "svc_exec %s: capprotect mint: %m",
		    m->label);
	}
	if (capprotect_fd >= 0 &&
	    cap_xfer_limit(capprotect_fd, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "svc_exec %s: capprotect confinement: %m",
		    m->label);
		close(oracle_end);
		close(child_end);
		close(coalition_fd);
		close(capprotect_fd);
		return (-1);
	}

	/*
	 * Mint tokens via oracle.  The oracle auto-claims resources
	 * not already in its manifest — one trip per token.
	 *
	 * Each mint is a synchronous RPC with SERVICED_RPC_TIMEOUT_MS
	 * timeout.  Track total elapsed time and abort if the mint
	 * phase exceeds SVC_MINT_DEADLINE_MS to avoid blocking the
	 * event loop for an unbounded duration.
	 */
#define	SVC_MINT_DEADLINE_MS	2000	/* max total mint phase */
	{
	struct timespec mint_start, mint_now;
	uint64_t elapsed_ms;

	clock_gettime(CLOCK_MONOTONIC, &mint_start);
	ntokens = 0;

#define	MINT_CHECK_DEADLINE() do {					\
	clock_gettime(CLOCK_MONOTONIC, &mint_now);			\
	elapsed_ms = (uint64_t)(mint_now.tv_sec - mint_start.tv_sec) *	\
	    1000;							\
	if (mint_now.tv_nsec >= mint_start.tv_nsec) {			\
		elapsed_ms +=						\
		    (uint64_t)(mint_now.tv_nsec - mint_start.tv_nsec) /	\
		    1000000;						\
	} else {							\
		elapsed_ms -= 1000;					\
		elapsed_ms +=						\
		    (uint64_t)(1000000000L + mint_now.tv_nsec -		\
		    mint_start.tv_nsec) / 1000000;			\
	}								\
	if (elapsed_ms > SVC_MINT_DEADLINE_MS) {			\
		syslog(LOG_ERR, "svc_exec %s: mint deadline exceeded "	\
		    "(%ju ms, %u/%u tokens)", m->label,			\
		    (uintmax_t)elapsed_ms, ntokens, expected_tokens);	\
		goto fail_tokens;					\
	}								\
} while (0)

	for (i = 0; i < m->ncap_paths; i++) {
		int tfd = oracle_mint_path(sd.oracle_channel_fd,
		    m->cap_paths[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "token for %s", m->label, m->cap_paths[i]);
			SERVICED_PROBE_CAP_MINT(m->label, "path", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "path", 0);
		token_fds[ntokens++] = tfd;
		strlcpy(minted_manifest.cap_paths[
		    minted_manifest.ncap_paths++], m->cap_paths[i],
		    PATH_MAX);
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_files; i++) {
		int tfd = oracle_mint_file(sd.oracle_channel_fd,
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
		minted_manifest.cap_files[minted_manifest.ncap_files++] =
		    m->cap_files[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_net; i++) {
		int tfd = oracle_mint_net(sd.oracle_channel_fd, &m->cap_net[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "network token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "net", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "net", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_net[minted_manifest.ncap_net++] =
		    m->cap_net[i];
		MINT_CHECK_DEADLINE();
	}
	for (i = 0; i < m->ncap_jail; i++) {
		int tfd = oracle_mint_jail(sd.oracle_channel_fd,
		    &m->cap_jail[i]);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "jail token %u", m->label, i);
			SERVICED_PROBE_CAP_MINT(m->label, "jail", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "jail", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_jail[minted_manifest.ncap_jail++] =
		    m->cap_jail[i];
		MINT_CHECK_DEADLINE();
	}
	if (m->cap_system != 0) {
		int tfd = oracle_mint_system(sd.oracle_channel_fd,
		    m->cap_system);

		if (tfd == -1) {
			syslog(LOG_ERR, "svc_exec %s: failed to mint "
			    "system token", m->label);
			SERVICED_PROBE_CAP_MINT(m->label, "system", -1);
			goto fail_tokens;
		}
		SERVICED_PROBE_CAP_MINT(m->label, "system", 0);
		token_fds[ntokens++] = tfd;
		minted_manifest.cap_system = m->cap_system;
	}

#undef MINT_CHECK_DEADLINE
	}

	/*
	 * This is the final all-or-nothing barrier before jail creation and
	 * pdfork().  The child receives only the complete manifest token set;
	 * any missing token takes the fail_tokens cleanup path instead.
	 */
	if (ntokens != expected_tokens) {
		syslog(LOG_ERR, "svc_exec %s: incomplete capability set "
		    "(%u/%u tokens)", m->label, ntokens, expected_tokens);
		goto fail_tokens;
	}

	if (ntokens > 0)
		syslog(LOG_DEBUG, "svc_exec %s: minted %u tokens",
		    m->label, ntokens);

	/* Create jail via oracle if manifest specifies one. */
	if (m->has_jail) {
		svc->jail_fd = oracle_create_jail(sd.oracle_channel_fd,
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
			child_exec(m, child_end, capprotect_fd, token_fds, ntokens,
			    svc->jail_fd,
		    uid, gid, have_creds,
		    homedir[0] != '\0' ? homedir : NULL,
		    groups, ngroups);
		/* NOTREACHED */
	}

	/* Parent. */
	close(child_end);
	if (capprotect_fd >= 0) {
		close(capprotect_fd);
		capprotect_fd = -1;
	}
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	if (svc->jail_fd >= 0 &&
	    (cap_xfer_limit(svc->jail_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(svc->jail_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(svc->jail_fd, CAP_CLOEXEC_LOCKED) == -1)) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: jail fd confinement: %m",
		    m->label);
		goto fail_postfork;
	}

	/* Enlist in coalition and set as leader. */
	if (mac_cap_coalition_enlist(coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition enlist: %m",
		    m->label);
		goto fail_postfork;
	}
	if (mac_cap_coalition_set_leader(coalition_fd, pd_fd) != 0) {
		saved_errno = errno;
		syslog(LOG_ERR, "svc_exec %s: coalition set_leader: %m",
		    m->label);
		goto fail_postfork;
	}

	/* Freeze all supervisor-owned authority before another service fork. */
	{
		cap_rights_t rights;

		cap_rights_init(&rights, CAP_PDKILL, CAP_EVENT);
		if (cap_rights_limit(pd_fd, &rights) == -1 ||
		    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
		    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(oracle_end, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(oracle_end, CAP_CLOEXEC_LOCKED) == -1 ||
		    cap_clofork_limit(coalition_fd, CAP_CLOFORK_LOCKED) == -1 ||
		    cap_cloexec_limit(coalition_fd, CAP_CLOEXEC_LOCKED) == -1) {
			saved_errno = errno;
			syslog(LOG_ERR,
			    "svc_exec %s: supervisor fd confinement: %m",
			    m->label);
			goto fail_postfork;
		}
	}

	/* Store state. */
	svc->pid = pid;
	svc->pd_fd = pd_fd;
	svc->channel_fd = oracle_end;
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
		oracle_release_manifest(sd.oracle_channel_fd,
		    &minted_manifest);
		close(svc->pd_fd);
		svc->pd_fd = -1;
		close(svc->channel_fd);
		svc->channel_fd = -1;
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

	/*
	 * Audit the launch.  Executing a service under changed credentials is
	 * a security-relevant transition, so record the resulting principal
	 * (uid/gid) and pid in the trusted audit trail, not just via DTrace.
	 */
	serviced_audit(AUE_SERVICED_SVC_EXEC, getuid(), 0,
	    "svc=%s pid=%jd uid=%u gid=%u creds_changed=%d",
	    m->label, (intmax_t)pid, (unsigned)uid, (unsigned)gid,
	    have_creds ? 1 : 0);

	{
		struct timespec exec_end;
		uint64_t dur __unused;

		clock_gettime(CLOCK_MONOTONIC, &exec_end);
		dur = (uint64_t)(exec_end.tv_sec - exec_start.tv_sec) *
		    1000000000ULL +
		    (uint64_t)(exec_end.tv_nsec - exec_start.tv_nsec);
		SERVICED_PROBE_SVC_EXEC_DONE(m->label, dur, ntokens);
	}
	return (0);

fail_postfork:
	/* child_end and token_fds already closed by parent path above.
	 * Report the errno captured at the failure site: the intervening
	 * syslog() and the cleanup syscalls below can clobber errno. */
	SERVICED_PROBE_SVC_EXEC_FAIL(m->label, saved_errno);
	pdkill(pd_fd, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	oracle_release_manifest(sd.oracle_channel_fd, &minted_manifest);
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
	/*
	 * Capability minting is the core privilege primitive; record mint
	 * failures in the audit trail.  errno is unreliable here (the mint
	 * call sites log via syslog before jumping), so report the failure
	 * generically and rely on the text token for detail.
	 */
	serviced_audit(AUE_SERVICED_CAP_MINT, getuid(), EIO,
	    "svc=%s capability mint failed after %u tokens", m->label, ntokens);
	oracle_release_manifest(sd.oracle_channel_fd, &minted_manifest);
	close(oracle_end);
	close(child_end);
	close(coalition_fd);
	if (capprotect_fd >= 0)
		close(capprotect_fd);
	for (i = 0; i < ntokens; i++)
		close(token_fds[i]);
	if (svc->jail_fd >= 0) {
		jail_remove_jd(svc->jail_fd);
		close(svc->jail_fd);
		svc->jail_fd = -1;
	}
	return (-1);
}

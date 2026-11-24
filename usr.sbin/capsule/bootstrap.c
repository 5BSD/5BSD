/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Bootstrap supervisor for switchboard.
 *
 * Capsule starts switchboard as its single child via pdfork().
 * The child inherits one end of a mac_capability channel on fd 3.  Capsule
 * monitors the process descriptor and restarts switchboard on crash
 * with exponential backoff.
 *
 * Every start hands SwitchBoard its own authority issuer (see "PID 1's
 * authority issuer" below).  Without one SwitchBoard is not started: PID 1
 * enters single-user, saying "no authority issuer".
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "capsule.h"
#include "capsule_ctl.h"	/* CTL_OP_SINGLE */
#include "capsule_daemon.h"
#include "capsule_svc_proto.h"
#include "probes.h"
#include "bootstrap_exec.h"
#include "service_bootstrap.h"

/* Restart policy constants. */
#define	BOOTSTRAP_MIN_UPTIME	5	/* seconds before reset */
#define	BOOTSTRAP_BASE_DELAY	1	/* initial restart delay (seconds) */
#define	BOOTSTRAP_MAX_DELAY	30	/* max restart delay (seconds) */
#define	BOOTSTRAP_MAX_FAILURES	10	/* circuit breaker threshold */

/*
 * Descriptors kept in reserve for issuer creates: one take makes at most two
 * (this start's, when none is held, and the next start's).
 */
#define	BOOTSTRAP_ISSUER_RESERVE	2

/* Well-known fds for switchboard. */
#define	SWITCHBOARD_CHANNEL_FD	3	/* channel to capsule */
#define	SWITCHBOARD_CHANNEL_SVC_FD	4	/* channel service instance (mintable) */
#define	SWITCHBOARD_COALITION_SVC_FD 5	/* coalition service instance (mintable) */
#define	SWITCHBOARD_CAPPROTECT_FD	6	/* capprotect service instance */
#define	SWITCHBOARD_IDENTITY_FD	7	/* identity service instance */
#define	SWITCHBOARD_AUTHORITY_FD	8
#define	SWITCHBOARD_DISCOVERY_FD	9	/* system discovery, server end */
#define	SWITCHBOARD_LAST_FD	9	/* highest well-known fd */

static struct {
	pid_t		pid;
	int		pd_fd;		/* process descriptor */
	int		channel_fd;	/* Capsule's end of channel */
	unsigned	restart_count;
	struct timespec	last_start;
	bool		started;
	uintptr_t	timer_ident;	/* kevent timer ident */
	int		issuer_next_fd;	/* the next start's issuer, held unused */
	int		issuer_next_error; /* errno of its failed create, or 0 */
	int		issuer_refused;	/* errno that refused this start, or 0 */
	/* Released for the creates in one take: Capsule's own limit never fails them. */
	int		reserve_fd[BOOTSTRAP_ISSUER_RESERVE];
	/*
	 * The system discovery channel, kept for the whole boot.  Its client
	 * end is capsule.c's ambient lookup (every getty, and each
	 * SwitchBoard's own slot); its server end goes to each SwitchBoard.
	 * Every slot names this one channel, so a restarted SwitchBoard serves
	 * the routes of processes started under the one before it.
	 */
	int		discovery_fd;	/* server end */
	bool		discovery_tried; /* created once per Capsule, or never */
	/* The boot converged (a SwitchBoard reported READY): no rc replay. */
	bool		boot_complete;
} bs = { .issuer_next_fd = -1, .discovery_fd = -1,
    .reserve_fd = { [0 ... BOOTSTRAP_ISSUER_RESERVE - 1] = -1 } };

static uintptr_t next_timer_ident = 90000;

static void	bootstrap_backoff(int kq);

/*
 * Child setup and exec for switchboard.
 * Runs in the post-fork child — async-signal-safe only.
 */
/*
 * Fds to delegate to switchboard: channel_svc (channel factory), coalition_svc
 * (coalition factory), capprotect (shield).  -1 if unavailable.
 */
struct bootstrap_delegate_fds {
	int	channel_svc_fd;
	int	coalition_svc_fd;
	int	capprotect_fd;
	int	identity_fd;
	int	authority_fd;
	int	discovery_fd;	/* dup of the discovery server end, or -1 */
	int	lookup_fd;	/* discovery client end for the slot, or -1 */
	bool	boot_complete;
	bool	rc_fastboot;	/* /etc/rc without autoboot (after single-user) */
	int	issuer_next_error;	/* the next start's issuer failed, or 0 */
	/*
	 * The managed authority, constrained to service_manager with
	 * CAP_AUTH_ROLE_CORE, that carries base exclusion across switchboard's
	 * exec (cap_process(2) BASE EXCLUSION).  -1 when none was made.
	 */
	int	core_token;
	/*
	 * The service manager's image, opened O_VERIFY: the vnode the Core
	 * authority pins.  The child executes this descriptor (fexecve), so
	 * a binary replaced on disk after the pin is never what runs.
	 */
	int	core_image;
	/*
	 * Bundle-directory overrides forwarded to switchboard.  Captured from
	 * capsule's environment in the parent (getenv is not async-signal-safe,
	 * so it must not run in the post-fork child).  NULL when unset, which
	 * is the normal production case — switchboard then uses its compiled
	 * /Capabilities defaults.  These are a live override in any environment,
	 * not test-only: whoever controls capsule's environment (root) can point
	 * switchboard's bundle scan elsewhere.  In practice only test harnesses do.
	 */
	const char	*bundle_dir_system;
	const char	*bundle_dir_user;
	const char	*run_dir;	/* SWITCHBOARD_RUN_DIR override */
	const char	*watch_settle;	/* SWITCHBOARD_REGISTRY_WATCH_SETTLE */
	/*
	 * "1" opts switchboard out of running /etc/rc.  Forwarded like the
	 * bundle-directory overrides; test harnesses must be able to start a
	 * fixture switchboard without replaying the host's rc sequence.
	 */
	const char	*skip_rc;
	/* "1" drops CP_SF_SIGKILL from switchboard's shield (test-only). */
	const char	*test_no_sigkill;
};

static void __dead2
bootstrap_child_exec(int child_channel_fd, const struct bootstrap_delegate_fds *d)
{
	char channel_env[64];
	char channel_svc_env[64], coalition_svc_env[64], capprotect_env[64];
	char identity_env[64], authority_env[64], discovery_env[64];
	char next_issuer_env[64];
	char bundle_sys_env[PATH_MAX + 32], bundle_usr_env[PATH_MAX + 32];
	char skip_rc_env[32], no_sigkill_env[40];
	char run_dir_env[PATH_MAX + 32], settle_env[64];
	char *env[20];
	char *argv[2];
	int nullfd, fd, safe_base;
	int src_fds[9], dst_fds[9], image_dst = -1;
	unsigned envc, i, nfds;

	/*
	 * First: install the Core authority while its descriptor is still
	 * here (the remapping below closes everything outside the reserved
	 * slots).  It stays pending until the execve() at the end, and
	 * nothing in between installs another.  This child of PID 1 is
	 * excluded, so switchboard's exec of the pinned image keeps it.
	 */
	if (d->core_token >= 0) {
		if (syscall(SYS_cap_process, CAP_AUTH_INSTALL, d->core_token, 0,
		    NULL) == -1)
			_exit(126);
		(void)close(d->core_token);
	}

	/*
	 * Redirect stdio to /dev/null.  In foreground mode, preserve
	 * stderr so switchboard's LOG_PERROR output reaches the same
	 * destination as capsule's (useful for test log capture).
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
	 * The system discovery route goes into the kernel slot, as for getty:
	 * SwitchBoard's own lookups, rc and the rc-world daemons inherit it.
	 */
	if (d->lookup_fd >= 0 && service_install_ambient_lookup(d->lookup_fd) == -1)
		_exit(126);

	/*
	 * Collect source→dest fd mappings, then move all sources
	 * above the reserved range to avoid clobbering.
	 */
	nfds = 0;
	src_fds[nfds] = child_channel_fd;
	dst_fds[nfds] = SWITCHBOARD_CHANNEL_FD;
	nfds++;
	if (d->channel_svc_fd >= 0) {
		src_fds[nfds] = d->channel_svc_fd;
		dst_fds[nfds] = SWITCHBOARD_CHANNEL_SVC_FD;
		nfds++;
	}
	if (d->coalition_svc_fd >= 0) {
		src_fds[nfds] = d->coalition_svc_fd;
		dst_fds[nfds] = SWITCHBOARD_COALITION_SVC_FD;
		nfds++;
	}
	if (d->capprotect_fd >= 0) {
		src_fds[nfds] = d->capprotect_fd;
		dst_fds[nfds] = SWITCHBOARD_CAPPROTECT_FD;
		nfds++;
	}
	if (d->identity_fd >= 0) {
		src_fds[nfds] = d->identity_fd;
		dst_fds[nfds] = SWITCHBOARD_IDENTITY_FD;
		nfds++;
	}

	if (d->authority_fd >= 0) {
		src_fds[nfds] = d->authority_fd;
		dst_fds[nfds++] = SWITCHBOARD_AUTHORITY_FD;
	}
	if (d->discovery_fd >= 0) {
		src_fds[nfds] = d->discovery_fd;
		dst_fds[nfds++] = SWITCHBOARD_DISCOVERY_FD;
	}
	/* The pinned image, just above the reserved range, for fexecve(). */
	if (d->core_image >= 0) {
		image_dst = SWITCHBOARD_LAST_FD + 1;
		src_fds[nfds] = d->core_image;
		dst_fds[nfds++] = image_dst;
	}

	safe_base = (image_dst >= 0 ? image_dst : SWITCHBOARD_LAST_FD) + 1;
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
	 * is optional; without this pass an unrelated capsule descriptor that
	 * happened to occupy fd 7 could survive the exec.
	 */
	for (fd = SWITCHBOARD_CHANNEL_FD; fd <= SWITCHBOARD_LAST_FD; fd++) {
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

	/* Close everything above the reserved range (and the image). */
	closefrom(safe_base);

	/*
	 * Permit this exec only; prevent propagation before manager startup.
	 * The image descriptor is close-on-exec: executing it consumes it.
	 */
	for (i = 0; i < nfds; i++) {
		if (dst_fds[i] == image_dst) {
			if (fcntl(image_dst, F_SETFD, FD_CLOEXEC) == -1)
				_exit(126);
			continue;
		}
		if (bootstrap_confine_manager_fd(dst_fds[i]) == -1)
			_exit(126);
	}

	/* Build minimal environment. */
	envc = 0;
	env[envc++] = __DECONST(char *,
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin");

	(void)snprintf(channel_env, sizeof(channel_env),
	    "CAPSULE_CHANNEL_FD=%d", SWITCHBOARD_CHANNEL_FD);
	env[envc++] = channel_env;

	if (d->channel_svc_fd >= 0) {
		(void)snprintf(channel_svc_env, sizeof(channel_svc_env),
		    "SWITCHBOARD_CHANNEL_SVC_FD=%d", SWITCHBOARD_CHANNEL_SVC_FD);
		env[envc++] = channel_svc_env;
	}
	if (d->coalition_svc_fd >= 0) {
		(void)snprintf(coalition_svc_env, sizeof(coalition_svc_env),
		    "SWITCHBOARD_COALITION_SVC_FD=%d",
		    SWITCHBOARD_COALITION_SVC_FD);
		env[envc++] = coalition_svc_env;
	}
	if (d->capprotect_fd >= 0) {
		(void)snprintf(capprotect_env, sizeof(capprotect_env),
		    "SWITCHBOARD_CAPPROTECT_FD=%d", SWITCHBOARD_CAPPROTECT_FD);
		env[envc++] = capprotect_env;
	}
	if (d->identity_fd >= 0) {
		(void)snprintf(identity_env, sizeof(identity_env),
		    "SWITCHBOARD_IDENTITY_FD=%d", SWITCHBOARD_IDENTITY_FD);
		env[envc++] = identity_env;
	}

	if (d->authority_fd >= 0) {
		(void)snprintf(authority_env, sizeof(authority_env),
		    "SWITCHBOARD_AUTHORITY_FD=%d", SWITCHBOARD_AUTHORITY_FD);
		env[envc++] = authority_env;
	}
	if (d->discovery_fd >= 0) {
		(void)snprintf(discovery_env, sizeof(discovery_env),
		    "SWITCHBOARD_DISCOVERY_FD=%d", SWITCHBOARD_DISCOVERY_FD);
		env[envc++] = discovery_env;
	}
	if (d->boot_complete)
		env[envc++] = __DECONST(char *, "SWITCHBOARD_BOOT_COMPLETE=1");
	else if (d->rc_fastboot)
		env[envc++] = __DECONST(char *, "SWITCHBOARD_RC_FASTBOOT=1");
	/* Reported by capsulectl status: the next start must create its own. */
	if (d->issuer_next_error != 0) {
		(void)snprintf(next_issuer_env, sizeof(next_issuer_env),
		    "SWITCHBOARD_NEXT_ISSUER_ERROR=%d", d->issuer_next_error);
		env[envc++] = next_issuer_env;
	}


	/* Forward bundle-directory overrides when present (see struct comment). */
	if (d->bundle_dir_system != NULL) {
		(void)snprintf(bundle_sys_env, sizeof(bundle_sys_env),
		    "SWITCHBOARD_BUNDLE_DIR_SYSTEM=%s", d->bundle_dir_system);
		env[envc++] = bundle_sys_env;
	}
	if (d->bundle_dir_user != NULL) {
		(void)snprintf(bundle_usr_env, sizeof(bundle_usr_env),
		    "SWITCHBOARD_BUNDLE_DIR_USER=%s", d->bundle_dir_user);
		env[envc++] = bundle_usr_env;
	}
	if (d->run_dir != NULL) {
		(void)snprintf(run_dir_env, sizeof(run_dir_env),
		    "SWITCHBOARD_RUN_DIR=%s", d->run_dir);
		env[envc++] = run_dir_env;
	}
	if (d->watch_settle != NULL) {
		(void)snprintf(settle_env, sizeof(settle_env),
		    "SWITCHBOARD_REGISTRY_WATCH_SETTLE=%s", d->watch_settle);
		env[envc++] = settle_env;
	}
	if (d->skip_rc != NULL && d->skip_rc[0] == '1') {
		(void)snprintf(skip_rc_env, sizeof(skip_rc_env),
		    "SWITCHBOARD_SKIP_RC=1");
		env[envc++] = skip_rc_env;
	}
	if (d->test_no_sigkill != NULL && d->test_no_sigkill[0] == '1') {
		(void)snprintf(no_sigkill_env, sizeof(no_sigkill_env),
		    "SWITCHBOARD_TEST_SHIELD_NO_SIGKILL=1");
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

	/* The supervisor must remain available to restart essential services.
	 * Do not inherit this exemption into every service it later launches. */
	{
		int flags = PPROT_SET;
		if (procctl(P_PID, getpid(), PROC_SPROTECT, &flags) == -1)
			_exit(126);
	}
	if (image_dst >= 0)
		fexecve(image_dst, argv, env);
	else
		execve(od.cfg.service_manager, argv, env);
	_exit(127);
}

/*
 * Q15 (rev 3 delta 3.4): with mac_veriexec enforcing, the O_VERIFY open of
 * the service manager already refused an image outside the signed base
 * manifest; without it, nothing distinguishes a replaced binary, and the
 * grant says so, as switchboard does for each Core unit.
 */
static void
bootstrap_core_verified_warning(const char *image_path)
{
	char state[64], *word, *rest;
	size_t len = sizeof(state) - 1;
	bool enforcing = false;

	if (sysctlbyname("security.mac.veriexec.state", state, &len, NULL,
	    0) == 0) {
		state[len] = '\0';
		rest = state;
		while ((word = strsep(&rest, " ")) != NULL)
			if (strcmp(word, "enforce") == 0)
				enforcing = true;
	}
	if (!enforcing)
		syslog(LOG_WARNING, "bootstrap: %s: Core role granted without "
		    "Veriexec enforcement: image not verified against the base "
		    "manifest", image_path);
}

/*
 * Issue and constrain the managed authority that carries the Core role
 * into switchboard's exec (cap_process(2) BASE EXCLUSION).  The image is
 * opened O_VERIFY; library directories are the system ones, checked as
 * switchboard checks its units' (authority.c set_loader_directories()).
 * The token cannot be passed on (CAP_XFER_NONE).
 */
static int
bootstrap_core_authority(int issuer, const char *image_path, int *tokenp,
    int *imagep)
{
	static const char *const libdirs[] = { "/lib", "/usr/lib" };
	struct cap_authority_spec spec = { .version = CAP_AUTH_VERSION,
	    .kind = CAP_AUTH_MANAGED };
	struct cap_authority_constraint c = { .flags = CAP_AUTH_ROLE_CORE,
	    .nexec = 1 };
	struct cap_authority_libdirs dirs = { .count = 0 };
	struct stat st;
	int image = -1, token = -1, saved, result = -1;
	unsigned i;

	token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0, &spec);
	if (token == -1)
		goto out;
	image = open(image_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY);
	if (image == -1)
		goto out;
	c.token_fd = token;
	c.executable_fds[0] = image;
	if (syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0, &c) == -1)
		goto out;
	bootstrap_core_verified_warning(image_path);
	dirs.token_fd = token;
	for (i = 0; i < nitems(libdirs); i++) {
		int fd = open(libdirs[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC |
		    O_NOFOLLOW);

		if (fd == -1)
			goto out;
		dirs.directory_fds[dirs.count++] = fd;
		if (fstat(fd, &st) == -1)
			goto out;
		if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
			errno = EPERM;
			goto out;
		}
	}
	if (syscall(SYS_cap_process, CAP_AUTH_SET_LIBDIRS, issuer, 0,
	    &dirs) == -1)
		goto out;
	if (cap_xfer_limit(token, CAP_XFER_NONE) == -1)
		goto out;
	*tokenp = token;
	token = -1;
	*imagep = image;
	image = -1;
	result = 0;
out:
	saved = errno;
	for (i = 0; i < dirs.count; i++)
		close(dirs.directory_fds[i]);
	if (image != -1)
		close(image);
	if (token != -1)
		close(token);
	errno = saved;
	return (result);
}

/*
 * PID 1 has no environment to carry SWITCHBOARD_TEST_SHIELD_NO_SIGKILL, so a
 * test kernel also takes it from the loader: switchboard_test_no_sigkill="1"
 * lets a guest test kill SwitchBoard to exercise a crash restart.  Honoured
 * only on a test kernel booted with kern.mac_capability.test_issuer=1.
 */
static bool
bootstrap_test_no_sigkill(void)
{
	char value[8];
	size_t len;
	int knob;

	len = sizeof(knob);
	if (sysctlbyname("kern.mac_capability.test_issuer", &knob, &len,
	    NULL, 0) == -1 || knob != 1)
		return (false);
	if (kenv(KENV_GET, "switchboard_test_no_sigkill", value,
	    sizeof(value)) <= 0 || strcmp(value, "1") != 0)
		return (false);
	syslog(LOG_WARNING, "bootstrap: TEST MODE: switchboard shield without "
	    "SIGKILL (switchboard_test_no_sigkill)");
	return (true);
}

/*
 * PID 1's authority issuer.  Each SwitchBoard start is handed its own; when
 * that SwitchBoard exits its descriptor closes, and issuer_close() revokes
 * every grant the issuer made and removes its application catalogue
 * (sys/dev/mac_capability/mac_capability_authority.c).
 *
 * Capsule creates the next start's issuer as soon as one is handed out and
 * holds it unused, so that a restart does not depend on a create succeeding
 * at that moment.  A held issuer authorises nothing: authority exists only as
 * grants an issuer has made, and Capsule makes none.  Holding it does not
 * change the running SwitchBoard's revocation either: issuer_revoke() acts on
 * one issuer's own grants, leases and applications, and every grant records
 * the issuer that made it (tests/sys/mac_capability
 * authority_test_issuer_test:held_issuer_independent).
 *
 * No failure of CAP_AUTH_ISSUER_CREATE ends with an event Capsule could wait
 * on.  EPERM, EINVAL, ENOSPC (the identity sequence never wraps) and a kernel
 * without the operation are permanent.  ENFILE, the system file table full,
 * clears only when something closes a file, which nothing reports.  So a
 * start without an issuer is refused, and PID 1 enters single-user.  EMFILE,
 * Capsule's own table being full, is prevented: BOOTSTRAP_ISSUER_RESERVE
 * reserved descriptors are released for the creates of one take.  The
 * kernel's allocations wait rather than fail (M_WAITOK), so there is no
 * ENOMEM.
 *
 * The held issuer is close-on-fork and not transferable from creation: a
 * Capsule child that stalls between fork and exec (getty's respawn sleep,
 * the window-system wait) must not hold a reference, or the issuer would
 * outlive the SwitchBoard it was handed to and its grants and catalogue with
 * it (issuer_close() revokes on the last close).  Only the pdfork into
 * SwitchBoard carries it: bootstrap_issuer_take() clears close-on-fork for the
 * issuer being handed out.
 *
 * A test kernel (options MAC_CAPABILITY_TEST_PERMISSIVE, booted with
 * kern.mac_capability.test_issuer=1) also gives a test-local Capsule a test
 * issuer until PID 1 anchors the boot; that is said loudly.
 */
static void
bootstrap_reserve(bool acquire)
{
	unsigned i;

	for (i = 0; i < BOOTSTRAP_ISSUER_RESERVE; i++) {
		if (!acquire) {
			if (bs.reserve_fd[i] >= 0)
				(void)close(bs.reserve_fd[i]);
			bs.reserve_fd[i] = -1;
		} else if (bs.reserve_fd[i] < 0 &&
		    (bs.reserve_fd[i] = open("/dev/null",
		    O_RDONLY | O_CLOEXEC | O_CLOFORK)) == -1)
			syslog(LOG_CRIT, "bootstrap: descriptor reserve for "
			    "issuer creates lost: %m; a create may fail with "
			    "EMFILE");
	}
}

static int
bootstrap_issuer_create(void)
{
	int fd;

	fd = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0, NULL);
	if (fd < 0)
		return (-1);
	/* Held: close on fork and exec, never transferable (see above). */
	if (fcntl(fd, F_SETFD, FD_CLOEXEC | FD_CLOFORK) == -1 ||
	    cap_xfer_limit(fd, CAP_XFER_NONE) == -1) {
		syslog(LOG_ERR, "bootstrap: confine held issuer: %m");
		(void)close(fd);
		errno = EBADF;
		return (-1);
	}
	if (getpid() != 1)
		syslog(LOG_WARNING,
		    "bootstrap: TEST MODE: authority issuer created off PID 1");
	return (fd);
}

/*
 * The issuer for this start: the one held from the last start, or, when that
 * create failed or this is the first start, one created now.  Then the next
 * start's issuer is created.  Returns -1 with bs.issuer_refused set when this
 * start has none.  The returned issuer may be inherited by the next fork,
 * which must be the pdfork into SwitchBoard.
 */
static int
bootstrap_issuer_take(void)
{
	int error, fd;

	bootstrap_reserve(false);
	fd = bs.issuer_next_fd;
	bs.issuer_next_fd = -1;
	if (fd < 0 && (fd = bootstrap_issuer_create()) < 0) {
		error = errno;
		bootstrap_reserve(true);
		bs.issuer_refused = error;
		syslog(LOG_CRIT, "bootstrap: no authority issuer: %s; "
		    "switchboard not started", strerror(error));
		return (-1);
	}
	bs.issuer_next_fd = bootstrap_issuer_create();
	bs.issuer_next_error = bs.issuer_next_fd < 0 ? errno : 0;
	bootstrap_reserve(true);
	if (bs.issuer_next_fd < 0)
		syslog(LOG_CRIT, "bootstrap: no authority issuer for the next "
		    "switchboard start: %s; that start will create one, or "
		    "refuse", strerror(bs.issuer_next_error));
	/* This one crosses the pdfork into SwitchBoard. */
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		error = errno;
		(void)close(fd);
		bs.issuer_refused = error;
		syslog(LOG_CRIT, "bootstrap: no authority issuer: %s; "
		    "switchboard not started", strerror(error));
		return (-1);
	}
	return (fd);
}

/*
 * A start refused for want of an issuer.  At first boot capsule_engine_start()
 * reports it and enters recovery; on a running system (a restart) PID 1 goes to
 * single-user the same way an operator's "capsulectl single" would.
 */
static void
bootstrap_issuer_refuse(void)
{

	if (getpid() != 1) {
		syslog(LOG_CRIT, "bootstrap: no authority issuer: %s; "
		    "switchboard not restarted", strerror(bs.issuer_refused));
		return;
	}
	syslog(LOG_CRIT, "bootstrap: no authority issuer: %s; entering "
	    "single-user", strerror(bs.issuer_refused));
	(void)capsule_lifecycle(CTL_OP_SINGLE);
}

/*
 * A descriptor for the discovery server end to delegate, creating the channel
 * on the first start of this Capsule.  Its client end becomes capsule.c's
 * ambient lookup for logins.  If the channel cannot be created on that first
 * start, this Capsule never owns one: every SwitchBoard mints its own route
 * and hands it over, as before (*fdp -1, return 0).  Once Capsule owns the
 * channel, a failed dup fails the start (-1): a SwitchBoard with its own
 * route would split discovery from the route every existing process holds.
 */
static int
bootstrap_discovery_dup(int *fdp)
{
	int client, server;

	*fdp = -1;
	if (!bs.discovery_tried) {
		bs.discovery_tried = true;
		if (mac_capability_create_channel(&server, &client) == -1) {
			syslog(LOG_WARNING, "bootstrap: no boot discovery "
			    "channel: %m; switchboard provides the route");
			return (0);
		}
		if (capsule_set_ambient_lookup(client) == -1) {
			syslog(LOG_WARNING, "bootstrap: boot discovery channel "
			    "client end: %m; switchboard provides the route");
			(void)close(server);
			return (0);
		}
		(void)fcntl(server, F_SETFD, FD_CLOEXEC | FD_CLOFORK);
		bs.discovery_fd = server;
		syslog(LOG_INFO, "bootstrap: boot discovery channel created");
	}
	if (bs.discovery_fd < 0)
		return (0);
	*fdp = fcntl(bs.discovery_fd, F_DUPFD_CLOEXEC, 0);
	if (*fdp == -1) {
		syslog(LOG_ERR, "bootstrap: dup discovery channel: %m");
		return (-1);
	}
	return (0);
}

/* Capsule serves discovery itself: a SwitchBoard route must not replace it. */
bool
bootstrap_owns_discovery(void)
{

	return (bs.discovery_fd >= 0);
}

/*
 * The capability world stopped (shutdown, single-user): the boot is over, and
 * the next SwitchBoard start runs /etc/rc again.  Called from
 * capsule_world_stop() whether or not a SwitchBoard was running.
 */
void
bootstrap_world_stopped(void)
{

	bs.boot_complete = false;
}

/*
 * The SwitchBoard that was started reported READY: the boot converged, and
 * any later start in this boot is a restart, which must not replay /etc/rc.
 */
void
bootstrap_note_ready(void)
{

	if (!bs.boot_complete)
		syslog(LOG_INFO, "bootstrap: boot converged; later switchboard "
		    "starts do not replay /etc/rc");
	bs.boot_complete = true;
}

/* The errno that made Capsule refuse to start SwitchBoard, or 0. */
int
bootstrap_issuer_refused(void)
{

	return (bs.issuer_refused);
}

/*
 * Start switchboard.  Creates a channel, pdforks, and registers the
 * process descriptor and channel fd on the kqueue.
 * Returns 0 on success, -1 on failure.
 */
int
bootstrap_start(int kq)
{
	struct bootstrap_delegate_fds dfds;
	struct kevent kev[2];
	cap_rights_t rights;
	int capsule_end, child_end;
	int pd_fd;
	pid_t pid;

	bs.issuer_refused = 0;
	if (od.cfg.service_manager[0] == '\0') {
		syslog(LOG_INFO, "bootstrap: no service_manager configured");
		return (0);
	}

	if (access(od.cfg.service_manager, X_OK) != 0) {
		syslog(LOG_ERR, "bootstrap: %s not executable: %m",
		    od.cfg.service_manager);
		return (-1);
	}

	/* The descriptor reserve that keeps EMFILE from the issuer creates. */
	bootstrap_reserve(true);

	/* Create channel. */
	if (mac_capability_create_channel(&capsule_end, &child_end) == -1) {
		syslog(LOG_ERR, "bootstrap: failed to create channel");
		return (-1);
	}

	/*
	 * Create service instance fds so switchboard can create channels,
	 * coalitions, and shield itself without round-tripping through
	 * the Capsule protocol.  These are mintable service instances —
	 * switchboard calls MAC_CAPABILITY_MINT_INSTANCE on them to get fresh
	 * instances for each service it launches.
	 */
	dfds.channel_svc_fd = mac_capability_connect_for_delegate("channel");
	if (dfds.channel_svc_fd == -1) {
		syslog(LOG_ERR, "bootstrap: channel service not available");
		close(capsule_end);
		close(child_end);
		return (-1);
	}
	dfds.coalition_svc_fd = mac_capability_connect_for_delegate("coalition");
	if (dfds.coalition_svc_fd == -1) {
		syslog(LOG_ERR, "bootstrap: coalition service not available");
		close(capsule_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		return (-1);
	}
	dfds.capprotect_fd = mac_capability_connect_for_delegate("capprotect");
	if (dfds.capprotect_fd == -1) {
		syslog(LOG_ERR, "bootstrap: capprotect service not available");
		close(capsule_end);
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

	dfds.core_token = -1;
	dfds.core_image = -1;
	dfds.authority_fd = bootstrap_issuer_take();
	if (dfds.authority_fd < 0) {
		close(capsule_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0)
			close(dfds.identity_fd);
		return (-1);
	}
	dfds.issuer_next_error = bs.issuer_next_error;

	/*
	 * PID 1's start carries base exclusion across switchboard's exec: a
	 * Core authority from the issuer just taken, pinning the image opened
	 * now (each start opens it again).  Without it the start is refused,
	 * as for a missing issuer; switchboard never runs unexcluded under
	 * PID 1.  Only PID 1's fork chain can be excluded, so a test-local
	 * Capsule makes no Core authority.
	 */
	if (getpid() == 1 && bootstrap_core_authority(dfds.authority_fd,
	    od.cfg.service_manager, &dfds.core_token, &dfds.core_image) == -1) {
		syslog(LOG_ERR, "bootstrap: core authority for switchboard: %m");
		close(capsule_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0)
			close(dfds.identity_fd);
		close(dfds.authority_fd);
		return (-1);
	}

	/* The boot-long discovery route (see bs.discovery_fd). */
	if (bootstrap_discovery_dup(&dfds.discovery_fd) == -1) {
		close(capsule_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0)
			close(dfds.identity_fd);
		close(dfds.authority_fd);
		if (dfds.core_token >= 0)
			close(dfds.core_token);
		if (dfds.core_image >= 0)
			close(dfds.core_image);
		return (-1);
	}
	dfds.lookup_fd = dfds.discovery_fd >= 0 ? capsule_ambient_lookup() : -1;
	dfds.boot_complete = bs.boot_complete;
	dfds.rc_fastboot = !capsule_rc_autoboot();

	/* Capture bundle-dir overrides here — getenv is not safe post-fork. */
	dfds.bundle_dir_system = getenv("SWITCHBOARD_BUNDLE_DIR_SYSTEM");
	dfds.bundle_dir_user = getenv("SWITCHBOARD_BUNDLE_DIR_USER");
	dfds.run_dir = getenv("SWITCHBOARD_RUN_DIR");
	dfds.watch_settle = getenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE");
	dfds.skip_rc = getenv("SWITCHBOARD_SKIP_RC");
	dfds.test_no_sigkill = getenv("SWITCHBOARD_TEST_SHIELD_NO_SIGKILL");
	if (dfds.test_no_sigkill == NULL && bootstrap_test_no_sigkill())
		dfds.test_no_sigkill = "1";

	/*
	 * These descriptors cross exactly one fork edge into switchboard.  They
	 * must never be transferable by either side. After this fork the trusted
	 * child locks CLOFORK and sets CLOEXEC_ONCE on its final descriptor slots.
	 * The manager exec consumes ONCE, locking further exec propagation before
	 * constructors run. SwitchBoard repeats the locked-state checks at startup.
	 */
	if (cap_xfer_limit(child_end, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.channel_svc_fd, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.coalition_svc_fd, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(dfds.capprotect_fd, CAP_XFER_NONE) == -1 ||
	    (dfds.identity_fd >= 0 &&
	    cap_xfer_limit(dfds.identity_fd, CAP_XFER_NONE) == -1) ||
	    (dfds.authority_fd >= 0 &&
	    cap_xfer_limit(dfds.authority_fd, CAP_XFER_NONE) == -1) ||
	    (dfds.discovery_fd >= 0 &&
	    cap_xfer_limit(dfds.discovery_fd, CAP_XFER_NONE) == -1)) {
		syslog(LOG_ERR, "bootstrap: confine delegated fd: %m");
		close(capsule_end);
		close(child_end);
		close(dfds.channel_svc_fd);
		close(dfds.coalition_svc_fd);
		close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0)
			close(dfds.identity_fd);
		if (dfds.authority_fd >= 0)
			close(dfds.authority_fd);
		if (dfds.core_token >= 0)
			close(dfds.core_token);
		if (dfds.core_image >= 0)
			close(dfds.core_image);
		if (dfds.discovery_fd >= 0)
			close(dfds.discovery_fd);
		return (-1);
	}

	pid = pdfork(&pd_fd, PD_CLOEXEC | PD_NOWAITPID);
	if (pid == -1) {
		syslog(LOG_ERR, "bootstrap: pdfork: %m");
		CAPSULE_PROBE_ERROR("bootstrap", "pdfork failed");
		close(capsule_end);
		close(child_end);
		if (dfds.channel_svc_fd >= 0) close(dfds.channel_svc_fd);
		if (dfds.coalition_svc_fd >= 0) close(dfds.coalition_svc_fd);
		if (dfds.capprotect_fd >= 0) close(dfds.capprotect_fd);
		if (dfds.identity_fd >= 0) close(dfds.identity_fd);
		if (dfds.authority_fd >= 0) close(dfds.authority_fd);
		if (dfds.core_token >= 0) close(dfds.core_token);
		if (dfds.core_image >= 0) close(dfds.core_image);
		if (dfds.discovery_fd >= 0) close(dfds.discovery_fd);
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
	if (dfds.authority_fd >= 0)
		close(dfds.authority_fd);
	if (dfds.core_token >= 0)
		close(dfds.core_token);
	if (dfds.core_image >= 0)
		close(dfds.core_image);
	if (dfds.discovery_fd >= 0)
		close(dfds.discovery_fd);

	/*
	 * The process descriptor is capsule's explicit and exclusive authority
	 * over this switchboard instance.  pdkill(2) intentionally bypasses ambient
	 * credential and MAC signal checks, so this descriptor must not escape
	 * through transfer, fork, or exec.  Failure to freeze that topology is a
	 * bootstrap failure, not a condition in which supervision may continue.
	 */
	cap_rights_init(&rights, CAP_PDKILL, CAP_EVENT);
	if (cap_rights_limit(pd_fd, &rights) == -1 ||
	    cap_xfer_limit(pd_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(pd_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(pd_fd, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "bootstrap: confine switchboard procdesc: %m");
		(void)pdkill(pd_fd, SIGKILL);
		close(pd_fd);
		close(capsule_end);
		return (-1);
	}

	/* Capsule's channel endpoint is equally exclusive and fail-closed. */
	if (cap_xfer_limit(capsule_end, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(capsule_end, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(capsule_end, CAP_CLOEXEC_LOCKED) == -1) {
		syslog(LOG_ERR, "bootstrap: confine Capsule channel: %m");
		(void)pdkill(pd_fd, SIGKILL);
		close(pd_fd);
		close(capsule_end);
		return (-1);
	}

	bs.pid = pid;
	bs.pd_fd = pd_fd;
	bs.channel_fd = capsule_end;
	bs.started = true;
	clock_gettime(CLOCK_MONOTONIC, &bs.last_start);

	/* Tell the protocol handler about the channel fd. */
	capsule_proto_init(capsule_end);

	/* Register procdesc and channel on kqueue. */
	EV_SET(&kev[0], pd_fd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXIT, 0, NULL);
	EV_SET(&kev[1], capsule_end, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, kev, 2, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "bootstrap: kevent register: %m");
		pdkill(pd_fd, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
		close(pd_fd);
		close(capsule_end);
		bs.started = false;
		bs.pid = 0;
		bs.pd_fd = -1;
		bs.channel_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "bootstrap: started switchboard pid %jd",
	    (intmax_t)pid);
	CAPSULE_PROBE_BOOTSTRAP_START(pid);
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
 * Tear down all switchboard resources and restart with backoff.
 * Called only from the EVFILT_PROCDESC path — process exit is
 * the single source of truth for lifecycle.
 */
static void
bootstrap_teardown_and_restart(int kq, int status)
{
	struct timespec now;
	long uptime;

	if (WIFEXITED(status))
		syslog(LOG_WARNING, "bootstrap: switchboard exited status %d",
		    WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		syslog(LOG_WARNING, "bootstrap: switchboard killed by signal %d",
		    WTERMSIG(status));

	CAPSULE_PROBE_BOOTSTRAP_EXIT(bs.pid, status);

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
	capsule_proto_reset();

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

	bootstrap_backoff(kq);
}

/*
 * Handle channel EOF.
 *
 * The procdesc remains the lifecycle source of truth, but loss of the
 * exclusive Capsule channel is an integrity failure: a live switchboard can
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
 * Handle switchboard process exit (EVFILT_PROCDESC).
 */
void
bootstrap_handle_exit(struct kevent *kev, int kq)
{

	bootstrap_teardown_and_restart(kq, (int)kev->data);
}

/*
 * Handle restart timer expiry.  If bootstrap_start still fails
 * (e.g. binary missing, mac_capability unavailable), reschedule with
 * backoff rather than leaving switchboard permanently dead.
 */
void
bootstrap_handle_timer(int kq)
{

	syslog(LOG_INFO, "bootstrap: restart timer fired");
	if (bootstrap_start(kq) == 0)
		return;

	syslog(LOG_ERR, "bootstrap: restart failed");
	bootstrap_backoff(kq);
}

/*
 * Count one failed start and schedule the next with exponential backoff,
 * or trip the circuit breaker.
 */
static void
bootstrap_backoff(int kq)
{
	unsigned delay;

	/* Without an issuer no restart can succeed: do not count, refuse. */
	if (bs.issuer_refused != 0) {
		bootstrap_issuer_refuse();
		return;
	}
	bs.restart_count++;
	if (bs.restart_count >= BOOTSTRAP_MAX_FAILURES) {
		syslog(LOG_CRIT,
		    "bootstrap: switchboard failed %u times, giving up",
		    bs.restart_count);
		CAPSULE_PROBE_ERROR("bootstrap", "circuit breaker tripped");
		return;
	}

	delay = BOOTSTRAP_BASE_DELAY << (bs.restart_count - 1);
	if (delay > BOOTSTRAP_MAX_DELAY)
		delay = BOOTSTRAP_MAX_DELAY;

	CAPSULE_PROBE_BOOTSTRAP_RESTART(bs.restart_count, delay);
	bootstrap_schedule_restart(kq, delay);
}

/*
 * Send a signal to switchboard via its process descriptor.
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
 * Gracefully stop switchboard.
 */
void
bootstrap_stop(void)
{

	if (!bs.started || bs.pd_fd < 0)
		return;

	syslog(LOG_INFO, "bootstrap: stopping switchboard");
	pdkill(bs.pd_fd, SIGTERM);
}

bool
bootstrap_is_stopped(void)
{

	return (!bs.started);
}

/*
 * True once the restart circuit breaker has tripped: switchboard has failed
 * BOOTSTRAP_MAX_FAILURES times and will not be restarted again.  This is
 * the definitive "switchboard is permanently dead" signal (as opposed to a
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

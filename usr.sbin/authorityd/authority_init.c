/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2026 Kory Heard
 *
 * This code is derived from software contributed to Berkeley by
 * Donn Seeley at Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Authority PID 1 personality.
 *
 * A port of init(8)'s state machine (see
 * docs/freebsd-init-behavior-audit.md for the behavior contract) with
 * one additional state: after /etc/rc completes, ESTABLISH_AUTHORITY
 * brings up the Authority capability engine (mac_capability, control
 * socket, serviced under a procdesc) before multi-user session
 * management begins.  The multi-user wait is a kqueue loop so the
 * engine's control socket, serviced procdesc/channel, and restart
 * timers are serviced from PID 1 without threads.
 *
 * Compatibility contract (docs/authority-init-todo.md):
 *  - never daemonize, never exit: every stock init exit path becomes a
 *    logged emergency followed by deliberate reboot or recovery;
 *  - PID 1 is already the real-init reaper: verify, don't acquire;
 *  - rc remains the owner of the legacy Unix service world; serviced
 *    owns only migrated capability services;
 *  - shutdown order: revoke ttys -> /etc/rc.shutdown (serviced still
 *    available) -> drain/stop serviced via its procdesc -> global
 *    SIGTERM/SIGKILL sweep -> /etc/rc.final -> reboot(2).
 *
 * Intentional divergences from stock init (each logged at runtime):
 *  - init_exec is ignored: it is the hook that led the kernel to this
 *    program; honoring it again would exec-loop;
 *  - COMPAT_SYSV_INIT runlevels are not accepted (stock /sbin/init
 *    remains installed for that);
 *  - fatal errors and fatal signals reboot deliberately instead of
 *    exiting (a PID 1 exit panics the kernel).
 */

#include <sys/param.h>
#include <sys/boottrace.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <db.h>
#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <libutil.h>
#include <login_cap.h>
#include <mntopts.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ttyent.h>
#include <unistd.h>

#include "authorityd.h"
#include "authorityd_ctl.h"
#include "authority_init.h"
#include "mac_capability_priv.h"
#include "service_bootstrap.h"	/* SERVICE_LOOKUP_FIXED_FD (§21 getty carry) */

#define	_PATH_INITLOG		"/var/log/init.log"
#define	_PATH_RUNCOM		"/etc/rc"
#define	_PATH_RUNDOWN		"/etc/rc.shutdown"
#define	_PATH_RUNFINAL		"/etc/rc.final"
#define	_PATH_REROOT		"/dev/reroot"
#define	_PATH_REROOT_INIT	_PATH_REROOT "/init"

/*
 * Sleep times; used to prevent thrashing.  Observable compatibility
 * constants — see audit section 10.
 */
#define	GETTY_SPACING		 5	/* N secs minimum getty spacing */
#define	GETTY_SLEEP		30	/* sleep N secs after spacing problem */
#define	GETTY_NSPACE		 3	/* max. spacing count to bring reaction */
#define	WINDOW_WAIT		 3	/* wait N secs after starting window */
#define	STALL_TIMEOUT		30	/* wait N secs after warning */
#define	DEATH_WATCH		10	/* wait N secs for procs to die */
#define	DEATH_SCRIPT		120	/* wait for 2min for /etc/rc.shutdown */
#define	WORLD_WATCH		30	/* wait N secs for serviced to drain */
#define	RESOURCE_RC		"daemon"
#define	RESOURCE_WINDOW		"default"
#define	RESOURCE_GETTY		"default"
#define	SCRIPT_ARGV_SIZE	3

static void oi_handle(sig_t, ...);
static void oi_delset(sigset_t *, ...);

static void stall(const char *, ...) __printflike(1, 2);
static void warning(const char *, ...) __printflike(1, 2);
static void emergency(const char *, ...) __printflike(1, 2);
static void oi_fatal(const char *, ...) __printflike(1, 2) __dead2;
static void disaster(int);
static void revoke_ttys(void);
static int  runshutdown(void);
static char *strk(char *);
static void runfinal(void);

typedef long (*state_func_t)(void);
typedef state_func_t (*state_t)(void);

static state_func_t single_user(void);
static state_func_t runcom(void);
static state_func_t establish_authority(void);
static state_func_t read_ttys(void);
static state_func_t multi_user(void);
static state_func_t clean_ttys(void);
static state_func_t catatonia(void);
static state_func_t death(void);
static state_func_t death_single(void);
static state_func_t reroot(void);
static state_func_t reroot_phase_two(void);

static state_func_t run_script(const char *);

static enum { AUTOBOOT, FASTBOOT } runcom_mode = AUTOBOOT;

static bool Reboot = false;
static int howto = RB_AUTOBOOT;

static bool devfs = false;
static char *init_path_argv0;

static void transition(state_t) __dead2;
static state_t requested_transition;
static state_t current_state = death_single;

static void execute_script(char *argv[]);
static void open_console(void);
static const char *get_shell(void);
static void write_stderr(const char *message);

/* Authority engine integration. */
static int  oi_kq = -1;
static bool oi_engine_up;
static bool oi_mac_up;
static bool oi_ctl_up;

/*
 * Ambient lookup channel (§21) carried into interactive logins.  serviced
 * hands us a dup of its SYSTEM ambient lookup client end over the authority
 * channel (AUTHORITY_OP_SET_AMBIENT_LOOKUP); we pin it here and dup2() it to
 * SERVICE_LOOKUP_FIXED_FD in each getty child so login inherits it across the
 * hand-built getty environment.  -1 means "no channel"; the whole mechanism is
 * best-effort and never gates getty, login, or boot.
 */
static int oi_ambient_lookup_fd = -1;
static void oi_engine_start(void);
static void oi_dispatch(struct kevent *);
static void oi_lifecycle_apply(int op);
static int oi_await_convergence(void);
static void oi_ctl_try_setup(void);
static void oi_drain_children(void);
static void oi_world_stop(void);

typedef struct init_session {
	pid_t	se_process;		/* controlling process */
	time_t	se_started;		/* used to avoid thrashing */
	int	se_flags;		/* status of session */
#define	SE_SHUTDOWN	0x1		/* session won't be restarted */
#define	SE_PRESENT	0x2		/* session is in /etc/ttys */
#define	SE_IFEXISTS	0x4		/* session defined as "onifexists" */
#define	SE_IFCONSOLE	0x8		/* session defined as "onifconsole" */
	int	se_nspace;		/* spacing count */
	char	*se_device;		/* filename of port */
	char	*se_getty;		/* what to run on that port */
	char	*se_getty_argv_space;   /* pre-parsed argument array space */
	char	**se_getty_argv;	/* pre-parsed argument array */
	char	*se_window;		/* window system (started only once) */
	char	*se_window_argv_space;  /* pre-parsed argument array space */
	char	**se_window_argv;	/* pre-parsed argument array */
	char	*se_type;		/* default terminal type */
	struct	init_session *se_prev;
	struct	init_session *se_next;
} session_t;

static void free_session(session_t *);
static session_t *new_session(session_t *, struct ttyent *);
static session_t *sessions;

static char **construct_argv(char *);
static void start_window_system(session_t *);
static void collect_child(pid_t);
static pid_t start_getty(session_t *);
static void transition_handler(int);
static void alrm_handler(int);
static void setsecuritylevel(int);
static int getsecuritylevel(void);
static int setupargv(session_t *, struct ttyent *);
static void setprocresources(const char *);
static bool clang;

static int start_session_db(void);
static void add_session(session_t *);
static void del_session(session_t *);
static session_t *find_session(pid_t);
static DB *session_db;

/*
 * The mother of all processes: PID 1 entry point.
 */
void
authority_init_main(int argc, char *argv[])
{
	state_t initial_transition = runcom;
	char kenv_value[PATH_MAX];
	int c, error;
	struct sigaction sa;
	struct kevent kev;
	sigset_t mask;

	init_path_argv0 = strdup(argv[0]);
	if (init_path_argv0 == NULL)
		init_path_argv0 = __DECONST(char *, "/sbin/authority-init");

	/* Present as "Authority" in ps/top -- the plane's spine, not base init. */
	setproctitle("-Authority");

	BOOTTRACE("authority-init starting...");

	/* LOG_CONS keeps early diagnostics on the console until syslogd
	 * runs; there is no /var dependency for survival. */
	openlog("init", LOG_CONS, LOG_AUTH);

	if (setsid() < 0 && (errno != EPERM || getsid(0) != 1))
		warning("initial setsid() failed: %m");

	if (setlogin("root") < 0)
		warning("setlogin() failed: %m");

	/* Reset the option index: main() has not consumed anything when
	 * PID 1 dispatch happens, but be explicit for safety. */
	optreset = 1;
	optind = 1;
	while ((c = getopt(argc, argv, "dsfr")) != -1)
		switch (c) {
		case 'd':
			devfs = true;
			break;
		case 's':
			initial_transition = single_user;
			break;
		case 'f':
			runcom_mode = FASTBOOT;
			break;
		case 'r':
			initial_transition = reroot_phase_two;
			break;
		default:
			warning("unrecognized flag '-%c'", c);
			break;
		}

	if (optind != argc)
		warning("ignoring excess arguments");

	/*
	 * We catch or block signals rather than ignore them,
	 * so that they get reset on exec.
	 */
	oi_handle(disaster, SIGABRT, SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGSYS,
	    SIGXCPU, SIGXFSZ, 0);
	oi_handle(transition_handler, SIGHUP, SIGINT, SIGEMT, SIGTERM, SIGTSTP,
	    SIGUSR1, SIGUSR2, SIGWINCH, 0);
	oi_handle(alrm_handler, SIGALRM, 0);
	sigfillset(&mask);
	oi_delset(&mask, SIGABRT, SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGSYS,
	    SIGXCPU, SIGXFSZ, SIGHUP, SIGINT, SIGEMT, SIGTERM, SIGTSTP,
	    SIGALRM, SIGUSR1, SIGUSR2, SIGWINCH, 0);
	sigprocmask(SIG_SETMASK, &mask, NULL);
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTTOU, &sa, NULL);

	close(0);
	close(1);
	close(2);

	/*
	 * The PID 1 wait loops are kqueue-driven so the Authority engine's
	 * events can be serviced from multi-user state.  SIGCHLD stays
	 * blocked (as in stock init); EVFILT_SIGNAL fires on generation
	 * regardless, waking the loop to drain waitpid(WNOHANG).
	 */
	oi_kq = kqueue();
	if (oi_kq >= 0 && oi_kq < 3) {
		/*
		 * Keep the stdio slots free: children expect to place
		 * their console/tty at 0-2, and a kqueue parked there
		 * is a state no other process ever presents to the
		 * kernel's fork/exec descriptor handling.
		 */
		int nfd = fcntl(oi_kq, F_DUPFD, 3);

		if (nfd >= 0) {
			close(oi_kq);
			oi_kq = nfd;
		}
	}
	if (oi_kq >= 0) {
		EV_SET(&kev, SIGCHLD, EVFILT_SIGNAL, EV_ADD | EV_ENABLE,
		    0, 0, NULL);
		if (kevent(oi_kq, &kev, 1, NULL, 0, NULL) == -1)
			warning("kevent SIGCHLD: %m");
	} else
		warning("kqueue: %m");

	/*
	 * Divergence from stock init: init_exec is how the kernel's
	 * chosen init reached this program; honoring it here would
	 * exec-loop.  Log and continue.
	 */
	if (kenv(KENV_GET, "init_exec", kenv_value, sizeof(kenv_value)) > 0)
		warning("init_exec=%s ignored by authority-init", kenv_value);

	if (kenv(KENV_GET, "init_script", kenv_value, sizeof(kenv_value)) > 0) {
		state_func_t next_transition;

		if ((next_transition = run_script(kenv_value)) != NULL)
			initial_transition = (state_t) next_transition;
	}

	if (kenv(KENV_GET, "init_chroot", kenv_value, sizeof(kenv_value)) > 0) {
		if (chdir(kenv_value) != 0 || chroot(".") != 0)
			warning("Can't chroot to %s: %m", kenv_value);
	}

	/*
	 * Additional check if devfs needs to be mounted:
	 * If "/" and "/dev" have the same device number,
	 * then it hasn't been mounted yet.
	 */
	if (!devfs) {
		struct stat stst;
		dev_t root_devno;

		stat("/", &stst);
		root_devno = stst.st_dev;
		if (stat("/dev", &stst) != 0)
			warning("Can't stat /dev: %m");
		else if (stst.st_dev == root_devno)
			devfs = true;
	}

	if (devfs) {
		struct iovec iov[4];
		char *s;
		int i;

		char _fstype[]	= "fstype";
		char _devfs[]	= "devfs";
		char _fspath[]	= "fspath";
		char _path_dev[]= _PATH_DEV;

		iov[0].iov_base = _fstype;
		iov[0].iov_len = sizeof(_fstype);
		iov[1].iov_base = _devfs;
		iov[1].iov_len = sizeof(_devfs);
		iov[2].iov_base = _fspath;
		iov[2].iov_len = sizeof(_fspath);
		s = strdup(_PATH_DEV);
		if (s != NULL) {
			i = strlen(s);
			if (i > 0 && s[i - 1] == '/')
				s[i - 1] = '\0';
			iov[3].iov_base = s;
			iov[3].iov_len = strlen(s) + 1;
		} else {
			iov[3].iov_base = _path_dev;
			iov[3].iov_len = sizeof(_path_dev);
		}
		nmount(iov, 4, 0);
		if (s != NULL)
			free(s);
	}

	if (initial_transition != reroot_phase_two) {
		error = unmount(_PATH_REROOT, MNT_FORCE);
		if (error != 0 && errno != EINVAL)
			warning("Cannot unmount %s: %m", _PATH_REROOT);
	}

	transition(initial_transition);
	/* NOTREACHED */
}

static void
oi_handle(sig_t handler, ...)
{
	int sig;
	struct sigaction sa;
	sigset_t mask_everything;
	va_list ap;
	va_start(ap, handler);

	sa.sa_handler = handler;
	sigfillset(&mask_everything);

	while ((sig = va_arg(ap, int)) != 0) {
		sa.sa_mask = mask_everything;
		sa.sa_flags = sig == SIGCHLD ? SA_NOCLDSTOP : 0;
		sigaction(sig, &sa, NULL);
	}
	va_end(ap);
}

static void
oi_delset(sigset_t *maskp, ...)
{
	int sig;
	va_list ap;
	va_start(ap, maskp);

	while ((sig = va_arg(ap, int)) != 0)
		sigdelset(maskp, sig);
	va_end(ap);
}

static void
stall(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
	sleep(STALL_TIMEOUT);
}

static void
warning(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_ALERT, message, ap);
	va_end(ap);
}

static void
emergency(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_EMERG, message, ap);
	va_end(ap);
}

/*
 * An unrecoverable PID 1 error.  Stock init would exit here, which
 * panics the kernel.  Log, give the operator a chance to read the
 * console, then reboot deliberately.
 */
static void
oi_fatal(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);

	vsyslog(LOG_EMERG, message, ap);
	va_end(ap);
	emergency("unrecoverable error in PID 1; rebooting in %d seconds",
	    STALL_TIMEOUT);
	sync();
	sleep(STALL_TIMEOUT);
	reboot(RB_AUTOBOOT);
	/* If even reboot(2) fails there is nothing left to do but spin;
	 * exiting would panic with less information. */
	for (;;)
		sleep(STALL_TIMEOUT);
}

/*
 * Catch a fatal synchronous signal.  Stock init sleeps and exits
 * (kernel panic); reboot deliberately instead.  reboot(2) and sync(2)
 * are async-signal-safe.
 */
static void
disaster(int sig)
{

	emergency("fatal signal: %s",
	    (unsigned)sig < NSIG ? sys_siglist[sig] : "unknown signal");

	sleep(STALL_TIMEOUT);
	sync();
	reboot(RB_AUTOBOOT);
	_exit(sig);	/* unreachable; kernel panic as last resort */
}

static int
getsecuritylevel(void)
{
	int name[2], curlevel;
	size_t len;

	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	len = sizeof curlevel;
	if (sysctl(name, 2, &curlevel, &len, NULL, 0) == -1) {
		emergency("cannot get kernel security level: %m");
		return (-1);
	}
	return (curlevel);
}

static void
setsecuritylevel(int newlevel)
{
	int name[2], curlevel;

	curlevel = getsecuritylevel();
	if (newlevel == curlevel)
		return;
	name[0] = CTL_KERN;
	name[1] = KERN_SECURELVL;
	if (sysctl(name, 2, NULL, NULL, &newlevel, sizeof newlevel) == -1) {
		emergency(
		    "cannot change kernel security level from %d to %d: %m",
		    curlevel, newlevel);
		return;
	}
	warning("kernel security level changed from %d to %d",
	    curlevel, newlevel);
}

static void
transition(state_t s)
{

	current_state = s;
	for (;;)
		current_state = (state_t) (*current_state)();
}

/*
 * Start a session and allocate a controlling terminal.
 * Only called by children of PID 1 after forking.
 */
static void
open_console(void)
{
	int fd;

	revoke(_PATH_CONSOLE);
	if ((fd = open(_PATH_CONSOLE, O_RDWR | O_NONBLOCK)) != -1) {
		(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
		if (login_tty(fd) == 0)
			return;
		close(fd);
	}

	/* No luck.  Log output to file if possible. */
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		stall("cannot open null device.");
		_exit(1);
	}
	if (fd != STDIN_FILENO) {
		dup2(fd, STDIN_FILENO);
		close(fd);
	}
	fd = open(_PATH_INITLOG, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd == -1)
		dup2(STDIN_FILENO, STDOUT_FILENO);
	else if (fd != STDOUT_FILENO) {
		dup2(fd, STDOUT_FILENO);
		close(fd);
	}
	dup2(STDOUT_FILENO, STDERR_FILENO);
}

static const char *
get_shell(void)
{
	static char kenv_value[PATH_MAX];

	if (kenv(KENV_GET, "init_shell", kenv_value, sizeof(kenv_value)) > 0)
		return kenv_value;
	else
		return _PATH_BSHELL;
}

static void
write_stderr(const char *message)
{

	write(STDERR_FILENO, message, strlen(message));
}

static int
read_file(const char *path, void **bufp, size_t *bufsizep)
{
	struct stat sb;
	size_t bufsize;
	void *buf;
	ssize_t nbytes;
	int error, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		emergency("%s: %m", path);
		return (-1);
	}

	error = fstat(fd, &sb);
	if (error != 0) {
		emergency("fstat: %m");
		close(fd);
		return (error);
	}

	bufsize = sb.st_size;
	buf = malloc(bufsize);
	if (buf == NULL) {
		emergency("malloc: %m");
		close(fd);
		return (-1);
	}

	nbytes = read(fd, buf, bufsize);
	if (nbytes != (ssize_t)bufsize) {
		emergency("read: %m");
		close(fd);
		free(buf);
		return (-1);
	}

	error = close(fd);
	if (error != 0) {
		emergency("close: %m");
		free(buf);
		return (error);
	}

	*bufp = buf;
	*bufsizep = bufsize;

	return (0);
}

static int
create_file(const char *path, const void *buf, size_t bufsize)
{
	ssize_t nbytes;
	int error, fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0700);
	if (fd < 0) {
		emergency("%s: %m", path);
		return (-1);
	}

	nbytes = write(fd, buf, bufsize);
	if (nbytes != (ssize_t)bufsize) {
		emergency("write: %m");
		close(fd);
		return (-1);
	}

	error = close(fd);
	if (error != 0) {
		emergency("close: %m");
		return (-1);
	}

	return (0);
}

static int
mount_tmpfs(const char *fspath)
{
	struct iovec *iov;
	char errmsg[255];
	int error, iovlen;

	iov = NULL;
	iovlen = 0;
	memset(errmsg, 0, sizeof(errmsg));
	build_iovec(&iov, &iovlen, "fstype",
	    __DECONST(void *, "tmpfs"), (size_t)-1);
	build_iovec(&iov, &iovlen, "fspath",
	    __DECONST(void *, fspath), (size_t)-1);
	build_iovec(&iov, &iovlen, "errmsg",
	    errmsg, sizeof(errmsg));

	error = nmount(iov, iovlen, 0);
	if (error != 0) {
		if (*errmsg != '\0') {
			emergency("cannot mount tmpfs on %s: %s: %m",
			    fspath, errmsg);
		} else {
			emergency("cannot mount tmpfs on %s: %m",
			    fspath);
		}
		return (error);
	}
	return (0);
}

static state_func_t
reroot(void)
{
	void *buf;
	size_t bufsize;
	int error;

	buf = NULL;
	bufsize = 0;

	revoke_ttys();
	runshutdown();
	oi_world_stop();

	/*
	 * Make sure nobody can interfere with our scheme.
	 * Ignore ESRCH, which can apparently happen when
	 * there are no processes to kill.
	 */
	error = kill(-1, SIGKILL);
	if (error != 0 && errno != ESRCH) {
		emergency("kill(2) failed: %m");
		goto out;
	}

	/*
	 * Copy the init binary into tmpfs, so that we can unmount
	 * the old rootfs without committing suicide.
	 */
	error = read_file(init_path_argv0, &buf, &bufsize);
	if (error != 0)
		goto out;
	error = mount_tmpfs(_PATH_REROOT);
	if (error != 0)
		goto out;
	error = create_file(_PATH_REROOT_INIT, buf, bufsize);
	if (error != 0)
		goto out;

	execl(_PATH_REROOT_INIT, _PATH_REROOT_INIT, "-r", NULL);
	emergency("cannot exec %s: %m", _PATH_REROOT_INIT);

out:
	emergency("reroot failed; going to single user mode");
	free(buf);
	return (state_func_t) single_user;
}

static state_func_t
reroot_phase_two(void)
{
	char init_path[PATH_MAX], *path, *path_component;
	size_t init_path_len;
	int nbytes, error;

	/*
	 * Ask the kernel to mount the new rootfs.
	 */
	error = reboot(RB_REROOT);
	if (error != 0) {
		emergency("RB_REROOT failed: %m");
		goto out;
	}

	nbytes = kenv(KENV_GET, "init_path", init_path, sizeof(init_path));
	if (nbytes <= 0) {
		init_path_len = sizeof(init_path);
		error = sysctlbyname("kern.init_path",
		    init_path, &init_path_len, NULL, 0);
		if (error != 0) {
			emergency("failed to retrieve kern.init_path: %m");
			goto out;
		}
	}

	path_component = init_path;
	while ((path = strsep(&path_component, ":")) != NULL)
		execl(path, path, NULL);
	emergency("cannot exec init from %s: %m", init_path);

out:
	emergency("reroot failed; going to single user mode");
	return (state_func_t) single_user;
}

/*
 * Bring the system up single user, or perform the final reboot syscall.
 */
static state_func_t
single_user(void)
{
	pid_t pid, wpid;
	int status;
	sigset_t mask;
	const char *shell;
	char *argv[2];
	struct timeval tv, tn;
	struct passwd *pp;
	struct ttyent *typ;
	static const char banner[] =
		"Enter root password, or ^D to go multi-user\n";
	char *clear, *password;
	char altshell[128];

	if (Reboot) {
		/* Instead of going single user, reboot the machine */
		BOOTTRACE("shutting down the system");
		sync();
		runfinal();
		if (reboot(howto) == -1)
			emergency("reboot(%#x) failed, %m", howto);
		else
			warning("reboot(%#x) returned", howto);
		/* Stock init exits here (kernel panic); reboot again
		 * with defaults as a last resort. */
		sleep(STALL_TIMEOUT);
		reboot(RB_AUTOBOOT);
		oi_fatal("reboot(2) is not working");
	}

	BOOTTRACE("going to single user mode");
	shell = get_shell();

	if ((pid = fork()) == 0) {
		/*
		 * Start the single user session.
		 */
		open_console();

		pp = getpwnam("root");
		/*
		 * Check the root password (SECURE behavior).
		 * We don't care if the console is 'on' by default;
		 * it's the only tty that can be 'off' and 'secure'.
		 */
		typ = getttynam("console");
		if (typ && (typ->ty_status & TTY_SECURE) == 0 &&
		    pp && *pp->pw_passwd) {
			write_stderr(banner);
			for (;;) {
				clear = getpass("Password:");
				if (clear == NULL || *clear == '\0')
					_exit(0);
				password = crypt(clear, pp->pw_passwd);
				explicit_bzero(clear, _PASSWORD_LEN);
				if (password != NULL &&
				    strcmp(password, pp->pw_passwd) == 0)
					break;
				warning("single-user login failed\n");
			}
		}
		endttyent();

		/* DEBUGSHELL behavior. */
		{
			char *cp = altshell;
			int num;

#define	SHREQUEST "Enter full pathname of shell or RETURN for "
			write_stderr(SHREQUEST);
			write_stderr(shell);
			write_stderr(": ");
			while ((num = read(STDIN_FILENO, cp, 1)) != -1 &&
			    num != 0 && *cp != '\n' && cp < &altshell[127])
				cp++;
			*cp = '\0';
			if (altshell[0] != '\0')
				shell = altshell;
		}

		if (pp != NULL && pp->pw_dir != NULL && *pp->pw_dir != '\0' &&
		    chdir(pp->pw_dir) == 0) {
			setenv("HOME", pp->pw_dir, 1);
		} else {
			chdir("/");
			setenv("HOME", "/", 1);
		}
		endpwent();

		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);

		{
			char name[] = "-sh";

			argv[0] = name;
			argv[1] = NULL;
			execv(shell, argv);
			emergency("can't exec %s for single user: %m", shell);
			execv(_PATH_BSHELL, argv);
			emergency("can't exec %s for single user: %m",
			    _PATH_BSHELL);
		}
		sleep(STALL_TIMEOUT);
		_exit(1);
	}

	if (pid == -1) {
		/*
		 * We are seriously hosed.  Do our best.
		 */
		emergency("can't fork single-user shell, trying again");
		while (waitpid(-1, (int *) 0, WNOHANG) > 0)
			continue;
		return (state_func_t) single_user;
	}

	requested_transition = 0;
	do {
		if ((wpid = waitpid(-1, &status, WUNTRACED)) != -1)
			collect_child(wpid);
		if (wpid == -1) {
			if (errno == EINTR)
				continue;
			warning("wait for single-user shell failed: %m; restarting");
			return (state_func_t) single_user;
		}
		if (wpid == pid && WIFSTOPPED(status)) {
			warning("shell stopped, restarting\n");
			kill(pid, SIGCONT);
			wpid = -1;
		}
	} while (wpid != pid && !requested_transition);

	if (requested_transition)
		return (state_func_t) requested_transition;

	if (!WIFEXITED(status)) {
		if (WTERMSIG(status) == SIGKILL) {
			/*
			 *  reboot(8) killed shell?
			 */
			warning("single user shell terminated.");
			gettimeofday(&tv, NULL);
			tn = tv;
			tv.tv_sec += STALL_TIMEOUT;
			while (tv.tv_sec > tn.tv_sec || (tv.tv_sec ==
			    tn.tv_sec && tv.tv_usec > tn.tv_usec)) {
				sleep(1);
				gettimeofday(&tn, NULL);
			}
			/* Stock init exits here while reboot(8) completes
			 * the syscall.  Wait quietly instead; if the
			 * rebooting process died too, recover. */
			warning("reboot did not arrive; recovering");
			return (state_func_t) single_user;
		} else {
			warning("single user shell terminated, restarting");
			return (state_func_t) single_user;
		}
	}

	runcom_mode = FASTBOOT;
	return (state_func_t) runcom;
}

/*
 * Run the system startup script.
 */
static state_func_t
runcom(void)
{

	/*
	 * serviced owns rc startup now: it runs /etc/rc as a oneshot, then
	 * launches native capability services.  PID 1 therefore does NOT run
	 * /etc/rc; it brings up the capability engine (which starts
	 * serviced) in establish_authority.  This state is retained only as
	 * the entry into establish_authority so the single-user -> multi-user
	 * path is unchanged; init_rc/autoboot no longer apply here.
	 */
	BOOTTRACE("rc startup delegated to serviced");
	runcom_mode = AUTOBOOT;
	return (state_func_t) establish_authority;
}

/*
 * Phase two of boot: bring up the Authority capability engine, which starts
 * serviced, which runs /etc/rc and the native services.  Because serviced
 * now owns rc startup, PID 1 must not proceed to multi-user until serviced
 * signals convergence -- and if serviced cannot bring the system up, PID 1
 * must reach a recovery shell rather than a dead multi-user with no rc
 * world.  This is the converge-or-recover gate.
 */
static state_func_t
establish_authority(void)
{

	oi_engine_start();
	if (!oi_engine_up) {
		/* No serviced => nothing runs /etc/rc.  Recover. */
		emergency("capability engine did not start; entering recovery");
		return (state_func_t) single_user;
	}
	if (oi_await_convergence() != 0) {
		emergency("serviced did not converge; entering recovery");
		return (state_func_t) single_user;
	}
	/*
	 * / is read-write now that /etc/rc has run.  Retry the control socket
	 * that could not bind during the read-only early boot.
	 */
	oi_ctl_try_setup();
	return (state_func_t) read_ttys;
}

/*
 * Wait for serviced to signal boot convergence over its authenticated,
 * per-instance authority channel after running /etc/rc and launching native
 * services.  The engine kqueue is serviced meanwhile so serviced's
 * channel/procdesc events -- including crash and restart -- are handled.
 *
 * There is deliberately no time deadline: /etc/rc has no knowable
 * duration (fsck, key generation, network/entropy waits), and init
 * historically waited on it indefinitely.  Recovery is triggered only by
 * serviced *permanently* dying -- the restart circuit breaker tripping --
 * not by a clock, so a legitimately slow boot is never cut short.  A
 * wedged-but-alive serviced hangs boot exactly as a wedged /etc/rc hung
 * init before; that remains an operator/console matter.
 *
 * Returns 0 on convergence, -1 if serviced has permanently failed.
 */
static int
oi_await_convergence(void)
{
	struct kevent kev;
	struct timespec ts;
	int nev;

	BOOTTRACE("awaiting serviced convergence");
	for (;;) {
		if (authority_proto_is_ready()) {
			BOOTTRACE("serviced converged");
			return (0);
		}
		if (bootstrap_has_given_up()) {
			warning("serviced permanently failed before convergence");
			return (-1);
		}

		if (oi_kq < 0) {
			sleep(1);
			oi_drain_children();
			continue;
		}
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		nev = kevent(oi_kq, NULL, 0, &kev, 1, &ts);
		if (nev == -1) {
			if (errno != EINTR)
				warning("kevent awaiting convergence: %m");
		} else if (nev > 0) {
			if (kev.filter == EVFILT_SIGNAL &&
			    (int)kev.ident == SIGCHLD)
				oi_drain_children();
			else
				oi_dispatch(&kev);
		}
		oi_drain_children();
	}
}

/*
 * Bind PID 1's control socket (/var/run/authorityd.sock), idempotently.  Called
 * from oi_engine_start (before /etc/rc) and again after convergence: the early
 * attempt fails with EROFS because / is still read-only, so the socket must be
 * retried once serviced has run /etc/rc and remounted / read-write.
 */
static void
oi_ctl_try_setup(void)
{
	struct kevent kev;
	struct stat sb;

	/*
	 * On a read-write root (ZFS root images) the early-boot bind
	 * SUCCEEDS — and then rc.d/cleanvar wipes /var/run, unlinking the
	 * socket path out from under the live listener.  A path check is
	 * therefore mandatory on the post-convergence retry: a listener
	 * whose filesystem name is gone is unreachable by every client
	 * and equivalent to no socket at all (this was half of the
	 * 2026-08-14 unshutdownable-guest wedge).  Tear it down and
	 * rebind on the now-stable /var/run.
	 */
	if (oi_ctl_up) {
		if (stat(od.cfg.control_socket, &sb) == 0) {
			/*
			 * Socket healthy (bound early, survived rc).  The
			 * post-convergence call still owes the deferred
			 * signal shield; apply_signal_shield is idempotent.
			 */
			if (oi_engine_up && apply_signal_shield() == -1)
				warning("signal shield not raised; "
				    "signal ABI stays open");
			return;
		}
		warning("control socket path vanished (rc cleanup?); "
		    "rebinding");
		ctl_teardown();
		oi_ctl_up = false;
	}
	/* control.c registers connection events on event_kq. */
	event_kq = oi_kq;
	if (ctl_setup() == -1) {
		warning("authority control socket unavailable (will retry): %m");
		return;
	}
	oi_ctl_up = true;
	EV_SET(&kev, ctl_fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(oi_kq, &kev, 1, NULL, 0, NULL) == -1)
		warning("kevent control socket: %m");
	/*
	 * The signal ABI is now redundant: the control socket is the
	 * authenticated lifecycle path, so the deferred CP_SF_SIGNAL
	 * shield can go up.  Until this point shutdown(8)'s fallback
	 * kill(1, SIGINT) must keep working, or a boot that never binds
	 * the socket is unshutdownable.
	 */
	if (oi_engine_up && apply_signal_shield() == -1)
		warning("signal shield not raised; signal ABI stays open");
}

static void
oi_engine_start(void)
{

	if (oi_engine_up)
		return;
	if (oi_kq < 0) {
		emergency("no kqueue; capability world unavailable");
		return;
	}

	BOOTTRACE("authority engine starting...");

	if (!oi_mac_up) {
		config_init_defaults(&od.cfg);
		if (config_load(&od.cfg, AUTHORITYD_DEFAULT_CONFFILE) != 0) {
			warning("authority: config error in %s; "
			    "capability world disabled",
			    AUTHORITYD_DEFAULT_CONFFILE);
			return;
		}
		strlcpy(od.conffile, AUTHORITYD_DEFAULT_CONFFILE,
		    sizeof(od.conffile));

		/*
		 * PID 1 is already the real-init reaper: verify rather
		 * than acquire (PROC_REAP_ACQUIRE would return EBUSY).
		 */
		{
			struct procctl_reaper_status rs;

			memset(&rs, 0, sizeof(rs));
			if (procctl(P_PID, getpid(), PROC_REAP_STATUS,
			    &rs) == -1)
				warning("PROC_REAP_STATUS: %m");
			else if ((rs.rs_flags & REAPER_STATUS_OWNED) == 0 ||
			    (rs.rs_flags & REAPER_STATUS_REALINIT) == 0)
				warning("PID 1 lacks real-init reaper "
				    "status (flags %#x)", rs.rs_flags);
		}

		if (mac_capability_setup() == -1) {
			emergency("mac_capability unavailable; "
			    "capability world disabled");
			return;
		}
		oi_mac_up = true;
	}

	oi_ctl_try_setup();

	od.shutting_down = false;
	if (bootstrap_start(oi_kq) == -1) {
		warning("bootstrap: serviced start failed; "
		    "running with rc services only");
		return;
	}

	od.running = true;
	oi_engine_up = true;
	syslog(LOG_INFO, "authority engine started; serviced pid %jd",
	    (intmax_t)bootstrap_pid());
	BOOTTRACE("authority engine started");
}

/*
 * Translate an authenticated control-socket lifecycle request into a
 * state-machine transition.  The socket-ABI counterpart of
 * transition_handler(); the op-to-transition mapping is identical to
 * the signal mapping documented in the init behavior audit (section
 * 14), so both interfaces drive the same states.
 */
static void
oi_lifecycle_apply(int op)
{
	bool to_death;

	/* States from which a shutdown request runs the full death
	 * path (rc.shutdown etc.); otherwise the minimal one.  Matches
	 * transition_handler(). */
	to_death = (current_state == read_ttys || current_state == multi_user ||
	    current_state == clean_ttys || current_state == catatonia);

	/*
	 * Assign howto/Reboot outright (never |=): unlike the signal
	 * handler, which fires once and tears down immediately, a control
	 * request could arrive after a prior one, and OR-accumulated
	 * flags from an un-torn-down earlier request would corrupt the
	 * reboot mode.
	 */
	switch (op) {
	case CTL_OP_POWEROFF:
		howto = RB_HALT | RB_POWEROFF;
		Reboot = true;
		requested_transition = to_death ? death : death_single;
		break;
	case CTL_OP_HALT:
		howto = RB_HALT;
		Reboot = true;
		requested_transition = to_death ? death : death_single;
		break;
	case CTL_OP_POWERCYCLE:
		howto = RB_POWERCYCLE;
		Reboot = true;
		requested_transition = to_death ? death : death_single;
		break;
	case CTL_OP_REBOOT:
		howto = RB_AUTOBOOT;
		Reboot = true;
		requested_transition = to_death ? death : death_single;
		break;
	case CTL_OP_SINGLE:
		Reboot = false;
		requested_transition = to_death ? death : death_single;
		break;
	case CTL_OP_REROOT:
		requested_transition = reroot;
		break;
	case CTL_OP_RESCAN:
		if (to_death)
			requested_transition = clean_ttys;
		break;
	case CTL_OP_CATATONIA:
		if (current_state == runcom || current_state == read_ttys ||
		    current_state == clean_ttys ||
		    current_state == multi_user || current_state == catatonia)
			requested_transition = catatonia;
		break;
	default:
		warning("unknown lifecycle op %d", op);
		break;
	}
}

/*
 * Dispatch one non-SIGCHLD kevent for the Authority engine.  Mirrors the
 * non-signal dispatch in event.c's event_loop().
 */
static void
oi_dispatch(struct kevent *kev)
{
	int cfd;

	cfd = oi_ctl_up ? ctl_fd() : -1;

	if (kev->filter == EVFILT_READ &&
	    (int)kev->ident == cfd && kev->udata == NULL) {
		if (!od.shutting_down)
			(void)ctl_accept();
		return;
	}

	if (oi_ctl_up && ctl_is_conn_event(kev)) {
		int action;

		action = ctl_conn_event(kev);
		if (action & CTL_ACTION_LIFECYCLE) {
			/*
			 * Authenticated system lifecycle request — the
			 * control-socket replacement for init(8)'s signal
			 * ABI.  The opcode rides in the action's high bits
			 * (from this exact connection), so translate it into
			 * a state transition just as transition_handler()
			 * does for a signal, without async-signal-safety
			 * constraints and without a shared-state race.
			 */
			oi_lifecycle_apply(CTL_ACTION_OP(action));
		}
		/*
		 * CTL_ACTION_SHUTDOWN cannot occur here: cmd_shutdown()
		 * rejects CTL_OP_SHUTDOWN when authorityd is PID 1.  The
		 * whole-system shutting_down flag is owned by the death
		 * path (oi_world_stop); it must never be set from the
		 * multi_user dispatch, or the level-triggered listener
		 * livelocks once new connections stop being accepted.
		 */
		return;
	}

	if (bootstrap_is_procdesc(kev)) {
		bootstrap_handle_exit(kev, oi_kq);
		return;
	}

	if (bootstrap_is_channel(kev)) {
		if (kev->flags & EV_EOF) {
			syslog(LOG_INFO, "serviced closed channel");
			bootstrap_handle_channel_eof();
		} else {
			authority_proto_dispatch();
		}
		return;
	}

	if (bootstrap_is_timer(kev)) {
		bootstrap_handle_timer(oi_kq);
		return;
	}
}

/*
 * Reap every waitable child, dispatching known session children.
 * pdfork()ed children (serviced) are procdesc-managed and never
 * returned by waitpid(), so this cannot race bootstrap_handle_exit().
 */
static void
oi_drain_children(void)
{
	pid_t pid;

	while ((pid = waitpid(-1, (int *)0, WNOHANG)) > 0)
		collect_child(pid);
}

/*
 * Stop the managed capability world with a bounded deadline:
 * graceful stop via bootstrap, SIGKILL through the retained procdesc
 * on timeout.  Runs after /etc/rc.shutdown (whose adapters may need
 * serviced) and before the global process sweep.
 */
static void
oi_world_stop(void)
{
	struct kevent kev;
	struct timespec ts;
	time_t deadline;
	int nev;

	if (!oi_engine_up && bootstrap_is_stopped())
		return;
	if (oi_kq < 0)
		return;

	BOOTTRACE("stopping capability world");
	od.shutting_down = true;
	bootstrap_stop();

	deadline = time(NULL) + WORLD_WATCH;
	while (!bootstrap_is_stopped() && time(NULL) < deadline) {
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		nev = kevent(oi_kq, NULL, 0, &kev, 1, &ts);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			warning("kevent during world stop: %m");
			break;
		}
		if (nev > 0) {
			if (kev.filter == EVFILT_SIGNAL &&
			    (int)kev.ident == SIGCHLD)
				oi_drain_children();
			else
				oi_dispatch(&kev);
		}
		oi_drain_children();
	}

	if (!bootstrap_is_stopped()) {
		warning("serviced did not stop in %d seconds; killing",
		    WORLD_WATCH);
		bootstrap_signal(SIGKILL);
		deadline = time(NULL) + 5;
		while (!bootstrap_is_stopped() && time(NULL) < deadline) {
			ts.tv_sec = 1;
			ts.tv_nsec = 0;
			nev = kevent(oi_kq, NULL, 0, &kev, 1, &ts);
			if (nev > 0) {
				if (kev.filter == EVFILT_SIGNAL &&
				    (int)kev.ident == SIGCHLD)
					oi_drain_children();
				else
					oi_dispatch(&kev);
			}
			oi_drain_children();
		}
	}

	oi_engine_up = false;
	BOOTTRACE("capability world stopped");
}

static void
execute_script(char *argv[])
{
	struct sigaction sa;
	char* sh_argv[3 + SCRIPT_ARGV_SIZE];
	const char *shell, *script;
	int error, sh_argv_len, i;

	bzero(&sa, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	open_console();

	sigprocmask(SIG_SETMASK, &sa.sa_mask, NULL);
	setprocresources(RESOURCE_RC);

	/*
	 * Try to directly execute the script first.  If it
	 * fails, try the old method of passing the script path
	 * to sh(1).  Don't complain if it fails because of
	 * the missing execute bit.
	 */
	script = argv[0];
	error = access(script, X_OK);
	if (error == 0) {
		execv(script, argv);
		warning("can't directly exec %s: %m", script);
	} else if (errno != EACCES) {
		warning("can't access %s: %m", script);
	}

	shell = get_shell();
	sh_argv[0] = __DECONST(char*, shell);
	sh_argv_len = 1;
	if (strcmp(shell, _PATH_BSHELL) == 0) {
		sh_argv[1] = __DECONST(char*, "-o");
		sh_argv[2] = __DECONST(char*, "verify");
		sh_argv_len = 3;
	}
	for (i = 0; i != SCRIPT_ARGV_SIZE; ++i)
		sh_argv[i + sh_argv_len] = argv[i];
	execv(shell, sh_argv);
	stall("can't exec %s for %s: %m", shell, script);
}

/*
 * Run a shell script.
 * Returns 0 on success, otherwise the next transition to enter:
 *  - single_user if fork/execv/waitpid failed, or if the script
 *    terminated with a signal or exit code != 0.
 *  - death_single if a SIGTERM was delivered.
 */
static state_func_t
run_script(const char *script)
{
	pid_t pid, wpid;
	int status;
	char *argv[SCRIPT_ARGV_SIZE];
	const char *shell;

	shell = get_shell();

	if ((pid = fork()) == 0) {

		char _autoboot[] = "autoboot";

		argv[0] = __DECONST(char *, script);
		argv[1] = runcom_mode == AUTOBOOT ? _autoboot : NULL;
		argv[2] = NULL;

		execute_script(argv);
		sleep(STALL_TIMEOUT);
		_exit(1);	/* force single user mode */
	}

	if (pid == -1) {
		emergency("can't fork for %s on %s: %m", shell, script);
		while (waitpid(-1, (int *) 0, WNOHANG) > 0)
			continue;
		sleep(STALL_TIMEOUT);
		return (state_func_t) single_user;
	}

	requested_transition = 0;
	do {
		if ((wpid = waitpid(-1, &status, WUNTRACED)) != -1)
			collect_child(wpid);
		if (requested_transition == death_single ||
		    requested_transition == reroot)
			return (state_func_t) requested_transition;
		if (wpid == -1) {
			if (errno == EINTR)
				continue;
			warning("wait for %s on %s failed: %m; going to "
			    "single user mode", shell, script);
			return (state_func_t) single_user;
		}
		if (wpid == pid && WIFSTOPPED(status)) {
			warning("%s on %s stopped, restarting\n",
			    shell, script);
			kill(pid, SIGCONT);
			wpid = -1;
		}
	} while (wpid != pid);

	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM &&
	    requested_transition == catatonia) {
		/* /etc/rc executed /sbin/reboot; wait for the end quietly */
		sigset_t s;

		sigfillset(&s);
		for (;;)
			sigsuspend(&s);
	}

	if (!WIFEXITED(status)) {
		warning("%s on %s terminated abnormally, going to single "
		    "user mode", shell, script);
		return (state_func_t) single_user;
	}

	if (WEXITSTATUS(status))
		return (state_func_t) single_user;

	return (state_func_t) 0;
}

static int
start_session_db(void)
{
	if (session_db && (*session_db->close)(session_db))
		emergency("session database close: %m");
	if ((session_db = dbopen(NULL, O_RDWR, 0, DB_HASH, NULL)) == NULL) {
		emergency("session database open: %m");
		return (1);
	}
	return (0);

}

static void
add_session(session_t *sp)
{
	DBT key;
	DBT data;

	key.data = &sp->se_process;
	key.size = sizeof sp->se_process;
	data.data = &sp;
	data.size = sizeof sp;

	if ((*session_db->put)(session_db, &key, &data, 0))
		emergency("insert %d: %m", sp->se_process);
}

static void
del_session(session_t *sp)
{
	DBT key;

	key.data = &sp->se_process;
	key.size = sizeof sp->se_process;

	if ((*session_db->del)(session_db, &key, 0))
		emergency("delete %d: %m", sp->se_process);
}

static session_t *
find_session(pid_t pid)
{
	DBT key;
	DBT data;
	session_t *ret;

	if (session_db == NULL)
		return (NULL);
	key.data = &pid;
	key.size = sizeof pid;
	if ((*session_db->get)(session_db, &key, &data, 0) != 0)
		return (NULL);
	bcopy(data.data, (char *)&ret, sizeof(ret));
	return (ret);
}

static char **
construct_argv(char *command)
{
	int argc = 0;
	char **argv = (char **) malloc(((strlen(command) + 1) / 2 + 1)
						* sizeof (char *));

	if (argv == NULL)
		return (NULL);
	if ((argv[argc++] = strk(command)) == NULL) {
		free(argv);
		return (NULL);
	}
	while ((argv[argc++] = strk((char *) 0)) != NULL)
		continue;
	return argv;
}

static void
free_session(session_t *sp)
{
	free(sp->se_device);
	if (sp->se_getty) {
		free(sp->se_getty);
		free(sp->se_getty_argv_space);
		free(sp->se_getty_argv);
	}
	if (sp->se_window) {
		free(sp->se_window);
		free(sp->se_window_argv_space);
		free(sp->se_window_argv);
	}
	if (sp->se_type)
		free(sp->se_type);
	free(sp);
}

static session_t *
new_session(session_t *sprev, struct ttyent *typ)
{
	session_t *sp;

	if ((typ->ty_status & TTY_ON) == 0 ||
	    typ->ty_name == 0 ||
	    typ->ty_getty == 0)
		return 0;

	sp = (session_t *) calloc(1, sizeof (session_t));
	if (sp == NULL) {
		emergency("calloc: %m");
		return 0;
	}

	sp->se_flags |= SE_PRESENT;

	if ((typ->ty_status & TTY_IFEXISTS) != 0)
		sp->se_flags |= SE_IFEXISTS;

	if ((typ->ty_status & TTY_IFCONSOLE) != 0)
		sp->se_flags |= SE_IFCONSOLE;

	if (asprintf(&sp->se_device, "%s%s", _PATH_DEV, typ->ty_name) < 0) {
		emergency("asprintf: %m");
		free(sp);
		return 0;
	}

	if (setupargv(sp, typ) == 0) {
		free_session(sp);
		return (0);
	}

	sp->se_next = 0;
	if (sprev == NULL) {
		sessions = sp;
		sp->se_prev = 0;
	} else {
		sprev->se_next = sp;
		sp->se_prev = sprev;
	}

	return sp;
}

static int
setupargv(session_t *sp, struct ttyent *typ)
{

	if (sp->se_getty) {
		free(sp->se_getty);
		free(sp->se_getty_argv_space);
		free(sp->se_getty_argv);
	}
	if (asprintf(&sp->se_getty, "%s %s", typ->ty_getty, typ->ty_name) < 0) {
		emergency("asprintf: %m");
		sp->se_getty = NULL;
		sp->se_getty_argv_space = NULL;
		sp->se_getty_argv = NULL;
		return (0);
	}
	sp->se_getty_argv_space = strdup(sp->se_getty);
	sp->se_getty_argv = sp->se_getty_argv_space == NULL ? NULL :
	    construct_argv(sp->se_getty_argv_space);
	if (sp->se_getty_argv == NULL) {
		warning("can't parse getty for port %s", sp->se_device);
		free(sp->se_getty);
		free(sp->se_getty_argv_space);
		sp->se_getty = sp->se_getty_argv_space = 0;
		return (0);
	}
	if (sp->se_window) {
		free(sp->se_window);
		free(sp->se_window_argv_space);
		free(sp->se_window_argv);
	}
	sp->se_window = sp->se_window_argv_space = 0;
	sp->se_window_argv = 0;
	if (typ->ty_window) {
		sp->se_window = strdup(typ->ty_window);
		sp->se_window_argv_space = sp->se_window == NULL ? NULL :
		    strdup(sp->se_window);
		sp->se_window_argv = sp->se_window_argv_space == NULL ? NULL :
		    construct_argv(sp->se_window_argv_space);
		if (sp->se_window_argv == NULL) {
			warning("can't parse window for port %s",
			    sp->se_device);
			free(sp->se_window_argv_space);
			free(sp->se_window);
			sp->se_window = sp->se_window_argv_space = 0;
			return (0);
		}
	}
	if (sp->se_type)
		free(sp->se_type);
	sp->se_type = typ->ty_type ? strdup(typ->ty_type) : 0;
	return (1);
}

static state_func_t
read_ttys(void)
{
	session_t *sp, *snext;
	struct ttyent *typ;

	/*
	 * Destroy any previous session state.
	 * There shouldn't be any, but just in case...
	 */
	for (sp = sessions; sp; sp = snext) {
		snext = sp->se_next;
		free_session(sp);
	}
	sessions = 0;
	if (start_session_db())
		return (state_func_t) single_user;

	/*
	 * Allocate a session entry for each active port.
	 * Note that sp starts at 0.
	 */
	while ((typ = getttyent()) != NULL)
		if ((snext = new_session(sp, typ)) != NULL)
			sp = snext;

	endttyent();

	return (state_func_t) multi_user;
}

static void
start_window_system(session_t *sp)
{
	pid_t pid;
	sigset_t mask;
	char term[64], *env[2];
	int status;

	if ((pid = fork()) == -1) {
		emergency("can't fork for window system on port %s: %m",
		    sp->se_device);
		/* hope that getty fails and we can try again */
		return;
	}
	if (pid) {
		waitpid(-1, &status, 0);
		return;
	}

	/* reparent window process to PID 1 to not make a zombie on exit */
	if ((pid = fork()) == -1) {
		emergency("can't fork for window system on port %s: %m",
		    sp->se_device);
		_exit(1);
	}
	if (pid)
		_exit(0);

	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	if (setsid() < 0)
		emergency("setsid failed (window) %m");

	setprocresources(RESOURCE_WINDOW);
	if (sp->se_type) {
		/* Don't use malloc after fork */
		strcpy(term, "TERM=");
		strlcat(term, sp->se_type, sizeof(term));
		env[0] = term;
		env[1] = NULL;
	}
	else
		env[0] = NULL;
	execve(sp->se_window_argv[0], sp->se_window_argv, env);
	stall("can't exec window system '%s' for port %s: %m",
		sp->se_window_argv[0], sp->se_device);
	_exit(1);
}

/*
 * Store the ambient lookup channel client end serviced forwarded (§21) and
 * make it durable across the getty fork/exec: unlock its clofork limit so it
 * survives fork(2) and clear FD_CLOEXEC so it survives execve(2).  A previously
 * installed channel is replaced (serviced sends this once per session, but a
 * serviced restart may resend).  Best-effort throughout: on any failure the fd
 * is dropped and oi_ambient_lookup_fd left at -1, so getty spawning simply
 * proceeds without an ambient channel.
 */
int
authority_init_set_ambient_lookup(int fd)
{

	int saved;

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (fcntl(fd, F_SETFD, 0) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (oi_ambient_lookup_fd >= 0)
		(void)close(oi_ambient_lookup_fd);
	oi_ambient_lookup_fd = fd;
	return (0);
}

static pid_t
start_getty(session_t *sp)
{
	pid_t pid;
	sigset_t mask;
	time_t current_time = time((time_t *) 0);
	int too_quick = 0;
	char term[64], *env[2];

	if (current_time >= sp->se_started &&
	    current_time - sp->se_started < GETTY_SPACING) {
		if (++sp->se_nspace > GETTY_NSPACE) {
			sp->se_nspace = 0;
			too_quick = 1;
		}
	} else
		sp->se_nspace = 0;

	/*
	 * fork(), not vfork() -- we can't afford to block.
	 */
	if ((pid = fork()) == -1) {
		emergency("can't fork for getty on port %s: %m",
		    sp->se_device);
		return -1;
	}

	if (pid)
		return pid;

	if (too_quick) {
		warning("getty repeating too quickly on port %s, sleeping %d secs",
		    sp->se_device, GETTY_SLEEP);
		sleep((unsigned) GETTY_SLEEP);
	}

	if (sp->se_window) {
		start_window_system(sp);
		sleep(WINDOW_WAIT);
	}

	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	setprocresources(RESOURCE_GETTY);
	if (sp->se_type) {
		/* Don't use malloc after fork */
		strcpy(term, "TERM=");
		strlcat(term, sp->se_type, sizeof(term));
		env[0] = term;
		env[1] = NULL;
	} else
		env[0] = NULL;
	/*
	 * §21 getty carry: pin the ambient lookup channel at the fixed
	 * descriptor number so login (which getty execs with a rebuilt
	 * environment, dropping SERVICE_LOOKUP_FD) inherits it.  Post-fork
	 * child: async-signal-safe calls only (dup2/fcntl), no malloc, no
	 * logging.  Best-effort -- a dup2/fcntl failure must never stop getty,
	 * so we ignore errors and fall through to execve regardless.
	 */
	if (oi_ambient_lookup_fd >= 0 &&
	    oi_ambient_lookup_fd != SERVICE_LOOKUP_FIXED_FD) {
		if (dup2(oi_ambient_lookup_fd, SERVICE_LOOKUP_FIXED_FD) != -1)
			(void)fcntl(SERVICE_LOOKUP_FIXED_FD, F_SETFD, 0);
	} else if (oi_ambient_lookup_fd == SERVICE_LOOKUP_FIXED_FD)
		(void)fcntl(SERVICE_LOOKUP_FIXED_FD, F_SETFD, 0);
	execve(sp->se_getty_argv[0], sp->se_getty_argv, env);
	stall("can't exec getty '%s' for port %s: %m",
		sp->se_getty_argv[0], sp->se_device);
	_exit(1);
}

/*
 * Return 1 if the session is defined as "onifexists"
 * or "onifconsole" and the device node does not exist.
 */
static int
session_has_no_tty(session_t *sp)
{
	int fd;

	if ((sp->se_flags & SE_IFEXISTS) == 0 &&
	    (sp->se_flags & SE_IFCONSOLE) == 0)
		return (0);

	fd = open(sp->se_device, O_RDONLY | O_NONBLOCK, 0);
	if (fd < 0) {
		if (errno == ENOENT)
			return (1);
		return (0);
	}

	close(fd);
	return (0);
}

static void
collect_child(pid_t pid)
{
	session_t *sp, *sprev, *snext;

	if (! sessions)
		return;

	if (! (sp = find_session(pid)))
		return;

	del_session(sp);
	sp->se_process = 0;

	if (sp->se_flags & SE_SHUTDOWN ||
	    session_has_no_tty(sp)) {
		if ((sprev = sp->se_prev) != NULL)
			sprev->se_next = sp->se_next;
		else
			sessions = sp->se_next;
		if ((snext = sp->se_next) != NULL)
			snext->se_prev = sp->se_prev;
		free_session(sp);
		return;
	}

	if ((pid = start_getty(sp)) == -1) {
		/* serious trouble */
		requested_transition = clean_ttys;
		return;
	}

	sp->se_process = pid;
	sp->se_started = time((time_t *) 0);
	add_session(sp);
}

static const char *
get_current_state(void)
{

	if (current_state == single_user)
		return ("single-user");
	if (current_state == runcom)
		return ("runcom");
	if (current_state == establish_authority)
		return ("establish-authority");
	if (current_state == read_ttys)
		return ("read-ttys");
	if (current_state == multi_user)
		return ("multi-user");
	if (current_state == clean_ttys)
		return ("clean-ttys");
	if (current_state == catatonia)
		return ("catatonia");
	if (current_state == death)
		return ("death");
	if (current_state == death_single)
		return ("death-single");
	return ("unknown");
}

static void
boottrace_transition(int sig)
{
	const char *action;

	switch (sig) {
	case SIGUSR2:
		action = "halt & poweroff";
		break;
	case SIGUSR1:
		action = "halt";
		break;
	case SIGINT:
		action = "reboot";
		break;
	case SIGWINCH:
		action = "powercycle";
		break;
	case SIGTERM:
		action = Reboot ? "reboot" : "single-user";
		break;
	default:
		BOOTTRACE("signal %d from %s", sig, get_current_state());
		return;
	}

	/* Trace the shutdown reason. */
	SHUTTRACE("%s from %s", action, get_current_state());
}

/*
 * Catch a signal and request a state transition.  The traditional
 * init(8) control ABI, preserved so shutdown(8), reboot(8), and
 * halt(8) keep working during the migration.
 */
static void
transition_handler(int sig)
{

	boottrace_transition(sig);
	switch (sig) {
	case SIGHUP:
		if (current_state == read_ttys || current_state == multi_user ||
		    current_state == clean_ttys || current_state == catatonia)
			requested_transition = clean_ttys;
		break;
	case SIGUSR2:
		howto = RB_POWEROFF;
	case SIGUSR1:
		howto |= RB_HALT;
	case SIGWINCH:
	case SIGINT:
		if (sig == SIGWINCH)
			howto |= RB_POWERCYCLE;
		Reboot = true;
	case SIGTERM:
		if (current_state == read_ttys || current_state == multi_user ||
		    current_state == clean_ttys || current_state == catatonia)
			requested_transition = death;
		else
			requested_transition = death_single;
		break;
	case SIGTSTP:
		if (current_state == runcom || current_state == read_ttys ||
		    current_state == clean_ttys ||
		    current_state == multi_user || current_state == catatonia)
			requested_transition = catatonia;
		break;
	case SIGEMT:
		requested_transition = reroot;
		break;
	default:
		requested_transition = 0;
		break;
	}
}

/*
 * Take the system multiuser.  The wait loop is kqueue-driven so the
 * Authority engine (control socket, serviced procdesc/channel, restart
 * timers) is serviced from PID 1 alongside session reaping.
 */
static state_func_t
multi_user(void)
{
	static bool inmultiuser = false;
	struct kevent kev;
	struct timespec ctl_ts;
	pid_t pid;
	session_t *sp;
	int nev;

	requested_transition = 0;

	/*
	 * If the administrator has not set the security level to -1
	 * to indicate that the kernel should not run multiuser in secure
	 * mode, and the run script has not set a higher level of security
	 * than level 1, then put the kernel into secure mode.
	 */
	if (getsecuritylevel() == 0)
		setsecuritylevel(1);

	for (sp = sessions; sp; sp = sp->se_next) {
		if (sp->se_process)
			continue;
		if (session_has_no_tty(sp))
			continue;
		if ((pid = start_getty(sp)) == -1) {
			/* serious trouble */
			requested_transition = clean_ttys;
			break;
		}
		sp->se_process = pid;
		sp->se_started = time((time_t *) 0);
		add_session(sp);
	}

	if (requested_transition == 0 && !inmultiuser) {
		inmultiuser = true;
		/* This marks the change from boot-time tracing to run-time. */
		RUNTRACE("multi-user start");
	}

	while (!requested_transition) {
		if (oi_kq < 0) {
			/* Degraded mode: no kqueue; stock init behavior. */
			if ((pid = waitpid(-1, (int *) 0, 0)) != -1)
				collect_child(pid);
			continue;
		}
		/*
		 * Wake periodically to self-heal the control socket: the
		 * one-shot post-convergence bind can fail (or the bound
		 * path can be unlinked by rc) and a PID 1 with neither
		 * socket nor retry is a lifecycle dead end.  The check is
		 * one stat(2) every 30s when healthy.
		 */
		ctl_ts.tv_sec = 30;
		ctl_ts.tv_nsec = 0;
		nev = kevent(oi_kq, NULL, 0, &kev, 1, &ctl_ts);
		if (nev == 0) {
			oi_ctl_try_setup();
			continue;
		}
		if (nev == -1) {
			if (errno == EINTR) {
				/* A transition signal or SIGALRM. */
				oi_drain_children();
				continue;
			}
			/*
			 * A persistent (non-EINTR) kevent error would spin
			 * PID 1 at full CPU and flood the log.  Reap what we
			 * can and pause a second so a degraded kqueue cannot
			 * livelock init.
			 */
			warning("kevent in multi-user: %m");
			oi_drain_children();
			sleep(1);
			continue;
		}
		if (nev > 0) {
			if (kev.filter == EVFILT_SIGNAL &&
			    (int)kev.ident == SIGCHLD)
				oi_drain_children();
			else
				oi_dispatch(&kev);
		}
		oi_drain_children();
	}

	return (state_func_t) requested_transition;
}

/*
 * This is an (n*2)+(n^2) algorithm.  We hope it isn't run often...
 */
static state_func_t
clean_ttys(void)
{
	session_t *sp, *sprev;
	struct ttyent *typ;
	int devlen;
	char *old_getty, *old_window, *old_type;

	/*
	 * mark all sessions for death, (!SE_PRESENT)
	 * as we find or create new ones they'll be marked as keepers,
	 * we'll later nuke all the ones not found in /etc/ttys
	 */
	for (sp = sessions; sp != NULL; sp = sp->se_next)
		sp->se_flags &= ~SE_PRESENT;

	devlen = sizeof(_PATH_DEV) - 1;
	while ((typ = getttyent()) != NULL) {
		for (sprev = 0, sp = sessions; sp; sprev = sp, sp = sp->se_next)
			if (strcmp(typ->ty_name, sp->se_device + devlen) == 0)
				break;

		if (sp) {
			/* we want this one to live */
			sp->se_flags |= SE_PRESENT;
			if ((typ->ty_status & TTY_ON) == 0 ||
			    typ->ty_getty == 0) {
				sp->se_flags |= SE_SHUTDOWN;
				kill(sp->se_process, SIGHUP);
				continue;
			}
			sp->se_flags &= ~SE_SHUTDOWN;
			old_getty = sp->se_getty ? strdup(sp->se_getty) : 0;
			old_window = sp->se_window ? strdup(sp->se_window) : 0;
			old_type = sp->se_type ? strdup(sp->se_type) : 0;
			if (setupargv(sp, typ) == 0) {
				warning("can't parse getty for port %s",
					sp->se_device);
				sp->se_flags |= SE_SHUTDOWN;
				kill(sp->se_process, SIGHUP);
			}
			else if (   !old_getty
				 || (!old_type && sp->se_type)
				 || (old_type && !sp->se_type)
				 || (!old_window && sp->se_window)
				 || (old_window && !sp->se_window)
				 || (strcmp(old_getty, sp->se_getty) != 0)
				 || (old_window && strcmp(old_window, sp->se_window) != 0)
				 || (old_type && strcmp(old_type, sp->se_type) != 0)
				) {
				/* Don't set SE_SHUTDOWN here */
				sp->se_nspace = 0;
				sp->se_started = 0;
				kill(sp->se_process, SIGHUP);
			}
			if (old_getty)
				free(old_getty);
			if (old_window)
				free(old_window);
			if (old_type)
				free(old_type);
			continue;
		}

		new_session(sprev, typ);
	}

	endttyent();

	/*
	 * sweep through and kill all deleted sessions
	 * ones who's /etc/ttys line was deleted (SE_PRESENT unset)
	 */
	for (sp = sessions; sp != NULL; sp = sp->se_next) {
		if ((sp->se_flags & SE_PRESENT) == 0) {
			sp->se_flags |= SE_SHUTDOWN;
			kill(sp->se_process, SIGHUP);
		}
	}

	return (state_func_t) multi_user;
}

/*
 * Block further logins.
 */
static state_func_t
catatonia(void)
{
	session_t *sp;

	for (sp = sessions; sp; sp = sp->se_next)
		sp->se_flags |= SE_SHUTDOWN;

	return (state_func_t) multi_user;
}

static void
alrm_handler(int sig)
{

	(void)sig;
	clang = true;
}

/*
 * Bring the system down to single user.  Order (audit section 15 plus
 * the capability world): revoke ttys, run /etc/rc.shutdown while
 * serviced remains available to migrated rc adapters, then stop the
 * managed capability world, then the global process sweep.
 */
static state_func_t
death(void)
{
	int block, blocked;
	size_t len;

	/* Temporarily block suspend. */
	len = sizeof(blocked);
	block = 1;
	if (sysctlbyname("kern.suspend_blocked", &blocked, &len,
	    &block, sizeof(block)) == -1)
		blocked = 0;

	/*
	 * Also revoke the TTY here.  Because runshutdown() may reopen
	 * the TTY whose getty we're killing here, there is no guarantee
	 * runshutdown() will perform the initial open() call, causing
	 * the terminal attributes to be misconfigured.
	 */
	revoke_ttys();

	/*
	 * Stop the managed capability world before rc.shutdown, not after.
	 * The capability services belong to serviced; leaving the manager
	 * running lets it restart providers against a world that is being
	 * torn down, and the resulting crash-loop can stall rc.shutdown
	 * into its watchdog.  rc.shutdown owns only the rc daemons.
	 */
	oi_world_stop();

	/* Try to run the rc.shutdown script within a period of time */
	runshutdown();

	/* Unblock suspend if we blocked it. */
	if (!blocked)
		sysctlbyname("kern.suspend_blocked", NULL, NULL,
		    &blocked, sizeof(blocked));

	return (state_func_t) death_single;
}

/*
 * Do what is necessary to reinitialize single user mode or reboot
 * from an incomplete state.
 */
static state_func_t
death_single(void)
{
	int i;
	pid_t pid;
	static const int death_sigs[2] = { SIGTERM, SIGKILL };

	revoke(_PATH_CONSOLE);

	/* A shutdown request may arrive before boot completed;
	 * make sure the capability world is not left running. */
	oi_world_stop();

	BOOTTRACE("start killing user processes");
	for (i = 0; i < 2; ++i) {
		if (kill(-1, death_sigs[i]) == -1 && errno == ESRCH)
			return (state_func_t) single_user;

		clang = false;
		alarm(DEATH_WATCH);
		do
			if ((pid = waitpid(-1, (int *)0, 0)) != -1)
				collect_child(pid);
		while (!clang && errno != ECHILD);

		if (errno == ECHILD)
			return (state_func_t) single_user;
	}

	warning("some processes would not die; ps axl advised");

	return (state_func_t) single_user;
}

static void
revoke_ttys(void)
{
	session_t *sp;

	for (sp = sessions; sp; sp = sp->se_next) {
		sp->se_flags |= SE_SHUTDOWN;
		kill(sp->se_process, SIGHUP);
		revoke(sp->se_device);
	}
}

/*
 * Run the system shutdown script.
 *
 * Exit codes:
 * -2       shutdown script terminated abnormally
 * -1       fatal error - can't run script
 * 0        good.
 * >0       some error (exit code)
 */
static int
runshutdown(void)
{
	pid_t pid, wpid;
	int status;
	int shutdowntimeout;
	size_t len;
	char *argv[SCRIPT_ARGV_SIZE];
	struct stat sb;

	BOOTTRACE("start rc.shutdown");

	/*
	 * rc.shutdown is optional.
	 */
	if (stat(_PATH_RUNDOWN, &sb) == -1 && errno == ENOENT)
		return 0;

	if ((pid = fork()) == 0) {
		char _reboot[]	= "reboot";
		char _single[]	= "single";
		char _path_rundown[] = _PATH_RUNDOWN;

		argv[0] = _path_rundown;
		argv[1] = Reboot ? _reboot : _single;
		argv[2] = NULL;

		execute_script(argv);
		_exit(1);
	}

	if (pid == -1) {
		emergency("can't fork for %s: %m", _PATH_RUNDOWN);
		while (waitpid(-1, (int *) 0, WNOHANG) > 0)
			continue;
		sleep(STALL_TIMEOUT);
		return -1;
	}

	len = sizeof(shutdowntimeout);
	if (sysctlbyname("kern.init_shutdown_timeout", &shutdowntimeout, &len,
	    NULL, 0) == -1 || shutdowntimeout < 2)
		shutdowntimeout = DEATH_SCRIPT;
	alarm(shutdowntimeout);
	clang = false;
	do {
		if ((wpid = waitpid(-1, &status, WUNTRACED)) != -1)
			collect_child(wpid);
		if (clang) {
			/* we were waiting for the sub-shell */
			kill(wpid, SIGTERM);
			warning("timeout expired for %s: %m; going to "
			    "single user mode", _PATH_RUNDOWN);
			BOOTTRACE("rc.shutdown's %d sec timeout expired",
				  shutdowntimeout);
			return -1;
		}
		if (wpid == -1) {
			if (errno == EINTR)
				continue;
			warning("wait for %s failed: %m; going to "
			    "single user mode", _PATH_RUNDOWN);
			return -1;
		}
		if (wpid == pid && WIFSTOPPED(status)) {
			warning("%s stopped, restarting\n",
			    _PATH_RUNDOWN);
			kill(pid, SIGCONT);
			wpid = -1;
		}
	} while (wpid != pid && !clang);

	/* Turn off the alarm */
	alarm(0);

	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM &&
	    requested_transition == catatonia) {
		/*
		 * /etc/rc.shutdown executed /sbin/reboot;
		 * wait for the end quietly
		 */
		sigset_t s;

		sigfillset(&s);
		for (;;)
			sigsuspend(&s);
	}

	if (!WIFEXITED(status)) {
		warning("%s terminated abnormally, going to "
		    "single user mode", _PATH_RUNDOWN);
		return -2;
	}

	if ((status = WEXITSTATUS(status)) != 0)
		warning("%s returned status %d", _PATH_RUNDOWN, status);

	return status;
}

static char *
strk(char *p)
{
	static char *t;
	char *q;
	int c;

	if (p)
		t = p;
	if (!t)
		return 0;

	c = *t;
	while (c == ' ' || c == '\t' )
		c = *++t;
	if (!c) {
		t = 0;
		return 0;
	}
	q = t;
	if (c == '\'') {
		c = *++t;
		q = t;
		while (c && c != '\'')
			c = *++t;
		if (!c)  /* unterminated string */
			q = t = 0;
		else
			*t++ = 0;
	} else {
		while (c && c != ' ' && c != '\t' )
			c = *++t;
		*t++ = 0;
		if (!c)
			t = 0;
	}
	return q;
}

static void
setprocresources(const char *cname)
{
	login_cap_t *lc;
	if ((lc = login_getclassbyname(cname, NULL)) != NULL) {
		setusercontext(lc, (struct passwd*)NULL, 0,
		    LOGIN_SETENV |
		    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES |
		    LOGIN_SETLOGINCLASS | LOGIN_SETCPUMASK);
		login_close(lc);
	}
}

/*
 * Run /etc/rc.final to execute scripts after all user processes have
 * been terminated.
 */
static void
runfinal(void)
{
	struct stat sb;
	pid_t other_pid, pid;
	sigset_t mask;

	/* Avoid any surprises. */
	alarm(0);

	/* rc.final is optional. */
	if (stat(_PATH_RUNFINAL, &sb) == -1 && errno == ENOENT)
		return;
	if (access(_PATH_RUNFINAL, X_OK) != 0) {
		warning("%s exists, but not executable", _PATH_RUNFINAL);
		return;
	}

	pid = fork();
	if (pid == 0) {
		/*
		 * Reopen stdin/stdout/stderr so that scripts can write to
		 * console.
		 */
		close(0);
		open(_PATH_DEVNULL, O_RDONLY);
		close(1);
		close(2);
		open_console();
		dup2(1, 2);
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		signal(SIGCHLD, SIG_DFL);
		execl(_PATH_RUNFINAL, _PATH_RUNFINAL, NULL);
		perror("execl(" _PATH_RUNFINAL ") failed");
		exit(1);
	}

	/* Wait for rc.final script to exit */
	while ((other_pid = waitpid(-1, NULL, 0)) != pid && other_pid > 0) {
		continue;
	}
}

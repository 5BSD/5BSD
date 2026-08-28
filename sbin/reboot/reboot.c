/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1980, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include <sys/boottrace.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <utmpx.h>

#include "authorityd_ctl.h"

extern char **environ;

#define PATH_NEXTBOOT "/boot/nextboot.conf"

static void usage(void) __dead2;
static uint64_t get_pageins(void);

static bool dofast;
static bool dohalt;
static bool donextboot;

#define E(...) do {				\
		if (force) {			\
			warn( __VA_ARGS__ );	\
			return;			\
		}				\
		err(1, __VA_ARGS__);		\
	} while (0)				\

static void
zfsbootcfg(const char *pool, bool force)
{
	const char * const av[] = {
		"zfsbootcfg",
		"-z",
		pool,
		"-n",
		"freebsd:nvstore",
		"-k",
		"nextboot_enable",
		"-v",
		"YES",
		NULL
	};
	int rv, status;
	pid_t p;

	rv = posix_spawnp(&p, av[0], NULL, NULL, __DECONST(char **, av),
	    environ);
	if (rv == -1)
		E("system zfsbootcfg");
	if (waitpid(p, &status, WEXITED) < 0) {
		if (errno == EINTR)
			return;
		E("waitpid zfsbootcfg");
	}
	if (WIFEXITED(status)) {
		int e = WEXITSTATUS(status);

		if (e == 0)
			return;
		if (e == 127)
			E("zfsbootcfg not found in path");
		E("zfsbootcfg returned %d", e);
	}
	if (WIFSIGNALED(status))
		E("zfsbootcfg died with signal %d", WTERMSIG(status));
	E("zfsbootcfg unexpected status %d", status);
}

static void
write_nextboot(const char *fn, const char *env, bool append, bool force)
{
	char tmp[PATH_MAX];
	FILE *fp;
	struct statfs sfs;
	ssize_t ret;
	int fd, tmpfd;
	bool supported = false;
	bool zfs = false;

	if (statfs("/boot", &sfs) != 0)
		err(1, "statfs /boot");
	if (strcmp(sfs.f_fstypename, "ufs") == 0) {
		/*
		 * Only UFS supports the full nextboot protocol.
		 */
		supported = true;
	} else if (strcmp(sfs.f_fstypename, "zfs") == 0) {
		zfs = true;
	}

	if (zfs) {
		char *slash;

		slash = strchr(sfs.f_mntfromname, '/');
		if (slash != NULL)
			*slash = '\0';
		zfsbootcfg(sfs.f_mntfromname, force);
	}

	if (strlcpy(tmp, fn, sizeof(tmp)) >= sizeof(tmp))
		E("Path too long %s", fn);
	if (strlcat(tmp, ".XXXXXX", sizeof(tmp)) >= sizeof(tmp))
		E("Path too long %s", fn);

	tmpfd = mkstemp(tmp);
	if (tmpfd == -1)
		E("mkstemp %s", tmp);

	fp = fdopen(tmpfd, "w");
	if (fp == NULL)
		E("fdopen %s", tmp);

	if (append) {
		if ((fd = open(fn, O_RDONLY)) < 0) {
			if (errno != ENOENT)
				E("open %s", fn);
		} else {
			do {
				ret = copy_file_range(fd, NULL, tmpfd, NULL,
				    SSIZE_MAX, 0);
				if (ret < 0)
					E("copy %s to %s", fn, tmp);
			} while (ret > 0);
			close(fd);
		}
	}

	if (fprintf(fp, "%s%s",
	    supported ? "nextboot_enable=\"YES\"\n" : "",
	    env != NULL ? env : "") < 0) {
		int e;

		e = errno;
		if (unlink(tmp))
			warn("unlink %s", tmp);
		errno = e;
		E("Can't write %s", tmp);
	}
	if (fsync(fileno(fp)) != 0)
		E("Can't fsync %s", fn);
	if (rename(tmp, fn) != 0) {
		int e;

		e = errno;
		if (unlink(tmp))
			warn("unlink %s", tmp);
		errno = e;
		E("Can't rename %s to %s", tmp, fn);
	}
	fclose(fp);
}

static char *
split_kv(char *raw)
{
	char *eq;
	int len;

	eq = strchr(raw, '=');
	if (eq == NULL)
		errx(1, "No = in environment string %s", raw);
	*eq++ = '\0';
	len = strlen(eq);
	if (len == 0)
		errx(1, "Invalid null value %s=", raw);
	if (eq[0] == '"') {
		if (len < 2 || eq[len - 1] != '"')
			errx(1, "Invalid string '%s'", eq);
		eq[len - 1] = '\0';
		return (eq + 1);
	}
	return (eq);
}

static void
add_env(char **env, const char *key, const char *value)
{
	char *oldenv;

	oldenv = *env;
	asprintf(env, "%s%s=\"%s\"\n", oldenv != NULL ? oldenv : "", key, value);
	if (env == NULL)
		errx(1, "No memory to build env array");
	free(oldenv);
}

/*
 * Ask authority-init to perform a lifecycle transition over its control
 * socket.  Returns 0 if accepted, an errno on a daemon-reported refusal,
 * or -1 (with errno) if the socket is absent/unusable — signalling that
 * the caller should fall back to the signal ABI.
 *
 * A minimal inline client is used deliberately rather than libauthorityctl:
 * reboot(8)/halt(8) live in /sbin and must not acquire a /usr runtime
 * dependency, since they have to work before /usr is mounted.
 */
static int
authority_lifecycle(uint32_t op)
{
	struct sockaddr_un un;
	struct ctl_request req;
	struct ctl_reply rpl;
	ssize_t n;
	size_t off;
	int fd, saved;

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, AUTHORITYD_CTL_SOCK, sizeof(un.sun_path));
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		saved = errno;
		close(fd);
		errno = saved;
		return (-1);		/* no authority-init socket: fall back */
	}

	memset(&req, 0, sizeof(req));
	req.version = CTL_VERSION;
	req.op = op;
	for (off = 0; off < sizeof(req); off += n) {
		n = send(fd, (char *)&req + off, sizeof(req) - off,
		    MSG_NOSIGNAL);
		if (n <= 0) {
			saved = (n == 0) ? EIO : errno;
			close(fd);
			errno = saved;
			return (-1);
		}
	}
	for (off = 0; off < sizeof(rpl); off += n) {
		n = read(fd, (char *)&rpl + off, sizeof(rpl) - off);
		if (n <= 0) {
			saved = (n == 0) ? ECONNRESET : errno;
			close(fd);
			errno = saved;
			return (-1);
		}
	}
	close(fd);
	return ((int)rpl.status);
}

static void
reboot_request(int howto)
{
	char sigstr[SIG2STR_MAX];
	uint32_t op =
	    howto & RB_POWERCYCLE ? CTL_OP_POWERCYCLE :
	    howto & RB_POWEROFF ? CTL_OP_POWEROFF :
	    howto & RB_HALT ? CTL_OP_HALT :
	    howto & RB_REROOT ? CTL_OP_REROOT :
	    CTL_OP_REBOOT;
	int signo =
	    howto & RB_POWERCYCLE ? SIGWINCH :
	    howto & RB_POWEROFF ? SIGUSR2 :
	    howto & RB_HALT ? SIGUSR1 :
	    howto & RB_REROOT ? SIGEMT :
	    SIGINT;
	int error;

	/*
	 * Prefer the authenticated Authority control socket: when PID 1 is
	 * authority-init, it is shielded from the signal ABI and lifecycle
	 * requests arrive over the socket.  Fall back to signalling init
	 * directly when the socket is absent (stock init, or authority-init
	 * before its capability engine has started).
	 */
	error = authority_lifecycle(op);
	if (error == 0) {
		BOOTTRACE("lifecycle op %u to authority-init", op);
		exit(0);
	}
	if (error > 0) {
		/*
		 * Socket present but the request was refused — e.g. a
		 * non-PID-1 authorityd owns the socket while the real init is
		 * a signalable stock init.  Fall back to the signal ABI
		 * rather than failing outright.
		 */
		warnx("authority-init lifecycle request refused (%s); "
		    "signalling init", strerror(error));
	}

	(void)sig2str(signo, sigstr);
	BOOTTRACE("SIG%s to init(8)...", sigstr);
	if (kill(1, signo) == -1)
		err(1, "SIG%s init", sigstr);
	exit(0);
}

/*
 * Different options are valid for different programs.
 */
#define GETOPT_REBOOT "cDde:fk:lNno:pqr"
#define GETOPT_NEXTBOOT "aDe:fk:o:"

int
main(int argc, char *argv[])
{
	struct utmpx utx;
	struct stat st;
	const struct passwd *pw;
	const char *progname, *user;
	const char *kernel = NULL, *getopts = GETOPT_REBOOT;
	char *env = NULL, *v;
	uint64_t pageins;
	int ch, howto = 0, i, sverrno;
	bool aflag, Dflag, fflag, lflag, Nflag, nflag, qflag;

	progname = getprogname();
	if (strncmp(progname, "fast", 4) == 0) {
		dofast = true;
		progname += 4;
	}
	if (strcmp(progname, "halt") == 0) {
		dohalt = true;
		howto = RB_HALT;
	} else if (strcmp(progname, "nextboot") == 0) {
		donextboot = true;
		getopts = GETOPT_NEXTBOOT; /* Note: reboot's extra opts return '?' */
	} else {
		/* reboot */
		howto = 0;
	}
	aflag = Dflag = fflag = lflag = Nflag = nflag = qflag = false;
	while ((ch = getopt(argc, argv, getopts)) != -1) {
		switch(ch) {
		case 'a':
			aflag = true;
			break;
		case 'c':
			howto |= RB_POWERCYCLE;
			break;
		case 'D':
			Dflag = true;
			break;
		case 'd':
			howto |= RB_DUMP;
			break;
		case 'e':
			v = split_kv(optarg);
			add_env(&env, optarg, v);
			break;
		case 'f':
			fflag = true;
			break;
		case 'k':
			kernel = optarg;
			break;
		case 'l':
			lflag = true;
			break;
		case 'n':
			nflag = true;
			howto |= RB_NOSYNC;
			break;
		case 'N':
			nflag = true;
			Nflag = true;
			break;
		case 'o':
			add_env(&env, "kernel_options", optarg);
			break;
		case 'p':
			howto |= RB_POWEROFF;
			break;
		case 'q':
			qflag = true;
			break;
		case 'r':
			howto |= RB_REROOT;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	if (!donextboot && !fflag && stat(_PATH_NOSHUTDOWN, &st) == 0) {
		errx(1, "Reboot cannot be done, " _PATH_NOSHUTDOWN
		    " is present");
	}

	if (Dflag && ((howto & ~RB_HALT) != 0  || kernel != NULL))
		errx(1, "cannot delete existing nextboot config and do anything else");
	if ((howto & (RB_DUMP | RB_HALT)) == (RB_DUMP | RB_HALT))
		errx(1, "cannot dump (-d) when halting; must reboot instead");
	if (Nflag && (howto & RB_NOSYNC) != 0)
		errx(1, "-N cannot be used with -n");
	if ((howto & RB_POWEROFF) && (howto & RB_POWERCYCLE))
		errx(1, "-c and -p cannot be used together");
	if ((howto & RB_REROOT) != 0 && howto != RB_REROOT)
		errx(1, "-r cannot be used with -c, -d, -n, or -p");
	if ((howto & RB_REROOT) != 0 && dofast)
		errx(1, "-r cannot be performed in fast mode");
	if ((howto & RB_REROOT) != 0 && kernel != NULL)
		errx(1, "-r and -k cannot be used together, there is no next kernel");

	if (Dflag) {
		struct stat sb;

		/*
		 * Break the rule about stat then doing
		 * something. When we're booting, there's no
		 * race. When we're a read-only root, though, the
		 * read-only error takes priority over the file not
		 * there error in unlink. So stat it first and exit
		 * with success if it isn't there. Otherwise, let
		 * unlink sort error reporting. POSIX-1.2024 suggests
		 * ENOENT should be preferred to EROFS for unlink,
		 * but FreeBSD historically has preferred EROFS.
		 */
		if (stat(PATH_NEXTBOOT, &sb) != 0 && errno == ENOENT)
			exit(0);
		if (unlink(PATH_NEXTBOOT) != 0)
			warn("unlink " PATH_NEXTBOOT);
		exit(0);
	}

	if (!donextboot && geteuid() != 0) {
		errno = EPERM;
		err(1, NULL);
	}

	if (qflag) {
		reboot(howto);
		err(1, NULL);
	}

	if (kernel != NULL) {
		if (!fflag) {
			char *k;
			struct stat sb;

			asprintf(&k, "/boot/%s/kernel", kernel);
			if (k == NULL)
				errx(1, "No memory to check %s", kernel);
			if (stat(k, &sb) != 0)
				err(1, "stat %s", k);
			if (!S_ISREG(sb.st_mode))
				errx(1, "%s is not a file", k);
			free(k);
		}
		add_env(&env, "kernel", kernel);
	}

	if (env != NULL)
		write_nextboot(PATH_NEXTBOOT, env, aflag, fflag);
	if (donextboot)
		exit (0);

	/* Log the reboot. */
	if (!lflag)  {
		if ((user = getlogin()) == NULL)
			user = (pw = getpwuid(getuid())) ?
			    pw->pw_name : "???";
		if (dohalt) {
			openlog("halt", 0, LOG_AUTH | LOG_CONS);
			syslog(LOG_CRIT, "halted by %s", user);
		} else if (howto & RB_REROOT) {
			openlog("reroot", 0, LOG_AUTH | LOG_CONS);
			syslog(LOG_CRIT, "rerooted by %s", user);
		} else if (howto & RB_POWEROFF) {
			openlog("reboot", 0, LOG_AUTH | LOG_CONS);
			syslog(LOG_CRIT, "powered off by %s", user);
		} else if (howto & RB_POWERCYCLE) {
			openlog("reboot", 0, LOG_AUTH | LOG_CONS);
			syslog(LOG_CRIT, "power cycled by %s", user);
		} else {
			openlog("reboot", 0, LOG_AUTH | LOG_CONS);
			syslog(LOG_CRIT, "rebooted by %s", user);
		}
	}
	utx.ut_type = SHUTDOWN_TIME;
	gettimeofday(&utx.ut_tv, NULL);
	pututxline(&utx);

	/*
	 * Do a sync early on, so disks start transfers while we're off
	 * killing processes.  Don't worry about writes done before the
	 * processes die, the reboot system call syncs the disks.
	 */
	if (!nflag)
		sync();

	/*
	 * Ignore signals that we can get as a result of killing
	 * parents, group leaders, etc.
	 */
	(void)signal(SIGHUP,  SIG_IGN);
	(void)signal(SIGINT,  SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);

	/*
	 * If we're running in a pipeline, we don't want to die
	 * after killing whatever we're writing to.
	 */
	(void)signal(SIGPIPE, SIG_IGN);

	/*
	 * Common case: clean shutdown.
	 */
	if (!dofast)
		reboot_request(howto);

	/*
	 * Stop init from respawning gettys during teardown.  authority-init
	 * is signal-shielded, so prefer the control socket (CATATONIA);
	 * fall back to SIGTSTP for stock init.  Best-effort: reboot(2)
	 * below still completes if init cannot be quiesced, so this must
	 * not be fatal (a fatal error here would abort the fast reboot).
	 */
	BOOTTRACE("quiescing init(8)...");
	if (authority_lifecycle(CTL_OP_CATATONIA) != 0 && kill(1, SIGTSTP) == -1)
		warn("could not quiesce init; continuing");

	/* Send a SIGTERM first, a chance to save the buffers. */
	BOOTTRACE("SIGTERM to all other processes...");
	if (kill(-1, SIGTERM) == -1 && errno != ESRCH)
		err(1, "SIGTERM processes");

	/*
	 * After the processes receive the signal, start the rest of the
	 * buffers on their way.  Wait 5 seconds between the SIGTERM and
	 * the SIGKILL to give everybody a chance. If there is a lot of
	 * paging activity then wait longer, up to a maximum of approx
	 * 60 seconds.
	 */
	sleep(2);
	for (i = 0; i < 20; i++) {
		pageins = get_pageins();
		if (!nflag)
			sync();
		sleep(3);
		if (get_pageins() == pageins)
			break;
	}

	for (i = 1;; ++i) {
		BOOTTRACE("SIGKILL to all other processes(%d)...", i);
		if (kill(-1, SIGKILL) == -1) {
			if (errno == ESRCH)
				break;
			goto restart;
		}
		if (i > 5) {
			(void)fprintf(stderr,
			    "WARNING: some process(es) wouldn't die\n");
			break;
		}
		(void)sleep(2 * i);
	}

	reboot(howto);
	/* FALLTHROUGH */

restart:
	BOOTTRACE("SIGHUP to init(8)...");
	sverrno = errno;
	errx(1, "%s%s", kill(1, SIGHUP) == -1 ? "(can't restart init): " : "",
	    strerror(sverrno));
	/* NOTREACHED */
}

static void
usage(void)
{
	if (donextboot) {
		fprintf(stderr, "usage: nextboot [-aDf] "
		    "[-e name=value] [-k kernel] [-o options]\n");
	} else {
		fprintf(stderr, "usage: %s%s [-%sflNnpq%s] "
		    "[-e name=value] [-k kernel] [-o options]\n",
		    dofast ? "fast" : "",
		    dohalt ? "halt" : dofast ? "boot" : "reboot",
		    dohalt ? "D" : "cDd",
		    dohalt || dofast ? "" : "r");
	}
	exit(1);
}

static uint64_t
get_pageins(void)
{
	uint64_t pageins;
	size_t len;

	len = sizeof(pageins);
	if (sysctlbyname("vm.stats.vm.v_swappgsin", &pageins, &len, NULL, 0)
	    != 0) {
		warn("v_swappgsin");
		return (0);
	}
	return (pageins);
}

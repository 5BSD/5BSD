/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2020, 2023, Domagoj Stolfa. All rights reserved.
 */

#include <sys/types.h>
#include <sys/procctl.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <dev/vmm/vmm_param.h>

#include <assert.h>
#include <dt_benchmark.h>
#include <dt_elf.h>
#include "dtraced_io.h"
#include "dtrace_identifiers.h"
#include "hypertrace_frame.h"
#include <dt_resolver.h>
#include <dt_program.h>
#include <dtrace.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#ifdef illumos
#include <alloca.h>
#endif
#include <libgen.h>
#ifdef illumos
#include <libproc.h>
#endif
#ifdef __FreeBSD__
#include <locale.h>
#include <spawn.h>
#endif
#include <dtraced.h>
#include <dtraced_wire.h>
#include <dtraced_derived.h>
#include <pthread.h>

#undef NORETURN /* needed because libxo redefines it */
#include <libxo/xo.h>

#include "dtotel_session.h"

typedef struct dtrace_cmd {
	void (*dc_func)(struct dtrace_cmd *);	/* function to compile arg */
	dtrace_probespec_t dc_spec;		/* probe specifier context */
	char *dc_arg;				/* argument from main argv */
	const char *dc_name;			/* name for error messages */
	const char *dc_desc;			/* desc for error messages */
	dtrace_prog_t *dc_prog;			/* program compiled from arg */
	char dc_ofile[PATH_MAX];		/* derived output file name */
} dtrace_cmd_t;

typedef struct dtd_arg {
	int rx_sock;
	int wx_sock;
	uint8_t rx_session[16];
	uint8_t program_digest[32];
	uint8_t program_registration[64];
	dtrace_prog_t *hostpgp;
} dtd_arg_t;

typedef struct dt_pgplist {
	dt_list_t list;
	dtrace_prog_t *pgp;
	dtrace_prog_t *gpgp;
	dtrace_prog_t *response;
	uint16_t vmid;
	dtraced_derived_parent_t derived_parent;
	uint8_t ingress_digest[SHA256_DIGEST_LENGTH];
	int derived_parent_known;
	int ingress_digest_known;
	int execution_done;
	int execution_ok;
} dt_pgplist_t;

typedef struct dt_execution_notice {
	struct dt_execution_notice *next;
	dtraced_consumer_ack_t result;
	dt_pgplist_t *wait_for;
} dt_execution_notice_t;

typedef struct dt_probelist {
	dt_list_t list;
	const dtrace_probedesc_t *pdesc;
} dt_probelist_t;

#define	DMODE_VERS	0	/* display version information and exit (-V) */
#define	DMODE_EXEC	1	/* compile program for enabling (-a/e/E) */
#define	DMODE_ANON	2	/* compile program for anonymous tracing (-A) */
#define	DMODE_LINK	3	/* compile program for linking with ELF (-G) */
#define	DMODE_LIST	4	/* compile program and list probes (-l) */
#define	DMODE_HEADER	5	/* compile program for headergen (-h) */
#define	DMODE_LISTVMS	6	/* ask dtraced about instrumentable vms (-M) */

#define	PGPL_ALLOC	0x01	/* allocate a new entry */
#define	PGPL_SRCIDENT	0x02	/* use srcident */
#define	PGPL_HOST	0x04	/* search for the host program */
#define	PGPL_GUEST	0x08	/* search for the guest program */

#define	E_SUCCESS	0
#define	E_ERROR		1
#define	E_USAGE		2

#define	DTRACED_SLEEPTIME	10000	/* us to recv from dtraced again */
static const char DTRACE_OPTSTR[] =
	"1:3:6:aAb:Bc:CdD:eEf:Fg:GhHi:I:lL:m:Mn:No:Op:P:qrs:SuU:vVwx:y:Y:X:Z";

static char g_bench_path[MAXPATHLEN] = "/root/bench/userspace_e2e.json";
static char *g_script;
static dt_benchmark_t *g_e2ebench;
static char **g_argv;
static int g_argc;
static int g_guest = 0;
static int g_failmsg_needed = 0;
static char **g_objv;
static int g_objc;
static dtrace_cmd_t *g_cmdv;
static int g_cmdc;
static struct ps_prochandle **g_psv;
static int g_psc;
static int g_pslive;
static char *g_pname;
static int g_quiet;
static int g_flowindent;
static int g_allow_root_srcident;
static int g_checkmodref;	/* -x checkmodref: report ref-after-mod */
static int g_unsafe;
static int g_has_idents;
static const char *g_hypertrace_session_file;
static int g_hypertrace_session_fd = -1;
static _Atomic int g_intr;
static _Atomic int g_stop;
static _Atomic int g_session_stop;
static _Atomic int g_output_worker_done = 1;
static _Atomic int g_impatient;
static _Atomic int g_newline;

/*
 * Program list for HyperTrace
 */
static dt_list_t g_probe_advlist;
static dt_list_t g_pgplist;
static dt_list_t g_derived_replaylist;
static dt_list_t g_kill_list;
static dt_list_t g_benchlist;
static dt_execution_notice_t *g_execution_notices;
static size_t g_execution_notice_count;
static int g_execution_receiver_done;
static pthread_mutex_t g_pgplistmtx;
static pthread_cond_t g_pgpcond;
static int g_processing_pgp;
static int g_execution_reporting;
static pthread_mutex_t g_benchlistmtx;

#ifdef __FreeBSD__
static _Atomic int g_siginfo;
static uint32_t rslv;
#endif
static int g_total;
static int g_cflags;
static int g_oflags;
static int g_verbose;
static int g_exec = 1;
static int g_elf = 0;
static int g_elfrun = 0;	/* -y ran (or declined) its ELF; nothing follows */
static const char *g_graphfile = NULL;
static int g_mode = DMODE_EXEC;
static int g_status = E_SUCCESS;
static int g_grabanon = 0;

static pthread_t g_dtracedtd;
static pthread_t g_executiontd;
static pthread_t g_worktd;
static pthread_t g_sighandlertd;

static const char *g_ofile = NULL;
static FILE *g_ofp;

/*
 * OpenTelemetry output (-x otel=...): the trace data goes to an
 * exporter through libdtotel instead of to g_ofp.
 */
static struct dtotel_options g_otel_opts;
static struct dtotel_session *g_otel;
static int otel_clock(void);
static void otel_finish(int);

static pthread_mutex_t g_dtpmtx;
static dtrace_hdl_t *g_dtp;

#define CALL_EAGAIN     1
#define ABORTED         2
#define VPROG_CREATION  3

typedef struct dt_benchlist {
	dt_list_t next;
	dt_benchmark_t *bench;
} dt_benchlist_t;

#ifdef illumos
static char *g_etcfile = "/etc/system";
static const char *g_etcbegin = "* vvvv Added by DTrace";
static const char *g_etcend = "* ^^^^ Added by DTrace";

static const char *g_etc[] =  {
"*",
"* The following forceload directives were added by dtrace(1M) to allow for",
"* tracing during boot.  If these directives are removed, the system will",
"* continue to function, but tracing will not occur during boot as desired.",
"* To remove these directives (and this block comment) automatically, run",
"* \"dtrace -A\" without additional arguments.  See the \"Anonymous Tracing\"",
"* chapter of the Solaris Dynamic Tracing Guide for details.",
"*",
NULL };
#endif

#if !defined(illumos) && defined(NEED_ERRLOC)
void dt_get_errloc(dtrace_hdl_t *, char **, int *);
#endif /* !illumos && NEED_ERRLOC */

static void go(void);

static int
usage(FILE *fp)
{
	static const char predact[] = "[[ predicate ] action ]";

	(void) fprintf(fp, "Usage: %s [-32|-64] [-1aACdeFGhHlqSvVwZ] "
	    "[-b bufsz] [-c cmd] [-D name[=def]]\n\t[-I path] [-L path] "
	    "[-o output] [-p pid] [-s script] [-U name]\n\t"
	    "[-x opt[=val]] [-X a|c|s|t]\n\n"
	    "\t[-P provider %s]\n"
	    "\t[-m [ provider: ] module %s]\n"
	    "\t[-f [[ provider: ] module: ] func %s]\n"
	    "\t[-n [[[ provider: ] module: ] func: ] name %s]\n"
	    "\t[-i probe-id %s] [ args ... ]\n\n", g_pname,
	    predact, predact, predact, predact, predact);

	(void) fprintf(fp, "\tpredicate -> '/' D-expression '/'\n");
	(void) fprintf(fp, "\t   action -> '{' D-statements '}'\n");

	(void) fprintf(fp, "\n"
	    "\t-1  specify benchmark file suffix [default: userspace_e2e.json]\n"
	    "\t-32 generate 32-bit D programs and ELF files\n"
	    "\t-64 generate 64-bit D programs and ELF files\n\n"
	    "\t-a  claim anonymous tracing state\n"
	    "\t-A  generate driver.conf(4) directives for anonymous tracing\n"
	    "\t-b  set trace buffer size\n"
	    "\t-c  run specified command and exit upon its completion\n"
	    "\t-C  run cpp(1) preprocessor on script files\n"
	    "\t-d  dump script after syntactic transformations\n"
	    "\t-D  define symbol when invoking preprocessor\n"
	    "\t-e  exit after compiling request but prior to enabling probes\n"
	    "\t-E  operate in HyperTrace mode (use ELF instead of DOF)\n"
	    "\t-f  enable or list probes matching the specified function name\n"
	    "\t-F  coalesce trace output by function\n"
	    "\t-G  generate an ELF file containing embedded dtrace program\n"
	    "\t-g  output GraphViz Dot representation of script actions\n"
	    "\t-h  generate a header file with definitions for static probes\n"
	    "\t-H  print included files when invoking preprocessor\n"
	    "\t-i  enable or list probes matching the specified probe id\n"
	    "\t-I  add include directory to preprocessor search path\n"
	    "\t-l  list probes matching specified criteria\n"
	    "\t-L  add library directory to library search path\n"
	    "\t-m  enable or list probes matching the specified module name\n"
	    "\t-n  enable or list probes matching the specified probe name\n"
	    "\t-N  accept only programs with given identifiers (HyperTrace)\n"
	    "\t-o  set output file\n"
	    "\t-O  print output upon exiting (specific to oformat)\n"
	    "\t-p  grab specified process-ID and cache its symbol tables\n"
	    "\t-P  enable or list probes matching the specified provider name\n"
	    "\t-q  set quiet mode (only output explicitly traced data)\n"
	    "\t-s  enable or list probes according to the specified D script\n"
	    "\t-S  print D compiler intermediate code\n"
	    "\t-U  undefine symbol when invoking preprocessor\n"
	    "\t-v  set verbose mode (report stability attributes, arguments)\n"
	    "\t-V  report DTrace API version\n"
	    "\t-w  permit destructive actions\n"
	    "\t-x  enable or modify compiler and tracing options\n"
	    "\t-X  specify ISO C conformance settings for preprocessor\n"
	    "\t-y  run the provided ELF file\n"
	    "\t-Y  process the provided ELF file in a HyperTrace context\n"
	    "\t-Z  permit probe descriptions that match zero probes\n");

	return (E_USAGE);
}

/*
 * Handle ownership.  Once a second thread exists (signal handler, receiver,
 * reporter, output worker), every use of g_dtp is serialized by the handle
 * lock through dtp_lock()/dtp_unlock(), which is recursive through a
 * per-thread depth.  A thread holding the handle never waits for
 * g_pgplistmtx (the lock order is g_pgplistmtx before the handle).
 *
 * The handle lock is granted in arrival order.  The output worker holds it
 * across dtrace_sleep() and takes it again immediately after each release;
 * with a plain mutex the receiver, the reporter and the stop path could
 * lose every one of those races and starve (a guest reply sent while an
 * earlier program was enabling was then never parsed).  g_dtpmtx only
 * guards the ownership state below and is held briefly.  Neither it nor
 * g_dtpcv is ever destroyed: other threads may still wait while the
 * process exits.
 */
struct dtp_waiter {
	struct dtp_waiter *next;
};
static pthread_cond_t g_dtpcv;
static int g_dtp_held;
static struct dtp_waiter *g_dtp_head;
static struct dtp_waiter **g_dtp_tail = &g_dtp_head;
static int g_dtpmtx_ready;
static _Thread_local int t_dtp_depth;
static _Atomic int g_exiting;
static pthread_t g_exiting_thread;
static _Atomic int g_proc_wake;

/* Take the handle, waiting behind earlier arrivals. */
static void
dtp_lock(void)
{
	struct dtp_waiter self = { NULL };

	if (!g_dtpmtx_ready)
		return;
	if (t_dtp_depth > 0) {
		t_dtp_depth++;
		return;
	}
	(void) pthread_mutex_lock(&g_dtpmtx);
	if (g_dtp_held || g_dtp_head != NULL) {
		*g_dtp_tail = &self;
		g_dtp_tail = &self.next;
		while (g_dtp_held || g_dtp_head != &self)
			(void) pthread_cond_wait(&g_dtpcv, &g_dtpmtx);
		g_dtp_head = self.next;
		if (g_dtp_head == NULL)
			g_dtp_tail = &g_dtp_head;
	}
	g_dtp_held = 1;
	(void) pthread_mutex_unlock(&g_dtpmtx);
	t_dtp_depth = 1;
}

/* The handle if it is free and nobody waits for it; EBUSY otherwise. */
static int
dtp_trylock(void)
{
	int error = 0;

	if (!g_dtpmtx_ready)
		return (0);
	if (t_dtp_depth > 0) {
		t_dtp_depth++;
		return (0);
	}
	(void) pthread_mutex_lock(&g_dtpmtx);
	if (g_dtp_held || g_dtp_head != NULL)
		error = EBUSY;
	else
		g_dtp_held = 1;
	(void) pthread_mutex_unlock(&g_dtpmtx);
	if (error == 0)
		t_dtp_depth = 1;
	return (error);
}

static void
dtp_unlock(void)
{
	if (!g_dtpmtx_ready)
		return;
	if (--t_dtp_depth > 0)
		return;
	(void) pthread_mutex_lock(&g_dtpmtx);
	g_dtp_held = 0;
	if (g_dtp_head != NULL)
		(void) pthread_cond_broadcast(&g_dtpcv);
	(void) pthread_mutex_unlock(&g_dtpmtx);
}

/*
 * Temporary files created by this process.  A failure path that terminates
 * the process (fatal(), dfatal(), dabort()) unlinks every file still listed.
 * Templates honour TMPDIR unless the process is set-id.
 */
#define	DT_TMP_SLOTS	8
static pthread_mutex_t g_tmpmtx = PTHREAD_MUTEX_INITIALIZER;
static char g_tmpfiles[DT_TMP_SLOTS][MAXPATHLEN];

static void
tmp_track(const char *path, int add)
{
	int i;

	(void) pthread_mutex_lock(&g_tmpmtx);
	for (i = 0; i < DT_TMP_SLOTS; i++) {
		if (add && g_tmpfiles[i][0] == '\0') {
			(void) strlcpy(g_tmpfiles[i], path, MAXPATHLEN);
			break;
		}
		if (!add && strcmp(g_tmpfiles[i], path) == 0) {
			g_tmpfiles[i][0] = '\0';
			break;
		}
	}
	(void) pthread_mutex_unlock(&g_tmpmtx);
}

static void
tmp_cleanup(void)
{
	int i;

	(void) pthread_mutex_lock(&g_tmpmtx);
	for (i = 0; i < DT_TMP_SLOTS; i++) {
		if (g_tmpfiles[i][0] != '\0')
			(void) unlink(g_tmpfiles[i]);
		g_tmpfiles[i][0] = '\0';
	}
	(void) pthread_mutex_unlock(&g_tmpmtx);
}

/* mkstemp() in TMPDIR (or /tmp) with the given name prefix; tracked. */
static int
tmp_mkstemp(char *path, size_t size, const char *name)
{
	const char *dir = issetugid() ? NULL : getenv("TMPDIR");
	int fd;

	if (dir == NULL || dir[0] != '/' ||
	    (size_t)snprintf(path, size, "%s/%s.XXXXXXXXXXXX", dir, name) >= size)
		(void) snprintf(path, size, "/tmp/%s.XXXXXXXXXXXX", name);
	if ((fd = mkstemp(path)) >= 0)
		tmp_track(path, 1);
	return (fd);
}

static int
tmp_unlink(const char *path)
{
	tmp_track(path, 0);
	return (unlink(path));
}

/*
 * Only the first terminating thread proceeds.  Another thread that reaches
 * fatal() meanwhile releases any hold it has on the handle (so the first can
 * close the handle) and waits for the process to exit; it never touches
 * g_dtp again.  Re-entry on the terminating thread exits at once.
 */
static void
fatal_enter(void)
{
	int expected = 0;

	if (atomic_compare_exchange_strong(&g_exiting, &expected, 1)) {
		g_exiting_thread = pthread_self();
		return;
	}
	if (pthread_equal(g_exiting_thread, pthread_self()))
		_exit(E_ERROR);
	while (t_dtp_depth > 0)
		dtp_unlock();
	for (;;)
		(void) pause();
}

/*
 * Close the DTrace handle to ensure that any controlled processes are
 * correctly restored and continued (created processes are handled as
 * dtrace_close() does), then exit while still holding the handle so that no
 * other thread can use the closed handle.
 */
static void
fatal_exit(int status)
{
	tmp_cleanup();
	dtp_lock();
	if (g_dtp != NULL)
		dtrace_close(g_dtp);
	g_dtp = NULL;
	exit(status);
}

static void
verror(const char *fmt, va_list ap)
{
	int error = errno;
	char msg[2048];

	/* One stdio call, so other threads' diagnostics cannot interleave. */
	(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, "%s: %s: %s\n", g_pname, msg,
		    strerror(error));
	else
		(void) fprintf(stderr, "%s: %s", g_pname, msg);
}

/*PRINTFLIKE1*/
static void
fatal(const char *fmt, ...)
{
	va_list ap;
	int error = errno;

	fatal_enter();
	errno = error;
	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
	fatal_exit(E_ERROR);
}

/*
 * hypertrace_link() failed.  A program error (the type checker's) has been
 * printed by libdtrace and is reported as the program's error; any other
 * failure with the linker's code and message.
 */
static void
link_failed(dtrace_prog_t *pgp, const char *what, int err, const char *errmsg)
{
	if (pgp->dp_haserror)
		fatal("%s\n", pgp->dp_err);
	fatal("%s: %s: %s\n", what, dtrace_hypertrace_errstr(err), errmsg);
}

/*PRINTFLIKE1*/
static void
dabort(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
	tmp_cleanup();
	abort();
}

/*PRINTFLIKE1*/
static void
dfatal(const char *fmt, ...)
{
#if !defined(illumos) && defined(NEED_ERRLOC)
	char *p_errfile = NULL;
	int errline = 0;
#endif
	va_list ap;

	fatal_enter();
	/* The handle's error state is read under the handle lock. */
	dtp_lock();
	char msg[2048] = "";

	va_start(ap, fmt);
	if (fmt != NULL)
		(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	va_end(ap);

	/* One stdio call, so other threads' diagnostics cannot interleave. */
	if (fmt != NULL && fmt[strlen(fmt) - 1] != '\n') {
		(void) fprintf(stderr, "%s: %s: %s\n", g_pname, msg,
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	} else if (fmt == NULL) {
		(void) fprintf(stderr, "%s: %s\n", g_pname,
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	} else
		(void) fprintf(stderr, "%s: %s", g_pname, msg);
#if !defined(illumos) && defined(NEED_ERRLOC)
	dt_get_errloc(g_dtp, &p_errfile, &errline);
	if (p_errfile != NULL)
		printf("File '%s', line %d\n", p_errfile, errline);
#endif

	fatal_exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
notice(const char *fmt, ...)
{
	va_list ap;

	if (g_quiet)
		return; /* -q or quiet pragma suppresses notice()s */

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
oprintf(const char *fmt, ...)
{
	va_list ap;
	int n;

	if (g_ofp == NULL || atomic_load(&g_session_stop))
		return;

	va_start(ap, fmt);
	n = vfprintf(g_ofp, fmt, ap);
	va_end(ap);

	if (n < 0) {
		if (errno != EINTR) {
			fatal("failed to write to %s",
			    g_ofile ? g_ofile : "<stdout>");
		}
		clearerr(g_ofp);
	}
}

static char **
make_argv(char *s)
{
	const char *ws = "\f\n\r\t\v ";
	char **argv = malloc(sizeof (char *) * (strlen(s) / 2 + 1));
	int argc = 0;
	char *p = s;

	if (argv == NULL)
		return (NULL);

	for (p = strtok(s, ws); p != NULL; p = strtok(NULL, ws))
		argv[argc++] = p;

	if (argc == 0)
		argv[argc++] = s;

	argv[argc] = NULL;
	return (argv);
}

#ifdef __FreeBSD__
static void
siginfo(int signo __unused)
{

	atomic_fetch_add(&g_siginfo, 1);
	atomic_store(&g_newline, 1);
}
#endif

static void *
handle_signals(void *arg __unused)
{
	sigset_t sigset;
	int err, sig = 0, nsigs = 2;

	(void) sigfillset(&sigset);
	err = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if (err)
		fatal("failed to apply sigmask to signal handler thread: %s\n",
		    strerror(err));

	(void) sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
#ifdef __FreeBSD__
	sigaddset(&sigset, SIGPIPE);
	sigaddset(&sigset, SIGUSR1);
#endif

	do {
		err = sigwait(&sigset, &sig);
		if (err)
			fatal("failed to sigwait: %s\n", strerror(err));

		if (!atomic_load(&g_intr))
			atomic_store(&g_newline, 1);

		if (atomic_fetch_add(&g_intr, 1))
			atomic_store(&g_impatient, 1);

		pthread_mutex_lock(&g_pgplistmtx);
		pthread_cond_broadcast(&g_pgpcond);
		pthread_mutex_unlock(&g_pgplistmtx);
	} while (--nsigs > 0);

	return (NULL);
}

static void
block_signals(void)
{
	sigset_t sigset;

	(void) sigemptyset(&sigset);
	(void) sigaddset(&sigset, SIGINT);
	(void) sigaddset(&sigset, SIGTERM);
#ifdef __FreeBSD__
	(void) sigaddset(&sigset, SIGPIPE);
	(void) sigaddset(&sigset, SIGUSR1);
#endif

	(void) pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}

static void
installsighands(void)
{
	struct sigaction act, oact;

	/*
	 * The signal handler is already installed and all the signals should be
	 * blocked. If the caller wishes to just block signals, one should call
	 * block_signals() instead.
	 */
	if (g_sighandlertd != NULL)
		return;

	block_signals();
	if (pthread_create(&g_sighandlertd, NULL, handle_signals, NULL))
		abort();

	/*
	 * Handle SIGINFO normally.
	 */
#ifdef __FreeBSD__
	(void)sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = siginfo;
	if (sigaction(SIGINFO, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void)sigaction(SIGINFO, &act, NULL);
#endif
}

static void
dof_prune(const char *fname)
{
	struct stat sbuf;
	size_t sz, i, j, mark, len;
	char *buf;
	int msg = 0, fd;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		/*
		 * This is okay only if the file doesn't exist at all.
		 */
		if (errno != ENOENT)
			fatal("failed to open %s", fname);
		return;
	}

	if (fstat(fd, &sbuf) == -1)
		fatal("failed to fstat %s", fname);

	if ((buf = malloc((sz = sbuf.st_size) + 1)) == NULL)
		fatal("failed to allocate memory for %s", fname);

	if (read(fd, buf, sz) != sz)
		fatal("failed to read %s", fname);

	buf[sz] = '\0';
	(void) close(fd);

	if ((fd = open(fname, O_WRONLY | O_TRUNC)) == -1)
		fatal("failed to open %s for writing", fname);

	len = strlen("dof-data-");

	for (mark = 0, i = 0; i < sz; i++) {
		if (strncmp(&buf[i], "dof-data-", len) != 0)
			continue;

		/*
		 * This is only a match if it's in the 0th column.
		 */
		if (i != 0 && buf[i - 1] != '\n')
			continue;

		if (msg++ == 0) {
			error("cleaned up old anonymous "
			    "enabling in %s\n", fname);
		}

		/*
		 * We have a match.  First write out our data up until now.
		 */
		if (i != mark) {
			if (write(fd, &buf[mark], i - mark) != i - mark)
				fatal("failed to write to %s", fname);
		}

		/*
		 * Now scan forward until we scan past a newline.
		 */
		for (j = i; j < sz && buf[j] != '\n'; j++)
			continue;

		/*
		 * Reset our mark.
		 */
		if ((mark = j + 1) >= sz)
			break;

		i = j;
	}

	if (mark < sz) {
		if (write(fd, &buf[mark], sz - mark) != sz - mark)
			fatal("failed to write to %s", fname);
	}

	(void) close(fd);
	free(buf);
}

#ifdef __FreeBSD__
/*
 * Use nextboot(8) to tell the loader to load DTrace kernel modules during
 * the next boot of the system. The nextboot(8) configuration is removed during
 * boot, so it will not persist indefinitely.
 */
static void
bootdof_add(void)
{
	char * const nbargv[] = {
		"nextboot", "-a",
		"-e", "dtraceall_load=\"YES\"",
		"-e", "dtrace_dof_load=\"YES\"",
		"-e", "dtrace_dof_name=\"/boot/dtrace.dof\"",
		"-e", "dtrace_dof_type=\"dtrace_dof\"",
		NULL,
	};
	pid_t child;
	int err, status;

	err = posix_spawnp(&child, "nextboot", NULL, NULL, nbargv,
	    NULL);
	if (err != 0) {
		error("failed to execute nextboot: %s", strerror(err));
		exit(E_ERROR);
	}

	if (waitpid(child, &status, 0) != child)
		fatal("waiting for nextboot");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		error("nextboot returned with status %d", status);
		exit(E_ERROR);
	}
}
#else
static void
etcsystem_prune(void)
{
	struct stat sbuf;
	size_t sz;
	char *buf, *start, *end;
	int fd;
	char *fname = g_etcfile, *tmpname;

	if ((fd = open(fname, O_RDONLY)) == -1)
		fatal("failed to open %s", fname);

	if (fstat(fd, &sbuf) == -1)
		fatal("failed to fstat %s", fname);

	if ((buf = malloc((sz = sbuf.st_size) + 1)) == NULL)
		fatal("failed to allocate memory for %s", fname);

	if (read(fd, buf, sz) != sz)
		fatal("failed to read %s", fname);

	buf[sz] = '\0';
	(void) close(fd);

	if ((start = strstr(buf, g_etcbegin)) == NULL)
		goto out;

	if (strlen(buf) != sz) {
		fatal("embedded nul byte in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if (strstr(start + 1, g_etcbegin) != NULL) {
		fatal("multiple start sentinels in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if ((end = strstr(buf, g_etcend)) == NULL) {
		fatal("missing end sentinel in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if (start > end) {
		fatal("end sentinel preceeds start sentinel in %s; manual "
		    "repair of %s required\n", fname, fname);
	}

	end += strlen(g_etcend) + 1;
	bcopy(end, start, strlen(end) + 1);

	tmpname = alloca(sz = strlen(fname) + 80);
	(void) snprintf(tmpname, sz, "%s.dtrace.%d", fname, getpid());

	if ((fd = open(tmpname,
	    O_WRONLY | O_CREAT | O_EXCL, sbuf.st_mode)) == -1)
		fatal("failed to create %s", tmpname);

	if (write(fd, buf, strlen(buf)) < strlen(buf)) {
		(void) unlink(tmpname);
		fatal("failed to write to %s", tmpname);
	}

	(void) close(fd);

	if (chown(tmpname, sbuf.st_uid, sbuf.st_gid) != 0) {
		(void) unlink(tmpname);
		fatal("failed to chown(2) %s to uid %d, gid %d", tmpname,
		    (int)sbuf.st_uid, (int)sbuf.st_gid);
	}

	if (rename(tmpname, fname) == -1)
		fatal("rename of %s to %s failed", tmpname, fname);

	error("cleaned up forceload directives in %s\n", fname);
out:
	free(buf);
}

static void
etcsystem_add(void)
{
	const char *mods[20];
	int nmods, line;

	if ((g_ofp = fopen(g_ofile = g_etcfile, "a")) == NULL)
		fatal("failed to open output file '%s'", g_ofile);

	oprintf("%s\n", g_etcbegin);

	for (line = 0; g_etc[line] != NULL; line++)
		oprintf("%s\n", g_etc[line]);

	nmods = dtrace_provider_modules(g_dtp, mods,
	    sizeof (mods) / sizeof (char *) - 1);

	if (nmods >= sizeof (mods) / sizeof (char *))
		fatal("unexpectedly large number of modules!");

	mods[nmods++] = "dtrace";

	for (line = 0; line < nmods; line++)
		oprintf("forceload: drv/%s\n", mods[line]);

	oprintf("%s\n", g_etcend);

	if (fclose(g_ofp) == EOF)
		fatal("failed to close output file '%s'", g_ofile);

	error("added forceload directives to %s\n", g_ofile);
}
#endif /* !__FreeBSD__ */

static void
print_probe_info(const dtrace_probeinfo_t *p)
{
	char buf[BUFSIZ];
	char *user;
	int i;

	oprintf("\n\tProbe Description Attributes\n");

	oprintf("\t\tIdentifier Names: %s\n",
	    dtrace_stability_name(p->dtp_attr.dtat_name));
	oprintf("\t\tData Semantics:   %s\n",
	    dtrace_stability_name(p->dtp_attr.dtat_data));
	oprintf("\t\tDependency Class: %s\n",
	    dtrace_class_name(p->dtp_attr.dtat_class));

	oprintf("\n\tArgument Attributes\n");

	oprintf("\t\tIdentifier Names: %s\n",
	    dtrace_stability_name(p->dtp_arga.dtat_name));
	oprintf("\t\tData Semantics:   %s\n",
	    dtrace_stability_name(p->dtp_arga.dtat_data));
	oprintf("\t\tDependency Class: %s\n",
	    dtrace_class_name(p->dtp_arga.dtat_class));

	oprintf("\n\tArgument Types\n");

	for (i = 0; i < p->dtp_argc; i++) {
		if (p->dtp_argv[i].dtt_flags & DTT_FL_USER)
			user = "userland ";
		else
			user = "";
		if (ctf_type_name(p->dtp_argv[i].dtt_ctfp,
		    p->dtp_argv[i].dtt_type, buf, sizeof (buf)) == NULL)
			(void) strlcpy(buf, "(unknown)", sizeof (buf));
		oprintf("\t\targs[%d]: %s%s\n", i, user, buf);
	}

	if (p->dtp_argc == 0)
		oprintf("\t\tNone\n");

	oprintf("\n");
}

/*ARGSUSED*/
static int
info_stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmtdesc_t *stp, dtrace_ecbdesc_t **last)
{
	dtrace_ecbdesc_t *edp = stp->dtsd_ecbdesc;
	dtrace_probedesc_t *pdp = &edp->dted_probe;
	dtrace_probeinfo_t p;

	if (edp == *last)
		return (0);

	oprintf("\n%s:%s:%s:%s\n",
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	if (dtrace_probe_info(dtp, pdp, &p) == 0)
		print_probe_info(&p);

	*last = edp;
	return (0);
}

static bool
checkmodref(int action_modref, int cumulative_modref,
    const dtrace_probedesc_t *dp, FILE *output)
{

	if ((cumulative_modref & DTRACE_MODREF_ANY_MOD) == 0) {
		// We don't care about pre-modification behaviour.
		return (true);
	}

	if (action_modref & DTRACE_MODREF_ANY_REF) {
		fprintf(output, "%s: ref-after-mod in %s:%s:%s:%s:", g_pname,
			dp->dtpd_provider, dp->dtpd_mod, dp->dtpd_func,
			dp->dtpd_name);
		if (action_modref & DTRACE_MODREF_GLOBAL_REF)
			fprintf(output, " global");
		if (action_modref & DTRACE_MODREF_THREAD_LOCAL_REF)
			fprintf(output, " thread");
		if (action_modref & DTRACE_MODREF_CLAUSE_LOCAL_REF)
			fprintf(output, " clause");
		if (action_modref & DTRACE_MODREF_MEMORY_REF)
			fprintf(output, " external");
		if (action_modref & DTRACE_MODREF_STATE_REF)
			fprintf(output, " internal");
		fprintf(output, "\n");

		return (false);
	}

	return (true);
}

/*
 * -x checkmodref: before a program is enabled, warn about every action that
 * references state (global, thread-local, clause-local, external memory or
 * internal DTrace state) after an earlier action of the same program
 * modified any state.  A warning only; the program still runs.
 */
static void
check_program_modref(dtrace_prog_t *pgp)
{
	if (g_checkmodref && pgp != NULL)
		(void) dtrace_analyze_program_modref(pgp, checkmodref, stderr);
}

static dt_pgplist_t *
get_pgplist_entry(char *ident, uint16_t vmid, uint64_t epoch, int *found, int flags)
{
	dt_pgplist_t *pgpl;
	dtrace_prog_t *pgp;
	int use_srcident;
	char *_ident;
	int err;

	assert((flags & PGPL_HOST) != 0 || (flags & PGPL_GUEST) != 0);

	*found = 0;
	use_srcident = flags & PGPL_SRCIDENT;
	for (pgpl = dt_list_next(&g_pgplist); pgpl;
	    pgpl = dt_list_next(pgpl)) {
		pgp = flags & PGPL_HOST ? pgpl->pgp :
		    flags & PGPL_GUEST ? pgpl->gpgp : NULL;

		/*
		 * If for some reason we're in a state where we don't have a
		 * program associated with this pgp list entry, we simply
		 * continue.
		 */
		if (pgp == NULL)
			continue;

		_ident = use_srcident ? pgp->dp_srcident : pgp->dp_ident;

		if (memcmp(_ident, ident, DT_PROG_IDENTLEN) == 0 &&
		    pgp->dp_vmid == vmid && pgp->dp_vmepoch == epoch) {
			*found = 1;
			return (pgpl);
		}
	}

	if ((flags & PGPL_ALLOC) == 0)
		return (NULL);

	pgpl = malloc(sizeof(dt_pgplist_t));
	if (pgpl == NULL)
		return (NULL);

	memset(pgpl, 0, sizeof(dt_pgplist_t));
	return (pgpl);
}

static int
pgpl_valid(dt_pgplist_t *pgpl)
{
	if (pgpl == NULL)
		return (0);

	return ((pgpl->vmid > 0 && pgpl->pgp && pgpl->gpgp && pgpl->response) ||
	    (pgpl->vmid == 0 && pgpl->pgp));
}

static int
send_kill(int tofd, dtrace_prog_t *pgp)
{
	pid_t pid_to_kill;
	/*
	 * For a kill message, we have everything we need in the header.
	 * Therefore we don't really need to make a large message and the header
	 * itself is sufficient.
	 */
	dtraced_hdr_t msg;

	if (tofd == -1) {
		fprintf(stderr, "file descriptor must be != -1\n");
		errno = EBADF;
		return (-1);
	}

	memset(&msg, 0, sizeof(msg));

	assert(pgp != NULL);
	pid_to_kill = pgp->dp_pid;

	/*
	 * It is highly unlikely we will have dtrace running as pid0 or init...
	 */
	if (pid_to_kill <= 1 || pgp->dp_vmid == 0 || pgp->dp_vmepoch == 0) {
		fprintf(stderr,
		    "dtrace: WARN: %s program pid claims to be %d\n",
		    pgp->dp_vmname, pid_to_kill);
		return (0);
	}

	DTRACED_MSG_TYPE(msg) = DTRACED_MSG_KILL;
	DTRACED_MSG_KILLPID(msg) = pid_to_kill;
	DTRACED_MSG_KILLVMID(msg) = pgp->dp_vmid;
	DTRACED_MSG_KILLEPOCH(msg) = pgp->dp_vmepoch;
	if (dtrace_program_source_id(pgp, msg.kill.source_id) != 0)
		return (-1);

	return (dtrace_send_message(tofd, &msg, NULL, 0));
}

static void
set_snapshot_names(void)
{
#ifdef __DTRACE_RUN_BENCHMARKS__
	dt_benchlist_t *be;
	dt_benchmark_t *b;
	size_t i;
	const char *names[] = {
		"ELF parsing - start",
		"ELF parsing - end",
		"Virtual program creation - start",
		"Virtual program creation - persisted",
		"Virtual program creation - sent to dtraced"
	};

	for (be = dt_list_next(&g_benchlist); be; be = dt_list_next(be)) {
		b = be->bench;
		if (b == g_e2ebench)
			continue;

		assert(b != NULL);
		assert(b->dtbe_nsnapshots == 5);

		for (i = 0; i < b->dtbe_nsnapshots; i++) {
			if (b->dtbe_timesnaps[i].__data == ABORTED) {
				dt_snapshot_setinfo(b, i, "aborted call");
				break;
			}

			dt_snapshot_setinfo(b, i, names[i]);
		}
	}
#endif
}

static void *
merge_benchmarks(void)
{
	void *merge;
	dt_benchlist_t *be;
	dt_benchmark_t *b;

	merge = dt_merge_new();
	if (merge == NULL)
		abort();

	for (be = dt_list_next(&g_benchlist); be; be = dt_list_next(be)) {
		b = be->bench;
		assert(b != NULL);

		if (dt_bench_merge(merge, b) == NULL)
			abort();
	}

	return (merge);
}

static dt_benchlist_t *
new_bench_list_entry(dt_benchmark_t *bench)
{
	dt_benchlist_t *new;

	new = malloc(sizeof(dt_benchlist_t));
	if (new == NULL)
		abort();

	memset(new, 0, sizeof(dt_benchlist_t));
	new->bench = bench;
	return (new);
}

static void
append_bench_locked(dt_benchmark_t *bench)
{

	pthread_mutex_lock(&g_benchlistmtx);
	dt_list_append(&g_benchlist, new_bench_list_entry(bench));
	pthread_mutex_unlock(&g_benchlistmtx);
}

static int reconnect_dtraced(dtd_arg_t *, int *, int *);
static int handle_consumer_drain(dtd_arg_t *, int, int64_t);
static int handle_consumer_stop(dtd_arg_t *, int, int64_t);

static void
execution_identity_set(dtraced_consumer_ack_t *execution,
    const dtraced_hdr_t *header, int derived)
{
	memset(execution, 0, sizeof(*execution));
	execution->delivery_id = header->elf.delivery_id;
	memcpy(execution->program_id, header->elf.program_id, 16);
	memcpy(execution->source_id, header->elf.source_id, 16);
	execution->vmid = header->elf.vmid;
	execution->epoch = header->elf.epoch;
	execution->outcome = derived ? DTRACED_CONSUMER_ACK_DERIVED :
	    DTRACED_CONSUMER_ACK_NO_DERIVED;
	memcpy(execution->ingress_session, header->installed.name, 16);
}

static int
identified_ingress_header_valid(const dtraced_hdr_t *header)
{
	static const unsigned char zero_session[16] = {0};

	return (header != NULL && header->elf.delivery_id != 0 &&
	    header->installed.delivery_id == header->elf.delivery_id &&
	    header->installed.vmid == header->elf.vmid &&
	    header->installed.epoch == header->elf.epoch &&
	    memcmp(header->installed.program_id,
	    header->elf.program_id, 16) == 0 &&
	    memcmp(header->installed.source_id,
	    header->elf.source_id, 16) == 0 &&
	    memcmp(header->installed.name, zero_session, 16) != 0);
}

/* The receiver must remain free to replay an ACK while a processing result
 * waits for daemon acceptance. Only the reporter uses the result connection.
 * A dependent program is retained on the active or replay list until exit. */
static void
queue_identified_execution(const dtraced_hdr_t *header, int outcome,
    dt_pgplist_t *wait_for)
{
	dt_execution_notice_t *notice;

	if (header->elf.delivery_id == 0)
		return;
	notice = calloc(1, sizeof(*notice));
	if (notice == NULL)
		fatal("failed to allocate identified execution notice");
	execution_identity_set(&notice->result, header,
	    outcome == DTRACED_CONSUMER_ACK_DERIVED);
	notice->wait_for = wait_for;
	pthread_mutex_lock(&g_pgplistmtx);
	if (g_execution_notice_count >= 65536) {
		pthread_mutex_unlock(&g_pgplistmtx);
		free(notice);
		fatal("identified execution notice limit reached\n");
	}
	notice->next = g_execution_notices;
	g_execution_notices = notice;
	g_execution_notice_count++;
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
}

static void
ack_identified_delivery(dtd_arg_t *connection, int *rx, int *wx,
    const dtraced_hdr_t *header, int outcome)
{
	dtraced_consumer_ack_t ack = { 0 };
	unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
	size_t transferred;
	int64_t deadline;

	if (header->elf.delivery_id == 0)
		return;
	ack.delivery_id = header->elf.delivery_id;
	memcpy(ack.program_id, header->elf.program_id,
	    sizeof(ack.program_id));
	memcpy(ack.source_id, header->elf.source_id,
	    sizeof(ack.source_id));
	ack.vmid = header->elf.vmid;
	ack.epoch = header->elf.epoch;
	ack.outcome = outcome;
	dtraced_wire_encode_consumer_ack(wire, &ack);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0 || dtraced_io_transfer(*rx, wire, sizeof(wire), true,
	    deadline, &transferred) != 0) {
		/* The daemon may have received no ACK, a partial ACK, or the
		 * complete ACK before this failure. Reconnect rather than sending
		 * it again on a stream with an ambiguous frame boundary. The same
		 * session will receive any still-pending delivery for exact replay. */
		fprintf(stderr, "dtrace: identified delivery ACK failed; "
		    "reconnecting for replay\n");
		(void)reconnect_dtraced(connection, rx, wx);
	}
}

/* A reconnect may replay the exact ingress after its derived send reached
 * dtraced but before the consumer ACK was durable.  Re-send only the parent
 * that created this cached guest program: a second upload of the same source
 * program is not authority to install a second derived guest program. */
static int
identified_derived_parent_matches(const dt_pgplist_t *entry,
    const dtd_arg_t *connection, const dtraced_hdr_t *header)
{
	const dtraced_derived_parent_t *saved;

	if (header->elf.delivery_id == 0 || entry == NULL ||
	    entry->gpgp == NULL || !entry->derived_parent_known)
		return (0);
	saved = &entry->derived_parent;
	return (memcmp(saved->consumer_session, connection->rx_session,
	    16) == 0 && saved->delivery_id == header->elf.delivery_id &&
	    saved->vmid == header->elf.vmid &&
	    saved->epoch == header->elf.epoch &&
	    memcmp(saved->program_id, header->elf.program_id, 16) == 0 &&
	    memcmp(saved->source_id, header->elf.source_id, 16) == 0);
}

/* Caller holds g_pgplistmtx. Completed programs remain replayable after
 * leaving the active execution queue. */
static dt_pgplist_t *
find_identified_derived(const dtd_arg_t *connection,
    const dtraced_hdr_t *header)
{
	for (int listno = 0; listno < 2; listno++) {
		dt_list_t *list = listno == 0 ? &g_pgplist :
		    &g_derived_replaylist;
		for (dt_pgplist_t *cached = dt_list_next(list);
		    cached != NULL; cached = dt_list_next(cached))
			if (identified_derived_parent_matches(cached,
			    connection, header))
				return (cached);
	}
	return (NULL);
}

static int
reemit_identified_derived(dt_pgplist_t *entry, const dtd_arg_t *connection,
    const dtraced_hdr_t *header,
    const uint8_t ingress_digest[SHA256_DIGEST_LENGTH], int wx_sockfd)
{
	const dtraced_derived_parent_t *saved;
	char path[MAXPATHLEN];
	hypertrace_errmsg_t errmsg;
	int fd, error, result;

	if (!identified_derived_parent_matches(entry, connection, header))
		return (0);
	if (!entry->ingress_digest_known || ingress_digest == NULL ||
	    memcmp(entry->ingress_digest, ingress_digest,
	    sizeof(entry->ingress_digest)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	saved = &entry->derived_parent;
	fd = tmp_mkstemp(path, sizeof(path), "ddtrace-reemit");
	if (fd < 0)
		return (-1);
	result = -1;
	dtp_lock();
	error = dtrace_elf_create(g_dtp, entry->gpgp, ELFDATA2LSB, fd, path,
	    errmsg);
	dtp_unlock();
	if (error != 0) {
		errno = EIO;
		goto done;
	}
	if (fsync(fd) != 0 || lseek(fd, 0, SEEK_SET) < 0)
		goto done;
	if (dtrace_send_elf_derived(entry->gpgp, fd, wx_sockfd,
	    saved) != 0)
		goto done;
	result = 1;
done:
	error = errno != 0 ? errno : EIO;
	if (close(fd) != 0 && result == 1) {
		error = errno;
		result = -1;
	}
	if (tmp_unlink(path) != 0 && result == 1) {
		error = errno;
		result = -1;
	}
	if (result < 0)
		errno = error;
	return (result);
}

static int
dtraced_connection_lost(int error)
{
	return (error == ECONNRESET || error == EPIPE ||
	    error == ENOTCONN);
}

/*
 * A derived program that dtraced did not accept is kept and offered again
 * when the parent delivery is replayed on a new connection.  A refusal that
 * persists must not spin through reconnects: back off between attempts and
 * give up after DERIVED_SEND_ATTEMPTS consecutive failures.
 */
#define	DERIVED_SEND_ATTEMPTS		6
#define	DERIVED_SEND_BACKOFF		250000U		/* usec, doubled */
#define	DERIVED_SEND_BACKOFF_MAX	4000000U

static void
derived_send_failed(int *failures, int error)
{
	useconds_t delay;

	if (++*failures >= DERIVED_SEND_ATTEMPTS)
		fatal("dtraced did not accept the derived program after %d "
		    "attempts: %s\n", *failures, strerror(error));
	delay = DERIVED_SEND_BACKOFF << (*failures - 1);
	(void)usleep(delay < DERIVED_SEND_BACKOFF_MAX ? delay :
	    DERIVED_SEND_BACKOFF_MAX);
}

static int
reconnect_dtraced(dtd_arg_t *connection, int *rx, int *wx)
{
	int next_rx, next_wx;
	dtraced_hdr_t program_message = { 0 };

	close(*rx);
	close(*wx);
	*rx = *wx = -1;
	connection->rx_sock = connection->wx_sock = -1;
	fprintf(stderr, "dtrace: dtraced disconnected; reconnecting\n");
	while (!atomic_load(&g_intr) && !atomic_load(&g_stop)) {
		next_rx = open_dtraced_session(DTD_SUB_ELFWRITE,
		    connection->rx_session);
		if (next_rx >= 0) {
			program_message.msg_type =
			    DTRACED_MSG_CONSUMER_PROGRAM;
			program_message.elf.len =
			    sizeof(connection->program_registration);
			if (dtrace_send_message(next_rx, &program_message,
			    connection->program_registration,
			    sizeof(connection->program_registration)) != 0) {
				close(next_rx);
				(void)usleep(250000);
				continue;
			}
			next_wx = open_dtraced(DTD_SUB_READDATA);
			if (next_wx >= 0) {
				*rx = connection->rx_sock = next_rx;
				*wx = connection->wx_sock = next_wx;
				fprintf(stderr, "dtrace: dtraced reconnected\n");
				return (0);
			}
			close(next_rx);
		}
		(void)usleep(250000);
	}
	return (-1);
}


static void *
listen_dtraced(void *arg)
{
	int rx_sockfd;
	int wx_sockfd;
	int novm = 0;
	size_t elflen;
	char *elf;
	size_t size;
	unsigned char *elf_base;
	struct dtrace_ht_view view;
	size_t transferred;
	int64_t deadline;
	dtrace_prog_t *newprog;
	dtrace_prog_t *hostpgp, *guestpgp;
	int fd;
	int err;
	char template[MAXPATHLEN];
	int tmpfd;
	char vm_name[VM_MAX_NAMELEN] = { 0 };
	dtd_arg_t *dtd_arg = (dtd_arg_t *)arg;
	dt_pgplist_t *newpgpl;
	int done;
	uint16_t vmid;
	size_t lentowrite;
	int found;
	int derived_sent;
	int derived_failures = 0;
	ssize_t r;
	dtraced_hdr_t header;
	uint8_t ingress_digest[SHA256_DIGEST_LENGTH];
	void *verictx;
	dt_snapshot_hdl_t cshdl;
	dt_benchmark_t *bench;
	char buf[1024];
	hypertrace_errmsg_t errmsg;

	rx_sockfd = 0;
	elflen = 0;
	elf = NULL;
	size = 0;
	newprog = NULL;
	fd = 0;
	err = 0;
	done = 0;
	vmid = 0;
	lentowrite = 0;

	/*
	 * Assume this is an int.
	 */
	rx_sockfd = dtd_arg->rx_sock;
	wx_sockfd = dtd_arg->wx_sock;
	hostpgp = dtd_arg->hostpgp;
	guestpgp = NULL;

	dtp_lock();
	verictx = dt_verictx_init(g_dtp);
	dtp_unlock();

	do {
		newpgpl = NULL;
		derived_sent = 0;
		/*
		 * Now that we have created an ELF file, we wait for dtraced
		 * to give us the new ELF file that contains all the applied
		 * relocations. We will then verify that the relocations that
		 * were applied are sensible, get the identifier of which VM
		 * it actually is and fill in the necessary filters.
		 */
		if (atomic_load(&g_intr) || atomic_load(&g_stop))
			break;
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0)
			fatal("failed to set dtraced receive deadline: %s\n",
			    strerror(errno));
		unsigned char header_wire[DTRACED_MSGHDRSIZE];
		if (dtraced_io_transfer(rx_sockfd, header_wire, sizeof(header_wire),
		    false, deadline, &transferred) != 0) {
			if (errno == ETIMEDOUT && transferred == 0)
				continue;
			if (dtraced_connection_lost(errno)) {
				if (reconnect_dtraced(dtd_arg, &rx_sockfd,
				    &wx_sockfd) == 0)
					continue;
				break;
			}
			fatal("failed to receive complete dtraced header");
		}
		if (dtraced_wire_decode_header(&header, header_wire) != 0)
			fatal("invalid dtraced ELF header");
		if (DTRACED_MSG_TYPE(header) == DTRACED_MSG_CONSUMER_STOP) {
			if (handle_consumer_stop(dtd_arg, rx_sockfd, deadline) != 0)
				fatal("failed to process dtraced stop challenge: %s\n",
				    strerror(errno));
			if (atomic_load(&g_session_stop))
				break;
			continue;
		}
		if (DTRACED_MSG_TYPE(header) == DTRACED_MSG_CONSUMER_DRAIN) {
			if (handle_consumer_drain(dtd_arg, rx_sockfd,
			    deadline) != 0) {
				if (dtraced_connection_lost(errno) &&
				    reconnect_dtraced(dtd_arg, &rx_sockfd,
				    &wx_sockfd) == 0)
					continue;
				fatal("failed to process dtraced drain challenge: %s\n",
				    strerror(errno));
			}
			continue;
		}
		if (DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF)
			fatal("unexpected message on dtraced ELF connection\n");

		/*
		 * "rcvpgp" -- create
		 */
		bench = __dt_bench_new_time(5);
		if (dt_bench_start(bench) == -1)
			fatal("failed to start bench at line %d\n", __LINE__);


		elflen = DTRACED_MSG_LEN(header);
		if (elflen < 4 || elflen > 64U * 1024U * 1024U)
			fatal("invalid dtraced ELF frame length\n");
		elf_base = malloc(elflen);
		if (elf_base == NULL)
			fatal("failed to allocate dtraced ELF frame");
		if (dtraced_io_transfer(rx_sockfd, elf_base, elflen, false,
		    deadline, &transferred) != 0) {
			err = errno;
			free(elf_base);
			if (dtraced_connection_lost(err)) {
				dt_bench_destroy(bench);
				if (reconnect_dtraced(dtd_arg, &rx_sockfd,
				    &wx_sockfd) == 0)
					continue;
				break;
			}
			fatal("failed to receive complete dtraced ELF frame");
		}
		if (atomic_load(&g_intr) || atomic_load(&g_stop)) {
			free(elf_base);
			dt_bench_destroy(bench);
			break;
		}
		if (dtrace_ht_decode(elf_base, elflen, sizeof(vm_name), &view) != 0) {
			free(elf_base);
			fatal("invalid dtraced VM/ELF envelope\n");
		}
		if (dtrace_ht_validate_delivery(&view,
		    header.elf.delivery_id, header.elf.program_id,
		    header.elf.source_id, header.elf.vmid,
		    header.elf.epoch) != 0) {
			free(elf_base);
			fatal("dtraced delivery identity conflicts with VM envelope\n");
		}
		if (header.elf.delivery_id != 0 &&
		    !identified_ingress_header_valid(&header)) {
			free(elf_base);
			fatal("dtraced ingress session is missing or mismatched\n");
		}
		memset(ingress_digest, 0, sizeof(ingress_digest));
		if (header.elf.delivery_id != 0 &&
		    SHA256(elf_base, elflen, ingress_digest) == NULL) {
			free(elf_base);
			fatal("failed to digest identified dtraced ELF frame");
		}
		/* A send may have failed after the derived result was generated but
		 * before its daemon acceptance was known. Replay that exact result
		 * before parsing this ingress as another host/guest response. */
		if (header.elf.delivery_id != 0) {
			int replay = 0, replay_error = 0;
			dt_pgplist_t *cached;

			pthread_mutex_lock(&g_pgplistmtx);
			cached = find_identified_derived(dtd_arg, &header);
			/* The execution thread may have just moved this entry to
			 * the replay list. Wait for its DTrace handle operations to
			 * finish before serializing the cached guest program. */
			while (cached != NULL && g_processing_pgp) {
				pthread_cond_wait(&g_pgpcond, &g_pgplistmtx);
				cached = find_identified_derived(dtd_arg, &header);
			}
			if (cached != NULL) {
				replay = reemit_identified_derived(cached, dtd_arg,
				    &header, ingress_digest, wx_sockfd);
				replay_error = errno;
			}
			pthread_mutex_unlock(&g_pgplistmtx);
			if (replay != 0) {
				free(elf_base);
				elf_base = NULL;
				dt_bench_destroy(bench);
				if (replay < 0) {
					fprintf(stderr, "dtrace: failed to replay derived ELF: %s\n",
					    strerror(replay_error));
					derived_send_failed(&derived_failures,
					    replay_error);
				} else
					derived_failures = 0;
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header, replay < 0 ?
				    DTRACED_CONSUMER_ACK_FAILURE :
				    DTRACED_CONSUMER_ACK_DERIVED);
				if (replay > 0)
					queue_identified_execution(&header,
					    DTRACED_CONSUMER_ACK_DERIVED, cached);
				continue;
			}
		}
		vmid = view.vmid;
		novm = vmid == 0;
		size = view.name_length;
		memset(vm_name, 0, sizeof(vm_name));
		if (size != 0)
			memcpy(vm_name, view.name, size);
		elf = (char *)(uintptr_t)view.elf;
		lentowrite = view.length;
		dt_bench_hdl_attach(bench, DT_BENCH_TOPLEVEL, vmid);

		fd = tmp_mkstemp(template, sizeof(template), "ddtrace-elf");
		if (fd == -1)
			dabort("failed to create a temporary file (%s)",
			    strerror(errno));

		for (size_t offset = 0; offset < lentowrite; offset += r) {
			r = write(fd, elf + offset, lentowrite - offset);
			if (r < 0 && errno == EINTR) {
				r = 0;
				continue;
			}
			if (r <= 0)
				fatal("failed to write received ELF file");
		}
		free(elf_base);
		elf_base = NULL;

		if (fsync(fd))
			dabort("failed to sync file");

		/*
		 * "rcvpgp" -- snapshot "ELF parsing - start"
		 */
		cshdl = __dt_bench_snapshot_time(bench);
		dtp_lock();
		newprog = dtrace_elf_parse(g_dtp, fd, template, 0, &err, errmsg,
		    hostpgp);
		dtp_unlock();
		if (newprog == NULL && err != E_HYPERTRACE_AGAIN) {
			/*
			 * "rcvpgp" @ "ELF parsing - start" -- destroy
			 */
			dt_bench_destroy(bench);
			close(fd);
			(void) tmp_unlink(template);
			ack_identified_delivery(dtd_arg, &rx_sockfd,
			    &wx_sockfd, &header, 0);
			continue;
		}

		if (newprog == NULL) {
			char buf[DT_PROG_IDENTLEN];

			/*
			 * "rcvpgp" @ "ELF parsing - start" -- attach data = EAGAIN
			 */
			dt_bench_hdl_attach(bench, cshdl, CALL_EAGAIN);

			(void) dtrace_get_srcident(buf);
			pthread_mutex_lock(&g_pgplistmtx);
			newpgpl = get_pgplist_entry(buf, vmid, view.epoch, &found,
			    PGPL_GUEST);

			/*
			 * If we found nothing, we're simply going to go back to
			 * sleep. This program is not for us. If we have found
			 * something, but it's a valid pgpl, we've raced against
			 * another thread that is currently busy processing this
			 * particular entry. Report it and go back to sleep.
			 */
			if (found == 0) {
				/*
				 * "rcvpgp" @ "ELF parsing - start" -- destroy
				 */
				dt_bench_destroy(bench);
				pthread_mutex_unlock(&g_pgplistmtx);
				close(fd);
				(void) tmp_unlink(template);
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header, 1);
				queue_identified_execution(&header,
				    DTRACED_CONSUMER_ACK_NO_DERIVED, NULL);
				continue;
			} else if (pgpl_valid(newpgpl)) {
				int replay = reemit_identified_derived(newpgpl,
				    dtd_arg, &header, ingress_digest, wx_sockfd);
				int replay_error = errno;

				fprintf(stderr,
				    "dtrace: found a valid pgpl, sleeping...");
				pthread_mutex_unlock(&g_pgplistmtx);
				/*
				 * "rcvpgp" @ "ELF parsing - start" -- destroy
				 */
				dt_bench_destroy(bench);
				close(fd);
				(void) tmp_unlink(template);
				if (replay < 0) {
					fprintf(stderr, "dtrace: failed to replay derived ELF: %s\n",
					    strerror(replay_error));
					derived_send_failed(&derived_failures,
					    replay_error);
				} else
					derived_failures = 0;
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header,
				    replay < 0 ? 0 : replay == 1 ?
				    DTRACED_CONSUMER_ACK_DERIVED :
				    DTRACED_CONSUMER_ACK_NO_DERIVED);
				if (replay >= 0)
					queue_identified_execution(&header, replay == 1 ?
					    DTRACED_CONSUMER_ACK_DERIVED :
					    DTRACED_CONSUMER_ACK_NO_DERIVED, newpgpl);
				continue;
			}

			dtp_lock();
			newprog = dtrace_elf_parse(g_dtp, fd, template, 0, &err,
			    errmsg, newpgpl->gpgp);
			dtp_unlock();
			if (newprog == NULL) {
				fprintf(stderr, "ELF parsing failed: %s: %s",
				    dtrace_hypertrace_errstr(err), errmsg);
				pthread_mutex_unlock(&g_pgplistmtx);
				/*
				 * "rcvpgp" @ "ELF parsing - start" -- destroy
				 */
				dt_bench_destroy(bench);
				close(fd);
				(void) tmp_unlink(template);
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header, 0);
				continue;
			}
		}

		/*
		 * "rcvpgp" -- snapshot "ELF parsing - end"
		 */
		__dt_bench_snapshot_time(bench);

		(void) tmp_unlink(template);
		close(fd);

		newprog->dp_vmid = vmid;
		newprog->dp_vmepoch = view.epoch;
		strlcpy(newprog->dp_vmname, vm_name, VM_MAX_NAMELEN);

		/*
		 * srcident only is not sufficient here, as it's an one-to-many
		 * relation. However, scoping it with vmid as well *should* give
		 * us a unique program.
		 */
		if (newpgpl == NULL) {
			pthread_mutex_lock(&g_pgplistmtx);
			newpgpl = get_pgplist_entry(newprog->dp_srcident, vmid, view.epoch,
			    &found, PGPL_ALLOC | PGPL_HOST);
		}

		if (newpgpl == NULL)
			dabort("malloc of newpgpl failed");

		if (pgpl_valid(newpgpl)) {
			int replay = reemit_identified_derived(newpgpl,
			    dtd_arg, &header, ingress_digest, wx_sockfd);
			int replay_error = errno;

			fprintf(stderr,
			    "dtrace: found a valid pgpl, sleeping...");
			pthread_mutex_unlock(&g_pgplistmtx);
			dtp_lock();
			dt_program_destroy(g_dtp, newprog);
			dtp_unlock();
			newprog = NULL;
			/*
			 * "rcvpgp" @ "ELF parsing - end" -- destroy
			 */
			dt_bench_destroy(bench);
			if (replay < 0) {
				fprintf(stderr, "dtrace: failed to replay derived ELF: %s\n",
				    strerror(replay_error));
				derived_send_failed(&derived_failures,
				    replay_error);
			} else
				derived_failures = 0;
			ack_identified_delivery(dtd_arg, &rx_sockfd,
			    &wx_sockfd, &header,
			    replay < 0 ? 0 : replay == 1 ?
			    DTRACED_CONSUMER_ACK_DERIVED :
			    DTRACED_CONSUMER_ACK_NO_DERIVED);
			if (replay >= 0)
				queue_identified_execution(&header, replay == 1 ?
				    DTRACED_CONSUMER_ACK_DERIVED :
				    DTRACED_CONSUMER_ACK_NO_DERIVED, newpgpl);
			continue;
		}

		/*
		 * vmid is only 0 when we haven't filled in the program we will
		 * execute on the host.
		 *
		 * We check that we don't have a guest trying to pretend that it
		 * is someone else.
		 */
		if (newpgpl->vmid != 0 && (newpgpl->vmid != vmid)) {
			uint16_t claimed_vmid = newpgpl->vmid;

			pthread_mutex_unlock(&g_pgplistmtx);
			dtp_lock();
			dt_program_destroy(g_dtp, newprog);
			dtp_unlock();
			newprog = NULL;
			/*
			 * "rcvpgp" @ "ELF parsing - end" -- destroy
			 */
			dt_bench_destroy(bench);
			syslog(LOG_SECURITY, "vmid (%u) is claiming to be %u\n",
			    vmid, claimed_vmid);
			fprintf(stderr, "vmid (%u) is claiming to be %u\n",
			    vmid, claimed_vmid);
			ack_identified_delivery(dtd_arg, &rx_sockfd,
			    &wx_sockfd, &header, 0);
			continue;
		}

		dtp_lock();
		size_t difo_checkpoint = dt_verictx_mark(verictx);
		int unverified = found ? newpgpl->gpgp == NULL ||
		    dt_prog_verify(verictx, newpgpl->gpgp, newprog) :
		    dt_prog_verify(verictx, hostpgp, newprog);
		dtp_unlock();
		if (found) {
			/* The returned guest ELF is a response to the exact
			 * forwarding program we sent, not a new host program. */
			if (unverified) {
				fprintf(stderr,
				    "failed to verify guest response from %s (%u)\n",
				    vm_name[0] == '\0' ? "host" : vm_name, vmid);
				pthread_mutex_unlock(&g_pgplistmtx);
				dtp_lock();
				dt_program_destroy(g_dtp, newprog);
				dtp_unlock();
				newprog = NULL;
				dt_bench_destroy(bench);
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header, 0);
				continue;
			}
			newpgpl->response = newprog;
		} else {
			if (unverified) {
				fprintf(stderr,
				    "failed to verify DIF from %s (%u)\n",
				    vm_name[0] == '\0' ? "host" : vm_name, vmid);
				free(newpgpl);
				pthread_mutex_unlock(&g_pgplistmtx);
				dtp_lock();
				dt_program_destroy(g_dtp, newprog);
				dtp_unlock();
				newprog = NULL;
				/*
				 * "rcvpgp" @ "ELF parsing - end" -- destroy
				 */
				dt_bench_destroy(bench);
				ack_identified_delivery(dtd_arg, &rx_sockfd,
				    &wx_sockfd, &header, 0);
				continue;
			}

			newpgpl->vmid = vmid;
			newpgpl->pgp = newprog;
		}
		if (!found && novm == 0) {
			/*
			 * "rcvpgp" -- snapshot "Virtual program creation - start"
			 */
			cshdl = __dt_bench_snapshot_time(bench);
			/*
			 * "rcvpgp" @ "Virtual program creation - start" -- attach data = VPROG_CREATION
			 */
			dt_bench_hdl_attach(bench, cshdl, VPROG_CREATION);
			tmpfd = -1;
			dtp_lock();
			guestpgp = dtrace_vprog_from(g_dtp, newprog,
			    PGP_KIND_HYPERCALLS);
			dtp_unlock();
			if (guestpgp == NULL) {
				fprintf(stderr,
				    "failed to create guest forwarding program "
				    "from %s (%u)\n",
				    vm_name[0] == '\0' ? "host" : vm_name, vmid);
				goto reject_guest_generation;
			}

			if (g_verbose > 1) {
				fprintf(stderr, "GENERATED PROGRAM:\n");
				fprintf(stderr,
				    "=================================================================="
				    "\n");
				dtp_lock();
				dtrace_dump_actions(guestpgp);
				dtp_unlock();
				fprintf(stderr,
				    "=================================================================="
				    "\n");
			}

			guestpgp->dp_exec = DT_PROG_EXEC;

			tmpfd = tmp_mkstemp(template, sizeof(template),
			    "ddtrace-elf");
			if (tmpfd == -1) {
				fprintf(stderr, "failed to create guest ELF file: %s\n",
				    strerror(errno));
				goto reject_guest_generation;
			}
			dtp_lock();
			err = dtrace_elf_create(g_dtp, guestpgp, ELFDATA2LSB,
			    tmpfd, template, errmsg);
			dtp_unlock();
			if (err) {
				fprintf(stderr, "failed to create guest ELF: %s: %s\n",
				    dtrace_hypertrace_errstr(err), errmsg);
				goto reject_guest_generation;
			}
			if (fsync(tmpfd)) {
				fprintf(stderr, "failed to sync guest ELF: %s\n",
				    strerror(errno));
				goto reject_guest_generation;
			}
			if (lseek(tmpfd, 0, SEEK_SET)) {
				fprintf(stderr, "failed to rewind guest ELF: %s\n",
				    strerror(errno));
				goto reject_guest_generation;
			}
			/*
			 * "rcvpgp" -- snapshot "Virtual program creation - persisted"
			 */
			__dt_bench_snapshot_time(bench);

			if (header.elf.delivery_id != 0) {
				/* The source handoff fence waits for the derived ELF to be
				 * durably accepted by dtraced, not merely queued here. */
				dtraced_derived_parent_t parent = {
				    .delivery_id = header.elf.delivery_id,
				    .vmid = header.elf.vmid,
				    .epoch = header.elf.epoch
				};
				memcpy(parent.consumer_session,
				    dtd_arg->rx_session, 16);
				memcpy(parent.program_id, header.elf.program_id, 16);
				memcpy(parent.source_id, header.elf.source_id, 16);
				if (dtrace_send_elf_derived(guestpgp, tmpfd,
				    wx_sockfd, &parent) == 0)
					err = 0;
				else
					err = errno != 0 ? errno : EIO;
				/* Retain the exact result even if the socket breaks after
				 * publication. A replay on this session can complete it. */
			newpgpl->derived_parent = parent;
			newpgpl->derived_parent_known = 1;
			memcpy(newpgpl->ingress_digest, ingress_digest,
			    sizeof(newpgpl->ingress_digest));
			newpgpl->ingress_digest_known = 1;
				close(tmpfd);
			} else {
				err = dtrace_send_elf_async(guestpgp, tmpfd,
				    wx_sockfd, template, "outbound", 0);
			}
			(void) tmp_unlink(template);

			if (err) {
				if (header.elf.delivery_id == 0) {
					close(tmpfd);
					tmpfd = -1;
				}
				fprintf(stderr,
				    "failed to dtrace_send_elf(): %s\n",
				    strerror(err));
				if (header.elf.delivery_id != 0) {
					/* No success ACK is possible yet. Keep the generated
					 * program and parent so an exact-session replay can
					 * retry this same derived result. */
					newpgpl->gpgp = guestpgp;
					if (newpgpl->pgp == newprog)
						dt_list_append(&g_pgplist, newpgpl);
					pthread_mutex_unlock(&g_pgplistmtx);
					dt_bench_destroy(bench);
					derived_send_failed(&derived_failures, err);
					if (reconnect_dtraced(dtd_arg, &rx_sockfd,
					    &wx_sockfd) == 0)
						continue;
					break;
				}
				goto reject_guest_generation;
			}
			/* The identified send received daemon spool acceptance. */
			derived_sent = header.elf.delivery_id != 0;
			derived_failures = 0;

			/*
			 * "rcvpgp" -- snapshot "Virtual program creation - sent to dtraced"
			 */
			__dt_bench_snapshot_time(bench);

			newpgpl->gpgp = guestpgp;
		}

		/*
		 * "rcvpgp" -- stop ("ELF parsing - end" || "Virtual program creation - persisted")
		 */
		__dt_bench_stop_time(bench);
		dt_bench_setinfo(bench, "rcvpgp",
		    "Received program", DT_BENCHKIND_TIME);
		append_bench_locked(bench);

		/*
		 * If this is a new program, we add it to the list.
		 */
		if (newpgpl->pgp == newprog) {
			dt_list_append(&g_pgplist, newpgpl);
		}

		/*
		 * For vmid == 0, we allow signalling because there will never
		 * be a guest program that will be run.
		 */
		if (pgpl_valid(newpgpl))
			pthread_cond_broadcast(&g_pgpcond);

		pthread_mutex_unlock(&g_pgplistmtx);
		ack_identified_delivery(dtd_arg, &rx_sockfd,
		    &wx_sockfd, &header,
		    derived_sent ? DTRACED_CONSUMER_ACK_DERIVED :
		    DTRACED_CONSUMER_ACK_NO_DERIVED);
		queue_identified_execution(&header,
		    derived_sent ? DTRACED_CONSUMER_ACK_DERIVED :
		    DTRACED_CONSUMER_ACK_NO_DERIVED, newpgpl);
		continue;

reject_guest_generation:
		if (tmpfd >= 0) {
			close(tmpfd);
			(void) tmp_unlink(template);
		}
		/* The verifier retains DIFO pointers from this response. Remove
		 * them before destroying either generated or parsed program. */
		dtp_lock();
		dt_verictx_rewind(verictx, difo_checkpoint);
		dtp_unlock();
		free(newpgpl);
		pthread_mutex_unlock(&g_pgplistmtx);
		dtp_lock();
		if (guestpgp != NULL)
			dt_program_destroy(g_dtp, guestpgp);
		dt_program_destroy(g_dtp, newprog);
		dtp_unlock();
		guestpgp = NULL;
		newprog = NULL;
		dt_bench_destroy(bench);
		ack_identified_delivery(dtd_arg, &rx_sockfd, &wx_sockfd, &header, 0);
	} while (!done);

	dtp_lock();
	dt_verictx_teardown(verictx);
	dtp_unlock();
	return (arg);
}

static void
setup_tracing(void)
{
	dtrace_optval_t opt;
	int i;

	/*
	 * Start tracing.  Once we dtrace_go(), reload any options that affect
	 * our globals in case consuming anonymous state has changed them.
	 */
	dtp_lock();
	go();

	if (g_elf == 0) {
		(void) dtrace_getopt(g_dtp, "flowindent", &opt);
		g_flowindent = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "grabanon", &opt);
		g_grabanon = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "quiet", &opt);
		g_quiet = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "destructive", &opt);
		if (opt != DTRACEOPT_UNSET)
			notice("allowing destructive actions\n");
	}

	installsighands();

	/*
	 * Now that tracing is active and we are ready to consume trace data,
	 * continue any grabbed or created processes, setting them running
	 * using the /proc control mechanism inside of libdtrace.
	 */
	for (i = 0; i < g_psc; i++)
		dtrace_proc_continue(g_dtp, g_psv[i]);

	g_pslive = g_psc; /* count for prochandler() */
	dtp_unlock();
}

/*ARGSUSED*/
static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
	dtrace_actkind_t act;
	uintptr_t addr;

	if (rec == NULL) {
		/*
		 * We have processed the final record; output the newline if
		 * we're not in quiet mode.  OpenTelemetry output instead
		 * records a firing that printed nothing by its probe.
		 */
		if (g_otel != NULL)
			dtotel_firing_end(dtotel_session_bridge(g_otel), data,
			    g_quiet);
		else if (!g_quiet)
			oprintf("\n");

		return (DTRACE_CONSUME_NEXT);
	}

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	if (act == DTRACEACT_EXIT) {
		g_status = *((uint32_t *)addr);
		if (g_otel != NULL)
			dtotel_exit(dtotel_session_bridge(g_otel), g_status);
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	processorid_t cpu = data->dtpda_cpu;
	static int heading;

	if (g_impatient) {
		g_newline = 0;
		return (DTRACE_CONSUME_ABORT);
	}

	/* OpenTelemetry records carry the probe; no heading or prefix. */
	if (g_otel != NULL)
		return (DTRACE_CONSUME_THIS);

	if (heading == 0) {
		if (!g_flowindent) {
			if (!g_quiet) {
				oprintf("%3s %6s %32s\n",
				    "CPU", "ID", "FUNCTION:NAME");
			}
		} else {
			oprintf("%3s %-41s\n", "CPU", "FUNCTION");
		}
		heading = 1;
	}

	if (!g_flowindent) {
		if (dtrace_oformat(g_dtp)) {
			dtrace_oformat_probe(g_dtp, data, cpu, pd);
		} else if (!g_quiet) {
			char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];

			(void) snprintf(name, sizeof (name), "%s:%s",
			    pd->dtpd_func, pd->dtpd_name);

			oprintf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
		}
	} else {
		int indent = data->dtpda_indent;
		char *name;
		size_t len;

		if (data->dtpda_flow == DTRACEFLOW_NONE) {
			len = indent + DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 5;
			name = alloca(len);
			(void) snprintf(name, len, "%*s%s%s:%s", indent, "",
			    data->dtpda_prefix, pd->dtpd_func,
			    pd->dtpd_name);
		} else {
			len = indent + DTRACE_FUNCNAMELEN + 5;
			name = alloca(len);
			(void) snprintf(name, len, "%*s%s%s", indent, "",
			    data->dtpda_prefix, pd->dtpd_func);
		}

		oprintf("%3d %-41s ", cpu, name);
	}

	return (DTRACE_CONSUME_THIS);
}

static int
consumer_drain_gate_held(const dtraced_consumer_drain_t *challenge)
{
	struct hypertrace_epoch_gate gate = { 0 };
	int fd, held;

	fd = open("/dev/dtrace/hypertrace", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (0);
	gate.vmid = challenge->vmid;
	gate.epoch = challenge->epoch;
	held = ioctl(fd, HYPERTRACE_IOC_EPOCH_GATE_QUERY, &gate) == 0 &&
	    gate.suspended == 1 &&
	    memcmp(gate.token, challenge->token, sizeof(gate.token)) == 0;
	(void)close(fd);
	return (held);
}

/* A process-local reply is valid only for this HPI1 consumer incarnation.
 * It is not a durable handoff receipt; the daemon must journal and recheck it
 * under the source ticket before PREPARE can rely on it. */
static int
handle_consumer_drain(dtd_arg_t *connection, int rx_sockfd, int64_t deadline)
{
	unsigned char wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
	unsigned char reply[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
	static const uint8_t zero_session[16] = { 0 };
	dtraced_consumer_drain_t challenge;
	dtrace_consumer_t con = {
		.dc_consume_probe = chew,
		.dc_consume_rec = chewrec,
		.dc_get_buf = NULL,
		.dc_put_buf = NULL
	};
	struct stat st;
	size_t transferred;
	int output_fd;
	int64_t reply_deadline;

	if (dtraced_io_transfer(rx_sockfd, wire, sizeof(wire), false,
	    deadline, &transferred) != 0)
		return (-1);
	if (dtraced_wire_decode_consumer_drain(&challenge, wire) != 0)
		return (-1);
	if (!atomic_load(&g_intr) && !atomic_load(&g_stop) &&
	    memcmp(connection->rx_session, zero_session,
	    sizeof(zero_session)) != 0 &&
	    memcmp(challenge.consumer_session, connection->rx_session,
	    sizeof(connection->rx_session)) == 0 &&
	    memcmp(challenge.program_digest, connection->program_digest,
	    sizeof(connection->program_digest)) == 0 &&
	    consumer_drain_gate_held(&challenge)) {
		dtp_lock();
		output_fd = g_ofp == NULL ? -1 : fileno(g_ofp);
		/*
		 * OpenTelemetry output is drained into the exporter, which
		 * then hands it on (file sinks fsync, OTLP posts or spools).
		 */
		if (g_otel != NULL) {
			if (g_dtp != NULL &&
			    dtrace_consume_quiesced(g_dtp, NULL, &con,
			    NULL) == 0 &&
			    dtotel_session_flush(g_otel) == 0 &&
			    consumer_drain_gate_held(&challenge))
				challenge.result = 1;
		} else if (g_dtp != NULL && output_fd >= 0 &&
		    fstat(output_fd, &st) == 0 && S_ISREG(st.st_mode) &&
		    dtrace_consume_quiesced(g_dtp, g_ofp, &con, NULL) == 0 &&
		    fsync(output_fd) == 0 &&
		    consumer_drain_gate_held(&challenge))
			challenge.result = 1;
		dtp_unlock();
	}
	dtraced_wire_encode_consumer_drain_ack(reply, &challenge);
	reply_deadline = dtraced_io_deadline_after(60000);
	if (reply_deadline < 0)
		return (-1);
	return (dtraced_io_transfer(rx_sockfd, reply, sizeof(reply), true,
	    reply_deadline, &transferred));
}

/* The receiver cannot join the main execution thread, which joins it on
 * shutdown. Close admission under its queue mutex, then wait for the active
 * operation, reporter and output worker to relinquish the old session. */
static int
mutex_trylock(void *mutex)
{
	return (pthread_mutex_trylock(mutex));
}

static int
handle_trylock(void *unused __unused)
{
	return (dtp_trylock());
}

/* Poll trylock(arg) until it succeeds or the deadline passes. */
static int
consumer_stop_lock(int (*trylock)(void *), void *arg, int64_t deadline)
{
	int error, timeout;
	for (;;) {
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (-1);
		error = trylock(arg);
		if (error == 0)
			return (0);
		if (error != EBUSY) {
			errno = error;
			return (-1);
		}
		(void)usleep(10000);
	}
}

/* Acquire before collector tracing work can launch system() descendants.
 * Existing traced targets are not adopted: this reaper owns future children. */
static int g_consumer_reaper;

static int
consumer_descendants_prepare(void)
{
	struct procctl_reaper_status status = {0};
	if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) != 0 &&
	    errno != EBUSY)
		return (-1);
	if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &status) != 0)
		return (-1);
	if (!(status.rs_flags & REAPER_STATUS_OWNED) ||
	    status.rs_reaper != getpid()) {
		errno = EPROTO;
		return (-1);
	}
	g_consumer_reaper = 1;
	return (0);
}

/* Called only after all collector work producers are quiescent. Reap only
 * reported zombie children in our own reaper set, never unrelated targets.
 * A bounded batch keeps retries governed by the caller's stop deadline. */
static int
consumer_descendants_step(void)
{
	struct procctl_reaper_status status = {0};
	struct procctl_reaper_pidinfo children[256] = {{0}};
	struct procctl_reaper_pids query = {0};
	if (!g_consumer_reaper) {
		errno = EAGAIN;
		return (-1);
	}
	if (procctl(P_PID, getpid(), PROC_REAP_STATUS, &status) != 0)
		return (-1);
	if (!(status.rs_flags & REAPER_STATUS_OWNED) ||
	    status.rs_reaper != getpid()) {
		errno = ESTALE;
		return (-1);
	}
	if (status.rs_descendants == 0)
		return (1);
	query.rp_count = nitems(children);
	query.rp_pids = children;
	if (procctl(P_PID, getpid(), PROC_REAP_GETPIDS, &query) != 0)
		return (-1);
	for (size_t i = 0; i < nitems(children); i++) {
		if ((children[i].pi_flags & (REAPER_PIDINFO_VALID |
		    REAPER_PIDINFO_CHILD | REAPER_PIDINFO_ZOMBIE)) !=
		    (REAPER_PIDINFO_VALID | REAPER_PIDINFO_CHILD |
		    REAPER_PIDINFO_ZOMBIE))
			continue;
		if (children[i].pi_pid <= 1) {
			errno = EPROTO;
			return (-1);
		}
		if (waitpid(children[i].pi_pid, NULL, WNOHANG) == -1 &&
		    errno != ECHILD && errno != EINTR)
			return (-1);
	}
	/* Even successful reaping is not a census: re-query next step. */
	return (0);
}

static int
consumer_stop_quiesce(const dtraced_consumer_stop_t *challenge,
    int64_t deadline)
{
	int busy, stopped, timeout, async_done;
	if (consumer_stop_lock(mutex_trylock, &g_pgplistmtx, deadline) != 0)
		return (0);
	atomic_store(&g_session_stop, 1);
	atomic_store(&g_stop, 1);
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
	for (;;) {
		async_done = dtrace_async_discard_step();
		if (async_done < 0)
			return (0);
		if (consumer_stop_lock(mutex_trylock, &g_pgplistmtx, deadline) != 0)
			return (0);
		busy = g_processing_pgp || g_execution_reporting;
		pthread_mutex_unlock(&g_pgplistmtx);
		if (!busy && atomic_load(&g_output_worker_done) && async_done == 1) {
			int descendants_done = consumer_descendants_step();
			if (descendants_done < 0)
				return (0);
			if (descendants_done == 1)
				break;
		}
		if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
			return (0);
		(void)usleep(10000);
	}
	/* The worker is done: the handle is normally free; never wait
	 * past the stop deadline for it. */
	if (consumer_stop_lock(handle_trylock, NULL, deadline) != 0)
		return (0);
	stopped = g_dtp != NULL &&
	    dtrace_output_discard(g_dtp, g_ofp) == 0 &&
	    (dtrace_status(g_dtp) == DTRACE_STATUS_INACTIVE ||
	    dtrace_stop(g_dtp) == 0) &&
	    consumer_drain_gate_held(challenge);
	dtp_unlock();
	return (stopped);
}

static int
consumer_stop_commit(dtd_arg_t *connection,
    const dtraced_consumer_stop_t *proof)
{
	unsigned char frame[8 + DTRACED_MSGHDRSIZE +
	    DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE], accepted;
	dtraced_hdr_t header = { .msg_type = DTRACED_MSG_CONSUMER_STOP_COMMIT };
	uint8_t session[16];
	size_t transferred;
	int error = EIO;

	memcpy(session, connection->rx_session, sizeof(session));
	dtraced_wire_put_u64(frame, sizeof(frame) - 8);
	dtraced_wire_encode_header(frame + 8, &header);
	dtraced_wire_encode_consumer_stop_ack(frame + 8 + DTRACED_MSGHDRSIZE, proof);
	for (int retry = 0; retry < 2; retry++) {
		int fd = open_dtraced_session(DTD_SUB_READDATA, session);
		if (fd < 0) {
			error = errno;
			continue;
		}
		int64_t deadline = dtraced_io_deadline_after(5000);
		int sent = deadline >= 0 &&
		    dtraced_io_transfer(fd, frame, sizeof(frame), true,
		    deadline, &transferred) == 0 &&
		    dtraced_io_transfer(fd, &accepted, sizeof(accepted), false,
		    deadline, &transferred) == 0;
		error = sent ? EIO : errno;
		(void)close(fd);
		if (sent && accepted == 1)
			return (0);
	}
	errno = error;
	return (-1);
}

static int
handle_consumer_stop(dtd_arg_t *connection, int rx_sockfd, int64_t deadline)
{
	unsigned char wire[DTRACED_CONSUMER_STOP_WIRE_SIZE];
	unsigned char reply[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
	dtraced_consumer_stop_t challenge;
	size_t transferred;
	int64_t stop_deadline;

	if (dtraced_io_transfer(rx_sockfd, wire, sizeof(wire), false,
	    deadline, &transferred) != 0 ||
	    dtraced_wire_decode_consumer_stop(&challenge, wire) != 0)
		return (-1);
	stop_deadline = dtraced_io_deadline_after(45000);
	if (stop_deadline < 0)
		return (-1);
	if (!atomic_load(&g_intr) && !atomic_load(&g_stop) &&
	    memcmp(challenge.consumer_session, connection->rx_session, 16) == 0 &&
	    memcmp(challenge.program_digest, connection->program_digest, 32) == 0 &&
	    consumer_drain_gate_held(&challenge))
		challenge.result = consumer_stop_quiesce(&challenge, stop_deadline);
	dtraced_wire_encode_consumer_stop_ack(reply, &challenge);
	/* Release the daemon worker waiting on this reply before asking another
	 * request to commit proof. Otherwise a single-worker daemon deadlocks.
	 * A failed/partial write must also wake that worker before the commit. */
	deadline = dtraced_io_deadline_after(5000);
	int sent = deadline < 0 ? -1 : dtraced_io_transfer(rx_sockfd, reply,
	    sizeof(reply), true, deadline, &transferred);
	if (sent != 0)
		(void)shutdown(rx_sockfd, SHUT_RDWR);
	/* Confirm durable proof before exit even when the original reply was
	 * lost. The coordinator may already have persisted the same receipt. */
	if (challenge.result == 1)
		return (consumer_stop_commit(connection, &challenge));
	return (sent);
}

typedef struct dtrace_workarg {
	int print_upon_exit;
} dtrace_workarg_t;

static void *
dtc_work(void *_arg)
{
	int done = 0, status, impatient;
	dtrace_consumer_t con;
	dtrace_workarg_t *arg = _arg;

	con.dc_consume_probe = chew;
	con.dc_consume_rec = chewrec;
	con.dc_get_buf = NULL;
	con.dc_put_buf = NULL;

	dtp_lock();
	dtrace_oformat_setup(g_dtp);
	dtp_unlock();
	do {
		if (atomic_load(&g_session_stop))
			goto stopped_session;
		dtp_lock();
		if (!atomic_load(&g_intr) && !done) {
			dtrace_sleep(g_dtp);
		}
		if (atomic_load(&g_session_stop)) {
			dtp_unlock();
			goto stopped_session;
		}

		status = dtrace_status(g_dtp);
		dtp_unlock();
		/* g_pgplistmtx is taken only without the handle lock; this
		 * also delivers prochandler()'s deferred wakeup. */
		if (atomic_exchange(&g_proc_wake, 0) ||
		    status == DTRACE_STATUS_STOPPED ||
		    status == DTRACE_STATUS_EXITED) {
			pthread_mutex_lock(&g_pgplistmtx);
			if (status == DTRACE_STATUS_STOPPED ||
			    status == DTRACE_STATUS_EXITED)
				atomic_store(&g_stop, 1);
			pthread_cond_broadcast(&g_pgpcond);
			pthread_mutex_unlock(&g_pgplistmtx);
		}

#ifdef __FreeBSD__
		dtp_lock();
		if (atomic_load(&g_siginfo) && g_otel != NULL) {
			/* A snapshot of the aggregations, as for printing. */
			(void)dtotel_aggregate(dtotel_session_bridge(g_otel));
			atomic_store(&g_siginfo, 0);
		} else if (atomic_load(&g_siginfo) && !dtrace_oformat(g_dtp)) {
			(void)dtrace_aggregate_print(g_dtp, g_ofp, NULL);
			atomic_store(&g_siginfo, 0);
		}
		dtp_unlock();
#endif

		if (atomic_load(&g_newline)) {
			/*
			 * Output a newline just to make the output look
			 * slightly cleaner.  Note that we do this even in
			 * "quiet" mode...
			 */
			if (g_otel == NULL)
				oprintf("\n");
			atomic_store(&g_newline, 0);
		}

		dtp_lock();
		if (done || atomic_load(&g_intr) || (g_psc != 0 && g_pslive == 0)) {
			done = 1;
			if (dtrace_stop(g_dtp) == -1)
				dfatal("couldn't stop tracing");
		}

		if (atomic_load(&g_session_stop)) {
			dtp_unlock();
			goto stopped_session;
		}
		switch (dtrace_work_consumer(g_dtp, g_otel != NULL ? NULL :
		    g_ofp, &con, NULL)) {
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_OKAY:
			break;
		default:
			if (!atomic_load(&g_impatient) &&
			    dtrace_errno(g_dtp) != EINTR)
				dfatal("processing aborted");
		}
		dtp_unlock();

		if (atomic_load(&g_session_stop))
			goto stopped_session;
		if (g_ofp != NULL && fflush(g_ofp) == EOF)
			clearerr(g_ofp);
		if (g_otel != NULL) {
			dtp_lock();
			if (dtotel_session_tick(g_otel) != 0)
				g_status = E_ERROR;
			dtp_unlock();
		}

	} while (!done);

	if (atomic_load(&g_session_stop))
		goto stopped_session;
	dtp_lock();
	if (!dtrace_oformat(g_dtp) && g_otel == NULL)
		oprintf("\n");

	impatient = atomic_load(&g_impatient);
	if (g_otel != NULL)
		otel_finish(!impatient);
	else if (arg != NULL) {
		if (!impatient &&
		    (!dtrace_oformat(g_dtp) || arg->print_upon_exit)) {
			if (dtrace_aggregate_print(g_dtp, g_ofp, NULL) == -1 &&
			    dtrace_errno(g_dtp) != EINTR)
				dfatal("failed to print aggregations");
		}
	}
	dtp_unlock();

stopped_session:
	dtp_lock();
	/* A stopped session exports only what was already accepted. */
	otel_finish(0);
	if (atomic_load(&g_session_stop))
		dtrace_oformat_discard(g_dtp);
	else
		dtrace_oformat_teardown(g_dtp);
	dtp_unlock();
	pthread_mutex_lock(&g_pgplistmtx);
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
	atomic_store(&g_output_worker_done, 1);
	return (NULL);
}

/* Called with the handle lock held (see execute_new_pgp()). */
static int
process_new_pgp(dtrace_prog_t *pgp, dtrace_prog_t *gpgp_resp)
{
	static size_t n_pgps = 0;
	dtrace_proginfo_t dpi;
	int err, n;

	if (gpgp_resp == NULL && pgp->dp_vmid != 0) {
		if (atomic_fetch_add(&g_intr, 1))
			atomic_store(&g_impatient, 1);
		fprintf(stderr,
		    "the guest program can only be NULL if program's vmid "
		    "is 0, but it is %u\n",
		    pgp->dp_vmid);
		return (-1);
	}

	if (gpgp_resp && ((pgp->dp_vmid != gpgp_resp->dp_vmid ||
	    pgp->dp_vmepoch != gpgp_resp->dp_vmepoch))) {
		if (atomic_fetch_add(&g_intr, 1))
			atomic_store(&g_impatient, 1);
		fprintf(stderr,
		    "mismatch between pgp and gpgp_resp vmids (%u != %u)",
		    pgp->dp_vmid, gpgp_resp->dp_vmid);
		return (-1);
	}

	if (pgp->dp_vmid != 0 && g_otel != NULL &&
	    dtotel_guest(dtotel_session_bridge(g_otel), pgp->dp_vmid,
	    pgp->dp_vmepoch, pgp->dp_vmname) != 0)
		error("failed to update the OpenTelemetry resource of VMID "
		    "%u\n", pgp->dp_vmid);

	if (pgp->dp_vmid != 0) {
		/*
		 * If no probes were enabled for this program, we don't need to
		 * do anything.
		 */
		if (gpgp_resp->dp_neprobes == 0) {
			if (g_quiet == 0)
				fprintf(stderr,
				    "Ignoring 0 probes from VMID %u\n",
				    gpgp_resp->dp_vmid);
			return (0);
		}

		n = dtrace_vprobes_create(g_dtp, gpgp_resp);
		if (n == -1) {
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			fprintf(stderr, "failed to create vprobes: %s\n",
			    strerror(errno));
			return (-1);
		}
	}

	/*
	 * Dump actions if we ask for verbose output.
	 */
	if (g_verbose) {
		fprintf(stderr, "Processing new program from: %s\n", pgp->dp_vmname);
		fprintf(stderr,
		    "=================================================================="
		    "\n");
		dtrace_dump_actions(pgp);
		fprintf(stderr,
		    "=================================================================="
		    "\n");
	}
	if (g_verbose > 1)
		dtrace_dump_ecbs(pgp);

	if (n_pgps == 0) {
		pthread_t worktd;

		/* The probe clock is local to this consumer, never shipped. */
		if (g_otel != NULL && otel_clock() != 0) {
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			return (-1);
		}
		if (dtrace_program_exec(g_dtp, pgp, &dpi) == -1) {
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			fprintf(stderr, "failed to enable program: %s",
			    strerror(errno));
			return (-1);
		} else {
			notice("matched %u probe%s (%hhx%hhx%hhx) from %u\n",
			    dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s",
			    pgp->dp_ident[0], pgp->dp_ident[1],
			    pgp->dp_ident[2], pgp->dp_vmid);
		}

		setup_tracing();
		atomic_store(&g_output_worker_done, 0);
		err = pthread_create(&worktd, NULL, dtc_work, NULL);
		if (err != 0) {
			atomic_store(&g_output_worker_done, 1);
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			fprintf(stderr, "failed to start tracing worker: %s\n",
			    strerror(err));
			return (-1);
		}
		g_worktd = worktd;
	} else {
		if (dtrace_augment_tracing(g_dtp, pgp)) {
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			fprintf(stderr, "failed to augment tracing: %s",
			    strerror(errno));
			return (-1);
		} else {
			notice("augmented with probes from (%hhx%hhx%hhx) %u\n",
			    pgp->dp_ident[0], pgp->dp_ident[1],
			    pgp->dp_ident[2], pgp->dp_vmid);
		}
	}

	if (n_pgps > 0 && dtrace_hypertrace_options_update(g_dtp) == -1)
		fatal("failed to load options\n");
	n_pgps++;
	return (0);
}

/* Executes a received program; the handle lock covers all of its use. */
static int
execute_new_pgp(dtrace_prog_t *pgp, dtrace_prog_t *gpgp_resp)
{
	int result;

	dtp_lock();
	/* Received programs are checked before they are enabled. */
	check_program_modref(pgp);
	result = process_new_pgp(pgp, gpgp_resp);
	dtp_unlock();
	return (result);
}

/* The receiver's earlier ACK proves parsing and derived publication only.
 * Report host execution on a separate one-shot consumer connection so its
 * retry cannot corrupt the receiver's ACK stream or the derived ELF stream.
 * A NAK can mean the ACK-to-HCR1 fsync has not finished yet; the daemon's
 * exact, fsynced phase transition makes retries idempotent. */
static int
report_identified_execution(const dtd_arg_t *connection,
    const dtraced_consumer_ack_t *execution)
{
	static const unsigned char zero_session[16] = {0};
	unsigned char frame[8 + DTRACED_MSGHDRSIZE +
	    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
	dtraced_hdr_t header = { .msg_type =
	    DTRACED_MSG_CONSUMER_EXECUTION };
	uint8_t session[16];
	int64_t deadline, attempt;
	unsigned char accepted;
	size_t transferred;
	int fd;

	if (connection == NULL || execution == NULL ||
	    execution->delivery_id == 0 ||
	    memcmp(execution->ingress_session, zero_session, 16) == 0) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(session, connection->rx_session, sizeof(session));
	header.elf.len = DTRACED_CONSUMER_EXECUTION_WIRE_SIZE;
	dtraced_wire_put_u64(frame, DTRACED_MSGHDRSIZE +
	    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE);
	dtraced_wire_encode_header(frame + 8, &header);
	dtraced_wire_encode_consumer_execution(frame + 8 + DTRACED_MSGHDRSIZE,
	    execution);
	deadline = dtraced_io_deadline_after(60000);
	if (deadline < 0)
		return (-1);
	for (;;) {
		if (atomic_load(&g_intr) || atomic_load(&g_session_stop)) {
			errno = EINTR;
			return (-1);
		}
		attempt = dtraced_io_deadline_after(5000);
		if (attempt < 0)
			return (-1);
		if (attempt > deadline)
			attempt = deadline;
		fd = open_dtraced_session(DTD_SUB_READDATA, session);
		if (fd >= 0) {
			int sent = dtraced_io_transfer(fd, frame,
			    sizeof(frame), true, attempt, &transferred) == 0 &&
			    dtraced_io_transfer(fd, &accepted, sizeof(accepted),
			    false, attempt, &transferred) == 0;
			(void)close(fd);
			if (sent && accepted == 1)
				return (0);
		}
		int64_t now = dtraced_io_milliseconds();
		if (now < 0)
			return (-1);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return (-1);
		}
		(void)usleep(100000);
	}
}

static void *
report_identified_executions(void *arg)
{
	dtd_arg_t *connection = arg;
	dt_execution_notice_t *notice;
	dt_execution_notice_t **slot;

	for (;;) {
		pthread_mutex_lock(&g_pgplistmtx);
		for (;;) {
			if (atomic_load(&g_intr) || atomic_load(&g_session_stop)) {
				pthread_mutex_unlock(&g_pgplistmtx);
				return (NULL);
			}
			for (slot = &g_execution_notices; *slot != NULL;
			    slot = &(*slot)->next) {
				if ((*slot)->wait_for == NULL ||
				    (*slot)->wait_for->execution_done)
					break;
			}
			if (*slot != NULL)
				break;
			if (g_execution_receiver_done) {
				pthread_mutex_unlock(&g_pgplistmtx);
				return (NULL);
			}
			pthread_cond_wait(&g_pgpcond, &g_pgplistmtx);
		}
		notice = *slot;
		*slot = notice->next;
		g_execution_notice_count--;
		g_execution_reporting = 1;
		int executed = notice->wait_for == NULL ||
		    notice->wait_for->execution_ok;
		pthread_mutex_unlock(&g_pgplistmtx);
		if (executed && report_identified_execution(connection,
		    &notice->result) != 0 && !atomic_load(&g_session_stop)) {
			fprintf(stderr, "dtrace: host execution receipt failed: "
			    "%s\n", strerror(errno));
			if (atomic_fetch_add(&g_intr, 1))
				atomic_store(&g_impatient, 1);
			pthread_mutex_lock(&g_pgplistmtx);
			pthread_cond_broadcast(&g_pgpcond);
			pthread_mutex_unlock(&g_pgplistmtx);
		}
		free(notice);
		pthread_mutex_lock(&g_pgplistmtx);
		g_execution_reporting = 0;
		pthread_cond_broadcast(&g_pgpcond);
		pthread_mutex_unlock(&g_pgplistmtx);
	}
}

/* A supervisor can retain one consumer session across a process restart.
 * The file is provisioned before connection admission and remains locked for
 * this process's lifetime; a short or malformed file never creates a fresh
 * identity that could abandon an accepted HCR1 recipient. */
static int
dtrace_consumer_session_load(const char *path, uint8_t session[16])
{
	uint8_t wire[4 + 16 + SHA256_DIGEST_LENGTH], digest[SHA256_DIGEST_LENGTH];
	static const uint8_t zero[16] = { 0 };
	struct stat st;
	ssize_t n;
	int fd, error;

	if (path == NULL || path[0] != '/' || session == NULL ||
	    g_hypertrace_session_fd >= 0) {
		errno = EINVAL;
		return (-1);
	}
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &st) != 0) {
		error = errno;
		goto fail;
	}
	if (!S_ISREG(st.st_mode) ||
	    st.st_uid != geteuid() || st.st_nlink != 1 ||
	    (st.st_mode & 077) != 0 || st.st_size != (off_t)sizeof(wire)) {
		error = EPROTO;
		goto fail;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		error = errno;
		goto fail;
	}
	do {
		n = pread(fd, wire, sizeof(wire), 0);
	} while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(wire) ||
	    memcmp(wire, "HCS1", 4) != 0 ||
	    SHA256(wire, 20, digest) == NULL ||
	    memcmp(wire + 20, digest, sizeof(digest)) != 0 ||
	    memcmp(wire + 4, zero, sizeof(zero)) == 0) {
		error = n < 0 ? errno : EPROTO;
		goto fail;
	}
	memcpy(session, wire + 4, 16);
	g_hypertrace_session_fd = fd;
	return (0);
fail:
	close(fd);
	errno = error;
	return (-1);
}

/*
 * Execute the specified program by enabling the corresponding instrumentation.
 * If -e has been specified, we get the program info but do not enable it.  If
 * -v has been specified, we print a stability report for the program.
 */
static void
exec_prog(const dtrace_cmd_t *dcp)
{
	dtrace_ecbdesc_t *last = NULL;
	dtrace_proginfo_t dpi;
	char template[MAXPATHLEN];
	char *elf;
	size_t elflen;
	int rx_sock;
	int wx_sock;
	size_t l;
	int fd;
	int err = 0;
	dtd_arg_t *dtd_arg = NULL;
	void *rval;
	dt_pgplist_t *pgpl = NULL;
	int again = 0;
	int tmpfd;
	uint64_t subs = 0;
	void *verictx, *merge;
	dtrace_prog_t *resp;
	dt_benchlist_t *be;
	hypertrace_errmsg_t errmsg;

	/* Every path leaves with the handle lock released or exits. */
	dtp_lock();
	dcp->dc_prog->dp_rflags = rslv;
	if (!g_elf || !g_exec)
		check_program_modref(dcp->dc_prog);

	if (g_graphfile) {
		FILE *graph_file = fopen(g_graphfile, "w");
		if (graph_file == NULL) {
			fprintf(stderr, "Failed to open %s for writing\n",
				g_graphfile);
			dtp_unlock();
			return;
		}

		dtrace_graph_program(g_dtp, dcp->dc_prog, graph_file);
		fclose(graph_file);
	}

	if (g_unsafe) {
		dtp_unlock();
		return;
	} else if (!g_exec) {
		dtrace_program_info(g_dtp, dcp->dc_prog, &dpi);
		if (g_elf) {
			tmpfd = tmp_mkstemp(template, sizeof(template),
			    "dtrace-execprog");
			if (tmpfd == -1)
				fatal("failed to mkstemp()");


			/*
			 * In this case we don't really send anything, we just
			 * create the ELF file for debugging purposes and output
			 * where it was created.
			 */
			err = dtrace_elf_create(g_dtp, dcp->dc_prog,
			    ELFDATA2LSB, tmpfd, template, errmsg);
			if (err)
				fatal("failed to create elf file: %s: %s\n",
				    dtrace_hypertrace_errstr(err), errmsg);
			printf("%s\n", template);
			/* Kept for inspection: no longer a temporary file. */
			tmp_track(template, 0);

			close(tmpfd);
		}
	} else if (g_elf) {
		if (consumer_descendants_prepare() != 0)
			fatal("cannot establish collector descendant ownership: %s\n",
			    strerror(errno));
		installsighands();
		uint8_t consumer_program_digest[32], registration[64] = {0};
		dtrace_handle_lifetime_t lifetime;
		dtraced_hdr_t program_message = { 0 };
		if (dtrace_program_compiled_digest(g_dtp, dcp->dc_prog,
		    consumer_program_digest) != 0)
			fatal("failed to identify compiled HyperTrace program");

		/*
		 * We open a dtraced socket because we expect the following
		 * things to happen:
		 *  (1) We write our ELF file to /var/ddtrace/outbound
		 *  (2) dtraced forwards it to the traced machine (can be host)
		 *  (3) dtraced DTrace applies relocations to the program
		 *  (4) dtraced dtraced sends it back to host dtraced
		 *  (5) dtraced writes out the ELF file to this DTrace
		 *      instance for further processing.
		 */
		uint8_t rx_session[16] = { 0 };
		/* Every program is in this one (hypertrace_combine()). */
		if (g_hypertrace_session_file != NULL) {
			if (dtrace_consumer_session_load(
			    g_hypertrace_session_file, rx_session) != 0)
				fatal("cannot load exclusive HyperTrace consumer "
				    "session: %s\n", strerror(errno));
		}
		if (dtrace_handle_identity(g_dtp, &lifetime) != 0)
			fatal("cannot identify HyperTrace DTrace handle: %s\n",
			    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
		memcpy(registration, "HPI2", 4);
		memcpy(registration + 8, consumer_program_digest, 32);
		dtraced_wire_put_u64(registration + 40, lifetime.generation[0]);
		dtraced_wire_put_u64(registration + 48, lifetime.generation[1]);
		dtraced_wire_put_u64(registration + 56, lifetime.serial);
		rx_sock = open_dtraced_session(DTD_SUB_ELFWRITE, rx_session);
		if (rx_sock == -1)
			fatal("failed to open rx_sock");
		program_message.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
		program_message.elf.len = sizeof(registration);
		if (dtrace_send_message(rx_sock, &program_message,
		    registration, sizeof(registration)) != 0)
			fatal("failed to bind HyperTrace consumer program: %s\n",
			    strerror(errno));
		wx_sock = open_dtraced(DTD_SUB_READDATA);
		if (wx_sock == -1)
			fatal("failed to open wx_sock");

		g_e2ebench = dt_bench_new("hypertrace_end2end",
		    "HyperTrace end to end benchmark", DT_BENCHKIND_TIME, 0);

		if (g_e2ebench == NULL)
			fatal("failed to create new benchmark");

		if (dt_bench_start(g_e2ebench) == -1)
			fatal("failed to start g_e2ebench");

		tmpfd = tmp_mkstemp(template, sizeof(template),
		    "dtrace-execprog");
		if (tmpfd == -1)
			fatal("failed to mkstemp()");
		if (g_verbose) {
			fprintf(stderr, "Initial program:\n");
			fprintf(stderr,
			    "=================================================================="
			    "\n");
			dtrace_dump_actions(dcp->dc_prog);
			fprintf(stderr,
			    "=================================================================="
			    "\n");
		}
		if (g_verbose > 1)
			dtrace_dump_ecbs(dcp->dc_prog);

		err = dtrace_elf_create(g_dtp, dcp->dc_prog, ELFDATA2LSB, tmpfd,
		    template, errmsg);
		if (err)
			fatal("failed to create elf file: %s: %s\n",
			    dtrace_hypertrace_errstr(err), errmsg);
		(void) tmp_unlink(template);

		if (fsync(tmpfd))
			fatal("failed to sync file");

		if (lseek(tmpfd, 0, SEEK_SET))
			fatal("lseek() failed");

		if (dtrace_send_elf(dcp->dc_prog, tmpfd, wx_sock, "base", 0))
			fatal("failed to dtrace_send_elf()");

		close(tmpfd);

		dtd_arg = malloc(sizeof(dtd_arg_t));
		if (dtd_arg == NULL)
			fatal("failed to malloc dtd_arg");

		dtd_arg->rx_sock = rx_sock;
		dtd_arg->wx_sock = wx_sock;
		memcpy(dtd_arg->rx_session, rx_session,
		    sizeof(dtd_arg->rx_session));
		memcpy(dtd_arg->program_registration, registration, sizeof(registration));
		memcpy(dtd_arg->program_digest, consumer_program_digest,
		    sizeof(dtd_arg->program_digest));
		explicit_bzero(registration, sizeof(registration));
		dtd_arg->hostpgp = dcp->dc_prog;

		/* The receiver and reporter now share the handle. */
		dtp_unlock();
		err = pthread_create(&g_executiontd, NULL,
		    report_identified_executions, dtd_arg);
		if (err != 0)
			fatal("failed to create g_executiontd");
		err = pthread_create(&g_dtracedtd, NULL,
		    listen_dtraced, dtd_arg);
		if (err != 0)
			fatal("failed to create g_dtracedtd");

		for (;;) {
			/*
			 * Wait for us to actually have a program in the list
			 */
again:
			pthread_mutex_lock(&g_pgplistmtx);
			while (!atomic_load(&g_intr) &&
			    !atomic_load(&g_stop) &&
			    (dt_list_next(&g_pgplist) == NULL ||
			    again == 1)) {
				pthread_cond_wait(&g_pgpcond, &g_pgplistmtx);
				again = 0;
			}

			if (atomic_load(&g_intr) ||
			    atomic_load(&g_stop)) {
				pthread_mutex_unlock(&g_pgplistmtx);
				break;
			}

			/*
			 * We are in a situation where the condition variable
			 * has been triggered and we expect to have at least one
			 * pgplist entry which contains both the probe
			 * specification that we need to create on the host and
			 * the program that we need to run.
			 */
			for (pgpl = dt_list_next(&g_pgplist); pgpl;
			     pgpl = dt_list_next(pgpl)) {
				if (pgpl_valid(pgpl))
					break;
			}

			if (pgpl == NULL) {
				again = 1;
				pthread_mutex_unlock(&g_pgplistmtx);
				goto again;
			}

			dt_list_delete(&g_pgplist, pgpl);
			g_processing_pgp = 1;
			/* A completed host program may still have a pending HCR1 if
			 * its last ACK was lost. Preserve its exact derived result for
			 * an in-process replay, outside the active execution queue. */
			if (pgpl->derived_parent_known)
				dt_list_append(&g_derived_replaylist, pgpl);
			pthread_mutex_unlock(&g_pgplistmtx);

			resp = pgpl->response;
			int executed = execute_new_pgp(pgpl->pgp, resp);
			pthread_mutex_lock(&g_pgplistmtx);
			g_processing_pgp = 0;
			pgpl->execution_done = 1;
			pgpl->execution_ok = executed == 0;
			pthread_cond_broadcast(&g_pgpcond);
			pthread_mutex_unlock(&g_pgplistmtx);
			if (pgpl->vmid != 0)
				dt_list_append(&g_kill_list, resp);
		}

		err = pthread_join(g_dtracedtd, NULL);
		if (err != 0)
			fatal("failed to join g_dtracedtd: %s\n", strerror(err));
		pthread_mutex_lock(&g_pgplistmtx);
		g_execution_receiver_done = 1;
		pthread_cond_broadcast(&g_pgpcond);
		pthread_mutex_unlock(&g_pgplistmtx);
		err = pthread_join(g_executiontd, NULL);
		if (err != 0)
			fatal("failed to join g_executiontd: %s\n", strerror(err));
		while (g_execution_notices != NULL) {
			dt_execution_notice_t *notice = g_execution_notices;
			g_execution_notices = notice->next;
			free(notice);
		}
		g_execution_notice_count = 0;

		for (resp = dt_list_next(&g_kill_list);
		     resp && !atomic_load(&g_session_stop);
		     resp = dt_list_next(resp)) {
			if (send_kill(dtd_arg->wx_sock, resp))
				fprintf(stderr, "send_kill() failed with: %s\n",
				    strerror(errno));
		}

		dt_bench_stop(g_e2ebench);
		pthread_mutex_lock(&g_benchlistmtx);
		dt_list_append(&g_benchlist, new_bench_list_entry(g_e2ebench));
		pthread_mutex_unlock(&g_benchlistmtx);

		merge = NULL;
		if (!atomic_load(&g_session_stop)) {
			set_snapshot_names();
			merge = merge_benchmarks();
			dt_bench_dump(dt_merge_get(merge), dt_merge_size(merge),
			    g_bench_path, g_script);
		}

		pthread_mutex_lock(&g_benchlistmtx);
		while ((be = dt_list_next(&g_benchlist)) != NULL) {
			dt_list_delete(&g_benchlist, be);
			dt_bench_free(be->bench);
			free(be);
		}
		pthread_mutex_unlock(&g_benchlistmtx);

		if (merge != NULL)
			dt_merge_cleanup(merge);
		dtrace_async_teardown();

		if (g_worktd) {
			err = pthread_join(g_worktd, NULL);
			if (err != 0)
				fprintf(stderr, "failed to join g_worktd\n");
		}

		/* The signal thread may still use g_pgplistmtx/g_pgpcond:
		 * they are not destroyed. */
		if (dtd_arg->rx_sock >= 0)
			close(dtd_arg->rx_sock);
		if (dtd_arg->wx_sock >= 0)
			close(dtd_arg->wx_sock);
		free(dtd_arg);
		dtp_lock();
		dtrace_close(g_dtp);
		g_dtp = NULL;
		exit(0);
	} else if ((err = hypertrace_link(g_dtp, dcp->dc_prog, errmsg)) == 0) {
		if (g_verbose)
			dtrace_dump_actions(dcp->dc_prog);
		verictx = dt_verictx_init(g_dtp);
		if (dt_prog_verify(verictx, dcp->dc_prog, dcp->dc_prog) != 0)
			dfatal("failed to verify %p", dcp->dc_prog);

		dt_verictx_teardown(verictx);
		if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1) {
			dfatal("failed to enable '%s'", dcp->dc_name);
		} else {
			notice("%s '%s' matched %u probe%s\n",
			    dcp->dc_desc, dcp->dc_name,
			    dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s");
		}
		/* main() starts tracing once every program is enabled:
		 * dtrace(4) refuses ENABLE on an active state (EBUSY). */
	} else {
		link_failed(dcp->dc_prog, "failed to apply relocations", err,
		    errmsg);
	}

	if (g_verbose) {
		oprintf("\nStability attributes for %s %s:\n",
		    dcp->dc_desc, dcp->dc_name);

		oprintf("\n\tMinimum Probe Description Attributes\n");
		oprintf("\t\tIdentifier Names: %s\n",
		    dtrace_stability_name(dpi.dpi_descattr.dtat_name));
		oprintf("\t\tData Semantics:   %s\n",
		    dtrace_stability_name(dpi.dpi_descattr.dtat_data));
		oprintf("\t\tDependency Class: %s\n",
		    dtrace_class_name(dpi.dpi_descattr.dtat_class));

		oprintf("\n\tMinimum Statement Attributes\n");

		oprintf("\t\tIdentifier Names: %s\n",
		    dtrace_stability_name(dpi.dpi_stmtattr.dtat_name));
		oprintf("\t\tData Semantics:   %s\n",
		    dtrace_stability_name(dpi.dpi_stmtattr.dtat_data));
		oprintf("\t\tDependency Class: %s\n",
		    dtrace_class_name(dpi.dpi_stmtattr.dtat_class));

		if (!g_exec) {
			(void) dtrace_stmt_iter(g_dtp, dcp->dc_prog,
			    (dtrace_stmt_f *)info_stmt, &last);
		} else
			oprintf("\n");
	}

	g_total += dpi.dpi_matches;
	dtp_unlock();
}

/*
 * A HyperTrace host (-E) forwards one ELF to dtraced and binds one compiled
 * program digest to its consumer session, and each guest links, enables and
 * returns that one program.  Every -s/-n/-P/-m/-f/-i program is therefore
 * appended, in command-line order, to the first one, and exec_prog() serves
 * the result once: guests run every program, with one session, one drain
 * and one stop for all of them, as a local consumer enables every program
 * before it starts tracing.  -e writes this same combined ELF.
 */
static void
hypertrace_combine(dtrace_cmd_t *dcp)
{
	int i, err;

	*dcp = g_cmdv[0];
	if (g_cmdc == 1)
		return;
	dtp_lock();
	for (i = 1, err = 0; i < g_cmdc && err == 0; i++)
		err = dtrace_program_append(g_dtp, dcp->dc_prog,
		    g_cmdv[i].dc_prog);
	dtp_unlock();
	/* dfatal() reads the handle's error under the handle lock. */
	if (err != 0)
		dfatal("failed to combine %s '%s' into the HyperTrace program",
		    g_cmdv[i - 1].dc_desc, g_cmdv[i - 1].dc_name);
	dcp->dc_desc = "HyperTrace";
	dcp->dc_name = "program";
	if (g_verbose)
		notice("combined %d programs into one HyperTrace program\n",
		    g_cmdc);
}

/*
 * Print out the specified DOF buffer as a set of ASCII bytes appropriate for
 * storing in a driver.conf(4) file associated with the dtrace driver.
 */
static void
anon_prog(const dtrace_cmd_t *dcp, dof_hdr_t *dof, int n)
{
	const uchar_t *p, *q;

	if (dof == NULL)
		dfatal("failed to create DOF image for '%s'", dcp->dc_name);

	p = (uchar_t *)dof;
	q = p + dof->dofh_filesz;

#ifdef __FreeBSD__
	/*
	 * On FreeBSD, the DOF file is read directly during boot - just write
	 * two hex characters per byte.
	 */
	oprintf("dof-data-%d=", n);

	while (p < q)
		oprintf("%02x", *p++);

	oprintf("\n");
#else
	oprintf("dof-data-%d=0x%x", n, *p++);

	while (p < q)
		oprintf(",0x%x", *p++);

	oprintf(";\n");
#endif

	dtrace_dof_destroy(g_dtp, dof);
}

/*
 * Link the specified D program in DOF form into an ELF file for use in either
 * helpers, userland provider definitions, or both.  If -o was specified, that
 * path is used as the output file name.  If -o wasn't specified and the input
 * program is from a script whose name is %.d, use basename(%.o) as the output
 * file name.  Otherwise we use "d.out" as the default output file name.
 */
static void
link_prog(dtrace_cmd_t *dcp)
{
	char *p;

	if (g_cmdc == 1 && g_ofile != NULL) {
		(void) strlcpy(dcp->dc_ofile, g_ofile, sizeof (dcp->dc_ofile));
	} else if ((p = strrchr(dcp->dc_arg, '.')) != NULL &&
	    strcmp(p, ".d") == 0) {
		p[0] = '\0'; /* strip .d suffix */
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "%s.o", basename(dcp->dc_arg));
	} else if (g_cmdc > 1) {
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "d.out.%td", dcp - g_cmdv);
	} else {
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "d.out");
	}

	if (dtrace_program_link(g_dtp, dcp->dc_prog, DTRACE_D_PROBES,
	    dcp->dc_ofile, g_objc, g_objv) != 0)
		dfatal("failed to link %s %s", dcp->dc_desc, dcp->dc_name);
}

/*ARGSUSED*/
static int
list_probe(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp, void *arg)
{
	dtrace_probeinfo_t p;

	oprintf("%5d %10s %17s %33s %s\n", pdp->dtpd_id,
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	if (g_verbose && dtrace_probe_info(dtp, pdp, &p) == 0)
		print_probe_info(&p);

	if (atomic_load(&g_intr) != 0)
		return (1);


	return (0);
}

/*ARGSUSED*/
static int
list_stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmtdesc_t *stp, dtrace_ecbdesc_t **last)
{
	dtrace_ecbdesc_t *edp = stp->dtsd_ecbdesc;

	if (edp == *last)
		return (0);

	if (dtrace_probe_iter(g_dtp, &edp->dted_probe, list_probe, NULL) != 0) {
		error("failed to match %s:%s:%s:%s: %s\n",
		    edp->dted_probe.dtpd_provider, edp->dted_probe.dtpd_mod,
		    edp->dted_probe.dtpd_func, edp->dted_probe.dtpd_name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}

	*last = edp;
	return (0);
}

/*
 * List the probes corresponding to the specified program by iterating over
 * each statement and then matching probes to the statement probe descriptions.
 */
static void
list_prog(const dtrace_cmd_t *dcp)
{
	dtrace_ecbdesc_t *last = NULL;

	(void) dtrace_stmt_iter(g_dtp, dcp->dc_prog,
	    (dtrace_stmt_f *)list_stmt, &last);
}

static void
compile_file(dtrace_cmd_t *dcp)
{
	char *arg0;
	FILE *fp;

	if ((fp = fopen(dcp->dc_arg, "r")) == NULL)
		fatal("failed to open %s", dcp->dc_arg);

	arg0 = g_argv[0];
	g_argv[0] = dcp->dc_arg;

	if ((dcp->dc_prog = dtrace_program_fcompile(g_dtp, fp,
	    g_cflags, g_argc, g_argv)) == NULL)
		dfatal("failed to compile script %s", dcp->dc_arg);

	if (g_verbose)
		dtrace_dump_actions(dcp->dc_prog);
	g_argv[0] = arg0;
	(void) fclose(fp);

	dcp->dc_desc = "script";
	dcp->dc_name = dcp->dc_arg;
}

static int
link_elf(dtrace_cmd_t *dcp, char *progpath)
{
	int fd;
	dt_stmt_t *stp;
	int err = 0;
	void *dof = NULL;
	int prog_exec = 0;
	hypertrace_errmsg_t errmsg;

	assert(g_elf == 1);

	if ((fd = open(progpath, O_RDONLY)) < 0)
		fatal("failed to open %s with %s\n", progpath, strerror(errno));

	fprintf(stderr, "dtrace_elf_parse() call\n");
	dcp->dc_prog = dtrace_elf_parse(g_dtp, fd, progpath, 1, &err, errmsg,
	    NULL);
	fprintf(stderr, "prog = %p\n", dcp->dc_prog);
	if (dcp->dc_prog == NULL) {
		fatal("failed to parse the ELF file %s: %s: %s\n", dcp->dc_arg,
		    dtrace_hypertrace_errstr(err), errmsg);
	}

	prog_exec = dcp->dc_prog->dp_exec;
	close(fd);
	check_program_modref(dcp->dc_prog);

	dcp->dc_desc = "ELF file";
	dcp->dc_name = dcp->dc_arg;

	fprintf(stderr, "prog_exec = %d\n", prog_exec);
	return (prog_exec);
}

static void
process_elf(dtrace_cmd_t *dcp)
{
	dtrace_proginfo_t dpi;
	int prog_exec;

	dtp_lock();
	prog_exec = link_elf(dcp, dcp->dc_arg);
	if (!g_exec) {
		/* -e: link only; exec_prog() writes the linked ELF for inspection. */
		dtp_unlock();
		return;
	}
	if (prog_exec != DT_PROG_EXEC) {
		if (g_verbose >= 1)
			fprintf(stderr, "not executing %s\n", dcp->dc_arg);
		fprintf(stderr, "%s: %s: program is not marked for execution\n",
		    g_pname, dcp->dc_arg);
		dtp_unlock();
		g_status = E_ERROR;
		g_elfrun = 1;
		return;
	}

	/*
	 * -y runs the provided ELF here: enable its program, trace, and
	 * consume until it ends.  It is a complete command; main() does not
	 * continue into the host consumer path afterwards.
	 */
	if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1)
		fatal("failed to enable %s: %s\n", dcp->dc_arg,
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	notice("matched %u probe%s\n", dpi.dpi_matches,
	    dpi.dpi_matches == 1 ? "" : "s");
	setup_tracing();
	dtp_unlock();
	pthread_create(&g_worktd, NULL, dtc_work, NULL);
	pthread_join(g_worktd, NULL);
	g_worktd = 0;
	g_elfrun = 1;
}

static void
process_elf_hypertrace(dtrace_cmd_t *dcp)
{
	char template[MAXPATHLEN];
	char *progpath, *hostorguest;
	int host, prog_exec, i, tmpfd, dtraced_sock, err, installed;
	int64_t report_deadline;
	dtrace_proginfo_t dpi;
	hypertrace_errmsg_t errmsg;

	progpath = strtok(dcp->dc_arg, ",");
	if (progpath == NULL)
		fatal("failed to tokenize %s\n", dcp->dc_arg);

	hostorguest = strtok(NULL, ",");
	if (hostorguest && strcmp(hostorguest, "host") == 0)
		host = 1;
	else if (hostorguest && strcmp(hostorguest, "guest") == 0)
		host = 0;
	else if (hostorguest == NULL)
		host = 0;
	else
		fatal("unexpected string in -Y: %s\n", hostorguest);

	fprintf(stderr, "dtrace: link_elf(%s)\n", progpath);
	dtp_lock();
	prog_exec = link_elf(dcp, progpath);
	installed = 0;
	if (g_verbose) {
		fprintf(stderr, "Unrelocated program:\n");
		fprintf(stderr,
		    "=================================================================="
		    "\n");
		dtrace_dump_actions(dcp->dc_prog);
		fprintf(stderr,
		    "=================================================================="
		    "\n");
	}

	if (g_verbose > 1) {
		fprintf(stderr, "ECBs from an unrelocated program:\n");
		dtrace_dump_ecbs(dcp->dc_prog);
	}

	if ((err = hypertrace_link(g_dtp, dcp->dc_prog, errmsg)) != 0)
		link_failed(dcp->dc_prog, "Failed to apply relocations", err,
		    errmsg);

	if (g_verbose) {
		fprintf(stderr, "Relocated program:\n");
		fprintf(stderr,
		    "=================================================================="
		    "\n");
		dtrace_dump_actions(dcp->dc_prog);
		fprintf(stderr,
		    "=================================================================="
		    "\n");
	}

	if (g_verbose > 1) {
		fprintf(stderr, "ECBs from a relocated program:\n");
		dtrace_dump_ecbs(dcp->dc_prog);
	}

	if ((prog_exec == DT_PROG_EXEC && g_allow_root_srcident) ||
	    (prog_exec == DT_PROG_EXEC && g_has_idents)) {
		if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1) {
			dfatal("failed to enable program");
		} else {
			notice(
			    "process_elf_hypertrace(): matched %u probe%s\n",
			    dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s");
		}

		/*
		 * If we are actually tracing things, we will need to stop at
		 * some point. Get the pid so that the host can send a message
		 * to dtraced to kill us later.
		 */
		assert(dtrace_is_guest(g_dtp) != 0);
		dcp->dc_prog->dp_pid = getpid();
		setup_tracing();
		dtp_unlock();
		err = pthread_create(&g_worktd, NULL, dtc_work, NULL);
		dtp_lock();
		if (err != 0)
			fatal("failed to start tracing worker: %s\n", strerror(err));
		installed = 1;
	}
	/* Network and file I/O below run without the handle lock. */
	dtp_unlock();
	dtraced_sock = open_dtraced(DTD_SUB_READDATA);
	if (dtraced_sock == -1)
		fatal("failed to open dtraced");
	tmpfd = tmp_mkstemp(template, sizeof(template), "dtrace-process-elf");
	if (tmpfd == -1)
		fatal("mkstemp() failed (%s)", template);
	dtp_lock();
	err = dtrace_elf_create(g_dtp, dcp->dc_prog, ELFDATA2LSB, tmpfd,
	    template, errmsg);
	dtp_unlock();
	if (err)
		fatal("failed to create ELF file: %s: %s\n",
		    dtrace_hypertrace_errstr(err), errmsg);
	if (fsync(tmpfd))
		fatal("failed to sync file");
	if (lseek(tmpfd, 0, SEEK_SET))
		fatal("lseek() failed");
	fprintf(stderr, "dtrace: send_elf(%s)\n", template);
	if (dtrace_send_elf(dcp->dc_prog, tmpfd, dtraced_sock,
	    host ? "inbound" : "outbound",
	    host ? 0 : prog_exec == DT_PROG_EXEC ? 0 : 1))
		fatal("failed to dtrace_send_elf()");
	if (g_has_idents && getenv("HYPERTRACE_LAUNCH_REPORT") != NULL) {
		report_deadline = dtraced_io_deadline_after(10000);
		if (report_deadline < 0)
			fatal("failed to set guest report deadline: %s\n",
			    strerror(errno));
		if (dtrace_write_launch_result(STDOUT_FILENO, installed,
		    dcp->dc_prog->dp_srcident, DT_PROG_IDENTLEN,
		    report_deadline) != 0)
			fatal("failed to report guest installation: %s\n",
			    strerror(errno));
	}
	(void) tmp_unlink(template);
	close(tmpfd);
	close(dtraced_sock);
	if (g_worktd && prog_exec == DT_PROG_EXEC)
		(void)pthread_join(g_worktd, NULL);
	/* Exit holding the handle lock: no other thread may use it. */
	dtp_lock();
	dtrace_close(g_dtp);
	g_dtp = NULL;
	exit(g_status);
}

static void
compile_str(dtrace_cmd_t *dcp)
{
	char *p;

	if ((dcp->dc_prog = dtrace_program_strcompile(g_dtp, dcp->dc_arg,
	    dcp->dc_spec, g_cflags | DTRACE_C_PSPEC, g_argc, g_argv)) == NULL)
		dfatal("invalid probe specifier %s", dcp->dc_arg);

	if ((p = strpbrk(dcp->dc_arg, "{/;")) != NULL)
		*p = '\0'; /* crop name for reporting */

	dcp->dc_desc = "description";
	dcp->dc_name = dcp->dc_arg;
}

/*ARGSUSED*/
static void
prochandler(struct ps_prochandle *P, const char *msg, void *arg)
{
#ifdef illumos
	const psinfo_t *prp = Ppsinfo(P);
	int pid = Pstatus(P)->pr_pid;
	char name[SIG2STR_MAX];
#else
	int wstatus = proc_getwstat(P);
	int pid = proc_getpid(P);
#endif

	if (msg != NULL) {
		notice("pid %d: %s\n", pid, msg);
		return;
	}

#ifdef illumos
	switch (Pstate(P)) {
#else
	switch (proc_state(P)) {
#endif
	case PS_UNDEAD:
#ifdef illumos
		/*
		 * Ideally we would like to always report pr_wstat here, but it
		 * isn't possible given current /proc semantics.  If we grabbed
		 * the process, Ppsinfo() will either fail or return a zeroed
		 * psinfo_t depending on how far the parent is in reaping it.
		 * When /proc provides a stable pr_wstat in the status file,
		 * this code can be improved by examining this new pr_wstat.
		 */
		if (prp != NULL && WIFSIGNALED(prp->pr_wstat)) {
			notice("pid %d terminated by %s\n", pid,
			    proc_signame(WTERMSIG(prp->pr_wstat),
			    name, sizeof (name)));
#else
		if (WIFSIGNALED(wstatus)) {
			notice("pid %d terminated by %d\n", pid,
			    WTERMSIG(wstatus));
#endif
#ifdef illumos
		} else if (prp != NULL && WEXITSTATUS(prp->pr_wstat) != 0) {
			notice("pid %d exited with status %d\n",
			    pid, WEXITSTATUS(prp->pr_wstat));
#else
		} else if (WEXITSTATUS(wstatus) != 0) {
			notice("pid %d exited with status %d\n",
			    pid, WEXITSTATUS(wstatus));
#endif
		} else {
			notice("pid %d has exited\n", pid);
		}

		/* Called under the handle lock from dtrace_sleep(): defer the
		 * g_pgplistmtx broadcast to the worker (lock order). */
		atomic_store(&g_stop, 1);
		atomic_store(&g_proc_wake, 1);
		g_pslive--;
		break;

	case PS_LOST:
		notice("pid %d exec'd a set-id or unobservable program\n", pid);
		g_pslive--;
		break;
	}
}

/*ARGSUSED*/
static int
errhandler(const dtrace_errdata_t *data, void *arg)
{
	error(data->dteda_msg);
	/* OpenTelemetry: an ERROR log record and the errors counter. */
	if (g_otel != NULL)
		dtotel_error_record(dtotel_session_bridge(g_otel), data);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
drophandler(const dtrace_dropdata_t *data, void *arg)
{
	if (!dtrace_oformat(g_dtp)) {
		error(data->dtdda_msg);
	}
	if (g_otel != NULL)
		dtotel_drops(dtotel_session_bridge(g_otel), data->dtdda_kind,
		    data->dtdda_drops);

	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
setopthandler(const dtrace_setoptdata_t *data, void *arg)
{
	if (strcmp(data->dtsda_option, "quiet") == 0)
		g_quiet = data->dtsda_newval != DTRACEOPT_UNSET;

	if (strcmp(data->dtsda_option, "flowindent") == 0)
		g_flowindent = data->dtsda_newval != DTRACEOPT_UNSET;

	return (DTRACE_HANDLE_OK);
}

#define	BUFDUMPHDR(hdr) \
	(void) printf("%s: %s%s\n", g_pname, hdr, strlen(hdr) > 0 ? ":" : "");

#define	BUFDUMPSTR(ptr, field) \
	(void) printf("%s: %20s => ", g_pname, #field);	\
	if ((ptr)->field != NULL) {			\
		const char *c = (ptr)->field;		\
		(void) printf("\"");			\
		do {					\
			if (*c == '\n') {		\
				(void) printf("\\n");	\
				continue;		\
			}				\
							\
			(void) printf("%c", *c);	\
		} while (*c++ != '\0');			\
		(void) printf("\"\n");			\
	} else {					\
		(void) printf("<NULL>\n");		\
	}

#define	BUFDUMPASSTR(ptr, field, str) \
	(void) printf("%s: %20s => %s\n", g_pname, #field, str);

#define	BUFDUMP(ptr, field) \
	(void) printf("%s: %20s => %lld\n", g_pname, #field, \
	    (long long)(ptr)->field);

#define	BUFDUMPPTR(ptr, field) \
	(void) printf("%s: %20s => %s\n", g_pname, #field, \
	    (ptr)->field != NULL ? "<non-NULL>" : "<NULL>");

/*ARGSUSED*/
static int
bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
	const dtrace_aggdata_t *agg = bufdata->dtbda_aggdata;
	const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
	const dtrace_probedesc_t *pd;
	uint32_t flags = bufdata->dtbda_flags;
	char buf[512], *c = buf, *end = c + sizeof (buf);
	int i, printed;

	struct {
		const char *name;
		uint32_t value;
	} flagnames[] = {
	    { "AGGVAL",		DTRACE_BUFDATA_AGGVAL },
	    { "AGGKEY",		DTRACE_BUFDATA_AGGKEY },
	    { "AGGFORMAT",	DTRACE_BUFDATA_AGGFORMAT },
	    { "AGGLAST",	DTRACE_BUFDATA_AGGLAST },
	    { "???",		UINT32_MAX },
	    { NULL }
	};

	if (bufdata->dtbda_probe != NULL) {
		pd = bufdata->dtbda_probe->dtpda_pdesc;
	} else if (agg != NULL) {
		pd = agg->dtada_pdesc;
	} else {
		pd = NULL;
	}

	BUFDUMPHDR(">>> Called buffer handler");
	BUFDUMPHDR("");

	BUFDUMPHDR("  dtrace_bufdata");
	BUFDUMPSTR(bufdata, dtbda_buffered);
	BUFDUMPPTR(bufdata, dtbda_probe);
	BUFDUMPPTR(bufdata, dtbda_aggdata);
	BUFDUMPPTR(bufdata, dtbda_recdesc);

	(void) snprintf(c, end - c, "0x%x ", bufdata->dtbda_flags);
	c += strlen(c);

	for (i = 0, printed = 0; flagnames[i].name != NULL; i++) {
		if (!(flags & flagnames[i].value))
			continue;

		(void) snprintf(c, end - c,
		    "%s%s", printed++ ? " | " : "(", flagnames[i].name);
		c += strlen(c);
		flags &= ~flagnames[i].value;
	}

	if (printed)
		(void) snprintf(c, end - c, ")");

	BUFDUMPASSTR(bufdata, dtbda_flags, buf);
	BUFDUMPHDR("");

	if (pd != NULL) {
		BUFDUMPHDR("  dtrace_probedesc");
		BUFDUMPSTR(pd, dtpd_provider);
		BUFDUMPSTR(pd, dtpd_mod);
		BUFDUMPSTR(pd, dtpd_func);
		BUFDUMPSTR(pd, dtpd_name);
		BUFDUMPHDR("");
	}

	if (rec != NULL) {
		BUFDUMPHDR("  dtrace_recdesc");
		BUFDUMP(rec, dtrd_action);
		BUFDUMP(rec, dtrd_size);

		if (agg != NULL) {
			uint8_t *data;
			int lim = rec->dtrd_size;

			(void) sprintf(buf, "%d (data: ", rec->dtrd_offset);
			c = buf + strlen(buf);

			if (lim > sizeof (uint64_t))
				lim = sizeof (uint64_t);

			data = (uint8_t *)agg->dtada_data + rec->dtrd_offset;

			for (i = 0; i < lim; i++) {
				(void) snprintf(c, end - c, "%s%02x",
				    i == 0 ? "" : " ", *data++);
				c += strlen(c);
			}

			(void) snprintf(c, end - c,
			    "%s)", lim < rec->dtrd_size ? " ..." : "");
			BUFDUMPASSTR(rec, dtrd_offset, buf);
		} else {
			BUFDUMP(rec, dtrd_offset);
		}

		BUFDUMPHDR("");
	}

	if (agg != NULL) {
		dtrace_aggdesc_t *desc = agg->dtada_desc;

		BUFDUMPHDR("  dtrace_aggdesc");
		BUFDUMPSTR(desc, dtagd_name);
		BUFDUMP(desc, dtagd_varid);
		BUFDUMP(desc, dtagd_id);
		BUFDUMP(desc, dtagd_nrecs);
		BUFDUMPHDR("");
	}

	return (DTRACE_HANDLE_OK);
}

static void compile_file(dtrace_cmd_t *);
static void compile_str(dtrace_cmd_t *);

/*
 * Open the OpenTelemetry session: the scripts' text names the
 * aggregation keys, the first script names the records.
 */
static void
otel_open(void)
{
	struct dtotel_session_config cfg;
	struct oe_buf src;
	char err[256], buf[4096], *profile, *dot;
	size_t n;
	FILE *fp;
	int i;

	/*
	 * The D text, for aggregation key names: -s scripts are read
	 * again; the rest (-n, -P, -m, -f, -i) are D text already, as
	 * -x otel excludes the ELF options.
	 */
	oe_buf_init(&src);
	for (i = 0; i < g_cmdc; i++) {
		if (g_cmdv[i].dc_func != compile_file) {
			oe_buf_appendstr(&src, g_cmdv[i].dc_arg);
			oe_buf_append(&src, "\n", 1);
			continue;
		}
		if ((fp = fopen(g_cmdv[i].dc_arg, "r")) == NULL)
			continue;
		while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
			oe_buf_append(&src, buf, n);
		fclose(fp);
	}
	if (src.error)
		fatal("failed to allocate memory");
	/* Records are named after the first script. */
	profile = NULL;
	for (i = 0; i < g_cmdc; i++) {
		if (g_cmdv[i].dc_func == compile_file) {
			profile = strdup(basename(g_cmdv[i].dc_arg));
			break;
		}
	}
	if (profile != NULL && (dot = strrchr(profile, '.')) != NULL &&
	    dot != profile)
		*dot = '\0';
	memset(&cfg, 0, sizeof(cfg));
	cfg.options = &g_otel_opts;
	cfg.dtp = g_dtp;
	cfg.output = g_ofile;
	cfg.service_name = "dtrace";
	cfg.service_version = _dtrace_version;
	cfg.scope_name = "dtrace";
	cfg.profile = profile != NULL ? profile : "dtrace";
	cfg.source = src.data;
	cfg.hypertrace = g_elf;
	g_otel = dtotel_session_open(&cfg, err, sizeof(err));
	oe_buf_free(&src);
	free(profile);
	if (g_otel == NULL)
		fatal("%s\n", err);
}

/* Enable the probe clock program (before any traced program). */
static int
otel_clock(void)
{
	char err[256];

	if (dtotel_session_clock(g_otel, g_dtp, err, sizeof(err)) != 0) {
		error("%s\n", err);
		return (-1);
	}
	return (0);
}

/* End the session; called by the output worker with the handle lock. */
static void
otel_finish(int finish)
{

	if (g_otel == NULL)
		return;
	if (dtotel_session_close(g_otel, finish) != 0) {
		error("failed to export OpenTelemetry data\n");
		g_status = E_ERROR;
	}
	g_otel = NULL;
}

static void
go(void)
{
	int i;

	struct {
		char *name;
		char *optname;
		dtrace_optval_t val;
	} bufs[] = {
		{ "buffer size", "bufsize" },
		{ "aggregation size", "aggsize" },
		{ "speculation size", "specsize" },
		{ "dynamic variable size", "dynvarsize" },
		{ NULL }
	}, rates[] = {
		{ "cleaning rate", "cleanrate" },
		{ "status rate", "statusrate" },
		{ NULL }
	};

	for (i = 0; bufs[i].name != NULL; i++) {
		if (dtrace_getopt(g_dtp, bufs[i].optname, &bufs[i].val) == -1)
			fatal("couldn't get option %s", bufs[i].optname);
	}

	for (i = 0; rates[i].name != NULL; i++) {
		if (dtrace_getopt(g_dtp, rates[i].optname, &rates[i].val) == -1)
			fatal("couldn't get option %s", rates[i].optname);
	}

	if (dtrace_go(g_dtp) == -1)
		dfatal("could not enable tracing");

	for (i = 0; bufs[i].name != NULL; i++) {
		dtrace_optval_t j = 0, mul = 10;
		dtrace_optval_t nsize;

		if (bufs[i].val == DTRACEOPT_UNSET)
			continue;

		(void) dtrace_getopt(g_dtp, bufs[i].optname, &nsize);

		if (nsize == DTRACEOPT_UNSET || nsize == 0)
			continue;

		if (nsize >= bufs[i].val - sizeof (uint64_t))
			continue;

		for (; (INT64_C(1) << mul) <= nsize; j++, mul += 10)
			continue;

		if (!(nsize & ((INT64_C(1) << (mul - 10)) - 1))) {
			error("%s lowered to %lld%c\n", bufs[i].name,
			    (long long)nsize >> (mul - 10), " kmgtpe"[j]);
		} else {
			error("%s lowered to %lld bytes\n", bufs[i].name,
			    (long long)nsize);
		}
	}

	for (i = 0; rates[i].name != NULL; i++) {
		dtrace_optval_t nval;
		char *dir;

		if (rates[i].val == DTRACEOPT_UNSET)
			continue;

		(void) dtrace_getopt(g_dtp, rates[i].optname, &nval);

		if (nval == DTRACEOPT_UNSET || nval == 0)
			continue;

		if (rates[i].val == nval)
			continue;

		dir = nval > rates[i].val ? "reduced" : "increased";

		if (nval <= NANOSEC && (NANOSEC % nval) == 0) {
			error("%s %s to %lld hz\n", rates[i].name, dir,
			    (long long)NANOSEC / (long long)nval);
			continue;
		}

		if ((nval % NANOSEC) == 0) {
			error("%s %s to once every %lld seconds\n",
			    rates[i].name, dir,
			    (long long)nval / (long long)NANOSEC);
			continue;
		}

		error("%s %s to once every %lld nanoseconds\n",
		    rates[i].name, dir, (long long)nval);
	}
}

static void
print_imsgs(dtraced_infomsg_t *imsgs, size_t nimsgs)
{
	size_t i, j, k;
	dtraced_infomsg_t *imsg;
	char **processed;
	int process;

	processed = calloc(nimsgs != 0 ? nimsgs : 1, sizeof(*processed));
	if (processed == NULL)
		fatal("cannot allocate VM listing");
	oprintf("HyperTrace-aware VMs:\n\n");
	j = 0;
	for (i = 0; i < nimsgs; i++) {
		imsg = &imsgs[i];

		process = 1;
		for (k = 0; k < j; k++)
			if (strcmp(processed[k], imsg->client_name) == 0)
				process = 0;

		if (process == 0)
			continue;

		if (imsg->client_kind == DTRACED_KIND_FORWARDER)
			oprintf("%s\n", imsg->client_name);

		processed[j++] = imsg->client_name;
	}

	free(processed);
}

int
main(int argc, char *argv[])
{
	dtrace_bufdesc_t buf;
	dtrace_status_t status[2];
	dtrace_cmd_t *dcp;
	dtrace_optval_t opt;

	g_ofp = stdout;
	int done = 0, mode = 0;
	int err, i, rv, c, new_argc, libxo_specified = 0;
	int print_upon_exit = 0;
	char *p, *p2, **v;
	struct ps_prochandle *P;
	pid_t pid;
	size_t len1, len2;
	size_t idents_to_read;
	unsigned char *idents;

	p2 = NULL;

	rslv = (1 << DT_RSLV_HOSTNAME) | (1 << DT_RSLV_VERSION);
	len1 = len2 = 0;

#ifdef __FreeBSD__
	/* For %'d and the like. */
	(void) setlocale(LC_NUMERIC, "");

	/* For %T. */
	(void) setlocale(LC_TIME, "");
#endif

	g_pname = basename(argv[0]);

	if (argc == 1)
		return (usage(stderr));

	if ((g_argv = malloc(sizeof (char *) * argc)) == NULL ||
	    (g_cmdv = malloc(sizeof (dtrace_cmd_t) * argc)) == NULL ||
	    (g_psv = malloc(sizeof (struct ps_prochandle *) * argc)) == NULL)
		fatal("failed to allocate memory for arguments");

	new_argc = xo_parse_args(argc, argv);
	if (new_argc < 0)
		return (usage(stderr));

	if (new_argc != argc)
		libxo_specified = 1;

	argc = new_argc;

	g_argv[g_argc++] = argv[0];	/* propagate argv[0] to D as $0/$$0 */
	argv[0] = g_pname;		/* rewrite argv[0] for getopt errors */

	bzero(status, sizeof (status));
	bzero(&buf, sizeof (buf));

	/*
	 * Make an initial pass through argv[] processing any arguments that
	 * affect our behavior mode (g_mode) and flags used for dtrace_open().
	 * We also accumulate arguments that are not affiliated with getopt
	 * options into g_argv[], and abort if any invalid options are found.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case '3':
				if (strcmp(optarg, "2") != 0) {
					(void) fprintf(stderr,
					    "%s: illegal option -- 3%s\n",
					    argv[0], optarg);
					return (usage(stderr));
				}
				g_oflags &= ~DTRACE_O_MODEL_MASK;
				g_oflags |= DTRACE_O_ILP32;
				break;

			case '6':
				if (strcmp(optarg, "4") != 0) {
					(void) fprintf(stderr,
					    "%s: illegal option -- 6%s\n",
					    argv[0], optarg);
					return (usage(stderr));
				}
				g_oflags &= ~DTRACE_O_MODEL_MASK;
				g_oflags |= DTRACE_O_LP64;
				break;

			case 'a':
				g_grabanon++; /* also checked in pass 2 below */
				break;

			case 'A':
				g_mode = DMODE_ANON;
				g_exec = 0;
				mode++;
				break;

			case 'e':
				g_exec = 0;
				done = 1;
				break;

			case 'E':
				g_elf = 1;
				done = 1;
				break;

			case 'g':
				g_graphfile = optarg;
				break;

			case 'h':
				g_mode = DMODE_HEADER;
				g_oflags |= DTRACE_O_NODEV;
				g_cflags |= DTRACE_C_ZDEFS; /* -h implies -Z */
				g_exec = 0;
				mode++;
				break;

			case 'G':
				g_mode = DMODE_LINK;
				g_oflags |= DTRACE_O_NODEV;
				g_cflags |= DTRACE_C_ZDEFS; /* -G implies -Z */
				g_exec = 0;
				mode++;
				break;

			case 'y':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = process_elf;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				g_elf = 1;
				g_guest = 1;
				break;

			case 'Y':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = process_elf_hypertrace;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				g_elf = 1;
				g_guest = 1;
				g_failmsg_needed = 1;
				break;

			case 'M':
				g_mode = DMODE_LISTVMS;
				mode++;
				break;

			case 'l':
				g_mode = DMODE_LIST;
				g_cflags |= DTRACE_C_ZDEFS; /* -l implies -Z */
				mode++;
				break;

			case 'V':
				g_mode = DMODE_VERS;
				mode++;
				break;

			default:
				if (strchr(DTRACE_OPTSTR, c) == NULL)
					return (usage(stderr));
			}
		}

		if (optind < argc)
			g_argv[g_argc++] = argv[optind];
	}

	if (mode > 1) {
		(void) fprintf(stderr, "%s: only one of the [-AGhlV] options "
		    "can be specified at a time\n", g_pname);
		return (E_USAGE);
	}
	if (g_mode == DMODE_VERS)
		return (printf("%s: %s\n", g_pname, _dtrace_version) <= 0);

	if (g_mode == DMODE_LISTVMS) {
		int fd;
		dtraced_infomsg_t *imsgs;
		size_t count, transferred, item;
		int64_t deadline;
		dtraced_hdr_t hdr = { 0 };

		fd = open_dtraced(DTD_SUB_INFO);
		if (fd < 0)
			fatal("cannot connect to dtraced");
		deadline = dtraced_io_deadline_after(10000);
		if (deadline < 0) {
			int error = errno;

			close(fd);
			fatal("cannot set dtraced information deadline: %s\n",
			    strerror(error));
		}
		unsigned char header_wire[DTRACED_MSGHDRSIZE];
		if (dtraced_io_transfer(fd, header_wire, sizeof(header_wire), false,
		    deadline, &transferred) != 0) {
			close(fd);
			fatal("cannot receive dtraced information header");
		}
		if (dtraced_wire_decode_header(&hdr, header_wire) != 0) {
			close(fd);
			fatal("invalid dtraced information header");
		}
		if (hdr.msg_type != DTRACED_MSG_INFO ||
		    hdr.info.count > (64U * 1024 * 1024) / sizeof(*imsgs)) {
			close(fd);
			fatal("invalid dtraced information header\n");
		}
		count = hdr.info.count;
		imsgs = calloc(count != 0 ? count : 1, sizeof(*imsgs));
		if (imsgs == NULL) {
			close(fd);
			fatal("cannot allocate dtraced information");
		}
		for (item = 0; item < count; item++) {
			unsigned char info_wire[DTRACED_INFO_WIRE_SIZE];
			if (dtraced_io_transfer(fd, info_wire,
			    sizeof(info_wire), false, deadline, &transferred) != 0) {
				close(fd);
				free(imsgs);
				fatal("cannot receive dtraced information");
			}
			if (dtraced_wire_decode_info(&imsgs[item],
			    info_wire) != 0) {
				close(fd);
				free(imsgs);
				fatal("invalid dtraced information entry");
			}
		}
		close(fd);
		for (item = 0; item < count; item++) {
			if (memchr(imsgs[item].client_name, '\0',
			    sizeof(imsgs[item].client_name)) == NULL) {
				free(imsgs);
				fatal("unterminated dtraced client name\n");
			}
		}
		print_imsgs(imsgs, count);
		free(imsgs);
		exit(EXIT_SUCCESS);
	}

	/*
	 * If we're in linker mode and the data model hasn't been specified,
	 * we try to guess the appropriate setting by examining the object
	 * files. We ignore certain errors since we'll catch them later when
	 * we actually process the object files.
	 */
	if (g_mode == DMODE_LINK && (g_oflags & DTRACE_O_MODEL_MASK) == 0 &&
	    elf_version(EV_CURRENT) != EV_NONE) {
		int fd;
		Elf *elf;
		GElf_Ehdr ehdr;

		for (i = 1; i < g_argc; i++) {
			if ((fd = open64(g_argv[i], O_RDONLY)) == -1)
				break;

			if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
				(void) close(fd);
				break;
			}

			if (elf_kind(elf) != ELF_K_ELF ||
			    gelf_getehdr(elf, &ehdr) == NULL) {
				(void) close(fd);
				(void) elf_end(elf);
				break;
			}

			(void) close(fd);
			(void) elf_end(elf);

			if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
				if (g_oflags & DTRACE_O_ILP32) {
					fatal("can't mix 32-bit and 64-bit "
					    "object files\n");
				}
				g_oflags |= DTRACE_O_LP64;
			} else if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
				if (g_oflags & DTRACE_O_LP64) {
					fatal("can't mix 32-bit and 64-bit "
					    "object files\n");
				}
				g_oflags |= DTRACE_O_ILP32;
			} else {
				break;
			}
		}
	}

	/*
	 * Open libdtrace.  If we are not actually going to be enabling any
	 * instrumentation attempt to reopen libdtrace using DTRACE_O_NODEV.
	 */
	/* pthread functions return the error; fatal() reports errno. */
	{
		if ((errno = pthread_cond_init(&g_dtpcv, NULL)) != 0 ||
		    (errno = pthread_mutex_init(&g_dtpmtx, NULL)) != 0)
			fatal("failed to create the dtp lock");
		g_dtpmtx_ready = 1;
	}

	if ((errno = pthread_mutex_init(&g_pgplistmtx, NULL)) != 0)
		fatal("failed to init pgplistmtx");

	if ((errno = pthread_cond_init(&g_pgpcond, NULL)) != 0)
		fatal("failed to init pgpcond");

	if ((errno = pthread_mutex_init(&g_benchlistmtx, NULL)) != 0)
		fatal("failed to init benchlistmtx");

	while ((g_dtp = dtrace_open(DTRACE_VERSION, g_oflags, &err)) == NULL) {
		if (!(g_oflags & DTRACE_O_NODEV) && !g_exec && !g_grabanon) {
			g_oflags |= DTRACE_O_NODEV;
			continue;
		}

		fatal("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(NULL, err));
	}

	if (g_guest)
		dtrace_set_guest(g_dtp);

	if (g_elf)
		dtrace_enable_hypertrace(g_dtp);

	if (g_failmsg_needed)
		dtrace_set_failmsg_needed(g_dtp);


#if defined(__i386__)
	/* XXX The 32-bit seems to need more buffer space by default -sson */
	(void) dtrace_setopt(g_dtp, "bufsize", "12m");
	(void) dtrace_setopt(g_dtp, "aggsize", "12m");
#else
	(void) dtrace_setopt(g_dtp, "bufsize", "4m");
	(void) dtrace_setopt(g_dtp, "aggsize", "4m");
#endif
	(void) dtrace_setopt(g_dtp, "temporal", "yes");
	(void) dtrace_setopt(g_dtp, "strsize", "256");

	/*
	 * If -G is specified, enable -xlink=dynamic and -xunodefs to permit
	 * references to undefined symbols to remain as unresolved relocations.
	 * If -A is specified, enable -xlink=primary to permit static linking
	 * only to kernel symbols that are defined in a primary kernel module.
	 */
	if (g_mode == DMODE_LINK) {
		(void) dtrace_setopt(g_dtp, "linkmode", "dynamic");
		(void) dtrace_setopt(g_dtp, "unodefs", NULL);

		/*
		 * Use the remaining arguments as the list of object files
		 * when in linker mode.
		 */
		g_objc = g_argc - 1;
		g_objv = g_argv + 1;

		/*
		 * We still use g_argv[0], the name of the executable.
		 */
		g_argc = 1;
	} else if (g_mode == DMODE_ANON)
		(void) dtrace_setopt(g_dtp, "linkmode", "primary");


	if (libxo_specified)
		dtrace_oformat_configure(g_dtp);

	/*
	 * Now that we have libdtrace open, make a second pass through argv[]
	 * to perform any dtrace_setopt() calls and change any compiler flags.
	 * We also accumulate any program specifications into our g_cmdv[] at
	 * this time; these will compiled as part of the fourth processing pass.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case 'a':
				if (dtrace_setopt(g_dtp, "grabanon", 0) != 0)
					dfatal("failed to set -a");
				break;

			case 'b':
				if (dtrace_setopt(g_dtp,
				    "bufsize", optarg) != 0)
					dfatal("failed to set -b %s", optarg);
				break;

			case 'B':
				g_ofp = NULL;
				break;

			case 'C':
				g_cflags |= DTRACE_C_CPP;
				break;

			case 'd':
				g_cflags |= DTRACE_C_SUGAR;
				break;

			case 'D':
				if (dtrace_setopt(g_dtp, "define", optarg) != 0)
					dfatal("failed to set -D %s", optarg);
				break;

			case '1':
				if (strlen(optarg) >= MAXPATHLEN)
					fatal("strlen(%s) (%zu) > %zu\n", optarg,
					    strlen(optarg), (size_t)MAXPATHLEN - 1);
				strcpy(g_bench_path, optarg);
				break;

			case 'f':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_FUNC;
				dcp->dc_arg = optarg;
				break;

			case 'F':
				if (dtrace_setopt(g_dtp, "flowindent", 0) != 0)
					dfatal("failed to set -F");
				break;

			case 'H':
				if (dtrace_setopt(g_dtp, "cpphdrs", 0) != 0)
					dfatal("failed to set -H");
				break;

			case 'i':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_NAME;
				dcp->dc_arg = optarg;
				break;

			case 'I':
				if (dtrace_setopt(g_dtp, "incdir", optarg) != 0)
					dfatal("failed to set -I %s", optarg);
				break;

			case 'L':
				if (dtrace_setopt(g_dtp, "libdir", optarg) != 0)
					dfatal("failed to set -L %s", optarg);
				break;

			case 'm':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_MOD;
				dcp->dc_arg = optarg;
				break;

			case 'n':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_NAME;
				dcp->dc_arg = optarg;
				g_script = strdup(optarg);
				break;

			case 'N': {
				int64_t handshake_deadline;

				handshake_deadline = dtraced_io_deadline_after(10000);
				if (handshake_deadline < 0)
					fatal("failed to set identifier deadline: %s\n",
					    strerror(errno));
				if (dtrace_read_identifiers(STDIN_FILENO, &idents,
				    &idents_to_read, DT_PROG_IDENTLEN,
				    handshake_deadline) != 0)
					fatal("failed to read complete identifier handshake");

				if (dtrace_compile_idents_set(g_dtp, idents,
				    idents_to_read) != 0) {
					fatal("failed to compile identifiers");
				}

				free(idents);
				g_has_idents = 1;
				break;
			}

			case 'P':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_PROVIDER;
				dcp->dc_arg = optarg;
				break;

			case 'O':
				print_upon_exit = 1;
				break;

			case 'q':
				if (dtrace_setopt(g_dtp, "quiet", 0) != 0)
					dfatal("failed to set -q");
				break;

			case 'r':
				g_allow_root_srcident = 1;
				break;

			case 'o':
				g_ofile = optarg;
				break;

			case 's':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_file;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				break;

			case 'S':
				g_cflags |= DTRACE_C_DIFV;
				break;

			case 'U':
				if (dtrace_setopt(g_dtp, "undef", optarg) != 0)
					dfatal("failed to set -U %s", optarg);
				break;

			case 'u':
				g_unsafe = 1;
				break;

			case 'v':
				g_verbose++;
				break;

			case 'w':
				if (dtrace_setopt(g_dtp, "destructive", 0) != 0)
					dfatal("failed to set -w");
				break;

			case 'x':
				if ((p = strchr(optarg, '=')) != NULL)
					*p++ = '\0';
				{
					/* dtrace(1) options, not libdtrace's. */
					char oerr[256];
					int handled;

					handled = dtotel_option(&g_otel_opts,
					    optarg, p, oerr, sizeof(oerr));
					if (handled < 0)
						fatal("%s\n", oerr);
					if (handled > 0)
						break;
				}
				if (strcmp(optarg, "checkmodref") == 0) {
					/* A dtrace(1) check, not a libdtrace option. */
					if (p != NULL)
						fatal("-x checkmodref takes no value\n");
					g_checkmodref = 1;
					break;
				}
				if (strcmp(optarg, "hypertrace_session_file") == 0) {
					if (p == NULL || p[0] != '/' || p[1] == '\0')
						fatal("-x hypertrace_session_file needs an "
						    "absolute path\n");
					g_hypertrace_session_file = p;
					break;
				}

				len1 = strlen(optarg);
				len2 = strlen("resolvers");

				/*
				 * If the option is of form
				 * "resolvers=hostname,version"
				 * we get the two arguments, set the global
				 * variable to have the appropriate flags and
				 * break out of the switch statement.
				 */
				if (len1 == len2 &&
				    strncmp(optarg, "resolvers", len1) == 0) {
					if (p == NULL)
						fatal("-x resolvers requires a value\n");
					if ((p2 = strchr(p, ',')) != NULL)
						*p2++ = '\0';

					if (strcmp(p, "hostname") != 0      &&
					    ((p2 && strcmp(p2, "hostname")) ||
					    p2 == NULL))
						rslv &= ~(1 << DT_RSLV_HOSTNAME);

					if (strcmp(p, "version") != 0      &&
					    ((p2 && strcmp(p2, "version")) ||
					    p2 == NULL))
						rslv &= ~(1 << DT_RSLV_VERSION);

					break;
				}

				if (dtrace_setopt(g_dtp, optarg, p) != 0)
					dfatal("failed to set -x %s", optarg);
				break;

			case 'X':
				if (dtrace_setopt(g_dtp, "stdc", optarg) != 0)
					dfatal("failed to set -X %s", optarg);
				break;

			case 'Z':
				g_cflags |= DTRACE_C_ZDEFS;
				break;

			default:
				if (strchr(DTRACE_OPTSTR, c) == NULL)
					return (usage(stderr));
			}
		}
	}

	dtrace_resolver_setflags(rslv);

	/* The session file is known only after the second pass. */
	if (g_hypertrace_session_file != NULL &&
	    (g_mode != DMODE_EXEC || !g_elf || g_guest))
		fatal("-x hypertrace_session_file requires a host HyperTrace "
		    "consumer (-E)\n");
	if (g_checkmodref && g_mode != DMODE_EXEC)
		fatal("-x checkmodref is valid only when programs are compiled "
		    "for execution\n");
	{
		char oerr[256];

		if (dtotel_options_check(&g_otel_opts, g_ofile, oerr,
		    sizeof(oerr)) != 0)
			fatal("%s\n", oerr);
	}
	if (g_otel_opts.format != DTOTEL_OFF) {
		if (g_mode != DMODE_EXEC || !g_exec || g_guest)
			fatal("-x otel applies to tracing (not -A, -e, -G, "
			    "-h, -l, -y or -Y)\n");
		if (g_ofp == NULL)
			fatal("-x otel is not valid with -B\n");
	}

	if (g_ofp == NULL && g_mode != DMODE_EXEC) {
		(void) fprintf(stderr, "%s: -B not valid in combination"
		    " with [-AGl] options\n", g_pname);
		return (E_USAGE);
	}

	if (g_ofp == NULL && g_ofile != NULL) {
		(void) fprintf(stderr, "%s: -B not valid in combination"
		    " with -o option\n", g_pname);
		return (E_USAGE);
	}

	/*
	 * In our third pass we handle any command-line options related to
	 * grabbing or creating victim processes.  The behavior of these calls
	 * may been affected by any library options set by the second pass.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case 'c':
				if ((v = make_argv(optarg)) == NULL)
					fatal("failed to allocate memory");

				P = dtrace_proc_create(g_dtp, v[0], v, NULL, NULL);
				if (P == NULL)
					dfatal(NULL); /* dtrace_errmsg() only */

				g_psv[g_psc++] = P;
				free(v);
				break;

			case 'p':
				errno = 0;
				pid = strtol(optarg, &p, 10);

				if (errno != 0 || p == optarg || p[0] != '\0')
					fatal("invalid pid: %s\n", optarg);

				P = dtrace_proc_grab(g_dtp, pid, 0);
				if (P == NULL)
					dfatal(NULL); /* dtrace_errmsg() only */

				g_psv[g_psc++] = P;
				break;
			}
		}
	}

	/*
	 * In our fourth pass we finish g_cmdv[] by calling dc_func to convert
	 * each string or file specification into a compiled program structure.
	 */
	for (i = 0; i < g_cmdc; i++)
		g_cmdv[i].dc_func(&g_cmdv[i]);

	if (g_mode != DMODE_LIST) {
		if (dtrace_handle_err(g_dtp, &errhandler, NULL) == -1)
			dfatal("failed to establish error handler");

		if (dtrace_handle_drop(g_dtp, &drophandler, NULL) == -1)
			dfatal("failed to establish drop handler");

		if (dtrace_handle_proc(g_dtp, &prochandler, NULL) == -1)
			dfatal("failed to establish proc handler");

		if (dtrace_handle_setopt(g_dtp, &setopthandler, NULL) == -1)
			dfatal("failed to establish setopt handler");

		if (g_ofp == NULL &&
		    dtrace_handle_buffered(g_dtp, &bufhandler, NULL) == -1)
			dfatal("failed to establish buffered handler");
	}

	(void) dtrace_getopt(g_dtp, "flowindent", &opt);
	g_flowindent = opt != DTRACEOPT_UNSET;

	(void) dtrace_getopt(g_dtp, "grabanon", &opt);
	g_grabanon = opt != DTRACEOPT_UNSET;

	(void) dtrace_getopt(g_dtp, "quiet", &opt);
	g_quiet = opt != DTRACEOPT_UNSET;

	if (dtrace_oformat(g_dtp)) {
		if (g_otel_opts.format != DTOTEL_OFF)
			fatal("-x otel is not valid with --libxo\n");
		if (dtrace_setopt(g_dtp, "quiet", 0) != 0)
			dfatal("failed to set quiet (caused by oformat)");
	}

	/*
	 * Now make a fifth and final pass over the options that have been
	 * turned into programs and saved in g_cmdv[], performing any mode-
	 * specific processing.  If g_mode is DMODE_EXEC, we will break out
	 * of the switch() and continue on to the data processing loop.  For
	 * other modes, we will exit dtrace once mode-specific work is done.
	 */
	switch (g_mode) {
	case DMODE_EXEC:
		if (g_otel_opts.format != DTOTEL_OFF) {
			/*
			 * The session owns -o; a host HyperTrace consumer
			 * enables the clock when its first program comes
			 * back from dtraced (process_new_pgp()).
			 */
			otel_open();
			if (!g_elf && otel_clock() != 0)
				fatal("failed to start OpenTelemetry output\n");
		} else if (g_ofile != NULL &&
		    (g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);

		if (dtrace_oformat(g_dtp))
			dtrace_set_outfp(g_ofp);

		if (g_elf && !g_guest && g_cmdc > 0) {
			dtrace_cmd_t combined;

			hypertrace_combine(&combined);
			exec_prog(&combined);
		} else for (i = 0; i < g_cmdc; i++) {
			/* -y already ran its ELF in process_elf(); under -e it
			 * only linked, and exec_prog() writes the ELF. */
			if (g_cmdv[i].dc_func == process_elf && g_exec)
				continue;
			exec_prog(&g_cmdv[i]);
		}

		if (g_elfrun) {
			dtp_lock();
			if (g_dtp)
				dtrace_close(g_dtp);
			g_dtp = NULL;
			return (g_status);
		}

		if (done && !g_grabanon) {
			/*
			 * Join the worker thread if we started it.
			 */
			if (g_worktd)
				(void)pthread_join(g_worktd, NULL);
			/* Without a worker the session was never ended. */
			dtp_lock();
			otel_finish(0);
			dtp_unlock();

			/* Return holding the handle lock (see dtp_lock()). */
			dtp_lock();
			if (g_dtp)
				dtrace_close(g_dtp);
			g_dtp = NULL;

			return (g_status);
		}
		break;

	case DMODE_ANON:
		if (g_ofile == NULL)
#ifdef illumos
			g_ofile = "/kernel/drv/dtrace.conf";
#else
			/*
			 * On FreeBSD, anonymous DOF data is written to
			 * the DTrace DOF file.
			 */
			g_ofile = "/boot/dtrace.dof";
#endif

		dof_prune(g_ofile); /* strip out any old DOF directives */
#ifdef illumos
		etcsystem_prune(); /* string out any forceload directives */
#endif

		if (g_cmdc == 0) {
			dtrace_close(g_dtp);
			g_dtp = NULL;

			return (g_status);
		}

		if ((g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);

		if (dtrace_oformat(g_dtp))
			dtrace_set_outfp(g_ofp);

		for (i = 0; i < g_cmdc; i++) {
			anon_prog(&g_cmdv[i],
			    dtrace_dof_create(g_dtp, g_cmdv[i].dc_prog, 0), i);
		}

		/*
		 * Dump out the DOF corresponding to the error handler and the
		 * current options as the final DOF property in the .conf file.
		 */
		anon_prog(NULL, dtrace_geterr_dof(g_dtp), i++);
		anon_prog(NULL, dtrace_getopt_dof(g_dtp), i++);

		if (fclose(g_ofp) == EOF)
			fatal("failed to close output file '%s'", g_ofile);

		/*
		 * These messages would use notice() rather than error(), but
		 * we don't want them suppressed when -A is run on a D program
		 * that itself contains a #pragma D option quiet.
		 */
		error("saved anonymous enabling in %s\n", g_ofile);

#ifdef __FreeBSD__
		bootdof_add();
#else
		etcsystem_add();
		error("run update_drv(1M) or reboot to enable changes\n");
#endif

		dtrace_close(g_dtp);

		return (g_status);

	case DMODE_LINK:
		if (g_cmdc == 0) {
			(void) fprintf(stderr, "%s: -G requires one or more "
			    "scripts or enabling options\n", g_pname);
			dtrace_close(g_dtp);

			return (E_USAGE);
		}

		for (i = 0; i < g_cmdc; i++)
			link_prog(&g_cmdv[i]);

		if (g_cmdc > 1 && g_ofile != NULL) {
			char **objv = alloca(g_cmdc * sizeof (char *));

			for (i = 0; i < g_cmdc; i++)
				objv[i] = g_cmdv[i].dc_ofile;

			if (dtrace_program_link(g_dtp, NULL, DTRACE_D_PROBES,
			    g_ofile, g_cmdc, objv) != 0)
				dfatal(NULL); /* dtrace_errmsg() only */
		}

		dtrace_close(g_dtp);
		return (g_status);

	case DMODE_LIST:
		if (g_ofile != NULL && (g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);

		/* The signal thread exists from here on. */
		dtp_lock();
		installsighands();

		oprintf("%5s %10s %17s %33s %s\n",
		    "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");

		for (i = 0; i < g_cmdc; i++)
			list_prog(&g_cmdv[i]);

		if (g_cmdc == 0)
			(void) dtrace_probe_iter(g_dtp, NULL, list_probe, NULL);

		dtrace_close(g_dtp);

		return (g_status);

	case DMODE_HEADER:
		if (g_cmdc == 0) {
			(void) fprintf(stderr, "%s: -h requires one or more "
			    "scripts or enabling options\n", g_pname);
			dtrace_close(g_dtp);

			return (E_USAGE);
		}

		if (g_ofile == NULL) {
			char *p;

			if (g_cmdc > 1) {
				(void) fprintf(stderr, "%s: -h requires an "
				    "output file if multiple scripts are "
				    "specified\n", g_pname);
				dtrace_close(g_dtp);

				return (E_USAGE);
			}

			if ((p = strrchr(g_cmdv[0].dc_arg, '.')) == NULL ||
			    strcmp(p, ".d") != 0) {
				(void) fprintf(stderr, "%s: -h requires an "
				    "output file if no scripts are "
				    "specified\n", g_pname);

				dtrace_close(g_dtp);
				return (E_USAGE);
			}

			p[0] = '\0'; /* strip .d suffix */
			g_ofile = p = g_cmdv[0].dc_ofile;
			(void) snprintf(p, sizeof (g_cmdv[0].dc_ofile),
			    "%s.h", basename(g_cmdv[0].dc_arg));
		}

		if ((g_ofp = fopen(g_ofile, "w")) == NULL)
			fatal("failed to open header file '%s'", g_ofile);

		oprintf("/*\n * Generated by dtrace(1M).\n */\n\n");

		if (dtrace_program_header(g_dtp, g_ofp, g_ofile) != 0 ||
		    fclose(g_ofp) == EOF)
			dfatal("failed to create header file %s", g_ofile);

		dtrace_close(g_dtp);
		return (g_status);
	}

	/*
	 * If -a and -Z were not specified and no probes have been matched, no
	 * probe criteria was specified on the command line and we abort.
	 */
	if (g_total == 0 && !g_grabanon && !(g_cflags & DTRACE_C_ZDEFS))
		dfatal("no probes %s\n", g_cmdc ? "matched" : "specified");

	/* Every local program is enabled (or -a grabs anonymous state):
	 * start tracing.  HyperTrace modes start their own and never get here
	 * with a program. */
	if (!g_elf)
		setup_tracing();

	dtrace_workarg_t workarg = { print_upon_exit };
	(void) dtc_work(&workarg);
	/* Return holding the handle lock (see dtp_lock()). */
	dtp_lock();
	if (g_dtp)
		dtrace_close(g_dtp);
	g_dtp = NULL;
	return (g_status);
}

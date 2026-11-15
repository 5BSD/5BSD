/*
 * oeslogger -j / -J / -i: the installed logger restricted to one jail.
 *
 * Each case runs /usr/sbin/oeslogger writing compact JSON Lines to a file,
 * drives processes in and out of jails, and looks for their pids in the
 * file.  A process that must be absent is always run before one that must
 * be present, and the file is read once the latter has appeared.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <stdarg.h>
#include <sysexits.h>

#include "test_jail_common.h"

#define LOGGER		"/usr/sbin/oeslogger"
#define WAIT_MS		10000

static char n_a[64], n_b[80], n_c[96], n_s[64];
static int j_a = -1, j_b = -1, j_c = -1, j_s = -1;

struct logger {
	pid_t	pid;
	int	errfd;
	char	out[40];
	char	err[4096];
	size_t	errlen;
};

static void
logger_collect(struct logger *lg, int timeout_ms)
{
	struct pollfd pfd;
	ssize_t n;

	pfd.fd = lg->errfd;
	pfd.events = POLLIN;
	if (lg->errfd < 0 || poll(&pfd, 1, timeout_ms) <= 0)
		return;
	if (lg->errlen >= sizeof(lg->err) - 1)
		return;
	n = read(lg->errfd, lg->err + lg->errlen,
	    sizeof(lg->err) - 1 - lg->errlen);
	if (n > 0) {
		lg->errlen += (size_t)n;
		lg->err[lg->errlen] = '\0';
	}
}

/*
 * Start the logger with the given arguments (NULL-terminated) followed by
 * the output file.  With wait_listening, 0 only once it is listening.
 */
static int
logger_start(struct logger *lg, int wait_listening, ...)
{
	struct timespec start;
	char *argv[16];
	va_list ap;
	int argc, fd, fds[2];

	memset(lg, 0, sizeof(*lg));
	strlcpy(lg->out, "/tmp/oeslj-out.XXXXXX", sizeof(lg->out));
	fd = mkstemp(lg->out);
	if (fd < 0 || pipe(fds) != 0)
		return (-1);
	close(fd);
	argc = 0;
	argv[argc++] = __DECONST(char *, "oeslogger");
	argv[argc++] = __DECONST(char *, "-o");
	argv[argc++] = lg->out;
	va_start(ap, wait_listening);
	while (argc < 15 && (argv[argc] = va_arg(ap, char *)) != NULL)
		argc++;
	va_end(ap);
	argv[argc] = NULL;
	fflush(NULL);
	lg->pid = fork();
	if (lg->pid < 0)
		return (-1);
	if (lg->pid == 0) {
		close(fds[0]);
		dup2(fds[1], STDERR_FILENO);
		close(fds[1]);
		execv(LOGGER, argv);
		_exit(127);
	}
	close(fds[1]);
	lg->errfd = fds[0];
	if (!wait_listening)
		return (0);
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (jt_elapsed_ms(&start) < WAIT_MS) {
		logger_collect(lg, 100);
		if (strstr(lg->err, "listening for events") != NULL)
			return (0);
	}
	printf("    logger did not start listening: %s\n", lg->err);
	return (-1);
}

/*
 * Wait up to limit_ms for the logger to exit, sending SIGTERM first if
 * asked.  The exit status, or -1 when it had to be killed.
 */
static int
logger_stop_ms(struct logger *lg, bool term, long limit_ms)
{
	struct timespec start;
	int status;

	status = -1;
	if (term)
		(void)kill(lg->pid, SIGTERM);
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		logger_collect(lg, 50);
		if (waitpid(lg->pid, &status, WNOHANG) == lg->pid)
			break;
		if (jt_elapsed_ms(&start) >= limit_ms) {
			(void)kill(lg->pid, SIGKILL);
			(void)waitpid(lg->pid, &status, 0);
			status = -1;
			break;
		}
	}
	logger_collect(lg, 100);
	close(lg->errfd);
	lg->errfd = -1;
	if (status == -1)
		return (-1);
	return (WIFEXITED(status) ? WEXITSTATUS(status) :
	    256 + WTERMSIG(status));
}

static int
logger_stop(struct logger *lg, bool term)
{

	return (logger_stop_ms(lg, term, WAIT_MS));
}

static void
logger_done(struct logger *lg)
{

	unlink(lg->out);
}

/*
 * Is there a line in the logger's output with every one of the given
 * substrings (NULL-terminated list)?
 */
static bool
log_has(struct logger *lg, ...)
{
	const char *want[8];
	char *line;
	size_t cap;
	va_list ap;
	FILE *fp;
	bool found;
	int i, n;

	n = 0;
	va_start(ap, lg);
	while (n < 8 && (want[n] = va_arg(ap, const char *)) != NULL)
		n++;
	va_end(ap);
	fp = fopen(lg->out, "r");
	if (fp == NULL)
		return (false);
	line = NULL;
	cap = 0;
	found = false;
	while (!found && getline(&line, &cap, fp) > 0) {
		for (i = 0; i < n; i++) {
			if (strstr(line, want[i]) == NULL)
				break;
		}
		found = (i == n);
	}
	free(line);
	fclose(fp);
	return (found);
}

static const char *
pidkey(char *buf, size_t len, pid_t pid)
{

	/* The process object's pid; "ppid" and friends do not match. */
	snprintf(buf, len, "\"pid\":%d,", (int)pid);
	return (buf);
}

/* Wait for the exit record of a process to reach the file. */
static bool
log_wait_exit(struct logger *lg, pid_t pid)
{
	struct timespec start;
	char key[32];

	pidkey(key, sizeof(key), pid);
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (jt_elapsed_ms(&start) < WAIT_MS) {
		if (log_has(lg, "\"event_type\":\"NOTIFY_EXIT\"", key, NULL))
			return (true);
		usleep(50000);
	}
	return (false);
}

static bool
log_has_pid(struct logger *lg, pid_t pid)
{
	char key[32];

	return (log_has(lg, pidkey(key, sizeof(key), pid), NULL));
}

static void
case_scope(const char *what, const char *opt, const char *jail)
{
	struct logger lg;
	pid_t host, sibling, nested, inside;
	int rc;

	TEST_BEGIN(what);
	if (logger_start(&lg, true, opt, jail, "exec", "exit", NULL) != 0) {
		TEST_FAIL("%s: logger did not start", what);
		return;
	}
	host = jt_run_true(-1);
	sibling = jt_run_true(j_s);
	nested = jt_run_true(j_b);
	inside = jt_run_true(j_a);
	ASSERT_MSG(log_wait_exit(&lg, inside), "%s: jail's process not logged",
	    what);
	rc = logger_stop(&lg, true);
	ASSERT_MSG(rc == 0, "%s: logger exit status %d: %s", what, rc, lg.err);
	ASSERT_MSG(!log_has_pid(&lg, host), "%s: host process logged", what);
	ASSERT_MSG(!log_has_pid(&lg, sibling), "%s: sibling jail logged", what);
	if (strcmp(opt, "-J") == 0)
		ASSERT_MSG(!log_has_pid(&lg, nested),
		    "%s: nested jail logged", what);
	else
		ASSERT_MSG(log_has_pid(&lg, nested),
		    "%s: nested jail not logged", what);
	ASSERT_MSG(strstr(lg.err, "oeslogger: jail ") != NULL,
	    "%s: no scope line on standard error: %s", what, lg.err);
	logger_done(&lg);
}

static void
case_nested_names(void)
{
	char jid[32], key[32], full[128];
	struct logger lg;
	pid_t pb, pc;
	/* The exec target is filled with the process locked; see the pins. */
	static const char exec[] = "\"event_type\":\"NOTIFY_EXEC\"";

	TEST_BEGIN("L3 nested jails are told apart by jid and jail_fullname");
	if (logger_start(&lg, true, "-j", n_a, "exec", "exit", NULL) != 0) {
		TEST_FAIL("logger did not start");
		return;
	}
	pb = jt_run_true(j_b);
	pc = jt_run_true(j_c);
	ASSERT_MSG(log_wait_exit(&lg, pc), "deepest process not logged");
	ASSERT_MSG(logger_stop(&lg, true) == 0, "logger exit status");
	snprintf(jid, sizeof(jid), "\"jid\":%d,", j_b);
	snprintf(full, sizeof(full), "\"jail_fullname\":\"%s\"", n_b);
	ASSERT_MSG(log_has(&lg, exec, pidkey(key, sizeof(key), pb), jid, full, NULL),
	    "no record with %s %s for the process in A.b", jid, full);
	snprintf(jid, sizeof(jid), "\"jid\":%d,", j_c);
	snprintf(full, sizeof(full), "\"jail_fullname\":\"%s\"", n_c);
	ASSERT_MSG(log_has(&lg, exec, pidkey(key, sizeof(key), pc), jid, full, NULL),
	    "no record with %s %s for the process in A.b.c", jid, full);
	logger_done(&lg);
}

static void
case_later_entrant(void)
{
	char jidstr[16], key[32];
	struct logger lg;
	pid_t pid;

	TEST_BEGIN("L5 a process that enters the jail later is logged");
	snprintf(jidstr, sizeof(jidstr), "%d", j_a);
	if (logger_start(&lg, true, "-j", jidstr, "exec", "exit", NULL) != 0) {
		TEST_FAIL("logger did not start");
		return;
	}
	pid = jt_run_true(j_a);		/* Forks on the host, then attaches. */
	ASSERT_MSG(log_wait_exit(&lg, pid), "entrant's exit not logged");
	ASSERT_MSG(logger_stop(&lg, true) == 0, "logger exit status");
	ASSERT_MSG(log_has(&lg, "\"event_type\":\"NOTIFY_EXEC\"",
	    pidkey(key, sizeof(key), pid), NULL), "entrant's exec not logged");
	logger_done(&lg);
}

static void
case_refused(const char *what, int want, const char *msg, const char *a1,
    const char *a2, const char *a3)
{
	struct logger lg;
	int rc;

	if (logger_start(&lg, false, a1, a2, a3, NULL) != 0) {
		TEST_FAIL("%s: cannot run the logger", what);
		return;
	}
	rc = logger_stop(&lg, false);
	ASSERT_MSG(rc == want, "%s: exit status %d, want %d: %s", what, rc,
	    want, lg.err);
	ASSERT_MSG(strstr(lg.err, msg) != NULL, "%s: standard error: %s", what,
	    lg.err);
	logger_done(&lg);
}

static void
case_removed(void)
{
	char name[64];
	struct logger lg;
	pid_t pid;
	int jid, rc;

	TEST_BEGIN("L7 the jail is removed while the logger runs");
	jt_name(name, sizeof(name), "oeslj", "r");
	jid = jt_make_jail(name, "oeslj-r", NULL, "1");
	if (jid == -1 ||
	    logger_start(&lg, true, "-j", name, "exit", NULL) != 0) {
		TEST_FAIL("setup");
		return;
	}
	pid = jt_run_true(jid);
	if (jail_remove(jid) != 0)
		TEST_FAIL("jail_remove: %s", strerror(errno));
	jt_forget_jail(jid);
	rc = logger_stop(&lg, false);	/* Must stop by itself. */
	ASSERT_MSG(rc == 0, "exit status %d: %s", rc, lg.err);
	ASSERT_MSG(strstr(lg.err, "was removed; stopping") != NULL,
	    "standard error: %s", lg.err);
	ASSERT_MSG(log_has(&lg, "\"event_type\":\"NOTIFY_EXIT\"",
	    pidkey(name, sizeof(name), pid), NULL),
	    "exit before the removal is not in the log");
	logger_done(&lg);
}

/*
 * The same while other processes keep the kernel's deferred delivery queue
 * full: the logger must still be told that its jail is gone and stop.
 */
static void
case_removed_under_load(void)
{
	struct timespec start;
	struct jt_load load;
	struct logger lg;
	char name[64];
	long exited, released;
	pid_t pid;
	int jid, rc, statfd;

	TEST_BEGIN("L7b the jail is removed while the system is busy");
	jt_name(name, sizeof(name), "oeslj", "rl");
	jid = jt_make_jail(name, "oeslj-rl", NULL, "1");
	statfd = test_open_oes();
	if (jid == -1 || statfd < 0 ||
	    logger_start(&lg, true, "-j", name, "exit", NULL) != 0) {
		TEST_FAIL("setup");
		return;
	}
	/* Before the load: a full queue may discard what is generated. */
	pid = jt_run_true(jid);
	if (jt_load_start(&load, statfd) != 0) {
		TEST_FAIL("cannot keep the deferred queue full");
		(void)logger_stop(&lg, true);
		logger_done(&lg);
		close(statfd);
		return;
	}
	if (jail_remove(jid) != 0)
		TEST_FAIL("jail_remove: %s", strerror(errno));
	jt_forget_jail(jid);
	clock_gettime(CLOCK_MONOTONIC, &start);
	/*
	 * The kernel has ended the scope when the removed jail is no longer
	 * held; the logger then has to notice, write its log and close.
	 * Tell the two apart, and show where a slow logger is.
	 */
	released = -1;
	while (jt_elapsed_ms(&start) < load.limit_ms) {
		if (released == -1 && !jt_jail_exists_dying(name))
			released = jt_elapsed_ms(&start);
		if (waitpid(lg.pid, NULL, WNOHANG | WNOWAIT) == lg.pid)
			break;
		logger_collect(&lg, 50);
	}
	exited = jt_elapsed_ms(&start);
	if (released == -1 && !jt_jail_exists_dying(name))
		released = exited;
	rc = logger_stop_ms(&lg, false, 1);		/* By itself. */
	printf("    jail released %ld ms and logger %s %ld ms after the "
	    "removal\n", released, rc == -1 ? "still running" : "exited",
	    exited);
	if (!jt_load_still_full(statfd))
		printf("    note: the queue was no longer full after the "
		    "wait\n");
	jt_load_stop(&load);
	close(statfd);
	ASSERT_MSG(rc == 0, "exit status %d under load: %s", rc, lg.err);
	ASSERT_MSG(strstr(lg.err, "was removed; stopping") != NULL,
	    "standard error: %s", lg.err);
	ASSERT_MSG(log_has(&lg, "\"event_type\":\"NOTIFY_EXIT\"",
	    pidkey(name, sizeof(name), pid), NULL),
	    "exit before the removal is not in the log");
	logger_done(&lg);
}

static pid_t
sleeper(int jid)
{
	int fds[2];
	pid_t pid;
	char byte;

	if (pipe(fds) != 0)
		return (-1);
	fflush(NULL);
	pid = fork();
	if (pid == 0) {
		close(fds[0]);
		(void)signal(SIGUSR1, SIG_IGN);
		if (jail_attach(jid) != 0)
			_exit(101);
		(void)write(fds[1], "R", 1);
		for (;;)
			pause();
	}
	close(fds[1]);
	if (read(fds[0], &byte, 1) != 1) {
		(void)jt_reap(pid);
		pid = -1;
	}
	close(fds[0]);
	return (pid);
}

/* A process in the given jail (-1: the host) that signals pid. */
static pid_t
signaller(int jid, pid_t pid)
{
	pid_t k;

	fflush(NULL);
	k = fork();
	if (k == 0) {
		if (jid != -1 && jail_attach(jid) != 0)
			_exit(101);
		_exit(kill(pid, SIGUSR1) == 0 ? 0 : 1);
	}
	return (jt_reap(k) == 0 ? k : -1);
}

static void
case_inbound(bool inbound)
{
	struct timespec start;
	struct logger lg;
	pid_t victim, outside, inside;
	char key[32];
	bool marker;
	int rc;

	TEST_BEGIN(inbound ? "L9 -i logs a signal sent into the jail" :
	    "L9b without -i it is not logged");
	if (inbound)
		rc = logger_start(&lg, true, "-j", n_a, "-i", "signal", NULL);
	else
		rc = logger_start(&lg, true, "-j", n_a, "signal", NULL);
	victim = sleeper(j_a);
	if (rc != 0 || victim <= 0) {
		TEST_FAIL("setup");
		return;
	}
	outside = signaller(-1, victim);
	inside = signaller(j_a, victim);
	ASSERT_MSG(outside > 0 && inside > 0, "signallers");
	marker = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!marker && jt_elapsed_ms(&start) < WAIT_MS) {
		marker = log_has(&lg, "\"event_type\":\"NOTIFY_SIGNAL\"",
		    pidkey(key, sizeof(key), inside), NULL);
		if (!marker)
			usleep(50000);
	}
	ASSERT_MSG(marker, "signal sent inside the jail not logged");
	ASSERT_MSG(logger_stop(&lg, true) == 0, "logger exit status");
	ASSERT_MSG(log_has(&lg, "\"event_type\":\"NOTIFY_SIGNAL\"",
	    pidkey(key, sizeof(key), outside), NULL) == inbound,
	    "signal from outside the jail %s", inbound ? "not logged" :
	    "logged");
	(void)kill(victim, SIGKILL);
	(void)jt_reap(victim);
	logger_done(&lg);
}

int
main(void)
{
	char jidstr[16];

	TEST_SUITE_BEGIN("oeslogger jail scope");
	if (geteuid() != 0) {
		TEST_SKIP("requires root");
		return (0);
	}
	if (access(LOGGER, X_OK) != 0) {
		TEST_FAIL("%s is not installed", LOGGER);
		return (1);
	}
	(void)atexit(jt_remove_jails);
	jt_name(n_a, sizeof(n_a), "oeslj", "a");
	snprintf(n_b, sizeof(n_b), "%s.b", n_a);
	snprintf(n_c, sizeof(n_c), "%s.c", n_b);
	jt_name(n_s, sizeof(n_s), "oeslj", "s");
	j_a = jt_make_jail(n_a, "oeslj-a", NULL, "8");
	if (j_a != -1)
		j_b = jt_make_jail(n_b, "oeslj-b", NULL, "4");
	if (j_b != -1)
		j_c = jt_make_jail(n_c, "oeslj-c", NULL, "2");
	j_s = jt_make_jail(n_s, "oeslj-s", NULL, "2");
	if (j_a == -1 || j_b == -1 || j_c == -1 || j_s == -1) {
		TEST_FAIL("cannot create the test jails");
		return (1);
	}
	snprintf(jidstr, sizeof(jidstr), "%d", j_a);

	case_scope("L1 -j by jail ID", "-j", jidstr);
	case_scope("L2 -j by jail name", "-j", n_a);
	case_nested_names();
	case_scope("L4 -J logs the named jail only", "-J", n_a);
	case_later_entrant();
	TEST_BEGIN("L6 a jail that does not exist");
	case_refused("L6 by name", EX_NOINPUT, "no such jail", "-j",
	    "oeslj_nojail", "exit");
	case_refused("L6 by jail ID", EX_NOINPUT, "no such jail", "-j",
	    "999999", "exit");
	TEST_BEGIN("L8 scope options that exclude each other");
	case_refused("L8 -j with -d", EX_USAGE, "usage:", "-j", "1", "-d");
	case_refused("L8 -i alone", EX_USAGE, "usage:", "-i", "exit", NULL);
	case_removed();
	case_removed_under_load();
	case_inbound(true);
	case_inbound(false);

	jt_remove_jails();
	if (oes_test_failures == 0)
		TEST_SUITE_END("oeslogger jail scope");
	return (oes_test_failures != 0);
}

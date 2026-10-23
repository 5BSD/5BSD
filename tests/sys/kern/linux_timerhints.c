/* SPDX-License-Identifier: BSD-2-Clause */
/* Timer-slack lifecycle and the Linux THP status view. */
#include "linux_test.h"

#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30
#define SYS_sched_setscheduler 144
#define SLACK_DEFAULT 50000
#define SLACK_PARENT 123456
#define SLACK_CHILD 654321

static const char *program;
static const char thp_path[] =
    "/sys/kernel/mm/transparent_hugepage/enabled";
static const char thp_never[] = "always madvise [never]\n";

static long
setslack(unsigned long value)
{
	return (sys5(SYS_prctl, PR_SET_TIMERSLACK, value, 0, 0, 0));
}

static unsigned long
getslack(void)
{
	return ((unsigned long)sys5(SYS_prctl, PR_GET_TIMERSLACK, 0, 0, 0, 0));
}

static int
slack_state(void)
{
	static const unsigned long values[] = { 1, 1000, SLACK_PARENT,
	    1UL << 40, 1UL << 63, ~0UL };
	unsigned i;

	if (getslack() != SLACK_DEFAULT)
		return (1);
	for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		if (setslack(values[i]) != 0 || getslack() != values[i])
			return (2);
	}
	/* Unlike NO_NEW_PRIVS, these options ignore the unused arguments. */
	if (sys5(SYS_prctl, PR_SET_TIMERSLACK, SLACK_CHILD, 1, 2, 3) != 0 ||
	    sys5(SYS_prctl, PR_GET_TIMERSLACK, 1, 2, 3, 4) != SLACK_CHILD)
		return (3);
	if (setslack(0) != 0 || getslack() != SLACK_DEFAULT)
		return (4);
	return (0);
}

static int
inherited(void *unused __attribute__((unused)))
{
	if (getslack() != SLACK_PARENT)
		return (1);
	if (setslack(SLACK_CHILD) != 0 || getslack() != SLACK_CHILD)
		return (2);
	if (setslack(0) != 0 || getslack() != SLACK_PARENT)
		return (3);
	return (0);
}

static int
slack_fork(void)
{
	int rc;

	if (setslack(SLACK_PARENT) != 0)
		return (1);
	rc = run_child(inherited, 0);
	if (rc != 0)
		return (10 + rc);
	if (getslack() != SLACK_PARENT)
		return (2);
	if (setslack(0) != 0 || getslack() != SLACK_DEFAULT)
		return (3);
	return (0);
}

static int
slack_worker(void *arg)
{
	int rc = inherited(0);

	if (rc == 0 && setslack(SLACK_CHILD) != 0)
		rc = 4;
	/* Fork from a nonleader: inherit the caller, not the process leader. */
	if (rc == 0) {
		long pid = sys0(SYS_fork);
		int status;
		if (pid == 0) {
			int child_rc = getslack() != SLACK_CHILD ||
			    setslack(1) != 0 || setslack(0) != 0 ||
			    getslack() != SLACK_CHILD;
			(void)sys1(SYS_exit_group, child_rc);
			__builtin_unreachable();
		}
		if (pid < 0 || sys4(SYS_wait4, pid, &status, 0, 0) != pid ||
		    status != 0)
			rc = 5;
	}
	__atomic_store_n((int *)arg, rc, __ATOMIC_RELEASE);
	return (0);
}

static int
slack_thread(void)
{
	struct thread th;
	int result = -1;

	if (setslack(SLACK_PARENT) != 0 ||
	    thread_create(&th, slack_worker, &result) != 0)
		return (1);
	while (__atomic_load_n(&th.tid, __ATOMIC_ACQUIRE) != 0)
		sleep_ms(1);
	(void)sys2(SYS_munmap, th.stack, th.stack_size);
	if (__atomic_load_n(&result, __ATOMIC_ACQUIRE) != 0)
		return (2);
	if (getslack() != SLACK_PARENT)
		return (3);
	if (setslack(0) != 0 || getslack() != SLACK_DEFAULT)
		return (4);
	return (0);
}

static int
exec_child(void *unused __attribute__((unused)))
{
	char *av[] = { (char *)program, "exec_check", 0 };
	char *ev[] = { 0 };

	if (getslack() != SLACK_PARENT || setslack(SLACK_CHILD) != 0)
		return (1);
	(void)sys3(SYS_execve, program, av, ev);
	return (2);
}

static int
slack_exec(void)
{
	int rc;

	if (setslack(SLACK_PARENT) != 0)
		return (1);
	rc = run_child(exec_child, 0);
	(void)setslack(0);
	return (rc);
}

/* Change another task to exercise target-thread state and locking. */
static int
slack_remote_rt(void *arg)
{
	int priority = 1;

	return (sys3(SYS_sched_setscheduler, (long)arg, 1, &priority) != 0);
}

static int
slack_realtime(void)
{
	struct {
		unsigned size, policy;
		unsigned long flags;
		int nice;
		unsigned priority;
		unsigned long runtime, deadline, period;
	} attr = { 48, 1, 0, 0, 1, 0, 0, 0 };
	int priority, rc, api;
	long result;

	for (api = 0; api < 2; api++) {
		priority = 1;
		attr.policy = 1;
		attr.priority = 1;
		if (setslack(SLACK_PARENT) != 0)
			return (1);
		result = api == 0 ?
		    sys3(SYS_sched_setscheduler, 0, 1, &priority) :
		    sys3(SYS_sched_setattr, 0, &attr, 0);
		if (result != 0)
			return (2);
		rc = getslack() != 0 || setslack(SLACK_CHILD) != 0 ||
		    getslack() != 0 || setslack(0) != 0 || getslack() != 0;
		/* sched_setparam keeps the real-time policy and zero slack. */
		priority = 2;
		if (sys2(142 /* sched_setparam */, 0, &priority) != 0 ||
		    getslack() != 0)
			rc = 1;
		priority = 0;
		attr.policy = 0;
		attr.priority = 0;
		result = api == 0 ?
		    sys3(SYS_sched_setscheduler, 0, 0, &priority) :
		    sys3(SYS_sched_setattr, 0, &attr, 0);
		if (result != 0)
			return (4);
		if (rc != 0 || getslack() != SLACK_DEFAULT)
			return (5);
	}
	if (setslack(SLACK_PARENT) != 0 ||
	    run_child(slack_remote_rt, (void *)sys0(SYS_getpid)) != 0)
		return (6);
	rc = getslack() != 0;
	priority = 0;
	if (sys3(SYS_sched_setscheduler, 0, 0, &priority) != 0 ||
	    getslack() != SLACK_DEFAULT || rc != 0)
		return (7);
	return (0);
}

static int
slack_sleep(void)
{
	struct timespec before, after, delay = { 0, 10000000 };
	long elapsed;
	unsigned i;

	for (i = 0; i < 2; i++) {
		if (setslack(i == 0 ? 1 : 1000000000) != 0 ||
		    sys2(SYS_clock_gettime, 1, &before) != 0 ||
		    sys2(SYS_nanosleep, &delay, 0) != 0 ||
		    sys2(SYS_clock_gettime, 1, &after) != 0)
			return (1);
		elapsed = (after.tv_sec - before.tv_sec) * 1000000000L +
		    after.tv_nsec - before.tv_nsec;
		/* Slack never permits a timer to expire early. */
		if (elapsed < delay.tv_nsec)
			return (2);
	}
	(void)setslack(0);
	return (0);
}

static int
thp_read(void)
{
	char buf[sizeof(thp_never)];
	long fd, n;
	unsigned i;

	fd = sys3(SYS_open, thp_path, 0, 0);
	if (fd < 0)
		return (1);
	n = sys3(SYS_read, fd, buf, sizeof(buf));
	if (n != sizeof(thp_never) - 1)
		return (2);
	for (i = 0; i < sizeof(thp_never) - 1; i++)
		if (buf[i] != thp_never[i])
			return (3);
	if (sys3(SYS_read, fd, buf, 1) != 0 ||
	    sys3(SYS_lseek, fd, 0, 0) != 0)
		return (4);
	for (i = 0; i < sizeof(thp_never) - 1; i++)
		if (sys3(SYS_read, fd, buf, 1) != 1 || buf[0] != thp_never[i])
			return (5);
	(void)sys1(SYS_close, fd);
	return (0);
}

static int
thp_readonly(void)
{
	long fd, n;

	fd = sys3(SYS_open, thp_path, 1 /* O_WRONLY */, 0);
	if (fd >= 0) {
		n = sys3(SYS_write, fd, "always\n", 7);
		(void)sys1(SYS_close, fd);
		if (n >= 0)
			return (1);
	}
	return (thp_read());
}

static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	static const struct subtest cases[] = {
		{ "slack_state", slack_state },
		{ "slack_fork", slack_fork },
		{ "slack_thread", slack_thread },
		{ "slack_exec", slack_exec },
		{ "slack_realtime", slack_realtime },
		{ "slack_sleep", slack_sleep },
		{ "thp_read", thp_read },
		{ "thp_readonly", thp_readonly },
	};

	program = argv[0];
	if (argc == 2 && xstreq(argv[1], "exec_check")) {
		if (getslack() != SLACK_CHILD || setslack(0) != 0 ||
		    getslack() != SLACK_PARENT)
			return (1);
		return (0);
	}
	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}

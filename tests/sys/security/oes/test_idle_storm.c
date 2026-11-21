/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Activation and deactivation of OES and mac_abac hooks racing with the
 * system calls those hooks sit on.
 *
 * Worker processes loop over open, read, write, fstat, stat, pipe I/O,
 * mprotect, fork+exit and exec.  At the same time togglers open OES
 * clients, subscribe them to random event sets (NOTIFY, and AUTH with a
 * descendants scope that the workers are outside), drain and close them,
 * and load and remove mac_abac rules naming a label nobody carries.
 * Nothing may fail, hang or panic; afterwards every hook is idle again and
 * the fast-path state is consistent (security.mac.fastpath: flags are the OR
 * of the policies' counted sets, oes and mac_abac count nothing).
 *
 * STORM_SECONDS (default 30) sets the duration.
 */

#include <sys/param.h>
#include <sys/mac.h>
#include <sys/mman.h>

#include <security/mac_abac/mac_abac.h>

#include "test_idle_common.h"

#define	NWORKERS	6
#define	NTOGGLERS	3

static char work_file[PATH_MAX];
static volatile sig_atomic_t stop;

static void
on_alarm(int sig __unused)
{

	stop = 1;
}

static int
worker(int id)
{
	char buf[64], c;
	struct stat sb;
	pid_t pid;
	void *map;
	int fd, p[2], status, errors;
	long n;

	errors = 0;
	for (n = 0; !stop; n++) {
		fd = open(work_file, O_RDWR);
		if (fd < 0) {
			errors++;
			continue;
		}
		if (pread(fd, buf, sizeof(buf), 0) < 0 ||
		    pwrite(fd, "w", 1, id) != 1 || fstat(fd, &sb) != 0)
			errors++;
		map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
		if (map == MAP_FAILED ||
		    mprotect(map, 4096, PROT_READ) != 0)
			errors++;
		if (map != MAP_FAILED)
			(void)munmap(map, 4096);
		(void)close(fd);
		if (stat(work_file, &sb) != 0)
			errors++;
		if (pipe(p) != 0 || write(p[1], "p", 1) != 1 ||
		    read(p[0], &c, 1) != 1)
			errors++;
		(void)close(p[0]);
		(void)close(p[1]);
		if (n % 16 == 0) {
			pid = fork();
			if (pid == 0) {
				if (id % 2 == 0)
					execl("/usr/bin/true", "true",
					    (char *)NULL);
				_exit(id % 2 == 0 ? 127 : 0);
			}
			if (pid < 0 || waitpid(pid, &status, 0) != pid ||
			    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errors++;
		}
		if (errors > 0 && errors < 5)
			printf("    worker %d: %s\n", id, strerror(errno));
	}
	printf("    worker %d: %ld rounds, %d errors\n", id, n, errors);
	return (errors == 0 ? 0 : 1);
}

static const oes_event_type_t storm_events[] = {
	OES_EVENT_NOTIFY_OPEN, OES_EVENT_NOTIFY_CLOSE, OES_EVENT_NOTIFY_READ,
	OES_EVENT_NOTIFY_WRITE, OES_EVENT_NOTIFY_STAT,
	OES_EVENT_NOTIFY_LOOKUP, OES_EVENT_NOTIFY_EXEC,
	OES_EVENT_NOTIFY_FORK, OES_EVENT_NOTIFY_EXIT,
	OES_EVENT_NOTIFY_PIPE_READ, OES_EVENT_NOTIFY_PIPE_WRITE,
	OES_EVENT_NOTIFY_MPROTECT, OES_EVENT_NOTIFY_MMAP,
	OES_EVENT_NOTIFY_PRIV_CHECK, OES_EVENT_NOTIFY_SYSCTL,
};

static const oes_event_type_t storm_auth[] = {
	OES_EVENT_AUTH_OPEN, OES_EVENT_AUTH_READ, OES_EVENT_AUTH_WRITE,
	OES_EVENT_AUTH_STAT, OES_EVENT_AUTH_EXEC, OES_EVENT_AUTH_MPROTECT,
	OES_EVENT_AUTH_LOOKUP,
};

/* One AUTH client: scope, subscribe at random, answer, close. */
static int
auth_round(void)
{
	oes_event_type_t ev[nitems(storm_auth)];
	test_msg_buf buf;
	size_t i, n;
	int fd, k, errors;

	errors = 0;
	srandom(getpid());
	fd = idle_scoped_client(OES_MODE_AUTH, 1000, NULL, 0);
	if (fd < 0) {
		fprintf(stderr, "    auth client: %s\n", strerror(errno));
		return (1);
	}
	for (k = 0; k < 4 && !stop; k++) {
		n = 0;
		for (i = 0; i < nitems(storm_auth); i++)
			if (random() % 2)
				ev[n++] = storm_auth[i];
		if (n != 0 && test_subscribe(fd, ev, n, OES_SUB_ADD) != 0) {
			fprintf(stderr, "    auth subscribe: %s\n",
			    strerror(errno));
			errors++;
		}
		while (test_wait_event(fd, &buf.msg, 0) == 0)
			if (buf.msg.em_action == OES_ACTION_AUTH)
				(void)idle_respond(fd, buf.msg.em_id,
				    OES_AUTH_ALLOW);
		if (n != 0 && random() % 2 &&
		    test_subscribe(fd, ev, n, OES_SUB_REMOVE) != 0)
			errors++;
	}
	(void)close(fd);
	return (errors == 0 ? 0 : 1);
}

static int
oes_toggler(int id)
{
	oes_event_type_t ev[nitems(storm_events)];
	test_msg_buf buf;
	size_t n, i;
	long rounds;
	int fd, errors, k;

	errors = 0;
	srandom(getpid());
	for (rounds = 0; !stop; rounds++) {
		if (random() % 3 == 0) {
			/*
			 * A descendants scope adds a marker to the caller's
			 * credential (at most OES_SCOPE_MARKERS_MAX): use a
			 * child per AUTH client.
			 */
			pid_t c = fork();
			int st = 0;

			if (c == 0)
				_exit(auth_round());
			if (c < 0 || waitpid(c, &st, 0) != c ||
			    !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
				fprintf(stderr, "    auth round: status %#x\n",
				    st);
				errors++;
			}
			continue;
		}
		fd = test_open_oes();
		if (fd < 0 || test_set_mode(fd, OES_MODE_NOTIFY) != 0) {
			fprintf(stderr, "    notify client: %s\n", strerror(errno));
			if (fd >= 0)
				(void)close(fd);
			errors++;
			continue;
		}
		for (k = 0; k < 4 && !stop; k++) {
			n = 0;
			for (i = 0; i < nitems(storm_events); i++)
				if (random() % 3 == 0)
					ev[n++] = storm_events[i];
			if (n != 0 && test_subscribe(fd, ev, n,
			    (random() % 2) ? OES_SUB_REPLACE : OES_SUB_ADD) != 0) {
				fprintf(stderr, "    subscribe: %s\n",
				    strerror(errno));
				errors++;
			}
			while (test_wait_event(fd, &buf.msg, 0) == 0)
				if (buf.msg.em_action == OES_ACTION_AUTH)
					(void)idle_respond(fd, buf.msg.em_id,
					    OES_AUTH_ALLOW);
			if (n != 0 && random() % 2 &&
			    test_subscribe(fd, ev, n, OES_SUB_REMOVE) != 0)
				errors++;
		}
		(void)close(fd);
	}
	printf("    oes toggler %d: %ld clients, %d errors\n", id, rounds,
	    errors);
	return (errors == 0 ? 0 : 1);
}

static const uint32_t storm_ops[] = {
	ABAC_OP_READ, ABAC_OP_WRITE, ABAC_OP_STAT, ABAC_OP_LOOKUP,
	ABAC_OP_OPEN, ABAC_OP_EXEC, ABAC_OP_MMAP, ABAC_OP_MPROTECT,
	ABAC_OP_SEND, ABAC_OP_RECEIVE,
};

static int
abac_toggler(void)
{
	static const char subj[] = "type=abac-storm-nobody";
	static const char obj[] = "*";
	char buf[512];
	struct abac_rule_arg rule;
	struct abac_set_range r;
	uint32_t id;
	long rounds;
	int errors, k;

	errors = 0;
	srandom(getpid());
	/*
	 * mac_abac appends every rule at the end of its table and a removal
	 * leaves a hole, so the table fills after ABAC_MAX_RULES additions:
	 * clear it now and then (nothing else loads rules during the storm).
	 */
	for (rounds = 0; !stop; rounds++) {
		if (rounds % 512 == 0)
			(void)mac_syscall("mac_abac", ABAC_SYS_RULE_CLEAR, NULL);
		memset(&rule, 0, sizeof(rule));
		rule.vr_action = ABAC_ACTION_DENY;
		rule.vr_set = 61007;
		for (k = 0; k < (int)nitems(storm_ops); k++)
			if (random() % 3 == 0)
				rule.vr_operations |= storm_ops[k];
		if (rule.vr_operations == 0)
			rule.vr_operations = ABAC_OP_READ;
		rule.vr_subject_len = sizeof(subj);
		rule.vr_object_len = sizeof(obj);
		memcpy(buf, &rule, sizeof(rule));
		memcpy(buf + sizeof(rule), subj, sizeof(subj));
		memcpy(buf + sizeof(rule) + sizeof(subj), obj, sizeof(obj));
		if (mac_syscall("mac_abac", ABAC_SYS_RULE_ADD, buf) != 0) {
			fprintf(stderr, "    rule add: %s\n", strerror(errno));
			errors++;
			continue;
		}
		memcpy(&rule, buf, sizeof(rule));
		id = rule.vr_id;
		if (random() % 2) {
			r.vsr_start = r.vsr_end = 61007;
			(void)mac_syscall("mac_abac", ABAC_SYS_SET_DISABLE, &r);
			(void)mac_syscall("mac_abac", ABAC_SYS_SET_ENABLE, &r);
		}
		if (mac_syscall("mac_abac", ABAC_SYS_RULE_REMOVE, &id) != 0)
			errors++;
	}
	printf("    abac toggler: %ld rules, %d errors\n", rounds, errors);
	return (errors == 0 ? 0 : 1);
}

/* Every hook idle and the fast-path state consistent, if exported. */
static void
check_idle_state(void)
{
	static char text[65536];
	unsigned long long a, flags, or;
	const char *p;
	size_t l;
	int live;

	l = sizeof(text) - 1;
	if (sysctlbyname("security.oes.gate.hooks", text, &l, NULL, 0) == 0) {
		text[l] = '\0';
		live = 0;
		for (p = strstr(text, " live 1"); p != NULL;
		    p = strstr(p + 1, " live 1"))
			live++;
		ASSERT_MSG(live == 0, "%d OES hooks live after the storm",
		    live);
	} else
		printf("    note: no security.oes.gate.hooks\n");
	l = sizeof(live);
	if (sysctlbyname("security.mac.mac_abac.live_ops", &live, &l, NULL,
	    0) == 0)
		ASSERT_MSG(live == 0, "mac_abac live_ops %#x after the storm",
		    live);
	l = sizeof(text) - 1;
	if (sysctlbyname("security.mac.fastpath", text, &l, NULL, 0) != 0) {
		printf("    note: no security.mac.fastpath\n");
		return;
	}
	text[l] = '\0';
	if (sscanf(text, "flags %llx", &flags) != 1) {
		TEST_FAIL("malformed security.mac.fastpath");
		return;
	}
	or = 0;
	for (p = strstr(text, "\npolicy "); p != NULL;
	    p = strstr(p + 1, "\npolicy ")) {
		const char *q = strstr(p, " active ");

		if (q == NULL || sscanf(q, " active %llx", &a) != 1) {
			TEST_FAIL("malformed policy line");
			return;
		}
		or |= a;
		if (strncmp(p, "\npolicy oes ", 12) == 0 ||
		    strncmp(p, "\npolicy mac_abac ", 17) == 0)
			ASSERT_MSG(a == 0, "%.*s counts %#llx after the storm",
			    (int)(strchr(p + 1, ' ') - p), p + 1, a);
	}
	ASSERT_MSG(or == flags, "flags %#llx, policies count %#llx", flags,
	    or);
}

int
main(void)
{
	pid_t pids[NWORKERS + NTOGGLERS + 1];
	const char *env;
	int fd, i, n, secs, status;

	TEST_SUITE_BEGIN("OES and mac_abac idle storm");
	env = getenv("STORM_SECONDS");
	secs = env != NULL ? atoi(env) : 30;
	if (secs <= 0)
		secs = 30;
	snprintf(work_file, sizeof(work_file), "./idle-storm.%d",
	    (int)getpid());
	fd = open(work_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0 || ftruncate(fd, 4096) != 0) {
		TEST_FAIL("work file: %s", strerror(errno));
		return (1);
	}
	(void)close(fd);
	(void)signal(SIGALRM, on_alarm);
	n = 0;
	for (i = 0; i < NWORKERS + NTOGGLERS + 1; i++) {
		pids[n] = fork();
		if (pids[n] == 0) {
			(void)signal(SIGALRM, on_alarm);
			alarm(secs);
			if (i < NWORKERS)
				status = worker(i);
			else if (i < NWORKERS + NTOGGLERS)
				status = oes_toggler(i - NWORKERS);
			else
				status = abac_toggler();
			fflush(NULL);
			_exit(status);
		}
		if (pids[n] > 0)
			n++;
	}
	for (i = 0; i < n; i++) {
		ASSERT_MSG(waitpid(pids[i], &status, 0) == pids[i] &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "process %d: status %#x", i, status);
	}
	check_idle_state();
	(void)unlink(work_file);
	TEST_SUITE_END("OES and mac_abac idle storm");
	return (0);
}

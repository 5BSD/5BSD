/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * mac_abac idle gating: security.mac.mac_abac.live_ops follows exactly the
 * operations enabled rules name (all of them under default deny or
 * force_hooks, none while disabled), a rule applies from the moment the
 * call that loaded it returns, and with no rule nothing is evaluated.
 *
 * ABAC_IDLE_LEVEL is the part of the work the kernel under test has:
 *   1  live_ops is computed and exported, hooks are not yet gated;
 *   2  hooks return at their gate when their operations are not live;
 *   3  mac_abac counts fast-path flags only for live operations.
 */

#include <pthread.h>
#include <stdatomic.h>

#include "idle_common.h"

#ifndef ABAC_IDLE_LEVEL
#define	ABAC_IDLE_LEVEL	3
#endif

static void
idle_head(atf_tc_t *tc, const char *descr)
{

	atf_tc_set_md_var(tc, "descr", descr);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_abac");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}

#define	IDLE_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc) { idle_head(tc, descr); }				\
ATF_TC_CLEANUP(name, tc) { (void)tc; idle_cleanup(); }			\
ATF_TC_BODY(name, tc)

static uint32_t
live_ops(void)
{

	return ((uint32_t)idle_sysctl_get("security.mac.mac_abac.live_ops"));
}

#if ABAC_IDLE_LEVEL >= 3
/*
 * The fast-path hooks of mac_abac and their operations (mac_abac.c
 * abac_fp_gate[]).  DEV_DQ kernels add the four file_check hooks.
 */
static const struct {
	const char	*hook;
	uint32_t	ops;
} fp_gate[] = {
	{ "vnode_check_access", ABAC_OP_ACCESS },
	{ "vnode_check_lookup", ABAC_OP_LOOKUP },
	{ "vnode_check_readlink", ABAC_OP_READ },
	{ "vnode_check_open", ABAC_OP_OPEN },
	{ "vnode_check_stat", ABAC_OP_STAT },
	{ "vnode_check_read", ABAC_OP_READ },
	{ "vnode_check_write", ABAC_OP_WRITE },
	{ "vnode_check_mmap", ABAC_OP_MMAP },
	{ "vnode_check_poll", ABAC_OP_READ },
	{ "vnode_check_rename_from", ABAC_OP_RENAME },
	{ "proc_check_mprotect", ABAC_OP_MPROTECT },
	{ "pipe_check_read", ABAC_OP_READ },
	{ "pipe_check_stat", ABAC_OP_STAT },
	{ "pipe_check_write", ABAC_OP_WRITE },
	{ "socket_check_send", ABAC_OP_SEND },
	{ "socket_check_receive", ABAC_OP_RECEIVE },
	{ "file_check_read", ABAC_OP_READ },
	{ "file_check_write", ABAC_OP_WRITE },
	{ "file_check_stat", ABAC_OP_STAT },
	{ "file_check_mmap", ABAC_OP_MMAP },
};

static char fp_text[65536];

static void
fp_fetch(void)
{
	size_t l;

	l = sizeof(fp_text) - 1;
	ATF_REQUIRE_MSG(sysctlbyname("security.mac.fastpath", fp_text, &l,
	    NULL, 0) == 0, "security.mac.fastpath: %s", strerror(errno));
	fp_text[l] = '\0';
}

static int
fp_bit(const char *hook)
{
	char name[64];
	const char *p;
	int bit, cnt;

	bit = 0;
	for (p = strstr(fp_text, "\nhook "); p != NULL;
	    p = strstr(p + 1, "\nhook ")) {
		if (sscanf(p + 1, "hook %63s count %d", name, &cnt) == 2 &&
		    strcmp(name, hook) == 0)
			return (bit);
		bit++;
	}
	return (-1);
}

static uint64_t
fp_field(const char *policy, const char *field)
{
	char key[80];
	unsigned long long v;
	const char *p;

	snprintf(key, sizeof(key), "policy %s ", policy);
	p = strstr(fp_text, key);
	ATF_REQUIRE_MSG(p != NULL, "no policy %s", policy);
	snprintf(key, sizeof(key), " %s ", field);
	p = strstr(p, key);
	ATF_REQUIRE(p != NULL);
	ATF_REQUIRE(sscanf(p + strlen(key), "%llx", &v) == 1);
	return (v);
}

/* mac_abac counts exactly the fast-path hooks of the live operations. */
static void
fp_expect(const char *what)
{
	uint64_t active, impl, want;
	uint32_t ops;
	size_t i;
	int b;

	fp_fetch();
	ATF_CHECK_MSG(strstr(fp_text, "policy mac_abac inactive 1 ") != NULL,
	    "%s: mac_abac is not registered fast-path inactive", what);
	ops = live_ops();
	active = fp_field("mac_abac", "active");
	impl = fp_field("mac_abac", "implemented");
	want = 0;
	for (i = 0; i < nitems(fp_gate); i++) {
		b = fp_bit(fp_gate[i].hook);
		ATF_REQUIRE_MSG(b >= 0, "no hook %s", fp_gate[i].hook);
		if ((impl & (1ULL << b)) != 0 && (ops & fp_gate[i].ops) != 0)
			want |= 1ULL << b;
	}
	ATF_CHECK_MSG(active == want, "%s: live_ops %#x, mac_abac counts "
	    "%#jx, expected %#jx", what, ops, (uintmax_t)active,
	    (uintmax_t)want);
}

static bool
fp_counted(const char *hook)
{
	int b;

	fp_fetch();
	b = fp_bit(hook);
	ATF_REQUIRE(b >= 0);
	return ((fp_field("mac_abac", "active") & (1ULL << b)) != 0);
}
#else
#define	fp_expect(what)	do { } while (0)
#endif

IDLE_TC(a1_no_rule_idle, "A-1: no rule, default allow: nothing is live")
{

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	ATF_CHECK_EQ(0, live_ops());
	fp_expect("A-1");
}

IDLE_TC(a2_a3_a4_rules_follow,
    "A-2..A-4: rules make exactly their operations live, enforced at once")
{
	struct lworker w;
	uint32_t exec_id, read_id;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	lworker_start(&w);
	exec_id = idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC);
	ATF_CHECK_EQ(ABAC_OP_EXEC, live_ops());
	fp_expect("A-2");
	ATF_CHECK_EQ_MSG(EACCES, lworker_do(&w, LW_EXEC), "exec, A-2");
	read_id = idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_READ);
	ATF_CHECK_EQ(ABAC_OP_EXEC | ABAC_OP_READ, live_ops());
	fp_expect("A-3");
	ATF_CHECK_EQ_MSG(EACCES, lworker_do(&w, LW_READ), "read, A-3");
	idle_remove_rule(exec_id);
	idle_remove_rule(read_id);
	ATF_CHECK_EQ(0, live_ops());
	fp_expect("A-4");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_READ), "read, A-4");
	ATF_CHECK_EQ_MSG(0, lworker_do(&w, LW_EXEC), "exec, A-4");
	lworker_stop(&w);
}

IDLE_TC(a5_default_deny_all_live,
    "A-5: default deny (permissive) makes every operation live")
{

	(void)tc;
	idle_save_state();
	idle_set_mode(ABAC_MODE_PERMISSIVE);
	idle_set_defpol(1);
	ATF_CHECK_EQ(ABAC_OP_ALL, live_ops());
	fp_expect("A-5");
	idle_set_defpol(0);
	ATF_CHECK_EQ(0, live_ops());
	fp_expect("A-5 restored");
}

IDLE_TC(a6_mode_and_enabled,
    "A-6: disabled mode or policy makes nothing live")
{
	size_t len;
	int v;

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_WRITE);
	idle_set_mode(ABAC_MODE_DISABLED);
	ATF_CHECK_EQ_MSG(0, live_ops(), "mode disabled");
	idle_set_mode(ABAC_MODE_ENFORCING);
	ATF_CHECK_EQ_MSG(ABAC_OP_WRITE, live_ops(), "mode enforcing");
	idle_set_mode(ABAC_MODE_PERMISSIVE);
	v = 0;
	len = sizeof(v);
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.enabled", NULL, NULL,
	    &v, len) == 0);
	ATF_CHECK_EQ_MSG(0, live_ops(), "enabled 0");
	v = 1;
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.enabled", NULL, NULL,
	    &v, len) == 0);
	ATF_CHECK_EQ_MSG(ABAC_OP_WRITE, live_ops(), "enabled 1");
	fp_expect("A-6");
}

IDLE_TC(a7_sets, "A-7: a disabled set's rules are not live")
{

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_WRITE);
	idle_set_range(ABAC_SYS_SET_DISABLE, IDLE_SET);
	ATF_CHECK_EQ_MSG(0, live_ops(), "set disabled");
	fp_expect("A-7 disabled");
	idle_set_range(ABAC_SYS_SET_ENABLE, IDLE_SET);
	ATF_CHECK_EQ_MSG(ABAC_OP_WRITE, live_ops(), "set enabled");
	fp_expect("A-7 enabled");
}

IDLE_TC(a11_force_hooks_values, "A-11: force_hooks takes 0 or 1 only")
{
	int v;

	(void)tc;
	idle_save_state();
	v = 2;
	ATF_CHECK_ERRNO(EINVAL, sysctlbyname("security.mac.mac_abac.force_hooks",
	    NULL, NULL, &v, sizeof(v)) == -1);
	v = 1;
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.force_hooks", NULL,
	    NULL, &v, sizeof(v)) == 0);
	ATF_CHECK_EQ(ABAC_OP_ALL, live_ops());
	v = 0;
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.force_hooks", NULL,
	    NULL, &v, sizeof(v)) == 0);
	ATF_CHECK_EQ(0, live_ops());
}

#if ABAC_IDLE_LEVEL >= 2
IDLE_TC(a10_force_hooks_counts,
    "A-10: force_hooks restores evaluation of unnamed operations")
{
	struct stat sb;
	uint64_t c0, c1, c2, c3;
	int i, v;

	(void)tc;
	idle_save_state();
	idle_make_objects();
	idle_set_defpol(0);
	v = 1;
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.force_hooks", NULL,
	    NULL, &v, sizeof(v)) == 0);
	c0 = idle_sysctl_u64("security.mac.mac_abac.checks");
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE(stat(idle_obj, &sb) == 0);
	c1 = idle_sysctl_u64("security.mac.mac_abac.checks");
	v = 0;
	ATF_REQUIRE(sysctlbyname("security.mac.mac_abac.force_hooks", NULL,
	    NULL, &v, sizeof(v)) == 0);
	/*
	 * The write itself is checked while force_hooks is still 1 (a
	 * sysctl(3) write is two sysctl calls): count from after it.
	 */
	c2 = idle_sysctl_u64("security.mac.mac_abac.checks");
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE(stat(idle_obj, &sb) == 0);
	c3 = idle_sysctl_u64("security.mac.mac_abac.checks");
	ATF_CHECK_MSG(c1 - c0 >= 1000, "force_hooks: %ju evaluations",
	    (uintmax_t)(c1 - c0));
	ATF_CHECK_EQ_MSG(c2, c3, "idle again: %ju evaluations",
	    (uintmax_t)(c3 - c2));
}
#endif

#if ABAC_IDLE_LEVEL >= 3
IDLE_TC(a12_write_rule_leaves_reads,
    "A-12: a write rule leaves the read, stat and lookup flags uncounted")
{

	(void)tc;
	idle_save_state();
	idle_set_defpol(0);
	(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_WRITE);
	ATF_CHECK(!fp_counted("vnode_check_read"));
	ATF_CHECK(!fp_counted("vnode_check_stat"));
	ATF_CHECK(!fp_counted("vnode_check_lookup"));
	ATF_CHECK(!fp_counted("pipe_check_read"));
	ATF_CHECK(fp_counted("vnode_check_write"));
	ATF_CHECK(fp_counted("pipe_check_write"));
	fp_expect("A-12");
}

/*
 * A-8/A-9: no window after a load returns.  Threads of a labelled process
 * read in a loop, each read tagged with the generation it saw before
 * starting; the main thread loads a deny-read rule and then publishes a new
 * generation.  Every read that saw it must be denied.  The reads are of a
 * pipe the process created (its label is the subject's, which the rule
 * names as object): only OES and mac_abac hook pipe reads, so with OES idle
 * the framework is not entered at all unless mac_abac has counted the flag.
 */
#define	NREADERS	4
/*
 * Reads checked after the load: every reader runs its loop many times over
 * (a hundred reads each), so a window that let any read through after the
 * load returned would show in some reader.
 */
#define	A8_CHECKS	(NREADERS * 100)

enum load_kind { LOAD_ADD, LOAD_REPLACE, LOAD_SET_ENABLE };

struct a8_state {
	atomic_int	gen;
	atomic_int	stop;
	atomic_int	bad;
	atomic_int	checked;
	int		fds[NREADERS][2];
	pthread_mutex_t	mtx;		/* Protects started and wakes cv */
	pthread_cond_t	cv;
	int		started;	/* Readers that have read once */
};

static struct a8_state a8 = {
	.mtx = PTHREAD_MUTEX_INITIALIZER,
	.cv = PTHREAD_COND_INITIALIZER,
};

static void *
a8_reader(void *arg)
{
	int i = (int)(intptr_t)arg;
	char c;
	int seen, r;
	bool first;

	first = true;
	while (!atomic_load(&a8.stop)) {
		seen = atomic_load_explicit(&a8.gen, memory_order_acquire);
		if (write(a8.fds[i][1], "x", 1) != 1)
			break;
		r = read(a8.fds[i][0], &c, 1) == 1 ? 0 : errno;
		if (first) {
			/* Running before the load: tell the main thread. */
			first = false;
			pthread_mutex_lock(&a8.mtx);
			a8.started++;
			pthread_cond_broadcast(&a8.cv);
			pthread_mutex_unlock(&a8.mtx);
		}
		if (seen == 1) {
			if (atomic_fetch_add(&a8.checked, 1) + 1 == A8_CHECKS) {
				pthread_mutex_lock(&a8.mtx);
				pthread_cond_broadcast(&a8.cv);
				pthread_mutex_unlock(&a8.mtx);
			}
			if (r != EACCES)
				atomic_fetch_add(&a8.bad, 1);
		}
	}
	return (NULL);
}

static void
a8_run(enum load_kind kind)
{
	char buf[512];
	pthread_t t[NREADERS];
	size_t len;
	mac_t label;
	pid_t pid;
	int i, status;

	idle_save_state();
	idle_set_defpol(0);
	idle_set_mode(ABAC_MODE_ENFORCING);
	if (kind == LOAD_REPLACE)
		(void)idle_add_rule(ABAC_ACTION_DENY, ABAC_OP_EXEC);
	if (kind == LOAD_SET_ENABLE) {
		(void)idle_add_rule_full(ABAC_ACTION_DENY, ABAC_OP_READ,
		    IDLE_SET, SUBJ_LABEL, SUBJ_LABEL);
		idle_set_range(ABAC_SYS_SET_DISABLE, IDLE_SET);
	}
	ATF_REQUIRE((live_ops() & ABAC_OP_READ) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (mac_from_text(&label, "mac_abac/" SUBJ_LABEL) != 0 ||
		    mac_set_proc(label) != 0)
			_exit(100);
		for (i = 0; i < NREADERS; i++)
			if (pipe(a8.fds[i]) != 0)
				_exit(101);
		for (i = 0; i < NREADERS; i++)
			pthread_create(&t[i], NULL, a8_reader,
			    (void *)(intptr_t)i);
		pthread_mutex_lock(&a8.mtx);
		while (a8.started < NREADERS)
			pthread_cond_wait(&a8.cv, &a8.mtx);
		pthread_mutex_unlock(&a8.mtx);
		switch (kind) {
		case LOAD_ADD:
			(void)idle_add_rule_full(ABAC_ACTION_DENY,
			    ABAC_OP_READ, IDLE_SET, SUBJ_LABEL, SUBJ_LABEL);
			break;
		case LOAD_REPLACE:
			len = idle_pack_rule(buf, sizeof(buf),
			    ABAC_ACTION_DENY, ABAC_OP_READ, IDLE_SET,
			    SUBJ_LABEL, SUBJ_LABEL);
			idle_load_rules(buf, len, 1);
			break;
		case LOAD_SET_ENABLE:
			idle_set_range(ABAC_SYS_SET_ENABLE, IDLE_SET);
			break;
		}
		atomic_store_explicit(&a8.gen, 1, memory_order_release);
		pthread_mutex_lock(&a8.mtx);
		while (atomic_load(&a8.checked) < A8_CHECKS)
			pthread_cond_wait(&a8.cv, &a8.mtx);
		pthread_mutex_unlock(&a8.mtx);
		atomic_store(&a8.stop, 1);
		for (i = 0; i < NREADERS; i++)
			(void)close(a8.fds[i][1]);
		for (i = 0; i < NREADERS; i++)
			pthread_join(t[i], NULL);
		printf("%d reads after the load returned, %d not denied\n",
		    atomic_load(&a8.checked), atomic_load(&a8.bad));
		_exit(atomic_load(&a8.bad) == 0 ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "reads passed after the rule was in force (status %#x)", status);
	ATF_CHECK((live_ops() & ABAC_OP_READ) != 0);
	ATF_CHECK(fp_counted("pipe_check_read"));
}

IDLE_TC(a8_no_window_add,
    "A-8: every pipe read after RULE_ADD returns is denied")
{

	(void)tc;
	a8_run(LOAD_ADD);
}

IDLE_TC(a9_no_window_load,
    "A-9: every pipe read after RULE_LOAD returns is denied")
{

	(void)tc;
	a8_run(LOAD_REPLACE);
}

IDLE_TC(a9_no_window_set_enable,
    "A-9: every pipe read after SET_ENABLE returns is denied")
{

	(void)tc;
	a8_run(LOAD_SET_ENABLE);
}
#endif

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, a1_no_rule_idle);
	ATF_TP_ADD_TC(tp, a2_a3_a4_rules_follow);
	ATF_TP_ADD_TC(tp, a5_default_deny_all_live);
	ATF_TP_ADD_TC(tp, a6_mode_and_enabled);
	ATF_TP_ADD_TC(tp, a7_sets);
	ATF_TP_ADD_TC(tp, a11_force_hooks_values);
#if ABAC_IDLE_LEVEL >= 2
	ATF_TP_ADD_TC(tp, a10_force_hooks_counts);
#endif
#if ABAC_IDLE_LEVEL >= 3
	ATF_TP_ADD_TC(tp, a12_write_rule_leaves_reads);
	ATF_TP_ADD_TC(tp, a8_no_window_add);
	ATF_TP_ADD_TC(tp, a9_no_window_load);
	ATF_TP_ADD_TC(tp, a9_no_window_set_enable);
#endif
	return (atf_no_error());
}

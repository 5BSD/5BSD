/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * OES idle gating: which hooks are live follows exactly what the clients
 * and the strict settings need (security.oes.gate.hooks), a subscription is
 * delivered from the moment its ioctl returns, and closing the last client
 * leaves every hook idle.
 *
 * OES_IDLE_LEVEL is the part of the work the kernel under test has:
 *   1  liveness is computed and exported, hooks are not yet gated;
 *   2  hooks return at their gate when not live (security.oes.gate.passes);
 *   3  OES counts fast-path flags only for live hooks (security.mac.fastpath).
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/user.h>

#include "test_idle_common.h"

#ifndef OES_IDLE_LEVEL
#define	OES_IDLE_LEVEL	1
#endif

#define	GATE_MAX	128

struct gate {
	int		g_n;
	char		g_name[GATE_MAX][40];
	char		g_fp[GATE_MAX][40];
	unsigned	g_auth[GATE_MAX];
	unsigned	g_notify[GATE_MAX];
	unsigned	g_alt[GATE_MAX];
	int		g_inv[GATE_MAX];
	int		g_live[GATE_MAX];
};

static char gate_text[65536];

static int
gate_parse(struct gate *g, const char *text)
{
	const char *p;
	int idx, n;

	memset(g, 0, sizeof(*g));
	for (p = text; *p != '\0'; p = strchr(p, '\n') + 1) {
		if (sscanf(p, "%d", &idx) != 1 || idx < 0 || idx >= GATE_MAX)
			return (-1);
		n = sscanf(p, "%*d %39s auth %x notify %x alt %x invalidates %d "
		    "fp %39s live %d", g->g_name[idx], &g->g_auth[idx],
		    &g->g_notify[idx], &g->g_alt[idx], &g->g_inv[idx],
		    g->g_fp[idx], &g->g_live[idx]);
		if (n != 7)
			return (-1);
		if (idx + 1 > g->g_n)
			g->g_n = idx + 1;
		if (strchr(p, '\n') == NULL)
			break;
	}
	return (g->g_n > 0 ? 0 : -1);
}

/* Read the hook table.  No file operation: safe under a strict setting. */
static int
gate_fetch(char *buf, size_t len)
{
	size_t l;

	l = len - 1;
	if (sysctlbyname("security.oes.gate.hooks", buf, &l, NULL, 0) != 0)
		return (-1);
	buf[l] = '\0';
	return (0);
}

static int
gate_read(struct gate *g)
{

	if (gate_fetch(gate_text, sizeof(gate_text)) != 0) {
		TEST_FAIL("security.oes.gate.hooks: %s", strerror(errno));
		return (-1);
	}
	if (gate_parse(g, gate_text) != 0) {
		TEST_FAIL("malformed security.oes.gate.hooks");
		return (-1);
	}
	return (0);
}

static int
gate_find(const struct gate *g, const char *name)
{
	int h;

	for (h = 0; h < g->g_n; h++)
		if (strcmp(g->g_name[h], name) == 0)
			return (h);
	return (-1);
}

/* Print the live hooks; returns how many are live. */
static int
gate_live_list(const struct gate *g, char *out, size_t len)
{
	int h, n;

	n = 0;
	out[0] = '\0';
	for (h = 0; h < g->g_n; h++) {
		if (!g->g_live[h])
			continue;
		n++;
		strlcat(out, " ", len);
		strlcat(out, g->g_name[h], len);
	}
	return (n);
}

/* Exactly the hooks named (NULL-terminated) are live. */
static void
gate_expect(const char *what, const char * const *names)
{
	char live[4096];
	struct gate g;
	int h, i, n, want;

	if (gate_read(&g) != 0)
		return;
	n = gate_live_list(&g, live, sizeof(live));
	want = 0;
	for (i = 0; names[i] != NULL; i++) {
		h = gate_find(&g, names[i]);
		ASSERT_MSG(h >= 0, "%s: no hook %s", what, names[i]);
		if (h < 0)
			continue;
		ASSERT_MSG(g.g_live[h], "%s: %s not live (live:%s)", what,
		    names[i], live);
		want++;
	}
	ASSERT_MSG(n == want, "%s: %d hooks live, expected %d (live:%s)", what,
	    n, want, live);
}

static const char *none[] = { NULL };

#if OES_IDLE_LEVEL >= 3
/*
 * security.mac.fastpath: policy oes counts exactly the fast-path hooks of
 * the live hooks, and the flags are the OR of every policy's counted set.
 */
static char fp_text[65536];

static uint64_t
fp_policy_active(const char *text, const char *policy, int *found)
{
	char key[64];
	const char *p;
	unsigned long long a;

	snprintf(key, sizeof(key), "policy %s inactive ", policy);
	*found = 0;
	p = strstr(text, key);
	if (p == NULL)
		return (0);
	p = strstr(p, " active ");
	if (p == NULL || sscanf(p, " active %llx", &a) != 1)
		return (0);
	*found = 1;
	return (a);
}

static int
fp_hook_bit(const char *text, const char *hook)
{
	char name[64];
	const char *p;
	int bit, cnt;

	bit = 0;
	for (p = strstr(text, "hook "); p != NULL; p = strstr(p + 1, "\nhook ")) {
		if (*p == '\n')
			p++;
		if (sscanf(p, "hook %63s count %d", name, &cnt) == 2 &&
		    strcmp(name, hook) == 0)
			return (bit);
		bit++;
	}
	return (-1);
}

static void
fp_expect_oes(const char *what)
{
	struct gate g;
	uint64_t active, want;
	size_t l;
	int b, found, h;

	l = sizeof(fp_text) - 1;
	if (sysctlbyname("security.mac.fastpath", fp_text, &l, NULL, 0) != 0) {
		TEST_FAIL("%s: security.mac.fastpath: %s", what,
		    strerror(errno));
		return;
	}
	fp_text[l] = '\0';
	if (gate_read(&g) != 0)
		return;
	ASSERT_MSG(strstr(fp_text, "policy oes inactive 1 ") != NULL,
	    "%s: policy oes is not registered fast-path inactive", what);
	active = fp_policy_active(fp_text, "oes", &found);
	ASSERT_MSG(found, "%s: no policy oes in the snapshot", what);
	want = 0;
	for (h = 0; h < g.g_n; h++) {
		if (!g.g_live[h] || strcmp(g.g_fp[h], "-") == 0)
			continue;
		b = fp_hook_bit(fp_text, g.g_fp[h]);
		ASSERT_MSG(b >= 0, "%s: no fast-path hook %s", what, g.g_fp[h]);
		if (b >= 0)
			want |= 1ULL << b;
	}
	ASSERT_MSG(active == want, "%s: oes counts %#jx, its live hooks need "
	    "%#jx", what, (uintmax_t)active, (uintmax_t)want);
}

static int
fp_hook_count(const char *hook)
{
	char key[80];
	const char *p;
	size_t l;
	int cnt;

	l = sizeof(fp_text) - 1;
	if (sysctlbyname("security.mac.fastpath", fp_text, &l, NULL, 0) != 0)
		return (-1);
	fp_text[l] = '\0';
	snprintf(key, sizeof(key), "\nhook %s count ", hook);
	p = strstr(fp_text, key);
	if (p == NULL || sscanf(p + strlen(key), "%d", &cnt) != 1)
		return (-1);
	return (cnt);
}
#else
#define	fp_expect_oes(what)	do { } while (0)
#endif

#if OES_IDLE_LEVEL >= 2
static uint64_t
gate_passes(void)
{
	uint64_t v;
	size_t l;

	l = sizeof(v);
	if (sysctlbyname("security.oes.gate.passes", &v, &l, NULL, 0) != 0)
		return (UINT64_MAX);
	return (v);
}
#endif

static char work_file[PATH_MAX];
static ino_t work_ino;

static int
notify_client(oes_event_type_t *ev, size_t n, uint32_t queue)
{
	struct oes_mode_args ma;
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (-1);
	memset(&ma, 0, sizeof(ma));
	ma.ema_mode = OES_MODE_NOTIFY;
	ma.ema_queue_size = queue;
	if (ioctl(fd, OES_IOC_SET_MODE, &ma) != 0 ||
	    (n != 0 && test_subscribe(fd, ev, n, OES_SUB_REPLACE) != 0)) {
		(void)close(fd);
		return (-1);
	}
	return (fd);
}

static void
g1_g2_idle(void)
{
	int fd;

	TEST_BEGIN("G-1 no client: no hook is live");
	gate_expect("G-1", none);
	fp_expect_oes("G-1");

	TEST_BEGIN("G-2 a client with a mode and no subscription: still none");
	fd = notify_client(NULL, 0, 0);
	ASSERT_MSG(fd >= 0, "client: %s", strerror(errno));
	gate_expect("G-2", none);
	fp_expect_oes("G-2");
	if (fd >= 0)
		(void)close(fd);
}

static void
g3_g4_subscribe_unsubscribe_close(void)
{
	static const char *open_hook[] = { "VNODE_CHECK_OPEN", NULL };
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	struct idle_worker w;
	int fd;

	TEST_BEGIN("G-3 NOTIFY_OPEN makes exactly the open hook live");
	if (idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("worker: %s", strerror(errno));
		return;
	}
	fd = notify_client(&ev, 1, 0);
	ASSERT_MSG(fd >= 0, "client: %s", strerror(errno));
	if (fd < 0) {
		idle_worker_stop(&w);
		return;
	}
	gate_expect("G-3", open_hook);
	fp_expect_oes("G-3");
	(void)idle_worker_send(&w, IW_OPEN);
	ASSERT_MSG(idle_worker_result(&w, 5000) == 0, "worker open");
	ASSERT_MSG(idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000, NULL) ==
	    0, "open record not delivered");

	TEST_BEGIN("G-4 unsubscribe, then close: nothing live");
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_REMOVE) == 0,
	    "unsubscribe: %s", strerror(errno));
	gate_expect("G-4 unsubscribed", none);
	fp_expect_oes("G-4 unsubscribed");
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_ADD) == 0,
	    "resubscribe: %s", strerror(errno));
	gate_expect("G-4 resubscribed", open_hook);
	(void)close(fd);
	gate_expect("G-4 closed", none);
	fp_expect_oes("G-4 closed");
	idle_worker_stop(&w);
}

#if OES_IDLE_LEVEL >= 3
static void
g5_lookup_count(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_LOOKUP;
	int before, during, after, fd;

	TEST_BEGIN("G-5 NOTIFY_LOOKUP counts vnode_check_lookup, close uncounts");
	before = fp_hook_count("vnode_check_lookup");
	fd = notify_client(&ev, 1, 0);
	ASSERT_MSG(fd >= 0, "client: %s", strerror(errno));
	during = fp_hook_count("vnode_check_lookup");
	if (fd >= 0)
		(void)close(fd);
	after = fp_hook_count("vnode_check_lookup");
	ASSERT_MSG(before >= 0 && during == before + 1 && after == before,
	    "vnode_check_lookup count %d -> %d -> %d", before, during, after);
}
#endif

/* Read the table under a strict setting: no file operation in between. */
static void
g9_g10_strict(const char *knob, int on)
{
	static char text[65536];
	char live[4096], what[96];
	struct gate g;
	int h, n, off, set, rc, want;

	snprintf(what, sizeof(what), "%s=%d", knob, on);
	off = 0;
	set = on;
	if (sysctlbyname(knob, NULL, NULL, &set, sizeof(set)) != 0) {
		TEST_FAIL("set %s: %s", knob, strerror(errno));
		return;
	}
	rc = gate_fetch(text, sizeof(text));
	if (sysctlbyname(knob, NULL, NULL, &off, sizeof(off)) != 0)
		(void)sysctlbyname(knob, NULL, NULL, &off, sizeof(off));
	ASSERT_MSG(rc == 0, "%s: read the table", what);
	if (rc != 0 || gate_parse(&g, text) != 0)
		return;
	n = gate_live_list(&g, live, sizeof(live));
	want = 0;
	for (h = 0; h < g.g_n; h++) {
		if (g.g_auth[h] != 0)
			want++;
		ASSERT_MSG(g.g_live[h] == (g.g_auth[h] != 0),
		    "%s: %s live %d, produces AUTH %#x", what, g.g_name[h],
		    g.g_live[h], g.g_auth[h]);
	}
	ASSERT_MSG(n == want && want > 30, "%s: %d live of %d AUTH hooks", what,
	    n, want);
	gate_expect("after the strict setting", none);
	fp_expect_oes("after the strict setting");
}

static void
g11_cache_use(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	char live[4096];
	oes_cache_entry_t entry;
	struct idle_worker w;
	struct gate g;
	test_msg_buf buf;
	int fd, h, n, want;

	TEST_BEGIN("G-11 a client that used its cache: exactly the "
	    "invalidating hooks");
	fd = idle_scoped_client(OES_MODE_AUTH, 10000, &ev, 1);
	if (fd < 0 || idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("client or worker: %s", strerror(errno));
		if (fd >= 0)
			(void)close(fd);
		return;
	}
	(void)idle_worker_send(&w, IW_OPEN);
	if (idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000, &buf.msg) != 0) {
		TEST_FAIL("AUTH_OPEN not delivered");
		goto out;
	}
	(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_ALLOW);
	(void)idle_worker_result(&w, 5000);
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_REMOVE) == 0,
	    "unsubscribe: %s", strerror(errno));
	gate_expect("G-11 before the cache", none);
	memset(&entry, 0, sizeof(entry));
	entry.ece_key.eck_event = OES_EVENT_AUTH_OPEN;
	entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
	entry.ece_key.eck_op_flags = buf.msg.em_event_data.open.access;
	entry.ece_key.eck_process = buf.msg.em_process.ep_token;
	entry.ece_key.eck_exec_id = buf.msg.em_process.ep_exec_id;
	entry.ece_key.eck_file = buf.msg.em_event_data.open.file.ef_token;
	entry.ece_result = OES_AUTH_ALLOW;
	entry.ece_ttl_ms = 60000;
	ASSERT_MSG(ioctl(fd, OES_IOC_CACHE_ADD, &entry) == 0, "cache add: %s",
	    strerror(errno));
	if (gate_read(&g) == 0) {
		n = gate_live_list(&g, live, sizeof(live));
		want = 0;
		for (h = 0; h < g.g_n; h++) {
			if (g.g_inv[h])
				want++;
			ASSERT_MSG(g.g_live[h] == g.g_inv[h],
			    "G-11: %s live %d, invalidates %d", g.g_name[h],
			    g.g_live[h], g.g_inv[h]);
		}
		ASSERT_MSG(n == want && want > 10, "G-11: %d live, %d "
		    "invalidating", n, want);
	}
	fp_expect_oes("G-11");
out:
	idle_worker_stop(&w);
	(void)close(fd);
	gate_expect("G-11 closed", none);
	fp_expect_oes("G-11 closed");
}

static void
g12_two_clients(void)
{
	static const char *both[] = { "VNODE_CHECK_OPEN", "VNODE_CHECK_EXEC",
	    NULL };
	static const char *exec_only[] = { "VNODE_CHECK_EXEC", NULL };
	oes_event_type_t ev_open = OES_EVENT_NOTIFY_OPEN;
	oes_event_type_t ev_exec = OES_EVENT_NOTIFY_EXEC;
	int a, b;

	TEST_BEGIN("G-12 two clients: closing one keeps the other's hooks");
	a = notify_client(&ev_open, 1, 0);
	b = notify_client(&ev_exec, 1, 0);
	ASSERT_MSG(a >= 0 && b >= 0, "clients: %s", strerror(errno));
	gate_expect("G-12 both", both);
	fp_expect_oes("G-12 both");
	if (a >= 0)
		(void)close(a);
	gate_expect("G-12 one closed", exec_only);
	fp_expect_oes("G-12 one closed");
	if (b >= 0)
		(void)close(b);
	gate_expect("G-12 both closed", none);
}

static void
g13_replace(void)
{
	static const char *open_hook[] = { "VNODE_CHECK_OPEN", NULL };
	static const char *exec_only[] = { "VNODE_CHECK_EXEC", NULL };
	oes_event_type_t ev_open = OES_EVENT_NOTIFY_OPEN;
	oes_event_type_t ev_exec = OES_EVENT_NOTIFY_EXEC;
	int fd;

	TEST_BEGIN("G-13 OES_SUB_REPLACE moves liveness");
	fd = notify_client(&ev_open, 1, 0);
	ASSERT_MSG(fd >= 0, "client: %s", strerror(errno));
	if (fd < 0)
		return;
	gate_expect("G-13 open", open_hook);
	ASSERT_MSG(test_subscribe(fd, &ev_exec, 1, OES_SUB_REPLACE) == 0,
	    "replace: %s", strerror(errno));
	gate_expect("G-13 exec", exec_only);
	fp_expect_oes("G-13 exec");
	(void)close(fd);
	gate_expect("G-13 closed", none);
}

static void
g15_passive(void)
{
	static const char *open_hook[] = { "VNODE_CHECK_OPEN", NULL };
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct oes_mode_args ma;
	struct idle_worker w;
	int fd;

	TEST_BEGIN("G-15 a PASSIVE client of AUTH_OPEN makes the open hook "
	    "live and receives");
	if (idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("worker: %s", strerror(errno));
		return;
	}
	fd = test_open_oes();
	memset(&ma, 0, sizeof(ma));
	ma.ema_mode = OES_MODE_PASSIVE;
	ASSERT_MSG(fd >= 0 && ioctl(fd, OES_IOC_SET_MODE, &ma) == 0 &&
	    test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0, "client: %s",
	    strerror(errno));
	gate_expect("G-15", open_hook);
	(void)idle_worker_send(&w, IW_OPEN);
	ASSERT_MSG(idle_worker_result(&w, 5000) == 0, "worker open");
	ASSERT_MSG(idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000, NULL) ==
	    0, "passive open record not delivered");
	if (fd >= 0)
		(void)close(fd);
	idle_worker_stop(&w);
	gate_expect("G-15 closed", none);
}

/*
 * Hooks whose fast-path flag only OES can hold once mac_abac is idle: a
 * missing flag shows here as a missing record, not only in the tables.
 */
static void
g16_oes_only_flags(void)
{
	oes_event_type_t ev[] = { OES_EVENT_NOTIFY_CLOSE,
	    OES_EVENT_NOTIFY_PIPE_WRITE };
	struct timespec start;
	test_msg_buf buf;
	pid_t pid;
	int fd, p[2], status;
	bool got_close, got_pipe;
	char c;

	TEST_BEGIN("G-16 close and pipe-write records after SUBSCRIBE");
	fd = idle_scoped_client(OES_MODE_NOTIFY, 0, ev, nitems(ev));
	ASSERT_MSG(fd >= 0, "client: %s", strerror(errno));
	if (fd < 0)
		return;
	pid = fork();
	if (pid == 0) {
		int f;

		f = open(work_file, O_RDONLY);
		if (f >= 0)
			(void)close(f);
		if (pipe(p) != 0 || write(p[1], "x", 1) != 1 ||
		    read(p[0], &c, 1) != 1)
			_exit(1);
		_exit(0);
	}
	ASSERT_MSG(pid > 0 && waitpid(pid, &status, 0) == pid &&
	    WIFEXITED(status) && WEXITSTATUS(status) == 0, "child");
	got_close = got_pipe = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while ((!got_close || !got_pipe) && idle_elapsed_ms(&start) < 5000) {
		if (test_wait_event(fd, &buf.msg, 100) != 0 ||
		    buf.msg.em_process.ep_pid != pid)
			continue;
		if (buf.msg.em_event == OES_EVENT_NOTIFY_CLOSE)
			got_close = true;
		if (buf.msg.em_event == OES_EVENT_NOTIFY_PIPE_WRITE)
			got_pipe = true;
	}
	ASSERT_MSG(got_close, "no NOTIFY_CLOSE record");
	ASSERT_MSG(got_pipe, "no NOTIFY_PIPE_WRITE record");
	(void)close(fd);
}

#if OES_IDLE_LEVEL >= 3
/*
 * G-6: no record is lost once SUBSCRIBE has returned.  Workers open
 * numbered files in a loop; after the ioctl returns the main process
 * publishes a generation, and every open a worker starts after seeing it
 * must be delivered.
 */
#define	G6_WORKERS	4
#define	G6_OPENS	150

struct g6_shared {
	volatile int	gen;		/* 1 once SUBSCRIBE has returned */
	volatile int	go;
	int		seen[G6_WORKERS][G6_OPENS];
	ino_t		ino[G6_WORKERS][G6_OPENS];
};

static void
g6_no_record_lost(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	char path[PATH_MAX + 32];
	struct g6_shared *sh;
	struct timespec start;
	test_msg_buf buf;
	pid_t pids[G6_WORKERS];
	struct stat sb;
	bool *got;
	int fd, i, k, f, status, need, have, missing;

	TEST_BEGIN("G-6 every open after SUBSCRIBE returns is delivered");
	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_SHARED, -1, 0);
	got = calloc(G6_WORKERS * G6_OPENS, sizeof(*got));
	if (sh == MAP_FAILED || got == NULL) {
		TEST_FAIL("memory");
		return;
	}
	memset(sh, 0, sizeof(*sh));
	for (i = 0; i < G6_WORKERS; i++)
		for (k = 0; k < G6_OPENS; k++) {
			snprintf(path, sizeof(path), "%s.g6.%d.%d", work_file,
			    i, k);
			f = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
			if (f < 0 || fstat(f, &sb) != 0) {
				TEST_FAIL("create %s", path);
				return;
			}
			sh->ino[i][k] = sb.st_ino;
			(void)close(f);
		}
	/* Descendants scope: the workers only, so the queue holds them. */
	fd = test_open_oes();
	if (fd < 0 || test_set_descendants_scope(fd) != 0) {
		TEST_FAIL("client: %s", strerror(errno));
		return;
	}
	{
		struct oes_mode_args ma;

		memset(&ma, 0, sizeof(ma));
		ma.ema_mode = OES_MODE_NOTIFY;
		ma.ema_queue_size = 4096;
		ASSERT_MSG(ioctl(fd, OES_IOC_SET_MODE, &ma) == 0, "mode: %s",
		    strerror(errno));
	}
	for (i = 0; i < G6_WORKERS; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			(void)close(fd);
			while (!sh->go)
				;
			for (k = 0; k < G6_OPENS; k++) {
				sh->seen[i][k] = __atomic_load_n(&sh->gen,
				    __ATOMIC_ACQUIRE);
				snprintf(path, sizeof(path), "%s.g6.%d.%d",
				    work_file, i, k);
				f = open(path, O_RDONLY);
				if (f >= 0)
					(void)close(f);
			}
			_exit(0);
		}
	}
	sh->go = 1;
	idle_sleep_ms(5);
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0,
	    "subscribe: %s", strerror(errno));
	__atomic_store_n(&sh->gen, 1, __ATOMIC_RELEASE);
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < G6_WORKERS; i++)
		(void)waitpid(pids[i], &status, 0);
	while (test_wait_event(fd, &buf.msg, 300) == 0) {
		if (buf.msg.em_event != ev)
			continue;
		for (i = 0; i < G6_WORKERS; i++)
			for (k = 0; k < G6_OPENS; k++)
				if (sh->ino[i][k] ==
				    buf.msg.em_event_data.open.file.ef_token.eft_id)
					got[i * G6_OPENS + k] = true;
	}
	need = have = missing = 0;
	for (i = 0; i < G6_WORKERS; i++)
		for (k = 0; k < G6_OPENS; k++) {
			if (!sh->seen[i][k])
				continue;
			need++;
			if (got[i * G6_OPENS + k])
				have++;
			else if (missing++ < 5)
				printf("    missing: worker %d open %d\n", i, k);
		}
	printf("    %d opens after SUBSCRIBE returned, %d delivered\n", need,
	    have);
	ASSERT_MSG(need > 0, "no open started after SUBSCRIBE returned");
	ASSERT_MSG(have == need, "%d records lost", need - have);
	(void)close(fd);
	for (i = 0; i < G6_WORKERS; i++)
		for (k = 0; k < G6_OPENS; k++) {
			snprintf(path, sizeof(path), "%s.g6.%d.%d", work_file,
			    i, k);
			(void)unlink(path);
		}
	free(got);
	(void)munmap(sh, sizeof(*sh));
}

/* G-7: deny and allow alternate with subscribe and unsubscribe. */
static void
g7_auth_toggle(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct idle_worker w;
	struct timespec start;
	test_msg_buf buf;
	int fd, i, err, bad;
	long ms, worst;

	TEST_BEGIN("G-7 200 rounds: subscribe AUTH_OPEN deny, unsubscribe allow");
	fd = idle_scoped_client(OES_MODE_AUTH, 10000, NULL, 0);
	if (fd < 0 || idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("client or worker: %s", strerror(errno));
		if (fd >= 0)
			(void)close(fd);
		return;
	}
	bad = 0;
	worst = 0;
	for (i = 0; i < 200 && bad < 5; i++) {
		ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_ADD) == 0,
		    "subscribe: %s", strerror(errno));
		clock_gettime(CLOCK_MONOTONIC, &start);
		(void)idle_worker_send(&w, IW_OPEN);
		if (idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000,
		    &buf.msg) == 0)
			(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_DENY);
		err = idle_worker_result(&w, 5000);
		ms = idle_elapsed_ms(&start);
		worst = MAX(worst, ms);
		if (err != EACCES) {
			printf("    round %d: subscribed open returned %d\n", i,
			    err);
			bad++;
		}
		ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_REMOVE) == 0,
		    "unsubscribe: %s", strerror(errno));
		clock_gettime(CLOCK_MONOTONIC, &start);
		(void)idle_worker_send(&w, IW_OPEN);
		err = idle_worker_result(&w, 5000);
		ms = idle_elapsed_ms(&start);
		worst = MAX(worst, ms);
		if (err != 0) {
			printf("    round %d: unsubscribed open returned %d\n",
			    i, err);
			bad++;
		}
	}
	printf("    slowest open %ld ms\n", worst);
	ASSERT_MSG(bad == 0, "%d rounds went wrong", bad);
	ASSERT_MSG(worst <= 2000, "an open took %ld ms", worst);
	idle_worker_stop(&w);
	(void)close(fd);
}
#endif

#if OES_IDLE_LEVEL >= 2
/* G-8: after closing a silent AUTH client nothing runs a hook body. */
static void
g8_close_then_nothing_runs(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct idle_worker w[8];
	struct timespec start;
	test_msg_buf buf;
	uint64_t p0, p1;
	struct stat sb;
	pid_t pid;
	void *map;
	int fd, i, got, err, status, f;
	long ms;

	TEST_BEGIN("G-8 close a silent AUTH client: waiters return, then no "
	    "hook body runs");
	fd = idle_scoped_client(OES_MODE_AUTH, 30000, &ev, 1);
	if (fd < 0) {
		TEST_FAIL("client: %s", strerror(errno));
		return;
	}
	for (i = 0; i < 8; i++) {
		w[i].iw_pid = -1;
		if (idle_worker_start(&w[i], work_file) == 0)
			(void)idle_worker_send(&w[i], IW_OPEN);
	}
	got = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (got < 8 && idle_elapsed_ms(&start) < 10000)
		if (test_wait_event(fd, &buf.msg, 100) == 0 &&
		    buf.msg.em_event == ev)
			got++;
	ASSERT_MSG(got == 8, "%d of 8 opens reached the client", got);
	clock_gettime(CLOCK_MONOTONIC, &start);
	(void)close(fd);
	for (i = 0; i < 8; i++) {
		if (w[i].iw_pid <= 0)
			continue;
		err = idle_worker_result(&w[i], 5000);
		ms = idle_elapsed_ms(&start);
		ASSERT_MSG(err != -1 && ms <= 2000, "worker %d: %d after %ld ms",
		    i, err, ms);
		idle_worker_stop(&w[i]);
	}
	p0 = gate_passes();
	f = open(work_file, O_RDWR);
	if (f >= 0) {
		(void)write(f, "x", 1);
		(void)fstat(f, &sb);
		map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0);
		if (map != MAP_FAILED) {
			(void)mprotect(map, 4096, PROT_READ);
			(void)munmap(map, 4096);
		}
		(void)close(f);
	}
	(void)stat(work_file, &sb);
	pid = fork();
	if (pid == 0) {
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}
	if (pid > 0)
		(void)waitpid(pid, &status, 0);
	p1 = gate_passes();
	ASSERT_MSG(p0 != UINT64_MAX && p1 == p0, "gate passes %ju -> %ju after "
	    "the last client closed", (uintmax_t)p0, (uintmax_t)p1);
}

/* G-14: with nobody listening, fork, exit, mprotect and sysctl pass no gate. */
static void
g14_idle_paths(void)
{
	uint64_t p0, p1;
	size_t l;
	void *map;
	int f, i, v;

	TEST_BEGIN("G-14 idle: 1000 fork+exit, mprotect and sysctl pass no "
	    "gate");
	p0 = gate_passes();
	ASSERT_MSG(idle_fork_exit(1000) == 0, "fork loop");
	f = open(work_file, O_RDONLY);
	map = f >= 0 ? mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0) :
	    MAP_FAILED;
	for (i = 0; map != MAP_FAILED && i < 1000; i++)
		(void)mprotect(map, 4096, PROT_READ);
	if (map != MAP_FAILED)
		(void)munmap(map, 4096);
	if (f >= 0)
		(void)close(f);
	for (i = 0; i < 1000; i++) {
		l = sizeof(v);
		(void)sysctlbyname("kern.maxproc", &v, &l, NULL, 0);
	}
	p1 = gate_passes();
	ASSERT_MSG(p0 != UINT64_MAX && p1 == p0, "gate passes %ju -> %ju",
	    (uintmax_t)p0, (uintmax_t)p1);
}
#endif

int
main(void)
{
	struct stat sb;
	int fd;

	TEST_SUITE_BEGIN("OES idle gate");
	snprintf(work_file, sizeof(work_file), "./oes-idle-gate.%d",
	    (int)getpid());
	fd = open(work_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0 || ftruncate(fd, 4096) != 0 || fstat(fd, &sb) != 0) {
		TEST_FAIL("work file: %s", strerror(errno));
		return (1);
	}
	(void)close(fd);
	work_ino = sb.st_ino;
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		printf("    note: mlockall: %s\n", strerror(errno));

	g1_g2_idle();
	g3_g4_subscribe_unsubscribe_close();
#if OES_IDLE_LEVEL >= 3
	g5_lookup_count();
	g6_no_record_lost();
	g7_auth_toggle();
#endif
#if OES_IDLE_LEVEL >= 2
	g8_close_then_nothing_runs();
#endif
	TEST_BEGIN("G-9 require_auth_clients: every AUTH hook, nothing else");
	g9_g10_strict("security.oes.require_auth_clients", 1);
	TEST_BEGIN("G-10 auth_fail_closed: the same");
	g9_g10_strict("security.oes.auth_fail_closed", 1);
	TEST_BEGIN("G-10 deadline-miss fail closed: the same");
	g9_g10_strict("security.oes.default_deadline_miss_mode",
	    OES_DEADLINE_MISS_FAIL_CLOSED);
	g11_cache_use();
	g12_two_clients();
	g13_replace();
#if OES_IDLE_LEVEL >= 2
	g14_idle_paths();
#endif
	g15_passive();
	g16_oes_only_flags();

	(void)unlink(work_file);
	TEST_SUITE_END("OES idle gate");
	return (0);
}

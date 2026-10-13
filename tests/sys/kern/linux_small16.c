/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux proc/sysfs ABI regressions. Run only in disposable amd64 guests. */
#include "linux_test.h"

static const char *self;
static char status[8192];
#define CHECK(c)                                         \
	do {                                             \
		if (!(c)) {                              \
			msgnum("check line ", __LINE__); \
			return (1);                      \
		}                                        \
	} while (0)
static long
rd(const char *p, char *b, long n)
{
	long fd = sys3(SYS_open, p, 0, 0), r;
	if (fd < 0)
		return fd;
	r = sys3(SYS_read, fd, b, n - 1);
	sys1(SYS_close, fd);
	if (r >= 0)
		b[r] = 0;
	return r;
}
static long
wr(const char *p, const char *b)
{
	long fd = sys3(SYS_open, p, 1, 0), r;
	if (fd < 0)
		return fd;
	r = sys3(SYS_write, fd, b, xstrlen(b));
	sys1(SYS_close, fd);
	return r;
}
static unsigned long
number(const char *p, unsigned base)
{
	unsigned long v = 0;
	unsigned d;
	while (*p == ' ' || *p == '\t')
		p++;
	while (*p) {
		d = *p >= '0' && *p <= '9' ? *p - '0' :
		    *p >= 'a' && *p <= 'f' ? *p - 'a' + 10 :
					     99;
		if (d >= base)
			break;
		v = v * base + d;
		p++;
	}
	return v;
}
static long
readnum(const char *p)
{
	char b[128];
	long n = rd(p, b, sizeof(b));
	if (n < 0)
		return n;
	return b[0] == '-' ? -(long)number(b + 1, 10) : (long)number(b, 10);
}
static const char *
field(const char *key)
{
	const char *p = status;
	unsigned n = xstrlen(key);
	while (*p) {
		unsigned i = 0;
		while (i < n && p[i] == key[i])
			i++;
		if (i == n && p[i] == ':') {
			p += i + 1;
			while (*p == ' ' || *p == '\t')
				p++;
			return p;
		}
		while (*p && *p != '\n')
			p++;
		if (*p)
			p++;
	}
	return 0;
}
static int
st(const char *path)
{
	return rd(path, status, sizeof(status)) > 0 ? 0 : 1;
}
static long
val(const char *key, unsigned base)
{
	const char *p = field(key);
	return p ? (long)number(p, base) : -1;
}
static void
pathnum(char *dst, const char *prefix, unsigned long n, const char *suffix)
{
	char b[32];
	int k = 0, i = 0;
	while (*prefix)
		dst[i++] = *prefix++;
	do {
		b[k++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (k)
		dst[i++] = b[--k];
	while (*suffix)
		dst[i++] = *suffix++;
	dst[i] = 0;
}
static int
join(struct thread *t)
{
	while (__atomic_load_n(&t->tid, __ATOMIC_ACQUIRE))
		sleep_ms(1);
	return sys2(SYS_munmap, t->stack, t->stack_size) != 0;
}
static long
pr(long op, long n)
{
	return sys5(SYS_prctl, op, n, 0, 0, 0);
}
static int
slack_file(void)
{
	unsigned long old = pr(30, 0);
	char b[64];
	CHECK(pr(29, 123456) == 0);
	CHECK(readnum("/proc/self/timerslack_ns") == 123456);
	CHECK(wr("/proc/self/timerslack_ns", "+654321\n") == 8);
	CHECK(pr(30, 0) == 654321);
	CHECK(wr("/proc/self/timerslack_ns", "0") == 1 &&
	    (unsigned long)pr(30, 0) == old);
	CHECK(wr("/proc/self/timerslack_ns", "18446744073709551615") == 20);
	CHECK(rd("/proc/self/timerslack_ns", b, sizeof(b)) == 21 &&
	    xstreq(b, "18446744073709551615\n"));
	const char *bad[] = { "", "-1", " 1", "1 ", "1x", "1\n\n" };
	for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		/* write(fd,"",0) is a VFS no-op on 5BSD; test nonempty parse
		 * errors. */
		if (i)
			CHECK(
			    wr("/proc/self/timerslack_ns", bad[i]) == -EINVAL);
	}
	CHECK(wr("/proc/self/timerslack_ns", "18446744073709551616") == -34);
	CHECK((unsigned long)pr(30, 0) == ~0UL);
	CHECK(pr(29, old) == 0);
	return 0;
}
static int
slack_worker(void *arg)
{
	int rc = 0;
	char path[128];
#ifdef LINUX_REFERENCE
	pathnum(path, "/proc/", sys0(SYS_gettid), "/timerslack_ns");
#else
	pathnum(path, "/proc/self/task/", sys0(SYS_gettid), "/timerslack_ns");
#endif
	if (readnum(path) != 123456 || wr(path, "654321") != 6 ||
	    pr(30, 0) != 654321 || readnum(path) != 654321)
		rc = 1;
	__atomic_store_n((int *)arg, rc, __ATOMIC_RELEASE);
	return 0;
}
static int
slack_thread(void)
{
	struct thread t;
	int rc = -1;
	CHECK(pr(29, 123456) == 0);
	CHECK(thread_create(&t, slack_worker, &rc) == 0);
	CHECK(join(&t) == 0);
	CHECK(rc == 0 && pr(30, 0) == 123456);
	CHECK(pr(29, 0) == 0);
	return 0;
}
static int
unpriv_slack(void *arg)
{
	char path[128];
	pathnum(path, "/proc/", (unsigned long)arg, "/timerslack_ns");
	CHECK(sys1(106, 60001) == 0 && sys1(105, 60001) == 0);
	CHECK(wr("/proc/self/timerslack_ns", "99") == 2 &&
	    readnum("/proc/self/timerslack_ns") == 99);
	CHECK(readnum(path) == -EPERM);
	CHECK(wr(path, "88") == -EPERM);
	return 0;
}
static int
slack_permissions(void)
{
	return run_child(unpriv_slack, (void *)sys0(SYS_getpid));
}
static int
slack_rt(void)
{
	int priority = 1;
	CHECK(sys3(144, 0, 1, &priority) == 0);
	long w = wr("/proc/self/timerslack_ns", "123456"),
	     v = readnum("/proc/self/timerslack_ns");
	priority = 0;
	CHECK(sys3(144, 0, 0, &priority) == 0);
	CHECK(w == 6 && v == 0);
	return 0;
}
static int
oom_worker(void *arg)
{
	int rc = 0;
	char path[128];
	pathnum(path, "/proc/self/task/", sys0(SYS_gettid), "/oom_score_adj");
	if (readnum(path) != 500 || readnum("/proc/thread-self/oom_adj") != 8 ||
	    wr(path, "600") != 3)
		rc = 1;
	__atomic_store_n((int *)arg, rc, __ATOMIC_RELEASE);
	return 0;
}
static int
oom_views(void)
{
	struct thread t;
	int rc = -1;
	CHECK(wr("/proc/self/oom_score_adj", "500") == 3);
	CHECK(readnum("/proc/self/oom_adj") == 8);
	CHECK(thread_create(&t, oom_worker, &rc) == 0);
	CHECK(join(&t) == 0);
	CHECK(rc == 0);
	CHECK(readnum("/proc/self/oom_score_adj") == 600);
	CHECK(wr("/proc/thread-self/oom_adj", "15") == 2 &&
	    readnum("/proc/self/oom_score_adj") == 1000);
	CHECK(wr("/proc/self/oom_adj", "-17") == 3 &&
	    readnum("/proc/self/oom_score_adj") == -1000);
	CHECK(wr("/proc/self/oom_adj", "-16") == 3 &&
	    readnum("/proc/self/oom_score_adj") == -941);
	CHECK(wr("/proc/self/oom_score_adj", "0") == 1);
	return 0;
}
static int
oom_parse(void)
{
	const char *bad[] = { "x", "1x", "+", "-", "1001", "-1001", "1 2",
		"08" };
	CHECK(wr("/proc/self/oom_score_adj", "0") == 1);
	for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		CHECK(wr("/proc/self/oom_score_adj", bad[i]) == -EINVAL);
		CHECK(readnum("/proc/self/oom_score_adj") == 0);
	}
	CHECK(wr("/proc/self/oom_score_adj", "2147483648") == -34);
	CHECK(wr("/proc/self/oom_score_adj", " \t+0x64\n") == 8 &&
	    readnum("/proc/self/oom_score_adj") == 100);
	CHECK(wr("/proc/self/oom_score_adj", "010") == 3 &&
	    readnum("/proc/self/oom_score_adj") == 8);
	CHECK(wr("/proc/self/oom_adj", "16") == -EINVAL);
	CHECK(wr("/proc/self/oom_adj", "-18") == -EINVAL);
	CHECK(wr("/proc/self/oom_score_adj", "0") == 1);
	return 0;
}
static int
unpriv_oom(void *unused __attribute__((unused)))
{
	long fd = sys3(SYS_open, "/proc/self/oom_score_adj", 1, 0);
	CHECK(fd >= 0);
	CHECK(sys1(106, 60001) == 0 && sys1(105, 60001) == 0);
	CHECK(pr(4, 1) == 0);
	/* An fd opened while privileged cannot lower the inherited floor. */
	CHECK(sys3(SYS_write, fd, "99", 2) == -EACCES);
	CHECK(wr("/proc/self/oom_score_adj", "200") == 3);
	CHECK(wr("/proc/self/oom_score_adj", "100") == 3);
	CHECK(wr("/proc/self/oom_adj", "0") == -EACCES);
	CHECK(readnum("/proc/self/oom_score_adj") == 100);
	sys1(SYS_close, fd);
	return 0;
}
static int
oom_permissions(void)
{
	CHECK(wr("/proc/self/oom_score_adj", "100") == 3);
	int rc = run_child(unpriv_oom, 0);
	CHECK(wr("/proc/self/oom_score_adj", "0") == 1);
	return rc;
}
static int
exec_oom(void *unused __attribute__((unused)))
{
	CHECK(readnum("/proc/self/oom_score_adj") == 321);
	char *av[] = { (char *)self, "exec_oom", 0 };
	char *ev[] = { 0 };
	sys3(SYS_execve, self, av, ev);
	return 2;
}
static int
oom_lifecycle(void)
{
	CHECK(wr("/proc/self/oom_score_adj", "321") == 3);
	int rc = run_child(exec_oom, 0);
	CHECK(wr("/proc/self/oom_score_adj", "0") == 1);
	return rc;
}
static int
status_umask(void)
{
	long old = sys1(SYS_umask, 027);
	CHECK(st("/proc/self/status") == 0 && val("Umask", 8) == 027);
	CHECK(st("/proc/thread-self/status") == 0 && val("Umask", 8) == 027);
	sys1(SYS_umask, old);
	return 0;
}
static int
status_nnp(void)
{
	CHECK(
	    st("/proc/self/status") == 0 && val("NoNewPrivs", 10) == pr(39, 0));
	CHECK(pr(38, 1) == 0);
	CHECK(
	    st("/proc/thread-self/status") == 0 && val("NoNewPrivs", 10) == 1);
	return 0;
}
struct affinity_check {
	int cpu, leader, result;
};

static int
affinity_worker(void *arg)
{
	struct affinity_check *check = arg;
	unsigned long one[16] = { 0 };
	int rc = 0;

	one[check->cpu / 64] = 1UL << (check->cpu % 64);
	if (sys3(203, 0, sizeof(one), one) != 0 ||
	    st("/proc/thread-self/status") != 0 ||
	    val("Cpus_allowed_list", 10) != check->cpu ||
	    st("/proc/self/status") != 0 ||
	    val("Cpus_allowed_list", 10) != check->leader)
		rc = 1;
	__atomic_store_n(&check->result, rc, __ATOMIC_RELEASE);
	return 0;
}

static int
status_affinity(void)
{
	unsigned long mask[16] = { 0 }, one[16] = { 0 };
	int cpu = -1;
	CHECK(sys3(204, 0, sizeof(mask), mask) > 0);
	for (int i = 0; i < 1024; i++)
		if (mask[i / 64] & (1UL << (i % 64))) {
			cpu = i;
			break;
		}
	CHECK(cpu >= 0);
	one[cpu / 64] = 1UL << (cpu % 64);
	CHECK(sys3(203, 0, sizeof(one), one) == 0);
	CHECK(st("/proc/thread-self/status") == 0);
	const char *p = field("Cpus_allowed_list");
	CHECK(p && number(p, 10) == (unsigned)cpu);
	while (*p >= '0' && *p <= '9')
		p++;
	CHECK(*p == '\n');
	p = field("Cpus_allowed");
	CHECK(p != 0);
	unsigned long v = 0;
	while (*p && *p != '\n') {
		if (*p != ',') {
			unsigned d = *p <= '9' ? *p - '0' : *p - 'a' + 10;
			v = (v << 4) | d;
		}
		p++;
	}
	CHECK(cpu < 64 && v == (1UL << cpu));
	/* A worker's status must follow its own mask, not the leader's. */
	struct affinity_check check = { cpu, cpu, -1 };
	for (int i = cpu + 1; i < 1024; i++)
		if (mask[i / 64] & (1UL << (i % 64))) {
			check.cpu = i;
			break;
		}
	struct thread worker;
	CHECK(thread_create(&worker, affinity_worker, &check) == 0);
	CHECK(join(&worker) == 0 && check.result == 0);
	CHECK(sys3(203, 0, sizeof(mask), mask) == 0);
	return 0;
}
static int
status_fdsize(void)
{
	CHECK(st("/proc/self/status") == 0);
	long before = val("FDSize", 10);
	long fd = sys3(SYS_open, "/proc/self/status", 0, 0);
	CHECK(fd >= 0);
	CHECK(sys3(SYS_fcntl, fd, 0, 512) >= 512);
	CHECK(st("/proc/self/status") == 0 && val("FDSize", 10) > 512 &&
	    val("FDSize", 10) >= before);
	sys1(SYS_close, fd);
	return 0;
}
static int
status_switches(void)
{
	CHECK(st("/proc/thread-self/status") == 0);
	long a = val("voluntary_ctxt_switches", 10),
	     b = val("nonvoluntary_ctxt_switches", 10);
	CHECK(a >= 0 && b >= 0);
	for (int i = 0; i < 8; i++)
		sleep_ms(2);
	CHECK(st("/proc/thread-self/status") == 0 &&
	    val("voluntary_ctxt_switches", 10) > a &&
	    val("nonvoluntary_ctxt_switches", 10) >= b);
	return 0;
}
static int
status_hwm(void)
{
	CHECK(st("/proc/self/status") == 0);
	long old = val("VmHWM", 10);
	CHECK(old >= 0);
	long mem = sys6(SYS_mmap, 0, 16 * 1024 * 1024, 3, 0x22, -1, 0);
	CHECK(mem > 0);
	for (long i = 0; i < 16 * 1024 * 1024; i += 4096)
		((volatile char *)mem)[i] = 1;
	/* Native rusage is sampled by statclock: keep the allocation resident
	 * and the thread running until that accounting observes it. */
	struct timespec start, now;
	long usage[18];
	CHECK(sys2(SYS_clock_gettime, 1, &start) == 0);
	for (;;) {
		CHECK(sys2(98 /* getrusage */, 0, usage) == 0);
		if (usage[4] >= 16 * 1024)
			break;
		CHECK(sys2(SYS_clock_gettime, 1, &now) == 0);
		CHECK(now.tv_sec - start.tv_sec < 3);
	}
	CHECK(st("/proc/self/status") == 0);
	long high = val("VmHWM", 10);
	CHECK(high >= old && high >= val("VmRSS", 10));
	CHECK(sys2(SYS_munmap, mem, 16 * 1024 * 1024) == 0);
	CHECK(st("/proc/self/status") == 0);
	/* Linux RSS batching can make a sampled peak fall by a few pages. */
	CHECK(val("VmHWM", 10) >= 16 * 1024 && val("VmHWM", 10) >= old);
	return 0;
}
static int
status_caps(void)
{
	unsigned long bound = 0, ambient = 0;
	for (int i = 0; i < 64; i++) {
		long b = pr(23, i);
		if (b == -EINVAL)
			break;
		CHECK(b == 0 || b == 1);
		bound |= (unsigned long)b << i;
		long a = sys5(SYS_prctl, 47, 1, i, 0, 0);
		CHECK(a == 0 || a == 1);
		ambient |= (unsigned long)a << i;
	}
	CHECK(st("/proc/self/status") == 0 &&
	    (unsigned long)val("CapBnd", 16) == bound &&
	    (unsigned long)val("CapAmb", 16) == ambient);
	return 0;
}
static int
thp_worker(void *arg)
{
	int rc = pr(42, 0) != 1 || pr(41, 0) != 0;
	__atomic_store_n((int *)arg, rc, __ATOMIC_RELEASE);
	return 0;
}

static int
thp_state(void)
{
	long old = pr(42, 0);
	for (int i = 0; i < 3; i++) {
		CHECK(pr(41, i) == 0 && pr(42, 0) == (i != 0));
		CHECK(st("/proc/self/status") == 0 &&
		    val("THP_enabled", 10) == (i == 0));
	}
	CHECK(sys5(SYS_prctl, 41, 0, 0, 1, 0) == -EINVAL && pr(42, 0) == 1);
	CHECK(sys5(SYS_prctl, 42, 1, 0, 0, 0) == -EINVAL);
	struct thread worker;
	int result = -1;
	CHECK(thread_create(&worker, thp_worker, &result) == 0);
	CHECK(join(&worker) == 0 && result == 0 && pr(42, 0) == 0);
	CHECK(pr(41, old) == 0);
	return 0;
}
static int
exec_thp(void *unused __attribute__((unused)))
{
	CHECK(pr(42, 0) == 1);
	char *av[] = { (char *)self, "exec_thp", 0 };
	char *ev[] = { 0 };
	sys3(SYS_execve, self, av, ev);
	return 2;
}
static int
thp_lifecycle(void)
{
	CHECK(pr(41, 1) == 0);
	int rc = run_child(exec_thp, 0);
	CHECK(pr(41, 0) == 0);
	return rc;
}
static long
statfield(const char *path, int wanted)
{
	char b[4096];
	CHECK(rd(path, b, sizeof(b)) > 0);
	char *p = b, *end = 0;
	while (*p) {
		if (*p == ')')
			end = p;
		p++;
	}
	CHECK(end != 0);
	p = end + 2;
	for (int i = 3; i < wanted; i++) {
		while (*p && *p != ' ')
			p++;
		while (*p == ' ')
			p++;
	}
	return *p == '-' ? -(long)number(p + 1, 10) : (long)number(p, 10);
}
static int
stat_rsslim(void)
{
	unsigned long old[2], lim[2];
	CHECK(sys2(SYS_getrlimit, 5, old) == 0);
	lim[0] = 123456789;
	lim[1] = old[1];
	CHECK(sys2(SYS_setrlimit, 5, lim) == 0);
	CHECK(statfield("/proc/self/stat", 25) == (long)lim[0]);
	CHECK(statfield("/proc/thread-self/stat", 25) == (long)lim[0]);
	CHECK(sys2(SYS_setrlimit, 5, old) == 0);
	return 0;
}
static int
exit_worker(void *arg)
{
	__atomic_store_n((int *)arg,
	    statfield("/proc/thread-self/stat", 38) == -1 ? 0 : 1,
	    __ATOMIC_RELEASE);
	return 0;
}
static int
stat_exitsignal(void)
{
	struct thread t;
	int rc = -1;
	CHECK(statfield("/proc/self/stat", 38) == 17);
	CHECK(thread_create(&t, exit_worker, &rc) == 0);
	CHECK(join(&t) == 0);
	CHECK(rc == 0);
	ignore_signal(10);
	long pid = sys5(SYS_clone, 10, 0, 0, 0, 0);
	CHECK(pid >= 0);
	if (!pid) {
		int x = statfield("/proc/self/stat", 38) != 10;
		sys1(SYS_exit_group, x);
		__builtin_unreachable();
	}
	ignore_signal(10);
	int code;
	CHECK(sys4(SYS_wait4, pid, &code, 0x80000000U, 0) == pid && code == 0);
	return 0;
}
static unsigned long
listmask(const char *p)
{
	unsigned long mask = 0;
	while (*p && *p != '\n') {
		unsigned a = number(p, 10);
		while (*p >= '0' && *p <= '9')
			p++;
		unsigned b = a;
		if (*p == '-') {
			p++;
			b = number(p, 10);
			while (*p >= '0' && *p <= '9')
				p++;
		}
		if (a > b || b >= 64)
			return ~0UL;
		for (unsigned i = a; i <= b; i++)
			mask |= 1UL << i;
		if (*p == ',')
			p++;
		else if (*p != '\n' && *p)
			return ~0UL;
	}
	return mask;
}
static int
cpu_discovery(void)
{
	char b[512];
	unsigned long present, online, offline;
	CHECK(rd("/sys/devices/system/cpu/present", b, sizeof(b)) > 0);
	present = listmask(b);
	CHECK(rd("/sys/devices/system/cpu/online", b, sizeof(b)) > 0);
	online = listmask(b);
	CHECK(rd("/sys/devices/system/cpu/offline", b, sizeof(b)) >= 0);
	offline = listmask(b);
	CHECK((online & offline) == 0 && (online | offline) == present);
	long max = readnum("/sys/devices/system/cpu/kernel_max");
	CHECK(max >= 0);
	for (int i = 0; i < 64; i++)
		if (present & (1UL << i))
			CHECK(max >= i);
	return 0;
}
#define CASE(n) { #n, n }
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	self = argv[0];
	if (argc == 2 && xstreq(argv[1], "exec_oom"))
		return readnum("/proc/self/oom_score_adj") != 321;
	if (argc == 2 && xstreq(argv[1], "exec_thp"))
		return pr(42, 0) != 1;
	static const struct subtest cases[] = { CASE(slack_file),
		CASE(slack_thread), CASE(slack_permissions), CASE(slack_rt),
		CASE(oom_views), CASE(oom_parse), CASE(oom_permissions),
		CASE(oom_lifecycle), CASE(status_umask), CASE(status_nnp),
		CASE(status_affinity), CASE(status_fdsize),
		CASE(status_switches), CASE(status_hwm), CASE(status_caps),
		CASE(thp_state), CASE(thp_lifecycle), CASE(stat_rsslim),
		CASE(stat_exitsignal), CASE(cpu_discovery) };
	return run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0]));
}

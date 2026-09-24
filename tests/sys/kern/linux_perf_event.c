/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux perf_event_open software-counting contract. */
#include "linux_test.h"

#if !defined(__x86_64__)
#error "perf_event test currently qualifies Linux64 amd64"
#endif

#define SYS_perf_event_open 298
#define PERF_TYPE_SOFTWARE 1
#define PERF_COUNT_SW_CPU_CLOCK 0
#define PERF_COUNT_SW_TASK_CLOCK 1
#define PERF_COUNT_SW_PAGE_FAULTS 2
#define PERF_COUNT_SW_CONTEXT_SWITCHES 3
#define PERF_COUNT_SW_CPU_MIGRATIONS 4
#define PERF_COUNT_SW_PAGE_FAULTS_MIN 5
#define PERF_COUNT_SW_PAGE_FAULTS_MAJ 6
#define PERF_COUNT_SW_DUMMY 9
#define PERF_FORMAT_TOTAL_TIME_ENABLED (1ULL << 0)
#define PERF_FORMAT_TOTAL_TIME_RUNNING (1ULL << 1)
#define PERF_FORMAT_ID (1ULL << 2)
#define PERF_FORMAT_GROUP (1ULL << 3)
#define PERF_FORMAT_LOST (1ULL << 4)
#define PERF_ATTR_DISABLED (1ULL << 0)
#define PERF_ATTR_INHERIT (1ULL << 1)
#define PERF_FLAG_FD_NO_GROUP 1
#define PERF_FLAG_FD_OUTPUT 2
#define PERF_FLAG_PID_CGROUP 4
#define PERF_FLAG_FD_CLOEXEC 8
#define PERF_EVENT_IOC_ENABLE 0x2400
#define PERF_EVENT_IOC_DISABLE 0x2401
#define PERF_EVENT_IOC_RESET 0x2403
#define PERF_EVENT_IOC_ID 0x80082407U
#define PERF_EVENT_IOC_PERIOD 0x40082404U
#define PERF_IOC_FLAG_GROUP 1
#define F_GETFD 1
#define FD_CLOEXEC 1
#define POLLIN 1

struct perf_attr {
	u32 type, size;
	u64 config, sample_period, sample_type, read_format, bits;
	u32 wakeup_events, bp_type;
	u64 config1, config2, branch_sample_type, sample_regs_user;
	u32 sample_stack_user;
	int clockid;
	u64 sample_regs_intr;
	u32 aux_watermark;
	u16 sample_max_stack, reserved2;
	u32 aux_sample_size, aux_action;
	u64 sig_data, config3, config4;
};
struct pollfd { int fd; short events, revents; };
_Static_assert(sizeof(struct perf_attr) == 144, "perf attr ABI");

static long
perf_open(struct perf_attr *a, long pid, long cpu, long group, u64 flags)
{
	return (sys5(SYS_perf_event_open, a, pid, cpu, group, flags));
}

static void
attr_init(struct perf_attr *a, u64 config)
{
	xmemset(a, 0, sizeof(*a));
	a->type = PERF_TYPE_SOFTWARE;
	a->size = 64;
	a->config = config;
}

static void
burn(unsigned long n)
{
	volatile unsigned long x = 1;
	while (n-- != 0)
		x = x * 1103515245 + 12345;
	if (x == 0xfeedface)
		msg("impossible\n");
}

static int
basic_task_clock(void)
{
	struct perf_attr a;
	u64 before, after;
	long fd;

	attr_init(&a, PERF_COUNT_SW_TASK_CLOCK);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	if (sys3(SYS_read, fd, &before, sizeof(before)) != sizeof(before))
		return (2);
	burn(4000000);
	if (sys3(SYS_read, fd, &after, sizeof(after)) != sizeof(after) ||
	    after <= before || after - before < 1000)
		return (3);
	if (sys1(SYS_close, fd) != 0)
		return (4);
	return (0);
}

static int
disabled_transitions(void)
{
	struct perf_attr a;
	u64 v0, v1, v2, v3, v4;
	long fd;

	attr_init(&a, PERF_COUNT_SW_TASK_CLOCK);
	a.bits = PERF_ATTR_DISABLED;
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	burn(1000000);
	if (sys3(SYS_read, fd, &v0, 8) != 8 || v0 != 0)
		return (2);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
		return (3);
	burn(3000000);
	if (sys3(SYS_read, fd, &v1, 8) != 8 || v1 == 0)
		return (4);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_DISABLE, 0) != 0 ||
	    sys3(SYS_read, fd, &v2, 8) != 8 || v2 < v1)
		return (5);
	burn(2000000);
	if (sys3(SYS_read, fd, &v3, 8) != 8 || v3 != v2)
		return (6);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_RESET, 0) != 0 ||
	    sys3(SYS_read, fd, &v4, 8) != 8 || v4 != 0)
		return (7);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0 ||
	    sys3(SYS_ioctl, fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0)
		return (8);
	sys1(SYS_close, fd);
	return (0);
}

static int
read_formats(void)
{
	struct perf_attr a;
	u64 v[5] = {~0ULL, ~0ULL, ~0ULL, ~0ULL, 0x1234}, id;
	long fd;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
	    PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	burn(1000000);
	if (sys3(SYS_read, fd, v, 40) != 32 || v[0] != 0 || v[1] == 0 ||
	    v[2] != v[1] || v[3] == 0 || v[4] != 0x1234)
		return (2);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ID, &id) != 0 || id != v[3])
		return (3);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ID, (void *)1) != -EFAULT)
		return (4);
	if (sys3(SYS_read, fd, v, 31) != -ENOSPC)
		return (5);
	sys1(SYS_close, fd);
	return (0);
}

static long
read_counter(u64 config, void (*work)(void))
{
	struct perf_attr a;
	u64 before, after;
	long fd;

	attr_init(&a, config);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (fd);
	if (sys3(SYS_read, fd, &before, 8) != 8) {
		sys1(SYS_close, fd);
		return (-1000);
	}
	work();
	if (sys3(SYS_read, fd, &after, 8) != 8) {
		sys1(SYS_close, fd);
		return (-1001);
	}
	sys1(SYS_close, fd);
	return ((long)(after - before));
}

static void
fault_work(void)
{
	char *p;
	long r;

	r = sys6(SYS_mmap, 0, 128 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0)
		return;
	p = (char *)r;
	for (int i = 0; i < 128; i++)
		p[i * PAGE] = (char)i;
	(void)sys2(SYS_munmap, p, 128 * PAGE);
}

static void
switch_work(void)
{
	for (int i = 0; i < 8; i++)
		sleep_ms(1);
}

static void
no_work(void)
{
	burn(10000);
}

static int
software_counters(void)
{
	long all, min, maj, csw, dummy;

	all = read_counter(PERF_COUNT_SW_PAGE_FAULTS, fault_work);
	min = read_counter(PERF_COUNT_SW_PAGE_FAULTS_MIN, fault_work);
	maj = read_counter(PERF_COUNT_SW_PAGE_FAULTS_MAJ, no_work);
	csw = read_counter(PERF_COUNT_SW_CONTEXT_SWITCHES, switch_work);
	dummy = read_counter(PERF_COUNT_SW_DUMMY, no_work);
	if (all <= 0 || min <= 0 || maj < 0 || csw <= 0 || dummy != 0)
		return (1);
	return (0);
}

static int
attribute_sizes(void)
{
	struct {
		struct perf_attr attr;
		u64 tail;
	} extended;
	struct perf_attr a;
	long fd;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.size = 0;
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0 || a.size != 0)
		return (1);
	sys1(SYS_close, fd);
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.size = 63;
	if (perf_open(&a, 0, -1, -1, 0) != -E2BIG || a.size != 144)
		return (2);
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.size = sizeof(a);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (3);
	sys1(SYS_close, fd);
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.size = sizeof(a);
	a.config4 = 1;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (4);
	if (perf_open((void *)1, 0, -1, -1, 0) != -EFAULT)
		return (5);
	xmemset(&extended, 0, sizeof(extended));
	attr_init(&extended.attr, PERF_COUNT_SW_DUMMY);
	extended.attr.size = sizeof(extended);
	fd = perf_open(&extended.attr, 0, -1, -1, 0);
	if (fd < 0)
		return (6);
	sys1(SYS_close, fd);
	extended.tail = 1;
	if (perf_open(&extended.attr, 0, -1, -1, 0) != -E2BIG)
		return (7);
	extended.attr.size = PAGE + 1;
	if (perf_open(&extended.attr, 0, -1, -1, 0) != -E2BIG)
		return (8);
	return (0);
}

static int
attribute_options(void)
{
	struct perf_attr a;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.sample_period = 1;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (1);
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.read_format = PERF_FORMAT_GROUP;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (2);
	a.read_format = PERF_FORMAT_LOST;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (3);
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a.bits = PERF_ATTR_INHERIT;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (4);
	a.bits = 1ULL << 63;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (5);
	a.bits = 0;
	a.size = sizeof(a);
	a.reserved2 = 1;
	if (perf_open(&a, 0, -1, -1, 0) != -EOPNOTSUPP)
		return (6);
	return (0);
}

static int
target_and_flags(void)
{
	struct perf_attr a;
	long fd, regular;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	if (perf_open(&a, 0, -1, -1, 1ULL << 63) != -EINVAL ||
	    perf_open(&a, 0, -1, -1, PERF_FLAG_FD_NO_GROUP) != -EOPNOTSUPP ||
	    perf_open(&a, 0, -1, -1, PERF_FLAG_FD_OUTPUT) != -EOPNOTSUPP ||
	    perf_open(&a, 0, -1, -1, PERF_FLAG_PID_CGROUP) != -EOPNOTSUPP)
		return (1);
	if (perf_open(&a, 0, 0, -1, 0) != -EOPNOTSUPP ||
	    perf_open(&a, -1, -1, -1, 0) != -EINVAL)
		return (2);
	fd = perf_open(&a, sys0(SYS_gettid), -1, -1, 0);
	if (fd < 0)
		return (10);
	sys1(SYS_close, fd);
	if (perf_open(&a, 0, -1, 99999, 0) != -EBADF)
		return (3);
	regular = sys4(SYS_openat, AT_FDCWD, ".", O_RDONLY, 0);
	if (regular < 0)
		return (4);
	if (perf_open(&a, 0, -1, regular, 0) != -EOPNOTSUPP)
		return (5);
	sys1(SYS_close, regular);
	a.type = 99;
	if (perf_open(&a, 0, -1, -1, 0) != -2)
		return (6);
	a.type = PERF_TYPE_SOFTWARE;
	a.config = 99;
	if (perf_open(&a, 0, -1, -1, 0) != -2)
		return (7);
	a.config = PERF_COUNT_SW_CPU_CLOCK;
	if (perf_open(&a, 0, -1, -1, 0) != -2)
		return (8);
	a.config = PERF_COUNT_SW_CPU_MIGRATIONS;
	if (perf_open(&a, 0, -1, -1, 0) != -2)
		return (9);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd >= 0)
		sys1(SYS_close, fd);
	return (0);
}

static int
fd_contract(void)
{
	struct perf_attr a;
	struct stat st;
	struct pollfd pfd;
	u64 v;
	long fd, dupfd;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	dupfd = sys1(SYS_dup, fd);
	if (dupfd < 0 || sys1(SYS_close, fd) != 0 ||
	    sys3(SYS_read, dupfd, &v, 8) != 8 || v != 0)
		return (2);
	if (sys2(SYS_fstat, dupfd, &st) != 0 || (st.st_mode & S_IFMT) != S_IFREG)
		return (3);
	if (sys3(SYS_write, dupfd, &v, 8) != -EBADF)
		return (4);
	pfd.fd = (int)dupfd; pfd.events = POLLIN; pfd.revents = 0;
	if (sys3(SYS_poll, &pfd, 1, 0) != 0 || pfd.revents != 0)
		return (5);
	if (sys1(SYS_close, dupfd) != 0 || sys3(SYS_read, dupfd, &v, 8) != -EBADF)
		return (6);
	return (0);
}

static int
ioctl_validation(void)
{
	struct perf_attr a;
	u64 period = 1;
	long fd;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ENABLE, 2) != -EINVAL ||
	    sys3(SYS_ioctl, fd, PERF_EVENT_IOC_PERIOD, &period) != -EINVAL ||
	    sys3(SYS_ioctl, fd, 0x24ff, 0) != -EINVAL)
		return (2);
	sys1(SYS_close, fd);
	if (sys3(SYS_ioctl, fd, PERF_EVENT_IOC_ENABLE, 0) != -EBADF)
		return (3);
	return (0);
}

static int
cloexec_flag(void)
{
	struct perf_attr a;
	long a_fd, b_fd;

	attr_init(&a, PERF_COUNT_SW_DUMMY);
	a_fd = perf_open(&a, 0, -1, -1, 0);
	b_fd = perf_open(&a, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
	if (a_fd < 0 || b_fd < 0)
		return (1);
	if (sys3(SYS_fcntl, a_fd, F_GETFD, 0) != 0 ||
	    sys3(SYS_fcntl, b_fd, F_GETFD, 0) != FD_CLOEXEC)
		return (2);
	sys1(SYS_close, a_fd);
	sys1(SYS_close, b_fd);
	return (0);
}

static volatile int worker_fd = -1;
static int
exit_worker(void *arg)
{
	struct perf_attr a;
	long fd;

	(void)arg;
	attr_init(&a, PERF_COUNT_SW_TASK_CLOCK);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	burn(3000000);
	__atomic_store_n(&worker_fd, (int)fd, __ATOMIC_RELEASE);
	return (0);
}

static int
thread_exit_lifetime(void)
{
	struct thread t;
	u64 v, frozen;
	int fd;

	worker_fd = -1;
	if (thread_create(&t, exit_worker, 0) != 0 || thread_join(&t) != 0)
		return (1);
	fd = __atomic_load_n(&worker_fd, __ATOMIC_ACQUIRE);
	if (fd < 0 || sys3(SYS_read, fd, &v, 8) != 8 || v == 0)
		return (2);
	frozen = v;
	burn(1000000);
	if (sys3(SYS_read, fd, &v, 8) != 8 || v != frozen)
		return (3);
	sys1(SYS_close, fd);
	return (0);
}

static volatile int race_go;
static int
race_worker(void *arg)
{
	struct perf_attr a;
	long fd;

	(void)arg;
	attr_init(&a, PERF_COUNT_SW_DUMMY);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	__atomic_store_n(&worker_fd, (int)fd, __ATOMIC_RELEASE);
	while (__atomic_load_n(&race_go, __ATOMIC_ACQUIRE) == 0)
		(void)sys0(SYS_sched_yield);
	return (0);
}

static int
thread_close_race(void)
{
	struct thread t;
	int fd;

	for (int i = 0; i < 32; i++) {
		worker_fd = -1; race_go = 0;
		if (thread_create(&t, race_worker, 0) != 0)
			return (1);
		while ((fd = __atomic_load_n(&worker_fd, __ATOMIC_ACQUIRE)) < 0)
			(void)sys0(SYS_sched_yield);
		__atomic_store_n(&race_go, 1, __ATOMIC_RELEASE);
		(void)sys1(SYS_close, fd);
		if (thread_join(&t) != 0)
			return (2);
	}
	return (0);
}

static int
fork_inheritance(void)
{
	struct perf_attr a;
	u64 v;
	long fd, pid;
	int status = 0;

	attr_init(&a, PERF_COUNT_SW_TASK_CLOCK);
	fd = perf_open(&a, 0, -1, -1, 0);
	if (fd < 0)
		return (1);
	burn(1000000);
	pid = fork_process();
	if (pid < 0)
		return (2);
	if (pid == 0) {
		int rc = sys3(SYS_read, fd, &v, 8) == 8 && v != 0 ? 0 : 1;
		sys1(SYS_exit_group, rc);
	}
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != 0)
		return (3);
	if (sys3(SYS_read, fd, &v, 8) != 8 || v == 0)
		return (4);
	sys1(SYS_close, fd);
	return (0);
}

static const struct subtest tests[] = {
	{"basic_task_clock", basic_task_clock},
	{"disabled_transitions", disabled_transitions},
	{"read_formats", read_formats},
	{"software_counters", software_counters},
	{"attribute_sizes", attribute_sizes},
	{"attribute_options", attribute_options},
	{"target_and_flags", target_and_flags},
	{"fd_contract", fd_contract},
	{"ioctl_validation", ioctl_validation},
	{"cloexec_flag", cloexec_flag},
	{"thread_exit_lifetime", thread_exit_lifetime},
	{"thread_close_race", thread_close_race},
	{"fork_inheritance", fork_inheritance},
};

static int
test(int argc, char **argv, char **envp)
{
	struct perf_attr a;
	char fdarg[24], *native_argv[5];
	long fd, n;
	int i;

	if (argc == 5 && xstreq(argv[1], "native_exec_hold")) {
		attr_init(&a, PERF_COUNT_SW_TASK_CLOCK);
		fd = perf_open(&a, 0, -1, -1, 0);
		if (fd < 0)
			return (120);
		n = fd;
		i = sizeof(fdarg) - 1;
		fdarg[i] = '\0';
		do {
			fdarg[--i] = '0' + n % 10;
			n /= 10;
		} while (n != 0);
		native_argv[0] = argv[2];
		native_argv[1] = &fdarg[i];
		native_argv[2] = argv[3];
		native_argv[3] = argv[4];
		native_argv[4] = 0;
		(void)sys3(SYS_execve, argv[2], native_argv, envp);
		return (121);
	}
	return (run_subtests(argc, argv, tests, sizeof(tests) / sizeof(tests[0])));
}

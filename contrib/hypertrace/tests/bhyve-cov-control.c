/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of the bhyverun.c migration and startup
 * control paths and of ipc.c (compiled from its original source).
 *
 * bhyverun.c is included with main() renamed; only the functions under test
 * run.  vCPU threads are real pthreads executing the original vm_loop()
 * against a fake libvmmapi run interface, so the migration CPU barrier,
 * retirement and joins are exercised with real concurrency.  Symbols the
 * remainder of bhyve would provide stay unresolved (the link ignores them);
 * calling one would crash the test.
 *
 * Oracles: a successful pause leaves every vCPU parked (no run request
 * completes while held) and the source not runnable; every failed pause
 * either reports a runnable source that was resumed or the resume error;
 * retirement joins every created thread exactly once; the kernel-owned
 * INIT/SIPI handshake accepts exactly the statuses the vmm startup ABI
 * defines and exits EX_OSERR on any other; the IPC endpoint is private,
 * admits no command before startup completes, never hands the VM context to
 * a command after quarantine, and leaves no socket path behind on failure.
 */
#define main bhyverun_main
#include "bhyverun.c"
#undef main

#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include "test-coverage.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)

static int checks;
#define OK(x) do { CHECK(x); checks++; } while (0)

/* ---------------------------------------------------------- fake VM */
struct vcpu {
	int id;
};
struct vmctx {
	char name[64];
};
static struct vmctx the_vm = { "ctl-vm" };
static struct vcpu vcpus[4] = { { 0 }, { 1 }, { 2 }, { 3 } };
static atomic_int runs[4];
static atomic_int suspend_all_calls, resume_all_calls;
static int fail_suspend_all, fail_resume_all, fail_activate, fail_suspend_cpu;
static atomic_int run_error_at;	/* make vm_run fail on this call (total) */
static atomic_int total_runs;
static int run_exitcode = VM_EXITCODE_INOUT;
static atomic_int generation_eintr;
static int generation_fail;
/* abort() in a child: exit through atexit so its profile is written. */
static void abrt_exit(int sig) { (void)sig; exit(134); }
static atomic_int generation_calls;

int vcpu_id(struct vcpu *v) { return (v->id); }
const char *vm_get_name(struct vmctx *c) { return (c->name); }
int vm_activate_cpu(struct vcpu *v) { (void)v; return (fail_activate ? (errno = EBUSY, -1) : 0); }
int vm_suspend_cpu(struct vcpu *v) { (void)v; return (fail_suspend_cpu ? (errno = EIO, -1) : 0); }

/* Calls failing without errno: the callers' EIO fallback. */
static bool resume_noerrno, suspend_noerrno, clock_noerrno;

int
vm_suspend_all_cpus(struct vmctx *c)
{
	(void)c;
	atomic_fetch_add(&suspend_all_calls, 1);
	if (fail_suspend_all) {
		errno = suspend_noerrno ? 0 : fail_suspend_all;
		return (-1);
	}
	return (0);
}

int
vm_resume_all_cpus(struct vmctx *c)
{
	(void)c;
	atomic_fetch_add(&resume_all_calls, 1);
	if (fail_resume_all) {
		errno = resume_noerrno ? 0 : fail_resume_all;
		return (-1);
	}
	return (0);
}

int
vm_active_cpus(struct vmctx *c, cpuset_t *set)
{
	(void)c;
	CPU_ZERO(set);
	for (int i = 0; i < 4; i++)
		CPU_SET(i, set);
	return (0);
}

int
vm_run(struct vcpu *v, struct vm_run *r)
{
	int n = atomic_fetch_add(&total_runs, 1) + 1;

	usleep(200);
	if (n == atomic_load(&run_error_at)) {
		errno = ENXIO;
		return (-1);
	}
	r->vm_exit->exitcode = run_exitcode;
	atomic_fetch_add(&runs[v->id], 1);
	return (0);
}

int
vm_run_generation(struct vcpu *v, struct vmm_startup_run_request *r)
{
	atomic_fetch_add(&generation_calls, 1);
	CHECK(r->version == VMM_STARTUP_RUN_REQUEST_VERSION &&
	    r->size == VMM_STARTUP_RUN_REQUEST_SIZE &&
	    r->generation == kernel_startup_generation && r->cpuset_address != 0 &&
	    r->exit_address != 0);
	if (generation_fail != 0) {
		errno = generation_fail;
		return (-1);
	}
	{
		int left = atomic_load(&generation_eintr);
		while (left > 0 &&
		    !atomic_compare_exchange_weak(&generation_eintr, &left, left - 1))
			;
		if (left > 0) {
			errno = EINTR;
			return (-1);
		}
	}
	((struct vm_exit *)(uintptr_t)r->exit_address)->exitcode = VM_EXITCODE_INOUT;
	atomic_fetch_add(&runs[v->id], 1);
	return (0);
}

/* The vmm startup ABI: CONFIGURE opens a collecting generation, WAIT_READY
 * reports every vCPU entered, COMMIT moves to committed, STATUS reports a
 * replacement generation.  corrupt_field breaks one reply field. */
static uint64_t kernel_generation = 40;
static bool commit_fail_second;
static int corrupt_field = -1, corrupt_at = 1, request_index, startup_eintr, startup_fail;

int
vm_startup_request(struct vmctx *c, struct vmm_startup_request *r)
{
	uint32_t expected;

	(void)c;
	if (startup_eintr > 0) {
		startup_eintr--;
		errno = EINTR;
		return (-1);
	}
	if (startup_fail) {
		errno = startup_fail;
		return (-1);
	}
	if (commit_fail_second && r->operation == VMM_STARTUP_REQUEST_COMMIT) {
		errno = EIO;
		return (-1);
	}
	CHECK(r->version == VMM_STARTUP_REQUEST_VERSION && r->size == VMM_STARTUP_REQUEST_SIZE);
	for (size_t i = 0; i < sizeof(r->reserved8); i++)
		CHECK(r->reserved8[i] == 0);
	expected = (uint32_t)guest_ncpus;
	switch (r->operation) {
	case VMM_STARTUP_REQUEST_CONFIGURE:
		CHECK(r->expected_vcpus == expected && r->generation == 0);
		r->generation = ++kernel_generation;
		r->entered_vcpus = 0;
		r->bootstrap_entered = 0;
		r->phase = VMM_STARTUP_REQUEST_PHASE_COLLECTING;
		break;
	case VMM_STARTUP_REQUEST_WAIT_READY:
	case VMM_STARTUP_REQUEST_COMMIT:
		/* Status fields are reserved as zero on input. */
		CHECK(r->generation == kernel_generation && r->expected_vcpus == 0 &&
		    r->entered_vcpus == 0 && r->bootstrap_entered == 0 && r->phase == 0);
		r->expected_vcpus = expected;
		r->entered_vcpus = expected;
		r->bootstrap_entered = 1;
		r->phase = r->operation == VMM_STARTUP_REQUEST_COMMIT ?
		    VMM_STARTUP_REQUEST_PHASE_COMMITTED : VMM_STARTUP_REQUEST_PHASE_COLLECTING;
		break;
	case VMM_STARTUP_REQUEST_STATUS:
		r->generation = ++kernel_generation;
		r->entered_vcpus = 0;
		r->bootstrap_entered = 0;
		r->phase = VMM_STARTUP_REQUEST_PHASE_COLLECTING;
		break;
	default:
		abort();
	}
	r->expected_vcpus = expected;
	r->owner = VMM_STARTUP_REQUEST_OWNER_KERNEL;
	r->execution = VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED;
	if (++request_index != corrupt_at)
		return (0);
	switch (corrupt_field) {
	case 0: r->generation = r->operation == VMM_STARTUP_REQUEST_STATUS ?
	    kernel_startup_generation : r->generation + 1; break;
	case 1: r->expected_vcpus++; break;
	case 2: r->entered_vcpus ^= 1; break;
	case 3: r->bootstrap_entered ^= 1; break;
	case 4: r->phase = VMM_STARTUP_REQUEST_PHASE_OPEN; break;
	case 5: r->owner = VMM_STARTUP_REQUEST_OWNER_USERSPACE; break;
	case 6: r->execution = VMM_STARTUP_REQUEST_EXECUTION_USERSPACE; break;
	case 7: r->generation = 0; break;
	}
	return (0);
}

/* ------------------------------------------ bhyve-internal boundaries */
static atomic_int console_retired, sci_retired, cpu_added, gdb_added, source_prepared;
static int events[16], nevents;
void console_input_retire(void) { atomic_fetch_add(&console_retired, 1); }
void sci_retire(void) { atomic_fetch_add(&sci_retired, 1); }
void checkpoint_cpu_add(int id) { (void)id; atomic_fetch_add(&cpu_added, 1); }
void gdb_cpu_add(struct vcpu *v) { (void)v; atomic_fetch_add(&gdb_added, 1); }
int migration_prod_source_prepare(void) { events[nevents++] = 1; atomic_fetch_add(&source_prepared, 1); return (0); }

static int
exit_continue(struct vmctx *c, struct vcpu *v, struct vm_run *r)
{
	(void)c; (void)v; (void)r;
	return (VMEXIT_CONTINUE);
}

static int
exit_other(struct vmctx *c, struct vcpu *v, struct vm_run *r)
{
	(void)c; (void)v; (void)r;
	return (7);
}

static int
exit_abort(struct vmctx *c, struct vcpu *v, struct vm_run *r)
{
	(void)c; (void)v; (void)r;
	return (VMEXIT_ABORT);
}

const vmexit_handler_t vmexit_handlers[VM_EXITCODE_MAX] = {
	[VM_EXITCODE_INOUT] = exit_continue,
	[VM_EXITCODE_VMX] = exit_other,
	[VM_EXITCODE_SVM] = exit_abort,
};

/* --------------------------------------------------- wrapped libc */
int __real_pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
int __real_clock_gettime(clockid_t, struct timespec *);
int __real_pthread_join(pthread_t, void **);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_condattr_init(pthread_condattr_t *);
int __real_pthread_condattr_setclock(pthread_condattr_t *, clockid_t);
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
static int fail_setclock, fail_cond_init;
int __wrap_pthread_condattr_setclock(pthread_condattr_t *a, clockid_t c)
{ return (fail_setclock ? fail_setclock : __real_pthread_condattr_setclock(a, c)); }
int __wrap_pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a)
{ return (fail_cond_init ? fail_cond_init : __real_pthread_cond_init(c, a)); }
int __real_socket(int, int, int);
int __real_bind(int, const struct sockaddr *, socklen_t);
int __real_lchmod(const char *, mode_t);
int __real_setsockopt(int, int, int, const void *, socklen_t);
int __real_listen(int, int);
int __real_accept4(int, struct sockaddr *, socklen_t *, int);
static int fail_timedwait, fail_clock, fail_join, fail_create, fail_condattr;
static int fail_socket, fail_bind, fail_lchmod, fail_setsockopt, fail_listen;
static atomic_int accept_script[8], accept_index, accept_fatal_seen;

/* Capability-mode setup failures (stdout/stderr limits, cap_enter). */
static int fail_cap_fd = -1, fail_cap_enter, fail_cap_sockets;
int __real_cap_rights_limit(int, const cap_rights_t *);
int __wrap_cap_rights_limit(int fd, const cap_rights_t *r)
{
	struct stat st;
	if (fd == fail_cap_fd || (fail_cap_sockets && fstat(fd, &st) == 0 &&
	    S_ISSOCK(st.st_mode))) {
		errno = EPERM;
		return (-1);
	}
	return (__real_cap_rights_limit(fd, r));
}
int __real_cap_enter(void);
int __wrap_cap_enter(void)
{ if (fail_cap_enter) { errno = EPERM; return (-1); } return (__real_cap_enter()); }
/* The bootstrap vCPU's wait for the others is observable: a waiter that
 * enters pthread_cond_wait() is announced before the wait releases its mutex. */
static atomic_int cond_waiters;
int __real_pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int __wrap_pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{ atomic_fetch_add(&cond_waiters, 1); return (__real_pthread_cond_wait(c, m)); }
int __wrap_pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *t)
{ return (fail_timedwait ? fail_timedwait : __real_pthread_cond_timedwait(c, m, t)); }
int __wrap_clock_gettime(clockid_t id, struct timespec *t)
{ if (fail_clock) { errno = clock_noerrno ? 0 : fail_clock; return (-1); }
  return (__real_clock_gettime(id, t)); }
int __wrap_pthread_join(pthread_t t, void **r)
{ return (fail_join ? fail_join : __real_pthread_join(t, r)); }
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *p)
{ return (fail_create ? fail_create : __real_pthread_create(t, a, f, p)); }
int __wrap_pthread_condattr_init(pthread_condattr_t *a)
{ return (fail_condattr ? fail_condattr : __real_pthread_condattr_init(a)); }
int __wrap_socket(int d, int t, int p)
{ if (fail_socket) { errno = fail_socket; return (-1); } return (__real_socket(d, t, p)); }
int __wrap_bind(int s, const struct sockaddr *a, socklen_t l)
{ if (fail_bind) { errno = fail_bind; return (-1); } return (__real_bind(s, a, l)); }
int __wrap_lchmod(const char *p, mode_t m)
{ if (fail_lchmod) { errno = fail_lchmod; return (-1); } return (__real_lchmod(p, m)); }
int __wrap_setsockopt(int s, int l, int o, const void *v, socklen_t n)
{ if (fail_setsockopt && o == SO_RCVTIMEO) { errno = fail_setsockopt; return (-1); }
  return (__real_setsockopt(s, l, o, v, n)); }
int __wrap_listen(int s, int b)
{ if (fail_listen) { errno = fail_listen; return (-1); } return (__real_listen(s, b)); }
int
__wrap_accept4(int s, struct sockaddr *a, socklen_t *l, int f)
{
	int i = atomic_load(&accept_index);

	if (i < 8 && atomic_load(&accept_script[i]) != 0) {
		atomic_store(&accept_index, i + 1);
		errno = atomic_load(&accept_script[i]);
		if (errno != EINTR && errno != ECONNABORTED)
			atomic_store(&accept_fatal_seen, 1);
		return (-1);
	}
	return (__real_accept4(s, a, l, f));
}

/* Wait until the command thread has taken its scripted fatal accept error
 * (it then reports and leaves; allow it a moment to print). */
static void
wait_accept_fatal(void)
{
	for (int i = 0; i < 500 && !atomic_load(&accept_fatal_seen); i++)
		usleep(10000);
	CHECK(atomic_load(&accept_fatal_seen));
	usleep(50000);
}

/* ------------------------------------------------------------ helpers */
static pid_t
child(void)
{
	pid_t pid;

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	CHECK(pid >= 0);
	return (pid);
}

static int
child_status(pid_t pid)
{
	int status;
	pid_t got = waitpid(pid, &status, 0);

	if (got != pid)
		fprintf(stderr, "waitpid(%d) in %d -> %d\n", (int)pid, (int)getpid(), (int)got);
	CHECK(got == pid);
	return (status);
}

#define EXPECT_EXIT(code, body) do {					\
	pid_t p_ = child();						\
	if (p_ == 0) {							\
		body;							\
		exit(250);						\
	}								\
	int s_ = child_status(p_);					\
	OK(WIFEXITED(s_) && WEXITSTATUS(s_) == (code));			\
} while (0)

static void
setup_vcpus(int n)
{
	guest_ncpus = n;
	free(vcpu_info);
	free(vcpumap);
	vcpu_info = calloc((size_t)n, sizeof(*vcpu_info));
	vcpumap = calloc((size_t)n, sizeof(*vcpumap));
	for (int i = 0; i < n; i++) {
		vcpu_info[i].ctx = &the_vm;
		vcpu_info[i].vcpu = &vcpus[i];
		vcpu_info[i].vcpuid = i;
	}
}

static int
total(void)
{
	int sum = 0;

	for (int i = 0; i < 4; i++)
		sum += atomic_load(&runs[i]);
	return (sum);
}

static bool
all_running(int n)
{
	int before[4];

	for (int i = 0; i < n; i++)
		before[i] = atomic_load(&runs[i]);
	for (int t = 0; t < 2000; t++) {
		bool all = true;
		usleep(1000);
		for (int i = 0; i < n; i++)
			all &= atomic_load(&runs[i]) > before[i] + 2;
		if (all)
			return (true);
	}
	return (false);
}

/* -------------------------------------------------------------- tests */
static void
test_numa(void)
{
	uint64_t sizes[VM_MAXMEMDOM];
	uint16_t domains[4];
	size_t count;
	int before = checks;

	setup_vcpus(2);
	guest_ndomains = 0;
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 4, &count) == EINVAL);
	guest_ndomains = 1;
	guest_domains[0].size = 1UL << 30;
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 4, &count) == EINVAL); /* no map */
	{
		const uint64_t s2[2] = { 1UL << 30, 1UL << 30 };
		const uint16_t d2[2] = { 1, 0 };
		OK(bhyve_numa_restore_apply(s2, 2, d2, 3, 2UL << 30) == EINVAL);
		OK(bhyve_numa_restore_apply(s2, VM_MAXMEMDOM + 1, d2, 2, 2UL << 30) == EINVAL);
		OK(bhyve_numa_restore_apply(s2, 2, d2, 2, 3UL << 30) != 0);	/* sizes != total */
		{
			const uint16_t bad[2] = { 0, 2 };
			OK(bhyve_numa_restore_apply(s2, 2, bad, 2, 2UL << 30) != 0);
		}
		OK(bhyve_numa_restore_apply(s2, 2, d2, 2, 2UL << 30) == 0 && guest_numa_restored &&
		    guest_ndomains == 2 && guest_domains[1].size == 1UL << 30 &&
		    guest_domains[2].size == 0);
	}
	OK(bhyve_numa_checkpoint_export(NULL, 8, domains, 4, &count) == EINVAL);
	OK(bhyve_numa_checkpoint_export(sizes, 8, NULL, 4, &count) == EINVAL);
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 4, NULL) == EINVAL);
	OK(bhyve_numa_checkpoint_export(sizes, 1, domains, 4, &count) == EINVAL);
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 1, &count) == EINVAL);
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 4, &count) == 0 && count == 2 &&
	    sizes[0] == 1UL << 30 && domains[0] == 1 && domains[1] == 0);
	guest_ncpus = 0;
	OK(bhyve_numa_checkpoint_export(sizes, 8, domains, 4, &count) == EINVAL);
	guest_ncpus = 2;
	printf("control NUMA export/apply: %d checks\n", checks - before);
}

static void
test_kernel_startup(void)
{
	int before = checks;

	setup_vcpus(2);
	startup_eintr = 2;
	kernel_startup_configure(&the_vm);
	OK(kernel_startup_generation == kernel_generation);
	kernel_startup_commit(&the_vm);
	{
		uint64_t previous = kernel_startup_generation;
		kernel_startup_refresh(&the_vm);
		OK(kernel_startup_generation != previous &&
		    kernel_startup_generation == kernel_generation);
	}
	/* Every reply field the ABI fixes is checked by each request. */
	for (int field = 0; field <= 7; field++) {
		/* CONFIGURE accepts any nonzero generation. */
		if (field != 0)
			EXPECT_EXIT(EX_OSERR, { corrupt_field = field; request_index = 0;
			    corrupt_at = 1; kernel_startup_configure(&the_vm); });
		{
			/* WAIT_READY (request 1) and COMMIT (request 2). */
			EXPECT_EXIT(EX_OSERR, { kernel_startup_configure(&the_vm);
			    corrupt_field = field; request_index = 0; corrupt_at = 1;
			    kernel_startup_commit(&the_vm); });
			EXPECT_EXIT(EX_OSERR, { kernel_startup_configure(&the_vm);
			    corrupt_field = field; request_index = 0; corrupt_at = 2;
			    kernel_startup_commit(&the_vm); });
		}
		EXPECT_EXIT(EX_OSERR, { corrupt_field = field; request_index = 0; corrupt_at = 1;
		    kernel_startup_refresh(&the_vm); });
	}
	/* A corrupted reply to a request that is not checked is harmless. */
	corrupt_field = 1;
	request_index = 0;
	corrupt_at = 99;
	kernel_startup_configure(&the_vm);
	corrupt_field = -1;
	EXPECT_EXIT(EX_OSERR, { startup_fail = EIO; kernel_startup_configure(&the_vm); });
	EXPECT_EXIT(EX_OSERR, { kernel_startup_configure(&the_vm); startup_fail = EIO;
	    kernel_startup_commit(&the_vm); });
	EXPECT_EXIT(EX_OSERR, { kernel_startup_configure(&the_vm);
	    startup_fail = 0; request_index = 0; corrupt_at = 99;
	    /* Fail the COMMIT request after a good WAIT_READY. */
	    commit_fail_second = true; kernel_startup_commit(&the_vm); });
	EXPECT_EXIT(EX_OSERR, { startup_fail = EIO; kernel_startup_refresh(&the_vm); });
	printf("control kernel INIT/SIPI handshake: %d checks\n", checks - before);
}

static void
test_cpu_barrier(void)
{
	bool runnable;
	int frozen, before = checks;

	setup_vcpus(3);
	OK(fbsdrun_retire_cpus_wait() == EINVAL);
	EXPECT_EXIT(EX_OSERR, { fail_activate = 1; fbsdrun_addcpu(0); });
	EXPECT_EXIT(EX_OSERR, { fail_suspend_cpu = 1; fbsdrun_addcpu(0); });
	EXPECT_EXIT(EX_OSERR, { fail_create = EAGAIN; fbsdrun_addcpu(0); });
	for (int i = 0; i < 3; i++)
		fbsdrun_addcpu(i);
	OK(all_running(3) && atomic_load(&cpu_added) == 3 && atomic_load(&gdb_added) == 3);

	/* Pause: every vCPU parks between exits; nothing runs while held. */
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == 0 && !runnable);
	OK(migration_cpu_parked == 3 && atomic_load(&suspend_all_calls) == 1);
	frozen = total();
	usleep(20000);
	OK(total() == frozen);
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EBUSY && !runnable);
	OK(fbsdrun_migration_resume_cpus(&the_vm) == 0 && all_running(3));
	OK(migration_cpu_parked == 0);

	/* A failed suspend request resumes and reports a runnable source. */
	fail_suspend_all = EIO;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EIO && runnable);
	fail_suspend_all = 0;
	OK(all_running(3));
	/* Barrier timeout: resumed, runnable. */
	fail_timedwait = ETIMEDOUT;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == ETIMEDOUT && runnable);
	OK(all_running(3));
	/* Timeout and a failed resume: the resume error, not runnable. */
	fail_resume_all = EIO;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EIO && !runnable);
	fail_timedwait = 0;
	fail_resume_all = 0;
	OK(fbsdrun_migration_resume_cpus(&the_vm) == 0 && all_running(3));
	/* No deadline: runnable, never held. */
	fail_clock = EINVAL;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EINVAL && runnable);
	fail_clock = 0;
	OK(!atomic_load(&migration_cpu_hold) && all_running(3));

	/* Failures that leave errno clear are reported as EIO. */
	suspend_noerrno = resume_noerrno = clock_noerrno = true;
	fail_suspend_all = EIO;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EIO && runnable);
	fail_suspend_all = 0;
	fail_clock = EINVAL;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EIO && runnable);
	fail_clock = 0;
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == 0);
	fail_resume_all = EIO;
	OK(fbsdrun_migration_resume_cpus(&the_vm) == EIO);
	fail_resume_all = 0;
	suspend_noerrno = resume_noerrno = clock_noerrno = false;
	OK(fbsdrun_migration_resume_cpus(&the_vm) == 0 && all_running(3));
	/* Retirement while held: parked vCPUs exit; each thread joined once. */
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == 0);
	fbsdrun_retire_cpus_begin();
	OK(fbsdrun_cpus_retiring() && atomic_load(&console_retired) == 1 &&
	    atomic_load(&sci_retired) == 1);
	OK(fbsdrun_migration_pause_cpus(&the_vm, &runnable) == EBUSY && !runnable);
	OK(fbsdrun_migration_resume_cpus(&the_vm) == ECANCELED);
	fail_join = ESRCH;
	OK(fbsdrun_retire_cpus_wait() == ESRCH);
	fail_join = 0;
	OK(fbsdrun_retire_cpus_wait() == 0);
	for (int i = 0; i < 3; i++)
		OK(vcpu_info[i].thread_joined);
	OK(fbsdrun_retire_cpus_wait() == 0);
	OK(CPU_EMPTY(&cpumask));
	printf("control migration CPU barrier and retirement: %d checks\n", checks - before);
}

/* Fresh processes: the barrier's one-time initialization and vm_loop exits. */
static void *
delete_after_bsp_waits(void *arg)
{
	(void)arg;
	while (atomic_load(&cond_waiters) == 0)
		usleep(1000);
	fbsdrun_deletecpu(1);	/* exits this thread */
	return (NULL);
}

static void
test_cpu_barrier_init_and_loop(void)
{
	bool runnable;
	int before = checks;

	EXPECT_EXIT(0, {
		fail_condattr = ENOMEM;
		bool r;
		CHECK(fbsdrun_migration_resume_cpus(&the_vm) == ENOMEM);
		CHECK(fbsdrun_migration_pause_cpus(&the_vm, &r) == ENOMEM && r);
		fbsdrun_retire_cpus_begin();	/* wake is a no-op */
		exit(0);
	});
	EXPECT_EXIT(0, { fail_setclock = EINVAL; bool r;
	    CHECK(fbsdrun_migration_pause_cpus(&the_vm, &r) == EINVAL && r); exit(0); });
	EXPECT_EXIT(0, { fail_cond_init = ENOMEM; bool r;
	    CHECK(fbsdrun_migration_pause_cpus(&the_vm, &r) == ENOMEM && r); exit(0); });
	(void)runnable;
	/* vCPU host affinity: applied, or fatal when the host refuses it. */
	EXPECT_EXIT(0, {
		static cpuset_t mask;
		setup_vcpus(1);
		CPU_ZERO(&mask);
		CPU_SET(0, &mask);
		vcpumap[0] = &mask;
		fbsdrun_addcpu(0);
		CHECK(all_running(1));
		fbsdrun_retire_cpus_begin();
		CHECK(fbsdrun_retire_cpus_wait() == 0);
		exit(0);
	});
	EXPECT_EXIT(EX_OSERR, {
		static cpuset_t mask;
		setup_vcpus(1);
		CPU_ZERO(&mask);
		CPU_SET(CPU_SETSIZE - 1, &mask);	/* no such host CPU */
		vcpumap[0] = &mask;
		fbsdrun_addcpu(0);
		pause();
	});
	/* vm_loop: a failed run request ends the vCPU thread with an error. */
	EXPECT_EXIT(BHYVE_EXIT_ERROR, {
		setup_vcpus(1);
		atomic_store(&run_error_at, atomic_load(&total_runs) + 3);
		fbsdrun_addcpu(0);
		pause();
	});
	EXPECT_EXIT(BHYVE_EXIT_ERROR, {
		raw_stdio = 1;
		setup_vcpus(1);
		atomic_store(&run_error_at, atomic_load(&total_runs) + 3);
		fbsdrun_addcpu(0);
		pause();
	});
	/* An exit code without a handler, and a handler error. */
	EXPECT_EXIT(BHYVE_EXIT_ERROR, { setup_vcpus(1); run_exitcode = VM_EXITCODE_HLT;
	    fbsdrun_addcpu(0); pause(); });
	EXPECT_EXIT(BHYVE_EXIT_ERROR, { setup_vcpus(1); run_exitcode = VM_EXITCODE_MAX + 1;
	    fbsdrun_addcpu(0); pause(); });
	EXPECT_EXIT(BHYVE_EXIT_ERROR, { setup_vcpus(1); run_exitcode = VM_EXITCODE_VMX;
	    fbsdrun_addcpu(0); pause(); });
	{
		/* An exit handler asking for VMEXIT_ABORT aborts the process. */
		pid_t p = child();
		if (p == 0) {
			signal(SIGABRT, abrt_exit);
			setup_vcpus(1);
			run_exitcode = VM_EXITCODE_SVM;
			fbsdrun_addcpu(0);
			pause();
		}
		int s = child_status(p);
		OK(WIFEXITED(s) && WEXITSTATUS(s) == 134);
	}
	/* A kernel-owned startup run that fails (not EINTR) ends the loop and
	 * the process exits with an error. */
	EXPECT_EXIT(BHYVE_EXIT_ERROR, {
		setup_vcpus(1);
		kernel_startup = true;
		kernel_startup_configure(&the_vm);
		generation_fail = ENXIO;
		fbsdrun_addcpu(0);
		pause();
	});
	/* Kernel-owned startup: generation runs (with EINTR) before ordinary
	 * runs; retirement ends both vCPUs, the bootstrap one last. */
	EXPECT_EXIT(0, {
		setup_vcpus(2);
		kernel_startup = true;
		kernel_startup_configure(&the_vm);
		atomic_store(&generation_eintr, 3);
		fbsdrun_addcpu(0);
		fbsdrun_addcpu(1);
		CHECK(all_running(2));
		if (atomic_load(&generation_calls) != 5)
			fprintf(stderr, "generation calls %d\n", atomic_load(&generation_calls));
		CHECK(atomic_load(&generation_calls) == 5);
		fbsdrun_retire_cpus_begin();
		CHECK(fbsdrun_retire_cpus_wait() == 0);
		exit(0);
	});
	/* A vCPU deleted twice is fatal, in either console mode. */
	EXPECT_EXIT(BHYVE_EXIT_ERROR, { CPU_ZERO(&cpumask); fbsdrun_deletecpu(1); });
	EXPECT_EXIT(BHYVE_EXIT_ERROR, { raw_stdio = 1; CPU_ZERO(&cpumask); fbsdrun_deletecpu(1); });
	/* Retirement without a migration hold also refuses a pause, and the
	 * retirement wait skips vCPUs whose threads were never created. */
	EXPECT_EXIT(0, {
		bool r = true;
		setup_vcpus(2);
		vcpu_info[1].thread_created = false;
		fbsdrun_retire_cpus_begin();
		CHECK(fbsdrun_migration_pause_cpus(&the_vm, &r) == EBUSY && !r);
		vcpu_info[0].thread_created = false;
		CHECK(fbsdrun_retire_cpus_wait() == 0 && !vcpu_info[1].thread_joined);
		exit(0);
	});
	/* The bootstrap vCPU deleted first waits until every other vCPU is gone;
	 * the other vCPU is released only once the bootstrap one is waiting. */
	EXPECT_EXIT(0, {
		pthread_t ap;
		CPU_ZERO(&cpumask);
		CPU_SET(BSP, &cpumask);
		CPU_SET(1, &cpumask);
		atomic_store(&cond_waiters, 0);
		CHECK(pthread_create(&ap, NULL, delete_after_bsp_waits, NULL) == 0);
		fbsdrun_deletecpu(BSP);
		CHECK(CPU_EMPTY(&cpumask) && atomic_load(&cond_waiters) >= 1);
		exit(0);
	});
	printf("control barrier init and vm_loop exits: %d checks\n", checks - before);
}

/* ----------------------------------------------------------------- IPC */
static char rundir[256];

static nvlist_t *
test_ctx_command(struct vmctx *ctx, const nvlist_t *nvl)
{
	nvlist_t *reply = nvlist_create(0);

	(void)nvl;
	nvlist_add_bool(reply, "has_ctx", ctx == &the_vm);
	nvlist_add_bool(reply, "null_ctx", ctx == NULL);
	return (reply);
}
IPC_COMMAND(test_ctx, test_ctx_command);

static nvlist_t *
test_fail_command(struct vmctx *ctx, const nvlist_t *nvl)
{
	nvlist_t *reply = nvlist_create(0);

	(void)ctx;
	(void)nvl;
	nvlist_add_string(reply, "error", "handler refused");
	return (reply);
}
IPC_COMMAND(test_fail, test_fail_command);

static nvlist_t *
quarantine_command(struct vmctx *ctx, const nvlist_t *nvl)
{
	const char *what = nvlist_get_string(nvl, "what");
	nvlist_t *reply = nvlist_create(0);

	(void)ctx;
	if (strcmp(what, "quarantine") == 0)
		ipc_quarantine_vm();
	else if (strcmp(what, "wedge") == 0)
		ipc_wedge_vm();
	else
		nvlist_add_number(reply, "unwedge", ipc_unwedge_vm());
	return (reply);
}
IPC_COMMAND(test_state, quarantine_command);

/* Ends bhyve once answered, as a checkpoint with suspend does. */
static nvlist_t *
test_exit_command(struct vmctx *ctx, const nvlist_t *nvl)
{
	nvlist_t *reply = nvlist_create(0);

	(void)ctx;
	nvlist_add_bool(reply, "answered", true);
	if (nvlist_exists_bool(nvl, "large")) {
		/* Larger than the socket buffers: the send blocks. */
		size_t len = 1024 * 1024;
		void *pad = calloc(1, len);

		CHECK(pad != NULL);
		nvlist_move_binary(reply, "pad", pad, len);
	}
	ipc_exit_after_reply(42);
	return (reply);
}
IPC_COMMAND(test_exit, test_exit_command);
IPC_COMMAND(migrate_recover, test_ctx_command);
IPC_COMMAND(migrate_repair, test_ctx_command);

static int
ipc_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int s = socket(AF_UNIX, SOCK_STREAM, 0);

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", rundir, the_vm.name);
	addr.sun_len = SUN_LEN(&addr);
	CHECK(s >= 0 && connect(s, (struct sockaddr *)&addr, addr.sun_len) == 0);
	return (s);
}

static nvlist_t *
ipc_call(nvlist_t *request)
{
	int s = ipc_connect();
	nvlist_t *reply = nvlist_xfer(s, request, 0);

	close(s);
	CHECK(reply != NULL);
	return (reply);
}

static nvlist_t *
cmd(const char *name)
{
	nvlist_t *request = nvlist_create(0);

	nvlist_add_string(request, "cmd", name);
	return (ipc_call(request));
}

static bool
socket_exists(void)
{
	char path[300];
	struct stat st;

	snprintf(path, sizeof(path), "%s/%s", rundir, the_vm.name);
	return (lstat(path, &st) == 0);
}

static int
open_fds(void)
{
	int n = 0;

	for (int fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return (n);
}

static void
test_ipc(void)
{
	nvlist_t *reply, *request;
	int before = checks, fds;

	snprintf(rundir, sizeof(rundir), "%s", "ipc.XXXXXX");
	CHECK(mkdtemp(rundir) != NULL);
	/* Failures release the descriptor and leave no endpoint behind. */
	fds = open_fds();
	/* Each failure is reported in both console modes (raw_stdio selects the
	 * line ending of EPRINTLN); the outcome is the same in both. */
	for (int raw = 0; raw < 2; raw++) {
	raw_stdio = raw;
	fail_socket = EMFILE;
	OK(init_ipc_thread(&the_vm, rundir) == -1 && !socket_exists() && open_fds() == fds);
	fail_socket = 0;
	{
		char longdir[200];
		memset(longdir, 'd', sizeof(longdir) - 1);
		longdir[sizeof(longdir) - 1] = '\0';
		OK(init_ipc_thread(&the_vm, longdir) == ENAMETOOLONG && open_fds() == fds);
	}
	fail_bind = EADDRINUSE;
	OK(init_ipc_thread(&the_vm, rundir) == -1 && !socket_exists() && open_fds() == fds);
	fail_bind = 0;
	fail_lchmod = EPERM;
	OK(init_ipc_thread(&the_vm, rundir) == EPERM && !socket_exists() && open_fds() == fds);
	fail_lchmod = 0;
	fail_setsockopt = ENOBUFS;
	OK(init_ipc_thread(&the_vm, rundir) == ENOBUFS && !socket_exists() && open_fds() == fds);
	fail_setsockopt = 0;
	fail_listen = EINVAL;
	OK(init_ipc_thread(&the_vm, rundir) == EINVAL && !socket_exists() && open_fds() == fds);
	fail_listen = 0;
	fail_create = EAGAIN;
	OK(init_ipc_thread(&the_vm, rundir) == EAGAIN && !socket_exists() && open_fds() == fds);
	fail_create = 0;
	}
	raw_stdio = 0;
	/* The endpoint's rights limit failing is fatal (EX_OSERR). */
	EXPECT_EXIT(EX_OSERR, { fail_cap_sockets = 1; init_ipc_thread(&the_vm, rundir); });
	/* The default run directory is used when none is configured. */
	EXPECT_EXIT(0, { fail_bind = EACCES; exit(init_ipc_thread(&the_vm, NULL) == -1 ? 0 : 1); });

	atomic_store(&accept_script[0], EINTR);
	atomic_store(&accept_script[1], ECONNABORTED);
	OK(init_ipc_thread(&the_vm, rundir) == 0 && socket_exists());
	{
		char path[300];
		struct stat st;
		snprintf(path, sizeof(path), "%s/%s", rundir, the_vm.name);
		OK(lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
		    (st.st_mode & 0777) == (S_IRUSR | S_IWUSR));
	}
	/* No command is admitted before startup completes. */
	{
		int s = ipc_connect();
		struct pollfd pfd = { .fd = s, .events = POLLIN };
		request = nvlist_create(0);
		nvlist_add_string(request, "cmd", "get_vm_pid");
		CHECK(nvlist_send(s, request) == 0);
		nvlist_destroy(request);
		OK(poll(&pfd, 1, 200) == 0);
		ipc_startup_complete();
		reply = nvlist_recv(s, 0);
		OK(reply != NULL && nvlist_get_number(reply, "pid") == (uint64_t)getpid());
		nvlist_destroy(reply);
		close(s);
	}
	OK(atomic_load(&accept_index) == 2);	/* EINTR and ECONNABORTED retried */
	reply = cmd("test_ctx");
	OK(nvlist_get_bool(reply, "has_ctx"));
	nvlist_destroy(reply);
	reply = cmd("no_such_command");
	OK(strcmp(nvlist_get_string(reply, "error"), "command 'no_such_command' not found") == 0);
	nvlist_destroy(reply);
	for (int raw = 0; raw < 2; raw++) {
		raw_stdio = raw;
		reply = cmd("test_fail");
		OK(strcmp(nvlist_get_string(reply, "error"), "handler refused") == 0);
		nvlist_destroy(reply);
	}
	raw_stdio = 0;
	request = nvlist_create(0);
	nvlist_add_number(request, "cmd", 7);
	reply = ipc_call(request);
	OK(strcmp(nvlist_get_string(reply, "error"), "missing command name") == 0);
	nvlist_destroy(reply);
	/* A malformed request and a client that leaves before the reply do not
	 * stop the command thread. */
	for (int raw = 0; raw < 2; raw++) {
		raw_stdio = raw;
		int s = ipc_connect();
		CHECK(write(s, "garbage-not-an-nvlist-header-xxxxxxxx", 37) == 37);
		shutdown(s, SHUT_WR);
		char buf[16];
		OK(read(s, buf, sizeof(buf)) == 0);
		close(s);
	}
	raw_stdio = 0;
	{
		int s = ipc_connect();
		request = nvlist_create(0);
		nvlist_add_string(request, "cmd", "get_vm_pid");
		CHECK(nvlist_send(s, request) == 0);
		nvlist_destroy(request);
		close(s);
	}
	reply = cmd("get_vm_pid");
	OK(nvlist_exists_number(reply, "pid"));
	nvlist_destroy(reply);
	/* A handler that ends bhyve has its reply sent first: the IPC thread
	 * (a new one in the child) answers, then exits with its status. */
	EXPECT_EXIT(42, {
		snprintf(rundir, sizeof(rundir), "%s", "ipcx.XXXXXX");
		if (mkdtemp(rundir) == NULL ||
		    init_ipc_thread(&the_vm, rundir) != 0)
			_exit(1);
		reply = cmd("test_exit");
		if (reply == NULL || !nvlist_exists_bool(reply, "answered"))
			_exit(2);
		for (;;)
			pause();
	});
	/* A controller that never reads a reply larger than the socket
	 * buffers cannot keep bhyve alive after the VM ended: the send times
	 * out and bhyve exits anyway. */
	EXPECT_EXIT(42, {
		alarm(20);
		snprintf(rundir, sizeof(rundir), "%s", "ipcy.XXXXXX");
		if (mkdtemp(rundir) == NULL ||
		    init_ipc_thread(&the_vm, rundir) != 0)
			_exit(1);
		int s = ipc_connect();
		request = nvlist_create(0);
		nvlist_add_string(request, "cmd", "test_exit");
		nvlist_add_bool(request, "large", true);
		if (nvlist_send(s, request) != 0)
			_exit(2);
		for (;;)
			pause();
	});

	/* Wedge: only migrate_repair (without the context) and get_vm_pid. */
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "test_state");
	nvlist_add_string(request, "what", "unwedge");
	reply = ipc_call(request);
	OK(nvlist_get_number(reply, "unwedge") == EPERM);
	nvlist_destroy(reply);
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "test_state");
	nvlist_add_string(request, "what", "wedge");
	nvlist_destroy(ipc_call(request));
	reply = cmd("test_ctx");
	OK(strstr(nvlist_get_string(reply, "error"), "use migrate_repair") != NULL &&
	    nvlist_get_number(reply, "error_code") == ECANCELED);
	nvlist_destroy(reply);
	reply = cmd("migrate_repair");
	OK(nvlist_get_bool(reply, "null_ctx"));
	nvlist_destroy(reply);
	reply = cmd("migrate_recover");
	OK(nvlist_get_bool(reply, "null_ctx"));
	nvlist_destroy(reply);
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "test_state");
	nvlist_add_string(request, "what", "unwedge");
	reply = ipc_call(request);	/* refused: test_state is not admitted */
	OK(nvlist_exists_string(reply, "error"));
	nvlist_destroy(reply);
	OK(ipc_unwedge_vm() == 0);
	reply = cmd("test_ctx");
	OK(nvlist_get_bool(reply, "has_ctx"));
	nvlist_destroy(reply);
	/* Retirement quarantine is irreversible and cannot become a wedge. */
	request = nvlist_create(0);
	nvlist_add_string(request, "cmd", "test_state");
	nvlist_add_string(request, "what", "quarantine");
	nvlist_destroy(ipc_call(request));
	ipc_wedge_vm();
	OK(ipc_unwedge_vm() == EPERM);
	reply = cmd("test_ctx");
	OK(strcmp(nvlist_get_string(reply, "error"),
	    "VM is quarantined after migration retirement") == 0);
	nvlist_destroy(reply);
	reply = cmd("migrate_repair");
	OK(nvlist_exists_string(reply, "error"));
	nvlist_destroy(reply);
	reply = cmd("migrate_recover");
	OK(nvlist_get_bool(reply, "null_ctx"));
	nvlist_destroy(reply);
	reply = cmd("get_vm_pid");
	OK(nvlist_exists_number(reply, "pid"));
	nvlist_destroy(reply);
	/* A fatal accept error ends the command thread (raw console mode here;
	 * the cooked-mode report is in the prepare-control child). */
	raw_stdio = 1;
	atomic_store(&accept_fatal_seen, 0);
	atomic_store(&accept_script[2], EBADF);
	{
		/* The thread is already inside accept: one served request, then
		 * its next accept fails. */
		reply = cmd("get_vm_pid");
		nvlist_destroy(reply);
		wait_accept_fatal();
	}
	raw_stdio = 0;
	printf("control IPC endpoint and admission: %d checks\n", checks - before);
}

/* bhyve_prepare_control in a child: the migration journal lookup precedes
 * the endpoint, the endpoint answers once startup completes, and the child
 * then runs in capability mode. */
static void
test_prepare_control(void)
{
	int ready[2], quit[2], before = checks;
	pid_t pid;

	snprintf(rundir, sizeof(rundir), "%s", "prep.XXXXXX");
	CHECK(mkdtemp(rundir) != NULL);
	CHECK(pipe(ready) == 0 && pipe(quit) == 0);
	pid = child();
	if (pid == 0) {
		u_int mode;
		/* Capability mode: the profile is opened before cap_enter. */
		ht_test_coverage_start("prepare-control", true);
		set_config_value("rundir", rundir);
		bhyve_prepare_control(&the_vm);
		CHECK(cap_getmode(&mode) == 0 && mode == 1);
		CHECK(events[0] == 1 && atomic_load(&source_prepared) == 1);
		ipc_startup_complete();
		CHECK(write(ready[1], "r", 1) == 1);
		close(quit[1]);
		{
			char x;
			/* 'k': the parent is done with commands; the next accept
			 * fails fatally and ends only the command thread. */
			CHECK(read(quit[0], &x, 1) == 1 && x == 'k');
			/* The script state is inherited from the parent: restart it. */
			atomic_store(&accept_index, 0);
			atomic_store(&accept_fatal_seen, 0);
			atomic_store(&accept_script[0], EBADF);
			CHECK(write(ready[1], "r", 1) == 1);
			close(ready[1]);
			while (read(quit[0], &x, 1) > 0)
				;
			wait_accept_fatal();
		}
		ht_test_coverage_finish();
		_exit(0);
	}
	{
		char c;
		nvlist_t *reply;
		CHECK(read(ready[0], &c, 1) == 1);
		reply = cmd("get_vm_pid");
		OK(nvlist_get_number(reply, "pid") == (uint64_t)pid);
		nvlist_destroy(reply);
		CHECK(write(quit[1], "k", 1) == 1);
		CHECK(read(ready[0], &c, 1) == 1);
		reply = cmd("get_vm_pid");	/* served; the next accept fails */
		nvlist_destroy(reply);
		usleep(200000);	/* the child's thread reports in its own process */
		/* The child leaves when the pipe closes. */
		close(ready[1]);
		close(quit[0]);
		close(quit[1]);
		{
			int st, n = 0;
			pid_t got;
			while ((got = waitpid(pid, &st, 0)) == -1 && errno == EINTR && n++ < 10)
				;
			fprintf(stderr, "prepare child wait %d errno %d\n", (int)got, errno);
			OK(got == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
		}
	}
	EXPECT_EXIT(EX_OSERR, { set_config_value("rundir", rundir); fail_socket = EMFILE;
	    bhyve_prepare_control(&the_vm); });
	/* Rights for stdout or stderr, or capability mode itself, cannot be
	 * applied: bhyve refuses to run unsandboxed. */
	EXPECT_EXIT(EX_OSERR, { set_config_value("rundir", rundir); fail_cap_fd = STDOUT_FILENO;
	    bhyve_prepare_control(&the_vm); });
	EXPECT_EXIT(EX_OSERR, { set_config_value("rundir", rundir); fail_cap_fd = STDERR_FILENO;
	    bhyve_prepare_control(&the_vm); });
	EXPECT_EXIT(EX_OSERR, { set_config_value("rundir", rundir); fail_cap_enter = 1;
	    bhyve_prepare_control(&the_vm); });
	printf("control prepare (journal, IPC, Capsicum): %d checks\n", checks - before);
}

int
main(void)
{
	signal(SIGPIPE, SIG_IGN);
	init_config();
	test_numa();
	test_kernel_startup();
	test_cpu_barrier_init_and_loop();
	test_cpu_barrier();
	test_ipc();
	test_prepare_control();
	printf("PASS: %d control checks\n", checks);
	return (0);
}

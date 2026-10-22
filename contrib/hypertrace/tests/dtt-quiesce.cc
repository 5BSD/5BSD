/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * quiesce_guest_tracing() with real child processes owned through process
 * descriptors, using the actual daemon objects. The children are this
 * test's own pdfork(2) children that only sleep; no tracing program is run.
 *
 * Oracles: success requires every child to be dead and reaped (kill(pid, 0)
 * reports ESRCH) and its ledger entry removed; when any child lacks a
 * process descriptor no child may be signalled (all remain alive); each
 * injected poll/pdwait/lock/clock fault returns its exact errno.
 */
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <shared_mutex>
#include <memory>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_io.h"
#include "dtraced_state.h"

using namespace dtraced;

static pthread_t main_thread;
static std::atomic<int> poll_mode{0};	/* 0 real, 1 EINTR once, 2 POLLERR, 3 timeout, 4 EFAULT */
static std::atomic<int> pdwait_errno{0};
static std::atomic<int64_t> skew_s{0};
static std::atomic<int> skew_at{0};
static std::atomic<int> clock_fail_after{-1};

extern "C" int __real_poll(struct pollfd *, nfds_t, int);
extern "C" int
__wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	if (pthread_equal(pthread_self(), main_thread) && n == 1 &&
	    fds[0].events == POLLHUP) {
		int mode = poll_mode.load();
		if (mode == 1) {
			poll_mode.store(0);
			errno = EINTR;
			return (-1);
		}
		if (mode == 2) {
			fds[0].revents = POLLERR;
			return (1);
		}
		if (mode == 3) {
			skew_s.store(100);
			fds[0].revents = 0;
			return (0);
		}
		if (mode == 4) {
			errno = EFAULT;
			return (-1);
		}
	}
	return (__real_poll(fds, n, timeout));
}

extern "C" int __real_pdwait(int, int *, int, struct __wrusage *, struct __siginfo *);
extern "C" int
__wrap_pdwait(int fd, int *status, int options, struct __wrusage *ru,
    struct __siginfo *info)
{
	int e = pdwait_errno.exchange(0);
	if (e) {
		(void)__real_pdwait(fd, status, options, ru, info);
		errno = e;
		return (-1);
	}
	return (__real_pdwait(fd, status, options, ru, info));
}

extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	int r = __real_clock_gettime(id, ts);
	if (r == 0 && id == CLOCK_MONOTONIC &&
	    pthread_equal(pthread_self(), main_thread)) {
		int left = clock_fail_after.load();
		if (left == 0) {
			errno = EIO;
			return (-1);
		}
		if (left > 0)
			clock_fail_after.fetch_sub(1);
		int at = skew_at.load();
		if (at > 0 && skew_at.fetch_sub(1) == 1)
			skew_s.store(100);
		ts->tv_sec += skew_s.load();
	}
	return (r);
}

static void
reset()
{
	poll_mode.store(0);
	pdwait_errno.store(0);
	skew_s.store(0);
	skew_at.store(0);
	clock_fail_after.store(-1);
}

struct child {
	pid_t pid = -1;
	int fd = -1;
};

static child
spawn(bool exit_now = false)
{
	child c;
	fflush(nullptr);
	c.pid = pdfork(&c.fd, PD_CLOEXEC);
	CHECK(c.pid >= 0);
	if (c.pid == 0) {
		if (!exit_now)
			sleep(30);
		_exit(0);
	}
	return (c);
}

static bool
alive(pid_t pid)
{
	return (kill(pid, 0) == 0);
}

struct fixture {
	temp_tree tree{"dtt-quiesce"};
	std::unique_ptr<dir> inbound;
	state s{};
	std::vector<child> children;
	fixture()
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		inbound->state = &s;
		s.inbounddir = inbound.get();
	}
	void own(const child &c, bool with_fd = true)
	{
		s.pidlist.insert(c.pid);
		if (with_fd)
			s.pidfds.emplace(c.pid, c.fd);
		children.push_back(c);
	}
	~fixture()
	{
		for (auto &c : children) {
			if (c.fd >= 0) {
				(void)pdkill(c.fd, SIGKILL);
				int st;
				(void)__real_pdwait(c.fd, &st, WEXITED, nullptr, nullptr);
				close(c.fd);
			}
		}
		s.inbounddir = nullptr;
	}
};

static void
test_success()
{
	reset();
	fixture f;
	for (int i = 0; i < 3; ++i)
		f.own(spawn());
	f.own(spawn(true));	/* already exiting: SIGKILL may see ESRCH */
	/* a ledger entry for one child must be removed */
	char name[32];
	snprintf(name, sizeof(name), ".child.%d", f.children[0].pid);
	int lf = openat(f.inbound->dirfd, name, O_WRONLY | O_CREAT, 0600);
	CHECK(lf >= 0);
	close(lf);
	poll_mode.store(1);	/* one interrupted wait */
	CHECK(quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(5000)));
	CHECK(f.s.cleanup_in_progress.load());
	for (auto &c : f.children)
		CHECK(!alive(c.pid) && errno == ESRCH);
	struct stat st;
	CHECK(fstatat(f.inbound->dirfd, name, &st, 0) != 0 && errno == ENOENT);
	/* An empty session quiesces trivially. */
	fixture g;
	CHECK(quiesce_guest_tracing(&g.s, dtraced_io_deadline_after(1000)));
}

static void
test_capability_check()
{
	reset();
	/* A child without a process descriptor: refuse before signalling. */
	{
		fixture f;
		child a = spawn(), b = spawn();
		f.own(a);
		f.own(b, false);
		errno = 0;
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)) &&
		    errno == EPROTO);
		CHECK(alive(a.pid) && alive(b.pid));
	}
	{	/* PID 1 can never be owned */
		fixture f;
		child a = spawn();
		f.own(a);
		f.s.pidlist.insert(1);
		f.s.pidfds.emplace(1, a.fd);
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)) &&
		    errno == EPROTO);
		CHECK(alive(a.pid));
		f.s.pidfds.erase(1);
	}
	{	/* descriptor that is not a process descriptor */
		fixture f;
		int devnull = open("/dev/null", O_RDONLY);
		f.s.pidlist.insert(4242);
		f.s.pidfds.emplace(4242, devnull);
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)));
		CHECK(errno != ESRCH);
		close(devnull);
	}
}

static void
test_wait_faults()
{
	struct { int mode; int expect; } polls[] = {
		{2, EIO}, {3, ETIMEDOUT}, {4, EFAULT},
	};
	for (auto &p : polls) {
		reset();
		fixture f;
		f.own(spawn());
		poll_mode.store(p.mode);
		errno = 0;
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)) &&
		    errno == p.expect);
	}
	{	/* reaping fails */
		reset();
		fixture f;
		f.own(spawn());
		pdwait_errno.store(ECHILD);
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)) &&
		    errno == ECHILD);
	}
	{	/* ledger cannot be retired */
		reset();
		fixture f;
		child c = spawn();
		f.own(c);
		char name[32];
		snprintf(name, sizeof(name), ".child.%d", c.pid);
		int lf = openat(f.inbound->dirfd, name, O_WRONLY | O_CREAT, 0600);
		CHECK(lf >= 0);
		close(lf);
		std::string in = std::string(f.tree.path) + "/inbound";
		CHECK(chmod(in.c_str(), 0500) == 0);
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)) &&
		    errno == EACCES);
		CHECK(chmod(in.c_str(), 0700) == 0);
		CHECK(!alive(c.pid));
	}
	{	/* no inbound journal to retire into */
		reset();
		fixture f;
		f.own(spawn());
		f.s.inbounddir = nullptr;
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(2000)));
	}
}

static void
test_deadlines_and_locks()
{
	reset();
	{
		fixture f;
		CHECK(!quiesce_guest_tracing(nullptr, 1) && errno == EINVAL);
		CHECK(!quiesce_guest_tracing(&f.s, -1) && errno == EINVAL);
		CHECK(!quiesce_guest_tracing(&f.s, 0) && errno == ETIMEDOUT);
	}
	{	/* a launch in flight holds the shared admission gate */
		fixture f;
		std::shared_lock launch(f.s.launch_gate);
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(80)) &&
		    errno == ETIMEDOUT);
	}
	{	/* the child registry is busy */
		fixture f;
		std::atomic<bool> held{false}, release{false};
		std::thread holder([&] {
			std::lock_guard lock(f.s.pidlistmtx);
			held.store(true);
			while (!release.load())
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
		});
		CHECK(eventually([&] { return held.load(); }));
		CHECK(!quiesce_guest_tracing(&f.s, dtraced_io_deadline_after(80)) &&
		    errno == ETIMEDOUT);
		release.store(true);
		holder.join();
	}
	/* Clock failure in each lock acquisition and in the final check. */
	for (int fail = 0; fail < 3; ++fail) {
		reset();
		fixture f;
		int64_t deadline = dtraced_io_deadline_after(2000);
		clock_fail_after.store(fail);
		CHECK(!quiesce_guest_tracing(&f.s, deadline) && errno == EIO);
	}
	{	/* the budget runs out after the children are gone */
		reset();
		fixture f;
		int64_t deadline = dtraced_io_deadline_after(2000);
		skew_at.store(3);
		CHECK(!quiesce_guest_tracing(&f.s, deadline) && errno == ETIMEDOUT);
	}
	{	/* clock failure while waiting for a child */
		reset();
		fixture f;
		f.own(spawn());
		int64_t deadline = dtraced_io_deadline_after(2000);
		clock_fail_after.store(2);
		CHECK(!quiesce_guest_tracing(&f.s, deadline) && errno == EIO);
	}
	reset();
}

int
main()
{
	alarm(200);
	main_thread = pthread_self();
	signal(SIGPIPE, SIG_IGN);
	test_success();
	test_capability_check();
	test_wait_faults();
	test_deadlines_and_locks();
	printf("dtt-quiesce: %u checks passed\n", harness_checks);
	return (0);
}

/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Collector crash/exit evidence helpers (dtraced_process.cc, actual object):
 * collector_handle_retired, collector_process_pin, collector_process_exited
 * and collector_process_reaper_empty. The HyperTrace device, procdesc ioctls
 * and pdopenpid(2) are injected; nothing opens a tracing device. Real
 * pdfork(2) children supply genuine process descriptors for exit polling.
 *
 * Oracles: an independent decision table for every reaper-snapshot flag
 * combination; exact echo checks for the handle query; birth identity
 * comparison field by field; the rule that a missing PID, a failed query or
 * any inconsistent answer is never treated as proof of exit (the helpers
 * return -1, not 1), and that a rejected pin never leaks its descriptor.
 */
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <sys/wait.h>
#include <cstdarg>
#include <map>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_process.h"

using namespace dtraced;

static int device_open_errno;
static int device_fd = -1;
static int handle_ioctl_errno;
static dtrace_handle_lifetime_t handle_reply;
static bool handle_echo = true;
static int close_errno_fd = -1;
static int pdopen_errno;
static int pdopen_target = -1;	/* descriptor duplicated by pdopenpid */
static int birth_errno;
static pd_birth_identity birth_reply;
static int reaper_errno;
static pd_reaper_exit reaper_reply;
static int poll_mode;	/* 0 real, 1 error, 2 POLLERR, 3 POLLIN|POLLHUP */

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	int mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	va_end(ap);
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		if (device_open_errno) {
			errno = device_open_errno;
			return (-1);
		}
		device_fd = __real_open("/dev/null", O_RDONLY);
		return (device_fd);
	}
	CHECK(strncmp(path, "/dev/", 5) != 0 || strcmp(path, "/dev/null") == 0);
	return (__real_open(path, flags, mode));
}

extern "C" int __real_close(int);
extern "C" int
__wrap_close(int fd)
{
	int r = __real_close(fd);
	if (fd == close_errno_fd) {
		close_errno_fd = -1;
		errno = EIO;
		return (-1);
	}
	return (r);
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (request == HYPERTRACE_IOC_HANDLE_QUERY) {
		CHECK(fd == device_fd);
		if (handle_ioctl_errno) {
			errno = handle_ioctl_errno;
			return (-1);
		}
		auto *q = static_cast<dtrace_handle_lifetime_t *>(arg);
		if (handle_echo) {
			handle_reply.generation[0] = q->generation[0];
			handle_reply.generation[1] = q->generation[1];
			handle_reply.serial = q->serial;
		}
		*q = handle_reply;
		return (0);
	}
	if (request == PDIOC_GET_BIRTH_IDENTITY) {
		if (birth_errno) {
			errno = birth_errno;
			return (-1);
		}
		*static_cast<pd_birth_identity *>(arg) = birth_reply;
		return (0);
	}
	if (request == PDIOC_GET_REAPER_EXIT) {
		if (reaper_errno) {
			errno = reaper_errno;
			return (-1);
		}
		*static_cast<pd_reaper_exit *>(arg) = reaper_reply;
		return (0);
	}
	return (__real_ioctl(fd, request, arg));
}

extern "C" int
__wrap_pdopenpid(pid_t, int)
{
	if (pdopen_errno) {
		errno = pdopen_errno;
		return (-1);
	}
	return (fcntl(pdopen_target, F_DUPFD_CLOEXEC, 0));
}

extern "C" int __real_poll(struct pollfd *, nfds_t, int);
extern "C" int
__wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	if (poll_mode == 1) {
		errno = EINTR;
		return (-1);
	}
	if (poll_mode == 2) {
		fds[0].revents = POLLERR;
		return (1);
	}
	if (poll_mode == 3) {
		fds[0].revents = POLLIN | POLLHUP;
		return (1);
	}
	return (__real_poll(fds, n, timeout));
}

static int
open_fds()
{
	int n = 0;
	for (int fd = 0; fd < 256; ++fd)
		if (fcntl(fd, F_GETFD) != -1)
			++n;
	return (n);
}

static std::array<uint8_t, 24>
identity(uint64_t g0, uint64_t g1, uint64_t serial)
{
	std::array<uint8_t, 24> id{};
	for (int i = 0; i < 8; ++i) {
		id[i] = (uint8_t)(g0 >> (8 * i));
		id[8 + i] = (uint8_t)(g1 >> (8 * i));
		id[16 + i] = (uint8_t)(serial >> (8 * i));
	}
	return (id);
}

static void
test_handle_retired()
{
	int baseline = open_fds();
	CHECK(collector_handle_retired(identity(0, 0, 5)) == -1 && errno == EINVAL);
	CHECK(collector_handle_retired(identity(1, 0, 0)) == -1 && errno == EINVAL);
	device_open_errno = ENOENT;
	CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == ENOENT);
	device_open_errno = 0;
	handle_ioctl_errno = EPERM;
	CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == EPERM);
	handle_ioctl_errno = 0;
	handle_reply = {};
	handle_echo = true;
	handle_reply.retired = 0;
	CHECK(collector_handle_retired(identity(1, 2, 3)) == 0);
	handle_reply.retired = 1;
	CHECK(collector_handle_retired(identity(0, 2, 3)) == 1);	/* g1 suffices */
	handle_reply.retired = 2;
	CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == EPROTO);
	handle_reply.retired = 1;
	handle_reply.reserved = 1;
	CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == EPROTO);
	handle_reply.reserved = 0;
	/* an answer for another handle is not evidence */
	handle_echo = false;
	for (int field = 0; field < 3; ++field) {
		handle_reply.generation[0] = 1;
		handle_reply.generation[1] = 2;
		handle_reply.serial = 3;
		if (field == 0) handle_reply.generation[0] = 9;
		if (field == 1) handle_reply.generation[1] = 9;
		if (field == 2) handle_reply.serial = 9;
		CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == EPROTO);
	}
	handle_echo = true;
	/* closing the query descriptor fails after a valid answer */
	handle_reply.retired = 1;
	close_errno_fd = -2;	/* armed below with the real descriptor */
	device_open_errno = 0;
	{
		/* the device descriptor number is predictable: lowest free */
		int probe = __real_open("/dev/null", O_RDONLY);
		__real_close(probe);
		close_errno_fd = probe;
		CHECK(collector_handle_retired(identity(1, 2, 3)) == -1 && errno == EIO);
	}
	CHECK(open_fds() == baseline);
}

static void
test_process_pin()
{
	int pd;
	fflush(nullptr);
	pid_t child = pdfork(&pd, PD_CLOEXEC);
	CHECK(child >= 0);
	if (child == 0) {
		sleep(30);
		_exit(0);
	}
	pdopen_target = pd;
	pd_birth_identity expected{child, 0, 100, 7};
	int result = -1;
	int baseline = open_fds();
	/* argument validation */
	CHECK(collector_process_pin(child, expected, nullptr) == -1 && errno == EINVAL);
	CHECK(collector_process_pin(1, {1, 0, 100, 7}, &result) == -1 && errno == EINVAL);
	CHECK(collector_process_pin(child, {child + 1, 0, 100, 7}, &result) == -1 &&
	    errno == EINVAL);
	CHECK(collector_process_pin(child, {child, 1, 100, 7}, &result) == -1 &&
	    errno == EINVAL);
	CHECK(collector_process_pin(child, {child, 0, 100, 1000000}, &result) == -1 &&
	    errno == EINVAL);
	CHECK(collector_process_pin(child, {child, 0, 0, 0}, &result) == -1 &&
	    errno == EINVAL);
	/* the process cannot be pinned */
	pdopen_errno = ESRCH;
	CHECK(collector_process_pin(child, expected, &result) == -1 && errno == ESRCH);
	pdopen_errno = 0;
	/* birth query fails */
	birth_errno = EOPNOTSUPP;
	CHECK(collector_process_pin(child, expected, &result) == -1 &&
	    errno == EOPNOTSUPP && result == -1);
	birth_errno = 0;
	/* a different birth (recycled PID) is never pinned */
	pd_birth_identity wrong[] = {{child + 1, 0, 100, 7}, {child, 1, 100, 7},
	    {child, 0, 101, 7}, {child, 0, 100, 8}};
	for (auto &w : wrong) {
		birth_reply = w;
		CHECK(collector_process_pin(child, expected, &result) == -1 &&
		    errno == ESTALE && result == -1);
	}
	CHECK(open_fds() == baseline);	/* rejected pins closed their fd */
	birth_reply = expected;
	CHECK(collector_process_pin(child, expected, &result) == 0 && result >= 0);
	pid_t pinned;
	CHECK(pdgetpid(result, &pinned) == 0 && pinned == child);
	/* exit evidence on the pinned descriptor */
	CHECK(collector_process_exited(-1) == -1 && errno == EINVAL);
	CHECK(collector_process_exited(result) == 0);
	poll_mode = 1;
	CHECK(collector_process_exited(result) == -1 && errno == EINTR);
	poll_mode = 2;
	CHECK(collector_process_exited(result) == -1 && errno == EIO);
	poll_mode = 3;
	CHECK(collector_process_exited(result) == -1 && errno == EPROTO);
	poll_mode = 0;
	CHECK(pdkill(pd, SIGKILL) == 0);
	CHECK(eventually([&] { return collector_process_exited(result) == 1; }));
	int bad = dup(result);
	close(bad);
	CHECK(collector_process_exited(bad) == -1 && errno == EBADF);
	int st;
	(void)pdwait(pd, &st, WEXITED, nullptr, nullptr);
	close(result);
	close(pd);
}

static bool
reaper_model_valid(uint32_t flags, uint32_t reserved)
{
	const uint32_t E = PD_REAPER_EXITED, O = PD_REAPER_OWNED, M = PD_REAPER_EMPTY;
	if (reserved != 0 || (flags & ~(E | O | M)) != 0)
		return (false);
	if ((flags & O) && !(flags & E))
		return (false);	/* only an exited process can own a reaper snapshot */
	if ((flags & M) && (flags & (E | O)) != (E | O))
		return (false);	/* empty is meaningful only for an exited owner */
	return (true);
}

static void
test_reaper_snapshot()
{
	CHECK(collector_process_reaper_empty(-1) == -1 && errno == EINVAL);
	int fd = __real_open("/dev/null", O_RDONLY);
	reaper_errno = ENOTTY;
	CHECK(collector_process_reaper_empty(fd) == -1 && errno == ENOTTY);
	reaper_errno = 0;
	for (uint32_t flags = 0; flags < 16; ++flags)
		for (uint32_t reserved : {0u, 1u}) {
			reaper_reply = {flags, reserved};
			errno = 0;
			int got = collector_process_reaper_empty(fd);
			if (!reaper_model_valid(flags, reserved))
				CHECK(got == -1 && errno == EPROTO);
			else
				CHECK(got == (flags == (PD_REAPER_EXITED | PD_REAPER_OWNED |
				    PD_REAPER_EMPTY) ? 1 : 0));
		}
	__real_close(fd);
}

int
main()
{
	alarm(60);
	test_handle_retired();
	test_process_pin();
	test_reaper_snapshot();
	printf("collector-evidence: %u checks passed\n", harness_checks);
	return (0);
}

/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Deadline, framed I/O, descriptor passing and fixed wire codecs from the
 * unmodified dtraced_io.h and dtraced_wire.h headers.
 *
 * Oracles:
 *  - clock arithmetic is recomputed with 128-bit integers;
 *  - transfer/connect/descriptor paths run against scripted syscall results
 *    on a reserved synthetic descriptor; each script states the exact bytes
 *    moved, the errno and the number of syscalls the helper must issue;
 *  - every codec is checked against an independent byte-layout model written
 *    from the documented offsets: encode(x) == model(x), decode(model(x)) == x,
 *    and every single-byte mutation is accepted exactly when the independent
 *    acceptance predicate accepts it.
 * Real socketpairs cover kernel EOF, truncation and SCM_RIGHTS behaviour.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <poll.h>
#include <random>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>
#include "dtraced.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"

static constexpr int SYNTH = 9000;	/* never a real descriptor */
static unsigned checks;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", \
    __FILE__, __LINE__, #x); abort(); } ++checks; } while (0)

/* ---- clock injection ---- */
enum class clock_mode { real, error, fixed };
static clock_mode cmode = clock_mode::real;
static struct timespec cfixed;
static std::deque<struct timespec> cscript;	/* consumed before cfixed */
static unsigned clock_calls;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	if (id != CLOCK_MONOTONIC || cmode == clock_mode::real)
		return (__real_clock_gettime(id, ts));
	++clock_calls;
	if (cmode == clock_mode::error) {
		errno = EIO;
		return (-1);
	}
	if (!cscript.empty()) {
		*ts = cscript.front();
		cscript.pop_front();
	} else
		*ts = cfixed;
	return (0);
}

/* ---- scripted socket syscalls on SYNTH ---- */
struct step {
	char call;	/* 's' send, 'r' recv, 'p' poll, 'c' connect, 'g' getsockopt, 'm' sendmsg */
	ssize_t result;
	int error;	/* errno when result < 0; SO_ERROR for 'g'; revents for 'p' */
};
static std::deque<step> script;
static std::string sent;
static std::string to_receive;
static int send_flags_seen, recv_flags_seen;

static step
next(char call)
{
	if (script.empty() || script.front().call != call) {
		fprintf(stderr, "unexpected syscall %c (next %c)\n", call,
		    script.empty() ? '-' : script.front().call);
		abort();
	}
	step s = script.front();
	script.pop_front();
	return (s);
}

extern "C" ssize_t __real_send(int, const void *, size_t, int);
extern "C" ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags)
{
	if (fd != SYNTH)
		return (__real_send(fd, buf, len, flags));
	step s = next('s');
	send_flags_seen = flags;
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	size_t n = (size_t)s.result < len ? (size_t)s.result : len;
	sent.append((const char *)buf, n);
	return ((ssize_t)n);
}

extern "C" ssize_t __real_recv(int, void *, size_t, int);
extern "C" ssize_t
__wrap_recv(int fd, void *buf, size_t len, int flags)
{
	if (fd != SYNTH)
		return (__real_recv(fd, buf, len, flags));
	step s = next('r');
	recv_flags_seen = flags;
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	size_t n = (size_t)s.result < len ? (size_t)s.result : len;
	CHECK(n <= to_receive.size());
	memcpy(buf, to_receive.data(), n);
	to_receive.erase(0, n);
	return ((ssize_t)n);
}

static int last_poll_timeout;
extern "C" int __real_poll(struct pollfd *, nfds_t, int);
extern "C" int
__wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	if (n != 1 || fds[0].fd != SYNTH)
		return (__real_poll(fds, n, timeout));
	step s = next('p');
	last_poll_timeout = timeout;
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	fds[0].revents = (short)s.error;
	return ((int)s.result);
}

extern "C" int __real_connect(int, const struct sockaddr *, socklen_t);
extern "C" int
__wrap_connect(int fd, const struct sockaddr *a, socklen_t l)
{
	if (fd != SYNTH)
		return (__real_connect(fd, a, l));
	step s = next('c');
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	return (0);
}

extern "C" int __real_getsockopt(int, int, int, void *, socklen_t *);
extern "C" int
__wrap_getsockopt(int fd, int level, int name, void *v, socklen_t *l)
{
	if (fd != SYNTH)
		return (__real_getsockopt(fd, level, name, v, l));
	CHECK(level == SOL_SOCKET && name == SO_ERROR && *l == sizeof(int));
	step s = next('g');
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	memcpy(v, &s.error, sizeof(int));
	return (0);
}

extern "C" ssize_t __real_sendmsg(int, const struct msghdr *, int);
extern "C" ssize_t
__wrap_sendmsg(int fd, const struct msghdr *m, int flags)
{
	if (fd != SYNTH)
		return (__real_sendmsg(fd, m, flags));
	step s = next('m');
	if (s.result < 0) {
		errno = s.error;
		return (-1);
	}
	return (s.result);
}

static void
done()
{
	CHECK(script.empty());
}

static void
set_clock(int64_t sec, long nsec)
{
	cmode = clock_mode::fixed;
	cfixed.tv_sec = sec;
	cfixed.tv_nsec = nsec;
	cscript.clear();
}

/* ---- deadline arithmetic ---- */
static void
test_clock()
{
	cmode = clock_mode::real;
	int64_t a = dtraced_io_milliseconds();
	CHECK(a >= 0);
	cmode = clock_mode::error;
	errno = 0;
	CHECK(dtraced_io_milliseconds() == -1 && errno == EIO);
	CHECK(dtraced_io_deadline_after(5) == -1 && errno == EIO);
	int t = 0;
	CHECK(dtraced_io_remaining_timeout(100, &t) == -1 && errno == EIO);
	/* Independent 128-bit oracle for the conversion. */
	const int64_t secs[] = {0, 1, 999, INT64_MAX / 1000 - 1,
	    INT64_MAX / 1000, INT64_MAX / 1000 + 1, INT64_MAX, -1, INT64_MIN};
	const long nsecs[] = {0, 1, 999999, 1000000, 807000000, 807999999,
	    808000000, 999999999, 1000000000, -1};
	for (int64_t s : secs)
		for (long ns : nsecs) {
			set_clock(s, ns);
			errno = 0;
			int64_t got = dtraced_io_milliseconds();
			__int128 ms = (__int128)s * 1000 + ns / 1000000;
			bool valid = s >= 0 && ns >= 0 && ns < 1000000000L &&
			    ms <= (__int128)INT64_MAX;
			if (valid)
				CHECK(got == (int64_t)ms);
			else
				CHECK(got == -1 && errno == EOVERFLOW);
		}
	/* deadline_from */
	errno = 0;
	CHECK(dtraced_io_deadline_from(-1, 5) == -1 && errno == EINVAL);
	CHECK(dtraced_io_deadline_from(0, 0) == -1 && errno == EINVAL);
	CHECK(dtraced_io_deadline_from(0, -7) == -1 && errno == EINVAL);
	CHECK(dtraced_io_deadline_from(INT64_MAX - 5, 5) == INT64_MAX);
	errno = 0;
	CHECK(dtraced_io_deadline_from(INT64_MAX - 5, 6) == -1 &&
	    errno == EOVERFLOW);
	CHECK(dtraced_io_deadline_from(12, 30) == 42);
	CHECK(dtraced_io_deadline_after(0) == -1 && errno == EINVAL);
	set_clock(10, 0);
	CHECK(dtraced_io_deadline_after(25) == 10025);
	set_clock(INT64_MAX / 1000, 0);
	errno = 0;
	CHECK(dtraced_io_deadline_after(1000) == -1 && errno == EOVERFLOW);
	/* remaining_timeout */
	CHECK(dtraced_io_remaining_timeout(-1, &t) == -1 && errno == EINVAL);
	CHECK(dtraced_io_remaining_timeout(1, nullptr) == -1 && errno == EINVAL);
	set_clock(1, 0);
	CHECK(dtraced_io_remaining_timeout(1000, &t) == -1 && errno == ETIMEDOUT);
	CHECK(dtraced_io_remaining_timeout(999, &t) == -1 && errno == ETIMEDOUT);
	CHECK(dtraced_io_remaining_timeout(1001, &t) == 0 && t == 1);
	CHECK(dtraced_io_remaining_timeout(1000 + (int64_t)INT32_MAX, &t) == 0 &&
	    t == INT32_MAX);
	CHECK(dtraced_io_remaining_timeout(1001 + (int64_t)INT32_MAX, &t) == 0 &&
	    t == INT32_MAX);
	CHECK(dtraced_io_remaining_timeout(INT64_MAX, &t) == 0 && t == INT32_MAX);
	cmode = clock_mode::real;
}

/* ---- framed transfer ---- */
static void
transfer_case(bool writing, size_t length, std::vector<step> steps,
    int expect_rc, size_t expect_transferred, int expect_errno)
{
	script.assign(steps.begin(), steps.end());
	sent.clear();
	to_receive.assign(length, 'q');
	std::string buffer(length, writing ? 'w' : '\0');
	size_t transferred = 77;
	set_clock(100, 0);
	errno = 0;
	int rc = dtraced_io_transfer(SYNTH, buffer.data(), length, writing,
	    100500, &transferred);
	CHECK(rc == expect_rc);
	CHECK(transferred == expect_transferred);
	if (rc != 0)
		CHECK(errno == expect_errno);
	if (writing) {
		CHECK(sent == std::string(expect_transferred, 'w'));
		if (expect_transferred)
			CHECK(send_flags_seen == (MSG_DONTWAIT | MSG_NOSIGNAL));
	} else {
		CHECK(buffer.compare(0, expect_transferred,
		    std::string(expect_transferred, 'q')) == 0);
		if (expect_transferred)
			CHECK(recv_flags_seen == MSG_DONTWAIT);
	}
	done();
	cmode = clock_mode::real;
}

static void
test_transfer()
{
	for (bool w : {false, true}) {
		char c = w ? 's' : 'r';
		/* zero length issues no syscall */
		transfer_case(w, 0, {}, 0, 0, 0);
		/* partial progress, then completion */
		transfer_case(w, 10, {{c, 3, 0}, {c, 7, 0}}, 0, 10, 0);
		/* peer closed */
		transfer_case(w, 10, {{c, 4, 0}, {c, 0, 0}}, -1, 4,
		    w ? EPIPE : ECONNRESET);
		/* EINTR retries without polling */
		transfer_case(w, 5, {{c, -1, EINTR}, {c, 5, 0}}, 0, 5, 0);
		/* hard error */
		transfer_case(w, 5, {{c, 2, 0}, {c, -1, ECONNREFUSED}}, -1, 2,
		    ECONNREFUSED);
		/* would-block: poll timeout keeps waiting, poll EINTR keeps
		 * waiting, readiness resumes transfer */
		transfer_case(w, 6, {{c, -1, EAGAIN}, {'p', 0, 0},
		    {c, -1, EWOULDBLOCK}, {'p', -1, EINTR}, {c, -1, EAGAIN},
		    {'p', 1, w ? POLLOUT : POLLIN}, {c, 6, 0}}, 0, 6, 0);
		CHECK(last_poll_timeout == 500);
		/* poll failure */
		transfer_case(w, 6, {{c, -1, EAGAIN}, {'p', -1, ENOMEM}}, -1, 0,
		    ENOMEM);
		/* invalid descriptor reported by poll */
		transfer_case(w, 6, {{c, 1, 0}, {c, -1, EAGAIN}, {'p', 1, POLLNVAL}},
		    -1, 1, EBADF);
		/* POLLHUP alone retries the syscall, which reports EOF */
		transfer_case(w, 6, {{c, -1, EAGAIN}, {'p', 1, POLLHUP}, {c, 0, 0}},
		    -1, 0, w ? EPIPE : ECONNRESET);
	}
	/* Deadline consumed between the syscall and the poll. */
	script = {{'r', -1, EAGAIN}};
	cmode = clock_mode::fixed;
	cscript = {{100, 0}, {101, 0}};
	cfixed = {101, 0};
	size_t moved = 0;
	char b[4];
	errno = 0;
	CHECK(dtraced_io_transfer(SYNTH, b, sizeof(b), false, 100500, &moved) ==
	    -1 && errno == ETIMEDOUT && moved == 0);
	done();
	/* Expired before the first syscall. */
	set_clock(200, 0);
	CHECK(dtraced_io_transfer(SYNTH, b, sizeof(b), true, 1, &moved) == -1 &&
	    errno == ETIMEDOUT && moved == 0);
	cmode = clock_mode::real;
}

/* ---- connect ---- */
static void
connect_case(std::vector<step> steps, int expect_rc, int expect_errno,
    int64_t deadline = 100500)
{
	script.assign(steps.begin(), steps.end());
	set_clock(100, 0);
	struct sockaddr_un addr{};
	addr.sun_family = AF_UNIX;
	errno = 0;
	int rc = dtraced_io_connect(SYNTH, (struct sockaddr *)&addr,
	    sizeof(addr), deadline);
	CHECK(rc == expect_rc);
	if (rc != 0)
		CHECK(errno == expect_errno);
	done();
	cmode = clock_mode::real;
}

static void
test_connect()
{
	connect_case({}, -1, ETIMEDOUT, 1);
	connect_case({{'c', 0, 0}}, 0, 0);
	connect_case({{'c', -1, ECONNREFUSED}}, -1, ECONNREFUSED);
	for (int pending : {EINPROGRESS, EALREADY, EINTR}) {
		connect_case({{'c', -1, pending}, {'p', 1, POLLOUT}, {'g', 0, 0}},
		    0, 0);
	}
	/* poll timeout and EINTR keep waiting; getsockopt reports progress,
	 * then success */
	connect_case({{'c', -1, EINPROGRESS}, {'p', 0, 0}, {'p', -1, EINTR},
	    {'p', 1, POLLOUT}, {'g', 0, EINPROGRESS}, {'p', 1, POLLOUT},
	    {'g', 0, EALREADY}, {'p', 1, POLLOUT}, {'g', 0, 0}}, 0, 0);
	connect_case({{'c', -1, EINPROGRESS}, {'p', -1, EFAULT}}, -1, EFAULT);
	connect_case({{'c', -1, EINPROGRESS}, {'p', 1, POLLNVAL}}, -1, EBADF);
	connect_case({{'c', -1, EINPROGRESS}, {'p', 1, POLLOUT},
	    {'g', -1, ENOTSOCK}}, -1, ENOTSOCK);
	connect_case({{'c', -1, EINPROGRESS}, {'p', 1, POLLOUT | POLLERR},
	    {'g', 0, ECONNREFUSED}}, -1, ECONNREFUSED);
	/* deadline expires while pending */
	script = {{'c', -1, EINPROGRESS}, {'p', 0, 0}};
	cmode = clock_mode::fixed;
	cscript = {{100, 0}, {100, 0}};
	cfixed = {101, 0};
	struct sockaddr_un addr{};
	errno = 0;
	CHECK(dtraced_io_connect(SYNTH, (struct sockaddr *)&addr, sizeof(addr),
	    100500) == -1 && errno == ETIMEDOUT);
	done();
	cmode = clock_mode::real;
}

/* ---- sizes over real sockets ---- */
static void
test_sizes()
{
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	std::mt19937_64 rng(0x5eed);
	for (int i = 0; i < 2000; ++i) {
		uint64_t v = i < 70 ? (i < 64 ? 1ull << i : ~0ull - (uint64_t)i) :
		    rng();
		size_t t = 0;
		int64_t deadline = dtraced_io_deadline_after(5000);
		CHECK(dtraced_io_write_size(sv[0], (size_t)v, deadline, &t) == 0 &&
		    t == 8);
		unsigned char raw[8];
		CHECK(recv(sv[1], raw, 8, MSG_WAITALL) == 8);
		for (int b = 0; b < 8; ++b)
			CHECK(raw[b] == (unsigned char)(v >> (8 * b)));
		CHECK(send(sv[0], raw, 8, 0) == 8);
		size_t back = 0;
		CHECK(dtraced_io_read_size(sv[1], &back, deadline, &t) == 0 &&
		    back == v && t == 8);
	}
	/* short frame then EOF */
	CHECK(send(sv[0], "abc", 3, 0) == 3);
	CHECK(shutdown(sv[0], SHUT_WR) == 0);
	size_t back = 0, t = 0;
	errno = 0;
	CHECK(dtraced_io_read_size(sv[1], &back, dtraced_io_deadline_after(2000),
	    &t) == -1 && errno == ECONNRESET && t == 3);
	close(sv[0]);
	close(sv[1]);
	/* timeout with nothing to read */
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	errno = 0;
	CHECK(dtraced_io_read_size(sv[1], &back, dtraced_io_deadline_after(30),
	    &t) == -1 && errno == ETIMEDOUT && t == 0);
	/* writing to a closed peer fails with EPIPE, not SIGPIPE */
	close(sv[1]);
	errno = 0;
	CHECK(dtraced_io_write_size(sv[0], 9, dtraced_io_deadline_after(2000),
	    &t) == -1 && errno == EPIPE);
	close(sv[0]);
}

/* ---- descriptor passing ---- */
static int
open_count()
{
	int n = 0;
	for (int fd = 0; fd < 512; ++fd)
		if (fcntl(fd, F_GETFD) != -1)
			++n;
	return (n);
}

static void
send_raw_rights(int sock, unsigned char marker, const std::vector<int> &fds,
    size_t bytes = 1)
{
	unsigned char payload[2] = {marker, marker};
	struct iovec iov = {payload, bytes};
	std::vector<unsigned char> control(CMSG_SPACE(sizeof(int) *
	    (fds.empty() ? 1 : fds.size())));
	struct msghdr msg{};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (!fds.empty()) {
		msg.msg_control = control.data();
		msg.msg_controllen = CMSG_SPACE(sizeof(int) * fds.size());
		struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
		memcpy(CMSG_DATA(c), fds.data(), sizeof(int) * fds.size());
	}
	CHECK(sendmsg(sock, &msg, 0) == (ssize_t)bytes);
}

static void
test_fd_passing()
{
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	int baseline = open_count();
	int devnull = open("/dev/null", O_RDONLY);
	CHECK(devnull >= 0);
	struct stat expected{}, actual{};
	CHECK(fstat(devnull, &expected) == 0);
	CHECK(dtraced_io_send_fd(sv[0], devnull, dtraced_io_deadline_after(2000)) == 0);
	int got = dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000));
	CHECK(got >= 0 && got != devnull);
	CHECK(fstat(got, &actual) == 0 && actual.st_ino == expected.st_ino &&
	    actual.st_dev == expected.st_dev);
	CHECK((fcntl(got, F_GETFD) & FD_CLOEXEC) != 0);
	close(got);
	/* missing rights */
	send_raw_rights(sv[0], 0xa5, {});
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000)) == -1 &&
	    errno == EPROTO);
	/* wrong marker closes the received descriptor */
	send_raw_rights(sv[0], 0x5a, {devnull});
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000)) == -1 &&
	    errno == EPROTO);
	/* two descriptors: both closed, rejected */
	send_raw_rights(sv[0], 0xa5, {devnull, devnull});
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000)) == -1 &&
	    errno == EPROTO);
	/* more rights than the control buffer: truncated, rejected */
	send_raw_rights(sv[0], 0xa5, {devnull, devnull, devnull, devnull, devnull,
	    devnull});
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000)) == -1 &&
	    errno == EPROTO);
	close(devnull);
	CHECK(open_count() == baseline);
	/* timeout and EOF */
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(30)) == -1 &&
	    errno == ETIMEDOUT);
	close(sv[0]);
	errno = 0;
	CHECK(dtraced_io_recv_fd(sv[1], dtraced_io_deadline_after(2000)) == -1 &&
	    errno == ECONNRESET);
	errno = 0;
	CHECK(dtraced_io_send_fd(sv[1], 0, dtraced_io_deadline_after(2000)) == -1 &&
	    errno == EPIPE);
	close(sv[1]);
	/* expired deadlines */
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	set_clock(5, 0);
	CHECK(dtraced_io_send_fd(sv[0], 0, 1) == -1 && errno == ETIMEDOUT);
	CHECK(dtraced_io_recv_fd(sv[1], 1) == -1 && errno == ETIMEDOUT);
	cmode = clock_mode::real;
	close(sv[0]);
	close(sv[1]);
	/* scripted sendmsg outcomes */
	struct { std::vector<step> steps; int rc; int err; } cases[] = {
		{{{'m', 1, 0}}, 0, 0},
		{{{'m', 0, 0}}, -1, EPIPE},
		{{{'m', -1, EINTR}, {'m', 1, 0}}, 0, 0},
		{{{'m', -1, EMSGSIZE}}, -1, EMSGSIZE},
		{{{'m', -1, EAGAIN}, {'p', 0, 0}, {'m', -1, EWOULDBLOCK},
		    {'p', -1, EINTR}, {'m', 1, 0}}, 0, 0},
		{{{'m', -1, EAGAIN}, {'p', -1, EINVAL}}, -1, EINVAL},
		{{{'m', -1, EAGAIN}, {'p', 1, POLLNVAL}}, -1, EBADF},
	};
	for (auto &c : cases) {
		script.assign(c.steps.begin(), c.steps.end());
		set_clock(100, 0);
		errno = 0;
		int rc = dtraced_io_send_fd(SYNTH, 0, 100500);
		CHECK(rc == c.rc);
		if (rc)
			CHECK(errno == c.err);
		done();
	}
	/* deadline consumed between sendmsg and poll */
	script = {{'m', -1, EAGAIN}};
	cscript = {{100, 0}, {101, 0}};
	cfixed = {101, 0};
	CHECK(dtraced_io_send_fd(SYNTH, 0, 100500) == -1 && errno == ETIMEDOUT);
	done();
	cmode = clock_mode::real;
}

/* ---- independent wire models ---- */
static std::mt19937_64 rng(20261021);
static void
fill(uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; ++i)
		p[i] = (uint8_t)rng();
}
static void
le(std::vector<uint8_t> &w, size_t off, uint64_t v, unsigned bytes)
{
	for (unsigned i = 0; i < bytes; ++i)
		w[off + i] = (uint8_t)(v >> (8 * i));
}
static uint64_t
rd(const std::vector<uint8_t> &w, size_t off, unsigned bytes)
{
	uint64_t v = 0;
	for (unsigned i = 0; i < bytes; ++i)
		v |= (uint64_t)w[off + i] << (8 * i);
	return (v);
}
static bool
zero(const std::vector<uint8_t> &w, size_t off, size_t n)
{
	for (size_t i = 0; i < n; ++i)
		if (w[off + i] != 0)
			return (false);
	return (true);
}
static bool
canonical(const std::vector<uint8_t> &w, size_t off, size_t n)
{
	size_t i = 0;
	while (i < n && w[off + i] != 0)
		++i;
	if (i == n)
		return (false);
	return (zero(w, off + i, n - i));
}

/* Mutate each byte (and a few random bytes) and compare the decoder's
 * verdict with the independent predicate. */
template <class Decode, class Accept>
static void
mutations(std::vector<uint8_t> base, Decode decode, Accept accept)
{
	std::vector<size_t> positions;
	for (size_t i = 0; i < base.size(); ++i)
		positions.push_back(i);
	for (size_t pos : positions)
		for (uint8_t value : {(uint8_t)0, (uint8_t)1, (uint8_t)0xff,
		    (uint8_t)(base[pos] ^ 0x80), (uint8_t)rng()}) {
			std::vector<uint8_t> w = base;
			w[pos] = value;
			errno = 0;
			bool ok = decode(w);
			CHECK(ok == accept(w));
			if (!ok)
				CHECK(errno == EPROTO);
		}
}

static void
test_scalars()
{
	unsigned char b[8];
	for (int i = 0; i < 4096; ++i) {
		uint64_t v = rng();
		std::vector<uint8_t> w(8);
		le(w, 0, v, 8);
		dtraced_wire_put_u64(b, v);
		CHECK(memcmp(b, w.data(), 8) == 0 && dtraced_wire_get_u64(b) == v);
		dtraced_wire_put_u32(b, (uint32_t)v);
		CHECK(memcmp(b, w.data(), 4) == 0 &&
		    dtraced_wire_get_u32(b) == (uint32_t)v);
		dtraced_wire_put_u16(b, (uint16_t)v);
		CHECK(memcmp(b, w.data(), 2) == 0 &&
		    dtraced_wire_get_u16(b) == (uint16_t)v);
	}
	/* canonical names, exhaustive over 4-byte patterns from {0, 'a'} */
	for (unsigned m = 0; m < 16; ++m) {
		std::vector<uint8_t> w(4);
		for (int i = 0; i < 4; ++i)
			w[i] = (m >> i) & 1 ? 'a' : 0;
		CHECK(dtraced_wire_canonical_name(w.data(), 4) == (int)canonical(w, 0, 4));
	}
	CHECK(dtraced_wire_canonical_name((const unsigned char *)"", 0) == 0);
}

static void
test_init()
{
	for (int i = 0; i < 512; ++i) {
		dtd_initmsg_t m{};
		m.kind = (int32_t)rng();
		m.protocol_version = (uint32_t)rng();
		m.subs = rng();
		fill((uint8_t *)m.ident, sizeof(m.ident));
		fill(m.session_id, sizeof(m.session_id));
		unsigned char wire[DTRACED_INIT_WIRE_SIZE];
		dtraced_wire_encode_init(wire, &m);
		std::vector<uint8_t> w(DTRACED_INIT_WIRE_SIZE);
		le(w, 0, (uint32_t)m.kind, 4);
		le(w, 4, m.protocol_version, 4);
		le(w, 8, m.subs, 8);
		memcpy(&w[16], m.ident, 128);
		memcpy(&w[144], m.session_id, 16);
		CHECK(memcmp(wire, w.data(), w.size()) == 0);
		dtd_initmsg_t d;
		memset(&d, 0x6b, sizeof(d));
		dtraced_wire_decode_init(&d, wire);
		CHECK(d.kind == m.kind && d.protocol_version == m.protocol_version &&
		    d.subs == m.subs && memcmp(d.ident, m.ident, 128) == 0 &&
		    memcmp(d.session_id, m.session_id, 16) == 0);
	}
	dtd_initmsg_t s{};
	s.kind = DTRACED_KIND_DTRACED;
	s.protocol_version = DTRACED_PROTOCOL_VERSION;
	CHECK(dtraced_wire_valid_server_init(&s));
	CHECK(!dtraced_wire_valid_server_init(nullptr));
	dtd_initmsg_t t = s; t.kind = DTRACED_KIND_CONSUMER;
	CHECK(!dtraced_wire_valid_server_init(&t));
	t = s; t.protocol_version--;
	CHECK(!dtraced_wire_valid_server_init(&t));
	t = s; t.subs = 1;
	CHECK(!dtraced_wire_valid_server_init(&t));
	t = s; t.ident[127] = 1;
	CHECK(!dtraced_wire_valid_server_init(&t));
	t = s; t.session_id[15] = 1;
	CHECK(!dtraced_wire_valid_server_init(&t));
	/* read/write over a real socketpair */
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	size_t n = 0;
	CHECK(dtraced_wire_write_init(sv[0], &s, dtraced_io_deadline_after(2000),
	    &n) == 0 && n == DTRACED_INIT_WIRE_SIZE);
	dtd_initmsg_t r{};
	CHECK(dtraced_wire_read_init(sv[1], &r, dtraced_io_deadline_after(2000),
	    &n) == 0 && dtraced_wire_valid_server_init(&r));
	CHECK(send(sv[0], "x", 1, 0) == 1);
	close(sv[0]);
	CHECK(dtraced_wire_read_init(sv[1], &r, dtraced_io_deadline_after(2000),
	    &n) == -1 && errno == ECONNRESET && n == 1);
	close(sv[1]);
}

static void
test_small_records()
{
	/* replay kill */
	for (int i = 0; i < 256; ++i) {
		dtraced_replay_kill_t k{};
		k.pid = (int32_t)rng();
		k.vmid = (uint16_t)rng();
		k.epoch = rng();
		fill(k.source_id, 16);
		unsigned char wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
		memset(wire, 0xcc, sizeof(wire));
		dtraced_wire_encode_replay_kill(wire, &k);
		std::vector<uint8_t> w(32);
		le(w, 0, (uint32_t)k.pid, 4);
		le(w, 4, k.vmid, 2);
		le(w, 8, k.epoch, 8);
		memcpy(&w[16], k.source_id, 16);
		CHECK(memcmp(wire, w.data(), 32) == 0);
		auto accept = [](const std::vector<uint8_t> &v) {
			return v[6] == 0 && v[7] == 0 && (int32_t)rd(v, 0, 4) > 1 &&
			    rd(v, 4, 2) != 0 && rd(v, 4, 2) < DTRACED_WIRE_MAX_VMS &&
			    rd(v, 8, 8) != 0 && !zero(v, 16, 16);
		};
		auto decode = [](const std::vector<uint8_t> &v) {
			dtraced_replay_kill_t d;
			if (dtraced_wire_decode_replay_kill(&d, v.data()) != 0)
				return (false);
			CHECK(d.pid == (int32_t)rd(v, 0, 4) && d.vmid == rd(v, 4, 2) &&
			    d.epoch == rd(v, 8, 8) &&
			    memcmp(d.source_id, &v[16], 16) == 0);
			return (true);
		};
		CHECK(decode(w) == accept(w));
		if (i < 8) {
			k.pid = 2 + i; k.vmid = 1 + i; k.epoch = 1 + i;
			dtraced_wire_encode_replay_kill(wire, &k);
			mutations(std::vector<uint8_t>(wire, wire + 32), decode, accept);
		}
	}
	/* status */
	const uint8_t phases[] = {0, 'a', 'c', 'g', 'i', 'm', 'p', 'r', 't', 'u',
	    'v', 'x'};
	for (int phase = 0; phase < 256; ++phase) {
		dtraced_delivery_status_t st{};
		st.delivery_id = rng();
		st.phase = (uint8_t)phase;
		st.revoked = (uint8_t)(rng() % 3);
		st.replay = (uint8_t)(rng() % 3);
		fill(st.digest, 32);
		unsigned char wire[DTRACED_STATUS_WIRE_SIZE];
		dtraced_wire_encode_status(wire, &st);
		std::vector<uint8_t> w(DTRACED_STATUS_WIRE_SIZE);
		le(w, 0, st.delivery_id, 8);
		w[8] = st.phase; w[9] = st.revoked; w[10] = st.replay;
		memcpy(&w[16], st.digest, 32);
		CHECK(memcmp(wire, w.data(), w.size()) == 0);
		auto accept = [&](const std::vector<uint8_t> &v) {
			bool known = std::find(std::begin(phases), std::end(phases),
			    v[8]) != std::end(phases);
			return known && v[9] <= 1 && v[10] <= 1 && zero(v, 11, 5);
		};
		auto decode = [](const std::vector<uint8_t> &v) {
			dtraced_delivery_status_t d;
			if (dtraced_wire_decode_status(&d, v.data()) != 0)
				return (false);
			CHECK(d.delivery_id == rd(v, 0, 8) && d.phase == v[8] &&
			    d.revoked == v[9] && d.replay == v[10] &&
			    memcmp(d.digest, &v[16], 32) == 0 &&
			    zero(std::vector<uint8_t>(d.reserved, d.reserved + 5), 0, 5));
			return (true);
		};
		CHECK(decode(w) == accept(w));
		if (phase == 'p')
			mutations(w, decode, accept);
	}
	/* stats and ack */
	for (int i = 0; i < 256; ++i) {
		dtraced_stats_t s{rng(), rng(), rng(), rng()};
		unsigned char wire[DTRACED_STATS_WIRE_SIZE];
		dtraced_wire_encode_stats(wire, &s);
		std::vector<uint8_t> w(32);
		le(w, 0, s.forwarder_channels, 8); le(w, 8, s.outbound_deliveries, 8);
		le(w, 16, s.installed_deliveries, 8); le(w, 24, s.revoked_deliveries, 8);
		CHECK(memcmp(wire, w.data(), 32) == 0);
		dtraced_stats_t d{};
		dtraced_wire_decode_stats(&d, wire);
		CHECK(memcmp(&d, &s, sizeof(d)) == 0);
		dtraced_delivery_ack_t a{rng()}, b{};
		unsigned char aw[DTRACED_ACK_WIRE_SIZE];
		dtraced_wire_encode_ack(aw, &a);
		dtraced_wire_decode_ack(&b, aw);
		CHECK(b.delivery_id == a.delivery_id && rd(std::vector<uint8_t>(aw,
		    aw + 8), 0, 8) == a.delivery_id);
	}
	/* status/stats/ack over sockets */
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	dtraced_delivery_status_t st{};
	st.delivery_id = 9; st.phase = 'a';
	unsigned char sw[DTRACED_STATUS_WIRE_SIZE];
	dtraced_wire_encode_status(sw, &st);
	CHECK(send(sv[0], sw, sizeof(sw), 0) == (ssize_t)sizeof(sw));
	dtraced_delivery_status_t got{};
	size_t n;
	CHECK(dtraced_wire_read_status(sv[1], &got, dtraced_io_deadline_after(2000),
	    &n) == 0 && got.delivery_id == 9 && got.phase == 'a');
	sw[8] = 'z';
	CHECK(send(sv[0], sw, sizeof(sw), 0) == (ssize_t)sizeof(sw));
	CHECK(dtraced_wire_read_status(sv[1], &got, dtraced_io_deadline_after(2000),
	    &n) == -1 && errno == EPROTO);
	dtraced_stats_t s{1, 2, 3, 4}, sg{};
	unsigned char stw[DTRACED_STATS_WIRE_SIZE];
	dtraced_wire_encode_stats(stw, &s);
	CHECK(send(sv[0], stw, sizeof(stw), 0) == (ssize_t)sizeof(stw));
	CHECK(dtraced_wire_read_stats(sv[1], &sg, dtraced_io_deadline_after(2000),
	    &n) == 0 && memcmp(&s, &sg, sizeof(s)) == 0);
	dtraced_delivery_ack_t ack{0x0102030405060708ull};
	CHECK(dtraced_wire_write_ack(sv[0], &ack, dtraced_io_deadline_after(2000),
	    &n) == 0 && n == 8);
	unsigned char ab[8];
	CHECK(recv(sv[1], ab, 8, MSG_WAITALL) == 8 && ab[0] == 8 && ab[7] == 1);
	close(sv[0]);
	CHECK(dtraced_wire_read_status(sv[1], &got, dtraced_io_deadline_after(2000),
	    &n) == -1 && errno == ECONNRESET);
	CHECK(dtraced_wire_read_stats(sv[1], &sg, dtraced_io_deadline_after(2000),
	    &n) == -1 && errno == ECONNRESET);
	close(sv[1]);
}

static bool
accept_consumer_ack(const std::vector<uint8_t> &v)
{
	return zero(v, 43, 5) && rd(v, 0, 8) != 0 && !zero(v, 8, 16) &&
	    !zero(v, 24, 16) && rd(v, 40, 2) != 0 &&
	    rd(v, 40, 2) < DTRACED_WIRE_MAX_VMS &&
	    v[42] >= DTRACED_CONSUMER_ACK_NO_DERIVED &&
	    v[42] <= DTRACED_CONSUMER_ACK_DERIVED && rd(v, 48, 8) != 0;
}

static void
test_consumer_records()
{
	for (int i = 0; i < 64; ++i) {
		dtraced_consumer_ack_t a{};
		a.delivery_id = 1 + rng() % 1000;
		fill(a.program_id, 16); a.program_id[0] |= 1;
		fill(a.source_id, 16); a.source_id[0] |= 1;
		a.vmid = 1 + rng() % 1023;
		a.outcome = 1 + rng() % 2;
		a.epoch = 1 + rng() % 1000;
		fill(a.ingress_session, 16); a.ingress_session[3] |= 1;
		unsigned char wire[DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
		memset(wire, 0xee, sizeof(wire));
		dtraced_wire_encode_consumer_execution(wire, &a);
		std::vector<uint8_t> w(DTRACED_CONSUMER_EXECUTION_WIRE_SIZE);
		le(w, 0, a.delivery_id, 8);
		memcpy(&w[8], a.program_id, 16);
		memcpy(&w[24], a.source_id, 16);
		le(w, 40, a.vmid, 2);
		w[42] = a.outcome;
		le(w, 48, a.epoch, 8);
		memcpy(&w[DTRACED_CONSUMER_ACK_WIRE_SIZE], a.ingress_session, 16);
		CHECK(memcmp(wire, w.data(), w.size()) == 0);
		auto ack_decode = [](const std::vector<uint8_t> &v) {
			dtraced_consumer_ack_t d;
			if (dtraced_wire_decode_consumer_ack(&d, v.data()) != 0)
				return (false);
			CHECK(d.delivery_id == rd(v, 0, 8) && d.vmid == rd(v, 40, 2) &&
			    d.outcome == v[42] && d.epoch == rd(v, 48, 8) &&
			    memcmp(d.program_id, &v[8], 16) == 0 &&
			    memcmp(d.source_id, &v[24], 16) == 0);
			return (true);
		};
		auto exec_decode = [](const std::vector<uint8_t> &v) {
			dtraced_consumer_ack_t d;
			if (dtraced_wire_decode_consumer_execution(&d, v.data()) != 0)
				return (false);
			CHECK(memcmp(d.ingress_session,
			    &v[DTRACED_CONSUMER_ACK_WIRE_SIZE], 16) == 0);
			return (true);
		};
		auto exec_accept = [](const std::vector<uint8_t> &v) {
			return !zero(v, DTRACED_CONSUMER_ACK_WIRE_SIZE, 16) &&
			    accept_consumer_ack(v);
		};
		std::vector<uint8_t> ackonly(w.begin(),
		    w.begin() + DTRACED_CONSUMER_ACK_WIRE_SIZE);
		if (i < 4) {
			mutations(ackonly, ack_decode, accept_consumer_ack);
			mutations(w, exec_decode, exec_accept);
		} else {
			CHECK(ack_decode(ackonly) && exec_decode(w));
		}
	}
	/* drain / drain ack / stop / stop ack */
	for (int i = 0; i < 16; ++i) {
		dtraced_consumer_drain_t d{};
		fill(d.token, 16); d.token[0] |= 1;
		fill(d.source_session, 16); d.source_session[0] |= 1;
		fill(d.consumer_session, 16); d.consumer_session[0] |= 1;
		fill(d.program_digest, 32);
		if (i & 1)
			memset(d.program_digest, 0, 16);	/* upper half only */
		d.program_digest[31] |= 1;
		d.vmid = 1 + rng() % 1023;
		d.epoch = 1 + rng();
		d.result = i & 2 ? 1 : 0;
		std::vector<uint8_t> w(DTRACED_CONSUMER_DRAIN_WIRE_SIZE);
		memcpy(&w[0], d.token, 16);
		memcpy(&w[16], d.source_session, 16);
		memcpy(&w[32], d.consumer_session, 16);
		memcpy(&w[48], d.program_digest, 32);
		le(w, 80, d.vmid, 2);
		le(w, 88, d.epoch, 8);
		unsigned char dw[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
		dtraced_wire_encode_consumer_drain(dw, &d);
		CHECK(memcmp(dw, w.data(), w.size()) == 0);
		auto drain_accept = [](const std::vector<uint8_t> &v, size_t o) {
			return !zero(v, o, 16) && !zero(v, o + 16, 16) &&
			    !zero(v, o + 32, 16) && !zero(v, o + 48, 32) &&
			    rd(v, o + 80, 2) != 0 &&
			    rd(v, o + 80, 2) < DTRACED_WIRE_MAX_VMS &&
			    zero(v, o + 82, 6) && rd(v, o + 88, 8) != 0;
		};
		auto check_fields = [&](const dtraced_consumer_drain_t &g,
		    const std::vector<uint8_t> &v, size_t o) {
			CHECK(memcmp(g.token, &v[o], 16) == 0 &&
			    memcmp(g.source_session, &v[o + 16], 16) == 0 &&
			    memcmp(g.consumer_session, &v[o + 32], 16) == 0 &&
			    memcmp(g.program_digest, &v[o + 48], 32) == 0 &&
			    g.vmid == rd(v, o + 80, 2) && g.epoch == rd(v, o + 88, 8));
		};
		auto dec = [&](const std::vector<uint8_t> &v) {
			dtraced_consumer_drain_t g;
			if (dtraced_wire_decode_consumer_drain(&g, v.data()) != 0)
				return (false);
			check_fields(g, v, 0);
			return (true);
		};
		mutations(w, dec, [&](const std::vector<uint8_t> &v) {
			return drain_accept(v, 0); });
		/* drain ack */
		std::vector<uint8_t> aw = w;
		aw.resize(DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE, 0);
		aw[DTRACED_CONSUMER_DRAIN_WIRE_SIZE] = d.result;
		unsigned char adw[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
		dtraced_wire_encode_consumer_drain_ack(adw, &d);
		CHECK(memcmp(adw, aw.data(), aw.size()) == 0);
		auto ack_accept = [&](const std::vector<uint8_t> &v) {
			return v[DTRACED_CONSUMER_DRAIN_WIRE_SIZE] <= 1 &&
			    zero(v, DTRACED_CONSUMER_DRAIN_WIRE_SIZE + 1, 7) &&
			    drain_accept(v, 0);
		};
		auto ack_dec = [&](const std::vector<uint8_t> &v) {
			dtraced_consumer_drain_t g;
			memset(&g, 0x33, sizeof(g));
			dtraced_consumer_drain_t before = g;
			if (dtraced_wire_decode_consumer_drain_ack(&g, v.data()) != 0) {
				CHECK(memcmp(&g, &before, sizeof(g)) == 0);
				return (false);
			}
			check_fields(g, v, 0);
			CHECK(g.result == v[DTRACED_CONSUMER_DRAIN_WIRE_SIZE]);
			return (true);
		};
		mutations(aw, ack_dec, ack_accept);
		/* stop and stop ack add an 8-byte magic */
		std::vector<uint8_t> sw(8);
		memcpy(sw.data(), "HST1\0\0\0\0", 8);
		sw.insert(sw.end(), w.begin(), w.end());
		unsigned char ssw[DTRACED_CONSUMER_STOP_WIRE_SIZE];
		dtraced_wire_encode_consumer_stop(ssw, &d);
		CHECK(memcmp(ssw, sw.data(), sw.size()) == 0);
		mutations(sw, [&](const std::vector<uint8_t> &v) {
			dtraced_consumer_stop_t g;
			if (dtraced_wire_decode_consumer_stop(&g, v.data()) != 0)
				return (false);
			check_fields(g, v, 8);
			return (true);
		}, [&](const std::vector<uint8_t> &v) {
			return memcmp(v.data(), "HST1\0\0\0\0", 8) == 0 &&
			    drain_accept(v, 8);
		});
		std::vector<uint8_t> saw(8);
		memcpy(saw.data(), "HSA1\0\0\0\0", 8);
		saw.insert(saw.end(), aw.begin(), aw.end());
		unsigned char sasw[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
		dtraced_wire_encode_consumer_stop_ack(sasw, &d);
		CHECK(memcmp(sasw, saw.data(), saw.size()) == 0);
		mutations(saw, [&](const std::vector<uint8_t> &v) {
			dtraced_consumer_stop_t g;
			if (dtraced_wire_decode_consumer_stop_ack(&g, v.data()) != 0)
				return (false);
			check_fields(g, v, 8);
			CHECK(g.result == v[8 + DTRACED_CONSUMER_DRAIN_WIRE_SIZE]);
			return (true);
		}, [&](const std::vector<uint8_t> &v) {
			return memcmp(v.data(), "HSA1\0\0\0\0", 8) == 0 &&
			    v[8 + DTRACED_CONSUMER_DRAIN_WIRE_SIZE] <= 1 &&
			    zero(v, 8 + DTRACED_CONSUMER_DRAIN_WIRE_SIZE + 1, 7) &&
			    drain_accept(v, 8);
		});
	}
}

static void
test_info_session()
{
	for (int kind = 0; kind < 6; ++kind)
		for (int variant = 0; variant < 4; ++variant) {
			dtraced_infomsg_t m{};
			m.client_kind = kind;
			if (variant == 0)
				strlcpy(m.client_name, "guest-a", sizeof(m.client_name));
			else if (variant == 1)
				memset(m.client_name, 'z', sizeof(m.client_name));
			else if (variant == 2) {
				strlcpy(m.client_name, "a", sizeof(m.client_name));
				m.client_name[100] = 'x';
			}
			unsigned char wire[DTRACED_INFO_WIRE_SIZE];
			dtraced_wire_encode_info(wire, &m);
			std::vector<uint8_t> w(DTRACED_INFO_WIRE_SIZE);
			le(w, 0, (uint32_t)kind, 4);
			memcpy(&w[4], m.client_name, 128);
			CHECK(memcmp(wire, w.data(), w.size()) == 0);
			auto accept = [](const std::vector<uint8_t> &v) {
				uint64_t k = rd(v, 0, 4);
				return (k == DTRACED_KIND_CONSUMER ||
				    k == DTRACED_KIND_FORWARDER ||
				    k == DTRACED_KIND_DTRACED) && canonical(v, 4, 128);
			};
			auto decode = [](const std::vector<uint8_t> &v) {
				dtraced_infomsg_t d;
				if (dtraced_wire_decode_info(&d, v.data()) != 0)
					return (false);
				CHECK(d.client_kind == (int32_t)rd(v, 0, 4) &&
				    memcmp(d.client_name, &v[4], 128) == 0);
				return (true);
			};
			CHECK(decode(w) == accept(w));
			if (kind == DTRACED_KIND_FORWARDER && variant == 0)
				mutations(w, decode, accept);
		}
	for (int which = 0; which < 2; ++which) {
		const char *magic = which ? "FRE1\0\0\0\0" : "FST1\0\0\0\0";
		uint8_t token[16];
		fill(token, 16);
		token[5] |= 1;
		unsigned char wire[DTRACED_SESSION_STOP_WIRE_SIZE];
		if (which)
			dtraced_wire_encode_session_release(wire, token);
		else
			dtraced_wire_encode_session_stop(wire, token);
		std::vector<uint8_t> w(magic, magic + 8);
		w.insert(w.end(), token, token + 16);
		CHECK(memcmp(wire, w.data(), w.size()) == 0);
		mutations(w, [&](const std::vector<uint8_t> &v) {
			uint8_t out[16];
			int rc = which ? dtraced_wire_decode_session_release(out, v.data()) :
			    dtraced_wire_decode_session_stop(out, v.data());
			if (rc != 0)
				return (false);
			CHECK(memcmp(out, &v[8], 16) == 0);
			return (true);
		}, [&](const std::vector<uint8_t> &v) {
			return memcmp(v.data(), magic, 8) == 0 && !zero(v, 8, 16);
		});
	}
}

static void
test_handoff_records()
{
	/* operation classes from dtraced.h comments: zero-digest operations */
	auto source_without_digest = [](int op) {
		return op == DTRACED_HANDOFF_ABORT ||
		    op == DTRACED_HANDOFF_SOURCE_STATUS ||
		    op == DTRACED_HANDOFF_EXPORT ||
		    op == DTRACED_HANDOFF_SOURCE_GATE_BEGIN ||
		    op == DTRACED_HANDOFF_SOURCE_GATE_ABORT;
	};
	for (int op = 0; op < 256; ++op)
		for (int digest_zero = 0; digest_zero < 2; ++digest_zero) {
			dtraced_handoff_request_t r{};
			r.op = (uint8_t)op;
			fill(r.token, 16); r.token[0] |= 1;
			if (!digest_zero) { fill(r.digest, 32); r.digest[0] |= 1; }
			unsigned char wire[DTRACED_HANDOFF_WIRE_SIZE];
			dtraced_wire_encode_handoff(wire, &r);
			std::vector<uint8_t> w(DTRACED_HANDOFF_WIRE_SIZE);
			w[0] = (uint8_t)op;
			memcpy(&w[1], r.token, 16);
			memcpy(&w[17], r.digest, 32);
			CHECK(memcmp(wire, w.data(), w.size()) == 0);
			auto accept = [&](const std::vector<uint8_t> &v) {
				int o = v[0];
				if (o < DTRACED_HANDOFF_PREPARE ||
				    o > DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT)
					return (false);
				return !zero(v, 1, 16) &&
				    zero(v, 17, 32) == source_without_digest(o);
			};
			auto decode = [](const std::vector<uint8_t> &v) {
				dtraced_handoff_request_t d;
				if (dtraced_wire_decode_handoff(&d, v.data()) != 0)
					return (false);
				CHECK(d.op == v[0] && memcmp(d.token, &v[1], 16) == 0 &&
				    memcmp(d.digest, &v[17], 32) == 0);
				return (true);
			};
			CHECK(decode(w) == accept(w));
			if (op == DTRACED_HANDOFF_COMMIT && !digest_zero)
				mutations(w, decode, accept);
		}
	/* delivery and bind-delivery */
	for (int scope : {0, 3, 1}) {
		dtraced_handoff_bind_delivery_request_t b{};
		auto &r = b.delivery;
		fill(r.token, 16); r.token[1] |= 1;
		fill(r.digest, 32); r.digest[1] |= 1;
		r.delivery_id = 1 + rng() % 99;
		fill(r.program_id, 16); r.program_id[2] |= 1;
		fill(r.source_id, 16); r.source_id[2] |= 1;
		r.scope = (uint8_t)scope;
		fill(b.payload_digest, 32); b.payload_digest[3] |= 1;
		std::vector<uint8_t> w(DTRACED_HANDOFF_DELIVERY_WIRE_SIZE);
		memcpy(&w[0], r.token, 16);
		memcpy(&w[16], r.digest, 32);
		le(w, 48, r.delivery_id, 8);
		memcpy(&w[56], r.program_id, 16);
		memcpy(&w[72], r.source_id, 16);
		w[88] = r.scope;
		unsigned char dw[DTRACED_HANDOFF_DELIVERY_WIRE_SIZE];
		dtraced_wire_encode_handoff_delivery(dw, &r);
		CHECK(memcmp(dw, w.data(), w.size()) == 0);
		auto accept = [](const std::vector<uint8_t> &v) {
			return zero(v, 89, 7) && (v[88] == 0 || v[88] == 3) &&
			    rd(v, 48, 8) != 0 && !zero(v, 0, 16) && !zero(v, 16, 32) &&
			    !zero(v, 56, 16) && !zero(v, 72, 16);
		};
		auto decode = [](const std::vector<uint8_t> &v) {
			dtraced_handoff_delivery_request_t d;
			if (dtraced_wire_decode_handoff_delivery(&d, v.data()) != 0)
				return (false);
			CHECK(memcmp(d.token, &v[0], 16) == 0 &&
			    memcmp(d.digest, &v[16], 32) == 0 &&
			    d.delivery_id == rd(v, 48, 8) &&
			    memcmp(d.program_id, &v[56], 16) == 0 &&
			    memcmp(d.source_id, &v[72], 16) == 0 && d.scope == v[88]);
			return (true);
		};
		mutations(w, decode, accept);
		std::vector<uint8_t> bw = w;
		bw.insert(bw.end(), b.payload_digest, b.payload_digest + 32);
		unsigned char bdw[DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE];
		dtraced_wire_encode_handoff_bind_delivery(bdw, &b);
		CHECK(memcmp(bdw, bw.data(), bw.size()) == 0);
		mutations(bw, [](const std::vector<uint8_t> &v) {
			dtraced_handoff_bind_delivery_request_t d;
			memset(&d, 0x44, sizeof(d));
			auto before = d;
			if (dtraced_wire_decode_handoff_bind_delivery(&d, v.data()) != 0) {
				CHECK(memcmp(&d, &before, sizeof(d)) == 0);
				return (false);
			}
			CHECK(memcmp(d.payload_digest,
			    &v[DTRACED_HANDOFF_DELIVERY_WIRE_SIZE], 32) == 0 &&
			    d.delivery.delivery_id == rd(v, 48, 8));
			return (true);
		}, [&](const std::vector<uint8_t> &v) {
			return accept(v) && v[88] == 0 &&
			    !zero(v, DTRACED_HANDOFF_DELIVERY_WIRE_SIZE, 32);
		});
	}
	/* kill */
	{
		dtraced_handoff_kill_request_t k{};
		fill(k.token, 16); k.token[0] |= 1;
		fill(k.digest, 32); k.digest[0] |= 1;
		k.pid = 4242;
		fill(k.source_id, 16); k.source_id[0] |= 1;
		std::vector<uint8_t> w(DTRACED_HANDOFF_KILL_WIRE_SIZE);
		memcpy(&w[0], k.token, 16);
		memcpy(&w[16], k.digest, 32);
		le(w, 48, (uint32_t)k.pid, 4);
		memcpy(&w[52], k.source_id, 16);
		unsigned char kw[DTRACED_HANDOFF_KILL_WIRE_SIZE];
		dtraced_wire_encode_handoff_kill(kw, &k);
		CHECK(memcmp(kw, w.data(), w.size()) == 0);
		mutations(w, [](const std::vector<uint8_t> &v) {
			dtraced_handoff_kill_request_t d;
			if (dtraced_wire_decode_handoff_kill(&d, v.data()) != 0)
				return (false);
			CHECK(d.pid == (int32_t)rd(v, 48, 4) &&
			    memcmp(d.source_id, &v[52], 16) == 0);
			return (true);
		}, [](const std::vector<uint8_t> &v) {
			return zero(v, 68, 4) && (int32_t)rd(v, 48, 4) > 1 &&
			    !zero(v, 0, 16) && !zero(v, 16, 32) && !zero(v, 52, 16);
		});
	}
	/* cleanup */
	{
		dtraced_handoff_cleanup_request_t c{};
		fill(c.token, 16); c.token[0] |= 1;
		fill(c.digest, 32); c.digest[0] |= 1;
		c.delivery_id = 77;
		std::vector<uint8_t> w(DTRACED_HANDOFF_CLEANUP_WIRE_SIZE);
		memcpy(&w[0], c.token, 16);
		memcpy(&w[16], c.digest, 32);
		le(w, 48, c.delivery_id, 8);
		unsigned char cw[DTRACED_HANDOFF_CLEANUP_WIRE_SIZE];
		dtraced_wire_encode_handoff_cleanup(cw, &c);
		CHECK(memcmp(cw, w.data(), w.size()) == 0);
		mutations(w, [](const std::vector<uint8_t> &v) {
			dtraced_handoff_cleanup_request_t d;
			if (dtraced_wire_decode_handoff_cleanup(&d, v.data()) != 0)
				return (false);
			CHECK(d.delivery_id == rd(v, 48, 8) &&
			    memcmp(d.token, &v[0], 16) == 0 &&
			    memcmp(d.digest, &v[16], 32) == 0);
			return (true);
		}, [](const std::vector<uint8_t> &v) {
			return !zero(v, 0, 16) && !zero(v, 16, 32) && rd(v, 48, 8) != 0;
		});
	}
	/* launch result */
	{
		dtraced_launch_result_t l{};
		l.magic = DTRACED_LAUNCH_MAGIC;
		l.installed = 1;
		strlcpy(l.source_ident, "source", sizeof(l.source_ident));
		std::vector<uint8_t> w(DTRACED_LAUNCH_WIRE_SIZE);
		le(w, 0, l.magic, 8);
		w[8] = 1;
		memcpy(&w[16], l.source_ident, DTRACED_PROGIDENTLEN);
		unsigned char lw[DTRACED_LAUNCH_WIRE_SIZE];
		dtraced_wire_encode_launch(lw, &l);
		CHECK(memcmp(lw, w.data(), w.size()) == 0);
		mutations(w, [](const std::vector<uint8_t> &v) {
			dtraced_launch_result_t d;
			if (dtraced_wire_decode_launch(&d, v.data()) != 0)
				return (false);
			CHECK(d.magic == DTRACED_LAUNCH_MAGIC && d.installed == v[8] &&
			    memcmp(d.source_ident, &v[16], DTRACED_PROGIDENTLEN) == 0);
			return (true);
		}, [](const std::vector<uint8_t> &v) {
			return rd(v, 0, 8) == DTRACED_LAUNCH_MAGIC && zero(v, 9, 7) &&
			    v[8] <= 1;
		});
	}
	/* HPI2 program registration */
	{
		std::vector<uint8_t> w(64, 0);
		memcpy(w.data(), "HPI2", 4);
		fill(&w[8], 32); w[8] |= 1;
		fill(&w[40], 24); w[40] |= 1; w[56] |= 1;
		uint8_t digest[32], life[24];
		CHECK(dtraced_wire_decode_consumer_program_v2(w.data(), 64, digest,
		    life) == 0 && memcmp(digest, &w[8], 32) == 0 &&
		    memcmp(life, &w[40], 24) == 0);
		CHECK(dtraced_wire_decode_consumer_program_v2(nullptr, 64, digest,
		    life) == EPROTO);
		CHECK(dtraced_wire_decode_consumer_program_v2(w.data(), 64, nullptr,
		    life) == EPROTO);
		CHECK(dtraced_wire_decode_consumer_program_v2(w.data(), 64, digest,
		    nullptr) == EPROTO);
		CHECK(dtraced_wire_decode_consumer_program_v2(w.data(), 63, digest,
		    life) == EPROTO);
		for (size_t pos = 0; pos < 64; ++pos)
			for (uint8_t value : {(uint8_t)0, (uint8_t)0x5a}) {
				std::vector<uint8_t> v = w;
				v[pos] = value;
				bool expected = memcmp(v.data(), "HPI2", 4) == 0 &&
				    zero(v, 4, 4) && !zero(v, 8, 32) && !zero(v, 40, 16) &&
				    rd(v, 56, 8) != 0;
				CHECK((dtraced_wire_decode_consumer_program_v2(v.data(), 64,
				    digest, life) == 0) == expected);
			}
	}
}

/* Independent acceptance model of the 520-byte message header. */
static bool
header_model(const std::vector<uint8_t> &v)
{
	uint64_t type = rd(v, 0, 8);
	bool elf = false, kill = false, cleanup = false, info = false,
	    installed = false;
	switch (type) {
	case DTRACED_MSG_ELF: elf = installed = true; break;
	case DTRACED_MSG_CONSUMER_EXECUTION:
	case DTRACED_MSG_CONSUMER_PROGRAM:
	case DTRACED_MSG_CONSUMER_DRAIN:
	case DTRACED_MSG_CONSUMER_STOP: elf = true; break;
	case DTRACED_MSG_KILL: case DTRACED_MSG_KILL_APPLIED: kill = true; break;
	case DTRACED_MSG_CLEANUP: case DTRACED_MSG_CLEANUP_APPLIED:
	case DTRACED_MSG_STATS: cleanup = true; break;
	case DTRACED_MSG_INFO: info = true; break;
	case DTRACED_MSG_INSTALLED: case DTRACED_MSG_UNINSTALLED:
	case DTRACED_MSG_STATUS: case DTRACED_MSG_INGRESS_STATUS:
		installed = true; break;
	case DTRACED_MSG_HANDOFF: case DTRACED_MSG_HANDOFF_DELIVERY:
	case DTRACED_MSG_HANDOFF_KILL: case DTRACED_MSG_HANDOFF_BIND_DELIVERY:
	case DTRACED_MSG_HANDOFF_BIND_KILL: case DTRACED_MSG_HANDOFF_CLEANUP:
	case DTRACED_MSG_HANDOFF_IMPORT: case DTRACED_MSG_HANDOFF_RELEASE_IMPORT:
	case DTRACED_MSG_SESSION_STOP: case DTRACED_MSG_SESSION_RELEASE:
	case DTRACED_MSG_CONSUMER_STOP_COMMIT: break;
	default: return (false);
	}
	/* reserved padding */
	if (!zero(v, 66, 6) || !zero(v, 278, 2) || !zero(v, 314, 6) ||
	    !zero(v, 346, 6))
		return (false);
	/* unused groups are all zero */
	if (!elf && !zero(v, 8, 264)) return (false);
	if (!kill && !zero(v, 272, 32)) return (false);
	if (!cleanup && !zero(v, 304, 24)) return (false);
	if (!cleanup && !info && !zero(v, 328, 8)) return (false);
	if (!installed && !zero(v, 336, 184)) return (false);
	if (elf) {
		uint64_t len = rd(v, 8, 8);
		if (rd(v, 64, 2) >= DTRACED_WIRE_MAX_VMS) return (false);
		if (type == DTRACED_MSG_CONSUMER_EXECUTION &&
		    (len != DTRACED_CONSUMER_EXECUTION_WIRE_SIZE || !zero(v, 16, 256)))
			return (false);
		if (type == DTRACED_MSG_CONSUMER_PROGRAM &&
		    ((len != 32 && len != 64) || !zero(v, 16, 256)))
			return (false);
		if (type == DTRACED_MSG_CONSUMER_DRAIN &&
		    (len != DTRACED_CONSUMER_DRAIN_WIRE_SIZE || !zero(v, 16, 256)))
			return (false);
		if (type == DTRACED_MSG_CONSUMER_STOP &&
		    (len != DTRACED_CONSUMER_STOP_WIRE_SIZE || !zero(v, 16, 256)))
			return (false);
		if (!canonical(v, 80, 64)) return (false);
		uint64_t present = rd(v, 56, 4), filter = rd(v, 60, 4);
		if (present > 1 || filter > 1) return (false);
		/* The program identity is 128 opaque bytes when present. */
		if (present == 0 && !zero(v, 144, 128)) return (false);
	}
	if (kill && ((int32_t)rd(v, 272, 4) <= 1 || rd(v, 276, 2) == 0 ||
	    rd(v, 276, 2) >= DTRACED_WIRE_MAX_VMS || rd(v, 280, 8) == 0 ||
	    zero(v, 288, 16)))
		return (false);
	if (cleanup && rd(v, 312, 2) >= DTRACED_WIRE_MAX_VMS) return (false);
	if (type == DTRACED_MSG_STATS && (rd(v, 312, 2) || rd(v, 320, 8) ||
	    rd(v, 328, 8)))
		return (false);
	if (type == DTRACED_MSG_CLEANUP &&
	    ((rd(v, 312, 2) == 0) != (rd(v, 320, 8) == 0) ||
	    (rd(v, 312, 2) == 0) != (rd(v, 328, 8) == 0)))
		return (false);
	if (type == DTRACED_MSG_CLEANUP_APPLIED && (rd(v, 304, 8) != 0 ||
	    rd(v, 312, 2) == 0 || rd(v, 320, 8) == 0 || rd(v, 328, 8) == 0))
		return (false);
	if (installed) {
		if (rd(v, 344, 2) >= DTRACED_WIRE_MAX_VMS) return (false);
		if (type != DTRACED_MSG_ELF && !canonical(v, 392, 128))
			return (false);
		if (type == DTRACED_MSG_ELF && !zero(v, 336, 184) &&
		    (rd(v, 336, 8) == 0 || rd(v, 344, 2) == 0 || rd(v, 352, 8) == 0 ||
		    zero(v, 360, 16) || zero(v, 376, 16) || zero(v, 392, 16) ||
		    !zero(v, 408, 112)))
			return (false);
	}
	return (true);
}

static std::vector<uint8_t>
header_seed(uint64_t type)
{
	std::vector<uint8_t> v(DTRACED_MSGHDRSIZE, 0);
	le(v, 0, type, 8);
	switch (type) {
	case DTRACED_MSG_ELF:
		le(v, 8, 4096, 8); le(v, 16, 5, 8); v[24] = 1; v[40] = 2;
		le(v, 56, 1, 4); le(v, 64, 3, 2); le(v, 72, 9, 8);
		memcpy(&v[80], "/var/ddtrace/x", 14); memcpy(&v[144], "prog", 4);
		le(v, 336, 1, 8); le(v, 344, 2, 2); le(v, 352, 3, 8);
		v[360] = 4; v[376] = 5; v[392] = 6; v[407] = 7;
		break;
	case DTRACED_MSG_CONSUMER_EXECUTION:
		le(v, 8, DTRACED_CONSUMER_EXECUTION_WIRE_SIZE, 8); break;
	case DTRACED_MSG_CONSUMER_PROGRAM: le(v, 8, 64, 8); break;
	case DTRACED_MSG_CONSUMER_DRAIN:
		le(v, 8, DTRACED_CONSUMER_DRAIN_WIRE_SIZE, 8); break;
	case DTRACED_MSG_CONSUMER_STOP:
		le(v, 8, DTRACED_CONSUMER_STOP_WIRE_SIZE, 8); break;
	case DTRACED_MSG_KILL: case DTRACED_MSG_KILL_APPLIED:
		le(v, 272, 77, 4); le(v, 276, 4, 2); le(v, 280, 5, 8); v[288] = 9;
		break;
	case DTRACED_MSG_CLEANUP:
		le(v, 304, 2, 8); le(v, 312, 3, 2); le(v, 320, 4, 8); le(v, 328, 5, 8);
		break;
	case DTRACED_MSG_CLEANUP_APPLIED:
		le(v, 312, 3, 2); le(v, 320, 4, 8); le(v, 328, 5, 8); break;
	case DTRACED_MSG_INFO: le(v, 328, 11, 8); break;
	case DTRACED_MSG_INSTALLED: case DTRACED_MSG_UNINSTALLED:
	case DTRACED_MSG_STATUS: case DTRACED_MSG_INGRESS_STATUS:
		le(v, 336, 1, 8); le(v, 344, 2, 2); le(v, 352, 3, 8);
		v[360] = 4; v[376] = 5; memcpy(&v[392], "vm0", 3);
		break;
	default: break;
	}
	return (v);
}

static void
test_header()
{
	const uint64_t types[] = {DTRACED_MSG_ELF, DTRACED_MSG_CONSUMER_EXECUTION,
	    DTRACED_MSG_CONSUMER_PROGRAM, DTRACED_MSG_CONSUMER_DRAIN,
	    DTRACED_MSG_CONSUMER_STOP, DTRACED_MSG_KILL, DTRACED_MSG_KILL_APPLIED,
	    DTRACED_MSG_CLEANUP, DTRACED_MSG_CLEANUP_APPLIED, DTRACED_MSG_STATS,
	    DTRACED_MSG_INFO, DTRACED_MSG_INSTALLED, DTRACED_MSG_UNINSTALLED,
	    DTRACED_MSG_STATUS, DTRACED_MSG_INGRESS_STATUS, DTRACED_MSG_HANDOFF,
	    DTRACED_MSG_HANDOFF_DELIVERY, DTRACED_MSG_HANDOFF_KILL,
	    DTRACED_MSG_HANDOFF_BIND_DELIVERY, DTRACED_MSG_HANDOFF_BIND_KILL,
	    DTRACED_MSG_HANDOFF_CLEANUP, DTRACED_MSG_HANDOFF_IMPORT,
	    DTRACED_MSG_HANDOFF_RELEASE_IMPORT, DTRACED_MSG_SESSION_STOP,
	    DTRACED_MSG_SESSION_RELEASE, DTRACED_MSG_CONSUMER_STOP_COMMIT, 9999};
	auto decode = [](const std::vector<uint8_t> &v) {
		dtraced_hdr_t h;
		if (dtraced_wire_decode_header(&h, v.data()) != 0)
			return (false);
		/* Decoding then re-encoding reproduces the wire exactly. */
		unsigned char again[DTRACED_MSGHDRSIZE];
		dtraced_wire_encode_header(again, &h);
		CHECK(memcmp(again, v.data(), DTRACED_MSGHDRSIZE) == 0);
		return (true);
	};
	for (uint64_t type : types) {
		std::vector<uint8_t> seed = header_seed(type);
		CHECK(header_model(seed) == (type != 9999));
		mutations(seed, decode, header_model);
		/* ELF frames without the optional installed group, and with
		 * ident_present clear. */
		if (type == DTRACED_MSG_ELF) {
			std::vector<uint8_t> bare = seed;
			memset(&bare[336], 0, 184);
			memset(&bare[144], 0, 128);
			le(bare, 56, 0, 4);
			CHECK(header_model(bare));
			mutations(bare, decode, header_model);
		}
		if (type == DTRACED_MSG_CLEANUP) {
			std::vector<uint8_t> all = seed;
			memset(&all[312], 0, 16);
			memset(&all[328], 0, 8);
			CHECK(header_model(all));
			mutations(all, decode, header_model);
		}
	}
	/* Regression: libdtrace sends dp_ident from arc4random_buf. Every random
	 * 128-byte identity must be accepted and carried exactly. */
	for (int i = 0; i < 4096; ++i) {
		std::vector<uint8_t> v = header_seed(DTRACED_MSG_ELF);
		fill(&v[144], 128);
		dtraced_hdr_t h;
		CHECK(dtraced_wire_decode_header(&h, v.data()) == 0 &&
		    memcmp(h.elf.ident, &v[144], 128) == 0 && h.elf.ident_present == 1);
		le(v, 56, 0, 4);
		errno = 0;
		CHECK(dtraced_wire_decode_header(&h, v.data()) == -1 && errno == EPROTO);
	}
	/* random multi-byte corruption against the model */
	for (int i = 0; i < 20000; ++i) {
		std::vector<uint8_t> v = header_seed(types[rng() % 26]);
		int edits = 1 + rng() % 4;
		for (int e = 0; e < edits; ++e)
			v[rng() % v.size()] = (uint8_t)(rng() % 3 == 0 ? 0 : rng());
		CHECK(decode(v) == header_model(v));
	}
}

int
main()
{
	alarm(240);
	test_clock();
	test_transfer();
	test_connect();
	test_sizes();
	test_fd_passing();
	test_scalars();
	test_init();
	test_small_records();
	test_consumer_records();
	test_info_session();
	test_handoff_records();
	test_header();
	printf("io-wire: %u checks passed\n", checks);
	return (0);
}

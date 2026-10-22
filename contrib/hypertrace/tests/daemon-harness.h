/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shared fixture helpers for daemon-extra suites. These helpers never start
 * an installed daemon, open tracing devices or operate a VM. Every injected
 * boundary is an explicit --wrap symbol whose wrapper passes all other
 * descriptors and requests through to the real system call.
 */
#ifndef DAEMON_HARNESS_H
#define DAEMON_HARNESS_H
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ftw.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <dttransport.h>

static unsigned harness_checks;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) errno=%d\n", \
    __FILE__, __LINE__, #x, errno); abort(); } ++harness_checks; } while (0)

extern "C" int __llvm_profile_write_file(void) __attribute__((weak));

/* Flush coverage counters before a forked child leaves through _exit. */
static inline void
harness_flush_profile(void)
{
	if (__llvm_profile_write_file != nullptr)
		(void)__llvm_profile_write_file();
}

static inline int
harness_rm(const char *path, const struct stat *, int, struct FTW *)
{
	return (remove(path));
}

/* A private temporary tree; removed recursively on destruction. */
struct temp_tree {
	char path[64];
	explicit temp_tree(const char *tag)
	{
		snprintf(path, sizeof(path), "/tmp/hypertrace-%s.XXXXXX", tag);
		CHECK(mkdtemp(path) != nullptr);
	}
	~temp_tree()
	{
		(void)chmod(path, 0700);
		(void)nftw(path, harness_rm, 16, FTW_DEPTH | FTW_PHYS);
	}
	std::string sub(const char *name) const
	{
		std::string p = std::string(path) + "/" + name;
		if (mkdir(p.c_str(), 0700) != 0 && errno != EEXIST)
			abort();
		return (p);
	}
};

/* Exact-size record I/O on the peer side of a socketpair. */
static inline void
peer_send(int fd, const dtt_entry_t &e)
{
	const unsigned char *p = reinterpret_cast<const unsigned char *>(&e);
	size_t off = 0;
	while (off < sizeof(e)) {
		ssize_t n = write(fd, p + off, sizeof(e) - off);
		if (n < 0 && errno == EINTR)
			continue;
		CHECK(n > 0);
		off += (size_t)n;
	}
}

static inline bool
peer_recv(int fd, dtt_entry_t &e, int timeout_ms = 3000)
{
	unsigned char *p = reinterpret_cast<unsigned char *>(&e);
	size_t off = 0;
	auto end = std::chrono::steady_clock::now() +
	    std::chrono::milliseconds(timeout_ms);
	while (off < sizeof(e)) {
		int left = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
		    end - std::chrono::steady_clock::now()).count();
		if (left <= 0)
			return (false);
		struct pollfd pfd = {fd, POLLIN, 0};
		int r = poll(&pfd, 1, left);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return (false);
		ssize_t n = read(fd, p + off, sizeof(e) - off);
		if (n < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (n <= 0)
			return (false);
		off += (size_t)n;
	}
	return (true);
}

/* True when nothing arrives within the window. */
static inline bool
peer_quiet(int fd, int window_ms)
{
	struct pollfd pfd = {fd, POLLIN, 0};
	return (poll(&pfd, 1, window_ms) == 0);
}

/* True when the peer closes without sending any further byte. */
static inline bool
peer_eof(int fd, int timeout_ms = 5000)
{
	struct pollfd pfd = {fd, POLLIN, 0};
	if (poll(&pfd, 1, timeout_ms) != 1)
		return (false);
	char c;
	ssize_t n;
	do
		n = read(fd, &c, 1);
	while (n < 0 && errno == EINTR);
	return (n == 0);
}

template <class Predicate>
static inline bool
eventually(Predicate p, int timeout_ms = 3000)
{
	auto end = std::chrono::steady_clock::now() +
	    std::chrono::milliseconds(timeout_ms);
	while (std::chrono::steady_clock::now() < end) {
		if (p())
			return (true);
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
	return (p());
}

/* Run fn in a forked child; returns the raw wait status. */
template <class Fn>
static inline int
in_child(Fn fn)
{
	fflush(nullptr);
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		int code = fn();
		harness_flush_profile();
		_exit(code);
	}
	int status = 0;
	while (waitpid(pid, &status, 0) < 0)
		CHECK(errno == EINTR);
	return (status);
}

static inline bool
exited_with(int status, int code)
{
	return (WIFEXITED(status) && WEXITSTATUS(status) == code);
}
#endif

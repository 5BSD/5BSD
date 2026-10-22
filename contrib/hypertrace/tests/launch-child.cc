/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * launch_program() child setup (dtraced_process.cc, actual object) with
 * real pdfork children that exec /usr/bin/true or fail to exec. Coverage
 * counters of the post-fork child are written immediately before execve and
 * _exit (both wrapped to flush, then call the real function), closing the
 * measurement gap where a forked child's counters are lost at exec.
 * PDIOC_GET_BIRTH_IDENTITY is answered for this test's own children.
 *
 * Oracles: success registers exactly the launched pid with its process
 * descriptor (and source, if any) and the child exits 0; exec failure returns
 * the child's errno and registers nothing; refused launches never fork
 * (no child appears, no ledger file is written).
 */
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdarg>
#include <memory>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_process.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

using namespace dtraced;

extern "C" int __real_execve(const char *, char *const[], char *const[]);
extern "C" int
__wrap_execve(const char *path, char *const argv[], char *const envp[])
{
	/* Only /usr/bin/true or a nonexistent path is ever executed here. */
	if (strcmp(path, "/usr/bin/true") != 0 &&
	    strcmp(path, "/nonexistent/hypertrace-launch") != 0)
		abort();
	harness_flush_profile();
	return (__real_execve(path, argv, envp));
}

extern "C" void __real__exit(int) __attribute__((noreturn));
extern "C" void
__wrap__exit(int code)
{
	harness_flush_profile();
	__real__exit(code);
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (request == PDIOC_GET_BIRTH_IDENTITY) {
		pid_t pid;
		if (pdgetpid(fd, &pid) != 0)
			return (-1);
		*static_cast<pd_birth_identity *>(arg) = {pid, 0, 1, 2};
		return (0);
	}
	return (__real_ioctl(fd, request, arg));
}

struct fixture {
	temp_tree tree{"launch-child"};
	std::unique_ptr<dir> inbound;
	state s{};
	fixture()
	{
		inbound = std::make_unique<dir>(tree.sub("inbound").c_str(), nullptr);
		inbound->state = &s;
		s.inbounddir = inbound.get();
	}
	~fixture()
	{
		for (auto &[pid, fd] : s.pidfds) {
			int st;
			(void)pdwait(fd, &st, WEXITED, nullptr, nullptr);
			close(fd);
		}
		s.inbounddir = nullptr;
	}
	/* registered child exits with this status */
	bool registered_exit(pid_t pid, int code)
	{
		auto it = s.pidfds.find(pid);
		if (it == s.pidfds.end() || s.pidlist.count(pid) != 1)
			return (false);
		int st = -1;
		if (pdwait(it->second, &st, WEXITED, nullptr, nullptr) != 0)
			return (false);
		return (WIFEXITED(st) && WEXITSTATUS(st) == code);
	}
	int ledger_files()
	{
		int n = 0;
		DIR *d = opendir((std::string(tree.path) + "/inbound").c_str());
		while (struct dirent *e = readdir(d))
			n += strncmp(e->d_name, ".child.", 7) == 0;
		closedir(d);
		return (n);
	}
};

static void
test_launches()
{
	{	/* host consumer launch */
		fixture f;
		pid_t pid = -1;
		bool installed = true;
		CHECK(launch_program(f.s, "/tmp/elf-host", true, "/usr/bin/true",
		    &installed, &pid));
		CHECK(pid > 1 && !installed && f.registered_exit(pid, 0));
		CHECK(f.ledger_files() == 0);	/* host children are not ledgered */
	}
	{	/* guest launch without identifiers: stdin/stdout from /dev/null,
		 * ledgered before release from the exec gate */
		fixture f;
		pid_t pid = -1;
		CHECK(launch_program(f.s, "/tmp/plain-program", false, "/usr/bin/true",
		    nullptr, &pid));
		CHECK(pid > 1 && f.registered_exit(pid, 0));
		CHECK(f.ledger_files() == 1);
	}
	{	/* a sourced guest spool records its source lineage */
		fixture f;
		pid_t pid = -1;
		std::string path = std::string("/tmp/elf.") +
		    "11111111111111111111111111111111." + "22222222222222222222222222222222";
		CHECK(launch_program(f.s, path, false, "/usr/bin/true", nullptr, &pid));
		CHECK(f.s.pid_sources.count(pid) == 1 &&
		    f.s.pid_sources[pid][0] == 0x22);
		CHECK(f.registered_exit(pid, 0));
	}
	{	/* exec failure: the child's errno, nothing registered */
		fixture f;
		pid_t pid = 7;
		errno = 0;
		CHECK(!launch_program(f.s, "/tmp/elf-host", true,
		    "/nonexistent/hypertrace-launch", nullptr, &pid));
		CHECK(errno == ENOENT && pid == -1 && f.s.pidlist.empty());
		CHECK(!launch_program(f.s, "/tmp/plain", false,
		    "/nonexistent/hypertrace-launch", nullptr, &pid));
		CHECK(errno == ENOENT && f.s.pidlist.empty() && f.ledger_files() == 0);
	}
	{	/* descriptors 0 and 1 free: launch descriptors move above stdio */
		fixture f;
		int saved[2] = {dup(0), dup(1)};
		close(0);
		close(1);
		pid_t pid = -1;
		bool ok = launch_program(f.s, "/tmp/plain", false, "/usr/bin/true",
		    nullptr, &pid);
		int error = errno;
		bool exited = ok && f.registered_exit(pid, 0);
		/* the process descriptor may now occupy 0 or 1; release it
		 * before restoring stdio */
		for (auto &[child, fd] : f.s.pidfds)
			close(fd);
		f.s.pidfds.clear();
		for (int i = 0; i < 2; ++i) {
			dup2(saved[i], i);
			close(saved[i]);
		}
		errno = error;
		CHECK(ok && exited);
	}
}

static void
test_refusals()
{
	fixture f;
	f.s.cleanup_in_progress.store(true);
	errno = 0;
	CHECK(!launch_program(f.s, "/tmp/x", true, "/usr/bin/true") &&
	    errno == ECANCELED);
	f.s.cleanup_in_progress.store(false);
	CHECK(!launch_program(f.s, "/tmp/elf.not-canonical", false,
	    "/usr/bin/true") && errno == EPROTO);
	CHECK(!launch_program(f.s, "/tmp/plain", false, "/usr/bin/true", nullptr,
	    nullptr, true) && errno == EAGAIN);
	std::string sourced = std::string("/tmp/elf.") +
	    "11111111111111111111111111111111." + "33333333333333333333333333333333";
	uint8_t src[16];
	memset(src, 0x33, sizeof(src));
	CHECK(f.inbound->revoke_source(src));
	CHECK(!launch_program(f.s, sourced, false, "/usr/bin/true") &&
	    errno == ECANCELED);
	std::string other = std::string("/tmp/elf.") +
	    "11111111111111111111111111111111." + "44444444444444444444444444444444";
	std::array<uint8_t, 16> revoked;
	revoked.fill(0x44);
	f.s.revoked_sources.insert(revoked);
	CHECK(!launch_program(f.s, other, false, "/usr/bin/true") &&
	    errno == ECANCELED);
	/* no ledger directory for a guest launch */
	f.s.inbounddir = nullptr;
	CHECK(!launch_program(f.s, "/tmp/plain", false, "/usr/bin/true"));
	f.s.inbounddir = f.inbound.get();
	CHECK(f.s.pidlist.empty() && f.ledger_files() == 0);
}

/* waitpid_timeout (kept for existing callers, decision 2): the exit status
 * of a finished child, ETIMEDOUT for one still running, EINVAL for bad
 * arguments, ECHILD for a process that is not a child. */
static void
test_waitpid_timeout()
{
	pid_t done = fork();
	CHECK(done >= 0);
	if (done == 0) {
		harness_flush_profile();
		_exit(23);
	}
	struct timespec t = {5, 0};
	int status = waitpid_timeout(done, &t);
	CHECK(status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 23);
	pid_t running = fork();
	CHECK(running >= 0);
	if (running == 0) {
		harness_flush_profile();
		for (;;)
			pause();
	}
	t = {0, 30000000};
	errno = 0;
	CHECK(waitpid_timeout(running, &t) == -1 && errno == ETIMEDOUT);
	kill(running, SIGKILL);
	t = {5, 0};
	status = waitpid_timeout(running, &t);
	CHECK(status != -1 && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	errno = 0;
	CHECK(waitpid_timeout(1, &t) == -1 && errno == EINVAL);
	struct timespec bad = {0, 1000000000};
	CHECK(waitpid_timeout(running, &bad) == -1 && errno == EINVAL);
	CHECK(waitpid_timeout(running, nullptr) == -1 && errno == EINVAL);
	t = {0, 10000000};
	CHECK(waitpid_timeout(running, &t) == -1 && errno == ECHILD);
}

int
main()
{
	alarm(120);
	signal(SIGPIPE, SIG_IGN);
	test_launches();
	test_refusals();
	test_waitpid_timeout();
	printf("launch-child: %u checks passed\n", harness_checks);
	return (0);
}

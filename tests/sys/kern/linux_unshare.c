/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in a disposable guest, with a writable current directory. */
#include "linux_test.h"

#if !defined(__x86_64__)
#error This reference matrix currently targets Linux amd64.
#endif
#define SYS_unshare 272
#define SYS_setuid 105
#define SYS_chroot 161
#define AT_REMOVEDIR 0x200
#define F_GETFD 1
#define F_SETLK 6
#define F_GETLK 5
#define F_WRLCK 1
#define F_UNLCK 2

static int
wait_child(long pid)
{
	int status = 0;

	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid)
		return (90);
	if ((status & 0x7f) != 0)
		return (91);
	return ((status >> 8) & 255);
}

/* A child shares both resources, then detaches exactly the requested one. */
static int
sharing(void *arg)
{
	unsigned long flags = (unsigned long)arg;
	long fd, pid, mask;
	int rc;
	char before[4096], after[4096];

	if (sys2(SYS_getcwd, before, sizeof(before)) < 0)
		return (1);
	/* The runner must use a private working directory, not /. */
	if (xstreq(before, "/"))
		return (2);
	fd = sys2(SYS_memfd_create, "unshare-fd", 0);
	if (fd < 0)
		return (3);
	(void)sys1(SYS_umask, 0022);
	pid = sys5(SYS_clone, CLONE_FS | CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (4);
	if (pid == 0) {
		if (sys1(SYS_unshare, flags) != 0)
			(void)sys1(SYS_exit, 5);
		if (sys1(SYS_close, fd) != 0 || sys1(SYS_chdir, "/") != 0)
			(void)sys1(SYS_exit, 6);
		(void)sys1(SYS_umask, 0077);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	rc = wait_child(pid);
	if (rc != 0)
		return (rc);
	if (sys3(SYS_fcntl, fd, F_GETFD, 0) !=
	    ((flags & CLONE_FILES) != 0 ? 0 : -EBADF))
		return (7);
	mask = sys1(SYS_umask, 0022);
	if (mask != ((flags & CLONE_FS) != 0 ? 0022 : 0077))
		return (8);
	if (sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
	    !xstreq(after, (flags & CLONE_FS) != 0 ? before : "/"))
		return (9);
	return (0);
}

static int zero(void) { return (run_child(sharing, (void *)0)); }
static int fs(void) { return (run_child(sharing, (void *)CLONE_FS)); }
static int files(void) { return (run_child(sharing, (void *)CLONE_FILES)); }
static int both(void)
{
	return (run_child(sharing, (void *)(CLONE_FS | CLONE_FILES)));
}

static int
invalid(void)
{
	unsigned int bit;

	/* Reserved high bits must not disappear through a 32-bit argument. */
	for (bit = 32; bit < 64; bit++) {
		if (sys1(SYS_unshare, 1UL << bit) != -EINVAL ||
		    sys1(SYS_unshare, (1UL << bit) | CLONE_FS) != -EINVAL)
			return (1);
	}
	if (sys1(SYS_unshare, SIGCHLD) != -EINVAL ||
	    sys1(SYS_unshare, CLONE_FILES | CLONE_VFORK) != -EINVAL)
		return (2);
	return (0);
}

/* Rejecting a flag combination must leave both shared objects attached. */
static int
rejected(void *unused)
{
	long fd, pid;
	int rc;

	(void)unused;
	fd = sys2(SYS_memfd_create, "unshare-reject", 0);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_umask, 0022);
	pid = sys5(SYS_clone, CLONE_FS | CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (2);
	if (pid == 0) {
		if (sys1(SYS_unshare, CLONE_FS | CLONE_FILES | (1UL << 63)) !=
		    -EINVAL)
			(void)sys1(SYS_exit, 3);
		if (sys1(SYS_close, fd) != 0)
			(void)sys1(SYS_exit, 4);
		(void)sys1(SYS_umask, 0077);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	rc = wait_child(pid);
	if (rc != 0)
		return (rc);
	if (sys3(SYS_fcntl, fd, F_GETFD, 0) != -EBADF ||
	    sys1(SYS_umask, 0022) != 0077)
		return (5);
	return (0);
}

static int reject_atomicity(void) { return (run_child(rejected, 0)); }

/* Copy descriptor entries, but keep the same open file description. */
static int
description(void *unused)
{
	long fd, pid;
	int rc;

	(void)unused;
	fd = sys2(SYS_memfd_create, "unshare-offset", 0);
	if (fd < 0)
		return (1);
	pid = sys5(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (2);
	if (pid == 0) {
		if (sys1(SYS_unshare, CLONE_FILES) != 0 ||
		    sys3(SYS_lseek, fd, 123, 0) != 123 ||
		    sys1(SYS_close, fd) != 0)
			(void)sys1(SYS_exit, 3);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	rc = wait_child(pid);
	if (rc != 0)
		return (rc);
	return (sys3(SYS_lseek, fd, 0, 1) == 123 ? 0 : 4);
}

static int shared_description(void) { return (run_child(description, 0)); }

struct linux_flock {
	short type, whence;
	long start, len;
	int pid;
};

/* POSIX locks stay with the old shared file table, not the detaching task. */
static int
locks(void *unused)
{
	struct linux_flock lock = { .type = F_WRLCK, .len = 1 };
	int ready[2], release[2], rc;
	long fd, pid;
	char byte = 'x';

	(void)unused;
	fd = tmpfile_fd("unshare-lock");
	if (fd < 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "unshare-lock", 0);
	if (sys3(SYS_fcntl, fd, F_SETLK, &lock) != 0 ||
	    sys2(SYS_pipe2, ready, 0) != 0 ||
	    sys2(SYS_pipe2, release, 0) != 0)
		return (2);
	pid = sys5(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (3);
	if (pid == 0) {
		if (sys3(SYS_write, ready[1], &byte, 1) != 1 ||
		    sys3(SYS_read, release[0], &byte, 1) != 1)
			(void)sys1(SYS_exit, 4);
		if (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
		    lock.type != F_UNLCK)
			(void)sys1(SYS_exit, 5);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	if (sys3(SYS_read, ready[0], &byte, 1) != 1)
		return (6);
	rc = sys1(SYS_unshare, CLONE_FILES) == 0 ? 0 : 7;
	if (rc == 0 && (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
	    lock.type != F_WRLCK || lock.pid != sys0(SYS_getpid)))
		rc = 10;
	if (sys3(SYS_write, release[1], &byte, 1) != 1)
		return (8);
	if (wait_child(pid) != 0)
		return (9);
	lock.type = F_WRLCK;
	if (rc == 0 && (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
	    lock.type != F_UNLCK))
		return (11);
	return (rc);
}

static int posix_locks(void) { return (run_child(locks, 0)); }

/* Each range reports its acquiring process, even with a shared owner. */
static int
lock_pids_and_close(void *unused)
{
	struct linux_flock lock = { .type = F_WRLCK, .len = 1 };
	int ready[2], release[2], rc = 0;
	long fd, duplicate, pid, owner;
	char byte = 'x';

	(void)unused;
	owner = sys0(SYS_getpid);
	fd = tmpfile_fd("unshare-lock-pids");
	if (fd < 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "unshare-lock-pids", 0);
	duplicate = sys1(SYS_dup, fd);
	if (duplicate < 0 || sys3(SYS_fcntl, fd, F_SETLK, &lock) != 0 ||
	    sys2(SYS_pipe2, ready, 0) != 0 ||
	    sys2(SYS_pipe2, release, 0) != 0)
		return (2);
	pid = sys5(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (3);
	if (pid == 0) {
		lock.start = 2;
		if (sys3(SYS_fcntl, fd, F_SETLK, &lock) != 0 ||
		    sys3(SYS_write, ready[1], &byte, 1) != 1 ||
		    sys3(SYS_read, release[0], &byte, 1) != 1)
			(void)sys1(SYS_exit, 4);
		/* Closing any fd for the inode clears this table's POSIX locks. */
		if (sys1(SYS_close, duplicate) != 0 ||
		    sys3(SYS_write, ready[1], &byte, 1) != 1 ||
		    sys3(SYS_read, release[0], &byte, 1) != 1)
			(void)sys1(SYS_exit, 5);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	if (sys3(SYS_read, ready[0], &byte, 1) != 1)
		return (6);
	if (sys1(SYS_unshare, CLONE_FILES) != 0)
		rc = 7;
	/* Closing in the new table must leave both old-table locks intact. */
	if (rc == 0 && sys1(SYS_close, duplicate) != 0)
		rc = 8;
	if (rc == 0 && (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
	    lock.type != F_WRLCK || lock.pid != owner))
		rc = 9;
	lock.type = F_WRLCK;
	lock.start = 2;
	if (rc == 0 && (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
	    lock.type != F_WRLCK || lock.pid != pid))
		rc = 10;
	if (sys3(SYS_write, release[1], &byte, 1) != 1 ||
	    sys3(SYS_read, ready[0], &byte, 1) != 1)
		return (11);
	lock.type = F_WRLCK;
	lock.start = 0;
	lock.len = 3;
	if (rc == 0 && (sys3(SYS_fcntl, fd, F_GETLK, &lock) != 0 ||
	    lock.type != F_UNLCK))
		rc = 12;
	if (sys3(SYS_write, release[1], &byte, 1) != 1 ||
	    wait_child(pid) != 0)
		return (13);
	return (rc);
}

static int posix_lock_pids(void)
{
	return (run_child(lock_pids_and_close, 0));
}

struct fs_race_state {
	unsigned int turns;
	int stop;
};

/* Check isolation while a different process keeps mutating the old pwd. */
static int
fs_race_child(struct fs_race_state *state, long cwd_fd)
{
	char before[4096], after[4096];
	unsigned int turns;
	long mask;
	int i;

	if (sys1(SYS_unshare, CLONE_FS) != 0 ||
	    sys2(SYS_getcwd, before, sizeof(before)) < 0)
		return (1);
	mask = sys1(SYS_umask, 0033);
	if (mask != 0022 && mask != 0077)
		return (2);
	turns = __atomic_load_n(&state->turns, __ATOMIC_ACQUIRE);
	for (i = 0; i < 100000; i++) {
		if (sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
		    !xstreq(before, after) || sys1(SYS_umask, 0033) != 0033)
			return (3);
		if (__atomic_load_n(&state->turns, __ATOMIC_ACQUIRE) != turns)
			break;
		(void)sys0(SYS_sched_yield);
	}
	if (i == 100000 || sys1(SYS_fchdir, cwd_fd) != 0)
		return (4);
	/* The private state stays writable and subsequent detaches are safe. */
	if (sys1(SYS_unshare, CLONE_FS) != 0 ||
	    sys1(SYS_umask, 0022) != 0033)
		return (5);
	return (0);
}

static int
fs_race(void *unused)
{
	struct fs_race_state *state;
	long mapping, cwd_fd, mutator, pid;
	int i, rc = 0;

	(void)unused;
	cwd_fd = sys4(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0);
	mapping = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (cwd_fd < 0 || (unsigned long)mapping >= (unsigned long)-4095)
		return (1);
	state = (void *)mapping;
	(void)sys1(SYS_umask, 0022);
	mutator = sys5(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
	if (mutator < 0)
		return (2);
	if (mutator == 0) {
		while (!__atomic_load_n(&state->stop, __ATOMIC_ACQUIRE)) {
			if (sys1(SYS_chdir, "/") != 0 ||
			    sys1(SYS_fchdir, cwd_fd) != 0)
				(void)sys1(SYS_exit, 3);
			(void)sys1(SYS_umask, 0077);
			(void)sys1(SYS_umask, 0022);
			__atomic_add_fetch(&state->turns, 1, __ATOMIC_RELEASE);
		}
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	for (i = 0; i < 64; i++) {
		pid = sys5(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
		if (pid < 0) {
			rc = 4;
			break;
		}
		if (pid == 0) {
			(void)sys1(SYS_exit, fs_race_child(state, cwd_fd));
			__builtin_unreachable();
		}
		rc = wait_child(pid);
		if (rc != 0)
			break;
	}
	__atomic_store_n(&state->stop, 1, __ATOMIC_RELEASE);
	if (wait_child(mutator) != 0)
		rc = 6;
	(void)sys1(SYS_close, cwd_fd);
	(void)sys2(SYS_munmap, state, 4096);
	return (rc);
}

static int fs_concurrent(void) { return (run_child(fs_race, 0)); }

static const char *self_path;

static int
unprivileged(void *unused)
{
	(void)unused;
	if (sys1(SYS_setuid, 65534) != 0)
		return (1);
	return (sharing((void *)CLONE_FS));
}

static int fs_unprivileged(void) { return (run_child(unprivileged, 0)); }

static int
repeated(void)
{
	int i;

	for (i = 0; i < 256; i++) {
		if (sys1(SYS_unshare, CLONE_FS) != 0 ||
		    sys1(SYS_unshare, 0) != 0)
			return (1);
	}
	return (0);
}

static int
exec_lifetime(void *unused)
{
	char before[4096], after[4096];
	char *args[] = { (char *)self_path, "exec_check", 0 };
	char *env[] = { 0 };
	long pid;
	int rc;

	(void)unused;
	if (sys2(SYS_getcwd, before, sizeof(before)) < 0)
		return (1);
	(void)sys1(SYS_umask, 0022);
	pid = sys5(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (2);
	if (pid == 0) {
		if (sys1(SYS_unshare, CLONE_FS) != 0 ||
		    sys1(SYS_chdir, "/") != 0)
			(void)sys1(SYS_exit, 3);
		(void)sys1(SYS_umask, 0077);
		if (sys3(SYS_execve, "/unshare-no-such-executable", args, env) !=
		    -ENOENT || sys1(SYS_umask, 0077) != 0077)
			(void)sys1(SYS_exit, 4);
		(void)sys3(SYS_execve, self_path, args, env);
		(void)sys1(SYS_exit, 5);
		__builtin_unreachable();
	}
	rc = wait_child(pid);
	if (rc != 0)
		return (rc);
	if (sys1(SYS_umask, 0022) != 0022 ||
	    sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
	    !xstreq(before, after))
		return (6);
	return (0);
}

static int fs_exec(void) { return (run_child(exec_lifetime, 0)); }

static int
root_lifetime(void *unused)
{
	char before[4096], after[4096];
	long pid;
	int rc;

	(void)unused;
	if (sys2(SYS_getcwd, before, sizeof(before)) < 0 ||
	    sys3(SYS_mkdirat, AT_FDCWD, "unshare-root", 0700) != 0)
		return (1);
	pid = sys5(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
	if (pid < 0)
		return (2);
	if (pid == 0) {
		if (sys1(SYS_unshare, CLONE_FS) != 0 ||
		    sys1(SYS_chroot, "unshare-root") != 0 ||
		    sys1(SYS_chdir, "/") != 0 ||
		    sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
		    !xstreq(after, "/"))
			(void)sys1(SYS_exit, 3);
		(void)sys1(SYS_exit, 0);
		__builtin_unreachable();
	}
	rc = wait_child(pid);
	if (sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
	    !xstreq(before, after) ||
	    sys3(SYS_unlinkat, AT_FDCWD, "unshare-root", AT_REMOVEDIR) != 0)
		return (4);
	return (rc);
}

static int fs_root(void) { return (run_child(root_lifetime, 0)); }

struct worker_state {
	long fd;
	int done, error;
};
static char worker_stack[65536] __attribute__((aligned(16)));

static int
detach_thread(void *arg)
{
	struct worker_state *state = arg;

	if (sys1(SYS_unshare, CLONE_FS | CLONE_FILES) != 0)
		state->error = 1;
	else if (sys1(SYS_close, state->fd) != 0 ||
	    sys1(SYS_chdir, "/") != 0)
		state->error = 2;
	(void)sys1(SYS_umask, 0077);
	__atomic_store_n(&state->done, 1, __ATOMIC_RELEASE);
	/* Stay alive until the isolated test process calls exit_group. */
	for (;;)
		(void)sys0(SYS_sched_yield);
}

static int
thread_detach(void *unused)
{
	struct worker_state state = { 0 };
	char before[4096], after[4096];
	int i;

	(void)unused;
	if (sys2(SYS_getcwd, before, sizeof(before)) < 0 ||
	    xstreq(before, "/"))
		return (1);
	state.fd = sys2(SYS_memfd_create, "unshare-thread", 0);
	if (state.fd < 0)
		return (2);
	(void)sys1(SYS_umask, 0022);
	if (__thread_clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD | CLONE_SYSVSEM, worker_stack + sizeof(worker_stack),
	    0, 0, detach_thread, &state) < 0)
		return (3);
	for (i = 0; i < 1000000; i++) {
		if (__atomic_load_n(&state.done, __ATOMIC_ACQUIRE))
			break;
		(void)sys0(SYS_sched_yield);
	}
	if (i == 1000000 || state.error != 0)
		return (4);
	if (sys3(SYS_fcntl, state.fd, F_GETFD, 0) != 0 ||
	    sys1(SYS_umask, 0022) != 0022 ||
	    sys2(SYS_getcwd, after, sizeof(after)) < 0 ||
	    !xstreq(before, after))
		return (5);
	return (0);
}

static int per_thread(void) { return (run_child(thread_detach, 0)); }

#ifdef UNSHARE_BSD_SUBSET
static int
bsd_rejections(void)
{
	unsigned int bit;

	for (bit = 0; bit < 64; bit++) {
		if ((1UL << bit) == CLONE_FS)
			continue;
		if (sys1(SYS_unshare, 1UL << bit) != -EINVAL ||
		    sys1(SYS_unshare, (1UL << bit) | CLONE_FS) != -EINVAL)
			return (1);
	}
	return (0);
}

static int
reject_thread(void *arg)
{
	struct worker_state *state = arg;

	if (sys1(SYS_unshare, CLONE_FS) != -EINVAL ||
	    sys1(SYS_unshare, 0) != 0)
		state->error = 1;
	(void)sys1(SYS_umask, 0077);
	__atomic_store_n(&state->done, 1, __ATOMIC_RELEASE);
	for (;;)
		(void)sys0(SYS_sched_yield);
}

static int
thread_rejection(void *unused)
{
	struct worker_state state = { 0 };
	int i;

	(void)unused;
	(void)sys1(SYS_umask, 0022);
	if (__thread_clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD | CLONE_SYSVSEM, worker_stack + sizeof(worker_stack),
	    0, 0, reject_thread, &state) < 0)
		return (1);
	for (i = 0; i < 1000000; i++) {
		if (__atomic_load_n(&state.done, __ATOMIC_ACQUIRE))
			break;
		(void)sys0(SYS_sched_yield);
	}
	if (i == 1000000 || state.error != 0 ||
	    sys1(SYS_umask, 0022) != 0077)
		return (2);
	return (0);
}

static int bsd_thread_rejection(void)
{
	return (run_child(thread_rejection, 0));
}
#endif

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
#ifdef UNSHARE_BSD_SUBSET
		{ "bsd_rejected_flags", bsd_rejections },
		{ "bsd_thread_rejection", bsd_thread_rejection },
#endif
		{ "zero_preserves_sharing", zero },
		{ "fs_detaches_only_paths_and_umask", fs },
		{ "files_detaches_only_descriptors", files },
		{ "fs_files_detach_both", both },
		{ "invalid_flags", invalid },
		{ "fs_unprivileged", fs_unprivileged },
		{ "fs_repeated", repeated },
		{ "fs_concurrent_shared_mutation", fs_concurrent },
		{ "fs_fork_exec_lifetime", fs_exec },
		{ "fs_root_lifetime", fs_root },
		{ "rejection_preserves_sharing", reject_atomicity },
		{ "files_preserves_open_description", shared_description },
		{ "files_preserves_old_table_lock_ownership", posix_locks },
		{ "files_lock_pids_and_close_ownership", posix_lock_pids },
		{ "thread_detaches_without_affecting_sibling", per_thread },
	};

	char cwd[4096];

	(void)envp;
	self_path = argv[0];
	if (argc == 2 && xstreq(argv[1], "exec_check")) {
		return (sys1(SYS_umask, 0077) == 0077 &&
		    sys2(SYS_getcwd, cwd, sizeof(cwd)) > 0 &&
		    xstreq(cwd, "/") ? 0 : 20);
	}
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}

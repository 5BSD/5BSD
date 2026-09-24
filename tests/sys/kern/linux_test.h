/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shared preamble for the freestanding amd64/arm64 Linux syscall tests: no Linux
 * libc or sysroot is required.  A test is one static binary whose exit
 * status is the number of the failed check (0 = all passed); it is built
 * and run by its ATF sh wrapper with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 *
 * Provides: raw syscall entry, the architecture-specific Linux syscall numbers and errno
 * values used across the suite, minimal string helpers, fork/wait helpers
 * and an argv-aware _start.  Each test defines
 *   static int test(int argc, char **argv, char **envp);
 * and includes this header last.
 */
#ifndef LINUX_TEST_H
#define LINUX_TEST_H

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long ssize_t;
typedef unsigned long size_t;

#if defined(__x86_64__)
/* Linux amd64 syscall numbers. */
#define	SYS_read		0
#define	SYS_write		1
#define	SYS_open		2
#define	SYS_close		3
#define	SYS_stat		4
#define	SYS_fstat		5
#define	SYS_lstat		6
#define	SYS_poll		7
#define	SYS_lseek		8
#define	SYS_mmap		9
#define	SYS_mprotect		10
#define	SYS_munmap		11
#define	SYS_brk			12
#define	SYS_rt_sigaction	13
#define	SYS_rt_sigprocmask	14
#define	SYS_ioctl		16
#define	SYS_pread64		17
#define	SYS_pwrite64		18
#define	SYS_readv		19
#define	SYS_writev		20
#define	SYS_access		21
#define	SYS_pipe		22
#define	SYS_sched_yield		24
#define	SYS_mremap		25
#define	SYS_msync		26
#define	SYS_mincore		27
#define	SYS_madvise		28
#define	SYS_dup			32
#define	SYS_dup2		33
#define	SYS_nanosleep		35
#define	SYS_getpid		39
#define	SYS_socket		41
#define	SYS_connect		42
#define	SYS_accept		43
#define	SYS_sendto		44
#define	SYS_recvfrom		45
#define	SYS_sendmsg		46
#define	SYS_recvmsg		47
#define	SYS_shutdown		48
#define	SYS_bind		49
#define	SYS_listen		50
#define	SYS_getsockname		51
#define	SYS_getpeername		52
#define	SYS_socketpair		53
#define	SYS_setsockopt		54
#define	SYS_getsockopt		55
#define	SYS_clone		56
#define	SYS_fork		57
#define	SYS_vfork		58
#define	SYS_execve		59
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_uname		63
#define	SYS_fcntl		72
#define	SYS_flock		73
#define	SYS_fsync		74
#define	SYS_fdatasync		75
#define	SYS_truncate		76
#define	SYS_ftruncate		77
#define	SYS_getcwd		79
#define	SYS_chdir		80
#define	SYS_fchdir		81
#define	SYS_mkdir		83
#define	SYS_rmdir		84
#define	SYS_unlink		87
#define	SYS_symlink		88
#define	SYS_readlink		89
#define	SYS_chmod		90
#define	SYS_umask		95
#define	SYS_getrlimit		97
#define	SYS_getuid		102
#define	SYS_getgid		104
#define	SYS_geteuid		107
#define	SYS_getegid		108
#define	SYS_getppid		110
#define	SYS_personality		135
#define	SYS_prctl		157
#define	SYS_arch_prctl		158
#define	SYS_setrlimit		160
#define	SYS_mount		165
#define	SYS_umount2		166
#define	SYS_gettid		186
#define	SYS_futex		202
#define	SYS_getdents64		217
#define	SYS_set_tid_address	218
#define	SYS_fadvise64		221
#define	SYS_clock_gettime	228
#define	SYS_clock_nanosleep	230
#define	SYS_exit_group		231
#define	SYS_epoll_wait		232
#define	SYS_epoll_ctl		233
#define	SYS_tgkill		234
#define	SYS_openat		257
#define	SYS_mkdirat		258
#define	SYS_newfstatat		262
#define	SYS_unlinkat		263
#define	SYS_readlinkat		267
#define	SYS_faccessat		269
#define	SYS_ppoll		271
#define	SYS_splice		275
#define	SYS_sync_file_range	277
#define	SYS_utimensat		280
#define	SYS_epoll_pwait		281
#define	SYS_timerfd_create	283
#define	SYS_eventfd2		290
#define	SYS_epoll_create1	291
#define	SYS_dup3		292
#define	SYS_pipe2		293
#define	SYS_preadv		295
#define	SYS_pwritev		296
#define	SYS_prlimit64		302
#define	SYS_getcpu		309
#define	SYS_kcmp		312
#define	SYS_sched_setattr	314
#define	SYS_sched_getattr	315
#define	SYS_renameat2		316
#define	SYS_getrandom		318
#define	SYS_memfd_create	319
#define	SYS_execveat		322
#define	SYS_mlock2		325
#define	SYS_copy_file_range	326
#define	SYS_preadv2		327
#define	SYS_pwritev2		328
#define	SYS_statx		332
#define	SYS_pidfd_send_signal	424
#define	SYS_pidfd_open		434
#define	SYS_clone3		435
#define	SYS_close_range		436
#define	SYS_openat2		437
#define	SYS_pidfd_getfd		438
#define	SYS_faccessat2		439
#define	SYS_process_madvise	440
#define	SYS_epoll_pwait2	441
#define	SYS_fallocate		285
#define	SYS_mlockall		151
#define	SYS_munlockall		152
#define	SYS_mlock		149
#define	SYS_munlock		150
#define	SYS_waitid		247

#elif defined(__aarch64__)
/* Linux arm64 asm-generic syscall numbering. */
#define	SYS_mmap		222
#define	SYS_futex		98
#define	SYS_fstat		80
#define	SYS_read		63
#define	SYS_write		64
#define	SYS_close		57
#define	SYS_lseek		62
#define	SYS_mprotect		226
#define	SYS_munmap		215
#define	SYS_brk		214
#define	SYS_rt_sigaction		134
#define	SYS_rt_sigprocmask		135
#define	SYS_ioctl		29
#define	SYS_pread64		67
#define	SYS_pwrite64		68
#define	SYS_readv		65
#define	SYS_writev		66
#define	SYS_sched_yield		124
#define	SYS_mremap		216
#define	SYS_msync		227
#define	SYS_mincore		232
#define	SYS_madvise		233
#define	SYS_dup		23
#define	SYS_nanosleep		101
#define	SYS_getpid		172
#define	SYS_socket		198
#define	SYS_connect		203
#define	SYS_accept		202
#define	SYS_sendto		206
#define	SYS_recvfrom		207
#define	SYS_sendmsg		211
#define	SYS_recvmsg		212
#define	SYS_shutdown		210
#define	SYS_bind		200
#define	SYS_listen		201
#define	SYS_getsockname		204
#define	SYS_getpeername		205
#define	SYS_socketpair		199
#define	SYS_setsockopt		208
#define	SYS_getsockopt		209
#define	SYS_clone		220
#define	SYS_execve		221
#define	SYS_exit		93
#define	SYS_wait4		260
#define	SYS_kill		129
#define	SYS_fcntl		25
#define	SYS_flock		32
#define	SYS_fsync		82
#define	SYS_fdatasync		83
#define	SYS_truncate		45
#define	SYS_ftruncate		46
#define	SYS_getcwd		17
#define	SYS_chdir		49
#define	SYS_fchdir		50
#define	SYS_umask		166
#define	SYS_getrlimit		163
#define	SYS_getuid		174
#define	SYS_getgid		176
#define	SYS_geteuid		175
#define	SYS_getegid		177
#define	SYS_getppid		173
#define	SYS_personality		92
#define	SYS_prctl		167
#define	SYS_setrlimit		164
#define	SYS_mount		40
#define	SYS_umount2		39
#define	SYS_gettid		178
#define	SYS_getdents64		61
#define	SYS_set_tid_address		96
#define	SYS_fadvise64		223
#define	SYS_clock_gettime		113
#define	SYS_clock_nanosleep		115
#define	SYS_exit_group		94
#define	SYS_epoll_ctl		21
#define	SYS_tgkill		131
#define	SYS_openat		56
#define	SYS_mkdirat		34
#define	SYS_newfstatat		79
#define	SYS_unlinkat		35
#define	SYS_readlinkat		78
#define	SYS_faccessat		48
#define	SYS_ppoll		73
#define	SYS_splice		76
#define	SYS_sync_file_range		84
#define	SYS_utimensat		88
#define	SYS_epoll_pwait		22
#define	SYS_timerfd_create		85
#define	SYS_eventfd2		19
#define	SYS_epoll_create1		20
#define	SYS_dup3		24
#define	SYS_pipe2		59
#define	SYS_preadv		69
#define	SYS_pwritev		70
#define	SYS_prlimit64		261
#define	SYS_getcpu		168
#define	SYS_kcmp		272
#define	SYS_sched_setattr		274
#define	SYS_sched_getattr		275
#define	SYS_renameat2		276
#define	SYS_getrandom		278
#define	SYS_memfd_create		279
#define	SYS_execveat		281
#define	SYS_mlock2		284
#define	SYS_copy_file_range		285
#define	SYS_preadv2		286
#define	SYS_pwritev2		287
#define	SYS_statx		291
#define	SYS_pidfd_send_signal		424
#define	SYS_pidfd_open		434
#define	SYS_clone3		435
#define	SYS_close_range		436
#define	SYS_openat2		437
#define	SYS_pidfd_getfd		438
#define	SYS_faccessat2		439
#define	SYS_process_madvise		440
#define	SYS_epoll_pwait2		441
#define	SYS_fallocate		47
#define	SYS_mlockall		230
#define	SYS_munlockall		231
#define	SYS_mlock		228
#define	SYS_munlock		229
#define	SYS_waitid		95
#else
#error Unsupported Linux test architecture
#endif

/* errno */
#define	EPERM		1
#define	ENOENT		2
#define	ESRCH		3
#define	EINTR		4
#define	EIO		5
#define	ENXIO		6
#define	E2BIG		7
#define	ENOEXEC		8
#define	EBADF		9
#define	ECHILD		10
#define	EAGAIN		11
#define	ENOMEM		12
#define	EACCES		13
#define	EFAULT		14
#define	EBUSY		16
#define	EEXIST		17
#define	EXDEV		18
#define	ENODEV		19
#define	ENOTDIR		20
#define	EISDIR		21
#define	EINVAL		22
#define	ENFILE		23
#define	EMFILE		24
#define	ENOTTY		25
#define	EFBIG		27
#define	ENOSPC		28
#define	ESPIPE		29
#define	EROFS		30
#define	EPIPE		32
#define	ENAMETOOLONG	36
#define	ERANGE		34
#define	ENOSYS		38
#define	ENOTEMPTY	39
#define	ELOOP		40
#define	ENODATA	61
#define	ENOTSOCK	88
#define	EOPNOTSUPP	95
#define	EAFNOSUPPORT	97
#define	ENOTCONN	107
#define	ETIMEDOUT	110

/* open(2) flags. */
#define	O_RDONLY	00
#define	O_WRONLY	01
#define	O_RDWR		02
#define	O_CREAT		0100
#define	O_EXCL		0200
#define	O_NOCTTY	0400
#define	O_TRUNC		01000
#define	O_APPEND	02000
#define	O_NONBLOCK	04000
#define	O_DSYNC		010000
#define	O_ASYNC		020000
#ifdef __aarch64__
#define	O_DIRECT	0200000
#define	O_LARGEFILE	0400000
#define	O_DIRECTORY	040000
#define	O_NOFOLLOW	0100000
#else
#define	O_DIRECT	040000
#define	O_LARGEFILE	0100000
#define	O_DIRECTORY	0200000
#define	O_NOFOLLOW	0400000
#endif
#define	O_NOATIME	01000000
#define	O_CLOEXEC	02000000
#define	__O_SYNC	04000000
#define	O_SYNC		(__O_SYNC | O_DSYNC)
#define	O_PATH		010000000
#define	__O_TMPFILE	020000000
#define	O_TMPFILE	(__O_TMPFILE | O_DIRECTORY)
#define	AT_FDCWD	-100

/* mmap(2) */
#define	PROT_NONE	0
#define	PROT_READ	1
#define	PROT_WRITE	2
#define	PROT_EXEC	4
#define	PROT_GROWSDOWN	0x01000000
#define	PROT_GROWSUP	0x02000000
#define	MAP_SHARED	0x01
#define	MAP_PRIVATE	0x02
#define	MAP_SHARED_VALIDATE 0x03
#define	MAP_FIXED	0x10
#define	MAP_ANONYMOUS	0x20
#define	MAP_32BIT	0x40
#define	MAP_GROWSDOWN	0x0100
#define	MAP_DENYWRITE	0x0800
#define	MAP_EXECUTABLE	0x1000
#define	MAP_LOCKED	0x2000
#define	MAP_NORESERVE	0x4000
#define	MAP_POPULATE	0x8000
#define	MAP_NONBLOCK	0x10000
#define	MAP_STACK	0x20000
#define	MAP_HUGETLB	0x40000
#define	MAP_SYNC	0x80000
#define	MAP_FIXED_NOREPLACE 0x100000
#define	MAP_UNINITIALIZED 0x4000000
#define	MAP_HUGE_SHIFT	26
#define	MAP_HUGE_2MB	(21 << MAP_HUGE_SHIFT)
#define	MAP_HUGE_1GB	(30 << MAP_HUGE_SHIFT)
#define	PAGE		4096UL

/* wait */
#define	WNOHANG		1
#define	WUNTRACED	2
#define	WEXITED		4
#define	WCONTINUED	8
#define	WNOWAIT		0x01000000
#define	__WNOTHREAD	0x20000000
#define	__WALL		0x40000000
#define	__WCLONE	0x80000000
#define	P_ALL		0
#define	P_PID		1
#define	P_PGID		2
#define	P_PIDFD		3

/* signals */
#define	SIGHUP		1
#define	SIGINT		2
#define	SIGKILL		9
#define	SIGUSR1		10
#define	SIGSEGV		11
#define	SIGUSR2		12
#define	SIGPIPE		13
#define	SIGTERM		15
#define	SIGCHLD		17
#define	SIGCONT		18
#define	SIGSTOP		19
#define	SIG_BLOCK	0
#define	SIG_UNBLOCK	1
#define	SIG_SETMASK	2

/* clone flags */
#define	CLONE_VM		0x00000100
#define	CLONE_FS		0x00000200
#define	CLONE_FILES		0x00000400
#define	CLONE_SIGHAND		0x00000800
#define	CLONE_PIDFD		0x00001000
#define	CLONE_PTRACE		0x00002000
#define	CLONE_VFORK		0x00004000
#define	CLONE_PARENT		0x00008000
#define	CLONE_THREAD		0x00010000
#define	CLONE_NEWNS		0x00020000
#define	CLONE_SYSVSEM		0x00040000
#define	CLONE_SETTLS		0x00080000
#define	CLONE_PARENT_SETTID	0x00100000
#define	CLONE_CHILD_CLEARTID	0x00200000
#define	CLONE_DETACHED		0x00400000
#define	CLONE_UNTRACED		0x00800000
#define	CLONE_CHILD_SETTID	0x01000000
#define	CLONE_NEWCGROUP		0x02000000
#define	CLONE_NEWUTS		0x04000000
#define	CLONE_NEWIPC		0x08000000
#define	CLONE_NEWUSER		0x10000000
#define	CLONE_NEWPID		0x20000000
#define	CLONE_NEWNET		0x40000000
#define	CLONE_IO		0x80000000
#define	CLONE_CLEAR_SIGHAND	0x100000000ULL
#define	CLONE_INTO_CGROUP	0x200000000ULL
#define	CLONE_NEWTIME		0x00000080

struct clone_args {
	u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack,
	    stack_size, tls, set_tid, set_tid_size, cgroup;
};

#ifdef __aarch64__
struct stat {
	u64 st_dev, st_ino;
	u32 st_mode, st_nlink, st_uid, st_gid;
	u64 st_rdev, __pad1;
	long st_size;
	int st_blksize, __pad2;
	long st_blocks;
	u64 st_atime, st_atime_nsec;
	u64 st_mtime, st_mtime_nsec;
	u64 st_ctime, st_ctime_nsec;
	u32 __unused[2];
};
#else
/* Linux x86_64 struct stat. */
struct stat {
	u64 st_dev;
	u64 st_ino;
	u64 st_nlink;
	u32 st_mode;
	u32 st_uid;
	u32 st_gid;
	u32 __pad0;
	u64 st_rdev;
	long st_size;
	long st_blksize;
	long st_blocks;
	u64 st_atime, st_atime_nsec;
	u64 st_mtime, st_mtime_nsec;
	u64 st_ctime, st_ctime_nsec;
	long __unused[3];
};
#endif
#define	S_IFMT		0170000
#define	S_IFDIR		0040000
#define	S_IFREG		0100000
#define	S_IFCHR		0020000
#define	S_IFIFO		0010000
#define	S_IFLNK		0120000
#define	S_IFSOCK	0140000

struct iovec { void *iov_base; unsigned long iov_len; };
struct timespec { long tv_sec; long tv_nsec; };
struct rlimit { u64 rlim_cur; u64 rlim_max; };
#define	RLIM_INFINITY	(~0UL)

static long __attribute__((unused))
call(long nr, long a, long b, long c, long d, long e, long f)
{
#ifdef __aarch64__
	register long x8 __asm__("x8") = nr;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1),
	    "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
	return (x0);
#else
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
#endif
}

#define	sys0(n)			call(n, 0, 0, 0, 0, 0, 0)
#define	sys1(n, a)		call(n, (long)(a), 0, 0, 0, 0, 0)
#define	sys2(n, a, b)		call(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define	sys3(n, a, b, c)	call(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define	sys4(n, a, b, c, d)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), 0, 0)
#define	sys5(n, a, b, c, d, e)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), 0)
#define	sys6(n, a, b, c, d, e, f) call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), (long)(f))

static unsigned long __attribute__((unused))
xstrlen(const char *s)
{
	unsigned long n;

	for (n = 0; s[n] != '\0'; n++)
		;
	return (n);
}

static void __attribute__((unused))
xmemset(void *p, int v, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = (char)v;
}

static int __attribute__((unused))
xmemcmp(const void *a, const void *b, unsigned long n)
{
	const unsigned char *x = a, *y = b;

	for (; n > 0; n--, x++, y++)
		if (*x != *y)
			return (*x - *y);
	return (0);
}

static void __attribute__((unused))
xmemcpy(void *d, const void *s, unsigned long n)
{
	char *x = d;
	const char *y = s;

	while (n-- > 0)
		*x++ = *y++;
}

static int __attribute__((unused))
xstreq(const char *a, const char *b)
{

	while (*a != '\0' && *a == *b) {
		a++;
		b++;
	}
	return (*a == *b);
}

/* Write a message to stderr (used for skip notices and diagnostics). */
static void __attribute__((unused))
msg(const char *s)
{

	(void)sys3(SYS_write, 2, s, xstrlen(s));
}

static void __attribute__((unused))
msgnum(const char *s, long v)
{
	char buf[32];
	int i = 31, neg = 0;
	unsigned long u;

	if (v < 0) {
		neg = 1;
		u = (unsigned long)-v;
	} else
		u = (unsigned long)v;
	buf[i] = '\0';
	do {
		buf[--i] = '0' + u % 10;
		u /= 10;
	} while (u != 0);
	if (neg)
		buf[--i] = '-';
	msg(s);
	msg(&buf[i]);
	msg("\n");
}

/* Exit 0 with a notice: the environment cannot exercise the feature. */
static void __attribute__((unused))
skip(const char *s)
{

	msg(s);
	(void)sys1(SYS_exit_group, 0);
	__builtin_unreachable();
}

/* Fork without an architecture-specific legacy syscall. */
static long __attribute__((unused))
fork_process(void)
{
#ifdef __aarch64__
	return (sys5(SYS_clone, SIGCHLD, 0, 0, 0, 0));
#else
	return (sys0(SYS_fork));
#endif
}

/* Fork and run fn() in the child; returns the child's exit status byte. */
static int __attribute__((unused))
run_child(int (*fn)(void *), void *arg)
{
	long pid;
	int status;

	pid = fork_process();
	if (pid < 0)
		return (-1);
	if (pid == 0)
		(void)sys1(SYS_exit_group, fn(arg) & 0xff);
	status = 0;
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid)
		return (-2);
	if ((status & 0x7f) != 0)
		return (-3);
	return ((status >> 8) & 0xff);
}

/* Unlink-on-open temporary file in the cwd; returns fd or -errno. */
static long __attribute__((unused))
tmpfile_fd(const char *name)
{
	long fd;

	(void)sys3(SYS_unlinkat, AT_FDCWD, name, 0);
	fd = sys4(SYS_openat, AT_FDCWD, name, O_RDWR | O_CREAT | O_EXCL, 0600);
	return (fd);
}

/*
 * Minimal threads: clone(2) with a fresh stack and CLONE_THREAD; the child
 * runs fn(arg) on the new stack and exits with SYS_exit (not exit_group).
 * thread_join() waits on the CHILD_CLEARTID futex the kernel wakes when the
 * thread exits.  No TLS is set up, so thread code must not rely on it
 * (the tests are built with -fno-stack-protector).
 */
#define	FUTEX_WAIT	0
#define	FUTEX_WAKE	1
#define	FUTEX_PRIVATE_FLAG 128
#define	THREAD_FLAGS	(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | \
    CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID | CLONE_PARENT_SETTID)

/* Thread helpers remain amd64-only until their own suite is ported. */
#ifdef __x86_64__
struct thread {
	int tid;		/* zeroed by the kernel on exit */
	void *stack;
	unsigned long stack_size;
};

long __thread_clone(unsigned long flags, void *stack, int *ptid, int *ctid,
    int (*fn)(void *), void *arg);
__asm__(
	".text\n"
	".globl __thread_clone\n"
	"__thread_clone:\n"
	/* rdi=flags rsi=stack rdx=ptid rcx=ctid r8=fn r9=arg */
	"	and $-16, %rsi\n"
	"	sub $16, %rsi\n"
	"	mov %r9, 8(%rsi)\n"	/* arg */
	"	mov %r8, 0(%rsi)\n"	/* fn */
	"	mov $56, %eax\n"	/* SYS_clone */
	"	mov %rcx, %r10\n"	/* ctid -> r10 */
	"	xor %r8d, %r8d\n"	/* tls = 0 */
	"	syscall\n"
	"	test %rax, %rax\n"
	"	jnz 1f\n"
	/* child: on the new stack */
	"	xor %ebp, %ebp\n"
	"	pop %rax\n"		/* fn */
	"	pop %rdi\n"		/* arg */
	"	call *%rax\n"
	"	mov %eax, %edi\n"
	"	mov $60, %eax\n"	/* SYS_exit */
	"	syscall\n"
	"	hlt\n"
	"1:	ret\n");

static int __attribute__((unused))
thread_create(struct thread *t, int (*fn)(void *), void *arg)
{
	long r;

	t->stack_size = 256 * 1024;
	r = call(SYS_mmap, 0, t->stack_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (r < 0)
		return ((int)r);
	t->stack = (void *)r;
	t->tid = 1;	/* cleared by the kernel when the thread exits */
	r = __thread_clone(THREAD_FLAGS, (char *)t->stack + t->stack_size,
	    &t->tid, &t->tid, fn, arg);
	if (r < 0) {
		(void)sys2(SYS_munmap, t->stack, t->stack_size);
		return ((int)r);
	}
	return (0);
}

static int __attribute__((unused))
thread_join(struct thread *t)
{
	long r;
	int tid;

	for (;;) {
		tid = __atomic_load_n(&t->tid, __ATOMIC_ACQUIRE);
		if (tid == 0)
			break;
		/* The kernel wakes CHILD_CLEARTID with a private key. */
		r = sys6(SYS_futex, &t->tid, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, tid,
		    0, 0, 0);
		if (r != 0 && r != -EAGAIN && r != -EINTR)
			return ((int)r);
	}
	(void)sys2(SYS_munmap, t->stack, t->stack_size);
	return (0);
}

#endif /* __x86_64__ thread helpers */

static long __attribute__((unused))
futex_wait(int *addr, int val, const struct timespec *ts)
{

	return (sys6(SYS_futex, addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, val, ts,
	    0, 0));
}

static long __attribute__((unused))
futex_wake(int *addr, int n)
{

	return (sys6(SYS_futex, addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, n, 0, 0,
	    0));
}

/* SIG_IGN a signal through rt_sigaction (Linux struct sigaction layout). */
static void __attribute__((unused))
ignore_signal(int sig)
{
	struct { void *handler; unsigned long flags; void *restorer;
	    unsigned long mask; } sa;

	xmemset(&sa, 0, sizeof(sa));
	sa.handler = (void *)1;		/* SIG_IGN */
	(void)sys4(SYS_rt_sigaction, sig, &sa, 0, 8);
}

static void __attribute__((unused))
sleep_ms(long ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	(void)sys2(SYS_nanosleep, &ts, 0);
}

/*
 * Subtest framework.  A test file may define a table of named subtests and
 * hand it to run_subtests() from test(); this lets one freestanding binary
 * expose many independently-named, independently-run cases:
 *
 *   ./binary            run every subtest, print "ok"/"FAIL <name> rc=N" to
 *                       stderr, exit with the count of failures (0 == all ok).
 *   ./binary <name>     run one subtest, exit with its return code (0 == ok).
 *   ./binary -l         list subtest names on stdout, one per line, exit 0.
 *
 * The VM runner enumerates the names with -l on the (Linux) host at stage
 * time and generates one kyua test case per subtest.
 */
struct subtest {
	const char	*name;
	int		(*fn)(void);
};

static void __attribute__((unused))
wr1(const char *s)
{

	(void)sys3(SYS_write, 1, s, xstrlen(s));
}

static int __attribute__((unused))
run_subtests(int argc, char **argv, const struct subtest *t, int n)
{
	int i, fails, rc;

	if (argc > 1) {
		if (argv[1][0] == '-' && argv[1][1] == 'l' && argv[1][2] == '\0') {
			for (i = 0; i < n; i++) {
				wr1(t[i].name);
				wr1("\n");
			}
			return (0);
		}
		for (i = 0; i < n; i++) {
			if (xstreq(argv[1], t[i].name))
				return (t[i].fn());
		}
		msg("unknown subtest: ");
		msg(argv[1]);
		msg("\n");
		return (111);
	}
	fails = 0;
	for (i = 0; i < n; i++) {
		rc = t[i].fn();
		if (rc == 0) {
			msg("ok ");
			msg(t[i].name);
			msg("\n");
		} else {
			msg("FAIL ");
			msg(t[i].name);
			msgnum(" rc=", rc);
			fails++;
		}
	}
	return (fails);
}

static int test(int argc, char **argv, char **envp);

/* Entry with access to argv/envp: _start hands the initial stack to us. */
#ifdef __x86_64__
__attribute__((force_align_arg_pointer))
#endif
void
start_c(long *sp)
{
	long argc;
	char **argv, **envp;

	argc = sp[0];
	argv = (char **)&sp[1];
	envp = argv + argc + 1;
	(void)sys1(SYS_exit_group, test((int)argc, argv, envp));
	__builtin_unreachable();
}

#ifdef __aarch64__
__asm__(
	".globl _start\n"
	"_start:\n"
	" mov x29, #0\n"
	" mov x0, sp\n"
	" bl start_c\n"
	" brk #0\n");
#else
__asm__(
	".globl _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call start_c\n"
	"	hlt\n");
#endif

#endif /* LINUX_TEST_H */

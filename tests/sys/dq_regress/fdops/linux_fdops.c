/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * linux_fdops: the Linux-ABI system calls whose descriptor handling
 * DescriptorQueue stage 0 rewired (sys/compat/linux, 3b9f9873d291..), on
 * every descriptor kind a Linux program can create, by a process that is
 * not attached to a dq(4) controller.  A freestanding static amd64 Linux
 * program (no Linux libc), built at test time by linux_fdops_test.sh with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static
 * and run under linux64.ko.
 *
 * EXPECTATIONS are FreeBSD's behaviour at the project base 3b9f9873d291,
 * derived from that source and cited per cell ("lf:1378" is
 * sys/compat/linux/linux_file.c, "lx:" linux_xattr.c, "li:" linux_ioctl.c,
 * "ls:" linux_stats.c, "lm:" linux_misc.c, "vs:" sys/kern/vfs_syscalls.c,
 * "kd:" sys/kern/kern_descrip.c, "sp:" sys/kern/sys_pipe.c, all at
 * 3b9f9873d291).  Where base hands the call to a filesystem, the expected
 * value is the path form of the same Linux call on the same vnode (an
 * oracle; the path forms were not rewired).  Where the tree differed from
 * base before ux-0, base's value is what is expected; ux-0 slice 1
 * restored those cells.  Every failing cell prints one line; exit status 1
 * if any cell is not as base, 0 otherwise.
 *
 * usage: linux_fdops LPROC FLAGS
 *   LPROC  a linprocfs mount (for the O_PATH reopen of a pipe through
 *          LPROC/self/fd/N), or "-" when none is mounted.
 *   FLAGS  "skipfsyncfifo" when the kernel is the base kernel with
 *          INVARIANTS (base kern_fsync_fp asserts DTYPE_VNODE, vs:3693, and
 *          panics on a FIFO or ptmx master), else "-".
 *
 * ------------------------------------------------------------------------
 * CELLS RESTORED BY UX-0 SLICE 1 (their base value differed from the tree
 * before it, proxy/objects at f9e922d244b; derived by reading that tree's
 * sys/compat/linux and sys/kern against base; "now" is what that tree
 * answered, the last column the row that restored base):
 *
 *  fsync, fdatasync              opath_pipe          base EINVAL  now EBADF   D237
 *  utimensat(fd, NULL) (futimens) opath_pipe         base EINVAL  now EBADF   D237
 *  sync_file_range               memfd               base ESPIPE  now EINVAL  D237
 *  sync_file_range               inotify, signalfd,  base ESPIPE  now EINVAL  D237*
 *                                pidfd
 *  fadvise64                     epoll               base 0       now ESPIPE  D237
 *  fadvise64                     eventfd, inotify,   base 0       now ESPIPE  D237*
 *                                signalfd, pidfd
 *  fadvise64                     memfd               base 0       now ENODEV  D237*
 *  fadvise64                     fifo_rd, fifo_wr    base 0       now ESPIPE  D237*
 *    (DTYPE_FIFO is neither DTYPE_PIPE nor a DTYPE_VNODE VFIFO, lf:2540)
 *  fadvise64 bad advice          fifo_rd, fifo_wr,   base EINVAL  now ESPIPE  D237*
 *                                eventfd, epoll
 *  fallocate (len 0)             epoll               base ENODEV  now ESPIPE  D237
 *  fallocate (len 0)             eventfd             base ENODEV  now ESPIPE  D237*
 *  fallocate (len 0)             inotify, pidfd      base ENODEV  now EBADF   D237*
 *  fallocate (len 0)             signalfd            base ENODEV  now EINVAL  D237*
 *  fallocate (len 0)             fifo_rd, fifo_wr    base ENODEV  now ESPIPE  D237*
 *    (DTYPE_FIFO falls to the default case, lf:2722)
 *  readahead (offset -1)         memfd, inotify,     base EINVAL  now 0       D237*
 *                                signalfd, pidfd
 *  FS_IOC_SETFLAGS               pipe_r, pipe_w      base ENOTTY  now EINVAL  D237
 *  FS_IOC_SETFLAGS               ptmx                base ENOTTY  now 0       D237
 *  FS_IOC_SETFLAGS               fifo_rd, fifo_wr    base ENOTTY  now 0       D237*
 *  FS_IOC_SETFLAGS               opath_pipe          base ENOTTY  now EBADF   D237*
 *  FS_IOC_GETFLAGS               (none)              base has no type test
 *    (li:4014-4025: kern_fstat answers every kind, so 0 with no flag set;
 *    the plan's section 0bb says ENOTTY, which base's source does not give)
 *  file_getattr, file_setattr    opath_pipe          base EOPNOTSUPP now EBADF D237
 *    (NULL path, AT_EMPTY_PATH)
 *  F_SET_RW_HINT unprivileged    devnull, bad ptr    base EPERM   now EFAULT  D237
 *  F_SET_RW_HINT unprivileged    devnull, hint 99    base EPERM   now EINVAL  D237
 *  getdents64                    pipe_r, pipe_w      base EINVAL  now ENOTDIR UNOWNED
 *  getdents64                    opath_pipe          base EINVAL  now EBADF   UNOWNED
 *  f{get,set,remove}xattr        pipe_r, pipe_w      base EINVAL  now EOPNOTSUPP UNOWNED
 *    "bogus.x" (6 cells)
 *  f{get,set,list,remove}xattr   opath_pipe          base EINVAL  now EBADF   D237
 *    "user.*" and "bogus.x" (7 cells)
 *  flock(fd, 0)                  pipe_r, pipe_w,     base EOPNOTSUPP now EBADF D212
 *                                opath_pipe
 *  F_OFD_SETLK bad type,         devnull             base EOPNOTSUPP now EINVAL, D231
 *  F_OFD_SETLK/GETLK SEEK_CUR                        EOVERFLOW, EOVERFLOW
 *    overflow (3 cells)
 *  copy_file_range               as the native matrix (D230): a non-vnode    D230
 *                                readable input with an output refused by
 *                                fget or O_APPEND, or len 0, or a vnode input
 *                                with a non-vnode output and len 0: base
 *                                EINVAL, now EBADF or 0.
 *                                (60 len1 + 141 len0 cells with this
 *                                matrix: 12 non-vnode readable inputs,
 *                                7 vnode readable inputs, 10 outputs)
 *
 * In all, 263 cells when every kind is available (62 outside
 * copy_file_range).
 *
 *  D237* : D237's rule ("each Linux wrapper keeps base's type test result",
 *  plan section 1a.8) covers the cell, but the row's enumerated examples do
 *  not name that descriptor kind.
 *  UNOWNED: getdents64 (linux_getdents_error) and the xattr name-before-
 *  type order (xattr_getvnode) are rewired Linux paths that no plan row
 *  named; slice 1 restored them under D237's rule.
 *
 * NOT REACHABLE HERE: the Linux mount-id cap at INT_MAX-1 (needs 2^31
 * mounts); /proc/self/mountinfo (linprocfs output unchanged by the
 * project); the MAC-only changes to splice, tee and sendfile (no policy
 * here; the rows below pin their unchanged results).
 */

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef long s64;

#define	SYS_read		0
#define	SYS_write		1
#define	SYS_open		2
#define	SYS_close		3
#define	SYS_stat		4
#define	SYS_fstat		5
#define	SYS_lstat		6
#define	SYS_lseek		8
#define	SYS_ioctl		16
#define	SYS_dup2		33
#define	SYS_getpid		39
#define	SYS_sendfile		40
#define	SYS_socket		41
#define	SYS_socketpair		53
#define	SYS_fork		57
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_fcntl		72
#define	SYS_flock		73
#define	SYS_fsync		74
#define	SYS_fdatasync		75
#define	SYS_mkdir		83
#define	SYS_symlink		88
#define	SYS_chmod		90
#define	SYS_fchmod		91
#define	SYS_fchown		93
#define	SYS_lchown		94
#define	SYS_setuid		105
#define	SYS_setgid		106
#define	SYS_statfs		137
#define	SYS_fstatfs		138
#define	SYS_readahead		187
#define	SYS_setxattr		188
#define	SYS_lsetxattr		189
#define	SYS_fsetxattr		190
#define	SYS_getxattr		191
#define	SYS_lgetxattr		192
#define	SYS_fgetxattr		193
#define	SYS_listxattr		194
#define	SYS_llistxattr		195
#define	SYS_flistxattr		196
#define	SYS_removexattr		197
#define	SYS_lremovexattr	198
#define	SYS_fremovexattr	199
#define	SYS_getdents64		217
#define	SYS_fadvise64		221
#define	SYS_exit_group		231
#define	SYS_openat		257
#define	SYS_mknodat		259
#define	SYS_fchownat		260
#define	SYS_splice		275
#define	SYS_tee			276
#define	SYS_sync_file_range	277
#define	SYS_utimensat		280
#define	SYS_timerfd_create	283
#define	SYS_fallocate		285
#define	SYS_signalfd4		289
#define	SYS_eventfd2		290
#define	SYS_epoll_create1	291
#define	SYS_pipe2		293
#define	SYS_inotify_init1	294
#define	SYS_syncfs		306
#define	SYS_memfd_create	319
#define	SYS_copy_file_range	326
#define	SYS_statx		332
#define	SYS_pidfd_open		434
#define	SYS_fchmodat2		452
#define	SYS_file_getattr	468
#define	SYS_file_setattr	469

#define	EPERM		1
#define	EBADF		9
#define	EFAULT		14
#define	ENODEV		19
#define	ENOTDIR		20
#define	EISDIR		21
#define	EINVAL		22
#define	ENOTTY		25
#define	ESPIPE		29
#define	EOVERFLOW	75
#define	EOPNOTSUPP	95

#define	AT_FDCWD		-100
#define	AT_SYMLINK_NOFOLLOW	0x100
#define	AT_EMPTY_PATH		0x1000
#define	O_RDONLY	0
#define	O_WRONLY	1
#define	O_RDWR		2
#define	O_CREAT		0100
#define	O_EXCL		0200
#define	O_NOCTTY	0400
#define	O_APPEND	02000
#define	O_NONBLOCK	04000
#define	O_DIRECTORY	0200000
#define	O_NOFOLLOW	0400000
#define	O_PATH		010000000
#define	S_IFIFO		0010000
#define	S_IFMT		0170000
#define	F_GETLK		5
#define	F_SETLK		6
#define	F_OFD_GETLK	36
#define	F_OFD_SETLK	37
#define	F_GET_RW_HINT	1035
#define	F_SET_RW_HINT	1036
#define	F_RDLCK		0
#define	F_WRLCK		1
#define	F_UNLCK		2
#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	LOCK_EX		2
#define	LOCK_NB		4
#define	LOCK_UN		8
#define	FS_IOC_GETFLAGS	0x80086601UL
#define	FS_IOC_SETFLAGS	0x40086602UL
#define	UTIME_OMIT	((1L << 30) - 2L)
#define	STATX_BASIC_STATS	0x7ff
#define	STATX_MNT_ID		0x1000
#define	OFF_MAX		0x7fffffffffffffffL

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

#define	S1(n, a)		call(n, (long)(a), 0, 0, 0, 0, 0)
#define	S2(n, a, b)		call(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define	S3(n, a, b, c)		call(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define	S4(n, a, b, c, d)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), 0, 0)
#define	S5(n, a, b, c, d, e)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), 0)
#define	S6(n, a, b, c, d, e, f)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), (long)(f))

/* The compiler may emit these for struct copies and zeroing. */
void *memset(void *, int, unsigned long);
void *memcpy(void *, const void *, unsigned long);
void *
memset(void *p, int v, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = (char)v;
	return (p);
}
void *
memcpy(void *d, const void *s, unsigned long n)
{
	volatile char *x = d;
	const char *y = s;

	while (n-- > 0)
		*x++ = *y++;
	return (d);
}

static unsigned long
slen(const char *s)
{
	unsigned long n;

	for (n = 0; s[n] != '\0'; n++)
		;
	return (n);
}

static int
seq(const char *a, const char *b)
{
	while (*a != '\0' && *a == *b) {
		a++;
		b++;
	}
	return (*a == *b);
}

static void
out(const char *s)
{
	(void)S3(SYS_write, 1, s, slen(s));
}

static void
outn(long v)
{
	char b[24];
	int i = 23;
	int neg = v < 0;
	unsigned long u = neg ? (unsigned long)-v : (unsigned long)v;

	b[i] = '\0';
	do {
		b[--i] = (char)('0' + u % 10);
		u /= 10;
	} while (u != 0);
	if (neg)
		b[--i] = '-';
	out(&b[i]);
}

/* Build "prefix<n>" into buf. */
static void
mkname(char *buf, const char *prefix, int n)
{
	char d[16];
	int i = 15, j;

	d[i] = '\0';
	do {
		d[--i] = (char)('0' + n % 10);
		n /= 10;
	} while (n != 0);
	for (j = 0; prefix[j] != '\0'; j++)
		buf[j] = prefix[j];
	while (d[i] != '\0')
		buf[j++] = d[i++];
	buf[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* Cells.                                                              */
/* ------------------------------------------------------------------ */

static int g_cells, g_fails, g_skips;
static const char *g_row = "?";

/* want: a negative Linux errno, or an exact value (>= 0), or W_ANY. */
#define	W_ANY	(-1000000L)

static int
cell(const char *sub, const char *kind, const char *k2, long got, long want,
    const char *cite)
{
	int ok;

	g_cells++;
	ok = want == W_ANY ? got >= 0 : got == want;
	if (ok)
		return (1);
	g_fails++;
	out("FAIL ");
	out(g_row);
	out("/");
	out(sub);
	out(" [");
	out(kind);
	if (k2 != 0) {
		out(" -> ");
		out(k2);
	}
	out("]: got ");
	outn(got);
	out(", base ");
	if (want == W_ANY)
		out(">=0");
	else
		outn(want);
	out(" (");
	out(cite);
	out(")\n");
	return (0);
}

/* ------------------------------------------------------------------ */
/* Descriptor kinds (base attributes).                                 */
/* ------------------------------------------------------------------ */

enum dt { DT_VNODE, DT_FIFO, DT_PIPE, DT_SOCK, DT_KQ, DT_SHM, DT_PTS,
	DT_EVFD, DT_TFD, DT_SIGFD, DT_INOT, DT_PIDFD, DT_BAD };
enum vt { VT_NONE, VT_REG, VT_DIR, VT_LNK, VT_FIFO, VT_CHR };

#define	A_VN	0x001	/* f_vnode != NULL */
#define	A_OPATH	0x002	/* path_fileops */
#define	A_OPF	0x004	/* O_PATH in f_flag on pipeops (linprocfs reopen) */
#define	A_RD	0x008
#define	A_WR	0x010
#define	A_APP	0x020
#define	A_DEV	0x040
#define	A_LNK	0x080
#define	A_INET	0x100

enum kid {
	K_REG, K_REG_RDONLY, K_REG_WRONLY, K_REG_APPEND, K_DIR,
	K_SYMLINK_OPATH, K_FIFO_RD, K_FIFO_WR, K_PIPE_R, K_PIPE_W,
	K_UNIX_STREAM, K_UNIX_DGRAM, K_SOCKETPAIR, K_INET, K_EVENTFD,
	K_TIMERFD, K_SIGNALFD, K_EPOLL, K_INOTIFY, K_MEMFD, K_PIDFD, K_PTMX,
	K_DEVNULL, K_OPATH_REG, K_OPATH_DIR, K_OPATH_FIFO, K_OPATH_DEV,
	K_OPATH_PIPE, K_BAD_NEG, K_BAD_CLOSED, K_BAD_RANGE, K__N
};

struct kdef {
	const char	*name;
	unsigned	 a;
	enum dt		 dt;
	enum vt		 vt;
};

#define	RW	(A_RD | A_WR)
static const struct kdef kdefs[K__N] = {
	[K_REG] = { "reg", A_VN | RW, DT_VNODE, VT_REG },
	[K_REG_RDONLY] = { "reg_rdonly", A_VN | A_RD, DT_VNODE, VT_REG },
	[K_REG_WRONLY] = { "reg_wronly", A_VN | A_WR, DT_VNODE, VT_REG },
	[K_REG_APPEND] = { "reg_append", A_VN | RW | A_APP, DT_VNODE, VT_REG },
	[K_DIR] = { "dir", A_VN | A_RD, DT_VNODE, VT_DIR },
	[K_SYMLINK_OPATH] = { "symlink_opath", A_VN | A_OPATH | A_LNK,
	    DT_VNODE, VT_LNK },
	[K_FIFO_RD] = { "fifo_rd", A_VN | A_RD, DT_FIFO, VT_FIFO },
	[K_FIFO_WR] = { "fifo_wr", A_VN | A_WR, DT_FIFO, VT_FIFO },
	[K_PIPE_R] = { "pipe_r", A_RD, DT_PIPE, VT_NONE },
	[K_PIPE_W] = { "pipe_w", A_WR, DT_PIPE, VT_NONE },
	[K_UNIX_STREAM] = { "unix_stream", RW, DT_SOCK, VT_NONE },
	[K_UNIX_DGRAM] = { "unix_dgram", RW, DT_SOCK, VT_NONE },
	[K_SOCKETPAIR] = { "socketpair", RW, DT_SOCK, VT_NONE },
	[K_INET] = { "inet", RW | A_INET, DT_SOCK, VT_NONE },
	[K_EVENTFD] = { "eventfd", RW, DT_EVFD, VT_NONE },
	[K_TIMERFD] = { "timerfd", A_RD, DT_TFD, VT_NONE },
	[K_SIGNALFD] = { "signalfd", RW, DT_SIGFD, VT_NONE },
	[K_EPOLL] = { "epoll", RW, DT_KQ, VT_NONE },
	[K_INOTIFY] = { "inotify", A_RD, DT_INOT, VT_NONE },
	[K_MEMFD] = { "memfd", RW, DT_SHM, VT_NONE },
	[K_PIDFD] = { "pidfd", A_RD, DT_PIDFD, VT_NONE },
	[K_PTMX] = { "ptmx", A_VN | RW | A_DEV, DT_PTS, VT_CHR },
	[K_DEVNULL] = { "devnull", A_VN | RW | A_DEV, DT_VNODE, VT_CHR },
	[K_OPATH_REG] = { "opath_reg", A_VN | A_OPATH, DT_VNODE, VT_REG },
	[K_OPATH_DIR] = { "opath_dir", A_VN | A_OPATH, DT_VNODE, VT_DIR },
	[K_OPATH_FIFO] = { "opath_fifo", A_VN | A_OPATH, DT_VNODE, VT_FIFO },
	[K_OPATH_DEV] = { "opath_dev", A_VN | A_OPATH | A_DEV, DT_VNODE,
	    VT_CHR },
	[K_OPATH_PIPE] = { "opath_pipe", A_OPF, DT_PIPE, VT_NONE },
	[K_BAD_NEG] = { "bad_neg", 0, DT_BAD, VT_NONE },
	[K_BAD_CLOSED] = { "bad_closed", 0, DT_BAD, VT_NONE },
	[K_BAD_RANGE] = { "bad_range", 0, DT_BAD, VT_NONE },
};

struct kinst {
	const struct kdef *k;
	enum kid	 id;
	int		 fd;
	int		 aux[2];
	char		 path[64];	/* the vnode's path, "" if none */
};

#define	HAS(ki, f)	(((ki)->k->a & (f)) != 0)
#define	BAD(ki)		((ki)->k->dt == DT_BAD)

static const char *g_lproc;
static int g_seq;
static int g_skipfsyncfifo;
static const char data10[] = "0123456789";

static long
mkfile(const char *path)
{
	long fd;

	fd = S4(SYS_openat, AT_FDCWD, path, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd < 0)
		return (fd);
	(void)S3(SYS_write, fd, data10, 10);
	(void)S1(SYS_close, fd);
	return (0);
}

static void
cpy(char *d, const char *s)
{
	while ((*d++ = *s++) != '\0')
		;
}

/* Returns 0, or a negative errno: the kind is not available. */
static long
kmake(enum kid id, struct kinst *ki)
{
	char tgt[32], fdp[96];
	long fd, p[2], r;
	u64 mask;
	int sv[2];

	ki->k = &kdefs[id];
	ki->id = id;
	ki->fd = -1;
	ki->aux[0] = ki->aux[1] = -1;
	ki->path[0] = '\0';
	fd = -1;
	switch (id) {
	case K_REG:
	case K_REG_RDONLY:
	case K_REG_WRONLY:
	case K_REG_APPEND:
	case K_OPATH_REG:
		mkname(ki->path, "lf", ++g_seq);
		if ((r = mkfile(ki->path)) < 0)
			return (r);
		fd = S3(SYS_open, ki->path, id == K_REG ? O_RDWR :
		    id == K_REG_RDONLY ? O_RDONLY : id == K_REG_WRONLY ?
		    O_WRONLY : id == K_REG_APPEND ? O_RDWR | O_APPEND : O_PATH,
		    0);
		break;
	case K_DIR:
	case K_OPATH_DIR:
		mkname(ki->path, "ld", ++g_seq);
		if ((r = S2(SYS_mkdir, ki->path, 0755)) < 0)
			return (r);
		fd = S3(SYS_open, ki->path, (id == K_DIR ? O_RDONLY : O_PATH) |
		    O_DIRECTORY, 0);
		break;
	case K_SYMLINK_OPATH:
		mkname(tgt, "lt", ++g_seq);
		if ((r = mkfile(tgt)) < 0)
			return (r);
		mkname(ki->path, "ll", ++g_seq);
		if ((r = S2(SYS_symlink, tgt, ki->path)) < 0)
			return (r);
		fd = S3(SYS_open, ki->path, O_PATH | O_NOFOLLOW, 0);
		break;
	case K_FIFO_RD:
	case K_FIFO_WR:
	case K_OPATH_FIFO:
		mkname(ki->path, "lp", ++g_seq);
		if ((r = S4(SYS_mknodat, AT_FDCWD, ki->path, S_IFIFO | 0644,
		    0)) < 0)
			return (r);
		if (id == K_FIFO_RD)
			fd = S3(SYS_open, ki->path, O_RDONLY | O_NONBLOCK, 0);
		else if (id == K_FIFO_WR) {
			ki->aux[0] = (int)S3(SYS_open, ki->path,
			    O_RDONLY | O_NONBLOCK, 0);
			fd = S3(SYS_open, ki->path, O_WRONLY | O_NONBLOCK, 0);
		} else
			fd = S3(SYS_open, ki->path, O_PATH, 0);
		break;
	case K_PIPE_R:
	case K_PIPE_W:
	case K_OPATH_PIPE: {
		int pp[2];

		/* linux_pipe2: one-way pipes (kern_pipe_unidirectional). */
		if ((r = S2(SYS_pipe2, pp, 0)) < 0)
			return (r);
		p[0] = pp[0];
		p[1] = pp[1];
		if (id == K_OPATH_PIPE) {
			if (g_lproc[0] == '-')
				return (-1000);
			ki->aux[0] = (int)p[0];
			ki->aux[1] = (int)p[1];
			cpy(fdp, g_lproc);
			mkname(fdp + slen(fdp), "/self/fd/", (int)p[1]);
			fd = S3(SYS_open, fdp, O_PATH, 0);
			if (fd < 0)
				return (fd);
			break;
		}
		fd = id == K_PIPE_R ? p[0] : p[1];
		ki->aux[0] = (int)(id == K_PIPE_R ? p[1] : p[0]);
		break;
	}
	case K_UNIX_STREAM:
		fd = S3(SYS_socket, 1, 1, 0);
		break;
	case K_UNIX_DGRAM:
		fd = S3(SYS_socket, 1, 2, 0);
		break;
	case K_SOCKETPAIR:
		if ((r = S4(SYS_socketpair, 1, 1, 0, sv)) < 0)
			return (r);
		fd = sv[0];
		ki->aux[0] = sv[1];
		break;
	case K_INET:
		fd = S3(SYS_socket, 2, 1, 0);
		break;
	case K_EVENTFD:
		fd = S2(SYS_eventfd2, 0, 0);
		break;
	case K_TIMERFD:
		fd = S2(SYS_timerfd_create, 1, 0);
		break;
	case K_SIGNALFD:
		mask = 1UL << 9;	/* SIGUSR1 - 1 */
		fd = S4(SYS_signalfd4, -1, &mask, 8, 0);
		break;
	case K_EPOLL:
		fd = S1(SYS_epoll_create1, 0);
		break;
	case K_INOTIFY:
		fd = S1(SYS_inotify_init1, 0);
		break;
	case K_MEMFD:
		fd = S2(SYS_memfd_create, "fdops", 0);
		break;
	case K_PIDFD:
		fd = S2(SYS_pidfd_open, S1(SYS_getpid, 0), 0);
		break;
	case K_PTMX:
		cpy(ki->path, "/dev/ptmx");
		fd = S3(SYS_open, ki->path, O_RDWR | O_NOCTTY, 0);
		break;
	case K_DEVNULL:
	case K_OPATH_DEV:
		cpy(ki->path, "/dev/null");
		fd = S3(SYS_open, ki->path, id == K_DEVNULL ? O_RDWR : O_PATH,
		    0);
		break;
	case K_BAD_NEG:
		ki->fd = -1;
		return (0);
	case K_BAD_CLOSED:
		fd = S3(SYS_open, "/dev/null", O_RDONLY, 0);
		(void)S2(SYS_dup2, fd, 900);
		(void)S1(SYS_close, fd);
		(void)S1(SYS_close, 900);
		ki->fd = 900;
		return (0);
	case K_BAD_RANGE:
		ki->fd = 0x7fffffff;
		return (0);
	case K__N:
		break;
	}
	if (fd < 0)
		return (fd);
	ki->fd = (int)fd;
	return (0);
}

static void
kfree(struct kinst *ki)
{
	if (!BAD(ki) && ki->fd >= 0)
		(void)S1(SYS_close, ki->fd);
	if (ki->aux[0] >= 0)
		(void)S1(SYS_close, ki->aux[0]);
	if (ki->aux[1] >= 0)
		(void)S1(SYS_close, ki->aux[1]);
}

typedef void rowfn_t(struct kinst *);

static void
each_kind(const char *row, rowfn_t *fn)
{
	struct kinst ki;
	long r;
	int i;

	g_row = row;
	for (i = 0; i < K__N; i++) {
		r = kmake((enum kid)i, &ki);
		if (r < 0) {
			g_skips++;
			out("skip ");
			out(row);
			out(" [");
			out(kdefs[i].name);
			out("]: ");
			if (r == -1000)
				out("no linprocfs mount");
			else {
				out("create errno ");
				outn(-r);
			}
			out("\n");
			kfree(&ki);
			continue;
		}
		fn(&ki);
		kfree(&ki);
	}
}

/* ------------------------------------------------------------------ */
/* Linux struct layouts (x86_64).                                      */
/* ------------------------------------------------------------------ */

struct l_stat {
	u64	dev, ino, nlink;
	u32	mode, uid, gid, pad0;
	u64	rdev;
	s64	size, blksize, blocks;
	u64	atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
	s64	unused[3];
};

struct l_flock {
	short	type;
	short	whence;
	int	pad;
	s64	start;
	s64	len;
	int	pid;
	int	pad2;
};

struct l_timespec {
	s64	sec;
	s64	nsec;
};

struct l_file_attr {
	u64	xflags;
	u32	extsize, nextents, projid, cowextsize;
};

/* The vnode's own stat, by path (lstat for a symlink). */
static long
pstat(const struct kinst *ki, struct l_stat *st)
{
	return (S2(HAS(ki, A_LNK) ? SYS_lstat : SYS_stat, ki->path, st));
}

/* ------------------------------------------------------------------ */
/* fsync(2), fdatasync(2): native sys_fsync/linux_fdatasync ->         */
/* kern_fsync, vs:3717-3735.                                           */
/* ------------------------------------------------------------------ */

static long
want_fsync(const struct kinst *ki, const char **why)
{
	if (BAD(ki)) {
		*why = "vs:3723 getvnode: fget";
		return (-EBADF);
	}
	if (!HAS(ki, A_VN)) {
		*why = "vs:3723 -> 4632-4636 no vnode (an O_PATH pipe too)";
		return (-EINVAL);
	}
	if (HAS(ki, A_OPATH)) {
		*why = "vs:3723 -> 4661-4663 O_PATH";
		return (-EBADF);
	}
	*why = "vs:3686-3713 kern_fsync_fp";
	return (0);
}

static void
row_fsync(struct kinst *ki)
{
	const char *why;
	long w;

	w = want_fsync(ki, &why);
	if (w == 0 && ki->k->dt != DT_VNODE && g_skipfsyncfifo) {
		out("not run fsync [");
		out(ki->k->name);
		out("]: base MPASS at vs:3693 panics INVARIANTS\n");
		return;
	}
	(void)cell("fsync", ki->k->name, 0, S1(SYS_fsync, ki->fd), w, why);
	(void)cell("fdatasync", ki->k->name, 0, S1(SYS_fdatasync, ki->fd), w,
	    why);
}

/* ------------------------------------------------------------------ */
/* sync_file_range(2): linux_sync_file_range, lf:1378-1410.            */
/* ------------------------------------------------------------------ */

static void
row_sync_file_range(struct kinst *ki)
{
	const char *why;
	long w;

	if (BAD(ki)) {
		w = -EBADF;
		why = "lf:1388 fget";
	} else if (ki->k->dt != DT_VNODE || (ki->k->vt != VT_REG &&
	    ki->k->vt != VT_DIR && ki->k->vt != VT_LNK)) {
		w = -ESPIPE;
		why = "lf:1398-1403 not a DTYPE_VNODE VREG/VBLK/VDIR/VLNK";
	} else {
		w = 0;
		why = "lf:1406 kern_fsync_fp (O_PATH accepted)";
	}
	(void)cell("whole", ki->k->name, 0, S4(SYS_sync_file_range, ki->fd,
	    0, 0, 0), w, why);
	(void)cell("bad_flags", ki->k->name, 0, S4(SYS_sync_file_range,
	    ki->fd, 0, 0, 8), BAD(ki) ? -EBADF : -EINVAL, BAD(ki) ?
	    "lf:1388 fget, before the flags" : "lf:1391-1397 flags, before "
	    "the type");
}

/* ------------------------------------------------------------------ */
/* fadvise64(2): linux_kern_fadvise, lf:2530-2566.                     */
/* ------------------------------------------------------------------ */

static void
row_fadvise64(struct kinst *ki)
{
	const char *why, *bwhy;
	long w, bw;
	int pipe;

	pipe = ki->k->dt == DT_PIPE || (ki->k->dt == DT_VNODE &&
	    ki->k->vt == VT_FIFO);
	if (BAD(ki)) {
		w = bw = -EBADF;
		why = bwhy = "lf:2537 fget";
	} else if (pipe) {
		w = bw = -ESPIPE;
		why = bwhy = "lf:2540-2544 DTYPE_PIPE or VFIFO";
	} else {
		bw = -EINVAL;
		bwhy = "lf:2549-2553 advice";
		if (ki->k->dt != DT_VNODE || ki->k->vt != VT_REG) {
			w = 0;
			why = "lf:2555-2558 not a DTYPE_VNODE VREG: no-op";
		} else if (HAS(ki, A_OPATH)) {
			w = -ESPIPE;
			why = "lf:2563 -> vs:5141-5142 path_fileops not "
			    "seekable";
		} else {
			w = 0;
			why = "lf:2563 -> vs:5129 kern_posix_fadvise_fp";
		}
	}
	(void)cell("normal", ki->k->name, 0, S4(SYS_fadvise64, ki->fd, 0, 0,
	    0), w, why);
	(void)cell("bad_advice", ki->k->name, 0, S4(SYS_fadvise64, ki->fd, 0,
	    0, 99), bw, bwhy);
}

/* ------------------------------------------------------------------ */
/* fallocate(2) with len 0: linux_kern_fallocate, lf:2765-2779 and     */
/* linux_fallocate_check, lf:2702-2728: the type test, FWRITE, then    */
/* the length (lf:2745), so no filesystem is reached.                  */
/* ------------------------------------------------------------------ */

static void
row_fallocate(struct kinst *ki)
{
	const char *why;
	long w;

	if (BAD(ki)) {
		w = -EBADF;
		why = "lf:2775 fget";
	} else {
		w = 0;
		why = "";
		switch (ki->k->dt) {
		case DT_VNODE:
			if (ki->k->vt == VT_FIFO) {
				w = -ESPIPE;
				why = "lf:2710-2711 VFIFO";
			} else if (ki->k->vt == VT_DIR) {
				w = -EISDIR;
				why = "lf:2712-2713 VDIR";
			} else if (ki->k->vt != VT_REG) {
				w = -ENODEV;
				why = "lf:2714-2715 not VREG";
			}
			break;
		case DT_SHM:
			break;
		case DT_PIPE:
			w = -ESPIPE;
			why = "lf:2719-2721 DTYPE_PIPE";
			break;
		default:
			/* DTYPE_FIFO, sockets, kqueue (epoll), pts, eventfd,
			 * timerfd, signalfd, inotify, pidfd. */
			w = -ENODEV;
			why = "lf:2722-2724 any other type";
			break;
		}
		if (w == 0 && !HAS(ki, A_WR)) {
			w = -EBADF;
			why = "lf:2726-2727 not FWRITE";
		}
		if (w == 0) {
			w = -EINVAL;
			why = "lf:2745-2746 len <= 0";
		}
	}
	(void)cell("len0", ki->k->name, 0, S4(SYS_fallocate, ki->fd, 0, 0, 0),
	    w, why);
}

/* ------------------------------------------------------------------ */
/* readahead(2) with a negative offset (a no-op hint after the type    */
/* test): linux_readahead, lf:2837-2864.                               */
/* ------------------------------------------------------------------ */

static void
row_readahead(struct kinst *ki)
{
	const char *why;
	long w;

	if (BAD(ki) || !HAS(ki, A_RD)) {
		w = -EBADF;
		why = "lf:2843-2845 fget_read";
	} else if (ki->k->dt != DT_VNODE || ki->k->vt != VT_REG) {
		w = -EINVAL;
		why = "lf:2846-2847 not a DTYPE_VNODE VREG";
	} else {
		w = 0;
		why = "lf:2855-2856 negative offset: no-op";
	}
	(void)cell("neg_offset", ki->k->name, 0, S3(SYS_readahead, ki->fd,
	    -1, 4096), w, why);
}

/* ------------------------------------------------------------------ */
/* getdents64(2): linux_getdents64, lf:920, and linux_getdents_error,  */
/* lf:756-773.                                                         */
/* ------------------------------------------------------------------ */

static void
row_getdents64(struct kinst *ki)
{
	char buf[4096];
	const char *why;
	long w;

	if (BAD(ki)) {
		w = -EBADF;
		why = "lf:763 getvnode: fget";
	} else if (!HAS(ki, A_VN)) {
		w = -EINVAL;
		why = "lf:763 -> vs:4632-4636 no vnode (pipe ends, O_PATH "
		    "pipe), whatever getdirentries said";
	} else if (HAS(ki, A_OPATH)) {
		w = -EBADF;
		why = "lf:763 -> vs:4661-4663 O_PATH";
	} else if (ki->k->vt != VT_DIR) {
		w = -ENOTDIR;
		why = "lf:767-769 not VDIR";
	} else {
		w = W_ANY;
		why = "lf:937 linux_getdirentries";
	}
	(void)cell("read", ki->k->name, 0, S3(SYS_getdents64, ki->fd, buf,
	    sizeof(buf)), w, why);
}

/* ------------------------------------------------------------------ */
/* FS_IOC_SETFLAGS: linux_ioctl_generic, li:4028-4060, then the native */
/* sys_fchflags (vs:2854).  The flags are the file's own: nothing      */
/* changes.                                                            */
/* ------------------------------------------------------------------ */

static void
row_setflags(struct kinst *ki)
{
	const char *why;
	long w;
	unsigned long lflags;

	lflags = 0;
	if (BAD(ki)) {
		w = -EBADF;
		why = "li:4040-4043 fget";
	} else if (ki->k->dt != DT_VNODE) {
		w = -ENOTTY;
		why = "li:4044-4047 not DTYPE_VNODE (FIFO, pipe, ptmx, ...)";
	} else if (HAS(ki, A_OPATH)) {
		w = -EBADF;
		why = "li:4060 sys_fchflags -> vs:2862 -> 4661-4663 O_PATH";
	} else {
		w = 0;
		why = "li:4060 sys_fchflags -> vs:2892 setfflags";
	}
	(void)cell("same_flags", ki->k->name, 0, S3(SYS_ioctl, ki->fd,
	    FS_IOC_SETFLAGS, &lflags), w, why);
}

/* ------------------------------------------------------------------ */
/* FS_IOC_GETFLAGS: linux_ioctl_generic, li:4014-4025.  Base makes no  */
/* type test: kern_fstat (li:4015) answers every kind, and none made   */
/* here carries a flag Linux can see.                                  */
/* ------------------------------------------------------------------ */

static void
row_getflags(struct kinst *ki)
{
	unsigned long lflags;
	long r;

	lflags = ~0UL;
	r = S3(SYS_ioctl, ki->fd, FS_IOC_GETFLAGS, &lflags);
	if (BAD(ki)) {
		(void)cell("get", ki->k->name, 0, r, -EBADF,
		    "li:4015 kern_fstat -> fget");
		return;
	}
	if (cell("get", ki->k->name, 0, r, 0,
	    "li:4015-4025 kern_fstat, no type test"))
		(void)cell("flags", ki->k->name, 0, (long)lflags, 0,
		    "li:4018-4024 no st_flags bit set");
}

/* ------------------------------------------------------------------ */
/* file_getattr(2), file_setattr(2) with a NULL path and AT_EMPTY_PATH: */
/* lf:479-503, 542-596 and linux_fileattr_stat, lf:399-439.            */
/* ------------------------------------------------------------------ */

static void
row_fileattr(struct kinst *ki)
{
	struct l_file_attr fa;
	const char *why;
	long w;

	if (ki->fd < 0) {
		w = -EFAULT;
		why = "lf:413-414 NULL filename with fd < 0";
	} else if (BAD(ki)) {
		w = -EBADF;
		why = "lf:416 getvnode: fget";
	} else if (!HAS(ki, A_VN)) {
		w = -EOPNOTSUPP;
		why = "lf:416-418 getvnode EINVAL -> EOPNOTSUPP (no vnode, an "
		    "O_PATH pipe too)";
	} else if (HAS(ki, A_OPATH)) {
		w = -EBADF;
		why = "lf:416 -> vs:4661-4663 O_PATH";
	} else if (ki->k->vt != VT_REG && ki->k->vt != VT_DIR) {
		w = -EOPNOTSUPP;
		why = "lf:497-498 / 576-577 not VREG/VDIR";
	} else {
		w = 0;
		why = "lf:500-502 / 590 setfflags";
	}
	memset(&fa, 0, sizeof(fa));
	(void)cell("getattr", ki->k->name, 0, S5(SYS_file_getattr, ki->fd, 0,
	    &fa, sizeof(fa), AT_EMPTY_PATH), w, why);
	/* The file's own flags back (xflags 0 keeps the other bits). */
	fa.xflags = 0;
	(void)cell("setattr", ki->k->name, 0, S5(SYS_file_setattr, ki->fd, 0,
	    &fa, sizeof(fa), AT_EMPTY_PATH), w, why);
}

/* ------------------------------------------------------------------ */
/* F_GET_RW_HINT / F_SET_RW_HINT: fcntl_common, lf:2305-2335.          */
/* ------------------------------------------------------------------ */

static void
row_rw_hint(struct kinst *ki)
{
	const char *why;
	u64 hint;
	long w;

	if (BAD(ki)) {
		w = -EBADF;
		why = "lf:2306/2316 fget";
	} else if (ki->k->dt != DT_VNODE) {
		w = -EINVAL;
		why = "lf:2309-2312/2319-2322 not DTYPE_VNODE";
	} else {
		w = 0;
		why = "lf:2313-2315 / 2323-2333";
	}
	hint = 7;
	(void)cell("get", ki->k->name, 0, S3(SYS_fcntl, ki->fd,
	    F_GET_RW_HINT, &hint), w, why);
	hint = 0;	/* RWH_WRITE_LIFE_NOT_SET: the default, nothing changes */
	(void)cell("set_default", ki->k->name, 0, S3(SYS_fcntl, ki->fd,
	    F_SET_RW_HINT, &hint), w, why);
	hint = 99;
	(void)cell("set_bad_hint", ki->k->name, 0, S3(SYS_fcntl, ki->fd,
	    F_SET_RW_HINT, &hint), w == 0 ? -EINVAL : w, w == 0 ?
	    "lf:2329-2330 hint > RWH_WRITE_LIFE_EXTREME" : why);
	(void)cell("set_bad_ptr", ki->k->name, 0, S3(SYS_fcntl, ki->fd,
	    F_SET_RW_HINT, 8), w == 0 ? -EFAULT : w, w == 0 ?
	    "lf:2327-2328 copyin" : why);
}

/*
 * The same set by an unprivileged process on /dev/null (root's): base
 * checks VADMIN (lf:2323-2326, EPERM from devfs vaccess) before reading
 * the argument.
 */
static void
rw_hint_unpriv(void)
{
	long fd, pid, res[3];
	int pp[2], st;
	u64 hint;

	g_row = "rw_hint_unpriv";
	fd = S3(SYS_open, "/dev/null", O_RDWR, 0);
	if (fd < 0 || S2(SYS_pipe2, pp, 0) < 0) {
		out("skip rw_hint_unpriv: setup\n");
		g_skips++;
		return;
	}
	pid = S1(SYS_fork, 0);
	if (pid == 0) {
		if (S1(SYS_setgid, 65534) != 0 || S1(SYS_setuid, 65534) != 0)
			(void)S1(SYS_exit_group, 3);
		hint = 0;
		res[0] = S3(SYS_fcntl, fd, F_SET_RW_HINT, &hint);
		res[1] = S3(SYS_fcntl, fd, F_SET_RW_HINT, 8);
		hint = 99;
		res[2] = S3(SYS_fcntl, fd, F_SET_RW_HINT, &hint);
		(void)S3(SYS_write, pp[1], res, sizeof(res));
		(void)S1(SYS_exit_group, 0);
	}
	(void)S4(SYS_wait4, pid, &st, 0, 0);
	if (S3(SYS_read, pp[0], res, sizeof(res)) != sizeof(res)) {
		out("skip rw_hint_unpriv: child\n");
		g_skips++;
		return;
	}
	(void)cell("valid", "devnull", 0, res[0], -EPERM,
	    "lf:2323-2326 VOP_ACCESS(VADMIN)");
	(void)cell("bad_ptr", "devnull", 0, res[1], -EPERM,
	    "lf:2323-2326 VADMIN before the copyin at 2327");
	(void)cell("bad_hint", "devnull", 0, res[2], -EPERM,
	    "lf:2323-2326 VADMIN before the range test at 2329");
	(void)S1(SYS_close, fd);
	(void)S1(SYS_close, pp[0]);
	(void)S1(SYS_close, pp[1]);
}

/* ------------------------------------------------------------------ */
/* f*xattr(2): lx:136-145 xattr_getvnode (getvnode: no vnode EINVAL,   */
/* O_PATH EBADF) before the name (lx:483 xattr_to_extattr), then the   */
/* vnode (oracle: the path form, lx:459-530 and siblings).            */
/* ------------------------------------------------------------------ */

static long
want_x(const struct kinst *ki, long oracle, const char **why,
    const char *vwhy)
{
	if (BAD(ki)) {
		*why = "lx:144 getvnode: fget";
		return (-EBADF);
	}
	if (!HAS(ki, A_VN)) {
		*why = "lx:144 -> vs:4632-4636 no vnode, before the name";
		return (-EINVAL);
	}
	if (HAS(ki, A_OPATH)) {
		*why = "lx:144 -> vs:4661-4663 O_PATH";
		return (-EBADF);
	}
	*why = vwhy;
	return (oracle);
}

static void
row_xattr(struct kinst *ki)
{
	char buf[256];
	const char *why, *p = ki->path;
	int lnk = HAS(ki, A_LNK);
	long r, o;

	o = 0;
	r = S5(SYS_fsetxattr, ki->fd, "user.fdops", "v", 1, 0);
	if (HAS(ki, A_VN))
		o = S5(lnk ? SYS_lsetxattr : SYS_setxattr, p, "user.fdops",
		    "v", 1, 0);
	(void)cell("set", ki->k->name, 0, r, want_x(ki, o, &why,
	    "lx:548 setxattr (oracle: setxattr on the path)"), why);

	r = S4(SYS_fgetxattr, ki->fd, "user.fdops", buf, sizeof(buf));
	if (HAS(ki, A_VN))
		o = S4(lnk ? SYS_lgetxattr : SYS_getxattr, p, "user.fdops",
		    buf, sizeof(buf));
	(void)cell("get", ki->k->name, 0, r, want_x(ki, o, &why,
	    "lx:459 getxattr (oracle: getxattr on the path)"), why);

	r = S3(SYS_flistxattr, ki->fd, buf, sizeof(buf));
	if (HAS(ki, A_VN))
		o = S3(lnk ? SYS_llistxattr : SYS_listxattr, p, buf,
		    sizeof(buf));
	(void)cell("list", ki->k->name, 0, r, want_x(ki, o, &why,
	    "lx:174 listxattr (oracle: listxattr on the path)"), why);

	r = S2(SYS_fremovexattr, ki->fd, "user.fdops");
	if (HAS(ki, A_VN)) {
		(void)S5(lnk ? SYS_lsetxattr : SYS_setxattr, p, "user.fdops",
		    "v", 1, 0);
		o = S2(lnk ? SYS_lremovexattr : SYS_removexattr, p,
		    "user.fdops");
	}
	(void)cell("remove", ki->k->name, 0, r, want_x(ki, o, &why,
	    "lx:317 removexattr (oracle: removexattr on the path)"), why);

	/* An unknown namespace: the descriptor is looked up first. */
	(void)cell("get_bogus", ki->k->name, 0, S4(SYS_fgetxattr, ki->fd,
	    "bogus.x", buf, sizeof(buf)), want_x(ki, -EOPNOTSUPP, &why,
	    "lx:483 xattr_to_extattr: unknown prefix"), why);
	(void)cell("set_bogus", ki->k->name, 0, S5(SYS_fsetxattr, ki->fd,
	    "bogus.x", "v", 1, 0), want_x(ki, -EOPNOTSUPP, &why,
	    "lx:xattr_to_extattr: unknown prefix"), why);
	(void)cell("remove_bogus", ki->k->name, 0, S2(SYS_fremovexattr,
	    ki->fd, "bogus.x"), want_x(ki, -EOPNOTSUPP, &why,
	    "lx:xattr_to_extattr: unknown prefix"), why);
}

/* ------------------------------------------------------------------ */
/* flock(2): the native sys_flock, kd:4596-4640.                       */
/* ------------------------------------------------------------------ */

static void
row_flock(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 how;
	} subs[] = {
		{ "ex_nb", LOCK_EX | LOCK_NB },
		{ "un", LOCK_UN },
		{ "none", 0 },
	};
	const char *why;
	long w;
	int i;

	for (i = 0; i < 3; i++) {
		if (BAD(ki)) {
			w = -EBADF;
			why = "kd:4604 fget";
		} else if (ki->k->dt != DT_VNODE && ki->k->dt != DT_FIFO) {
			w = -EOPNOTSUPP;
			why = "kd:4607-4610 not DTYPE_VNODE/FIFO, before how";
		} else if (HAS(ki, A_OPATH)) {
			w = -EOPNOTSUPP;
			why = "kd:4611-4613 O_PATH";
		} else if (subs[i].how == 0) {
			w = -EBADF;
			why = "kd:4630-4632 no operation";
		} else {
			w = 0;
			why = "kd:4620-4636";
		}
		if (cell(subs[i].sub, ki->k->name, 0, S2(SYS_flock, ki->fd,
		    subs[i].how), w, why) && w == 0)
			(void)S2(SYS_flock, ki->fd, LOCK_UN);
	}
}

/* ------------------------------------------------------------------ */
/* fcntl(2) record and OFD locks: fcntl_common lf:2126-2240 ->         */
/* kern_fcntl, kd:776-990.                                             */
/* ------------------------------------------------------------------ */

static int
fs_ofd(const struct kinst *ki)
{
	s64 sf[15];

	/* devfs has no VFCF_OFDLOCKS (devfs_vfsops.c:244). */
	if (HAS(ki, A_DEV))
		return (0);
	if (S2(SYS_statfs, ki->path, sf) != 0)
		return (0);
	/* ufs, zfs, tmpfs (Linux f_type magics as linux_stats.c maps them):
	 * ffs_vfsops.c:117, zfs_vfsops.c:142-143, tmpfs_vfsops.c:726. */
	return (sf[0] == 0x00011954 || sf[0] == 0x2fc12fc1 ||
	    sf[0] == 0x01021994);
}

static void
row_locks(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 cmd;
		short		 type;
		short		 whence;
		s64		 start;
	} subs[] = {
		{ "setlk_wr", F_SETLK, F_WRLCK, SEEK_SET, 0 },
		{ "getlk_wr", F_GETLK, F_WRLCK, SEEK_SET, 0 },
		{ "ofd_setlk_wr", F_OFD_SETLK, F_WRLCK, SEEK_SET, 0 },
		{ "ofd_setlk_badtype", F_OFD_SETLK, 99, SEEK_SET, 0 },
		{ "ofd_setlk_seekcur_ovf", F_OFD_SETLK, F_RDLCK, SEEK_CUR,
		    OFF_MAX },
		{ "ofd_getlk_seekcur_ovf", F_OFD_GETLK, F_WRLCK, SEEK_CUR,
		    OFF_MAX },
	};
	struct l_flock fl;
	const char *why;
	long w;
	int i, get, ofd;

	for (i = 0; i < 6; i++) {
		get = subs[i].cmd == F_GETLK || subs[i].cmd == F_OFD_GETLK;
		ofd = subs[i].cmd == F_OFD_SETLK || subs[i].cmd == F_OFD_GETLK;
		if (BAD(ki)) {
			w = -EBADF;
			why = "kd:824/948 fget_unlocked";
		} else if (ki->k->dt != DT_VNODE || HAS(ki, A_OPATH)) {
			w = -EBADF;
			why = "kd:827-831/951-955 not a DTYPE_VNODE file";
		} else if (ofd && !fs_ofd(ki)) {
			w = -EOPNOTSUPP;
			why = "kd:834/964 -> 626-628 no VFCF_OFDLOCKS, before "
			    "SEEK_CUR and l_type";
		} else if (subs[i].whence == SEEK_CUR) {
			w = -EOVERFLOW;
			why = get ? "kd:971-980" : "kd:841-849";
		} else if (!get && subs[i].type == 99) {
			w = -EINVAL;
			why = "kd:900-902 l_type (lf:1937 maps it to -1)";
		} else if (!get && subs[i].type == F_WRLCK &&
		    !HAS(ki, A_WR)) {
			w = -EBADF;
			why = "kd:872-875 F_WRLCK without FWRITE";
		} else {
			w = 0;
			why = "VOP_ADVLOCK";
		}
		(void)S3(SYS_lseek, ki->fd, subs[i].whence == SEEK_CUR ? 1 : 0,
		    SEEK_SET);
		memset(&fl, 0, sizeof(fl));
		fl.type = subs[i].type;
		fl.whence = subs[i].whence;
		fl.start = subs[i].start;
		(void)cell(subs[i].sub, ki->k->name, 0, S3(SYS_fcntl, ki->fd,
		    subs[i].cmd, &fl), w, why);
		memset(&fl, 0, sizeof(fl));
		fl.type = F_UNLCK;
		(void)S3(SYS_fcntl, ki->fd, F_SETLK, &fl);
		(void)S3(SYS_fcntl, ki->fd, F_OFD_SETLK, &fl);
	}
}

/* ------------------------------------------------------------------ */
/* copy_file_range(2): linux_copy_file_range, lf:2792-2834, ->         */
/* kern_copy_file_range, vs:5253.  Same rules as the native matrix.   */
/* ------------------------------------------------------------------ */

static long
want_cfr(const struct kinst *in, const struct kinst *out_, unsigned long len,
    const char **why)
{
	if (BAD(in) || !HAS(in, A_RD)) {
		*why = "vs:5285 fget_read";
		return (-EBADF);
	}
	if (!HAS(in, A_VN)) {
		*why = "vs:5293-5295 input has no vnode, before the output";
		return (-EINVAL);
	}
	if (BAD(out_) || !HAS(out_, A_WR)) {
		*why = "vs:5297 fget_write";
		return (-EBADF);
	}
	if (!HAS(out_, A_VN)) {
		*why = "vs:5305-5307 output has no vnode";
		return (-EINVAL);
	}
	if (HAS(out_, A_APP)) {
		*why = "vs:5345-5349 output O_APPEND";
		return (-EBADF);
	}
	if (len == 0) {
		*why = "vs:5352-5353 len == 0";
		return (0);
	}
	if (seq(in->path, out_->path)) {
		*why = "vs:5368-5372 one vnode, overlapping";
		return (-EINVAL);
	}
	if (in->k->vt == VT_DIR || out_->k->vt == VT_DIR) {
		*why = "vfs_vnops.c:3790-3791";
		return (-EISDIR);
	}
	if (in->k->vt != VT_REG || out_->k->vt != VT_REG) {
		*why = "vfs_vnops.c:3792-3794 not VREG";
		return (-EINVAL);
	}
	*why = "vs:5391 vn_copy_file_range";
	return ((long)len);
}

static void
cfr_matrix(void)
{
	static const enum kid outs[] = { K_REG, K_REG_RDONLY, K_REG_APPEND,
	    K_PIPE_W, K_SOCKETPAIR, K_MEMFD, K_DEVNULL, K_OPATH_REG,
	    K_TIMERFD, K_BAD_NEG };
	struct kinst in, o;
	const char *why;
	s64 io, oo;
	unsigned long len;
	long w;
	int i, j, l;

	g_row = "copy_file_range";
	for (i = 0; i < K__N; i++)
		for (j = 0; j < (int)(sizeof(outs) / sizeof(outs[0])); j++)
			for (l = 0; l < 2; l++) {
				len = l == 0 ? 1 : 0;
				if (kmake((enum kid)i, &in) < 0) {
					kfree(&in);
					g_skips++;
					continue;
				}
				if (kmake(outs[j], &o) < 0) {
					kfree(&o);
					kfree(&in);
					g_skips++;
					continue;
				}
				w = want_cfr(&in, &o, len, &why);
				io = 5;
				oo = 0;
				(void)cell(l == 0 ? "len1" : "len0",
				    in.k->name, o.k->name,
				    S6(SYS_copy_file_range, in.fd, &io, o.fd,
				    &oo, len, 0), w, why);
				kfree(&o);
				kfree(&in);
			}
}

/* ------------------------------------------------------------------ */
/* splice(2), tee(2), sendfile(2): only a MAC check was added (D94);   */
/* reference cells pin the unchanged results.                         */
/* ------------------------------------------------------------------ */

static void
splice_tee_sendfile(void)
{
	struct kinst reg, pw, sp;
	int p2[2];
	s64 off;

	g_row = "splice_tee_sendfile";
	if (kmake(K_REG, &reg) < 0 || kmake(K_PIPE_W, &pw) < 0 ||
	    kmake(K_SOCKETPAIR, &sp) < 0 || S2(SYS_pipe2, p2, 0) < 0) {
		out("skip splice_tee_sendfile: setup\n");
		g_skips++;
		return;
	}
	off = 0;
	(void)cell("splice_file_to_pipe", "reg", "pipe_w", S6(SYS_splice,
	    reg.fd, &off, pw.fd, 0, 1, 0), 1, "lf:3224 linux_splice -> "
	    "lf:3068 linux_splice_common");
	/* pw.aux[0] is the read end holding that byte. */
	(void)cell("tee_pipe_to_pipe", "pipe_r", "pipe_w", S4(SYS_tee,
	    pw.aux[0], p2[1], 1, 0), 1, "lf:3242 linux_tee");
	off = 0;
	(void)cell("sendfile_to_socket", "reg", "socketpair", S4(SYS_sendfile,
	    sp.fd, reg.fd, &off, 1), 1, "linux_socket.c linux_sendfile -> "
	    "kern_sendfile");
	off = 0;
	(void)cell("sendfile_to_pipe", "reg", "pipe_w", S4(SYS_sendfile,
	    p2[1], reg.fd, &off, 1), 1, "linux_socket.c sendfile_fallback");
	kfree(&reg);
	kfree(&pw);
	kfree(&sp);
	(void)S1(SYS_close, p2[0]);
	(void)S1(SYS_close, p2[1]);
}

/* ------------------------------------------------------------------ */
/* statx(2) AT_EMPTY_PATH with STATX_MNT_ID, fstatfs(2), syncfs(2).    */
/* ------------------------------------------------------------------ */

static void
row_stat_family(struct kinst *ki)
{
	unsigned char sx[256], px[256];
	s64 sf[15];
	const char *why;
	long w, r;

	/* statx: kern_fstat for an empty path (ls: linux_statx). */
	w = BAD(ki) ? -EBADF : 0;
	r = S5(SYS_statx, ki->fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS |
	    STATX_MNT_ID, sx);
	if (cell("statx_empty", ki->k->name, 0, r, w, BAD(ki) ?
	    "ls:linux_kern_fstat_id fget" : "ls:linux_kern_fstat_id fo_stat") &&
	    r == 0 && HAS(ki, A_VN) && ki->k->dt == DT_VNODE &&
	    S5(SYS_statx, AT_FDCWD, ki->path, HAS(ki, A_LNK) ?
	    AT_SYMLINK_NOFOLLOW : 0, STATX_MNT_ID, px) == 0)
		(void)cell("statx_mnt_id", ki->k->name, 0,
		    (long)*(u64 *)(void *)(sx + 0x90),
		    (long)*(u64 *)(void *)(px + 0x90),
		    "ls:linux_kern_fstat_id: linux_vnode_mount_id, as the "
		    "path form");

	/* fstatfs: linux_fstatfs -> kern_fstatfs, vs:376-407. */
	if (BAD(ki)) {
		w = -EBADF;
		why = "vs:384 getvnode_path: fget";
	} else if (!HAS(ki, A_VN)) {
		w = -EINVAL;
		why = "vs:384 -> 4632-4636 no vnode";
	} else {
		w = 0;
		why = "vs:406 kern_do_statfs (O_PATH accepted)";
	}
	(void)cell("fstatfs", ki->k->name, 0, S2(SYS_fstatfs, ki->fd, sf), w,
	    why);

	/* syncfs: ls:480 linux_syncfs -> fgetvp (kd:4472-4491). */
	(void)cell("syncfs", ki->k->name, 0, S1(SYS_syncfs, ki->fd), w,
	    BAD(ki) ? "ls:485 fgetvp: fget" : !HAS(ki, A_VN) ?
	    "ls:485 -> kd:4482-4483 no vnode" : "ls:491-504 VFS_SYNC");
}

/* ------------------------------------------------------------------ */
/* fchmod(2), fchown(2) (native fo_chmod/fo_chown), utimensat(fd,     */
/* NULL) (lm:812-815 kern_futimens), and fchmodat2/fchownat/utimensat */
/* on the descriptor with AT_EMPTY_PATH (namei EMPTYPATH,             */
/* kd:3961-4000: no vnode is ENOTDIR).                                 */
/* ------------------------------------------------------------------ */

static long
want_fchmod(const struct kinst *ki, const char **why)
{
	if (BAD(ki)) {
		*why = "vs:3026 fget";
		return (-EBADF);
	}
	if (HAS(ki, A_OPATH)) {
		*why = "kd:6035-6039 badfo_chmod";
		return (-EBADF);
	}
	switch (ki->k->dt) {
	case DT_VNODE:
	case DT_FIFO:
	case DT_SHM:
		*why = "vn_chmod / sp:1996-1997 / uipc_shm.c:1972";
		return (0);
	case DT_PIPE:
		if (HAS(ki, A_OPF)) {
			*why = "sp:1998-2002 one-way pipe, O_PATH";
			return (-EBADF);
		}
		*why = "sp:1998-2010 one-way pipe: its own mode";
		return (0);
	case DT_SOCK:
		if (HAS(ki, A_INET)) {
			*why = "sys_socket.c:398-402 no pr_chmod";
			return (-EINVAL);
		}
		*why = "uipc_usrreq.c:1093-1110 uipc_chmod";
		return (0);
	default:
		*why = "invfo_chmod (pts, kqueue, eventfd, timerfd, "
		    "signalfd, inotify, pidfd)";
		return (-EINVAL);
	}
}

static long
want_fchown(const struct kinst *ki, const char **why)
{
	if (BAD(ki)) {
		*why = "vs:3185 fget";
		return (-EBADF);
	}
	if (HAS(ki, A_OPATH)) {
		*why = "kd:6043-6047 badfo_chown";
		return (-EBADF);
	}
	switch (ki->k->dt) {
	case DT_VNODE:
	case DT_FIFO:
	case DT_SHM:
		*why = "vn_chown / sp:2027-2028 / uipc_shm.c:2009";
		return (0);
	case DT_PIPE:
		if (HAS(ki, A_OPF)) {
			*why = "sp:2029-2032 one-way pipe, O_PATH";
			return (-EBADF);
		}
		*why = "sp:2029-2049 one-way pipe";
		return (0);
	default:
		*why = "invfo_chown (sockets, pts, kqueue, eventfd, timerfd, "
		    "signalfd, inotify, pidfd)";
		return (-EINVAL);
	}
}

static void
row_attrs(struct kinst *ki)
{
	struct l_timespec ts[2];
	struct l_stat st;
	const char *why;
	unsigned mode;
	long w, o;
	int vn;

	vn = HAS(ki, A_VN) && pstat(ki, &st) == 0;
	mode = vn ? (st.mode & 07777) : 0600;

	(void)cell("fchmod", ki->k->name, 0, S2(SYS_fchmod, ki->fd, mode),
	    want_fchmod(ki, &why), why);
	(void)cell("fchown", ki->k->name, 0, S3(SYS_fchown, ki->fd, -1, -1),
	    want_fchown(ki, &why), why);

	/* utimensat(fd, NULL, times): kern_futimens (vs:3504-3540). */
	if (vn) {
		ts[0].sec = (s64)st.atime;
		ts[0].nsec = (s64)st.atime_ns;
		ts[1].sec = (s64)st.mtime;
		ts[1].nsec = (s64)st.mtime_ns;
	} else {
		ts[0].sec = ts[1].sec = 1000000000;
		ts[0].nsec = ts[1].nsec = 0;
	}
	(void)cell("futimens", ki->k->name, 0, S4(SYS_utimensat, ki->fd, 0,
	    ts, 0), BAD(ki) ? -EBADF : !HAS(ki, A_VN) ? -EINVAL :
	    HAS(ki, A_OPATH) ? -EBADF : 0,
	    BAD(ki) ? "vs:3518 getvnode: fget" : !HAS(ki, A_VN) ?
	    "lm:815 -> vs:3518 -> 4632-4636 no vnode" : HAS(ki, A_OPATH) ?
	    "vs:3518 -> 4661-4663 O_PATH" : "vs:3536 setutimes");
	ts[0].nsec = ts[1].nsec = UTIME_OMIT;
	(void)cell("futimens_omit", ki->k->name, 0, S4(SYS_utimensat, ki->fd,
	    0, ts, 0), 0, "lm:797-801 both UTIME_OMIT, before the "
	    "descriptor");

	/* AT_EMPTY_PATH: the descriptor's own vnode; no vnode is ENOTDIR. */
	if (HAS(ki, A_LNK))
		return;		/* a symlink's mode is the filesystem's call */
	if (BAD(ki)) {
		w = -EBADF;
		why = "kd:3976 fgetvp_lookup: fget_cap";
	} else if (!HAS(ki, A_VN)) {
		w = -ENOTDIR;
		why = "kd:3994-3997 fgetvp_lookup: no vnode";
	} else {
		o = S4(SYS_fchmodat2, AT_FDCWD, ki->path, mode, 0);
		w = o;
		why = "namei EMPTYPATH, setfmode (oracle: the path form)";
	}
	(void)cell("fchmodat2_empty", ki->k->name, 0, S4(SYS_fchmodat2,
	    ki->fd, "", mode, AT_EMPTY_PATH), w, why);
	if (HAS(ki, A_VN) && !BAD(ki))
		w = S5(SYS_fchownat, AT_FDCWD, ki->path, -1, -1, 0);
	(void)cell("fchownat_empty", ki->k->name, 0, S5(SYS_fchownat, ki->fd,
	    "", -1, -1, AT_EMPTY_PATH), w, why);
	ts[0].nsec = ts[1].nsec = UTIME_OMIT;
	ts[1].nsec = vn ? (s64)st.mtime_ns : 0;
	ts[1].sec = vn ? (s64)st.mtime : 1000000000;
	if (HAS(ki, A_VN) && !BAD(ki))
		w = S4(SYS_utimensat, AT_FDCWD, ki->path, ts, 0);
	(void)cell("utimensat_empty", ki->k->name, 0, S4(SYS_utimensat,
	    ki->fd, "", ts, AT_EMPTY_PATH), w, why);
}

/* ------------------------------------------------------------------ */

static int
test(int argc, char **argv)
{
	if (argc < 3)
		return (2);
	g_lproc = argv[1];
	g_skipfsyncfifo = seq(argv[2], "skipfsyncfifo");

	each_kind("fsync", row_fsync);
	each_kind("sync_file_range", row_sync_file_range);
	each_kind("fadvise64", row_fadvise64);
	each_kind("fallocate", row_fallocate);
	each_kind("readahead", row_readahead);
	each_kind("getdents64", row_getdents64);
	each_kind("fs_ioc_setflags", row_setflags);
	each_kind("fs_ioc_getflags", row_getflags);
	each_kind("file_attr", row_fileattr);
	each_kind("rw_hint", row_rw_hint);
	rw_hint_unpriv();
	each_kind("xattr", row_xattr);
	each_kind("flock", row_flock);
	each_kind("locks", row_locks);
	cfr_matrix();
	splice_tee_sendfile();
	each_kind("stat_family", row_stat_family);
	each_kind("attrs", row_attrs);

	out("linux_fdops: ");
	outn(g_cells);
	out(" cells, ");
	outn(g_fails);
	out(" not as base, ");
	outn(g_skips);
	out(" kind instances skipped\n");
	return (g_fails == 0 ? 0 : 1);
}

void start_c(long *sp);
__attribute__((force_align_arg_pointer)) void
start_c(long *sp)
{
	(void)S1(SYS_exit_group, test((int)sp[0], (char **)&sp[1]));
	__builtin_unreachable();
}

__asm__(
	".globl _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call start_c\n"
	"	hlt\n");

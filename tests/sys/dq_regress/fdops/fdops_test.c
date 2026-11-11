/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fdops_test: every system call DescriptorQueue stage 0 rewired through the
 * new per-descriptor operations of struct fileops (fo_pathconf, fo_statfs,
 * fo_fsync, fo_setattr, fo_fadvise, fo_readdir, fo_copy_file_range, fo_acl,
 * fo_extattr, fo_fcntl, fo_advlock), called on every descriptor kind this
 * test can create, by a process that is not attached to a dq(4)
 * controller.  The question every cell answers: does an ordinary program
 * see exactly what it saw before the project?
 *
 * EXPECTATIONS.  Every expected value is FreeBSD's behaviour at the project
 * base, commit 3b9f9873d291, derived by reading that source
 * (git show 3b9f9873d291:<path>).  Each expectation names the base file and
 * line(s) that produce it ("vfs_syscalls.c:4632" is
 * sys/kern/vfs_syscalls.c at 3b9f9873d291); the citation is printed with
 * every failing cell.  Where base hands the call to a filesystem's vnode
 * operation (VOP_PATHCONF, VOP_SETATTR, VOP_GETEXTATTR, VOP_GETACL, ...),
 * the expected value is that filesystem's answer, obtained from an oracle:
 * the path form of the same operation on the same vnode (pathconf(2) for
 * fpathconf(2), statfs(2) for fstatfs(2), extattr_get_file(2) for
 * extattr_get_fd(2), and so on; the l* forms for a symbolic link).  The
 * path forms were not rewired by stage 0 and reach the same vnode
 * operation, so an oracle pins the dispatch, not a filesystem's choices.
 * Where the tree differed from base before ux-0 the test expects base's
 * value; ux-0 slice 1 restored those cells, which are listed below with
 * what the tree answered before.  No expectation was weakened to make a
 * kernel pass.
 *
 * Bad descriptors (-1, a closed descriptor, INT_MAX) are kinds of their
 * own, so each row also checks which argument errors come before the
 * descriptor lookup (futimens(2) with UTIME_OMIT twice returns 0 even for
 * -1, F_KINFO checks its size before the descriptor, ...).  Wrong open
 * modes (O_RDONLY, O_WRONLY, the write-only end of a FIFO and a write-only
 * message queue) and O_APPEND (a file and a socket) are kinds too.
 *
 * The configuration variable "pre1c" (kyua -v test_suites.FreeBSD.pre1c=yes)
 * says the kernel under test is the base kernel; it only suppresses the
 * cells that panic a base INVARIANTS kernel (below).
 *
 * ------------------------------------------------------------------------
 * CELLS RESTORED BY UX-0 SLICE 1: their base value differed from the tree
 * before it (proxy/objects at f9e922d244b, 2026-11-09).  Derived by reading
 * that code against base; "current" below is what that tree answered, and
 * each cell failed on it.  The row that restored base is named per entry.
 * "non-vnode readable kinds" are the 17 kinds that are open for reading and
 * have no vnode in base (f_vnode == NULL): pipe_r, pipe_w, unix_stream,
 * unix_dgram, socketpair, sock_append, inet, kqueue, shm, shm_anon,
 * shm_sealed, memfd, pt_openpt, procdesc, eventfd, timerfd, inotify.
 * "vnode readable kinds" are the 14 open for reading that have one:
 * reg_tmpfs, reg, reg_rdonly, reg_append, dir, fifo_rd, fifo_rdwr,
 * pt_ptmx, pts, devnull, devzero, devnull_ro, caplim, scm_reg.
 *
 *  1. fchflags(fd, -1) [row fchflags, sub vnoval], the 18 kinds with no
 *     vnode: the 17 above and mq_wronly.
 *     base EINVAL (getvnode_path, vfs_syscalls.c:4632-4636);
 *     current EOPNOTSUPP (early VNOVAL refusal).            ux-0: D228
 *  2. fchflags(fd, -1) as an unprivileged user [row fchflags_unpriv]:
 *     devnull and pt_ptmx (vnoval): base EPERM (PRIV_VFS_CHFLAGS_DEV,
 *     vfs_syscalls.c:2880-2883, before VNOVAL), current EOPNOTSUPP;
 *     pipe_r (vnoval): base EINVAL (no vnode), current EOPNOTSUPP.
 *     3 cells.                                               ux-0: D228
 *  3. getdirentries(2) on mq_wronly [row getdirentries, sub read].
 *     base EINVAL (no vnode, vfs_syscalls.c:4461 -> 4632);
 *     current EBADF (FREAD tested first).                    ux-0: D229
 *  4. copy_file_range(2) [row copy_file_range]:
 *     a. sub len1, input a non-vnode readable kind (17) x output one of
 *        the 18 kinds refused by the output fget or by O_APPEND
 *        (bad_neg, bad_closed, bad_range, caplim, reg_rdonly, dir,
 *        fifo_rd, devnull_ro, symlink_opath, opath_reg, opath_dir,
 *        opath_fifo, opath_dev, opath_sock, timerfd, inotify, reg_append,
 *        sock_append: 18 outputs) = 306 cells;
 *        base EINVAL (input has no vnode, vfs_syscalls.c:5293-5295, before
 *        the output is fetched); current EBADF, or ENOTCAPABLE for caplim.
 *     b. sub len1, input a vnode readable kind (14) x output sock_append
 *        = 14 cells; base EINVAL (output has no vnode,
 *        vfs_syscalls.c:5305-5307, before the O_APPEND test at 5345);
 *        current EBADF.
 *     c. sub len0, input a non-vnode readable kind (17) x every output
 *        kind (43) = 731 cells; base EINVAL; current 0 for writable
 *        outputs, EBADF/ENOTCAPABLE for the 18 above.
 *     d. sub len0, input a vnode readable kind (14) x output a writable
 *        non-vnode kind (16: pipe_r, pipe_w, unix_stream, unix_dgram,
 *        socketpair, sock_append, inet, kqueue, shm, shm_anon, shm_sealed,
 *        memfd, pt_openpt, procdesc, eventfd, mq_wronly) = 224 cells;
 *        base EINVAL (vfs_syscalls.c:5305); current 0 (EBADF for
 *        sock_append).
 *     e. sub samefd, timerfd and inotify (read-only, no vnode) = 2 cells;
 *        base EINVAL (5293); current EBADF (output fget_write first).
 *     (All cells for which the kind is available; a skipped kind removes
 *     its cells.)                                            ux-0: D230
 *  5. flock(2) on an anonymous pipe with an invalid operation [row flock,
 *     subs none and nb_only], pipe_r and pipe_w = 4 cells.
 *     base EOPNOTSUPP (type test before "how", kern_descrip.c:4607-4610);
 *     current EBADF.                                         ux-0: D212
 *  6. F_OFD_* on devfs, which has no VFCF_OFDLOCKS (devfs_vfsops.c:244)
 *     [row fcntl_lock], devnull, devzero, devnull_ro and pts x subs
 *     ofd_setlk_badtype, ofd_setlk_seekcur_ovf, ofd_getlk_seekcur_ovf
 *     (12 cells), and devnull_ro x ofd_setlk_wr (1 cell) = 13 cells.
 *     base EOPNOTSUPP (fcntl_ofd_check, kern_descrip.c:626-628, before
 *     the SEEK_CUR and type tests); current EINVAL, EOVERFLOW, EOVERFLOW
 *     and EBADF.                                             ux-0: D231
 *  7. /dev/fd/N setattr through fdescfs [row fdesc_setattr], pipe_r,
 *     pipe_w and pt_openpt x chmod, chown, truncate, utimens = 12 cells,
 *     base 0 (silently dropped, fdesc_vnops.c:619-626), current EINVAL;
 *     and x chflags = 3 cells, base EOPNOTSUPP (fdesc_vnops.c:622-623),
 *     current EINVAL.                                        ux-0: D232
 *  8. /dev/fd/N of a /dev/ptmx master, chmod, chown and truncate
 *     [row fdesc_setattr], 3 cells: base 0 (VOP_SETATTR on /dev/ptmx,
 *     fdesc_vnops.c:630-633; the test uses the node's own values, so
 *     nothing changes); current EINVAL.                      ux-0: D233
 *  9. /dev/fd/N of an O_PATH descriptor [row fdesc_setattr],
 *     symlink_opath, opath_reg, opath_dir, opath_fifo, opath_dev and
 *     opath_sock x chmod and chown = 12 cells: base the vnode's answer
 *     (getvnode_path accepts O_PATH, fdesc_vnops.c:612; 0 on ufs, zfs,
 *     tmpfs and devfs), current EBADF (badfo_chmod/badfo_chown);
 *     x truncate = 6 cells: base EBADF (getvnode refuses O_PATH,
 *     fdesc_vnops.c:609 -> vfs_syscalls.c:4661-4663), current EINVAL
 *     (badfo_truncate through file_setattr_direct).          ux-0: D234
 *
 * UNOWNED: none found.  Every difference above had a ux-0 row.
 *
 * Differences that a native, unprivileged-or-root program cannot see
 * without a MAC policy (D235's ordering; fchmod/fchown MAC errno on a ptmx
 * master, D301; the "MAC errno first" part of D230) are not cells here:
 * they need a denying policy, and tests/sys/file/fsetattr_test.c has them
 * under mac_test_hooks.  One such difference
 * needs no denial and shows once any policy registering
 * mpo_file_check_fcntl is loaded (mac_test, which an earlier test in a
 * full run may leave loaded): fcntl(badfd, ...) answers EBADF ahead of
 * the checks base made before the descriptor (declared in D79).  The
 * fcntl_kinfo row probes for that hook and expects D79's order only then.
 *
 * NOT COVERED, AND WHY.
 *  - Linux-ABI rows (linux_file.c, linux_stats.c, linux_xattr.c,
 *    linux_ioctl.c, linux_socket.c, linux_util.c; D237): reachable only
 *    from a Linux binary (an O_PATH-reopened one-way pipe exists only via
 *    linprocfs, kern_pipe_unidirectional only via linux_pipe); a native
 *    test cannot issue them.
 *  - readlink(/dev/fd/N) of a devfs-opened linuxkpi file (D236): needs a
 *    linuxkpi device.  The native readlink cells all match base (a FIFO is
 *    KF_TYPE_FIFO in both trees, so it stays anon_inode).
 *  - One-way pipes (getdirentries on a write-only pipe end, D229's other
 *    example): kern_pipe_unidirectional is called only by the Linux ABI.
 *  - mmap of a CAP_MMAP_R-limited shm descriptor MAP_PRIVATE|PROT_WRITE
 *    (D240): base reaches a KASSERT in vm_map_insert (an INVARIANTS panic;
 *    a production kernel inserts an inconsistent mapping), so there is no
 *    base value to assert.
 *  - fsync(2)/fdatasync(2) on a FIFO or a /dev/ptmx master are skipped when
 *    "pre1c" is set and the kernel has INVARIANTS: base asserts
 *    DTYPE_VNODE (vfs_syscalls.c:3693) and panics.  Otherwise they run and
 *    expect the production base's 0.
 *  - posix_fallocate(2), ftruncate(2), read/write and aio reads/writes
 *    gained only a MAC check (no rewiring); ftruncate is kept as a
 *    reference row, the others are not rows.
 *  - lseek(2) was not touched; it is kept as a reference row.
 */

/* The __acl_*_fd(2) system calls themselves, not the libc wrappers. */
#define	_ACL_PRIVATE

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/extattr.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <aio.h>
#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	DATA		"0123456789"
#define	DATALEN		10
#define	NOBODY		65534
#define	ANON_INODE	"anon_inode:[unknown]"
/* sys/vnode.h: the "no value" of a vattr field, -1 (kernel-only there). */
#define	VNOVAL		(-1)

/* ------------------------------------------------------------------ */
/* Descriptor kinds.                                                   */
/* ------------------------------------------------------------------ */

/*
 * Base attributes of a kind (what the 3b9f9873d291 kernel sees).
 */
#define	A_VN	0x00001	/* f_vnode != NULL: getvnode_path() accepts it */
#define	A_OPATH	0x00002	/* path_fileops (O_PATH) */
#define	A_DTV	0x00004	/* f_type == DTYPE_VNODE */
#define	A_RD	0x00008	/* FREAD */
#define	A_WR	0x00010	/* FWRITE */
#define	A_APP	0x00020	/* FAPPEND */
#define	A_SEEK	0x00040	/* DFLAG_SEEKABLE */
#define	A_DEV	0x00080	/* VN_ISDEV(f_vnode), on devfs */
#define	A_PS	0x00100	/* fpathconf: DTYPE_PIPE without vnode, DTYPE_SOCKET */
#define	A_BAD	0x00200	/* not an open descriptor */
#define	A_LNK	0x00400	/* the vnode is a symbolic link: l* oracles */
#define	A_CAP	0x00800	/* rights limited to CAP_READ|CAP_SEEK */
#define	A_SEAL	0x01000	/* shm with F_SEAL_GROW|SHRINK|WRITE|SEAL */

/* Vnode types, for the type tests base makes. */
enum vt { VT_NONE, VT_REG, VT_DIR, VT_LNK, VT_FIFO, VT_CHR, VT_SOCK };

/* The fileops table base installs. */
enum tbl {
	T_NONE,		/* not a descriptor */
	T_VNOPS,	/* vnops (vfs_vnops.c) */
	T_FIFO,		/* pipeops on a FIFO (sys_pipe.c, PIPE_TYPE_NAMED) */
	T_PIPE,		/* pipeops on an anonymous pipe */
	T_SOCKU,	/* socketops, AF_UNIX */
	T_SOCKI,	/* socketops, AF_INET */
	T_KQ,		/* kqueueops */
	T_SHM,		/* shm_ops */
	T_PTS,		/* ptsdev_ops (pseudo-terminal master) */
	T_DEVFS,	/* devfs_ops_f */
	T_PATH,		/* path_fileops */
	T_PD,		/* procdesc_ops */
	T_EVFD,		/* eventfdops */
	T_TFD,		/* timerfdops */
	T_INOT,		/* inotifyfdops */
	T_MQ,		/* mqueueops */
};

enum kid {
	K_REG_TMPFS, K_REG, K_REG_RDONLY, K_REG_WRONLY, K_REG_APPEND, K_DIR,
	K_SYMLINK_OPATH, K_FIFO_RD, K_FIFO_WR, K_FIFO_RDWR, K_PIPE_R,
	K_PIPE_W, K_UNIX_STREAM, K_UNIX_DGRAM, K_SOCKETPAIR, K_SOCK_APPEND,
	K_INET, K_KQUEUE, K_SHM, K_SHM_ANON, K_SHM_SEALED, K_MEMFD,
	K_PT_OPENPT, K_PT_PTMX, K_PTS, K_PROCDESC, K_EVENTFD, K_TIMERFD,
	K_INOTIFY, K_MQ_WRONLY, K_DEVNULL, K_DEVZERO, K_DEVNULL_RO,
	K_OPATH_REG, K_OPATH_DIR, K_OPATH_FIFO, K_OPATH_DEV, K_OPATH_SOCK,
	K_CAPLIM, K_SCM_REG, K_BAD_NEG, K_BAD_CLOSED, K_BAD_RANGE,
};

struct kdef {
	const char	*name;
	enum kid	 id;
	unsigned	 a;
	enum vt		 vt;
	enum tbl	 tbl;
};

#define	RW	(A_RD | A_WR)
#define	VNF	(A_VN | A_DTV)
static const struct kdef kdefs[] = {
	{ "reg_tmpfs",	K_REG_TMPFS,	VNF | RW | A_SEEK,	VT_REG,	T_VNOPS },
	{ "reg",	K_REG,		VNF | RW | A_SEEK,	VT_REG,	T_VNOPS },
	{ "reg_rdonly",	K_REG_RDONLY,	VNF | A_RD | A_SEEK,	VT_REG,	T_VNOPS },
	{ "reg_wronly",	K_REG_WRONLY,	VNF | A_WR | A_SEEK,	VT_REG,	T_VNOPS },
	{ "reg_append",	K_REG_APPEND,	VNF | RW | A_APP | A_SEEK, VT_REG, T_VNOPS },
	{ "dir",	K_DIR,		VNF | A_RD | A_SEEK,	VT_DIR,	T_VNOPS },
	{ "symlink_opath", K_SYMLINK_OPATH, VNF | A_OPATH | A_LNK, VT_LNK, T_PATH },
	{ "fifo_rd",	K_FIFO_RD,	A_VN | A_RD,		VT_FIFO, T_FIFO },
	{ "fifo_wr",	K_FIFO_WR,	A_VN | A_WR,		VT_FIFO, T_FIFO },
	{ "fifo_rdwr",	K_FIFO_RDWR,	A_VN | RW,		VT_FIFO, T_FIFO },
	{ "pipe_r",	K_PIPE_R,	RW | A_PS,		VT_NONE, T_PIPE },
	{ "pipe_w",	K_PIPE_W,	RW | A_PS,		VT_NONE, T_PIPE },
	{ "unix_stream", K_UNIX_STREAM,	RW | A_PS,		VT_NONE, T_SOCKU },
	{ "unix_dgram",	K_UNIX_DGRAM,	RW | A_PS,		VT_NONE, T_SOCKU },
	{ "socketpair",	K_SOCKETPAIR,	RW | A_PS,		VT_NONE, T_SOCKU },
	{ "sock_append", K_SOCK_APPEND,	RW | A_APP | A_PS,	VT_NONE, T_SOCKU },
	{ "inet",	K_INET,		RW | A_PS,		VT_NONE, T_SOCKI },
	{ "kqueue",	K_KQUEUE,	RW,			VT_NONE, T_KQ },
	{ "shm",	K_SHM,		RW | A_SEEK,		VT_NONE, T_SHM },
	{ "shm_anon",	K_SHM_ANON,	RW | A_SEEK,		VT_NONE, T_SHM },
	{ "shm_sealed",	K_SHM_SEALED,	RW | A_SEEK | A_SEAL,	VT_NONE, T_SHM },
	{ "memfd",	K_MEMFD,	RW | A_SEEK,		VT_NONE, T_SHM },
	{ "pt_openpt",	K_PT_OPENPT,	RW,			VT_NONE, T_PTS },
	{ "pt_ptmx",	K_PT_PTMX,	A_VN | RW | A_DEV,	VT_CHR,	T_PTS },
	{ "pts",	K_PTS,		VNF | RW | A_SEEK | A_DEV, VT_CHR, T_DEVFS },
	{ "procdesc",	K_PROCDESC,	RW,			VT_NONE, T_PD },
	{ "eventfd",	K_EVENTFD,	RW,			VT_NONE, T_EVFD },
	{ "timerfd",	K_TIMERFD,	A_RD,			VT_NONE, T_TFD },
	{ "inotify",	K_INOTIFY,	A_RD,			VT_NONE, T_INOT },
	{ "mq_wronly",	K_MQ_WRONLY,	A_WR,			VT_NONE, T_MQ },
	{ "devnull",	K_DEVNULL,	VNF | RW | A_SEEK | A_DEV, VT_CHR, T_DEVFS },
	{ "devzero",	K_DEVZERO,	VNF | RW | A_SEEK | A_DEV, VT_CHR, T_DEVFS },
	{ "devnull_ro",	K_DEVNULL_RO,	VNF | A_RD | A_SEEK | A_DEV, VT_CHR, T_DEVFS },
	{ "opath_reg",	K_OPATH_REG,	VNF | A_OPATH,		VT_REG,	T_PATH },
	{ "opath_dir",	K_OPATH_DIR,	VNF | A_OPATH,		VT_DIR,	T_PATH },
	{ "opath_fifo",	K_OPATH_FIFO,	VNF | A_OPATH,		VT_FIFO, T_PATH },
	{ "opath_dev",	K_OPATH_DEV,	VNF | A_OPATH | A_DEV,	VT_CHR,	T_PATH },
	{ "opath_sock",	K_OPATH_SOCK,	VNF | A_OPATH,		VT_SOCK, T_PATH },
	{ "caplim",	K_CAPLIM,	VNF | RW | A_SEEK | A_CAP, VT_REG, T_VNOPS },
	{ "scm_reg",	K_SCM_REG,	VNF | RW | A_SEEK,	VT_REG,	T_VNOPS },
	{ "bad_neg",	K_BAD_NEG,	A_BAD,			VT_NONE, T_NONE },
	{ "bad_closed",	K_BAD_CLOSED,	A_BAD,			VT_NONE, T_NONE },
	{ "bad_range",	K_BAD_RANGE,	A_BAD,			VT_NONE, T_NONE },
};

/* One live instance of a kind. */
struct kinst {
	const struct kdef *k;
	int		 fd;
	int		 aux[2];
	mqd_t		 mq;
	bool		 hasmq;
	char		 path[PATH_MAX];	/* the vnode's path, "" if none */
};

#define	HAS(ki, f)	(((ki)->k->a & (f)) != 0)

/* ------------------------------------------------------------------ */
/* Environment.                                                        */
/* ------------------------------------------------------------------ */

static char	g_cwd[PATH_MAX];
static bool	g_tmpfs;
static char	g_tmpfs_err[128];
static bool	g_pre1c;
static bool	g_invariants;
static bool	g_fcntl_hook;
static int	g_seq;
static const char *g_row = "?";
static int	g_cells;
static int	g_fails;
static int	g_skipped;

static int
mount_fs(const char *fstype, const char *dir, const char *opt)
{
	struct iovec iov[6];
	int n;

	n = 0;
	iov[n].iov_base = __DECONST(char *, "fstype");
	iov[n++].iov_len = sizeof("fstype");
	iov[n].iov_base = __DECONST(char *, fstype);
	iov[n++].iov_len = strlen(fstype) + 1;
	iov[n].iov_base = __DECONST(char *, "fspath");
	iov[n++].iov_len = sizeof("fspath");
	iov[n].iov_base = __DECONST(char *, dir);
	iov[n++].iov_len = strlen(dir) + 1;
	if (opt != NULL) {
		iov[n].iov_base = __DECONST(char *, opt);
		iov[n++].iov_len = strlen(opt) + 1;
		iov[n].iov_base = NULL;
		iov[n++].iov_len = 0;
	}
	return (nmount(iov, (unsigned)n, 0));
}

static bool
sysctl_bool(const char *name)
{
	int v;
	size_t len;

	v = 0;
	len = sizeof(v);
	return (sysctlbyname(name, &v, &len, NULL, 0) == 0 && v != 0);
}

/*
 * Whether a MAC policy registering mpo_file_check_fcntl is loaded.  With
 * one, kern_fcntl's prologue (kern_descrip.c:649-657) looks the
 * descriptor up before every command, so a bad descriptor answers EBADF
 * where base checked the command first (declared in D79).  mac_test is
 * the in-tree registrant and stays loaded once a test loads it; its
 * counter moving across one fcntl(2) proves the hook runs.  Without it
 * (and on base, which has no such hook) base's order is pinned.
 */
static bool
fcntl_hook_registered(void)
{
	static const char ctr[] = "security.mac.test.counter.file_check_fcntl";
	size_t len;
	int after, before, fd;

	len = sizeof(before);
	if (sysctlbyname(ctr, &before, &len, NULL, 0) != 0)
		return (false);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	(void)fcntl(fd, F_GETFD);
	(void)close(fd);
	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname(ctr, &after, &len, NULL, 0) == 0);
	return (after != before);
}

static void
fx_setup(const atf_tc_t *tc, const char *row)
{
	g_row = row;
	g_cells = g_fails = g_skipped = 0;
	(void)signal(SIGSYS, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(realpath(".", g_cwd) != NULL);
	g_pre1c = atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false);
	g_invariants = sysctl_bool("kern.features.invariants");
	g_fcntl_hook = fcntl_hook_registered();
	ATF_REQUIRE(mkdir("tmpfs", 0755) == 0);
	g_tmpfs = mount_fs("tmpfs", "tmpfs", NULL) == 0;
	if (!g_tmpfs)
		snprintf(g_tmpfs_err, sizeof(g_tmpfs_err),
		    "mount tmpfs: %s", strerror(errno));
}

static void
fx_cleanup(void)
{
	(void)unmount("fdesc_rl", MNT_FORCE);
	(void)unmount("fdesc", MNT_FORCE);
	(void)unmount("tmpfs", MNT_FORCE);
}

static void
fx_done(void)
{
	printf("%s: %d cells, %d not as base, %d kind instances skipped\n",
	    g_row, g_cells, g_fails, g_skipped);
}

static bool
fdesc_mount(const char *dir, const char *opt)
{
	ATF_REQUIRE(mkdir(dir, 0755) == 0);
	if (mount_fs("fdescfs", dir, opt) != 0) {
		printf("fdescfs not available (%s): row not run\n",
		    strerror(errno));
		return (false);
	}
	return (true);
}

/* ------------------------------------------------------------------ */
/* Results and cells.                                                  */
/* ------------------------------------------------------------------ */

struct res {
	long	ret;
	int	err;	/* errno of a failed call, 0 for success */
};

struct want {
	int		 err;	/* the errno base gives, 0 for success */
	long		 ret;
	bool		 chkret;
	const char	*why;	/* base file:line */
};

static struct res
mkres(long r)
{
	struct res x;

	x.ret = r;
	x.err = r == -1 ? errno : 0;
	return (x);
}

/* A call that returns -1 and sets errno on failure. */
#define	CALL(e)		(errno = 0, mkres((long)(e)))

/* A call that returns the error number (posix_fadvise(2)). */
static struct res
resv(int rv)
{
	struct res x;

	x.err = rv;
	x.ret = rv == 0 ? 0 : -1;
	return (x);
}

static struct want
want_err(int e, const char *why)
{
	struct want w;

	w.err = e;
	w.ret = -1;
	w.chkret = false;
	w.why = why;
	return (w);
}

static struct want
want_ok(const char *why)
{
	struct want w;

	w.err = 0;
	w.ret = 0;
	w.chkret = false;
	w.why = why;
	return (w);
}

static struct want
want_val(long v, const char *why)
{
	struct want w;

	w = want_ok(why);
	w.ret = v;
	w.chkret = true;
	return (w);
}

/* The filesystem's own answer, from an oracle: its error, or its value. */
static struct want
want_res(struct res r, const char *why)
{
	/* pathconf(2) may return -1 with no error: a value, not a failure. */
	return (r.err != 0 ? want_err(r.err, why) : want_val(r.ret, why));
}

static const char *
fmt_err(int e, char *buf, size_t len)
{
	snprintf(buf, len, "%s (%d)", strerror(e), e);
	return (buf);
}

/*
 * Record one cell.  k2 names the second descriptor of a two-descriptor
 * call (copy_file_range's output).
 */
static bool
cell(const char *sub, const struct kinst *ki, const struct kinst *k2,
    struct res got, struct want w)
{
	char gb[96], wb[96];
	bool ok;

	g_cells++;
	if (w.err != 0)
		ok = got.err == w.err;
	else
		ok = got.err == 0 && (!w.chkret || got.ret == w.ret);
	if (ok)
		return (true);
	g_fails++;
	if (got.err != 0)
		fmt_err(got.err, gb, sizeof(gb));
	else
		snprintf(gb, sizeof(gb), "%ld", got.ret);
	if (w.err != 0)
		fmt_err(w.err, wb, sizeof(wb));
	else if (w.chkret)
		snprintf(wb, sizeof(wb), "%ld", w.ret);
	else
		snprintf(wb, sizeof(wb), "success");
	ATF_CHECK_MSG(ok, "%s/%s [%s%s%s]: got %s, base %s (%s)", g_row, sub,
	    ki->k->name, k2 != NULL ? " -> " : "",
	    k2 != NULL ? k2->k->name : "", gb, wb, w.why);
	return (false);
}

/* A success's observable effect. */
static void
effect(bool ok, const char *sub, const struct kinst *ki, const char *what)
{
	ATF_CHECK_MSG(ok, "%s/%s [%s]: effect missing: %s", g_row, sub,
	    ki->k->name, what);
}

static void
note_skip(const char *sub, const struct kinst *ki, const char *why)
{
	printf("%s/%s [%s]: not run: %s\n", g_row, sub, ki->k->name, why);
}

/*
 * The descriptor lookup every row starts with (fget, fget_unlocked,
 * getvnode_path, fget_mmap: kern_descrip.c:4313-4322 and fget_unlocked):
 * EBADF for a descriptor that is not open, ENOTCAPABLE when the rights
 * lack one of need.
 */
static int
fget_err(const struct kinst *ki, const cap_rights_t *need)
{
	cap_rights_t have;

	if (HAS(ki, A_BAD))
		return (EBADF);
	if (!HAS(ki, A_CAP))
		return (0);
	ATF_REQUIRE(cap_rights_get(ki->fd, &have) == 0);
	return (cap_rights_contains(&have, need) ? 0 : ENOTCAPABLE);
}

/* ------------------------------------------------------------------ */
/* Making kinds.                                                       */
/* ------------------------------------------------------------------ */

static void
newname(char *rel, size_t rlen, char *abspath, const char *prefix)
{
	snprintf(rel, rlen, "%s%d", prefix, ++g_seq);
	snprintf(abspath, PATH_MAX, "%s/%s", g_cwd, rel);
}

static void
mkfile(const char *path)
{
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "create %s: %s", path, strerror(errno));
	ATF_REQUIRE(write(fd, DATA, DATALEN) == DATALEN);
	ATF_REQUIRE(close(fd) == 0);
}

static int
pass_fd(int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	char c;
	int sv[2], nfd;

	ATF_REQUIRE(socketpair(PF_LOCAL, SOCK_STREAM, 0, sv) == 0);
	c = 'x';
	iov.iov_base = &c;
	iov.iov_len = 1;
	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	ATF_REQUIRE(sendmsg(sv[0], &msg, 0) == 1);
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_controllen = sizeof(cbuf);
	ATF_REQUIRE(recvmsg(sv[1], &msg, 0) == 1);
	cm = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cm != NULL && cm->cmsg_type == SCM_RIGHTS);
	memcpy(&nfd, CMSG_DATA(cm), sizeof(int));
	(void)close(sv[0]);
	(void)close(sv[1]);
	return (nfd);
}

static int
open_reg(char *path, int flags)
{
	char rel[32];
	int fd;

	newname(rel, sizeof(rel), path, "f");
	mkfile(rel);
	fd = open(rel, flags);
	ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", rel, strerror(errno));
	return (fd);
}

/* Returns NULL, or why the kind is not available here. */
static const char *
kmake(const struct kdef *k, struct kinst *ki)
{
	static char why[160];
	struct sockaddr_un sun;
	cap_rights_t rights;
	char rel[64];
	int fd, p[2];
	pid_t pid;

	memset(ki, 0, sizeof(*ki));
	ki->k = k;
	ki->fd = -1;
	ki->aux[0] = ki->aux[1] = -1;
	fd = -1;
	switch (k->id) {
	case K_REG_TMPFS:
		if (!g_tmpfs)
			return (g_tmpfs_err);
		snprintf(rel, sizeof(rel), "tmpfs/f%d", ++g_seq);
		snprintf(ki->path, sizeof(ki->path), "%s/%s", g_cwd, rel);
		mkfile(rel);
		fd = open(rel, O_RDWR);
		break;
	case K_REG:
	case K_SCM_REG:
	case K_CAPLIM:
		fd = open_reg(ki->path, O_RDWR);
		if (k->id == K_SCM_REG) {
			int nfd = pass_fd(fd);

			(void)close(fd);
			fd = nfd;
		} else if (k->id == K_CAPLIM) {
			ATF_REQUIRE(cap_rights_limit(fd,
			    cap_rights_init(&rights, CAP_READ, CAP_SEEK)) == 0);
		}
		break;
	case K_REG_RDONLY:
		fd = open_reg(ki->path, O_RDONLY);
		break;
	case K_REG_WRONLY:
		fd = open_reg(ki->path, O_WRONLY);
		break;
	case K_REG_APPEND:
		fd = open_reg(ki->path, O_RDWR | O_APPEND);
		break;
	case K_OPATH_REG:
		fd = open_reg(ki->path, O_PATH);
		break;
	case K_DIR:
	case K_OPATH_DIR:
		newname(rel, sizeof(rel), ki->path, "d");
		ATF_REQUIRE(mkdir(rel, 0755) == 0);
		fd = open(rel, (k->id == K_DIR ? O_RDONLY : O_PATH) |
		    O_DIRECTORY);
		break;
	case K_SYMLINK_OPATH: {
		char tpath[PATH_MAX];

		newname(rel, sizeof(rel), tpath, "t");
		mkfile(rel);
		{
			char lrel[64];

			newname(lrel, sizeof(lrel), ki->path, "l");
			ATF_REQUIRE(symlink(rel, lrel) == 0);
			fd = open(lrel, O_PATH | O_NOFOLLOW);
		}
		break;
	}
	case K_FIFO_RD:
	case K_FIFO_WR:
	case K_FIFO_RDWR:
	case K_OPATH_FIFO:
		newname(rel, sizeof(rel), ki->path, "p");
		ATF_REQUIRE(mkfifo(rel, 0644) == 0);
		if (k->id == K_FIFO_RD)
			fd = open(rel, O_RDONLY | O_NONBLOCK);
		else if (k->id == K_FIFO_WR) {
			ki->aux[0] = open(rel, O_RDONLY | O_NONBLOCK);
			ATF_REQUIRE(ki->aux[0] >= 0);
			fd = open(rel, O_WRONLY | O_NONBLOCK);
		} else if (k->id == K_FIFO_RDWR)
			fd = open(rel, O_RDWR | O_NONBLOCK);
		else
			fd = open(rel, O_PATH);
		break;
	case K_PIPE_R:
	case K_PIPE_W:
		ATF_REQUIRE(pipe(p) == 0);
		fd = k->id == K_PIPE_R ? p[0] : p[1];
		ki->aux[0] = k->id == K_PIPE_R ? p[1] : p[0];
		break;
	case K_UNIX_STREAM:
		fd = socket(PF_LOCAL, SOCK_STREAM, 0);
		break;
	case K_UNIX_DGRAM:
		fd = socket(PF_LOCAL, SOCK_DGRAM, 0);
		break;
	case K_SOCKETPAIR:
	case K_SOCK_APPEND:
		ATF_REQUIRE(socketpair(PF_LOCAL, SOCK_STREAM, 0, p) == 0);
		fd = p[0];
		ki->aux[0] = p[1];
		if (k->id == K_SOCK_APPEND)
			ATF_REQUIRE(fcntl(fd, F_SETFL, O_APPEND) == 0);
		break;
	case K_INET:
		fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			snprintf(why, sizeof(why), "socket(PF_INET): %s",
			    strerror(errno));
			return (why);
		}
		break;
	case K_KQUEUE:
		fd = kqueue();
		break;
	case K_SHM: {
		char name[64];

		snprintf(name, sizeof(name), "/fdops_test.%d.%d", getpid(),
		    ++g_seq);
		fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		ATF_REQUIRE_MSG(fd >= 0, "shm_open: %s", strerror(errno));
		(void)shm_unlink(name);
		ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) == 0);
		break;
	}
	case K_SHM_ANON:
		fd = shm_open(SHM_ANON, O_RDWR, 0600);
		ATF_REQUIRE(fd >= 0);
		ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) == 0);
		break;
	case K_SHM_SEALED:
	case K_MEMFD:
		fd = memfd_create("fdops_test",
		    k->id == K_SHM_SEALED ? MFD_ALLOW_SEALING : 0);
		if (fd < 0) {
			snprintf(why, sizeof(why), "memfd_create: %s",
			    strerror(errno));
			return (why);
		}
		ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) == 0);
		if (k->id == K_SHM_SEALED)
			ATF_REQUIRE(fcntl(fd, F_ADD_SEALS, F_SEAL_GROW |
			    F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL) == 0);
		break;
	case K_PT_OPENPT:
		fd = posix_openpt(O_RDWR | O_NOCTTY);
		break;
	case K_PT_PTMX:
		strlcpy(ki->path, "/dev/ptmx", sizeof(ki->path));
		fd = open(ki->path, O_RDWR | O_NOCTTY);
		break;
	case K_PTS: {
		const char *name;

		ki->aux[0] = posix_openpt(O_RDWR | O_NOCTTY);
		ATF_REQUIRE(ki->aux[0] >= 0);
		ATF_REQUIRE(grantpt(ki->aux[0]) == 0);
		ATF_REQUIRE(unlockpt(ki->aux[0]) == 0);
		name = ptsname(ki->aux[0]);
		ATF_REQUIRE(name != NULL);
		strlcpy(ki->path, name, sizeof(ki->path));
		fd = open(ki->path, O_RDWR | O_NOCTTY);
		break;
	}
	case K_PROCDESC:
		pid = pdfork(&fd, 0);
		ATF_REQUIRE(pid >= 0);
		if (pid == 0) {
			for (;;)
				(void)pause();
		}
		break;
	case K_EVENTFD:
		fd = eventfd(0, 0);
		break;
	case K_TIMERFD:
		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd < 0) {
			snprintf(why, sizeof(why), "timerfd_create: %s",
			    strerror(errno));
			return (why);
		}
		break;
	case K_INOTIFY:
		fd = inotify_init1(0);
		if (fd < 0) {
			snprintf(why, sizeof(why), "inotify_init1: %s",
			    strerror(errno));
			return (why);
		}
		break;
	case K_MQ_WRONLY: {
		char name[64];

		snprintf(name, sizeof(name), "/fdops_test.%d.%d", getpid(),
		    ++g_seq);
		ki->mq = mq_open(name, O_WRONLY | O_CREAT | O_EXCL, 0600,
		    NULL);
		if (ki->mq == (mqd_t)-1) {
			snprintf(why, sizeof(why), "mq_open: %s (mqueuefs)",
			    strerror(errno));
			return (why);
		}
		(void)mq_unlink(name);
		ki->hasmq = true;
		fd = mq_getfd_np(ki->mq);
		break;
	}
	case K_DEVNULL:
	case K_DEVNULL_RO:
	case K_OPATH_DEV:
		strlcpy(ki->path, "/dev/null", sizeof(ki->path));
		fd = open(ki->path, k->id == K_DEVNULL ? O_RDWR :
		    k->id == K_DEVNULL_RO ? O_RDONLY : O_PATH);
		break;
	case K_DEVZERO:
		strlcpy(ki->path, "/dev/zero", sizeof(ki->path));
		fd = open(ki->path, O_RDWR);
		break;
	case K_OPATH_SOCK:
		newname(rel, sizeof(rel), ki->path, "s");
		ki->aux[0] = socket(PF_LOCAL, SOCK_STREAM, 0);
		ATF_REQUIRE(ki->aux[0] >= 0);
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_LOCAL;
		sun.sun_len = sizeof(sun);
		strlcpy(sun.sun_path, rel, sizeof(sun.sun_path));
		ATF_REQUIRE(bind(ki->aux[0], (struct sockaddr *)&sun,
		    sizeof(sun)) == 0);
		fd = open(rel, O_PATH);
		break;
	case K_BAD_NEG:
		ki->fd = -1;
		return (NULL);
	case K_BAD_CLOSED:
		fd = open("/dev/null", O_RDONLY);
		ATF_REQUIRE(fd >= 0);
		ki->fd = fcntl(fd, F_DUPFD, 512);
		ATF_REQUIRE(ki->fd >= 512);
		(void)close(fd);
		(void)close(ki->fd);
		return (NULL);
	case K_BAD_RANGE:
		ki->fd = INT_MAX;
		return (NULL);
	}
	if (fd < 0) {
		snprintf(why, sizeof(why), "creating %s: %s", k->name,
		    strerror(errno));
		atf_tc_fail("%s", why);
	}
	ki->fd = fd;
	return (NULL);
}

static void
kfree(struct kinst *ki)
{
	if (ki->hasmq)
		(void)mq_close(ki->mq);
	else if (!HAS(ki, A_BAD) && ki->fd >= 0)
		(void)close(ki->fd);
	if (ki->aux[0] >= 0)
		(void)close(ki->aux[0]);
	if (ki->aux[1] >= 0)
		(void)close(ki->aux[1]);
	ki->fd = -1;
}

typedef void rowfn_t(struct kinst *);

/* Run fn on a fresh instance of every kind. */
static void
each_kind(rowfn_t *fn)
{
	struct kinst ki;
	const char *why;
	size_t i;

	for (i = 0; i < nitems(kdefs); i++) {
		why = kmake(&kdefs[i], &ki);
		if (why != NULL) {
			printf("%s: kind %s not available: %s\n", g_row,
			    kdefs[i].name, why);
			g_skipped++;
			continue;
		}
		fn(&ki);
		kfree(&ki);
	}
}

/* ------------------------------------------------------------------ */
/* Oracles: the path forms, on the vnode's own path.                   */
/* ------------------------------------------------------------------ */

static int
st_path(const struct kinst *ki, struct stat *sb)
{
	return (HAS(ki, A_LNK) ? lstat(ki->path, sb) : stat(ki->path, sb));
}

/* Does the filesystem of the vnode take F_OFD locks (VFCF_OFDLOCKS)? */
static bool
fs_ofd(const struct kinst *ki)
{
	struct statfs sf;

	/* devfs: VFS_SET(devfs_vfsops, devfs, VFCF_SYNTHETIC | VFCF_JAIL),
	 * devfs_vfsops.c:244, no VFCF_OFDLOCKS. */
	if (HAS(ki, A_DEV))
		return (false);
	ATF_REQUIRE(statfs(ki->path, &sf) == 0);
	/* ffs_vfsops.c:117, zfs_vfsops.c:142-143, tmpfs_vfsops.c:726,
	 * fuse_main.c:102 set VFCF_OFDLOCKS; nothing else in base does. */
	return (strcmp(sf.f_fstypename, "ufs") == 0 ||
	    strcmp(sf.f_fstypename, "zfs") == 0 ||
	    strcmp(sf.f_fstypename, "tmpfs") == 0 ||
	    strcmp(sf.f_fstypename, "fusefs") == 0);
}

/* ------------------------------------------------------------------ */
/* fpathconf(2): kern_fpathconf, kern_descrip.c:1935-1967.             */
/* ------------------------------------------------------------------ */

static void
row_fpathconf(struct kinst *ki)
{
	static const struct {
		int		 name;
		const char	*sub;
	} names[] = {
		{ _PC_LINK_MAX, "link_max" },
		{ _PC_NAME_MAX, "name_max" },
		{ _PC_PIPE_BUF, "pipe_buf" },
		{ _PC_ASYNC_IO, "async_io" },
		{ -1, "bad_name" },
	};
	cap_rights_t need;
	struct want w;
	size_t i;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FPATHCONF));
	for (i = 0; i < nitems(names); i++) {
		if (e != 0)
			w = want_err(e, "kern_descrip.c:1941 fget");
		else if (names[i].name == _PC_ASYNC_IO)
			w = want_val(_POSIX_ASYNCHRONOUS_IO,
			    "kern_descrip.c:1945-1947, before the type");
		else if (HAS(ki, A_VN))
			w = want_res(CALL(HAS(ki, A_LNK) ?
			    lpathconf(ki->path, names[i].name) :
			    pathconf(ki->path, names[i].name)),
			    "kern_descrip.c:1950-1953 VOP_PATHCONF (oracle: "
			    "pathconf of the vnode)");
		else if (HAS(ki, A_PS))
			w = names[i].name == _PC_PIPE_BUF ?
			    want_val(PIPE_BUF, "kern_descrip.c:1958-1959") :
			    want_err(EINVAL, "kern_descrip.c:1955-1956");
		else
			w = want_err(EOPNOTSUPP, "kern_descrip.c:1961-1962");
		(void)cell(names[i].sub, ki, NULL,
		    CALL(fpathconf(ki->fd, names[i].name)), w);
	}
}

/* ------------------------------------------------------------------ */
/* fstatfs(2): kern_fstatfs, vfs_syscalls.c:376-407.                   */
/* ------------------------------------------------------------------ */

static void
row_fstatfs(struct kinst *ki)
{
	struct statfs sf, so;
	struct statfs *volatile nullbuf;
	cap_rights_t need;
	struct want w;
	int e;

	nullbuf = NULL;
	e = fget_err(ki, cap_rights_init(&need, CAP_FSTATFS));
	if (e != 0)
		w = want_err(e, "vfs_syscalls.c:384 getvnode_path: fget");
	else if (!HAS(ki, A_VN))
		w = want_err(EINVAL, "vfs_syscalls.c:384 -> 4632-4636 no vnode");
	else
		w = want_ok("vfs_syscalls.c:406 kern_do_statfs");
	if (cell("buf", ki, NULL, CALL(fstatfs(ki->fd, &sf)), w) &&
	    w.err == 0) {
		ATF_REQUIRE(statfs(ki->path, &so) == 0);
		effect(memcmp(&sf.f_fsid, &so.f_fsid, sizeof(sf.f_fsid)) ==
		    0 && strcmp(sf.f_fstypename, so.f_fstypename) == 0,
		    "buf", ki, "the vnode's filesystem");
	}
	if (e == 0 && HAS(ki, A_VN))
		w = want_err(EFAULT, "vfs_syscalls.c:369-370 copyout after a "
		    "successful kern_fstatfs");
	(void)cell("null_buf", ki, NULL, CALL(fstatfs(ki->fd, nullbuf)), w);
}

/* ------------------------------------------------------------------ */
/* fsync(2), fdatasync(2): kern_fsync, vfs_syscalls.c:3717-3752.       */
/* ------------------------------------------------------------------ */

static void
fsync_common(struct kinst *ki, bool full)
{
	const char *sub = full ? "fsync" : "fdatasync";
	cap_rights_t need;
	struct want w;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FSYNC));
	if (e != 0)
		w = want_err(e, "vfs_syscalls.c:3723 getvnode: fget");
	else if (!HAS(ki, A_VN))
		w = want_err(EINVAL, "vfs_syscalls.c:3723 -> 4632-4636 no vnode");
	else if (HAS(ki, A_OPATH))
		w = want_err(EBADF, "vfs_syscalls.c:3723 -> 4661-4663 O_PATH");
	else {
		if (!HAS(ki, A_DTV) && g_pre1c && g_invariants) {
			note_skip(sub, ki, "base MPASS(DTYPE_VNODE) at "
			    "vfs_syscalls.c:3693 panics an INVARIANTS kernel");
			return;
		}
		w = want_val(0, "vfs_syscalls.c:3686-3713 kern_fsync_fp: "
		    "VOP_FSYNC/VOP_FDATASYNC");
	}
	(void)cell(sub, ki, NULL, CALL(full ? fsync(ki->fd) :
	    fdatasync(ki->fd)), w);
}

static void
row_fsync(struct kinst *ki)
{
	fsync_common(ki, true);
}

static void
row_fdatasync(struct kinst *ki)
{
	fsync_common(ki, false);
}

/* ------------------------------------------------------------------ */
/* fchmod(2), fchown(2): sys_fchmod/sys_fchown, vfs_syscalls.c:3018,   */
/* 3178; the answer is the table's fo_chmod/fo_chown.                  */
/* ------------------------------------------------------------------ */

static struct want
want_chmodown(const struct kinst *ki, bool chmod, int e)
{
	if (e != 0)
		return (want_err(e, chmod ? "vfs_syscalls.c:3026 fget" :
		    "vfs_syscalls.c:3185 fget"));
	switch (ki->k->tbl) {
	case T_VNOPS:
	case T_DEVFS:
		return (want_val(0, chmod ? "vfs_syscalls.c:3042 fo_chmod = "
		    "vn_chmod (vnops, devfs_ops_f)" : "vfs_syscalls.c:3201 "
		    "fo_chown = vn_chown (vnops, devfs_ops_f)"));
	case T_FIFO:
		return (want_val(0, chmod ? "sys_pipe.c:1996-1997 named: "
		    "vn_chmod" : "sys_pipe.c:2027-2028 named: vn_chown"));
	case T_PIPE:
		return (want_err(EINVAL, chmod ? "sys_pipe.c:2015 invfo_chmod" :
		    "sys_pipe.c:2052 invfo_chown"));
	case T_SOCKU:
		return (chmod ? want_val(0, "sys_socket.c:393-402 -> "
		    "uipc_usrreq.c:1093-1110 uipc_chmod, unbound") :
		    want_err(EINVAL, "sys_socket.c:120 invfo_chown"));
	case T_SOCKI:
		return (want_err(EINVAL, chmod ? "sys_socket.c:398-401 no "
		    "pr_chmod" : "sys_socket.c:120 invfo_chown"));
	case T_SHM:
		return (want_val(0, chmod ? "uipc_shm.c:1972 shm_chmod" :
		    "uipc_shm.c:2009 shm_chown"));
	case T_MQ:
		return (want_val(0, chmod ? "uipc_mqueue.c:2704 mqf_chmod" :
		    "uipc_mqueue.c:2724 mqf_chown"));
	case T_PTS:
		return (want_err(EINVAL, chmod ? "tty_pts.c:714 invfo_chmod" :
		    "tty_pts.c:715 invfo_chown"));
	case T_PATH:
		return (want_err(EBADF, chmod ? "kern_descrip.c:6035-6039 "
		    "badfo_chmod" : "kern_descrip.c:6043-6047 badfo_chown"));
	default:
		return (want_err(EINVAL, chmod ? "kern_descrip.c:6154-6158 "
		    "invfo_chmod (kqueue, procdesc, eventfd, timerfd, "
		    "inotify)" : "kern_descrip.c:6162-6166 invfo_chown"));
	}
}

static void
row_fchmod(struct kinst *ki)
{
	cap_rights_t need;
	struct stat sb;
	struct want w;
	mode_t m;

	w = want_chmodown(ki, true,
	    fget_err(ki, cap_rights_init(&need, CAP_FCHMOD)));
	/* devfs nodes keep their own mode: nothing on /dev changes. */
	if (ki->k->tbl == T_DEVFS) {
		ATF_REQUIRE(stat(ki->path, &sb) == 0);
		m = sb.st_mode & ALLPERMS;
	} else if (ki->k->tbl == T_SOCKU)
		m = 0600;
	else
		m = ki->k->vt == VT_DIR ? 0750 : 0640;
	if (cell("mode", ki, NULL, CALL(fchmod(ki->fd, m)), w) &&
	    w.err == 0 && (ki->k->tbl == T_VNOPS || ki->k->tbl == T_FIFO ||
	    ki->k->tbl == T_SHM)) {
		ATF_REQUIRE(fstat(ki->fd, &sb) == 0);
		effect((sb.st_mode & ALLPERMS) == m, "mode", ki,
		    "fstat shows the new mode");
	}
}

static void
row_fchown(struct kinst *ki)
{
	cap_rights_t need;
	struct stat sb;
	struct want w;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FCHOWN));
	w = want_chmodown(ki, false, e);
	(void)cell("unchanged", ki, NULL, CALL(fchown(ki->fd, -1, -1)), w);
	/* A real change, only where it is the test's own file. */
	if (ki->k->tbl == T_VNOPS && ki->k->vt == VT_REG) {
		if (cell("gid", ki, NULL, CALL(fchown(ki->fd, -1, 5)), w) &&
		    w.err == 0) {
			ATF_REQUIRE(stat(ki->path, &sb) == 0);
			effect(sb.st_gid == 5, "gid", ki, "st_gid is 5");
		}
	}
}

/* ------------------------------------------------------------------ */
/* fchflags(2): sys_fchflags, vfs_syscalls.c:2854-2896.                */
/* ------------------------------------------------------------------ */

static struct want
want_fchflags(const struct kinst *ki, u_long flags, bool root)
{
	cap_rights_t need;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FCHFLAGS));
	if (e != 0)
		return (want_err(e, "vfs_syscalls.c:2862 getvnode: fget"));
	if (!HAS(ki, A_VN))
		return (want_err(EINVAL, "vfs_syscalls.c:2862 -> 4632-4636 "
		    "no vnode"));
	if (HAS(ki, A_OPATH))
		return (want_err(EBADF, "vfs_syscalls.c:2862 -> 4661-4663 "
		    "O_PATH"));
	if (HAS(ki, A_DEV) && !root)
		return (want_err(EPERM, "vfs_syscalls.c:2880-2883 "
		    "PRIV_VFS_CHFLAGS_DEV"));
	if (flags == (u_long)VNOVAL)
		return (want_err(EOPNOTSUPP, "vfs_syscalls.c:2730-2731 "
		    "setfflags: VNOVAL"));
	return (want_ok("vfs_syscalls.c:2892 setfflags: VOP_SETATTR"));
}

static void
row_fchflags(struct kinst *ki)
{
	struct stat sb;
	struct want w;

	/* flags 0: VOP_SETATTR's answer, from chflags(2) on the path. */
	w = want_fchflags(ki, 0, true);
	if (w.err == 0) {
		ATF_REQUIRE(st_path(ki, &sb) == 0);
		w = want_res(CALL(chflags(ki->path, sb.st_flags)),
		    "vfs_syscalls.c:2892 -> 2736-2739 VOP_SETATTR (oracle: "
		    "chflags of the vnode)");
		(void)cell("current", ki, NULL,
		    CALL(fchflags(ki->fd, sb.st_flags)), w);
	} else
		(void)cell("current", ki, NULL, CALL(fchflags(ki->fd, 0)), w);

	w = want_fchflags(ki, UF_NODUMP, true);
	if (w.err == 0 && HAS(ki, A_DEV))
		w = want_err(EINVAL, "vfs_syscalls.c:2892 -> devfs_vnops.c:"
		    "1805-1809 devfs_setattr: flags other than 0");
	if (w.err != 0 || (ki->k->tbl == T_VNOPS && ki->k->vt == VT_REG)) {
		if (cell("nodump", ki, NULL,
		    CALL(fchflags(ki->fd, UF_NODUMP)), w) && w.err == 0) {
			ATF_REQUIRE(stat(ki->path, &sb) == 0);
			effect((sb.st_flags & UF_NODUMP) != 0, "nodump", ki,
			    "st_flags has UF_NODUMP");
			ATF_REQUIRE(fchflags(ki->fd, 0) == 0);
		}
	}

	(void)cell("vnoval", ki, NULL, CALL(fchflags(ki->fd, (u_long)VNOVAL)),
	    want_fchflags(ki, (u_long)VNOVAL, true));
}

/* ------------------------------------------------------------------ */
/* futimens(2), futimes(2): vfs_syscalls.c:3458-3540.                  */
/* ------------------------------------------------------------------ */

static const struct timespec fixed_ts[2] = {
	{ .tv_sec = 1000000000, .tv_nsec = 123000000 },
	{ .tv_sec = 1100000000, .tv_nsec = 456000000 },
};

static struct want
want_utimes(const struct kinst *ki, const char *line)
{
	cap_rights_t need;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FUTIMES));
	if (e != 0)
		return (want_err(e, line));
	if (!HAS(ki, A_VN))
		return (want_err(EINVAL, "getvnode -> vfs_syscalls.c:4632-4636 "
		    "no vnode"));
	if (HAS(ki, A_OPATH))
		return (want_err(EBADF, "getvnode -> vfs_syscalls.c:4661-4663 "
		    "O_PATH"));
	return (want_val(0, "setutimes: VOP_SETATTR (vfs_syscalls.c:3488, "
	    "3536)"));
}

static void
row_futimens(struct kinst *ki)
{
	struct timespec ts[2];
	struct stat sb;
	struct want w;

	w = want_utimes(ki, "vfs_syscalls.c:3518 getvnode: fget");
	/* A device node keeps its own times: nothing on /dev changes. */
	if (HAS(ki, A_DEV) && HAS(ki, A_VN)) {
		ATF_REQUIRE(stat(ki->path, &sb) == 0);
		ts[0] = sb.st_atim;
		ts[1] = sb.st_mtim;
	} else {
		ts[0] = fixed_ts[0];
		ts[1] = fixed_ts[1];
	}
	if (cell("times", ki, NULL, CALL(futimens(ki->fd, ts)), w) &&
	    w.err == 0 && !HAS(ki, A_DEV)) {
		ATF_REQUIRE(st_path(ki, &sb) == 0);
		effect(sb.st_mtim.tv_sec == ts[1].tv_sec &&
		    sb.st_mtim.tv_nsec == ts[1].tv_nsec, "times", ki,
		    "st_mtim set");
	}
	if (!(HAS(ki, A_DEV) && HAS(ki, A_VN)))
		(void)cell("now", ki, NULL, CALL(futimens(ki->fd, NULL)), w);

	ts[0].tv_sec = ts[1].tv_sec = 0;
	ts[0].tv_nsec = ts[1].tv_nsec = UTIME_OMIT;
	(void)cell("omit_omit", ki, NULL, CALL(futimens(ki->fd, ts)),
	    want_val(0, "vfs_syscalls.c:3516-3517 UTIMENS_EXIT before the "
	    "descriptor"));

	ts[0].tv_sec = ts[1].tv_sec = 0;
	ts[0].tv_nsec = 1000000000L;
	ts[1].tv_nsec = 0;
	(void)cell("bad_nsec", ki, NULL, CALL(futimens(ki->fd, ts)),
	    want_err(EINVAL, "vfs_syscalls.c:3513 -> 3274-3275 getutimens, "
	    "before the descriptor"));
}

static void
row_futimes(struct kinst *ki)
{
	struct timeval tv[2];
	struct stat sb;
	struct want w;

	w = want_utimes(ki, "vfs_syscalls.c:3470 getvnode: fget");
	tv[0].tv_sec = fixed_ts[0].tv_sec;
	tv[0].tv_usec = 123000;
	tv[1].tv_sec = fixed_ts[1].tv_sec;
	tv[1].tv_usec = 456000;
	/*
	 * A device node is left alone: futimes would round its times to
	 * microseconds.  futimens covers the device kinds.
	 */
	if (!(HAS(ki, A_DEV) && HAS(ki, A_VN))) {
		if (cell("times", ki, NULL, CALL(futimes(ki->fd, tv)), w) &&
		    w.err == 0) {
			ATF_REQUIRE(st_path(ki, &sb) == 0);
			effect(sb.st_mtim.tv_sec == tv[1].tv_sec &&
			    sb.st_mtim.tv_nsec == 456000000L, "times", ki,
			    "st_mtim set");
		}
	}
	tv[0].tv_usec = 1000000;
	(void)cell("bad_usec", ki, NULL, CALL(futimes(ki->fd, tv)),
	    want_err(EINVAL, "vfs_syscalls.c:3467 -> 3232-3234 getutimes, "
	    "before the descriptor"));
}

/*
 * The "grow" length: twice the page every shm kind already has, so that
 * shm_dotruncate_locked does not return early on an unchanged size
 * (uipc_shm.c:883-884) and the sealed kind reaches its F_SEAL_GROW test.
 */
#define	GROWTO	(2 * PAGE_SIZE)

/* ------------------------------------------------------------------ */
/* ftruncate(2): kern_ftruncate, sys_generic.c:667-688 (reference row: */
/* stage 0 added only a MAC check).                                    */
/* ------------------------------------------------------------------ */

static void
row_ftruncate(struct kinst *ki)
{
	cap_rights_t need;
	struct stat sb;
	struct want w;
	int e;

	(void)cell("negative", ki, NULL, CALL(ftruncate(ki->fd, -1)),
	    want_err(EINVAL, "sys_generic.c:673-674, before the descriptor"));

	e = fget_err(ki, cap_rights_init(&need, CAP_FTRUNCATE));
	if (e != 0)
		w = want_err(e, "sys_generic.c:675 fget");
	else if (!HAS(ki, A_WR))
		w = want_err(EINVAL, "sys_generic.c:679-681 not FWRITE");
	else {
		switch (ki->k->tbl) {
		case T_VNOPS:
			w = want_val(0, "sys_generic.c:683 -> vn_truncate");
			break;
		case T_FIFO:
		case T_DEVFS:
			w = want_res(CALL(truncate(ki->path, GROWTO)),
			    "sys_generic.c:683 -> sys_pipe.c:1702 / "
			    "devfs_vnops.c:1962 -> vn_truncate VOP_SETATTR "
			    "(oracle: truncate of the vnode)");
			break;
		case T_SHM:
			w = HAS(ki, A_SEAL) ? want_err(EPERM, "uipc_shm.c:"
			    "918-919 F_SEAL_GROW") : want_val(0, "uipc_shm.c:"
			    "698-713 shm_truncate");
			break;
		case T_PIPE:
			w = want_err(EINVAL, "sys_pipe.c:1704 invfo_truncate");
			break;
		case T_PTS:
			w = want_err(EINVAL, "tty_pts.c:708 invfo_truncate");
			break;
		default:
			w = want_err(EINVAL, "kern_descrip.c:6123-6127 "
			    "invfo_truncate");
			break;
		}
	}
	if (cell("grow", ki, NULL, CALL(ftruncate(ki->fd, GROWTO)), w) &&
	    w.err == 0 && (ki->k->tbl == T_VNOPS || ki->k->tbl == T_SHM)) {
		ATF_REQUIRE(fstat(ki->fd, &sb) == 0);
		effect(sb.st_size == GROWTO, "grow", ki, "st_size grew");
	}
}

/* ------------------------------------------------------------------ */
/* posix_fadvise(2): vfs_syscalls.c:5105-5240.                         */
/* ------------------------------------------------------------------ */

static void
row_fadvise(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		off_t		 off;
		int		 advice;
	} subs[] = {
		{ "normal", 0, POSIX_FADV_NORMAL },
		{ "sequential", 0, POSIX_FADV_SEQUENTIAL },
		{ "bad_advice", 0, 99 },
		{ "neg_offset", -1, POSIX_FADV_NORMAL },
	};
	cap_rights_t need;
	struct want w;
	size_t i;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_POSIX_FADVISE));
	for (i = 0; i < nitems(subs); i++) {
		if (subs[i].off < 0 || subs[i].advice == 99)
			w = want_err(EINVAL, "vfs_syscalls.c:5229 -> 5108-5121 "
			    "validated before the descriptor");
		else if (e != 0)
			w = want_err(e, "vfs_syscalls.c:5234 fget");
		else if (!HAS(ki, A_SEEK))
			w = want_err(ESPIPE, "vfs_syscalls.c:5141-5142");
		else if (!HAS(ki, A_DTV))
			w = want_err(ENODEV, "vfs_syscalls.c:5143-5144");
		else if (ki->k->vt != VT_REG)
			w = want_err(ENODEV, "vfs_syscalls.c:5146-5147");
		else
			w = want_val(0, "vfs_syscalls.c:5149-5216");
		(void)cell(subs[i].sub, ki, NULL, resv(posix_fadvise(ki->fd,
		    subs[i].off, 0, subs[i].advice)), w);
	}
}

/* ------------------------------------------------------------------ */
/* getdirentries(2): kern_getdirentries, vfs_syscalls.c:4445-4530.     */
/* ------------------------------------------------------------------ */

static void
row_getdirentries(struct kinst *ki)
{
	char buf[8192];
	cap_rights_t need;
	struct dirent *dp;
	struct want w;
	struct res r;
	off_t base;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_READ));
	if (e != 0)
		w = want_err(e, "vfs_syscalls.c:4461 getvnode: fget");
	else if (!HAS(ki, A_VN))
		w = want_err(EINVAL, "vfs_syscalls.c:4461 -> 4632-4636 no vnode");
	else if (HAS(ki, A_OPATH))
		w = want_err(EBADF, "vfs_syscalls.c:4461 -> 4661-4663 O_PATH");
	else if (!HAS(ki, A_RD))
		w = want_err(EBADF, "vfs_syscalls.c:4464-4466 not FREAD");
	else if (ki->k->vt != VT_DIR)
		w = want_err(ENOTDIR, "vfs_syscalls.c:4488-4494 not VDIR");
	else
		w = want_ok("vfs_syscalls.c:4499-4505 VOP_READDIR");
	r = CALL(getdirentries(ki->fd, buf, sizeof(buf), &base));
	if (cell("read", ki, NULL, r, w) && w.err == 0) {
		dp = (struct dirent *)(void *)buf;
		effect(r.ret > 0 && dp->d_reclen > 0 &&
		    strcmp(dp->d_name, ".") == 0, "read", ki,
		    "the first entry is \".\"");
	}
	(void)cell("huge_count", ki, NULL,
	    CALL(getdirentries(ki->fd, buf, SIZE_MAX, &base)),
	    want_err(EINVAL, "vfs_syscalls.c:4458-4459 count > IOSIZE_MAX, "
	    "before the descriptor"));
}

/* ------------------------------------------------------------------ */
/* copy_file_range(2): kern_copy_file_range, vfs_syscalls.c:5253-5420, */
/* and vn_copy_file_range, vfs_vnops.c:3774.                           */
/* ------------------------------------------------------------------ */

static struct want
want_cfr(const struct kinst *in, const struct kinst *out, size_t len,
    bool offsets)
{
	cap_rights_t need;
	int e;

	e = fget_err(in, offsets ? cap_rights_init(&need, CAP_PREAD) :
	    cap_rights_init(&need, CAP_READ));
	if (e != 0)
		return (want_err(e, "vfs_syscalls.c:5285 fget_read: fget"));
	if (!HAS(in, A_RD))
		return (want_err(EBADF, "vfs_syscalls.c:5285 fget_read: not "
		    "FREAD (kern_descrip.c:4333-4336)"));
	if (!HAS(in, A_VN))
		return (want_err(EINVAL, "vfs_syscalls.c:5293-5295 input has no "
		    "vnode, before the output is fetched"));
	e = fget_err(out, offsets ? cap_rights_init(&need, CAP_PWRITE) :
	    cap_rights_init(&need, CAP_WRITE));
	if (e != 0)
		return (want_err(e, "vfs_syscalls.c:5297 fget_write: fget"));
	if (!HAS(out, A_WR))
		return (want_err(EBADF, "vfs_syscalls.c:5297 fget_write: not "
		    "FWRITE (kern_descrip.c:4333-4336)"));
	if (!HAS(out, A_VN))
		return (want_err(EINVAL, "vfs_syscalls.c:5305-5307 output has "
		    "no vnode"));
	if (!offsets && in->fd == out->fd)
		return (want_err(EINVAL, "vfs_syscalls.c:5325-5332 one file "
		    "offset"));
	if (HAS(out, A_APP))
		return (want_err(EBADF, "vfs_syscalls.c:5345-5349 output "
		    "O_APPEND"));
	if (len == 0)
		return (want_val(0, "vfs_syscalls.c:5352-5353 len == 0"));
	if (strcmp(in->path, out->path) == 0)
		return (want_err(EINVAL, "vfs_syscalls.c:5368-5372 one vnode, "
		    "overlapping ranges"));
	if (in->k->vt == VT_DIR || out->k->vt == VT_DIR)
		return (want_err(EISDIR, "vfs_vnops.c:3790-3791"));
	if (in->k->vt != VT_REG || out->k->vt != VT_REG)
		return (want_err(EINVAL, "vfs_vnops.c:3792-3794 not VREG"));
	return (want_val((long)len, "vfs_syscalls.c:5391 vn_copy_file_range"));
}

static void
cfr_pair(const struct kdef *kin, const struct kdef *kout, size_t len,
    const char *sub)
{
	struct kinst in, out;
	struct want w;
	char c;
	off_t io, oo;
	int fd;

	if (kmake(kin, &in) != NULL) {
		g_skipped++;
		return;
	}
	if (kmake(kout, &out) != NULL) {
		g_skipped++;
		kfree(&in);
		return;
	}
	w = want_cfr(&in, &out, len, true);
	io = 5;
	oo = 0;
	if (cell(sub, &in, &out, CALL(copy_file_range(in.fd, &io, out.fd,
	    &oo, len, 0)), w) && w.err == 0 && len > 0) {
		fd = open(out.path, O_RDONLY);
		ATF_REQUIRE(fd >= 0);
		ATF_REQUIRE(pread(fd, &c, 1, 0) == 1);
		(void)close(fd);
		effect(c == '5' && io == 6 && oo == 1, sub, &in,
		    "byte 5 of the input is byte 0 of the output");
	}
	kfree(&out);
	kfree(&in);
}

static void
row_cfr_samefd(struct kinst *ki)
{
	(void)cell("samefd", ki, ki, CALL(copy_file_range(ki->fd, NULL,
	    ki->fd, NULL, 1, 0)), want_cfr(ki, ki, 1, false));
}

static void
row_cfr_flags(struct kinst *ki)
{
	char path[PATH_MAX];
	off_t io, oo;
	int out;

	out = open_reg(path, O_RDWR);
	io = oo = 0;
	(void)cell("bad_flags", ki, NULL, CALL(copy_file_range(ki->fd, &io,
	    out, &oo, 1, 1)), want_err(EINVAL, "vfs_syscalls.c:5272-5275, "
	    "before either descriptor"));
	(void)close(out);
}

/* ------------------------------------------------------------------ */
/* extattr_{set,get,list,delete}_fd(2): vfs_extattr.c:264-850.         */
/* ------------------------------------------------------------------ */

static struct want
want_xattr(const struct kinst *ki, uint64_t right, const char *fline,
    struct res oracle, const char *vline)
{
	cap_rights_t need;
	int e;

	e = fget_err(ki, cap_rights_init(&need, right));
	if (e != 0)
		return (want_err(e, fline));
	if (!HAS(ki, A_VN))
		return (want_err(EINVAL, "getvnode_path -> vfs_syscalls.c:"
		    "4632-4636 no vnode"));
	return (want_res(oracle, vline));
}

static void
row_extattr(struct kinst *ki)
{
	const int ns = EXTATTR_NAMESPACE_USER;
	const char *an = "fdops_test";
	const char *p = ki->path;
	bool lnk = HAS(ki, A_LNK), vn = HAS(ki, A_VN);
	char buf[256], obuf[256];
	struct res r, o;

	memset(&o, 0, sizeof(o));
	r = CALL(extattr_set_fd(ki->fd, ns, an, "v", 1));
	if (vn)
		o = CALL(lnk ? extattr_set_link(p, ns, an, "v", 1) :
		    extattr_set_file(p, ns, an, "v", 1));
	(void)cell("set", ki, NULL, r, want_xattr(ki, CAP_EXTATTR_SET,
	    "vfs_extattr.c:285 getvnode_path: fget", o,
	    "vfs_extattr.c:269 extattr_set_vp (oracle: extattr_set_file)"));

	r = CALL(extattr_get_fd(ki->fd, ns, an, buf, sizeof(buf)));
	if (vn)
		o = CALL(lnk ? extattr_get_link(p, ns, an, obuf, sizeof(obuf)) :
		    extattr_get_file(p, ns, an, obuf, sizeof(obuf)));
	(void)cell("get", ki, NULL, r, want_xattr(ki, CAP_EXTATTR_GET,
	    "vfs_extattr.c:484 getvnode_path: fget", o,
	    "vfs_extattr.c:468 extattr_get_vp (oracle: extattr_get_file)"));

	r = CALL(extattr_list_fd(ki->fd, ns, buf, sizeof(buf)));
	if (vn)
		o = CALL(lnk ? extattr_list_link(p, ns, obuf, sizeof(obuf)) :
		    extattr_list_file(p, ns, obuf, sizeof(obuf)));
	(void)cell("list", ki, NULL, r, want_xattr(ki, CAP_EXTATTR_LIST,
	    "vfs_extattr.c:831 getvnode_path: fget", o,
	    "vfs_extattr.c:818 extattr_list_vp (oracle: extattr_list_file)"));

	/* The oracle recreates the attribute first, to see the same state. */
	r = CALL(extattr_delete_fd(ki->fd, ns, an));
	if (vn) {
		(void)(lnk ? extattr_set_link(p, ns, an, "v", 1) :
		    extattr_set_file(p, ns, an, "v", 1));
		o = CALL(lnk ? extattr_delete_link(p, ns, an) :
		    extattr_delete_file(p, ns, an));
	}
	(void)cell("delete", ki, NULL, r, want_xattr(ki, CAP_EXTATTR_DELETE,
	    "vfs_extattr.c:652 getvnode_path: fget", o,
	    "vfs_extattr.c:637 extattr_delete_vp (oracle: "
	    "extattr_delete_file)"));
}

/* ------------------------------------------------------------------ */
/* __acl_{get,set,delete,aclcheck}_fd(2), the system calls under       */
/* acl_get_fd_np(3) and friends: vfs_acl.c:449-607.                    */
/* ------------------------------------------------------------------ */

static void
acl_fresh(struct acl *a)
{
	memset(a, 0, sizeof(*a));
	a->acl_maxcnt = ACL_MAX_ENTRIES;
}

static void
row_acl(struct kinst *ki)
{
	static const struct {
		const char	*get, *check, *set;
		acl_type_t	 type;
	} gt[] = {
		{ "get_access", "check_access", "set_access", ACL_TYPE_ACCESS },
		{ "get_nfs4", "check_nfs4", "set_nfs4", ACL_TYPE_NFS4 },
	};
	static const struct {
		const char	*sub;
		acl_type_t	 type;
	} dt[] = {
		{ "delete_default", ACL_TYPE_DEFAULT },
		{ "delete_nfs4", ACL_TYPE_NFS4 },
	};
	struct acl a, o, c;
	cap_rights_t need;
	const char *p = ki->path;
	bool lnk = HAS(ki, A_LNK), vn = HAS(ki, A_VN);
	struct want w;
	struct res r, ro;
	size_t i;
	int e;

	for (i = 0; i < nitems(gt); i++) {
		acl_fresh(&a);
		acl_fresh(&o);
		acl_fresh(&c);
		memset(&ro, 0, sizeof(ro));
		r = CALL(__acl_get_fd(ki->fd, gt[i].type, &a));
		if (vn)
			ro = CALL(lnk ? __acl_get_link(p, gt[i].type, &o) :
			    __acl_get_file(p, gt[i].type, &o));
		e = fget_err(ki, cap_rights_init(&need, CAP_ACL_GET));
		w = e != 0 ? want_err(e, "vfs_acl.c:458 getvnode_path: fget") :
		    !vn ? want_err(EINVAL, "vfs_acl.c:458 -> vfs_syscalls.c:"
		    "4632-4636 no vnode") : want_res(ro, "vfs_acl.c:461 "
		    "vacl_get_acl, O_PATH accepted (oracle: __acl_get_file)");
		if (cell(gt[i].get, ki, NULL, r, w) && w.err == 0)
			effect(a.acl_cnt == o.acl_cnt, gt[i].get, ki,
			    "the same ACL as the path form");
		if (vn && ro.err == 0)
			c = o;

		r = CALL(__acl_aclcheck_fd(ki->fd, gt[i].type, &c));
		if (vn)
			ro = CALL(lnk ? __acl_aclcheck_link(p, gt[i].type, &c) :
			    __acl_aclcheck_file(p, gt[i].type, &c));
		e = fget_err(ki, cap_rights_init(&need, CAP_ACL_CHECK));
		w = e != 0 ? want_err(e, "vfs_acl.c:601 getvnode_path: fget") :
		    !vn ? want_err(EINVAL, "vfs_acl.c:601 -> vfs_syscalls.c:"
		    "4632-4636 no vnode") : want_res(ro, "vfs_acl.c:604 "
		    "vacl_aclcheck, O_PATH accepted (oracle: "
		    "__acl_aclcheck_file)");
		(void)cell(gt[i].check, ki, NULL, r, w);

		/* The ACL the file already has: nothing changes. */
		r = CALL(__acl_set_fd(ki->fd, gt[i].type, &c));
		e = fget_err(ki, cap_rights_init(&need, CAP_ACL_SET));
		if (e != 0)
			w = want_err(e, "vfs_acl.c:478 getvnode_path: fget");
		else if (!vn)
			w = want_err(EINVAL, "vfs_acl.c:478 -> vfs_syscalls.c:"
			    "4632-4636 no vnode");
		else if (HAS(ki, A_OPATH))
			w = want_err(EBADF, "vfs_acl.c:481-483 O_PATH");
		else
			w = want_res(CALL(lnk ? __acl_set_link(p, gt[i].type, &c) :
			    __acl_set_file(p, gt[i].type, &c)), "vfs_acl.c:485 "
			    "vacl_set_acl (oracle: __acl_set_file)");
		(void)cell(gt[i].set, ki, NULL, r, w);
	}
	for (i = 0; i < nitems(dt); i++) {
		r = CALL(__acl_delete_fd(ki->fd, dt[i].type));
		e = fget_err(ki, cap_rights_init(&need, CAP_ACL_DELETE));
		if (e != 0)
			w = want_err(e, "vfs_acl.c:539 getvnode_path: fget");
		else if (!vn)
			w = want_err(EINVAL, "vfs_acl.c:539 -> vfs_syscalls.c:"
			    "4632-4636 no vnode");
		else if (HAS(ki, A_OPATH))
			w = want_err(EBADF, "vfs_acl.c:542-544 O_PATH");
		else
			w = want_res(CALL(lnk ? __acl_delete_link(p, dt[i].type) :
			    __acl_delete_file(p, dt[i].type)), "vfs_acl.c:546 "
			    "vacl_delete (oracle: __acl_delete_file)");
		(void)cell(dt[i].sub, ki, NULL, r, w);
	}
}

/* ------------------------------------------------------------------ */
/* flock(2): sys_flock, kern_descrip.c:4596-4640.                      */
/* ------------------------------------------------------------------ */

static void
row_flock(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 how;
	} subs[] = {
		{ "ex_nb", LOCK_EX | LOCK_NB },
		{ "sh_nb", LOCK_SH | LOCK_NB },
		{ "un", LOCK_UN },
		{ "none", 0 },
		{ "nb_only", LOCK_NB },
	};
	cap_rights_t need;
	struct want w;
	size_t i;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FLOCK));
	for (i = 0; i < nitems(subs); i++) {
		if (e != 0)
			w = want_err(e, "kern_descrip.c:4604 fget");
		else if (!HAS(ki, A_DTV) && ki->k->tbl != T_FIFO)
			w = want_err(EOPNOTSUPP, "kern_descrip.c:4607-4610 not "
			    "DTYPE_VNODE or DTYPE_FIFO, before \"how\"");
		else if (HAS(ki, A_OPATH))
			w = want_err(EOPNOTSUPP, "kern_descrip.c:4611-4613 "
			    "O_PATH");
		else if ((subs[i].how & LOCK_UN) != 0)
			w = want_val(0, "kern_descrip.c:4620-4624");
		else if ((subs[i].how & (LOCK_EX | LOCK_SH)) != 0)
			w = want_val(0, "kern_descrip.c:4626-4636 (a FIFO: "
			    "fifo_vnops.c:348-354 takes F_FLOCK)");
		else
			w = want_err(EBADF, "kern_descrip.c:4630-4632 no "
			    "operation");
		if (cell(subs[i].sub, ki, NULL, CALL(flock(ki->fd,
		    subs[i].how)), w) && w.err == 0)
			ATF_REQUIRE(flock(ki->fd, LOCK_UN) == 0);
	}
}

/* ------------------------------------------------------------------ */
/* fcntl(2) record locks: kern_fcntl, kern_descrip.c:776-990.          */
/* ------------------------------------------------------------------ */

struct lksub {
	const char	*sub;
	int		 cmd;
	short		 type;
	short		 whence;
	off_t		 start;
	pid_t		 pid;
};

static const struct lksub lksubs[] = {
	{ "setlk_rd", F_SETLK, F_RDLCK, SEEK_SET, 0, 0 },
	{ "setlk_wr", F_SETLK, F_WRLCK, SEEK_SET, 0, 0 },
	{ "setlk_un", F_SETLK, F_UNLCK, SEEK_SET, 0, 0 },
	{ "setlk_badtype", F_SETLK, 99, SEEK_SET, 0, 0 },
	{ "setlk_badwhence", F_SETLK, F_UNLCK, 99, 0, 0 },
	{ "setlk_seekcur_ovf", F_SETLK, F_RDLCK, SEEK_CUR, OFF_MAX, 0 },
	{ "getlk_wr", F_GETLK, F_WRLCK, SEEK_SET, 0, 0 },
	{ "getlk_badtype", F_GETLK, 99, SEEK_SET, 0, 0 },
	{ "getlk_seekcur_ovf", F_GETLK, F_WRLCK, SEEK_CUR, OFF_MAX, 0 },
	{ "ofd_setlk_rd", F_OFD_SETLK, F_RDLCK, SEEK_SET, 0, 0 },
	{ "ofd_setlk_wr", F_OFD_SETLK, F_WRLCK, SEEK_SET, 0, 0 },
	{ "ofd_setlk_un", F_OFD_SETLK, F_UNLCK, SEEK_SET, 0, 0 },
	{ "ofd_setlk_pid", F_OFD_SETLK, F_WRLCK, SEEK_SET, 0, 1 },
	{ "ofd_setlk_badtype", F_OFD_SETLK, 99, SEEK_SET, 0, 0 },
	{ "ofd_setlk_seekcur_ovf", F_OFD_SETLK, F_RDLCK, SEEK_CUR, OFF_MAX, 0 },
	{ "ofd_getlk_wr", F_OFD_GETLK, F_WRLCK, SEEK_SET, 0, 0 },
	{ "ofd_getlk_badtype", F_OFD_GETLK, 99, SEEK_SET, 0, 0 },
	{ "ofd_getlk_pid", F_OFD_GETLK, F_WRLCK, SEEK_SET, 0, 1 },
	{ "ofd_getlk_seekcur_ovf", F_OFD_GETLK, F_WRLCK, SEEK_CUR, OFF_MAX, 0 },
};

static struct want
want_lk(const struct kinst *ki, const struct lksub *s)
{
	cap_rights_t need;
	bool get, ofd;
	int e;

	get = s->cmd == F_GETLK || s->cmd == F_OFD_GETLK;
	ofd = s->cmd == F_OFD_SETLK || s->cmd == F_OFD_GETLK;
	e = fget_err(ki, cap_rights_init(&need, CAP_FLOCK));
	if (e != 0)
		return (want_err(e, get ? "kern_descrip.c:948 fget_unlocked" :
		    "kern_descrip.c:824 fget_unlocked"));
	if (!HAS(ki, A_DTV) || HAS(ki, A_OPATH))
		return (want_err(EBADF, get ? "kern_descrip.c:951-955 not a "
		    "DTYPE_VNODE file" : "kern_descrip.c:827-831 not a "
		    "DTYPE_VNODE file"));
	if (get && s->type != F_RDLCK && s->type != F_WRLCK &&
	    s->type != F_UNLCK)
		return (want_err(EINVAL, "kern_descrip.c:957-962 l_type, "
		    "before the OFD test"));
	if (ofd && s->pid != 0)
		return (want_err(EINVAL, "kern_descrip.c:834/964 -> 620-621 "
		    "fcntl_ofd_check: l_pid"));
	if (ofd && !fs_ofd(ki))
		return (want_err(EOPNOTSUPP, "kern_descrip.c:834/964 -> "
		    "626-628 fcntl_ofd_check: no VFCF_OFDLOCKS, before "
		    "SEEK_CUR and l_type"));
	if (s->whence == SEEK_CUR)
		return (want_err(EOVERFLOW, get ? "kern_descrip.c:971-980" :
		    "kern_descrip.c:841-849"));
	if (!get) {
		switch (s->type) {
		case F_RDLCK:
			if (!HAS(ki, A_RD))
				return (want_err(EBADF, "kern_descrip.c:857-860 "
				    "F_RDLCK without FREAD"));
			break;
		case F_WRLCK:
			if (!HAS(ki, A_WR))
				return (want_err(EBADF, "kern_descrip.c:872-875 "
				    "F_WRLCK without FWRITE"));
			break;
		case F_UNLCK:
			break;
		default:
			return (want_err(EINVAL, "kern_descrip.c:900-902 "
			    "l_type"));
		}
	}
	if (s->whence != SEEK_SET)
		return (want_err(EINVAL, "VOP_ADVLOCK -> kern_lockf.c:454-473 "
		    "lf_advlockasync: l_whence"));
	return (want_val(0, "VOP_ADVLOCK -> lf_advlock"));
}

static void
row_fcntl_lock(struct kinst *ki)
{
	struct flock fl;
	struct want w;
	size_t i;

	for (i = 0; i < nitems(lksubs); i++) {
		/* An offset of 1, for the SEEK_CUR overflow subcases. */
		if (HAS(ki, A_SEEK))
			(void)lseek(ki->fd, lksubs[i].whence == SEEK_CUR ? 1 :
			    0, SEEK_SET);
		memset(&fl, 0, sizeof(fl));
		fl.l_type = lksubs[i].type;
		fl.l_whence = lksubs[i].whence;
		fl.l_start = lksubs[i].start;
		fl.l_len = 0;
		fl.l_pid = lksubs[i].pid;
		w = want_lk(ki, &lksubs[i]);
		if (cell(lksubs[i].sub, ki, NULL, CALL(fcntl(ki->fd,
		    lksubs[i].cmd, &fl)), w) && w.err == 0 &&
		    (lksubs[i].cmd == F_GETLK || lksubs[i].cmd == F_OFD_GETLK))
			effect(fl.l_type == F_UNLCK, lksubs[i].sub, ki,
			    "no conflicting lock reported");
		/* Release whatever the cell took. */
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_UNLCK;
		fl.l_whence = SEEK_SET;
		(void)fcntl(ki->fd, F_SETLK, &fl);
		(void)fcntl(ki->fd, F_OFD_SETLK, &fl);
	}
}

/* ------------------------------------------------------------------ */
/* fcntl(2) commands that moved to fo_fcntl, and F_KINFO.              */
/* ------------------------------------------------------------------ */

static void
row_fcntl_readahead(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 cmd;
		int		 arg;
	} subs[] = {
		{ "readahead_128k", F_READAHEAD, 128 * 1024 },
		{ "readahead_off", F_READAHEAD, -1 },
		{ "rdahead_on", F_RDAHEAD, 1 },
		{ "rdahead_off", F_RDAHEAD, 0 },
	};
	cap_rights_t need;
	struct want w;
	size_t i;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FCNTL_READAHEAD));
	if (e != 0)
		w = want_err(e, "kern_descrip.c:1012 fget_unlocked");
	else if (!HAS(ki, A_DTV) || HAS(ki, A_OPATH))
		w = want_err(EBADF, "kern_descrip.c:1015-1019 not DTYPE_VNODE, "
		    "or O_PATH");
	else if (ki->k->vt != VT_REG)
		w = want_err(ENOTTY, "kern_descrip.c:1021-1025 not VREG");
	else
		w = want_val(0, "kern_descrip.c:1031-1046");
	for (i = 0; i < nitems(subs); i++)
		(void)cell(subs[i].sub, ki, NULL, CALL(fcntl(ki->fd,
		    subs[i].cmd, subs[i].arg)), w);
}

static void
row_fcntl_isunionstack(struct kinst *ki)
{
	cap_rights_t need;
	struct want w;
	int e;

	e = fget_err(ki, cap_rights_init(&need));
	if (e != 0)
		w = want_err(e, "kern_descrip.c:1063 fget_unlocked, no rights");
	else if (!HAS(ki, A_DTV))
		w = want_err(EBADF, "kern_descrip.c:1066-1070 not DTYPE_VNODE "
		    "(O_PATH accepted)");
	else
		w = want_val(0, "kern_descrip.c:1085-1088 not a union mount");
	(void)cell("isunionstack", ki, NULL, CALL(fcntl(ki->fd,
	    F_ISUNIONSTACK)), w);
}

static int
kf_type_of(const struct kinst *ki, const char **why)
{
	switch (ki->k->tbl) {
	case T_FIFO:
		*why = "sys_pipe.c:2061-2062 -> vfs_vnops.c:3443-3444";
		return (KF_TYPE_FIFO);
	case T_VNOPS:
	case T_DEVFS:
	case T_PATH:
		*why = "vfs_vnops.c:3445-3446";
		return (KF_TYPE_VNODE);
	case T_PIPE:
		*why = "sys_pipe.c:2063";
		return (KF_TYPE_PIPE);
	case T_SOCKU:
	case T_SOCKI:
		*why = "sys_socket.c:414";
		return (KF_TYPE_SOCKET);
	case T_KQ:
		*why = "kern_event.c:2687";
		return (KF_TYPE_KQUEUE);
	case T_SHM:
		*why = "uipc_shm.c:2156";
		return (KF_TYPE_SHM);
	case T_PTS:
		*why = "tty_pts.c:696";
		return (KF_TYPE_PTS);
	case T_PD:
		*why = "sys_procdesc.c:786";
		return (KF_TYPE_PROCDESC);
	case T_EVFD:
		*why = "sys_eventfd.c:432";
		return (KF_TYPE_EVENTFD);
	case T_TFD:
		*why = "sys_timerfd.c:417";
		return (KF_TYPE_TIMERFD);
	case T_INOT:
		*why = "vfs_inotify.c:965";
		return (KF_TYPE_INOTIFY);
	case T_MQ:
		*why = "uipc_mqueue.c:2800";
		return (KF_TYPE_MQUEUE);
	default:
		*why = "";
		return (-1);
	}
}

static void
row_fcntl_kinfo(struct kinst *ki)
{
	struct kinfo_file kif;
	cap_rights_t need;
	const char *why;
	struct want w;
	bool hooked;
	int e, t;

	e = fget_err(ki, cap_rights_init(&need, CAP_FCNTL));
	if (e != 0)
		w = want_err(e, "kern_descrip.c:1110 fget_cap_noref");
	else
		w = want_val(0, "kern_descrip.c:1111-1118 export_file_to_kinfo, "
		    "KF_ATTR_VALID");
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	if (cell("kinfo", ki, NULL, CALL(fcntl(ki->fd, F_KINFO, &kif)), w) &&
	    w.err == 0) {
		t = kf_type_of(ki, &why);
		ATF_CHECK_MSG(kif.kf_type == t, "%s/kinfo [%s]: kf_type %d, "
		    "base %d (%s)", g_row, ki->k->name, kif.kf_type, t, why);
	}

	/*
	 * Base fails the cells below before the descriptor.  Under a policy
	 * registering file_check_fcntl the prologue's lookup comes first
	 * (D79), which only a bad descriptor can see.
	 */
	hooked = g_fcntl_hook && HAS(ki, A_BAD);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = 1;
	(void)cell("kinfo_bad_size", ki, NULL, CALL(fcntl(ki->fd, F_KINFO,
	    &kif)), hooked ? want_err(EBADF, "D79: file_check_fcntl prologue "
	    "lookup, kern_descrip.c:649-652") : want_err(EINVAL,
	    "kern_descrip.c:1101-1106 size, before the descriptor"));

	/* The kernel-only Linux hint commands are not fcntl(2) commands. */
	(void)cell("rw_hint_cmd", ki, NULL, CALL(fcntl(ki->fd, 0x1000, 0)),
	    hooked ? want_err(EBADF, "D79: file_check_fcntl prologue lookup, "
	    "kern_descrip.c:649-652") : want_err(EINVAL, "kern_descrip.c:"
	    "1129-1131 unknown command, before the descriptor"));
	(void)cell("set_rw_hint_cmd", ki, NULL, CALL(fcntl(ki->fd, 0x1001,
	    0)), hooked ? want_err(EBADF, "D79: file_check_fcntl prologue "
	    "lookup, kern_descrip.c:649-652") : want_err(EINVAL,
	    "kern_descrip.c:1129-1131 unknown command"));
}

/* ------------------------------------------------------------------ */
/* lseek(2): kern_lseek, vfs_syscalls.c:2035-2047 (reference row).     */
/* ------------------------------------------------------------------ */

static void
row_lseek(struct kinst *ki)
{
	cap_rights_t need;
	struct want w, wb;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_SEEK));
	if (e != 0)
		w = wb = want_err(e, "vfs_syscalls.c:2041 fget");
	else if (!HAS(ki, A_SEEK))
		w = wb = want_err(ESPIPE, "vfs_syscalls.c:2044-2045 not "
		    "DFLAG_SEEKABLE, before whence");
	else {
		w = want_val(0, "vfs_syscalls.c:2045 fo_seek");
		wb = want_err(EINVAL, ki->k->tbl == T_SHM ? "uipc_shm.c:583-584 "
		    "shm_seek" : "vfs_vnops.c:3400-3401 vn_seek");
	}
	(void)cell("cur", ki, NULL, CALL(lseek(ki->fd, 0, SEEK_CUR)), w);
	(void)cell("bad_whence", ki, NULL, CALL(lseek(ki->fd, 0, 99)), wb);
}

/* ------------------------------------------------------------------ */
/* /dev/fd/N attributes through fdescfs: fdesc_setattr,                */
/* fdesc_vnops.c:583-637.                                              */
/* ------------------------------------------------------------------ */

static struct want
want_fdesc(const struct kinst *ki, int e, bool size, bool flags,
    struct res oracle)
{
	if (e != 0)
		return (want_err(e, size ? "fdesc_vnops.c:609 getvnode: fget" :
		    "fdesc_vnops.c:612 getvnode_path: fget"));
	if (!HAS(ki, A_VN))
		return (flags ? want_err(EOPNOTSUPP, "fdesc_vnops.c:621-623 "
		    "no vnode: chflags refused") : want_val(0,
		    "fdesc_vnops.c:621-626 no vnode: change dropped"));
	if (size && HAS(ki, A_OPATH))
		return (want_err(EBADF, "fdesc_vnops.c:609 -> vfs_syscalls.c:"
		    "4661-4663 O_PATH truncate"));
	return (want_res(oracle, "fdesc_vnops.c:630-633 VOP_SETATTR on the "
	    "descriptor's vnode (oracle: the path form)"));
}

static void
row_fdesc_setattr(struct kinst *ki)
{
	struct timespec ts[2];
	cap_rights_t need;
	struct stat sb;
	struct res o;
	char p[64];
	const char *path = ki->path;
	bool lnk = HAS(ki, A_LNK), vn = HAS(ki, A_VN);
	int e;

	if (HAS(ki, A_BAD))
		return;		/* No /dev/fd/N to name. */
	snprintf(p, sizeof(p), "fdesc/%d", ki->fd);
	e = fget_err(ki, cap_rights_init(&need, CAP_EXTATTR_SET));
	memset(&sb, 0, sizeof(sb));
	memset(&o, 0, sizeof(o));
	/* The vnode's own values, so that nothing changes on /dev. */
	if (vn)
		ATF_REQUIRE(st_path(ki, &sb) == 0);

	sb.st_mode = vn ? sb.st_mode & ALLPERMS : 0600;
	if (vn && e == 0)
		o = CALL(lnk ? lchmod(path, sb.st_mode) :
		    chmod(path, sb.st_mode));
	(void)cell("chmod", ki, NULL, CALL(chmod(p, sb.st_mode)),
	    want_fdesc(ki, e, false, false, o));

	if (vn && e == 0)
		o = CALL(lnk ? lchown(path, sb.st_uid, (gid_t)-1) :
		    chown(path, sb.st_uid, (gid_t)-1));
	(void)cell("chown", ki, NULL, CALL(chown(p, sb.st_uid, (gid_t)-1)),
	    want_fdesc(ki, e, false, false, o));

	if (vn && e == 0 && !HAS(ki, A_OPATH))
		o = CALL(truncate(path, sb.st_size));
	(void)cell("truncate", ki, NULL, CALL(truncate(p, sb.st_size)),
	    want_fdesc(ki, e, true, false, o));

	if (vn) {
		ts[0] = sb.st_atim;
		ts[1] = sb.st_mtim;
	} else {
		ts[0] = fixed_ts[0];
		ts[1] = fixed_ts[1];
	}
	if (vn && e == 0)
		o = CALL(utimensat(AT_FDCWD, path, ts,
		    lnk ? AT_SYMLINK_NOFOLLOW : 0));
	(void)cell("utimens", ki, NULL, CALL(utimensat(AT_FDCWD, p, ts, 0)),
	    want_fdesc(ki, e, false, false, o));

	if (vn && e == 0)
		o = CALL(lnk ? lchflags(path, sb.st_flags) :
		    chflags(path, sb.st_flags));
	(void)cell("chflags", ki, NULL, CALL(chflags(p, sb.st_flags)),
	    want_fdesc(ki, e, false, true, o));
}

/* ------------------------------------------------------------------ */
/* readlink(/dev/fd/N) on an fdescfs mounted "rdlnk": fdesc_readlink,  */
/* fdesc_vnops.c:737-782.                                              */
/* ------------------------------------------------------------------ */

static void
row_readlink(struct kinst *ki)
{
	char p[64], buf[PATH_MAX], want[PATH_MAX];
	struct want w;
	struct res r;

	if (HAS(ki, A_BAD))
		return;		/* No /dev/fd/N to name. */
	snprintf(p, sizeof(p), "fdesc_rl/%d", ki->fd);
	if (HAS(ki, A_DTV)) {
		strlcpy(want, ki->path, sizeof(want));
		w = want_val((long)strlen(want), "fdesc_vnops.c:762-764 "
		    "DTYPE_VNODE: vn_fullpath");
	} else {
		strlcpy(want, ANON_INODE, sizeof(want));
		w = want_val((long)strlen(want), "fdesc_vnops.c:766-767 not "
		    "DTYPE_VNODE (a FIFO is DTYPE_FIFO, a ptmx master "
		    "DTYPE_PTS)");
	}
	r = CALL(readlink(p, buf, sizeof(buf) - 1));
	if (cell("readlink", ki, NULL, r, w)) {
		buf[r.ret] = '\0';
		ATF_CHECK_MSG(strcmp(buf, want) == 0, "%s/readlink [%s]: "
		    "\"%s\", base \"%s\"", g_row, ki->k->name, buf, want);
	}
}

/* ------------------------------------------------------------------ */
/* mmap(2): kern_mmap, vm_mmap.c:430-495, and the tables' fo_mmap.     */
/* ------------------------------------------------------------------ */

static struct want
want_mmap(const struct kinst *ki, int prot, int flags)
{
	cap_rights_t need;
	bool shared, wr;
	int e;

	shared = (flags & MAP_SHARED) != 0;
	wr = (prot & PROT_WRITE) != 0;
	cap_rights_init(&need, CAP_MMAP, CAP_MMAP_R);
	if (shared && wr)
		cap_rights_set(&need, CAP_MMAP_W);
	e = fget_err(ki, &need);
	if (e != 0)
		return (want_err(e, "vm_mmap.c:440-448 fget_mmap"));
	switch (ki->k->tbl) {
	case T_VNOPS:
		if (!HAS(ki, A_RD))
			return (want_err(EACCES, "vfs_vnops.c:3556-3559 not "
			    "FREAD"));
		if (shared && wr && !HAS(ki, A_WR))
			return (want_err(EACCES, "vfs_vnops.c:3566-3570 shared "
			    "write without FWRITE"));
		if (ki->k->vt != VT_REG)
			return (want_err(EINVAL, "vm_mmap.c:1440 "
			    "vm_mmap_vnode: not VREG"));
		return (want_ok("vfs_vnops.c:3523 vn_mmap"));
	case T_SHM:
		if (shared && wr && HAS(ki, A_SEAL))
			return (want_err(EPERM, "uipc_shm.c:1902-1917 write "
			    "seal"));
		return (want_ok("uipc_shm.c:1866 shm_mmap"));
	case T_DEVFS:
		if (shared && wr && !HAS(ki, A_WR))
			return (want_err(EACCES, "devfs_vnops.c:2049-2052 shared "
			    "write without FWRITE"));
		if (ki->k->id == K_DEVZERO)
			return (want_ok("vm_mmap.c:1517-1522 D_MMAP_ANON"));
		if (wr && !shared)
			return (want_err(EACCES, "vm_mmap.c:1528-1530 private "
			    "write of a cdev"));
		if (!shared)
			return (want_err(EINVAL, "vm_mmap.c:1531-1532 cdev "
			    "mapping must be shared"));
		return (want_err(EINVAL, "vm_mmap.c:1553-1560 no d_mmap: "
		    "device pager allocation fails"));
	default:
		return (want_err(ENODEV, "vm_mmap.c:487 -> file.h:489-490 no "
		    "fo_mmap"));
	}
}

static void
row_mmap(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 prot;
		int		 flags;
	} subs[] = {
		{ "r_shared", PROT_READ, MAP_SHARED },
		{ "rw_private", PROT_READ | PROT_WRITE, MAP_PRIVATE },
		{ "rw_shared", PROT_READ | PROT_WRITE, MAP_SHARED },
	};
	struct want w;
	struct res r;
	void *addr;
	size_t i;

	for (i = 0; i < nitems(subs); i++) {
		w = want_mmap(ki, subs[i].prot, subs[i].flags);
		addr = mmap(NULL, PAGE_SIZE, subs[i].prot, subs[i].flags,
		    ki->fd, 0);
		r.err = addr == MAP_FAILED ? errno : 0;
		r.ret = addr == MAP_FAILED ? -1 : 0;
		if (cell(subs[i].sub, ki, NULL, r, w) && w.err == 0 &&
		    ki->k->tbl == T_VNOPS)
			effect(*(volatile char *)addr == '0', subs[i].sub, ki,
			    "the file's first byte is mapped");
		if (addr != MAP_FAILED)
			ATF_REQUIRE(munmap(addr, PAGE_SIZE) == 0);
	}
}

/* A cell whose descriptor is made by the case itself. */
static bool
named_cell(const char *kname, const char *sub, struct res r, struct want w)
{
	struct kdef kd;
	struct kinst ki;

	memset(&kd, 0, sizeof(kd));
	kd.name = kname;
	memset(&ki, 0, sizeof(ki));
	ki.k = &kd;
	return (cell(sub, &ki, NULL, r, w));
}

static struct res
mmap_res(int fd, int prot, int flags)
{
	struct res r;
	void *addr;

	addr = mmap(NULL, PAGE_SIZE, prot, flags, fd, 0);
	r.err = addr == MAP_FAILED ? errno : 0;
	r.ret = addr == MAP_FAILED ? -1 : 0;
	if (addr != MAP_FAILED)
		ATF_REQUIRE(munmap(addr, PAGE_SIZE) == 0);
	return (r);
}

/* ------------------------------------------------------------------ */
/* aio_fsync(2): kern_aio_fsync, vfs_aio.c:2870-2887, aio_aqueue.      */
/* ------------------------------------------------------------------ */

static bool g_aio_unsafe;

static void
row_aio_fsync(struct kinst *ki)
{
	static const struct {
		const char	*sub;
		int		 op;
	} subs[] = {
		{ "sync", O_SYNC },
		{ "dsync", O_DSYNC },
		{ "bad_op", 0 },
	};
	const struct aiocb *list[1];
	struct timespec to;
	cap_rights_t need;
	struct aiocb cb;
	struct want w;
	size_t i;
	int e;

	e = fget_err(ki, cap_rights_init(&need, CAP_FSYNC));
	for (i = 0; i < nitems(subs); i++) {
		if (subs[i].op == 0)
			w = want_err(EINVAL, "vfs_aio.c:2875-2884 op, before the "
			    "descriptor");
		else if (e != 0)
			w = want_err(e, "vfs_aio.c:1700 fget");
		else if (!HAS(ki, A_VN))
			w = want_err(EINVAL, "vfs_aio.c:1713-1716 LIO_SYNC "
			    "without a vnode");
		else if (HAS(ki, A_OPATH))
			w = want_err(EBADF, "vfs_aio.c:1726-1729 O_PATH");
		else if (!(HAS(ki, A_DTV) && (ki->k->vt == VT_REG ||
		    ki->k->vt == VT_DIR)) && !g_aio_unsafe)
			w = want_err(EOPNOTSUPP, "vfs_aio.c:1804 -> 2073-2086 "
			    "unsafe AIO (vfs.aio.enable_unsafe=0)");
		else
			w = want_val(0, "vfs_aio.c:1804 -> 2089-2120 queued");
		memset(&cb, 0, sizeof(cb));
		cb.aio_fildes = ki->fd;
		cb.aio_sigevent.sigev_notify = SIGEV_NONE;
		if (!cell(subs[i].sub, ki, NULL, CALL(aio_fsync(subs[i].op,
		    &cb)), w) || w.err != 0)
			continue;
		list[0] = &cb;
		to.tv_sec = 30;
		to.tv_nsec = 0;
		while (aio_error(&cb) == EINPROGRESS)
			ATF_REQUIRE(aio_suspend(list, 1, &to) == 0 ||
			    errno == EINTR);
		effect(aio_error(&cb) == 0 && aio_return(&cb) == 0,
		    subs[i].sub, ki, "the queued fsync completed with 0 "
		    "(base aio_fsync_vnode: VOP_FSYNC)");
	}
}

/* ------------------------------------------------------------------ */
/* The test cases.                                                     */
/* ------------------------------------------------------------------ */

#define	FDOPS_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	fx_cleanup();							\
}									\
ATF_TC_BODY(name, tc)

#define	FDOPS_ROW_TC(name, fn, descr)					\
FDOPS_TC(name, descr)							\
{									\
	fx_setup(tc, #name);						\
	each_kind(fn);							\
	fx_done();							\
}

FDOPS_ROW_TC(fpathconf, row_fpathconf,
    "fpathconf(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fstatfs, row_fstatfs,
    "fstatfs(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fsync, row_fsync,
    "fsync(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fdatasync, row_fdatasync,
    "fdatasync(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fchmod, row_fchmod,
    "fchmod(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fchown, row_fchown,
    "fchown(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fchflags, row_fchflags,
    "fchflags(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(futimens, row_futimens,
    "futimens(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(futimes, row_futimes,
    "futimes(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(ftruncate, row_ftruncate,
    "ftruncate(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(posix_fadvise, row_fadvise,
    "posix_fadvise(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(getdirentries, row_getdirentries,
    "getdirentries(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(extattr, row_extattr,
    "extattr_{set,get,list,delete}_fd(2) on every descriptor kind")
FDOPS_ROW_TC(acl, row_acl,
    "__acl_{get,aclcheck,set,delete}_fd(2) on every descriptor kind")
FDOPS_ROW_TC(flock, row_flock,
    "flock(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(fcntl_lock, row_fcntl_lock,
    "fcntl(2) F_SETLK/F_GETLK/F_OFD_* on every descriptor kind")
FDOPS_ROW_TC(fcntl_readahead, row_fcntl_readahead,
    "fcntl(2) F_READAHEAD/F_RDAHEAD on every descriptor kind")
FDOPS_ROW_TC(fcntl_isunionstack, row_fcntl_isunionstack,
    "fcntl(2) F_ISUNIONSTACK on every descriptor kind")
FDOPS_ROW_TC(fcntl_kinfo, row_fcntl_kinfo,
    "fcntl(2) F_KINFO and the kernel-only hint commands on every kind")
FDOPS_ROW_TC(lseek, row_lseek,
    "lseek(2) on every descriptor kind (reference row)")
FDOPS_ROW_TC(mmap, row_mmap,
    "mmap(2) on every descriptor kind, as at 3b9f9873d291")
FDOPS_ROW_TC(copy_file_range_misc, row_cfr_samefd,
    "copy_file_range(2) with one descriptor as input and output")

FDOPS_TC(copy_file_range_flags,
    "copy_file_range(2) checks its flags before either descriptor")
{
	fx_setup(tc, "copy_file_range_flags");
	each_kind(row_cfr_flags);
	fx_done();
}

FDOPS_TC(copy_file_range,
    "copy_file_range(2) with every kind as input and as output")
{
	size_t i, j;

	fx_setup(tc, "copy_file_range");
	for (i = 0; i < nitems(kdefs); i++)
		for (j = 0; j < nitems(kdefs); j++) {
			cfr_pair(&kdefs[i], &kdefs[j], 1, "len1");
			cfr_pair(&kdefs[i], &kdefs[j], 0, "len0");
		}
	fx_done();
}

FDOPS_TC(fdesc_setattr,
    "chmod/chown/truncate/utimensat/chflags of /dev/fd/N (fdescfs)")
{
	fx_setup(tc, "fdesc_setattr");
	if (!fdesc_mount("fdesc", NULL))
		atf_tc_skip("fdescfs not available");
	each_kind(row_fdesc_setattr);
	fx_done();
}

FDOPS_TC(fdesc_readlink,
    "readlink(2) of /dev/fd/N on fdescfs mounted rdlnk")
{
	fx_setup(tc, "fdesc_readlink");
	if (!fdesc_mount("fdesc_rl", "rdlnk"))
		atf_tc_skip("fdescfs not available");
	each_kind(row_readlink);
	fx_done();
}

FDOPS_TC(aio_fsync,
    "aio_fsync(2) on every descriptor kind, as at 3b9f9873d291")
{
	struct aiocb cb;
	char path[PATH_MAX];
	int fd;

	fx_setup(tc, "aio_fsync");
	g_aio_unsafe = sysctl_bool("vfs.aio.enable_unsafe");
	fd = open_reg(path, O_RDWR);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_sigevent.sigev_notify = SIGEV_NONE;
	if (aio_fsync(O_SYNC, &cb) != 0 && errno == ENOSYS)
		atf_tc_skip("aio(4) not available");
	while (aio_error(&cb) == EINPROGRESS)
		(void)usleep(1000);
	(void)aio_return(&cb);
	(void)close(fd);
	each_kind(row_aio_fsync);
	fx_done();
}

FDOPS_TC(mmap_caps,
    "mmap(2) private writes of capability-limited descriptors")
{
	cap_rights_t rights;
	char path[PATH_MAX];
	int fd;

	fx_setup(tc, "mmap_caps");
	fd = open_reg(path, O_RDWR);
	ATF_REQUIRE(cap_rights_limit(fd, cap_rights_init(&rights, CAP_MMAP_R,
	    CAP_READ, CAP_SEEK)) == 0);
	(void)named_cell("reg_mmap_r", "rw_private", mmap_res(fd,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE), want_ok("vm_mmap.c:470-471 "
	    "DTYPE_VNODE private write needs no CAP_MMAP_W"));
	(void)named_cell("reg_mmap_r", "rw_shared", mmap_res(fd,
	    PROT_READ | PROT_WRITE, MAP_SHARED), want_err(ENOTCAPABLE,
	    "vm_mmap.c:439-448 shared write needs CAP_MMAP_W"));
	(void)close(fd);

	fd = open("/dev/zero", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(cap_rights_limit(fd, cap_rights_init(&rights, CAP_MMAP_R,
	    CAP_READ)) == 0);
	(void)named_cell("devzero_mmap_r", "rw_private", mmap_res(fd,
	    PROT_READ | PROT_WRITE, MAP_PRIVATE), want_ok("vm_mmap.c:470-471 "
	    "DTYPE_VNODE (devfs) private write; 1517-1522 D_MMAP_ANON"));
	(void)close(fd);
	printf("not run: shm limited to CAP_MMAP_R, MAP_PRIVATE|PROT_WRITE: "
	    "base reaches vm_map_insert's KASSERT (D240)\n");
	fx_done();
}

/*
 * Closing any DTYPE_VNODE descriptor of a file, O_PATH included, drops the
 * process's POSIX locks on it: closef, kern_descrip.c:3443-3452.
 */
static bool
lock_released(const char *path)
{
	struct flock fl;
	pid_t pid;
	int fd, st;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fd = open(path, O_RDWR);
		if (fd < 0)
			_exit(2);
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		if (fcntl(fd, F_GETLK, &fl) != 0)
			_exit(2);
		_exit(fl.l_type == F_UNLCK ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(pid, &st, 0) == pid);
	ATF_REQUIRE(WIFEXITED(st) && WEXITSTATUS(st) != 2);
	return (WEXITSTATUS(st) == 0);
}

FDOPS_TC(close_unlock,
    "closing another descriptor of a locked file drops POSIX locks")
{
	static const char *const variants[] = {
		"rdonly", "wronly", "opath", "caplim", "scm_rdonly",
	};
	cap_rights_t rights;
	char path[PATH_MAX];
	struct flock fl;
	struct res r;
	size_t i;
	int fd0, fd1, t;

	fx_setup(tc, "close_unlock");
	fd0 = open_reg(path, O_RDWR);
	for (i = 0; i < nitems(variants); i++) {
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		ATF_REQUIRE(fcntl(fd0, F_SETLK, &fl) == 0);
		ATF_REQUIRE(!lock_released(path));
		switch (i) {
		case 0:
			fd1 = open(path, O_RDONLY);
			break;
		case 1:
			fd1 = open(path, O_WRONLY);
			break;
		case 2:
			fd1 = open(path, O_PATH);
			break;
		case 3:
			fd1 = open(path, O_RDONLY);
			ATF_REQUIRE(fd1 >= 0);
			ATF_REQUIRE(cap_rights_limit(fd1,
			    cap_rights_init(&rights, CAP_READ)) == 0);
			break;
		default:
			t = open(path, O_RDONLY);
			ATF_REQUIRE(t >= 0);
			fd1 = pass_fd(t);
			(void)close(t);
			/* That close already released the lock: retake it. */
			ATF_REQUIRE(fcntl(fd0, F_SETLK, &fl) == 0);
			break;
		}
		ATF_REQUIRE(fd1 >= 0);
		ATF_REQUIRE(close(fd1) == 0);
		r.err = 0;
		r.ret = lock_released(path) ? 1 : 0;
		(void)named_cell(variants[i], "released", r, want_val(1,
		    "kern_descrip.c:3443-3452 closef: any DTYPE_VNODE close "
		    "unlocks the process's POSIX locks"));
	}
	fx_done();
}

/*
 * fchflags(2) by an unprivileged user: PRIV_VFS_CHFLAGS_DEV comes before
 * the VNOVAL refusal for a device (vfs_syscalls.c:2880-2883, 2730).  The
 * root-opened descriptors are used after setuid; the check is on the
 * caller's credential.
 */
FDOPS_TC(fchflags_unpriv,
    "fchflags(2) by an unprivileged user on devices, a pipe and a file")
{
	static const struct {
		const char	*kind;
		const char	*sub;
		int		 which;
		u_long		 flags;
	} calls[] = {
		{ "devnull", "vnoval", 0, (u_long)VNOVAL },
		{ "devnull", "zero", 0, 0 },
		{ "pt_ptmx", "vnoval", 1, (u_long)VNOVAL },
		{ "pt_ptmx", "zero", 1, 0 },
		{ "pipe_r", "vnoval", 2, (u_long)VNOVAL },
		{ "reg_own", "vnoval", 3, (u_long)VNOVAL },
		{ "reg_own", "current", 3, 0 },
	};
	struct want w[nitems(calls)];
	struct res got[nitems(calls)];
	char path[PATH_MAX];
	struct stat sb;
	int fds[4], p[2], rp[2], st;
	size_t i;
	pid_t pid;

	fx_setup(tc, "fchflags_unpriv");
	fds[0] = open("/dev/null", O_RDWR);
	fds[1] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(pipe(p) == 0);
	fds[2] = p[0];
	fds[3] = open_reg(path, O_RDWR);
	ATF_REQUIRE(fds[0] >= 0 && fds[1] >= 0);
	ATF_REQUIRE(fchown(fds[3], NOBODY, NOBODY) == 0);
	/* The file keeps its own flags (UF_ARCHIVE on zfs): nothing changes. */
	ATF_REQUIRE(fstat(fds[3], &sb) == 0);
	ATF_REQUIRE(pipe(rp) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (setgid(NOBODY) != 0 || setuid(NOBODY) != 0)
			_exit(1);
		for (i = 0; i < nitems(calls); i++)
			got[i] = CALL(fchflags(fds[calls[i].which], i == 6 ?
			    sb.st_flags : calls[i].flags));
		_exit(write(rp[1], got, sizeof(got)) == (ssize_t)sizeof(got) ?
		    0 : 1);
	}
	ATF_REQUIRE(waitpid(pid, &st, 0) == pid);
	ATF_REQUIRE(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	ATF_REQUIRE(read(rp[0], got, sizeof(got)) == (ssize_t)sizeof(got));
	w[0] = want_err(EPERM, "vfs_syscalls.c:2880-2883 PRIV_VFS_CHFLAGS_DEV, "
	    "before VNOVAL (2730)");
	w[1] = want_err(EPERM, "vfs_syscalls.c:2880-2883 PRIV_VFS_CHFLAGS_DEV");
	w[2] = want_err(EPERM, "vfs_syscalls.c:2862 (f_vnode is /dev/ptmx) -> "
	    "2880-2883 PRIV_VFS_CHFLAGS_DEV, before VNOVAL");
	w[3] = want_err(EPERM, "vfs_syscalls.c:2880-2883 PRIV_VFS_CHFLAGS_DEV");
	w[4] = want_err(EINVAL, "vfs_syscalls.c:2862 -> 4632-4636 no vnode");
	w[5] = want_err(EOPNOTSUPP, "vfs_syscalls.c:2730-2731 VNOVAL");
	w[6] = want_val(0, "vfs_syscalls.c:2892 VOP_SETATTR by the owner");
	for (i = 0; i < nitems(calls); i++)
		(void)named_cell(calls[i].kind, calls[i].sub, got[i], w[i]);
	fx_done();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fpathconf);
	ATF_TP_ADD_TC(tp, fstatfs);
	ATF_TP_ADD_TC(tp, fsync);
	ATF_TP_ADD_TC(tp, fdatasync);
	ATF_TP_ADD_TC(tp, fchmod);
	ATF_TP_ADD_TC(tp, fchown);
	ATF_TP_ADD_TC(tp, fchflags);
	ATF_TP_ADD_TC(tp, fchflags_unpriv);
	ATF_TP_ADD_TC(tp, futimens);
	ATF_TP_ADD_TC(tp, futimes);
	ATF_TP_ADD_TC(tp, ftruncate);
	ATF_TP_ADD_TC(tp, posix_fadvise);
	ATF_TP_ADD_TC(tp, getdirentries);
	ATF_TP_ADD_TC(tp, copy_file_range);
	ATF_TP_ADD_TC(tp, copy_file_range_misc);
	ATF_TP_ADD_TC(tp, copy_file_range_flags);
	ATF_TP_ADD_TC(tp, extattr);
	ATF_TP_ADD_TC(tp, acl);
	ATF_TP_ADD_TC(tp, flock);
	ATF_TP_ADD_TC(tp, fcntl_lock);
	ATF_TP_ADD_TC(tp, fcntl_readahead);
	ATF_TP_ADD_TC(tp, fcntl_isunionstack);
	ATF_TP_ADD_TC(tp, fcntl_kinfo);
	ATF_TP_ADD_TC(tp, lseek);
	ATF_TP_ADD_TC(tp, fdesc_setattr);
	ATF_TP_ADD_TC(tp, fdesc_readlink);
	ATF_TP_ADD_TC(tp, mmap);
	ATF_TP_ADD_TC(tp, mmap_caps);
	ATF_TP_ADD_TC(tp, aio_fsync);
	ATF_TP_ADD_TC(tp, close_unlock);
	return (atf_no_error());
}

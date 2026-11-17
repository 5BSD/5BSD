/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue (dq): the installed ABI between the kernel and a
 * controller.
 *
 * A controller opens /dev/dq (one open is one queue), mints descriptors
 * that present an identity of its choosing, reads the operations the
 * kernel turns into events, and answers them.  Everything here is fixed
 * width, native byte order, LP64 only, and additive: a field is never
 * moved or retyped; new fields take pad space or extend a struct behind a
 * larger de_size/dm_version.  See dq(4) and the chapter
 * docs/book/src/capability/descriptor-queue.md.
 */

#ifndef _DEV_DQ_DQ_H_
#define	_DEV_DQ_DQ_H_

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/capsicum.h>

#if !defined(__LP64__)
#error "DescriptorQueue is LP64 only"
#endif

/*
 * ufs/ufs/dinode.h defines di_rdev as a macro (di_db[0]); any source that
 * includes it before this header (the NFS server does, through its port
 * headers) would turn struct dq_ident_file's di_rdev into a zero-length
 * array and change the layout.  The identity's field names are ABI, so
 * the macro is suspended for this header instead.
 */
#pragma push_macro("di_rdev")
#undef di_rdev
/* sys/bus.h defines dr_data (struct dq_reply's field name is ABI). */
#pragma push_macro("dr_data")
#undef dr_data

/*
 * The version every ioctl argument carries and every event header
 * reports; the kernel accepts this one only.  2 (D184): the RESOLVE body
 * grew from 96 to 112 bytes and moved its strings (drs_root,
 * drs_rootpathlen, the served root's path), which a version-1 controller
 * would misparse.
 */
#define	DQ_API_VERSION		2

#define	DQ_PATH_MAX		1024	/* presented path, NUL included */
#define	DQ_MNAMELEN		1024	/* == MNAMELEN, sys/mount.h */
#define	DQ_MFSNAMELEN		16	/* == MFSNAMELEN */

/*
 * Kinds (design 7.3).  Stage 1a serves DQ_KIND_FILE; stage 1c-iii-b adds
 * DQ_KIND_DIR (MINT and RESOLVE FD) and DQ_KIND_SYMLINK (RESOLVE FD only,
 * O_PATH | O_NOFOLLOW opens); the others are reserved numbers so the ABI
 * does not move when they arrive.
 */
enum dq_kind {
	DQ_KIND_FILE = 1,
	DQ_KIND_DIR = 2,
	DQ_KIND_SYMLINK = 3,
	DQ_KIND_SOCKET = 4,
	DQ_KIND_CDEV = 5,
};

struct dq_timespec {
	int64_t		tv_sec;
	int64_t		tv_nsec;
};

/*
 * Presented identity (design 7.4).  Every field fstat(2), fstatfs(2),
 * fpathconf(2), F_KINFO and realpath(3) can answer comes from here; the
 * kernel validates it at MINT and SETIDENT (dq(4) lists the rules) and
 * forces what it must (statfs f_version).
 */
struct dq_statfs {
	uint32_t	ds_type;		/* f_type */
	uint32_t	ds_pad0;
	uint64_t	ds_flags;		/* f_flags (MNT_*) */
	uint64_t	ds_bsize;
	uint64_t	ds_iosize;
	uint64_t	ds_blocks;
	uint64_t	ds_bfree;
	int64_t		ds_bavail;
	uint64_t	ds_files;
	int64_t		ds_ffree;
	uint64_t	ds_syncwrites;
	uint64_t	ds_asyncwrites;
	uint64_t	ds_syncreads;
	uint64_t	ds_asyncreads;
	uint32_t	ds_nvnodelistsize;
	uint32_t	ds_namemax;
	uint32_t	ds_owner;
	uint32_t	ds_pad1;
	uint32_t	ds_fsid[2];
	char		ds_fstypename[DQ_MFSNAMELEN];
	char		ds_mntfromname[DQ_MNAMELEN];
	char		ds_mntonname[DQ_MNAMELEN];	/* a component-boundary
							   prefix of di_path */
};

/*
 * pathconf(2): the _PC_* constants are sparse, so the identity uses a
 * dense index.  dq_pc_names[] maps each DQ_PC_* to its _PC_* constant and
 * is shared by the kernel, libdq and the tests (define DQ_WANT_PC_NAMES).
 * A bit set in dp_valid means dp_value[i] is the answer; a name a regular
 * file can answer that dp_valid lacks is EINVAL, as on a filesystem
 * without it.  _PC_ASYNC_IO is answered by the kernel before dispatch.
 */
enum dq_pc {
	DQ_PC_LINK_MAX = 0,
	DQ_PC_MAX_CANON,
	DQ_PC_MAX_INPUT,
	DQ_PC_NAME_MAX,
	DQ_PC_PATH_MAX,
	DQ_PC_PIPE_BUF,
	DQ_PC_CHOWN_RESTRICTED,
	DQ_PC_NO_TRUNC,
	DQ_PC_VDISABLE,
	DQ_PC_ASYNC_IO,
	DQ_PC_PRIO_IO,
	DQ_PC_SYNC_IO,
	DQ_PC_ALLOC_SIZE_MIN,
	DQ_PC_FILESIZEBITS,
	DQ_PC_REC_INCR_XFER_SIZE,
	DQ_PC_REC_MAX_XFER_SIZE,
	DQ_PC_REC_MIN_XFER_SIZE,
	DQ_PC_REC_XFER_ALIGN,
	DQ_PC_SYMLINK_MAX,
	DQ_PC_ACL_EXTENDED,
	DQ_PC_ACL_PATH_MAX,
	DQ_PC_CAP_PRESENT,
	DQ_PC_INF_PRESENT,
	DQ_PC_MAC_PRESENT,
	DQ_PC_ACL_NFS4,
	DQ_PC_DEALLOC_PRESENT,
	DQ_PC_NAMEDATTR_ENABLED,
	DQ_PC_HAS_NAMEDATTR,
	DQ_PC_HAS_HIDDENSYSTEM,
	DQ_PC_CLONE_BLKSIZE,
	DQ_PC_CASE_INSENSITIVE,
	DQ_PC_MIN_HOLE_SIZE,
	DQ_PC_NCOUNT
};
#define	DQ_PC_SLOTS		64

struct dq_pathconf {
	uint64_t	dp_valid;		/* bit i: dp_value[i] answers */
	int64_t		dp_value[DQ_PC_SLOTS];
};

#if defined(_KERNEL) || defined(DQ_WANT_PC_NAMES)
#include <sys/unistd.h>
static const int dq_pc_names[DQ_PC_NCOUNT] = {
	[DQ_PC_LINK_MAX] = _PC_LINK_MAX,
	[DQ_PC_MAX_CANON] = _PC_MAX_CANON,
	[DQ_PC_MAX_INPUT] = _PC_MAX_INPUT,
	[DQ_PC_NAME_MAX] = _PC_NAME_MAX,
	[DQ_PC_PATH_MAX] = _PC_PATH_MAX,
	[DQ_PC_PIPE_BUF] = _PC_PIPE_BUF,
	[DQ_PC_CHOWN_RESTRICTED] = _PC_CHOWN_RESTRICTED,
	[DQ_PC_NO_TRUNC] = _PC_NO_TRUNC,
	[DQ_PC_VDISABLE] = _PC_VDISABLE,
	[DQ_PC_ASYNC_IO] = _PC_ASYNC_IO,
	[DQ_PC_PRIO_IO] = _PC_PRIO_IO,
	[DQ_PC_SYNC_IO] = _PC_SYNC_IO,
	[DQ_PC_ALLOC_SIZE_MIN] = _PC_ALLOC_SIZE_MIN,
	[DQ_PC_FILESIZEBITS] = _PC_FILESIZEBITS,
	[DQ_PC_REC_INCR_XFER_SIZE] = _PC_REC_INCR_XFER_SIZE,
	[DQ_PC_REC_MAX_XFER_SIZE] = _PC_REC_MAX_XFER_SIZE,
	[DQ_PC_REC_MIN_XFER_SIZE] = _PC_REC_MIN_XFER_SIZE,
	[DQ_PC_REC_XFER_ALIGN] = _PC_REC_XFER_ALIGN,
	[DQ_PC_SYMLINK_MAX] = _PC_SYMLINK_MAX,
	[DQ_PC_ACL_EXTENDED] = _PC_ACL_EXTENDED,
	[DQ_PC_ACL_PATH_MAX] = _PC_ACL_PATH_MAX,
	[DQ_PC_CAP_PRESENT] = _PC_CAP_PRESENT,
	[DQ_PC_INF_PRESENT] = _PC_INF_PRESENT,
	[DQ_PC_MAC_PRESENT] = _PC_MAC_PRESENT,
	[DQ_PC_ACL_NFS4] = _PC_ACL_NFS4,
	[DQ_PC_DEALLOC_PRESENT] = _PC_DEALLOC_PRESENT,
	[DQ_PC_NAMEDATTR_ENABLED] = _PC_NAMEDATTR_ENABLED,
	[DQ_PC_HAS_NAMEDATTR] = _PC_HAS_NAMEDATTR,
	[DQ_PC_HAS_HIDDENSYSTEM] = _PC_HAS_HIDDENSYSTEM,
	[DQ_PC_CLONE_BLKSIZE] = _PC_CLONE_BLKSIZE,
	[DQ_PC_CASE_INSENSITIVE] = _PC_CASE_INSENSITIVE,
	[DQ_PC_MIN_HOLE_SIZE] = _PC_MIN_HOLE_SIZE,
};
#endif

struct dq_ident_file {
	uint64_t	di_dev;			/* st_dev */
	uint64_t	di_ino;			/* st_ino */
	uint64_t	di_gen;			/* st_gen */
	uint64_t	di_filerev;		/* st_filerev */
	uint32_t	di_mode;		/* S_IFMT bits match the kind;
						   S_ISUID|S_ISGID rejected */
	uint32_t	di_nlink;
	uint32_t	di_uid;
	uint32_t	di_gid;
	uint64_t	di_size;
	uint64_t	di_blocks;
	uint32_t	di_blksize;		/* >= PAGE_SIZE */
	uint32_t	di_flags;		/* st_flags */
	uint64_t	di_rdev;
	struct dq_timespec di_atime;
	struct dq_timespec di_mtime;
	struct dq_timespec di_ctime;
	struct dq_timespec di_birthtime;
	uint32_t	di_pathlen;		/* strlen(di_path), 1..DQ_PATH_MAX-1 */
	uint32_t	di_pad0;
	char		di_path[DQ_PATH_MAX];	/* absolute, normalized */
	struct dq_statfs di_statfs;
	struct dq_pathconf di_pathconf;
};

/*
 * Policy (design 7.5).  The answers are distinct values so a wrong value
 * for a field is EINVAL rather than a silent reinterpretation.
 */
enum dq_cache {
	DQ_CACHE_NONE = 0,	/* read(2) always posts; pages exist only
				   while mapped or wired; fstat posts only
				   under DQ_EVENTS_GETATTR */
	DQ_CACHE_ATTR = 1,	/* attributes from the identity */
	DQ_CACHE_DATA = 2,	/* attributes and pages: read(2) is served
				   from cached pages, a miss posts READ for
				   whole pages; INVALIDATE drops them */
};
enum dq_answer {
	DQ_DENY = 0,
	DQ_EVENT = 1,
	DQ_ALLOW = 2,
};
#define	DQ_DEADLINE_DEFAULT	(-1)	/* kern.dq.default_deadline_ms */
#define	DQ_EVENTS_GETATTR	0x00000001	/* fstat is an event */
#define	DQ_EVENTS_CLOSE		0x00000002	/* last reference posts CLOSE */
#define	DQ_EVENTS_RCVD		0x00000004	/* stage 2 */
#define	DQ_EVENTS_SOCKOPT	0x00000008	/* stage 2 */
#define	DQ_EVENTS_SET_TEXT	0x00000010	/* stage 3 */

struct dq_policy {
	uint32_t	dp_cache;		/* enum dq_cache */
	uint32_t	dp_write;		/* DQ_DENY | DQ_EVENT */
	uint32_t	dp_exec;		/* DQ_DENY | DQ_ALLOW */
	uint32_t	dp_mmap_shared_write;	/* DQ_DENY | DQ_ALLOW (ALLOW needs
						   dp_write == DQ_EVENT) */
	uint32_t	dp_lock;		/* DQ_EVENT */
	uint32_t	dp_ioctl;		/* DQ_DENY | DQ_EVENT */
	int32_t		dp_deadline_ms;		/* DQ_DEADLINE_DEFAULT, 0 = none, or ms */
	uint32_t	dp_events;		/* DQ_EVENTS_* */
	uint32_t	dp_rights_version;	/* CAP_RIGHTS_VERSION dp_rights was built with */
	uint32_t	dp_flags;		/* DQ_PF_* (was dp_pad0, zero) */
	cap_rights_t	dp_rights;		/* rights of the minted descriptor */
};
/*
 * DQ_PF_NO_STAMP: the controller keeps the object's times itself (with
 * SETIDENT, GETATTR or the post-operation attributes of its replies); the
 * kernel does not stamp them after an operation that carried none.
 * 0x00000001 and 0x00000002 are reserved (DQ_PF_INTR, DQ_PF_WRITE_UNIT).
 */
#define	DQ_PF_NO_STAMP		0x00000004
#define	DQ_PF_VALID		(DQ_PF_NO_STAMP)

/*
 * Event header (design 8.1).  de_size is the whole record, header and
 * body; records are packed back to back in a read(2) buffer.
 */
struct dq_caller {
	int32_t		dc_pid;
	int32_t		dc_ppid;
	int32_t		dc_tid;
	uint32_t	dc_uid;
	uint32_t	dc_euid;
	uint32_t	dc_gid;
	uint32_t	dc_egid;
	uint32_t	dc_jid;
	uint64_t	dc_nonce;		/* mac_capability identity nonce, 0 if none */
	uint32_t	dc_flags;		/* DQ_CALLER_F_* */
	uint32_t	dc_pad0;
};
#define	DQ_CALLER_F_KERNEL	0x00000001	/* a kernel thread or no thread
						   posted it (pid 0) */
#define	DQ_CALLER_F_ATTACHED	0x00000002	/* the caller's process is
						   attached (RESOLVE, 1c) */

struct dq_event {
	uint32_t	de_version;		/* DQ_API_VERSION */
	uint32_t	de_size;		/* header + body, bytes; always a
						   multiple of 8 */
	uint32_t	de_op;			/* enum dq_op */
	uint32_t	de_flags;		/* DQ_EVENT_F_* */
	uint64_t	de_id;			/* reply token, unique per queue;
						   0 for records needing no reply */
	uint64_t	de_object;		/* object id; 0 = queue-level */
	uint64_t	de_seq;			/* per-queue sequence; a gap is a drop */
	struct dq_caller de_caller;
	struct dq_timespec de_time;		/* CLOCK_MONOTONIC */
};
#define	DQ_EVENT_F_OBSERVED	0x00000001	/* a copy on an observer queue */
#define	DQ_EVENT_F_NODATA	0x00000002	/* observer copy with the data
						   removed, lengths kept */

enum dq_op {
	DQ_OP_READ = 1,
	DQ_OP_READ_ASYNC = 2,
	DQ_OP_WRITE = 3,
	DQ_OP_WRITE_ASYNC = 4,
	DQ_OP_GETATTR = 5,
	DQ_OP_SETATTR = 6,
	DQ_OP_FSYNC = 7,
	DQ_OP_FALLOCATE = 8,
	DQ_OP_FSPACECTL = 9,
	DQ_OP_IOCTL = 10,
	DQ_OP_LOCK = 11,
	DQ_OP_UNLOCK_ALL = 12,
	DQ_OP_READDIR = 13,
	DQ_OP_RESOLVE = 14,
	DQ_OP_SET_TEXT = 15,
	DQ_OP_UNSET_TEXT = 16,
	DQ_OP_CLOSE = 17,
	DQ_OP_INTERRUPT = 18,
	DQ_OP_REPLY = 64,	/* observer record of a controller reply */
};

/*
 * Post-operation attributes (DQ_REPLY_F_POSTOP): what the controller's
 * backing file says after the operation, appended to the reply of a
 * WRITE, FALLOCATE or FSPACECTL (any of the fields), or of a READ
 * (DQ_PA_ATIME alone), as an NFS server returns wcc data.  The fields
 * dpa_valid names become the presented identity's; the kernel stamps
 * none of the times itself then.  A size below what the operation itself
 * proves (WRITE: dwr_offset + dwr_written; FALLOCATE: the range's end), a
 * time with tv_nsec outside 0..999999999, a size above OFF_MAX, an
 * unknown bit or a non-zero dpa_pad make the block ignored and counted
 * (ds2_postop_ignored, dq:::postop-attr), never an error on an operation
 * that has already happened; the kernel then stamps as without one.
 */
struct dq_postop_attr {
	uint32_t	dpa_valid;		/* DQ_PA_* */
	uint32_t	dpa_pad;
	uint64_t	dpa_size;
	struct dq_timespec dpa_mtime;
	struct dq_timespec dpa_ctime;
	struct dq_timespec dpa_atime;
	uint64_t	dpa_blocks;
};
#define	DQ_PA_SIZE		0x00000001
#define	DQ_PA_MTIME		0x00000002
#define	DQ_PA_CTIME		0x00000004
#define	DQ_PA_BLOCKS		0x00000008
#define	DQ_PA_ATIME		0x00000010
#define	DQ_PA_VALID		(DQ_PA_SIZE | DQ_PA_MTIME | DQ_PA_CTIME | \
	    DQ_PA_BLOCKS | DQ_PA_ATIME)

/* Bodies.  READ: reply is errno + up to dr_len bytes (short = EOF). */
struct dq_read_body {
	uint64_t	dr_offset;
	uint32_t	dr_len;
	uint32_t	dr_pad0;
};

/*
 * Page operations (stage 1b-ii, design 10).  READ is also what a page fault
 * posts (page-aligned dr_offset, dr_len up to the end of the file).
 * READ_ASYNC (sendfile(2) filling pages) has the READ body and is answered
 * as READ: errno + up to dr_len bytes, a short reply being the end of the
 * file.  WRITE_ASYNC (writeback of dirty pages of a shared mapping: msync,
 * fsync, the page daemon) has the WRITE body, dw_flags 0, followed by the
 * page data, and is answered as WRITE: errno + struct dq_write_reply with
 * dwr_offset == dw_offset.  Neither has a waiting requester: the caller is
 * DQ_CALLER_F_KERNEL for WRITE_ASYNC, the queue enforces a deadline on both
 * (the policy's, else kern.dq.default_deadline_ms, else 30 s: a page never
 * waits forever), and a deadline that passes after the controller read the
 * event posts INTERRUPT.  The REPLY ioctl returns before the pages are
 * finished; msync(MS_SYNC) and fsync wait for that, not for the reply.
 */
/* GETATTR: no body; reply is errno + one struct dq_ident_file. */
/* CLOSE: no body, no reply. */
struct dq_interrupt_body {		/* no reply; de_id is 0 */
	uint64_t	din_id;		/* the abandoned event */
};
struct dq_reply_record {		/* observer copy of a reply (DQ_OP_REPLY) */
	uint64_t	drr_id;
	int32_t		drr_errno;
	uint32_t	drr_len;
};

/*
 * READDIR (stage 1c-iii-b, DQ_KIND_DIR): getdirentries(2) on a served
 * directory.  drd_cookie is the descriptor's offset, which holds the
 * controller's cookie (0 at open; lseek(2) sets it).  The reply is errno,
 * or struct dq_readdir_reply followed by drdr_len bytes of struct dirent
 * records as getdirentries(2) returns them: each d_reclen a multiple of 8,
 * at least GENERIC_DIRSIZ, d_namlen 1..MAXNAMLEN, the name NUL-terminated
 * with no '/' and no inner NUL, d_type a DT_* value; drdr_len <= drd_len
 * and the sum of the records; drdr_next (the cookie after them) <=
 * OFF_MAX.  Zero bytes with drdr_eof == 0 is refused.  A malformed reply
 * is EINVAL to the controller and the event stays in flight.
 */
struct dq_readdir_body {
	uint64_t	drd_cookie;
	uint32_t	drd_len;		/* <= kern.dq.max_io - 16 */
	uint32_t	drd_pad0;
};
struct dq_readdir_reply {
	uint64_t	drdr_next;		/* the cookie after these records */
	uint32_t	drdr_eof;		/* 1: no more entries */
	uint32_t	drdr_len;		/* record bytes that follow */
};

/*
 * Stage 1b-i bodies (design 8.2, D95-D99).  A variable-length body carries
 * its payload right after the fixed part; the record (de_size) is padded to
 * a multiple of 8 with zeros and the length field counts the payload alone.
 * The reply errnos a controller may answer are allow-listed per operation
 * in dq(4); any other errno reaches the requester as EIO and is counted in
 * ds2_bad_replies.  A reply body of the wrong size is EINVAL to the
 * controller and leaves the event in flight.
 */

/* WRITE: data[dw_len] follows; reply is errno + struct dq_write_reply. */
struct dq_write_body {
	uint64_t	dw_offset;	/* advisory under DQ_WRITE_F_APPEND */
	uint32_t	dw_len;		/* data bytes, <= kern.dq.max_io */
	uint32_t	dw_flags;	/* DQ_WRITE_F_* */
};
#define	DQ_WRITE_F_APPEND	0x00000001	/* at the controller's EOF */
#define	DQ_WRITE_F_SYNC		0x00000002	/* O_SYNC: data and metadata */
#define	DQ_WRITE_F_DSYNC	0x00000004	/* O_DSYNC: data only */
struct dq_write_reply {
	uint64_t	dwr_written;	/* <= dw_len; less is a short write */
	uint64_t	dwr_offset;	/* where the bytes went; the implicit
					   file offset becomes offset+written */
};

/* SETATTR: reply is errno.  Times are realtime, like the identity's. */
struct dq_setattr_body {
	uint32_t	dsa_mask;	/* DQ_SETATTR_* */
	uint32_t	dsa_mode;	/* ALLPERMS bits */
	uint32_t	dsa_uid;
	uint32_t	dsa_gid;
	uint64_t	dsa_size;
	uint32_t	dsa_flags;	/* st_flags */
	uint32_t	dsa_priv;	/* DQ_SAPRIV_* (was dsa_pad0): RESOLVE
					   events only, 0 in object SETATTR */
	struct dq_timespec dsa_atime;
	struct dq_timespec dsa_mtime;
	struct dq_timespec dsa_birthtime;
};
#define	DQ_SETATTR_MODE		0x00000001
#define	DQ_SETATTR_UID		0x00000002
#define	DQ_SETATTR_GID		0x00000004
#define	DQ_SETATTR_SIZE		0x00000008	/* ftruncate */
#define	DQ_SETATTR_FLAGS	0x00000010	/* fchflags */
#define	DQ_SETATTR_ATIME	0x00000020
#define	DQ_SETATTR_MTIME	0x00000040
#define	DQ_SETATTR_BIRTHTIME	0x00000080
#define	DQ_SETATTR_F_UTIMES_NULL 0x00000100	/* utimes(2) with a NULL
						   argument: the times are now;
						   VWRITE sufficed */
#define	DQ_SETATTR_ATIME_NOW	0x00000200	/* RESOLVE: UTIME_NOW, the
						   kernel's time is in dsa_atime */
#define	DQ_SETATTR_MTIME_NOW	0x00000400
/*
 * dsa_priv (RESOLVE SETATTR/TRUNCATE, 1c-iii): the privileges the kernel
 * evaluated on the requester's credential for this operation only (chmod:
 * ADMIN and SETGID; chown: CHOWN and ADMIN; chflags: SYSFLAGS and ADMIN;
 * utimes: ADMIN), so the controller applies the D96 rules without
 * guessing.  A bit not evaluated is 0.
 */
#define	DQ_SAPRIV_ADMIN		0x00000001	/* PRIV_VFS_ADMIN */
#define	DQ_SAPRIV_CHOWN		0x00000002	/* PRIV_VFS_CHOWN */
#define	DQ_SAPRIV_SETGID	0x00000004	/* PRIV_VFS_SETGID */
#define	DQ_SAPRIV_SYSFLAGS	0x00000008	/* PRIV_VFS_SYSFLAGS */
#define	DQ_SAPRIV_SECURELEVEL	0x00000010	/* securelevel_gt(cred, 0) == 0
						   (chflags only) */

/* FSYNC: reply is errno. */
struct dq_fsync_body {
	uint32_t	dfs_mode;	/* the fo_fsync mode word: MNT_WAIT */
	uint32_t	dfs_pad0;
};

/* FALLOCATE: reply is errno; the kernel extends di_size to offset+len. */
struct dq_fallocate_body {
	uint64_t	dfa_offset;
	uint64_t	dfa_len;
};

/* FSPACECTL: reply is errno + struct dq_fspacectl_reply. */
struct dq_fspacectl_body {
	uint32_t	dsc_cmd;	/* SPACECTL_DEALLOC */
	uint32_t	dsc_flags;	/* SPACECTL_F_* */
	uint64_t	dsc_offset;
	uint64_t	dsc_len;
};
struct dq_fspacectl_reply {		/* the range left to do */
	uint64_t	dscr_offset;	/* dsc_offset..dsc_offset + dsc_len */
	uint64_t	dscr_len;	/* 0, or offset + len == dsc_offset +
					   dsc_len */
};

/*
 * LOCK: reply is errno, plus struct dq_lock_reply for DQ_LOCK_GETLK.
 * Types are F_RDLCK, F_WRLCK and F_UNLCK of <fcntl.h>; start and len are
 * normalised as lockf(9) normalises them (whence SEEK_SET, negative lengths
 * folded, SEEK_END resolved from di_size; len 0 = to the end of the file).
 * The owner is the process leader's pid for POSIX locks and a keyed hash
 * of the open file for flock(2) and OFD locks: stable across dup and fork,
 * distinct per open, never a kernel pointer.  pid is the owner's pid for
 * POSIX locks and -1 otherwise, as lockf(9) reports it.
 */
struct dq_lock_body {
	uint32_t	dl_op;		/* DQ_LOCK_* */
	uint32_t	dl_kind;	/* DQ_LOCK_POSIX, _FLOCK, _OFD */
	uint32_t	dl_type;	/* F_RDLCK, F_WRLCK, F_UNLCK */
	uint32_t	dl_pad0;
	int64_t		dl_start;
	int64_t		dl_len;
	uint64_t	dl_owner;
	int32_t		dl_pid;
	int32_t		dl_pad1;
};
#define	DQ_LOCK_GETLK		1
#define	DQ_LOCK_SETLK		2
#define	DQ_LOCK_SETLKW		3	/* the requester waits; no deadline */
#define	DQ_LOCK_UNLCK		4
#define	DQ_LOCK_POSIX		1
#define	DQ_LOCK_FLOCK		2
#define	DQ_LOCK_OFD		3
struct dq_lock_reply {			/* GETLK: the blocking lock, or F_UNLCK */
	uint32_t	dlr_type;
	uint32_t	dlr_pad0;
	int64_t		dlr_start;
	int64_t		dlr_len;
	int32_t		dlr_pid;
	int32_t		dlr_pad1;
};

/*
 * UNLOCK_ALL: no reply.  Every lock of this kind held by this owner on the
 * object is gone: posted by close for the POSIX locks a process owes and
 * for the flock/OFD locks of a closing open file, only when a LOCK of that
 * kind was ever posted on the object (D14).
 */
struct dq_unlock_all_body {
	uint32_t	dua_kind;
	uint32_t	dua_pad0;
	uint64_t	dua_owner;
};

/*
 * IOCTL: in[dio_len] follows: the argument of an IOC_IN command and the
 * integer of an IOC_VOID command with an int-sized argument; nothing for
 * IOC_VOID with size 0 or for IOC_OUT alone.  Reply is errno + out[len],
 * where len must be IOCPARM_LEN(cmd) when the command is IOC_OUT and errno
 * is 0, and 0 otherwise.  A command whose argument embeds pointers cannot
 * be served; the controller answers ENOTTY.
 */
struct dq_ioctl_body {
	uint64_t	dio_cmd;
	uint32_t	dio_len;
	uint32_t	dio_pad0;
};

/*
 * Replies.  dr_data points at dr_len bytes in the controller's memory;
 * the kernel copies them before taking any lock.
 */
struct dq_reply {
	uint32_t	dr_version;
	uint32_t	dr_flags;		/* DQ_REPLY_F_* (was dr_pad0, zero) */
	uint64_t	dr_id;
	int32_t		dr_errno;		/* 0 or an errno */
	uint32_t	dr_len;			/* <= kern.dq.max_io */
	const void	*dr_data;
};

/*
 * DQ_REPLY_F_POSTOP: the last sizeof(struct dq_postop_attr) bytes of
 * dr_data are post-operation attributes; the rest is the reply as without
 * them.  For a READ, WRITE, FALLOCATE or FSPACECTL that succeeded only
 * (EINVAL otherwise, and for a reply shorter than the block).
 */
#define	DQ_REPLY_F_POSTOP	0x00000001
#define	DQ_REPLY_F_VALID	(DQ_REPLY_F_POSTOP)

/* MINT refusal reasons, written through dm_reasonp with EINVAL. */
enum dq_reason {
	DQ_REASON_NONE = 0,
	DQ_REASON_VERSION,	/* dm_version */
	DQ_REASON_KIND,		/* kind not served */
	DQ_REASON_PATH,		/* di_path not absolute/normalized/terminated */
	DQ_REASON_MNTNAME,	/* ds_mntonname not a component prefix */
	DQ_REASON_TYPE,		/* S_IFMT bits do not match the kind */
	DQ_REASON_SETID,	/* S_ISUID or S_ISGID present */
	DQ_REASON_BLKSIZE,	/* di_blksize < PAGE_SIZE */
	DQ_REASON_STRING,	/* a statfs string not NUL-terminated */
	DQ_REASON_SIZE,		/* di_size > OFF_MAX */
	DQ_REASON_TIME,		/* tv_nsec out of range */
	DQ_REASON_MODE,		/* bits outside S_IFMT|07777 */
	DQ_REASON_POLICY,	/* a policy value outside its range or this stage */
	DQ_REASON_RIGHTS,	/* dp_rights_version / cap_rights version */
	DQ_REASON_PATHCONF,	/* dp_valid names an unknown slot */
	DQ_REASON_NAMEMAX,	/* ds_namemax == 0 */
	DQ_REASON_FLAGS,	/* dm_flags unknown, or DQ_MINT_F_WRITE without
				   dp_write == DQ_EVENT */
	DQ_REASON_TARGET,	/* a bad symlink target or REAL path (1c-iii) */
};

/*
 * MINT flags.  DQ_MINT_F_WRITE installs the descriptor FREAD|FWRITE (as
 * open(2) fixes the access mode at open) and needs dp_write == DQ_EVENT;
 * without it the descriptor is read-only whatever the policy says.
 */
#define	DQ_MINT_F_WRITE		0x00000001
#define	DQ_MINT_F_CREATED	0x00000002	/* RESOLVE FD only: this open
						   created the file (O_CREAT in
						   drs_mode); DAC is not checked */

struct dq_mint_args {
	uint32_t	dm_version;		/* DQ_API_VERSION */
	uint32_t	dm_kind;		/* enum dq_kind */
	struct dq_ident_file dm_ident;
	struct dq_policy dm_policy;
	uint64_t	dm_object;		/* out: object id */
	int32_t		dm_fd;			/* out: the minted descriptor */
	uint32_t	dm_flags;		/* DQ_MINT_F_* (was dm_pad0, zero) */
	int32_t		*dm_reasonp;		/* optional: receives enum dq_reason
						   on EINVAL (an ioctl that fails
						   copies its argument back to
						   nobody), DQ_REASON_NONE on 0 */
};

#define	DQ_OBS_F_DATA		0x00000001	/* copies carry data bodies */
struct dq_observer_args {
	uint32_t	do_version;
	uint32_t	do_flags;		/* DQ_OBS_F_* */
	int32_t		do_fd;			/* out */
	int32_t		do_pad0;
};

struct dq_object_args {
	uint32_t	doa_version;
	uint32_t	doa_pad0;
	uint64_t	doa_object;
};

struct dq_setident_args {
	uint32_t	dsi_version;
	uint32_t	dsi_pad0;
	uint64_t	dsi_object;
	struct dq_ident_file dsi_ident;
};

struct dq_setpolicy_args {
	uint32_t	dsp_version;
	uint32_t	dsp_pad0;
	uint64_t	dsp_object;
	struct dq_policy dsp_policy;
};

struct dq_stats {
	uint32_t	ds_version;
	uint32_t	ds_pad0;
	uint64_t	ds_queue_id;		/* kernel-wide, never reused */
	uint64_t	ds_events_posted;
	uint64_t	ds_events_delivered;
	uint64_t	ds_events_dropped;	/* queue full; each left a seq gap */
	uint64_t	ds_replies;
	uint64_t	ds_late_replies;	/* replies to unknown ids */
	uint64_t	ds_interrupts;
	uint64_t	ds_deadline_misses;
	uint64_t	ds_objects_live;
	uint64_t	ds_objects_total;
	uint64_t	ds_objects_revoked;
	uint64_t	ds_inflight;		/* delivered, awaiting reply */
	uint64_t	ds_queue_depth;
	uint64_t	ds_queue_current;
	uint64_t	ds_queue_highwater;
	uint64_t	ds_queue_bytes;
	uint64_t	ds_observers;
};

/*
 * GET_STATS2 (B8): dq_stats is frozen (its size is in the command word);
 * everything new goes here.  ds2_size is written by the kernel.
 */
struct dq_stats2 {
	uint32_t	ds2_size;		/* sizeof(struct dq_stats2) */
	uint32_t	ds2_pad0;
	uint64_t	ds2_queue_id;
	uint64_t	ds2_events_posted;
	uint64_t	ds2_events_delivered;
	uint64_t	ds2_events_dropped;
	uint64_t	ds2_replies;
	uint64_t	ds2_late_replies;
	uint64_t	ds2_interrupts;
	uint64_t	ds2_deadline_misses;
	uint64_t	ds2_objects_live;
	uint64_t	ds2_objects_total;
	uint64_t	ds2_objects_revoked;
	uint64_t	ds2_inflight;
	uint64_t	ds2_queue_depth;
	uint64_t	ds2_queue_current;
	uint64_t	ds2_queue_highwater;
	uint64_t	ds2_queue_bytes;
	uint64_t	ds2_observers;
	uint64_t	ds2_locks;		/* LOCK events posted */
	uint64_t	ds2_pushes;		/* PUSH ioctls applied */
	uint64_t	ds2_bad_replies;	/* reply errno outside the per-op
						   allow-list: the requester got EIO */
	uint64_t	ds2_async_pending;	/* READ_ASYNC/WRITE_ASYNC posted
						   and not yet completed (now) */
	uint64_t	ds2_async_bytes;	/* their bytes, bounded by
						   kern.dq.max_inflight_bytes (now) */
	uint64_t	ds2_async_deadlines;	/* async events failed by their
						   deadline (total) */
	uint64_t	ds2_overdepth;		/* UNLOCK_ALL/INTERRUPT queued past
						   the depth (never dropped) */
	uint64_t	ds2_close_dropped;	/* dirty pages dropped after the
						   last close because their
						   write-back failed or expired */
	uint64_t	ds2_task_drops;		/* INTERRUPT records the completion
						   task could not allocate (the
						   late reply gets ESRCH) */
	uint64_t	ds2_resolves;		/* RESOLVE events posted (1c) */
	uint64_t	ds2_resolve_pass;	/* answered PASS */
	uint64_t	ds2_resolve_kernel;	/* class 2/3 consultations */
	uint64_t	ds2_resolve_unmarked;	/* unmarked user-space lookups
						   (a ledger failure; dqpass
						   asserts 0) */
	uint64_t	ds2_resolve_failclosed;	/* refused without an answer:
						   dead binding, deadline, held
						   lock */
	uint64_t	ds2_attached;		/* ATTACHes committed */
	uint64_t	ds2_resolve_served;	/* answered FD, ATTR, LINK or OK
						   (1c-iii) */
	uint64_t	ds2_resolve_retired;	/* served objects retired before
						   a descriptor was installed */
	uint64_t	ds2_resolve_exdev;	/* refused EXDEV with no event
						   (1c-iii-b/c) */
	uint64_t	ds2_readdirs;		/* READDIR events (1c-iii-b) */
	uint64_t	ds2_postop_ignored;	/* post-operation attribute blocks
						   ignored (DQ_REPLY_F_POSTOP) */
	uint64_t	ds2_reserved[2];
};

/*
 * PUSH: the controller tells the kernel something about an object.
 * DQ_PUSH_NOTIFY_VNODE raises dp_note on the object's EVFILT_VNODE knotes
 * for what happened elsewhere (NOTE_DELETE, LINK, RENAME; WRITE, EXTEND,
 * ATTRIB caused by others, SETIDENT carrying the attributes themselves).
 * NOTE_REVOKE belongs to the REVOKE ioctl.  DQ_PUSH_INVALIDATE drops the
 * object's clean cached pages in [dp_offset, dp_offset + dp_len) (dp_len 0:
 * to the end), so the next access faults or reads them again; dirty pages
 * of shared mappings the controller has not yet seen survive and are
 * written back (OBJPR_CLEANONLY).  dp_note is 0 for it and the range is 0
 * for NOTIFY_VNODE.  The 24-byte stage 1b-i layout (no range) is still
 * accepted under its own command word for NOTIFY_VNODE.
 */
struct dq_push_args {
	uint32_t	dp_version;
	uint32_t	dp_op;			/* DQ_PUSH_* */
	uint64_t	dp_object;
	uint32_t	dp_note;		/* NOTE_* of <sys/event.h> */
	uint32_t	dp_pad0;
	uint64_t	dp_offset;		/* INVALIDATE: page-rounded out */
	uint64_t	dp_len;			/* INVALIDATE: 0 = to the end */
};
#define	DQ_PUSH_NOTIFY_VNODE	1
#define	DQ_PUSH_INVALIDATE	2

/*
 * Ioctls on the queue, group 'j' (the only unused letter near 'q'/'Q').
 * 10 is ATTACH (stage 1c); 11 is reserved for REGISTER_NAME.
 */
#define	DQ_IOC_MINT		_IOWR('j', 1, struct dq_mint_args)
#define	DQ_IOC_MINT_OBSERVER	_IOWR('j', 2, struct dq_observer_args)
#define	DQ_IOC_REPLY		_IOW('j', 3, struct dq_reply)
#define	DQ_IOC_REVOKE		_IOW('j', 4, struct dq_object_args)
#define	DQ_IOC_SETIDENT		_IOW('j', 5, struct dq_setident_args)
#define	DQ_IOC_SETPOLICY	_IOW('j', 6, struct dq_setpolicy_args)
#define	DQ_IOC_GET_STATS	_IOR('j', 7, struct dq_stats)
#define	DQ_IOC_SET_QUEUE_DEPTH	_IOW('j', 8, uint32_t)
#define	DQ_IOC_PUSH		_IOW('j', 9, struct dq_push_args)
#define	DQ_IOC_GET_STATS2	_IOR('j', 12, struct dq_stats2)

/*
 * Stage 1c: resolution (design 11).  A process attached to a queue
 * (DQ_IOC_ATTACH) has every name it resolves posted as a queue-level
 * RESOLVE event (de_object 0) before the lookup runs; the controller
 * answers PASS (the lookup proceeds unchanged) or an errno (the syscall
 * fails with it).  Series 1c-iii adds the served answers below; series
 * 1c-iii-b makes a served directory (DQ_KIND_DIR) a lookup start for the
 * processes attached to its queue: such a lookup is posted with
 * DQ_START_SERVED and drs_start = the directory's object, and never
 * accepts PASS.
 *
 * RESOLVE body: struct dq_resolve_body, then drs_pathlen bytes of path,
 * NUL, drs_path2len bytes of the second path (RENAME, LINK), NUL,
 * drs_startpathlen bytes of the start hint, NUL, drs_startpath2len bytes
 * of the second path's start hint, NUL, drs_rootpathlen bytes of the
 * process's served root's di_path (1c-iii-c), NUL; the record is padded
 * to a multiple of 8.  drs_root is that root's object (0 when the root is
 * real; then the fifth string is empty): a controller resolves absolute
 * names, absolute symbolic link targets and ".." at the root against it,
 * as chroot(2) does.  Every length excludes its NUL.  The second path has
 * its own start kind (drs_start2_kind, from its own dirfd and leading
 * '/'; 0 when there is no second path); a hint is present only when
 * DQ_RF_STARTPATH_VALID (path) or DQ_RF_STARTPATH2_VALID (path2) is set.
 * drs_rflags describe the first path's lookup; the second path's own
 * lookup flags are not known when the event is posted.
 */
struct dq_resolve_body {
	uint32_t	drs_op;			/* DQ_ROP_* */
	uint32_t	drs_rflags;		/* DQ_RF_* */
	uint32_t	drs_start_kind;		/* DQ_START_* */
	uint32_t	drs_flags;		/* DQ_RCLASS_* (D127) */
	uint64_t	drs_start;		/* served start object; 0 */
	uint32_t	drs_mode;		/* open flags, mkdir mode, ... */
	uint32_t	drs_syscall;		/* the requester's syscall number */
	uint64_t	drs_dev;		/* mknod dev */
	uint32_t	drs_start2_kind;
	uint32_t	drs_pathlen;
	uint32_t	drs_path2len;
	uint32_t	drs_startpathlen;
	uint64_t	drs_start2;
	uint64_t	drs_object;		/* a served fd argument */
	int32_t		drs_domain;		/* sockets (1c-ii) */
	int32_t		drs_type;
	int32_t		drs_protocol;
	uint32_t	drs_cmode;		/* creation mode after the umask
						   (was drs_pad0, 1c-iii) */
	uint32_t	drs_startpath2len;	/* path2's start hint */
	uint32_t	drs_accept;		/* DQ_RACCEPT(DQ_RESOLVE_*): the
						   answers this event takes (was
						   drs_pad1, 1c-iii) */
	uint64_t	drs_root;		/* the served root's object, or
						   0 (D184) */
	uint32_t	drs_rootpathlen;	/* its path, the 5th string */
	uint32_t	drs_pad2;		/* 0 */
};
#define	DQ_RACCEPT(k)		(1u << (k))

/* Operations (drs_op). */
#define	DQ_ROP_OPEN		1
#define	DQ_ROP_STAT		2
#define	DQ_ROP_ACCESS		3
#define	DQ_ROP_READLINK		4
#define	DQ_ROP_REALPATH		5
#define	DQ_ROP_GETFH		6
#define	DQ_ROP_UNLINK		7
#define	DQ_ROP_RMDIR		8
#define	DQ_ROP_RENAME		9
#define	DQ_ROP_LINK		10
#define	DQ_ROP_SYMLINK		11
#define	DQ_ROP_MKDIR		12
#define	DQ_ROP_MKNOD		13
#define	DQ_ROP_MKFIFO		14
#define	DQ_ROP_SETATTR		15
#define	DQ_ROP_TRUNCATE		16
#define	DQ_ROP_EXEC		17
#define	DQ_ROP_EXEC_INTERP	18
#define	DQ_ROP_CONNECT		19
#define	DQ_ROP_BIND		20
#define	DQ_ROP_SOCKET		21
#define	DQ_ROP_SOCKETPAIR	22
#define	DQ_ROP_CHDIR		23
#define	DQ_ROP_CHROOT		24
#define	DQ_ROP_INOTIFY		25
#define	DQ_ROP_XATTR		26
#define	DQ_ROP_ACL		27
#define	DQ_ROP_REVOKE		28
#define	DQ_ROP_INTERNAL		29
#define	DQ_ROP_MAX		29

/* Lookup flags (drs_rflags). */
#define	DQ_RF_USER		0x00000001	/* user-origin (class 1) */
#define	DQ_RF_STRICTREL		0x00000002	/* capability-mode relative */
#define	DQ_RF_BENEATH		0x00000004	/* O_RESOLVE_BENEATH */
#define	DQ_RF_RINROOT		0x00000008	/* resolve in a scoped root */
#define	DQ_RF_NOFOLLOW		0x00000010
#define	DQ_RF_EMPTYPATH		0x00000020
#define	DQ_RF_FSEARCH		0x00000040
#define	DQ_RF_NOSYMLINKS	0x00000080
#define	DQ_RF_NOMAGICLINKS	0x00000100
#define	DQ_RF_NOXDEV		0x00000200
#define	DQ_RF_TRAILINGSLASH	0x00000400
#define	DQ_RF_STARTPATH_VALID	0x00000800	/* the start hint is present */
#define	DQ_RF_SYMLINK_RESTART	0x00001000	/* re-consulted at an absolute
						   symlink (1c-iii) */
#define	DQ_RF_ABSTRACT		0x00002000	/* AF_UNIX abstract name (1c-ii) */
#define	DQ_RF_KCONSUMER		0x00004000	/* the object goes to the kernel
						   (class 2) */
#define	DQ_RF_STARTPATH2_VALID	0x00008000	/* path2's start hint is present */
#define	DQ_RF_STRICTREL2	0x00010000	/* path2's start is capability-
						   mode or limited-rights
						   relative (1c-iii-b) */
#define	DQ_RF_BENEATH2		0x00020000	/* path2's start descriptor is
						   FD_RESOLVE_BENEATH */

/* Start kinds (drs_start_kind). */
#define	DQ_START_SERVED		1	/* drs_start names it (1c-iii) */
#define	DQ_START_REAL_CWD	2
#define	DQ_START_REAL_ROOT	3	/* absolute path */
#define	DQ_START_REAL_DIRFD	4
#define	DQ_START_NONE		5	/* sockets */
#define	DQ_START_REAL_SYMDIR	6	/* a relative symlink's directory: a
					   re-consultation of a PASSed lookup
					   (DQ_RF_SYMLINK_RESTART); the hint
					   is that directory (1c-iii-b) */

/* Lookup classes (drs_flags, D127). */
#define	DQ_RCLASS_USER		1	/* the requester's own path */
#define	DQ_RCLASS_KCONSUMER	2	/* a user path for a kernel consumer */
#define	DQ_RCLASS_KERNEL	3	/* a kernel-origin lookup (EXEC_INTERP) */

/*
 * The reply body: struct dq_resolve_reply, then the kind's payload (1c-iii).
 * The kernel publishes the kinds an event accepts in drs_accept; any other
 * kind is EINVAL to the controller and the event stays in flight.
 *
 *	PASS, OK	the reply alone (8 bytes)
 *	FD		+ struct dq_resolve_mint (3976 bytes): a served object
 *			minted at the reply, installed in the requester
 *	ATTR		+ struct dq_resolve_attr (3904): attributes only
 *	LINK		+ struct dq_resolve_attr (S_ISLNK, di_size == drt_len)
 *			+ struct dq_resolve_target (<= 4936)
 *	REAL		+ struct dq_resolve_target (1c-iii-b): an absolute,
 *			normalized real path the lookup continues from
 *	FD (SYMLINK)	+ struct dq_resolve_mint + struct dq_resolve_target
 *			(the link's target, drt_len == di_size; <= 5008)
 *
 * A target is drt_len bytes, a NUL, and zeros to the next 8-byte boundary;
 * no inner NUL.  An errno reply carries no body.  The reply may be up to
 * MAX(kern.dq.max_io, DQ_RESOLVE_REPLY_MAX) bytes.
 */
struct dq_resolve_reply {
	uint32_t	drr_kind;		/* DQ_RESOLVE_* */
	uint32_t	drr_pad0;
};
#define	DQ_RESOLVE_PASS		1
#define	DQ_RESOLVE_FD		2	/* + struct dq_resolve_mint (iii) */
#define	DQ_RESOLVE_ATTR		3	/* (iii) */
#define	DQ_RESOLVE_LINK		4	/* (iii) */
#define	DQ_RESOLVE_OK		5	/* (iii) */
#define	DQ_RESOLVE_REAL		6	/* + struct dq_resolve_target (iii-b) */
#define	DQ_RESOLVE_SWAP		7	/* + struct dq_resolve_swap */
#define	DQ_RESOLVE_REPLY_MAX	8192

/*
 * SWAP: the open file behind drw_fd, a descriptor of the replying
 * process, becomes the result of the program's open(2).  The program then
 * holds the real open file; no later operation on it reaches the queue.
 * Offered (drs_accept) for DQ_ROP_OPEN where FD is.
 *
 * The file must be a vnode file opened for this answer and referenced by
 * nothing else (EBUSY); a regular file or a directory, or any vnode when
 * both it and the request are O_PATH (EOPNOTSUPP otherwise); with the
 * request's access mode and status flags (EFTYPE), opened without
 * O_TRUNC: the kernel truncates for an O_TRUNC request once the program's
 * own write permission is checked.  The entry must be transferable
 * (ENOTCAPABLE); the rights installed are the entry's, limited by its
 * transfer ceiling.  A refused reply consumes nothing and leaves the
 * event in flight.  After a successful reply the replying process closes
 * drw_fd.
 *
 * At completion the program's thread checks its own MAC and DAC
 * permission on the object, as its own open would have; a refusal there
 * is the program's errno and is not reported to the replying process.
 *
 * No pointers: the layout is the same for every controller ABI.
 */
struct dq_resolve_swap {
	int32_t		drw_fd;
	uint32_t	drw_flags;		/* DQ_SWAP_F_* */
	uint64_t	drw_spare[3];		/* 0 */
};
#define	DQ_SWAP_F_NOXFER	0x00000001	/* install as CAP_XFER_NONE */
/*			0x00000002	   reserved */
#define	DQ_SWAP_F_CREATED	0x00000004	/* the file did not exist and
						   was created for this O_CREAT
						   request (EINVAL without
						   O_CREAT): the program's
						   access check is skipped, and
						   the file not truncated, if it
						   is a regular file the
						   program's effective uid owns
						   with no immutable or
						   append-only flag; otherwise
						   the flag is ignored */
#define	DQ_SWAP_F_VALID		(DQ_SWAP_F_NOXFER | DQ_SWAP_F_CREATED)

struct dq_resolve_attr {		/* ATTR, LINK */
	uint32_t	dra_flags;		/* 0 */
	uint32_t	dra_pad0;
	struct dq_ident_file dra_ident;		/* any S_IFMT; set-id bits allowed */
};

struct dq_resolve_target {		/* LINK, REAL */
	uint32_t	drt_len;		/* 1..DQ_PATH_MAX-1, NUL excluded */
	uint32_t	drt_pad0;
	char		drt_target[];		/* drt_len bytes, NUL, zero pad */
};

/*
 * FD: the object is minted at the reply.  *drm_objectp receives its id
 * and *drm_reasonp DQ_REASON_NONE (or the refusal reason with EINVAL)
 * before the object is linked; on any later failure of the reply
 * *drm_objectp is undefined (zeroed where possible) and the id is never
 * used.  Native LP64 controllers only (the pointers are native).
 */
struct dq_resolve_mint {		/* stage 1c-iii */
	uint32_t	drm_kind;		/* DQ_KIND_FILE, _DIR, _SYMLINK */
	uint32_t	drm_flags;		/* DQ_MINT_F_WRITE, _CREATED */
	struct dq_ident_file drm_ident;
	struct dq_policy drm_policy;
	uint64_t	*drm_objectp;		/* out, before linking */
	int32_t		*drm_reasonp;		/* optional */
};

/*
 * ATTACH (D138): attach the process named by the process descriptor
 * da_procfd to this queue.  It must be a child that has not exec'd, not
 * already attached, not sharing its pwddesc or descriptor table, holding
 * no descriptor of this queue, and debuggable by the caller.  ATTACH sets
 * P2_NO_NEW_PRIVS on it (D150).  da_rootfd and da_cwdfd (1c-iii-c, D169)
 * are -1 or live served directories (DQ_KIND_DIR) of this queue held by
 * the caller, which become the process's served root and cwd (EINVAL for
 * another descriptor, ENOTDIR for another kind, EIO once revoked); the
 * attachment holds the controller's struct file itself.  With a root and
 * no cwd the cwd is the root (EIO if the root's reference count is
 * exhausted); a cwd must be the root or a served directory under it
 * (EINVAL).  Open directories (D184): with a root, the child's table is
 * held to chroot(2)'s rule exactly (kern.chroot_allow_open_directories,
 * EPERM), so with the default of 1 an unchrooted child keeps its open
 * real directories.  DQ_ATTACH_F_NODIRS, with or without a root, refuses
 * any open real directory instead (EBUSY).  Other da_flags bits are
 * EINVAL.
 */
#define	DQ_ATTACH_F_NODIRS	0x00000001
struct dq_attach_args {
	uint32_t	da_version;
	int32_t		da_procfd;
	int32_t		da_rootfd;		/* -1 or a served DIR */
	int32_t		da_cwdfd;		/* -1 or a served DIR */
	uint32_t	da_flags;		/* DQ_ATTACH_F_* */
	uint32_t	da_pad0;
};
#define	DQ_IOC_ATTACH		_IOW('j', 10, struct dq_attach_args)

#ifdef _KERNEL
/* The stage 1b-i PUSH layout, before the INVALIDATE range (24 bytes). */
struct dq_push_args_v1 {
	uint32_t	dp_version;
	uint32_t	dp_op;
	uint64_t	dp_object;
	uint32_t	dp_note;
	uint32_t	dp_pad0;
};
#define	DQ_IOC_PUSH_V1		_IOW('j', 9, struct dq_push_args_v1)
_Static_assert(sizeof(struct dq_push_args_v1) == 24, "dq_push_args_v1");
#endif

/* Layout is part of the ABI. */
_Static_assert(sizeof(struct dq_timespec) == 16, "dq_timespec");
_Static_assert(sizeof(struct dq_statfs) == 2192, "dq_statfs");
_Static_assert(sizeof(struct dq_pathconf) == 520, "dq_pathconf");
_Static_assert(sizeof(struct dq_ident_file) == 3888, "dq_ident_file");
_Static_assert(sizeof(struct dq_policy) == 56, "dq_policy");
_Static_assert(sizeof(struct dq_caller) == 48, "dq_caller");
_Static_assert(sizeof(struct dq_event) == 104, "dq_event");
_Static_assert(sizeof(struct dq_read_body) == 16, "dq_read_body");
_Static_assert(sizeof(struct dq_postop_attr) == 72, "dq_postop_attr");
_Static_assert(sizeof(struct dq_resolve_swap) == 32, "dq_resolve_swap");
_Static_assert(sizeof(struct dq_reply) == 32, "dq_reply");
_Static_assert(sizeof(struct dq_mint_args) == 3976, "dq_mint_args");
_Static_assert(sizeof(struct dq_stats) == 144, "dq_stats");
_Static_assert(sizeof(struct dq_interrupt_body) == 8, "dq_interrupt_body");
_Static_assert(sizeof(struct dq_reply_record) == 16, "dq_reply_record");
_Static_assert(sizeof(struct dq_write_body) == 16, "dq_write_body");
_Static_assert(sizeof(struct dq_write_reply) == 16, "dq_write_reply");
_Static_assert(sizeof(struct dq_setattr_body) == 80, "dq_setattr_body");
_Static_assert(sizeof(struct dq_fsync_body) == 8, "dq_fsync_body");
_Static_assert(sizeof(struct dq_fallocate_body) == 16, "dq_fallocate_body");
_Static_assert(sizeof(struct dq_fspacectl_body) == 24, "dq_fspacectl_body");
_Static_assert(sizeof(struct dq_fspacectl_reply) == 16, "dq_fspacectl_reply");
_Static_assert(sizeof(struct dq_lock_body) == 48, "dq_lock_body");
_Static_assert(sizeof(struct dq_lock_reply) == 32, "dq_lock_reply");
_Static_assert(sizeof(struct dq_unlock_all_body) == 16, "dq_unlock_all_body");
_Static_assert(sizeof(struct dq_ioctl_body) == 16, "dq_ioctl_body");
_Static_assert(sizeof(struct dq_stats2) == 320, "dq_stats2");
_Static_assert(sizeof(struct dq_push_args) == 40, "dq_push_args");
_Static_assert(sizeof(struct dq_resolve_body) == 112, "dq_resolve_body");
_Static_assert(__offsetof(struct dq_resolve_body, drs_root) == 96 &&
    __offsetof(struct dq_resolve_body, drs_rootpathlen) == 104 &&
    __offsetof(struct dq_resolve_body, drs_pad2) == 108,
    "dq_resolve_body: the 1c-iii-c served root is appended");
_Static_assert(__offsetof(struct dq_resolve_body, drs_cmode) == 84 &&
    __offsetof(struct dq_resolve_body, drs_startpath2len) == 88 &&
    __offsetof(struct dq_resolve_body, drs_accept) == 92,
    "dq_resolve_body: the 1c-i additions are appended");
_Static_assert(__offsetof(struct dq_setattr_body, dsa_priv) == 28,
    "dq_setattr_body: dsa_priv");
_Static_assert(sizeof(struct dq_resolve_attr) == 3896, "dq_resolve_attr");
_Static_assert(sizeof(struct dq_resolve_target) == 8, "dq_resolve_target");
_Static_assert(sizeof(struct dq_resolve_reply) + sizeof(struct dq_resolve_mint) +
    sizeof(struct dq_resolve_target) + DQ_PATH_MAX <= DQ_RESOLVE_REPLY_MAX,
    "an FD reply fits");
_Static_assert(sizeof(struct dq_resolve_reply) + sizeof(struct dq_resolve_attr) +
    sizeof(struct dq_resolve_target) + DQ_PATH_MAX <= DQ_RESOLVE_REPLY_MAX,
    "a LINK reply fits");
_Static_assert(sizeof(struct dq_resolve_reply) == 8, "dq_resolve_reply");
_Static_assert(sizeof(struct dq_resolve_mint) == 3968, "dq_resolve_mint");
_Static_assert(sizeof(struct dq_attach_args) == 24, "dq_attach_args");
_Static_assert(sizeof(struct dq_readdir_body) == 16, "dq_readdir_body");
_Static_assert(sizeof(struct dq_readdir_reply) == 16, "dq_readdir_reply");
_Static_assert(sizeof(struct dq_resolve_reply) + sizeof(struct dq_resolve_mint) +
    sizeof(struct dq_resolve_target) + DQ_PATH_MAX == 5008,
    "the largest FD (SYMLINK) reply");

#pragma pop_macro("dr_data")
#pragma pop_macro("di_rdev")

#endif /* !_DEV_DQ_DQ_H_ */

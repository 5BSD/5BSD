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

#define	DQ_API_VERSION		1

#define	DQ_PATH_MAX		1024	/* presented path, NUL included */
#define	DQ_MNAMELEN		1024	/* == MNAMELEN, sys/mount.h */
#define	DQ_MFSNAMELEN		16	/* == MFSNAMELEN */

/*
 * Kinds (design 7.3).  Stage 1a serves DQ_KIND_FILE; the others are
 * reserved numbers so the ABI does not move when they arrive.
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
	DQ_CACHE_NONE = 0,	/* no page cache (stage 1b); fstat posts
				   only under DQ_EVENTS_GETATTR */
	DQ_CACHE_ATTR = 1,	/* attributes from the identity */
	DQ_CACHE_DATA = 2,	/* attributes and pages (stage 1b) */
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
	uint32_t	dp_mmap_shared_write;	/* DQ_DENY | DQ_ALLOW */
	uint32_t	dp_lock;		/* DQ_EVENT */
	uint32_t	dp_ioctl;		/* DQ_DENY | DQ_EVENT */
	int32_t		dp_deadline_ms;		/* DQ_DEADLINE_DEFAULT, 0 = none, or ms */
	uint32_t	dp_events;		/* DQ_EVENTS_* */
	uint32_t	dp_rights_version;	/* CAP_RIGHTS_VERSION dp_rights was built with */
	uint32_t	dp_pad0;
	cap_rights_t	dp_rights;		/* rights of the minted descriptor */
};

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

/* Bodies.  READ: reply is errno + up to dr_len bytes (short = EOF). */
struct dq_read_body {
	uint64_t	dr_offset;
	uint32_t	dr_len;
	uint32_t	dr_pad0;
};
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
	uint32_t	dsa_pad0;
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
	uint64_t	dscr_offset;	/* >= dsc_offset */
	uint64_t	dscr_len;	/* offset + len == dsc_offset + dsc_len */
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
	uint32_t	dr_pad0;
	uint64_t	dr_id;
	int32_t		dr_errno;		/* 0 or an errno */
	uint32_t	dr_len;			/* <= kern.dq.max_io */
	const void	*dr_data;
};

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
};

/*
 * MINT flags.  DQ_MINT_F_WRITE installs the descriptor FREAD|FWRITE (as
 * open(2) fixes the access mode at open) and needs dp_write == DQ_EVENT;
 * without it the descriptor is read-only whatever the policy says.
 */
#define	DQ_MINT_F_WRITE		0x00000001

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
	uint64_t	ds2_async_pending;	/* stage 1b-ii; 0 */
	uint64_t	ds2_async_bytes;	/* stage 1b-ii; 0 */
	uint64_t	ds2_async_deadlines;	/* stage 1b-ii; 0 */
	uint64_t	ds2_overdepth;		/* UNLOCK_ALL/INTERRUPT queued past
						   the depth (never dropped) */
	uint64_t	ds2_reserved[15];
};

/*
 * PUSH: the controller tells the kernel something about an object.
 * DQ_PUSH_NOTIFY_VNODE raises dp_note on the object's EVFILT_VNODE knotes
 * for what happened elsewhere (NOTE_DELETE, LINK, RENAME; WRITE, EXTEND,
 * ATTRIB caused by others, SETIDENT carrying the attributes themselves).
 * NOTE_REVOKE belongs to the REVOKE ioctl; DQ_PUSH_INVALIDATE is 1b-ii.
 */
struct dq_push_args {
	uint32_t	dp_version;
	uint32_t	dp_op;			/* DQ_PUSH_* */
	uint64_t	dp_object;
	uint32_t	dp_note;		/* NOTE_* of <sys/event.h> */
	uint32_t	dp_pad0;
};
#define	DQ_PUSH_NOTIFY_VNODE	1
#define	DQ_PUSH_INVALIDATE	2	/* reserved: stage 1b-ii */

/*
 * Ioctls on the queue, group 'j' (the only unused letter near 'q'/'Q').
 * 10-11 are reserved for ATTACH and REGISTER_NAME (later stages).
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

/* Layout is part of the ABI. */
_Static_assert(sizeof(struct dq_timespec) == 16, "dq_timespec");
_Static_assert(sizeof(struct dq_statfs) == 2192, "dq_statfs");
_Static_assert(sizeof(struct dq_pathconf) == 520, "dq_pathconf");
_Static_assert(sizeof(struct dq_ident_file) == 3888, "dq_ident_file");
_Static_assert(sizeof(struct dq_policy) == 56, "dq_policy");
_Static_assert(sizeof(struct dq_caller) == 48, "dq_caller");
_Static_assert(sizeof(struct dq_event) == 104, "dq_event");
_Static_assert(sizeof(struct dq_read_body) == 16, "dq_read_body");
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
_Static_assert(sizeof(struct dq_push_args) == 24, "dq_push_args");

#endif /* !_DEV_DQ_DQ_H_ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * libdq: the controller side of a DescriptorQueue (dq(4)).
 *
 * A controller opens a queue, mints descriptors that present an identity of
 * its choosing, reads the events the kernel posts for operations on them
 * and answers by id.  Every function here is a thin, errno-preserving
 * wrapper over the ioctls and read(2) of <dev/dq/dq.h>; the kernel's own
 * errnos pass through unchanged and libdq(3) lists them per function.
 * dq_serve_file() is the one routine with policy of its own: it answers
 * every stage 1b-i event from a backing descriptor.
 */

#ifndef _LIBDQ_H_
#define	_LIBDQ_H_

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <stdint.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_observe_proto.h>

/* The device node; one open is one queue. */
#define	DQ_DEVICE		"/dev/dq"
/* The mac_capability device dq_observe_connect() opens. */
#define	DQ_MAC_CAPABILITY_DEVICE	"/dev/mac_capability"

/*
 * The fo_fsync mode word a DQ_OP_FSYNC body carries (dfs_mode): the
 * kernel's FO_FSYNC_* of <sys/file.h>, which userland does not see.
 */
#define	DQ_FSYNC_FULL		0	/* fsync(2): data and metadata */
#define	DQ_FSYNC_DATA		1	/* fdatasync(2): data only */
#define	DQ_FSYNC_FS		2	/* the whole filesystem (Linux syncfs) */

__BEGIN_DECLS

/*
 * Queue
 */

/*
 * Open a queue: O_RDWR|O_CLOEXEC|O_CLOFORK, so a forked requester inherits
 * the minted descriptors and not the queue (D86: the EDEADLK rule applies to
 * any process whose table holds the queue).  Returns the queue fd or -1.
 */
int	dq_open(void);

/* Statistics of a queue or of an observer descriptor. */
int	dq_get_stats(int fd, struct dq_stats *st);
/* The extended counters (DQ_IOC_GET_STATS2); ds2_size is the kernel's. */
int	dq_get_stats2(int fd, struct dq_stats2 *st);

/* Lower the queue's depth; 1..kern.dq.queue_depth, never above it. */
int	dq_set_queue_depth(int q, uint32_t depth);

/*
 * Identity and policy
 */

/*
 * The default policy the kernel accepts (D87): no served writes (the object
 * is read-only), locks as events, no ioctls, no exec, no shared writable
 * mappings, the default deadline, no optional events, and CAP_ALL_RIGHTS
 * because that is what open(2) returns.  A controller that serves writes
 * sets dp_write = DQ_EVENT and mints with DQ_MINT_F_WRITE.
 */
void	dq_policy_default(struct dq_policy *pol);

/*
 * Fill an identity from a real file: path (absolute and normalized, as the
 * kernel validates it), the stat and statfs the caller took, and the
 * pathconf answers of fd (fpathconf(2) is asked for every dq_pc_names[]
 * entry; a name the filesystem refuses is left out of dp_valid, so the
 * served descriptor refuses it too).  fd may be -1 to present no pathconf.
 * di_blksize is floored at the page size, as the kernel requires.
 */
int	dq_ident_from_stat(struct dq_ident_file *ident, const char *path,
	    const struct stat *st, const struct statfs *sfs, int fd);

/*
 * Objects
 */

/*
 * Mint a DQ_KIND_FILE object.  On success *object is its id and *fd the
 * descriptor installed in the caller (O_CLOEXEC, dp_rights, not
 * transferable over SCM_RIGHTS).  On EINVAL *reason names the refused
 * field (enum dq_reason); reason may be NULL.  dq_mint_file() mints a
 * read-only descriptor; dq_mint_file_flags() passes dm_flags, where
 * DQ_MINT_F_WRITE installs it FREAD|FWRITE and needs dp_write == DQ_EVENT
 * (else EINVAL with DQ_REASON_FLAGS).
 */
int	dq_mint_file(int q, const struct dq_ident_file *ident,
	    const struct dq_policy *pol, uint64_t *object, int *fd,
	    int *reason);
int	dq_mint_file_flags(int q, const struct dq_ident_file *ident,
	    const struct dq_policy *pol, uint32_t flags, uint64_t *object,
	    int *fd, int *reason);

/* Mint an observer descriptor of the queue (DQ_OBS_F_*).  Returns the fd. */
int	dq_mint_observer(int q, uint32_t flags);

int	dq_revoke(int q, uint64_t object);
int	dq_set_ident(int q, uint64_t object, const struct dq_ident_file *ident);
int	dq_set_policy(int q, uint64_t object, const struct dq_policy *pol);

/*
 * Raise an EVFILT_VNODE note on an object's knotes for what happened
 * elsewhere (DQ_IOC_PUSH, DQ_PUSH_NOTIFY_VNODE): NOTE_DELETE, LINK,
 * RENAME, WRITE, EXTEND, ATTRIB, OPEN, CLOSE, CLOSE_WRITE, READ.  0 and
 * NOTE_REVOKE are EINVAL (revoke is dq_revoke()).
 */
int	dq_push_vnode_note(int q, uint64_t object, uint32_t note);

/*
 * Drop the object's clean cached pages in [offset, offset + len) (len 0:
 * to the end; the range is rounded out to pages) so the next fault or
 * DQ_CACHE_DATA read asks again (DQ_IOC_PUSH, DQ_PUSH_INVALIDATE).  Dirty
 * pages of a shared mapping the controller has not yet seen survive and
 * are written back.  ESRCH for an unknown object.
 */
int	dq_push_invalidate(int q, uint64_t object, uint64_t offset,
	    uint64_t len);

/*
 * Events
 */

/*
 * One read(2) of whole records into buf; *got is the byte count (0 only
 * when an observer's queue has gone away).  EINVAL for len below one
 * header, ENOBUFS when the next record does not fit an empty buffer,
 * EAGAIN on an empty non-blocking queue, ENXIO once the queue closes.
 */
int	dq_read_events(int fd, void *buf, size_t len, ssize_t *got);

/*
 * Walk the records of a buffer.  Each returns NULL when no further whole
 * record (de_size at least a header, a multiple of 8, within len) follows.
 */
const struct dq_event *dq_event_first(const void *buf, size_t len);
const struct dq_event *dq_event_next(const void *buf, size_t len,
	    const struct dq_event *ev);

/* The body that follows the header; *bodylen may be NULL. */
const void *dq_event_body(const struct dq_event *ev, size_t *bodylen);

/*
 * Typed body accessors.  Each checks de_op and that the record holds the
 * fixed body (and, for WRITE and IOCTL, the payload its length field
 * counts; the record is padded to 8 bytes, so a payload is shorter than
 * what follows the fixed part).  They return 0 with the pointers set, or
 * -1 with errno EINVAL for a record of another operation or one too short
 * for its body.  Output pointers other than the body may be NULL.  For an
 * observer's DQ_OP_REPLY record *data is NULL when the record carries no
 * bytes (DQ_EVENT_F_NODATA, or a reply without a body) and *len is the
 * reply's length either way.
 */
int	dq_event_read(const struct dq_event *ev,
	    const struct dq_read_body **body);
int	dq_event_write(const struct dq_event *ev,
	    const struct dq_write_body **body, const void **data, size_t *len);
int	dq_event_setattr(const struct dq_event *ev,
	    const struct dq_setattr_body **body);
int	dq_event_fsync(const struct dq_event *ev,
	    const struct dq_fsync_body **body);
int	dq_event_fallocate(const struct dq_event *ev,
	    const struct dq_fallocate_body **body);
int	dq_event_fspacectl(const struct dq_event *ev,
	    const struct dq_fspacectl_body **body);
int	dq_event_lock(const struct dq_event *ev,
	    const struct dq_lock_body **body);
int	dq_event_unlock_all(const struct dq_event *ev,
	    const struct dq_unlock_all_body **body);
int	dq_event_ioctl(const struct dq_event *ev,
	    const struct dq_ioctl_body **body, const void **in, size_t *len);
int	dq_event_interrupt(const struct dq_event *ev,
	    const struct dq_interrupt_body **body);
int	dq_event_reply_record(const struct dq_event *ev,
	    const struct dq_reply_record **rr, const void **data, size_t *len);

/*
 * Answer an event: error is 0 or an errno; data/len the reply body the
 * operation defines (READ: up to the asked length, short means EOF;
 * GETATTR: exactly one struct dq_ident_file when error is 0; the stage
 * 1b-i bodies have the typed helpers below).  The kernel validates the
 * body against the operation (EINVAL, the event stays in flight) and maps
 * an errno outside the operation's allow-list to EIO for the requester.
 */
int	dq_reply(int q, uint64_t id, int error, const void *data, size_t len);

/*
 * The per-operation reply bodies.  dq_reply_write(): the count taken (at
 * most dw_len) and the offset the bytes went to (for DQ_WRITE_F_APPEND the
 * controller's end of file; the implicit file offset becomes
 * offset+written).  dq_reply_fspacectl(): the range left undone, with
 * offset >= dsc_offset and offset+len == dsc_offset+dsc_len (0 remaining:
 * dsc_offset+dsc_len, 0).  dq_reply_lock(): a DQ_LOCK_GETLK answer, the
 * blocking lock or dlr_type F_UNLCK.  dq_reply_ioctl(): out[len] with len
 * IOCPARM_LEN(cmd) for a successful IOC_OUT command and 0 otherwise.
 */
int	dq_reply_write(int q, uint64_t id, uint64_t written, uint64_t offset);
int	dq_reply_fspacectl(int q, uint64_t id, uint64_t offset, uint64_t len);
int	dq_reply_lock(int q, uint64_t id, const struct dq_lock_reply *lr);
int	dq_reply_ioctl(int q, uint64_t id, int error, const void *out,
	    size_t len);

/*
 * The kernel's per-operation errno allow-list (dq(4)): true when a reply
 * of error to op reaches the requester as itself, false when the kernel
 * turns it into EIO and counts it in ds2_bad_replies.  READ and GETATTR
 * accept any errno.  For DQ_OP_RESOLVE it is true when some resolve
 * operation allows error; dq_resolve_errno_allowed() answers for one
 * (DQ_ROP_*): socket(2) and socketpair(2) have a list of their own.
 */
int	dq_reply_errno_allowed(uint32_t op, int error);
int	dq_resolve_errno_allowed(uint32_t rop, int error);

/*
 * Resolution (stage 1c-i)
 */

/*
 * Attach the process named by the process descriptor procfd to the queue
 * (DQ_IOC_ATTACH): from then on every name it resolves is posted as a
 * RESOLVE event and waits for PASS or an errno.  The target must be a
 * pdfork(2)ed child that has not exec'd, shares neither its pwddesc nor
 * its descriptor table, holds no descriptor of the queue and is
 * debuggable by the caller (EBUSY, ESRCH, EPERM, EINVAL otherwise, see
 * dq(4)).  It gets P2_NO_NEW_PRIVS and its descendants stay attached.
 */
int	dq_attach(int q, int procfd);

/*
 * A RESOLVE event's fixed body and its four strings (the path, the second
 * path of RENAME/LINK, the start hint, the second path's start hint),
 * each NUL-terminated and possibly empty; checked to lie within the
 * record.  Output pointers may be NULL.  -1 with EINVAL for another
 * operation or a malformed record.
 */
int	dq_event_resolve(const struct dq_event *ev,
	    const struct dq_resolve_body **body, const char **path,
	    const char **path2, const char **startpath,
	    const char **startpath2);

/* Answer a RESOLVE: PASS (the lookup proceeds) or an errno (it fails). */
int	dq_reply_resolve_pass(int q, uint64_t id);
int	dq_reply_resolve_errno(int q, uint64_t id, int error);

/*
 * Served answers (stage 1c-iii-a).  The kernel publishes the kinds an
 * event takes in drs_accept: dq_resolve_accepts() tests one
 * (DQ_RESOLVE_*); a kind outside the set is EINVAL and the event stays in
 * flight.  dq_resolve_errno_allowed_ev() is the allow-list for this
 * event (ENOTCAPABLE only on a STRICTREL, BENEATH or RINROOT lookup).
 * dq_event_resolve_ext() also returns the SETATTR/TRUNCATE body that
 * follows the strings (NULL for other operations).
 *
 * dq_reply_resolve_fd(): a served object minted at the reply (kind
 * DQ_KIND_FILE, flags DQ_MINT_F_WRITE and DQ_MINT_F_CREATED, the latter
 * only for an O_CREAT open that created the file); *objectp receives its
 * id before the kernel links it, and is undefined if the reply then fails
 * (zeroed where possible); reasonp (may be NULL) gets the dq_reason of an
 * EINVAL.  Every id a successful reply returned ends exactly once: CLOSE,
 * when the policy subscribes, comes after the requester's last close or
 * when the answer was refused after the reply.
 * dq_reply_resolve_attr(): attributes only (stat, access, realpath); any
 * file type, set-id bits allowed.  dq_reply_resolve_link(): readlink, an
 * S_IFLNK identity whose di_size is strlen(target).  dq_reply_resolve_ok():
 * the controller performed a mutating operation.
 */
int	dq_resolve_accepts(const struct dq_resolve_body *rb, uint32_t kind);
int	dq_resolve_errno_allowed_ev(const struct dq_resolve_body *rb,
	    int error);
int	dq_event_resolve_ext(const struct dq_event *ev,
	    const struct dq_resolve_body **body, const char **path,
	    const char **path2, const char **startpath,
	    const char **startpath2, const struct dq_setattr_body **setattr);
int	dq_reply_resolve_fd(int q, uint64_t id, uint32_t kind, uint32_t flags,
	    const struct dq_ident_file *ident, const struct dq_policy *pol,
	    uint64_t *objectp, int32_t *reasonp);
int	dq_reply_resolve_attr(int q, uint64_t id,
	    const struct dq_ident_file *ident);
int	dq_reply_resolve_link(int q, uint64_t id,
	    const struct dq_ident_file *ident, const char *target);
int	dq_reply_resolve_ok(int q, uint64_t id);

/*
 * Served directories and REAL (stage 1c-iii-b).
 *
 * dq_mint_dir(): a served directory (DQ_KIND_DIR) minted in the
 * controller, as dq_mint_file() mints a file; given to an attached child
 * by inheritance it is a lookup start inside the attachment (EDEADLK
 * outside it).  dq_policy_default_dir(): the policy a directory or a
 * symbolic link admits (nothing written, executed or mapped shared).
 * dq_ident_from_lstat(): the identity of name relative to dirfd, not
 * following a final symbolic link, presented as presented.
 * dq_reply_resolve_fd() also mints DQ_KIND_DIR; a DQ_KIND_SYMLINK object
 * carries its target: dq_reply_resolve_fd_symlink() (an O_PATH |
 * O_NOFOLLOW open, lchmod and the like; di_size becomes strlen(target)).
 * dq_reply_resolve_real(): the name is the real absolute normalized path
 * (never under STRICTREL, BENEATH, RINROOT, NOSYMLINKS, NOMAGICLINKS or
 * NOXDEV, nor for rename and link); the lookup continues there.
 *
 * READDIR: dq_event_readdir() returns the body (drd_cookie, drd_len);
 * dq_dirent_add() appends a struct dirent record to a buffer;
 * dq_reply_readdir() answers the records, the cookie after them and the
 * end-of-directory flag.
 */
void	dq_policy_default_dir(struct dq_policy *pol);
int	dq_mint_dir(int q, const struct dq_ident_file *ident,
	    const struct dq_policy *pol, uint64_t *object, int *fd,
	    int *reason);
int	dq_ident_from_lstat(struct dq_ident_file *ident,
	    const char *presented, int dirfd, const char *name);
int	dq_reply_resolve_fd_symlink(int q, uint64_t id,
	    const struct dq_ident_file *ident, const struct dq_policy *pol,
	    const char *target, uint64_t *objectp, int32_t *reasonp);
int	dq_reply_resolve_real(int q, uint64_t id, const char *path);
int	dq_event_readdir(const struct dq_event *ev,
	    const struct dq_readdir_body **body);
int	dq_dirent_add(void *buf, size_t cap, size_t *lenp, uint64_t fileno,
	    uint64_t off, uint8_t type, const char *name);
int	dq_reply_readdir(int q, uint64_t id, uint64_t next, int eof,
	    const void *records, size_t len);

/*
 * One read(2) and one handler call per record.  The handler returns 0 to
 * continue or nonzero to stop; dq_dispatch returns the records handed
 * over, or -1 when the read failed.  The buffer holds the largest record
 * the kernel posts (a WRITE of kern.dq.max_io bytes).
 */
typedef int (*dq_handler_t)(int q, const struct dq_event *ev,
	    const void *body, size_t bodylen, void *arg);
int	dq_dispatch(int q, dq_handler_t handler, void *arg);

/*
 * Serving a backing file
 */

/*
 * dq_serve_file() answers one event from a real file open on backing_fd:
 * READ by pread(2), GETATTR from fstat(2)/fstatfs(2)/fpathconf(2), WRITE by
 * pwrite(2) (an append goes to the backing file's end and reports that
 * offset; O_SYNC/O_DSYNC flags are honoured with fsync(2)/fdatasync(2)),
 * SETATTR by the masked fchmod/fchown/ftruncate/futimens/fchflags calls,
 * FSYNC by fsync or fdatasync, FALLOCATE by posix_fallocate(2), FSPACECTL
 * by fspacectl(2), LOCK and UNLOCK_ALL by OFD locks on a separate open of
 * the backing file per owner so distinct owners are distinct lockers (a
 * POSIX owner per identity, a flock or OFD owner per object), IOCTL by
 * the caller's handler or ENOTTY.  CLOSE, INTERRUPT and
 * UNLOCK_ALL need no reply and update the lock state.  A backing errno the
 * operation's allow-list refuses is sent as EIO.
 *
 * The lock state (one per queue, shared by all its objects) holds the
 * owner opens and the threads blocked in a DQ_LOCK_SETLKW; without it
 * every LOCK is answered ENOLCK.  A GETLK by an owner that holds nothing
 * asks through a temporary open; a SETLKW granted after its requester gave
 * up (the reply answers ESRCH) is unlocked again.
 * so_ident, when set, is the controller's copy of the identity: GETATTR is
 * answered from it refreshed, and after a successful SETATTR (and, under
 * DQ_SERVE_F_SYNC_IDENT, after WRITE, FALLOCATE and FSPACECTL) it is
 * refreshed from the backing file and sent with dq_set_ident(), so the
 * presented mtime, ctime and blocks are the backing file's.  Without it
 * GETATTR is answered EIO.
 *
 * The ioctl handler receives the command, its input and a buffer of
 * IOCPARM_LEN(cmd) bytes for an IOC_OUT command; it returns 0 after
 * filling the output, or an errno.  Pointer-embedding commands cannot be
 * served: refuse them with ENOTTY.
 *
 * Returns 0 once the record is answered (or needed no answer), -1 with the
 * errno of the failing reply ioctl.  An operation it does not know is
 * answered EIO; a record of another queue's ABI (too short for its body)
 * is answered EIO too.
 */
struct dq_serve_state;

typedef int (*dq_ioctl_handler_t)(int backing_fd,
	    const struct dq_ioctl_body *ib, const void *in, void *out,
	    size_t outlen, void *arg);

/*
 * A RESOLVE policy: return 0 to PASS the lookup or an errno to fail it.
 * Called with the body and its strings (dq_event_resolve).
 */
typedef int (*dq_resolve_handler_t)(const struct dq_event *ev,
	    const struct dq_resolve_body *rb, const char *path,
	    const char *path2, void *arg);

struct dq_serve_opts {
	struct dq_serve_state *so_state;	/* lock owners; may be NULL */
	struct dq_ident_file *so_ident;		/* identity copy; may be NULL */
	dq_ioctl_handler_t so_ioctl;		/* NULL: ENOTTY */
	void		*so_arg;
	uint32_t	 so_flags;		/* DQ_SERVE_F_* */
	uint32_t	 so_pad0;
	dq_resolve_handler_t so_resolve;	/* NULL: PASS (see below) */
	void		*so_resolve_arg;
};
#define	DQ_SERVE_F_SYNC_IDENT	0x00000001	/* SETIDENT after every
						   mutating operation */
#define	DQ_SERVE_F_RESOLVE_STRICT 0x00000002	/* M2: a consultation that is
						   not the requester's own path
						   (class 2, 3) is PASSed only
						   for EXEC_INTERP, EACCES
						   otherwise */

struct dq_serve_state *dq_serve_state_create(void);
/* Cancels the blocked SETLKW threads and closes the owner opens. */
void	dq_serve_state_destroy(struct dq_serve_state *st);
/* Lock owners currently held open (for tests and diagnostics). */
int	dq_serve_state_owners(const struct dq_serve_state *st);

int	dq_serve_file(int q, const struct dq_event *ev, const void *body,
	    size_t bodylen, int backing_fd, const struct dq_serve_opts *opts);

/*
 * dq_serve_tree() (D173), stage 1c-iii-a mode: the tree open at rootfd is
 * presented at the real-namespace directory prefix to the processes
 * attached to q, whose starts all stay real.  A RESOLVE naming something
 * under prefix (its path made absolute with the start hint, normalized,
 * symlinks in the backing tree followed) is answered from the backing
 * tree: open FD of a regular file (O_CREAT and O_EXCL performed here,
 * O_TRUNC by the kernel through the object; DQ_MINT_F_CREATED when this
 * open created it), stat, access and
 * realpath ATTR, readlink LINK, chmod/chown/utimes/chflags/truncate FD of
 * the target (the kernel applies D96 and posts the object's SETATTR),
 * mkdir, mknod, mkfifo, unlink, rmdir, symlink, rename and link OK after
 * performing them (a rename or link across the prefix is EXDEV), exec
 * EACCES, extended attributes and ACLs EOPNOTSUPP.  Directories and the
 * other non-regular objects, names outside prefix, the kernel's own
 * lookups and restricted lookups (no served kind in drs_accept) are
 * PASSed, as is a symlink leading out of the prefix answered EACCES.
 * di_path is the real-namespace name the process resolved (under prefix),
 * never the backing path; ds_mntonname is "/".  Object events are served
 * by dq_serve_file() on the backing file; CLOSE closes it.  Parent
 * directory permissions are not checked by the controller (the kernel's
 * DAC applies to FD answers).  DQ_TREE_F_WRITE serves writes; without it
 * every mutation (creation, removal, rename, link, truncation, a write or
 * O_TRUNC open) is EROFS.  A refused FD answer is followed by EIO, so no
 * event stays in flight.  Renames honour AT_RENAME_NOREPLACE (drs_mode).
 */
/*
 * Stage 1c-iii-b mode (DQ_TREE_F_SERVED): dq_tree_root() mints the tree's
 * root as a served directory (presented at prefix) and returns the
 * controller's descriptor of it; a child that inherits it and is attached
 * to q starts lookups there.  Lookups from a served start are answered as
 * above but never PASS: directories are served (FD of a DIR; READDIR
 * from the backing directory, cookies its offsets), a final symbolic link
 * opened O_PATH | O_NOFOLLOW is a served SYMLINK (O_NOFOLLOW alone is
 * EMLINK), and device, FIFO and socket nodes, AF_UNIX connect and bind,
 * names outside prefix (also through a backing symbolic link) and the
 * operations the tree does not serve are answered REAL with the real path
 * when the event takes it (the backing path under prefix), PASS from a
 * real start, ENOTCAPABLE under a restricted lookup.
 * DQ_TREE_F_EXEC_REAL answers exec REAL of the backing binary.
 */
struct dq_tree;
#define	DQ_TREE_F_WRITE		0x00000001
#define	DQ_TREE_F_SERVED	0x00000002	/* 1c-iii-b mode */
#define	DQ_TREE_F_EXEC_REAL	0x00000004
struct dq_tree *dq_tree_create(int q, int rootfd, const char *prefix,
	    uint32_t flags);
int	dq_tree_root(struct dq_tree *t, int *fdp, uint64_t *objectp);
void	dq_tree_destroy(struct dq_tree *t);
int	dq_tree_objects(const struct dq_tree *t);
int	dq_serve_tree(struct dq_tree *t, const struct dq_event *ev,
	    const void *body, size_t bodylen);

/*
 * The dq.observe service (D90)
 */

/* Connect to dq.observe through /dev/mac_capability.  Returns the fd. */
int	dq_observe_connect(void);

/*
 * List queues (or the objects of one queue) starting at index first into
 * buf[nbuf]; *count is how many were filled, *total how many exist (either
 * may be NULL).
 */
int	dq_observe_list_queues(int svc, uint64_t first,
	    struct dqo_queue_info *buf, size_t nbuf, size_t *count,
	    uint64_t *total);
int	dq_observe_list_objects(int svc, uint64_t queue, uint64_t first,
	    struct dqo_object_info *buf, size_t nbuf, size_t *count,
	    uint64_t *total);

/* A metadata-only observer of queue.  Returns the observer fd. */
int	dq_observe_subscribe(int svc, uint64_t queue);

__END_DECLS

#endif /* !_LIBDQ_H_ */

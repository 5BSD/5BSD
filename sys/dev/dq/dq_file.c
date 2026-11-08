/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: the dq fileops for DQ_KIND_FILE.
 *
 * A served file is a struct file with this table and no vnode.  Every
 * answer a regular file gives from its vnode this table gives from the
 * presented identity or from the controller: fstat, fstatfs, fpathconf,
 * F_KINFO and realpath read the identity; read and write post READ and
 * WRITE events; truncate, fchmod, fchown, futimens and fchflags post
 * SETATTR after the permission rules a vnode applies (D96); fsync,
 * fallocate, fspacectl, the record locks and (under dp_ioctl = EVENT) the
 * ioctls a regular file does not answer locally are events too.  Seek,
 * poll, kqueue and the ioctls a regular file answers from its vnode's
 * state alone stay local.  A descriptor minted without DQ_MINT_F_WRITE is
 * read-only: the mutating operations answer what a read-only descriptor on
 * a real file answers (D87), and dq(4) lists each one.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/rangelock.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/sf_buf.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <crypto/siphash/siphash.h>

#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <dev/mac_capability/mac_capability_label.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_kern.h>
#include <dev/dq/dq_var.h>

_Static_assert(DQ_MNAMELEN == MNAMELEN, "DQ_MNAMELEN");
_Static_assert(DQ_MFSNAMELEN == MFSNAMELEN, "DQ_MFSNAMELEN");

/*
 * O_PATH (D133, plan 4.7): a served file opened O_PATH answers as
 * path_fileops does: no data, no mode or owner change through it, no
 * mapping, POLLNVAL, kevent only when FKQALLOWED, no locks but the POSIX
 * release of a close; stat, statfs, pathconf, kinfo, fcntl, fsync,
 * setattr, ACLs and extended attributes as on the object.
 */
#define	DQ_OPATH(fp)	(((fp)->f_flag & O_PATH) != 0)

static fo_rdwr_t	dq_read;
static fo_rdwr_t	dq_write;
static fo_truncate_t	dq_truncate;
static fo_ioctl_t	dq_ioctl;
static fo_poll_t	dq_poll;
static fo_kqfilter_t	dq_kqfilter;
static fo_stat_t	dq_stat;
static fo_close_t	dq_close;
static fo_chmod_t	dq_chmod;
static fo_chown_t	dq_chown;
static fo_seek_t	dq_seek;
static fo_fill_kinfo_t	dq_fill_kinfo;
static fo_mmap_t	dq_mmap;
static fo_add_seals_t	dq_add_seals;
static fo_get_seals_t	dq_get_seals;
static fo_fallocate_t	dq_fallocate;
static fo_fspacectl_t	dq_fspacectl;
static fo_pathconf_t	dq_pathconf;
static fo_statfs_t	dq_statfs;
static fo_fsync_t	dq_fsync;
static fo_setattr_t	dq_setattr;
static fo_fadvise_t	dq_fadvise;
static fo_readdir_t	dq_readdir;
static fo_acl_t		dq_acl;
static fo_extattr_t	dq_extattr;
static fo_fcntl_t	dq_fcntl;
static fo_advlock_t	dq_advlock;
static fo_sendfile_t	dq_sendfile;

/*
 * DFLAG_FLOCK | DFLAG_RECLOCK: locks are LOCK events (D98).
 * DFLAG_PRIVWRITE: a private mapping is copy-on-write in an anonymous
 * shadow and needs no write right on the descriptor (D103).
 */
const struct fileops dq_fileops = {
	.fo_read = dq_read,
	.fo_write = dq_write,
	.fo_truncate = dq_truncate,
	.fo_ioctl = dq_ioctl,
	.fo_poll = dq_poll,
	.fo_kqfilter = dq_kqfilter,
	.fo_stat = dq_stat,
	.fo_close = dq_close,
	.fo_chmod = dq_chmod,
	.fo_chown = dq_chown,
	.fo_sendfile = dq_sendfile,
	.fo_seek = dq_seek,
	.fo_fill_kinfo = dq_fill_kinfo,
	.fo_mmap = dq_mmap,
	.fo_add_seals = dq_add_seals,
	.fo_get_seals = dq_get_seals,
	.fo_fallocate = dq_fallocate,
	.fo_fspacectl = dq_fspacectl,
	.fo_cmp = file_kcmp_generic,
	.fo_pathconf = dq_pathconf,
	.fo_statfs = dq_statfs,
	.fo_fsync = dq_fsync,
	.fo_setattr = dq_setattr,
	.fo_fadvise = dq_fadvise,
	.fo_readdir = dq_readdir,
	.fo_acl = dq_acl,
	.fo_extattr = dq_extattr,
	.fo_fcntl = dq_fcntl,
	.fo_advlock = dq_advlock,
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE | DFLAG_FLOCK |
	    DFLAG_RECLOCK | DFLAG_PRIVWRITE,
};

/*
 * Lock owners for flock(2) and OFD locks (D98, B6): a keyed hash of the
 * struct file pointer, as fusefs derives them, so the id is stable across
 * dup and fork, distinct per open and discloses no kernel address.  The
 * key is drawn once, at device initialisation.
 */
static uint8_t dq_lock_owner_key[SIPHASH_KEY_LENGTH];

void
dq_file_init(void)
{

	arc4random_buf(dq_lock_owner_key, sizeof(dq_lock_owner_key));
}

static uint64_t
dq_lock_owner(void *id, int flags)
{
	SIPHASH_CTX ctx;

	if ((flags & (F_FLOCK | F_OFD)) != 0)
		return (SipHashX(&ctx, 2, 4, dq_lock_owner_key, &id, sizeof(id)));
	/* The leader: what closef, fdclearlocks and fcntl pass as id. */
	return ((uint64_t)((struct proc *)id)->p_pid);
}

/*
 * Identity and policy validation (design 7.4, dq(4)).  Each refusal names
 * its reason so a controller can fix what it presented.
 */

static bool
dq_path_normalized(const char *path, size_t len)
{
	size_t i, start;

	if (len == 0 || path[0] != '/')
		return (false);
	if (len == 1)
		return (true);
	if (path[len - 1] == '/')
		return (false);
	for (i = 1; i <= len; i++) {
		if (i == len || path[i] == '/') {
			/* The component [start, i). */
			for (start = i; start > 0 && path[start - 1] != '/';
			    start--)
				;
			if (i == start)
				return (false);	/* empty: "//" */
			if (path[start] == '.' && (i - start == 1 ||
			    (i - start == 2 && path[start + 1] == '.')))
				return (false);
		}
	}
	return (true);
}

static bool
dq_string_terminated(const char *s, size_t size)
{

	return (strnlen(s, size) < size);
}

static bool
dq_time_valid(const struct dq_timespec *ts)
{

	return (ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L);
}

int
dq_ident_validate(u_int kind, const struct dq_ident_file *di, int *reason)
{
	const struct dq_statfs *ds;
	size_t mlen;
	mode_t type;

	*reason = DQ_REASON_NONE;
	switch (kind) {
	case DQ_KIND_FILE:
		type = S_IFREG;
		break;
	case DQ_KIND_ANY:
		/*
		 * A RESOLVE ATTR or LINK identity (D160): attributes only, no
		 * object, so any file type and the set-id bits are allowed
		 * (I3 governs objects) and the block size is what the
		 * presented node has.
		 */
		type = di->di_mode & S_IFMT;
		switch (type) {
		case S_IFREG: case S_IFDIR: case S_IFLNK: case S_IFIFO:
		case S_IFSOCK: case S_IFCHR: case S_IFBLK: case S_IFWHT:
			break;
		default:
			*reason = DQ_REASON_TYPE;
			return (EINVAL);
		}
		break;
	default:
		*reason = DQ_REASON_KIND;
		return (EINVAL);
	}
	if (di->di_pathlen == 0 || di->di_pathlen >= DQ_PATH_MAX ||
	    di->di_path[di->di_pathlen] != '\0' ||
	    strnlen(di->di_path, DQ_PATH_MAX) != di->di_pathlen ||
	    !dq_path_normalized(di->di_path, di->di_pathlen)) {
		*reason = DQ_REASON_PATH;
		return (EINVAL);
	}
	ds = &di->di_statfs;
	if (!dq_string_terminated(ds->ds_mntonname, DQ_MNAMELEN) ||
	    !dq_string_terminated(ds->ds_mntfromname, DQ_MNAMELEN) ||
	    !dq_string_terminated(ds->ds_fstypename, DQ_MFSNAMELEN)) {
		*reason = DQ_REASON_STRING;
		return (EINVAL);
	}
	mlen = strlen(ds->ds_mntonname);
	if (mlen == 0 || ds->ds_mntonname[0] != '/' ||
	    strncmp(ds->ds_mntonname, di->di_path, mlen) != 0 ||
	    (mlen > 1 && di->di_pathlen > mlen && di->di_path[mlen] != '/') ||
	    (mlen > 1 && ds->ds_mntonname[mlen - 1] == '/')) {
		*reason = DQ_REASON_MNTNAME;
		return (EINVAL);
	}
	if (ds->ds_namemax == 0) {
		*reason = DQ_REASON_NAMEMAX;
		return (EINVAL);
	}
	if ((di->di_mode & ~(S_IFMT | ALLPERMS)) != 0) {
		*reason = DQ_REASON_MODE;
		return (EINVAL);
	}
	if ((di->di_mode & S_IFMT) != type) {
		*reason = DQ_REASON_TYPE;
		return (EINVAL);
	}
	if (kind != DQ_KIND_ANY && (di->di_mode & (S_ISUID | S_ISGID)) != 0) {
		*reason = DQ_REASON_SETID;
		return (EINVAL);
	}
	if (kind != DQ_KIND_ANY && di->di_blksize < PAGE_SIZE) {
		*reason = DQ_REASON_BLKSIZE;
		return (EINVAL);
	}
	if (di->di_size > OFF_MAX) {
		*reason = DQ_REASON_SIZE;
		return (EINVAL);
	}
	if (!dq_time_valid(&di->di_atime) || !dq_time_valid(&di->di_mtime) ||
	    !dq_time_valid(&di->di_ctime) || !dq_time_valid(&di->di_birthtime)) {
		*reason = DQ_REASON_TIME;
		return (EINVAL);
	}
	if (DQ_PC_NCOUNT < 64 &&
	    (di->di_pathconf.dp_valid & ~(((uint64_t)1 << DQ_PC_NCOUNT) - 1)) != 0) {
		*reason = DQ_REASON_PATHCONF;
		return (EINVAL);
	}
	if (di->di_pad0 != 0 || ds->ds_pad0 != 0 || ds->ds_pad1 != 0) {
		*reason = DQ_REASON_VERSION;
		return (EINVAL);
	}
	return (0);
}

/*
 * The set stage 1b accepts (plan section 3): writes, locks and ioctls as
 * events, the data cache, shared writable mappings when writes are served
 * (N13), no exec; GETATTR and CLOSE are the optional events.
 */
int
dq_policy_validate(const struct dq_policy *pol, int *reason)
{

	*reason = DQ_REASON_POLICY;
	if (pol->dp_cache != DQ_CACHE_NONE && pol->dp_cache != DQ_CACHE_ATTR &&
	    pol->dp_cache != DQ_CACHE_DATA)
		return (EINVAL);
	if (pol->dp_write != DQ_DENY && pol->dp_write != DQ_EVENT)
		return (EINVAL);
	if (pol->dp_mmap_shared_write != DQ_DENY &&
	    (pol->dp_mmap_shared_write != DQ_ALLOW ||
	    pol->dp_write != DQ_EVENT))
		return (EINVAL);
	if (pol->dp_exec != DQ_DENY || pol->dp_lock != DQ_EVENT)
		return (EINVAL);
	if (pol->dp_ioctl != DQ_DENY && pol->dp_ioctl != DQ_EVENT)
		return (EINVAL);
	if (pol->dp_deadline_ms < DQ_DEADLINE_DEFAULT)
		return (EINVAL);
	if ((pol->dp_events & ~(DQ_EVENTS_GETATTR | DQ_EVENTS_CLOSE)) != 0)
		return (EINVAL);
	if (pol->dp_pad0 != 0)
		return (EINVAL);
	*reason = DQ_REASON_RIGHTS;
	if (pol->dp_rights_version != CAP_RIGHTS_VERSION ||
	    !cap_rights_is_valid(&pol->dp_rights))
		return (EINVAL);
	*reason = DQ_REASON_NONE;
	return (0);
}

/*
 * Install the minted descriptor in the controller (D86): the rights the
 * policy names, O_CLOEXEC, and CAP_XFER_NONE so it cannot be sent; it
 * reaches a requester by inheritance until RESOLVE installs it (1c).  The
 * access mode is fixed here as open(2) fixes it (D95).
 */
int
dq_file_install(struct thread *td, struct dq_object *o,
    const struct dq_policy *pol, u_int mflags, int *fdp)
{
	struct fdinstall_prop prop = { .fip_xfer_state = CAP_XFER_NONE };
	struct filecaps fcaps;
	struct file *fp;
	int error;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		/*
		 * No file ever referenced it; retire it here, post no CLOSE,
		 * and drop its pager object as dq_close would.
		 */
		DQO_LOCK(o);
		o->o_policy.dp_events &= ~DQ_EVENTS_CLOSE;
		DQO_UNLOCK(o);
		dq_object_vm_teardown(o, true);
		dq_object_retire(o, td);
		return (error);
	}
	dq_object_hold(o);	/* the struct file's reference */
	DQO_LOCK(o);
	o->o_fp = fp;
	DQO_UNLOCK(o);
	/*
	 * The policy's rights, with the fcntl and ioctl sets a
	 * cap_rights_limit(2) to those rights would leave (kern_cap_rights_limit):
	 * everything when the right is held, nothing when it is not.
	 */
	filecaps_fill(&fcaps);
	fcaps.fc_rights = pol->dp_rights;
	if (!cap_rights_is_set(&fcaps.fc_rights, CAP_FCNTL))
		fcaps.fc_fcntls = 0;
	if (!cap_rights_is_set(&fcaps.fc_rights, CAP_IOCTL))
		fcaps.fc_nioctls = 0;
	finit(fp, FREAD | ((mflags & DQ_MINT_F_WRITE) != 0 ? FWRITE : 0),
	    DTYPE_DQ, o, &dq_fileops);
	error = finstall_prop(td, fp, fdp, O_CLOEXEC, &fcaps, &prop);
	if (error != 0) {
		filecaps_free(&fcaps);
		DQO_LOCK(o);
		o->o_policy.dp_events &= ~DQ_EVENTS_CLOSE;
		DQO_UNLOCK(o);
	} else {
		/* NOTE_OPEN reaches the identity's other objects (B7). */
		dq_object_knote_siblings(o, NOTE_OPEN);
	}
	/* On failure this is the last file reference: dq_close retires it. */
	fdrop(fp, td);
	return (error);
}

/*
 * Bind a RESOLVE FD answer to a new file in the requester's thread (D159):
 * f_cred is the requester's, the object's creation reference becomes the
 * file's, and the file is returned referenced, not installed.  A file
 * that cannot be allocated (ENFILE) or an object revoked, or whose queue
 * closed, since the reply (EIO) retires the object (D171).  fflags are
 * the open flags (FREAD, FWRITE, O_PATH, ...).
 */
static int	dq_object_usable(struct dq_object *o);

int
dq_file_bind(struct thread *td, struct dq_object *o, int fflags,
    struct file **fpp)
{
	struct file *fp;
	int error;

	*fpp = NULL;
	/* debug.dq.fail_bind_enfile: falloc's ENFILE, for the tests. */
	error = dq_fault_inject(&dq_fail_bind_enfile) ? ENFILE :
	    falloc_noinstall(td, &fp);
	if (error != 0) {
		dq_object_retire_unbound(o, td);
		return (error);
	}
	if (dq_object_usable(o) != 0) {
		falloc_abort(td, fp);
		dq_object_retire_unbound(o, td);
		return (EIO);
	}
	DQO_LOCK(o);
	o->o_fp = fp;
	DQO_UNLOCK(o);
	finit(fp, fflags & FMASK, DTYPE_DQ, o, &dq_fileops);
	/* NOTE_OPEN reaches the identity's other objects (B7). */
	dq_object_knote_siblings(o, NOTE_OPEN);
	*fpp = fp;
	return (0);
}

/* Fire the object's EVFILT knotes.  The caller holds o_mtx. */
void
dq_file_knote(struct dq_object *o, long hint)
{

	DQO_LOCK_ASSERT(o);
	KNOTE_LOCKED(&o->o_sel.si_note, hint);
}

static inline struct dq_object *
dq_fp_object(struct file *fp)
{

	KASSERT(fp->f_ops == &dq_fileops, ("dq: not a dq object"));
	return (fp->f_data);
}

/*
 * 15.4, run before the operation takes foffset or a rangelock: a
 * controller operating on its own served descriptor must be refused, not
 * left asleep (uninterruptibly, in rangelock_*lock) behind a requester
 * whose event only that controller can answer.  dq_event_post_wait checks
 * again for the operations that take no lock first.
 */
static int
dq_deadlock_check(struct dq_object *o, struct thread *td)
{

	return (dq_caller_holds_queue(o->o_queue, td) ? EDEADLK : 0);
}

/* EIO once revoked or once the controller is gone (I10, 15.8). */
static int
dq_object_usable(struct dq_object *o)
{
	int error;

	error = 0;
	if ((o->o_queue->q_flags & DQ_Q_CLOSING) != 0)
		return (EIO);
	DQO_LOCK(o);
	if (o->o_state != DQ_OBJ_LIVE)
		error = EIO;
	DQO_UNLOCK(o);
	return (error);
}

int
dq_file_ident(struct file *fp, struct dq_ident_file *ident, uint64_t *objectp,
    uint64_t *noncep)
{
	struct dq_object *o;

	if (fp->f_type != DTYPE_DQ || fp->f_ops != &dq_fileops)
		return (ENOTTY);
	o = fp->f_data;
	DQO_LOCK(o);
	*ident = o->o_ident;
	DQO_UNLOCK(o);
	*objectp = o->o_id;
	*noncep = mac_capability_proc_nonce(o->o_queue->q_cred);
	return (0);
}

struct ucred *
dq_file_cred(struct file *fp)
{
	struct dq_object *o;

	if (fp->f_type != DTYPE_DQ || fp->f_ops != &dq_fileops)
		return (NULL);
	o = fp->f_data;
	return (o->o_queue->q_cred);
}

/*
 * Data
 */

/*
 * A uio is advanced by uiomove as it copies, so a copy that fails or a
 * write the controller took only part of has to be undone: snapshot the
 * iovecs before, restore after, and advance by the accepted count.
 */
struct dq_uio_save {
	struct iovec	*us_iov;
	struct iovec	*us_iovsave;
	int		 us_iovcnt;
	ssize_t		 us_resid;
	off_t		 us_offset;
};

static void
dq_uio_snapshot(struct uio *uio, struct dq_uio_save *us)
{

	us->us_iov = uio->uio_iov;
	us->us_iovcnt = uio->uio_iovcnt;
	us->us_resid = uio->uio_resid;
	us->us_offset = uio->uio_offset;
	memcpy(us->us_iovsave, us->us_iov,
	    (size_t)us->us_iovcnt * sizeof(struct iovec));
}

static void
dq_uio_restore(struct uio *uio, const struct dq_uio_save *us)
{

	memcpy(us->us_iov, us->us_iovsave,
	    (size_t)us->us_iovcnt * sizeof(struct iovec));
	uio->uio_iov = us->us_iov;
	uio->uio_iovcnt = us->us_iovcnt;
	uio->uio_resid = us->us_resid;
	uio->uio_offset = us->us_offset;
}

/* Advance the iovecs and resid by n bytes without touching the offset. */
static void
dq_uio_advance(struct uio *uio, size_t n)
{
	struct iovec *iov;
	size_t cnt;

	while (n > 0) {
		iov = uio->uio_iov;
		cnt = MIN(iov->iov_len, n);
		iov->iov_base = (char *)iov->iov_base + cnt;
		iov->iov_len -= cnt;
		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
		}
		uio->uio_resid -= cnt;
		n -= cnt;
	}
}

/*
 * dp_cache = NONE or ATTR: one READ per max_io chunk, in order; a short
 * answer is the end of the file.
 */
static int
dq_read_events(struct dq_object *o, struct uio *uio, struct thread *td)
{
	struct dq_read_body rb;
	struct dq_data *reply;
	size_t replylen, chunk;
	int error, rerror;

	error = 0;
	while (uio->uio_resid > 0) {
		chunk = MIN((size_t)uio->uio_resid, (size_t)dq_max_io);
		if ((off_t)chunk > OFF_MAX - uio->uio_offset)
			chunk = OFF_MAX - uio->uio_offset;
		if (chunk == 0)
			break;
		rb.dr_offset = uio->uio_offset;
		rb.dr_len = chunk;
		rb.dr_pad0 = 0;
		error = dq_event_post_wait(o, DQ_OP_READ, &rb, sizeof(rb), td,
		    0, &reply, &rerror);
		if (error != 0)
			break;
		if (rerror != 0) {
			dq_reply_free(reply);
			error = rerror;
			break;
		}
		replylen = reply != NULL ? reply->dd_len : 0;
		if (replylen != 0)
			error = uiomove(reply->dd_bytes, replylen, uio);
		dq_reply_free(reply);
		if (error != 0 || replylen < chunk)
			break;	/* a short answer is the end of the file */
	}
	return (error);
}

/*
 * dp_cache = DATA (D103): read(2) is served from the object's pages, as
 * uiomove_object serves shm; a miss pages in through the pager (a READ for
 * whole pages, with read-ahead up to VM_INITIAL_PAGEIN pages, waited for as
 * a fault waits).  The page is wired, not busy, across the copy, so a
 * destination that maps the same page can fault it in.  The end of the
 * file is the size the pager object follows (o_vmsize, read under its
 * lock), so a page past the object's end is never zero-filled into the
 * cache while an identity change is still being applied.
 */
static int
dq_read_cached(struct dq_object *o, struct uio *uio)
{
	vm_object_t obj;
	vm_page_t m;
	off_t nsize, size;
	size_t pgoff, tlen;
	int error, npages, rv;

	obj = o->o_object;
	error = 0;
	while (uio->uio_resid > 0) {
		VM_OBJECT_WLOCK(obj);
		size = o->o_vmsize;
		if (uio->uio_offset >= size) {
			VM_OBJECT_WUNLOCK(obj);
			break;
		}
		pgoff = uio->uio_offset & PAGE_MASK;
		tlen = MIN(PAGE_SIZE - pgoff, (size_t)uio->uio_resid);
		tlen = MIN(tlen, (size_t)(size - uio->uio_offset));
		npages = howmany(MIN((off_t)uio->uio_resid,
		    size - uio->uio_offset) + pgoff, PAGE_SIZE);
		rv = vm_page_grab_valid(&m, obj, OFF_TO_IDX(uio->uio_offset),
		    VM_ALLOC_NORMAL | VM_ALLOC_WIRED | VM_ALLOC_NOBUSY |
		    VM_ALLOC_COUNT(MIN(npages, VM_ALLOC_COUNT_MAX)));
		VM_OBJECT_WUNLOCK(obj);
		if (rv == VM_PAGER_BAD)
			break;		/* the size shrank under us */
		if (rv != VM_PAGER_OK) {
			/*
			 * A shrink fails the page-ins reaching past it: look
			 * again at the new size before calling it an error.
			 */
			VM_OBJECT_WLOCK(obj);
			nsize = o->o_vmsize;
			VM_OBJECT_WUNLOCK(obj);
			if (uio->uio_offset >= nsize)
				break;
			if (nsize != size)
				continue;
			error = EIO;
			break;
		}
		error = uiomove_fromphys(&m, pgoff, tlen, uio);
		vm_page_unwire(m, PQ_ACTIVE);
		if (error != 0)
			break;
	}
	return (error);
}

static int
dq_read(struct file *fp, struct uio *uio, struct ucred *active_cred __unused,
    int flags, struct thread *td)
{
	struct dq_object *o;
	void *cookie;
	off_t start, end;
	int error;
	bool cached;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	if (uio->uio_resid == 0)
		return (0);
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);

	foffset_lock_uio(fp, uio, flags);
	start = uio->uio_offset;
	if (start < 0) {
		error = EINVAL;
		goto out_offset;
	}
	end = uio->uio_resid > OFF_MAX - start ? OFF_MAX :
	    start + uio->uio_resid;
	cookie = rangelock_rlock(&o->o_rl, start, end);
	DQO_LOCK(o);
	cached = o->o_policy.dp_cache == DQ_CACHE_DATA;
	DQO_UNLOCK(o);
	if (cached)
		error = dq_read_cached(o, uio);
	else
		error = dq_read_events(o, uio, td);
	rangelock_unlock(&o->o_rl, cookie);
	if (error == 0) {
		/* As the VOP_READ post hook raises it (D100). */
		DQO_LOCK(o);
		dq_file_knote(o, NOTE_READ);
		DQO_UNLOCK(o);
	}
out_offset:
	foffset_unlock_uio(fp, uio, flags);
	return (error);
}

/*
 * D95: a write is one WRITE event per max_io chunk, in order, each carrying
 * its data, under the implicit-offset lock and the range lock vn_io_fault
 * would take.  The controller answers the count it took and the offset it
 * wrote at (the authoritative EOF of an append is the controller's); the
 * kernel moves the implicit offset to offset + written, extends di_size and
 * raises NOTE_WRITE (+ NOTE_EXTEND).  A failure after accepted chunks
 * returns the error with the count lost, except for EINTR, ERESTART and
 * EWOULDBLOCK, which dofilewrite turns into a short write; no rollback is
 * possible (IO_UNIT is a per-filesystem property; declared).  RLIMIT_FSIZE
 * is applied as the filesystems under vn_write apply it (N3).
 */
static int
dq_write(struct file *fp, struct uio *uio, struct ucred *active_cred __unused,
    int flags, struct thread *td)
{
	struct dq_object *o;
	struct dq_write_body *wb;
	const struct dq_write_reply *wr;
	struct dq_data *reply;
	struct dq_uio_save us;
	void *cookie;
	ssize_t resid, resid_adj, done;
	off_t start, lim, newend, woff;
	size_t chunk, bodylen, written;
	uint32_t wflags;
	long hint;
	int error, rerror;
	bool append, extended;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	extended = false;
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	if (uio->uio_resid == 0)
		return (0);	/* posts nothing, after the checks */
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);

	/* The flags as vn_write computes ioflag: a full sync dominates. */
	append = (flags & FOF_APPEND) != 0 ||
	    ((fp->f_flag & O_APPEND) != 0 && (flags & FOF_NOAPPEND) == 0);
	wflags = append ? DQ_WRITE_F_APPEND : 0;
	if ((flags & FOF_SYNC) != 0 || (fp->f_flag & O_FSYNC) != 0)
		wflags |= DQ_WRITE_F_SYNC;
	else if ((flags & FOF_DSYNC) != 0 || (fp->f_flag & O_DSYNC) != 0)
		wflags |= DQ_WRITE_F_DSYNC;

	us.us_iovsave = malloc((size_t)uio->uio_iovcnt * sizeof(struct iovec),
	    M_DQ, M_WAITOK);
	resid_adj = 0;
	done = 0;
	foffset_lock_uio(fp, uio, flags);
	start = uio->uio_offset;
	if (start < 0) {
		error = EINVAL;
		goto out_offset;
	}
	/*
	 * RLIMIT_FSIZE as vn_rlimit_fsizex applies it for a VOP_WRITE: clamp
	 * the request to the limit, or EFBIG with SIGXFSZ when the offset is
	 * already past it.  An append is measured at the identity's size,
	 * the best the kernel knows before the controller names the EOF.  The
	 * clamped tail is given back to the uio at the end, unwritten
	 * (vn_rlimit_fsizex_res).
	 */
	if (append) {
		DQO_LOCK(o);
		lim = o->o_ident.di_size;
		DQO_UNLOCK(o);
	} else
		lim = start;
	resid = uio->uio_resid;
	error = rlimit_fsize_check(lim, &resid, 0, true, td);
	if (error != 0)
		goto out_offset;
	resid_adj = uio->uio_resid - resid;
	uio->uio_resid = resid;

	/* vn_io_fault's rule: appenders and implicit offsets take the whole file. */
	if ((fp->f_flag & O_APPEND) != 0 ||
	    (flags & (FOF_OFFSET | FOF_APPEND)) != FOF_OFFSET)
		cookie = rangelock_wlock(&o->o_rl, 0, OFF_MAX);
	else
		cookie = rangelock_wlock(&o->o_rl, start,
		    resid > OFF_MAX - start ? OFF_MAX : start + resid);

	while (uio->uio_resid > 0) {
		chunk = MIN((size_t)uio->uio_resid, (size_t)dq_max_io);
		if (!append && (off_t)chunk > OFF_MAX - uio->uio_offset) {
			chunk = OFF_MAX - uio->uio_offset;
			if (chunk == 0) {
				error = EFBIG;
				break;
			}
		}
		bodylen = roundup2(sizeof(*wb) + chunk, 8);
		wb = malloc(bodylen, M_DQ, M_WAITOK | M_ZERO);
		wb->dw_offset = uio->uio_offset;
		wb->dw_len = chunk;
		wb->dw_flags = wflags;
		/*
		 * The data is copied in under the range lock only.  The uio
		 * is restored afterwards in every case and advanced by what
		 * the controller took: a fault or a refusal leaves the chunk
		 * unwritten, a short write leaves its tail.
		 */
		dq_uio_snapshot(uio, &us);
		error = uiomove(wb + 1, chunk, uio);
		dq_uio_restore(uio, &us);
		if (error != 0) {
			free(wb, M_DQ);
			break;
		}
		error = dq_event_post_wait(o, DQ_OP_WRITE, wb, bodylen, td, 0,
		    &reply, &rerror);
		if (error != 0) {
			free(wb, M_DQ);
			break;
		}
		if (rerror != 0) {
			free(wb, M_DQ);
			dq_reply_free(reply);
			error = rerror;
			break;
		}
		/* The reply path validated the size and the bounds (N2). */
		wr = (const struct dq_write_reply *)reply->dd_bytes;
		written = wr->dwr_written;
		woff = wr->dwr_offset;
		dq_reply_free(reply);
		/*
		 * Accepted: the cached pages the bytes cover take them, valid
		 * and as clean as they were (D103), so mappings and DATA reads
		 * see the write.
		 */
		dq_pager_write_resident(o, woff, (const char *)(wb + 1),
		    written);
		free(wb, M_DQ);

		dq_uio_advance(uio, written);
		/*
		 * Only the implicit offset follows the controller's word; a
		 * positioned write leaves f_offset alone (foffset_unlock_uio
		 * with FOF_OFFSET) and its uio offset merely advances.
		 */
		if ((flags & FOF_OFFSET) == 0)
			uio->uio_offset = woff + written;
		else
			uio->uio_offset += written;
		done += written;
		newend = woff + written;
		DQO_LOCK(o);
		hint = NOTE_WRITE;
		if ((uint64_t)newend > o->o_ident.di_size) {
			o->o_ident.di_size = newend;
			hint |= NOTE_EXTEND;
			extended = true;
		}
		if (written != 0)
			dq_file_knote(o, hint);
		DQO_UNLOCK(o);
		if (extended) {
			dq_object_setsize(o, newend);	/* B10 */
			extended = false;
		}
		if (written < chunk)
			break;	/* a short write ends the call */
	}
	rangelock_unlock(&o->o_rl, cookie);
	/*
	 * dofilewrite's count rule, for the callers that do not apply it
	 * themselves (aio, the Linux bridges): bytes moved before an
	 * interruption are a short write, not an error.
	 */
	if (done != 0 && (error == EINTR || error == ERESTART ||
	    error == EWOULDBLOCK))
		error = 0;
out_offset:
	uio->uio_resid += resid_adj;
	foffset_unlock_uio(fp, uio, flags);
	free(us.us_iovsave, M_DQ);
	return (error);
}

/*
 * Attributes
 */

static void
dq_ident_to_stat(const struct dq_ident_file *di, struct stat *sb)
{

	bzero(sb, sizeof(*sb));
	sb->st_dev = di->di_dev;
	sb->st_ino = di->di_ino;
	sb->st_nlink = di->di_nlink;
	sb->st_mode = di->di_mode;
	sb->st_bsdflags = 0;
	sb->st_uid = di->di_uid;
	sb->st_gid = di->di_gid;
	sb->st_rdev = di->di_rdev;
	sb->st_atim.tv_sec = di->di_atime.tv_sec;
	sb->st_atim.tv_nsec = di->di_atime.tv_nsec;
	sb->st_mtim.tv_sec = di->di_mtime.tv_sec;
	sb->st_mtim.tv_nsec = di->di_mtime.tv_nsec;
	sb->st_ctim.tv_sec = di->di_ctime.tv_sec;
	sb->st_ctim.tv_nsec = di->di_ctime.tv_nsec;
	sb->st_birthtim.tv_sec = di->di_birthtime.tv_sec;
	sb->st_birthtim.tv_nsec = di->di_birthtime.tv_nsec;
	sb->st_size = di->di_size;
	sb->st_blocks = di->di_blocks;
	sb->st_blksize = di->di_blksize;
	sb->st_flags = di->di_flags;
	sb->st_gen = di->di_gen;
	sb->st_filerev = di->di_filerev;
}

static int
dq_stat(struct file *fp, struct stat *sb, struct ucred *active_cred __unused)
{
	struct dq_object *o;
	struct dq_ident_file *di;
	struct dq_data *reply;
	bool event;
	int error, rerror;

	o = dq_fp_object(fp);
	DQO_LOCK(o);
	event = (o->o_policy.dp_events & DQ_EVENTS_GETATTR) != 0 &&
	    o->o_state == DQ_OBJ_LIVE &&
	    (o->o_queue->q_flags & DQ_Q_CLOSING) == 0;
	DQO_UNLOCK(o);
	if (event) {
		error = dq_event_post_wait(o, DQ_OP_GETATTR, NULL, 0, curthread,
		    0, &reply, &rerror);
		if (error != 0)
			return (error);
		if (rerror != 0) {
			dq_reply_free(reply);
			return (rerror);
		}
		/*
		 * The reply path validated it against the kind; the identity
		 * index follows a changed (di_dev, di_ino).
		 */
		dq_object_set_ident(o,
		    (const struct dq_ident_file *)reply->dd_bytes, 0);
		dq_reply_free(reply);
	}
	/* After a revoke the frozen identity keeps answering (design 9). */
	di = malloc(sizeof(*di), M_DQ, M_WAITOK);
	DQO_LOCK(o);
	*di = o->o_ident;
	DQO_UNLOCK(o);
	dq_ident_to_stat(di, sb);
	free(di, M_DQ);
	return (0);
}

static int
dq_statfs(struct file *fp, struct statfs *buf, struct thread *td __unused)
{
	struct dq_object *o;
	struct dq_statfs *ds;

	o = dq_fp_object(fp);
	ds = malloc(sizeof(*ds), M_DQ, M_WAITOK);
	DQO_LOCK(o);
	*ds = o->o_ident.di_statfs;
	DQO_UNLOCK(o);
	bzero(buf, sizeof(*buf));
	buf->f_version = STATFS_VERSION;
	buf->f_type = ds->ds_type;
	buf->f_flags = ds->ds_flags;
	buf->f_bsize = ds->ds_bsize;
	buf->f_iosize = ds->ds_iosize;
	buf->f_blocks = ds->ds_blocks;
	buf->f_bfree = ds->ds_bfree;
	buf->f_bavail = ds->ds_bavail;
	buf->f_files = ds->ds_files;
	buf->f_ffree = ds->ds_ffree;
	buf->f_syncwrites = ds->ds_syncwrites;
	buf->f_asyncwrites = ds->ds_asyncwrites;
	buf->f_syncreads = ds->ds_syncreads;
	buf->f_asyncreads = ds->ds_asyncreads;
	buf->f_nvnodelistsize = ds->ds_nvnodelistsize;
	buf->f_namemax = ds->ds_namemax;
	buf->f_owner = ds->ds_owner;
	buf->f_fsid.val[0] = ds->ds_fsid[0];
	buf->f_fsid.val[1] = ds->ds_fsid[1];
	memcpy(buf->f_fstypename, ds->ds_fstypename, MFSNAMELEN);
	memcpy(buf->f_mntfromname, ds->ds_mntfromname, MNAMELEN);
	memcpy(buf->f_mntonname, ds->ds_mntonname, MNAMELEN);
	free(ds, M_DQ);
	return (0);
}

static int
dq_pathconf(struct file *fp, int name, long *valuep, struct thread *td __unused)
{
	struct dq_object *o;
	int i;

	o = dq_fp_object(fp);
	for (i = 0; i < DQ_PC_NCOUNT; i++) {
		if (dq_pc_names[i] == name)
			break;
	}
	if (i == DQ_PC_NCOUNT)
		return (EINVAL);
	DQO_LOCK(o);
	if ((o->o_ident.di_pathconf.dp_valid & ((uint64_t)1 << i)) == 0) {
		DQO_UNLOCK(o);
		return (EINVAL);
	}
	*valuep = o->o_ident.di_pathconf.dp_value[i];
	DQO_UNLOCK(o);
	return (0);
}

static int
dq_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct dq_object *o;
	struct dq_ident_file *di;

	o = dq_fp_object(fp);
	di = malloc(sizeof(*di), M_DQ, M_WAITOK);
	DQO_LOCK(o);
	*di = o->o_ident;
	DQO_UNLOCK(o);
	kif->kf_type = KF_TYPE_VNODE;
	kif->kf_un.kf_file.kf_file_type = KF_VTYPE_VREG;
	strlcpy(kif->kf_path, di->di_path, sizeof(kif->kf_path));
	kif->kf_un.kf_file.kf_file_fsid = di->di_dev;
	kif->kf_un.kf_file.kf_file_fsid_freebsd11 = di->di_dev;
	kif->kf_un.kf_file.kf_file_fileid = di->di_ino;
	kif->kf_un.kf_file.kf_file_mode = di->di_mode;
	kif->kf_un.kf_file.kf_file_size = di->di_size;
	kif->kf_un.kf_file.kf_file_rdev = di->di_rdev;
	kif->kf_un.kf_file.kf_file_rdev_freebsd11 = di->di_rdev;
	kif->kf_un.kf_file.kf_file_nlink = di->di_nlink;
	free(di, M_DQ);
	return (0);
}

/*
 * SETATTR (D96, N4).  Before posting, the kernel applies to the presented
 * identity and the requester's credential the DAC and privilege rules a
 * vnode applies, in ufs_setattr's order, so the controller is asked only
 * what it alone can decide (a read-only backing store, stale state).  The
 * flags a vnode accepts are ufs_setattr's set (the plan's "settable"
 * masks cover every bit of a 32-bit word, so the ufs list is the rule).
 */
#define	DQ_FLAGS_SETTABLE	(SF_APPEND | SF_ARCHIVED | SF_IMMUTABLE | \
	SF_NOUNLINK | SF_SNAPSHOT | UF_APPEND | UF_ARCHIVE | UF_HIDDEN | \
	UF_IMMUTABLE | UF_NODUMP | UF_NOUNLINK | UF_OFFLINE | UF_OPAQUE | \
	UF_READONLY | UF_REPARSE | UF_SPARSE | UF_SYSTEM | UF_NOCACHE)
#define	DQ_FLAGS_LOCKED		(SF_IMMUTABLE | UF_IMMUTABLE | SF_APPEND | \
	UF_APPEND)
#define	DQ_SETATTR_TIMES	(DQ_SETATTR_ATIME | DQ_SETATTR_MTIME | \
	DQ_SETATTR_BIRTHTIME)

static int
dq_setattr_check(const struct dq_ident_file *di, const struct dq_setattr_body *sb,
    struct ucred *cred)
{
	uint32_t mask, curflags, newflags, mode;
	uid_t uid;
	gid_t gid;
	int error;

	mask = sb->dsa_mask;
	curflags = di->di_flags;
	newflags = curflags;
	if ((mask & DQ_SETATTR_FLAGS) != 0) {
		if ((sb->dsa_flags & ~DQ_FLAGS_SETTABLE) != 0)
			return (EOPNOTSUPP);
		/* Only VADMIN may modify the flags. */
		error = vaccess(VREG, di->di_mode, di->di_uid, di->di_gid,
		    VADMIN, cred);
		if (error != 0)
			return (error);
		/*
		 * Unprivileged processes may not unset system flags, or
		 * modify flags while any system flag is set; privileged
		 * ones may not touch system flags under securelevel > 0
		 * while any is set, and never toggle the snapshot flag.
		 */
		if (!priv_check_cred(cred, PRIV_VFS_SYSFLAGS)) {
			if ((curflags & (SF_NOUNLINK | SF_IMMUTABLE |
			    SF_APPEND)) != 0) {
				error = securelevel_gt(cred, 0);
				if (error != 0)
					return (error);
			}
			if (((sb->dsa_flags ^ curflags) & SF_SNAPSHOT) != 0)
				return (EPERM);
		} else {
			if ((curflags & (SF_NOUNLINK | SF_IMMUTABLE |
			    SF_APPEND)) != 0 ||
			    ((sb->dsa_flags ^ curflags) & SF_SETTABLE) != 0)
				return (EPERM);
		}
		newflags = sb->dsa_flags;
	}
	/*
	 * Immutable or append: no other attribute changes.  Evaluated on the
	 * flags being set (the plan refuses the rest with EPERM where ufs
	 * would silently skip them after setting the flags) or, when none
	 * are, on the current ones, where ufs refuses even an empty change.
	 */
	if ((newflags & DQ_FLAGS_LOCKED) != 0 &&
	    ((mask & DQ_SETATTR_FLAGS) == 0 ||
	    (mask & ~(DQ_SETATTR_FLAGS | DQ_SETATTR_F_UTIMES_NULL)) != 0))
		return (EPERM);
	if ((mask & (DQ_SETATTR_UID | DQ_SETATTR_GID)) != 0) {
		uid = (mask & DQ_SETATTR_UID) != 0 ? sb->dsa_uid : di->di_uid;
		gid = (mask & DQ_SETATTR_GID) != 0 ? sb->dsa_gid : di->di_gid;
		error = vaccess(VREG, di->di_mode, di->di_uid, di->di_gid,
		    VADMIN, cred);
		if (error != 0)
			return (error);
		/*
		 * Giving the file away, or to a group the caller is not a
		 * member of, takes privilege (ufs_chown, shm_chown).
		 */
		if (((uid != di->di_uid && uid != cred->cr_uid) ||
		    (gid != di->di_gid && !groupmember(gid, cred))) &&
		    (error = priv_check_cred(cred, PRIV_VFS_CHOWN)) != 0)
			return (error);
	}
	if ((mask & DQ_SETATTR_SIZE) != 0 && (curflags & SF_SNAPSHOT) != 0)
		return (EPERM);	/* a snapshot is not truncated (ufs) */
	if ((mask & DQ_SETATTR_TIMES) != 0) {
		if ((curflags & SF_SNAPSHOT) != 0)
			return (EPERM);
		/*
		 * vn_utimes_perm without a vnode: VWRITE_ATTRIBUTES is the
		 * owner or PRIV_VFS_ADMIN (vop_stdaccessx maps it to VADMIN);
		 * with a NULL utimes argument, write permission suffices.
		 */
		error = vaccess(VREG, di->di_mode, di->di_uid, di->di_gid,
		    VADMIN, cred);
		if (error != 0 && (mask & DQ_SETATTR_F_UTIMES_NULL) != 0)
			error = vaccess(VREG, di->di_mode, di->di_uid,
			    di->di_gid, VWRITE, cred);
		if (error != 0)
			return (error);
	}
	if ((mask & DQ_SETATTR_MODE) != 0) {
		mode = sb->dsa_mode;
		/* A snapshot never becomes writable or executable (ufs). */
		if ((curflags & SF_SNAPSHOT) != 0 &&
		    (mode & (S_IXUSR | S_IWUSR | S_IXGRP | S_IWGRP | S_IXOTH |
		    S_IWOTH)) != 0)
			return (EPERM);
		/* ufs_chmod: VWRITE_ACL, which is VADMIN here. */
		error = vaccess(VREG, di->di_mode, di->di_uid, di->di_gid,
		    VADMIN, cred);
		if (error != 0)
			return (error);
		/* The sticky bit on a non-directory takes privilege. */
		if ((mode & S_ISTXT) != 0 &&
		    priv_check_cred(cred, PRIV_VFS_STICKYFILE) != 0)
			return (EFTYPE);
		if (!groupmember(di->di_gid, cred) && (mode & S_ISGID) != 0) {
			error = priv_check_cred(cred, PRIV_VFS_SETGID);
			if (error != 0)
				return (error);
		}
		if ((mode & S_ISUID) != 0 && di->di_uid != cred->cr_uid) {
			error = priv_check_cred(cred, PRIV_VFS_ADMIN);
			if (error != 0)
				return (error);
		}
		/* I3: a served identity never carries set-id bits. */
		if ((mode & (S_ISUID | S_ISGID)) != 0)
			return (EPERM);
	}
	return (0);
}

/*
 * Check, post, apply.  On success the requested fields become the
 * identity, a modification time earlier than the birth time pulls the
 * birth time back with it (vn_setattr), ctime is now and NOTE_ATTRIB is
 * raised; the controller may SETIDENT the rest at any time.  An empty mask
 * (fchown(fd, -1, -1)) posts nothing once the immutable rule passed.
 */
static int
dq_setattr_post(struct dq_object *o, struct dq_setattr_body *sb,
    struct ucred *cred, struct thread *td)
{
	struct dq_ident_file *di;
	struct dq_data *reply;
	struct timespec now;
	uint32_t mask;
	int error, rerror;

	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);
	di = malloc(sizeof(*di), M_DQ, M_WAITOK);
	DQO_LOCK(o);
	*di = o->o_ident;
	DQO_UNLOCK(o);
	error = dq_setattr_check(di, sb, cred);
	/*
	 * RLIMIT_FSIZE is the truncation's last check, as ufs_setattr
	 * applies vn_rlimit_trunc only after the flag, owner and snapshot
	 * rules: a refused truncation raises no SIGXFSZ.
	 */
	if (error == 0 && (sb->dsa_mask & DQ_SETATTR_SIZE) != 0)
		error = vn_rlimit_trunc(sb->dsa_size, td);
	if (error == 0 && (sb->dsa_mask & DQ_SETATTR_MTIME) != 0 &&
	    (sb->dsa_mask & DQ_SETATTR_BIRTHTIME) == 0 &&
	    (sb->dsa_mtime.tv_sec < di->di_birthtime.tv_sec ||
	    (sb->dsa_mtime.tv_sec == di->di_birthtime.tv_sec &&
	    sb->dsa_mtime.tv_nsec < di->di_birthtime.tv_nsec))) {
		sb->dsa_birthtime = sb->dsa_mtime;
		sb->dsa_mask |= DQ_SETATTR_BIRTHTIME;
	}
	free(di, M_DQ);
	if (error != 0)
		return (error);
	if ((sb->dsa_mask & ~DQ_SETATTR_F_UTIMES_NULL) == 0)
		return (0);
	if ((sb->dsa_mask & DQ_SETATTR_MODE) != 0)
		sb->dsa_mode &= ALLPERMS;	/* as ufs_chmod applies it */

	error = dq_event_post_wait(o, DQ_OP_SETATTR, sb, sizeof(*sb), td, 0,
	    &reply, &rerror);
	if (error != 0)
		return (error);
	dq_reply_free(reply);
	if (rerror != 0)
		return (rerror);

	nanotime(&now);
	mask = sb->dsa_mask;
	DQO_LOCK(o);
	if ((mask & DQ_SETATTR_MODE) != 0)
		o->o_ident.di_mode = (o->o_ident.di_mode & S_IFMT) |
		    sb->dsa_mode;
	if ((mask & DQ_SETATTR_UID) != 0)
		o->o_ident.di_uid = sb->dsa_uid;
	if ((mask & DQ_SETATTR_GID) != 0)
		o->o_ident.di_gid = sb->dsa_gid;
	if ((mask & DQ_SETATTR_SIZE) != 0)
		o->o_ident.di_size = sb->dsa_size;
	if ((mask & DQ_SETATTR_FLAGS) != 0)
		o->o_ident.di_flags = sb->dsa_flags;
	if ((mask & DQ_SETATTR_ATIME) != 0)
		o->o_ident.di_atime = sb->dsa_atime;
	if ((mask & DQ_SETATTR_MTIME) != 0)
		o->o_ident.di_mtime = sb->dsa_mtime;
	if ((mask & DQ_SETATTR_BIRTHTIME) != 0)
		o->o_ident.di_birthtime = sb->dsa_birthtime;
	o->o_ident.di_ctime.tv_sec = now.tv_sec;
	o->o_ident.di_ctime.tv_nsec = now.tv_nsec;
	dq_file_knote(o, NOTE_ATTRIB);
	DQO_UNLOCK(o);
	if ((mask & DQ_SETATTR_SIZE) != 0)
		dq_object_setsize(o, sb->dsa_size);	/* B10 */
	return (0);
}

/*
 * ftruncate(2): a negative length and a descriptor without FWRITE are the
 * generic layer's EINVAL.  The whole range is locked so a split write is
 * not half before and half after the truncation (vn_truncate), and the
 * limit is vn_rlimit_trunc's (SIGXFSZ and EFBIG past RLIMIT_FSIZE),
 * applied in dq_setattr_post after the permission rules.
 */
static int
dq_truncate(struct file *fp, off_t length, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_object *o;
	struct dq_setattr_body sb;
	void *cookie;
	int error;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	error = dq_deadlock_check(o, td);	/* before the rangelock */
	if (error != 0)
		return (error);
	bzero(&sb, sizeof(sb));
	sb.dsa_mask = DQ_SETATTR_SIZE;
	sb.dsa_size = length;
	cookie = rangelock_wlock(&o->o_rl, 0, OFF_MAX);
	error = dq_setattr_post(o, &sb, active_cred, td);
	rangelock_unlock(&o->o_rl, cookie);
	return (error);
}

static int
dq_chmod(struct file *fp, mode_t mode, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_setattr_body sb;

	if (DQ_OPATH(fp))
		return (EBADF);
	bzero(&sb, sizeof(sb));
	sb.dsa_mask = DQ_SETATTR_MODE;
	sb.dsa_mode = mode;
	return (dq_setattr_post(dq_fp_object(fp), &sb, active_cred, td));
}

static int
dq_chown(struct file *fp, uid_t uid, gid_t gid, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_setattr_body sb;

	if (DQ_OPATH(fp))
		return (EBADF);
	bzero(&sb, sizeof(sb));
	if (uid != (uid_t)-1) {
		sb.dsa_mask |= DQ_SETATTR_UID;
		sb.dsa_uid = uid;
	}
	if (gid != (gid_t)-1) {
		sb.dsa_mask |= DQ_SETATTR_GID;
		sb.dsa_gid = gid;
	}
	return (dq_setattr_post(dq_fp_object(fp), &sb, active_cred, td));
}

/*
 * The whole vattr (futimens, fchflags, fdescfs): size, mode and owner go
 * through their direct operations as every fo_setattr body does; the times
 * and flags are one SETATTR.  A flags word wider than st_flags has unknown
 * bits by definition.
 */
static int
dq_setattr(struct file *fp, struct vattr *vap, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_setattr_body sb;
	int error;

	error = file_setattr_direct(fp, vap, active_cred, td);
	if (error != 0)
		return (error);
	bzero(&sb, sizeof(sb));
	if (vap->va_flags != VNOVAL) {
		if (vap->va_flags > UINT32_MAX)
			return (EOPNOTSUPP);
		sb.dsa_mask |= DQ_SETATTR_FLAGS;
		sb.dsa_flags = vap->va_flags;
	}
	if (vap->va_atime.tv_sec != VNOVAL) {
		sb.dsa_mask |= DQ_SETATTR_ATIME;
		sb.dsa_atime.tv_sec = vap->va_atime.tv_sec;
		sb.dsa_atime.tv_nsec = vap->va_atime.tv_nsec;
	}
	if (vap->va_mtime.tv_sec != VNOVAL) {
		sb.dsa_mask |= DQ_SETATTR_MTIME;
		sb.dsa_mtime.tv_sec = vap->va_mtime.tv_sec;
		sb.dsa_mtime.tv_nsec = vap->va_mtime.tv_nsec;
	}
	if (vap->va_birthtime.tv_sec != VNOVAL) {
		sb.dsa_mask |= DQ_SETATTR_BIRTHTIME;
		sb.dsa_birthtime.tv_sec = vap->va_birthtime.tv_sec;
		sb.dsa_birthtime.tv_nsec = vap->va_birthtime.tv_nsec;
	}
	if (sb.dsa_mask == 0)
		return (0);
	if ((vap->va_vaflags & VA_UTIMES_NULL) != 0)
		sb.dsa_mask |= DQ_SETATTR_F_UTIMES_NULL;
	return (dq_setattr_post(dq_fp_object(fp), &sb, active_cred, td));
}

/*
 * Space (D95).  The generic layer validated the range (offset >= 0, len >
 * 0, offset + len <= OFF_MAX) and FWRITE.  No RLIMIT_FSIZE: vn_fallocate
 * applies none (N3).  The range is locked as vn_deallocate_impl locks it.
 */
static int
dq_fallocate(struct file *fp, off_t offset, off_t len, struct thread *td)
{
	struct dq_object *o;
	struct dq_fallocate_body fb;
	struct dq_data *reply;
	void *cookie;
	uint64_t end;
	long hint;
	int error, rerror;

	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);
	fb.dfa_offset = offset;
	fb.dfa_len = len;
	cookie = rangelock_wlock(&o->o_rl, offset, offset + len);
	error = dq_event_post_wait(o, DQ_OP_FALLOCATE, &fb, sizeof(fb), td, 0,
	    &reply, &rerror);
	if (error == 0) {
		dq_reply_free(reply);
		error = rerror;
	}
	if (error == 0) {
		end = (uint64_t)offset + (uint64_t)len;
		DQO_LOCK(o);
		hint = NOTE_WRITE;
		if (end > o->o_ident.di_size) {
			o->o_ident.di_size = end;
			hint |= NOTE_EXTEND;
		}
		dq_file_knote(o, hint);
		DQO_UNLOCK(o);
		if ((hint & NOTE_EXTEND) != 0)
			dq_object_setsize(o, end);	/* B10 */
	}
	rangelock_unlock(&o->o_rl, cookie);
	return (error);
}

static int
dq_fspacectl(struct file *fp, int cmd, off_t *offset, off_t *length,
    int flags, struct ucred *active_cred __unused, struct thread *td)
{
	struct dq_object *o;
	struct dq_fspacectl_body sb;
	const struct dq_fspacectl_reply *sr;
	struct dq_data *reply;
	void *cookie;
	int error, rerror;

	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);
	sb.dsc_cmd = cmd;
	sb.dsc_flags = flags;
	sb.dsc_offset = *offset;
	sb.dsc_len = *length;
	cookie = rangelock_wlock(&o->o_rl, *offset, *offset + *length);
	error = dq_event_post_wait(o, DQ_OP_FSPACECTL, &sb, sizeof(sb), td, 0,
	    &reply, &rerror);
	if (error == 0 && rerror == 0) {
		/* Validated by the reply path against the invariant. */
		sr = (const struct dq_fspacectl_reply *)reply->dd_bytes;
		*offset = sr->dscr_offset;
		*length = sr->dscr_len;
		DQO_LOCK(o);
		dq_file_knote(o, NOTE_WRITE);	/* B7 */
		DQO_UNLOCK(o);
	}
	if (error == 0) {
		dq_reply_free(reply);
		error = rerror;
	}
	rangelock_unlock(&o->o_rl, cookie);
	return (error);
}

/*
 * N10: FSYNC posts whenever the policy serves writes, whatever this
 * descriptor's FWRITE (another descriptor may have written); under
 * dp_write = DENY nothing is ever dirty and the answer is 0 locally.  D42:
 * the dirty pages of shared mappings are written back first and their
 * WRITE_ASYNC completions waited for, so the controller's FSYNC covers
 * them; a page it refused is EIO here.
 */
static int
dq_fsync(struct file *fp, int mode, struct thread *td)
{
	struct dq_object *o;
	struct dq_fsync_body fb;
	struct dq_data *reply;
	vm_object_t obj;
	bool event, flushed;
	int error, rerror;

	o = dq_fp_object(fp);
	DQO_LOCK(o);
	event = o->o_policy.dp_write == DQ_EVENT;
	DQO_UNLOCK(o);
	if (!event)
		return (0);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	error = dq_deadlock_check(o, td);
	if (error != 0)
		return (error);
	obj = o->o_object;
	VM_OBJECT_WLOCK(obj);
	flushed = dq_pager_flush(o, obj, 0, IDX_TO_OFF(obj->size), TRUE,
	    FALSE);
	VM_OBJECT_WUNLOCK(obj);
	if (!flushed)
		return (EIO);
	fb.dfs_mode = mode;
	fb.dfs_pad0 = 0;
	error = dq_event_post_wait(o, DQ_OP_FSYNC, &fb, sizeof(fb), td, 0,
	    &reply, &rerror);
	if (error != 0)
		return (error);
	dq_reply_free(reply);
	return (rerror);
}

/*
 * Locks (D98, B6, N11).  Every lock operation is a LOCK event the
 * requester waits for without a deadline (a blocked SETLKW is legitimate
 * for any length of time; a signal posts INTERRUPT as for any delivered
 * event); the controller owns the lock table and its deadlock detection.
 * The close-time unlocks (F_CLOSEUNLCK from closef, fdclearlocks and the
 * fcntl race recheck; FHASLOCK/FHASOFDLOCK in dq_close) post UNLOCK_ALL
 * without waiting, and only when a LOCK of that kind was ever posted on
 * the object (D14's fast path).
 */
static int
dq_advlock(struct file *fp, void *id, int op, struct flock *fl, int flags,
    struct thread *td)
{
	struct dq_object *o;
	struct dq_lock_body lb;
	struct dq_unlock_all_body ub;
	const struct dq_lock_reply *lr;
	struct dq_data *reply;
	off_t start, end, oadd, size;
	uint32_t kind, kindbit;
	int error, rerror;
	bool posted;

	/* path_advlock: only the POSIX release a close owes. */
	if (DQ_OPATH(fp) && (op != F_UNLCK || (flags & F_POSIX) == 0))
		return (EBADF);
	o = dq_fp_object(fp);
	if ((flags & F_FLOCK) != 0) {
		kind = DQ_LOCK_FLOCK;
		kindbit = DQ_LOCKED_FLOCK;
	} else if ((flags & F_OFD) != 0) {
		kind = DQ_LOCK_OFD;
		kindbit = DQ_LOCKED_OFD;
	} else if ((flags & F_POSIX) != 0) {
		kind = DQ_LOCK_POSIX;
		kindbit = DQ_LOCKED_POSIX;
	} else
		return (EINVAL);	/* F_REMOTE: no remote owner exists */

	if ((flags & F_CLOSEUNLCK) != 0) {
		KASSERT(op == F_UNLCK && kind == DQ_LOCK_POSIX,
		    ("dq: F_CLOSEUNLCK with op %d flags %#x", op, flags));
		DQO_LOCK(o);
		posted = (o->o_locked & kindbit) != 0 &&
		    o->o_state == DQ_OBJ_LIVE;
		DQO_UNLOCK(o);
		if (posted) {
			ub.dua_kind = kind;
			ub.dua_pad0 = 0;
			ub.dua_owner = dq_lock_owner(id, flags);
			dq_event_post_nowait(o->o_queue, o, DQ_OP_UNLOCK_ALL, &ub,
			    sizeof(ub), td);
		}
		return (0);
	}

	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	bzero(&lb, sizeof(lb));
	switch (op) {
	case F_GETLK:
		lb.dl_op = DQ_LOCK_GETLK;
		break;
	case F_SETLK:
	case F_SETLKW:
		if (fl->l_type == F_UNLCK)
			lb.dl_op = DQ_LOCK_UNLCK;
		else
			lb.dl_op = (op == F_SETLKW || (flags & F_WAIT) != 0) ?
			    DQ_LOCK_SETLKW : DQ_LOCK_SETLK;
		break;
	case F_UNLCK:
		lb.dl_op = DQ_LOCK_UNLCK;
		break;
	default:
		return (EINVAL);	/* F_UNLCKSYS, F_CANCEL */
	}
	if (fl->l_type != F_RDLCK && fl->l_type != F_WRLCK &&
	    fl->l_type != F_UNLCK)
		return (EINVAL);

	/* The range as lf_advlock normalises it (kern_lockf.c). */
	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:	/* fcntl added the offset already */
		start = fl->l_start;
		break;
	case SEEK_END:
		DQO_LOCK(o);
		size = o->o_ident.di_size;
		DQO_UNLOCK(o);
		if (fl->l_start > 0 && size > OFF_MAX - fl->l_start)
			return (EOVERFLOW);
		start = size + fl->l_start;
		break;
	default:
		return (EINVAL);
	}
	if (start < 0)
		return (EINVAL);
	if (fl->l_len < 0) {
		if (start == 0)
			return (EINVAL);
		end = start - 1;
		start += fl->l_len;
		if (start < 0)
			return (EINVAL);
	} else if (fl->l_len == 0) {
		end = OFF_MAX;
	} else {
		oadd = fl->l_len - 1;
		if (oadd > OFF_MAX - start)
			return (EOVERFLOW);
		end = start + oadd;
	}
	lb.dl_kind = kind;
	lb.dl_type = fl->l_type;
	lb.dl_start = start;
	lb.dl_len = end == OFF_MAX ? 0 : end - start + 1;
	lb.dl_owner = dq_lock_owner(id, flags);
	lb.dl_pid = kind == DQ_LOCK_POSIX ? ((struct proc *)id)->p_pid : -1;

	/*
	 * Recorded before the wait: a SETLKW the requester abandons may
	 * still be granted by a controller that has not yet seen the
	 * INTERRUPT, and the close-time UNLOCK_ALL must then reach it.
	 */
	if (lb.dl_op == DQ_LOCK_SETLK || lb.dl_op == DQ_LOCK_SETLKW) {
		/* A controller refused with EDEADLK leaves no mark behind. */
		error = dq_deadlock_check(o, td);
		if (error != 0)
			return (error);
		/* POSIX: every sibling of the identity too (B4). */
		dq_object_mark_locked(o, kindbit);
	}
	error = dq_event_post_wait(o, DQ_OP_LOCK, &lb, sizeof(lb), td,
	    DQ_POST_NODEADLINE | DQ_POST_LOCK, &reply, &rerror);
	if (error != 0)
		return (error);
	if (rerror == 0 && lb.dl_op == DQ_LOCK_GETLK) {
		/* Validated by the reply path as fusefs validates it. */
		lr = (const struct dq_lock_reply *)reply->dd_bytes;
		fl->l_type = lr->dlr_type;
		fl->l_whence = SEEK_SET;
		if (lr->dlr_type != F_UNLCK) {
			fl->l_start = lr->dlr_start;
			fl->l_len = lr->dlr_len;
			fl->l_pid = lr->dlr_pid;
			fl->l_sysid = 0;
		}
	}
	dq_reply_free(reply);
	return (rerror);
}

/*
 * Local answers
 */

/*
 * The ioctls a regular file answers from state the identity carries stay
 * local; everything else is an IOCTL event under dp_ioctl = EVENT (D99,
 * N6), carrying the generic layer's post-copyin argument for IOC_IN
 * commands and the integer of an int-sized IOC_VOID command, never a raw
 * pointer value.  The kernel cannot tell a pointer-embedding command from
 * its number: the controller refuses what it cannot serve with ENOTTY.
 */
static int
dq_ioctl(struct file *fp, u_long com, void *data, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_object *o;
	struct dq_ioctl_body *ib;
	struct dq_data *reply;
	off_t size, *offp;
	size_t inlen, parmlen, bodylen;
	bool event;
	int error, rerror;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	DQO_LOCK(o);
	size = o->o_ident.di_size;
	event = o->o_policy.dp_ioctl == DQ_EVENT;
	DQO_UNLOCK(o);
	switch (com) {
	case FIONREAD:
		/* As vn_ioctl: the int truncation is the real file's too. */
		*(int *)data = size - fp->f_offset;
		return (0);
	case FIONBIO:
	case FIOASYNC:
		return (0);
	case FIOSEEKDATA:
	case FIOSEEKHOLE:
		offp = data;
		if (*offp < 0 || *offp >= size)
			return (ENXIO);
		if (com == FIOSEEKHOLE)
			*offp = size;
		return (0);
	case FIOBMAP2:
		return (EOPNOTSUPP);	/* no VOP_BMAP to run; declared */
	default:
		break;
	}
	if (!event)
		return (ENOTTY);	/* dp_ioctl = DENY */
	error = dq_object_usable(o);
	if (error != 0)
		return (error);

	parmlen = IOCPARM_LEN(com);
	if ((com & IOC_IN) != 0)
		inlen = parmlen;
	else if ((com & IOC_VOID) != 0 && parmlen == sizeof(int))
		inlen = sizeof(int);	/* sys_ioctl: data points at the int */
	else
		inlen = 0;
	bodylen = roundup2(sizeof(*ib) + inlen, 8);
	ib = malloc(bodylen, M_DQ, M_WAITOK | M_ZERO);
	ib->dio_cmd = com;
	ib->dio_len = inlen;
	if (inlen != 0)
		memcpy(ib + 1, data, inlen);
	error = dq_event_post_wait(o, DQ_OP_IOCTL, ib, bodylen, td, 0, &reply,
	    &rerror);
	free(ib, M_DQ);
	if (error != 0)
		return (error);
	if (rerror == 0 && (com & IOC_OUT) != 0) {
		/* The reply path required exactly IOCPARM_LEN bytes. */
		memcpy(data, reply->dd_bytes, parmlen);
	}
	dq_reply_free(reply);
	return (rerror);
}

static int
dq_poll(struct file *fp, int events, struct ucred *active_cred __unused,
    struct thread *td __unused)
{

	if (DQ_OPATH(fp))
		return (POLLNVAL);
	return (poll_no_poll(events));
}

static void
dq_kqdetach(struct knote *kn)
{
	struct dq_object *o = kn->kn_hook;

	knlist_remove(&o->o_sel.si_note, kn, 0);
}

static int
dq_kqread(struct knote *kn, long hint)
{
	struct dq_object *o = kn->kn_hook;

	DQO_LOCK_ASSERT(o);
	if (hint == NOTE_REVOKE || o->o_state != DQ_OBJ_LIVE) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}
	kn->kn_data = o->o_ident.di_size - kn->kn_fp->f_offset;
	return ((kn->kn_sfflags & NOTE_FILE_POLL) != 0 || kn->kn_data != 0);
}

static int
dq_kqwrite(struct knote *kn, long hint)
{
	struct dq_object *o = kn->kn_hook;

	DQO_LOCK_ASSERT(o);
	if (hint == NOTE_REVOKE || o->o_state != DQ_OBJ_LIVE)
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
	kn->kn_data = 0;
	return (1);
}

static int
dq_kqvnode(struct knote *kn, long hint)
{
	struct dq_object *o = kn->kn_hook;

	DQO_LOCK_ASSERT(o);
	if ((kn->kn_sfflags & hint) != 0)
		kn->kn_fflags |= hint;
	if (hint == NOTE_REVOKE || o->o_state != DQ_OBJ_LIVE) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (kn->kn_fflags != 0);
}

static const struct filterops dq_rfiltops = {
	.f_isfd = 1,
	.f_detach = dq_kqdetach,
	.f_event = dq_kqread,
};
static const struct filterops dq_wfiltops = {
	.f_isfd = 1,
	.f_detach = dq_kqdetach,
	.f_event = dq_kqwrite,
};
static const struct filterops dq_vfiltops = {
	.f_isfd = 1,
	.f_detach = dq_kqdetach,
	.f_event = dq_kqvnode,
};

static int
dq_kqfilter(struct file *fp, struct knote *kn)
{
	struct dq_object *o;

	if (DQ_OPATH(fp) && (fp->f_flag & FKQALLOWED) == 0)
		return (EBADF);
	o = dq_fp_object(fp);
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &dq_rfiltops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &dq_wfiltops;
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &dq_vfiltops;
		break;
	default:
		return (EINVAL);
	}
	kn->kn_hook = o;
	knlist_add(&o->o_sel.si_note, kn, 0);
	return (0);
}

static int
dq_seek(struct file *fp, off_t offset, int whence, struct thread *td)
{
	struct dq_object *o;
	off_t foffset, size;
	int error;

	o = dq_fp_object(fp);
	if (whence == L_INCR && offset == 0) {
		foffset = foffset_get(fp);
		if (__predict_false(foffset < 0))
			return (EOVERFLOW);
		td->td_uretoff.tdu_off = foffset;
		return (0);
	}
	DQO_LOCK(o);
	size = o->o_ident.di_size;
	DQO_UNLOCK(o);
	foffset = foffset_lock(fp, 0);
	error = 0;
	switch (whence) {
	case L_INCR:
		if (foffset < 0 || (offset > 0 && foffset > OFF_MAX - offset)) {
			error = EOVERFLOW;
			break;
		}
		offset += foffset;
		break;
	case L_XTND:
		if (offset > 0 && size > OFF_MAX - offset) {
			error = EOVERFLOW;
			break;
		}
		offset += size;
		break;
	case L_SET:
		break;
	case SEEK_DATA:
	case SEEK_HOLE:
		if (offset < 0 || offset >= size)
			error = ENXIO;
		else if (whence == SEEK_HOLE)
			offset = size;
		break;
	default:
		error = EINVAL;
	}
	if (error == 0 && offset < 0)
		error = EINVAL;
	if (error == 0) {
		DQO_LOCK(o);
		dq_file_knote(o, 0);
		DQO_UNLOCK(o);
		td->td_uretoff.tdu_off = offset;
	}
	foffset_unlock(fp, offset, error != 0 ? FOF_NOUPDATE : 0);
	return (error);
}

static int
dq_fcntl(struct file *fp, int cmd, intptr_t arg, struct thread *td)
{

	switch (cmd) {
	case F_READAHEAD:
		/* No read-ahead exists to size; the flag is kept as vn_fcntl keeps it. */
		if (arg >= 0)
			atomic_set_int(&fp->f_flag, FRDAHEAD);
		else
			atomic_clear_int(&fp->f_flag, FRDAHEAD);
		return (0);
	case F_ISUNIONSTACK:
		td->td_retval[0] = 0;
		return (0);
	case F_GET_RW_HINT:
		td->td_retval[0] = 0;	/* WRITE_LIFE_NOT_SET */
		return (0);
	case F_SET_RW_HINT:
		return (EPERM);		/* N12: a hint without a vnode has no consumer */
	default:
		return (EINVAL);
	}
}

/*
 * mmap(2) (D103), in shm_mmap's and vn_mmap's shape.  maxprot: READ with
 * FREAD, EXECUTE unless the presented filesystem is MNT_NOEXEC (as
 * vn_mmap); a private mapping may always be written (copy-on-write into an
 * anonymous shadow: DFLAG_PRIVWRITE); a shared one only with FWRITE and
 * dp_mmap_shared_write = ALLOW, else PROT_WRITE is EACCES as on a read-only
 * descriptor; then the capability's maximum.  mac_file_check_mmap ran at
 * the boundary.  The mapping holds the file (vm_mmap_file with the owner,
 * N15), so dq_close and its flock/OFD release, CLOSE and NOTE_CLOSE happen
 * at the last munmap when a mapping outlives the descriptor (N9).
 */
static int
dq_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t cap_maxprot, int flags, vm_ooffset_t foff,
    struct thread *td)
{
	struct dq_object *o;
	vm_object_t obj;
	vm_prot_t maxprot;
	uint64_t fsflags;
	uint32_t sharedw;
	bool writecnt;
	int error;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	DQO_LOCK(o);
	fsflags = o->o_ident.di_statfs.ds_flags;
	sharedw = o->o_policy.dp_mmap_shared_write;
	DQO_UNLOCK(o);

	if ((fsflags & MNT_NOEXEC) != 0) {
		maxprot = VM_PROT_NONE;
		if ((prot & VM_PROT_EXECUTE) != 0)
			return (EACCES);
	} else
		maxprot = VM_PROT_EXECUTE;
	if ((fp->f_flag & FREAD) != 0)
		maxprot |= VM_PROT_READ;
	else if ((prot & VM_PROT_READ) != 0)
		return (EACCES);
	writecnt = false;
	if ((flags & MAP_SHARED) != 0) {
		if ((fp->f_flag & FWRITE) != 0 && sharedw == DQ_ALLOW)
			maxprot |= VM_PROT_WRITE;
		else if ((prot & VM_PROT_WRITE) != 0)
			return (EACCES);
	} else
		maxprot |= VM_PROT_WRITE;
	maxprot &= cap_maxprot;
	if ((flags & MAP_SHARED) != 0 && (maxprot & VM_PROT_WRITE) != 0)
		writecnt = true;

	/* As vn_mmap and shm_mmap: an offset inside the object, no wrap. */
	if (size > OFF_MAX || foff > OFF_MAX - size)
		return (EINVAL);

	obj = o->o_object;
	vm_object_reference(obj);
	if (writecnt)
		vm_pager_update_writecount(obj, 0, size);
	error = vm_mmap_file(map, addr, size, prot, maxprot, flags, obj, foff,
	    writecnt, td, map == &td->td_proc->p_vmspace->vm_map ? fp : NULL);
	if (error != 0) {
		if (writecnt)
			vm_pager_release_writecount(obj, 0, size);
		vm_object_deallocate(obj);
	}
	return (error);
}

/*
 * sendfile(2) (D104): the table answers; the f_type switch in
 * sendfile_getobj gains no arm.  The source is the object's pager object,
 * referenced while the transfer runs; its size is the pager's (o_vmsize,
 * which follows the identity), re-read for each chunk, and a revoked
 * object stops the transfer with EIO.  The syscall runs no file hook, so the read admission is checked
 * here (N8).  Pages are filled by getpages_async (READ_ASYNC).
 */
static int
dq_sendfile_getsize(struct sendfile_src *ss, struct thread *td __unused,
    off_t *sizep)
{
	struct dq_object *o;
	int error;

	o = ss->ss_priv;
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	/* The pager's size, as vnode sendfile uses vnp_size. */
	*sizep = dq_object_vmsize(o);
	return (0);
}

static void
dq_sendfile_accessed(struct sendfile_src *ss)
{
	struct dq_object *o;

	o = ss->ss_priv;
	DQO_LOCK(o);
	dq_file_knote(o, NOTE_READ);
	DQO_UNLOCK(o);
}

static void
dq_sendfile_release(struct sendfile_src *ss)
{

	vm_object_deallocate(ss->ss_obj);
}

static const struct sendfile_src_ops dq_sendfile_ops = {
	.ss_getsize = dq_sendfile_getsize,
	.ss_accessed = dq_sendfile_accessed,
	.ss_release = dq_sendfile_release,
};

static int
dq_sendfile(struct file *fp, int sockfd, struct uio *hdr_uio,
    struct uio *trl_uio, off_t offset, size_t nbytes, off_t *sent, int flags,
    struct thread *td)
{
	struct dq_object *o;
	struct sendfile_src ss;
	int error;

	if (DQ_OPATH(fp))
		return (EBADF);
	o = dq_fp_object(fp);
	if (sent != NULL)
		*sent = 0;
	error = dq_object_usable(o);
	if (error == 0)
		error = dq_deadlock_check(o, td);
	if (error == 0)
		error = mac_file_check_read(td->td_ucred, fp->f_cred, fp);
	if (error != 0)
		return (error);
	bzero(&ss, sizeof(ss));
	ss.ss_ops = &dq_sendfile_ops;
	ss.ss_obj = o->o_object;
	ss.ss_priv = o;
	ss.ss_size = dq_object_vmsize(o);
	vm_object_reference(ss.ss_obj);
	return (sendfile_send(&ss, sockfd, hdr_uio, trl_uio, offset, nbytes,
	    sent, flags, td));
}

static int
dq_add_seals(struct file *fp __unused, int flags __unused)
{

	return (EINVAL);
}

static int
dq_get_seals(struct file *fp __unused, int *flags __unused)
{

	return (EINVAL);
}

static int
dq_fadvise(struct file *fp __unused, off_t offset __unused, off_t len __unused,
    int advice __unused, struct thread *td __unused)
{

	return (0);		/* vn_fadvise on a VREG: advice accepted */
}

static int
dq_readdir(struct file *fp, struct uio *uio __unused,
    off_t *basep __unused, struct thread *td __unused)
{

	if (DQ_OPATH(fp))
		return (EBADF);
	return (ENOTDIR);	/* getdirentries on a regular file */
}

static int
dq_acl(struct file *fp __unused, int op __unused, int type __unused,
    struct acl *aclp __unused, struct thread *td __unused)
{

	return (EOPNOTSUPP);
}

static int
dq_extattr(struct file *fp __unused, int op __unused, int attrnamespace __unused,
    const char *attrname __unused, void *data __unused, size_t nbytes __unused,
    struct uio *auio __unused, struct thread *td __unused)
{

	return (EOPNOTSUPP);
}

/*
 * The last reference: descriptor entries, SCM_RIGHTS in flight, and later
 * mappings and attachments.  td may be NULL (closef_nothread from the
 * unix-domain garbage collector).  Never waits for the controller: the
 * flock/OFD release vn_closefile owes the open file is an UNLOCK_ALL posted
 * without waiting, and NOTE_CLOSE (CLOSE_WRITE for a writable descriptor)
 * reaches the identity's other objects (B7) before the id retires.
 */
static int
dq_close(struct file *fp, struct thread *td)
{
	struct dq_object *o;
	struct dq_unlock_all_body ub;
	u_int locked;
	bool live;

	o = dq_fp_object(fp);
	if ((fp->f_flag & (FHASLOCK | FHASOFDLOCK)) != 0) {
		DQO_LOCK(o);
		locked = o->o_locked;
		live = o->o_state == DQ_OBJ_LIVE;
		DQO_UNLOCK(o);
		ub.dua_pad0 = 0;
		ub.dua_owner = dq_lock_owner(fp, F_FLOCK);
		if (live && (fp->f_flag & FHASLOCK) != 0 &&
		    (locked & DQ_LOCKED_FLOCK) != 0) {
			ub.dua_kind = DQ_LOCK_FLOCK;
			dq_event_post_nowait(o->o_queue, o, DQ_OP_UNLOCK_ALL, &ub,
			    sizeof(ub), td);
		}
		if (live && (fp->f_flag & FHASOFDLOCK) != 0 &&
		    (locked & DQ_LOCKED_OFD) != 0) {
			ub.dua_kind = DQ_LOCK_OFD;
			dq_event_post_nowait(o->o_queue, o, DQ_OP_UNLOCK_ALL, &ub,
			    sizeof(ub), td);
		}
	}
	dq_object_knote_siblings(o,
	    (fp->f_flag & FWRITE) != 0 ? NOTE_CLOSE_WRITE : NOTE_CLOSE);
	fp->f_data = NULL;
	/*
	 * The last reference (a mapping holds one, so this is after the last
	 * munmap: N9).  What was written through MAP_SHARED is not lost: the
	 * dirty pages are written back by a deferred close on dq_taskq, which
	 * then removes the pages, retires the id (CLOSE follows the
	 * write-backs) and drops this reference.  Nothing here waits (I11).
	 */
	dq_object_close_deferred(o);
	return (0);
}

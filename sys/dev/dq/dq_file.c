/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: the dq fileops for DQ_KIND_FILE.
 *
 * A served file is a struct file with this table and no vnode.  Every
 * answer a regular file gives from its vnode this table gives from the
 * presented identity or from the controller: fstat, fstatfs, fpathconf,
 * F_KINFO and realpath read the identity; read posts READ events; seek,
 * poll, kqueue and the ioctls a regular file answers locally are local.
 * Stage 1a serves read-only descriptors: the mutating operations answer
 * exactly what a read-only descriptor on a real file answers (D87), and
 * dq(4) lists each one.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/rangelock.h>
#include <sys/refcount.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <dev/mac_capability/mac_capability_label.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_kern.h>
#include <dev/dq/dq_var.h>

_Static_assert(DQ_MNAMELEN == MNAMELEN, "DQ_MNAMELEN");
_Static_assert(DQ_MFSNAMELEN == MFSNAMELEN, "DQ_MFSNAMELEN");

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
	.fo_sendfile = invfo_sendfile,
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
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE,
};

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
	if ((di->di_mode & (S_ISUID | S_ISGID)) != 0) {
		*reason = DQ_REASON_SETID;
		return (EINVAL);
	}
	if (di->di_blksize < PAGE_SIZE) {
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
 * The set stage 1a accepts (D87): read-only data, no served writes, locks,
 * ioctls, exec or shared writable mappings yet; GETATTR and CLOSE are the
 * optional events.
 */
int
dq_policy_validate(const struct dq_policy *pol, int *reason)
{

	*reason = DQ_REASON_POLICY;
	if (pol->dp_cache != DQ_CACHE_NONE && pol->dp_cache != DQ_CACHE_ATTR)
		return (EINVAL);
	if (pol->dp_write != DQ_DENY || pol->dp_exec != DQ_DENY ||
	    pol->dp_mmap_shared_write != DQ_DENY || pol->dp_lock != DQ_EVENT ||
	    pol->dp_ioctl != DQ_DENY)
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
 * reaches a requester by inheritance until RESOLVE installs it (1c).
 */
int
dq_file_install(struct thread *td, struct dq_object *o,
    const struct dq_policy *pol, int *fdp)
{
	struct fdinstall_prop prop = { .fip_xfer_state = CAP_XFER_NONE };
	struct filecaps fcaps;
	struct file *fp;
	int error;

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		/* No file ever referenced it; retire it here, post no CLOSE. */
		DQO_LOCK(o);
		o->o_policy.dp_events &= ~DQ_EVENTS_CLOSE;
		DQO_UNLOCK(o);
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
	finit(fp, FREAD, DTYPE_DQ, o, &dq_fileops);
	error = finstall_prop(td, fp, fdp, O_CLOEXEC, &fcaps, &prop);
	if (error != 0) {
		filecaps_free(&fcaps);
		DQO_LOCK(o);
		o->o_policy.dp_events &= ~DQ_EVENTS_CLOSE;
		DQO_UNLOCK(o);
	}
	/* On failure this is the last file reference: dq_close retires it. */
	fdrop(fp, td);
	return (error);
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

/*
 * Data
 */

static int
dq_read(struct file *fp, struct uio *uio, struct ucred *active_cred __unused,
    int flags, struct thread *td)
{
	struct dq_object *o;
	struct dq_read_body rb;
	void *reply, *cookie;
	size_t replylen, chunk;
	off_t start, end;
	int error, rerror;

	o = dq_fp_object(fp);
	error = dq_object_usable(o);
	if (error != 0)
		return (error);
	if (uio->uio_resid == 0)
		return (0);
	/* The EDEADLK rule (15.4) is applied by dq_event_post_wait. */

	foffset_lock_uio(fp, uio, flags);
	start = uio->uio_offset;
	if (start < 0) {
		error = EINVAL;
		goto out_offset;
	}
	end = uio->uio_resid > OFF_MAX - start ? OFF_MAX :
	    start + uio->uio_resid;
	cookie = rangelock_rlock(&o->o_rl, start, end);
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
		    &reply, &replylen, &rerror);
		if (error != 0)
			break;
		if (rerror != 0) {
			dq_reply_free(reply);
			error = rerror;
			break;
		}
		if (replylen != 0)
			error = uiomove(reply, replylen, uio);
		dq_reply_free(reply);
		if (error != 0 || replylen < chunk)
			break;	/* a short answer is the end of the file */
	}
	rangelock_unlock(&o->o_rl, cookie);
out_offset:
	foffset_unlock_uio(fp, uio, flags);
	return (error);
}

/* Unreachable: the descriptor has no FWRITE.  The read-only answer. */
static int
dq_write(struct file *fp __unused, struct uio *uio __unused,
    struct ucred *active_cred __unused, int flags __unused,
    struct thread *td __unused)
{

	return (EBADF);
}

static int
dq_truncate(struct file *fp __unused, off_t length __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (EBADF);
}

static int
dq_fallocate(struct file *fp __unused, off_t offset __unused,
    off_t len __unused, struct thread *td __unused)
{

	return (EBADF);
}

static int
dq_fspacectl(struct file *fp __unused, int cmd __unused,
    off_t *offset __unused, off_t *length __unused, int flags __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (EBADF);
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
	void *reply;
	size_t replylen;
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
		    &reply, &replylen, &rerror);
		if (error != 0)
			return (error);
		if (rerror != 0) {
			dq_reply_free(reply);
			return (rerror);
		}
		/* The reply path validated it against the kind. */
		DQO_LOCK(o);
		o->o_ident = *(struct dq_ident_file *)reply;
		DQO_UNLOCK(o);
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

/* The non-owner's answer until SETATTR events arrive (1b). */
static int
dq_chmod(struct file *fp __unused, mode_t mode __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (EPERM);
}

static int
dq_chown(struct file *fp __unused, uid_t uid __unused, gid_t gid __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (EPERM);
}

static int
dq_setattr(struct file *fp __unused, struct vattr *vap __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (EPERM);
}

/*
 * Local answers
 */

static int
dq_ioctl(struct file *fp, u_long com, void *data, struct ucred *active_cred,
    struct thread *td)
{
	struct dq_object *o;
	off_t size, *offp;

	o = dq_fp_object(fp);
	DQO_LOCK(o);
	size = o->o_ident.di_size;
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
		return (ENOTTY);	/* dp_ioctl = DENY in stage 1a */
	}
}

static int
dq_poll(struct file *fp __unused, int events, struct ucred *active_cred __unused,
    struct thread *td __unused)
{

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
		return (EPERM);		/* VADMIN on a real file; D87 */
	default:
		return (EINVAL);
	}
}

static int
dq_mmap(struct file *fp __unused, vm_map_t map __unused,
    vm_offset_t *addr __unused, vm_size_t size __unused, vm_prot_t prot __unused,
    vm_prot_t cap_maxprot __unused, int flags __unused, vm_ooffset_t foff __unused,
    struct thread *td __unused)
{

	return (ENODEV);	/* the dq pager is stage 1b */
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
dq_fsync(struct file *fp __unused, int mode __unused, struct thread *td __unused)
{

	return (0);		/* nothing is dirty on a read-only descriptor */
}

static int
dq_fadvise(struct file *fp __unused, off_t offset __unused, off_t len __unused,
    int advice __unused, struct thread *td __unused)
{

	return (0);		/* vn_fadvise on a VREG: advice accepted */
}

static int
dq_readdir(struct file *fp __unused, struct uio *uio __unused,
    off_t *basep __unused, struct thread *td __unused)
{

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
 * unix-domain garbage collector).  Never waits for the controller.
 */
static int
dq_close(struct file *fp, struct thread *td)
{
	struct dq_object *o;

	o = dq_fp_object(fp);
	fp->f_data = NULL;
	dq_object_retire(o, td);
	dq_object_rele(o);
	return (0);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/envfd.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/resourcevar.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <security/audit/audit.h>

MALLOC_DEFINE(M_ENVFD, "envfd", "environment descriptor objects and values");

/*
 * Global and per-real-UID accounting bound both empty-object spam and value
 * memory.  Object and blob memory remain charged until their final reference
 * is released, including immutable old blobs retained by concurrent readers.
 */
static struct mtx envfd_account_lock;
MTX_SYSINIT(envfd_account_lock, &envfd_account_lock, "envfd accounting",
    MTX_DEF);

static u_long envfd_max_objects = 16384;
static u_long envfd_max_bytes = 64 * 1024 * 1024;
static u_long envfd_max_user_objects = 1024;
static u_long envfd_max_user_bytes = 16 * 1024 * 1024;
static u_long envfd_max_value_size = 1024 * 1024;
static u_long envfd_objects;
static u_long envfd_bytes;

SYSCTL_NODE(_kern, OID_AUTO, envfd, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Environment descriptor limits and accounting");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, max_objects, CTLFLAG_RWTUN,
    &envfd_max_objects, 0, "Maximum system-wide EnvFD objects (0 unlimited)");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, max_bytes, CTLFLAG_RWTUN,
    &envfd_max_bytes, 0, "Maximum system-wide EnvFD kernel bytes (0 unlimited)");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, max_user_objects, CTLFLAG_RWTUN,
    &envfd_max_user_objects, 0, "Maximum EnvFD objects per real UID");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, max_user_bytes, CTLFLAG_RWTUN,
    &envfd_max_user_bytes, 0, "Maximum EnvFD kernel bytes per real UID");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, max_value_size, CTLFLAG_RWTUN,
    &envfd_max_value_size, 0, "Maximum value size for one EnvFD");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, objects, CTLFLAG_RD,
    &envfd_objects, 0, "Current system-wide EnvFD object count");
SYSCTL_ULONG(_kern_envfd, OID_AUTO, bytes, CTLFLAG_RD,
    &envfd_bytes, 0, "Current system-wide EnvFD kernel bytes");

SDT_PROVIDER_DEFINE(envfd);
SDT_PROBE_DEFINE6(envfd, , , create,
    "struct envfd *", "pid_t", "struct ucred *", "uint32_t", "uint64_t",
    "int");
SDT_PROBE_DEFINE6(envfd, , , read,
    "struct envfd *", "pid_t", "struct ucred *", "uint64_t", "uint64_t",
    "int");
SDT_PROBE_DEFINE6(envfd, , , write,
    "struct envfd *", "pid_t", "struct ucred *", "uint64_t", "uint64_t",
    "int");
SDT_PROBE_DEFINE5(envfd, , , seal,
    "struct envfd *", "pid_t", "struct ucred *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(envfd, , , notify,
    "struct envfd *", "pid_t", "uint64_t", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(envfd, , , close,
    "struct envfd *", "pid_t", "struct ucred *", "uint64_t", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE5(envfd, , , deny__capmode,
    "struct envfd *", "pid_t", "struct ucred *", "int", "int");

#define	ENVFD_OP_READ		1
#define	ENVFD_OP_WRITE		2
#define	ENVFD_OP_GETINFO	3
#define	ENVFD_OP_STAT		4
#define	ENVFD_OP_KQUEUE		5

struct envfd_blob {
	u_int		eb_refs;
	size_t		eb_size;
	size_t		eb_alloc_size;
	unsigned char	eb_data[];
};

struct envfd {
	struct mtx	ef_lock;
	struct knlist	ef_knotes;
	struct envfd_blob *ef_blob;
	struct uidinfo	*ef_uidinfo;
	uint64_t	ef_generation;
	uint64_t	ef_max_size;
	uint32_t	ef_flags;
	bool		ef_written;
	char		ef_name[ENVFD_NAME_MAX];
};

static fo_rdwr_t	envfd_read;
static fo_rdwr_t	envfd_write;
static fo_ioctl_t	envfd_ioctl;
static fo_kqfilter_t	envfd_kqfilter;
static fo_stat_t	envfd_stat;
static fo_aio_queue_t	envfd_aio_queue;
static fo_close_t	envfd_close;
static fo_fill_kinfo_t	envfd_fill_kinfo;

static void	envfd_kqdetach(struct knote *kn);
static int	envfd_kqevent(struct knote *kn, long hint);

static const struct filterops envfd_filtops = {
	.f_isfd = 1,
	.f_detach = envfd_kqdetach,
	.f_event = envfd_kqevent,
	.f_copy = knote_triv_copy,
};

static const struct fileops envfd_fileops = {
	.fo_read = envfd_read,
	.fo_write = envfd_write,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = envfd_ioctl,
	/* EnvFD I/O never blocks; value changes use EVFILT_ENVFD. */
	.fo_poll = invfo_poll,
	.fo_kqfilter = envfd_kqfilter,
	.fo_stat = envfd_stat,
	.fo_close = envfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = envfd_fill_kinfo,
	.fo_aio_queue = envfd_aio_queue,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

static int
envfd_account_reserve(struct uidinfo *uip, size_t bytes, bool object)
{
	int error;

	if (bytes > INT_MAX)
		return (EFBIG);
	if (object && !chgenvfdcnt(uip, 1, envfd_max_user_objects))
		return (EMFILE);
	if (bytes != 0 &&
	    !chgenvfdbytes(uip, (int)bytes, envfd_max_user_bytes)) {
		if (object)
			(void)chgenvfdcnt(uip, -1, 0);
		return (ENOMEM);
	}

	error = 0;
	mtx_lock(&envfd_account_lock);
	if (object && envfd_max_objects != 0 &&
	    envfd_objects >= envfd_max_objects)
		error = ENFILE;
	else if (bytes > ULONG_MAX - envfd_bytes)
		error = ENOMEM;
	else if (envfd_max_bytes != 0 &&
	    (envfd_bytes >= envfd_max_bytes ||
	    bytes > envfd_max_bytes - envfd_bytes))
		error = ENOMEM;
	else {
		if (object)
			envfd_objects++;
		envfd_bytes += bytes;
	}
	mtx_unlock(&envfd_account_lock);

	if (error != 0) {
		if (bytes != 0)
			(void)chgenvfdbytes(uip, -(int)bytes, 0);
		if (object)
			(void)chgenvfdcnt(uip, -1, 0);
	}
	return (error);
}

static void
envfd_account_release(struct uidinfo *uip, size_t bytes, bool object)
{

	mtx_lock(&envfd_account_lock);
	KASSERT(envfd_bytes >= bytes,
	    ("%s: releasing %zu with only %lu charged", __func__, bytes,
	    envfd_bytes));
	KASSERT(!object || envfd_objects > 0,
	    ("%s: releasing object with none charged", __func__));
	envfd_bytes -= bytes;
	if (object)
		envfd_objects--;
	mtx_unlock(&envfd_account_lock);

	if (bytes != 0)
		(void)chgenvfdbytes(uip, -(int)bytes, 0);
	if (object)
		(void)chgenvfdcnt(uip, -1, 0);
}

static struct envfd_blob *
envfd_blob_alloc(struct envfd *ef, size_t size, int *errorp)
{
	struct envfd_blob *blob;
	size_t alloc_size;
	int error;

	if (size > SIZE_MAX - offsetof(struct envfd_blob, eb_data)) {
		*errorp = EOVERFLOW;
		return (NULL);
	}
	alloc_size = offsetof(struct envfd_blob, eb_data) + size;
	error = envfd_account_reserve(ef->ef_uidinfo, alloc_size, false);
	if (error != 0) {
		*errorp = error;
		return (NULL);
	}
	blob = malloc(alloc_size, M_ENVFD, M_WAITOK | M_ZERO);
	refcount_init(&blob->eb_refs, 1);
	blob->eb_size = size;
	blob->eb_alloc_size = alloc_size;
	*errorp = 0;
	return (blob);
}

static void
envfd_blob_drop(struct envfd *ef, struct envfd_blob *blob)
{
	size_t alloc_size;

	if (blob == NULL || !refcount_release(&blob->eb_refs))
		return;
	alloc_size = blob->eb_alloc_size;
	explicit_bzero(blob, alloc_size);
	free(blob, M_ENVFD);
	envfd_account_release(ef->ef_uidinfo, alloc_size, false);
}

static uint32_t
envfd_state_locked(const struct envfd *ef)
{

	mtx_assert(&ef->ef_lock, MA_OWNED);
	if (!ef->ef_written)
		return (ENVFD_STATE_UNWRITTEN);
	if ((ef->ef_flags & ENVFD_WRITE_ONCE) != 0)
		return (ENVFD_STATE_SEALED);
	return (ENVFD_STATE_READY);
}

static int
envfd_capmode_check(struct envfd *ef, struct thread *td, int operation)
{

	if ((ef->ef_flags & ENVFD_CAPMODE_ONLY) == 0 ||
	    IN_CAPABILITY_MODE(td))
		return (0);
	SDT_PROBE5(envfd, , , deny__capmode, ef, td->td_proc->p_pid,
	    td->td_ucred, operation, ECAPMODE);
	return (ECAPMODE);
}

int
envfd_create_file(struct thread *td, struct file *fp, const char *name,
    const struct envfd_create_options *options)
{
	struct envfd *ef;
	struct uidinfo *uip;
	size_t namelen;
	int error, fflags;

	namelen = strnlen(name, ENVFD_NAME_MAX);
	if (namelen == ENVFD_NAME_MAX)
		return (ENAMETOOLONG);
	if (namelen == 0 || strchr(name, '=') != NULL)
		return (EINVAL);
	if (options->eco_max_value_size > envfd_max_value_size ||
	    options->eco_max_value_size > INT_MAX -
	    offsetof(struct envfd_blob, eb_data))
		return (EFBIG);

	AUDIT_ARG_FFLAGS(options->eco_flags);
	AUDIT_ARG_VALUE((long)options->eco_max_value_size);
	uip = td->td_ucred->cr_ruidinfo;
	uihold(uip);
	error = envfd_account_reserve(uip, sizeof(*ef), true);
	if (error != 0) {
		uifree(uip);
		SDT_PROBE6(envfd, , , create, NULL, td->td_proc->p_pid,
		    td->td_ucred, options->eco_flags,
		    options->eco_max_value_size, error);
		return (error);
	}

	ef = malloc(sizeof(*ef), M_ENVFD, M_WAITOK | M_ZERO);
	mtx_init(&ef->ef_lock, "envfd", NULL, MTX_DEF);
	knlist_init_mtx(&ef->ef_knotes, &ef->ef_lock);
	ef->ef_uidinfo = uip;
	ef->ef_max_size = options->eco_max_value_size;
	ef->ef_flags = options->eco_flags;
	strlcpy(ef->ef_name, name, sizeof(ef->ef_name));

	fflags = 0;
	switch (options->eco_access) {
	case O_RDONLY:
		fflags = FREAD;
		break;
	case O_WRONLY:
		fflags = FWRITE;
		break;
	case O_RDWR:
		fflags = FREAD | FWRITE;
		break;
	default:
		panic("%s: invalid validated access %#x", __func__,
		    options->eco_access);
	}
	finit(fp, fflags, DTYPE_ENVFD, ef, &envfd_fileops);
	SDT_PROBE6(envfd, , , create, ef, td->td_proc->p_pid, td->td_ucred,
	    options->eco_flags, options->eco_max_value_size, 0);
	return (0);
}

static int
envfd_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct envfd *ef;
	struct envfd_blob *blob;
	uint64_t generation, size;
	int error;

	ef = fp->f_data;
	blob = NULL;
	generation = 0;
	size = 0;
	error = envfd_capmode_check(ef, td, ENVFD_OP_READ);
	if (error != 0)
		goto out;

	mtx_lock(&ef->ef_lock);
	if (!ef->ef_written) {
		error = ENOATTR;
	} else {
		blob = ef->ef_blob;
		KASSERT(blob != NULL, ("%s: written EnvFD without blob", __func__));
		generation = ef->ef_generation;
		size = blob->eb_size;
		if ((uint64_t)uio->uio_resid < size)
			error = EMSGSIZE;
		else
			refcount_acquire(&blob->eb_refs);
	}
	mtx_unlock(&ef->ef_lock);

	if (error == 0) {
		error = uiomove(blob->eb_data, (int)blob->eb_size, uio);
		envfd_blob_drop(ef, blob);
	}
out:
	SDT_PROBE6(envfd, , , read, ef, td->td_proc->p_pid, active_cred,
	    generation, size, error);
	return (error);
}

static int
envfd_write(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct envfd *ef;
	struct envfd_blob *blob, *old_blob;
	size_t original_resid;
	uint32_t notes;
	uint64_t generation;
	int error;

	ef = fp->f_data;
	blob = NULL;
	old_blob = NULL;
	notes = 0;
	generation = 0;
	original_resid = uio->uio_resid;
	error = envfd_capmode_check(ef, td, ENVFD_OP_WRITE);
	if (error != 0)
		goto out;

	/*
	 * Give permanent object state precedence over buffer validation and
	 * allocation.  The checks are repeated at publication to close the
	 * race with another writer.
	 */
	mtx_lock(&ef->ef_lock);
	if ((ef->ef_flags & ENVFD_WRITE_ONCE) != 0 && ef->ef_written)
		error = EROFS;
	else if (ef->ef_generation == UINT64_MAX)
		error = EOVERFLOW;
	mtx_unlock(&ef->ef_lock);
	if (error != 0)
		goto out;
	if ((uint64_t)original_resid > ef->ef_max_size) {
		error = EFBIG;
		goto out;
	}

	/*
	 * This unlocked allocation intentionally charges the complete new
	 * immutable blob while the old blob remains charged.  It therefore
	 * bounds replacement peaks and old versions retained by readers.
	 */
	blob = envfd_blob_alloc(ef, original_resid, &error);
	if (blob == NULL)
		goto out;
	error = uiomove(blob->eb_data, (int)original_resid, uio);
	if (error != 0) {
		envfd_blob_drop(ef, blob);
		blob = NULL;
		goto out;
	}

	mtx_lock(&ef->ef_lock);
	if ((ef->ef_flags & ENVFD_WRITE_ONCE) != 0 && ef->ef_written) {
		error = EROFS;
	} else if (ef->ef_generation == UINT64_MAX) {
		error = EOVERFLOW;
	} else {
		old_blob = ef->ef_blob;
		ef->ef_blob = blob;
		ef->ef_written = true;
		generation = ++ef->ef_generation;
		notes = NOTE_ENVFD_WRITE;
		if ((ef->ef_flags & ENVFD_WRITE_ONCE) != 0)
			notes |= NOTE_ENVFD_SEALED;
		KNOTE_LOCKED(&ef->ef_knotes, notes);
		SDT_PROBE5(envfd, , , notify, ef, td->td_proc->p_pid,
		    generation, original_resid, notes);
		if ((notes & NOTE_ENVFD_SEALED) != 0)
			SDT_PROBE5(envfd, , , seal, ef, td->td_proc->p_pid,
			    active_cred, generation, original_resid);
		blob = NULL;
	}
	mtx_unlock(&ef->ef_lock);

	if (error != 0) {
		envfd_blob_drop(ef, blob);
		blob = NULL;
	} else
		envfd_blob_drop(ef, old_blob);
out:
	SDT_PROBE6(envfd, , , write, ef, td->td_proc->p_pid, active_cred,
	    generation, original_resid, error);
	return (error);
}

static int
envfd_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	struct envfd *ef;
	struct envfd_info *info;
	int error;

	ef = fp->f_data;
	if (cmd != ENVFD_GETINFO)
		return (ENOTTY);
	error = envfd_capmode_check(ef, td, ENVFD_OP_GETINFO);
	if (error != 0)
		return (error);

	info = data;
	memset(info, 0, sizeof(*info));
	info->ei_size = sizeof(*info);
	mtx_lock(&ef->ef_lock);
	info->ei_flags = ef->ef_flags;
	info->ei_state = envfd_state_locked(ef);
	info->ei_value_size = ef->ef_blob == NULL ? 0 : ef->ef_blob->eb_size;
	info->ei_max_value_size = ef->ef_max_size;
	info->ei_generation = ef->ef_generation;
	strlcpy(info->ei_name, ef->ef_name, sizeof(info->ei_name));
	mtx_unlock(&ef->ef_lock);
	return (0);
}

static int
envfd_stat(struct file *fp, struct stat *st, struct ucred *active_cred)
{
	struct envfd *ef;
	int error;

	ef = fp->f_data;
	error = envfd_capmode_check(ef, curthread, ENVFD_OP_STAT);
	if (error != 0)
		return (error);

	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFREG;
	if ((fp->f_flag & FREAD) != 0)
		st->st_mode |= S_IRUSR;
	if ((fp->f_flag & FWRITE) != 0)
		st->st_mode |= S_IWUSR;
	mtx_lock(&ef->ef_lock);
	st->st_size = ef->ef_blob == NULL ? 0 : ef->ef_blob->eb_size;
	st->st_blksize = ef->ef_max_size;
	mtx_unlock(&ef->ef_lock);
	return (0);
}

static int
envfd_aio_queue(struct file *fp __unused, struct kaiocb *job __unused)
{

	return (EOPNOTSUPP);
}

static int
envfd_kqfilter(struct file *fp, struct knote *kn)
{
	struct envfd *ef;
	int error;

	ef = fp->f_data;
	error = envfd_capmode_check(ef, curthread, ENVFD_OP_KQUEUE);
	if (error != 0)
		return (error);
	if (kn->kn_filter != EVFILT_ENVFD ||
	    kn->kn_sfflags == 0 ||
	    (kn->kn_sfflags & ~NOTE_ENVFD_CTRLMASK) != 0)
		return (EINVAL);

	mtx_lock(&ef->ef_lock);
	kn->kn_fop = &envfd_filtops;
	kn->kn_hook = ef;
	kn->kn_flags |= EV_CLEAR;
	knlist_add(&ef->ef_knotes, kn, 1);
	mtx_unlock(&ef->ef_lock);
	return (0);
}

static void
envfd_kqdetach(struct knote *kn)
{
	struct envfd *ef;

	ef = kn->kn_hook;
	mtx_lock(&ef->ef_lock);
	knlist_remove(&ef->ef_knotes, kn, 1);
	mtx_unlock(&ef->ef_lock);
}

static int
envfd_kqevent(struct knote *kn, long hint)
{
	struct envfd *ef;
	uint32_t events;

	ef = kn->kn_hook;
	mtx_assert(&ef->ef_lock, MA_OWNED);
	if (hint == 0)
		return (0);
	events = (uint32_t)hint & NOTE_ENVFD_CTRLMASK & kn->kn_sfflags;
	if (events == 0)
		return (0);
	kn->kn_fflags |= events;
	kn->kn_data = ef->ef_generation;
	kn->kn_kevent.ext[0] =
	    ef->ef_blob == NULL ? 0 : ef->ef_blob->eb_size;
	return (1);
}

static int
envfd_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct envfd *ef;

	ef = fp->f_data;
	kif->kf_type = KF_TYPE_ENVFD;
	mtx_lock(&ef->ef_lock);
	kif->kf_un.kf_envfd.kf_envfd_value_size =
	    ef->ef_blob == NULL ? 0 : ef->ef_blob->eb_size;
	kif->kf_un.kf_envfd.kf_envfd_max_size = ef->ef_max_size;
	kif->kf_un.kf_envfd.kf_envfd_generation = ef->ef_generation;
	kif->kf_un.kf_envfd.kf_envfd_addr = (uintptr_t)ef;
	kif->kf_un.kf_envfd.kf_envfd_flags = ef->ef_flags;
	kif->kf_un.kf_envfd.kf_envfd_state = envfd_state_locked(ef);
	snprintf(kif->kf_path, sizeof(kif->kf_path), "envfd:%s", ef->ef_name);
	mtx_unlock(&ef->ef_lock);
	return (0);
}

static int
envfd_close(struct file *fp, struct thread *td)
{
	struct envfd *ef;
	struct envfd_blob *blob;
	struct ucred *cred;
	struct uidinfo *uip;
	size_t object_size;
	uint64_t generation, size;
	uint32_t state;
	pid_t pid;

	ef = fp->f_data;
	object_size = sizeof(*ef);
	pid = td == NULL ? -1 : td->td_proc->p_pid;
	cred = td == NULL ? NULL : td->td_ucred;
	fp->f_data = NULL;
	mtx_lock(&ef->ef_lock);
	blob = ef->ef_blob;
	ef->ef_blob = NULL;
	generation = ef->ef_generation;
	size = blob == NULL ? 0 : blob->eb_size;
	state = envfd_state_locked(ef);
	mtx_unlock(&ef->ef_lock);

	SDT_PROBE6(envfd, , , close, ef, pid, cred, generation, size, state);
	envfd_blob_drop(ef, blob);
	knlist_destroy(&ef->ef_knotes);
	mtx_destroy(&ef->ef_lock);
	uip = ef->ef_uidinfo;
	explicit_bzero(ef, sizeof(*ef));
	free(ef, M_ENVFD);
	envfd_account_release(uip, object_size, true);
	uifree(uip);
	return (0);
}

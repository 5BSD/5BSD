/* SPDX-License-Identifier: BSD-2-Clause */
/* Issued authority is independent of discovery and UNIX credential privilege. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/ktrace.h>
#include <sys/elf_cache.h>
#include <sys/elf_cache_layout.h>
#include <sys/sysent.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <sys/uio.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/taskqueue.h>
#include <machine/atomic.h>
#include "mac_capability_internal.h"

FEATURE(cap_authority, "Protected process authority independent of discovery");
MALLOC_DEFINE(M_CAP_AUTHORITY, "cap_authority", "issued process authority");

struct authority_issuer {
	volatile u_int refs;
	volatile u_int revoked;
	struct mtx lock;
	struct ucred *cred;
	uint64_t identity;
	uint64_t next;
};
struct cap_authority {
	volatile u_int refs;
	volatile u_int consumed;
	volatile u_int revoked;
	struct authority_issuer *issuer;
	uint64_t identity;
	uint32_t kind;
	uid_t uid;
	uint32_t nexec;
	struct vnode *executable[CAP_AUTH_EXEC_MAX];
	unsigned nlibdirs;
	struct file *libdirs[CAP_AUTH_LIBDIR_MAX];
	struct filecaps libcaps[CAP_AUTH_LIBDIR_MAX];
	struct file *cache_domain;
	bool cache_seed;
	struct task cleanup;
	LIST_ENTRY(cap_authority) application_link;
	bool registered;
};
static struct fileops issuer_ops, token_ops;
struct library_cache {
	struct file *backing;
	struct file *directories[2];
	struct authority_issuer *issuer;
};
struct cache_domain {
	struct file *cache, *layout, *relro;
	struct authority_issuer *issuer;
	struct mtx lock;
	void *layout_bytes;
	size_t layout_size;
	struct stat cache_stat;
	uint64_t identity, base;
	bool seed_claimed, published;
};
static struct fileops domain_ops, domain_relro_ops;
static int cache_domain_create(struct thread *, int, void *);
static int cache_domain_bind(struct thread *, int, void *);
static int cache_domain_get(struct thread *, int, int, void *);
static int cache_domain_publish(struct thread *, int, void *);
static int cache_domain_cache(struct thread *, struct file **);
static struct fileops cache_ops;
static struct file *selected_cache;
static struct mtx cache_lock;
MTX_SYSINIT(library_cache, &cache_lock, "library cache", MTX_DEF);
static int cache_prepare(struct thread *, int, void *);
static int cache_publish(struct thread *, int, void *);
static int cache_get(struct thread *, int, void *);


/* Pinned executable identity, never a caller-supplied pathname or UID. */
#define AUTH_APP_BUCKETS 256
#define AUTH_APP_MAX 4096
static LIST_HEAD(, cap_authority) applications[AUTH_APP_BUCKETS];
static struct mtx application_lock;
MTX_SYSINIT(authority_applications, &application_lock, "authority applications",
    MTX_DEF);
static unsigned application_count;

static unsigned
application_bucket(struct vnode *vp)
{
	return (((uintptr_t)vp >> 8) & (AUTH_APP_BUCKETS - 1));
}

static void
application_remove_locked(struct cap_authority *a)
{
	mtx_assert(&application_lock, MA_OWNED);
	KASSERT(a->registered, ("removing unregistered application"));
	LIST_REMOVE(a, application_link);
	a->registered = false;
	application_count--;
}


static void
issuer_drop(struct authority_issuer *issuer)
{
	if (!refcount_release(&issuer->refs))
		return;
	crfree(issuer->cred);
	mtx_destroy(&issuer->lock);
	free(issuer, M_CAP_AUTHORITY);
}
void
cap_authority_retain(struct cap_authority *authority)
{
	if (authority != NULL)
		refcount_acquire(&authority->refs);
}
static void
authority_free(void *context, int pending __unused)
{
	struct cap_authority *a = context;

	for (unsigned i = 0; i < a->nexec; i++) {
		vn_lock(a->executable[i], LK_EXCLUSIVE | LK_RETRY);
		VOP_UNSET_TEXT_CHECKED(a->executable[i]);
		vput(a->executable[i]);
	}
	for (unsigned i = 0; i < a->nlibdirs; i++) {
		fdrop(a->libdirs[i], curthread);
		filecaps_free(&a->libcaps[i]);
	}
	if (a->cache_domain != NULL)
		fdrop(a->cache_domain, curthread);
	issuer_drop(a->issuer);
	free(a, M_CAP_AUTHORITY);
}
void
cap_authority_drop(struct cap_authority *authority)
{
	if (authority == NULL || !refcount_release(&authority->refs))
		return;
	/* Message destruction can hold a channel mutex. Vnode release may sleep. */
	if (authority->nexec != 0 || authority->nlibdirs != 0 ||
	    authority->cache_domain != NULL)
		taskqueue_enqueue(taskqueue_thread, &authority->cleanup);
	else
		authority_free(authority, 0);
}

static bool
authority_valid(struct proc *p)
{
	struct cap_authority *a = p->p_cap_authority;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	return (a != NULL && !p->p_cap_authority_invalid &&
	    !p->p_cap_authority_pending_exec &&
	    !atomic_load_acq_int(&a->revoked) &&
	    !atomic_load_acq_int(&a->issuer->revoked) &&
	    a->issuer->cred->cr_prison == p->p_ucred->cr_prison);
}
/*
 * Traditional debugging cannot manufacture the target's protected authority.
 * The caller holds target's PROC lock and stabilizes actor (curproc, or the
 * parent under proctree_lock for PT_TRACE_ME). Never wait for a second PROC
 * lock: two processes may simultaneously ask to inspect each other.
 */
int
cap_authority_debug_check(struct proc *actor, struct proc *target)
{
	struct cap_authority *a;
	bool acquired, allowed;

	PROC_LOCK_ASSERT(target, MA_OWNED);
	if (actor == target)
		return (0);
	a = target->p_cap_authority;
	if (a == NULL || target->p_cap_authority_invalid ||
	    atomic_load_acq_int(&a->revoked) ||
	    atomic_load_acq_int(&a->issuer->revoked))
		return (0);
	if (mac_capability_debug_authorized(actor->p_pid, target->p_pid))
		return (0);
	acquired = !PROC_LOCKED(actor);
	if (acquired && !PROC_TRYLOCK(actor))
		return (EBUSY);
	allowed = actor->p_cap_authority == a && authority_valid(actor);
	if (acquired)
		PROC_UNLOCK(actor);
	return (allowed ? 0 : EPERM);
}

struct cap_authority *
cap_authority_hold_locked(struct proc *p)
{
	if (!authority_valid(p))
		return (NULL);
	refcount_acquire(&p->p_cap_authority->refs);
	return (p->p_cap_authority);
}
static void
authority_describe(struct cap_authority *a, struct cap_authority_info *info)
{
	bzero(info, sizeof(*info));
	if (a == NULL)
		return;
	info->issuer = a->issuer->identity;
	info->identity = a->identity;
	info->kind = a->kind;
	info->uid = a->uid;
	info->consumed = atomic_load_acq_int(&a->consumed);
	info->references = refcount_load(&a->refs);
	info->revoked = atomic_load_acq_int(&a->revoked) ||
	    atomic_load_acq_int(&a->issuer->revoked);
}
void
cap_authority_info_locked(struct proc *p, struct cap_authority_info *info)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	/* Self-inspection includes a pending context; valid controls its use. */
	authority_describe(p->p_cap_authority, info);
	info->generation = p->p_cap_authority_generation;
	info->valid = authority_valid(p);
}
void
cap_authority_stamp_locked(struct proc *p, struct cap_authority_stamp *stamp)
{
	struct cap_authority_info info;

	cap_authority_info_locked(p, &info);
	bzero(stamp, sizeof(*stamp));
	/* Pending or invalid contexts never identify an authenticated sender. */
	if (!info.valid)
		return;
	stamp->issuer = info.issuer;
	stamp->identity = info.identity;
	stamp->generation = info.generation;
	stamp->kind = info.kind;
	stamp->uid = info.uid;
	stamp->valid = info.valid;
}
int
cap_authority_check_locked(struct proc *p, struct cap_authority *bound)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	return (bound == NULL || (authority_valid(p) &&
	    p->p_cap_authority == bound) ? 0 : EPERM);
}
void
cap_authority_fork(struct proc *parent, struct proc *child)
{
	PROC_LOCK_ASSERT(parent, MA_OWNED);
	child->p_cap_authority = parent->p_cap_authority;
	if (child->p_cap_authority != NULL)
		refcount_acquire(&child->p_cap_authority->refs);
	child->p_cap_authority_generation = parent->p_cap_authority_generation;
	child->p_cap_authority_invalid = parent->p_cap_authority_invalid;
	child->p_cap_authority_pending_exec = parent->p_cap_authority_pending_exec;
}
void
cap_authority_exit(struct proc *p)
{
	struct cap_authority *old;

	PROC_LOCK(p);
	old = p->p_cap_authority;
	p->p_cap_authority = NULL;
	PROC_UNLOCK(p);
	cap_authority_drop(old);
}
void
cap_authority_cred_changed(struct proc *p, const struct ucred *old,
    const struct ucred *new)
{
	struct cap_authority *a = p->p_cap_authority;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (a == NULL || p->p_cap_authority_invalid)
		return;
	/* UNIX credential changes do not change software authority. A prison
	 * transition invalidates it permanently, even if the process returns. */
	if (old->cr_prison != new->cr_prison) {
		p->p_cap_authority_invalid = true;
		p->p_cap_authority_generation++;
	}
}
/* Called before image activation: privileged code needs a secure loader. */
struct cap_authority *
cap_authority_exec_prepare(struct proc *p, struct vnode *image)
{
	struct cap_authority *a, *selected = NULL;

	PROC_LOCK(p);
	if ((p->p_flag & P_TRACED) != 0 ||
	    (p->p_traceflag & KTRFAC_MASK) != 0 ||
	    (p->p_flag2 & P2_NO_NEW_PRIVS) != 0)
		goto out;
	/* Preserve an explicitly scoped managed launch of this same image. */
	a = p->p_cap_authority;
	if (a != NULL && a->kind == CAP_AUTH_MANAGED &&
	    !p->p_cap_authority_invalid &&
	    !atomic_load_acq_int(&a->revoked) &&
	    !atomic_load_acq_int(&a->issuer->revoked) &&
	    a->issuer->cred->cr_prison == p->p_ucred->cr_prison) {
		for (unsigned i = 0; i < a->nexec; i++) {
			if (a->executable[i] == image) {
				selected = a;
				cap_authority_retain(selected);
				goto out;
			}
		}
	}
	mtx_lock(&application_lock);
	LIST_FOREACH(a, &applications[application_bucket(image)], application_link) {
		if (a->executable[0] == image &&
		    a->issuer->cred->cr_prison == p->p_ucred->cr_prison &&
		    !atomic_load_acq_int(&a->revoked) &&
		    !atomic_load_acq_int(&a->issuer->revoked)) {
			selected = a;
			cap_authority_retain(selected);
			break;
		}
	}
	mtx_unlock(&application_lock);
out:
	PROC_UNLOCK(p);
	return (selected);
}

void
cap_authority_exec(struct proc *p, struct vnode *image,
    struct cap_authority *selected)
{
	struct cap_authority *a = p->p_cap_authority;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (selected != NULL && !atomic_load_acq_int(&selected->revoked) &&
	    !atomic_load_acq_int(&selected->issuer->revoked) &&
	    selected->issuer->cred->cr_prison == p->p_ucred->cr_prison &&
	    (p->p_flag & P_TRACED) == 0 &&
	    (p->p_traceflag & KTRFAC_MASK) == 0 &&
	    (p->p_flag2 & P2_NO_NEW_PRIVS) == 0) {
		for (unsigned i = 0; i < selected->nexec; i++) {
			if (selected->executable[i] != image)
				continue;
			if (selected != a) {
				cap_authority_retain(selected);
				p->p_cap_authority = selected;
				p->p_cap_authority_generation++;
				cap_authority_drop(a);
			}
			p->p_cap_authority_invalid = false;
			p->p_cap_authority_pending_exec = false;
			return;
		}
	}
	if (a == NULL || a->nexec == 0 || p->p_cap_authority_invalid)
		return;
	p->p_cap_authority_invalid = true;
	p->p_cap_authority_pending_exec = false;
	p->p_cap_authority_generation++;
}

int
cap_authority_check(struct thread *td, struct cap_authority *bound)
{
	int error;

	if (bound == NULL)
		return (0); /* An explicitly unbound bearer capability. */
	PROC_LOCK(td->td_proc);
	error = cap_authority_check_locked(td->td_proc, bound);
	PROC_UNLOCK(td->td_proc);
	return (error);
}
static int
issuer_close(struct file *fp, struct thread *td __unused)
{
	struct authority_issuer *issuer = fp->f_data;

	struct cap_authority *a, *next;
	struct file *cache = NULL;
	LIST_HEAD(, cap_authority) removed = LIST_HEAD_INITIALIZER(removed);

	/* Losing the issuer revokes grants and removes its executable catalogue. */
	mtx_lock(&application_lock);
	atomic_store_rel_int(&issuer->revoked, 1);
	for (unsigned i = 0; i < AUTH_APP_BUCKETS; i++) {
		LIST_FOREACH_SAFE(a, &applications[i], application_link, next) {
			if (a->issuer != issuer)
				continue;
			application_remove_locked(a);
			LIST_INSERT_HEAD(&removed, a, application_link);
		}
	}
	mtx_unlock(&application_lock);
	while ((a = LIST_FIRST(&removed)) != NULL) {
		LIST_REMOVE(a, application_link);
		cap_authority_drop(a);
	}
	mtx_lock(&cache_lock);
	if (selected_cache != NULL &&
	    ((struct library_cache *)selected_cache->f_data)->issuer == issuer) {
		cache = selected_cache;
		selected_cache = NULL;
	}
	mtx_unlock(&cache_lock);
	if (cache != NULL)
		fdrop(cache, curthread);
	issuer_drop(issuer);
	return (0);
}
static int
token_close(struct file *fp, struct thread *td __unused)
{
	cap_authority_drop(fp->f_data);
	return (0);
}
static int
authority_stat(struct file *fp __unused, struct stat *st,
    struct ucred *cred __unused)
{
	bzero(st, sizeof(*st));
	st->st_mode = S_IFREG | 0400;
	return (0);
}
static int
authority_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	kif->kf_type = KF_TYPE_UNKNOWN;
	strlcpy(kif->kf_path, fp->f_ops == &issuer_ops ?
	    "authority-issuer" : "authority-grant", sizeof(kif->kf_path));
	return (0);
}
static struct fileops issuer_ops = {
	.fo_read = invfo_rdwr, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = authority_stat, .fo_close = issuer_close,
	.fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile, .fo_cmp = file_kcmp_generic,
	.fo_fill_kinfo = authority_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE,
};
static struct fileops token_ops = {
	.fo_read = invfo_rdwr, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = authority_stat, .fo_close = token_close,
	.fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile, .fo_cmp = file_kcmp_generic,
	.fo_fill_kinfo = authority_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE,
};
static int
install_file(struct thread *td, struct file *fp)
{
	int error, fd;

	error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error == 0)
		td->td_retval[0] = fd;
	return (error);
}
static int
get_object(struct thread *td, int fd, const struct fileops *ops,
    uint64_t right, struct file **fp)
{
	cap_rights_t rights;
	int error;

	error = fget(td, fd, cap_rights_init(&rights, right), fp);
	if (error != 0)
		return (error);
	if ((*fp)->f_ops != ops) {
		fdrop(*fp, td);
		return (EINVAL);
	}
	return (0);
}

/* Installing a token must not bypass descriptor inheritance attenuation. */
static int
get_install_token(struct thread *td, int fd, struct file **fp)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct filedescent *fde;
	cap_rights_t rights;
	int error;

	FILEDESC_SLOCK(fdp);
	error = fget_cap_noref(fdp, fd, cap_rights_init(&rights, CAP_READ),
	    fp, NULL);
	if (error == 0) {
		fde = &fdp->fd_ofiles[fd];
		if ((*fp)->f_ops != &token_ops)
			error = EINVAL;
		else if (fde->fde_clofork_state != CAP_CLOFORK_UNLOCKED ||
		    fde->fde_cloexec_state != CAP_CLOEXEC_UNLOCKED)
			error = ENOTCAPABLE;
		else if (!fhold(*fp))
			error = EBADF;
	}
	FILEDESC_SUNLOCK(fdp);
	return (error);
}
static int
constrain_authority(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_constraint request;
	struct vnode *images[CAP_AUTH_EXEC_MAX];
	unsigned held = 0;
	struct cap_authority *a;
	struct file *issuer, *token;
	struct vnode *vp;
	int error;

	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.reserved != 0 || request.nexec == 0 ||
	    request.nexec > CAP_AUTH_EXEC_MAX ||
	    request.flags != 0)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	error = get_object(td, request.token_fd, &token_ops, CAP_FSTAT, &token);
	if (error != 0) {
		fdrop(issuer, td);
		return (error);
	}
	a = token->f_data;
	if (a->issuer != issuer->f_data || a->kind != CAP_AUTH_MANAGED ||
	    atomic_load_acq_int(&a->revoked) ||
	    a->issuer->cred->cr_prison != td->td_ucred->cr_prison) {
		error = EPERM;
		goto out;
	}
	/* State 2 excludes installation while constraints are prepared. */
	if (!atomic_cmpset_acq_int(&a->consumed, 0, 2)) {
		error = EALREADY;
		goto out;
	}
	if (a->nexec != 0) {
		error = EALREADY;
		goto unlock;
	}
	for (unsigned i = 0; i < request.nexec; i++) {
		error = fgetvp_exec(td, request.executable_fds[i],
		    &cap_fexecve_rights, &vp);
		if (error != 0)
			goto unlock;
		if (vp->v_type != VREG) {
			vrele(vp);
			error = EINVAL;
			goto unlock;
		}
		/* Pin both identity and contents while an authority can select it. */
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_SET_TEXT(vp);
		VOP_UNLOCK(vp);
		if (error != 0) {
			vrele(vp);
			goto unlock;
		}
		images[held++] = vp;
	}
	memcpy(a->executable, images, request.nexec * sizeof(images[0]));
	a->nexec = request.nexec;
	held = 0; /* References now belong to the immutable grant. */
unlock:
	while (held != 0) {
		vp = images[--held];
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		VOP_UNSET_TEXT_CHECKED(vp);
		vput(vp);
	}
	atomic_store_rel_int(&a->consumed, 0);
out:
	fdrop(token, td);
	fdrop(issuer, td);
	return (error);
}

/* Directory references and their existing rights become immutable at install. */
static int
set_library_directories(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_libdirs request;
	struct cap_authority *a;
	struct file *issuer, *token, *files[CAP_AUTH_LIBDIR_MAX];
	struct filecaps caps[CAP_AUTH_LIBDIR_MAX];
	cap_rights_t rights;
	unsigned held = 0;
	int error;

	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.reserved != 0 || request.count == 0 ||
	    request.count > CAP_AUTH_LIBDIR_MAX)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	error = get_object(td, request.token_fd, &token_ops, CAP_FSTAT, &token);
	if (error != 0) {
		fdrop(issuer, td);
		return (error);
	}
	a = token->f_data;
	if (a->issuer != issuer->f_data || a->kind != CAP_AUTH_MANAGED ||
	    atomic_load_acq_int(&a->revoked) ||
	    atomic_load_acq_int(&a->issuer->revoked) ||
	    a->issuer->cred->cr_prison != td->td_ucred->cr_prison) {
		error = EPERM;
		goto out;
	}
	if (!atomic_cmpset_acq_int(&a->consumed, 0, 2)) {
		error = EALREADY;
		goto out;
	}
	if (a->nlibdirs != 0 || a->nexec == 0) {
		error = EINVAL;
		goto unlock;
	}
	for (unsigned i = 0; i < request.count; i++) {
		error = fget_cap(td, request.directory_fds[i],
		    cap_rights_init(&rights, CAP_LOOKUP), NULL, &files[i], &caps[i]);
		if (error != 0)
			goto unlock;
		held++;
		if (files[i]->f_type != DTYPE_VNODE ||
		    files[i]->f_vnode->v_type != VDIR ||
		    (files[i]->f_flag & FREAD) == 0 ||
		    (files[i]->f_flag & FWRITE) != 0) {
			error = EINVAL;
			goto unlock;
		}
	}
	for (unsigned i = 0; i < held; i++) {
		a->libdirs[i] = files[i];
		filecaps_move(&caps[i], &a->libcaps[i]);
	}
	a->nlibdirs = held;
	held = 0;
unlock:
	while (held != 0) {
		held--;
		fdrop(files[held], td);
		filecaps_free(&caps[held]);
	}
	atomic_store_rel_int(&a->consumed, 0);
out:
	fdrop(token, td);
	fdrop(issuer, td);
	return (error);
}

static int
get_library_directory(struct thread *td, int index)
{
	struct cap_authority *a;
	struct filecaps caps;
	int error, result;

	if (index < 0 || index >= CAP_AUTH_LIBDIR_MAX)
		return (EINVAL);
	PROC_LOCK(td->td_proc);
	a = cap_authority_hold_locked(td->td_proc);
	PROC_UNLOCK(td->td_proc);
	if (a == NULL)
		return (ENOENT);
	if ((unsigned)index >= a->nlibdirs) {
		cap_authority_drop(a);
		return (ENOENT);
	}
	filecaps_copy(&a->libcaps[index], &caps, true);
	error = finstall(td, a->libdirs[index], &result, O_CLOEXEC, &caps);
	if (error != 0)
		filecaps_free(&caps);
	else
		td->td_retval[0] = result;
	cap_authority_drop(a);
	return (error);
}

static int
register_application(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_application request;
	struct cap_authority *a, *other;
	struct file *issuer, *token;
	unsigned bucket;
	int error;

	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.reserved != 0)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	error = get_object(td, request.token_fd, &token_ops, CAP_FSTAT, &token);
	if (error != 0) {
		fdrop(issuer, td);
		return (error);
	}
	a = token->f_data;
	if (a->issuer != issuer->f_data || a->kind != CAP_AUTH_MANAGED ||
	    a->issuer->cred->cr_prison != td->td_ucred->cr_prison) {
		error = EPERM;
		goto out;
	}
	/* Serializes with constrain/install: a registered token is consumed. */
	if (!atomic_cmpset_acq_int(&a->consumed, 0, 2)) {
		error = EALREADY;
		goto out;
	}
	if (a->nexec != 1) {
		error = EINVAL;
		goto reset;
	}
	bucket = application_bucket(a->executable[0]);
	mtx_lock(&application_lock);
	if (atomic_load_acq_int(&a->revoked) ||
	    atomic_load_acq_int(&a->issuer->revoked))
		error = EPERM;
	else if (application_count == AUTH_APP_MAX)
		error = ENOSPC;
	else {
		LIST_FOREACH(other, &applications[bucket], application_link) {
			if (other->executable[0] == a->executable[0] &&
			    other->issuer->cred->cr_prison == a->issuer->cred->cr_prison) {
				error = EEXIST;
				break;
			}
		}
	}
	if (error == 0) {
		cap_authority_retain(a);
		a->registered = true;
		LIST_INSERT_HEAD(&applications[bucket], a, application_link);
		application_count++;
		atomic_store_rel_int(&a->consumed, 1);
	}
	mtx_unlock(&application_lock);
reset:
	if (error != 0)
		atomic_store_rel_int(&a->consumed, 0);
out:
	fdrop(token, td);
	fdrop(issuer, td);
	return (error);
}

int
cap_authority_call(struct thread *td, int op, int fd, void *data)
{
	struct cap_authority_spec spec;
	struct cap_authority_info info;
	struct authority_issuer *issuer;
	struct cap_authority *a, *old;
	struct cap_authority_bind binding;
	struct cap_authority_revoke revoke;
	struct mac_capability_instance *instance;
	struct file *fp, *token, *capability, *fresh;
	int error;

	if ((op == CAP_AUTH_ISSUER_CREATE || op == CAP_AUTH_INSTALL ||
	    op == CAP_AUTH_CLEAR) && data != NULL)
		return (EINVAL);
	switch (op) {
	case CAP_CACHE_PREPARE:
		return (cache_prepare(td, fd, data));
	case CAP_CACHE_PUBLISH:
		return (cache_publish(td, fd, data));
	case CAP_CACHE_GET:
		return (cache_get(td, fd, data));
	case CAP_CACHE_DOMAIN_CREATE:
		return (cache_domain_create(td, fd, data));
	case CAP_CACHE_DOMAIN_BIND:
		return (cache_domain_bind(td, fd, data));
	case CAP_CACHE_DOMAIN_GET_LAYOUT:
	case CAP_CACHE_DOMAIN_GET_RELRO:
		return (cache_domain_get(td, op, fd, data));
	case CAP_CACHE_DOMAIN_PUBLISH:
		return (cache_domain_publish(td, fd, data));
	case CAP_AUTH_GET_LIBDIR:
		if (data != NULL)
			return (EINVAL);
		return (get_library_directory(td, fd));
	case CAP_AUTH_SET_LIBDIRS:
		return (set_library_directories(td, fd, data));
	case CAP_AUTH_REGISTER_APP:
		return (register_application(td, fd, data));
	case CAP_AUTH_CONSTRAIN:
		return (constrain_authority(td, fd, data));
	case CAP_AUTH_ISSUER_CREATE:
		/* A boot trust anchor, not a superuser privilege. */
		if (td->td_proc != initproc || jailed(td->td_ucred))
			return (EPERM);
		error = falloc_noinstall(td, &fresh);
		if (error != 0)
			return (error);
		issuer = malloc(sizeof(*issuer), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
		refcount_init(&issuer->refs, 1);
		mtx_init(&issuer->lock, "authority issuer", NULL, MTX_DEF);
		issuer->cred = crhold(td->td_ucred);
		do {
			arc4random_buf(&issuer->identity, sizeof(issuer->identity));
		} while (issuer->identity == 0);
		finit(fresh, FREAD | FWRITE, DTYPE_DEV, issuer, &issuer_ops);
		return (install_file(td, fresh));
	case CAP_AUTH_ISSUE:
		error = copyin(data, &spec, sizeof(spec));
		if (error != 0)
			return (error);
		if (spec.version != CAP_AUTH_VERSION || spec.reserved != 0 ||
		    spec.kind != CAP_AUTH_MANAGED)
			return (EINVAL);
		error = get_object(td, fd, &issuer_ops, CAP_WRITE, &fp);
		if (error != 0)
			return (error);
		issuer = fp->f_data;
		if (issuer->cred->cr_prison != td->td_ucred->cr_prison) {
			fdrop(fp, td);
			return (EPERM);
		}
		error = falloc_noinstall(td, &fresh);
		if (error != 0) {
			fdrop(fp, td);
			return (error);
		}
		a = malloc(sizeof(*a), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
		refcount_init(&a->refs, 1);
		TASK_INIT(&a->cleanup, 0, authority_free, a);
		a->issuer = issuer;
		refcount_acquire(&issuer->refs);
		a->kind = spec.kind;
		a->uid = spec.uid;
		mtx_lock(&issuer->lock);
		if (issuer->next == UINT64_MAX)
			error = EOVERFLOW;
		else
			a->identity = ++issuer->next;
		mtx_unlock(&issuer->lock);
		fdrop(fp, td);
		finit(fresh, FREAD, DTYPE_DEV, a, &token_ops);
		if (error != 0) {
			fdrop(fresh, td);
			return (error);
		}
		return (install_file(td, fresh));
	case CAP_AUTH_TOKEN_INFO:
		error = get_object(td, fd, &token_ops, CAP_FSTAT, &fp);
		if (error != 0)
			return (error);
		authority_describe(fp->f_data, &info);
		fdrop(fp, td);
		return (copyout(&info, data, sizeof(info)));
	case CAP_AUTH_INFO:
		PROC_LOCK(td->td_proc);
		cap_authority_info_locked(td->td_proc, &info);
		PROC_UNLOCK(td->td_proc);
		return (copyout(&info, data, sizeof(info)));
	case CAP_AUTH_INSTALL:
		error = get_install_token(td, fd, &fp);
		if (error != 0)
			return (error);
		a = fp->f_data;
		PROC_LOCK(td->td_proc);
		if ((td->td_proc->p_flag & P_TRACED) != 0 ||
		    (td->td_proc->p_traceflag & KTRFAC_MASK) != 0 ||
		    atomic_load_acq_int(&a->revoked) ||
		    atomic_load_acq_int(&a->issuer->revoked) ||
		    a->issuer->cred->cr_prison != td->td_proc->p_ucred->cr_prison)
			error = EPERM;
		else if (!atomic_cmpset_acq_int(&a->consumed, 0, 1))
			error = EALREADY;
		if (error == 0) {
			refcount_acquire(&a->refs);
			old = td->td_proc->p_cap_authority;
			td->td_proc->p_cap_authority = a;
			td->td_proc->p_cap_authority_invalid = false;
			td->td_proc->p_cap_authority_pending_exec = a->nexec != 0;
			td->td_proc->p_cap_authority_generation++;
		} else
			old = NULL;
		PROC_UNLOCK(td->td_proc);
		fdrop(fp, td);
		cap_authority_drop(old);
		return (error);
	case CAP_AUTH_CLEAR:
		PROC_LOCK(td->td_proc);
		old = td->td_proc->p_cap_authority;
		td->td_proc->p_cap_authority = NULL;
		td->td_proc->p_cap_authority_invalid = false;
		td->td_proc->p_cap_authority_pending_exec = false;
		td->td_proc->p_cap_authority_generation++;
		PROC_UNLOCK(td->td_proc);
		cap_authority_drop(old);
		return (0);
	case CAP_AUTH_REVOKE:
		error = copyin(data, &revoke, sizeof(revoke));
		if (error != 0)
			return (error);
		if (revoke.reserved != 0)
			return (EINVAL);
		error = get_object(td, fd, &issuer_ops, CAP_WRITE, &fp);
		if (error != 0)
			return (error);
		error = get_object(td, revoke.token_fd, &token_ops, CAP_FSTAT, &token);
		if (error != 0) {
			fdrop(fp, td);
			return (error);
		}
		a = token->f_data;
		if (a->issuer != fp->f_data ||
		    a->issuer->cred->cr_prison != td->td_ucred->cr_prison)
			error = EPERM;
		else {
			mtx_lock(&application_lock);
			atomic_store_rel_int(&a->revoked, 1);
			old = a->registered ? a : NULL;
			if (old != NULL)
				application_remove_locked(old);
			mtx_unlock(&application_lock);
			cap_authority_drop(old);
		}
		fdrop(token, td);
		fdrop(fp, td);
		return (error);
	case CAP_AUTH_BIND:
		error = copyin(data, &binding, sizeof(binding));
		if (error != 0)
			return (error);
		if (binding.flags != 0 || binding.reserved != 0)
			return (EINVAL);
		error = get_object(td, fd, &issuer_ops, CAP_WRITE, &fp);
		if (error != 0)
			return (error);
		error = get_object(td, binding.token_fd, &token_ops, CAP_FSTAT, &token);
		if (error != 0) {
			fdrop(fp, td);
			return (error);
		}
		a = token->f_data;
		if (a->issuer != fp->f_data ||
		    a->issuer->cred->cr_prison != td->td_ucred->cr_prison)
			error = EPERM;
		else {
			error = get_object(td, binding.capability_fd,
			    &mac_capability_instance_ops, CAP_IOCTL, &capability);
			if (error == 0) {
				instance = capability->f_data;
				mtx_lock(&instance->ci_mtx);
				if (instance->ci_authority != NULL)
					error = EALREADY;
				else {
					refcount_acquire(&a->refs);
					instance->ci_authority = a;
				}
				mtx_unlock(&instance->ci_mtx);
				fdrop(capability, td);
			}
		}
		fdrop(token, td);
		fdrop(fp, td);
		return (error);
	default:
		return (EINVAL);
	}
}

/* A cache descriptor retains the text pin across verification, publication,
 * replacement, descriptor transfer and mmap. Delegation never exposes writes,
 * ioctls, shared mappings, or a mutable shared file offset. */
static int
cache_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags,
    struct thread *td)
{
	struct library_cache *cache = fp->f_data;
	if ((flags & FOF_OFFSET) == 0)
		return (ESPIPE);
	return (fo_read(cache->backing, uio, cred, flags, td));
}
static int
cache_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	struct library_cache *cache = fp->f_data;
	return (fo_stat(cache->backing, st, cred));
}
static int
cache_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t maxprot, int flags, vm_ooffset_t offset,
    struct thread *td)
{
	struct library_cache *cache = fp->f_data;
	struct vnode *vp = cache->backing->f_vnode;
	vm_object_t object;
	boolean_t writecounted = FALSE;
	int error;
	if ((flags & MAP_PRIVATE) == 0 || (flags & MAP_SHARED) != 0 ||
	    (prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
		return (EACCES);
	if ((vp->v_mount->mnt_flag & MNT_NOEXEC) != 0 && (prot & PROT_EXEC) != 0)
		return (EACCES);
	if (size > OFF_MAX || offset > OFF_MAX - size)
		return (EINVAL);
	/* Per-mapping maximum permissions preserve W^X under mprotect too. */
	maxprot = (maxprot | VM_PROT_WRITE) & prot;
	error = vm_mmap_vnode(td, size, prot, &maxprot, &flags, vp,
	    &offset, &object, &writecounted);
	if (error != 0)
		return (error);
	/* Keep this wrapper, hence its text pin, through final unmap, including
	 * fork and partial unmap. Holding only the backing VM object is not a
	 * sufficient immutable-file lifetime guarantee. */
	error = vm_mmap_file(map, addr, size, prot, maxprot, flags, object,
	    offset, writecounted, td, fp);
	if (error != 0)
		vm_object_deallocate(object);
	return (error);
}
static int
cache_close(struct file *fp, struct thread *td)
{
	struct library_cache *cache = fp->f_data;
	struct vnode *vp = cache->backing->f_vnode;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VOP_UNSET_TEXT_CHECKED(vp);
	VOP_UNLOCK(vp);
	fdrop(cache->backing, td);
	for (unsigned i = 0; i < nitems(cache->directories); i++)
		fdrop(cache->directories[i], td);
	issuer_drop(cache->issuer);
	free(cache, M_CAP_AUTHORITY);
	return (0);
}
static int
cache_seek(struct file *fp __unused, off_t offset __unused,
    int whence __unused, struct thread *td __unused)
{
	return (ESPIPE);
}
static int
cache_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	struct library_cache *cache = fp->f_data;
	return (fo_fill_kinfo(cache->backing, kif, fdp));
}
static struct fileops cache_ops = {
	.fo_read = cache_read, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = cache_stat, .fo_close = cache_close,
	.fo_seek = cache_seek, .fo_fill_kinfo = cache_fill_kinfo,
	.fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_mmap = cache_mmap,
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE,
};
static int
cache_prepare(struct thread *td, int issuer_fd, void *data)
{
	struct cap_cache_prepare request;
	struct library_cache *cache;
	struct file *issuer, *backing = NULL, *dirs[2] = {NULL, NULL}, *fresh;
	struct stat st;
	cap_rights_t rights;
	int error;
	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.reserved != 0)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	if (((struct authority_issuer *)issuer->f_data)->cred->cr_prison !=
	    td->td_ucred->cr_prison || jailed(td->td_ucred) ||
	    atomic_load_acq_int(&((struct authority_issuer *)issuer->f_data)->revoked)) {
		error = EPERM;
		goto out;
	}
	error = fget(td, request.backing_fd,
	    cap_rights_init(&rights, CAP_READ, CAP_MMAP_R, CAP_MMAP_X, CAP_FSTAT),
	    &backing);
	if (error != 0)
		goto out;
	if (backing->f_type != DTYPE_VNODE || backing->f_vnode->v_type != VREG ||
	    (backing->f_flag & (FREAD | FWRITE)) != FREAD) {
		error = EINVAL;
		goto out;
	}
	error = fo_stat(backing, &st, td->td_ucred);
	if (error != 0)
		goto out;
	if (st.st_size < (off_t)sizeof(struct elf_cache_header) ||
	    (uint64_t)st.st_size > ELF_CACHE_MAX_SIZE) {
		error = EFBIG;
		goto out;
	}
	for (unsigned i = 0; i < nitems(dirs); i++) {
		error = fget(td, request.directory_fds[i],
		    cap_rights_init(&rights, CAP_LOOKUP), &dirs[i]);
		if (error != 0)
			goto out;
		if (dirs[i]->f_type != DTYPE_VNODE || dirs[i]->f_vnode->v_type != VDIR ||
		    (dirs[i]->f_flag & (FREAD | FWRITE)) != FREAD) {
			error = EINVAL;
			goto out;
		}
	}
	error = falloc_noinstall(td, &fresh);
	if (error != 0)
		goto out;
	vn_lock(backing->f_vnode, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_SET_TEXT(backing->f_vnode);
	VOP_UNLOCK(backing->f_vnode);
	if (error != 0) {
		fdrop(fresh, td);
		goto out;
	}
	cache = malloc(sizeof(*cache), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
	cache->backing = backing;
	cache->directories[0] = dirs[0];
	cache->directories[1] = dirs[1];
	cache->issuer = issuer->f_data;
	refcount_acquire(&cache->issuer->refs);
	backing = dirs[0] = dirs[1] = NULL;
	finit(fresh, FREAD, DTYPE_DEV, cache, &cache_ops);
	error = install_file(td, fresh);
out:
	if (backing != NULL)
		fdrop(backing, td);
	for (unsigned i = 0; i < nitems(dirs); i++)
		if (dirs[i] != NULL)
			fdrop(dirs[i], td);
	fdrop(issuer, td);
	return (error);
}
static int
cache_publish(struct thread *td, int issuer_fd, void *data)
{
	struct cap_cache_publish request;
	struct file *issuer, *cache = NULL, *old;
	int error;
	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.reserved != 0 || request.cache_fd < -1)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	if (request.cache_fd >= 0) {
		error = get_object(td, request.cache_fd, &cache_ops, CAP_READ, &cache);
		if (error != 0)
			goto out;
		if (((struct library_cache *)cache->f_data)->issuer != issuer->f_data) {
			error = EPERM;
			goto out;
		}
	}
	mtx_lock(&cache_lock);
	if (atomic_load_acq_int(&((struct authority_issuer *)issuer->f_data)->revoked) ||
	    ((struct authority_issuer *)issuer->f_data)->cred->cr_prison != td->td_ucred->cr_prison ||
	    (selected_cache != NULL &&
	    ((struct library_cache *)selected_cache->f_data)->issuer != issuer->f_data)) {
		mtx_unlock(&cache_lock);
		error = EPERM;
		goto out;
	}
	old = selected_cache;
	selected_cache = cache;
	cache = NULL;
	mtx_unlock(&cache_lock);
	if (old != NULL)
		fdrop(old, td);
out:
	if (cache != NULL)
		fdrop(cache, td);
	fdrop(issuer, td);
	return (error);
}
static int
cache_get(struct thread *td, int directory_fd, void *data)
{
	struct cap_cache_result result = {0};
	struct library_cache *cache;
	struct file *directory, *selected = NULL;
	struct filecaps caps;
	cap_rights_t rights;
	int error, fd;
	error = fget(td, directory_fd, cap_rights_init(&rights, CAP_LOOKUP), &directory);
	if (error != 0)
		return (error);
	error = cache_domain_cache(td, &selected);
	if (error != 0 && error != ENOENT) {
		fdrop(directory, td);
		return (error);
	}
	mtx_lock(&cache_lock);
	if (selected == NULL && selected_cache != NULL && fhold(selected_cache))
		selected = selected_cache;
	mtx_unlock(&cache_lock);
	error = ENOENT;
	if (selected != NULL && directory->f_type == DTYPE_VNODE) {
		cache = selected->f_data;
		if (cache->issuer->cred->cr_prison == td->td_ucred->cr_prison &&
		    !atomic_load_acq_int(&cache->issuer->revoked)) {
			for (unsigned i = 0; i < nitems(cache->directories); i++) {
				if (directory->f_vnode == cache->directories[i]->f_vnode) {
					result.directory = i;
					error = 0;
					break;
				}
			}
		}
	}
	fdrop(directory, td);
	if (error != 0) {
		if (selected != NULL) fdrop(selected, td);
		return (error);
	}
	error = copyout(&result, data, sizeof(result));
	if (error == 0) {
		filecaps_init(&caps);
		/* Restricted cache descriptors delegate no ioctl commands. */
		caps.fc_nioctls = 0;
		cap_rights_init(&caps.fc_rights, CAP_READ, CAP_SEEK, CAP_FSTAT,
		    CAP_MMAP_R, CAP_MMAP_W, CAP_MMAP_X);
		error = finstall(td, selected, &fd, O_CLOEXEC, &caps);
		if (error != 0)
			filecaps_free(&caps);
		else
			td->td_retval[0] = fd;
	}
	fdrop(selected, td);
	return (error);
}

/* Authority-scoped, opt-in common-layout domains. No ambient selection. */
struct domain_io {
	struct file *file;
	struct thread *thread;
};
static int
domain_io(struct file *fp, struct thread *td, uint64_t offset, void *bytes,
    size_t size, enum uio_rw direction)
{
	struct iovec iov = { .iov_base = bytes, .iov_len = size };
	struct uio uio = { .uio_iov = &iov, .uio_iovcnt = 1,
	    .uio_offset = (off_t)offset, .uio_resid = size,
	    .uio_segflg = UIO_SYSSPACE, .uio_rw = direction, .uio_td = td };
	int error;

	if (offset > OFF_MAX || size > OFF_MAX - offset)
		return (EINVAL);
	if (direction == UIO_READ)
		error = fo_read(fp, &uio, td->td_ucred, FOF_OFFSET, td);
	else
		error = fo_write(fp, &uio, td->td_ucred, FOF_OFFSET, td);
	return (error != 0 ? error : uio.uio_resid != 0 ? EIO : 0);
}
static int
domain_cache_read(void *argument, uint64_t offset, void *bytes, size_t size)
{
	struct domain_io *io = argument;
	return (domain_io(io->file, io->thread, offset, bytes, size, UIO_READ));
}
static bool
domain_issuer_valid(struct thread *td, struct authority_issuer *issuer)
{
	return (!jailed(td->td_ucred) &&
	    issuer->cred->cr_prison == td->td_ucred->cr_prison &&
	    !atomic_load_acq_int(&issuer->revoked));
}
static void
domain_header(struct cache_domain *domain, struct elf_cache_relro_header *h)
{
	const struct elf_cache_layout_header *layout = domain->layout_bytes;
	bzero(h, sizeof(*h));
	memcpy(h->magic, "5BSDRLO", 8);
	h->version = htole32(ELF_CACHE_RELRO_VERSION);
	h->header_size = htole32(sizeof(*h));
	h->domain_id = htole64(domain->identity);
	h->domain_base = htole64(domain->base);
	h->count = layout->count;
	h->completed_offset = htole32(sizeof(*h));
	h->file_size = layout->relro_size;
	memcpy(h->cache_sha256, layout->cache_sha256, sizeof(h->cache_sha256));
}
static int
domain_close(struct file *fp, struct thread *td)
{
	struct cache_domain *domain = fp->f_data;
	fdrop(domain->cache, td);
	fdrop(domain->layout, td);
	fdrop(domain->relro, td);
	issuer_drop(domain->issuer);
	free(domain->layout_bytes, M_CAP_AUTHORITY);
	mtx_destroy(&domain->lock);
	free(domain, M_CAP_AUTHORITY);
	return (0);
}
static int
domain_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	struct cache_domain *domain = fp->f_data;
	return (fo_stat(domain->relro, st, cred));
}
static int
domain_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	kif->kf_type = KF_TYPE_UNKNOWN;
	strlcpy(kif->kf_path, fp->f_ops == &domain_ops ?
	    "elf-cache-domain" : "elf-cache-relro", sizeof(kif->kf_path));
	return (0);
}
static struct fileops domain_ops = {
	.fo_read = invfo_rdwr, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = domain_stat, .fo_close = domain_close,
	.fo_seek = cache_seek, .fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile, .fo_cmp = file_kcmp_generic,
	.fo_fill_kinfo = domain_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE,
};
static struct cache_domain *
relro_domain(struct file *fp)
{
	struct file *owner = fp->f_data;
	return (owner->f_data);
}
static int
domain_relro_read(struct file *fp, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	if ((flags & FOF_OFFSET) == 0) return (ESPIPE);
	return (fo_read(relro_domain(fp)->relro, uio, cred, flags, td));
}
static int
domain_relro_stat(struct file *fp, struct stat *st, struct ucred *cred)
{
	return (fo_stat(relro_domain(fp)->relro, st, cred));
}
static int
domain_relro_seals(struct file *fp, int *seals)
{
	return (fo_get_seals(relro_domain(fp)->relro, seals));
}
static int
domain_relro_mmap(struct file *fp, vm_map_t map, vm_offset_t *address,
    vm_size_t size, vm_prot_t prot, vm_prot_t maxprot, int flags,
    vm_ooffset_t offset, struct thread *td)
{
	struct cache_domain *domain = relro_domain(fp);
	const struct elf_cache_layout_header *layout = domain->layout_bytes;
	uint64_t length = le64toh(layout->relro_size);
	if ((flags & MAP_PRIVATE) == 0 || (flags & MAP_SHARED) != 0 ||
	    (prot & VM_PROT_EXECUTE) != 0 || offset > length || size > length - offset)
		return (EACCES);
	/* Sealed shm owns immutable bytes through its normal object lifetime.
	 * Unlike executable vnode mappings, no vnode text pin is required here.
	 * Maximum RW permits private COW, while execute can never be restored. */
	maxprot &= VM_PROT_READ | VM_PROT_WRITE;
	return (fo_mmap(domain->relro, map, address, size, prot, maxprot,
	    flags, offset, td));
}
static int
domain_relro_close(struct file *fp, struct thread *td)
{
	fdrop(fp->f_data, td);
	return (0);
}
static struct fileops domain_relro_ops = {
	.fo_read = domain_relro_read, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = domain_relro_stat, .fo_close = domain_relro_close,
	.fo_seek = cache_seek, .fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile, .fo_mmap = domain_relro_mmap,
	.fo_get_seals = domain_relro_seals, .fo_cmp = file_kcmp_generic,
	.fo_fill_kinfo = domain_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE,
};
static int
cache_domain_create(struct thread *td, int issuer_fd, void *data)
{
	struct cap_cache_domain_create request;
	struct file *issuer = NULL, *cache = NULL, *layout = NULL, *relro = NULL, *fresh;
	struct library_cache *c, *l;
	struct cache_domain *domain = NULL;
	struct elf_cache_layout_reader reader;
	struct domain_io io;
	struct stat cache_stat, layout_stat, relro_stat;
	struct elf_cache_relro_header header;
	const struct elf_cache_layout_header *h;
	cap_rights_t rights;
	void *bytes = NULL;
	int error, seals;

#if !defined(__amd64__)
	return (EOPNOTSUPP);
#endif
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) return (EOPNOTSUPP);
	error = copyin(data, &request, sizeof(request));
	if (error != 0) return (error);
	if (request.reserved != 0) return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0) return (error);
	if (!domain_issuer_valid(td, issuer->f_data)) { error = EPERM; goto out; }
	error = get_object(td, request.cache_fd, &cache_ops, CAP_READ, &cache);
	if (error != 0) goto out;
	error = get_object(td, request.layout_fd, &cache_ops, CAP_READ, &layout);
	if (error != 0) goto out;
	c = cache->f_data; l = layout->f_data;
	if (c->issuer != issuer->f_data || l->issuer != c->issuer || cache == layout) {
		error = EPERM; goto out;
	}
	for (unsigned i = 0; i < nitems(c->directories); i++)
		if (c->directories[i]->f_vnode != l->directories[i]->f_vnode) {
			error = EPERM; goto out;
		}
	error = fo_stat(cache, &cache_stat, td->td_ucred);
	if (error != 0) goto out;
	error = fo_stat(layout, &layout_stat, td->td_ucred);
	if (error != 0) goto out;
	if (layout_stat.st_size < (off_t)sizeof(*h) ||
	    layout_stat.st_size > ELF_CACHE_LAYOUT_MAX_SIZE || cache_stat.st_size < 0) {
		error = EINVAL; goto out;
	}
	bytes = malloc((size_t)layout_stat.st_size, M_CAP_AUTHORITY, M_WAITOK);
	error = domain_io(layout, td, 0, bytes, (size_t)layout_stat.st_size, UIO_READ);
	if (error != 0) goto out;
	io = (struct domain_io){ cache, td };
	reader = (struct elf_cache_layout_reader){ domain_cache_read, &io, cache_stat.st_size };
	error = elf_cache_layout_validate(bytes, (size_t)layout_stat.st_size, &reader, EM_X86_64, PAGE_SIZE);
	if (error != 0) goto out;
	error = fget(td, request.relro_fd, cap_rights_init(&rights,
	    CAP_PREAD, CAP_PWRITE, CAP_FSTAT, CAP_FTRUNCATE), &relro);
	if (error != 0) goto out;
	if (relro->f_type != DTYPE_SHM ||
	    (relro->f_flag & (FREAD | FWRITE)) != (FREAD | FWRITE) ||
	    fo_get_seals(relro, &seals) != 0 || seals != 0) { error = EINVAL; goto out; }
	error = fo_stat(relro, &relro_stat, td->td_ucred);
	if (error != 0) goto out;
	if (relro_stat.st_size != 0) { error = EINVAL; goto out; }
	domain = malloc(sizeof(*domain), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
	domain->layout_bytes = bytes; domain->layout_size = layout_stat.st_size;
	domain->cache_stat = cache_stat;
	do { arc4random_buf(&domain->identity, sizeof(domain->identity)); } while (domain->identity == 0);
	domain->base = (1ULL << 40) + ((uint64_t)arc4random_uniform(1U << 24) << 21);
	h = bytes;
	if (domain->base > td->td_proc->p_sysent->sv_maxuser ||
	    le64toh(h->layout_span) > td->td_proc->p_sysent->sv_maxuser - domain->base) { error = EINVAL; goto out; }
	error = fo_truncate(relro, (off_t)le64toh(h->relro_size), td->td_ucred, td);
	if (error != 0) goto out;
	domain_header(domain, &header);
	error = domain_io(relro, td, 0, &header, sizeof(header), UIO_WRITE);
	if (error != 0) goto out;
	if (!domain_issuer_valid(td, issuer->f_data)) { error = EPERM; goto out; }
	error = falloc_noinstall(td, &fresh);
	if (error != 0) goto out;
	domain->cache = cache; domain->layout = layout; domain->relro = relro;
	domain->issuer = issuer->f_data; refcount_acquire(&domain->issuer->refs);
	mtx_init(&domain->lock, "ELF cache domain", NULL, MTX_DEF);
	finit(fresh, FREAD, DTYPE_DEV, domain, &domain_ops);
	cache = layout = relro = NULL; bytes = NULL; domain = NULL;
	error = install_file(td, fresh);
out:
	if (domain != NULL) free(domain, M_CAP_AUTHORITY);
	if (bytes != NULL) free(bytes, M_CAP_AUTHORITY);
	if (relro != NULL) fdrop(relro, td);
	if (layout != NULL) fdrop(layout, td);
	if (cache != NULL) fdrop(cache, td);
	if (issuer != NULL) fdrop(issuer, td);
	return (error);
}
static int
cache_domain_bind(struct thread *td, int issuer_fd, void *data)
{
	struct cap_cache_domain_bind request;
	struct file *issuer = NULL, *token = NULL, *domain_file = NULL;
	struct cap_authority *a;
	struct cache_domain *domain;
	int error;

	error = copyin(data, &request, sizeof(request));
	if (error != 0) return (error);
	if (request.reserved != 0 || (request.flags & ~CAP_CACHE_DOMAIN_SEED) != 0)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0) return (error);
	if (!domain_issuer_valid(td, issuer->f_data)) { error = EPERM; goto out; }
	error = get_object(td, request.token_fd, &token_ops, CAP_FSTAT, &token);
	if (error != 0) goto out;
	error = get_object(td, request.domain_fd, &domain_ops, CAP_READ, &domain_file);
	if (error != 0) goto out;
	a = token->f_data; domain = domain_file->f_data;
	if (a->issuer != issuer->f_data || domain->issuer != a->issuer ||
	    a->kind != CAP_AUTH_MANAGED || atomic_load_acq_int(&a->revoked)) {
		error = EPERM; goto out;
	}
	if (!atomic_cmpset_acq_int(&a->consumed, 0, 2)) { error = EALREADY; goto out; }
	if (a->cache_domain != NULL) { error = EALREADY; goto reset; }
	if ((request.flags & CAP_CACHE_DOMAIN_SEED) != 0 && a->nexec != 1) {
		error = EPERM; goto reset;
	}
	mtx_lock(&domain->lock);
	if (!domain_issuer_valid(td, domain->issuer) || atomic_load_acq_int(&a->revoked))
		error = EPERM;
	else if ((request.flags & CAP_CACHE_DOMAIN_SEED) != 0 &&
	    (domain->seed_claimed || domain->published))
		error = EALREADY;
	else {
		a->cache_seed = (request.flags & CAP_CACHE_DOMAIN_SEED) != 0;
		if (a->cache_seed) domain->seed_claimed = true;
		a->cache_domain = domain_file; domain_file = NULL;
		error = 0;
	}
	mtx_unlock(&domain->lock);
reset:
	atomic_store_rel_int(&a->consumed, 0);
out:
	if (domain_file != NULL) fdrop(domain_file, td);
	if (token != NULL) fdrop(token, td);
	if (issuer != NULL) fdrop(issuer, td);
	return (error);
}
/* Returns a retained current authority, never a caller-selected token. */
static int
domain_current(struct thread *td, struct cap_authority **out)
{
	struct cap_authority *a;
	bool bound;

	*out = NULL;
	PROC_LOCK(td->td_proc);
	bound = td->td_proc->p_cap_authority != NULL &&
	    td->td_proc->p_cap_authority->cache_domain != NULL;
	a = cap_authority_hold_locked(td->td_proc);
	PROC_UNLOCK(td->td_proc);
	if (a == NULL) return (bound ? EPERM : ENOENT);
	if (a->cache_domain == NULL) {
		cap_authority_drop(a); return (ENOENT);
	}
	if (!domain_issuer_valid(td, a->issuer)) {
		cap_authority_drop(a); return (EPERM);
	}
	*out = a;
	return (0);
}
static int
cache_domain_cache(struct thread *td, struct file **out)
{
	struct cap_authority *a;
	struct cache_domain *domain;
	int error;

	*out = NULL;
	error = domain_current(td, &a);
	if (error != 0) return (error);
	domain = a->cache_domain->f_data;
	if (!fhold(domain->cache)) error = EBADF;
	else *out = domain->cache;
	cap_authority_drop(a);
	return (error);
}
static int
cache_domain_get(struct thread *td, int operation, int fd, void *data)
{
	struct cap_authority *a;
	struct cache_domain *domain;
	struct cap_cache_domain_result result = {0};
	struct file *selected = NULL;
	struct filecaps caps;
	bool published;
	int error, installed;

	if (fd != -1) return (EINVAL);
	error = domain_current(td, &a);
	if (error != 0) return (error);
	domain = a->cache_domain->f_data;
	mtx_lock(&domain->lock);
	published = domain->published;
	mtx_unlock(&domain->lock);
	result.domain_id = domain->identity; result.domain_base = domain->base;
	result.cache_device = domain->cache_stat.st_dev;
	result.cache_inode = domain->cache_stat.st_ino;
	result.cache_size = domain->cache_stat.st_size;
	result.flags = (a->cache_seed ? CAP_CACHE_DOMAIN_SEED : 0) |
	    (published ? CAP_CACHE_DOMAIN_READY : 0);
	filecaps_init(&caps);
	/* Restricted cache descriptors delegate no ioctl commands. */
	caps.fc_nioctls = 0;
	if (operation == CAP_CACHE_DOMAIN_GET_LAYOUT) {
		if (!fhold(domain->layout)) { error = EBADF; goto out; }
		selected = domain->layout;
		cap_rights_init(&caps.fc_rights, CAP_PREAD, CAP_FSTAT, CAP_MMAP_R);
	} else if (a->cache_seed) {
		if (published) { error = EPERM; goto out; }
		if (!fhold(domain->relro)) { error = EBADF; goto out; }
		selected = domain->relro;
		/* Capture uses pwrite only; no writable mmap or truncate delegation. */
		cap_rights_init(&caps.fc_rights, CAP_PREAD, CAP_PWRITE, CAP_FSTAT);
	} else {
		if (!published) { error = ENOENT; goto out; }
		error = falloc_noinstall(td, &selected);
		if (error != 0) goto out;
		if (!fhold(a->cache_domain)) { fdrop(selected, td); selected = NULL; error = EBADF; goto out; }
		finit(selected, FREAD, DTYPE_DEV, a->cache_domain, &domain_relro_ops);
		/* CAP_MMAP_W includes CAP_WRITE; the wrapper denies all file writes. */
		cap_rights_init(&caps.fc_rights, CAP_PREAD, CAP_FSTAT, CAP_MMAP_RW);
	}
	error = cap_authority_check(td, a);
	if (error == 0) error = copyout(&result, data, sizeof(result));
	if (error == 0) {
		error = finstall(td, selected, &installed, O_CLOEXEC, &caps);
		if (error == 0) td->td_retval[0] = installed;
	}
out:
	if (error != 0) filecaps_free(&caps);
	if (selected != NULL) fdrop(selected, td);
	cap_authority_drop(a);
	return (error);
}
static int
cache_domain_publish(struct thread *td, int issuer_fd, void *data)
{
	struct cap_cache_domain_publish request;
	struct file *issuer = NULL, *domain_file = NULL;
	struct cache_domain *domain;
	struct elf_cache_relro_header actual, expected;
	const struct elf_cache_layout_header *h;
	const struct elf_cache_layout_entry *entries;
	struct stat st;
	unsigned char *completed = NULL;
	unsigned count, present = 0;
	int error, seals, required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

	error = copyin(data, &request, sizeof(request));
	if (error != 0) return (error);
	if (request.reserved != 0) return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0) return (error);
	if (!domain_issuer_valid(td, issuer->f_data)) { error = EPERM; goto out; }
	error = get_object(td, request.domain_fd, &domain_ops, CAP_READ, &domain_file);
	if (error != 0) goto out;
	domain = domain_file->f_data;
	if (domain->issuer != issuer->f_data) { error = EPERM; goto out; }
	if (fo_get_seals(domain->relro, &seals) != 0 || (seals & required) != required) {
		error = EPERM; goto out;
	}
	h = domain->layout_bytes; entries = (const void *)(h + 1); count = le32toh(h->count);
	error = fo_stat(domain->relro, &st, td->td_ucred);
	if (error != 0) goto out;
	if (st.st_size < 0 || (uint64_t)st.st_size != le64toh(h->relro_size)) { error = EINVAL; goto out; }
	error = domain_io(domain->relro, td, 0, &actual, sizeof(actual), UIO_READ);
	if (error != 0) goto out;
	domain_header(domain, &expected);
	if (memcmp(&actual, &expected, sizeof(actual)) != 0) { error = EINVAL; goto out; }
	completed = malloc(count, M_CAP_AUTHORITY, M_WAITOK);
	error = domain_io(domain->relro, td, sizeof(actual), completed, count, UIO_READ);
	if (error != 0) goto out;
	for (unsigned i = 0; i < count; i++) {
		if (completed[i] > 1 || (completed[i] != 0 && entries[i].relro_size == 0)) {
			error = EINVAL; goto out;
		}
		present += completed[i] != 0;
	}
	if (present == 0) { error = ENOENT; goto out; }
	mtx_lock(&domain->lock);
	if (!domain_issuer_valid(td, domain->issuer)) error = EPERM;
	else if (!domain->seed_claimed || domain->published) error = EALREADY;
	else { domain->published = true; error = 0; }
	mtx_unlock(&domain->lock);
out:
	if (completed != NULL) free(completed, M_CAP_AUTHORITY);
	if (domain_file != NULL) fdrop(domain_file, td);
	if (issuer != NULL) fdrop(issuer, td);
	return (error);
}

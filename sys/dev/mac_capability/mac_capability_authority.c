/* SPDX-License-Identifier: BSD-2-Clause */
/* Issued authority is independent of discovery and UNIX credential privilege. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/callout.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/ktrace.h>
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
#include <sys/procdesc.h>
#include <sys/sx.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/taskqueue.h>
#include <machine/atomic.h>
#include "mac_capability_internal.h"
#include "mac_capability_label.h"

FEATURE(cap_authority, "Protected process authority independent of discovery");
MALLOC_DEFINE(M_CAP_AUTHORITY, "cap_authority", "issued process authority");

struct authority_issuer {
	volatile u_int refs;
	volatile u_int revoked;
	struct mtx lock;
	struct ucred *cred;
	struct task cleanup;
	uint64_t identity;
	uint64_t next;
	LIST_HEAD(, cap_authority_lease) leases;
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
	struct task cleanup;
	LIST_ENTRY(cap_authority) application_link;
	bool registered;
};
/* One lazily allocated dependency state per observed invocation. The process
 * owns one reference; users retain the state, never the process. Revocation is
 * sticky and checked without taking another process lock from storage locks. */
struct cap_authority_invocation {
	volatile u_int refs, revoked;
	struct cap_authority *authority;
};

void
cap_authority_invocation_release(struct cap_authority_invocation *invocation)
{
	if (invocation != NULL && refcount_release(&invocation->refs)) {
		cap_authority_drop(invocation->authority);
		free(invocation, M_CAP_AUTHORITY);
	}
}

bool
cap_authority_invocation_valid(const struct cap_authority_invocation *invocation)
{
	return (invocation == NULL ||
	    (!atomic_load_acq_int(&invocation->revoked) &&
	    !atomic_load_acq_int(&invocation->authority->revoked) &&
	    !atomic_load_acq_int(&invocation->authority->issuer->revoked)));
}

void
cap_authority_invocation_invalidate_locked(struct proc *p)
{
	struct cap_authority_invocation *invocation;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	invocation = p->p_cap_invocation;
	p->p_cap_invocation = NULL;
	if (invocation != NULL) {
		atomic_store_rel_int(&invocation->revoked, 1);
		cap_authority_invocation_release(invocation);
	}
}

struct cap_authority_lease {
	volatile u_int refs, revoked;
	struct authority_issuer *issuer;
	struct mtx lock;
	struct callout expiry;
	struct task cleanup;
	sbintime_t deadline;
	LIST_HEAD(, mac_capability_instance) endpoints;
	LIST_ENTRY(cap_authority_lease) issuer_link;
};
static struct fileops issuer_ops, token_ops, lease_control_ops, lease_owner_ops;
static void lease_revoke(struct cap_authority_lease *);
/* Pinned executable identity, never a caller-supplied pathname or UID. */
#define AUTH_APP_BUCKETS 256
#define AUTH_APP_MAX 4096
static LIST_HEAD(, cap_authority) applications[AUTH_APP_BUCKETS];
static struct mtx application_lock;
MTX_SYSINIT(authority_applications, &application_lock, "authority applications",
    MTX_DEF);
static unsigned application_count;
static volatile uint64_t execution_sequence;
static volatile uint64_t issuer_sequence;

/*
 * Kernel-only identities: fork preserves a family; exec and explicit authority
 * installation start another. Never recycle an identity. Exhaustion removes
 * implicit family debugging rather than allowing unrelated executions to match.
 */
static uint64_t
next_identity(volatile uint64_t *sequence)
{
	uint64_t previous;

	previous = atomic_load_acq_64(sequence);
	while (previous != UINT64_MAX) {
		if (atomic_fcmpset_64(sequence, &previous, previous + 1))
			return (previous + 1);
	}
	return (0);
}

static uint64_t
new_execution(void)
{
	return (next_identity(&execution_sequence));
}

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
issuer_free(void *context, int pending __unused)
{
	struct authority_issuer *issuer = context;

	crfree(issuer->cred);
	mtx_destroy(&issuer->lock);
	free(issuer, M_CAP_AUTHORITY);
}

static void
issuer_drop(struct authority_issuer *issuer)
{
	if (!refcount_release(&issuer->refs))
		return;
	/* Defer credential cleanup from channel destruction contexts. */
	taskqueue_enqueue(taskqueue_thread, &issuer->cleanup);
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
	issuer_drop(a->issuer);
	free(a, M_CAP_AUTHORITY);
}
void
cap_authority_drop(struct cap_authority *authority)
{
	if (authority == NULL || !refcount_release(&authority->refs))
		return;
	/* Message destruction can hold a channel mutex. Vnode release may sleep. */
	if (authority->nexec != 0 || authority->nlibdirs != 0)
		taskqueue_enqueue(taskqueue_thread, &authority->cleanup);
	else
		authority_free(authority, 0);
}

bool
cap_authority_is_revoked(const struct cap_authority *authority)
{
	return (authority != NULL &&
	    (atomic_load_acq_int(&authority->revoked) ||
	    atomic_load_acq_int(&authority->issuer->revoked)));
}

bool
cap_authority_matches_stamp(const struct cap_authority *authority,
    const struct cap_authority_stamp *stamp)
{
	return (authority == NULL || (stamp->valid != 0 &&
	    stamp->issuer == authority->issuer->identity &&
	    stamp->identity == authority->identity &&
	    !cap_authority_is_revoked(authority)));
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
	/* Also covers PT_TRACE_ME, which does not use the ordinary debug hook. */
	if (target->p_noambient)
		return (EPERM);
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
	allowed = actor->p_cap_authority == a && authority_valid(actor) &&
	    target->p_cap_execution != 0 &&
	    actor->p_cap_execution == target->p_cap_execution;
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
	child->p_cap_invocation = NULL; /* A fork is never the parent invocation. */
	child->p_cap_authority = parent->p_cap_authority;
	if (child->p_cap_authority != NULL)
		refcount_acquire(&child->p_cap_authority->refs);
	child->p_cap_authority_generation = parent->p_cap_authority_generation;
	child->p_cap_execution = parent->p_cap_execution;
	child->p_cap_authority_invalid = parent->p_cap_authority_invalid;
	child->p_cap_authority_pending_exec = parent->p_cap_authority_pending_exec;
}
void
cap_authority_exit(struct proc *p)
{
	struct cap_authority *old;

	PROC_LOCK(p);
	cap_authority_invocation_invalidate_locked(p);
	old = p->p_cap_authority;
	p->p_cap_authority = NULL;
	p->p_cap_execution = 0;
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
		cap_authority_invocation_invalidate_locked(p);
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
	/* Called only after a successful image activation, never on failed exec. */
	cap_authority_invocation_invalidate_locked(p);
	p->p_cap_execution = (a != NULL || selected != NULL) ? new_execution() : 0;
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
	mtx_lock(&issuer->lock);
	struct cap_authority_lease *lease;
	LIST_FOREACH(lease, &issuer->leases, issuer_link)
		lease_revoke(lease);
	mtx_unlock(&issuer->lock);
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
	    "authority-issuer" : fp->f_ops == &lease_control_ops ?
	    "authority-lease-control" : fp->f_ops == &lease_owner_ops ?
	    "authority-lease-owner" : "authority-grant", sizeof(kif->kf_path));
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

/* Capture ownership, not an endpoint lifetime. No descriptor survives this
 * function. The destination must be unpublished and have no owned reference. */
int
cap_authority_binding_acquire(struct thread *td, int issuer_fd, int token_fd,
    uint64_t identity, uint64_t nonce, struct cap_authority_binding *binding)
{
	struct file *issuer, *token;
	struct cap_authority *authority;
	int error;

	bzero(binding, sizeof(*binding));
	if ((identity == 0) != (nonce == 0))
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	error = get_object(td, token_fd, &token_ops, CAP_FSTAT, &token);
	if (error == 0) {
		authority = token->f_data;
		if (authority->issuer != issuer->f_data ||
		    authority->issuer->cred->cr_prison != td->td_ucred->cr_prison)
			error = EPERM;
		else {
			cap_authority_retain(authority);
			binding->authority = authority;
			binding->process_identity = identity;
			binding->execution_nonce = nonce;
		}
		fdrop(token, td);
	}
	fdrop(issuer, td);
	return (error);
}

void
cap_authority_binding_release(struct cap_authority_binding *binding)
{
	struct cap_authority *authority = binding->authority;

	bzero(binding, sizeof(*binding));
	cap_authority_drop(authority);
}

/* The issuer binds before delivering the capability. The process identity
 * distinguishes fork descendants; the credential nonce distinguishes execs.
 * Neither UNIX credentials nor re-executing the same approved image can match
 * another invocation. Software authority and its revocation remain required. */
int
cap_authority_binding_check_locked(struct proc *p,
    const struct cap_authority_binding *binding)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	error = cap_authority_check_locked(p, binding->authority);
	if (error == 0 && binding->process_identity != 0 &&
	    (p->p_cap_identity != binding->process_identity ||
	    mac_capability_proc_nonce(p->p_ucred) != binding->execution_nonce))
		error = EPERM;
	return (error);
}

bool
cap_authority_binding_matches(const struct cap_authority_binding *binding,
    const struct cap_authority_stamp *stamp, uint64_t identity, uint64_t nonce)
{
	return (cap_authority_matches_stamp(binding->authority, stamp) &&
	    (binding->process_identity == 0 ||
	    (binding->process_identity == identity &&
	    binding->execution_nonce == nonce)));
}

/* Lock order is issuer -> lease -> channel. Fast permission checks take no
 * lease lock. A channel's final destruction unlinks before destroying its
 * mutex/knlists, so the lease's list contains stable weak pointers while locked.
 * Neither a bound channel nor an internal reference keeps the owner file open.
 */
bool
cap_authority_lease_valid(const struct cap_authority_lease *lease)
{
	return (lease == NULL || (!atomic_load_acq_int(&lease->revoked) &&
	    !atomic_load_acq_int(&lease->issuer->revoked) &&
	    sbinuptime() < lease->deadline));
}

static void
lease_notify_locked(struct cap_authority_lease *lease)
{
	struct mac_capability_instance *s;

	mtx_assert(&lease->lock, MA_OWNED);
	atomic_store_rel_int(&lease->revoked, 1);
	LIST_FOREACH(s, &lease->endpoints, ci_lease_link) {
		mtx_lock(&s->ci_mtx);
		wakeup(&s->ci_txq);
		KNOTE_LOCKED(&s->ci_rknotes, 0);
		KNOTE_LOCKED(&s->ci_wknotes, 0);
		mtx_unlock(&s->ci_mtx);
	}
}

static void
lease_revoke(struct cap_authority_lease *lease)
{
	mtx_lock(&lease->lock);
	lease_notify_locked(lease);
	mtx_unlock(&lease->lock);
}

static void
lease_expire(void *context)
{
	/* callout_init_mtx holds the lease lock for this callback. */
	lease_notify_locked(context);
}

static void
lease_free(void *context, int pending __unused)
{
	struct cap_authority_lease *lease = context;

	/* Final release may occur under descriptor/channel teardown locks. */
	callout_drain(&lease->expiry);
	mtx_lock(&lease->issuer->lock);
	LIST_REMOVE(lease, issuer_link);
	mtx_unlock(&lease->issuer->lock);
	mtx_destroy(&lease->lock);
	issuer_drop(lease->issuer);
	free(lease, M_CAP_AUTHORITY);
}

static void
lease_drop(struct cap_authority_lease *lease)
{
	if (refcount_release(&lease->refs))
		taskqueue_enqueue(taskqueue_thread, &lease->cleanup);
}

void
cap_authority_lease_release(struct cap_authority_lease *lease)
{
	if (lease != NULL)
		lease_drop(lease);
}

int
cap_authority_lease_acquire(struct thread *td, int issuer_fd, int lease_fd,
    struct cap_authority_lease **result)
{
	struct file *issuer, *control;
	struct cap_authority_lease *lease;
	int error;

	*result = NULL;
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer);
	if (error != 0)
		return (error);
	error = get_object(td, lease_fd, &lease_control_ops, CAP_FSTAT, &control);
	if (error == 0) {
		lease = control->f_data;
		if (lease->issuer != issuer->f_data ||
		    lease->issuer->cred->cr_prison != td->td_ucred->cr_prison ||
		    !cap_authority_lease_valid(lease))
			error = EPERM;
		else {
			refcount_acquire(&lease->refs);
			*result = lease;
		}
		fdrop(control, td);
	}
	fdrop(issuer, td);
	return (error);
}

void
cap_authority_lease_detach(struct mac_capability_instance *s)
{
	struct cap_authority_lease *lease = s->ci_lease;

	if (lease == NULL)
		return;
	mtx_lock(&lease->lock);
	LIST_REMOVE(s, ci_lease_link);
	mtx_unlock(&lease->lock);
	lease_drop(lease);
}

static int
lease_close(struct file *fp, struct thread *td __unused)
{
	struct cap_authority_lease *lease = fp->f_data;

	lease_revoke(lease);
	lease_drop(lease);
	return (0);
}

#define LEASE_FILEOPS { \
	.fo_read = invfo_rdwr, .fo_write = invfo_rdwr, \
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl, \
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter, \
	.fo_stat = authority_stat, .fo_close = lease_close, \
	.fo_chmod = invfo_chmod, .fo_chown = invfo_chown, \
	.fo_sendfile = invfo_sendfile, .fo_cmp = file_kcmp_generic, \
	.fo_fill_kinfo = authority_fill_kinfo, .fo_flags = DFLAG_PASSABLE \
}
static struct fileops lease_control_ops = LEASE_FILEOPS;
static struct fileops lease_owner_ops = LEASE_FILEOPS;
#undef LEASE_FILEOPS

static int
lease_create(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_lease_create req;
	struct cap_authority_lease *lease;
	struct file *issuer_file, *control, *owner;
	struct fdinstall_prop properties = {
	    .fip_xfer_state = CAP_XFER_NONE,
	    .fip_clofork_state = CAP_CLOFORK_LOCKED,
	    .fip_cloexec_state = CAP_CLOEXEC_LOCKED };
	int error;

	error = copyin(data, &req, sizeof(req));
	if (error != 0)
		return (error);
	if (req.flags != 0 || req.reserved != 0 || req.seconds == 0 ||
	    req.seconds > CAP_AUTH_LEASE_SECONDS_MAX)
		return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer_file);
	if (error != 0)
		return (error);
	struct authority_issuer *issuer = issuer_file->f_data;
	if (issuer->cred->cr_prison != td->td_ucred->cr_prison) {
		fdrop(issuer_file, td);
		return (EPERM);
	}
	error = falloc_noinstall(td, &control);
	if (error != 0) { fdrop(issuer_file, td); return (error); }
	error = falloc_noinstall(td, &owner);
	if (error != 0) { fdrop(control, td); fdrop(issuer_file, td); return (error); }
	lease = malloc(sizeof(*lease), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
	refcount_init(&lease->refs, 2);
	lease->issuer = issuer;
	refcount_acquire(&issuer->refs);
	lease->deadline = sbinuptime() + (sbintime_t)req.seconds * SBT_1S;
	mtx_init(&lease->lock, "authority lease", NULL, MTX_DEF);
	LIST_INIT(&lease->endpoints);
	callout_init_mtx(&lease->expiry, &lease->lock, 0);
	TASK_INIT(&lease->cleanup, 0, lease_free, lease);
	mtx_lock(&issuer->lock);
	LIST_INSERT_HEAD(&issuer->leases, lease, issuer_link);
	mtx_unlock(&issuer->lock);
	mtx_lock(&lease->lock);
	callout_reset_sbt(&lease->expiry, lease->deadline, 0,
	    lease_expire, lease, C_ABSOLUTE);
	mtx_unlock(&lease->lock);
	finit(control, FREAD, DTYPE_DEV, lease, &lease_control_ops);
	finit(owner, FREAD, DTYPE_DEV, lease, &lease_owner_ops);
	req.control_fd = req.owner_fd = -1;
	error = finstall_prop(td, control, &req.control_fd, O_CLOEXEC, NULL, &properties);
	if (error == 0) {
		properties.fip_xfer_state = CAP_XFER_ONCE;
		error = finstall_prop(td, owner, &req.owner_fd, O_CLOEXEC, NULL, &properties);
	}
	if (error == 0)
		error = copyout(&req, data, sizeof(req));
	if (error != 0) {
		if (req.control_fd >= 0) fdclose(td, control, req.control_fd);
		if (req.owner_fd >= 0) fdclose(td, owner, req.owner_fd);
	}
	fdrop(control, td); fdrop(owner, td); fdrop(issuer_file, td);
	return (error);
}

static int
lease_bind(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_lease_bind req;
	struct cap_authority_lease *lease;
	struct mac_capability_instance *instance;
	struct file *issuer_file, *control, *capability;
	int error;

	error = copyin(data, &req, sizeof(req));
	if (error != 0) return (error);
	if (req.flags != 0 || req.reserved != 0) return (EINVAL);
	error = get_object(td, issuer_fd, &issuer_ops, CAP_WRITE, &issuer_file);
	if (error != 0) return (error);
	error = get_object(td, req.lease_fd, &lease_control_ops, CAP_FSTAT, &control);
	if (error != 0) { fdrop(issuer_file, td); return (error); }
	lease = control->f_data;
	if (lease->issuer != issuer_file->f_data ||
	    lease->issuer->cred->cr_prison != td->td_ucred->cr_prison) {
		error = EPERM;
		goto out;
	}
	error = get_object(td, req.capability_fd, &mac_capability_instance_ops,
	    CAP_IOCTL, &capability);
	if (error != 0) goto out;
	instance = capability->f_data;
	/* Restrict this ABI to direct message channels: no service-specific
	 * mint operation or synchronous kernel handler can bypass the lease. */
	if (!mac_capability_channel_is_service(instance->ci_service)) {
		error = EOPNOTSUPP;
		goto out_capability;
	}
	mtx_lock(&lease->lock);
	mtx_lock(&instance->ci_mtx);
	if (instance->ci_priv == NULL)
		error = EOPNOTSUPP; /* Unconnected channel factories are not endpoints. */
	else if (instance->ci_lease != NULL)
		error = EALREADY;
	else if (!cap_authority_lease_valid(lease))
		error = EPERM;
	else {
		refcount_acquire(&lease->refs);
		instance->ci_lease = lease;
		atomic_set_int(&instance->ci_restricted, MAC_CAPABILITY_RF_NO_MINT);
		LIST_INSERT_HEAD(&lease->endpoints, instance, ci_lease_link);
	}
	mtx_unlock(&instance->ci_mtx);
	mtx_unlock(&lease->lock);
out_capability:
	fdrop(capability, td);
out:
	fdrop(control, td); fdrop(issuer_file, td);
	return (error);
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
		error = vn_text_pin_supported(vp) ? VOP_SET_TEXT(vp) :
		    EOPNOTSUPP;
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
cap_authority_invocation_acquire(struct thread *td, int issuer_fd,
    const struct cap_authority_check_invocation *request,
    struct cap_authority_invocation **result)
{
	struct cap_authority_binding binding;
	struct cap_authority_invocation *fresh;
	struct file *fp;
	struct proc *p;
	int error;

	*result = NULL;
	if (request->flags != 0 || request->reserved != 0 ||
	    request->process_identity == 0 || request->execution_nonce == 0)
		return (EINVAL);
	error = cap_authority_binding_acquire(td, issuer_fd, request->token_fd,
	    request->process_identity, request->execution_nonce, &binding);
	if (error != 0)
		return (error);
	fresh = malloc(sizeof(*fresh), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
	refcount_init(&fresh->refs, 1);
	fresh->authority = binding.authority;
	cap_authority_retain(fresh->authority);
	sx_slock(&proctree_lock);
	error = fget_procdesc(td, request->process_fd, &cap_pdgetpid_rights,
	    EINVAL, &fp, NULL, &p);
	if (error == 0) {
		error = (p->p_flag & P_WEXIT) != 0 ? ESRCH :
		    cap_authority_binding_check_locked(p, &binding);
		if (error == 0) {
			if (p->p_cap_invocation == NULL) {
				p->p_cap_invocation = fresh;
				fresh = NULL;
			}
			refcount_acquire(&p->p_cap_invocation->refs);
			*result = p->p_cap_invocation;
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&proctree_lock);
	if (fp != NULL)
		fdrop(fp, td);
	cap_authority_invocation_release(fresh);
	cap_authority_binding_release(&binding);
	return (error);
}

static int
check_invocation(struct thread *td, int issuer_fd, void *data)
{
	struct cap_authority_check_invocation request;
	struct cap_authority_binding binding;
	struct file *fp;
	struct proc *p;
	int error;

	error = copyin(data, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.flags != 0 || request.reserved != 0 ||
	    request.process_identity == 0 || request.execution_nonce == 0)
		return (EINVAL);
	error = cap_authority_binding_acquire(td, issuer_fd, request.token_fd,
	    request.process_identity, request.execution_nonce, &binding);
	if (error != 0)
		return (error);
	/* fget_procdesc returns the process locked. The procdesc reference must
	 * be dropped after proctree_lock: its final close acquires that lock. */
	sx_slock(&proctree_lock);
	error = fget_procdesc(td, request.process_fd, &cap_pdgetpid_rights,
	    EINVAL, &fp, NULL, &p);
	if (error == 0) {
		error = (p->p_flag & P_WEXIT) != 0 ? ESRCH :
		    cap_authority_binding_check_locked(p, &binding);
		PROC_UNLOCK(p);
	}
	sx_sunlock(&proctree_lock);
	if (fp != NULL)
		fdrop(fp, td);
	cap_authority_binding_release(&binding);
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
	struct cap_authority_binding owned_binding;
	struct cap_authority_bind_invocation invocation = {0};
	struct cap_authority_revoke revoke;
	struct mac_capability_instance *instance;
	struct file *fp, *token, *capability, *fresh;
	uint64_t issuer_identity;
	int error;

	if ((op == CAP_AUTH_ISSUER_CREATE || op == CAP_AUTH_INSTALL ||
	    op == CAP_AUTH_CLEAR) && data != NULL)
		return (EINVAL);
	switch (op) {
	case CAP_AUTH_CHECK_INVOCATION:
		return (check_invocation(td, fd, data));
	case CAP_AUTH_LEASE_CREATE:
		return (lease_create(td, fd, data));
	case CAP_AUTH_LEASE_BIND:
		return (lease_bind(td, fd, data));
	case CAP_AUTH_LEASE_CHECK:
		if (data != NULL) return (EINVAL);
		error = get_object(td, fd, &lease_control_ops, CAP_FSTAT, &fp);
		if (error != 0) return (error);
		error = cap_authority_lease_valid(fp->f_data) ? 0 : EPERM;
		fdrop(fp, td);
		return (error);
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
		/* Snapshot comparison needs collision-free identity, not a secret.
		 * Consume IDs even on allocation failure; never wrap or reuse. */
		issuer_identity = next_identity(&issuer_sequence);
		if (issuer_identity == 0)
			return (ENOSPC);
		error = falloc_noinstall(td, &fresh);
		if (error != 0)
			return (error);
		issuer = malloc(sizeof(*issuer), M_CAP_AUTHORITY, M_WAITOK | M_ZERO);
		refcount_init(&issuer->refs, 1);
		mtx_init(&issuer->lock, "authority issuer", NULL, MTX_DEF);
		LIST_INIT(&issuer->leases);
		issuer->cred = crhold(td->td_ucred);
		TASK_INIT(&issuer->cleanup, 0, issuer_free, issuer);
		issuer->identity = issuer_identity;
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
			cap_authority_invocation_invalidate_locked(td->td_proc);
			old = td->td_proc->p_cap_authority;
			td->td_proc->p_cap_authority = a;
			td->td_proc->p_cap_execution = new_execution();
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
		cap_authority_invocation_invalidate_locked(td->td_proc);
		old = td->td_proc->p_cap_authority;
		td->td_proc->p_cap_authority = NULL;
		td->td_proc->p_cap_execution = 0;
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
	case CAP_AUTH_BIND_INVOCATION:
		if (op == CAP_AUTH_BIND_INVOCATION) {
			error = copyin(data, &invocation, sizeof(invocation));
			if (error != 0)
				return (error);
			if (invocation.process_identity == 0 ||
			    invocation.execution_nonce == 0)
				return (EINVAL);
			binding.token_fd = invocation.token_fd;
			binding.capability_fd = invocation.capability_fd;
			binding.flags = invocation.flags;
			binding.reserved = invocation.reserved;
		} else
			error = copyin(data, &binding, sizeof(binding));
		if (error != 0)
			return (error);
		if (binding.flags != 0 || binding.reserved != 0)
			return (EINVAL);
		error = cap_authority_binding_acquire(td, fd, binding.token_fd,
		    invocation.process_identity, invocation.execution_nonce,
		    &owned_binding);
		if (error != 0)
			return (error);
		error = get_object(td, binding.capability_fd,
		    &mac_capability_instance_ops, CAP_IOCTL, &capability);
		if (error == 0) {
			instance = capability->f_data;
			mtx_lock(&instance->ci_mtx);
			if (instance->ci_binding.authority != NULL)
				error = EALREADY;
			else {
				instance->ci_binding = owned_binding;
				bzero(&owned_binding, sizeof(owned_binding));
			}
			mtx_unlock(&instance->ci_mtx);
			fdrop(capability, td);
		}
		cap_authority_binding_release(&owned_binding);
		return (error);
	default:
		return (EINVAL);
	}
}

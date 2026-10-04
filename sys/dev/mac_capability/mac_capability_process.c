/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Self-owned process discovery and independent responsible-process identity.
 * A held channel survives descriptor cleanup and exec. Installing it never
 * creates authority: the caller must already hold the channel. Working fds
 * preserve its rights and cannot be transferred. No PID-based or root bypass.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cap_process.h>
#include <sys/capsicum.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/ucred.h>
#include <sys/user.h>

#include <bsm/audit_kevents.h>

#include "mac_capability_internal.h"

FEATURE(cap_process, "Process-held capability discovery and attribution");

MALLOC_DEFINE(M_CAP_PROCESS, "cap_process", "capability process context");
struct mac_cap_process_context {
	u_int refs;
	struct file *fp;
	struct filecaps caps;
	struct ucred *cred; /* Pins the originating prison. */
	uid_t uid; /* Session principal, not temporary effective UID. */
};
struct origin_token {
	struct mac_cap_process_info info;
	struct ucred *cred;
};
static void
context_drop(struct mac_cap_process_context *c)
{
	if (c == NULL || !refcount_release(&c->refs))
		return;
	/* File close may sleep. No process or fd-table locks may be held here.
	 */
	fdrop(c->fp, curthread);
	filecaps_free(&c->caps);
	crfree(c->cred);
	free(c, M_CAP_PROCESS);
}
static uint64_t
process_identity(struct proc *p)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (p->p_cap_identity == 0) {
		do {
			arc4random_buf(&p->p_cap_identity,
			    sizeof(p->p_cap_identity));
		} while (p->p_cap_identity == 0);
	}
	return (p->p_cap_identity);
}
void
mac_capability_process_info(struct proc *p, struct mac_cap_process_info *info)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	bzero(info, sizeof(*info));
	info->identity = process_identity(p);
	info->pid = p->p_pid;
	info->responsible_identity = p->p_cap_responsible;
	info->responsible_pid = p->p_cap_responsible_pid;
	info->generation = p->p_cap_generation;
	if (p->p_cap_context != NULL) {
		info->present = 1;
		info->uid = p->p_cap_context->uid;
	}
}
static void
context_fork(void *arg __unused, struct proc *parent, struct proc *child,
    int flags __unused)
{
	PROC_LOCK(parent);
	child->p_cap_context = parent->p_cap_context;
	if (child->p_cap_context != NULL)
		refcount_acquire(&child->p_cap_context->refs);
	child->p_cap_generation = parent->p_cap_generation;
	child->p_cap_responsible = parent->p_cap_responsible;
	child->p_cap_responsible_pid = parent->p_cap_responsible_pid;
	PROC_UNLOCK(parent);
	PROC_LOCK(child);
	(void)process_identity(child);
	PROC_UNLOCK(child);
}
static void
context_exit(void *arg __unused, struct proc *p)
{
	struct mac_cap_process_context *c;
	PROC_LOCK(p);
	c = p->p_cap_context;
	p->p_cap_context = NULL;
	PROC_UNLOCK(p);
	context_drop(c);
}
static void
context_ctor(void *arg __unused, struct proc *p)
{
	p->p_cap_context = NULL;
	p->p_cap_identity = 0;
	p->p_cap_responsible = 0;
	p->p_cap_generation = 0;
	p->p_cap_responsible_pid = 0;
}
static void
context_init(void *arg __unused)
{
	EVENTHANDLER_REGISTER(process_ctor, context_ctor, NULL,
	    EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_fork, context_fork, NULL,
	    EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_exit, context_exit, NULL,
	    EVENTHANDLER_PRI_ANY);
}
SYSINIT(cap_process, SI_SUB_EVENTHANDLER, SI_ORDER_ANY, context_init, NULL);

static int
context_set(struct thread *td, int fd, uid_t uid)
{
	struct mac_cap_process_context *c, *old;
	struct mac_capability_instance *ci;
	struct filedescent *fde;
	struct filedesc *fdp = td->td_proc->p_fd;
	int error;
	c = malloc(sizeof(*c), M_CAP_PROCESS, M_WAITOK | M_ZERO);
	refcount_init(&c->refs, 1);
	FILEDESC_SLOCK(fdp);
	error = fget_cap_noref(fdp, fd, &cap_no_rights, &c->fp, NULL);
	if (error == 0) {
		fde = &fdp->fd_ofiles[fd];
		/* A slot must not launder enforced fork/exec attenuation. */
		if (fde->fde_clofork_state != CAP_CLOFORK_UNLOCKED ||
		    fde->fde_cloexec_state != CAP_CLOEXEC_UNLOCKED)
			error = ENOTCAPABLE;
		else if (c->fp->f_ops != &mac_capability_instance_ops)
			error = EINVAL;
		else {
			ci = c->fp->f_data;
			if (strcmp(ci->ci_service->csvc_name, "channel") != 0)
				error = EINVAL;
		}
		if (error == 0) {
			if (!fhold(c->fp))
				error = EBADF;
			else
				(void)filecaps_copy(&fde->fde_caps, &c->caps,
				    true);
		}
	}
	FILEDESC_SUNLOCK(fdp);
	if (error != 0) {
		free(c, M_CAP_PROCESS);
		return (error);
	}
	c->cred = crhold(td->td_ucred);
	c->uid = uid;
	PROC_LOCK(td->td_proc);
	old = td->td_proc->p_cap_context;
	td->td_proc->p_cap_context = c;
	td->td_proc->p_cap_generation++;
	PROC_UNLOCK(td->td_proc);
	context_drop(old);
	return (0);
}
static int
context_get(struct thread *td)
{
	struct mac_cap_process_context *c;
	struct filecaps caps;
	const struct fdinstall_prop prop = {
		.fip_xfer_state = CAP_XFER_NONE,
		.fip_cloexec_state = CAP_CLOEXEC_UNLOCKED,
		.fip_clofork_state = CAP_CLOFORK_UNLOCKED,
	};
	int error, fd;
	PROC_LOCK(td->td_proc);
	c = td->td_proc->p_cap_context;
	if (c != NULL)
		refcount_acquire(&c->refs);
	PROC_UNLOCK(td->td_proc);
	if (c == NULL)
		return (ENOENT);
	if (c->cred->cr_prison != td->td_ucred->cr_prison ||
	    c->uid != td->td_ucred->cr_ruid) {
		context_drop(c);
		return (EPERM);
	}
	(void)filecaps_copy(&c->caps, &caps, true);
	error = finstall_prop(td, c->fp, &fd, O_CLOEXEC, &caps, &prop);
	if (error != 0)
		filecaps_free(&caps);
	context_drop(c);
	if (error == 0)
		td->td_retval[0] = fd;
	return (error);
}
static int
origin_close(struct file *fp, struct thread *td __unused)
{
	struct origin_token *t = fp->f_data;
	crfree(t->cred);
	free(t, M_CAP_PROCESS);
	return (0);
}
static int
origin_stat(struct file *fp __unused, struct stat *sb,
    struct ucred *cred __unused)
{
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFREG | 0400;
	return (0);
}
static int
origin_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct origin_token *t = fp->f_data;
	kif->kf_type = KF_TYPE_UNKNOWN;
	snprintf(kif->kf_path, sizeof(kif->kf_path), "process-origin:%ju/%d",
	    (uintmax_t)t->info.identity, t->info.pid);
	return (0);
}
static const struct fileops origin_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = origin_stat,
	.fo_close = origin_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = origin_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};
int
sys_cap_process(struct thread *td, struct cap_process_args *a)
{
	struct mac_cap_process_context *old;
	struct mac_cap_process_info info;
	struct origin_token *t;
	struct file *fp;
	int error, fd;
	if (a->data != NULL && a->op != MAC_CAP_PROCESS_INFO)
		return (EINVAL);
	switch (a->op) {
	case MAC_CAP_PROCESS_SET:
		return (context_set(td, a->fd, a->uid));
	case MAC_CAP_PROCESS_GET:
		return (context_get(td));
	case MAC_CAP_PROCESS_CLEAR:
		PROC_LOCK(td->td_proc);
		old = td->td_proc->p_cap_context;
		td->td_proc->p_cap_context = NULL;
		td->td_proc->p_cap_generation++;
		PROC_UNLOCK(td->td_proc);
		context_drop(old);
		return (0);
	case MAC_CAP_PROCESS_INFO:
		PROC_LOCK(td->td_proc);
		if (td->td_proc->p_cap_context != NULL &&
		    (td->td_proc->p_cap_context->cred->cr_prison !=
			    td->td_ucred->cr_prison ||
			td->td_proc->p_cap_context->uid !=
			    td->td_ucred->cr_ruid)) {
			PROC_UNLOCK(td->td_proc);
			return (EPERM);
		}
		mac_capability_process_info(td->td_proc, &info);
		PROC_UNLOCK(td->td_proc);
		return (copyout(&info, a->data, sizeof(info)));
	case MAC_CAP_PROCESS_ORIGIN_EXPORT:
		t = malloc(sizeof(*t), M_CAP_PROCESS, M_WAITOK | M_ZERO);
		t->cred = crhold(td->td_ucred);
		PROC_LOCK(td->td_proc);
		mac_capability_process_info(td->td_proc, &t->info);
		PROC_UNLOCK(td->td_proc);
		error = falloc_noinstall(td, &fp);
		if (error != 0) {
			crfree(t->cred);
			free(t, M_CAP_PROCESS);
			return (error);
		}
		finit(fp, FREAD, DTYPE_DEV, t, &origin_ops);
		error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
		fdrop(fp, td);
		if (error == 0)
			td->td_retval[0] = fd;
		return (error);
	case MAC_CAP_PROCESS_ORIGIN_SET:
		error = fget(td, a->fd, &cap_no_rights, &fp);
		if (error != 0)
			return (error);
		if (fp->f_ops != &origin_ops) {
			fdrop(fp, td);
			return (EINVAL);
		}
		t = fp->f_data;
		if (t->cred->cr_prison != td->td_ucred->cr_prison)
			error = EPERM;
		else {
			PROC_LOCK(td->td_proc);
			td->td_proc->p_cap_responsible = t->info.identity;
			td->td_proc->p_cap_responsible_pid = t->info.pid;
			PROC_UNLOCK(td->td_proc);
		}
		fdrop(fp, td);
		return (error);
	default:
		return (EINVAL);
	}
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Capability-pure (SYF_CAPREQUIRED) variants of vnode metadata syscalls.
 *
 * Each function calls the same shared helper as the ambient variant but
 * passes cap_noambient=true to skip MAC policy gates.  MAC notifications,
 * VOP-internal checks, and Capsicum rights are all preserved.
 *
 * These syscalls are only reachable in capability mode; the dispatcher
 * rejects them with ENOTCAPABLE otherwise.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/syscallsubr.h>
#include <sys/limits.h>
#include <sys/rangelock.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <security/audit/audit.h>

int
sys_cap_fchmod(struct thread *td, struct cap_fchmod_args *uap)
{
	struct file *fp;
	struct vnode *vp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_MODE(uap->mode);
	error = getvnode(td, uap->fd, &cap_fchmod_rights, &fp);
	if (error != 0)
		return (error);
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	error = setfmode(td, td->td_ucred, vp, uap->mode, true);
	fdrop(fp, td);
	return (error);
}

int
sys_cap_fchown(struct thread *td, struct cap_fchown_args *uap)
{
	struct file *fp;
	struct vnode *vp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_OWNER(uap->uid, uap->gid);
	error = getvnode(td, uap->fd, &cap_fchown_rights, &fp);
	if (error != 0)
		return (error);
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	error = setfown(td, td->td_ucred, vp, uap->uid, uap->gid, true);
	fdrop(fp, td);
	return (error);
}

int
sys_cap_fchflags(struct thread *td, struct cap_fchflags_args *uap)
{
	struct file *fp;
	struct vnode *vp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_FFLAGS(uap->flags);
	error = getvnode(td, uap->fd, &cap_fchflags_rights, &fp);
	if (error != 0)
		return (error);
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	error = setfflags(td, vp, uap->flags, true);
	fdrop(fp, td);
	return (error);
}

int
sys_cap_futimes(struct thread *td, struct cap_futimes_args *uap)
{
	struct timespec ts[2];
	struct file *fp;
	struct vnode *vp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	error = getutimes(uap->times, UIO_USERSPACE, ts);
	if (error != 0)
		return (error);
	error = getvnode(td, uap->fd, &cap_futimes_rights, &fp);
	if (error != 0)
		return (error);
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	error = setutimes(td, vp, ts, 2, uap->times == NULL, true);
	fdrop(fp, td);
	return (error);
}

static MALLOC_DEFINE(M_CAPSTATFS, "capstatfs", "cap_fstatfs buffer");

int
sys_cap_fstatfs(struct thread *td, struct cap_fstatfs_args *uap)
{
	struct statfs *sfp;
	struct file *fp;
	struct mount *mp;
	struct vnode *vp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_CAPSTATFS, M_WAITOK);
	AUDIT_ARG_FD(uap->fd);
	error = getvnode_path(td, uap->fd, &cap_fstatfs_rights, NULL, &fp);
	if (error != 0) {
		free(sfp, M_CAPSTATFS);
		return (error);
	}
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	mp = vfs_ref_from_vp(vp);
	fdrop(fp, td);
	error = kern_do_statfs(td, mp, sfp, true);
	if (error == 0)
		error = copyout(sfp, uap->buf, sizeof(struct statfs));
	free(sfp, M_CAPSTATFS);
	return (error);
}

int
sys_cap_ftruncate(struct thread *td, struct cap_ftruncate_args *uap)
{
	struct file *fp;
	struct mount *mp;
	struct vnode *vp;
	void *rl_cookie;
	int error;

	AUDIT_ARG_FD(uap->fd);
	if (uap->length < 0)
		return (EINVAL);
	error = getvnode(td, uap->fd, &cap_ftruncate_rights, &fp);
	if (error != 0)
		return (error);
	AUDIT_ARG_FILE(td->td_proc, fp);
	if (!(fp->f_flag & FWRITE)) {
		fdrop(fp, td);
		return (EINVAL);
	}
	vp = fp->f_vnode;

retry:
	rl_cookie = vn_rangelock_wlock(vp, 0, OFF_MAX);
	error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH);
	if (error)
		goto out1;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}
	/* MAC checks skipped — capability-pure path. */
	error = vn_truncate_locked(vp, uap->length,
	    (fp->f_flag & O_FSYNC) != 0, fp->f_cred);
out:
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
out1:
	vn_rangelock_unlock(vp, rl_cookie);
	if (error == ERELOOKUP)
		goto retry;
	fdrop(fp, td);
	return (error);
}

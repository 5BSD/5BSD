/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_capsicum.h"
#include "opt_ktrace.h"

#define	EXTERR_CATEGORY		EXTERR_CAT_VFSSYSCALL
#include <sys/systm.h>
#ifdef COMPAT_FREEBSD11
#include <sys/abi_compat.h>
#endif
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/capsicum.h>
#include <sys/disk.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/exterrvar.h>
#include <sys/fcntl.h>
#include <sys/fdswap.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/procdesc.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/stdarg.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/dqres.h>
#include <dev/dq/dq.h>
#include <ufs/ufs/quota.h>	/* Q_QUOTAON, SUBCMDSHIFT */

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vnode_pager.h>
#include <vm/uma.h>

#include <fs/devfs/devfs.h>

MALLOC_DEFINE(M_FADVISE, "fadvise", "posix_fadvise(2) information");

SDT_PROVIDER_DECLARE(vfs);
SDT_PROVIDER_DECLARE(fd);
SDT_PROBE_DECLARE(fd, , , refused);
/* Operation boundaries; see tools/test/system-tracing/COVERAGE-THIRTEENTH. */
SDT_PROBE_DEFINE3(vfs, , , copy__range__start,
    "struct vnode *", "struct vnode *", "size_t");
SDT_PROBE_DEFINE4(vfs, , , copy__range__done,
    "struct vnode *", "struct vnode *", "size_t", "int");
SDT_PROBE_DEFINE3(vfs, , , chflags, "u_long", "struct ucred *", "int");
SDT_PROBE_DEFINE3(vfs, , , chroot, "struct vnode *", "struct ucred *", "int");

static int kern_chflagsat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, u_long flags, int atflag);
static int getutimens(const struct timespec *, enum uio_seg,
    struct timespec *, int *);
static int vn_access(struct vnode *vp, int user_flags, struct ucred *cred,
    struct thread *td);
static int kern_fhlinkat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, fhandle_t *fhp);
static int kern_readlink_vp(struct vnode *vp, char *buf, enum uio_seg bufseg,
    size_t count, struct thread *td);
static int kern_linkat_vp(struct thread *td, struct vnode *vp, int fd,
    const char *path, enum uio_seg segflag);
static int chroot_priv_check(struct thread *td);
static void chroot_knote(struct thread *td);

uint64_t
at2cnpflags(u_int at_flags, u_int mask)
{
	uint64_t res;

	MPASS((at_flags & (AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW)) !=
	    (AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW));

	res = 0;
	at_flags &= mask;
	if ((at_flags & AT_RESOLVE_BENEATH) != 0)
		res |= RBENEATH;
	if ((at_flags & AT_SYMLINK_FOLLOW) != 0)
		res |= FOLLOW;
	/* NOFOLLOW is pseudo flag */
	if ((mask & AT_SYMLINK_NOFOLLOW) != 0) {
		res |= (at_flags & AT_SYMLINK_NOFOLLOW) != 0 ? NOFOLLOW :
		    FOLLOW;
	}
	if ((mask & AT_EMPTY_PATH) != 0 && (at_flags & AT_EMPTY_PATH) != 0)
		res |= EMPTYPATH;
	return (res);
}

int
kern_sync(struct thread *td)
{
	struct mount *mp, *nmp;
	int save;

	mtx_lock(&mountlist_mtx);
	for (mp = TAILQ_FIRST(&mountlist); mp != NULL; mp = nmp) {
		if (vfs_busy(mp, MBF_NOWAIT | MBF_MNTLSTLOCK)) {
			nmp = TAILQ_NEXT(mp, mnt_list);
			continue;
		}
		if ((mp->mnt_flag & MNT_RDONLY) == 0 &&
		    vn_start_write(NULL, &mp, V_NOWAIT) == 0) {
			save = curthread_pflags_set(TDP_SYNCIO);
			vfs_periodic(mp, MNT_NOWAIT);
			VFS_SYNC(mp, MNT_NOWAIT);
			curthread_pflags_restore(save);
			vn_finished_write(mp);
		}
		mtx_lock(&mountlist_mtx);
		nmp = TAILQ_NEXT(mp, mnt_list);
		vfs_unbusy(mp);
	}
	mtx_unlock(&mountlist_mtx);
	return (0);
}

/*
 * Sync each mounted filesystem.
 */
#ifndef _SYS_SYSPROTO_H_
struct sync_args {
	int     dummy;
};
#endif
/* ARGSUSED */
int
sys_sync(struct thread *td, struct sync_args *uap)
{

	return (kern_sync(td));
}

/*
 * Change filesystem quotas.
 */
#ifndef _SYS_SYSPROTO_H_
struct quotactl_args {
	char *path;
	int cmd;
	int uid;
	caddr_t arg;
};
#endif
static int
sys_quotactl_dqimpl(struct thread *td, struct quotactl_args *uap)
{
	struct mount *mp;
	struct nameidata nd;
	int error;
	bool mp_busy;

	AUDIT_ARG_CMD(uap->cmd);
	AUDIT_ARG_UID(uap->uid);
	if (!prison_allow(td->td_ucred, PR_ALLOW_QUOTAS))
		return (EPERM);
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNODE1, UIO_USERSPACE,
	    uap->path);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	mp = nd.ni_vp->v_mount;
	vfs_ref(mp);
	vput(nd.ni_vp);
	/*
	 * DescriptorQueue (design 11): Q_QUOTAON's quota file (uap->arg,
	 * slot 1) is looked up inside VFS_QUOTACTL; an attached caller's
	 * is consulted here, before the mount is busied, and that lookup
	 * only checks it resolves what was consulted.
	 */
	error = dqres_consult_slot(td, 1);
	if (error != 0) {
		vfs_rel(mp);
		return (error);
	}
	error = vfs_busy(mp, 0);
	if (error != 0) {
		vfs_rel(mp);
		return (error);
	}
	mp_busy = true;
	error = VFS_QUOTACTL(mp, uap->cmd, uap->uid, uap->arg, &mp_busy);

	/*
	 * Since quota on/off operations typically need to open quota
	 * files, the implementation may need to unbusy the mount point
	 * before calling into namei.  Otherwise, unmount might be
	 * started between two vfs_busy() invocations (first is ours,
	 * second is from mount point cross-walk code in lookup()),
	 * causing deadlock.
	 *
	 * Avoid unbusying mp if the implementation indicates it has
	 * already done so.
	 */
	if (mp_busy)
		vfs_unbusy(mp);
	vfs_rel(mp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_INTERNAL; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
sys_quotactl(struct thread *td, struct quotactl_args *uap)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(true) || !DQRES_ATTACHED_TD(td))
		return (sys_quotactl_dqimpl(td, uap));
	dq_intent_enter(td, &dqi, DQ_ROP_INTERNAL, DQI_USER);
	dq_intent_slot(&dqi, 0, uap->path, UIO_USERSPACE, AT_FDCWD);
	/* Q_QUOTAON: the quota file, an independent slot (ufs quotaon). */
	if ((uap->cmd >> SUBCMDSHIFT) == Q_QUOTAON &&
	    uap->arg != NULL) {
		dq_intent_slot(&dqi, 1, uap->arg, UIO_USERSPACE, AT_FDCWD);
		dq_intent_slot_kconsumer(&dqi, 1);
	}
	dqerror = sys_quotactl_dqimpl(td, uap);
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Used by statfs conversion routines to scale the block size up if
 * necessary so that all of the block counts are <= 'max_size'.  Note
 * that 'max_size' should be a bitmask, i.e. 2^n - 1 for some non-zero
 * value of 'n'.
 */
void
statfs_scale_blocks(struct statfs *sf, long max_size)
{
	uint64_t count;
	int shift;

	KASSERT(powerof2(max_size + 1), ("%s: invalid max_size", __func__));

	/*
	 * Attempt to scale the block counts to give a more accurate
	 * overview to userland of the ratio of free space to used
	 * space.  To do this, find the largest block count and compute
	 * a divisor that lets it fit into a signed integer <= max_size.
	 */
	if (sf->f_bavail < 0)
		count = -sf->f_bavail;
	else
		count = sf->f_bavail;
	count = MAX(sf->f_blocks, MAX(sf->f_bfree, count));
	if (count <= max_size)
		return;

	count >>= flsl(max_size);
	shift = 0;
	while (count > 0) {
		shift++;
		count >>=1;
	}

	sf->f_bsize <<= shift;
	sf->f_blocks >>= shift;
	sf->f_bfree >>= shift;
	sf->f_bavail >>= shift;
}

int
kern_do_statfs(struct thread *td, struct mount *mp, struct statfs *buf)
{
	int error;

	if (mp == NULL)
		return (EBADF);
	error = vfs_busy(mp, MBF_PCATCH);
	vfs_rel(mp);
	if (error != 0)
		return (error);
	error = VFS_STATFS(mp, buf);
	if (error != 0)
		goto out;
	if (priv_check_cred_vfs_generation(td->td_ucred))
		prison_enforce_statfs(td->td_ucred, mp, buf);
out:
	vfs_unbusy(mp);
	return (error);
}

/*
 * Get filesystem statistics.
 */
#ifndef _SYS_SYSPROTO_H_
struct statfs_args {
	char *path;
	struct statfs *buf;
};
#endif
int
sys_statfs(struct thread *td, struct statfs_args *uap)
{
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_statfs(td, uap->path, UIO_USERSPACE, sfp);
	if (error == 0)
		error = copyout(sfp, uap->buf, sizeof(struct statfs));
	free(sfp, M_STATFS);
	return (error);
}

/*
 * DescriptorQueue (stage 1c-iii-a, D157-D166): completions of served
 * answers.  Each runs in its marked wrapper when the impl returned
 * EDQRESOLVED, with DQI_COMPLETING set; none makes a lookup.  The answer
 * is the controller's FD, ATTR, LINK or OK, of a kind the event accepted.
 */

/* A mutating operation the controller performed: OK. */
static int
dq_ok_dqserved(struct dq_intent *di)
{

	return (di->di_res.da_kind == DQ_RESOLVE_OK ? 0 : EIO);
}

/*
 * SETATTR answered OK (the controller decided, Q7) or FD: the posted
 * change applied through the transient file under D96's rules (D160).
 */
static int
dq_setattr_dqserved(struct thread *td, struct dq_intent *di)
{
	struct file *fp;
	int error;

	if (di->di_res.da_kind == DQ_RESOLVE_OK)
		return (0);
	if (di->di_res.da_kind != DQ_RESOLVE_FD)
		return (EIO);
	error = dqres_take_file_raw(td, di, FREAD, &fp);
	if (error != 0)
		return (error);
	error = dqres_setattr_apply(td, fp, di->di_setattr);
	fdrop(fp, td);
	return (error);
}

/* The served kinds of a SETATTR: OK and FD; FD only when withheld. */
static uint32_t
dq_setattr_accept(bool fd_only)
{

	return ((fd_only ? 0 : DQ_RACCEPT(DQ_RESOLVE_OK)) |
	    DQ_RACCEPT(DQ_RESOLVE_FD));
}

/* The times of a utimes(2)/utimensat(2) SETATTR body (D161). */
static void
dq_setattr_times(struct dq_setattr_body *sb, const struct timespec *ts)
{
	struct timespec now;
	int i;

	vfs_timestamp(&now);
	if (ts == NULL) {
		sb->dsa_mask |= DQ_SETATTR_ATIME | DQ_SETATTR_MTIME |
		    DQ_SETATTR_ATIME_NOW | DQ_SETATTR_MTIME_NOW |
		    DQ_SETATTR_F_UTIMES_NULL;
		sb->dsa_atime.tv_sec = sb->dsa_mtime.tv_sec = now.tv_sec;
		sb->dsa_atime.tv_nsec = sb->dsa_mtime.tv_nsec = now.tv_nsec;
		return;
	}
	for (i = 0; i < 2; i++) {
		struct dq_timespec *d;
		uint32_t bit, nowbit;

		d = i == 0 ? &sb->dsa_atime : &sb->dsa_mtime;
		bit = i == 0 ? DQ_SETATTR_ATIME : DQ_SETATTR_MTIME;
		nowbit = i == 0 ? DQ_SETATTR_ATIME_NOW : DQ_SETATTR_MTIME_NOW;
		if (ts[i].tv_nsec == UTIME_OMIT)
			continue;
		sb->dsa_mask |= bit;
		if (ts[i].tv_nsec == UTIME_NOW) {
			sb->dsa_mask |= nowbit;
			d->tv_sec = now.tv_sec;
			d->tv_nsec = now.tv_nsec;
		} else {
			d->tv_sec = ts[i].tv_sec;
			d->tv_nsec = ts[i].tv_nsec;
		}
	}
	if (ts[0].tv_nsec == UTIME_NOW && ts[1].tv_nsec == UTIME_NOW)
		sb->dsa_mask |= DQ_SETATTR_F_UTIMES_NULL;
}

static int
kern_statfs_dqimpl(struct thread *td, const char *path, enum uio_seg pathseg,
    struct statfs *buf)
{
	struct mount *mp;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNODE1, pathseg, path);
	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	mp = vfs_ref_from_vp(nd.ni_vp);
	vrele(nd.ni_vp);
#ifdef MAC
	if (mp != NULL) {
		error = mac_mount_check_stat(td->td_ucred, mp);
		if (error != 0) {
			vfs_rel(mp);
			return (error);
		}
	}
#endif
	return (kern_do_statfs(td, mp, buf));
}

/* ATTR: the identity's statfs as the reader sees it (D201). */
static int
kern_statfs_dqserved(struct thread *td, struct dq_intent *di,
    struct statfs *buf)
{
	const struct dq_ident_file *id;

	id = dqres_ident(di, DQ_RESOLVE_ATTR);
	if (id == NULL)
		return (EIO);
	dqres_statfs_present(td, di->di_res.da_qgid, &id->di_statfs, buf);
	return (0);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_STAT; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_statfs(struct thread *td, const char *path, enum uio_seg pathseg,
    struct statfs *buf)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_statfs_dqimpl(td, path, pathseg, buf));
	dq_intent_enter_served(td, &dqi, DQ_ROP_STAT, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_ATTR));
	dq_intent_slot(&dqi, 0, path, pathseg, AT_FDCWD);
	dqerror = kern_statfs_dqimpl(td, path, pathseg, buf);
	DQRES_SERVED(td, &dqi, dqerror, kern_statfs_dqserved(td, &dqi, buf));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Get filesystem statistics.
 */
#ifndef _SYS_SYSPROTO_H_
struct fstatfs_args {
	int fd;
	struct statfs *buf;
};
#endif
int
sys_fstatfs(struct thread *td, struct fstatfs_args *uap)
{
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fstatfs(td, uap->fd, sfp);
	if (error == 0)
		error = copyout(sfp, uap->buf, sizeof(struct statfs));
	free(sfp, M_STATFS);
	return (error);
}

int
kern_fstatfs(struct thread *td, int fd, struct statfs *buf)
{
	struct file *fp;
	int error;

	AUDIT_ARG_FD(fd);
	error = fget(td, fd, &cap_fstatfs_rights, &fp);
	if (error != 0)
		return (error);
	error = fo_statfs(fp, buf, td);
	fdrop(fp, td);
	return (error);
}

/*
 * Get statistics on all filesystems.
 */
#ifndef _SYS_SYSPROTO_H_
struct getfsstat_args {
	struct statfs *buf;
	long bufsize;
	int mode;
};
#endif
int
sys_getfsstat(struct thread *td, struct getfsstat_args *uap)
{
	size_t count;
	int error;

	if (uap->bufsize < 0 || uap->bufsize > SIZE_MAX)
		return (EINVAL);
	error = kern_getfsstat(td, &uap->buf, uap->bufsize, &count,
	    UIO_USERSPACE, uap->mode);
	if (error == 0)
		td->td_retval[0] = count;
	return (error);
}

/*
 * If (bufsize > 0 && bufseg == UIO_SYSSPACE)
 *	The caller is responsible for freeing memory which will be allocated
 *	in '*buf'.
 */
int
kern_getfsstat(struct thread *td, struct statfs **buf, size_t bufsize,
    size_t *countp, enum uio_seg bufseg, int mode)
{
	struct mount *mp, *nmp;
	struct statfs *sfsp, *sp, *sptmp, *tofree;
	size_t count, maxcount;
	int error;

	switch (mode) {
	case MNT_WAIT:
	case MNT_NOWAIT:
		break;
	default:
		if (bufseg == UIO_SYSSPACE)
			*buf = NULL;
		return (EINVAL);
	}
restart:
	maxcount = bufsize / sizeof(struct statfs);
	if (bufsize == 0) {
		sfsp = NULL;
		tofree = NULL;
	} else if (bufseg == UIO_USERSPACE) {
		sfsp = *buf;
		tofree = NULL;
	} else /* if (bufseg == UIO_SYSSPACE) */ {
		count = 0;
		mtx_lock(&mountlist_mtx);
		TAILQ_FOREACH(mp, &mountlist, mnt_list) {
			count++;
		}
		mtx_unlock(&mountlist_mtx);
		if (maxcount > count)
			maxcount = count;
		tofree = sfsp = *buf = malloc(maxcount * sizeof(struct statfs),
		    M_STATFS, M_WAITOK);
	}

	count = 0;

	/*
	 * If there is no target buffer they only want the count.
	 *
	 * This could be TAILQ_FOREACH but it is open-coded to match the original
	 * code below.
	 */
	if (sfsp == NULL) {
		mtx_lock(&mountlist_mtx);
		for (mp = TAILQ_FIRST(&mountlist); mp != NULL; mp = nmp) {
			if (prison_canseemount(td->td_ucred, mp) != 0) {
				nmp = TAILQ_NEXT(mp, mnt_list);
				continue;
			}
#ifdef MAC
			if (mac_mount_check_stat(td->td_ucred, mp) != 0) {
				nmp = TAILQ_NEXT(mp, mnt_list);
				continue;
			}
#endif
			count++;
			nmp = TAILQ_NEXT(mp, mnt_list);
		}
		mtx_unlock(&mountlist_mtx);
		*countp = count;
		return (0);
	}

	/*
	 * They want the entire thing.
	 *
	 * Short-circuit the corner case of no room for anything, avoids
	 * relocking below.
	 */
	if (maxcount < 1) {
		goto out;
	}

	mtx_lock(&mountlist_mtx);
	for (mp = TAILQ_FIRST(&mountlist); mp != NULL; mp = nmp) {
		if (prison_canseemount(td->td_ucred, mp) != 0) {
			nmp = TAILQ_NEXT(mp, mnt_list);
			continue;
		}
#ifdef MAC
		if (mac_mount_check_stat(td->td_ucred, mp) != 0) {
			nmp = TAILQ_NEXT(mp, mnt_list);
			continue;
		}
#endif
		if (mode == MNT_WAIT) {
			if (vfs_busy(mp, MBF_MNTLSTLOCK) != 0) {
				/*
				 * If vfs_busy() failed, and MBF_NOWAIT
				 * wasn't passed, then the mp is gone.
				 * Furthermore, because of MBF_MNTLSTLOCK,
				 * the mountlist_mtx was dropped.  We have
				 * no other choice than to start over.
				 */
				mtx_unlock(&mountlist_mtx);
				free(tofree, M_STATFS);
				goto restart;
			}
		} else {
			if (vfs_busy(mp, MBF_NOWAIT | MBF_MNTLSTLOCK) != 0) {
				nmp = TAILQ_NEXT(mp, mnt_list);
				continue;
			}
		}
		sp = &mp->mnt_stat;
		/*
		 * If MNT_NOWAIT is specified, do not refresh
		 * the fsstat cache.
		 */
		if (mode != MNT_NOWAIT) {
			error = VFS_STATFS(mp, sp);
			if (error != 0) {
				mtx_lock(&mountlist_mtx);
				nmp = TAILQ_NEXT(mp, mnt_list);
				vfs_unbusy(mp);
				continue;
			}
		}
		if (priv_check_cred_vfs_generation(td->td_ucred)) {
			sptmp = malloc(sizeof(struct statfs), M_STATFS,
			    M_WAITOK);
			*sptmp = *sp;
			prison_enforce_statfs(td->td_ucred, mp, sptmp);
			sp = sptmp;
		} else
			sptmp = NULL;
		if (bufseg == UIO_SYSSPACE) {
			bcopy(sp, sfsp, sizeof(*sp));
			free(sptmp, M_STATFS);
		} else /* if (bufseg == UIO_USERSPACE) */ {
			error = copyout(sp, sfsp, sizeof(*sp));
			free(sptmp, M_STATFS);
			if (error != 0) {
				vfs_unbusy(mp);
				return (error);
			}
		}
		sfsp++;
		count++;

		if (count == maxcount) {
			vfs_unbusy(mp);
			goto out;
		}

		mtx_lock(&mountlist_mtx);
		nmp = TAILQ_NEXT(mp, mnt_list);
		vfs_unbusy(mp);
	}
	mtx_unlock(&mountlist_mtx);
out:
	*countp = count;
	return (0);
}


#if defined(COMPAT_FREEBSD11)
/*
 * Get old format filesystem statistics.
 */
static void freebsd11_cvtstatfs(struct statfs *, struct freebsd11_statfs *);

int
freebsd11_statfs(struct thread *td, struct freebsd11_statfs_args *uap)
{
	struct freebsd11_statfs osb;
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_statfs(td, uap->path, UIO_USERSPACE, sfp);
	if (error == 0) {
		freebsd11_cvtstatfs(sfp, &osb);
		error = copyout(&osb, uap->buf, sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Get filesystem statistics.
 */
int
freebsd11_fstatfs(struct thread *td, struct freebsd11_fstatfs_args *uap)
{
	struct freebsd11_statfs osb;
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fstatfs(td, uap->fd, sfp);
	if (error == 0) {
		freebsd11_cvtstatfs(sfp, &osb);
		error = copyout(&osb, uap->buf, sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Get statistics on all filesystems.
 */
int
freebsd11_getfsstat(struct thread *td, struct freebsd11_getfsstat_args *uap)
{
	return (kern_freebsd11_getfsstat(td, uap->buf, uap->bufsize, uap->mode));
}

int
kern_freebsd11_getfsstat(struct thread *td, struct freebsd11_statfs * ubuf,
    long bufsize, int mode)
{
	struct freebsd11_statfs osb;
	struct statfs *buf, *sp;
	size_t count, size;
	int error;

	if (bufsize < 0)
		return (EINVAL);

	count = bufsize / sizeof(struct ostatfs);
	size = count * sizeof(struct statfs);
	error = kern_getfsstat(td, &buf, size, &count, UIO_SYSSPACE, mode);
	if (error == 0)
		td->td_retval[0] = count;
	if (size > 0) {
		sp = buf;
		while (count > 0 && error == 0) {
			freebsd11_cvtstatfs(sp, &osb);
			error = copyout(&osb, ubuf, sizeof(osb));
			sp++;
			ubuf++;
			count--;
		}
		free(buf, M_STATFS);
	}
	return (error);
}

/*
 * Implement fstatfs() for (NFS) file handles.
 */
int
freebsd11_fhstatfs(struct thread *td, struct freebsd11_fhstatfs_args *uap)
{
	struct freebsd11_statfs osb;
	struct statfs *sfp;
	fhandle_t fh;
	int error;

	error = copyin(uap->u_fhp, &fh, sizeof(fhandle_t));
	if (error)
		return (error);
	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fhstatfs(td, fh, sfp);
	if (error == 0) {
		freebsd11_cvtstatfs(sfp, &osb);
		error = copyout(&osb, uap->buf, sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Convert a new format statfs structure to an old format statfs structure.
 */
static void
freebsd11_cvtstatfs(struct statfs *nsp, struct freebsd11_statfs *osp)
{

	bzero(osp, sizeof(*osp));
	osp->f_version = FREEBSD11_STATFS_VERSION;
	osp->f_type = nsp->f_type;
	osp->f_flags = nsp->f_flags;
	osp->f_bsize = nsp->f_bsize;
	osp->f_iosize = nsp->f_iosize;
	osp->f_blocks = nsp->f_blocks;
	osp->f_bfree = nsp->f_bfree;
	osp->f_bavail = nsp->f_bavail;
	osp->f_files = nsp->f_files;
	osp->f_ffree = nsp->f_ffree;
	osp->f_syncwrites = nsp->f_syncwrites;
	osp->f_asyncwrites = nsp->f_asyncwrites;
	osp->f_syncreads = nsp->f_syncreads;
	osp->f_asyncreads = nsp->f_asyncreads;
	osp->f_namemax = nsp->f_namemax;
	osp->f_owner = nsp->f_owner;
	osp->f_fsid = nsp->f_fsid;
	strlcpy(osp->f_fstypename, nsp->f_fstypename,
	    MIN(MFSNAMELEN, sizeof(osp->f_fstypename)));
	strlcpy(osp->f_mntonname, nsp->f_mntonname,
	    MIN(MNAMELEN, sizeof(osp->f_mntonname)));
	strlcpy(osp->f_mntfromname, nsp->f_mntfromname,
	    MIN(MNAMELEN, sizeof(osp->f_mntfromname)));
}
#endif /* COMPAT_FREEBSD11 */

/*
 * Change current working directory to a given file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchdir_args {
	int	fd;
};
#endif

/*
 * fchdir(2), fchroot(2) of a served directory (D135, D163, D166, D169):
 * fp held by dqres_fchdir_file (UF_RESOLVE_BENEATH already refused),
 * consumed.  chroot's privilege rule first, then the attachment (EACCES
 * unattached, EDEADLK attached elsewhere), a revoked object (EIO), the
 * kind and the search check; the reference becomes dr_cwd or dr_root.
 */
static int
fchdir_dqres(struct thread *td, struct file *fp, bool root)
{
	int error;

	error = root ? chroot_priv_check(td) : 0;
	if (error == 0)
		error = dqres_dir_check(td, fp);
	if (error != 0) {
		fdrop(fp, td);
		return (error);
	}
	if (!root) {
		dqres_set_cwd(td, fp);
		return (0);
	}
	error = dqres_set_root(td, fp);
	if (error == 0)
		chroot_knote(td);
	return (error);
}

int
sys_fchdir(struct thread *td, struct fchdir_args *uap)
{
	struct vnode *vp, *tdp;
	struct mount *mp;
	struct file *fp;
	int error;
	uint8_t fdflags;

	AUDIT_ARG_FD(uap->fd);
	error = getvnode_path(td, uap->fd, &cap_fchdir_rights, &fdflags,
	    &fp);
	if (error == EINVAL) {
		/* A vnode-less descriptor: a served directory (D169)? */
		error = dqres_fchdir_file(td, uap->fd, &cap_fchdir_rights, &fp);
		if (error == 0)
			return (fchdir_dqres(td, fp, false));
		if (error == ENOTTY)
			error = EINVAL;
		return (error);
	}
	if (error != 0)
		return (error);
	if ((fdflags & UF_RESOLVE_BENEATH) != 0) {
		fdrop(fp, td);
		return (ENOTCAPABLE);
	}
	vp = fp->f_vnode;
	vrefact(vp);
	fdrop(fp, td);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
	error = change_dir(vp, td);
	while (!error && (mp = vp->v_mountedhere) != NULL) {
		if (vfs_busy(mp, 0))
			continue;
		error = VFS_ROOT(mp, LK_SHARED, &tdp);
		vfs_unbusy(mp);
		if (error != 0)
			break;
		vput(vp);
		vp = tdp;
	}
	if (error != 0) {
		vput(vp);
		return (error);
	}
	VOP_UNLOCK(vp);
	pwd_chdir(td, vp);
	return (0);
}

/*
 * Change current working directory (``.'').
 */
#ifndef _SYS_SYSPROTO_H_
struct chdir_args {
	char	*path;
};
#endif
int
sys_chdir(struct thread *td, struct chdir_args *uap)
{

	return (kern_chdir(td, uap->path, UIO_USERSPACE));
}

static int
kern_chdir_dqimpl(struct thread *td, const char *path, enum uio_seg pathseg)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1,
	    pathseg, path);
	if ((error = namei(&nd)) != 0)
		return (error);
	if ((error = change_dir(nd.ni_vp, td)) != 0) {
		vput(nd.ni_vp);
		NDFREE_PNBUF(&nd);
		return (error);
	}
	VOP_UNLOCK(nd.ni_vp);
	NDFREE_PNBUF(&nd);
	pwd_chdir(td, nd.ni_vp);
	return (0);
}

/*
 * chdir(2) answered FD (D169): a served directory, the D166 search
 * check, then the served cwd.  The real pd_pwd is unchanged.
 */
static int
kern_chdir_dqserved(struct thread *td, struct dq_intent *di)
{
	struct file *fp;
	int error;

	if (di->di_res.da_kind != DQ_RESOLVE_FD)
		return (EIO);
	error = dqres_take_dir(td, di, &fp);
	if (error != 0)
		return (error);
	dqres_set_cwd(td, fp);
	return (0);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_CHDIR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_chdir(struct thread *td, const char *path, enum uio_seg pathseg)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_chdir_dqimpl(td, path, pathseg));
	dq_intent_enter_served(td, &dqi, DQ_ROP_CHDIR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_FD));
	dq_intent_slot(&dqi, 0, path, pathseg, AT_FDCWD);
	dqerror = kern_chdir_dqimpl(td, path, pathseg);
	DQRES_SERVED(td, &dqi, dqerror, kern_chdir_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

static int unprivileged_chroot = 0;
SYSCTL_INT(_security_bsd, OID_AUTO, unprivileged_chroot, CTLFLAG_RW,
    &unprivileged_chroot, 0,
    "Unprivileged processes can use chroot(2)");

/*
 * chroot(2)'s privilege rule, shared by a real and a served root (D169):
 * PRIV_VFS_CHROOT, or security.bsd.unprivileged_chroot with
 * PROC_NO_NEW_PRIVS.
 */
static int
chroot_priv_check(struct thread *td)
{
	struct proc *p;
	int error;

	error = priv_check(td, PRIV_VFS_CHROOT);
	if (error != 0) {
		p = td->td_proc;
		if (unprivileged_chroot == 0)
			return (EXTERROR(EPERM,
		    "security.bsd.unprivileged_chroot sysctl not enabled"));
		if ((p->p_flag2 & P2_NO_NEW_PRIVS) == 0)
			return (EXTERROR(EPERM,
			    "PROC_NO_NEW_PRIVS not enabled"));
	}
	return (0);
}

/* A chroot, real or served, done: NOTE_CHROOT for process descriptors. */
static void
chroot_knote(struct thread *td)
{
	struct proc *p;

	p = td->td_proc;
	PROC_LOCK(p);
	procdesc_knote(p, NOTE_CHROOT);
	PROC_UNLOCK(p);
}

/*
 * Takes locked vnode, unlocks it before returning.
 *
 * Exported (prototype in <sys/syscallsubr.h>): the mac_capability capprotect
 * policy chroots a thread to a capability-owned vnode, and that policy is now
 * compiled statically into the kernel, so this helper must be a global symbol.
 */
int
kern_chroot(struct thread *td, struct vnode *vp)
{
	int error;

	error = chroot_priv_check(td);
	if (error != 0)
		goto e_vunlock;

	error = change_dir(vp, td);
	if (error != 0)
		goto e_vunlock;
#ifdef MAC
	error = mac_vnode_check_chroot(td->td_ucred, vp);
	if (error != 0)
		goto e_vunlock;
#endif
	VOP_UNLOCK(vp);
	error = pwd_chroot(td, vp);
	if (error == 0)
		chroot_knote(td);
	SDT_PROBE3(vfs, , , chroot, vp, td->td_ucred, error);
	vrele(vp);
	return (error);
e_vunlock:
	SDT_PROBE3(vfs, , , chroot, vp, td->td_ucred, error);
	vput(vp);
	return (error);
}

/*
 * Change notion of root (``/'') directory.
 */
#ifndef _SYS_SYSPROTO_H_
struct chroot_args {
	char	*path;
};
#endif
static int
sys_chroot_dqimpl(struct thread *td, struct chroot_args *uap)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1,
	    UIO_USERSPACE, uap->path);
	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	error = kern_chroot(td, nd.ni_vp);
	return (error);
}

/*
 * chroot(2) answered FD (D169): chroot's privilege rule, a served
 * directory, the D166 search check, the open-directory rule (served
 * directories counted), then the served root and NOTE_CHROOT.
 */
static int
sys_chroot_dqserved(struct thread *td, struct dq_intent *di)
{
	struct file *fp;
	int error;

	if (di->di_res.da_kind != DQ_RESOLVE_FD)
		return (EIO);
	/* A refusal leaves the answer to dq_intent_leave, which retires it. */
	error = chroot_priv_check(td);
	if (error != 0)
		return (error);
	error = dqres_take_dir(td, di, &fp);
	if (error != 0)
		return (error);
	error = dqres_set_root(td, fp);
	if (error == 0)
		chroot_knote(td);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_CHROOT; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
sys_chroot(struct thread *td, struct chroot_args *uap)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(true) || !DQRES_ATTACHED_TD(td))
		return (sys_chroot_dqimpl(td, uap));
	dq_intent_enter_served(td, &dqi, DQ_ROP_CHROOT, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_FD));
	dq_intent_slot(&dqi, 0, uap->path, UIO_USERSPACE, AT_FDCWD);
	dqerror = sys_chroot_dqimpl(td, uap);
	DQRES_SERVED(td, &dqi, dqerror, sys_chroot_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Change notion of root directory to a given file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchroot_args {
	int	fd;
};
#endif
int
sys_fchroot(struct thread *td, struct fchroot_args *uap)
{
	struct vnode *vp;
	struct file *fp;
	int error;
	uint8_t fdflags;

	error = getvnode_path(td, uap->fd, &cap_fchroot_rights, &fdflags, &fp);
	if (error == EINVAL) {
		/* A vnode-less descriptor: a served directory (D169)? */
		error = dqres_fchdir_file(td, uap->fd, &cap_fchroot_rights,
		    &fp);
		if (error == 0)
			return (fchdir_dqres(td, fp, true));
		if (error == ENOTTY)
			error = EINVAL;
		return (error);
	}
	if (error != 0)
		return (error);
	if ((fdflags & UF_RESOLVE_BENEATH) != 0) {
		fdrop(fp, td);
		return (ENOTCAPABLE);
	}
	vp = fp->f_vnode;
	vrefact(vp);
	fdrop(fp, td);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = kern_chroot(td, vp);
	return (error);
}

/*
 * Common routine for chroot and chdir.  Callers must provide a locked vnode
 * instance.
 */
int
change_dir(struct vnode *vp, struct thread *td)
{
#ifdef MAC
	int error;
#endif

	ASSERT_VOP_LOCKED(vp, "change_dir(): vp not locked");
	if (vp->v_type != VDIR)
		return (ENOTDIR);
#ifdef MAC
	error = mac_vnode_check_chdir(td->td_ucred, vp);
	if (error != 0)
		return (error);
#endif
	return (VOP_ACCESS(vp, VEXEC, td->td_ucred, td));
}

static __inline void
flags_to_rights(int flags, cap_rights_t *rightsp)
{
	if (flags & O_EXEC) {
		cap_rights_set_one(rightsp, CAP_FEXECVE);
		if (flags & O_PATH)
			return;
	} else {
		switch ((flags & O_ACCMODE)) {
		case O_RDONLY:
			cap_rights_set_one(rightsp, CAP_READ);
			break;
		case O_RDWR:
			cap_rights_set_one(rightsp, CAP_READ);
			/* FALLTHROUGH */
		case O_WRONLY:
			cap_rights_set_one(rightsp, CAP_WRITE);
			if (!(flags & (O_APPEND | O_TRUNC)))
				cap_rights_set_one(rightsp, CAP_SEEK);
			break;
		}
	}

	if (flags & O_CREAT)
		cap_rights_set_one(rightsp, CAP_CREATE);

	if (flags & O_TRUNC)
		cap_rights_set_one(rightsp, CAP_FTRUNCATE);

	if (flags & (O_SYNC | O_FSYNC | O_DSYNC))
		cap_rights_set_one(rightsp, CAP_FSYNC);

	if (flags & (O_EXLOCK | O_SHLOCK))
		cap_rights_set_one(rightsp, CAP_FLOCK);
}

/*
 * Check permissions, allocate an open file structure, and call the device
 * open routine if any.
 */
#ifndef _SYS_SYSPROTO_H_
struct open_args {
	char	*path;
	int	flags;
	int	mode;
};
#endif
int
sys_open(struct thread *td, struct open_args *uap)
{

	return (kern_openat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct openat_args {
	int	fd;
	char	*path;
	int	flag;
	int	mode;
};
#endif
int
sys_openat(struct thread *td, struct openat_args *uap)
{

	AUDIT_ARG_FD(uap->fd);
	return (kern_openat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->mode));
}

/*
 * Validate open(2) flags and convert access mode flags (O_RDONLY etc.) to their
 * in-kernel representations (FREAD etc.).
 */
static int
openflags(int *flagsp)
{
	int flags;

	flags = *flagsp;
	if ((flags & ~FUSERALLOWED) != 0)
		return (EINVAL);

	/*
	 * Only one of the O_EXEC, O_RDONLY, O_WRONLY and O_RDWR flags
	 * may be specified.  On the other hand, for O_PATH any mode
	 * except O_EXEC is ignored.
	 */
	if ((flags & O_PATH) != 0) {
		flags &= ~O_ACCMODE;
	} else if ((flags & O_EXEC) != 0) {
		if ((flags & O_ACCMODE) != 0)
			return (EINVAL);
	} else if ((flags & O_ACCMODE) == O_ACCMODE) {
		return (EINVAL);
	} else {
		flags = FFLAGS(flags);
	}
	*flagsp = flags;
	return (0);
}

static void
finit_open(struct file *fp, struct vnode *vp, int flags)
{
	/*
	 * Store the vnode, for any f_type. Typically, the vnode use count is
	 * decremented by a direct call to vnops.fo_close() for files that
	 * switched type.
	 */
	fp->f_vnode = vp;

	/*
	 * If the file wasn't claimed by devfs or fifofs, bind it to the normal
	 * vnode operations here.
	 */
	if (fp->f_ops == &badfileops) {
		KASSERT(vp->v_type != VFIFO || (flags & O_PATH) != 0,
		    ("Unexpected fifo fp %p vp %p", fp, vp));
		if ((flags & O_PATH) != 0) {
			finit(fp, (flags & FMASK) | (fp->f_flag & FKQALLOWED),
			    DTYPE_VNODE, NULL, &path_fileops);
		} else {
			finit_vnode(fp, flags, NULL, &vnops);
		}
	}
}

/*
 * If fpp != NULL, opened file is not installed into the file
 * descriptor table, instead it is returned in *fpp.  This is
 * incompatible with fdopen(), in which case we return EINVAL.
 */
static int
openatfp_dqimpl(struct thread *td, int dirfd, const char *path,
    enum uio_seg pathseg, int flags, int mode, uint64_t lookup_flags,
    struct file **fpp)
{
	struct proc *p;
	struct filedesc *fdp;
	struct pwddesc *pdp;
	struct file *fp;
	struct vnode *vp;
	struct filecaps *fcaps;
	struct nameidata nd;
	cap_rights_t rights;
	int cmode, error, indx;

	indx = -1;
	p = td->td_proc;
	fdp = p->p_fd;
	pdp = p->p_pd;

	AUDIT_ARG_FFLAGS(flags);
	AUDIT_ARG_MODE(mode);
	cap_rights_init_one(&rights, CAP_LOOKUP);
	flags_to_rights(flags, &rights);

	error = openflags(&flags);
	if (error != 0)
		return (error);

	/*
	 * Allocate a file structure. The descriptor to reference it
	 * is allocated and used by finstall_refed() below.
	 */
	error = falloc_noinstall(td, &fp);
	if (error != 0)
		return (error);
	/* Set the flags early so the finit in devfs can pick them up. */
	fp->f_flag = flags & FMASK;
	cmode = ((mode & ~pdp->pd_cmask) & ALLPERMS) & ~S_ISTXT;
	NDINIT_ATRIGHTS(&nd, LOOKUP,
	    FOLLOW | AUDITVNODE1 | WANTIOCTLCAPS | lookup_flags,
	    pathseg, path, dirfd, &rights);
	td->td_dupfd = -1;		/* XXX check for fdopen */
	error = vn_open_cred(&nd, &flags, cmode, VN_OPEN_WANTIOCTLCAPS,
	    td->td_ucred, fp);
	if (error != 0) {
		/*
		 * If the vn_open replaced the method vector, something
		 * wonderous happened deep below and we just pass it up
		 * pretending we know what we do.
		 */
		if (error == ENXIO && fp->f_ops != &badfileops) {
			MPASS((flags & O_PATH) == 0 || fp->f_type == DTYPE_PIPE);
			error = 0;
			goto success;
		}

		/*
		 * Handle special fdopen() case. bleh.
		 *
		 * Don't do this for relative (capability) lookups; we don't
		 * understand exactly what would happen, and we don't think
		 * that it ever should.
		 */
		if ((nd.ni_resflags & NIRES_STRICTREL) == 0 &&
		    (error == ENODEV || error == ENXIO) &&
		    td->td_dupfd >= 0) {
			MPASS(fpp == NULL);
			error = dupfdopen(td, fdp, td->td_dupfd, flags, error,
			    &indx);
			if (error == 0)
				goto success;
		}

		goto bad;
	}
	td->td_dupfd = 0;
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;

	finit_open(fp, vp, flags);
	VOP_UNLOCK(vp);
	if (flags & O_TRUNC) {
		error = fo_truncate(fp, 0, td->td_ucred, td);
		if (error != 0)
			goto bad;
	}
success:
	if (fpp != NULL) {
		MPASS(error == 0);
		NDFREE_IOCTLCAPS(&nd);
		*fpp = fp;
		return (0);
	}

	/*
	 * If we haven't already installed the FD (for dupfdopen), do so now.
	 */
	if (indx == -1) {
#ifdef CAPABILITIES
		if ((nd.ni_resflags & NIRES_STRICTREL) != 0)
			fcaps = &nd.ni_filecaps;
		else
#endif
			fcaps = NULL;
		if ((nd.ni_resflags & NIRES_BENEATH) != 0)
			flags |= O_RESOLVE_BENEATH;
		else
			flags &= ~O_RESOLVE_BENEATH;
		error = finstall_refed(td, fp, &indx, flags, fcaps);
		/* On success finstall_refed() consumes fcaps. */
		if (error != 0) {
			goto bad;
		}
	} else {
		NDFREE_IOCTLCAPS(&nd);
		falloc_abort(td, fp);
	}

	td->td_retval[0] = indx;
	return (0);
bad:
	KASSERT(indx == -1, ("indx=%d, should be -1", indx));
	NDFREE_IOCTLCAPS(&nd);
	falloc_abort(td, fp);
	return (error);
}

/*
 * A swapped file as the result of open(2) (sys/fdswap.h): the open layer.
 *
 * open_swap_admit(): may this open file, held by the process answering
 * the open, be what an open(2) with 'oflags' (the caller's, before
 * openflags()) and lookup flags 'rflags' (DQ_RF_*) returns?  It must
 * present as what the open would have produced: a vnode file, of a type
 * and with the access mode and status flags the request asked for, as
 * fresh as a new open is.  Run in the answering thread under its
 * descriptor-table lock (fdswap_take), so it does not sleep; 'rights' are
 * the rights that would be transferred.  A refusal goes to the answering
 * process, never to the program:
 *	EOPNOTSUPP	not a vnode; a full open of anything but a regular
 *			file or a directory (a device's and a FIFO's open
 *			acts in the opener's context, which a swap does not
 *			run for the program)
 *	EFTYPE		type, access mode or status flags differ; a
 *			directory for an O_CREAT without O_DIRECTORY; a
 *			symbolic link for anything but O_PATH | O_NOFOLLOW;
 *			not a directory for a name with a trailing slash;
 *			a file that was read or seeked (non-zero offset);
 *			that holds a flock the request did not ask for, or
 *			has ever held an OFD lock (FHASOFDLOCK is never
 *			cleared); for O_CREAT | O_EXCL with a lock, a file
 *			on which the answering process does not hold the
 *			flock (the program's must never wait: base's
 *			F_FIRSTOPEN)
 *	ENOTCAPABLE	O_SHLOCK/O_EXLOCK asked and CAP_FLOCK not transferred
 *	EINVAL		the request's flags are not valid open flags
 * O_CREAT, O_EXCL, and the choice of object are the answering process's
 * own open; O_TRUNC is applied at completion (open_swap_check, then the
 * caller), so the supplied file must not have been opened with it.  The
 * offset test is racy by nature, as the sole-reference rule is: a check
 * against mistakes.
 */
#define	OPEN_SWAP_ACCMODE	(FREAD | FWRITE | FEXEC | O_PATH)
#define	OPEN_SWAP_STATUS	(FAPPEND | FNONBLOCK | FFSYNC | FDSYNC | \
	    O_DIRECT | FASYNC)

static int
open_swap_refuse(int reason)
{

	SDT_PROBE3(dqres, , , subst__refuse, DQ_ROP_OPEN, reason, EFTYPE);
	return (EFTYPE);
}

int
open_swap_admit(struct file *fp, int oflags, uint32_t rflags,
    const cap_rights_t *rights)
{
	struct vnode *vp;
	int fflags;

	fflags = oflags;
	if (openflags(&fflags) != 0)
		return (EINVAL);
	if (fp->f_type != DTYPE_VNODE || (vp = fp->f_vnode) == NULL)
		return (EOPNOTSUPP);
	if ((fflags & O_PATH) == 0) {
		if (vp->v_type != VREG && vp->v_type != VDIR)
			return (EOPNOTSUPP);
		/* vn_open_vnode: a directory opens for reading or search. */
		if (vp->v_type == VDIR && (fflags & (FWRITE | O_TRUNC)) != 0)
			return (EFTYPE);
	}
	/* vn_open_cred: O_CREAT of an existing directory is EISDIR. */
	if (vp->v_type == VDIR &&
	    (fflags & (O_CREAT | O_DIRECTORY)) == O_CREAT)
		return (EFTYPE);
	/* A symbolic link is what only O_PATH | O_NOFOLLOW opens. */
	if (vp->v_type == VLNK && ((fflags & O_NOFOLLOW) == 0 ||
	    (fflags & FEXEC) != 0))
		return (EFTYPE);
	if ((fflags & O_DIRECTORY) != 0 && vp->v_type != VDIR)
		return (EFTYPE);
	if (((fp->f_flag ^ fflags) & (OPEN_SWAP_ACCMODE | OPEN_SWAP_STATUS)) !=
	    0)
		return (EFTYPE);
	if ((fflags & (O_SHLOCK | O_EXLOCK)) != 0 && (fflags & O_PATH) == 0 &&
	    !cap_rights_is_set(rights, CAP_FLOCK))
		return (ENOTCAPABLE);
	/* namei: a trailing slash names a directory. */
	if ((rflags & DQ_RF_TRAILINGSLASH) != 0 && vp->v_type != VDIR)
		return (open_swap_refuse(DQRES_R_SUBST_SLASH));
	if (foffset_get(fp) != 0)
		return (open_swap_refuse(DQRES_R_SUBST_OFFSET));
	if ((fp->f_flag & FHASOFDLOCK) != 0)
		return (open_swap_refuse(DQRES_R_SUBST_OFDLOCK));
	if ((fp->f_flag & FHASLOCK) != 0 &&
	    (fflags & (O_SHLOCK | O_EXLOCK)) == 0)
		return (open_swap_refuse(DQRES_R_SUBST_FLOCK));
	if ((fflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) &&
	    (fflags & (O_SHLOCK | O_EXLOCK)) != 0 &&
	    (fp->f_flag & FHASLOCK) == 0)
		return (open_swap_refuse(DQRES_R_SUBST_EXCL_LOCK));
	return (0);
}

/*
 * open_swap_check(): the requesting thread's own permission on the file
 * it is about to receive, MAC then DAC, in vn_open_vnode()'s order and
 * with its access mode, so the program sees the errno its own open of
 * this object would have given.  'fflags' are the request's flags after
 * openflags().  VOP_OPEN is not run again: the file had its open, under
 * the answering process's credential, and will have one close.
 *
 * 'declared_created': the answering process says it created the file for
 * this O_CREAT request.  Base skips the access check for a file the open
 * created; here that is honoured only for a regular file the requester's
 * effective uid owns and that carries no immutable or append-only flag
 * (what a false declaration then gains is bounded by what the owner's
 * chmod could have).  *createdp says whether it was honoured; the caller
 * then does not truncate, as base does not truncate a file it created.
 */
int
open_swap_check(struct thread *td, struct file *fp, int fflags,
    bool declared_created, bool *createdp)
{
	struct vattr va;
	struct vnode *vp;
	accmode_t accmode;
	int error;
	bool created;

	*createdp = false;
	MPASS(fp->f_type == DTYPE_VNODE);
	vp = fp->f_vnode;
	/* open_swap_admit made them equal; the union is belt and braces. */
	fflags |= fp->f_flag & (FREAD | FWRITE | FEXEC);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	if (VN_IS_DOOMED(vp)) {
		error = EBADF;
		goto out;
	}
	created = false;
	if (declared_created && (fflags & (O_CREAT | O_PATH)) == O_CREAT &&
	    vp->v_type == VREG) {
		error = VOP_GETATTR(vp, &va, td->td_ucred);
		if (error != 0)
			goto out;
		created = va.va_uid == td->td_ucred->cr_uid &&
		    (va.va_flags & (IMMUTABLE | APPEND)) == 0;
	}
	accmode = 0;
	if ((fflags & O_PATH) == 0) {
		if ((fflags & (FWRITE | O_TRUNC)) != 0)
			accmode |= VWRITE;
		if ((fflags & FREAD) != 0)
			accmode |= VREAD;
		if ((fflags & O_APPEND) != 0 && (fflags & FWRITE) != 0)
			accmode |= VAPPEND;
#ifdef MAC
		/* As base, which clears O_CREAT when the file existed. */
		if (created)
			accmode |= VCREAT;
#endif
	}
	if ((fflags & FEXEC) != 0)
		accmode |= VEXEC;
#ifdef MAC
	if ((fflags & O_VERIFY) != 0)
		accmode |= VVERIFY;
	error = mac_vnode_check_open(td->td_ucred, vp, accmode);
	if (error != 0)
		goto out;
	accmode &= ~(VCREAT | VVERIFY);
#endif
	/* The object the open returns, beside the name it asked for. */
	AUDIT_ARG_VNODE1(vp);
	if (!created && accmode != 0) {
		error = VOP_ACCESS(vp, accmode, td->td_ucred, td);
		if (error != 0)
			goto out;
	}
	/*
	 * Base lets an O_PATH descriptor into a kqueue only when the opener
	 * could read the node.  The flag is the supplied file's, which this
	 * code does not alter: a file that has it is refused to a requester
	 * that may not read (a documented difference from base, which would
	 * have returned a descriptor without kqueue access).
	 */
	if ((fflags & O_PATH) != 0 && (fp->f_flag & FKQALLOWED) != 0 &&
	    VOP_ACCESS(vp, VREAD, td->td_ucred, td) != 0) {
		error = EACCES;
		goto out;
	}
	*createdp = created;
#ifdef MAC
	/*
	 * The open the program receives, under its own credential and with
	 * the vnode locked, as vn_open_vnode tells the policies.  inotify is
	 * not told again: the answering process's open raised IN_OPEN, and
	 * the file has one close.
	 */
	mac_vnode_notify_open(td->td_ucred, vp, fflags);
#endif
out:
	VOP_UNLOCK(vp);
	return (error);
}

/*
 * open(2) answered FD (D133, D159, D166, D176): the checks a real open of
 * the presented file would fail, the bind in the requester's credential,
 * O_EXLOCK/O_SHLOCK through fo_advlock (a LOCK event; a signal is EINTR,
 * never a restart after a served answer), O_TRUNC through fo_truncate,
 * then the install or *fpp.  O_CREAT and O_EXCL were the controller's.
 *
 * open(2) answered SWAP: the real open file the supervisor handed over.
 * dqres_take_file makes the receive check; open_swap_check then checks
 * this thread's own MAC and DAC permission on the object.  The lock and
 * the truncation follow as for FD and in base's order, on the real file:
 * the truncation is the kernel's, made only now that write permission
 * was checked under this thread's credential, and not for a file the
 * supervisor created for this open (base does not truncate what it
 * created).  A lock wait interrupted under SA_RESTART restarts the open,
 * which consults the supervisor again, as base's open restarts.  For
 * O_CREAT | O_EXCL the supervisor holds the flock (open_swap_admit), so
 * the program's lock converts it without waiting, as base's F_FIRSTOPEN
 * never waits; a conversion that would wait (a shared lock handed over
 * for O_EXLOCK, with another holder) is a refused answer: EIO, counted.
 * Any failure drops the file: nothing is installed.
 */
static int
openatfp_dqserved(struct thread *td, struct dq_intent *di, int flags,
    struct file **fpp)
{
	struct file *fp;
	struct flock lf;
	int error, indx, type;
	bool created, swap;

	if (di->di_res.da_kind != DQ_RESOLVE_FD &&
	    di->di_res.da_kind != DQ_RESOLVE_SWAP)
		return (EIO);
	swap = di->di_res.da_kind == DQ_RESOLVE_SWAP;
	error = openflags(&flags);
	if (error != 0)
		return (error);
	error = dqres_take_file(td, di, flags, &fp);
	if (error != 0)
		return (error);
	created = false;
	if (swap) {
		error = open_swap_check(td, fp, flags,
		    (di->di_res.da_swflags & DQ_SWAP_F_CREATED) != 0, &created);
		if (error != 0) {
			fdrop(fp, td);
			return (error);
		}
		di->di_res.da_swcreated = created;
	}
	if ((flags & (O_EXLOCK | O_SHLOCK)) != 0 && (flags & O_PATH) == 0) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = (flags & O_EXLOCK) != 0 ? F_WRLCK : F_RDLCK;
		type = F_FLOCK;
		if ((flags & FNONBLOCK) == 0 && (!swap ||
		    (flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL)))
			type |= F_WAIT;
		error = fo_advlock(fp, (caddr_t)fp, F_SETLK, &lf, type, td);
		if (swap && (type & F_WAIT) == 0 && error == EAGAIN &&
		    (flags & FNONBLOCK) == 0) {
			SDT_PROBE3(dqres, , , subst__refuse, DQ_ROP_OPEN,
			    DQRES_R_SUBST_EXCL_LOCK, EIO);
			dqres_bad_answer(td);
			error = EIO;
		}
		if (error == ERESTART && !swap)
			error = EINTR;
		if (error != 0) {
			fdrop(fp, td);	/* the last reference: retired */
			return (error);
		}
		atomic_set_int(&fp->f_flag, FHASLOCK);
	}
	/*
	 * O_TRUNC as openatfp_dqimpl applies it, after D166 checked write
	 * access (so O_RDONLY | O_TRUNC truncates as on a real file): the
	 * object's SETATTR.  For SWAP, the real file's truncation.
	 */
	if ((flags & O_TRUNC) != 0 && (flags & O_PATH) == 0 && !created) {
		error = fo_truncate(fp, 0, td->td_ucred, td);
		if (error != 0) {
			fdrop(fp, td);
			return (error);
		}
	}
	if (fpp != NULL) {
		*fpp = fp;
		return (0);
	}
	error = dqres_install(td, di, fp, flags, &indx);
	if (error == 0)
		td->td_retval[0] = indx;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_OPEN; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
static int
openatfp(struct thread *td, int dirfd, const char *path,
    enum uio_seg pathseg, int flags, int mode, uint64_t lookup_flags,
    struct file **fpp)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (openatfp_dqimpl(td, dirfd, path, pathseg, flags, mode, lookup_flags, fpp));
	/*
	 * A swapped file is installed with the rights and states its carrier
	 * holds and through the queue's gate (dqres_install): it is not
	 * offered to a caller that takes the file itself.
	 */
	dq_intent_enter_served(td, &dqi, DQ_ROP_OPEN, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_FD) |
	    (fpp == NULL ? DQ_RACCEPT(DQ_RESOLVE_SWAP) : 0));
	dqi.di_cmode = ((mode & ~td->td_proc->p_pd->pd_cmask) & ALLPERMS) &
	    ~S_ISTXT;
	dqi.di_mode = flags;
	dq_intent_slot(&dqi, 0, path, pathseg, dirfd);
	dqerror = openatfp_dqimpl(td, dirfd, path, pathseg, flags, mode, lookup_flags, fpp);
	DQRES_SERVED(td, &dqi, dqerror, openatfp_dqserved(td, &dqi, flags, fpp));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

int
kern_openat(struct thread *td, int dirfd, const char *path,
    enum uio_seg pathseg, int flags, int mode)
{
	return (openatfp(td, dirfd, path, pathseg, flags, mode, 0, NULL));
}

/* Internal per-lookup constraints, independent of descriptor open flags. */
int
kern_openat_resolve(struct thread *td, int dirfd, const char *path,
    enum uio_seg pathseg, int flags, int mode, uint64_t lookup_flags)
{

	if ((lookup_flags & ~(NOSYMLINKS | NOMAGICLINKS | NOXDEV | RINROOT)) != 0)
		return (EINVAL);
	return (openatfp(td, dirfd, path, pathseg, flags, mode, lookup_flags,
	    NULL));
}

int
kern_openatfp(struct thread *td, int dirfd, const char *path,
    enum uio_seg pathseg, int flags, int mode, struct file **fpp)
{
	int error, old_dupfd;

	old_dupfd = td->td_dupfd;
	td->td_dupfd = -1;
	error = openatfp(td, dirfd, path, pathseg, flags, mode, 0, fpp);
	td->td_dupfd = old_dupfd;
	return (error);
}

#ifdef COMPAT_43
/*
 * Create a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct ocreat_args {
	char	*path;
	int	mode;
};
#endif
int
ocreat(struct thread *td, struct ocreat_args *uap)
{

	return (kern_openat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    O_WRONLY | O_CREAT | O_TRUNC, uap->mode));
}
#endif /* COMPAT_43 */

/*
 * Create a special file.
 */
#ifndef _SYS_SYSPROTO_H_
struct mknodat_args {
	int	fd;
	char	*path;
	mode_t	mode;
	dev_t	dev;
};
#endif
int
sys_mknodat(struct thread *td, struct mknodat_args *uap)
{

	return (kern_mknodat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode,
	    uap->dev));
}

#if defined(COMPAT_FREEBSD11)
int
freebsd11_mknod(struct thread *td,
    struct freebsd11_mknod_args *uap)
{

	return (kern_mknodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, uap->dev));
}

int
freebsd11_mknodat(struct thread *td,
    struct freebsd11_mknodat_args *uap)
{

	return (kern_mknodat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode,
	    uap->dev));
}
#endif /* COMPAT_FREEBSD11 */

static int
kern_mknodat_dqimpl(struct thread *td, int fd, const char *path, enum uio_seg pathseg,
    int mode, dev_t dev)
{
	struct vnode *vp;
	struct mount *mp;
	struct vattr vattr;
	struct nameidata nd;
	int error, whiteout = 0;

	AUDIT_ARG_MODE(mode);
	AUDIT_ARG_DEV(dev);
	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
		error = priv_check(td, PRIV_VFS_MKNOD_DEV);
		if (error == 0 && dev == VNOVAL)
			error = EINVAL;
		break;
	case S_IFWHT:
		error = priv_check(td, PRIV_VFS_MKNOD_WHT);
		break;
	case S_IFIFO:
		if (dev == 0)
			return (kern_mkfifoat(td, fd, path, pathseg, mode));
		/* FALLTHROUGH */
	default:
		error = EINVAL;
		break;
	}
	if (error != 0)
		return (error);
	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | AUDITVNODE1 | NOCACHE,
	    pathseg, path, fd, &cap_mknodat_rights);
	if ((error = namei(&nd)) != 0)
		return (error);
	vp = nd.ni_vp;
	if (vp != NULL) {
		NDFREE_PNBUF(&nd);
		if (vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		return (EEXIST);
	} else if ((vn_irflag_read(nd.ni_dvp) & VIRF_NAMEDDIR) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		return (EINVAL);
	} else {
		VATTR_NULL(&vattr);
		vattr.va_mode = (mode & ALLPERMS) &
		    ~td->td_proc->p_pd->pd_cmask;
		vattr.va_rdev = dev;
		whiteout = 0;

		switch (mode & S_IFMT) {
		case S_IFCHR:
			vattr.va_type = VCHR;
			break;
		case S_IFBLK:
			vattr.va_type = VBLK;
			break;
		case S_IFWHT:
			whiteout = 1;
			break;
		default:
			panic("kern_mknod: invalid mode");
		}
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			return (error);
		goto restart;
	}
#ifdef MAC
	if (error == 0 && !whiteout)
		error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp,
		    &nd.ni_cnd, &vattr);
#endif
	if (error == 0) {
		if (whiteout)
			error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, CREATE);
		else {
			error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp,
						&nd.ni_cnd, &vattr);
		}
	}
	VOP_VPUT_PAIR(nd.ni_dvp, error == 0 && !whiteout ? &nd.ni_vp : NULL,
	    true);
	vn_finished_write(mp);
	NDFREE_PNBUF(&nd);
	if (error == ERELOOKUP)
		goto restart;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_MKNOD; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_mknodat(struct thread *td, int fd, const char *path, enum uio_seg pathseg,
    int mode, dev_t dev)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_mknodat_dqimpl(td, fd, path, pathseg, mode, dev));
	dq_intent_enter_served(td, &dqi, DQ_ROP_MKNOD, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dqi.di_cmode = (mode & ALLPERMS) & ~td->td_proc->p_pd->pd_cmask;
	dqi.di_dev = dev;
	dqi.di_mode = mode;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_mknodat_dqimpl(td, fd, path, pathseg, mode, dev);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Create a named pipe.
 */
#ifndef _SYS_SYSPROTO_H_
struct mkfifo_args {
	char	*path;
	int	mode;
};
#endif
int
sys_mkfifo(struct thread *td, struct mkfifo_args *uap)
{

	return (kern_mkfifoat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct mkfifoat_args {
	int	fd;
	char	*path;
	mode_t	mode;
};
#endif
int
sys_mkfifoat(struct thread *td, struct mkfifoat_args *uap)
{

	return (kern_mkfifoat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->mode));
}

static int
kern_mkfifoat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int mode)
{
	struct mount *mp;
	struct vattr vattr;
	struct nameidata nd;
	int error;

	AUDIT_ARG_MODE(mode);
	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | AUDITVNODE1 | NOCACHE,
	    pathseg, path, fd, &cap_mkfifoat_rights);
	if ((error = namei(&nd)) != 0)
		return (error);
	if (nd.ni_vp != NULL) {
		NDFREE_PNBUF(&nd);
		if (nd.ni_vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		return (EEXIST);
	}
	if ((vn_irflag_read(nd.ni_dvp) & VIRF_NAMEDDIR) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		return (EINVAL);
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			return (error);
		goto restart;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VFIFO;
	vattr.va_mode = (mode & ALLPERMS) & ~td->td_proc->p_pd->pd_cmask;
#ifdef MAC
	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd,
	    &vattr);
	if (error != 0)
		goto out;
#endif
	error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
#ifdef MAC
out:
#endif
	VOP_VPUT_PAIR(nd.ni_dvp, error == 0 ? &nd.ni_vp : NULL, true);
	vn_finished_write(mp);
	NDFREE_PNBUF(&nd);
	if (error == ERELOOKUP)
		goto restart;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_MKFIFO; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_mkfifoat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int mode)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_mkfifoat_dqimpl(td, fd, path, pathseg, mode));
	dq_intent_enter_served(td, &dqi, DQ_ROP_MKFIFO, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dqi.di_cmode = (mode & ALLPERMS) & ~td->td_proc->p_pd->pd_cmask;
	dqi.di_mode = mode;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_mkfifoat_dqimpl(td, fd, path, pathseg, mode);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Make a hard file link.
 */
#ifndef _SYS_SYSPROTO_H_
struct link_args {
	char	*path;
	char	*link;
};
#endif
int
sys_link(struct thread *td, struct link_args *uap)
{

	return (kern_linkat(td, AT_FDCWD, AT_FDCWD, uap->path, uap->link,
	    UIO_USERSPACE, AT_SYMLINK_FOLLOW));
}

#ifndef _SYS_SYSPROTO_H_
struct linkat_args {
	int	fd1;
	char	*path1;
	int	fd2;
	char	*path2;
	int	flag;
};
#endif
int
sys_linkat(struct thread *td, struct linkat_args *uap)
{

	return (kern_linkat(td, uap->fd1, uap->fd2, uap->path1, uap->path2,
	    UIO_USERSPACE, uap->flag));
}

int hardlink_check_uid = 0;
SYSCTL_INT(_security_bsd, OID_AUTO, hardlink_check_uid, CTLFLAG_RW,
    &hardlink_check_uid, 0,
    "Unprivileged processes cannot create hard links to files owned by other "
    "users");
static int hardlink_check_gid = 0;
SYSCTL_INT(_security_bsd, OID_AUTO, hardlink_check_gid, CTLFLAG_RW,
    &hardlink_check_gid, 0,
    "Unprivileged processes cannot create hard links to files owned by other "
    "groups");

static int
can_hardlink(struct vnode *vp, struct ucred *cred)
{
	struct vattr va;
	int error;

	if (!hardlink_check_uid && !hardlink_check_gid)
		return (0);

	error = VOP_GETATTR(vp, &va, cred);
	if (error != 0)
		return (error);

	if (hardlink_check_uid && cred->cr_uid != va.va_uid) {
		error = priv_check_cred(cred, PRIV_VFS_LINK);
		if (error != 0)
			return (error);
	}

	if (hardlink_check_gid && !groupmember(va.va_gid, cred)) {
		error = priv_check_cred(cred, PRIV_VFS_LINK);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
kern_linkat_dqimpl(struct thread *td, int fd1, int fd2, const char *path1,
    const char *path2, enum uio_seg segflag, int flag)
{
	struct nameidata nd;
	struct file *fp;
	int error;

	if ((flag & ~(AT_SYMLINK_FOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	NDPREINIT(&nd);
	do {
		bwillwrite();
		NDINIT_ATRIGHTS(&nd, LOOKUP, AUDITVNODE1 | at2cnpflags(flag,
		    AT_SYMLINK_FOLLOW | AT_RESOLVE_BENEATH | AT_EMPTY_PATH),
		    segflag, path1, fd1, &cap_linkat_source_rights);
		if ((error = namei(&nd)) != 0) {
			/*
			 * D164 (Q5): a served descriptor has no name to
			 * link in the real namespace.
			 */
			if (error == ENOTDIR &&
			    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
			    dqres_emptypath_file(td, fd1,
			    &cap_linkat_source_rights, &fp) == 0) {
				fdrop(fp, td);
				error = EXDEV;
			}
			return (error);
		}
		NDFREE_PNBUF(&nd);
		if ((nd.ni_resflags & NIRES_EMPTYPATH) != 0) {
			error = priv_check(td, PRIV_VFS_FHOPEN);
#ifdef MAC
			if (error == 0) {
				error = vn_lock(nd.ni_vp, LK_SHARED);
				if (error == 0) {
					error = mac_vnode_check_fh(td->td_ucred, nd.ni_vp);
					VOP_UNLOCK(nd.ni_vp);
				}
			}
#endif
			if (error != 0) {
				vrele(nd.ni_vp);
				return (error);
			}
		}
		error = kern_linkat_vp(td, nd.ni_vp, fd2, path2, segflag);
	} while (error ==  EAGAIN || error == ERELOOKUP);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_LINK; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_linkat(struct thread *td, int fd1, int fd2, const char *path1,
    const char *path2, enum uio_seg segflag, int flag)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(segflag == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_linkat_dqimpl(td, fd1, fd2, path1, path2, segflag, flag));
	dq_intent_enter_served(td, &dqi, DQ_ROP_LINK, DQI_USER | DQI_NO_ERESTART | DQI_PATH2,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dq_intent_slot(&dqi, 0, path1, segflag, fd1);
	dq_intent_slot(&dqi, 1, path2, segflag, fd2);
	dq_intent_slot_rights(&dqi, 1, &cap_linkat_target_rights);
	dqerror = kern_linkat_dqimpl(td, fd1, fd2, path1, path2, segflag, flag);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

static int
kern_linkat_vp(struct thread *td, struct vnode *vp, int fd, const char *path,
    enum uio_seg segflag)
{
	struct nameidata nd;
	struct mount *mp;
	int error;

	if (vp->v_type == VDIR) {
		vrele(vp);
		return (EPERM);		/* POSIX */
	}
	if ((vn_irflag_read(vp) & (VIRF_NAMEDDIR | VIRF_NAMEDATTR)) != 0) {
		vrele(vp);
		return (EINVAL);
	}
	/*
	 * dq-ledger: slot 1 path2 of kern/vfs_syscalls.c:kern_linkat, slot 0 path of kern/vfs_syscalls.c:kern_fhlinkat
	 */
	NDINIT_ATRIGHTS(&nd, CREATE,
	    LOCKPARENT | AUDITVNODE2 | NOCACHE, segflag, path, fd,
	    &cap_linkat_target_rights);
	if ((error = namei(&nd)) == 0) {
		if (nd.ni_vp != NULL) {
			NDFREE_PNBUF(&nd);
			if (nd.ni_dvp == nd.ni_vp)
				vrele(nd.ni_dvp);
			else
				vput(nd.ni_dvp);
			vrele(nd.ni_vp);
			vrele(vp);
			return (EEXIST);
		} else if (nd.ni_dvp->v_mount != vp->v_mount) {
			/*
			 * Cross-device link.  No need to recheck
			 * vp->v_type, since it cannot change, except
			 * to VBAD.
			 */
			NDFREE_PNBUF(&nd);
			vput(nd.ni_dvp);
			vrele(vp);
			return (EXDEV);
		} else if (vn_lock(vp, LK_EXCLUSIVE) == 0) {
			error = can_hardlink(vp, td->td_ucred);
#ifdef MAC
			if (error == 0)
				error = mac_vnode_check_link(td->td_ucred,
				    nd.ni_dvp, vp, &nd.ni_cnd);
#endif
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE_PNBUF(&nd);
				return (error);
			}
			error = vn_start_write(vp, &mp, V_NOWAIT);
			if (error != 0) {
				vput(vp);
				vput(nd.ni_dvp);
				NDFREE_PNBUF(&nd);
				error = vn_start_write(NULL, &mp,
				    V_XSLEEP | V_PCATCH);
				if (error != 0)
					return (error);
				return (EAGAIN);
			}
			error = VOP_LINK(nd.ni_dvp, vp, &nd.ni_cnd);
#ifdef MAC
			if (error == 0)
				mac_vnode_notify_link(td->td_ucred,
				    nd.ni_dvp, vp, &nd.ni_cnd);
#endif
			VOP_VPUT_PAIR(nd.ni_dvp, &vp, true);
			vn_finished_write(mp);
			NDFREE_PNBUF(&nd);
			vp = NULL;
		} else {
			vput(nd.ni_dvp);
			NDFREE_PNBUF(&nd);
			vrele(vp);
			return (EAGAIN);
		}
	}
	if (vp != NULL)
		vrele(vp);
	return (error);
}

/*
 * Make a symbolic link.
 */
#ifndef _SYS_SYSPROTO_H_
struct symlink_args {
	char	*path;
	char	*link;
};
#endif
int
sys_symlink(struct thread *td, struct symlink_args *uap)
{

	return (kern_symlinkat(td, uap->path, AT_FDCWD, uap->link,
	    UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct symlinkat_args {
	char	*path;
	int	fd;
	char	*path2;
};
#endif
int
sys_symlinkat(struct thread *td, struct symlinkat_args *uap)
{

	return (kern_symlinkat(td, uap->path1, uap->fd, uap->path2,
	    UIO_USERSPACE));
}

static int
kern_symlinkat_dqimpl(struct thread *td, const char *path1, enum uio_seg seg1,
    int fd, const char *path2, enum uio_seg segflg)
{
	struct mount *mp;
	struct vattr vattr;
	const char *syspath;
	char *tmppath;
	struct nameidata nd;
	int error;

	if (seg1 == UIO_SYSSPACE) {
		syspath = path1;
	} else {
		tmppath = uma_zalloc(namei_zone, M_WAITOK);
		if ((error = copyinstr(path1, tmppath, MAXPATHLEN, NULL)) != 0)
			goto out;
		syspath = tmppath;
	}
	AUDIT_ARG_TEXT(syspath);
	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | AUDITVNODE1 | NOCACHE, segflg,
	    path2, fd, &cap_symlinkat_rights);
	if ((error = namei(&nd)) != 0)
		goto out;
	if (nd.ni_vp) {
		NDFREE_PNBUF(&nd);
		if (nd.ni_vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		nd.ni_vp = NULL;
		error = EEXIST;
		goto out;
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			goto out;
		goto restart;
	}
	if ((vn_irflag_read(nd.ni_dvp) & VIRF_NAMEDDIR) != 0) {
		error = EINVAL;
		goto out2;
	}
	VATTR_NULL(&vattr);
	vattr.va_mode = ACCESSPERMS &~ td->td_proc->p_pd->pd_cmask;
#ifdef MAC
	vattr.va_type = VLNK;
	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd,
	    &vattr);
	if (error != 0)
		goto out2;
#endif
	error = VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr, syspath);
out2:
	VOP_VPUT_PAIR(nd.ni_dvp, error == 0 ? &nd.ni_vp : NULL, true);
	vn_finished_write(mp);
	NDFREE_PNBUF(&nd);
	if (error == ERELOOKUP)
		goto restart;
out:
	if (seg1 != UIO_SYSSPACE)
		uma_zfree(namei_zone, tmppath);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SYMLINK; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_symlinkat(struct thread *td, const char *path1, int fd, const char *path2,
    enum uio_seg segflg)
{
	struct dq_intent dqi;
	char *target;
	size_t len;
	int dqerror;

	if (!(segflg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_symlinkat_dqimpl(td, path1, segflg, fd, path2,
		    segflg));
	/*
	 * The target is copied once and posted as path2 (data, no start);
	 * the symlink created on PASS holds exactly the posted bytes.
	 */
	target = uma_zalloc(namei_zone, M_WAITOK);
	dqerror = copyinstr(path1, target, MAXPATHLEN, &len);
	if (dqerror != 0) {
		uma_zfree(namei_zone, target);
		return (dqerror);
	}
	dq_intent_enter_served(td, &dqi, DQ_ROP_SYMLINK, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dqi.di_cmode = ACCESSPERMS & ~td->td_proc->p_pd->pd_cmask;
	dqi.di_text = target;
	dqi.di_textlen = len - 1;
	dq_intent_slot(&dqi, 0, path2, segflg, fd);
	dqerror = kern_symlinkat_dqimpl(td, target, UIO_SYSSPACE, fd, path2,
	    segflg);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	uma_zfree(namei_zone, target);
	return (dqerror);
}

/*
 * Delete a whiteout from the filesystem.
 */
#ifndef _SYS_SYSPROTO_H_
struct undelete_args {
	char *path;
};
#endif
static int
sys_undelete_dqimpl(struct thread *td, struct undelete_args *uap)
{
	struct mount *mp;
	struct nameidata nd;
	int error;

	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT(&nd, DELETE, LOCKPARENT | DOWHITEOUT | AUDITVNODE1,
	    UIO_USERSPACE, uap->path);
	error = namei(&nd);
	if (error != 0)
		return (error);

	if (nd.ni_vp != NULL || !(nd.ni_cnd.cn_flags & ISWHITEOUT)) {
		NDFREE_PNBUF(&nd);
		if (nd.ni_vp == nd.ni_dvp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp)
			vrele(nd.ni_vp);
		return (EEXIST);
	}
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			return (error);
		goto restart;
	}
	error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, DELETE);
	NDFREE_PNBUF(&nd);
	vput(nd.ni_dvp);
	vn_finished_write(mp);
	if (error == ERELOOKUP)
		goto restart;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_INTERNAL; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
sys_undelete(struct thread *td, struct undelete_args *uap)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(true) || !DQRES_ATTACHED_TD(td))
		return (sys_undelete_dqimpl(td, uap));
	dq_intent_enter(td, &dqi, DQ_ROP_INTERNAL, DQI_USER);
	dq_intent_slot(&dqi, 0, uap->path, UIO_USERSPACE, AT_FDCWD);
	dqerror = sys_undelete_dqimpl(td, uap);
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Delete a name from the filesystem.
 */
#ifndef _SYS_SYSPROTO_H_
struct unlink_args {
	char	*path;
};
#endif
int
sys_unlink(struct thread *td, struct unlink_args *uap)
{

	return (kern_funlinkat(td, AT_FDCWD, uap->path, FD_NONE, UIO_USERSPACE,
	    0, 0));
}

static int
kern_funlinkat_ex(struct thread *td, int dfd, const char *path, int fd,
    int flags, enum uio_seg pathseg, ino_t oldinum)
{

	if ((flags & ~(AT_REMOVEDIR | AT_RESOLVE_BENEATH)) != 0)
		return (EINVAL);

	if ((flags & AT_REMOVEDIR) != 0)
		return (kern_frmdirat(td, dfd, path, fd, pathseg,
		    flags & ~AT_REMOVEDIR));

	return (kern_funlinkat(td, dfd, path, fd, pathseg, flags, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct unlinkat_args {
	int	fd;
	char	*path;
	int	flag;
};
#endif
int
sys_unlinkat(struct thread *td, struct unlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->fd, uap->path, FD_NONE, uap->flag,
	    UIO_USERSPACE, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct funlinkat_args {
	int		dfd;
	const char	*path;
	int		fd;
	int		flag;
};
#endif
int
sys_funlinkat(struct thread *td, struct funlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->dfd, uap->path, uap->fd, uap->flag,
	    UIO_USERSPACE, 0));
}

static int
kern_funlinkat_dqimpl(struct thread *td, int dfd, const char *path, int fd,
    enum uio_seg pathseg, int flag, ino_t oldinum)
{
	struct mount *mp;
	struct file *fp;
	struct vnode *vp;
	struct nameidata nd;
	struct stat sb;
	int error;

	fp = NULL;
	if (fd != FD_NONE) {
		/* D170: a served descriptor names the served object. */
		error = dqres_unlink_fd(td, fd, &cap_no_rights, &fp);
		if (error == ENOTTY) {
			error = getvnode_path(td, fd, &cap_no_rights, NULL,
			    &fp);
			if (error == 0)
				dqres_unlink_realfd(td);
		}
		if (error != 0)
			return (error);
	}

	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, DELETE, LOCKPARENT | LOCKLEAF | AUDITVNODE1 |
	    at2cnpflags(flag, AT_RESOLVE_BENEATH),
	    pathseg, path, dfd, &cap_unlinkat_rights);
	if ((error = namei(&nd)) != 0) {
		if (error == EINVAL)
			error = EPERM;
		goto fdout;
	}
	vp = nd.ni_vp;
	if (vp->v_type == VDIR && oldinum == 0) {
		error = EPERM;		/* POSIX */
	} else if (oldinum != 0 &&
	    ((error = VOP_STAT(vp, &sb, td->td_ucred, NOCRED)) == 0) &&
	    sb.st_ino != oldinum) {
		error = EIDRM;	/* Identifier removed */
	} else if (fp != NULL && fp->f_vnode != vp) {
		/*
		 * A served descriptor never names a real vnode (D170); an
		 * unattached process holding one is refused EACCES, as for any
		 * use of a served directory outside its attachment.
		 */
		if (fp->f_vnode != NULL && VN_IS_DOOMED(fp->f_vnode))
			error = EBADF;
		else if (fp->f_vnode == NULL && !DQRES_ATTACHED_TD(td))
			error = EACCES;
		else
			error = EDEADLK;
	} else {
		/*
		 * The root of a mounted filesystem cannot be deleted.
		 *
		 * XXX: can this only be a VDIR case?
		 */
		if (vp->v_vflag & VV_ROOT)
			error = EBUSY;
	}
	if (error == 0) {
		if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
			NDFREE_PNBUF(&nd);
			vput(nd.ni_dvp);
			if (vp == nd.ni_dvp)
				vrele(vp);
			else
				vput(vp);
			if ((error = vn_start_write(NULL, &mp,
			    V_XSLEEP | V_PCATCH)) != 0) {
				goto fdout;
			}
			goto restart;
		}
#ifdef MAC
		error = mac_vnode_check_unlink(td->td_ucred, nd.ni_dvp, vp,
		    &nd.ni_cnd);
		if (error != 0)
			goto out;
#endif
		error = VOP_REMOVE(nd.ni_dvp, vp, &nd.ni_cnd);
#ifdef MAC
		if (error == 0)
			mac_vnode_notify_unlink(td->td_ucred, nd.ni_dvp,
			    vp, &nd.ni_cnd);
out:
#endif
		vn_finished_write(mp);
	}
	NDFREE_PNBUF(&nd);
	vput(nd.ni_dvp);
	if (vp == nd.ni_dvp)
		vrele(vp);
	else
		vput(vp);
	if (error == ERELOOKUP)
		goto restart;
fdout:
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_UNLINK; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_funlinkat(struct thread *td, int dfd, const char *path, int fd,
    enum uio_seg pathseg, int flag, ino_t oldinum)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_funlinkat_dqimpl(td, dfd, path, fd, pathseg, flag, oldinum));
	dq_intent_enter_served(td, &dqi, DQ_ROP_UNLINK, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dq_intent_slot(&dqi, 0, path, pathseg, dfd);
	dqerror = kern_funlinkat_dqimpl(td, dfd, path, fd, pathseg, flag, oldinum);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Reposition read/write file offset.
 */
#ifndef _SYS_SYSPROTO_H_
struct lseek_args {
	int	fd;
	int	pad;
	off_t	offset;
	int	whence;
};
#endif
int
sys_lseek(struct thread *td, struct lseek_args *uap)
{

	return (kern_lseek(td, uap->fd, uap->offset, uap->whence));
}

int
kern_lseek(struct thread *td, int fd, off_t offset, int whence)
{
	struct file *fp;
	int error;

	AUDIT_ARG_FD(fd);
	error = fget(td, fd, &cap_seek_rights, &fp);
	if (error != 0)
		return (error);
	error = (fp->f_ops->fo_flags & DFLAG_SEEKABLE) != 0 ?
	    fo_seek(fp, offset, whence, td) : ESPIPE;
	fdrop(fp, td);
	return (error);
}

#if defined(COMPAT_43)
/*
 * Reposition read/write file offset.
 */
#ifndef _SYS_SYSPROTO_H_
struct olseek_args {
	int	fd;
	long	offset;
	int	whence;
};
#endif
int
olseek(struct thread *td, struct olseek_args *uap)
{

	return (kern_lseek(td, uap->fd, uap->offset, uap->whence));
}
#endif /* COMPAT_43 */


/*
 * Check access permissions using passed credentials.
 */
static int
vn_access(struct vnode *vp, int user_flags, struct ucred *cred,
     struct thread *td)
{
	accmode_t accmode;
	int error;

	/* Flags == 0 means only check for existence. */
	if (user_flags == 0)
		return (0);

	accmode = 0;
	if (user_flags & R_OK)
		accmode |= VREAD;
	if (user_flags & W_OK)
		accmode |= VWRITE;
	if (user_flags & X_OK)
		accmode |= VEXEC;
#ifdef MAC
	error = mac_vnode_check_access(cred, vp, accmode);
	if (error != 0)
		return (error);
#endif
	if ((accmode & VWRITE) == 0 || (error = vn_writechk(vp)) == 0)
		error = VOP_ACCESS(vp, accmode, cred, td);
	return (error);
}

/*
 * Check access permissions using "real" credentials.
 */
#ifndef _SYS_SYSPROTO_H_
struct access_args {
	char	*path;
	int	amode;
};
#endif
int
sys_access(struct thread *td, struct access_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    0, uap->amode));
}

#ifndef _SYS_SYSPROTO_H_
struct faccessat_args {
	int	dirfd;
	char	*path;
	int	amode;
	int	flag;
}
#endif
int
sys_faccessat(struct thread *td, struct faccessat_args *uap)
{

	return (kern_accessat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->amode));
}

/* access(2) answered ATTR: D166 on the presented identity. */
static int
dq_access_ident(struct thread *td, const struct dq_ident_file *id, int flag,
    int amode)
{
	struct ucred *cred, *usecred;
	int accmode, error;

	cred = td->td_ucred;
	if ((flag & AT_EACCESS) == 0 &&
	    ((cred->cr_uid != cred->cr_ruid ||
	    cred->cr_rgid != cred->cr_gid))) {
		usecred = crdup(cred);
		usecred->cr_uid = cred->cr_ruid;
		usecred->cr_gid = cred->cr_rgid;
	} else
		usecred = cred;
	accmode = 0;
	if ((amode & R_OK) != 0)
		accmode |= VREAD;
	if ((amode & W_OK) != 0)
		accmode |= VWRITE;
	if ((amode & X_OK) != 0)
		accmode |= VEXEC;
	error = dqres_ident_access(id, accmode, usecred);
	if (usecred != cred)
		crfree(usecred);
	return (error);
}

/* faccessat(fd, "", AT_EMPTY_PATH) of a served descriptor (D164). */
static int
dq_emptypath_access(struct thread *td, int fd, int flag, int amode,
    struct ucred *cred)
{
	struct dq_ident_file *id;
	struct file *fp;
	struct ucred *save;
	uint64_t qgid;
	bool closed;
	int error;

	/* kern_accessat_dqimpl swapped td_ucred; use the caller's. */
	save = td->td_ucred;
	td->td_ucred = cred;
	error = dqres_emptypath_file(td, fd, &cap_fstat_rights, &fp);
	if (error == 0) {
		id = malloc(sizeof(*id), M_TEMP, M_WAITOK);
		error = dqres_file_ident(fp, id, &qgid, &closed);
		if (error == 0)
			error = dq_access_ident(td, id, flag, amode);
		free(id, M_TEMP);
		fdrop(fp, td);
	}
	td->td_ucred = save;
	return (error);
}

static int
kern_accessat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int flag, int amode)
{
	struct ucred *cred, *usecred;
	struct vnode *vp;
	struct nameidata nd;
	int error;

	if ((flag & ~(AT_EACCESS | AT_RESOLVE_BENEATH | AT_EMPTY_PATH |
	    AT_SYMLINK_NOFOLLOW)) != 0)
		return (EINVAL);
	if (amode != F_OK && (amode & ~(R_OK | W_OK | X_OK)) != 0)
		return (EINVAL);

	/*
	 * Create and modify a temporary credential instead of one that
	 * is potentially shared (if we need one).
	 */
	cred = td->td_ucred;
	if ((flag & AT_EACCESS) == 0 &&
	    ((cred->cr_uid != cred->cr_ruid ||
	    cred->cr_rgid != cred->cr_gid))) {
		usecred = crdup(cred);
		usecred->cr_uid = cred->cr_ruid;
		usecred->cr_gid = cred->cr_rgid;
		td->td_ucred = usecred;
	} else
		usecred = cred;
	AUDIT_ARG_VALUE(amode);
	NDINIT_ATRIGHTS(&nd, LOOKUP, LOCKSHARED | LOCKLEAF |
	    AUDITVNODE1 | at2cnpflags(flag, AT_RESOLVE_BENEATH | AT_SYMLINK_NOFOLLOW |
	    AT_EMPTY_PATH), pathseg, path, fd, &cap_fstat_rights);
	if ((error = namei(&nd)) != 0) {
		/* D164: a served descriptor's own access, no event. */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0)
			error = dq_emptypath_access(td, fd, flag, amode, cred);
		goto out;
	}
	vp = nd.ni_vp;

	error = vn_access(vp, amode, usecred, td);
	NDFREE_PNBUF(&nd);
	vput(vp);
out:
	if (usecred != cred) {
		td->td_ucred = cred;
		crfree(usecred);
	}
	return (error);
}

static int
kern_accessat_dqserved(struct thread *td, struct dq_intent *di, int flag,
    int amode)
{
	const struct dq_ident_file *id;

	id = dqres_ident(di, DQ_RESOLVE_ATTR);
	if (id == NULL)
		return (EIO);
	return (dq_access_ident(td, id, flag, amode));
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_ACCESS; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_accessat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int flag, int amode)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_accessat_dqimpl(td, fd, path, pathseg, flag, amode));
	dq_intent_enter_served(td, &dqi, DQ_ROP_ACCESS, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_ATTR));
	dqi.di_mode = amode;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_accessat_dqimpl(td, fd, path, pathseg, flag, amode);
	DQRES_SERVED(td, &dqi, dqerror, kern_accessat_dqserved(td, &dqi, flag, amode));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Check access permissions using "effective" credentials.
 */
#ifndef _SYS_SYSPROTO_H_
struct eaccess_args {
	char	*path;
	int	amode;
};
#endif
int
sys_eaccess(struct thread *td, struct eaccess_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    AT_EACCESS, uap->amode));
}

#if defined(COMPAT_43)
/*
 * Get file status; this version follows links.
 */
#ifndef _SYS_SYSPROTO_H_
struct ostat_args {
	char	*path;
	struct ostat *ub;
};
#endif
int
ostat(struct thread *td, struct ostat_args *uap)
{
	struct stat sb;
	struct ostat osb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, uap->path, UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	cvtstat(&sb, &osb);
	return (copyout(&osb, uap->ub, sizeof (osb)));
}

/*
 * Get file status; this version does not follow links.
 */
#ifndef _SYS_SYSPROTO_H_
struct olstat_args {
	char	*path;
	struct ostat *ub;
};
#endif
int
olstat(struct thread *td, struct olstat_args *uap)
{
	struct stat sb;
	struct ostat osb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->path,
	    UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	cvtstat(&sb, &osb);
	return (copyout(&osb, uap->ub, sizeof (osb)));
}

/*
 * Convert from an old to a new stat structure.
 * XXX: many values are blindly truncated.
 */
void
cvtstat(struct stat *st, struct ostat *ost)
{

	bzero(ost, sizeof(*ost));
	ost->st_dev = st->st_dev;
	ost->st_ino = st->st_ino;
	ost->st_mode = st->st_mode;
	ost->st_nlink = st->st_nlink;
	ost->st_uid = st->st_uid;
	ost->st_gid = st->st_gid;
	ost->st_rdev = st->st_rdev;
	ost->st_size = MIN(st->st_size, INT32_MAX);
	ost->st_atim = st->st_atim;
	ost->st_mtim = st->st_mtim;
	ost->st_ctim = st->st_ctim;
	ost->st_blksize = st->st_blksize;
	ost->st_blocks = st->st_blocks;
	ost->st_flags = st->st_flags;
	ost->st_gen = st->st_gen;
}
#endif /* COMPAT_43 */

#if defined(COMPAT_43) || defined(COMPAT_FREEBSD11)
int ino64_trunc_error;
SYSCTL_INT(_vfs, OID_AUTO, ino64_trunc_error, CTLFLAG_RW,
    &ino64_trunc_error, 0,
    "Error on truncation of device, file or inode number, or link count");

int
freebsd11_cvtstat(struct stat *st, struct freebsd11_stat *ost)
{

	ost->st_dev = st->st_dev;
	if (ost->st_dev != st->st_dev) {
		switch (ino64_trunc_error) {
		default:
			/*
			 * Since dev_t is almost raw, don't clamp to the
			 * maximum for case 2, but ignore the error.
			 */
			break;
		case 1:
			return (EOVERFLOW);
		}
	}
	ost->st_ino = st->st_ino;
	if (ost->st_ino != st->st_ino) {
		switch (ino64_trunc_error) {
		default:
		case 0:
			break;
		case 1:
			return (EOVERFLOW);
		case 2:
			ost->st_ino = UINT32_MAX;
			break;
		}
	}
	ost->st_mode = st->st_mode;
	ost->st_nlink = st->st_nlink;
	if (ost->st_nlink != st->st_nlink) {
		switch (ino64_trunc_error) {
		default:
		case 0:
			break;
		case 1:
			return (EOVERFLOW);
		case 2:
			ost->st_nlink = UINT16_MAX;
			break;
		}
	}
	ost->st_uid = st->st_uid;
	ost->st_gid = st->st_gid;
	ost->st_rdev = st->st_rdev;
	if (ost->st_rdev != st->st_rdev) {
		switch (ino64_trunc_error) {
		default:
			break;
		case 1:
			return (EOVERFLOW);
		}
	}
	ost->st_atim = st->st_atim;
	ost->st_mtim = st->st_mtim;
	ost->st_ctim = st->st_ctim;
	ost->st_size = st->st_size;
	ost->st_blocks = st->st_blocks;
	ost->st_blksize = st->st_blksize;
	ost->st_flags = st->st_flags;
	ost->st_gen = st->st_gen;
	ost->st_lspare = 0;
	ost->st_birthtim = st->st_birthtim;
	bzero((char *)&ost->st_birthtim + sizeof(ost->st_birthtim),
	    sizeof(*ost) - offsetof(struct freebsd11_stat,
	    st_birthtim) - sizeof(ost->st_birthtim));
	return (0);
}

int
freebsd11_stat(struct thread *td, struct freebsd11_stat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat osb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, uap->path, UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, uap->ub, sizeof(osb));
	return (error);
}

int
freebsd11_lstat(struct thread *td, struct freebsd11_lstat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat osb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->path,
	    UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, uap->ub, sizeof(osb));
	return (error);
}

int
freebsd11_fhstat(struct thread *td, struct freebsd11_fhstat_args* uap)
{
	struct fhandle fh;
	struct stat sb;
	struct freebsd11_stat osb;
	int error;

	error = copyin(uap->u_fhp, &fh, sizeof(fhandle_t));
	if (error != 0)
		return (error);
	error = kern_fhstat(td, fh, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, uap->sb, sizeof(osb));
	return (error);
}

int
freebsd11_fstatat(struct thread *td, struct freebsd11_fstatat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat osb;
	int error;

	error = kern_statat(td, uap->flag, uap->fd, uap->path,
	    UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, uap->buf, sizeof(osb));
	return (error);
}
#endif	/* COMPAT_FREEBSD11 */

/*
 * Get file status
 */
#ifndef _SYS_SYSPROTO_H_
struct fstatat_args {
	int	fd;
	char	*path;
	struct stat	*buf;
	int	flag;
}
#endif
int
sys_fstatat(struct thread *td, struct fstatat_args *uap)
{
	struct stat sb;
	int error;

	error = kern_statat(td, uap->flag, uap->fd, uap->path,
	    UIO_USERSPACE, &sb);
	if (error == 0)
		error = copyout(&sb, uap->buf, sizeof (sb));
	return (error);
}

static int
kern_statat_dqimpl(struct thread *td, int flag, int fd, const char *path,
    enum uio_seg pathseg, struct stat *sbp)
{
	struct nameidata nd;
	int error;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	NDINIT_ATRIGHTS(&nd, LOOKUP, at2cnpflags(flag, AT_RESOLVE_BENEATH |
	    AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) | LOCKSHARED | LOCKLEAF |
	    AUDITVNODE1, pathseg, path, fd, &cap_fstat_rights);

	if ((error = namei(&nd)) != 0) {
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0)
			error = kern_fstat(td, fd, sbp);
		return (error);
	}
	error = VOP_STAT(nd.ni_vp, sbp, td->td_ucred, NOCRED);
	NDFREE_PNBUF(&nd);
	if (error == 0 && (nd.ni_vp->v_vflag & VV_ROOT) != 0)
		sbp->st_bsdflags |= SFBSD_MNTPOINT;
	vput(nd.ni_vp);
#ifdef __STAT_TIME_T_EXT
	sbp->st_atim_ext = 0;
	sbp->st_mtim_ext = 0;
	sbp->st_ctim_ext = 0;
	sbp->st_btim_ext = 0;
#endif
#ifdef KTRACE
	if (KTRPOINT(td, KTR_STRUCT))
		ktrstat_error(sbp, error);
#endif
	return (error);
}

static int
kern_statat_dqserved(struct thread *td, struct dq_intent *di,
    struct stat *sbp)
{
	const struct dq_ident_file *id;

	id = dqres_ident(di, DQ_RESOLVE_ATTR);
	if (id == NULL)
		return (EIO);
	dqres_ident_to_stat(id, td->td_ucred, sbp);
#ifdef KTRACE
	if (KTRPOINT(td, KTR_STRUCT))
		ktrstat_error(sbp, 0);
#endif
	return (0);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_STAT; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_statat(struct thread *td, int flag, int fd, const char *path,
    enum uio_seg pathseg, struct stat *sbp)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_statat_dqimpl(td, flag, fd, path, pathseg, sbp));
	dq_intent_enter_served(td, &dqi, DQ_ROP_STAT, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_ATTR));
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_statat_dqimpl(td, flag, fd, path, pathseg, sbp);
	DQRES_SERVED(td, &dqi, dqerror, kern_statat_dqserved(td, &dqi, sbp));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

#if defined(COMPAT_FREEBSD11)
/*
 * Implementation of the NetBSD [l]stat() functions.
 */
int
freebsd11_cvtnstat(struct stat *sb, struct nstat *nsb)
{
	struct freebsd11_stat sb11;
	int error;

	error = freebsd11_cvtstat(sb, &sb11);
	if (error != 0)
		return (error);

	bzero(nsb, sizeof(*nsb));
	CP(sb11, *nsb, st_dev);
	CP(sb11, *nsb, st_ino);
	CP(sb11, *nsb, st_mode);
	CP(sb11, *nsb, st_nlink);
	CP(sb11, *nsb, st_uid);
	CP(sb11, *nsb, st_gid);
	CP(sb11, *nsb, st_rdev);
	CP(sb11, *nsb, st_atim);
	CP(sb11, *nsb, st_mtim);
	CP(sb11, *nsb, st_ctim);
	CP(sb11, *nsb, st_size);
	CP(sb11, *nsb, st_blocks);
	CP(sb11, *nsb, st_blksize);
	CP(sb11, *nsb, st_flags);
	CP(sb11, *nsb, st_gen);
	CP(sb11, *nsb, st_birthtim);
	return (0);
}

#ifndef _SYS_SYSPROTO_H_
struct freebsd11_nstat_args {
	char	*path;
	struct nstat *ub;
};
#endif
int
freebsd11_nstat(struct thread *td, struct freebsd11_nstat_args *uap)
{
	struct stat sb;
	struct nstat nsb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, uap->path, UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtnstat(&sb, &nsb);
	if (error == 0)
		error = copyout(&nsb, uap->ub, sizeof (nsb));
	return (error);
}

/*
 * NetBSD lstat.  Get file status; this version does not follow links.
 */
#ifndef _SYS_SYSPROTO_H_
struct freebsd11_nlstat_args {
	char	*path;
	struct nstat *ub;
};
#endif
int
freebsd11_nlstat(struct thread *td, struct freebsd11_nlstat_args *uap)
{
	struct stat sb;
	struct nstat nsb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->path,
	    UIO_USERSPACE, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_cvtnstat(&sb, &nsb);
	if (error == 0)
		error = copyout(&nsb, uap->ub, sizeof (nsb));
	return (error);
}
#endif /* COMPAT_FREEBSD11 */

/*
 * Get configurable pathname variables.
 */
#ifndef _SYS_SYSPROTO_H_
struct pathconf_args {
	char	*path;
	int	name;
};
#endif
int
sys_pathconf(struct thread *td, struct pathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name, FOLLOW,
	    &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct lpathconf_args {
	char	*path;
	int	name;
};
#endif
int
sys_lpathconf(struct thread *td, struct lpathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name,
	    NOFOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

static int
kern_pathconf_dqimpl(struct thread *td, const char *path, enum uio_seg pathseg,
    int name, u_long flags, long *valuep)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, LOCKSHARED | LOCKLEAF | AUDITVNODE1 | flags,
	       pathseg, path);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE_PNBUF(&nd);

	error = VOP_PATHCONF(nd.ni_vp, name, valuep);
	vput(nd.ni_vp);
	return (error);
}

static int
kern_pathconf_dqserved(struct dq_intent *di, int name, long *valuep)
{
	const struct dq_ident_file *id;

	id = dqres_ident(di, DQ_RESOLVE_ATTR);
	if (id == NULL)
		return (EIO);
	return (dqres_ident_pathconf(id, name, valuep));
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_STAT; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_pathconf(struct thread *td, const char *path, enum uio_seg pathseg,
    int name, u_long flags, long *valuep)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_pathconf_dqimpl(td, path, pathseg, name, flags, valuep));
	dq_intent_enter_served(td, &dqi, DQ_ROP_STAT, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_ATTR));
	dq_intent_slot(&dqi, 0, path, pathseg, AT_FDCWD);
	dqerror = kern_pathconf_dqimpl(td, path, pathseg, name, flags, valuep);
	DQRES_SERVED(td, &dqi, dqerror, kern_pathconf_dqserved(&dqi, name, valuep));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Return target name of a symbolic link.
 */
#ifndef _SYS_SYSPROTO_H_
struct readlink_args {
	char	*path;
	char	*buf;
	size_t	count;
};
#endif
int
sys_readlink(struct thread *td, struct readlink_args *uap)
{

	return (kern_readlinkat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->count));
}
#ifndef _SYS_SYSPROTO_H_
struct readlinkat_args {
	int	fd;
	char	*path;
	char	*buf;
	size_t	bufsize;
};
#endif
int
sys_readlinkat(struct thread *td, struct readlinkat_args *uap)
{

	return (kern_readlinkat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->bufsize));
}

static int
kern_readlinkat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, char *buf, enum uio_seg bufseg, size_t count)
{
	struct file *fp;
	struct vnode *vp;
	struct nameidata nd;
	int error;

	if (count > IOSIZE_MAX)
		return (EINVAL);

	NDINIT_AT(&nd, LOOKUP, NOFOLLOW | LOCKSHARED | LOCKLEAF | AUDITVNODE1 |
	    EMPTYPATH, pathseg, path, fd);

	if ((error = namei(&nd)) != 0) {
		/*
		 * D164: a served symlink's own target, no event; any other
		 * served descriptor is not a symlink (EINVAL).
		 */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
		    dqres_emptypath_file(td, fd, &cap_no_rights, &fp) == 0) {
			char *target;
			size_t tlen;

			error = dqres_file_target(fp, &target, &tlen);
			fdrop(fp, td);
			if (error == 0) {
				tlen = MIN(tlen, count);
				if (bufseg == UIO_SYSSPACE)
					bcopy(target, buf, tlen);
				else
					error = copyout(target, buf, tlen);
				free(target, M_TEMP);
				if (error == 0)
					td->td_retval[0] = tlen;
			}
		}
		return (error);
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;

	error = kern_readlink_vp(vp, buf, bufseg, count, td);
	vput(vp);

	return (error);
}

/* readlink(2) answered LINK: the target, as kern_readlink_vp copies it. */
static int
kern_readlinkat_dqserved(struct thread *td, struct dq_intent *di, char *buf,
    enum uio_seg bufseg, size_t count)
{
	size_t len;
	int error;

	if (di->di_res.da_kind != DQ_RESOLVE_LINK)
		return (EIO);
	len = MIN(count, di->di_res.da_targetlen);
	error = 0;
	if (bufseg == UIO_SYSSPACE)
		bcopy(di->di_res.da_target, buf, len);
	else
		error = copyout(di->di_res.da_target, buf, len);
	if (error == 0)
		td->td_retval[0] = len;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_READLINK; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_readlinkat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, char *buf, enum uio_seg bufseg, size_t count)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_readlinkat_dqimpl(td, fd, path, pathseg, buf, bufseg, count));
	dq_intent_enter_served(td, &dqi, DQ_ROP_READLINK, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_LINK));
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_readlinkat_dqimpl(td, fd, path, pathseg, buf, bufseg, count);
	DQRES_SERVED(td, &dqi, dqerror, kern_readlinkat_dqserved(td, &dqi, buf, bufseg, count));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Helper function to readlink from a vnode
 */
static int
kern_readlink_vp(struct vnode *vp, char *buf, enum uio_seg bufseg, size_t count,
    struct thread *td)
{
	struct iovec aiov;
	struct uio auio;
	int error;

	ASSERT_VOP_LOCKED(vp, "kern_readlink_vp(): vp not locked");
#ifdef MAC
	error = mac_vnode_check_readlink(td->td_ucred, vp);
	if (error != 0)
		return (error);
#endif
	if (vp->v_type != VLNK && (vp->v_vflag & VV_READLINK) == 0)
		return (EINVAL);

	aiov.iov_base = buf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = 0;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = bufseg;
	auio.uio_td = td;
	auio.uio_resid = count;
	error = VOP_READLINK(vp, &auio, td->td_ucred);
	td->td_retval[0] = count - auio.uio_resid;
	return (error);
}

/*
 * Common implementation code for chflags() and fchflags().
 */
int
setfflags(struct thread *td, struct vnode *vp, u_long flags)
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	/* We can't support the value matching VNOVAL. */
	if (flags == VNOVAL)
		return (EOPNOTSUPP);

	if ((error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH)) != 0)
		return (error);
	VATTR_NULL(&vattr);
	vattr.va_flags = flags;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_SETATTR(vp, &vattr, td->td_ucred);
#ifdef MAC
	if (error == 0)
		mac_vnode_notify_setflags(td->td_ucred, vp, vattr.va_flags);
#endif
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
	SDT_PROBE3(vfs, , , chflags, flags, td->td_ucred, error);
	return (error);
}

/*
 * Change flags of a file given a path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chflags_args {
	const char *path;
	u_long	flags;
};
#endif
int
sys_chflags(struct thread *td, struct chflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct chflagsat_args {
	int	fd;
	const char *path;
	u_long	flags;
	int	atflag;
}
#endif
int
sys_chflagsat(struct thread *td, struct chflagsat_args *uap)
{

	return (kern_chflagsat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->flags, uap->atflag));
}

/*
 * Same as chflags() but doesn't follow symlinks.
 */
#ifndef _SYS_SYSPROTO_H_
struct lchflags_args {
	const char *path;
	u_long flags;
};
#endif
int
sys_lchflags(struct thread *td, struct lchflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, AT_SYMLINK_NOFOLLOW));
}

static int
kern_chflagsat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, u_long flags, int atflag)
{
	struct file *fp;
	struct vattr va;
	struct nameidata nd;
	struct vnode *vp;
	int error;

	if ((atflag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	AUDIT_ARG_FFLAGS(flags);
	NDINIT_ATRIGHTS(&nd, LOOKUP, at2cnpflags(atflag, AT_SYMLINK_NOFOLLOW |
	    AT_RESOLVE_BENEATH | AT_EMPTY_PATH) | AUDITVNODE1, pathseg, path,
	    fd, &cap_fchflags_rights);
	if ((error = namei(&nd)) != 0) {
		/* D164: the served descriptor's own fchflags, no event. */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
		    dqres_emptypath_file(td, fd, &cap_fchflags_rights,
		    &fp) == 0) {
			VATTR_NULL(&va);
			va.va_flags = flags;
			error = fo_setattr(fp, &va, td->td_ucred, td);
			fdrop(fp, td);
		}
		return (error);
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;

	/*
	 * Prevent non-root users from setting flags on devices.  When
	 * a device is reused, users can retain ownership of the device
	 * if they are allowed to set flags and programs assume that
	 * chown can't fail when done as root.
	 */
	if (VN_ISDEV(vp)) {
		error = priv_check(td, PRIV_VFS_CHFLAGS_DEV);
		if (error != 0)
			goto out;
	}
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setflags(td->td_ucred, vp, flags);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setfflags(td, vp, flags);
out:
	vrele(vp);
	return (error);
}

/* chflags(2) answered OK or FD: the full flags word through fo_setattr. */
static int
kern_chflagsat_dqserved(struct thread *td, struct dq_intent *di,
    u_long flags)
{
	struct file *fp;
	struct vattr va;
	int error;

	if (di->di_res.da_kind == DQ_RESOLVE_OK)
		return (0);
	if (di->di_res.da_kind != DQ_RESOLVE_FD)
		return (EIO);
	error = dqres_take_file_raw(td, di, FREAD, &fp);
	if (error != 0)
		return (error);
	VATTR_NULL(&va);
	va.va_flags = flags;
	error = fo_setattr(fp, &va, td->td_ucred, td);
	fdrop(fp, td);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
static int
kern_chflagsat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, u_long flags, int atflag)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_chflagsat_dqimpl(td, fd, path, pathseg, flags, atflag));
	/*
	 * A flags word wider than st_flags (VNOVAL included) has no 32-bit
	 * body: OK is withheld and nothing is posted in the mask; the FD path
	 * hands the full word to fo_setattr, so the answer is a real file's
	 * (EOPNOTSUPP, or no change for VNOVAL).
	 */
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    dq_setattr_accept(flags > UINT32_MAX));
	bzero(&sb, sizeof(sb));
	if (flags <= UINT32_MAX) {
		sb.dsa_mask = DQ_SETATTR_FLAGS;
		sb.dsa_flags = (uint32_t)flags;
	}
	/* Privilege only matters for system flags; VADMIN always may. */
	dqres_setattr_priv(td, &sb, DQ_SAPRIV_ADMIN |
	    ((flags & SF_SETTABLE) != 0 ? DQ_SAPRIV_SYSFLAGS |
	    DQ_SAPRIV_SECURELEVEL : 0));
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_chflagsat_dqimpl(td, fd, path, pathseg, flags, atflag);
	DQRES_SERVED(td, &dqi, dqerror, kern_chflagsat_dqserved(td, &dqi,
	    flags));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Change flags of a file given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchflags_args {
	int	fd;
	u_long	flags;
};
#endif
int
sys_fchflags(struct thread *td, struct fchflags_args *uap)
{
	struct vattr vattr;
	struct file *fp;
	struct vnode *vp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_FFLAGS(uap->flags);
	error = fget(td, uap->fd, &cap_fchflags_rights, &fp);
	if (error != 0)
		return (error);
	error = getvnode_fp(fp, false);
	if (error != 0) {
		SDT_PROBE4(fd, , , refused, "fchflags", fp, 0, error);
		goto out;
	}
	if (fp->f_type == DTYPE_DQ) {
		/* A served file answers through its table. */
		if (uap->flags == VNOVAL) {
			error = EOPNOTSUPP;
			goto out;
		}
		VATTR_NULL(&vattr);
		vattr.va_flags = uap->flags;
#ifdef MAC
		error = mac_file_check_setattr(td->td_ucred, fp, uap->fd,
		    &vattr);
		if (error != 0)
			goto out;
#endif
		error = fo_setattr(fp, &vattr, td->td_ucred, td);
		goto out;
	}
	vp = fp->f_vnode;
#ifdef AUDIT
	if (AUDITING_TD(td)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		AUDIT_ARG_VNODE1(vp);
		VOP_UNLOCK(vp);
	}
#endif
	/*
	 * Prevent non-root users from setting flags on devices.  When
	 * a device is reused, users can retain ownership of the device
	 * if they are allowed to set flags and programs assume that
	 * chown can't fail when done as root.
	 */
	if (VN_ISDEV(vp)) {
		error = priv_check(td, PRIV_VFS_CHFLAGS_DEV);
		if (error != 0)
			goto out;
	}
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setflags(td->td_ucred, vp, uap->flags);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setfflags(td, vp, uap->flags);
out:
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation code for chmod(), lchmod() and fchmod().
 */
int
setfmode(struct thread *td, struct ucred *cred, struct vnode *vp, int mode)
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	if ((error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH)) != 0)
		return (error);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VATTR_NULL(&vattr);
	vattr.va_mode = mode & ALLPERMS;
	error = VOP_SETATTR(vp, &vattr, cred);
#ifdef MAC
	if (error == 0)
		mac_vnode_notify_setmode(cred, vp, vattr.va_mode);
#endif
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Change mode of a file given path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chmod_args {
	char	*path;
	int	mode;
};
#endif
int
sys_chmod(struct thread *td, struct chmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct fchmodat_args {
	int	dirfd;
	char	*path;
	mode_t	mode;
	int	flag;
}
#endif
int
sys_fchmodat(struct thread *td, struct fchmodat_args *uap)
{

	return (kern_fchmodat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->mode, uap->flag));
}

/*
 * Change mode of a file given path name (don't follow links.)
 */
#ifndef _SYS_SYSPROTO_H_
struct lchmod_args {
	char	*path;
	int	mode;
};
#endif
int
sys_lchmod(struct thread *td, struct lchmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, AT_SYMLINK_NOFOLLOW));
}

static int
kern_fchmodat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, mode_t mode, int flag)
{
	struct file *fp;
	struct nameidata nd;
	struct vnode *vp;
	int error;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	AUDIT_ARG_MODE(mode);
	NDINIT_ATRIGHTS(&nd, LOOKUP, at2cnpflags(flag, AT_SYMLINK_NOFOLLOW |
	    AT_RESOLVE_BENEATH | AT_EMPTY_PATH) | AUDITVNODE1, pathseg, path,
	    fd, &cap_fchmod_rights);
	if ((error = namei(&nd)) != 0) {
		/*
		 * D164: the served descriptor's own chmod, no event, through
		 * the object-level setattr, so an O_PATH descriptor works as
		 * a vnode's O_PATH descriptor does here (1c-iii-b).
		 */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
		    dqres_emptypath_file(td, fd, &cap_fchmod_rights,
		    &fp) == 0) {
			struct dq_setattr_body sb;

			bzero(&sb, sizeof(sb));
			sb.dsa_mask = DQ_SETATTR_MODE;
			sb.dsa_mode = mode & ALLPERMS;
			error = dqres_file_setattr(td, fp, &sb);
			fdrop(fp, td);
		}
		return (error);
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setmode(td->td_ucred, vp, mode & ALLPERMS);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setfmode(td, td->td_ucred, vp, mode);
#ifdef MAC
out:
#endif
	vrele(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_fchmodat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, mode_t mode, int flag)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_fchmodat_dqimpl(td, fd, path, pathseg, mode, flag));
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    dq_setattr_accept((mode & (S_ISUID | S_ISGID)) != 0));
	/*
	 * D161: set-id bits never reach a served identity (I3).  OK is
	 * withheld so a PASS keeps the real chmod and an FD answer gets
	 * D96's EPERM; the controller cannot report success.
	 */
	bzero(&sb, sizeof(sb));
	sb.dsa_mask = DQ_SETATTR_MODE;
	sb.dsa_mode = mode & ALLPERMS;
	/*
	 * The owner is not known before the answer, so VADMIN's privilege
	 * is evaluated; SETGID only when the mode sets it.
	 */
	dqres_setattr_priv(td, &sb, DQ_SAPRIV_ADMIN |
	    ((mode & S_ISGID) != 0 ? DQ_SAPRIV_SETGID : 0));
	dqi.di_setattr = &sb;
	dqi.di_mode = mode;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_fchmodat_dqimpl(td, fd, path, pathseg, mode, flag);
	DQRES_SERVED(td, &dqi, dqerror, dq_setattr_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Change mode of a file given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchmod_args {
	int	fd;
	int	mode;
};
#endif
int
sys_fchmod(struct thread *td, struct fchmod_args *uap)
{
	struct file *fp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_MODE(uap->mode);

	error = fget(td, uap->fd, &cap_fchmod_rights, &fp);
	if (error != 0)
		return (error);
#ifdef MAC
	/*
	 * The vnode's policy check comes before the table answers, so a
	 * descriptor whose table refuses (O_PATH, a /dev/ptmx master) gets
	 * the policy's errno first.  A served file has no vnode; its check
	 * is the file-level one.
	 */
	if (fp->f_type == DTYPE_DQ) {
		struct vattr va;

		VATTR_NULL(&va);
		va.va_mode = uap->mode;
		error = mac_file_check_setattr(td->td_ucred, fp, uap->fd, &va);
		if (error != 0)
			goto out;
	} else {
		struct vnode *vp = fp->f_vnode;

		if (vp != NULL) {
			vn_lock(vp, LK_SHARED | LK_RETRY);
			error = mac_vnode_check_setmode(td->td_ucred, vp,
			    uap->mode & ALLPERMS);
			VOP_UNLOCK(vp);
			if (error != 0)
				goto out;
		}
	}
#endif
	error = fo_chmod(fp, uap->mode, td->td_ucred, td);
#ifdef MAC
out:
#endif
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation for chown(), lchown(), and fchown()
 */
int
setfown(struct thread *td, struct ucred *cred, struct vnode *vp, uid_t uid,
    gid_t gid)
{
	struct mount *mp;
	struct vattr vattr;
	int error;

	if ((error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH)) != 0)
		return (error);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VATTR_NULL(&vattr);
	vattr.va_uid = uid;
	vattr.va_gid = gid;
	error = VOP_SETATTR(vp, &vattr, cred);
#ifdef MAC
	if (error == 0)
		mac_vnode_notify_setowner(cred, vp, vattr.va_uid,
		    vattr.va_gid);
#endif
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Set ownership given a path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct chown_args {
	char	*path;
	int	uid;
	int	gid;
};
#endif
int
sys_chown(struct thread *td, struct chown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE, uap->uid,
	    uap->gid, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct fchownat_args {
	int fd;
	const char * path;
	uid_t uid;
	gid_t gid;
	int flag;
};
#endif
int
sys_fchownat(struct thread *td, struct fchownat_args *uap)
{

	return (kern_fchownat(td, uap->fd, uap->path, UIO_USERSPACE, uap->uid,
	    uap->gid, uap->flag));
}

static int
kern_fchownat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int uid, int gid, int flag)
{
	struct file *fp;
	struct nameidata nd;
	struct vnode *vp;
	int error;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	AUDIT_ARG_OWNER(uid, gid);
	NDINIT_ATRIGHTS(&nd, LOOKUP, at2cnpflags(flag, AT_SYMLINK_NOFOLLOW |
	    AT_RESOLVE_BENEATH | AT_EMPTY_PATH) | AUDITVNODE1, pathseg, path,
	    fd, &cap_fchown_rights);

	if ((error = namei(&nd)) != 0) {
		/*
		 * D164: the served descriptor's own chown, no event, through
		 * the object-level setattr (O_PATH as for a vnode, 1c-iii-b).
		 */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
		    dqres_emptypath_file(td, fd, &cap_fchown_rights,
		    &fp) == 0) {
			struct dq_setattr_body sb;

			bzero(&sb, sizeof(sb));
			if (uid != (uid_t)-1) {
				sb.dsa_mask |= DQ_SETATTR_UID;
				sb.dsa_uid = uid;
			}
			if (gid != (gid_t)-1) {
				sb.dsa_mask |= DQ_SETATTR_GID;
				sb.dsa_gid = gid;
			}
			error = dqres_file_setattr(td, fp, &sb);
			fdrop(fp, td);
		}
		return (error);
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setowner(td->td_ucred, vp, uid, gid);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setfown(td, td->td_ucred, vp, uid, gid);
#ifdef MAC
out:
#endif
	vrele(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_fchownat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, int uid, int gid, int flag)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_fchownat_dqimpl(td, fd, path, pathseg, uid, gid, flag));
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    dq_setattr_accept(false));
	bzero(&sb, sizeof(sb));
	if (uid != -1) {
		sb.dsa_mask |= DQ_SETATTR_UID;
		sb.dsa_uid = uid;
	}
	if (gid != -1) {
		sb.dsa_mask |= DQ_SETATTR_GID;
		sb.dsa_gid = gid;
	}
	/*
	 * Privilege can matter only for a change to another uid or to a
	 * group the caller is not in (the owner is not known yet).
	 */
	if ((uid != -1 && (uid_t)uid != td->td_ucred->cr_uid) ||
	    (gid != -1 && !groupmember((gid_t)gid, td->td_ucred)))
		dqres_setattr_priv(td, &sb, DQ_SAPRIV_CHOWN | DQ_SAPRIV_ADMIN);
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_fchownat_dqimpl(td, fd, path, pathseg, uid, gid, flag);
	DQRES_SERVED(td, &dqi, dqerror, dq_setattr_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Set ownership given a path name, do not cross symlinks.
 */
#ifndef _SYS_SYSPROTO_H_
struct lchown_args {
	char	*path;
	int	uid;
	int	gid;
};
#endif
int
sys_lchown(struct thread *td, struct lchown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->uid, uap->gid, AT_SYMLINK_NOFOLLOW));
}

/*
 * Set ownership given a file descriptor.
 */
#ifndef _SYS_SYSPROTO_H_
struct fchown_args {
	int	fd;
	int	uid;
	int	gid;
};
#endif
int
sys_fchown(struct thread *td, struct fchown_args *uap)
{
	struct file *fp;
	int error;

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_OWNER(uap->uid, uap->gid);
	error = fget(td, uap->fd, &cap_fchown_rights, &fp);
	if (error != 0)
		return (error);
#ifdef MAC
	/* As fchmod(2): the vnode's check first; the file's when served. */
	if (fp->f_type == DTYPE_DQ) {
		struct vattr va;

		VATTR_NULL(&va);
		va.va_uid = uap->uid;
		va.va_gid = uap->gid;
		error = mac_file_check_setattr(td->td_ucred, fp, uap->fd, &va);
		if (error != 0)
			goto out;
	} else {
		struct vnode *vp = fp->f_vnode;

		if (vp != NULL) {
			vn_lock(vp, LK_SHARED | LK_RETRY);
			error = mac_vnode_check_setowner(td->td_ucred, vp,
			    uap->uid, uap->gid);
			VOP_UNLOCK(vp);
			if (error != 0)
				goto out;
		}
	}
#endif
	error = fo_chown(fp, uap->uid, uap->gid, td->td_ucred, td);
#ifdef MAC
out:
#endif
	fdrop(fp, td);
	return (error);
}

/*
 * Common implementation code for utimes(), lutimes(), and futimes().
 */
int
getutimes(const struct timeval *usrtvp, enum uio_seg tvpseg,
    struct timespec *tsp)
{
	struct timeval tv[2];
	const struct timeval *tvp;
	int error;

	if (usrtvp == NULL) {
		vfs_timestamp(&tsp[0]);
		tsp[1] = tsp[0];
	} else {
		if (tvpseg == UIO_SYSSPACE) {
			tvp = usrtvp;
		} else {
			if ((error = copyin(usrtvp, tv, sizeof(tv))) != 0)
				return (error);
			tvp = tv;
		}

		if (tvp[0].tv_usec < 0 || tvp[0].tv_usec >= 1000000 ||
		    tvp[1].tv_usec < 0 || tvp[1].tv_usec >= 1000000)
			return (EINVAL);
		TIMEVAL_TO_TIMESPEC(&tvp[0], &tsp[0]);
		TIMEVAL_TO_TIMESPEC(&tvp[1], &tsp[1]);
	}
	return (0);
}

/*
 * Common implementation code for futimens(), utimensat().
 */
#define	UTIMENS_NULL	0x1
#define	UTIMENS_EXIT	0x2
static int
getutimens(const struct timespec *usrtsp, enum uio_seg tspseg,
    struct timespec *tsp, int *retflags)
{
	struct timespec tsnow;
	int error;

	vfs_timestamp(&tsnow);
	*retflags = 0;
	if (usrtsp == NULL) {
		tsp[0] = tsnow;
		tsp[1] = tsnow;
		*retflags |= UTIMENS_NULL;
		return (0);
	}
	if (tspseg == UIO_SYSSPACE) {
		tsp[0] = usrtsp[0];
		tsp[1] = usrtsp[1];
	} else if ((error = copyin(usrtsp, tsp, sizeof(*tsp) * 2)) != 0)
		return (error);
	if (tsp[0].tv_nsec == UTIME_OMIT && tsp[1].tv_nsec == UTIME_OMIT)
		*retflags |= UTIMENS_EXIT;
	if (tsp[0].tv_nsec == UTIME_NOW && tsp[1].tv_nsec == UTIME_NOW)
		*retflags |= UTIMENS_NULL;
	if (tsp[0].tv_nsec == UTIME_OMIT)
		tsp[0].tv_sec = VNOVAL;
	else if (tsp[0].tv_nsec == UTIME_NOW)
		tsp[0] = tsnow;
	else if (tsp[0].tv_nsec < 0 || tsp[0].tv_nsec >= 1000000000L)
		return (EINVAL);
	if (tsp[1].tv_nsec == UTIME_OMIT)
		tsp[1].tv_sec = VNOVAL;
	else if (tsp[1].tv_nsec == UTIME_NOW)
		tsp[1] = tsnow;
	else if (tsp[1].tv_nsec < 0 || tsp[1].tv_nsec >= 1000000000L)
		return (EINVAL);

	return (0);
}

/*
 * Common implementation code for utimes(), lutimes(), futimes(), futimens(),
 * and utimensat().
 */
int
setutimes(struct thread *td, struct vnode *vp, const struct timespec *ts,
    int numtimes, int nullflag)
{
	struct mount *mp;
	struct vattr vattr;
	int error;
	bool setbirthtime;

	setbirthtime = false;
	vattr.va_birthtime.tv_sec = VNOVAL;
	vattr.va_birthtime.tv_nsec = 0;

	if ((error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH)) != 0)
		return (error);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	if (numtimes < 3 && VOP_GETATTR(vp, &vattr, td->td_ucred) == 0 &&
	    timespeccmp(&ts[1], &vattr.va_birthtime, < ))
		setbirthtime = true;
	VATTR_NULL(&vattr);
	vattr.va_atime = ts[0];
	vattr.va_mtime = ts[1];
	if (setbirthtime)
		vattr.va_birthtime = ts[1];
	if (numtimes > 2)
		vattr.va_birthtime = ts[2];
	if (nullflag)
		vattr.va_vaflags |= VA_UTIMES_NULL;
	error = VOP_SETATTR(vp, &vattr, td->td_ucred);
#ifdef MAC
	if (error == 0)
		mac_vnode_notify_setutimes(td->td_ucred, vp);
#endif
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct utimes_args {
	char	*path;
	struct	timeval *tptr;
};
#endif
int
sys_utimes(struct thread *td, struct utimes_args *uap)
{

	return (kern_utimesat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->tptr, UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct futimesat_args {
	int fd;
	const char * path;
	const struct timeval * times;
};
#endif
int
sys_futimesat(struct thread *td, struct futimesat_args *uap)
{

	return (kern_utimesat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE));
}

static int
kern_utimesat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, const struct timeval *tptr, enum uio_seg tptrseg)
{
	struct nameidata nd;
	struct vnode *vp;
	struct timespec ts[2];
	int error;

	if ((error = getutimes(tptr, tptrseg, ts)) != 0)
		return (error);
	NDINIT_ATRIGHTS(&nd, LOOKUP, FOLLOW | AUDITVNODE1, pathseg, path, fd,
	    &cap_futimes_rights);

	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setutimes(td->td_ucred, vp, ts[0], ts[1]);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setutimes(td, vp, ts, 2, tptr == NULL);
#ifdef MAC
out:
#endif
	vrele(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_utimesat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, const struct timeval *tptr, enum uio_seg tptrseg)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	struct timeval ktv[2];
	struct timespec ts[2];
	const struct timeval *ktp;
	enum uio_seg tseg;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_utimesat_dqimpl(td, fd, path, pathseg, tptr, tptrseg));
	/*
	 * D161: the times are copied in once (only from user space) and the
	 * impl applies exactly what was posted.
	 */
	ktp = tptr;
	tseg = tptrseg;
	if (tptr != NULL && tptrseg == UIO_USERSPACE) {
		dqerror = copyin(tptr, ktv, sizeof(ktv));
		if (dqerror != 0)
			return (dqerror);
		ktp = ktv;
		tseg = UIO_SYSSPACE;
	}
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK) | DQ_RACCEPT(DQ_RESOLVE_FD));
	bzero(&sb, sizeof(sb));
	if (ktp == NULL)
		dq_setattr_times(&sb, NULL);	/* the _NOW flags, UTIMES_NULL */
	else {
		TIMEVAL_TO_TIMESPEC(&ktp[0], &ts[0]);
		TIMEVAL_TO_TIMESPEC(&ktp[1], &ts[1]);
		dq_setattr_times(&sb, ts);
		/* Explicit times need ownership or PRIV_VFS_ADMIN. */
		dqres_setattr_priv(td, &sb, DQ_SAPRIV_ADMIN);
	}
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_utimesat_dqimpl(td, fd, path, pathseg, ktp, tseg);
	DQRES_SERVED(td, &dqi, dqerror, dq_setattr_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct lutimes_args {
	char	*path;
	struct	timeval *tptr;
};
#endif
int
sys_lutimes(struct thread *td, struct lutimes_args *uap)
{

	return (kern_lutimes(td, uap->path, UIO_USERSPACE, uap->tptr,
	    UIO_USERSPACE));
}

static int
kern_lutimes_dqimpl(struct thread *td, const char *path, enum uio_seg pathseg,
    const struct timeval *tptr, enum uio_seg tptrseg)
{
	struct timespec ts[2];
	struct nameidata nd;
	struct vnode *vp;
	int error;

	if ((error = getutimes(tptr, tptrseg, ts)) != 0)
		return (error);
	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNODE1, pathseg, path);
	if ((error = namei(&nd)) != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
#ifdef MAC
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = mac_vnode_check_setutimes(td->td_ucred, vp, ts[0], ts[1]);
	VOP_UNLOCK(vp);
	if (error != 0)
		goto out;
#endif
	error = setutimes(td, vp, ts, 2, tptr == NULL);
#ifdef MAC
out:
#endif
	vrele(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_lutimes(struct thread *td, const char *path, enum uio_seg pathseg,
    const struct timeval *tptr, enum uio_seg tptrseg)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	struct timeval ktv[2];
	struct timespec ts[2];
	const struct timeval *ktp;
	enum uio_seg tseg;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_lutimes_dqimpl(td, path, pathseg, tptr, tptrseg));
	/*
	 * D161: the times are copied in once (only from user space) and the
	 * impl applies exactly what was posted.
	 */
	ktp = tptr;
	tseg = tptrseg;
	if (tptr != NULL && tptrseg == UIO_USERSPACE) {
		dqerror = copyin(tptr, ktv, sizeof(ktv));
		if (dqerror != 0)
			return (dqerror);
		ktp = ktv;
		tseg = UIO_SYSSPACE;
	}
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK) | DQ_RACCEPT(DQ_RESOLVE_FD));
	bzero(&sb, sizeof(sb));
	if (ktp == NULL)
		dq_setattr_times(&sb, NULL);	/* the _NOW flags, UTIMES_NULL */
	else {
		TIMEVAL_TO_TIMESPEC(&ktp[0], &ts[0]);
		TIMEVAL_TO_TIMESPEC(&ktp[1], &ts[1]);
		dq_setattr_times(&sb, ts);
		/* Explicit times need ownership or PRIV_VFS_ADMIN. */
		dqres_setattr_priv(td, &sb, DQ_SAPRIV_ADMIN);
	}
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, AT_FDCWD);
	dqerror = kern_lutimes_dqimpl(td, path, pathseg, ktp, tseg);
	DQRES_SERVED(td, &dqi, dqerror, dq_setattr_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Set the access and modification times of a file.
 */
#ifndef _SYS_SYSPROTO_H_
struct futimes_args {
	int	fd;
	struct	timeval *tptr;
};
#endif
int
sys_futimes(struct thread *td, struct futimes_args *uap)
{

	return (kern_futimes(td, uap->fd, uap->tptr, UIO_USERSPACE));
}

/*
 * futimes(2) and futimens(2): the descriptor sets its own times.  Neither
 * ever accepted a descriptor without a vnode or an O_PATH one.
 */
static int
kern_fsetutimes(struct thread *td, int fd, const struct timespec *ts,
    bool nullflag)
{
	struct vattr vattr;
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_futimes_rights, &fp);
	if (error != 0)
		return (error);
	error = getvnode_fp(fp, false);
	if (error != 0) {
		SDT_PROBE4(fd, , , refused, "futimens", fp, 0, error);
		goto out;
	}
	VATTR_NULL(&vattr);
	vattr.va_atime = ts[0];
	vattr.va_mtime = ts[1];
	if (nullflag)
		vattr.va_vaflags |= VA_UTIMES_NULL;
#ifdef MAC
	/* A served file's check; a vnode's are made by vn_setattr(). */
	if (fp->f_type == DTYPE_DQ) {
		error = mac_file_check_setattr(td->td_ucred, fp, fd, &vattr);
		if (error != 0)
			goto out;
	}
#endif
	error = fo_setattr(fp, &vattr, td->td_ucred, td);
out:
	fdrop(fp, td);
	return (error);
}

int
kern_futimes(struct thread *td, int fd, const struct timeval *tptr,
    enum uio_seg tptrseg)
{
	struct timespec ts[2];
	int error;

	AUDIT_ARG_FD(fd);
	error = getutimes(tptr, tptrseg, ts);
	if (error != 0)
		return (error);
	return (kern_fsetutimes(td, fd, ts, tptr == NULL));
}

int
sys_futimens(struct thread *td, struct futimens_args *uap)
{

	return (kern_futimens(td, uap->fd, uap->times, UIO_USERSPACE));
}

int
kern_futimens(struct thread *td, int fd, const struct timespec *tptr,
    enum uio_seg tptrseg)
{
	struct timespec ts[2];
	int error, flags;

	AUDIT_ARG_FD(fd);
	error = getutimens(tptr, tptrseg, ts, &flags);
	if (error != 0)
		return (error);
	if (flags & UTIMENS_EXIT)
		return (0);
	return (kern_fsetutimes(td, fd, ts, (flags & UTIMENS_NULL) != 0));
}

int
sys_utimensat(struct thread *td, struct utimensat_args *uap)
{

	return (kern_utimensat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE, uap->flag));
}

static int
kern_utimensat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, const struct timespec *tptr, enum uio_seg tptrseg,
    int flag)
{
	struct nameidata nd;
	struct vnode *vp;
	struct file *fp;
	struct vattr va;
	struct timespec ts[2];
	int error, flags;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);

	if ((error = getutimens(tptr, tptrseg, ts, &flags)) != 0)
		return (error);
	NDINIT_ATRIGHTS(&nd, LOOKUP, at2cnpflags(flag, AT_SYMLINK_NOFOLLOW |
	    AT_RESOLVE_BENEATH | AT_EMPTY_PATH) | AUDITVNODE1,
	    pathseg, path, fd, &cap_futimes_rights);
	if ((error = namei(&nd)) != 0) {
		/* D164: the served descriptor's own futimens, no event. */
		if (error == ENOTDIR &&
		    (nd.ni_resflags & NIRES_EMPTYPATH) != 0 &&
		    dqres_emptypath_file(td, fd, &cap_futimes_rights,
		    &fp) == 0) {
			error = 0;
			if ((flags & UTIMENS_EXIT) == 0) {
				VATTR_NULL(&va);
				va.va_atime = ts[0];
				va.va_mtime = ts[1];
				if ((flags & UTIMENS_NULL) != 0)
					va.va_vaflags |= VA_UTIMES_NULL;
				error = fo_setattr(fp, &va, td->td_ucred, td);
			}
			fdrop(fp, td);
		}
		return (error);
	}
	/*
	 * We are allowed to call namei() regardless of 2xUTIME_OMIT.
	 * POSIX states:
	 * "If both tv_nsec fields are UTIME_OMIT... EACCESS may be detected."
	 * "Search permission is denied by a component of the path prefix."
	 */
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
	if ((flags & UTIMENS_EXIT) == 0) {
#ifdef MAC
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = mac_vnode_check_setutimes(td->td_ucred, vp,
		    ts[0], ts[1]);
		VOP_UNLOCK(vp);
		if (error == 0)
#endif
			error = setutimes(td, vp, ts, 2,
			    flags & UTIMENS_NULL);
	}
	vrele(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_SETATTR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_utimensat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, const struct timespec *tptr, enum uio_seg tptrseg,
    int flag)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	struct timespec kts[2];
	const struct timespec *ktp;
	enum uio_seg tseg;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_utimensat_dqimpl(td, fd, path, pathseg, tptr, tptrseg, flag));
	/*
	 * The implementation refuses unknown flags before it reads the
	 * times: so must this copy, or a bad times pointer would be EFAULT
	 * where an unattached caller gets EINVAL.
	 */
	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH |
	    AT_EMPTY_PATH)) != 0)
		return (EINVAL);
	/* D161: the times are copied in once, only from user space. */
	ktp = tptr;
	tseg = tptrseg;
	if (tptr != NULL && tptrseg == UIO_USERSPACE) {
		dqerror = copyin(tptr, kts, sizeof(kts));
		if (dqerror != 0)
			return (dqerror);
		ktp = kts;
		tseg = UIO_SYSSPACE;
	}
	dq_intent_enter_served(td, &dqi, DQ_ROP_SETATTR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK) | DQ_RACCEPT(DQ_RESOLVE_FD));
	bzero(&sb, sizeof(sb));
	dq_setattr_times(&sb, ktp);
	/* Explicit times (not both UTIME_NOW) need ownership or privilege. */
	if ((sb.dsa_mask & DQ_SETATTR_F_UTIMES_NULL) == 0)
		dqres_setattr_priv(td, &sb, DQ_SAPRIV_ADMIN);
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_utimensat_dqimpl(td, fd, path, pathseg, ktp, tseg, flag);
	DQRES_SERVED(td, &dqi, dqerror, dq_setattr_dqserved(td, &dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Truncate a file given its path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct truncate_args {
	char	*path;
	int	pad;
	off_t	length;
};
#endif
int
sys_truncate(struct thread *td, struct truncate_args *uap)
{

	return (kern_truncate(td, uap->path, UIO_USERSPACE, uap->length));
}

static int
kern_truncate_dqimpl(struct thread *td, const char *path, enum uio_seg pathseg,
    off_t length)
{
	struct mount *mp;
	struct vnode *vp;
	void *rl_cookie;
	struct nameidata nd;
	int error;

	if (length < 0)
		return (EINVAL);
	NDPREINIT(&nd);
retry:
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNODE1, pathseg, path);
	if ((error = namei(&nd)) != 0)
		return (error);
	vp = nd.ni_vp;
	NDFREE_PNBUF(&nd);
	rl_cookie = vn_rangelock_wlock(vp, 0, OFF_MAX);
	if ((error = vn_start_write(vp, &mp, V_WAIT | V_PCATCH)) != 0) {
		vn_rangelock_unlock(vp, rl_cookie);
		vrele(vp);
		return (error);
	}
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}
#ifdef MAC
	error = mac_vnode_check_write(td->td_ucred, NOCRED, vp);
	if (error != 0)
		goto out;
	error = mac_vnode_check_truncate(td->td_ucred, vp);
	if (error != 0)
		goto out;
#endif
	error = VOP_ACCESS(vp, VWRITE, td->td_ucred, td);
	if (error != 0)
		goto out;

	error = vn_truncate_locked(vp, length, false, td->td_ucred);
out:
	VOP_UNLOCK(vp);
	vn_finished_write(mp);
	vn_rangelock_unlock(vp, rl_cookie);
	vrele(vp);
	if (error == ERELOOKUP)
		goto retry;
	return (error);
}

/*
 * truncate(2) answered OK (the controller truncated) or FD (review
 * amendment 1): kern_truncate's VWRITE check on the presented identity
 * (D166, with the append-only rule of ufs_setattr), the file bound
 * writable (the mint carried DQ_MINT_F_WRITE), RLIMIT_FSIZE, then
 * fo_truncate.
 */
static int
kern_truncate_dqserved(struct thread *td, struct dq_intent *di, off_t length)
{
	const struct dq_ident_file *id;
	struct file *fp;
	int error;

	if (di->di_res.da_kind == DQ_RESOLVE_OK)
		return (0);
	id = dqres_ident(di, DQ_RESOLVE_FD);
	if (id == NULL)
		return (EIO);
	error = dqres_ident_access(id, VWRITE, td->td_ucred);
	if (error == 0 && (id->di_flags & (SF_APPEND | UF_APPEND)) != 0)
		error = EPERM;
	if (error != 0)
		return (error);		/* dq_intent_leave retires it */
	error = dqres_take_file_raw(td, di, FREAD | FWRITE, &fp);
	if (error != 0)
		return (error);
	error = vn_rlimit_trunc(length, td);
	if (error == 0)
		error = fo_truncate(fp, length, td->td_ucred, td);
	fdrop(fp, td);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_TRUNCATE; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_truncate(struct thread *td, const char *path, enum uio_seg pathseg,
    off_t length)
{
	struct dq_intent dqi;
	struct dq_setattr_body sb;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_truncate_dqimpl(td, path, pathseg, length));
	dq_intent_enter_served(td, &dqi, DQ_ROP_TRUNCATE, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_FD) |
	    (length >= 0 && (rlim_t)length > lim_cur(td, RLIMIT_FSIZE) ? 0 :
	    DQ_RACCEPT(DQ_RESOLVE_OK)));
	/*
	 * D161: the size; a length past RLIMIT_FSIZE withholds OK, so the
	 * FD path applies SIGXFSZ and EFBIG (a negative one is EINVAL in the
	 * impl before any lookup).
	 */
	bzero(&sb, sizeof(sb));
	sb.dsa_mask = DQ_SETATTR_SIZE;
	sb.dsa_size = length;
	dqi.di_setattr = &sb;
	dq_intent_slot(&dqi, 0, path, pathseg, AT_FDCWD);
	dqerror = kern_truncate_dqimpl(td, path, pathseg, length);
	DQRES_SERVED(td, &dqi, dqerror, kern_truncate_dqserved(td, &dqi, length));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

#if defined(COMPAT_43)
/*
 * Truncate a file given its path name.
 */
#ifndef _SYS_SYSPROTO_H_
struct otruncate_args {
	char	*path;
	long	length;
};
#endif
int
otruncate(struct thread *td, struct otruncate_args *uap)
{

	return (kern_truncate(td, uap->path, UIO_USERSPACE, uap->length));
}
#endif /* COMPAT_43 */


int
kern_fsync_fp(struct thread *td, struct file *fp, bool fullsync)
{
#ifdef MAC
	int error;

	error = mac_file_check_fsync(td->td_ucred, fp);
	if (error != 0)
		return (error);
#endif
	return (fo_fsync(fp, fullsync ? FO_FSYNC_FULL : FO_FSYNC_DATA, td));
}

int
kern_fsync(struct thread *td, int fd, bool fullsync)
{
	struct file *fp;
	int error;

	AUDIT_ARG_FD(fd);
	error = fget(td, fd, &cap_fsync_rights, &fp);
	if (error != 0)
		return (error);
	/*
	 * fsync(2) and fdatasync(2) never accepted a descriptor without a
	 * vnode, or an O_PATH one.  aio_fsync(2) makes the same two tests
	 * in aio_aqueue(); Linux syncfs(2) takes an O_PATH descriptor and
	 * does not come this way.
	 */
	error = getvnode_fp(fp, false);
	if (error != 0)
		SDT_PROBE4(fd, , , refused, "fsync", fp, 0, error);
	else
		error = kern_fsync_fp(td, fp, fullsync);
	fdrop(fp, td);
	return (error);
}

/*
 * Sync an open file.
 */
#ifndef _SYS_SYSPROTO_H_
struct fsync_args {
	int	fd;
};
#endif
int
sys_fsync(struct thread *td, struct fsync_args *uap)
{

	return (kern_fsync(td, uap->fd, true));
}

int
sys_fdatasync(struct thread *td, struct fdatasync_args *uap)
{

	return (kern_fsync(td, uap->fd, false));
}

/*
 * Rename files.  Source and destination must either both be directories, or
 * both not be directories.  If target is a directory, it must be empty.
 */
#ifndef _SYS_SYSPROTO_H_
struct rename_args {
	char	*from;
	char	*to;
};
#endif
int
sys_rename(struct thread *td, struct rename_args *uap)
{

	return (kern_renameat(td, AT_FDCWD, uap->from, AT_FDCWD,
	    uap->to, UIO_USERSPACE, 0));
}

#ifndef _SYS_SYSPROTO_H_
struct renameat_args {
	int	oldfd;
	char	*old;
	int	newfd;
	char	*new;
};
#endif
int
sys_renameat(struct thread *td, struct renameat_args *uap)
{

	return (kern_renameat(td, uap->oldfd, uap->old, uap->newfd, uap->new,
	    UIO_USERSPACE, 0));
}

int
sys_renameat2(struct thread *td, struct renameat2_args *uap)
{

	return (kern_renameat(td, uap->oldfd, uap->old, uap->newfd, uap->new,
	    UIO_USERSPACE, uap->flags));
}

#ifdef MAC
static int
kern_renameat_mac(struct thread *td, int fromfd, const char *from, int tofd,
    const char *to, enum uio_seg pathseg, struct nameidata *fromnd, int op,
    int ndflags)
{
	int error;

	/* dq-ledger: slot 0 from of kern/vfs_syscalls.c:kern_renameat */
	NDINIT_ATRIGHTS(fromnd, op, LOCKPARENT | LOCKLEAF | AUDITVNODE1 |
	    ndflags, pathseg, from, fromfd, &cap_renameat_source_rights);
	if ((error = namei(fromnd)) != 0)
		return (error);
	/*
	 * AT_RENAME_EXCHANGE looks the source up with RENAME, which succeeds
	 * with no vnode for a missing last component.  Fail as the non-MAC
	 * path in kern_renameat() does (EBUSY for a non-directory parent,
	 * then ENOENT) instead of handing the policy a NULL vnode.
	 */
	if (fromnd->ni_vp == NULL) {
		error = fromnd->ni_dvp->v_type != VDIR ? EBUSY : ENOENT;
		VOP_UNLOCK(fromnd->ni_dvp);
		NDFREE_PNBUF(fromnd);
		vrele(fromnd->ni_dvp);
		return (error);
	}
	error = mac_vnode_check_rename_from(td->td_ucred, fromnd->ni_dvp,
	    fromnd->ni_vp, &fromnd->ni_cnd);
	VOP_UNLOCK(fromnd->ni_dvp);
	if (fromnd->ni_dvp != fromnd->ni_vp)
		VOP_UNLOCK(fromnd->ni_vp);
	if (error != 0) {
		NDFREE_PNBUF(fromnd);
		vrele(fromnd->ni_dvp);
		vrele(fromnd->ni_vp);
	}
	return (error);
}
#endif

static int
kern_renameat_dqimpl(struct thread *td, int fromfd, const char *from, int tofd,
    const char *to, enum uio_seg pathseg, u_int flags)
{
	struct mount *mp, *tmp;
	struct vnode *tvp, *fvp, *tdvp;
	struct nameidata fromnd, tond;
	uint64_t tondflags;
	int error, fndflags, op;
	short irflag;
	bool exchange;

	if ((flags & ~(AT_RENAME_NOREPLACE | AT_RENAME_EXCHANGE)) != 0)
		return (EINVAL);
	if ((flags & (AT_RENAME_NOREPLACE | AT_RENAME_EXCHANGE)) ==
	    (AT_RENAME_NOREPLACE | AT_RENAME_EXCHANGE))
		return (EINVAL);
	if ((flags & AT_RENAME_EXCHANGE) != 0) {
		op = RENAME;
		exchange = true;
	} else {
		op = DELETE;
		exchange = false;
	}
	fndflags = 0;
again:
	tmp = mp = NULL;
	bwillwrite();
#ifdef MAC
	if (mac_vnode_check_rename_from_enabled()) {
		error = kern_renameat_mac(td, fromfd, from, tofd, to, pathseg,
		    &fromnd, op, fndflags);
		if (error != 0)
			return (error);
	} else {
#endif
	NDINIT_ATRIGHTS(&fromnd, op, WANTPARENT | AUDITVNODE1 | fndflags,
	    pathseg, from, fromfd, &cap_renameat_source_rights);
	if ((error = namei(&fromnd)) != 0)
		return (error);
#ifdef MAC
	}
#endif
	fvp = fromnd.ni_vp;
	if (fromnd.ni_dvp->v_type != VDIR) {
		NDFREE_PNBUF(&fromnd);
		vrele(fromnd.ni_dvp);
		if (fvp != NULL)
			vrele(fromnd.ni_vp);
		return (EBUSY);
	}
	if (exchange && fvp == NULL) {
		NDFREE_PNBUF(&fromnd);
		vrele(fromnd.ni_dvp);
		return (ENOENT);
	}
	tondflags = LOCKPARENT | LOCKLEAF | NOCACHE | AUDITVNODE2;
	if (fromnd.ni_vp->v_type == VDIR)
		tondflags |= WILLBEDIR;
	NDINIT_ATRIGHTS(&tond, RENAME, tondflags, pathseg, to, tofd,
	    &cap_renameat_target_rights);
	if ((error = namei(&tond)) != 0) {
		/* Translate error code for rename("dir1", "dir2/."). */
		if (error == EISDIR && fvp->v_type == VDIR)
			error = EINVAL;
		NDFREE_PNBUF(&fromnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto out1;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;
	if (tdvp->v_type != VDIR) {
		/*
		 * Rename of the root vnode of the mounted
		 * filesystem. It is possible to get there with the
		 * nullfs mount over the regular file.
		 */
		error = EBUSY;
		goto out;
	}
	if (tvp != NULL && (flags & AT_RENAME_NOREPLACE) != 0) {
		/*
		 * Often filesystems need to relock the vnodes in
		 * VOP_RENAME(), which opens a window for invalidation
		 * of this check.  Then, not all filesystems might
		 * implement AT_RENAME_NOREPLACE.  This leads to
		 * situation where sometimes EOPNOTSUPP might be
		 * returned from the VOP due to race, while most of
		 * the time this check works.
		 */
		error = EEXIST;
		goto out;
	}
	if (fvp->v_type == VDIR &&
	    ((fromnd.ni_resflags | tond.ni_resflags) & NIRES_BENEATH) != 0) {
		/*
		 * We must not rename a directory relative to FD_RESOLVE_BENEATH
		 * descriptors.
		 */
		error = ENOTCAPABLE;
		goto out;
	}
	if (exchange) {
		if (tvp == NULL) {
			error = ENOENT;
			goto out;
		}
		if (tvp->v_type == VDIR && fndflags == 0) {
			fndflags = WILLBEDIR;
again2:
			NDFREE_PNBUF(&fromnd);
			vrele(fromnd.ni_dvp);
			vrele(fvp);
			NDFREE_PNBUF(&tond);
			VOP_VPUT_PAIR(tdvp, &tvp, true);
			error = sig_intr();
			if (error != 0)
				goto out1;
			goto again;
		}
		if (tvp->v_type != VDIR && fndflags != 0) {
			fndflags = 0;
			goto again2;
		}
	}
	error = vn_start_write(fvp, &mp, V_NOWAIT);
	if (error != 0) {
again1:
		NDFREE_PNBUF(&fromnd);
		NDFREE_PNBUF(&tond);
		if (tvp != NULL)
			vput(tvp);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		if (tmp != NULL) {
			lockmgr(&tmp->mnt_renamelock, LK_EXCLUSIVE, NULL);
			lockmgr(&tmp->mnt_renamelock, LK_RELEASE, NULL);
			vfs_rel(tmp);
			tmp = NULL;
		}
		error = sig_intr();
		if (error != 0)
			return (error);
		error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH);
		if (error != 0)
			return (error);
		goto again;
	}
	error = VOP_GETWRITEMOUNT(tdvp, &tmp);
	if (error != 0 || tmp == NULL)
		goto again1;
	error = lockmgr(&tmp->mnt_renamelock, LK_EXCLUSIVE | LK_NOWAIT, NULL);
	if (error != 0) {
		vn_finished_write(mp);
		goto again1;
	}
	irflag = vn_irflag_read(fvp);
	if (((irflag & VIRF_NAMEDATTR) != 0 && tdvp != fromnd.ni_dvp) ||
	    (irflag & VIRF_NAMEDDIR) != 0) {
		error = EINVAL;
		goto out;
	}
	if (tvp != NULL) {
		if (!exchange) {
			if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			} else if (fvp->v_type != VDIR &&
			    tvp->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}
#ifdef CAPABILITIES
		if (tofd != AT_FDCWD && (tond.ni_resflags & NIRES_ABS) == 0) {
			/*
			 * If the target already exists we require CAP_UNLINKAT
			 * from 'tofd', when tofd was used for the lookup.
			 */
			error = cap_check(&tond.ni_filecaps.fc_rights,
			    &cap_unlinkat_rights);
			if (error != 0)
				goto out;
		}
#endif
	}
	if (fvp == tdvp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * If the source is the same as the destination (that is, if they
	 * are links to the same vnode), then there is nothing to do.
	 */
	if (fvp == tvp)
		error = ERESTART;
#ifdef MAC
	else
		error = mac_vnode_check_rename_to(td->td_ucred, tdvp,
		    tond.ni_vp, fromnd.ni_dvp == tdvp, &tond.ni_cnd);
#endif
out:
	if (error == 0) {
		error = VOP_RENAME(fromnd.ni_dvp, fromnd.ni_vp, &fromnd.ni_cnd,
		    tond.ni_dvp, tond.ni_vp, &tond.ni_cnd, flags);
#ifdef MAC
		if (error == 0)
			mac_vnode_notify_rename(td->td_ucred,
			    &fromnd.ni_cnd, &tond.ni_cnd);
#endif
		NDFREE_PNBUF(&fromnd);
		NDFREE_PNBUF(&tond);
	} else {
		NDFREE_PNBUF(&fromnd);
		NDFREE_PNBUF(&tond);
		if (tvp != NULL)
			vput(tvp);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
	}
	if (tmp != NULL) {
		lockmgr(&tmp->mnt_renamelock, LK_RELEASE, 0);
		vfs_rel(tmp);
	}
	if (mp != NULL)
		vn_finished_write(mp);
out1:
	if (error == ERESTART)
		return (0);
	if (error == ERELOOKUP) {
		error = sig_intr();
		if (error == 0)
			goto again;
	}
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_RENAME; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_renameat(struct thread *td, int fromfd, const char *from, int tofd,
    const char *to, enum uio_seg pathseg, u_int flags)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_renameat_dqimpl(td, fromfd, from, tofd, to, pathseg, flags));
	dq_intent_enter_served(td, &dqi, DQ_ROP_RENAME, DQI_USER | DQI_NO_ERESTART | DQI_PATH2,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dqi.di_mode = flags;
	dq_intent_slot(&dqi, 0, from, pathseg, fromfd);
	dq_intent_slot(&dqi, 1, to, pathseg, tofd);
	dq_intent_slot_rights(&dqi, 1, &cap_renameat_target_rights);
	dqerror = kern_renameat_dqimpl(td, fromfd, from, tofd, to, pathseg, flags);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Make a directory file.
 */
#ifndef _SYS_SYSPROTO_H_
struct mkdir_args {
	char	*path;
	int	mode;
};
#endif
int
sys_mkdir(struct thread *td, struct mkdir_args *uap)
{

	return (kern_mkdirat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

#ifndef _SYS_SYSPROTO_H_
struct mkdirat_args {
	int	fd;
	char	*path;
	mode_t	mode;
};
#endif
int
sys_mkdirat(struct thread *td, struct mkdirat_args *uap)
{

	return (kern_mkdirat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode));
}

static int
kern_mkdirat_dqimpl(struct thread *td, int fd, const char *path, enum uio_seg segflg,
    int mode)
{
	struct mount *mp;
	struct vattr vattr;
	struct nameidata nd;
	int error;

	AUDIT_ARG_MODE(mode);
	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, CREATE, LOCKPARENT | AUDITVNODE1 |
	    NC_NOMAKEENTRY | NC_KEEPPOSENTRY | FAILIFEXISTS | WILLBEDIR,
	    segflg, path, fd, &cap_mkdirat_rights);
	if ((error = namei(&nd)) != 0)
		return (error);
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			return (error);
		goto restart;
	}
	if ((vn_irflag_read(nd.ni_dvp) & VIRF_NAMEDDIR) != 0) {
		error = EINVAL;
		goto out;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VDIR;
	vattr.va_mode = (mode & ACCESSPERMS) &~ td->td_proc->p_pd->pd_cmask;
#ifdef MAC
	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd,
	    &vattr);
	if (error != 0)
		goto out;
#endif
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
out:
	NDFREE_PNBUF(&nd);
	VOP_VPUT_PAIR(nd.ni_dvp, error == 0 ? &nd.ni_vp : NULL, true);
	vn_finished_write(mp);
	if (error == ERELOOKUP)
		goto restart;
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_MKDIR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_mkdirat(struct thread *td, int fd, const char *path, enum uio_seg segflg,
    int mode)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(segflg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_mkdirat_dqimpl(td, fd, path, segflg, mode));
	dq_intent_enter_served(td, &dqi, DQ_ROP_MKDIR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dqi.di_cmode = (mode & ACCESSPERMS) & ~td->td_proc->p_pd->pd_cmask;
	dqi.di_mode = mode;
	dq_intent_slot(&dqi, 0, path, segflg, fd);
	dqerror = kern_mkdirat_dqimpl(td, fd, path, segflg, mode);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * Remove a directory file.
 */
#ifndef _SYS_SYSPROTO_H_
struct rmdir_args {
	char	*path;
};
#endif
int
sys_rmdir(struct thread *td, struct rmdir_args *uap)
{

	return (kern_frmdirat(td, AT_FDCWD, uap->path, FD_NONE, UIO_USERSPACE,
	    0));
}

static int
kern_frmdirat_dqimpl(struct thread *td, int dfd, const char *path, int fd,
    enum uio_seg pathseg, int flag)
{
	struct mount *mp;
	struct vnode *vp;
	struct file *fp;
	struct nameidata nd;
	cap_rights_t rights;
	int error;

	fp = NULL;
	if (fd != FD_NONE) {
		/* D170: a served descriptor names the served object. */
		error = dqres_unlink_fd(td, fd, cap_rights_init_one(&rights,
		    CAP_LOOKUP), &fp);
		if (error == ENOTTY) {
			error = getvnode(td, fd, &rights, &fp);
			if (error == 0)
				dqres_unlink_realfd(td);
		}
		if (error != 0)
			return (error);
	}

	NDPREINIT(&nd);
restart:
	bwillwrite();
	NDINIT_ATRIGHTS(&nd, DELETE, LOCKPARENT | LOCKLEAF | AUDITVNODE1 |
	    at2cnpflags(flag, AT_RESOLVE_BENEATH),
	    pathseg, path, dfd, &cap_unlinkat_rights);
	if ((error = namei(&nd)) != 0)
		goto fdout;
	vp = nd.ni_vp;
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * No rmdir "." please.
	 */
	if (nd.ni_dvp == vp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * The root of a mounted filesystem cannot be deleted.
	 */
	if (vp->v_vflag & VV_ROOT) {
		error = EBUSY;
		goto out;
	}

	if (fp != NULL && fp->f_vnode != vp) {
		/*
		 * A served descriptor never names a real vnode (D170); an
		 * unattached process holding one is refused EACCES, as for any
		 * use of a served directory outside its attachment.
		 */
		if (fp->f_vnode != NULL && VN_IS_DOOMED(fp->f_vnode))
			error = EBADF;
		else if (fp->f_vnode == NULL && !DQRES_ATTACHED_TD(td))
			error = EACCES;
		else
			error = EDEADLK;
		goto out;
	}

#ifdef MAC
	error = mac_vnode_check_unlink(td->td_ucred, nd.ni_dvp, vp,
	    &nd.ni_cnd);
	if (error != 0)
		goto out;
#endif
	if (vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE_PNBUF(&nd);
		vput(vp);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if ((error = vn_start_write(NULL, &mp, V_XSLEEP | V_PCATCH)) != 0)
			goto fdout;
		goto restart;
	}
	error = VOP_RMDIR(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
	vn_finished_write(mp);
out:
	NDFREE_PNBUF(&nd);
	vput(vp);
	if (nd.ni_dvp == vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	if (error == ERELOOKUP)
		goto restart;
fdout:
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_RMDIR; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_frmdirat(struct thread *td, int dfd, const char *path, int fd,
    enum uio_seg pathseg, int flag)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_frmdirat_dqimpl(td, dfd, path, fd, pathseg, flag));
	dq_intent_enter_served(td, &dqi, DQ_ROP_RMDIR, DQI_USER,
	    DQ_RACCEPT(DQ_RESOLVE_OK));
	dq_intent_slot(&dqi, 0, path, pathseg, dfd);
	dqerror = kern_frmdirat_dqimpl(td, dfd, path, fd, pathseg, flag);
	DQRES_SERVED(td, &dqi, dqerror, dq_ok_dqserved(&dqi));
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

#if defined(COMPAT_43) || defined(COMPAT_FREEBSD11)
int
freebsd11_kern_getdirentries(struct thread *td, int fd, char *ubuf, u_int count,
    long *basep, void (*func)(struct freebsd11_dirent *))
{
	struct freebsd11_dirent dstdp;
	struct dirent *dp, *edp;
	char *dirbuf;
	off_t base;
	ssize_t resid, ucount;
	int error;

	/* XXX arbitrary sanity limit on `count'. */
	count = min(count, 64 * 1024);

	dirbuf = malloc(count, M_TEMP, M_WAITOK);

	error = kern_getdirentries(td, fd, dirbuf, count, &base, &resid,
	    UIO_SYSSPACE);
	if (error != 0)
		goto done;
	if (basep != NULL)
		*basep = base;

	ucount = 0;
	for (dp = (struct dirent *)dirbuf,
	    edp = (struct dirent *)&dirbuf[count - resid];
	    ucount < count && dp < edp; ) {
		if (dp->d_reclen == 0)
			break;
		MPASS(dp->d_reclen >= _GENERIC_DIRLEN(0));
		if (dp->d_namlen >= sizeof(dstdp.d_name))
			continue;
		dstdp.d_type = dp->d_type;
		dstdp.d_namlen = dp->d_namlen;
		dstdp.d_fileno = dp->d_fileno;		/* truncate */
		if (dstdp.d_fileno != dp->d_fileno) {
			switch (ino64_trunc_error) {
			default:
			case 0:
				break;
			case 1:
				error = EOVERFLOW;
				goto done;
			case 2:
				dstdp.d_fileno = UINT32_MAX;
				break;
			}
		}
		dstdp.d_reclen = sizeof(dstdp) - sizeof(dstdp.d_name) +
		    ((dp->d_namlen + 1 + 3) &~ 3);
		bcopy(dp->d_name, dstdp.d_name, dstdp.d_namlen);
		bzero(dstdp.d_name + dstdp.d_namlen,
		    dstdp.d_reclen - offsetof(struct freebsd11_dirent, d_name) -
		    dstdp.d_namlen);
		MPASS(dstdp.d_reclen <= dp->d_reclen);
		MPASS(ucount + dstdp.d_reclen <= count);
		if (func != NULL)
			func(&dstdp);
		error = copyout(&dstdp, ubuf + ucount, dstdp.d_reclen);
		if (error != 0)
			break;
		dp = (struct dirent *)((char *)dp + dp->d_reclen);
		ucount += dstdp.d_reclen;
	}

done:
	free(dirbuf, M_TEMP);
	if (error == 0)
		td->td_retval[0] = ucount;
	return (error);
}
#endif /* COMPAT */

#ifdef COMPAT_43
static void
ogetdirentries_cvt(struct freebsd11_dirent *dp)
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
	/*
	 * The expected low byte of dp->d_namlen is our dp->d_type.
	 * The high MBZ byte of dp->d_namlen is our dp->d_namlen.
	 */
	dp->d_type = dp->d_namlen;
	dp->d_namlen = 0;
#else
	/*
	 * The dp->d_type is the high byte of the expected dp->d_namlen,
	 * so must be zero'ed.
	 */
	dp->d_type = 0;
#endif
}

/*
 * Read a block of directory entries in a filesystem independent format.
 */
#ifndef _SYS_SYSPROTO_H_
struct ogetdirentries_args {
	int	fd;
	char	*buf;
	u_int	count;
	long	*basep;
};
#endif
int
ogetdirentries(struct thread *td, struct ogetdirentries_args *uap)
{
	long loff;
	int error;

	error = kern_ogetdirentries(td, uap, &loff);
	if (error == 0)
		error = copyout(&loff, uap->basep, sizeof(long));
	return (error);
}

int
kern_ogetdirentries(struct thread *td, struct ogetdirentries_args *uap,
    long *ploff)
{
	long base;
	int error;

	/* XXX arbitrary sanity limit on `count'. */
	if (uap->count > 64 * 1024)
		return (EINVAL);

	error = freebsd11_kern_getdirentries(td, uap->fd, uap->buf, uap->count,
	    &base, ogetdirentries_cvt);

	if (error == 0 && uap->basep != NULL)
		error = copyout(&base, uap->basep, sizeof(long));

	return (error);
}
#endif /* COMPAT_43 */

#if defined(COMPAT_FREEBSD11)
#ifndef _SYS_SYSPROTO_H_
struct freebsd11_getdirentries_args {
	int	fd;
	char	*buf;
	u_int	count;
	long	*basep;
};
#endif
int
freebsd11_getdirentries(struct thread *td,
    struct freebsd11_getdirentries_args *uap)
{
	long base;
	int error;

	error = freebsd11_kern_getdirentries(td, uap->fd, uap->buf, uap->count,
	    &base, NULL);

	if (error == 0 && uap->basep != NULL)
		error = copyout(&base, uap->basep, sizeof(long));
	return (error);
}

int
freebsd11_getdents(struct thread *td, struct freebsd11_getdents_args *uap)
{
	struct freebsd11_getdirentries_args ap;

	ap.fd = uap->fd;
	ap.buf = uap->buf;
	ap.count = uap->count;
	ap.basep = NULL;
	return (freebsd11_getdirentries(td, &ap));
}
#endif /* COMPAT_FREEBSD11 */

/*
 * Read a block of directory entries in a filesystem independent format.
 */
int
sys_getdirentries(struct thread *td, struct getdirentries_args *uap)
{
	off_t base;
	int error;

	error = kern_getdirentries(td, uap->fd, uap->buf, uap->count, &base,
	    NULL, UIO_USERSPACE);
	if (error != 0)
		return (error);
	if (uap->basep != NULL)
		error = copyout(&base, uap->basep, sizeof(off_t));
	return (error);
}

int
kern_getdirentries(struct thread *td, int fd, char *buf, size_t count,
    off_t *basep, ssize_t *residp, enum uio_seg bufseg)
{
	struct file *fp;
	struct uio auio;
	struct iovec aiov;
	int error;

	AUDIT_ARG_FD(fd);
	if (count > IOSIZE_MAX)
		return (EINVAL);
	error = fget(td, fd, &cap_read_rights, &fp);
	if (error != 0)
		return (error);
	error = getvnode_fp(fp, false);
	if (error == 0 && (fp->f_flag & FREAD) == 0)
		error = EBADF;
	if (error != 0) {
		SDT_PROBE4(fd, , , refused, "getdirentries", fp, 0, error);
		fdrop(fp, td);
		return (error);
	}
	aiov.iov_base = buf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = count;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = bufseg;
	auio.uio_td = td;
	auio.uio_offset = foffset_lock(fp, 0);
	error = fo_readdir(fp, &auio, basep, td);
	foffset_unlock(fp, auio.uio_offset, 0);
	fdrop(fp, td);
	if (error != 0)
		return (error);
	if (residp != NULL)
		*residp = auio.uio_resid;
	td->td_retval[0] = count - auio.uio_resid;
	return (0);
}

/*
 * Directory entries of a vnode file.  A union mount's root directory reads
 * on into the directory it covers, and the file follows: f_vnode moves to
 * the covered vnode and the offset restarts, as it always has.
 */
int
vn_readdir(struct file *fp, struct uio *uio, off_t *basep, struct thread *td)
{
	struct vn_file_context filectx;
	struct vnode *vp;
	ssize_t count;
	off_t loff;
	int error, eofflag;

	count = uio->uio_resid;
	vp = fp->f_vnode;
unionread:
	if (__predict_false((vp->v_vflag & VV_UNLINKED) != 0))
		return (ENOENT);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	/*
	 * We want to return ENOTDIR for anything that is not VDIR, but
	 * not for VBAD, and we can't check for VBAD while the vnode is
	 * unlocked.
	 */
	if (vp->v_type != VDIR) {
		error = vp->v_type == VBAD ? EBADF : ENOTDIR;
		VOP_UNLOCK(vp);
		return (error);
	}
	AUDIT_ARG_VNODE1(vp);
	loff = uio->uio_offset;
#ifdef MAC
	error = mac_vnode_check_readdir(td->td_ucred, vp);
	if (error == 0)
#endif
		{
		vn_file_context_enter(&filectx, fp, NULL, 0);
		error = VOP_READDIR(vp, uio, fp->f_cred, &eofflag, NULL, NULL);
		vn_file_context_leave(&filectx);
	}
	if (error != 0) {
		VOP_UNLOCK(vp);
		return (error);
	}
	if (count == uio->uio_resid &&
	    (vp->v_vflag & VV_ROOT) &&
	    (vp->v_mount->mnt_flag & MNT_UNION)) {
		struct vnode *tvp = vp;

		vp = vp->v_mount->mnt_vnodecovered;
		vref(vp);
		fp->f_vnode = vp;
		uio->uio_offset = 0;
		vput(tvp);
		goto unionread;
	}
	VOP_UNLOCK(vp);
	*basep = loff;
	return (0);
}

/*
 * Set the mode mask for creation of filesystem nodes.
 */
#ifndef _SYS_SYSPROTO_H_
struct umask_args {
	int	newmask;
};
#endif
int
sys_umask(struct thread *td, struct umask_args *uap)
{
	struct pwddesc *pdp;

	pdp = td->td_proc->p_pd;
	PWDDESC_XLOCK(pdp);
	td->td_retval[0] = pdp->pd_cmask;
	pdp->pd_cmask = uap->newmask & ALLPERMS;
	PWDDESC_XUNLOCK(pdp);
	return (0);
}

/*
 * Void all references to file by ripping underlying filesystem away from
 * vnode.
 */
#ifndef _SYS_SYSPROTO_H_
struct revoke_args {
	char	*path;
};
#endif
static int
sys_revoke_dqimpl(struct thread *td, struct revoke_args *uap)
{
	struct vnode *vp;
	struct vattr vattr;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNODE1, UIO_USERSPACE,
	    uap->path);
	if ((error = namei(&nd)) != 0)
		return (error);
	vp = nd.ni_vp;
	NDFREE_PNBUF(&nd);
	if (vp->v_type != VCHR || vp->v_rdev == NULL) {
		error = EINVAL;
		goto out;
	}
#ifdef MAC
	error = mac_vnode_check_revoke(td->td_ucred, vp);
	if (error != 0)
		goto out;
#endif
	error = VOP_GETATTR(vp, &vattr, td->td_ucred);
	if (error != 0)
		goto out;
	if (td->td_ucred->cr_uid != vattr.va_uid) {
		error = priv_check(td, PRIV_VFS_ADMIN);
		if (error != 0)
			goto out;
	}
	if (devfs_usecount(vp) > 0)
		VOP_REVOKE(vp, REVOKEALL);
out:
	vput(vp);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_REVOKE; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
sys_revoke(struct thread *td, struct revoke_args *uap)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(true) || !DQRES_ATTACHED_TD(td))
		return (sys_revoke_dqimpl(td, uap));
	dq_intent_enter(td, &dqi, DQ_ROP_REVOKE, DQI_USER);
	dq_intent_slot(&dqi, 0, uap->path, UIO_USERSPACE, AT_FDCWD);
	dqerror = sys_revoke_dqimpl(td, uap);
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

/*
 * This variant of getvnode() allows O_PATH files.  Caller should
 * ensure that returned file and vnode are only used for compatible
 * semantics.
 */
int
getvnode_path(struct thread *td, int fd, const cap_rights_t *rightsp,
    uint8_t *flagsp, struct file **fpp)
{
	struct file *fp;
	int error;

	error = fget_unlocked_flags(td, fd, rightsp, flagsp, &fp);
	if (error != 0)
		return (error);

	/*
	 * The file could be not of the vnode type, or it may be not
	 * yet fully initialized, in which case the f_vnode pointer
	 * may be set, but f_ops is still badfileops.  E.g.,
	 * devfs_open() transiently create such situation to
	 * facilitate csw d_fdopen().
	 *
	 * Dupfdopen() handling in kern_openat() installs the
	 * half-baked file into the process descriptor table, allowing
	 * other thread to dereference it. Guard against the race by
	 * checking f_ops.
	 */
	if (__predict_false(fp->f_vnode == NULL || fp->f_ops == &badfileops)) {
		fdrop(fp, td);
		*fpp = NULL;
		return (EINVAL);
	}

	*fpp = fp;
	return (0);
}

/*
 * Convert a user file descriptor to a kernel file entry and check
 * that, if it is a capability, the correct rights are present.
 * A reference on the file entry is held upon returning.
 */
int
getvnode(struct thread *td, int fd, const cap_rights_t *rightsp,
    struct file **fpp)
{
	int error;

	error = getvnode_path(td, fd, rightsp, NULL, fpp);
	if (__predict_false(error != 0))
		return (error);

	/*
	 * Filter out O_PATH file descriptors, most getvnode() callers
	 * do not call fo_ methods.
	 */
	if (__predict_false((*fpp)->f_ops == &path_fileops)) {
		fdrop(*fpp, td);
		*fpp = NULL;
		error = EBADF;
	}

	return (error);
}

/*
 * The tests getvnode() and, when "path" is true, getvnode_path() make, on
 * a file the caller already holds: EINVAL for a file without a vnode,
 * EBADF for an O_PATH file unless "path" accepts it.  A served (DTYPE_DQ)
 * file has no vnode but answers through its table, so only the O_PATH
 * test applies to it.
 */
int
getvnode_fp(struct file *fp, bool path)
{

	if (fp->f_type == DTYPE_DQ)
		return (!path && (fp->f_flag & O_PATH) != 0 ? EBADF : 0);
	if (__predict_false(fp->f_vnode == NULL || fp->f_ops == &badfileops))
		return (EINVAL);
	if (!path && __predict_false(fp->f_ops == &path_fileops))
		return (EBADF);
	return (0);
}

/*
 * Get an (NFS) file handle.
 */
#ifndef _SYS_SYSPROTO_H_
struct lgetfh_args {
	char *fname;
	fhandle_t *fhp;
};
#endif
int
sys_lgetfh(struct thread *td, struct lgetfh_args *uap)
{

	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->fname,
	    UIO_USERSPACE, uap->fhp, UIO_USERSPACE));
}

#ifndef _SYS_SYSPROTO_H_
struct getfh_args {
	char *fname;
	fhandle_t *fhp;
};
#endif
int
sys_getfh(struct thread *td, struct getfh_args *uap)
{

	return (kern_getfhat(td, 0, AT_FDCWD, uap->fname, UIO_USERSPACE,
	    uap->fhp, UIO_USERSPACE));
}

/*
 * syscall for the rpc.lockd to use to translate an open descriptor into
 * a NFS file handle.
 *
 * warning: do not remove the priv_check() call or this becomes one giant
 * security hole.
 */
#ifndef _SYS_SYSPROTO_H_
struct getfhat_args {
	int fd;
	char *path;
	fhandle_t *fhp;
	int flags;
};
#endif
int
sys_getfhat(struct thread *td, struct getfhat_args *uap)
{

	return (kern_getfhat(td, uap->flags, uap->fd, uap->path, UIO_USERSPACE,
	    uap->fhp, UIO_USERSPACE));
}

static int
kern_getfhat_dqimpl(struct thread *td, int flags, int fd, const char *path,
    enum uio_seg pathseg, fhandle_t *fhp, enum uio_seg fhseg)
{
	struct nameidata nd;
	fhandle_t fh;
	struct vnode *vp;
	int error;

	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH)) != 0)
		return (EINVAL);
	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);
	NDINIT_AT(&nd, LOOKUP, at2cnpflags(flags, AT_SYMLINK_NOFOLLOW |
	    AT_RESOLVE_BENEATH) | LOCKLEAF | AUDITVNODE1, pathseg, path,
	    fd);
	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
	bzero(&fh, sizeof(fh));
	fh.fh_fsid = vp->v_mount->mnt_stat.f_fsid;
#ifdef MAC
	error = mac_vnode_check_fh(td->td_ucred, vp);
	if (error == 0)
#endif
		error = VOP_VPTOFH(vp, &fh.fh_fid);
	vput(vp);
	if (error == 0) {
		if (fhseg == UIO_USERSPACE)
			error = copyout(&fh, fhp, sizeof (fh));
		else
			memcpy(fhp, &fh, sizeof(fh));
	}
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of a
 * user-supplied path, DQ_ROP_GETFH; kernel callers pass kernel-space paths and
 * are not marked.  Entries recorded in sys/dev/dq/dq_resolve_ledger.txt.
 */
int
kern_getfhat(struct thread *td, int flags, int fd, const char *path,
    enum uio_seg pathseg, fhandle_t *fhp, enum uio_seg fhseg)
{
	struct dq_intent dqi;
	int dqerror;

	if (!(pathseg == UIO_USERSPACE) || !DQRES_ATTACHED_TD(td))
		return (kern_getfhat_dqimpl(td, flags, fd, path, pathseg, fhp, fhseg));
	dq_intent_enter(td, &dqi, DQ_ROP_GETFH, DQI_USER);
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_getfhat_dqimpl(td, flags, fd, path, pathseg, fhp, fhseg);
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

#ifndef _SYS_SYSPROTO_H_
struct fhlink_args {
	fhandle_t *fhp;
	const char *to;
};
#endif
int
sys_fhlink(struct thread *td, struct fhlink_args *uap)
{

	return (kern_fhlinkat(td, AT_FDCWD, uap->to, UIO_USERSPACE, uap->fhp));
}

#ifndef _SYS_SYSPROTO_H_
struct fhlinkat_args {
	fhandle_t *fhp;
	int tofd;
	const char *to;
};
#endif
int
sys_fhlinkat(struct thread *td, struct fhlinkat_args *uap)
{

	return (kern_fhlinkat(td, uap->tofd, uap->to, UIO_USERSPACE, uap->fhp));
}

static int
kern_fhlinkat_dqimpl(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, fhandle_t *fhp)
{
	fhandle_t fh;
	struct mount *mp;
	struct vnode *vp;
	int error;

	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);
	error = copyin(fhp, &fh, sizeof(fh));
	if (error != 0)
		return (error);
	do {
		bwillwrite();
		if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
			return (ESTALE);
		error = VFS_FHTOVP(mp, &fh.fh_fid, LK_SHARED, &vp);
		vfs_unbusy(mp);
		if (error != 0)
			return (error);
#ifdef MAC
		error = mac_vnode_check_fh(td->td_ucred, vp);
		if (error != 0) {
			vput(vp);
			return (error);
		}
#endif
		VOP_UNLOCK(vp);
		error = kern_linkat_vp(td, vp, fd, path, pathseg);
	} while (error == EAGAIN || error == ERELOOKUP);
	return (error);
}

/*
 * DescriptorQueue (stage 1c, D126/D127): the lookup intent of fhlink(2)
 * and fhlinkat(2)'s user-supplied path, DQ_ROP_LINK (the file is named by
 * a handle, so only the new name is resolved; the loop below reruns it on
 * ERELOOKUP, hence DQI_NO_ERESTART as kern_linkat).  Entries recorded in
 * sys/dev/dq/dq_resolve_ledger.txt.
 */
static int
kern_fhlinkat(struct thread *td, int fd, const char *path,
    enum uio_seg pathseg, fhandle_t *fhp)
{
	struct dq_intent dqi;
	int dqerror;

	if (pathseg != UIO_USERSPACE || !DQRES_ATTACHED_TD(td))
		return (kern_fhlinkat_dqimpl(td, fd, path, pathseg, fhp));
	/* PASS only (review): the handle's file is real, its link too. */
	dq_intent_enter(td, &dqi, DQ_ROP_LINK, DQI_USER | DQI_NO_ERESTART);
	dq_intent_slot(&dqi, 0, path, pathseg, fd);
	dqerror = kern_fhlinkat_dqimpl(td, fd, path, pathseg, fhp);
	dq_intent_leave(td, &dqi);
	return (dqerror);
}

#ifndef _SYS_SYSPROTO_H_
struct fhreadlink_args {
	fhandle_t *fhp;
	char *buf;
	size_t bufsize;
};
#endif
int
sys_fhreadlink(struct thread *td, struct fhreadlink_args *uap)
{
	fhandle_t fh;
	struct mount *mp;
	struct vnode *vp;
	int error;

	error = priv_check(td, PRIV_VFS_GETFH);
	if (error != 0)
		return (error);
	if (uap->bufsize > IOSIZE_MAX)
		return (EINVAL);
	error = copyin(uap->fhp, &fh, sizeof(fh));
	if (error != 0)
		return (error);
	if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
		return (ESTALE);
	error = VFS_FHTOVP(mp, &fh.fh_fid, LK_SHARED, &vp);
	vfs_unbusy(mp);
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_vnode_check_fh(td->td_ucred, vp);
	if (error != 0) {
		vput(vp);
		return (error);
	}
#endif
	error = kern_readlink_vp(vp, uap->buf, UIO_USERSPACE, uap->bufsize, td);
	vput(vp);
	return (error);
}

/*
 * syscall for the rpc.lockd to use to translate a NFS file handle into an
 * open descriptor.
 *
 * warning: do not remove the priv_check() call or this becomes one giant
 * security hole.
 */
#ifndef _SYS_SYSPROTO_H_
struct fhopen_args {
	const struct fhandle *u_fhp;
	int flags;
};
#endif
int
sys_fhopen(struct thread *td, struct fhopen_args *uap)
{
	return (kern_fhopen(td, uap->u_fhp, uap->flags));
}

int
kern_fhopen(struct thread *td, const struct fhandle *u_fhp, int flags)
{
	struct mount *mp;
	struct vnode *vp;
	struct fhandle fhp;
	struct file *fp;
	int error, indx;
	bool named_attr;

	error = priv_check(td, PRIV_VFS_FHOPEN);
	if (error != 0)
		return (error);

	indx = -1;
	if ((flags & O_CREAT) != 0)
		return (EINVAL);
	error = openflags(&flags);
	if (error != 0)
		return (error);
	error = copyin(u_fhp, &fhp, sizeof(fhp));
	if (error != 0)
		return (error);
	/* find the mount point */
	mp = vfs_busyfs(&fhp.fh_fsid);
	if (mp == NULL)
		return (ESTALE);
	/* now give me my vnode, it gets returned to me locked */
	error = VFS_FHTOVP(mp, &fhp.fh_fid, LK_EXCLUSIVE, &vp);
	vfs_unbusy(mp);
	if (error != 0)
		return (error);

#ifdef MAC
	error = mac_vnode_check_fh(td->td_ucred, vp);
	if (error != 0) {
		vput(vp);
		return (error);
	}
#endif
	/*
	 * Check to see if the file handle refers to a named attribute
	 * directory or attribute.  If it does, the O_NAMEDATTR flag
	 * must have been specified.
	 */
	named_attr = (vn_irflag_read(vp) &
	    (VIRF_NAMEDDIR | VIRF_NAMEDATTR)) != 0;
	if ((named_attr && (flags & O_NAMEDATTR) == 0) ||
	    (!named_attr && (flags & O_NAMEDATTR) != 0)) {
		vput(vp);
		return (ENOATTR);
	}

	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		vput(vp);
		return (error);
	}
	/* Set the flags early so the finit in devfs can pick them up. */
	fp->f_flag = flags & FMASK;

#ifdef INVARIANTS
	td->td_dupfd = -1;
#endif
	error = vn_open_vnode(vp, flags, td->td_ucred, td, fp);
	if (error != 0) {
		KASSERT(fp->f_ops == &badfileops,
		    ("VOP_OPEN in fhopen() set f_ops"));
		KASSERT(td->td_dupfd < 0,
		    ("fhopen() encountered fdopen()"));

		vput(vp);
		goto bad;
	}
#ifdef INVARIANTS
	td->td_dupfd = 0;
#endif
	finit_open(fp, vp, flags);
	VOP_UNLOCK(vp);
	if ((flags & O_TRUNC) != 0) {
		error = fo_truncate(fp, 0, td->td_ucred, td);
		if (error != 0)
			goto bad;
	}

	error = finstall(td, fp, &indx, flags, NULL);
bad:
	fdrop(fp, td);
	td->td_retval[0] = indx;
	return (error);
}

/*
 * Stat an (NFS) file handle.
 */
#ifndef _SYS_SYSPROTO_H_
struct fhstat_args {
	struct fhandle *u_fhp;
	struct stat *sb;
};
#endif
int
sys_fhstat(struct thread *td, struct fhstat_args *uap)
{
	struct stat sb;
	struct fhandle fh;
	int error;

	error = copyin(uap->u_fhp, &fh, sizeof(fh));
	if (error != 0)
		return (error);
	error = kern_fhstat(td, fh, &sb);
	if (error == 0)
		error = copyout(&sb, uap->sb, sizeof(sb));
	return (error);
}

int
kern_fhstat(struct thread *td, struct fhandle fh, struct stat *sb)
{
	struct mount *mp;
	struct vnode *vp;
	int error;

	error = priv_check(td, PRIV_VFS_FHSTAT);
	if (error != 0)
		return (error);
	if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
		return (ESTALE);
	error = VFS_FHTOVP(mp, &fh.fh_fid, LK_EXCLUSIVE, &vp);
	vfs_unbusy(mp);
	if (error != 0)
		return (error);
#ifdef MAC
	error = mac_vnode_check_fh(td->td_ucred, vp);
	if (error != 0) {
		vput(vp);
		return (error);
	}
#endif
	error = VOP_STAT(vp, sb, td->td_ucred, NOCRED);
	vput(vp);
	return (error);
}

/*
 * Implement fstatfs() for (NFS) file handles.
 */
#ifndef _SYS_SYSPROTO_H_
struct fhstatfs_args {
	struct fhandle *u_fhp;
	struct statfs *buf;
};
#endif
int
sys_fhstatfs(struct thread *td, struct fhstatfs_args *uap)
{
	struct statfs *sfp;
	fhandle_t fh;
	int error;

	error = copyin(uap->u_fhp, &fh, sizeof(fhandle_t));
	if (error != 0)
		return (error);
	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fhstatfs(td, fh, sfp);
	if (error == 0)
		error = copyout(sfp, uap->buf, sizeof(*sfp));
	free(sfp, M_STATFS);
	return (error);
}

int
kern_fhstatfs(struct thread *td, fhandle_t fh, struct statfs *buf)
{
	struct mount *mp;
	struct vnode *vp;
	int error;

	error = priv_check(td, PRIV_VFS_FHSTATFS);
	if (error != 0)
		return (error);
	if ((mp = vfs_busyfs(&fh.fh_fsid)) == NULL)
		return (ESTALE);
	error = VFS_FHTOVP(mp, &fh.fh_fid, LK_EXCLUSIVE, &vp);
	if (error != 0) {
		vfs_unbusy(mp);
		return (error);
	}
#ifdef MAC
	error = mac_vnode_check_fh(td->td_ucred, vp);
	if (error != 0) {
		vput(vp);
		vfs_unbusy(mp);
		return (error);
	}
#endif
	vput(vp);
	error = prison_canseemount(td->td_ucred, mp);
	if (error != 0)
		goto out;
#ifdef MAC
	error = mac_mount_check_stat(td->td_ucred, mp);
	if (error != 0)
		goto out;
#endif
	error = VFS_STATFS(mp, buf);
out:
	vfs_unbusy(mp);
	return (error);
}

/*
 * Unlike madvise(2), we do not make a best effort to remember every
 * possible caching hint.  Instead, we remember the last setting with
 * the exception that we will allow POSIX_FADV_NORMAL to adjust the
 * region of any current setting.
 */
static int
kern_posix_fadvise_validate(off_t offset, off_t len, int advice)
{

	if (offset < 0 || len < 0 || offset > OFF_MAX - len)
		return (EINVAL);
	switch (advice) {
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_NOREUSE:
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * Apply an already validated hint to a held file.  This lets compatibility
 * layers preserve their own descriptor/error ordering without reopening an fd
 * and racing close/reuse.  The caller retains ownership of fp.
 */
int
kern_posix_fadvise_fp(struct thread *td, struct file *fp, off_t offset,
    off_t len, int advice)
{
	int error;

	error = kern_posix_fadvise_validate(offset, len, advice);
	if (error != 0)
		return (error);
	AUDIT_ARG_FILE(td->td_proc, fp);
	if ((fp->f_ops->fo_flags & DFLAG_SEEKABLE) == 0)
		return (ESPIPE);
	return (fo_fadvise(fp, offset, len, advice, td));
}

/*
 * The fadvise(2) regions a vnode file keeps in f_advice, consulted by
 * vn_read() and vn_write(), plus VOP_ADVISE for the hints the filesystem
 * acts on itself.  Only regular files have anything to advise about.
 */
int
vn_fadvise(struct file *fp, off_t offset, off_t len, int advice,
    struct thread *td)
{
	struct fadvise_info *fa, *new;
	struct vnode *vp;
	off_t end;
	int error;

	vp = fp->f_vnode;
	if (vp->v_type != VREG)
		return (ENODEV);
	error = 0;
	switch (advice) {
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_NOREUSE:
		new = malloc(sizeof(*fa), M_FADVISE, M_WAITOK);
		break;
	default:
		new = NULL;
		break;
	}
	if (len == 0)
		end = OFF_MAX;
	else
		end = offset + len - 1;
	switch (advice) {
	case POSIX_FADV_SEQUENTIAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_NOREUSE:
		/*
		 * Try to merge any existing non-standard region with
		 * this new region if possible, otherwise create a new
		 * non-standard region for this request.
		 */
		mtx_pool_lock(mtxpool_sleep, fp);
		fa = fp->f_advice;
		if (fa != NULL && fa->fa_advice == advice &&
		    ((fa->fa_start <= end && fa->fa_end >= offset) ||
		    (end != OFF_MAX && fa->fa_start == end + 1) ||
		    (fa->fa_end != OFF_MAX && fa->fa_end + 1 == offset))) {
			if (offset < fa->fa_start)
				fa->fa_start = offset;
			if (end > fa->fa_end)
				fa->fa_end = end;
		} else {
			new->fa_advice = advice;
			new->fa_start = offset;
			new->fa_end = end;
			fp->f_advice = new;
			new = fa;
		}
		mtx_pool_unlock(mtxpool_sleep, fp);
		break;
	case POSIX_FADV_NORMAL:
		/*
		 * If the normal region overlaps with an existing
		 * non-standard region, trim or remove that region.
		 */
		mtx_pool_lock(mtxpool_sleep, fp);
		fa = fp->f_advice;
		if (fa != NULL) {
			if (offset <= fa->fa_start && end >= fa->fa_end) {
				new = fa;
				fp->f_advice = NULL;
			} else if (offset <= fa->fa_start &&
			    end >= fa->fa_start)
				fa->fa_start = end + 1;
			else if (offset <= fa->fa_end && end >= fa->fa_end)
				fa->fa_end = offset - 1;
			else if (offset >= fa->fa_start && end <= fa->fa_end) {
				new = fa;
				fp->f_advice = NULL;
			}
		}
		mtx_pool_unlock(mtxpool_sleep, fp);
		break;
	case POSIX_FADV_WILLNEED:
	case POSIX_FADV_DONTNEED:
		error = VOP_ADVISE(vp, offset, end, advice);
		break;
	}
	free(new, M_FADVISE);
	return (error);
}

int
kern_posix_fadvise(struct thread *td, int fd, off_t offset, off_t len,
    int advice)
{
	struct file *fp;
	int error;

	error = kern_posix_fadvise_validate(offset, len, advice);
	if (error != 0)
		return (error);
	AUDIT_ARG_VALUE(advice);
	AUDIT_ARG_FD(fd);
	error = fget(td, fd, &cap_posix_fadvise_rights, &fp);
	if (error != 0)
		return (error);
	error = kern_posix_fadvise_fp(td, fp, offset, len, advice);
	fdrop(fp, td);
	return (error);
}

int
sys_posix_fadvise(struct thread *td, struct posix_fadvise_args *uap)
{
	int error;

	error = kern_posix_fadvise(td, uap->fd, uap->offset, uap->len,
	    uap->advice);
	return (kern_posix_error(td, error));
}

int
kern_copy_file_range(struct thread *td, int infd, off_t *inoffp, int outfd,
    off_t *outoffp, size_t len, unsigned int flags)
{
	struct file *infp, *infp1, *outfp, *outfp1;
	int error;
	size_t retlen;
	off_t inoff, outoff, savinoff, savoutoff;
	bool foffsets_locked, foffsets_set;

	infp = outfp = NULL;
	foffsets_locked = false;
	foffsets_set = false;
	error = 0;
	retlen = 0;

	if ((flags & ~COPY_FILE_RANGE_USERFLAGS) != 0) {
		error = EINVAL;
		goto out;
	}
	if (len > SSIZE_MAX)
		/*
		 * Although the len argument is size_t, the return argument
		 * is ssize_t (which is signed).  Therefore a size that won't
		 * fit in ssize_t can't be returned.
		 */
		len = SSIZE_MAX;

	/* Get the file structures for the file descriptors. */
	error = fget_read(td, infd,
	    inoffp != NULL ? &cap_pread_rights : &cap_read_rights, &infp);
	if (error != 0)
		goto out;
	if (infp->f_ops == &badfileops) {
		error = EBADF;
		goto out;
	}
	/* A served file answers through its table; others need a vnode. */
	if (infp->f_vnode == NULL && infp->f_type != DTYPE_DQ) {
		error = EINVAL;
		goto out;
	}
	error = fget_write(td, outfd,
	    outoffp != NULL ? &cap_pwrite_rights : &cap_write_rights, &outfp);
	if (error != 0)
		goto out;
	if (outfp->f_ops == &badfileops) {
		error = EBADF;
		goto out;
	}
	if (outfp->f_vnode == NULL && outfp->f_type != DTYPE_DQ) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Figure out which file offsets we're reading from and writing to.
	 * If the offsets come from the file descriptions, we need to lock them,
	 * and locking both offsets requires a loop to avoid deadlocks.
	 */
	infp1 = outfp1 = NULL;
	if (inoffp != NULL)
		inoff = *inoffp;
	else
		infp1 = infp;
	if (outoffp != NULL)
		outoff = *outoffp;
	else
		outfp1 = outfp;
	if (infp1 != NULL || outfp1 != NULL) {
		if (infp1 == outfp1) {
			/*
			 * Overlapping ranges are not allowed.  A more thorough
			 * check appears below, but we must not lock the same
			 * offset twice.
			 */
			error = EINVAL;
			goto out;
		}
		foffset_lock_pair(infp1, &inoff, outfp1, &outoff, 0);
		foffsets_locked = true;
	} else {
		foffsets_set = true;
	}
	savinoff = inoff;
	savoutoff = outoff;

	/* Sanity check the f_flag bits. */
	if ((outfp->f_flag & (FWRITE | FAPPEND)) != FWRITE ||
	    (infp->f_flag & FREAD) == 0) {
		error = EBADF;
		goto out;
	}

	/* If len == 0, just return 0. */
	if (len == 0)
		goto out;

	/*
	 * Make sure that the ranges checked and locked below are valid.  Note
	 * that len is clamped to SSIZE_MAX above.
	 */
	if (inoff < 0 || outoff < 0) {
		error = EINVAL;
		goto out;
	}

	retlen = len;
#ifdef MAC
	error = mac_file_check_read(td->td_ucred, infp->f_cred, infp);
	if (error == 0)
		error = mac_file_check_write(td->td_ucred, outfp->f_cred,
		    outfp);
	if (error != 0)
		goto out;
#endif
	/*
	 * The descriptors answer: a type with no range copy gets the
	 * default's EINVAL, where the vnode body's own type test stood.
	 */
	error = fo_copy_file_range(infp, &inoff, outfp, &outoff, &retlen,
	    flags, td);
out:
	if ((foffsets_locked || foffsets_set) &&
	    (error == EINTR || error == ERESTART)) {
		inoff = savinoff;
		outoff = savoutoff;
	}
	if (foffsets_locked) {
		if (inoffp == NULL)
			foffset_unlock(infp, inoff, 0);
		else
			*inoffp = inoff;
		if (outoffp == NULL)
			foffset_unlock(outfp, outoff, 0);
		else
			*outoffp = outoff;
	} else if (foffsets_set) {
		*inoffp = inoff;
		*outoffp = outoff;
	}
	if (outfp != NULL)
		fdrop(outfp, td);
	if (infp != NULL)
		fdrop(infp, td);
	td->td_retval[0] = retlen;
	return (error);
}

/*
 * copy_file_range(2) between two vnode files: the same-file overlap check,
 * the byte-range locks on both vnodes, and vn_copy_file_range() inside the
 * file context.  Offsets and length are written back whatever the result,
 * as the system call then restores them on EINTR.
 */
int
vn_copy_range(struct file *infp, off_t *inoffp, struct file *outfp,
    off_t *outoffp, size_t *lenp, unsigned int flags, struct thread *td)
{
	struct vn_file_context filectx;
	struct vnode *invp, *outvp;
	void *rl_rcookie, *rl_wcookie;
	off_t inoff, outoff;
	size_t len;
	int error;

	/*
	 * The partner must be a vnode file too, or a served one, which
	 * answers through its file operations (file_generic_copy_range).
	 */
	if (outfp->f_type == DTYPE_DQ)
		return (file_generic_copy_range(infp, inoffp, outfp, outoffp,
		    lenp, flags, td));
	if (outfp->f_vnode == NULL)
		return (EINVAL);
	invp = infp->f_vnode;
	outvp = outfp->f_vnode;
	inoff = *inoffp;
	outoff = *outoffp;
	len = *lenp;

	/*
	 * If infp and outfp refer to the same file, the byte ranges cannot
	 * overlap.
	 */
	if (invp == outvp) {
		if ((inoff <= outoff && inoff + len > outoff) ||
		    (inoff > outoff && outoff + len > inoff))
			return (EINVAL);
		rangelock_may_recurse(&invp->v_rl);
	}

	/* Range lock the byte ranges for both invp and outvp. */
	for (;;) {
		rl_wcookie = vn_rangelock_wlock(outvp, outoff, outoff + len);
		rl_rcookie = vn_rangelock_tryrlock(invp, inoff, inoff + len);
		if (rl_rcookie != NULL)
			break;
		vn_rangelock_unlock(outvp, rl_wcookie);
		rl_rcookie = vn_rangelock_rlock(invp, inoff, inoff + len);
		vn_rangelock_unlock(invp, rl_rcookie);
	}

	vn_file_context_enter(&filectx, infp, outfp, 0);
	SDT_PROBE3(vfs, , , copy__range__start, (invp), (outvp), (len));
	error = vn_copy_file_range(invp, &inoff, outvp, &outoff, &len,
	    flags, infp->f_cred, outfp->f_cred, td);
	SDT_PROBE4(vfs, , , copy__range__done, (invp), (outvp), (len),
	    (error));
	vn_file_context_leave(&filectx);
	vn_rangelock_unlock(invp, rl_rcookie);
	vn_rangelock_unlock(outvp, rl_wcookie);
	*inoffp = inoff;
	*outoffp = outoff;
	*lenp = len;
	return (error);
}

/*
 * What file_generic_copy_range needs of one side: its type, its identity
 * and its I/O size.  A vnode file answers from the vnode, as
 * vn_copy_file_range reads it (v_type, the attributes, the mount's
 * f_iosize), so no stat check is added for it; a served file answers
 * fo_stat, the presented identity.
 */
struct cfr_side {
	__enum_uint8(vtype) type;
	dev_t		dev;
	ino_t		ino;
	size_t		iosize;
};

static int
cfr_side(struct file *fp, struct cfr_side *cs, struct thread *td)
{
	struct stat sb;
	struct vattr va;
	struct vnode *vp;
	int error;

	if (fp->f_type == DTYPE_VNODE) {
		vp = fp->f_vnode;
		vn_lock(vp, LK_SHARED | LK_RETRY);
		if (VN_IS_DOOMED(vp))
			error = EBADF;
		else
			error = VOP_GETATTR(vp, &va, td->td_ucred);
		if (error == 0) {
			cs->type = vp->v_type;
			cs->dev = va.va_fsid;
			cs->ino = va.va_fileid;
			cs->iosize = vp->v_mount->mnt_stat.f_iosize;
		}
		VOP_UNLOCK(vp);
		return (error);
	}
	error = fo_stat(fp, &sb, td->td_ucred);
	if (error != 0)
		return (error);
	cs->type = S_ISDIR(sb.st_mode) ? VDIR : S_ISREG(sb.st_mode) ? VREG :
	    VNON;
	cs->dev = sb.st_dev;
	cs->ino = sb.st_ino;
	cs->iosize = (size_t)MAX(sb.st_blksize, 0);
	return (0);
}

/*
 * copy_file_range(2) with a side that is not a vnode file: a served
 * (DTYPE_DQ) file, which answers through fo_read and fo_write.  The
 * checks are vn_copy_range's and vn_copy_file_range's, in their order:
 * overlapping ranges of one identity (st_dev, st_ino; a served file's is
 * the presented one) are EINVAL, a directory is EISDIR, anything else
 * that is not a regular file EINVAL, and COPY_FILE_RANGE_CLONE
 * EOPNOTSUPP as vn_generic_copy_file_range answers it.  As that function
 * does before its first read, the count is clipped at RLIMIT_FSIZE on the
 * output; an output offset already at or past the limit is EFBIG with
 * SIGXFSZ before anything is read.  The copy is that function's loop
 * without hole detection: a read of at most one buffer at *inoffp, then a
 * write of what it returned at *outoffp.  Zeros are written as data, so
 * the copy makes no holes in the output, and the output is never
 * truncated or extended past the last byte written.  A short read is the
 * end of the input; a short write (a full file system, a supervisor's
 * short count) ends the copy; a write that fails copies nothing of its
 * buffer, as vn_write_outvp's failed block, so the offsets and the count
 * cover the buffers written before it; a signal after some bytes were
 * copied ends the copy with the count copied.  Unlike vn_copy_range, no
 * range lock covers both files for the whole copy: each read and each
 * write holds its own file's range lock (fileops.9).  Offsets and the
 * count are written back whatever the result, as vn_copy_range writes
 * them.
 */
int
file_generic_copy_range(struct file *infp, off_t *inoffp, struct file *outfp,
    off_t *outoffp, size_t *lenp, unsigned int flags, struct thread *td)
{
	struct cfr_side in, out;
	struct timespec curts, endts;
	struct uio auio;
	struct iovec aiov;
	char *dat;
	off_t inoff, outoff;
	size_t blksize, got, len, savlen, wrote, xfer;
	ssize_t resid;
	uint64_t uval;
	int error, interrupted;

	inoff = *inoffp;
	outoff = *outoffp;
	len = savlen = *lenp;
	dat = NULL;

	error = cfr_side(infp, &in, td);
	if (error == 0)
		error = cfr_side(outfp, &out, td);
	if (error != 0)
		goto out;
	/* vn_copy_range: one file's byte ranges may not overlap. */
	if (in.dev == out.dev && in.ino == out.ino &&
	    ((inoff <= outoff && inoff + len > outoff) ||
	    (inoff > outoff && outoff + len > inoff))) {
		error = EINVAL;
		goto out;
	}
	/* vn_copy_file_range's argument checks. */
	if (in.type == VDIR || out.type == VDIR) {
		error = EISDIR;
		goto out;
	}
	if (inoff < 0 || outoff < 0 || in.type != VREG || out.type != VREG) {
		error = EINVAL;
		goto out;
	}
	/* Ensure offset + len does not wrap around. */
	uval = inoff;
	uval += len;
	if (uval > INT64_MAX)
		len = INT64_MAX - inoff;
	uval = outoff;
	uval += len;
	if (uval > INT64_MAX)
		len = INT64_MAX - outoff;
	savlen = len;
	if (len == 0)
		goto out;
	if ((flags & COPY_FILE_RANGE_CLONE) != 0) {
		error = EOPNOTSUPP;
		goto out;
	}
	/*
	 * vn_generic_copy_file_range's vn_rlimit_fsizex, before the first
	 * read: the count stops at the limit, so no buffer's write meets it;
	 * an output offset at or past it is EFBIG and SIGXFSZ.
	 * kern_copy_file_range clamped len to SSIZE_MAX.
	 */
	resid = (ssize_t)len;
	error = rlimit_fsize_check(outoff, &resid, 0, true, td);
	if (error != 0)
		goto out;
	len = savlen = (size_t)resid;

	/* The larger I/O size of the two, clipped as the vnode copy clips. */
	blksize = MAX(in.iosize, out.iosize);
	if (blksize < 4096)
		blksize = 4096;
	else if (blksize > maxphys)
		blksize = maxphys;
	dat = malloc(blksize, M_TEMP, M_WAITOK);
	if ((flags & COPY_FILE_RANGE_TIMEO1SEC) != 0) {
		getnanouptime(&endts);
		endts.tv_sec++;
	} else
		timespecclear(&endts);

	interrupted = 0;
	while (len > 0 && interrupted == 0) {
		xfer = MIN(len, blksize);
		aiov.iov_base = dat;
		aiov.iov_len = xfer;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = inoff;
		auio.uio_resid = xfer;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_READ;
		auio.uio_td = td;
		error = fo_read(infp, &auio, td->td_ucred, FOF_OFFSET, td);
		if (error != 0)
			break;
		got = xfer - auio.uio_resid;
		if (got == 0)
			break;		/* the end of the input */

		aiov.iov_base = dat;
		aiov.iov_len = got;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = outoff;
		auio.uio_resid = got;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_td = td;
		if (outfp->f_type == DTYPE_VNODE)
			bwillwrite();	/* as dofilewrite */
		error = fo_write(outfp, &auio, td->td_ucred, FOF_OFFSET, td);
		if (error != 0)
			break;		/* vn_write_outvp: none of it counts */
		wrote = got - auio.uio_resid;
		inoff += wrote;
		outoff += wrote;
		len -= wrote;
		if (wrote < got || got < xfer)
			break;
		interrupted = sig_intr();
		if (timespecisset(&endts) && interrupted == 0) {
			getnanouptime(&curts);
			if (timespeccmp(&curts, &endts, >=))
				interrupted = EINTR;
		}
	}
out:
	free(dat, M_TEMP);
	*inoffp = inoff;
	*outoffp = outoff;
	*lenp = savlen - len;
	return (error);
}

int
sys_copy_file_range(struct thread *td, struct copy_file_range_args *uap)
{
	off_t inoff, outoff, *inoffp, *outoffp;
	int error;

	inoffp = outoffp = NULL;
	if (uap->inoffp != NULL) {
		error = copyin(uap->inoffp, &inoff, sizeof(off_t));
		if (error != 0)
			return (error);
		inoffp = &inoff;
	}
	if (uap->outoffp != NULL) {
		error = copyin(uap->outoffp, &outoff, sizeof(off_t));
		if (error != 0)
			return (error);
		outoffp = &outoff;
	}
	error = kern_copy_file_range(td, uap->infd, inoffp, uap->outfd,
	    outoffp, uap->len, uap->flags);
	if (error == 0 && uap->inoffp != NULL)
		error = copyout(inoffp, uap->inoffp, sizeof(off_t));
	if (error == 0 && uap->outoffp != NULL)
		error = copyout(outoffp, uap->outoffp, sizeof(off_t));
	return (error);
}

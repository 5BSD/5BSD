/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2007-2009 Google Inc. and Amit Singh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of Google Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (C) 2005 Csaba Henk.
 * All rights reserved.
 *
 * Copyright (c) 2019 The FreeBSD Foundation
 *
 * Portions of this software were developed by BFF Storage Systems, LLC under
 * sponsorship from the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/aio.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/sdt.h>
#include <sys/file.h>
#include <sys/sysctl.h>

#include <crypto/siphash/siphash.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_io.h"
#include "fuse_ipc.h"
#include "fuse_node.h"

MALLOC_DEFINE(M_FUSE_FILEHANDLE, "fuse_filefilehandle", "FUSE file handle");

SDT_PROVIDER_DECLARE(fusefs);
/* 
 * Fuse trace probe:
 * arg0: verbosity.  Higher numbers give more verbose messages
 * arg1: Textual message
 */
SDT_PROBE_DEFINE2(fusefs, , file, trace, "int", "char*");

static counter_u64_t fuse_fh_count;

SYSCTL_COUNTER_U64(_vfs_fusefs_stats, OID_AUTO, filehandle_count, CTLFLAG_RD,
    &fuse_fh_count, "number of open FUSE filehandles");

/* Keep protocol headers and handle selection on the same AIO identity. */
pid_t
fuse_thread_pid(struct thread *td)
{

	if (td == NULL || td == curthread)
		return (aio_issuer_pid());
	return (td->td_proc->p_pid);
}

/* Get the FUFH type for a particular access mode */
static inline fufh_type_t
fflags_2_fufh_type(int fflags)
{
	if ((fflags & FREAD) && (fflags & FWRITE))
		return FUFH_RDWR;
	else if (fflags & (FWRITE))
		return FUFH_WRONLY;
	else if (fflags & (FREAD))
		return FUFH_RDONLY;
	else if (fflags & (FEXEC))
		return FUFH_EXEC;
	else
		panic("FUSE: What kind of a flag is this (%x)?", fflags);
}

int
fuse_filehandle_xflags(struct mount *mp, fufh_type_t type)
{

	/* Linux has no O_EXEC; executable handles are read-only on the wire. */
	if (fuse_get_mpdata(mp)->linux_errnos && type == FUFH_EXEC)
		return (O_RDONLY);
	return (fufh_type_2_fflags(type));
}

/* The complete set of status flags meaningful to a Linux FUSE daemon. */
uint32_t
fuse_filehandle_openflags(struct mount *mp, int mode)
{
	uint32_t flags;

	flags = fuse_filehandle_xflags(mp, fflags_2_fufh_type(mode));
	if (!fuse_get_mpdata(mp)->linux_errnos)
		return (flags);
	/* Linux64 opens support large files, including native clients. */
	flags |= 00100000;
	if (mode & O_DIRECTORY)
		flags |= 00200000;
	if (mode & O_NOFOLLOW)
		flags |= 00400000;
	if (mode & O_APPEND)
		flags |= 00002000;
	if (mode & O_NONBLOCK)
		flags |= 00004000;
	if (mode & O_ASYNC)
		flags |= 00020000;
	if (mode & O_DIRECT)
		flags |= 00040000;
	if (mode & O_DSYNC)
		flags |= 00010000;
	if (mode & O_SYNC)
		flags |= 04010000;
	return (flags);
}

uint32_t
fuse_filehandle_wireflags(struct vnode *vp, struct fuse_filehandle *fh)
{
	if (fh->fp == NULL)
		return (fuse_filehandle_xflags(vnode_mount(vp), fh->fufh_type));
	return (fuse_filehandle_openflags(vnode_mount(vp),
	    fh->opened ? (fh->open_mode & ~FMASK) |
	    (fh->fp->f_flag & FMASK) : fh->open_mode));
}

struct fuse_filehandle *
fuse_filehandle_for_file(struct vnode *vp, struct file *fp)
{
	struct fuse_filehandle *fh;

	if (fp == NULL)
		return (NULL);
	LIST_FOREACH(fh, &VTOFUD(vp)->handles, next)
		if (fh->fp == fp)
			return (fh);
	return (NULL);
}

struct file *
fuse_filehandle_context(struct vnode *vp, int mode)
{
	struct vn_file_context *ctx = vn_file_context_current();
	struct file *fp;

	if (ctx == NULL)
		return (NULL);
	fp = mode == FWRITE && ctx->fp2 != NULL ? ctx->fp2 : ctx->fp;
	return (fuse_filehandle_for_file(vp, fp) != NULL ? fp : NULL);
}

int
fuse_filehandle_open(struct vnode *vp, int mode, struct fuse_filehandle **fh,
    struct thread *td, struct ucred *cred)
{
	return (fuse_filehandle_open_file(vp, mode, fh, td, cred, NULL));
}

int
fuse_filehandle_open_file(struct vnode *vp, int a_mode,
    struct fuse_filehandle **fufhp, struct thread *td, struct ucred *cred,
    struct file *fp)
{
	struct mount *mp = vnode_mount(vp);
	struct fuse_dispatcher fdi;
	const struct fuse_open_out default_foo = {
		.fh = 0,
		.open_flags = FOPEN_KEEP_CACHE,
		.padding = 0
	};
	struct fuse_open_in *foi = NULL;
	const struct fuse_open_out *foo;
	fufh_type_t fufh_type;
	int err = 0;
	int oflags = 0;
	int op = FUSE_OPEN;
	int relop = FUSE_RELEASE;

	fufh_type = fflags_2_fufh_type(a_mode);
	oflags = fp != NULL ? fuse_filehandle_openflags(mp, a_mode) :
	    fuse_filehandle_xflags(mp, fufh_type);

	if (vnode_isdir(vp)) {
		op = FUSE_OPENDIR;
		relop = FUSE_RELEASEDIR;
		/* vn_open_vnode already rejects FWRITE on directories */
		MPASS(fufh_type == FUFH_RDONLY || fufh_type == FUFH_EXEC);
	}
	fdisp_init(&fdi, sizeof(*foi));
	if (fsess_not_impl(mp, op)) {
		/* The operation implicitly succeeds */
		foo = &default_foo;
	} else {
		fdisp_make_vp(&fdi, op, vp, td, cred);

		foi = fdi.indata;
		foi->flags = oflags;

		err = fdisp_wait_answ(&fdi);
		if (err == ENOSYS) {
			/* The operation implicitly succeeds */
			foo = &default_foo;
			fsess_set_notimpl(mp, op);
			fsess_set_notimpl(mp, relop);
			err = 0;
		} else if (err) {
			SDT_PROBE2(fusefs, , file, trace, 1,
				"OUCH ... daemon didn't give fh");
			if (err == ENOENT)
				fuse_internal_vnode_disappear(vp);
			goto out;
		} else {
			foo = fdi.answ;
			fsess_set_impl(mp, op);
		}
	}

	fuse_filehandle_init(vp, fufh_type, fufhp, td, cred, foo, fp, a_mode);
	fuse_vnode_open(vp, foo->open_flags, td);

out:
	if (foi)
		fdisp_destroy(&fdi);
	return err;
}

/* RELEASE replies carry no data, and their errors cannot undo final close. */
static int
fuse_filehandle_release_callback(struct fuse_ticket *tick __unused,
    struct uio *uio __unused)
{

	return (0);
}

int
fuse_filehandle_close(struct vnode *vp, struct fuse_filehandle *fufh,
    struct thread *td, struct ucred *cred)
{
	struct mount *mp = vnode_mount(vp);
	struct fuse_dispatcher fdi;
	struct fuse_release_in *fri;

	int err = 0;
	int op = FUSE_RELEASE;

	ASSERT_VOP_ELOCKED(vp, __func__);

	if (fuse_isdeadfs(vp)) {
		goto out;
	}
	if (vnode_isdir(vp))
		op = FUSE_RELEASEDIR;

	if (fsess_not_impl(mp, op))
		goto out;

	fdisp_init(&fdi, sizeof(*fri));
	fdisp_make_vp(&fdi, op, vp, td, cred);
	fri = fdi.indata;
	fri->fh = fufh->fh_id;
	fri->flags = fuse_filehandle_wireflags(vp, fufh);
	/* 
	 * If the file has a POSIX lock then we're supposed to set lock_owner.
	 * If not, then lock_owner is undefined.  So we may as well always set
	 * it.
	 */
	fri->lock_owner = fuse_thread_pid(td);
	if (fufh->fp != NULL && fufh->flocked) {
		fri->release_flags |= FUSE_RELEASE_FLOCK_UNLOCK;
		fri->lock_owner = fuse_file_lock_owner(fufh->fp);
	}

	if (fufh->fp != NULL) {
		/* Final fdrop may run in the daemon itself or a pager worker. */
		fuse_insert_callback(fdi.tick, fuse_filehandle_release_callback);
		fuse_insert_message(fdi.tick, false);
	} else {
		err = fdisp_wait_answ(&fdi);
	}
	fdisp_destroy(&fdi);

out:
	counter_u64_add(fuse_fh_count, -1);
	LIST_REMOVE(fufh, next);
	free(fufh, M_FUSE_FILEHANDLE);

	return err;
}

/*
 * Check for a valid file handle, first the type requested, but if that
 * isn't valid, try for FUFH_RDWR.
 * Return true if there is any file handle with the correct credentials and
 * a fufh type that includes the provided one.
 * A pid of 0 means "don't care"
 */
bool
fuse_filehandle_validrw(struct vnode *vp, int mode,
	struct ucred *cred, pid_t pid)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh;
	fufh_type_t fufh_type = fflags_2_fufh_type(mode);

	/* 
	 * Unlike fuse_filehandle_get, we want to search for a filehandle with
	 * the exact cred, and no fallback
	 */
	LIST_FOREACH(fufh, &fvdat->handles, next) {
		if (fufh->fufh_type == fufh_type &&
		    fufh->uid == cred->cr_uid &&
		    fufh->gid == cred->cr_rgid &&
		    (pid == 0 || fufh->pid == pid))
			return true;
	}

	if (fufh_type == FUFH_EXEC)
		return false;

	/* Fallback: find a RDWR list entry with the right cred */
	LIST_FOREACH(fufh, &fvdat->handles, next) {
		if (fufh->fufh_type == FUFH_RDWR &&
		    fufh->uid == cred->cr_uid &&
		    fufh->gid == cred->cr_rgid &&
		    (pid == 0 || fufh->pid == pid))
			return true;
	}

	return false;
}

int
fuse_filehandle_get(struct vnode *vp, int fflag,
    struct fuse_filehandle **fufhp, struct ucred *cred, pid_t pid)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh;
	fufh_type_t fufh_type;

	fufh = fuse_filehandle_for_file(vp, fuse_filehandle_context(vp, fflag));
	if (fufh != NULL &&
	    ((fflag & FWRITE) == 0 || fufh->fufh_type == FUFH_WRONLY ||
	    fufh->fufh_type == FUFH_RDWR) &&
	    ((fflag & FREAD) == 0 || fufh->fufh_type != FUFH_WRONLY ||
	    fsess_opt_writeback(vnode_mount(vp))))
		goto found;

	fufh_type = fflags_2_fufh_type(fflag);
	/* cred can be NULL for in-kernel clients */
	if (cred == NULL)
		goto fallback;

	LIST_FOREACH(fufh, &fvdat->handles, next) {
		if (fufh->fufh_type == fufh_type &&
		    fufh->uid == cred->cr_uid &&
		    fufh->gid == cred->cr_rgid &&
		    (pid == 0 || fufh->pid == pid))
			goto found;
	}

fallback:
	/* Fallback: find a list entry with the right flags */
	LIST_FOREACH(fufh, &fvdat->handles, next) {
		if (fufh->fufh_type == fufh_type)
			break;
	}

	if (fufh == NULL)
		return EBADF;

found:
	if (fufhp != NULL)
		*fufhp = fufh;
	return 0;
}

/* Get a file handle with any kind of flags */
int
fuse_filehandle_get_anyflags(struct vnode *vp,
    struct fuse_filehandle **fufhp, struct ucred *cred, pid_t pid)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh;

	fufh = fuse_filehandle_for_file(vp, fuse_filehandle_context(vp, 0));
	if (fufh != NULL)
		goto found;

	if (cred == NULL)
		goto fallback;

	LIST_FOREACH(fufh, &fvdat->handles, next) {
		if (fufh->uid == cred->cr_uid &&
		    fufh->gid == cred->cr_rgid &&
		    (pid == 0 || fufh->pid == pid))
			goto found;
	}

fallback:
	/* Fallback: find any list entry */
	fufh = LIST_FIRST(&fvdat->handles);

	if (fufh == NULL)
		return EBADF;

found:
	if (fufhp != NULL)
		*fufhp = fufh;
	return 0;
}

int
fuse_filehandle_getrw(struct vnode *vp, int fflag,
    struct fuse_filehandle **fufhp, struct ucred *cred, pid_t pid)
{
	int err;

	err = fuse_filehandle_get(vp, fflag, fufhp, cred, pid);
	if (err)
		err = fuse_filehandle_get(vp, FREAD | FWRITE, fufhp, cred, pid);
	return err;
}

void
fuse_filehandle_init(struct vnode *vp, fufh_type_t fufh_type,
    struct fuse_filehandle **fufhp, struct thread *td, const struct ucred *cred,
    const struct fuse_open_out *foo, struct file *fp, int mode)
{
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh;

	fufh = malloc(sizeof(struct fuse_filehandle), M_FUSE_FILEHANDLE,
		M_WAITOK);
	MPASS(fufh != NULL);
	fufh->fp = fp;
	fufh->open_mode = mode;
	fufh->opened = false;
	fufh->flocked = false;
	fufh->fh_id = foo->fh;
	fufh->fufh_type = fufh_type;
	fufh->gid = cred->cr_rgid;
	fufh->uid = cred->cr_uid;
	fufh->pid = fuse_thread_pid(td);
	fufh->fuse_open_flags = foo->open_flags;
	if (!FUFH_IS_VALID(fufh)) {
		panic("FUSE: init: invalid filehandle id (type=%d)", fufh_type);
	}
	LIST_INSERT_HEAD(&fvdat->handles, fufh, next);
	if (fufhp != NULL)
		*fufhp = fufh;

	counter_u64_add(fuse_fh_count, 1);

	if (foo->open_flags & FOPEN_DIRECT_IO) {
		ASSERT_VOP_ELOCKED(vp, __func__);
		if (fp == NULL)
			VTOFUD(vp)->flag |= FN_DIRECTIO;
		fuse_io_invalbuf(vp, td);
	} else {
		if ((foo->open_flags & FOPEN_KEEP_CACHE) == 0)
			fuse_io_invalbuf(vp, td);
		/*
		 * XXX Update the flag without the lock for now.  See
		 * https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=293088
		 */
		if (fp == NULL)
			VTOFUD(vp)->flag &= ~FN_DIRECTIO;
	}

}

static uint8_t fuse_lock_owner_key[SIPHASH_KEY_LENGTH];

/* Stable for dup/fork, distinct for independent opens, no pointer disclosure. */
uint64_t
fuse_file_lock_owner(void *id)
{
	SIPHASH_CTX ctx;

	return (SipHashX(&ctx, 2, 4, fuse_lock_owner_key, &id, sizeof(id)));
}

void
fuse_file_init(void)
{
	arc4random_buf(fuse_lock_owner_key, sizeof(fuse_lock_owner_key));
	fuse_fh_count = counter_u64_alloc(M_WAITOK);
}

void
fuse_file_destroy(void)
{
	counter_u64_free(fuse_fh_count);
}

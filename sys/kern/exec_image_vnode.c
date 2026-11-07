/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1993, David Greenman
 * All rights reserved.
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
 * The vnode image source: the exec core reaches the file it is activating
 * only through imgp->is_ops, and every vnode operation that do_execve()
 * and the ELF activator used to perform inline lives here, in the order
 * they performed it.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cap_authority.h>
#include <sys/dirent.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/imgact.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

/*
 * The backend's private state, imgp->is_data.  The fname form keeps the
 * nameidata for NDFREE_PNBUF, the parent directory and the hardlink name
 * that become p_textdvp and p_binname.
 */
struct exec_image_vnode {
	struct nameidata eiv_nd;	/* the lookup (fname form) */
	struct vnode	*eiv_dvp;	/* parent, or NULL */
	char		*eiv_binname;	/* M_PARGS copy of cn_nameptr, or NULL */
	size_t		eiv_binnamelen;	/* cn_namelen */
	bool		eiv_fname;	/* constructed from args->fname */
};

static const struct image_source_ops exec_image_vnode_ops;

static struct exec_image_vnode *
exec_image_vnode_data(const struct image_params *imgp)
{
	MPASS(imgp->is_ops == &exec_image_vnode_ops);
	return (imgp->is_data);
}

static void
exec_image_vnode_setup(struct image_params *imgp, struct vnode *vp,
    bool fname)
{
	struct exec_image_vnode *eiv;

	MPASS(imgp->is_ops == NULL && imgp->is_data == NULL);
	eiv = malloc(sizeof(*eiv), M_TEMP, M_WAITOK | M_ZERO);
	eiv->eiv_fname = fname;
	imgp->is_data = eiv;
	imgp->is_ops = &exec_image_vnode_ops;
	imgp->vp = vp;
}

/*
 * The args->fname form: namei() has returned the image locked shared with
 * its parent (WANTPARENT) and the last component.  The parent and the name
 * are what p_textdvp and p_binname become.
 */
void
exec_image_vnode_from_namei(struct image_params *imgp, struct nameidata *nd)
{
	struct exec_image_vnode *eiv;
	struct vnode *vp;

	vp = nd->ni_vp;
	exec_image_vnode_setup(imgp, vp, true);
	eiv = imgp->is_data;
	eiv->eiv_nd = *nd;
	eiv->eiv_dvp = nd->ni_dvp;
	eiv->eiv_nd.ni_dvp = NULL;
	eiv->eiv_binnamelen = nd->ni_cnd.cn_namelen;
	eiv->eiv_binname = malloc(nd->ni_cnd.cn_namelen + 1, M_PARGS,
	    M_WAITOK);
	memcpy(eiv->eiv_binname, nd->ni_cnd.cn_nameptr, nd->ni_cnd.cn_namelen);
	eiv->eiv_binname[nd->ni_cnd.cn_namelen] = '\0';

	if (atomic_load_8(&eiv->eiv_dvp->v_type) != VDIR) {
		struct vnode *dvp1;
		char *buf1;
		size_t buf1len;

		/*
		 * The parent vnode might be not a directory when
		 * reclaimed or when the image is mounted over a regular
		 * file.  In the latter case, try to resolve the
		 * containing directory.
		 *
		 * In any case, p_textdvp must be either a directory or
		 * reclaimed.
		 */
		VOP_UNLOCK(vp);
		dvp1 = eiv->eiv_dvp;
		buf1len = MAXNAMLEN + 1;
		buf1 = malloc(buf1len, M_TEMP, M_WAITOK);
		if (vn_vptocnp(&dvp1, buf1, &buf1len) == 0) {
			if (atomic_load_8(&dvp1->v_type) == VDIR) {
				eiv->eiv_dvp = dvp1;
			} else {
				vrele(dvp1);
				eiv->eiv_dvp = NULL;
			}
		} else {
			eiv->eiv_dvp = NULL;
		}
		free(buf1, M_TEMP);
		vn_lock(vp, LK_SHARED | LK_RETRY);
	}
}

/*
 * The interpreter-vnode (binmisc) and fexecve forms: the vnode is
 * referenced and unlocked.  Resolve its path, lock it and audit it, as
 * do_execve() did for both.
 */
void
exec_image_vnode_from_vnode(struct image_params *imgp, struct vnode *vp)
{

	exec_image_vnode_setup(imgp, vp, false);
	if (vn_fullpath(vp, &imgp->execpath, &imgp->freepath) != 0)
		imgp->execpath = imgp->args->fname;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	AUDIT_ARG_VNODE1(vp);
}

/*
 * The ELF interpreter loader's form: its own kernel-origin namei() has
 * returned the vnode locked shared; the reference is never installed.
 */
void
exec_image_vnode_init(struct image_params *imgp, struct vnode *vp)
{

	exec_image_vnode_setup(imgp, vp, false);
}

static void
exec_image_vnode_lock(const struct image_params *imgp)
{

	vn_lock(imgp->vp, LK_SHARED | LK_RETRY);
}

static void
exec_image_vnode_unlock(const struct image_params *imgp)
{

	VOP_UNLOCK(imgp->vp);
}

static void
exec_image_vnode_assert_locked(const struct image_params *imgp,
    const char *msg)
{

	ASSERT_VOP_LOCKED(imgp->vp, msg);
}

/*
 * Check permissions of file to execute.
 *	Called with imgp->vp locked.
 *	Return 0 for success or error code on failure.
 *
 * Exported: __elfN(load_interp_file) and veriexec rely on it by name.
 */
int
exec_check_permissions(struct image_params *imgp)
{
	struct vnode *vp = imgp->vp;
	struct vattr *attr = imgp->attr;
	struct thread *td;
	int error;

	td = curthread;

	/* Get file attributes */
	error = VOP_GETATTR(vp, attr, td->td_ucred);
	if (error)
		return (error);

#ifdef MAC
	error = mac_vnode_check_exec(td->td_ucred, imgp->vp, imgp);
	if (error)
		return (error);
#endif

	/*
	 * 1) Check if file execution is disabled for the filesystem that
	 *    this file resides on.
	 * 2) Ensure that at least one execute bit is on. Otherwise, a
	 *    privileged user will always succeed, and we don't want this
	 *    to happen unless the file really is executable.
	 * 3) Ensure that the file is a regular file.
	 */
	if ((vp->v_mount->mnt_flag & MNT_NOEXEC) ||
	    (attr->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 ||
	    (attr->va_type != VREG))
		return (EACCES);

	/*
	 * Zero length files can't be exec'd
	 */
	if (attr->va_size == 0)
		return (ENOEXEC);

	/*
	 *  Check for execute permission to file based on current credentials.
	 */
	error = VOP_ACCESS(vp, VEXEC, td->td_ucred, td);
	if (error)
		return (error);

	/*
	 * Check number of open-for-writes on the file and deny execution
	 * if there are any.
	 *
	 * Add a text reference now so no one can write to the
	 * executable while we're activating it.
	 *
	 * Remember if this was set before and unset it in case this is not
	 * actually an executable image.
	 */
	error = VOP_SET_TEXT(vp);
	if (error != 0)
		return (error);
	imgp->textset = true;

	/*
	 * Call filesystem specific open routine (which does nothing in the
	 * general case).
	 */
	error = VOP_OPEN(vp, FREAD, td->td_ucred, td, NULL);
	if (error == 0)
		imgp->opened = true;
	return (error);
}

static int
exec_image_vnode_first_page(struct image_params *imgp)
{

	imgp->object = imgp->vp->v_object;
	if (imgp->object != NULL)
		vm_object_reference(imgp->object);

	return (exec_map_first_page(imgp));
}

static int
exec_image_vnode_read(const struct image_params *imgp, void *buf, size_t len,
    off_t off)
{

	return (vn_rdwr(UIO_READ, imgp->vp, buf, len, off, UIO_SYSSPACE,
	    IO_NODELOCKED, imgp->td->td_ucred, NOCRED, NULL, imgp->td));
}

static int
exec_image_vnode_map_cow(const struct image_params *imgp)
{

	return (MAP_VN_EXEC);
}

static void
exec_image_vnode_map_text(const struct image_params *imgp, vm_object_t object)
{

	MPASS(imgp->vp->v_object == object);
	VOP_SET_TEXT_CHECKED(imgp->vp);
}

static void
exec_image_vnode_unset_text(struct image_params *imgp)
{

	if (imgp->textset) {
		VOP_UNSET_TEXT_CHECKED(imgp->vp);
		imgp->textset = false;
	}
}

/*
 * The fname form resolves through the parent and the hardlink name, with
 * the image unlocked around the lookup as do_execve() did; without a
 * parent it leaves the path alone.  The other forms resolved their path
 * at construction, before the vnode was locked, and never come here:
 * vn_fullpath() on the locked image would relock it on a namecache miss.
 */
static int
exec_image_vnode_path(struct image_params *imgp, char **retbuf,
    char **freebuf)
{
	struct exec_image_vnode *eiv;
	size_t freepath_size;
	int error;

	eiv = exec_image_vnode_data(imgp);
	MPASS(eiv->eiv_fname);
	if (eiv->eiv_dvp == NULL)
		return (0);
	VOP_UNLOCK(imgp->vp);
	freepath_size = MAXPATHLEN;
	error = vn_fullpath_hardlink(imgp->vp, eiv->eiv_dvp, eiv->eiv_binname,
	    eiv->eiv_binnamelen, retbuf, freebuf, &freepath_size);
	vn_lock(imgp->vp, LK_SHARED | LK_RETRY);
	return (error);
}

static int
exec_image_vnode_commname(struct image_params *imgp, char *buf, size_t len)
{
	struct exec_image_vnode *eiv;

	eiv = exec_image_vnode_data(imgp);
	if (eiv->eiv_fname) {
		bcopy(eiv->eiv_binname, buf, min(eiv->eiv_binnamelen,
		    MAXCOMLEN));
		return (0);
	}
	return (vn_commname(imgp->vp, buf, len));
}

static bool
exec_image_vnode_nosuid(struct image_params *imgp)
{

	return ((imgp->vp->v_mount->mnt_flag & MNT_NOSUID) != 0);
}

static int
exec_image_vnode_mac(struct image_params *imgp, int phase,
    struct ucred *oldcred, struct ucred *newcred)
{
#ifdef MAC
	switch (phase) {
	case IS_MAC_WILL_TRANSITION:
		return (mac_vnode_execve_will_transition(oldcred, imgp->vp,
		    imgp->interpvplabel, imgp));
	case IS_MAC_WILL_RELABEL:
		return (mac_vnode_execve_will_relabel(oldcred, imgp->vp,
		    imgp->interpvplabel, imgp));
	case IS_MAC_TRANSITION:
		mac_vnode_execve_transition(oldcred, newcred, imgp->vp,
		    imgp->interpvplabel, imgp);
		return (0);
	case IS_MAC_RELABEL:
		mac_vnode_execve_relabel(oldcred, newcred, imgp->vp,
		    imgp->interpvplabel, imgp);
		return (0);
	case IS_MAC_INTERP_ENTER:
		mac_execve_interpreter_enter(imgp->vp, &imgp->interpvplabel);
		return (0);
	default:
		panic("%s: phase %d", __func__, phase);
	}
#else
	return (0);
#endif
}

static struct cap_authority *
exec_image_vnode_authority_prepare(struct image_params *imgp, struct proc *p)
{

	if ((imgp->vp->v_mount->mnt_flag & MNT_NOSUID) == 0)
		return (cap_authority_exec_prepare(p, imgp->vp));
	return (NULL);
}

static void
exec_image_vnode_authority_exec(struct image_params *imgp, struct proc *p,
    struct cap_authority *selected)
{

	cap_authority_exec(p, imgp->vp, selected);
}

/*
 * Store the vp for use in kern.proc.pathname.  This vnode was
 * referenced by namei() or by fexecve variant of fname handling.
 */
static void
exec_image_vnode_install(struct image_params *imgp, struct proc *p,
    struct image_source_old *old)
{
	struct exec_image_vnode *eiv;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	eiv = exec_image_vnode_data(imgp);
	old->iso_textvp = p->p_textvp;
	p->p_textvp = imgp->vp;
	old->iso_textdvp = p->p_textdvp;
	p->p_textdvp = eiv->eiv_dvp;
	eiv->eiv_dvp = NULL;
	old->iso_binname = p->p_binname;
	p->p_binname = eiv->eiv_binname;
	eiv->eiv_binname = NULL;
	/* Whatever image this one displaces, its state goes with the old. */
	old->iso_fp = p->p_image.pi_fp;
	old->iso_path = p->p_image.pi_path;
	p->p_image.pi_kind = PI_KIND_VNODE;
	p->p_image.pi_fp = NULL;
	p->p_image.pi_path = NULL;
}

/*
 * Handle deferred decrement of ref counts.
 */
static void
exec_image_vnode_release_old(struct image_params *imgp,
    struct image_source_old *old)
{

	if (old->iso_textvp != NULL)
		vrele(old->iso_textvp);
	if (old->iso_textdvp != NULL)
		vrele(old->iso_textdvp);
	free(old->iso_binname, M_PARGS);
	if (old->iso_fp != NULL)
		fdrop(old->iso_fp, curthread);
	free(old->iso_path, M_PARGS);
}

static void
exec_image_vnode_accessed(struct image_params *imgp)
{

	VOP_UPDATE_ATIME(imgp->vp, NULL);
}

/*
 * Close the image.  When the reference is to be released (an error, or an
 * image that was never installed) it is dropped with the lock; otherwise
 * the reference now belongs to p_textvp and only the lock goes.
 */
static void
exec_image_vnode_close(struct image_params *imgp, bool release)
{
	struct exec_image_vnode *eiv;
	struct thread *td;

	eiv = exec_image_vnode_data(imgp);
	td = imgp->td;
	if (imgp->opened) {
		VOP_CLOSE(imgp->vp, FREAD, td->td_ucred, td);
		imgp->opened = false;
	}
	if (imgp->textset) {
		VOP_UNSET_TEXT_CHECKED(imgp->vp);
		imgp->textset = false;
	}
	if (release)
		vput(imgp->vp);
	else
		VOP_UNLOCK(imgp->vp);
	if (eiv->eiv_fname)
		NDFREE_PNBUF(&eiv->eiv_nd);
	if (eiv->eiv_dvp != NULL)
		vrele(eiv->eiv_dvp);
	free(eiv->eiv_binname, M_PARGS);
	free(eiv, M_TEMP);
	imgp->is_data = NULL;
	imgp->is_ops = NULL;
	imgp->vp = NULL;
}

static const struct image_source_ops exec_image_vnode_ops = {
	.is_lock = exec_image_vnode_lock,
	.is_unlock = exec_image_vnode_unlock,
	.is_assert_locked = exec_image_vnode_assert_locked,
	.is_check = exec_check_permissions,
	.is_first_page = exec_image_vnode_first_page,
	.is_read = exec_image_vnode_read,
	.is_map_cow = exec_image_vnode_map_cow,
	.is_map_text = exec_image_vnode_map_text,
	.is_unset_text = exec_image_vnode_unset_text,
	.is_path = exec_image_vnode_path,
	.is_commname = exec_image_vnode_commname,
	.is_nosuid = exec_image_vnode_nosuid,
	.is_mac = exec_image_vnode_mac,
	.is_authority_prepare = exec_image_vnode_authority_prepare,
	.is_authority_exec = exec_image_vnode_authority_exec,
	.is_install = exec_image_vnode_install,
	.is_release_old = exec_image_vnode_release_old,
	.is_accessed = exec_image_vnode_accessed,
	.is_close = exec_image_vnode_close,
};

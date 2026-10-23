/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Dmitry Chagin <dchagin@FreeBSD.org>
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

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/extattr.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>

#include <security/mac/mac_framework.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>

#include <compat/linux/linux_file.h>
#include <compat/linux/linux_util.h>

#define	LINUX_XATTR_SIZE_MAX	65536
#define	LINUX_XATTR_LIST_MAX	65536
#define	LINUX_XATTR_NAME_MAX	255

/*
 * Linux struct xattr_args, the argument block of the *xattrat() family
 * (Linux 6.13).  Same layout on every architecture we emulate.
 */
struct l_xattr_args {
	uint64_t	value;		/* user pointer to the value buffer */
	uint32_t	size;
	uint32_t	flags;
};
#define	LINUX_XATTR_ARGS_SIZE_VER0	16
_Static_assert(sizeof(struct l_xattr_args) == LINUX_XATTR_ARGS_SIZE_VER0,
    "struct l_xattr_args layout");

#define	LINUX_XATTRAT_FLAGS	(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH)

/*
 * Resolved *xattrat() target.  Either an fd (the caller's own descriptor
 * with AT_EMPTY_PATH, or a temporary O_PATH descriptor opened relative to
 * dfd) or a path relative to the current directory.
 */
struct xattrat_target {
	int		fd;		/* descriptor to operate on, or -1 */
	int		tmpfd;		/* temporary O_PATH fd to close, or -1 */
	const char	*path;		/* user path, NULL when fd is used */
	int		follow;		/* FOLLOW / NOFOLLOW for path lookups */
};

struct listxattr_args {
	int		fd;
	const char	*path;
	char		*list;
	l_size_t	size;
	int		follow;
	bool		opath;		/* fd may be an internal O_PATH fd */
};

struct setxattr_args {
	int		fd;
	const char	*path;
	const char	*name;
	void 		*value;
	l_size_t	size;
	l_int		flags;
	int		follow;
	bool		opath;		/* fd may be an internal O_PATH fd */
};

struct getxattr_args {
	int		fd;
	const char	*path;
	const char	*name;
	void 		*value;
	l_size_t	size;
	int		follow;
	bool		opath;		/* fd may be an internal O_PATH fd */
};

struct removexattr_args {
	int		fd;
	const char	*path;
	const char	*name;
	int		follow;
	bool		opath;		/* fd may be an internal O_PATH fd */
};

static char *extattr_namespace_names[] = EXTATTR_NAMESPACE_NAMES;


static int
error_to_xattrerror(int attrnamespace, int error)
{

	if (attrnamespace == EXTATTR_NAMESPACE_SYSTEM && error == EPERM)
		return (ENOTSUP);
	else
		return (error);
}

/*
 * Look up the vnode-backed file for the f*xattr() family.  Like Linux, a
 * user-supplied O_PATH descriptor fails with EBADF.  The *xattrat() family
 * resolves dfd-relative paths through a temporary internal O_PATH
 * descriptor (see xattrat_resolve()), which must be accepted.
 */
static int
xattr_getvnode(struct thread *td, int fd, bool opath, cap_rights_t *rightsp,
    struct file **fpp)
{

	if (opath)
		return (getvnode_path(td, fd, rightsp, NULL, fpp));
	return (getvnode(td, fd, rightsp, fpp));
}

static int
xattr_to_extattr(const char *uattrname, int *attrnamespace, char *attrname)
{
	char uname[LINUX_XATTR_NAME_MAX + 1], *dot;
	size_t len, cplen;
	int error;

	error = copyinstr(uattrname, uname, sizeof(uname), &cplen);
	if (error != 0)
		return (error);
	dot = strchr(uname, '.');
	if (dot == NULL)
		return (ENOTSUP);
	*dot = '\0';
	for (*attrnamespace = EXTATTR_NAMESPACE_USER;
	    *attrnamespace < nitems(extattr_namespace_names);
	    (*attrnamespace)++) {
		if (bcmp(uname, extattr_namespace_names[*attrnamespace],
		    dot - uname + 1) == 0) {
			dot++;
			len = strlen(dot) + 1;
			bcopy(dot, attrname, len);
			return (0);
		}
	}
	return (ENOTSUP);
}

static int
listxattr(struct thread *td, struct listxattr_args *args)
{
	char attrname[LINUX_XATTR_NAME_MAX + 1];
	char *data, *prefix, *key;
	cap_rights_t rights;
	struct file *fp = NULL;
	struct uio auio;
	struct iovec aiov;
	unsigned char keylen;
	size_t sz, cnt, rs, prefixlen, pairlen;
	int attrnamespace, error;

	if (args->path == NULL) {
		error = xattr_getvnode(td, args->fd, args->opath,
		    cap_rights_init_one(&rights, CAP_EXTATTR_LIST), &fp);
		if (error != 0)
			return (error);
	}

	/* Native lists may truncate in the middle of a length-prefixed name. */
	sz = LINUX_XATTR_LIST_MAX;

	data = malloc(sz, M_LINUX, M_WAITOK);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = td;
	cnt = 0;
	for (attrnamespace = EXTATTR_NAMESPACE_USER;
	    attrnamespace < nitems(extattr_namespace_names);
	    attrnamespace++) {
		aiov.iov_base = data;
		aiov.iov_len = sz;
		auio.uio_resid = sz;
		auio.uio_offset = 0;

		if (args->path != NULL)
			error = kern_extattr_list_path(td, args->path,
			    attrnamespace, &auio, args->follow, UIO_USERSPACE);
		else
			error = kern_extattr_list_fp(td, fp,
			    attrnamespace, &auio);
		rs = sz - auio.uio_resid;
		/* Omit namespaces the caller may not enumerate. */
		if (error == EPERM && attrnamespace == EXTATTR_NAMESPACE_SYSTEM) {
			error = 0;
			continue;
		}
		if (error == EPERM)
			break;
		if (error != 0)
			break;
		if (rs == 0)
			continue;
		prefix = extattr_namespace_names[attrnamespace];
		prefixlen = strlen(prefix);
		key = data;
		while (rs > 0) {
			keylen = (unsigned char)key[0];
			if (keylen == 0 || keylen + 1 > rs) {
				error = EIO;
				goto out;
			}
			pairlen = prefixlen + 1 + keylen + 1;
			cnt += pairlen;
			if (cnt > LINUX_XATTR_LIST_MAX) {
				error = E2BIG;
				goto out;
			}
			/*
			 * If size is specified as zero, return the current size
			 * of the list of extended attribute names.
			 */
			if ((args->size > 0 && cnt > args->size) ||
			    pairlen > sizeof(attrname)) {
				error = ERANGE;
				goto out;
			}
			++key;
			if (args->size > 0) {
				sprintf(attrname, "%s.%.*s", prefix, keylen, key);
				error = copyout(attrname, args->list, pairlen);
				if (error != 0)
					goto out;
				args->list += pairlen;
			}
			key += keylen;
			rs -= (keylen + 1);
		}
	}
out:
	if (error == 0)
		td->td_retval[0] = cnt;
	free(data, M_LINUX);
	if (fp != NULL)
		fdrop(fp, td);
	return (error_to_xattrerror(attrnamespace, error));
}

int
linux_listxattr(struct thread *td, struct linux_listxattr_args *args)
{
	struct listxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.list = args->list,
		.size = args->size,
		.follow = FOLLOW,
	};

	return (listxattr(td, &eargs));
}

int
linux_llistxattr(struct thread *td, struct linux_llistxattr_args *args)
{
	struct listxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.list = args->list,
		.size = args->size,
		.follow = NOFOLLOW,
	};

	return (listxattr(td, &eargs));
}

int
linux_flistxattr(struct thread *td, struct linux_flistxattr_args *args)
{
	struct listxattr_args eargs = {
		.fd = args->fd,
		.path = NULL,
		.list = args->list,
		.size = args->size,
		.follow = 0,
	};

	return (listxattr(td, &eargs));
}

static int
removexattr(struct thread *td, struct removexattr_args *args)
{
	char attrname[LINUX_XATTR_NAME_MAX + 1];
	struct file *fp = NULL;
	cap_rights_t rights;
	int attrnamespace, error;

	if (args->path == NULL) {
		error = xattr_getvnode(td, args->fd, args->opath,
		    cap_rights_init_one(&rights, CAP_EXTATTR_DELETE), &fp);
		if (error != 0)
			return (error);
	}

	error = xattr_to_extattr(args->name, &attrnamespace, attrname);
	if (error != 0)
		goto out_err;
	if (args->path != NULL)
		error = kern_extattr_delete_path(td, args->path, attrnamespace,
		    attrname, args->follow, UIO_USERSPACE);
	else
		error = kern_extattr_delete_fp(td, fp, attrnamespace,
		    attrname);
	if (fp != NULL)
		fdrop(fp, td);
	return (error_to_xattrerror(attrnamespace, error));
out_err:
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

int
linux_removexattr(struct thread *td, struct linux_removexattr_args *args)
{
	struct removexattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.follow = FOLLOW,
	};

	return (removexattr(td, &eargs));
}

int
linux_lremovexattr(struct thread *td, struct linux_lremovexattr_args *args)
{
	struct removexattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.follow = NOFOLLOW,
	};

	return (removexattr(td, &eargs));
}

int
linux_fremovexattr(struct thread *td, struct linux_fremovexattr_args *args)
{
	struct removexattr_args eargs = {
		.fd = args->fd,
		.path = NULL,
		.name = args->name,
		.follow = 0,
	};

	return (removexattr(td, &eargs));
}

/*-
 * Linux-specific atomic extended attribute get on a vnode.
 *
 * Probes the attribute size and reads the data under a single vnode lock,
 * preventing a TOCTOU race and returning ERANGE when the buffer is too
 * small (matching Linux getxattr(2) semantics).
 */
static int
linux_extattr_get_vp(struct vnode *vp, int attrnamespace, const char *attrname,
    void *data, size_t nbytes, struct thread *td)
{
	struct uio auio;
	struct iovec aiov;
	size_t size;
	int error;

	if (nbytes > IOSIZE_MAX)
		return (EINVAL);

	vn_lock(vp, LK_SHARED | LK_RETRY);

#ifdef MAC
	error = mac_vnode_check_getextattr(td->td_ucred, vp, attrnamespace,
	    attrname);
	if (error != 0)
		goto done;
#endif

	/*
	 * Probe the attribute size first under the vnode lock;
	 */
	error = VOP_GETEXTATTR(vp, attrnamespace, attrname, NULL,
	    &size, td->td_ucred, td);
	if (error != 0)
		goto done;

	/*
	 * The caller only wants the size, so we are done after this.
	 */
	if (data == NULL || nbytes == 0) {
		td->td_retval[0] = size;
		goto done;
	}
	/*
	 * If the buffer is too small, return ERANGE
	 * so the caller can retry (Linux getxattr semantics).
	 */
	if (size > nbytes) {
		error = ERANGE;
		goto done;
	}
	/* Buffer is large enough; read the value. */
	aiov.iov_base = data;
	aiov.iov_len = nbytes;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = 0;
	auio.uio_resid = nbytes;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_td = td;
	error = VOP_GETEXTATTR(vp, attrnamespace, attrname, &auio, NULL,
		td->td_ucred, td);
	if (error == 0)
		td->td_retval[0] = nbytes - auio.uio_resid;
done:
	VOP_UNLOCK(vp);
	return (error);
}

static int
getxattr(struct thread *td, struct getxattr_args *args)
{
	char attrname[LINUX_XATTR_NAME_MAX + 1];
	struct file *fp = NULL;
	struct nameidata nd;
	struct vnode *vp;
	cap_rights_t rights;
	int attrnamespace, error;

	if (args->path == NULL) {
		error = xattr_getvnode(td, args->fd, args->opath,
		    cap_rights_init_one(&rights, CAP_EXTATTR_GET), &fp);
		if (error != 0)
			return (error);
		vp = fp->f_vnode;
	} else {
		NDINIT_ATRIGHTS(&nd, LOOKUP, args->follow, UIO_USERSPACE,
		    args->path, AT_FDCWD,
		    cap_rights_init_one(&rights, CAP_EXTATTR_GET));
		error = namei(&nd);
		if (error != 0)
			return (error);
		NDFREE_PNBUF(&nd);
		vp = nd.ni_vp;
	}

	error = xattr_to_extattr(args->name, &attrnamespace, attrname);
	if (error == 0) {
		error = linux_extattr_get_vp(vp, attrnamespace, attrname,
			args->value, args->size, td);
		if (error == EPERM || error == EOPNOTSUPP)
			error = ENOATTR;
	}
	/* An unknown namespace prefix stays EOPNOTSUPP, as on Linux. */

	if (fp != NULL) {
		fdrop(fp, td);
	} else {
		vrele(nd.ni_vp);
	}
	return (error);
}

int
linux_getxattr(struct thread *td, struct linux_getxattr_args *args)
{
	struct getxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.follow = FOLLOW,
	};

	return (getxattr(td, &eargs));
}

int
linux_lgetxattr(struct thread *td, struct linux_lgetxattr_args *args)
{
	struct getxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.follow = NOFOLLOW,
	};

	return (getxattr(td, &eargs));
}

int
linux_fgetxattr(struct thread *td, struct linux_fgetxattr_args *args)
{
	struct getxattr_args eargs = {
		.fd = args->fd,
		.path = NULL,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.follow = 0,
	};

	return (getxattr(td, &eargs));
}

static int
setxattr(struct thread *td, struct setxattr_args *args)
{
	char attrname[LINUX_XATTR_NAME_MAX + 1];
	struct file *fp = NULL;
	cap_rights_t rights;
	int attrnamespace, error;

	if (args->path == NULL) {
		if ((args->flags & LINUX_XATTR_FLAGS) != 0)
			cap_rights_init(&rights, CAP_EXTATTR_GET, CAP_EXTATTR_SET);
		else
			cap_rights_init_one(&rights, CAP_EXTATTR_SET);
		error = xattr_getvnode(td, args->fd, args->opath, &rights,
		    &fp);
		if (error != 0)
			return (error);
	}

	/*
	 * Linux accepts XATTR_CREATE and XATTR_REPLACE together; see below.
	 */
	if ((args->flags & ~LINUX_XATTR_FLAGS) != 0) {
		error = EINVAL;
		goto out_err;
	}
	error = xattr_to_extattr(args->name, &attrnamespace, attrname);
	if (error != 0)
		goto out_err;

	if ((args->flags & LINUX_XATTR_FLAGS) != 0) {
		if (args->path != NULL)
			error = kern_extattr_get_path(td, args->path,
			    attrnamespace, attrname, NULL, 0,
			    args->follow, UIO_USERSPACE);
		else
			error = kern_extattr_get_fp(td, fp,
			    attrnamespace, attrname, NULL, 0);
		if (args->flags == LINUX_XATTR_FLAGS) {
			/* Both bits are legal.  CREATE wins when present and
			 * REPLACE wins when absent, matching Linux VFS semantics. */
			if (error == 0)
				error = EEXIST;
		} else if ((args->flags & LINUX_XATTR_CREATE) != 0) {
			if (error == 0)
				error = EEXIST;
			else if (error == ENOATTR)
				error = 0;
		}
		if (error != 0)
			goto out;
	}
	if (args->path != NULL)
		error = kern_extattr_set_path(td, args->path, attrnamespace,
		    attrname, args->value, args->size, args->follow,
		    UIO_USERSPACE);
	else
		error = kern_extattr_set_fp(td, fp, attrnamespace,
		    attrname, args->value, args->size);
out:
	if (fp != NULL)
		fdrop(fp, td);
	td->td_retval[0] = 0;
	return (error_to_xattrerror(attrnamespace, error));
out_err:
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

int
linux_setxattr(struct thread *td, struct linux_setxattr_args *args)
{
	struct setxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.flags = args->flags,
		.follow = FOLLOW,
	};

	return (setxattr(td, &eargs));
}

int
linux_lsetxattr(struct thread *td, struct linux_lsetxattr_args *args)
{
	struct setxattr_args eargs = {
		.fd = -1,
		.path = args->path,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.flags = args->flags,
		.follow = NOFOLLOW,
	};

	return (setxattr(td, &eargs));
}

int
linux_fsetxattr(struct thread *td, struct linux_fsetxattr_args *args)
{
	struct setxattr_args eargs = {
		.fd = args->fd,
		.path = NULL,
		.name = args->name,
		.value = args->value,
		.size = args->size,
		.flags = args->flags,
		.follow = 0,
	};

	return (setxattr(td, &eargs));
}

/*
 * Linux copy_struct_from_user() rules for struct xattr_args: the caller's
 * size must be at least the minimum (VER0, the whole struct today), sizes
 * above a page are E2BIG, and if the caller's struct is larger than ours
 * every trailing byte must be zero (E2BIG otherwise).
 */
static int
xattrat_copyin_args(const struct l_xattr_args *uargs, l_size_t usize,
    struct l_xattr_args *args)
{
	char tail[64];
	const char *up;
	size_t left, n, i;
	int error;

	if (usize < LINUX_XATTR_ARGS_SIZE_VER0)
		return (EINVAL);
	if (usize > PAGE_SIZE)
		return (E2BIG);
	error = copyin(uargs, args, sizeof(*args));
	if (error != 0)
		return (error);
	up = (const char *)uargs + sizeof(*args);
	left = usize - sizeof(*args);
	while (left > 0) {
		n = min(left, sizeof(tail));
		error = copyin(up, tail, n);
		if (error != 0)
			return (error);
		for (i = 0; i < n; i++)
			if (tail[i] != 0)
				return (E2BIG);
		up += n;
		left -= n;
	}
	return (0);
}

/*
 * Resolve dfd/path/at_flags to a target usable by the common xattr code.
 *
 * FreeBSD has no dfd-relative kern_extattr_*() entry points, so a relative
 * path with dfd != AT_FDCWD is resolved by opening it O_PATH (no access
 * check on the object itself, exactly like a plain namei() lookup) and the
 * attribute operation is then performed through the descriptor.  The VFS
 * extattr code applies the same VOP_ACCESS() checks on both routes.  The
 * temporary descriptor is closed before returning to the user.
 */
static int
xattrat_resolve(struct thread *td, int dfd, const char *upath,
    l_uint at_flags, struct xattrat_target *tgt)
{
	int c, error, oflags;
	bool empty;

	if ((at_flags & ~LINUX_XATTRAT_FLAGS) != 0)
		return (EINVAL);

	tgt->fd = -1;
	tgt->tmpfd = -1;
	tgt->path = NULL;
	tgt->follow = (at_flags & LINUX_AT_SYMLINK_NOFOLLOW) != 0 ?
	    NOFOLLOW : FOLLOW;

	empty = false;
	if ((at_flags & LINUX_AT_EMPTY_PATH) != 0) {
		/* Linux getname_maybe_null(): NULL or "" names dfd itself. */
		if (upath == NULL)
			empty = true;
		else {
			c = fubyte(upath);
			if (c == -1)
				return (EFAULT);
			empty = (c == 0);
		}
	}
	if (empty) {
		tgt->fd = dfd;
		return (0);
	}
	if (dfd == LINUX_AT_FDCWD) {
		tgt->path = upath;
		return (0);
	}
	oflags = O_PATH | O_CLOEXEC;
	if (tgt->follow == NOFOLLOW)
		oflags |= O_NOFOLLOW;
	error = kern_openat(td, dfd, upath, UIO_USERSPACE, oflags, 0);
	if (error != 0)
		return (error);
	tgt->fd = tgt->tmpfd = td->td_retval[0];
	td->td_retval[0] = 0;
	return (0);
}

static void
xattrat_release(struct thread *td, struct xattrat_target *tgt)
{
	register_t rv;

	if (tgt->tmpfd == -1)
		return;
	rv = td->td_retval[0];
	(void)kern_close(td, tgt->tmpfd);
	td->td_retval[0] = rv;
	tgt->tmpfd = -1;
}

int
linux_setxattrat(struct thread *td, struct linux_setxattrat_args *args)
{
	struct l_xattr_args xa;
	struct xattrat_target tgt;
	struct setxattr_args eargs;
	int error;

	error = xattrat_copyin_args(args->args, args->size, &xa);
	if (error != 0)
		return (error);
	error = xattrat_resolve(td, args->dfd, args->path, args->at_flags,
	    &tgt);
	if (error != 0)
		return (error);
	eargs = (struct setxattr_args){
		.fd = tgt.fd,
		.path = tgt.path,
		.name = args->name,
		.value = (void *)(uintptr_t)xa.value,
		.size = xa.size,
		.flags = xa.flags,
		.follow = tgt.follow,
		.opath = (tgt.tmpfd != -1),
	};
	error = setxattr(td, &eargs);
	xattrat_release(td, &tgt);
	return (error);
}

int
linux_getxattrat(struct thread *td, struct linux_getxattrat_args *args)
{
	struct l_xattr_args xa;
	struct xattrat_target tgt;
	struct getxattr_args eargs;
	int error;

	error = xattrat_copyin_args(args->args, args->size, &xa);
	if (error != 0)
		return (error);
	/* Linux: no flags are defined for getxattrat(). */
	if (xa.flags != 0)
		return (EINVAL);
	error = xattrat_resolve(td, args->dfd, args->path, args->at_flags,
	    &tgt);
	if (error != 0)
		return (error);
	eargs = (struct getxattr_args){
		.fd = tgt.fd,
		.path = tgt.path,
		.name = args->name,
		.value = (void *)(uintptr_t)xa.value,
		.size = xa.size,
		.follow = tgt.follow,
		.opath = (tgt.tmpfd != -1),
	};
	error = getxattr(td, &eargs);
	xattrat_release(td, &tgt);
	return (error);
}

int
linux_listxattrat(struct thread *td, struct linux_listxattrat_args *args)
{
	struct xattrat_target tgt;
	struct listxattr_args eargs;
	int error;

	error = xattrat_resolve(td, args->dfd, args->path, args->at_flags,
	    &tgt);
	if (error != 0)
		return (error);
	eargs = (struct listxattr_args){
		.fd = tgt.fd,
		.path = tgt.path,
		.list = args->list,
		.size = args->size,
		.follow = tgt.follow,
		.opath = (tgt.tmpfd != -1),
	};
	error = listxattr(td, &eargs);
	xattrat_release(td, &tgt);
	return (error);
}

int
linux_removexattrat(struct thread *td, struct linux_removexattrat_args *args)
{
	struct xattrat_target tgt;
	struct removexattr_args eargs;
	int error;

	error = xattrat_resolve(td, args->dfd, args->path, args->at_flags,
	    &tgt);
	if (error != 0)
		return (error);
	eargs = (struct removexattr_args){
		.fd = tgt.fd,
		.path = tgt.path,
		.name = args->name,
		.follow = tgt.follow,
		.opath = (tgt.tmpfd != -1),
	};
	error = removexattr(td, &eargs);
	xattrat_release(td, &tgt);
	return (error);
}

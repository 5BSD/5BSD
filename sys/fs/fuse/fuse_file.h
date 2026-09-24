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

#ifndef _FUSE_FILE_H_
#define _FUSE_FILE_H_

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vnode.h>

/* 
 * The fufh type is the access mode of the fuse file handle.  It's the portion
 * of the open(2) flags related to permission.
 */
typedef enum fufh_type {
	FUFH_INVALID = -1,
	FUFH_RDONLY  = O_RDONLY,
	FUFH_WRONLY  = O_WRONLY,
	FUFH_RDWR    = O_RDWR,
	FUFH_EXEC    = O_EXEC,
} fufh_type_t;

/*
 * Linux-daemon mounts bind each independent open to its struct file.  Dup,
 * fork, and mappings retain that same file and its handle; the final close
 * releases it after description-owned locks.  Vnode operations reached from
 * fileops or descriptor syscalls select the handle through vn_file_context.
 * Pager operations without a file context use a compatible vnode handle,
 * as do Linux cache writeback operations.
 *
 * Native-daemon mounts retain the credential/pid/access-mode handle cache.
 * The vnode owns both kinds of handle, so forced reclaim can free them without
 * leaving module callbacks or dangling handle pointers in a struct file.
 */
struct fuse_filehandle {
	LIST_ENTRY(fuse_filehandle) next;

	/* Non-owning identity; the open file keeps the vnode/handle alive. */
	struct file *fp;
	int open_mode;
	bool opened;
	bool flocked;

	/* The filehandle returned by FUSE_OPEN */
	uint64_t fh_id;

	/*
	 * flags returned by FUSE_OPEN
	 * Supported flags: FOPEN_DIRECT_IO, FOPEN_KEEP_CACHE, FOPEN_NOFLUSH
	 * Unsupported:
	 *     FOPEN_NONSEEKABLE: Adding support would require a new per-file
	 *     or per-vnode attribute, which would have to be checked by
	 *     kern_lseek (and others) for every file system.  The benefit is
	 *     dubious, since I'm unaware of any file systems in ports that use
	 *     this flag.
	 */
	uint32_t fuse_open_flags;

	/* The access mode of the file handle */
	fufh_type_t fufh_type;

	/* Credentials used to open the file */
	gid_t gid;
	pid_t pid;
	uid_t uid;
};

#define FUFH_IS_VALID(f)  ((f)->fufh_type != FUFH_INVALID)

/*
 * Get the flags to use for FUSE_CREATE, FUSE_OPEN and FUSE_RELEASE
 *
 * These are supposed to be the same as the flags argument to open(2).
 * However, since we can't reliably associate a fuse_filehandle with a specific
 * file descriptor it would would be dangerous to include anything more than
 * the access mode flags.  For example, suppose we open a file twice, once with
 * O_APPEND and once without.  Then the user pwrite(2)s to offset using the
 * second file descriptor.  If fusefs uses the first file handle, then the
 * server may append the write to the end of the file rather than at offset 0.
 * To prevent problems like this, we only ever send the portion of flags
 * related to access mode.
 *
 * It's essential to send that portion, because FUSE uses it for server-side
 * authorization.
 */
static inline int
fufh_type_2_fflags(fufh_type_t type)
{
	int oflags = -1;

	switch (type) {
	case FUFH_RDONLY:
	case FUFH_WRONLY:
	case FUFH_RDWR:
	case FUFH_EXEC:
		oflags = type;
		break;
	default:
		break;
	}

	return oflags;
}

/* Access flags encoded for the daemon ABI, not the caller ABI. */
int fuse_filehandle_xflags(struct mount *mp, fufh_type_t type);

bool fuse_filehandle_validrw(struct vnode *vp, int mode,
	struct ucred *cred, pid_t pid);
int fuse_filehandle_get(struct vnode *vp, int fflag,
                        struct fuse_filehandle **fufhp, struct ucred *cred,
			pid_t pid);
int fuse_filehandle_get_anyflags(struct vnode *vp,
                        struct fuse_filehandle **fufhp, struct ucred *cred,
			pid_t pid);
int fuse_filehandle_getrw(struct vnode *vp, int fflag,
                          struct fuse_filehandle **fufhp, struct ucred *cred,
			  pid_t pid);

void fuse_filehandle_init(struct vnode *vp, fufh_type_t fufh_type,
		          struct fuse_filehandle **fufhp, struct thread *td,
			  const struct ucred *cred,
			  const struct fuse_open_out *foo, struct file *fp, int mode);
int fuse_filehandle_open(struct vnode *vp, int mode,
                         struct fuse_filehandle **fufhp, struct thread *td,
                         struct ucred *cred);
int fuse_filehandle_open_file(struct vnode *, int, struct fuse_filehandle **,
    struct thread *, struct ucred *, struct file *);
struct fuse_filehandle *fuse_filehandle_for_file(struct vnode *, struct file *);
struct file *fuse_filehandle_context(struct vnode *, int);
uint32_t fuse_filehandle_wireflags(struct vnode *, struct fuse_filehandle *);
uint32_t fuse_filehandle_openflags(struct mount *, int);

int fuse_filehandle_close(struct vnode *vp, struct fuse_filehandle *fufh,
                          struct thread *td, struct ucred *cred);

uint64_t fuse_file_lock_owner(void *id);
void fuse_file_init(void);
void fuse_file_destroy(void);

/* Original submitter for AIO; the supplied thread otherwise. */
pid_t fuse_thread_pid(struct thread *td);

#endif /* _FUSE_FILE_H_ */

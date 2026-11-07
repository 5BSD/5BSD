/*-
 * SPDX-License-Identifier: BSD-3-Clause
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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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

#ifndef _SYS_IMGACT_H_
#define	_SYS_IMGACT_H_

#include <sys/_uio.h>

#include <vm/vm.h>

#define MAXSHELLCMDLEN	PAGE_SIZE

struct ucred;

struct image_args {
	char *buf;		/* pointer to string buffer */
	void *bufkva;		/* cookie for string buffer KVA */
	char *begin_argv;	/* beginning of argv in buf */
	char *begin_envv;	/* (interal use only) beginning of envv in buf,
				 * access with exec_args_get_begin_envv(). */
	char *endp;		/* current `end' pointer of arg & env strings */
	char *fname;            /* pointer to filename of executable (system space) */
	char *fname_buf;	/* pointer to optional malloc(M_TEMP) buffer */
	int stringspace;	/* space left in arg & env buffer */
	int argc;		/* count of argument strings */
	int envc;		/* count of environment strings */
	int fd;			/* file descriptor of the executable */
};

struct image_params {
	struct proc *proc;		/* our process */
	struct thread *td;
	struct label *execlabel;	/* optional exec label */
	struct vnode *vp;		/* pointer to vnode of file to exec */
	struct vm_object *object;	/* The vm object for this vp */
	struct vattr *attr;		/* attributes of file */
	const char *image_header;	/* header of file to exec */
	unsigned long entry_addr;	/* entry address of target executable */
	unsigned long reloc_base;	/* load address of image */
	unsigned long et_dyn_addr;	/* PIE load base */
	char *interpreter_name;		/* name of the interpreter */
	void *auxargs;			/* ELF Auxinfo structure pointer */
	struct sf_buf *firstpage;	/* first page that we mapped */
	void *ps_strings;		/* pointer to ps_string (user space) */
	struct image_args *args;	/* system call arguments */
	struct sysentvec *sysent;	/* system entry vector */
	void *argv;			/* pointer to argv (user space) */
	void *envv;			/* pointer to envv (user space) */
	char *execpath;
	void *execpathp;
	char *freepath;
	void *canary;
	int canarylen;
	void *pagesizes;
	int pagesizeslen;
	vm_prot_t stack_prot;
	u_long stack_sz;
	struct ucred *newcred;		/* new credentials if changing */
#define IMGACT_SHELL	0x1
#define IMGACT_BINMISC	0x2
#define IMGACT_INTERP_ELF 0x4		/* only used within the ELF activator */
	unsigned char interpreted;	/* mask of interpreters that have run */
	bool credential_setid;		/* true if becoming setid */
	bool authority_setid;		/* secure software-authority exec */
	bool vmspace_destroyed;		/* we've blown away original vm space */
	bool opened;			/* we have opened executable vnode */
	bool textset;
	u_int map_flags;
#define IMGP_ASLR_SHARED_PAGE	0x1
	uint32_t imgp_flags;
	struct vnode *interpreter_vp;	/* vnode of the interpreter */
	const struct image_source_ops *is_ops;	/* NULL until the source is constructed */
	void *is_data;			/* the backend's private state */
	struct label *interpvplabel;	/* label of the #! interpreter's script */
};

/*
 * The process image state that is_install displaced; released by
 * is_release_old after the process lock and the image lock are dropped.
 * Written by the backend, opaque to the exec core.
 */
struct image_source_old {
	struct vnode	*iso_textvp;
	struct vnode	*iso_textdvp;
	char		*iso_binname;
};

/*
 * Image source: how the exec core reaches the image it is activating.
 * The vnode backend (kern/exec_image_vnode.c) is the code that used to be
 * inline in do_execve() and the ELF activator.  Lock preconditions: the
 * image is locked for is_check, is_read, every is_mac phase,
 * is_authority_prepare, is_install and is_accessed; is_mac TRANSITION and
 * RELABEL additionally run under PROC_LOCK and must not sleep.
 */
struct cap_authority;
struct proc;
struct image_source_ops {
	void (*is_lock)(const struct image_params *);
	void (*is_unlock)(const struct image_params *);
	void (*is_assert_locked)(const struct image_params *, const char *);
	int  (*is_check)(struct image_params *);	/* exec_check_permissions */
	int  (*is_first_page)(struct image_params *);	/* references imgp->object, maps page 0 */
	int  (*is_read)(const struct image_params *, void *, size_t, off_t);
	int  (*is_map_cow)(const struct image_params *);	/* extra MAP_* flags for vm_map_fixed */
	void (*is_map_text)(const struct image_params *, vm_object_t);	/* text reference per mapping */
	void (*is_unset_text)(struct image_params *);
	int  (*is_path)(struct image_params *, char **retbuf, char **freebuf);
	int  (*is_commname)(struct image_params *, char *buf, size_t len);
	bool (*is_nosuid)(struct image_params *);
	int  (*is_mac)(struct image_params *, int phase, struct ucred *oldcred,
		    struct ucred *newcred);
	struct cap_authority *(*is_authority_prepare)(struct image_params *,
		    struct proc *);			/* NULL when nosuid */
	void (*is_authority_exec)(struct image_params *, struct proc *,
		    struct cap_authority *selected);
	void (*is_install)(struct image_params *, struct proc *,
		    struct image_source_old *);	/* under PROC_LOCK */
	void (*is_release_old)(struct image_params *,
		    struct image_source_old *);	/* after PROC_UNLOCK and is_close */
	void (*is_accessed)(struct image_params *);	/* VOP_UPDATE_ATIME */
	void (*is_close)(struct image_params *, int error);	/* close; vput when error */
};

/* is_mac phases.  The will_* phases return the MAC hook's answer. */
#define	IS_MAC_WILL_TRANSITION	1
#define	IS_MAC_WILL_RELABEL	2
#define	IS_MAC_TRANSITION	3
#define	IS_MAC_RELABEL		4
#define	IS_MAC_INTERP_ENTER	5	/* mac_execve_interpreter_enter */

#ifdef _KERNEL
struct nameidata;
struct sysentvec;
struct thread;
struct vmspace;
struct vnode;

/* The vnode image source, kern/exec_image_vnode.c. */
void	exec_image_vnode_from_namei(struct image_params *, struct nameidata *);
void	exec_image_vnode_from_vnode(struct image_params *, struct vnode *);
void	exec_image_vnode_init(struct image_params *, struct vnode *);

int	exec_alloc_args(struct image_args *);
int	exec_args_add_arg(struct image_args *args, const char *argp,
	    enum uio_seg segflg);
int	exec_args_add_env(struct image_args *args, const char *envp,
	    enum uio_seg segflg);
int	exec_args_add_fname(struct image_args *args, const char *fname,
	    enum uio_seg segflg);
int	exec_args_adjust_args(struct image_args *args, size_t consume,
	    ssize_t extend);
char	*exec_args_get_begin_envv(struct image_args *args);
int	exec_check_permissions(struct image_params *);
void	exec_cleanup(struct thread *td, struct vmspace *);
int	exec_copyout_strings(struct image_params *, uintptr_t *);
void	exec_free_args(struct image_args *);
int	exec_map_stack(struct image_params *);
int	exec_new_vmspace(struct image_params *, struct sysentvec *);
void	exec_setregs(struct thread *, struct image_params *, uintptr_t);
int	exec_shell_imgact(struct image_params *);
int	exec_copyin_args(struct image_args *, const char *, char **, char **);
int	pre_execve(struct thread *td, struct vmspace **oldvmspace);
void	post_execve(struct thread *td, int error, struct vmspace *oldvmspace);
bool	execve_block(struct thread *td, struct proc *p);
void	execve_block_wait(struct thread *td, struct proc *p);
void	execve_unblock(struct thread *td, struct proc *p);
void	execve_block_pass(struct thread *td);
#endif

#endif /* !_SYS_IMGACT_H_ */

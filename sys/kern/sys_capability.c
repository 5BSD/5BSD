/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2008-2011 Robert N. M. Watson
 * Copyright (c) 2010-2011 Jonathan Anderson
 * Copyright (c) 2012 FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc.
 *
 * Portions of this software were developed by Pawel Jakub Dawidek under
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
 * FreeBSD kernel capability facility.
 *
 * Two kernel features are implemented here: capability mode, a sandboxed mode
 * of execution for processes, and capabilities, a refinement on file
 * descriptors that allows fine-grained control over operations on the file
 * descriptor.  Collectively, these allow processes to run in the style of a
 * historic "capability system" in which they can use only resources
 * explicitly delegated to them.  This model is enforced by restricting access
 * to global namespaces in capability mode.
 *
 * Capabilities wrap other file descriptor types, binding them to a constant
 * rights mask set when the capability is created.  New capabilities may be
 * derived from existing capabilities, but only if they have the same or a
 * strict subset of the rights on the original capability.
 *
 * System calls permitted in capability mode are defined by CAPENABLED
 * flags in syscalls.master; calls must be carefully audited for safety
 * to ensure that they don't allow escape from a sandbox.  Some calls
 * permit only a subset of operations in capability mode -- for example,
 * shm_open(2) is limited to creating anonymous, rather than named,
 * POSIX shared memory objects.
 */

#include <sys/cdefs.h>
#include "opt_capsicum.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/sysctl.h>
#include <sys/procdesc.h>
#include <sys/sdt.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/ktrace.h>

#include <security/audit/audit.h>

#include <vm/uma.h>
#include <vm/vm.h>

bool __read_frequently trap_enotcap;
SYSCTL_BOOL(_kern, OID_AUTO, trap_enotcap, CTLFLAG_RWTUN, &trap_enotcap, 0,
    "Deliver SIGTRAP on ECAPMODE and ENOTCAPABLE");

SDT_PROVIDER_DEFINE(capsicum);
SDT_PROBE_DEFINE3(capsicum, , , mode__enter,
    "pid_t", "struct ucred *", "int");
SDT_PROBE_DEFINE6(capsicum, , , rights__limit,
    "int", "pid_t", "struct ucred *", "cap_rights_t *", "int", "short");
SDT_PROBE_DEFINE6(capsicum, , , ioctls__limit,
    "int", "pid_t", "struct ucred *", "u_long *", "size_t", "int");
SDT_PROBE_DEFINE6(capsicum, , , fcntls__limit,
    "int", "pid_t", "struct ucred *", "uint32_t", "int", "short");
SDT_PROBE_DEFINE6(capsicum, , , ioctl__deny,
    "int", "pid_t", "struct ucred *", "u_long", "short", "int");
SDT_PROBE_DEFINE6(capsicum, , , fcntl__deny,
    "int", "pid_t", "struct ucred *", "int", "short", "int");
SDT_PROBE_DEFINE6(capsicum, , , check__deny,
    "cap_rights_t *", "cap_rights_t *", "pid_t", "struct ucred *", "int",
    "int");
SDT_PROBE_DEFINE6(capsicum, , , rights__get,
    "int", "pid_t", "struct ucred *", "cap_rights_t *", "int", "short");
SDT_PROBE_DEFINE6(capsicum, , , ioctls__get,
    "int", "pid_t", "struct ucred *", "size_t", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , fcntls__get,
    "int", "pid_t", "struct ucred *", "uint32_t", "int", "short");
SDT_PROBE_DEFINE6(capsicum, , , xfer__limit,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , cloexec__limit,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , clofork__limit,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , connect__capmode__deny,
    "pid_t", "struct ucred *", "int", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , connect__capmode__server__deny,
    "pid_t", "struct ucred *", "int", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , mmap__capmode,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , mmap__capmode__deny,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , lookup__capmode,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
SDT_PROBE_DEFINE6(capsicum, , , lookup__capmode__deny,
    "int", "pid_t", "struct ucred *", "int", "int", "int");
/*
 * An ambient syscall was blocked in capability mode, or a capability-required
 * syscall was invoked outside it: pid, syscall code, sy_flags, errno.
 */
SDT_PROBE_DEFINE4(capsicum, , , syscall__deny,
    "pid_t", "int", "int", "int");
/*
 * A capability violation was escalated to a SIGTRAP (TRAP_CAP): pid, errno,
 * syscall code, si_code.
 */
SDT_PROBE_DEFINE4(capsicum, , , trap__signal,
    "pid_t", "int", "int", "int");
/*
 * A process in capability mode was denied signalling another process:
 * sender pid, target pid, signal number, errno.
 */
SDT_PROBE_DEFINE4(capsicum, , , signal__capmode__deny,
    "pid_t", "pid_t", "int", "int");
/*
 * Process-descriptor lifecycle: a process is a capability referenced by an
 * fd.  pdfork: a new described process (parent pid, child pid, flags).
 * pdkill: a signal delivered via a descriptor, bypassing p_cansignal
 * (fd, target pid, signal).  pdclose: last close on a descriptor
 * (target pid, pd_flags, killed).
 */
SDT_PROBE_DEFINE3(capsicum, , , pdfork, "pid_t", "pid_t", "int");
SDT_PROBE_DEFINE3(capsicum, , , pdkill, "int", "pid_t", "int");
SDT_PROBE_DEFINE3(capsicum, , , pdclose, "pid_t", "int", "int");

#ifdef CAPABILITY_MODE

#define        IOCTLS_MAX_COUNT        256     /* XXX: Is 256 sane? */

FEATURE(security_capability_mode, "Capsicum Capability Mode");

/*
 * System call to enter capability mode for the process.
 */
int
sys_cap_enter(struct thread *td, struct cap_enter_args *uap)
{
	struct ucred *newcred, *oldcred;
	struct proc *p;

	if (IN_CAPABILITY_MODE(td))
		return (0);

	newcred = crget();
	p = td->td_proc;
	PROC_LOCK(p);
	oldcred = crcopysafe(p, newcred);
	newcred->cr_flags |= CRED_FLAG_CAPMODE;
	proc_set_cred(p, newcred);

	/* Notify procdesc listeners that we entered capability mode. */
	procdesc_knote(p, NOTE_CAPMODE);	/* drops+reacquires */
	PROC_UNLOCK(p);

	crfree(oldcred);
	SDT_PROBE3(capsicum, , , mode__enter, p->p_pid,
	    td->td_ucred, 0);
	return (0);
}

/*
 * System call to query whether the process is in capability mode.
 */
int
sys_cap_getmode(struct thread *td, struct cap_getmode_args *uap)
{
	u_int i;

	i = IN_CAPABILITY_MODE(td) ? 1 : 0;
	return (copyout(&i, uap->modep, sizeof(i)));
}

#else /* !CAPABILITY_MODE */

int
sys_cap_enter(struct thread *td, struct cap_enter_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_getmode(struct thread *td, struct cap_getmode_args *uap)
{

	return (ENOSYS);
}

#endif /* CAPABILITY_MODE */

#ifdef CAPABILITIES

FEATURE(security_capabilities, "Capsicum Capabilities");

MALLOC_DECLARE(M_FILECAPS);

static inline int
_cap_check(const cap_rights_t *havep, const cap_rights_t *needp,
    enum ktr_cap_violation type)
{
	const cap_rights_t rights[] = { *needp, *havep };

	if (!cap_rights_contains(havep, needp)) {
		if (CAP_TRACING(curthread))
			ktrcapfail(type, rights);
		SDT_PROBE6(capsicum, , , check__deny, havep, needp,
		    curthread->td_proc->p_pid, curthread->td_ucred, type,
		    ENOTCAPABLE);
		return (ENOTCAPABLE);
	}
	return (0);
}

/*
 * Test whether a capability grants the requested rights.
 */
int
cap_check(const cap_rights_t *havep, const cap_rights_t *needp)
{

	return (_cap_check(havep, needp, CAPFAIL_NOTCAPABLE));
}

int
cap_check_failed_notcapable(const cap_rights_t *havep, const cap_rights_t *needp)
{
	const cap_rights_t rights[] = { *needp, *havep };

	if (CAP_TRACING(curthread))
		ktrcapfail(CAPFAIL_NOTCAPABLE, rights);
	SDT_PROBE6(capsicum, , , check__deny, havep, needp,
	    curthread->td_proc->p_pid, curthread->td_ucred, CAPFAIL_NOTCAPABLE,
	    ENOTCAPABLE);
	return (ENOTCAPABLE);
}

/*
 * Convert capability rights into VM access flags.
 */
vm_prot_t
cap_rights_to_vmprot(const cap_rights_t *havep)
{
	vm_prot_t maxprot;

	maxprot = VM_PROT_NONE;
	if (cap_rights_is_set(havep, CAP_MMAP_R))
		maxprot |= VM_PROT_READ;
	if (cap_rights_is_set(havep, CAP_MMAP_W))
		maxprot |= VM_PROT_WRITE;
	if (cap_rights_is_set(havep, CAP_MMAP_X))
		maxprot |= VM_PROT_EXECUTE;

	return (maxprot);
}

/*
 * Extract rights from a capability for monitoring purposes -- not for use in
 * any other way, as we want to keep all capability permission evaluation in
 * this one file.
 */

const cap_rights_t *
cap_rights_fde(const struct filedescent *fdep)
{

	return (cap_rights_fde_inline(fdep));
}

const cap_rights_t *
cap_rights(struct filedesc *fdp, int fd)
{

	return (cap_rights_fde(&fdp->fd_ofiles[fd]));
}

int
kern_cap_rights_limit(struct thread *td, int fd, cap_rights_t *rights)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	u_long *ioctls;
	int error;
	short ftype;

	fdp = td->td_proc->p_fd;
	ftype = -1;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	ioctls = NULL;
	ftype = fdep->fde_file->f_type;
	error = _cap_check(cap_rights(fdp, fd), rights, CAPFAIL_INCREASE);
	if (error == 0) {
		seqc_write_begin(&fdep->fde_seqc);
		fdep->fde_rights = *rights;
		if (!cap_rights_is_set(rights, CAP_IOCTL)) {
			ioctls = fdep->fde_ioctls;
			fdep->fde_ioctls = NULL;
			fdep->fde_nioctls = 0;
		}
		if (!cap_rights_is_set(rights, CAP_FCNTL))
			fdep->fde_fcntls = 0;
		seqc_write_end(&fdep->fde_seqc);
	}
	FILEDESC_XUNLOCK(fdp);
	free(ioctls, M_FILECAPS);
out_probe:
	SDT_PROBE6(capsicum, , , rights__limit, fd, td->td_proc->p_pid,
	    td->td_ucred, rights, error, ftype);
	return (error);
}

/*
 * System call to limit rights of the given capability.
 */
int
sys_cap_rights_limit(struct thread *td, struct cap_rights_limit_args *uap)
{
	cap_rights_t rights;
	int error, version;

	cap_rights_init_zero(&rights);

	error = copyin(uap->rightsp, &rights, sizeof(rights.cr_rights[0]));
	if (error != 0)
		return (error);
	version = CAPVER(&rights);
	if (version != CAP_RIGHTS_VERSION_00)
		return (EINVAL);

	error = copyin(uap->rightsp, &rights,
	    sizeof(rights.cr_rights[0]) * CAPARSIZE(&rights));
	if (error != 0)
		return (error);
	/* Check for race. */
	if (CAPVER(&rights) != version)
		return (EINVAL);

	if (!cap_rights_is_valid(&rights))
		return (EINVAL);

	if (version != CAP_RIGHTS_VERSION) {
		rights.cr_rights[0] &= ~(0x3ULL << 62);
		rights.cr_rights[0] |= ((uint64_t)CAP_RIGHTS_VERSION << 62);
	}
#ifdef KTRACE
	if (KTRPOINT(td, KTR_STRUCT))
		ktrcaprights(&rights);
#endif

	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_RIGHTS(&rights);
	return (kern_cap_rights_limit(td, uap->fd, &rights));
}

/*
 * System call to query the rights mask associated with a capability.
 */
int
sys___cap_rights_get(struct thread *td, struct __cap_rights_get_args *uap)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	cap_rights_t rights;
	int error, fd, i, n;
	short ftype;

	fd = uap->fd;
	cap_rights_init_zero(&rights);
	ftype = -1;
	error = 0;
	if (uap->version != CAP_RIGHTS_VERSION_00) {
		error = EINVAL;
		goto out_probe;
	}

	AUDIT_ARG_FD(fd);

	fdp = td->td_proc->p_fd;
	FILEDESC_SLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_SUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	ftype = fdep->fde_file->f_type;
	rights = *cap_rights(fdp, fd);
	FILEDESC_SUNLOCK(fdp);
	n = uap->version + 2;
	if (uap->version != CAPVER(&rights)) {
		/*
		 * For older versions we need to check if the descriptor
		 * doesn't contain rights not understood by the caller.
		 * If it does, we have to return an error.
		 */
		for (i = n; i < CAPARSIZE(&rights); i++) {
			if ((rights.cr_rights[i] & ~(0x7FULL << 57)) != 0) {
				error = EINVAL;
				goto out_probe;
			}
		}
	}
	error = copyout(&rights, uap->rightsp, sizeof(rights.cr_rights[0]) * n);
#ifdef KTRACE
	if (error == 0 && KTRPOINT(td, KTR_STRUCT))
		ktrcaprights(&rights);
#endif
out_probe:
	SDT_PROBE6(capsicum, , , rights__get, fd, td->td_proc->p_pid,
	    td->td_ucred, &rights, error, ftype);
	return (error);
}

/*
 * Test whether a capability grants the given ioctl command.
 * If descriptor doesn't have CAP_IOCTL, then ioctls list is empty and
 * ENOTCAPABLE will be returned.
 */
int
cap_ioctl_check(struct filedesc *fdp, int fd, u_long cmd)
{
	struct filedescent *fdep;
	u_long *cmds;
	ssize_t ncmds;
	long i;

	KASSERT(fd >= 0 && fd < fdp->fd_nfiles,
		("%s: invalid fd=%d", __func__, fd));

	fdep = fdeget_noref(fdp, fd);
	KASSERT(fdep != NULL,
	    ("%s: invalid fd=%d", __func__, fd));

	ncmds = fdep->fde_nioctls;
	if (ncmds == -1)
		return (0);

	cmds = fdep->fde_ioctls;
	for (i = 0; i < ncmds; i++) {
		if (cmds[i] == cmd)
			return (0);
	}

	SDT_PROBE6(capsicum, , , ioctl__deny, fd,
	    curthread->td_proc->p_pid, curthread->td_ucred, cmd,
	    fdep->fde_file->f_type, ENOTCAPABLE);
	return (ENOTCAPABLE);
}

/*
 * Check if the current ioctls list can be replaced by the new one.
 */
static int
filecaps_ioctl_limit_check(const struct filecaps *fcaps, const u_long *cmds,
    size_t ncmds)
{
	u_long *ocmds;
	ssize_t oncmds;
	u_long i;
	long j;

	oncmds = fcaps->fc_nioctls;
	if (oncmds == -1)
		return (0);
	if (oncmds < (ssize_t)ncmds)
		return (ENOTCAPABLE);

	ocmds = fcaps->fc_ioctls;
	for (i = 0; i < ncmds; i++) {
		for (j = 0; j < oncmds; j++) {
			if (cmds[i] == ocmds[j])
				break;
		}
		if (j == oncmds)
			return (ENOTCAPABLE);
	}

	return (0);
}

static int
cap_ioctl_limit_check(struct filedescent *fdep, const u_long *cmds,
    size_t ncmds)
{

	return (filecaps_ioctl_limit_check(&fdep->fde_caps, cmds, ncmds));
}

int
kern_cap_ioctls_limit(struct thread *td, int fd, u_long *cmds, size_t ncmds)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	u_long *newcmds, *ocmds;
	int error;

	AUDIT_ARG_FD(fd);
	newcmds = cmds;

	if (ncmds > IOCTLS_MAX_COUNT) {
		error = EINVAL;
		goto out_free;
	}

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);

	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		error = EBADF;
		goto out;
	}

	error = cap_ioctl_limit_check(fdep, cmds, ncmds);
	if (error != 0)
		goto out;

	ocmds = fdep->fde_ioctls;
	seqc_write_begin(&fdep->fde_seqc);
	fdep->fde_ioctls = cmds;
	fdep->fde_nioctls = ncmds;
	seqc_write_end(&fdep->fde_seqc);

	cmds = ocmds;
	error = 0;
out:
	FILEDESC_XUNLOCK(fdp);
out_free:
	SDT_PROBE6(capsicum, , , ioctls__limit, fd,
	    td->td_proc->p_pid, td->td_ucred, newcmds, ncmds, error);
	free(cmds, M_FILECAPS);
	return (error);
}

int
sys_cap_ioctls_limit(struct thread *td, struct cap_ioctls_limit_args *uap)
{
	u_long *cmds;
	size_t ncmds;
	int error;

	ncmds = uap->ncmds;

	if (ncmds > IOCTLS_MAX_COUNT)
		return (EINVAL);

	if (ncmds == 0) {
		cmds = NULL;
	} else {
		cmds = malloc(sizeof(cmds[0]) * ncmds, M_FILECAPS, M_WAITOK);
		error = copyin(uap->cmds, cmds, sizeof(cmds[0]) * ncmds);
		if (error != 0) {
			free(cmds, M_FILECAPS);
			return (error);
		}
	}

	return (kern_cap_ioctls_limit(td, uap->fd, cmds, ncmds));
}

int
sys_cap_ioctls_get(struct thread *td, struct cap_ioctls_get_args *uap)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	u_long *cmdsp, *dstcmds;
	size_t maxcmds, ncmds;
	int16_t count;
	int error, fd;

	fd = uap->fd;
	dstcmds = uap->cmds;
	maxcmds = uap->maxcmds;

	AUDIT_ARG_FD(fd);

	fdp = td->td_proc->p_fd;

	cmdsp = NULL;
	if (dstcmds != NULL) {
		cmdsp = malloc(sizeof(cmdsp[0]) * IOCTLS_MAX_COUNT, M_FILECAPS,
		    M_WAITOK | M_ZERO);
	}

	FILEDESC_SLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		error = EBADF;
		FILEDESC_SUNLOCK(fdp);
		goto out;
	}
	count = fdep->fde_nioctls;
	if (count != -1 && cmdsp != NULL) {
		ncmds = MIN(count, maxcmds);
		memcpy(cmdsp, fdep->fde_ioctls, sizeof(cmdsp[0]) * ncmds);
	}
	FILEDESC_SUNLOCK(fdp);

	/*
	 * If all ioctls are allowed (fde_nioctls == -1 && fde_ioctls == NULL)
	 * the only sane thing we can do is to not populate the given array and
	 * return CAP_IOCTLS_ALL.
	 */
	if (count != -1) {
		if (cmdsp != NULL) {
			error = copyout(cmdsp, dstcmds,
			    sizeof(cmdsp[0]) * ncmds);
			if (error != 0)
				goto out;
		}
		td->td_retval[0] = count;
	} else {
		td->td_retval[0] = CAP_IOCTLS_ALL;
	}

	error = 0;
out:
	SDT_PROBE6(capsicum, , , ioctls__get, fd,
	    td->td_proc->p_pid, td->td_ucred, maxcmds,
	    error == 0 ? td->td_retval[0] : -1, error);
	free(cmdsp, M_FILECAPS);
	return (error);
}

/*
 * Test whether a capability grants the given fcntl command.
 */
int
cap_fcntl_check_fde(struct filedescent *fdep, int cmd)
{
	uint32_t fcntlcap;

	fcntlcap = (1 << cmd);
	KASSERT((CAP_FCNTL_ALL & fcntlcap) != 0,
	    ("Unsupported fcntl=%d.", cmd));

	if ((fdep->fde_fcntls & fcntlcap) != 0)
		return (0);

	return (ENOTCAPABLE);
}

int
cap_fcntl_check(struct filedesc *fdp, int fd, int cmd)
{
	struct filedescent *fdep;
	int error;

	KASSERT(fd >= 0 && fd < fdp->fd_nfiles,
	    ("%s: invalid fd=%d", __func__, fd));

	fdep = &fdp->fd_ofiles[fd];
	error = cap_fcntl_check_fde(fdep, cmd);
	if (error != 0) {
		SDT_PROBE6(capsicum, , , fcntl__deny, fd,
		    curthread->td_proc->p_pid, curthread->td_ucred, cmd,
		    fdep->fde_file->f_type, error);
	}
	return (error);
}

int
sys_cap_fcntls_limit(struct thread *td, struct cap_fcntls_limit_args *uap)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	uint32_t fcntlrights;
	int error, fd;
	short ftype;

	fd = uap->fd;
	fcntlrights = uap->fcntlrights;
	ftype = -1;

	AUDIT_ARG_FD(fd);
	AUDIT_ARG_FCNTL_RIGHTS(fcntlrights);

	if ((fcntlrights & ~CAP_FCNTL_ALL) != 0) {
		error = EINVAL;
		goto out_probe;
	}

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);

	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	ftype = fdep->fde_file->f_type;

	if ((fcntlrights & ~fdep->fde_fcntls) != 0) {
		FILEDESC_XUNLOCK(fdp);
		error = ENOTCAPABLE;
		goto out_probe;
	}

	seqc_write_begin(&fdep->fde_seqc);
	fdep->fde_fcntls = fcntlrights;
	seqc_write_end(&fdep->fde_seqc);
	FILEDESC_XUNLOCK(fdp);
	error = 0;

out_probe:
	SDT_PROBE6(capsicum, , , fcntls__limit, fd,
	    td->td_proc->p_pid, td->td_ucred, fcntlrights, error, ftype);
	return (error);
}

int
sys_cap_fcntls_get(struct thread *td, struct cap_fcntls_get_args *uap)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	uint32_t rights;
	int error, fd;
	short ftype;

	fd = uap->fd;
	rights = 0;
	ftype = -1;

	AUDIT_ARG_FD(fd);

	fdp = td->td_proc->p_fd;
	FILEDESC_SLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_SUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	rights = fdep->fde_fcntls;
	ftype = fdep->fde_file->f_type;
	FILEDESC_SUNLOCK(fdp);

	error = copyout(&rights, uap->fcntlrightsp, sizeof(rights));
out_probe:
	SDT_PROBE6(capsicum, , , fcntls__get, fd,
	    td->td_proc->p_pid, td->td_ucred, rights, error, ftype);
	return (error);
}

int
kern_cap_xfer_limit(struct thread *td, int fd, int state)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	int error, old_state = -1;

	if (state != CAP_XFER_UNLIMITED &&
	    state != CAP_XFER_ONCE && state != CAP_XFER_NONE)
		return (EINVAL);

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	old_state = fdep->fde_xfer_state;
	if (old_state != CAP_XFER_UNLIMITED &&
	    !(old_state == CAP_XFER_ONCE &&
	    (state == CAP_XFER_ONCE || state == CAP_XFER_NONE)) &&
	    !(old_state == CAP_XFER_NONE && state == CAP_XFER_NONE)) {
		FILEDESC_XUNLOCK(fdp);
		error = ENOTCAPABLE;
		goto out_probe;
	}
	fdep->fde_xfer_state = state;
	FILEDESC_XUNLOCK(fdp);
	error = 0;
out_probe:
	SDT_PROBE6(capsicum, , , xfer__limit, fd, td->td_proc->p_pid,
	    td->td_ucred, state, error, old_state);
	return (error);
}

int
sys_cap_xfer_limit(struct thread *td, struct cap_xfer_limit_args *uap)
{

	return (kern_cap_xfer_limit(td, uap->fd, uap->state));
}

int
kern_cap_xfer_rights_limit(struct thread *td, int fd,
    const cap_rights_t *rights)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	u_long *ioctls;
	int error;

	fdp = td->td_proc->p_fd;
	ioctls = NULL;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		error = EBADF;
		goto out;
	}
	error = _cap_check(&fdep->fde_xfer_caps.fc_rights, rights,
	    CAPFAIL_INCREASE);
	if (error != 0)
		goto out;

	seqc_write_begin(&fdep->fde_seqc);
	fdep->fde_xfer_caps.fc_rights = *rights;
	if (!cap_rights_is_set(rights, CAP_IOCTL)) {
		ioctls = fdep->fde_xfer_caps.fc_ioctls;
		fdep->fde_xfer_caps.fc_ioctls = NULL;
		fdep->fde_xfer_caps.fc_nioctls = 0;
	}
	if (!cap_rights_is_set(rights, CAP_FCNTL))
		fdep->fde_xfer_caps.fc_fcntls = 0;
	seqc_write_end(&fdep->fde_seqc);
	error = 0;
out:
	FILEDESC_XUNLOCK(fdp);
	free(ioctls, M_FILECAPS);
	return (error);
}

int
sys_cap_xfer_rights_limit(struct thread *td,
    struct cap_xfer_rights_limit_args *uap)
{
	cap_rights_t rights;
	int error, version;

	cap_rights_init_zero(&rights);
	error = copyin(uap->rightsp, &rights, sizeof(rights.cr_rights[0]));
	if (error != 0)
		return (error);
	version = CAPVER(&rights);
	if (version != CAP_RIGHTS_VERSION_00)
		return (EINVAL);
	error = copyin(uap->rightsp, &rights,
	    sizeof(rights.cr_rights[0]) * CAPARSIZE(&rights));
	if (error != 0)
		return (error);
	if (CAPVER(&rights) != version || !cap_rights_is_valid(&rights))
		return (EINVAL);
	if (version != CAP_RIGHTS_VERSION) {
		rights.cr_rights[0] &= ~(0x3ULL << 62);
		rights.cr_rights[0] |= ((uint64_t)CAP_RIGHTS_VERSION << 62);
	}
	AUDIT_ARG_FD(uap->fd);
	AUDIT_ARG_RIGHTS(&rights);
	return (kern_cap_xfer_rights_limit(td, uap->fd, &rights));
}

int
kern_cap_xfer_ioctls_limit(struct thread *td, int fd, u_long *cmds,
    size_t ncmds)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	u_long *oldcmds;
	int error;

	if (ncmds > IOCTLS_MAX_COUNT) {
		error = EINVAL;
		goto out_free;
	}
	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		error = EBADF;
		goto out;
	}
	if (ncmds != 0 && !cap_rights_is_set(
	    &fdep->fde_xfer_caps.fc_rights, CAP_IOCTL)) {
		error = ENOTCAPABLE;
		goto out;
	}
	error = filecaps_ioctl_limit_check(&fdep->fde_xfer_caps, cmds,
	    ncmds);
	if (error != 0)
		goto out;

	oldcmds = fdep->fde_xfer_caps.fc_ioctls;
	seqc_write_begin(&fdep->fde_seqc);
	fdep->fde_xfer_caps.fc_ioctls = cmds;
	fdep->fde_xfer_caps.fc_nioctls = ncmds;
	seqc_write_end(&fdep->fde_seqc);
	cmds = oldcmds;
	error = 0;
out:
	FILEDESC_XUNLOCK(fdp);
out_free:
	free(cmds, M_FILECAPS);
	return (error);
}

int
sys_cap_xfer_ioctls_limit(struct thread *td,
    struct cap_xfer_ioctls_limit_args *uap)
{
	u_long *cmds;
	size_t ncmds;
	int error;

	ncmds = uap->ncmds;
	if (ncmds > IOCTLS_MAX_COUNT)
		return (EINVAL);
	if (ncmds == 0)
		cmds = NULL;
	else {
		cmds = mallocarray(ncmds, sizeof(cmds[0]), M_FILECAPS,
		    M_WAITOK);
		error = copyin(uap->cmds, cmds, ncmds * sizeof(cmds[0]));
		if (error != 0) {
			free(cmds, M_FILECAPS);
			return (error);
		}
	}
	return (kern_cap_xfer_ioctls_limit(td, uap->fd, cmds, ncmds));
}

int
kern_cap_xfer_fcntls_limit(struct thread *td, int fd, uint32_t rights)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	int error;

	if ((rights & ~CAP_FCNTL_ALL) != 0)
		return (EINVAL);
	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		error = EBADF;
		goto out;
	}
	if ((rights & ~fdep->fde_xfer_caps.fc_fcntls) != 0) {
		error = ENOTCAPABLE;
		goto out;
	}
	if (rights != 0 && !cap_rights_is_set(
	    &fdep->fde_xfer_caps.fc_rights, CAP_FCNTL)) {
		error = ENOTCAPABLE;
		goto out;
	}
	seqc_write_begin(&fdep->fde_seqc);
	fdep->fde_xfer_caps.fc_fcntls = rights;
	seqc_write_end(&fdep->fde_seqc);
	error = 0;
out:
	FILEDESC_XUNLOCK(fdp);
	return (error);
}

int
sys_cap_xfer_fcntls_limit(struct thread *td,
    struct cap_xfer_fcntls_limit_args *uap)
{

	return (kern_cap_xfer_fcntls_limit(td, uap->fd,
	    uap->fcntlrights));
}

int
kern_cap_cloexec_limit(struct thread *td, int fd, int state)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	int error, new_rank, old_rank, old_state = -1;

	switch (state) {
	case CAP_CLOEXEC_UNLOCKED:
		new_rank = 0;
		break;
	case CAP_CLOEXEC_ONCE:
		new_rank = 1;
		break;
	case CAP_CLOEXEC_LOCKED:
		new_rank = 2;
		break;
	default:
		return (EINVAL);
	}

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	old_state = fdep->fde_cloexec_state;
	switch (old_state) {
	case CAP_CLOEXEC_UNLOCKED:
		old_rank = 0;
		break;
	case CAP_CLOEXEC_ONCE:
		old_rank = 1;
		break;
	case CAP_CLOEXEC_LOCKED:
		old_rank = 2;
		break;
	default:
		panic("%s: invalid cloexec state %d", __func__, old_state);
	}
	if (new_rank < old_rank) {
		FILEDESC_XUNLOCK(fdp);
		error = ENOTCAPABLE;
		goto out_probe;
	}
	fdep->fde_cloexec_state = state;
	FILEDESC_XUNLOCK(fdp);
	error = 0;
out_probe:
	SDT_PROBE6(capsicum, , , cloexec__limit, fd, td->td_proc->p_pid,
	    td->td_ucred, state, error, old_state);
	return (error);
}

int
sys_cap_cloexec_limit(struct thread *td, struct cap_cloexec_limit_args *uap)
{

	return (kern_cap_cloexec_limit(td, uap->fd, uap->state));
}

int
kern_cap_clofork_limit(struct thread *td, int fd, int state)
{
	struct filedesc *fdp;
	struct filedescent *fdep;
	int error, new_rank, old_rank, old_state = -1;

	switch (state) {
	case CAP_CLOFORK_UNLOCKED:
		new_rank = 0;
		break;
	case CAP_CLOFORK_ONCE:
		new_rank = 1;
		break;
	case CAP_CLOFORK_LOCKED:
		new_rank = 2;
		break;
	default:
		return (EINVAL);
	}

	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdep = fdeget_noref(fdp, fd);
	if (fdep == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	old_state = fdep->fde_clofork_state;
	switch (old_state) {
	case CAP_CLOFORK_UNLOCKED:
		old_rank = 0;
		break;
	case CAP_CLOFORK_ONCE:
		old_rank = 1;
		break;
	case CAP_CLOFORK_LOCKED:
		old_rank = 2;
		break;
	default:
		panic("%s: invalid clofork state %d", __func__, old_state);
	}
	if (new_rank < old_rank) {
		FILEDESC_XUNLOCK(fdp);
		error = ENOTCAPABLE;
		goto out_probe;
	}
	fdep->fde_clofork_state = state;
	FILEDESC_XUNLOCK(fdp);
	error = 0;
out_probe:
	SDT_PROBE6(capsicum, , , clofork__limit, fd, td->td_proc->p_pid,
	    td->td_ucred, state, error, old_state);
	return (error);
}

int
sys_cap_clofork_limit(struct thread *td, struct cap_clofork_limit_args *uap)
{

	return (kern_cap_clofork_limit(td, uap->fd, uap->state));
}

int
sys_cap_mmap_capmode(struct thread *td, struct cap_mmap_capmode_args *uap)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct filedescent *fde;
	int fd = uap->fd;
	int error, old_state = -1;

	AUDIT_ARG_FD(fd);
	FILEDESC_XLOCK(fdp);
	fde = fdeget_noref(fdp, fd);
	if (fde == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	old_state = (fde->fde_flags & UF_MMAP_CAPMODE) ? 1 : 0;
#ifdef CAPABILITIES
	seqc_write_begin(&fde->fde_seqc);
#endif
	fde->fde_flags |= UF_MMAP_CAPMODE;
#ifdef CAPABILITIES
	seqc_write_end(&fde->fde_seqc);
#endif
	FILEDESC_XUNLOCK(fdp);
	error = 0;
out_probe:
	SDT_PROBE6(capsicum, , , mmap__capmode, fd, td->td_proc->p_pid,
	    td->td_ucred, 1, error, old_state);
	return (error);
}

int
sys_cap_lookup_capmode(struct thread *td, struct cap_lookup_capmode_args *uap)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct filedescent *fde;
	int fd = uap->fd;
	int error, old_state = -1;

	AUDIT_ARG_FD(fd);
	FILEDESC_XLOCK(fdp);
	fde = fdeget_noref(fdp, fd);
	if (fde == NULL) {
		FILEDESC_XUNLOCK(fdp);
		error = EBADF;
		goto out_probe;
	}
	old_state = (fde->fde_flags & UF_LOOKUP_CAPMODE) ? 1 : 0;
#ifdef CAPABILITIES
	seqc_write_begin(&fde->fde_seqc);
#endif
	fde->fde_flags |= UF_LOOKUP_CAPMODE;
#ifdef CAPABILITIES
	seqc_write_end(&fde->fde_seqc);
#endif
	FILEDESC_XUNLOCK(fdp);
	error = 0;
out_probe:
	SDT_PROBE6(capsicum, , , lookup__capmode, fd, td->td_proc->p_pid,
	    td->td_ucred, 1, error, old_state);
	return (error);
}

#else /* !CAPABILITIES */

/*
 * Stub Capability functions for when options CAPABILITIES isn't compiled
 * into the kernel.
 */

int
sys_cap_rights_limit(struct thread *td, struct cap_rights_limit_args *uap)
{

	return (ENOSYS);
}

int
sys___cap_rights_get(struct thread *td, struct __cap_rights_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_ioctls_limit(struct thread *td, struct cap_ioctls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_ioctls_get(struct thread *td, struct cap_ioctls_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_fcntls_limit(struct thread *td, struct cap_fcntls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_fcntls_get(struct thread *td, struct cap_fcntls_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_xfer_limit(struct thread *td, struct cap_xfer_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_xfer_rights_limit(struct thread *td,
    struct cap_xfer_rights_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_xfer_ioctls_limit(struct thread *td,
    struct cap_xfer_ioctls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_xfer_fcntls_limit(struct thread *td,
    struct cap_xfer_fcntls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_cloexec_limit(struct thread *td, struct cap_cloexec_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_clofork_limit(struct thread *td, struct cap_clofork_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_mmap_capmode(struct thread *td, struct cap_mmap_capmode_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_lookup_capmode(struct thread *td, struct cap_lookup_capmode_args *uap)
{

	return (ENOSYS);
}

#endif /* CAPABILITIES */

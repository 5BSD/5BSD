/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2001 Dag-Erling Smørgrav
 * Copyright (c) 1993 Sean Eric Fagan
 * Copyright (c) 1993 Jan-Simon Pendry
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/exec.h>
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>

#include <fs/pseudofs/pseudofs.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <compat/linprocfs/linprocfs_helpers.h>

/*
 * Filler function for proc/pid/file
 */
int
linprocfs_common_doprocfile(PFS_FILL_ARGS)
{
	char *fullpath, *freepath, *binpath;
	int error;

	freepath = NULL;
	binpath = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	PROC_LOCK(p);
	error = proc_get_binpath(p, binpath, &fullpath, &freepath);
	if (error == 0)
		sbuf_cat(sb, fullpath);
	free(binpath, M_TEMP);
	free(freepath, M_TEMP);
	return (error);
}

/*
 * Filler function for proc/curproc
 */
int
linprocfs_common_docurproc(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "%ld", (long)td->td_proc->p_pid);
	return (0);
}

static int
linprocfs_common_attr(PFS_ATTR_ARGS, int mode) {
	vap->va_mode = mode;
	if (p != NULL) {
		PROC_LOCK_ASSERT(p, MA_OWNED);

		if ((p->p_flag & P_SUGID) && pn->pn_type != pfstype_procdir)
			vap->va_mode = 0;
	}

	return (0);
}


int
linprocfs_common_attr_rw(PFS_ATTR_ARGS)
{

	return (linprocfs_common_attr(td, p, pn, vap, 0600));
}


/*
 * Visibility: some files only exist for non-system processes
 * Shared by Linux process and task entries.
 */
int
linprocfs_common_notsystem(PFS_VIS_ARGS)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	return ((p->p_flag & P_SYSTEM) == 0);
}

/*
 * Visibility: some files are only visible to process that can debug
 * the target process.
 */
int
linprocfs_common_candebug(PFS_VIS_ARGS)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);
	return ((p->p_flag & P_SYSTEM) == 0 && p_candebug(td, p) == 0);
}

/*
 * Copy data in and out of the target process.
 * We do this by mapping the process's page into
 * the kernel and then doing a uiomove direct
 * from the kernel address space.
 */
int
linprocfs_common_doprocmem(PFS_FILL_ARGS)
{
	int error;

	if (uio->uio_resid == 0)
		return (0);

	error = proc_rwmem(p, uio, PRVM_CHECK_DEBUG | PRVM_BLOCK_EXEC);

	return (error);
}

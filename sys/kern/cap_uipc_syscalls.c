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
 * Capability-pure (SYF_CAPREQUIRED) variants of socket syscalls.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/uio.h>

int
sys_cap_bind(struct thread *td, struct cap_bind_args *uap)
{
	struct sockaddr *sa;
	int error;

	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error == 0) {
		error = kern_bindat(td, AT_FDCWD, uap->s, sa, true);
		free(sa, M_SONAME);
	}
	return (error);
}

int
sys_cap_listen(struct thread *td, struct cap_listen_args *uap)
{

	return (kern_listen(td, uap->s, uap->backlog, true));
}

int
sys_cap_accept(struct thread *td, struct cap_accept_args *uap)
{
	struct sockaddr_storage ss = { .ss_len = sizeof(ss) };
	socklen_t addrlen;
	struct file *fp;
	int error;

	if (uap->name != NULL) {
		error = copyin(uap->anamelen, &addrlen, sizeof(addrlen));
		if (error != 0)
			return (error);
	}

	error = kern_accept4(td, uap->s, (struct sockaddr *)&ss,
	    ACCEPT4_INHERIT, &fp, true);

	if (error != 0)
		return (error);

	if (uap->name != NULL) {
		if (addrlen > ss.ss_len)
			addrlen = ss.ss_len;
		error = copyout(&ss, uap->name, addrlen);
		if (error == 0) {
			addrlen = ss.ss_len;
			error = copyout(&addrlen, uap->anamelen,
			    sizeof(addrlen));
		}
	}
	if (error != 0)
		fdclose(td, fp, td->td_retval[0]);
	fdrop(fp, td);
	return (error);
}

int
sys_cap_connect(struct thread *td, struct cap_connect_args *uap)
{
	struct sockaddr *sa;
	int error;

	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error == 0) {
		error = kern_connectat(td, AT_FDCWD, uap->s, sa, true);
		free(sa, M_SONAME);
	}
	return (error);
}

/*
 * sys_cap_sendmsg and sys_cap_recvmsg are in uipc_syscalls.c because
 * they need access to the static sendit()/recvit() helpers.
 */

int
sys_cap_setsockopt(struct thread *td, struct cap_setsockopt_args *uap)
{

	return (kern_setsockopt(td, uap->s, uap->level, uap->name,
	    uap->val, UIO_USERSPACE, uap->valsize, true));
}

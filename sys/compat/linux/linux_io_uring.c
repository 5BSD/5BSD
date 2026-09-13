/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux io_uring front-end.  The completion-ring engine itself is the native
 * "rqueue" core in sys/kern/sys_rqueue.c; this file provides the Linux ABI:
 * the io_uring_setup/enter/register syscalls (which call the kern_rqueue_*
 * KPI with a Linux front-end descriptor) and linux_iou_issue_ext, the opcode
 * extension that delegates the flag/path/sockaddr-translating opcodes to the
 * Linuxulator's own syscall handlers so behaviour matches the direct syscalls.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/callout.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include <sys/io_uring.h>
#include <sys/rqueue.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux.h>
#include <compat/linux/linux_errno.h>

/*
 * Linux front-end opcode extension (registered as ctx->issue_ext): the opcodes
 * that delegate to the Linuxulator's own syscall handlers.  Invoked by the
 * rqueue core for opcodes it does not handle itself.
 */
static int32_t
linux_iou_issue_ext(struct io_uring_ctx *ctx, struct iou_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;

	switch (sqe->opcode) {
	case IORING_OP_TEE: {
		struct linux_tee_args a;

		bzero(&a, sizeof(a));
		a.fd_in = sqe->splice_fd_in;
		a.fd_out = sqe->fd;
		a.len = sqe->len;
		a.flags = sqe->splice_flags;
		return (iou_result(ctx, td, linux_tee(td, &a)));
	}
	case IORING_OP_PIPE: {
		struct linux_pipe2_args a;

		bzero(&a, sizeof(a));
		a.pipefds = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->pipe_flags;
		return (iou_result(ctx, td, linux_pipe2(td, &a)));
	}
	case IORING_OP_SPLICE: {
		struct linux_splice_args a;

		/*
		 * io_uring passes offsets by value; we support the pipe /
		 * current-position case where both are -1 (NULL to splice).
		 */
		if (sqe->splice_off_in != (uint64_t)-1 ||
		    sqe->off != (uint64_t)-1)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.fd_in = sqe->splice_fd_in;
		a.off_in = NULL;
		a.fd_out = sqe->fd;
		a.off_out = NULL;
		a.len = sqe->len;
		a.flags = sqe->splice_flags;
		return (iou_result(ctx, td, linux_splice(td, &a)));
	}
	case IORING_OP_EPOLL_WAIT: {
		struct linux_epoll_pwait_args a;

		bzero(&a, sizeof(a));
		a.epfd = sqe->fd;
		a.events = (void *)(uintptr_t)sqe->addr;
		a.maxevents = (int)sqe->len;
		a.timeout = 0;
		a.mask = NULL;
		a.sigsetsize = 0;
		return (iou_result(ctx, td, linux_epoll_pwait(td, &a)));
	}
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC: {
		int32_t r;

		if (sqe->opcode == IORING_OP_SEND_ZC) {
			struct linux_sendto_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.len = sqe->len;
			a.flags = sqe->msg_flags;
			a.to = (l_uintptr_t)sqe->addr2;
			a.tolen = sqe->addr_len;
			r = iou_result(ctx, td, linux_sendto(td, &a));
		} else {
			struct linux_sendmsg_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.flags = sqe->msg_flags;
			r = iou_result(ctx, td, linux_sendmsg(td, &a));
		}
		mtx_lock(&ctx->mtx);
		if (r < 0) {
			iou_post_cqe(ctx, req->user_data, r, 0);
		} else {
			iou_post_cqe(ctx, req->user_data, r, IORING_CQE_F_MORE);
			iou_post_cqe(ctx, req->user_data,
			    (int32_t)IORING_NOTIF_USAGE_ZC_COPIED,
			    IORING_CQE_F_NOTIF);
		}
		mtx_unlock(&ctx->mtx);
		req->posted = true;
		return (r);
	}
	case IORING_OP_FUTEX_WAKE: {
		struct linux_futex_wake_args a;

		bzero(&a, sizeof(a));
		a.uaddr = (void *)(uintptr_t)sqe->addr;
		a.mask = sqe->addr3;
		a.nr = (int)sqe->off;
		a.flags = sqe->futex_flags;
		return (iou_result(ctx, td, linux_futex_wake(td, &a)));
	}
	case IORING_OP_FUTEX_WAIT: {
		struct linux_futex_wait_args a;

		bzero(&a, sizeof(a));
		a.uaddr = (void *)(uintptr_t)sqe->addr;
		a.val = sqe->off;
		a.mask = sqe->addr3;
		a.flags = sqe->futex_flags;
		a.timeout = NULL;
		a.clockid = 0;
		return (iou_result(ctx, td, linux_futex_wait(td, &a)));
	}
	case IORING_OP_FUTEX_WAITV: {
		struct linux_futex_waitv_args a;

		bzero(&a, sizeof(a));
		a.waiters = (void *)(uintptr_t)sqe->addr;
		a.nr_futexes = sqe->len;
		a.flags = 0;
		a.timeout = NULL;
		a.clockid = 0;
		return (iou_result(ctx, td, linux_futex_waitv(td, &a)));
	}
	case IORING_OP_WAITID: {
		struct linux_waitid_args a;

		bzero(&a, sizeof(a));
		a.idtype = (int)sqe->len;
		a.id = (int)sqe->fd;
		a.info = (void *)(uintptr_t)sqe->addr2;
		a.options = (int)sqe->file_index;
		a.rusage = NULL;
		return (iou_result(ctx, td, linux_waitid(td, &a)));
	}
	case IORING_OP_OPENAT: {
		struct linux_openat_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->open_flags;
		a.mode = sqe->len;
		return (iou_result(ctx, td, linux_openat(td, &a)));
	}
	case IORING_OP_OPENAT2: {
		struct linux_openat2_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.how = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_openat2(td, &a)));
	}
	case IORING_OP_STATX: {
		struct linux_statx_args a;

		bzero(&a, sizeof(a));
		a.dirfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->statx_flags;
		a.mask = sqe->len;
		a.statxbuf = (void *)(uintptr_t)sqe->addr2;
		return (iou_result(ctx, td, linux_statx(td, &a)));
	}
	case IORING_OP_RENAMEAT: {
		struct linux_renameat2_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flags = sqe->rename_flags;
		return (iou_result(ctx, td, linux_renameat2(td, &a)));
	}
	case IORING_OP_UNLINKAT: {
		struct linux_unlinkat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flag = sqe->unlink_flags;
		return (iou_result(ctx, td, linux_unlinkat(td, &a)));
	}
	case IORING_OP_MKDIRAT: {
		struct linux_mkdirat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.mode = sqe->len;
		return (iou_result(ctx, td, linux_mkdirat(td, &a)));
	}
	case IORING_OP_SYMLINKAT: {
		struct linux_symlinkat_args a;

		bzero(&a, sizeof(a));
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = sqe->fd;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		return (iou_result(ctx, td, linux_symlinkat(td, &a)));
	}
	case IORING_OP_LINKAT: {
		struct linux_linkat_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flag = sqe->hardlink_flags;
		return (iou_result(ctx, td, linux_linkat(td, &a)));
	}
	case IORING_OP_MADVISE: {
		struct linux_madvise_args a;

		bzero(&a, sizeof(a));
		a.addr = (l_ulong)sqe->addr;
		a.len = sqe->len;
		a.behav = sqe->fadvise_advice;
		return (iou_result(ctx, td, linux_madvise(td, &a)));
	}
	case IORING_OP_SYNC_FILE_RANGE: {
		struct linux_sync_file_range_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.offset = (off_t)sqe->off;
		a.nbytes = (off_t)sqe->len;
		a.flags = sqe->sync_range_flags;
		return (iou_result(ctx, td, linux_sync_file_range(td, &a)));
	}
	case IORING_OP_SOCKET: {
		struct linux_socket_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.domain = sqe->fd;
		a.type = (int)sqe->off;
		a.protocol = (int)sqe->len;
		return (iou_result(ctx, td, linux_socket(td, &a)));
	}
	case IORING_OP_CONNECT: {
		struct linux_connect_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->off;
		return (iou_result(ctx, td, linux_connect(td, &a)));
	}
	case IORING_OP_ACCEPT: {
		struct linux_accept4_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.addr = (l_uintptr_t)sqe->addr;
		a.namelen = (l_uintptr_t)sqe->addr2;
		a.flags = sqe->accept_flags;
		return (iou_result(ctx, td, linux_accept4(td, &a)));
	}
	case IORING_OP_BIND: {
		struct linux_bind_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->addr2;
		return (iou_result(ctx, td, linux_bind(td, &a)));
	}
	case IORING_OP_LISTEN: {
		struct linux_listen_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.backlog = (int)sqe->len;
		return (iou_result(ctx, td, linux_listen(td, &a)));
	}
	case IORING_OP_SHUTDOWN: {
		struct linux_shutdown_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.how = (int)sqe->len;
		return (iou_result(ctx, td, linux_shutdown(td, &a)));
	}
	case IORING_OP_SEND: {
		struct linux_sendto_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.len = sqe->len;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		a.to = (l_uintptr_t)sqe->addr2;
		a.tolen = sqe->addr_len;
		return (iou_result(ctx, td, linux_sendto(td, &a)));
	}
	case IORING_OP_RECV: {
		struct linux_recvfrom_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.buf = (l_uintptr_t)sqe->addr;
		a.len = sqe->len;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_recvfrom(td, &a)));
	}
	case IORING_OP_SENDMSG: {
		struct linux_sendmsg_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_sendmsg(td, &a)));
	}
	case IORING_OP_RECVMSG: {
		struct linux_recvmsg_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_recvmsg(td, &a)));
	}
	case IORING_OP_EPOLL_CTL: {
		struct linux_epoll_ctl_args a;

		bzero(&a, sizeof(a));
		a.epfd = sqe->fd;
		a.op = (int)sqe->len;
		a.fd = (int)sqe->off;
		a.event = (void *)(uintptr_t)sqe->addr;
		return (iou_result(ctx, td, linux_epoll_ctl(td, &a)));
	}
	case IORING_OP_FSETXATTR: {
		struct linux_fsetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (iou_result(ctx, td, linux_fsetxattr(td, &a)));
	}
	case IORING_OP_SETXATTR: {
		struct linux_setxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (iou_result(ctx, td, linux_setxattr(td, &a)));
	}
	case IORING_OP_FGETXATTR: {
		struct linux_fgetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_fgetxattr(td, &a)));
	}
	case IORING_OP_GETXATTR: {
		struct linux_getxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_getxattr(td, &a)));
	}
	default:
		return (iou_err(ctx, EINVAL));
	}
}

/* ---- Linux front-end ---- */
static const struct iou_frontend linux_frontend = {
	.is_linux = true,
	.err_xlate = bsd_to_linux_errno,
	.issue_ext = linux_iou_issue_ext,
};

int
linux_io_uring_setup(struct thread *td, struct linux_io_uring_setup_args *args)
{
	struct io_uring_params p;
	int error, fd;

	error = copyin(args->params, &p, sizeof(p));
	if (error != 0)
		return (error);
	error = kern_rqueue_setup(td, args->entries, &p, &linux_frontend, &fd);
	if (error != 0)
		return (error);
	error = copyout(&p, args->params, sizeof(p));
	if (error != 0) {
		(void)kern_close(td, fd);
		return (error);
	}
	td->td_retval[0] = fd;
	return (0);
}

int
linux_io_uring_enter(struct thread *td, struct linux_io_uring_enter_args *args)
{

	return (kern_rqueue_enter(td, args->fd, args->to_submit,
	    args->min_complete, args->flags, NULL, 0));
}

int
linux_io_uring_register(struct thread *td,
    struct linux_io_uring_register_args *args)
{

	return (kern_rqueue_register(td, args->fd, args->opcode,
	    args->arg, args->nr_args));
}

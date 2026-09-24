/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux io_uring front-end.  The completion-ring engine itself is the native
 * "squeue" core in sys/kern/sys_squeue.c; this file provides the Linux ABI:
 * the io_uring_setup/enter/register syscalls (which call the kern_squeue_*
 * KPI with a Linux front-end descriptor) and linux_iou_issue_ext, the opcode
 * extension that delegates the flag/path/sockaddr-translating opcodes to the
 * Linuxulator's own syscall handlers so behaviour matches the direct syscalls.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/queue.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/domain.h>
#include <sys/filio.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

#include <sys/io_uring.h>
#include <sys/squeue.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif
#include <compat/linux/linux_util.h>
#include <compat/linux/linux.h>
#include <compat/linux/linux_common.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_futex.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_socket.h>
#include <compat/linux/linux_time.h>

struct linux_iou_waitid_state {
	struct linux_iou_waitid_spec spec;
};

static void
linux_iou_waitid_cancel(void *arg __unused)
{
	/* The shared engine wakes the process-context poller after cancellation. */
}

static void
linux_iou_waitid_activate(void *arg __unused)
{
}

static int32_t
linux_iou_waitid_poll(struct sq_req *req, struct thread *td)
{
	struct linux_iou_waitid_state *state = req->ext_arg;
	struct squeue_ctx *ctx = req->ctx;
	bool cancelled, pending;
	int error;

	mtx_lock(&ctx->mtx);
	cancelled = req->cancel_requested;
	mtx_unlock(&ctx->mtx);
	if (cancelled) {
		const l_int signo = 0;

		if (state->spec.info != NULL)
			(void)copyout(&signo, &state->spec.info->lsi_signo,
			    sizeof(signo));
		free(state, M_LINUX);
		return (sq_err(ctx, ECANCELED));
	}
	error = linux_iou_waitid_probe(td, &state->spec, &pending);
	if (pending)
		return (SQ_EXT_PENDING);
	free(state, M_LINUX);
	return (sq_result(ctx, td, error));
}

static int32_t
linux_iou_waitid_issue(struct sq_req *req, struct thread *td)
{
	struct linux_iou_waitid_state *state;
	struct squeue_ctx *ctx = req->ctx;
	const struct io_uring_sqe *sqe = &req->sqe;
	bool pending;
	int error;

	state = malloc(sizeof(*state), M_LINUX, M_WAITOK | M_ZERO);
	error = linux_iou_waitid_prepare(td, (int)sqe->len,
	    (int)sqe->fd, (int)sqe->file_index,
	    (void *)(uintptr_t)sqe->addr2, &state->spec);
	if (error == 0)
		error = linux_iou_waitid_probe(td, &state->spec, &pending);
	if (error != 0 || !pending) {
		free(state, M_LINUX);
		return (sq_result(ctx, td, error));
	}
	error = sq_ext_poll_start(ctx, td);
	if (error == 0)
		error = sq_ext_park(req, state, linux_iou_waitid_cancel,
		    linux_iou_waitid_activate);
	if (error != 0) {
		free(state, M_LINUX);
		return (sq_err(ctx, error));
	}
	return (SQ_EXT_PENDING);
}

static int
linux_iou_socket_fd(struct thread *td, int fd)
{
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_SOCKET)
		error = ENOTSOCK;
	fdrop(fp, td);
	return (error);
}

static uint32_t
linux_iou_bundle_used(const struct sq_pbuf_desc *bufs, uint32_t nbufs,
    int32_t result)
{
	uint32_t i;
	int32_t left;

	if (result <= 0)
		return (0);
	left = result;
	for (i = 0; i < nbufs; i++) {
		if (left <= (int32_t)bufs[i].len)
			return (i + 1);
		left -= bufs[i].len;
	}
	return (nbufs);
}

/*
 * SEND/RECV bundle policy is Linux-specific, but detaching and returning the
 * provided-buffer run is a shared squeue operation.  The socket helper accepts
 * a kernel iovec whose bases remain Linux user addresses.
 */
static int32_t
linux_iou_issue_bundle(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td, bool send)
{
	const struct io_uring_sqe *sqe;
	struct sq_pbuf_desc *bufs;
	struct iovec *iov;
	struct uio uio;
	struct l_msghdr msg;
	uint64_t want;
	uint32_t i, nbufs, used;
	int32_t res;
	int error;
	size_t total;
	bool full, terminal;

	sqe = &req->sqe;
	bufs = mallocarray(UIO_MAXIOV, sizeof(*bufs), M_LINUX, M_WAITOK);
	iov = mallocarray(UIO_MAXIOV, sizeof(*iov), M_LINUX, M_WAITOK);
	want = sqe->len == 0 ? 0x7fffffffU : MIN((uint64_t)sqe->len, UINT64_C(0x7fffffff));
	if (!send && req->net_mshot_remaining != 0)
		want = MIN(want, req->net_mshot_remaining);
	/* Legacy multishot consumes one buffer per CQE; PBUF_RING may span many. */
	error = sq_select_buffer_batch(ctx, sqe->buf_group, want, bufs,
	    UIO_MAXIOV, !send && req->net_multishot ? 1 : UIO_MAXIOV,
	    &nbufs);
	if (error != 0) {
		free(iov, M_LINUX);
		free(bufs, M_LINUX);
		return (sq_err(ctx, error));
	}
	total = 0;
	for (i = 0; i < nbufs; i++) {
		iov[i].iov_base = (void *)(uintptr_t)bufs[i].addr;
		iov[i].iov_len = bufs[i].len;
		total += bufs[i].len;
	}
	bzero(&uio, sizeof(uio));
	uio.uio_iov = iov;
	uio.uio_iovcnt = nbufs;
	uio.uio_offset = 0;
	uio.uio_resid = total;
	uio.uio_segflg = UIO_USERSPACE;
	uio.uio_rw = send ? UIO_WRITE : UIO_READ;
	uio.uio_td = td;
	if (send) {
		bzero(&msg, sizeof(msg));
		msg.msg_name = sqe->addr2;
		msg.msg_namelen = sqe->addr_len;
		error = linux_sendmsg_kbuf_uring(td, sqe->fd, &msg,
		    sqe->msg_flags | SQ_MSG_DONTWAIT, &uio);
	} else {
		error = linux_recvmsg_kbuf_uring(td, sqe->fd,
		    sqe->msg_flags | SQ_MSG_DONTWAIT, &uio);
	}
	res = sq_result(ctx, td, error);
	used = linux_iou_bundle_used(bufs, nbufs, res);
	if (used == 0) {
		sq_commit_buffer_batch(ctx, sqe->buf_group, bufs, nbufs, 0, 0);
		free(iov, M_LINUX);
		free(bufs, M_LINUX);
		return (res);
	}
	req->cflags = IORING_CQE_F_BUFFER |
	    ((uint32_t)bufs[0].bid << IORING_CQE_BUFFER_SHIFT);
	if (sq_commit_buffer_batch(ctx, sqe->buf_group, bufs, nbufs, used,
	    (uint32_t)res))
		req->cflags |= IORING_CQE_F_BUF_MORE;
	full = (size_t)res == total;
	terminal = send ? !full : false;
	if (!send && req->net_mshot_remaining != 0) {
		req->net_mshot_remaining -= MIN((uint32_t)res,
		    req->net_mshot_remaining);
		if (req->net_mshot_remaining == 0)
			terminal = true;
	}
	if ((send || req->net_multishot) &&
	    sq_buffer_group_empty(ctx, sqe->buf_group))
		terminal = true;
	if ((!send && req->net_multishot && !terminal) ||
	    (send && !terminal)) {
		mtx_lock(&ctx->mtx);
		sq_post_multishot_cqe(ctx, req, res,
		    req->cflags | IORING_CQE_F_MORE);
		mtx_unlock(&ctx->mtx);
		free(iov, M_LINUX);
		free(bufs, M_LINUX);
		return (sq_err(ctx, EAGAIN));
	}
	free(iov, M_LINUX);
	free(bufs, M_LINUX);
	return (res);
}

static int32_t
linux_iou_fd_result(struct squeue_ctx *ctx, struct thread *td, int error,
    uint32_t file_index)
{
	int32_t direct, result;

	result = sq_result(ctx, td, error);
	if (result < 0 || file_index == 0)
		return (result);
	error = sq_install_direct_fd(ctx, td, result, file_index, &direct);
	return (error == 0 ? direct : sq_err(ctx, error));
}

/* File-specific Linux socket URING_CMD commands. */
static int32_t
linux_iou_uring_cmd(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe,
    struct thread *td)
{
    struct linux_setsockopt_args a;
    struct linux_getsockname_args sn;
    struct linux_getpeername_args pn;
    struct socket *so;
    struct file *fp;
    int32_t result;
    int error, family, value;

    if (sqe->opcode == IORING_OP_URING_CMD128 &&
        ctx->sqe_stride != 2 * sizeof(*sqe) &&
        (ctx->setup_flags & IORING_SETUP_SQE_MIXED) == 0)
        return (sq_err(ctx, EINVAL));
    if (sqe->__pad1 != 0 ||
        (sqe->uring_cmd_flags & ~IORING_URING_CMD_MASK) != 0 ||
        (sqe->uring_cmd_flags & IORING_URING_CMD_MULTISHOT) != 0 ||
        (sqe->flags & IOSQE_BUFFER_SELECT) != 0 ||
        (sqe->uring_cmd_flags & IORING_URING_CMD_FIXED) != 0)
        return (sq_err(ctx, EINVAL));
    error = fget(td, sqe->fd, &cap_no_rights, &fp);
    if (error != 0)
        return (sq_err(ctx, error));
    if (fp->f_type != DTYPE_SOCKET) {
        fdrop(fp, td);
        return (sq_err(ctx, EOPNOTSUPP));
    }
    so = fp->f_data;
    family = so->so_proto->pr_domain->dom_family;
    fdrop(fp, td);
    switch (sqe->cmd_op) {
    case SOCKET_URING_OP_SIOCINQ:
    case SOCKET_URING_OP_SIOCOUTQ:
        if (family != AF_INET && family != AF_INET6)
            return (sq_err(ctx, EOPNOTSUPP));
        value = 0;
        error = kern_ioctl(td, sqe->fd,
            sqe->cmd_op == SOCKET_URING_OP_SIOCINQ ? FIONREAD : FIONWRITE,
            (caddr_t)&value);
        return (error != 0 ? sq_err(ctx, error) : value);
    case SOCKET_URING_OP_GETSOCKOPT:
    case SOCKET_URING_OP_SETSOCKOPT:
        if (sqe->ioprio != 0 || sqe->len != 0)
            return (sq_err(ctx, EINVAL));
        if (sqe->cmd_op == SOCKET_URING_OP_GETSOCKOPT) {
            error = linux_getsockopt_uring(td, sqe->fd, sqe->level,
                sqe->optname, (void *)(uintptr_t)sqe->optval,
                sqe->optlen, &result);
            return (error != 0 ? sq_err(ctx, error) : result);
        }
        bzero(&a, sizeof(a));
        a.s = sqe->fd;
        a.level = sqe->level;
        a.optname = sqe->optname;
        a.optval = sqe->optval;
        a.optlen = sqe->optlen;
        error = linux_setsockopt(td, &a);
        return (error != 0 ? sq_err(ctx, error) : 0);
    case SOCKET_URING_OP_GETSOCKNAME:
        if (sqe->ioprio != 0 || sqe->len != 0 ||
            sqe->uring_cmd_flags != 0 || sqe->optlen > 1)
            return (sq_err(ctx, EINVAL));
        if (sqe->optlen == 0) {
            bzero(&sn, sizeof(sn));
            sn.s = sqe->fd;
            sn.addr = sqe->addr;
            sn.namelen = sqe->addr3;
            error = linux_getsockname(td, &sn);
        } else {
            bzero(&pn, sizeof(pn));
            pn.s = sqe->fd;
            pn.addr = sqe->addr;
            pn.namelen = sqe->addr3;
            error = linux_getpeername(td, &pn);
        }
        return (error != 0 ? sq_err(ctx, error) : 0);
    default:
        return (sq_err(ctx, EOPNOTSUPP));
    }
}

/*
 * io_uring resolves and pins a request file before FTRUNCATE execution.
 * Preserve that ordering here: for an invalid fd plus a negative length Linux
 * reports EBADF, whereas the direct syscall and kern_ftruncate() validate the
 * length first and report EINVAL.
 */
static int
linux_iou_ftruncate(struct thread *td, int fd, off_t length)
{
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_ftruncate_rights, &fp);
	if (error != 0)
		return (error);
	if (length < 0)
		error = EINVAL;
	else if ((fp->f_flag & FWRITE) == 0)
		error = EINVAL;
	else
		error = fo_truncate(fp, length, td->td_ucred, td);
	fdrop(fp, td);
	return (error);
}

/*
 * Linux front-end opcode extension (registered as ctx->issue_ext): the opcodes
 * that delegate to the Linuxulator's own syscall handlers.  Invoked by the
 * squeue core for opcodes it does not handle itself.
 */
static int32_t
linux_iou_issue_ext(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;

	switch (sqe->opcode) {
	case IORING_OP_URING_CMD:
	case IORING_OP_URING_CMD128:
		return (linux_iou_uring_cmd(ctx, sqe, td));
	case IORING_OP_FTRUNCATE:
		return (sq_result(ctx, td, linux_iou_ftruncate(td, sqe->fd,
		    (off_t)sqe->off)));
	case IORING_OP_FADVISE:
		return (sq_result(ctx, td, linux_kern_fadvise(td, sqe->fd,
		    (off_t)sqe->off, sqe->addr != 0 ? (off_t)sqe->addr :
		    (off_t)sqe->len, sqe->fadvise_advice)));
	case IORING_OP_FALLOCATE: {
		struct file *fp;
		int error;

		/* Linux io_uring resolves and pins the request file before
		 * vfs_fallocate() validates mode and range arguments. */
		error = fget(td, sqe->fd, &cap_pwrite_rights, &fp);
		if (error == 0) {
			error = linux_kern_fallocate_fp(td, fp, sqe->len,
			    (off_t)sqe->off, (off_t)sqe->addr);
			fdrop(fp, td);
		}
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_TEE: {
		struct linux_tee_args a;
		int error, fd_in;
		bool fixed_in;

		if ((sqe->splice_flags &
		    ~(LINUX_SPLICE_F_ALL | SPLICE_F_FD_IN_FIXED)) != 0)
			return (sq_err(ctx, EINVAL));
		fixed_in = (sqe->splice_flags & SPLICE_F_FD_IN_FIXED) != 0;
		fd_in = sqe->splice_fd_in;
		if (fixed_in) {
			error = sq_install_registered_fd(ctx, td, fd_in, &fd_in);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		bzero(&a, sizeof(a));
		a.fd_in = fd_in;
		a.fd_out = sqe->fd;
		a.len = sqe->len;
		a.flags = sqe->splice_flags & ~SPLICE_F_FD_IN_FIXED;
		error = linux_tee(td, &a);
		if (fixed_in)
			(void)kern_close(td, fd_in);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_PIPE: {
		struct linux_pipe2_args a;
		int fds[2], error;

		bzero(&a, sizeof(a));
		a.pipefds = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->pipe_flags;
		if (sqe->file_index == 0)
			return (sq_result(ctx, td, linux_pipe2(td, &a)));
		if ((sqe->pipe_flags & LINUX_O_CLOEXEC) != 0)
			return (sq_err(ctx, EINVAL));
		error = linux_kern_pipe2(td, fds, sqe->pipe_flags);
		if (error != 0)
			return (sq_result(ctx, td, error));
		error = sq_install_direct_fds(ctx, td, fds, sqe->file_index,
		    sqe->addr);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_SPLICE: {
		off_t off_in, off_out;
		int error, fd_in;
		bool fixed_in;

		if ((sqe->splice_flags &
		    ~(LINUX_SPLICE_F_ALL | SPLICE_F_FD_IN_FIXED)) != 0)
			return (sq_err(ctx, EINVAL));
		fixed_in = (sqe->splice_flags & SPLICE_F_FD_IN_FIXED) != 0;
		fd_in = sqe->splice_fd_in;
		if (fixed_in) {
			error = sq_install_registered_fd(ctx, td, fd_in, &fd_in);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		/* SQE offsets are values, not pointers to userspace offsets. */
		off_in = (off_t)sqe->splice_off_in;
		off_out = (off_t)sqe->off;
		error = linux_kern_splice(td, fd_in,
		    off_in == -1 ? NULL : &off_in, sqe->fd,
		    off_out == -1 ? NULL : &off_out, sqe->len,
		    sqe->splice_flags & ~SPLICE_F_FD_IN_FIXED);
		if (fixed_in)
			(void)kern_close(td, fd_in);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_EPOLL_WAIT: {
		struct linux_epoll_pwait_args a;
		int32_t res;
		int error, epfd;

		/* Linux rejects these reserved SQE fields before issuing the wait. */
		if (sqe->off != 0 || sqe->rw_flags != 0 ||
		    sqe->buf_index != 0 || sqe->splice_fd_in != 0)
			return (sq_err(ctx, EINVAL));
		epfd = sqe->fd;
		if (req->poll_use_held_fd) {
			error = sq_install_held_fd(req, td, &epfd);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		bzero(&a, sizeof(a));
		a.epfd = epfd;
		a.events = (void *)(uintptr_t)sqe->addr;
		a.maxevents = (int)sqe->len;
		a.timeout = 0;
		a.mask = NULL;
		a.sigsetsize = 0;
		error = linux_epoll_pwait(td, &a);
		res = error == 0 && td->td_retval[0] == 0 ?
		    sq_err(ctx, EAGAIN) : sq_result(ctx, td, error);
		if (req->poll_use_held_fd)
			(void)kern_close(td, epfd);
		return (res);
	}
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC: {
		int32_t r;
		int error;
		uint32_t send_flags;

		send_flags = sqe->msg_flags | SQ_MSG_DONTWAIT |
		    LINUX_MSG_NOSIGNAL;

		if ((sqe->ioprio & IORING_RECVSEND_FIXED_BUF) != 0) {
			struct l_msghdr msg;
			bool vec;

			bzero(&msg, sizeof(msg));
			vec = sqe->opcode == IORING_OP_SENDMSG_ZC ||
			    (sqe->ioprio & IORING_SEND_VECTORIZED) != 0;
			if (sqe->opcode == IORING_OP_SENDMSG_ZC) {
				error = copyin((void *)(uintptr_t)sqe->addr, &msg,
				    sizeof(msg));
				if (error != 0) {
					r = sq_err(ctx, error);
					goto zc_complete;
				}
				if (msg.msg_iovlen > UIO_MAXIOV) {
					r = sq_err(ctx, EMSGSIZE);
					goto zc_complete;
				}
			} else {
				msg.msg_name = sqe->addr2;
				msg.msg_namelen = sqe->addr_len;
				if (vec) {
					msg.msg_iov = sqe->addr;
					msg.msg_iovlen = sqe->len;
				}
			}
			if (vec)
				error = sq_prepare_fixed_buffer(ctx, req, msg.msg_iov,
				    (uint32_t)msg.msg_iovlen, true);
			else
				error = sq_prepare_fixed_buffer(ctx, req, sqe->addr,
				    sqe->len, false);
			if (error != 0) {
				r = sq_err(ctx, error);
				goto zc_complete;
			}
			if (vec && msg.msg_iovlen == 0) {
				r = 0;
				goto zc_complete;
			}
			r = sq_result(ctx, td, linux_sendmsg_kbuf_uring(td,
			    sqe->fd, &msg, send_flags,
			    req->buf_uio));
		} else if (sqe->opcode == IORING_OP_SEND_ZC &&
		    (sqe->ioprio & IORING_SEND_VECTORIZED) != 0) {
			struct l_msghdr msg;

			bzero(&msg, sizeof(msg));
			msg.msg_name = sqe->addr2;
			msg.msg_namelen = sqe->addr_len;
			msg.msg_iov = sqe->addr;
			msg.msg_iovlen = sqe->len;
			r = sq_result(ctx, td, linux_sendmsg_uring(td, sqe->fd,
			    &msg, send_flags));
		} else if (sqe->opcode == IORING_OP_SEND_ZC) {
			struct linux_sendto_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.len = sqe->len;
			a.flags = send_flags;
			a.to = (l_uintptr_t)sqe->addr2;
			a.tolen = sqe->addr_len;
			r = sq_result(ctx, td, linux_sendto(td, &a));
		} else {
			struct linux_sendmsg_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.flags = send_flags;
			r = sq_result(ctx, td, linux_sendmsg(td, &a));
		}
zc_complete:
		if (r == sq_err(ctx, EAGAIN))
			return (r);
		mtx_lock(&ctx->mtx);
		/* A prepared zero-copy send always owns a notification CQE. */
		sq_post_cqe(ctx, req->user_data, r, IORING_CQE_F_MORE);
		sq_post_cqe(ctx, req->sqe.addr3 != 0 ? req->sqe.addr3 :
		    req->user_data,
		    (req->sqe.ioprio & IORING_SEND_ZC_REPORT_USAGE) != 0 ?
		    (int32_t)IORING_NOTIF_USAGE_ZC_COPIED : 0,
		    IORING_CQE_F_NOTIF);
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
		req->posted = true;
		return (r);
	}
	case IORING_OP_FUTEX_WAKE: {
		struct linux_futex_wake_args a;

		if (sqe->len != 0 || sqe->futex_flags != 0 ||
		    sqe->buf_index != 0 || sqe->file_index != 0)
			return (sq_err(ctx, EINVAL));
		bzero(&a, sizeof(a));
		a.uaddr = (void *)(uintptr_t)sqe->addr;
		a.mask = sqe->addr3;
		a.nr = (int)sqe->off;
		a.flags = sqe->fd;
		return (sq_result(ctx, td, linux_futex_wake(td, &a)));
	}
	case IORING_OP_FUTEX_WAIT:
		if (sqe->len != 0 || sqe->futex_flags != 0 ||
		    sqe->buf_index != 0 || sqe->file_index != 0)
			return (sq_err(ctx, EINVAL));
		return (linux_futex_iou_wait(req, td, false));
	case IORING_OP_FUTEX_WAITV:
		if (sqe->fd != 0 || sqe->addr2 != 0 || sqe->addr3 != 0 ||
		    sqe->futex_flags != 0 || sqe->buf_index != 0 ||
		    sqe->file_index != 0)
			return (sq_err(ctx, EINVAL));
		return (linux_futex_iou_wait(req, td, true));
	case IORING_OP_WAITID:
		if (sqe->addr != 0 || sqe->buf_index != 0 ||
		    sqe->addr3 != 0 || sqe->waitid_flags != 0)
			return (sq_err(ctx, EINVAL));
		return (linux_iou_waitid_issue(req, td));
	case IORING_OP_OPENAT: {
		struct linux_openat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->open_flags;
		a.mode = sqe->len;
		return (linux_iou_fd_result(ctx, td, linux_openat(td, &a),
		    sqe->file_index));
	}
	case IORING_OP_OPENAT2: {
		struct linux_openat2_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.how = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (linux_iou_fd_result(ctx, td, linux_openat2(td, &a),
		    sqe->file_index));
	}
	case IORING_OP_STATX: {
		struct linux_statx_args a;

		bzero(&a, sizeof(a));
		a.dirfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->statx_flags;
		a.mask = sqe->len;
		a.statxbuf = (void *)(uintptr_t)sqe->addr2;
		return (sq_result(ctx, td, linux_statx(td, &a)));
	}
	case IORING_OP_RENAMEAT: {
		struct linux_renameat2_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flags = sqe->rename_flags;
		return (sq_result(ctx, td, linux_renameat2(td, &a)));
	}
	case IORING_OP_UNLINKAT: {
		struct linux_unlinkat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flag = sqe->unlink_flags;
		return (sq_result(ctx, td, linux_unlinkat(td, &a)));
	}
	case IORING_OP_MKDIRAT: {
		struct linux_mkdirat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.mode = sqe->len;
		return (sq_result(ctx, td, linux_mkdirat(td, &a)));
	}
	case IORING_OP_SYMLINKAT: {
		struct linux_symlinkat_args a;

		bzero(&a, sizeof(a));
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = sqe->fd;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		return (sq_result(ctx, td, linux_symlinkat(td, &a)));
	}
	case IORING_OP_LINKAT: {
		struct linux_linkat_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flag = sqe->hardlink_flags;
		return (sq_result(ctx, td, linux_linkat(td, &a)));
	}
	case IORING_OP_MADVISE: {
		struct linux_madvise_args a;

		bzero(&a, sizeof(a));
#ifdef COMPAT_LINUX32
		a.addr = (void *)(uintptr_t)sqe->addr;
#else
		a.addr = (l_ulong)sqe->addr;
#endif
		/*
		 * Linux added the 64-bit off field as the preferred MADVISE
		 * length while retaining len as the compatibility fallback.
		 */
		a.len = sqe->off != 0 ? sqe->off : sqe->len;
		a.behav = sqe->fadvise_advice;
		return (sq_result(ctx, td, linux_madvise(td, &a)));
	}
	case IORING_OP_SYNC_FILE_RANGE: {
		struct linux_sync_file_range_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
#ifdef COMPAT_LINUX32
		a.offset1 = (uint32_t)sqe->off;
		a.offset2 = (uint32_t)(sqe->off >> 32);
		a.nbytes1 = sqe->len;
		a.nbytes2 = 0;
#else
		a.offset = (off_t)sqe->off;
		a.nbytes = (off_t)sqe->len;
#endif
		a.flags = sqe->sync_range_flags;
		return (sq_result(ctx, td, linux_sync_file_range(td, &a)));
	}
	case IORING_OP_SOCKET: {
		struct linux_socket_args a;

		bzero(&a, sizeof(a));
		a.domain = sqe->fd;
		a.type = (int)sqe->off;
		a.protocol = (int)sqe->len;
		return (linux_iou_fd_result(ctx, td, linux_socket(td, &a),
		    sqe->file_index));
	}
	case IORING_OP_CONNECT: {
		struct linux_connect_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->off;
		return (sq_result(ctx, td, linux_connect(td, &a)));
	}
	case IORING_OP_ACCEPT: {
		struct linux_accept4_args a;
		int32_t res;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.addr = (l_uintptr_t)sqe->addr;
		a.namelen = (l_uintptr_t)sqe->addr2;
		a.flags = sqe->accept_flags;
		res = linux_iou_fd_result(ctx, td, linux_accept4(td, &a),
		    sqe->file_index);
		if (req->net_multishot && res >= 0) {
			mtx_lock(&ctx->mtx);
			sq_post_multishot_cqe(ctx, req, res, IORING_CQE_F_MORE);
			mtx_unlock(&ctx->mtx);
			return (sq_err(ctx, EAGAIN));
		}
		return (res);
	}
	case IORING_OP_BIND: {
		struct linux_bind_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->addr2;
		return (sq_result(ctx, td, linux_bind(td, &a)));
	}
	case IORING_OP_LISTEN: {
		struct linux_listen_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.backlog = (int)sqe->len;
		return (sq_result(ctx, td, linux_listen(td, &a)));
	}
	case IORING_OP_SHUTDOWN: {
		struct linux_shutdown_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.how = (int)sqe->len;
		return (sq_result(ctx, td, linux_shutdown(td, &a)));
	}
	case IORING_OP_SEND: {
		struct linux_sendto_args a;
		int error;

		if (req->net_bundle)
			return (linux_iou_issue_bundle(ctx, req, td, true));
		if ((sqe->ioprio & IORING_SEND_VECTORIZED) != 0) {
			struct l_msghdr msg;

			bzero(&msg, sizeof(msg));
			msg.msg_name = sqe->addr2;
			msg.msg_namelen = sqe->addr_len;
			msg.msg_iov = sqe->addr;
			msg.msg_iovlen = sqe->len;
			return (sq_result(ctx, td, linux_sendmsg_uring(td,
			    sqe->fd, &msg, sqe->msg_flags | SQ_MSG_DONTWAIT)));
		}
		if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0) {
			error = linux_iou_socket_fd(td, sqe->fd);
			if (error == 0)
				error = sq_select_buffer(ctx, req, 0);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)(req->pbuf_selected ? req->pbuf_addr :
		    sqe->addr);
		a.len = req->pbuf_selected ? req->pbuf_len : sqe->len;
		a.flags = sqe->msg_flags | SQ_MSG_DONTWAIT;
		a.to = (l_uintptr_t)sqe->addr2;
		a.tolen = sqe->addr_len;
		return (sq_result(ctx, td, linux_sendto(td, &a)));
	}
	case IORING_OP_RECV: {
		struct linux_recvfrom_args a;
		int32_t res;
		int error;

		if (req->net_bundle)
			return (linux_iou_issue_bundle(ctx, req, td, false));
		if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0) {
			error = linux_iou_socket_fd(td, sqe->fd);
			if (error == 0)
				error = sq_select_buffer(ctx, req, sqe->len);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.buf = (l_uintptr_t)(req->pbuf_selected ? req->pbuf_addr :
		    sqe->addr);
		a.len = req->pbuf_selected ? req->pbuf_len : sqe->len;
		a.flags = sqe->msg_flags | SQ_MSG_DONTWAIT;
		res = sq_result(ctx, td, linux_recvfrom(td, &a));
		if (req->net_multishot && res > 0) {
			if (req->net_mshot_remaining != 0) {
				req->net_mshot_remaining -= MIN((uint32_t)res,
				    req->net_mshot_remaining);
				if (req->net_mshot_remaining == 0) {
					req->cflags = sq_consume_buffer(req,
					    (uint32_t)res);
					return (res);
				}
			}
			{
				uint32_t cflags;

				cflags = sq_consume_buffer(req, (uint32_t)res);
				mtx_lock(&ctx->mtx);
				sq_post_multishot_cqe(ctx, req, res,
				    cflags | IORING_CQE_F_MORE);
				mtx_unlock(&ctx->mtx);
			}
			return (sq_err(ctx, EAGAIN));
		}
		if (res != sq_err(ctx, EAGAIN) && res <= 0)
			sq_recycle_buffer(req);
		return (res);
	}
	case IORING_OP_RECV_ZC:
		return (sq_zcrx_recv(ctx, req, td, sqe->zcrx_ifq_idx));
	case IORING_OP_SENDMSG: {
		struct linux_sendmsg_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | SQ_MSG_DONTWAIT;
		return (sq_result(ctx, td, linux_sendmsg(td, &a)));
	}
	case IORING_OP_RECVMSG: {
		struct linux_recvmsg_args a;
		int error;

		if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0) {
			int32_t payload, res;

			error = linux_iou_socket_fd(td, sqe->fd);
			if (error == 0)
				error = sq_select_buffer(ctx, req,
				    req->net_multishot ? 0 : req->pbuf_want);
			if (error != 0)
				return (sq_err(ctx, error));
			if (!req->net_multishot) {
				error = linux_recvmsg_pbuf(td, sqe->fd,
				    (struct l_msghdr *)(uintptr_t)sqe->addr,
				    sqe->msg_flags | SQ_MSG_DONTWAIT,
				    (void *)(uintptr_t)req->pbuf_addr, req->pbuf_len);
				return (sq_result(ctx, td, error));
			}
			error = linux_recvmsg_mshot_uring(td, sqe->fd,
			    sqe->msg_flags | SQ_MSG_DONTWAIT,
			    (void *)(uintptr_t)req->pbuf_addr, req->pbuf_len,
			    req->recvmsg_namelen, req->recvmsg_controllen, &res,
			    &payload);
			if (error != 0) {
				res = sq_err(ctx, error);
				if (error != EAGAIN)
					sq_recycle_buffer(req);
				return (res);
			}
			if (payload == 0) {
				req->cflags = sq_consume_buffer(req,
				    (uint32_t)res);
				return (res);
			}
			{
				uint32_t cflags;

				cflags = sq_consume_buffer(req, (uint32_t)res);
				mtx_lock(&ctx->mtx);
				sq_post_multishot_cqe(ctx, req, res,
				    cflags | IORING_CQE_F_MORE);
				mtx_unlock(&ctx->mtx);
			}
			return (sq_err(ctx, EAGAIN));
		}
		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | SQ_MSG_DONTWAIT;
		return (sq_result(ctx, td, linux_recvmsg(td, &a)));
	}
	case IORING_OP_EPOLL_CTL: {
		struct linux_epoll_ctl_args a;

		bzero(&a, sizeof(a));
		a.epfd = sqe->fd;
		a.op = (int)sqe->len;
		a.fd = (int)sqe->off;
		a.event = (void *)(uintptr_t)sqe->addr;
		return (sq_result(ctx, td, linux_epoll_ctl(td, &a)));
	}
	case IORING_OP_FSETXATTR: {
		struct linux_fsetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (sq_result(ctx, td, linux_fsetxattr(td, &a)));
	}
	case IORING_OP_SETXATTR: {
		struct linux_setxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (sq_result(ctx, td, linux_setxattr(td, &a)));
	}
	case IORING_OP_FGETXATTR: {
		struct linux_fgetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (sq_result(ctx, td, linux_fgetxattr(td, &a)));
	}
	case IORING_OP_GETXATTR: {
		struct linux_getxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (sq_result(ctx, td, linux_getxattr(td, &a)));
	}
	default:
		return (sq_err(ctx, EINVAL));
	}
}

/* Only ABI extension opcodes belong in this front end's probe contribution. */
static bool
linux_iou_op_supported(uint8_t op)
{

	switch (op) {
	case IORING_OP_URING_CMD:
	case IORING_OP_URING_CMD128:
	case IORING_OP_TEE:
	case IORING_OP_PIPE:
	case IORING_OP_SPLICE:
	case IORING_OP_EPOLL_WAIT:
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC:
	case IORING_OP_FUTEX_WAKE:
	case IORING_OP_FUTEX_WAIT:
	case IORING_OP_FUTEX_WAITV:
	case IORING_OP_WAITID:
	case IORING_OP_OPENAT:
	case IORING_OP_OPENAT2:
	case IORING_OP_STATX:
	case IORING_OP_RENAMEAT:
	case IORING_OP_UNLINKAT:
	case IORING_OP_MKDIRAT:
	case IORING_OP_SYMLINKAT:
	case IORING_OP_LINKAT:
	case IORING_OP_MADVISE:
	case IORING_OP_SYNC_FILE_RANGE:
	case IORING_OP_SOCKET:
	case IORING_OP_CONNECT:
	case IORING_OP_ACCEPT:
	case IORING_OP_BIND:
	case IORING_OP_LISTEN:
	case IORING_OP_SHUTDOWN:
	case IORING_OP_SEND:
	case IORING_OP_RECV:
	case IORING_OP_RECV_ZC:
	case IORING_OP_SENDMSG:
	case IORING_OP_RECVMSG:
	case IORING_OP_EPOLL_CTL:
	case IORING_OP_FSETXATTR:
	case IORING_OP_SETXATTR:
	case IORING_OP_FGETXATTR:
	case IORING_OP_GETXATTR:
		return (true);
	default:
		return (false);
	}
}

/* ---- Linux front-end ---- */
static int
linux_iou_rw_flags(uint32_t flags, int *foflags)
{
	int error;

	error = linux_rwf_flags(flags, foflags);
	if (error != 0)
		return (error);
	/* HIPRI requires an IOPOLL ring, which setup currently rejects. */
	return ((flags & LINUX_RWF_HIPRI) != 0 ? EINVAL : 0);
}

/* Match Linux ioprio_check_cap() for the read/write SQE family.  The native
 * backend currently treats valid block-I/O priorities as advisory, but the
 * Linux ABI still requires class/level validation and privilege enforcement. */
static int
linux_iou_rw_ioprio(uint16_t ioprio)
{

	return (linux_ioprio_check_cap(curthread, ioprio));
}

static int
linux_iou_copy_open_how(struct l_open_how *how, const void *src, size_t usize)
{
	char chunk[64];
	const char *p;
	size_t i, left, n;
	int error;

	if (usize < LINUX_OPEN_HOW_SIZE_VER0)
		return (EINVAL);
	if (usize > PAGE_SIZE)
		return (E2BIG);
	bzero(how, sizeof(*how));
	error = copyin(src, how, MIN(sizeof(*how), usize));
	if (error != 0 || usize <= sizeof(*how))
		return (error);
	p = (const char *)src + sizeof(*how);
	for (left = usize - sizeof(*how); left > 0; left -= n, p += n) {
		n = MIN(left, sizeof(chunk));
		error = copyin(p, chunk, n);
		if (error != 0)
			return (error);
		for (i = 0; i < n; i++)
			if (chunk[i] != 0)
				return (E2BIG);
	}
	return (0);
}

static int
linux_iou_validate_sockaddr(uint64_t addr, uint64_t addr2,
    struct sockaddr_storage *result)
{
	struct sockaddr_storage local, *ss;
	int len;

	len = (int)addr2;
	if (len < 0 || len > (int)sizeof(local))
		return (EINVAL);
	ss = result != NULL ? result : &local;
	bzero(ss, sizeof(*ss));
	if (len == 0)
		return (0);
	return (copyin((const void *)(uintptr_t)addr, ss, len));
}

static int
linux_iou_validate_path(uint64_t addr)
{
	char *path;
	int error;

	path = malloc(PATH_MAX, M_LINUX, M_WAITOK);
	error = copyinstr((const void *)(uintptr_t)addr, path, PATH_MAX, NULL);
	free(path, M_LINUX);
	return (error);
}

static int
linux_iou_prepare_ext(struct sq_req *req)
{
	struct l_msghdr msg;
	struct iovec iov;
	int error;

	switch (req->opcode) {
	case IORING_OP_CONNECT: {
		struct io_uring_bpf_ctx bctx;
		struct sockaddr_storage ss;
		uint16_t family;

		family = 0;
		/* Retain the imported address fields used by request filters. */
		error = linux_iou_validate_sockaddr(req->sqe.addr,
		    req->sqe.addr2, &ss);
		if (error != 0)
			return (error);
		bzero(&bctx, sizeof(bctx));
		if (req->sqe.addr2 >= sizeof(family)) {
			bcopy(&ss, &family, sizeof(family));
			bctx.connect.family = family;
		}
		if (family == LINUX_AF_INET && req->sqe.addr2 >= 16) {
			bcopy((char *)&ss + 2, &bctx.connect.port,
			    sizeof(bctx.connect.port));
			bcopy((char *)&ss + 4, &bctx.connect.v4_addr,
			    sizeof(bctx.connect.v4_addr));
		} else if (family == LINUX_AF_INET6 && req->sqe.addr2 >= 28) {
			bcopy((char *)&ss + 2, &bctx.connect.port,
			    sizeof(bctx.connect.port));
			bcopy((char *)&ss + 8, bctx.connect.v6_addr,
			    sizeof(bctx.connect.v6_addr));
		}
		bcopy(&bctx.connect, req->bpf_pdu, sizeof(bctx.connect));
		break;
	}
	case IORING_OP_BIND:
		/* Linux imports the sockaddr during opcode preparation, before
		 * resolving an ordinary or registered request file. */
		error = linux_iou_validate_sockaddr(req->sqe.addr,
		    req->sqe.addr2, NULL);
		if (error != 0)
			return (error);
		break;
	case IORING_OP_CLOSE:
		if (req->sqe.off != 0 || req->sqe.addr != 0 ||
		    req->sqe.len != 0 || req->sqe.rw_flags != 0 ||
		    req->sqe.buf_index != 0)
			return (EINVAL);
		if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0)
			return (EBADF);
		if (req->sqe.file_index != 0 && req->sqe.fd != 0)
			return (EINVAL);
		break;
	case IORING_OP_OPENAT:
		if (req->sqe.buf_index != 0)
			return (EINVAL);
		if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0)
			return (EBADF);
		error = linux_iou_validate_path(req->sqe.addr);
		if (error != 0)
			return (error);
		if (req->sqe.file_index != 0 &&
		    (req->sqe.open_flags & LINUX_O_CLOEXEC) != 0)
			return (EINVAL);
		break;
	case IORING_OP_OPENAT2: {
		struct l_open_how how;

		error = linux_iou_copy_open_how(&how,
		    (const void *)(uintptr_t)req->sqe.addr2, req->sqe.len);
		if (error != 0)
			return (error);
		if (req->sqe.buf_index != 0)
			return (EINVAL);
		if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0)
			return (EBADF);
		error = linux_iou_validate_path(req->sqe.addr);
		if (error != 0)
			return (error);
		if (req->sqe.file_index != 0 &&
		    (how.flags & LINUX_O_CLOEXEC) != 0)
			return (EINVAL);
		bcopy(&how, req->bpf_pdu, sizeof(how));
		break;
	}
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_READ:
	case IORING_OP_WRITE:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED:
		error = linux_iou_rw_ioprio(req->sqe.ioprio);
		if (error != 0)
			return (error);
		if (req->sqe.attr_type_mask == 0)
			break;
		if (req->sqe.attr_type_mask != IORING_RW_ATTR_FLAG_PI)
			return (EINVAL);
		/* Protection-information metadata requires a storage metadata
		 * iterator and target-device contract.  Keep RW_ATTR clear and
		 * reject the known request rather than silently dropping it. */
		return (EOPNOTSUPP);
	case IORING_OP_SEND:
	case IORING_OP_SENDMSG:
		if ((req->opcode == IORING_OP_SEND &&
		    req->sqe.__pad3[0] != 0) ||
		    (req->opcode == IORING_OP_SENDMSG &&
		    (req->sqe.addr2 != 0 || req->sqe.file_index != 0)))
			return (EINVAL);
		if ((req->sqe.ioprio & ~(IORING_RECVSEND_POLL_FIRST |
		    IORING_RECVSEND_BUNDLE | IORING_SEND_VECTORIZED)) != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & IORING_RECVSEND_BUNDLE) != 0) {
			if (req->opcode == IORING_OP_SENDMSG ||
			    (req->sqe_flags & IOSQE_BUFFER_SELECT) == 0)
				return (EINVAL);
			req->net_bundle = true;
		}
		req->poll_first =
		    (req->sqe.ioprio & IORING_RECVSEND_POLL_FIRST) != 0;
		break;
	case IORING_OP_RECV:
	case IORING_OP_RECVMSG:
		/* Linux reserves addr2 for both receive opcodes. */
		if (req->sqe.addr2 != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & ~(IORING_RECVSEND_POLL_FIRST |
		    IORING_RECV_MULTISHOT | IORING_RECVSEND_BUNDLE)) != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & IORING_RECVSEND_BUNDLE) != 0) {
			if (req->opcode == IORING_OP_RECVMSG ||
			    (req->sqe_flags & IOSQE_BUFFER_SELECT) == 0)
				return (EINVAL);
			req->net_bundle = true;
		}
		if ((req->sqe.ioprio & IORING_RECV_MULTISHOT) != 0) {
			if ((req->sqe_flags & IOSQE_BUFFER_SELECT) == 0 ||
			    (req->sqe.msg_flags & LINUX_MSG_WAITALL) != 0 ||
			    (req->opcode == IORING_OP_RECVMSG &&
			    req->sqe.optlen != 0))
				return (EINVAL);
			req->net_multishot = true;
			if (req->opcode == IORING_OP_RECV)
				req->net_mshot_remaining = req->sqe.optlen;
		} else if (req->sqe.optlen != 0)
			return (EINVAL);
		req->poll_first =
		    (req->sqe.ioprio & IORING_RECVSEND_POLL_FIRST) != 0;
		break;
	case IORING_OP_RECV_ZC:
		if (req->sqe.addr != 0 || req->sqe.off != 0 ||
		    req->sqe.addr3 != 0 || req->sqe.msg_flags != 0 ||
		    (req->sqe.ioprio & ~(IORING_RECVSEND_POLL_FIRST |
		    IORING_RECV_MULTISHOT)) != 0 ||
		    (req->sqe.ioprio & IORING_RECV_MULTISHOT) == 0)
			return (EINVAL);
		req->net_multishot = true;
		req->net_mshot_remaining = req->sqe.len;
		req->poll_first =
		    (req->sqe.ioprio & IORING_RECVSEND_POLL_FIRST) != 0;
		break;
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC:
		/* SEND_ZC reserves the upper address-length padding; SENDMSG_ZC
		 * reserves the direct-send destination and output slot. */
		if ((req->opcode == IORING_OP_SEND_ZC &&
		    req->sqe.__pad3[0] != 0) ||
		    (req->opcode == IORING_OP_SENDMSG_ZC &&
		    (req->sqe.addr2 != 0 || req->sqe.file_index != 0)))
			return (EINVAL);
		/* Linux requires both the primary and notification CQEs. */
		if ((req->sqe_flags & IOSQE_CQE_SKIP_SUCCESS) != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & ~(IORING_RECVSEND_POLL_FIRST |
		    IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE |
		    IORING_SEND_VECTORIZED)) != 0)
			return (EINVAL);
		req->poll_first =
		    (req->sqe.ioprio & IORING_RECVSEND_POLL_FIRST) != 0;
		break;
	case IORING_OP_PIPE:
		/* PIPE has no request file, but validates its creation flags during
		 * preparation before IOSQE_FIXED_FILE is ignored. */
		if ((req->sqe.pipe_flags & ~(LINUX_O_CLOEXEC |
		    LINUX_O_NONBLOCK | LINUX_O_DIRECT | LINUX_O_EXCL)) != 0)
			return (EINVAL);
		break;
	case IORING_OP_TEE:
	case IORING_OP_SPLICE:
		/* Linux validates splice flags during opcode preparation, before
		 * resolving either an ordinary or registered output file. */
		if ((req->sqe.splice_flags &
		    ~(LINUX_SPLICE_F_ALL | SPLICE_F_FD_IN_FIXED)) != 0)
			return (EINVAL);
		break;
	case IORING_OP_FSETXATTR:
		/* Linux imports and validates xattr flags before resolving the
		 * request file, including a registered-file slot. */
		if ((req->sqe.xattr_flags & ~LINUX_XATTR_FLAGS) != 0)
			return (EINVAL);
		break;
	case IORING_OP_FGETXATTR:
		if (req->sqe.xattr_flags != 0)
			return (EINVAL);
		break;
	case IORING_OP_SOCKET:
		if (req->sqe.file_index != 0 &&
		    (req->sqe.off & LINUX_SOCK_CLOEXEC) != 0)
			return (EINVAL);
		break;
	case IORING_OP_ACCEPT:
		if (req->sqe.file_index != 0 &&
		    (req->sqe.accept_flags & LINUX_SOCK_CLOEXEC) != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & ~(IORING_ACCEPT_MULTISHOT |
		    IORING_ACCEPT_DONTWAIT | IORING_ACCEPT_POLL_FIRST)) != 0)
			return (EINVAL);
		if ((req->sqe.ioprio & IORING_ACCEPT_MULTISHOT) != 0) {
			if (req->sqe.file_index != 0 &&
			    req->sqe.file_index != IORING_FILE_INDEX_ALLOC)
				return (EINVAL);
			req->net_multishot = true;
		}
		req->complete_eagain =
		    (req->sqe.ioprio & IORING_ACCEPT_DONTWAIT) != 0;
		req->poll_first =
		    (req->sqe.ioprio & IORING_ACCEPT_POLL_FIRST) != 0;
		break;
	default:
		break;
	}
	if (req->opcode != IORING_OP_RECVMSG ||
	    (req->sqe_flags & IOSQE_BUFFER_SELECT) == 0)
		return (0);
	error = copyin((void *)(uintptr_t)req->sqe.addr, &msg, sizeof(msg));
	if (error != 0)
		return (error);
	if (msg.msg_iovlen > 1)
		return (EINVAL);
	if (req->net_multishot) {
		if (msg.msg_namelen < 0 || msg.msg_controllen > UINT32_MAX ||
		    (uint64_t)sizeof(struct io_uring_recvmsg_out) +
		    (uint32_t)msg.msg_namelen + msg.msg_controllen > UINT32_MAX)
			return (EOVERFLOW);
		req->recvmsg_namelen = msg.msg_namelen;
		req->recvmsg_controllen = msg.msg_controllen;
		return (0);
	}
	if (msg.msg_iovlen == 1) {
		error = copyin(PTRIN(msg.msg_iov), &iov, sizeof(iov));
		if (error != 0)
			return (error);
		req->pbuf_want = iov.iov_len;
	}
	return (0);
}

static int
linux_iou_clockid(clockid_t linux_clockid, clockid_t *native_clockid)
{

	/* REGISTER_CLOCK admits exactly these two Linux clock domains. */
	if (linux_clockid != LINUX_CLOCK_MONOTONIC &&
	    linux_clockid != LINUX_CLOCK_BOOTTIME)
		return (EINVAL);
	return (linux_to_native_clockid(native_clockid, linux_clockid) == 0 ?
	    0 : EINVAL);
}

/* Linux 6.18's blind/ring query ABI has one operation: opcode inventory. */
struct linux_iou_query_hdr {
	uint64_t next_entry;
	uint64_t query_data;
	uint32_t query_op;
	uint32_t size;
	int32_t result;
	uint32_t resv[3];
};

struct linux_iou_query_opcodes {
	uint32_t nr_request_opcodes;
	uint32_t nr_register_opcodes;
	uint64_t feature_flags;
	uint64_t ring_setup_flags;
	uint64_t enter_flags;
	uint64_t sqe_flags;
	uint32_t nr_query_opcodes;
	uint32_t pad;
};

_Static_assert(sizeof(struct linux_iou_query_hdr) == 40, "Linux query header");
_Static_assert(sizeof(struct linux_iou_query_opcodes) == 48,
    "Linux query opcodes");

static int
linux_iou_register_query(struct thread *td __unused, void *arg, uint32_t nr)
{
	static const uint8_t zeros[128];
	struct linux_iou_query_hdr hdr;
	struct linux_iou_query_opcodes out;
	uint64_t user_hdr;
	size_t copylen, off, n, usize;
	int error, entries, result;

	if (nr != 0)
		return (EINVAL);
	user_hdr = (uint64_t)(uintptr_t)arg;
	entries = 0;
	while (user_hdr != 0) {
		error = copyin((void *)(uintptr_t)user_hdr, &hdr, sizeof(hdr));
		if (error != 0)
			return (error);
		usize = hdr.size;
		copylen = MIN(usize, sizeof(out));
		result = EINVAL;
		if (hdr.query_op != 0)
			result = EOPNOTSUPP;
		else if (hdr.resv[0] == 0 && hdr.resv[1] == 0 &&
		    hdr.resv[2] == 0 && hdr.result == 0 && usize != 0) {
			error = copyin((void *)(uintptr_t)hdr.query_data,
			    &out, copylen);
			if (error != 0)
				return (error);
			bzero(&out, sizeof(out));
			out.nr_request_opcodes = IORING_OP_LAST;
			out.nr_register_opcodes = IORING_REGISTER_LAST;
			out.feature_flags = SQ_SUPPORTED_FEATURE_FLAGS |
			    IORING_FEAT_RECVSEND_BUNDLE;
			out.ring_setup_flags = SQ_SUPPORTED_SETUP_FLAGS;
			out.enter_flags = SQ_SUPPORTED_ENTER_FLAGS;
			out.sqe_flags = SQ_SUPPORTED_SQE_FLAGS;
			out.nr_query_opcodes = 1;
			result = 0;
		}
		if (result == 0) {
			error = copyout(&out, (void *)(uintptr_t)hdr.query_data,
			    copylen);
			if (error != 0)
				return (error);
		}
		for (off = result == 0 ? copylen : 0; off < usize; off += n) {
			n = MIN(usize - off, sizeof(zeros));
			error = copyout(zeros,
			    (void *)(uintptr_t)(hdr.query_data + off), n);
			if (error != 0)
				return (error);
		}
		hdr.result = result == 0 ? 0 : bsd_to_linux_errno(result);
		hdr.size = result == 0 ? copylen : 0;
		error = copyout(&hdr, (void *)(uintptr_t)user_hdr,
		    sizeof(hdr));
		if (error != 0)
			return (error);
		user_hdr = hdr.next_entry;
		if (++entries >= 1000)
			return (ERANGE);
	}
	return (0);
}

#define LINUX_ZCRX_REG_IMPORT	1U
#define LINUX_ZCRX_REG_NODEV	2U
#define LINUX_ZCRX_AREA_DMABUF	1U
#define LINUX_ZCRX_CTRL_FLUSH_RQ	0U
#define LINUX_ZCRX_CTRL_EXPORT	1U

struct linux_iou_zcrx_offsets {
	uint32_t head;
	uint32_t tail;
	uint32_t rqes;
	uint32_t resv2;
	uint64_t resv[2];
};

struct linux_iou_zcrx_area_reg {
	uint64_t addr;
	uint64_t len;
	uint64_t rq_area_token;
	uint32_t flags;
	uint32_t dmabuf_fd;
	uint64_t resv[2];
};

struct linux_iou_zcrx_ifq_reg {
	uint32_t if_idx;
	uint32_t if_rxq;
	uint32_t rq_entries;
	uint32_t flags;
	uint64_t area_ptr;
	uint64_t region_ptr;
	struct linux_iou_zcrx_offsets offsets;
	uint32_t zcrx_id;
	uint32_t rx_buf_len;
	uint64_t resv[3];
};

struct linux_iou_zcrx_ctrl {
	uint32_t zcrx_id;
	uint32_t op;
	uint64_t resv[2];
	uint64_t data[6];
};

_Static_assert(sizeof(struct linux_iou_zcrx_offsets) == 32,
    "Linux ZCRX offsets");
_Static_assert(sizeof(struct linux_iou_zcrx_area_reg) == 48,
    "Linux ZCRX area");
_Static_assert(sizeof(struct linux_iou_zcrx_ifq_reg) == 96,
    "Linux ZCRX registration");
_Static_assert(sizeof(struct linux_iou_zcrx_ctrl) == 72,
    "Linux ZCRX control");

struct linux_iou_zcrx_publish {
	void *regp;
	void *areap;
	void *regionp;
	struct linux_iou_zcrx_ifq_reg reg;
	struct linux_iou_zcrx_area_reg area;
	struct io_uring_region_desc region;
};

static int
linux_iou_zcrx_publish(void *cookie, const struct sq_zcrx_reg *out)
{
	struct linux_iou_zcrx_publish *p = cookie;
	int error;

	p->reg.rq_entries = out->rq_entries;
	p->reg.zcrx_id = out->id;
	p->reg.rx_buf_len = out->rx_buf_len;
	p->reg.offsets.head = out->head_off;
	p->reg.offsets.tail = out->tail_off;
	p->reg.offsets.rqes = out->rqes_off;
	p->area.rq_area_token = 0;
	p->region.mmap_offset = out->mmap_offset;
	error = copyout(&p->reg, p->regp, sizeof(p->reg));
	if (error == 0)
		error = copyout(&p->region, p->regionp, sizeof(p->region));
	if (error == 0)
		error = copyout(&p->area, p->areap, sizeof(p->area));
	return (error);
}

static int
linux_iou_register_zcrx(struct squeue_ctx *ctx, struct thread *td, void *arg,
    uint32_t nr)
{
	struct linux_iou_zcrx_publish p;
	struct sq_zcrx_reg shared;
	uint64_t need;
	int error;

	/* Linux gates ZCRX registration on CAP_NET_ADMIN before ABI copyin. */
	if (priv_check(td, PRIV_NET_SETIFFLAGS) != 0)
		return (EPERM);
	if ((ctx->setup_flags & IORING_SETUP_DEFER_TASKRUN) == 0 ||
	    (ctx->setup_flags & (IORING_SETUP_CQE32 |
	    IORING_SETUP_CQE_MIXED)) == 0)
		return (EINVAL);
	if (arg == NULL || nr != 1)
		return (EINVAL);
	bzero(&p, sizeof(p));
	p.regp = arg;
	error = copyin(arg, &p.reg, sizeof(p.reg));
	if (error != 0)
		return (error);
	if (memcchr(p.reg.resv, 0, sizeof(p.reg.resv)) != NULL ||
	    p.reg.zcrx_id != 0 ||
	    (p.reg.flags & ~(LINUX_ZCRX_REG_IMPORT |
	    LINUX_ZCRX_REG_NODEV)) != 0)
		return (EINVAL);
	if ((p.reg.flags & LINUX_ZCRX_REG_IMPORT) != 0) {
		if (p.reg.if_rxq != 0 || p.reg.rq_entries != 0 ||
		    p.reg.area_ptr != 0 || p.reg.region_ptr != 0 ||
		    (p.reg.flags & ~LINUX_ZCRX_REG_IMPORT) != 0)
			return (EINVAL);
		/* No importable ZCRX descriptor exists without EXPORT support. */
		return (EBADF);
	}
	if (p.reg.if_rxq == UINT32_MAX || p.reg.rq_entries == 0)
		return (EINVAL);
	if ((p.reg.flags & LINUX_ZCRX_REG_NODEV) != 0 &&
	    (p.reg.if_idx != 0 || p.reg.if_rxq != 0))
		return (EINVAL);
	if (p.reg.rq_entries > SQ_MAX_ENTRIES) {
		if ((ctx->setup_flags & IORING_SETUP_CLAMP) == 0)
			return (EINVAL);
		p.reg.rq_entries = SQ_MAX_ENTRIES;
	}
	if (p.reg.rx_buf_len != 0 && p.reg.rx_buf_len != PAGE_SIZE) {
		if (p.reg.rx_buf_len < PAGE_SIZE ||
		    !powerof2(p.reg.rx_buf_len))
			return (EINVAL);
		return (EOPNOTSUPP);
	}
	p.areap = (void *)(uintptr_t)p.reg.area_ptr;
	p.regionp = (void *)(uintptr_t)p.reg.region_ptr;
	error = copyin(p.regionp, &p.region, sizeof(p.region));
	if (error != 0)
		return (error);
	error = copyin(p.areap, &p.area, sizeof(p.area));
	if (error != 0)
		return (error);
	if (memcchr(p.region.__resv, 0, sizeof(p.region.__resv)) != NULL ||
	    (p.region.flags & ~IORING_MEM_REGION_TYPE_USER) != 0 ||
	    p.region.id != 0 || p.region.mmap_offset != 0)
		return (EINVAL);
	if (((p.region.flags & IORING_MEM_REGION_TYPE_USER) != 0) !=
	    (p.region.user_addr != 0))
		return (EFAULT);
	if (p.region.size == 0 ||
	    ((p.region.user_addr | p.region.size) & PAGE_MASK) != 0)
		return (EINVAL);
	if (p.region.user_addr > UINT64_MAX - p.region.size)
		return (EOVERFLOW);
	if (memcchr(p.area.resv, 0, sizeof(p.area.resv)) != NULL ||
	    p.area.rq_area_token != 0 ||
	    (p.area.flags & ~LINUX_ZCRX_AREA_DMABUF) != 0)
		return (EINVAL);
	if ((p.area.flags & LINUX_ZCRX_AREA_DMABUF) != 0)
		return ((p.reg.flags & LINUX_ZCRX_REG_NODEV) != 0 ?
		    EINVAL : EOPNOTSUPP);
	if (p.area.addr == 0)
		return (EFAULT);
	if (p.area.len == 0 ||
	    ((p.area.addr | p.area.len) & PAGE_MASK) != 0)
		return (EINVAL);
	if (p.area.addr > UINT64_MAX - p.area.len)
		return (EOVERFLOW);

	if ((p.reg.flags & LINUX_ZCRX_REG_NODEV) == 0)
		return (p.reg.if_idx == 0 ? ENODEV : EOPNOTSUPP);

	need = round_page(64 + (uint64_t)(1U <<
	    flsl(p.reg.rq_entries - 1)) * 16);
	if (p.region.size < need)
		return (EINVAL);
	bzero(&shared, sizeof(shared));
	shared.area_addr = (uintptr_t)p.area.addr;
	shared.area_len = p.area.len;
	shared.rq_addr = (uintptr_t)p.region.user_addr;
	shared.rq_size = p.region.size;
	shared.rq_entries = p.reg.rq_entries;
	shared.rq_user =
	    (p.region.flags & IORING_MEM_REGION_TYPE_USER) != 0;
	return (sq_zcrx_register_nodev(ctx, &shared, td,
	    linux_iou_zcrx_publish, &p));
}

static int
linux_iou_register_zcrx_ctrl(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct linux_iou_zcrx_ctrl ctrl;
	int error;

	if (nr != 0)
		return (EINVAL);
	error = copyin(arg, &ctrl, sizeof(ctrl));
	if (error != 0)
		return (error);
	if (memcchr(ctrl.resv, 0, sizeof(ctrl.resv)) != NULL)
		return (EFAULT);
	if (!sq_zcrx_exists(ctx, ctrl.zcrx_id))
		return (ENXIO);
	if (ctrl.op == LINUX_ZCRX_CTRL_FLUSH_RQ) {
		if (memcchr(ctrl.data, 0, sizeof(ctrl.data)) != NULL)
			return (EINVAL);
		error = sq_zcrx_refill(ctx, ctrl.zcrx_id);
		return (error == ENOENT ? ENXIO : error);
	}
	if (ctrl.op == LINUX_ZCRX_CTRL_EXPORT)
		return (EOPNOTSUPP);
	return (EOPNOTSUPP);
}

static int
linux_iou_register_ext(struct squeue_ctx *ctx, struct thread *td, uint32_t op,
    void *arg, uint32_t nr)
{

	switch (op) {
	case IORING_REGISTER_ZCRX_IFQ:
		return (linux_iou_register_zcrx(ctx, td, arg, nr));
	case IORING_REGISTER_ZCRX_CTRL:
		return (linux_iou_register_zcrx_ctrl(ctx, arg, nr));
	default:
		return (EINVAL);
	}
}

static void
linux_iou_sqpoll_thread_init(struct thread *td)
{
	linux_proc_init(td, td, true);
}

static const struct sq_frontend linux_frontend = {
	.is_linux = true,
	.err_xlate = bsd_to_linux_errno,
	.issue_ext = linux_iou_issue_ext,
	.op_supported = linux_iou_op_supported,
	.rw_flags = linux_iou_rw_flags,
	.prepare_ext = linux_iou_prepare_ext,
	.clockid_xlate = linux_iou_clockid,
	.register_query = linux_iou_register_query,
	.register_ext = linux_iou_register_ext,
	.mmap_bad_offset_errno = ENOMEM,
	.feature_flags = IORING_FEAT_RECVSEND_BUNDLE,
	.sqpoll_thread_init = linux_iou_sqpoll_thread_init,
	.ext_poll = linux_iou_waitid_poll,
};

int
linux_io_uring_setup(struct thread *td, struct linux_io_uring_setup_args *args)
{
	struct io_uring_params p;
	int error, fd;

	error = copyin(args->params, &p, sizeof(p));
	if (error != 0)
		return (error);
	error = kern_squeue_setup(td, args->entries, &p, &linux_frontend, &fd);
	if (error != 0)
		return (error);
	error = kern_squeue_bpf_task_attach(td, fd, em_find(td)->iou_bpf);
	if (error != 0) {
		kern_squeue_setup_abort(td, fd, p.flags);
		return (error);
	}
	error = copyout(&p, args->params, sizeof(p));
	if (error != 0) {
		kern_squeue_setup_abort(td, fd, p.flags);
		return (error);
	}
	td->td_retval[0] = fd;
	return (0);
}

static int
linux_iou_copy_sigset(const void *arg, size_t size, sigset_t *set)
{
	l_sigset_t lset;
	int error;

	if (size != sizeof(lset))
		return (EINVAL);
	error = copyin(arg, &lset, sizeof(lset));
	if (error == 0)
		linux_to_bsd_sigset(&lset, set);
	return (error);
}

int
linux_io_uring_enter(struct thread *td, struct linux_io_uring_enter_args *args)
{
	int error;

	error = kern_squeue_enter_sigmask(td, args->fd, args->to_submit,
	    args->min_complete, args->flags, args->arg, args->argsz,
	    linux_iou_copy_sigset);
	if (error == SQ_BAD_RING_STATE) {
		td->td_retval[0] = -LINUX_EBADFD;
		return (0);
	}
	if (error == ETIMEDOUT) {
		/* Linux ETIME has no native errno; return the Linux ABI value. */
		td->td_retval[0] = -SQ_LINUX_ETIME;
		return (0);
	}
	return (error);
}

int
linux_io_uring_register(struct thread *td,
    struct linux_io_uring_register_args *args)
{

	int error;

	if (args->fd == -1 &&
	    (args->opcode & ~IORING_REGISTER_USE_REGISTERED_RING) ==
	    IORING_REGISTER_QUERY)
		return (linux_iou_register_query(td, args->arg, args->nr_args));
	if (args->fd == -1 &&
	    (args->opcode & ~IORING_REGISTER_USE_REGISTERED_RING) ==
	    IORING_REGISTER_BPF_FILTER) {
		bool no_new_privs;

		PROC_LOCK(td->td_proc);
		no_new_privs =
		    (td->td_proc->p_flag2 & P2_NO_NEW_PRIVS) != 0;
		PROC_UNLOCK(td->td_proc);
		if (!no_new_privs && priv_check(td, PRIV_VFS_ADMIN) != 0)
			return (EACCES);
		return (kern_squeue_bpf_task_register(
		    &em_find(td)->iou_bpf, args->arg, args->nr_args));
	}
	error = kern_squeue_register(td, args->fd, args->opcode,
	    args->arg, args->nr_args);
	if (error == SQ_BAD_RING_STATE) {
		td->td_retval[0] = -LINUX_EBADFD;
		return (0);
	}
	if (error == ETIMEDOUT) {
		td->td_retval[0] = -SQ_LINUX_ETIME;
		return (0);
	}
	return (error);
}

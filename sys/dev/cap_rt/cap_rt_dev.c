/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — message-passing capability framework.
 * Instance file descriptor operations.
 *
 * ioctl(CAP_RT_SENDMSG)  enqueue on RX, EAGAIN if full
 * ioctl(CAP_RT_RECVMSG)  dequeue from TX (blocks if empty)
 * ioctl(CAP_RT_GETINFO)  query service name, badge, limits
 *
 * read()/write() are disabled.  All messaging goes through the
 * structured ioctl API, which carries fds, reply tokens, and
 * credential metadata.  Capsicum cap_ioctls_limit() restricts
 * which operations a given fd can perform.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <vm/uma.h>

#include "cap_rt_internal.h"
#include "cap_rt_label.h"

MALLOC_DECLARE(M_CAP_RT);

SDT_PROVIDER_DECLARE(cap_rt);
SDT_PROBE_DECLARE(cap_rt, , , send);
SDT_PROBE_DECLARE(cap_rt, , , send__done);
SDT_PROBE_DECLARE(cap_rt, , , recv);
SDT_PROBE_DECLARE(cap_rt, , , recv__done);
SDT_PROBE_DECLARE(cap_rt, , , call);
SDT_PROBE_DECLARE(cap_rt, , , call__done);
SDT_PROBE_DECLARE(cap_rt, , , close);
SDT_PROBE_DECLARE(cap_rt, , , fd__close);
SDT_PROBE_DECLARE(cap_rt, , , fd__receive);
SDT_PROBE_DECLARE(cap_rt, , , control);
SDT_PROBE_DECLARE(cap_rt, , , ioctl__deny);
SDT_PROBE_DECLARE(cap_rt, , , error);
SDT_PROBE_DECLARE(cap_rt, , , instance__finalize);
SDT_PROBE_DECLARE(cap_rt, , , instance__lastclose);
SDT_PROBE_DECLARE(cap_rt, , , rights__change);
SDT_PROBE_DECLARE(cap_rt, , , state);
SDT_PROBE_DECLARE(cap_rt, , , queue__pressure);

static fo_ioctl_t	cap_rt_instance_ioctl;
static fo_kqfilter_t	cap_rt_instance_kqfilter;
static fo_stat_t	cap_rt_instance_stat;
static fo_close_t	cap_rt_instance_close;
static fo_fdclose_t	cap_rt_instance_fdclose;
static fo_fill_kinfo_t	cap_rt_instance_fill_kinfo;
static fo_cmp_t		cap_rt_instance_cmp;

/*
 * Capsicum per-ioctl rights enforcement.
 *
 * CAP_RT_SENDMSG  requires  CAP_CAP_RT_SEND
 * CAP_RT_CALL     requires  CAP_CAP_RT_SEND (request) + CAP_CAP_RT_RECV (reply)
 * CAP_RT_RECVMSG  requires  CAP_CAP_RT_RECV
 * CAP_RT_MINT_INSTANCE requires CAP_CAP_RT_MINT
 *
 * GETINFO, REVOKE_*, TERMINATE are always allowed — they are
 * introspection or capability-narrowing operations.
 */
static int
cap_rt_instance_ioctl_check(struct file *fp, u_long cmd,
    const cap_rights_t *havep)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;
	cap_rights_t need;
	int error;

	switch (cmd) {
	case CAP_RT_SENDMSG:
		cap_rights_init(&need, CAP_IOCTL, CAP_CAP_RT_SEND);
		break;
	case CAP_RT_RECVMSG:
		cap_rights_init(&need, CAP_IOCTL, CAP_CAP_RT_RECV);
		break;
	case CAP_RT_CALL:
		cap_rights_init(&need, CAP_IOCTL, CAP_CAP_RT_SEND,
		    CAP_CAP_RT_RECV);
		break;
	case CAP_RT_MINT_INSTANCE:
		cap_rights_init(&need, CAP_IOCTL, CAP_CAP_RT_MINT);
		break;
	default:
		return (0);
	}
	error = cap_check(havep, &need);
	if (error != 0) {
		s = fp->f_data;
		svc = s != NULL ? s->ci_service : NULL;
		if (svc != NULL) {
			SDT_PROBE6(cap_rt, , , ioctl__deny,
			    svc->csvc_name, s->ci_badge, cmd,
			    curthread->td_proc->p_pid, curthread->td_ucred,
			    cap_rt_proc_nonce(curthread->td_ucred));
		}
	}
	return (error);
}

const struct fileops cap_rt_instance_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = cap_rt_instance_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = cap_rt_instance_kqfilter,
	.fo_stat = cap_rt_instance_stat,
	.fo_close = cap_rt_instance_close,
	.fo_fdclose = cap_rt_instance_fdclose,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = cap_rt_instance_fill_kinfo,
	.fo_cmp = cap_rt_instance_cmp,
	.fo_ioctl_check = cap_rt_instance_ioctl_check,
	.fo_flags = DFLAG_PASSABLE,
};

static void
cap_rt_probe_fd_receive(struct file *fp, int fd, struct thread *td)
{
	struct cap_rt_instance *rs;
	struct cap_rt_service *rsvc;

	if (fp->f_type != DTYPE_CAP_RT || fp->f_data == NULL)
		return;

	rs = fp->f_data;
	rsvc = rs->ci_service;
	if (rsvc == NULL)
		return;

	SDT_PROBE6(cap_rt, , , fd__receive, rsvc->csvc_name,
	    rs->ci_badge, fd, td->td_proc->p_pid, td->td_ucred,
	    cap_rt_proc_nonce(td->td_ucred));
}

static void
cap_rt_probe_control(struct cap_rt_instance *s, u_long cmd, struct thread *td)
{
	struct cap_rt_service *svc;

	svc = s->ci_service;
	if (svc == NULL)
		return;

	SDT_PROBE6(cap_rt, , , control, svc->csvc_name, s->ci_badge,
	    cmd, td->td_proc->p_pid, td->td_ucred,
	    cap_rt_proc_nonce(td->td_ucred));
}

static void
cap_rt_probe_error(struct cap_rt_instance *s, u_long op, int error,
    struct thread *td)
{
	struct cap_rt_service *svc;
	const char *svc_name;

	if (error == 0)
		return;
	svc = s->ci_service;
	svc_name = svc != NULL ? svc->csvc_name : "<none>";
	SDT_PROBE6(cap_rt, , , error, svc_name, s->ci_badge, op,
	    td->td_proc->p_pid, cap_rt_proc_nonce(td->td_ucred), error);
}

static void
cap_rt_probe_rights_change(struct cap_rt_instance *s, u_long cmd,
    struct thread *td)
{
	struct cap_rt_service *svc;
	int flags, restricted;

	svc = s->ci_service;
	if (svc == NULL)
		return;
	mtx_lock(&s->ci_mtx);
	flags = s->ci_flags;
	restricted = s->ci_restricted;
	mtx_unlock(&s->ci_mtx);
	SDT_PROBE6(cap_rt, , , rights__change, svc->csvc_name,
	    s->ci_badge, cmd, td->td_proc->p_pid, td->td_ucred,
	    cap_rt_proc_nonce(td->td_ucred));
	SDT_PROBE6(cap_rt, , , state, svc->csvc_name, s->ci_badge,
	    flags, restricted, td->td_proc->p_pid,
	    cap_rt_proc_nonce(td->td_ucred));
}

static int
cap_rt_instance_enqueue_rx(struct cap_rt_instance *s, struct cap_rt_msg *msg)
{
	struct cap_rt_service *svc;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	if (s->ci_flags & CAP_RT_SF_DEAD) {
		cap_rt_msg_free(msg);
		return (ECONNRESET);
	}
	if (s->ci_rxqlen >= s->ci_rxqlimit) {
		svc = s->ci_service;
		if (svc != NULL) {
			SDT_PROBE5(cap_rt, , , queue__pressure,
			    svc->csvc_name, s->ci_badge, "rx",
			    s->ci_rxqlen, s->ci_rxqlimit);
		}
		cap_rt_msg_free(msg);
		return (EAGAIN);
	}
	STAILQ_INSERT_TAIL(&s->ci_rxq, msg, cm_link);
	s->ci_rxqlen++;

	svc = s->ci_service;
	if (svc != NULL && svc->csvc_taskq != NULL)
		taskqueue_enqueue(svc->csvc_taskq, &s->ci_task);

	return (0);
}

static int
cap_rt_instance_do_sendmsg(struct cap_rt_instance *s,
    struct cap_rt_sendmsg_args *args, struct thread *td)
{
	struct cap_rt_service *svc;
	struct cap_rt_msg *msg;
	sbintime_t start __unused;
	const char *svc_name __unused;
	int fdbuf[CAP_RT_MAX_FDS];
	int error, i;

	start = getsbinuptime();
	svc_name = "<none>";
	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] |
	    args->_reserved[2] | args->_reserved[3]) != 0) {
		error = EINVAL;
		goto out;
	}

	svc = s->ci_service;
	if (svc != NULL)
		svc_name = svc->csvc_name;
	if (svc == NULL || svc->csvc_ops->co_handler == NULL) {
		error = EOPNOTSUPP;
		goto out;
	}

	if (atomic_load_acq_int(&s->ci_flags) & CAP_RT_SF_DEAD) {
		error = EPIPE;
		goto out;
	}

	if (args->payload_len > CAP_RT_MSG_PAYLOAD_SIZE) {
		error = EMSGSIZE;
		goto out;
	}
	if (args->nfds > CAP_RT_MAX_FDS) {
		error = EINVAL;
		goto out;
	}

	msg = uma_zalloc(cap_rt_msg_zone, M_WAITOK | M_ZERO);

	/* Copyin payload directly into inline buffer. */
	if (args->payload_len > 0) {
		error = copyin(args->payload, msg->cm_data,
		    args->payload_len);
		if (error != 0) {
			uma_zfree(cap_rt_msg_zone, msg);
			goto out;
		}
	}
	msg->cm_datalen = args->payload_len;

	if (args->nfds > 0) {
		error = copyin(args->fds, fdbuf, args->nfds * sizeof(int));
		if (error != 0) {
			uma_zfree(cap_rt_msg_zone, msg);
			goto out;
		}
		for (i = 0; i < (int)args->nfds; i++) {
			error = fget_cap(td, fdbuf[i], &cap_no_rights,
			    NULL, &msg->cm_fds[i], &msg->cm_fcaps[i]);
			if (error != 0)
				goto sendmsg_fd_err;
			if (!(msg->cm_fds[i]->f_ops->fo_flags &
			    DFLAG_PASSABLE)) {
				error = EINVAL;
				fdrop(msg->cm_fds[i], td);
				msg->cm_fds[i] = NULL;
				filecaps_free(&msg->cm_fcaps[i]);
				goto sendmsg_fd_err;
			}
		}
		msg->cm_nfds = args->nfds;

		/* Check and consume transfer state under exclusive lock. */
		{
			struct filedesc *fdesc = td->td_proc->p_fd;
			struct filedescent *fde;

			FILEDESC_XLOCK(fdesc);
			for (i = 0; i < (int)args->nfds; i++) {
				fde = &fdesc->fd_ofiles[fdbuf[i]];
				if (fde->fde_file != msg->cm_fds[i]) {
					FILEDESC_XUNLOCK(fdesc);
					error = EBADF;
					i = (int)args->nfds;
					goto sendmsg_fd_err;
				}
				if (fde->fde_xfer_state == CAP_XFER_NONE) {
					FILEDESC_XUNLOCK(fdesc);
					error = ENOTCAPABLE;
					i = (int)args->nfds;
					goto sendmsg_fd_err;
				}
			}
			for (i = 0; i < (int)args->nfds; i++) {
				fde = &fdesc->fd_ofiles[fdbuf[i]];
				if (fde->fde_xfer_state == CAP_XFER_ONCE) {
					fde->fde_xfer_state = CAP_XFER_NONE;
					msg->cm_xfer_state[i] = CAP_XFER_NONE;
				} else {
					msg->cm_xfer_state[i] =
					    fde->fde_xfer_state;
				}
			}
			FILEDESC_XUNLOCK(fdesc);

			msg->cm_badge = s->ci_badge;
			msg->cm_reply_token = args->reply_token;
			msg->cm_cred = crhold(td->td_ucred);

			mtx_lock(&s->ci_mtx);
			error = cap_rt_instance_enqueue_rx(s, msg);
			mtx_unlock(&s->ci_mtx);

			if (error == 0)
				SDT_PROBE3(cap_rt, , , send,
				    svc->csvc_name, s->ci_badge,
				    args->payload_len);
			goto out;
		}

sendmsg_fd_err:
		while (--i >= 0) {
			fdrop(msg->cm_fds[i], td);
			msg->cm_fds[i] = NULL;
			filecaps_free(&msg->cm_fcaps[i]);
		}
		uma_zfree(cap_rt_msg_zone, msg);
		goto out;
	}

	/* No fds — build and enqueue directly. */
	msg->cm_badge = s->ci_badge;
	msg->cm_reply_token = args->reply_token;
	msg->cm_cred = crhold(td->td_ucred);

	mtx_lock(&s->ci_mtx);
	error = cap_rt_instance_enqueue_rx(s, msg);
	mtx_unlock(&s->ci_mtx);

	if (error == 0)
		SDT_PROBE3(cap_rt, , , send,
		    svc->csvc_name, s->ci_badge, args->payload_len);

out:
	SDT_PROBE6(cap_rt, , , send__done, svc_name, s->ci_badge,
	    args->payload_len, args->nfds, error, getsbinuptime() - start);
	cap_rt_probe_error(s, CAP_RT_SENDMSG, error, td);
	return (error);
}

static int
cap_rt_instance_do_recvmsg(struct cap_rt_instance *s, struct file *fp,
    struct cap_rt_recvmsg_args *args, struct thread *td)
{
	struct cap_rt_msg *msg;
	sbintime_t start __unused;
	const char *svc_name __unused;
	int fdbuf[CAP_RT_MAX_FDS];
	int error, i, nfds_out;

	start = getsbinuptime();
	svc_name = (s->ci_service != NULL) ? s->ci_service->csvc_name : "<none>";
	error = 0;
	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] | args->_reserved[2] | args->_reserved[3]) != 0) {
		error = EINVAL;
		goto out;
	}

	mtx_lock(&s->ci_mtx);
	while (STAILQ_EMPTY(&s->ci_txq)) {
		if (s->ci_flags & CAP_RT_SF_REVOKED) {
			mtx_unlock(&s->ci_mtx);
			error = ECONNRESET;
			goto out;
		}
		if (s->ci_flags & CAP_RT_SF_CLOSED) {
			mtx_unlock(&s->ci_mtx);
			args->payload_len = 0;
			args->nfds = 0;
			args->badge = 0;
			args->reply_token = 0;
			memset(&args->trailer, 0, sizeof(args->trailer));
			error = 0;
			goto out;
		}
		if (fp->f_flag & FNONBLOCK) {
			mtx_unlock(&s->ci_mtx);
			error = EAGAIN;
			goto out;
		}
		error = msleep(&s->ci_txq, &s->ci_mtx,
		    PCATCH, "cap_rtrv", 0);
		if (error != 0) {
			mtx_unlock(&s->ci_mtx);
			goto out;
		}
	}

	/*
	 * Peek at the head message and verify that the caller's
	 * buffers are large enough BEFORE dequeuing.  If either
	 * payload or fd buffer is too small, return EMSGSIZE and
	 * leave the message queued so the caller can retry with a
	 * larger buffer.
	 */
	msg = STAILQ_FIRST(&s->ci_txq);
	if (msg->cm_datalen > args->payload_len) {
		args->payload_len = msg->cm_datalen;
		mtx_unlock(&s->ci_mtx);
		error = EMSGSIZE;
		goto out;
	}
	nfds_out = msg->cm_nfds;
	if (nfds_out > 0 && args->fds == NULL) {
		args->nfds = nfds_out;
		mtx_unlock(&s->ci_mtx);
		error = EMSGSIZE;
		goto out;
	}
	if (nfds_out > (int)args->nfds) {
		args->nfds = nfds_out;
		mtx_unlock(&s->ci_mtx);
		error = EMSGSIZE;
		goto out;
	}

	STAILQ_REMOVE_HEAD(&s->ci_txq, cm_link);
	s->ci_txqlen--;
	mtx_unlock(&s->ci_mtx);

	/* Copyout payload. */
	if (msg->cm_datalen > 0)
		error = copyout(msg->cm_data, args->payload, msg->cm_datalen);
	if (error != 0) {
		cap_rt_msg_free(msg);
		goto out;
	}
	args->payload_len = msg->cm_datalen;

	/* Fill metadata. */
	args->badge = msg->cm_badge;
	args->reply_token = msg->cm_reply_token;
	if (msg->cm_cred != NULL) {
		args->trailer.uid = msg->cm_cred->cr_uid;
		args->trailer.gid = msg->cm_cred->cr_gid;
		args->trailer.prison_id =
		    msg->cm_cred->cr_prison->pr_id;
		args->trailer.nonce =
		    cap_rt_proc_nonce(msg->cm_cred);
	} else {
		memset(&args->trailer, 0, sizeof(args->trailer));
	}
	{
		struct filedesc *fdesc = td->td_proc->p_fd;
		int installed;

		for (i = 0; i < nfds_out; i++) {
			if (!fhold(msg->cm_fds[i])) {
				/* Drop refs already taken. */
				while (--i >= 0)
					fdrop(msg->cm_fds[i], td);
				error = EBADF;
				cap_rt_msg_free(msg);
				args->nfds = 0;
				goto out;
			}
		}
		FILEDESC_XLOCK(fdesc);
		for (installed = 0; installed < nfds_out; installed++) {
			struct filecaps *fc = &msg->cm_fcaps[installed];

			error = fdalloc(td, 0, &fdbuf[installed]);
			if (error != 0)
				break;
			if (fc->fc_rights.cr_rights[0] == 0 &&
			    fc->fc_rights.cr_rights[1] == 0)
				fc = NULL;
			_finstall(fdesc, msg->cm_fds[installed],
			    fdbuf[installed], 0, fc);
			fdesc->fd_ofiles[fdbuf[installed]].fde_xfer_state =
			    msg->cm_xfer_state[installed];
		}
		FILEDESC_XUNLOCK(fdesc);
		if (installed < nfds_out) {
			/* fdrop refs for fds not installed. */
			for (i = installed; i < nfds_out; i++)
				fdrop(msg->cm_fds[i], td);
			/* Close fds that were installed. */
			for (i = 0; i < installed; i++)
				kern_close(td, fdbuf[i]);
			cap_rt_msg_free(msg);
			args->nfds = 0;
			goto out;
		}
		for (i = 0; i < nfds_out; i++)
			cap_rt_probe_fd_receive(msg->cm_fds[i], fdbuf[i], td);
	}
	if (nfds_out > 0 && args->fds != NULL) {
		error = copyout(fdbuf, args->fds, nfds_out * sizeof(int));
		if (error != 0) {
			for (i = 0; i < nfds_out; i++)
				kern_close(td, fdbuf[i]);
			cap_rt_msg_free(msg);
			args->nfds = 0;
			goto out;
		}
	}
	args->nfds = nfds_out;

	if (s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , recv,
		    s->ci_service->csvc_name, s->ci_badge, args->payload_len);

	cap_rt_msg_free(msg);
out:
	SDT_PROBE6(cap_rt, , , recv__done, svc_name, s->ci_badge,
	    args->payload_len, args->nfds, error, getsbinuptime() - start);
	cap_rt_probe_error(s, CAP_RT_RECVMSG, error, td);
	return (error);
}

static int
cap_rt_instance_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct cap_rt_instance *s;

	s = fp->f_data;

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		/*
		 * Generic fcntl(F_SETFL) translates O_NONBLOCK/O_ASYNC into
		 * these ioctls.  cap_rt has no device-specific state to toggle;
		 * successful return lets the generic layer update f_flag.
		 */
		return (0);
	case CAP_RT_SENDMSG:
		if (s->ci_restricted & CAP_RT_RF_NO_SEND) {
			cap_rt_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		return (cap_rt_instance_do_sendmsg(s,
		    (struct cap_rt_sendmsg_args *)data, td));
	case CAP_RT_RECVMSG:
		if (s->ci_restricted & CAP_RT_RF_NO_RECV) {
			cap_rt_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		return (cap_rt_instance_do_recvmsg(s, fp,
		    (struct cap_rt_recvmsg_args *)data, td));
	case CAP_RT_CALL: {
		struct cap_rt_call_args *ca = (struct cap_rt_call_args *)data;
		struct cap_rt_service *svc = s->ci_service;
		sbintime_t start __unused;
		bool held;
		const char *svc_name __unused;
		struct file **files;
		struct filecaps *call_fcaps;
		uint8_t call_xfer_state[CAP_RT_MAX_FDS];
		struct file *out_fds[CAP_RT_MAX_FDS];
		void *req_buf, *reply_buf;
		int fdbuf[CAP_RT_MAX_FDS];
		size_t rlen;
		int out_nfds;
		int error, i;

		start = getsbinuptime();
		held = false;
		svc_name = (svc != NULL) ? svc->csvc_name : "<none>";
		if (s->ci_restricted & CAP_RT_RF_NO_CALL) {
			error = EACCES;
			goto call_done;
		}
		if (ca->flags != 0 || (ca->_reserved[0] |
		    ca->_reserved[1]) != 0) {
			error = EINVAL;
			goto call_done;
		}
		if (svc == NULL || svc->csvc_ops->co_call == NULL) {
			error = EOPNOTSUPP;
			goto call_done;
		}
		if (ca->req_nfds > CAP_RT_MAX_FDS ||
		    ca->reply_nfds > CAP_RT_MAX_FDS) {
			error = EINVAL;
			goto call_done;
		}

		mtx_lock(&s->ci_mtx);
		if (s->ci_flags & CAP_RT_SF_DEAD) {
			mtx_unlock(&s->ci_mtx);
			error = ECONNRESET;
			goto call_done;
		}
		/*
		 * Hold instance alive and track as inflight so revoke
		 * waits for us.  Do NOT set ci_handler_td — CALL does
		 * not support self-revoke.  Multiple CALLs can run
		 * concurrently; the service serializes if needed.
		 */
		cap_rt_instance_hold(s);
		held = true;
		s->ci_inflight++;
		mtx_unlock(&s->ci_mtx);

		/* Initialize for goto cleanup. */
		req_buf = NULL;
		files = NULL;
		call_fcaps = NULL;
		reply_buf = NULL;
		out_nfds = 0;
		memset(out_fds, 0, sizeof(out_fds));
		error = 0;

		if (ca->req_len > CAP_RT_MSG_PAYLOAD_SIZE) {
			error = EMSGSIZE;
			goto call_out;
		}
		/* Cap reply buffer at msg_size. */
		if (ca->reply_len > CAP_RT_MSG_PAYLOAD_SIZE)
			ca->reply_len = CAP_RT_MSG_PAYLOAD_SIZE;

		if (ca->req_len > 0) {
			req_buf = malloc(ca->req_len, M_CAP_RT, M_WAITOK);
			error = copyin(ca->req, req_buf, ca->req_len);
			if (error != 0)
				goto call_out;
		}

		/* Resolve attached fds with Capsicum rights. */
		if (ca->req_nfds > 0) {
			error = copyin(ca->req_fds, fdbuf,
			    ca->req_nfds * sizeof(int));
			if (error != 0)
				goto call_out;
			files = malloc(ca->req_nfds * sizeof(struct file *),
			    M_CAP_RT, M_WAITOK | M_ZERO);
			call_fcaps = malloc(ca->req_nfds *
			    sizeof(struct filecaps), M_CAP_RT,
			    M_WAITOK | M_ZERO);
			for (i = 0; i < (int)ca->req_nfds; i++) {
				error = fget_cap(td, fdbuf[i], &cap_no_rights,
				    NULL, &files[i], &call_fcaps[i]);
				if (error != 0) {
					while (--i >= 0) {
						fdrop(files[i], td);
						files[i] = NULL;
					}
					goto call_out;
				}
			}

			/* Check and consume transfer state. */
			error = 0;
			{
				struct filedesc *fdesc = td->td_proc->p_fd;
				struct filedescent *fde;

				FILEDESC_XLOCK(fdesc);
				for (i = 0; i < (int)ca->req_nfds; i++) {
					fde = &fdesc->fd_ofiles[fdbuf[i]];
					if (fde->fde_file != files[i]) {
						error = EBADF;
						break;
					}
					if (fde->fde_xfer_state ==
					    CAP_XFER_NONE) {
						error = ENOTCAPABLE;
						break;
					}
				}
				if (error == 0) {
					for (i = 0; i < (int)ca->req_nfds;
					    i++) {
						fde = &fdesc->fd_ofiles[
						    fdbuf[i]];
						if (fde->fde_xfer_state ==
						    CAP_XFER_ONCE) {
							fde->fde_xfer_state =
							    CAP_XFER_NONE;
							call_xfer_state[i] =
							    CAP_XFER_NONE;
						} else {
							call_xfer_state[i] =
							    fde->fde_xfer_state;
						}
					}
				}
				FILEDESC_XUNLOCK(fdesc);
			}
			if (error != 0) {
				for (i = 0; i < (int)ca->req_nfds; i++) {
					fdrop(files[i], td);
					files[i] = NULL;
				}
				goto call_out;
			}
		}

		/* Allocate reply buffer. */
		rlen = ca->reply_len;
		if (rlen > 0)
			reply_buf = malloc(rlen, M_CAP_RT, M_WAITOK | M_ZERO);

		out_nfds = ca->reply_nfds;

		/* Stamp caller credentials — same contract as RECVMSG. */
		ca->trailer.uid = td->td_ucred->cr_uid;
		ca->trailer.gid = td->td_ucred->cr_gid;
		ca->trailer.prison_id =
		    td->td_ucred->cr_prison->pr_id;
		ca->trailer.nonce = cap_rt_proc_nonce(td->td_ucred);

		SDT_PROBE3(cap_rt, , , call,
		    svc->csvc_name, s->ci_badge, ca->req_len);
		error = svc->csvc_ops->co_call(s, req_buf, ca->req_len,
		    files, call_fcaps, ca->req_nfds,
		    reply_buf, &rlen,
		    out_fds, &out_nfds,
		    svc->csvc_arg);

		/* Clamp and trim out_nfds to actual fds set by handler. */
		if (out_nfds > CAP_RT_MAX_FDS)
			out_nfds = CAP_RT_MAX_FDS;
		while (out_nfds > 0 && out_fds[out_nfds - 1] == NULL)
			out_nfds--;

		if (error == 0 && rlen > 0 && reply_buf != NULL) {
			if (rlen > ca->reply_len) {
				/*
				 * Reply too large for caller's buffer.
				 * Report the required size so they can
				 * retry.  Matches RECVMSG EMSGSIZE.
				 */
				ca->reply_len = rlen;
				error = EMSGSIZE;
			} else {
				error = copyout(reply_buf, ca->reply, rlen);
				ca->reply_len = rlen;
			}
		} else if (error == 0) {
			ca->reply_len = rlen;
		}

		/* Install reply fds into caller's fd table.
		 * If handler returned fds but caller has no buffer,
		 * drop them to avoid leaking. */
		if (error == 0 && out_nfds > 0 && ca->reply_fds == NULL) {
			for (i = 0; i < out_nfds; i++) {
				if (out_fds[i] != NULL) {
					fdrop(out_fds[i], td);
					out_fds[i] = NULL;
				}
			}
			out_nfds = 0;
		}
		if (error == 0 && out_nfds > 0 && ca->reply_fds != NULL) {
			for (i = 0; i < out_nfds; i++) {
				struct filecaps *install_fcaps;
				int j, k;

				install_fcaps = NULL;
				j = -1;
				for (k = 0; k < (int)ca->req_nfds; k++) {
					if (out_fds[i] == files[k]) {
						install_fcaps = &call_fcaps[k];
						j = k;
						break;
					}
				}
				if (!fhold(out_fds[i])) {
					error = EBADF;
				} else {
					struct filedesc *fdesc;

					fdesc = td->td_proc->p_fd;
					FILEDESC_XLOCK(fdesc);
					error = fdalloc(td, 0, &fdbuf[i]);
					if (error == 0) {
						_finstall(fdesc, out_fds[i],
						    fdbuf[i], 0, install_fcaps);
						if (j >= 0)
							fdesc->fd_ofiles[
							    fdbuf[i]].
							    fde_xfer_state =
							    call_xfer_state[j];
					}
					FILEDESC_XUNLOCK(fdesc);
					if (error != 0)
						fdrop(out_fds[i], td);
				}
				if (error == 0) {
					cap_rt_probe_fd_receive(out_fds[i],
					    fdbuf[i], td);
				}
				/* Drop handler's ref (finstall took its own). */
				fdrop(out_fds[i], td);
				out_fds[i] = NULL;
				if (error != 0) {
					while (--i >= 0)
						kern_close(td, fdbuf[i]);
					out_nfds = 0;
					break;
				}
			}
			if (error == 0) {
				error = copyout(fdbuf, ca->reply_fds,
				    out_nfds * sizeof(int));
				if (error != 0) {
					for (i = 0; i < out_nfds; i++)
						kern_close(td, fdbuf[i]);
					out_nfds = 0;
				}
			}
		}
		ca->reply_nfds = (error == 0) ? out_nfds : 0;

call_out:
		/* Drop reply fds not installed (error path). */
		if (error != 0) {
			for (i = 0; i < out_nfds; i++) {
				if (out_fds[i] != NULL)
					fdrop(out_fds[i], td);
			}
		}
		if (files != NULL) {
			for (i = 0; i < (int)ca->req_nfds; i++) {
				if (files[i] != NULL)
					fdrop(files[i], td);
			}
			free(files, M_CAP_RT);
		}
		if (call_fcaps != NULL) {
			for (i = 0; i < (int)ca->req_nfds; i++)
				filecaps_free(&call_fcaps[i]);
			free(call_fcaps, M_CAP_RT);
		}
		free(req_buf, M_CAP_RT);
		free(reply_buf, M_CAP_RT);

		mtx_lock(&s->ci_mtx);
		s->ci_inflight--;
		if (s->ci_inflight == 0 && (s->ci_flags & CAP_RT_SF_DEAD))
			wakeup(&s->ci_inflight);
		mtx_unlock(&s->ci_mtx);

		if (held)
			cap_rt_instance_rele(s);
call_done:
		SDT_PROBE6(cap_rt, , , call__done, svc_name, s->ci_badge,
		    ca->req_len, ca->reply_len, error, getsbinuptime() - start);
		cap_rt_probe_error(s, CAP_RT_CALL, error, td);
		return (error);
	}
	case CAP_RT_GETINFO: {
		struct cap_rt_info_args *info = (struct cap_rt_info_args *)data;
		struct cap_rt_service *svc = s->ci_service;

		memset(info, 0, sizeof(*info));
		if (svc != NULL) {
			strlcpy(info->name, svc->csvc_name,
			    sizeof(info->name));
			info->msg_limit = CAP_RT_MSG_PAYLOAD_SIZE;
			info->queue_depth = svc->csvc_queue_depth;
			info->tx_limit = svc->csvc_tx_limit;
			if (svc->csvc_ops->co_handler != NULL) {
				info->features |= CAP_RT_INFO_F_SENDMSG;
				info->features |= CAP_RT_INFO_F_RECVMSG;
				info->features |= CAP_RT_INFO_F_KQUEUE;
			}
			if ((svc->csvc_svc_flags & CAP_RT_SVC_NOTIFY) != 0) {
				info->features |= CAP_RT_INFO_F_RECVMSG;
				info->features |= CAP_RT_INFO_F_KQUEUE;
			}
			if (svc->csvc_ops->co_call != NULL)
				info->features |= CAP_RT_INFO_F_CALL;
		}
		info->max_fds = CAP_RT_MAX_FDS;
		info->badge = s->ci_badge;
		return (0);
	}
	case CAP_RT_REVOKE_SEND:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_SEND);
		cap_rt_probe_control(s, cmd, td);
		cap_rt_probe_rights_change(s, cmd, td);
		return (0);
	case CAP_RT_REVOKE_RECV:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_RECV);
		cap_rt_probe_control(s, cmd, td);
		cap_rt_probe_rights_change(s, cmd, td);
		return (0);
	case CAP_RT_REVOKE_CALL:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_CALL);
		cap_rt_probe_control(s, cmd, td);
		cap_rt_probe_rights_change(s, cmd, td);
		return (0);
	case CAP_RT_REVOKE_MINT:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_MINT);
		cap_rt_probe_control(s, cmd, td);
		cap_rt_probe_rights_change(s, cmd, td);
		return (0);
	case CAP_RT_TERMINATE:
		cap_rt_probe_control(s, cmd, td);
		cap_rt_instance_revoke(s);
		return (0);
	case CAP_RT_MINT_INSTANCE: {
		struct cap_rt_mint_instance_args *ma;
		struct cap_rt_service *svc;
		uint64_t badge;
		int error, newfd;

		ma = (struct cap_rt_mint_instance_args *)data;
		if (ma->flags != 0 ||
		    (ma->_reserved[0] | ma->_reserved[1]) != 0) {
			cap_rt_probe_error(s, cmd, EINVAL, td);
			return (EINVAL);
		}

		if (s->ci_restricted & CAP_RT_RF_NO_MINT) {
			cap_rt_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		svc = s->ci_service;
		if (svc == NULL) {
			cap_rt_probe_error(s, cmd, ENXIO, td);
			return (ENXIO);
		}
		if (!(svc->csvc_svc_flags & CAP_RT_SVC_MINTABLE)) {
			cap_rt_probe_error(s, cmd, EOPNOTSUPP, td);
			return (EOPNOTSUPP);
		}

		/* Run co_connect for authorization. */
		badge = 0;
		if (svc->csvc_ops->co_connect != NULL) {
			error = svc->csvc_ops->co_connect(td->td_ucred,
			    svc->csvc_arg, &badge);
			if (error != 0) {
				cap_rt_probe_error(s, cmd, error, td);
				return (error);
			}
		}

		error = cap_rt_instance_create(svc, td, badge, &newfd);
		if (error != 0) {
			cap_rt_probe_error(s, cmd, error, td);
			return (error);
		}

		ma->fd = newfd;
		cap_rt_probe_control(s, cmd, td);
		return (0);
	}
	default:
		return (ENOTTY);
	}
}

/* EVFILT_READ */
static void
cap_rt_rkqops_detach(struct knote *kn)
{
	struct cap_rt_instance *s;

	s = kn->kn_fp->f_data;
	knlist_remove(&s->ci_rknotes, kn, 0);
}

static int
cap_rt_rkqops_event(struct knote *kn, long hint __unused)
{
	struct cap_rt_instance *s;

	s = kn->kn_fp->f_data;
	mtx_assert(&s->ci_mtx, MA_OWNED);

	if (s->ci_flags & CAP_RT_SF_DEAD) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	kn->kn_data = s->ci_txqlen;
	return (s->ci_txqlen > 0);
}

static const struct filterops cap_rt_rfiltops = {
	.f_isfd = 1,
	.f_detach = cap_rt_rkqops_detach,
	.f_event = cap_rt_rkqops_event,
	.f_copy = knote_triv_copy,
};

/* kqueue EVFILT_WRITE */
static void
cap_rt_wkqops_detach(struct knote *kn)
{
	struct cap_rt_instance *s;

	s = kn->kn_fp->f_data;
	knlist_remove(&s->ci_wknotes, kn, 0);
}

static int
cap_rt_wkqops_event(struct knote *kn, long hint __unused)
{
	struct cap_rt_instance *s;

	s = kn->kn_fp->f_data;
	mtx_assert(&s->ci_mtx, MA_OWNED);

	if (s->ci_flags & CAP_RT_SF_DEAD) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	kn->kn_data = s->ci_rxqlimit - s->ci_rxqlen;
	return (kn->kn_data > 0);
}

static const struct filterops cap_rt_wfiltops = {
	.f_isfd = 1,
	.f_detach = cap_rt_wkqops_detach,
	.f_event = cap_rt_wkqops_event,
	.f_copy = knote_triv_copy,
};

static int
cap_rt_instance_kqfilter(struct file *fp, struct knote *kn)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;
	bool can_recv, can_send;

	s = fp->f_data;
	svc = s->ci_service;
	if (svc == NULL)
		return (EOPNOTSUPP);

	can_send = svc->csvc_ops->co_handler != NULL;
	can_recv = can_send ||
	    (svc->csvc_svc_flags & CAP_RT_SVC_NOTIFY) != 0;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (!can_recv)
			return (EOPNOTSUPP);
		kn->kn_fop = &cap_rt_rfiltops;
		knlist_add(&s->ci_rknotes, kn, 0);
		return (0);
	case EVFILT_WRITE:
		if (!can_send)
			return (EOPNOTSUPP);
		kn->kn_fop = &cap_rt_wfiltops;
		knlist_add(&s->ci_wknotes, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static void
cap_rt_instance_fdclose(struct file *fp, int fd, struct thread *td)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;

	s = fp->f_data;

	/*
	 * Skip if finalized — co_revoke already ran and the service
	 * module may have unloaded.  The ops pointer could be stale.
	 */
	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & CAP_RT_SF_FINALIZED) {
		mtx_unlock(&s->ci_mtx);
		return;
	}
	mtx_unlock(&s->ci_mtx);

	svc = s->ci_service;
	if (svc != NULL)
		SDT_PROBE6(cap_rt, , , fd__close, svc->csvc_name,
		    s->ci_badge, fd, td->td_proc->p_pid, td->td_ucred,
		    cap_rt_proc_nonce(td->td_ucred));
	if (svc != NULL && svc->csvc_ops->co_fdclose != NULL)
		svc->csvc_ops->co_fdclose(s, fd, td, svc->csvc_arg);
}

static int
cap_rt_instance_stat(struct file *fp, struct stat *sb,
    struct ucred *active_cred __unused)
{
	struct cap_rt_instance *s;

	bzero(sb, sizeof(*sb));
	s = fp->f_data;
	sb->st_mode = S_IFREG | S_IRWXU;
	sb->st_size = atomic_load_acq_int(&s->ci_txqlen);
	return (0);
}

static int
cap_rt_instance_close(struct file *fp, struct thread *td __unused)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;

	s = fp->f_data;
	fp->f_data = NULL;
	svc = s->ci_service;

	/*
	 * Hold an explicit service ref for the duration of close.
	 * This keeps svc alive even if cap_rt_service_destroy
	 * force-finalizes our instance and releases the reservation
	 * ref before we finish.  The last close frees the service.
	 */
	if (svc != NULL)
		refcount_acquire(&svc->csvc_refcnt);

	if (svc != NULL)
		SDT_PROBE2(cap_rt, , , close, svc->csvc_name, s->ci_badge);

	/*
	 * Pre-drain: let any already-scheduled async task complete so
	 * messages in the RX queue are dispatched to their handler
	 * before we discard them.  Without this, a close that wins
	 * the mutex race against the taskqueue destroys messages the
	 * handler would have forwarded (e.g., cap_rt_pair).
	 */
	if (svc != NULL && svc->csvc_taskq != NULL)
		taskqueue_drain(svc->csvc_taskq, &s->ci_task);

	/* Mark closed and drain RX to prevent new dispatches. */
	mtx_lock(&s->ci_mtx);
	s->ci_flags |= CAP_RT_SF_CLOSED;

	cap_rt_instance_drain_rxq(s);

	/* Wait for in-flight handlers and calls to complete. */
	while (s->ci_inflight > 0)
		msleep(&s->ci_inflight, &s->ci_mtx, 0, "cap_rtterm", 0);

	cap_rt_instance_drain_txq(s);

	wakeup(&s->ci_txq);
	KNOTE_LOCKED(&s->ci_rknotes, 0);
	KNOTE_LOCKED(&s->ci_wknotes, 0);

	mtx_unlock(&s->ci_mtx);

	/* Post-drain: catch any task re-scheduled between the
	 * pre-drain and the CLOSED flag.  Harmless if nothing ran. */
	if (svc != NULL && svc->csvc_taskq != NULL)
		taskqueue_drain(svc->csvc_taskq, &s->ci_task);

	/*
	 * Wait for deferred work to release BEFORE firing co_revoke.
	 * Deferred tasks may still reference ci_priv; co_revoke may
	 * free it.
	 */
	while (refcount_load(&s->ci_refcnt) > 1)
		tsleep(s, 0, "cap_rtfr", CAP_RT_POLL_TICKS);
	refcount_release(&s->ci_refcnt);

	/* Fire co_revoke exactly once, after all work is done. */
	mtx_lock(&s->ci_mtx);
	if (!(s->ci_flags & CAP_RT_SF_FINALIZED)) {
		enum cap_rt_revoke_reason reason;

		s->ci_flags |= CAP_RT_SF_FINALIZED;
		if (s->ci_flags & CAP_RT_SF_REVOKED)
			reason = (svc != NULL &&
			    (svc->csvc_flags & CAP_RT_SVCF_DESTROYING)) ?
			    CAP_RT_REVOKE_UNLOAD :
			    CAP_RT_REVOKE_BY_SERVICE;
		else
			reason = CAP_RT_REVOKE_PEER_CLOSED;
		mtx_unlock(&s->ci_mtx);

		if (svc != NULL) {
			SDT_PROBE6(cap_rt, , , instance__finalize,
			    svc->csvc_name, s->ci_badge, reason,
			    td->td_proc->p_pid, td->td_ucred,
			    cap_rt_proc_nonce(td->td_ucred));
			SDT_PROBE6(cap_rt, , , state, svc->csvc_name,
			    s->ci_badge, s->ci_flags, s->ci_restricted,
			    td->td_proc->p_pid,
			    cap_rt_proc_nonce(td->td_ucred));
		}
		if (svc != NULL && svc->csvc_ops->co_revoke != NULL)
			svc->csvc_ops->co_revoke(s, s->ci_badge,
			    reason, svc->csvc_arg);
	} else {
		mtx_unlock(&s->ci_mtx);
	}

	/*
	 * Unlink from service under xlock.  LINKED is checked
	 * under xlock because cap_rt_service_destroy's force-finalize
	 * pass may clear it concurrently.
	 */
	if (svc != NULL) {
		bool was_linked;

		sx_xlock(&cap_rt_registry_lock);
		was_linked = (s->ci_flags & CAP_RT_SF_LINKED) != 0;
		if (was_linked) {
			LIST_REMOVE(s, ci_svc_link);
			svc->csvc_ninstances--;
			s->ci_flags &= ~CAP_RT_SF_LINKED;
		}
		sx_xunlock(&cap_rt_registry_lock);
		/* Release the reservation ref (from cap_rt_service_reserve). */
		if (was_linked)
			refcount_release(&svc->csvc_refcnt);
	}

	if (svc != NULL) {
		SDT_PROBE6(cap_rt, , , instance__lastclose, svc->csvc_name,
		    s->ci_badge, 0, td->td_proc->p_pid, td->td_ucred,
		    cap_rt_proc_nonce(td->td_ucred));
		SDT_PROBE6(cap_rt, , , state, svc->csvc_name, s->ci_badge,
		    s->ci_flags, s->ci_restricted, td->td_proc->p_pid,
		    cap_rt_proc_nonce(td->td_ucred));
	}
	cap_rt_instance_free(s);

	/* Release close's own ref.  May be the last — frees svc. */
	if (svc != NULL && refcount_release(&svc->csvc_refcnt))
		cap_rt_service_free(svc);

	return (0);
}

static int
cap_rt_instance_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;
	int flags, restricted;

	kif->kf_type = KF_TYPE_CAP_RT;
	s = fp->f_data;
	svc = s->ci_service;
	if (svc != NULL) {
		mtx_lock(&s->ci_mtx);
		flags = s->ci_flags;
		restricted = s->ci_restricted;
		mtx_unlock(&s->ci_mtx);
		snprintf(kif->kf_path, sizeof(kif->kf_path),
		    "cap_rt:%s[%ju]%s%s%s%s%s%s",
		    svc->csvc_name, (uintmax_t)s->ci_badge,
		    (restricted & CAP_RT_RF_NO_SEND) != 0 ? ":no-send" : "",
		    (restricted & CAP_RT_RF_NO_RECV) != 0 ? ":no-recv" : "",
		    (restricted & CAP_RT_RF_NO_CALL) != 0 ? ":no-call" : "",
		    (restricted & CAP_RT_RF_NO_MINT) != 0 ? ":no-mint" : "",
		    (flags & CAP_RT_SF_REVOKED) != 0 ? ":revoked" : "",
		    (flags & CAP_RT_SF_CLOSED) != 0 ? ":closed" : "");
	}
	return (0);
}

static int
cap_rt_instance_cmp(struct file *fp1, struct file *fp2,
    struct thread *td __unused)
{

	if (fp2->f_type != DTYPE_CAP_RT)
		return (3);
	return (file_kcmp_generic(fp1, fp2, NULL));
}

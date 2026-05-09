/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — message-passing capability framework.
 * Instance file descriptor operations.
 *
 * ioctl(CAP_RT_SENDMSG)  enqueue on RX, return immediately
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
SDT_PROBE_DECLARE(cap_rt, , , recv);
SDT_PROBE_DECLARE(cap_rt, , , call);
SDT_PROBE_DECLARE(cap_rt, , , close);

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
 *
 * GETINFO, LOCK, REVOKE_*, TERMINATE are always allowed — they are
 * introspection or capability-narrowing operations.
 */
static int
cap_rt_instance_ioctl_check(struct file *fp __unused, u_long cmd,
    const cap_rights_t *havep)
{
	cap_rights_t need;

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
	default:
		return (0);
	}
	return (cap_check(havep, &need));
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

/* Non-transferable variant — cannot be passed via SCM_RIGHTS. */
const struct fileops cap_rt_instance_noxfer_ops = {
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
	.fo_flags = 0,
};

/* ----------------------------------------------------------------
 * RX enqueue helper — enqueue on RX queue, schedule taskqueue
 * ---------------------------------------------------------------- */

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

/* ----------------------------------------------------------------
 * ioctl — SENDMSG, RECVMSG, GETINFO
 *
 * CAP_RT_SENDMSG and CAP_RT_RECVMSG are the canonical message API.
 * read()/write() are disabled (invfo_rdwr).  Capsicum ioctl
 * whitelisting via cap_ioctls_limit() controls which operations
 * a restricted fd can perform.
 * ---------------------------------------------------------------- */

static int
cap_rt_instance_do_sendmsg(struct cap_rt_instance *s,
    struct cap_rt_sendmsg_args *args, struct thread *td)
{
	struct cap_rt_service *svc;
	struct cap_rt_msg *msg;
	int fdbuf[CAP_RT_MAX_FDS];
	int error, i;

	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] | args->_reserved[2] | args->_reserved[3]) != 0)
		return (EINVAL);

	svc = s->ci_service;
	if (svc == NULL || svc->csvc_ops->co_handler == NULL)
		return (EOPNOTSUPP);

	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & CAP_RT_SF_DEAD) {
		mtx_unlock(&s->ci_mtx);
		return (EPIPE);
	}
	mtx_unlock(&s->ci_mtx);

	if (args->payload_len > CAP_RT_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (args->nfds > CAP_RT_MAX_FDS)
		return (EINVAL);

	/* Allocate fixed-size message — one allocation, no malloc. */
	msg = uma_zalloc(cap_rt_msg_zone, M_WAITOK | M_ZERO);

	/* Copyin payload directly into inline buffer. */
	if (args->payload_len > 0) {
		error = copyin(args->payload, msg->cm_data,
		    args->payload_len);
		if (error != 0) {
			uma_zfree(cap_rt_msg_zone, msg);
			return (error);
		}
	}
	msg->cm_datalen = args->payload_len;

	/* Resolve attached fds directly into inline slots. */
	if (args->nfds > 0) {
		error = copyin(args->fds, fdbuf, args->nfds * sizeof(int));
		if (error != 0) {
			uma_zfree(cap_rt_msg_zone, msg);
			return (error);
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
		goto sendmsg_build;

sendmsg_fd_err:
		while (--i >= 0) {
			fdrop(msg->cm_fds[i], td);
			msg->cm_fds[i] = NULL;
			filecaps_free(&msg->cm_fcaps[i]);
		}
		uma_zfree(cap_rt_msg_zone, msg);
		return (error);
	}

sendmsg_build:
	msg->cm_badge = s->ci_badge;
	msg->cm_reply_token = args->reply_token;
	msg->cm_cred = crhold(td->td_ucred);

	/*
	 * Enqueue on RX.  On success, msg (including buf and files)
	 * is owned by the queue.  On failure, enqueue_rx frees msg
	 * via cap_rt_msg_free which cleans up buf, files, and cred.
	 */
	mtx_lock(&s->ci_mtx);
	error = cap_rt_instance_enqueue_rx(s, msg);
	mtx_unlock(&s->ci_mtx);

	if (error == 0)
		SDT_PROBE3(cap_rt, , , send,
		    svc->csvc_name, s->ci_badge, args->payload_len);

	return (error);
}

static int
cap_rt_instance_do_recvmsg(struct cap_rt_instance *s, struct file *fp,
    struct cap_rt_recvmsg_args *args, struct thread *td)
{
	struct cap_rt_msg *msg;
	int fdbuf[CAP_RT_MAX_FDS];
	int error, i, nfds_out;

	if (args->flags != 0 || (args->_reserved[0] | args->_reserved[1] | args->_reserved[2] | args->_reserved[3]) != 0)
		return (EINVAL);

	mtx_lock(&s->ci_mtx);
	while (STAILQ_EMPTY(&s->ci_txq)) {
		if (s->ci_flags & CAP_RT_SF_REVOKED) {
			mtx_unlock(&s->ci_mtx);
			return (ECONNRESET);
		}
		if (s->ci_flags & CAP_RT_SF_CLOSED) {
			mtx_unlock(&s->ci_mtx);
			args->payload_len = 0;
			args->nfds = 0;
			args->badge = 0;
			args->reply_token = 0;
			memset(&args->trailer, 0, sizeof(args->trailer));
			return (0);
		}
		if (fp->f_flag & FNONBLOCK) {
			mtx_unlock(&s->ci_mtx);
			return (EAGAIN);
		}
		error = msleep(&s->ci_txq, &s->ci_mtx,
		    PCATCH, "cap_rtrv", 0);
		if (error != 0) {
			mtx_unlock(&s->ci_mtx);
			return (error);
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
		return (EMSGSIZE);
	}
	nfds_out = msg->cm_nfds;
	if (nfds_out > 0 && args->fds == NULL) {
		args->nfds = nfds_out;
		mtx_unlock(&s->ci_mtx);
		return (EMSGSIZE);
	}
	if (nfds_out > (int)args->nfds) {
		args->nfds = nfds_out;
		mtx_unlock(&s->ci_mtx);
		return (EMSGSIZE);
	}

	STAILQ_REMOVE_HEAD(&s->ci_txq, cm_link);
	s->ci_txqlen--;
	mtx_unlock(&s->ci_mtx);

	/* Copyout payload. */
	error = 0;
	if (msg->cm_datalen > 0 && msg->cm_data != NULL)
		error = copyout(msg->cm_data, args->payload, msg->cm_datalen);
	if (error != 0) {
		cap_rt_msg_free(msg);
		return (error);
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
	for (i = 0; i < nfds_out; i++) {
		struct filecaps *fc = &msg->cm_fcaps[i];

		/* Zeroed filecaps = no rights were set — pass NULL for full rights. */
		if (fc->fc_rights.cr_rights[0] == 0 &&
		    fc->fc_rights.cr_rights[1] == 0)
			fc = NULL;
		error = finstall(td, msg->cm_fds[i], &fdbuf[i], 0, fc);
		if (error != 0) {
			while (--i >= 0)
				kern_close(td, fdbuf[i]);
			cap_rt_msg_free(msg);
			args->nfds = 0;
			return (error);
		}
	}
	if (nfds_out > 0 && args->fds != NULL) {
		error = copyout(fdbuf, args->fds, nfds_out * sizeof(int));
		if (error != 0) {
			for (i = 0; i < nfds_out; i++)
				kern_close(td, fdbuf[i]);
			cap_rt_msg_free(msg);
			args->nfds = 0;
			return (error);
		}
	}
	args->nfds = nfds_out;

	if (s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , recv,
		    s->ci_service->csvc_name, s->ci_badge, args->payload_len);

	cap_rt_msg_free(msg);
	return (0);
}

static int
cap_rt_instance_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct cap_rt_instance *s;

	s = fp->f_data;
	if (s == NULL)
		return (EBADF);

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
		if (s->ci_restricted & CAP_RT_RF_NO_SEND)
			return (EACCES);
		return (cap_rt_instance_do_sendmsg(s,
		    (struct cap_rt_sendmsg_args *)data, td));
	case CAP_RT_RECVMSG:
		if (s->ci_restricted & CAP_RT_RF_NO_RECV)
			return (EACCES);
		return (cap_rt_instance_do_recvmsg(s, fp,
		    (struct cap_rt_recvmsg_args *)data, td));
	case CAP_RT_CALL: {
		struct cap_rt_call_args *ca = (struct cap_rt_call_args *)data;
		struct cap_rt_service *svc = s->ci_service;
		struct file **files;
		struct filecaps *call_fcaps;
		struct file *out_fds[CAP_RT_MAX_FDS];
		void *req_buf, *reply_buf;
		int fdbuf[CAP_RT_MAX_FDS];
		size_t rlen;
		int out_nfds;
		int err, i;

		if (s->ci_restricted & CAP_RT_RF_NO_CALL)
			return (EACCES);
		if (ca->flags != 0 || (ca->_reserved[0] |
		    ca->_reserved[1]) != 0)
			return (EINVAL);
		if (svc == NULL || svc->csvc_ops->co_call == NULL)
			return (EOPNOTSUPP);
		if (ca->req_nfds > CAP_RT_MAX_FDS)
			return (EINVAL);
		if (ca->reply_nfds > CAP_RT_MAX_FDS)
			return (EINVAL);

		mtx_lock(&s->ci_mtx);
		if (s->ci_flags & CAP_RT_SF_DEAD) {
			mtx_unlock(&s->ci_mtx);
			return (ECONNRESET);
		}
		/*
		 * Hold instance alive and track as inflight so revoke
		 * waits for us.  Do NOT set ci_handler_td — CALL does
		 * not support self-revoke.  Multiple CALLs can run
		 * concurrently; the service serializes if needed.
		 */
		cap_rt_instance_hold(s);
		s->ci_inflight++;
		mtx_unlock(&s->ci_mtx);

		/* Initialize for goto cleanup. */
		req_buf = NULL;
		files = NULL;
		call_fcaps = NULL;
		reply_buf = NULL;
		out_nfds = 0;
		memset(out_fds, 0, sizeof(out_fds));
		err = 0;

		if (ca->req_len > CAP_RT_MSG_PAYLOAD_SIZE) {
			err = EMSGSIZE;
			goto call_out;
		}
		/* Cap reply buffer at msg_size. */
		if (ca->reply_len > CAP_RT_MSG_PAYLOAD_SIZE)
			ca->reply_len = CAP_RT_MSG_PAYLOAD_SIZE;

		if (ca->req_len > 0) {
			req_buf = malloc(ca->req_len, M_CAP_RT, M_WAITOK);
			err = copyin(ca->req, req_buf, ca->req_len);
			if (err != 0)
				goto call_out;
		}

		/* Resolve attached fds with Capsicum rights. */
		if (ca->req_nfds > 0) {
			err = copyin(ca->req_fds, fdbuf,
			    ca->req_nfds * sizeof(int));
			if (err != 0)
				goto call_out;
			files = malloc(ca->req_nfds * sizeof(struct file *),
			    M_CAP_RT, M_WAITOK | M_ZERO);
			call_fcaps = malloc(ca->req_nfds *
			    sizeof(struct filecaps), M_CAP_RT,
			    M_WAITOK | M_ZERO);
			for (i = 0; i < (int)ca->req_nfds; i++) {
				err = fget_cap(td, fdbuf[i],
				    &cap_no_rights, NULL,
				    &files[i], &call_fcaps[i]);
				if (err != 0) {
					while (--i >= 0) {
						fdrop(files[i], td);
						files[i] = NULL;
						filecaps_free(&call_fcaps[i]);
					}
					goto call_out;
				}
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
		err = svc->csvc_ops->co_call(s, req_buf, ca->req_len,
		    files, call_fcaps, ca->req_nfds,
		    reply_buf, &rlen,
		    out_fds, &out_nfds,
		    svc->csvc_arg);

		/* Trim out_nfds to actual fds set by handler. */
		while (out_nfds > 0 && out_fds[out_nfds - 1] == NULL)
			out_nfds--;

		if (err == 0 && rlen > 0 && reply_buf != NULL) {
			if (rlen > ca->reply_len) {
				/*
				 * Reply too large for caller's buffer.
				 * Report the required size so they can
				 * retry.  Matches RECVMSG EMSGSIZE.
				 */
				ca->reply_len = rlen;
				err = EMSGSIZE;
			} else {
				err = copyout(reply_buf, ca->reply, rlen);
				ca->reply_len = rlen;
			}
		} else if (err == 0) {
			ca->reply_len = rlen;
		}

		/* Install reply fds into caller's fd table.
		 * If handler returned fds but caller has no buffer,
		 * drop them to avoid leaking. */
		if (err == 0 && out_nfds > 0 && ca->reply_fds == NULL) {
			for (i = 0; i < out_nfds; i++) {
				if (out_fds[i] != NULL) {
					fdrop(out_fds[i], td);
					out_fds[i] = NULL;
				}
			}
			out_nfds = 0;
		}
		if (err == 0 && out_nfds > 0 && ca->reply_fds != NULL) {
			for (i = 0; i < out_nfds; i++) {
				err = finstall(td, out_fds[i], &fdbuf[i],
				    0, NULL);
				/* Drop the handler's ref (finstall took its own). */
				fdrop(out_fds[i], td);
				out_fds[i] = NULL;
				if (err != 0) {
					while (--i >= 0)
						kern_close(td, fdbuf[i]);
					out_nfds = 0;
					break;
				}
			}
			if (err == 0) {
				err = copyout(fdbuf, ca->reply_fds,
				    out_nfds * sizeof(int));
				if (err != 0) {
					for (i = 0; i < out_nfds; i++)
						kern_close(td, fdbuf[i]);
					out_nfds = 0;
				}
			}
		}
		ca->reply_nfds = (err == 0) ? out_nfds : 0;

call_out:
		/* Drop reply fds not installed (error path). */
		if (err != 0) {
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

		cap_rt_instance_rele(s);
		return (err);
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
				info->features |= CAP_RT_INFO_F_KQUEUE;
			} else if ((svc->csvc_svc_flags & CAP_RT_SVC_KQUEUE) != 0)
				info->features |= CAP_RT_INFO_F_KQUEUE;
			if (svc->csvc_ops->co_call != NULL)
				info->features |= CAP_RT_INFO_F_CALL;
		}
		info->max_fds = CAP_RT_MAX_FDS;
		info->badge = s->ci_badge;
		return (0);
	}
	case CAP_RT_LOCK:
		/*
		 * Permanently prevent this fd from being passed via
		 * SCM_RIGHTS.  One-way latch — cannot be undone.
		 */
		fp->f_ops = &cap_rt_instance_noxfer_ops;
		return (0);
	case CAP_RT_REVOKE_SEND:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_SEND);
		return (0);
	case CAP_RT_REVOKE_RECV:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_RECV);
		return (0);
	case CAP_RT_REVOKE_CALL:
		atomic_set_int(&s->ci_restricted, CAP_RT_RF_NO_CALL);
		return (0);
	case CAP_RT_TERMINATE:
		cap_rt_instance_revoke(s);
		return (0);
	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * kqueue
 * ---------------------------------------------------------------- */

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

	s = fp->f_data;
	if (s == NULL)
		return (EBADF);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &cap_rt_rfiltops;
		knlist_add(&s->ci_rknotes, kn, 0);
		return (0);
	case EVFILT_WRITE:
		kn->kn_fop = &cap_rt_wfiltops;
		knlist_add(&s->ci_wknotes, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

/* ----------------------------------------------------------------
 * fdclose — per-fd notification (fires even if other refs remain)
 * ---------------------------------------------------------------- */

static void
cap_rt_instance_fdclose(struct file *fp, int fd, struct thread *td)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;

	s = fp->f_data;
	if (s == NULL)
		return;

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
	if (svc != NULL && svc->csvc_ops->co_fdclose != NULL)
		svc->csvc_ops->co_fdclose(s, fd, td, svc->csvc_arg);
}

/* ----------------------------------------------------------------
 * Stat / close / fill_kinfo / cmp
 * ---------------------------------------------------------------- */

static int
cap_rt_instance_stat(struct file *fp, struct stat *sb,
    struct ucred *active_cred __unused)
{
	struct cap_rt_instance *s;

	bzero(sb, sizeof(*sb));
	s = fp->f_data;
	if (s == NULL)
		return (EBADF);
	sb->st_mode = S_IFREG | S_IRWXU;
	mtx_lock(&s->ci_mtx);
	sb->st_size = s->ci_txqlen;
	mtx_unlock(&s->ci_mtx);
	return (0);
}

static int
cap_rt_instance_close(struct file *fp, struct thread *td __unused)
{
	struct cap_rt_instance *s;
	struct cap_rt_service *svc;

	s = fp->f_data;
	if (s == NULL)
		return (0);

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

	/* Drain the per-instance task so it can't run after free. */
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

	kif->kf_type = KF_TYPE_CAP_RT;
	s = fp->f_data;
	if (s != NULL) {
		svc = s->ci_service;
		if (svc != NULL)
			snprintf(kif->kf_path, sizeof(kif->kf_path),
			    "cap_rt:%s[%ju]", svc->csvc_name,
			    (uintmax_t)s->ci_badge);
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

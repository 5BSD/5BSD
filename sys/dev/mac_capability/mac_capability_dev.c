/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability — message-passing capability framework.
 * Instance file descriptor operations.
 *
 * ioctl(MAC_CAPABILITY_SENDMSG)  enqueue on RX, EAGAIN if full
 * ioctl(MAC_CAPABILITY_RECVMSG)  dequeue from TX (blocks if empty)
 * ioctl(MAC_CAPABILITY_GETINFO)  query service name, badge, limits
 *
 * read()/write() are disabled.  All messaging goes through the
 * structured ioctl API, which carries fds, reply tokens, and
 * credential metadata.  Capsicum cap_ioctls_limit() restricts
 * which operations a given fd can perform.
 */

#include "opt_capsicum.h"

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
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <vm/uma.h>

#include "mac_capability_internal.h"
#include "mac_capability_label.h"

MALLOC_DECLARE(M_MAC_CAPABILITY);

SDT_PROVIDER_DECLARE(mac_capability);
SDT_PROBE_DECLARE(mac_capability, , , send);
SDT_PROBE_DECLARE(mac_capability, , , send__done);
SDT_PROBE_DECLARE(mac_capability, , , recv);
SDT_PROBE_DECLARE(mac_capability, , , recv__done);
SDT_PROBE_DECLARE(mac_capability, , , call);
SDT_PROBE_DECLARE(mac_capability, , , call__done);
SDT_PROBE_DECLARE(mac_capability, , , close);
SDT_PROBE_DECLARE(mac_capability, , , fd__close);
SDT_PROBE_DECLARE(mac_capability, , , fd__receive);
SDT_PROBE_DECLARE(mac_capability, , , control);
SDT_PROBE_DECLARE(mac_capability, , , error);
SDT_PROBE_DECLARE(mac_capability, , , instance__finalize);
SDT_PROBE_DECLARE(mac_capability, , , instance__lastclose);
SDT_PROBE_DECLARE(mac_capability, , , rights__change);
SDT_PROBE_DECLARE(mac_capability, , , state);
SDT_PROBE_DECLARE(mac_capability, , , queue__pressure);

static fo_ioctl_t	mac_capability_instance_ioctl;
static fo_poll_t	mac_capability_instance_poll;
static fo_kqfilter_t	mac_capability_instance_kqfilter;
static fo_stat_t	mac_capability_instance_stat;
static fo_close_t	mac_capability_instance_close;
static fo_fdclose_t	mac_capability_instance_fdclose;
static fo_fill_kinfo_t	mac_capability_instance_fill_kinfo;
static fo_cmp_t		mac_capability_instance_cmp;

const struct fileops mac_capability_instance_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = mac_capability_instance_ioctl,
	.fo_poll = mac_capability_instance_poll,
	.fo_kqfilter = mac_capability_instance_kqfilter,
	.fo_stat = mac_capability_instance_stat,
	.fo_close = mac_capability_instance_close,
	.fo_fdclose = mac_capability_instance_fdclose,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = mac_capability_instance_fill_kinfo,
	.fo_cmp = mac_capability_instance_cmp,
	.fo_flags = DFLAG_PASSABLE,
};

static void
mac_capability_probe_fd_receive(struct file *fp, int fd, struct thread *td)
{
	struct mac_capability_instance *rs;
	struct mac_capability_service *rsvc;

	if (fp->f_type != DTYPE_MAC_CAPABILITY || fp->f_data == NULL)
		return;

	rs = fp->f_data;
	rsvc = rs->ci_service;
	if (rsvc == NULL)
		return;

	SDT_PROBE6(mac_capability, , , fd__receive, rsvc->csvc_name,
	    rs->ci_badge, fd, td->td_proc->p_pid, td->td_ucred,
	    mac_capability_proc_nonce(td->td_ucred));
}

static void
mac_capability_probe_control(struct mac_capability_instance *s, u_long cmd, struct thread *td)
{
	struct mac_capability_service *svc;

	svc = s->ci_service;
	if (svc == NULL)
		return;

	SDT_PROBE6(mac_capability, , , control, svc->csvc_name, s->ci_badge,
	    cmd, td->td_proc->p_pid, td->td_ucred,
	    mac_capability_proc_nonce(td->td_ucred));
}

static void
mac_capability_probe_error(struct mac_capability_instance *s, u_long op, int error,
    struct thread *td)
{
	struct mac_capability_service *svc;
	const char *svc_name __diagused;

	if (error == 0)
		return;
	svc = s->ci_service;
	svc_name = svc != NULL ? svc->csvc_name : "<none>";
	SDT_PROBE6(mac_capability, , , error, svc_name, s->ci_badge, op,
	    td->td_proc->p_pid, mac_capability_proc_nonce(td->td_ucred), error);
}

static void
mac_capability_probe_rights_change(struct mac_capability_instance *s, u_long cmd,
    struct thread *td)
{
	struct mac_capability_service *svc;
	int flags __diagused, restricted __diagused;

	svc = s->ci_service;
	if (svc == NULL)
		return;
	mtx_lock(&s->ci_mtx);
	flags = s->ci_flags;
	restricted = s->ci_restricted;
	mtx_unlock(&s->ci_mtx);
	SDT_PROBE6(mac_capability, , , rights__change, svc->csvc_name,
	    s->ci_badge, cmd, td->td_proc->p_pid, td->td_ucred,
	    mac_capability_proc_nonce(td->td_ucred));
	SDT_PROBE6(mac_capability, , , state, svc->csvc_name, s->ci_badge,
	    flags, restricted, td->td_proc->p_pid,
	    mac_capability_proc_nonce(td->td_ucred));
}

static int
mac_capability_instance_rx_ready(struct mac_capability_instance *s)
{
	struct mac_capability_service *svc;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	if (s->ci_flags & MAC_CAPABILITY_SF_DEAD) {
		return (ECONNRESET);
	}
	if (s->ci_rxqlen >= s->ci_rxqlimit) {
		svc = s->ci_service;
		if (svc != NULL) {
			SDT_PROBE5(mac_capability, , , queue__pressure,
			    svc->csvc_name, s->ci_badge, "rx",
			    s->ci_rxqlen, s->ci_rxqlimit);
		}
		return (EAGAIN);
	}
	return (0);
}

static void
mac_capability_instance_enqueue_rx_committed(
    struct mac_capability_instance *s, struct mac_capability_msg *msg)
{
	struct mac_capability_service *svc;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	KASSERT(mac_capability_instance_rx_ready(s) == 0,
	    ("%s: RX queue no longer has room", __func__));
	STAILQ_INSERT_TAIL(&s->ci_rxq, msg, cm_link);
	s->ci_rxqlen++;

	svc = s->ci_service;
	/*
	 * A multi-threaded taskqueue may run the same struct task concurrently
	 * when it is enqueued again after a worker has cleared ta_pending but
	 * before that worker returns.  Keep one task responsible for draining an
	 * instance so request and reply ordering stays FIFO.  Other instances
	 * still use the service's remaining taskqueue threads in parallel.
	 */
	if (svc != NULL && svc->csvc_taskq != NULL && !s->ci_dispatching) {
		s->ci_dispatching = true;
		taskqueue_enqueue(svc->csvc_taskq, &s->ci_task);
	}
}

static int
mac_capability_instance_enqueue_rx(struct mac_capability_instance *s,
    struct mac_capability_msg *msg)
{
	int error;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	error = mac_capability_instance_rx_ready(s);
	if (error != 0) {
		mac_capability_msg_free(msg);
		return (error);
	}
	mac_capability_instance_enqueue_rx_committed(s, msg);
	return (0);
}

static int
mac_capability_instance_do_sendmsg(struct mac_capability_instance *s,
    struct mac_capability_sendmsg_args *args, struct thread *td)
{
	struct mac_capability_service *svc;
	struct mac_capability_msg *msg;
	sbintime_t start __unused;
	const char *svc_name __unused;
	int fdbuf[MAC_CAPABILITY_MAX_FDS];
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

	if (atomic_load_acq_int(&s->ci_flags) & MAC_CAPABILITY_SF_DEAD) {
		error = EPIPE;
		goto out;
	}

	if (args->payload_len > MAC_CAPABILITY_MSG_PAYLOAD_SIZE) {
		error = EMSGSIZE;
		goto out;
	}
	if (args->nfds > MAC_CAPABILITY_MAX_FDS) {
		error = EINVAL;
		goto out;
	}

	msg = uma_zalloc(mac_capability_msg_zone, M_WAITOK | M_ZERO);

	/* Copyin payload directly into inline buffer. */
	if (args->payload_len > 0) {
		error = copyin(args->payload, msg->cm_data,
		    args->payload_len);
		if (error != 0) {
			uma_zfree(mac_capability_msg_zone, msg);
			goto out;
		}
	}
	msg->cm_datalen = args->payload_len;

	if (args->nfds > 0) {
		error = copyin(args->fds, fdbuf, args->nfds * sizeof(int));
		if (error != 0) {
			uma_zfree(mac_capability_msg_zone, msg);
			goto out;
		}
		for (i = 0; i < (int)args->nfds; i++) {
			error = fget_cap(td, fdbuf[i], &cap_no_rights,
			    NULL, &msg->cm_fds[i], &msg->cm_fcaps[i]);
			if (error != 0)
				goto sendmsg_fd_err;
			msg->cm_nfds++;
			if (!(msg->cm_fds[i]->f_ops->fo_flags &
			    DFLAG_PASSABLE)) {
				error = EINVAL;
				goto sendmsg_fd_err;
			}
		}

		/*
		 * Validate transfer state and reserve RX capacity under one
		 * critical section.  Transfer authority is consumed only after
		 * the message is known to be accepted, so EAGAIN is retryable.
		 */
		{
			struct filedesc *fdesc = td->td_proc->p_fd;
			struct filedescent *fde;

			FILEDESC_XLOCK(fdesc);
			for (i = 0; i < (int)args->nfds; i++) {
				fde = &fdesc->fd_ofiles[fdbuf[i]];
				if (fde->fde_file != msg->cm_fds[i]) {
					FILEDESC_XUNLOCK(fdesc);
					error = EBADF;
					goto sendmsg_fd_err;
				}
				if (fde->fde_xfer_state == CAP_XFER_NONE) {
					FILEDESC_XUNLOCK(fdesc);
					error = ENOTCAPABLE;
					goto sendmsg_fd_err;
				}
			}

			mtx_lock(&s->ci_mtx);
			error = mac_capability_instance_rx_ready(s);
			if (error != 0) {
				mtx_unlock(&s->ci_mtx);
				FILEDESC_XUNLOCK(fdesc);
				goto sendmsg_fd_err;
			}
			for (i = 0; i < (int)args->nfds; i++) {
				fde = &fdesc->fd_ofiles[fdbuf[i]];
				filecaps_free(&msg->cm_fcaps[i]);
				filecaps_copy(&fde->fde_caps,
				    &msg->cm_fcaps[i], true);
				filecaps_intersect(&msg->cm_fcaps[i],
				    &fde->fde_xfer_caps);
				if (fde->fde_xfer_state == CAP_XFER_ONCE) {
					fde->fde_xfer_state = CAP_XFER_NONE;
					msg->cm_xfer_state[i] = CAP_XFER_NONE;
				} else {
					msg->cm_xfer_state[i] =
					    fde->fde_xfer_state;
				}
				msg->cm_cloexec_state[i] =
				    fde->fde_cloexec_state;
				msg->cm_clofork_state[i] =
				    fde->fde_clofork_state;
				msg->cm_fde_flags[i] =
				    fde->fde_flags &
				    (UF_MMAP_CAPMODE | UF_LOOKUP_CAPMODE);
			}
			msg->cm_badge = s->ci_badge;
			msg->cm_reply_token = args->reply_token;
			msg->cm_cred = crhold(td->td_ucred);

			mac_capability_instance_enqueue_rx_committed(s, msg);
			mtx_unlock(&s->ci_mtx);
			FILEDESC_XUNLOCK(fdesc);

			SDT_PROBE3(mac_capability, , , send,
			    svc->csvc_name, s->ci_badge, args->payload_len);
			error = 0;
			goto out;
		}

sendmsg_fd_err:
		mac_capability_msg_free(msg);
		goto out;
	}

	/* No fds — build and enqueue directly. */
	msg->cm_badge = s->ci_badge;
	msg->cm_reply_token = args->reply_token;
	msg->cm_cred = crhold(td->td_ucred);

	mtx_lock(&s->ci_mtx);
	error = mac_capability_instance_enqueue_rx(s, msg);
	mtx_unlock(&s->ci_mtx);

	if (error == 0)
		SDT_PROBE3(mac_capability, , , send,
		    svc->csvc_name, s->ci_badge, args->payload_len);

out:
	SDT_PROBE6(mac_capability, , , send__done, svc_name, s->ci_badge,
	    args->payload_len, args->nfds, error, getsbinuptime() - start);
	mac_capability_probe_error(s, MAC_CAPABILITY_SENDMSG, error, td);
	return (error);
}

static int
mac_capability_instance_do_recvmsg(struct mac_capability_instance *s, struct file *fp,
    struct mac_capability_recvmsg_args *args, struct thread *td)
{
	struct mac_capability_msg *msg;
	sbintime_t start __unused;
	const char *svc_name __unused;
	int fdbuf[MAC_CAPABILITY_MAX_FDS];
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
		if (s->ci_flags & MAC_CAPABILITY_SF_REVOKED) {
			mtx_unlock(&s->ci_mtx);
			error = ECONNRESET;
			goto out;
		}
		if (s->ci_flags & MAC_CAPABILITY_SF_CLOSED) {
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
		    PCATCH, "mac_capabilityrv", 0);
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

	/*
	 * Notify a bearer after capacity is genuinely released.  The callback
	 * may schedule a peer whose accepted RX head is waiting to forward.
	 */
	if (s->ci_service != NULL &&
	    s->ci_service->csvc_ops->co_txdrain != NULL)
		s->ci_service->csvc_ops->co_txdrain(s,
		    s->ci_service->csvc_arg);

	/* Copyout payload. */
	if (msg->cm_datalen > 0)
		error = copyout(msg->cm_data, args->payload, msg->cm_datalen);
	if (error != 0) {
		mac_capability_msg_free(msg);
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
		    mac_capability_proc_nonce(msg->cm_cred);
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
				mac_capability_msg_free(msg);
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
			fdesc->fd_ofiles[fdbuf[installed]].fde_cloexec_state =
			    msg->cm_cloexec_state[installed];
			fdesc->fd_ofiles[fdbuf[installed]].fde_clofork_state =
			    msg->cm_clofork_state[installed];
			fdesc->fd_ofiles[fdbuf[installed]].fde_flags |=
			    msg->cm_fde_flags[installed] &
			    (UF_MMAP_CAPMODE | UF_LOOKUP_CAPMODE);
		}
		FILEDESC_XUNLOCK(fdesc);
		if (installed < nfds_out) {
			/* fdrop refs for fds not installed. */
			for (i = installed; i < nfds_out; i++)
				fdrop(msg->cm_fds[i], td);
			/* Close fds that were installed. */
			for (i = 0; i < installed; i++)
				kern_close(td, fdbuf[i]);
			mac_capability_msg_free(msg);
			args->nfds = 0;
			goto out;
		}
		for (i = 0; i < nfds_out; i++)
			mac_capability_probe_fd_receive(msg->cm_fds[i], fdbuf[i], td);
	}
	if (nfds_out > 0 && args->fds != NULL) {
		error = copyout(fdbuf, args->fds, nfds_out * sizeof(int));
		if (error != 0) {
			for (i = 0; i < nfds_out; i++)
				kern_close(td, fdbuf[i]);
			mac_capability_msg_free(msg);
			args->nfds = 0;
			goto out;
		}
	}
	args->nfds = nfds_out;

	if (s->ci_service != NULL)
		SDT_PROBE3(mac_capability, , , recv,
		    s->ci_service->csvc_name, s->ci_badge, args->payload_len);

	mac_capability_msg_free(msg);
out:
	SDT_PROBE6(mac_capability, , , recv__done, svc_name, s->ci_badge,
	    args->payload_len, args->nfds, error, getsbinuptime() - start);
	mac_capability_probe_error(s, MAC_CAPABILITY_RECVMSG, error, td);
	return (error);
}

static int
mac_capability_instance_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct mac_capability_instance *s;

	s = fp->f_data;

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		/*
		 * Generic fcntl(F_SETFL) translates O_NONBLOCK/O_ASYNC into
		 * these ioctls.  mac_capability has no device-specific state to toggle;
		 * successful return lets the generic layer update f_flag.
		 */
		return (0);
	case MAC_CAPABILITY_SENDMSG:
		if (s->ci_restricted & MAC_CAPABILITY_RF_NO_SEND) {
			mac_capability_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		return (mac_capability_instance_do_sendmsg(s,
		    (struct mac_capability_sendmsg_args *)data, td));
	case MAC_CAPABILITY_RECVMSG:
		if (s->ci_restricted & MAC_CAPABILITY_RF_NO_RECV) {
			mac_capability_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		return (mac_capability_instance_do_recvmsg(s, fp,
		    (struct mac_capability_recvmsg_args *)data, td));
	case MAC_CAPABILITY_CALL: {
		struct mac_capability_call_args *ca = (struct mac_capability_call_args *)data;
		struct mac_capability_service *svc = s->ci_service;
		sbintime_t start __unused;
		bool held;
		const char *svc_name __unused;
		struct file **files;
		struct filecaps *call_fcaps;
		uint8_t call_xfer_state[MAC_CAPABILITY_MAX_FDS];
		uint8_t call_cloexec_state[MAC_CAPABILITY_MAX_FDS];
		uint8_t call_clofork_state[MAC_CAPABILITY_MAX_FDS];
		struct file *out_fds[MAC_CAPABILITY_MAX_FDS];
		void *req_buf, *reply_buf;
		int fdbuf[MAC_CAPABILITY_MAX_FDS];
		size_t rlen;
		int out_nfds;
		int error, i;

		start = getsbinuptime();
		held = false;
		svc_name = (svc != NULL) ? svc->csvc_name : "<none>";
		if (s->ci_restricted & MAC_CAPABILITY_RF_NO_CALL) {
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
		if (ca->req_nfds > MAC_CAPABILITY_MAX_FDS ||
		    ca->reply_nfds > MAC_CAPABILITY_MAX_FDS) {
			error = EINVAL;
			goto call_done;
		}

		mtx_lock(&s->ci_mtx);
		if (s->ci_flags & MAC_CAPABILITY_SF_DEAD) {
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
		mac_capability_instance_hold(s);
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

		if (ca->req_len > MAC_CAPABILITY_MSG_PAYLOAD_SIZE) {
			error = EMSGSIZE;
			goto call_out;
		}
		/* Cap reply buffer at msg_size. */
		if (ca->reply_len > MAC_CAPABILITY_MSG_PAYLOAD_SIZE)
			ca->reply_len = MAC_CAPABILITY_MSG_PAYLOAD_SIZE;

		if (ca->req_len > 0) {
			req_buf = malloc(ca->req_len, M_MAC_CAPABILITY, M_WAITOK);
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
			    M_MAC_CAPABILITY, M_WAITOK | M_ZERO);
			call_fcaps = malloc(ca->req_nfds *
			    sizeof(struct filecaps), M_MAC_CAPABILITY,
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
						filecaps_free(
						    &call_fcaps[i]);
						filecaps_copy(
						    &fde->fde_caps,
						    &call_fcaps[i], true);
						filecaps_intersect(
						    &call_fcaps[i],
						    &fde->fde_xfer_caps);
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
						call_cloexec_state[i] =
						    fde->fde_cloexec_state;
						call_clofork_state[i] =
						    fde->fde_clofork_state;
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
			reply_buf = malloc(rlen, M_MAC_CAPABILITY, M_WAITOK | M_ZERO);

		out_nfds = ca->reply_nfds;

		/* Stamp caller credentials — same contract as RECVMSG. */
		ca->trailer.uid = td->td_ucred->cr_uid;
		ca->trailer.gid = td->td_ucred->cr_gid;
		ca->trailer.prison_id =
		    td->td_ucred->cr_prison->pr_id;
		ca->trailer.nonce = mac_capability_proc_nonce(td->td_ucred);

		SDT_PROBE3(mac_capability, , , call,
		    svc->csvc_name, s->ci_badge, ca->req_len);
		error = svc->csvc_ops->co_call(s, req_buf, ca->req_len,
		    files, call_fcaps, ca->req_nfds,
		    reply_buf, &rlen,
		    out_fds, &out_nfds,
		    svc->csvc_arg);

		/* Clamp and trim out_nfds to actual fds set by handler. */
		if (out_nfds > MAC_CAPABILITY_MAX_FDS)
			out_nfds = MAC_CAPABILITY_MAX_FDS;
		/*
		 * The handler must not exceed the caller's declared reply fd
		 * capacity: the copyout below writes out_nfds slots into the
		 * caller's reply_fds array, so an oversized count would
		 * corrupt caller memory.  Drop any excess fds.
		 */
		while (out_nfds > (int)ca->reply_nfds) {
			out_nfds--;
			if (out_fds[out_nfds] != NULL) {
				fdrop(out_fds[out_nfds], td);
				out_fds[out_nfds] = NULL;
			}
		}
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
						if (j >= 0) {
							fdesc->fd_ofiles[
							    fdbuf[i]].
							    fde_xfer_state =
							    call_xfer_state[j];
							fdesc->fd_ofiles[
							    fdbuf[i]].
							    fde_cloexec_state =
							    call_cloexec_state[j];
							fdesc->fd_ofiles[
							    fdbuf[i]].
							    fde_clofork_state =
							    call_clofork_state[j];
						}
					}
					FILEDESC_XUNLOCK(fdesc);
					if (error != 0)
						fdrop(out_fds[i], td);
				}
				if (error == 0) {
					mac_capability_probe_fd_receive(out_fds[i],
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
			free(files, M_MAC_CAPABILITY);
		}
		if (call_fcaps != NULL) {
			for (i = 0; i < (int)ca->req_nfds; i++)
				filecaps_free(&call_fcaps[i]);
			free(call_fcaps, M_MAC_CAPABILITY);
		}
		free(req_buf, M_MAC_CAPABILITY);
		free(reply_buf, M_MAC_CAPABILITY);

		mtx_lock(&s->ci_mtx);
		s->ci_inflight--;
		if (s->ci_inflight == 0 && (s->ci_flags & MAC_CAPABILITY_SF_DEAD)) {
			wakeup(&s->ci_inflight);
			/* Wake service destroy loop waiting on svc. */
			wakeup(s->ci_service);
		}
		mtx_unlock(&s->ci_mtx);

		if (held)
			mac_capability_instance_rele(s);
call_done:
		SDT_PROBE6(mac_capability, , , call__done, svc_name, s->ci_badge,
		    ca->req_len, ca->reply_len, error, getsbinuptime() - start);
		mac_capability_probe_error(s, MAC_CAPABILITY_CALL, error, td);
		return (error);
	}
	case MAC_CAPABILITY_GETINFO: {
		struct mac_capability_info_args *info = (struct mac_capability_info_args *)data;
		struct mac_capability_service *svc = s->ci_service;

		memset(info, 0, sizeof(*info));
		if (svc != NULL) {
			strlcpy(info->name, svc->csvc_name,
			    sizeof(info->name));
			info->msg_limit = MAC_CAPABILITY_MSG_PAYLOAD_SIZE;
			info->queue_depth = svc->csvc_queue_depth;
			info->tx_limit = svc->csvc_tx_limit;
			if (svc->csvc_ops->co_handler != NULL) {
				info->features |= MAC_CAPABILITY_INFO_F_SENDMSG;
				info->features |= MAC_CAPABILITY_INFO_F_RECVMSG;
				info->features |= MAC_CAPABILITY_INFO_F_KQUEUE;
			}
			if ((svc->csvc_svc_flags & MAC_CAPABILITY_SVC_NOTIFY) != 0) {
				info->features |= MAC_CAPABILITY_INFO_F_RECVMSG;
				info->features |= MAC_CAPABILITY_INFO_F_KQUEUE;
			}
			if (svc->csvc_ops->co_call != NULL)
				info->features |= MAC_CAPABILITY_INFO_F_CALL;
		}
		info->max_fds = MAC_CAPABILITY_MAX_FDS;
		info->badge = s->ci_badge;
		return (0);
	}
	case MAC_CAPABILITY_REVOKE_SEND:
		atomic_set_int(&s->ci_restricted, MAC_CAPABILITY_RF_NO_SEND);
		mac_capability_probe_control(s, cmd, td);
		mac_capability_probe_rights_change(s, cmd, td);
		return (0);
	case MAC_CAPABILITY_REVOKE_RECV:
		atomic_set_int(&s->ci_restricted, MAC_CAPABILITY_RF_NO_RECV);
		mac_capability_probe_control(s, cmd, td);
		mac_capability_probe_rights_change(s, cmd, td);
		return (0);
	case MAC_CAPABILITY_REVOKE_CALL:
		atomic_set_int(&s->ci_restricted, MAC_CAPABILITY_RF_NO_CALL);
		mac_capability_probe_control(s, cmd, td);
		mac_capability_probe_rights_change(s, cmd, td);
		return (0);
	case MAC_CAPABILITY_REVOKE_MINT:
		atomic_set_int(&s->ci_restricted, MAC_CAPABILITY_RF_NO_MINT);
		mac_capability_probe_control(s, cmd, td);
		mac_capability_probe_rights_change(s, cmd, td);
		return (0);
	case MAC_CAPABILITY_TERMINATE:
		mac_capability_probe_control(s, cmd, td);
		mac_capability_instance_revoke(s);
		return (0);
	case MAC_CAPABILITY_MINT_INSTANCE: {
		struct mac_capability_mint_instance_args *ma;
		struct mac_capability_service *svc;
		uint64_t badge;
		int error, newfd;

		ma = (struct mac_capability_mint_instance_args *)data;
		if (ma->flags != 0 ||
		    (ma->_reserved[0] | ma->_reserved[1]) != 0) {
			mac_capability_probe_error(s, cmd, EINVAL, td);
			return (EINVAL);
		}

		if (s->ci_restricted & MAC_CAPABILITY_RF_NO_MINT) {
			mac_capability_probe_error(s, cmd, EACCES, td);
			return (EACCES);
		}
		svc = s->ci_service;
		if (svc == NULL) {
			mac_capability_probe_error(s, cmd, ENXIO, td);
			return (ENXIO);
		}
		if (!(svc->csvc_svc_flags & MAC_CAPABILITY_SVC_MINTABLE)) {
			mac_capability_probe_error(s, cmd, EOPNOTSUPP, td);
			return (EOPNOTSUPP);
		}

		/* Run co_connect for authorization. */
		badge = 0;
		if (svc->csvc_ops->co_connect != NULL) {
			error = svc->csvc_ops->co_connect(td->td_ucred,
			    svc->csvc_arg, &badge);
			if (error != 0) {
				mac_capability_probe_error(s, cmd, error, td);
				return (error);
			}
		}

		error = mac_capability_instance_create(svc, td, badge, &newfd);
		if (error != 0) {
			mac_capability_probe_error(s, cmd, error, td);
			return (error);
		}

		ma->fd = newfd;
		mac_capability_probe_control(s, cmd, td);
		return (0);
	}
	default:
		return (ENOTTY);
	}
}

/*
 * Capability channels are kqueue-only.  poll(2)/select(2) are deliberately
 * unsupported: readiness is level state that only the EVFILT_READ/EVFILT_WRITE
 * kqfilters report correctly.  Return POLLNVAL so a poll/select caller fails
 * loudly (it must switch to kqueue) rather than receiving invfo_poll's
 * unconditional "readable/writable", which busy-spins a poll loop against a
 * channel that has no pending message.
 */
static int
mac_capability_instance_poll(struct file *fp __unused, int events __unused,
    struct ucred *active_cred __unused, struct thread *td __unused)
{

	return (POLLNVAL);
}

/* EVFILT_READ */
static void
mac_capability_rkqops_detach(struct knote *kn)
{
	struct mac_capability_instance *s;

	s = kn->kn_fp->f_data;
	knlist_remove(&s->ci_rknotes, kn, 0);
}

static int
mac_capability_rkqops_event(struct knote *kn, long hint __unused)
{
	struct mac_capability_instance *s;

	s = kn->kn_fp->f_data;
	mtx_assert(&s->ci_mtx, MA_OWNED);

	if (s->ci_flags & MAC_CAPABILITY_SF_DEAD) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	kn->kn_data = s->ci_txqlen;
	return (s->ci_txqlen > 0);
}

static const struct filterops mac_capability_rfiltops = {
	.f_isfd = 1,
	.f_detach = mac_capability_rkqops_detach,
	.f_event = mac_capability_rkqops_event,
	.f_copy = knote_triv_copy,
};

/* kqueue EVFILT_WRITE */
static void
mac_capability_wkqops_detach(struct knote *kn)
{
	struct mac_capability_instance *s;

	s = kn->kn_fp->f_data;
	knlist_remove(&s->ci_wknotes, kn, 0);
}

static int
mac_capability_wkqops_event(struct knote *kn, long hint __unused)
{
	struct mac_capability_instance *s;

	s = kn->kn_fp->f_data;
	mtx_assert(&s->ci_mtx, MA_OWNED);

	if (s->ci_flags & MAC_CAPABILITY_SF_DEAD) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	kn->kn_data = s->ci_rxqlimit - s->ci_rxqlen;
	return (kn->kn_data > 0);
}

static const struct filterops mac_capability_wfiltops = {
	.f_isfd = 1,
	.f_detach = mac_capability_wkqops_detach,
	.f_event = mac_capability_wkqops_event,
	.f_copy = knote_triv_copy,
};

static int
mac_capability_instance_kqfilter(struct file *fp, struct knote *kn)
{
	struct mac_capability_instance *s;
	struct mac_capability_service *svc;
	bool can_recv, can_send;

	s = fp->f_data;
	svc = s->ci_service;
	if (svc == NULL)
		return (EOPNOTSUPP);

	can_send = svc->csvc_ops->co_handler != NULL;
	can_recv = can_send ||
	    (svc->csvc_svc_flags & MAC_CAPABILITY_SVC_NOTIFY) != 0;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (!can_recv)
			return (EOPNOTSUPP);
		kn->kn_fop = &mac_capability_rfiltops;
		knlist_add(&s->ci_rknotes, kn, 0);
		return (0);
	case EVFILT_WRITE:
		if (!can_send)
			return (EOPNOTSUPP);
		kn->kn_fop = &mac_capability_wfiltops;
		knlist_add(&s->ci_wknotes, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static void
mac_capability_instance_fdclose(struct file *fp, int fd, struct thread *td)
{
	struct mac_capability_instance *s;
	struct mac_capability_service *svc;

	s = fp->f_data;

	/*
	 * Skip if finalized — co_revoke already ran and the service
	 * module may have unloaded.  The ops pointer could be stale.
	 */
	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & MAC_CAPABILITY_SF_FINALIZED) {
		mtx_unlock(&s->ci_mtx);
		return;
	}
	mtx_unlock(&s->ci_mtx);

	svc = s->ci_service;
	if (svc != NULL)
		SDT_PROBE6(mac_capability, , , fd__close, svc->csvc_name,
		    s->ci_badge, fd, td->td_proc->p_pid, td->td_ucred,
		    mac_capability_proc_nonce(td->td_ucred));
	if (svc != NULL && svc->csvc_ops->co_fdclose != NULL)
		svc->csvc_ops->co_fdclose(s, fd, td, svc->csvc_arg);
}

static int
mac_capability_instance_stat(struct file *fp, struct stat *sb,
    struct ucred *active_cred __unused)
{
	struct mac_capability_instance *s;

	bzero(sb, sizeof(*sb));
	s = fp->f_data;
	sb->st_mode = S_IFREG | S_IRWXU;
	sb->st_size = atomic_load_acq_int(&s->ci_txqlen);
	return (0);
}

static int
mac_capability_instance_close(struct file *fp, struct thread *td __unused)
{
	struct mac_capability_instance *s;
	struct mac_capability_service *svc;

	s = fp->f_data;
	fp->f_data = NULL;
	svc = s->ci_service;

	/*
	 * Hold an explicit service ref for the duration of close.
	 * This keeps svc alive even if mac_capability_service_destroy
	 * force-finalizes our instance and releases the reservation
	 * ref before we finish.  The last close frees the service.
	 */
	if (svc != NULL)
		refcount_acquire(&svc->csvc_refcnt);

	if (svc != NULL)
		SDT_PROBE2(mac_capability, , , close, svc->csvc_name, s->ci_badge);

	/*
	 * Pre-drain: let any already-scheduled async task complete so
	 * messages in the RX queue are dispatched to their handler
	 * before we discard them.  Without this, a close that wins
	 * the mutex race against the taskqueue destroys messages the
	 * handler would have forwarded (e.g., mac_capability_channel).
	 */
	if (svc != NULL && svc->csvc_taskq != NULL)
		taskqueue_drain(svc->csvc_taskq, &s->ci_task);

	struct mac_capability_msgq deadrx, deadtx;

	STAILQ_INIT(&deadrx);
	STAILQ_INIT(&deadtx);

	/* Mark closed and detach RX to prevent new dispatches.  Freeing is
	 * deferred until after ci_mtx is dropped: a queued message may carry an
	 * attached capability fd whose fdrop re-enters this close path and
	 * drains a taskqueue (sleepable), which must not happen under ci_mtx. */
	mtx_lock(&s->ci_mtx);
	s->ci_flags |= MAC_CAPABILITY_SF_CLOSED;

	STAILQ_CONCAT(&deadrx, &s->ci_rxq);
	s->ci_rxqlen = 0;

	/* Wait for in-flight handlers and calls to complete. */
	while (s->ci_inflight > 0)
		msleep(&s->ci_inflight, &s->ci_mtx, 0, "mac_capabilityterm", 0);

	STAILQ_CONCAT(&deadtx, &s->ci_txq);
	s->ci_txqlen = 0;

	wakeup(&s->ci_txq);
	KNOTE_LOCKED(&s->ci_rknotes, 0);
	KNOTE_LOCKED(&s->ci_wknotes, 0);

	mtx_unlock(&s->ci_mtx);

	mac_capability_free_msgq(&deadrx);
	mac_capability_free_msgq(&deadtx);

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
		tsleep(s, 0, "mac_capabilityfr", MAC_CAPABILITY_POLL_TICKS);
	refcount_release(&s->ci_refcnt);

	/* Fire co_revoke exactly once, after all work is done. */
	mtx_lock(&s->ci_mtx);
	if (!(s->ci_flags & MAC_CAPABILITY_SF_FINALIZED)) {
		enum mac_capability_revoke_reason reason;

		s->ci_flags |= MAC_CAPABILITY_SF_FINALIZED;
		if (s->ci_flags & MAC_CAPABILITY_SF_REVOKED)
			reason = (svc != NULL &&
			    (svc->csvc_flags & MAC_CAPABILITY_SVCF_DESTROYING)) ?
			    MAC_CAPABILITY_REVOKE_UNLOAD :
			    MAC_CAPABILITY_REVOKE_BY_SERVICE;
		else
			reason = MAC_CAPABILITY_REVOKE_PEER_CLOSED;
		mtx_unlock(&s->ci_mtx);

		if (svc != NULL) {
			SDT_PROBE6(mac_capability, , , instance__finalize,
			    svc->csvc_name, s->ci_badge, reason,
			    td->td_proc->p_pid, td->td_ucred,
			    mac_capability_proc_nonce(td->td_ucred));
			SDT_PROBE6(mac_capability, , , state, svc->csvc_name,
			    s->ci_badge, s->ci_flags, s->ci_restricted,
			    td->td_proc->p_pid,
			    mac_capability_proc_nonce(td->td_ucred));
		}
		if (svc != NULL && svc->csvc_ops->co_revoke != NULL)
			svc->csvc_ops->co_revoke(s, s->ci_badge,
			    reason, svc->csvc_arg);
	} else {
		mtx_unlock(&s->ci_mtx);
	}

	/*
	 * Unlink from service under xlock.  LINKED is checked
	 * under xlock because mac_capability_service_destroy's force-finalize
	 * pass may clear it concurrently.
	 */
	if (svc != NULL) {
		bool was_linked;

		sx_xlock(&mac_capability_registry_lock);
		was_linked = (s->ci_flags & MAC_CAPABILITY_SF_LINKED) != 0;
		if (was_linked) {
			LIST_REMOVE(s, ci_svc_link);
			svc->csvc_ninstances--;
			s->ci_flags &= ~MAC_CAPABILITY_SF_LINKED;
		}
		sx_xunlock(&mac_capability_registry_lock);
		/* Release the reservation ref (from mac_capability_service_reserve). */
		if (was_linked)
			refcount_release(&svc->csvc_refcnt);
	}

	if (svc != NULL) {
		SDT_PROBE6(mac_capability, , , instance__lastclose, svc->csvc_name,
		    s->ci_badge, 0, td->td_proc->p_pid, td->td_ucred,
		    mac_capability_proc_nonce(td->td_ucred));
		SDT_PROBE6(mac_capability, , , state, svc->csvc_name, s->ci_badge,
		    s->ci_flags, s->ci_restricted, td->td_proc->p_pid,
		    mac_capability_proc_nonce(td->td_ucred));
	}
	mac_capability_instance_free(s);

	/* Release close's own ref.  May be the last — frees svc. */
	if (svc != NULL && refcount_release(&svc->csvc_refcnt))
		mac_capability_service_free(svc);

	return (0);
}

static int
mac_capability_instance_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct mac_capability_instance *s;
	struct mac_capability_service *svc;
	int flags, restricted;

	kif->kf_type = KF_TYPE_MAC_CAPABILITY;
	s = fp->f_data;
	svc = s->ci_service;
	if (svc != NULL) {
		mtx_lock(&s->ci_mtx);
		flags = s->ci_flags;
		restricted = s->ci_restricted;
		mtx_unlock(&s->ci_mtx);
		snprintf(kif->kf_path, sizeof(kif->kf_path),
		    "mac_capability:%s[%ju]%s%s%s%s%s%s",
		    svc->csvc_name, (uintmax_t)s->ci_badge,
		    (restricted & MAC_CAPABILITY_RF_NO_SEND) != 0 ? ":no-send" : "",
		    (restricted & MAC_CAPABILITY_RF_NO_RECV) != 0 ? ":no-recv" : "",
		    (restricted & MAC_CAPABILITY_RF_NO_CALL) != 0 ? ":no-call" : "",
		    (restricted & MAC_CAPABILITY_RF_NO_MINT) != 0 ? ":no-mint" : "",
		    (flags & MAC_CAPABILITY_SF_REVOKED) != 0 ? ":revoked" : "",
		    (flags & MAC_CAPABILITY_SF_CLOSED) != 0 ? ":closed" : "");
	}
	return (0);
}

static int
mac_capability_instance_cmp(struct file *fp1, struct file *fp2,
    struct thread *td __unused)
{

	if (fp2->f_type != DTYPE_MAC_CAPABILITY)
		return (3);
	return (file_kcmp_generic(fp1, fp2, NULL));
}

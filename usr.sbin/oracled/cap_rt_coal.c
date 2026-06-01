/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT coalition wrappers for oracled.
 *
 * Wraps CAP_RT_CALL ioctls for the coalition service so that
 * callers don't need to know the wire protocol.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "cap_rt_priv.h"

int
cap_rt_coalition_enlist(int coalition_fd, int member_fd)
{
	struct cap_rt_call_args call;
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_ENLIST;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &member_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_set_leader(int coalition_fd, int leader_fd)
{
	struct cap_rt_call_args call;
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_SET_LEADER;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &leader_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_set_deadline(int coalition_fd, int timeout_ms,
    int sig, int grace_ms)
{
	struct coalition_set_deadline_req dreq;
	struct coalition_reply reply;

	memset(&dreq, 0, sizeof(dreq));
	dreq.op = COALITION_OP_SET_DEADLINE;
	dreq.timeout_ms = (uint32_t)timeout_ms;
	dreq.signal = sig;
	dreq.grace_ms = (uint32_t)grace_ms;

	if (cap_rt_do_call(coalition_fd, &dreq, sizeof(dreq),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_terminate(int coalition_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_TERMINATE;

	if (cap_rt_do_call(coalition_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_recv_event(int coalition_fd, uint32_t *flagsp)
{
	struct cap_rt_recvmsg_args ra;
	struct coalition_event_msg ev;

	memset(&ev, 0, sizeof(ev));
	memset(&ra, 0, sizeof(ra));
	ra.payload = &ev;
	ra.payload_len = sizeof(ev);

	if (ioctl(coalition_fd, CAP_RT_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (1);
		return (-1);
	}

	if (ra.payload_len < sizeof(ev))
		return (-1);
	*flagsp = ev.flags;
	return (0);
}

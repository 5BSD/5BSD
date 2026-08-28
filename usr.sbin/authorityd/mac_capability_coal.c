/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY coalition wrappers for authorityd.
 *
 * Wraps MAC_CAPABILITY_CALL ioctls for the coalition service so that
 * callers don't need to know the wire protocol.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "authorityd.h"
#include "mac_capability_priv.h"

int
mac_capability_coalition_enlist(int coalition_fd, int member_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_ENLIST;

	if (mac_capability_do_call_fds(coalition_fd, &req, sizeof(req),
	    &member_fd, 1, &reply, sizeof(reply), NULL, 0) == -1)
		return (-1);
	return (reply.status);
}

int
mac_capability_coalition_set_leader(int coalition_fd, int leader_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_SET_LEADER;

	if (mac_capability_do_call_fds(coalition_fd, &req, sizeof(req),
	    &leader_fd, 1, &reply, sizeof(reply), NULL, 0) == -1)
		return (-1);
	return (reply.status);
}

int
mac_capability_coalition_set_deadline(int coalition_fd, int timeout_ms,
    int sig, int grace_ms)
{
	struct coalition_set_deadline_req dreq;
	struct coalition_reply reply;

	memset(&dreq, 0, sizeof(dreq));
	dreq.op = COALITION_OP_SET_DEADLINE;
	dreq.timeout_ms = (uint32_t)timeout_ms;
	dreq.signal = sig;
	dreq.grace_ms = (uint32_t)grace_ms;

	if (mac_capability_do_call(coalition_fd, &dreq, sizeof(dreq),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
mac_capability_coalition_terminate(int coalition_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_TERMINATE;

	if (mac_capability_do_call(coalition_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
mac_capability_coalition_recv_event(int coalition_fd, uint32_t *flagsp)
{
	struct mac_capability_recvmsg_args ra;
	struct coalition_event_msg ev;

	memset(&ev, 0, sizeof(ev));
	memset(&ra, 0, sizeof(ra));
	ra.payload = &ev;
	ra.payload_len = sizeof(ev);

	if (ioctl(coalition_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (1);
		return (-1);
	}

	if (ra.payload_len < sizeof(ev))
		return (-1);
	*flagsp = ev.flags;
	return (0);
}

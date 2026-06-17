/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Direct cap_rt operations for serviced.
 *
 * Uses delegated service instance fds (inherited from oracled) to
 * create channels and coalitions via CAP_RT_MINT_INSTANCE — no /dev/cap_rt
 * access needed.  oracled hands serviced one instance of each
 * mintable service; serviced mints fresh instances from those.
 *
 * If a delegated fd is not available, falls back to the oracle
 * channel protocol client.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <dev/cap_rt/cap_rt_coalition_proto.h>
#include <dev/cap_rt/cap_rt_channel_proto.h>
#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"

/* Timeout for cap_rt channel recvmsg (milliseconds). */
#define	CAPRT_DIRECT_TIMEOUT_MS	SERVICED_RPC_TIMEOUT_MS

/*
 * Mint a fresh instance from an existing service instance fd.
 * The service must have CAP_RT_SVC_MINTABLE set.
 */
static int
mint_instance(int svc_fd)
{
	struct cap_rt_mint_instance_args ma;

	memset(&ma, 0, sizeof(ma));
	if (ioctl(svc_fd, CAP_RT_MINT_INSTANCE, &ma) == -1)
		return (-1);
	(void)fcntl(ma.fd, F_SETFD, FD_CLOEXEC);
	return (ma.fd);
}

/*
 * Create a channel using the delegated channel service instance.
 * Mints a fresh channel instance, sends CHANNEL_OP_CREATE, gets the peer.
 * Falls back to oracle protocol if channel_svc_fd unavailable.
 */
int
caprt_create_channel(int *our_end, int *child_end)
{
	struct cap_rt_sendmsg_args sa;
	struct cap_rt_recvmsg_args ra;
	uint32_t op;
	int channel_fd, peer_fd;

	if (sd.channel_svc_fd == -1)
		return (oracle_create_channel(sd.oracle_channel_fd,
		    our_end, child_end));

	channel_fd = mint_instance(sd.channel_svc_fd);
	if (channel_fd == -1) {
		syslog(LOG_WARNING, "caprt_direct: channel mint: %m");
		return (oracle_create_channel(sd.oracle_channel_fd,
		    our_end, child_end));
	}

	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);

	if (ioctl(channel_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "caprt_direct: channel sendmsg: %m");
		close(channel_fd);
		return (-1);
	}

	peer_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer_fd;
	ra.nfds = 1;

	{
		struct pollfd pfd;
		int rv;

		pfd.fd = channel_fd;
		pfd.events = POLLIN;

		for (;;) {
			rv = poll(&pfd, 1, CAPRT_DIRECT_TIMEOUT_MS);
			if (rv == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_WARNING,
				    "caprt_direct: channel poll: %m");
				close(channel_fd);
				return (-1);
			}
			if (rv == 0) {
				syslog(LOG_ERR,
				    "caprt_direct: channel recvmsg timeout");
				close(channel_fd);
				errno = ETIMEDOUT;
				return (-1);
			}
			if (pfd.revents & (POLLERR | POLLHUP)) {
				syslog(LOG_ERR,
				    "caprt_direct: channel closed");
				close(channel_fd);
				errno = ECONNRESET;
				return (-1);
			}
			if (ioctl(channel_fd, CAP_RT_RECVMSG, &ra) == 0)
				break;
			if (errno == EAGAIN)
				continue;
			syslog(LOG_WARNING,
			    "caprt_direct: channel recvmsg: %m");
			close(channel_fd);
			return (-1);
		}
	}

	if (peer_fd < 0) {
		close(channel_fd);
		return (-1);
	}

	(void)fcntl(channel_fd, F_SETFD, FD_CLOEXEC);
	(void)fcntl(peer_fd, F_SETFD, FD_CLOEXEC);

	*our_end = channel_fd;
	*child_end = peer_fd;
	return (0);
}

/*
 * Create a coalition using the delegated coalition service instance.
 * Mints a fresh coalition instance.
 * Falls back to oracle protocol if coalition_svc_fd unavailable.
 */
int
caprt_create_coalition(void)
{
	int fd;

	if (sd.coalition_svc_fd == -1)
		return (oracle_create_coalition(sd.oracle_channel_fd));

	fd = mint_instance(sd.coalition_svc_fd);
	if (fd == -1) {
		syslog(LOG_WARNING, "caprt_direct: coalition mint: %m");
		return (oracle_create_coalition(sd.oracle_channel_fd));
	}

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	return (fd);
}

/*
 * Coalition helpers — wrap CAP_RT_CALL ioctls.
 * These operate on coalition fds that serviced owns directly.
 */
int
caprt_coalition_enlist(int coalition_fd, int member_fd)
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
caprt_coalition_set_leader(int coalition_fd, int leader_fd)
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
caprt_coalition_graceful(int coalition_fd, int sig, unsigned timeout_ms)
{
	struct cap_rt_call_args call;
	struct coalition_graceful_req req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_GRACEFUL;
	req.signal = sig;
	req.timeout_ms = timeout_ms;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	if (reply.status != 0) {
		errno = reply.status;
		return (-1);
	}
	return (0);
}

/*
 * Terminate all processes in a coalition.
 * Sends SIGKILL to every member via the kernel.
 */
int
caprt_coalition_terminate(int coalition_fd)
{
	struct cap_rt_call_args call;
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_TERMINATE;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	return (reply.status);
}

int
caprt_mint_capprotect(void)
{

	if (sd.capprotect_fd < 0) {
		errno = ENOTSUP;
		return (-1);
	}
	return (mint_instance(sd.capprotect_fd));
}

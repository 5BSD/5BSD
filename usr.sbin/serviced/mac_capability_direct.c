/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Direct mac_capability operations for serviced.
 *
 * Uses delegated service instance fds (inherited from authorityd) to
 * create channels and coalitions via MAC_CAPABILITY_MINT_INSTANCE — no /dev/mac_capability
 * access needed.  authorityd hands serviced one instance of each
 * mintable service; serviced mints fresh instances from those.
 *
 * If a delegated fd is not available, falls back to the authority
 * channel protocol client.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_coalition_proto.h>
#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <capability.h>

#include "serviced.h"

/* Timeout for mac_capability channel recvmsg (milliseconds). */
#define	MAC_CAP_DIRECT_TIMEOUT_MS	SERVICED_RPC_TIMEOUT_MS

static int
kernel_call(int fd, const void *request, size_t request_length,
    const int *request_fds, size_t request_nfds, void *reply,
    size_t expected_reply_length)
{
	size_t reply_length, reply_nfds;

	reply_length = expected_reply_length;
	reply_nfds = 0;
	if (capability_kernel_call(fd, request, request_length, request_fds,
	    request_nfds, reply, &reply_length, NULL, &reply_nfds) == -1)
		return (-1);
	if (reply_length != expected_reply_length || reply_nfds != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/*
 * Mint a fresh instance from an existing service instance fd.
 * The service must have MAC_CAPABILITY_SVC_MINTABLE set.
 */
static int
mint_instance(int svc_fd)
{
	struct mac_capability_mint_instance_args ma;

	memset(&ma, 0, sizeof(ma));
	if (ioctl(svc_fd, MAC_CAPABILITY_MINT_INSTANCE, &ma) == -1)
		return (-1);
	(void)fcntl(ma.fd, F_SETFD, FD_CLOEXEC);
	return (ma.fd);
}

/*
 * Create a channel using the delegated channel service instance.
 * Mints a fresh channel instance, sends CHANNEL_OP_CREATE, gets the peer.
 * Falls back to authority protocol if channel_svc_fd unavailable.
 */
int
mac_cap_create_channel(int *our_end, int *child_end)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t op;
	int channel_fd, peer_fd;

	if (sd.channel_svc_fd == -1)
		return (authority_create_channel(sd.authority_channel_fd,
		    our_end, child_end));

	channel_fd = mint_instance(sd.channel_svc_fd);
	if (channel_fd == -1) {
		syslog(LOG_WARNING, "mac_cap_direct: channel mint: %m");
		return (authority_create_channel(sd.authority_channel_fd,
		    our_end, child_end));
	}

	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);

	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "mac_cap_direct: channel sendmsg: %m");
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
			rv = poll(&pfd, 1, MAC_CAP_DIRECT_TIMEOUT_MS);
			if (rv == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_WARNING,
				    "mac_cap_direct: channel poll: %m");
				close(channel_fd);
				return (-1);
			}
			if (rv == 0) {
				syslog(LOG_ERR,
				    "mac_cap_direct: channel recvmsg timeout");
				close(channel_fd);
				errno = ETIMEDOUT;
				return (-1);
			}
			if (pfd.revents & (POLLERR | POLLHUP)) {
				syslog(LOG_ERR,
				    "mac_cap_direct: channel closed");
				close(channel_fd);
				errno = ECONNRESET;
				return (-1);
			}
			if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
				break;
			if (errno == EAGAIN)
				continue;
			syslog(LOG_WARNING,
			    "mac_cap_direct: channel recvmsg: %m");
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
 * Falls back to authority protocol if coalition_svc_fd unavailable.
 */
int
mac_cap_create_coalition(void)
{
	int fd;

	if (sd.coalition_svc_fd == -1)
		return (authority_create_coalition(sd.authority_channel_fd));

	fd = mint_instance(sd.coalition_svc_fd);
	if (fd == -1) {
		syslog(LOG_WARNING, "mac_cap_direct: coalition mint: %m");
		return (authority_create_coalition(sd.authority_channel_fd));
	}

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	return (fd);
}

/*
 * Coalition helpers — wrap MAC_CAPABILITY_CALL ioctls.
 * These operate on coalition fds that serviced owns directly.
 */
int
mac_cap_coalition_enlist(int coalition_fd, int member_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_ENLIST;

	if (kernel_call(coalition_fd, &req, sizeof(req), &member_fd, 1,
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
mac_cap_coalition_set_leader(int coalition_fd, int leader_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_SET_LEADER;

	if (kernel_call(coalition_fd, &req, sizeof(req), &leader_fd, 1,
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
mac_cap_coalition_graceful(int coalition_fd, int sig, unsigned timeout_ms)
{
	struct coalition_graceful_req req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_GRACEFUL;
	req.signal = sig;
	req.timeout_ms = timeout_ms;

	if (kernel_call(coalition_fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1)
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
mac_cap_coalition_terminate(int coalition_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_TERMINATE;

	if (kernel_call(coalition_fd, &req, sizeof(req), NULL, 0,
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
mac_cap_mint_capprotect(void)
{

	if (sd.capprotect_fd < 0) {
		errno = ENOTSUP;
		return (-1);
	}
	return (mint_instance(sd.capprotect_fd));
}

/*
 * Launcher-applied protection: shield the process named by an attached process
 * descriptor with the given CP_SF_* flag set.  Issued through a capprotect
 * instance descriptor; the target is identified by pd_fd, which must still be
 * transferable (call before pd_fd's cap_xfer is narrowed to NONE).
 */
int
mac_cap_protect(int capprotect_fd, int pd_fd, uint32_t flags)
{
	struct cp_request req;

	if (capprotect_fd < 0 || pd_fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_PROTECT;
	req.flags = flags;
	return (kernel_call(capprotect_fd, &req, sizeof(req), &pd_fd, 1, NULL, 0));
}

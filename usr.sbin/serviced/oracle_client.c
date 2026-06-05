/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Oracle pair protocol client.
 *
 * Sends requests to oracled over the inherited cap_rt pair channel
 * and receives replies with attached file descriptors.  Each request
 * uses a unique reply_token for correlation.
 */

#include <sys/types.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"

/* Shared between oracled and serviced. */
#include "../oracled/oracled_svc_proto.h"

static volatile uint64_t next_reply_token = 1;

/* Timeout for oracle replies (milliseconds). */
#define	ORACLE_RPC_TIMEOUT_MS	100

/*
 * Send a request and wait for the reply.
 * On success, fills reply_fds[0..max_reply_fds-1] with received fds
 * and returns the status from oracled (0 = success, errno on failure).
 * Returns -1 on communication error (sets errno).
 */
static int
oracle_rpc(int pair_fd, const void *req, uint32_t reqlen,
    int *reply_fds, int max_reply_fds, int *nfds_out)
{
	struct cap_rt_sendmsg_args sa;
	struct cap_rt_recvmsg_args ra;
	struct oracle_reply rpl;
	uint64_t token;
	int i;

	token = __atomic_fetch_add(&next_reply_token, 1,
	    __ATOMIC_RELAXED);

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;

	if (ioctl(pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "oracle_rpc: sendmsg: %m");
		return (-1);
	}

	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);
	if (max_reply_fds > 0 && reply_fds != NULL) {
		ra.fds = reply_fds;
		ra.nfds = (uint32_t)max_reply_fds;
		/* Initialize to -1 so caller can detect unfilled slots. */
		for (i = 0; i < max_reply_fds; i++)
			reply_fds[i] = -1;
	}

	/*
	 * Wait for the reply with a timeout.  The pair fd should be
	 * non-blocking; poll() for readiness before attempting RECVMSG
	 * to avoid hanging the event loop if oracled drops a reply.
	 */
	{
		struct pollfd pfd;
		int rv;

		pfd.fd = pair_fd;
		pfd.events = POLLIN;

		for (;;) {
			rv = poll(&pfd, 1, ORACLE_RPC_TIMEOUT_MS);
			if (rv == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_WARNING,
				    "oracle_rpc: poll: %m");
				return (-1);
			}
			if (rv == 0) {
				syslog(LOG_ERR,
				    "oracle_rpc: timeout waiting for reply");
				errno = ETIMEDOUT;
				return (-1);
			}
			if (pfd.revents & (POLLERR | POLLHUP)) {
				syslog(LOG_ERR,
				    "oracle_rpc: pair closed");
				errno = ECONNRESET;
				return (-1);
			}
			if (ioctl(pair_fd, CAP_RT_RECVMSG, &ra) == 0)
				break;
			if (errno == EAGAIN)
				continue;
			syslog(LOG_WARNING,
			    "oracle_rpc: recvmsg: %m");
			return (-1);
		}
	}

	if (ra.reply_token != token) {
		syslog(LOG_WARNING,
		    "oracle_rpc: token mismatch (got %ju, expected %ju)",
		    (uintmax_t)ra.reply_token, (uintmax_t)token);
		/* Close any fds we received. */
		for (i = 0; i < max_reply_fds; i++) {
			if (reply_fds[i] >= 0)
				close(reply_fds[i]);
		}
		errno = EPROTO;
		return (-1);
	}

	if (nfds_out != NULL)
		*nfds_out = (int)ra.nfds;

	return (rpl.status);
}

int
oracle_mint_path(int pair_fd, const char *path)
{
	struct oracle_mint_path_req req;
	int token_fd;
	int status;

	if (strlen(path) >= sizeof(req.path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_MINT_PATH;
	strlcpy(req.path, path, sizeof(req.path));

	status = oracle_rpc(pair_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (token_fd);
}

int
oracle_mint_file(int pair_fd, const char *path, uint64_t actions)
{
	struct oracle_mint_file_req req;
	int token_fd;
	int status;

	if (actions == 0 || (actions & ~FI_FS_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (strlen(path) >= sizeof(req.path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_MINT_FILE;
	req.actions = actions;
	strlcpy(req.path, path, sizeof(req.path));

	status = oracle_rpc(pair_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (token_fd);
}

int
oracle_mint_net(int pair_fd, const struct serviced_net_claim *nc)
{
	struct oracle_mint_net_req req;
	int token_fd;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_MINT_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port_min = nc->port_min;
	req.port_max = nc->port_max;
	req.direction = nc->direction;

	status = oracle_rpc(pair_fd, &req, sizeof(req), &token_fd, 1, NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (token_fd);
}

int
oracle_mint_jail(int pair_fd, const struct serviced_jail_claim *jc)
{
	struct oracle_mint_jail_req req;
	int token_fd;
	int status;

	if (jc->jid < 0 || jc->actions == 0 ||
	    (jc->actions & ~FI_JAIL_ALL) != 0 ||
	    (jc->jid == 0 && jc->name[0] == '\0')) {
		errno = EINVAL;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_MINT_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));

	status = oracle_rpc(pair_fd, &req, sizeof(req), &token_fd, 1, NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (token_fd);
}

int
oracle_create_jail(int pair_fd, const char *name, const char *path,
    const char *hostname, const char *ip4_addr)
{
	struct oracle_create_jail_req req;
	int jd;
	int status;

	if (name == NULL || name[0] == '\0' ||
	    path == NULL || path[0] != '/') {
		errno = EINVAL;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_CREATE_JAIL;
	if (strlcpy(req.name, name, sizeof(req.name)) >= sizeof(req.name) ||
	    strlcpy(req.path, path, sizeof(req.path)) >= sizeof(req.path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (hostname != NULL && hostname[0] != '\0') {
		if (strlcpy(req.hostname, hostname,
		    sizeof(req.hostname)) >= sizeof(req.hostname)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
	}
	if (ip4_addr != NULL && ip4_addr[0] != '\0') {
		if (strlcpy(req.ip4_addr, ip4_addr,
		    sizeof(req.ip4_addr)) >= sizeof(req.ip4_addr)) {
			errno = ENAMETOOLONG;
			return (-1);
		}
	}

	status = oracle_rpc(pair_fd, &req, sizeof(req), &jd, 1, NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (jd);
}

int
oracle_mint_system(int pair_fd, uint32_t gates)
{
	struct oracle_mint_system_req req;
	int token_fd;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_MINT_SYSTEM;
	req.gates = gates;

	status = oracle_rpc(pair_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (token_fd);
}

int
oracle_create_pair(int pair_fd, int *our_end, int *child_end)
{
	struct oracle_req_hdr req;
	int fds[2];
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_CREATE_PAIR;

	status = oracle_rpc(pair_fd, &req, sizeof(req), fds, 2, NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	if (fds[0] < 0 || fds[1] < 0) {
		if (fds[0] >= 0) close(fds[0]);
		if (fds[1] >= 0) close(fds[1]);
		errno = EIO;
		return (-1);
	}

	*our_end = fds[0];
	*child_end = fds[1];
	return (0);
}

int
oracle_create_coalition(int pair_fd)
{
	struct oracle_req_hdr req;
	int cfd;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_CREATE_COALITION;

	status = oracle_rpc(pair_fd, &req, sizeof(req), &cfd, 1, NULL);
	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (cfd);
}

int
oracle_send_ready(int pair_fd)
{
	struct oracle_req_hdr req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_READY;

	status = oracle_rpc(pair_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

int
oracle_ping(int pair_fd)
{
	struct oracle_req_hdr req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_PING;

	status = oracle_rpc(pair_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Oracle channel protocol client.
 *
 * Sends requests to oracled over the inherited mac_capability channel
 * and receives replies with attached file descriptors.  Each request
 * uses a unique reply_token for correlation.
 */

#include <sys/types.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"

static volatile uint64_t next_reply_token = 1;

/* Timeout for oracle replies (milliseconds). */
#define	ORACLE_RPC_TIMEOUT_MS	SERVICED_RPC_TIMEOUT_MS
#define	ORACLE_DRAIN_REPOLL_MS	10	/* short re-poll for stragglers */

/*
 * Send a request and wait for the reply.
 * On success, fills reply_fds[0..max_reply_fds-1] with received fds
 * and returns the status from oracled (0 = success, errno on failure).
 * Returns -1 on communication error (sets errno).
 */
static int
oracle_rpc(int channel_fd, const void *req, uint32_t reqlen,
    int *reply_fds, int max_reply_fds, int *nfds_out)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct oracle_reply rpl;
	uint64_t token;
	int i;

	token = __atomic_fetch_add(&next_reply_token, 1,
	    __ATOMIC_RELAXED);

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;

	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "oracle_rpc: sendmsg: %m");
		return (-1);
	}

	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);
	if (max_reply_fds > 0) {
		ra.fds = reply_fds;
		ra.nfds = (uint32_t)max_reply_fds;
		/* Initialize to -1 so caller can detect unfilled slots. */
		for (i = 0; i < max_reply_fds; i++)
			reply_fds[i] = -1;
	}

	/*
	 * Wait for the reply with a timeout.  The channel fd should be
	 * non-blocking; poll() for readiness before attempting RECVMSG
	 * to avoid hanging the event loop if oracled drops a reply.
	 */
	{
		struct pollfd pfd;
		int rv;

		pfd.fd = channel_fd;
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
				    "oracle_rpc: channel closed");
				errno = ECONNRESET;
				return (-1);
			}
			if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
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

/*
 * Fill an oracle_path_req from a path string.
 * Returns 0 on success, -1 with errno set on failure.
 */
static int
fill_path_req(struct oracle_path_req *req, uint32_t op, const char *path)
{

	if (strlen(path) >= sizeof(req->path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memset(req, 0, sizeof(*req));
	req->op = op;
	strlcpy(req->path, path, sizeof(req->path));
	return (0);
}

/*
 * Fill an oracle_net_req from an ort_net_claim.
 */
static void
fill_net_req(struct oracle_net_req *req, uint32_t op,
    const struct ort_net_claim *nc)
{

	memset(req, 0, sizeof(*req));
	req->op = op;
	req->domain = nc->domain;
	req->protocol = nc->protocol;
	req->port_min = nc->port_min;
	req->port_max = nc->port_max;
	req->direction = nc->direction;
	req->prefix = nc->prefix;
	memcpy(req->addr, nc->addr, sizeof(req->addr));
}

/*
 * Fill an oracle_jail_req from a serviced_jail_claim.
 */
static void
fill_jail_req(struct oracle_jail_req *req, uint32_t op,
    const struct serviced_jail_claim *jc)
{

	memset(req, 0, sizeof(*req));
	req->op = op;
	req->jid = jc->jid;
	req->actions = jc->actions;
	strlcpy(req->name, jc->name, sizeof(req->name));
}

/*
 * Fill an oracle_system_req from a gates bitmask.
 */
static void
fill_system_req(struct oracle_system_req *req, uint32_t op, uint32_t gates)
{

	memset(req, 0, sizeof(*req));
	req->op = op;
	req->gates = gates;
}

/*
 * Common status check for RPC calls that return no fds.
 * Maps oracled error status to errno; returns 0 on success, -1 on error.
 */
static int
check_status(int status)
{

	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (0);
}

/*
 * Common status check for RPC calls that return a single fd.
 * Maps oracled error status to errno; returns the fd on success, -1 on error.
 */
static int
check_status_fd(int status, int fd)
{

	if (status < 0)
		return (-1);
	if (status != 0) {
		errno = status;
		return (-1);
	}
	return (fd);
}

/* --- Mint operations (return token fds) --- */

int
oracle_mint_path(int channel_fd, const char *path)
{
	struct oracle_path_req req;
	int token_fd, status;

	if (fill_path_req(&req, ORACLE_OP_MINT_PATH, path) != 0)
		return (-1);
	status = oracle_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
oracle_mint_file(int channel_fd, const char *path, uint64_t actions)
{
	struct oracle_mint_file_req req;
	int token_fd, status;

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

	status = oracle_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
oracle_mint_net(int channel_fd, const struct ort_net_claim *nc)
{
	struct oracle_net_req req;
	int token_fd, status;

	fill_net_req(&req, ORACLE_OP_MINT_NET, nc);
	status = oracle_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
oracle_mint_jail(int channel_fd, const struct serviced_jail_claim *jc)
{
	struct oracle_jail_req req;
	int token_fd, status;

	if (jc->jid < 0 || jc->actions == 0 ||
	    (jc->actions & ~FI_JAIL_ALL) != 0 ||
	    (jc->jid == 0 && jc->name[0] == '\0')) {
		errno = EINVAL;
		return (-1);
	}

	fill_jail_req(&req, ORACLE_OP_MINT_JAIL, jc);
	status = oracle_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
oracle_create_jail(int channel_fd, const char *name, const char *path,
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

	status = oracle_rpc(channel_fd, &req, sizeof(req), &jd, 1, NULL);
	return (check_status_fd(status, jd));
}

int
oracle_mint_system(int channel_fd, uint32_t gates)
{
	struct oracle_system_req req;
	int token_fd, status;

	fill_system_req(&req, ORACLE_OP_MINT_SYSTEM, gates);
	status = oracle_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
oracle_create_channel(int channel_fd, int *our_end, int *child_end)
{
	struct oracle_req_hdr req;
	int fds[2];
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_CREATE_CHANNEL;

	status = oracle_rpc(channel_fd, &req, sizeof(req), fds, 2, NULL);
	if (check_status(status) != 0)
		return (-1);
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
oracle_create_coalition(int channel_fd)
{
	struct oracle_req_hdr req;
	int cfd;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_CREATE_COALITION;

	status = oracle_rpc(channel_fd, &req, sizeof(req), &cfd, 1, NULL);
	return (check_status_fd(status, cfd));
}

int
oracle_send_ready(int channel_fd)
{
	struct oracle_req_hdr req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = ORACLE_OP_READY;

	status = oracle_rpc(channel_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

/*
 * --- Dynamic claim/release operations ---
 *
 * These are generated with macros because claim and release share
 * identical fill-and-RPC logic — only the op code differs.
 */

#define	ORACLE_PATH_OP(fname, op)					\
int									\
fname(int channel_fd, const char *path)					\
{									\
	struct oracle_path_req req;					\
									\
	if (fill_path_req(&req, (op), path) != 0)			\
		return (-1);						\
	return (check_status(oracle_rpc(channel_fd, &req,			\
	    sizeof(req), NULL, 0, NULL)));				\
}

#define	ORACLE_NET_OP(fname, op)					\
int									\
fname(int channel_fd, const struct ort_net_claim *nc)			\
{									\
	struct oracle_net_req req;					\
									\
	fill_net_req(&req, (op), nc);					\
	return (check_status(oracle_rpc(channel_fd, &req,			\
	    sizeof(req), NULL, 0, NULL)));				\
}

#define	ORACLE_JAIL_OP(fname, op)					\
int									\
fname(int channel_fd, const struct serviced_jail_claim *jc)		\
{									\
	struct oracle_jail_req req;					\
									\
	fill_jail_req(&req, (op), jc);					\
	return (check_status(oracle_rpc(channel_fd, &req,			\
	    sizeof(req), NULL, 0, NULL)));				\
}

#define	ORACLE_SYSTEM_OP(fname, op)					\
int									\
fname(int channel_fd, uint32_t gates)					\
{									\
	struct oracle_system_req req;					\
									\
	fill_system_req(&req, (op), gates);				\
	return (check_status(oracle_rpc(channel_fd, &req,			\
	    sizeof(req), NULL, 0, NULL)));				\
}

ORACLE_PATH_OP(oracle_claim_path, ORACLE_OP_CLAIM_PATH)
ORACLE_NET_OP(oracle_claim_net, ORACLE_OP_CLAIM_NET)
ORACLE_JAIL_OP(oracle_claim_jail, ORACLE_OP_CLAIM_JAIL)
ORACLE_SYSTEM_OP(oracle_claim_system, ORACLE_OP_CLAIM_SYSTEM)

ORACLE_PATH_OP(oracle_release_path, ORACLE_OP_RELEASE_PATH)
ORACLE_NET_OP(oracle_release_net, ORACLE_OP_RELEASE_NET)
ORACLE_JAIL_OP(oracle_release_jail, ORACLE_OP_RELEASE_JAIL)
ORACLE_SYSTEM_OP(oracle_release_system, ORACLE_OP_RELEASE_SYSTEM)

/* --- Batched release --- */

/*
 * Send a release message without waiting for the reply.
 * Returns a token that can be drained later, or 0 on send failure.
 */
static uint64_t
oracle_release_send(int channel_fd, const void *req, uint32_t reqlen)
{
	struct mac_capability_sendmsg_args sa;
	uint64_t token;

	token = __atomic_fetch_add(&next_reply_token, 1,
	    __ATOMIC_RELAXED);

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;

	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "oracle_release_send: sendmsg: %m");
		return (0);
	}
	return (token);
}

/*
 * Drain pending release replies.  Blocks once for up to
 * ORACLE_RPC_TIMEOUT_MS, then reads as many replies as are
 * available.  Returns the number of replies successfully drained.
 */
static int
oracle_release_drain(int channel_fd, unsigned expected)
{
	struct mac_capability_recvmsg_args ra;
	struct oracle_reply rpl;
	struct pollfd pfd;
	unsigned drained;
	int rv, timeout;

	if (expected == 0)
		return (0);

	pfd.fd = channel_fd;
	pfd.events = POLLIN;
	drained = 0;
	timeout = ORACLE_RPC_TIMEOUT_MS;

	/*
	 * Poll-and-read loop: wait for replies, drain what's
	 * available, re-poll if more are expected.  Use the full
	 * timeout on the first poll; subsequent polls use a short
	 * timeout since the oracle is actively processing.
	 */
	while (drained < expected) {
		rv = poll(&pfd, 1, timeout);
		if (rv == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_WARNING,
			    "oracle_release_drain: poll: %m");
			break;
		}
		if (rv == 0)
			break;		/* timeout */
		if (pfd.revents & (POLLERR | POLLHUP))
			break;

		while (drained < expected) {
			memset(&ra, 0, sizeof(ra));
			ra.payload = &rpl;
			ra.payload_len = sizeof(rpl);

			if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
				if (errno == EAGAIN)
					break;	/* back to poll */
				syslog(LOG_WARNING,
				    "oracle_release_drain: recvmsg: %m");
				return ((int)drained);
			}
			drained++;
		}

		timeout = ORACLE_DRAIN_REPOLL_MS;
	}

	return ((int)drained);
}

/*
 * Release all capabilities from a manifest in one burst.
 * Sends all release messages, then drains replies in a single
 * blocking window.  Returns the number of releases sent.
 */
int
oracle_release_manifest(int channel_fd, const struct svc_manifest *m)
{
	unsigned i, nsent;

	nsent = 0;

	for (i = 0; i < m->ncap_paths; i++) {
		struct oracle_path_req req;

		if (fill_path_req(&req, ORACLE_OP_RELEASE_PATH,
		    m->cap_paths[i]) == 0 &&
		    oracle_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	for (i = 0; i < m->ncap_files; i++) {
		struct oracle_path_req req;

		if (fill_path_req(&req, ORACLE_OP_RELEASE_PATH,
		    m->cap_files[i].path) == 0 &&
		    oracle_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	for (i = 0; i < m->ncap_net; i++) {
		struct oracle_net_req req;

		fill_net_req(&req, ORACLE_OP_RELEASE_NET, &m->cap_net[i]);
		if (oracle_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	for (i = 0; i < m->ncap_jail; i++) {
		struct oracle_jail_req req;

		fill_jail_req(&req, ORACLE_OP_RELEASE_JAIL,
		    &m->cap_jail[i]);
		if (oracle_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	if (m->cap_system != 0) {
		struct oracle_system_req req;

		fill_system_req(&req, ORACLE_OP_RELEASE_SYSTEM,
		    m->cap_system);
		if (oracle_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}

	/* One blocking window to drain all replies. */
	if (nsent > 0)
		oracle_release_drain(channel_fd, nsent);

	return ((int)nsent);
}

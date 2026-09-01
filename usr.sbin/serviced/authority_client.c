/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Authority channel protocol client.
 *
 * Sends requests to authorityd over the inherited mac_capability channel
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

/* Timeout for authority replies (milliseconds). */
#define	AUTHORITY_RPC_TIMEOUT_MS	SERVICED_RPC_TIMEOUT_MS
#define	AUTHORITY_DRAIN_REPOLL_MS	10	/* short re-poll for stragglers */

/*
 * Send a request (optionally with attached descriptors) and wait for the reply.
 * On success, fills reply_fds[0..max_reply_fds-1] with received fds and returns
 * the status from authorityd (0 = success, errno on failure).  Returns -1 on
 * communication error (sets errno).
 */
static int
authority_rpc_fds(int channel_fd, const void *req, uint32_t reqlen,
    const int *send_fds, uint32_t send_nfds,
    int *reply_fds, int max_reply_fds, int *nfds_out)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct authority_reply rpl;
	uint64_t token;
	int i;

	token = __atomic_fetch_add(&next_reply_token, 1,
	    __ATOMIC_RELAXED);

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.fds = send_fds;
	sa.nfds = send_nfds;
	sa.reply_token = token;

	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "authority_rpc: sendmsg: %m");
		return (-1);
	}

	memset(&rpl, 0, sizeof(rpl));
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
	 * to avoid hanging the event loop if authorityd drops a reply.
	 *
	 * On token mismatch, drain the stale reply and retry up to 8
	 * times.  This prevents a single stale reply from corrupting
	 * all subsequent RPCs on this channel.
	 */
	{
		struct pollfd pfd;
		int rv, retries;

		pfd.fd = channel_fd;
		pfd.events = POLLIN;
		retries = 0;

retry:
		for (;;) {
			rv = poll(&pfd, 1, AUTHORITY_RPC_TIMEOUT_MS);
			if (rv == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_WARNING,
				    "authority_rpc: poll: %m");
				return (-1);
			}
			if (rv == 0) {
				syslog(LOG_ERR,
				    "authority_rpc: timeout waiting for reply");
				errno = ETIMEDOUT;
				return (-1);
			}
			if (pfd.revents & (POLLERR | POLLHUP)) {
				syslog(LOG_ERR,
				    "authority_rpc: channel closed");
				errno = ECONNRESET;
				return (-1);
			}
			if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == 0)
				break;
			if (errno == EAGAIN)
				continue;
			syslog(LOG_WARNING,
			    "authority_rpc: recvmsg: %m");
			return (-1);
		}

		if (ra.reply_token != token) {
			syslog(LOG_WARNING,
			    "authority_rpc: draining stale reply "
			    "(got %ju, expected %ju)",
			    (uintmax_t)ra.reply_token, (uintmax_t)token);
			/* Close any fds from the stale reply. */
			for (i = 0; i < max_reply_fds; i++) {
				if (reply_fds[i] >= 0) {
					close(reply_fds[i]);
					reply_fds[i] = -1;
				}
			}
			if (++retries < 8) {
				/* Re-initialize ra for the next recv. */
				memset(&ra, 0, sizeof(ra));
				ra.payload = &rpl;
				ra.payload_len = sizeof(rpl);
				if (max_reply_fds > 0) {
					ra.fds = reply_fds;
					ra.nfds = (uint32_t)max_reply_fds;
				}
				goto retry;
			}
			syslog(LOG_ERR,
			    "authority_rpc: too many stale replies, giving up");
			errno = EPROTO;
			return (-1);
		}
	}

	/*
	 * The reply wire shape is exact.  Successful descriptor-producing
	 * operations must return the requested number of fds; errors and
	 * status-only operations must return none.
	 */
	if (ra.payload_len != sizeof(rpl) ||
	    ra.nfds != (uint32_t)(rpl.status == 0 ? max_reply_fds : 0)) {
		syslog(LOG_ERR, "authority_rpc: malformed reply (%u bytes, %u fds)",
		    (unsigned)ra.payload_len, (unsigned)ra.nfds);
		for (i = 0; i < max_reply_fds; i++) {
			if (reply_fds[i] >= 0) {
				close(reply_fds[i]);
				reply_fds[i] = -1;
			}
		}
		errno = EPROTO;
		return (-1);
	}

	if (nfds_out != NULL)
		*nfds_out = (int)ra.nfds;

	return (rpl.status);
}

/*
 * Send a request with no attached descriptors and wait for the reply.
 */
static int
authority_rpc(int channel_fd, const void *req, uint32_t reqlen,
    int *reply_fds, int max_reply_fds, int *nfds_out)
{

	return (authority_rpc_fds(channel_fd, req, reqlen, NULL, 0,
	    reply_fds, max_reply_fds, nfds_out));
}

/*
 * Fill an authority_path_req from a path string.
 * Returns 0 on success, -1 with errno set on failure.
 */
static int
fill_path_req(struct authority_path_req *req, uint32_t op, const char *path)
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
 * Fill an authority_net_req from an ort_net_claim.
 */
static void
fill_net_req(struct authority_net_req *req, uint32_t op,
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
 * Fill an authority_system_req from a gates bitmask.
 */
static void
fill_system_req(struct authority_system_req *req, uint32_t op, uint32_t gates)
{

	memset(req, 0, sizeof(*req));
	req->op = op;
	req->gates = gates;
}

static void
fill_vsock_req(struct authority_vsock_req *req, uint32_t op,
    const struct ort_vsock_claim *vc)
{
	memset(req, 0, sizeof(*req));
	req->op = op;
	req->cid = vc->cid;
	req->port_min = vc->port_min;
	req->port_max = vc->port_max;
	req->direction = vc->direction;
}

/*
 * Common status check for RPC calls that return no fds.
 * Maps authorityd error status to errno; returns 0 on success, -1 on error.
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
 * Maps authorityd error status to errno; returns the fd on success, -1 on error.
 */
static int
check_status_fd(int status, int fd)
{

	if (status == 0)
		return (fd);
	/*
	 * Error path.  authorityd should not attach an fd alongside a non-zero
	 * status, but close one defensively rather than leak it.  status < 0
	 * is a communication error (errno already set by authority_rpc); status
	 * > 0 is an authorityd errno.
	 */
	if (fd >= 0)
		close(fd);
	if (status > 0)
		errno = status;
	return (-1);
}

/* --- Mint operations (return token fds) --- */

int
authority_mint_path(int channel_fd, const char *path)
{
	struct authority_path_req req;
	int token_fd, status;

	if (fill_path_req(&req, AUTHORITY_OP_MINT_PATH, path) != 0)
		return (-1);
	status = authority_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
authority_mint_file(int channel_fd, const char *path, uint64_t actions)
{
	struct authority_mint_file_req req;
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
	req.op = AUTHORITY_OP_MINT_FILE;
	req.actions = actions;
	strlcpy(req.path, path, sizeof(req.path));

	status = authority_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
authority_mint_net(int channel_fd, const struct ort_net_claim *nc)
{
	struct authority_net_req req;
	int token_fd, status;

	fill_net_req(&req, AUTHORITY_OP_MINT_NET, nc);
	status = authority_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
authority_mint_vsock(int channel_fd, const struct ort_vsock_claim *vc)
{
	struct authority_vsock_req req;
	int token_fd, status;
	fill_vsock_req(&req, AUTHORITY_OP_MINT_VSOCK, vc);
	status = authority_rpc(channel_fd, &req, sizeof(req), &token_fd, 1, NULL);
	return (check_status_fd(status, token_fd));
}

int
authority_mint_system(int channel_fd, uint32_t gates)
{
	struct authority_system_req req;
	int token_fd, status;

	fill_system_req(&req, AUTHORITY_OP_MINT_SYSTEM, gates);
	status = authority_rpc(channel_fd, &req, sizeof(req), &token_fd, 1,
	    NULL);
	return (check_status_fd(status, token_fd));
}

int
authority_create_channel(int channel_fd, int *our_end, int *child_end)
{
	struct authority_req_hdr req;
	int fds[2];
	int status;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_CREATE_CHANNEL;

	status = authority_rpc(channel_fd, &req, sizeof(req), fds, 2, NULL);
	if (check_status(status) != 0) {
		/* Close any fds attached to an error reply rather than leak. */
		if (fds[0] >= 0) close(fds[0]);
		if (fds[1] >= 0) close(fds[1]);
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
authority_create_coalition(int channel_fd)
{
	struct authority_req_hdr req;
	int cfd;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_CREATE_COALITION;

	status = authority_rpc(channel_fd, &req, sizeof(req), &cfd, 1, NULL);
	return (check_status_fd(status, cfd));
}

int
authority_delegate_service(int channel_fd, const char *name)
{
	struct authority_service_req req;
	int fd, status;

	if (name == NULL ||
	    (strcmp(name, "mount") != 0 && strcmp(name, "node") != 0 &&
	    strcmp(name, "accounting") != 0 && strcmp(name, "identity") != 0)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_DELEGATE_SERVICE;
	strlcpy(req.name, name, sizeof(req.name));
	status = authority_rpc(channel_fd, &req, sizeof(req), &fd, 1, NULL);
	return (check_status_fd(status, fd));
}

int
authority_send_ready(int channel_fd)
{
	struct authority_req_hdr req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_READY;

	status = authority_rpc(channel_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

/*
 * Relay a system lifecycle transition to authorityd (docs/lifecycle-capability-
 * design.md, P4b): serviced authorized the request over its ADMIN-gated
 * system.lifecycle capability and forwards the opcode to the spine, which is
 * PID 1 and applies it.  Returns the authority's status (0 = accepted).
 */
int
authority_lifecycle(int channel_fd, uint32_t lifecycle_op)
{
	struct authority_lifecycle_req req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_LIFECYCLE;
	req.lifecycle_op = lifecycle_op;

	status = authority_rpc(channel_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

/*
 * Relay an authority config reload to authorityd (P4b): the reloadable half of
 * the authorityd control surface, re-homed from the getpeereid socket onto the
 * authority channel.  Returns the authority's status (0 = ok).
 */
int
authority_reload(int channel_fd)
{
	struct authority_req_hdr req;
	int status;

	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_RELOAD;

	status = authority_rpc(channel_fd, &req, sizeof(req), NULL, 0, NULL);
	if (status < 0)
		return (-1);
	return (status);
}

/*
 * Forward the ambient lookup channel client end to authority-init (§21) so it can
 * carry the channel into interactive logins spawned from /etc/ttys.  lookup_fd
 * is duped across as an attached descriptor; the caller retains its own copy.
 *
 * Best-effort discovery plumbing, never authority: the rc path already carries
 * the channel by environment inheritance, so the caller treats any failure as
 * "no interactive carry" and continues.  Returns 0 on success, -1 (errno set)
 * on any communication or install failure.
 */
int
authority_set_ambient_lookup(int channel_fd, int lookup_fd)
{
	struct authority_req_hdr req;
	int status;

	if (lookup_fd < 0) {
		errno = EBADF;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = AUTHORITY_OP_SET_AMBIENT_LOOKUP;

	status = authority_rpc_fds(channel_fd, &req, sizeof(req), &lookup_fd, 1,
	    NULL, 0, NULL);
	return (check_status(status));
}

/* --- Batched release --- */

/*
 * Send a release message without waiting for the reply.
 * Returns a token that can be drained later, or 0 on send failure.
 */
static uint64_t
authority_release_send(int channel_fd, const void *req, uint32_t reqlen)
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
		syslog(LOG_WARNING, "authority_release_send: sendmsg: %m");
		return (0);
	}
	return (token);
}

/*
 * Drain pending release replies.  Blocks once for up to
 * AUTHORITY_RPC_TIMEOUT_MS, then reads as many replies as are
 * available.  Returns the number of replies successfully drained.
 */
static int
authority_release_drain(int channel_fd, unsigned expected)
{
	struct mac_capability_recvmsg_args ra;
	struct authority_reply rpl;
	struct pollfd pfd;
	unsigned drained;
	int rv, timeout;

	if (expected == 0)
		return (0);

	pfd.fd = channel_fd;
	pfd.events = POLLIN;
	drained = 0;
	timeout = AUTHORITY_RPC_TIMEOUT_MS;

	/*
	 * Poll-and-read loop: wait for replies, drain what's
	 * available, re-poll if more are expected.  Use the full
	 * timeout on the first poll; subsequent polls use a short
	 * timeout since the authority is actively processing.
	 */
	while (drained < expected) {
		rv = poll(&pfd, 1, timeout);
		if (rv == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_WARNING,
			    "authority_release_drain: poll: %m");
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
				    "authority_release_drain: recvmsg: %m");
				return ((int)drained);
			}
			drained++;
		}

		timeout = AUTHORITY_DRAIN_REPOLL_MS;
	}

	return ((int)drained);
}

/*
 * Release all capabilities from a manifest in one burst.
 * Sends all release messages, then drains replies in a single
 * blocking window.  Returns the number of releases sent.
 */
int
authority_release_manifest(int channel_fd, const struct svc_manifest *m)
{
	unsigned i, nsent;

	nsent = 0;

	for (i = 0; i < m->ncap_paths; i++) {
		struct authority_path_req req;

		if (fill_path_req(&req, AUTHORITY_OP_RELEASE_PATH,
		    m->cap_paths[i]) == 0 &&
		    authority_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	for (i = 0; i < m->ncap_net; i++) {
		struct authority_net_req req;

		fill_net_req(&req, AUTHORITY_OP_RELEASE_NET, &m->cap_net[i]);
		if (authority_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	for (i = 0; i < m->ncap_vsock; i++) {
		struct authority_vsock_req req;
		fill_vsock_req(&req, AUTHORITY_OP_RELEASE_VSOCK,
		    &m->cap_vsock[i]);
		if (authority_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	if (m->cap_system != 0) {
		struct authority_system_req req;

		fill_system_req(&req, AUTHORITY_OP_RELEASE_SYSTEM,
		    m->cap_system);
		if (authority_release_send(channel_fd, &req, sizeof(req)) != 0)
			nsent++;
	}
	/*
	 * Storage teardown is not serviced's concern: a storage consumer holds
	 * its own tzfsd channel and its ephemeral storage is bound to that
	 * channel's lifetime (tzfsd reaps orphaned leases).  serviced neither
	 * mints nor releases storage.
	 */

	/* One blocking window to drain all replies. */
	if (nsent > 0)
		authority_release_drain(channel_fd, nsent);

	return ((int)nsent);
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled pair channel protocol handler.
 *
 * Receives requests from serviced over the NOXFER pair channel,
 * validates them against the oracle's claimed resource set, and
 * dispatches to cap_rt to mint tokens or create pairs/coalitions.
 * Replies are sent back over the same pair with attached fds.
 */

#include <sys/event.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_svc_proto.h"

static int	proto_pair_fd = -1;
static bool	serviced_ready;
static uint64_t	serviced_nonce;		/* set on first message */
static bool	nonce_set;

/*
 * Send a reply with optional attached fds.
 */
static int
proto_reply(int status, uint64_t reply_token, int *fds, int nfds)
{
	struct cap_rt_sendmsg_args sa;
	struct oracle_reply rpl;

	rpl.status = status;

	memset(&sa, 0, sizeof(sa));
	sa.payload = &rpl;
	sa.payload_len = sizeof(rpl);
	sa.reply_token = reply_token;
	if (nfds > 0) {
		sa.fds = fds;
		sa.nfds = (uint32_t)nfds;
	}

	if (ioctl(proto_pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "oracle_proto: reply: %m");
		return (-1);
	}
	return (0);
}

/*
 * Validate that a path is within the oracle's claimed set.
 */
static bool
path_is_claimed(const char *path)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		if (strcmp(od.cfg.claim_paths[i], path) == 0)
			return (true);
	}
	return (false);
}

static bool
net_claim_covers(const struct oracled_net_claim *claim,
    const struct oracled_net_claim *req)
{

	if ((claim->direction & req->direction) != req->direction)
		return (false);
	if (claim->domain != 0 &&
	    (req->domain == 0 || claim->domain != req->domain))
		return (false);
	if (claim->protocol != 0 &&
	    (req->protocol == 0 || claim->protocol != req->protocol))
		return (false);
	if (claim->port != 0 &&
	    (req->port == 0 || claim->port != req->port))
		return (false);
	return (true);
}

static bool
net_is_claimed(const struct oracled_net_claim *req)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_net; i++) {
		if (net_claim_covers(&od.cfg.claim_net[i], req))
			return (true);
	}
	return (false);
}

static void
handle_mint_path(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_path_req *req;
	int token_fd;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	/* Ensure null-terminated. */
	if (strnlen(req->path, PATH_MAX) >= PATH_MAX) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}

	if (req->path[0] != '/') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	if (!path_is_claimed(req->path)) {
		syslog(LOG_NOTICE, "oracle_proto: mint_path denied: %s",
		    req->path);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_path_token(req->path);
	if (token_fd == -1) {
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_net(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_net_req *req;
	struct oracled_net_claim nc;
	int token_fd;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (req->direction == 0 || (req->direction & ~ORACLED_NET_DIR_ANY) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (req->domain != 0 && req->domain != AF_INET &&
	    req->domain != AF_INET6) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	memset(&nc, 0, sizeof(nc));
	nc.domain = req->domain;
	nc.protocol = req->protocol;
	nc.port = req->port;
	nc.direction = req->direction;

	if (!net_is_claimed(&nc)) {
		syslog(LOG_NOTICE, "oracle_proto: mint_net denied: %u/%d",
		    nc.port, nc.protocol);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_net_token(&nc);
	if (token_fd == -1) {
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_system_req *req;
	int token_fd;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if ((req->gates & od.cfg.claim_system) != req->gates) {
		syslog(LOG_NOTICE,
		    "oracle_proto: mint_system denied: 0x%x not in 0x%x",
		    req->gates, od.cfg.claim_system);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_system_token(req->gates);
	if (token_fd == -1) {
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_pair(uint64_t reply_token)
{
	int fds[2];

	if (cap_rt_create_pair(&fds[0], &fds[1]) == -1) {
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	proto_reply(0, reply_token, fds, 2);
	close(fds[0]);
	close(fds[1]);
}

static void
handle_create_coalition(uint64_t reply_token)
{
	int cfd;

	cfd = cap_rt_create_coalition();
	if (cfd == -1) {
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	proto_reply(0, reply_token, &cfd, 1);
	close(cfd);
}

static void
handle_ready(uint64_t reply_token)
{

	if (!serviced_ready) {
		serviced_ready = true;
		syslog(LOG_INFO, "oracle_proto: serviced ready");
	}
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ping(uint64_t reply_token)
{

	proto_reply(0, reply_token, NULL, 0);
}

/*
 * Dispatch a single request from the pair channel.
 * Returns 0 if message processed, -1 on receive error (peer closed).
 */
static int
proto_dispatch_one(void)
{
	struct cap_rt_recvmsg_args ra;
	char buf[sizeof(struct oracle_mint_path_req)];
	uint32_t op;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);

	if (ioctl(proto_pair_fd, CAP_RT_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN)
			return (0);
		syslog(LOG_WARNING, "oracle_proto: recvmsg: %m");
		return (-1);
	}

	if (ra.payload_len < sizeof(uint32_t)) {
		syslog(LOG_WARNING, "oracle_proto: short message (%u bytes)",
		    ra.payload_len);
		return (0);
	}

	/* Nonce verification — lock to first sender. */
	if (!nonce_set) {
		serviced_nonce = ra.trailer.nonce;
		nonce_set = true;
	} else if (ra.trailer.nonce != serviced_nonce) {
		syslog(LOG_WARNING,
		    "oracle_proto: nonce mismatch (got 0x%jx, expected 0x%jx)",
		    (uintmax_t)ra.trailer.nonce,
		    (uintmax_t)serviced_nonce);
		proto_reply(EACCES, ra.reply_token, NULL, 0);
		return (0);
	}

	memcpy(&op, buf, sizeof(op));

	switch (op) {
	case ORACLE_OP_MINT_PATH:
		handle_mint_path(buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_NET:
		handle_mint_net(buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_SYSTEM:
		handle_mint_system(buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CREATE_PAIR:
		handle_create_pair(ra.reply_token);
		break;
	case ORACLE_OP_CREATE_COALITION:
		handle_create_coalition(ra.reply_token);
		break;
	case ORACLE_OP_READY:
		handle_ready(ra.reply_token);
		break;
	case ORACLE_OP_PING:
		handle_ping(ra.reply_token);
		break;
	default:
		syslog(LOG_WARNING, "oracle_proto: unknown op %u", op);
		proto_reply(ENOTSUP, ra.reply_token, NULL, 0);
		break;
	}

	return (0);
}

/*
 * Called from the event loop when EVFILT_READ fires on the pair fd.
 * Processes one message per call; kqueue re-fires if more are queued.
 */
int
oracle_proto_dispatch(struct kevent *kev __unused)
{

	return (proto_dispatch_one());
}

/*
 * Initialize the protocol handler.
 * pair_fd is oracled's end of the pair to serviced.
 */
void
oracle_proto_init(int pair_fd)
{

	proto_pair_fd = pair_fd;
	serviced_ready = false;
	nonce_set = false;
}

/*
 * Reset state when serviced exits (before restart).
 */
void
oracle_proto_reset(void)
{

	serviced_ready = false;
	nonce_set = false;
}

bool
oracle_proto_is_ready(void)
{

	return (serviced_ready);
}

int
oracle_proto_fd(void)
{

	return (proto_pair_fd);
}

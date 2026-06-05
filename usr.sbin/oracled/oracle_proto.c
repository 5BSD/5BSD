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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/jail.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_svc_proto.h"
#include "probes.h"

static int	proto_pair_fd = -1;
static bool	serviced_ready;
static uint64_t	serviced_nonce;		/* set on first message */
static bool	nonce_set;

/* Per-dispatch tracking for the ipc-dispatch-done probe. */
static uint32_t dispatch_op;
static int dispatch_status;

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
	dispatch_status = status;
	ORACLED_PROBE_IPC_REPLY(dispatch_op, status);
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
	if (claim->port_min > req->port_min ||
	    claim->port_max < req->port_max)
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

static bool
jail_claim_covers(const struct oracled_jail_claim *claim,
    const struct oracled_jail_claim *req)
{

	if ((claim->actions & req->actions) != req->actions)
		return (false);
	/*
	 * When the claim specifies both JID and name, require both keys
	 * to be present in the request and both to match.  This mirrors
	 * the kernel's fi_jail_req_matches() and prevents a request
	 * with only a matching JID from covering a claim intended for
	 * a specific name + JID pair.
	 *
	 * Exception: FI_JAIL_CREATE requests carry no JID (the jail
	 * doesn't exist yet).  Match on name alone in that case.
	 *
	 * When only one key is specified, match on that key alone.
	 */
	if (claim->jid != 0 && claim->name[0] != '\0') {
		if (req->jid == 0 && req->name[0] != '\0' &&
		    req->actions == FI_JAIL_CREATE)
			return (strcmp(claim->name, req->name) == 0);
		return (req->jid == claim->jid &&
		    req->name[0] != '\0' &&
		    strcmp(claim->name, req->name) == 0);
	}
	if (claim->jid != 0)
		return (req->jid != 0 && claim->jid == req->jid);
	if (claim->name[0] != '\0')
		return (req->name[0] != '\0' &&
		    strcmp(claim->name, req->name) == 0);
	return (false);
}

/*
 * Verify that the requested jail path is allowed by the matching
 * claim.  If the claim specifies a path prefix, req_path must start
 * with it followed by '/' or end exactly at the prefix.  An empty
 * claim path means any absolute path is allowed.
 */
static bool
jail_path_allowed(const char *jail_name, const char *req_path)
{
	unsigned i;
	size_t plen;

	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		const struct oracled_jail_claim *c = &od.cfg.claim_jail[i];

		if (c->name[0] == '\0' || strcmp(c->name, jail_name) != 0)
			continue;
		if (c->path[0] == '\0')
			return (true);
		plen = strlen(c->path);
		if (strncmp(req_path, c->path, plen) == 0 &&
		    (req_path[plen] == '\0' || req_path[plen] == '/'))
			return (true);
		return (false);
	}
	/* No matching claim found — shouldn't happen after jail_is_claimed. */
	return (false);
}

static bool
jail_is_claimed(const struct oracled_jail_claim *req)
{
	unsigned i;

	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		if (jail_claim_covers(&od.cfg.claim_jail[i], req))
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
		ORACLED_PROBE_MINT_PATH(req->path, EACCES);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_path_token(req->path);
	if (token_fd == -1) {
		ORACLED_PROBE_MINT_PATH(req->path, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_PATH(req->path, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_file(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_file_req *req;
	int token_fd;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (strnlen(req->path, PATH_MAX) >= PATH_MAX) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}
	if (req->path[0] != '/') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (req->actions == 0 || (req->actions & ~FI_FS_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (!path_is_claimed(req->path)) {
		syslog(LOG_NOTICE, "oracle_proto: mint_file denied: %s",
		    req->path);
		ORACLED_PROBE_MINT_PATH(req->path, EACCES);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_file_token(req->path, req->actions);
	if (token_fd == -1) {
		ORACLED_PROBE_MINT_PATH(req->path, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_PATH(req->path, 0);
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
	if (req->port_min > req->port_max) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	memset(&nc, 0, sizeof(nc));
	nc.domain = req->domain;
	nc.protocol = req->protocol;
	nc.port_min = req->port_min;
	nc.port_max = req->port_max;
	nc.direction = req->direction;
	nc.prefix = req->prefix;
	memcpy(nc.addr, req->addr, sizeof(nc.addr));

	if (!net_is_claimed(&nc)) {
		syslog(LOG_NOTICE, "oracle_proto: mint_net denied: %u-%u/%d",
		    nc.port_min, nc.port_max, nc.protocol);
		ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol,
		    EACCES);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_net_token(&nc);
	if (token_fd == -1) {
		ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol,
		    EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_mint_jail_req *req;
	struct oracled_jail_claim jc;
	int token_fd;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	if (req->jid < 0 || (req->actions == 0 ||
	    (req->actions & ~FI_JAIL_ALL) != 0)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (memchr(req->name, '\0', sizeof(req->name)) == NULL) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}
	if (req->jid == 0 && req->name[0] == '\0') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	memset(&jc, 0, sizeof(jc));
	jc.jid = req->jid;
	jc.actions = req->actions;
	strlcpy(jc.name, req->name, sizeof(jc.name));

	if (!jail_is_claimed(&jc)) {
		syslog(LOG_NOTICE, "oracle_proto: mint_jail denied: "
		    "jid=%d name=%s actions=0x%x", jc.jid, jc.name,
		    jc.actions);
		ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, EACCES);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_jail_token(&jc);
	if (token_fd == -1) {
		ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_JAIL(jc.jid, jc.name, jc.actions, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_jail(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct oracle_create_jail_req *req;
	struct oracled_jail_claim jc;
	struct iovec iov[10];
	struct in_addr ip4;
	int jd, persist, niov;

	if (len < sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;

	/* Validate strings are NUL-terminated. */
	if (memchr(req->name, '\0', sizeof(req->name)) == NULL ||
	    memchr(req->path, '\0', sizeof(req->path)) == NULL ||
	    memchr(req->hostname, '\0', sizeof(req->hostname)) == NULL ||
	    memchr(req->ip4_addr, '\0', sizeof(req->ip4_addr)) == NULL) {
		proto_reply(ENAMETOOLONG, reply_token, NULL, 0);
		return;
	}
	if (req->name[0] == '\0' || req->path[0] != '/') {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	/* Validate ip4_addr if specified. */
	if (req->ip4_addr[0] != '\0') {
		if (inet_pton(AF_INET, req->ip4_addr, &ip4) != 1) {
			syslog(LOG_NOTICE,
			    "oracle_proto: create_jail: bad ip4_addr: %s",
			    req->ip4_addr);
			proto_reply(EINVAL, reply_token, NULL, 0);
			return;
		}
	}

	/* Verify the jail name is covered by our claimed set. */
	memset(&jc, 0, sizeof(jc));
	jc.actions = FI_JAIL_CREATE;
	strlcpy(jc.name, req->name, sizeof(jc.name));
	if (!jail_is_claimed(&jc)) {
		syslog(LOG_NOTICE, "oracle_proto: create_jail denied: %s",
		    req->name);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	/* Verify the jail path is under the claim's allowed root. */
	if (!jail_path_allowed(req->name, req->path)) {
		syslog(LOG_NOTICE,
		    "oracle_proto: create_jail path denied: %s path=%s",
		    req->name, req->path);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	/* Build jail iovec. */
	persist = 1;
	niov = 0;
	iov[niov].iov_base = __DECONST(char *, "name");
	iov[niov].iov_len = sizeof("name");
	niov++;
	iov[niov].iov_base = __DECONST(char *, req->name);
	iov[niov].iov_len = strlen(req->name) + 1;
	niov++;
	iov[niov].iov_base = __DECONST(char *, "path");
	iov[niov].iov_len = sizeof("path");
	niov++;
	iov[niov].iov_base = __DECONST(char *, req->path);
	iov[niov].iov_len = strlen(req->path) + 1;
	niov++;
	iov[niov].iov_base = __DECONST(char *, "persist");
	iov[niov].iov_len = sizeof("persist");
	niov++;
	iov[niov].iov_base = &persist;
	iov[niov].iov_len = sizeof(persist);
	niov++;
	iov[niov].iov_base = __DECONST(char *, "host.hostname");
	iov[niov].iov_len = sizeof("host.hostname");
	niov++;
	iov[niov].iov_base = __DECONST(char *,
	    req->hostname[0] != '\0' ? req->hostname : req->name);
	iov[niov].iov_len = strlen(req->hostname[0] != '\0' ?
	    req->hostname : req->name) + 1;
	niov++;
	if (req->ip4_addr[0] != '\0') {
		iov[niov].iov_base = __DECONST(char *, "ip4.addr");
		iov[niov].iov_len = sizeof("ip4.addr");
		niov++;
		iov[niov].iov_base = &ip4;
		iov[niov].iov_len = sizeof(ip4);
		niov++;
	}

	jd = jail_set(iov, niov,
	    JAIL_CREATE | JAIL_GET_DESC | JAIL_OWN_DESC);
	if (jd < 0) {
		syslog(LOG_ERR, "oracle_proto: jail_set(%s): %m", req->name);
		ORACLED_PROBE_CREATE_JAIL(req->name, errno);
		proto_reply(errno, reply_token, NULL, 0);
		return;
	}

	syslog(LOG_INFO, "oracle_proto: created jail %s jd=%d", req->name, jd);
	ORACLED_PROBE_CREATE_JAIL(req->name, 0);
	proto_reply(0, reply_token, &jd, 1);
	close(jd);
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
		ORACLED_PROBE_MINT_SYSTEM(req->gates, EACCES);
		proto_reply(EACCES, reply_token, NULL, 0);
		return;
	}

	token_fd = cap_rt_mint_system_token(req->gates);
	if (token_fd == -1) {
		ORACLED_PROBE_MINT_SYSTEM(req->gates, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_MINT_SYSTEM(req->gates, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_pair(uint64_t reply_token)
{
	int fds[2];

	if (cap_rt_create_pair(&fds[0], &fds[1]) == -1) {
		ORACLED_PROBE_PAIR_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_PAIR_CREATE(0);
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
		ORACLED_PROBE_COALITION_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	ORACLED_PROBE_COALITION_CREATE(0);
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
	union {
		struct oracle_create_jail_req create_jail;
		struct oracle_mint_file_req file;
		struct oracle_mint_path_req path;
		struct oracle_mint_net_req net;
		struct oracle_mint_jail_req jail;
		struct oracle_mint_system_req system;
		struct oracle_req_hdr hdr;
	} buf;
	uint32_t op;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &buf;
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

	memcpy(&op, &buf, sizeof(op));
	dispatch_op = op;
	dispatch_status = 0;
	ORACLED_PROBE_IPC_RECV(op);

	{
	struct timespec ts_start, ts_end;
	uint64_t dur;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	switch (op) {
	case ORACLE_OP_MINT_PATH:
		handle_mint_path(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_FILE:
		handle_mint_file(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_NET:
		handle_mint_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_JAIL:
		handle_mint_jail(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_MINT_SYSTEM:
		handle_mint_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case ORACLE_OP_CREATE_JAIL:
		handle_create_jail(&buf, ra.payload_len, ra.reply_token);
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

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	dur = (uint64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
	    (uint64_t)(ts_end.tv_nsec - ts_start.tv_nsec);
	ORACLED_PROBE_IPC_DISPATCH_DONE(op, dispatch_status, dur);
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

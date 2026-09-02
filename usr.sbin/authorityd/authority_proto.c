/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityd channel protocol handler.
 *
 * Receives requests from serviced over the restricted channel,
 * validates them against the authority's claimed resource set, and
 * dispatches to mac_capability to mint tokens or create channels/coalitions.
 * Replies are sent back over the same channel with attached fds.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/wait.h>

#include <sys/zfshandle.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <fcntl.h>

#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "authorityd.h"
#include "capsule.h"
#include "authorityd_svc_proto.h"
#include "authorityd_ctl.h"		/* struct ctl_reply for cmd_reload() */
#include "serviced_ctl.h"		/* SERVICED_CTL_SUMMARY_MAX */
#include "commands.h"			/* cmd_reload() */
#include "mac_capability_priv.h"
#include "probes.h"
#include "authority_proto_claims.h"
#include "req_validate.h"


static int	proto_channel_fd = -1;
static bool	serviced_ready;
static uint64_t	serviced_nonce;		/* set on first message */
static bool	nonce_set;

/* Per-dispatch tracking for the ipc-dispatch-done probe. */
static uint32_t dispatch_op;
static int dispatch_status;

/*
 * Send a reply with optional attached fds.
 */
int
proto_reply(int status, uint64_t reply_token, int *fds, int nfds)
{
	struct mac_capability_sendmsg_args sa;
	struct authority_reply rpl;
	int i;

	/*
	 * Every delegated descriptor crosses exactly this one message edge.
	 * CAP_XFER_ONCE is consumed atomically by SENDMSG and the receiving
	 * descriptor is installed as CAP_XFER_NONE.
	 */
	if (status == 0 && nfds > 0) {
		for (i = 0; i < nfds; i++) {
			if (cap_xfer_limit(fds[i], CAP_XFER_ONCE) == -1) {
				syslog(LOG_ERR,
				    "authority_proto: confine reply fd: %m");
				status = EIO;
				fds = NULL;
				nfds = 0;
				break;
			}
		}
	}

	rpl.status = status;

	memset(&sa, 0, sizeof(sa));
	sa.payload = &rpl;
	sa.payload_len = sizeof(rpl);
	sa.reply_token = reply_token;
	if (nfds > 0) {
		sa.fds = fds;
		sa.nfds = (uint32_t)nfds;
	}

	if (ioctl(proto_channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "authority_proto: reply: %m");
		return (-1);
	}
	dispatch_status = status;
	AUTHORITYD_PROBE_IPC_REPLY(dispatch_op, status);
	return (0);
}

/*
 * Validate that a path is within the authority's claimed set.
 */
#include "claim_check.h"

/* Convenience wrapper using the global config. */
#define	net_is_claimed(r)	claim_net_covered(&od.cfg, (r))

static void
handle_mint_net(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_net_claim nc;
	int err, token_fd;

	if (!validate_net_req(payload, len, &nc, &err)) {
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	if (auto_claim_net(&nc, &err) != 0 &&
	    !net_is_claimed(&nc)) {
		AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max,
		    nc.protocol, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}

	token_fd = mac_capability_mint_net_token(&nc);
	if (token_fd == -1) {
		release_auto_claim_net(&nc);
		AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol,
		    EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_NET(nc.port_min, nc.port_max, nc.protocol, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_vsock(const void *payload, uint32_t len, uint64_t reply_token)
{
	struct ort_vsock_claim vc;
	int err, token_fd;
	if (!validate_vsock_req(payload, len, &vc, &err)) {
		AUTHORITYD_PROBE_MINT_VSOCK(0, 0, 0, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	if (auto_claim_vsock(&vc, &err) != 0) {
		AUTHORITYD_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, err);
		proto_reply(err, reply_token, NULL, 0);
		return;
	}
	token_fd = mac_capability_mint_vsock_token(&vc);
	if (token_fd == -1) {
		release_auto_claim_vsock(&vc);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}
	AUTHORITYD_PROBE_MINT_VSOCK(vc.cid, vc.port_min, vc.port_max, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_mint_system(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_system_req *req;
	int token_fd;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	if (req->gates == 0 || (req->gates & ~SYS_GATE_ALL) != 0) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}

	{
		int err;

		if (auto_claim_system(req->gates, &err) != 0) {
			AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, err);
			proto_reply(err, reply_token, NULL, 0);
			return;
		}
	}

	token_fd = mac_capability_mint_system_token(req->gates);
	if (token_fd == -1) {
		release_auto_claim_system(req->gates);
		AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_MINT_SYSTEM(req->gates, 0);
	proto_reply(0, reply_token, &token_fd, 1);
	close(token_fd);
}

static void
handle_create_channel(uint64_t reply_token)
{
	int fds[2];

	if (mac_capability_create_channel(&fds[0], &fds[1]) == -1) {
		AUTHORITYD_PROBE_CHANNEL_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_CHANNEL_CREATE(0);
	proto_reply(0, reply_token, fds, 2);
	close(fds[0]);
	close(fds[1]);
}

static void
handle_create_coalition(uint64_t reply_token)
{
	int cfd;

	cfd = mac_capability_create_coalition();
	if (cfd == -1) {
		AUTHORITYD_PROBE_COALITION_CREATE(EIO);
		proto_reply(EIO, reply_token, NULL, 0);
		return;
	}

	AUTHORITYD_PROBE_COALITION_CREATE(0);
	proto_reply(0, reply_token, &cfd, 1);
	close(cfd);
}

static void
handle_ready(uint64_t reply_token)
{

	if (!serviced_ready) {
		serviced_ready = true;
		syslog(LOG_INFO, "authority_proto: serviced ready");
	}
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_ping(uint64_t reply_token)
{

	proto_reply(0, reply_token, NULL, 0);
}

/*
 * AUTHORITY_OP_SET_AMBIENT_LOOKUP (§21): serviced forwarded a dup of its SYSTEM
 * ambient lookup channel client end so capsule can carry it into
 * interactive logins.  Takes ownership of fd (installs or closes it).
 *
 * Best-effort: a malformed request or a failed install is reported in the
 * status reply and never disturbs the event loop.  The reply carries no fds.
 */
/*
 * Apply a system lifecycle transition serviced relayed from its ADMIN-gated
 * system.lifecycle capability (docs/lifecycle-capability-design.md, P4b).  The
 * ack is queued before the transition runs — capsule_lifecycle() only
 * *sets* the requested transition, which the state-machine loop applies after
 * this dispatch returns, so the caller's reply precedes the death sweep (same
 * ordering as the legacy control-socket path).
 */
static void
handle_lifecycle(const void *payload, uint32_t len, uint64_t reply_token)
{
	const struct authority_lifecycle_req *req;
	int error;

	if (len != sizeof(*req)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	req = payload;
	error = capsule_lifecycle((int)req->lifecycle_op);
	if (error == 0)
		syslog(LOG_NOTICE,
		    "authority_proto: capability lifecycle op %u accepted",
		    req->lifecycle_op);
	proto_reply(error, reply_token, NULL, 0);
}

/*
 * Reload the authority config claims, relayed from authorityctl(8) over
 * serviced's ADMIN-gated system.lifecycle capability (P4b) in place of the
 * getpeereid control socket.  serviced has already authorized the caller, so
 * cmd_reload() runs with euid 0 to satisfy its transitional uid check; the
 * summary it produces is informational and dropped (the reply is status-only).
 */
static void
handle_reload(const void *payload __unused, uint32_t len, uint64_t reply_token)
{
	struct ctl_reply reply;
	char summary[SERVICED_CTL_SUMMARY_MAX];

	if (len != sizeof(struct authority_req_hdr)) {
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	memset(&reply, 0, sizeof(reply));
	summary[0] = '\0';
	cmd_reload(0, &reply, summary, sizeof(summary));
	proto_reply((int)reply.status, reply_token, NULL, 0);
}

static void
handle_set_ambient_lookup(uint32_t len, int fd, uint64_t reply_token)
{

	if (len != sizeof(struct authority_req_hdr) || fd < 0) {
		if (fd >= 0)
			(void)close(fd);
		proto_reply(EINVAL, reply_token, NULL, 0);
		return;
	}
	if (capsule_set_ambient_lookup(fd) == -1) {
		/* set_ambient_lookup already closed fd on failure. */
		syslog(LOG_NOTICE,
		    "authority_proto: ambient lookup install failed: %m");
		proto_reply(errno, reply_token, NULL, 0);
		return;
	}
	syslog(LOG_INFO, "authority_proto: ambient lookup channel installed for "
	    "interactive logins");
	proto_reply(0, reply_token, NULL, 0);
}

static void
handle_delegate_service(const void *payload, uint32_t len,
    uint64_t reply_token)
{
	const struct authority_service_req *req;
	int error, fd;

	if (!validate_service_req(payload, len, &req, &error)) {
		AUTHORITYD_PROBE_SERVICE_DELEGATE("", error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	fd = mac_capability_connect_for_delegate(req->name);
	if (fd == -1) {
		error = errno;
		AUTHORITYD_PROBE_SERVICE_DELEGATE(req->name, error);
		proto_reply(error, reply_token, NULL, 0);
		return;
	}
	AUTHORITYD_PROBE_SERVICE_DELEGATE(req->name, 0);
	proto_reply(0, reply_token, &fd, 1);
	close(fd);
}

/* Claim/release handlers and sweep are in authority_proto_claims.c. */

/*
 * Dispatch a single request from the channel.
 * Returns 0 if message processed, -1 on receive error (peer closed).
 */
static int
proto_dispatch_one(void)
{
	struct mac_capability_recvmsg_args ra;
	union {
		struct authority_net_req net;
		struct authority_vsock_req vsock;
		struct authority_system_req system;
		struct authority_service_req service;
		struct authority_req_hdr hdr;
	} buf;
	uint32_t op;
	int recv_fd = -1;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &buf;
	ra.payload_len = sizeof(buf);
	/*
	 * Accept at most one attached descriptor.  Only
	 * AUTHORITY_OP_SET_AMBIENT_LOOKUP (§21) sends one; any stray fd on another
	 * op is closed below rather than leaked.
	 */
	ra.fds = &recv_fd;
	ra.nfds = 1;

	if (ioctl(proto_channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN)
			return (0);
		syslog(LOG_WARNING, "authority_proto: recvmsg: %m");
		return (-1);
	}

	if (ra.payload_len < sizeof(uint32_t)) {
		syslog(LOG_WARNING, "authority_proto: short message (%u bytes)",
		    ra.payload_len);
		if (recv_fd >= 0)
			(void)close(recv_fd);
		return (0);
	}

	/* Nonce verification — lock to first sender. */
	if (!nonce_set) {
		serviced_nonce = ra.trailer.nonce;
		nonce_set = true;
	} else if (ra.trailer.nonce != serviced_nonce) {
		syslog(LOG_WARNING,
		    "authority_proto: nonce mismatch (got 0x%jx, expected 0x%jx)",
		    (uintmax_t)ra.trailer.nonce,
		    (uintmax_t)serviced_nonce);
		proto_reply(EACCES, ra.reply_token, NULL, 0);
		if (recv_fd >= 0)
			(void)close(recv_fd);
		return (0);
	}

	memcpy(&op, &buf, sizeof(op));
	dispatch_op = op;
	dispatch_status = 0;
	AUTHORITYD_PROBE_IPC_RECV(op);

	{
	struct timespec ts_start, ts_end;
	uint64_t dur;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	switch (op) {
	case AUTHORITY_OP_MINT_NET:
		handle_mint_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_VSOCK:
		handle_mint_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_MINT_SYSTEM:
		handle_mint_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CREATE_CHANNEL:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_channel(ra.reply_token);
		break;
	case AUTHORITY_OP_CREATE_COALITION:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_create_coalition(ra.reply_token);
		break;
	case AUTHORITY_OP_READY:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ready(ra.reply_token);
		break;
	case AUTHORITY_OP_PING:
		if (ra.payload_len != sizeof(struct authority_req_hdr))
			proto_reply(EINVAL, ra.reply_token, NULL, 0);
		else
			handle_ping(ra.reply_token);
		break;
	case AUTHORITY_OP_SET_AMBIENT_LOOKUP:
		/* Consumes recv_fd (installs or closes it). */
		handle_set_ambient_lookup(ra.payload_len, recv_fd,
		    ra.reply_token);
		recv_fd = -1;
		break;
	case AUTHORITY_OP_DELEGATE_SERVICE:
		handle_delegate_service(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_NET:
		handle_claim_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_SYSTEM:
		handle_claim_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_CLAIM_VSOCK:
		handle_claim_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_NET:
		handle_release_net(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_SYSTEM:
		handle_release_system(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELEASE_VSOCK:
		handle_release_vsock(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_LIFECYCLE:
		handle_lifecycle(&buf, ra.payload_len, ra.reply_token);
		break;
	case AUTHORITY_OP_RELOAD:
		handle_reload(&buf, ra.payload_len, ra.reply_token);
		break;
	default:
		syslog(LOG_WARNING, "authority_proto: unknown op %u", op);
		proto_reply(ENOTSUP, ra.reply_token, NULL, 0);
		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	dur = (uint64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
	    (uint64_t)(ts_end.tv_nsec - ts_start.tv_nsec);
	AUTHORITYD_PROBE_IPC_DISPATCH_DONE(op, dispatch_status, dur);
	}

	/* Close any descriptor an op did not consume (only §21 sends one). */
	if (recv_fd >= 0)
		(void)close(recv_fd);

	return (0);
}

/*
 * Called from the event loop when EVFILT_READ fires on the channel fd.
 * Processes one message per call; kqueue re-fires if more are queued.
 */
int
authority_proto_dispatch(void)
{

	return (proto_dispatch_one());
}

/*
 * Initialize the protocol handler.
 * channel_fd is authorityd's end of the channel to serviced.
 */
void
authority_proto_init(int channel_fd)
{

	proto_channel_fd = channel_fd;
	serviced_ready = false;
	nonce_set = false;
}

/*
 * Reset state when serviced exits (before restart).
 */
void
authority_proto_reset(void)
{

	/* The caller already closed the fd; prevent stale ioctl use. */
	proto_channel_fd = -1;
	sweep_dynamic_claims();
	serviced_ready = false;
	nonce_set = false;
}

bool
authority_proto_is_ready(void)
{

	return (serviced_ready);
}

int
authority_proto_fd(void)
{

	return (proto_channel_fd);
}

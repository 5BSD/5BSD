/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT token minting and pair/coalition creation for oracled.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_capprotect_proto.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>
#include <dev/cap_rt/cap_rt_system_proto.h>
#include <dev/cap_rt/cap_rt_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "gates.h"
#include "probes.h"
#include "cap_rt_priv.h"

#include <dev/cap_rt/cap_rt_pair_proto.h>

/*
 * Mint an isolation access token for a claimed path.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_path_token(const char *path)
{

	return (cap_rt_mint_file_token(path, FI_FS_ALL));
}

int
cap_rt_mint_file_token(const char *path, uint64_t actions)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd, token_fd;

	if (cap_rt_isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_path_token: isolation not connected");
		return (-1);
	}

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		syslog(LOG_WARNING, "mint_path_token: open %s: %m", path);
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT;
	req.actions = actions;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_path_token: mint %s: %m", path);
		close(fd);
		return (-1);
	}

	close(fd);
	return (token_fd);
}

/*
 * Mint a network isolation access token for one endpoint.  The oracle
 * must already hold a claim covering the endpoint.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_net_token(const struct oracled_net_claim *nc)
{
	struct cap_rt_call_args call;
	struct fi_net_request req;
	struct fi_reply reply;
	int token_fd;

	if (cap_rt_isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_net_token: isolation not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port_min = htons(nc->port_min);
	req.port_max = htons(nc->port_max);
	req.direction = nc->direction;
	req.prefix = nc->prefix;
	memcpy(req.addr, nc->addr, sizeof(req.addr));

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_net_token: %m");
		return (-1);
	}

	return (token_fd);
}

int
cap_rt_mint_jail_token(const struct oracled_jail_claim *jc)
{
	struct cap_rt_call_args call;
	struct fi_jail_request req;
	struct fi_reply reply;
	int token_fd;

	if (cap_rt_isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_jail_token: isolation not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_jail_token: jid=%d name=%s: %m",
		    jc->jid, jc->name);
		return (-1);
	}

	return (token_fd);
}

/*
 * Mint a system access token for the given gate bitmask.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_system_token(uint32_t gates)
{
	struct cap_rt_call_args call;
	struct sys_request req;
	int token_fd;

	if (cap_rt_system_fd == -1) {
		syslog(LOG_WARNING, "mint_system_token: system not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	req.gates = gates;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply_len = 0;
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(cap_rt_system_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_system_token: mint 0x%x: %m", gates);
		return (-1);
	}

	return (token_fd);
}

/*
 * Create a cap_rt pair channel.
 * Sets *oracle_end and *child_end to the two paired fds.
 * Returns 0 on success, -1 on failure.
 */
int
cap_rt_create_pair(int *oracle_end, int *child_end)
{
	struct cap_rt_sendmsg_args sa;
	struct cap_rt_recvmsg_args ra;
	uint32_t op;
	int pair_fd, peer_fd;

	if (cap_rt_fd == -1)
		return (-1);

	pair_fd = cap_rt_svc_connect("pair");
	if (pair_fd == -1)
		return (-1);

	op = PAIR_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);

	if (ioctl(pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "create_pair: sendmsg: %m");
		close(pair_fd);
		return (-1);
	}

	peer_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer_fd;
	ra.nfds = 1;

	if (ioctl(pair_fd, CAP_RT_RECVMSG, &ra) == -1) {
		syslog(LOG_WARNING, "create_pair: recvmsg: %m");
		close(pair_fd);
		return (-1);
	}

	if (peer_fd < 0) {
		syslog(LOG_WARNING, "create_pair: recvmsg returned no fd");
		close(pair_fd);
		return (-1);
	}

	if (fcntl(pair_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_pair: fcntl CLOEXEC pair_fd: %m");
		close(pair_fd);
		close(peer_fd);
		return (-1);
	}
	if (fcntl(peer_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_pair: fcntl CLOEXEC peer_fd: %m");
		close(pair_fd);
		close(peer_fd);
		return (-1);
	}

	*oracle_end = pair_fd;
	*child_end = peer_fd;
	return (0);
}

/*
 * Create a coalition instance.
 * Returns the coalition fd on success, -1 on failure.
 */
int
cap_rt_create_coalition(void)
{
	int fd;

	if (cap_rt_fd == -1)
		return (-1);
	fd = cap_rt_svc_connect("coalition");
	if (fd >= 0)
		(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	return (fd);
}

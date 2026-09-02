/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY token minting and channel/coalition creation for authorityd.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "mac_capability_priv.h"
#include "gates.h"
#include "authorityd.h"
#include "probes.h"

/*
 * Mint a narrowed file isolation access token for a path.
 * Returns the token fd on success, -1 on failure.
 */
int
mac_capability_mint_file_token(const char *path, uint64_t actions)
{
	struct fi_request req;
	struct fi_reply reply;
	int fd, token_fd;

	if (mac_capability_isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_file_token: isolation not connected");
		return (-1);
	}

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		syslog(LOG_WARNING, "mint_file_token: open %s: %m", path);
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT;
	req.actions = actions;

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), &fd, 1, &reply, sizeof(reply),
	    &token_fd, 1) == -1) {
		syslog(LOG_WARNING, "mint_file_token: mint %s: %m", path);
		close(fd);
		return (-1);
	}

	close(fd);
	return (token_fd);
}

/*
 * Mint a network isolation access token for one endpoint.  The authority
 * must already hold a claim covering the endpoint.
 * Returns the token fd on success, -1 on failure.
 */
int
mac_capability_mint_net_token(const struct ort_net_claim *nc)
{
	struct fi_net_request req;
	struct fi_reply reply;
	int token_fd;

	if (mac_capability_isolation_fd == -1) {
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

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), NULL, 0, &reply, sizeof(reply),
	    &token_fd, 1) == -1) {
		syslog(LOG_WARNING, "mint_net_token: %m");
		return (-1);
	}

	return (token_fd);
}

int
mac_capability_mint_vsock_token(const struct ort_vsock_claim *vc)
{
	struct fi_vsock_request req;
	struct fi_reply reply;
	int token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT_VSOCK;
	req.cid = vc->cid;
	req.port_min = vc->port_min;
	req.port_max = vc->port_max;
	req.direction = vc->direction;
	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), NULL, 0, &reply, sizeof(reply),
	    &token_fd, 1) == -1)
		return (-1);
	return (token_fd);
}

/*
 * Mint a system access token for the given gate bitmask.
 * Returns the token fd on success, -1 on failure.
 */
int
mac_capability_mint_system_token(uint32_t gates)
{
	struct sys_request req;
	int token_fd;

	if (mac_capability_system_fd == -1) {
		syslog(LOG_WARNING, "mint_system_token: system not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	req.gates = gates;

	if (mac_capability_do_call_fds(mac_capability_system_fd,
	    &req, sizeof(req), NULL, 0, NULL, 0, &token_fd, 1) == -1) {
		syslog(LOG_WARNING, "mint_system_token: mint 0x%x: %m", gates);
		return (-1);
	}

	return (token_fd);
}

/*
 * Create a mac_capability channel.
 * Sets *authority_end and *child_end to the two connected fds.
 * Returns 0 on success, -1 on failure.
 */
int
mac_capability_create_channel(int *authority_end, int *child_end)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	uint32_t op;
	int chan_fd, peer_fd;

	if (mac_capability_fd == -1)
		return (-1);

	chan_fd = mac_capability_svc_connect("channel");
	if (chan_fd == -1)
		return (-1);

	op = CHANNEL_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);

	if (ioctl(chan_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "create_channel: sendmsg: %m");
		close(chan_fd);
		return (-1);
	}

	peer_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer_fd;
	ra.nfds = 1;

	if (ioctl(chan_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) {
		syslog(LOG_WARNING, "create_channel: recvmsg: %m");
		close(chan_fd);
		return (-1);
	}

	if (peer_fd < 0) {
		syslog(LOG_WARNING, "create_channel: recvmsg returned no fd");
		close(chan_fd);
		return (-1);
	}

	if (fcntl(chan_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_channel: fcntl CLOEXEC chan_fd: %m");
		close(chan_fd);
		close(peer_fd);
		return (-1);
	}
	if (fcntl(peer_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_channel: fcntl CLOEXEC peer_fd: %m");
		close(chan_fd);
		close(peer_fd);
		return (-1);
	}

	*authority_end = chan_fd;
	*child_end = peer_fd;
	return (0);
}

/*
 * Create a coalition instance.
 * Returns the coalition fd on success, -1 on failure.
 */
int
mac_capability_create_coalition(void)
{
	int fd;

	if (mac_capability_fd == -1)
		return (-1);
	fd = mac_capability_svc_connect("coalition");
	if (fd >= 0)
		(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	return (fd);
}

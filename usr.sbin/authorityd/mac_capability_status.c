/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY status formatting for authorityd.
 *
 * Formats the current claim state (paths, network, jails,
 * system gates, integrity) into a human-readable buffer
 * for the control socket status command.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "authorityd.h"
#include "authorityd_svc_proto.h"
#include "gates.h"
#include "mac_capability_priv.h"

static void
net_claim_address_string(const struct ort_net_claim *nc, char *buf,
    size_t bufsz)
{
	static const uint8_t zero[16];
	char addr[INET6_ADDRSTRLEN];

	if (memcmp(nc->addr, zero, sizeof(zero)) == 0) {
		strlcpy(buf, "*", bufsz);
		return;
	}
	if (nc->domain == AF_BLUETOOTH) {
		(void)snprintf(addr, sizeof(addr),
		    "%02x:%02x:%02x:%02x:%02x:%02x", nc->addr[5],
		    nc->addr[4], nc->addr[3], nc->addr[2], nc->addr[1],
		    nc->addr[0]);
	} else if (nc->domain == AF_INET ||
	    (nc->domain == 0 && nc->addr[10] == 0xff &&
	    nc->addr[11] == 0xff)) {
		if (inet_ntop(AF_INET, &nc->addr[12], addr, sizeof(addr)) == NULL)
			strlcpy(addr, "?", sizeof(addr));
	} else if (inet_ntop(AF_INET6, nc->addr, addr, sizeof(addr)) == NULL) {
		strlcpy(addr, "?", sizeof(addr));
	}
	(void)snprintf(buf, bufsz, "%s/%u", addr, nc->prefix);
}

/* --- Static query helpers --- */

static bool
query_path_claimed(const char *path)
{
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	if (mac_capability_isolation_fd == -1)
		return (false);

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY;
	req.actions = FI_FS_ALL;

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), &fd, 1, &reply, sizeof(reply), NULL, 0) == -1) {
		close(fd);
		return (false);
	}

	close(fd);
	return ((reply.flags & FI_QF_MINE) != 0);
}

static bool
query_net_claimed(const struct ort_net_claim *nc)
{
	struct fi_net_request req;
	struct fi_reply reply;

	if (mac_capability_isolation_fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port_min = htons(nc->port_min);
	req.port_max = htons(nc->port_max);
	req.direction = nc->direction;
	req.prefix = nc->prefix;
	memcpy(req.addr, nc->addr, sizeof(req.addr));

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (false);

	return ((reply.flags & FI_QF_MINE) != 0);
}

static bool
query_jail_claimed(const struct authorityd_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;

	if (mac_capability_isolation_fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (false);

	return ((reply.flags & FI_QF_MINE) != 0);
}

static bool
query_vsock_claimed(const struct ort_vsock_claim *vc)
{
	struct fi_vsock_request req;
	struct fi_reply reply;

	if (mac_capability_isolation_fd == -1)
		return (false);
	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY_VSOCK;
	req.cid = vc->cid;
	req.port_min = vc->port_min;
	req.port_max = vc->port_max;
	req.direction = vc->direction;
	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (false);
	return ((reply.flags & FI_QF_MINE) != 0);
}

/*
 * Format current claim status into a buffer for status reporting.
 */
void
mac_capability_format_status(char *buf, size_t bufsz, size_t *offp)
{
	unsigned i;
	bool first, verified;

	/* Integrity flags. */
	BUF_APPEND(buf, bufsz, offp, "INTEGRITY:\n  ");
	if (od.cfg.integrity_flags == 0) {
		BUF_APPEND(buf, bufsz, offp, "(none)");
	} else {
		first = true;
		for (i = 0; i < nitems(integrity_flag_names); i++) {
			if (od.cfg.integrity_flags &
			    integrity_flag_names[i].flag) {
				BUF_APPEND(buf, bufsz, offp, "%s%s",
				    first ? "" : " ",
				    integrity_flag_names[i].name);
				first = false;
			}
		}
		BUF_APPEND(buf, bufsz, offp, " (0x%x)",
		    od.cfg.integrity_flags);
	}
	BUF_APPEND(buf, bufsz, offp, "\n");

	/* Path claims — verified against kernel via FI_OP_QUERY. */
	BUF_APPEND(buf, bufsz, offp, "\nCLAIMS:\n");
	BUF_APPEND(buf, bufsz, offp, "  paths:    %u",
	    od.cfg.nclaim_paths + 1);	/* +1 for /dev/mac_capability */
	verified = query_path_claimed("/dev/mac_capability");
	BUF_APPEND(buf, bufsz, offp, "\n    /dev/mac_capability%s\n",
	    verified ? "" : " [NOT HELD]");
	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		verified = query_path_claimed(od.cfg.claim_paths[i]);
		if (od.cfg.claim_path_source[i] == CLAIM_SOURCE_SERVICE)
			BUF_APPEND(buf, bufsz, offp,
			    "    %s [service, refcount=%u]%s\n",
			    od.cfg.claim_paths[i],
			    od.cfg.claim_path_refcount[i],
			    verified ? "" : " [NOT HELD]");
		else
			BUF_APPEND(buf, bufsz, offp, "    %s [policy]%s\n",
			    od.cfg.claim_paths[i],
			    verified ? "" : " [NOT HELD]");
	}

	/* Network claims — verified against kernel via FI_OP_QUERY_NET. */
	BUF_APPEND(buf, bufsz, offp, "  network:  %u\n",
	    od.cfg.nclaim_net);
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		const struct ort_net_claim *nc = &od.cfg.claim_net[i];
		char addrbuf[INET6_ADDRSTRLEN + 8], portbuf[32];

		net_claim_port_string(nc, portbuf, sizeof(portbuf));
		net_claim_address_string(nc, addrbuf, sizeof(addrbuf));
		verified = query_net_claimed(nc);
		if (od.cfg.claim_net_source[i] == CLAIM_SOURCE_SERVICE)
			BUF_APPEND(buf, bufsz, offp,
			    "    %s %s/%s %s address=%s [service, refcount=%u]%s\n",
			    ort_net_domain_name(nc->domain),
			    ort_net_protocol_name(nc->protocol), portbuf,
			    ort_net_direction_name(nc->direction),
			    addrbuf,
			    od.cfg.claim_net_refcount[i],
			    verified ? "" : " [NOT HELD]");
		else
			BUF_APPEND(buf, bufsz, offp,
			    "    %s %s/%s %s address=%s [policy]%s\n",
			    ort_net_domain_name(nc->domain),
			    ort_net_protocol_name(nc->protocol), portbuf,
			    ort_net_direction_name(nc->direction),
			    addrbuf,
			    verified ? "" : " [NOT HELD]");
	}

	/* Jail claims — verified against kernel via FI_OP_QUERY_JAIL. */
	BUF_APPEND(buf, bufsz, offp, "  jails:    %u\n",
	    od.cfg.nclaim_jail);
	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		const struct authorityd_jail_claim *jc = &od.cfg.claim_jail[i];
		char jailbuf[AUTHORITYD_JAIL_DESC_MAX];

		jail_claim_string(jc, jailbuf, sizeof(jailbuf));
		verified = query_jail_claimed(jc);
		if (od.cfg.claim_jail_source[i] == CLAIM_SOURCE_SERVICE)
			BUF_APPEND(buf, bufsz, offp,
			    "    %s actions=0x%x [service, refcount=%u]%s\n",
			    jailbuf, jc->actions,
			    od.cfg.claim_jail_refcount[i],
			    verified ? "" : " [NOT HELD]");
		else
			BUF_APPEND(buf, bufsz, offp,
			    "    %s actions=0x%x [policy]%s\n",
			    jailbuf, jc->actions,
			    verified ? "" : " [NOT HELD]");
	}

	/* VSOCK claims — verified against kernel via FI_OP_QUERY_VSOCK. */
	BUF_APPEND(buf, bufsz, offp, "  vsock:    %u\n",
	    od.cfg.nclaim_vsock);
	for (i = 0; i < od.cfg.nclaim_vsock; i++) {
		const struct ort_vsock_claim *vc = &od.cfg.claim_vsock[i];

		verified = query_vsock_claimed(vc);
		BUF_APPEND(buf, bufsz, offp,
		    "    cid=%" PRIu64 " ports=%u-%u %s [service, refcount=%u]%s\n",
		    vc->cid, vc->port_min, vc->port_max,
		    ort_net_direction_name(vc->direction),
		    od.cfg.claim_vsock_refcount[i],
		    verified ? "" : " [NOT HELD]");
	}

	/* System gates — with provenance per gate. */
	BUF_APPEND(buf, bufsz, offp, "  system:   ");
	if (od.cfg.claim_system == 0) {
		BUF_APPEND(buf, bufsz, offp, "(none)\n");
	} else {
		BUF_APPEND(buf, bufsz, offp, "(0x%x)\n",
		    od.cfg.claim_system);
		for (i = 0; i < nitems(gate_names); i++) {
			uint32_t g = gate_names[i].gate;
			unsigned bit;

			if (!(od.cfg.claim_system & g))
				continue;
			/* Find the bit index for refcount lookup. */
			for (bit = 0; bit < AUTHORITYD_SYSTEM_GATE_NBITS; bit++) {
				if ((1U << bit) == g)
					break;
			}
			if (od.cfg.claim_system_policy & g)
				BUF_APPEND(buf, bufsz, offp,
				    "    %s [policy]\n",
				    gate_names[i].name);
			else if (od.cfg.claim_system_service & g)
				BUF_APPEND(buf, bufsz, offp,
				    "    %s [service, refcount=%u]\n",
				    gate_names[i].name,
				    bit < AUTHORITYD_SYSTEM_GATE_NBITS ?
				    od.cfg.claim_system_refcount[bit] : 0);
			else
				BUF_APPEND(buf, bufsz, offp,
				    "    %s\n", gate_names[i].name);
		}
	}
}

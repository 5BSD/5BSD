/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT status formatting for oracled.
 *
 * Formats the current claim state (paths, network, jails,
 * system gates, integrity) into a human-readable buffer
 * for the control socket status command.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_svc_proto.h"
#include "gates.h"
#include "cap_rt_priv.h"

/* --- Static query helpers --- */

static bool
query_path_claimed(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	if (cap_rt_isolation_fd == -1)
		return (false);

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY;
	req.actions = FI_FS_ALL;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
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

	if (cap_rt_isolation_fd == -1)
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

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (false);

	return ((reply.flags & FI_QF_MINE) != 0);
}

static bool
query_jail_claimed(const struct oracled_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;

	if (cap_rt_isolation_fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (false);

	return ((reply.flags & FI_QF_MINE) != 0);
}

/*
 * Format current claim status into a buffer for status reporting.
 */
void
cap_rt_format_status(char *buf, size_t bufsz, size_t *offp)
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
	    od.cfg.nclaim_paths + 1);	/* +1 for /dev/cap_rt */
	verified = query_path_claimed("/dev/cap_rt");
	BUF_APPEND(buf, bufsz, offp, "\n    /dev/cap_rt%s\n",
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
		char portbuf[32];

		net_claim_port_string(nc, portbuf, sizeof(portbuf));
		verified = query_net_claimed(nc);
		if (od.cfg.claim_net_source[i] == CLAIM_SOURCE_SERVICE)
			BUF_APPEND(buf, bufsz, offp,
			    "    %s/%s %s [service, refcount=%u]%s\n",
			    ort_net_protocol_name(nc->protocol), portbuf,
			    ort_net_direction_name(nc->direction),
			    od.cfg.claim_net_refcount[i],
			    verified ? "" : " [NOT HELD]");
		else
			BUF_APPEND(buf, bufsz, offp,
			    "    %s/%s %s [policy]%s\n",
			    ort_net_protocol_name(nc->protocol), portbuf,
			    ort_net_direction_name(nc->direction),
			    verified ? "" : " [NOT HELD]");
	}

	/* Jail claims — verified against kernel via FI_OP_QUERY_JAIL. */
	BUF_APPEND(buf, bufsz, offp, "  jails:    %u\n",
	    od.cfg.nclaim_jail);
	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		const struct oracled_jail_claim *jc = &od.cfg.claim_jail[i];
		char jailbuf[ORACLED_JAIL_DESC_MAX];

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
			for (bit = 0; bit < ORACLED_SYSTEM_GATE_NBITS; bit++) {
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
				    bit < ORACLED_SYSTEM_GATE_NBITS ?
				    od.cfg.claim_system_refcount[bit] : 0);
			else
				BUF_APPEND(buf, bufsz, offp,
				    "    %s\n", gate_names[i].name);
		}
	}
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced control socket wire protocol.
 *
 * Used by servicectl(8) and future libraries to manage services.
 * One-shot connections: connect, send request, receive reply, close.
 */

#ifndef SERVICED_CTL_H
#define SERVICED_CTL_H

#include <sys/types.h>

#define	SERVICED_CTL_SOCK	"/var/run/serviced.sock"
#define	SERVICED_CTL_VERSION	2
#define	SERVICED_CTL_MAX_PAYLOAD	1024
#define	SERVICED_CTL_SUMMARY_MAX	4096

/*
 * Control opcodes.
 */
#define	SCTL_OP_STATUS		1	/* query serviced status (any) */
#define	SCTL_OP_SERVICES	2	/* list loaded services (any) */
#define	SCTL_OP_RELOAD		3	/* reload manifests (root) */
#define	SCTL_OP_START_SVC	4	/* start a loaded unit (root) */
#define	SCTL_OP_STOP_SVC	5	/* stop a loaded unit (root) */

struct sctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	datalen;
} __packed;

struct sctl_reply {
	uint32_t	status;		/* 0 = ok, nonzero = errno */
	uint32_t	flags;		/* summary text length */
} __packed;

#endif /* SERVICED_CTL_H */

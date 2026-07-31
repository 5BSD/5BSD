/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _COMPONENT_SESSION_H_
#define	_COMPONENT_SESSION_H_

#include <sys/types.h>

#include <stdint.h>

#define	COMPONENT_SESSION_MAGIC		0x434f4d50U	/* "COMP" */
#define	COMPONENT_SESSION_VERSION	2
#define	COMPONENT_SESSION_NAME_MAX	64
#define	COMPONENT_SESSION_INTERFACE_MAX	128
#define	COMPONENT_SESSION_INTERFACE_VERSION_MAX	32
#define	COMPONENT_SESSION_LABEL_MAX	64
#define	COMPONENT_SESSION_RESOURCE_MAX	4

/*
 * A provider must acknowledge bootstrap with exactly one attached membership
 * descriptor.  It may be a procdesc for a single worker or a coalition
 * descriptor for a contained worker tree.  serviced enlists that descriptor
 * into the client's coalition before the client is allowed to exec.
 */
#define	COMPONENT_SESSION_MEMBER_PROCDESC	1
#define	COMPONENT_SESSION_MEMBER_COALITION	2

struct component_session_bootstrap {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	header_size;
	uint64_t	instance_id;
	char		name[COMPONENT_SESSION_NAME_MAX];
	char		interface[COMPONENT_SESSION_INTERFACE_MAX];
	char		interface_version[COMPONENT_SESSION_INTERFACE_VERSION_MAX];
	char		client_label[COMPONENT_SESSION_LABEL_MAX];
	uint32_t	reserved[4];
};

struct component_session_reply {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	header_size;
	int32_t		status;
	uint32_t	member_type;
	uint64_t	instance_id;
	uint32_t	reserved[5];
};

#endif /* !_COMPONENT_SESSION_H_ */

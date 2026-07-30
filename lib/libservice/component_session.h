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
#define	COMPONENT_SESSION_VERSION	1
#define	COMPONENT_SESSION_NAME_MAX	64
#define	COMPONENT_SESSION_INTERFACE_MAX	128
#define	COMPONENT_SESSION_INTERFACE_VERSION_MAX	32
#define	COMPONENT_SESSION_LABEL_MAX	64
#define	COMPONENT_SESSION_OPTIONS_MAX	4096

#define	COMPONENT_SESSION_F_REQUIRED	0x00000001U
#define	COMPONENT_SESSION_F_SHARED	0x00000002U
#define	COMPONENT_SESSION_F_MASK		0x00000003U

#define	COMPONENT_SESSION_SCOPE_PRIVATE	1
#define	COMPONENT_SESSION_SCOPE_JAIL	2
#define	COMPONENT_SESSION_SCOPE_SERVICE	3
#define	COMPONENT_SESSION_SCOPE_SYSTEM	4

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
	uint32_t	length;
	uint32_t	scope;
	uint32_t	flags;
	uint32_t	options_length;
	uint64_t	instance_id;
	char		name[COMPONENT_SESSION_NAME_MAX];
	char		interface[COMPONENT_SESSION_INTERFACE_MAX];
	char		interface_version[COMPONENT_SESSION_INTERFACE_VERSION_MAX];
	char		client_label[COMPONENT_SESSION_LABEL_MAX];
	/* options_length bytes of UTF-8 JSON, including its NUL, follow. */
};

struct component_session_reply {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	header_size;
	uint32_t	length;
	int32_t		status;
	uint32_t	member_type;
	uint64_t	instance_id;
	uint32_t	reserved[4];
};

#endif /* !_COMPONENT_SESSION_H_ */

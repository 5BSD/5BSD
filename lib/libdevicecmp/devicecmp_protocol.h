/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for system.Device: open a named /dev node on behalf of a
 * capability-plane consumer and deliver a rights-limited descriptor.
 *
 * This is intentionally a thin v1 abstraction that sits just below
 * system.Filesystem: Filesystem brokers persistent storage (datasets, files),
 * while Device brokers raw device nodes for the driver model.  Today it hands
 * back a Capsicum-narrowed fd, optionally restricted to a per-device ioctl
 * whitelist; tomorrow the same name can carry richer driver semantics.
 */

#ifndef _DEVICECMP_PROTOCOL_H_
#define	_DEVICECMP_PROTOCOL_H_

#include <stdint.h>

#define	DEVICECMP_INTERFACE		"system.Device"
#define	DEVICECMP_INTERFACE_VERSION	"1.0.0"
#define	DEVICECMP_MAGIC			0x44455643U	/* "DEVC" */
#define	DEVICECMP_ABI_VERSION		1

#define	DEVICECMP_MAX_NAME		256

/*
 * Requested access rights.  A small portable bitmask the provider maps to a
 * cap_rights_t; the client asks for what it needs and the provider intersects
 * with the per-device policy maximum before limiting the delivered fd.
 */
#define	DEVICECMP_RIGHT_READ		0x0001U
#define	DEVICECMP_RIGHT_WRITE		0x0002U
#define	DEVICECMP_RIGHT_IOCTL		0x0004U
#define	DEVICECMP_RIGHT_MMAP		0x0008U
#define	DEVICECMP_RIGHT_SEEK		0x0010U
#define	DEVICECMP_RIGHT_EVENT		0x0020U	/* kqueue/poll (CAP_EVENT) */
#define	DEVICECMP_RIGHT_ALL \
	(DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE | DEVICECMP_RIGHT_IOCTL | \
	 DEVICECMP_RIGHT_MMAP | DEVICECMP_RIGHT_SEEK | DEVICECMP_RIGHT_EVENT)

enum devicecmp_opcode {
	DEVICECMP_OP_HELLO = 1,
	DEVICECMP_OP_OPEN	/* open a named /dev node; reply delivers the fd */
};

enum devicecmp_message_role {
	DEVICECMP_MESSAGE_REQUEST = 1,
	DEVICECMP_MESSAGE_REPLY
};

struct devicecmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;		/* reply: 0 or -errno */
};

/*
 * OPEN body immediately follows the header; the device name (NUL-terminated,
 * name_length bytes including the NUL) is packed after this struct.  rights is
 * the DEVICECMP_RIGHT_* mask the caller wants.  The successful reply carries the
 * header (status 0), the granted rights mask in this same body, and one
 * delivered descriptor; a failure reply is the bare header.
 */
struct devicecmp_open_body {
	uint32_t	rights;		/* request: wanted; reply: granted */
	uint16_t	name_length;	/* includes trailing NUL (request only) */
	uint16_t	reserved;
};

struct devicecmp_hello_reply {
	uint32_t	version;
	uint32_t	reserved[3];
};

_Static_assert(sizeof(struct devicecmp_msg) == 16,
    "devicecmp message header ABI");
_Static_assert(sizeof(struct devicecmp_open_body) == 8,
    "devicecmp open body ABI");

#endif /* _DEVICECMP_PROTOCOL_H_ */

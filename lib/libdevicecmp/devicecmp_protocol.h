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
	DEVICECMP_OP_OPEN,	/* open a named /dev node; reply delivers the fd */
	DEVICECMP_OP_LIST	/* enumerate the caller-label's openable devices */
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

/*
 * LIST: enumerate the devices the CALLER'S LABEL is permitted to open, so a
 * consumer can discover its openable device set without blind trial-and-error.
 * The request carries an optional pagination cursor (0 for the first page; a
 * prior reply's next_cursor otherwise); flags/reserved are additive fields that
 * must be zero.  The reply is data-only (no fd delivered): a page of at most
 * DEVICECMP_LIST_MAX entries, each carrying a device leaf name, the policy
 * maximum rights mask for (this label, this device), and a flag word noting
 * whether a per-device ioctl whitelist further narrows a delivered CAP_IOCTL fd.
 * next_cursor is 0 on the final page, otherwise the cursor to re-issue with.
 *
 * Owner-scoping is the hard invariant: the walk is filtered on the connecting
 * channel's unforgeable label, never a wire argument, so a caller can only ever
 * observe entries whose policy label equals its own.  Default-deny is preserved:
 * a label with no policy entry lists empty (count 0), not an error.
 */
#define	DEVICECMP_LIST_MAX		32	/* device entries per reply page */

#define	DEVICECMP_LIST_FLAG_IOCTL_WHITELIST	0x0001U	/* ioctl whitelist applies */

struct devicecmp_list_request {
	uint32_t	cursor;		/* 0 = first page; else a prior next_cursor */
	uint32_t	flags;		/* reserved; must be 0 */
	uint32_t	reserved[2];	/* must be 0 */
};

/* One enumerated device: its /dev leaf plus the policy-max rights and flags. */
struct devicecmp_list_entry {
	char		name[DEVICECMP_MAX_NAME];	/* leaf, NUL-terminated */
	uint32_t	rights;		/* policy-max DEVICECMP_RIGHT_* mask */
	uint32_t	flags;		/* DEVICECMP_LIST_FLAG_* */
};

struct devicecmp_list_reply {
	uint32_t	count;		/* entries filled in this page */
	uint32_t	next_cursor;	/* 0 = last page; else pass back as cursor */
	uint32_t	reserved[2];
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
};

_Static_assert(sizeof(struct devicecmp_msg) == 16,
    "devicecmp message header ABI");
_Static_assert(sizeof(struct devicecmp_open_body) == 8,
    "devicecmp open body ABI");
_Static_assert(sizeof(struct devicecmp_list_request) == 16,
    "devicecmp list request ABI");
_Static_assert(sizeof(struct devicecmp_list_entry) == DEVICECMP_MAX_NAME + 8,
    "devicecmp list entry ABI");
_Static_assert(sizeof(struct devicecmp_list_reply) ==
    16 + DEVICECMP_LIST_MAX * (DEVICECMP_MAX_NAME + 8),
    "devicecmp list reply ABI");

#endif /* _DEVICECMP_PROTOCOL_H_ */

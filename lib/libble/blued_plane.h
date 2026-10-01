/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The plane hand-off between a libble client and blued(8): the wire contract
 * spoken over the system.Bluetooth service channel.  A client that opens the
 * name over the capability plane arrives with a kernel-stamped identity
 * (bundle label, container); it sends one ATTACH request and receives one
 * end of a stream socketpair, over which it then speaks the ordinary framed
 * control protocol (ipc_proto.h).  blued keeps the other end as a control
 * client that knows which bundle it serves, so the GATT services that client
 * registers are attributed to the bundle and reclaimed once it is gone
 * (docs/book/src/plane/containers-and-storage.md).
 *
 * Private, shared source contract between libble and blued -- not installed.
 */
#ifndef _BLUED_PLANE_H_
#define	_BLUED_PLANE_H_

#include <stddef.h>
#include <stdint.h>

#define	BLUED_PLANE_SERVICE	"system.Bluetooth"
#define	BLUED_PLANE_MAGIC	0x424c5545u	/* 'BLUE' */
#define	BLUED_PLANE_OP_ATTACH	1u	/* reply: status 0 + the socket end */

/*
 * A private contract built from one source tree: the magic, the message
 * length and the descriptor count are the whole shape check, and a message
 * that fails any of them is refused with EPROTO.
 */
struct blued_plane_msg {
	uint32_t	magic;
	uint32_t	opcode;
	int32_t		status;		/* reply: 0, or errno */
};

/*
 * The message length is one of the three shape checks, so a silent layout
 * change here would be refused at runtime as EPROTO rather than diagnosed.
 * Pin the shape at compile time in both ends instead.
 */
_Static_assert(sizeof(struct blued_plane_msg) == 12,
    "struct blued_plane_msg size changed: the plane attach wire moved");
_Static_assert(offsetof(struct blued_plane_msg, magic) == 0,
    "struct blued_plane_msg layout changed: magic must lead");
_Static_assert(offsetof(struct blued_plane_msg, opcode) == 4,
    "struct blued_plane_msg layout changed");
_Static_assert(offsetof(struct blued_plane_msg, status) == 8,
    "struct blued_plane_msg layout changed");

#endif /* !_BLUED_PLANE_H_ */

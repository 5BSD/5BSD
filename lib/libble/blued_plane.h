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

#include <stdint.h>

#define	BLUED_PLANE_SERVICE	"system.Bluetooth"
#define	BLUED_PLANE_MAGIC	0x424c5545u	/* 'BLUE' */
#define	BLUED_PLANE_VERSION	1u
#define	BLUED_PLANE_OP_ATTACH	1u	/* reply: status 0 + the socket end */

struct blued_plane_msg {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	opcode;
	int32_t		status;		/* reply: 0, or errno */
};

#endif /* !_BLUED_PLANE_H_ */

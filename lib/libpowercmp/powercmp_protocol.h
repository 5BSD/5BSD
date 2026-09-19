/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * system.Power wire protocol.  A client holds a system.Power channel and asks
 * the broker for the supported ACPI sleep states (STATES, unprivileged) or, when
 * the per-label policy permits, to enter one (SUSPEND -- privileged, needs
 * PRIV to drive /dev/acpi).  Fixed-size messages.
 */
#ifndef _POWERCMP_PROTOCOL_H_
#define	_POWERCMP_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#define	POWERCMP_INTERFACE		"system.Power"
#define	POWERCMP_INTERFACE_VERSION	"1.0.0"
#define	POWERCMP_MAGIC			0x50575200U	/* "PWR\0" */
#define	POWERCMP_ABI_VERSION		1

enum powercmp_opcode {
	POWERCMP_OP_HELLO = 1,
	POWERCMP_OP_STATES,	/* reply: supported S-state bitmask (unpriv) */
	POWERCMP_OP_SUSPEND	/* request: enter S-state N -- privileged */
};

enum powercmp_message_role {
	POWERCMP_MESSAGE_REQUEST = 1,
	POWERCMP_MESSAGE_REPLY
};

struct powercmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;		/* reply: 0 or -errno */
};

/*
 * Fixed body.  SUSPEND request sets `state` (the S-state number, 1..5).
 * STATES reply sets `supported`, a bitmask where bit N means SN is supported
 * (e.g. (1<<3)|(1<<4)|(1<<5) for "S3 S4 S5").
 */
struct powercmp_body {
	uint32_t	state;
	uint32_t	supported;
	uint32_t	reserved[2];
};

#define	POWERCMP_MAX_MESSAGE	(sizeof(struct powercmp_msg) + \
				 sizeof(struct powercmp_body))

_Static_assert(sizeof(struct powercmp_msg) == 16, "powercmp header ABI");
_Static_assert(sizeof(struct powercmp_body) == 16, "powercmp body ABI");

int	powercmp_validate_message(const struct powercmp_msg *, size_t length,
	    enum powercmp_message_role);

#endif /* _POWERCMP_PROTOCOL_H_ */

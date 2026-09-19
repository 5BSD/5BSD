/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * system.Time wire protocol.  A client holds a system.Time channel and asks the
 * broker to read CLOCK_REALTIME (unprivileged, allowed to any holder) or, when
 * the per-label policy permits, to STEP it (clock_settime) or SLEW it (adjtime)
 * -- the two privileged operations.  Fixed-size messages; no variable payload.
 */
#ifndef _TIMECMP_PROTOCOL_H_
#define	_TIMECMP_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#define	TIMECMP_INTERFACE		"system.Time"
#define	TIMECMP_INTERFACE_VERSION	"1.0.0"
#define	TIMECMP_MAGIC			0x54494d45U	/* "TIME" */
#define	TIMECMP_ABI_VERSION		1

enum timecmp_opcode {
	TIMECMP_OP_HELLO = 1,
	TIMECMP_OP_GET,		/* read CLOCK_REALTIME (reply: timecmp_time) */
	TIMECMP_OP_SET,		/* clock_settime(CLOCK_REALTIME) -- privileged */
	TIMECMP_OP_ADJUST	/* adjtime() slew -- privileged; reply: old delta */
};

enum timecmp_message_role {
	TIMECMP_MESSAGE_REQUEST = 1,
	TIMECMP_MESSAGE_REPLY
};

struct timecmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;		/* reply: 0 or -errno */
};

/*
 * A time value.  For GET (reply) and SET (request) it is an absolute
 * CLOCK_REALTIME point: sec + nsec, nsec in [0, 999999999].  For ADJUST it is a
 * signed slew delta expressed the same way (sec carries the sign; nsec is the
 * sub-second magnitude, 0..999999999), matching adjtime(2)'s timeval once
 * scaled.  `present` is 1 when the body carries a value (0 for a bare request
 * such as GET, or an ADJUST reply with no prior correction pending).
 */
struct timecmp_time {
	int64_t		sec;
	int32_t		nsec;
	uint32_t	present;
};

struct timecmp_hello_reply {
	uint32_t	version;
	uint32_t	reserved[3];
};

/* A message is the header, optionally followed by exactly one timecmp_time. */
#define	TIMECMP_MAX_MESSAGE	(sizeof(struct timecmp_msg) + \
				 sizeof(struct timecmp_time))

_Static_assert(sizeof(struct timecmp_msg) == 16, "timecmp header ABI");
_Static_assert(sizeof(struct timecmp_time) == 16, "timecmp time ABI");

/*
 * Validate a received message of the given role: magic, version, a known
 * opcode, and a length that is either the bare header or header + one
 * timecmp_time.  Returns 0 if well-formed, -1 otherwise.  Shared by the client
 * and the BSDTime daemon (both link libtimecmp).
 */
int	timecmp_validate_message(const struct timecmp_msg *, size_t length,
	    enum timecmp_message_role);

#endif /* _TIMECMP_PROTOCOL_H_ */

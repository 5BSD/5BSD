/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYSCTLCMP_PROTOCOL_H_
#define	_SYSCTLCMP_PROTOCOL_H_

#include <stdint.h>

#define	SYSCTLCMP_INTERFACE		"system.Sysctl"
#define	SYSCTLCMP_INTERFACE_VERSION	"1.0.0"
#define	SYSCTLCMP_MAGIC			0x53435450U	/* "SCTP" */
#define	SYSCTLCMP_ABI_VERSION		1

#define	SYSCTLCMP_MAX_NAME		256
#define	SYSCTLCMP_MAX_VALUE		8192
#define	SYSCTLCMP_MAX_MESSAGE		(sizeof(struct sysctlcmp_msg) + \
					 sizeof(struct sysctlcmp_body) + \
					 SYSCTLCMP_MAX_NAME + SYSCTLCMP_MAX_VALUE)

enum sysctlcmp_opcode {
	SYSCTLCMP_OP_HELLO = 1,
	SYSCTLCMP_OP_GET,	/* read raw value by name */
	SYSCTLCMP_OP_SET,	/* write raw value by name */
	SYSCTLCMP_OP_OIDFMT,	/* type/flags: reply = u32 kind + format string */
	SYSCTLCMP_OP_DESCR,	/* description string (sysctl -d) */
	SYSCTLCMP_OP_NEXT	/* enumeration: reply = next permitted name */
};

/*
 * OIDFMT reply value layout: a uint32_t "kind" (CTLTYPE in the low bits,
 * CTLFLAG_* in the high bits, exactly as sysctl(9) oidfmt reports) followed by
 * the NUL-terminated printf-style format string.
 */
struct sysctlcmp_oidfmt {
	uint32_t	kind;
	char		fmt[];
};

enum sysctlcmp_message_role {
	SYSCTLCMP_MESSAGE_REQUEST = 1,
	SYSCTLCMP_MESSAGE_REPLY
};

struct sysctlcmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;		/* reply: 0 or -errno */
};

/*
 * Body immediately follows the header.  name[] then value[] are variable-length
 * and packed after this struct in that order (name_length + value_length bytes).
 * For a GET request value_length is 0; the reply carries value_length bytes.
 * For a SET request value_length carries the new value; the reply is empty.
 */
struct sysctlcmp_body {
	uint16_t	name_length;	/* includes trailing NUL */
	uint16_t	reserved;
	uint32_t	value_length;
};

struct sysctlcmp_hello_reply {
	uint32_t	version;
	uint32_t	reserved[3];
};

_Static_assert(sizeof(struct sysctlcmp_msg) == 16,
    "sysctlcmp message header ABI");
_Static_assert(sizeof(struct sysctlcmp_body) == 8,
    "sysctlcmp body ABI");

#endif

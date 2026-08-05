/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _REBOOTCTL_PROTOCOL_H_
#define	_REBOOTCTL_PROTOCOL_H_

#include <sys/reboot.h>

#include <stdint.h>

#define	REBOOTCTL_INTERFACE		"org.5bsd.system.reboot"
#define	REBOOTCTL_INTERFACE_VERSION	"1.0.0"
#define	REBOOTCTL_MAGIC			0x52425443U	/* "RBTC" */
#define	REBOOTCTL_ABI_VERSION		3
#define	REBOOTCTL_MAX_MESSAGE		160
#define	REBOOTCTL_DEFAULT_DELAY_MS	10000U
#define	REBOOTCTL_MAX_DELAY_MS		86400000U
#define	REBOOTCTL_IMMINENT_MS		1000U
#define	REBOOTCTL_ALLOWED_FLAGS		(RB_HALT | RB_POWEROFF | RB_REROOT)

enum rebootctl_opcode {
	REBOOTCTL_OP_REBOOT = 1,
	REBOOTCTL_OP_SHUTDOWN,
	REBOOTCTL_OP_STATUS,
	REBOOTCTL_OP_CANCEL
};

struct rebootctl_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct rebootctl_msg) == 16, "rebootctl header ABI");

struct rebootctl_request {
	uint32_t howto;
	uint32_t delay_ms;
};

struct rebootctl_status_reply {
	uint32_t pending;
	uint32_t howto;
	uint64_t request_id;
	uint64_t requested_at_ns;
	uint64_t execute_at_ns;
};

#define	REBOOTCTL_NOTIFY_REQUESTED	"system.shutdown.requested"
#define	REBOOTCTL_NOTIFY_SCHEDULED	"system.shutdown.scheduled"
#define	REBOOTCTL_NOTIFY_IMMINENT	"system.shutdown.imminent"
#define	REBOOTCTL_NOTIFY_CANCELLED	"system.shutdown.cancelled"

enum rebootctl_notification_state {
	REBOOTCTL_NOTIFICATION_REQUESTED = 1,
	REBOOTCTL_NOTIFICATION_SCHEDULED,
	REBOOTCTL_NOTIFICATION_IMMINENT,
	REBOOTCTL_NOTIFICATION_CANCELLED
};

struct rebootctl_notification {
	uint32_t version;
	uint32_t state;
	uint64_t request_id;
	uint64_t requested_at_ns;
	uint64_t execute_at_ns;
	uint32_t remaining_ms;
	uint32_t howto;
	int32_t error;
	uint16_t requester_length;
	uint16_t reserved16;
	char requester[64];
};

_Static_assert(sizeof(struct rebootctl_notification) == 112,
    "reboot notification ABI");

#endif

/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NETWORK_STATE_PROTOCOL_H_
#define _NETWORK_STATE_PROTOCOL_H_
#include <stddef.h>

#include "network_state.h"
#define NETWORK_STATE_MAGIC UINT32_C(0x4e535431)
struct network_state_header {
	uint32_t magic;
	uint16_t version, opcode;
	int32_t status;
	uint32_t reserved;
};
struct network_state_request {
	struct network_state_header header;
	uint32_t timeout_ms, reserved;
};
struct network_state_reply {
	struct network_state_header header;
	struct network_state_snapshot state;
};
#define NETWORK_STATE_REPLY_SIZE(n)                               \
	(offsetof(struct network_state_reply, state.interfaces) + \
	    (n) * sizeof(struct network_state_interface))
_Static_assert(sizeof(struct network_state_header) == 16,
    "network state header ABI");
_Static_assert(sizeof(struct network_state_request) == 24,
    "network state request ABI");
_Static_assert(sizeof(struct network_state_interface) == 32,
    "network interface ABI");
_Static_assert(offsetof(struct network_state_snapshot, interfaces) == 24,
    "snapshot ABI");
int network_state_validate_request(const void *, size_t);
int network_state_validate_reply(const void *, size_t);
#endif

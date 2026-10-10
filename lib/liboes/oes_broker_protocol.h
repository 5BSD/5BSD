/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _OES_BROKER_PROTOCOL_H_
#define _OES_BROKER_PROTOCOL_H_

#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define OES_BROKER_ENDPOINT "system.OES"
#define OES_BROKER_ATTRIBUTE "system.oes"
#define OES_BROKER_MAGIC UINT32_C(0x4f455342)
#define OES_BROKER_VERSION 1
#define OES_BROKER_OPEN_NOTIFY 1

/* Native local IPC ABI. No request FDs; exactly one FD on successful reply. */
struct oes_broker_message {
	uint32_t magic;
	uint16_t version;
	uint16_t operation;
	int32_t status;
	uint32_t reserved;
};
_Static_assert(sizeof(struct oes_broker_message) == 16, "OES broker wire ABI");

/* Does not consume data or descriptors. Caller closes attachments on failure.
 * Copy first: channel payloads need not satisfy this structure's alignment. */
static inline int
oes_broker_validate(const void *data, size_t length, size_t nfds, bool reply)
{
	struct oes_broker_message message;

	if (data == NULL || length != sizeof(message))
		return (errno = EPROTO, -1);
	memcpy(&message, data, sizeof(message));
	if (message.magic != OES_BROKER_MAGIC ||
	    message.version != OES_BROKER_VERSION ||
	    message.operation != OES_BROKER_OPEN_NOTIFY ||
	    message.reserved != 0 || message.status < 0 || message.status > ELAST ||
	    (!reply && message.status != 0) ||
	    nfds != (size_t)(reply && message.status == 0 ? 1 : 0))
		return (errno = EPROTO, -1);
	return (0);
}
#endif

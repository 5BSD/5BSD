/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/reboot.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <rebootctl.h>

#include "rebootd_state.h"

static uint32_t
state_checksum(const struct rebootd_state_record *record)
{
	const uint8_t *bytes;
	uint32_t hash;
	size_t i;

	bytes = (const uint8_t *)record;
	hash = UINT32_C(2166136261);
	for (i = 0; i < sizeof(*record); i++) {
		if (i >= offsetof(struct rebootd_state_record, checksum) &&
		    i < offsetof(struct rebootd_state_record, checksum) +
		    sizeof(record->checksum))
			continue;
		hash = (hash ^ bytes[i]) * UINT32_C(16777619);
	}
	return (hash);
}

void
rebootd_state_seal(struct rebootd_state_record *record)
{

	record->magic = REBOOTD_STATE_MAGIC;
	record->version = REBOOTD_STATE_VERSION;
	record->size = sizeof(*record);
	record->checksum = 0;
	record->checksum = state_checksum(record);
}

bool
rebootd_state_valid(const struct rebootd_state_record *record)
{
	size_t length;

	if (record == NULL || record->magic != REBOOTD_STATE_MAGIC ||
	    record->version != REBOOTD_STATE_VERSION ||
	    record->size != sizeof(*record) ||
	    record->checksum != state_checksum(record) || record->active > 1)
		return (false);
	length = strnlen(record->requester, sizeof(record->requester));
	if (length != record->requester_length ||
	    (length < sizeof(record->requester) &&
	    memcmp(record->requester + length + 1,
	    (char[sizeof(record->requester)]){ 0 },
	    sizeof(record->requester) - length - 1) != 0))
		return (false);
	if (record->active == 0)
		return (record->request_id == 0 && record->requested_at_ns == 0 &&
		    record->execute_at_ns == 0 && record->howto == 0 &&
		    record->opcode == 0 && record->requester_length == 0);
	return (record->request_id != 0 &&
	    record->next_request_id >= record->request_id &&
	    record->requested_at_ns != 0 &&
	    record->execute_at_ns >= record->requested_at_ns &&
	    (record->howto & ~REBOOTCTL_ALLOWED_FLAGS) == 0 &&
	    (record->opcode == REBOOTCTL_OP_REBOOT ||
	    record->opcode == REBOOTCTL_OP_SHUTDOWN) &&
	    record->requester_length != 0);
}

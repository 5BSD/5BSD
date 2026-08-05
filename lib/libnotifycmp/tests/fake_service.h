/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _FAKE_SERVICE_H_
#define _FAKE_SERVICE_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

enum fake_service_fault {
	FAKE_SERVICE_FAULT_NONE,
	FAKE_SERVICE_FAULT_TIMEOUT,
	FAKE_SERVICE_FAULT_TRUNCATE,
	FAKE_SERVICE_FAULT_WRONG_OPCODE,
	FAKE_SERVICE_FAULT_ATTACHED_FD,
	FAKE_SERVICE_FAULT_STATUS,
	FAKE_SERVICE_FAULT_INVALID_HELLO,
	FAKE_SERVICE_FAULT_INVALID_STATE
};

void	fake_service_reset(void);
void	fake_service_fail_next(void);
void	fake_service_fail_opcode(uint16_t);
void	fake_service_fault_next(enum fake_service_fault);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_subscriptions(void);
unsigned fake_service_publishes(void);
unsigned fake_service_max_concurrent(void);
ssize_t	fake_service_last_payload(void *, size_t);

#endif

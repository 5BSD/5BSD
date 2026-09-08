/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _CRYPTOCMP_FAKE_SERVICE_H_
#define _CRYPTOCMP_FAKE_SERVICE_H_

enum fake_service_fault {
	FAKE_SERVICE_FAULT_NONE,
	FAKE_SERVICE_FAULT_CALL,
	FAKE_SERVICE_FAULT_TRUNCATE,
	FAKE_SERVICE_FAULT_WRONG_MAGIC,
	FAKE_SERVICE_FAULT_WRONG_VERSION,
	FAKE_SERVICE_FAULT_WRONG_OPCODE,
	FAKE_SERVICE_FAULT_POSITIVE_STATUS,
	FAKE_SERVICE_FAULT_INVALID_STATUS,
	FAKE_SERVICE_FAULT_MISSING_FD,
	FAKE_SERVICE_FAULT_UNEXPECTED_FD,
	FAKE_SERVICE_FAULT_NAMED_GENERATION,
	FAKE_SERVICE_FAULT_STAT_GENERATION,
	FAKE_SERVICE_FAULT_STAT_RIGHTS,
	FAKE_SERVICE_FAULT_LIST_CURSOR,
	FAKE_SERVICE_FAULT_LIST_NAME,
	FAKE_SERVICE_FAULT_LIST_GENERATION,
	FAKE_SERVICE_FAULT_LIST_RIGHTS,
	FAKE_SERVICE_FAULT_LIST_PAD,
};

void	 fake_service_reset(void);
void	 fake_service_fault_next(enum fake_service_fault);
void	 fake_service_status_next(int);
int	 fake_service_last_fd(void);
unsigned fake_service_calls(void);
unsigned fake_service_closed(void);
unsigned fake_service_created(void);
unsigned fake_service_failed(void);

#endif

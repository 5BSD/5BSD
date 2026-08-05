/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _LOGCMP_FAKE_SERVICE_H_
#define _LOGCMP_FAKE_SERVICE_H_

#include <sys/types.h>

#include <stdint.h>

enum fake_service_fault {
	FAKE_SERVICE_FAULT_NONE,
	FAKE_SERVICE_FAULT_DELAY,
	FAKE_SERVICE_FAULT_TIMEOUT,
	FAKE_SERVICE_FAULT_TRUNCATE,
	FAKE_SERVICE_FAULT_WRONG_OPCODE,
	FAKE_SERVICE_FAULT_ATTACHED_FD,
	FAKE_SERVICE_FAULT_STATUS,
	FAKE_SERVICE_FAULT_INVALID_HELLO
};

void	fake_service_reset(void);
void	fake_service_fail_write(void);
void	fake_service_fail_write_with(int);
void	fake_service_fail_attach_with(int);
void	fake_service_fail_operation(uint16_t, int);
void	fake_service_corrupt_next_ring(void);
void	fake_service_break_next_wakeup(void);
void	fake_service_fault_next(enum fake_service_fault);
void	fake_service_enable_ring(void);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_writes(void);
unsigned fake_service_max_concurrent(void);
unsigned fake_service_loss_records(void);
unsigned fake_service_attaches(void);
unsigned fake_service_detaches(void);
size_t fake_service_ring_capacity(void);
uint32_t fake_service_ring_shape(void);
uint64_t fake_service_last_loss_count(void);

#endif

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _CRYPTOCMP_FAKE_SERVICE_H_
#define _CRYPTOCMP_FAKE_SERVICE_H_

enum fake_service_fault {
	FAKE_SERVICE_FAULT_NONE,
	FAKE_SERVICE_FAULT_CALL,		/* close instead of replying */
	FAKE_SERVICE_FAULT_ZERO_ERRNO,		/* error 0 is not an errno */
	FAKE_SERVICE_FAULT_RANGE_ERRNO,		/* error > ELAST */
	FAKE_SERVICE_FAULT_FUTURE_VERSION,	/* wire version 2 */
	FAKE_SERVICE_FAULT_LEASE_GENERATION,	/* lease with generation 0 */
	FAKE_SERVICE_FAULT_NAMED_GENERATION,
	FAKE_SERVICE_FAULT_STAT_GENERATION,
	FAKE_SERVICE_FAULT_STAT_RIGHTS,
	FAKE_SERVICE_FAULT_LIST_CURSOR,
	FAKE_SERVICE_FAULT_LIST_NAME,
	FAKE_SERVICE_FAULT_LIST_GENERATION,
	FAKE_SERVICE_FAULT_LIST_RIGHTS,
	FAKE_SERVICE_FAULT_RANDOM_SIZE,
};

void	 fake_service_reset(void);
void	 fake_service_fault_next(enum fake_service_fault);
void	 fake_service_status_next(int);
/* The read end of a pipe whose write end the last lease delivered. */
int	 fake_service_last_fd(void);
unsigned fake_service_calls(void);
unsigned fake_service_closed(void);
unsigned fake_service_created(void);

#endif

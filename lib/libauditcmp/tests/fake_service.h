/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUDITCMP_TEST_FAKE_SERVICE_H_
#define _AUDITCMP_TEST_FAKE_SERVICE_H_

enum fake_reply_mode {
	FAKE_REPLY_NORMAL,
	FAKE_REPLY_STATUS,		/* Submit fails EPERM */
	FAKE_REPLY_ZERO_ERRNO,		/* Submit error 0 (not an errno) */
	FAKE_REPLY_RANGE_ERRNO,		/* Submit error > ELAST */
	FAKE_REPLY_FUTURE_VERSION	/* wire version 2 */
};

void	 fake_service_reset(void);
/* ETIMEDOUT: leave the next call unanswered; other values: close instead. */
void	 fake_service_fail_next(int);
void	 fake_service_fail_connect_next(int);
void	 fake_service_reply_mode(enum fake_reply_mode);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_submitted(void);

#endif

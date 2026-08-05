/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _AUDITCMP_TEST_FAKE_SERVICE_H_
#define _AUDITCMP_TEST_FAKE_SERVICE_H_

enum fake_reply_mode {
	FAKE_REPLY_NORMAL,
	FAKE_REPLY_BAD_OPCODE,
	FAKE_REPLY_UNEXPECTED_FD,
	FAKE_REPLY_BAD_STATS,
	FAKE_REPLY_TRUNCATED,
	FAKE_REPLY_STATUS,
	FAKE_REPLY_BAD_HELLO
};

void	 fake_service_reset(void);
void	 fake_service_fail_next(int);
void	 fake_service_fail_connect_next(int);
void	 fake_service_reply_mode(enum fake_reply_mode);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_max_concurrent(void);

#endif

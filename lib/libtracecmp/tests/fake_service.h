/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TRACECMP_FAKE_SERVICE_H_
#define _TRACECMP_FAKE_SERVICE_H_
/* Provider counters the fake service reports in a STATS reply. */
#define	FAKE_STATS_OPENED	7
#define	FAKE_STATS_REJECTED	3
enum fake_reply_mode { FAKE_REPLY_NORMAL, FAKE_REPLY_NO_FEATURE,
    FAKE_REPLY_BAD_OPCODE, FAKE_REPLY_MISSING_FD,
    FAKE_REPLY_UNEXPECTED_HELLO_FD, FAKE_REPLY_BAD_MAGIC,
    FAKE_REPLY_BAD_VERSION, FAKE_REPLY_BAD_FLAGS,
    FAKE_REPLY_BAD_HELLO_RESERVED };
void fake_service_reset(void);
void fake_service_fail_connect(int);
void fake_service_fail_call(int);
void fake_service_reply_mode(enum fake_reply_mode);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_max_concurrent(void);
#endif

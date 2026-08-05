/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _KLDMGR_FAKE_SERVICE_H_
#define _KLDMGR_FAKE_SERVICE_H_
enum fake_reply_mode { FAKE_REPLY_NORMAL, FAKE_REPLY_BAD_OPCODE,
    FAKE_REPLY_UNEXPECTED_FD, FAKE_REPLY_TRUNCATED, FAKE_REPLY_STATUS,
    FAKE_REPLY_BAD_MAGIC, FAKE_REPLY_BAD_VERSION, FAKE_REPLY_BAD_FLAGS,
    FAKE_REPLY_BAD_STATUS, FAKE_REPLY_ERROR_PAYLOAD, FAKE_REPLY_BAD_ID,
    FAKE_REPLY_BAD_ID_RESERVED, FAKE_REPLY_BAD_LIST_COUNT,
    FAKE_REPLY_BAD_LIST_RESERVED, FAKE_REPLY_BAD_LIST_ID,
    FAKE_REPLY_BAD_LIST_NAME };
void fake_service_reset(void);
void fake_service_fail_next(int);
void fake_service_fail_connect_next(int);
void fake_service_reply_mode(enum fake_reply_mode);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_max_concurrent(void);
unsigned fake_service_nonzero_name_tail(void);
#endif

/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FILESYSTEMCMP_FAKE_SERVICE_H_
#define _FILESYSTEMCMP_FAKE_SERVICE_H_
void fake_service_reset(void);
void fake_service_fail(int);
void fake_service_malformed_reply(void);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_calls(void);
unsigned fake_service_max_concurrent(void);
#endif

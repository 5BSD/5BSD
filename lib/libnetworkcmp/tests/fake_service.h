/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NETWORKCMP_FAKE_SERVICE_H_
#define _NETWORKCMP_FAKE_SERVICE_H_
void fake_service_reset(void);
void fake_service_fail(int);
void fake_service_malformed_reply(void);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_calls(void);
unsigned fake_service_max_concurrent(void);
#endif

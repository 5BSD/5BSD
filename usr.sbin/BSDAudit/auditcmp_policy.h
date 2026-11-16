/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _AUDITCMP_POLICY_H_
#define	_AUDITCMP_POLICY_H_

int	auditcmp_policy_event(const char *);
int	auditcmp_policy_operation_event(const char *, const char *, int);

#endif

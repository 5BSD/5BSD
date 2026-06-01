/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Private header shared between cap_rt_*.c files in oracled.
 * Not for external use.
 */

#ifndef CAP_RT_PRIV_H
#define CAP_RT_PRIV_H

#include "oracled.h"

/* Service fd variables (defined in cap_rt_setup.c). */
extern int	cap_rt_fd;
extern int	cap_rt_isolation_fd;
extern int	cap_rt_system_fd;
extern int	cap_rt_capprotect_fd;

/* Internal helpers used by multiple cap_rt_*.c files. */
int	cap_rt_svc_connect(const char *name);
int	cap_rt_do_call(int fd, const void *req, size_t reqlen,
	    void *reply, size_t replylen);

/* Claims lifecycle (cap_rt_claims.c), called from cap_rt_setup.c. */
int	isolate_resources(void);
int	apply_integrity(void);
int	claim_system_gates(void);

#endif /* CAP_RT_PRIV_H */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libpowercmp: client to system.Power (BSDPower).  Query supported ACPI sleep
 * states, and -- policy permitting -- request the machine enter one.
 */
#ifndef _POWERCMP_H_
#define	_POWERCMP_H_

#include "powercmp_protocol.h"

struct powercmp_client;

__BEGIN_DECLS

int	powercmp_client_open(struct powercmp_client **);
void	powercmp_client_close(struct powercmp_client *);

/* Supported sleep states as a bitmask (bit N => SN); reads are unprivileged. */
int	powercmp_states(struct powercmp_client *, uint32_t *supported);

/*
 * Request the machine enter sleep state `state` (1..5).  Fails EPERM if the
 * caller's label is not granted suspend authority by the provider policy.
 */
int	powercmp_suspend(struct powercmp_client *, uint32_t state);

__END_DECLS

#endif /* _POWERCMP_H_ */

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

/* bsd.power.v1 (powercmp.fidl) wire major, checked on a session's first call. */
#define POWERCMP_WIRE_VERSION 1

struct powercmp_client;

__BEGIN_DECLS

/* Adopt a held native channel; consumes fd only on success.
 * Version negotiation occurs on the first operation within its deadline. */
int	powercmp_client_create(int fd, struct powercmp_client **);

int	powercmp_client_open(struct powercmp_client **);
void	powercmp_client_close(struct powercmp_client *);

/* Supported sleep states as a bitmask (bit N => SN); reads are unprivileged. */
int	powercmp_states(struct powercmp_client *, uint32_t *supported);

/*
 * Request the machine enter sleep state `state` (1..5).  Fails EPERM if the
 * caller's label is not granted suspend authority by the provider policy.
 */
int	powercmp_suspend(struct powercmp_client *, uint32_t state);

/* One inhibitor per client session; separately policy-gated. EALREADY on
 * duplicate acquisition, ENOENT on release without a lease. Disconnect,
 * client close, or provider death revokes it. No automatic reacquisition.
 * Transport/protocol failure closes the session and makes the handle terminal;
 * free it with powercmp_client_close(). Policy errors preserve the session.
 * Calls require external serialization, as do other powercmp operations. */
int powercmp_inhibit(struct powercmp_client *);
int powercmp_uninhibit(struct powercmp_client *);
int powercmp_inhibitors(struct powercmp_client *, uint32_t *);
__END_DECLS

#endif /* _POWERCMP_H_ */

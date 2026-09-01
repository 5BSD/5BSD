/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for sysextd(8) — the system-extension broker.
 *
 * sysextd owns kernel-module (kernel "system extension") loading, taking it out
 * of PID 1.  It is a socket-free service_provider: clients reach it over a held
 * mac_capability channel obtained by name (service_open(system.SystemExtension))
 * and ask it to ensure a named extension is loaded.  Access is gated by the
 * domain layer — system.SystemExtension resolves only for SYSTEM-domain clients,
 * so a user service can never load kernel code.  sysextd itself holds the
 * SYS_GATE_KLDLOAD/SYS_GATE_KLDSTAT system-capability gates (declared in its
 * manifest) and claims them around each modfind/kldload.
 */

#ifndef SYSEXT_PROTO_H
#define SYSEXT_PROTO_H

#include <stdint.h>

#define	SYSEXT_SERVICE_NAME	"system.SystemExtension"

/* A module name is a single, safe filename component. */
#define	SYSEXT_NAME_MAX		64	/* module name incl. NUL */

#define	SYSEXT_OP_ENSURE	1	/* ensure a named extension is loaded */

struct sysext_request {
	uint32_t	op;			/* SYSEXT_OP_ENSURE */
	uint32_t	_reserved;
	char		name[SYSEXT_NAME_MAX];	/* kernel module name */
};

struct sysext_reply {
	int32_t		status;			/* 0, or errno */
	uint32_t	_reserved;
};

#endif /* SYSEXT_PROTO_H */

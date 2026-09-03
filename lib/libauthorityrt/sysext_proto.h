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
 * and ask it either to ensure a named extension is loaded (SYSEXT_OP_ENSURE) or
 * to query whether one is loaded without attempting a load (SYSEXT_OP_STAT).
 * Access is gated by the domain layer — system.SystemExtension resolves only for
 * SYSTEM-domain clients, so a user service can never load kernel code.  sysextd
 * itself holds the SYS_GATE_KLDLOAD/SYS_GATE_KLDSTAT system-capability gates
 * (declared in its manifest): the kldload gate authorizes ENSURE's kldload(2),
 * and the kldstat gate authorizes STAT's kldfind(2) query.
 *
 * There is deliberately no UNLOAD operation.  Unloading a module safely needs
 * per-consumer refcounting / ownership that this broker does not track, so an
 * unload requested by one SYSTEM client could pull kernel code out from under
 * another.  Module removal stays out of the broker.
 */

#ifndef SYSEXT_PROTO_H
#define SYSEXT_PROTO_H

#include <stdint.h>

#define	SYSEXT_SERVICE_NAME	"system.SystemExtension"

/* A module name is a single, safe filename component. */
#define	SYSEXT_NAME_MAX		64	/* module name incl. NUL */

#define	SYSEXT_OP_ENSURE	1	/* ensure a named extension is loaded */
#define	SYSEXT_OP_STAT		2	/* query whether an extension is loaded */

struct sysext_request {
	uint32_t	op;			/* SYSEXT_OP_ENSURE or _STAT */
	uint32_t	_reserved;
	char		name[SYSEXT_NAME_MAX];	/* kernel module name */
};

struct sysext_reply {
	int32_t		status;			/* 0, or errno */
	uint32_t	_reserved;
};

/*
 * Reply to SYSEXT_OP_STAT.  Same wire size as sysext_reply so the framing is
 * identical, but the second word carries the loaded state instead of a reserved
 * pad.  status is 0 for a completed query (then loaded is authoritative) or an
 * errno for a real failure (a denied name is EPERM, exactly as ENSURE, so a
 * non-allow-listed module leaks no loaded/not-loaded information).
 */
struct sysext_stat_reply {
	int32_t		status;			/* 0 on a completed query, or errno */
	int32_t		loaded;			/* 1 if loaded, 0 if not */
};

#endif /* SYSEXT_PROTO_H */

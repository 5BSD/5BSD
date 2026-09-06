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
 * itself holds the SYS_GATE_KLDLOAD system-capability gate (declared in its
 * manifest), which authorizes ENSURE's kldload(2).  STAT's kldfind(2) query is
 * read-only and ungated — module enumeration is deliberately open.
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
#define	SYSEXT_OP_LIST		3	/* enumerate the allow-listed module names */

/*
 * Wire cap on the number of module names a single SYSEXT_OP_LIST reply carries.
 * It bounds the reply and MUST be >= the daemon's allow-list capacity
 * (SYSEXT_MAX_ALLOW in sysextd.h) so the whole allow-list fits in one reply; the
 * daemon _Static_asserts that relationship.  The allow-list is small and fixed,
 * so LIST is a single, bounded, unpaged reply.
 */
#define	SYSEXT_LIST_MAX		32	/* max names in a LIST reply */

struct sysext_request {
	uint32_t	op;			/* SYSEXT_OP_ENSURE, _STAT or _LIST */
	uint32_t	_reserved;
	char		name[SYSEXT_NAME_MAX];	/* kernel module name (unused by LIST) */
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

/*
 * Reply to SYSEXT_OP_LIST: the set of module names the allow-list permits, so a
 * consumer can discover what it may ENSURE without STAT-probing names blindly.
 * The allow-list is global (not per-label), so every SYSTEM-domain caller sees
 * the same set; LIST is data-only (no descriptor) and reveals only which module
 * NAMES may load, never any loaded/not-loaded state.  status is 0 on success
 * (then count/names are authoritative) or an errno.  count <= SYSEXT_LIST_MAX;
 * each names[i] is a NUL-terminated single-component module name.  This reply's
 * wire size is deliberately distinct from sysext_reply / sysext_stat_reply.
 */
struct sysext_list_reply {
	int32_t		status;			/* 0, or errno */
	uint32_t	count;			/* number of names in names[] */
	char		names[SYSEXT_LIST_MAX][SYSEXT_NAME_MAX];
};

#endif /* SYSEXT_PROTO_H */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for bsdextension(8) — the system-extension broker.
 *
 * bsdextension owns kernel-module (kernel "system extension") loading, taking it out
 * of PID 1.  It is a socket-free service_provider: clients reach it over a held
 * mac_capability channel obtained by name (service_open(system.SystemExtension))
 * and ask it either to ensure a named extension is loaded (SYSEXT_OP_ENSURE) or
 * to query whether one is loaded without attempting a load (SYSEXT_OP_STAT).
 * Access is gated by the domain layer — system.SystemExtension resolves only for
 * SYSTEM-domain clients, so a user service can never load kernel code.  bsdextension
 * itself holds the SYS_GATE_KLDLOAD system-capability gate (declared in its
 * manifest), which authorizes ENSURE's kldload(2).  STAT's kldfind(2) query is
 * read-only and ungated — module enumeration is deliberately open.
 *
 * Persistent policy operations require ADMIN.  Disabling activation changes
 * the next boot; it never forcibly unloads shared kernel code.  NEXT provides
 * bounded discovery using an exclusive lexical name cursor (empty starts).
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
#define	SYSEXT_OP_RELOAD		4	/* admin: reload the configured policy file */

#define SYSEXT_OP_ALLOW 5
#define SYSEXT_OP_DENY 6
#define SYSEXT_OP_RESET 7
#define SYSEXT_OP_ENABLE 8
#define SYSEXT_OP_DISABLE 9
#define SYSEXT_OP_RESTORE 10
#define SYSEXT_OP_INFO 11
#define SYSEXT_OP_NEXT 12

#define SYSEXT_STATE_ALLOWED 0x01
#define SYSEXT_STATE_ENABLED 0x02
#define SYSEXT_STATE_LOADED 0x04
#define SYSEXT_STATE_OVERRIDE 0x08
#define SYSEXT_STATE_READY 0x10

struct sysext_info_reply {
    int32_t status;
    uint32_t flags;
    char name[SYSEXT_NAME_MAX];
};

/* LIST returns EOVERFLOW if the effective policy exceeds this cap. */
#define	SYSEXT_LIST_MAX		32	/* max names in a LIST reply */

struct sysext_request {
	uint32_t	op;			/* SYSEXT_OP_* */
	uint32_t	_reserved;
	char		name[SYSEXT_NAME_MAX];	/* module name or NEXT cursor */
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

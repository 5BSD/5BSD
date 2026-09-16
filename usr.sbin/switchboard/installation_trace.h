/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_IDENTITY_TRACE_H
#define SWITCHBOARD_IDENTITY_TRACE_H
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "switchboard_probes.h"

/* The per-unit resource-ownership id: 16 bytes, formatted as 32 hex chars. */
#define	SVC_IDENTITY_ID_SIZE	16

static inline bool
svc_identity_id_nonzero(const uint8_t *id)
{
	uint8_t any = 0;

	for (size_t i = 0; i < SVC_IDENTITY_ID_SIZE; i++)
		any |= id[i];
	return (any != 0);
}

static inline void
svc_identity_id_format(const uint8_t *id, char hex[33])
{
	static const char h[] = "0123456789abcdef";

	for (size_t i = 0; i < SVC_IDENTITY_ID_SIZE; i++) {
		hex[i * 2] = h[id[i] >> 4];
		hex[i * 2 + 1] = h[id[i] & 0x0f];
	}
	hex[32] = '\0';
}

/*
 * Trace a resource-ownership identity assignment (unit launch or client
 * session).  Observability only; no capability contents enter the trace, and
 * it is disabled unless SWITCHBOARD_TRACE_IDENTITY=1.
 */
static inline void
svc_trace_identity(const char *action, const char *label, const uint8_t *id,
    int error)
{
	char hex[33] = "-";
	const char *enabled;
	int saved = errno;

	if (id != NULL && svc_identity_id_nonzero(id))
		svc_identity_id_format(id, hex);
	SWITCHBOARD_PROBE_INSTALLATION(action, label, hex, 0, error);
	enabled = getenv("SWITCHBOARD_TRACE_IDENTITY");
	if (enabled != NULL && strcmp(enabled, "1") == 0)
		syslog(LOG_NOTICE, "identity action=%s label=%s id=%s error=%d",
		    action, label, hex, error);
	errno = saved;
}
#endif

/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_INSTALLATION_TRACE_H
#define SWITCHBOARD_INSTALLATION_TRACE_H
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "switchboard_lifecycle.h"
#include "switchboard_probes.h"

/* No package sources or capability contents enter the trace. Disabled by default. */
static inline void
svc_trace_installation(const char *action, const char *label,
    const uint8_t *generation, int state, int error)
{
	char identity[33] = "-";
	const char *enabled;
	int saved = errno;

	if (generation != NULL && sl_generation_valid(generation))
		sl_generation_format(generation, identity);
	SWITCHBOARD_PROBE_INSTALLATION(action, label, identity, state, error);
	enabled = getenv("SWITCHBOARD_TRACE_INSTALLATION");
	if (enabled != NULL && strcmp(enabled, "1") == 0)
		syslog(LOG_NOTICE, "installation action=%s label=%s id=%s state=%d error=%d",
		    action, label, identity, state, error);
	errno = saved;
}
#endif

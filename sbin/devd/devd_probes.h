/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef DEVD_PROBES_H
#define DEVD_PROBES_H


#ifdef WITH_DTRACE
#include <devd_provider.h>
#define DEVD_PROBE_ACTION(event, cmd) do { \
	if (DEVD_ACTION_ENABLED()) \
		DEVD_ACTION((char *)(uintptr_t)(event), (char *)(uintptr_t)(cmd)); \
} while (0)
#define TRACE_DEVD_EVENT__START(a0) do { \
	if (DEVD_EVENT_START_ENABLED()) \
		DEVD_EVENT_START((int)(a0)); \
} while (0)
#define TRACE_DEVD_EVENT__DONE(a0) do { \
	if (DEVD_EVENT_DONE_ENABLED()) \
		DEVD_EVENT_DONE((int)(a0)); \
} while (0)
#define TRACE_DEVD_RULE(a0, a1) do { \
	if (DEVD_RULE_ENABLED()) \
		DEVD_RULE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_DEVD_ACTION__START(a0) do { \
	if (DEVD_ACTION_START_ENABLED()) \
		DEVD_ACTION_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_DEVD_ACTION__DONE(a0, a1) do { \
	if (DEVD_ACTION_DONE_ENABLED()) \
		DEVD_ACTION_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_DEVD_CHILD(a0) do { \
	if (DEVD_CHILD_ENABLED()) \
		DEVD_CHILD((int)(a0)); \
} while (0)
#else
#define DEVD_PROBE_ACTION(event, cmd) do { } while (0)
#define TRACE_DEVD_EVENT__START(a0) do { } while (0)
#define TRACE_DEVD_EVENT__DONE(a0) do { } while (0)
#define TRACE_DEVD_RULE(a0, a1) do { } while (0)
#define TRACE_DEVD_ACTION__START(a0) do { } while (0)
#define TRACE_DEVD_ACTION__DONE(a0, a1) do { } while (0)
#define TRACE_DEVD_CHILD(a0) do { } while (0)
#endif

#endif /* DEVD_PROBES_H */

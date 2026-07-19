/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef MESHD_PROBES_H
#define	MESHD_PROBES_H

/*
 * DTrace/test probes for meshd's application socket surface.  No probe emits
 * key material or decrypted access payload bytes; arguments are observable
 * routing facts only.
 */

#if defined(MESHD_WITH_PROBE_TAP)

#include "blued_probe_tap.h"

#define	MESHD_PROBE_APP_CONNECT(fd)					\
	probe_tap_rec1("meshd:app:connect", NULL, (uint64_t)(fd))
#define	MESHD_PROBE_APP_DISCONNECT(fd)					\
	probe_tap_rec1("meshd:app:disconnect", NULL, (uint64_t)(fd))
#define	MESHD_PROBE_APP_REGISTER(fd, model, vendor)			\
	probe_tap_rec3("meshd:app:register", NULL, (uint64_t)(fd),	\
	    (uint64_t)(model), (uint64_t)(vendor))
#define	MESHD_PROBE_APP_EVENT_QUEUE(fd, opcode, count)			\
	probe_tap_rec3("meshd:app:event:queue", NULL, (uint64_t)(fd),	\
	    (uint64_t)(opcode), (uint64_t)(count))
#define	MESHD_PROBE_APP_EVENT_DROP(fd, dropped)				\
	probe_tap_rec2("meshd:app:event:drop", NULL, (uint64_t)(fd),	\
	    (uint64_t)(dropped))
#define	MESHD_PROBE_APP_EVENT_SEND(fd, opcode, len)			\
	probe_tap_rec3("meshd:app:event:send", NULL, (uint64_t)(fd),	\
	    (uint64_t)(opcode), (uint64_t)(len))

#elif defined(MESHD_DTRACE_PROBES)

#include <sys/sdt.h>

#define	MESHD_PROBE_APP_CONNECT(fd)					\
	DTRACE_PROBE1(meshd, app__connect, fd)
#define	MESHD_PROBE_APP_DISCONNECT(fd)					\
	DTRACE_PROBE1(meshd, app__disconnect, fd)
#define	MESHD_PROBE_APP_REGISTER(fd, model, vendor)			\
	DTRACE_PROBE3(meshd, app__register, fd, model, vendor)
#define	MESHD_PROBE_APP_EVENT_QUEUE(fd, opcode, count)			\
	DTRACE_PROBE3(meshd, app__event__queue, fd, opcode, count)
#define	MESHD_PROBE_APP_EVENT_DROP(fd, dropped)				\
	DTRACE_PROBE2(meshd, app__event__drop, fd, dropped)
#define	MESHD_PROBE_APP_EVENT_SEND(fd, opcode, len)			\
	DTRACE_PROBE3(meshd, app__event__send, fd, opcode, len)

#else

#define	MESHD_PROBE_APP_CONNECT(fd)					\
	do { (void)(fd); } while (0)
#define	MESHD_PROBE_APP_DISCONNECT(fd)					\
	do { (void)(fd); } while (0)
#define	MESHD_PROBE_APP_REGISTER(fd, model, vendor)			\
	do { (void)(fd); (void)(model); (void)(vendor); } while (0)
#define	MESHD_PROBE_APP_EVENT_QUEUE(fd, opcode, count)			\
	do { (void)(fd); (void)(opcode); (void)(count); } while (0)
#define	MESHD_PROBE_APP_EVENT_DROP(fd, dropped)				\
	do { (void)(fd); (void)(dropped); } while (0)
#define	MESHD_PROBE_APP_EVENT_SEND(fd, opcode, len)			\
	do { (void)(fd); (void)(opcode); (void)(len); } while (0)

#endif

#endif /* MESHD_PROBES_H */

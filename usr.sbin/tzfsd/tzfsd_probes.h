/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _TZFSD_PROBES_H_
#define	_TZFSD_PROBES_H_

#ifdef WITH_DTRACE
#include "tzfsd_provider.h"
#define	TZFSD_PROBE_MSG(len, nfds)	TZFSD_REQUEST_MSG(len, nfds)
#define	TZFSD_PROBE_VALIDATE(op, del, rights, life, ok) \
	TZFSD_REQUEST_VALIDATE(op, del, rights, life, ok)
#define	TZFSD_PROBE_GRANT(op, del, fd, err) \
	TZFSD_REQUEST_GRANT(op, del, fd, err)
#define	TZFSD_PROBE_REPLY(op, status, fd)	TZFSD_REQUEST_REPLY(op, status, fd)
#else
#define	TZFSD_PROBE_MSG(len, nfds) \
	do { (void)(len); (void)(nfds); } while (0)
#define	TZFSD_PROBE_VALIDATE(op, del, rights, life, ok) \
	do { (void)(op); (void)(del); (void)(rights); (void)(life); (void)(ok); } while (0)
#define	TZFSD_PROBE_GRANT(op, del, fd, err) \
	do { (void)(op); (void)(del); (void)(fd); (void)(err); } while (0)
#define	TZFSD_PROBE_REPLY(op, status, fd) \
	do { (void)(op); (void)(status); (void)(fd); } while (0)
#endif

#endif

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
#define	TZFSD_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	TZFSD_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#define	TZFSD_PROBE_RECLAIM_DESTROY(bundle, err) \
	TZFSD_RECLAIM_DESTROY(__DECONST(char *, bundle), err)
#define	TZFSD_PROBE_RECLAIM_SNAPSHOT(snap) \
	TZFSD_RECLAIM_SNAPSHOT(__DECONST(char *, snap))
#else
#define	TZFSD_PROBE_MSG(len, nfds) \
	do { (void)(len); (void)(nfds); } while (0)
#define	TZFSD_PROBE_VALIDATE(op, del, rights, life, ok) \
	do { (void)(op); (void)(del); (void)(rights); (void)(life); (void)(ok); } while (0)
#define	TZFSD_PROBE_GRANT(op, del, fd, err) \
	do { (void)(op); (void)(del); (void)(fd); (void)(err); } while (0)
#define	TZFSD_PROBE_REPLY(op, status, fd) \
	do { (void)(op); (void)(status); (void)(fd); } while (0)
#define	TZFSD_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#define	TZFSD_PROBE_RECLAIM_DESTROY(bundle, err) \
	do { (void)(bundle); (void)(err); } while (0)
#define	TZFSD_PROBE_RECLAIM_SNAPSHOT(snap) \
	do { (void)(snap); } while (0)
#endif

#endif

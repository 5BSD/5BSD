/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _BSDFILESYSTEM_PROBES_H_
#define	_BSDFILESYSTEM_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdfilesystem_provider.h"
#define	BSDFILESYSTEM_PROBE_MSG(len, nfds)	BSDFILESYSTEM_REQUEST_MSG(len, nfds)
#define	BSDFILESYSTEM_PROBE_VALIDATE(op, del, rights, life, ok) \
	BSDFILESYSTEM_REQUEST_VALIDATE(op, del, rights, life, ok)
#define	BSDFILESYSTEM_PROBE_GRANT(op, del, fd, err) \
	BSDFILESYSTEM_REQUEST_GRANT(op, del, fd, err)
#define	BSDFILESYSTEM_PROBE_REPLY(op, status, fd)	BSDFILESYSTEM_REQUEST_REPLY(op, status, fd)
#define	BSDFILESYSTEM_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	BSDFILESYSTEM_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#define	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(bundle, err) \
	BSDFILESYSTEM_RECLAIM_DESTROY(__DECONST(char *, bundle), err)
#define	BSDFILESYSTEM_PROBE_RECLAIM_SNAPSHOT(snap) \
	BSDFILESYSTEM_RECLAIM_SNAPSHOT(__DECONST(char *, snap))
#else
#define	BSDFILESYSTEM_PROBE_MSG(len, nfds) \
	do { (void)(len); (void)(nfds); } while (0)
#define	BSDFILESYSTEM_PROBE_VALIDATE(op, del, rights, life, ok) \
	do { (void)(op); (void)(del); (void)(rights); (void)(life); (void)(ok); } while (0)
#define	BSDFILESYSTEM_PROBE_GRANT(op, del, fd, err) \
	do { (void)(op); (void)(del); (void)(fd); (void)(err); } while (0)
#define	BSDFILESYSTEM_PROBE_REPLY(op, status, fd) \
	do { (void)(op); (void)(status); (void)(fd); } while (0)
#define	BSDFILESYSTEM_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#define	BSDFILESYSTEM_PROBE_RECLAIM_DESTROY(bundle, err) \
	do { (void)(bundle); (void)(err); } while (0)
#define	BSDFILESYSTEM_PROBE_RECLAIM_SNAPSHOT(snap) \
	do { (void)(snap); } while (0)
#endif

#endif

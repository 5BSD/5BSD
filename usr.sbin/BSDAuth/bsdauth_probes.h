/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDAUTH_PROBES_H_
#define	_BSDAUTH_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdauth_provider.h"
#define	BSDAUTH_PROBE_REQUEST_START(client) \
	BSDAUTH_REQUEST_START(__DECONST(char *, client))
#define	BSDAUTH_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	BSDAUTH_REQUEST_DONE(__DECONST(char *, client), uid, kind, flags, \
	    status, error)
#define	BSDAUTH_PROBE_ELEVATE_START(client) \
	BSDAUTH_ELEVATE_START(__DECONST(char *, client))
#define	BSDAUTH_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage) \
	BSDAUTH_ELEVATE_DONE(__DECONST(char *, client), uid, \
	    __DECONST(char *, name), status, error, __DECONST(char *, stage))
#define	BSDAUTH_PROBE_RATELIMIT_BLOCK(uid, failures) \
	BSDAUTH_RATELIMIT_BLOCK(uid, failures)
#define	BSDAUTH_PROBE_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule) \
	BSDAUTH_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule)
#else
#define	BSDAUTH_PROBE_REQUEST_START(client) \
	do { (void)(client); } while (0)
#define	BSDAUTH_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	do { (void)(client); (void)(uid); (void)(kind); (void)(flags); \
	    (void)(status); (void)(error); } while (0)
#define	BSDAUTH_PROBE_ELEVATE_START(client) \
	do { (void)(client); } while (0)
#define	BSDAUTH_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage) \
	do { (void)(client); (void)(uid); (void)(name); (void)(status); \
	    (void)(error); (void)(stage); } while (0)
#define	BSDAUTH_PROBE_RATELIMIT_BLOCK(uid, failures) \
	do { (void)(uid); (void)(failures); } while (0)
#define	BSDAUTH_PROBE_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule) \
	do { (void)(uid); (void)(count); (void)(all); (void)(admin_rights); \
	    (void)(from_default_rule); } while (0)
#endif

#endif /* !_BSDAUTH_PROBES_H_ */

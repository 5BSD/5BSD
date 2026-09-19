/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _AUTHAGENTD_PROBES_H_
#define	_AUTHAGENTD_PROBES_H_

#ifdef WITH_DTRACE
#include "authagentd_provider.h"
#define	AUTHAGENT_PROBE_REQUEST_START(client) \
	AUTHAGENT_REQUEST_START(__DECONST(char *, client))
#define	AUTHAGENT_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	AUTHAGENT_REQUEST_DONE(__DECONST(char *, client), uid, kind, flags, \
	    status, error)
#define	AUTHAGENT_PROBE_ELEVATE_START(client) \
	AUTHAGENT_ELEVATE_START(__DECONST(char *, client))
#define	AUTHAGENT_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage) \
	AUTHAGENT_ELEVATE_DONE(__DECONST(char *, client), uid, \
	    __DECONST(char *, name), status, error, __DECONST(char *, stage))
#define	AUTHAGENT_PROBE_RATELIMIT_BLOCK(uid, failures) \
	AUTHAGENT_RATELIMIT_BLOCK(uid, failures)
#define	AUTHAGENT_PROBE_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule) \
	AUTHAGENT_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule)
#else
#define	AUTHAGENT_PROBE_REQUEST_START(client) \
	do { (void)(client); } while (0)
#define	AUTHAGENT_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	do { (void)(client); (void)(uid); (void)(kind); (void)(flags); \
	    (void)(status); (void)(error); } while (0)
#define	AUTHAGENT_PROBE_ELEVATE_START(client) \
	do { (void)(client); } while (0)
#define	AUTHAGENT_PROBE_ELEVATE_DONE(client, uid, name, status, error, stage) \
	do { (void)(client); (void)(uid); (void)(name); (void)(status); \
	    (void)(error); (void)(stage); } while (0)
#define	AUTHAGENT_PROBE_RATELIMIT_BLOCK(uid, failures) \
	do { (void)(uid); (void)(failures); } while (0)
#define	AUTHAGENT_PROBE_POLICY_RESOLVE(uid, count, all, admin_rights, \
	    from_default_rule) \
	do { (void)(uid); (void)(count); (void)(all); (void)(admin_rights); \
	    (void)(from_default_rule); } while (0)
#endif

#endif /* !_AUTHAGENTD_PROBES_H_ */

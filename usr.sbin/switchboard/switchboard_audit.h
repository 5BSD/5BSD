/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard — OpenBSM audit-trail helpers.
 *
 * switchboard makes security-relevant decisions (control-socket privileged
 * commands, service execution under changed credentials, capability
 * minting, configuration reload).  These emit BSM audit records in
 * addition to the DTrace probes so that the events land in the trusted,
 * tamper-evident audit trail rather than syslog alone.
 *
 * Audit support is compiled in only when the build defines USE_BSM_AUDIT;
 * otherwise the helpers collapse to no-ops so the daemon still builds on
 * systems without OpenBSM.
 */

#ifndef SWITCHBOARD_AUDIT_H
#define SWITCHBOARD_AUDIT_H

#include <sys/types.h>

#ifdef USE_BSM_AUDIT
#include <bsm/audit.h>
#include <bsm/audit_kevents.h>

/*
 * Emit a single audit record.
 *
 *   event  - AUE_SWITCHBOARD_* event number
 *   auid   - subject uid to attribute the event to (the acting principal;
 *            for control commands this is the peer euid, otherwise the
 *            daemon's own uid)
 *   error  - 0 on success, otherwise an errno describing the failure
 *   fmt    - printf(3)-style text token describing the event
 *
 * Safe to call before auditing is configured; audit_submit(3) handles the
 * "auditing disabled" case internally.
 */
void	switchboard_audit(int event, uid_t auid, int error, const char *fmt, ...)
	    __printflike(4, 5);
#else
#define	switchboard_audit(event, auid, error, ...)	((void)0)
#endif

#endif /* SWITCHBOARD_AUDIT_H */

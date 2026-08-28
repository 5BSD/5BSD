/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Curated rc.d adoption (§8, item 5 of the service-discovery model).
 *
 * The launchd-style rc model: the /etc/rc shim keeps starting everything that
 * is NOT adopted, while serviced natively adopts a small, explicit allow-list
 * of rc.d services as supervised SVC_KIND_RC units.  Each adopted service is
 * removed from the /etc/rc path (its rc.conf <name>_enable is set to NO in the
 * image), and serviced starts it with service(8) "onestart" — which ignores
 * the rcvar — so exactly one instance runs, supervised by serviced.
 *
 * The selection and unit-building logic is pure (no daemon state, no I/O beyond
 * reading the candidate scripts) so it is unit-testable in isolation; only
 * rc_adopt_register() touches sd.services and the kqueue.
 */

#ifndef SERVICED_RC_ADOPT_H
#define SERVICED_RC_ADOPT_H

#include <stdbool.h>

#include "rc_ingest.h"		/* struct rc_unit */

struct svc_runtime;		/* serviced.h */

/*
 * The curated allow-list of rc.d service names serviced adopts.  Returns the
 * count and, via *listp, a pointer to the static array of names.  Initially
 * one entry ("cron"); extend the array in rc_adopt.c to widen adoption.
 */
unsigned rc_adopt_allowlist(const char *const **listp);

/* True if name is on the curated adoption allow-list. */
bool	rc_adopt_is_allowed(const char *name);

/*
 * Inspect a single candidate script rcd_dir/name.  Returns true and fills
 * *out (name + parsed rcorder header) when the script exists, is an executable
 * regular file, and is an orderable, auto-started service (PROVIDE present and
 * not KEYWORD nostart); false otherwise (absent, unreadable, non-executable,
 * or not a service).  name must be on the allow-list — callers pass allow-list
 * entries only.
 */
bool	rc_adopt_present(const char *rcd_dir, const char *name,
	    struct rc_unit *out);

/*
 * Select every allow-listed rc.d service present in rcd_dir, appending each to
 * out (bounded by max).  Non-allow-listed scripts in the directory are ignored
 * entirely.  Returns the number selected (0 when none of the allow-listed
 * scripts are present — never an error; an absent service is simply not
 * adopted).  Pure: reads only the candidate scripts, touches no daemon state.
 */
int	rc_adopt_select(const char *rcd_dir, struct rc_unit *out, unsigned max);

/*
 * Build a supervised RC unit from a selected rc.d service into *svc (which the
 * caller has zero-initialised): kind = SVC_KIND_RC, manifest.label = the rc.d
 * service name (svc_exec_rc launches "service <label> onestart"), management =
 * SVC_MGMT_SYSTEM (root-manageable, not core), restart on-failure, state
 * STOPPED (ready for the boot launch).  fds are initialised to -1.
 */
void	rc_adopt_build_unit(const struct rc_unit *u, struct svc_runtime *svc);

/*
 * The service(8) program and the subcommand serviced uses to launch an adopted
 * RC unit.  The verb is "onestart" (not "faststart"): the "one" prefix forces
 * the service to start regardless of its rc.conf <name>_enable rcvar, so
 * serviced can start a service the /etc/rc shim was told to skip (<name>_enable
 * = "NO" in the image) without double-starting it.
 */
extern const char rc_adopt_service_prog[];	/* "/usr/sbin/service" */
extern const char rc_adopt_start_verb[];	/* "onestart" */

/*
 * The subcommand serviced uses to stop an adopted RC unit.  "onestop" (like
 * "onestart") forces the operation regardless of the rc.conf <name>_enable
 * rcvar — an adopted service is <name>_enable="NO" in the image, so a plain
 * "stop" would refuse it as disabled and never kill the daemon.  onestop reads
 * the daemon's pidfile and signals the real process, which is the only correct
 * way to stop an rc.d daemon: the daemon daemonized and reparented to init, so
 * it is NOT the process serviced holds a descriptor for.
 */
extern const char rc_adopt_stop_verb[];		/* "onestop" */

/*
 * Build the NUL-terminated service(8) argv that runs verb (onestart/onestop)
 * on the adopted RC unit label: { rc_adopt_service_prog, label, verb, NULL }.
 * Pure; shared by the live launch/stop paths (svc_exec_rc / svc_exec_rc_stop)
 * and their tests so the argv layouts can never drift.  out must have room for
 * 4 entries; out[1] aliases label and out[2] aliases verb.
 */
void	rc_adopt_verb_argv(const char *label, const char *verb,
	    const char *out[4]);

/*
 * Convenience wrappers over rc_adopt_verb_argv() for the two live verbs.
 * rc_adopt_launch_argv uses rc_adopt_start_verb ("onestart");
 * rc_adopt_stop_argv uses rc_adopt_stop_verb ("onestop").
 */
void	rc_adopt_launch_argv(const char *label, const char *out[4]);
void	rc_adopt_stop_argv(const char *label, const char *out[4]);

/*
 * Adopt the curated rc.d allow-list into sd.services as boot-launched RC units.
 * For each allow-listed service present under the rc.d directory (default
 * "/etc/rc.d", overridable with SERVICED_RCD_DIR for tests) that is not already
 * registered by label, append a unit built by rc_adopt_build_unit().  The
 * caller's boot launch loop then starts every newly appended STOPPED unit in
 * parallel with the capability components — independent of the /etc/rc oneshot.
 *
 * Idempotent: a service already present by label is left untouched.  Never
 * fatal: an absent rc.d directory or absent candidate script logs NOTICE and is
 * skipped so a missing service can never block boot.  Returns the number of
 * units newly appended (>= 0).
 */
int	rc_adopt_register(int kq);

#endif /* SERVICED_RC_ADOPT_H */

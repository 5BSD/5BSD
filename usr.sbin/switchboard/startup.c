/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Parallel service startup for switchboard.
 *
 * Services carry no startup ordering.  Every boot service launches in
 * parallel with no sequencing; inter-service needs are satisfied on
 * demand through IPC activation as they arise.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libcapbundle.h>
#include <service_bootstrap.h>

#include "switchboard.h"
#include "launch_limits.h"
#include "rc_adopt.h"
#include "switchboard_probes.h"

/*
 * Log a loaded manifest's key attributes for operational visibility.
 */
static void
log_loaded_manifest(const struct svc_manifest *m)
{
	unsigned j;

	syslog(LOG_INFO, "startup: loaded %s restart=%s",
	    m->label, restart_policy_name(m->restart));

	for (j = 0; j < m->nprovides; j++)
		syslog(LOG_INFO, "startup: %s provides: %s",
		    m->label, m->provides[j]);
	if (svc_launch_token_count(m) > 0)
		syslog(LOG_INFO, "startup: %s capabilities: system=0x%x",
		    m->label, m->cap_system);
}

/*
 * Transitional rc world: run /etc/rc once, as a oneshot, and block until
 * it finishes.  switchboard now owns rc startup (init no longer runs
 * /etc/rc), so this reproduces the traditional boot -- the full rc
 * sequence runs before native capability services launch.  /etc/rc
 * normally exits 0 even when individual rc.d services fail, so a non-zero
 * result here means rc itself is broken; it is logged but not fatal
 * (native services still launch).  Returns 0 if /etc/rc exited 0.
 */
static int
run_rc_bootstrap(int kqunused)
{
	static struct svc_runtime rc;	/* static: stable kevent udata */
	struct kevent event;
	int nev;

	(void)kqunused;

	memset(&rc, 0, sizeof(rc));
	rc.kind = SVC_KIND_ONESHOT;
	strlcpy(rc.manifest.label, "etc-rc", sizeof(rc.manifest.label));
	/*
	 * /etc/rc is a non-executable (0644) /bin/sh script, exactly as init
	 * runs it: execve(_PATH_BSHELL, {"sh", "/etc/rc", "autoboot"}).  Exec
	 * it through /bin/sh -- execv("/etc/rc") directly fails EACCES (child
	 * _exit(127)), which silently skips the entire rc boot (no rw remount,
	 * no /var), stalling convergence.
	 */
	strlcpy(rc.manifest.program, "/bin/sh", sizeof(rc.manifest.program));
	strlcpy(rc.manifest.arguments[0], "/etc/rc",
	    sizeof(rc.manifest.arguments[0]));
	strlcpy(rc.manifest.arguments[1], "autoboot",
	    sizeof(rc.manifest.arguments[1]));
	rc.manifest.narguments = 2;
	rc.manifest.restart = SVC_RESTART_NEVER;
	rc.state = SVC_STATE_STOPPED;
	rc.want_console = true;		/* rc progress must be visible on console */
	svc_runtime_init_fds(&rc);

	/*
	 * Install the SYSTEM ambient lookup channel (§21) before exec'ing rc so
	 * rc, getty, login, su, and every other boot descendant inherits system
	 * service discovery.  switchboard keeps the retained client end open for the
	 * life of the daemon; svc_exec_command spares it from the rc child's
	 * closefrom(2) and SERVICE_LOOKUP_FD (set in switchboard's environment by
	 * service_install_ambient_lookup) names it for the child's execv(2).
	 *
	 * This is best-effort discovery, never authority: if minting or install
	 * fails, log and run rc exactly as before with no ambient channel.  A
	 * broken ambient carry must never prevent the system from booting.
	 */
	if (switchboard_ambient_lookup_fd < 0) {
		int lookup_fd = -1;

		if (domain_mint_system_channel(&lookup_fd, switchboard_kq) == -1)
			syslog(LOG_NOTICE, "startup: no system ambient lookup "
			    "channel (mint failed): %m");
		else if (service_install_ambient_lookup(lookup_fd) == -1) {
			syslog(LOG_NOTICE, "startup: no system ambient lookup "
			    "channel (install failed): %m");
			(void)close(lookup_fd);
		} else {
			switchboard_ambient_lookup_fd = lookup_fd;
			syslog(LOG_INFO, "startup: system ambient lookup channel "
			    "on fd %d", lookup_fd);
		}
	}

	/*
	 * Carry the ambient lookup channel into interactive logins (§21).  rc
	 * and its descendants inherit SERVICE_LOOKUP_FD by environment, but the
	 * getty/login sessions capsule spawns from /etc/ttys are siblings of
	 * rc and never see that environment.  Hand capsule (PID 1) a dup of
	 * the retained client end so it can pin the channel at
	 * SERVICE_LOOKUP_FIXED_FD when it execs each getty.
	 *
	 * Strictly best-effort: the rc path already works, so any failure here
	 * (no channel, no Capsule link, dup or send error) is logged at
	 * LOG_NOTICE and boot proceeds unchanged.
	 */
	if (switchboard_ambient_lookup_fd >= 0 && sd.capsule_channel_fd >= 0) {
		int dupfd = dup(switchboard_ambient_lookup_fd);

		if (dupfd == -1)
			syslog(LOG_NOTICE, "startup: cannot dup ambient lookup "
			    "channel for interactive carry: %m");
		else {
			if (capsule_set_ambient_lookup(sd.capsule_channel_fd,
			    dupfd) == -1)
				syslog(LOG_NOTICE, "startup: capsule "
				    "interactive ambient carry unavailable: %m");
			else
				syslog(LOG_INFO, "startup: ambient lookup "
				    "channel handed to capsule for logins");
			(void)close(dupfd);
		}
	}

	syslog(LOG_INFO, "startup: running /etc/rc");
	if (svc_exec(&rc, switchboard_kq) == -1) {
		syslog(LOG_ERR, "startup: cannot launch /etc/rc");
		return (-1);
	}

	/*
	 * Wait for /etc/rc to finish, however long it takes.  rc has no
	 * knowable deadline (fsck, key generation, network/entropy waits can
	 * all be legitimately slow), and init historically waited on /etc/rc
	 * indefinitely -- so we do the same.
	 *
	 * Drive the FULL switchboard dispatch on the shared switchboard_kq while
	 * waiting, rather than blocking on a private kqueue that only sees rc's
	 * exit.  rc and its rc.d children inherit the ambient lookup channel
	 * (SERVICE_LOOKUP_FD, installed above) and may make synchronous
	 * capability lookups — which switchboard itself answers on switchboard_kq — so
	 * a private-kqueue wait would deadlock any rc child that blocks on a
	 * lookup that rc then waits on.  Each kevent() retrieves one ready event and
	 * switchboard_dispatch_event() consumes it before another is dequeued, so no
	 * level-triggered source can starve rc's EVFILT_PROCDESC exit (the
	 * starvation the old dedicated kqueue guarded against).  sd.running
	 * clears if SIGTERM or Capsule loss arrives mid-rc.
	 */
	while (rc.state == SVC_STATE_STARTING && sd.running) {
		nev = kevent(switchboard_kq, NULL, 0, &event, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "startup: kevent during /etc/rc: %m");
			break;
		}
		if (nev == 1)
			switchboard_dispatch_event(&event);
	}

	if (rc.state == SVC_STATE_DONE) {
		syslog(LOG_INFO, "startup: /etc/rc completed");
		return (0);
	}
	syslog(LOG_WARNING, "startup: /etc/rc did not exit cleanly (state %d)",
	    rc.state);
	return (-1);
}

/*
 * Launch every populated service still in the STOPPED state, in parallel with
 * no ordering (inter-service needs are satisfied on demand via IPC activation).
 * Idempotent: a unit a lookup already activated is skipped -- so this is safe to
 * call in more than one phase (the native boot units before /etc/rc, the adopted
 * rc.d units after).  Returns how many it launched.
 */
static unsigned
startup_launch_stopped(int kq)
{
	unsigned i, launched = 0;

	for (i = 0; i < sd.nservices; i++) {
		/* A lookup may already have activated this unit; a second
		 * exec would create a duplicate runtime. */
		if (sd.services[i].state != SVC_STATE_STOPPED)
			continue;
		syslog(LOG_INFO, "startup: service: %s",
		    sd.services[i].manifest.label);
		if (svc_launch_or_await(&sd.services[i], kq) == 0)
			launched++;
		else
			syslog(LOG_ERR, "startup: failed to launch '%s'",
			    sd.services[i].manifest.label);
	}
	return (launched);
}

/*
 * Launch all system services in parallel.
 *
 * 1. Scan bundle registry for non-on-demand services
 * 2. Fill svc_runtime array with entries from bundles
 * 3. Launch native boot units, then run /etc/rc in parallel with them
 */
int
startup_launch_system(int kq)
{
	/*
	 * Run/live must exist before the first launch, whatever else this
	 * startup does: providers that reconcile against the running set receive
	 * it as a delivered directory descriptor at exec time, and Run/ is
	 * recreated every boot.
	 */
	svc_reclaim_live_prepare();
	svc_reclaim_publish_groups();	/* installed-claimed groups: known now */
	struct startup_entry {
		struct svc_manifest manifest;
		unsigned bundle_idx;
		unsigned service_idx;
	} *entries;
	unsigned nmanifests, i, bi, si;
	unsigned launched;
	struct capbundle *b;
	struct capbundle_service *asvc;
	struct timespec start_ts;
	const char *skip_rc_env;
	bool skip_rc;

	skip_rc_env = getenv("SWITCHBOARD_SKIP_RC");
	skip_rc = skip_rc_env != NULL && skip_rc_env[0] == '1';

	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	/*
	 * /etc/rc is run further down, AFTER the native boot units are launched,
	 * so the born-in-capability-mode services come up in parallel with rc
	 * instead of waiting for the whole rc sequence to finish first.
	 */

	/* Collect all non-on-demand service entries from bundles. */
	entries = calloc(SWITCHBOARD_MAX_SERVICES, sizeof(*entries));
	if (entries == NULL) {
		syslog(LOG_ERR, "startup: calloc: %m");
		return (-1);
	}

	nmanifests = 0;
	for (bi = 0; bi < bundle_registry_count(); bi++) {
		b = bundle_registry_get(bi);
		if (b == NULL)
			continue;

		for (si = 0; si < capbundle_nservices(b); si++) {
			asvc = capbundle_service(b, si);
			if (asvc == NULL)
				continue;
			/*
			 * Only boot units are launched here.  Units activated
			 * on demand — by IPC lookup, by a timer, or by a path
			 * event (Phase 5) — stay stopped until their source
			 * fires.  Timer/path units get their persistent runtime
			 * slot from activation_register_all(), not from startup.
			 */
			if (!capbundle_svc_activates_at_boot(asvc))
				continue;
			if (nmanifests >= SWITCHBOARD_MAX_SERVICES) {
				syslog(LOG_WARNING,
				    "startup: service limit reached");
				break;
			}

			/* Fill svc_manifest from bundle service. */
			if (capbundle_svc_fill_manifest(asvc,
			    &entries[nmanifests].manifest) == -1) {
				syslog(LOG_WARNING,
				    "startup: skipping invalid bundle service "
				    "'%s'", capbundle_svc_label(asvc));
				continue;
			}
			log_loaded_manifest(&entries[nmanifests].manifest);
			entries[nmanifests].bundle_idx = bi;
			entries[nmanifests].service_idx = si;
			nmanifests++;
		}
	}

	/* Allocate runtime state — always, even with no boot services,
	 * because on-demand launches and reload append to this array. */
	sd.services = calloc(SWITCHBOARD_MAX_SERVICES, sizeof(*sd.services));
	if (sd.services == NULL) {
		syslog(LOG_ERR, "startup: calloc services: %m");
		free(entries);
		return (-1);
	}

	syslog(LOG_INFO, "startup: %u services loaded", nmanifests);

	/* Copy entries into runtime slots. */
	for (i = 0; i < nmanifests; i++) {
		sd.services[i].manifest = entries[i].manifest;
		sd.services[i].bundle_idx = entries[i].bundle_idx;
		sd.services[i].bundle_svc_idx = entries[i].service_idx;
		svc_runtime_init_fds(&sd.services[i]);
		sd.services[i].state = SVC_STATE_STOPPED;
		strlcpy(sd.services[i].launched_by, "system",
		    sizeof(sd.services[i].launched_by));
		clock_gettime(CLOCK_MONOTONIC, &sd.services[i].launch_time);
	}
	sd.nservices = nmanifests;
	free(entries);

	/*
	 * Launch the native boot units NOW, before /etc/rc.  run_rc_bootstrap
	 * below drives the shared switchboard dispatch loop, so these units reach
	 * readiness WHILE rc runs rather than after the whole rc sequence.  Born-
	 * in-capability-mode services take their resources from the descriptors
	 * switchboard delivers and the loader-imported pool, never from rc, so they
	 * do not depend on rc having finished; anything transiently unavailable is
	 * retried on demand (no hard dependencies).
	 */
	SWITCHBOARD_PROBE_STARTUP_BEGIN(sd.nservices, 1);
	launched = startup_launch_stopped(kq);
	syslog(LOG_INFO, "startup: launched %u native services", launched);

	/*
	 * Transitional rc world: run /etc/rc once (a oneshot) and block until it
	 * completes -- but the native plane above is already coming up in parallel.
	 * A non-zero /etc/rc is reported for non-convergence.  A test fixture opts
	 * out via the environment (a fixture must not replay the host's rc, which
	 * would flip the machine's runlevel state from inside a test).  Per-service
	 * rc units replace this monolithic step in a later phase.
	 */
	if (skip_rc)
		syslog(LOG_INFO, "startup: /etc/rc skipped by environment");
	else
		(void)run_rc_bootstrap(kq);

	/*
	 * A procdesc-delivered shutdown can interrupt /etc/rc while PID 1 is still
	 * waiting for convergence; adopt and launch nothing further past it (the
	 * native units already launched are torn down by the shutdown path).
	 */
	if (!sd.running) {
		syslog(LOG_INFO, "startup: cancelled during /etc/rc shutdown");
		return (0);
	}

	/*
	 * Curated rc adoption (§8): a small allow-list of rc.d services (initially
	 * cron), supervised as SVC_KIND_RC units, appended after the /etc/rc oneshot
	 * and launched now alongside the capability peers.  Never fatal: an absent
	 * rc.d service logs NOTICE and boot proceeds (see rc_adopt_register).
	 * svc_exec_rc first uses "onestatus" to adopt an instance /etc/rc already
	 * started, and runs "onestart" only if absent.
	 */
	if (!skip_rc)
		(void)rc_adopt_register(kq);
	launched += startup_launch_stopped(kq);

	syslog(LOG_INFO, "startup: launched %u services", launched);
	SWITCHBOARD_PROBE_STARTUP_TIER(0, launched);

	/*
	 * Publish the running-bundle markers for the container-model reconcile
	 * now that the boot units are launched.  The installed set (System/,
	 * Apps/) is the primary live set a provider reaps against; these markers
	 * add the bundles whose units are running, so cleanup never races a unit
	 * that is up but whose bundle is mid-removal.
	 */
	svc_reclaim_publish_live();

	{
		struct timespec end_ts;
		uint64_t dur_ms;

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		if (end_ts.tv_nsec < start_ts.tv_nsec) {
			end_ts.tv_sec--;
			end_ts.tv_nsec += 1000000000L;
		}
		dur_ms = (uint64_t)(end_ts.tv_sec - start_ts.tv_sec) * 1000 +
		    (uint64_t)(end_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
		syslog(LOG_INFO, "startup: complete in %llu ms",
		    (unsigned long long)dur_ms);
		SWITCHBOARD_PROBE_STARTUP_DONE(dur_ms);
	}

	return (0);
}

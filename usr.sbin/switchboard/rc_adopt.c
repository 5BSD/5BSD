/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Curated rc.d adoption — see rc_adopt.h.  switchboard natively supervises a small
 * allow-list of rc.d services as SVC_KIND_RC units; /etc/rc keeps starting the
 * rest.  An "onestatus" probe adopts a live legacy instance, while "onestart"
 * starts an absent one regardless of its rcvar.  This makes migration safe for
 * old images and administrator overrides without a duplicate launch.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "switchboard.h"
#include "rc_ingest.h"
#include "rc_adopt.h"

/*
 * The curated adoption allow-list is POLICY, not code: it is read from a
 * configuration file (default RC_ADOPT_DEFAULT_CONF, overridable with
 * SWITCHBOARD_ADOPT_CONF for tests) rather than baked into a C array.  One
 * rc.d service name per line, '#' comments, blank lines ignored.  Under
 * mac_veriexec the /Capabilities tree is integrity-protected, so the list is
 * tamper-evident.  An absent/empty file adopts nothing (logged NOTICE) -- the
 * file is the sole authority, with no hardcoded fallback.
 */
#define	RC_ADOPT_DEFAULT_CONF	"/Capabilities/Config/switchboard/rc_adopt.conf"
#define	RC_ADOPT_MAX_NAMES	64
#define	RC_ADOPT_NAME_MAX	64

static char adopt_storage[RC_ADOPT_MAX_NAMES][RC_ADOPT_NAME_MAX];
static const char *adopt_names[RC_ADOPT_MAX_NAMES];
static unsigned adopt_count;
static bool adopt_loaded;

static const char *
rc_adopt_conf_path(void)
{
	const char *p = getenv("SWITCHBOARD_ADOPT_CONF");

	return (p != NULL && p[0] != '\0') ? p : RC_ADOPT_DEFAULT_CONF;
}

/*
 * Load the adoption allow-list from the config file, once per process.  Every
 * public accessor calls this first, so the list is always populated on demand.
 * Parsing is fail-soft: a bad line is skipped with a warning, an absent file
 * yields an empty list, and adoption of an absent service is simply a no-op --
 * a malformed list can never block boot.
 */
static void
rc_adopt_load(void)
{
	FILE *f;
	const char *path;
	char line[256];

	if (adopt_loaded)
		return;
	adopt_loaded = true;
	adopt_count = 0;

	path = rc_adopt_conf_path();
	f = fopen(path, "re");
	if (f == NULL) {
		syslog(LOG_NOTICE, "rc adoption: no adopt list at %s (%m); "
		    "adopting no rc.d services", path);
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		char *s, *e, *hash;
		unsigned i;
		bool dup;

		/* Strip a trailing comment, then trim surrounding whitespace. */
		if ((hash = strchr(line, '#')) != NULL)
			*hash = '\0';
		s = line;
		while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
			s++;
		e = s + strlen(s);
		while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
		    e[-1] == '\n' || e[-1] == '\r'))
			*--e = '\0';
		if (*s == '\0')
			continue;
		if (strlen(s) >= RC_ADOPT_NAME_MAX || strchr(s, '/') != NULL) {
			syslog(LOG_WARNING, "rc adoption: invalid service name "
			    "'%s' in %s; skipping", s, path);
			continue;
		}
		dup = false;
		for (i = 0; i < adopt_count; i++)
			if (strcmp(adopt_names[i], s) == 0) {
				dup = true;
				break;
			}
		if (dup)
			continue;
		if (adopt_count >= RC_ADOPT_MAX_NAMES) {
			syslog(LOG_WARNING, "rc adoption: more than %u entries in "
			    "%s; ignoring '%s' and the rest", RC_ADOPT_MAX_NAMES,
			    path, s);
			break;
		}
		strlcpy(adopt_storage[adopt_count], s, RC_ADOPT_NAME_MAX);
		adopt_names[adopt_count] = adopt_storage[adopt_count];
		adopt_count++;
	}
	(void)fclose(f);
	syslog(LOG_INFO, "rc adoption: loaded %u service name(s) from %s",
	    adopt_count, path);
}

const char rc_adopt_service_prog[] = "/usr/sbin/service";
const char rc_adopt_status_verb[] = "onestatus";
const char rc_adopt_start_verb[] = "onestart";
const char rc_adopt_stop_verb[] = "onestop";

void
rc_adopt_verb_argv(const char *label, const char *verb, const char *out[4])
{

	out[0] = rc_adopt_service_prog;
	out[1] = label;
	out[2] = verb;
	out[3] = NULL;
}

void
rc_adopt_launch_argv(const char *label, const char *out[4])
{

	rc_adopt_verb_argv(label, rc_adopt_start_verb, out);
}

void
rc_adopt_status_argv(const char *label, const char *out[4])
{

	rc_adopt_verb_argv(label, rc_adopt_status_verb, out);
}

void
rc_adopt_stop_argv(const char *label, const char *out[4])
{

	rc_adopt_verb_argv(label, rc_adopt_stop_verb, out);
}

unsigned
rc_adopt_allowlist(const char *const **listp)
{

	rc_adopt_load();
	if (listp != NULL)
		*listp = adopt_names;
	return (adopt_count);
}

bool
rc_adopt_is_allowed(const char *name)
{
	unsigned i;

	rc_adopt_load();
	for (i = 0; i < adopt_count; i++)
		if (strcmp(adopt_names[i], name) == 0)
			return (true);
	return (false);
}

/* Read the leading rcorder header of path into *meta.  Returns 0, or -1 if the
 * file cannot be opened/read (caller treats -1 as "not a candidate"). */
static int
read_header_file(const char *path, struct rc_unit_meta *meta)
{
	char buf[8192];
	int fd;
	ssize_t r;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (-1);
	r = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (r <= 0)
		return (-1);
	buf[r] = '\0';
	rc_parse_header(buf, meta);
	return (0);
}

bool
rc_adopt_present(const char *rcd_dir, const char *name, struct rc_unit *out)
{
	char path[PATH_MAX];
	struct rc_unit_meta meta;
	struct stat st;

	if (snprintf(path, sizeof(path), "%s/%s", rcd_dir, name) >=
	    (int)sizeof(path))
		return (false);
	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return (false);
	if (access(path, X_OK) != 0)
		return (false);
	if (read_header_file(path, &meta) != 0)
		return (false);
	/* Must be an orderable, auto-started service — same rule as
	 * rc_ingest_scan: a PROVIDE line and not KEYWORD nostart. */
	if (meta.nprovides == 0 || meta.kw_nostart)
		return (false);

	memset(out, 0, sizeof(*out));
	strlcpy(out->name, name, sizeof(out->name));
	out->meta = meta;
	return (true);
}

int
rc_adopt_select(const char *rcd_dir, struct rc_unit *out, unsigned max)
{
	unsigned i, n = 0;

	rc_adopt_load();
	for (i = 0; i < adopt_count; i++) {
		if (n >= max)
			break;
		if (rc_adopt_present(rcd_dir, adopt_names[i], &out[n]))
			n++;
	}
	return ((int)n);
}

void
rc_adopt_build_unit(const struct rc_unit *u, struct svc_runtime *svc)
{

	svc->kind = SVC_KIND_RC;
	strlcpy(svc->manifest.label, u->name, sizeof(svc->manifest.label));
	/* Root-manageable, not core: switchboardctl stop/start/restart works for
	 * root, but it is not unloadable-as-core (§5). */
	svc->manifest.management = SVC_MGMT_SYSTEM;
	/* A supervised system daemon: bring it back if it crashes, but not if
	 * an operator stops it. */
	svc->manifest.restart = SVC_RESTART_ON_FAILURE;
	/*
	 * Backstop deadline for the "service <label> onestop" command.  This is
	 * NOT a SIGKILL grace period (an RC unit is never signalled by
	 * switchboard); it bounds how long switchboard waits for onestop to finish
	 * before force-marking the unit STOPPED.  A zero timeout would fire the
	 * backstop immediately, so give onestop a generous window.
	 */
	svc->manifest.stop_timeout = 30;
	svc->state = SVC_STATE_STOPPED;
	svc_runtime_init_fds(svc);
}

int
rc_adopt_register(int kq)
{
	const char *dir;
	const char *const *names;
	unsigned nn, i;
	int adopted = 0;

	(void)kq;	/* the caller's boot launch loop starts appended units */

	dir = getenv("SWITCHBOARD_RCD_DIR");
	if (dir == NULL || dir[0] == '\0')
		dir = "/etc/rc.d";

	nn = rc_adopt_allowlist(&names);
	for (i = 0; i < nn; i++) {
		struct rc_unit u;
		struct svc_runtime *svc;

		if (!rc_adopt_present(dir, names[i], &u)) {
			syslog(LOG_NOTICE, "rc adoption: %s/%s absent or not an "
			    "orderable rc.d service; not adopting", dir, names[i]);
			continue;
		}
		/* Idempotent: never double-register by label. */
		if (svc_by_label(u.name) != NULL) {
			syslog(LOG_INFO, "rc adoption: '%s' already registered; "
			    "leaving as is", u.name);
			continue;
		}
		if (sd.nservices >= SWITCHBOARD_MAX_SERVICES) {
			syslog(LOG_WARNING, "rc adoption: service limit reached; "
			    "cannot adopt '%s'", u.name);
			break;
		}
		svc = &sd.services[sd.nservices];
		memset(svc, 0, sizeof(*svc));
		rc_adopt_build_unit(&u, svc);
		strlcpy(svc->launched_by, "system", sizeof(svc->launched_by));
		clock_gettime(CLOCK_MONOTONIC, &svc->launch_time);
		sd.nservices++;
		adopted++;
		syslog(LOG_INFO, "rc adoption: adopted rc.d service '%s' as a "
		    "supervised SVC_KIND_RC unit (mgmt=system, restart=on-failure)",
		    u.name);
	}
	return (adopted);
}

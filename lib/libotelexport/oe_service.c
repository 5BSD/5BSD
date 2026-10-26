/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared setup of the base system telemetry services: exporter creation
 * through the otel.conf(5) layers, and privilege dropping.
 */

#include <sys/types.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_sysconf.h"

int
oe_service_open(struct oe_service *svc, const char *service_name,
    const char *version, const char *profile, const char *cli_endpoint,
    double flush_interval, char *err, size_t errlen)
{
	struct oe_otlp_config cfg;

	memset(svc, 0, sizeof(*svc));
	if (oe_sysconf_load(&svc->sc, NULL, NULL) != 0) {
		snprintf(err, errlen, "%s", svc->sc.error);
		return (-1);
	}
	if (!svc->sc.enable) {
		snprintf(err, errlen, "OpenTelemetry is disabled in "
		    "otel.conf (enable = false)");
		return (-1);
	}
	if (oe_env_load_system(&svc->env, &svc->sc, cli_endpoint) != 0) {
		snprintf(err, errlen, "out of memory");
		return (-1);
	}
	oe_host_name(svc->host, sizeof(svc->host));
	oe_host_arch(svc->arch, sizeof(svc->arch));
	oe_os_version(svc->osver, sizeof(svc->osver));
	svc->resource.service_name = svc->env.service_name != NULL ?
	    svc->env.service_name : service_name;
	svc->resource.service_version = version;
	svc->resource.host_name = svc->host;
	svc->resource.host_arch = svc->arch;
	svc->resource.os_name = "freebsd";
	svc->resource.os_version = svc->osver;
	svc->resource.custom = svc->env.resource_attrs;
	svc->resource.ncustom = svc->env.nresource_attrs;

	memset(&cfg, 0, sizeof(cfg));
	/* The system layer is enabled, so an endpoint is always set. */
	cfg.endpoint = svc->env.endpoint;
	cfg.profile = profile;
	cfg.resource = &svc->resource;
	cfg.flush_interval = flush_interval;
	cfg.max_retries = -1;
	cfg.timeout = svc->env.timeout_ms > 0 ?
	    (double)svc->env.timeout_ms / 1000.0 : 0;
	cfg.headers = svc->env.headers;
	cfg.nheaders = svc->env.nheaders;
	cfg.compression = svc->env.compression;
	svc->exporter = oe_otlp_new(&cfg);
	if (svc->exporter == NULL) {
		snprintf(err, errlen, "cannot create the OTLP exporter for "
		    "%s", cfg.endpoint);
		return (-1);
	}
	if (oe_start(svc->exporter) != 0) {
		snprintf(err, errlen, "cannot start the OTLP exporter");
		return (-1);
	}
	return (0);
}

void
oe_service_close(struct oe_service *svc)
{

	if (svc->exporter != NULL) {
		oe_flush(svc->exporter);
		oe_shutdown(svc->exporter);
		oe_exporter_free(svc->exporter);
		svc->exporter = NULL;
	}
	oe_env_free(&svc->env);
	oe_sysconf_free(&svc->sc);
}

int
oe_drop_privileges(const char *user, char *err, size_t errlen)
{
	struct passwd *pw;

	errno = 0;
	pw = getpwnam(user);
	if (pw == NULL) {
		snprintf(err, errlen, "unknown user %s", user);
		return (-1);
	}
	if (setgroups(1, &pw->pw_gid) != 0 || setgid(pw->pw_gid) != 0 ||
	    setuid(pw->pw_uid) != 0) {
		snprintf(err, errlen, "cannot switch to user %s: %s", user,
		    strerror(errno));
		return (-1);
	}
	if (pw->pw_uid != 0 && (setuid(0) == 0 || seteuid(0) == 0)) {
		snprintf(err, errlen, "root privileges were not dropped");
		return (-1);
	}
	return (0);
}

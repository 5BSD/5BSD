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
    double flush_interval, const char *user, char *err, size_t errlen)
{
	struct oe_otlp_config cfg;
	struct oe_config_request req;

	memset(svc, 0, sizeof(*svc));
	memset(&req, 0, sizeof(req));
	req.scope = service_name;
	req.endpoint = cli_endpoint;
	req.system = 1;
	if (oe_config_load(&svc->env, &req, err, errlen) != 0)
		return (-1);
	if (!svc->env.sysconf->enable) {
		snprintf(err, errlen, "OpenTelemetry is disabled in "
		    "otel.conf (enable = false)");
		return (-1);
	}
	/*
	 * Nothing in the base system listens on the conventional OTLP
	 * port: a service never falls back to it.
	 */
	if (svc->env.endpoint_default) {
		snprintf(err, errlen, "no export target: set endpoint or "
		    "export.target = \"file\" in otel.conf(5) (or "
		    "OTEL_EXPORTER_OTLP_ENDPOINT, or the endpoint option)");
		return (-1);
	}
	if (user != NULL && oe_drop_privileges(user, err, errlen) != 0)
		return (-1);
	oe_host_detect(&svc->host);
	oe_resource_init(&svc->resource, &svc->env, &svc->host, service_name,
	    version);

	memset(&cfg, 0, sizeof(cfg));
	cfg.profile = profile;
	cfg.resource = &svc->resource;
	cfg.flush_interval = flush_interval;
	cfg.max_retries = -1;
	cfg.scope_name = service_name;
	/* OTLP/HTTP, or the otel.conf file target. */
	svc->exporter = oe_exporter_open(&svc->env, &cfg);
	if (svc->exporter == NULL) {
		snprintf(err, errlen, "cannot create the exporter for %s",
		    svc->env.file_path != NULL ? svc->env.file_path :
		    svc->env.endpoint);
		return (-1);
	}
	if (oe_start(svc->exporter) != 0) {
		snprintf(err, errlen, "cannot start the OTLP exporter");
		return (-1);
	}
	return (0);
}

int
oe_service_flush(struct oe_service *svc)
{

	/* OTLP/HTTP batches on its sender thread. */
	if (svc->exporter == NULL || svc->env.file_path == NULL)
		return (0);
	return (oe_flush(svc->exporter));
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

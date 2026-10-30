/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * System OpenTelemetry configuration layer for libotelexport.
 *
 * Precedence, highest first: command line > OTEL_* environment >
 * system configuration (this file's layer) > built-in defaults.
 * The system configuration is the UCL file /etc/otel.conf layered over
 * /etc/defaults/otel.conf; see otel.conf(5).
 */

#ifndef _OE_SYSCONF_H_
#define	_OE_SYSCONF_H_

#include <sys/types.h>

#include <stdint.h>

#include "otelexport.h"

#define	OE_SYSCONF_PATH			"/etc/otel.conf"
#define	OE_SYSCONF_DEFAULTS_PATH	"/etc/defaults/otel.conf"

/* No endpoint: the services refuse to start until one is configured. */
#define	OE_SYSCONF_DEFAULT_ENDPOINT	""
#define	OE_SYSCONF_DEFAULT_PROTOCOL	"http/json"
#define	OE_SYSCONF_DEFAULT_COMPRESSION	"gzip"
#define	OE_SYSCONF_DEFAULT_TIMEOUT_MS	10000
#define	OE_SYSCONF_DEFAULT_HOSTID_FILE	"/etc/hostid"
#define	OE_SYSCONF_DEFAULT_SPOOL_DIR	"/var/spool/otel"
#define	OE_SYSCONF_DEFAULT_EXPORT_DIR	"/var/log/otel"
#define	OE_SYSCONF_DEFAULT_SPOOL_MAX	(256ULL * 1024 * 1024)

/* Hard limits; files or values beyond them are refused. */
#define	OE_SYSCONF_FILE_MAX		(64 * 1024)
#define	OE_SYSCONF_HEADERS_FILE_MAX	(16 * 1024)
#define	OE_SYSCONF_HEADERS_MAX		32
#define	OE_SYSCONF_ATTRS_MAX		32
#define	OE_SYSCONF_KEY_MAX		255
#define	OE_SYSCONF_VALUE_MAX		1024
#define	OE_SYSCONF_SPOOL_MIN		(1ULL * 1024 * 1024)
#define	OE_SYSCONF_SPOOL_LIMIT		(1ULL << 40)
#define	OE_SYSCONF_TIMEOUT_MAX_MS	600000

/*
 * Resolved system configuration.  All strings are owned by the object
 * and released by oe_sysconf_free().
 */
struct oe_sysconf {
	int		 enable;	/* system layer active */
	char		*endpoint;	/* exporter endpoint (base URL); "" unset */
	char		*protocol;	/* exporter protocol: http/json */
	char		*compression;	/* gzip | none */
	int		 timeout_ms;
	char		*headers_file;	/* "" when unset */
	struct oe_attr	*headers;	/* loaded from headers_file */
	size_t		 nheaders;
	char		*host_id_file;	/* "" disables host.id */
	struct oe_attr	*resource_attrs; /* resource block + host.id */
	size_t		 nresource_attrs;
	char		*spool_dir;
	uint64_t	 spool_max_bytes;
	/*
	 * Export target: OTLP/HTTP to endpoint, or OTLP JSON Lines files
	 * <export_dir>/<program>.jsonl.
	 */
	int		 export_file;	/* export.target = "file" */
	char		*export_dir;	/* export.directory */

	char		 error[512];	/* set when a call returns -1 */
};

/* Initialize to built-in defaults (no files read). */
int	oe_sysconf_init(struct oe_sysconf *);

/*
 * Load the defaults file and then the local file over it.  NULL selects
 * the standard path ($OTELCONF_DEFAULTS / $OTELCONF_FILE override it for
 * programs that are not set-id); "" skips that layer.  A missing file is not an
 * error.  On failure returns -1, leaves a description in sc->error and
 * resets sc to built-in defaults.
 */
int	oe_sysconf_load(struct oe_sysconf *, const char *defaults_path,
	    const char *path);

void	oe_sysconf_free(struct oe_sysconf *);

/*
 * Read a credentials file of "Name: value" lines.  The file must be a
 * regular file owned by root or the effective user with no group or
 * other permission bits.  Returns 0 or -1 with err filled in.
 */
int	oe_headers_file_load(const char *path, struct oe_attr **,
	    size_t *, char *err, size_t errlen);
void	oe_attrs_free(struct oe_attr *, size_t);

/*
 * Resolve the exporter settings across all layers: cli_endpoint (NULL
 * when the command line did not name one) > OTEL_* environment
 * (oe_env_load) > system configuration > unset.  Environment entries win
 * over system entries with the same key.  Credentials from the system
 * headers file are added only when the resolved endpoint is the system
 * endpoint, so they never travel to an endpoint chosen elsewhere.
 * String pointers may refer into sc and cli_endpoint, which must outlive
 * env.  Release env with oe_env_free().  Returns 0, or -1 on allocation
 * failure; env is then partially merged but still valid for oe_env_free().
 */
int	oe_env_load_system(struct oe_env *, const struct oe_sysconf *,
	    const char *cli_endpoint);

/*
 * Base system telemetry services (otelpfd(8), otelauditd(8)): one
 * exporter configured through all layers by oe_config_load() (OTLP/HTTP
 * or the file target), refusing to run when the system configuration is
 * disabled or names no export target.  The service name
 * is also the instrumentation scope (the metric and attribute prefix)
 * and names the system spool file.
 */
struct oe_service {
	struct oe_env		 env;	/* owns the otel.conf layer */
	struct oe_host_info	 host;
	struct oe_resource	 resource;
	struct oe_exporter	*exporter;
};

/*
 * Open svc.  service_name is the default service.name (OTEL_SERVICE_NAME
 * wins) and the scope; cli_endpoint may be NULL.  With a user, the
 * process switches to it (oe_drop_privileges()) after reading the
 * configuration and credentials and before creating the exporter, so the
 * spool belongs to that user.  Returns 0, or -1 with err filled in.
 */
int	oe_service_open(struct oe_service *, const char *service_name,
	    const char *version, const char *profile, const char *cli_endpoint,
	    double flush_interval, const char *user, char *err, size_t errlen);
/*
 * Make what svc queued durable now when it exports to the file target
 * (writes the pending OTLP JSON lines, syncs the file, reopens it
 * after rotation); a no-op for OTLP/HTTP, which batches on its own
 * thread.  Call it after each batch of records and at least once a
 * second while records are pending.  Returns 0 or -1.
 */
int	oe_service_flush(struct oe_service *);
/* Flush, stop and release svc (safe on a zeroed or failed svc). */
void	oe_service_close(struct oe_service *);

/*
 * Permanently switch to user's uid, gid and group list.  Returns 0, or
 * -1 with err filled in.  Root only; verifies root cannot be regained.
 */
int	oe_drop_privileges(const char *user, char *err, size_t errlen);

#endif /* !_OE_SYSCONF_H_ */

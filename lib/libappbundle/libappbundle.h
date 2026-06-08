/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libappbundle — parse and validate 5BSD .app bundles.
 *
 * A bundle is a self-contained application directory:
 *   Name.app/Contents/5BSD/Services/svc.ucl  (service manifests)
 *   Name.app/Contents/bin/program            (executables)
 *   <Name>.app/Contents/Resources/           (optional data)
 *
 * Each Service.ucl declares bundle metadata (bundle_id, version, author)
 * alongside its service definition (program, provides, requires, etc.).
 */

#ifndef LIBAPPBUNDLE_H
#define LIBAPPBUNDLE_H

#include <sys/types.h>
#include <stdbool.h>

/* Limits */
#define	APPBUNDLE_MAX_SERVICES		32
#define	APPBUNDLE_MAX_PROVIDES		8
#define	APPBUNDLE_MAX_REQUIRES		8
#define	APPBUNDLE_ID_MAX		128
#define	APPBUNDLE_VERSION_MAX		32
#define	APPBUNDLE_AUTHOR_MAX		128
#define	APPBUNDLE_NAME_MAX		255

struct appbundle;
struct appbundle_service;

/*
 * Open and parse a .app bundle directory.
 * Returns 0 on success, -1 on error (details in errbuf if non-NULL).
 */
int	appbundle_open(const char *path, struct appbundle **bp,
	    char *errbuf, size_t errlen);
void	appbundle_close(struct appbundle *b);

/* Bundle-level accessors. */
const char	*appbundle_id(const struct appbundle *b);
const char	*appbundle_version(const struct appbundle *b);
const char	*appbundle_author(const struct appbundle *b);
const char	*appbundle_path(const struct appbundle *b);
const char	*appbundle_name(const struct appbundle *b);  /* dir basename */

/* Service enumeration. */
unsigned	 appbundle_nservices(const struct appbundle *b);
struct appbundle_service *appbundle_service(const struct appbundle *b,
		    unsigned idx);

/* Service accessors. */
const char	*appbundle_svc_program(const struct appbundle_service *s);
const char	*appbundle_svc_label(const struct appbundle_service *s);
unsigned	 appbundle_svc_nprovides(const struct appbundle_service *s);
const char	*appbundle_svc_provides(const struct appbundle_service *s,
		    unsigned idx);
unsigned	 appbundle_svc_nrequires(const struct appbundle_service *s);
const char	*appbundle_svc_requires(const struct appbundle_service *s,
		    unsigned idx);
bool		 appbundle_svc_on_demand(const struct appbundle_service *s);
int		 appbundle_svc_restart(const struct appbundle_service *s);
uint32_t	 appbundle_svc_cap_system(const struct appbundle_service *s);

/* Capability accessors */
unsigned	 appbundle_svc_ncap_paths(const struct appbundle_service *s);
const char	*appbundle_svc_cap_path(const struct appbundle_service *s,
		    unsigned idx);
unsigned	 appbundle_svc_ncap_net(const struct appbundle_service *s);
unsigned	 appbundle_svc_ncap_jail(const struct appbundle_service *s);

/*
 * Fill a svc_manifest struct from a bundle service.
 * This is the preferred way to get a complete manifest — handles all
 * capability fields, not just system gates.
 * Caller provides the struct; function fills all fields.
 * Returns 0 on success, -1 on error.
 */
struct svc_manifest;
int	appbundle_svc_fill_manifest(const struct appbundle_service *s,
	    struct svc_manifest *m);

/*
 * Validate bundle integrity.
 * Checks structure, required fields, binary existence, internal consistency.
 * Returns 0 if valid, -1 with details in errbuf.
 */
int	appbundle_verify(const struct appbundle *b, char *errbuf, size_t errlen);

/*
 * Check for circular dependencies across multiple bundles.
 * Builds a global dependency graph from all provides/requires declarations.
 * Returns 0 if acyclic, -1 with cycle description in errbuf.
 */
int	appbundle_check_cycles(struct appbundle **bundles, unsigned nbundles,
	    char *errbuf, size_t errlen);

/*
 * Scan a directory for .app bundles.
 * Calls cb for each successfully opened bundle.
 * If cb returns non-zero, scanning stops and that value is returned.
 * Returns 0 on success, -1 on directory error.
 * Bundles that fail to open are logged and skipped.
 */
typedef int (*appbundle_scan_cb)(struct appbundle *b, void *ctx);
int	appbundle_scan_dir(const char *dirpath, appbundle_scan_cb cb, void *ctx);

/* Restart policy constants (matches serviced). */
#define	APPBUNDLE_RESTART_NEVER		0
#define	APPBUNDLE_RESTART_ALWAYS	1
#define	APPBUNDLE_RESTART_ON_FAILURE	2

#endif /* LIBAPPBUNDLE_H */

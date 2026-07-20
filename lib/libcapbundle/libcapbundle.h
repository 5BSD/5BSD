/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle — parse and validate 5BSD .cap bundles.
 *
 * A bundle is a self-contained application directory:
 *   Name.cap/etc/svc.ucl          (service manifests)
 *   Name.cap/bin/program           (executables)
 *   Name.cap/resources/            (optional data)
 *
 * Each Service.ucl declares bundle metadata (bundle_id, version, author)
 * alongside its service definition (program, provides, requires, etc.).
 */

#ifndef LIBCAPBUNDLE_H
#define LIBCAPBUNDLE_H

#include <sys/types.h>
#include <stdbool.h>

/* Limits */
#define	CAPBUNDLE_MAX_SERVICES		32
#define	CAPBUNDLE_MAX_PROVIDES		8
#define	CAPBUNDLE_MAX_REQUIRES		8
#define	CAPBUNDLE_ID_MAX		128
#define	CAPBUNDLE_VERSION_MAX		32
#define	CAPBUNDLE_AUTHOR_MAX		128
#define	CAPBUNDLE_NAME_MAX		255

struct capbundle;
struct capbundle_service;

/*
 * Open and parse a .cap bundle directory.
 * Returns 0 on success, -1 on error (details in errbuf if non-NULL).
 */
int	capbundle_open(const char *path, struct capbundle **bp,
	    char *errbuf, size_t errlen);
void	capbundle_close(struct capbundle *b);

/* Bundle-level accessors. */
const char	*capbundle_id(const struct capbundle *b);
const char	*capbundle_version(const struct capbundle *b);
const char	*capbundle_author(const struct capbundle *b);
const char	*capbundle_path(const struct capbundle *b);
const char	*capbundle_name(const struct capbundle *b);  /* dir basename */

/* Service enumeration. */
unsigned	 capbundle_nservices(const struct capbundle *b);
struct capbundle_service *capbundle_service(const struct capbundle *b,
		    unsigned idx);

/* Service accessors. */
const char	*capbundle_svc_program(const struct capbundle_service *s);
const char	*capbundle_svc_label(const struct capbundle_service *s);
unsigned	 capbundle_svc_nprovides(const struct capbundle_service *s);
const char	*capbundle_svc_provides(const struct capbundle_service *s,
		    unsigned idx);
unsigned	 capbundle_svc_nrequires(const struct capbundle_service *s);
const char	*capbundle_svc_requires(const struct capbundle_service *s,
		    unsigned idx);
bool		 capbundle_svc_on_demand(const struct capbundle_service *s);
unsigned	 capbundle_svc_narguments(const struct capbundle_service *s);
const char	*capbundle_svc_argument(const struct capbundle_service *s,
		    unsigned idx);
unsigned	 capbundle_svc_nenvironment(const struct capbundle_service *s);
const char	*capbundle_svc_environment(const struct capbundle_service *s,
		    unsigned idx);

/*
 * Fill a svc_manifest struct from a bundle service.
 * This is the preferred way to get a complete manifest — handles all
 * capability fields, not just system gates.
 * Caller provides the struct; function fills all fields.
 * Returns 0 on success, -1 on error.
 */
struct svc_manifest;
int	capbundle_svc_fill_manifest(const struct capbundle_service *s,
	    struct svc_manifest *m);

/*
 * Validate bundle integrity.
 * Checks structure, required fields, binary existence, internal consistency.
 * Returns 0 if valid, -1 with details in errbuf.
 */
int	capbundle_verify(const struct capbundle *b, char *errbuf, size_t errlen);

/*
 * Check for circular dependencies across multiple bundles.
 * Builds a global dependency graph from all provides/requires declarations.
 * Returns 0 if acyclic, -1 with cycle description in errbuf.
 */
int	capbundle_check_cycles(struct capbundle **bundles, unsigned nbundles,
	    char *errbuf, size_t errlen);

/*
 * Scan a directory for .cap bundles.
 * Calls cb for each successfully opened bundle.
 * If cb returns non-zero, scanning stops and that value is returned.
 * Returns 0 on success, -1 on a directory or malformed-bundle error.
 * Invalid bundles stop the scan; declarations are never silently skipped.
 */
typedef int (*capbundle_scan_cb)(struct capbundle *b, void *ctx);
int	capbundle_scan_dir(const char *dirpath, capbundle_scan_cb cb, void *ctx);

/* Restart policy constants (matches serviced). */
#define	CAPBUNDLE_RESTART_NEVER		0
#define	CAPBUNDLE_RESTART_ALWAYS	1
#define	CAPBUNDLE_RESTART_ON_FAILURE	2

#endif /* LIBCAPBUNDLE_H */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle — bundle verification and cycle detection.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <fts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcapbundle_internal.h"

/* --- Verification --- */

static int
verify_tree_shape(const char *path, char *errbuf, size_t errlen)
{
	FTS *fts;
	FTSENT *ent;
	char *paths[2];
	uint64_t total;
	unsigned entries;

	paths[0] = __DECONST(char *, path);
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: %s", path, strerror(errno));
		return (-1);
	}
	entries = 0;
	total = 0;
	for (;;) {
		errno = 0;
		ent = fts_read(fts);
		if (ent == NULL)
			break;
		if (ent->fts_info == FTS_DP)
			continue;
		if (++entries > CAPBUNDLE_MAX_TREE_ENTRIES) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: bundle exceeds %u tree entries", path,
				    CAPBUNDLE_MAX_TREE_ENTRIES);
			(void)fts_close(fts);
			return (-1);
		}
		if (ent->fts_info != FTS_D && ent->fts_info != FTS_F) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: symlink or non-regular object is not allowed",
				    ent->fts_path);
			(void)fts_close(fts);
			return (-1);
		}
		if (ent->fts_info == FTS_F &&
		    (ent->fts_statp->st_size < 0 ||
		    (uint64_t)ent->fts_statp->st_size > CAPBUNDLE_MAX_FILE_SIZE ||
		    (uint64_t)ent->fts_statp->st_size >
		    CAPBUNDLE_MAX_TREE_SIZE - total)) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: bundle file or total size exceeds limit",
				    ent->fts_path);
			(void)fts_close(fts);
			return (-1);
		}
		if (ent->fts_info == FTS_F)
			total += (uint64_t)ent->fts_statp->st_size;
	}
	if (errno != 0) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: traversal failed: %s", path,
			    strerror(errno));
		(void)fts_close(fts);
		return (-1);
	}
	(void)fts_close(fts);
	return (0);
}

int
capbundle_verify(const struct capbundle *b, char *errbuf, size_t errlen)
{
	unsigned i, j, k;
	struct stat sb;

	if (b == NULL) {
		errno = EINVAL;
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "bundle is required");
		return (-1);
	}
	if (verify_tree_shape(b->path, errbuf, errlen) != 0)
		return (-1);

	if (b->bundle_id[0] == '\0') {
		if (errbuf)
			snprintf(errbuf, errlen,
			    "%s: no bundle_id in any service", b->name);
		return (-1);
	}

	for (i = 0; i < b->nservices; i++) {
		const struct capbundle_service *s = &b->services[i];

		/* Binary must exist and be executable. */
		if (stat(s->program, &sb) == -1) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: binary not found: %s",
				    b->name, s->program);
			return (-1);
		}
		if (!S_ISREG(sb.st_mode) || !(sb.st_mode & S_IXUSR)) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: not executable: %s",
				    b->name, s->program);
			return (-1);
		}

		/*
		 * Activation is explicit; a unit must declare at least one
		 * trigger — boot, an IPC endpoint, a timer, or a path (Phase 5).
		 */
		if (!s->activation_boot && s->nprovides == 0 &&
		    s->timer_interval_sec == 0 && s->activation_path[0] == '\0') {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: unit '%s' has no activation trigger",
				    b->name, s->label);
			return (-1);
		}
		if (strlen(s->label) >= SERVICED_LABEL_MAX) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: service label too long: %s",
				    b->name, s->label);
			return (-1);
		}
		for (j = 0; j < s->nprovides; j++) {
			if (strlen(s->provides[j]) >= SERVICED_LABEL_MAX) {
				if (errbuf)
					snprintf(errbuf, errlen,
					    "%s: provides name too long: %s",
					    b->name, s->provides[j]);
				return (-1);
			}
			for (k = j + 1; k < s->nprovides; k++) {
				if (strcmp(s->provides[j], s->provides[k]) == 0) {
					if (errbuf)
						snprintf(errbuf, errlen,
						    "%s: duplicate provides '%s'",
						    b->name, s->provides[j]);
					return (-1);
				}
			}
		}
		/* Check for duplicate provides within the bundle. */
		for (j = 0; j < i; j++) {
			const struct capbundle_service *prev = &b->services[j];
			for (k = 0; k < s->nprovides; k++) {
				unsigned m;
				for (m = 0; m < prev->nprovides; m++) {
					if (strcmp(s->provides[k],
					    prev->provides[m]) == 0) {
						if (errbuf)
							snprintf(errbuf, errlen,
							    "%s: duplicate provides '%s'",
							    b->name, s->provides[k]);
						return (-1);
					}
				}
			}
		}
	}

	return (0);
}

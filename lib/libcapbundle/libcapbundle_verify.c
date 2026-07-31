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

	paths[0] = __DECONST(char *, path);
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		if (errbuf != NULL)
			snprintf(errbuf, errlen, "%s: %s", path, strerror(errno));
		return (-1);
	}
	errno = 0;
	while ((ent = fts_read(fts)) != NULL) {
		if (ent->fts_info == FTS_DP)
			continue;
		if (ent->fts_info != FTS_D && ent->fts_info != FTS_F) {
			if (errbuf != NULL)
				snprintf(errbuf, errlen,
				    "%s: symlink or non-regular object is not allowed",
				    ent->fts_path);
			(void)fts_close(fts);
			return (-1);
		}
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
		 * A service with no exported names is an eager boot task.
		 * Exported names turn the service into an on-demand provider.
		 */
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
		for (j = 0; j < s->nstartup_after; j++) {
			if (strlen(s->startup_after[j]) >= SERVICED_LABEL_MAX) {
				if (errbuf)
					snprintf(errbuf, errlen,
					    "%s: startup edge name too long: %s",
					    b->name, s->startup_after[j]);
				return (-1);
			}
			for (k = j + 1; k < s->nstartup_after; k++) {
				if (strcmp(s->startup_after[j],
				    s->startup_after[k]) == 0) {
					if (errbuf)
						snprintf(errbuf, errlen,
						    "%s: duplicate startup edge '%s'",
						    b->name,
						    s->startup_after[j]);
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

		/* A component consumer cannot also be its own factory. */
		for (j = 0; j < s->nstartup_after; j++) {
			for (k = 0; k < s->nprovides; k++) {
				if (strcmp(s->startup_after[j],
				    s->provides[k]) == 0) {
					if (errbuf)
						snprintf(errbuf, errlen,
						    "%s: '%s' has a self startup edge",
						    b->name, s->label);
					return (-1);
				}
			}
		}
	}

	return (0);
}

/* --- Cycle Detection (Kahn's Algorithm) --- */

int
capbundle_check_startup_cycles(struct capbundle **bundles, unsigned nbundles,
    char *errbuf, size_t errlen)
{
	/*
	 * Build adjacency from provides to internal component-startup edges.
	 * Each provides name is a node.  An edge exists from node A to
	 * node B if the service providing B must start after A.
	 *
	 * Use a simple flat array of all service nodes.
	 */
	struct node {
		const char *name;		/* first provides name = identity */
		unsigned in_degree;
		unsigned *deps;
		unsigned ndeps;
	};
	struct node *nodes;
	unsigned nnodes, cap;
	unsigned i, j, k, bi, si;
	unsigned *queue, qhead, qtail, processed;

	/* Count total services. */
	cap = 0;
	for (bi = 0; bi < nbundles; bi++)
		cap += bundles[bi]->nservices;

	if (cap == 0)
		return (0);

	nodes = calloc(cap, sizeof(*nodes));
	queue = calloc(cap, sizeof(*queue));
	if (nodes == NULL || queue == NULL) {
		free(nodes);
		free(queue);
		if (errbuf)
			snprintf(errbuf, errlen, "out of memory");
		return (-1);
	}
	for (i = 0; i < cap; i++) {
		nodes[i].deps = calloc(cap, sizeof(*nodes[i].deps));
		if (nodes[i].deps == NULL) {
			while (i > 0)
				free(nodes[--i].deps);
			free(nodes);
			free(queue);
			if (errbuf)
				snprintf(errbuf, errlen, "out of memory");
			return (-1);
		}
	}

	/* Populate nodes. */
	nnodes = 0;
	for (bi = 0; bi < nbundles; bi++) {
		for (si = 0; si < bundles[bi]->nservices; si++) {
			nodes[nnodes].name = bundles[bi]->services[si].label;
			nodes[nnodes].in_degree = 0;
			nodes[nnodes].ndeps = 0;
			nnodes++;
		}
	}

	/*
	 * Build edges: for each service's startup_after[], find the node that
	 * provides that name, and add an edge (provider -> this service).
	 */
	nnodes = 0;
	for (bi = 0; bi < nbundles; bi++) {
		for (si = 0; si < bundles[bi]->nservices; si++) {
			const struct capbundle_service *svc =
			    &bundles[bi]->services[si];

			for (j = 0; j < svc->nstartup_after; j++) {
				/* Find provider of this requirement. */
				unsigned provider_idx = (unsigned)-1;
				unsigned ni = 0;

				for (unsigned b2 = 0; b2 < nbundles; b2++) {
					for (unsigned s2 = 0;
					    s2 < bundles[b2]->nservices; s2++) {
						const struct capbundle_service *p =
						    &bundles[b2]->services[s2];
						for (k = 0; k < p->nprovides; k++) {
							if (strcmp(p->provides[k],
							    svc->startup_after[j]) == 0) {
								provider_idx = ni;
								goto found;
							}
						}
						ni++;
					}
				}
found:
				if (provider_idx != (unsigned)-1) {
					/* Edge: provider -> this node */
					nodes[provider_idx].deps[
					    nodes[provider_idx].ndeps++] = nnodes;
					nodes[nnodes].in_degree++;
				}
			}
			nnodes++;
		}
	}

	/* Kahn's algorithm: process nodes with in_degree == 0. */
	qhead = qtail = 0;
	for (i = 0; i < nnodes; i++) {
		if (nodes[i].in_degree == 0)
			queue[qtail++] = i;
	}

	processed = 0;
	while (qhead < qtail) {
		unsigned cur = queue[qhead++];
		processed++;
		for (j = 0; j < nodes[cur].ndeps; j++) {
			unsigned dep = nodes[cur].deps[j];
			nodes[dep].in_degree--;
			if (nodes[dep].in_degree == 0)
				queue[qtail++] = dep;
		}
	}

	free(queue);

	if (processed < nnodes) {
		/* Cycle detected -- find a participating node. */
		if (errbuf) {
			for (i = 0; i < nnodes; i++) {
				if (nodes[i].in_degree > 0) {
					snprintf(errbuf, errlen,
					    "circular dependency involving '%s'",
					    nodes[i].name);
					break;
				}
			}
		}
		for (i = 0; i < cap; i++)
			free(nodes[i].deps);
		free(nodes);
		return (-1);
	}

	for (i = 0; i < cap; i++)
		free(nodes[i].deps);
	free(nodes);
	return (0);
}

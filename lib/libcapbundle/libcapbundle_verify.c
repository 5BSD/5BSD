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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcapbundle_internal.h"

/* --- Verification --- */

int
capbundle_verify(const struct capbundle *b, char *errbuf, size_t errlen)
{
	unsigned i, j, k;
	struct stat sb;

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

		/* Must provide at least one name. */
		if (s->nprovides == 0) {
			if (errbuf)
				snprintf(errbuf, errlen,
				    "%s: service '%s' has no provides",
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
		}
		for (j = 0; j < s->nrequires; j++) {
			if (strlen(s->requires[j]) >= SERVICED_LABEL_MAX) {
				if (errbuf)
					snprintf(errbuf, errlen,
					    "%s: requires name too long: %s",
					    b->name, s->requires[j]);
				return (-1);
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

		/* Intra-bundle cycle: service requires its own provides. */
		for (j = 0; j < s->nrequires; j++) {
			for (k = 0; k < s->nprovides; k++) {
				if (strcmp(s->requires[j],
				    s->provides[k]) == 0) {
					if (errbuf)
						snprintf(errbuf, errlen,
						    "%s: '%s' requires itself",
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
capbundle_check_cycles(struct capbundle **bundles, unsigned nbundles,
    char *errbuf, size_t errlen)
{
	/*
	 * Build adjacency from provides -> requires.
	 * Each provides name is a node.  An edge exists from node A to
	 * node B if the service providing B requires A.
	 *
	 * Use a simple flat array of all service nodes.
	 */
	struct node {
		const char *name;		/* first provides name = identity */
		unsigned in_degree;
		unsigned deps[CAPBUNDLE_MAX_REQUIRES];
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
	 * Build edges: for each service's requires[], find the node that
	 * provides that name, and add an edge (provider -> this service).
	 */
	nnodes = 0;
	for (bi = 0; bi < nbundles; bi++) {
		for (si = 0; si < bundles[bi]->nservices; si++) {
			const struct capbundle_service *svc =
			    &bundles[bi]->services[si];

			for (j = 0; j < svc->nrequires; j++) {
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
							    svc->requires[j]) == 0) {
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
					if (nodes[provider_idx].ndeps <
					    CAPBUNDLE_MAX_REQUIRES) {
						nodes[provider_idx].deps[
						    nodes[provider_idx].ndeps++] =
						    nnodes;
					} else {
						/*
						 * Truncating edges: cycle
						 * detection may miss cycles
						 * involving this provider.
						 */
						warnx("capbundle: provider "
						    "'%s' has too many "
						    "dependents for cycle "
						    "detection (max %d)",
						    nodes[provider_idx].name,
						    CAPBUNDLE_MAX_REQUIRES);
					}
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
		free(nodes);
		return (-1);
	}

	free(nodes);
	return (0);
}

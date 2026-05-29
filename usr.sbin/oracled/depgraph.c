/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Dependency graph for oracled service manifests.
 *
 * Topological sort using Kahn's algorithm.  Reorders the service
 * array in-place so that startup iterates forward and shutdown
 * iterates backward.  Cycle detection is fatal — no services
 * launch if a cycle exists.
 */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "oracled.h"

/*
 * Find which service provides a given capability name.
 * Returns the index into svcs[], or -1 if not found.
 * "ORACLED" is always satisfied (implicit provider).
 */
static int
find_provider(struct svc_runtime *svcs, unsigned nsvc, const char *name)
{
	unsigned i, j;

	if (strcmp(name, "ORACLED") == 0)
		return (-2);	/* sentinel: always satisfied */

	for (i = 0; i < nsvc; i++) {
		for (j = 0; j < svcs[i].manifest.nprovides; j++) {
			if (strcmp(svcs[i].manifest.provides[j], name) == 0)
				return ((int)i);
		}
	}
	return (-1);
}

/*
 * Check for duplicate labels and duplicate provides names.
 * Logs warnings but does not fail — first-wins semantics.
 */
static void
check_duplicates(struct svc_runtime *svcs, unsigned nsvc)
{
	unsigned i, j, pi, pj;

	for (i = 0; i < nsvc; i++) {
		for (j = i + 1; j < nsvc; j++) {
			if (strcmp(svcs[i].manifest.label,
			    svcs[j].manifest.label) == 0)
				syslog(LOG_WARNING, "depgraph: duplicate "
				    "label '%s' (files will shadow)",
				    svcs[i].manifest.label);
		}
		for (pi = 0; pi < svcs[i].manifest.nprovides; pi++) {
			for (j = i + 1; j < nsvc; j++) {
				for (pj = 0; pj < svcs[j].manifest.nprovides;
				    pj++) {
					if (strcmp(
					    svcs[i].manifest.provides[pi],
					    svcs[j].manifest.provides[pj])
					    == 0)
						syslog(LOG_WARNING,
						    "depgraph: '%s' and '%s' "
						    "both provide '%s'",
						    svcs[i].manifest.label,
						    svcs[j].manifest.label,
						    svcs[i].manifest.provides[pi]);
				}
			}
		}
	}
}

int
depgraph_sort(struct svc_runtime *svcs, unsigned nsvc)
{
	/*
	 * adj[i][j] = 1 means service i depends on service j
	 * (j must start before i).
	 */
	uint8_t adj[ORACLED_MAX_SERVICES][ORACLED_MAX_SERVICES];
	unsigned indeg[ORACLED_MAX_SERVICES];
	unsigned queue[ORACLED_MAX_SERVICES];
	unsigned order[ORACLED_MAX_SERVICES];
	unsigned qhead, qtail, sorted;
	struct svc_runtime *tmp;
	unsigned i, k;
	int provider, rv;

	if (nsvc == 0)
		return (0);
	if (nsvc > ORACLED_MAX_SERVICES)
		return (-1);

	check_duplicates(svcs, nsvc);

	memset(adj, 0, sizeof(adj));
	memset(indeg, 0, sizeof(indeg));

	/* Build adjacency matrix from requires -> provides. */
	for (i = 0; i < nsvc; i++) {
		for (k = 0; k < svcs[i].manifest.nrequires; k++) {
			provider = find_provider(svcs, nsvc,
			    svcs[i].manifest.requires[k]);
			if (provider == -2)
				continue;	/* ORACLED — always satisfied */
			if (provider == -1) {
				syslog(LOG_WARNING, "depgraph: %s requires "
				    "unknown provider '%s', treating as "
				    "satisfied", svcs[i].manifest.label,
				    svcs[i].manifest.requires[k]);
				continue;
			}
			if ((unsigned)provider == i)
				continue;	/* self-dep, ignore */
			if (!adj[i][provider]) {
				adj[i][provider] = 1;
				indeg[i]++;
			}
		}
	}

	/* Kahn's algorithm: BFS from nodes with in-degree 0. */
	qhead = qtail = sorted = 0;
	for (i = 0; i < nsvc; i++) {
		if (indeg[i] == 0)
			queue[qtail++] = i;
	}

	while (qhead < qtail) {
		unsigned cur = queue[qhead++];
		order[sorted++] = cur;

		/* Reduce in-degree of dependents. */
		for (i = 0; i < nsvc; i++) {
			if (adj[i][cur]) {
				adj[i][cur] = 0;
				if (--indeg[i] == 0)
					queue[qtail++] = i;
			}
		}
	}

	if (sorted < nsvc) {
		syslog(LOG_ERR, "depgraph: cycle detected, refusing to "
		    "start services");
		for (i = 0; i < nsvc; i++) {
			if (indeg[i] > 0)
				syslog(LOG_ERR, "depgraph: service '%s' is "
				    "in a dependency cycle",
				    svcs[i].manifest.label);
		}
		return (-1);
	}

	/* Reorder svcs[] in-place using the topological order. */
	tmp = calloc(nsvc, sizeof(*tmp));
	if (tmp == NULL) {
		syslog(LOG_ERR, "depgraph: calloc: %m");
		return (-1);
	}

	rv = 0;
	for (i = 0; i < nsvc; i++)
		tmp[i] = svcs[order[i]];
	for (i = 0; i < nsvc; i++)
		svcs[i] = tmp[i];
	free(tmp);

	syslog(LOG_INFO, "depgraph: sorted %u services", nsvc);
	return (rv);
}

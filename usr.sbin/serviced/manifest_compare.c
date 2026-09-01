/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <stdbool.h>
#include <string.h>

#include "manifest_compare.h"

bool
serviced_manifest_equal(const struct svc_manifest *a,
    const struct svc_manifest *b)
{
	unsigned i;

	if (strcmp(a->label, b->label) != 0 ||
	    strcmp(a->program, b->program) != 0 ||
	    strcmp(a->user, b->user) != 0 ||
	    strcmp(a->group, b->group) != 0 ||
	    a->narguments != b->narguments ||
	    a->nenvironment != b->nenvironment ||
	    a->restart != b->restart ||
	    a->management != b->management ||
	    a->stop_timeout != b->stop_timeout ||
	    a->max_failures != b->max_failures ||
	    a->nprovides != b->nprovides ||
	    a->ncap_paths != b->ncap_paths ||
	    a->ncap_net != b->ncap_net ||
	    a->ncap_vsock != b->ncap_vsock ||
	    a->ncap_services != b->ncap_services ||
	    a->cap_system != b->cap_system ||
	    a->protect_flags != b->protect_flags ||
	    a->privileged != b->privileged ||
	    a->timer_interval_sec != b->timer_interval_sec ||
	    strcmp(a->activation_path, b->activation_path) != 0)
		return (false);
	for (i = 0; i < a->narguments; i++)
		if (strcmp(a->arguments[i], b->arguments[i]) != 0)
			return (false);
	for (i = 0; i < a->nenvironment; i++)
		if (strcmp(a->environment[i], b->environment[i]) != 0)
			return (false);
	/* Compare only populated entries; unused trailing bytes are irrelevant. */
	for (i = 0; i < a->nprovides; i++)
		if (strcmp(a->provides[i], b->provides[i]) != 0)
			return (false);
	for (i = 0; i < a->ncap_paths; i++)
		if (strcmp(a->cap_paths[i], b->cap_paths[i]) != 0)
			return (false);
	for (i = 0; i < a->ncap_net; i++)
		if (memcmp(&a->cap_net[i], &b->cap_net[i],
		    sizeof(a->cap_net[i])) != 0)
			return (false);
	for (i = 0; i < a->ncap_vsock; i++)
		if (memcmp(&a->cap_vsock[i], &b->cap_vsock[i],
		    sizeof(a->cap_vsock[i])) != 0)
			return (false);
	for (i = 0; i < a->ncap_services; i++)
		if (strcmp(a->cap_services[i], b->cap_services[i]) != 0)
			return (false);
	return (true);
}

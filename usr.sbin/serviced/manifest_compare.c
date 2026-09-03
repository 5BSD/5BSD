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
	    a->cap_system != b->cap_system ||
	    a->protect_flags != b->protect_flags ||
	    a->privileged != b->privileged ||
	    a->timer_interval_sec != b->timer_interval_sec ||
	    strcmp(a->activation_path, b->activation_path) != 0 ||
	    strcmp(a->queue_directory, b->queue_directory) != 0 ||
	    a->activation_on_mount != b->activation_on_mount ||
	    a->has_calendar != b->has_calendar ||
	    a->calendar_persistent != b->calendar_persistent ||
	    (a->has_calendar &&
	    memcmp(&a->calendar, &b->calendar, sizeof(a->calendar)) != 0) ||
	    a->nactivation_sockets != b->nactivation_sockets)
		return (false);
	/*
	 * Compare every activation source, not just the timer and path: a change
	 * to a socket listener, queue directory, mount watch, or calendar must be
	 * detected on reload, or the change is silently dropped (the unit keeps its
	 * old activation).  Socket entries mix scalars, a binary address, and path
	 * strings, so compare field by field rather than memcmp (trailing bytes).
	 */
	for (i = 0; i < a->nactivation_sockets; i++) {
		const struct svc_activation_socket *sa = &a->activation_sockets[i];
		const struct svc_activation_socket *sb = &b->activation_sockets[i];

		if (strcmp(sa->name, sb->name) != 0 ||
		    sa->domain != sb->domain || sa->socktype != sb->socktype ||
		    sa->port != sb->port || sa->backlog != sb->backlog ||
		    memcmp(sa->addr, sb->addr, sizeof(sa->addr)) != 0 ||
		    strcmp(sa->unixpath, sb->unixpath) != 0)
			return (false);
	}
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
	return (true);
}

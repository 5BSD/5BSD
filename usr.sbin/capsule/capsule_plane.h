/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Capsule plane-free boot decision.
 *
 * The loader knob capability_plane="NO" (or off/0) tells Capsule to hand PID 1
 * to stock /sbin/init and never start the capability plane — the recovery and
 * mac_capability-device-test escape hatch (docs/plane-free-boot).  The value ->
 * "disable the plane" test is factored out of capsule.c capsule_main() here so
 * the exact set of accepted spellings is pinned by a unit test.  The caller
 * still owns kenv(2) presence: this predicate speaks only to the value string.
 */
#ifndef CAPSULE_PLANE_H
#define CAPSULE_PLANE_H

#include <stdbool.h>
#include <strings.h>
#include <string.h>

/*
 * True when kenv_value requests a plane-free boot.  Accepts "NO"/"off"
 * case-insensitively and the exact digit "0"; every other value (including
 * "yes", "1", "", and typos) keeps the plane.
 */
static inline bool
capsule_plane_disabled(const char *kenv_value)
{

	if (kenv_value == NULL)
		return (false);
	return (strcasecmp(kenv_value, "NO") == 0 ||
	    strcasecmp(kenv_value, "off") == 0 ||
	    strcmp(kenv_value, "0") == 0);
}

#endif /* CAPSULE_PLANE_H */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared UCL parsers for network and jail claims.
 *
 * Compiled into both oracled and serviced.  The struct types
 * (oracled_net_claim / serviced_net_claim etc.) have identical
 * field layout, so callers cast as needed.  These functions
 * operate on the raw UCL tree and write to struct members by
 * offset-compatible pointers.
 */

#include <sys/socket.h>
#include <netinet/in.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include "claim_parse.h"

int
parse_port_range_string(const char *s, uint16_t *minp, uint16_t *maxp)
{
	char *end;
	unsigned long first, last;

	if (strcmp(s, "*") == 0) {
		*minp = 0;
		*maxp = UINT16_MAX;
		return (0);
	}
	if (s[0] == '.' || s[0] == '<') {
		first = strtoul(s + 1, &end, 10);
		if (*end != '\0' || first == 0 || first > UINT16_MAX + 1UL)
			return (-1);
		*minp = 0;
		*maxp = (uint16_t)(first - 1);
		return (0);
	}

	first = strtoul(s, &end, 10);
	if (end == s || first > UINT16_MAX)
		return (-1);
	if (*end == '\0') {
		*minp = (uint16_t)first;
		*maxp = (uint16_t)first;
		return (0);
	}
	if (*end != '-')
		return (-1);
	last = strtoul(end + 1, &end, 10);
	if (*end != '\0' || last > UINT16_MAX || first > last)
		return (-1);
	*minp = (uint16_t)first;
	*maxp = (uint16_t)last;
	return (0);
}

int
parse_port_range_obj(const ucl_object_t *v, uint16_t *minp, uint16_t *maxp)
{
	int64_t pv;

	if (v == NULL)
		return (0);
	if (ucl_object_type(v) == UCL_INT) {
		pv = ucl_object_toint(v);
		if (pv < 0 || pv > UINT16_MAX)
			return (-1);
		if (pv == 0) {
			*minp = 0;
			*maxp = UINT16_MAX;
		} else {
			*minp = (uint16_t)pv;
			*maxp = (uint16_t)pv;
		}
		return (0);
	}
	if (ucl_object_type(v) == UCL_STRING)
		return (parse_port_range_string(ucl_object_tostring(v),
		    minp, maxp));
	return (-1);
}

int
parse_jail_action_string(const char *s, uint32_t *actionsp)
{

	if (strcmp(s, "*") == 0 || strcmp(s, "all") == 0)
		*actionsp |= FI_JAIL_ALL;
	else if (strcmp(s, "create") == 0)
		*actionsp |= FI_JAIL_CREATE;
	else if (strcmp(s, "get") == 0)
		*actionsp |= FI_JAIL_GET;
	else if (strcmp(s, "set") == 0)
		*actionsp |= FI_JAIL_SET;
	else if (strcmp(s, "remove") == 0)
		*actionsp |= FI_JAIL_REMOVE;
	else if (strcmp(s, "attach") == 0)
		*actionsp |= FI_JAIL_ATTACH;
	else
		return (-1);
	return (0);
}

int
parse_jail_actions(const ucl_object_t *v, uint32_t *actionsp)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;

	*actionsp = 0;
	if (v == NULL) {
		*actionsp = FI_JAIL_ALL;
		return (0);
	}
	if (ucl_object_type(v) == UCL_STRING)
		return (parse_jail_action_string(ucl_object_tostring(v),
		    actionsp));
	if (ucl_object_type(v) != UCL_ARRAY)
		return (-1);
	it = NULL;
	while ((elem = ucl_object_iterate(v, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			return (-1);
		if (parse_jail_action_string(ucl_object_tostring(elem),
		    actionsp) != 0)
			return (-1);
	}
	return (*actionsp != 0 ? 0 : -1);
}

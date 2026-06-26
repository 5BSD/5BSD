/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared UCL parsers for network and jail claims.
 *
 * Shared between oracled, serviced, and libcapbundle via
 * liboraclert.  All callers use struct ort_net_claim (from
 * oraclert.h) as the canonical network claim type.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <ucl.h>

#include <dev/mac_capability/mac_capability_isolation_proto.h>

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
parse_address_string(const char *s, uint8_t addr[16],
    uint8_t *prefixp, int *domainp)
{
	char buf[INET6_ADDRSTRLEN];
	const char *slash;
	struct in_addr v4;
	struct in6_addr v6;
	unsigned long pfx;
	char *end;
	size_t len;

	memset(addr, 0, 16);
	*prefixp = 0;
	*domainp = 0;

	if (strcmp(s, "*") == 0)
		return (0);

	/* Split address and optional /prefix. */
	slash = strchr(s, '/');
	if (slash != NULL) {
		len = (size_t)(slash - s);
		if (len == 0 || len >= sizeof(buf))
			return (-1);
		memcpy(buf, s, len);
		buf[len] = '\0';
		pfx = strtoul(slash + 1, &end, 10);
		if (*end != '\0' || pfx > 128)
			return (-1);
	} else {
		if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
			return (-1);
		pfx = 0;
	}

	/* Try IPv4 first. */
	if (inet_pton(AF_INET, buf, &v4) == 1) {
		/* Store as v4-mapped IPv6: ::ffff:A.B.C.D */
		addr[10] = 0xff;
		addr[11] = 0xff;
		memcpy(&addr[12], &v4, 4);
		if (slash != NULL) {
			if (pfx > 32)
				return (-1);
			*prefixp = (uint8_t)pfx;
		} else {
			*prefixp = 32;	/* bare address = exact host */
		}
		*domainp = AF_INET;
		return (0);
	}

	/* Try IPv6. */
	if (inet_pton(AF_INET6, buf, &v6) == 1) {
		memcpy(addr, &v6, 16);
		*prefixp = (slash != NULL) ? (uint8_t)pfx : 128;
		*domainp = AF_INET6;
		return (0);
	}

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

int
parse_file_action_string(const char *s, uint64_t *actionsp)
{

	if (strcmp(s, "*") == 0 || strcmp(s, "all") == 0)
		*actionsp |= FI_FS_ALL;
	else if (strcmp(s, "lookup") == 0)
		*actionsp |= FI_FS_LOOKUP;
	else if (strcmp(s, "stat") == 0)
		*actionsp |= FI_FS_STAT;
	else if (strcmp(s, "read") == 0)
		*actionsp |= FI_FS_READ;
	else if (strcmp(s, "write") == 0)
		*actionsp |= FI_FS_WRITE;
	else if (strcmp(s, "append") == 0)
		*actionsp |= FI_FS_APPEND;
	else if (strcmp(s, "create") == 0)
		*actionsp |= FI_FS_CREATE;
	else if (strcmp(s, "delete") == 0)
		*actionsp |= FI_FS_DELETE;
	else if (strcmp(s, "rename_from") == 0)
		*actionsp |= FI_FS_RENAME_FROM;
	else if (strcmp(s, "rename_to") == 0)
		*actionsp |= FI_FS_RENAME_TO;
	else if (strcmp(s, "link") == 0)
		*actionsp |= FI_FS_LINK;
	else if (strcmp(s, "exec") == 0)
		*actionsp |= FI_FS_EXEC;
	else if (strcmp(s, "setattr") == 0)
		*actionsp |= FI_FS_SETATTR;
	else if (strcmp(s, "truncate") == 0)
		*actionsp |= FI_FS_TRUNCATE;
	else if (strcmp(s, "connect") == 0)
		*actionsp |= FI_FS_UIPC_CONNECT;
	else
		return (-1);
	return (0);
}

int
parse_file_actions(const ucl_object_t *v, uint64_t *actionsp)
{
	const ucl_object_t *elem;
	ucl_object_iter_t it;

	*actionsp = 0;
	if (v == NULL) {
		*actionsp = FI_FS_ALL;
		return (0);
	}
	if (ucl_object_type(v) == UCL_STRING)
		return (parse_file_action_string(ucl_object_tostring(v),
		    actionsp));
	if (ucl_object_type(v) != UCL_ARRAY)
		return (-1);
	it = NULL;
	while ((elem = ucl_object_iterate(v, &it, true)) != NULL) {
		if (ucl_object_type(elem) != UCL_STRING)
			return (-1);
		if (parse_file_action_string(ucl_object_tostring(elem),
		    actionsp) != 0)
			return (-1);
	}
	return (*actionsp != 0 ? 0 : -1);
}

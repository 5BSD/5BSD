/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared UCL parsers for network and jail claims.
 * Used by both authorityd (config.c) and serviced (manifest.c).
 */

#ifndef CLAIM_PARSE_H
#define CLAIM_PARSE_H

#include <stdint.h>

struct ucl_object_s;	/* forward decl to avoid ucl.h dependency in header */

int	parse_port_range_string(const char *s, uint16_t *minp, uint16_t *maxp);
int	parse_port_range_obj(const struct ucl_object_s *v,
	    uint16_t *minp, uint16_t *maxp);
int	parse_jail_action_string(const char *s, uint32_t *actionsp);
int	parse_jail_actions(const struct ucl_object_s *v, uint32_t *actionsp);
int	parse_address_string(const char *s, uint8_t addr[16],
	    uint8_t *prefixp, int *domainp);
int	parse_net_protocol_string(const char *s, int *protop);
int	parse_bdaddr_string(const char *s, uint8_t addr[16], uint8_t *prefixp);
int	parse_file_action_string(const char *s, uint64_t *actionsp);
int	parse_file_actions(const struct ucl_object_s *v, uint64_t *actionsp);
int	parse_storage_right_string(const char *s, uint64_t *rightsp);
int	parse_storage_rights(const struct ucl_object_s *v, uint64_t *rightsp);
int	parse_storage_lifetime_string(const char *s, uint8_t *lifetimep);

#endif /* CLAIM_PARSE_H */

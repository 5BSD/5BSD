/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd configuration: defaults, a "key value" line parser and validation.
 * The parser is pure (operates on strings); meshd_config_load() is the thin
 * file-reading wrapper around it.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "meshd.h"

void
meshd_config_defaults(struct meshd_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	cfg->company_id = MESHD_DEFAULT_CID;
	cfg->product_id = MESHD_DEFAULT_PID;
	cfg->version_id = MESHD_DEFAULT_VID;
	cfg->netkey_index = 0;
	cfg->appkey_index = 0;
	cfg->iv_index = 0;
	cfg->unicast_addr = MESHD_UNICAST_MIN;
	cfg->default_ttl = 7;			/* MshPRT default TTL */
	cfg->features = 0;
	/* The radio bearer is reached through blued's control socket. */
	(void)strlcpy(cfg->blued_socket, "/var/run/blued.sock",
	    sizeof(cfg->blued_socket));
}

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

int
meshd_hexdecode(const char *hex, uint8_t *out, size_t outlen)
{
	size_t i;
	int hi, lo;

	if (hex == NULL || out == NULL)
		return (-1);
	if (strlen(hex) != outlen * 2)
		return (-1);
	for (i = 0; i < outlen; i++) {
		hi = hexval((unsigned char)hex[i * 2]);
		lo = hexval((unsigned char)hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return (-1);
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return (0);
}

/* Parse an unsigned integer (decimal, or 0x-prefixed hex).  Returns 0/-1. */
static int
parse_u32(const char *s, uint32_t *out)
{
	char *end;
	unsigned long v;

	if (s == NULL || *s == '\0')
		return (-1);
	errno = 0;
	v = strtoul(s, &end, 0);
	if (*end != '\0' || errno != 0 || v > 0xFFFFFFFFUL)
		return (-1);
	*out = (uint32_t)v;
	return (0);
}

int
meshd_config_parse_line(struct meshd_config *cfg, const char *line)
{
	char key[32], val[128];
	uint32_t u;
	int n;

	if (cfg == NULL || line == NULL)
		return (-1);

	/* Skip leading whitespace; ignore blank and comment lines. */
	while (*line == ' ' || *line == '\t')
		line++;
	if (*line == '\0' || *line == '\n' || *line == '#')
		return (0);

	n = sscanf(line, "%31s %127s", key, val);
	if (n != 2)
		return (-1);

	if (strcmp(key, "device_uuid") == 0) {
		if (meshd_hexdecode(val, cfg->device_uuid,
		    sizeof(cfg->device_uuid)) != 0)
			return (-1);
		cfg->have_uuid = 1;
	} else if (strcmp(key, "company_id") == 0) {
		if (parse_u32(val, &u) != 0 || u > UINT16_MAX)
			return (-1);
		cfg->company_id = (uint16_t)u;
	} else if (strcmp(key, "product_id") == 0) {
		if (parse_u32(val, &u) != 0 || u > UINT16_MAX)
			return (-1);
		cfg->product_id = (uint16_t)u;
	} else if (strcmp(key, "version_id") == 0) {
		if (parse_u32(val, &u) != 0 || u > UINT16_MAX)
			return (-1);
		cfg->version_id = (uint16_t)u;
	} else if (strcmp(key, "netkey") == 0) {
		if (meshd_hexdecode(val, cfg->netkey, sizeof(cfg->netkey)) != 0)
			return (-1);
		cfg->have_netkey = 1;
	} else if (strcmp(key, "appkey") == 0) {
		if (meshd_hexdecode(val, cfg->appkey, sizeof(cfg->appkey)) != 0)
			return (-1);
		cfg->have_appkey = 1;
	} else if (strcmp(key, "device_key") == 0) {
		if (meshd_hexdecode(val, cfg->device_key,
		    sizeof(cfg->device_key)) != 0)
			return (-1);
		cfg->have_device_key = 1;
	} else if (strcmp(key, "netkey_index") == 0) {
		if (parse_u32(val, &u) != 0 || u > 0x0FFF)
			return (-1);
		cfg->netkey_index = (uint16_t)u;
	} else if (strcmp(key, "appkey_index") == 0) {
		if (parse_u32(val, &u) != 0 || u > 0x0FFF)
			return (-1);
		cfg->appkey_index = (uint16_t)u;
	} else if (strcmp(key, "iv_index") == 0) {
		if (parse_u32(val, &u) != 0)
			return (-1);
		cfg->iv_index = u;
	} else if (strcmp(key, "unicast_addr") == 0) {
		if (parse_u32(val, &u) != 0 || u > 0xFFFF)
			return (-1);
		cfg->unicast_addr = (uint16_t)u;
	} else if (strcmp(key, "default_ttl") == 0) {
		if (parse_u32(val, &u) != 0 || u > 0x7F)
			return (-1);
		cfg->default_ttl = (uint8_t)u;
	} else if (strcmp(key, "relay") == 0) {
		if (parse_u32(val, &u) != 0 || u > 1)
			return (-1);
		if (u)
			cfg->features |= MESH_CFG_FEATURE_RELAY;
		else
			cfg->features &= ~MESH_CFG_FEATURE_RELAY;
	} else if (strcmp(key, "proxy") == 0) {
		if (parse_u32(val, &u) != 0 || u > 1)
			return (-1);
		if (u)
			cfg->features |= MESH_CFG_FEATURE_PROXY;
		else
			cfg->features &= ~MESH_CFG_FEATURE_PROXY;
	} else if (strcmp(key, "friend") == 0) {
		if (parse_u32(val, &u) != 0 || u > 1)
			return (-1);
		if (u)
			cfg->features |= MESH_CFG_FEATURE_FRIEND;
		else
			cfg->features &= ~MESH_CFG_FEATURE_FRIEND;
	} else if (strcmp(key, "low_power") == 0) {
		if (parse_u32(val, &u) != 0 || u > 1)
			return (-1);
		if (u)
			cfg->features |= MESH_CFG_FEATURE_LOW_POWER;
		else
			cfg->features &= ~MESH_CFG_FEATURE_LOW_POWER;
	} else if (strcmp(key, "blued_socket") == 0) {
		if (strlcpy(cfg->blued_socket, val,
		    sizeof(cfg->blued_socket)) >= sizeof(cfg->blued_socket))
			return (-1);		/* path too long */
	} else {
		return (-1);			/* unknown key */
	}
	return (0);
}

int
meshd_config_validate(const struct meshd_config *cfg)
{

	if (cfg == NULL)
		return (-1);
	if (!meshd_addr_is_unicast(cfg->unicast_addr))
		return (-1);
	if (cfg->default_ttl > 0x7F || cfg->default_ttl == 1)
		return (-1);
	if (cfg->netkey_index > 0x0FFF || cfg->appkey_index > 0x0FFF)
		return (-1);
	return (0);
}

int
meshd_config_load(struct meshd_config *cfg, const char *path)
{
	struct stat sb;
	FILE *fp;
	char line[256];
	int fd;

	if (cfg == NULL || path == NULL)
		return (-1);
	meshd_config_defaults(cfg);

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid()) {
		(void)close(fd);
		errno = EPERM;
		return (-1);
	}
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		(void)close(fd);
		return (-1);
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		/* Reject a physical line that does not fit in the parser buffer;
		 * parsing its prefix as a complete directive can silently change
		 * security policy while ignoring the attacker-controlled suffix. */
		if (strchr(line, '\n') == NULL && !feof(fp)) {
			(void)fclose(fp);
			errno = EOVERFLOW;
			return (-1);
		}
		if (meshd_config_parse_line(cfg, line) != 0) {
			(void)fclose(fp);
			return (-1);
		}
	}
	if (ferror(fp)) {
		(void)fclose(fp);
		return (-1);
	}
	if (fclose(fp) != 0)
		return (-1);
	/* NetKey/AppKey directives turn the configuration into a credential
	 * store.  Refuse to operate when those long-term network credentials are
	 * readable by another uid or group. */
	if ((cfg->have_netkey || cfg->have_appkey || cfg->have_device_key) &&
	    (sb.st_mode & 077) != 0) {
		errno = EPERM;
		return (-1);
	}
	return (meshd_config_validate(cfg));
}

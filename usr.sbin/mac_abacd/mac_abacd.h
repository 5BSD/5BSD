/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 */

#ifndef _MAC_ABACD_H_
#define _MAC_ABACD_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * Include the shared kernel/userland header for mac_syscall definitions
 */
#include <security/mac_abac/mac_abac.h>

/*
 * Default paths
 */
#define MAC_ABACD_DEFAULT_CONFIG	"/etc/mac_abac.conf"
#define MAC_ABACD_DEFAULT_PIDFILE	"/var/run/mac_abacd.pid"

/*
 * Policy name for mac_syscall
 */
#define ABAC_POLICY_NAME	"mac_abac"

/*
 * Daemon configuration
 */
struct mac_abacd_config {
	const char	*config_file;
	const char	*pidfile;
	bool		daemonize;
	bool		verbose;
	bool		test_mode;
};

/*
 * Logging function (mac_abacd.c)
 */
void mac_abacd_log(int priority, const char *fmt, ...);

/*
 * Line format parsing (parse_line.c)
 */
int mac_abacd_parse_line(const char *line, struct abac_rule_io *rule);
int mac_abacd_parse_operations(const char *text, uint32_t *operations);
int mac_abacd_parse_pattern(const char *text, struct abac_pattern_io *pattern);
int mac_abacd_validate_label(const char *text);

/*
 * Callback type for rule iteration during UCL parsing
 * Return 0 to continue, non-zero to stop parsing
 */
typedef int (*abac_rule_callback_t)(struct abac_rule_io *rule, void *ctx);

struct mac_abac_policy_settings {
	bool	 has_mode;
	int	 mode;
	bool	 has_default_policy;
	int	 default_policy;
};

/* Parse and validate a complete UCL policy without changing kernel state. */
int mac_abacd_compile_ucl(const char *path, bool verbose,
    abac_rule_callback_t callback, void *ctx,
    struct mac_abac_policy_settings *settings);

#endif /* !_MAC_ABACD_H_ */

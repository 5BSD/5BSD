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
 * Kernel communication functions (mac_abacd.c)
 */
int mac_abacd_add_rule(struct abac_rule_io *rule);
int mac_abacd_clear_rules(void);
int mac_abacd_set_mode(int mode);
int mac_abacd_set_default_policy(int policy);

/*
 * Policy parsing functions (parse_ucl.c)
 *
 * mac_abacd_parse_ucl_check_append: Parse and check if append mode is set
 *   Returns: 0 = success (no append), 1 = success (append mode), -1 = error
 *
 * mac_abacd_parse_ucl: Parse and load rules (legacy interface)
 */
int mac_abacd_parse_ucl(const char *path, bool verbose);
int mac_abacd_parse_ucl_check_append(const char *path, bool verbose, bool *append_mode);

/*
 * Line format parsing (parse_line.c)
 */
int mac_abacd_parse_line(const char *line, struct abac_rule_io *rule);

/*
 * Callback type for rule iteration during UCL parsing
 * Return 0 to continue, non-zero to stop parsing
 */
typedef int (*abac_rule_callback_t)(struct abac_rule_io *rule, void *ctx);

/*
 * Parse UCL file and call callback for each rule (parse_ucl.c)
 * Used by mac_abac_ctl for building packed rule buffers
 */
int mac_abacd_parse_ucl_with_callback(const char *path, bool verbose,
    abac_rule_callback_t callback, void *ctx);

#endif /* !_MAC_ABACD_H_ */

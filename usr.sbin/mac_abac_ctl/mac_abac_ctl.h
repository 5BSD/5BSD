/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * mac_abac_ctl - Internal header for shared declarations
 */

#ifndef MAC_ABAC_CTL_H
#define MAC_ABAC_CTL_H

#include <sys/types.h>
#include <stdint.h>

#define ABAC_POLICY_NAME	"mac_abac"

/*
 * Shared utility functions (mac_abac_ctl.c)
 */
int abac_syscall(int cmd, void *arg);
char *convert_label_format(const char *input);
const char *ops_to_string(uint32_t ops, char *buf, size_t buflen);
const char *get_extattr_name(void);
void usage(void);

/*
 * Command handlers
 */
int cmd_mode(int argc, char *argv[]);
int cmd_default(int argc, char *argv[]);
int cmd_stats(int argc, char *argv[]);
int cmd_status(int argc, char *argv[]);
int cmd_limits(int argc, char *argv[]);
int cmd_lock(int argc, char *argv[]);
int cmd_log(int argc, char *argv[]);

/* mac_abac_ctl_rule.c */
int cmd_rule(int argc, char *argv[]);

/* mac_abac_ctl_label.c */
int cmd_label(int argc, char *argv[]);
int cmd_test(int argc, char *argv[]);

/* mac_abac_ctl_set.c */
int cmd_set(int argc, char *argv[]);

#endif /* MAC_ABAC_CTL_H */

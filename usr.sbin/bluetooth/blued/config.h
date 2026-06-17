/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_CONFIG_H_
#define _BLUED_CONFIG_H_

#include <sys/param.h>
#include <stdbool.h>
#include <stdint.h>

#define BLUED_MAX_DEVICES	16

struct blued_device_conf {
	uint8_t		addr[6];
	uint8_t		addr_type;
	bool		reconnect;
};

struct blued_config {
	char		pidfile[PATH_MAX];
	char		bonddb[PATH_MAX];
	char		ctlsock[PATH_MAX];
	char		logfile[PATH_MAX];
	int		loglevel;
	bool		daemonize;

	char		adapters[8][16];
	int		nadapters;		/* 0 = auto-detect */

	uint8_t		io_capability;
	bool		bondable;
	bool		sc_only;

	bool		eatt;
	bool		privacy;
	bool		reconnect;
	int		reconnect_max_delay;

	bool		peripheral_mode;
	bool		scan_mode;

	struct blued_device_conf devices[BLUED_MAX_DEVICES];
	int		ndevices;
};

void	blued_config_defaults(struct blued_config *cfg);
int	blued_config_load(struct blued_config *cfg, const char *path);
void	blued_config_apply_cli(struct blued_config *cfg, int argc, char **argv);

#endif /* _BLUED_CONFIG_H_ */

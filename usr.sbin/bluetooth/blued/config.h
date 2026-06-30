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
#define BLUED_MAX_CONF_SERVICES	8
#define BLUED_MAX_CONF_CHARS	8	/* per service */

/* Default paths and tuning constants */
#define BLUED_PIDFILE_DEFAULT		"/var/run/blued.pid"
#define BLUED_BONDDB_DEFAULT		"/var/db/blued/bonds"
#define BLUED_CTLSOCK_DEFAULT		"/var/run/blued.sock"
#define BLUED_CONFIG_DEFAULT		"/etc/blued.conf"
#define BLUED_MIN_KEY_SIZE_DEFAULT	16	/* KNOB-safe */
#define BLUED_SOCKET_POOL_DEFAULT	8
#define BLUED_RECONNECT_MAX_DEFAULT	60
#define BLUED_RPA_TIMEOUT_DEFAULT	900	/* 15 minutes */

struct blued_char_conf {
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	uint8_t		properties;	/* GATT_PROP_* flags */
	uint8_t		permissions;	/* ATT_PERM_* flags */
	uint8_t		initial_value[64];
	uint16_t	initial_value_len;
	bool		has_cccd;	/* auto-add CCCD if notify or indicate */
};

struct blued_service_conf {
	char		name[64];
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	struct blued_char_conf chars[BLUED_MAX_CONF_CHARS];
	int		nchars;
};

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

	int		min_key_size;		/* minimum encryption key size (7-16, default 16) */
	int		rpa_timeout;		/* RPA rotation timeout (1-3600s) */
	int		privacy_mode;		/* 0=network, 1=device (default) */
	int		subrate_factor;		/* connection subrate factor (0=disabled, 1-500) */
	int		socket_pool_size;	/* pre-allocated L2CAP sockets for Capsicum (1-64) */

	bool		peripheral_mode;
	bool		scan_mode;

	char		peripheral_name[64];

	struct blued_device_conf devices[BLUED_MAX_DEVICES];
	int		ndevices;

	struct blued_service_conf services[BLUED_MAX_CONF_SERVICES];
	int		nservices;
};

void	blued_config_defaults(struct blued_config *cfg);
int	blued_config_load(struct blued_config *cfg, const char *path);
void	blued_config_apply_cli(struct blued_config *cfg, int argc, char **argv);

/* Shared GATT property/permission parsing (used by config.c and ctl.c) */
uint8_t	blued_parse_gatt_properties(const char *str);
uint8_t	blued_parse_gatt_permissions(const char *str);
int	blued_parse_uuid(const char *str, uint16_t *uuid16, uint8_t uuid128[16]);
int	blued_parse_hex_value(const char *hex, uint8_t *out, size_t maxlen);

#endif /* _BLUED_CONFIG_H_ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <corvink@FreeBSD.org>
 */

#pragma once

#include <stdbool.h>
#include <sys/linker_set.h>

#include "config.h"

struct tpm_device;

struct tpm_emul {
	const char *name;

	int (*init)(void **sc, nvlist_t *nvl);
	void (*deinit)(void *sc);
	int (*execute_cmd)(void *sc, void *cmd, uint32_t cmd_size, void *rsp,
	    uint32_t rsp_size);
	/* Control operations require the device command worker to be quiesced. */
	bool (*state_available)(void *sc);
	int (*state_stop)(void *sc);
	int (*state_init)(void *sc);
	int (*state_lock)(void *sc);
	int (*state_get_blob)(void *sc, uint32_t type, uint8_t **blob,
	    size_t *length, uint32_t *flags);
	int (*state_set_blob)(void *sc, uint32_t type, const uint8_t *blob,
	    size_t length, uint32_t flags);
};
#define TPM_EMUL_SET(x) DATA_SET(tpm_emul_set, x)

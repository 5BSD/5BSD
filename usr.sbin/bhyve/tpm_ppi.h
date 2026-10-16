/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "config.h"

struct tpm_ppi {
	const char *name;

	int (*init)(void **sc);
	void (*deinit)(void *sc);
	size_t state_size;
	int (*state_get)(void *sc, uint8_t *wire, size_t wire_size);
	int (*state_validate)(const uint8_t *wire, size_t wire_size);
	int (*state_set)(void *sc, const uint8_t *wire, size_t wire_size);
	int (*write_dsdt_regions)(void *sc);
	int (*write_dsdt_dsm)(void *sc);
};
#define TPM_PPI_SET(x) DATA_SET(tpm_ppi_set, x)

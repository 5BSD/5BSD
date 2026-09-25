/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDPOWER_TEST_H_
#define	_BSDPOWER_TEST_H_

#include <stdint.h>

struct powercmp_config;

/*
 * Test-only entrypoints, compiled into BSDPower.c only under -DBSDPOWER_TESTING
 * (main() is guarded out).  They let the ATF suite drive the real per-session
 * channel worker -- protocol validation, the per-label SUSPEND policy,
 * HELLO/STATES/SUSPEND dispatch -- over an already-connected provider channel
 * fd, and stand in for the two values main() caches before entering capability
 * mode: the supported sleep-state mask and the narrowed /dev/acpi descriptor.
 */
int	bsdpower_test_serve_session(int fd, const char *label,
	    const struct powercmp_config *config);
void	bsdpower_test_set_states(uint32_t mask);
void	bsdpower_test_set_acpi_fd(int fd);
uint32_t bsdpower_test_supported_states(void);

#endif /* _BSDPOWER_TEST_H_ */

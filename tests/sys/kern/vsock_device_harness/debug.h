/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/* Mock of bhyve debug.h for the vsock device harness. */
#ifndef MOCK_DEBUG_H
#define MOCK_DEBUG_H
#include <stdio.h>
#define PRINTLN(fmt, ...)  do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#define EPRINTLN(fmt, ...) do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#endif

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Probe-tap build of gatt.c for probe_tap_test -- see ptap_att_server.c for
 * why a uniquely-named wrapper is used.  Compiled with -DWITH_PROBE_TAP so
 * the gatt:disc:step sites record into the in-process tap.
 */

#include "gatt.c"

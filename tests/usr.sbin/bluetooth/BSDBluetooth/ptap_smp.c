/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Probe-tap build of smp.c for probe_tap_test -- see ptap_att_server.c for
 * why a uniquely-named wrapper is used.  Compiled with -DWITH_PROBE_TAP so
 * the smp:phase, smp:method:select, smp:pair:start, auth:fail and
 * smp:timeout sites record into the in-process tap.
 */

#include "smp.c"

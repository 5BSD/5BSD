/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Probe-tap build of att_server.c for probe_tap_test.
 *
 * The production ATT/GATT/SMP objects are shared (one .o each) across every
 * blued ATF test in this directory, so they cannot carry a per-test
 * -DWITH_PROBE_TAP without either being silently reused as a stale no-tap
 * object or breaking the tests that do not link blued_probe_tap.c.  This
 * uniquely-named wrapper compiles a private copy of att_server.c with
 * -DWITH_PROBE_TAP (see CFLAGS.ptap_att_server.c in the Makefile) so its
 * BLUED_PROBE_* sites record into the in-process tap.
 */

#include "att_server.c"

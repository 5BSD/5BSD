/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Probe-tap build of att_server_notify.c for probe_tap_test -- see
 * ptap_att_server.c for why a uniquely-named wrapper is used.  Compiled with
 * -DWITH_PROBE_TAP so the att:notify / att:indicate / att:notify:multi sites
 * record into the in-process tap.
 */

#include "att_server_notify.c"

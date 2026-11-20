/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider of the capprotect debug and tracing fixture
 * (capprotect_usdt_helper.c).  tick fires once per loop of the fixture's
 * control loop; ready fires once, after the fixture has applied its mode.
 */
provider cpusdt {
	probe tick(int);
	probe ready();
};

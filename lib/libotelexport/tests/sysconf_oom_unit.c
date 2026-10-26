/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oe_sysconf.c with its allocations routed through failalloc.c, for
 * sysconf_oom_test.  The library copy is unaffected.
 */

#include "failalloc.h"
#include "../oe_sysconf.c"

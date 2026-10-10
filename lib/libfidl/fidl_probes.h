/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_PROBES_H
#define FIDL_BSD_PROBES_H
#ifdef WITH_DTRACE
#include "fidl_provider.h"
#else
#define FIDL_BSD_REQUEST_START(a, b, c, d, e) do { } while (0)
#define FIDL_BSD_REQUEST_DONE(a, b, c, d) do { } while (0)
#define FIDL_BSD_DISPATCH_START(a) do { } while (0)
#define FIDL_BSD_DISPATCH_DONE(a, b) do { } while (0)
#define FIDL_BSD_MESSAGE(a, b, c) do { } while (0)
#define FIDL_BSD_CLOSE(a, b) do { } while (0)
#endif
#endif

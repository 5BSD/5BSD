/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BSDMEMORY_PROBES_H
#define BSDMEMORY_PROBES_H
#ifdef WITH_DTRACE
#include "bsdmemory_provider.h"
#else
#define BSDMEMORY_READY() do { } while (0)
#define BSDMEMORY_SAMPLE_START() do { } while (0)
#define BSDMEMORY_SAMPLE_DONE(a, b, c, d) do { } while (0)
#define BSDMEMORY_PRESSURE(a, b, c) do { } while (0)
#define BSDMEMORY_PUBLISH_START(a) do { } while (0)
#define BSDMEMORY_PUBLISH_DONE(a, b, c) do { } while (0)
#define BSDMEMORY_EXIT(a) do { } while (0)
#endif
#endif

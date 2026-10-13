/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_BSDDEVICE_TRACE_PRESSURE_H
#define USR_SBIN_BSDDEVICE_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include "bsddevice_provider.h"
#endif
#ifdef WITH_DTRACE
#define BSDDEVICE_TRACE_WORKER_REJECT(a0, a1, a2) \
	BSDDEVICE_WORKER_REJECT(a0, a1, a2)
#else
#define BSDDEVICE_TRACE_WORKER_REJECT(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#endif

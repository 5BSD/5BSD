/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_BSDEXTENSION_TRACE_PRESSURE_H
#define USR_SBIN_BSDEXTENSION_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include "bsdextension_provider.h"
#endif
#ifdef WITH_DTRACE
#define BSDEXTENSION_TRACE_ACCEPT_RETRY(a0) \
	BSDEXTENSION_ACCEPT_RETRY(a0)
#else
#define BSDEXTENSION_TRACE_ACCEPT_RETRY(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define BSDEXTENSION_TRACE_WORKER_REJECT(a0, a1) \
	BSDEXTENSION_WORKER_REJECT(a0, a1)
#else
#define BSDEXTENSION_TRACE_WORKER_REJECT(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif

/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBSERVICE_TRACE_PRESSURE_H
#define LIB_LIBSERVICE_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_RETRY_SCHEDULED(a0, a1, a2) \
	DTRACE_PROBE3(service_runtime, retry__scheduled, (a0), (a1), (a2))
#else
#define SERVICE_RUNTIME_TRACE_RETRY_SCHEDULED(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_RETRY_RECOVERED(a0, a1) \
	DTRACE_PROBE2(service_runtime, retry__recovered, (a0), (a1))
#else
#define SERVICE_RUNTIME_TRACE_RETRY_RECOVERED(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_HEALTH_CHANGE(a0, a1, a2) \
	DTRACE_PROBE3(service_runtime, health__change, (a0), (a1), (a2))
#else
#define SERVICE_RUNTIME_TRACE_HEALTH_CHANGE(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_BUDGET_REJECTED(a0, a1) \
	DTRACE_PROBE2(service_runtime, budget__rejected, (a0), (a1))
#else
#define SERVICE_RUNTIME_TRACE_BUDGET_REJECTED(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_BUDGET_EXPIRED(a0) \
	DTRACE_PROBE1(service_runtime, budget__expired, (a0))
#else
#define SERVICE_RUNTIME_TRACE_BUDGET_EXPIRED(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SERVICE_RUNTIME_TRACE_LEASE_LIMIT(a0, a1, a2) \
	DTRACE_PROBE3(service_runtime, lease__limit, (a0), (a1), (a2))
#else
#define SERVICE_RUNTIME_TRACE_LEASE_LIMIT(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#endif

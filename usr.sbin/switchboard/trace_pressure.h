/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_SWITCHBOARD_TRACE_PRESSURE_H
#define USR_SBIN_SWITCHBOARD_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define SWITCHBOARD_TRACE_CAPSULE_RPC_START(a0, a1, a2) \
	DTRACE_PROBE3(switchboard, capsule__rpc__start, (a0), (a1), (a2))
#else
#define SWITCHBOARD_TRACE_CAPSULE_RPC_START(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SWITCHBOARD_TRACE_CAPSULE_RPC_DONE(a0, a1) \
	DTRACE_PROBE2(switchboard, capsule__rpc__done, (a0), (a1))
#else
#define SWITCHBOARD_TRACE_CAPSULE_RPC_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SWITCHBOARD_TRACE_CAPSULE_STALE_REPLY(a0) \
	DTRACE_PROBE1(switchboard, capsule__stale__reply, (a0))
#else
#define SWITCHBOARD_TRACE_CAPSULE_STALE_REPLY(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define SWITCHBOARD_TRACE_CAPSULE_MALFORMED_REPLY(a0, a1) \
	DTRACE_PROBE2(switchboard, capsule__malformed__reply, (a0), (a1))
#else
#define SWITCHBOARD_TRACE_CAPSULE_MALFORMED_REPLY(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif

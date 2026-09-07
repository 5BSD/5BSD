/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the libservice ambient discovery path.
 *
 * Provider: service_ambient
 *
 * Usage:
 *   dtrace -n 'service_ambient*:::'             -- trace all probes
 *   dtrace -n 'service_ambient*:::reg-result'   -- private vs fallback + cause
 *   dtrace -n 'service_ambient*:::reg-create'   -- channel-create syscall result
 *
 * The probes carry no capability material: only small integers (an errno and
 * three booleans), so tracing them leaks no authority.  When DTrace is disabled
 * they compile to nothing.
 */

#ifndef SERVICE_AMBIENT_PROBES_H
#define SERVICE_AMBIENT_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE1(provider, name, arg1) \
	do { if (0) { (void)(arg1); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); (void)(arg4); } } \
	while (0)
#endif

/* mac_capability_channel_create() result (create_errno == 0 -> got a pair). */
#define	SERVICE_AMBIENT_PROBE_REG_CREATE(create_errno)	\
	DTRACE_PROBE1(service_ambient, reg__create, create_errno)
/* REGISTER send over the shared channel finished (send_ok 1/0). */
#define	SERVICE_AMBIENT_PROBE_REG_SEND(send_ok)	\
	DTRACE_PROBE1(service_ambient, reg__send, send_ok)
/* ACK receive on the private endpoint finished (ack_ok 1/0). */
#define	SERVICE_AMBIENT_PROBE_REG_ACK(ack_ok)	\
	DTRACE_PROBE1(service_ambient, reg__ack, ack_ok)
/* Final private-vs-fallback decision, with the inputs that produced it. */
#define	SERVICE_AMBIENT_PROBE_REG_RESULT(use_private, create_errno, send_ok, \
	    ack_ok)	\
	DTRACE_PROBE4(service_ambient, reg__result, use_private, create_errno, \
	    send_ok, ack_ok)

#endif /* SERVICE_AMBIENT_PROBES_H */

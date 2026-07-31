/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#endif
#define	LOGCMP_PROBE_OPEN(name, result) \
	DTRACE_PROBE2(logcmp, component__open, name, result)
#define	LOGCMP_PROBE_SEND(op, len, nfds, result) \
	DTRACE_PROBE4(logcmp, message__send, op, len, nfds, result)
#define	LOGCMP_PROBE_RECEIVE(op, len, nfds, result) \
	DTRACE_PROBE4(logcmp, message__receive, op, len, nfds, result)
#define	LOGCMP_PROBE_REJECT(op, len, error) \
	DTRACE_PROBE3(logcmp, message__reject, op, len, error)

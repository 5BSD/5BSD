#ifndef _FILESYSTEMCMP_PROBES_H_
#define	_FILESYSTEMCMP_PROBES_H_
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
#define	FILESYSTEMCMP_PROBE_OPEN(component, result) \
	DTRACE_PROBE2(filesystemcmp, component__open, component, result)
#define	FILESYSTEMCMP_PROBE_SEND(op, len, nfds, result) \
	DTRACE_PROBE4(filesystemcmp, message__send, op, len, nfds, result)
#define	FILESYSTEMCMP_PROBE_RECEIVE(op, len, nfds, result) \
	DTRACE_PROBE4(filesystemcmp, message__receive, op, len, nfds, result)
#define	FILESYSTEMCMP_PROBE_REJECT(op, len, error) \
	DTRACE_PROBE3(filesystemcmp, message__reject, op, len, error)
#endif

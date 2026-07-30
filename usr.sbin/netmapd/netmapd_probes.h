#ifndef _NETMAPD_PROBES_H_
#define	_NETMAPD_PROBES_H_
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#endif
#define	NETMAPD_PROBE_REQUEST(label, opcode, length) \
	DTRACE_PROBE3(netmapd, request, label, opcode, length)
#define	NETMAPD_PROBE_BEARER(label, interface, bearer, result) \
	DTRACE_PROBE4(netmapd, bearer__create, label, interface, bearer, result)
#endif

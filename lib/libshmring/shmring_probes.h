#ifndef _SHMRING_PROBES_H_
#define	_SHMRING_PROBES_H_
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
#define	DTRACE_PROBE5(provider, name, arg1, arg2, arg3, arg4, arg5) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); (void)(arg5); } } while (0)
#endif
#define	SHMRING_PROBE_CREATE(cap, shape, mode, maxrec, result) \
	DTRACE_PROBE5(shmring, create, cap, shape, mode, maxrec, result)
#define	SHMRING_PROBE_OPEN(role, cap, shape, mode, result) \
	DTRACE_PROBE5(shmring, open, role, cap, shape, mode, result)
#define	SHMRING_PROBE_CLOSE(role, cap) \
	DTRACE_PROBE2(shmring, close, role, cap)
#define	SHMRING_PROBE_WRITE(mode, requested, completed, result) \
	DTRACE_PROBE4(shmring, write, mode, requested, completed, result)
#define	SHMRING_PROBE_READ(mode, requested, completed, result) \
	DTRACE_PROBE4(shmring, read, mode, requested, completed, result)
#define	SHMRING_PROBE_CORRUPT(head, tail, cap) \
	DTRACE_PROBE3(shmring, corrupt, head, tail, cap)
#endif

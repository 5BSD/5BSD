#ifndef _CHANNEL_PROBES_H_
#define	_CHANNEL_PROBES_H_
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
#define	LIBCHANNEL_PROBE_CREATE(fd, role, result) \
	DTRACE_PROBE3(libchannel, create, fd, role, result)
#define	LIBCHANNEL_PROBE_QUEUE(token, bytes, fds, depth) \
	DTRACE_PROBE4(libchannel, queue, token, bytes, fds, depth)
#define	LIBCHANNEL_PROBE_SEND(token, bytes, fds, result) \
	DTRACE_PROBE4(libchannel, send, token, bytes, fds, result)
#define	LIBCHANNEL_PROBE_RECEIVE(kind, token, bytes, fds) \
	DTRACE_PROBE4(libchannel, receive, kind, token, bytes, fds)
#define	LIBCHANNEL_PROBE_COMPLETE(token, result) \
	DTRACE_PROBE2(libchannel, complete, token, result)
#define	LIBCHANNEL_PROBE_DISCARD(token, fds, reason) \
	DTRACE_PROBE3(libchannel, discard, token, fds, reason)
#define	LIBCHANNEL_PROBE_PEER_DEATH(error, pending) \
	DTRACE_PROBE2(libchannel, peer__death, error, pending)
#endif

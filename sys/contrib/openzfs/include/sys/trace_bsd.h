/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef _SYS_TRACE_BSD_H
#define _SYS_TRACE_BSD_H

/*
 * FreeBSD SDT additions. Include after trace_zfs.h. Other OpenZFS tracing
 * backends require separately declared events; do not introduce undeclared
 * Linux tracepoint calls or evaluate probe arguments in those builds.
 */
#if defined(__FreeBSD__) && defined(_KERNEL)
#define ZFS_BSD_PROBE1(...) DTRACE_PROBE1(__VA_ARGS__)
#define ZFS_BSD_PROBE2(...) DTRACE_PROBE2(__VA_ARGS__)
#define ZFS_BSD_PROBE3(...) DTRACE_PROBE3(__VA_ARGS__)
#define ZFS_BSD_PROBE4(...) DTRACE_PROBE4(__VA_ARGS__)
#else
#define ZFS_BSD_PROBE1(...) do { } while (0)
#define ZFS_BSD_PROBE2(...) do { } while (0)
#define ZFS_BSD_PROBE3(...) do { } while (0)
#define ZFS_BSD_PROBE4(...) do { } while (0)
#endif

#endif /* _SYS_TRACE_BSD_H */

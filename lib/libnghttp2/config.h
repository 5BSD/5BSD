/*
 * nghttp2 configuration for the 5BSD base system (lib/libnghttp2).  The
 * library sources consult only these macros (contrib/nghttp2/README.5BSD).
 */
#ifndef NGHTTP2_BSD_CONFIG_H
#define NGHTTP2_BSD_CONFIG_H

#define	HAVE_ARPA_INET_H		1
#define	HAVE_NETINET_IN_H		1
#define	HAVE_CLOCK_GETTIME		1
#define	HAVE_DECL_CLOCK_MONOTONIC	1

#endif

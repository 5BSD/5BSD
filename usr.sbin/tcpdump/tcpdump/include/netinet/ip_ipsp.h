/*
 * 5BSD: OpenBSD header from contrib/openbsd-pf.  Its union sockaddr_union
 * is already defined by <net/pfvar.h> and the compatibility header.
 */
#define	sockaddr_union	ipsp_sockaddr_union
#include "../../../../../contrib/openbsd-pf/sys/netinet/ip_ipsp.h"
#undef	sockaddr_union

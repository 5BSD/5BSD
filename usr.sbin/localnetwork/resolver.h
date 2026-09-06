#ifndef _LOCALNETWORK_RESOLVER_H_
#define _LOCALNETWORK_RESOLVER_H_
#include <netdb.h>   /* struct addrinfo */

struct service_context;

/*
 * Initialize the resolver.  Born in capability mode, localnetwork cannot open
 * a path, so this obtains /etc/resolv.conf (parsed here for nameservers),
 * /etc/hosts and /etc/services on demand through the filesystem provider via
 * the given service context.  Call once at startup.  Returns 0 (best-effort:
 * missing files just narrow what resolves), or -1+errno.
 */
int  netresolve_init(struct service_context *ctx);
/*
 * A capability-mode-safe subset of getaddrinfo(3).  Same return convention:
 * 0 on success (*res is a malloc'd addrinfo list, free with netfreeaddrinfo),
 * or a non-zero EAI_* code.  Honors hints: ai_family (AF_INET/AF_INET6/
 * AF_UNSPEC), ai_socktype (SOCK_STREAM/SOCK_DGRAM/0=both), ai_flags
 * (AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST, AI_NUMERICSERV).
 */
int  netresolve(const char *host, const char *serv,
     const struct addrinfo *hints, struct addrinfo **res);
void netfreeaddrinfo(struct addrinfo *res);
#endif

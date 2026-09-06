#ifndef _LOCALNETWORK_RESOLVER_H_
#define _LOCALNETWORK_RESOLVER_H_
#include <netdb.h>   /* struct addrinfo */
/*
 * Pre-cap_enter init: res_ninit() to parse /etc/resolv.conf, and open
 * read-only /etc/hosts and /etc/services descriptors to retain across
 * cap_enter.  Call once before entering capability mode.  0, or -1+errno.
 */
int  netresolve_init(void);
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

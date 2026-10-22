/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded resolver stand-ins for printf-conversions.c, so that %P and %I
 * never consult /etc/services, /etc/hosts or DNS.  The return conventions
 * are those of FreeBSD libc, which printf-conversions.py checks against the
 * real libc before trusting them: getservbyport_r() and gethostbyaddr_r()
 * return 0 and set *result on success, return 0 with *result NULL when the
 * entry does not exist, and return an error number (ERANGE for a short
 * buffer) with *result NULL on failure.  getipnodebyaddr() returns an
 * allocated hostent to be released with freehostent(), or NULL.
 *
 * ASan intercepts some of these, so they live in a preloaded object rather
 * than in the instrumented executable.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

/* Counters the harness reads through dlsym(). */
unsigned pcs_serv_calls, pcs_host_calls, pcs_node_calls, pcs_node_frees;
int pcs_serv_erange, pcs_host_erange;

int
getservbyport_r(int port, const char *proto, struct servent *sptr,
    char *buffer, size_t buflen, struct servent **result)
{
	(void)proto;
	pcs_serv_calls++;
	*result = NULL;
	if (pcs_serv_erange)
		return (ERANGE);
	if (port != htons(22))
		return (0);
	if (buflen < sizeof ("ssh"))
		return (ERANGE);
	memset(sptr, 0, sizeof (*sptr));
	strcpy(buffer, "ssh");
	sptr->s_name = buffer;
	sptr->s_port = port;
	*result = sptr;
	return (0);
}

int
gethostbyaddr_r(const void *addr, socklen_t len, int af, struct hostent *hp,
    char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	static const unsigned char want[4] = { 192, 0, 2, 7 };

	pcs_host_calls++;
	*result = NULL;
	*h_errnop = HOST_NOT_FOUND;
	if (pcs_host_erange)
		return (ERANGE);
	if (af != AF_INET || len != 4 || memcmp(addr, want, 4) != 0)
		return (0);
	/* Layout in buf: alias list, address list, address, name. */
	if (buflen < 4 * sizeof (char *) + 4 + sizeof ("host-a.example"))
		return (ERANGE);
	memset(hp, 0, sizeof (*hp));
	hp->h_aliases = (char **)(void *)buf;
	hp->h_addr_list = (char **)(void *)buf + 2;
	hp->h_aliases[0] = NULL;
	hp->h_addr_list[0] = buf + 4 * sizeof (char *);
	hp->h_addr_list[1] = NULL;
	memcpy(hp->h_addr_list[0], want, 4);
	hp->h_name = hp->h_addr_list[0] + 4;
	strcpy(hp->h_name, "host-a.example");
	hp->h_addrtype = AF_INET;
	hp->h_length = 4;
	*h_errnop = 0;
	*result = hp;
	return (0);
}

struct hostent *
getipnodebyaddr(const void *src, size_t len, int af, int *error_num)
{
	struct in6_addr want;
	struct hostent *hp;

	pcs_node_calls++;
	(void)inet_pton(AF_INET6, "2001:db8::7", &want);
	if (af != AF_INET6 || len != sizeof (want) ||
	    memcmp(src, &want, sizeof (want)) != 0) {
		*error_num = HOST_NOT_FOUND;
		return (NULL);
	}
	if ((hp = calloc(1, sizeof (*hp))) == NULL ||
	    (hp->h_name = strdup("host-b.example")) == NULL ||
	    (hp->h_aliases = calloc(1, sizeof (char *))) == NULL ||
	    (hp->h_addr_list = calloc(1, sizeof (char *))) == NULL) {
		if (hp != NULL) {
			free(hp->h_name);
			free(hp->h_aliases);
		}
		free(hp);
		*error_num = NO_RECOVERY;
		return (NULL);
	}
	hp->h_addrtype = AF_INET6;
	hp->h_length = sizeof (want);
	*error_num = 0;
	return (hp);
}

void
freehostent(struct hostent *hp)
{
	pcs_node_frees++;
	if (hp != NULL) {
		free(hp->h_name);
		free(hp->h_aliases);
		free(hp->h_addr_list);
		free(hp);
	}
}

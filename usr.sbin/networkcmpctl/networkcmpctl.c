/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <networkcmp.h>

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: networkcmpctl config\n"
	    "       networkcmpctl info\n"
	    "       networkcmpctl resolve host [service]\n");
	exit(EX_USAGE);
}

static struct networkcmp_client *
open_client(void)
{
	struct networkcmp_client *client;

	if (networkcmp_client_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", NETWORKCMP_INTERFACE);
	return (client);
}

static int
info(void)
{
	const struct networkcmp_hello_reply *limits;
	struct networkcmp_client *client;

	client = open_client();
	limits = networkcmp_client_limits(client);
	if (limits == NULL) {
		int error = errno == 0 ? EPROTO : errno;

		networkcmp_client_close(client);
		errno = error;
		err(EX_PROTOCOL, "limits");
	}
	printf("version=%u features=0x%08x max_resolve_results=%u\n",
	    limits->version, limits->features, limits->max_resolve_results);
	networkcmp_client_close(client);
	return (0);
}

static const char *
family_name(uint8_t family)
{

	if (family == NETWORKCMP_AF_INET4)
		return ("inet4");
	if (family == NETWORKCMP_AF_INET6)
		return ("inet6");
	return ("unknown");
}

static int
endpoint_address(const struct networkcmp_resolve_result *result,
    char address[INET6_ADDRSTRLEN])
{
	int family;

	family = result->endpoint.family == NETWORKCMP_AF_INET4 ? AF_INET :
	    result->endpoint.family == NETWORKCMP_AF_INET6 ? AF_INET6 : AF_UNSPEC;
	if (family == AF_UNSPEC || inet_ntop(family, result->endpoint.address,
	    address, INET6_ADDRSTRLEN) == NULL) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
resolve(const char *host, const char *service)
{
	struct networkcmp_resolve_result results[NETWORKCMP_RESOLVE_MAX_RESULTS];
	struct networkcmp_client *client;
	char addresses[NETWORKCMP_RESOLVE_MAX_RESULTS][INET6_ADDRSTRLEN];
	char canonname[NETWORKCMP_CANONNAME_MAX + 1];
	size_t count, i;
	uint32_t ttl;

	client = open_client();
	count = nitems(results);
	memset(canonname, 0, sizeof(canonname));
	if (networkcmp_resolve(client, host, service, NETWORKCMP_AF_UNSPEC,
	    NETWORKCMP_SOCK_ANY, NETWORKCMP_RESOLVE_F_CANONNAME, results,
	    &count, canonname, sizeof(canonname), &ttl) == -1) {
		int error = errno;

		networkcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "resolve %s", host);
	}
	for (i = 0; i < count; i++) {
		if (endpoint_address(&results[i], addresses[i]) == -1) {
			int error = errno;

			networkcmp_client_close(client);
			errno = error;
			err(EX_PROTOCOL, "malformed resolve result");
		}
	}
	printf("count=%zu ttl_seconds=%u canonname=%s\n", count, ttl,
	    canonname);
	for (i = 0; i < count; i++)
		printf("result[%zu].family=%s address=%s port=%u scope_id=%u"
		    " socket_type=%u protocol=%u\n", i,
		    family_name(results[i].endpoint.family), addresses[i],
		    results[i].endpoint.port, results[i].endpoint.scope_id,
		    results[i].socket_type, results[i].protocol);
	networkcmp_client_close(client);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc == 2 && strcmp(argv[1], "config") == 0) {
		puts("# No manifest declaration is required: link libnetworkcmp and");
		puts("# call networkcmp_*().  The system.Network service is reached at");
		puts("# runtime via service_connect(3), like any global service.");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "info") == 0)
		return (info());
	if ((argc == 3 || argc == 4) && strcmp(argv[1], "resolve") == 0)
		return (resolve(argv[2], argc == 4 ? argv[3] : NULL));
	usage();
}

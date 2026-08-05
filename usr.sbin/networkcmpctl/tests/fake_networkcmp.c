/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <networkcmp.h>

struct networkcmp_client { int open; struct networkcmp_hello_reply limits; };
static struct networkcmp_client client;

static int
fail(const char *operation)
{
	const char *requested;

	requested = getenv("CMP_TEST_FAIL");
	if (requested != NULL && strcmp(requested, operation) == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
networkcmp_client_open(struct networkcmp_client **result)
{
	if (result == NULL || fail("open") == -1)
		return (-1);
	memset(&client, 0, sizeof(client));
	client.open = 1;
	client.limits = (struct networkcmp_hello_reply){
	    .version = 1,
	    .features = NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
	        NETWORKCMP_FEATURE_DNS,
	    .max_sockets = 32,
	    .max_inline = NETWORKCMP_INLINE_MAX,
	    .max_datagram = NETWORKCMP_INLINE_MAX,
	    .max_resolve_results = 16,
	    .io_timeout_max = NETWORKCMP_IO_TIMEOUT_MAX,
	};
	*result = &client;
	return (0);
}

const struct networkcmp_hello_reply *
networkcmp_client_limits(const struct networkcmp_client *value)
{
	if (value != &client || !client.open || fail("limits") == -1)
		return (NULL);
	return (&client.limits);
}

void
networkcmp_client_close(struct networkcmp_client *value)
{
	if (value == &client) {
		client.open = 0;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

int
networkcmp_resolve(struct networkcmp_client *value, const char *host,
    const char *service, uint32_t family, uint32_t socket_type, uint32_t flags,
    struct networkcmp_resolve_result *results, size_t *count, char *canonname,
    size_t canonname_size, uint32_t *ttl)
{
	static const uint8_t loopback[16] = { 127, 0, 0, 1 };

	if (value != &client || !client.open || strcmp(host, "localhost") != 0 ||
	    (service != NULL && strcmp(service, "80") != 0) ||
	    family != NETWORKCMP_AF_UNSPEC || socket_type != NETWORKCMP_SOCK_ANY ||
	    flags != NETWORKCMP_RESOLVE_F_CANONNAME || results == NULL ||
	    count == NULL || *count < 1 || canonname == NULL ||
	    canonname_size < sizeof("localhost") || ttl == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("resolve") == -1)
		return (-1);
	memset(results, 0, sizeof(*results));
	results[0].endpoint.family = getenv("CMP_TEST_BAD_FAMILY") == NULL ?
	    NETWORKCMP_AF_INET4 : 99;
	memcpy(results[0].endpoint.address, loopback, sizeof(loopback));
	results[0].endpoint.port = service == NULL ? 0 : 80;
	results[0].socket_type = NETWORKCMP_SOCK_STREAM;
	results[0].protocol = 6;
	*count = 1;
	strlcpy(canonname, "localhost", canonname_size);
	*ttl = 60;
	return (0);
}

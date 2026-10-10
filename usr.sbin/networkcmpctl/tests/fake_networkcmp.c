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
	    .features = NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
	        NETWORKCMP_FEATURE_DNS,
	    .max_resolve_results = 16,
	};
	*result = &client;
	return (0);
}

int
networkcmp_client_open_admin(struct networkcmp_client **result)
{
	return (networkcmp_client_open(result));
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
	const char *expected_family = getenv("CMP_TEST_FAMILY");
	const char *expected_flags = getenv("CMP_TEST_FLAGS");
	uint32_t want_family = expected_family != NULL ?
	    (uint32_t)strtoul(expected_family, NULL, 0) : NETWORKCMP_AF_UNSPEC;
	uint32_t want_flags = expected_flags != NULL ?
	    (uint32_t)strtoul(expected_flags, NULL, 0) : NETWORKCMP_RESOLVE_F_CANONNAME;

	if (value != &client || !client.open || strcmp(host, "localhost") != 0 ||
	    (service != NULL && strcmp(service, "80") != 0) ||
	    family != want_family || socket_type != NETWORKCMP_SOCK_ANY ||
	    flags != want_flags || results == NULL ||
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
	if (family == NETWORKCMP_AF_INET6) {
		results[0].endpoint.family = NETWORKCMP_AF_INET6;
		memset(results[0].endpoint.address, 0, 16);
		if ((flags & NETWORKCMP_RESOLVE_F_V4MAPPED) != 0) {
			results[0].endpoint.address[10] = 0xff;
			results[0].endpoint.address[11] = 0xff;
			memcpy(results[0].endpoint.address + 12, loopback, 4);
		} else
			results[0].endpoint.address[15] = 1;
	}
	results[0].endpoint.port = service == NULL ? 0 : 80;
	results[0].socket_type = NETWORKCMP_SOCK_STREAM;
	results[0].protocol = 6;
	*count = 1;
	strlcpy(canonname, "localhost", canonname_size);
	*ttl = 60;
	return (0);
}

int
networkcmp_listen(struct networkcmp_client *value, uint16_t backlog,
    uint16_t *port_out, int *out_fd)
{
	(void)backlog;
	if (value == NULL || !value->open || port_out == NULL || out_fd == NULL)
		return (errno = EINVAL, -1);
	if (fail("listen") == -1)
		return (-1);
	*port_out = 12345;
	*out_fd = -1;
	return (0);
}

int
networkcmp_connect_ex(struct networkcmp_client *value,
    const struct sockaddr *address, socklen_t address_length,
    uint32_t timeout_ms, int *out_fd)
{
	(void)address;
	(void)address_length;
	(void)timeout_ms;
	if (value == NULL || !value->open || out_fd == NULL)
		return (errno = EINVAL, -1);
	if (fail("connect") == -1)
		return (-1);
	*out_fd = -1;
	return (0);
}

int
networkcmp_udp(struct networkcmp_client *value, const struct sockaddr *peer,
    socklen_t peer_length, int *out_fd)
{
	(void)peer;
	(void)peer_length;
	if (value == NULL || !value->open || out_fd == NULL)
		return (errno = EINVAL, -1);
	if (fail("udp") == -1)
		return (-1);
	*out_fd = -1;
	return (0);
}

#include <network_state.h>
struct network_state_client { unsigned calls; };
static struct network_state_client state_client;
int
network_state_open(struct network_state_client **out)
{
	if (fail("state-open") == -1)
		return (-1);
	state_client.calls = 0;
	*out = &state_client;
	return (0);
}
int
network_state_watch(struct network_state_client *value,
    struct network_state_snapshot *out, uint32_t timeout)
{
	if (fail("state-watch") == -1)
		return (-1);
	if (getenv("CMP_TEST_TIMEOUT") != NULL && timeout != 17)
		return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out));
	out->epoch = 7;
	out->generation = ++value->calls;
	if (getenv("CMP_TEST_SOURCE_ERROR") != NULL) {
		out->source_error = EIO;
		return (0);
	}
	out->count = 1;
	out->interfaces[0].index = 1;
	out->interfaces[0].mtu = 1500;
	out->interfaces[0].link_state = NETWORK_STATE_LINK_UP;
	strlcpy(out->interfaces[0].name, "v\n0", sizeof(out->interfaces[0].name));
	return (0);
}
void
network_state_close(struct network_state_client *value)
{
	(void)value;
	if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
		fprintf(stderr, "state-client-closed\n");
}

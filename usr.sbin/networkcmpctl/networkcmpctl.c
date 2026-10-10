/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <networkcmp.h>
#include <network_state.h>

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: networkcmpctl config\n"
	    "       networkcmpctl info\n"
	    "       networkcmpctl state-watch [count [timeout-ms]]\n"
	    "       networkcmpctl listen\n"
	    "       networkcmpctl connect addr port\n"
	    "       networkcmpctl udp addr port\n"
	    "       networkcmpctl resolve [-4|-6] [-m] [-a] host [service]\n");
	exit(EX_USAGE);
}

static struct networkcmp_client *
open_client(void)
{
	struct networkcmp_client *client;

	/* Approved by its own identity: system.network.admin. */
	if (networkcmp_client_open_admin(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", NETWORKCMP_ADMIN_INTERFACE);
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
	printf("features=0x%08x max_resolve_results=%u\n",
	    limits->features, limits->max_resolve_results);
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
resolve(const char *host, const char *service, uint32_t family, uint32_t flags)
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
	if (networkcmp_resolve(client, host, service, family,
	    NETWORKCMP_SOCK_ANY, flags | NETWORKCMP_RESOLVE_F_CANONNAME, results,
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

static int
resolve_command(int argc, char **argv)
{
	uint32_t family = NETWORKCMP_AF_UNSPEC, flags = 0, selected;

	while (argc > 0 && argv[0][0] == '-') {
		if (strcmp(argv[0], "--") == 0) {
			argc--;
			argv++;
			break;
		}
		if (strcmp(argv[0], "-4") == 0 || strcmp(argv[0], "-6") == 0) {
			selected = argv[0][1] == '4' ? NETWORKCMP_AF_INET4 : NETWORKCMP_AF_INET6;
			if (family != NETWORKCMP_AF_UNSPEC && family != selected)
				usage();
			family = selected;
		} else if (strcmp(argv[0], "-m") == 0)
			flags |= NETWORKCMP_RESOLVE_F_V4MAPPED;
		else if (strcmp(argv[0], "-a") == 0)
			flags |= NETWORKCMP_RESOLVE_F_ALL;
		else
			usage();
		argc--;
		argv++;
	}
	if (argc < 1 || argc > 2 ||
	    (flags != 0 && family != NETWORKCMP_AF_INET6) ||
	    ((flags & NETWORKCMP_RESOLVE_F_ALL) != 0 &&
	    (flags & NETWORKCMP_RESOLVE_F_V4MAPPED) == 0))
		usage();
	return (resolve(argv[0], argc == 2 ? argv[1] : NULL, family, flags));
}

/*
 * Exercise the LISTEN capability end to end: obtain a listening descriptor on
 * an OS-assigned loopback port from the broker, connect to it, accept the
 * connection, and verify a byte flows.  The connect uses a raw socket rather
 * than the plane's CONNECT, which (correctly) blocks loopback as an internal
 * SSRF target: a locally-advertised listener's natural client connects directly.
 */
static int
do_listen(void)
{
	struct networkcmp_client *client;
	struct sockaddr_in sin;
	uint16_t port = 0;
	int lfd = -1, cfd, afd, error;
	char buf = 0;

	client = open_client();
	if (networkcmp_listen(client, 0, &port, &lfd) == -1) {
		error = errno;
		networkcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "listen");
	}
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd == -1)
		err(EX_OSERR, "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(cfd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(EX_UNAVAILABLE, "connect 127.0.0.1:%u", port);
	afd = accept(lfd, NULL, NULL);
	if (afd == -1)
		err(EX_UNAVAILABLE, "accept");
	if (write(cfd, "x", 1) != 1 || read(afd, &buf, 1) != 1 || buf != 'x')
		errx(EX_UNAVAILABLE, "listener data path failed");
	printf("listen ok: port=%u accepted and verified\n", port);
	(void)close(afd);
	(void)close(cfd);
	(void)close(lfd);
	networkcmp_client_close(client);
	return (0);
}

/*
 * Exercise CONNECT: ask the broker to open a connected TCP socket to a numeric
 * address.  Its point in this rig is to prove the born-in-capmode broker can
 * reach connect(2) at all -- capmode blocks plain connect(2) and AT_FDCWD
 * connectat(2), so a working path returns a connected fd or an ordinary network
 * error (ETIMEDOUT/ECONNREFUSED/EHOSTUNREACH), NEVER ECAPMODE.
 */
static int
do_connect(const char *ip, const char *port)
{
	struct networkcmp_client *client;
	struct sockaddr_in sin;
	char *end;
	unsigned long p;
	int fd = -1, error;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	errno = 0;
	p = strtoul(port, &end, 10);
	if (errno != 0 || end == port || *end != '\0' || p == 0 || p > 65535)
		errx(EX_USAGE, "connect: invalid port \"%s\"", port);
	sin.sin_port = htons((uint16_t)p);
	if (inet_pton(AF_INET, ip, &sin.sin_addr) != 1)
		errx(EX_USAGE, "connect: invalid address \"%s\"", ip);
	client = open_client();
	/* Bound the attempt so an unroutable address does not hang the tool. */
	if (networkcmp_connect_ex(client, (const struct sockaddr *)&sin,
	    sizeof(sin), 3000, &fd) == -1) {
		error = errno;
		networkcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "connect %s:%s", ip, port);
	}
	printf("connect ok: connected to %s:%s\n", ip, port);
	(void)close(fd);
	networkcmp_client_close(client);
	return (0);
}

/*
 * Exercise UDP: ask the broker to open a connected SOCK_DGRAM socket to a
 * numeric address.  Its point in this rig -- which has no network -- is to prove
 * the born-in-capmode broker can reach the datagram connect path at all: capmode
 * blocks plain connect(2) and AT_FDCWD connectat(2), and UDP has no pr_connectat,
 * so a working path returns a connected fd or an ordinary network error
 * (ENETUNREACH/EADDRNOTAVAIL), NEVER ECAPMODE.
 */
static int
do_udp(const char *ip, const char *port)
{
	struct networkcmp_client *client;
	struct sockaddr_in sin;
	char *end;
	unsigned long p;
	int fd = -1, error;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	errno = 0;
	p = strtoul(port, &end, 10);
	if (errno != 0 || end == port || *end != '\0' || p == 0 || p > 65535)
		errx(EX_USAGE, "udp: invalid port \"%s\"", port);
	sin.sin_port = htons((uint16_t)p);
	if (inet_pton(AF_INET, ip, &sin.sin_addr) != 1)
		errx(EX_USAGE, "udp: invalid address \"%s\"", ip);
	client = open_client();
	if (networkcmp_udp(client, (const struct sockaddr *)&sin,
	    sizeof(sin), &fd) == -1) {
		error = errno;
		networkcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "udp %s:%s", ip, port);
	}
	printf("udp ok: connected datagram socket to %s:%s\n", ip, port);
	(void)close(fd);
	networkcmp_client_close(client);
	return (0);
}

static uint32_t
state_number(const char *text, uint32_t minimum)
{
	char *end;
	uintmax_t value;

	if (*text < '0' || *text > '9')
		errx(EX_USAGE, "state-watch: invalid number %s", text);
	errno = 0;
	value = strtoumax(text, &end, 10);
	if (errno != 0 || *end != '\0' || value < minimum ||
	    value > UINT32_MAX)
		errx(EX_USAGE, "state-watch: invalid number %s", text);
	return ((uint32_t)value);
}

static int
state_watch(int argc, char **argv)
{
	struct network_state_client *client;
	struct network_state_snapshot state;
	uint32_t count = argc >= 3 ? state_number(argv[2], 1) : 1;
	uint32_t timeout = argc >= 4 ? state_number(argv[3], 0) :
	    NETWORK_STATE_TIMEOUT_INFINITE;
	int error;

	if (network_state_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", NETWORK_STATE_INTERFACE);
	for (uint32_t sample = 0; sample < count; sample++) {
		if (network_state_watch(client, &state, timeout) == -1) {
			error = errno;
			network_state_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "state-watch");
		}
		printf("epoch=%" PRIu64 " generation=%" PRIu64
		    " source_error=%d count=%u\n", state.epoch,
		    state.generation, state.source_error, state.count);
		for (uint32_t i = 0; i < state.count; i++) {
			const struct network_state_interface *entry = &state.interfaces[i];
			printf("index=%u name=", entry->index);
			for (size_t j = 0; entry->name[j] != '\0'; j++) {
				unsigned char c = entry->name[j];
				if (c <= ' ' || c >= 127 || c == '\\')
					printf("\\x%02x", c);
				else
					putchar(c);
			}
			printf(" flags=0x%08x mtu=%u link=%s\n", entry->flags,
			    entry->mtu, entry->link_state == NETWORK_STATE_LINK_UP ?
			    "up" : entry->link_state == NETWORK_STATE_LINK_DOWN ?
			    "down" : "unknown");
		}
		if (fflush(stdout) == EOF) {
			error = errno;
			network_state_close(client);
			errno = error;
			err(EX_IOERR, "stdout");
		}
	}
	network_state_close(client);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc >= 2 && argc <= 4 && strcmp(argv[1], "state-watch") == 0)
		return (state_watch(argc, argv));
	if (argc == 2 && strcmp(argv[1], "config") == 0) {
		puts("# No manifest declaration is required: link libnetworkcmp and");
		puts("# call networkcmp_*().  The system.Network service is reached at");
		puts("# runtime via service_connect(3), like any global service.");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "info") == 0)
		return (info());
	if (argc == 2 && strcmp(argv[1], "listen") == 0)
		return (do_listen());
	if (argc == 4 && strcmp(argv[1], "connect") == 0)
		return (do_connect(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "udp") == 0)
		return (do_udp(argv[2], argv[3]));
	if (argc >= 2 && strcmp(argv[1], "resolve") == 0)
		return (resolve_command(argc - 2, argv + 2));
	usage();
}

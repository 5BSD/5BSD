/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cap_rt_ioctl.h"
#include "cap_rt_isolation_proto.h"

static int
fi_net_call(int svc, uint32_t op, int domain, int protocol, uint16_t port,
    uint8_t direction, const char *addr, uint8_t prefix)
{
	struct cap_rt_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;

	memset(&nr, 0, sizeof(nr));
	nr.op = op;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port = port;
	nr.direction = direction;
	nr.prefix = prefix;

	if (addr != NULL && strcmp(addr, "-") != 0) {
		if (domain == AF_INET) {
			struct in_addr in4;

			if (inet_pton(AF_INET, addr, &in4) != 1)
				return (-1);
			nr.addr[10] = 0xff;
			nr.addr[11] = 0xff;
			memcpy(&nr.addr[12], &in4, sizeof(in4));
		} else if (domain == AF_INET6) {
			struct in6_addr in6;

			if (inet_pton(AF_INET6, addr, &in6) != 1)
				return (-1);
			memcpy(nr.addr, &in6, sizeof(in6));
		} else {
			return (-1);
		}
	}

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(svc, CAP_RT_CALL, &ca));
}

static int
socket_create(int domain, int type, int protocol)
{
	int s;

	s = socket(domain, type, protocol);
	if (s >= 0) {
		close(s);
		return (0);
	}
	if (errno == EACCES || errno == EPERM)
		return (1);
	return (2);
}

static int
socket_connect(int domain, int type, int protocol, const char *addr,
    uint16_t port)
{
	struct sockaddr_in sin;
	int s, error;

	if (domain != AF_INET)
		return (2);

	s = socket(domain, type, protocol);
	if (s < 0) {
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1) {
		close(s);
		return (2);
	}

	error = connect(s, (struct sockaddr *)&sin, sizeof(sin));
	close(s);
	if (error == 0)
		return (0);
	if (errno == EACCES || errno == EPERM)
		return (1);
	return (2);
}

static int
unix_socket_connect(const char *path)
{
	struct sockaddr_un sun;
	int s, error;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	error = connect(s, (struct sockaddr *)&sun, sizeof(sun));
	close(s);
	if (error == 0)
		return (0);
	if (errno == EACCES || errno == EPERM)
		return (1);
	return (2);
}

int
main(int argc, char **argv)
{
	char *end;
	const char *addr;
	int svc, op, domain, protocol;
	unsigned long port, direction, prefix;

	if (argc == 5 && strcmp(argv[1], "socket") == 0) {
		int type;

		domain = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		type = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		protocol = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);
		return (socket_create(domain, type, protocol));
	}

	if (argc == 3 && strcmp(argv[1], "unix-connect") == 0)
		return (unix_socket_connect(argv[2]));

	if (argc == 7 && strcmp(argv[1], "connect") == 0) {
		int type;

		domain = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		type = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		protocol = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);
		addr = argv[5];
		port = strtoul(argv[6], &end, 10);
		if (*end != '\0' || port > UINT16_MAX)
			return (2);
		return (socket_connect(domain, type, protocol, addr,
		    (uint16_t)port));
	}

	if (argc != 9)
		return (2);

	svc = (int)strtol(argv[1], &end, 10);
	if (*end != '\0')
		return (2);
	op = (int)strtol(argv[2], &end, 10);
	if (*end != '\0')
		return (2);
	domain = (int)strtol(argv[3], &end, 10);
	if (*end != '\0')
		return (2);
	protocol = (int)strtol(argv[4], &end, 10);
	if (*end != '\0')
		return (2);
	port = strtoul(argv[5], &end, 10);
	if (*end != '\0' || port > UINT16_MAX)
		return (2);
	direction = strtoul(argv[6], &end, 10);
	if (*end != '\0' || direction > UINT8_MAX)
		return (2);
	addr = argv[7];
	prefix = strtoul(argv[8], &end, 10);
	if (*end != '\0' || prefix > UINT8_MAX)
		return (2);

	if (fi_net_call(svc, (uint32_t)op, domain, protocol,
	    htons((uint16_t)port), (uint8_t)direction, addr,
	    (uint8_t)prefix) == 0)
		return (0);
	if (errno == EBUSY)
		return (1);
	return (2);
}

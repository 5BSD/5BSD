/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_isolation_proto.h"

static int
fi_net_call(int svc, uint32_t op, int domain, int protocol, uint16_t port,
    uint8_t direction, const char *addr, uint8_t prefix)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;

	memset(&nr, 0, sizeof(nr));
	nr.op = op;
	nr.domain = domain;
	nr.protocol = protocol;
	if (port == 0) {
		nr.port_min = htons(0);
		nr.port_max = htons(UINT16_MAX);
	} else {
		nr.port_min = port;
		nr.port_max = port;
	}
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
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
fi_net_query(int svc, int domain, int protocol, uint16_t port_min,
    uint16_t port_max, uint8_t direction, uint32_t expected_flags)
{
	struct mac_capability_call_args ca;
	struct fi_net_request nr;
	struct fi_reply rpl;

	memset(&nr, 0, sizeof(nr));
	nr.op = FI_OP_QUERY_NET;
	nr.domain = domain;
	nr.protocol = protocol;
	nr.port_min = htons(port_min);
	nr.port_max = htons(port_max);
	nr.direction = direction;

	memset(&ca, 0, sizeof(ca));
	ca.req = &nr;
	ca.req_len = sizeof(nr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (2);
	return (rpl.flags == expected_flags ? 0 : 1);
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

static int
fi_authorize(int token_fd)
{
	struct mac_capability_call_args ca;
	struct fi_request req;
	struct fi_reply rpl;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca));
}

int
main(int argc, char **argv)
{
	char *end;
	const char *addr;
	int svc, op, domain, protocol;
	unsigned long port, direction, prefix;

	/*
	 * net-token-bind <token_fd> <port>
	 *
	 * Authorize on the token, then try to bind a TCP socket
	 * on 127.0.0.1:<port>.
	 * Returns 0 if bind succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 4 && strcmp(argv[1], "net-token-bind") == 0) {
		int token_fd, s, error;
		struct sockaddr_in sin;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		port = strtoul(argv[3], &end, 10);
		if (*end != '\0' || port > UINT16_MAX)
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0) {
			if (errno == EACCES || errno == EPERM)
				return (1);
			return (2);
		}
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((uint16_t)port);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		error = bind(s, (struct sockaddr *)&sin, sizeof(sin));
		close(s);
		if (error == 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * net-token-query <svc_fd> <token_fd> <domain> <protocol>
	 *     <port_min> <port_max> <direction> <expected_flags>
	 */
	if (argc == 10 && strcmp(argv[1], "net-token-query") == 0) {
		int token_fd;
		unsigned long port_min, port_max, expected_flags;

		svc = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		token_fd = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		domain = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);
		protocol = (int)strtol(argv[5], &end, 10);
		if (*end != '\0')
			return (2);
		port_min = strtoul(argv[6], &end, 10);
		if (*end != '\0' || port_min > UINT16_MAX)
			return (2);
		port_max = strtoul(argv[7], &end, 10);
		if (*end != '\0' || port_max > UINT16_MAX)
			return (2);
		direction = strtoul(argv[8], &end, 10);
		if (*end != '\0' || direction > UINT8_MAX)
			return (2);
		expected_flags = strtoul(argv[9], &end, 10);
		if (*end != '\0' || expected_flags > UINT32_MAX)
			return (2);

		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);
		return (fi_net_query(svc, domain, protocol,
		    (uint16_t)port_min, (uint16_t)port_max,
		    (uint8_t)direction, (uint32_t)expected_flags));
	}

	/*
	 * net-try-bind <port>
	 *
	 * Try to bind a TCP socket on 127.0.0.1:<port> without any token.
	 * Returns 0 if bind succeeds, 1 if blocked.
	 */
	if (argc == 3 && strcmp(argv[1], "net-try-bind") == 0) {
		int s, error;
		struct sockaddr_in sin;

		port = strtoul(argv[2], &end, 10);
		if (*end != '\0' || port > UINT16_MAX)
			return (2);

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0) {
			if (errno == EACCES || errno == EPERM)
				return (1);
			return (2);
		}
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((uint16_t)port);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		error = bind(s, (struct sockaddr *)&sin, sizeof(sin));
		close(s);
		if (error == 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * token-open <token_fd> <filepath> <mode> [twice]
	 *
	 * Authorize on the token, optionally authorize a second time,
	 * then open the file in read or write mode.
	 * Returns 0 if open succeeds, 1 if blocked, 10 if authorize failed.
	 */
	if ((argc == 5 || argc == 6) && strcmp(argv[1], "token-open") == 0) {
		int token_fd, fd, flags;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (strcmp(argv[4], "read") == 0)
			flags = O_RDONLY;
		else if (strcmp(argv[4], "write") == 0)
			flags = O_WRONLY;
		else if (strcmp(argv[4], "exec") == 0)
			flags = -1;	/* sentinel for execve path */
		else
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		if (argc == 6) {
			if (strcmp(argv[5], "twice") != 0)
				return (2);
			if (fi_authorize(token_fd) != 0)
				return (10);
		}
		if (flags == -1) {
			/* Try execve — it won't return on success,
			 * so fork first. */
			pid_t cpid = fork();
			if (cpid < 0) {
				close(token_fd);
				return (2);
			}
			if (cpid == 0) {
				close(token_fd);
				execl(argv[3], argv[3], NULL);
				_exit(errno == EACCES ? 1 : 2);
			}
			{
				int st;
				waitpid(cpid, &st, 0);
				close(token_fd);
				if (WIFEXITED(st))
					return (WEXITSTATUS(st));
				return (2);
			}
		}
		fd = open(argv[3], flags);
		if (fd >= 0) {
			close(fd);
			close(token_fd);
			return (0);
		}
		close(token_fd);
		return (1);
	}

	/*
	 * token-create <token_fd> <filepath>
	 *
	 * Authorize on the token, then try to create a file.
	 * Returns 0 if O_CREAT succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 4 && strcmp(argv[1], "token-create") == 0) {
		int token_fd, fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		fd = open(argv[3], O_CREAT | O_WRONLY | O_EXCL, 0644);
		if (fd >= 0) {
			unlink(argv[3]);
			close(fd);
			close(token_fd);
			return (0);
		}
		close(token_fd);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * token-rename <token_fd> <oldpath> <newpath>
	 *
	 * Authorize on the token, then try to rename.
	 * Returns 0 if rename succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 5 && strcmp(argv[1], "token-rename") == 0) {
		int token_fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);
		if (rename(argv[3], argv[4]) == 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * token-unlink <token_fd> <filepath>
	 *
	 * Authorize on the token, then try to unlink.
	 * Returns 0 if unlink succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 4 && strcmp(argv[1], "token-unlink") == 0) {
		int token_fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);
		if (unlink(argv[3]) == 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * token-uipc-connect <token_fd> <sockpath>
	 *
	 * Authorize on the token, then try to connect to a Unix socket.
	 * Returns 0 if connect succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 4 && strcmp(argv[1], "token-uipc-connect") == 0) {
		int token_fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);
		return (unix_socket_connect(argv[3]));
	}

	/*
	 * token-check <token_fd> <filepath>
	 *
	 * Authorize on the token, then try to open the file.
	 * Returns 0 if open succeeds, 1 if blocked, 10 if
	 * authorize failed.
	 */
	if (argc == 4 && strcmp(argv[1], "token-check") == 0) {
		int token_fd, fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		if (fi_authorize(token_fd) != 0)
			return (10);
		fd = open(argv[3], O_RDONLY);
		if (fd >= 0) {
			close(fd);
			close(token_fd);
			return (0);
		}
		close(token_fd);
		return (1);
	}

	/*
	 * token-revoke <token_fd> <ready_fd> <go_fd> <filepath>
	 *
	 * Authorize on the token, close it, signal the parent via
	 * ready_fd, wait for parent on go_fd, then try to open the
	 * file.  Returns 0 if open is blocked (revoke worked),
	 * 1 if open succeeded (revoke failed), 10 if authorize failed.
	 */
	if (argc == 6 && strcmp(argv[1], "token-revoke") == 0) {
		int token_fd, ready_fd, go_fd, fd;
		char buf;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		ready_fd = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		go_fd = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);

		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);

		write(ready_fd, "r", 1);
		close(ready_fd);

		read(go_fd, &buf, 1);
		close(go_fd);

		fd = open(argv[5], O_RDONLY);
		if (fd < 0)
			return (0);	/* blocked — revoke worked */
		close(fd);
		return (1);		/* opened — revoke failed */
	}

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

	if (argc == 9 && strcmp(argv[1], "net-range") == 0) {
		struct mac_capability_call_args ca;
		struct fi_net_request nr;
		struct fi_reply rpl;
		unsigned long port_min, port_max;

		svc = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		op = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		domain = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);
		protocol = (int)strtol(argv[5], &end, 10);
		if (*end != '\0')
			return (2);
		port_min = strtoul(argv[6], &end, 10);
		if (*end != '\0' || port_min > UINT16_MAX)
			return (2);
		port_max = strtoul(argv[7], &end, 10);
		if (*end != '\0' || port_max > UINT16_MAX)
			return (2);
		direction = strtoul(argv[8], &end, 10);
		if (*end != '\0' || direction > UINT8_MAX)
			return (2);

		memset(&nr, 0, sizeof(nr));
		nr.op = (uint32_t)op;
		nr.domain = domain;
		nr.protocol = protocol;
		nr.port_min = htons((uint16_t)port_min);
		nr.port_max = htons((uint16_t)port_max);
		nr.direction = (uint8_t)direction;

		memset(&ca, 0, sizeof(ca));
		ca.req = &nr;
		ca.req_len = sizeof(nr);
		ca.reply = &rpl;
		ca.reply_len = sizeof(rpl);
		if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) == 0)
			return (0);
		if (errno == EBUSY || errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * net-query <svc_fd> <domain> <protocol> <port_min> <port_max>
	 *     <direction> <expected_flags>
	 */
	if (argc == 9 && strcmp(argv[1], "net-query") == 0) {
		unsigned long port_min, port_max, expected_flags;

		svc = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		domain = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		protocol = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);
		port_min = strtoul(argv[5], &end, 10);
		if (*end != '\0' || port_min > UINT16_MAX)
			return (2);
		port_max = strtoul(argv[6], &end, 10);
		if (*end != '\0' || port_max > UINT16_MAX)
			return (2);
		direction = strtoul(argv[7], &end, 10);
		if (*end != '\0' || direction > UINT8_MAX)
			return (2);
		expected_flags = strtoul(argv[8], &end, 10);
		if (*end != '\0' || expected_flags > UINT32_MAX)
			return (2);

		return (fi_net_query(svc, domain, protocol,
		    (uint16_t)port_min, (uint16_t)port_max,
		    (uint8_t)direction, (uint32_t)expected_flags));
	}

	/*
	 * jail-create <name>
	 *
	 * Try to create a persist jail with the given name.
	 * Returns 0 if jail_set succeeds, 1 if EACCES/EPERM, 2 on other error.
	 * On success, prints the JID to stdout.
	 */
	if (argc == 3 && strcmp(argv[1], "jail-create") == 0) {
		struct iovec iov[6];
		char *jname = argv[2];
		int jid, persist = 1;

		iov[0].iov_base = __DECONST(char *, "name");
		iov[0].iov_len = sizeof("name");
		iov[1].iov_base = jname;
		iov[1].iov_len = strlen(jname) + 1;
		iov[2].iov_base = __DECONST(char *, "path");
		iov[2].iov_len = sizeof("path");
		iov[3].iov_base = __DECONST(char *, "/");
		iov[3].iov_len = sizeof("/");
		iov[4].iov_base = __DECONST(char *, "persist");
		iov[4].iov_len = sizeof("persist");
		iov[5].iov_base = &persist;
		iov[5].iov_len = sizeof(persist);

		jid = jail_set(iov, 6, JAIL_CREATE);
		if (jid >= 0) {
			char buf[16];
			int len = snprintf(buf, sizeof(buf), "%d\n", jid);
			write(STDOUT_FILENO, buf, (size_t)len);
			return (0);
		}
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * jail-get <jid>
	 *
	 * Try jail_get on the given JID.
	 * Returns 0 on success, 1 if EACCES/EPERM.
	 */
	if (argc == 3 && strcmp(argv[1], "jail-get") == 0) {
		struct iovec iov[2];
		int jid;

		jid = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);

		iov[0].iov_base = __DECONST(char *, "jid");
		iov[0].iov_len = sizeof("jid");
		iov[1].iov_base = &jid;
		iov[1].iov_len = sizeof(jid);

		if (jail_get(iov, 2, 0) >= 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * jail-remove <jid>
	 *
	 * Try jail_remove on the given JID.
	 * Returns 0 on success, 1 if EACCES/EPERM.
	 */
	if (argc == 3 && strcmp(argv[1], "jail-remove") == 0) {
		int jid;

		jid = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);

		if (jail_remove(jid) == 0)
			return (0);
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * jail-token-create <token_fd> <name>
	 *
	 * Authorize on the token, then try to create a persist jail.
	 * Returns 0 if jail_set succeeds, 1 if EACCES/EPERM,
	 * 10 if authorize failed.  On success, prints JID.
	 */
	if (argc == 4 && strcmp(argv[1], "jail-token-create") == 0) {
		int token_fd, jid, persist = 1;
		char *jname;
		struct iovec iov[6];

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		jname = argv[3];

		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);

		iov[0].iov_base = __DECONST(char *, "name");
		iov[0].iov_len = sizeof("name");
		iov[1].iov_base = jname;
		iov[1].iov_len = strlen(jname) + 1;
		iov[2].iov_base = __DECONST(char *, "path");
		iov[2].iov_len = sizeof("path");
		iov[3].iov_base = __DECONST(char *, "/");
		iov[3].iov_len = sizeof("/");
		iov[4].iov_base = __DECONST(char *, "persist");
		iov[4].iov_len = sizeof("persist");
		iov[5].iov_base = &persist;
		iov[5].iov_len = sizeof(persist);

		jid = jail_set(iov, 6, JAIL_CREATE);
		if (jid >= 0) {
			char buf[16];
			int len = snprintf(buf, sizeof(buf), "%d\n", jid);
			write(STDOUT_FILENO, buf, (size_t)len);
			return (0);
		}
		if (errno == EACCES || errno == EPERM)
			return (1);
		return (2);
	}

	/*
	 * token-query <token_fd> <svc_fd> <target_fd>
	 *
	 * Authorize on the token, then query the vnode via svc_fd.
	 * Returns the query flags as exit code (0-7), 10 if authorize
	 * failed, 11 if query failed.
	 */
	if (argc == 5 && strcmp(argv[1], "token-query") == 0) {
		struct mac_capability_call_args ca;
		struct fi_request req;
		struct fi_reply rpl;
		int token_fd, svc_fd, target_fd;

		token_fd = (int)strtol(argv[2], &end, 10);
		if (*end != '\0')
			return (2);
		svc_fd = (int)strtol(argv[3], &end, 10);
		if (*end != '\0')
			return (2);
		target_fd = (int)strtol(argv[4], &end, 10);
		if (*end != '\0')
			return (2);

		if (fi_authorize(token_fd) != 0)
			return (10);
		close(token_fd);

		memset(&req, 0, sizeof(req));
		req.op = FI_OP_QUERY;
		req.actions = FI_FS_ALL;
		memset(&ca, 0, sizeof(ca));
		ca.req = &req;
		ca.req_len = sizeof(req);
		ca.req_fds = &target_fd;
		ca.req_nfds = 1;
		ca.reply = &rpl;
		ca.reply_len = sizeof(rpl);
		if (ioctl(svc_fd, MAC_CAPABILITY_CALL, &ca) != 0)
			return (11);
		return ((int)(rpl.flags & 0x07));
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

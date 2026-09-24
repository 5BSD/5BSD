/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 NETLINK_SOCK_DIAG probe. Run only in disposable guests. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct nladdr { uint16_t family, pad; uint32_t pid, groups; };
struct nlhead { uint32_t len; uint16_t type, flags; uint32_t seq, pid; };
struct diag_id { uint16_t sport, dport; uint32_t src[4], dst[4], index, cookie[2]; };
struct diag_req { uint8_t family, proto, ext, pad; uint32_t states; struct diag_id id; };
struct diag_msg { uint8_t family, state, timer, retrans; struct diag_id id; uint32_t expires, rx, tx, uid, inode; };
_Static_assert(sizeof(struct diag_req) == 56, "request ABI");
_Static_assert(sizeof(struct diag_msg) == 72, "reply ABI");
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "DIAG line %d: %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
static uint32_t
loopback4(void)
{
	struct in_addr addr;
	const char *text = getenv("DIAG_IPV4");
	CHECK(inet_pton(AF_INET, text != NULL ? text : "127.0.0.1", &addr) == 1);
	return addr.s_addr;
}
static uint32_t seq;
static uint8_t request_attrs[512];
static size_t request_attrs_len;
static struct diag_msg found;
static unsigned matches, total;
static unsigned attrs;
static uint8_t diag_tos, diag_tclass, diag_shutdown;
static uint32_t diag_memory[9], diag_meminfo[4], diag_info[26];
static char diag_congestion[32];

static void
attributes(const char *buf, size_t len)
{
	attrs = 0;
	memset(diag_info, 0, sizeof(diag_info));
	while (len != 0) {
		uint16_t size, type;
		CHECK(len >= 4);
		memcpy(&size, buf, 2);
		memcpy(&type, buf + 2, 2);
		CHECK(size >= 4 && size <= len);
		type &= 0x3fff;
		if (type <= 8) {
			CHECK((attrs & (1U << type)) == 0);
			attrs |= 1U << type;
		}
		switch (type) {
		case 1:
			CHECK(size == 4 + sizeof(diag_meminfo));
			memcpy(diag_meminfo, buf + 4, sizeof(diag_meminfo));
			break;
		case 2:
			CHECK(size >= 4 + sizeof(diag_info));
			memcpy(diag_info, buf + 4, sizeof(diag_info));
			break;
		case 4:
			CHECK(size > 5 && size <= 4 + sizeof(diag_congestion));
			CHECK(buf[size - 1] == 0);
			memcpy(diag_congestion, buf + 4, size - 4);
			break;
		case 5: case 6: case 8:
			CHECK(size == 5);
			if (type == 5) diag_tos = buf[4];
			if (type == 6) diag_tclass = buf[4];
			if (type == 8) diag_shutdown = buf[4];
			break;
		case 7:
			CHECK(size >= 4 + sizeof(diag_memory));
			memcpy(diag_memory, buf + 4, sizeof(diag_memory));
			break;
		}
		size = (size + 3) & ~3U;
		CHECK(size <= len);
		buf += size;
		len -= size;
	}
}

static uint16_t bulk_ports[128];
static unsigned bulk_seen[128], bulk_count;

static int
query(struct diag_req *req, int dump, uint16_t port, int short_request)
{
	struct { struct nlhead h; struct diag_req r; uint8_t attrs[512]; } packet = {0};
	struct nladdr kernel = { .family = 16 }, local = { .family = 16 };
	struct timeval timeout = { .tv_sec = 5 };
	int fd = socket(16, SOCK_RAW, 4), result = 0, done = 0;
	char buf[32768];
	CHECK(fd >= 0);
	CHECK(bind(fd, (void *)&local, sizeof(local)) == 0);
	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
	packet.h.len = sizeof(packet.h) + sizeof(packet.r) + request_attrs_len - (short_request ? 1 : 0);
	memcpy(packet.attrs, request_attrs, request_attrs_len);
	packet.h.type = 20;
	packet.h.flags = 1 | (dump ? 0x300 : 0);
	packet.h.seq = ++seq;
	packet.r = *req;
	if (!dump && req->proto == 17) {
		uint32_t addr[4];
		packet.r.id.sport = req->id.dport;
		packet.r.id.dport = req->id.sport;
		memcpy(addr, req->id.src, sizeof(addr));
		memcpy(packet.r.id.src, req->id.dst, sizeof(addr));
		memcpy(packet.r.id.dst, addr, sizeof(addr));
	}
	CHECK(sendto(fd, &packet, packet.h.len, 0, (void *)&kernel, sizeof(kernel)) == packet.h.len);
	matches = total = 0;
	memset(bulk_seen, 0, sizeof(bulk_seen));
	while (!done) {
		socklen_t len = sizeof(kernel);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (void *)&kernel, &len);
		CHECK(n >= (ssize_t)sizeof(struct nlhead));
		CHECK(kernel.pid == 0);
		for (size_t off = 0; off < (size_t)n;) {
			struct nlhead h;
			CHECK((size_t)n - off >= sizeof(h));
			memcpy(&h, buf + off, sizeof(h));
			CHECK(h.len >= sizeof(h) && h.len <= (size_t)n - off);
			CHECK(h.seq == seq);
			if (h.type == 2 || h.type == 3) {
				CHECK(h.len >= sizeof(h) + sizeof(int));
				memcpy(&result, buf + off + sizeof(h), sizeof(result));
				done = 1;
			} else {
				struct diag_msg row;
				CHECK(h.type == 20 && h.len >= sizeof(h) + sizeof(row));
				memcpy(&row, buf + off + sizeof(h), sizeof(row));
				CHECK(row.family == req->family);
				CHECK(!dump || (h.flags & 2));
				total++;
				for (unsigned j = 0; j < bulk_count; j++)
					if (row.id.sport == bulk_ports[j]) bulk_seen[j]++;
				if (row.id.sport == port) {
					found = row;
					matches++;
					attributes(buf + off + sizeof(h) + sizeof(row),
					    h.len - sizeof(h) - sizeof(row));
				}
				if (!dump) done = 1;
			}
			off += (h.len + 3) & ~3U;
			CHECK(off <= (size_t)n);
		}
	}
	CHECK(close(fd) == 0);
	return result;
}
static void
bytecode(uint8_t opcode, uint8_t yes, uint16_t no, const void *arg, size_t len)
{
	uint16_t size = 8 + len, type = 1;
	memset(request_attrs, 0, sizeof(request_attrs));
	memcpy(request_attrs, &size, 2);
	memcpy(request_attrs + 2, &type, 2);
	request_attrs[4] = opcode;
	request_attrs[5] = yes;
	memcpy(request_attrs + 6, &no, 2);
	if (len != 0) memcpy(request_attrs + 8, arg, len);
	request_attrs_len = (size + 3) & ~3U;
}

static void
filters(struct diag_req *req, uint16_t port)
{
	struct diag_id saved = req->id;
	uint16_t pair[2] = {0, ntohs(port)};
	uint32_t dev = 0;
	struct { uint8_t family, prefix; uint16_t pad; int32_t port; uint32_t addr[4]; } host = {0};
	for (unsigned opcode = 0; opcode <= 12; opcode++) {
		if (opcode == 10) continue;
		if (opcode == 0 || opcode == 1 || opcode == 6) {
			bytecode(opcode, 4, 8, NULL, 0);
			CHECK(query(req, 1, port, 0) == 0 && matches == (opcode != 1));
		} else if (opcode == 7 || opcode == 8) {
			host.family = req->family;
			host.prefix = req->family == AF_INET ? 32 : 128;
			host.port = -1;
			memcpy(host.addr, opcode == 7 ? saved.src : saved.dst, sizeof(host.addr));
			size_t len = req->family == AF_INET ? 12 : 24;
			bytecode(opcode, 4 + len, 8 + len, &host, len);
			CHECK(query(req, 1, port, 0) == 0 && matches == 1);
			((uint8_t *)host.addr)[0] ^= 0x80;
			bytecode(opcode, 4 + len, 8 + len, &host, len);
			CHECK(query(req, 1, port, 0) == 0 && matches == 0);
			host.prefix++;
			bytecode(opcode, 4 + len, 8 + len, &host, len);
			CHECK(query(req, 1, port, 0) == -EINVAL);
		} else if (opcode == 9) {
			bytecode(opcode, 8, 12, &dev, sizeof(dev));
			CHECK(query(req, 1, port, 0) == 0 && matches == 1);
			dev = UINT32_MAX;
			bytecode(opcode, 8, 12, &dev, sizeof(dev));
			CHECK(query(req, 1, port, 0) == 0 && matches == 0);
		} else {
			int source = opcode == 2 || opcode == 3 || opcode == 11;
			pair[1] = ntohs(source ? saved.sport : saved.dport);
			bytecode(opcode, 8, 12, pair, sizeof(pair));
			CHECK(query(req, 1, port, 0) == 0 && matches == 1);
			if (opcode == 2 || opcode == 4) pair[1]++;
			else if (opcode == 3 || opcode == 5) {
				if (pair[1] == 0) continue;
				pair[1]--;
			} else pair[1] ^= 1;
			bytecode(opcode, 8, 12, pair, sizeof(pair));
			CHECK(query(req, 1, port, 0) == 0 && matches == 0);
		}
	}
	/* Two predicates: both must pass; the false branch skips to rejection. */
	pair[1] = ntohs(saved.sport);
	bytecode(11, 8, 20, pair, sizeof(pair));
	uint16_t size = 20, no = 12;
	memcpy(request_attrs, &size, 2);
	request_attrs[12] = 12;
	request_attrs[13] = 8;
	memcpy(request_attrs + 14, &no, 2);
	pair[1] = ntohs(saved.dport);
	memcpy(request_attrs + 16, pair, sizeof(pair));
	request_attrs_len = size;
	CHECK(query(req, 1, port, 0) == 0 && matches == 1);
	request_attrs[18] ^= 1;
	CHECK(query(req, 1, port, 0) == 0 && matches == 0);
	/* A branch to the second predicate is valid; its operand is not. */
	request_attrs[18] ^= 1;
	no = 8;
	request_attrs[6] = no;
	CHECK(query(req, 1, port, 0) == 0 && matches == 1);
	request_attrs[6] = 12;
	CHECK(query(req, 1, port, 0) == -EINVAL);
	/* A branch into an operand, a zero step, an unknown opcode, truncation. */
	bytecode(11, 8, 4, pair, sizeof(pair));
	CHECK(query(req, 1, port, 0) == -EINVAL);
	bytecode(0, 0, 0, NULL, 0);
	CHECK(query(req, 1, port, 0) == -EINVAL);
	bytecode(255, 4, 8, NULL, 0);
	CHECK(query(req, 1, port, 0) == -EINVAL);
	bytecode(11, 8, 12, NULL, 0);
	CHECK(query(req, 1, port, 0) == -EINVAL);
	/* The protocol attribute overrides the byte-sized header protocol. */
	uint32_t protocol = req->proto;
	uint16_t length = 8, type = 3;
	memcpy(request_attrs, &length, 2);
	memcpy(request_attrs + 2, &type, 2);
	memcpy(request_attrs + 4, &protocol, 4);
	request_attrs_len = 8;
	req->proto = 0;
	CHECK(query(req, 1, port, 0) == 0 && matches == 1);
	req->proto = protocol;
	request_attrs_len = 0;
	req->id.index = UINT32_MAX;
	/* The dump header index is ignored; BC_DEV_COND performs filtering. */
	CHECK(query(req, 1, port, 0) == 0 && matches == 1);
	req->id = saved;
	CHECK(query(req, 1, port, 0) == 0 && matches == 1);
}

static int
endpoint(int family, int type, uint16_t *port)
{
	struct sockaddr_storage addr = {0};
	socklen_t len;
	int fd = socket(family, type, 0);
	CHECK(fd >= 0);
	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)&addr;
		sin->sin_family = family;
		sin->sin_addr.s_addr = loopback4();
		len = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin = (void *)&addr;
		sin->sin6_family = family;
		sin->sin6_addr = in6addr_loopback;
		len = sizeof(*sin);
	}
	CHECK(bind(fd, (void *)&addr, len) == 0);
	if (type == SOCK_STREAM) CHECK(listen(fd, 8) == 0);
	CHECK(getsockname(fd, (void *)&addr, &len) == 0);
	*port = family == AF_INET ? ((struct sockaddr_in *)&addr)->sin_port : ((struct sockaddr_in6 *)&addr)->sin6_port;
	return fd;
}
int
main(int argc, char **argv)
{
	int family, type, fd, status, accepted = -1;
	int connected;
	pid_t churn = -1;
	uint16_t port;
	struct diag_req req = {0};
	if (argc == 4 && strcmp(argv[1], "hold") == 0) {
		FILE *ready;
		fd = endpoint(AF_INET, SOCK_STREAM, &port);
		CHECK((ready = fopen(argv[2], "w")) != NULL);
		fprintf(ready, "%u\n", ntohs(port));
		CHECK(fclose(ready) == 0);
		sleep(atoi(argv[3]));
		CHECK(close(fd) == 0);
		return 0;
	}
	CHECK(argc == 3);
	if (getenv("DIAG_UID") != NULL) {
		unsigned uid = atoi(getenv("DIAG_UID"));
		CHECK(setgid(uid) == 0 && setuid(uid) == 0);
	}
	family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
	type = strncmp(argv[2], "tcp", 3) == 0 ? SOCK_STREAM : SOCK_DGRAM;
	connected = strcmp(argv[2], "tcp-connected") == 0;
	alarm(45);
	fd = endpoint(family, type, &port);
	if (getenv("DIAG_HIDE_PORT") != NULL) {
		uint16_t hidden = htons(atoi(getenv("DIAG_HIDE_PORT")));
		for (int attempt = 0; port == hidden && attempt < 8; attempt++) {
			CHECK(close(fd) == 0);
			fd = endpoint(family, type, &port);
		}
		CHECK(port != hidden);
	}
	if (connected) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);
		char peek[7];
		int client = socket(family, SOCK_STREAM, 0);
		CHECK(client >= 0);
		CHECK(getsockname(fd, (void *)&addr, &len) == 0);
		CHECK(connect(client, (void *)&addr, len) == 0);
		accepted = accept(fd, NULL, NULL);
		CHECK(accepted >= 0 && close(fd) == 0);
		fd = client;
		CHECK(getsockname(fd, (void *)&addr, &len) == 0);
		port = family == AF_INET ? ((struct sockaddr_in *)&addr)->sin_port : ((struct sockaddr_in6 *)&addr)->sin6_port;
		CHECK(send(accepted, "payload", 7, 0) == 7);
		CHECK(recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_WAITALL) == 7);
	}
	if (getenv("DIAG_CHURN") != NULL) {
		churn = fork();
		CHECK(churn >= 0);
		if (churn == 0) {
			CHECK(close(fd) == 0);
			for (int i = 0; i < 1000; i++) {
				uint16_t unused;
				int other = endpoint(family, type, &unused);
				CHECK(close(other) == 0);
			}
			_exit(0);
		}
	}
	req.family = family;
	req.proto = type == SOCK_STREAM ? 6 : 17;
	req.states = UINT32_MAX;
	req.id.cookie[0] = req.id.cookie[1] = UINT32_MAX;
	CHECK(query(&req, 1, port, 0) == 0 && matches == 1);
	CHECK(found.state == (connected ? 1 : type == SOCK_STREAM ? 10 : 7));
	if (connected) CHECK(found.rx == 7);
	CHECK(found.uid == getuid() && found.inode != 0);
	CHECK(found.id.cookie[0] != UINT32_MAX || found.id.cookie[1] != UINT32_MAX);
	if (family == AF_INET) CHECK(found.id.src[0] == loopback4());
	else CHECK(memcmp(found.id.src, &in6addr_loopback, 16) == 0);
	if (getenv("DIAG_HIDE_PORT") != NULL) {
		uint16_t hidden = htons(atoi(getenv("DIAG_HIDE_PORT")));
		CHECK(query(&req, 1, hidden, 0) == 0 && matches == 0);
		CHECK(query(&req, 1, port, 0) == 0 && matches == 1);
	}
	if (getenv("DIAG_BULK") != NULL) {
		int extra[128];
		for (unsigned j = 0; j < 128; j++)
			extra[j] = endpoint(family, type, &bulk_ports[j]);
		bulk_count = 128;
		CHECK(query(&req, 1, port, 0) == 0 && matches == 1);
		for (unsigned j = 0; j < 128; j++) {
			if (bulk_seen[j] != 1)
				fprintf(stderr, "DIAG_BULK port=%u seen=%u total=%u\n", ntohs(bulk_ports[j]), bulk_seen[j], total);
			CHECK(bulk_seen[j] == 1);
			CHECK(close(extra[j]) == 0);
		}
		bulk_count = 0;
	}
	/* Request each extension separately and together, on exact and dump paths. */
	int traffic = 0x28;
	int traffic6 = 0x38;
	CHECK(setsockopt(fd, IPPROTO_IP, IP_TOS, &traffic, sizeof(traffic)) == 0);
	if (family == AF_INET6)
		CHECK(setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &traffic6, sizeof(traffic6)) == 0);
	for (unsigned mask = 1; mask <= 256; mask <<= 1) {
		req.ext = mask == 256 ? 255 : mask;
		CHECK(query(&req, 1, port, 0) == 0 && matches == 1);
		unsigned wanted = (1U << 8);
		if (req.ext & 1) wanted |= 1U << 1;
		if ((req.ext & 2) && type == SOCK_STREAM) wanted |= 1U << 2;
		if ((req.ext & 8) && type == SOCK_STREAM) wanted |= 1U << 4;
		if (req.ext & 16) wanted |= 1U << 5;
		if ((req.ext & 32) && family == AF_INET6) wanted |= 1U << 6;
		if (req.ext & 64) wanted |= 1U << 7;
		CHECK((attrs & wanted) == wanted);
		CHECK((attrs & 0xf6) == (wanted & 0xf6));
		CHECK(diag_shutdown == 0);
		if (req.ext & 16) CHECK(diag_tos == traffic);
		if ((req.ext & 32) && family == AF_INET6) CHECK(diag_tclass == traffic6);
		if (req.ext & 64) CHECK(diag_memory[1] > 0 && diag_memory[3] > 0);
		if ((req.ext & 8) && type == SOCK_STREAM) {
			char name[32] = {0};
			socklen_t len = sizeof(name);
			CHECK(getsockopt(fd, IPPROTO_TCP, 13, name, &len) == 0);
			CHECK(strcmp(name, diag_congestion) == 0);
		}
		if ((req.ext & 2) && type == SOCK_STREAM) {
			CHECK(((uint8_t *)diag_info)[0] == found.state);
			if (connected) {
				uint32_t socket_info[64];
				socklen_t len = sizeof(socket_info);
				CHECK(diag_info[2] > 0 && diag_info[4] > 0 && diag_info[20] > 0);
				CHECK(getsockopt(fd, IPPROTO_TCP, 11, socket_info, &len) == 0);
				CHECK(len >= 104 && socket_info[4] == diag_info[4]);
				CHECK(socket_info[20] == diag_info[20]);
			}
		}
	}
	req.id = found.id;
	CHECK(query(&req, 0, port, 0) == 0 && matches == 1 && (attrs & (1U << 7)));
	if (connected) {
		CHECK(shutdown(fd, SHUT_WR) == 0);
		CHECK(query(&req, 0, port, 0) == 0 && matches == 1 && (diag_shutdown & 2));
	}
	req.ext = 0;
	filters(&req, port);
	CHECK(query(&req, 0, port, 0) == 0 && matches == 1);
	req.id.cookie[0] ^= 0x12345678;
	CHECK(query(&req, 0, port, 0) == -(type == SOCK_STREAM ? ENOENT : ESTALE));
	req.id.cookie[0] ^= 0x12345678;
	req.states = 0;
	CHECK(query(&req, 1, port, 0) == 0 && total == 0);
	req.states = UINT32_MAX;
	CHECK(query(&req, 1, port, 1) == -EINVAL);
	if (churn > 0) {
		CHECK(waitpid(churn, &status, 0) == churn);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	if (connected) {
		char payload[7];
		CHECK(recv(fd, payload, sizeof(payload), MSG_WAITALL) == 7);
	}
	CHECK(close(fd) == 0);
	if (connected) {
		char byte;
		CHECK(recv(accepted, &byte, 1, 0) == 0);
		CHECK(close(accepted) == 0);
		req.states = 1U << 6; /* TIME_WAIT survives the last descriptor. */
		for (int attempt = 0; attempt < 100; attempt++) {
			CHECK(query(&req, 1, port, 0) == 0);
			if (matches == 1) break;
			usleep(10000);
		}
		CHECK(matches == 1 && found.state == 6 && found.inode == 0);
	} else {
		CHECK(query(&req, 0, port, 0) == -ENOENT);
	}
	printf("DIAG_PASS %s %s\n", argv[1], argv[2]);
	return 0;
}

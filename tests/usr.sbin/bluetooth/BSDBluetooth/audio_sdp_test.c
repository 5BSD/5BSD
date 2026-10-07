/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <sdp.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int created = -1, binds, connects, fail_connect;

int __wrap_socket(int, int, int);
int __wrap_bindat(int, int, const struct sockaddr *, socklen_t);
int __wrap_connectat(int, int, const struct sockaddr *, socklen_t);
int __wrap_getsockopt(int, int, int, void *, socklen_t *);

int
__wrap_socket(int domain, int type, int protocol)
{
	ATF_REQUIRE_EQ(PF_BLUETOOTH, domain);
	ATF_REQUIRE_EQ(SOCK_SEQPACKET, type);
	ATF_REQUIRE_EQ(BLUETOOTH_PROTO_L2CAP, protocol);
	created = open("/dev/null", O_RDWR);
	return (created);
}

int
__wrap_bindat(int authority, int fd, const struct sockaddr *sa, socklen_t len)
{
	const struct sockaddr_l2cap *address = (const void *)sa;
	ATF_REQUIRE_EQ(created, authority);
	ATF_REQUIRE_EQ(created, fd);
	ATF_REQUIRE_EQ(sizeof(*address), len);
	ATF_REQUIRE_EQ(AF_BLUETOOTH, address->l2cap_family);
	ATF_REQUIRE_EQ(BDADDR_BREDR, address->l2cap_bdaddr_type);
	ATF_REQUIRE_EQ(0, address->l2cap_psm);
	binds++;
	return (0);
}

int
__wrap_connectat(int authority, int fd, const struct sockaddr *sa, socklen_t len)
{
	const struct sockaddr_l2cap *address = (const void *)sa;
	ATF_REQUIRE_EQ(created, authority);
	ATF_REQUIRE_EQ(created, fd);
	ATF_REQUIRE_EQ(sizeof(*address), len);
	ATF_REQUIRE_EQ(htole16(NG_L2CAP_PSM_SDP), address->l2cap_psm);
	connects++;
	if (fail_connect) {
		errno = EACCES;
		return (-1);
	}
	return (0);
}

int
__wrap_getsockopt(int fd, int level, int name, void *data, socklen_t *len)
{
	uint16_t mtu = 672;
	ATF_REQUIRE_EQ(created, fd);
	ATF_REQUIRE_EQ(SOL_L2CAP, level);
	ATF_REQUIRE(name == SO_L2CAP_OMTU || name == SO_L2CAP_IMTU);
	ATF_REQUIRE_EQ(sizeof(mtu), *len);
	memcpy(data, &mtu, sizeof(mtu));
	return (0);
}

ATF_TC_WITHOUT_HEAD(capability_transport);
ATF_TC_BODY(capability_transport, tc)
{
	bdaddr_t local = {{0}}, peer = {{1, 2, 3, 4, 5, 6}};
	void *session;
	(void)tc;
	for (fail_connect = 0; fail_connect != 2; fail_connect++) {
		binds = connects = 0;
		session = sdp_open(&local, &peer);
		ATF_REQUIRE(session != NULL);
		ATF_REQUIRE_EQ(fail_connect ? EACCES : 0, sdp_error(session));
		ATF_REQUIRE_EQ(1, binds);
		ATF_REQUIRE_EQ(1, connects);
		ATF_REQUIRE_EQ(0, sdp_close(session));
		ATF_REQUIRE_EQ(-1, fcntl(created, F_GETFD));
		ATF_REQUIRE_EQ(EBADF, errno);
	}
}

ATF_TC_WITHOUT_HEAD(invalid_address_preserves_stdin);
ATF_TC_BODY(invalid_address_preserves_stdin, tc)
{
	void *session;
	int fd;
	(void)tc;
	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, dup2(fd, 0));
	if (fd != 0)
		close(fd);
	session = sdp_open(NULL, NULL);
	ATF_REQUIRE(session != NULL);
	ATF_REQUIRE_EQ(EINVAL, sdp_error(session));
	ATF_REQUIRE_EQ(0, sdp_close(session));
	ATF_REQUIRE(fcntl(0, F_GETFD) >= 0);
	ATF_REQUIRE_EQ(-1, created);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capability_transport);
	ATF_TP_ADD_TC(tp, invalid_address_preserves_stdin);
	return (atf_no_error());
}

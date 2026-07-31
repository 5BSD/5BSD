/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <notifycmp.h>

#include "transport.h"

static struct notifycmp_msg
hello(void)
{
	struct notifycmp_msg message;

	memset(&message, 0, sizeof(message));
	ATF_REQUIRE_EQ(notifycmp_message_init(&message,
	    NOTIFYCMP_OP_HELLO, 0), 0);
	return (message);
}

ATF_TC_WITHOUT_HEAD(messages);
ATF_TC_BODY(messages, tc)
{
	struct {
		struct notifycmp_msg message;
		char payload[16];
	} oversized;
	struct notifycmp_msg request, received;
	char malformed;
	int sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_send(sv[0], NULL, sizeof(request),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_receive(sv[1], NULL, sizeof(received),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_receive(sv[1], &received, sizeof(received) - 1,
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);
	request = hello();
	ATF_REQUIRE_EQ(internal_send(sv[0], &request, sizeof(request),
	    NOTIFYCMP_MESSAGE_REQUEST), 0);
	ATF_REQUIRE_EQ(internal_receive(sv[1], &received, sizeof(received),
	    NOTIFYCMP_MESSAGE_REQUEST), sizeof(received));
	ATF_CHECK_EQ(memcmp(&request, &received, sizeof(request)), 0);

	request.status = -EINVAL;
	ATF_CHECK_ERRNO(EPROTO,
	    internal_send(sv[0], &request, sizeof(request),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);
	malformed = 0;
	ATF_REQUIRE_EQ(send(sv[0], &malformed, sizeof(malformed), 0),
	    sizeof(malformed));
	ATF_CHECK_ERRNO(EPROTO,
	    internal_receive(sv[1], &received, sizeof(received),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);

	memset(&oversized, 0, sizeof(oversized));
	oversized.message = hello();
	ATF_REQUIRE_EQ(send(sv[0], &oversized, sizeof(oversized), 0),
	    sizeof(oversized));
	ATF_CHECK_ERRNO(EPROTO,
	    internal_receive(sv[1], &received, sizeof(received),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(descriptors);
ATF_TC_BODY(descriptors, tc)
{
	char data[] = "session", received[sizeof(data)];
	int fd, returned, sv[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_send_fd(sv[0], NULL, sizeof(data), fd) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_send_fd(sv[0], data, 0, fd) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_send_fd(sv[0], data, sizeof(data), -1) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_receive_fd(sv[1], NULL, sizeof(received), &returned) ==
	    -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_receive_fd(sv[1], received, 0, &returned) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    internal_receive_fd(sv[1], received, sizeof(received), NULL) ==
	    -1);
	ATF_REQUIRE_EQ(internal_send_fd(sv[0], data, sizeof(data), fd), 0);
	ATF_REQUIRE_EQ(internal_receive_fd(sv[1], received, sizeof(received),
	    &returned), sizeof(received));
	ATF_CHECK_EQ(memcmp(data, received, sizeof(data)), 0);
	ATF_CHECK((fcntl(returned, F_GETFD) & FD_CLOEXEC) != 0);
	close(returned);

	ATF_REQUIRE_EQ(send(sv[0], data, sizeof(data), 0), sizeof(data));
	ATF_CHECK_ERRNO(EPROTO, internal_receive_fd(sv[1], received,
	    sizeof(received), &returned) == -1);
	ATF_CHECK_EQ(returned, -1);

	ATF_REQUIRE_EQ(internal_send_fd(sv[0], data, sizeof(data), fd), 0);
	ATF_CHECK_ERRNO(EPROTO,
	    internal_receive_fd(sv[1], received, sizeof(received) - 1,
	    &returned) == -1);
	ATF_CHECK_EQ(returned, -1);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, messages);
	ATF_TP_ADD_TC(tp, descriptors);
	return (atf_no_error());
}

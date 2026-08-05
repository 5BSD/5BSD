/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <notifycmp.h>
#include <notifycmp_server.h>

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, messages);
	return (atf_no_error());
}

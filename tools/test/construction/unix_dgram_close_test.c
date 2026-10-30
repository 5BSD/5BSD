/* SPDX-License-Identifier: BSD-2-Clause */
/* Logging diagnostic: delivery after successful sends is the tested property,
 * not a claim that SOCK_DGRAM provides acknowledged delivery. */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
exercise(int close_before_receive)
{
	struct sockaddr_un address;
	struct timeval timeout = { .tv_sec = 1 };
	int receiver, senders[2], capacity = 65536, received = 0, mask = 0;
	char message;
	ssize_t length;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_len = sizeof(address);
	strcpy(address.sun_path, "datagram-receiver");
	receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
	ATF_REQUIRE(receiver >= 0);
	ATF_REQUIRE(setsockopt(receiver, SOL_SOCKET, SO_RCVBUF,
	    &capacity, sizeof(capacity)) == 0);
	ATF_REQUIRE(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO,
	    &timeout, sizeof(timeout)) == 0);
	ATF_REQUIRE(bind(receiver, (struct sockaddr *)&address,
	    sizeof(address)) == 0);
	for (int i = 0; i < 2; i++) {
		senders[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
		ATF_REQUIRE(senders[i] >= 0);
		ATF_REQUIRE(connect(senders[i], (struct sockaddr *)&address,
		    sizeof(address)) == 0);
		message = '0' + i;
		ATF_REQUIRE(send(senders[i], &message, 1, 0) == 1);
		if (close_before_receive)
			ATF_REQUIRE(close(senders[i]) == 0);
	}
	while (received < 2) {
		length = recv(receiver, &message, 1, 0);
		if (length == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
		ATF_REQUIRE(length == 1);
		ATF_REQUIRE(message == '0' || message == '1');
		ATF_REQUIRE((mask & (1 << (message - '0'))) == 0);
		mask |= 1 << (message - '0');
		received++;
	}
	if (!close_before_receive)
		for (int i = 0; i < 2; i++)
			ATF_REQUIRE(close(senders[i]) == 0);
	ATF_REQUIRE(close(receiver) == 0);
	ATF_REQUIRE(unlink(address.sun_path) == 0);
	printf("UNIX_DGRAM_DELIVERY close_before_receive=%d sent=2 received=%d mask=%d\n",
	    close_before_receive, received, mask);
	fflush(stdout);
	ATF_REQUIRE_MSG(received == 2, "successful sends were not both delivered");
}

ATF_TC(senders_open);
ATF_TC_HEAD(senders_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "Control: receive from connected senders before close");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(senders_open, tc)
{
	(void)tc;
	exercise(0);
}
ATF_TC(senders_closed);
ATF_TC_HEAD(senders_closed, tc)
{
	atf_tc_set_md_var(tc, "descr", "Diagnostic: delivery after both connected senders close");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(senders_closed, tc)
{
	(void)tc;
	exercise(1);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, senders_open);
	ATF_TP_ADD_TC(tp, senders_closed);
	return atf_no_error();
}

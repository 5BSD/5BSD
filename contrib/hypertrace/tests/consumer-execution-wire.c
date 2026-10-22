/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "dtraced_wire.h"

typedef struct dtd_arg {
	int rx_sock;
	int wx_sock;
	uint8_t rx_session[16];
	void *hostpgp;
} dtd_arg_t;

static _Atomic int g_intr;
static _Atomic int g_session_stop;
static int peers[2], opens;

static int
open_dtraced_session(uint64_t subs, uint8_t session[16])
{
	int pair[2];
	unsigned char accepted;

	assert(subs == DTD_SUB_READDATA && session[0] == 0x5a);
	assert(opens < 2);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	accepted = opens == 0 ? 0 : 1;
	assert(write(pair[1], &accepted, 1) == 1);
	peers[opens++] = pair[1];
	return (pair[0]);
}

/* FUNCTION */

int
main(void)
{
	dtd_arg_t connection = {};
	dtraced_consumer_ack_t execution = {};
	unsigned char frame[8 + DTRACED_MSGHDRSIZE +
	    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
	size_t transferred;
	dtraced_hdr_t header;
	dtraced_consumer_ack_t decoded;

	connection.rx_session[0] = 0x5a;
	execution.delivery_id = 73;
	execution.program_id[0] = 0xa1;
	execution.source_id[0] = 0xb2;
	execution.vmid = 7;
	execution.epoch = 42;
	execution.outcome = DTRACED_CONSUMER_ACK_DERIVED;
	execution.ingress_session[0] = 0x91;
	assert(report_identified_execution(&connection, &execution) == 0);
	assert(opens == 2);
	for (int i = 0; i < opens; i++) {
		assert(dtraced_io_transfer(peers[i], frame, sizeof(frame),
		    false, dtraced_io_deadline_after(1000), &transferred) == 0);
		assert(dtraced_wire_get_u64(frame) ==
		    DTRACED_MSGHDRSIZE + DTRACED_CONSUMER_EXECUTION_WIRE_SIZE);
		assert(dtraced_wire_decode_header(&header, frame + 8) == 0);
		assert(header.msg_type == DTRACED_MSG_CONSUMER_EXECUTION &&
		    header.elf.len == DTRACED_CONSUMER_EXECUTION_WIRE_SIZE);
		assert(dtraced_wire_decode_consumer_execution(&decoded,
		    frame + 8 + DTRACED_MSGHDRSIZE) == 0);
		assert(decoded.delivery_id == execution.delivery_id &&
		    decoded.program_id[0] == execution.program_id[0] &&
		    decoded.source_id[0] == execution.source_id[0] &&
		    decoded.vmid == execution.vmid &&
		    decoded.epoch == execution.epoch &&
		    decoded.outcome == execution.outcome &&
		    decoded.ingress_session[0] == 0x91);
		assert(close(peers[i]) == 0);
	}
	execution.delivery_id = 0;
	assert(report_identified_execution(&connection, &execution) == -1 &&
	    errno == EINVAL && opens == 2);
	execution.delivery_id = 73;
	execution.ingress_session[0] = 0;
	assert(report_identified_execution(&connection, &execution) == -1 &&
	    errno == EINVAL && opens == 2);
	execution.ingress_session[0] = 0x91;
	atomic_store(&g_intr, 1);
	assert(report_identified_execution(&connection, &execution) == -1 &&
	    errno == EINTR && opens == 2);
	atomic_store(&g_intr, 0);
	atomic_store(&g_session_stop, 1);
	assert(report_identified_execution(&connection, &execution) == -1 &&
	    errno == EINTR && opens == 2);
	puts("PASS: consumer execution frame, retry, and fail-closed stop");
	return (0);
}

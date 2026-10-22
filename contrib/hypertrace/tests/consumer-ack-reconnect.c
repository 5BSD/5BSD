/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>

typedef struct dtd_arg {
	int rx_sock;
	int wx_sock;
	uint8_t rx_session[16];
} dtd_arg_t;

static int reconnects, replay_rx = -1, replay_wx = -1;
static uint8_t expected_session[16] = { 0x65 };

#include "consumer-ack-reconnect.inc"

static int
reconnect_dtraced(dtd_arg_t *connection, int *rx, int *wx)
{
	int next_rx[2], next_wx[2];

	assert(memcmp(connection->rx_session, expected_session, 16) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, next_rx) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, next_wx) == 0);
	close(*rx);
	close(*wx);
	*rx = connection->rx_sock = next_rx[0];
	*wx = connection->wx_sock = next_wx[0];
	replay_rx = next_rx[1];
	replay_wx = next_wx[1];
	reconnects++;
	return (0);
}

static void
read_ack(int fd, const dtraced_hdr_t *header, uint8_t outcome)
{
	unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
	dtraced_consumer_ack_t ack = { 0 };

	assert(read(fd, wire, sizeof(wire)) == sizeof(wire));
	assert(dtraced_wire_decode_consumer_ack(&ack, wire) == 0);
	assert(ack.delivery_id == header->elf.delivery_id);
	assert(ack.vmid == header->elf.vmid);
	assert(ack.epoch == header->elf.epoch);
	assert(memcmp(ack.program_id, header->elf.program_id, 16) == 0);
	assert(memcmp(ack.source_id, header->elf.source_id, 16) == 0);
	assert(ack.outcome == outcome);
}

int
main(void)
{
	int initial_rx[2], initial_wx[2];
	dtraced_hdr_t header = { 0 };
	dtd_arg_t connection = { .rx_session = { 0x65 } };
	int rx, wx;
	char byte;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, initial_rx) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, initial_wx) == 0);
	rx = connection.rx_sock = initial_rx[0];
	wx = connection.wx_sock = initial_wx[0];
	header.elf.delivery_id = 17;
	header.elf.vmid = 3;
	header.elf.epoch = 4;
	header.elf.program_id[0] = 0xa1;
	header.elf.source_id[0] = 0xb2;
	ack_identified_delivery(&connection, &rx, &wx, &header,
	    DTRACED_CONSUMER_ACK_NO_DERIVED);
	read_ack(initial_rx[1], &header, DTRACED_CONSUMER_ACK_NO_DERIVED);
	assert(reconnects == 0);

	close(initial_rx[1]);
	ack_identified_delivery(&connection, &rx, &wx, &header,
	    DTRACED_CONSUMER_ACK_DERIVED);
	assert(reconnects == 1);
	assert(connection.rx_sock == rx && connection.wx_sock == wx);
	assert(recv(replay_rx, &byte, 1, MSG_DONTWAIT) == -1 &&
	    errno == EAGAIN);
	/* Only a replayed frame on the new stream may cause a new ACK. */
	ack_identified_delivery(&connection, &rx, &wx, &header,
	    DTRACED_CONSUMER_ACK_DERIVED);
	read_ack(replay_rx, &header, DTRACED_CONSUMER_ACK_DERIVED);
	assert(reconnects == 1);
	close(rx);
	close(wx);
	close(replay_rx);
	close(replay_wx);
	close(initial_wx[1]);
	puts("PASS: failed consumer ACK reconnects without acknowledging an unreplayed frame");
	return (0);
}

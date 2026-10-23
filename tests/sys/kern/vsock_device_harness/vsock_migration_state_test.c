/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "vsock_migration_state.c"

ATF_TC_WITHOUT_HEAD(conn_state_roundtrip);
ATF_TC_BODY(conn_state_roundtrip, tc)
{
	const uint8_t reasm[] = { 1, 2, 3 };
	const uint8_t tx[] = { 4, 5 };
	const uint8_t resid[] = { 6, 7, 8, 9 };
	struct vsock_migration_conn_state decoded, source = {
		.local_port = 43210,
		.guest_port = 80,
		.type = VSOCK_MIGRATION_TYPE_SEQPACKET,
		.state = VSOCK_MIGRATION_CONN_ESTABLISHED,
		.flags = VSOCK_MIGRATION_CONN_TX_EOR |
		    VSOCK_MIGRATION_CONN_RESID_SEQ |
		    VSOCK_MIGRATION_CONN_RESID_EOR |
		    VSOCK_MIGRATION_CONN_STALL_TIMER,
		.peer_shutdown = 1,
		.buf_alloc = VSOCK_MIGRATION_MAX_BUFFER,
		.fwd_cnt = 14,
		.last_fwd_cnt = 9,
		.tx_cnt = 22,
		.peer_buf_alloc = 8192,
		.peer_fwd_cnt = 7,
		.rx_reasm_len = sizeof(reasm),
		.tx_buf_len = sizeof(tx),
		.rx_resid_len = sizeof(resid),
		.rx_resid_off = 2,
		.close_age_seconds = 0,
		.stall_age_seconds = 4,
		.rx_reasm = reasm,
		.tx_buf = tx,
		.rx_resid = resid,
	};
	uint8_t wire[VSOCK_MIGRATION_CONN_HEADER_SIZE + 9];
	size_t size;

	(void)tc;
	ATF_REQUIRE_EQ(vsock_migration_conn_state_size(&source, &size), 0);
	ATF_REQUIRE_EQ(size, sizeof(wire));
	memset(wire, 0xa5, sizeof(wire));
	ATF_REQUIRE_EQ(vsock_migration_conn_state_encode(&source, wire,
	    sizeof(wire)), 0);
	ATF_CHECK_EQ(le32dec(wire), 0x31435356U);
	ATF_CHECK_EQ(le32dec(wire + 4), 1U);
	ATF_CHECK_EQ(le32dec(wire + 8), sizeof(wire));
	ATF_REQUIRE_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.local_port, source.local_port);
	ATF_CHECK_EQ(decoded.guest_port, source.guest_port);
	ATF_CHECK_EQ(decoded.flags, source.flags);
	ATF_CHECK_EQ(decoded.fwd_cnt, source.fwd_cnt);
	ATF_CHECK_EQ(decoded.rx_resid_off, source.rx_resid_off);
	ATF_CHECK_EQ(decoded.stall_age_seconds, source.stall_age_seconds);
	ATF_CHECK_EQ(memcmp(decoded.rx_reasm, reasm, sizeof(reasm)), 0);
	ATF_CHECK_EQ(memcmp(decoded.tx_buf, tx, sizeof(tx)), 0);
	ATF_CHECK_EQ(memcmp(decoded.rx_resid, resid, sizeof(resid)), 0);
	source.guest_port = 0;
	ATF_REQUIRE_EQ(vsock_migration_conn_state_encode(&source, wire,
	    sizeof(wire)), 0);
	ATF_REQUIRE_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.guest_port, 0U);
}

ATF_TC_WITHOUT_HEAD(conn_state_rejects_bad_lengths_and_flags);
ATF_TC_BODY(conn_state_rejects_bad_lengths_and_flags, tc)
{
	const uint8_t data[] = { 0x11 };
	struct vsock_migration_conn_state decoded, original, source = {
		.local_port = 1024,
		.guest_port = 1,
		.type = VSOCK_MIGRATION_TYPE_STREAM,
		.state = VSOCK_MIGRATION_CONN_ESTABLISHED,
		.buf_alloc = VSOCK_MIGRATION_MAX_BUFFER,
		.tx_buf_len = sizeof(data),
		.tx_buf = data,
	};
	uint8_t wire[VSOCK_MIGRATION_CONN_HEADER_SIZE + 1];
	size_t size;

	(void)tc;
	/* A parked host record can reach the guest's 4 MiB credit window. */
	source.type = VSOCK_MIGRATION_TYPE_SEQPACKET;
	source.flags = VSOCK_MIGRATION_CONN_RESID_SEQ;
	source.rx_resid = data;
	source.rx_resid_len = VSOCK_MIGRATION_MAX_PEER_BUFFER;
	ATF_REQUIRE_EQ(vsock_migration_conn_state_size(&source, &size), 0);
	ATF_CHECK_EQ(size, VSOCK_MIGRATION_CONN_HEADER_SIZE +
	    sizeof(data) + VSOCK_MIGRATION_MAX_PEER_BUFFER);
	source.rx_resid_len++;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.rx_resid = NULL;
	source.rx_resid_len = 0;
	source.type = VSOCK_MIGRATION_TYPE_STREAM;
	source.flags = 0;
	source.state = VSOCK_MIGRATION_CONN_CONNECTING;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.state = VSOCK_MIGRATION_CONN_ESTABLISHED;
	source.flags = VSOCK_MIGRATION_CONN_CLOSE_TIMER;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.state = VSOCK_MIGRATION_CONN_CLOSING;
	/* A retained close requires host EOF and the guest's SEND shutdown. */
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.flags |= VSOCK_MIGRATION_CONN_HOST_EOF;
	source.peer_shutdown = VSOCK_MIGRATION_PEER_SHUTDOWN_SEND;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), 0);
	source.peer_shutdown |= VSOCK_MIGRATION_PEER_SHUTDOWN_RCV;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.peer_shutdown = VSOCK_MIGRATION_PEER_SHUTDOWN_SEND;
	source.flags = 0;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.state = VSOCK_MIGRATION_CONN_ESTABLISHED;
	source.flags = VSOCK_MIGRATION_CONN_HOST_EOF;
	ATF_CHECK_EQ(vsock_migration_conn_state_size(&source, &size), EINVAL);
	source.flags = 0;
	source.peer_shutdown = 0;
	memset(wire, 0xa5, sizeof(wire));
	ATF_CHECK_EQ(vsock_migration_conn_state_encode(&source, wire,
	    sizeof(wire) - 1), EMSGSIZE);
	ATF_CHECK_EQ(wire[0], 0xa5);
	ATF_REQUIRE_EQ(vsock_migration_conn_state_encode(&source, wire,
	    sizeof(wire)), 0);
	memset(&decoded, 0x5a, sizeof(decoded));
	original = decoded;
	le32enc(wire + 24, VSOCK_MIGRATION_CONN_CLOSING);
	le32enc(wire + 28, VSOCK_MIGRATION_CONN_CLOSE_TIMER);
	le32enc(wire + 32, VSOCK_MIGRATION_PEER_SHUTDOWN_SEND);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 28, 0);
	le32enc(wire + 32, 0);
	le32enc(wire + 24, VSOCK_MIGRATION_CONN_CONNECTING);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 24, VSOCK_MIGRATION_CONN_ESTABLISHED);
	le32enc(wire + 64, VSOCK_MIGRATION_MAX_BUFFER + 1);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 64, 1);
	le32enc(wire + 28, VSOCK_MIGRATION_CONN_TX_EOR);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 28, 0);
	le32enc(wire + 80, 1);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 80, 0);
	le32enc(wire + 56, 1);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
	le32enc(wire + 48, 5);
	le32enc(wire + 56, UINT32_MAX);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), 0);
	le32enc(wire + 48, 0);
	le32enc(wire + 56, 0);
	memcpy(&decoded, &original, sizeof(decoded));
	le32enc(wire + 84, 1);
	ATF_CHECK_EQ(vsock_migration_conn_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &original, sizeof(decoded)), 0);
}

ATF_TC_WITHOUT_HEAD(conn_table_roundtrip_and_atomic_reject);
ATF_TC_BODY(conn_table_roundtrip_and_atomic_reject, tc)
{
	const uint8_t reasm[] = { 1, 2, 3 };
	const uint8_t tx[] = { 4, 5 };
	struct vsock_migration_conn_state decoded[2], original[2];
	struct vsock_migration_conn_state source[2] = {
		{ .local_port = 1024, .guest_port = 7,
		  .type = VSOCK_MIGRATION_TYPE_SEQPACKET,
		  .state = VSOCK_MIGRATION_CONN_ESTABLISHED,
		  .buf_alloc = VSOCK_MIGRATION_MAX_BUFFER,
		  .rx_reasm_len = sizeof(reasm), .rx_reasm = reasm },
		{ .local_port = 1025, .guest_port = 8,
		  .type = VSOCK_MIGRATION_TYPE_STREAM,
		  .state = VSOCK_MIGRATION_CONN_ESTABLISHED,
		  .buf_alloc = VSOCK_MIGRATION_MAX_BUFFER,
		  .tx_buf_len = sizeof(tx), .tx_buf = tx },
	};
	uint8_t wire[VSOCK_MIGRATION_TABLE_HEADER_SIZE +
	    2 * VSOCK_MIGRATION_CONN_HEADER_SIZE + sizeof(reasm) + sizeof(tx)];
	size_t size, second_offset;
	uint32_t count;

	(void)tc;
	ATF_REQUIRE_EQ(vsock_migration_table_size(source, 2, &size), 0);
	ATF_REQUIRE_EQ(size, sizeof(wire));
	ATF_REQUIRE_EQ(vsock_migration_table_encode(source, 2, wire,
	    sizeof(wire)), 0);
	count = UINT32_MAX;
	ATF_REQUIRE_EQ(vsock_migration_table_decode(wire, sizeof(wire),
	    decoded, 2, &count), 0);
	ATF_CHECK_EQ(count, 2U);
	ATF_CHECK_EQ(decoded[0].local_port, 1024U);
	ATF_CHECK_EQ(decoded[1].local_port, 1025U);
	ATF_CHECK_EQ(memcmp(decoded[0].rx_reasm, reasm, sizeof(reasm)), 0);
	ATF_CHECK_EQ(memcmp(decoded[1].tx_buf, tx, sizeof(tx)), 0);

	memset(decoded, 0x5a, sizeof(decoded));
	memcpy(original, decoded, sizeof(decoded));
	count = UINT32_MAX;
	second_offset = VSOCK_MIGRATION_TABLE_HEADER_SIZE +
	    VSOCK_MIGRATION_CONN_HEADER_SIZE + sizeof(reasm);
	le32enc(wire + second_offset + 12, 1024);
	ATF_CHECK_EQ(vsock_migration_table_decode(wire, sizeof(wire),
	    decoded, 2, &count), EINVAL);
	ATF_CHECK_EQ(memcmp(decoded, original, sizeof(decoded)), 0);
	ATF_CHECK_EQ(count, UINT32_MAX);
	le32enc(wire + second_offset + 12, 1025);
	le32enc(wire + second_offset + 8, sizeof(wire));
	ATF_CHECK_EQ(vsock_migration_table_decode(wire, sizeof(wire),
	    decoded, 2, &count), EINVAL);
	ATF_CHECK_EQ(memcmp(decoded, original, sizeof(decoded)), 0);
	ATF_CHECK_EQ(count, UINT32_MAX);
	le32enc(wire + second_offset + 8,
	    VSOCK_MIGRATION_CONN_HEADER_SIZE + sizeof(tx));
	ATF_CHECK_EQ(vsock_migration_table_decode(wire, sizeof(wire),
	    decoded, 1, &count), EINVAL);
	ATF_CHECK_EQ(memcmp(decoded, original, sizeof(decoded)), 0);
	ATF_CHECK_EQ(count, UINT32_MAX);
	{
		uint8_t empty[VSOCK_MIGRATION_TABLE_HEADER_SIZE];

		ATF_REQUIRE_EQ(vsock_migration_table_encode(NULL, 0, empty,
		    sizeof(empty)), 0);
		ATF_REQUIRE_EQ(vsock_migration_table_decode(empty,
		    sizeof(empty), NULL, 0, &count), 0);
		ATF_CHECK_EQ(count, 0U);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, conn_state_roundtrip);
	ATF_TP_ADD_TC(tp, conn_state_rejects_bad_lengths_and_flags);
	ATF_TP_ADD_TC(tp, conn_table_roundtrip_and_atomic_reject);
	return (atf_no_error());
}

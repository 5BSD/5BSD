/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>
#include <sys/endian.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../../usr.sbin/bhyve/tpm_swtpm_control.c"

static void
read_exact(int fd, void *buffer, size_t length)
{
	uint8_t *p = buffer;
	ssize_t n;

	while (length != 0) {
		n = read(fd, p, length);
		ATF_REQUIRE(n > 0);
		p += n;
		length -= n;
	}
}

static void
write_exact(int fd, const void *buffer, size_t length)
{
	const uint8_t *p = buffer;
	ssize_t n;

	while (length != 0) {
		n = write(fd, p, length);
		ATF_REQUIRE(n > 0);
		p += n;
		length -= n;
	}
}

static void
make_migration_blob(uint8_t blob[92])
{

	memset(blob, 0xa5, 92);
	blob[0] = 2;
	blob[1] = 1;
	be16enc(blob + 2, 10);
	be16enc(blob + 4, 6);
	be32enc(blob + 6, 92);
	be16enc(blob + 10, 5);
	be32enc(blob + 12, 16);
	be16enc(blob + 32, 3);
	be32enc(blob + 34, 32);
	be16enc(blob + 70, 7);
	be32enc(blob + 72, 16);
}

ATF_TC_WITHOUT_HEAD(capabilities_and_commands);
ATF_TC_BODY(capabilities_and_commands, tc)
{
	uint8_t response[8], command[8];
	uint32_t caps;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	be32enc(response, 0);
	be32enc(response + 4, SWTPM_CONTROL_CAP_INIT |
	    SWTPM_CONTROL_CAP_GET_STATEBLOB |
	    SWTPM_CONTROL_CAP_SET_STATEBLOB | SWTPM_CONTROL_CAP_STOP |
	    SWTPM_CONTROL_CAP_GET_CONFIG |
	    SWTPM_CONTROL_CAP_LOCK_STORAGE);
	write_exact(sv[1], response, sizeof(response));
	ATF_REQUIRE_EQ(tpm_swtpm_control_capabilities(sv[0], &caps), 0);
	ATF_CHECK_EQ(caps, be32dec(response + 4));
	read_exact(sv[1], command, 4);
	ATF_CHECK_EQ(be32dec(command), 1U);

	be32enc(response, 0);
	be32enc(response + 4, SWTPM_CONTROL_CONFIG_MIGRATION_KEY);
	write_exact(sv[1], response, sizeof(response));
	ATF_REQUIRE_EQ(tpm_swtpm_control_get_config(sv[0], &caps), 0);
	ATF_CHECK_EQ(caps, SWTPM_CONTROL_CONFIG_MIGRATION_KEY);
	read_exact(sv[1], command, 4);
	ATF_CHECK_EQ(be32dec(command), 15U);

	write_exact(sv[1], response, 4);
	ATF_REQUIRE_EQ(tpm_swtpm_control_stop(sv[0]), 0);
	read_exact(sv[1], command, 4);
	ATF_CHECK_EQ(be32dec(command), 14U);

	write_exact(sv[1], response, 4);
	ATF_REQUIRE_EQ(tpm_swtpm_control_init(sv[0], 0), 0);
	read_exact(sv[1], command, 8);
	ATF_CHECK_EQ(be32dec(command), 2U);
	ATF_CHECK_EQ(be32dec(command + 4), 0U);
	ATF_CHECK_EQ(tpm_swtpm_control_get_config(sv[0], NULL), EINVAL);
	be32enc(response, 1);
	write_exact(sv[1], response, sizeof(response));
	caps = 0xa5a5a5a5;
	ATF_CHECK_EQ(tpm_swtpm_control_get_config(sv[0], &caps), EIO);
	ATF_CHECK_EQ(caps, 0xa5a5a5a5);
	read_exact(sv[1], command, 4);
	ATF_CHECK_EQ(be32dec(command), 15U);
	be32enc(response, 0);
	ATF_CHECK_EQ(tpm_swtpm_control_init(sv[0], 1), EINVAL);
	write_exact(sv[1], response, 4);
	ATF_REQUIRE_EQ(tpm_swtpm_control_lock_storage(sv[0], 0), 0);
	read_exact(sv[1], command, 8);
	ATF_CHECK_EQ(be32dec(command), 19U);
	ATF_CHECK_EQ(be32dec(command + 4), 0U);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(blob_roundtrip_and_empty);
ATF_TC_BODY(blob_roundtrip_and_empty, tc)
{
	uint8_t response[16], command[92], *blob, *saved_blob;
	uint8_t encoded_blob[92];
	uint8_t tampered_blob[sizeof(encoded_blob)];
	uint8_t legacy_blob[58] = { 0 };
	uint32_t flags, saved_flags;
	size_t length, saved_length;
	int sv[2];

	(void)tc;
	make_migration_blob(encoded_blob);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	be32enc(response, 0);
	be32enc(response + 4, 0);
	be32enc(response + 8, sizeof(encoded_blob));
	be32enc(response + 12, sizeof(encoded_blob));
	write_exact(sv[1], response, sizeof(response));
	write_exact(sv[1], encoded_blob, sizeof(encoded_blob));
	ATF_REQUIRE_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_PERMANENT, &blob, &length, &flags), 0);
	ATF_CHECK_EQ(length, sizeof(encoded_blob));
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(memcmp(blob, encoded_blob, sizeof(encoded_blob)), 0);
	saved_blob = blob;
	saved_length = length;
	saved_flags = flags;
	read_exact(sv[1], command, 16);
	ATF_CHECK_EQ(be32dec(command), 12U);
	ATF_CHECK_EQ(be32dec(command + 4),
	    SWTPM_CONTROL_STATE_DECRYPTED);
	ATF_CHECK_EQ(be32dec(command + 8), SWTPM_CONTROL_BLOB_PERMANENT);
	ATF_CHECK_EQ(be32dec(command + 12), 0U);

	be32enc(response, 0x800);
	be32enc(response + 4, 0);
	be32enc(response + 8, 0);
	be32enc(response + 12, 0);
	write_exact(sv[1], response, sizeof(response));
	{
		uint8_t *empty = (uint8_t *)1;
		size_t empty_length = 1;
		uint32_t empty_flags = 1;

		ATF_REQUIRE_EQ(tpm_swtpm_control_get_blob(sv[0],
		    SWTPM_CONTROL_BLOB_SAVESTATE, &empty, &empty_length,
		    &empty_flags), 0);
		ATF_CHECK(empty == NULL);
		ATF_CHECK_EQ(empty_length, 0);
		ATF_CHECK_EQ(empty_flags, 0);
	}
	read_exact(sv[1], command, 16);
	ATF_CHECK_EQ(be32dec(command), 12U);
	ATF_CHECK_EQ(be32dec(command + 8), SWTPM_CONTROL_BLOB_SAVESTATE);
	/* A missing required blob must fail the capture. */
	write_exact(sv[1], response, sizeof(response));
	ATF_CHECK_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, &blob, &length, &flags), EIO);
	read_exact(sv[1], command, 16);
	ATF_CHECK_EQ(be32dec(command + 8), SWTPM_CONTROL_BLOB_VOLATILE);
	/* Another nonfatal TPM result must not masquerade as a missing blob. */
	be32enc(response, 0x922);
	write_exact(sv[1], response, sizeof(response));
	ATF_CHECK_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_SAVESTATE, &blob, &length, &flags), EIO);
	read_exact(sv[1], command, 16);

	memcpy(tampered_blob, saved_blob, sizeof(tampered_blob));
	tampered_blob[5] &= ~SWTPM_BLOB_FLAG_MIGRATION_ENCRYPTED;
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, tampered_blob,
	    sizeof(tampered_blob), 0), EPROTO);
	memcpy(tampered_blob, saved_blob, sizeof(tampered_blob));
	tampered_blob[0] = 3;
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, tampered_blob,
	    sizeof(tampered_blob), 0), EPROTO);
	legacy_blob[0] = 1;
	legacy_blob[1] = 1;
	be16enc(legacy_blob + 2, 10);
	be16enc(legacy_blob + 4, 6);
	be32enc(legacy_blob + 6, sizeof(legacy_blob));
	ATF_CHECK_EQ(tpm_swtpm_control_blob_validate(
	    SWTPM_CONTROL_BLOB_VOLATILE, legacy_blob,
	    sizeof(legacy_blob), 0), 0);
	be32enc(legacy_blob + 6, sizeof(legacy_blob) - 1);
	ATF_CHECK_EQ(tpm_swtpm_control_blob_validate(
	    SWTPM_CONTROL_BLOB_VOLATILE, legacy_blob,
	    sizeof(legacy_blob), 0), EPROTO);
	memcpy(tampered_blob, saved_blob, sizeof(tampered_blob));
	be32enc(tampered_blob + 12, 17);
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, tampered_blob,
	    sizeof(tampered_blob), 0), EPROTO);
	memcpy(tampered_blob, saved_blob, sizeof(tampered_blob));
	be16enc(tampered_blob + 32, 4);
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, tampered_blob,
	    sizeof(tampered_blob), 0), EPROTO);
	memcpy(tampered_blob, saved_blob, sizeof(tampered_blob));
	be32enc(tampered_blob + 72, 33);
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, tampered_blob,
	    sizeof(tampered_blob), 0), EPROTO);
	ATF_CHECK_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, saved_blob, saved_length,
	    SWTPM_CONTROL_STATE_ENCRYPTED), EINVAL);
	be32enc(response, 0);
	write_exact(sv[1], response, 4);
	ATF_REQUIRE_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, saved_blob, saved_length,
	    saved_flags), 0);
	read_exact(sv[1], command, 16);
	ATF_CHECK_EQ(be32dec(command), 13U);
	ATF_CHECK_EQ(be32dec(command + 4), saved_flags);
	ATF_CHECK_EQ(be32dec(command + 8), SWTPM_CONTROL_BLOB_VOLATILE);
	ATF_CHECK_EQ(be32dec(command + 12), saved_length);
	read_exact(sv[1], command, saved_length);
	ATF_CHECK_EQ(memcmp(command, saved_blob, saved_length), 0);
	be32enc(response, 0);
	write_exact(sv[1], response, 4);
	ATF_REQUIRE_EQ(tpm_swtpm_control_set_blob(sv[0],
	    SWTPM_CONTROL_BLOB_SAVESTATE, NULL, 0, 0), 0);
	read_exact(sv[1], command, 16);
	ATF_CHECK_EQ(be32dec(command), 13U);
	ATF_CHECK_EQ(be32dec(command + 8), SWTPM_CONTROL_BLOB_SAVESTATE);
	ATF_CHECK_EQ(be32dec(command + 12), 0U);
	explicit_bzero(saved_blob, saved_length);
	free(saved_blob);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(malformed_blob_and_eof);
ATF_TC_BODY(malformed_blob_and_eof, tc)
{
	uint8_t response[16], *blob;
	uint8_t plaintext_blob[15] = { 2, 1, 0, 10, 0, 4,
	    0, 0, 0, 15, 'p', 'l', 'a', 'i', 'n' };
	uint32_t flags;
	size_t length;
	int sv[2];

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	be32enc(response, 0);
	be32enc(response + 4, 0);
	be32enc(response + 8, SWTPM_CONTROL_MAX_BLOB + 1);
	be32enc(response + 12, 1);
	write_exact(sv[1], response, sizeof(response));
	ATF_CHECK_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, &blob, &length, &flags), EPROTO);
	ATF_CHECK(blob == NULL);
	ATF_CHECK_EQ(length, 0);
	close(sv[0]);
	close(sv[1]);

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	be32enc(response, 0);
	be32enc(response + 4, 0);
	be32enc(response + 8, 5);
	be32enc(response + 12, 3);
	write_exact(sv[1], response, sizeof(response));
	ATF_CHECK_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_VOLATILE, &blob, &length, &flags), EPROTO);
	ATF_CHECK(blob == NULL);
	close(sv[0]);
	close(sv[1]);

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	be32enc(response, 0);
	be32enc(response + 4, 0);
	be32enc(response + 8, sizeof(plaintext_blob));
	be32enc(response + 12, sizeof(plaintext_blob));
	write_exact(sv[1], response, sizeof(response));
	write_exact(sv[1], plaintext_blob, sizeof(plaintext_blob));
	ATF_CHECK_EQ(tpm_swtpm_control_get_blob(sv[0],
	    SWTPM_CONTROL_BLOB_PERMANENT, &blob, &length, &flags), EPROTO);
	ATF_CHECK(blob == NULL);
	ATF_CHECK_EQ(length, 0);
	close(sv[0]);
	close(sv[1]);

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	close(sv[1]);
	{
		int error = tpm_swtpm_control_capabilities(sv[0], &flags);
		ATF_CHECK(error == ECONNRESET || error == EPIPE);
	}
	close(sv[0]);
}

ATF_TC_WITHOUT_HEAD(stalled_control_peer_times_out);
ATF_TC_BODY(stalled_control_peer_times_out, tc)
{
	uint8_t buffer[8192] = { 0 };
	uint64_t deadline;
	int sv[2];
	ssize_t n;

	(void)tc;
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	ATF_REQUIRE_EQ(write(sv[1], buffer, 1), 1);
	ATF_REQUIRE_EQ(swtpm_io_deadline(100, &deadline), 0);
	ATF_CHECK_EQ(swtpm_recv_all_deadline(sv[0], buffer, 2, deadline),
	    ETIMEDOUT);
	close(sv[0]);
	close(sv[1]);

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	do {
		n = send(sv[0], buffer, sizeof(buffer), MSG_DONTWAIT |
		    MSG_NOSIGNAL);
	} while (n > 0);
	ATF_REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
	ATF_REQUIRE_EQ(swtpm_io_deadline(100, &deadline), 0);
	ATF_CHECK_EQ(swtpm_send_all_deadline(sv[0], buffer,
	    sizeof(buffer), deadline), ETIMEDOUT);
	close(sv[0]);
	close(sv[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, capabilities_and_commands);
	ATF_TP_ADD_TC(tp, blob_roundtrip_and_empty);
	ATF_TP_ADD_TC(tp, malformed_blob_and_eof);
	ATF_TP_ADD_TC(tp, stalled_control_peer_times_out);
	return (atf_no_error());
}

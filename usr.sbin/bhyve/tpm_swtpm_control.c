/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "tpm_swtpm_control.h"

/* swtpm's non-CUSE control commands use network-order 32-bit words. */
#define CMD_GET_CAPABILITY 1U
#define CMD_INIT 2U
#define CMD_GET_STATEBLOB 12U
#define CMD_SET_STATEBLOB 13U
#define CMD_STOP 14U
#define CMD_GET_CONFIG 15U
#define CMD_LOCK_STORAGE 19U
/* libtpms' TPM_RETRY is the missing-state-file result used by swtpm. */
#define SWTPM_TPM_RETRY 0x800U
/* swtpm v0.10.2's packed blobheader and migration flags. */
#define SWTPM_BLOB_HEADER_SIZE 10U
#define SWTPM_BLOB_SUPPORTED_VERSION 2U
#define SWTPM_BLOB_FLAG_MIGRATION_ENCRYPTED 0x02U
#define SWTPM_BLOB_FLAG_MIGRATION_DATA 0x04U
#define SWTPM_BLOB_FLAG_FILE_ENCRYPTED 0x01U
#define SWTPM_BLOB_FLAG_FILE_KEY_256 0x08U
#define SWTPM_BLOB_FLAG_MIGRATION_KEY_256 0x10U
#define SWTPM_TLV_HEADER_SIZE 6U
#define SWTPM_TLV_ENCRYPTED_MIGRATION_DATA 5U
#define SWTPM_TLV_HMAC 3U
#define SWTPM_TLV_MIGRATION_IV 7U
#define SWTPM_CONTROL_IO_TIMEOUT_MS 30000

static bool
swtpm_tlv_next(const uint8_t *blob, size_t length, size_t *offset,
    uint16_t tag, uint32_t *value_length)
{
	uint32_t size;

	if (*offset > length || length - *offset < SWTPM_TLV_HEADER_SIZE ||
	    be16dec(blob + *offset) != tag)
		return (false);
	size = be32dec(blob + *offset + 2);
	*offset += SWTPM_TLV_HEADER_SIZE;
	if (size > length - *offset)
		return (false);
	*offset += size;
	*value_length = size;
	return (true);
}

static bool
swtpm_v2_migration_tlvs_valid(const uint8_t *blob, size_t length)
{
	size_t offset;
	uint32_t ciphertext_length, hmac_length, iv_length;

	offset = SWTPM_BLOB_HEADER_SIZE;
	if (!swtpm_tlv_next(blob, length, &offset,
	    SWTPM_TLV_ENCRYPTED_MIGRATION_DATA, &ciphertext_length) ||
	    ciphertext_length == 0 || ciphertext_length % 16 != 0 ||
	    !swtpm_tlv_next(blob, length, &offset, SWTPM_TLV_HMAC,
	    &hmac_length) || hmac_length != 32)
		return (false);
	/* swtpm may omit the IV tag if generating a new IV failed. */
	if (offset == length)
		return (true);
	return (swtpm_tlv_next(blob, length, &offset,
	    SWTPM_TLV_MIGRATION_IV, &iv_length) &&
	    (iv_length == 16 || iv_length == 32) && offset == length);
}

static bool
swtpm_migration_blob_valid(const uint8_t *blob, size_t length)
{
	uint16_t flags;

	if (blob == NULL || length <= SWTPM_BLOB_HEADER_SIZE ||
	    length > SWTPM_CONTROL_MAX_BLOB || blob[0] == 0 ||
	    blob[0] > SWTPM_BLOB_SUPPORTED_VERSION ||
	    blob[1] > blob[0] ||
	    blob[1] > SWTPM_BLOB_SUPPORTED_VERSION ||
	    be16dec(blob + 2) != SWTPM_BLOB_HEADER_SIZE ||
	    be32dec(blob + 6) != length)
		return (false);
	flags = be16dec(blob + 4);
	return ((flags & (SWTPM_BLOB_FLAG_MIGRATION_ENCRYPTED |
	    SWTPM_BLOB_FLAG_MIGRATION_DATA)) ==
	    (SWTPM_BLOB_FLAG_MIGRATION_ENCRYPTED |
	    SWTPM_BLOB_FLAG_MIGRATION_DATA) &&
	    (flags & (SWTPM_BLOB_FLAG_FILE_ENCRYPTED |
	    SWTPM_BLOB_FLAG_FILE_KEY_256)) == 0 &&
	    (flags & ~(SWTPM_BLOB_FLAG_MIGRATION_ENCRYPTED |
	    SWTPM_BLOB_FLAG_MIGRATION_DATA |
	    SWTPM_BLOB_FLAG_MIGRATION_KEY_256)) == 0 &&
	    (blob[0] == 2 ? swtpm_v2_migration_tlvs_valid(blob, length) :
	    length - SWTPM_BLOB_HEADER_SIZE >= 48 &&
	    (length - SWTPM_BLOB_HEADER_SIZE) % 16 == 0));
}

static bool
swtpm_blob_type_valid(uint32_t type)
{

	return (type >= SWTPM_CONTROL_BLOB_PERMANENT &&
	    type <= SWTPM_CONTROL_BLOB_SAVESTATE);
}

static int
swtpm_io_deadline(int timeout_ms, uint64_t *deadline)
{
	struct timespec now;

	if (timeout_ms <= 0 || deadline == NULL)
		return (EINVAL);
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (errno != 0 ? errno : EIO);
	*deadline = (uint64_t)now.tv_sec * 1000 +
	    (uint64_t)now.tv_nsec / 1000000 + (uint64_t)timeout_ms;
	return (0);
}

static int
swtpm_io_remaining(uint64_t deadline, int *remaining_ms)
{
	struct timespec now;
	uint64_t current, remaining;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (errno != 0 ? errno : EIO);
	current = (uint64_t)now.tv_sec * 1000 +
	    (uint64_t)now.tv_nsec / 1000000;
	if (current >= deadline)
		return (ETIMEDOUT);
	remaining = deadline - current;
	*remaining_ms = remaining > INT_MAX ? INT_MAX : (int)remaining;
	return (0);
}

static int
swtpm_io_wait(int fd, short events, uint64_t deadline)
{
	struct pollfd pfd;
	int error, remaining_ms, result;

	for (;;) {
		error = swtpm_io_remaining(deadline, &remaining_ms);
		if (error != 0)
			return (error);
		pfd = (struct pollfd){ .fd = fd, .events = events };
		result = poll(&pfd, 1, remaining_ms);
		if (result == 0)
			return (ETIMEDOUT);
		if (result < 0) {
			if (errno == EINTR)
				continue;
			return (errno != 0 ? errno : EIO);
		}
		if ((pfd.revents & POLLNVAL) != 0)
			return (EBADF);
		if ((pfd.revents & (events | POLLERR | POLLHUP)) != 0)
			return (0);
	}
}

static int
swtpm_send_all_deadline(int fd, const void *buffer, size_t length,
    uint64_t deadline)
{
	const uint8_t *p = buffer;
	ssize_t n;
	int error, remaining_ms;

	while (length != 0) {
		error = swtpm_io_remaining(deadline, &remaining_ms);
		if (error != 0)
			return (error);
		n = send(fd, p, length, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				error = swtpm_io_wait(fd, POLLOUT, deadline);
				if (error != 0)
					return (error);
				continue;
			}
			return (errno);
		}
		if (n == 0)
			return (ECONNRESET);
		p += n;
		length -= n;
	}
	return (0);
}

static int
swtpm_send_all(int fd, const void *buffer, size_t length)
{
	uint64_t deadline;
	int error;

	error = swtpm_io_deadline(SWTPM_CONTROL_IO_TIMEOUT_MS, &deadline);
	return (error != 0 ? error :
	    swtpm_send_all_deadline(fd, buffer, length, deadline));
}

static int
swtpm_recv_all_deadline(int fd, void *buffer, size_t length,
    uint64_t deadline)
{
	uint8_t *p = buffer;
	ssize_t n;
	int error, remaining_ms;

	while (length != 0) {
		error = swtpm_io_remaining(deadline, &remaining_ms);
		if (error != 0)
			return (error);
		n = recv(fd, p, length, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				error = swtpm_io_wait(fd, POLLIN, deadline);
				if (error != 0)
					return (error);
				continue;
			}
			return (errno);
		}
		if (n == 0)
			return (ECONNRESET);
		p += n;
		length -= n;
	}
	return (0);
}

static int
swtpm_recv_all(int fd, void *buffer, size_t length)
{
	uint64_t deadline;
	int error;

	error = swtpm_io_deadline(SWTPM_CONTROL_IO_TIMEOUT_MS, &deadline);
	return (error != 0 ? error :
	    swtpm_recv_all_deadline(fd, buffer, length, deadline));
}

static int
swtpm_result(int fd)
{
	uint8_t response[4];
	int error;

	error = swtpm_recv_all(fd, response, sizeof(response));
	if (error != 0)
		return (error);
	return (be32dec(response) == 0 ? 0 : EIO);
}

static int
swtpm_command(int fd, uint32_t command, const void *request,
    size_t request_length)
{
	uint8_t encoded[4];
	int error;

	if (fd < 0 || (request == NULL && request_length != 0))
		return (EINVAL);
	be32enc(encoded, command);
	error = swtpm_send_all(fd, encoded, sizeof(encoded));
	if (error != 0 || request_length == 0)
		return (error);
	return (swtpm_send_all(fd, request, request_length));
}

int
tpm_swtpm_control_capabilities(int fd, uint32_t *caps)
{
	uint8_t response[8];
	int error;

	if (caps == NULL)
		return (EINVAL);
	error = swtpm_command(fd, CMD_GET_CAPABILITY, NULL, 0);
	if (error != 0)
		return (error);
	error = swtpm_recv_all(fd, response, sizeof(response));
	if (error != 0)
		return (error);
	if (be32dec(response) != 0)
		return (EIO);
	*caps = be32dec(response + 4);
	return (0);
}

int
tpm_swtpm_control_get_config(int fd, uint32_t *flags)
{
	uint8_t response[8];
	int error;

	if (flags == NULL)
		return (EINVAL);
	error = swtpm_command(fd, CMD_GET_CONFIG, NULL, 0);
	if (error != 0)
		return (error);
	error = swtpm_recv_all(fd, response, sizeof(response));
	if (error != 0)
		return (error);
	if (be32dec(response) != 0)
		return (EIO);
	*flags = be32dec(response + 4);
	return (0);
}

int
tpm_swtpm_control_get_blob(int fd, uint32_t type, uint8_t **blob,
    size_t *length, uint32_t *flags)
{
	uint8_t request[12], response[16];
	uint8_t *data;
	uint32_t chunk, current_flags, result, total;
	int error;

	if (!swtpm_blob_type_valid(type) || blob == NULL || length == NULL ||
	    flags == NULL)
		return (EINVAL);
	*blob = NULL;
	*length = 0;
	*flags = 0;
	/* Non-CUSE swtpm returns the whole blob after a single header. */
	/*
	 * Let the destination use a different file key; a migration key still
	 * protects the returned blob when configured on the swtpm process.
	 */
	be32enc(request, SWTPM_CONTROL_STATE_DECRYPTED);
	be32enc(request + 4, type);
	be32enc(request + 8, 0);
	error = swtpm_command(fd, CMD_GET_STATEBLOB, request,
	    sizeof(request));
	if (error != 0)
		return (error);
	error = swtpm_recv_all(fd, response, sizeof(response));
	if (error != 0)
		return (error);
	result = be32dec(response);
	current_flags = be32dec(response + 4);
	total = be32dec(response + 8);
	chunk = be32dec(response + 12);
	/* Only savestate may be absent from a complete running TPM image. */
	if (result != 0) {
		if (type == SWTPM_CONTROL_BLOB_SAVESTATE &&
		    result == SWTPM_TPM_RETRY && current_flags == 0 &&
		    total == 0 && chunk == 0)
			return (0);
		return (EIO);
	}
	if (current_flags != 0 ||
	    total > SWTPM_CONTROL_MAX_BLOB || chunk != total)
		return (EPROTO);
	data = malloc(total == 0 ? 1 : total);
	if (data == NULL)
		return (ENOMEM);
	error = swtpm_recv_all(fd, data, chunk);
	if (error != 0)
		goto fail;
	if (!swtpm_migration_blob_valid(data, total)) {
		error = EPROTO;
		goto fail;
	}
	*blob = data;
	*length = total;
	*flags = current_flags;
	return (0);
fail:
	if (data != NULL) {
		explicit_bzero(data, total);
		free(data);
	}
	return (error);
}

int
tpm_swtpm_control_blob_validate(uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags)
{
	if (!swtpm_blob_type_valid(type) || (blob == NULL && length != 0) ||
	    length > SWTPM_CONTROL_MAX_BLOB || flags != 0 ||
	    (length == 0 && type != SWTPM_CONTROL_BLOB_SAVESTATE))
		return (EINVAL);
	if (length != 0 && !swtpm_migration_blob_valid(blob, length))
		return (EPROTO);
	return (0);
}

int
tpm_swtpm_control_set_blob(int fd, uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags)
{
	uint8_t request[12];
	int error;

	error = tpm_swtpm_control_blob_validate(type, blob, length, flags);
	if (error != 0)
		return (error);
	be32enc(request, flags);
	be32enc(request + 4, type);
	be32enc(request + 8, length);
	error = swtpm_command(fd, CMD_SET_STATEBLOB, request,
	    sizeof(request));
	if (error != 0)
		return (error);
	error = swtpm_send_all(fd, blob, length);
	if (error != 0)
		return (error);
	return (swtpm_result(fd));
}

int
tpm_swtpm_control_stop(int fd)
{
	int error;

	error = swtpm_command(fd, CMD_STOP, NULL, 0);
	return (error == 0 ? swtpm_result(fd) : error);
}

int
tpm_swtpm_control_init(int fd, uint32_t flags)
{
	uint8_t request[4];
	int error;

	if (flags != 0)
		return (EINVAL);
	be32enc(request, flags);
	error = swtpm_command(fd, CMD_INIT, request, sizeof(request));
	return (error == 0 ? swtpm_result(fd) : error);
}

int
tpm_swtpm_control_lock_storage(int fd, uint32_t retries)
{
	uint8_t request[4];
	int error;

	be32enc(request, retries);
	error = swtpm_command(fd, CMD_LOCK_STORAGE, request,
	    sizeof(request));
	return (error == 0 ? swtpm_result(fd) : error);
}

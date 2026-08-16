/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal, dependency-free TPM2 guest probe for the 5BSD VM image.  It uses
 * the native tpm(4) character-device transaction interface and deliberately
 * implements only the two commands required by the qualification lane.
 */
#include <sys/endian.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_CC_GET_RANDOM  0x0000017b
#define TPM_CC_PCR_READ    0x0000017e
#define TPM_RC_SUCCESS     0
#define TPM_ALG_SHA256     0x000b
#define TPM_HEADER_SIZE    10
#define TPM_BUFFER_SIZE    4096

static size_t
make_get_random(uint8_t *command, uint16_t amount)
{
	be16enc(command, TPM_ST_NO_SESSIONS);
	be32enc(command + 2, 12);
	be32enc(command + 6, TPM_CC_GET_RANDOM);
	be16enc(command + 10, amount);
	return (12);
}

static size_t
make_pcr_read(uint8_t *command)
{
	be16enc(command, TPM_ST_NO_SESSIONS);
	be32enc(command + 2, 20);
	be32enc(command + 6, TPM_CC_PCR_READ);
	be32enc(command + 10, 1);       /* one TPMS_PCR_SELECTION */
	be16enc(command + 14, TPM_ALG_SHA256);
	command[16] = 3;                /* PCR 0..23 selection bitmap */
	command[17] = 1;                /* select PCR 0 */
	command[18] = 0;
	command[19] = 0;
	return (20);
}

static size_t
transmit(int fd, const uint8_t *command, size_t command_length,
    uint8_t *response)
{
	ssize_t amount;
	uint32_t response_length;

	amount = write(fd, command, command_length);
	if (amount < 0)
		err(1, "write TPM command");
	if ((size_t)amount != command_length)
		errx(1, "short TPM command write: %zd of %zu", amount,
		    command_length);
	amount = read(fd, response, TPM_BUFFER_SIZE);
	if (amount < 0)
		err(1, "read TPM response");
	if (amount < TPM_HEADER_SIZE)
		errx(1, "short TPM response: %zd", amount);
	if (be16dec(response) != TPM_ST_NO_SESSIONS)
		errx(1, "unexpected TPM response tag: %#x", be16dec(response));
	response_length = be32dec(response + 2);
	if (response_length < TPM_HEADER_SIZE || response_length > (size_t)amount)
		errx(1, "invalid TPM response length: %u in %zd bytes",
		    response_length, amount);
	if (be32dec(response + 6) != TPM_RC_SUCCESS)
		errx(1, "TPM command failed: %#x", be32dec(response + 6));
	return (response_length);
}

static void
check_get_random(int fd)
{
	uint8_t command[20], response[TPM_BUFFER_SIZE];
	size_t length;
	uint16_t random_length;

	length = transmit(fd, command, make_get_random(command, 32), response);
	if (length < TPM_HEADER_SIZE + 2)
		errx(1, "GetRandom response has no TPM2B_DIGEST");
	random_length = be16dec(response + TPM_HEADER_SIZE);
	if (random_length != 32 ||
	    TPM_HEADER_SIZE + 2 + random_length > length)
		errx(1, "invalid GetRandom byte count: %u", random_length);
}

static void
check_pcr_read(int fd)
{
	uint8_t command[20], response[TPM_BUFFER_SIZE];
	size_t length, offset;
	uint32_t selections, digests;
	uint8_t select_size;
	uint16_t digest_size;

	length = transmit(fd, command, make_pcr_read(command), response);
	offset = TPM_HEADER_SIZE + 4;    /* pcrUpdateCounter */
	if (length < offset + 4)
		errx(1, "PCR_Read response lacks selection count");
	selections = be32dec(response + offset);
	offset += 4;
	if (selections != 1 || length < offset + 3)
		errx(1, "unexpected PCR selection count: %u", selections);
	if (be16dec(response + offset) != TPM_ALG_SHA256)
		errx(1, "PCR_Read returned the wrong hash algorithm");
	select_size = response[offset + 2];
	offset += 3;
	if (select_size == 0 || offset + select_size + 4 > length)
		errx(1, "invalid PCR selection bitmap size: %u", select_size);
	offset += select_size;
	digests = be32dec(response + offset);
	offset += 4;
	if (digests == 0 || offset + 2 > length)
		errx(1, "PCR_Read returned no digest");
	digest_size = be16dec(response + offset);
	if (digest_size != 32 || offset + 2 + digest_size > length)
		errx(1, "invalid SHA-256 PCR digest size: %u", digest_size);
}

static int
self_test(void)
{
	uint8_t command[20];

	memset(command, 0, sizeof(command));
	if (make_get_random(command, 32) != 12 ||
	    be16dec(command) != TPM_ST_NO_SESSIONS ||
	    be32dec(command + 2) != 12 ||
	    be32dec(command + 6) != TPM_CC_GET_RANDOM ||
	    be16dec(command + 10) != 32)
		errx(1, "GetRandom marshalling self-test failed");
	memset(command, 0, sizeof(command));
	if (make_pcr_read(command) != 20 || be32dec(command + 2) != 20 ||
	    be32dec(command + 6) != TPM_CC_PCR_READ ||
	    be16dec(command + 14) != TPM_ALG_SHA256 || command[17] != 1)
		errx(1, "PCR_Read marshalling self-test failed");
	puts("SELFTEST PASS");
	return (0);
}

int
main(int argc, char **argv)
{
	const char *path;
	int fd;

	if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
		return (self_test());
	if (argc > 2)
		errx(2, "usage: freebsd-tpm2-check [device] | --self-test");
	path = argc == 2 ? argv[1] : "/dev/tpm0";
	fd = open(path, O_RDWR);
	if (fd < 0)
		err(1, "open %s", path);
	check_get_random(fd);
	check_pcr_read(fd);
	if (close(fd) != 0)
		err(1, "close %s", path);
	puts("PASS tpm2 getrandom=ok pcr-sha256-0=ok");
	return (0);
}

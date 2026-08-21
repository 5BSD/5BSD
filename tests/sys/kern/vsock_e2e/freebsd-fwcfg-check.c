/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Guest-side QEMU fw_cfg port-I/O probe.  The active mode deliberately
 * leaves the shared data cursor between two reads so a VM checkpoint must
 * preserve both the selected item and its byte offset.
 */
#include <sys/types.h>

#ifdef __linux__
#include <sys/io.h>
#else
#include <machine/cpufunc.h>
#endif

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FWCFG_SELECTOR_PORT 0x510
#define FWCFG_DATA_PORT 0x511
#define FWCFG_FILE_DIRECTORY 0x19
#define FWCFG_NAME_SIZE 56

static uint16_t
load_be16(const uint8_t *bytes)
{
	return ((uint16_t)bytes[0] << 8 | bytes[1]);
}

static uint32_t
load_be32(const uint8_t *bytes)
{
	return ((uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
	    (uint32_t)bytes[2] << 8 | bytes[3]);
}

static void
store_be16(uint8_t *bytes, uint16_t value)
{
	bytes[0] = value >> 8;
	bytes[1] = value;
}

static void
store_be32(uint8_t *bytes, uint32_t value)
{
	bytes[0] = value >> 24;
	bytes[1] = value >> 16;
	bytes[2] = value >> 8;
	bytes[3] = value;
}

static void
select_item(uint16_t selector)
{
#ifdef __linux__
	outw(selector, FWCFG_SELECTOR_PORT);
#else
	outw(FWCFG_SELECTOR_PORT, selector);
#endif
}

static void
read_bytes(void *buffer, size_t length)
{
	uint8_t *bytes;

	bytes = buffer;
	for (size_t i = 0; i < length; i++)
		bytes[i] = inb(FWCFG_DATA_PORT);
}

static uint16_t
find_file(const char *wanted, uint32_t *sizep)
{
	uint8_t header[4], entry[64];
	uint32_t count;

	select_item(FWCFG_FILE_DIRECTORY);
	read_bytes(header, sizeof(header));
	count = load_be32(header);
	if (count > 4096)
		errx(1, "invalid fw_cfg directory count: %u", count);
	for (uint32_t i = 0; i < count; i++) {
		read_bytes(entry, sizeof(entry));
		if (memchr(entry + 8, '\0', FWCFG_NAME_SIZE) == NULL)
			errx(1, "unterminated fw_cfg file name");
		if (strcmp((const char *)entry + 8, wanted) == 0) {
			*sizep = load_be32(entry);
			return (load_be16(entry + 4));
		}
	}
	errx(1, "fw_cfg file not found: %s", wanted);
}

static void
write_marker(const char *path, const char *value)
{
	int fd;
	ssize_t amount;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		err(1, "open %s", path);
	amount = write(fd, value, strlen(value));
	if (amount < 0 || (size_t)amount != strlen(value))
		err(1, "write %s", path);
	if (close(fd) != 0)
		err(1, "close %s", path);
}

static void
open_io(void)
{
	uint8_t signature[4];

#ifdef __linux__
	if (ioperm(FWCFG_SELECTOR_PORT, 2, 1) != 0)
		err(1, "ioperm fw_cfg ports");
#else
	if (open("/dev/io", O_RDWR) < 0)
		err(1, "open /dev/io");
#endif
	select_item(0);
	read_bytes(signature, sizeof(signature));
	if (memcmp(signature, "QEMU", sizeof(signature)) != 0)
		errx(1, "fw_cfg signature mismatch");
}

static void
check_live(const char *name, const char *expected)
{
	uint32_t size;
	uint16_t selector;
	size_t expected_size;
	char *actual;

	selector = find_file(name, &size);
	expected_size = strlen(expected) + 1;
	if (size != expected_size)
		errx(1, "fw_cfg file size mismatch: %u != %zu", size,
		    expected_size);
	actual = malloc(size + 1);
	if (actual == NULL)
		err(1, "malloc");
	select_item(selector);
	read_bytes(actual, size);
	actual[size] = '\0';
	if (memcmp(actual, expected, expected_size) != 0)
		errx(1, "fw_cfg file payload mismatch");
	free(actual);
}

static void
check_active(const char *name, const char *expected, const char *ready,
    const char *go, const char *result)
{
	uint32_t size;
	uint16_t selector;
	size_t expected_size, prefix;
	char *actual;

	selector = find_file(name, &size);
	expected_size = strlen(expected) + 1;
	if (size != expected_size || size < 2)
		errx(1, "fw_cfg active payload has invalid size: %u", size);
	actual = malloc(size);
	if (actual == NULL)
		err(1, "malloc");
	prefix = size / 2;
	select_item(selector);
	read_bytes(actual, prefix);
	write_marker(ready, "ready\n");
	for (unsigned int i = 0; access(go, F_OK) != 0; i++) {
		if (i == 600)
			errx(1, "timed out waiting for cursor continuation");
		usleep(100000);
	}
	/* No selector write here: this read must continue at the saved cursor. */
	read_bytes(actual + prefix, size - prefix);
	if (memcmp(actual, expected, expected_size) != 0)
		errx(1, "fw_cfg selector/cursor was not preserved");
	write_marker(result, "pass\n");
	free(actual);
}

static int
self_test(void)
{
	uint8_t entry[64] = { 0 };

	store_be32(entry, 32);
	store_be16(entry + 4, 0x20);
	strcpy((char *)entry + 8, "opt/waspnest/checkpoint");
	if (load_be32(entry) != 32 || load_be16(entry + 4) != 0x20 ||
	    strcmp((char *)entry + 8, "opt/waspnest/checkpoint") != 0)
		errx(1, "fw_cfg directory codec self-test failed");
	puts("SELFTEST PASS");
	return (0);
}

int
main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
		return (self_test());
	if (argc != 4 && argc != 7)
		errx(2, "usage: freebsd-fwcfg-check live name value | "
		    "active name value ready go result | --self-test");
	open_io();
	if (argc == 4 && strcmp(argv[1], "live") == 0)
		check_live(argv[2], argv[3]);
	else if (argc == 7 && strcmp(argv[1], "active") == 0)
		check_active(argv[2], argv[3], argv[4], argv[5], argv[6]);
	else
		errx(2, "invalid fw_cfg check mode: %s", argv[1]);
	puts("PASS fwcfg selector=ok cursor=ok payload=ok");
	return (0);
}

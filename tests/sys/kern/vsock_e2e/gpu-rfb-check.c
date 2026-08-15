/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Verify that bhyve's external framebuffer presents the pixels written by
 * the VirtIO GPU guest test.  This deliberately implements only the small,
 * unencrypted RFB 3.8/raw-encoding subset used by the test fixture.
 */

#include <sys/endian.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	RFB_VERSION		"RFB 003.008\n"
#define	RFB_VERSION_LEN		12
#define	RFB_SECURITY_NONE	1
#define	RFB_ENCODING_RAW	0
#define	RFB_MAX_NAME		4096
#define	RFB_MAX_DIMENSION	4096
#define	RFB_TIMEOUT_MS		15000

/* Must remain independent from the bhyve implementation headers. */
static const uint8_t first_pixel[4] = { 0x13, 0x57, 0x9b, 0x00 };
static const uint8_t last_pixel[4] = { 0x24, 0x68, 0xac, 0x00 };

static void rfb_handshake(int, uint32_t, uint32_t, int64_t);
static uint8_t *rfb_read_frame(int, uint32_t, uint32_t, int64_t);

static int64_t
milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		err(1, "clock_gettime");
	return ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static void
wait_fd(int fd, short events, int64_t deadline)
{
	struct pollfd pfd;
	int64_t remaining;
	int result;

	pfd.fd = fd;
	pfd.events = events;
	for (;;) {
		remaining = deadline - milliseconds();
		if (remaining <= 0)
			errx(1, "RFB operation timed out");
		result = poll(&pfd, 1, remaining > INT_MAX ? INT_MAX :
		    (int)remaining);
		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			err(1, "poll RFB socket");
		if (result == 0)
			errx(1, "RFB operation timed out");
		if ((pfd.revents & events) != 0)
			return;
		if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
			errx(1, "RFB socket closed unexpectedly (revents %#x)",
			    pfd.revents);
	}
}

static void
read_all(int fd, void *buffer, size_t length, int64_t deadline)
{
	uint8_t *cursor;
	ssize_t amount;

	cursor = buffer;
	while (length != 0) {
		wait_fd(fd, POLLIN, deadline);
		amount = read(fd, cursor, length);
		if (amount < 0 && errno == EINTR)
			continue;
		if (amount < 0)
			err(1, "read RFB socket");
		if (amount == 0)
			errx(1, "unexpected EOF from RFB server");
		cursor += amount;
		length -= (size_t)amount;
	}
}

static void
write_all(int fd, const void *buffer, size_t length, int64_t deadline)
{
	const uint8_t *cursor;
	ssize_t amount;

	cursor = buffer;
	while (length != 0) {
		wait_fd(fd, POLLOUT, deadline);
		amount = write(fd, cursor, length);
		if (amount < 0 && errno == EINTR)
			continue;
		if (amount < 0)
			err(1, "write RFB socket");
		if (amount == 0)
			errx(1, "zero-length RFB write");
		cursor += amount;
		length -= (size_t)amount;
	}
}

static uint32_t
parse_dimension(const char *text, const char *name)
{
	char *end;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || *text == '\0' || *end != '\0' || value == 0 ||
	    value > RFB_MAX_DIMENSION)
		errx(2, "%s must be an integer from 1 through %u", name,
		    RFB_MAX_DIMENSION);
	return ((uint32_t)value);
}

static void
parse_pixel(const char *text, uint8_t pixel[4])
{
	char byte[3], *end;
	unsigned long value;

	if (strlen(text) != 8)
		errx(2, "pixel must contain exactly eight hexadecimal digits");
	byte[2] = '\0';
	for (size_t i = 0; i < 4; i++) {
		byte[0] = text[i * 2];
		byte[1] = text[i * 2 + 1];
		errno = 0;
		value = strtoul(byte, &end, 16);
		if (errno != 0 || *end != '\0' || value > UINT8_MAX)
			errx(2, "pixel must contain exactly eight hexadecimal digits");
		pixel[i] = (uint8_t)value;
	}
}

static void
check_pixel(const uint8_t *frame, uint32_t width, uint32_t height,
    uint32_t x, uint32_t y, const uint8_t expected[4])
{
	const uint8_t *actual;

	if (x >= width || y >= height)
		errx(1, "pixel coordinate outside framebuffer");
	actual = frame + ((size_t)y * width + x) * 4;
	if (memcmp(actual, expected, 4) != 0)
		errx(1, "RFB pixel %u,%u is %02x%02x%02x%02x, expected "
		    "%02x%02x%02x%02x", x, y, actual[0], actual[1],
		    actual[2], actual[3], expected[0], expected[1], expected[2],
		    expected[3]);
}

static int
self_test(void)
{
	uint8_t frame[4 * 3 * 2], buffer[20], init[24], rectangle[12];
	uint8_t parsed_pixel[4];
	uint8_t *received;
	int sockets[2], status;
	int64_t deadline;
	pid_t child;

	memset(frame, 0, sizeof(frame));
	memcpy(frame + (3 - 1) * 4, first_pixel, 4);
	memcpy(frame + (3 * (2 - 1)) * 4, last_pixel, 4);
	check_pixel(frame, 3, 2, 2, 0, first_pixel);
	check_pixel(frame, 3, 2, 0, 1, last_pixel);
	parse_pixel("759abfe4", parsed_pixel);
	if (memcmp(parsed_pixel, (uint8_t[]){ 0x75, 0x9a, 0xbf, 0xe4 },
	    sizeof(parsed_pixel)) != 0)
		errx(1, "pixel parser self-test failed");
	if (parse_dimension("4096", "width") != 4096)
		errx(1, "dimension parser self-test failed");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
		err(1, "socketpair self-test");
	child = fork();
	if (child < 0)
		err(1, "fork self-test");
	deadline = milliseconds() + 5000;
	if (child == 0) {
		close(sockets[0]);
		write_all(sockets[1], RFB_VERSION, RFB_VERSION_LEN, deadline);
		read_all(sockets[1], buffer, RFB_VERSION_LEN, deadline);
		if (memcmp(buffer, RFB_VERSION, RFB_VERSION_LEN) != 0)
			errx(1, "self-test client version mismatch");
		buffer[0] = 1;
		buffer[1] = RFB_SECURITY_NONE;
		write_all(sockets[1], buffer, 2, deadline);
		read_all(sockets[1], buffer, 1, deadline);
		if (buffer[0] != RFB_SECURITY_NONE)
			errx(1, "self-test security selection mismatch");
		memset(buffer, 0, 4);
		write_all(sockets[1], buffer, 4, deadline);
		read_all(sockets[1], buffer, 1, deadline);
		if (buffer[0] != 1)
			errx(1, "self-test shared flag mismatch");
		memset(init, 0, sizeof(init));
		be16enc(init, 3);
		be16enc(init + 2, 2);
		init[4] = 32;
		init[5] = 32;
		init[7] = 1;
		be16enc(init + 8, 255);
		be16enc(init + 10, 255);
		be16enc(init + 12, 255);
		init[14] = 16;
		init[15] = 8;
		be32enc(init + 20, 4);
		write_all(sockets[1], init, sizeof(init), deadline);
		write_all(sockets[1], "mock", 4, deadline);
		read_all(sockets[1], buffer, 20, deadline);
		if (buffer[0] != 0 || buffer[4] != 32 || buffer[5] != 24)
			errx(1, "self-test pixel format mismatch");
		read_all(sockets[1], buffer, 8, deadline);
		if (buffer[0] != 2 || be16dec(buffer + 2) != 1 ||
		    be32dec(buffer + 4) != RFB_ENCODING_RAW)
			errx(1, "self-test encoding mismatch");
		read_all(sockets[1], buffer, 10, deadline);
		if (buffer[0] != 3 || buffer[1] != 0 ||
		    be16dec(buffer + 6) != 3 || be16dec(buffer + 8) != 2)
			errx(1, "self-test update request mismatch");
		memset(buffer, 0, 4);
		be16enc(buffer + 2, 1);
		write_all(sockets[1], buffer, 4, deadline);
		memset(rectangle, 0, sizeof(rectangle));
		be16enc(rectangle + 4, 3);
		be16enc(rectangle + 6, 2);
		be32enc(rectangle + 8, RFB_ENCODING_RAW);
		write_all(sockets[1], rectangle, sizeof(rectangle), deadline);
		write_all(sockets[1], frame, sizeof(frame), deadline);
		close(sockets[1]);
		_exit(0);
	}
	close(sockets[1]);
	rfb_handshake(sockets[0], 3, 2, deadline);
	received = rfb_read_frame(sockets[0], 3, 2, deadline);
	check_pixel(received, 3, 2, 2, 0, first_pixel);
	check_pixel(received, 3, 2, 0, 1, last_pixel);
	free(received);
	close(sockets[0]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		errx(1, "RFB mock server self-test failed");
	puts("SELFTEST PASS");
	return (0);
}

static int
connect_unix(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(2, "RFB socket path is too long");
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "socket");
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "connect %s", path);
	return (fd);
}

static void
rfb_handshake(int fd, uint32_t expected_width, uint32_t expected_height,
    int64_t deadline)
{
	uint8_t version[RFB_VERSION_LEN], security[2], result[4], init[24];
	uint8_t shared;
	uint32_t name_length;
	char *name;

	read_all(fd, version, sizeof(version), deadline);
	if (memcmp(version, RFB_VERSION, sizeof(version)) != 0)
		errx(1, "RFB server did not offer version 3.8");
	write_all(fd, RFB_VERSION, RFB_VERSION_LEN, deadline);
	read_all(fd, security, sizeof(security), deadline);
	if (security[0] != 1 || security[1] != RFB_SECURITY_NONE)
		errx(1, "RFB server did not offer exactly None security");
	write_all(fd, &security[1], 1, deadline);
	read_all(fd, result, sizeof(result), deadline);
	if (be32dec(result) != 0)
		errx(1, "RFB server rejected None security");
	shared = 1;
	write_all(fd, &shared, sizeof(shared), deadline);
	read_all(fd, init, sizeof(init), deadline);
	if (be16dec(init) != expected_width || be16dec(init + 2) != expected_height)
		errx(1, "RFB geometry is %ux%u, expected %ux%u",
		    be16dec(init), be16dec(init + 2), expected_width,
		    expected_height);
	if (init[4] != 32 || init[5] != 32 || init[6] != 0 || init[7] != 1 ||
	    be16dec(init + 8) != 255 || be16dec(init + 10) != 255 ||
	    be16dec(init + 12) != 255 || init[14] != 16 || init[15] != 8 ||
	    init[16] != 0)
		errx(1, "RFB server advertised an unexpected pixel format");
	name_length = be32dec(init + 20);
	if (name_length > RFB_MAX_NAME)
		errx(1, "RFB desktop name is too long: %u", name_length);
	name = malloc((size_t)name_length + 1);
	if (name == NULL)
		err(1, "malloc RFB desktop name");
	read_all(fd, name, name_length, deadline);
	name[name_length] = '\0';
	free(name);
}

static uint8_t *
rfb_read_frame(int fd, uint32_t width, uint32_t height, int64_t deadline)
{
	uint8_t set_format[20] = {
		0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255,
		16, 8, 0, 0, 0, 0
	};
	uint8_t set_encodings[8] = { 2, 0, 0, 1, 0, 0, 0, 0 };
	uint8_t request[10] = { 3, 0 };
	uint8_t update[4], rectangle[12];
	uint8_t *frame, *payload;
	uint32_t encoding, rectangle_width, rectangle_height, x, y;
	size_t frame_length, payload_length;
	uint16_t rectangles;

	be16enc(request + 6, width);
	be16enc(request + 8, height);
	write_all(fd, set_format, sizeof(set_format), deadline);
	write_all(fd, set_encodings, sizeof(set_encodings), deadline);
	write_all(fd, request, sizeof(request), deadline);
	if ((size_t)width > SIZE_MAX / height / 4)
		errx(1, "RFB framebuffer size overflow");
	frame_length = (size_t)width * height * 4;
	frame = calloc(1, frame_length);
	if (frame == NULL)
		err(1, "calloc RFB framebuffer");
	read_all(fd, update, sizeof(update), deadline);
	if (update[0] != 0)
		errx(1, "unexpected RFB server message type %u", update[0]);
	rectangles = be16dec(update + 2);
	if (rectangles == 0)
		errx(1, "RFB update contained no rectangles");
	for (uint16_t i = 0; i < rectangles; i++) {
		read_all(fd, rectangle, sizeof(rectangle), deadline);
		x = be16dec(rectangle);
		y = be16dec(rectangle + 2);
		rectangle_width = be16dec(rectangle + 4);
		rectangle_height = be16dec(rectangle + 6);
		encoding = be32dec(rectangle + 8);
		if (encoding != RFB_ENCODING_RAW)
			errx(1, "unexpected RFB encoding %d", (int32_t)encoding);
		if (rectangle_width == 0 || rectangle_height == 0 || x > width ||
		    y > height || rectangle_width > width - x ||
		    rectangle_height > height - y)
			errx(1, "invalid RFB rectangle %u,%u %ux%u", x, y,
			    rectangle_width, rectangle_height);
		if ((size_t)rectangle_width > SIZE_MAX / rectangle_height / 4)
			errx(1, "RFB rectangle size overflow");
		payload_length = (size_t)rectangle_width * rectangle_height * 4;
		payload = malloc(payload_length);
		if (payload == NULL)
			err(1, "malloc RFB rectangle");
		read_all(fd, payload, payload_length, deadline);
		for (uint32_t row = 0; row < rectangle_height; row++)
			memcpy(frame + ((size_t)(y + row) * width + x) * 4,
			    payload + (size_t)row * rectangle_width * 4,
			    (size_t)rectangle_width * 4);
		free(payload);
	}
	return (frame);
}

int
main(int argc, char **argv)
{
	uint8_t expected_last[4];
	uint8_t *frame;
	uint32_t width, height;
	int64_t deadline;
	int fd;

	if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
		return (self_test());
	if (argc != 4 && argc != 5)
		errx(2, "usage: gpu-rfb-check socket-path width height "
		    "[last-pixel-hex] | --self-test");
	width = parse_dimension(argv[2], "width");
	height = parse_dimension(argv[3], "height");
	memcpy(expected_last, last_pixel, sizeof(expected_last));
	if (argc == 5)
		parse_pixel(argv[4], expected_last);
	deadline = milliseconds() + RFB_TIMEOUT_MS;
	fd = connect_unix(argv[1]);
	rfb_handshake(fd, width, height, deadline);
	frame = rfb_read_frame(fd, width, height, deadline);
	check_pixel(frame, width, height, width - 1, 0, first_pixel);
	check_pixel(frame, width, height, 0, height - 1, expected_last);
	free(frame);
	close(fd);
	printf("PASS gpu-rfb size=%ux%u first=%02x%02x%02x%02x "
	    "last=%02x%02x%02x%02x\n", width, height, first_pixel[0],
	    first_pixel[1], first_pixel[2], first_pixel[3], expected_last[0],
	    expected_last[1], expected_last[2],
	    expected_last[3]);
	return (0);
}

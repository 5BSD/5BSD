/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for libble's framed daemon-response parser.
 *
 * Arbitrary bytes are fed through a socketpair into ble_process(), exercising
 * frame reassembly, length checks, operation correlation and typed event
 * decoding.  Both endpoints are non-blocking so oversized inputs cannot stall
 * the harness.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "ble.h"

static void
set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);

	if (fl >= 0)
		(void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ble_ctx_t *ctx;
	size_t off = 0;
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return (0);
	set_nonblock(sp[0]);
	set_nonblock(sp[1]);

	ctx = ble_open_fd(sp[0]);
	if (ctx == NULL) {
		close(sp[0]);
		close(sp[1]);
		return (0);
	}

	while (off < size) {
		ssize_t w = send(sp[1], data + off, size - off, MSG_DONTWAIT);

		if (w > 0)
			off += (size_t)w;
		if (ble_process(ctx) < 0 || w <= 0)
			break;
	}
	(void)ble_process(ctx);

	ble_close(ctx);
	close(sp[1]);
	return (0);
}

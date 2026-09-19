/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the blued configuration-file parser
 * (usr.sbin/bluetooth/blued/config.c).
 *
 * blued reads /etc/blued.conf through libucl and walks the resulting
 * object tree in config_parse_root() -> config_parse_{general,features,
 * security,devices,service,characteristic}().  The file is trusted-ish
 * (root-owned) but a malformed or hostile config is a real robustness
 * surface: the walkers copy strings into fixed struct fields, parse
 * hex/UUID/addr tokens, and bound device/service/characteristic counts.
 *
 * Entry point: blued_config_load_fd() -- the exact path blued uses to
 * reload configuration from a pre-opened descriptor inside its Capsicum
 * sandbox (SIGHUP reload).  It fstat/read()s the fd, hands the bytes to
 * ucl_parser_add_string(), then runs config_parse_root() over the parsed
 * tree.  We stage each fuzz input in an anonymous temp file and feed its
 * descriptor, so both the UCL parse and every config_parse_* walker run.
 *
 * ASan/UBSan catch out-of-bounds copies and UB; libucl is linked from the
 * staged libprivateucl.a (see fuzz/Makefile UCL_A), same as fuzz_ctl_ipc.
 *
 * Reference: usr.sbin/bluetooth/blued/config.c.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct blued_config	cfg;
	FILE			*f;
	int			 fd;

	/* blued_config_load_fd() rejects files larger than 1 MiB. */
	if (size > 1024 * 1024)
		size = 1024 * 1024;

	f = tmpfile();
	if (f == NULL)
		return (0);
	fd = fileno(f);

	if (size > 0 && fwrite(data, 1, size, f) != size) {
		fclose(f);
		return (0);
	}
	fflush(f);
	/* blued_config_load_fd() lseeks to 0 itself before reading. */

	blued_config_defaults(&cfg);
	(void)blued_config_load_fd(&cfg, fd);

	fclose(f);
	return (0);
}

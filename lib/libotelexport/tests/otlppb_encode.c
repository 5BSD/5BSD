/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlppb_encode - transcode OTLP JSON requests to binary protobuf with
 * the library's encoder (oe_otlppb.c), for the oracle tests.
 *
 *   otlppb_encode [-s logs|metrics|traces] < request.json > request.pb
 *
 * Without -s the signal comes from the request's top-level key.  Each
 * input line is one request; with several lines, each output message
 * is preceded by its length as a 4-byte big-endian integer.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"

int
main(int argc, char **argv)
{
	struct oe_otlppb_defs defs;
	char *line, *pb, msg[256];
	size_t cap, pblen, nlines;
	ssize_t len;
	unsigned char hdr[4];
	int ch, sig, forced, framed;

	forced = -1;
	framed = 0;
	while ((ch = getopt(argc, argv, "fs:")) != -1) {
		switch (ch) {
		case 'f':
			framed = 1;
			break;
		case 's':
			if (strcmp(optarg, "logs") == 0)
				forced = OE_SIGNAL_LOGS;
			else if (strcmp(optarg, "metrics") == 0)
				forced = OE_SIGNAL_METRICS;
			else if (strcmp(optarg, "traces") == 0)
				forced = OE_SIGNAL_TRACES;
			else if (strcmp(optarg, "profiles") == 0)
				forced = OE_SIGNAL_PROFILES;
			else
				errx(2, "unknown signal %s", optarg);
			break;
		default:
			fprintf(stderr, "usage: otlppb_encode [-f] "
			    "[-s logs|metrics|traces|profiles]\n");
			return (2);
		}
	}
	if (oe_otlppb_defs_init(&defs) != 0)
		errx(1, "cannot load the OTLP definitions");
	line = NULL;
	cap = 0;
	nlines = 0;
	while ((len = getline(&line, &cap, stdin)) > 0) {
		if (line[len - 1] == '\n')
			line[--len] = '\0';
		if (len == 0)
			continue;
		nlines++;
		sig = forced >= 0 ? forced : oe_enc_classify(line);
		if (sig < 0)
			errx(1, "line %zu: not an OTLP request", nlines);
		if (oe_otlppb_encode(&defs, (enum oe_signal)sig, line,
		    (size_t)len, &pb, &pblen, msg, sizeof(msg)) != 0)
			errx(1, "line %zu: %s", nlines, msg);
		if (framed) {
			hdr[0] = (unsigned char)(pblen >> 24);
			hdr[1] = (unsigned char)(pblen >> 16);
			hdr[2] = (unsigned char)(pblen >> 8);
			hdr[3] = (unsigned char)pblen;
			fwrite(hdr, 1, 4, stdout);
		}
		fwrite(pb, 1, pblen, stdout);
		free(pb);
	}
	free(line);
	oe_otlppb_defs_fini(&defs);
	if (fflush(stdout) != 0 || ferror(stdout))
		err(1, "stdout");
	return (0);
}

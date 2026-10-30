/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_pb_receiver - loopback OTLP/HTTP and OTLP/gRPC receiver for the
 * system tests (dtrace -x otelprotocol, the VM runs).
 *
 *   otlp_pb_receiver -m http|grpc -p portfile -d dir [-n count] [-t secs]
 *
 * Listens on 127.0.0.1 (an ephemeral port, written to portfile once
 * listening) and accepts every request with success (an empty
 * Export*ServiceResponse) until SIGTERM, SIGINT or secs seconds (default
 * 60), so a client that keeps sending is never refused.  It then writes
 * each request to dir/NNNN.path (the request path, or gRPC method),
 * NNNN.hdr (headers) and NNNN.bin (the body or message, decompressed)
 * and exits 0 when at least count requests arrived, 1 otherwise (also
 * when more requests arrived than it can record: 64).  Decode
 * NNNN.bin with otlp_pb_oracle or protoc --decode.
 */

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "grpc_testsrv.h"
#include "otel_testutil.h"

static void
put(const char *dir, int i, const char *ext, const void *data, size_t len)
{
	char path[1024];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%04d.%s", dir, i, ext);
	if ((f = fopen(path, "w")) == NULL)
		err(1, "%s", path);
	if (len > 0 && fwrite(data, 1, len, f) != len)
		err(1, "%s", path);
	if (fclose(f) != 0)
		err(1, "%s", path);
}

static void
put_port(const char *portfile, int port)
{
	char tmp[1024];
	FILE *f;

	/* Rename into place, so a reader never sees a partial number. */
	snprintf(tmp, sizeof(tmp), "%s.tmp", portfile);
	if ((f = fopen(tmp, "w")) == NULL || fprintf(f, "%d\n", port) < 0 ||
	    fclose(f) != 0 || rename(tmp, portfile) != 0)
		err(1, "%s", portfile);
}

static volatile sig_atomic_t stop;

static void
on_signal(int sig __unused)
{

	stop = 1;
}

static void
usage(void)
{

	fprintf(stderr, "usage: otlp_pb_receiver -m http|grpc -p portfile "
	    "-d dir [-n count] [-t secs]\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct collector co;
	struct coll_reply rep[COLL_MAX_SCRIPT];
	struct gsrv gs;
	const char *mode, *portfile, *dir;
	time_t end;
	int ch, count, secs, i, n = 0, lost = 0;

	mode = portfile = dir = NULL;
	count = 1;
	secs = 60;
	while ((ch = getopt(argc, argv, "d:m:n:p:t:")) != -1) {
		switch (ch) {
		case 'd':
			dir = optarg;
			break;
		case 'm':
			mode = optarg;
			break;
		case 'n':
			count = atoi(optarg);
			break;
		case 'p':
			portfile = optarg;
			break;
		case 't':
			secs = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	if (mode == NULL || portfile == NULL || dir == NULL || count < 1 ||
	    count > COLL_MAX_SCRIPT || secs < 1)
		usage();
	end = time(NULL) + secs;
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	if (strcmp(mode, "grpc") == 0) {
		if (gsrv_start(&gs, 0, NULL, NULL) != 0)
			errx(1, "cannot start the gRPC server");
		put_port(portfile, gs.port);
		while (!stop && time(NULL) < end)
			usleep(100000);
		n = gsrv_nreqs(&gs);
		lost = gs.nlost;
		/* gsrv_stop() frees the requests. */
		for (i = 0; i < n; i++) {
			put(dir, i, "path", gs.reqs[i].path,
			    strlen(gs.reqs[i].path));
			put(dir, i, "hdr", gs.reqs[i].headers,
			    strlen(gs.reqs[i].headers));
			put(dir, i, "bin", gs.reqs[i].msg, gs.reqs[i].msglen);
		}
		gsrv_stop(&gs);
	} else if (strcmp(mode, "http") == 0) {
		if (coll_start(&co, 0, 0, NULL) != 0)
			errx(1, "cannot start the HTTP server");
		/* 200 with an empty body: an empty Export*ServiceResponse. */
		memset(rep, 0, sizeof(rep));
		for (i = 0; i < COLL_MAX_SCRIPT; i++) {
			rep[i].status = 200;
			rep[i].body = "";
		}
		coll_script(&co, rep, COLL_MAX_SCRIPT);
		/* And past the script too: never the OTLP/JSON "{}". */
		co.fallback_body = "";
		put_port(portfile, co.port);
		while (!stop && time(NULL) < end)
			usleep(100000);
		n = coll_nreqs(&co);
		lost = co.nlost;
		for (i = 0; i < n; i++) {
			put(dir, i, "path", co.reqs[i].path,
			    strlen(co.reqs[i].path));
			put(dir, i, "hdr", co.reqs[i].headers,
			    strlen(co.reqs[i].headers));
			put(dir, i, "bin", co.reqs[i].body,
			    co.reqs[i].bodylen);
		}
		coll_stop(&co);
	} else
		usage();
	/* Requests past the recording limit were answered but not kept. */
	if (lost > 0) {
		warnx("%d requests past the first %d were not recorded",
		    lost, n);
		return (1);
	}
	return (n >= count ? 0 : 1);
}

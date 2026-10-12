/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Trace peer built from evolution/tracecmp_next.fidl at bsd:2 (one
 * method more than the production bsd:1 schema).  evolution_test pairs it
 * with the real bsd:1 client and provider:
 *
 *   next_peer serve FD   serve bsd:2 on FD; exit 0 once the peer leaves
 *   next_peer call FD    as a bsd:2 client: negotiate, use Stats, then call
 *                        the added method, which a bsd:1 provider must
 *                        refuse by closing the session (strict method)
 */
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.trace.v1/c/bsd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x)                                                             \
	do {                                                                 \
		if (!(x)) {                                                  \
			fprintf(stderr, "next_peer: %d: %s\n", __LINE__, #x); \
			exit(1);                                             \
		}                                                            \
	} while (0)

struct result {
	bool done;
	int error;
	uint32_t value;
};

static void
pump(struct fidl_bsd_connection *c, struct result *r)
{
	for (int i = 0; i < 500 && !r->done; ++i) {
		int error = fidl_bsd_connection_poll(c, 10);
		if (error != 0 && error != ETIMEDOUT && error != EAGAIN &&
		    !r->done) {
			r->done = true;
			r->error = error;
		}
	}
	CHECK(r->done);
}
static void
info_reply(void *p, int error, struct bsd_trace_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}
static void
stats_reply(void *p, int error, struct bsd_trace_v1_TraceStats *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = (uint32_t)v->opened;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { 0 };
	uint32_t txid;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &c) == 0);
	CHECK(bsd_trace_v1_Trace_GetProtocolInfo(c, &empty, info_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 1);
	r = (struct result){ 0 };
	CHECK(bsd_trace_v1_Trace_Stats(c, &empty, stats_reply, &r, &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0);
	/* The added strict method is unknown to a bsd:1 provider. */
	r = (struct result){ 0 };
	CHECK(bsd_trace_v1_Trace_Probe(c, &empty, stats_reply, &r, &txid) == 0);
	pump(c, &r);
	CHECK(r.error != 0);
	CHECK(fidl_bsd_connection_error(c) != 0);
	fidl_bsd_connection_destroy(c);
	printf("next_peer: bsd:2 client vs bsd:1 provider: added method "
	    "refused (%s), bsd:1 methods served\n", strerror(r.error));
	return (0);
}

static void
serve_info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_trace_v1_ProtocolInfo v = { 1, 1 };
	(void)e;
	++*(unsigned *)x;
	CHECK(bsd_trace_v1_Trace_GetProtocolInfo_reply(c, q, &v) == 0);
}
static void
serve_open(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_trace_v1_Trace_Open_Result v = {
		.tag = bsd_trace_v1_Trace_Open_Result_response_tag
	};
	int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	(void)e;
	CHECK(fd >= 0);
	++*(unsigned *)x;
	v.value.response.dtrace = fd;
	CHECK(bsd_trace_v1_Trace_Open_reply(c, q, &v) == 0);
	close(fd);
}
static void
serve_stats(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_trace_v1_TraceStats v = { 0, 0 };
	(void)x;
	(void)e;
	CHECK(bsd_trace_v1_Trace_Stats_reply(c, q, &v) == 0);
}
static void
serve_probe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_trace_v1_TraceStats v = { 9, 9 };
	(void)x;
	(void)e;
	CHECK(bsd_trace_v1_Trace_Probe_reply(c, q, &v) == 0);
}

static int
run_server(int fd)
{
	struct bsd_trace_v1_Trace_server handlers = {
		.GetProtocolInfo = serve_info,
		.Open = serve_open,
		.Stats = serve_stats,
		.Probe = serve_probe
	};
	struct fidl_bsd_connection *c;
	unsigned served = 0;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &c) == 0);
	CHECK(bsd_trace_v1_Trace_bind(c, &handlers, &served) == 0);
	while (fidl_bsd_connection_poll(c, 10000) == 0)
		;
	fidl_bsd_connection_destroy(c);
	/* The bsd:1 client negotiated and opened a consumer. */
	return (served == 2 ? 0 : 1);
}

int
main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "call") == 0)
		return (run_client(atoi(argv[2])));
	if (argc == 3 && strcmp(argv[1], "serve") == 0)
		return (run_server(atoi(argv[2])));
	fprintf(stderr, "usage: next_peer call|serve FD\n");
	return (2);
}

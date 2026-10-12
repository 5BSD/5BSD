/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Notify peer built from evolution/notify_next.fidl at bsd:2 (one
 * method more than the production bsd:1 schema).  session_test pairs it
 * with the real bsd:1 client and router:
 *
 *   next_peer serve FD   serve bsd:2 on FD; exit 0 once the peer leaves
 *   next_peer call FD    as a bsd:2 client: negotiate, read the limits, then
 *                        call the added method, which a bsd:1 provider must
 *                        refuse by closing the session (strict method)
 */
#include <errno.h>
#include <fidl/bsd.notify.v1/c/bsd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	uint64_t value;
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
info_reply(void *p, int error, struct bsd_notify_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}
static void
hello_reply(void *p, int error, struct bsd_notify_v1_Notify_Hello_Result *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->tag == bsd_notify_v1_Notify_Hello_Result_response_tag ?
		    v->value.response.router_epoch : 0;
}
static void
probe_reply(void *p, int error, struct bsd_notify_v1_Stats *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->published;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_notify_v1_HelloRequest hello = { 0 };
	struct result r = { 0 };
	uint32_t txid;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &c) == 0);
	CHECK(bsd_notify_v1_Notify_GetProtocolInfo(c, &empty, info_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 1);
	r = (struct result){ 0 };
	CHECK(bsd_notify_v1_Notify_Hello(c, &hello, hello_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value != 0);
	/* The added strict method is unknown to a bsd:1 provider. */
	r = (struct result){ 0 };
	CHECK(bsd_notify_v1_Notify_Probe(c, &empty, probe_reply, &r,
	    &txid) == 0);
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
	struct bsd_notify_v1_ProtocolInfo v = { 1 };
	(void)x;
	(void)e;
	CHECK(bsd_notify_v1_Notify_GetProtocolInfo_reply(c, q, &v) == 0);
}
static void
serve_hello(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct bsd_notify_v1_HelloRequest *e)
{
	/* The limits libnotify requires: features PUBSUB..LOSS_REPORTING. */
	struct bsd_notify_v1_Notify_Hello_Result v = {
		.tag = bsd_notify_v1_Notify_Hello_Result_response_tag,
		.value.response = { 0x1f, 128, 2048, 64, 256, 64, 4096, 77 }
	};
	(void)x;
	(void)e;
	CHECK(bsd_notify_v1_Notify_Hello_reply(c, q, &v) == 0);
}
static void
serve_stats(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_notify_v1_Notify_GetStats_Result v = {
		.tag = bsd_notify_v1_Notify_GetStats_Result_response_tag,
		.value.response = { 5, 0, 0, 0, 0 }
	};
	(void)e;
	++*(unsigned *)x;
	CHECK(bsd_notify_v1_Notify_GetStats_reply(c, q, &v) == 0);
}
static void
serve_probe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_notify_v1_Stats v = { 0 };
	(void)x;
	(void)e;
	CHECK(bsd_notify_v1_Notify_Probe_reply(c, q, &v) == 0);
}

static int
run_server(int fd)
{
	struct bsd_notify_v1_Notify_server handlers = {
		.GetProtocolInfo = serve_info,
		.Hello = serve_hello,
		.GetStats = serve_stats,
		.Probe = serve_probe
	};
	struct fidl_bsd_connection *c;
	unsigned served = 0;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &c) == 0);
	CHECK(bsd_notify_v1_Notify_bind(c, &handlers, &served) == 0);
	while (fidl_bsd_connection_poll(c, 10000) == 0)
		;
	fidl_bsd_connection_destroy(c);
	return (served == 1 ? 0 : 1);
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

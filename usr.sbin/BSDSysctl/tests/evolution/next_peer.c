/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Sysctl peer built from evolution/sysctlcmp_next.fidl at bsd:2 (one
 * method more than the production bsd:1 schema).  evolution_test pairs it
 * with the real bsd:1 client and provider:
 *
 *   next_peer serve FD   serve bsd:2 on FD; exit 0 once the peer leaves
 *   next_peer call FD    as a bsd:2 client: negotiate, Get kern.ostype, then
 *                        call the added method, which a bsd:1 provider must
 *                        refuse by closing the session (strict method)
 */
#include <errno.h>
#include <fidl/bsd.sysctl.v1/c/bsd.h>
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
info_reply(void *p, int error, struct bsd_sysctl_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}
static void
get_reply(void *p, int error, struct bsd_sysctl_v1_Sysctl_Get_Result *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->tag == bsd_sysctl_v1_Sysctl_Get_Result_response_tag ?
		    (uint32_t)v->value.response.value_size : UINT32_MAX;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_sysctl_v1_NameRequest name = { "kern.ostype", 11 };
	struct result r = { 0 };
	uint32_t txid;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &c) == 0);
	CHECK(bsd_sysctl_v1_Sysctl_GetProtocolInfo(c, &empty, info_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 1);
	r = (struct result){ 0 };
	CHECK(bsd_sysctl_v1_Sysctl_Get(c, &name, get_reply, &r, &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value != UINT32_MAX && r.value > 0);
	/* The added strict method is unknown to a bsd:1 provider. */
	r = (struct result){ 0 };
	CHECK(bsd_sysctl_v1_Sysctl_Probe(c, &empty, info_reply, &r, &txid) == 0);
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
	struct bsd_sysctl_v1_ProtocolInfo v = { 1 };
	(void)x;
	(void)e;
	CHECK(bsd_sysctl_v1_Sysctl_GetProtocolInfo_reply(c, q, &v) == 0);
}
static void
serve_get(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct bsd_sysctl_v1_NameRequest *e)
{
	static uint8_t text[] = "5BSD";
	struct bsd_sysctl_v1_Sysctl_Get_Result v = {
		.tag = bsd_sysctl_v1_Sysctl_Get_Result_response_tag
	};
	(void)e;
	++*(unsigned *)x;
	v.value.response.value = text;
	v.value.response.value_size = sizeof(text);
	CHECK(bsd_sysctl_v1_Sysctl_Get_reply(c, q, &v) == 0);
}
static void
serve_probe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_sysctl_v1_ProtocolInfo v = { 2 };
	(void)x;
	(void)e;
	CHECK(bsd_sysctl_v1_Sysctl_Probe_reply(c, q, &v) == 0);
}

static int
run_server(int fd)
{
	struct bsd_sysctl_v1_Sysctl_server handlers = {
		.GetProtocolInfo = serve_info,
		.Get = serve_get,
		.Probe = serve_probe
	};
	struct fidl_bsd_connection *c;
	unsigned served = 0;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &c) == 0);
	CHECK(bsd_sysctl_v1_Sysctl_bind(c, &handlers, &served) == 0);
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

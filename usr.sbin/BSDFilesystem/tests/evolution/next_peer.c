/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Filesystem peer built from evolution/filesystemcmp_next.fidl at bsd:2
 * (one method more than the production bsd:1 schema).  evolution_test pairs it
 * with the real bsd:1 client and provider:
 *
 *   next_peer serve FD   serve bsd:2 on FD; exit 0 once the peer leaves
 *   next_peer call FD    as a bsd:2 client: negotiate, use Ping, then call
 *                        the added method, which a bsd:1 provider must
 *                        refuse by closing the session (strict method)
 */
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.filesystem.v1/c/bsd.h>
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
info_reply(void *p, int error, struct bsd_filesystem_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}
static void
ping_reply(void *p, int error,
    struct bsd_filesystem_v1_Filesystem_Ping_Result *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = (uint32_t)v->tag;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { 0 };
	uint32_t txid;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &c) == 0);
	CHECK(bsd_filesystem_v1_Filesystem_GetProtocolInfo(c, &empty,
	    info_reply, &r, &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 1);
	r = (struct result){ 0 };
	CHECK(bsd_filesystem_v1_Filesystem_Ping(c, &empty, ping_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 &&
	    r.value == bsd_filesystem_v1_Filesystem_Ping_Result_response_tag);
	/* The added strict method is unknown to a bsd:1 provider. */
	r = (struct result){ 0 };
	CHECK(bsd_filesystem_v1_Filesystem_Probe(c, &empty, info_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error != 0);
	CHECK(fidl_bsd_connection_error(c) != 0);
	fidl_bsd_connection_destroy(c);
	printf("next_peer: bsd:2 client vs bsd:1 provider: added method "
	    "refused (%s), bsd:1 methods served\n", strerror(r.error));
	return (0);
}

static unsigned served;

static void
serve_info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_filesystem_v1_ProtocolInfo v = { 1 };
	(void)x;
	(void)e;
	CHECK(bsd_filesystem_v1_Filesystem_GetProtocolInfo_reply(c, q, &v) == 0);
}
static void
serve_list(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct bsd_filesystem_v1_ListRequest *e)
{
	struct bsd_filesystem_v1_ClaimEntry entry = {
		.name = "state", .name_size = 5, .used = 4096,
		.refquota = 1 << 20, .lifetime = 0
	};
	struct bsd_filesystem_v1_Filesystem_List_Result v = {
		.tag = bsd_filesystem_v1_Filesystem_List_Result_response_tag
	};
	(void)x;
	CHECK(e->cursor == 0 && e->scope == 0 && e->group_size == 0);
	served++;
	v.value.response.entries = &entry;
	v.value.response.entries_size = 1;
	CHECK(bsd_filesystem_v1_Filesystem_List_reply(c, q, &v) == 0);
}
static void
serve_open(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct bsd_filesystem_v1_OpenRequest *e)
{
	struct bsd_filesystem_v1_Filesystem_Open_Result v = {
		.tag = bsd_filesystem_v1_Filesystem_Open_Result_response_tag
	};
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	(void)x;
	CHECK(fd >= 0);
	CHECK(e->path_size == 9 && memcmp(e->path, "/dev/null", 9) == 0);
	served++;
	v.value.response.handle = fd;
	CHECK(bsd_filesystem_v1_Filesystem_Open_reply(c, q, &v) == 0);
	close(fd);
}
static void
serve_probe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_filesystem_v1_ProtocolInfo v = { 2 };
	(void)x;
	(void)e;
	CHECK(bsd_filesystem_v1_Filesystem_Probe_reply(c, q, &v) == 0);
}

static int
run_server(int fd)
{
	struct bsd_filesystem_v1_Filesystem_server handlers = {
		.GetProtocolInfo = serve_info,
		.List = serve_list,
		.Open = serve_open,
		.Probe = serve_probe
	};
	struct fidl_bsd_connection *c;

	/* Methods left NULL fail with ENOSYS in the bindings. */
	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &c) == 0);
	CHECK(bsd_filesystem_v1_Filesystem_bind(c, &handlers, NULL) == 0);
	while (fidl_bsd_connection_poll(c, 10000) == 0)
		;
	fidl_bsd_connection_destroy(c);
	/* The bsd:1 client used List and Open. */
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

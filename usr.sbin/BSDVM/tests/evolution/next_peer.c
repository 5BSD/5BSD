/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.VM peer built from evolution/vmcmp_next.fidl at bsd:2 (one method
 * more than the production bsd:1 schema).  evolution_test pairs it with the
 * real bsd:1 client and provider:
 *
 *   next_peer serve FD   serve bsd:2 on FD; exit 0 once the peer leaves
 *   next_peer call FD    as a bsd:2 client: negotiate, use List, then call
 *                        the added method, which a bsd:1 provider must
 *                        refuse by closing the session (strict method)
 */
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.vm.v1/c/bsd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The host-local CID and the first window (bsdvm_proto.h). */
#define PEER_CID	1u
#define PEER_BASE	0x40000000u

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
info_reply(void *p, int error, struct bsd_vm_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}
static void
list_reply(void *p, int error, struct bsd_vm_v1_VM_List_Result *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->tag == bsd_vm_v1_VM_List_Result_response_tag ?
		    v->value.response.port_count : UINT32_MAX;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { 0 };
	uint32_t txid;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &c) == 0);
	CHECK(bsd_vm_v1_VM_GetProtocolInfo(c, &empty, info_reply, &r,
	    &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 1);
	r = (struct result){ 0 };
	CHECK(bsd_vm_v1_VM_List(c, &empty, list_reply, &r, &txid) == 0);
	pump(c, &r);
	CHECK(r.error == 0 && r.value == 16);
	/* The added strict method is unknown to a bsd:1 provider. */
	r = (struct result){ 0 };
	CHECK(bsd_vm_v1_VM_Probe(c, &empty, info_reply, &r, &txid) == 0);
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
	struct bsd_vm_v1_ProtocolInfo v = { 1 };
	(void)x;
	(void)e;
	CHECK(bsd_vm_v1_VM_GetProtocolInfo_reply(c, q, &v) == 0);
}
static void
serve_bind(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct bsd_vm_v1_BindRequest *e)
{
	struct bsd_vm_v1_VM_Bind_Result v = {
		.tag = bsd_vm_v1_VM_Bind_Result_response_tag
	};
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	++*(unsigned *)x;
	v.value.response.listener = fd;
	v.value.response.cid = PEER_CID;
	v.value.response.port = PEER_BASE + e->index;
	CHECK(bsd_vm_v1_VM_Bind_reply(c, q, &v) == 0);
	close(fd);
}
static void
serve_connect(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *q, struct bsd_vm_v1_ConnectRequest *e)
{
	struct bsd_vm_v1_VM_Connect_Result v = {
		.tag = bsd_vm_v1_VM_Connect_Result_err_tag,
		.value.err = ECONNREFUSED
	};
	(void)x;
	(void)e;
	CHECK(bsd_vm_v1_VM_Connect_reply(c, q, &v) == 0);
}
static void
serve_list(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_vm_v1_VM_List_Result v = {
		.tag = bsd_vm_v1_VM_List_Result_response_tag
	};
	(void)e;
	++*(unsigned *)x;
	v.value.response.cid = PEER_CID;
	v.value.response.port_base = PEER_BASE;
	v.value.response.port_limit = PEER_BASE + 16;
	v.value.response.port_count = 16;
	CHECK(bsd_vm_v1_VM_List_reply(c, q, &v) == 0);
}
static void
serve_probe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *q,
    struct fidl_bsd_empty *e)
{
	struct bsd_vm_v1_ProtocolInfo v = { 2 };
	(void)x;
	(void)e;
	CHECK(bsd_vm_v1_VM_Probe_reply(c, q, &v) == 0);
}

static int
run_server(int fd)
{
	struct bsd_vm_v1_VM_server handlers = {
		.GetProtocolInfo = serve_info,
		.Bind = serve_bind,
		.Connect = serve_connect,
		.List = serve_list,
		.Probe = serve_probe
	};
	struct fidl_bsd_connection *c;
	unsigned served = 0;

	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &c) == 0);
	CHECK(bsd_vm_v1_VM_bind(c, &handlers, &served) == 0);
	while (fidl_bsd_connection_poll(c, 10000) == 0)
		;
	fidl_bsd_connection_destroy(c);
	/* The bsd:1 client used Bind and List. */
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

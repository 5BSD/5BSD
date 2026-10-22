/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Schema evolution peer. Built once against bsd:1 and once against bsd:2
 * of evolution.fidl. "peer launch ROLE OTHER" creates a channel,
 * runs OTHER with the opposite role on descriptor 3, and runs ROLE locally.
 */
#include <sys/wait.h>

#include <channel.h>
#include <errno.h>
#include <fidl/bsd.evolution/c/bsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef EVOLVE_VERSION
#error EVOLVE_VERSION must be 1 or 2
#endif

#define CHECK(x)                                                         \
	do {                                                             \
		if (!(x)) {                                              \
			fprintf(stderr, "evolution v%d %s: %d: %s\n",    \
			    EVOLVE_VERSION, role, __LINE__, #x);         \
			exit(1);                                         \
		}                                                        \
	} while (0)

static const char *role = "?";

struct state {
	unsigned exchanges, unknown_methods, unknown_events, announced;
	unsigned added_errors, replies;
	int done;
};

static void
pump(struct fidl_bsd_connection *c, int *done, int target)
{
	for (int i = 0; i < 2000 && *done < target; ++i) {
		int error = fidl_bsd_connection_poll(c, 10);
		CHECK(error == 0 || error == ETIMEDOUT || error == EAGAIN);
	}
	CHECK(*done >= target);
}

/* What a peer built at this version must observe from a newer peer. */
static void
check_from_newer(const struct bsd_evolution_Payload *p)
{
	CHECK(p->record.has_name && p->record.name_size == 3);
	CHECK(memcmp(p->record.name, "new", 3) == 0);
	/* Unknown table fields are dropped; unknown union variants surface. */
	CHECK(p->shape.tag == bsd_evolution_Shape_unknown_tag);
	/* Flexible enum and bits values pass through unchanged. */
	CHECK(p->color == 2);
	CHECK(p->perms == 3);
}

static void
check_from_older(const struct bsd_evolution_Payload *p, bool echoed)
{
	CHECK(p->record.has_name && p->record.name_size == 3);
	CHECK(memcmp(p->record.name, "old", 3) == 0);
#if EVOLVE_VERSION >= 2
	CHECK(!p->record.has_extra && !p->record.has_tint);
#endif
	CHECK(p->shape.tag == bsd_evolution_Shape_circle_tag);
	CHECK(p->shape.value.circle == 4);
	if (echoed) {
		/* An older server returned values it does not know. */
		CHECK(p->color == 2 && p->perms == 3);
	} else {
		CHECK(p->color == bsd_evolution_Color_RED);
		CHECK(p->perms == bsd_evolution_Perms_READ);
	}
}

static void
fill(struct bsd_evolution_Payload *p)
{
	memset(p, 0, sizeof(*p));
	p->record.has_name = true;
#if EVOLVE_VERSION >= 2
	p->record.name = "new";
	p->record.name_size = 3;
	p->record.has_extra = true;
	p->record.extra = 7;
	p->record.has_tint = true;
	p->record.tint = bsd_evolution_Color_GREEN;
	p->shape.tag = bsd_evolution_Shape_square_tag;
	p->shape.value.square = UINT64_C(1) << 40;
	p->color = bsd_evolution_Color_GREEN;
	p->perms = bsd_evolution_Perms_READ | bsd_evolution_Perms_WRITE;
#else
	p->record.name = "old";
	p->record.name_size = 3;
	p->shape.tag = bsd_evolution_Shape_circle_tag;
	p->shape.value.circle = 4;
	p->color = bsd_evolution_Color_RED;
	p->perms = bsd_evolution_Perms_READ;
#endif
}

static int peer_version;

static void
check_received(const struct bsd_evolution_Payload *p, bool reply)
{
	if (peer_version > EVOLVE_VERSION)
		check_from_newer(p);
	else if (peer_version < EVOLVE_VERSION)
		check_from_older(p, reply);
	else {
		struct bsd_evolution_Payload expected;
		fill(&expected);
		CHECK(p->shape.tag == expected.shape.tag);
		CHECK(p->color == expected.color && p->perms == expected.perms);
	}
}

static void
server_exchange(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_evolution_Payload *value)
{
	struct state *state = context;
	struct bsd_evolution_Payload reply;
	check_received(value, false);
	fill(&reply);
#if EVOLVE_VERSION >= 2
	/* A newer server may announce new events to any client. */
	CHECK(bsd_evolution_Evolve_Announced(connection, &reply) == 0);
#endif
	if (peer_version > EVOLVE_VERSION) {
		/* Values unknown to this schema can still be returned. */
		reply.color = value->color;
		reply.perms = value->perms;
	}
	CHECK(bsd_evolution_Evolve_Exchange_reply(connection, request,
		  &reply) == 0);
	++state->exchanges;
}

#if EVOLVE_VERSION >= 2
static void
server_added(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value)
{
	(void)context;
	(void)value;
	struct bsd_evolution_Evolve_Added_Result result = {
		.tag = bsd_evolution_Evolve_Added_Result_response_tag
	};
	CHECK(bsd_evolution_Evolve_Added_reply(connection, request, &result) ==
	    0);
}
#endif

static void
server_unknown(void *context, uint64_t ordinal, bool two_way)
{
	struct state *state = context;
	(void)ordinal;
	CHECK(two_way);
	++state->unknown_methods;
}

static int
run_server(int fd)
{
	struct fidl_bsd_connection *server;
	struct state state = { 0 };
	struct bsd_evolution_Evolve_server handlers = {
		.Exchange = server_exchange,
#if EVOLVE_VERSION >= 2
		.Added = server_added,
#endif
		.unknown_interaction = server_unknown,
	};
	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &server) == 0);
	CHECK(bsd_evolution_Evolve_bind(server, &handlers, &state) == 0);
	for (int i = 0; i < 2000; ++i) {
		int error = fidl_bsd_connection_poll(server, 10);
		if (error != 0 && error != ETIMEDOUT && error != EAGAIN)
			break;
	}
	CHECK(state.exchanges == 2);
	/* An older server answers a newer client's added method generically. */
	CHECK(state.unknown_methods == (peer_version > EVOLVE_VERSION ? 1 : 0));
	fidl_bsd_connection_destroy(server);
	return 0;
}

static struct state client_state;

static void
client_exchanged(void *context, int error, struct bsd_evolution_Payload *value)
{
	struct state *state = context;
	CHECK(error == 0 && value);
	check_received(value, true);
	++state->replies;
	++state->done;
}

#if EVOLVE_VERSION >= 2
static void
client_added(void *context, int error,
    struct bsd_evolution_Evolve_Added_Result *result)
{
	struct state *state = context;
	if (peer_version < EVOLVE_VERSION) {
		/* Unknown flexible method: nonterminal framework error. */
		CHECK(error == EOPNOTSUPP ||
		    (error == 0 && result &&
			result->tag ==
			    bsd_evolution_Evolve_Added_Result_framework_err_tag));
		++state->added_errors;
	} else {
		CHECK(error == 0 && result &&
		    result->tag ==
			bsd_evolution_Evolve_Added_Result_response_tag);
	}
	++state->done;
}

static void
client_announced(void *context, struct bsd_evolution_Payload *value)
{
	struct state *state = context;
	check_received(value, false);
	++state->announced;
}
#endif

static void
client_unknown_event(void *context, uint64_t ordinal)
{
	struct state *state = context;
	(void)ordinal;
	++state->unknown_events;
}

static int
run_client(int fd)
{
	struct fidl_bsd_connection *client;
	struct state *state = &client_state;
	struct bsd_evolution_Payload request;
	uint32_t txid;
	struct bsd_evolution_Evolve_events events = {
#if EVOLVE_VERSION >= 2
		.Announced = client_announced,
#endif
		.unknown_interaction = client_unknown_event,
	};
	CHECK(fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT, &client) == 0);
	CHECK(bsd_evolution_Evolve_bind_events(client, &events, state) == 0);
	fill(&request);
	CHECK(bsd_evolution_Evolve_Exchange(client, &request, client_exchanged,
		  state, &txid) == 0);
	pump(client, &state->done, 1);
#if EVOLVE_VERSION >= 2
	struct fidl_bsd_empty empty = { 0 };
	CHECK(bsd_evolution_Evolve_Added(client, &empty, client_added, state,
		  &txid) == 0);
	pump(client, &state->done, 2);
#endif
	/* The connection remains usable after every evolution path. */
	CHECK(bsd_evolution_Evolve_Exchange(client, &request, client_exchanged,
		  state, &txid) == 0);
	pump(client, &state->done, EVOLVE_VERSION >= 2 ? 3 : 2);
	/* Drain events sent with the second reply. */
	for (int i = 0; i < 5; ++i)
		(void)fidl_bsd_connection_poll(client, 10);
	CHECK(state->replies == 2);
	CHECK(fidl_bsd_connection_error(client) == 0);
	if (peer_version > EVOLVE_VERSION)
		CHECK(state->unknown_events == 2);
	else
		CHECK(state->unknown_events == 0);
#if EVOLVE_VERSION >= 2
	CHECK(state->announced == (peer_version >= 2 ? 2 : 0));
	CHECK(state->added_errors == (peer_version < EVOLVE_VERSION ? 1 : 0));
#endif
	fidl_bsd_connection_destroy(client);
	return 0;
}

int
main(int argc, char **argv)
{
	alarm(60);
	if (argc == 4 && strcmp(argv[1], "serve") == 0) {
		role = "server";
		peer_version = atoi(argv[3]);
		return run_server(atoi(argv[2]));
	}
	if (argc == 4 && strcmp(argv[1], "call") == 0) {
		role = "client";
		peer_version = atoi(argv[3]);
		return run_client(atoi(argv[2]));
	}
	if (argc != 5 || strcmp(argv[1], "launch") != 0) {
		fprintf(stderr,
		    "usage: peer launch serve|call OTHER OTHER_VERSION\n");
		return 2;
	}
	int ends[2], status;
	char version[16];
	snprintf(version, sizeof(version), "%d", EVOLVE_VERSION);
	peer_version = atoi(argv[4]);
	if (mac_capability_channel_create(ends) != 0) {
		perror("mac_capability_channel_create");
		return 1;
	}
	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		close(ends[0]);
		if (dup2(ends[1], 3) < 0)
			_exit(126);
		const char *other = strcmp(argv[2], "serve") == 0 ? "call" :
								     "serve";
		execl(argv[3], argv[3], other, "3", version, (char *)NULL);
		_exit(127);
	}
	close(ends[1]);
	int result;
	if (strcmp(argv[2], "serve") == 0) {
		role = "server";
		result = run_server(ends[0]);
	} else {
		role = "client";
		result = run_client(ends[0]);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		fprintf(stderr, "evolution peer exited with status %d\n",
		    status);
		return 1;
	}
	return result;
}

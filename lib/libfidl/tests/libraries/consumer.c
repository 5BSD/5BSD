/* SPDX-License-Identifier: BSD-2-Clause */
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/cross.app/c/bsd.h>
#include <fidl/cross.shared/c/bsd.h>
#include <fidl/cross.types/c/bsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                               \
	do {                                                                   \
		if (!(x)) {                                                    \
			fprintf(stderr, "cross-library C: %d: %s\n", __LINE__, \
			    #x);                                               \
			exit(1);                                               \
		}                                                              \
	} while (0)
struct state {
	unsigned successes, failures;
	int taken;
};
static void
check_payload(struct cross_types_Payload *value)
{
	CHECK(value->fd >= 0 && value->mode == cross_types_Mode_ON);
	CHECK(value->words_size == 1 && value->words[0].data_size == 3);
	CHECK(memcmp(value->words[0].data, "tag", 3) == 0);
}
static void
exchange(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct cross_shared_Envelope *value)
{
	(void)context;
	check_payload(&value->value);
	struct cross_shared_Base_Exchange_Result result = { 0 };
	if (value->value.label_size) {
		result.tag = cross_shared_Base_Exchange_Result_response_tag;
		result.value.response = *value;
	} else {
		result.tag = cross_shared_Base_Exchange_Result_err_tag;
		result.value.err = 42;
	}
	CHECK(cross_shared_Base_Exchange_reply(connection, request, &result) ==
	    0);
}
static void
exchanged(void *context, int error,
    struct cross_shared_Base_Exchange_Result *result)
{
	struct state *state = context;
	CHECK(error == 0 && result);
	if (result->tag == cross_shared_Base_Exchange_Result_err_tag) {
		CHECK(result->value.err == 42);
		++state->failures;
	} else {
		CHECK(result->tag ==
		    cross_shared_Base_Exchange_Result_response_tag);
		check_payload(&result->value.response.value);
		state->taken = fidl_bsd_take_fd(
		    &result->value.response.value.fd);
		++state->successes;
	}
}
static void
echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct cross_types_Payload *value)
{
	(void)context;
	check_payload(value);
	CHECK(cross_app_App_Echo_reply(connection, request, value) == 0);
}
static void
echoed(void *context, int error, struct cross_types_Payload *value)
{
	struct state *state = context;
	CHECK(error == 0 && value);
	check_payload(value);
	state->taken = fidl_bsd_take_fd(&value->fd);
	++state->successes;
}
static void
pump(struct fidl_bsd_connection *client, struct fidl_bsd_connection *server)
{
	for (unsigned i = 0; i < 4; ++i) {
		fidl_bsd_connection_poll(server, 2);
		fidl_bsd_connection_poll(client, 2);
	}
}
int
main(void)
{
	int ends[2], pipefd[2];
	uint32_t txid;
	struct fidl_bsd_connection *client, *server;
	struct state state = { .taken = -1 };
	alarm(20);
	CHECK(mac_capability_channel_create(ends) == 0);
	CHECK(pipe(pipefd) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT, &client) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER, &server) == 0);
	struct cross_shared_Base_server base = { .Exchange = exchange };
	CHECK(cross_shared_Base_bind(server, &base, NULL) == 0);
	struct cross_types_fidl_string words[] = { { .data = "tag",
	    .data_size = 3 } };
	struct cross_shared_Envelope request = {
		.value = { .fd = pipefd[1],
		    .label = "value",
		    .label_size = 5,
		    .words = words,
		    .words_size = 1,
		    .mode = cross_types_Mode_ON }
	};
	/* A composed client must interoperate with the original base protocol.
	 */
	CHECK(cross_app_App_Exchange(client, &request, exchanged, &state,
		  &txid) == 0);
	pump(client, server);
	CHECK(state.successes == 1 && state.taken >= 0);
	CHECK(write(state.taken, "x", 1) == 1);
	char byte;
	CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'x');
	close(state.taken);
	request.value.label_size = 0;
	CHECK(cross_app_App_Exchange(client, &request, exchanged, &state,
		  &txid) == 0);
	pump(client, server);
	CHECK(state.failures == 1);
	struct cross_app_App_server app = { .Exchange = exchange,
		.Echo = echo };
	CHECK(cross_app_App_bind(server, &app, NULL) == 0);
	CHECK(cross_app_App_Echo(client, &request.value, echoed, &state,
		  &txid) == 0);
	pump(client, server);
	CHECK(state.successes == 2);
	close(state.taken);
	close(pipefd[1]);
	CHECK(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == 0);
	CHECK(read(pipefd[0], &byte, 1) == 0);
	close(pipefd[0]);
	fidl_bsd_connection_destroy(client);
	fidl_bsd_connection_destroy(server);
	puts(
	    "Cross-library C: composed protocol, imported resource/collection/enum, application results, descriptor cleanup: PASS");
	return 0;
}

/* SPDX-License-Identifier: BSD-2-Clause */
/* This translation unit must compile as ISO C, not C++. */
#include <sys/capsicum.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.runtime.test/c/bsd.h>
#include <fidl/bsd/runtime_c.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x)                                                               \
	do {                                                                   \
		if (!(x)) {                                                    \
			fprintf(stderr, "C binding check failed: %s:%d: %s\n", \
			    __FILE__, __LINE__, #x);                           \
			exit(1);                                               \
		}                                                              \
	} while (0)
struct state {
	unsigned replies, errors, notifications, events;
	int defer, taken_fd;
	struct fidl_bsd_request *held;
};
static void
response(void *context, int error, struct bsd_runtime_test_Response *value)
{
	struct state *s = context;
	if (error) {
		++s->errors;
		CHECK(value == NULL);
		return;
	}
	CHECK(value != NULL);
	CHECK(value->text_size == 1 && value->text[0] == 'C');
	++s->replies;
}
static void
round_trip(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	struct state *s = context;
	CHECK(fidl_bsd_request_native(request) != NULL);
	if (s->defer) {
		fidl_bsd_request_retain(request);
		s->held = request;
		return;
	}
	struct bsd_runtime_test_Response r = { value->text, value->text_size };
	CHECK(bsd_runtime_test_Service_RoundTrip_reply(connection, request,
		  &r) == 0);
	CHECK(bsd_runtime_test_Service_RoundTrip_reply(connection, request,
		  &r) == EALREADY);
}
static void
take(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_ReadOnly *value)
{
	struct state *s = context;
	cap_rights_t rights;
	char c;
	CHECK(cap_rights_get(value->fd, &rights) == 0);
	CHECK(cap_rights_is_set(&rights, CAP_READ));
	CHECK(!cap_rights_is_set(&rights, CAP_WRITE));
	s->taken_fd = fidl_bsd_take_fd(&value->fd);
	CHECK(value->fd == -1);
	CHECK(read(s->taken_fd, &c, 1) == 1 && c == 'C');
	struct bsd_runtime_test_Response r = { &c, 1 };
	CHECK(
	    bsd_runtime_test_Service_Take_reply(connection, request, &r) == 0);
}
static void
notify(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	struct state *s = context;
	(void)connection;
	(void)request;
	CHECK(value->text_size == 1);
	++s->notifications;
}
static void
changed(void *context, struct bsd_runtime_test_Response *value)
{
	struct state *s = context;
	CHECK(value->text_size == 1 && value->text[0] == 'C');
	++s->events;
}
static void
pump(struct fidl_bsd_connection *client, struct fidl_bsd_connection *server)
{
	for (int i = 0; i < 8; ++i) {
		fidl_bsd_connection_poll(server, 2);
		fidl_bsd_connection_poll(client, 2);
	}
}

static void
ping(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value)
{
	(void)context;
	CHECK(bsd_runtime_test_Shapes_Ping_reply(connection, request, value) ==
	    0);
}
static void
ping_reply(void *context, int error, struct fidl_bsd_empty *value)
{
	CHECK(error == 0 && value != NULL);
	++*(int *)context;
}
static void
shape_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_runtime_test_ShapesEchoRequest *value)
{
	(void)context;
	struct bsd_runtime_test_ShapesEchoResponse response = { value->value };
	CHECK(bsd_runtime_test_Shapes_Echo_reply(connection, request,
		  &response) == 0);
}
static void
shape_reply(void *context, int error,
    struct bsd_runtime_test_ShapesEchoResponse *value)
{
	CHECK(error == 0 && value != NULL && value->value == 42);
	++*(int *)context;
}

static void
endpoint_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_runtime_test_EndpointRequest *value)
{
	(void)context;
	CHECK(bsd_runtime_test_EndpointExchange_RoundTrip_reply(connection,
		  request, value) == 0);
}
static void
endpoint_reply(void *context, int error,
    struct bsd_runtime_test_EndpointRequest *value)
{
	CHECK(error == 0 && value != NULL);
	*(int *)context = fidl_bsd_take_fd(&value->ep);
}
static void
names_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_runtime_test_EscapedNames *value)
{
	(void)context;
	CHECK(value->switch_fidl == 11 && value->text_size == 22 &&
	    value->UpperCase == 33);
	CHECK(value->text_fidl_size == 4 &&
	    memcmp(value->text_fidl, "name", 4) == 0);
	CHECK(bsd_runtime_test_Naming_RoundTrip_reply(connection, request,
		  value) == 0);
}
static void
names_reply(void *context, int error,
    struct bsd_runtime_test_EscapedNames *value)
{
	CHECK(error == 0 && value != NULL);
	CHECK(value->switch_fidl == 11 && value->text_size == 22 &&
	    value->UpperCase == 33);
	CHECK(value->text_fidl_size == 4 &&
	    memcmp(value->text_fidl, "name", 4) == 0);
	++*(int *)context;
}
struct collection_state {
	unsigned replies, configurations, successes, failures;
	int taken;
	bool optional_variant;
};
static void
collection_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Collection *value)
{
	struct collection_state *state = context;
	CHECK(value->entries_size == 2);
	CHECK(value->entries[0].key_size == 3 &&
	    memcmp(value->entries[0].key, "one", 3) == 0);
	CHECK(value->entries[1].value_size == 5 &&
	    memcmp(value->entries[1].value, "value", 5) == 0);
	CHECK(value->numbers[2] == 9 && value->switches_size == 3);
	CHECK(value->switches[0] && !value->switches[1] && value->switches[2]);
	CHECK(value->label_present == !state->optional_variant &&
	    value->label_size == 0);
	CHECK(value->optional_numbers_present == state->optional_variant &&
	    value->optional_numbers_size == 0);
	CHECK(value->chain && value->chain->value == 10 && value->chain->next);
	CHECK(value->chain->next->value == 20 && !value->chain->next->next);
	CHECK(value->mode == bsd_runtime_test_Mode_ON);
	CHECK(value->features ==
	    (bsd_runtime_test_Features_FIRST |
		bsd_runtime_test_Features_SECOND));
	CHECK(bsd_runtime_test_Collections_Echo_reply(connection, request,
		  value) == 0);
}
static void
collection_reply(void *context, int error,
    struct bsd_runtime_test_Collection *value)
{
	struct collection_state *state = context;
	CHECK(error == 0 && value != NULL);
	CHECK(value->entries_size == 2 && value->entries[0].key_size == 3);
	CHECK(value->chain->next->value == 20 &&
	    value->label_present == !state->optional_variant);
	CHECK(value->descriptors_size == 1);
	state->taken = fidl_bsd_take_fd(&value->descriptors[0]);
	CHECK(state->taken >= 0);
	/* Cleanup tracks the original slots, even if a callback changes its
	 * view. */
	value->descriptors = NULL;
	value->descriptors_size = 0;
	++state->replies;
}
static void
configuration_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_runtime_test_Configuration *value)
{
	(void)context;
	CHECK(value->has_selection && !value->has_label);
	CHECK(value->selection.tag == bsd_runtime_test_Selection_entry_tag);
	CHECK(value->selection.value.entry.key_size == 3);
	CHECK(bsd_runtime_test_Collections_Configure_reply(connection, request,
		  value) == 0);
}
static void
configuration_reply(void *context, int error,
    struct bsd_runtime_test_Configuration *value)
{
	struct collection_state *state = context;
	CHECK(error == 0 && value && value->has_selection && !value->has_label);
	CHECK(value->selection.tag == bsd_runtime_test_Selection_entry_tag);
	CHECK(value->selection.value.entry.value_size == 5);
	++state->configurations;
}
static void
collection_check(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	(void)context;
	struct bsd_runtime_test_Collections_Check_Result result = { 0 };
	if (value->text_size) {
		result.tag =
		    bsd_runtime_test_Collections_Check_Result_response_tag;
		result.value.response.text = value->text;
		result.value.response.text_size = value->text_size;
	} else {
		result.tag = bsd_runtime_test_Collections_Check_Result_err_tag;
		result.value.err = 42;
	}
	CHECK(bsd_runtime_test_Collections_Check_reply(connection, request,
		  &result) == 0);
}
static void
collection_checked(void *context, int error,
    struct bsd_runtime_test_Collections_Check_Result *value)
{
	struct collection_state *state = context;
	CHECK(error == 0 && value);
	if (value->tag ==
	    bsd_runtime_test_Collections_Check_Result_response_tag) {
		CHECK(value->value.response.text_size == 1);
		++state->successes;
	} else {
		CHECK(value->tag ==
		    bsd_runtime_test_Collections_Check_Result_err_tag);
		CHECK(value->value.err == 42);
		++state->failures;
	}
}
static void
test_collections(void)
{
	int ends[2], fds[2];
	uint32_t txid;
	struct fidl_bsd_connection *client, *server;
	struct collection_state state = { .taken = -1 };
	CHECK(mac_capability_channel_create(ends) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT, &client) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER, &server) == 0);
	struct bsd_runtime_test_Collections_server handlers = {
		.Echo = collection_echo,
		.Configure = configuration_echo,
		.Check = collection_check
	};
	CHECK(
	    bsd_runtime_test_Collections_bind(server, &handlers, &state) == 0);
	struct bsd_runtime_test_DictionaryEntry entries[] = {
		{ .key = "one",
		    .key_size = 3,
		    .value = "first",
		    .value_size = 5 },
		{ .key = "two",
		    .key_size = 3,
		    .value = "value",
		    .value_size = 5 }
	};
	struct bsd_runtime_test_Linked tail = { .value = 20 };
	struct bsd_runtime_test_Linked head = { .value = 10, .next = &tail };
	bool switches[] = { true, false, true };
	CHECK(pipe(fds) == 0);
	struct bsd_runtime_test_Collection value = { .entries = entries,
		.entries_size = 2,
		.numbers = { 1, 4, 9 },
		.switches = switches,
		.switches_size = 3,
		.label_present = true,
		.chain = &head,
		.descriptors = &fds[1],
		.descriptors_size = 1,
		.mode = bsd_runtime_test_Mode_ON,
		.features = bsd_runtime_test_Features_FIRST |
		    bsd_runtime_test_Features_SECOND };
	/* Invalid lengths and cyclic C input must fail before any delivery. */
	value.entries_size = 5;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == EINVAL);
	CHECK(txid == 0);
	value.entries_size = 2;
	tail.next = &head;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == EINVAL);
	tail.next = NULL;
	value.optional_numbers_size = 1;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == EINVAL);
	value.optional_numbers_size = 0;
	value.mode = 99;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == EINVAL);
	value.mode = bsd_runtime_test_Mode_ON;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == 0);
	pump(client, server);
	CHECK(state.replies == 1 && state.taken >= 0);
	CHECK(write(state.taken, "v", 1) == 1);
	char byte;
	CHECK(read(fds[0], &byte, 1) == 1 && byte == 'v');
	close(state.taken);
	state.optional_variant = true;
	value.label_present = false;
	value.optional_numbers_present = true;
	CHECK(bsd_runtime_test_Collections_Echo(client, &value,
		  collection_reply, &state, &txid) == 0);
	pump(client, server);
	CHECK(state.replies == 2 && state.taken >= 0);
	close(state.taken);
	close(fds[1]);
	CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	CHECK(read(fds[0], &byte, 1) ==
	    0); /* Every callback duplicate was closed. */
	close(fds[0]);
	struct bsd_runtime_test_Configuration config = { .has_selection = true,
		.selection = { .tag = bsd_runtime_test_Selection_entry_tag,
		    .value.entry = entries[1] } };
	CHECK(bsd_runtime_test_Collections_Configure(client, &config,
		  configuration_reply, &state, &txid) == 0);
	pump(client, server);
	CHECK(state.configurations == 1);
	config.selection.tag = bsd_runtime_test_Selection_unknown_tag;
	CHECK(bsd_runtime_test_Collections_Configure(client, &config,
		  configuration_reply, &state, &txid) == EINVAL);
	struct bsd_runtime_test_Request request = { .text = "x",
		.text_size = 1 };
	CHECK(bsd_runtime_test_Collections_Check(client, &request,
		  collection_checked, &state, &txid) == 0);
	pump(client, server);
	request.text_size = 0;
	CHECK(bsd_runtime_test_Collections_Check(client, &request,
		  collection_checked, &state, &txid) == 0);
	pump(client, server);
	CHECK(state.successes == 1 && state.failures == 1);
	fidl_bsd_connection_destroy(client);
	fidl_bsd_connection_destroy(server);
}

struct flexible_state {
	unsigned replies, application_errors, unsupported, notes, events;
	unsigned unknown_one_way, unknown_two_way, unknown_events;
};
static void
flexible_ping(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value)
{
	(void)context;
	(void)value;
	struct bsd_runtime_test_Flexible_Ping_Result result = {
		.tag = bsd_runtime_test_Flexible_Ping_Result_response_tag
	};
	CHECK(bsd_runtime_test_Flexible_Ping_reply(connection, request,
		  &result) == 0);
}
static void
flexible_ping_response(void *context, int error,
    struct bsd_runtime_test_Flexible_Ping_Result *value)
{
	struct flexible_state *s = context;
	CHECK(error == 0 && value != NULL);
	CHECK(value->tag == bsd_runtime_test_Flexible_Ping_Result_response_tag);
	++s->replies;
}
static void
flexible_echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	(void)context;
	struct bsd_runtime_test_Flexible_Echo_Result result = {
		.tag = bsd_runtime_test_Flexible_Echo_Result_response_tag,
		.value.response = { value->text, value->text_size }
	};
	CHECK(bsd_runtime_test_Flexible_Echo_reply(connection, request,
		  &result) == 0);
}
static void
flexible_echo_response(void *context, int error,
    struct bsd_runtime_test_Flexible_Echo_Result *value)
{
	struct flexible_state *s = context;
	if (error) {
		CHECK(error == EOPNOTSUPP && value == NULL);
		++s->unsupported;
		return;
	}
	CHECK(value != NULL);
	CHECK(value->tag == bsd_runtime_test_Flexible_Echo_Result_response_tag);
	CHECK(value->value.response.text_size == 1 &&
	    value->value.response.text[0] == 'C');
	++s->replies;
}
static void
flexible_check(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	(void)context;
	struct bsd_runtime_test_Flexible_Check_Result result = { 0 };
	if (value->text_size) {
		result.tag =
		    bsd_runtime_test_Flexible_Check_Result_response_tag;
		result.value.response = (struct bsd_runtime_test_Response) {
			value->text, value->text_size
		};
	} else {
		result.tag = bsd_runtime_test_Flexible_Check_Result_err_tag;
		result.value.err = 42;
	}
	CHECK(bsd_runtime_test_Flexible_Check_reply(connection, request,
		  &result) == 0);
}
static void
flexible_check_response(void *context, int error,
    struct bsd_runtime_test_Flexible_Check_Result *value)
{
	struct flexible_state *s = context;
	CHECK(error == 0 && value != NULL);
	if (value->tag == bsd_runtime_test_Flexible_Check_Result_err_tag) {
		CHECK(value->value.err == 42);
		++s->application_errors;
	} else {
		CHECK(value->tag ==
		    bsd_runtime_test_Flexible_Check_Result_response_tag);
		CHECK(value->value.response.text_size == 1 &&
		    value->value.response.text[0] == 'C');
		++s->replies;
	}
}
static void
flexible_note(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	struct flexible_state *s = context;
	(void)connection;
	(void)request;
	CHECK(value->text_size == 1 && value->text[0] == 'C');
	++s->notes;
}
static void
flexible_strict_ping(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *value)
{
	(void)context;
	CHECK(bsd_runtime_test_Flexible_StrictPing_reply(connection, request,
		  value) == 0);
}
static void
flexible_strict_response(void *context, int error, struct fidl_bsd_empty *value)
{
	struct flexible_state *s = context;
	CHECK(error == 0 && value != NULL);
	++s->replies;
}
static void
flexible_changed(void *context, struct bsd_runtime_test_Response *value)
{
	struct flexible_state *s = context;
	CHECK(value->text_size == 1 && value->text[0] == 'C');
	++s->events;
}
static void
flexible_unknown(void *context, uint64_t ordinal, bool two_way)
{
	struct flexible_state *s = context;
	CHECK(ordinal != 0);
	if (two_way)
		++s->unknown_two_way;
	else
		++s->unknown_one_way;
}
static void
flexible_unknown_event(void *context, uint64_t ordinal)
{
	struct flexible_state *s = context;
	CHECK(ordinal != 0);
	++s->unknown_events;
}
static void
test_flexible(void)
{
	int ends[2];
	uint32_t txid;
	struct fidl_bsd_connection *client, *server;
	struct flexible_state state = { 0 };
	CHECK(mac_capability_channel_create(ends) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT, &client) == 0);
	CHECK(
	    fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER, &server) == 0);
	struct bsd_runtime_test_Flexible_server handlers = {
		.Ping = flexible_ping,
		.Echo = flexible_echo,
		.Check = flexible_check,
		.Note = flexible_note,
		.StrictPing = flexible_strict_ping
	};
	CHECK(bsd_runtime_test_Flexible_bind(server, &handlers, &state) == 0);
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_runtime_test_Request request = { "C", 1 };
	struct bsd_runtime_test_Response event = { "C", 1 };
	CHECK(bsd_runtime_test_Flexible_Ping(client, &empty,
		  flexible_ping_response, &state, &txid) == 0);
	CHECK(bsd_runtime_test_Flexible_Echo(client, &request,
		  flexible_echo_response, &state, &txid) == 0);
	CHECK(bsd_runtime_test_Flexible_Check(client, &request,
		  flexible_check_response, &state, &txid) == 0);
	request.text_size = 0;
	CHECK(bsd_runtime_test_Flexible_Check(client, &request,
		  flexible_check_response, &state, &txid) == 0);
	request.text_size = 1;
	CHECK(bsd_runtime_test_Flexible_StrictPing(client, &empty,
		  flexible_strict_response, &state, &txid) == 0);
	CHECK(bsd_runtime_test_Flexible_Note(client, &request) == 0);
	// No event handler: decode and discard a known event without closing.
	CHECK(bsd_runtime_test_Flexible_Changed(server, &event) == 0);
	pump(client, server);
	CHECK(state.replies == 4 && state.application_errors == 1 &&
	    state.notes == 1);
	CHECK(state.events == 0 && fidl_bsd_connection_error(client) == 0);
	struct bsd_runtime_test_Flexible_events events = {
		.Changed = flexible_changed
	};
	CHECK(bsd_runtime_test_Flexible_bind_events(client, &events, &state) ==
	    0);
	CHECK(bsd_runtime_test_Flexible_Changed(server, &event) == 0);
	pump(client, server);
	CHECK(state.events == 1);
	// Model an older server which has none of the client's methods.
	struct bsd_runtime_test_OpenSurface_server older = {
		.unknown_interaction = flexible_unknown
	};
	CHECK(bsd_runtime_test_OpenSurface_bind(server, &older, &state) == 0);
	for (unsigned i = 0; i < 2; ++i) {
		CHECK(bsd_runtime_test_Flexible_Echo(client, &request,
			  flexible_echo_response, &state, &txid) == 0);
		CHECK(bsd_runtime_test_Flexible_Note(client, &request) == 0);
		pump(client, server);
		CHECK(state.unsupported == i + 1);
		CHECK(state.unknown_two_way == i + 1 &&
		    state.unknown_one_way == i + 1);
		CHECK(fidl_bsd_connection_error(client) == 0 &&
		    fidl_bsd_connection_error(server) == 0);
	}
	struct bsd_runtime_test_OpenSurface_events older_events = {
		.unknown_interaction = flexible_unknown_event
	};
	CHECK(bsd_runtime_test_OpenSurface_bind_events(client, &older_events,
		  &state) == 0);
	CHECK(bsd_runtime_test_Flexible_Changed(server, &event) == 0);
	pump(client, server);
	CHECK(state.unknown_events == 1 &&
	    fidl_bsd_connection_error(client) == 0);
	fidl_bsd_connection_destroy(client);
	fidl_bsd_connection_destroy(server);
	puts(
	    "C flexible protocols: empty/payload/application-error replies, events, unknown interactions and nonterminal errors: PASS");
}

static struct fidl_bsd_connection *destroying;
static int destroyed_calls, destroyed_error, destroyed_connection_error;
static void
destroy_completed(void *context, int error,
    struct bsd_runtime_test_Response *value)
{
	(void)context;
	CHECK(value == NULL);
	++destroyed_calls;
	destroyed_error = error;
	/* The completion may still inspect its connection during destroy. */
	destroyed_connection_error = fidl_bsd_connection_error(destroying);
}
static void
test_destroy_with_pending_call(void)
{
	int ends[2];
	uint32_t txid;
	struct fidl_bsd_connection *server;
	CHECK(mac_capability_channel_create(ends) == 0);
	CHECK(fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT,
		  &destroying) == 0);
	CHECK(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER, &server) ==
	    0);
	struct bsd_runtime_test_Request request = { "x", 1 };
	CHECK(bsd_runtime_test_Service_RoundTrip(destroying, &request,
		  destroy_completed, NULL, &txid) == 0);
	fidl_bsd_connection_destroy(destroying);
	CHECK(destroyed_calls == 1 && destroyed_error == ECANCELED);
	CHECK(destroyed_connection_error == ECANCELED);
	fidl_bsd_connection_destroy(server);
	fidl_bsd_connection_destroy(NULL);
}
int
main(void)
{
	int ends[2], pipefd[2];
	uint32_t txid = 0;
	struct state state = { .taken_fd = -1 };
	struct fidl_bsd_connection *client = NULL, *server = NULL;
	alarm(20);
	test_collections();
	test_flexible();
	test_destroy_with_pending_call();
	CHECK(pipe(pipefd) == 0);
	CHECK(fidl_bsd_connection_create(pipefd[0], FIDL_BSD_CLIENT, &client) !=
	    0);
	CHECK(client == NULL && fcntl(pipefd[0], F_GETFD) >= 0);
	CHECK(fidl_bsd_connection_create(pipefd[0], (enum fidl_bsd_role)0,
		  &client) == EINVAL);
	CHECK(client == NULL && fcntl(pipefd[0], F_GETFD) >= 0);
	CHECK(fidl_bsd_connection_create(pipefd[0], FIDL_BSD_CLIENT, NULL) ==
	    EINVAL);
	CHECK(fcntl(pipefd[0], F_GETFD) >= 0);
	close(pipefd[0]);
	close(pipefd[1]);
	CHECK(mac_capability_channel_create(ends) == 0);
	CHECK(fidl_bsd_runtime_abi_version() == FIDL_BSD_ABI_VERSION);
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	--options.size;
	CHECK(fidl_bsd_connection_create_with_options(ends[0], FIDL_BSD_CLIENT,
		  &options, &client) == EINVAL);
	CHECK(client == NULL && fcntl(ends[0], F_GETFD) >= 0);
	++options.size;
	options.reserved = 1;
	CHECK(fidl_bsd_connection_create_with_options(ends[0], FIDL_BSD_CLIENT,
		  &options, &client) == EINVAL);
	options.reserved = 0;
	options.max_pending_requests = 2;
	CHECK(fidl_bsd_connection_create_with_options(ends[0], FIDL_BSD_CLIENT,
		  &options, &client) == 0);
	int32_t epitaph = 123;
	CHECK(fidl_bsd_connection_peer_epitaph(client, &epitaph) == ENOENT &&
	    epitaph == 123);

	CHECK(
	    fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER, &server) == 0);
	struct bsd_runtime_test_Service_server handlers = { round_trip, take,
		notify };
	struct bsd_runtime_test_Service_events events = { changed };
	CHECK(bsd_runtime_test_Service_bind(server, &handlers, &state) == 0);
	CHECK(
	    bsd_runtime_test_Service_bind_events(client, &events, &state) == 0);
	struct bsd_runtime_test_Request request = { "C", 1 };
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &request, response,
		  &state, &txid) == 0 &&
	    txid != 0);
	pump(client, server);
	CHECK(state.replies == 1);
	CHECK(bsd_runtime_test_Service_Notify(client, &request) == 0);
	struct bsd_runtime_test_Response event = { "C", 1 };
	CHECK(bsd_runtime_test_Service_Changed(server, &event) == 0);
	pump(client, server);
	CHECK(state.notifications == 1 && state.events == 1);
	CHECK(pipe(pipefd) == 0);
	CHECK(write(pipefd[1], "C", 1) == 1);
	close(pipefd[1]);
	struct bsd_runtime_test_ReadOnly resource = { pipefd[0] };
	CHECK(bsd_runtime_test_Service_Take(client, &resource, response, &state,
		  &txid) == 0);
	CHECK(resource.fd == pipefd[0] && fcntl(resource.fd, F_GETFD) >= 0);
	cap_rights_t rights;
	CHECK(cap_rights_get(resource.fd, &rights) == 0);
	CHECK(cap_rights_is_set(&rights,
	    CAP_FSTAT)); /* Narrowing the duplicate did not alter the caller. */
	pump(client, server);
	CHECK(state.replies == 2);
	CHECK(state.taken_fd >= 0);
	CHECK(fcntl(state.taken_fd, F_GETFD) >= 0);
	/* C senders deliver lent descriptors with inheritance locked. */
	CHECK(cap_cloexec_limit(state.taken_fd, CAP_CLOEXEC_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE);
	CHECK(cap_clofork_limit(state.taken_fd, CAP_CLOFORK_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE);
	close(state.taken_fd);
	close(resource.fd);
	/* Transfer denial must survive the bridge's private duplication. */
	CHECK(pipe(pipefd) == 0);
	CHECK(cap_xfer_limit(pipefd[0], CAP_XFER_NONE) == 0);
	resource.fd = pipefd[0];
	unsigned before_replies = state.replies, before_errors = state.errors;
	for (unsigned i = 0; i < 3; ++i) {
		txid = 123;
		CHECK(bsd_runtime_test_Service_Take(client, &resource, response,
			  &state, &txid) == ENOTCAPABLE);
		CHECK(txid == 0);
		CHECK(fcntl(resource.fd, F_GETFD) >= 0);
	}
	pump(client, server);
	CHECK(state.replies == before_replies && state.errors == before_errors);
	CHECK(fidl_bsd_connection_error(client) == 0);
	CHECK(write(pipefd[1], "C", 1) == 1);
	char retained;
	CHECK(read(resource.fd, &retained, 1) == 1 && retained == 'C');
	close(pipefd[0]);
	close(pipefd[1]);
	state.defer = 1;
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &request, response,
		  &state, &txid) == 0);
	pump(client, server);
	CHECK(state.held != NULL && state.replies == 2);
	CHECK(bsd_runtime_test_Service_RoundTrip_reply(server, state.held,
		  &event) == 0);
	fidl_bsd_request_release(state.held);
	state.held = NULL;
	pump(client, server);
	CHECK(state.replies == 3);
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &request, response,
		  &state, &txid) == 0);
	pump(client, server);
	CHECK(state.held != NULL);
	CHECK(fidl_bsd_connection_cancel(client, txid) == 0);
	CHECK(state.errors == 1);
	CHECK(bsd_runtime_test_Service_RoundTrip_reply(server, state.held,
		  &event) == 0);
	fidl_bsd_request_release(state.held);
	state.held = NULL;
	pump(client, server);
	CHECK(state.errors == 1 && state.replies == 3);
	struct bsd_runtime_test_Request bad = { NULL, 1 };
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &bad, response, &state,
		  &txid) == EINVAL &&
	    txid == 0);
	bad.text = "C";
	bad.text_size = 257;
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &bad, response, &state,
		  &txid) == EINVAL);
	CHECK(bsd_runtime_test_Service_RoundTrip(client, &request, NULL, &state,
		  &txid) == EINVAL);
	CHECK(fidl_bsd_connection_error(client) == 0 &&
	    fidl_bsd_connection_error(server) == 0);
	struct bsd_runtime_test_Shapes_server shapes = { ping, shape_echo };
	CHECK(bsd_runtime_test_Shapes_bind(server, &shapes, NULL) == 0);
	int shape_replies = 0;
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_runtime_test_ShapesEchoRequest shaped = { 42 };
	CHECK(bsd_runtime_test_Shapes_Ping(client, &empty, ping_reply,
		  &shape_replies, &txid) == 0);
	CHECK(bsd_runtime_test_Shapes_Echo(client, &shaped, shape_reply,
		  &shape_replies, &txid) == 0);
	CHECK(bsd_runtime_test_Shapes_Ping(client, &empty, ping_reply,
		  &shape_replies, &txid) == ENOBUFS &&
	    txid == 0);
	pump(client, server);
	CHECK(shape_replies == 2);
	struct bsd_runtime_test_EndpointExchange_server endpoint_handlers = {
		endpoint_echo
	};
	CHECK(bsd_runtime_test_EndpointExchange_bind(server, &endpoint_handlers,
		  NULL) == 0);
	int endpoint_fds[2], received_endpoint = -1;
	CHECK(mac_capability_channel_create(endpoint_fds) == 0);
	struct bsd_runtime_test_EndpointRequest endpoint_value = {
		endpoint_fds[0]
	};
	CHECK(
	    bsd_runtime_test_EndpointExchange_RoundTrip(client, &endpoint_value,
		endpoint_reply, &received_endpoint, &txid) == 0);
	pump(client, server);
	CHECK(received_endpoint >= 0 && fcntl(endpoint_fds[0], F_GETFD) >= 0);
	struct fidl_bsd_connection *returned_endpoint = NULL;
	CHECK(fidl_bsd_connection_create(received_endpoint, FIDL_BSD_CLIENT,
		  &returned_endpoint) == 0);
	fidl_bsd_connection_destroy(returned_endpoint);
	close(endpoint_fds[0]);
	close(endpoint_fds[1]);
	struct bsd_runtime_test_Naming_server names_handlers = { names_echo };
	CHECK(bsd_runtime_test_Naming_bind(server, &names_handlers, NULL) == 0);
	struct bsd_runtime_test_EscapedNames names = { .switch_fidl = 11,
		.text_fidl = "name",
		.text_fidl_size = 4,
		.text_size = 22,
		.UpperCase = 33 };
	int names_replies = 0;
	CHECK(bsd_runtime_test_Naming_RoundTrip(client, &names, names_reply,
		  &names_replies, &txid) == 0);
	pump(client, server);
	CHECK(names_replies == 1);
	CHECK(fidl_bsd_connection_shutdown(server, 0) == 0);
	pump(client, server);
	CHECK(fidl_bsd_connection_error(client) == EPIPE);
	CHECK(fidl_bsd_connection_peer_epitaph(client, &epitaph) == 0 &&
	    epitaph == 0);
	fidl_bsd_connection_destroy(client);
	fidl_bsd_connection_destroy(server);
	puts(
	    "C bindings: round trip, one-way, events, borrowed sends, descriptor take, deferred reply, cancellation, bounds, shutdown: PASS");
	return 0;
}

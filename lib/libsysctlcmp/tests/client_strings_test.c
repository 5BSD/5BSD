/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * libsysctlcmp reply validation against a scripted bsd.sysctl.v1 server over
 * a real capability channel: semantic strings must be NUL-terminated and
 * non-empty, interface inventories must be well formed, malformed replies and
 * future peers make the client terminal, and short output buffers report the
 * needed size without a partial copy.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.sysctl.v1/c/bsd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sysctlcmp.h"

static struct script {
	bool omit_nul, empty_value, future;
} *script;

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_sysctl_v1_ProtocolInfo v = { SYSCTLCMP_WIRE_VERSION };
	(void)x;
	(void)e;
	if (script->future)
		v.wire_version++;
	assert(bsd_sysctl_v1_Sysctl_GetProtocolInfo_reply(c, r, &v) == 0);
}

/* Describe/Next return text; OidFormat {kind; "A"}; Get an empty value. */
static void
value(struct bsd_sysctl_v1_Value *v, uint8_t *storage, int which)
{
	const char *text = which == 1 ? "description" : "kern.next";

	if (script->empty_value || which == 0) {
		v->value = storage;
		v->value_size = 0;
		return;
	}
	if (which == 3) {
		uint32_t kind = 0x1234;
		memcpy(storage, &kind, sizeof(kind));
		storage[4] = 'A';
		storage[5] = '\0';
		v->value_size = sizeof(kind) + (script->omit_nul ? 1 : 2);
	} else {
		memcpy(storage, text, strlen(text) + 1);
		v->value_size = strlen(text) + (script->omit_nul ? 0 : 1);
	}
	v->value = storage;
}

#define HANDLER(method, which)                                                \
static void                                                                   \
method##_handler(void *x, struct fidl_bsd_connection *c,                     \
    struct fidl_bsd_request *r, struct bsd_sysctl_v1_NameRequest *q)         \
{                                                                             \
	struct bsd_sysctl_v1_Sysctl_##method##_Result v = {                   \
		.tag = bsd_sysctl_v1_Sysctl_##method##_Result_response_tag   \
	};                                                                    \
	uint8_t storage[64];                                                  \
	(void)x;                                                              \
	(void)q;                                                              \
	value(&v.value.response, storage, which);                             \
	assert(bsd_sysctl_v1_Sysctl_##method##_reply(c, r, &v) == 0);         \
}
HANDLER(Get, 0)
HANDLER(Describe, 1)
HANDLER(Next, 2)
HANDLER(OidFormat, 3)

static void
interfaces_handler(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct fidl_bsd_empty *e)
{
	struct bsd_sysctl_v1_Interface entries[2] = {
		{ .index = 1, .mtu = 1500, .name = "em0", .name_size = 3 },
		{ .index = 2, .mtu = 16384, .name = "lo0", .name_size = 3 },
	};
	struct bsd_sysctl_v1_Sysctl_ListInterfaces_Result v = {
		.tag = bsd_sysctl_v1_Sysctl_ListInterfaces_Result_response_tag
	};
	(void)x;
	(void)e;
	if (script->omit_nul)
		entries[1].index = 1;	/* not strictly increasing */
	v.value.response.interfaces = entries;
	v.value.response.interfaces_size = 2;
	assert(bsd_sysctl_v1_Sysctl_ListInterfaces_reply(c, r, &v) == 0);
}

static pid_t server;

static struct sysctlcmp_client *
client_create(void)
{
	struct bsd_sysctl_v1_Sysctl_server handlers = {
		.GetProtocolInfo = info,
		.Get = Get_handler,
		.Describe = Describe_handler,
		.Next = Next_handler,
		.OidFormat = OidFormat_handler,
		.ListInterfaces = interfaces_handler
	};
	struct sysctlcmp_client *client;
	struct fidl_bsd_connection *connection;
	int ends[2], fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
	if (script == NULL) {
		script = mmap(NULL, sizeof(*script), PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_SHARED, -1, 0);
		ATF_REQUIRE(script != MAP_FAILED);
	}
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	server = fork();
	ATF_REQUIRE(server >= 0);
	if (server == 0) {
		close(ends[0]);
		assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
		    &connection) == 0);
		assert(bsd_sysctl_v1_Sysctl_bind(connection, &handlers,
		    NULL) == 0);
		while (fidl_bsd_connection_poll(connection, 10000) == 0)
			;
		_exit(0);
	}
	close(ends[1]);
	ATF_REQUIRE_EQ(0, sysctlcmp_client_create(ends[0], &client));
	return (client);
}

static void
client_done(struct sysctlcmp_client *client)
{
	int status;

	sysctlcmp_client_close(client);
	ATF_REQUIRE_EQ(server, waitpid(server, &status, 0));
	memset(script, 0, sizeof(*script));
}

ATF_TC_WITHOUT_HEAD(strings_valid);
ATF_TC_BODY(strings_valid, tc)
{
	struct sysctlcmp_client *client = client_create();
	unsigned int kind;
	char buf[64];
	size_t len;

	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_describe(client, "kern.test", buf, &len));
	ATF_CHECK_STREQ("description", buf);
	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_next(client, "", buf, &len));
	ATF_CHECK_STREQ("kern.next", buf);
	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_oidfmt(client, "kern.test", &kind, buf,
	    &len));
	ATF_CHECK_EQ(0x1234, kind);
	ATF_CHECK_STREQ("A", buf);
	/* A size query reports the needed length and keeps the session. */
	len = 0;
	ATF_CHECK_ERRNO(ENOMEM, sysctlcmp_describe(client, "kern.test", NULL,
	    &len) == -1);
	ATF_CHECK_EQ(sizeof("description"), len);
	len = sizeof(buf);
	ATF_CHECK_EQ(0, sysctlcmp_describe(client, "kern.test", buf, &len));
	client_done(client);
}

/* Each kind of malformed string reply is terminal for its client. */
static void
reject(bool omit_nul, bool empty)
{
	struct sysctlcmp_client *client;
	unsigned int kind;
	char buf[64];
	size_t len;

	for (int op = 0; op < 3; op++) {
		client = client_create();
		script->omit_nul = omit_nul;
		script->empty_value = empty;
		len = sizeof(buf);
		if (op == 0)
			ATF_CHECK_ERRNO(EPROTO, sysctlcmp_describe(client,
			    "kern.test", buf, &len) == -1);
		else if (op == 1)
			ATF_CHECK_ERRNO(EPROTO, sysctlcmp_next(client, "", buf,
			    &len) == -1);
		else
			ATF_CHECK_ERRNO(EPROTO, sysctlcmp_oidfmt(client,
			    "kern.test", &kind, buf, &len) == -1);
		/* The client is now terminal. */
		len = sizeof(buf);
		ATF_CHECK_ERRNO(EPROTO, sysctlcmp_get(client, "kern.x", buf,
		    &len) == -1);
		client_done(client);
	}
}

ATF_TC_WITHOUT_HEAD(strings_reject_unterminated);
ATF_TC_BODY(strings_reject_unterminated, tc)
{
	reject(true, false);
}

ATF_TC_WITHOUT_HEAD(strings_reject_empty);
ATF_TC_BODY(strings_reject_empty, tc)
{
	struct sysctlcmp_client *client;
	size_t len;

	reject(false, true);
	/* An empty opaque value stays valid. */
	client = client_create();
	script->empty_value = true;
	len = 0;
	ATF_REQUIRE_EQ(0, sysctlcmp_get(client, "kern.empty", NULL, &len));
	ATF_CHECK_EQ(0, len);
	client_done(client);
}

ATF_TC_WITHOUT_HEAD(future_version_is_terminal);
ATF_TC_BODY(future_version_is_terminal, tc)
{
	struct sysctlcmp_client *client = client_create();
	char buf[32];
	size_t len = sizeof(buf);

	script->future = true;
	ATF_CHECK_ERRNO(EPROTONOSUPPORT,
	    sysctlcmp_describe(client, "kern.test", buf, &len) == -1);
	ATF_CHECK_ERRNO(EPROTONOSUPPORT,
	    sysctlcmp_get(client, "kern.test", buf, &len) == -1);
	client_done(client);
}

ATF_TC_WITHOUT_HEAD(interface_output_contract);
ATF_TC_BODY(interface_output_contract, tc)
{
	struct sysctlcmp_client *client = client_create();
	struct sysctlcmp_interface out[2], saved[2];
	size_t count;

	count = 0;
	ATF_REQUIRE_EQ(0, sysctlcmp_interfaces(client, NULL, &count));
	ATF_CHECK_EQ(2, count);
	memset(out, 0xa5, sizeof(out));
	memcpy(saved, out, sizeof(out));
	count = 1;
	ATF_CHECK_ERRNO(ENOMEM, sysctlcmp_interfaces(client, out, &count) ==
	    -1);
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(0, memcmp(saved, out, sizeof(out)));
	ATF_REQUIRE_EQ(0, sysctlcmp_interfaces(client, out, &count));
	ATF_CHECK_STREQ("em0", out[0].name);
	ATF_CHECK_STREQ("lo0", out[1].name);
	ATF_CHECK_EQ(0, out[0].reserved[0]);
	memcpy(saved, out, sizeof(out));
	script->omit_nul = true;
	ATF_CHECK_ERRNO(EPROTO, sysctlcmp_interfaces(client, out, &count) ==
	    -1);
	ATF_CHECK_EQ(0, memcmp(saved, out, sizeof(out)));
	client_done(client);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, interface_output_contract);
	ATF_TP_ADD_TC(tp, strings_valid);
	ATF_TP_ADD_TC(tp, strings_reject_unterminated);
	ATF_TP_ADD_TC(tp, strings_reject_empty);
	ATF_TP_ADD_TC(tp, future_version_is_terminal);
	return (atf_no_error());
}

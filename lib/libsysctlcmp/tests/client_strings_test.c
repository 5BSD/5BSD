/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../sysctlcmp.c"

struct service_session {
	int unused;
};

static bool omit_nul;
static bool empty_value;
static bool wrong_opcode;
static unsigned fail_calls;

int
service_open(const char *name, int *fdp)
{
	(void)name;
	(void)fdp;
	errno = ENOSYS;
	return (-1);
}

int
service_session_create(int fd, struct service_session **sessionp)
{
	(void)fd;
	(void)sessionp;
	errno = ENOSYS;
	return (-1);
}

void
service_session_close(struct service_session *session)
{
	(void)session;
}

int
service_session_fail(struct service_session *session, int error)
{
	ATF_REQUIRE(session != NULL);
	ATF_REQUIRE_EQ(EPROTO, error);
	fail_calls++;
	return (0);
}

int
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *incoming,
    const struct service_call_options *options)
{
	const struct sysctlcmp_msg *request;
	struct sysctlcmp_msg *reply;
	struct sysctlcmp_body *body;
	struct sysctlcmp_oidfmt *oidfmt;
	const char *text;
	uint8_t *value;
	size_t value_length;

	ATF_REQUIRE(session != NULL);
	ATF_REQUIRE(outgoing != NULL);
	ATF_REQUIRE(incoming != NULL);
	ATF_REQUIRE(options != NULL);
	request = outgoing->data;
	reply = incoming->data;
	ATF_REQUIRE_EQ(0, sysctlcmp_message_init_reply(reply, request, 0));
	if (wrong_opcode)
		reply->opcode = request->opcode == SYSCTLCMP_OP_DESCR ?
		    SYSCTLCMP_OP_NEXT : SYSCTLCMP_OP_DESCR;
	body = (void *)(reply + 1);
	memset(body, 0, sizeof(*body));
	value = (uint8_t *)(body + 1);
	if (empty_value) {
		value_length = 0;
	} else if (request->opcode == SYSCTLCMP_OP_OIDFMT) {
		oidfmt = (void *)value;
		oidfmt->kind = 0x1234;
		oidfmt->fmt[0] = 'A';
		oidfmt->fmt[1] = '\0';
		value_length = sizeof(*oidfmt) + (omit_nul ? 1 : 2);
	} else {
		text = request->opcode == SYSCTLCMP_OP_NEXT ?
		    "kern.next" : "description";
		value_length = strlen(text) + (omit_nul ? 0 : 1);
		memcpy(value, text, value_length);
	}
	body->value_length = (uint32_t)value_length;
	incoming->length = sizeof(*reply) + sizeof(*body) + value_length;
	incoming->nfds = 0;
	return (0);
}

static void
init_client(struct sysctlcmp_client *client)
{

	memset(client, 0, sizeof(*client));
	client->session = (struct service_session *)(uintptr_t)1;
	client->owner = getpid();
	omit_nul = false;
	empty_value = false;
	wrong_opcode = false;
	fail_calls = 0;
}

ATF_TC(strings_valid);
ATF_TC_HEAD(strings_valid, tc)
{
	atf_tc_set_md_var(tc, "descr", "string replies require and preserve NUL termination");
}
ATF_TC_BODY(strings_valid, tc)
{
	struct sysctlcmp_client client;
	unsigned int kind;
	char buf[64];
	size_t len;

	init_client(&client);
	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_describe(&client, "kern.test", buf, &len));
	ATF_CHECK_STREQ("description", buf);
	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_next(&client, "", buf, &len));
	ATF_CHECK_STREQ("kern.next", buf);
	len = sizeof(buf);
	ATF_REQUIRE_EQ(0, sysctlcmp_oidfmt(&client, "kern.test", &kind,
	    buf, &len));
	ATF_CHECK_EQ(0x1234, kind);
	ATF_CHECK_STREQ("A", buf);
	ATF_CHECK_EQ(0, fail_calls);
}

ATF_TC(strings_reject_unterminated);
ATF_TC_HEAD(strings_reject_unterminated, tc)
{
	atf_tc_set_md_var(tc, "descr", "unterminated semantic strings poison the session");
}
ATF_TC_BODY(strings_reject_unterminated, tc)
{
	struct sysctlcmp_client client;
	unsigned int kind;
	char buf[64];
	size_t len;

	init_client(&client);
	omit_nul = true;
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_describe(&client, "kern.test", buf, &len) == -1);
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_next(&client, "", buf, &len) == -1);
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_oidfmt(&client, "kern.test", &kind, buf, &len) == -1);
	ATF_CHECK_EQ(3, fail_calls);
}

ATF_TC(strings_reject_empty);
ATF_TC_HEAD(strings_reject_empty, tc)
{
	atf_tc_set_md_var(tc, "descr", "empty string payloads fail while empty opaque values remain valid");
}
ATF_TC_BODY(strings_reject_empty, tc)
{
	struct sysctlcmp_client client;
	unsigned int kind;
	char buf[8];
	size_t len;

	init_client(&client);
	empty_value = true;
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_describe(&client, "kern.test", buf, &len) == -1);
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_next(&client, "", buf, &len) == -1);
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_oidfmt(&client, "kern.test", &kind, buf, &len) == -1);
	len = 0;
	ATF_REQUIRE_EQ(0, sysctlcmp_get(&client, "kern.empty", NULL, &len));
	ATF_CHECK_EQ(0, len);
	ATF_CHECK_EQ(3, fail_calls);
}

ATF_TC(wrong_opcode_is_terminal);
ATF_TC_HEAD(wrong_opcode_is_terminal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A valid reply for another operation poisons the session");
}
ATF_TC_BODY(wrong_opcode_is_terminal, tc)
{
	struct sysctlcmp_client client;
	char buf[32];
	size_t len;

	init_client(&client);
	wrong_opcode = true;
	len = sizeof(buf);
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_describe(&client, "kern.test", buf, &len) == -1);
	ATF_CHECK_EQ(1, fail_calls);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, strings_valid);
	ATF_TP_ADD_TC(tp, strings_reject_unterminated);
	ATF_TP_ADD_TC(tp, strings_reject_empty);
	ATF_TP_ADD_TC(tp, wrong_opcode_is_terminal);
	return (atf_no_error());
}

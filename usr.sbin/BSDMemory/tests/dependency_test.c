/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int bsdmemory_test_main(void);
#define main bsdmemory_test_main
#include "../BSDMemory.c"
#undef main

struct sysctlcmp_client { int unused; };
struct notify_client { int unused; };
static struct sysctlcmp_client source_client;
static struct notify_client notify_client;
static int open_error, read_error, set_error;
static bool short_reply;
static unsigned opens, closes, reads, sets;
static uint64_t observed_level, set_level;
int __wrap_sysctlcmp_client_open(struct sysctlcmp_client **);
void __wrap_sysctlcmp_client_close(struct sysctlcmp_client *);
int __wrap_sysctlcmp_get(struct sysctlcmp_client *, const char *, void *, size_t *);
int __wrap_notify_client_open_system(struct notify_client **);
void __wrap_notify_client_close(struct notify_client *);
int __wrap_notify_state_get(struct notify_client *, const char *, struct notify_state_reply *);
int __wrap_notify_state_set(struct notify_client *, const char *, uint64_t);

int
__wrap_sysctlcmp_client_open(struct sysctlcmp_client **out)
{
	opens++;
	*out = open_error ? NULL : &source_client;
	return (open_error ? (errno = open_error, -1) : 0);
}
void
__wrap_sysctlcmp_client_close(struct sysctlcmp_client *client)
{
	ATF_REQUIRE(client == &source_client);
	closes++;
	errno = EBADF; /* Cleanup must not replace the operation's failure. */
}
int
__wrap_sysctlcmp_get(struct sysctlcmp_client *client, const char *name,
    void *value, size_t *length)
{
	ATF_REQUIRE(client == &source_client);
	ATF_REQUIRE(name != NULL);
	reads++;
	*length = short_reply ? 1 : sizeof(uint32_t);
	if (read_error)
		return (errno = read_error, -1);
	*(uint32_t *)value = reads;
	return (0);
}
int
__wrap_notify_client_open_system(struct notify_client **out)
{
	opens++;
	*out = open_error ? NULL : &notify_client;
	return (open_error ? (errno = open_error, -1) : 0);
}
void
__wrap_notify_client_close(struct notify_client *client)
{
	ATF_REQUIRE(client == &notify_client);
	closes++;
	errno = EBADF;
}
int
__wrap_notify_state_get(struct notify_client *client, const char *topic,
    struct notify_state_reply *out)
{
	ATF_REQUIRE(client == &notify_client);
	ATF_CHECK_STREQ(NOTIFY_PRESSURE_TOPIC, topic);
	reads++;
	if (read_error)
		return (errno = read_error, -1);
	*out = (struct notify_state_reply){ .router_epoch = 1,
	    .generation = 1, .state = observed_level };
	return (0);
}
int
__wrap_notify_state_set(struct notify_client *client, const char *topic,
    uint64_t level)
{
	ATF_REQUIRE(client == &notify_client);
	ATF_CHECK_STREQ(NOTIFY_PRESSURE_TOPIC, topic);
	sets++;
	set_level = level;
	return (set_error ? (errno = set_error, -1) : 0);
}

ATF_TC_WITHOUT_HEAD(sample_errors_and_recovery);
ATF_TC_BODY(sample_errors_and_recovery, tc)
{
	struct sysctlcmp_client *client = NULL;
	uint32_t values[3];

	open_error = EACCES;
	ATF_REQUIRE_ERRNO(EACCES, sample(&client, values) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_EQ(0, reads);
	open_error = 0;
	read_error = ENOMEM;
	short_reply = true;
	ATF_REQUIRE_ERRNO(ENOMEM, sample(&client, values) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_EQ(1, reads);
	ATF_CHECK_EQ(1, closes);
	read_error = 0;
	ATF_REQUIRE_ERRNO(EPROTO, sample(&client, values) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_EQ(2, closes);
	short_reply = false;
	reads = 0;
	ATF_REQUIRE_EQ(0, sample(&client, values));
	ATF_CHECK_EQ(3, reads);
	ATF_CHECK_EQ(1, values[0]);
	ATF_CHECK_EQ(2, values[1]);
	ATF_CHECK_EQ(3, values[2]);
	ATF_CHECK(client == &source_client);
}
ATF_TC_WITHOUT_HEAD(publication_repairs_state_and_preserves_errors);
ATF_TC_BODY(publication_repairs_state_and_preserves_errors, tc)
{
	struct notify_client *client = NULL;
	unsigned published = NOTIFY_PRESSURE_UNKNOWN + 1;

	open_error = EACCES;
	ATF_REQUIRE_ERRNO(EACCES, publish_pressure(&client,
	    NOTIFY_PRESSURE_CRITICAL, &published) == -1);
	ATF_CHECK_EQ(0, sets);
	open_error = 0;
	ATF_REQUIRE_EQ(0, publish_pressure(&client, NOTIFY_PRESSURE_CRITICAL, &published));
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL, published);
	ATF_CHECK_EQ(1, sets);
	observed_level = NOTIFY_PRESSURE_CRITICAL;
	ATF_REQUIRE_EQ(0, publish_pressure(&client, NOTIFY_PRESSURE_CRITICAL, &published));
	ATF_CHECK_EQ(1, sets); /* Unchanged valid state needs no write. */
	read_error = ENOENT;
	ATF_REQUIRE_EQ(0, publish_pressure(&client, NOTIFY_PRESSURE_CRITICAL, &published));
	ATF_CHECK_EQ(2, sets); /* Lost state is restored despite unchanged level. */
	read_error = ECONNRESET;
	set_error = ENOSPC;
	ATF_REQUIRE_ERRNO(ENOSPC, publish_pressure(&client,
	    NOTIFY_PRESSURE_CRITICAL, &published) == -1);
	ATF_CHECK(client == NULL);
	ATF_CHECK_EQ(1, closes);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL, published);
	read_error = set_error = 0;
	ATF_REQUIRE_EQ(0, publish_pressure(&client, NOTIFY_PRESSURE_CRITICAL, &published));
	ATF_CHECK_EQ(4, sets);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_CRITICAL, set_level);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sample_errors_and_recovery);
	ATF_TP_ADD_TC(tp, publication_repairs_state_and_preserves_errors);
	return (atf_no_error());
}

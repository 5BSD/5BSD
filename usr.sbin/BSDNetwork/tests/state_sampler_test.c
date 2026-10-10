/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <stdatomic.h>
#include "../state.c"

struct sysctlcmp_client { int unused; };
static struct sysctlcmp_client fake_client;
static atomic_uint opened, closed, sampled;
int
sysctlcmp_client_open(struct sysctlcmp_client **out)
{
	atomic_fetch_add(&opened, 1);
	*out = &fake_client;
	return (0);
}
void
sysctlcmp_client_close(struct sysctlcmp_client *client)
{
	(void)client;
	atomic_fetch_add(&closed, 1);
}
int
sysctlcmp_interfaces(struct sysctlcmp_client *client,
    struct sysctlcmp_interface *entries, size_t *count)
{
	(void)client;
	if (atomic_fetch_add(&sampled, 1) == 0)
		return (errno = ECONNRESET, -1);
	memset(entries, 0, sizeof(*entries));
	entries[0].index = 7;
	entries[0].mtu = 1500;
	entries[0].link_state = NETWORK_STATE_LINK_UP;
	strlcpy(entries[0].name, "em0", sizeof(entries[0].name));
	*count = 1;
	return (0);
}
ATF_TC(sampler_recovery_and_shutdown);
ATF_TC_HEAD(sampler_recovery_and_shutdown, tc)
{
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(sampler_recovery_and_shutdown, tc)
{
	struct network_state_server *server;
	struct notify_watcher *watcher;
	struct network_state_snapshot state;
	struct notify_watch_cursor cursor;
	struct timespec before, after;
	uint32_t flags;
	size_t length;
	bool unavailable = false, recovered = false;
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	ATF_REQUIRE_EQ(0, notify_watch_open(server->store, NULL, &watcher));
	ATF_REQUIRE_EQ(0, notify_watch_begin(watcher));
	for (unsigned i = 0; i < 300 && !recovered; i++) {
		int result = notify_watch_take(watcher, &state, sizeof(state),
		    &length, &cursor, &flags);
		ATF_REQUIRE(result >= 0);
		if (result == 1) {
			if (state.source_error == ECONNRESET)
				unavailable = true;
			if (state.source_error == 0 && state.count == 1) {
				recovered = true;
				ATF_CHECK_EQ(7, state.interfaces[0].index);
				ATF_CHECK_EQ(1500, state.interfaces[0].mtu);
				ATF_CHECK_EQ(NETWORK_STATE_LINK_UP, state.interfaces[0].link_state);
				ATF_CHECK_STREQ("em0", state.interfaces[0].name);
			}
			ATF_REQUIRE_EQ(0, notify_watch_begin(watcher));
		}
		usleep(10000);
	}
	ATF_CHECK(unavailable);
	ATF_REQUIRE(recovered);
	notify_watch_close(watcher);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &before));
	network_state_server_destroy(server);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &after));
	ATF_CHECK((after.tv_sec - before.tv_sec) * 1000000000LL +
	    after.tv_nsec - before.tv_nsec < 500000000LL);
	ATF_CHECK_EQ(2, atomic_load(&opened));
	ATF_CHECK_EQ(2, atomic_load(&closed));
	close(kq);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sampler_recovery_and_shutdown);
	return (atf_no_error());
}

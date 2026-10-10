/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <stdatomic.h>
#include "../state.c"

struct sysctlcmp_client { int unused; };
static struct sysctlcmp_client fake_client;
static atomic_uint opened, closed, sampled, budget_expired;
static atomic_int stall_phase;
static atomic_uint sample_budget;
static int
stall_rpc(void)
{
	uint32_t timeout = UINT32_MAX;
	while (service_budget_timeout(&timeout) == 0)
		usleep(10000);
	atomic_fetch_add(&budget_expired, 1);
	return (-1);
}
int
sysctlcmp_client_open(struct sysctlcmp_client **out)
{
	atomic_fetch_add(&opened, 1);
	if (atomic_load(&stall_phase) == 1) {
		*out = NULL;
		return (stall_rpc());
	}
	if (atomic_load(&stall_phase) == 3) {
		uint64_t until = service_monotime_ms() + 650;
		while (service_monotime_ms() < until)
			usleep(1000);
	}
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
	unsigned attempt = atomic_fetch_add(&sampled, 1);
	if (atomic_load(&stall_phase) >= 2) {
		uint32_t timeout = UINT32_MAX;
		if (service_budget_timeout(&timeout) == -1)
			timeout = 0;
		atomic_store(&sample_budget, timeout);
		return (stall_rpc());
	}
	if (attempt == 0)
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
ATF_TC(sampler_stalled_rpc_shutdown);
ATF_TC_HEAD(sampler_stalled_rpc_shutdown, tc)
{
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(sampler_stalled_rpc_shutdown, tc)
{
	struct network_state_server *server;
	uint64_t started;
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	for (int phase = 1; phase <= 3; phase++) {
		atomic_store(&opened, 0);
		atomic_store(&sampled, 0);
		atomic_store(&closed, 0);
		atomic_store(&budget_expired, 0);
		atomic_store(&stall_phase, phase);
		ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
		for (unsigned i = 0; i < 3000; i++) {
			if ((phase == 1 && atomic_load(&opened) != 0) ||
			    (phase >= 2 && atomic_load(&sampled) != 0))
				break;
			usleep(1000);
		}
		ATF_REQUIRE(atomic_load(&opened) != 0);
		if (phase >= 2)
			ATF_REQUIRE(atomic_load(&sampled) != 0);
		started = service_monotime_ms();
		network_state_server_destroy(server);
		ATF_CHECK(service_monotime_ms() - started < 2500);
		ATF_CHECK_EQ(1, atomic_load(&budget_expired));
		ATF_CHECK_EQ(phase >= 2 ? 1 : 0, atomic_load(&closed));
		if (phase == 3)
			ATF_CHECK(atomic_load(&sample_budget) <= 400);
	}
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sampler_stalled_rpc_shutdown);
	ATF_TP_ADD_TC(tp, sampler_recovery_and_shutdown);
	return (atf_no_error());
}

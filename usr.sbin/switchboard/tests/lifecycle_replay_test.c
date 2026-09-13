/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "switchboard.h"
#include "switchboard_lifecycle.h"
#include "switchboard_reclamation.h"
#include "switchboard_svc_proto.h"

static struct svc_runtime client, provider;
static struct svc_reclaim_label_msg delivery;
static unsigned sent, stopped;

struct svc_runtime *
svc_by_label(const char *label)
{
	if (strcmp(label, client.manifest.label) == 0)
		return (&client);
	if (strcmp(label, provider.manifest.label) == 0)
		return (&provider);
	return (NULL);
}

bool
bundle_registry_label_installed(const char *label __unused)
{
	return (false);
}

void
svc_graceful_stop(struct svc_runtime *svc, int kq __unused)
{
	ATF_REQUIRE(svc == &client);
	stopped++;
}

int
svc_channel_send_event(struct svc_runtime *svc, const void *data, size_t length,
    const int *fds __unused, size_t nfds, int kq __unused)
{
	ATF_REQUIRE(svc == &provider);
	ATF_REQUIRE_EQ(sizeof(delivery), length);
	ATF_REQUIRE_EQ(0, nfds);
	memcpy(&delivery, data, length);
	sent++;
	return (0);
}

ATF_TC_WITHOUT_HEAD(offline_replay_and_late_receipt);
ATF_TC_BODY(offline_replay_and_late_receipt, tc)
{
	struct sl_db db;
	struct svc_reclaim_result_req reply;
	struct svc_new_client_msg request = {0};
	uint8_t old[16], fresh[16];

	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM", "1", 1));
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_LIFECYCLE_DIR", "state", 1));
	strlcpy(client.manifest.label, "org.test.app/worker", sizeof(client.manifest.label));
	strlcpy(provider.manifest.label, "org.test.storage/provider", sizeof(provider.manifest.label));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_adopt(&db, client.manifest.label, old));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
	memcpy(old, client.installation, sizeof(old));
	ATF_REQUIRE_EQ(0, svc_lifecycle_register(&provider));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, client.manifest.label, fresh));
	ATF_REQUIRE_EQ(0, sl_retire(&db, client.manifest.label, old));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_CHECK_EQ(0, svc_lifecycle_replay(-1));
	ATF_CHECK_EQ(1, stopped);
	/* A stale restart cannot undo retirement, including after reopening state. */
	ATF_CHECK_ERRNO(ESTALE, svc_lifecycle_identity(&client) == -1);
	/* Reinstall while the provider is offline, then replay the historical ID. */
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install(&db, client.manifest.label, fresh));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	/* The old running client cannot borrow the replacement's identity. */
	ATF_CHECK_ERRNO(ESTALE, svc_lifecycle_client(&client, &provider, &request) == -1);
	ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
	memcpy(fresh, client.installation, sizeof(fresh));
	ATF_REQUIRE(memcmp(old, fresh, sizeof(old)) != 0);
	provider.state = SVC_STATE_RUNNING;
	provider.protocol_ready = true;
	provider.control_channel = (struct channel *)&provider;
	ATF_CHECK_EQ(1, svc_lifecycle_replay(-1));
	ATF_CHECK_EQ(1, stopped);
	ATF_CHECK_EQ(0, memcmp(old, delivery.generation, sizeof(old)));
	ATF_CHECK_STREQ(client.manifest.label, delivery.owner);
	memset(&reply, 0, sizeof(reply));
	reply.op = SVC_OP_RECLAIM_RESULT;
	strlcpy(reply.label, delivery.label, sizeof(reply.label));
	memcpy(reply.generation, old, sizeof(old));
	reply.status = EIO;
	ATF_REQUIRE_EQ(0, svc_lifecycle_ack(&provider, &reply));
	ATF_CHECK_EQ(1, svc_lifecycle_replay(-1));
	provider.reclaim_registered = false;
	reply.status = 0;
	ATF_CHECK_EQ(EINVAL, svc_lifecycle_ack(&provider, &reply));
	ATF_REQUIRE_EQ(0, svc_lifecycle_register(&provider));
	ATF_REQUIRE_EQ(0, svc_lifecycle_ack(&provider, &reply));
	ATF_CHECK_EQ(0, svc_lifecycle_replay(-1));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_EQ(SL_COMPLETE, sl_generation(&db, reply.label, old)->phase);
	ATF_CHECK_EQ(SL_ACTIVE, sl_generation(&db, reply.label, fresh)->phase);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(session_records_only_its_provider);
ATF_TC_BODY(session_records_only_its_provider, tc)
{
    struct sl_db db;
    struct svc_new_client_msg request = {0};
    uint8_t generation[16];
    unsigned deliveries = 0;

    ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM", "1", 1));
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
    ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_LIFECYCLE_DIR", "state", 1));
    strlcpy(client.manifest.label, "org.test.app/worker", sizeof(client.manifest.label));
    strlcpy(provider.manifest.label, "org.test.storage/provider", sizeof(provider.manifest.label));
    strlcpy(request.client_label, client.manifest.label, sizeof(request.client_label));
    ATF_REQUIRE_EQ(0, sl_open("state", &db));
    ATF_REQUIRE_EQ(0, sl_install(&db, client.manifest.label, generation));
    ATF_REQUIRE_EQ(0, sl_register_provider(&db, "org.test.unused/provider"));
    ATF_REQUIRE_EQ(0, sl_commit(&db));
    sl_close(&db);
    ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
    ATF_REQUIRE_EQ(0, svc_lifecycle_register(&provider));
    ATF_REQUIRE_EQ(0, svc_lifecycle_client(&client, &provider, &request));
    ATF_REQUIRE_EQ(0, svc_lifecycle_client(&client, &provider, &request));
    ATF_CHECK(strncmp(request.resource_owner, "install.", 8) == 0);
    ATF_REQUIRE_EQ(0, sl_open("state", &db));
    ATF_REQUIRE_EQ(0, sl_prepare(&db, client.manifest.label, generation));
    ATF_REQUIRE_EQ(0, sl_retire(&db, client.manifest.label, generation));
    ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, client.manifest.label, generation));
    for (size_t i = 0; i < db.count; i++) {
        if (db.records[i].kind != SL_DELIVERY)
            continue;
        deliveries++;
        ATF_CHECK_STREQ(provider.manifest.label, db.records[i].provider);
    }
    ATF_CHECK_EQ(1, deliveries);
    ATF_REQUIRE_EQ(0, sl_commit(&db));
    sl_close(&db);
}

ATF_TC(authority_does_not_schedule_cleanup);
ATF_TC_HEAD(authority_does_not_schedule_cleanup, tc)
{
	atf_tc_set_md_var(tc, "timeout", "5");
}
ATF_TC_BODY(authority_does_not_schedule_cleanup, tc)
{
	struct sl_db db;
	struct sl_installation result;
	uint8_t generation[16];
	size_t count;
	const char *install = "11111111111111111111111111111111";
	const char *remove = "22222222222222222222222222222222";

	ATF_REQUIRE_EQ(0, unsetenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM"));
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_LIFECYCLE_DIR", "state", 1));
	strlcpy(client.manifest.label, "org.test.app/worker", sizeof(client.manifest.label));
	strlcpy(provider.manifest.label, "org.test.storage/provider", sizeof(provider.manifest.label));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, client.manifest.label, "pkg.test", install));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, client.manifest.label, install, false));
	memcpy(generation, sl_owner(&db, client.manifest.label)->generation, sizeof(generation));
	/* Even records from the earlier experiment cannot turn uninstall into cleanup. */
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider.manifest.label));
	ATF_REQUIRE_EQ(0, sl_track_holding(&db, client.manifest.label, provider.manifest.label, generation));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, client.manifest.label, "pkg.test", remove));
	count = db.count;
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, client.manifest.label, remove, false));
	ATF_CHECK_EQ(count, db.count);
	/* A paused installer must not block the default timer either. */
	ATF_CHECK_EQ(0, svc_lifecycle_replay(-1));
	ATF_REQUIRE_EQ(0, sl_query(&db, client.manifest.label, generation, &result));
	ATF_CHECK_EQ(SL_REMOVED, result.state);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	memcpy(client.installation, generation, sizeof(generation));
	ATF_REQUIRE_EQ(0, svc_lifecycle_register(&provider));
	provider.state = SVC_STATE_RUNNING;
	provider.protocol_ready = true;
	provider.control_channel = (struct channel *)&provider;
	ATF_CHECK_EQ(0, svc_lifecycle_replay(-1));
	ATF_CHECK_EQ(0, sent);
	ATF_CHECK_EQ(1, stopped);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_CHECK_EQ(count, db.count);
	sl_close(&db);
	/* Pending deliveries from a previous experiment are also inert by default. */
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, client.manifest.label, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_CHECK_EQ(0, svc_lifecycle_replay(-1));
	ATF_CHECK_EQ(0, sent);
}

ATF_TC_WITHOUT_HEAD(runtime_requires_explicit_registration);
ATF_TC_BODY(runtime_requires_explicit_registration, tc)
{
	struct sl_db db;
	struct svc_new_client_msg request = {0};
	uint8_t generation[16];
	size_t count;

	ATF_REQUIRE_EQ(0, unsetenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM"));
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_LIFECYCLE_DIR", "state", 1));
	strlcpy(client.manifest.label, "org.test.app/worker", sizeof(client.manifest.label));
	strlcpy(request.client_label, "org.5bsd.user-session", sizeof(request.client_label));
	ATF_CHECK_ERRNO(ENOENT, svc_lifecycle_init(-1) == -1);
	ATF_CHECK_ERRNO(ENOENT, svc_lifecycle_identity(&client) == -1);
	ATF_CHECK_ERRNO(ENOENT, svc_lifecycle_client(NULL, NULL, &request) == -1);
	struct stat st;
	ATF_CHECK_ERRNO(ENOENT, stat("state/state", &st) == -1);
	ATF_CHECK_ERRNO(ENOENT, stat("state/lock", &st) == -1);
	/* Explicit installer migration supplies the missing identity. */
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_adopt(&db, client.manifest.label, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	count = db.count;
	sl_close(&db);
	ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
	ATF_CHECK_EQ(0, memcmp(generation, client.installation, sizeof(generation)));
	ATF_REQUIRE_EQ(0, svc_lifecycle_client(&client, NULL, &request));
	ATF_CHECK_ERRNO(ENOENT, svc_lifecycle_client(NULL, NULL, &request) == -1);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_CHECK_EQ(count, db.count);
	sl_close(&db);
	/* Ambient sessions are registered by the runtime package, not a lookup. */
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install(&db, request.client_label, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, svc_lifecycle_client(NULL, NULL, &request));
	ATF_CHECK_EQ(0, memcmp(generation, request.generation, sizeof(generation)));
}

ATF_TC_WITHOUT_HEAD(runtime_upgrade_preserves_identity);
ATF_TC_BODY(runtime_upgrade_preserves_identity, tc)
{
	struct sl_db db;
	struct svc_new_client_msg request = {0};
	char operation[33];
	uint8_t generation[16];

	ATF_REQUIRE_EQ(0, unsetenv("SWITCHBOARD_EXPERIMENTAL_RECLAIM"));
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, setenv("SWITCHBOARD_LIFECYCLE_DIR", "state", 1));
	strlcpy(client.manifest.label, "org.test.app/worker", sizeof(client.manifest.label));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, operation));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, client.manifest.label, "pkg.app", operation));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, client.manifest.label, operation, false));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
	memcpy(generation, client.installation, sizeof(generation));
	for (unsigned cancel = 0; cancel <= 1; cancel++) {
		ATF_REQUIRE_EQ(0, sl_open("state", &db));
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, operation));
		ATF_REQUIRE_EQ(0, sl_install_begin(&db, client.manifest.label, "pkg.app", operation));
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_CHECK_ERRNO(EBUSY, svc_lifecycle_identity(&client) == -1);
		ATF_CHECK_ERRNO(EBUSY, svc_lifecycle_client(&client, NULL, &request) == -1);
		ATF_REQUIRE_EQ(0, sl_open("state", &db));
		ATF_REQUIRE_EQ(0, sl_install_finish(&db, client.manifest.label, operation, cancel));
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_REQUIRE_EQ(0, svc_lifecycle_identity(&client));
		ATF_REQUIRE_EQ(0, svc_lifecycle_client(&client, NULL, &request));
		ATF_CHECK_EQ(0, memcmp(generation, client.installation, sizeof(generation)));
		ATF_CHECK_EQ(0, memcmp(generation, request.generation, sizeof(generation)));
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, runtime_requires_explicit_registration);
	ATF_TP_ADD_TC(tp, runtime_upgrade_preserves_identity);
	ATF_TP_ADD_TC(tp, authority_does_not_schedule_cleanup);
	ATF_TP_ADD_TC(tp, offline_replay_and_late_receipt);
	ATF_TP_ADD_TC(tp, session_records_only_its_provider);
	return (atf_no_error());
}

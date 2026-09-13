/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/stat.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "switchboard_lifecycle.h"
#include "switchboard_reclamation.h"

static const char owner[] = "org.test.app/worker";
static const char provider1[] = "system.First/provider";
static const char provider2[] = "system.Second/provider";

static void setup(struct sl_db *db)
{
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, sl_open("state", db));
}

ATF_TC_WITHOUT_HEAD(generation_barrier_and_replay);
ATF_TC_BODY(generation_barrier_and_replay, tc)
{
	struct sl_db db;
	uint8_t old[16], current[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider2));
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, old));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, current));
	ATF_CHECK_EQ(0, memcmp(old, current, sizeof(old)));
	ATF_CHECK_ERRNO(EBUSY, sl_adopt(&db, owner, current) == -1);
	ATF_REQUIRE_EQ(0, sl_retire(&db, owner, old));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, old));
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, old));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);

	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK(!sl_blocked(&db, owner));
	ATF_CHECK_EQ(SL_RETIRED, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, old));
	ATF_CHECK_EQ(SL_RETIRED, sl_generation(&db, owner, old)->phase);
	ATF_CHECK_ERRNO(EPERM, sl_ack(&db, owner, "org.stranger/unit", old) == -1);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider2, old));
	ATF_CHECK_EQ(SL_COMPLETE, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);

	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_ERRNO(ESTALE, sl_adopt(&db, owner, current) == -1);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, current));
	ATF_CHECK(memcmp(old, current, sizeof(old)) != 0);
	ATF_CHECK_EQ(0, sl_retire(&db, owner, old));
	ATF_CHECK_EQ(0, sl_ack(&db, owner, provider2, old));
	ATF_CHECK_EQ(SL_ACTIVE, sl_owner(&db, owner)->phase);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(failed_publication_keeps_barrier);
ATF_TC_BODY(failed_publication_keeps_barrier, tc)
{
	struct sl_db db;
	uint8_t generation[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_retire(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, generation));
	ATF_REQUIRE_EQ(0, rename("state/state", "state/saved"));
	ATF_REQUIRE_EQ(0, mkdir("state/state", 0700));
	ATF_REQUIRE_EQ(-1, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, rmdir("state/state"));
	ATF_REQUIRE_EQ(0, rename("state/saved", "state/state"));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_EQ(SL_RETIRED, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK(!sl_blocked(&db, owner));
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(corruption_and_symlinks_fail_closed);
ATF_TC_BODY(corruption_and_symlinks_fail_closed, tc)
{
	struct sl_db db;
	uint8_t generation[16];

	setup(&db);
	ATF_CHECK_ERRNO(ESTALE, sl_prepare(&db, owner, generation) == -1);
	ATF_CHECK(sl_owner(&db, owner) == NULL);
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, truncate("state/state", 3));
	ATF_CHECK_EQ(-1, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, unlink("state/state"));
	ATF_REQUIRE_EQ(0, symlink("lock", "state/state"));
	ATF_CHECK_EQ(-1, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, chmod("state", 0777));
	ATF_CHECK_ERRNO(EPERM, sl_open("state", &db) == -1);
}

ATF_TC_WITHOUT_HEAD(invalid_identity_and_generation);
ATF_TC_BODY(invalid_identity_and_generation, tc)
{
	uint8_t generation[16];
	char text[33];

	ATF_CHECK(!sl_label_valid("../escape"));
	ATF_CHECK(!sl_label_valid("bad label"));
	ATF_CHECK(!sl_label_valid(""));
	ATF_REQUIRE_EQ(0, sl_generation_parse("0123456789abcdef0123456789abcdef", generation));
	sl_generation_format(generation, text);
	ATF_CHECK_STREQ("0123456789abcdef0123456789abcdef", text);
	ATF_CHECK_EQ(-1, sl_generation_parse("00000000000000000000000000000000", generation));
	ATF_CHECK_EQ(-1, sl_generation_parse("0123456789abcdef0123456789abcdeg", generation));
}

ATF_TC_WITHOUT_HEAD(reinstall_while_cleanup_pending);
ATF_TC_BODY(reinstall_while_cleanup_pending, tc)
{
	struct sl_db db;
	uint8_t old[16], fresh[16], same[16];
	char old_owner[64], new_owner[64];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, old));
	ATF_CHECK_STREQ(owner, sl_owner(&db, owner)->provider);
	strlcpy(old_owner, sl_owner(&db, owner)->provider, sizeof(old_owner));
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, same));
	ATF_REQUIRE_EQ(0, sl_retire(&db, owner, old));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, old));
	ATF_CHECK_ERRNO(ESTALE, sl_adopt(&db, owner, fresh) == -1);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, fresh));
	ATF_REQUIRE(memcmp(old, fresh, sizeof(old)) != 0);
	strlcpy(new_owner, sl_owner(&db, owner)->provider, sizeof(new_owner));
	ATF_CHECK(strcmp(old_owner, new_owner) != 0);
	ATF_CHECK_EQ(0, strncmp(new_owner, "install.", 8));
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, same));
	ATF_CHECK_EQ(0, memcmp(fresh, same, sizeof(same)));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, old));
	ATF_CHECK_EQ(SL_COMPLETE, sl_generation(&db, owner, old)->phase);
	ATF_CHECK_EQ(SL_ACTIVE, sl_generation(&db, owner, fresh)->phase);
	ATF_CHECK_STREQ(new_owner, sl_owner(&db, owner)->provider);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(lost_state_and_bit_corruption_fail_closed);
ATF_TC_BODY(lost_state_and_bit_corruption_fail_closed, tc)
{
	struct sl_db db;
	uint8_t generation[16], byte;
	int fd;

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	fd = open("state/state", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 40));
	byte ^= 1;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 40));
	close(fd);
	ATF_CHECK_ERRNO(EILSEQ, sl_open("state", &db) == -1);
	ATF_REQUIRE_EQ(0, unlink("state/state"));
	ATF_CHECK_ERRNO(EIO, sl_open("state", &db) == -1);
}


static const char op1[] = "11111111111111111111111111111111";
static const char op2[] = "22222222222222222222222222222222";
static const char op3[] = "33333333333333333333333333333333";
static const char op4[] = "44444444444444444444444444444444";

ATF_TC_WITHOUT_HEAD(delayed_transaction_during_replacement_removal);
ATF_TC_BODY(delayed_transaction_during_replacement_removal, tc)
{
	struct sl_db db;
	uint8_t old[16], fresh[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.app", op1));
	ATF_CHECK_ERRNO(EBUSY, sl_adopt(&db, owner, old) == -1);
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op1, false));
	memcpy(old, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.app", op2));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op2, false));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.app", op3));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op3, false));
	memcpy(fresh, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE(memcmp(old, fresh, 16) != 0);
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.app", op4));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	/* Old prepare and completion must never resolve the latest owner. */
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.app", op2));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op2, false));
	ATF_CHECK_EQ(SL_PREPARED, sl_generation(&db, owner, fresh)->phase);
	ATF_CHECK_EQ(SL_REMOVE_PENDING, sl_operation(&db, owner, op4)->phase);
	ATF_CHECK_ERRNO(ECANCELED, sl_remove_finish(&db, owner, op2, true) == -1);
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op4, true));
	ATF_CHECK_ERRNO(ECANCELED, sl_remove_finish(&db, owner, op4, false) == -1);
	ATF_CHECK_EQ(SL_ACTIVE, sl_generation(&db, owner, fresh)->phase);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(version_references_and_interrupted_publication);
ATF_TC_BODY(version_references_and_interrupted_publication, tc)
{
	struct sl_db db;
	uint8_t generation[16], same[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "bundle.v1", op1));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_ERRNO(EBUSY, sl_adopt(&db, owner, generation) == -1);
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op1, false));
	memcpy(generation, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "bundle.v2", op2));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op2, false));
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, same));
	ATF_CHECK_EQ(0, memcmp(generation, same, 16));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "bundle.v1", op3));
	ATF_CHECK_EQ(SL_ACTIVE, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op3, false));
	ATF_CHECK_EQ(SL_ACTIVE, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "bundle.v2", op4));
	ATF_CHECK_EQ(SL_PREPARED, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op4, false));
	ATF_CHECK_EQ(SL_COMPLETE, sl_owner(&db, owner)->phase);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(cancelled_upgrade_preserves_reference);
ATF_TC_BODY(cancelled_upgrade_preserves_reference, tc)
{
	struct sl_db db;
	uint8_t old[16], current[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", op1));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op1, false));
	memcpy(old, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", op2));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op2, true));
	ATF_REQUIRE_EQ(0, sl_adopt(&db, owner, current));
	ATF_CHECK_EQ(0, memcmp(old, current, 16));
	ATF_CHECK_ERRNO(ECANCELED, sl_install_finish(&db, owner, op2, false) == -1);
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.slot", op3));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op3, false));
	ATF_CHECK_EQ(SL_COMPLETE, sl_owner(&db, owner)->phase);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(empty_cleanup_batch_is_durably_complete);
ATF_TC_BODY(empty_cleanup_batch_is_durably_complete, tc)
{
	struct sl_db db;
	uint8_t id[16];
	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, id));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, id));
	ATF_REQUIRE_EQ(0, sl_retire(&db, owner, id));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, id));
	ATF_CHECK_EQ(SL_COMPLETE, sl_owner(&db, owner)->phase);
	ATF_CHECK_STREQ(SL_CLEANUP_COMPLETE, sl_owner(&db, owner)->reference);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_CHECK_STREQ(SL_CLEANUP_COMPLETE, sl_owner(&db, owner)->reference);
	ATF_CHECK_ERRNO(EROFS, sl_cleanup_prepare(&db, owner, id) == -1);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(cleanup_history_is_bounded_pending_survives);
ATF_TC_BODY(cleanup_history_is_bounded_pending_survives, tc)
{
	struct sl_db db;
	uint8_t id[16], pending[16];
	char operation[33];
	setup(&db);
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	for (unsigned n = 0; n < 350; n++) {
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, operation));
		ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.test", operation));
		ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, operation, false));
		memcpy(id, sl_owner(&db, owner)->generation, sizeof(id));
		if (n == 0)
			memcpy(pending, id, sizeof(id));
		ATF_REQUIRE_EQ(0, sl_track_holding(&db, owner, provider1, id));
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, operation));
		ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.test", operation));
		ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, operation, false));
		ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, id));
		if (n != 0)
			ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, id));
		ATF_REQUIRE_EQ(0, sl_commit(&db));
	}
	ATF_CHECK(db.count < 2048);
	ATF_REQUIRE(sl_generation(&db, owner, pending) != NULL);
	ATF_CHECK_EQ(SL_RETIRED, sl_generation(&db, owner, pending)->phase);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, pending));
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, NULL));
	ATF_CHECK(sl_generation(&db, owner, pending) == NULL);
	ATF_CHECK(db.count < 20);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(pretracking_installations_use_all_providers);
ATF_TC_BODY(pretracking_installations_use_all_providers, tc)
{
	struct sl_db db;
	uint8_t id[16];
	unsigned deliveries = 0;
	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, id));
	/* An old format-4 owner: modern key, but no tracking contract. Even a
	 * later tracked delegation cannot prove other providers hold nothing. */
	sl_owner(&db, owner)->reference[0] = '\0';
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider1));
	ATF_REQUIRE_EQ(0, sl_register_provider(&db, provider2));
	ATF_REQUIRE_EQ(0, sl_track_holding(&db, owner, provider1, id));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, owner, id));
	ATF_REQUIRE_EQ(0, sl_retire(&db, owner, id));
	ATF_REQUIRE_EQ(0, sl_cleanup_prepare(&db, owner, id));
	for (size_t i = 0; i < db.count; i++)
		deliveries += db.records[i].kind == SL_DELIVERY;
	ATF_CHECK_EQ(2, deliveries);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider1, id));
	ATF_CHECK_EQ(SL_RETIRED, sl_owner(&db, owner)->phase);
	ATF_REQUIRE_EQ(0, sl_ack(&db, owner, provider2, id));
	ATF_CHECK_STREQ(SL_CLEANUP_COMPLETE, sl_owner(&db, owner)->reference);
	sl_close(&db);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pretracking_installations_use_all_providers);
	ATF_TP_ADD_TC(tp, empty_cleanup_batch_is_durably_complete);
	ATF_TP_ADD_TC(tp, cleanup_history_is_bounded_pending_survives);
	ATF_TP_ADD_TC(tp, delayed_transaction_during_replacement_removal);
	ATF_TP_ADD_TC(tp, version_references_and_interrupted_publication);
	ATF_TP_ADD_TC(tp, cancelled_upgrade_preserves_reference);
	ATF_TP_ADD_TC(tp, reinstall_while_cleanup_pending);
	ATF_TP_ADD_TC(tp, lost_state_and_bit_corruption_fail_closed);
	ATF_TP_ADD_TC(tp, generation_barrier_and_replay);
	ATF_TP_ADD_TC(tp, failed_publication_keeps_barrier);
	ATF_TP_ADD_TC(tp, corruption_and_symlinks_fail_closed);
	ATF_TP_ADD_TC(tp, invalid_identity_and_generation);
	return (atf_no_error());
}

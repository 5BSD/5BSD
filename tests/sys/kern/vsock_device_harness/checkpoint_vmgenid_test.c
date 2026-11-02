/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ACPI VM Generation ID semantics of bhyve checkpoint restore and live
 * migration (usr.sbin/bhyve/checkpoint_vmgenid.c).
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checkpoint_vmgenid.c"

static const struct checkpoint_acpi_pm source_pm = {
	.pm1_enable = 0x0120, .pm1_status = 0, .pm1_control = 0x0001,
	.gpe0_enable = 1, .gpe0_status = 0, .sci_active = false,
};

static void
checkpoint_image(struct checkpoint_vmgenid *saved)
{
	char text[CHECKPOINT_VMGENID_TEXT_SIZE];
	struct checkpoint_vmgenid source;

	memset(&source, 0, sizeof(source));
	ATF_REQUIRE_EQ(getentropy(source.id, sizeof(source.id)), 0);
	source.pm = source_pm;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_encode(&source, text, sizeof(text)), 0);
	ATF_REQUIRE_EQ(checkpoint_vmgenid_decode(text, saved), 0);
	ATF_REQUIRE(memcmp(saved->id, source.id, sizeof(source.id)) == 0);
}

static int
real_entropy(void *buf, size_t len)
{
	return (getentropy(buf, len) == 0 ? 0 : errno);
}

ATF_TC_WITHOUT_HEAD(restore_twice_new_notified_ids);
ATF_TC_BODY(restore_twice_new_notified_ids, tc)
{
	struct checkpoint_vmgenid saved;
	uint8_t first[CHECKPOINT_VMGENID_ID_SIZE], second[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;

	checkpoint_image(&saved);
	/* After the fixed-ROM copy the destination page holds saved.id. */
	notify = false;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE,
	    &saved, saved.id, real_entropy, first, &notify), 0);
	ATF_CHECK(notify);
	notify = false;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE,
	    &saved, saved.id, real_entropy, second, &notify), 0);
	ATF_CHECK(notify);
	ATF_CHECK(memcmp(first, saved.id, sizeof(first)) != 0);
	ATF_CHECK(memcmp(second, saved.id, sizeof(second)) != 0);
	ATF_CHECK(memcmp(first, second, sizeof(first)) != 0);
}

static const uint8_t *repeat_id;
static int repeats;

static int
repeating_entropy(void *buf, size_t len)
{
	if (repeats > 0) {
		repeats--;
		memcpy(buf, repeat_id, len);
		return (0);
	}
	return (getentropy(buf, len) == 0 ? 0 : errno);
}

ATF_TC_WITHOUT_HEAD(restore_never_repeats_checkpoint_id);
ATF_TC_BODY(restore_never_repeats_checkpoint_id, tc)
{
	struct checkpoint_vmgenid saved;
	uint8_t current[CHECKPOINT_VMGENID_ID_SIZE] = { 0x55 };
	uint8_t next[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;

	checkpoint_image(&saved);
	repeat_id = saved.id;
	repeats = 3;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE,
	    &saved, current, repeating_entropy, next, &notify), 0);
	ATF_CHECK_EQ(repeats, 0);
	ATF_CHECK(notify && memcmp(next, saved.id, sizeof(next)) != 0);
	repeats = 8;
	ATF_CHECK_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE,
	    &saved, current, repeating_entropy, next, &notify), EAGAIN);
	ATF_CHECK(!notify);
}

ATF_TC_WITHOUT_HEAD(migration_keeps_source_id);
ATF_TC_BODY(migration_keeps_source_id, tc)
{
	struct checkpoint_vmgenid saved;
	uint8_t destination[CHECKPOINT_VMGENID_ID_SIZE];
	uint8_t next[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;

	checkpoint_image(&saved);
	ATF_REQUIRE_EQ(getentropy(destination, sizeof(destination)), 0);
	notify = true;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_MIGRATE,
	    &saved, destination, real_entropy, next, &notify), 0);
	ATF_CHECK(!notify);
	ATF_CHECK(memcmp(next, saved.id, sizeof(next)) == 0);
}

ATF_TC_WITHOUT_HEAD(old_peer_without_record);
ATF_TC_BODY(old_peer_without_record, tc)
{
	uint8_t destination[CHECKPOINT_VMGENID_ID_SIZE];
	uint8_t next[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;

	ATF_REQUIRE_EQ(getentropy(destination, sizeof(destination)), 0);
	/* Migration from an older source: the destination keeps its own ID. */
	notify = true;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_MIGRATE,
	    NULL, destination, real_entropy, next, &notify), 0);
	ATF_CHECK(!notify);
	ATF_CHECK(memcmp(next, destination, sizeof(next)) == 0);
	/* An older checkpoint still restores as a new generation. */
	ATF_REQUIRE_EQ(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE,
	    NULL, destination, real_entropy, next, &notify), 0);
	ATF_CHECK(notify);
	ATF_CHECK(memcmp(next, destination, sizeof(next)) != 0);
}

ATF_TC_WITHOUT_HEAD(record_codec_is_strict);
ATF_TC_BODY(record_codec_is_strict, tc)
{
	struct checkpoint_vmgenid record, decoded;
	char text[CHECKPOINT_VMGENID_TEXT_SIZE];

	memset(&record, 0, sizeof(record));
	for (size_t i = 0; i < sizeof(record.id); i++)
		record.id[i] = (uint8_t)i;
	record.pm = source_pm;
	ATF_REQUIRE_EQ(checkpoint_vmgenid_encode(&record, text, sizeof(text)), 0);
	ATF_CHECK_STREQ(text,
	    "1:000102030405060708090a0b0c0d0e0f:0120:0000:0001:01:00:0");
	ATF_REQUIRE_EQ(checkpoint_vmgenid_decode(text, &decoded), 0);
	ATF_CHECK(memcmp(decoded.id, record.id, sizeof(record.id)) == 0);
	ATF_CHECK_EQ(decoded.pm.gpe0_enable, 1);
	text[0] = '2';
	ATF_CHECK_EQ(checkpoint_vmgenid_decode(text, &decoded), EINVAL);
	ATF_CHECK_EQ(checkpoint_vmgenid_decode("1:", &decoded), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, restore_twice_new_notified_ids);
	ATF_TP_ADD_TC(tp, restore_never_repeats_checkpoint_id);
	ATF_TP_ADD_TC(tp, migration_keeps_source_id);
	ATF_TP_ADD_TC(tp, old_peer_without_record);
	ATF_TP_ADD_TC(tp, record_codec_is_strict);
	return (atf_no_error());
}

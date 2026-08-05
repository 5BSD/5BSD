/*- SPDX-License-Identifier: BSD-2-Clause */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <filesystemcmp.h>
#include <rebootctl.h>

#include "rebootd_state.h"
#include "rebootd_store.h"

struct filesystemcmp_client { int unused; };

static struct filesystemcmp_client fake_client;
static struct rebootd_state_record committed, temporary;
static bool have_committed, have_temporary, fail_file_sync, fail_rename,
    fail_root_sync;

static void
reset_store(void)
{

	memset(&committed, 0, sizeof(committed));
	memset(&temporary, 0, sizeof(temporary));
	have_committed = false;
	have_temporary = false;
	fail_file_sync = false;
	fail_rename = false;
	fail_root_sync = false;
}

int
filesystemcmp_open(struct filesystemcmp_client **client)
{

	*client = &fake_client;
	return (0);
}

void
filesystemcmp_close(struct filesystemcmp_client *client __unused)
{
}

int
filesystemcmp_open_namespace(struct filesystemcmp_client *client __unused,
    uint32_t namespace_id, struct filesystemcmp_handle *root)
{

	if (namespace_id != FILESYSTEMCMP_NAMESPACE_PERSISTENT)
		return (errno = EINVAL, -1);
	*root = (struct filesystemcmp_handle){ .object = 1, .generation = 1 };
	return (0);
}

int
filesystemcmp_lookup(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle root __unused, const char *name,
    struct filesystemcmp_handle_reply *reply)
{

	if (strcmp(name, "schedule") != 0 || !have_committed)
		return (errno = ENOENT, -1);
	reply->handle = (struct filesystemcmp_handle){ .object = 3,
	    .generation = 1 };
	reply->type = FILESYSTEMCMP_TYPE_REGULAR;
	return (0);
}

int
filesystemcmp_stat(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle handle, struct filesystemcmp_stat_reply *reply)
{

	if (handle.object != 3 || !have_committed)
		return (errno = EBADF, -1);
	memset(reply, 0, sizeof(*reply));
	reply->type = FILESYSTEMCMP_TYPE_REGULAR;
	reply->size = sizeof(committed);
	return (0);
}

ssize_t
filesystemcmp_pread(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle handle, void *buffer, size_t length,
    uint64_t offset)
{

	if (handle.object != 3 || !have_committed || offset != 0 ||
	    length != sizeof(committed))
		return (errno = EINVAL, -1);
	memcpy(buffer, &committed, sizeof(committed));
	return (sizeof(committed));
}

int
filesystemcmp_unlink(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle root __unused, const char *name,
    uint32_t flags __unused)
{

	if (strcmp(name, "schedule.new") != 0 || !have_temporary)
		return (errno = ENOENT, -1);
	have_temporary = false;
	return (0);
}

int
filesystemcmp_create(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle root __unused, const char *name,
    uint32_t flags, uint32_t mode, struct filesystemcmp_handle_reply *reply)
{

	if (strcmp(name, "schedule.new") != 0 ||
	    flags != FILESYSTEMCMP_CREATE_EXCLUSIVE || mode != 0600 ||
	    have_temporary)
		return (errno = EINVAL, -1);
	have_temporary = true;
	memset(&temporary, 0, sizeof(temporary));
	reply->handle = (struct filesystemcmp_handle){ .object = 2,
	    .generation = 1 };
	reply->type = FILESYSTEMCMP_TYPE_REGULAR;
	return (0);
}

ssize_t
filesystemcmp_pwrite(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle handle, const void *buffer, size_t length,
    uint64_t offset)
{

	if (handle.object != 2 || !have_temporary || offset != 0 ||
	    length != sizeof(temporary))
		return (errno = EINVAL, -1);
	memcpy(&temporary, buffer, sizeof(temporary));
	return (sizeof(temporary));
}

int
filesystemcmp_sync(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle handle)
{

	if (handle.object == 2 && fail_file_sync)
		return (errno = EIO, -1);
	if (handle.object == 1 && fail_root_sync)
		return (errno = EIO, -1);
	return (0);
}

int
filesystemcmp_close_handle(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle handle __unused)
{

	return (0);
}

int
filesystemcmp_rename(struct filesystemcmp_client *client __unused,
    struct filesystemcmp_handle old_root __unused, const char *old_name,
    struct filesystemcmp_handle new_root __unused, const char *new_name,
    uint32_t flags)
{

	if (strcmp(old_name, "schedule.new") != 0 ||
	    strcmp(new_name, "schedule") != 0 || flags != 0 || !have_temporary)
		return (errno = EINVAL, -1);
	if (fail_rename)
		return (errno = EIO, -1);
	committed = temporary;
	have_committed = true;
	have_temporary = false;
	return (0);
}

static struct rebootd_state_record
record(uint64_t request_id)
{
	struct rebootd_state_record value;

	memset(&value, 0, sizeof(value));
	if (request_id != 0) {
		value.active = 1;
		value.next_request_id = request_id;
		value.request_id = request_id;
		value.requested_at_ns = 10;
		value.execute_at_ns = 20;
		value.opcode = REBOOTCTL_OP_SHUTDOWN;
		value.requester_length = 8;
		memcpy(value.requester, "org.test", 8);
	}
	rebootd_state_seal(&value);
	return (value);
}

ATF_TC_WITHOUT_HEAD(create_save_and_reload);
ATF_TC_BODY(create_save_and_reload, tc)
{
	struct rebootd_state_record loaded, wanted;
	struct rebootd_store *store;

	(void)tc;
	reset_store();
	ATF_REQUIRE_EQ(0, rebootd_store_open(&store));
	ATF_REQUIRE_EQ(0, rebootd_store_load(store, &loaded));
	ATF_CHECK(rebootd_state_valid(&loaded));
	ATF_CHECK_EQ(0, loaded.active);
	wanted = record(7);
	ATF_REQUIRE_EQ(0, rebootd_store_save(store, &wanted, NULL));
	memset(&loaded, 0, sizeof(loaded));
	ATF_REQUIRE_EQ(0, rebootd_store_load(store, &loaded));
	ATF_CHECK_EQ(0, memcmp(&wanted, &loaded, sizeof(wanted)));
	rebootd_store_close(store);
}

ATF_TC_WITHOUT_HEAD(sync_failure_preserves_committed_record);
ATF_TC_BODY(sync_failure_preserves_committed_record, tc)
{
	struct rebootd_state_record first, second;
	struct rebootd_store *store;

	(void)tc;
	reset_store();
	ATF_REQUIRE_EQ(0, rebootd_store_open(&store));
	first = record(1);
	ATF_REQUIRE_EQ(0, rebootd_store_save(store, &first, NULL));
	second = record(2);
	fail_file_sync = true;
	ATF_CHECK_ERRNO(EIO, rebootd_store_save(store, &second, NULL) == -1);
	ATF_CHECK_EQ(0, memcmp(&first, &committed, sizeof(first)));
	ATF_CHECK(!have_temporary);
	rebootd_store_close(store);
}

ATF_TC_WITHOUT_HEAD(rename_failure_preserves_committed_record);
ATF_TC_BODY(rename_failure_preserves_committed_record, tc)
{
	struct rebootd_state_record first, second;
	struct rebootd_store *store;

	(void)tc;
	reset_store();
	ATF_REQUIRE_EQ(0, rebootd_store_open(&store));
	first = record(1);
	ATF_REQUIRE_EQ(0, rebootd_store_save(store, &first, NULL));
	second = record(2);
	fail_rename = true;
	ATF_CHECK_ERRNO(EIO, rebootd_store_save(store, &second, NULL) == -1);
	ATF_CHECK_EQ(0, memcmp(&first, &committed, sizeof(first)));
	ATF_CHECK(!have_temporary);
	rebootd_store_close(store);
}

ATF_TC_WITHOUT_HEAD(root_sync_failure_reports_visible_commit);
ATF_TC_BODY(root_sync_failure_reports_visible_commit, tc)
{
	struct rebootd_state_record first, second;
	struct rebootd_store *store;
	enum rebootd_store_commit commit;

	(void)tc;
	reset_store();
	ATF_REQUIRE_EQ(0, rebootd_store_open(&store));
	first = record(1);
	ATF_REQUIRE_EQ(0, rebootd_store_save(store, &first, NULL));
	second = record(2);
	fail_root_sync = true;
	ATF_CHECK_ERRNO(EIO, rebootd_store_save(store, &second, &commit) == -1);
	ATF_CHECK_EQ(REBOOTD_STORE_VISIBLE, commit);
	/* rename is visible even when its durability sync reports failure. */
	ATF_CHECK_EQ(0, memcmp(&second, &committed, sizeof(second)));
	ATF_CHECK(!have_temporary);
	rebootd_store_close(store);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, create_save_and_reload);
	ATF_TP_ADD_TC(tp, sync_failure_preserves_committed_record);
	ATF_TP_ADD_TC(tp, rename_failure_preserves_committed_record);
	ATF_TP_ADD_TC(tp, root_sync_failure_reports_visible_commit);
	return (atf_no_error());
}

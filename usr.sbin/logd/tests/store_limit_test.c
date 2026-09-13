/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "store.h"

static ssize_t
read_metadata(int dirfd, uint8_t *buffer, size_t capacity)
{
	ssize_t length;
	int fd;

	fd = openat(dirfd, "reclaim.meta", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	length = read(fd, buffer, capacity);
	ATF_REQUIRE(length > 0 && (size_t)length < capacity);
	ATF_REQUIRE_EQ(0, close(fd));
	return (length);
}

ATF_TC_WITHOUT_HEAD(full_retirement_metadata_remains_reopenable);
ATF_TC_BODY(full_retirement_metadata_remains_reopenable, tc)
{
	struct logcmp_store *store;
	uint8_t before[512], after[512];
	char owner[32];
	ssize_t length;
	int dirfd;

	(void)tc;
	ATF_REQUIRE_EQ(0, mkdir("store", 0700));
	dirfd = open("store", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE_EQ(0, logcmp_store_open(dirfd, LOGCMP_STORE_SEGMENT_MIN,
	    LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	/* This target compiles the real store with a four-entry format limit. */
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "owner.0"));
	for (int i = 1; i < 4; i++) {
		snprintf(owner, sizeof(owner), "owner.%d", i);
		ATF_REQUIRE_EQ(0, logcmp_store_retire_owner(store, owner));
	}
	length = read_metadata(dirfd, before, sizeof(before));
	ATF_REQUIRE_ERRNO(ENOSPC,
	    logcmp_store_retire_owner(store, "owner.extra") == -1);
	ATF_REQUIRE_ERRNO(ENOSPC,
	    logcmp_store_reclaim_label(store, "label.extra") == -1);
	ATF_REQUIRE_EQ(length, read_metadata(dirfd, after, sizeof(after)));
	ATF_REQUIRE_EQ(0, memcmp(before, after, (size_t)length));
	logcmp_store_close(store);

	ATF_REQUIRE_EQ(0, logcmp_store_open(dirfd, LOGCMP_STORE_SEGMENT_MIN,
	    LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	/* Existing work and retries still succeed when no new slot is available. */
	ATF_REQUIRE_EQ(0, logcmp_store_retire_owner(store, "owner.0"));
	ATF_REQUIRE_EQ(0, logcmp_store_retire_owner(store, "owner.3"));
	ATF_REQUIRE_ERRNO(ENOSPC,
	    logcmp_store_retire_owner(store, "owner.extra") == -1);
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, logcmp_store_open(dirfd, LOGCMP_STORE_SEGMENT_MIN,
	    LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_REQUIRE_EQ(0, logcmp_store_retire_owner(store, "owner.0"));
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, close(dirfd));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, full_retirement_metadata_remains_reopenable);
	return (atf_no_error());
}

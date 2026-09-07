/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logcmp.h>
#include <logcmp_server.h>

#include "store.h"

struct fixture {
	char path[PATH_MAX];
	int dirfd;
};

static void
fixture_create(struct fixture *fixture)
{

	strlcpy(fixture->path, "store.XXXXXX", sizeof(fixture->path));
	ATF_REQUIRE(mkdtemp(fixture->path) != NULL);
	fixture->dirfd = open(fixture->path,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fixture->dirfd >= 0);
}

static void
fixture_destroy(struct fixture *fixture)
{
	int fd;
	char name[PATH_MAX];
	DIR *directory;
	struct dirent *entry;

	fd = openat(fixture->dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	directory = fdopendir(fd);
	ATF_REQUIRE(directory != NULL);
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		strlcpy(name, entry->d_name, sizeof(name));
		ATF_REQUIRE_EQ(0, unlinkat(fixture->dirfd, name, 0));
	}
	closedir(directory);
	close(fixture->dirfd);
	ATF_REQUIRE_EQ(0, rmdir(fixture->path));
}

static size_t
make_record(uint8_t *buffer, const char *message, uint32_t privacy,
    const char *attribute_value, uint32_t attribute_privacy)
{
	static const char subsystem[] = "tests.store";
	static const char category[] = "persistence";
	static const char key[] = "credential";
	struct logcmp_attribute_wire attribute;
	struct logcmp_record *record;
	uint8_t *cursor;
	size_t message_length, value_length;

	message_length = strlen(message);
	value_length = strlen(attribute_value);
	record = (void *)buffer;
	memset(record, 0, sizeof(*record));
	record->sequence = 1;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = privacy;
	record->subsystem_length = sizeof(subsystem) - 1;
	record->category_length = sizeof(category) - 1;
	record->message_length = message_length;
	record->attribute_count = 1;
	record->attributes_length = sizeof(attribute) + sizeof(key) - 1 +
	    value_length;
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, sizeof(subsystem) - 1);
	cursor += sizeof(subsystem) - 1;
	memcpy(cursor, category, sizeof(category) - 1);
	cursor += sizeof(category) - 1;
	memcpy(cursor, message, message_length);
	cursor += message_length;
	memset(&attribute, 0, sizeof(attribute));
	attribute.key_length = sizeof(key) - 1;
	attribute.type = LOGCMP_ATTR_STRING;
	attribute.privacy = attribute_privacy;
	attribute.value_length = value_length;
	memcpy(cursor, &attribute, sizeof(attribute));
	cursor += sizeof(attribute);
	memcpy(cursor, key, sizeof(key) - 1);
	cursor += sizeof(key) - 1;
	memcpy(cursor, attribute_value, value_length);
	cursor += value_length;
	ATF_REQUIRE_EQ(0, logcmp_validate_record(record, cursor - buffer));
	return (cursor - buffer);
}

/*
 * Build a record with caller-chosen subsystem, category, timestamp, severity,
 * and sequence so filter tests can distinguish records.  subsystem/category
 * must be valid identifiers (validated by logcmp_validate_record).
 */
static size_t
make_named_record(uint8_t *buffer, uint64_t sequence, uint64_t timestamp_ns,
    uint32_t severity, const char *subsystem, const char *category,
    const char *message)
{
	struct logcmp_record *record;
	uint8_t *cursor;
	size_t subsystem_length, category_length, message_length;

	subsystem_length = strlen(subsystem);
	category_length = strlen(category);
	message_length = strlen(message);
	record = (void *)buffer;
	memset(record, 0, sizeof(*record));
	record->sequence = sequence;
	record->timestamp_ns = timestamp_ns;
	record->severity = severity;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = (uint16_t)subsystem_length;
	record->category_length = (uint16_t)category_length;
	record->message_length = (uint32_t)message_length;
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, subsystem_length);
	cursor += subsystem_length;
	memcpy(cursor, category, category_length);
	cursor += category_length;
	memcpy(cursor, message, message_length);
	cursor += message_length;
	ATF_REQUIRE_EQ(0, logcmp_validate_record(record, cursor - buffer));
	return (cursor - buffer);
}

static int
filtered_next(struct logcmp_store *store, const char *label, uint32_t severity,
    uint64_t from_ns, uint64_t to_ns, uint32_t match_flags,
    const char *subsystem, const char *category,
    struct logcmp_store_cursor *cursor, uint8_t *output, size_t *output_length)
{
	struct logcmp_query_filter filter;

	memset(&filter, 0, sizeof(filter));
	filter.from_ns = from_ns;
	filter.to_ns = to_ns;
	filter.match_flags = match_flags;
	if (subsystem != NULL) {
		filter.subsystem = subsystem;
		filter.subsystem_length = (uint16_t)strlen(subsystem);
	}
	if (category != NULL) {
		filter.category = category;
		filter.category_length = (uint16_t)strlen(category);
	}
	return (logcmp_store_query_next_filtered(store, label, severity, &filter,
	    cursor, output, LOGCMP_MAX_RECORD, output_length));
}

static bool
file_contains(int dirfd, const char *needle)
{
	struct stat status;
	char *buffer;
	int fd;
	bool found;

	fd = openat(dirfd, "active.segment", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &status));
	buffer = malloc((size_t)status.st_size + 1);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE_EQ(status.st_size, read(fd, buffer, status.st_size));
	buffer[status.st_size] = '\0';
	found = memmem(buffer, status.st_size, needle, strlen(needle)) != NULL;
	free(buffer);
	close(fd);
	return (found);
}

ATF_TC_WITHOUT_HEAD(redacts_private_values);
ATF_TC_BODY(redacts_private_values, tc)
{
	uint8_t source[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	uint8_t key[LOGCMP_STORE_PRIVACY_KEY_SIZE];
	struct logcmp_record *record;
	size_t length, output_length;

	memset(key, 0x5a, sizeof(key));
	length = make_record(source, "message-secret", LOGCMP_PRIVACY_PRIVATE,
	    "attribute-secret", LOGCMP_PRIVACY_PRIVATE_HASH);
	ATF_REQUIRE_EQ(0, logcmp_record_redact((const void *)source, length,
	    key, output, sizeof(output), &output_length));
	record = (void *)output;
	ATF_CHECK_EQ(LOGCMP_PRIVACY_PRIVATE, record->message_privacy);
	ATF_CHECK_EQ(0, logcmp_validate_record(record, output_length));
	ATF_CHECK(memmem(output, output_length, "message-secret", 14) == NULL);
	ATF_CHECK(memmem(output, output_length, "attribute-secret", 16) == NULL);
	ATF_CHECK(memmem(output, output_length, "<private>", 9) != NULL);
	ATF_CHECK(memmem(output, output_length, "<private:", 9) != NULL);
	ATF_CHECK(memmem(output, output_length, "attribute-secret", 16) == NULL);
	ATF_CHECK_ERRNO(EMSGSIZE, logcmp_record_redact((const void *)source,
	    length, key, output, sizeof(*record), &output_length) == -1);
}

ATF_TC_WITHOUT_HEAD(private_hash_is_keyed_and_stable);
ATF_TC_BODY(private_hash_is_keyed_and_stable, tc)
{
	uint8_t source[LOGCMP_MAX_RECORD], first[LOGCMP_MAX_RECORD];
	uint8_t second[LOGCMP_MAX_RECORD], third[LOGCMP_MAX_RECORD];
	uint8_t first_key[LOGCMP_STORE_PRIVACY_KEY_SIZE];
	uint8_t second_key[LOGCMP_STORE_PRIVACY_KEY_SIZE];
	size_t length, first_length, second_length, third_length;

	memset(first_key, 0x11, sizeof(first_key));
	memset(second_key, 0x22, sizeof(second_key));
	length = make_record(source, "same-secret", LOGCMP_PRIVACY_PRIVATE_HASH,
	    "same-secret", LOGCMP_PRIVACY_PRIVATE_HASH);
	ATF_REQUIRE_EQ(0, logcmp_record_redact((const void *)source, length,
	    first_key, first, sizeof(first), &first_length));
	ATF_REQUIRE_EQ(0, logcmp_record_redact((const void *)source, length,
	    first_key, second, sizeof(second), &second_length));
	ATF_REQUIRE_EQ(0, logcmp_record_redact((const void *)source, length,
	    second_key, third, sizeof(third), &third_length));
	ATF_CHECK_EQ(first_length, second_length);
	ATF_CHECK_EQ(first_length, third_length);
	ATF_CHECK_EQ(0, memcmp(first, second, first_length));
	ATF_CHECK(memcmp(first, third, first_length) != 0);
	ATF_CHECK(memmem(first, first_length, "same-secret", 11) == NULL);
}

ATF_TC_WITHOUT_HEAD(append_reopen_and_privacy);
ATF_TC_BODY(append_reopen_and_privacy, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD];
	off_t offset;
	size_t length;

	fixture_create(&fixture);
	length = make_record(record, "do-not-store", LOGCMP_PRIVACY_PRIVATE,
	    "also-private", LOGCMP_PRIVACY_PRIVATE);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(1, logcmp_store_generation(store));
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/client",
	    (const void *)record, length, true));
	offset = logcmp_store_offset(store);
	ATF_CHECK(offset > 32);
	logcmp_store_close(store);
	ATF_CHECK(!file_contains(fixture.dirfd, "do-not-store"));
	ATF_CHECK(!file_contains(fixture.dirfd, "also-private"));
	ATF_CHECK(file_contains(fixture.dirfd, "<private>"));
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(offset, logcmp_store_offset(store));
	ATF_REQUIRE_EQ(0, logcmp_store_flush(store));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(torn_tail_is_truncated);
ATF_TC_BODY(torn_tail_is_truncated, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t garbage[11] = { 1, 2, 3 };
	int fd;
	off_t good;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	good = logcmp_store_offset(store);
	logcmp_store_close(store);
	fd = openat(fixture.dirfd, "active.segment", O_WRONLY | O_APPEND);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(garbage), write(fd, garbage, sizeof(garbage)));
	close(fd);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(good, logcmp_store_offset(store));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(corruption_is_not_silently_truncated);
ATF_TC_BODY(corruption_is_not_silently_truncated, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], byte;
	int fd;
	size_t length;

	fixture_create(&fixture);
	length = make_record(record, "public", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
	    (const void *)record, length, false));
	logcmp_store_close(store);
	fd = openat(fixture.dirfd, "active.segment", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 60));
	byte ^= 0x80;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 60));
	close(fd);
	ATF_CHECK_ERRNO(EILSEQ, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store) == -1);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(rejects_corrupt_file_header);
ATF_TC_BODY(rejects_corrupt_file_header, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t byte;
	int fd;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	logcmp_store_close(store);
	fd = openat(fixture.dirfd, "active.segment", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 0));
	byte ^= 0xff;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 0));
	close(fd);
	ATF_CHECK_ERRNO(EILSEQ, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store) == -1);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(incomplete_record_body_is_truncated);
ATF_TC_BODY(incomplete_record_body_is_truncated, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t header[24], body[7] = { 0 };
	struct iovec iov[2];
	int fd;
	off_t good;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	good = logcmp_store_offset(store);
	logcmp_store_close(store);
	memset(header, 0, sizeof(header));
	le32enc(header, 0x4c524543U);
	le16enc(header + 4, 1);
	le16enc(header + 6, sizeof(header));
	le32enc(header + 8, 128);
	iov[0] = (struct iovec){ .iov_base = header, .iov_len = sizeof(header) };
	iov[1] = (struct iovec){ .iov_base = body, .iov_len = sizeof(body) };
	fd = openat(fixture.dirfd, "active.segment",
	    O_WRONLY | O_APPEND | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(header) + sizeof(body), writev(fd, iov, 2));
	close(fd);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(good, logcmp_store_offset(store));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(rejects_symlink_store);
ATF_TC_BODY(rejects_symlink_store, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, symlinkat("missing-target", fixture.dirfd,
	    "active.segment"));
	ATF_CHECK(logcmp_store_open(fixture.dirfd, LOGCMP_STORE_SEGMENT_MIN,
	    LOGCMP_STORE_SEGMENTS_DEFAULT, &store) == -1);
	ATF_CHECK(errno == ELOOP || errno == EMLINK);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(rotation);
ATF_TC_BODY(rotation, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD];
	char message[LOGCMP_MAX_TEXT + 1];
	struct stat status;
	size_t length;
	unsigned i;

	fixture_create(&fixture);
	memset(message, 'x', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	for (i = 0; i < 40; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 1;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
		    (const void *)record, length, false));
	}
	ATF_CHECK(logcmp_store_generation(store) > 1);
	ATF_REQUIRE_EQ(0, fstatat(fixture.dirfd,
	    "segment-00000000000000000001.log", &status, 0));
	ATF_CHECK(S_ISREG(status.st_mode));
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK(logcmp_store_generation(store) > 1);
	((struct logcmp_record *)(void *)record)->sequence++;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
	    (const void *)record, length, true));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(interrupted_rotation_is_reconstructed);
ATF_TC_BODY(interrupted_rotation_is_reconstructed, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;

	fixture_create(&fixture);
	length = make_record(record, "before-crash", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
	    (const void *)record, length, true));
	logcmp_store_close(store);

	/* Model a crash after rename and before creation of the next active file. */
	ATF_REQUIRE_EQ(0, renameat(fixture.dirfd, "active.segment",
	    fixture.dirfd, "segment-00000000000000000001.log"));
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(2, logcmp_store_generation(store));
	((struct logcmp_record *)(void *)record)->sequence = 2;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
	    (const void *)record, length, true));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(empty_successor_is_reconstructed);
ATF_TC_BODY(empty_successor_is_reconstructed, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	int fd;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, renameat(fixture.dirfd, "active.segment",
	    fixture.dirfd, "segment-00000000000000000001.log"));
	fd = openat(fixture.dirfd, "active.segment",
	    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(2, logcmp_store_generation(store));
	ATF_CHECK_EQ(32, logcmp_store_offset(store));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

static unsigned
completed_segment_count(int dirfd)
{
	DIR *directory;
	struct dirent *entry;
	int fd;
	unsigned count;

	fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	directory = fdopendir(fd);
	ATF_REQUIRE(directory != NULL);
	count = 0;
	while ((entry = readdir(directory)) != NULL)
		if (strncmp(entry->d_name, "segment-", 8) == 0 &&
		    strstr(entry->d_name, ".log") != NULL)
			count++;
	closedir(directory);
	return (count);
}

ATF_TC_WITHOUT_HEAD(retention_is_bounded_across_restart);
ATF_TC_BODY(retention_is_bounded_across_restart, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD];
	char message[LOGCMP_MAX_TEXT + 1];
	struct stat status;
	size_t length;
	unsigned i;

	fixture_create(&fixture);
	memset(message, 'r', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, 2, &store));
	for (i = 0; i < 240; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 1;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
		    (const void *)record, length, false));
	}
	ATF_CHECK(logcmp_store_generation(store) > 3);
	ATF_CHECK(completed_segment_count(fixture.dirfd) <= 2);
	ATF_CHECK_ERRNO(ENOENT, fstatat(fixture.dirfd,
	    "segment-00000000000000000001.log", &status, 0) == -1);
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, 1, &store));
	ATF_CHECK(completed_segment_count(fixture.dirfd) <= 1);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(directory_descriptor_is_borrowed);
ATF_TC_BODY(directory_descriptor_is_borrowed, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	logcmp_store_close(store);
	ATF_CHECK(fcntl(fixture.dirfd, F_GETFD) >= 0);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_is_scoped_filtered_and_cursor_driven);
ATF_TC_BODY(query_is_scoped_filtered_and_cursor_driven, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	struct logcmp_record *result;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	length = make_record(record, "alpha-info", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	((struct logcmp_record *)(void *)record)->sequence = 11;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/alpha",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 22;
	((struct logcmp_record *)(void *)record)->severity = LOGCMP_SEVERITY_FATAL;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/beta",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 33;
	((struct logcmp_record *)(void *)record)->severity = LOGCMP_SEVERITY_ERROR;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/alpha",
	    (const void *)record, length, false));

	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.test/alpha",
	    LOGCMP_SEVERITY_WARN, &cursor, output, sizeof(output),
	    &output_length));
	result = (void *)output;
	ATF_CHECK_EQ(33, result->sequence);
	ATF_CHECK_EQ(LOGCMP_SEVERITY_ERROR, result->severity);
	ATF_CHECK_EQ(0, logcmp_validate_record(result, output_length));
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.test/alpha",
	    LOGCMP_SEVERITY_WARN, &cursor, output, sizeof(output),
	    &output_length));

	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.test/alpha", 0,
	    &cursor, output, sizeof(output), &output_length));
	ATF_CHECK_EQ(11, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.test/alpha", 0,
	    &cursor, output, sizeof(output), &output_length));
	ATF_CHECK_EQ(33, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.test/alpha", 0,
	    &cursor, output, sizeof(output), &output_length));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_retry_does_not_advance_cursor);
ATF_TC_BODY(query_retry_does_not_advance_cursor, tc)
{
	struct logcmp_store_cursor cursor, original;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	char message[LOGCMP_MAX_TEXT + 1];
	size_t length, output_length;

	fixture_create(&fixture);
	memset(message, 'q', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE(length > sizeof(struct logcmp_record));
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/client",
	    (const void *)record, length, false));
	memset(&cursor, 0, sizeof(cursor));
	original = cursor;
	ATF_CHECK_ERRNO(EMSGSIZE, logcmp_store_query_next(store,
	    "org.test/client", 0, &cursor, output, sizeof(struct logcmp_record),
	    &output_length) == -1);
	ATF_CHECK_EQ(original.generation, cursor.generation);
	ATF_CHECK_EQ(original.offset, cursor.offset);
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.test/client", 0,
	    &cursor, output, sizeof(output), &output_length));
	ATF_CHECK_EQ(length, output_length);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_scan_is_bounded_and_resumable);
ATF_TC_BODY(query_scan_is_bounded_and_resumable, tc)
{
	struct logcmp_store_cursor cursor, first_slice;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;
	unsigned i;

	fixture_create(&fixture);
	length = make_record(record, "scan", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	for (i = 0; i < LOGCMP_STORE_QUERY_RECORD_BUDGET; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 1;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test.other",
		    (const void *)record, length, false));
	}
	((struct logcmp_record *)(void *)record)->sequence = 999;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test.target",
	    (const void *)record, length, false));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_CONTINUE,
	    logcmp_store_query_next(store, "org.test.target", 0, &cursor,
	    output, sizeof(output), &output_length));
	first_slice = cursor;
	ATF_CHECK(first_slice.generation != 0);
	ATF_CHECK(first_slice.offset > 32);
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_store_query_next(store, "org.test.target", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(999,
	    ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK(cursor.offset > first_slice.offset ||
	    cursor.generation > first_slice.generation);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_rejects_stale_and_invalid_cursors);
ATF_TC_BODY(query_rejects_stale_and_invalid_cursors, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	char message[LOGCMP_MAX_TEXT + 1];
	size_t length, output_length;
	unsigned i;

	fixture_create(&fixture);
	memset(message, 's', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, 1, &store));
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/client",
	    (const void *)record, length, false));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.test/client", 0,
	    &cursor, output, sizeof(output), &output_length));
	ATF_REQUIRE_EQ(1, cursor.generation);
	for (i = 0; i < 160; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 2;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/client",
		    (const void *)record, length, false));
	}
	ATF_REQUIRE(logcmp_store_generation(store) > 2);
	ATF_CHECK_ERRNO(ESTALE, logcmp_store_query_next(store,
	    "org.test/client", 0, &cursor, output, sizeof(output),
	    &output_length) == -1);
	cursor.generation = logcmp_store_generation(store) + 1;
	cursor.offset = 32;
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_query_next(store,
	    "org.test/client", 0, &cursor, output, sizeof(output),
	    &output_length) == -1);
	cursor.generation = logcmp_store_generation(store);
	cursor.offset = UINT64_MAX;
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_query_next(store,
	    "org.test/client", 0, &cursor, output, sizeof(output),
	    &output_length) == -1);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_detects_retained_segment_corruption);
ATF_TC_BODY(query_detects_retained_segment_corruption, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD], byte;
	char message[LOGCMP_MAX_TEXT + 1];
	int fd;
	size_t length, output_length;
	unsigned i;

	fixture_create(&fixture);
	memset(message, 'c', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	for (i = 0; i < 80; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 1;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test/client",
		    (const void *)record, length, false));
	}
	ATF_REQUIRE(logcmp_store_generation(store) > 1);
	fd = openat(fixture.dirfd, "segment-00000000000000000001.log",
	    O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 60));
	byte ^= 0x40;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 60));
	close(fd);
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_ERRNO(EILSEQ, logcmp_store_query_next(store,
	    "org.test/client", 0, &cursor, output, sizeof(output),
	    &output_length) == -1);
	ATF_CHECK_EQ(0, cursor.generation);
	ATF_CHECK_EQ(0, cursor.offset);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(rejects_invalid_inputs);
ATF_TC_BODY(rejects_invalid_inputs, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;

	fixture_create(&fixture);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_open(-1,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_open(fixture.dirfd, 1,
	    LOGCMP_STORE_SEGMENTS_DEFAULT, &store) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, 0, &store) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_MAX + 1,
	    &store) == -1);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	length = make_record(record, "public", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_append(store, "",
	    (const void *)record, length, false) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_append(store, "bad\nlabel",
	    (const void *)record, length, false) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_append(store,
	    "0123456789012345678901234567890123456789012345678901234567890123",
	    (const void *)record, length, false) == -1);
	((struct logcmp_record *)(void *)record)->sequence = 0;
	ATF_CHECK(logcmp_store_append(store, "org.test", (const void *)record,
	    length, false) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_flush(NULL) == -1);
	logcmp_store_close(store);
	logcmp_store_close(NULL);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_is_scoped_to_caller_label);
ATF_TC_BODY(query_is_scoped_to_caller_label, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;

	fixture_create(&fixture);
	length = make_record(record, "scoped", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	/*
	 * Interleave records stamped with two distinct trusted labels.  The
	 * store binds each record to the label supplied at append time, and a
	 * query is answered only from records whose stamped label matches the
	 * caller's, so one label can never observe another's records.
	 */
	((struct logcmp_record *)(void *)record)->sequence = 1;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.a",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 2;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.b",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 3;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.a",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 4;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.b",
	    (const void *)record, length, false));

	/* org.a observes only its own records, sequences 1 and 3. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.a", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(1, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.a", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(3, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.a", 0, &cursor,
	    output, sizeof(output), &output_length));

	/* org.b observes only its own records, sequences 2 and 4. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.b", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(2, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.b", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(4, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.b", 0, &cursor,
	    output, sizeof(output), &output_length));

	/* A label that never appended anything observes nothing. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.c", 0, &cursor,
	    output, sizeof(output), &output_length));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_filters_subsystem_category_and_time);
ATF_TC_BODY(query_filters_subsystem_category_and_time, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	struct logcmp_record *result;
	size_t length, output_length;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	/* Three records for org.f with distinct subsystem/category/timestamp. */
	length = make_named_record(record, 1, 1000, LOGCMP_SEVERITY_INFO,
	    "auth.daemon", "login", "a");
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.f",
	    (const void *)record, length, false));
	length = make_named_record(record, 2, 2000, LOGCMP_SEVERITY_INFO,
	    "net.stack", "connect", "b");
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.f",
	    (const void *)record, length, false));
	length = make_named_record(record, 3, 3000, LOGCMP_SEVERITY_INFO,
	    "auth.agent", "logout", "c");
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.f",
	    (const void *)record, length, false));
	/* A different label with a colliding subsystem, to prove scoping. */
	length = make_named_record(record, 99, 1000, LOGCMP_SEVERITY_INFO,
	    "auth.daemon", "login", "x");
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.other",
	    (const void *)record, length, false));
	result = (void *)output;

	/* Subsystem substring "auth" matches records 1 and 3, not 2. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, "auth",
	    NULL, &cursor, output, &output_length));
	ATF_CHECK_EQ(1, result->sequence);
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, "auth",
	    NULL, &cursor, output, &output_length));
	ATF_CHECK_EQ(3, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 0, 0, 0, "auth",
	    NULL, &cursor, output, &output_length));

	/* Subsystem exact "auth.daemon" matches only record 1. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0,
	    LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT, "auth.daemon", NULL, &cursor,
	    output, &output_length));
	ATF_CHECK_EQ(1, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 0, 0,
	    LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT, "auth.daemon", NULL, &cursor,
	    output, &output_length));

	/* Category substring "log" matches login (1) and logout (3). */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, NULL,
	    "log", &cursor, output, &output_length));
	ATF_CHECK_EQ(1, result->sequence);
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, NULL,
	    "log", &cursor, output, &output_length));
	ATF_CHECK_EQ(3, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 0, 0, 0, NULL,
	    "log", &cursor, output, &output_length));

	/* Category exact "connect" matches only record 2. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0,
	    LOGCMP_QUERY_MATCH_CATEGORY_EXACT, NULL, "connect", &cursor,
	    output, &output_length));
	ATF_CHECK_EQ(2, result->sequence);

	/* Time window [1500,2500] matches only record 2. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 1500, 2500, 0, NULL,
	    NULL, &cursor, output, &output_length));
	ATF_CHECK_EQ(2, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 1500, 2500, 0, NULL,
	    NULL, &cursor, output, &output_length));

	/* Open-ended lower bound from=2500 matches only record 3. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 2500, 0, 0, NULL,
	    NULL, &cursor, output, &output_length));
	ATF_CHECK_EQ(3, result->sequence);

	/* Combined subsystem "auth" AND to_ns=1500 narrows to record 1. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 1500, 0, "auth",
	    NULL, &cursor, output, &output_length));
	ATF_CHECK_EQ(1, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 0, 1500, 0, "auth",
	    NULL, &cursor, output, &output_length));

	/*
	 * Scoping is never widened by the filter: querying org.other with a
	 * subsystem that also occurs under org.f returns only org.other's own
	 * record (sequence 99), never org.f's.
	 */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.other", 0, 0, 0,
	    LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT, "auth.daemon", NULL, &cursor,
	    output, &output_length));
	ATF_CHECK_EQ(99, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.other", 0, 0, 0,
	    LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT, "auth.daemon", NULL, &cursor,
	    output, &output_length));

	/* An empty filter is unconstrained: all three org.f records, in order. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, NULL, NULL,
	    &cursor, output, &output_length));
	ATF_CHECK_EQ(1, result->sequence);
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, NULL, NULL,
	    &cursor, output, &output_length));
	ATF_CHECK_EQ(2, result->sequence);
	ATF_REQUIRE_EQ(1, filtered_next(store, "org.f", 0, 0, 0, 0, NULL, NULL,
	    &cursor, output, &output_length));
	ATF_CHECK_EQ(3, result->sequence);
	ATF_CHECK_EQ(0, filtered_next(store, "org.f", 0, 0, 0, 0, NULL, NULL,
	    &cursor, output, &output_length));

	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

static void
fill_completed_segments(struct logcmp_store *store)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	char message[LOGCMP_MAX_TEXT + 1];
	size_t length;
	unsigned i;

	memset(message, 'z', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	length = make_record(record, message, LOGCMP_PRIVACY_PUBLIC, "value",
	    LOGCMP_PRIVACY_PUBLIC);
	for (i = 0; i < 160; i++) {
		((struct logcmp_record *)(void *)record)->sequence = i + 1;
		ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
		    (const void *)record, length, false));
	}
}

ATF_TC_WITHOUT_HEAD(retention_disabled_keeps_all);
ATF_TC_BODY(retention_disabled_keeps_all, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	unsigned before;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	fill_completed_segments(store);
	before = completed_segment_count(fixture.dirfd);
	ATF_REQUIRE(before >= 3);
	/* Default 0/0 retention: enforcement is a keep-all no-op. */
	ATF_REQUIRE_EQ(0, logcmp_store_enforce_retention(store));
	ATF_CHECK_EQ(before, completed_segment_count(fixture.dirfd));
	ATF_CHECK_EQ(0, logcmp_store_pruned_segments(store));
	/* Explicitly disabled is the same. */
	logcmp_store_set_retention(store, 0, 0);
	ATF_REQUIRE_EQ(0, logcmp_store_enforce_retention(store));
	ATF_CHECK_EQ(before, completed_segment_count(fixture.dirfd));
	ATF_CHECK_EQ(0, logcmp_store_pruned_segments(store));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(retention_prunes_oldest_by_age);
ATF_TC_BODY(retention_prunes_oldest_by_age, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	struct stat status;
	struct timespec past[2];
	unsigned before;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	fill_completed_segments(store);
	before = completed_segment_count(fixture.dirfd);
	ATF_REQUIRE(before >= 3);
	/* Backdate only the oldest completed segment by an hour. */
	ATF_REQUIRE_EQ(0, fstatat(fixture.dirfd,
	    "segment-00000000000000000001.log", &status, 0));
	past[0].tv_sec = time(NULL) - 3600;
	past[0].tv_nsec = 0;
	past[1] = past[0];
	ATF_REQUIRE_EQ(0, utimensat(fixture.dirfd,
	    "segment-00000000000000000001.log", past, 0));
	logcmp_store_set_retention(store, 60, 0);
	ATF_REQUIRE_EQ(0, logcmp_store_enforce_retention(store));
	/* The aged-out oldest is gone; the next (recent) one survives. */
	ATF_CHECK_ERRNO(ENOENT, fstatat(fixture.dirfd,
	    "segment-00000000000000000001.log", &status, 0) == -1);
	ATF_CHECK_EQ(0, fstatat(fixture.dirfd,
	    "segment-00000000000000000002.log", &status, 0));
	ATF_CHECK_EQ(1, logcmp_store_pruned_segments(store));
	ATF_CHECK_EQ(before - 1, completed_segment_count(fixture.dirfd));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(retention_prunes_by_size_never_active);
ATF_TC_BODY(retention_prunes_by_size_never_active, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	struct stat status;
	uint8_t record[LOGCMP_MAX_RECORD];
	off_t active_before;
	size_t length;
	unsigned before;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	fill_completed_segments(store);
	before = completed_segment_count(fixture.dirfd);
	ATF_REQUIRE(before >= 3);
	active_before = logcmp_store_offset(store);
	/*
	 * A tiny byte budget forces every completed segment to be pruned, but
	 * the active segment is never a candidate.
	 */
	logcmp_store_set_retention(store, 0, 1024);
	ATF_REQUIRE_EQ(0, logcmp_store_enforce_retention(store));
	ATF_CHECK_EQ(0, completed_segment_count(fixture.dirfd));
	ATF_CHECK_EQ(before, logcmp_store_pruned_segments(store));
	ATF_CHECK(logcmp_store_pruned_records(store) > 0);
	/* The active segment is intact and still writable. */
	ATF_REQUIRE_EQ(0, fstatat(fixture.dirfd, "active.segment", &status, 0));
	ATF_CHECK_EQ(active_before, logcmp_store_offset(store));
	length = make_record(record, "after-prune", LOGCMP_PRIVACY_PUBLIC,
	    "value", LOGCMP_PRIVACY_PUBLIC);
	((struct logcmp_record *)(void *)record)->sequence = 1000;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.test",
	    (const void *)record, length, true));
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * Capability-cleanup reclaim: retiring one label's records must leave every
 * other label's records queryable and intact, be idempotent, and never corrupt
 * the active segment.
 */
ATF_TC_WITHOUT_HEAD(reclaim_drops_only_the_named_label);
ATF_TC_BODY(reclaim_drops_only_the_named_label, tc)
{
	struct logcmp_store_cursor cursor;
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	off_t offset_before;
	size_t length, output_length;

	fixture_create(&fixture);
	length = make_record(record, "kept", LOGCMP_PRIVACY_PUBLIC, "value",
	    LOGCMP_PRIVACY_PUBLIC);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	/* Interleave two labels so a reclaim of one must not disturb the other. */
	((struct logcmp_record *)(void *)record)->sequence = 1;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.a",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 2;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.b",
	    (const void *)record, length, false));
	((struct logcmp_record *)(void *)record)->sequence = 3;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.a",
	    (const void *)record, length, false));
	ATF_CHECK_EQ(2, logcmp_store_label_count(store, "org.a"));
	ATF_CHECK_EQ(1, logcmp_store_label_count(store, "org.b"));
	offset_before = logcmp_store_offset(store);

	/* Reclaiming a label that never logged is a no-op success. */
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.never"));

	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.a"));
	/* Idempotent: a repeated reclaim still succeeds. */
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.a"));

	/* org.a now observes nothing and reports a zero count. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.a", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(0, logcmp_store_label_count(store, "org.a"));

	/* org.b is untouched: both its count and its records survive. */
	ATF_CHECK_EQ(1, logcmp_store_label_count(store, "org.b"));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_store_query_next(store, "org.b", 0, &cursor,
	    output, sizeof(output), &output_length));
	ATF_CHECK_EQ(2, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(0, logcmp_store_query_next(store, "org.b", 0, &cursor,
	    output, sizeof(output), &output_length));

	/*
	 * The active segment is neither rewritten nor truncated by the logical
	 * prune, and it stays writable for live labels.
	 */
	ATF_CHECK_EQ(offset_before, logcmp_store_offset(store));
	((struct logcmp_record *)(void *)record)->sequence = 4;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, "org.b",
	    (const void *)record, length, true));
	ATF_CHECK_EQ(2, logcmp_store_label_count(store, "org.b"));

	/* A malformed label is rejected without recording anything. */
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_reclaim_label(store, "") == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_store_reclaim_label(NULL, "org.a") == -1);
	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * Query a label to EOF and return how many of its records are visible, checking
 * each returned record carries the caller's label scope (via its recovered
 * sequence being one the caller wrote).  Used by the reclaim invariant tests.
 */
static unsigned
count_visible(struct logcmp_store *store, const char *label,
    uint64_t *last_sequence)
{
	struct logcmp_store_cursor cursor;
	uint8_t output[LOGCMP_MAX_RECORD];
	size_t output_length;
	unsigned seen;
	int result;

	memset(&cursor, 0, sizeof(cursor));
	seen = 0;
	for (;;) {
		result = logcmp_store_query_next(store, label, 0, &cursor, output,
		    sizeof(output), &output_length);
		ATF_REQUIRE(result >= 0);
		if (result == LOGCMP_STORE_QUERY_EOF)
			break;
		if (result == LOGCMP_STORE_QUERY_CONTINUE)
			continue;
		ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD, result);
		if (last_sequence != NULL)
			*last_sequence =
			    ((struct logcmp_record *)(void *)output)->sequence;
		seen++;
	}
	return (seen);
}

static void
append_seq(struct logcmp_store *store, const char *label, uint64_t sequence)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;

	length = make_record(record, "payload", LOGCMP_PRIVACY_PUBLIC, "value",
	    LOGCMP_PRIVACY_PUBLIC);
	((struct logcmp_record *)(void *)record)->sequence = sequence;
	ATF_REQUIRE_EQ(0, logcmp_store_append(store, label, (const void *)record,
	    length, false));
}

/*
 * Invariant, part (a): reclaiming far MORE than the retired fixed cap of 128
 * distinct labels in one run must never fail with a would-leave-records-visible
 * error, and every reclaimed label must query empty.  A control label the sweep
 * never touches stays fully visible.
 */
ATF_TC_WITHOUT_HEAD(reclaim_scales_past_the_old_fixed_cap);
ATF_TC_BODY(reclaim_scales_past_the_old_fixed_cap, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	char label[64];
	unsigned i;
	const unsigned tenants = 300;	/* > the old 128-entry cap */

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	append_seq(store, "org.control", 1);
	for (i = 0; i < tenants; i++) {
		snprintf(label, sizeof(label), "org.tenant.%04u", i);
		append_seq(store, label, 1000 + i);
	}
	for (i = 0; i < tenants; i++) {
		snprintf(label, sizeof(label), "org.tenant.%04u", i);
		/* Every reclaim succeeds; none returns a failure code. */
		ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, label));
	}
	for (i = 0; i < tenants; i++) {
		snprintf(label, sizeof(label), "org.tenant.%04u", i);
		ATF_CHECK_EQ(0, count_visible(store, label, NULL));
		ATF_CHECK_EQ(0, logcmp_store_label_count(store, label));
	}
	/* The untouched control label is entirely unaffected. */
	ATF_CHECK_EQ(1, count_visible(store, "org.control", NULL));
	ATF_CHECK_EQ(1, logcmp_store_label_count(store, "org.control"));

	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * Cross-tenant invariant: after label "L" (owner A) is reclaimed, records
 * written under a REUSED "L" (owner B) are the only ones a query for L returns.
 * A's records must never resurface.  Proven both live and across a store
 * close/reopen, which is where the in-memory reclaimed set of the old design
 * silently dropped the reclaim.
 */
ATF_TC_WITHOUT_HEAD(reused_label_never_reads_prior_tenant);
ATF_TC_BODY(reused_label_never_reads_prior_tenant, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint64_t last;
	unsigned i;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	/* Owner A writes three records under "org.shared". */
	for (i = 0; i < 3; i++)
		append_seq(store, "org.shared", 100 + i);
	ATF_REQUIRE_EQ(3, count_visible(store, "org.shared", NULL));

	/* The bundle is retired. */
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.shared"));
	ATF_CHECK_EQ(0, count_visible(store, "org.shared", NULL));

	/* serviced reuses the name for owner B, who writes two records. */
	append_seq(store, "org.shared", 900);
	append_seq(store, "org.shared", 901);
	last = 0;
	ATF_CHECK_EQ(2, count_visible(store, "org.shared", &last));
	ATF_CHECK_EQ(901, last);
	ATF_CHECK_EQ(2, logcmp_store_label_count(store, "org.shared"));

	/* Across a restart the floor persists: still exactly B's two records. */
	logcmp_store_close(store);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	last = 0;
	ATF_CHECK_EQ(2, count_visible(store, "org.shared", &last));
	ATF_CHECK_EQ(901, last);

	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * Restart durability, part (b): a reclaim survives close/reopen.  After
 * reopening, the retired label's old records stay invisible, and reclaiming
 * again (idempotent) is still a clean success.
 */
ATF_TC_WITHOUT_HEAD(reclaim_survives_close_and_reopen);
ATF_TC_BODY(reclaim_survives_close_and_reopen, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	append_seq(store, "org.retired", 1);
	append_seq(store, "org.retired", 2);
	append_seq(store, "org.kept", 3);
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.retired"));
	ATF_CHECK_EQ(0, count_visible(store, "org.retired", NULL));
	ATF_CHECK_EQ(1, count_visible(store, "org.kept", NULL));
	logcmp_store_close(store);

	/* Reopen: the floor was persisted, so the retired label stays empty. */
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	ATF_CHECK_EQ(0, count_visible(store, "org.retired", NULL));
	/* A peer written before the reclaim is untouched by it. */
	ATF_CHECK_EQ(1, count_visible(store, "org.kept", NULL));
	/* Idempotent re-drive after a restart still succeeds. */
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.retired"));
	ATF_CHECK_EQ(0, count_visible(store, "org.retired", NULL));

	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * A reclaim floor holds even when the label's records straddle a rotated
 * (completed) segment and the active one: reclaim after both are written hides
 * everything, and a reused name writing into the new active segment is visible.
 */
ATF_TC_WITHOUT_HEAD(reclaim_floor_spans_rotated_segments);
ATF_TC_BODY(reclaim_floor_spans_rotated_segments, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint64_t generation_before;
	unsigned i;

	fixture_create(&fixture);
	/* A small segment limit forces rotation across the run. */
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));

	generation_before = logcmp_store_generation(store);
	/* Enough records to overflow a 64 KiB segment and rotate at least once. */
	for (i = 0; i < 800; i++)
		append_seq(store, "org.big", 1 + i);
	ATF_REQUIRE(logcmp_store_generation(store) > generation_before);
	ATF_CHECK_EQ(800, count_visible(store, "org.big", NULL));

	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.big"));
	ATF_CHECK_EQ(0, count_visible(store, "org.big", NULL));

	/* Reuse writes above the floor, into the current active segment. */
	append_seq(store, "org.big", 999999);
	ATF_CHECK_EQ(1, count_visible(store, "org.big", NULL));

	logcmp_store_close(store);
	fixture_destroy(&fixture);
}

/*
 * A corrupt reclaim metadata file must fail the open closed (EILSEQ) rather than
 * silently forgetting the reclaim and re-exposing a retired label's records.
 */
ATF_TC_WITHOUT_HEAD(corrupt_reclaim_meta_fails_closed);
ATF_TC_BODY(corrupt_reclaim_meta_fails_closed, tc)
{
	struct fixture fixture;
	struct logcmp_store *store;
	uint8_t byte;
	int fd;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT, &store));
	append_seq(store, "org.retired", 1);
	ATF_REQUIRE_EQ(0, logcmp_store_reclaim_label(store, "org.retired"));
	logcmp_store_close(store);

	/* Flip a payload byte to break the metadata body CRC. */
	fd = openat(fixture.dirfd, "reclaim.meta", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 24));
	byte ^= 0xff;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 24));
	close(fd);

	ATF_CHECK_ERRNO(EILSEQ, logcmp_store_open(fixture.dirfd,
	    LOGCMP_STORE_SEGMENT_MAX, LOGCMP_STORE_SEGMENTS_DEFAULT,
	    &store) == -1);

	/* Remove the poisoned metadata so fixture teardown's reopen is clean. */
	ATF_REQUIRE_EQ(0, unlinkat(fixture.dirfd, "reclaim.meta", 0));
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, redacts_private_values);
	ATF_TP_ADD_TC(tp, private_hash_is_keyed_and_stable);
	ATF_TP_ADD_TC(tp, append_reopen_and_privacy);
	ATF_TP_ADD_TC(tp, torn_tail_is_truncated);
	ATF_TP_ADD_TC(tp, corruption_is_not_silently_truncated);
	ATF_TP_ADD_TC(tp, rejects_corrupt_file_header);
	ATF_TP_ADD_TC(tp, incomplete_record_body_is_truncated);
	ATF_TP_ADD_TC(tp, rejects_symlink_store);
	ATF_TP_ADD_TC(tp, rotation);
	ATF_TP_ADD_TC(tp, interrupted_rotation_is_reconstructed);
	ATF_TP_ADD_TC(tp, empty_successor_is_reconstructed);
	ATF_TP_ADD_TC(tp, retention_is_bounded_across_restart);
	ATF_TP_ADD_TC(tp, directory_descriptor_is_borrowed);
	ATF_TP_ADD_TC(tp, query_is_scoped_filtered_and_cursor_driven);
	ATF_TP_ADD_TC(tp, query_retry_does_not_advance_cursor);
	ATF_TP_ADD_TC(tp, query_scan_is_bounded_and_resumable);
	ATF_TP_ADD_TC(tp, query_rejects_stale_and_invalid_cursors);
	ATF_TP_ADD_TC(tp, query_detects_retained_segment_corruption);
	ATF_TP_ADD_TC(tp, rejects_invalid_inputs);
	ATF_TP_ADD_TC(tp, query_is_scoped_to_caller_label);
	ATF_TP_ADD_TC(tp, query_filters_subsystem_category_and_time);
	ATF_TP_ADD_TC(tp, retention_disabled_keeps_all);
	ATF_TP_ADD_TC(tp, retention_prunes_oldest_by_age);
	ATF_TP_ADD_TC(tp, retention_prunes_by_size_never_active);
	ATF_TP_ADD_TC(tp, reclaim_drops_only_the_named_label);
	ATF_TP_ADD_TC(tp, reclaim_scales_past_the_old_fixed_cap);
	ATF_TP_ADD_TC(tp, reused_label_never_reads_prior_tenant);
	ATF_TP_ADD_TC(tp, reclaim_survives_close_and_reopen);
	ATF_TP_ADD_TC(tp, reclaim_floor_spans_rotated_segments);
	ATF_TP_ADD_TC(tp, corrupt_reclaim_meta_fails_closed);
	return (atf_no_error());
}

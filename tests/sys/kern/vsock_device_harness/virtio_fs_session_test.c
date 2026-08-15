/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtiofsd_export.c"
#include "virtiofsd_fuse.c"
#include "virtiofsd_handle.c"
#include "virtiofsd_session.c"

#define	DOC_FUSE_INIT		26U
#define	DOC_FUSE_LOOKUP		1U
#define	DOC_FUSE_GETATTR	3U
#define	DOC_FUSE_READLINK	5U
#define	DOC_FUSE_OPEN		14U
#define	DOC_FUSE_READ		15U
#define	DOC_FUSE_STATFS		17U
#define	DOC_FUSE_RELEASE	18U
#define	DOC_FUSE_FSYNC		20U
#define	DOC_FUSE_FLUSH		25U
#define	DOC_FUSE_FORGET		2U
#define	DOC_FUSE_OPENDIR	27U
#define	DOC_FUSE_READDIR	28U
#define	DOC_FUSE_RELEASEDIR	29U
#define	DOC_FUSE_ACCESS		34U
#define	DOC_FUSE_DESTROY	38U
#define	DOC_FUSE_BATCH_FORGET	42U
#define	DOC_LINUX_EROFS		30
#define	DOC_FUSE_ASYNC_READ	(UINT32_C(1) << 0)
#define	DOC_FUSE_PARALLEL_DIROPS (UINT32_C(1) << 18)

static void
request_header(uint8_t *wire, size_t length, uint32_t opcode,
    uint64_t unique, uint64_t nodeid)
{

	memset(wire, 0, length);
	le32enc(wire, (uint32_t)length);
	le32enc(wire + 4, opcode);
	le64enc(wire + 8, unique);
	le64enc(wire + 16, nodeid);
	le32enc(wire + 24, 1001);
	le32enc(wire + 28, 1002);
	le32enc(wire + 32, 1003);
}

static int
session_fixture(char path[static 32], struct virtiofsd_export **export,
    struct virtiofsd_session **session)
{
	int fd, rootfd;

	strcpy(path, "/tmp/virtiofsd-session.XXXXXX");
	ATF_REQUIRE(mkdtemp(path) != NULL);
	rootfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	fd = openat(rootfd, "file", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(write(fd, "waspnest", 8), 8);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(symlinkat("file", rootfd, "link"), 0);
	ATF_REQUIRE_EQ(mkfifoat(rootfd, "fifo", 0600), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_create(rootfd, 16, export), 0);
	ATF_REQUIRE_EQ(virtiofsd_session_create(*export, 8, 4096,
	    session), 0);
	return (rootfd);
}

static void
session_cleanup(int rootfd, const char *path,
    struct virtiofsd_export *export, struct virtiofsd_session *session)
{

	virtiofsd_session_destroy(session);
	virtiofsd_export_destroy(export);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "file", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "link", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "fifo", 0), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(path), 0);
}

static void
initialize(struct virtiofsd_session *session)
{
	uint8_t request[56], response[128];
	bool reply;
	size_t written;

	request_header(request, sizeof(request), DOC_FUSE_INIT, 1, 1);
	le32enc(request + 40, 7);
	le32enc(request + 44, 35);
	le32enc(request + 48, 65536);
	le32enc(request + 52, DOC_FUSE_ASYNC_READ |
	    DOC_FUSE_PARALLEL_DIROPS | (UINT32_C(1) << 31));
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), response, sizeof(response), &written, &reply),
	    0);
	ATF_REQUIRE(reply);
	ATF_REQUIRE_EQ(written, 80);
	ATF_REQUIRE_EQ(le32dec(response), written);
	ATF_REQUIRE_EQ(le32dec(response + 16), 7);
	ATF_REQUIRE_EQ(le32dec(response + 28), DOC_FUSE_ASYNC_READ |
	    DOC_FUSE_PARALLEL_DIROPS);
}

struct parallel_context {
	struct virtiofsd_session *session;
	_Atomic int error;
	unsigned int worker;
};

static void *
parallel_reader(void *argument)
{
	struct parallel_context *context;
	uint8_t forget[48], lookup[45], open_request[48], read_request[80];
	uint8_t release[64], response[256];
	uint64_t handle, nodeid, unique;
	bool reply;
	size_t written;
	unsigned int iteration;
	int error;

	context = argument;
	for (iteration = 0; iteration < 100; iteration++) {
		unique = UINT64_C(1000) + context->worker * 1000 +
		    iteration * 5;
		request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP,
		    unique, 1);
		memcpy(lookup + 40, "file", 5);
		error = virtiofsd_session_execute(context->session, lookup,
		    sizeof(lookup), response, sizeof(response), &written,
		    &reply);
		if (error != 0 || written != 144)
			goto fail;
		nodeid = le64dec(response + 16);

		request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN,
		    unique + 1, nodeid);
		error = virtiofsd_session_execute(context->session, open_request,
		    sizeof(open_request), response, sizeof(response), &written,
		    &reply);
		if (error != 0 || written != 32)
			goto fail_forget;
		handle = le64dec(response + 16);

		request_header(read_request, sizeof(read_request), DOC_FUSE_READ,
		    unique + 2, nodeid);
		le64enc(read_request + 40, handle);
		le32enc(read_request + 56, 8);
		error = virtiofsd_session_execute(context->session, read_request,
		    sizeof(read_request), response, sizeof(response), &written,
		    &reply);
		if (error != 0 || written != 24 ||
		    memcmp(response + 16, "waspnest", 8) != 0)
			goto fail_release;

		request_header(release, sizeof(release), DOC_FUSE_RELEASE,
		    unique + 3, nodeid);
		le64enc(release + 40, handle);
		error = virtiofsd_session_execute(context->session, release,
		    sizeof(release), response, sizeof(response), &written,
		    &reply);
		if (error != 0 || written != 16)
			goto fail_forget;

		request_header(forget, sizeof(forget), DOC_FUSE_FORGET,
		    unique + 4, nodeid);
		le64enc(forget + 40, 1);
		error = virtiofsd_session_execute(context->session, forget,
		    sizeof(forget), NULL, 0, &written, &reply);
		if (error != 0 || reply || written != 0)
			goto fail;
		continue;
fail_release:
		request_header(release, sizeof(release), DOC_FUSE_RELEASE,
		    unique + 3, nodeid);
		le64enc(release + 40, handle);
		(void)virtiofsd_session_execute(context->session, release,
		    sizeof(release), response, sizeof(response), &written,
		    &reply);
fail_forget:
		(void)virtiofsd_export_forget(context->session->export, nodeid,
		    1);
fail:
		atomic_store(&context->error, 1);
		return (NULL);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(read_lifetime_survives_forget_and_release_is_typed);
ATF_TC_BODY(read_lifetime_survives_forget_and_release_is_typed, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t lookup[45], open_request[48], read_request[80];
	uint8_t flush[64], fsync_request[56], getattr_request[56];
	uint8_t release[64], response[256];
	char path[32];
	uint64_t handle, nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);

	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 2, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	ATF_REQUIRE_EQ(written, 144);
	nodeid = le64dec(response + 16);
	ATF_CHECK(nodeid != 0 && nodeid != 1);

	request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN, 3,
	    nodeid);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(written, 32);
	handle = le64dec(response + 16);
	ATF_CHECK(handle != 0);

	request_header(getattr_request, sizeof(getattr_request),
	    DOC_FUSE_GETATTR, 4, nodeid);
	le32enc(getattr_request + 40, 1);	/* FUSE_GETATTR_FH. */
	le64enc(getattr_request + 48, handle);
	/* A handle is opaque but remains scoped to the node which created it. */
	request_header(getattr_request, sizeof(getattr_request),
	    DOC_FUSE_GETATTR, 4, VIRTIOFSD_ROOT_NODEID);
	le32enc(getattr_request + 40, 1);
	le64enc(getattr_request + 48, handle);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, getattr_request,
	    sizeof(getattr_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -116);
	request_header(getattr_request, sizeof(getattr_request),
	    DOC_FUSE_GETATTR, 4, nodeid);
	le32enc(getattr_request + 40, 1);
	le64enc(getattr_request + 48, handle);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, getattr_request,
	    sizeof(getattr_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 120);
	le64enc(getattr_request + 48, 0);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, getattr_request,
	    sizeof(getattr_request), response, sizeof(response), &written,
	    &reply), EPROTO);

	request_header(release, 48, DOC_FUSE_FORGET, 4, nodeid);
	le64enc(release + 40, 1);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, release, 48,
	    NULL, 0, &written, &reply), 0);
	ATF_CHECK(!reply);
	ATF_CHECK_EQ(written, 0);

	request_header(read_request, sizeof(read_request), DOC_FUSE_READ, 5,
	    nodeid);
	le64enc(read_request + 40, handle);
	le64enc(read_request + 48, 0);
	le32enc(read_request + 56, 8);
	request_header(read_request, sizeof(read_request), DOC_FUSE_READ, 5,
	    VIRTIOFSD_ROOT_NODEID);
	le64enc(read_request + 40, handle);
	le32enc(read_request + 56, 8);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -116);
	request_header(read_request, sizeof(read_request), DOC_FUSE_READ, 5,
	    nodeid);
	le64enc(read_request + 40, handle);
	le32enc(read_request + 56, 8);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(written, 24);
	ATF_CHECK_EQ(memcmp(response + 16, "waspnest", 8), 0);

	request_header(flush, sizeof(flush), DOC_FUSE_FLUSH, 51, nodeid);
	le64enc(flush + 40, handle);
	le64enc(flush + 56, 0x1234);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, flush,
	    sizeof(flush), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 16);

	request_header(fsync_request, sizeof(fsync_request), DOC_FUSE_FSYNC,
	    52, nodeid);
	le64enc(fsync_request + 40, handle);
	le32enc(fsync_request + 48, 1);	/* Linux FUSE_FSYNC_FDATASYNC. */
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, fsync_request,
	    sizeof(fsync_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 16);
	le32enc(fsync_request + 48, 2);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, fsync_request,
	    sizeof(fsync_request), response, sizeof(response), &written,
	    &reply), EPROTO);

	request_header(release, sizeof(release), DOC_FUSE_RELEASE, 6, nodeid);
	le64enc(release + 40, handle);
	request_header(release, sizeof(release), DOC_FUSE_RELEASE, 6,
	    VIRTIOFSD_ROOT_NODEID);
	le64enc(release + 40, handle);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, release,
	    sizeof(release), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -116);
	request_header(release, sizeof(release), DOC_FUSE_RELEASE, 6, nodeid);
	le64enc(release + 40, handle);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, release,
	    sizeof(release), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, release,
	    sizeof(release), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -116);

	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(read_only_policy_is_wire_abi_and_not_native_flags);
ATF_TC_BODY(read_only_policy_is_wire_abi_and_not_native_flags, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t lookup[45], open_request[48], response[256];
	char path[32];
	uint64_t nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 11, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);

	request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN, 12,
	    nodeid);
	le32enc(open_request + 40, 1);	/* Linux O_WRONLY. */
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -DOC_LINUX_EROFS);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, nodeid, 1), 0);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(newer_major_negotiation_blocks_normal_requests);
ATF_TC_BODY(newer_major_negotiation_blocks_normal_requests, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t init[56], lookup[45], opposite[56], response[256];
	char path[32];
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	request_header(init, sizeof(init), DOC_FUSE_INIT, 21, 1);
	le32enc(init + 40, 8);
	le32enc(init + 44, 0);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, init, sizeof(init),
	    response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 24);
	ATF_CHECK_EQ(le32dec(response + 16), 7);

	memset(opposite, 0, sizeof(opposite));
	be32enc(opposite, sizeof(opposite));
	be32enc(opposite + 4, DOC_FUSE_INIT);
	be64enc(opposite + 8, 22);
	be64enc(opposite + 16, 1);
	be32enc(opposite + 40, 7);
	be32enc(opposite + 44, 35);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, opposite,
	    sizeof(opposite), response, sizeof(response), &written, &reply),
	    EPROTO);

	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 22, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply),
	    EPROTO);

	le32enc(init + 40, 7);
	le64enc(init + 8, 23);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, init, sizeof(init),
	    response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 80);
	le64enc(init + 8, 24);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, init, sizeof(init),
	    response, sizeof(response), &written, &reply), EPROTO);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(readlink_returns_unterminated_wire_bytes);
ATF_TC_BODY(readlink_returns_unterminated_wire_bytes, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t lookup[45], readlink_request[40], response[256];
	char path[32];
	uint64_t nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 31, 1);
	memcpy(lookup + 40, "link", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);

	request_header(readlink_request, sizeof(readlink_request),
	    DOC_FUSE_READLINK, 32, nodeid);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, readlink_request,
	    sizeof(readlink_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 20);
	ATF_CHECK_EQ(le32dec(response), 20);
	ATF_CHECK_EQ(memcmp(response + 16, "file", 4), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, nodeid, 1), 0);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(readdir_uses_linux_wire_layout_and_hides_special_files);
ATF_TC_BODY(readdir_uses_linux_wire_layout_and_hides_special_files, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t open_request[48], read_request[80], release[64];
	uint8_t response[4096], response_again[4096];
	char name[256], path[32];
	uint64_t handle, previous_offset;
	bool found_file, found_fifo, found_link, reply;
	size_t body, entry_size, first_written, name_len, position, written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(open_request, sizeof(open_request), DOC_FUSE_OPENDIR,
	    41, 1);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(written, 32);
	handle = le64dec(response + 16);

	request_header(read_request, sizeof(read_request), DOC_FUSE_READDIR,
	    42, 1);
	le64enc(read_request + 40, handle);
	le64enc(read_request + 48, 0);
	le32enc(read_request + 56, sizeof(response) - 16);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(le32dec(response), written);
	body = written - 16;
	position = 0;
	previous_offset = 0;
	found_file = false;
	found_fifo = false;
	found_link = false;
	while (position < body) {
		ATF_REQUIRE(body - position >= 24);
		name_len = le32dec(response + 16 + position + 16);
		ATF_REQUIRE(name_len != 0 && name_len < sizeof(name));
		entry_size = (24 + name_len + 7) & ~(size_t)7;
		ATF_REQUIRE(entry_size <= body - position);
		ATF_CHECK(le64dec(response + 16 + position + 8) >
		    previous_offset);
		previous_offset = le64dec(response + 16 + position + 8);
		memcpy(name, response + 16 + position + 24, name_len);
		name[name_len] = '\0';
		if (strcmp(name, "file") == 0) {
			found_file = true;
			ATF_CHECK_EQ(le32dec(response + 16 + position + 20), 8);
		} else if (strcmp(name, "link") == 0) {
			found_link = true;
			ATF_CHECK_EQ(le32dec(response + 16 + position + 20), 10);
		} else if (strcmp(name, "fifo") == 0) {
			found_fifo = true;
		}
		position += entry_size;
	}
	ATF_CHECK(found_file);
	ATF_CHECK(found_link);
	ATF_CHECK(!found_fifo);
	first_written = written;
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response_again, sizeof(response_again),
	    &written, &reply), 0);
	ATF_REQUIRE_EQ(written, first_written);
	ATF_CHECK_EQ(memcmp(response, response_again, first_written), 0);
	le64enc(read_request + 8, 43);
	le64enc(read_request + 48, UINT64_MAX);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 16);

	request_header(release, sizeof(release), DOC_FUSE_RELEASEDIR, 44, 1);
	le64enc(release + 40, handle);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, release,
	    sizeof(release), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 16);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(statfs_and_access_are_explicitly_read_only);
ATF_TC_BODY(statfs_and_access_are_explicitly_read_only, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t request[48], response[256];
	char path[32];
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(request, 40, DOC_FUSE_STATFS, 51, 1);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request, 40,
	    response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 96);
	ATF_CHECK_EQ(le32dec(response), 96);
	ATF_CHECK(le32dec(response + 56) != 0);

	request_header(request, sizeof(request), DOC_FUSE_ACCESS, 52, 1);
	le32enc(request + 40, 4);	/* Linux R_OK. */
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), 0);
	le64enc(request + 8, 53);
	le32enc(request + 40, 2);	/* Linux W_OK. */
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ((int32_t)le32dec(response + 4), -DOC_LINUX_EROFS);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(batch_forget_validates_all_entries_before_applying);
ATF_TC_BODY(batch_forget_validates_all_entries_before_applying, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	struct stat sb;
	uint8_t lookup[45], request[80], response[256];
	char path[32];
	uint64_t nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 61, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);

	request_header(request, sizeof(request), DOC_FUSE_BATCH_FORGET, 62, 1);
	le32enc(request + 40, 2);
	le64enc(request + 48, nodeid);
	le64enc(request + 56, 1);
	le64enc(request + 64, 1);
	/* A zero lookup count makes the last entry malformed. */
	le64enc(request + 72, 0);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), NULL, 0, &written, &reply), EPROTO);
	ATF_CHECK(!reply);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid, &sb), 0);

	le64enc(request + 72, 1);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), NULL, 0, &written, &reply), 0);
	ATF_CHECK(!reply);
	ATF_CHECK_EQ(written, 0);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid, &sb), ESTALE);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(canceled_resource_results_are_rolled_back);
ATF_TC_BODY(canceled_resource_results_are_rolled_back, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	struct stat sb;
	uint8_t lookup[45], open_request[48], response[256];
	char path[32];
	uint64_t nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);

	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 71, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	ATF_REQUIRE_EQ(written, 144);
	nodeid = le64dec(response + 16);
	ATF_REQUIRE_EQ(virtiofsd_session_discard_result(session, lookup,
	    sizeof(lookup), response, written), 0);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid, &sb), ESTALE);

	le64enc(lookup + 8, 72);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);
	request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN, 73,
	    nodeid);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(written, 32);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 1);
	ATF_REQUIRE_EQ(virtiofsd_session_discard_result(session, open_request,
	    sizeof(open_request), response, written), 0);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, nodeid, 1), 0);

	/* A mismatched result must fail closed without touching state. */
	le64enc(lookup + 8, 74);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);
	le64enc(response + 8, 75);
	ATF_CHECK_EQ(virtiofsd_session_discard_result(session, lookup,
	    sizeof(lookup), response, written), EPROTO);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid, &sb), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, nodeid, 1), 0);

	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(destroy_replaces_handles_transactionally);
ATF_TC_BODY(destroy_replaces_handles_transactionally, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	uint8_t lookup[45], open_request[48], request[40], response[256];
	char path[32];
	uint64_t nodeid;
	bool reply;
	size_t written;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 81, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);
	request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN, 82,
	    nodeid);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_count(session->handles), 1);

	request_header(request, sizeof(request), DOC_FUSE_DESTROY, 83, 1);
	ATF_CHECK_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), NULL, 0, &written, &reply), EMSGSIZE);
	ATF_CHECK(session->initialized);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 1);

	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK(!session->initialized);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 0);
	ATF_CHECK_EQ(virtiofsd_export_forget(export, nodeid, 1), ESTALE);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid,
	    &(struct stat){}), ESTALE);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(parallel_readers_share_no_session_wide_exclusion);
ATF_TC_BODY(parallel_readers_share_no_session_wide_exclusion, tc)
{
	struct parallel_context contexts[8];
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	pthread_t threads[8];
	char path[32];
	unsigned int i;
	int rootfd;

	rootfd = session_fixture(path, &export, &session);
	initialize(session);
	for (i = 0; i < nitems(threads); i++) {
		contexts[i] = (struct parallel_context) {
			.session = session,
			.worker = i,
		};
		ATF_REQUIRE_EQ(pthread_create(&threads[i], NULL,
		    parallel_reader, &contexts[i]), 0);
	}
	for (i = 0; i < nitems(threads); i++) {
		ATF_REQUIRE_EQ(pthread_join(threads[i], NULL), 0);
		ATF_CHECK_EQ(atomic_load(&contexts[i].error), 0);
	}
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 0);
	session_cleanup(rootfd, path, export, session);
}

ATF_TC_WITHOUT_HEAD(checkpoint_reconstructs_live_objects_transactionally);
ATF_TC_BODY(checkpoint_reconstructs_live_objects_transactionally, tc)
{
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	struct stat sb;
	uint8_t idle[VIRTIOFSD_SESSION_STATE_SIZE];
	uint8_t obsolete[VIRTIOFSD_SESSION_STATE_SIZE], lookup[45],
	    other_lookup[46], open_request[48];
	uint8_t dir_request[48], read_dir[80], read_request[80], request[40];
	uint8_t response[256];
	uint8_t *state, *corrupt;
	char path[32];
	uint64_t directory_handle, handle, nodeid, other_nodeid;
	size_t export_len, handle_offset, state_size, truncated, written;
	bool reply;
	int fd, rootfd;

	rootfd = session_fixture(path, &export, &session);
	fd = openat(rootfd, "other", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(write(fd, "different", 9), 9);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(virtiofsd_session_checkpoint(session, idle), 0);
	ATF_CHECK_EQ(le32dec(idle), VIRTIOFSD_SESSION_STATE_MAGIC);
	ATF_CHECK_EQ(le16dec(idle + 4), VIRTIOFSD_SESSION_STATE_VERSION);
	ATF_CHECK_EQ(le16dec(idle + 6), 0);
	ATF_CHECK_EQ(le32dec(idle + 8), VIRTIOFSD_FUSE_ORDER_UNKNOWN);
	ATF_CHECK_EQ(le32dec(idle + 12), VIRTIOFSD_SESSION_STATE_SIZE);
	ATF_CHECK_EQ(le32dec(idle + 16), 0);
	ATF_CHECK_EQ(le32dec(idle + 20), 0);
	ATF_CHECK_EQ(le64dec(idle + 24), 0);
	memcpy(obsolete, idle, sizeof(obsolete));
	le16enc(obsolete + 4, 1);
	ATF_CHECK_EQ(virtiofsd_session_restore(session, obsolete,
	    sizeof(obsolete)), ENOTSUP);

	initialize(session);
	request_header(lookup, sizeof(lookup), DOC_FUSE_LOOKUP, 90, 1);
	memcpy(lookup + 40, "file", 5);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, lookup,
	    sizeof(lookup), response, sizeof(response), &written, &reply), 0);
	nodeid = le64dec(response + 16);
	request_header(open_request, sizeof(open_request), DOC_FUSE_OPEN, 91,
	    nodeid);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, open_request,
	    sizeof(open_request), response, sizeof(response), &written,
	    &reply), 0);
	handle = le64dec(response + 16);
	request_header(other_lookup, sizeof(other_lookup), DOC_FUSE_LOOKUP, 911,
	    1);
	memcpy(other_lookup + 40, "other", 6);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, other_lookup,
	    sizeof(other_lookup), response, sizeof(response), &written, &reply),
	    0);
	other_nodeid = le64dec(response + 16);
	request_header(dir_request, sizeof(dir_request), DOC_FUSE_OPENDIR, 92,
	    VIRTIOFSD_ROOT_NODEID);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, dir_request,
	    sizeof(dir_request), response, sizeof(response), &written,
	    &reply), 0);
	directory_handle = le64dec(response + 16);
	ATF_REQUIRE_EQ(virtiofsd_session_checkpoint_size(session,
	    &state_size), 0);
	ATF_REQUIRE(state_size > VIRTIOFSD_SESSION_STATE_SIZE);
	state = malloc(state_size);
	corrupt = malloc(state_size);
	ATF_REQUIRE(state != NULL && corrupt != NULL);
	ATF_REQUIRE_EQ(virtiofsd_session_checkpoint_write(session, state,
	    state_size, &written), 0);
	ATF_REQUIRE_EQ(written, state_size);
	ATF_CHECK_EQ(le16dec(state + 4), VIRTIOFSD_SESSION_STATE_VERSION);
	ATF_CHECK_EQ(le32dec(state + 12), state_size);
	export_len = le32dec(state + 16);
	handle_offset = VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_len;
	ATF_REQUIRE(handle_offset + VIRTIOFSD_HANDLE_STATE_HEADER +
	    VIRTIOFSD_HANDLE_STATE_ENTRY <= state_size);
	ATF_REQUIRE_EQ(le64dec(state + handle_offset +
	    VIRTIOFSD_HANDLE_STATE_HEADER), handle);
	/* A handle cannot be rebound to a different live FUSE node. */
	memcpy(corrupt, state, state_size);
	le64enc(corrupt + handle_offset + VIRTIOFSD_HANDLE_STATE_HEADER + 8,
	    other_nodeid);
	ATF_CHECK_EQ(virtiofsd_session_restore(session, corrupt, state_size),
	    EPROTO);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 2);
	/* An open handle remains valid after the kernel forgets its node. */
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, nodeid, 1), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, other_nodeid, 1), 0);
	ATF_REQUIRE_EQ(virtiofsd_session_checkpoint_size(session,
	    &state_size), 0);
	free(state);
	free(corrupt);
	state = malloc(state_size);
	corrupt = malloc(state_size);
	ATF_REQUIRE(state != NULL && corrupt != NULL);
	ATF_REQUIRE_EQ(virtiofsd_session_checkpoint_write(session, state,
	    state_size, &written), 0);
	ATF_REQUIRE_EQ(written, state_size);

	/* A changed destination path must fail before replacing live tables. */
	ATF_REQUIRE_EQ(renameat(rootfd, "file", rootfd, "moved"), 0);
	ATF_CHECK_EQ(virtiofsd_session_restore(session, state, state_size),
	    ENOENT);
	ATF_CHECK(session->initialized);
	request_header(read_request, sizeof(read_request), DOC_FUSE_READ, 93,
	    nodeid);
	le64enc(read_request + 40, handle);
	le32enc(read_request + 56, 8);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 24);
	ATF_CHECK_EQ(memcmp(response + 16, "waspnest", 8), 0);
	ATF_REQUIRE_EQ(renameat(rootfd, "moved", rootfd, "file"), 0);

	/* Reject structural corruption without changing the active session. */
	memcpy(corrupt, state, state_size);
	le64enc(corrupt + 24, 1);
	ATF_CHECK_EQ(virtiofsd_session_restore(session, corrupt, state_size),
	    EPROTO);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 2);
	export_len = le32dec(state + 16);
	handle_offset = VIRTIOFSD_SESSION_STATE_HEADER_SIZE + export_len;
	ATF_REQUIRE(handle_offset + VIRTIOFSD_HANDLE_STATE_HEADER +
	    VIRTIOFSD_HANDLE_STATE_ENTRY + 4 <= state_size);
	memcpy(corrupt, state, state_size);
	memcpy(corrupt + handle_offset + VIRTIOFSD_HANDLE_STATE_HEADER +
	    VIRTIOFSD_HANDLE_STATE_ENTRY, "../x", 4);
	ATF_CHECK_EQ(virtiofsd_session_restore(session, corrupt, state_size),
	    EPROTO);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 2);
	for (truncated = 0; truncated < state_size; truncated++)
		ATF_CHECK(virtiofsd_session_restore(session, state,
		    truncated) != 0);

	/* Clear runtime tables, then reconstruct the exact guest-visible IDs. */
	request_header(request, sizeof(request), DOC_FUSE_DESTROY, 94, 1);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, request,
	    sizeof(request), response, sizeof(response), &written, &reply), 0);
	ATF_REQUIRE_EQ(virtiofsd_session_restore(session, state, state_size), 0);
	ATF_CHECK(session->initialized);
	ATF_CHECK_EQ(session->byte_order, VIRTIOFSD_FUSE_ORDER_LITTLE);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, nodeid, &sb), ESTALE);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 2);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_request,
	    sizeof(read_request), response, sizeof(response), &written,
	    &reply), 0);
	ATF_CHECK_EQ(written, 24);
	ATF_CHECK_EQ(memcmp(response + 16, "waspnest", 8), 0);
	request_header(read_dir, sizeof(read_dir), DOC_FUSE_READDIR, 95,
	    VIRTIOFSD_ROOT_NODEID);
	le64enc(read_dir + 40, directory_handle);
	le32enc(read_dir + 56, 128);
	ATF_REQUIRE_EQ(virtiofsd_session_execute(session, read_dir,
	    sizeof(read_dir), response, sizeof(response), &written, &reply), 0);
	ATF_CHECK(written > VIRTIOFSD_FUSE_OUT_HEADER_SIZE);
	/* Repeated restore is replacement, not accumulation. */
	ATF_REQUIRE_EQ(virtiofsd_session_restore(session, state, state_size), 0);
	ATF_CHECK_EQ(virtiofsd_handles_count(session->handles), 2);
	free(corrupt);
	free(state);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "other", 0), 0);
	session_cleanup(rootfd, path, export, session);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp,
	    read_lifetime_survives_forget_and_release_is_typed);
	ATF_TP_ADD_TC(tp,
	    read_only_policy_is_wire_abi_and_not_native_flags);
	ATF_TP_ADD_TC(tp,
	    newer_major_negotiation_blocks_normal_requests);
	ATF_TP_ADD_TC(tp, readlink_returns_unterminated_wire_bytes);
	ATF_TP_ADD_TC(tp,
	    readdir_uses_linux_wire_layout_and_hides_special_files);
	ATF_TP_ADD_TC(tp, statfs_and_access_are_explicitly_read_only);
	ATF_TP_ADD_TC(tp,
	    batch_forget_validates_all_entries_before_applying);
	ATF_TP_ADD_TC(tp, canceled_resource_results_are_rolled_back);
	ATF_TP_ADD_TC(tp, destroy_replaces_handles_transactionally);
	ATF_TP_ADD_TC(tp,
	    checkpoint_reconstructs_live_objects_transactionally);
	ATF_TP_ADD_TC(tp,
	    parallel_readers_share_no_session_wide_exclusion);
	return (atf_no_error());
}

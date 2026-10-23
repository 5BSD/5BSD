/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct tests for the filesystem backend's protocol-component validation.
 */

#include <atf-c.h>
#include <sys/capsicum.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t, size_t);

static int fail_calloc_after = -1;

void *
__wrap_calloc(size_t count, size_t size)
{

	if (fail_calloc_after >= 0) {
		if (fail_calloc_after-- == 0) {
			errno = ENOMEM;
			return (NULL);
		}
	}
	return (__real_calloc(count, size));
}

/*
 * Include the implementation so the test exercises the exact internal
 * component builder used by create, link, rename, and unlink operations.
 * Unreferenced backend sections are discarded by the rootless harness.
 */
#include "backend/fs.c"
#include "hashtable.c"
#include "connection.c"

ATF_TC_WITHOUT_HEAD(single_component_names);
ATF_TC_BODY(single_component_names, tc)
{
	struct fs_fid ff;
	struct l9p_fid fid;
	char path[MAXPATHLEN];

	memset(&ff, 0, sizeof(ff));
	memset(&fid, 0, sizeof(fid));
	ff.ff_name = __DECONST(char *, "parent");
	fid.lo_aux = &ff;

	ATF_CHECK_EQ(fs_buildname(&fid, "child", path, sizeof(path)), 0);
	ATF_CHECK_STREQ(path, "parent/child");
	ATF_CHECK_EQ(fs_buildname(&fid, "", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, ".", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, "..", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, "nested/child", path, sizeof(path)),
	    EINVAL);

	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "renamed", sizeof(path)), 0);
	ATF_CHECK_STREQ(path, "parent/renamed");
	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "../outside", sizeof(path)), EINVAL);

	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "child", strlen("parent/child")),
	    ENAMETOOLONG);
	ATF_CHECK_STREQ(path, "parent");
	ATF_CHECK_EQ(fs_buildname(&fid, "child", path,
	    strlen("parent/child")), ENAMETOOLONG);
}

ATF_TC_WITHOUT_HEAD(fid_allocation_failure_rolls_back);
ATF_TC_BODY(fid_allocation_failure_rolls_back, tc)
{
	struct fs_authinfo ai;
	struct ht table;
	int value;

	(void)tc;
	memset(&ai, 0, sizeof(ai));
	ATF_REQUIRE_EQ(pthread_mutex_init(&ai.ai_mtx, NULL), 0);
	fail_calloc_after = 0;
	ATF_CHECK(open_fid(-1, ".", &ai, true) == NULL);
	ATF_CHECK_EQ(ai.ai_refcnt, 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&ai.ai_mtx), 0);

	value = 7;
	ht_init(&table, 8);
	fail_calloc_after = 0;
	errno = 0;
	ATF_CHECK_EQ(ht_add(&table, 42, &value), -1);
	ATF_CHECK_EQ(errno, ENOMEM);
	ATF_CHECK(ht_find(&table, 42) == NULL);
	ATF_REQUIRE_EQ(ht_add(&table, 42, &value), 0);
	ATF_CHECK(ht_find(&table, 42) == &value);
	ATF_REQUIRE_EQ(ht_remove(&table, 42), 0);
	ht_destroy(&table);
}

ATF_TC_WITHOUT_HEAD(connection_allocation_failure_rolls_back);
ATF_TC_BODY(connection_allocation_failure_rolls_back, tc)
{
	struct l9p_connection conn;
	struct iovec iov;
	uint8_t request[7] = { 0 };
	struct l9p_fid *fid;
	int error, result;

	(void)tc;
	memset(&conn, 0, sizeof(conn));
	iov.iov_base = request;
	iov.iov_len = sizeof(request);
	fail_calloc_after = 0;
	errno = 0;
	result = l9p_connection_recv(&conn, &iov, 1, NULL);
	error = errno;
	ATF_CHECK_EQ(result, -1);
	ATF_CHECK_EQ(error, ENOMEM);

	ht_init(&conn.lc_files, 8);
	fail_calloc_after = 0;
	errno = 0;
	fid = l9p_connection_alloc_fid(&conn, 42);
	error = errno;
	ATF_CHECK(fid == NULL);
	ATF_CHECK_EQ(error, ENOMEM);
	ATF_CHECK(ht_find(&conn.lc_files, 42) == NULL);

	fail_calloc_after = 1;
	errno = 0;
	fid = l9p_connection_alloc_fid(&conn, 42);
	error = errno;
	ATF_CHECK(fid == NULL);
	ATF_CHECK_EQ(error, ENOMEM);
	ATF_CHECK(ht_find(&conn.lc_files, 42) == NULL);
	ht_destroy(&conn.lc_files);
}

ATF_TC_WITHOUT_HEAD(fid_rebind_and_identity);
ATF_TC_BODY(fid_rebind_and_identity, tc)
{
	struct l9p_fs_fid_state state, replay;
	struct l9p_backend backend;
	cap_rights_t rights;
	struct fs_softc softc;
	struct fs_authinfo *ai;
	struct fs_fid *file;
	struct dirent *source_entry, *restored_entry;
	struct l9p_fid source, restored, stale, dir_source, dir_restored;
	char dirname[] = "/tmp/lib9p-fid.XXXXXX";
	char content[6];
	char *saved_path;
	int fd, rootfd;

	ATF_REQUIRE(mkdtemp(dirname) != NULL);
	rootfd = open(dirname, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(rootfd >= 0);
	ATF_REQUIRE_EQ(fcntl(rootfd, F_SETFD,
	    fcntl(rootfd, F_GETFD) | FD_RESOLVE_BENEATH), 0);
	fd = openat(rootfd, "file", O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(pwrite(fd, "source", sizeof(content), 0),
	    (ssize_t)sizeof(content));
	memset(&softc, 0, sizeof(softc));
	softc.fs_rootfd = rootfd;
	memset(&backend, 0, sizeof(backend));
	backend.softc = &softc;
	ai = calloc(1, sizeof(*ai) + 2 * sizeof(gid_t));
	ATF_REQUIRE(ai != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_init(&ai->ai_mtx, NULL), 0);
	ai->ai_uid = 1000;
	ai->ai_ngids = 2;
	ai->ai_gids[0] = 10;
	ai->ai_gids[1] = 20;
	file = open_fid(rootfd, "file", ai, true);
	ATF_REQUIRE(file != NULL);
	file->ff_fd = fd;
	cap_rights_init(&rights, CAP_LOOKUP, CAP_FSTAT, CAP_READ,
	    CAP_WRITE, CAP_SEEK, CAP_PREAD, CAP_PWRITE, CAP_CREATE,
	    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT,
	    CAP_FCNTL);
	ATF_REQUIRE_EQ(cap_rights_limit(rootfd, &rights), 0);
	ATF_REQUIRE_EQ(cap_fcntls_limit(rootfd, CAP_FCNTL_GETFL), 0);
	memset(&source, 0, sizeof(source));
	source.lo_aux = file;
	source.lo_flags = L9P_LO_ISVALID | L9P_LO_ISOPEN;
	ATF_REQUIRE_EQ(l9p_backend_fs_export_fid(&backend, &source, &state), 0);
	ATF_CHECK_STREQ(state.path, "file");
	ATF_CHECK_EQ(state.uid, 1000);
	ATF_CHECK_EQ(state.ngids, 2);
	ATF_CHECK_EQ(state.gids[0], 10);
	ATF_CHECK_EQ(state.gids[1], 20);
	ATF_CHECK_EQ(state.open_flags & O_ACCMODE, O_RDWR);

	memset(&restored, 0, sizeof(restored));
	ATF_REQUIRE_EQ(l9p_backend_fs_import_fid(&backend, &state,
	    &restored, false, L9P_2000L), 0);
	ATF_CHECK_EQ(restored.lo_flags, source.lo_flags);
	ATF_CHECK(((struct fs_fid *)restored.lo_aux)->ff_fd >= 0);
	ATF_REQUIRE_EQ(pread(((struct fs_fid *)restored.lo_aux)->ff_fd,
	    content, sizeof(content), 0), (ssize_t)sizeof(content));
	ATF_CHECK_EQ(memcmp(content, "source", sizeof(content)), 0);
	ATF_REQUIRE_EQ(pwrite(((struct fs_fid *)restored.lo_aux)->ff_fd,
	    "rebind", sizeof(content), 0), (ssize_t)sizeof(content));
	ATF_REQUIRE_EQ(pread(fd, content, sizeof(content), 0),
	    (ssize_t)sizeof(content));
	ATF_CHECK_EQ(memcmp(content, "rebind", sizeof(content)), 0);
	ATF_REQUIRE_EQ(l9p_backend_fs_export_fid(&backend, &restored,
	    &replay), 0);
	l9p_backend_fs_free_fid_state(&replay);
	state.dev ^= 1;
	memset(&stale, 0, sizeof(stale));
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    false, L9P_2000L), ESTALE);
	ATF_REQUIRE_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    true, L9P_2000L), 0);
	fs_freefid(&softc, &stale);
	stale.lo_aux = NULL;
	state.dev ^= 1;
	saved_path = state.path;
	state.path = __DECONST(char *, "../outside");
	memset(&stale, 0, sizeof(stale));
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    false, L9P_2000L),
	    EINVAL);
	state.path = saved_path;
	fs_freefid(&softc, &restored);

	ATF_REQUIRE_EQ(renameat(rootfd, "file", rootfd, "old"), 0);
	fd = openat(rootfd, "file", O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	memset(&stale, 0, sizeof(stale));
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    false, L9P_2000L),
	    ESTALE);
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    true, L9P_2000L), ESTALE);
	ATF_CHECK(stale.lo_aux == NULL);

	l9p_backend_fs_free_fid_state(&state);
	fs_freefid(&softc, &source);
	ai = calloc(1, sizeof(*ai));
	ATF_REQUIRE(ai != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_init(&ai->ai_mtx, NULL), 0);
	ai->ai_uid = 1000;
	file = open_fid(rootfd, ".", ai, true);
	ATF_REQUIRE(file != NULL);
	fd = openat(rootfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	ATF_REQUIRE(fd >= 0);
	file->ff_dir = fdopendir(fd);
	ATF_REQUIRE(file->ff_dir != NULL);
	ATF_REQUIRE_EQ(fs_dir_seek_index(file, 2), 0);
	ATF_CHECK_EQ(file->ff_dir_index, 2);
	memset(&dir_source, 0, sizeof(dir_source));
	dir_source.lo_aux = file;
	dir_source.lo_flags = L9P_LO_ISVALID | L9P_LO_ISDIR | L9P_LO_ISOPEN;
	ATF_REQUIRE_EQ(l9p_backend_fs_export_fid(&backend, &dir_source,
	    &state), 0);
	ATF_CHECK_EQ(state.dir_index, 2);
	ATF_CHECK(state.dir_hash != 0);
	ATF_CHECK_EQ(fs_dir_seek_index(file, UINT64_MAX), ESTALE);
	ATF_CHECK_EQ(file->ff_dir_index, state.dir_index);
	ATF_CHECK_EQ(file->ff_dir_hash, state.dir_hash);
	state.dir_hash ^= 1;
	memset(&stale, 0, sizeof(stale));
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    false, L9P_2000L), ESTALE);
	ATF_CHECK(stale.lo_aux == NULL);
	state.dir_hash ^= 1;
	state.dir_index = UINT64_MAX;
	memset(&stale, 0, sizeof(stale));
	ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state, &stale,
	    false, L9P_2000L),
	    ESTALE);
	ATF_CHECK(stale.lo_aux == NULL);
	state.dir_index = 2;
	memset(&dir_restored, 0, sizeof(dir_restored));
	ATF_REQUIRE_EQ(l9p_backend_fs_import_fid(&backend, &state,
	    &dir_restored, false, L9P_2000L), 0);
	ATF_CHECK(((struct fs_fid *)dir_restored.lo_aux)->ff_dir != NULL);
	ATF_CHECK_EQ(((struct fs_fid *)dir_restored.lo_aux)->ff_dir_index,
	    2);
	source_entry = readdir(file->ff_dir);
	restored_entry = readdir(((struct fs_fid *)dir_restored.lo_aux)->ff_dir);
	ATF_REQUIRE(source_entry != NULL);
	ATF_REQUIRE(restored_entry != NULL);
	ATF_CHECK_STREQ(source_entry->d_name, restored_entry->d_name);
	ATF_REQUIRE_EQ(fs_dir_seek_index(dir_restored.lo_aux, 0), 0);
	ATF_CHECK_EQ(((struct fs_fid *)dir_restored.lo_aux)->ff_dir_index,
	    0);
	ATF_REQUIRE_EQ(l9p_backend_fs_export_fid(&backend, &dir_restored,
	    &replay), 0);
	l9p_backend_fs_free_fid_state(&replay);
	l9p_backend_fs_free_fid_state(&state);
	fs_freefid(&softc, &dir_restored);
	fs_freefid(&softc, &dir_source);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "file", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "old", 0), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(dirname), 0);
}

ATF_TC_WITHOUT_HEAD(directory_cursor_hash_tracks_identity);
ATF_TC_BODY(directory_cursor_hash_tracks_identity, tc)
{
	struct dirent original, changed;
	uint64_t hash;

	(void)tc;
	memset(&original, 0, sizeof(original));
	strlcpy(original.d_name, "entry", sizeof(original.d_name));
	original.d_fileno = 41;
	hash = fs_dir_hash_entry(0, &original);
	ATF_CHECK_EQ(hash, fs_dir_hash_entry(0, &original));
	changed = original;
	changed.d_fileno = 42;
	ATF_CHECK(hash != fs_dir_hash_entry(0, &changed));
	changed = original;
	strlcpy(changed.d_name, "other", sizeof(changed.d_name));
	ATF_CHECK(hash != fs_dir_hash_entry(0, &changed));
}

ATF_TC_WITHOUT_HEAD(readdir_short_reply_preserves_cursor);
ATF_TC_BODY(readdir_short_reply_preserves_cursor, tc)
{
	struct l9p_request req = { 0 };
	struct l9p_fid fid = { 0 };
	struct fs_fid file = { 0 };
	struct dirent *entry;
	char dirname[] = "/tmp/lib9p-readdir.XXXXXX";
	char first[NAME_MAX + 1];
	uint8_t wire[1];
	int rootfd;

	(void)tc;
	ATF_REQUIRE(mkdtemp(dirname) != NULL);
	rootfd = open(dirname, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(rootfd >= 0);
	file.ff_dir = fdopendir(dup(rootfd));
	ATF_REQUIRE(file.ff_dir != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_init(&file.ff_mtx, NULL), 0);
	entry = readdir(file.ff_dir);
	ATF_REQUIRE(entry != NULL);
	ATF_REQUIRE(strlcpy(first, entry->d_name, sizeof(first)) <
	    sizeof(first));
	rewinddir(file.ff_dir);
	fid.lo_aux = &file;
	req.lr_fid = &fid;
	req.lr_data_iov[0].iov_base = wire;
	req.lr_data_iov[0].iov_len = sizeof(wire);
	req.lr_data_niov = 1;
	ATF_REQUIRE_EQ(fs_readdir(NULL, &req), 0);
	ATF_CHECK_EQ(req.lr_resp.io.count, 0);
	ATF_CHECK_EQ(file.ff_dir_index, 0);
	ATF_CHECK_EQ(file.ff_dir_hash, 0);
	entry = readdir(file.ff_dir);
	ATF_REQUIRE(entry != NULL);
	ATF_CHECK_STREQ(entry->d_name, first);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&file.ff_mtx), 0);
	ATF_REQUIRE_EQ(closedir(file.ff_dir), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(dirname), 0);
}

ATF_TC_WITHOUT_HEAD(fid_import_rejects_symlink_escape);
ATF_TC_BODY(fid_import_rejects_symlink_escape, tc)
{
	struct l9p_fs_fid_state state;
	struct l9p_backend backend;
	struct l9p_fid fid;
	struct fs_softc softc;
	struct stat st;
	char root[] = "/tmp/lib9p-root.XXXXXX";
	char outside[] = "/tmp/lib9p-outside.XXXXXX";
	int fd, rootfd, outsidefd;

	(void)tc;
	ATF_REQUIRE(mkdtemp(root) != NULL);
	ATF_REQUIRE(mkdtemp(outside) != NULL);
	rootfd = open(root, O_RDONLY | O_DIRECTORY);
	outsidefd = open(outside, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(rootfd >= 0 && outsidefd >= 0);
	fd = openat(outsidefd, "target", O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(fstat(fd, &st), 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(symlinkat(outside, rootfd, "link"), 0);
	memset(&state, 0, sizeof(state));
	state.path = __DECONST(char *, "link/target");
	state.flags = L9P_LO_ISVALID;
	state.dev = st.st_dev;
	state.ino = st.st_ino;
	state.mode = S_IFREG;
	memset(&softc, 0, sizeof(softc));
	softc.fs_rootfd = rootfd;
	memset(&backend, 0, sizeof(backend));
	backend.softc = &softc;
	memset(&fid, 0, sizeof(fid));
	/* This root fd deliberately lacks FD_RESOLVE_BENEATH. */
	ATF_CHECK(l9p_backend_fs_import_fid(&backend, &state, &fid,
	    false, L9P_2000L) != 0);
	ATF_CHECK(fid.lo_aux == NULL);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "link", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(outsidefd, "target", 0), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(close(outsidefd), 0);
	ATF_REQUIRE_EQ(rmdir(root), 0);
	ATF_REQUIRE_EQ(rmdir(outside), 0);
}

static void
classic_directory_tread_cursor_restore_case(enum l9p_version version)
{
	struct l9p_fs_fid_state state;
	struct l9p_backend backend = { 0 };
	cap_rights_t rights;
	struct fs_softc softc = { 0 };
	struct fs_authinfo *ai;
	struct fs_fid *source_file, *restored_file;
	struct l9p_stat first_stat;
	struct dirent *entry;
	struct stat st;
	struct l9p_connection conn = { 0 };
	struct l9p_fid source = { 0 }, restored = { 0 };
	struct l9p_request request = { 0 }, replay = { 0 };
	struct l9p_request invalid = { 0 };
	struct l9p_request source_next = { 0 }, restored_next = { 0 };
	uint8_t wire[4096], replay_wire[4096];
	uint8_t source_next_wire[4096], restored_next_wire[4096];
	char dirname[] = "/tmp/lib9p-classic-dir.XXXXXX";
	uint32_t first_count, first_size;
	int error, fd, rootfd;

	ATF_REQUIRE(mkdtemp(dirname) != NULL);
	rootfd = open(dirname, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(rootfd >= 0);
	ATF_REQUIRE_EQ(fcntl(rootfd, F_SETFD,
	    fcntl(rootfd, F_GETFD) | FD_RESOLVE_BENEATH), 0);
	fd = openat(rootfd, "file", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(close(fd), 0);
	softc.fs_rootfd = rootfd;
	backend.softc = &softc;
	ai = calloc(1, sizeof(*ai));
	ATF_REQUIRE(ai != NULL);
	ATF_REQUIRE_EQ(pthread_mutex_init(&ai->ai_mtx, NULL), 0);
	source_file = open_fid(rootfd, ".", ai, true);
	ATF_REQUIRE(source_file != NULL);
	fd = openat(rootfd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	ATF_REQUIRE(fd >= 0);
	source_file->ff_dir = fdopendir(fd);
	ATF_REQUIRE(source_file->ff_dir != NULL);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_SEEK,
	    CAP_FSTAT, CAP_PREAD, CAP_FCNTL, CAP_UNLINKAT);
	ATF_REQUIRE_EQ(cap_rights_limit(rootfd, &rights), 0);
	ATF_REQUIRE_EQ(cap_fcntls_limit(rootfd, CAP_FCNTL_GETFL), 0);
	source.lo_aux = source_file;
	source.lo_flags = L9P_LO_ISVALID | L9P_LO_ISDIR | L9P_LO_ISOPEN;
	conn.lc_version = version;
	entry = readdir(source_file->ff_dir);
	ATF_REQUIRE(entry != NULL);
	ATF_REQUIRE_EQ(fs_lstatat(source_file, entry->d_name, &st), 0);
	dostat(&softc, &first_stat, dirfd(source_file->ff_dir),
	    entry->d_name, &st, version >= L9P_2000U);
	first_size = l9p_sizeof_stat(&first_stat, conn.lc_version);
	l9p_freestat(&first_stat);
	rewinddir(source_file->ff_dir);
	request.lr_conn = &conn;
	request.lr_fid = &source;
	request.lr_req.io.count = first_size;
	request.lr_data_iov[0].iov_base = wire;
	request.lr_data_iov[0].iov_len = sizeof(wire);
	request.lr_data_niov = 1;
	ATF_REQUIRE_EQ(fs_read(&softc, &request), 0);
	first_count = request.lr_resp.io.count;
	ATF_REQUIRE_EQ(first_count, first_size);
	ATF_CHECK_EQ(source_file->ff_dir_bytes, first_count);
	ATF_REQUIRE_EQ(l9p_backend_fs_export_fid(&backend, &source,
	    &state), 0);
	ATF_CHECK_EQ(state.dir_bytes, first_count);
	error = l9p_backend_fs_import_fid(&backend, &state, &restored,
	    false, version);
	ATF_REQUIRE_MSG(error == 0,
	    "import error %d; index %ju hash %jx bytes %ju", error,
	    (uintmax_t)state.dir_index, (uintmax_t)state.dir_hash,
	    (uintmax_t)state.dir_bytes);
	restored_file = restored.lo_aux;
	ATF_CHECK_EQ(restored_file->ff_dir_bytes, first_count);
	ATF_CHECK_EQ(restored_file->ff_dir_index, state.dir_index);
	ATF_CHECK_EQ(restored_file->ff_dir_hash, state.dir_hash);
	state.dir_bytes++;
	{
		struct l9p_fid stale = { 0 };

		ATF_CHECK(l9p_backend_fs_import_fid(&backend, &state,
		    &stale, false, version) != 0);
		ATF_CHECK(stale.lo_aux == NULL);
	}
	state.dir_bytes--;
	state.dir_bytes--;
	{
		struct l9p_fid stale = { 0 };

		ATF_CHECK_EQ(l9p_backend_fs_import_fid(&backend, &state,
		    &stale, false, version), ESTALE);
		ATF_CHECK(stale.lo_aux == NULL);
	}
	state.dir_bytes++;
	invalid.lr_conn = &conn;
	invalid.lr_fid = &source;
	invalid.lr_req.io.offset = first_count + 1;
	invalid.lr_req.io.count = sizeof(wire);
	invalid.lr_data_iov[0].iov_base = wire;
	invalid.lr_data_iov[0].iov_len = sizeof(wire);
	invalid.lr_data_niov = 1;
	ATF_CHECK_EQ(fs_read(&softc, &invalid), EINVAL);
	ATF_CHECK_EQ(source_file->ff_dir_bytes, state.dir_bytes);
	ATF_CHECK_EQ(source_file->ff_dir_index, state.dir_index);
	ATF_CHECK_EQ(source_file->ff_dir_hash, state.dir_hash);
	source_next.lr_conn = &conn;
	source_next.lr_fid = &source;
	source_next.lr_req.io.offset = first_count;
	source_next.lr_req.io.count = sizeof(source_next_wire);
	source_next.lr_data_iov[0].iov_base = source_next_wire;
	source_next.lr_data_iov[0].iov_len = sizeof(source_next_wire);
	source_next.lr_data_niov = 1;
	restored_next.lr_conn = &conn;
	restored_next.lr_fid = &restored;
	restored_next.lr_req.io.offset = first_count;
	restored_next.lr_req.io.count = sizeof(restored_next_wire);
	restored_next.lr_data_iov[0].iov_base = restored_next_wire;
	restored_next.lr_data_iov[0].iov_len = sizeof(restored_next_wire);
	restored_next.lr_data_niov = 1;
	ATF_REQUIRE_EQ(fs_read(&softc, &source_next), 0);
	ATF_REQUIRE_EQ(fs_read(&softc, &restored_next), 0);
	ATF_CHECK_EQ(source_next.lr_resp.io.count,
	    restored_next.lr_resp.io.count);
	ATF_CHECK_EQ(memcmp(source_next_wire, restored_next_wire,
	    source_next.lr_resp.io.count), 0);
	/* A zero byte offset starts a fresh scan of the same directory. */
	replay.lr_conn = &conn;
	replay.lr_fid = &restored;
	replay.lr_req.io.offset = 0;
	replay.lr_req.io.count = first_count;
	replay.lr_data_iov[0].iov_base = replay_wire;
	replay.lr_data_iov[0].iov_len = sizeof(replay_wire);
	replay.lr_data_niov = 1;
	ATF_REQUIRE_EQ(fs_read(&softc, &replay), 0);
	ATF_CHECK_EQ(replay.lr_resp.io.count, first_count);
	ATF_CHECK_EQ(memcmp(replay_wire, wire, first_count), 0);
	l9p_backend_fs_free_fid_state(&state);
	fs_freefid(&softc, &restored);
	fs_freefid(&softc, &source);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "file", 0), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(dirname), 0);
}

ATF_TC_WITHOUT_HEAD(classic_directory_tread_cursor_restore);
ATF_TC_BODY(classic_directory_tread_cursor_restore, tc)
{

	(void)tc;
	classic_directory_tread_cursor_restore_case(L9P_2000);
}

ATF_TC_WITHOUT_HEAD(classic_u_directory_tread_cursor_restore);
ATF_TC_BODY(classic_u_directory_tread_cursor_restore, tc)
{

	(void)tc;
	classic_directory_tread_cursor_restore_case(L9P_2000U);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fid_allocation_failure_rolls_back);
	ATF_TP_ADD_TC(tp, connection_allocation_failure_rolls_back);
	ATF_TP_ADD_TC(tp, single_component_names);
	ATF_TP_ADD_TC(tp, fid_rebind_and_identity);
	ATF_TP_ADD_TC(tp, directory_cursor_hash_tracks_identity);
	ATF_TP_ADD_TC(tp, readdir_short_reply_preserves_cursor);
	ATF_TP_ADD_TC(tp, classic_directory_tread_cursor_restore);
	ATF_TP_ADD_TC(tp, classic_u_directory_tread_cursor_restore);
	ATF_TP_ADD_TC(tp, fid_import_rejects_symlink_escape);
	return (atf_no_error());
}

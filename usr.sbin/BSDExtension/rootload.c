/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Root loads for bsdextension(8): system.SystemExtension.RootLoad.
 *
 * A UID 0 login session (switchboard root-load.ucl) may ask the broker to load
 * a kernel module the base system installed.  The broker loads
 * /boot/kernel/NAME.ko -- by that absolute path, so kern.module_path cannot
 * redirect it -- only when all of these hold:
 *
 *  - /boot/kernel/NAME.ko, opened beneath the delivered kernel directory with
 *    O_NOFOLLOW, is a regular file (no symlink, no other directory);
 *  - the local package database records that path in a package whose origin
 *    is base/... and whose "repository" annotation is the configured base
 *    repository (root_load_repository), not as a symbolic link;
 *  - the file's checksum, computed here, equals the one pkg recorded at
 *    installation (pkg 2 records "2$" + z-base-32 BLAKE2b-512);
 *  - the file did not change while it was checked and loaded, and every file
 *    the kernel linker brought in with it (MODULE_DEPEND) passes the same
 *    checks; otherwise the load is undone.
 *
 * The package database is parsed in a pdfork(2)ed child.  The kldload token is
 * close-on-fork, and the child closes every descriptor but the delivered
 * /var/db/pkg directory and its reply pipe, so a malformed database reaches a
 * process that can load nothing.  The child maps local.sqlite privately and
 * opens it with sqlite3_deserialize(3) read-only (base's private sqlite; libpkg
 * is not part of base), with views, triggers and untrusted schema functions
 * disabled.
 *
 * What this is not: the package database and /boot/kernel are both writable by
 * root, so a root that edits the database, replaces a file between the check
 * and the load, or mounts over /boot/kernel defeats it, as does installing a
 * package or editing loader.conf and rebooting.  It keeps a root login shell
 * from loading arbitrary or modified files by mistake and records every
 * request; mac_veriexec(4) is the control against a compromised root.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sqlite3.h>
#include <libservice.h>

#include "sysext_proto.h"
#include "bsdextension.h"

/* sys/contrib/libb2 reference BLAKE2b, built with SUFFIX=_ref. */
#include "blake2.h"
int	blake2b_init_ref(blake2b_state *, size_t);
int	blake2b_update_ref(blake2b_state *, const uint8_t *, size_t);
int	blake2b_final_ref(blake2b_state *, uint8_t *, size_t);

#define	KERNEL_PREFIX		SYSEXT_KERNEL_DIR "/"
#define	PKGDB_TIMEOUT_MS	15000
#define	PKGDB_HEAP_LIMIT	(64LL * 1024 * 1024)
#define	ROOT_NEW_FILES_MAX	16

int sysext_pkgdb_dirfd = -1;
pthread_mutex_t sysext_load_lock = PTHREAD_MUTEX_INITIALIZER;

/* Modules a root load loaded: only these may be root-unloaded. */
struct root_loaded {
	char	file[SYSEXT_NAME_MAX + 3];	/* NAME.ko */
	int	fileid;
	bool	shared;		/* another client asked for it since */
	bool	used;
};
static pthread_mutex_t root_lock = PTHREAD_MUTEX_INITIALIZER;
static struct root_loaded root_loaded[SYSEXT_ROOT_LOADED_MAX];

#ifdef BSDEXTENSION_TESTING
int (*sysext_test_kld_load)(const char *, int *);
int (*sysext_test_kld_unload)(int);
int (*sysext_test_kld_stat)(int, char *, size_t, char *, size_t);
int (*sysext_test_kld_next)(int);

void
sysext_test_root_reset(void)
{

	pthread_mutex_lock(&root_lock);
	memset(root_loaded, 0, sizeof(root_loaded));
	pthread_mutex_unlock(&root_lock);
}
#endif

/* ------------------------------------------------------------ kernel seams */

static int
kld_load(const char *path, int *fileid)
{

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_kld_load != NULL)
		return (sysext_test_kld_load(path, fileid));
#endif
	if (sysext_kld_token >= 0)
		return (service_system_kldload(sysext_kld_token, path,
		    fileid) == 0 ? 0 : errno);
	if ((*fileid = kldload(path)) == -1)
		return (errno);
	return (0);
}

static int
kld_unload(int fileid)
{

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_kld_unload != NULL)
		return (sysext_test_kld_unload(fileid));
#endif
	if (sysext_kld_token >= 0)
		return (service_system_kldunload(sysext_kld_token, fileid,
		    LINKER_UNLOAD_NORMAL) == 0 ? 0 : errno);
	return (kldunload(fileid) == 0 ? 0 : errno);
}

static int
kld_stat(int fileid, char *name, size_t namelen, char *path, size_t pathlen)
{
	struct kld_file_stat fs;

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_kld_stat != NULL)
		return (sysext_test_kld_stat(fileid, name, namelen, path,
		    pathlen));
#endif
	memset(&fs, 0, sizeof(fs));
	fs.version = sizeof(fs);
	if (kldstat(fileid, &fs) == -1)
		return (errno);
	(void)strlcpy(name, fs.name, namelen);
	(void)strlcpy(path, fs.pathname, pathlen);
	return (0);
}

static int
kld_next(int fileid)
{
	int next;

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_kld_next != NULL)
		return (sysext_test_kld_next(fileid));
#endif
	next = kldnext(fileid);
	return (next > 0 ? next : 0);
}

/* ------------------------------------------------------- pkg's checksums */

/*
 * pkg's base32 (pkg_checksum.c pkg_checksum_encode_base32): the z-base-32
 * alphabet, least significant bits first.  A different bit order from RFC
 * 4648, so it is reproduced here exactly.
 */
void
sysext_pkg_base32(const unsigned char *in, size_t inlen, char *out,
    size_t outlen)
{
	static const char b32[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
	size_t i, r = 0;
	int remain = -1, x;

	if (outlen < (inlen * 8 + 4) / 5 + 1) {
		if (outlen > 0)
			out[0] = '\0';
		return;
	}
	for (i = 0; i < inlen; i++) {
		switch (i % 5) {
		case 0:
			x = in[i];
			remain = in[i] >> 5;
			out[r++] = b32[x & 0x1f];
			break;
		case 1:
			x = remain | in[i] << 3;
			out[r++] = b32[x & 0x1f];
			out[r++] = b32[x >> 5 & 0x1f];
			remain = x >> 10;
			break;
		case 2:
			x = remain | in[i] << 1;
			out[r++] = b32[x & 0x1f];
			remain = x >> 5;
			break;
		case 3:
			x = remain | in[i] << 4;
			out[r++] = b32[x & 0x1f];
			out[r++] = b32[x >> 5 & 0x1f];
			remain = x >> 10 & 0x3;
			break;
		case 4:
			x = remain | in[i] << 2;
			out[r++] = b32[x & 0x1f];
			out[r++] = b32[x >> 5 & 0x1f];
			remain = -1;
			break;
		}
	}
	if (remain >= 0)
		out[r++] = b32[remain];
	out[r] = '\0';
}

int
sysext_pkg_checksum_fd(int fd, char *out, size_t outlen)
{
	blake2b_state state;
	unsigned char *buf, digest[BLAKE2B_OUTBYTES];
	off_t off = 0;
	ssize_t n;
	int error = 0;

	if (outlen < 3 + (BLAKE2B_OUTBYTES * 8 + 4) / 5 + 1)
		return (ENAMETOOLONG);
	if ((buf = malloc(64 * 1024)) == NULL)
		return (ENOMEM);
	if (blake2b_init_ref(&state, BLAKE2B_OUTBYTES) != 0) {
		free(buf);
		return (EINVAL);
	}
	for (;;) {
		n = pread(fd, buf, 64 * 1024, off);
		if (n == -1 && errno == EINTR)
			continue;
		if (n == -1) {
			error = errno;
			break;
		}
		if (n == 0)
			break;
		if (off + n > SYSEXT_MODULE_FILE_MAX) {
			error = EFBIG;
			break;
		}
		(void)blake2b_update_ref(&state, buf, (size_t)n);
		off += n;
	}
	free(buf);
	if (error != 0)
		return (error);
	if (blake2b_final_ref(&state, digest, sizeof(digest)) != 0)
		return (EINVAL);
	out[0] = '2';
	out[1] = '$';
	sysext_pkg_base32(digest, sizeof(digest), out + 2, outlen - 2);
	return (0);
}

/* ------------------------------------------------------ package database */

/* The child's reply: fixed size, NUL-terminated strings. */
struct pkgdb_reply {
	int32_t	status;
	int32_t	found;
	int32_t	symlink;
	char	checksum[SYSEXT_PKG_CHECKSUM_MAX];
	char	package[128];
	char	origin[160];
	char	repository[SYSEXT_REPOSITORY_MAX];
};

static const char pkgdb_query_sql[] =
    "SELECT f.sha256, f.symlink_target, p.name, p.origin,"
    " (SELECT v.annotation FROM pkg_annotation pa"
    "  JOIN annotation t ON t.annotation_id = pa.tag_id"
    "  JOIN annotation v ON v.annotation_id = pa.value_id"
    "  WHERE pa.package_id = p.id AND t.annotation = 'repository')"
    " FROM files f JOIN packages p ON p.id = f.package_id"
    " WHERE f.path = ?1";

/* Copy a text column; false when it does not fit (never truncate). */
static bool
column_copy(sqlite3_stmt *stmt, int col, char *out, size_t outlen)
{
	const unsigned char *text;
	int len;

	out[0] = '\0';
	if (sqlite3_column_type(stmt, col) == SQLITE_NULL)
		return (true);
	text = sqlite3_column_text(stmt, col);
	len = sqlite3_column_bytes(stmt, col);
	if (text == NULL || len < 0 || (size_t)len >= outlen ||
	    memchr(text, '\0', (size_t)len) != NULL)
		return (false);
	memcpy(out, text, (size_t)len);
	out[len] = '\0';
	return (true);
}

/* In the child: answer one path from a private, read-only image of the db. */
static int
pkgdb_query(int dirfd, const char *path, struct pkgdb_reply *reply)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;
	struct stat st;
	unsigned char *image;
	char target[8];
	int fd, rc, error;

	fd = openat(dirfd, SYSEXT_PKGDB_FILE, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC | O_NONBLOCK);
	if (fd == -1)
		return (errno);
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size < 512 ||
	    st.st_size > SYSEXT_PKGDB_MAX) {
		(void)close(fd);
		return (EFTYPE);
	}
	image = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE, fd, 0);
	(void)close(fd);
	if (image == MAP_FAILED)
		return (errno);
	/*
	 * An in-memory image cannot use a write-ahead log: open a WAL-mode
	 * file as a rollback-journal one (header bytes 18 and 19).  Changes
	 * still only in the WAL are not seen; the checksum comparison then
	 * fails closed.
	 */
	if (image[18] == 2)
		image[18] = 1;
	if (image[19] == 2)
		image[19] = 1;
	(void)sqlite3_hard_heap_limit64(PKGDB_HEAP_LIMIT);
	error = EIO;
	if (sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE,
	    NULL) != SQLITE_OK)
		goto out;
	(void)sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
	(void)sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
	(void)sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, NULL);
	(void)sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, NULL);
	if (sqlite3_deserialize(db, "main", image, st.st_size, st.st_size,
	    SQLITE_DESERIALIZE_READONLY) != SQLITE_OK)
		goto out;
	if (sqlite3_prepare_v2(db, pkgdb_query_sql, -1, &stmt, NULL) !=
	    SQLITE_OK ||
	    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC) != SQLITE_OK)
		goto out;
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		error = 0;	/* no package records the path */
		goto out;
	}
	if (rc != SQLITE_ROW)
		goto out;
	error = EINVAL;
	if (!column_copy(stmt, 0, reply->checksum, sizeof(reply->checksum)) ||
	    !column_copy(stmt, 2, reply->package, sizeof(reply->package)) ||
	    !column_copy(stmt, 3, reply->origin, sizeof(reply->origin)) ||
	    !column_copy(stmt, 4, reply->repository,
	    sizeof(reply->repository)))
		goto out;
	/* Any non-empty symlink target marks a link record. */
	reply->symlink = sqlite3_column_type(stmt, 1) != SQLITE_NULL &&
	    (!column_copy(stmt, 1, target, sizeof(target)) || target[0] != '\0');
	reply->found = 1;
	error = 0;
out:
	if (stmt != NULL)
		(void)sqlite3_finalize(stmt);
	if (db != NULL)
		(void)sqlite3_close(db);
	(void)munmap(image, (size_t)st.st_size);
	return (error);
}

int
sysext_pkgdb_lookup(int dirfd, const char *path,
    struct sysext_pkg_record *rec)
{
	struct pkgdb_reply reply;
	struct pollfd pfd;
	size_t got = 0;
	ssize_t n;
	pid_t pid;
	int p[2], pd, error;

	memset(rec, 0, sizeof(*rec));
	if (dirfd < 0)
		return (EBADF);
	if (pipe2(p, O_CLOEXEC) == -1)
		return (errno);
	pid = pdfork(&pd, PD_CLOEXEC);
	if (pid == -1) {
		error = errno;
		(void)close(p[0]);
		(void)close(p[1]);
		return (error);
	}
	if (pid == 0) {
		int a, b;

		/*
		 * Keep only the database directory (3) and the reply pipe (4).
		 * The kldload token is close-on-fork; everything else held by
		 * the broker (listeners, sessions, other directories) is closed
		 * before a byte of the database is parsed.
		 */
		a = fcntl(dirfd, F_DUPFD, 10);
		b = fcntl(p[1], F_DUPFD, 10);
		if (a == -1 || b == -1 || dup2(a, 3) == -1 || dup2(b, 4) == -1)
			_exit(1);
		closefrom(5);
		memset(&reply, 0, sizeof(reply));
		reply.status = pkgdb_query(3, path, &reply);
		n = write(4, &reply, sizeof(reply));
		_exit(n == (ssize_t)sizeof(reply) ? 0 : 1);
	}
	(void)close(p[1]);
	memset(&reply, 0, sizeof(reply));
	error = 0;
	while (got < sizeof(reply)) {
		pfd.fd = p[0];
		pfd.events = POLLIN;
		pfd.revents = 0;
		n = poll(&pfd, 1, PKGDB_TIMEOUT_MS);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n == 0 ? ETIMEDOUT : errno;
			break;
		}
		n = read(p[0], (char *)&reply + got, sizeof(reply) - got);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n == 0 ? EIO : errno;
			break;
		}
		got += (size_t)n;
	}
	(void)close(p[0]);
	/* Closing the process descriptor kills and reaps the child. */
	(void)close(pd);
	if (error != 0)
		return (error);
	if (reply.status != 0)
		return (reply.status);
	/* The child is not trusted to terminate its strings. */
	if (memchr(reply.checksum, '\0', sizeof(reply.checksum)) == NULL ||
	    memchr(reply.package, '\0', sizeof(reply.package)) == NULL ||
	    memchr(reply.origin, '\0', sizeof(reply.origin)) == NULL ||
	    memchr(reply.repository, '\0', sizeof(reply.repository)) == NULL)
		return (EINVAL);
	(void)strlcpy(rec->checksum, reply.checksum, sizeof(rec->checksum));
	(void)strlcpy(rec->package, reply.package, sizeof(rec->package));
	(void)strlcpy(rec->origin, reply.origin, sizeof(rec->origin));
	(void)strlcpy(rec->repository, reply.repository,
	    sizeof(rec->repository));
	rec->symlink = reply.symlink != 0;
	rec->found = reply.found != 0;
	return (0);
}

/* ------------------------------------------------------------- decisions */

/* NAME or NAME.ko -> NAME.ko; false when it does not fit. */
static bool
module_file(const char *name, char *file, size_t filelen)
{
	size_t len = strlen(name);
	bool ko = len > 3 && strcmp(name + len - 3, ".ko") == 0;

	return ((size_t)snprintf(file, filelen, "%s%s", name, ko ? "" : ".ko") <
	    filelen);
}

static bool
same_file(const struct stat *a, const struct stat *b)
{

	return (a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
	    a->st_size == b->st_size &&
	    a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
	    a->st_mtim.tv_nsec == b->st_mtim.tv_nsec);
}

/*
 * Check /boot/kernel/file against the package database.  On success the open
 * descriptor and its stat are returned (the caller closes it).  Returns
 * SYSEXT_DECISION_LOADED for "acceptable", or the refusal.
 */
static uint32_t
verify_file(const char *repository, const char *file, int *fdp,
    struct stat *stp, int *errorp, char *detail, size_t detaillen)
{
	struct sysext_pkg_record rec;
	struct stat again;
	char path[sizeof(KERNEL_PREFIX) + SYSEXT_NAME_MAX + 3];
	char sum[SYSEXT_PKG_CHECKSUM_MAX];
	int fd, error;

	*fdp = -1;
	*errorp = 0;
	(void)snprintf(path, sizeof(path), "%s%s", KERNEL_PREFIX, file);
	fd = openat(sysext_driver_dirfd, file, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		*errorp = errno;
		(void)snprintf(detail, detaillen, "%s: %s", path,
		    errno == EMLINK || errno == ELOOP ? "a symbolic link" :
		    strerror(errno));
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	if (fstat(fd, stp) == -1 || !S_ISREG(stp->st_mode)) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s: not a regular file", path);
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	error = sysext_pkgdb_lookup(sysext_pkgdb_dirfd, path, &rec);
	if (error == 0 && !rec.found) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "no installed package "
		    "records %s", path);
		return (SYSEXT_DECISION_NOT_PACKAGED);
	}
	if (error != 0) {
		(void)close(fd);
		*errorp = error;
		(void)snprintf(detail, detaillen, "package database %s/%s: %s",
		    SYSEXT_PKGDB_DIR, SYSEXT_PKGDB_FILE, strerror(error));
		return (SYSEXT_DECISION_PKGDB);
	}
	if (rec.symlink || strncmp(rec.origin, "base/", 5) != 0 ||
	    strcmp(rec.repository, repository) != 0) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s belongs to %s (origin %s, "
		    "repository %s), not a %s base package%s", path,
		    rec.package, rec.origin,
		    rec.repository[0] != '\0' ? rec.repository : "unknown",
		    repository, rec.symlink ? "; recorded as a link" : "");
		return (SYSEXT_DECISION_NOT_PACKAGED);
	}
	if (strncmp(rec.checksum, "2$", 2) != 0) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s: %s records an unsupported "
		    "checksum format", path, rec.package);
		return (SYSEXT_DECISION_CHECKSUM);
	}
	error = sysext_pkg_checksum_fd(fd, sum, sizeof(sum));
	if (error != 0) {
		(void)close(fd);
		*errorp = error;
		(void)snprintf(detail, detaillen, "%s: checksum: %s", path,
		    strerror(error));
		return (SYSEXT_DECISION_FAILED);
	}
	if (strcmp(sum, rec.checksum) != 0) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s does not match the "
		    "checksum %s recorded at installation", path, rec.package);
		return (SYSEXT_DECISION_CHECKSUM);
	}
	if (fstat(fd, &again) == -1 || !same_file(stp, &again)) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s changed while it was "
		    "checked", path);
		return (SYSEXT_DECISION_CHANGED);
	}
	(void)snprintf(detail, detaillen, "%s from %s", path, rec.package);
	*fdp = fd;
	return (SYSEXT_DECISION_LOADED);
}

/* The name still in /boot/kernel is the file that was checked. */
static bool
still_same(const char *file, const struct stat *st)
{
	struct stat now;
	int fd;
	bool same;

	fd = openat(sysext_driver_dirfd, file, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC | O_NONBLOCK);
	if (fd == -1)
		return (false);
	same = fstat(fd, &now) == 0 && same_file(st, &now);
	(void)close(fd);
	return (same);
}

static void
root_track(const char *file, int fileid)
{
	struct root_loaded *slot = NULL;
	size_t i;

	pthread_mutex_lock(&root_lock);
	for (i = 0; i < nitems(root_loaded); i++) {
		if (root_loaded[i].used &&
		    strcmp(root_loaded[i].file, file) == 0) {
			slot = &root_loaded[i];
			break;
		}
		if (!root_loaded[i].used && slot == NULL)
			slot = &root_loaded[i];
	}
	if (slot != NULL) {
		memset(slot, 0, sizeof(*slot));
		(void)strlcpy(slot->file, file, sizeof(slot->file));
		slot->fileid = fileid;
		slot->used = true;
	} else
		syslog(LOG_WARNING, "root load %s: %d root loads already "
		    "tracked; it cannot be unloaded with sysextctl", file,
		    SYSEXT_ROOT_LOADED_MAX);
	pthread_mutex_unlock(&root_lock);
}

uint32_t
sysext_root_load(const char *repository, const char *name, int *errorp,
    char *detail, size_t detaillen)
{
	struct stat st;
	char file[SYSEXT_NAME_MAX + 3], path[sizeof(KERNEL_PREFIX) +
	    SYSEXT_NAME_MAX + 3];
	char kname[MAXPATHLEN], kpath[MAXPATHLEN], why[256];
	int before[1024], fresh[ROOT_NEW_FILES_MAX];
	size_t nbefore = 0, nfresh = 0, i, j;
	uint32_t result;
	int fd, fileid = -1, id, error;
	bool known, overflow = false;

	*errorp = 0;
	detail[0] = '\0';
	if (repository == NULL || repository[0] == '\0')
		return (SYSEXT_DECISION_DISABLED);
	if (!module_file(name, file, sizeof(file))) {
		*errorp = ENAMETOOLONG;
		return (SYSEXT_DECISION_FAILED);
	}
	if (sysext_driver_dirfd < 0 || sysext_pkgdb_dirfd < 0) {
		(void)snprintf(detail, detaillen, "%s or %s was not delivered",
		    SYSEXT_KERNEL_DIR, SYSEXT_PKGDB_DIR);
		return (sysext_driver_dirfd < 0 ?
		    SYSEXT_DECISION_NOT_KERNEL_DIR : SYSEXT_DECISION_PKGDB);
	}
	result = verify_file(repository, file, &fd, &st, errorp, detail,
	    detaillen);
	if (result != SYSEXT_DECISION_LOADED)
		return (result);
	(void)snprintf(path, sizeof(path), "%s%s", KERNEL_PREFIX, file);

	/*
	 * Serialise against the broker's other loads so the files that appear
	 * are this load's (the requested file and its dependencies).
	 */
	pthread_mutex_lock(&sysext_load_lock);
	for (id = kld_next(0); id > 0 && nbefore < nitems(before);
	    id = kld_next(id))
		before[nbefore++] = id;
	if (!still_same(file, &st)) {
		pthread_mutex_unlock(&sysext_load_lock);
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s changed while it was "
		    "checked", path);
		return (SYSEXT_DECISION_CHANGED);
	}
	error = kld_load(path, &fileid);
	if (error != 0) {
		pthread_mutex_unlock(&sysext_load_lock);
		(void)close(fd);
		if (error == EEXIST)
			return (SYSEXT_DECISION_PRESENT);
		*errorp = error;
		return (SYSEXT_DECISION_FAILED);
	}
	/* Every file this load brought in, the requested one included. */
	for (id = kld_next(0); id > 0; id = kld_next(id)) {
		known = false;
		for (j = 0; j < nbefore && !known; j++)
			known = before[j] == id;
		if (known)
			continue;
		if (nfresh == nitems(fresh)) {
			overflow = true;
			break;
		}
		fresh[nfresh++] = id;
	}
	pthread_mutex_unlock(&sysext_load_lock);
	result = SYSEXT_DECISION_LOADED;
	if (!still_same(file, &st)) {
		result = SYSEXT_DECISION_CHANGED;
		(void)snprintf(detail, detaillen, "%s was replaced during the "
		    "load", path);
	} else if (overflow) {
		result = SYSEXT_DECISION_CHANGED;
		(void)snprintf(detail, detaillen, "%s brought in more than %d "
		    "files", path, ROOT_NEW_FILES_MAX);
	}
	for (i = 0; i < nfresh && result == SYSEXT_DECISION_LOADED; i++) {
		int depfd, deperror;
		struct stat depst;

		if (fresh[i] == fileid)
			continue;
		/* A dependency the kernel linker loaded: same rules. */
		if (kld_stat(fresh[i], kname, sizeof(kname), kpath,
		    sizeof(kpath)) != 0)
			continue;
		if (strncmp(kpath, KERNEL_PREFIX, sizeof(KERNEL_PREFIX) - 1) !=
		    0 || strchr(kpath + sizeof(KERNEL_PREFIX) - 1, '/') != NULL) {
			result = SYSEXT_DECISION_NOT_KERNEL_DIR;
			(void)snprintf(detail, detaillen, "dependency %s was "
			    "loaded from outside %s", kpath, SYSEXT_KERNEL_DIR);
			break;
		}
		result = verify_file(repository, kpath +
		    sizeof(KERNEL_PREFIX) - 1, &depfd, &depst, &deperror, why,
		    sizeof(why));
		if (depfd >= 0)
			(void)close(depfd);
		if (result != SYSEXT_DECISION_LOADED) {
			*errorp = deperror;
			(void)snprintf(detail, detaillen, "dependency: %s", why);
		}
	}
	(void)close(fd);
	if (result != SYSEXT_DECISION_LOADED) {
		/* Unloading the file releases the dependencies it pulled in. */
		error = kld_unload(fileid);
		if (error != 0)
			syslog(LOG_ERR, "root load %s: undo failed (file id %d "
			    "stays loaded): %s", path, fileid, strerror(error));
		return (result);
	}
	root_track(file, fileid);
	return (SYSEXT_DECISION_LOADED);
}

/* Security policies, tracing and the hypervisor stay loaded. */
bool
sysext_root_unload_protected(const char *name)
{
	static const char *const prefixes[] = { "mac_", "dtrace", "hypertrace",
	    "kinst", "fbt", "sdt", "systrace", "fasttrap", "profile", "vmm",
	    "zfs", "opensolaris", "pf", "ipfw" };
	size_t i;

	for (i = 0; i < nitems(prefixes); i++)
		if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0)
			return (true);
	return (false);
}

void
sysext_root_note_shared(const char *name)
{
	char file[SYSEXT_NAME_MAX + 3];
	size_t i;

	if (!module_file(name, file, sizeof(file)))
		return;
	pthread_mutex_lock(&root_lock);
	for (i = 0; i < nitems(root_loaded); i++)
		if (root_loaded[i].used && strcmp(root_loaded[i].file, file) == 0)
			root_loaded[i].shared = true;
	pthread_mutex_unlock(&root_lock);
}

uint32_t
sysext_root_unload(const char *name, int *errorp, char *detail,
    size_t detaillen)
{
	struct root_loaded *slot = NULL;
	char file[SYSEXT_NAME_MAX + 3], kname[MAXPATHLEN], kpath[MAXPATHLEN];
	size_t i;
	uint32_t result;
	int error;

	*errorp = 0;
	detail[0] = '\0';
	if (!module_file(name, file, sizeof(file))) {
		*errorp = ENAMETOOLONG;
		return (SYSEXT_DECISION_FAILED);
	}
	if (sysext_root_unload_protected(file)) {
		(void)snprintf(detail, detaillen, "%s: security, tracing, "
		    "filesystem and hypervisor modules stay loaded", file);
		return (SYSEXT_DECISION_NOT_ROOT_LOADED);
	}
	pthread_mutex_lock(&root_lock);
	for (i = 0; i < nitems(root_loaded); i++)
		if (root_loaded[i].used &&
		    strcmp(root_loaded[i].file, file) == 0)
			slot = &root_loaded[i];
	if (slot == NULL) {
		pthread_mutex_unlock(&root_lock);
		(void)snprintf(detail, detaillen, "%s was not loaded by "
		    "sysextctl load since the broker started", file);
		return (SYSEXT_DECISION_NOT_ROOT_LOADED);
	}
	if (slot->shared) {
		pthread_mutex_unlock(&root_lock);
		(void)snprintf(detail, detaillen, "another client has asked "
		    "for %s since it was loaded", file);
		return (SYSEXT_DECISION_NOT_ROOT_LOADED);
	}
	/* The id must still name the file root loaded (ids are not reused
	 * while loaded, but the file may have been unloaded since). */
	if (kld_stat(slot->fileid, kname, sizeof(kname), kpath,
	    sizeof(kpath)) != 0 || strcmp(kname, file) != 0) {
		memset(slot, 0, sizeof(*slot));
		pthread_mutex_unlock(&root_lock);
		(void)snprintf(detail, detaillen, "%s is no longer loaded",
		    file);
		return (SYSEXT_DECISION_NOT_ROOT_LOADED);
	}
	error = kld_unload(slot->fileid);
	if (error == 0) {
		memset(slot, 0, sizeof(*slot));
		result = SYSEXT_DECISION_UNLOADED;
	} else {
		*errorp = error;
		(void)snprintf(detail, detaillen, "%s: %s%s", file,
		    strerror(error), error == EBUSY ?
		    " (in use, or another module depends on it)" : "");
		result = SYSEXT_DECISION_FAILED;
	}
	pthread_mutex_unlock(&root_lock);
	return (result);
}

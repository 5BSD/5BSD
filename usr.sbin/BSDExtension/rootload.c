/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Root loads for bsdextension(8): system.SystemExtension.RootLoad.
 *
 * A UID 0 login session (switchboard root-load.ucl) may ask the broker to load
 * a kernel module the base system installed.  The broker resolves everything
 * the load would bring in BEFORE anything is loaded, and loads only files that
 * passed every check, each by absolute path, so neither kern.module_path nor
 * the kernel's own dependency search picks a file:
 *
 *  - the module and, recursively, every MODULE_DEPEND it declares that no
 *    loaded file provides: read from the file's module metadata (in a forked
 *    child, libkldelf) and resolved through the running kernel's linker.hints
 *    exactly as the kernel linker would (kerneldir.c, bsdextension.c), within
 *    the running kernel's module directory only;
 *  - each such file, opened beneath that directory with O_NOFOLLOW, is a
 *    regular file (checked before the open: a device node is never opened);
 *  - the local package database records it in a package whose origin is
 *    base/... and whose "repository" annotation is the configured base
 *    repository (root_load_repository), not as a symbolic link;
 *  - its checksum, computed here, equals the one pkg recorded at installation
 *    (pkg 2 records "2$" + z-base-32 BLAKE2b-512);
 *  - no administrator override denies it and it is not a protected module
 *    (sysext_root_protected(): the same list root unloads refuse);
 *  - every dependency file provides the version the dependent asks for, and
 *    a dependency already met is met by the running kernel or by the loaded
 *    file the kernel directory's linker.hints names for that version range
 *    (a module of that name loaded from anywhere else may have a version the
 *    kernel would not accept, and the kernel would then search
 *    kern.module_path itself: refused).
 *
 * All of that runs without sysext_load_lock: one package database child per
 * request answers every file, and a hardware-driver load (devd) does not
 * wait for it.  Under the lock the broker repeats only what is cheap: the
 * kernel directory check, each dependency still met as planned, and each
 * file still the one checked (device, inode, size, modification and change
 * time of the open file, by name in the kernel directory and by its absolute
 * path from "/").  The files are then loaded dependencies first.  After each
 * load the broker compares the loaded files with the ones before: anything
 * but the file just loaded (the kernel resolved something itself, or another
 * process loaded a file meanwhile) is a hard failure, and the file id the
 * kernel reports must name, from "/", the file that was checked.  Every file
 * this request loaded is then unloaded again, as when a file or the kernel
 * directory changed between the check and the load; files it did not load
 * are logged and left alone.
 *
 * The package database and module metadata are parsed in pdfork(2)ed
 * children.  The kldload token is close-on-fork, and a child closes every
 * descriptor but the one it reads and its reply pipe, so a malformed database
 * or module reaches a process that can load nothing.  The database child maps
 * local.sqlite privately and opens it with sqlite3_deserialize(3) read-only
 * (base's private sqlite; libpkg is not part of base), with views, triggers
 * and untrusted schema functions disabled.
 *
 * What this is not: the package database and /boot are both writable by
 * root, so a root that edits the database, or swaps a file or /boot after the
 * last check and back before the next, defeats it, as does installing a
 * package or editing loader.conf and rebooting; only the kernel could load
 * the very vnode that was checked.  kern.module_path is isolated by the
 * capability plane (BSDSysctl), so any search the kernel still makes stays
 * within the loader's directories.  It keeps a root login shell from loading
 * arbitrary or modified files by mistake and records every request;
 * mac_veriexec(4) is the control against a compromised root.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/procdesc.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <gelf.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <kldelf.h>
#include <sqlite3.h>
#include <libservice.h>

#include "sysext_proto.h"
#include "bsdextension.h"

/* sys/contrib/libb2 reference BLAKE2b (blake2b-ref.c, built with an empty SUFFIX). */
#include "blake2.h"

#define	CHILD_TIMEOUT_MS	15000
#define	PKGDB_HEAP_LIMIT	(64LL * 1024 * 1024)
#define	LOADED_IDS_MAX		1024

int sysext_pkgdb_dirfd = -1;
pthread_mutex_t sysext_load_lock = PTHREAD_MUTEX_INITIALIZER;

/* Files a root load loaded: only these may be root-unloaded. */
struct root_loaded {
	char	file[NAME_MAX + 1];	/* NAME.ko */
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
int (*sysext_test_mod_find)(const char *);
int sysext_test_pkgdb_children;

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

int
sysext_kld_stat(int fileid, char *name, size_t namelen, char *path,
    size_t pathlen)
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


/* 0 when a loaded file provides the module name, else an errno. */
static int
mod_find(const char *name)
{

#ifdef BSDEXTENSION_TESTING
	if (sysext_test_mod_find != NULL)
		return (sysext_test_mod_find(name));
#endif
	return (modfind(name) == -1 ? errno : 0);
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
	if (blake2b_init(&state, BLAKE2B_OUTBYTES) != 0) {
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
		(void)blake2b_update(&state, buf, (size_t)n);
		off += n;
	}
	free(buf);
	if (error != 0)
		return (error);
	if (blake2b_final(&state, digest, sizeof(digest)) != 0)
		return (EINVAL);
	out[0] = '2';
	out[1] = '$';
	sysext_pkg_base32(digest, sizeof(digest), out + 2, outlen - 2);
	return (0);
}

/* ------------------------------------------------------ package database */

/* The child's answer for one path: fixed size, NUL-terminated strings. */
struct pkgdb_answer {
	int32_t	found;
	int32_t	symlink;
	char	checksum[SYSEXT_PKG_CHECKSUM_MAX];
	char	package[128];
	char	origin[160];
	char	repository[SYSEXT_REPOSITORY_MAX];
};

/* The child's reply: one answer per path asked for, in order. */
struct pkgdb_reply {
	int32_t	status;
	struct pkgdb_answer answer[SYSEXT_ROOT_FILES_MAX];
};

/* The paths one child answers (it sees them in its copy of the memory). */
struct pkgdb_request {
	const char *const *paths;
	size_t	npaths;
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

/* One path: 0 with *a filled (a->found 0 when no package records it). */
static int
pkgdb_answer_path(sqlite3_stmt *stmt, const char *path, struct pkgdb_answer *a)
{
	char target[8];
	int rc;

	if (sqlite3_reset(stmt) != SQLITE_OK ||
	    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC) != SQLITE_OK)
		return (EIO);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE)
		return (0);	/* no package records the path */
	if (rc != SQLITE_ROW)
		return (EIO);
	if (!column_copy(stmt, 0, a->checksum, sizeof(a->checksum)) ||
	    !column_copy(stmt, 2, a->package, sizeof(a->package)) ||
	    !column_copy(stmt, 3, a->origin, sizeof(a->origin)) ||
	    !column_copy(stmt, 4, a->repository, sizeof(a->repository)))
		return (EINVAL);
	/* Any non-empty symlink target marks a link record. */
	a->symlink = sqlite3_column_type(stmt, 1) != SQLITE_NULL &&
	    (!column_copy(stmt, 1, target, sizeof(target)) || target[0] != '\0');
	a->found = 1;
	return (0);
}

/*
 * In the child: answer every path of the request from one private, read-only
 * image of the database.
 */
static int
pkgdb_query(int dirfd, const struct pkgdb_request *rq,
    struct pkgdb_reply *reply)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;
	struct stat st;
	unsigned char *image;
	size_t i;
	int fd, error;

	if (rq->npaths > nitems(reply->answer))
		return (E2BIG);
	/* Refuse a non-regular file before an open that could block. */
	if (fstatat(dirfd, SYSEXT_PKGDB_FILE, &st, AT_SYMLINK_NOFOLLOW) == -1)
		return (errno);
	if (!S_ISREG(st.st_mode))
		return (EFTYPE);
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
	    SQLITE_OK)
		goto out;
	for (i = 0, error = 0; i < rq->npaths && error == 0; i++)
		error = pkgdb_answer_path(stmt, rq->paths[i], &reply->answer[i]);
out:
	if (stmt != NULL)
		(void)sqlite3_finalize(stmt);
	if (db != NULL)
		(void)sqlite3_close(db);
	(void)munmap(image, (size_t)st.st_size);
	return (error);
}


/* ------------------------------------------------------- forked readers */

/*
 * Run fn over fd in a pdfork(2)ed child and collect its fixed-size reply
 * (whose first member is the int32_t status fn returns).  The child keeps only
 * fd (as 3) and the reply pipe (as 4): the kldload token is close-on-fork and
 * everything else the broker holds (listeners, sessions, other directories)
 * is closed before a byte of the file is parsed.  The broker is threaded; the
 * child runs only the forking thread, and libc's allocator and stdio carry
 * fork handlers, so the child may allocate (sqlite, libelf) after the fork.
 * The child is killed after CHILD_TIMEOUT_MS.
 */
static int
child_read(int fd, int (*fn)(int, const void *, void *), const void *arg,
    void *reply, size_t replylen)
{
	struct pollfd pfd;
	size_t got = 0;
	ssize_t n;
	pid_t pid;
	int p[2], pd, error;

	if (fd < 0)
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

		a = fcntl(fd, F_DUPFD, 10);
		b = fcntl(p[1], F_DUPFD, 10);
		if (a == -1 || b == -1 || dup2(a, 3) == -1 || dup2(b, 4) == -1)
			_exit(1);
		closefrom(5);
		memset(reply, 0, replylen);
		*(int32_t *)reply = fn(3, arg, reply);
		n = write(4, reply, replylen);
		_exit(n == (ssize_t)replylen ? 0 : 1);
	}
	(void)close(p[1]);
	memset(reply, 0, replylen);
	error = 0;
	while (got < replylen) {
		pfd.fd = p[0];
		pfd.events = POLLIN;
		pfd.revents = 0;
		n = poll(&pfd, 1, CHILD_TIMEOUT_MS);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0) {
			error = n == 0 ? ETIMEDOUT : errno;
			break;
		}
		n = read(p[0], (char *)reply + got, replylen - got);
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
	return (*(int32_t *)reply);
}

static int
pkgdb_child(int dirfd, const void *rq, void *reply)
{

	return (pkgdb_query(dirfd, rq, reply));
}

/*
 * Look up every path in one child: the database image is read and parsed once
 * per request, however many files it names.
 */
static int
pkgdb_lookup_paths(int dirfd, const char *const *paths, size_t npaths,
    struct sysext_pkg_record *recs)
{
	struct pkgdb_request rq;
	struct pkgdb_reply *reply;
	const struct pkgdb_answer *a;
	size_t i;
	int error;

	memset(recs, 0, npaths * sizeof(*recs));
	if (npaths > nitems(reply->answer))
		return (E2BIG);
	if ((reply = malloc(sizeof(*reply))) == NULL)
		return (ENOMEM);
	rq.paths = paths;
	rq.npaths = npaths;
#ifdef BSDEXTENSION_TESTING
	sysext_test_pkgdb_children++;
#endif
	error = child_read(dirfd, pkgdb_child, &rq, reply, sizeof(*reply));
	for (i = 0; i < npaths && error == 0; i++) {
		a = &reply->answer[i];
		/* The child is not trusted to terminate its strings. */
		if (memchr(a->checksum, '\0', sizeof(a->checksum)) == NULL ||
		    memchr(a->package, '\0', sizeof(a->package)) == NULL ||
		    memchr(a->origin, '\0', sizeof(a->origin)) == NULL ||
		    memchr(a->repository, '\0', sizeof(a->repository)) == NULL) {
			error = EINVAL;
			break;
		}
		(void)strlcpy(recs[i].checksum, a->checksum,
		    sizeof(recs[i].checksum));
		(void)strlcpy(recs[i].package, a->package,
		    sizeof(recs[i].package));
		(void)strlcpy(recs[i].origin, a->origin, sizeof(recs[i].origin));
		(void)strlcpy(recs[i].repository, a->repository,
		    sizeof(recs[i].repository));
		recs[i].symlink = a->symlink != 0;
		recs[i].found = a->found != 0;
	}
	free(reply);
	return (error);
}

int
sysext_pkgdb_lookup(int dirfd, const char *path,
    struct sysext_pkg_record *rec)
{

	return (pkgdb_lookup_paths(dirfd, &path, 1, rec));
}

/* The metadata child's reply. */
struct kld_meta_reply {
	int32_t	status;
	struct sysext_kld_meta meta;
};

/* In the child: the module's MODULE_VERSION and MODULE_DEPEND records. */
static int
kld_meta_child(int fd, const void *arg __unused, void *out)
{
	struct sysext_kld_meta *meta = &((struct kld_meta_reply *)out)->meta;
	struct Gmod_metadata md;
	struct Gmod_depend dep;
	struct Gmod_version ver;
	struct elf_file ef;
	GElf_Addr *set;
	long count, i;
	char name[SYSEXT_MODNAME_MAX];
	int error;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (EINVAL);
	if ((error = elf_open_fd(&ef, fd, "module", 0)) != 0)
		return (error);
	error = elf_read_linker_set(&ef, MDT_SETNAME, &set, &count);
	if (error != 0) {
		elf_close_file(&ef);
		/* No metadata: a file that declares nothing. */
		return (error == ESRCH ? 0 : error);
	}
	for (i = 0; i < count && error == 0; i++) {
		if ((error = elf_read_mod_metadata(&ef, set[i], &md)) != 0)
			break;
		if (md.md_type != MDT_DEPEND && md.md_type != MDT_VERSION)
			continue;
		if ((error = elf_read_string(&ef, md.md_cval, name,
		    sizeof(name))) != 0 || name[0] == '\0') {
			error = EFTYPE;
			break;
		}
		if (md.md_type == MDT_VERSION) {
			if (meta->nversion == nitems(meta->version)) {
				error = E2BIG;
				break;
			}
			if ((error = elf_read_mod_version(&ef, md.md_data,
			    &ver)) != 0)
				break;
			(void)strlcpy(meta->version[meta->nversion].name, name,
			    sizeof(meta->version[0].name));
			meta->version[meta->nversion++].version =
			    ver.mv_version;
			continue;
		}
		if (meta->ndepend == nitems(meta->depend)) {
			error = E2BIG;
			break;
		}
		if ((error = elf_read_mod_depend(&ef, md.md_data, &dep)) != 0)
			break;
		(void)strlcpy(meta->depend[meta->ndepend].name, name,
		    sizeof(meta->depend[0].name));
		meta->depend[meta->ndepend].minimum = dep.md_ver_minimum;
		meta->depend[meta->ndepend].preferred = dep.md_ver_preferred;
		meta->depend[meta->ndepend++].maximum = dep.md_ver_maximum;
	}
	free(set);
	elf_close_file(&ef);
	return (error);
}

int
sysext_kld_metadata(int fd, struct sysext_kld_meta *meta)
{
	struct kld_meta_reply reply;
	unsigned i;
	int error;

	memset(meta, 0, sizeof(*meta));
	error = child_read(fd, kld_meta_child, NULL, &reply, sizeof(reply));
	if (error != 0)
		return (error);
	/* Not trusted either: bounded counts, terminated names. */
	if (reply.meta.nversion > nitems(reply.meta.version) ||
	    reply.meta.ndepend > nitems(reply.meta.depend))
		return (EINVAL);
	for (i = 0; i < reply.meta.nversion; i++)
		if (memchr(reply.meta.version[i].name, '\0',
		    sizeof(reply.meta.version[i].name)) == NULL)
			return (EINVAL);
	for (i = 0; i < reply.meta.ndepend; i++)
		if (memchr(reply.meta.depend[i].name, '\0',
		    sizeof(reply.meta.depend[i].name)) == NULL)
			return (EINVAL);
	*meta = reply.meta;
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

/* The same file, unchanged: utimes(2) can restore a mtime, not a ctime. */
static bool
same_file(const struct stat *a, const struct stat *b)
{

	return (a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
	    a->st_size == b->st_size &&
	    timespeccmp(&a->st_mtim, &b->st_mtim, ==) &&
	    timespeccmp(&a->st_ctim, &b->st_ctim, ==));
}

static void
kernel_path(const char *file, char *path, size_t pathlen)
{

	(void)snprintf(path, pathlen, "%s/%s", sysext_kernel_dir, file);
}

/*
 * Open the kernel directory's file: a regular file, not a link.  On success
 * the descriptor and its stat are returned (the plan closes it).  Returns
 * SYSEXT_DECISION_LOADED for "acceptable", or the refusal.
 */
static uint32_t
open_file(const char *file, int *fdp, struct stat *stp, int *errorp,
    char *detail, size_t detaillen)
{
	struct stat first;
	char path[MAXPATHLEN];
	int fd;

	*fdp = -1;
	*errorp = 0;
	kernel_path(file, path, sizeof(path));
	/* Refuse a link or a non-regular file before opening anything. */
	if (fstatat(sysext_driver_dirfd, file, &first,
	    AT_SYMLINK_NOFOLLOW) == -1) {
		*errorp = errno;
		(void)snprintf(detail, detaillen, "%s: %s", path,
		    strerror(errno));
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	if (S_ISLNK(first.st_mode) || !S_ISREG(first.st_mode)) {
		(void)snprintf(detail, detaillen, "%s: %s", path,
		    S_ISLNK(first.st_mode) ? "a symbolic link" :
		    "not a regular file");
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	fd = openat(sysext_driver_dirfd, file, O_RDONLY | O_NOFOLLOW |
	    O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		*errorp = errno;
		(void)snprintf(detail, detaillen, "%s: %s", path,
		    errno == EMLINK || errno == ELOOP ? "a symbolic link" :
		    strerror(errno));
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	if (fstat(fd, stp) == -1 || !S_ISREG(stp->st_mode) ||
	    stp->st_dev != first.st_dev || stp->st_ino != first.st_ino) {
		(void)close(fd);
		(void)snprintf(detail, detaillen, "%s changed while it was "
		    "checked", path);
		return (SYSEXT_DECISION_CHANGED);
	}
	*fdp = fd;
	return (SYSEXT_DECISION_LOADED);
}

/*
 * Check an open kernel directory file against its package database record.
 * Returns SYSEXT_DECISION_LOADED for "acceptable", or the refusal.
 */
static uint32_t
check_package(const char *repository, const char *file, int fd,
    const struct stat *st, const struct sysext_pkg_record *rec, int *errorp,
    char *detail, size_t detaillen)
{
	struct stat again;
	char path[MAXPATHLEN];
	char sum[SYSEXT_PKG_CHECKSUM_MAX];
	int error;

	*errorp = 0;
	kernel_path(file, path, sizeof(path));
	if (!rec->found) {
		(void)snprintf(detail, detaillen, "no installed package "
		    "records %s", path);
		return (SYSEXT_DECISION_NOT_PACKAGED);
	}
	if (rec->symlink || strncmp(rec->origin, "base/", 5) != 0 ||
	    strcmp(rec->repository, repository) != 0) {
		(void)snprintf(detail, detaillen, "%s belongs to %s (origin %s, "
		    "repository %s), not a %s base package%s", path,
		    rec->package, rec->origin,
		    rec->repository[0] != '\0' ? rec->repository : "unknown",
		    repository, rec->symlink ? "; recorded as a link" : "");
		return (SYSEXT_DECISION_NOT_PACKAGED);
	}
	if (strncmp(rec->checksum, "2$", 2) != 0) {
		(void)snprintf(detail, detaillen, "%s: %s records an unsupported "
		    "checksum format", path, rec->package);
		return (SYSEXT_DECISION_CHECKSUM);
	}
	error = sysext_pkg_checksum_fd(fd, sum, sizeof(sum));
	if (error != 0) {
		*errorp = error;
		(void)snprintf(detail, detaillen, "%s: checksum: %s", path,
		    strerror(error));
		return (SYSEXT_DECISION_FAILED);
	}
	if (strcmp(sum, rec->checksum) != 0) {
		(void)snprintf(detail, detaillen, "%s does not match the "
		    "checksum %s recorded at installation", path, rec->package);
		return (SYSEXT_DECISION_CHECKSUM);
	}
	if (fstat(fd, &again) == -1 || !same_file(st, &again)) {
		(void)snprintf(detail, detaillen, "%s changed while it was "
		    "checked", path);
		return (SYSEXT_DECISION_CHANGED);
	}
	return (SYSEXT_DECISION_LOADED);
}

/* The name still in the kernel directory is the file that was checked. */
static bool
still_same(const char *file, const struct stat *st)
{
	struct stat now;

	return (fstatat(sysext_driver_dirfd, file, &now,
	    AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(now.st_mode) &&
	    same_file(st, &now));
}

/*
 * The absolute path, looked up beneath "/" as the kernel resolves it for
 * kldload(2), names the file that was checked: no mount over /boot or a
 * directory on the way, no renamed /boot.
 */
static bool
path_names(const char *path, const struct stat *st)
{
	struct stat now;

	return (path[0] == '/' && path[1] != '\0' &&
	    fstatat(sysext_root_dirfd, path + 1, &now, 0) == 0 &&
	    S_ISREG(now.st_mode) && same_file(st, &now));
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

/*
 * The files one root load loads, dependencies first: each open, with its
 * metadata, the file that needs it, and its file id once loaded.
 */
struct root_file {
	char	file[NAME_MAX + 1];
	char	dependent[NAME_MAX + 1];	/* "" for the module */
	int	fd;
	int	fileid;
	struct stat st;
	struct sysext_kld_meta meta;
};
struct root_plan {
	const char *repository;
	struct root_file *files;	/* SYSEXT_ROOT_FILES_MAX */
	size_t	nfiles;
	const char *stack[SYSEXT_ROOT_FILES_MAX];	/* being resolved */
	size_t	depth;
};

static const struct root_file *
plan_find(const struct root_plan *plan, const char *file)
{
	size_t i;

	for (i = 0; i < plan->nfiles; i++)
		if (strcmp(plan->files[i].file, file) == 0)
			return (&plan->files[i]);
	return (NULL);
}

/* The file provides version name within [minimum, maximum]. */
static bool
provides(const struct sysext_kld_meta *meta, const char *name, int minimum,
    int maximum)
{
	unsigned i;

	for (i = 0; i < meta->nversion; i++)
		if (strcmp(meta->version[i].name, name) == 0 &&
		    meta->version[i].version >= minimum &&
		    meta->version[i].version <= maximum)
			return (true);
	return (false);
}

/*
 * The kernel directory's file is loaded, from that directory (the kernel then
 * loads no other).  A file of that name loaded from elsewhere is not it.
 */
static bool
file_loaded(const char *file)
{
	char kname[MAXPATHLEN], kpath[MAXPATHLEN], path[MAXPATHLEN];
	int id;

	kernel_path(file, path, sizeof(path));
	for (id = kld_next(0); id > 0; id = kld_next(id))
		if (sysext_kld_stat(id, kname, sizeof(kname), kpath,
		    sizeof(kpath)) == 0 && strcmp(kname, file) == 0)
			return (strcmp(kpath, path) == 0);
	return (false);
}

/*
 * How dependency i of rf is met, the way linker_load_dependencies() would
 * meet it.  SYSEXT_DECISION_LOADED with depfile empty: by rf itself, by the
 * running kernel, or by the loaded file that the kernel directory's
 * linker.hints names for the version range.  With depfile set: by that file
 * of the kernel directory, to be checked and loaded first.  Anything else is
 * the refusal.  modfind(2) reports no version, so a module of that name
 * loaded from any other file is refused: the kernel compares versions
 * (modlist_lookup2()) and, out of range, searches kern.module_path itself.
 */
static uint32_t
dep_resolve(const struct root_file *rf, unsigned i, char *depfile,
    size_t depfilelen, int *errorp, char *detail, size_t detaillen)
{
	const char *name = rf->meta.depend[i].name;
	int minimum = rf->meta.depend[i].minimum;
	int maximum = rf->meta.depend[i].maximum;
	unsigned j;

	depfile[0] = '\0';
	/* A file's own versions satisfy its own dependencies. */
	for (j = 0; j < rf->meta.nversion; j++)
		if (strcmp(rf->meta.version[j].name, name) == 0)
			return (SYSEXT_DECISION_LOADED);
	sysext_kernel_dir_dependency(name, minimum,
	    rf->meta.depend[i].preferred, maximum, depfile, depfilelen);
	/* The running kernel's own interfaces (build-id checked). */
	if (depfile[0] != '\0' &&
	    (strcmp(depfile, sysext_kernel_file_name()) == 0 ||
	    file_loaded(depfile))) {
		depfile[0] = '\0';
		return (SYSEXT_DECISION_LOADED);
	}
	if (mod_find(name) == 0) {
		*errorp = EEXIST;
		(void)snprintf(detail, detaillen, "%s depends on %s version "
		    "%d-%d; the loaded %s module is not from %s%s%s, so its "
		    "version is unknown and the kernel could search "
		    "kern.module_path", rf->file, name, minimum, maximum, name,
		    sysext_kernel_dir, depfile[0] != '\0' ? "/" : "", depfile);
		return (SYSEXT_DECISION_FAILED);
	}
	if (depfile[0] == '\0') {
		(void)snprintf(detail, detaillen, "%s depends on %s, which no "
		    "file in %s provides", rf->file, name, sysext_kernel_dir);
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	}
	return (SYSEXT_DECISION_LOADED);
}

/*
 * Open file and, first, every dependency it declares that is not met, the way
 * linker_load_dependencies() would find them, and add them to the plan in
 * load order.  dependent names the file that needs this one (NULL for the
 * requested module).  Runs without sysext_load_lock; the package checks
 * follow for the whole plan (plan_verify()).
 */
static uint32_t
plan_file(struct root_plan *plan, const char *file, const char *dependent,
    int *errorp, char *detail, size_t detaillen)
{
	struct root_file *rf;
	char why[384], depfile[NAME_MAX + 1];
	const struct root_file *dep;
	uint32_t result;
	unsigned i;

	*errorp = 0;
	if (plan_find(plan, file) != NULL)
		return (SYSEXT_DECISION_LOADED);
	for (i = 0; i < plan->depth; i++)
		if (strcmp(plan->stack[i], file) == 0) {
			*errorp = ELOOP;
			(void)snprintf(detail, detaillen, "%s: circular module "
			    "dependency", file);
			return (SYSEXT_DECISION_FAILED);
		}
	if (plan->nfiles + plan->depth >= SYSEXT_ROOT_FILES_MAX) {
		*errorp = E2BIG;
		(void)snprintf(detail, detaillen, "%s needs more than %d "
		    "files", plan->depth > 0 ? plan->stack[0] : file,
		    SYSEXT_ROOT_FILES_MAX);
		return (SYSEXT_DECISION_FAILED);
	}
	if (sysext_root_protected(file)) {
		(void)snprintf(detail, detaillen, "%s%s%s: security, tracing, "
		    "storage, packet filter and hypervisor modules are not "
		    "root-loaded", file, dependent != NULL ? ", needed by " : "",
		    dependent != NULL ? dependent : "");
		return (SYSEXT_DECISION_PROTECTED);
	}
	if (sysext_admin_denied(file)) {
		(void)snprintf(detail, detaillen, "%s%s%s denied by an "
		    "administrator override", file, dependent != NULL ?
		    ", a dependency of " : "", dependent != NULL ? dependent :
		    "");
		return (SYSEXT_DECISION_OVERRIDE);
	}
	/* Staged apart: its dependencies are planned (appended) first. */
	if ((rf = calloc(1, sizeof(*rf))) == NULL) {
		*errorp = ENOMEM;
		return (SYSEXT_DECISION_FAILED);
	}
	rf->fileid = -1;
	(void)strlcpy(rf->file, file, sizeof(rf->file));
	if (dependent != NULL)
		(void)strlcpy(rf->dependent, dependent, sizeof(rf->dependent));
	result = open_file(file, &rf->fd, &rf->st, errorp, why, sizeof(why));
	if (result != SYSEXT_DECISION_LOADED) {
		(void)snprintf(detail, detaillen, "%s%s%s%s", dependent !=
		    NULL ? "dependency of " : "", dependent != NULL ?
		    dependent : "", dependent != NULL ? ": " : "", why);
		free(rf);
		return (result);
	}
	if ((*errorp = sysext_kld_metadata(rf->fd, &rf->meta)) != 0) {
		(void)close(rf->fd);
		(void)snprintf(detail, detaillen, "%s/%s: module metadata: %s",
		    sysext_kernel_dir, file, strerror(*errorp));
		free(rf);
		return (SYSEXT_DECISION_FAILED);
	}
	plan->stack[plan->depth++] = rf->file;
	result = SYSEXT_DECISION_LOADED;
	for (i = 0; i < rf->meta.ndepend && result == SYSEXT_DECISION_LOADED;
	    i++) {
		result = dep_resolve(rf, i, depfile, sizeof(depfile), errorp,
		    detail, detaillen);
		if (result != SYSEXT_DECISION_LOADED || depfile[0] == '\0')
			continue;
		result = plan_file(plan, depfile, file, errorp, detail,
		    detaillen);
		if (result != SYSEXT_DECISION_LOADED)
			break;
		dep = plan_find(plan, depfile);
		if (dep == NULL || !provides(&dep->meta, rf->meta.depend[i].name,
		    rf->meta.depend[i].minimum, rf->meta.depend[i].maximum)) {
			result = SYSEXT_DECISION_FAILED;
			*errorp = ENOENT;
			(void)snprintf(detail, detaillen, "%s depends on %s "
			    "version %d-%d, which %s/%s does not provide",
			    file, rf->meta.depend[i].name,
			    rf->meta.depend[i].minimum,
			    rf->meta.depend[i].maximum, sysext_kernel_dir,
			    depfile);
		}
	}
	plan->depth--;
	if (result != SYSEXT_DECISION_LOADED)
		(void)close(rf->fd);
	else
		plan->files[plan->nfiles++] = *rf;
	free(rf);
	return (result);
}

/*
 * The package checks for every planned file, answered by one package database
 * child; the requested module's refusal is reported before its dependencies'.
 */
static uint32_t
plan_verify(struct root_plan *plan, int *errorp, char *detail,
    size_t detaillen)
{
	struct sysext_pkg_record *recs;
	const char *paths[SYSEXT_ROOT_FILES_MAX];
	char (*buf)[MAXPATHLEN], why[384];
	const struct root_file *rf;
	uint32_t result = SYSEXT_DECISION_LOADED;
	size_t i;
	int error;

	recs = calloc(plan->nfiles, sizeof(*recs));
	buf = calloc(plan->nfiles, sizeof(*buf));
	if (recs == NULL || buf == NULL) {
		free(recs);
		free(buf);
		*errorp = ENOMEM;
		return (SYSEXT_DECISION_FAILED);
	}
	for (i = 0; i < plan->nfiles; i++) {
		kernel_path(plan->files[i].file, buf[i], sizeof(buf[i]));
		paths[i] = buf[i];
	}
	error = pkgdb_lookup_paths(sysext_pkgdb_dirfd, paths, plan->nfiles,
	    recs);
	if (error != 0) {
		*errorp = error;
		(void)snprintf(detail, detaillen, "package database %s/%s: %s",
		    SYSEXT_PKGDB_DIR, SYSEXT_PKGDB_FILE, strerror(error));
		result = SYSEXT_DECISION_PKGDB;
	}
	for (i = plan->nfiles; i-- > 0 && result == SYSEXT_DECISION_LOADED;) {
		rf = &plan->files[i];
		result = check_package(plan->repository, rf->file, rf->fd,
		    &rf->st, &recs[i], errorp, why, sizeof(why));
		if (result != SYSEXT_DECISION_LOADED)
			(void)snprintf(detail, detaillen, "%s%s%s%s",
			    rf->dependent[0] != '\0' ? "dependency of " : "",
			    rf->dependent, rf->dependent[0] != '\0' ? ": " : "",
			    why);
	}
	free(recs);
	free(buf);
	return (result);
}

/*
 * With sysext_load_lock held: every dependency the plan found met is still
 * met (another request may have unloaded one meanwhile).  The files are
 * checked again as they are loaded (plan_load()).
 */
static uint32_t
plan_hold(const struct root_plan *plan, int *errorp, char *detail,
    size_t detaillen)
{
	char depfile[NAME_MAX + 1];
	const struct root_file *rf;
	uint32_t result;
	size_t i;
	unsigned j;

	for (i = 0; i < plan->nfiles; i++) {
		rf = &plan->files[i];
		for (j = 0; j < rf->meta.ndepend; j++) {
			result = dep_resolve(rf, j, depfile, sizeof(depfile),
			    errorp, detail, detaillen);
			if (result != SYSEXT_DECISION_LOADED)
				return (result);
			if (depfile[0] != '\0' &&
			    plan_find(plan, depfile) == NULL) {
				(void)snprintf(detail, detaillen, "%s, needed by "
				    "%s, was unloaded while the request was "
				    "checked", depfile, rf->file);
				return (SYSEXT_DECISION_CHANGED);
			}
		}
	}
	return (SYSEXT_DECISION_LOADED);
}

static bool
id_known(const int *ids, size_t n, int id)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (ids[i] == id)
			return (true);
	return (false);
}

/*
 * Unload what this request loaded, last first; the kernel releases what they
 * pulled in.  A file that appeared meanwhile and is still loaded is another
 * process's: it is logged, never unloaded.  Called with sysext_load_lock held.
 */
static void
plan_undo(struct root_plan *plan, const int *before, size_t nbefore)
{
	char kname[MAXPATHLEN], kpath[MAXPATHLEN];
	size_t i;
	int error, id;

	for (i = plan->nfiles; i-- > 0;) {
		if (plan->files[i].fileid <= 0)
			continue;
		error = kld_unload(plan->files[i].fileid);
		if (error != 0)
			syslog(LOG_ERR, "root load: undo of %s/%s failed (file "
			    "id %d stays loaded): %s", sysext_kernel_dir,
			    plan->files[i].file, plan->files[i].fileid,
			    strerror(error));
		else
			plan->files[i].fileid = -1;
	}
	for (id = kld_next(0); id > 0; id = kld_next(id)) {
		if (id_known(before, nbefore, id))
			continue;
		if (sysext_kld_stat(id, kname, sizeof(kname), kpath,
		    sizeof(kpath)) != 0)
			(void)strlcpy(kpath, "?", sizeof(kpath));
		syslog(LOG_WARNING, "root load: file id %d (%s) appeared during "
		    "the load and was not loaded by it; left loaded", id, kpath);
	}
}

/*
 * Load the plan, dependencies first, each by absolute path, with
 * sysext_load_lock held.  The kernel must load exactly the file asked for
 * each time: with every dependency already loaded it searches for nothing.
 */
static uint32_t
plan_load(struct root_plan *plan, int *errorp, char *detail, size_t detaillen)
{
	char path[MAXPATHLEN], kname[MAXPATHLEN], kpath[MAXPATHLEN];
	int before[LOADED_IDS_MAX];
	size_t nbefore = 0, i;
	uint32_t result = SYSEXT_DECISION_LOADED;
	int id, fileid, error;

	for (id = kld_next(0); id > 0; id = kld_next(id)) {
		if (nbefore == nitems(before)) {
			*errorp = E2BIG;
			(void)snprintf(detail, detaillen, "more than %d files "
			    "are loaded", LOADED_IDS_MAX);
			return (SYSEXT_DECISION_FAILED);
		}
		before[nbefore++] = id;
	}
	for (i = 0; i < plan->nfiles && result == SYSEXT_DECISION_LOADED;
	    i++) {
		struct root_file *rf = &plan->files[i];

		kernel_path(rf->file, path, sizeof(path));
		if ((error = sysext_kernel_dir_check(detail, detaillen)) != 0) {
			*errorp = error;
			result = SYSEXT_DECISION_NOT_KERNEL_DIR;
			break;
		}
		if (!still_same(rf->file, &rf->st) ||
		    !path_names(path, &rf->st)) {
			result = SYSEXT_DECISION_CHANGED;
			(void)snprintf(detail, detaillen, "%s changed while "
			    "it was checked", path);
			break;
		}
		error = kld_load(path, &fileid);
		if (error == EEXIST && i + 1 == plan->nfiles) {
			/* Loaded by someone else meanwhile. */
			result = SYSEXT_DECISION_PRESENT;
			break;
		}
		if (error != 0) {
			*errorp = error;
			result = SYSEXT_DECISION_FAILED;
			(void)snprintf(detail, detaillen, "%s: %s", path,
			    strerror(error));
			break;
		}
		rf->fileid = fileid;
		/* Every other new file is one the kernel chose itself. */
		for (id = kld_next(0); id > 0; id = kld_next(id)) {
			if (id == fileid || id_known(before, nbefore, id))
				continue;
			if (sysext_kld_stat(id, kname, sizeof(kname), kpath,
			    sizeof(kpath)) != 0)
				(void)strlcpy(kpath, "an unreadable file",
				    sizeof(kpath));
			result = SYSEXT_DECISION_CHANGED;
			(void)snprintf(detail, detaillen, "loading %s also "
			    "loaded %s (file id %d), which was not checked",
			    path, kpath, id);
			syslog(LOG_ERR, "root load: %s; undoing", detail);
			break;
		}
		/*
		 * The file loaded must be the file checked (S2: no skip): its
		 * pathname, looked up from "/", names the checked file.
		 */
		if (result == SYSEXT_DECISION_LOADED &&
		    ((error = sysext_kld_stat(fileid, kname, sizeof(kname),
		    kpath, sizeof(kpath))) != 0 || strcmp(kpath, path) != 0 ||
		    !path_names(kpath, &rf->st))) {
			*errorp = error;
			result = SYSEXT_DECISION_CHANGED;
			(void)snprintf(detail, detaillen, "file id %d is not "
			    "the checked %s%s%s", fileid, path, error != 0 ?
			    ": " : "", error != 0 ? strerror(error) : "");
		}
		if (nbefore < nitems(before))
			before[nbefore++] = fileid;
	}
	/* Nothing changed under the load. */
	for (i = 0; i < plan->nfiles && result == SYSEXT_DECISION_LOADED;
	    i++) {
		kernel_path(plan->files[i].file, path, sizeof(path));
		if (!still_same(plan->files[i].file, &plan->files[i].st) ||
		    !path_names(path, &plan->files[i].st)) {
			result = SYSEXT_DECISION_CHANGED;
			(void)snprintf(detail, detaillen, "%s was replaced "
			    "during the load", path);
		}
	}
	if (result == SYSEXT_DECISION_LOADED &&
	    (error = sysext_kernel_dir_check(detail, detaillen)) != 0) {
		*errorp = error;
		result = SYSEXT_DECISION_NOT_KERNEL_DIR;
	}
	if (result != SYSEXT_DECISION_LOADED)
		plan_undo(plan, before, nbefore);
	return (result);
}

uint32_t
sysext_root_load(const char *repository, const char *name, int *errorp,
    char *detail, size_t detaillen)
{
	struct root_plan plan;
	char file[NAME_MAX + 1];
	uint32_t result;
	size_t i;

	*errorp = 0;
	detail[0] = '\0';
	if (repository == NULL || repository[0] == '\0')
		return (SYSEXT_DECISION_DISABLED);
	if (!module_file(name, file, sizeof(file))) {
		*errorp = ENAMETOOLONG;
		return (SYSEXT_DECISION_FAILED);
	}
	if (sysext_driver_dirfd < 0 || sysext_root_dirfd < 0 ||
	    sysext_pkgdb_dirfd < 0) {
		(void)snprintf(detail, detaillen, "the kernel directory, %s or "
		    "%s was not delivered", SYSEXT_ROOT_DIR, SYSEXT_PKGDB_DIR);
		return (sysext_pkgdb_dirfd >= 0 ?
		    SYSEXT_DECISION_NOT_KERNEL_DIR : SYSEXT_DECISION_PKGDB);
	}
	if ((*errorp = sysext_kernel_dir_check(detail, detaillen)) != 0)
		return (SYSEXT_DECISION_NOT_KERNEL_DIR);
	memset(&plan, 0, sizeof(plan));
	plan.repository = repository;
	plan.files = calloc(SYSEXT_ROOT_FILES_MAX, sizeof(*plan.files));
	if (plan.files == NULL) {
		*errorp = ENOMEM;
		return (SYSEXT_DECISION_FAILED);
	}
	/*
	 * Resolve and check without the load lock: the metadata and package
	 * database children and the checksums take as long as they take, and
	 * the broker's other loads (devd's drivers) must not wait for them.
	 * Under the lock only what is cheap is checked again: what is loaded
	 * still meets every dependency as planned, and each file is still the
	 * one checked (plan_load()).
	 */
	result = plan_file(&plan, file, NULL, errorp, detail, detaillen);
	if (result == SYSEXT_DECISION_LOADED)
		result = plan_verify(&plan, errorp, detail, detaillen);
	if (result == SYSEXT_DECISION_LOADED) {
		pthread_mutex_lock(&sysext_load_lock);
		result = plan_hold(&plan, errorp, detail, detaillen);
		if (result == SYSEXT_DECISION_LOADED)
			result = plan_load(&plan, errorp, detail, detaillen);
		pthread_mutex_unlock(&sysext_load_lock);
	}
	for (i = 0; i < plan.nfiles; i++) {
		(void)close(plan.files[i].fd);
		if (result == SYSEXT_DECISION_LOADED)
			root_track(plan.files[i].file, plan.files[i].fileid);
	}
	if (result == SYSEXT_DECISION_LOADED && plan.nfiles > 1) {
		size_t len = strlen(detail);

		(void)snprintf(detail + len, detaillen - len, "%sdependencies "
		    "loaded first:", len > 0 ? "; " : "");
		for (i = 0; i + 1 < plan.nfiles; i++) {
			len = strlen(detail);
			(void)snprintf(detail + len, detaillen - len, " %s",
			    plan.files[i].file);
		}
	}
	free(plan.files);
	return (result);
}

/*
 * Security policies, tracing, storage, the packet filters and the hypervisor:
 * a root session neither loads nor unloads them.  Before root loads existed
 * the late-kldload gate refused all of them; the MAC policies grant
 * privileges (mac_ntpd, mac_portacl, mac_priority), tracing and hwpmc read
 * the kernel, ksyms exposes its symbols.  Names match exactly, NAME or
 * NAME.ko; only "mac_", the MAC policies' namespace, is a prefix.
 *
 * nullfs and unionfs are not protected although a mount of either can shadow
 * /boot: so can any file system (tmpfs, md(4)), the broker refuses a /boot
 * mounted over (kerneldir.c), and jails and containers mount them routinely.
 * The Linux ABI (linux*, linuxkpi*) is not protected either: it adds system
 * call personalities under the same credential and MAC checks, and rc.d/linux
 * loads it through the broker; its tracing provider (systrace_linux) is.
 */
bool
sysext_root_protected(const char *name)
{
	static const char *const names[] = {
	    /* tracing and the kernel's own memory */
	    "dtrace", "dtraceall", "dtrace_test", "dtaudit", "dtmalloc",
	    "dtnfscl", "dttransport", "fasttrap", "fbt", "kinst", "profile",
	    "prototype", "sdt", "systrace", "systrace_freebsd32",
	    "systrace_linux", "systrace_linux32", "hypertrace", "hwpmc",
	    "ksyms",
	    /* the hypervisor and storage */
	    "vmm", "zfs", "opensolaris",
	    /* the packet filters */
	    "pf", "pflog", "pfsync", "pflow", "ipfw", "ipfw_nat", "ipfw_nat64",
	    "ipfw_nptv6", "ipfw_pmod", "ipdivert", "dummynet", "ipl" };
	char modname[NAME_MAX + 1];
	size_t i, len;

	if (strncmp(name, "mac_", 4) == 0)
		return (true);
	(void)strlcpy(modname, name, sizeof(modname));
	len = strlen(modname);
	if (len > 3 && strcmp(modname + len - 3, ".ko") == 0)
		modname[len - 3] = '\0';
	for (i = 0; i < nitems(names); i++)
		if (strcmp(modname, names[i]) == 0)
			return (true);
	return (false);
}

void
sysext_root_note_shared(const char *name)
{
	char file[NAME_MAX + 1];
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
	char file[NAME_MAX + 1], kname[MAXPATHLEN], kpath[MAXPATHLEN];
	size_t i;
	uint32_t result;
	int error;

	*errorp = 0;
	detail[0] = '\0';
	if (!module_file(name, file, sizeof(file))) {
		*errorp = ENAMETOOLONG;
		return (SYSEXT_DECISION_FAILED);
	}
	if (sysext_root_protected(file)) {
		(void)snprintf(detail, detaillen, "%s: security, tracing, "
		    "storage, packet filter and hypervisor modules stay "
		    "loaded", file);
		return (SYSEXT_DECISION_PROTECTED);
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
	if (sysext_kld_stat(slot->fileid, kname, sizeof(kname), kpath,
	    sizeof(kpath)) != 0 || strcmp(kname, file) != 0) {
		memset(slot, 0, sizeof(*slot));
		pthread_mutex_unlock(&root_lock);
		(void)snprintf(detail, detaillen, "%s is no longer loaded",
		    file);
		return (SYSEXT_DECISION_NOT_ROOT_LOADED);
	}
	error = kld_unload(slot->fileid);
	/*
	 * The kernel drops the request's reference and keeps a file another
	 * loaded file still depends on: the unload succeeded, the file did
	 * not go.  Report it, and keep the slot.
	 */
	if (error == 0 && sysext_kld_stat(slot->fileid, kname, sizeof(kname),
	    kpath, sizeof(kpath)) == 0 && strcmp(kname, file) == 0)
		error = EBUSY;
	if (error == 0) {
		memset(slot, 0, sizeof(*slot));
		result = SYSEXT_DECISION_UNLOADED;
	} else {
		*errorp = error;
		(void)snprintf(detail, detaillen, "%s: %s%s", file,
		    strerror(error), error == EBUSY ?
		    " (still referenced: in use, or another module depends "
		    "on it)" : "");
		result = SYSEXT_DECISION_FAILED;
	}
	pthread_mutex_unlock(&root_lock);
	return (result);
}

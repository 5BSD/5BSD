/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl install — atomically install an immutable .cap bundle version.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced_ctl.h"
#include "servicectl.h"

#define	INSTALL_DIR	"/Capabilities"
#define	INSTALL_MAX_ENTRIES	4096U
#define	INSTALL_MAX_FILE_SIZE	(512ULL * 1024 * 1024)
#define	INSTALL_MAX_TOTAL_SIZE	(2ULL * 1024 * 1024 * 1024)

static const char *
install_dir(void)
{
	const char *dir;

	dir = getenv("SERVICED_BUNDLE_DIR_USER");
	if (dir != NULL && dir[0] != '\0')
		return (dir);
	return (INSTALL_DIR);
}

/* Remove only the private staging directory created by this process. */
static int
remove_staging_tree(const char *path)
{
	FTS *fts;
	FTSENT *ent;
	char *paths[2];
	int error, saved;

	paths[0] = __DECONST(char *, path);
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL)
		return (-1);
	error = 0;
	errno = 0;
	while ((ent = fts_read(fts)) != NULL) {
		switch (ent->fts_info) {
		case FTS_DP:
			if (rmdir(ent->fts_accpath) == -1 && errno != ENOENT)
				error = errno;
			break;
		case FTS_D:
			break;
		default:
			if (unlink(ent->fts_accpath) == -1 && errno != ENOENT)
				error = errno;
			break;
		}
	}
	if (errno != 0 && error == 0)
		error = errno;
	saved = error;
	(void)fts_close(fts);
	if (saved != 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

/*
 * Make the staged copy registry-safe.  The stage is mode 0700 and owned by
 * this root process, so after cp returns there is no untrusted writer racing
 * this traversal.  Symlinks and all non-directory/non-regular objects are
 * rejected; ownership and writable mode bits are normalized before parsing.
 */
static int
normalize_staging_tree(const char *path, char *errbuf, size_t errlen)
{
	FTS *fts;
	FTSENT *ent;
	char *paths[2];
	mode_t mode;
	int fd, saved;

	paths[0] = __DECONST(char *, path);
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		snprintf(errbuf, errlen, "fts_open: %s", strerror(errno));
		return (-1);
	}
	errno = 0;
	while ((ent = fts_read(fts)) != NULL) {
		if (ent->fts_info == FTS_D) {
			mode = ent->fts_level == 0 ? 0755 :
			    ((ent->fts_statp->st_mode & 0555) | 0700);
			if (chown(ent->fts_accpath, 0, 0) == -1 ||
			    chmod(ent->fts_accpath, mode) == -1)
				goto syscall_error;
			continue;
		}
		if (ent->fts_info == FTS_DP) {
			fd = open(ent->fts_accpath, O_RDONLY | O_DIRECTORY |
			    O_CLOEXEC | O_NOFOLLOW);
			if (fd == -1 || fsync(fd) == -1) {
				if (fd != -1)
					close(fd);
				goto syscall_error;
			}
			close(fd);
			continue;
		}
		if (ent->fts_info != FTS_F) {
			snprintf(errbuf, errlen,
			    "%s: only directories and regular files are allowed",
			    ent->fts_path);
			errno = EINVAL;
			(void)fts_close(fts);
			return (-1);
		}
		mode = ent->fts_statp->st_mode & 0555;
		if ((mode & 0444) == 0)
			mode |= 0400;
		if (chown(ent->fts_accpath, 0, 0) == -1 ||
		    chmod(ent->fts_accpath, mode) == -1)
			goto syscall_error;
		fd = open(ent->fts_accpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd == -1 || fsync(fd) == -1) {
			if (fd != -1)
				close(fd);
			goto syscall_error;
		}
		close(fd);
	}
	if (errno != 0) {
		snprintf(errbuf, errlen, "staging traversal: %s",
		    strerror(errno));
		(void)fts_close(fts);
		return (-1);
	}
	(void)fts_close(fts);
	return (0);

syscall_error:
	saved = errno;
	snprintf(errbuf, errlen, "%s: %s", ent->fts_path,
	    strerror(saved));
	(void)fts_close(fts);
	errno = saved;
	return (-1);
}

static int
copy_regular_file(const char *source, const char *destination,
    uint64_t *totalp)
{
	struct stat sb;
	char buffer[64 * 1024];
	ssize_t amount;
	uint64_t copied;
	int input, output, saved;

	input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (input == -1)
		return (-1);
	if (fstat(input, &sb) == -1) {
		saved = errno;
		close(input);
		return (errno = saved, -1);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size < 0) {
		close(input);
		return (errno = EINVAL, -1);
	}
	if (*totalp > INSTALL_MAX_TOTAL_SIZE ||
	    (uint64_t)sb.st_size > INSTALL_MAX_FILE_SIZE ||
	    (uint64_t)sb.st_size > INSTALL_MAX_TOTAL_SIZE - *totalp) {
		close(input);
		return (errno = EFBIG, -1);
	}
	output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
	    O_NOFOLLOW, 0600 | (sb.st_mode & 0111));
	if (output == -1) {
		saved = errno;
		close(input);
		return (errno = saved, -1);
	}
	copied = 0;
	for (;;) {
		amount = read(input, buffer, sizeof(buffer));
		if (amount == 0)
			break;
		if (amount < 0) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (copied > INSTALL_MAX_FILE_SIZE ||
		    *totalp > INSTALL_MAX_TOTAL_SIZE ||
		    (uint64_t)amount > INSTALL_MAX_FILE_SIZE - copied ||
		    (uint64_t)amount > INSTALL_MAX_TOTAL_SIZE - *totalp) {
			errno = EFBIG;
			goto fail;
		}
		for (ssize_t offset = 0; offset < amount;) {
			ssize_t written;

			written = write(output, buffer + offset,
			    (size_t)(amount - offset));
			if (written < 0) {
				if (errno == EINTR)
					continue;
				goto fail;
			}
			if (written == 0) {
				errno = EIO;
				goto fail;
			}
			offset += written;
		}
		copied += (uint64_t)amount;
		*totalp += (uint64_t)amount;
	}
	if (fsync(output) == -1)
		goto fail;
	close(input);
	close(output);
	return (0);

fail:
	saved = errno != 0 ? errno : EIO;
	close(input);
	close(output);
	(void)unlink(destination);
	return (errno = saved, -1);
}

/* Copy a bounded physical tree without ever following a source symlink. */
static int
copy_bundle(const char *source, const char *stage, char *errbuf, size_t errlen)
{
	FTS *fts;
	FTSENT *ent;
	char root[PATH_MAX], destination[PATH_MAX], *paths[2];
	const char *relative;
	size_t rootlen;
	uint64_t total;
	unsigned entries;
	int fd, saved;

	if (realpath(source, root) == NULL)
		return (-1);
	rootlen = strlen(root);
	paths[0] = root;
	paths[1] = NULL;
	fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL)
		return (-1);
	entries = 0;
	total = 0;
	for (;;) {
		errno = 0;
		ent = fts_read(fts);
		if (ent == NULL)
			break;
		if (ent->fts_level == 0)
			relative = "";
		else if (strncmp(ent->fts_path, root, rootlen) != 0 ||
		    ent->fts_path[rootlen] != '/') {
			errno = EINVAL;
			goto fail;
		} else
			relative = ent->fts_path + rootlen + 1;
		if (snprintf(destination, sizeof(destination), "%s%s%s", stage,
		    relative[0] != '\0' ? "/" : "", relative) >=
		    (int)sizeof(destination)) {
			errno = ENAMETOOLONG;
			goto fail;
		}
		if (ent->fts_info != FTS_DP && ++entries > INSTALL_MAX_ENTRIES) {
			errno = E2BIG;
			goto fail;
		}
		switch (ent->fts_info) {
		case FTS_D:
			if (ent->fts_level != 0 && mkdir(destination, 0700) == -1)
				goto fail;
			break;
		case FTS_DP:
			fd = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
			    O_NOFOLLOW);
			if (fd == -1 || fsync(fd) == -1) {
				if (fd != -1)
					close(fd);
				goto fail;
			}
			close(fd);
			break;
		case FTS_F:
			if (copy_regular_file(ent->fts_accpath, destination,
			    &total) == -1)
				goto fail;
			break;
		default:
			errno = EINVAL;
			goto fail;
		}
	}
	if (errno != 0)
		goto fail;
	(void)fts_close(fts);
	return (0);

fail:
	saved = errno != 0 ? errno : EIO;
	snprintf(errbuf, errlen,
	    "source exceeds limits or contains an unsafe object: %s",
	    strerror(saved));
	(void)fts_close(fts);
	return (errno = saved, -1);
}

int
cmd_install(const char *bundle_path)
{
	struct capbundle *b;
	struct stat sb;
	char errbuf[256], dst[PATH_MAX], stage[PATH_MAX];
	const char *idir;
	int dfd, saved;

	if (bundle_path == NULL || bundle_path[0] == '\0') {
		warnx("install: bundle path is required");
		return (1);
	}
	if (geteuid() != 0) {
		warnx("install: root privileges are required");
		return (1);
	}
	if (lstat(bundle_path, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
		warnx("install: %s is not a bundle directory", bundle_path);
		return (1);
	}

	idir = install_dir();
	if (lstat(idir, &sb) == -1) {
		if (errno != ENOENT || mkdir(idir, 0755) == -1) {
			warn("install: cannot create %s", idir);
			return (1);
		}
	} else if (!S_ISDIR(sb.st_mode) || sb.st_uid != 0 ||
	    (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		warnx("install: %s must be a root-owned, non-group/world-writable directory",
		    idir);
		return (1);
	}
	if (snprintf(stage, sizeof(stage), "%s/.servicectl.XXXXXX", idir) >=
	    (int)sizeof(stage)) {
		warnx("install: staging path is too long");
		return (1);
	}
	if (mkdtemp(stage) == NULL) {
		warn("install: cannot create staging directory");
		return (1);
	}

	if (copy_bundle(bundle_path, stage, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: cannot stage bundle: %s", errbuf);
		goto fail;
	}
	if (normalize_staging_tree(stage, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: unsafe staged bundle: %s", errbuf);
		goto fail;
	}
	if (capbundle_open(stage, &b, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: invalid staged bundle: %s", errbuf);
		goto fail;
	}
	if (capbundle_verify(b, errbuf, sizeof(errbuf)) == -1) {
		warnx("install: verification failed: %s", errbuf);
		capbundle_close(b);
		goto fail;
	}
	if (snprintf(dst, sizeof(dst), "%s/%s@%020" PRIu64 ".cap", idir,
	    capbundle_id(b), capbundle_sequence(b)) >= (int)sizeof(dst)) {
		warnx("install: destination path is too long");
		capbundle_close(b);
		goto fail;
	}
	printf("install: %s v%s, sequence %" PRIu64 " (%u units)\n",
	    capbundle_id(b), capbundle_version(b), capbundle_sequence(b),
	    capbundle_nservices(b));
	capbundle_close(b);

	errno = 0;
	if (lstat(dst, &sb) == 0) {
		errno = EEXIST;
		warn("install: %s", dst);
		goto fail;
	}
	if (errno != ENOENT) {
		warn("install: %s", dst);
		goto fail;
	}
	if (rename(stage, dst) == -1) {
		warn("install: cannot publish %s", dst);
		goto fail;
	}
	dfd = open(idir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dfd == -1 || fsync(dfd) == -1) {
		saved = errno;
		if (dfd != -1)
			close(dfd);
		warnc(saved, "install: published but cannot sync %s", idir);
		return (1);
	}
	close(dfd);

	printf("install: published %s\n", dst);
	printf("install: run 'servicectl reload' to select the highest sequence\n");
	return (0);

fail:
	saved = errno;
	if (remove_staging_tree(stage) == -1)
		warn("install: cannot remove private staging directory %s", stage);
	errno = saved;
	return (1);
}

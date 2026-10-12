/* SPDX-License-Identifier: BSD-2-Clause */
/* Personal installation never changes platform trust or another user's files. */
#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libcapbundle.h>
#include <switchboard_manifest.h>
#include "switchboardctl.h"

#define PERSONAL_ENTRIES 4096U
#define PERSONAL_DEPTH 32U
#define PERSONAL_FILE_MAX (512ULL * 1024 * 1024)
#define PERSONAL_TOTAL_MAX (2ULL * 1024 * 1024 * 1024)

int
personal_bundle_verify(struct capbundle *b, char *error, size_t size)
{
	struct svc_manifest *m;
	int result = -1;

	if (capbundle_verify(b, error, size) != 0)
		return (-1);
	m = calloc(1, sizeof(*m));
	if (m == NULL) {
		snprintf(error, size, "cannot allocate personal policy");
		return (-1);
	}
	for (unsigned i = 0; i < capbundle_nservices(b); i++) {
		if (capbundle_svc_fill_manifest(capbundle_service(b, i), m) != 0) {
			snprintf(error, size, "cannot read unit policy");
			goto out;
		}
		/* Match the restrictions imposed by svc_user_manifest_confine.
		 * Do not install a different policy from the one the user supplied. */
		if ((!m->exec_application && m->management != SVC_MGMT_USER) ||
		    m->domain != SVC_MANIFEST_DOMAIN_USER || m->user_resolvable ||
		    m->ambient || m->cap_system != 0 || m->n_sysctl_isolate != 0 ||
		    m->nactivation_sockets != 0 || m->nanointments != 0 ||
		    strcmp(m->user, SWITCHBOARD_DEFAULT_USER) != 0 ||
		    strcmp(m->group, SWITCHBOARD_DEFAULT_GROUP) != 0) {
			snprintf(error, size, "personal unit '%s' requires control=user, "
			    "domain=user and no platform grants or credential overrides",
			    capbundle_svc_label(capbundle_service(b, i)));
			errno = EPERM;
			goto out;
		}
	}
	result = 0;
out:
	free(m);
	return (result);
}

/* All components are opened without following symlinks.  No caller-selected
 * destination or target UID; the offline root changes only the filesystem root. */
static int
personal_child_dir(int parent, const char *name, uid_t owner, bool create)
{
	struct stat st;
	int fd;

	if (create && mkdirat(parent, name, 0755) != 0 && errno != EEXIST)
		return (-1);
	fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &st) != 0 || st.st_uid != owner ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		close(fd);
		return (errno = EPERM, -1);
	}
	return (fd);
}

static int
personal_root(void)
{
	const char *root = getenv("SWITCHBOARD_LIFECYCLE_ROOT");
	char *copy, *part, *next;
	struct stat st;
	int fd, child, saved;

	if (root == NULL || root[0] == '\0')
		root = "/";
	if (root[0] != '/')
		return (errno = EINVAL, -1);
	copy = strdup(root);
	if (copy == NULL)
		return (-1);
	fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) { free(copy); return (-1); }
	next = copy;
	while ((part = strsep(&next, "/")) != NULL) {
		if (part[0] == '\0')
			continue;
		if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
			errno = EINVAL;
			goto fail;
		}
		child = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (child < 0)
			goto fail;
		close(fd);
		fd = child;
	}
	/* The offline root itself must belong to the caller or root.  /tmp
	 * ancestors may be sticky shared directories, but all are pinned fds. */
	if (fstat(fd, &st) != 0 || (st.st_uid != 0 && st.st_uid != getuid()) ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		errno = EPERM;
		goto fail;
	}
	free(copy);
	return (fd);
fail:
	saved = errno;
	free(copy);
	close(fd);
	return (errno = saved, -1);
}

/* Descriptor-relative removal never traverses an attacker-supplied symlink. */
static int
personal_remove(int fd)
{
	DIR *dir;
	struct dirent *de;
	struct stat st;
	int child, error = 0;

	if (fchmod(fd, 0700) != 0)
		return (-1);
	int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scan < 0)
		return (-1);
	dir = fdopendir(scan);
	if (dir == NULL) { close(scan); return (-1); }
	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
			error = -1;
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			child = openat(fd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (child < 0) { error = -1; continue; }
			if (personal_remove(child) != 0) error = -1;
			close(child);
		}
		if (unlinkat(fd, de->d_name, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) != 0)
			error = -1;
	}
	closedir(dir);
	return (error);
}

/* Pin the object before opening for IO, so a raced device/FIFO replacement
 * cannot trigger device open side effects under the installing UID. */
static int
personal_source_entry(int parent, const char *name)
{
	struct stat st;
	int pathfd, fd, saved;

	pathfd = openat(parent, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (pathfd < 0)
		return (-1);
	if (fstat(pathfd, &st) != 0 ||
	    (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))) {
		close(pathfd);
		return (errno = EINVAL, -1);
	}
	fd = openat(pathfd, "", O_RDONLY | O_EMPTY_PATH | O_CLOEXEC |
	    (S_ISDIR(st.st_mode) ? O_DIRECTORY : 0));
	saved = errno;
	close(pathfd);
	errno = saved;
	return (fd);
}

static int
personal_copy(int source, int dest, unsigned depth, unsigned *entries,
    uint64_t *total)
{
	DIR *dir;
	struct dirent *de;
	struct stat st, after;
	char buffer[16384];
	int in = -1, out = -1, saved = 0;
	ssize_t n;
	uint64_t copied;

	if (depth > PERSONAL_DEPTH)
		return (errno = E2BIG, -1);
	int scan = openat(source, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (scan < 0)
		return (-1);
	dir = fdopendir(scan);
	if (dir == NULL) { close(scan); return (-1); }
	for (;;) {
		errno = 0;
		de = readdir(dir);
		if (de == NULL) {
			saved = errno;
			break;
		}
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (++*entries > PERSONAL_ENTRIES) { saved = E2BIG; break; }
		in = personal_source_entry(source, de->d_name);
		if (in < 0 || fstat(in, &st) != 0) goto fail;
		if ((!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) ||
		    (st.st_mode & (07000 | S_IWGRP | S_IWOTH)) != 0) {
			errno = EPERM; goto fail;
		}
		if (S_ISDIR(st.st_mode)) {
			if ((st.st_mode & 0500) != 0500) { errno = EPERM; goto fail; }
			if (mkdirat(dest, de->d_name, 0700) != 0) goto fail;
			out = openat(dest, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (out < 0 || personal_copy(in, out, depth + 1, entries, total) != 0)
				goto fail;
		} else {
			if (st.st_size < 0 || (uint64_t)st.st_size > PERSONAL_FILE_MAX ||
			    (uint64_t)st.st_size > PERSONAL_TOTAL_MAX - *total) {
				errno = EFBIG; goto fail;
			}
			out = openat(dest, de->d_name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
			if (out < 0) goto fail;
			copied = 0;
			for (;;) {
				n = read(in, buffer, sizeof(buffer));
				if (n < 0 && errno == EINTR) continue;
				if (n < 0) goto fail;
				if (n == 0) break;
				if ((uint64_t)n > PERSONAL_FILE_MAX - copied ||
				    (uint64_t)n > PERSONAL_TOTAL_MAX - *total) {
					errno = EFBIG; goto fail;
				}
				for (ssize_t pos = 0; pos < n;) {
					ssize_t done = write(out, buffer + pos, (size_t)(n - pos));
					if (done < 0 && errno == EINTR) continue;
					if (done <= 0) { if (done == 0) errno = EIO; goto fail; }
					pos += done;
				}
				copied += (uint64_t)n;
				*total += (uint64_t)n;
			}
			if (copied != (uint64_t)st.st_size || fstat(in, &after) != 0 ||
			    after.st_size != st.st_size ||
			    timespeccmp(&after.st_mtim, &st.st_mtim, !=) ||
			    timespeccmp(&after.st_ctim, &st.st_ctim, !=)) {
				errno = ESTALE; goto fail;
			}
		}
		/* Bundle seals authenticate these bits: preserve, do not normalize. */
		if (fchmod(out, st.st_mode & 0777) != 0 || fsync(out) != 0) goto fail;
		close(in); close(out); in = out = -1;
	}
	goto finish;
fail:
	saved = errno;
finish:
	if (in >= 0) close(in);
	if (out >= 0) close(out);
	closedir(dir);
	return (saved == 0 ? 0 : (errno = saved, -1));
}

int
cmd_install_personal(const char *path)
{
	struct capbundle *bundle = NULL;
	struct stat st;
	char uid[32], stage[64] = "", name[NAME_MAX + 1], error[512];
	unsigned entries = 0;
	uint64_t total = 0;
	int root = -1, caps = -1, users = -1, owner = -1, agents = -1;
	int source = -1, staged = -1, cwd = -1, result = 1;
	bool published = false;

	if (getuid() != geteuid() || getgid() != getegid()) {
		warnx("install --personal: refuse changed process credentials");
		return (1);
	}
	if (getenv("SWITCHBOARD_BUNDLE_DIR_USER") != NULL) {
		warnx("install --personal: custom global bundle directory is not a personal destination");
		return (1);
	}
	root = personal_root();
	if (root < 0) goto fail;
	caps = personal_child_dir(root, "Capabilities", 0, false);
	if (caps < 0) goto fail;
	users = personal_child_dir(caps, "Users", 0, false);
	if (users < 0) goto fail;
	snprintf(uid, sizeof(uid), "%ju", (uintmax_t)getuid());
	owner = personal_child_dir(users, uid, getuid(), false);
	if (owner < 0) {
		warnx("install --personal: /Capabilities/Users/%s must be provisioned for this account", uid);
		goto fail;
	}
	agents = personal_child_dir(owner, "Agents", getuid(), true);
	if (agents < 0) goto fail;
	source = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (source < 0) goto fail;
	for (unsigned tries = 0; tries < 32; tries++) {
		snprintf(stage, sizeof(stage), ".switchboardctl.%08x%08x", arc4random(), arc4random());
		if (mkdirat(agents, stage, 0700) == 0) break;
		if (errno != EEXIST || tries == 31) { stage[0] = '\0'; goto fail; }
	}
	staged = openat(agents, stage, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (staged < 0 || personal_copy(source, staged, 0, &entries, &total) != 0)
		goto fail;
	cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cwd < 0 || fchdir(staged) != 0) goto fail;
	if (capbundle_open_personal(".", &bundle, error, sizeof(error)) != 0 ||
	    personal_bundle_verify(bundle, error, sizeof(error)) != 0) {
		warnx("install --personal: invalid staged bundle: %s", error);
		goto out;
	}
	if (snprintf(name, sizeof(name), "%s@%020" PRIu64 ".cap", capbundle_id(bundle),
	    capbundle_sequence(bundle)) >= (int)sizeof(name)) { errno = ENAMETOOLONG; goto fail; }
	if (fchmod(staged, 0755) != 0 || fsync(staged) != 0) goto fail;
	/* Check target with no-follow semantics; renameat2 closes the race. */
	if (fstatat(agents, name, &st, AT_SYMLINK_NOFOLLOW) == 0) { errno = EEXIST; goto fail; }
	if (errno != ENOENT) goto fail;
	if (renameat2(agents, stage, agents, name, AT_RENAME_NOREPLACE) != 0) goto fail;
	published = true;
	if (fsync(agents) != 0) {
		warn("install --personal: published but directory sync failed");
		goto out;
	}
	printf("install: published /Capabilities/Users/%s/Agents/%s\n", uid, name);
	printf("install: an authorized reload is required for discovery\n");
	result = 0;
	goto out;
fail:
	warn("install --personal");
out:
	if (cwd >= 0 && fchdir(cwd) != 0) {
		warn("install --personal: restore working directory");
		result = 1;
	}
	if (bundle != NULL) capbundle_close(bundle);
	if (!published && staged >= 0) {
		if (personal_remove(staged) != 0 || unlinkat(agents, stage, AT_REMOVEDIR) != 0)
			warn("install --personal: remove staging directory");
	}
	if (cwd >= 0) close(cwd);
	if (staged >= 0) close(staged);
	if (source >= 0) close(source);
	if (agents >= 0) close(agents);
	if (owner >= 0) close(owner);
	if (users >= 0) close(users);
	if (caps >= 0) close(caps);
	if (root >= 0) close(root);
	return (result);
}

/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_SOURCE_OWNER_H_
#define _BHYVE_MIGRATION_SOURCE_OWNER_H_
#include <stdint.h>
#include "migration_recovery.h"

/* One trusted directory per controller lifetime; an owned descriptor survives
 * request teardown and prevents inode reuse while identity is compared. */
static inline int
migration_source_root_pin(int *owned, int requested)
{
	struct stat supplied, pinned;
	int error, fd;

	if (owned == NULL || *owned < -1)
		return (EINVAL);
	error = migration_recovery_file_check(requested, true);
	if (error != 0)
		return (error);
	if (fstat(requested, &supplied) != 0)
		return (errno);
	if (*owned >= 0) {
		if (fstat(*owned, &pinned) != 0)
			return (errno);
		return (supplied.st_dev == pinned.st_dev &&
		    supplied.st_ino == pinned.st_ino ? 0 : EXDEV);
	}
	fd = fcntl(requested, F_DUPFD_CLOEXEC, 0);
	if (fd < 0)
		return (errno);
	*owned = fd;
	return (0);
}

/* Walk the fixed host path from a trusted root descriptor. Parent directories
 * must be administrator-owned and not writable by group/other. The final
 * journal directory must also satisfy the private effective-owner policy.
 * The anchor/owner parameters allow isolated filesystem validation; production
 * callers use migration_source_canonical_root_open, never a request pathname. */
static inline int
migration_source_root_open_at(int anchor, uid_t administrator, int *result)
{
	static const char * const components[] = { "var", "db", "bhyve", "migration" };
	struct stat st;
	int current, next, error = 0;

	if (result == NULL)
		return (EINVAL);
	current = fcntl(anchor, F_DUPFD_CLOEXEC, 0);
	if (current < 0)
		return (errno);
	for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); i++) {
		if (fstat(current, &st) != 0) { error = errno; break; }
		if (!S_ISDIR(st.st_mode) || st.st_uid != administrator ||
		    (st.st_mode & 022) != 0) { error = EPERM; break; }
		next = openat(current, components[i], O_RDONLY | O_DIRECTORY |
		    O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
		if (next < 0) { error = errno; break; }
		close(current);
		current = next;
	}
	if (error == 0)
		error = migration_recovery_file_check(current, true);
	if (error != 0) {
		close(current);
		return (error);
	}
	*result = current;
	return (0);
}

static inline int
migration_source_canonical_root_open(int *result)
{
	int anchor, error;

	anchor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (anchor < 0)
		return (errno);
	error = migration_source_root_open_at(anchor, 0, result);
	close(anchor);
	return (error);
}

/* Serialize controllers for one lifetime within the trusted root. Keep the
 * returned descriptor open across all transitions/reconnects. Never unlink this
 * lock: a replacement inode would admit two owners. This is not retirement. */
static inline int
migration_source_controller_lock_at(int dirfd, uint16_t vmid, uint64_t epoch,
    int *result)
{
	char name[80];
	int fd, error;

	if (result == NULL || vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0)
		return (EINVAL);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	snprintf(name, sizeof(name), "source-controller-%04x-%016jx.lock",
	    (unsigned)vmid, (uintmax_t)epoch);
	fd = openat(dirfd, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error == 0 && flock(fd, LOCK_EX | LOCK_NB) != 0)
		error = errno == EWOULDBLOCK ? EBUSY : errno;
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (error == 0 && fsync(dirfd) != 0)
		error = errno;
	if (error != 0) {
		close(fd);
		return (error);
	}
	*result = fd;
	return (0);
}

/* Recover the immutable attempt for an independently known source lifetime.
 * The controller must supply its trusted recovery root, never a peer-selected
 * directory or lifetime. This neither creates evidence nor authorizes RELEASE.
 * The caller still needs the phase journal, peer authentication and retirement.
 * Keep the output unchanged on any validation or durability failure. */
static inline int
migration_source_owner_load_at(int dirfd, uint16_t vmid, uint64_t epoch,
    struct migration_recovery_record *result)
{
	struct migration_recovery_record record;
	struct hypertrace_session_record session;
	uint8_t wire[MIGRATION_RECOVERY_SIZE + 1];
	char stem[68], lockname[80], name[80];
	size_t used = 0;
	ssize_t n;
	int lockfd = -1, fd = -1, error;

	if (result == NULL || vmid == 0 || vmid >= HYPERTRACE_MAX_VMS || epoch == 0)
		return (EINVAL);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	snprintf(stem, sizeof(stem), "source-owner-%04x-%016jx",
	    (unsigned)vmid, (uintmax_t)epoch);
	snprintf(lockname, sizeof(lockname), "%s.lock", stem);
	snprintf(name, sizeof(name), "%s.state", stem);
	lockfd = openat(dirfd, lockname, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (lockfd < 0)
		return (errno);
	error = migration_recovery_file_check(lockfd, false);
	if (error == 0 && flock(lockfd, LOCK_SH) != 0)
		error = errno;
	if (error != 0)
		goto out;
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) { error = errno; goto out; }
	error = migration_recovery_file_check(fd, false);
	while (error == 0 && used < sizeof(wire)) {
		n = read(fd, wire + used, sizeof(wire) - used);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0) { error = errno; break; }
		if (n == 0) break;
		used += (size_t)n;
	}
	if (error == 0)
		error = migration_recovery_decode(wire, used, &record);
	if (error == 0 && record.phase != MIGRATION_REC_SOURCE_INTENT)
		error = EPROTO;
	if (error == 0)
		error = hypertrace_session_record_decode(record.session,
		    sizeof(record.session), &session);
	if (error == 0 && (session.vmid != vmid || session.epoch != epoch))
		error = ESTALE;
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (error == 0 && fsync(dirfd) != 0)
		error = errno;
	if (error == 0)
		*result = record;
out:
	if (fd >= 0) close(fd);
	close(lockfd);
	return (error);
}

/* Immutable ownership of one source lifetime within the trusted recovery root.
 * Publish before INTENT. Never remove on failed migration or confirmation:
 * retirement evidence must not authorize a second destination. The controller
 * must enforce a single recovery root and exclusive access to the VM context.
 * Validation cannot create missing evidence. This is not peer authentication.
 */
static inline int
migration_source_owner_at(int dirfd,
    const struct migration_recovery_record *expected, bool create)
{
	uint8_t wire[MIGRATION_RECOVERY_SIZE];
	char stem[68], lockname[80], name[80], temporary[112] = {0};
	uint16_t previous = 0;
	int lockfd = -1, fd = -1, error;
	size_t used = 0;
	ssize_t n;
	struct migration_recovery_record record;
	struct hypertrace_session_record session;
	const struct migration_recovery_record *r = &record;

	if (expected == NULL || expected->phase < MIGRATION_REC_SOURCE_INTENT ||
	    expected->phase > MIGRATION_REC_SOURCE_CONFIRMED)
		return (EINVAL);
	record = *expected;
	record.phase = MIGRATION_REC_SOURCE_INTENT;

	error = migration_recovery_encode(r, wire);
	if (error != 0)
		return (error);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	error = hypertrace_session_record_decode(r->session, sizeof(r->session), &session);
	if (error != 0)
		return (error);
	if (!create) {
		struct migration_recovery_record owned;
		uint8_t canonical[MIGRATION_RECOVERY_SIZE];

		error = migration_source_owner_load_at(dirfd, session.vmid,
		    session.epoch, &owned);
		if (error != 0)
			return (error);
		error = migration_recovery_encode(&owned, canonical);
		if (error != 0)
			return (error);
		return (memcmp(wire, canonical, sizeof(wire)) == 0 ? 0 : EPROTO);
	}
	snprintf(stem, sizeof(stem), "source-owner-%04x-%016jx",
	    (unsigned)session.vmid, (uintmax_t)session.epoch);
	snprintf(lockname, sizeof(lockname), "%s.lock", stem);
	snprintf(name, sizeof(name), "%s.state", stem);
	lockfd = openat(dirfd, lockname, O_RDWR | (create ? O_CREAT : 0) | O_NOFOLLOW |
	    O_NONBLOCK | O_CLOEXEC, 0600);
	if (lockfd < 0)
		return (errno);
	error = migration_recovery_file_check(lockfd, false);
	if (error == 0 && flock(lockfd, LOCK_EX) != 0)
		error = errno;
	if (error != 0)
		goto out;
	error = migration_recovery_read_locked(dirfd, name, r, &previous);
	if (error == ENOENT && create) {
		error = 0;
	} else if (error == 0) {
		if (previous != MIGRATION_REC_SOURCE_INTENT) {
			error = EPROTO;
			goto out;
		}
		goto sync_directory;
	}
	if (error != 0)
		goto out;
	snprintf(temporary, sizeof(temporary), "%s.tmp.%08x%08x", stem,
	    arc4random(), arc4random());
	fd = openat(dirfd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (fd < 0) { error = errno; temporary[0] = '\0'; goto out; }
	while (used < sizeof(wire)) {
		n = write(fd, wire + used, sizeof(wire) - used);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) { error = n < 0 ? errno : EIO; goto out; }
		used += (size_t)n;
	}
	if (fsync(fd) != 0) { error = errno; goto out; }
	if (renameat(dirfd, temporary, dirfd, name) != 0) {
		error = errno;
		goto out;
	}
	temporary[0] = '\0';
sync_directory:
	if (fsync(dirfd) != 0)
		error = errno;
out:
	if (fd >= 0) close(fd);
	if (temporary[0] != '\0') (void)unlinkat(dirfd, temporary, 0);
	close(lockfd);
	return (error);
}
#endif

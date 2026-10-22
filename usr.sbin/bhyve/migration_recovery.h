/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_RECOVERY_H_
#define _BHYVE_MIGRATION_RECOVERY_H_

#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sha256.h>
#include "hypertrace_session.h"
#include "migration_recovery_phase.h"

/* Local durable facts, never credentials to start a remote VM. Intent must
 * precede destruction; RETIRED requires checked destruction. A peer must
 * authenticate and reconcile these facts before any recovery action. */
struct migration_recovery_record {
	uint16_t phase;
	uint16_t destination_vmid;
	uint64_t destination_epoch;
	uint8_t session[HYPERTRACE_SESSION_RECORD_SIZE];
	uint8_t challenge[32];
	uint8_t state_digest[32];
	uint8_t source_certificate_sha256[32];
	uint8_t destination_certificate_sha256[32];
};

#define MIGRATION_RECOVERY_SIZE 224U

static inline void
migration_recovery_names(const struct migration_recovery_record *r,
    char lockname[80], char name[80], char stem[68])
{
	static const char hex[] = "0123456789abcdef";
	stem[0] = r->phase < MIGRATION_REC_DEST_STAGED ? 's' : 'd';
	stem[1] = '-';
	for (size_t i = 0; i < 32; i++) {
		stem[2 + 2*i] = hex[r->challenge[i] >> 4];
		stem[3 + 2*i] = hex[r->challenge[i] & 15];
	}
	stem[66] = '\0';
	snprintf(lockname, 80, "%s.lock", stem);
	snprintf(name, 80, "%s.state", stem);
}

static inline int
migration_recovery_encode(const struct migration_recovery_record *r,
    uint8_t wire[MIGRATION_RECOVERY_SIZE])
{
	struct hypertrace_session_record session;

	if (r == NULL || wire == NULL ||
	    !((r->phase >= MIGRATION_REC_SOURCE_INTENT &&
	    r->phase <= MIGRATION_REC_SOURCE_CONFIRMED) ||
	    (r->phase >= MIGRATION_REC_DEST_STAGED &&
	    r->phase <= MIGRATION_REC_DEST_RUNNING)) ||
	    hypertrace_session_record_decode(r->session, sizeof(r->session),
	    &session) != 0 || r->destination_vmid == 0 ||
	    r->destination_vmid >= HYPERTRACE_MAX_VMS ||
	    r->destination_epoch == 0 || r->destination_epoch == session.epoch ||
	    memcmp(r->challenge, (const uint8_t[32]){0}, 32) == 0 ||
	    memcmp(r->state_digest, (const uint8_t[32]){0}, 32) == 0 ||
	    memcmp(r->source_certificate_sha256, (const uint8_t[32]){0}, 32) == 0 ||
	    memcmp(r->destination_certificate_sha256, (const uint8_t[32]){0}, 32) == 0)
		return (EINVAL);
	memset(wire, 0, MIGRATION_RECOVERY_SIZE);
	memcpy(wire, "HMR2", 4);
	le16enc(wire + 4, 2);
	le16enc(wire + 6, r->phase);
	memcpy(wire + 8, r->session, 40);
	le16enc(wire + 48, r->destination_vmid);
	le64enc(wire + 56, r->destination_epoch);
	memcpy(wire + 64, r->challenge, 32);
	memcpy(wire + 96, r->state_digest, 32);
	memcpy(wire + 128, r->source_certificate_sha256, 32);
	memcpy(wire + 160, r->destination_certificate_sha256, 32);
	SHA256_CTX hash;
	SHA256_Init(&hash);
	SHA256_Update(&hash, wire, 192);
	SHA256_Final(wire + 192, &hash);
	return (0);
}

/* Decode only canonical, checksummed local records. This is serialization,
 * not authorization: callers must establish the trusted journal and owner. */
static inline int
migration_recovery_decode(const uint8_t *wire, size_t size,
    struct migration_recovery_record *result)
{
	struct migration_recovery_record record = {0};
	uint8_t canonical[MIGRATION_RECOVERY_SIZE];

	if (wire == NULL || result == NULL)
		return (EINVAL);
	if (size != MIGRATION_RECOVERY_SIZE)
		return (EPROTO);
	record.phase = le16dec(wire + 6);
	memcpy(record.session, wire + 8, sizeof(record.session));
	record.destination_vmid = le16dec(wire + 48);
	record.destination_epoch = le64dec(wire + 56);
	memcpy(record.challenge, wire + 64, sizeof(record.challenge));
	memcpy(record.state_digest, wire + 96, sizeof(record.state_digest));
	memcpy(record.source_certificate_sha256, wire + 128, 32);
	memcpy(record.destination_certificate_sha256, wire + 160, 32);
	if (migration_recovery_encode(&record, canonical) != 0 ||
	    memcmp(wire, canonical, sizeof(canonical)) != 0)
		return (EPROTO);
	*result = record;
	return (0);
}

static inline int
migration_recovery_file_check(int fd, bool directory)
{
	struct stat st;
	if (fstat(fd, &st) != 0)
		return (errno);
	if ((directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) ||
	    st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
	    (!directory && st.st_nlink != 1))
		return (EPERM);
	return (0);
}

/* Caller owns the per-attempt lock. The expected tuple is mandatory: a
 * journal file is not permission to recover an arbitrary VM incarnation. */
static inline int
migration_recovery_read_locked(int dirfd, const char *name,
    const struct migration_recovery_record *expected, uint16_t *phase)
{
	struct migration_recovery_record candidate = *expected;
	uint8_t wire[MIGRATION_RECOVERY_SIZE + 1], canonical[MIGRATION_RECOVERY_SIZE];
	size_t used = 0;
	int fd, error;
	ssize_t n;

	fd = openat(dirfd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	while (error == 0 && used < sizeof(wire)) {
		n = read(fd, wire + used, sizeof(wire) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) { error = errno; break; }
		if (n == 0) break;
		used += (size_t)n;
	}
	if (error == 0 && used != MIGRATION_RECOVERY_SIZE)
		error = EPROTO;
	if (error == 0) {
		candidate.phase = le16dec(wire + 6);
		error = migration_recovery_encode(&candidate, canonical);
		if (error == 0 && memcmp(wire, canonical, sizeof(canonical)) != 0)
			error = EPROTO;
	}
	/* Retry must finish uncertain durability from a prior publication. */
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	close(fd);
	if (error == 0)
		*phase = candidate.phase;
	return (error);
}

/* Read durable facts for an independently known binding, including after
 * process restart. Missing or corrupt evidence never becomes completion. */
static inline int
migration_recovery_load_at(int dirfd,
    const struct migration_recovery_record *expected, uint16_t *phase)
{
	uint8_t canonical[MIGRATION_RECOVERY_SIZE];
	char stem[68], lockname[80], name[80];
	uint16_t found = 0;
	int fd, error;

	if (phase == NULL)
		return (EINVAL);
	error = migration_recovery_encode(expected, canonical);
	if (error != 0)
		return (error);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_recovery_names(expected, lockname, name, stem);
	fd = openat(dirfd, lockname, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error == 0 && flock(fd, LOCK_SH) != 0)
		error = errno;
	if (error == 0)
		error = migration_recovery_read_locked(dirfd, name, expected, &found);
	if (error == 0 && (found < MIGRATION_REC_DEST_STAGED) !=
	    (expected->phase < MIGRATION_REC_DEST_STAGED))
		error = EPROTO;
	if (error == 0 && fsync(dirfd) != 0)
		error = errno;
	close(fd);
	if (error == 0)
		*phase = found;
	return (error);
}

/* Persist one monotonic transition in a private, pre-opened directory.
 * Atomic replacement leaves the previous or new complete record on a crash.
 * A failed fsync is never success, even when the new record is visible;
 * an exact retry revalidates and fsyncs it and its directory. */
static inline int
migration_recovery_store_at(int dirfd, const struct migration_recovery_record *r)
{
	uint8_t wire[MIGRATION_RECOVERY_SIZE];
	char stem[68], lockname[80], name[80], temporary[112] = {0};
	uint16_t previous = 0;
	int lockfd = -1, fd = -1, error;
	size_t used = 0;
	ssize_t n;
	bool source;

	error = migration_recovery_encode(r, wire);
	if (error != 0)
		return (error);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	source = r->phase < MIGRATION_REC_DEST_STAGED;
	migration_recovery_names(r, lockname, name, stem);
	lockfd = openat(dirfd, lockname, O_RDWR | O_CREAT | O_NOFOLLOW |
	    O_NONBLOCK | O_CLOEXEC, 0600);
	if (lockfd < 0)
		return (errno);
	error = migration_recovery_file_check(lockfd, false);
	if (error == 0 && flock(lockfd, LOCK_EX) != 0)
		error = errno;
	if (error != 0)
		goto out;
	error = migration_recovery_read_locked(dirfd, name, r, &previous);
	if (error == ENOENT) {
		error = r->phase == (source ? MIGRATION_REC_SOURCE_INTENT :
		    MIGRATION_REC_DEST_STAGED) ? 0 : ESTALE;
	} else if (error == 0) {
		if (previous == r->phase)
			goto sync_directory;
		if (r->phase != previous + 1 ||
		    (previous < MIGRATION_REC_DEST_STAGED) != source)
			error = ESTALE;
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

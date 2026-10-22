/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Handoff journal for ordinary (non-HyperTrace) migrations.
 *
 * A HyperTrace fresh-session migration keeps the HMR2 phase record, whose
 * encoder requires a HyperTrace session record and both certificate pins.
 * Every other migration keeps this journal instead, when a recovery directory
 * is configured: one append-only file per attempt and role, holding fixed-size
 * entries for each phase transition and, on a retained destination, for each
 * operator resolution (written before acting) and its outcome.  The journal
 * records what happened; it holds no guest state and authorizes nothing.
 *
 * Durability follows migration_recovery_store_at(): a private directory and
 * file, an exclusive lock across read-validate-append, fsync of the file after
 * every entry and of the directory when the file is new.  A torn tail (a
 * length that is not a whole number of entries) is refused rather than
 * repaired, so an operator sees it.
 */
#ifndef _MIGRATION_HANDOFF_H_
#define	_MIGRATION_HANDOFF_H_

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "migration_recovery.h"

#define	MIGRATION_HANDOFF_SIZE	128U
#define	MIGRATION_HANDOFF_MAX	64U	/* entries one attempt may hold */

enum migration_handoff_kind {
	MIGRATION_HANDOFF_PHASE = 1,	/* a phase transition */
	MIGRATION_HANDOFF_RESOLVE,	/* an operator decision, before acting */
	MIGRATION_HANDOFF_OUTCOME,	/* the result of that decision */
};

enum migration_handoff_role {
	MIGRATION_HANDOFF_SOURCE = 1,
	MIGRATION_HANDOFF_DEST,
};

enum migration_handoff_action {
	MIGRATION_HANDOFF_RESUME = 1,
	MIGRATION_HANDOFF_DISCARD,
};

struct migration_handoff_entry {
	uint8_t kind;			/* enum migration_handoff_kind */
	uint8_t role;			/* enum migration_handoff_role */
	uint8_t action;			/* RESOLVE/OUTCOME: enum migration_handoff_action */
	uint8_t tls;			/* 1 when both certificate pins were known */
	uint16_t phase;			/* PHASE: enum migration_recovery_phase */
	uint16_t destination_vmid;
	uint64_t destination_epoch;
	uint8_t challenge[32];
	uint8_t state_digest[32];
	int32_t result;			/* OUTCOME: errno, 0 on success */
	/* RESOLVE resume: the run witness that admitted the decision. */
	uint16_t witness_vmid;
	uint32_t witness_running;
	uint64_t witness_epoch;
	uint64_t witness_entries;
	uint32_t seq;			/* position in the file, from 0 */
};

/*
 * Wire layout, little endian:
 *   0 "MHJ1"  4 kind  5 role  6 action  7 tls  8 phase  10 vmid
 *  12 result  16 epoch  24 challenge  56 digest  88 witness_epoch
 *  96 witness_entries  104 witness_running  108 witness_vmid  110 zero
 * 112 seq  116 zero  124 crc32 of bytes [0, 124)
 */

static inline bool
migration_handoff_witness_zero(const struct migration_handoff_entry *e)
{
	return (e->witness_vmid == 0 && e->witness_running == 0 &&
	    e->witness_epoch == 0 && e->witness_entries == 0);
}

static inline bool
migration_handoff_valid(const struct migration_handoff_entry *e)
{
	static const uint8_t zero[32];
	bool source, action_ok;

	if (e == NULL || (e->role != MIGRATION_HANDOFF_SOURCE &&
	    e->role != MIGRATION_HANDOFF_DEST) || e->tls > 1 ||
	    memcmp(e->challenge, zero, 32) == 0 ||
	    memcmp(e->state_digest, zero, 32) == 0 ||
	    e->destination_vmid == 0 ||
	    e->destination_vmid >= HYPERTRACE_MAX_VMS ||
	    e->destination_epoch == 0)
		return (false);
	source = e->role == MIGRATION_HANDOFF_SOURCE;
	action_ok = e->action == MIGRATION_HANDOFF_RESUME ||
	    e->action == MIGRATION_HANDOFF_DISCARD;
	switch (e->kind) {
	case MIGRATION_HANDOFF_PHASE:
		if (e->action != 0 || e->result != 0 ||
		    !migration_handoff_witness_zero(e))
			return (false);
		return (source ?
		    (e->phase >= MIGRATION_REC_SOURCE_INTENT &&
		    e->phase <= MIGRATION_REC_SOURCE_CONFIRMED) :
		    (e->phase >= MIGRATION_REC_DEST_STAGED &&
		    e->phase <= MIGRATION_REC_DEST_RUNNING));
	case MIGRATION_HANDOFF_RESOLVE:
		/* Only a destination resolves; a discard consults no witness. */
		return (!source && e->phase == 0 && e->result == 0 && action_ok &&
		    (e->action == MIGRATION_HANDOFF_RESUME ||
		    migration_handoff_witness_zero(e)));
	case MIGRATION_HANDOFF_OUTCOME:
		return (!source && e->phase == 0 && action_ok && e->result >= 0 &&
		    migration_handoff_witness_zero(e));
	}
	return (false);
}

static inline int
migration_handoff_encode(const struct migration_handoff_entry *e,
    uint8_t wire[MIGRATION_HANDOFF_SIZE])
{
	if (wire == NULL || !migration_handoff_valid(e))
		return (EINVAL);
	memset(wire, 0, MIGRATION_HANDOFF_SIZE);
	memcpy(wire, "MHJ1", 4);
	wire[4] = e->kind;
	wire[5] = e->role;
	wire[6] = e->action;
	wire[7] = e->tls;
	le16enc(wire + 8, e->phase);
	le16enc(wire + 10, e->destination_vmid);
	le32enc(wire + 12, (uint32_t)e->result);
	le64enc(wire + 16, e->destination_epoch);
	memcpy(wire + 24, e->challenge, 32);
	memcpy(wire + 56, e->state_digest, 32);
	le64enc(wire + 88, e->witness_epoch);
	le64enc(wire + 96, e->witness_entries);
	le32enc(wire + 104, e->witness_running);
	le16enc(wire + 108, e->witness_vmid);
	le32enc(wire + 112, e->seq);
	le32enc(wire + 124, (uint32_t)crc32(0L, wire, 124));
	return (0);
}

static inline int
migration_handoff_decode(const uint8_t wire[MIGRATION_HANDOFF_SIZE],
    struct migration_handoff_entry *e)
{
	static const uint8_t zero[8];

	if (wire == NULL || e == NULL)
		return (EINVAL);
	if (memcmp(wire, "MHJ1", 4) != 0 ||
	    le32dec(wire + 124) != (uint32_t)crc32(0L, wire, 124) ||
	    memcmp(wire + 110, zero, 2) != 0 || memcmp(wire + 116, zero, 8) != 0)
		return (EPROTO);
	memset(e, 0, sizeof(*e));
	e->kind = wire[4];
	e->role = wire[5];
	e->action = wire[6];
	e->tls = wire[7];
	e->phase = le16dec(wire + 8);
	e->destination_vmid = le16dec(wire + 10);
	e->result = (int32_t)le32dec(wire + 12);
	e->destination_epoch = le64dec(wire + 16);
	memcpy(e->challenge, wire + 24, 32);
	memcpy(e->state_digest, wire + 56, 32);
	e->witness_epoch = le64dec(wire + 88);
	e->witness_entries = le64dec(wire + 96);
	e->witness_running = le32dec(wire + 104);
	e->witness_vmid = le16dec(wire + 108);
	e->seq = le32dec(wire + 112);
	return (migration_handoff_valid(e) ? 0 : EPROTO);
}

/* "h-s-<challenge>.log" or "h-d-<challenge>.log": one file per attempt+role. */
static inline void
migration_handoff_name(uint8_t role, const uint8_t challenge[32], char name[80])
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	name[0] = 'h';
	name[1] = '-';
	name[2] = role == MIGRATION_HANDOFF_SOURCE ? 's' : 'd';
	name[3] = '-';
	for (i = 0; i < 32; i++) {
		name[4 + 2 * i] = hex[challenge[i] >> 4];
		name[5 + 2 * i] = hex[challenge[i] & 15];
	}
	memcpy(name + 68, ".log", 5);
}

/* Caller holds the lock.  Every entry must belong to this attempt and role
 * and sit at its own position; a torn tail or any invalid entry is EPROTO. */
static inline int
migration_handoff_read_locked(int fd, uint8_t role, const uint8_t challenge[32],
    struct migration_handoff_entry *entries, size_t max, size_t *count)
{
	uint8_t wire[MIGRATION_HANDOFF_SIZE];
	struct stat st;
	size_t i, used, have;
	ssize_t n;
	int error;

	*count = 0;
	if (fstat(fd, &st) != 0)
		return (errno);
	if (st.st_size < 0 || (uint64_t)st.st_size % MIGRATION_HANDOFF_SIZE != 0)
		return (EPROTO);
	have = (size_t)((uint64_t)st.st_size / MIGRATION_HANDOFF_SIZE);
	if (have > max)
		return (E2BIG);
	for (i = 0; i < have; i++) {
		used = 0;
		while (used < sizeof(wire)) {
			n = pread(fd, wire + used, sizeof(wire) - used,
			    (off_t)(i * MIGRATION_HANDOFF_SIZE + used));
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0)
				return (errno);
			if (n == 0)
				return (EPROTO);	/* shrank under the lock */
			used += (size_t)n;
		}
		error = migration_handoff_decode(wire, &entries[i]);
		if (error != 0)
			return (error);
		if (entries[i].role != role || entries[i].seq != i ||
		    memcmp(entries[i].challenge, challenge, 32) != 0)
			return (EPROTO);
	}
	*count = have;
	return (0);
}

/*
 * Sequence rules for a new entry against the attempt's history:
 *   PHASE    the first is INTENT (source) or STAGED (destination); then each
 *            is the previous plus one.  Repeating the current phase is an
 *            idempotent retry (EALREADY, which the writer treats as success).
 *            Every phase entry of one attempt carries the same binding.
 *   RESOLVE  destination only, after at least one phase and never once the
 *            guest is RUNNING; refused (EBUSY) while an earlier decision has
 *            no outcome yet.
 *   OUTCOME  closes the pending RESOLVE of the same action.
 */
static inline int
migration_handoff_admit(const struct migration_handoff_entry *have,
    size_t count, const struct migration_handoff_entry *e)
{
	const struct migration_handoff_entry *last_phase = NULL;
	const struct migration_handoff_entry *pending = NULL;
	size_t i;

	for (i = 0; i < count; i++) {
		if (have[i].kind == MIGRATION_HANDOFF_PHASE) {
			last_phase = &have[i];
			if (have[i].destination_vmid != e->destination_vmid ||
			    have[i].destination_epoch != e->destination_epoch ||
			    memcmp(have[i].state_digest, e->state_digest, 32) != 0 ||
			    have[i].tls != e->tls)
				return (EPROTO);
		} else if (have[i].kind == MIGRATION_HANDOFF_RESOLVE)
			pending = &have[i];
		else
			pending = NULL;
	}
	switch (e->kind) {
	case MIGRATION_HANDOFF_PHASE:
		if (last_phase == NULL)
			return (e->phase == (e->role == MIGRATION_HANDOFF_SOURCE ?
			    MIGRATION_REC_SOURCE_INTENT : MIGRATION_REC_DEST_STAGED) ?
			    0 : ESTALE);
		if (last_phase->phase == e->phase)
			return (EALREADY);
		return (e->phase == last_phase->phase + 1 ? 0 : ESTALE);
	case MIGRATION_HANDOFF_RESOLVE:
		if (last_phase == NULL ||
		    last_phase->phase == MIGRATION_REC_DEST_RUNNING)
			return (ESTALE);
		return (pending != NULL ? EBUSY : 0);
	case MIGRATION_HANDOFF_OUTCOME:
		return (pending != NULL && pending->action == e->action ? 0 : ESTALE);
	}
	return (EINVAL);
}

/* Append one entry durably; the caller's seq is replaced by the position. */
static inline int
migration_handoff_append(int dirfd, const struct migration_handoff_entry *entry)
{
	struct migration_handoff_entry have[MIGRATION_HANDOFF_MAX], e;
	uint8_t wire[MIGRATION_HANDOFF_SIZE];
	char name[80];
	size_t count = 0, used;
	ssize_t n;
	int fd, error;

	if (!migration_handoff_valid(entry))
		return (EINVAL);
	e = *entry;
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_handoff_name(e.role, e.challenge, name);
	fd = openat(dirfd, name, O_RDWR | O_APPEND | O_CREAT | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error == 0 && flock(fd, LOCK_EX) != 0)
		error = errno;
	if (error == 0)
		error = migration_handoff_read_locked(fd, e.role, e.challenge,
		    have, MIGRATION_HANDOFF_MAX, &count);
	if (error == 0 && count == MIGRATION_HANDOFF_MAX)
		error = E2BIG;
	if (error == 0)
		error = migration_handoff_admit(have, count, &e);
	if (error == EALREADY) {
		error = 0;
		goto sync;	/* finish a prior append's uncertain durability */
	}
	if (error != 0)
		goto out;
	e.seq = (uint32_t)count;
	error = migration_handoff_encode(&e, wire);
	if (error != 0)
		goto out;
	used = 0;
	while (used < sizeof(wire)) {
		n = write(fd, wire + used, sizeof(wire) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			error = errno;
			goto out;
		}
		used += (size_t)n;
	}
sync:
	if (fsync(fd) != 0)
		error = errno;
	if (error == 0 && count == 0 && fsync(dirfd) != 0)
		error = errno;
out:
	close(fd);
	return (error);
}

/* Read one attempt's journal for inspection; ENOENT when it has none. */
static inline int
migration_handoff_load(int dirfd, uint8_t role, const uint8_t challenge[32],
    struct migration_handoff_entry *entries, size_t max, size_t *count)
{
	char name[80];
	int fd, error;

	if (entries == NULL || count == NULL)
		return (EINVAL);
	*count = 0;
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_handoff_name(role, challenge, name);
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error == 0 && flock(fd, LOCK_SH) != 0)
		error = errno;
	if (error == 0)
		error = migration_handoff_read_locked(fd, role, challenge, entries,
		    max, count);
	close(fd);
	return (error);
}

#endif /* _MIGRATION_HANDOFF_H_ */

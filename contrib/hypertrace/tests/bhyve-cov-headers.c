/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The inline migration helpers in usr.sbin/bhyve/migration_*.h, compiled with
 * migration_session.c's production preprocessor view and linked with the
 * original migration sources (references to the rest of bhyve are stubbed).
 *
 * Oracles:
 *  - codecs (recovery record, fresh COMMIT binding, migration blob view):
 *    random valid values round-trip; every single-byte mutation is either
 *    refused or decodes to a value whose canonical encoding is the mutated
 *    input; each rule violation is refused before any output is written;
 *  - the durable journal: monotonic phase transitions only, private files
 *    (owner, mode, link count, no symlinks), corrupted or mismatched evidence
 *    never yields a phase; the source-owner record is immutable and bound
 *    to its VM lifetime; controller locks exclude a second owner;
 *  - the root walk: every parent administrator-owned and not group/other
 *    writable, the journal directory private, a pinned root never replaced;
 *  - reconciliation: the documented action table over phases and the
 *    observed destination state.
 */
#include <sys/param.h>
#include <sys/socket.h>
#include <signal.h>
#include "migration_session.h"
#include "migration_recovery.h"
#include "migration_source_owner.h"
#include "migration_source_storage.h"
#include "migration_commit.h"
#include "migration_snapshot.h"
#include "migration_reconcile.h"
#include "migration_fresh_preflight.h"
#include "migration_credentials_nv.h"
#include "migration_channel.h"
#include "migration_dest_image.h"
#include "migration_recovery_execute.h"
#include "migration_restart_command.h"
#include <pthread.h>

#include <sys/wait.h>
#include <dirent.h>
#include <stdarg.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)

static uint64_t rng = 0x243f6a8885a308d3ULL;
static uint64_t
rnd(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (rng);
}

static void
fill(uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (uint8_t)(rnd() | 1);
}

static struct migration_recovery_record
valid_record(uint16_t phase, uint16_t vmid, uint64_t epoch)
{
	struct migration_recovery_record r;
	struct hypertrace_session_record s = { .vmid = vmid, .epoch = epoch,
	    .stop_token = 0x1234 + epoch, .features = HYPERTRACE_SESSION_FEATURES };

	memset(&r, 0, sizeof(r));
	r.phase = phase;
	CHECK(hypertrace_session_record_encode(r.session, sizeof(r.session), &s) == 0);
	r.destination_vmid = (uint16_t)(vmid % (HYPERTRACE_MAX_VMS - 1) + 1);
	r.destination_epoch = epoch + 1;
	fill(r.challenge, 32);
	fill(r.state_digest, 32);
	fill(r.source_certificate_sha256, 32);
	fill(r.destination_certificate_sha256, 32);
	return (r);
}

static bool
same_record(const struct migration_recovery_record *a, const struct migration_recovery_record *b)
{
	return (a->phase == b->phase && a->destination_vmid == b->destination_vmid &&
	    a->destination_epoch == b->destination_epoch &&
	    memcmp(a->session, b->session, sizeof(a->session)) == 0 &&
	    memcmp(a->challenge, b->challenge, 32) == 0 &&
	    memcmp(a->state_digest, b->state_digest, 32) == 0 &&
	    memcmp(a->source_certificate_sha256, b->source_certificate_sha256, 32) == 0 &&
	    memcmp(a->destination_certificate_sha256, b->destination_certificate_sha256, 32) == 0);
}

static void
test_recovery_codec(void)
{
	static const uint16_t phases[] = { MIGRATION_REC_SOURCE_INTENT, MIGRATION_REC_SOURCE_RETIRED,
	    MIGRATION_REC_SOURCE_RELEASED, MIGRATION_REC_SOURCE_CONFIRMED,
	    MIGRATION_REC_DEST_STAGED, MIGRATION_REC_DEST_RELEASED, MIGRATION_REC_DEST_RUNNING };
	uint8_t wire[MIGRATION_RECOVERY_SIZE];
	struct migration_recovery_record r, d;
	int mutations = 0, accepted = 0;

	for (int t = 0; t < 50; t++) {
		r = valid_record(phases[t % nitems(phases)], (uint16_t)(1 + rnd() % 200), 1 + rnd() % 1000);
		CHECK(migration_recovery_encode(&r, wire) == 0);
		CHECK(migration_recovery_decode(wire, sizeof(wire), &d) == 0 && same_record(&r, &d));
		if (t < 4) {
			for (size_t i = 0; i < sizeof(wire); i++) {
				uint8_t saved = wire[i];
				wire[i] ^= 0x01;
				memset(&d, 0xa5, sizeof(d));
				if (migration_recovery_decode(wire, sizeof(wire), &d) == 0) {
					uint8_t again[MIGRATION_RECOVERY_SIZE];
					accepted++;
					CHECK(migration_recovery_encode(&d, again) == 0 &&
					    memcmp(again, wire, sizeof(wire)) == 0);
				} else {
					CHECK(d.phase == 0xa5a5);
				}
				wire[i] = saved;
				mutations++;
			}
		}
	}
	/* Every encoding rule. */
	r = valid_record(MIGRATION_REC_SOURCE_INTENT, 5, 50);
	for (int rule = 0; rule < 13; rule++) {
		struct migration_recovery_record m = r;
		switch (rule) {
		case 0: m.phase = 0; break;
		case 1: m.phase = MIGRATION_REC_SOURCE_CONFIRMED + 1; break;
		case 2: m.phase = MIGRATION_REC_DEST_STAGED - 1; break;
		case 3: m.phase = MIGRATION_REC_DEST_RUNNING + 1; break;
		case 4: m.session[0] ^= 0xff; break;
		case 5: m.destination_vmid = 0; break;
		case 6: m.destination_vmid = HYPERTRACE_MAX_VMS; break;
		case 7: m.destination_epoch = 0; break;
		case 8: m.destination_epoch = 50; break;	/* same as the source */
		case 9: memset(m.challenge, 0, 32); break;
		case 10: memset(m.state_digest, 0, 32); break;
		case 11: memset(m.source_certificate_sha256, 0, 32); break;
		case 12: memset(m.destination_certificate_sha256, 0, 32); break;
		}
		CHECK(migration_recovery_encode(&m, wire) == EINVAL);
	}
	CHECK(migration_recovery_encode(NULL, wire) == EINVAL);
	CHECK(migration_recovery_encode(&r, NULL) == EINVAL);
	CHECK(migration_recovery_encode(&r, wire) == 0);
	CHECK(migration_recovery_decode(NULL, sizeof(wire), &d) == EINVAL);
	CHECK(migration_recovery_decode(wire, sizeof(wire), NULL) == EINVAL);
	CHECK(migration_recovery_decode(wire, sizeof(wire) - 1, &d) == EPROTO);
	/* Names: source and destination journals use distinct stems. */
	{
		char lock[80], name[80], stem[68];
		migration_recovery_names(&r, lock, name, stem);
		CHECK(stem[0] == 's' && strlen(stem) == 66 && strcmp(lock + 66, ".lock") == 0 &&
		    strcmp(name + 66, ".state") == 0);
		r.phase = MIGRATION_REC_DEST_STAGED;
		migration_recovery_names(&r, lock, name, stem);
		CHECK(stem[0] == 'd');
	}
	printf("headers recovery codec: %d mutations (%d canonical accepts)\n", mutations, accepted);
}

static void
test_commit_and_blob(void)
{
	struct migration_commit_binding b, d;
	uint8_t wire[MIGRATION_FRESH_COMMIT_SIZE];
	int mutations = 0, accepted = 0;

	memset(&b, 0, sizeof(b));
	b.destination_vmid = 9;
	b.destination_epoch = 99;
	fill(b.challenge, 32);
	fill(b.state_digest, 32);
	CHECK(migration_commit_encode(&b, wire) == 0);
	CHECK(migration_commit_decode(wire, sizeof(wire), &d) == 0 && memcmp(&b, &d, sizeof(b)) == 0);
	for (size_t i = 0; i < sizeof(wire); i++) {
		for (int v = 0; v < 2; v++) {
			uint8_t saved = wire[i];
			wire[i] = v == 0 ? (uint8_t)(saved ^ 0x80) : 0;
			if (wire[i] == saved) {
				continue;
			}
			memset(&d, 0xa5, sizeof(d));
			if (migration_commit_decode(wire, sizeof(wire), &d) == 0) {
				uint8_t again[MIGRATION_FRESH_COMMIT_SIZE];
				accepted++;
				CHECK(migration_commit_encode(&d, again) == 0 &&
				    memcmp(again, wire, sizeof(wire)) == 0);
			} else {
				CHECK(d.destination_vmid == 0xa5a5);
			}
			wire[i] = saved;
			mutations++;
		}
	}
	for (int rule = 0; rule < 6; rule++) {
		struct migration_commit_binding m = b;
		switch (rule) {
		case 0: m.destination_vmid = 0; break;
		case 1: m.destination_epoch = 0; break;
		case 2: memset(m.challenge, 0, 32); break;
		case 3: memset(m.state_digest, 0, 32); break;
		case 4: CHECK(migration_commit_encode(NULL, wire) == EINVAL); continue;
		case 5: CHECK(migration_commit_encode(&m, NULL) == EINVAL); continue;
		}
		CHECK(migration_commit_encode(&m, wire) == EINVAL);
	}
	CHECK(migration_commit_decode(NULL, sizeof(wire), &d) == EINVAL);
	CHECK(migration_commit_decode(wire, sizeof(wire), NULL) == EINVAL);
	CHECK(migration_commit_decode(wire, sizeof(wire) - 1, &d) == EINVAL);

	/* Blob view: header lengths must exactly cover the payload, plus one
	 * session record when (and only when) fresh tracing was negotiated. */
	{
		uint8_t blob[16 + 10 + 20 + HYPERTRACE_SESSION_RECORD_SIZE];
		struct migration_snapshot_view view;
		struct hypertrace_session_record s = { .vmid = 3, .epoch = 4, .stop_token = 5,
		    .features = HYPERTRACE_SESSION_FEATURES };
		le64enc(blob, 10);
		le64enc(blob + 8, 20);
		CHECK(hypertrace_session_record_encode(blob + 46, HYPERTRACE_SESSION_RECORD_SIZE, &s) == 0);
		CHECK(migration_snapshot_decode(blob, 46, false, &view) == 0 &&
		    view.metadata == blob + 16 && view.metadata_length == 10 &&
		    view.kernel == blob + 26 && view.kernel_length == 20 && view.fresh_record == NULL);
		CHECK(migration_snapshot_decode(blob, sizeof(blob), true, &view) == 0 &&
		    view.fresh_record == blob + 46);
		CHECK(migration_snapshot_decode(blob, sizeof(blob), false, &view) == EBADMSG);
		CHECK(migration_snapshot_decode(blob, 46, true, &view) == EBADMSG);
		CHECK(migration_snapshot_decode(blob, 15, false, &view) == EBADMSG);
		CHECK(migration_snapshot_decode(NULL, 46, false, &view) == EINVAL);
		CHECK(migration_snapshot_decode(blob, 46, false, NULL) == EINVAL);
		le64enc(blob, 31);
		CHECK(migration_snapshot_decode(blob, 46, false, &view) == EBADMSG);
		le64enc(blob, 10);
		le64enc(blob + 8, 21);
		CHECK(migration_snapshot_decode(blob, 46, false, &view) == EBADMSG);
		le64enc(blob + 8, 20);
		blob[46] ^= 0xff;
		CHECK(migration_snapshot_decode(blob, sizeof(blob), true, &view) != 0);
	}
	printf("headers commit binding and blob view: %d mutations (%d canonical accepts)\n",
	    mutations, accepted);
}

/* ---------------------------------------------------- durable journal */
static int
private_dir(const char *template, char *path)
{
	strcpy(path, template);
	CHECK(mkdtemp(path) != NULL && chmod(path, 0700) == 0);
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	CHECK(fd >= 0);
	return (fd);
}

static void
test_journal(void)
{
	char dir[128];
	int d = private_dir("journal.XXXXXX", dir);
	struct migration_recovery_record r = valid_record(MIGRATION_REC_SOURCE_INTENT, 7, 70);
	uint16_t phase = 0;

	/* Missing evidence never becomes a phase. */
	CHECK(migration_recovery_load_at(d, &r, &phase) == ENOENT && phase == 0);
	/* The first source record must be INTENT, a destination STAGED. */
	r.phase = MIGRATION_REC_SOURCE_RETIRED;
	CHECK(migration_recovery_store_at(d, &r) == ESTALE);
	r.phase = MIGRATION_REC_SOURCE_INTENT;
	CHECK(migration_recovery_store_at(d, &r) == 0);
	CHECK(migration_recovery_load_at(d, &r, &phase) == 0 && phase == MIGRATION_REC_SOURCE_INTENT);
	CHECK(migration_recovery_store_at(d, &r) == 0);		/* exact retry */
	r.phase = MIGRATION_REC_SOURCE_RELEASED;			/* skips RETIRED */
	CHECK(migration_recovery_store_at(d, &r) == ESTALE);
	for (uint16_t p = MIGRATION_REC_SOURCE_RETIRED; p <= MIGRATION_REC_SOURCE_CONFIRMED; p++) {
		r.phase = p;
		CHECK(migration_recovery_store_at(d, &r) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == 0 && phase == p);
	}
	r.phase = MIGRATION_REC_SOURCE_RETIRED;			/* backwards */
	CHECK(migration_recovery_store_at(d, &r) == ESTALE);
	/* Any other binding of the same attempt name is refused. */
	{
		struct migration_recovery_record other = r;
		other.state_digest[0] ^= 1;
		CHECK(migration_recovery_load_at(d, &other, &phase) == EPROTO);
	}
	/* The destination journal of the same challenge is separate. */
	{
		struct migration_recovery_record dest = r;
		dest.phase = MIGRATION_REC_DEST_RELEASED;
		CHECK(migration_recovery_store_at(d, &dest) == ESTALE);
		dest.phase = MIGRATION_REC_DEST_STAGED;
		CHECK(migration_recovery_store_at(d, &dest) == 0);
		dest.phase = MIGRATION_REC_DEST_RUNNING;
		CHECK(migration_recovery_store_at(d, &dest) == ESTALE);
		dest.phase = MIGRATION_REC_DEST_RELEASED;
		CHECK(migration_recovery_store_at(d, &dest) == 0);
		CHECK(migration_recovery_load_at(d, &dest, &phase) == 0 &&
		    phase == MIGRATION_REC_DEST_RELEASED);
	}
	/* File policy: corrupted, truncated, linked, group-readable and
	 * symlinked evidence is refused. */
	{
		char lock[80], name[80], stem[68];
		uint8_t wire[MIGRATION_RECOVERY_SIZE];
		migration_recovery_names(&r, lock, name, stem);
		int fd = openat(d, name, O_RDWR);
		CHECK(fd >= 0 && pread(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		wire[100] ^= 1;
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPROTO);
		wire[100] ^= 1;
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		CHECK(ftruncate(fd, sizeof(wire) - 1) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPROTO);
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		uint8_t extra = 0;
		CHECK(pwrite(fd, &extra, 1, sizeof(wire)) == 1);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPROTO);
		CHECK(ftruncate(fd, sizeof(wire)) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == 0);
		CHECK(fchmod(fd, 0640) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPERM);
		CHECK(fchmod(fd, 0600) == 0);
		CHECK(linkat(d, name, d, "second-link", 0) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPERM);
		CHECK(unlinkat(d, "second-link", 0) == 0);
		close(fd);
		CHECK(renameat(d, name, d, "moved") == 0 && symlinkat("moved", d, name) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) != 0);
		CHECK(unlinkat(d, name, 0) == 0 && renameat(d, "moved", d, name) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == 0);
		/* A missing or improper lock file. */
		CHECK(renameat(d, lock, d, "lock-moved") == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == ENOENT);
		CHECK(renameat(d, "lock-moved", d, lock) == 0);
		CHECK(fchmodat(d, lock, 0644, 0) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPERM);
		CHECK(migration_recovery_store_at(d, &r) == EPERM);
		CHECK(fchmodat(d, lock, 0600, 0) == 0);
		/* A journal directory open to others is refused. */
		CHECK(fchmod(d, 0750) == 0);
		CHECK(migration_recovery_load_at(d, &r, &phase) == EPERM);
		CHECK(migration_recovery_store_at(d, &r) == EPERM);
		CHECK(fchmod(d, 0700) == 0);
		/* A regular file is not a directory, and vice versa. */
		CHECK(migration_recovery_file_check(fd = openat(d, lock, O_RDONLY), true) == EPERM);
		close(fd);
		CHECK(migration_recovery_file_check(d, false) == EPERM);
		CHECK(migration_recovery_file_check(-1, false) == EBADF);
		/* Phase argument and invalid expectations. */
		CHECK(migration_recovery_load_at(d, &r, NULL) == EINVAL);
		struct migration_recovery_record bad = r;
		bad.destination_vmid = 0;
		CHECK(migration_recovery_load_at(d, &bad, &phase) == EINVAL);
		CHECK(migration_recovery_store_at(d, &bad) == EINVAL);
	}
	close(d);
	printf("headers durable journal: transitions and file policy\n");
}

static void
test_owner_and_locks(void)
{
	char dir[128];
	int d = private_dir("owner.XXXXXX", dir), l1, l2;
	struct migration_recovery_record r = valid_record(MIGRATION_REC_SOURCE_RETIRED, 11, 110), got;

	CHECK(migration_source_owner_load_at(d, 11, 110, &got) == ENOENT);
	CHECK(migration_source_owner_at(d, &r, false) == ENOENT);
	CHECK(migration_source_owner_at(d, &r, true) == 0);
	CHECK(migration_source_owner_at(d, &r, true) == 0);	/* idempotent */
	CHECK(migration_source_owner_at(d, &r, false) == 0);
	CHECK(migration_source_owner_load_at(d, 11, 110, &got) == 0 &&
	    got.phase == MIGRATION_REC_SOURCE_INTENT &&
	    memcmp(got.challenge, r.challenge, 32) == 0);
	/* The owner record is immutable: a different attempt is refused. */
	{
		struct migration_recovery_record other = r;
		other.challenge[0] ^= 1;
		CHECK(migration_source_owner_at(d, &other, false) == EPROTO);
		CHECK(migration_source_owner_at(d, &other, true) != 0);
	}
	CHECK(migration_source_owner_load_at(d, 11, 111, &got) == ENOENT);
	CHECK(migration_source_owner_load_at(NULL == NULL ? d : d, 0, 110, &got) == EINVAL);
	CHECK(migration_source_owner_load_at(d, HYPERTRACE_MAX_VMS, 110, &got) == EINVAL);
	CHECK(migration_source_owner_load_at(d, 11, 0, &got) == EINVAL);
	CHECK(migration_source_owner_load_at(d, 11, 110, NULL) == EINVAL);
	{
		struct migration_recovery_record bad = r;
		bad.phase = MIGRATION_REC_DEST_STAGED;
		CHECK(migration_source_owner_at(d, &bad, true) == EINVAL);
		CHECK(migration_source_owner_at(d, NULL, true) == EINVAL);
		bad = r;
		bad.destination_epoch = 0;
		CHECK(migration_source_owner_at(d, &bad, true) == EINVAL);
	}
	/* A state file naming another lifetime is stale. */
	{
		char name[80];
		snprintf(name, sizeof(name), "source-owner-%04x-%016jx.state", 11u, (uintmax_t)110);
		int fd = openat(d, name, O_RDWR);
		uint8_t wire[MIGRATION_RECOVERY_SIZE], saved[MIGRATION_RECOVERY_SIZE];
		CHECK(fd >= 0 && pread(fd, saved, sizeof(saved), 0) == (ssize_t)sizeof(saved));
		struct migration_recovery_record moved = valid_record(MIGRATION_REC_SOURCE_INTENT, 12, 110);
		CHECK(migration_recovery_encode(&moved, wire) == 0);
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		CHECK(migration_source_owner_load_at(d, 11, 110, &got) == ESTALE);
		moved.phase = MIGRATION_REC_SOURCE_RETIRED;
		CHECK(migration_recovery_encode(&moved, wire) == 0);
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		CHECK(migration_source_owner_load_at(d, 11, 110, &got) == EPROTO);
		wire[3] ^= 1;
		CHECK(pwrite(fd, wire, sizeof(wire), 0) == (ssize_t)sizeof(wire));
		CHECK(migration_source_owner_load_at(d, 11, 110, &got) == EPROTO);
		CHECK(fchmod(fd, 0644) == 0);
		CHECK(migration_source_owner_load_at(d, 11, 110, &got) == EPERM);
		CHECK(fchmod(fd, 0600) == 0);
		CHECK(pwrite(fd, saved, sizeof(saved), 0) == (ssize_t)sizeof(saved));
		close(fd);
	}
	/* Controller lock: one owner per lifetime. */
	CHECK(migration_source_controller_lock_at(d, 11, 110, &l1) == 0);
	CHECK(migration_source_controller_lock_at(d, 11, 110, &l2) == EBUSY);
	CHECK(migration_source_controller_lock_at(d, 11, 111, &l2) == 0);
	close(l2);
	close(l1);
	CHECK(migration_source_controller_lock_at(d, 11, 110, &l1) == 0);
	close(l1);
	CHECK(migration_source_controller_lock_at(d, 0, 110, &l1) == EINVAL);
	CHECK(migration_source_controller_lock_at(d, 11, 0, &l1) == EINVAL);
	CHECK(migration_source_controller_lock_at(d, 11, 110, NULL) == EINVAL);
	CHECK(fchmod(d, 0755) == 0);
	CHECK(migration_source_controller_lock_at(d, 11, 110, &l1) == EPERM);
	CHECK(migration_source_owner_load_at(d, 11, 110, &got) == EPERM);
	CHECK(migration_source_owner_at(d, &r, true) == EPERM);
	CHECK(fchmod(d, 0700) == 0);
	close(d);
	printf("headers source owner and controller locks: all checks\n");
}

/* Root walk from an anchor: var/db/bhyve/migration. */
static void
test_root_walk(void)
{
	char anchor[128], path[256];
	int a, root = -1, pinned = -1, other;
	uid_t me = geteuid();

	strcpy(anchor, "anchor.XXXXXX");
	CHECK(mkdtemp(anchor) != NULL && chmod(anchor, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var", anchor);
	CHECK(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/db", anchor);
	CHECK(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/db/bhyve", anchor);
	CHECK(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/db/bhyve/migration", anchor);
	CHECK(mkdir(path, 0700) == 0);
	a = open(anchor, O_RDONLY | O_DIRECTORY);
	CHECK(a >= 0);
	CHECK(migration_source_root_open_at(a, me, &root) == 0);
	CHECK(migration_source_root_open_at(a, me, NULL) == EINVAL);
	CHECK(migration_source_root_open_at(a, me + 1, &other) == EPERM);
	CHECK(migration_source_root_open_at(-1, me, &other) == EBADF);
	snprintf(path, sizeof(path), "%s/var/db", anchor);
	CHECK(chmod(path, 0775) == 0);
	CHECK(migration_source_root_open_at(a, me, &other) == EPERM);
	CHECK(chmod(path, 0757) == 0);
	CHECK(migration_source_root_open_at(a, me, &other) == EPERM);
	CHECK(chmod(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/db/bhyve/migration", anchor);
	CHECK(chmod(path, 0750) == 0);
	CHECK(migration_source_root_open_at(a, me, &other) == EPERM);
	CHECK(chmod(path, 0700) == 0);
	{
		char moved[256];
		snprintf(path, sizeof(path), "%s/var/db/bhyve", anchor);
		snprintf(moved, sizeof(moved), "%s/var/db/real", anchor);
		CHECK(rename(path, moved) == 0 && symlink("real", path) == 0);
		CHECK(migration_source_root_open_at(a, me, &other) != 0);
		CHECK(unlink(path) == 0);
		CHECK(migration_source_root_open_at(a, me, &other) == ENOENT);
		CHECK(rename(moved, path) == 0);
	}
	/* Pinning keeps the first root; aliases match it, others do not. */
	CHECK(migration_source_root_pin(NULL, root) == EINVAL);
	pinned = -2;
	CHECK(migration_source_root_pin(&pinned, root) == EINVAL);
	pinned = -1;
	CHECK(migration_source_root_pin(&pinned, root) == 0 && pinned >= 0);
	snprintf(path, sizeof(path), "%s/var/db/bhyve/migration", anchor);
	other = open(path, O_RDONLY | O_DIRECTORY);
	CHECK(migration_source_root_pin(&pinned, other) == 0);
	close(other);
	{
		char second[128];
		int s = private_dir("second.XXXXXX", second);
		CHECK(migration_source_root_pin(&pinned, s) == EXDEV);
		CHECK(fchmod(s, 0755) == 0);
		CHECK(migration_source_root_pin(&pinned, s) == EPERM);
		close(s);
	}
	/* The canonical root of this host does not exist or is not ours:
	 * storage preparation records that failure for later requests. */
	{
		struct migration_source_storage storage = { .directory = -1 };
		int error = migration_source_storage_prepare(&storage);
		CHECK(storage.prepared && error == storage.error && error != 0);
		CHECK(migration_source_storage_prepare(&storage) == error);	/* cached */
		CHECK(migration_source_storage_check(&storage, root) == error);
		struct migration_source_storage unprepared = { .directory = -1 };
		CHECK(migration_source_storage_check(&unprepared, root) == ENXIO);
		CHECK(migration_source_storage_check(NULL, root) == ENXIO);
		struct migration_source_storage ready = { .directory = -1, .prepared = true };
		CHECK(migration_source_storage_check(&ready, root) == 0 && ready.directory >= 0);
		close(ready.directory);
	}
	close(pinned);
	close(root);
	close(a);
	printf("headers root walk and pinning: all checks\n");
}

/* The reconciliation action table. */
static void
test_reconcile(void)
{
	struct migration_recovery_record s = valid_record(MIGRATION_REC_SOURCE_INTENT, 4, 40), d = s;
	enum migration_recovery_action action;
	const uint8_t *sc = s.source_certificate_sha256, *dc = s.destination_certificate_sha256;
	static const struct {
		uint16_t source, dest;
		enum migration_recovery_destination observed;
		int error;
		enum migration_recovery_action action;
	} table[] = {
		{ 1, 16, MIGRATION_REC_VM_PAUSED, 0, MIGRATION_REC_FINISH_RETIREMENT },
		{ 2, 16, MIGRATION_REC_VM_PAUSED, 0, MIGRATION_REC_REISSUE_RELEASE },
		{ 1, 17, MIGRATION_REC_VM_PAUSED, EPROTO, MIGRATION_REC_HOLD },
		{ 1, 16, MIGRATION_REC_VM_RUNNING, EPROTO, MIGRATION_REC_HOLD },
		{ 4, 18, MIGRATION_REC_VM_RUNNING, 0, MIGRATION_REC_COMPLETE },
		{ 4, 17, MIGRATION_REC_VM_RUNNING, EPROTO, MIGRATION_REC_HOLD },
		{ 4, 18, MIGRATION_REC_VM_PAUSED, EPROTO, MIGRATION_REC_HOLD },
		{ 3, 17, MIGRATION_REC_VM_RUNNING, 0, MIGRATION_REC_CONFIRM_RUNNING },
		{ 3, 18, MIGRATION_REC_VM_RUNNING, 0, MIGRATION_REC_CONFIRM_RUNNING },
		{ 3, 16, MIGRATION_REC_VM_RUNNING, EPROTO, MIGRATION_REC_HOLD },
		{ 3, 16, MIGRATION_REC_VM_PAUSED, 0, MIGRATION_REC_REISSUE_RELEASE },
		{ 3, 17, MIGRATION_REC_VM_PAUSED, 0, MIGRATION_REC_REISSUE_RELEASE },
		{ 3, 18, MIGRATION_REC_VM_PAUSED, EPROTO, MIGRATION_REC_HOLD },
		{ 3, 17, MIGRATION_REC_VM_UNAVAILABLE, ENXIO, MIGRATION_REC_HOLD },
		{ 3, 17, 7, EINVAL, MIGRATION_REC_HOLD },
		{ 16, 16, MIGRATION_REC_VM_PAUSED, EPROTO, MIGRATION_REC_HOLD },
		{ 1, 1, MIGRATION_REC_VM_PAUSED, EPROTO, MIGRATION_REC_HOLD },
	};

	for (size_t i = 0; i < nitems(table); i++) {
		s.phase = table[i].source;
		d.phase = table[i].dest;
		action = 99;
		CHECK(migration_recovery_reconcile(&s, &d, sc, dc, table[i].observed, &action) ==
		    table[i].error && action == table[i].action);
	}
	s.phase = 3;
	d.phase = 17;
	{
		struct migration_recovery_record x = d;
		x.state_digest[1] ^= 1;
		CHECK(migration_recovery_reconcile(&s, &x, sc, dc, MIGRATION_REC_VM_RUNNING, &action) ==
		    ESTALE);
		uint8_t wrong[32];
		memcpy(wrong, sc, 32);
		wrong[0] ^= 1;
		CHECK(migration_recovery_reconcile(&s, &d, wrong, dc, MIGRATION_REC_VM_RUNNING,
		    &action) == EACCES);
		CHECK(migration_recovery_reconcile(&s, &d, sc, wrong, MIGRATION_REC_VM_RUNNING,
		    &action) == EACCES);
		x = d;
		x.destination_vmid = 0;
		CHECK(migration_recovery_reconcile(&s, &x, sc, dc, MIGRATION_REC_VM_RUNNING, &action) ==
		    EINVAL);
		CHECK(migration_recovery_reconcile(NULL, &d, sc, dc, MIGRATION_REC_VM_RUNNING,
		    &action) == EINVAL);
		CHECK(migration_recovery_reconcile(&s, NULL, sc, dc, 0, &action) == EINVAL);
		CHECK(migration_recovery_reconcile(&s, &d, NULL, dc, 0, &action) == EINVAL);
		CHECK(migration_recovery_reconcile(&s, &d, sc, NULL, 0, &action) == EINVAL);
		CHECK(migration_recovery_reconcile(&s, &d, sc, dc, 0, NULL) == EINVAL);
	}
	printf("headers reconciliation table: %zu rows\n", nitems(table));
}

static void
test_credentials_and_preflight(void)
{
	uint8_t pin[32];
	char text[65];
	struct migration_tls_credentials cred;
	bool enabled;

	memset(text, 'A', 64);
	text[64] = '\0';
	CHECK(migration_credentials_pin(text, pin) == 0 && pin[0] == 0xaa);
	text[3] = 'g';
	CHECK(migration_credentials_pin(text, pin) == EINVAL);
	memset(text, '0', 64);
	CHECK(migration_credentials_pin(text, pin) == EINVAL);	/* all zero */
	CHECK(migration_credentials_pin("abc", pin) == EINVAL);
	CHECK(migration_credentials_pin(NULL, pin) == EINVAL);
	text[63] = '1';
	CHECK(migration_credentials_pin(text, NULL) == EINVAL);
	CHECK(migration_credentials_config(NULL, NULL, NULL, NULL, &cred, &enabled) == 0 && !enabled);
	CHECK(migration_credentials_config("3", NULL, NULL, NULL, &cred, &enabled) == EINVAL && enabled);
	CHECK(migration_credentials_config("3", "4", "5", text, &cred, &enabled) == 0 &&
	    cred.certificate_fd == 3 && cred.private_key_fd == 4 && cred.trust_fd == 5);
	CHECK(migration_credentials_config("x", "4", "5", text, &cred, &enabled) == EINVAL);
	CHECK(migration_credentials_config("3", "4", "5", "zz", &cred, &enabled) == EINVAL);
	CHECK(migration_credentials_config("3", "4", "5", text, NULL, &enabled) == EINVAL);
	CHECK(migration_credentials_config("3", "4", "5", text, &cred, NULL) == EINVAL);
	/* nvlist form. */
	{
		nvlist_t *n = nvlist_create(0);
		CHECK(migration_credentials_nv(n, &cred, &enabled) == 0 && !enabled);
		nvlist_add_string(n, "tls_peer_sha256", text);
		CHECK(migration_credentials_nv(n, &cred, &enabled) == EINVAL && enabled);
		nvlist_add_descriptor(n, "tls_certificate_fd", 0);
		nvlist_add_descriptor(n, "tls_private_key_fd", 1);
		nvlist_add_descriptor(n, "tls_trust_fd", 2);
		CHECK(migration_credentials_nv(n, &cred, &enabled) == 0 && cred.certificate_fd >= 0);
		nvlist_free_string(n, "tls_peer_sha256");
		nvlist_add_string(n, "tls_peer_sha256", "bad");
		CHECK(migration_credentials_nv(n, &cred, &enabled) == EINVAL);
		CHECK(migration_credentials_nv(NULL, &cred, &enabled) == EINVAL);
		CHECK(migration_credentials_nv(n, NULL, &enabled) == EINVAL);
		CHECK(migration_credentials_nv(n, &cred, NULL) == EINVAL);
		nvlist_destroy(n);
		n = nvlist_create(0);
		nvlist_add_number(n, "tls_trust_fd", 2);	/* wrong type */
		CHECK(migration_credentials_nv(n, &cred, &enabled) == EINVAL && enabled);
		nvlist_destroy(n);
	}
	/* Fresh capability advertisement. */
	{
		struct migration_hello hello;
		struct migration_recovery_record b = valid_record(MIGRATION_REC_SOURCE_INTENT, 2, 20);
		char dir[128];
		int d = private_dir("fresh.XXXXXX", dir);
		memset(&hello, 0, sizeof(hello));
		CHECK(migration_fresh_advertise(&hello, false, d, &b) == 0 &&
		    (hello.capability_flags & MIGRATION_CAP_HYPERTRACE_FRESH) == 0);
		CHECK(migration_fresh_advertise(&hello, true, d, &b) == 0 &&
		    (hello.capability_flags & MIGRATION_CAP_HYPERTRACE_FRESH) != 0);
		memset(&hello, 0, sizeof(hello));
		struct migration_recovery_record z = b;
		memset(z.source_certificate_sha256, 0, 32);
		CHECK(migration_fresh_advertise(&hello, true, d, &z) == EACCES);
		z = b;
		memset(z.destination_certificate_sha256, 0, 32);
		CHECK(migration_fresh_advertise(&hello, true, d, &z) == EACCES);
		CHECK(fchmod(d, 0755) == 0);
		CHECK(migration_fresh_advertise(&hello, true, d, &b) == EPERM);
		CHECK(migration_fresh_advertise(NULL, true, d, &b) == EINVAL);
		CHECK(migration_fresh_advertise(&hello, true, d, NULL) == EINVAL);
		CHECK(hello.capability_flags == 0);
		close(d);
	}
	/* Channels: plaintext init; bindings only from an authenticated
	 * channel; refused TLS credentials leave the channel insecure. */
	{
		struct migration_channel ch;
		struct migration_transport tr;
		uint8_t a[32], bb[32];
		int sp[2];
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
		CHECK(migration_channel_init(&ch, &tr, sp[0], false, NULL, 100) == 0 && !ch.secure);
		CHECK(migration_channel_binding(&ch, true, a, bb) == EACCES);
		CHECK(migration_channel_binding(NULL, true, a, bb) == EINVAL);
		CHECK(migration_channel_binding(&ch, true, NULL, bb) == EINVAL);
		CHECK(migration_channel_binding(&ch, true, a, NULL) == EINVAL);
		migration_channel_cleanup(&ch);
		CHECK(migration_channel_init(NULL, &tr, sp[0], false, NULL, 100) == EINVAL);
		CHECK(migration_channel_init(&ch, NULL, sp[0], false, NULL, 100) == EINVAL);
		struct migration_tls_credentials badcred = { .certificate_fd = -1,
		    .private_key_fd = -1, .trust_fd = -1 };
		memset(badcred.peer_certificate_sha256, 1, 32);
		CHECK(migration_channel_init(&ch, &tr, sp[0], true, &badcred, 100) != 0 && !ch.secure);
		migration_channel_cleanup(&ch);
		close(sp[0]);
		close(sp[1]);
	}
	printf("headers credentials, preflight and channels: all checks\n");
}

/* ------------------------------------------------ I/O fault boundaries */
static bool armed;
static char fault_name[32];
static int fault_occurrence, fault_errno;
static struct { const char *name; int count; } seen[32];

static int
boundary(const char *name)
{
	int i;

	if (!armed)
		return (0);
	for (i = 0; i < 32 && seen[i].name != NULL; i++)
		if (strcmp(seen[i].name, name) == 0)
			break;
	CHECK(i < 32);
	seen[i].name = name;
	if (++seen[i].count == fault_occurrence && strcmp(name, fault_name) == 0)
		return (fault_errno);
	return (0);
}

#define WRAP(ret, fn, params, args, fail)				\
	ret __real_##fn params;						\
	ret __wrap_##fn params						\
	{								\
		int e_ = boundary(#fn);					\
		if (e_ != 0) { errno = e_; return (fail); }		\
		return (__real_##fn args);				\
	}
WRAP(ssize_t, read, (int fd, void *b, size_t n), (fd, b, n), -1)
/* (the recovery-run transport uses __real_read/__real_write directly) */
WRAP(ssize_t, write, (int fd, const void *b, size_t n), (fd, b, n), -1)
WRAP(int, fsync, (int fd), (fd), -1)
WRAP(int, renameat, (int a, const char *b, int c, const char *d), (a, b, c, d), -1)
WRAP(int, unlinkat, (int a, const char *b, int c), (a, b, c), -1)
int __real_fstat(int, struct stat *);
static ino_t root_parents[4];
static bool root_patch;
int
__wrap_fstat(int fd, struct stat *st)
{
	int e = boundary("fstat");
	if (e != 0) {
		errno = e;
		return (-1);
	}
	int r = __real_fstat(fd, st);
	/* The test anchor stands in for "/": its parents are "root-owned". */
	if (r == 0 && root_patch)
		for (int i = 0; i < 4; i++)
			if (st->st_ino == root_parents[i])
				st->st_uid = 0;
	return (r);
}
WRAP(int, fstatat, (int fd, const char *p, struct stat *st, int f), (fd, p, st, f), -1)
WRAP(int, flock, (int fd, int op), (fd, op), -1)
WRAP(void *, malloc, (size_t n), (n), NULL)
int __real_openat(int, const char *, int, ...);
int
__wrap_openat(int fd, const char *path, int flags, ...)
{
	va_list ap;
	int mode, e;

	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	if ((e = boundary("openat")) != 0) {
		errno = e;
		return (-1);
	}
	return (__real_openat(fd, path, flags, mode));
}
int __real_open(const char *, int, ...);
static char anchor_path[256];
int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	int mode;

	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	if (anchor_path[0] != '\0' && strcmp(path, "/") == 0)
		path = anchor_path;
	return (__real_open(path, flags, mode));
}
int __real_close(int);
int
__wrap_close(int fd)
{
	int e = boundary("close");
	int r = __real_close(fd);
	if (e != 0) {
		errno = e;
		return (-1);
	}
	return (r);
}

/* ------------------------------------------------- destination image */
static uint8_t lowmem[8192], highmem[4096], lowmem2[8192], highmem2[4096];

static void *
map_src(void *arg, uint64_t gpa, size_t len)
{
	(void)arg;
	if (gpa + len <= sizeof(lowmem))
		return (lowmem + gpa);
	if (gpa >= 0x100000 && gpa - 0x100000 + len <= sizeof(highmem))
		return (highmem + (gpa - 0x100000));
	return (NULL);
}

static void *
map_dst(void *arg, uint64_t gpa, size_t len)
{
	(void)arg;
	if (gpa + len <= sizeof(lowmem2))
		return (lowmem2 + gpa);
	if (gpa >= 0x100000 && gpa - 0x100000 + len <= sizeof(highmem2))
		return (highmem2 + (gpa - 0x100000));
	return (NULL);
}

static void *
map_none(void *arg, uint64_t gpa, size_t len)
{
	(void)arg; (void)gpa; (void)len;
	return (NULL);
}

static int
tmp_count(int d)
{
	DIR *dir = fdopendir(dup(d));
	struct dirent *e;
	int n = 0;

	rewinddir(dir);
	while ((e = readdir(dir)) != NULL)
		n += strstr(e->d_name, ".tmp.") != NULL;
	closedir(dir);
	return (n);
}

static void
test_dest_image(void)
{
	char dir[128];
	int d = private_dir("image.XXXXXX", dir);
	struct migration_recovery_record r = valid_record(MIGRATION_REC_DEST_STAGED, 21, 210), hr;
	struct migration_dest_geometry g = { 8192, 0x100000, 4096 }, hg;
	uint8_t dev[300], *loaded = NULL;
	size_t loaded_len = 0;
	uint64_t dev_len;
	char stem[67], name[96];
	int mutations = 0, faults = 0;

	fill(lowmem, sizeof(lowmem));
	fill(highmem, sizeof(highmem));
	fill(dev, sizeof(dev));
	SHA256_Data(dev, sizeof(dev), NULL);
	{
		SHA256_CTX h;
		SHA256_Init(&h);
		SHA256_Update(&h, dev, sizeof(dev));
		SHA256_Final(r.state_digest, &h);
	}
	CHECK(migration_dest_image_write_at(d, &r, &g, map_src, NULL, dev, sizeof(dev)) == 0);
	CHECK(migration_dest_image_write_at(d, &r, &g, map_src, NULL, dev, sizeof(dev)) == EEXIST);
	CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, &dev_len) == 0 &&
	    hg.lowmem_length == 8192 && hg.highmem_base == 0x100000 && dev_len == sizeof(dev) &&
	    memcmp(hr.state_digest, r.state_digest, 32) == 0);
	CHECK(migration_dest_image_load_at(d, &r, &g, map_dst, NULL, &loaded, &loaded_len) == 0 &&
	    loaded_len == sizeof(dev) && memcmp(loaded, dev, sizeof(dev)) == 0 &&
	    memcmp(lowmem2, lowmem, sizeof(lowmem)) == 0 &&
	    memcmp(highmem2, highmem, sizeof(highmem)) == 0);
	free(loaded);
	/* Expectation mismatches. */
	{
		struct migration_dest_geometry other = g;
		other.highmem_length = 8192;
		loaded = NULL;
		CHECK(migration_dest_image_load_at(d, &r, &other, map_dst, NULL, &loaded,
		    &loaded_len) == ESTALE && loaded == NULL);
		struct migration_recovery_record x = r;
		x.state_digest[0] ^= 1;
		CHECK(migration_dest_image_load_at(d, &x, &g, map_dst, NULL, &loaded,
		    &loaded_len) == ESTALE);
		CHECK(migration_dest_image_load_at(d, &r, &g, map_none, NULL, &loaded,
		    &loaded_len) == EFAULT);
		uint8_t unknown[32];
		fill(unknown, 32);
		CHECK(migration_dest_image_header_at(d, unknown, &hr, &hg, &dev_len) == ENOENT);
		CHECK(migration_dest_image_load_at(d, NULL, &g, map_dst, NULL, &loaded, &loaded_len) == EINVAL);
		CHECK(migration_dest_image_load_at(d, &r, NULL, map_dst, NULL, &loaded, &loaded_len) == EINVAL);
		CHECK(migration_dest_image_load_at(d, &r, &g, NULL, NULL, &loaded, &loaded_len) == EINVAL);
		CHECK(migration_dest_image_load_at(d, &r, &g, map_dst, NULL, NULL, &loaded_len) == EINVAL);
		CHECK(migration_dest_image_load_at(d, &r, &g, map_dst, NULL, &loaded, NULL) == EINVAL);
		CHECK(migration_dest_image_header_at(d, NULL, &hr, &hg, &dev_len) == EINVAL);
		CHECK(migration_dest_image_header_at(d, r.challenge, NULL, &hg, &dev_len) == EINVAL);
		CHECK(migration_dest_image_header_at(d, r.challenge, &hr, NULL, &dev_len) == EINVAL);
		CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, NULL) == EINVAL);
	}
	/* Every byte of the image file: the loader refuses each change. */
	migration_dest_stem(r.challenge, stem);
	snprintf(name, sizeof(name), "%s.image", stem);
	{
		int fd = openat(d, name, O_RDWR);
		struct stat st;
		CHECK(fd >= 0 && __real_fstat(fd, &st) == 0);
		for (off_t off = 0; off < st.st_size; off += off < 300 ? 1 : 97) {
			uint8_t b, x;
			CHECK(pread(fd, &b, 1, off) == 1);
			x = b ^ 0x10;
			CHECK(pwrite(fd, &x, 1, off) == 1);
			loaded = NULL;
			int r1 = migration_dest_image_load_at(d, &r, &g, map_dst, NULL, &loaded, &loaded_len);
			CHECK(r1 != 0 && loaded == NULL);
			if (off < 256)
				CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, &dev_len) != 0);
			CHECK(pwrite(fd, &b, 1, off) == 1);
			mutations++;
		}
		/* Size changes. */
		CHECK(ftruncate(fd, st.st_size - 1) == 0);
		CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, &dev_len) == EPROTO);
		CHECK(migration_dest_image_load_at(d, &r, &g, map_dst, NULL, &loaded, &loaded_len) != 0);
		uint8_t zero = 0;
		CHECK(ftruncate(fd, st.st_size - 1) == 0);
		CHECK(pwrite(fd, &zero, 1, st.st_size) == 1);	/* one trailing byte */
		CHECK(migration_dest_image_load_at(d, &r, &g, map_dst, NULL, &loaded, &loaded_len) != 0);
		close(fd);
	}
	/* Writer argument and policy refusals. */
	{
		struct migration_recovery_record r2 = valid_record(MIGRATION_REC_DEST_STAGED, 22, 220);
		memcpy(r2.state_digest, r.state_digest, 32);
		struct migration_dest_geometry bad = g;
		CHECK(migration_dest_image_write_at(d, NULL, &g, map_src, NULL, dev, sizeof(dev)) == EINVAL);
		CHECK(migration_dest_image_write_at(d, &r2, &g, NULL, NULL, dev, sizeof(dev)) == EINVAL);
		CHECK(migration_dest_image_write_at(d, &r2, &g, map_src, NULL, NULL, sizeof(dev)) == EINVAL);
		bad.lowmem_length = 100;
		CHECK(migration_dest_image_write_at(d, &r2, &bad, map_src, NULL, dev, sizeof(dev)) == EINVAL);
		CHECK(migration_dest_image_write_at(d, &r2, &g, map_src, NULL, dev, 0) == EINVAL);
		CHECK(migration_dest_image_write_at(d, &r2, &g, map_src, NULL, dev, sizeof(dev) - 1) == ESTALE);
		CHECK(migration_dest_image_write_at(d, &r2, &g, map_none, NULL, dev, sizeof(dev)) == EFAULT &&
		    tmp_count(d) == 0);
		CHECK(fchmod(d, 0750) == 0);
		CHECK(migration_dest_image_write_at(d, &r2, &g, map_src, NULL, dev, sizeof(dev)) == EPERM);
		CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, &dev_len) == EPERM);
		CHECK(fchmod(d, 0700) == 0);
	}
	/* Geometry rules. */
	{
		struct migration_dest_geometry x;
		CHECK(!migration_dest_geometry_valid(NULL));
		x = g; x.lowmem_length = 0; CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.highmem_length = 1; CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.highmem_base = 1; CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.lowmem_length = MIGRATION_DEST_IMAGE_MAX_RAM + 4096;
		CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.highmem_length = MIGRATION_DEST_IMAGE_MAX_RAM;
		CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.highmem_length = 0; CHECK(!migration_dest_geometry_valid(&x));
		x.highmem_base = 0; CHECK(migration_dest_geometry_valid(&x));
		x = g; x.highmem_base = 4096; CHECK(!migration_dest_geometry_valid(&x));
		x = g; x.highmem_base = UINT64_MAX - 4095; CHECK(!migration_dest_geometry_valid(&x));
	}
	/* I/O failures of the writer: never success, never a temporary left
	 * unless removing it failed; then the image can still be written. */
	{
		static const char *names[] = { "openat", "write", "fsync", "close", "renameat",
		    "fstatat", "fstat", "unlinkat" };
		struct migration_recovery_record w = valid_record(MIGRATION_REC_DEST_STAGED, 23, 230);
		memcpy(w.state_digest, r.state_digest, 32);
		for (size_t n = 0; n < nitems(names); n++) {
			for (int occ = 1; occ <= 4; occ++) {
				pid_t child = fork();
				CHECK(child >= 0);
				if (child == 0) {
					memset(seen, 0, sizeof(seen));
					strlcpy(fault_name, names[n], sizeof(fault_name));
					fault_occurrence = occ;
					fault_errno = EIO;
					armed = true;
					int e = migration_dest_image_write_at(d, &w, &g, map_src, NULL,
					    dev, sizeof(dev));
					armed = false;
					int fired = 0;
					for (int i = 0; i < 32 && seen[i].name != NULL; i++)
						if (strcmp(seen[i].name, names[n]) == 0 &&
						    seen[i].count >= occ)
							fired = 1;
					if (fired && strcmp(names[n], "unlinkat") != 0)
						CHECK(e != 0);
					if (strcmp(names[n], "unlinkat") != 0)
						CHECK(tmp_count(d) == 0);
					/* Clean up for the next child. */
					char s2[67], n2[96];
					migration_dest_stem(w.challenge, s2);
					snprintf(n2, sizeof(n2), "%s.image", s2);
					(void)__real_unlinkat(d, n2, 0);
					exit(fired ? 1 : 0);
				}
				int st;
				CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) &&
				    WEXITSTATUS(st) <= 1);
				faults += WEXITSTATUS(st);
			}
		}
		/* EINTR is retried by the loops. */
		memset(seen, 0, sizeof(seen));
		strlcpy(fault_name, "write", sizeof(fault_name));
		fault_occurrence = 2;
		fault_errno = EINTR;
		armed = true;
		CHECK(migration_dest_image_write_at(d, &w, &g, map_src, NULL, dev, sizeof(dev)) == 0);
		memset(seen, 0, sizeof(seen));
		strlcpy(fault_name, "read", sizeof(fault_name));
		fault_occurrence = 3;
		CHECK(migration_dest_image_load_at(d, &w, &g, map_dst, NULL, &loaded, &loaded_len) == 0);
		armed = false;
		free(loaded);
		/* Loader failures. */
		static const char *lnames[] = { "openat", "read", "fstat", "malloc" };
		for (size_t n = 0; n < nitems(lnames); n++) {
			for (int occ = 1; occ <= 3; occ++) {
				memset(seen, 0, sizeof(seen));
				strlcpy(fault_name, lnames[n], sizeof(fault_name));
				fault_occurrence = occ;
				fault_errno = EIO;
				loaded = NULL;
				armed = true;
				int e = migration_dest_image_load_at(d, &w, &g, map_dst, NULL, &loaded,
				    &loaded_len);
				int h = migration_dest_image_header_at(d, w.challenge, &hr, &hg, &dev_len);
				armed = false;
				if (e == 0)
					free(loaded);
				else
					CHECK(loaded == NULL);
				(void)h;
				faults++;
			}
		}
	}
	/* Retirement removes the image; repeating it is harmless. */
	CHECK(migration_dest_image_retire_at(d, r.challenge) == 0);
	CHECK(migration_dest_image_retire_at(d, r.challenge) == 0);
	CHECK(migration_dest_image_header_at(d, r.challenge, &hr, &hg, &dev_len) == ENOENT);
	memset(seen, 0, sizeof(seen));
	strlcpy(fault_name, "fsync", sizeof(fault_name));
	fault_occurrence = 1;
	fault_errno = EIO;
	armed = true;
	CHECK(migration_dest_image_retire_at(d, r.challenge) == EIO);
	armed = false;
	close(d);
	printf("headers destination image: %d mutations refused, %d I/O faults\n", mutations, faults);
}

static int fake_retired_result, fake_destroy_result, destroy_calls;
static int
fake_retired(void *arg, uint16_t vmid, uint64_t epoch)
{
	(void)arg; (void)vmid; (void)epoch;
	return (fake_retired_result);
}

static int
fake_destroy(void *arg, const char *name, uint16_t vmid, uint64_t epoch)
{
	(void)arg; (void)name; (void)vmid; (void)epoch;
	destroy_calls++;
	if (fake_destroy_result == 0)
		fake_retired_result = 0;
	return (fake_destroy_result);
}

/* Successor records and reconstruction admission. */
static void
test_successor(void)
{
	char dir[128];
	int d = private_dir("succ.XXXXXX", dir), controller;
	struct migration_recovery_record r = valid_record(MIGRATION_REC_DEST_STAGED, 31, 310);
	struct migration_dest_geometry g = { 8192, 0x100000, 4096 };
	struct migration_dest_reconstruct_ops ops = { fake_retired, fake_destroy };
	struct migration_dest_reconstruction out;
	struct migration_dest_successor s = { 1, 5, 50, 6, 60 }, t;
	uint8_t digest[32], wire[MIGRATION_DEST_SUCCESSOR_SIZE], dev[64];
	int accepted = 0;

	fill(dev, sizeof(dev));
	{
		SHA256_CTX h;
		SHA256_Init(&h);
		SHA256_Update(&h, dev, sizeof(dev));
		SHA256_Final(r.state_digest, &h);
	}
	CHECK(migration_dest_binding_digest(&r, digest) == 0);
	CHECK(migration_dest_successor_encode(digest, &s, wire) == 0);
	CHECK(migration_dest_successor_decode(wire, sizeof(wire), digest, &t) == 0 &&
	    t.generation == s.generation && t.previous_vmid == s.previous_vmid &&
	    t.previous_epoch == s.previous_epoch && t.current_vmid == s.current_vmid &&
	    t.current_epoch == s.current_epoch);
	for (size_t i = 0; i < sizeof(wire); i++) {
		uint8_t saved = wire[i];
		wire[i] ^= 0x04;
		memset(&t, 0xa5, sizeof(t));
		int e = migration_dest_successor_decode(wire, sizeof(wire), digest, &t);
		if (e == 0) {
			uint8_t again[MIGRATION_DEST_SUCCESSOR_SIZE];
			accepted++;
			CHECK(migration_dest_successor_encode(wire + 8, &t, again) == 0 &&
			    memcmp(again, wire, sizeof(wire)) == 0);
		} else {
			CHECK(t.generation == 0xa5a5a5a5U);
		}
		wire[i] = saved;
	}
	{
		struct migration_dest_successor x;
		x = s; x.generation = 0; CHECK(migration_dest_successor_encode(digest, &x, wire) == EINVAL);
		x = s; x.previous_vmid = 0; CHECK(migration_dest_successor_encode(digest, &x, wire) == EINVAL);
		x = s; x.current_epoch = 0; CHECK(migration_dest_successor_encode(digest, &x, wire) == EINVAL);
		x = s; x.current_vmid = 5; x.current_epoch = 50;
		CHECK(migration_dest_successor_encode(digest, &x, wire) == EINVAL);
		CHECK(migration_dest_successor_encode(digest, &s, wire) == 0);
		uint8_t other[32];
		fill(other, 32);
		CHECK(migration_dest_successor_decode(wire, sizeof(wire), other, &t) == ESTALE);
		CHECK(migration_dest_successor_decode(wire, sizeof(wire) - 1, digest, &t) == EPROTO);
		CHECK(migration_dest_successor_decode(NULL, sizeof(wire), digest, &t) == EINVAL);
	}
	/* Admission: no controller lock yet, then each refusal. */
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == ENOENT);
	CHECK(migration_dest_controller_lock_at(d, r.challenge, true, &controller) == 0);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == EBUSY);
	close(controller);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == ENOENT);
	CHECK(migration_dest_image_write_at(d, &r, &g, map_src, NULL, dev, sizeof(dev)) == 0);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == ENOENT);
	CHECK(migration_recovery_store_at(d, &r) == 0);
	/* The new context may not be any bound lifetime. */
	{
		struct hypertrace_session_record src;
		CHECK(hypertrace_session_record_decode(r.session, sizeof(r.session), &src) == 0);
		CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", r.destination_vmid,
		    r.destination_epoch, &ops, NULL, &out) == EBUSY);
		CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", src.vmid, src.epoch,
		    &ops, NULL, &out) == EBUSY);
	}
	/* The previous incarnation is still live: named destruction is asked
	 * for, and without a name the admission waits. */
	fake_retired_result = EBUSY;
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, NULL, 40, 400, &ops, NULL, &out) == EBUSY);
	fake_destroy_result = EPERM;
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == EPERM &&
	    destroy_calls == 1);
	fake_destroy_result = 0;
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 40, 400, &ops, NULL, &out) == 0 &&
	    destroy_calls == 2 && out.successor.generation == 1 && out.successor.current_vmid == 40 &&
	    out.successor.previous_vmid == r.destination_vmid);
	close(out.controller);
	/* A second successor retires the first. */
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 41, 410, &ops, NULL, &out) == 0 &&
	    out.successor.generation == 2 && out.successor.previous_vmid == 40 &&
	    out.successor.previous_epoch == 400);
	close(out.controller);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 41, 410, &ops, NULL, &out) == EBUSY);
	/* Invalid arguments. */
	CHECK(migration_dest_reconstruct_begin(d, NULL, "vm", 42, 420, &ops, NULL, &out) == EINVAL);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "", 42, 420, &ops, NULL, &out) == EINVAL);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 0, 420, &ops, NULL, &out) == EINVAL);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 42, 420, NULL, NULL, &out) == EINVAL);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 42, 420, &ops, NULL, NULL) == EINVAL);
	/* After RELEASED the attempt is not recoverable. */
	r.phase = MIGRATION_REC_DEST_RELEASED;
	CHECK(migration_recovery_store_at(d, &r) == 0);
	CHECK(migration_dest_reconstruct_begin(d, r.challenge, "vm", 42, 420, &ops, NULL, &out) ==
	    ENOTRECOVERABLE);
	/* Corrupt successor evidence. */
	{
		char stem[67], name[96];
		migration_dest_stem(r.challenge, stem);
		snprintf(name, sizeof(name), "%s.successor", stem);
		int fd = openat(d, name, O_RDWR);
		uint8_t b;
		CHECK(fd >= 0 && pread(fd, &b, 1, 50) == 1);
		b ^= 1;
		CHECK(pwrite(fd, &b, 1, 50) == 1);
		struct migration_dest_successor x;
		CHECK(migration_dest_successor_load_at(d, r.challenge, digest, &x) == EPROTO);
		CHECK(fchmod(fd, 0644) == 0);
		CHECK(migration_dest_successor_load_at(d, r.challenge, digest, &x) == EPERM);
		close(fd);
	}
	/* Controller lock rules. */
	{
		uint8_t zero[32] = { 0 };
		CHECK(migration_dest_controller_lock_at(d, zero, true, &controller) == EINVAL);
		CHECK(migration_dest_controller_lock_at(d, NULL, true, &controller) == EINVAL);
		CHECK(migration_dest_controller_lock_at(d, r.challenge, true, NULL) == EINVAL);
		CHECK(migration_dest_controller_lock_at(d, r.challenge, true, &controller) == EEXIST);
	}
	/* Parsing the operator form of a challenge. */
	{
		char text[65];
		uint8_t c[32];
		for (int i = 0; i < 32; i++)
			snprintf(text + 2 * i, 3, "%02x", r.challenge[i]);
		CHECK(migration_dest_challenge_parse(text, c) == 0 && memcmp(c, r.challenge, 32) == 0);
		text[5] = 'A';
		CHECK(migration_dest_challenge_parse(text, c) == EINVAL);
		CHECK(migration_dest_challenge_parse("00", c) == EINVAL);
		CHECK(migration_dest_challenge_parse(NULL, c) == EINVAL);
		memset(text, '0', 64);
		text[64] = '\0';
		CHECK(migration_dest_challenge_parse(text, c) != 0);
	}
	close(d);
	printf("headers successor records and reconstruction admission: %d canonical accepts\n",
	    accepted);
}

/* ------------------------------------------ authenticated recovery runs */
struct side {
	struct migration_channel channel;
	struct migration_transport xp;
	int fd, sends, recvs, fail_send_at, fail_recv_at;
	bool corrupt_command;
};
static struct side sides[2];	/* 0 source, 1 destination */

static struct side *
side_of(void *cookie)
{
	for (int i = 0; i < 2; i++)
		if (cookie == &sides[i].channel.tls)
			return (&sides[i]);
	abort();
}

static int
xp_send(void *cookie, const void *buf, size_t len)
{
	struct side *s = side_of(cookie);

	if (++s->sends == s->fail_send_at)
		return (EPIPE);
	if (s->corrupt_command && len == 40) {
		uint8_t copy[40];
		memcpy(copy, buf, 40);
		copy[5] ^= 3;
		return (__real_write(s->fd, copy, 40) == 40 ? 0 : EIO);
	}
	return (__real_write(s->fd, buf, len) == (ssize_t)len ? 0 : EIO);
}

static int
xp_recv(void *cookie, void *buf, size_t len)
{
	struct side *s = side_of(cookie);
	size_t got = 0;

	if (++s->recvs == s->fail_recv_at)
		return (ETIMEDOUT);
	while (got < len) {
		ssize_t n = __real_read(s->fd, (char *)buf + got, len - got);
		if (n <= 0)
			return (n == 0 ? ECONNRESET : errno);
		got += (size_t)n;
	}
	return (0);
}

static uint8_t pin_src[32], pin_dst[32];

static void
sides_init(void)
{
	int sp[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	for (int i = 0; i < 2; i++) {
		memset(&sides[i], 0, sizeof(sides[i]));
		sides[i].fd = sp[i];
		sides[i].channel.secure = true;
		memcpy(sides[i].channel.tls.local_certificate_sha256, i == 0 ? pin_src : pin_dst, 32);
		memcpy(sides[i].channel.tls.peer_certificate_sha256, i == 0 ? pin_dst : pin_src, 32);
		sides[i].xp.xp_send = xp_send;
		sides[i].xp.xp_recv = xp_recv;
		sides[i].xp.xp_cookie = &sides[i].channel.tls;
	}
}

static void
sides_close(void)
{
	close(sides[0].fd);
	close(sides[1].fd);
}

static enum migration_recovery_destination observed_now;
static int observe_error, resume_error, resume_calls, observe_after_resume;
static int
op_observe(void *arg, enum migration_recovery_destination *o)
{
	(void)arg;
	*o = observed_now;
	return (observe_error);
}

static int
op_resume(void *arg)
{
	(void)arg;
	resume_calls++;
	if (resume_error != 0)
		return (resume_error);
	observed_now = observe_after_resume;
	return (0);
}

struct run_args {
	int dirfd;
	struct migration_recovery_record record;
	struct migration_recovery_run_state *state;
	int result;
};

static void *
dest_thread(void *p)
{
	struct run_args *a = p;
	static const struct migration_recovery_run_ops ops = { op_observe, op_resume };

	a->result = migration_recovery_destination_run(&sides[1].channel, &sides[1].xp, a->dirfd,
	    &a->record, &ops, NULL, a->state);
	shutdown(sides[1].fd, SHUT_RDWR);
	return (NULL);
}

static int
run_pair(int sd, int dd, struct migration_recovery_record *src, struct migration_recovery_record *dst,
    struct migration_recovery_run_state *state, int *dest_result)
{
	pthread_t t;
	struct run_args a = { dd, *dst, state, -1 };
	int r;

	CHECK(pthread_create(&t, NULL, dest_thread, &a) == 0);
	r = migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, src);
	shutdown(sides[0].fd, SHUT_RDWR);
	CHECK(pthread_join(t, NULL) == 0);
	*dest_result = a.result;
	return (r);
}

static void
test_recovery_runs(void)
{
	char sdir[128], ddir[128];
	int sd = private_dir("rsrc.XXXXXX", sdir), dd = private_dir("rdst.XXXXXX", ddir);
	struct migration_recovery_record src = valid_record(MIGRATION_REC_SOURCE_INTENT, 51, 510), dst;
	struct migration_recovery_run_state state = { 0 };
	uint16_t phase;
	int dr, scenarios = 0;

	memcpy(pin_src, src.source_certificate_sha256, 32);
	memcpy(pin_dst, src.destination_certificate_sha256, 32);
	/* Durable facts: source INTENT then RETIRED; destination STAGED. */
	CHECK(migration_recovery_store_at(sd, &src) == 0);
	dst = src;
	dst.phase = MIGRATION_REC_DEST_STAGED;
	CHECK(migration_recovery_store_at(dd, &dst) == 0);
	/* INTENT alone is not enough to reissue RELEASE. */
	sides_init();
	CHECK(migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, &src) == EBUSY);
	sides_close();
	src.phase = MIGRATION_REC_SOURCE_RETIRED;
	CHECK(migration_recovery_store_at(sd, &src) == 0);

	/* A paused destination: RELEASED, resume, RUNNING, ACK; the source
	 * records CONFIRMED. */
	observed_now = MIGRATION_REC_VM_PAUSED;
	observe_after_resume = MIGRATION_REC_VM_RUNNING;
	resume_calls = 0;
	sides_init();
	CHECK(run_pair(sd, dd, &src, &dst, &state, &dr) == 0 && dr == 0);
	CHECK(state.ack_sent && !state.resume_uncertain && resume_calls == 1);
	CHECK(migration_recovery_load_at(sd, &src, &phase) == 0 &&
	    phase == MIGRATION_REC_SOURCE_CONFIRMED);
	CHECK(migration_recovery_load_at(dd, &dst, &phase) == 0 && phase == MIGRATION_REC_DEST_RUNNING);
	sides_close();
	scenarios++;
	/* Repeating after completion: COMPLETE, no second resume. */
	sides_init();
	CHECK(run_pair(sd, dd, &src, &dst, &state, &dr) == 0 && dr == 0 && resume_calls == 1);
	sides_close();
	scenarios++;

	/* Transport failures on either side at every exchange step. */
	for (int sidex = 0; sidex < 2; sidex++) {
		for (int step = 1; step <= 3; step++) {
			for (int dir = 0; dir < 2; dir++) {
				sides_init();
				if (dir == 0)
					sides[sidex].fail_send_at = step;
				else
					sides[sidex].fail_recv_at = step;
				int sr = run_pair(sd, dd, &src, &dst, &state, &dr);
				bool fired = dir == 0 ? sides[sidex].sends >= step :
				    sides[sidex].recvs >= step;
				if (fired) {
					CHECK(sr != 0 || dr != 0);
					scenarios++;
				} else {
					CHECK(sr == 0 && dr == 0);
				}
				sides_close();
			}
		}
	}
	/* A corrupted command or ACK is a protocol error. */
	for (int sidex = 0; sidex < 2; sidex++) {
		sides_init();
		sides[sidex].corrupt_command = true;
		int sr = run_pair(sd, dd, &src, &dst, &state, &dr);
		CHECK(sidex == 0 ? dr == EPROTO : sr == EPROTO);
		sides_close();
		scenarios++;
	}
	/* Destination-side observation and resume outcomes, from a fresh
	 * attempt each time. */
	for (int variant = 0; variant < 5; variant++) {
		char s2[128], d2[128];
		int s2fd = private_dir("rsrc2.XXXXXX", s2), d2fd = private_dir("rdst2.XXXXXX", d2);
		struct migration_recovery_record a = valid_record(MIGRATION_REC_SOURCE_INTENT,
		    (uint16_t)(60 + variant), 600), b;
		memcpy(pin_src, a.source_certificate_sha256, 32);
		memcpy(pin_dst, a.destination_certificate_sha256, 32);
		CHECK(migration_recovery_store_at(s2fd, &a) == 0);
		a.phase = MIGRATION_REC_SOURCE_RETIRED;
		CHECK(migration_recovery_store_at(s2fd, &a) == 0);
		b = a;
		b.phase = MIGRATION_REC_DEST_STAGED;
		CHECK(migration_recovery_store_at(d2fd, &b) == 0);
		struct migration_recovery_run_state st = { 0 };
		observed_now = MIGRATION_REC_VM_PAUSED;
		observe_after_resume = MIGRATION_REC_VM_RUNNING;
		observe_error = resume_error = 0;
		switch (variant) {
		case 0: resume_error = EIO; break;
		case 1: observe_after_resume = MIGRATION_REC_VM_PAUSED; break;
		case 2: observe_error = ENXIO; break;
		case 3: observed_now = MIGRATION_REC_VM_UNAVAILABLE; break;
		case 4: observed_now = MIGRATION_REC_VM_RUNNING; break;
		}
		sides_init();
		int sr = run_pair(s2fd, d2fd, &a, &b, &st, &dr);
		switch (variant) {
		case 0:
			CHECK(dr == EIO && st.resume_uncertain && !st.ack_sent && sr != 0);
			/* Resume uncertainty quarantines this owner. */
			sides_close();
			sides_init();
			CHECK(migration_recovery_destination_run(&sides[1].channel, &sides[1].xp, d2fd, &b,
			    &(struct migration_recovery_run_ops){ op_observe, op_resume }, NULL, &st) ==
			    EBUSY);
			break;
		case 1: CHECK(dr == EBUSY && st.resume_uncertain); break;
		case 2: CHECK(dr == ENXIO); break;
		case 3: CHECK(dr == ENXIO); break;
		case 4: CHECK(dr == EPROTO); break;	/* RUNNING but still STAGED */
		}
		resume_error = observe_error = 0;
		sides_close();
		close(s2fd);
		close(d2fd);
		scenarios++;
	}
	memcpy(pin_src, src.source_certificate_sha256, 32);
	memcpy(pin_dst, src.destination_certificate_sha256, 32);
	/* Channel identity checks before any I/O. */
	sides_init();
	sides[0].channel.secure = false;
	CHECK(migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, &src) == EACCES);
	sides[0].channel.secure = true;
	sides[0].xp.xp_cookie = &sides[1].channel.tls;
	CHECK(migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, &src) == EACCES);
	sides[0].xp.xp_cookie = &sides[0].channel.tls;
	sides[0].channel.tls.peer_certificate_sha256[0] ^= 1;
	CHECK(migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, &src) == EACCES);
	sides[0].channel.tls.peer_certificate_sha256[0] ^= 1;
	CHECK(migration_recovery_source_run(NULL, &sides[0].xp, sd, &src) == EINVAL);
	CHECK(migration_recovery_source_run(&sides[0].channel, NULL, sd, &src) == EINVAL);
	CHECK(migration_recovery_source_run(&sides[0].channel, &sides[0].xp, sd, NULL) == EINVAL);
	{
		struct migration_recovery_record l, p;
		struct migration_transport broken = sides[0].xp;
		broken.xp_send = NULL;
		CHECK(migration_recovery_exchange(&sides[0].channel, &broken, sd, true, &src, &l, &p) ==
		    EINVAL);
		CHECK(migration_recovery_exchange(&sides[0].channel, &sides[0].xp, sd, true, &src, &l,
		    &l) == EINVAL);
		struct migration_recovery_record wrongrole = src;
		wrongrole.phase = MIGRATION_REC_DEST_STAGED;
		CHECK(migration_recovery_exchange(&sides[0].channel, &sides[0].xp, sd, true, &wrongrole,
		    &l, &p) == EPROTO);
		CHECK(migration_recovery_exchange(&sides[1].channel, &sides[1].xp, dd, false, &src,
		    &l, &p) == EPROTO);
		struct migration_recovery_run_state st = { 0 };
		CHECK(migration_recovery_destination_run(&sides[1].channel, &sides[1].xp, dd, &dst,
		    NULL, NULL, &st) == EINVAL);
		CHECK(migration_recovery_destination_run(&sides[1].channel, &sides[1].xp, dd, &dst,
		    &(struct migration_recovery_run_ops){ op_observe, op_resume }, NULL, NULL) == EINVAL);
	}
	sides_close();
	/* Peer message decoding rules. */
	{
		uint8_t wire[MIGRATION_RECOVERY_EXCHANGE_SIZE];
		struct migration_recovery_record peer, expected = src;
		expected.phase = MIGRATION_REC_SOURCE_RELEASED;
		memset(wire, 0, sizeof(wire));
		memcpy(wire, "HMX1", 4);
		wire[4] = 1;
		wire[5] = 1;
		CHECK(migration_recovery_encode(&expected, wire + 8) == 0);
		CHECK(migration_recovery_peer_decode(wire, sizeof(wire), &expected, true, &peer) == 0 &&
		    peer.phase == MIGRATION_REC_SOURCE_RELEASED);
		CHECK(migration_recovery_peer_decode(wire, sizeof(wire), &expected, false, &peer) == EPROTO);
		for (int f = 0; f < 6; f++) {
			uint8_t m[sizeof(wire)];
			memcpy(m, wire, sizeof(m));
			switch (f) {
			case 0: m[0] = 'X'; break;
			case 1: m[4] = 2; break;
			case 2: m[6] = 1; break;
			case 3: m[7] = 1; break;
			case 4: le16enc(m + 8 + 6, MIGRATION_REC_DEST_STAGED); break;
			case 5: m[8 + 70] ^= 1; break;
			}
			CHECK(migration_recovery_peer_decode(m, sizeof(m), &expected, true, &peer) ==
			    (f == 5 ? ESTALE : EPROTO));
		}
		CHECK(migration_recovery_peer_decode(wire, sizeof(wire) - 1, &expected, true, &peer) == EPROTO);
		CHECK(migration_recovery_peer_decode(NULL, sizeof(wire), &expected, true, &peer) == EINVAL);
		struct migration_recovery_record invalid = expected;
		invalid.destination_vmid = 0;
		CHECK(migration_recovery_peer_decode(wire, sizeof(wire), &invalid, true, &peer) == EINVAL);
	}
	close(sd);
	close(dd);
	printf("headers authenticated recovery runs: %d scenarios\n", scenarios);
}

/* ------------------------------------------------ operator restart */
static int query_opens, query_closes, query_error, recover_calls, recover_result;
static int recover_fd, recover_dir;
static uint16_t recover_vmid;
static uint64_t recover_epoch;
static const char *recover_name;

int
hypertrace_session_recovery_open(void)
{
	query_opens++;
	return (query_error);
}

void
hypertrace_session_recovery_close(void)
{
	query_closes++;
}

int
__wrap_migration_prod_source_recover_restart_named(int fd, int dir, uint16_t vmid,
    uint64_t epoch, const struct migration_tls_credentials *cred, const char *name)
{
	recover_calls++;
	recover_fd = fd;
	recover_dir = dir;
	recover_vmid = vmid;
	recover_epoch = epoch;
	recover_name = name;
	CHECK(cred != NULL && cred->certificate_fd >= 0);
	return (recover_result);
}

static void
make_root(void)
{
	char path[300];
	struct stat st;

	strcpy(anchor_path, "root.XXXXXX");
	CHECK(mkdtemp(anchor_path) != NULL && chmod(anchor_path, 0755) == 0);
	{
		char abs[PATH_MAX];
		CHECK(realpath(anchor_path, abs) != NULL);
		strlcpy(anchor_path, abs, sizeof(anchor_path));
	}
	CHECK(stat(anchor_path, &st) == 0);
	root_parents[0] = st.st_ino;
	const char *parts[] = { "var", "var/db", "var/db/bhyve" };
	for (int i = 0; i < 3; i++) {
		snprintf(path, sizeof(path), "%s/%s", anchor_path, parts[i]);
		CHECK(mkdir(path, 0755) == 0 && stat(path, &st) == 0);
		root_parents[i + 1] = st.st_ino;
	}
	snprintf(path, sizeof(path), "%s/var/db/bhyve/migration", anchor_path);
	CHECK(mkdir(path, 0700) == 0);
	root_patch = true;
}

static void
test_restart_command(void)
{
	char text[3][32], pin[65];
	int sock[2], dsock, regular, creds[3], root, journal;
	struct migration_recovery_record r = valid_record(MIGRATION_REC_SOURCE_INTENT, 71, 710);

	make_root();
	CHECK(migration_source_canonical_root_open(&root) == 0);
	/* Storage prepared from the canonical root accepts an alias of it and
	 * refuses a different private directory. */
	{
		struct migration_source_storage storage = { .directory = -1 };
		int other;
		CHECK(migration_source_storage_prepare(&storage) == 0 && storage.directory >= 0);
		CHECK(migration_source_storage_check(&storage, root) == 0);
		char second[128];
		other = private_dir("notroot.XXXXXX", second);
		CHECK(migration_source_storage_check(&storage, other) == EXDEV);
		close(other);
		close(storage.directory);
	}
	journal = root;
	CHECK(migration_source_owner_at(journal, &r, true) == 0);
	CHECK(migration_recovery_store_at(journal, &r) == 0);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == 0);
	dsock = socket(AF_UNIX, SOCK_DGRAM, 0);
	regular = openat(journal, "regular", O_RDWR | O_CREAT, 0600);
	for (int i = 0; i < 3; i++)
		creds[i] = openat(journal, i == 0 ? "c0" : i == 1 ? "c1" : "c2", O_RDWR | O_CREAT, 0600);
	for (int i = 0; i < 64; i++)
		pin[i] = "0123456789abcdef"[(r.destination_certificate_sha256[i / 2] >> (i % 2 ? 0 : 4)) & 15];
	pin[64] = '\0';
	snprintf(text[0], sizeof(text[0]), "%d", sock[0]);
	char vmid[8] = "71", epoch[16] = "710", c0[8], c1[8], c2[8];
	snprintf(c0, sizeof(c0), "%d", creds[0]);
	snprintf(c1, sizeof(c1), "%d", creds[1]);
	snprintf(c2, sizeof(c2), "%d", creds[2]);
	const char *v[7] = { text[0], vmid, epoch, c0, c1, c2, pin };

	/* INTENT: the session query channel brackets recovery. */
	recover_result = 0;
	CHECK(migration_restart_command_named(v, false, "guest") == 0 && recover_calls == 1 &&
	    query_opens == 1 && query_closes == 1 && recover_fd == sock[0] && recover_vmid == 71 &&
	    recover_epoch == 710 && strcmp(recover_name, "guest") == 0);
	for (int i = 0; i < 3; i++)
		CHECK((fcntl(creds[i], F_GETFD) & FD_CLOEXEC) != 0);
	CHECK((fcntl(sock[0], F_GETFD) & FD_CLOEXEC) != 0);
	recover_result = EPIPE;
	CHECK(migration_restart_command_named(v, false, NULL) == EPIPE && recover_name == NULL && query_closes == 2);
	query_error = ENXIO;
	CHECK(migration_restart_command_named(v, false, NULL) == ENXIO && recover_calls == 2 && query_closes == 2);
	query_error = 0;
	/* RETIRED: no query channel. */
	r.phase = MIGRATION_REC_SOURCE_RETIRED;
	CHECK(migration_recovery_store_at(journal, &r) == 0);
	recover_result = 0;
	CHECK(migration_restart_command_named(v, false, NULL) == 0 && query_opens == 3 && recover_calls == 3);
	/* Argument refusals. */
	CHECK(migration_restart_command_named(v, true, NULL) == EINVAL);
	{
		const char *bad[][7] = {
			{ "x", vmid, epoch, c0, c1, c2, pin },
			{ text[0], "0", epoch, c0, c1, c2, pin },
			{ text[0], "65535", epoch, c0, c1, c2, pin },
			{ text[0], vmid, "0", c0, c1, c2, pin },
			{ text[0], vmid, "18446744073709551616", c0, c1, c2, pin },
			{ text[0], vmid, epoch, NULL, NULL, NULL, NULL },
			{ text[0], vmid, epoch, c0, NULL, c2, pin },
			{ text[0], vmid, epoch, c0, c1, c2, "bad" },
		};
		for (size_t i = 0; i < nitems(bad); i++)
			CHECK(migration_restart_command_named(bad[i], false, NULL) == EINVAL);
		uint64_t n;
		CHECK(migration_restart_number("", 10, &n) == EINVAL);
		CHECK(migration_restart_number(NULL, 10, &n) == EINVAL);
		CHECK(migration_restart_number("11", 10, &n) == EINVAL);
		CHECK(migration_restart_number("9", 8, &n) == EINVAL);
		CHECK(migration_restart_number("10", 10, &n) == 0 && n == 10);
	}
	/* Descriptor checks. */
	{
		char dtext[16], rtext[16], ctext[16];
		snprintf(dtext, sizeof(dtext), "%d", dsock);
		snprintf(rtext, sizeof(rtext), "%d", regular);
		snprintf(ctext, sizeof(ctext), "%d", 1000);
		const char *dv[7] = { dtext, vmid, epoch, c0, c1, c2, pin };
		CHECK(migration_restart_command_named(dv, false, NULL) == EINVAL);
		const char *rv[7] = { rtext, vmid, epoch, c0, c1, c2, pin };
		CHECK(migration_restart_command_named(rv, false, NULL) == ENOTSOCK);
		const char *cv[7] = { text[0], vmid, epoch, ctext, c1, c2, pin };
		CHECK(migration_restart_command_named(cv, false, NULL) == EBADF);
	}
	/* Missing owner and an untrusted root. */
	{
		const char *ov[7] = { text[0], "72", epoch, c0, c1, c2, pin };
		CHECK(migration_restart_command_named(ov, false, NULL) == ENOENT);
		root_patch = false;
		CHECK(migration_restart_command_named(v, false, NULL) == EPERM);
		struct migration_source_storage untrusted = { .directory = -1 };
		CHECK(migration_source_storage_prepare(&untrusted) == EPERM &&
		    migration_source_storage_check(&untrusted, root) == EPERM);
		root_patch = true;
		char saved[256];
		strlcpy(saved, anchor_path, sizeof(saved));
		strlcpy(anchor_path, "/nonexistent-anchor", sizeof(anchor_path));
		CHECK(migration_restart_command_named(v, false, NULL) == ENOENT);
		strlcpy(anchor_path, saved, sizeof(anchor_path));
	}
	close(sock[0]);
	close(sock[1]);
	close(dsock);
	close(regular);
	for (int i = 0; i < 3; i++)
		close(creds[i]);
	close(root);
	anchor_path[0] = '\0';
	root_patch = false;
	printf("headers operator restart command: all checks\n");
}

int
main(void)
{
	signal(SIGPIPE, SIG_IGN);
	test_recovery_codec();
	test_commit_and_blob();
	test_journal();
	test_owner_and_locks();
	test_root_walk();
	test_reconcile();
	test_credentials_and_preflight();
	test_dest_image();
	test_successor();
	test_recovery_runs();
	test_restart_command();
	printf("PASS: migration header helpers\n");
	return (0);
}

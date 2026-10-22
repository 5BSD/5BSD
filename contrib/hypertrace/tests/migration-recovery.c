/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <sys/wait.h>
#include "migration_reconcile.h"

static void
reconciliation_cases(const struct migration_recovery_record *binding)
{
	struct migration_recovery_record s = *binding, d = *binding;
	enum migration_recovery_action action;
	/* Independent expected matrix: rows are source INTENT..CONFIRMED,
	 * columns destination STAGED/RELEASED/RUNNING, paused then running. */
	const int plans[4][3][2] = {
	    {{MIGRATION_REC_FINISH_RETIREMENT, -1}, {-1, -1}, {-1, -1}},
	    {{MIGRATION_REC_REISSUE_RELEASE, -1}, {-1, -1}, {-1, -1}},
	    {{MIGRATION_REC_REISSUE_RELEASE, -1},
	     {MIGRATION_REC_REISSUE_RELEASE, MIGRATION_REC_CONFIRM_RUNNING},
	     {-1, MIGRATION_REC_CONFIRM_RUNNING}},
	    {{-1, -1}, {-1, -1}, {-1, MIGRATION_REC_COMPLETE}},
	};
	for (unsigned i = 0; i < 4; i++) {
		for (unsigned j = 0; j < 3; j++) {
			s.phase = MIGRATION_REC_SOURCE_INTENT + i;
			d.phase = MIGRATION_REC_DEST_STAGED + j;
			for (unsigned k = 0; k < 3; k++) {
				action = MIGRATION_REC_COMPLETE;
				int error = migration_recovery_reconcile(&s, &d,
				    binding->source_certificate_sha256,
				    binding->destination_certificate_sha256, k, &action);
				if (k == 0 || plans[i][j][k - 1] == -1) {
					assert(error == (k == 0 ? ENXIO : EPROTO));
					assert(action == MIGRATION_REC_HOLD);
				} else {
					assert(error == 0);
					assert((int)action == plans[i][j][k - 1]);
				}
			}
		}
	}
	s.phase = MIGRATION_REC_SOURCE_RELEASED;
	d.phase = MIGRATION_REC_DEST_STAGED;
	/* Each independently meaningful binding field must prevent recovery of
	 * a different attempt, even when both records are individually valid. */
	uint8_t *fields[] = { d.session + 16, d.challenge, d.state_digest,
	    d.source_certificate_sha256, d.destination_certificate_sha256 };
	for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		*fields[i] ^= 0x20;
		assert(migration_recovery_reconcile(&s, &d,
		    binding->source_certificate_sha256,
		    binding->destination_certificate_sha256,
		    MIGRATION_REC_VM_PAUSED, &action) != 0);
		assert(action == MIGRATION_REC_HOLD);
		*fields[i] ^= 0x20;
	}
	d.destination_vmid++;
	assert(migration_recovery_reconcile(&s, &d,
	    binding->source_certificate_sha256, binding->destination_certificate_sha256,
	    MIGRATION_REC_VM_PAUSED, &action) == ESTALE);
	d.destination_vmid--;
	d.destination_epoch++;
	assert(migration_recovery_reconcile(&s, &d,
	    binding->source_certificate_sha256, binding->destination_certificate_sha256,
	    MIGRATION_REC_VM_PAUSED, &action) == ESTALE);
	d.destination_epoch--;
	assert(migration_recovery_reconcile(&s, &d,
	    binding->destination_certificate_sha256, binding->source_certificate_sha256,
	    MIGRATION_REC_VM_PAUSED, &action) == EACCES);
	assert(action == MIGRATION_REC_HOLD);
	assert(migration_recovery_reconcile(&d, &s,
	    binding->source_certificate_sha256, binding->destination_certificate_sha256,
	    MIGRATION_REC_VM_PAUSED, &action) == EPROTO);
	assert(migration_recovery_reconcile(NULL, &d,
	    binding->source_certificate_sha256, binding->destination_certificate_sha256,
	    MIGRATION_REC_VM_PAUSED, &action) == EINVAL);
	assert(action == MIGRATION_REC_HOLD);
}

static int syncs, fail_sync;
int __real_fsync(int);
int __wrap_fsync(int fd)
{
	if (++syncs == fail_sync) { errno = EIO; return (-1); }
	return (__real_fsync(fd));
}

int
main(void)
{
	char directory[] = "recovery.XXXXXX";
	struct migration_recovery_record r = {
	    .phase = MIGRATION_REC_SOURCE_INTENT,
	    .destination_vmid = 8, .destination_epoch = 10 };
	struct hypertrace_session_record source = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	int fd, statefd, status;
	char name[80], hex[65];
	uint8_t wire[MIGRATION_RECOVERY_SIZE];

	assert(mkdtemp(directory) != NULL);
	fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(fd >= 0);
	assert(hypertrace_session_record_encode(r.session, sizeof(r.session), &source) == 0);
	memset(r.challenge, 1, sizeof(r.challenge));
	memset(r.state_digest, 2, sizeof(r.state_digest));
	memset(r.source_certificate_sha256, 3, 32);
	memset(r.destination_certificate_sha256, 4, 32);
	reconciliation_cases(&r);
	r.phase = MIGRATION_REC_SOURCE_RETIRED;
	assert(migration_recovery_store_at(fd, &r) == ESTALE);
	r.phase = MIGRATION_REC_SOURCE_INTENT;
	/* Publication visible, directory fsync failed: exact retry must fsync again. */
	syncs = 0; fail_sync = 2;
	assert(migration_recovery_store_at(fd, &r) == EIO);
	syncs = fail_sync = 0;
	assert(migration_recovery_store_at(fd, &r) == 0 && syncs == 2);
	r.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	assert(migration_recovery_store_at(fd, &r) == ESTALE);
	r.phase = MIGRATION_REC_SOURCE_RETIRED;
	syncs = 0; fail_sync = 2; /* New record fsync fails before rename. */
	assert(migration_recovery_store_at(fd, &r) == EIO);
	fail_sync = 0;
	r.phase = MIGRATION_REC_SOURCE_INTENT;
	assert(migration_recovery_store_at(fd, &r) == 0);
	r.phase = MIGRATION_REC_SOURCE_RETIRED;
	assert(migration_recovery_store_at(fd, &r) == 0);
	r.phase = MIGRATION_REC_SOURCE_INTENT;
	assert(migration_recovery_store_at(fd, &r) == ESTALE);
	r.phase = MIGRATION_REC_SOURCE_RELEASED;
	assert(migration_recovery_store_at(fd, &r) == 0);
	r.state_digest[0] ^= 1;
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	r.state_digest[0] ^= 1;
	r.destination_epoch++;
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	r.destination_epoch--;
	/* Canonical phase mutation without its digest is corruption, not progress. */
	for (unsigned i = 0; i < 32; i++) memcpy(hex + i*2, "01", 2);
	hex[64] = 0;
	snprintf(name, sizeof(name), "s-%s.state", hex);
	statefd = openat(fd, name, O_RDWR | O_CLOEXEC);
	assert(statefd >= 0 && pread(statefd, wire, sizeof(wire), 0) == sizeof(wire));
	uint8_t bad = MIGRATION_REC_SOURCE_CONFIRMED;
	assert(pwrite(statefd, &bad, 1, 6) == 1);
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	assert(pwrite(statefd, wire, sizeof(wire), 0) == sizeof(wire));
	assert(ftruncate(statefd, sizeof(wire)-1) == 0);
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	assert(pwrite(statefd, wire, sizeof(wire), 0) == sizeof(wire));
	close(statefd);
	statefd = openat(fd, name, O_RDWR | O_CLOEXEC);
	assert(statefd >= 0);
	assert(pwrite(statefd, "HMR1", 4, 0) == 4 && ftruncate(statefd, 160) == 0);
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	assert(pwrite(statefd, wire, sizeof(wire), 0) == sizeof(wire));
	close(statefd);
	r.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	assert(migration_recovery_store_at(fd, &r) == 0);
	/* The destination role has a separate journal for the same attempt. */
	r.phase = MIGRATION_REC_DEST_STAGED;
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) _exit(migration_recovery_store_at(fd, &r) == 0 ? 0 : 1);
	assert(migration_recovery_store_at(fd, &r) == 0);
	assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	r.phase = MIGRATION_REC_DEST_RUNNING;
	assert(migration_recovery_store_at(fd, &r) == ESTALE);
	r.phase = MIGRATION_REC_DEST_RELEASED;
	assert(migration_recovery_store_at(fd, &r) == 0);
	r.phase = MIGRATION_REC_DEST_RUNNING;
	assert(migration_recovery_store_at(fd, &r) == 0);
	assert(fchmod(fd, 0770) == 0);
	assert(migration_recovery_store_at(fd, &r) == EPERM);
	assert(fchmod(fd, 0700) == 0);
	close(fd);
	/* Reopen without any in-memory storage state, as a recovery process does. */
	fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(fd >= 0);
	uint16_t phase = 0;
	assert(migration_recovery_load_at(fd, &r, &phase) == 0);
	assert(phase == MIGRATION_REC_DEST_RUNNING);
	r.phase = MIGRATION_REC_SOURCE_INTENT;
	assert(migration_recovery_load_at(fd, &r, &phase) == 0);
	assert(phase == MIGRATION_REC_SOURCE_CONFIRMED);
	struct migration_recovery_record recovered_source = r, recovered_destination = r;
	enum migration_recovery_action recovered_action = MIGRATION_REC_HOLD;
	recovered_source.phase = phase;
	recovered_destination.phase = MIGRATION_REC_DEST_STAGED;
	assert(migration_recovery_load_at(fd, &recovered_destination, &phase) == 0);
	recovered_destination.phase = phase;
	assert(migration_recovery_reconcile(&recovered_source, &recovered_destination,
	    r.source_certificate_sha256, r.destination_certificate_sha256,
	    MIGRATION_REC_VM_RUNNING, &recovered_action) == 0);
	assert(recovered_action == MIGRATION_REC_COMPLETE);
	r.source_certificate_sha256[0] ^= 1;
	assert(migration_recovery_load_at(fd, &r, &phase) == EPROTO);
	assert(migration_recovery_store_at(fd, &r) == EPROTO);
	r.source_certificate_sha256[0] ^= 1;
	r.destination_certificate_sha256[0] ^= 1;
	assert(migration_recovery_load_at(fd, &r, &phase) == EPROTO);
	r.destination_certificate_sha256[0] ^= 1;
	phase = 0; syncs = 0; fail_sync = 2;
	assert(migration_recovery_load_at(fd, &r, &phase) == EIO && phase == 0);
	fail_sync = 0; r.state_digest[0] ^= 1;
	assert(migration_recovery_load_at(fd, &r, &phase) == EPROTO && phase == 0);
	r.state_digest[0] ^= 1; r.challenge[0] ^= 1;
	assert(migration_recovery_load_at(fd, &r, &phase) == ENOENT && phase == 0);
	close(fd);
	return (0);
}

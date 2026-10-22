#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Ordinary-mode handoff journal through the production adapter.

Extracts prod_source_record, prod_dest_record, their journal helpers and the
migrate_resolve command from migration_session.c and drives them against a
private scratch directory.  The VM, IPC and HyperTrace boundaries are stubs;
the journal on disk is read back with migration_handoff_load as the oracle.
Never opens a VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
source_part = s[s.index('/*\n * Ordinary migrations keep the handoff journal'):
                s.index('/* The IPC controller owns this context')]
dest_part = s[s.index('static int\nprod_dest_record('):s.index('static void\nprod_dest_discard(')]
resolve_part = s[s.index('static pthread_mutex_t migration_resolve_mtx'):
                 s.index('IPC_COMMAND(migrate_resolve, vm_do_migrate_resolve);')]
fixture = r'''
#include <sys/nv.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dev/vmm/vmm_dev.h>
#include "migration_session.h"
#include "migration_recovery.h"
#include "migration_source_owner.h"
#include "migration_handoff.h"

struct vmctx { int unused; };
struct pci_devinst { int unused; };
struct migration_recovery_run_state { bool resume_uncertain; };
struct migration_prod_source {
	bool controller_held; int controller_fd; struct vmctx *ctx;
	bool quiesced, retirement_started, intent_pending, retired, fresh_stopped;
	uint8_t fresh_record[HYPERTRACE_SESSION_RECORD_SIZE];
	int recovery_dirfd; struct migration_recovery_record recovery;
};
struct migration_prod_dest {
	struct vmctx *ctx; bool committed; struct pci_devinst *fresh_device;
	int recovery_dirfd; bool running, retained;
	struct migration_commit_binding retained_binding;
	struct migration_recovery_run_state run_state;
	struct migration_recovery_record recovery;
};
static int quarantines, resumes, discards, frees, resume_error;
static struct vm_run_witness stub_witness;
static int witness_error;
static void ipc_quarantine_vm(void) { quarantines++; }
static int prod_dest_resume(void *arg) {
	struct migration_prod_dest *dst = arg; resumes++;
	if (resume_error != 0) return resume_error;
	dst->running = true; return 0;
}
static void prod_dest_discard(void *arg) { (void)arg; discards++; }
static void prod_dest_free(struct migration_prod_dest *dst, int owned_dirfd) {
	frees++; if (owned_dirfd >= 0) close(owned_dirfd); free(dst);
}
/* libvmmapi stubs: identity 7/0x1122334455667788 for every VM. */
int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch) {
	(void)ctx; *vmid = 7; *epoch = 0x1122334455667788ULL; return 0;
}
int vm_get_run_witness(struct vmctx *ctx, struct vm_run_witness *w) {
	(void)ctx; if (witness_error) { errno = witness_error; return -1; }
	*w = stub_witness; return 0;
}
#define IPC_COMMAND(name, fn)
static struct migration_prod_dest *migration_dest_retained;
''' + source_part + dest_part + resolve_part + r'''

static int entries_in(int dirfd) {
	int n = 0; DIR *d = fdopendir(dup(dirfd)); struct dirent *e;
	assert(d != NULL);
	rewinddir(d);	/* a dup shares the directory offset */
	while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') n++;
	closedir(d); return n;
}
static void fill_binding(struct migration_recovery_record *r, uint8_t tag) {
	r->destination_vmid = 7; r->destination_epoch = 0x1122334455667788ULL;
	memset(r->challenge, tag, 32); memset(r->state_digest, 0xd0 ^ tag, 32);
	memset(r->source_certificate_sha256, 1, 32);
	memset(r->destination_certificate_sha256, 2, 32);
}
static size_t journal(int dirfd, uint8_t role, const uint8_t challenge[32],
    struct migration_handoff_entry *have) {
	size_t count = 0;
	int error = migration_handoff_load(dirfd, role, challenge, have,
	    MIGRATION_HANDOFF_MAX, &count);
	assert(error == 0 || error == ENOENT);
	return count;
}

static void test_source(int dirfd) {
	struct migration_prod_source src; struct migration_handoff_entry have[MIGRATION_HANDOFF_MAX];
	memset(&src, 0, sizeof(src)); src.recovery_dirfd = dirfd; src.quiesced = true;
	fill_binding(&src.recovery, 0x11);
	uint8_t wrong[32]; memset(wrong, 0x12, 32);
	/* Wrong challenge, or RETIRED before retirement: refused, nothing written. */
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, wrong) == EPROTO);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RETIRED, src.recovery.challenge) == EPROTO);
	assert(journal(dirfd, MIGRATION_HANDOFF_SOURCE, src.recovery.challenge, have) == 0);
	assert(quarantines == 0 && !src.retirement_started);
	/* INTENT quarantines, marks retirement and clears the pending flag once durable. */
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, src.recovery.challenge) == 0);
	assert(quarantines == 1 && src.retirement_started && !src.intent_pending);
	assert(journal(dirfd, MIGRATION_HANDOFF_SOURCE, src.recovery.challenge, have) == 1);
	assert(have[0].kind == MIGRATION_HANDOFF_PHASE && have[0].phase == MIGRATION_REC_SOURCE_INTENT);
	assert(have[0].tls == 1 && have[0].destination_vmid == 7);
	assert(memcmp(have[0].state_digest, src.recovery.state_digest, 32) == 0);
	/* Retirement is the adapter's; the records follow it. */
	src.retired = true;
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, src.recovery.challenge) == EPROTO);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RETIRED, src.recovery.challenge) == 0);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RELEASED, src.recovery.challenge) == 0);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_CONFIRMED, src.recovery.challenge) == 0);
	assert(journal(dirfd, MIGRATION_HANDOFF_SOURCE, src.recovery.challenge, have) == 4);
	assert(have[3].phase == MIGRATION_REC_SOURCE_CONFIRMED && have[3].seq == 3);
	/* Plaintext migration: the entry says so. */
	memset(&src, 0, sizeof(src)); src.recovery_dirfd = dirfd; src.quiesced = true;
	fill_binding(&src.recovery, 0x13);
	memset(src.recovery.source_certificate_sha256, 0, 32);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, src.recovery.challenge) == 0);
	assert(journal(dirfd, MIGRATION_HANDOFF_SOURCE, src.recovery.challenge, have) == 1 && have[0].tls == 0);
	/* No recovery directory: the transitions succeed in memory only. */
	int before = entries_in(dirfd);
	memset(&src, 0, sizeof(src)); src.recovery_dirfd = -1; src.quiesced = true;
	fill_binding(&src.recovery, 0x14);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, src.recovery.challenge) == 0);
	assert(!src.intent_pending && src.retirement_started && src.recovery.phase == MIGRATION_REC_SOURCE_INTENT);
	src.retired = true;
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_RETIRED, src.recovery.challenge) == 0);
	assert(entries_in(dirfd) == before);
	/* A journal that refuses INTENT leaves the intent pending: the caller wedges. */
	assert(fchmod(dirfd, 0750) == 0);
	memset(&src, 0, sizeof(src)); src.recovery_dirfd = dirfd; src.quiesced = true;
	fill_binding(&src.recovery, 0x15);
	assert(prod_source_record(&src, MIGRATION_REC_SOURCE_INTENT, src.recovery.challenge) == EPERM);
	assert(src.intent_pending && src.retirement_started);
	assert(fchmod(dirfd, 0700) == 0);
	puts("source: ok");
}

static void test_dest(int dirfd) {
	struct migration_prod_dest dst; struct migration_handoff_entry have[MIGRATION_HANDOFF_MAX];
	memset(&dst, 0, sizeof(dst)); dst.recovery_dirfd = dirfd; dst.committed = true;
	fill_binding(&dst.recovery, 0x21);
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RUNNING, dst.recovery.challenge) == EPROTO);
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_STAGED, dst.recovery.challenge) == 0);
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RELEASED, dst.recovery.challenge) == 0);
	dst.running = true;
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RELEASED, dst.recovery.challenge) == EPROTO);
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_RUNNING, dst.recovery.challenge) == 0);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, dst.recovery.challenge, have) == 3);
	assert(have[2].phase == MIGRATION_REC_DEST_RUNNING && have[2].role == MIGRATION_HANDOFF_DEST);
	/* Uncommitted: nothing is recorded. */
	memset(&dst, 0, sizeof(dst)); dst.recovery_dirfd = dirfd; fill_binding(&dst.recovery, 0x22);
	assert(prod_dest_record(&dst, MIGRATION_REC_DEST_STAGED, dst.recovery.challenge) == EPROTO);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, dst.recovery.challenge, have) == 0);
	puts("dest: ok");
}

/* A retained ordinary destination at the given phase, with its own dirfd dup. */
static struct migration_prod_dest *retained(int dirfd, uint8_t tag, uint16_t phase, bool uncertain) {
	struct migration_prod_dest *dst = calloc(1, sizeof(*dst)); assert(dst);
	dst->recovery_dirfd = dirfd >= 0 ? dup(dirfd) : -1; dst->committed = true; dst->retained = true;
	dst->run_state.resume_uncertain = uncertain;
	fill_binding(&dst->recovery, tag);
	if (dirfd >= 0) {
		assert(prod_dest_record(dst, MIGRATION_REC_DEST_STAGED, dst->recovery.challenge) == 0);
		if (phase == MIGRATION_REC_DEST_RELEASED)
			assert(prod_dest_record(dst, MIGRATION_REC_DEST_RELEASED, dst->recovery.challenge) == 0);
	} else
		dst->recovery.phase = phase;
	migration_dest_retained = dst; migration_resolution = 0;
	resumes = discards = frees = 0; resume_error = 0; witness_error = 0;
	memset(&stub_witness, 0, sizeof(stub_witness));
	stub_witness.vmid = 7; stub_witness.epoch = 0x1122334455667788ULL;
	return dst;
}
static nvlist_t *resolve(const char *action, const char *flag) {
	nvlist_t *req = nvlist_create(0); struct vmctx ctx = {0};
	if (action) nvlist_add_string(req, "action", action);
	if (flag) nvlist_add_bool(req, flag, true);
	nvlist_t *reply = vm_do_migrate_resolve(&ctx, req); nvlist_destroy(req); return reply;
}
static void expect_reply(nvlist_t *reply, bool resolved, bool retained, int error_code) {
	assert(nvlist_get_bool(reply, "resolved") == resolved);
	assert(nvlist_get_bool(reply, "retained") == retained);
	if (error_code) assert(nvlist_get_number(reply, "error_code") == (uint64_t)error_code);
	else assert(!nvlist_exists_number(reply, "error_code"));
	assert(!nvlist_exists_number(reply, "journal_error"));
	nvlist_destroy(reply);
}
static void drop(struct migration_prod_dest *dst) {
	migration_dest_retained = NULL; if (dst->recovery_dirfd >= 0) close(dst->recovery_dirfd); free(dst);
}

static void test_resolve(int dirfd) {
	struct migration_handoff_entry have[MIGRATION_HANDOFF_MAX];
	struct migration_prod_dest *dst; uint8_t ch[32];
	/* Nothing retained. */
	migration_dest_retained = NULL;
	expect_reply(resolve("resume", "source_retired"), false, false, ENOENT);
	/* Refusals before any journal entry or action. */
	dst = retained(dirfd, 0x31, MIGRATION_REC_DEST_STAGED, false);
	memcpy(ch, dst->recovery.challenge, 32);
	expect_reply(resolve(NULL, NULL), false, true, EINVAL);
	expect_reply(resolve("export", NULL), false, true, EINVAL);
	expect_reply(resolve("resume", NULL), false, true, EINVAL);
	expect_reply(resolve("resume", "acknowledge_loss"), false, true, EINVAL);
	expect_reply(resolve("discard", NULL), false, true, EINVAL);
	expect_reply(resolve("discard", "source_retired"), false, true, EINVAL);
	assert(resumes == 0 && discards == 0 && frees == 0 && migration_resolution == 0);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 1);
	/* Resume at STAGED: decision, operator release, running, outcome. */
	expect_reply(resolve("resume", "source_retired"), true, false, 0);
	assert(resumes == 1 && frees == 1 && migration_resolution == 1 && migration_dest_retained == NULL);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 5);
	assert(have[1].kind == MIGRATION_HANDOFF_RESOLVE && have[1].action == MIGRATION_HANDOFF_RESUME);
	assert(migration_handoff_witness_zero(&have[1]));
	assert(have[2].kind == MIGRATION_HANDOFF_PHASE && have[2].phase == MIGRATION_REC_DEST_RELEASED);
	assert(have[3].kind == MIGRATION_HANDOFF_PHASE && have[3].phase == MIGRATION_REC_DEST_RUNNING);
	assert(have[4].kind == MIGRATION_HANDOFF_OUTCOME && have[4].result == 0);
	/* Uncertain resume: the witness decides. */
	dst = retained(dirfd, 0x32, MIGRATION_REC_DEST_RELEASED, true);
	memcpy(ch, dst->recovery.challenge, 32);
	stub_witness.guest_entries = 2;
	expect_reply(resolve("resume", "source_retired"), false, true, EBUSY);
	stub_witness.guest_entries = 0; stub_witness.running_vcpus = 1;
	expect_reply(resolve("resume", "source_retired"), false, true, EBUSY);
	stub_witness.running_vcpus = 0; stub_witness.epoch++;
	expect_reply(resolve("resume", "source_retired"), false, true, ESTALE);
	stub_witness.epoch--; witness_error = ENXIO;
	expect_reply(resolve("resume", "source_retired"), false, true, ENXIO);
	witness_error = 0;
	assert(resumes == 0 && journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 2);
	expect_reply(resolve("resume", "source_retired"), true, false, 0);
	assert(resumes == 1 && migration_resolution == 1);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 5);
	assert(have[2].kind == MIGRATION_HANDOFF_RESOLVE && have[2].witness_vmid == 7 &&
	    have[2].witness_epoch == 0x1122334455667788ULL && have[2].witness_entries == 0);
	assert(have[3].phase == MIGRATION_REC_DEST_RUNNING && have[4].kind == MIGRATION_HANDOFF_OUTCOME);
	/* A failed resume: decision and outcome are journaled, the image stays retained. */
	dst = retained(dirfd, 0x33, MIGRATION_REC_DEST_RELEASED, false);
	memcpy(ch, dst->recovery.challenge, 32); resume_error = EIO;
	expect_reply(resolve("resume", "source_retired"), false, true, EIO);
	assert(resumes == 1 && frees == 0 && migration_resolution == 0 && migration_dest_retained == dst);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 4);
	assert(have[2].kind == MIGRATION_HANDOFF_RESOLVE && have[3].kind == MIGRATION_HANDOFF_OUTCOME && have[3].result == EIO);
	/* ...and a later retry succeeds. */
	resume_error = 0;
	expect_reply(resolve("resume", "source_retired"), true, false, 0);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 7 && have[6].result == 0);
	/* A journal that cannot take the decision: nothing happens. */
	dst = retained(dirfd, 0x34, MIGRATION_REC_DEST_STAGED, false);
	memcpy(ch, dst->recovery.challenge, 32);
	assert(fchmod(dirfd, 0750) == 0);
	expect_reply(resolve("resume", "source_retired"), false, true, EPERM);
	expect_reply(resolve("discard", "acknowledge_loss"), false, true, EPERM);
	assert(fchmod(dirfd, 0700) == 0);
	assert(resumes == 0 && discards == 0 && journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 1);
	/* Discard. */
	expect_reply(resolve("discard", "acknowledge_loss"), true, false, 0);
	assert(discards == 1 && frees == 1 && migration_resolution == -1 && migration_dest_retained == NULL);
	assert(journal(dirfd, MIGRATION_HANDOFF_DEST, ch, have) == 3);
	assert(have[1].kind == MIGRATION_HANDOFF_RESOLVE && have[1].action == MIGRATION_HANDOFF_DISCARD);
	assert(have[2].kind == MIGRATION_HANDOFF_OUTCOME && have[2].action == MIGRATION_HANDOFF_DISCARD);
	/* Without a recovery directory the command still works, unjournaled. */
	int before = entries_in(dirfd);
	dst = retained(-1, 0x35, MIGRATION_REC_DEST_STAGED, false);
	expect_reply(resolve("resume", "source_retired"), true, false, 0);
	assert(resumes == 1 && migration_resolution == 1 && entries_in(dirfd) == before);
	dst = retained(-1, 0x36, MIGRATION_REC_DEST_STAGED, false);
	expect_reply(resolve("discard", "acknowledge_loss"), true, false, 0);
	assert(discards == 1 && migration_resolution == -1);
	(void)drop;
	puts("resolve: ok");
}

int main(void) {
	char path[] = "handoff-prod.XXXXXX";
	assert(mkdtemp(path) && chmod(path, 0700) == 0);
	int dirfd = open(path, O_RDONLY | O_DIRECTORY); assert(dirfd >= 0);
	test_source(dirfd);
	test_dest(dirfd);
	test_resolve(dirfd);
	return 0;
}
'''
(out / 'handoff.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
    '-fsanitize=address,undefined', '-I' + str(root / 'sys'),
    '-I' + str(root / 'usr.sbin/bhyve'), '-I' + str(root / 'lib/libvmmapi'),
    str(out / 'handoff.c'), '-lnv', '-lz', '-lmd', '-lpthread',
    '-o', str(out / 'handoff')], check=True)
subprocess.run([str(out / 'handoff')], cwd=out, check=True, timeout=60)
print('PASS: ordinary migrations journal every transition and every resolution decision before acting; refusals and failures leave the image retained')

#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""bhyvectl --migrate-journal: prints a handoff journal exactly as written.

The journal is produced with migration_handoff_append (the production writer);
the extracted bhyvectl printer reads it back.  The expected text is written out
by the test from the entries it appended, so the oracle is the journal's
content, not the printer.  Damaged and misnamed journals are refused whole."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyvectl/bhyvectl.c').read_text()
start = s.index('static const char *\nmigration_journal_phase_name(')
end = s.index('#endif', start)
fixture = r'''
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "migration_handoff.h"
#include "migration_recovery_phase.h"
''' + s[start:end] + r'''

static struct migration_handoff_entry base(uint8_t role, uint8_t tag) {
	struct migration_handoff_entry e; memset(&e, 0, sizeof(e));
	e.role = role; e.destination_vmid = 9; e.destination_epoch = 0xabcdef0123ULL;
	memset(e.challenge, tag, 32); memset(e.state_digest, 0x5a, 32); e.tls = 1;
	return e;
}
static char *printed(const char *path, int *error) {
	static char buf[8192]; FILE *f = fmemopen(buf, sizeof(buf), "w");
	assert(f); memset(buf, 0, sizeof(buf));
	*error = migration_journal_print(path, f); fclose(f); return buf;
}
int main(void) {
	char dir[] = "journal-cli.XXXXXX", path[PATH_MAX], name[80];
	assert(mkdtemp(dir) && chmod(dir, 0700) == 0);
	int dirfd = open(dir, O_RDONLY | O_DIRECTORY); assert(dirfd >= 0);
	/* A destination journal: staged, a refused-then-retried resolution, running. */
	struct migration_handoff_entry e = base(MIGRATION_HANDOFF_DEST, 0x42);
	e.kind = MIGRATION_HANDOFF_PHASE; e.phase = MIGRATION_REC_DEST_STAGED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_RESOLVE; e.phase = 0; e.action = MIGRATION_HANDOFF_RESUME;
	e.witness_vmid = 9; e.witness_epoch = 0xabcdef0123ULL;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_OUTCOME; e.result = EIO;
	memset(&e.witness_vmid, 0, sizeof(e.witness_vmid)); e.witness_epoch = 0;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_RESOLVE; e.result = 0;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_PHASE; e.action = 0; e.phase = MIGRATION_REC_DEST_RELEASED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.phase = MIGRATION_REC_DEST_RUNNING;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_OUTCOME; e.phase = 0; e.action = MIGRATION_HANDOFF_RESUME;
	assert(migration_handoff_append(dirfd, &e) == 0);
	migration_handoff_name(MIGRATION_HANDOFF_DEST, e.challenge, name);
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	int error; const char *text = printed(path, &error);
	assert(error == 0);
	const char *want =
	    "  0 destination phase destination-staged destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  1 destination resolve resume witness vm 9 epoch 0xabcdef0123 entries 0 running 0 destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  2 destination outcome resume Input/output error destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  3 destination resolve resume destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  4 destination phase destination-released destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  5 destination phase destination-running destination vm 9 epoch 0xabcdef0123 tls\n"
	    "  6 destination outcome resume ok destination vm 9 epoch 0xabcdef0123 tls\n"
	    "7 entries\n";
	if (strcmp(text, want) != 0) { fprintf(stderr, "got:\n%s\nwant:\n%s", text, want); return 1; }
	/* A plaintext source journal, read through a relative path. */
	e = base(MIGRATION_HANDOFF_SOURCE, 0x43); e.tls = 0;
	e.kind = MIGRATION_HANDOFF_PHASE; e.phase = MIGRATION_REC_SOURCE_INTENT;
	assert(migration_handoff_append(dirfd, &e) == 0);
	migration_handoff_name(MIGRATION_HANDOFF_SOURCE, e.challenge, name);
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	text = printed(path, &error); assert(error == 0);
	assert(strcmp(text, "  0 source phase source-intent destination vm 9 epoch 0xabcdef0123 plaintext\n1 entry\n") == 0);
	/* Refusals: a name that is not a journal, a missing journal, a torn one. */
	snprintf(path, sizeof(path), "%s/notes.log", dir);
	assert(printed(path, &error) && error == EINVAL);
	snprintf(path, sizeof(path), "%s/h-x-%s", dir, name + 4);
	assert(printed(path, &error) && error == EINVAL);
	snprintf(path, sizeof(path), "%s/h-d-%s", dir, name + 4);	/* other side: absent */
	assert(printed(path, &error) && error == ENOENT);
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	int fd = open(path, O_WRONLY | O_APPEND); assert(fd >= 0 && write(fd, "torn", 4) == 4); close(fd);
	text = printed(path, &error); assert(error == EPROTO && text[0] == '\0');
	puts("journal printer: ok");
	return 0;
}
'''
(out / 'journal.c').write_text(fixture)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    str(out / 'journal.c'), '-lz', '-lmd', '-o', str(out / 'journal')], check=True)
subprocess.run([str(out / 'journal')], cwd=out, check=True, timeout=30)
print('PASS: --migrate-journal prints every entry of a journal written by the production appender and refuses misnamed, missing or torn journals whole')

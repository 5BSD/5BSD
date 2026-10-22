#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""bhyvectl --migrate-journal, driven through the production binary.

usage: bhyvectl-journal.py OUT BHYVECTL

The journals are written by migration_handoff_append (the production writer,
compiled from migration_handoff.h); the expected text is derived from the
entries appended, so the oracle is the journal's content, not the printer.
Covers both roles, every record kind, witness fields, tls and plaintext, a
relative path, misnamed, missing and torn journals, and the CLI refusals:
the option combined with any other option, given twice, or with positional
arguments (usage, exit 1)."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
bhyvectl = Path(sys.argv[2]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)

writer = r'''
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "migration_handoff.h"
#include "migration_recovery_phase.h"
static struct migration_handoff_entry base(uint8_t role, uint8_t tag) {
	struct migration_handoff_entry e; memset(&e, 0, sizeof(e));
	e.role = role; e.destination_vmid = 9; e.destination_epoch = 0xabcdef0123ULL;
	memset(e.challenge, tag, 32); memset(e.state_digest, 0x5a, 32); e.tls = 1;
	return e;
}
int main(int argc, char **argv) {
	char name[80];
	assert(argc == 2);
	int dirfd = open(argv[1], O_RDONLY | O_DIRECTORY); assert(dirfd >= 0);
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
	puts(name);
	/* A plaintext source journal: every source phase (a source never
	 * resolves). */
	e = base(MIGRATION_HANDOFF_SOURCE, 0x43); e.tls = 0;
	e.kind = MIGRATION_HANDOFF_PHASE; e.phase = MIGRATION_REC_SOURCE_INTENT;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.phase = MIGRATION_REC_SOURCE_RETIRED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.phase = MIGRATION_REC_SOURCE_RELEASED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	migration_handoff_name(MIGRATION_HANDOFF_SOURCE, e.challenge, name);
	puts(name);
	/* A destination that discarded the retained copy. */
	e = base(MIGRATION_HANDOFF_DEST, 0x44);
	e.kind = MIGRATION_HANDOFF_PHASE; e.phase = MIGRATION_REC_DEST_STAGED;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_RESOLVE; e.phase = 0; e.action = MIGRATION_HANDOFF_DISCARD;
	assert(migration_handoff_append(dirfd, &e) == 0);
	e.kind = MIGRATION_HANDOFF_OUTCOME;
	assert(migration_handoff_append(dirfd, &e) == 0);
	migration_handoff_name(MIGRATION_HANDOFF_DEST, e.challenge, name);
	puts(name);
	return 0;
}
'''
(out / 'writer.c').write_text(writer)
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
    '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/bhyve'),
    str(out / 'writer.c'), '-lz', '-lmd', '-o', str(out / 'writer')], check=True)
jdir = out / 'journals'
jdir.mkdir(exist_ok=True)
os.chmod(jdir, 0o700)		# the appender requires a private directory
names = subprocess.run([str(out / 'writer'), str(jdir)], capture_output=True, text=True,
                       check=True).stdout.split()
dest_name, src_name, discard_name = names

env = dict(os.environ)
checks = 0


def run(*args, cwd=None):
    return subprocess.run([str(bhyvectl)] + list(args), capture_output=True, text=True,
                          timeout=60, cwd=cwd, env=env)


def expect(done, code, stdout=None, stderr_has=None):
    global checks
    if done.returncode != code or (stdout is not None and done.stdout != stdout) or \
            (stderr_has is not None and stderr_has not in done.stderr):
        raise SystemExit('bhyvectl %s: rc %d\nstdout:\n%s\nstderr:\n%s' % (
            done.args[1:], done.returncode, done.stdout, done.stderr))
    checks += 1


want_dest = (
    "  0 destination phase destination-staged destination vm 9 epoch 0xabcdef0123 tls\n"
    "  1 destination resolve resume witness vm 9 epoch 0xabcdef0123 entries 0 running 0 destination vm 9 epoch 0xabcdef0123 tls\n"
    "  2 destination outcome resume Input/output error destination vm 9 epoch 0xabcdef0123 tls\n"
    "  3 destination resolve resume destination vm 9 epoch 0xabcdef0123 tls\n"
    "  4 destination phase destination-released destination vm 9 epoch 0xabcdef0123 tls\n"
    "  5 destination phase destination-running destination vm 9 epoch 0xabcdef0123 tls\n"
    "  6 destination outcome resume ok destination vm 9 epoch 0xabcdef0123 tls\n"
    "7 entries\n")
want_src = (
    "  0 source phase source-intent destination vm 9 epoch 0xabcdef0123 plaintext\n"
    "  1 source phase source-retired destination vm 9 epoch 0xabcdef0123 plaintext\n"
    "  2 source phase source-released destination vm 9 epoch 0xabcdef0123 plaintext\n"
    "  3 source phase source-confirmed destination vm 9 epoch 0xabcdef0123 plaintext\n"
    "4 entries\n")
want_discard = (
    "  0 destination phase destination-staged destination vm 9 epoch 0xabcdef0123 tls\n"
    "  1 destination resolve discard destination vm 9 epoch 0xabcdef0123 tls\n"
    "  2 destination outcome discard ok destination vm 9 epoch 0xabcdef0123 tls\n"
    "3 entries\n")
expect(run('--migrate-journal', str(jdir / dest_name)), 0, want_dest)
expect(run('--migrate-journal=' + str(jdir / dest_name)), 0, want_dest)
expect(run('--migrate-journal', src_name, cwd=jdir), 0, want_src)	# relative path
expect(run('--migrate-journal', './' + src_name, cwd=jdir), 0, want_src)
expect(run('--migrate-journal', '/' + str(jdir / src_name).lstrip('/')), 0, want_src)
expect(run('--migrate-journal', str(jdir / discard_name)), 0, want_discard)
# Refusals of the journal itself: not a journal name, an unknown side, the
# other side of an existing attempt (absent), a torn journal, a directory
# that does not exist, and a path longer than PATH_MAX.
expect(run('--migrate-journal', str(jdir / 'notes.log')), 1, '', 'Usage')
expect(run('--migrate-journal', str(jdir / ('h-x-' + src_name[4:]))), 1, '', 'Usage')
expect(run('--migrate-journal', str(jdir / ('h-d-' + src_name[4:]))), 1, '',
       'No such file or directory')
expect(run('--migrate-journal', str(jdir / 'absent' / dest_name)), 1, '', 'No such file')
bad = jdir / ('h-s-' + 'zz' + src_name[6:])
expect(run('--migrate-journal', str(bad)), 1, '', 'Usage')
expect(run('--migrate-journal', 'x' * 5000), 1, '', 'File name too long')
torn = jdir / 'torn'
torn.mkdir(exist_ok=True)
os.chmod(torn, 0o700)
(torn / src_name).write_bytes((jdir / src_name).read_bytes() + b'torn')
# a journal readable by others is refused before its contents are read
expect(run('--migrate-journal', str(torn / src_name)), 1, '', 'Operation not permitted')
os.chmod(torn / src_name, 0o600)
expect(run('--migrate-journal', str(torn / src_name)), 1, '', 'Protocol error')
# CLI refusals: any other option, the option twice, positional arguments.
expect(run('--migrate-journal', str(jdir / dest_name), '--vm', 'x'), 1, '', 'Usage')
expect(run('--vm', 'x', '--migrate-journal', str(jdir / dest_name)), 1, '', 'Usage')
expect(run('--migrate-journal', str(jdir / dest_name), '--migrate-journal', str(jdir / dest_name)),
       1, '', 'Usage')
expect(run('--migrate-journal', str(jdir / dest_name), 'extra'), 1, '', 'Usage')
expect(run('--migrate-journal', str(jdir / dest_name), '--get-lowmem'), 1, '', 'Usage')
print('PASS: bhyvectl --migrate-journal prints three journals written by the production '
      'appender, refuses misnamed/missing/torn journals and every option conflict '
      '(%d checks)' % checks)

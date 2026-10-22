/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * migration_handoff.h: the ordinary-mode handoff journal.  Expectations come
 * from the header's documented rules (layout, validity, sequence, durability
 * refusals), not from running the implementation.  Takes one argument: a
 * scratch directory under /usr/obj in which to create private journals.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "migration_handoff.h"

static int failures;

#define	EXPECT(what, got, want) expect(what, (got), (want), __LINE__)

static void
expect(const char *what, int got, int want, int line)
{
	printf("%s %s (line %d): got %d want %d\n", got == want ? "PASS" : "FAIL",
	    what, line, got, want);
	failures += got != want;
}

static struct migration_handoff_entry
phase_entry(uint8_t role, uint16_t phase)
{
	struct migration_handoff_entry e;

	memset(&e, 0, sizeof(e));
	e.kind = MIGRATION_HANDOFF_PHASE;
	e.role = role;
	e.phase = phase;
	e.destination_vmid = 7;
	e.destination_epoch = 0x1122334455667788ULL;
	memset(e.challenge, 0xc1, 32);
	memset(e.state_digest, 0xd2, 32);
	e.tls = 1;
	return (e);
}

static struct migration_handoff_entry
resolution_entry(uint8_t kind, uint8_t action, int32_t result)
{
	struct migration_handoff_entry e = phase_entry(MIGRATION_HANDOFF_DEST, 0);

	e.kind = kind;
	e.phase = 0;
	e.action = action;
	e.result = result;
	return (e);
}

static int
raw_size(int dirfd, const char *name)
{
	struct stat st;

	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
		return (-1);
	return ((int)st.st_size);
}

static void
test_format(void)
{
	struct migration_handoff_entry e, d;
	uint8_t wire[MIGRATION_HANDOFF_SIZE];

	/* Round trip of each kind, and the documented byte positions. */
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_RETIRED);
	e.seq = 3;
	EXPECT("encode phase", migration_handoff_encode(&e, wire), 0);
	EXPECT("magic", memcmp(wire, "MHJ1", 4), 0);
	EXPECT("kind byte", wire[4], MIGRATION_HANDOFF_PHASE);
	EXPECT("role byte", wire[5], MIGRATION_HANDOFF_SOURCE);
	EXPECT("phase le16", le16dec(wire + 8), MIGRATION_REC_SOURCE_RETIRED);
	EXPECT("vmid le16", le16dec(wire + 10), 7);
	EXPECT("seq le32", (int)le32dec(wire + 112), 3);
	EXPECT("decode phase", migration_handoff_decode(wire, &d), 0);
	EXPECT("decoded equal", memcmp(&d, &e, sizeof(e)), 0);

	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	e.witness_vmid = 7;
	e.witness_epoch = 0x1122334455667788ULL;
	EXPECT("encode resolve", migration_handoff_encode(&e, wire), 0);
	EXPECT("decode resolve", migration_handoff_decode(wire, &d), 0);
	EXPECT("resolve equal", memcmp(&d, &e, sizeof(e)), 0);

	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_DISCARD, EIO);
	EXPECT("encode outcome", migration_handoff_encode(&e, wire), 0);
	EXPECT("result le32", (int)le32dec(wire + 12), EIO);
	EXPECT("decode outcome", migration_handoff_decode(wire, &d), 0);
	EXPECT("outcome equal", memcmp(&d, &e, sizeof(e)), 0);

	/* Corruption: a flipped payload byte, a bad magic, a dirty pad. */
	wire[30] ^= 1;
	EXPECT("flipped byte", migration_handoff_decode(wire, &d), EPROTO);
	wire[30] ^= 1;
	wire[0] = 'X';
	EXPECT("bad magic", migration_handoff_decode(wire, &d), EPROTO);
	wire[0] = 'M';
	EXPECT("restored decodes", migration_handoff_decode(wire, &d), 0);
	wire[117] = 1;
	le32enc(wire + 124, (uint32_t)crc32(0L, wire, 124));
	EXPECT("dirty pad with valid crc", migration_handoff_decode(wire, &d),
	    EPROTO);

	/* Validity rules, one field at a time. */
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_STAGED);
	EXPECT("valid dest phase", migration_handoff_encode(&e, wire), 0);
	e.phase = MIGRATION_REC_SOURCE_INTENT;
	EXPECT("source phase on dest", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_DEST_STAGED);
	EXPECT("dest phase on source", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_CONFIRMED + 1);
	EXPECT("phase past end", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(3, MIGRATION_REC_SOURCE_INTENT);
	EXPECT("unknown role", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.kind = 4;
	EXPECT("unknown kind", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	memset(e.challenge, 0, 32);
	EXPECT("zero challenge", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	memset(e.state_digest, 0, 32);
	EXPECT("zero digest", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.destination_vmid = 0;
	EXPECT("zero vmid", migration_handoff_encode(&e, wire), EINVAL);
	e.destination_vmid = HYPERTRACE_MAX_VMS;
	EXPECT("vmid out of range", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.destination_epoch = 0;
	EXPECT("zero epoch", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.tls = 2;
	EXPECT("tls not boolean", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.action = MIGRATION_HANDOFF_RESUME;
	EXPECT("phase with action", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.result = 1;
	EXPECT("phase with result", migration_handoff_encode(&e, wire), EINVAL);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	e.witness_entries = 1;
	EXPECT("phase with witness", migration_handoff_encode(&e, wire), EINVAL);

	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	e.role = MIGRATION_HANDOFF_SOURCE;
	EXPECT("source resolve", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, 3, 0);
	EXPECT("unknown action", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	e.phase = MIGRATION_REC_DEST_STAGED;
	EXPECT("resolve with phase", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 1);
	EXPECT("resolve with result", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_DISCARD, 0);
	e.witness_running = 1;
	EXPECT("discard with witness", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_RESUME, -1);
	EXPECT("negative result", migration_handoff_encode(&e, wire), EINVAL);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_RESUME, 0);
	e.witness_vmid = 1;
	EXPECT("outcome with witness", migration_handoff_encode(&e, wire), EINVAL);
	EXPECT("encode NULL", migration_handoff_encode(NULL, wire), EINVAL);
	EXPECT("decode NULL", migration_handoff_decode(wire, NULL), EINVAL);

	/* Names: side letter, 64 hex digits, fixed suffix. */
	{
		char name[80];
		uint8_t challenge[32] = {0xab, 0x01};

		migration_handoff_name(MIGRATION_HANDOFF_SOURCE, challenge, name);
		EXPECT("source name prefix", strncmp(name, "h-s-ab01", 8), 0);
		EXPECT("name length", (int)strlen(name), 72);
		EXPECT("name suffix", strcmp(name + 68, ".log"), 0);
		migration_handoff_name(MIGRATION_HANDOFF_DEST, challenge, name);
		EXPECT("dest name prefix", strncmp(name, "h-d-ab01", 8), 0);
	}
}

static void
test_sequence(int dirfd)
{
	struct migration_handoff_entry e, have[MIGRATION_HANDOFF_MAX];
	size_t count;
	char name[80];
	uint8_t challenge[32];

	memset(challenge, 0xc1, 32);
	migration_handoff_name(MIGRATION_HANDOFF_SOURCE, challenge, name);

	/* Nothing yet. */
	EXPECT("load missing", migration_handoff_load(dirfd,
	    MIGRATION_HANDOFF_SOURCE, challenge, have, MIGRATION_HANDOFF_MAX,
	    &count), ENOENT);

	/* The source must start at INTENT. */
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_RETIRED);
	EXPECT("source not at INTENT", migration_handoff_append(dirfd, &e), ESTALE);
	EXPECT("refusal created no file", raw_size(dirfd, name), 0);
	e = phase_entry(MIGRATION_HANDOFF_SOURCE, MIGRATION_REC_SOURCE_INTENT);
	EXPECT("INTENT", migration_handoff_append(dirfd, &e), 0);
	EXPECT("one entry", raw_size(dirfd, name), (int)MIGRATION_HANDOFF_SIZE);
	{
		struct stat st;

		EXPECT("fstatat", fstatat(dirfd, name, &st, 0), 0);
		EXPECT("mode 0600", (int)(st.st_mode & 0777), 0600);
	}
	/* Idempotent retry of the current phase appends nothing. */
	EXPECT("INTENT again", migration_handoff_append(dirfd, &e), 0);
	EXPECT("still one entry", raw_size(dirfd, name), (int)MIGRATION_HANDOFF_SIZE);
	/* Skipping a phase. */
	e.phase = MIGRATION_REC_SOURCE_RELEASED;
	EXPECT("skip to RELEASED", migration_handoff_append(dirfd, &e), ESTALE);
	/* Going back. */
	e.phase = MIGRATION_REC_SOURCE_RETIRED;
	EXPECT("RETIRED", migration_handoff_append(dirfd, &e), 0);
	e.phase = MIGRATION_REC_SOURCE_INTENT;
	EXPECT("back to INTENT", migration_handoff_append(dirfd, &e), ESTALE);
	/* A different binding for the same attempt. */
	e.phase = MIGRATION_REC_SOURCE_RELEASED;
	e.destination_epoch++;
	EXPECT("binding changed", migration_handoff_append(dirfd, &e), EPROTO);
	e.destination_epoch--;
	e.tls = 0;
	EXPECT("tls changed", migration_handoff_append(dirfd, &e), EPROTO);
	e.tls = 1;
	EXPECT("RELEASED", migration_handoff_append(dirfd, &e), 0);
	e.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	EXPECT("CONFIRMED", migration_handoff_append(dirfd, &e), 0);
	EXPECT("four entries", raw_size(dirfd, name), 4 * (int)MIGRATION_HANDOFF_SIZE);
	EXPECT("load source", migration_handoff_load(dirfd, MIGRATION_HANDOFF_SOURCE,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), 0);
	EXPECT("count 4", (int)count, 4);
	EXPECT("seq 3", (int)have[3].seq, 3);
	EXPECT("last CONFIRMED", have[3].phase, MIGRATION_REC_SOURCE_CONFIRMED);
	EXPECT("load too small", migration_handoff_load(dirfd,
	    MIGRATION_HANDOFF_SOURCE, challenge, have, 3, &count), E2BIG);
	/* No resolution on a source. */
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	e.role = MIGRATION_HANDOFF_SOURCE;
	EXPECT("source resolve append", migration_handoff_append(dirfd, &e), EINVAL);

	/* Destination: STAGED, then a resolution flow at STAGED. */
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	EXPECT("resolve before any phase", migration_handoff_append(dirfd, &e),
	    ESTALE);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RELEASED);
	EXPECT("dest not at STAGED", migration_handoff_append(dirfd, &e), ESTALE);
	e.phase = MIGRATION_REC_DEST_STAGED;
	EXPECT("STAGED", migration_handoff_append(dirfd, &e), 0);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_RESUME, 0);
	EXPECT("outcome without decision", migration_handoff_append(dirfd, &e),
	    ESTALE);
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	e.witness_vmid = 7;
	e.witness_epoch = 0x1122334455667788ULL;
	EXPECT("RESOLVE resume", migration_handoff_append(dirfd, &e), 0);
	EXPECT("second decision while pending", migration_handoff_append(dirfd, &e),
	    EBUSY);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_DISCARD, 0);
	EXPECT("outcome of the wrong action", migration_handoff_append(dirfd, &e),
	    ESTALE);
	/* The operator's release and a failed resume. */
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RELEASED);
	EXPECT("RELEASED by operator", migration_handoff_append(dirfd, &e), 0);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_RESUME, EIO);
	EXPECT("OUTCOME EIO", migration_handoff_append(dirfd, &e), 0);
	/* A second attempt is allowed once the first has its outcome. */
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_RESUME, 0);
	EXPECT("RESOLVE again", migration_handoff_append(dirfd, &e), 0);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RUNNING);
	EXPECT("RUNNING", migration_handoff_append(dirfd, &e), 0);
	e = resolution_entry(MIGRATION_HANDOFF_OUTCOME, MIGRATION_HANDOFF_RESUME, 0);
	EXPECT("OUTCOME 0", migration_handoff_append(dirfd, &e), 0);
	/* A running guest is never resolved again. */
	e = resolution_entry(MIGRATION_HANDOFF_RESOLVE, MIGRATION_HANDOFF_DISCARD, 0);
	EXPECT("resolve while RUNNING", migration_handoff_append(dirfd, &e), ESTALE);
	EXPECT("load dest", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), 0);
	EXPECT("dest count 7", (int)count, 7);
	EXPECT("dest kinds", have[0].kind == MIGRATION_HANDOFF_PHASE &&
	    have[1].kind == MIGRATION_HANDOFF_RESOLVE &&
	    have[2].kind == MIGRATION_HANDOFF_PHASE &&
	    have[3].kind == MIGRATION_HANDOFF_OUTCOME && have[3].result == EIO &&
	    have[4].kind == MIGRATION_HANDOFF_RESOLVE &&
	    have[5].kind == MIGRATION_HANDOFF_PHASE &&
	    have[5].phase == MIGRATION_REC_DEST_RUNNING &&
	    have[6].kind == MIGRATION_HANDOFF_OUTCOME && have[6].result == 0, 1);
	EXPECT("wrong role reads nothing", migration_handoff_load(dirfd,
	    MIGRATION_HANDOFF_SOURCE, (uint8_t[32]){0xee}, have,
	    MIGRATION_HANDOFF_MAX, &count), ENOENT);
}

static void
test_damage(int dirfd)
{
	struct migration_handoff_entry e, have[MIGRATION_HANDOFF_MAX];
	uint8_t wire[MIGRATION_HANDOFF_SIZE], challenge[32], other[32];
	size_t count;
	char name[80], other_name[80];
	int fd;

	memset(challenge, 0xc2, 32);
	memset(other, 0xc3, 32);
	migration_handoff_name(MIGRATION_HANDOFF_DEST, challenge, name);
	migration_handoff_name(MIGRATION_HANDOFF_DEST, other, other_name);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_STAGED);
	memcpy(e.challenge, challenge, 32);
	EXPECT("STAGED", migration_handoff_append(dirfd, &e), 0);

	/* A torn tail is refused by reader and writer alike. */
	fd = openat(dirfd, name, O_WRONLY | O_APPEND);
	EXPECT("open for tearing", fd >= 0, 1);
	EXPECT("write torn bytes", (int)write(fd, "torn", 4), 4);
	close(fd);
	e.phase = MIGRATION_REC_DEST_RELEASED;
	EXPECT("append onto torn tail", migration_handoff_append(dirfd, &e), EPROTO);
	EXPECT("load torn", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), EPROTO);
	EXPECT("torn file untouched", raw_size(dirfd, name),
	    (int)MIGRATION_HANDOFF_SIZE + 4);
	fd = openat(dirfd, name, O_WRONLY);
	EXPECT("truncate repair", ftruncate(fd, MIGRATION_HANDOFF_SIZE), 0);
	close(fd);
	EXPECT("repaired loads", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), 0);

	/* An entry of another attempt (or at the wrong position) in the file. */
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RELEASED);
	memcpy(e.challenge, other, 32);
	e.seq = 1;
	EXPECT("encode foreign", migration_handoff_encode(&e, wire), 0);
	fd = openat(dirfd, name, O_WRONLY | O_APPEND);
	EXPECT("write foreign", (int)write(fd, wire, sizeof(wire)), (int)sizeof(wire));
	close(fd);
	EXPECT("foreign entry", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), EPROTO);
	fd = openat(dirfd, name, O_WRONLY);
	EXPECT("drop foreign", ftruncate(fd, MIGRATION_HANDOFF_SIZE), 0);
	close(fd);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RELEASED);
	memcpy(e.challenge, challenge, 32);
	e.seq = 5;	/* right attempt, wrong position */
	EXPECT("encode misplaced", migration_handoff_encode(&e, wire), 0);
	fd = openat(dirfd, name, O_WRONLY | O_APPEND);
	EXPECT("write misplaced", (int)write(fd, wire, sizeof(wire)), (int)sizeof(wire));
	close(fd);
	EXPECT("misplaced entry", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), EPROTO);
	fd = openat(dirfd, name, O_WRONLY);
	EXPECT("drop misplaced", ftruncate(fd, MIGRATION_HANDOFF_SIZE), 0);
	close(fd);

	/* A symlink where the journal should be is never followed. */
	EXPECT("plant symlink", symlinkat(name, dirfd, other_name), 0);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_STAGED);
	memcpy(e.challenge, other, 32);
	EXPECT("append through symlink refused",
	    migration_handoff_append(dirfd, &e) != 0, 1);
	EXPECT("symlink target untouched", raw_size(dirfd, name),
	    (int)MIGRATION_HANDOFF_SIZE);
	EXPECT("remove symlink", unlinkat(dirfd, other_name, 0), 0);

	/* A second link to the journal makes it untrusted. */
	EXPECT("hard link", linkat(dirfd, name, dirfd, "alias", 0), 0);
	e = phase_entry(MIGRATION_HANDOFF_DEST, MIGRATION_REC_DEST_RELEASED);
	memcpy(e.challenge, challenge, 32);
	EXPECT("linked journal", migration_handoff_append(dirfd, &e), EPERM);
	EXPECT("unlink alias", unlinkat(dirfd, "alias", 0), 0);
	EXPECT("single link again", migration_handoff_append(dirfd, &e), 0);

	/* A journal readable by others is refused. */
	EXPECT("loosen file", fchmodat(dirfd, name, 0640, 0), 0);
	e.phase = MIGRATION_REC_DEST_RUNNING;
	EXPECT("loose file", migration_handoff_append(dirfd, &e), EPERM);
	EXPECT("restore file", fchmodat(dirfd, name, 0600, 0), 0);
	/* So is a directory readable by others. */
	EXPECT("loosen dir", fchmod(dirfd, 0750), 0);
	EXPECT("loose dir append", migration_handoff_append(dirfd, &e), EPERM);
	EXPECT("loose dir load", migration_handoff_load(dirfd, MIGRATION_HANDOFF_DEST,
	    challenge, have, MIGRATION_HANDOFF_MAX, &count), EPERM);
	EXPECT("restore dir", fchmod(dirfd, 0700), 0);
	EXPECT("not a directory", migration_handoff_append(STDIN_FILENO, &e) != 0, 1);
	EXPECT("closed dirfd", migration_handoff_append(1000, &e), EBADF);
	EXPECT("invalid entry", migration_handoff_append(dirfd,
	    &(struct migration_handoff_entry){0}), EINVAL);
}

int
main(int argc, char **argv)
{
	char path[1024];
	int dirfd;

	if (argc != 2 || strncmp(argv[1], "/usr/obj", 8) != 0) {
		fprintf(stderr, "usage: %s /usr/obj/scratch-dir\n", argv[0]);
		return (2);
	}
	snprintf(path, sizeof(path), "%s/handoff.XXXXXX", argv[1]);
	if (mkdtemp(path) == NULL || chmod(path, 0700) != 0) {
		perror("mkdtemp");
		return (2);
	}
	dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror(path);
		return (2);
	}
	test_format();
	test_sequence(dirfd);
	test_damage(dirfd);
	printf("%d failure(s)\n", failures);
	return (failures != 0);
}

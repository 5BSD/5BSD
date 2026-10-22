/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Offline tests of the durable destination image (HDI1), successor record
 * (HDS1), controller lock and reconstruction admission. Real private
 * directories and files are used; kernel witness/destruction are injected.
 * Write, fsync and rename faults are injected by call count and each one is
 * verified to fire. No VM, device, module or daemon is touched.
 */
#include <sys/wait.h>
#include <assert.h>
#include <dirent.h>
#include <stdatomic.h>
#include "migration_dest_image.h"

static int fail_fsync, fail_rename, fail_write, fired;
static int fsync_calls, rename_calls, write_calls;
int __real_fsync(int);
int __wrap_fsync(int fd) {
	if (fail_fsync != 0 && ++fsync_calls == fail_fsync) {
		fired++;
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int a, const char *b, int c, const char *d) {
	if (fail_rename != 0 && ++rename_calls == fail_rename) {
		fired++;
		errno = EXDEV;
		return (-1);
	}
	return (__real_renameat(a, b, c, d));
}
ssize_t __real_write(int, const void *, size_t);
ssize_t __wrap_write(int fd, const void *buffer, size_t length) {
	if (fail_write != 0 && ++write_calls == fail_write) {
		fired++;
		errno = ENOSPC;
		return (-1);
	}
	/* Exercise short-write continuation on every call. */
	if (length > 1 && fail_write != 0)
		length = (length + 1) / 2;
	return (__real_write(fd, buffer, length));
}
static void reset_faults(void) {
	fail_fsync = fail_rename = fail_write = 0;
	fsync_calls = rename_calls = write_calls = 0;
}

#define LOWMEM (MIGRATION_DEST_IMAGE_CHUNK + 8192U)
#define HIGHMEM (65536U)
#define HIGHBASE (1ULL << 32)
static uint8_t *ram_low, *ram_high;
static int map_fail_at, map_calls;
static void *map(void *arg, uint64_t gpa, size_t length) {
	(void)arg;
	if (map_fail_at != 0 && ++map_calls == map_fail_at) {
		fired++;
		return (NULL);
	}
	if (gpa + length <= LOWMEM)
		return (ram_low + gpa);
	if (gpa >= HIGHBASE && gpa + length <= HIGHBASE + HIGHMEM)
		return (ram_high + (gpa - HIGHBASE));
	abort();
}

static int live_vmid[4];
static uint64_t live_epoch[4];
static unsigned witness_calls, destroy_calls;
static int witness_error, destroy_error;
static int retired(void *arg, uint16_t vmid, uint64_t epoch) {
	(void)arg;
	witness_calls++;
	if (witness_error != 0)
		return (witness_error);
	for (int i = 0; i < 4; i++)
		if (live_vmid[i] == vmid && live_epoch[i] == epoch)
			return (EBUSY);
	return (0);
}
static int destroy(void *arg, const char *name, uint16_t vmid, uint64_t epoch) {
	(void)arg;
	destroy_calls++;
	assert(strcmp(name, "orphan") == 0);
	if (destroy_error != 0)
		return (destroy_error);
	for (int i = 0; i < 4; i++)
		if (live_vmid[i] == vmid && live_epoch[i] == epoch) {
			live_vmid[i] = 0;
			live_epoch[i] = 0;
			return (0);
		}
	return (ESTALE);
}
static const struct migration_dest_reconstruct_ops ops = { retired, destroy };

static uint8_t dev[777];
static struct migration_recovery_record record;
static const struct migration_dest_geometry geometry = {
	.lowmem_length = LOWMEM, .highmem_base = HIGHBASE, .highmem_length = HIGHMEM };

static int count_entries(int dirfd, const char *suffix) {
	int copy = dup(dirfd), count = 0;
	DIR *d = fdopendir(copy);
	struct dirent *entry;
	assert(d != NULL);
	rewinddir(d);
	while ((entry = readdir(d)) != NULL)
		if (strstr(entry->d_name, suffix) != NULL)
			count++;
	closedir(d);
	return (count);
}

static void make_record(void) {
	struct hypertrace_session_record stopped = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	SHA256_CTX hash;
	memset(&record, 0, sizeof(record));
	record.phase = MIGRATION_REC_DEST_STAGED;
	record.destination_vmid = 8;
	record.destination_epoch = 10;
	assert(hypertrace_session_record_encode(record.session, 40, &stopped) == 0);
	for (size_t i = 0; i < 32; i++)
		record.challenge[i] = (uint8_t)(0xa0 + i);
	for (size_t i = 0; i < sizeof(dev); i++)
		dev[i] = (uint8_t)(i * 7 + 3);
	SHA256_Init(&hash);
	SHA256_Update(&hash, dev, sizeof(dev));
	SHA256_Final(record.state_digest, &hash);
	memset(record.source_certificate_sha256, 3, 32);
	memset(record.destination_certificate_sha256, 4, 32);
}

static int fresh_directory(char *name) {
	assert(mkdtemp(name) != NULL);
	int fd = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(fd >= 0);
	return (fd);
}

static void fill_ram(uint8_t seed) {
	for (size_t i = 0; i < LOWMEM; i++)
		ram_low[i] = (uint8_t)(i * 13 + seed);
	for (size_t i = 0; i < HIGHMEM; i++)
		ram_high[i] = (uint8_t)(i * 5 + seed + 1);
}

static void test_codecs(void) {
	uint8_t header[MIGRATION_DEST_IMAGE_HEADER_SIZE], mutated[sizeof(header)];
	struct migration_recovery_record decoded;
	struct migration_dest_geometry g;
	uint64_t dev_length;
	unsigned rejected = 0;

	assert(migration_dest_image_header_encode(&record, &geometry, sizeof(dev), header) == 0);
	assert(migration_dest_image_header_decode(header, sizeof(header), &decoded, &g, &dev_length) == 0);
	assert(memcmp(&decoded, &record, sizeof(record)) == 0);
	assert(g.lowmem_length == LOWMEM && g.highmem_base == HIGHBASE && dev_length == sizeof(dev));
	/* Every single-bit mutation and every truncation is refused. */
	for (size_t i = 0; i < sizeof(header); i++)
		for (int bit = 0; bit < 8; bit++) {
			memcpy(mutated, header, sizeof(header));
			mutated[i] ^= (uint8_t)(1 << bit);
			assert(migration_dest_image_header_decode(mutated, sizeof(mutated),
			    &decoded, &g, &dev_length) != 0);
			rejected++;
		}
	for (size_t n = 0; n < sizeof(header); n++, rejected++)
		assert(migration_dest_image_header_decode(header, n, &decoded, &g, &dev_length) == EPROTO);
	/* Invalid geometry and DEV_STATE sizes cannot be encoded. */
	struct migration_dest_geometry bad[] = {
		{ 0, 0, 0 }, { 4097, 0, 0 }, { 4096, 0, 4097 }, { 4096, 4096, 0 },
		{ 8192, 4096, 4096 }, { 4096, 4097, 4096 },
		{ MIGRATION_DEST_IMAGE_MAX_RAM, HIGHBASE, 4096 },
		{ 4096, UINT64_MAX - 4095, 8192 },
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++, rejected++)
		assert(migration_dest_image_header_encode(&record, &bad[i], 1, header) == EINVAL);
	assert(migration_dest_image_header_encode(&record, &geometry, 0, header) == EINVAL);
	assert(migration_dest_image_header_encode(&record, &geometry,
	    MIGRATION_DEST_IMAGE_MAX_DEV + 1ULL, header) == EINVAL);
	struct migration_recovery_record invalid = record;
	invalid.destination_epoch = 9; /* equals the source epoch */
	assert(migration_dest_image_header_encode(&invalid, &geometry, 1, header) == EINVAL);

	/* Successor record. */
	uint8_t digest[32], wire[MIGRATION_DEST_SUCCESSOR_SIZE], copy[sizeof(wire)];
	struct migration_dest_successor s = { 3, 8, 10, 8, 12 }, out;
	assert(migration_dest_binding_digest(&record, digest) == 0);
	assert(migration_dest_successor_encode(digest, &s, wire) == 0);
	assert(migration_dest_successor_decode(wire, sizeof(wire), digest, &out) == 0);
	assert(out.generation == 3 && out.current_epoch == 12);
	for (size_t i = 0; i < sizeof(wire); i++, rejected++) {
		memcpy(copy, wire, sizeof(wire));
		copy[i] ^= 0x40;
		assert(migration_dest_successor_decode(copy, sizeof(copy), digest, &out) != 0);
	}
	for (size_t n = 0; n < sizeof(wire); n++, rejected++)
		assert(migration_dest_successor_decode(wire, n, digest, &out) == EPROTO);
	uint8_t other[32];
	memcpy(other, digest, 32);
	other[0] ^= 1;
	assert(migration_dest_successor_decode(wire, sizeof(wire), other, &out) == ESTALE);
	struct migration_dest_successor invalids[] = {
		{ 0, 8, 10, 8, 12 }, { 1, 0, 10, 8, 12 }, { 1, 8, 0, 8, 12 },
		{ 1, 8, 10, HYPERTRACE_MAX_VMS, 12 }, { 1, 8, 10, 8, 10 },
	};
	for (size_t i = 0; i < sizeof(invalids) / sizeof(invalids[0]); i++, rejected++)
		assert(migration_dest_successor_encode(digest, &invalids[i], wire) == EINVAL);

	/* Challenge parsing. */
	uint8_t challenge[32];
	char text[67];
	migration_dest_stem(record.challenge, text);
	assert(migration_dest_challenge_parse(text + 2, challenge) == 0);
	assert(memcmp(challenge, record.challenge, 32) == 0);
	const char *bad_text[] = { "", "00", "A0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
	    "0000000000000000000000000000000000000000000000000000000000000000",
	    "g0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" };
	for (size_t i = 0; i < sizeof(bad_text) / sizeof(bad_text[0]); i++, rejected++)
		assert(migration_dest_challenge_parse(bad_text[i], challenge) == EINVAL);
	printf("codecs: %u malformed encodings rejected\n", rejected);
}

static void test_write_load_faults(void) {
	unsigned injected = 0;
	/* Fail each write, fsync and rename point in turn. Before rename no image
	 * is visible; a failed directory sync reports error with the image
	 * present (the caller aborts before STAGED). Temp files never remain. */
	for (int kind = 0; kind < 4; kind++) {
		for (int n = 1;; n++) {
			char name[] = "faults.XXXXXX";
			int dirfd = fresh_directory(name), before = fired;
			reset_faults();
			map_fail_at = 0; map_calls = 0;
			if (kind == 0) fail_write = n;
			if (kind == 1) fail_fsync = n;
			if (kind == 2) fail_rename = n;
			if (kind == 3) map_fail_at = n;
			int error = migration_dest_image_write_at(dirfd, &record, &geometry,
			    map, NULL, dev, sizeof(dev));
			bool hit = fired != before;
			reset_faults();
			map_fail_at = 0;
			assert(count_entries(dirfd, ".tmp.") == 0);
			if (!hit) {
				assert(error == 0 && count_entries(dirfd, ".image") == 1);
				close(dirfd);
				break;
			}
			injected++;
			assert(error != 0);
			bool dir_sync = kind == 1 && count_entries(dirfd, ".image") == 1;
			assert(count_entries(dirfd, ".image") == (dir_sync ? 1 : 0));
			if (dir_sync) {
				/* The visible image is complete and loads; it is only
				 * unauthorized because STAGED was never published. */
				uint8_t *out; size_t len;
				assert(migration_dest_image_load_at(dirfd, &record, &geometry,
				    map, NULL, &out, &len) == 0);
				free(out);
				/* An exact retry never replaces an existing image. */
				assert(migration_dest_image_write_at(dirfd, &record, &geometry,
				    map, NULL, dev, sizeof(dev)) == EEXIST);
			}
			close(dirfd);
		}
	}
	printf("write faults: %u injected failures fired\n", injected);
}

static void test_roundtrip_and_corruption(void) {
	char name[] = "image.XXXXXX";
	int dirfd = fresh_directory(name);
	uint8_t *out = NULL, saved_low[64];
	size_t out_len = 0;
	struct migration_recovery_record r;
	struct migration_dest_geometry g;
	uint64_t dev_length;
	char stem[67], path[160];

	/* The bound DEV_STATE digest must match before anything is written. */
	dev[0] ^= 1;
	assert(migration_dest_image_write_at(dirfd, &record, &geometry, map, NULL,
	    dev, sizeof(dev)) == ESTALE);
	dev[0] ^= 1;
	fill_ram(1);
	assert(migration_dest_image_write_at(dirfd, &record, &geometry, map, NULL,
	    dev, sizeof(dev)) == 0);
	assert(migration_dest_image_header_at(dirfd, record.challenge, &r, &g, &dev_length) == 0);
	assert(memcmp(&r, &record, sizeof(r)) == 0 && dev_length == sizeof(dev));
	memcpy(saved_low, ram_low + LOWMEM - 64, 64);
	fill_ram(99);
	assert(migration_dest_image_load_at(dirfd, &record, &geometry, map, NULL,
	    &out, &out_len) == 0);
	assert(out_len == sizeof(dev) && memcmp(out, dev, sizeof(dev)) == 0);
	assert(memcmp(saved_low, ram_low + LOWMEM - 64, 64) == 0);
	assert(ram_high[HIGHMEM - 1] == (uint8_t)((HIGHMEM - 1) * 5 + 2));
	free(out);
	/* Geometry or attempt mismatch is refused before loading RAM. */
	struct migration_dest_geometry other = geometry;
	other.highmem_length -= 4096;
	assert(migration_dest_image_load_at(dirfd, &record, &other, map, NULL,
	    &out, &out_len) == ESTALE);
	struct migration_recovery_record wrong = record;
	wrong.destination_epoch = 77;
	assert(migration_dest_image_load_at(dirfd, &wrong, &geometry, map, NULL,
	    &out, &out_len) != 0);

	/* Corrupt a byte in each region of the file; every load is refused. */
	migration_dest_stem(record.challenge, stem);
	snprintf(path, sizeof(path), "%s/%s.image", name, stem);
	const off_t offsets[] = { 5, 100, 255, 256, 256 + LOWMEM - 1, 256 + LOWMEM,
	    256 + LOWMEM + HIGHMEM, 256 + LOWMEM + HIGHMEM + sizeof(dev) - 1,
	    256 + LOWMEM + HIGHMEM + sizeof(dev) + 31 };
	unsigned corrupt = 0;
	for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		int fd = open(path, O_RDWR);
		uint8_t byte;
		assert(fd >= 0 && pread(fd, &byte, 1, offsets[i]) == 1);
		byte ^= 0x10;
		assert(pwrite(fd, &byte, 1, offsets[i]) == 1);
		assert(migration_dest_image_load_at(dirfd, &record, &geometry, map,
		    NULL, &out, &out_len) != 0);
		byte ^= 0x10;
		assert(pwrite(fd, &byte, 1, offsets[i]) == 1);
		close(fd);
		corrupt++;
	}
	assert(migration_dest_image_load_at(dirfd, &record, &geometry, map, NULL,
	    &out, &out_len) == 0);
	free(out);
	/* Extra or missing bytes are refused. */
	int fd = open(path, O_RDWR | O_APPEND);
	assert(fd >= 0 && write(fd, "x", 1) == 1);
	assert(migration_dest_image_header_at(dirfd, record.challenge, &r, &g, &dev_length) == EPROTO);
	assert(migration_dest_image_load_at(dirfd, &record, &geometry, map, NULL,
	    &out, &out_len) == EPROTO);
	struct stat st;
	assert(fstat(fd, &st) == 0 && ftruncate(fd, st.st_size - 2) == 0);
	assert(migration_dest_image_load_at(dirfd, &record, &geometry, map, NULL,
	    &out, &out_len) == EPROTO);
	close(fd);
	/* File policy: permissive mode and extra links are refused. */
	assert(chmod(path, 0644) == 0);
	assert(migration_dest_image_header_at(dirfd, record.challenge, &r, &g, &dev_length) == EPERM);
	assert(chmod(path, 0600) == 0);
	char link_path[200];
	snprintf(link_path, sizeof(link_path), "%s/alias", name);
	assert(link(path, link_path) == 0);
	assert(migration_dest_image_header_at(dirfd, record.challenge, &r, &g, &dev_length) == EPERM);
	assert(unlink(link_path) == 0);
	/* Retirement removes the image idempotently. */
	assert(migration_dest_image_retire_at(dirfd, record.challenge) == 0);
	assert(migration_dest_image_retire_at(dirfd, record.challenge) == 0);
	assert(migration_dest_image_header_at(dirfd, record.challenge, &r, &g, &dev_length) == ENOENT);
	assert(fchmod(dirfd, 0755) == 0);
	assert(migration_dest_image_write_at(dirfd, &record, &geometry, map, NULL,
	    dev, sizeof(dev)) == EPERM);
	close(dirfd);
	printf("roundtrip: %u corrupted regions refused\n", corrupt);
}

static void test_lock(void) {
	char name[] = "lock.XXXXXX";
	int dirfd = fresh_directory(name), first, second;
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, false, &first) == ENOENT);
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, true, &first) == 0);
	/* A second open file description conflicts, as does creation. */
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, false, &second) == EBUSY);
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, true, &second) == EEXIST);
	/* Another process sees the lock as held while this one lives. */
	fflush(stdout);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		int fd;
		_exit(migration_dest_controller_lock_at(dirfd, record.challenge,
		    false, &fd) == EBUSY ? 0 : 1);
	}
	int status;
	assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
	close(first);
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, false, &second) == 0);
	close(second);
	/* A process that dies while holding the lock releases it. */
	fflush(stdout);
	child = fork();
	assert(child >= 0);
	if (child == 0) {
		int fd;
		if (migration_dest_controller_lock_at(dirfd, record.challenge, false, &fd) != 0)
			_exit(1);
		abort();
	}
	assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, false, &second) == 0);
	close(second);
	uint8_t zero[32] = {0};
	assert(migration_dest_controller_lock_at(dirfd, zero, true, &second) == EINVAL);
	close(dirfd);
}

/* Prepare one preserved, STAGED attempt whose original controller is dead. */
static int preserved(char *name, int extra_phase) {
	int dirfd = fresh_directory(name), lock;
	struct migration_recovery_record r = record;
	assert(migration_dest_controller_lock_at(dirfd, record.challenge, true, &lock) == 0);
	fill_ram(1);
	assert(migration_dest_image_write_at(dirfd, &record, &geometry, map, NULL,
	    dev, sizeof(dev)) == 0);
	if (extra_phase >= MIGRATION_REC_DEST_STAGED) {
		assert(migration_recovery_store_at(dirfd, &r) == 0);
		for (int p = MIGRATION_REC_DEST_STAGED + 1; p <= extra_phase; p++) {
			r.phase = (uint16_t)p;
			assert(migration_recovery_store_at(dirfd, &r) == 0);
		}
	}
	close(lock);
	return (dirfd);
}

static void test_reconstruct(void) {
	struct migration_dest_reconstruction admitted;
	struct migration_dest_successor s;
	uint8_t digest[32];
	unsigned refusals = 0;
	assert(migration_dest_binding_digest(&record, digest) == 0);

	/* The original destination identity is still live: EBUSY without a name
	 * and nothing is published. */
	{
		char name[] = "live.XXXXXX";
		int dirfd = preserved(name, MIGRATION_REC_DEST_STAGED);
		live_vmid[0] = 8; live_epoch[0] = 10;
		witness_calls = destroy_calls = 0;
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &admitted) == EBUSY);
		assert(witness_calls == 1 && destroy_calls == 0);
		assert(migration_dest_successor_load_at(dirfd, record.challenge, digest, &s) == ENOENT);
		/* A failed exact destruction remains an error. */
		destroy_error = ESTALE;
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, "orphan",
		    9, 20, &ops, NULL, &admitted) == ESTALE);
		assert(destroy_calls == 1);
		destroy_error = 0;
		assert(migration_dest_successor_load_at(dirfd, record.challenge, digest, &s) == ENOENT);
		/* Name-hinted exact destruction followed by an affirmative witness. */
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, "orphan",
		    9, 20, &ops, NULL, &admitted) == 0);
		assert(destroy_calls == 2 && live_vmid[0] == 0);
		assert(admitted.controller >= 0 && admitted.successor.generation == 1);
		assert(admitted.successor.previous_vmid == 8 && admitted.successor.previous_epoch == 10);
		assert(admitted.successor.current_vmid == 9 && admitted.successor.current_epoch == 20);
		assert(memcmp(&admitted.record, &record, sizeof(record)) == 0);
		assert(migration_dest_successor_load_at(dirfd, record.challenge, digest, &s) == 0);
		assert(s.generation == 1 && s.current_epoch == 20);
		/* While this successor lives, a competing successor is refused. */
		struct migration_dest_reconstruction competitor;
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 21, &ops, NULL, &competitor) == EBUSY);
		/* Successor dies before resume. Its own lifetime is now the previous
		 * incarnation and must be retired before generation 2. */
		close(admitted.controller);
		live_vmid[1] = 9; live_epoch[1] = 20;
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 21, &ops, NULL, &competitor) == EBUSY);
		live_vmid[1] = 0; live_epoch[1] = 0;
		/* The context may not be the previous incarnation itself. */
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &competitor) == EBUSY);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    8, 10, &ops, NULL, &competitor) == EBUSY);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    7, 9, &ops, NULL, &competitor) == EBUSY);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 22, &ops, NULL, &competitor) == 0);
		assert(competitor.successor.generation == 2);
		assert(competitor.successor.previous_vmid == 9 && competitor.successor.previous_epoch == 20);
		/* The image itself still loads exactly for the new incarnation. */
		uint8_t *out; size_t len;
		fill_ram(55);
		assert(migration_dest_image_load_at(dirfd, &competitor.record,
		    &competitor.geometry, map, NULL, &out, &len) == 0);
		assert(ram_low[0] == 1 && len == sizeof(dev));
		free(out);
		close(competitor.controller);
		refusals += 7;
		/* Corrupt successor evidence is never replaced or ignored. */
		char stem[67], path[200];
		migration_dest_stem(record.challenge, stem);
		snprintf(path, sizeof(path), "%s/%s.successor", name, stem);
		int fd = open(path, O_RDWR);
		uint8_t byte;
		assert(fd >= 0 && pread(fd, &byte, 1, 60) == 1);
		byte ^= 1;
		assert(pwrite(fd, &byte, 1, 60) == 1);
		close(fd);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 23, &ops, NULL, &competitor) == EPROTO);
		refusals++;
		close(dirfd);
	}
	/* Missing STAGED: the source can never have retired; refuse. */
	{
		char name[] = "unstaged.XXXXXX";
		int dirfd = preserved(name, 0);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &admitted) == ENOENT);
		close(dirfd);
		refusals++;
	}
	/* RELEASED and RUNNING may already have executed: quarantine. */
	for (int phase = MIGRATION_REC_DEST_RELEASED; phase <= MIGRATION_REC_DEST_RUNNING; phase++) {
		char name[] = "released.XXXXXX";
		int dirfd = preserved(name, phase);
		witness_calls = 0;
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &admitted) == ENOTRECOVERABLE);
		assert(witness_calls == 0);
		assert(migration_dest_successor_load_at(dirfd, record.challenge, digest, &s) == ENOENT);
		close(dirfd);
		refusals++;
	}
	/* No image or controller lock: nothing was preserved. */
	{
		char name[] = "none.XXXXXX";
		int dirfd = fresh_directory(name);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &admitted) == ENOENT);
		close(dirfd);
		refusals++;
	}
	/* Witness errors (unsupported/unavailable query) are not retirement. */
	{
		char name[] = "witness.XXXXXX";
		int dirfd = preserved(name, MIGRATION_REC_DEST_STAGED);
		const int errors[] = { ENXIO, ENOTTY, EOPNOTSUPP, EPROTO, EINVAL };
		for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
			witness_error = errors[i];
			destroy_calls = 0;
			assert(migration_dest_reconstruct_begin(dirfd, record.challenge,
			    "orphan", 9, 20, &ops, NULL, &admitted) == errors[i]);
			assert(destroy_calls == 0);
			refusals++;
		}
		witness_error = 0;
		/* Sync faults: 1 = STAGED evidence reread, 3 = successor file,
		 * 4 = directory after the successor rename. Nothing is admitted;
		 * a visible but unsynced successor names this context, so a retry
		 * by the same incarnation is refused rather than ignored. */
		for (int point = 1; point <= 4; point++) {
			if (point == 2)
				continue;
			reset_faults();
			fail_fsync = point;
			int before = fired;
			assert(migration_dest_reconstruct_begin(dirfd, record.challenge,
			    NULL, 9, 20, &ops, NULL, &admitted) == EIO);
			assert(fired == before + 1);
			reset_faults();
			int found = migration_dest_successor_load_at(dirfd,
			    record.challenge, digest, &s);
			assert(found == (point == 4 ? 0 : ENOENT));
			refusals++;
		}
		assert(s.current_vmid == 9 && s.current_epoch == 20);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &ops, NULL, &admitted) == EBUSY);
		/* Invalid arguments. */
		struct migration_dest_reconstruct_ops partial = { retired, NULL };
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    9, 20, &partial, NULL, &admitted) == EINVAL);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, "",
		    9, 20, &ops, NULL, &admitted) == EINVAL);
		assert(migration_dest_reconstruct_begin(dirfd, record.challenge, NULL,
		    0, 20, &ops, NULL, &admitted) == EINVAL);
		refusals += 4;
		close(dirfd);
	}
	printf("reconstruct: %u refusals and two successor generations verified\n", refusals);
}

int main(void) {
	ram_low = malloc(LOWMEM);
	ram_high = malloc(HIGHMEM);
	assert(ram_low != NULL && ram_high != NULL);
	make_record();
	test_codecs();
	test_write_load_faults();
	test_roundtrip_and_corruption();
	test_lock();
	test_reconstruct();
	free(ram_low);
	free(ram_high);
	puts("PASS: durable destination image, successor publication, controller lock and reconstruction admission");
	return (0);
}

#include <sys/endian.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "snapshot_devmem.h"

static unsigned int injected_pread_call;
static unsigned int injected_pread_failure;
static unsigned int injected_mutation_call;
static off_t injected_mutation_offset;
static uint8_t injected_mutation_value;

static ssize_t
snapshot_devmem_test_pread(int fd, void *buffer, size_t length, off_t offset)
{
	ssize_t result;

	injected_pread_call++;
	if (injected_pread_failure != 0 &&
	    injected_pread_call == injected_pread_failure) {
		errno = EIO;
		return (-1);
	}
	result = pread(fd, buffer, length, offset);
	if (result >= 0 && injected_mutation_call != 0 &&
	    injected_pread_call == injected_mutation_call &&
	    pwrite(fd, &injected_mutation_value, 1,
	    injected_mutation_offset) != 1) {
		if (errno == 0)
			errno = EIO;
		return (-1);
	}
	return (result);
}

/*
 * Include the codec itself so this rootless test exercises the production
 * implementation without linking the rest of bhyve.
 */
#define	pread snapshot_devmem_test_pread
#include "snapshot_devmem.c"
#undef pread

#define	NORMAL_MEMORY_SIZE	7

static int
temporary_file(void)
{
	char path[] = "/tmp/snapshot-devmem.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE_MSG(fd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(ftruncate(fd, NORMAL_MEMORY_SIZE) == 0);
	return (fd);
}

static off_t
file_size(int fd)
{
	struct stat sb;

	ATF_REQUIRE(fstat(fd, &sb) == 0);
	return (sb.st_size);
}

static void
write_all_at(int fd, const void *data, size_t length, off_t offset)
{
	const uint8_t *cursor;
	ssize_t written;

	cursor = data;
	while (length != 0) {
		written = pwrite(fd, cursor, length, offset);
		ATF_REQUIRE_MSG(written > 0, "pwrite: %s", strerror(errno));
		cursor += written;
		offset += written;
		length -= (size_t)written;
	}
}

static void
read_all_at(int fd, void *data, size_t length, off_t offset)
{
	uint8_t *cursor;
	ssize_t done;

	cursor = data;
	while (length != 0) {
		done = pread(fd, cursor, length, offset);
		ATF_REQUIRE_MSG(done > 0, "pread: %s", strerror(errno));
		cursor += done;
		offset += done;
		length -= (size_t)done;
	}
}

static void
set_region(struct bhyve_devmem_region *region, const char *name, void *memory,
    size_t length)
{

	memset(region, 0, sizeof(*region));
	strlcpy(region->name, name, sizeof(region->name));
	region->host_base = memory;
	region->length = length;
}

ATF_TC_WITHOUT_HEAD(roundtrip_and_golden_encoding);
ATF_TC_BODY(roundtrip_and_golden_encoding, tc)
{
	static const uint8_t alpha[] = { 1, 2, 3 };
	static const uint8_t zeta[] = { 0xaa, 0xbb };
	struct bhyve_devmem_region source[2], destination[2];
	uint8_t alpha_out[sizeof(alpha)], zeta_out[sizeof(zeta)];
	uint8_t bytes[117];
	size_t extension_size;
	int fd;

	fd = temporary_file();
	/* Supply reverse order; the encoded table must still be canonical. */
	set_region(&source[0], "zeta", __DECONST(void *, zeta), sizeof(zeta));
	set_region(&source[1], "alpha", __DECONST(void *, alpha),
	    sizeof(alpha));
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    source, nitems(source), &extension_size), 0);
	ATF_CHECK_EQ(extension_size, sizeof(bytes));
	ATF_CHECK_EQ(file_size(fd), NORMAL_MEMORY_SIZE + (off_t)sizeof(bytes));

	read_all_at(fd, bytes, sizeof(bytes), NORMAL_MEMORY_SIZE);
	ATF_CHECK(memcmp(bytes, "BHVDEM1\0", 8) == 0);
	ATF_CHECK_EQ(le16dec(bytes + 8), 1);
	ATF_CHECK_EQ(le16dec(bytes + 10), 32);
	ATF_CHECK_EQ(le16dec(bytes + 12), 40);
	ATF_CHECK_EQ(le16dec(bytes + 14), 0);
	ATF_CHECK_EQ(le32dec(bytes + 16), 2);
	ATF_CHECK_EQ(le32dec(bytes + 20), 0);
	ATF_CHECK_EQ(le64dec(bytes + 24), sizeof(bytes));

	ATF_CHECK(memcmp(bytes + 32, "alpha\0", 6) == 0);
	for (size_t i = 38; i < 48; i++)
		ATF_CHECK_EQ(bytes[i], 0);
	ATF_CHECK_EQ(le64dec(bytes + 48), sizeof(alpha));
	ATF_CHECK_EQ(le64dec(bytes + 56), 112);
	ATF_CHECK_EQ(le64dec(bytes + 64), UINT64_C(0xd0aa6218672cf5ab));
	ATF_CHECK(memcmp(bytes + 72, "zeta\0", 5) == 0);
	for (size_t i = 77; i < 88; i++)
		ATF_CHECK_EQ(bytes[i], 0);
	ATF_CHECK_EQ(le64dec(bytes + 88), sizeof(zeta));
	ATF_CHECK_EQ(le64dec(bytes + 96), 115);
	ATF_CHECK_EQ(le64dec(bytes + 104), UINT64_C(0x099a0d07b61c47f2));
	ATF_CHECK(memcmp(bytes + 112, alpha, sizeof(alpha)) == 0);
	ATF_CHECK(memcmp(bytes + 115, zeta, sizeof(zeta)) == 0);

	memset(alpha_out, 0, sizeof(alpha_out));
	memset(zeta_out, 0, sizeof(zeta_out));
	set_region(&destination[0], "alpha", alpha_out, sizeof(alpha_out));
	set_region(&destination[1], "zeta", zeta_out, sizeof(zeta_out));
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_validate(fd,
	    NORMAL_MEMORY_SIZE, file_size(fd), destination,
	    nitems(destination)), 0);
	for (size_t i = 0; i < sizeof(alpha_out); i++)
		ATF_CHECK_EQ(alpha_out[i], 0);
	for (size_t i = 0; i < sizeof(zeta_out); i++)
		ATF_CHECK_EQ(zeta_out[i], 0);
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), destination, nitems(destination)), 0);
	ATF_CHECK(memcmp(alpha_out, alpha, sizeof(alpha)) == 0);
	ATF_CHECK(memcmp(zeta_out, zeta, sizeof(zeta)) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(empty_and_identity_validation);
ATF_TC_BODY(empty_and_identity_validation, tc)
{
	struct bhyve_devmem_region regions[2];
	uint8_t memory[8] = { 1, 2, 3, 4 };
	size_t extension_size;
	int fd;

	fd = temporary_file();
	extension_size = SIZE_MAX;
	ATF_CHECK_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE, NULL, 0,
	    &extension_size), 0);
	ATF_CHECK_EQ(extension_size, 0);
	ATF_CHECK_EQ(file_size(fd), NORMAL_MEMORY_SIZE);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_validate(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), NULL, 0), 0);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), NULL, 0), 0);

	set_region(&regions[0], "same", memory, sizeof(memory));
	set_region(&regions[1], "same", memory, sizeof(memory));
	ATF_CHECK_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE, regions,
	    nitems(regions), &extension_size), EEXIST);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), regions, 1), ENOENT);

	set_region(&regions[0], "left", memory, 6);
	set_region(&regions[1], "right", memory + 4, 4);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE, regions,
	    nitems(regions), &extension_size), EINVAL);
	set_region(&regions[0], "metadata", regions, sizeof(regions));
	ATF_CHECK_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE, regions,
	    1, &extension_size), EINVAL);

	memset(&regions[0], 0, sizeof(regions[0]));
	regions[0].host_base = memory;
	regions[0].length = sizeof(memory);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE, regions,
	    1, &extension_size), EINVAL);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(corruption_is_detected_before_mutation);
ATF_TC_BODY(corruption_is_detected_before_mutation, tc)
{
	struct bhyve_devmem_region source, destination;
	struct bhyve_devmem_region *aliased_destination;
	uint8_t input[8193], corrupt;
	_Alignas(struct bhyve_devmem_region) uint8_t output[sizeof(input)];
	size_t extension_size;
	int fd;

	for (size_t i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(i * 37U + 11U);
	memset(output, 0x5a, sizeof(output));
	set_region(&source, "payload", input, sizeof(input));
	set_region(&destination, "payload", output, sizeof(output));
	fd = temporary_file();
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    &source, 1, &extension_size), 0);
	aliased_destination = (void *)output;
	set_region(aliased_destination, "payload", output, sizeof(output));
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), aliased_destination, 1), EINVAL);
	memset(output, 0x5a, sizeof(output));
	set_region(&destination, "payload", output, sizeof(output));
	corrupt = input[4000] ^ 0xff;
	write_all_at(fd, &corrupt, 1,
	    NORMAL_MEMORY_SIZE + DEVMEM_HEADER_SIZE + DEVMEM_ENTRY_SIZE + 4000);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_validate(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), &destination, 1), EPROTO);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), &destination, 1), EPROTO);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0x5a);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(malformed_metadata_rejected);
ATF_TC_BODY(malformed_metadata_rejected, tc)
{
	struct bhyve_devmem_region source, destination;
	uint8_t input[] = { 1, 3, 5, 7 }, output[sizeof(input)];
	uint8_t pristine[DEVMEM_HEADER_SIZE + DEVMEM_ENTRY_SIZE + sizeof(input)];
	uint8_t mutated[sizeof(pristine)];
	size_t extension_size;
	int fd;

	set_region(&source, "region", input, sizeof(input));
	set_region(&destination, "region", output, sizeof(output));
	fd = temporary_file();
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    &source, 1, &extension_size), 0);
	ATF_REQUIRE_EQ(extension_size, sizeof(pristine));
	read_all_at(fd, pristine, sizeof(pristine), NORMAL_MEMORY_SIZE);

#define	REJECT_MUTATION(statement) do {					\
	memcpy(mutated, pristine, sizeof(mutated));				\
	statement;								\
	write_all_at(fd, mutated, sizeof(mutated), NORMAL_MEMORY_SIZE);	\
	memset(output, 0xa5, sizeof(output));				\
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd,			\
	    NORMAL_MEMORY_SIZE, file_size(fd), &destination, 1), EPROTO);	\
} while (0)

	REJECT_MUTATION(mutated[0] ^= 1);
	REJECT_MUTATION(le16enc(mutated + 8, 2));
	REJECT_MUTATION(le16enc(mutated + 10, 31));
	REJECT_MUTATION(le16enc(mutated + 12, 39));
	REJECT_MUTATION(mutated[14] = 1);
	REJECT_MUTATION(mutated[20] = 1);
	REJECT_MUTATION(le32enc(mutated + 16, 0));
	REJECT_MUTATION(le64enc(mutated + 24, sizeof(mutated) - 1));
	REJECT_MUTATION(mutated[32] = '\0');
	REJECT_MUTATION(mutated[39] = 1);
	REJECT_MUTATION(le64enc(mutated + 48, 0));
	REJECT_MUTATION(le64enc(mutated + 56, 71));
	REJECT_MUTATION(mutated[64] ^= 1);
#undef REJECT_MUTATION

	write_all_at(fd, pristine, sizeof(pristine), NORMAL_MEMORY_SIZE);
	ATF_REQUIRE(ftruncate(fd, file_size(fd) - 1) == 0);
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), &destination, 1), EPROTO);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(streaming_large_region);
ATF_TC_BODY(streaming_large_region, tc)
{
	const size_t length = DEVMEM_IO_CHUNK * 2 + 17;
	struct bhyve_devmem_region source, destination;
	uint8_t *input, *output;
	size_t extension_size;
	int fd;

	input = malloc(length);
	output = malloc(length);
	ATF_REQUIRE(input != NULL);
	ATF_REQUIRE(output != NULL);
	for (size_t i = 0; i < length; i++)
		input[i] = (uint8_t)(i * 13U + 9U);
	memset(output, 0, length);
	set_region(&source, "large", input, length);
	set_region(&destination, "large", output, length);
	fd = temporary_file();
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    &source, 1, &extension_size), 0);
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), &destination, 1), 0);
	ATF_CHECK(memcmp(input, output, length) == 0);
	ATF_REQUIRE(close(fd) == 0);
	free(output);
	free(input);
}

ATF_TC_WITHOUT_HEAD(read_failure_is_atomic_across_regions);
ATF_TC_BODY(read_failure_is_atomic_across_regions, tc)
{
	static const uint8_t alpha[] = { 1, 2, 3 };
	static const uint8_t zeta[] = { 4, 5, 6, 7 };
	struct bhyve_devmem_region source[2], destination[2];
	uint8_t alpha_out[sizeof(alpha)], zeta_out[sizeof(zeta)];
	size_t extension_size;
	int fd;

	set_region(&source[0], "alpha", __DECONST(void *, alpha),
	    sizeof(alpha));
	set_region(&source[1], "zeta", __DECONST(void *, zeta), sizeof(zeta));
	memset(alpha_out, 0xa5, sizeof(alpha_out));
	memset(zeta_out, 0x5a, sizeof(zeta_out));
	set_region(&destination[0], "alpha", alpha_out, sizeof(alpha_out));
	set_region(&destination[1], "zeta", zeta_out, sizeof(zeta_out));
	fd = temporary_file();
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    source, nitems(source), &extension_size), 0);

	/*
	 * Header and two table entries consume calls 1-3.  Fail the second staged
	 * payload read.  Neither destination may have been published when that
	 * failure is reported.
	 */
	injected_pread_call = 0;
	injected_pread_failure = 5;
	ATF_CHECK_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), destination, nitems(destination)), EIO);
	injected_pread_failure = 0;
	for (size_t i = 0; i < sizeof(alpha_out); i++)
		ATF_CHECK_EQ(alpha_out[i], 0xa5);
	for (size_t i = 0; i < sizeof(zeta_out); i++)
		ATF_CHECK_EQ(zeta_out[i], 0x5a);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(staged_bytes_close_digest_reread_race);
ATF_TC_BODY(staged_bytes_close_digest_reread_race, tc)
{
	static const uint8_t alpha[] = { 1, 2, 3 };
	static const uint8_t zeta[] = { 4, 5, 6, 7 };
	struct bhyve_devmem_region source[2], destination[2];
	uint8_t alpha_out[sizeof(alpha)], zeta_out[sizeof(zeta)];
	size_t extension_size;
	int fd;

	set_region(&source[0], "alpha", __DECONST(void *, alpha),
	    sizeof(alpha));
	set_region(&source[1], "zeta", __DECONST(void *, zeta), sizeof(zeta));
	memset(alpha_out, 0, sizeof(alpha_out));
	memset(zeta_out, 0, sizeof(zeta_out));
	set_region(&destination[0], "alpha", alpha_out, sizeof(alpha_out));
	set_region(&destination[1], "zeta", zeta_out, sizeof(zeta_out));
	fd = temporary_file();
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_save(fd, NORMAL_MEMORY_SIZE,
	    source, nitems(source), &extension_size), 0);

	/*
	 * Mutate alpha after the fifth pread.  A hash-then-reread restore hashes
	 * both regions by that point but has not copied alpha, and would publish
	 * the changed byte.  The transactional restore has already staged and
	 * hashed both payloads, so it publishes one internally consistent image.
	 */
	injected_pread_call = 0;
	injected_mutation_call = 5;
	injected_mutation_offset = NORMAL_MEMORY_SIZE + DEVMEM_HEADER_SIZE +
	    2 * DEVMEM_ENTRY_SIZE;
	injected_mutation_value = 0xff;
	ATF_REQUIRE_EQ(bhyve_devmem_snapshot_restore(fd, NORMAL_MEMORY_SIZE,
	    file_size(fd), destination, nitems(destination)), 0);
	injected_mutation_call = 0;
	ATF_CHECK(memcmp(alpha_out, alpha, sizeof(alpha_out)) == 0);
	ATF_CHECK(memcmp(zeta_out, zeta, sizeof(zeta_out)) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, roundtrip_and_golden_encoding);
	ATF_TP_ADD_TC(tp, empty_and_identity_validation);
	ATF_TP_ADD_TC(tp, corruption_is_detected_before_mutation);
	ATF_TP_ADD_TC(tp, malformed_metadata_rejected);
	ATF_TP_ADD_TC(tp, streaming_large_region);
	ATF_TP_ADD_TC(tp, read_failure_is_atomic_across_regions);
	ATF_TP_ADD_TC(tp, staged_bytes_close_digest_reread_race);
	return (atf_no_error());
}

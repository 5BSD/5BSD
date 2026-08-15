/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "virtiofsd_fuse.c"

#define	DOC_FUSE_IN_HEADER_SIZE		40U
#define	DOC_FUSE_OUT_HEADER_SIZE	16U
#define	DOC_FUSE_INIT			26U
#define	DOC_FUSE_LOOKUP			1U
#define	DOC_FUSE_BATCH_FORGET		42U
#define	DOC_FUSE_READ			15U
#define	DOC_FUSE_READ_IN_SIZE		40U
#define	DOC_FUSE_READ_LOCKOWNER		(1U << 1)
#define	DOC_LINUX_EDEADLK		35
#define	DOC_LINUX_ESTALE		116
#define	DOC_LINUX_EIO			5

static void
request_header(uint8_t output[static DOC_FUSE_IN_HEADER_SIZE],
    enum virtiofsd_fuse_byte_order order, uint32_t length, uint32_t opcode,
    uint64_t unique, uint64_t nodeid)
{

	memset(output, 0, DOC_FUSE_IN_HEADER_SIZE);
	if (order == VIRTIOFSD_FUSE_ORDER_BIG) {
		be32enc(output, length);
		be32enc(output + 4, opcode);
		be64enc(output + 8, unique);
		be64enc(output + 16, nodeid);
		be32enc(output + 24, 1001);
		be32enc(output + 28, 1002);
		be32enc(output + 32, 1003);
	} else {
		le32enc(output, length);
		le32enc(output + 4, opcode);
		le64enc(output + 8, unique);
		le64enc(output + 16, nodeid);
		le32enc(output + 24, 1001);
		le32enc(output + 28, 1002);
		le32enc(output + 32, 1003);
	}
}

ATF_TC_WITHOUT_HEAD(request_byte_order_is_established_only_by_init);
ATF_TC_BODY(request_byte_order_is_established_only_by_init, tc)
{
	struct virtiofsd_fuse_request request;
	uint8_t wire[DOC_FUSE_IN_HEADER_SIZE + VIRTIOFSD_FUSE_INIT_IN_SIZE];

	request_header(wire, VIRTIOFSD_FUSE_ORDER_LITTLE, sizeof(wire),
	    DOC_FUSE_INIT, 11, 1);
	le32enc(wire + 40, 7);
	le32enc(wire + 44, 35);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_UNKNOWN, &request), 0);
	ATF_CHECK_EQ(request.byte_order, VIRTIOFSD_FUSE_ORDER_LITTLE);
	ATF_CHECK_EQ(request.opcode, DOC_FUSE_INIT);
	ATF_CHECK_EQ(request.unique, 11);
	ATF_CHECK_EQ(request.uid, 1001);

	request_header(wire, VIRTIOFSD_FUSE_ORDER_BIG, sizeof(wire),
	    DOC_FUSE_INIT, 12, 1);
	be32enc(wire + 40, 7);
	be32enc(wire + 44, 35);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_UNKNOWN, &request), 0);
	ATF_CHECK_EQ(request.byte_order, VIRTIOFSD_FUSE_ORDER_BIG);
	ATF_CHECK_EQ(request.unique, 12);

	request_header(wire, VIRTIOFSD_FUSE_ORDER_LITTLE, sizeof(wire),
	    DOC_FUSE_LOOKUP, 13, 1);
	ATF_CHECK_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_UNKNOWN, &request), EPROTO);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), 0);
}

ATF_TC_WITHOUT_HEAD(request_lengths_names_and_reserved_fields_fail_closed);
ATF_TC_BODY(request_lengths_names_and_reserved_fields_fail_closed, tc)
{
	struct virtiofsd_fuse_request request;
	const void *name;
	uint8_t wire[DOC_FUSE_IN_HEADER_SIZE + 5];
	size_t name_len;

	request_header(wire, VIRTIOFSD_FUSE_ORDER_LITTLE, sizeof(wire),
	    DOC_FUSE_LOOKUP, 21, 1);
	memcpy(wire + 40, "name", 5);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), 0);
	ATF_REQUIRE_EQ(virtiofsd_fuse_name(&request, &name, &name_len), 0);
	ATF_CHECK_EQ(name_len, 4);
	ATF_CHECK_EQ(memcmp(name, "name", 4), 0);

	wire[42] = '\0';
	ATF_CHECK_EQ(virtiofsd_fuse_name(&request, &name, &name_len), EPROTO);
	wire[42] = 'm';
	le32enc(wire + 36, 1);
	ATF_CHECK_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), EPROTO);
	le32enc(wire + 36, 0);
	le32enc(wire, sizeof(wire) - 1);
	ATF_CHECK_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), EPROTO);
	le32enc(wire, sizeof(wire));
	le64enc(wire + 8, 0);
	ATF_CHECK_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), EPROTO);
}

ATF_TC_WITHOUT_HEAD(batch_forget_is_exact_bounded_and_endian_explicit);
ATF_TC_BODY(batch_forget_is_exact_bounded_and_endian_explicit, tc)
{
	struct virtiofsd_fuse_forget_one entry;
	struct virtiofsd_fuse_request request;
	uint8_t wire[80];
	uint32_t count;

	memset(wire, 0, sizeof(wire));
	request_header(wire, VIRTIOFSD_FUSE_ORDER_BIG, sizeof(wire),
	    DOC_FUSE_BATCH_FORGET, 14, 1);
	be32enc(wire + 40, 2);
	be64enc(wire + 48, 0x100000002ULL);
	be64enc(wire + 56, 3);
	be64enc(wire + 64, 1);
	be64enc(wire + 72, 4);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_BIG, &request), 0);
	ATF_REQUIRE_EQ(virtiofsd_fuse_batch_forget_decode(&request, &count),
	    0);
	ATF_CHECK_EQ(count, 2);
	ATF_REQUIRE_EQ(virtiofsd_fuse_batch_forget_entry(&request, 0,
	    &entry), 0);
	ATF_CHECK_EQ(entry.nodeid, 0x100000002ULL);
	ATF_CHECK_EQ(entry.count, 3);
	ATF_REQUIRE_EQ(virtiofsd_fuse_batch_forget_entry(&request, 1,
	    &entry), 0);
	ATF_CHECK_EQ(entry.nodeid, 1);
	ATF_CHECK_EQ(entry.count, 4);
	ATF_CHECK_EQ(virtiofsd_fuse_batch_forget_entry(&request, 2,
	    &entry), ERANGE);

	be32enc(wire + 44, 1);
	ATF_CHECK_EQ(virtiofsd_fuse_batch_forget_decode(&request, &count),
	    EPROTO);
	be32enc(wire + 44, 0);
	request.body_len--;
	ATF_CHECK_EQ(virtiofsd_fuse_batch_forget_decode(&request, &count),
	    EPROTO);
}

ATF_TC_WITHOUT_HEAD(errors_are_linux_wire_values_not_host_errno);
ATF_TC_BODY(errors_are_linux_wire_values_not_host_errno, tc)
{
	uint8_t wire[DOC_FUSE_OUT_HEADER_SIZE];

	ATF_REQUIRE_EQ(virtiofsd_fuse_error_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 31, EDEADLK, wire), 0);
	ATF_CHECK_EQ(le32dec(wire), DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(wire + 4), -DOC_LINUX_EDEADLK);
	ATF_CHECK_EQ(le64dec(wire + 8), 31);

	ATF_REQUIRE_EQ(virtiofsd_fuse_error_encode(
	    VIRTIOFSD_FUSE_ORDER_BIG, 32, ESTALE, wire), 0);
	ATF_CHECK_EQ((int32_t)be32dec(wire + 4), -DOC_LINUX_ESTALE);
	ATF_CHECK_EQ(be64dec(wire + 8), 32);

	/* A host-only errno is represented safely as protocol EIO. */
	ATF_REQUIRE_EQ(virtiofsd_fuse_error_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 33, EPROGMISMATCH, wire), 0);
	ATF_CHECK_EQ((int32_t)le32dec(wire + 4), -DOC_LINUX_EIO);
}

ATF_TC_WITHOUT_HEAD(read_flags_and_padding_are_independently_validated);
ATF_TC_BODY(read_flags_and_padding_are_independently_validated, tc)
{
	struct virtiofsd_fuse_read read_request;
	struct virtiofsd_fuse_request request;
	uint8_t wire[DOC_FUSE_IN_HEADER_SIZE + DOC_FUSE_READ_IN_SIZE];

	memset(wire, 0, sizeof(wire));
	request_header(wire, VIRTIOFSD_FUSE_ORDER_LITTLE, sizeof(wire),
	    DOC_FUSE_READ, 35, 2);
	le64enc(wire + 40, 7);
	le64enc(wire + 48, 8);
	le32enc(wire + 56, 9);
	le32enc(wire + 60, DOC_FUSE_READ_LOCKOWNER);
	le64enc(wire + 64, 10);
	le32enc(wire + 72, 0x8000);
	ATF_REQUIRE_EQ(virtiofsd_fuse_request_decode(wire, sizeof(wire),
	    VIRTIOFSD_FUSE_ORDER_LITTLE, &request), 0);
	ATF_REQUIRE_EQ(virtiofsd_fuse_read_decode(&request, &read_request),
	    0);
	ATF_CHECK_EQ(read_request.handle, 7);
	ATF_CHECK_EQ(read_request.offset, 8);
	ATF_CHECK_EQ(read_request.size, 9);
	ATF_CHECK_EQ(read_request.read_flags, DOC_FUSE_READ_LOCKOWNER);
	ATF_CHECK_EQ(read_request.lock_owner, 10);
	ATF_CHECK_EQ(read_request.flags, 0x8000);

	le32enc(wire + 60, 1);
	ATF_CHECK_EQ(virtiofsd_fuse_read_decode(&request, &read_request),
	    EPROTO);
	le32enc(wire + 60, DOC_FUSE_READ_LOCKOWNER);
	le32enc(wire + 76, 1);
	ATF_CHECK_EQ(virtiofsd_fuse_read_decode(&request, &read_request),
	    EPROTO);
}

ATF_TC_WITHOUT_HEAD(response_structures_are_explicit_and_zero_reserved);
ATF_TC_BODY(response_structures_are_explicit_and_zero_reserved, tc)
{
	struct virtiofsd_fuse_init init;
	struct virtiofsd_fuse_statfs statfs;
	struct stat sb;
	uint8_t entry[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_ENTRY_OUT_SIZE];
	uint8_t init_wire[VIRTIOFSD_FUSE_OUT_HEADER_SIZE +
	    VIRTIOFSD_FUSE_INIT_OUT_SIZE];
	size_t i;

	init = (struct virtiofsd_fuse_init) {
		.major = 7,
		.minor = 99,
		.max_readahead = 65536,
		.flags = 0xffffffffU,
	};
	ATF_REQUIRE_EQ(virtiofsd_fuse_init_response_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 41, &init, 0x21, 131072,
	    init_wire), 0);
	ATF_CHECK_EQ(le32dec(init_wire), sizeof(init_wire));
	ATF_CHECK_EQ(le32dec(init_wire + 16), 7);
	ATF_CHECK_EQ(le32dec(init_wire + 20), 35);
	ATF_CHECK_EQ(le32dec(init_wire + 28), 0x21);
	ATF_CHECK_EQ(le32dec(init_wire + 36), 131072);
	for (i = 44; i < sizeof(init_wire); i++)
		ATF_CHECK_EQ(init_wire[i], 0);

	memset(&sb, 0, sizeof(sb));
	sb.st_ino = 51;
	sb.st_mode = S_IFREG | 0640;
	sb.st_nlink = 2;
	sb.st_size = 1234;
	sb.st_blocks = 3;
	sb.st_blksize = 4096;
	sb.st_uid = 1001;
	sb.st_gid = 1002;
	sb.st_rdev = 0x1234;
	ATF_REQUIRE_EQ(virtiofsd_fuse_entry_response_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 42, 52, 7, &sb, entry), 0);
	ATF_CHECK_EQ(le32dec(entry), sizeof(entry));
	ATF_CHECK_EQ(le64dec(entry + 16), 52);
	ATF_CHECK_EQ(le64dec(entry + 24), 7);
	ATF_CHECK_EQ(le64dec(entry + 56), 51);
	ATF_CHECK_EQ(le32dec(entry + 116), (uint32_t)sb.st_mode);
	ATF_CHECK_EQ(le32dec(entry + 132), 0);
	ATF_CHECK_EQ(le32dec(entry + 140), 0);

	memset(entry, 0xa5, sizeof(entry));
	ATF_REQUIRE_EQ(virtiofsd_fuse_dirent_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 61, 7, 8, "name", 4, entry,
	    sizeof(entry), &i), 0);
	ATF_CHECK_EQ(i, 32);
	ATF_CHECK_EQ(le64dec(entry), 61);
	ATF_CHECK_EQ(le64dec(entry + 8), 7);
	ATF_CHECK_EQ(le32dec(entry + 16), 4);
	ATF_CHECK_EQ(le32dec(entry + 20), 8);
	ATF_CHECK_EQ(memcmp(entry + 24, "name", 4), 0);
	for (size_t padding = 28; padding < i; padding++)
		ATF_CHECK_EQ(entry[padding], 0);
	ATF_CHECK_EQ(virtiofsd_fuse_dirent_encode(
	    VIRTIOFSD_FUSE_ORDER_LITTLE, 61, 7, 8, "bad/name", 8, entry,
	    sizeof(entry), &i), EINVAL);

	statfs = (struct virtiofsd_fuse_statfs) {
		.blocks = 101,
		.free_blocks = 102,
		.available_blocks = 103,
		.files = 104,
		.free_files = 105,
		.block_size = 4096,
		.maximum_name = 255,
		.fragment_size = 1024,
	};
	ATF_REQUIRE_EQ(virtiofsd_fuse_statfs_response_encode(
	    VIRTIOFSD_FUSE_ORDER_BIG, 62, &statfs, entry), 0);
	ATF_CHECK_EQ(be32dec(entry), 96);
	ATF_CHECK_EQ(be64dec(entry + 16), 101);
	ATF_CHECK_EQ(be64dec(entry + 48), 105);
	ATF_CHECK_EQ(be32dec(entry + 56), 4096);
	ATF_CHECK_EQ(be32dec(entry + 60), 255);
	ATF_CHECK_EQ(be32dec(entry + 64), 1024);
	for (i = 68; i < 96; i++)
		ATF_CHECK_EQ(entry[i], 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, request_byte_order_is_established_only_by_init);
	ATF_TP_ADD_TC(tp,
	    request_lengths_names_and_reserved_fields_fail_closed);
	ATF_TP_ADD_TC(tp,
	    batch_forget_is_exact_bounded_and_endian_explicit);
	ATF_TP_ADD_TC(tp, errors_are_linux_wire_values_not_host_errno);
	ATF_TP_ADD_TC(tp,
	    read_flags_and_padding_are_independently_validated);
	ATF_TP_ADD_TC(tp, response_structures_are_explicit_and_zero_reserved);
	return (atf_no_error());
}

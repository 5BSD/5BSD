/*
 * Rootless tests for the rebuilt-FreeBSD 9P guest's production wire helpers.
 *
 * The expected byte strings are independent protocol fixtures.  The test
 * includes the helper actually used by p9_protocol.c and p9_client.c.
 */
#include <sys/types.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <fs/p9fs/p9_wire.h>

ATF_TC_WITHOUT_HEAD(scalar_little_endian);
ATF_TC_BODY(scalar_little_endian, tc)
{
	static const uint8_t expected16[] = { 0xcd, 0xab };
	static const uint8_t expected32[] = { 0x78, 0x56, 0x34, 0x12 };
	static const uint8_t expected64[] = {
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
	};
	uint8_t wire[8];

	memset(wire, 0, sizeof(wire));
	p9_wire_store_le16(wire, UINT16_C(0xabcd));
	ATF_CHECK_EQ(memcmp(wire, expected16, sizeof(expected16)), 0);
	ATF_CHECK_EQ(p9_wire_load_le16(wire), UINT16_C(0xabcd));

	memset(wire, 0, sizeof(wire));
	p9_wire_store_le32(wire, UINT32_C(0x12345678));
	ATF_CHECK_EQ(memcmp(wire, expected32, sizeof(expected32)), 0);
	ATF_CHECK_EQ(p9_wire_load_le32(wire), UINT32_C(0x12345678));

	memset(wire, 0, sizeof(wire));
	p9_wire_store_le64(wire, UINT64_C(0x0123456789abcdef));
	ATF_CHECK_EQ(memcmp(wire, expected64, sizeof(expected64)), 0);
	ATF_CHECK_EQ(p9_wire_load_le64(wire),
	    UINT64_C(0x0123456789abcdef));
}

ATF_TC_WITHOUT_HEAD(range_validation);
ATF_TC_BODY(range_validation, tc)
{

	ATF_CHECK(p9_wire_range_valid(0, 0, 0));
	ATF_CHECK(p9_wire_range_valid(0, 7, 7));
	ATF_CHECK(p9_wire_range_valid(6, 7, 1));
	ATF_CHECK(!p9_wire_range_valid(8, 7, 0));
	ATF_CHECK(!p9_wire_range_valid(6, 7, 2));
	ATF_CHECK(!p9_wire_range_valid(SIZE_MAX, SIZE_MAX, 1));
	ATF_CHECK(!p9_wire_range_valid(1, SIZE_MAX, SIZE_MAX));
}

ATF_TC_WITHOUT_HEAD(response_length_validation);
ATF_TC_BODY(response_length_validation, tc)
{

	ATF_CHECK(p9_wire_response_length_valid(7, 7, 7));
	ATF_CHECK(p9_wire_response_length_valid(8192, 8192, 8192));
	ATF_CHECK(!p9_wire_response_length_valid(6, 8192, 6));
	ATF_CHECK(!p9_wire_response_length_valid(8193, 8192, 8193));
	ATF_CHECK(!p9_wire_response_length_valid(8, 8192, 7));
	ATF_CHECK(!p9_wire_response_length_valid(7, 8192, 8));
	ATF_CHECK(!p9_wire_response_length_valid(7, 8192, -1));
	ATF_CHECK(!p9_wire_response_length_valid(UINT32_MAX,
	    UINT32_MAX, INT32_MAX));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scalar_little_endian);
	ATF_TP_ADD_TC(tp, range_validation);
	ATF_TP_ADD_TC(tp, response_length_validation);
	return (atf_no_error());
}

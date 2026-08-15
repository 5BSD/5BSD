#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "snapshot_portable.h"
#include "snapshot_metadata.h"

ATF_TC_WITHOUT_HEAD(fixed_little_endian_vectors);
ATF_TC_BODY(fixed_little_endian_vectors, tc)
{
	static const uint8_t expected16[] = { 0x34, 0x12 };
	static const uint8_t expected32[] = { 0x78, 0x56, 0x34, 0x12 };
	static const uint8_t expected64[] = {
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
	};
	uint8_t storage[10];

	memset(storage, 0xa5, sizeof(storage));
	snapshot_store_le16(storage + 1, UINT16_C(0x1234));
	ATF_CHECK(memcmp(storage + 1, expected16, sizeof(expected16)) == 0);
	ATF_CHECK_EQ(snapshot_load_le16(storage + 1), UINT16_C(0x1234));

	snapshot_store_le32(storage + 1, UINT32_C(0x12345678));
	ATF_CHECK(memcmp(storage + 1, expected32, sizeof(expected32)) == 0);
	ATF_CHECK_EQ(snapshot_load_le32(storage + 1), UINT32_C(0x12345678));

	snapshot_store_le64(storage + 1, UINT64_C(0x0123456789abcdef));
	ATF_CHECK(memcmp(storage + 1, expected64, sizeof(expected64)) == 0);
	ATF_CHECK_EQ(snapshot_load_le64(storage + 1),
	    UINT64_C(0x0123456789abcdef));
}

ATF_TC_WITHOUT_HEAD(boundary_values);
ATF_TC_BODY(boundary_values, tc)
{
	uint8_t bytes[8];

	snapshot_store_le16(bytes, 0);
	ATF_CHECK_EQ(snapshot_load_le16(bytes), 0);
	snapshot_store_le16(bytes, UINT16_MAX);
	ATF_CHECK_EQ(snapshot_load_le16(bytes), UINT16_MAX);
	snapshot_store_le32(bytes, UINT32_MAX);
	ATF_CHECK_EQ(snapshot_load_le32(bytes), UINT32_MAX);
	snapshot_store_le64(bytes, UINT64_MAX);
	ATF_CHECK_EQ(snapshot_load_le64(bytes), UINT64_MAX);
}

ATF_TC_WITHOUT_HEAD(fixed_hex_metadata_grammar);
ATF_TC_BODY(fixed_hex_metadata_grammar, tc)
{
	uint64_t value;

	ATF_REQUIRE_EQ(vm_snapshot_parse_fixed_hex("0123456789abcdef", 16,
	    UINT64_MAX, &value), 0);
	ATF_CHECK_EQ(value, UINT64_C(0x0123456789abcdef));
	ATF_REQUIRE_EQ(vm_snapshot_parse_fixed_hex("FFFFFFFF", 8,
	    UINT32_MAX, &value), 0);
	ATF_CHECK_EQ(value, UINT32_MAX);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("-fffffffffffffff", 16,
	    UINT64_MAX, &value), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("+fffffffffffffff", 16,
	    UINT64_MAX, &value), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("0x123456789abcde", 16,
	    UINT64_MAX, &value), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("01234567", 16,
	    UINT64_MAX, &value), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("0123456789abcdef0", 16,
	    UINT64_MAX, &value), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_parse_fixed_hex("100000000", 9,
	    UINT32_MAX, &value), ERANGE);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fixed_little_endian_vectors);
	ATF_TP_ADD_TC(tp, boundary_values);
	ATF_TP_ADD_TC(tp, fixed_hex_metadata_grammar);
	return (atf_no_error());
}

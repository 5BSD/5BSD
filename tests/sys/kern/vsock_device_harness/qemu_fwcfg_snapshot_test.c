#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "qemu_fwcfg_snapshot.h"

static void
make_record(uint8_t wire[QEMU_FWCFG_SNAPSHOT_WIRE_SIZE])
{

	memset(wire, 0, QEMU_FWCFG_SNAPSHOT_WIRE_SIZE);
	snapshot_store_le32(wire, QEMU_FWCFG_SNAPSHOT_MAGIC);
	snapshot_store_le32(wire + 4, QEMU_FWCFG_SNAPSHOT_VERSION);
	snapshot_store_le16(wire + 8, UINT16_C(0x8123));
	snapshot_store_le32(wire + 12, UINT32_C(37));
	for (size_t i = 0; i < QEMU_FWCFG_SNAPSHOT_DIGEST_SIZE; i++)
		wire[16 + i] = (uint8_t)i;
}

ATF_TC_WITHOUT_HEAD(portable_record);
ATF_TC_BODY(portable_record, tc)
{
	struct qemu_fwcfg_snapshot_state state;
	uint8_t wire[QEMU_FWCFG_SNAPSHOT_WIRE_SIZE];

	make_record(wire);
	ATF_REQUIRE_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire), &state),
	    0);
	ATF_CHECK_EQ(state.selector, UINT16_C(0x8123));
	ATF_CHECK_EQ(state.data_offset, UINT32_C(37));
	ATF_CHECK(memcmp(state.catalog_digest, wire + 16,
	    sizeof(state.catalog_digest)) == 0);
}

ATF_TC_WITHOUT_HEAD(record_rejects_malformed_input);
ATF_TC_BODY(record_rejects_malformed_input, tc)
{
	struct qemu_fwcfg_snapshot_state state;
	uint8_t wire[QEMU_FWCFG_SNAPSHOT_WIRE_SIZE];

	make_record(wire);
	ATF_CHECK_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire) - 1,
	    &state), EINVAL);
	ATF_CHECK_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire) + 1,
	    &state), EINVAL);
	wire[0] ^= 1;
	ATF_CHECK_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire), &state),
	    EINVAL);
	make_record(wire);
	wire[4]++;
	ATF_CHECK_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire), &state),
	    EINVAL);
	make_record(wire);
	wire[10] = 1;
	ATF_CHECK_EQ(qemu_fwcfg_snapshot_decode(wire, sizeof(wire), &state),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(cursor_boundaries);
ATF_TC_BODY(cursor_boundaries, tc)
{

	ATF_CHECK(qemu_fwcfg_snapshot_cursor_valid(true, 0, 0));
	ATF_CHECK(qemu_fwcfg_snapshot_cursor_valid(true, 64, 0));
	ATF_CHECK(qemu_fwcfg_snapshot_cursor_valid(true, 64, 64));
	ATF_CHECK(!qemu_fwcfg_snapshot_cursor_valid(true, 64, 65));
	ATF_CHECK(qemu_fwcfg_snapshot_cursor_valid(false, 0, 0));
	ATF_CHECK(!qemu_fwcfg_snapshot_cursor_valid(false, 0, 1));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, portable_record);
	ATF_TP_ADD_TC(tp, record_rejects_malformed_input);
	ATF_TP_ADD_TC(tp, cursor_boundaries);
	return (atf_no_error());
}

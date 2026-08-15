#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "snapshot.h"

static void
meta_reset(struct vm_snapshot_meta *meta, enum vm_snapshot_op op, void *buffer,
    size_t length)
{

	meta->op = op;
	meta->buffer.buf = buffer;
	meta->buffer.buf_rem = length;
}

#define	META_INITIALIZER(OP, BUFFER, LENGTH)			\
	{							\
		.buffer = {					\
			.buf_start = (BUFFER),			\
			.buf_size = (LENGTH),			\
			.buf = (BUFFER),				\
			.buf_rem = (LENGTH),			\
		},						\
		.op = (OP),					\
	}

void
vm_snapshot_buf_err(const char *name __unused,
    enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		bytes[0] = (uint8_t)*value;
		bytes[1] = (uint8_t)(*value >> 8);
		bytes[2] = (uint8_t)(*value >> 16);
		bytes[3] = (uint8_t)(*value >> 24);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = (uint32_t)bytes[0] |
		    (uint32_t)bytes[1] << 8 |
		    (uint32_t)bytes[2] << 16 |
		    (uint32_t)bytes[3] << 24;
	}
	return (error);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value __unused,
    struct vm_snapshot_meta *meta __unused)
{

	return (ENOTSUP);
}

int
vm_snapshot_le64(uint64_t *value __unused,
    struct vm_snapshot_meta *meta __unused)
{

	return (ENOTSUP);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **addr __unused,
    size_t length __unused, bool restore_null __unused,
    struct vm_snapshot_meta *meta __unused)
{

	return (ENOTSUP);
}

ATF_TC_WITHOUT_HEAD(canonical_round_trip);
ATF_TC_BODY(canonical_round_trip, tc)
{
	static const uint8_t expected[] = {
		0x03, 0x00, 0x00, 0x00, 'a', 'b', 'c'
	};
	uint8_t record[sizeof(expected)];
	struct vm_snapshot_meta meta =
	    META_INITIALIZER(VM_SNAPSHOT_SAVE, record, sizeof(record));

	ATF_REQUIRE_EQ(vm_snapshot_identity_string("abc", 8, &meta), 0);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
	ATF_CHECK_EQ(memcmp(record, expected, sizeof(expected)), 0);

	meta_reset(&meta, VM_SNAPSHOT_VALIDATE, record, sizeof(record));
	ATF_REQUIRE_EQ(vm_snapshot_identity_string("abc", 8, &meta), 0);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
}

ATF_TC_WITHOUT_HEAD(rejects_mismatch_and_malformed_records);
ATF_TC_BODY(rejects_mismatch_and_malformed_records, tc)
{
	static const uint8_t valid[] = {
		0x03, 0x00, 0x00, 0x00, 'a', 'b', 'c'
	};
	static const uint8_t oversized[] = {
		0x09, 0x00, 0x00, 0x00
	};
	struct vm_snapshot_meta meta = META_INITIALIZER(VM_SNAPSHOT_VALIDATE,
	    __DECONST(uint8_t *, valid), sizeof(valid));

	ATF_CHECK_EQ(vm_snapshot_identity_string("abd", 8, &meta), EINVAL);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);

	meta_reset(&meta, VM_SNAPSHOT_VALIDATE, __DECONST(uint8_t *, valid),
	    sizeof(valid) - 1);
	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 8, &meta), E2BIG);

	meta_reset(&meta, VM_SNAPSHOT_VALIDATE,
	    __DECONST(uint8_t *, oversized),
	    sizeof(oversized));
	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 8, &meta), E2BIG);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
}

ATF_TC_WITHOUT_HEAD(bounds_and_empty_identity);
ATF_TC_BODY(bounds_and_empty_identity, tc)
{
	static const uint8_t empty[] = { 0x00, 0x00, 0x00, 0x00 };
	uint8_t record[8];
	struct vm_snapshot_meta meta =
	    META_INITIALIZER(VM_SNAPSHOT_SAVE, record, sizeof(record));

	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 2, &meta), E2BIG);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(record));
	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 0, &meta), EINVAL);
	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 8, NULL), EINVAL);

	meta_reset(&meta, VM_SNAPSHOT_SAVE, record, sizeof(empty));
	ATF_REQUIRE_EQ(vm_snapshot_identity_string(NULL, 8, &meta), 0);
	ATF_CHECK_EQ(memcmp(record, empty, sizeof(empty)), 0);

	meta_reset(&meta, VM_SNAPSHOT_VALIDATE, record, sizeof(empty));
	ATF_REQUIRE_EQ(vm_snapshot_identity_string(NULL, 8, &meta), 0);
	ATF_CHECK_EQ(meta.buffer.buf_rem, 0);
}

ATF_TC_WITHOUT_HEAD(bounded_and_overlap_safe_save);
ATF_TC_BODY(bounded_and_overlap_safe_save, tc)
{
	static const uint8_t expected[] = {
		0x03, 0x00, 0x00, 0x00, 'a', 'b', 'c'
	};
	char unterminated[4] = { 'x', 'x', 'x', 'x' };
	uint8_t aliased[sizeof(expected)] = { 'a', 'b', 'c', '\0' };
	uint8_t before[sizeof(expected) - 1];
	uint8_t short_record[sizeof(expected) - 1];
	struct vm_snapshot_meta meta = META_INITIALIZER(VM_SNAPSHOT_SAVE,
	    aliased, sizeof(aliased));

	ATF_REQUIRE_EQ(vm_snapshot_identity_string((const char *)aliased, 3,
	    &meta), 0);
	ATF_CHECK_EQ(memcmp(aliased, expected, sizeof(expected)), 0);

	memset(short_record, 0xa5, sizeof(short_record));
	memcpy(before, short_record, sizeof(before));
	meta_reset(&meta, VM_SNAPSHOT_SAVE, short_record,
	    sizeof(short_record));
	ATF_CHECK_EQ(vm_snapshot_identity_string("abc", 3, &meta), E2BIG);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(short_record));
	ATF_CHECK_EQ(memcmp(short_record, before, sizeof(before)), 0);

	meta_reset(&meta, VM_SNAPSHOT_SAVE, aliased, sizeof(aliased));
	ATF_CHECK_EQ(vm_snapshot_identity_string(unterminated, 3, &meta),
	    E2BIG);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(aliased));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, canonical_round_trip);
	ATF_TP_ADD_TC(tp, rejects_mismatch_and_malformed_records);
	ATF_TP_ADD_TC(tp, bounds_and_empty_identity);
	ATF_TP_ADD_TC(tp, bounded_and_overlap_safe_save);
	return (atf_no_error());
}

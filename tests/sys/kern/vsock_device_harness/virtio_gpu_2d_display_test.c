/*
 * Independent VirtIO 1.4 section 5.7 format conversion tests.
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_gpu_2d_protocol.c"
#include "virtio_gpu_2d_display.c"

struct format_case {
	uint32_t format;
	uint8_t bytes[4];
	uint32_t argb;
};

ATF_TC_WITHOUT_HEAD(all_documented_formats);
ATF_TC_BODY(all_documented_formats, tc)
{
	static const struct format_case cases[] = {
		{ 1, { 0x33, 0x22, 0x11, 0x44 }, 0x44112233 },
		{ 2, { 0x33, 0x22, 0x11, 0x99 }, 0xff112233 },
		{ 3, { 0x44, 0x11, 0x22, 0x33 }, 0x44112233 },
		{ 4, { 0x99, 0x11, 0x22, 0x33 }, 0xff112233 },
		{ 67, { 0x11, 0x22, 0x33, 0x44 }, 0x44112233 },
		{ 68, { 0x99, 0x33, 0x22, 0x11 }, 0xff112233 },
		{ 121, { 0x44, 0x33, 0x22, 0x11 }, 0x44112233 },
		{ 134, { 0x11, 0x22, 0x33, 0x99 }, 0xff112233 },
	};
	uint32_t actual;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ATF_REQUIRE_EQ(virtio_gpu_2d_pixel_to_argb(cases[i].format,
		    cases[i].bytes, &actual), 0);
		ATF_CHECK_EQ(actual, cases[i].argb);
	}
	ATF_CHECK_EQ(virtio_gpu_2d_pixel_to_argb(0, cases[0].bytes,
	    &actual), EINVAL);
}

ATF_TC_WITHOUT_HEAD(strides_and_xrgb_output);
ATF_TC_BODY(strides_and_xrgb_output, tc)
{
	const uint8_t source[24] = {
		0x03, 0x02, 0x01, 0xaa, 0x06, 0x05, 0x04, 0xbb,
		0xcc, 0xcc, 0xcc, 0xcc,
		0x09, 0x08, 0x07, 0xdd, 0x0c, 0x0b, 0x0a, 0xee,
		0xcc, 0xcc, 0xcc, 0xcc,
	};
	uint8_t destination[24];

	memset(destination, 0xa5, sizeof(destination));
	ATF_REQUIRE_EQ(virtio_gpu_2d_convert_xrgb(1, source, 12,
	    destination, 12, 2, 2), 0);
	ATF_CHECK(memcmp(destination,
	    (const uint8_t[]){ 0x03, 0x02, 0x01, 0x00 }, 4) == 0);
	ATF_CHECK(memcmp(destination + 4,
	    (const uint8_t[]){ 0x06, 0x05, 0x04, 0x00 }, 4) == 0);
	ATF_CHECK(memcmp(destination + 12,
	    (const uint8_t[]){ 0x09, 0x08, 0x07, 0x00 }, 4) == 0);
	ATF_CHECK(memcmp(destination + 16,
	    (const uint8_t[]){ 0x0c, 0x0b, 0x0a, 0x00 }, 4) == 0);
	ATF_CHECK_EQ(destination[8], 0xa5);
	ATF_CHECK_EQ(destination[20], 0xa5);
	ATF_CHECK_EQ(virtio_gpu_2d_convert_xrgb(1, source, 7,
	    destination, 12, 2, 2), EMSGSIZE);
	ATF_CHECK_EQ(virtio_gpu_2d_convert_xrgb(0, source, 12,
	    destination, 12, 2, 2), EINVAL);
}

ATF_TC_WITHOUT_HEAD(unaligned_destination);
ATF_TC_BODY(unaligned_destination, tc)
{
	const uint8_t source[4] = { 0x03, 0x02, 0x01, 0xff };
	uint8_t storage[6];

	memset(storage, 0xa5, sizeof(storage));
	ATF_REQUIRE_EQ(virtio_gpu_2d_convert_xrgb(1, source, 4,
	    storage + 1, 4, 1, 1), 0);
	ATF_CHECK(memcmp(storage + 1,
	    (const uint8_t[]){ 0x03, 0x02, 0x01, 0x00 }, 4) == 0);
	ATF_CHECK_EQ(storage[0], 0xa5);
	ATF_CHECK_EQ(storage[5], 0xa5);
}

ATF_TC_WITHOUT_HEAD(cursor_alpha_composition);
ATF_TC_BODY(cursor_alpha_composition, tc)
{
	const uint8_t source[16] = {
		0x6e, 0x78, 0x82, 0x80,
		0xfe, 0xdc, 0xba, 0x00,
		0x11, 0x22, 0x33, 0xff,
		0xa5, 0xa5, 0xa5, 0xa5,
	};
	uint8_t destination[16];

	memset(destination, 0xa5, sizeof(destination));
	memcpy(destination, (const uint8_t[]){ 0x1e, 0x14, 0x0a, 0x00 }, 4);
	memcpy(destination + 4,
	    (const uint8_t[]){ 0x33, 0x22, 0x11, 0x00 }, 4);
	memcpy(destination + 8,
	    (const uint8_t[]){ 0xef, 0xcd, 0xab, 0x00 }, 4);

	/* Format 67 is R8G8B8A8_UNORM in the independent document oracle. */
	ATF_REQUIRE_EQ(virtio_gpu_2d_composite_cursor_xrgb(67, source, 16,
	    destination, 16, 3, 1), 0);
	ATF_CHECK(memcmp(destination,
	    (const uint8_t[]){ 0x50, 0x46, 0x3c, 0x00 }, 4) == 0);
	ATF_CHECK(memcmp(destination + 4,
	    (const uint8_t[]){ 0x33, 0x22, 0x11, 0x00 }, 4) == 0);
	ATF_CHECK(memcmp(destination + 8,
	    (const uint8_t[]){ 0x33, 0x22, 0x11, 0x00 }, 4) == 0);
	ATF_CHECK_EQ(destination[12], 0xa5);

	ATF_CHECK_EQ(virtio_gpu_2d_composite_cursor_xrgb(67, source, 11,
	    destination, 16, 3, 1), EMSGSIZE);
	ATF_CHECK_EQ(virtio_gpu_2d_composite_cursor_xrgb(0, source, 16,
	    destination, 16, 3, 1), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, all_documented_formats);
	ATF_TP_ADD_TC(tp, strides_and_xrgb_output);
	ATF_TP_ADD_TC(tp, unaligned_destination);
	ATF_TP_ADD_TC(tp, cursor_alpha_composition);
	return (atf_no_error());
}

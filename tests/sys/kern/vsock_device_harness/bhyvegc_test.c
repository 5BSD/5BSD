/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <atf-c.h>

/* Include the production implementation to exercise its private ownership. */
#include "bhyvegc.c"

static void
destroy_gc(struct bhyvegc *gc)
{

	if (gc == NULL)
		return;
	if (!gc->raw)
		free(gc->gc_image->data);
	free(gc->gc_image);
	free(gc);
}

ATF_TC_WITHOUT_HEAD(invalid_geometry_rejected);
ATF_TC_BODY(invalid_geometry_rejected, tc)
{

	ATF_CHECK_EQ(bhyvegc_init(0, 1, NULL), NULL);
	ATF_CHECK_EQ(bhyvegc_init(1, 0, NULL), NULL);
	ATF_CHECK_EQ(bhyvegc_init(-1, 1, NULL), NULL);
	ATF_CHECK_EQ(bhyvegc_init(1, -1, NULL), NULL);
	ATF_CHECK_EQ(bhyvegc_init(INT_MAX, INT_MAX, NULL), NULL);
}

ATF_TC_WITHOUT_HEAD(owned_resize_is_transactional);
ATF_TC_BODY(owned_resize_is_transactional, tc)
{
	struct bhyvegc_image *image;
	struct bhyvegc *gc;
	uint32_t *old_data;

	gc = bhyvegc_init(2, 3, NULL);
	ATF_REQUIRE(gc != NULL);
	image = bhyvegc_get_image(gc);
	ATF_REQUIRE(image != NULL);
	ATF_REQUIRE(image->data != NULL);
	image->data[0] = UINT32_MAX;

	old_data = image->data;
	bhyvegc_resize(gc, INT_MAX, INT_MAX);
	ATF_CHECK_EQ(image->width, 2);
	ATF_CHECK_EQ(image->height, 3);
	ATF_CHECK_EQ(image->data, old_data);
	ATF_CHECK_EQ(image->data[0], UINT32_MAX);

	bhyvegc_resize(gc, 4, 5);
	ATF_CHECK_EQ(image->width, 4);
	ATF_CHECK_EQ(image->height, 5);
	ATF_REQUIRE(image->data != NULL);
	for (size_t i = 0; i < 20; i++)
		ATF_CHECK_EQ(image->data[i], 0);
	destroy_gc(gc);
}

ATF_TC_WITHOUT_HEAD(external_storage_is_never_freed_or_reallocated);
ATF_TC_BODY(external_storage_is_never_freed_or_reallocated, tc)
{
	struct bhyvegc_image *image;
	struct bhyvegc *gc;
	uint32_t first[6], second[20];

	gc = bhyvegc_init(2, 3, first);
	ATF_REQUIRE(gc != NULL);
	image = bhyvegc_get_image(gc);
	ATF_REQUIRE_EQ(image->data, first);
	bhyvegc_resize(gc, 4, 5);
	ATF_CHECK_EQ(image->width, 4);
	ATF_CHECK_EQ(image->height, 5);
	ATF_CHECK_EQ(image->data, first);

	bhyvegc_set_fbaddr(gc, second);
	ATF_CHECK_EQ(image->data, second);
	bhyvegc_set_fbaddr(gc, NULL);
	ATF_CHECK_EQ(image->data, second);
	first[0] = 1;
	second[0] = 2;
	ATF_CHECK_EQ(first[0], 1);
	ATF_CHECK_EQ(second[0], 2);
	destroy_gc(gc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, invalid_geometry_rejected);
	ATF_TP_ADD_TC(tp, owned_resize_is_transactional);
	ATF_TP_ADD_TC(tp, external_storage_is_never_freed_or_reallocated);
	return (atf_no_error());
}

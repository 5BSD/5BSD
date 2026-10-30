/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <intel-pt.h>

int
main(void)
{
	struct pt_version version = pt_library_version();

	assert(version.major == LIBIPT_VERSION_MAJOR);
	assert(version.minor == LIBIPT_VERSION_MINOR);
	assert(version.patch == LIBIPT_VERSION_PATCH);
	assert(LIBIPT_VERSION == ((version.major << 8) + version.minor));
	return (0);
}

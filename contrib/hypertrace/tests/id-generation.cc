/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

static unsigned draws;
static void
test_arc4random_buf(void *buffer, size_t length)
{
	assert(length == sizeof(uint64_t));
	uint64_t value = ++draws == 1 ? 0 : UINT64_C(0x123456789abcdef0);
	std::memcpy(buffer, &value, length);
}

#define arc4random_buf test_arc4random_buf
#include "dtraced_id.h"
#undef arc4random_buf

int
main()
{
	assert(dtraced::dtraced_genid() == UINT64_C(0x123456789abcdef0));
	assert(draws == 2);
}

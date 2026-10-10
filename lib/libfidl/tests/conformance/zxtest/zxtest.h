/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Minimal zxtest compatibility for GIDL-generated conformance tests.
 * Only the assertion forms emitted for host (non-__Fuchsia__) cases and used
 * by conformance_utils.h are provided; googletest supplies the framework.
 */
#ifndef FIDL_BSD_CONFORMANCE_ZXTEST_H
#define FIDL_BSD_CONFORMANCE_ZXTEST_H
#include <gtest/gtest.h>

#include <string_view>

/*
 * GIDL compares decoded std::string values with string literals. Use the
 * literal's full array length so embedded NUL bytes are compared too.
 */
template <size_t N>
constexpr std::string_view
ZxtestString(const char (&s)[N])
{
	return { s, N - 1 };
}
inline std::string_view
ZxtestString(std::string_view s)
{
	return s;
}
#undef ASSERT_STREQ
#define ASSERT_STREQ(a, b) ASSERT_EQ(ZxtestString(a), ZxtestString(b))
#endif

// SPDX-License-Identifier: BSD-2-Clause
// Compile with -nostdinc++: a toolchain must not force libc++ back into scope.
#if __has_include(<vector>)
#error standard_library_headers_not_disabled
#endif
int main() { return 0; }

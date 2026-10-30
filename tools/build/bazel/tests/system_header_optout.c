/* SPDX-License-Identifier: BSD-2-Clause */
/* __stdarg___gnuc_va_list.h is a Clang resource header in the selected SDK. */
/* Both -nostdinc and -nostdlibinc suppress the target C library headers. */
#if __has_include(<stdio.h>)
#error system_library_headers_not_disabled
#endif
#ifdef EXPECT_BUILTIN_HEADERS
#if !__has_include(<__stdarg___gnuc_va_list.h>)
#error builtin_headers_unexpectedly_disabled
#endif
#else
#if __has_include(<__stdarg___gnuc_va_list.h>)
#error builtin_headers_not_disabled
#endif
#endif
int main(void) { return 0; }

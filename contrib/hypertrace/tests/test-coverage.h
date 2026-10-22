/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef HYPERTRACE_TEST_COVERAGE_H
#define HYPERTRACE_TEST_COVERAGE_H
/* Test-only LLVM profile capture. Open before cap_enter(), flush before _exit().
 * Opt-in prevents ordinary tests from acquiring extra descriptors or requiring
 * the profiling runtime. Each process owns a distinct file; do not share one
 * FILE across fork. Child callers reset inherited counters after fork. */
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int __llvm_profile_set_file_object(FILE *, int) __attribute__((weak));
extern int __llvm_profile_write_file(void) __attribute__((weak));
extern void __llvm_profile_set_dumped(void) __attribute__((weak));
extern void __llvm_profile_reset_counters(void) __attribute__((weak));
static FILE *ht_test_profile;

static inline void __attribute__((no_profile_instrument_function))
ht_test_coverage_start(const char *tag, bool child)
{
	const char *directory = getenv("HYPERTRACE_COVERAGE_DIR");
	char path[PATH_MAX];
	int fd, length;

	if (directory == NULL)
		return;
	assert(ht_test_profile == NULL);
	assert(__llvm_profile_set_file_object != NULL &&
	    __llvm_profile_write_file != NULL && __llvm_profile_set_dumped != NULL &&
	    __llvm_profile_reset_counters != NULL);
	length = snprintf(path, sizeof(path), "%s/%s-%ld.profraw", directory,
	    tag, (long)getpid());
	assert(length > 0 && (size_t)length < sizeof(path));
	fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	assert(fd >= 0);
	ht_test_profile = fdopen(fd, "w+b");
	assert(ht_test_profile != NULL);
	assert(__llvm_profile_set_file_object(ht_test_profile, 0) == 0);
	if (child)
		__llvm_profile_reset_counters();
}

static inline void __attribute__((no_profile_instrument_function))
ht_test_coverage_finish(void)
{
	if (ht_test_profile == NULL)
		return;
	assert(__llvm_profile_write_file() == 0);
	__llvm_profile_set_dumped(); /* Avoid duplicate atexit writes/counts. */
	assert(fclose(ht_test_profile) == 0);
	ht_test_profile = NULL;
}
#endif

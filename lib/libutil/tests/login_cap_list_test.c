/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <login_cap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int track_decode, fail_copy, fail_array;
static char *decoded;
static unsigned int decoded_frees;
int __real_cgetstr(char *, const char *, char **);
int __wrap_cgetstr(char *, const char *, char **);
void __real_free(void *);
void __wrap_free(void *);
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *, size_t);
void *__real_reallocarray(void *, size_t, size_t);
void *__wrap_reallocarray(void *, size_t, size_t);

int
__wrap_cgetstr(char *record, const char *cap, char **out)
{
	int result = __real_cgetstr(record, cap, out);
	if (track_decode && result >= 0) {
		ATF_REQUIRE(decoded == NULL);
		decoded = *out;
	}
	return (result);
}
void
__wrap_free(void *ptr)
{
	if (ptr != NULL && ptr == decoded) {
		decoded_frees++;
		decoded = NULL;
	}
	__real_free(ptr);
}
void *
__wrap_realloc(void *ptr, size_t size)
{
	/* The decoder may itself realloc before __wrap_cgetstr returns.
	 * Inject only after that temporary exists, at the list-copy stage. */
	if (fail_copy && decoded != NULL) {
		fail_copy = 0;
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_realloc(ptr, size));
}
void *
__wrap_reallocarray(void *ptr, size_t count, size_t size)
{
	if (fail_array && decoded != NULL) {
		fail_array = 0;
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_reallocarray(ptr, count, size));
}

static void
list_ownership(int failure)
{
	char record[] = "selected:items=one,'two,three',four:";
	login_cap_t selected = { .lc_cap = record };
	login_cap_t *lc = &selected;
	const char **list;
	ATF_REQUIRE(lc != NULL);
	track_decode = 1;
	fail_copy = failure == 1;
	fail_array = failure == 2;
	errno = 0;
	list = login_getcaplist(lc, "items", ",");
	if (failure) {
		ATF_CHECK(list == NULL);
		ATF_CHECK_EQ(ENOMEM, errno);
	} else {
		ATF_REQUIRE(list != NULL);
		ATF_CHECK_STREQ("one", list[0]);
		ATF_CHECK_STREQ("two,three", list[1]);
		ATF_CHECK_STREQ("four", list[2]);
		ATF_CHECK(list[3] == NULL);
	}
	ATF_CHECK_EQ(1, decoded_frees);
	ATF_CHECK(decoded == NULL);
	/* Clean up a pre-fix leak after recording the failing assertions. */
	if (decoded != NULL)
		free(decoded);
	track_decode = 0;
}
ATF_TC_WITHOUT_HEAD(list_string_ownership);
ATF_TC_BODY(list_string_ownership, tc) { (void)tc; list_ownership(0); }
ATF_TC_WITHOUT_HEAD(list_copy_failure);
ATF_TC_BODY(list_copy_failure, tc) { (void)tc; list_ownership(1); }
ATF_TC_WITHOUT_HEAD(list_array_failure);
ATF_TC_BODY(list_array_failure, tc) { (void)tc; list_ownership(2); }

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, list_string_ownership);
	ATF_TP_ADD_TC(tp, list_copy_failure);
	ATF_TP_ADD_TC(tp, list_array_failure);
	return (atf_no_error());
}

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "virtiofsd_handle.c"

ATF_TC_WITHOUT_HEAD(handles_are_bounded_typed_and_generation_checked);
ATF_TC_BODY(handles_are_bounded_typed_and_generation_checked, tc)
{
	struct virtiofsd_handles *handles;
	uint64_t first, nodeid, replacement;
	int duplicate, fd, pipefd[2];

	ATF_REQUIRE_EQ(pipe(pipefd), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_create(1, &handles), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_insert(handles, pipefd[0], 41,
	    false, &first), 0);
	ATF_CHECK(first != 0);
	ATF_CHECK_EQ(virtiofsd_handles_count(handles), 1);
	ATF_CHECK_EQ(virtiofsd_handles_insert(handles, pipefd[1], 42,
	    false, &replacement), ENOSPC);
	ATF_REQUIRE_EQ(virtiofsd_handles_dup(handles, first, false,
	    &duplicate, &nodeid), 0);
	ATF_CHECK_EQ(nodeid, 41);
	ATF_REQUIRE_EQ(close(duplicate), 0);
	ATF_CHECK_EQ(virtiofsd_handles_dup(handles, first, true,
	    &duplicate, &nodeid), ESTALE);
	ATF_CHECK_EQ(virtiofsd_handles_remove_node(handles, first, false, 42),
	    ESTALE);
	ATF_CHECK_EQ(virtiofsd_handles_count(handles), 1);
	ATF_REQUIRE_EQ(virtiofsd_handles_remove_node(handles, first, false, 41),
	    0);
	ATF_CHECK_EQ(virtiofsd_handles_count(handles), 0);
	ATF_CHECK_EQ(virtiofsd_handles_remove(handles, first, false), ESTALE);

	ATF_REQUIRE_EQ(virtiofsd_handles_insert(handles, pipefd[1], 42,
	    true, &replacement), 0);
	ATF_CHECK(first != replacement);
	ATF_CHECK_EQ(virtiofsd_handles_dup(handles, first, false, &fd,
	    NULL), ESTALE);
	ATF_REQUIRE_EQ(virtiofsd_handles_remove(handles, replacement, true),
	    0);
	virtiofsd_handles_destroy(handles);
	ATF_REQUIRE_EQ(close(pipefd[0]), 0);
	ATF_REQUIRE_EQ(close(pipefd[1]), 0);
}

ATF_TC_WITHOUT_HEAD(handle_owns_a_duplicate_not_callers_descriptor);
ATF_TC_BODY(handle_owns_a_duplicate_not_callers_descriptor, tc)
{
	struct virtiofsd_handles *handles;
	char byte;
	uint64_t id;
	int duplicate, pipefd[2];

	ATF_REQUIRE_EQ(pipe(pipefd), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_create(2, &handles), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_insert(handles, pipefd[0], 51,
	    false, &id), 0);
	ATF_REQUIRE_EQ(close(pipefd[0]), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_dup(handles, id, false,
	    &duplicate, NULL), 0);
	ATF_REQUIRE_EQ(write(pipefd[1], "x", 1), 1);
	ATF_REQUIRE_EQ(read(duplicate, &byte, 1), 1);
	ATF_CHECK_EQ(byte, 'x');
	ATF_REQUIRE_EQ(close(duplicate), 0);
	ATF_REQUIRE_EQ(virtiofsd_handles_remove(handles, id, false), 0);
	virtiofsd_handles_destroy(handles);
	ATF_REQUIRE_EQ(close(pipefd[1]), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp,
	    handles_are_bounded_typed_and_generation_checked);
	ATF_TP_ADD_TC(tp, handle_owns_a_duplicate_not_callers_descriptor);
	return (atf_no_error());
}

/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "veriexec.h"

int dev_fd = -1, ForceFlags, Verbose, VeriexecVersion;
const char *Cdir = "/candidate";
static int calls, load_error;

int
veriexec_test_ioctl(int fd, unsigned long command, ...)
{
	(void)fd;
	ATF_REQUIRE_EQ(VERIEXEC_SIGNED_LOAD, command);
	calls++;
	if (load_error != 0) {
		errno = load_error;
		return (-1);
	}
	return (0);
}

static int
parse(const char *text)
{
	int error;

	calls = 0;
	ATF_REQUIRE(manifest_open("test.manifest", text) != NULL);
	error = yyparse();
	return (error != 0 || ManifestErrors != 0);
}

#define HASH "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define ENTRY "./bin/tool sha256=" HASH " mode=755\n"

ATF_TC_WITHOUT_HEAD(valid_manifest);
ATF_TC_BODY(valid_manifest, tc)
{
	ATF_CHECK_EQ(0, parse(ENTRY));
	ATF_CHECK_EQ(1, calls);
}

ATF_TC_WITHOUT_HEAD(rejects_bad_hash_lengths);
ATF_TC_BODY(rejects_bad_hash_lengths, tc)
{
	ATF_CHECK_EQ(1, parse("./bin/tool sha256=0 mode=755\n"));
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK_EQ(1, parse("./bin/tool sha256=" HASH "00 mode=755\n"));
	ATF_CHECK_EQ(0, calls);
}

ATF_TC_WITHOUT_HEAD(reports_load_failure);
ATF_TC_BODY(reports_load_failure, tc)
{
	load_error = EPERM;
	ATF_CHECK_EQ(1, parse(ENTRY));
	ATF_CHECK_EQ(1, calls);
	load_error = 0;
	ATF_CHECK_EQ(0, parse(ENTRY));
	ATF_CHECK_EQ(1, calls);
}

ATF_TC_WITHOUT_HEAD(reports_recovered_syntax_error);
ATF_TC_BODY(reports_recovered_syntax_error, tc)
{
	ATF_CHECK_EQ(1, parse("./bad =\n" ENTRY));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_manifest);
	ATF_TP_ADD_TC(tp, rejects_bad_hash_lengths);
	ATF_TP_ADD_TC(tp, reports_load_failure);
	ATF_TP_ADD_TC(tp, reports_recovered_syntax_error);
	return (atf_no_error());
}

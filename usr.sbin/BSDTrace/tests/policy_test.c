/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tracecmp_policy.h"

static void
write_policy(const char *contents)
{
	FILE *file;

	ATF_REQUIRE((file = fopen("policy", "w")) != NULL);
	ATF_REQUIRE_EQ(strlen(contents),
	    fwrite(contents, 1, strlen(contents), file));
	ATF_REQUIRE_EQ(0, fclose(file));
}

ATF_TC_WITHOUT_HEAD(default_deny);
ATF_TC_BODY(default_deny, tc)
{
	struct tracecmp_policy policy;

	ATF_REQUIRE_EQ(0, tracecmp_policy_load("missing", &policy));
	ATF_CHECK_EQ(0, policy.count);
	ATF_CHECK(!tracecmp_policy_allows(&policy, "org.test.client"));
	ATF_CHECK(!tracecmp_policy_allows(NULL, "org.test.client"));
	ATF_CHECK(!tracecmp_policy_allows(&policy, NULL));
}

ATF_TC_WITHOUT_HEAD(exact_labels);
ATF_TC_BODY(exact_labels, tc)
{
	struct tracecmp_policy policy;

	write_policy("# administrators\n org.test.trace \n"
	    "org.test.second # comment\n");
	ATF_REQUIRE_EQ(0, tracecmp_policy_load("policy", &policy));
	ATF_CHECK_EQ(2, policy.count);
	ATF_CHECK(tracecmp_policy_allows(&policy, "org.test.trace"));
	ATF_CHECK(tracecmp_policy_allows(&policy, "org.test.second"));
	ATF_CHECK(!tracecmp_policy_allows(&policy, "org.test"));
	ATF_CHECK(!tracecmp_policy_allows(&policy, "org.test.trace.child"));
}

ATF_TC_WITHOUT_HEAD(wildcard_rejected);
ATF_TC_BODY(wildcard_rejected, tc)
{
	struct tracecmp_policy policy;

	write_policy("*\n");
	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_policy_load("policy", &policy) == -1);
	ATF_CHECK_EQ(0, policy.count);
}

ATF_TC_WITHOUT_HEAD(malformed_labels);
ATF_TC_BODY(malformed_labels, tc)
{
	static const char *const invalid[] = {
		".leading\n", "trailing.\n", "two..dots\n", "white space\n",
		"path/name\n", "shell$meta\n", "\t\n"
	};
	struct tracecmp_policy policy;
	size_t i;

	for (i = 0; i < nitems(invalid); i++) {
		write_policy(invalid[i]);
		if (strcmp(invalid[i], "\t\n") == 0)
			ATF_CHECK_EQ(0, tracecmp_policy_load("policy", &policy));
		else
			ATF_CHECK_ERRNO(EINVAL,
			    tracecmp_policy_load("policy", &policy) == -1);
	}
}

ATF_TC_WITHOUT_HEAD(duplicate_rejected);
ATF_TC_BODY(duplicate_rejected, tc)
{
	struct tracecmp_policy policy;

	write_policy("org.test.trace\norg.test.trace\n");
	ATF_CHECK_ERRNO(EEXIST,
	    tracecmp_policy_load("policy", &policy) == -1);
	ATF_CHECK_EQ(0, policy.count);
}

ATF_TC_WITHOUT_HEAD(oversized_line);
ATF_TC_BODY(oversized_line, tc)
{
	struct tracecmp_policy policy;
	char line[300];

	memset(line, 'a', sizeof(line));
	line[sizeof(line) - 1] = '\0';
	write_policy(line);
	ATF_CHECK_ERRNO(E2BIG,
	    tracecmp_policy_load("policy", &policy) == -1);
	ATF_CHECK_EQ(0, policy.count);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct tracecmp_policy policy;

	ATF_CHECK_ERRNO(EINVAL, tracecmp_policy_load(NULL, &policy) == -1);
	ATF_CHECK_ERRNO(EINVAL, tracecmp_policy_load("missing", NULL) == -1);
}

ATF_TC_WITHOUT_HEAD(unsafe_policy_file_rejected);
ATF_TC_BODY(unsafe_policy_file_rejected, tc)
{
	struct tracecmp_policy policy;

	write_policy("org.test.trace\n");
	ATF_REQUIRE_EQ(0, chmod("policy", 0666));
	ATF_CHECK_ERRNO(EACCES,
	    tracecmp_policy_load("policy", &policy) == -1);
	ATF_REQUIRE_EQ(0, unlink("policy"));
	ATF_REQUIRE_EQ(0, mkdir("policy-dir", 0700));
	ATF_CHECK(tracecmp_policy_load("policy-dir", &policy) == -1);
	ATF_REQUIRE_EQ(0, symlink("policy-dir", "policy-link"));
	ATF_CHECK(tracecmp_policy_load("policy-link", &policy) == -1);
}

ATF_TC_WITHOUT_HEAD(bounded_policy_file);
ATF_TC_BODY(bounded_policy_file, tc)
{
	static const char embedded[] = "org.test.good\0org.test.hidden\n";
	struct tracecmp_policy policy;
	FILE *file;

	(void)tc;
	ATF_REQUIRE((file = fopen("policy", "w")) != NULL);
	ATF_REQUIRE_EQ(sizeof(embedded) - 1,
	    fwrite(embedded, 1, sizeof(embedded) - 1, file));
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_policy_load("policy", &policy) == -1);
	ATF_REQUIRE_EQ(0, unlink("policy"));
	ATF_REQUIRE((file = fopen("policy", "w")) != NULL);
	ATF_REQUIRE_EQ(0, ftruncate(fileno(file),
	    TRACECMP_POLICY_FILE_MAX + 1));
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_CHECK_ERRNO(EFBIG,
	    tracecmp_policy_load("policy", &policy) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, default_deny);
	ATF_TP_ADD_TC(tp, exact_labels);
	ATF_TP_ADD_TC(tp, wildcard_rejected);
	ATF_TP_ADD_TC(tp, malformed_labels);
	ATF_TP_ADD_TC(tp, duplicate_rejected);
	ATF_TP_ADD_TC(tp, oversized_line);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, unsafe_policy_file_rejected);
	ATF_TP_ADD_TC(tp, bounded_policy_file);
	return (atf_no_error());
}

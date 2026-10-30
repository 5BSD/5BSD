/* SPDX-License-Identifier: BSD-2-Clause */
/* Real policy parser and pam_start; isolated policy paths and real modules. */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "openpam_impl.h"

const char *openpam_policy_path[] = { "policies/", "policies.conf", NULL };

static void
policy(const char *name, const char *text)
{
	char path[256];
	FILE *f;

	ATF_REQUIRE(snprintf(path, sizeof(path), "policies/%s", name) < (int)sizeof(path));
	f = fopen(path, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs(text, f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE_EQ(0, chmod(path, 0600));
}

static void
prepare(void)
{
	struct rlimit limit;

	ATF_REQUIRE_EQ(0, mkdir("policies", 0700));
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0));
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &limit));
	if (limit.rlim_cur > 128) {
		limit.rlim_cur = 128;
		ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));
	}
}

static void
accepted(const char *service, unsigned entries)
{
	struct pam_conv conv = {0};
	pam_handle_t *pam = NULL;
	pam_chain_t *chain;
	unsigned count = 0;

	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_start(service, "root", &conv, &pam));
	ATF_REQUIRE(pam != NULL);
	for (chain = pam->chains[PAM_AUTH]; chain; chain = chain->next)
		count++;
	ATF_CHECK_EQ(entries, count);
	if (entries != 0)
		ATF_CHECK_EQ(PAM_AUTH_ERR, pam_authenticate(pam, PAM_SILENT));
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_end(pam, PAM_SUCCESS));
}

static void
rejected(const char *service, int expected)
{
	struct pam_conv conv = {0};
	pam_handle_t *pam = NULL;
	int status, error;

	errno = 0;
	status = pam_start(service, "root", &conv, &pam);
	error = errno;
	ATF_REQUIRE_EQ(PAM_SYSTEM_ERR, status);
	ATF_CHECK_MSG(expected == error, "expected errno %d, got %d", expected, error);
	ATF_CHECK(pam == NULL);
}

ATF_TC_WITHOUT_HEAD(self_and_optional_cycles);
ATF_TC_BODY(self_and_optional_cycles, tc)
{
	prepare();
	policy("self", "auth include self\n");
	rejected("self", ELOOP);
	policy("self", "-auth include self\n");
	rejected("self", ELOOP);
	policy("self", "auth required pam_deny.so\n");
	accepted("self", 1); /* Rejection must not poison the next transaction. */
}

ATF_TC_WITHOUT_HEAD(indirect_cycle);
ATF_TC_BODY(indirect_cycle, tc)
{
	prepare();
	policy("first", "auth include second\n");
	policy("second", "auth include first\n");
	rejected("first", ELOOP);
}

ATF_TC_WITHOUT_HEAD(aliases_are_same_file);
ATF_TC_BODY(aliases_are_same_file, tc)
{
	prepare();
	policy("first", "auth include alias\n");
	ATF_REQUIRE_EQ(0, link("policies/first", "policies/alias"));
	rejected("first", ELOOP);
	ATF_REQUIRE_EQ(0, unlink("policies/alias"));
	ATF_REQUIRE_EQ(0, symlink("first", "policies/alias"));
	rejected("first", ELOOP);
}

ATF_TC_WITHOUT_HEAD(repeated_include_and_facilities);
ATF_TC_BODY(repeated_include_and_facilities, tc)
{
	prepare();
	policy("first", "auth include shared\nauth include shared\naccount include shared\n");
	policy("shared", "auth required pam_deny.so\naccount required pam_deny.so\n");
	accepted("first", 2);
}

ATF_TC_WITHOUT_HEAD(combined_file_services);
ATF_TC_BODY(combined_file_services, tc)
{
	FILE *f;

	prepare();
	f = fopen("policies.conf", "w"); ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs("first auth include second\nsecond auth required pam_deny.so\n", f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	accepted("first", 1);
	f = fopen("policies.conf", "w"); ATF_REQUIRE(f != NULL);
	ATF_REQUIRE(fputs("first auth include second\nsecond auth include first\n", f) >= 0);
	ATF_REQUIRE_EQ(0, fclose(f));
	rejected("first", ELOOP);
}

ATF_TC_WITHOUT_HEAD(fallback_cycle);
ATF_TC_BODY(fallback_cycle, tc)
{
	prepare();
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 1));
	policy("first", "auth required pam_deny.so\n");
	policy("other", "account include other\n");
	rejected("first", ELOOP);
}

ATF_TC_WITHOUT_HEAD(depth_bound);
ATF_TC_BODY(depth_bound, tc)
{
	char name[32], text[80];
	unsigned i;

	prepare();
	for (i = 0; i < 63; i++) {
		snprintf(name, sizeof(name), "level%u", i);
		snprintf(text, sizeof(text), "auth include level%u\n", i + 1);
		policy(name, text);
	}
	policy("level63", "auth required pam_deny.so\n");
	accepted("level0", 1);
	policy("level63", "auth include level64\n");
	policy("level64", "auth required pam_deny.so\n");
	rejected("level0", ELOOP);
}

ATF_TC_WITHOUT_HEAD(expansion_bound);
ATF_TC_BODY(expansion_bound, tc)
{
	char name[32], text[100];
	unsigned i;

	prepare();
	/* No active cycle; a small graph expands exponentially, even with no modules. */
	for (i = 0; i < 10; i++) {
		snprintf(name, sizeof(name), "level%u", i);
		snprintf(text, sizeof(text), "auth include level%u\nauth include level%u\n", i + 1, i + 1);
		policy(name, text);
	}
	policy("level10", "# empty leaf\n");
	rejected("level0", E2BIG);
	accepted("level6", 0);
}

ATF_TC_WITHOUT_HEAD(unsafe_policy_still_rejected);
ATF_TC_BODY(unsafe_policy_still_rejected, tc)
{
	prepare();
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_VERIFY_POLICY_FILE, 1));
	policy("unsafe", "auth required pam_deny.so\n");
	ATF_REQUIRE_EQ(0, chmod("policies/unsafe", 0666));
	rejected("unsafe", EPERM);
	ATF_REQUIRE_EQ(0, chmod("policies/unsafe", 0600));
	accepted("unsafe", 1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unsafe_policy_still_rejected);
	ATF_TP_ADD_TC(tp, self_and_optional_cycles);
	ATF_TP_ADD_TC(tp, indirect_cycle);
	ATF_TP_ADD_TC(tp, aliases_are_same_file);
	ATF_TP_ADD_TC(tp, repeated_include_and_facilities);
	ATF_TP_ADD_TC(tp, combined_file_services);
	ATF_TP_ADD_TC(tp, fallback_cycle);
	ATF_TP_ADD_TC(tp, depth_bound);
	ATF_TP_ADD_TC(tp, expansion_bound);
	return (atf_no_error());
}

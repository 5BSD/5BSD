/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise real module loading/dispatch with policy local to the test. */
#include <sys/stat.h>
#include <atf-c.h>
#include <limits.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <stdio.h>
#include <unistd.h>

static void
check_dispatch(const atf_tc_t *tc, int deny, int mixed)
{
	static const char *facilities[] = {"auth", "account", "password", "session"};
	const char *permit_module, *deny_module;
	struct pam_conv conv = { .conv = openpam_nullconv };
	pam_handle_t *pam = NULL;
	char policy[PATH_MAX];
	FILE *file;
	unsigned i;

	permit_module = atf_tc_get_config_var(tc, "permit_module");
	deny_module = atf_tc_get_config_var(tc, "deny_module");
	ATF_REQUIRE(permit_module[0] == '/' && deny_module[0] == '/');
	ATF_REQUIRE(getcwd(policy, sizeof(policy)) != NULL);
	ATF_REQUIRE(strlcat(policy, "/policy", sizeof(policy)) < sizeof(policy));
	umask(0077);
	file = fopen(policy, "wx");
	ATF_REQUIRE(file != NULL);
	for (i = 0; i < sizeof(facilities) / sizeof(facilities[0]); i++) {
		if (mixed)
			ATF_REQUIRE(fprintf(file, "%s required %s\n", facilities[i], permit_module) > 0);
		ATF_REQUIRE(fprintf(file, "%s required %s\n", facilities[i],
		    deny ? deny_module : permit_module) > 0);
	}
	ATF_REQUIRE_EQ(0, fclose(file));
	/* Explicit absolute test inputs; keep ownership/permission checks enabled. */
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_start(policy, "dispatch-test", &conv, &pam));
	ATF_CHECK_EQ(deny ? PAM_AUTH_ERR : PAM_SUCCESS, pam_authenticate(pam, 0));
	ATF_CHECK_EQ(deny ? PAM_CRED_ERR : PAM_SUCCESS, pam_setcred(pam, PAM_ESTABLISH_CRED));
	ATF_CHECK_EQ(deny ? PAM_AUTH_ERR : PAM_SUCCESS, pam_acct_mgmt(pam, 0));
	ATF_CHECK_EQ(deny ? PAM_AUTHTOK_ERR : PAM_SUCCESS, pam_chauthtok(pam, 0));
	ATF_CHECK_EQ(deny ? PAM_SESSION_ERR : PAM_SUCCESS, pam_open_session(pam, 0));
	ATF_CHECK_EQ(deny ? PAM_SESSION_ERR : PAM_SUCCESS, pam_close_session(pam, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_end(pam, PAM_SUCCESS));
}

ATF_TC_WITHOUT_HEAD(permit);
ATF_TC_BODY(permit, tc) { check_dispatch(tc, 0, 0); }
ATF_TC_WITHOUT_HEAD(deny);
ATF_TC_BODY(deny, tc) { check_dispatch(tc, 1, 0); }
ATF_TC_WITHOUT_HEAD(required_deny);
ATF_TC_BODY(required_deny, tc) { check_dispatch(tc, 1, 1); }
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, permit);
	ATF_TP_ADD_TC(tp, deny);
	ATF_TP_ADD_TC(tp, required_deny);
	return (atf_no_error());
}

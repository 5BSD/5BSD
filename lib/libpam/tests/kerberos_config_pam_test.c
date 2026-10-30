/* SPDX-License-Identifier: BSD-2-Clause */
/* Load real Kerberos PAM modules; malformed local configuration must fail closed. */
#include <sys/stat.h>
#include <atf-c.h>
#include <dlfcn.h>
#include <limits.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
reject_conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
	unsigned *calls = data;
	(void)count;
	(void)messages;
	*responses = NULL;
	++*calls;
	return (PAM_CONV_ERR);
}

ATF_TC_WITHOUT_HEAD(malformed_config);
ATF_TC_BODY(malformed_config, tc)
{
	const char *module = atf_tc_get_config_var(tc, "module");
	unsigned calls = 0;
	struct pam_conv conv = { .conv = reject_conversation, .appdata_ptr = &calls };
	pam_handle_t *pam = NULL;
	char policy[PATH_MAX], config[PATH_MAX];
	FILE *file;
	void *handle;

	ATF_REQUIRE(module[0] == '/');
	handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	ATF_REQUIRE_MSG(handle != NULL, "dlopen(%s): %s", module, dlerror());
	ATF_REQUIRE(dlsym(handle, "pam_sm_authenticate") != NULL);
	ATF_REQUIRE(getcwd(policy, sizeof(policy)) != NULL);
	ATF_REQUIRE(strlcpy(config, policy, sizeof(config)) < sizeof(config));
	ATF_REQUIRE(strlcat(policy, "/policy", sizeof(policy)) < sizeof(policy));
	ATF_REQUIRE(strlcat(config, "/krb5.conf", sizeof(config)) < sizeof(config));
	umask(0077);
	file = fopen(config, "wx");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs("[libdefaults\n", file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE_EQ(0, setenv("KRB5_CONFIG", config, 1));
	file = fopen(policy, "wx");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fprintf(file, "auth required %s\n", module) > 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	/* Absolute test-owned policy/module paths; ownership checks remain enabled. */
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_start(policy, "kerberos-config-test", &conv, &pam));
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_set_item(pam, PAM_RUSER, "kerberos-config-test"));
	ATF_CHECK_EQ(PAM_SERVICE_ERR, pam_authenticate(pam, 0));
	ATF_CHECK_EQ(PAM_SERVICE_ERR, pam_authenticate(pam, 0));
	ATF_CHECK_EQ(0, calls);
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_end(pam, PAM_SERVICE_ERR));
	ATF_REQUIRE_EQ(0, dlclose(handle));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, malformed_config);
	return (atf_no_error());
}

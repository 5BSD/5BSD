/* SPDX-License-Identifier: BSD-2-Clause */
/* Real PAM/crypt dispatch with process-local account data, never host edits. */
#include <sys/types.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <limits.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

static char account_name[] = "hash-test";
static char account_class[] = "";
static char account_gecos[] = "";
static char account_home[] = "/nonexistent";
static char account_shell[] = "/bin/sh";
static struct passwd account = {
	.pw_name = account_name, .pw_uid = 1234, .pw_gid = 1234,
	.pw_class = account_class, .pw_gecos = account_gecos,
	.pw_dir = account_home, .pw_shell = account_shell
};
static unsigned int lookups;

/* Exported only by this test executable; the module uses real crypt(3). */
struct passwd *
getpwnam(const char *name)
{
	lookups++;
	return (strcmp(name, account.pw_name) == 0 ? &account : NULL);
}

static int
conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *context)
{
	struct pam_response *reply;
	int i;

	reply = calloc(count, sizeof(*reply));
	if (reply == NULL)
		return (PAM_BUF_ERR);
	for (i = 0; i < count; i++) {
		if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
			reply[i].resp = strdup(context);
			if (reply[i].resp == NULL)
				goto fail;
		} else if (messages[i]->msg_style != PAM_ERROR_MSG &&
		    messages[i]->msg_style != PAM_TEXT_INFO) {
			goto fail;
		}
	}
	*responses = reply;
	return (PAM_SUCCESS);
fail:
	for (i = 0; i < count; i++)
		free(reply[i].resp);
	free(reply);
	return (PAM_CONV_ERR);
}

static void
check(const char *policy, const char *hash, const char *password, int flags, int expected)
{
	struct pam_conv conv = { .conv = conversation,
	    .appdata_ptr = __DECONST(char *, password) };
	pam_handle_t *pam = NULL;

	account.pw_passwd = strdup(hash);
	ATF_REQUIRE(account.pw_passwd != NULL);
	lookups = 0;
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_start(policy, account.pw_name, &conv, &pam));
	ATF_REQUIRE_EQ(expected, pam_authenticate(pam, flags));
	ATF_REQUIRE(lookups > 0);
	ATF_REQUIRE_EQ(PAM_SUCCESS, pam_end(pam, PAM_SUCCESS));
	free(account.pw_passwd);
	account.pw_passwd = NULL;
}

ATF_TC(password_hashes);
ATF_TC_HEAD(password_hashes, tc)
{
	atf_tc_set_md_var(tc, "require.config", "module");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(password_hashes, tc)
{
	char policy[PATH_MAX], *hash;
	const char *module;
	FILE *file;

	openlog("password_hash_pam_test", LOG_PERROR, LOG_AUTH);
	module = atf_tc_get_config_var(tc, "module");
	ATF_REQUIRE(module[0] == '/');
	ATF_REQUIRE_EQ(0, access(module, R_OK));
	ATF_REQUIRE(getcwd(policy, sizeof(policy)) != NULL);
	ATF_REQUIRE(strlcat(policy, "/policy", sizeof(policy)) < sizeof(policy));
	umask(0077);
	file = fopen(policy, "wx");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fprintf(file, "auth required %s emptyok\n", module) > 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0));
	/* This fixture supplies only the facility under test, not host policy. */
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0));
	/* Prove the input exercises crypt failure, not merely a wrong password. */
	ATF_REQUIRE(crypt("password", "$2b$00$bad") == NULL);
	check(policy, "$2b$00$bad", "password", 0, PAM_AUTH_ERR);
	check(policy, "$2b$00$bad", "password", PAM_DISALLOW_NULL_AUTHTOK,
	    PAM_AUTH_ERR);
	hash = crypt("password", "$6$test-salt$");
	ATF_REQUIRE(hash != NULL);
	hash = strdup(hash);
	ATF_REQUIRE(hash != NULL);
	check(policy, hash, "password", 0, PAM_SUCCESS);
	check(policy, hash, "wrong", 0, PAM_AUTH_ERR);
	free(hash);
	hash = crypt("", "$6$test-salt$");
	ATF_REQUIRE(hash != NULL);
	hash = strdup(hash);
	ATF_REQUIRE(hash != NULL);
	check(policy, hash, "", 0, PAM_SUCCESS);
	check(policy, hash, "", PAM_DISALLOW_NULL_AUTHTOK, PAM_AUTH_ERR);
	free(hash);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, password_hashes);
	return (atf_no_error());
}

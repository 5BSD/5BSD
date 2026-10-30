/* SPDX-License-Identifier: BSD-2-Clause */
/* Real PAM dispatch; process-local account, class and resolver fixtures. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <atf-c.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <login_cap.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

static char name[] = "resolver-test", password[] = "*";
static char caps[] = "fixture:";
static struct passwd account = { .pw_name = name, .pw_passwd = password };
static login_cap_t login_class = { .lc_cap = caps };
static struct sockaddr_in address = {
	.sin_len = sizeof(address), .sin_family = AF_INET
};
static struct addrinfo answer = {
	.ai_family = AF_INET, .ai_addrlen = sizeof(address),
	.ai_addr = (struct sockaddr *)&address
};
static int resolver_error;
static unsigned int resolutions, releases, lookups;

struct passwd *
getpwnam(const char *user)
{
	lookups++;
	return (strcmp(user, name) == 0 ? &account : NULL);
}

login_cap_t *
login_getpwclass(const struct passwd *pwd)
{
	ATF_REQUIRE(pwd == &account);
	return (&login_class);
}

void
login_close(login_cap_t *lc)
{
	ATF_REQUIRE(lc == &login_class);
}

int
getaddrinfo(const char *host, const char *service,
    const struct addrinfo *hints, struct addrinfo **result)
{
	ATF_REQUIRE_STREQ("fixture.invalid", host);
	ATF_REQUIRE(service == NULL);
	ATF_REQUIRE_EQ(AF_UNSPEC, hints->ai_family);
	resolutions++;
	/* A failed call supplies no usable result, even when it is non-NULL. */
	*result = &answer;
	return (resolver_error);
}

void
freeaddrinfo(struct addrinfo *result)
{
	ATF_REQUIRE_EQ_MSG(0, resolver_error,
	    "PAM freed an address result from a failed lookup");
	ATF_REQUIRE(result == &answer);
	releases++;
}

ATF_TC(account_resolution);
ATF_TC_HEAD(account_resolution, tc)
{
	atf_tc_set_md_var(tc, "require.config", "module");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(account_resolution, tc)
{
	struct pam_conv conv = { 0 };
	pam_handle_t *pam;
	char policy[PATH_MAX];
	const char *module = atf_tc_get_config_var(tc, "module");
	FILE *file;
	int errors[] = { EAI_FAIL, EAI_NONAME, EAI_AGAIN, 0 };
	size_t i;

	openlog("account_resolution_pam_test", LOG_PERROR, LOG_AUTH);
	ATF_REQUIRE(module[0] == '/');
	ATF_REQUIRE_EQ(0, access(module, R_OK));
	ATF_REQUIRE(getcwd(policy, sizeof(policy)) != NULL);
	ATF_REQUIRE(strlcat(policy, "/policy", sizeof(policy)) < sizeof(policy));
	umask(0077);
	file = fopen(policy, "wx");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fprintf(file, "account required %s\n", module) > 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0));
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0));
	/* This fixture supplies only the facility under test, not host policy. */
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0));
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		resolver_error = errors[i];
		resolutions = releases = lookups = 0;
		ATF_REQUIRE_EQ(PAM_SUCCESS, pam_start(policy, name, &conv, &pam));
		ATF_REQUIRE_EQ(PAM_SUCCESS,
		    pam_set_item(pam, PAM_RHOST, "fixture.invalid"));
		ATF_REQUIRE_EQ(PAM_SUCCESS, pam_acct_mgmt(pam, 0));
		ATF_REQUIRE_EQ(1, lookups);
		ATF_REQUIRE_EQ(1, resolutions);
		ATF_REQUIRE_EQ(resolver_error == 0 ? 1 : 0, releases);
		ATF_REQUIRE_EQ(PAM_SUCCESS, pam_end(pam, PAM_SUCCESS));
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, account_resolution);
	return (atf_no_error());
}

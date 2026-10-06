/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "switchboard.h"
#include "authority.h"

static int
parse(const char *text, struct svc_domain *domain, struct svc_authority_scope *scope)
{
	char path[] = "boot-policy.XXXXXX";
	int fd = mkstemp(path), result, saved;

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
	result = svc_authority_parse_boot(fd, domain, scope);
	saved = errno;
	close(fd);
	errno = saved;
	return (result);
}
ATF_TC_WITHOUT_HEAD(valid_scope);
ATF_TC_BODY(valid_scope, tc)
{
	struct svc_domain domain;
	struct svc_authority_scope scope;

	(void)tc;
	ATF_REQUIRE(parse("endpoints=[\"system.SystemExtension\"];"
	    "attributes=[];admin_rights=true;", &domain, &scope) == 0);
	ATF_CHECK_EQ(scope.count, 1);
	ATF_CHECK_STREQ(scope.endpoints[0], "system.SystemExtension");
	ATF_CHECK(domain.anoint.admin_rights);
	ATF_CHECK(!domain.anoint.all && domain.anoint.n == 0);
	ATF_REQUIRE(parse("endpoints=[\"example.Service\"];"
	    "attributes=[\"example.permission\"];", &domain, &scope) == 0);
	ATF_CHECK(!domain.anoint.admin_rights);
	ATF_CHECK_EQ(domain.anoint.n, 1);
}
ATF_TC_WITHOUT_HEAD(reject_malformed);
ATF_TC_BODY(reject_malformed, tc)
{
	struct svc_domain domain;
	struct svc_authority_scope scope;
	const char *bad[] = {
	    "", "endpoints=[];", "endpoints=[\"*\"];", "endpoints=[42];",
	    "endpoints=[\"x.y\"];unknown=true;",
	    "endpoints=[\"x.y\"];anointments=[];",
	    "endpoints=[\"x.y\"];admin_rights=\"yes\";",
	    "endpoints=[\"x.y\"];admin_rights=true;admin_rights=false;",
	    "endpoints=[\"x.y\"];endpoints=[\"a.b\"];",
	    "endpoints=[\"x.y\"];attributes=[\"*\"];",
	    "endpoints=[\"x.y\"];attributes=\"a.b\";",
	    "endpoints=[\"x.y\\u0000hidden\"];",
	    "endpoints=[\"x.y\"];attributes=[\"a.b\\u0000hidden\"];"
	};

	(void)tc;
	for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		memset(&domain, 0xff, sizeof(domain));
		memset(&scope, 0xff, sizeof(scope));
		ATF_CHECK_MSG(parse(bad[i], &domain, &scope) == -1,
		    "accepted malformed policy: %s", bad[i]);
		ATF_CHECK_EQ(scope.count, 0);
		ATF_CHECK(!domain.anoint.admin_rights && !domain.anoint.all);
	}
}
ATF_TC_WITHOUT_HEAD(no_external_includes);
ATF_TC_BODY(no_external_includes, tc)
{
	struct svc_domain domain;
	struct svc_authority_scope scope;
	FILE *file;

	(void)tc;
	file = fopen("boot-external.ucl", "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs("endpoints=[\"example.Service\"];admin_rights=true;", file) >= 0);
	ATF_REQUIRE(fclose(file) == 0);
	ATF_REQUIRE(parse(".include \"boot-external.ucl\"\n", &domain, &scope) == -1);
	ATF_CHECK_EQ(scope.count, 0);
	ATF_CHECK(!domain.anoint.admin_rights);
	ATF_REQUIRE(unlink("boot-external.ucl") == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_scope);
	ATF_TP_ADD_TC(tp, reject_malformed);
	ATF_TP_ADD_TC(tp, no_external_includes);
	return (atf_no_error());
}

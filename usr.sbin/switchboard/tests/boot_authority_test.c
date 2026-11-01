/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "switchboard.h"
#include "authority.h"

static int
parse_bytes(const char *text, size_t length, struct svc_domain *domain,
    struct svc_authority_scope *scope)
{
	char path[] = "boot-policy.XXXXXX";
	int fd = mkstemp(path), result, saved;

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(write(fd, text, length) == (ssize_t)length);
	result = svc_authority_parse_boot(fd, domain, scope);
	saved = errno;
	close(fd);
	errno = saved;
	return (result);
}
static int
parse(const char *text, struct svc_domain *domain, struct svc_authority_scope *scope)
{
	return (parse_bytes(text, strlen(text), domain, scope));
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
	    "\"endpoints\\u0000suffix\"=[\"x.y\"];",
	    "endpoints=[\"x.y\"];\"admin_rights\\u0000suffix\"=true;",
	    "endpoints=[\"x.y\"];\"attributes\\u0000suffix\"=[\"a.b\"];",
	    "endpoints=[\"x.y\",\"x.y\"];",
	    "endpoints=[\"x.y\"];attributes=[\"a.b\",\"a.b\"];",
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

ATF_TC_WITHOUT_HEAD(descriptor_bounds);
ATF_TC_BODY(descriptor_bounds, tc)
{
	const char valid[] = "endpoints=[\"example.Service\"];";
	const char raw_nul[] = "endpoints=[\"example.Service\"];\0admin_rights=true;";
	struct svc_domain domain;
	struct svc_authority_scope scope;
	char *text;
	int fds[2], fd;

	(void)tc;
	ATF_REQUIRE_ERRNO(EBADF, svc_authority_parse_boot(-1, &domain, &scope) == -1);
	ATF_REQUIRE_EQ(scope.count, 0);
	ATF_REQUIRE_EQ(0, pipe(fds));
	ATF_REQUIRE_ERRNO(EINVAL, svc_authority_parse_boot(fds[0], &domain, &scope) == -1);
	close(fds[0]); close(fds[1]);
	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EINVAL, svc_authority_parse_boot(fd, &domain, &scope) == -1);
	close(fd);
	ATF_REQUIRE(parse_bytes(raw_nul, sizeof(raw_nul) - 1, &domain, &scope) == -1);
	ATF_REQUIRE_EQ(scope.count, 0);
	text = malloc(65537);
	ATF_REQUIRE(text != NULL);
	memset(text, ' ', 65537);
	memcpy(text, valid, sizeof(valid) - 1);
	ATF_REQUIRE_EQ(0, parse_bytes(text, 65536, &domain, &scope));
	ATF_REQUIRE_EQ(scope.count, 1);
	ATF_REQUIRE_ERRNO(EINVAL, parse_bytes(text, 65537, &domain, &scope) == -1);
	ATF_REQUIRE_EQ(scope.count, 0);
	free(text);
}

static int
parse_services(const char *text, struct svc_service_authority *out,
    unsigned max, unsigned *count)
{
	char path[] = "service-policy.XXXXXX";
	int fd = mkstemp(path), result, saved;

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
	result = svc_authority_parse_services(fd, out, max, count);
	saved = errno;
	close(fd);
	errno = saved;
	return (result);
}

ATF_TC_WITHOUT_HEAD(service_valid);
ATF_TC_BODY(service_valid, tc)
{
	struct svc_service_authority s[SVC_SERVICE_AUTHORITY_MAX];
	unsigned count = 99;

	(void)tc;
	ATF_REQUIRE(parse_services("devd { endpoints=[\"system.SystemExtension\"];"
	    "images=[\"/bin/sh\",\"/sbin/devd\"]; }"
	    "other { images=[\"/usr/sbin/x\"]; endpoints=[\"a.b\",\"c.d\"]; }",
	    s, SVC_SERVICE_AUTHORITY_MAX, &count) == 0);
	ATF_REQUIRE_EQ(count, 2);
	ATF_CHECK_STREQ(s[0].label, "devd");
	ATF_CHECK_EQ(s[0].scope.count, 1);
	ATF_CHECK_STREQ(s[0].scope.endpoints[0], "system.SystemExtension");
	ATF_CHECK_EQ(s[0].nimages, 2);
	ATF_CHECK_STREQ(s[0].images[1], "/sbin/devd");
	ATF_CHECK_STREQ(s[1].label, "other");
	ATF_CHECK_EQ(s[1].scope.count, 2);
	ATF_CHECK_EQ(s[1].nimages, 1);
}

ATF_TC_WITHOUT_HEAD(service_reject_malformed);
ATF_TC_BODY(service_reject_malformed, tc)
{
	struct svc_service_authority s[2];
	const char *bad[] = {
	    "devd=true;",
	    "devd { endpoints=[\"x.y\"]; }",
	    "devd { images=[\"/sbin/devd\"]; }",
	    "devd { endpoints=[]; images=[\"/sbin/devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin/devd\"]; admin_rights=true; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin/devd\"]; attributes=[\"a.b\"]; }",
	    "devd { endpoints=[\"*\"]; images=[\"/sbin/devd\"]; }",
	    "devd { endpoints=[\"x.y\",\"x.y\"]; images=[\"/sbin/devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"sbin/devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin/../tmp/devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin/./devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin//devd\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/sbin/\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/a\",\"/a\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/a\",\"/b\",\"/c\",\"/d\","
	    "\"/e\",\"/f\",\"/g\",\"/h\",\"/i\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[\"/a\\u0000b\"]; }",
	    "devd { endpoints=[\"x.y\"]; images=[42]; }",
	    "\"bad name\" { endpoints=[\"x.y\"]; images=[\"/a\"]; }",
	    "a.b { endpoints=[\"x.y\"]; images=[\"/a\"]; }",
	    "a { endpoints=[\"x.y\"]; images=[\"/a\"]; }"
	    "b { endpoints=[\"x.y\"]; images=[\"/a\"]; }"
	    "c { endpoints=[\"x.y\"]; images=[\"/a\"]; }",
	    ".include \"elsewhere.ucl\"\n",
	};
	unsigned count;

	(void)tc;
	for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		count = 99;
		memset(s, 0xff, sizeof(s));
		ATF_CHECK_MSG(parse_services(bad[i], s, 2, &count) == -1,
		    "accepted malformed service policy: %s", bad[i]);
		ATF_CHECK_EQ(count, 0);
		ATF_CHECK_EQ(s[0].scope.count, 0);
		ATF_CHECK_EQ(s[0].nimages, 0);
	}
}

/* The packaged policy parses and gives devd exactly one endpoint. */
ATF_TC(service_packaged_policy);
ATF_TC_HEAD(service_packaged_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The installed service-authority.ucl grants devd only SystemExtension");
}
ATF_TC_BODY(service_packaged_policy, tc)
{
	struct svc_service_authority s[SVC_SERVICE_AUTHORITY_MAX];
	const char *path = "/Capabilities/Config/switchboard/service-authority.ucl";
	unsigned count, i;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		atf_tc_skip("no packaged policy at %s", path);
	ATF_REQUIRE(svc_authority_parse_services(fd, s, SVC_SERVICE_AUTHORITY_MAX,
	    &count) == 0);
	close(fd);
	for (i = 0; i < count; i++)
		if (strcmp(s[i].label, "devd") == 0)
			break;
	ATF_REQUIRE_MSG(i < count, "devd has no lasting grant");
	ATF_CHECK_EQ(s[i].scope.count, 1);
	ATF_CHECK_STREQ(s[i].scope.endpoints[0], "system.SystemExtension");
}

static int
parse_root_query(const char *text, struct svc_authority_scope *scope)
{
	char path[] = "root-query.XXXXXX";
	int fd = mkstemp(path), result, saved;

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
	result = svc_authority_parse_root_query(fd, scope);
	saved = errno;
	close(fd);
	errno = saved;
	return (result);
}

ATF_TC_WITHOUT_HEAD(root_query_valid);
ATF_TC_BODY(root_query_valid, tc)
{
	struct svc_authority_scope scope;

	(void)tc;
	ATF_REQUIRE(parse_root_query("endpoints=[\"system.SystemExtension.Status\"];",
	    &scope) == 0);
	ATF_CHECK_EQ(scope.count, 1);
	ATF_CHECK_STREQ(scope.endpoints[0], "system.SystemExtension.Status");
	ATF_REQUIRE(parse_root_query("endpoints=[\"a.b\",\"c.d\"];", &scope) == 0);
	ATF_CHECK_EQ(scope.count, 2);
}

ATF_TC_WITHOUT_HEAD(root_query_reject_malformed);
ATF_TC_BODY(root_query_reject_malformed, tc)
{
	struct svc_authority_scope scope;
	const char *bad[] = {
	    "",
	    "endpoints=[];",
	    "endpoints=\"a.b\";",
	    "endpoints=[\"a.b\",\"a.b\"];",
	    "endpoints=[\"*\"];",
	    "endpoints=[42];",
	    "endpoints=[\"a.b\"];admin_rights=true;",
	    "endpoints=[\"a.b\"];attributes=[\"x.y\"];",
	    "endpoints=[\"a.b\"];uid=0;",
	    "endpoints=[\"a.b\"];endpoints=[\"c.d\"];",
	    "endpoints=[\"a\\u0000b\"];",
	    ".include \"elsewhere.ucl\"\n",
	};

	(void)tc;
	for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		memset(&scope, 0xff, sizeof(scope));
		ATF_CHECK_MSG(parse_root_query(bad[i], &scope) == -1,
		    "accepted malformed root query policy: %s", bad[i]);
		ATF_CHECK_EQ(scope.count, 0);
	}
}

/*
 * Only an unauthorized, kernel-stamped, unjailed UID 0 sender reaches a listed
 * name; every other caller, a name not listed, and control names are refused.
 */
ATF_TC_WITHOUT_HEAD(root_query_admits);
ATF_TC_BODY(root_query_admits, tc)
{
	struct svc_authority_scope scope;
	const char *status = "system.SystemExtension.Status";

	(void)tc;
	ATF_REQUIRE(parse_root_query("endpoints=[\"system.SystemExtension.Status\","
	    "\"x.Control\"];", &scope) == 0);
	ATF_CHECK(svc_authority_root_query_admits(&scope, false, true, 0, 0,
	    status));
	/* Non-root users get nothing. */
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 1001, 0,
	    status));
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 65534, 0,
	    status));
	/* Jailed root, an unstamped request, a caller with its own grant. */
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 0, 3,
	    status));
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, false, 0, 0,
	    status));
	ATF_CHECK(!svc_authority_root_query_admits(&scope, true, true, 0, 0,
	    status));
	/* The full broker endpoint is not read-only and is not listed. */
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 0, 0,
	    "system.SystemExtension"));
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 0, 0,
	    "x.Control"));
	ATF_CHECK(!svc_authority_root_query_admits(NULL, false, true, 0, 0,
	    status));
	ATF_CHECK(!svc_authority_root_query_admits(&scope, false, true, 0, 0,
	    NULL));
}

/* The packaged policy lists exactly the SystemExtension read-only view. */
ATF_TC(root_query_packaged_policy);
ATF_TC_HEAD(root_query_packaged_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The installed root-query.ucl lists only system.SystemExtension.Status");
}
ATF_TC_BODY(root_query_packaged_policy, tc)
{
	struct svc_authority_scope scope;
	const char *path = "/Capabilities/Config/switchboard/root-query.ucl";
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		atf_tc_skip("no packaged policy at %s", path);
	ATF_REQUIRE(svc_authority_parse_root_query(fd, &scope) == 0);
	close(fd);
	ATF_CHECK_EQ(scope.count, 1);
	ATF_CHECK_STREQ(scope.endpoints[0], "system.SystemExtension.Status");
}

/*
 * root-load.ucl uses the same admission over its own list: the load endpoint
 * reaches only an unauthorized, stamped, unjailed UID 0 sender, and a
 * read-only list never admits it.
 */
ATF_TC_WITHOUT_HEAD(root_load_admits);
ATF_TC_BODY(root_load_admits, tc)
{
	struct svc_authority_scope load, query;
	const char *rootload = "system.SystemExtension.RootLoad";

	(void)tc;
	ATF_REQUIRE(parse_root_query("endpoints=[\"system.SystemExtension.RootLoad\"];",
	    &load) == 0);
	ATF_REQUIRE(parse_root_query("endpoints=[\"system.SystemExtension.Status\"];",
	    &query) == 0);
	ATF_CHECK(svc_authority_root_query_admits(&load, false, true, 0, 0,
	    rootload));
	/* Non-root users, jailed root, unstamped, a caller with a grant. */
	ATF_CHECK(!svc_authority_root_query_admits(&load, false, true, 1001, 0,
	    rootload));
	ATF_CHECK(!svc_authority_root_query_admits(&load, false, true, 0, 7,
	    rootload));
	ATF_CHECK(!svc_authority_root_query_admits(&load, false, false, 0, 0,
	    rootload));
	ATF_CHECK(!svc_authority_root_query_admits(&load, true, true, 0, 0,
	    rootload));
	/* Neither the full broker endpoint nor the status view. */
	ATF_CHECK(!svc_authority_root_query_admits(&load, false, true, 0, 0,
	    "system.SystemExtension"));
	ATF_CHECK(!svc_authority_root_query_admits(&load, false, true, 0, 0,
	    "system.SystemExtension.Status"));
	/* The read-only list never admits the load endpoint. */
	ATF_CHECK(!svc_authority_root_query_admits(&query, false, true, 0, 0,
	    rootload));
}

/* The packaged policies keep the load endpoint out of the read-only list. */
ATF_TC(root_load_packaged_policy);
ATF_TC_HEAD(root_load_packaged_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The installed root-load.ucl lists only system.SystemExtension.RootLoad"
	    " and root-query.ucl does not list it");
}
ATF_TC_BODY(root_load_packaged_policy, tc)
{
	struct svc_authority_scope scope;
	const char *path = "/Capabilities/Config/switchboard/root-load.ucl";
	unsigned i;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		atf_tc_skip("no packaged policy at %s", path);
	ATF_REQUIRE(svc_authority_parse_root_query(fd, &scope) == 0);
	close(fd);
	ATF_CHECK_EQ(scope.count, 1);
	ATF_CHECK_STREQ(scope.endpoints[0], "system.SystemExtension.RootLoad");
	fd = open("/Capabilities/Config/switchboard/root-query.ucl", O_RDONLY);
	if (fd < 0)
		return;
	ATF_REQUIRE(svc_authority_parse_root_query(fd, &scope) == 0);
	close(fd);
	for (i = 0; i < scope.count; i++)
		ATF_CHECK(strcmp(scope.endpoints[i],
		    "system.SystemExtension.RootLoad") != 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, descriptor_bounds);
	ATF_TP_ADD_TC(tp, valid_scope);
	ATF_TP_ADD_TC(tp, reject_malformed);
	ATF_TP_ADD_TC(tp, no_external_includes);
	ATF_TP_ADD_TC(tp, service_valid);
	ATF_TP_ADD_TC(tp, service_reject_malformed);
	ATF_TP_ADD_TC(tp, service_packaged_policy);
	ATF_TP_ADD_TC(tp, root_query_valid);
	ATF_TP_ADD_TC(tp, root_query_reject_malformed);
	ATF_TP_ADD_TC(tp, root_query_admits);
	ATF_TP_ADD_TC(tp, root_query_packaged_policy);
	ATF_TP_ADD_TC(tp, root_load_admits);
	ATF_TP_ADD_TC(tp, root_load_packaged_policy);
	return (atf_no_error());
}

/* SPDX-License-Identifier: BSD-2-Clause */
/* Production resolver, real module files, explicit isolated search directories. */
#include <sys/types.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/openpam.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openpam_impl.h"

#define STRING_(x) #x
#define STRING(x) STRING_(x)
#define MODULE "probe.so." STRING(LIB_MAJ)
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return (PAM_AUTH_ERR);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return (PAM_CRED_ERR);
}

PAM_MODULE_ENTRY("probe");

const char *openpam_module_path[] = { "first", "second", NULL };

static void
copy_module(const atf_tc_t *tc, const char *path, mode_t mode)
{
	char buffer[16384];
	ssize_t n;
	int from, to;

	from = open(atf_tc_get_config_var_wd(tc, "pam_module",
	    "/usr/lib/pam_deny.so." STRING(LIB_MAJ)), O_RDONLY);
	ATF_REQUIRE(from >= 0);
	to = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(to >= 0);
	while ((n = read(from, buffer, sizeof(buffer))) > 0)
		ATF_REQUIRE_EQ(n, write(to, buffer, n));
	ATF_REQUIRE_EQ(0, n);
	ATF_REQUIRE_EQ(0, fchmod(to, mode));
	ATF_REQUIRE_EQ(0, close(to));
	ATF_REQUIRE_EQ(0, close(from));
}

static void
prepare(const atf_tc_t *tc)
{
	ATF_REQUIRE_EQ(0, mkdir("first", 0700));
	ATF_REQUIRE_EQ(0, mkdir("second", 0700));
	ATF_REQUIRE_EQ(PAM_SUCCESS,
	    openpam_set_feature(OPENPAM_VERIFY_MODULE_FILE, 1));
	copy_module(tc, "second/" MODULE, 0444);
}

static void
expect_module(const char *name, const char *path)
{
	pam_module_t *module;

	module = openpam_dynamic(name);
	ATF_REQUIRE_MSG(module != NULL, "load %s: errno=%d", name, errno);
	ATF_CHECK_STREQ(path, module->path);
	ATF_CHECK(module->func[PAM_SM_AUTHENTICATE] != NULL);
	ATF_REQUIRE_EQ(0, dlclose(module->dlh));
	free(module->path);
	free(module);
}

ATF_TC_WITHOUT_HEAD(missing_candidate_falls_back);
ATF_TC_BODY(missing_candidate_falls_back, tc)
{
	prepare(tc);
	expect_module("probe.so", "second/" MODULE);
	copy_module(tc, "first/probe.so", 0444);
	expect_module("probe.so", "first/probe.so");
}

ATF_TC_WITHOUT_HEAD(unsafe_versioned_stops_search);
ATF_TC_BODY(unsafe_versioned_stops_search, tc)
{
	prepare(tc);
	copy_module(tc, "first/" MODULE, 0666);
	copy_module(tc, "first/probe.so", 0444);
	errno = 0;
	ATF_REQUIRE(openpam_dynamic("probe.so") == NULL);
	ATF_CHECK_EQ(EPERM, errno);
}

ATF_TC_WITHOUT_HEAD(unsafe_unversioned_stops_search);
ATF_TC_BODY(unsafe_unversioned_stops_search, tc)
{
	prepare(tc);
	copy_module(tc, "first/probe.so", 0666);
	errno = 0;
	ATF_REQUIRE(openpam_dynamic("probe.so") == NULL);
	ATF_CHECK_EQ(EPERM, errno);
}

ATF_TC_WITHOUT_HEAD(malformed_module_stops_search);
ATF_TC_BODY(malformed_module_stops_search, tc)
{
	int fd;

	prepare(tc);
	fd = open("first/" MODULE, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(10, write(fd, "not an ELF", 10));
	ATF_REQUIRE_EQ(0, close(fd));
	errno = 0;
	ATF_REQUIRE(openpam_dynamic("probe.so") == NULL);
	ATF_CHECK_EQ(ENOEXEC, errno);
}

ATF_TC_WITHOUT_HEAD(explicit_version_is_exact);
ATF_TC_BODY(explicit_version_is_exact, tc)
{
	prepare(tc);
	copy_module(tc, "first/" MODULE, 0444);
	expect_module(MODULE, "first/" MODULE);
}

ATF_TC_WITHOUT_HEAD(static_fallback_only_for_absence);
ATF_TC_BODY(static_fallback_only_for_absence, tc)
{
	int fd;

	prepare(tc);
	ATF_REQUIRE_EQ(0, unlink("second/" MODULE));
	copy_module(tc, "first/" MODULE, 0666);
	ATF_REQUIRE(openpam_load_module("probe.so") == NULL);
	ATF_CHECK_EQ(EPERM, errno);
	ATF_REQUIRE_EQ(0, unlink("first/" MODULE));
	ATF_REQUIRE(openpam_load_module("probe.so") == &_pam_module);
	fd = open("first/" MODULE, O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(3, write(fd, "bad", 3));
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE(openpam_load_module("probe.so") == NULL);
	ATF_CHECK_EQ(ENOEXEC, errno);
}

ATF_TC_WITHOUT_HEAD(search_path_overflow_is_not_absence);
ATF_TC_BODY(search_path_overflow_is_not_absence, tc)
{
	char oversized[8192];

	prepare(tc);
	memset(oversized, 'x', sizeof(oversized) - 1);
	oversized[sizeof(oversized) - 1] = '\0';
	openpam_module_path[0] = oversized;
	ATF_REQUIRE(openpam_dynamic("probe.so") == NULL);
	ATF_CHECK_EQ(ENAMETOOLONG, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, static_fallback_only_for_absence);
	ATF_TP_ADD_TC(tp, search_path_overflow_is_not_absence);
	ATF_TP_ADD_TC(tp, missing_candidate_falls_back);
	ATF_TP_ADD_TC(tp, unsafe_versioned_stops_search);
	ATF_TP_ADD_TC(tp, unsafe_unversioned_stops_search);
	ATF_TP_ADD_TC(tp, malformed_module_stops_search);
	ATF_TP_ADD_TC(tp, explicit_version_is_exact);
	return (atf_no_error());
}

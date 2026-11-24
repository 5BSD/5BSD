/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/procdesc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nss_exchange.h"

static void
require_kernel(void)
{
	int feature = 0, pd, status;
	size_t size = sizeof(feature);
	pid_t pid;
	if (sysctlbyname("kern.features.cap_process", &feature, &size, NULL, 0) == -1 ||
	    feature != 1) atf_tc_skip("cap_process kernel feature required");
	pid = pdfork(&pd, PD_CLOEXEC | PD_NOWAITPID | PD_PROTECTED);
	if (pid == -1 && (errno == EINVAL || errno == EOPNOTSUPP))
		atf_tc_skip("protected pdfork flags required");
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) _exit(0);
	ATF_REQUIRE_EQ(pdwait(pd, &status, WEXITED, NULL, NULL), 0);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(pd);
}
/*
 * The timeout of the cases that run the probe (kyua's default, stated so
 * that the body can read it).
 */
#define	CASE_TIMEOUT	"300"

/*
 * The exchange's deadline: the case's own ATF timeout, so the case's timer,
 * which started first, always ends a wait that never ends before the
 * exchange would.  A guessed short deadline fails a correct exchange on a
 * slow machine.
 */
static int
case_timeout_ms(const atf_tc_t *tc)
{
	const char *text;
	char *end;
	long seconds;

	ATF_REQUIRE_MSG(atf_tc_has_md_var(tc, "timeout"),
	    "the case states no timeout to derive its deadline from");
	text = atf_tc_get_md_var(tc, "timeout");
	errno = 0;
	seconds = strtol(text, &end, 10);
	ATF_REQUIRE_MSG(errno == 0 && end != text && *end == '\0' &&
	    seconds > 0 && seconds <= INT_MAX / 1000,
	    "case timeout \"%s\" is not a usable deadline", text);
	return ((int)seconds * 1000);
}

static void
probe(const atf_tc_t *tc)
{
	struct sb_nss_request request = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = 1000 };
	struct sb_nss_reply reply;
	char path[PATH_MAX];
	int fd, marker, saved, result;
	const char *override = atf_tc_get_config_var_wd(tc, "probe", "");
	if (override[0] != '\0') {
		ATF_REQUIRE(strlcpy(path, override, sizeof(path)) < sizeof(path));
	} else {
		ATF_REQUIRE(snprintf(path, sizeof(path), "%s/nss_isolation_probe",
		    atf_tc_get_config_var(tc, "srcdir")) < (int)sizeof(path));
	}
	fd = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	/* Preserve any preexisting test-runner descriptor at the chosen marker. */
	saved = fcntl(128, F_DUPFD_CLOEXEC, 129);
	ATF_REQUIRE(saved >= 0 || errno == EBADF);
	marker = dup2(fd, 128);
	ATF_REQUIRE_EQ(marker, 128);
	ATF_REQUIRE(setenv("NSS_ISOLATION_PARENT_MARKER", "must-not-survive", 1) == 0);
	result = sb_nss_exchange(path, fd, &request, 1000, case_timeout_ms(tc),
	    &reply);
	int error = errno;
	ATF_REQUIRE(fcntl(marker, F_GETFD) >= 0);
	close(marker);
	if (saved >= 0) { ATF_REQUIRE_EQ(dup2(saved, 128), 128); close(saved); }
	close(fd);
	ATF_REQUIRE_MSG(result == 0, "isolation probe failed: %s", strerror(error));
	ATF_REQUIRE_STREQ(reply.name, "isolation-probe");
}
ATF_TC(clean_exec);
ATF_TC_HEAD(clean_exec, tc)
{
	atf_tc_set_md_var(tc, "timeout", CASE_TIMEOUT);
}
ATF_TC_BODY(clean_exec, tc)
{
	require_kernel();
	probe(tc);
}
ATF_TC(inherited_authority);
ATF_TC_HEAD(inherited_authority, tc)
{
	atf_tc_set_md_var(tc, "timeout", CASE_TIMEOUT);
}
ATF_TC_BODY(inherited_authority, tc)
{
	struct cap_authority_info info, after;
	require_kernel();
	ATF_REQUIRE(syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &info) == 0);
	if (info.identity == 0 || info.valid == 0 || info.revoked != 0)
		atf_tc_skip("requires a supervisor-launched test with valid attached authority");
	probe(tc);
	ATF_REQUIRE(syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &after) == 0);
	ATF_REQUIRE_EQ(after.identity, info.identity);
	ATF_REQUIRE_EQ(after.generation, info.generation);
	ATF_REQUIRE_EQ(after.valid, 1);
}
ATF_TC(inherited_discovery);
ATF_TC_HEAD(inherited_discovery, tc)
{
	atf_tc_set_md_var(tc, "timeout", CASE_TIMEOUT);
}
ATF_TC_BODY(inherited_discovery, tc)
{
	struct mac_cap_process_info info, after;
	require_kernel();
	ATF_REQUIRE(syscall(SYS_cap_process, MAC_CAP_PROCESS_INFO, -1, 0, &info) == 0);
	if (info.present == 0)
		atf_tc_skip("requires a supervisor-launched test with inherited discovery context");
	probe(tc);
	ATF_REQUIRE(syscall(SYS_cap_process, MAC_CAP_PROCESS_INFO, -1, 0, &after) == 0);
	ATF_REQUIRE_EQ(after.present, 1);
	ATF_REQUIRE_EQ(after.generation, info.generation);
	ATF_REQUIRE_EQ(after.identity, info.identity);
}
ATF_TC_WITHOUT_HEAD(real_account_lookup);
ATF_TC_BODY(real_account_lookup, tc)
{
	struct sb_nss_request request = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = getuid() };
	struct sb_nss_reply reply;
	char name[SB_NSS_NAME_MAX];
	struct passwd *pw;
	int fd;
	require_kernel();
	pw = getpwuid(getuid());
	ATF_REQUIRE(pw != NULL);
	ATF_REQUIRE(strlcpy(name, pw->pw_name, sizeof(name)) < sizeof(name));
	fd = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_MSG(sb_nss_exchange(atf_tc_get_config_var_wd(tc, "helper",
	    "/usr/libexec/switchboard-nss"), fd, &request, getuid(), 5000, &reply) == 0,
	    "real helper lookup failed: %s", strerror(errno));
	close(fd);
	ATF_REQUIRE_STREQ(reply.name, name);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, clean_exec);
	ATF_TP_ADD_TC(tp, inherited_authority);
	ATF_TP_ADD_TC(tp, inherited_discovery);
	ATF_TP_ADD_TC(tp, real_account_lookup);
	return (atf_no_error());
}

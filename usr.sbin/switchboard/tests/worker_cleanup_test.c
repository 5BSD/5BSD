/* SPDX-License-Identifier: BSD-2-Clause */
/* Registry revocation tests use a syscall double and real owned descriptors.
 * These check bookkeeping and fatal error handling, not kernel enforcement. */
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include "../switchboard.h"
static int authority_syscall(int, ...);
#define syscall(...) authority_syscall(__VA_ARGS__)
#include "../authority.c"
#undef syscall
struct switchboard_state sd;
struct svc_runtime *svc_by_label_scoped(const char *label __unused, uid_t uid __unused)
{ return (NULL); }
static int
owned_fd(void)
{
	int pair[2];
	ATF_REQUIRE(pipe(pair) == 0);
	ATF_REQUIRE(close(pair[1]) == 0);
	return (pair[0]);
}

static unsigned revoked;
static int expected_token;
static int revoke_error;
static int
authority_syscall(int number, ...)
{
	va_list ap;
	int op, issuer, flags;
	struct cap_authority_revoke *request;

	ATF_REQUIRE_EQ(SYS_cap_process, number);
	va_start(ap, number);
	op = va_arg(ap, int); issuer = va_arg(ap, int); flags = va_arg(ap, int);
	request = va_arg(ap, struct cap_authority_revoke *);
	va_end(ap);
	ATF_REQUIRE_EQ(CAP_AUTH_REVOKE, op);
	ATF_REQUIRE_EQ(sd.authority_issuer_fd, issuer);
	ATF_REQUIRE_EQ(0, flags);
	ATF_REQUIRE_EQ(expected_token, request->token_fd);
	revoked++;
	if (revoke_error != 0) return (errno = revoke_error, -1);
	return (0);
}

ATF_TC_WITHOUT_HEAD(revocation_failure_stops_broker);
ATF_TC_BODY(revocation_failure_stops_broker, tc)
{
	(void)tc;
	const int errors[] = {EIO, EBADF, EPERM};
	for (size_t i = 0; i < nitems(errors); i++) {
		int status;
		pid_t child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			struct authority_record *record = calloc(1, sizeof(*record));
			ATF_REQUIRE(record != NULL);
			record->token = expected_token = owned_fd();
			sd.authority_issuer_fd = owned_fd();
			revoke_error = errors[i];
			nrecords = 1;
			remove_record(&record);
			_exit(99); /* Returning would lose tracking after failed revocation. */
		}
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_REQUIRE(WIFEXITED(status));
		ATF_CHECK_EQ(EX_SOFTWARE, WEXITSTATUS(status));
	}
}

ATF_TC_WITHOUT_HEAD(unit_revocation_selects_exact_launch);
ATF_TC_BODY(unit_revocation_selects_exact_launch, tc)
{
	struct svc_runtime owner = {0};
	struct authority_record *entries[6];
	int tokens[6];
	(void)tc;

	owner.launch_id = 41;
	owner.owner_uid = 1001;
	strlcpy(owner.manifest.label, "test.Client/worker",
	    sizeof(owner.manifest.label));
	for (unsigned i = 0; i < nitems(entries); i++) {
		struct authority_record *r = calloc(1, sizeof(*r));
		ATF_REQUIRE(r != NULL);
		entries[i] = r;
		r->token = tokens[i] = owned_fd();
		r->launch_id = owner.launch_id;
		r->owner_uid = owner.owner_uid;
		r->kind = CAP_AUTH_MANAGED;
		strlcpy(r->label, owner.manifest.label, sizeof(r->label));
		/* A collision chain exercises removal without losing neighbours. */
		r->next = records[0];
		records[0] = r;
	}
	entries[0]->launch_id++;
	entries[1]->owner_uid++;
	strlcpy(entries[2]->label, "test.Other/worker", sizeof(entries[2]->label));
	/* Only entry 3 matches. Application records have a separate lifetime. */
	entries[4]->application = true;
	entries[5]->kind = 0;
	expected_token = tokens[3];
	nrecords = nitems(entries);
	revoked = 0;
	svc_authority_revoke_unit(&owner);
	ATF_CHECK_EQ(1, revoked);
	ATF_CHECK_EQ(nitems(entries) - 1, nrecords);
	ATF_CHECK_ERRNO(EBADF, fcntl(tokens[3], F_GETFD) == -1);
	for (unsigned i = 0; i < nitems(entries); i++)
		if (i != 3)
			ATF_REQUIRE(fcntl(tokens[i], F_GETFD) >= 0);
	/* A repeated disconnect must not revoke a different launch. */
	svc_authority_revoke_unit(&owner);
	ATF_CHECK_EQ(1, revoked);
	unsigned remaining = 0;
	while (records[0] != NULL) {
		struct authority_record *r = records[0];
		records[0] = r->next;
		close(r->token);
		free(r);
		remaining++;
	}
	ATF_CHECK_EQ(nitems(entries) - 1, remaining);
	nrecords = 0;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unit_revocation_selects_exact_launch);
	ATF_TP_ADD_TC(tp, revocation_failure_stops_broker);
	return (atf_no_error());
}

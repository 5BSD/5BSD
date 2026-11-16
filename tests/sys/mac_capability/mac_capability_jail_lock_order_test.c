/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The isolation service's prison checks run with the prison's mutex held,
 * which WITNESS orders after process locks.  They must read the caller's
 * software authority without taking its process lock: a jail_get(2) and a
 * jail_remove(2) of a claimed jail must leave no "jail mutex" / "process
 * lock" reversal in debug.witness.badstacks.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_isolation_proto.h"

#define	JAIL_NAME	"fi_lock_order_jail"

static int
fi_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = mac_capability_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "isolation", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0)
		atf_tc_fail("connect isolation: %s", strerror(errno));
	close(ctl);
	return (ca.fd);
}

static int
fi_jail_call(int svc, uint32_t op, const char *name, uint32_t actions)
{
	struct mac_capability_call_args ca;
	struct fi_jail_request jr;
	struct fi_reply rpl;

	memset(&jr, 0, sizeof(jr));
	jr.op = op;
	jr.actions = actions;
	strlcpy(jr.name, name, sizeof(jr.name));
	memset(&ca, 0, sizeof(ca));
	ca.req = &jr;
	ca.req_len = sizeof(jr);
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	return (ioctl(svc, MAC_CAPABILITY_CALL, &ca));
}

static int
jail_by_name(const char *name)
{
	struct iovec iov[2];
	char namebuf[64];

	strlcpy(namebuf, name, sizeof(namebuf));
	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = namebuf;
	iov[1].iov_len = strlen(namebuf) + 1;
	return (jail_get(iov, 2, 0));
}

/* Whether WITNESS has recorded a reversal between the two lock names. */
static bool
witness_reversal(const char *a, const char *b)
{
	char line[512];
	FILE *fp;
	bool found = false;

	fp = popen("sysctl -n debug.witness.badstacks", "r");
	ATF_REQUIRE(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, "Lock order reversal between") != NULL &&
		    strstr(line, a) != NULL && strstr(line, b) != NULL)
			found = true;
	}
	pclose(fp);
	return (found);
}

ATF_TC_WITH_CLEANUP(claimed_jail_get_remove);
ATF_TC_HEAD(claimed_jail_get_remove, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "prison checks of a claimed jail take no process lock");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(claimed_jail_get_remove, tc)
{
	struct iovec iov[6];
	size_t len;
	int jid, persist = 1, svc, watch;

	len = sizeof(watch);
	if (sysctlbyname("debug.witness.watch", &watch, &len, NULL, 0) != 0 ||
	    watch < 1)
		atf_tc_skip("WITNESS is not running");
	if (witness_reversal("\"jail mutex\"", "\"process lock\""))
		atf_tc_skip("the reversal was recorded earlier in this boot");

	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, JAIL_NAME);
	iov[1].iov_len = sizeof(JAIL_NAME);
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = &persist;
	iov[5].iov_len = sizeof(persist);
	jid = jail_set(iov, 6, JAIL_CREATE);
	ATF_REQUIRE_MSG(jid > 0, "jail_set: %s", strerror(errno));

	/* Claimed by this process: its own checks pass, and are made. */
	svc = fi_connect();
	ATF_REQUIRE_MSG(fi_jail_call(svc, FI_OP_CLAIM_JAIL, JAIL_NAME,
	    FI_JAIL_GET | FI_JAIL_REMOVE) == 0, "claim: %s", strerror(errno));
	ATF_CHECK_EQ(jid, jail_by_name(JAIL_NAME));
	ATF_CHECK_MSG(jail_remove(jid) == 0, "jail_remove: %s",
	    strerror(errno));
	close(svc);

	ATF_CHECK_MSG(!witness_reversal("\"jail mutex\"", "\"process lock\""),
	    "WITNESS recorded a jail mutex / process lock reversal");
}
ATF_TC_CLEANUP(claimed_jail_get_remove, tc)
{
	int jid;

	(void)tc;
	jid = jail_by_name(JAIL_NAME);
	if (jid > 0)
		(void)jail_remove(jid);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, claimed_jail_get_remove);
	return (atf_no_error());
}

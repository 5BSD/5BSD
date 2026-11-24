/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * jail_remove(2) of a jail with no processes frees it before it returns:
 * the jail is gone from the dying list at once, and a vnet jail's
 * interfaces are back in the caller's vnet.  rc.d/jail and the vnet.subr
 * cleanups rely on both right after "jail -r".  This pins the existing
 * behaviour; a free deferred to a task leaves the jail dying (and the
 * interface away) for a moment after the call, which the checks made in
 * the same thread, right after the call, see.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>

#include <errno.h>
#include <jail.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Repeat the remove to make a short-lived deferred free visible.  A vnet
 * jail costs a vnet create and destroy each time (seconds under emulation),
 * so it repeats fewer times; a deferred free fails it on the first.
 */
#define	ITERATIONS	200
#define	VNET_ITERATIONS	10

static const char jname[] = "jrsync";

static int
jail_create(bool vnet)
{
	int jid;

	if (vnet)
		jid = jail_setv(JAIL_CREATE, "name", jname, "persist", NULL,
		    "vnet", "new", NULL);
	else
		jid = jail_setv(JAIL_CREATE, "name", jname, "persist", NULL,
		    NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	return (jid);
}

/* Is a jail with this jid still there, alive or dying? */
static bool
jail_present(int jid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", jid);
	return (jail_getv(JAIL_DYING, "jid", buf, NULL) == jid);
}

static void
remove_cleanup(void)
{
	int jid;

	jid = jail_getid(jname);
	if (jid > 0)
		(void)jail_remove(jid);
}

ATF_TC_WITH_CLEANUP(persist_gone_at_return);
ATF_TC_HEAD(persist_gone_at_return, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "jail_remove of a persist-only jail leaves no dying jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(persist_gone_at_return, tc)
{
	int i, jid;

	for (i = 0; i < ITERATIONS; i++) {
		jid = jail_create(false);
		ATF_REQUIRE_EQ_MSG(jail_remove(jid), 0, "jail_remove: %s",
		    strerror(errno));
		ATF_REQUIRE_MSG(!jail_present(jid),
		    "iteration %d: jail %d still listed after jail_remove", i,
		    jid);
	}
}
ATF_TC_CLEANUP(persist_gone_at_return, tc)
{
	remove_cleanup();
}

static char epair[IFNAMSIZ];

static void
epair_create(int s)
{
	struct ifreq ifr;
	FILE *f;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, "epair", sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFCREATE2, &ifr) != 0)
		atf_tc_skip("cannot create an epair: %s", strerror(errno));
	strlcpy(epair, ifr.ifr_name, sizeof(epair));
	f = fopen("created_epair", "w");
	if (f != NULL) {
		fprintf(f, "%s\n", epair);
		fclose(f);
	}
}

ATF_TC_WITH_CLEANUP(vnet_interface_back_at_return);
ATF_TC_HEAD(vnet_interface_back_at_return, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "jail_remove of a persist vnet jail returns its interface");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vnet_interface_back_at_return, tc)
{
	struct ifreq ifr;
	int i, jid, s, vimage;
	size_t len;

	len = sizeof(vimage);
	if (sysctlbyname("kern.features.vimage", &vimage, &len, NULL, 0) != 0 ||
	    vimage == 0)
		atf_tc_skip("This test requires VIMAGE");
	s = socket(AF_INET, SOCK_DGRAM, 0);
	ATF_REQUIRE(s >= 0);
	epair_create(s);
	for (i = 0; i < VNET_ITERATIONS; i++) {
		jid = jail_create(true);
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, epair, sizeof(ifr.ifr_name));
		ifr.ifr_jid = jid;
		ATF_REQUIRE_EQ_MSG(ioctl(s, SIOCSIFVNET, &ifr), 0,
		    "SIOCSIFVNET: %s", strerror(errno));
		ATF_REQUIRE_EQ(if_nametoindex(epair), 0);
		ATF_REQUIRE_EQ_MSG(jail_remove(jid), 0, "jail_remove: %s",
		    strerror(errno));
		ATF_REQUIRE_MSG(if_nametoindex(epair) != 0,
		    "iteration %d: %s not back when jail_remove returned", i,
		    epair);
		ATF_REQUIRE_MSG(!jail_present(jid),
		    "iteration %d: jail %d still listed after jail_remove", i,
		    jid);
	}
	close(s);
}
ATF_TC_CLEANUP(vnet_interface_back_at_return, tc)
{
	struct ifreq ifr;
	FILE *f;
	int s;

	remove_cleanup();
	f = fopen("created_epair", "r");
	if (f == NULL)
		return;
	memset(&ifr, 0, sizeof(ifr));
	if (fgets(ifr.ifr_name, sizeof(ifr.ifr_name), f) != NULL) {
		ifr.ifr_name[strcspn(ifr.ifr_name, "\n")] = '\0';
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s >= 0) {
			(void)ioctl(s, SIOCIFDESTROY, &ifr);
			close(s);
		}
	}
	fclose(f);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, persist_gone_at_return);
	ATF_TP_ADD_TC(tp, vnet_interface_back_at_return);
	return (atf_no_error());
}

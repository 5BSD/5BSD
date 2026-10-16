/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * 5BSD follows OpenBSD's IPv4 address ioctls: the historical SIOCSIFADDR,
 * SIOCSIFNETMASK and SIOCSIFBRDADDR requests, contiguous netmasks, and a
 * point-to-point address without a destination.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

static char ifname[IFNAMSIZ];

static int
inetsock(void)
{
	int s;

	ATF_REQUIRE((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);
	return (s);
}

static void
create(int s, const char *driver)
{
	struct ifreq ifr = {};

	strlcpy(ifr.ifr_name, driver, sizeof(ifr.ifr_name));
	ATF_REQUIRE_MSG(ioctl(s, SIOCIFCREATE, &ifr) == 0,
	    "SIOCIFCREATE %s: %s", driver, strerror(errno));
	strlcpy(ifname, ifr.ifr_name, sizeof(ifname));
}

static void
destroy(int s)
{
	struct ifreq ifr = {};

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	(void)ioctl(s, SIOCIFDESTROY, &ifr);
}

static struct sockaddr_in
sin(const char *a, sa_family_t family)
{
	struct sockaddr_in s = {
		.sin_len = sizeof(struct sockaddr_in),
		.sin_family = family,
	};

	ATF_REQUIRE(inet_pton(AF_INET, a, &s.sin_addr) == 1);
	return (s);
}

static int
set(int s, u_long cmd, const char *a)
{
	struct ifreq ifr = {};
	struct sockaddr_in sa;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	/* As OpenBSD's ifconfig, a netmask carries no family. */
	sa = sin(a, cmd == SIOCSIFNETMASK ? AF_UNSPEC : AF_INET);
	memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
	return (ioctl(s, cmd, &ifr));
}

/* SIOCGIF* of the address @a, or of the first one if @a is NULL. */
static const char *
get(int s, u_long cmd, const char *a)
{
	static char buf[INET_ADDRSTRLEN];
	struct ifreq ifr = {};
	struct sockaddr_in sa;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (a != NULL) {
		sa = sin(a, AF_INET);
		memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
	}
	ATF_REQUIRE_MSG(ioctl(s, cmd, &ifr) == 0, "ioctl: %s",
	    strerror(errno));
	memcpy(&sa, &ifr.ifr_addr, sizeof(sa));
	return (inet_ntop(AF_INET, &sa.sin_addr, buf, sizeof(buf)));
}

static int
add(int s, const char *a, const char *mask, const char *dst)
{
	struct in_aliasreq ifra = {};

	strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));
	ifra.ifra_addr = sin(a, AF_INET);
	if (mask != NULL)
		ifra.ifra_mask = sin(mask, AF_UNSPEC);
	if (dst != NULL)
		ifra.ifra_dstaddr = sin(dst, AF_INET);
	return (ioctl(s, SIOCAIFADDR, &ifra));
}

/* The number of IPv4 addresses @a (all if NULL) on the interface. */
static int
count(const char *a)
{
	struct ifaddrs *ifa0, *ifa;
	struct in_addr in;
	struct sockaddr_in sa;
	int n = 0;

	if (a != NULL)
		ATF_REQUIRE(inet_pton(AF_INET, a, &in) == 1);
	ATF_REQUIRE(getifaddrs(&ifa0) == 0);
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0 ||
		    ifa->ifa_addr->sa_family != AF_INET)
			continue;
		memcpy(&sa, ifa->ifa_addr, sizeof(sa));
		if (a == NULL || sa.sin_addr.s_addr == in.s_addr)
			n++;
	}
	freeifaddrs(ifa0);
	return (n);
}

ATF_TC(sifaddr);
ATF_TC_HEAD(sifaddr, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SIOCSIFADDR, SIOCSIFNETMASK and SIOCSIFBRDADDR as OpenBSD");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sifaddr, tc)
{
	int s = inetsock();

	create(s, "vether");

	/* The first address gets its classful netmask. */
	ATF_REQUIRE(set(s, SIOCSIFADDR, "192.0.2.1") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, NULL), "255.255.255.0");
	ATF_CHECK_STREQ(get(s, SIOCGIFBRDADDR, NULL), "192.0.2.255");

	/* A new netmask keeps the broadcast address. */
	ATF_REQUIRE(set(s, SIOCSIFNETMASK, "255.255.0.0") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, NULL), "255.255.0.0");
	ATF_CHECK_STREQ(get(s, SIOCGIFBRDADDR, NULL), "192.0.2.255");

	/* A netmask must be contiguous. */
	ATF_CHECK_ERRNO(EINVAL, set(s, SIOCSIFNETMASK, "255.255.255.64") == -1);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, NULL), "255.255.0.0");

	ATF_REQUIRE(set(s, SIOCSIFBRDADDR, "255.255.255.255") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFBRDADDR, NULL), "255.255.255.255");

	/* A second SIOCSIFADDR replaces the address and keeps the mask. */
	ATF_REQUIRE(set(s, SIOCSIFADDR, "192.0.2.2") == 0);
	ATF_CHECK_EQ(count(NULL), 1);
	ATF_CHECK_EQ(count("192.0.2.2"), 1);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, "192.0.2.2"), "255.255.0.0");
	ATF_CHECK_STREQ(get(s, SIOCGIFBRDADDR, "192.0.2.2"), "192.0.255.255");

	/* An alias is not the first address and keeps its own mask. */
	ATF_REQUIRE(add(s, "198.51.100.1", "255.255.255.0", NULL) == 0);
	ATF_REQUIRE(set(s, SIOCSIFNETMASK, "255.255.255.128") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, "198.51.100.1"),
	    "255.255.255.0");

	/* SIOCSIFDSTADDR remains unsupported. */
	ATF_CHECK_ERRNO(EINVAL, set(s, SIOCSIFDSTADDR, "192.0.2.9") == -1);
	destroy(s);
}

ATF_TC(sifaddr_duplicate);
ATF_TC_HEAD(sifaddr_duplicate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SIOCSIFADDR does not remove an identical alias, as OpenBSD");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sifaddr_duplicate, tc)
{
	int s = inetsock();

	create(s, "vether");
	ATF_REQUIRE(set(s, SIOCSIFADDR, "192.0.2.1") == 0);
	ATF_REQUIRE(set(s, SIOCSIFNETMASK, "255.255.255.0") == 0);
	ATF_REQUIRE(add(s, "192.0.2.2", "255.255.0.0", NULL) == 0);
	ATF_REQUIRE(set(s, SIOCSIFADDR, "192.0.2.2") == 0);
	ATF_CHECK_EQ(count("192.0.2.1"), 0);
	ATF_CHECK_EQ(count("192.0.2.2"), 2);
	destroy(s);
	ATF_CHECK_EQ(count(NULL), 0);
}

ATF_TC(aifaddr_mask);
ATF_TC_HEAD(aifaddr_mask, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SIOCAIFADDR rejects a non-contiguous netmask, as OpenBSD");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(aifaddr_mask, tc)
{
	int s = inetsock();

	create(s, "vether");
	ATF_CHECK_ERRNO(EINVAL,
	    add(s, "192.0.2.1", "255.255.255.64", NULL) == -1);
	ATF_CHECK_EQ(count(NULL), 0);
	/* The netmask family is not checked. */
	ATF_REQUIRE(add(s, "192.0.2.1", "255.255.255.192", NULL) == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFNETMASK, "192.0.2.1"),
	    "255.255.255.192");
	destroy(s);
}

ATF_TC(p2p_nodst);
ATF_TC_HEAD(p2p_nodst, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A point-to-point address may be added without a destination");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p2p_nodst, tc)
{
	int s = inetsock();

	create(s, "tun");
	ATF_REQUIRE_MSG(add(s, "192.0.2.1", "255.255.255.0", NULL) == 0,
	    "SIOCAIFADDR: %s", strerror(errno));
	ATF_CHECK_STREQ(get(s, SIOCGIFDSTADDR, "192.0.2.1"), "0.0.0.0");
	/* The destination can be set later. */
	ATF_REQUIRE(add(s, "192.0.2.1", "255.255.255.0", "192.0.2.2") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFDSTADDR, "192.0.2.1"), "192.0.2.2");
	/* SIOCSIFADDR keeps the destination. */
	ATF_REQUIRE(set(s, SIOCSIFADDR, "192.0.2.3") == 0);
	ATF_CHECK_STREQ(get(s, SIOCGIFDSTADDR, "192.0.2.3"), "192.0.2.2");
	destroy(s);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sifaddr);
	ATF_TP_ADD_TC(tp, sifaddr_duplicate);
	ATF_TP_ADD_TC(tp, aifaddr_mask);
	ATF_TP_ADD_TC(tp, p2p_nodst);
	return (atf_no_error());
}

/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interfaces.h"

struct fixture {
	struct if_msghdrl header;
	struct sockaddr_dl link;
};
static struct fixture
record(unsigned index, const char *name)
{
	struct fixture f = { 0 };
	f.header.ifm_msglen = sizeof(f);
	f.header.ifm_version = RTM_VERSION;
	f.header.ifm_type = RTM_IFINFO;
	f.header.ifm_addrs = RTA_IFP;
	f.header.ifm_index = index;
	f.header.ifm_flags = IFF_UP;
	f.header.ifm_len = sizeof(f.header);
	f.header.ifm_data_off = offsetof(struct if_msghdrl, ifm_data);
	f.header.ifm_data.ifi_datalen = sizeof(struct if_data);
	f.header.ifm_data.ifi_mtu = 1500;
	f.header.ifm_data.ifi_link_state = LINK_STATE_UP;
	f.link.sdl_len = sizeof(f.link);
	f.link.sdl_family = AF_LINK;
	f.link.sdl_index = index;
	f.link.sdl_nlen = strlen(name);
	memcpy(f.link.sdl_data, name, strlen(name));
	return (f);
}

ATF_TC_WITHOUT_HEAD(parse_inventory);
ATF_TC_BODY(parse_inventory, tc)
{
	struct fixture f[2] = { record(9, "em0"), record(1, "lo0") };
	struct sysctlcmp_interface out[SYSCTLCMP_MAX_INTERFACES];
	size_t count = 99;
	unsigned char unaligned[sizeof(f) + 1];

	memcpy(unaligned + 1, f, sizeof(f));
	ATF_REQUIRE_EQ(0,
	    sysctlcmp_interfaces_parse(unaligned + 1, sizeof(f), out, &count));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(1, out[0].index);
	ATF_CHECK_STREQ("lo0", out[0].name);
	ATF_CHECK_EQ(9, out[1].index);
	ATF_CHECK_STREQ("em0", out[1].name);
	ATF_CHECK_EQ(1500, out[1].mtu);
	ATF_CHECK_EQ(SYSCTLCMP_LINK_UP, out[1].link_state);
	ATF_CHECK_EQ(IFF_UP, out[1].flags);
	ATF_REQUIRE_EQ(0, sysctlcmp_interfaces_parse(NULL, 0, out, &count));
	ATF_CHECK_EQ(0, count);
}

static void
reject(const void *data, size_t length, int error)
{
	struct sysctlcmp_interface out[SYSCTLCMP_MAX_INTERFACES],
	    before[SYSCTLCMP_MAX_INTERFACES];
	size_t count = 77;
	memset(out, 0xa5, sizeof(out));
	memcpy(before, out, sizeof(out));
	ATF_CHECK_ERRNO(error,
	    sysctlcmp_interfaces_parse(data, length, out, &count) == -1);
	ATF_CHECK_EQ(77, count);
	ATF_CHECK_EQ(0, memcmp(before, out, sizeof(out)));
}

ATF_TC_WITHOUT_HEAD(malformed_and_bounds);
ATF_TC_BODY(malformed_and_bounds, tc)
{
	struct fixture f = record(1, "em0"), bad, duplicate[2];
	struct fixture *many;
	char name[16];

	for (size_t n = 1; n < sizeof(f); n++)
		reject(&f, n, EPROTO);
	bad = f;
	bad.header.ifm_msglen = 0;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.header.ifm_version++;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.header.ifm_len = UINT16_MAX;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.header.ifm_data_off = 0;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.header.ifm_data.ifi_datalen = UINT16_MAX;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.header.ifm_data.ifi_link_state = 255;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.link.sdl_nlen = 255;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.link.sdl_family = AF_INET;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.link.sdl_index++;
	reject(&bad, sizeof(bad), EPROTO);
	bad = f;
	bad.link.sdl_data[1] = 0;
	reject(&bad, sizeof(bad), EPROTO);
	duplicate[0] = f;
	duplicate[1] = record(1, "lo0");
	reject(duplicate, sizeof(duplicate), EPROTO);
	duplicate[1] = record(2, "em0");
	reject(duplicate, sizeof(duplicate), EPROTO);
	many = calloc(SYSCTLCMP_MAX_INTERFACES + 1, sizeof(*many));
	ATF_REQUIRE(many != NULL);
	for (unsigned i = 0; i <= SYSCTLCMP_MAX_INTERFACES; i++) {
		snprintf(name, sizeof(name), "if%u", i);
		many[i] = record(i + 1, name);
	}
	reject(many, (SYSCTLCMP_MAX_INTERFACES + 1) * sizeof(*many), EOVERFLOW);
	free(many);
}

struct reader {
	unsigned probes, copies, failures;
	bool oversized, overreported;
};
static int
fake_read(void *arg, void *data, size_t *length)
{
	struct reader *r = arg;
	struct fixture f = record(1, "em0");
	if (data == NULL) {
		r->probes++;
		*length = r->oversized ? SYSCTLCMP_IFLIST_MAX_BYTES + 1 :
					 sizeof(f);
		return (0);
	}
	r->copies++;
	if (r->copies <= r->failures)
		return (errno = ENOMEM, -1);
	ATF_REQUIRE(*length >= sizeof(f));
	memcpy(data, &f, sizeof(f));
	*length = sizeof(f) + (r->overreported ? 1 : 0);
	return (0);
}

ATF_TC_WITHOUT_HEAD(bounded_churn);
ATF_TC_BODY(bounded_churn, tc)
{
	struct reader r = { .failures = 2 };
	struct sysctlcmp_interface out[SYSCTLCMP_MAX_INTERFACES];
	size_t count = 77;
	ATF_REQUIRE_EQ(0,
	    sysctlcmp_interfaces_collect(fake_read, &r, out, &count));
	ATF_CHECK_EQ(3, r.copies);
	ATF_CHECK_EQ(3, r.probes);
	ATF_CHECK_EQ(1, count);
	r = (struct reader) { .failures = 100 };
	count = 77;
	ATF_CHECK_ERRNO(EAGAIN,
	    sysctlcmp_interfaces_collect(fake_read, &r, out, &count) == -1);
	ATF_CHECK_EQ(3, r.copies);
	ATF_CHECK_EQ(77, count);
	r = (struct reader) { .oversized = true };
	ATF_CHECK_ERRNO(EOVERFLOW,
	    sysctlcmp_interfaces_collect(fake_read, &r, out, &count) == -1);
	ATF_CHECK_EQ(0, r.copies);
	r = (struct reader) { .overreported = true };
	ATF_CHECK_ERRNO(EPROTO,
	    sysctlcmp_interfaces_collect(fake_read, &r, out, &count) == -1);
}

static int
kernel_read(void *arg, void *data, size_t *length)
{
	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLISTL, 0 };
	(void)arg;
	return (sysctl(mib, 6, data, length, NULL, 0));
}
ATF_TC_WITHOUT_HEAD(native_inventory);
ATF_TC_BODY(native_inventory, tc)
{
	struct sysctlcmp_interface out[SYSCTLCMP_MAX_INTERFACES];
	size_t count;
	ATF_REQUIRE_EQ(0,
	    sysctlcmp_interfaces_collect(kernel_read, NULL, out, &count));
	ATF_CHECK(count > 0);
	for (size_t i = 0; i < count; i++) {
		ATF_CHECK(out[i].name[0] != 0);
		ATF_CHECK(out[i].index != 0);
		if (i)
			ATF_CHECK(out[i].index > out[i - 1].index);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, parse_inventory);
	ATF_TP_ADD_TC(tp, malformed_and_bounds);
	ATF_TP_ADD_TC(tp, bounded_churn);
	ATF_TP_ADD_TC(tp, native_inventory);
	return (atf_no_error());
}

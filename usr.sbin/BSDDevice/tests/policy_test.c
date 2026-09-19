/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit tests for localdevice(8)'s default-deny policy: leaf-name validation,
 * UCL policy parsing from a descriptor, and per-label lookup with ioctl
 * whitelists.
 */
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "policy.h"

static int
load_from_string(struct devicecmp_config *cfg, const char *ucl)
{
	char path[] = "/tmp/devicecmp_policy.XXXXXX";
	int fd, rc, saved;

	devicecmp_config_defaults(cfg);
	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE((size_t)write(fd, ucl, strlen(ucl)) == strlen(ucl));
	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	rc = devicecmp_config_load_fd(cfg, fd);
	saved = errno;
	(void)close(fd);
	(void)unlink(path);
	errno = saved;
	return (rc);
}

ATF_TC_WITHOUT_HEAD(name_validation);
ATF_TC_BODY(name_validation, tc)
{
	ATF_CHECK(devicecmp_valid_device_name("null"));
	ATF_CHECK(devicecmp_valid_device_name("hda"));
	ATF_CHECK(!devicecmp_valid_device_name(""));
	ATF_CHECK(!devicecmp_valid_device_name("/"));
	ATF_CHECK(!devicecmp_valid_device_name("a/b"));
	ATF_CHECK(!devicecmp_valid_device_name(".."));
	ATF_CHECK(!devicecmp_valid_device_name(".hidden"));
	ATF_CHECK(!devicecmp_valid_device_name(NULL));
}

ATF_TC_WITHOUT_HEAD(default_deny);
ATF_TC_BODY(default_deny, tc)
{
	struct devicecmp_config cfg;

	devicecmp_config_defaults(&cfg);
	ATF_CHECK(cfg.nentries == 0);
	ATF_CHECK(devicecmp_policy_lookup(&cfg, "system.Example", "null",
	    NULL, NULL) == 0);
}

ATF_TC_WITHOUT_HEAD(parse_and_lookup);
ATF_TC_BODY(parse_and_lookup, tc)
{
	static const char ucl[] =
	    "devices = ["
	    "  { label = \"system.A\"; device = \"null\"; "
	    "    rights = [\"read\", \"write\"]; },"
	    "  { label = \"system.B\"; device = \"hda\"; "
	    "    rights = [\"read\", \"ioctl\"]; ioctls = [1074033415, 2]; },"
	    "]\n";
	struct devicecmp_config cfg;
	const unsigned long *io;
	unsigned nio;
	uint32_t r;

	ATF_REQUIRE(load_from_string(&cfg, ucl) == 0);
	ATF_REQUIRE(cfg.nentries == 2);

	r = devicecmp_policy_lookup(&cfg, "system.A", "null", &io, &nio);
	ATF_CHECK(r == (DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_WRITE));
	ATF_CHECK(nio == 0);

	r = devicecmp_policy_lookup(&cfg, "system.B", "hda", &io, &nio);
	ATF_CHECK(r == (DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL));
	ATF_CHECK(nio == 2);
	ATF_CHECK(io != NULL && io[0] == 1074033415UL && io[1] == 2UL);

	/* Wrong label, wrong device, and unrelated pair all deny. */
	ATF_CHECK(devicecmp_policy_lookup(&cfg, "system.A", "hda",
	    NULL, NULL) == 0);
	ATF_CHECK(devicecmp_policy_lookup(&cfg, "system.C", "null",
	    NULL, NULL) == 0);
}

ATF_TC_WITHOUT_HEAD(reject_bad_config);
ATF_TC_BODY(reject_bad_config, tc)
{
	struct devicecmp_config cfg;

	/* An unknown right token is rejected and leaves default-deny intact. */
	ATF_CHECK_ERRNO(EINVAL, load_from_string(&cfg,
	    "devices = [ { label=\"x\"; device=\"null\"; "
	    "rights=[\"bogus\"]; } ]\n") == -1);
	ATF_CHECK(cfg.nentries == 0);

	/* A device name with a slash is rejected. */
	ATF_CHECK_ERRNO(EINVAL, load_from_string(&cfg,
	    "devices = [ { label=\"x\"; device=\"a/b\"; "
	    "rights=[\"read\"]; } ]\n") == -1);

	/* An ioctl whitelist without ioctl rights is rejected. */
	ATF_CHECK_ERRNO(EINVAL, load_from_string(&cfg,
	    "devices = [ { label=\"x\"; device=\"null\"; "
	    "rights=[\"read\"]; ioctls=[1]; } ]\n") == -1);
}

static void
put(struct devicecmp_config *cfg, const char *label, const char *device,
    uint32_t rights, unsigned nioctls)
{
	struct devicecmp_device_policy *pol = &cfg->entries[cfg->nentries++];

	memset(pol, 0, sizeof(*pol));
	strlcpy(pol->label, label, sizeof(pol->label));
	strlcpy(pol->device, device, sizeof(pol->device));
	pol->rights = rights;
	pol->nioctls = nioctls;
}

/*
 * devicecmp_policy_list is strictly label-scoped and paginates: it enumerates
 * only the queried label's entries (never another label's), sets the
 * ioctl-whitelist flag when nioctls > 0, and walks a stable window via cursor.
 */
ATF_TC_WITHOUT_HEAD(policy_list_scoped_and_paged);
ATF_TC_BODY(policy_list_scoped_and_paged, tc)
{
	struct devicecmp_config cfg;
	struct devicecmp_list_entry out[DEVICECMP_LIST_MAX];
	uint32_t count, next, page1_next;

	devicecmp_config_defaults(&cfg);
	put(&cfg, "system.A", "null", DEVICECMP_RIGHT_READ, 0);
	put(&cfg, "system.B", "random", DEVICECMP_RIGHT_READ, 0);
	put(&cfg, "system.A", "zero",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL, 2);
	put(&cfg, "system.A", "mem", DEVICECMP_RIGHT_READ, 0);

	/* Full page for system.A: exactly its three entries, in file order. */
	count = next = 99;
	devicecmp_policy_list(&cfg, "system.A", 0, out, DEVICECMP_LIST_MAX,
	    &count, &next);
	ATF_CHECK_EQ(3, count);
	ATF_CHECK_EQ(0, next);
	ATF_CHECK(strcmp(out[0].name, "null") == 0);
	ATF_CHECK(strcmp(out[1].name, "zero") == 0);
	ATF_CHECK(strcmp(out[2].name, "mem") == 0);
	ATF_CHECK_EQ(0, out[0].flags);
	ATF_CHECK_EQ(DEVICECMP_LIST_FLAG_IOCTL_WHITELIST, out[1].flags);
	ATF_CHECK_EQ(DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_IOCTL,
	    out[1].rights);

	/* An unpolicied label lists empty (default-deny). */
	count = next = 99;
	devicecmp_policy_list(&cfg, "system.Z", 0, out, DEVICECMP_LIST_MAX,
	    &count, &next);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, next);

	/* Paginate system.A with max == 2: page one yields a next cursor. */
	count = next = 99;
	devicecmp_policy_list(&cfg, "system.A", 0, out, 2, &count, &next);
	ATF_CHECK_EQ(2, count);
	ATF_CHECK_EQ(2, next);
	ATF_CHECK(strcmp(out[0].name, "null") == 0);
	ATF_CHECK(strcmp(out[1].name, "zero") == 0);
	page1_next = next;

	/* Page two from that cursor: the final entry, no further pages. */
	count = next = 99;
	devicecmp_policy_list(&cfg, "system.A", page1_next, out, 2, &count,
	    &next);
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(0, next);
	ATF_CHECK(strcmp(out[0].name, "mem") == 0);

	/* A cursor past the end yields an empty, final page. */
	count = next = 99;
	devicecmp_policy_list(&cfg, "system.A", 100, out, DEVICECMP_LIST_MAX,
	    &count, &next);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, next);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, name_validation);
	ATF_TP_ADD_TC(tp, default_deny);
	ATF_TP_ADD_TC(tp, parse_and_lookup);
	ATF_TP_ADD_TC(tp, reject_bad_config);
	ATF_TP_ADD_TC(tp, policy_list_scoped_and_paged);
	return (atf_no_error());
}

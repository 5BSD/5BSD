/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tzfsd.h"

static void
write_config(const char *path, const char *contents, mode_t mode)
{
	FILE *file;

	file = fopen(path, "w");
	ATF_REQUIRE_MSG(file != NULL, "fopen %s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ(strlen(contents), fwrite(contents, 1, strlen(contents),
	    file));
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE_EQ(0, chmod(path, mode));
}

ATF_TC_WITHOUT_HEAD(valid_overlay_and_defaults);
ATF_TC_BODY(valid_overlay_and_defaults, tc)
{
	struct tzfsd_flavor_def *flavor;
	struct tzfsd_config config;

	tzfsd_config_defaults(&config);
	ATF_CHECK_STREQ("zroot", config.pool);
	ATF_CHECK_STREQ("zroot/Capabilities", config.base);
	ATF_CHECK_EQ(2, config.nflavors);
	write_config("valid.ucl",
	    "pool = tank; ephemeral { sync = standard; } "
	    "roots { mountpoint = /Caps; } "
	    "flavors { linux { build = baked; "
	    "source = /tmp/linux.zst; default = true; } }", 0600);
	ATF_REQUIRE_EQ(0, tzfsd_config_load(&config, "valid.ucl"));
	ATF_CHECK_STREQ("tank", config.pool);
	ATF_CHECK_STREQ("tank/Capabilities", config.base);
	ATF_CHECK_STREQ("tank/Capabilities/persistent", config.persistent);
	ATF_CHECK_STREQ("/Caps", config.mountpoint);
	ATF_CHECK_STREQ("standard", config.ephemeral_sync);
	flavor = tzfsd_flavor_find(&config, "linux");
	ATF_REQUIRE(flavor != NULL);
	ATF_CHECK_EQ(TZFSD_BUILD_BAKED, flavor->build);
	ATF_CHECK(flavor->is_default);
	ATF_CHECK_STREQ("/tmp/linux.zst", flavor->source);
}

ATF_TC_WITHOUT_HEAD(invalid_overlays_are_transactional);
ATF_TC_BODY(invalid_overlays_are_transactional, tc)
{
	static const char *const invalid[] = {
		"pool = 123;",
		"pool = \"bad/pool\";",
		"pool = \"..\";",
		"ephemeral { sync = sometimes; }",
		"roots { persistent = elsewhere/data; }",
		"roots { persistent = zroot/Capabilities/..; }",
		"roots { ephemeral = zroot/Capabilities//ephemeral; }",
		"roots { mountpoint = /Capabilities/..; }",
		"roots { mountpoint = /Capabilities//nested; }",
		"flavors { \"bad/name\" { build = baked; "
		    "source = /tmp/a; } }",
		"flavors { \"..\" { build = baked; source = /tmp/a; } }",
		"flavors { custom { build = mystery; } }",
		"flavors { custom { build = live; } }",
		"flavors { custom { build = baked; source = relative; } }",
		"flavors { custom { build = baked; source = /tmp/../image; } }",
		"flavors { a { build = baked; source = /a; default = true; } "
		    "b { build = baked; source = /b; default = true; } }",
		"flavors = [];",
		"this is not valid UCL {{",
	};
	struct tzfsd_config before, config;
	size_t i;

	for (i = 0; i < nitems(invalid); i++) {
		tzfsd_config_defaults(&config);
		before = config;
		write_config("invalid.ucl", invalid[i], 0600);
		errno = 0;
		ATF_CHECK_MSG(tzfsd_config_load(&config, "invalid.ucl") == -1,
		    "invalid overlay %zu was accepted", i);
		ATF_CHECK_MSG(memcmp(&before, &config, sizeof(config)) == 0,
		    "invalid overlay %zu partially mutated configuration", i);
	}
}

ATF_TC_WITHOUT_HEAD(file_security_and_missing_policy);
ATF_TC_BODY(file_security_and_missing_policy, tc)
{
	struct tzfsd_config config;
	int fd;

	tzfsd_config_defaults(&config);
	ATF_REQUIRE_EQ(0, tzfsd_config_load(&config, "absent.ucl"));
	write_config("target.ucl", "pool = tank;", 0600);
	ATF_REQUIRE_EQ(0, symlink("target.ucl", "link.ucl"));
	errno = 0;
	ATF_CHECK(tzfsd_config_load(&config, "link.ucl") == -1);
	ATF_CHECK(errno == ELOOP || errno == EMLINK);
	ATF_REQUIRE_EQ(0, chmod("target.ucl", 0660));
	ATF_CHECK_ERRNO(EPERM,
	    tzfsd_config_load(&config, "target.ucl") == -1);
	ATF_REQUIRE_EQ(0, mkdir("directory.ucl", 0700));
	ATF_CHECK_ERRNO(EPERM,
	    tzfsd_config_load(&config, "directory.ucl") == -1);
	fd = open("large.ucl", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 1024 * 1024 + 1));
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_CHECK_ERRNO(EPERM,
	    tzfsd_config_load(&config, "large.ucl") == -1);
}

ATF_TC_WITHOUT_HEAD(confd_order_and_failure);
ATF_TC_BODY(confd_order_and_failure, tc)
{
	struct tzfsd_config config;

	ATF_REQUIRE_EQ(0, mkdir("conf.d", 0700));
	write_config("conf.d/10-first.ucl", "pool = tank;", 0600);
	write_config("conf.d/20-bad.ucl", "pool = [;", 0600);
	write_config("conf.d/30-never.ucl", "pool = later;", 0600);
	tzfsd_config_defaults(&config);
	ATF_REQUIRE(tzfsd_config_load_confd(&config, "conf.d") == -1);
	ATF_CHECK_STREQ("tank", config.pool);
	ATF_CHECK_STREQ("tank/Capabilities", config.base);
	ATF_REQUIRE_EQ(0,
	    tzfsd_config_load_confd(&config, "missing-conf.d"));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_overlay_and_defaults);
	ATF_TP_ADD_TC(tp, invalid_overlays_are_transactional);
	ATF_TP_ADD_TC(tp, file_security_and_missing_policy);
	ATF_TP_ADD_TC(tp, confd_order_and_failure);
	return (atf_no_error());
}

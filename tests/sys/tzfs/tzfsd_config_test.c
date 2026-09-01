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
	struct tzfsd_config config;

	tzfsd_config_defaults(&config);
	ATF_CHECK_STREQ("zroot", config.pool);
	ATF_CHECK_STREQ("zroot/Capabilities", config.base);
	write_config("valid.ucl",
	    "pool = tank; ephemeral { sync = standard; } "
	    "roots { mountpoint = /Caps; }", 0600);
	ATF_REQUIRE_EQ(0, tzfsd_config_load(&config, "valid.ucl"));
	ATF_CHECK_STREQ("tank", config.pool);
	ATF_CHECK_STREQ("tank/Capabilities", config.base);
	ATF_CHECK_STREQ("tank/Capabilities/persistent", config.persistent);
	ATF_CHECK_STREQ("/Caps", config.mountpoint);
	ATF_CHECK_STREQ("standard", config.ephemeral_sync);
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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_overlay_and_defaults);
	ATF_TP_ADD_TC(tp, invalid_overlays_are_transactional);
	ATF_TP_ADD_TC(tp, file_security_and_missing_policy);
	return (atf_no_error());
}

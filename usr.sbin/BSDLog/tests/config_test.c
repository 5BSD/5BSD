/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"

ATF_TC_WITHOUT_HEAD(defaults);
ATF_TC_BODY(defaults, tc)
{
	struct logcmp_config config;

	ATF_REQUIRE_EQ(0, logcmp_config_parse("{}", &config));
	ATF_CHECK_EQ(LOGCMP_RING_SIZE_DEFAULT, config.ring_size);
	ATF_CHECK_EQ(LOGCMP_DRAIN_MS_DEFAULT, config.fallback_drain_ms);
	ATF_CHECK_EQ(LOGCMP_SEGMENT_SIZE_DEFAULT, config.segment_size);
	ATF_CHECK_EQ(LOGCMP_MAX_SEGMENTS_DEFAULT, config.max_segments);
	ATF_CHECK_EQ(LOGCMP_MINIMUM_SEVERITY_DEFAULT, config.minimum_severity);
	ATF_CHECK_EQ(LOGCMP_RATE_INTERVAL_MS_DEFAULT,
	    config.rate_limit_interval_ms);
	ATF_CHECK_EQ(LOGCMP_RATE_BURST_DEFAULT, config.rate_limit_burst);
	ATF_CHECK_EQ(LOGCMP_INGRESS_SHARDS_DEFAULT, config.ingress_shards);
	ATF_CHECK_EQ(LOGCMP_MAX_SESSIONS_DEFAULT, config.max_sessions);
	ATF_CHECK_EQ(LOGCMP_DRAIN_BATCH_DEFAULT, config.drain_batch);
	ATF_CHECK_EQ(LOGCMP_RETENTION_MAX_AGE_DEFAULT, config.retention_max_age);
	ATF_CHECK_EQ(LOGCMP_RETENTION_MAX_BYTES_DEFAULT,
	    config.retention_max_bytes);
}

ATF_TC_WITHOUT_HEAD(retention_keys);
ATF_TC_BODY(retention_keys, tc)
{
	struct logcmp_config config;

	/* Zero is the keep-all default and must be accepted explicitly. */
	ATF_REQUIRE_EQ(0, logcmp_config_parse(
	    "{retention_max_age=0;retention_max_bytes=0;}", &config));
	ATF_CHECK_EQ(0, config.retention_max_age);
	ATF_CHECK_EQ(0, config.retention_max_bytes);
	ATF_REQUIRE_EQ(0, logcmp_config_parse(
	    "{retention_max_age=604800;retention_max_bytes=1073741824;}",
	    &config));
	ATF_CHECK_EQ(604800, config.retention_max_age);
	ATF_CHECK_EQ(1073741824, config.retention_max_bytes);
	/* Upper bounds accepted, over-bound and negative rejected. */
	ATF_REQUIRE_EQ(0, logcmp_config_parse(
	    "{retention_max_age=3153600000;}", &config));
	ATF_CHECK_EQ(LOGCMP_RETENTION_MAX_AGE_MAX, config.retention_max_age);
	ATF_CHECK_ERRNO(ERANGE, logcmp_config_parse(
	    "{retention_max_age=3153600001;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE, logcmp_config_parse(
	    "{retention_max_age=-1;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE, logcmp_config_parse(
	    "{retention_max_bytes=-1;}", &config) == -1);
}

ATF_TC_WITHOUT_HEAD(valid_bounds);
ATF_TC_BODY(valid_bounds, tc)
{
	struct logcmp_config config;

	ATF_REQUIRE_EQ(0, logcmp_config_parse(
	    "{ring_size=65536;fallback_drain_ms=1;segment_size=65536;"
	    "max_segments=1;minimum_severity=1;rate_limit_interval_ms=0;"
	    "rate_limit_burst=0;ingress_shards=1;max_sessions=64;drain_batch=1;}",
	    &config));
	ATF_CHECK_EQ(LOGCMP_RING_SIZE_MIN, config.ring_size);
	ATF_CHECK_EQ(LOGCMP_DRAIN_MS_MIN, config.fallback_drain_ms);
	ATF_CHECK_EQ(LOGCMP_SEGMENT_SIZE_MIN, config.segment_size);
	ATF_CHECK_EQ(LOGCMP_MAX_SEGMENTS_MIN, config.max_segments);
	ATF_CHECK_EQ(1, config.minimum_severity);
	ATF_CHECK_EQ(0, config.rate_limit_interval_ms);
	ATF_CHECK_EQ(0, config.rate_limit_burst);
	ATF_CHECK_EQ(LOGCMP_INGRESS_SHARDS_MIN, config.ingress_shards);
	ATF_CHECK_EQ(LOGCMP_MAX_SESSIONS_MIN, config.max_sessions);
	ATF_CHECK_EQ(LOGCMP_DRAIN_BATCH_MIN, config.drain_batch);
	ATF_REQUIRE_EQ(0, logcmp_config_parse(
	    "{ring_size=67108864;fallback_drain_ms=1000;"
	    "segment_size=1073741824;max_segments=1024;minimum_severity=24;"
	    "rate_limit_interval_ms=3600000;rate_limit_burst=1000000;"
	    "ingress_shards=64;max_sessions=262144;drain_batch=4096;}",
	    &config));
	ATF_CHECK_EQ(LOGCMP_RING_SIZE_MAX, config.ring_size);
	ATF_CHECK_EQ(LOGCMP_DRAIN_MS_MAX, config.fallback_drain_ms);
	ATF_CHECK_EQ(LOGCMP_SEGMENT_SIZE_MAX, config.segment_size);
	ATF_CHECK_EQ(LOGCMP_MAX_SEGMENTS_MAX, config.max_segments);
	ATF_CHECK_EQ(24, config.minimum_severity);
	ATF_CHECK_EQ(LOGCMP_RATE_INTERVAL_MS_MAX,
	    config.rate_limit_interval_ms);
	ATF_CHECK_EQ(LOGCMP_RATE_BURST_MAX, config.rate_limit_burst);
	ATF_CHECK_EQ(LOGCMP_INGRESS_SHARDS_MAX, config.ingress_shards);
	ATF_CHECK_EQ(LOGCMP_MAX_SESSIONS_MAX, config.max_sessions);
	ATF_CHECK_EQ(LOGCMP_DRAIN_BATCH_MAX, config.drain_batch);
	ATF_REQUIRE_EQ(0,
	    logcmp_config_parse("{minimum_severity=\"error\";}", &config));
	ATF_CHECK_EQ(LOGCMP_SEVERITY_ERROR, config.minimum_severity);
}

ATF_TC_WITHOUT_HEAD(rejects_schema_errors);
ATF_TC_BODY(rejects_schema_errors, tc)
{
	struct logcmp_config config;

	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("{unknown=1;}", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("{ring_size=\"262144\";}", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("{ring_size=262144;ring_size=524288;}",
	    &config) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("{", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("[]", &config) == -1);
}

ATF_TC_WITHOUT_HEAD(rejects_limits);
ATF_TC_BODY(rejects_limits, tc)
{
	struct logcmp_config config;

	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{ring_size=32768;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{ring_size=131073;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{ring_size=134217728;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{fallback_drain_ms=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{fallback_drain_ms=1001;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{segment_size=65535;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{segment_size=1073741825;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{max_segments=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{max_segments=1025;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{minimum_severity=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{minimum_severity=25;}", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_config_parse(
	    "{minimum_severity=\"verbose\";}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE, logcmp_config_parse(
	    "{rate_limit_interval_ms=3600001;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{rate_limit_burst=1000001;}", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_config_parse(
	    "{rate_limit_interval_ms=0;}", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_parse("{rate_limit_burst=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{ingress_shards=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{ingress_shards=65;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{max_sessions=63;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{max_sessions=262145;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{drain_batch=0;}", &config) == -1);
	ATF_CHECK_ERRNO(ERANGE,
	    logcmp_config_parse("{drain_batch=4097;}", &config) == -1);
}

ATF_TC_WITHOUT_HEAD(load_file);
ATF_TC_BODY(load_file, tc)
{
	struct logcmp_config config;
	FILE *file;

	file = fopen("logcmp.conf", "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs("ring_size=1048576;fallback_drain_ms=25;"
	    "segment_size=33554432;max_segments=7;minimum_severity=9;"
	    "rate_limit_interval_ms=500;rate_limit_burst=25;\n",
	    file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE_EQ(0, logcmp_config_load("logcmp.conf", &config));
	ATF_CHECK_EQ(1048576, config.ring_size);
	ATF_CHECK_EQ(25, config.fallback_drain_ms);
	ATF_CHECK_EQ(33554432, config.segment_size);
	ATF_CHECK_EQ(7, config.max_segments);
	ATF_CHECK_EQ(9, config.minimum_severity);
	ATF_CHECK_EQ(500, config.rate_limit_interval_ms);
	ATF_CHECK_EQ(25, config.rate_limit_burst);
	ATF_CHECK_EQ(-1, logcmp_config_load("missing.conf", &config));
}

ATF_TC_WITHOUT_HEAD(null_arguments);
ATF_TC_BODY(null_arguments, tc)
{
	struct logcmp_config config;

	ATF_CHECK_ERRNO(EINVAL, logcmp_config_parse(NULL, &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_config_parse("{}", NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_config_load(NULL, &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_config_load("x", NULL) == -1);
	logcmp_config_default(NULL);
}

ATF_TC_WITHOUT_HEAD(load_rejects_unsafe_files);
ATF_TC_BODY(load_rejects_unsafe_files, tc)
{
	struct logcmp_config config;
	int fd;

	fd = open("unsafe.conf", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(2, write(fd, "{}", 2));
	close(fd);
	ATF_REQUIRE_EQ(0, chmod("unsafe.conf", 0666));
	ATF_CHECK_ERRNO(EPERM,
	    logcmp_config_load("unsafe.conf", &config) == -1);
	ATF_REQUIRE_EQ(0, chmod("unsafe.conf", 0600));
	ATF_REQUIRE_EQ(0, symlink("unsafe.conf", "symlink.conf"));
	ATF_CHECK(logcmp_config_load("symlink.conf", &config) == -1);
	ATF_CHECK(errno == ELOOP || errno == EMLINK);
	ATF_REQUIRE_EQ(0, mkdir("config-directory", 0700));
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_config_load("config-directory", &config) == -1);
	fd = open("large.conf", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, LOGCMP_CONFIG_MAX_SIZE + 1));
	close(fd);
	ATF_CHECK_ERRNO(EFBIG,
	    logcmp_config_load("large.conf", &config) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, defaults);
	ATF_TP_ADD_TC(tp, retention_keys);
	ATF_TP_ADD_TC(tp, valid_bounds);
	ATF_TP_ADD_TC(tp, rejects_schema_errors);
	ATF_TP_ADD_TC(tp, rejects_limits);
	ATF_TP_ADD_TC(tp, load_file);
	ATF_TP_ADD_TC(tp, load_rejects_unsafe_files);
	ATF_TP_ADD_TC(tp, null_arguments);
	return (atf_no_error());
}

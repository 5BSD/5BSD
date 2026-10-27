/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <unistd.h>

#include "bsdfilesystem.h"

static int
input_fd(const void *data, size_t length)
{
	char path[] = "policy.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_REQUIRE_EQ((ssize_t)length, write(fd, data, length));
	return (fd);
}

static int
load(struct bsdfilesystem_config *cfg, const char *text)
{

	return (bsdfilesystem_config_load_fd(cfg, input_fd(text, strlen(text))));
}

ATF_TC_WITHOUT_HEAD(valid_inputs);
ATF_TC_BODY(valid_inputs, tc)
{
	struct bsdfilesystem_config cfg;

	bsdfilesystem_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load(&cfg, "pool = selected_pool; default_refquota=2gb; "
	    "reclaim_interval=5min; staging_idle_grace=1h; "
	    "ephemeral {sync=standard;} roots {mountpoint=\"/selected\";} "
	    "open_paths=[{label=\"example.Service/unit\"; path=\"/selected/input\"; "
	    "rights=[read,exec]; verify=true;}];"));
	ATF_CHECK_STREQ("selected_pool", cfg.pool);
	ATF_CHECK_STREQ("selected_pool/Capabilities/Data", cfg.persistent);
	ATF_CHECK_STREQ("/selected", cfg.mountpoint);
	ATF_CHECK_STREQ("standard", cfg.ephemeral_sync);
	ATF_CHECK_EQ(2ULL << 30, cfg.default_refquota);
	ATF_CHECK_EQ(300, cfg.reclaim_interval);
	ATF_CHECK_EQ(3600, cfg.staging_idle_grace);
	ATF_REQUIRE_EQ(1, cfg.nopen_policy);
	ATF_CHECK_STREQ("example.Service/unit", cfg.open_policy[0].label);
	ATF_CHECK(cfg.open_policy[0].verify);
	ATF_CHECK_EQ(BSDFILESYSTEM_OPEN_READ | BSDFILESYSTEM_OPEN_EXEC,
	    cfg.open_policy[0].rights);
	ATF_REQUIRE_EQ(0, load(&cfg, "pool=another_pool; open_paths=[]; "
	    "default_refquota=0; reclaim_interval=10; staging_idle_grace=1;"));
	ATF_CHECK_STREQ("another_pool/Capabilities/Data", cfg.persistent);
	ATF_CHECK_EQ(0, cfg.nopen_policy);
	ATF_CHECK_EQ(0, cfg.default_refquota);
	ATF_CHECK_EQ(10, cfg.reclaim_interval);
	ATF_CHECK_EQ(1, cfg.staging_idle_grace);
	ATF_REQUIRE_EQ(0, load(&cfg, "roots {base=\"another_pool/site\";}"));
	ATF_CHECK_STREQ("another_pool/site/Data", cfg.persistent);
	ATF_CHECK_STREQ("another_pool/site/ephemeral", cfg.ephemeral);
	ATF_REQUIRE_EQ(0, load(&cfg, "roots {base=\"another_pool/new\"; "
	    "persistent=\"another_pool/explicit\";}"));
	ATF_CHECK_STREQ("another_pool/explicit", cfg.persistent);
	ATF_CHECK_STREQ("another_pool/new/ephemeral", cfg.ephemeral);
}

ATF_TC_WITHOUT_HEAD(invalid_inputs_are_atomic);
ATF_TC_BODY(invalid_inputs_are_atomic, tc)
{
	static const char *const invalid[] = {
	    "pool=first; pool=second;",
	    "pool=changed; pol=misspelled;",
	    "roots {persisent=\"zroot/data\";}",
	    "ephemeral {synch=standard;}",
	    "pool=changed; roots {base=\"changed/base\"; base=\"changed/other\";}",
	    "pool=true;", "pool=42;", "pool=\"../escape\";",
	    "pool=\"${CURDIR}\";", ".include \"external-policy\";",
	    "pool=changed; .include \"external-policy\";",
	    "roots {mountpoint=\"/a/../b\";}",
	    "roots {persistent=\"another_pool/data\";}",
	    "ephemeral {sync=unexpected;}",
	    "default_refquota=-1;", "default_refquota=\"1gb\";",
	    "reclaim_interval=9;", "reclaim_interval=86401;",
	    "reclaim_interval=0.175min;", "reclaim_interval=true;",
	    "staging_idle_grace=0;", "staging_idle_grace=86401;",
	    "staging_idle_grace=0.025min;",
	    "open_paths=[{label=a; path=\"/x\"; rights=[read]; verfy=true;}];",
	    "open_paths=[{label=a; path=\"/x\"; rights=[read,read];}];",
	    "open_paths=[{label=a; path=\"/x\"; rights=[true];}];",
	    "open_paths=[{label=a; path=\"/x\"; rights=[];}];",
	    "open_paths=[{label=a; path=\"/x\"; rights=[write]; verify=true;}];",
	    "open_paths=[{label=a; path=\"/x\"; rights=[read]; verify=true; prefix=true;}];",
	    ("open_paths=[{label=a; path=\"/x\"; rights=[read];},"
	    "{label=a; path=\"/x\"; rights=[write];}];"),
	    "{\"pool\":\"changed\\u0000hidden\"}",
	    "{\"pool\\u0000hidden\":\"changed\"}",
	    "open_paths=[{label=\"a\\nother\"; path=\"/x\"; rights=[read];}];",
	};
	struct bsdfilesystem_config cfg, saved;
	char long_policy[256];

	bsdfilesystem_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load(&cfg, "pool=kept; reclaim_interval=120;"));
	saved = cfg;
	memset(long_policy, 'a', sizeof(long_policy));
	memcpy(long_policy, "pool=", 5);
	long_policy[245] = ';';
	long_policy[246] = '\0';
	ATF_CHECK_EQ(-1, load(&cfg, long_policy));
	ATF_CHECK_EQ(0, memcmp(&cfg, &saved, sizeof(cfg)));
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		errno = 0;
		ATF_CHECK_MSG(load(&cfg, invalid[i]) == -1,
		    "accepted invalid policy: %s", invalid[i]);
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_EQ(0, memcmp(&cfg, &saved, sizeof(cfg)));
	}
}

ATF_TC_WITHOUT_HEAD(no_external_expansion);
ATF_TC_BODY(no_external_expansion, tc)
{
	struct bsdfilesystem_config cfg;
	int fd;
	const char included[] = "pool=outside;";

	/* Even an existing, well-formed include must not affect policy. */
	fd = open("external-policy", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(included) - 1, write(fd, included, sizeof(included) - 1));
	ATF_REQUIRE_EQ(0, close(fd));
	bsdfilesystem_config_defaults(&cfg);
	ATF_CHECK_EQ(-1, load(&cfg, ".include \"external-policy\";"));
	ATF_CHECK_STREQ("zroot", cfg.pool);
	ATF_REQUIRE_EQ(0, setenv("POLICY_TEST_DIRECTORY", "expanded", 1));
	ATF_REQUIRE_EQ(0, load(&cfg, "roots {mountpoint=\"/${POLICY_TEST_DIRECTORY}\";}"));
	ATF_CHECK_STREQ("/${POLICY_TEST_DIRECTORY}", cfg.mountpoint);
}

ATF_TC_WITHOUT_HEAD(descriptor_validation);
ATF_TC_BODY(descriptor_validation, tc)
{
	const char nul[] = "pool=changed;\0pool=hidden;";
	struct bsdfilesystem_config cfg, saved;
	int fd, pipes[2];

	bsdfilesystem_config_defaults(&cfg);
	saved = cfg;
	fd = input_fd(nul, sizeof(nul) - 1);
	ATF_CHECK_EQ(-1, bsdfilesystem_config_load_fd(&cfg, fd));
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	fd = input_fd("", 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 1024 * 1024 + 1));
	ATF_CHECK_EQ(-1, bsdfilesystem_config_load_fd(&cfg, fd));
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	ATF_REQUIRE_EQ(0, pipe(pipes));
	ATF_CHECK_EQ(-1, bsdfilesystem_config_load_fd(&cfg, pipes[0]));
	ATF_REQUIRE_EQ(0, close(pipes[1]));
	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(-1, bsdfilesystem_config_load_fd(&cfg, fd));
	ATF_CHECK_EQ(0, memcmp(&saved, &cfg, sizeof(cfg)));
}

ATF_TC_WITHOUT_HEAD(installed_policy);
ATF_TC_BODY(installed_policy, tc)
{
	struct bsdfilesystem_config cfg;
	char path[1024];
	int fd;

	(void)snprintf(path, sizeof(path), "%s/storage-policy.ucl",
	    atf_tc_get_config_var(tc, "srcdir"));
	fd = open(path, O_RDONLY | O_NOFOLLOW);
	ATF_REQUIRE(fd >= 0);
	bsdfilesystem_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, bsdfilesystem_config_load_fd(&cfg, fd));
}

ATF_TC_WITHOUT_HEAD(installation_policy);
ATF_TC_BODY(installation_policy, tc)
{
	struct bsdfilesystem_config cfg;
	int fd;

	if (!atf_tc_has_config_var(tc, "installation_policy"))
		atf_tc_skip("explicit installation policy and expected layout required");
	fd = open(atf_tc_get_config_var(tc, "installation_policy"),
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	bsdfilesystem_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, bsdfilesystem_config_load_fd(&cfg, fd));
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "pool"), cfg.pool);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "dataset"), cfg.base);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "persistent"), cfg.persistent);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "ephemeral"), cfg.ephemeral);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "sync"), cfg.ephemeral_sync);
}

ATF_TC_WITHOUT_HEAD(shared_descriptor_offset);
ATF_TC_BODY(shared_descriptor_offset, tc)
{
	const char text[] = "pool = custom; roots { base = custom/services; }";
	struct bsdfilesystem_config manager, provider;
	int fd, copy;

	(void)tc;
	fd = input_fd(text, sizeof(text) - 1);
	ATF_REQUIRE_EQ(4096, lseek(fd, 4096, SEEK_SET));
	bsdfilesystem_config_defaults(&manager);
	copy = dup(fd);
	ATF_REQUIRE(copy >= 0);
	ATF_REQUIRE_EQ(0, bsdfilesystem_config_load_fd(&manager, copy));
	ATF_REQUIRE_EQ(4096, lseek(fd, 0, SEEK_CUR));
	ATF_REQUIRE_EQ(3, lseek(fd, 3, SEEK_SET));
	bsdfilesystem_config_defaults(&provider);
	copy = dup(fd);
	ATF_REQUIRE(copy >= 0);
	ATF_REQUIRE_EQ(0, bsdfilesystem_config_load_fd(&provider, copy));
	ATF_REQUIRE_EQ(3, lseek(fd, 0, SEEK_CUR));
	ATF_REQUIRE_EQ(0, memcmp(&manager, &provider, sizeof(manager)));
	ATF_REQUIRE_STREQ("custom/services", manager.base);
	ATF_REQUIRE_EQ(0, close(fd));
}

ATF_TC_WITHOUT_HEAD(retired_access_policy);
ATF_TC_BODY(retired_access_policy, tc)
{
	struct bsdfilesystem_config cfg, saved;
	const char *inputs[] = {
	    "access=[];",
	    "access=[{software=App/worker; subject=service; kind=durable; "
	    "namespace=App/worker/persistent; operations=[read];}];"
	};
	(void)tc;
	bsdfilesystem_config_defaults(&cfg);
	saved = cfg;
	for (size_t i = 0; i < nitems(inputs); i++) {
		ATF_REQUIRE_ERRNO(EINVAL, load(&cfg, inputs[i]) == -1);
		ATF_REQUIRE_EQ(0, memcmp(&saved, &cfg, sizeof(cfg)));
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, installation_policy);
	ATF_TP_ADD_TC(tp, retired_access_policy);
	ATF_TP_ADD_TC(tp, shared_descriptor_offset);
	ATF_TP_ADD_TC(tp, valid_inputs);
	ATF_TP_ADD_TC(tp, invalid_inputs_are_atomic);
	ATF_TP_ADD_TC(tp, no_external_expansion);
	ATF_TP_ADD_TC(tp, descriptor_validation);
	ATF_TP_ADD_TC(tp, installed_policy);
	return (atf_no_error());
}

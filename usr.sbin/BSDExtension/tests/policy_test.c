/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "bsdextension.h"
#include "test_policy.h"

static struct sysext_policy *
create(int *fd)
{
	struct sysext_config defaults;
	struct sysext_policy *p;

	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	*fd = open("state", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(*fd >= 0);
	test_base_policy(&defaults);
	p = sysext_policy_create(&defaults);
	ATF_REQUIRE(p != NULL);
	return (p);
}

ATF_TC_WITHOUT_HEAD(rights_and_bootstrap);
ATF_TC_BODY(rights_and_bootstrap, tc)
{
	int fd;
	struct sysext_policy *p = create(&fd);
	struct sysext_info_reply info;
	struct sysext_config cfg;

	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	ATF_CHECK_ERRNO(EPERM, sysext_policy_change(p, SYSEXT_OP_ALLOW,
	    "if_iwlwifi", SERVICE_RIGHTS_NONE) == -1);
	ATF_CHECK_ERRNO(EAGAIN, sysext_policy_change(p, SYSEXT_OP_ALLOW,
	    "if_iwlwifi", SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_CHECK_ERRNO(EPERM, sysext_policy_change(p, SYSEXT_OP_DENY,
	    "zfs", SERVICE_RIGHTS_NONE) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysext_policy_change(p, SYSEXT_OP_ALLOW,
	    "../evil", SERVICE_RIGHTS_ADMIN) == -1);
	ATF_CHECK_ERRNO(EPERM, sysext_policy_change(p, SYSEXT_OP_ENABLE,
	    "unknown", SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, sysext_policy_info(p, "zfs", false, &info));
	ATF_CHECK(info.flags & SYSEXT_STATE_READY);
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(persistence_and_precedence);
ATF_TC_BODY(persistence_and_precedence, tc)
{
	int fd, conf;
	struct sysext_policy *p = create(&fd);
	struct sysext_config cfg;
	struct sysext_info_reply info;
	const char *text = "allowed_extensions=[\"zfs\",\"cryptodev\"];";

	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_REQUIRE_EQ(0, sysext_policy_change(p, SYSEXT_OP_ALLOW,
	    "if_iwlwifi", SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_change(p, SYSEXT_OP_ENABLE,
	    "if_iwlwifi", SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_change(p, SYSEXT_OP_DENY,
	    "cryptodev", SERVICE_RIGHTS_ADMIN));
	conf = open("defaults.ucl", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(conf >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(conf, text, strlen(text)));
	ATF_REQUIRE_EQ(0, lseek(conf, 0, SEEK_SET));
	ATF_REQUIRE_EQ(0, sysext_policy_reload_fd(p, conf, SERVICE_RIGHTS_ADMIN));
	close(conf);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "if_iwlwifi"));
	ATF_CHECK(!extension_allowed(&cfg, "cryptodev"));
	sysext_policy_destroy(p);
	test_base_policy(&cfg);
	p = sysext_policy_create(&cfg);
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_REQUIRE_EQ(0, sysext_policy_enabled(p, &cfg));
	ATF_CHECK_EQ(1, cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "if_iwlwifi"));
	ATF_REQUIRE_EQ(0, sysext_policy_change(p, SYSEXT_OP_DENY,
	    "if_iwlwifi", SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_enabled(p, &cfg));
	ATF_CHECK_EQ(0, cfg.nallow);
	ATF_REQUIRE_EQ(0, sysext_policy_info(p, "if_iwlwifi", false, &info));
	ATF_CHECK(info.flags & SYSEXT_STATE_ENABLED);
	ATF_CHECK(!(info.flags & SYSEXT_STATE_ALLOWED));
	ATF_REQUIRE_EQ(0, sysext_policy_change(p, SYSEXT_OP_RESET,
	    "cryptodev", SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(failed_write_keeps_policy);
ATF_TC_BODY(failed_write_keeps_policy, tc)
{
	int fd;
	struct sysext_policy *p = create(&fd);
	struct sysext_config cfg;

	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_REQUIRE_EQ(0, mkdirat(fd, "overrides.new", 0700));
	ATF_CHECK(sysext_policy_change(p, SYSEXT_OP_ALLOW,
	    "badcommit", SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(!extension_allowed(&cfg, "badcommit"));
	ATF_CHECK_ERRNO(ENOENT, faccessat(fd, "overrides.ucl", F_OK, 0) == -1);
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(capability_mode_persistence);
ATF_TC_BODY(capability_mode_persistence, tc)
{
	int fd, status;
	pid_t pid;
	struct sysext_policy *p = create(&fd);
	struct sysext_config cfg;

	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Match the broker's descriptor-only persistence after confinement.
		 * Exercise create, sync, replacement and deletion of an override. */
		if (cap_enter() == -1 ||
		    sysext_policy_change(p, SYSEXT_OP_ALLOW, "confined_driver",
		    SERVICE_RIGHTS_ADMIN) == -1 ||
		    sysext_policy_change(p, SYSEXT_OP_ENABLE, "confined_driver",
		    SERVICE_RIGHTS_ADMIN) == -1 ||
		    sysext_policy_change(p, SYSEXT_OP_DENY, "zfs",
		    SERVICE_RIGHTS_ADMIN) == -1 ||
		    sysext_policy_change(p, SYSEXT_OP_RESET, "zfs",
		    SERVICE_RIGHTS_ADMIN) == -1)
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	sysext_policy_destroy(p);
	test_base_policy(&cfg);
	p = sysext_policy_create(&cfg);
	ATF_REQUIRE(p != NULL);
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_REQUIRE_EQ(0, sysext_policy_enabled(p, &cfg));
	ATF_CHECK_EQ(1, cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "confined_driver"));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(corrupt_registry_fails_closed);
ATF_TC_BODY(corrupt_registry_fails_closed, tc)
{
	int fd, file;
	struct sysext_policy *p = create(&fd);
	struct sysext_config cfg;
	const char *text = "version=2; extensions=[];";

	file = openat(fd, "overrides.ucl", O_WRONLY | O_CREAT, 0600);
	ATF_REQUIRE(file >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(file, text, strlen(text)));
	close(file);
	ATF_CHECK_ERRNO(EINVAL, sysext_policy_attach(p, fd) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysext_policy_snapshot(p, &cfg) == -1);
	ATF_REQUIRE_EQ(0, unlinkat(fd, "overrides.ucl", 0));
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(concurrent_updates_and_discovery);
ATF_TC_BODY(concurrent_updates_and_discovery, tc)
{
	int fd, i, status;
	size_t count = 0;
	struct sysext_config initial;
	pid_t children[4];
	struct sysext_policy *p = create(&fd);
	struct sysext_info_reply info;
	char name[64], cursor[64] = "";

	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &initial));
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	for (i = 0; i < 4; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0) {
			for (int j = 0; j < 12; j++) {
				snprintf(name, sizeof(name), "driver%d_%02d", i, j);
				if (sysext_policy_change(p, SYSEXT_OP_ALLOW, name,
				    SERVICE_RIGHTS_ADMIN) == -1)
					_exit(1);
			}
			_exit(0);
		}
	}
	for (i = 0; i < 4; i++) {
		ATF_REQUIRE_EQ(children[i], waitpid(children[i], &status, 0));
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	while (sysext_policy_info(p, cursor, true, &info) == 0) {
		ATF_CHECK(strcmp(info.name, cursor) > 0);
		strlcpy(cursor, info.name, sizeof(cursor));
		count++;
	}
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_CHECK_EQ(initial.nallow + 4 * 12, count);
	/* Check each committed name, so a duplicate or lost update cannot hide
	 * behind an unrelated change in the fixture base allow-list. */
	for (i = 0; i < 4; i++) {
		for (int j = 0; j < 12; j++) {
			snprintf(name, sizeof(name), "driver%d_%02d", i, j);
			ATF_REQUIRE_EQ(0, sysext_policy_info(p, name, false, &info));
			ATF_CHECK(info.flags & SYSEXT_STATE_ALLOWED);
		}
	}
	sysext_policy_destroy(p);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(writer_death_recovers_durable_commit);
ATF_TC_BODY(writer_death_recovers_durable_commit, tc)
{
	int fd, status;
	pid_t pid;
	struct sysext_policy *p = create(&fd);
	struct sysext_config cfg;

	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, fd));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		sysext_test_policy_commit_abandon(p);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "recovered"));
	sysext_policy_destroy(p);
	close(fd);
}


ATF_TC_WITHOUT_HEAD(override_input_contract);
ATF_TC_BODY(override_input_contract, tc)
{
	const char *invalid[] = {
	    "version=1; version=1; extensions=[];",
	    "version=1; extensions=[]; ignored=true;",
	    "version=1; extensions=[{name=\"a\";permission=1;enabled=true;extra=true;}];",
	    "version=1; extensions=[{name=\"a\";permission=1;permission=0;enabled=true;}];",
	    "version=1; extensions=[{name=\"a\";permission=1.0;enabled=true;}];",
	    "version=1; extensions=[{name=\"a\\u0000b\";permission=1;enabled=true;}];",
	    ("version=1; extensions=[{name=\"a\";permission=1;enabled=true;},"
	    "{name=\"a\";permission=1;enabled=true;}];"),
	    ".include \"injected-overrides.ucl\";",
	};
	const char *valid = "version=1; extensions=[];";
	struct sysext_config cfg;
	struct sysext_policy *p;
	size_t i;
	int dirfd, fd;

	p = create(&dirfd);
	fd = open("injected-overrides.ucl", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(valid), write(fd, valid, strlen(valid)));
	close(fd);
	for (i = 0; i < nitems(invalid); i++) {
		fd = openat(dirfd, "overrides.ucl", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		ATF_REQUIRE(fd >= 0);
		ATF_REQUIRE_EQ((ssize_t)strlen(invalid[i]), write(fd, invalid[i], strlen(invalid[i])));
		close(fd);
		ATF_CHECK_ERRNO(EINVAL, sysext_policy_attach(p, dirfd) == -1);
		ATF_CHECK_ERRNO(EINVAL, sysext_policy_snapshot(p, &cfg) == -1);
	}
	ATF_REQUIRE_EQ(0, unlinkat(dirfd, "overrides.ucl", 0));
	ATF_REQUIRE_EQ(0, mkfifoat(dirfd, "overrides.ucl", 0600));
	ATF_CHECK_ERRNO(EPERM, sysext_policy_attach(p, dirfd) == -1);
	ATF_CHECK_ERRNO(EPERM, sysext_policy_snapshot(p, &cfg) == -1);
	ATF_REQUIRE_EQ(0, unlinkat(dirfd, "overrides.ucl", 0));
	ATF_REQUIRE_EQ(0, sysext_policy_attach(p, dirfd));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(p, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	sysext_policy_destroy(p);
	close(dirfd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, override_input_contract);
	ATF_TP_ADD_TC(tp, rights_and_bootstrap);
	ATF_TP_ADD_TC(tp, writer_death_recovers_durable_commit);
	ATF_TP_ADD_TC(tp, persistence_and_precedence);
	ATF_TP_ADD_TC(tp, failed_write_keeps_policy);
	ATF_TP_ADD_TC(tp, capability_mode_persistence);
	ATF_TP_ADD_TC(tp, corrupt_registry_fails_closed);
	ATF_TP_ADD_TC(tp, concurrent_updates_and_discovery);
	return (atf_no_error());
}

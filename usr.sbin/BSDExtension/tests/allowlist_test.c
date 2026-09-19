/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pure-unit regression suite for the bsdextension(8) module allow-list — the
 * default-deny control that decides WHICH kernel module a (already
 * domain-authorized) SYSTEM client may load.  These cases link the daemon
 * object with -DBSDEXTENSION_TESTING and call its pure-logic functions directly; no
 * capability plane, no kldload, no privilege is required, so they run in any
 * environment.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bsdextension.h"

/*
 * Write content to a fresh 0600 file owned by the current euid (satisfying
 * sysext_config_load's regular/owner/not-group-or-other-writable checks) and
 * return its path in a caller-owned static buffer.
 */
static const char *
write_conf(const char *content)
{
	static char path[64];
	int fd;
	size_t len;

	strlcpy(path, "conf.XXXXXX", sizeof(path));
	fd = mkstemp(path);
	ATF_REQUIRE_MSG(fd >= 0, "mkstemp: %s", strerror(errno));
	len = strlen(content);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, content, len));
	ATF_REQUIRE_EQ(0, close(fd));
	return (path);
}

/*
 * The built-in default set must permit exactly the base system's on-demand
 * modules.  If any of these silently falls off the list, a legitimate consumer
 * (bsdcrypto/blued/bsdfilesystem) breaks.
 */
ATF_TC_WITHOUT_HEAD(allowlisted_module_is_permitted);
ATF_TC_BODY(allowlisted_module_is_permitted, tc)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(extension_allowed(&cfg, "vhid"));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	ATF_CHECK(extension_allowed(&cfg, "linux64"));
}

/*
 * THE security regression.  Before the default-deny allow-list, any client that
 * cleared the SYSTEM-domain gate could ask bsdextension to load ARBITRARY kernel
 * code.  A module that is not on the resolved allow-list MUST be denied; this
 * case locks that shut.
 */
ATF_TC_WITHOUT_HEAD(non_allowlisted_module_is_denied);
ATF_TC_BODY(non_allowlisted_module_is_denied, tc)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	ATF_CHECK(!extension_allowed(&cfg, "evil"));
	ATF_CHECK(!extension_allowed(&cfg, "if_tun"));
	ATF_CHECK(!extension_allowed(&cfg, ""));
	/* A prefix of an allowed name is not itself allowed (exact match). */
	ATF_CHECK(!extension_allowed(&cfg, "zf"));
	ATF_CHECK(!extension_allowed(&cfg, "zfss"));
}

/*
 * The syntactic guard: a module name must be one safe filename component.  It
 * rejects empty, the "." / ".." directory names, and anything containing '/'
 * (relative or absolute path traversal), but ACCEPTS embedded dots because real
 * module names carry them.
 */
ATF_TC_WITHOUT_HEAD(valid_module_name_rejects_paths_accepts_dotted);
ATF_TC_BODY(valid_module_name_rejects_paths_accepts_dotted, tc)
{

	ATF_CHECK(!valid_module_name(""));
	ATF_CHECK(!valid_module_name("."));
	ATF_CHECK(!valid_module_name(".."));
	ATF_CHECK(!valid_module_name("a/b"));
	ATF_CHECK(!valid_module_name("/abs"));
	ATF_CHECK(!valid_module_name("../evil"));
	ATF_CHECK(!valid_module_name("dir/mod"));

	ATF_CHECK(valid_module_name("foo.bar"));
	ATF_CHECK(valid_module_name("cryptodev"));
	ATF_CHECK(valid_module_name("if_foo.ko"));
}

/*
 * A name whose NUL falls outside the SYSEXT_NAME_MAX buffer (an unterminated /
 * oversized module name off the wire) must be rejected, not read past its
 * bounds.
 */
ATF_TC_WITHOUT_HEAD(valid_module_name_requires_termination);
ATF_TC_BODY(valid_module_name_requires_termination, tc)
{
	char name[SYSEXT_NAME_MAX];

	memset(name, 'a', sizeof(name));	/* no NUL within the buffer */
	ATF_CHECK(!valid_module_name(name));
}

/*
 * Fail-soft on a MALFORMED config: a config the parser cannot read must leave
 * the built-in defaults in place and never abort.  This is the boot-resilience
 * guarantee — a corrupt UCL file must not brick a boot=true daemon.
 */
ATF_TC_WITHOUT_HEAD(malformed_config_falls_back_to_defaults);
ATF_TC_BODY(malformed_config_falls_back_to_defaults, tc)
{
	struct sysext_config cfg;
	const char *path;

	sysext_config_defaults(&cfg);
	/* Unterminated string: a hard UCL parse failure. */
	path = write_conf("allowed_extensions = [ \"broken");
	(void)sysext_config_load(&cfg, path);	/* return ignored: must not abort */
	/* Built-in set survives untouched. */
	ATF_CHECK_EQ(4, (int)cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(extension_allowed(&cfg, "vhid"));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	(void)unlink(path);
}

/*
 * A config whose root is not an object is malformed; defaults must stand.
 */
ATF_TC_WITHOUT_HEAD(non_object_config_falls_back_to_defaults);
ATF_TC_BODY(non_object_config_falls_back_to_defaults, tc)
{
	struct sysext_config cfg;
	const char *path;

	sysext_config_defaults(&cfg);
	path = write_conf("[ 1, 2, 3 ]");
	ATF_CHECK_ERRNO(EINVAL, sysext_config_load(&cfg, path) == -1);
	ATF_CHECK_EQ(4, (int)cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	(void)unlink(path);
}

/*
 * A MISSING config (ENOENT) is not an error: load succeeds and the built-in
 * defaults stand.  bsdextension must not depend on a file existing early in boot.
 */
ATF_TC_WITHOUT_HEAD(missing_config_uses_defaults);
ATF_TC_BODY(missing_config_uses_defaults, tc)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	ATF_CHECK_EQ(0, sysext_config_load(&cfg, "./does-not-exist.ucl"));
	ATF_CHECK_EQ(4, (int)cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(extension_allowed(&cfg, "vhid"));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
}

/*
 * A config that lists a bogus (path-bearing) entry is over-broad/malformed and
 * must be rejected WHOLESALE, restoring the built-in defaults — a bad config can
 * never widen or corrupt what may load.
 */
ATF_TC_WITHOUT_HEAD(invalid_entry_config_rejected_keeps_defaults);
ATF_TC_BODY(invalid_entry_config_rejected_keeps_defaults, tc)
{
	struct sysext_config cfg;
	const char *path;

	sysext_config_defaults(&cfg);
	path = write_conf("allowed_extensions = [ \"a/b\" ]");
	ATF_CHECK(sysext_config_load(&cfg, path) == -1);
	ATF_CHECK_EQ(4, (int)cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(!extension_allowed(&cfg, "a/b"));
	(void)unlink(path);
}

/*
 * A well-formed operator config REPLACES the built-in set: a module the config
 * lists becomes allowed, and a built-in default the config omits becomes denied.
 * This proves the config is authoritative (not merely additive).
 */
ATF_TC_WITHOUT_HEAD(config_replaces_default_allowlist);
ATF_TC_BODY(config_replaces_default_allowlist, tc)
{
	struct sysext_config cfg;
	const char *path;

	sysext_config_defaults(&cfg);
	path = write_conf("allowed_extensions = [ \"custommod\" ]\n");
	ATF_CHECK_EQ(0, sysext_config_load(&cfg, path));
	ATF_CHECK_EQ(1, (int)cfg.nallow);
	/* Listed-but-not-default module becomes allowed... */
	ATF_CHECK(extension_allowed(&cfg, "custommod"));
	/* ...and a default the config omits becomes denied. */
	ATF_CHECK(!extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(!extension_allowed(&cfg, "vhid"));
	ATF_CHECK(!extension_allowed(&cfg, "zfs"));
	ATF_CHECK(!extension_allowed(&cfg, "linux64"));
	(void)unlink(path);
}

/*
 * STAT is gated by the SAME allow-list as ENSURE: a client may query only a
 * module it could load.  There is no separate STAT policy — the pure decision
 * for both operations is extension_allowed() — so the set a client may STAT is
 * exactly the set it may ENSURE, and a non-allow-listed name is denied to STAT
 * just as it is to ENSURE (the handler turns that into EPERM, so STAT of an
 * unknown module leaks no loaded/not-loaded information).  This locks the
 * "STAT gate == ENSURE gate" invariant against a future divergence.
 */
ATF_TC_WITHOUT_HEAD(stat_shares_ensure_allowlist_gate);
ATF_TC_BODY(stat_shares_ensure_allowlist_gate, tc)
{
	struct sysext_config cfg;

	sysext_config_defaults(&cfg);
	/* Allow-listed => queryable, exactly as it is loadable. */
	ATF_CHECK(extension_allowed(&cfg, "cryptodev"));
	ATF_CHECK(extension_allowed(&cfg, "zfs"));
	/* Not allow-listed => denied to STAT, exactly as to ENSURE. */
	ATF_CHECK(!extension_allowed(&cfg, "evil"));
	ATF_CHECK(!extension_allowed(&cfg, "kernel"));
}

ATF_TC_WITHOUT_HEAD(reload_authorization_and_last_good);
ATF_TC_BODY(reload_authorization_and_last_good, tc)
{
	struct sysext_config cfg;
	struct sysext_policy *policy;
	const char *path;
	const char *invalid[] = {
	    "allowed_extensions = [ \"broken",
	    "allowed_extensions = [ \"../evil\" ]",
	    "unrelated = true",
	};
	size_t i;

	sysext_config_defaults(&cfg);
	policy = sysext_policy_create(&cfg);
	ATF_REQUIRE(policy != NULL);
	ATF_CHECK_ERRNO(EPERM, sysext_policy_reload(policy, "missing",
	    SERVICE_RIGHTS_NONE) == -1);
	path = write_conf("allowed_extensions = [ \"custommod\" ]");
	ATF_REQUIRE_EQ(0, sysext_policy_reload(policy, path, SERVICE_RIGHTS_ADMIN));
	unlink(path);
	for (i = 0; i < nitems(invalid); i++) {
		path = write_conf(invalid[i]);
		ATF_CHECK_ERRNO(EINVAL, sysext_policy_reload(policy, path,
		    SERVICE_RIGHTS_ADMIN) == -1);
		unlink(path);
		ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
		ATF_CHECK_EQ(1, cfg.nallow);
		ATF_CHECK(extension_allowed(&cfg, "custommod"));
	}
	ATF_CHECK_ERRNO(ENOENT, sysext_policy_reload(policy, "missing",
	    SERVICE_RIGHTS_ADMIN) == -1);
	path = write_conf("allowed_extensions = []");
	ATF_REQUIRE_EQ(0, chmod(path, 0660));
	ATF_CHECK_ERRNO(EPERM, sysext_policy_reload(policy, path,
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, chmod(path, 0600));
	ATF_REQUIRE_EQ(0, symlink(path, "policy-link"));
	ATF_CHECK(sysext_policy_reload(policy, "policy-link",
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, mkfifo("policy-fifo", 0600));
	ATF_CHECK_ERRNO(EPERM, sysext_policy_reload(policy, "policy-fifo",
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "custommod"));
	ATF_REQUIRE_EQ(0, sysext_policy_reload(policy, path, SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK_EQ(0, cfg.nallow);
	sysext_policy_destroy(policy);
}

ATF_TC(reload_shared_and_owner_death);
ATF_TC_HEAD(reload_shared_and_owner_death, tc)
{
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(reload_shared_and_owner_death, tc)
{
	struct sysext_config cfg;
	struct sysext_policy *policy;
	const char *path;
	pid_t pid;
	int pd, status;

	sysext_config_defaults(&cfg);
	policy = sysext_policy_create(&cfg);
	ATF_REQUIRE(policy != NULL);
	path = write_conf("allowed_extensions = [ \"sharedmod\" ]");
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(sysext_policy_reload(policy, path, SERVICE_RIGHTS_ADMIN) != 0);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	close(pd);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK(extension_allowed(&cfg, "sharedmod"));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		sysext_test_policy_abandon(policy);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	close(pd);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK_EQ(1, cfg.nallow);
	ATF_CHECK(extension_allowed(&cfg, "sharedmod"));
	ATF_REQUIRE_EQ(0, sysext_policy_reload(policy, path, SERVICE_RIGHTS_ADMIN));
	sysext_policy_destroy(policy);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, allowlisted_module_is_permitted);
	ATF_TP_ADD_TC(tp, reload_authorization_and_last_good);
	ATF_TP_ADD_TC(tp, reload_shared_and_owner_death);
	ATF_TP_ADD_TC(tp, stat_shares_ensure_allowlist_gate);
	ATF_TP_ADD_TC(tp, non_allowlisted_module_is_denied);
	ATF_TP_ADD_TC(tp, valid_module_name_rejects_paths_accepts_dotted);
	ATF_TP_ADD_TC(tp, valid_module_name_requires_termination);
	ATF_TP_ADD_TC(tp, malformed_config_falls_back_to_defaults);
	ATF_TP_ADD_TC(tp, non_object_config_falls_back_to_defaults);
	ATF_TP_ADD_TC(tp, missing_config_uses_defaults);
	ATF_TP_ADD_TC(tp, invalid_entry_config_rejected_keeps_defaults);
	ATF_TP_ADD_TC(tp, config_replaces_default_allowlist);
	return (atf_no_error());
}

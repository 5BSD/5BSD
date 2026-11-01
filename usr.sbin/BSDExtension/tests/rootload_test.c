/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Root loads (system.SystemExtension.RootLoad, rootload.c).  A fixture kernel
 * directory and a real sqlite package database in pkg's schema stand in for
 * /boot/kernel and /var/db/pkg; the kernel linker calls are replaced by a
 * small fake kernel (sysext_test_kld_*) so the decisions run unprivileged and
 * nothing is loaded into the running kernel.  Which callers reach the endpoint
 * at all (UID 0, not jailed, no software authority) is switchboard's decision
 * and is tested there (boot_authority_test root_load_admits).
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>
#include <channel.h>
#include <libservice.h>
#include <extensioncmp.h>

#include "sysext_proto.h"
#include "bsdextension.h"
#include "test_policy.h"

/* --------------------------------------------------------- fake kernel */

#define	FAKE_FILES	16
static struct fake_file {
	int	id;
	char	name[64];
	char	path[MAXPATHLEN];
} fake[FAKE_FILES];
static int fake_next_id = 2, fake_loads, fake_unloads;
/* A file the next load of rltest_d.ko pulls in (MODULE_DEPEND), or "". */
static char fake_dependency[MAXPATHLEN];

static int
fake_add(const char *path)
{
	const char *base = strrchr(path, '/');

	for (size_t i = 0; i < nitems(fake); i++) {
		if (fake[i].id != 0)
			continue;
		fake[i].id = fake_next_id++;
		strlcpy(fake[i].name, base != NULL ? base + 1 : path,
		    sizeof(fake[i].name));
		strlcpy(fake[i].path, path, sizeof(fake[i].path));
		return (fake[i].id);
	}
	return (-1);
}

static int
fake_load(const char *path, int *fileid)
{
	const char *base = strrchr(path, '/');

	fake_loads++;
	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id != 0 && strcmp(fake[i].name, base + 1) == 0)
			return (EEXIST);
	*fileid = fake_add(path);
	if (strcmp(base + 1, "rltest_d.ko") == 0 && fake_dependency[0] != '\0')
		(void)fake_add(fake_dependency);
	return (*fileid > 0 ? 0 : ENOMEM);
}

static int
fake_unload(int fileid)
{

	fake_unloads++;
	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id == fileid) {
			/* The linker releases what the file pulled in. */
			if (strcmp(fake[i].name, "rltest_d.ko") == 0)
				for (size_t j = 0; j < nitems(fake); j++)
					if (strcmp(fake[j].path,
					    fake_dependency) == 0)
						memset(&fake[j], 0,
						    sizeof(fake[j]));
			memset(&fake[i], 0, sizeof(fake[i]));
			return (0);
		}
	return (ENOENT);
}

static int
fake_stat(int fileid, char *name, size_t namelen, char *path, size_t pathlen)
{

	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id == fileid) {
			strlcpy(name, fake[i].name, namelen);
			strlcpy(path, fake[i].path, pathlen);
			return (0);
		}
	return (ENOENT);
}

static int
fake_next(int fileid)
{
	int best = 0;

	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id > fileid && (best == 0 || fake[i].id < best))
			best = fake[i].id;
	return (best);
}

static bool
fake_loaded(const char *name)
{

	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id != 0 && strcmp(fake[i].name, name) == 0)
			return (true);
	return (false);
}

static void
fake_reset(void)
{

	memset(fake, 0, sizeof(fake));
	fake_next_id = 2;
	fake_loads = fake_unloads = 0;
	fake_dependency[0] = '\0';
	/* The kernel itself is file id 1, as in the real linker. */
	fake[0].id = 1;
	strlcpy(fake[0].name, "kernel", sizeof(fake[0].name));
	strlcpy(fake[0].path, "/boot/kernel/kernel", sizeof(fake[0].path));
	sysext_test_kld_load = fake_load;
	sysext_test_kld_unload = fake_unload;
	sysext_test_kld_stat = fake_stat;
	sysext_test_kld_next = fake_next;
	sysext_test_root_reset();
	sysext_test_decisions_reset();
}

/* ------------------------------------------------------------ fixtures */

static void
write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	ATF_REQUIRE((size_t)write(fd, content, strlen(content)) ==
	    strlen(content));
	close(fd);
}

static void
checksum_of(const char *content, char *out, size_t outlen)
{
	int fd;

	write_file("checksum.tmp", content);
	fd = open("checksum.tmp", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, sysext_pkg_checksum_fd(fd, out, outlen));
	close(fd);
	unlink("checksum.tmp");
}

static void
sql(sqlite3 *db, const char *statement)
{
	char *message = NULL;

	ATF_REQUIRE_MSG(sqlite3_exec(db, statement, NULL, NULL, &message) ==
	    SQLITE_OK, "%s: %s", statement, message != NULL ? message : "?");
}

static void
add_file(sqlite3 *db, const char *path, const char *checksum, int package)
{
	char *statement;

	statement = sqlite3_mprintf("INSERT INTO files (path, sha256, uname, "
	    "gname, perm, fflags, mtime, symlink_target, package_id) VALUES "
	    "(%Q, %Q, 'root', 'wheel', 365, 0, 0, NULL, %d);", path, checksum,
	    package);
	sql(db, statement);
	sqlite3_free(statement);
}

/*
 * kernel/ and pkg/local.sqlite in pkg's schema (the columns rootload.c reads):
 *   rltest_a.ko  base package, 5BSD-base, matching checksum
 *   rltest_b.ko  on disk, recorded by no package
 *   rltest_t.ko  base package, recorded checksum of other content (tampered)
 *   rltest_p.ko  recorded by a ports package (origin sysutils/...)
 *   rltest_r.ko  base origin, installed from another repository
 *   rltest_d.ko  base package (its load pulls in fake_dependency)
 *   rltest_l.ko  a symbolic link to rltest_a.ko
 *   rldep.ko     on disk, recorded by no package (a planted dependency)
 *   modules/rltest_m.ko  outside the kernel directory
 */
static void
fixture_files(void)
{
	char sum[SYSEXT_PKG_CHECKSUM_MAX];
	sqlite3 *db;

	ATF_REQUIRE_EQ(0, mkdir("kernel", 0755));
	ATF_REQUIRE_EQ(0, mkdir("modules", 0755));
	ATF_REQUIRE_EQ(0, mkdir("pkg", 0755));
	write_file("kernel/rltest_a.ko", "module a\n");
	write_file("kernel/rltest_b.ko", "module b\n");
	write_file("kernel/rltest_t.ko", "module t, modified\n");
	write_file("kernel/rltest_p.ko", "module p\n");
	write_file("kernel/rltest_r.ko", "module r\n");
	write_file("kernel/rltest_d.ko", "module d\n");
	write_file("kernel/rldep.ko", "planted dependency\n");
	write_file("modules/rltest_m.ko", "module m\n");
	ATF_REQUIRE_EQ(0, symlink("rltest_a.ko", "kernel/rltest_l.ko"));

	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_open("pkg/local.sqlite", &db));
	sql(db, "PRAGMA journal_mode = DELETE;");
	sql(db, "CREATE TABLE packages (id INTEGER PRIMARY KEY, origin TEXT "
	    "NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL);"
	    "CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT, uname "
	    "TEXT, gname TEXT, perm INTEGER, fflags INTEGER, mtime INTEGER, "
	    "symlink_target TEXT, package_id INTEGER REFERENCES packages(id));"
	    "CREATE TABLE annotation (annotation_id INTEGER PRIMARY KEY, "
	    "annotation TEXT NOT NULL UNIQUE);"
	    "CREATE TABLE pkg_annotation (package_id INTEGER, tag_id INTEGER "
	    "NOT NULL, value_id INTEGER NOT NULL, UNIQUE (package_id, tag_id));"
	    "INSERT INTO packages VALUES (1, 'base/5BSD-kernel-generic', "
	    "'5BSD-kernel-generic', '16.snap1');"
	    "INSERT INTO packages VALUES (2, 'sysutils/evil-kmod', 'evil-kmod', "
	    "'1.0');"
	    "INSERT INTO packages VALUES (3, 'base/5BSD-other', '5BSD-other', "
	    "'16.snap1');"
	    "INSERT INTO annotation VALUES (1, 'repository'), (2, '5BSD-base'), "
	    "(3, 'FreeBSD-base'), (4, 'set'), (5, 'kernels');"
	    "INSERT INTO pkg_annotation VALUES (1, 1, 2), (1, 4, 5), (2, 1, 2), "
	    "(3, 1, 3);");
	checksum_of("module a\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_a.ko", sum, 1);
	checksum_of("module t\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_t.ko", sum, 1);
	checksum_of("module p\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_p.ko", sum, 2);
	checksum_of("module r\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_r.ko", sum, 3);
	checksum_of("module d\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_d.ko", sum, 1);
	checksum_of("module a\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_l.ko", sum, 1);
	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_close(db));
}

/* Point rootload.c at the fixture directories in this process. */
static void
fixture_dirs(void)
{

	fixture_files();
	sysext_driver_dirfd = open("kernel", O_DIRECTORY | O_RDONLY);
	sysext_pkgdb_dirfd = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(sysext_driver_dirfd >= 0 && sysext_pkgdb_dirfd >= 0);
	fake_reset();
}

static uint32_t
load(const char *name, int *errorp)
{
	char detail[512];

	return (sysext_root_load("5BSD-base", name, errorp, detail,
	    sizeof(detail)));
}

static void
channel_pair(int *client, int *provider)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("capability channel syscall unavailable");
		atf_tc_fail("channel creation: %s", strerror(errno));
	}
	*client = pair[0];
	*provider = pair[1];
}

static void
policy(struct sysext_config *cfg, const char *repository)
{

	test_base_policy(cfg);
	if (repository != NULL)
		strlcpy(cfg->root_load_repository, repository,
		    sizeof(cfg->root_load_repository));
}

/* ------------------------------------------------------------- checksum */

/*
 * pkg 2.8.4 recorded this checksum for /usr/share/misc/init.ee (25 bytes) in
 * a 5BSD installation's local.sqlite: "2$" and pkg's z-base-32 of BLAKE2b-512.
 */
ATF_TC_WITHOUT_HEAD(checksum_matches_pkg);
ATF_TC_BODY(checksum_matches_pkg, tc)
{
	char sum[SYSEXT_PKG_CHECKSUM_MAX], small[8];
	int fd;

	(void)tc;
	checksum_of("emacs\nnoexpand\nnomargins\n", sum, sizeof(sum));
	ATF_CHECK_STREQ("2$po7r6okjgx8rh4399j9ofwwxcogck8h1ey3rjkcfr1xk5gr1so"
	    "jxc8ms5stpgkx1cqcu16y3kxo1r3e3yhgy1ha5y54wwbptwjy9rpd", sum);
	write_file("x", "x");
	fd = open("x", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(ENAMETOOLONG, sysext_pkg_checksum_fd(fd, small,
	    sizeof(small)));
	close(fd);
}

/* ----------------------------------------------------- package database */

ATF_TC_WITHOUT_HEAD(pkgdb_lookup);
ATF_TC_BODY(pkgdb_lookup, tc)
{
	struct sysext_pkg_record rec;
	int dir;

	(void)tc;
	fixture_files();
	dir = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dir >= 0);
	ATF_REQUIRE_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec));
	ATF_CHECK(rec.found);
	ATF_CHECK_STREQ("5BSD-kernel-generic", rec.package);
	ATF_CHECK_STREQ("base/5BSD-kernel-generic", rec.origin);
	ATF_CHECK_STREQ("5BSD-base", rec.repository);
	ATF_CHECK(strncmp(rec.checksum, "2$", 2) == 0);
	ATF_CHECK(!rec.symlink);
	ATF_CHECK_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_b.ko",
	    &rec));
	ATF_CHECK(!rec.found);
	/* A database that is not one fails closed. */
	write_file("pkg/local.sqlite", "not a database, but long enough to "
	    "pass the size check..........................................."
	    "..............................................................."
	    "..............................................................."
	    "..............................................................."
	    "..............................................................."
	    "..............................................................."
	    "..............................................................."
	    "...............................................................");
	ATF_CHECK(sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec) != 0);
	ATF_REQUIRE_EQ(0, unlink("pkg/local.sqlite"));
	ATF_CHECK_EQ(ENOENT, sysext_pkgdb_lookup(dir,
	    "/boot/kernel/rltest_a.ko", &rec));
	close(dir);
}

/* ------------------------------------------------------------ decisions */

ATF_TC_WITHOUT_HEAD(load_package_module);
ATF_TC_BODY(load_package_module, tc)
{
	char detail[256];
	int error;

	(void)tc;
	fixture_dirs();
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_a", &error));
	ATF_CHECK_EQ(0, error);
	ATF_CHECK(fake_loaded("rltest_a.ko"));
	/* By the absolute path, so kern.module_path cannot redirect it. */
	for (size_t i = 0; i < nitems(fake); i++)
		if (strcmp(fake[i].name, "rltest_a.ko") == 0)
			ATF_CHECK_STREQ("/boot/kernel/rltest_a.ko", fake[i].path);
	/* The kernel reports a second load as present. */
	ATF_CHECK_EQ(SYSEXT_DECISION_PRESENT, load("rltest_a.ko", &error));
	/* Unload: only what a root load loaded, once. */
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rltest_a",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(!fake_loaded("rltest_a.ko"));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_a", &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_d", &error, detail, sizeof(detail)));
	/* Another client relying on it blocks a root unload. */
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_a", &error));
	sysext_root_note_shared("rltest_a");
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_a", &error, detail, sizeof(detail)));
	ATF_CHECK(fake_loaded("rltest_a.ko"));
	/* Security, tracing and hypervisor modules are never root-unloaded. */
	ATF_CHECK(sysext_root_unload_protected("mac_portacl.ko"));
	ATF_CHECK(sysext_root_unload_protected("dtrace"));
	ATF_CHECK(sysext_root_unload_protected("vmm"));
	ATF_CHECK(!sysext_root_unload_protected("if_mos"));
}

ATF_TC_WITHOUT_HEAD(refuse_unpackaged_file);
ATF_TC_BODY(refuse_unpackaged_file, tc)
{
	int error;

	(void)tc;
	fixture_dirs();
	/* A file copied into /boot/kernel that no package records. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_b", &error));
	/* Owned by a ports package, or by a base package of another repo. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_p", &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_r", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

ATF_TC_WITHOUT_HEAD(refuse_tampered_checksum);
ATF_TC_BODY(refuse_tampered_checksum, tc)
{
	int error;

	(void)tc;
	fixture_dirs();
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_t", &error));
	/* A byte changed in a module that verified before. */
	write_file("kernel/rltest_a.ko", "module A\n");
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_a", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

ATF_TC_WITHOUT_HEAD(refuse_outside_kernel_dir);
ATF_TC_BODY(refuse_outside_kernel_dir, tc)
{
	int error;

	(void)tc;
	fixture_dirs();
	/* Only in another module directory, absent, or a symbolic link. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_m", &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_none",
	    &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_l", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

/* A dependency from outside /boot/kernel, or not packaged: undone. */
ATF_TC_WITHOUT_HEAD(refuse_unverified_dependency);
ATF_TC_BODY(refuse_unverified_dependency, tc)
{
	int error;

	(void)tc;
	fixture_dirs();
	strlcpy(fake_dependency, "/boot/modules/rldep.ko",
	    sizeof(fake_dependency));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_d", &error));
	ATF_CHECK_EQ(1, fake_unloads);
	ATF_CHECK(!fake_loaded("rltest_d.ko") && !fake_loaded("rldep.ko"));
	strlcpy(fake_dependency, "/boot/kernel/rldep.ko",
	    sizeof(fake_dependency));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_d", &error));
	ATF_CHECK_EQ(2, fake_unloads);
	ATF_CHECK(!fake_loaded("rltest_d.ko") && !fake_loaded("rldep.ko"));
	/* A verified dependency is fine. */
	strlcpy(fake_dependency, "/boot/kernel/rltest_a.ko",
	    sizeof(fake_dependency));
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_d", &error));
	ATF_CHECK(fake_loaded("rltest_d.ko") && fake_loaded("rltest_a.ko"));
}

ATF_TC_WITHOUT_HEAD(refuse_without_database);
ATF_TC_BODY(refuse_without_database, tc)
{
	int error;

	(void)tc;
	fixture_dirs();
	ATF_REQUIRE_EQ(0, unlink("pkg/local.sqlite"));
	ATF_CHECK_EQ(SYSEXT_DECISION_PKGDB, load("rltest_a", &error));
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(0, fake_loads);
}

/* ------------------------------------------------------------- endpoint */

/*
 * Serve RootLoad sessions in a child (the fake kernel lives there), then a
 * status session in the same process, so the decision ring is shared as in
 * the broker.
 */
struct endpoint {
	pid_t child;
	int clients[3];
};

static void
endpoint_start(struct endpoint *e, const char *repository, const char *deny,
    int nload)
{
	struct sysext_config cfg;
	int providers[3];

	fixture_files();
	policy(&cfg, repository);
	for (int i = 0; i < nload + 1; i++)
		channel_pair(&e->clients[i], &providers[i]);
	e->child = fork();
	ATF_REQUIRE(e->child >= 0);
	if (e->child == 0) {
		int kdir, pdir, r = 0;

		for (int i = 0; i < nload + 1; i++)
			close(e->clients[i]);
		kdir = open("kernel", O_DIRECTORY | O_RDONLY);
		pdir = open("pkg", O_DIRECTORY | O_RDONLY);
		fake_reset();
		for (int i = 0; i < nload; i++)
			r |= sysext_test_serve_rootload(providers[i],
			    "org.5bsd.user-session", &cfg, kdir, pdir, deny);
		r |= sysext_test_serve_status(providers[nload],
		    "org.5bsd.user-session", &cfg);
		_exit(r);
	}
	for (int i = 0; i < nload + 1; i++)
		close(providers[i]);
}

static void
endpoint_finish(struct endpoint *e)
{
	int st;

	ATF_REQUIRE_EQ(e->child, waitpid(e->child, &st, 0));
	ATF_CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/*
 * A root session loads a package module, its refusals carry the reason, and
 * the status view reports every decision with the root client.
 */
ATF_TC(endpoint_load_and_status);
ATF_TC_HEAD(endpoint_load_and_status, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RootLoad loads a base package module; status shows the decisions");
}
ATF_TC_BODY(endpoint_load_and_status, tc)
{
	struct service_extension_root_outcome o;
	struct service_extension_decision d;
	struct extensioncmp_session *root, *status;
	struct endpoint e;
	static const struct { const char *name; int result; } expect[] = {
		{ "rltest_a", SYSEXT_DECISION_LOADED },
		{ "rltest_b", SYSEXT_DECISION_NOT_PACKAGED },
		{ "rltest_t", SYSEXT_DECISION_CHECKSUM },
		{ "rltest_m", SYSEXT_DECISION_NOT_KERNEL_DIR },
		{ "kernel", SYSEXT_DECISION_PRESENT },
	};
	uint64_t after = 0;

	endpoint_start(&e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	for (size_t i = 0; i < nitems(expect); i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, expect[i].name,
		    &o));
		ATF_CHECK_EQ_MSG(expect[i].result, o.result, "%s: %d",
		    expect[i].name, o.result);
	}
	ATF_REQUIRE_EQ(0, extensioncmp_root_unload(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, o.result);
	ATF_REQUIRE_EQ(0, extensioncmp_root_unload(root, "rltest_b", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED, o.result);
	/* A path is not a module name: refused before anything is sent. */
	ATF_CHECK_ERRNO(EINVAL, extensioncmp_root_load(root,
	    "../modules/rltest_m", &o) == -1);
	ATF_CHECK_ERRNO(EINVAL, extensioncmp_root_load(root,
	    "/boot/modules/rltest_m.ko", &o) == -1);
	extensioncmp_session_close(root);

	ATF_REQUIRE_EQ(0, extensioncmp_session_create_status(e.clients[1],
	    &status));
	for (size_t i = 0; i < nitems(expect) + 2; i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_decision(status, after, &d));
		after = d.sequence;
		ATF_CHECK_STREQ("root (uid 0)", d.client);
		if (i < nitems(expect)) {
			ATF_CHECK_STREQ(expect[i].name, d.name);
			ATF_CHECK_EQ(SYSEXT_OP_ROOT_LOAD, d.operation);
			ATF_CHECK_EQ(expect[i].result, d.result);
		} else
			ATF_CHECK_EQ(SYSEXT_OP_ROOT_UNLOAD, d.operation);
	}
	ATF_CHECK_ERRNO(ENOENT, extensioncmp_decision(status, after, &d) == -1);
	extensioncmp_session_close(status);
	endpoint_finish(&e);
}

/* Administrator denies win; without root_load_repository nothing loads. */
ATF_TC(endpoint_policy_refusals);
ATF_TC_HEAD(endpoint_policy_refusals, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A denied module and an unconfigured policy are refused");
}
ATF_TC_BODY(endpoint_policy_refusals, tc)
{
	struct service_extension_root_outcome o;
	struct extensioncmp_session *root;
	struct endpoint e;

	endpoint_start(&e, "5BSD-base", "rltest_a", 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_OVERRIDE, o.result);
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_d", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, o.result);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
	ATF_REQUIRE_EQ(0, system("rm -rf kernel modules pkg rl-policy-state"));

	endpoint_start(&e, NULL, NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_DISABLED, o.result);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
}

/* FIDL v2 transactional message header and a Module body. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
struct module_frame {
	uint64_t size;
	uint64_t presence;
	char name[64];
};

#define	ORD_ROOTLOAD_PROTOCOL	UINT64_C(0x3e653a95966a0d64)
#define	ORD_ROOTLOAD_LOAD	UINT64_C(0x628311e2c07df9de)
#define	ORD_ENSURE	UINT64_C(0x20729fc6bf255a8d)
#define	ORD_STAT	UINT64_C(0x318126ca32fd13e1)
#define	ORD_LIST	UINT64_C(0x27d9ac31c7bce8c3)
#define	ORD_RELOAD	UINT64_C(0x42969f6472d4b6ef)
#define	ORD_ALLOW	UINT64_C(0x3d329bc1c82f3571)
#define	ORD_RESTORE	UINT64_C(0x055ac9d5d610de33)
#define	ORD_STATUS_PROTOCOL	UINT64_C(0x29dc67c4cb8fb696)

/* -1 when the provider closed the session, else the reply's error (0 ok). */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t body_length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };
	uint8_t frame[256], reply[4096];
	uint64_t tag;
	uint32_t value;

	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = frame;
	outgoing.length = sizeof(header) + body_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 5000;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length < sizeof(struct wire_header) + 16)
		return (0);
	memcpy(&tag, reply + sizeof(struct wire_header), sizeof(tag));
	memcpy(&value, reply + sizeof(struct wire_header) + 8, sizeof(value));
	return (tag == 2 ? (int)value : 0);
}

static size_t
module_frame(struct module_frame *f, const char *name)
{
	size_t length = strlen(name);

	memset(f, 0, sizeof(*f));
	f->size = length;
	f->presence = UINT64_MAX;
	memcpy(f->name, name, length);
	return (16 + ((length + 7) & ~(size_t)7));
}

/*
 * The RootLoad protocol has Load and Unload only: an Ensure, Stat, List,
 * Reload, Allow or Restore frame is an unknown ordinal and closes the session
 * unanswered, even with every right on it.  The library refuses the same
 * operations without sending anything.
 */
ATF_TC(endpoint_has_no_policy_methods);
ATF_TC_HEAD(endpoint_has_no_policy_methods, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The root-load endpoint answers no policy, list or status method");
}
ATF_TC_BODY(endpoint_has_no_policy_methods, tc)
{
	static const struct { uint64_t ordinal; bool named; } methods[] = {
		{ ORD_ENSURE, true }, { ORD_STAT, true }, { ORD_LIST, false },
		{ ORD_RELOAD, false }, { ORD_ALLOW, true },
		{ ORD_RESTORE, false }, { ORD_STATUS_PROTOCOL, false },
	};
	struct service_extension_info info;
	struct service_extension_decision d;
	struct service_session *raw;
	struct extensioncmp_session *root;
	struct module_frame body;
	struct endpoint e;
	size_t length;
	int loaded;

	for (size_t i = 0; i < nitems(methods); i++) {
		endpoint_start(&e, "5BSD-base", NULL, 1);
		ATF_REQUIRE_EQ(0, service_session_create(e.clients[0], &raw));
		ATF_REQUIRE_EQ(0, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL,
		    0));
		length = methods[i].named ? module_frame(&body, "rltest_a") : 0;
		ATF_CHECK_EQ_MSG(-1, send_frame(raw, methods[i].ordinal, &body,
		    length), "ordinal %#jx answered on the root-load endpoint",
		    (uintmax_t)methods[i].ordinal);
		ATF_CHECK_EQ(-1, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL,
		    0));
		service_session_close(raw);
		close(e.clients[1]);
		endpoint_finish(&e);
		ATF_REQUIRE_EQ(0, system("rm -rf kernel modules pkg"));
	}

	/* A malformed name is an error reply, not a decision. */
	endpoint_start(&e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, service_session_create(e.clients[0], &raw));
	ATF_REQUIRE_EQ(0, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL, 0));
	ATF_CHECK_EQ(EINVAL, send_frame(raw, ORD_ROOTLOAD_LOAD, &body,
	    module_frame(&body, "../modules/rltest_m")));
	ATF_CHECK_EQ(EINVAL, send_frame(raw, ORD_ROOTLOAD_LOAD, &body,
	    module_frame(&body, "..")));
	service_session_close(raw);
	close(e.clients[1]);
	endpoint_finish(&e);
	ATF_REQUIRE_EQ(0, system("rm -rf kernel modules pkg"));

	endpoint_start(&e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_CHECK_ERRNO(EPERM, extensioncmp_load(root, "rltest_a") == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_stat(root, "rltest_a",
	    &loaded) == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_reload(root) == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_manage(root,
	    SERVICE_EXTENSION_ALLOW, "rltest_a") == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_info(root, "rltest_a", 0,
	    &info) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, extensioncmp_decision(root, 0, &d) == -1);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
}

/* The policy key: a repository name, at most once, nothing else. */
ATF_TC_WITHOUT_HEAD(policy_key);
ATF_TC_BODY(policy_key, tc)
{
	struct sysext_config cfg;
	static const char *const bad[] = {
		"root_load_repository = 42; allowed_extensions = [];",
		"root_load_repository = \"a/b\"; allowed_extensions = [];",
		"root_load_repository = \"\"; allowed_extensions = [];",
		"root_load_repository = [\"5BSD-base\"]; allowed_extensions = [];",
		("root_load_repository = \"x\"; root_load_repository = \"y\"; "
		    "allowed_extensions = [];"),
	};

	(void)tc;
	write_file("good.ucl", "root_load_repository = \"5BSD-base\"; "
	    "device_drivers = true; driver_clients = [\"devd\"]; "
	    "allowed_extensions = [\"zfs\"];");
	ATF_REQUIRE_EQ(0, chmod("good.ucl", 0644));
	sysext_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, "good.ucl"));
	ATF_CHECK_STREQ("5BSD-base", cfg.root_load_repository);
	write_file("none.ucl", "allowed_extensions = [];");
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, "none.ucl"));
	ATF_CHECK_STREQ("", cfg.root_load_repository);
	for (size_t i = 0; i < nitems(bad); i++) {
		write_file("bad.ucl", bad[i]);
		ATF_CHECK_MSG(sysext_config_load(&cfg, "bad.ucl") == -1,
		    "accepted: %s", bad[i]);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, checksum_matches_pkg);
	ATF_TP_ADD_TC(tp, pkgdb_lookup);
	ATF_TP_ADD_TC(tp, load_package_module);
	ATF_TP_ADD_TC(tp, refuse_unpackaged_file);
	ATF_TP_ADD_TC(tp, refuse_tampered_checksum);
	ATF_TP_ADD_TC(tp, refuse_outside_kernel_dir);
	ATF_TP_ADD_TC(tp, refuse_unverified_dependency);
	ATF_TP_ADD_TC(tp, refuse_without_database);
	ATF_TP_ADD_TC(tp, endpoint_load_and_status);
	ATF_TP_ADD_TC(tp, endpoint_policy_refusals);
	ATF_TP_ADD_TC(tp, endpoint_has_no_policy_methods);
	ATF_TP_ADD_TC(tp, policy_key);
	return (atf_no_error());
}

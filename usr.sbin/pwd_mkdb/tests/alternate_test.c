/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the real generator and compare database records, not flat files. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <atf-c.h>
#include <db.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
input(const char *directory, const char *text)
{
	char path[256];
	FILE *file;

	ATF_REQUIRE(snprintf(path, sizeof(path), "%s/input", directory) < (int)sizeof(path));
	file = fopen(path, "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs(text, file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
}

static void
build_input(const atf_tc_t *tc, const char *directory, const char *name,
    const char *user, int status)
{
	const char *tool = atf_tc_get_config_var_wd(tc, "pwd_mkdb", "/usr/sbin/pwd_mkdb");
	char path[256];
	pid_t child;
	int result;

	ATF_REQUIRE(snprintf(path, sizeof(path), "%s/%s", directory, name) < (int)sizeof(path));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (user == NULL)
			execl(tool, tool, "-p", "-d", directory, path, (char *)NULL);
		else
			execl(tool, tool, "-p", "-d", directory, "-u", user, path, (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &result, 0));
	ATF_REQUIRE(WIFEXITED(result));
	ATF_REQUIRE_EQ(status, WEXITSTATUS(result));
}

static void
build(const atf_tc_t *tc, const char *directory, const char *user, int status)
{

	build_input(tc, directory, "input", user, status);
}

static void
record(const char *database, const char *name, uid_t uid)
{
	DB *actual, *expected;
	DBT key, a, e;
	char path[256], data[128];
	uint32_t number;

	ATF_REQUIRE(snprintf(path, sizeof(path), "target/%s", database) < (int)sizeof(path));
	actual = dbopen(path, O_RDONLY, 0, DB_HASH, NULL);
	ATF_REQUIRE(actual != NULL);
	ATF_REQUIRE(snprintf(path, sizeof(path), "expected/%s", database) < (int)sizeof(path));
	expected = dbopen(path, O_RDONLY, 0, DB_HASH, NULL);
	ATF_REQUIRE(expected != NULL);
	key.data = data;
	if (name != NULL) {
		data[0] = _PW_VERSIONED(_PW_KEYBYNAME, _PWD_CURRENT_VERSION);
		ATF_REQUIRE(strlen(name) < sizeof(data) - 1);
		memcpy(data + 1, name, strlen(name));
		key.size = strlen(name) + 1;
	} else {
		data[0] = _PW_VERSIONED(_PW_KEYBYUID, _PWD_CURRENT_VERSION);
		number = htonl(uid);
		memcpy(data + 1, &number, sizeof(number));
		key.size = sizeof(number) + 1;
	}
	ATF_REQUIRE_EQ(0, actual->get(actual, &key, &a, 0));
	ATF_REQUIRE_EQ(0, expected->get(expected, &key, &e, 0));
	ATF_CHECK_MSG(a.size == e.size && memcmp(a.data, e.data, a.size) == 0,
	    "%s %s record differs from a full rebuild of the declared target inputs",
	    database, name == NULL ? "UID" : "name");
	ATF_REQUIRE_EQ(0, actual->close(actual));
	ATF_REQUIRE_EQ(0, expected->close(expected));
}

static void
check(const char *name, uid_t uid)
{
	record("pwd.db", name, uid);
	record("pwd.db", NULL, uid);
	record("spwd.db", name, uid);
	record("spwd.db", NULL, uid);
}

static void
prepare(void)
{
	ATF_REQUIRE_EQ(0, mkdir("target", 0700));
	ATF_REQUIRE_EQ(0, mkdir("expected", 0700));
}

ATF_TC_WITHOUT_HEAD(alternate_uid_update);
ATF_TC_BODY(alternate_uid_update, tc)
{
	char name[32], before[256], after[256];

	prepare();
	snprintf(name, sizeof(name), "mkdb_fixture_%ld", (long)getpid());
	ATF_REQUIRE(getpwnam(name) == NULL);
	snprintf(before, sizeof(before), "%s:old:42420:42420::0:0:Before:/nonexistent:/usr/sbin/nologin\n", name);
	snprintf(after, sizeof(after), "%s:new:42420:42420::0:0:After:/nonexistent:/usr/sbin/nologin\n", name);
	input("target", before);
	build(tc, "target", NULL, 0);
	input("target", after);
	build(tc, "target", name, 0);
	input("expected", after);
	build(tc, "expected", NULL, 0);
	check(name, 42420);
}

ATF_TC_WITHOUT_HEAD(alternate_duplicate_uid);
ATF_TC_BODY(alternate_duplicate_uid, tc)
{
	const char *before = "first:*:0:0::0:0:First:/nonexistent:/usr/sbin/nologin\n"
	    "root:old:0:0::0:0:Before:/nonexistent:/usr/sbin/nologin\n";
	const char *after = "first:*:0:0::0:0:First:/nonexistent:/usr/sbin/nologin\n"
	    "root:new:0:0::0:0:After:/nonexistent:/usr/sbin/nologin\n";
	struct passwd *host;

	/* Host root owns its UID; the alternate root account is an alias. */
	host = getpwnam("root");
	ATF_REQUIRE(host != NULL);
	host = getpwuid(host->pw_uid);
	ATF_REQUIRE(host != NULL && strcmp(host->pw_name, "root") == 0);
	prepare();
	input("target", before);
	build(tc, "target", NULL, 0);
	input("target", after);
	build(tc, "target", "root", 0);
	input("expected", after);
	build(tc, "expected", NULL, 0);
	check("root", 0);
	check("first", 0);
}

ATF_TC_WITHOUT_HEAD(malformed_update_retains_database);
ATF_TC_BODY(malformed_update_retains_database, tc)
{
	const char *before = "fixture:*:42422:42422::0:0:Before:/nonexistent:/usr/sbin/nologin\n";

	prepare();
	input("target", before);
	build(tc, "target", NULL, 0);
	input("expected", before);
	build(tc, "expected", NULL, 0);
	input("target", "invalid password record\n");
	build(tc, "target", "fixture", 1);
	check("fixture", 42422);
	ATF_CHECK(access("target/pwd.db.tmp", F_OK) != 0);
	ATF_CHECK(access("target/spwd.db.tmp", F_OK) != 0);
}

ATF_TC_WITHOUT_HEAD(in_place_input_metadata);
ATF_TC_BODY(in_place_input_metadata, tc)
{
	struct stat before, after;

	ATF_REQUIRE_EQ(0, mkdir("target", 0700));
	input("target", "fixture:*:42422:42422::0:0:Fixture:/nonexistent:/usr/sbin/nologin\n");
	ATF_REQUIRE_EQ(0, rename("target/input", "target/master.passwd"));
	ATF_REQUIRE_EQ(0, chmod("target/master.passwd", 0600));
	ATF_REQUIRE_EQ(0, stat("target/master.passwd", &before));
	if (before.st_flags != 0)
		ATF_REQUIRE_EQ(0, chflags("target/master.passwd", 0));
	ATF_REQUIRE_EQ(0, stat("target/master.passwd", &before));
	build_input(tc, "target", "master.passwd", NULL, 0);
	ATF_REQUIRE_EQ(0, stat("target/master.passwd", &after));
	ATF_CHECK_EQ(before.st_flags, after.st_flags);
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);
	ATF_CHECK_EQ(before.st_mtim.tv_sec, after.st_mtim.tv_sec);
	ATF_CHECK_EQ(before.st_mtim.tv_nsec, after.st_mtim.tv_nsec);
}

ATF_TC_WITHOUT_HEAD(directory_alias_updates);
ATF_TC_BODY(directory_alias_updates, tc)
{
	static const char *names[] = { "master.passwd", "passwd", "pwd.db", "spwd.db" };
	static const char *inputs[] = {
	    "fixture:*:42422:42422::0:0:Before:/nonexistent:/usr/sbin/nologin\n",
	    "fixture:*:42422:42422::0:0:After:/nonexistent:/usr/sbin/nologin\n"
	};
	struct stat st;
	char alias[256], destination[256], link[256];
	ssize_t length;
	unsigned i, pass;

	ATF_REQUIRE_EQ(0, mkdir("etc", 0700));
	ATF_REQUIRE_EQ(0, mkdir("target", 0700));
	ATF_REQUIRE_EQ(0, mkdir("expected", 0700));
	ATF_REQUIRE_EQ(0, symlink("../target", "etc/accounts"));
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(alias, sizeof(alias), "etc/%s", names[i]);
		snprintf(destination, sizeof(destination), "accounts/%s", names[i]);
		ATF_REQUIRE_EQ(0, symlink(destination, alias));
	}
	for (pass = 0; pass < 2; pass++) {
		input("target", inputs[pass]);
		input("expected", inputs[pass]);
		build(tc, "etc/accounts", pass ? "fixture" : NULL, 0);
		build(tc, "expected", NULL, 0);
		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			snprintf(alias, sizeof(alias), "etc/%s", names[i]);
			ATF_REQUIRE_EQ(0, lstat(alias, &st));
			ATF_CHECK(S_ISLNK(st.st_mode));
			snprintf(destination, sizeof(destination), "accounts/%s", names[i]);
			length = readlink(alias, link, sizeof(link));
			ATF_REQUIRE_EQ((ssize_t)strlen(destination), length);
			ATF_CHECK(memcmp(link, destination, (size_t)length) == 0);
			ATF_REQUIRE_EQ(0, stat(alias, &st));
			ATF_CHECK(S_ISREG(st.st_mode));
		}
		ATF_REQUIRE_EQ(0, lstat("etc/accounts", &st));
		ATF_CHECK(S_ISLNK(st.st_mode));
		record("pwd.db", "fixture", 42422);
		record("spwd.db", "fixture", 42422);
		record("pwd.db", NULL, 42422);
		record("spwd.db", NULL, 42422);
	}
}

static void
shell_check(const atf_tc_t *tc, const char *shells, int expected,
    int warning)
{
	const char *tool = atf_tc_get_config_var_wd(tc, "pwd_mkdb", "/usr/sbin/pwd_mkdb");
	char output[2048];
	pid_t child;
	int status, fd;
	ssize_t length;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		fd = open("diagnostics", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0 || dup2(fd, STDERR_FILENO) < 0)
			_exit(126);
		close(fd);
		execl(tool, tool, "-C", "-S", shells, "target/input", (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(expected, WEXITSTATUS(status));
	fd = open("diagnostics", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	length = read(fd, output, sizeof(output) - 1);
	ATF_REQUIRE(length >= 0);
	output[length] = '\0';
	close(fd);
	ATF_REQUIRE_EQ(warning, strstr(output, "unknown root shell") != NULL);
	if (expected == 0 && !warning)
		ATF_REQUIRE_EQ(0, length);
	ATF_REQUIRE(access("target/pwd.db", F_OK) != 0);
	ATF_REQUIRE(access("target/spwd.db", F_OK) != 0);
}

ATF_TC_WITHOUT_HEAD(explicit_shell_policy);
ATF_TC_BODY(explicit_shell_policy, tc)
{
	FILE *file;

	prepare();
	input("target", "root:*:0:0::0:0:Root:/root:/test/declared-shell\n");
	file = fopen("shells", "w");
	ATF_REQUIRE(file != NULL);
	fputs("# comment\n  /test/declared-shell # comment\n", file);
	ATF_REQUIRE_EQ(0, fclose(file));
	shell_check(tc, "shells", 0, 0);
	file = fopen("shells", "w");
	ATF_REQUIRE(file != NULL);
	fputs("/test/different-shell\n", file);
	ATF_REQUIRE_EQ(0, fclose(file));
	shell_check(tc, "shells", 0, 1);
	file = fopen("shells", "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE_EQ(0, fclose(file));
	shell_check(tc, "shells", 0, 1);
	shell_check(tc, "missing-shell-list", 1, 0);
	file = fopen("shells", "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE_EQ(1, fwrite("/test/declared-shell\0bad\n", 25, 1, file));
	ATF_REQUIRE_EQ(0, fclose(file));
	shell_check(tc, "shells", 1, 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, explicit_shell_policy);
	ATF_TP_ADD_TC(tp, directory_alias_updates);
	ATF_TP_ADD_TC(tp, in_place_input_metadata);
	ATF_TP_ADD_TC(tp, alternate_uid_update);
	ATF_TP_ADD_TC(tp, alternate_duplicate_uid);
	ATF_TP_ADD_TC(tp, malformed_update_retains_database);
	return (atf_no_error());
}

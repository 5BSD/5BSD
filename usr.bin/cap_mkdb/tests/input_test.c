/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
write_input(const char *path, const char *contents)
{
	FILE *file = fopen(path, "w");
	ATF_REQUIRE(file != NULL);
	ATF_REQUIRE(fputs(contents, file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
}

static void
build(const atf_tc_t *tc, const char *output, const char *first,
    const char *second, int expected)
{
	const char *tool = atf_tc_get_config_var_wd(tc, "cap_mkdb", "/usr/bin/cap_mkdb");
	pid_t child = fork();
	int status;

	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (output == NULL)
			execl(tool, tool, "-l", first, second, (char *)NULL);
		else
			execl(tool, tool, "-l", "-f", output, first, second, (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status), "generator terminated by signal: %d", status);
	ATF_REQUIRE_EQ(expected, WEXITSTATUS(status));
}

static void
value(const char *path, const char *name, long expected)
{
	char *files[] = {__DECONST(char *, path), NULL};
	char *record;
	long number;

	ATF_REQUIRE_EQ(0, cgetent(&record, files, name));
	ATF_REQUIRE_EQ(0, cgetnum(record, "limit", &number));
	ATF_CHECK_EQ(expected, number);
	free(record);
}

ATF_TC_WITHOUT_HEAD(alternate_output);
ATF_TC_BODY(alternate_output, tc)
{
	write_input("input", "default:limit#11:\n");
	build(tc, NULL, "input", NULL, 0);
	write_input("input", "default:limit#29:\n");
	build(tc, "output", "input", NULL, 0);
	value("output", "default", 29);
	/* The pre-existing input cache is neither authority nor an output. */
	value("input", "default", 11);
}

ATF_TC_WITHOUT_HEAD(inherited_input);
ATF_TC_BODY(inherited_input, tc)
{
	write_input("parent", "parent:limit#11:\n");
	build(tc, NULL, "parent", NULL, 0);
	write_input("parent", "parent:limit#29:\n");
	write_input("child", "default:tc=parent:\n");
	build(tc, "output", "child", "parent", 0);
	value("output", "default", 29);
	value("output", "parent", 29);
	value("parent", "parent", 11);
}

ATF_TC_WITHOUT_HEAD(default_output);
ATF_TC_BODY(default_output, tc)
{
	write_input("input", "default:limit#11:\n");
	build(tc, NULL, "input", NULL, 0);
	write_input("input", "default:limit#29:\n");
	build(tc, NULL, "input", NULL, 0);
	value("input", "default", 29);
}

ATF_TC_WITHOUT_HEAD(reader_selection);
ATF_TC_BODY(reader_selection, tc)
{
	char input[] = "input", *files[] = {input, NULL}, *record;
	long number;

	write_input("input", "default:limit#11:\n");
	build(tc, NULL, "input", NULL, 0);
	write_input("input", "default:limit#29:\n");
	value("input", "default", 11);
	ATF_REQUIRE_EQ(1, cgetusedb(0));
	value("input", "default", 29);
	ATF_REQUIRE_EQ(1, cgetfirst(&record, files));
	ATF_REQUIRE_EQ(0, cgetnum(record, "limit", &number));
	ATF_CHECK_EQ(29, number);
	free(record);
	ATF_REQUIRE_EQ(0, cgetclose());
	ATF_REQUIRE_EQ(0, cgetusedb(1));
	value("input", "default", 11);
}

ATF_TC_WITHOUT_HEAD(long_continued_name);
ATF_TC_BODY(long_continued_name, tc)
{
	char text[8192];

	memset(text, 'a', sizeof(text) - 3);
	memcpy(text + 600, "\\\n", 2);
	memcpy(text + sizeof(text) - 3, ":\n", 3);
	write_input("input", text);
	build(tc, NULL, "input", NULL, 1);
	ATF_REQUIRE_EQ(-1, access("input.db", F_OK));
	ATF_REQUIRE_EQ(ENOENT, errno);
}

ATF_TC_WITHOUT_HEAD(long_name);
ATF_TC_BODY(long_name, tc)
{
	char text[8192];

	memset(text, 'a', sizeof(text) - 3);
	memcpy(text + sizeof(text) - 3, ":\n", 3);
	write_input("input", text);
	build(tc, NULL, "input", NULL, 1);
	ATF_REQUIRE_EQ(-1, access("input.db", F_OK));
	ATF_REQUIRE_EQ(ENOENT, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, alternate_output);
	ATF_TP_ADD_TC(tp, inherited_input);
	ATF_TP_ADD_TC(tp, default_output);
	ATF_TP_ADD_TC(tp, reader_selection);
	ATF_TP_ADD_TC(tp, long_name);
	ATF_TP_ADD_TC(tp, long_continued_name);
	return (atf_no_error());
}

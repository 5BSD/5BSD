/* SPDX-License-Identifier: BSD-2-Clause */
/* Runtime qualification for explicit Make/Bazel fixture binaries. */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
check_output(int fd, const char *expected, const char *label)
{
	char buffer[256];
	ssize_t n;

	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	n = read(fd, buffer, sizeof(buffer) - 1);
	ATF_REQUIRE_MSG(n >= 0, "%s read: %s", label, strerror(errno));
	buffer[n] = '\0';
	ATF_REQUIRE_MSG((size_t)n == strlen(expected) &&
	    memcmp(buffer, expected, (size_t)n) == 0,
	    "%s mismatch: got <%s>, expected <%s>", label, buffer, expected);
	ATF_REQUIRE_MSG(read(fd, buffer, sizeof(buffer)) == 0,
	    "%s contains additional output", label);
}

static void
run_case_status(const char *program, char *const argv[], const char *expected,
    int exit_status, const char *missing_library)
{
	char outname[] = "stdout.XXXXXX", errname[] = "stderr.XXXXXX";
	int outfd, errfd, status;
	pid_t child, waited;

	outfd = mkstemp(outname);
	ATF_REQUIRE(outfd >= 0);
	errfd = mkstemp(errname);
	ATF_REQUIRE(errfd >= 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (dup2(outfd, STDOUT_FILENO) < 0 ||
		    dup2(errfd, STDERR_FILENO) < 0)
			_exit(126);
		close(outfd);
		close(errfd);
		execv(program, argv);
		perror(program);
		_exit(127);
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	ATF_REQUIRE(waited == child);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == exit_status,
	    "%s failed: wait status %#x (output retained in %s and %s)",
	    program, status, outname, errname);
	check_output(outfd, expected, "stdout");
	if (missing_library == NULL) {
		check_output(errfd, "", "stderr");
	} else {
		char diagnostic[1024];
		ssize_t length;

		ATF_REQUIRE(lseek(errfd, 0, SEEK_SET) == 0);
		length = read(errfd, diagnostic, sizeof(diagnostic) - 1);
		ATF_REQUIRE(length > 0);
		diagnostic[length] = '\0';
		ATF_REQUIRE_MSG(strncmp(diagnostic, "dlopen ", 7) == 0 &&
		    strstr(diagnostic, missing_library) != NULL,
		    "missing-library diagnostic does not identify requested dlopen: %s", diagnostic);
	}
	close(outfd);
	close(errfd);
	ATF_REQUIRE(unlink(outname) == 0);
	ATF_REQUIRE(unlink(errname) == 0);
}

static void
run_case(const char *program, char *const argv[], const char *expected)
{
	run_case_status(program, argv, expected, 0, NULL);
}

ATF_TC(echo_variants);
ATF_TC_HEAD(echo_variants, tc)
{
	atf_tc_set_md_var(tc, "descr", "Execute the selected base echo with exact output/status checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
static void
echo_cases(const char *program)
{
	char echo[] = "echo", hello[] = "hello", world[] = "world";
	char nflag[] = "-n", eflag[] = "-e";
	char *empty[] = { echo, NULL };
	char *words[] = { echo, hello, world, NULL };
	char *nonewline[] = { echo, nflag, hello, NULL };
	char *literal[] = { echo, eflag, hello, NULL };

	run_case(program, empty, "\n");
	run_case(program, words, "hello world\n");
	run_case(program, nonewline, "hello");
	run_case(program, literal, "-e hello\n");
}

ATF_TC_BODY(echo_variants, tc)
{
	echo_cases(atf_tc_get_config_var_wd(tc, "echo_program",
	    "/usr/tests/bazel/echo"));
}

ATF_TC(make_echo_variants);
ATF_TC_HEAD(make_echo_variants, tc)
{
	atf_tc_set_md_var(tc, "descr", "Execute unchanged Make-built base echo with identical runtime cases");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(make_echo_variants, tc)
{
	echo_cases(atf_tc_get_config_var_wd(tc, "make_echo_program",
	    "/usr/tests/bazel/make-echo"));
}

ATF_TC(cpp_runtime);
ATF_TC_HEAD(cpp_runtime, tc)
{
	atf_tc_set_md_var(tc, "descr", "Execute staged C++ vector/iostream output with exact status checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cpp_runtime, tc)
{
	const char *program = atf_tc_get_config_var_wd(tc, "cpp_program",
	    "/usr/tests/bazel/cpp_runtime");
	char name[] = "cpp_runtime";
	char *args[] = { name, NULL };

	run_case(program, args, "3\n");
}

ATF_TC(archive_runtime);
ATF_TC_HEAD(archive_runtime, tc)
{
	atf_tc_set_md_var(tc, "descr", "Execute C and assembly archive member behavior with exact output/status");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(archive_runtime, tc)
{
	const char *program = atf_tc_get_config_var_wd(tc, "archive_program",
	    "/usr/tests/bazel/archive_runtime");
	char name[] = "archive_runtime";
	char *args[] = { name, NULL };

	run_case(program, args, "archive-runtime: ok\n");
}

static void
shared_case(const atf_tc_t *tc, const char *key, const char *fallback)
{
	const char *program = atf_tc_get_config_var_wd(tc, "shared_program",
	    "/usr/tests/bazel/shared_runtime");
	char name[] = "shared_runtime";
	char *library = strdup(atf_tc_get_config_var_wd(tc, key, fallback));
	char *args[] = { name, library, NULL };

	ATF_REQUIRE(library != NULL);
	run_case(program, args, "shared-runtime: ok\n");
	free(library);
}

ATF_TC(shared_bazel);
ATF_TC_HEAD(shared_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Load Bazel shared library and check symbol providers and behavior");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(shared_bazel, tc)
{
	shared_case(tc, "bazel_library", "/usr/tests/bazel/libbsd_samples.so.1");
}

ATF_TC(shared_make);
ATF_TC_HEAD(shared_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Load independent Make library with identical provider and behavior checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(shared_make, tc)
{
	shared_case(tc, "make_library", "/usr/tests/bazel/libbsd_samples-make.so.1");
}

ATF_TC(shared_missing_library);
ATF_TC_HEAD(shared_missing_library, tc)
{
	atf_tc_set_md_var(tc, "descr", "Require an actual dlopen failure for an explicitly missing library");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(shared_missing_library, tc)
{
	const char *program = atf_tc_get_config_var_wd(tc, "shared_program",
	    "/usr/tests/bazel/shared_runtime");
	char name[] = "shared_runtime";
	char *library = strdup(atf_tc_get_config_var_wd(tc, "missing_library",
	    "/usr/tests/bazel/intentionally-missing.so"));
	char *args[] = { name, library, NULL };

	ATF_REQUIRE(library != NULL);
	ATF_REQUIRE(access(library, F_OK) == -1 && errno == ENOENT);
	run_case_status(program, args, "", 2, library);
	free(library);
}

ATF_TC(sbuf_bazel);
ATF_TC_HEAD(sbuf_bazel, tc)
{
 atf_tc_set_md_var(tc, "descr", "Real libsbuf versioned providers, growth, formatting, errors and partial drains");
 atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(sbuf_bazel, tc)
{
 const char *program = atf_tc_get_config_var_wd(tc, "sbuf_program",
     "/usr/tests/bazel/sbuf_runtime");
 char name[] = "sbuf_runtime";
 char *library = strdup(atf_tc_get_config_var_wd(tc, "bazel_sbuf_library",
     "/usr/tests/bazel/libsbuf.so.6"));
 char *args[] = { name, library, NULL };
 ATF_REQUIRE(library != NULL);
 run_case(program, args, "sbuf-runtime: ok\n");
 free(library);
}

ATF_TC(sbuf_make);
ATF_TC_HEAD(sbuf_make, tc)
{
 atf_tc_set_md_var(tc, "descr", "Real libsbuf versioned providers, growth, formatting, errors and partial drains");
 atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(sbuf_make, tc)
{
 const char *program = atf_tc_get_config_var_wd(tc, "sbuf_program",
     "/usr/tests/bazel/sbuf_runtime");
 char name[] = "sbuf_runtime";
 char *library = strdup(atf_tc_get_config_var_wd(tc, "make_sbuf_library",
     "/usr/tests/bazel/libsbuf-make.so.6"));
 char *args[] = { name, library, NULL };
 ATF_REQUIRE(library != NULL);
 run_case(program, args, "sbuf-runtime: ok\n");
 free(library);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, echo_variants);
	ATF_TP_ADD_TC(tp, cpp_runtime);
	ATF_TP_ADD_TC(tp, make_echo_variants);
	ATF_TP_ADD_TC(tp, archive_runtime);
	ATF_TP_ADD_TC(tp, shared_bazel);
	ATF_TP_ADD_TC(tp, shared_make);
	ATF_TP_ADD_TC(tp, shared_missing_library);
	ATF_TP_ADD_TC(tp, sbuf_bazel);
	ATF_TP_ADD_TC(tp, sbuf_make);
	return (atf_no_error());
}

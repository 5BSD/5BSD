/* SPDX-License-Identifier: BSD-2-Clause */
/* Runtime qualification for explicit Make/Bazel fixture binaries. */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/elf64.h>
#include <sys/endian.h>
#include <stddef.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <poll.h>
#include <signal.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
check_output(int fd, const char *expected, const char *label, int contains)
{
	char buffer[65536];
	ssize_t n;

	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	n = read(fd, buffer, sizeof(buffer) - 1);
	ATF_REQUIRE_MSG(n >= 0, "%s read: %s", label, strerror(errno));
	buffer[n] = '\0';
	ATF_REQUIRE_MSG(contains ? strstr(buffer, expected) != NULL :
	    ((size_t)n == strlen(expected) && memcmp(buffer, expected, (size_t)n) == 0),
	    "%s mismatch: got <%s>, expected <%s>", label, buffer, expected);
	ATF_REQUIRE_MSG(read(fd, buffer, sizeof(buffer)) == 0,
	    "%s contains additional output", label);
}

static void
run_case_outputs(const char *program, char *const argv[], const char *expected,
    int exit_status, const char *missing_library, int contains, const char *input,
    const char *expected_stderr)
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
		if (input != NULL) {
			int infd = open(input, O_RDONLY);
			if (infd < 0 || dup2(infd, STDIN_FILENO) < 0)
				_exit(126);
			if (infd != STDIN_FILENO)
				close(infd);
		}
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
	if (!WIFEXITED(status) || WEXITSTATUS(status) != exit_status) {
		char diagnostic[2048];
		ssize_t length = pread(errfd, diagnostic, sizeof(diagnostic) - 1, 0);
		if (length < 0)
			length = 0;
		diagnostic[length] = '\0';
		/* ATF result records are single-line; preserve full child diagnostics. */
		fprintf(stderr, "%s child stderr:\n%s\n", program, diagnostic);
		atf_tc_fail("%s failed: wait status %#x, expected exit %d; stderr: %s (output in %s and %s)",
		    program, status, exit_status, diagnostic, outname, errname);
	}
	check_output(outfd, expected, "stdout", contains);
	if (missing_library == NULL) {
		check_output(errfd, expected_stderr != NULL ? expected_stderr : "", "stderr", 0);
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
run_case_status_input(const char *program, char *const argv[], const char *expected,
    int exit_status, const char *missing_library, int contains, const char *input)
{
	run_case_outputs(program, argv, expected, exit_status, missing_library,
	    contains, input, NULL);
}

static void
run_case_status(const char *program, char *const argv[], const char *expected,
    int exit_status, const char *missing_library, int contains)
{
	run_case_status_input(program, argv, expected, exit_status, missing_library,
	    contains, NULL);
}

static void
run_case(const char *program, char *const argv[], const char *expected)
{
	run_case_status(program, argv, expected, 0, NULL, 0);
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
	run_case_status(program, args, "", 2, library, 0);
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

/* Exercise both in-memory digesting and Casper-backed file access. */
static void
check_digest(const atf_tc_t *tc, const char *key, const char *fallback)
{
 const char *program = atf_tc_get_config_var_wd(tc, key, fallback);
 char md5[] = "md5", option[] = "-s", input[] = "abc";
 char filename[] = "digest-input", sum[] = "sha256sum";
 char *string_args[] = { md5, option, input, NULL };
 char *file_args[] = { md5, filename, NULL };
 char *sum_args[] = { sum, filename, NULL };
 int fd = open("digest-input", O_WRONLY | O_CREAT | O_EXCL, 0600);
 ATF_REQUIRE(fd >= 0);
 ATF_REQUIRE(write(fd, "abc", 3) == 3);
 ATF_REQUIRE(close(fd) == 0);
 run_case(program, string_args, "900150983cd24fb0d6963f7d28e17f72\n");
 run_case(program, file_args, "MD5 (digest-input) = 900150983cd24fb0d6963f7d28e17f72\n");
 run_case(program, sum_args, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  digest-input\n");
 ATF_REQUIRE(unlink("digest-input") == 0);
}
ATF_TC(digest_bazel);
ATF_TC_HEAD(digest_bazel, tc)
{
 atf_tc_set_md_var(tc, "descr", "Bazel digest with Casper file access and command alias dispatch");
 atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(digest_bazel, tc)
{
 check_digest(tc, "bazel_digest", "/usr/tests/bazel/md5");
}
ATF_TC(digest_make);
ATF_TC_HEAD(digest_make, tc)
{
 atf_tc_set_md_var(tc, "descr", "Make digest reference with the same runtime and Casper file access");
 atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(digest_make, tc)
{
 check_digest(tc, "make_digest", "/usr/tests/bazel/make-md5");
}

/* Known ELF64 little-endian layout, independent of either utility. */
static void
elf_fixture(void)
{
	struct {
		Elf64_Ehdr header;
		Elf64_Shdr sections[4];
		unsigned char payload[24];
	} image = {0};
	Elf64_Ehdr *h = &image.header;
	int fd;

	memcpy(h->e_ident, ELFMAG, SELFMAG);
	h->e_ident[EI_CLASS] = ELFCLASS64;
	h->e_ident[EI_DATA] = ELFDATA2LSB;
	h->e_ident[EI_VERSION] = EV_CURRENT;
	h->e_type = htole16(ET_REL);
	h->e_machine = htole16(EM_X86_64);
	h->e_version = htole32(EV_CURRENT);
	h->e_ehsize = htole16(sizeof(*h));
	h->e_shoff = htole64(offsetof(__typeof(image), sections));
	h->e_shentsize = htole16(sizeof(Elf64_Shdr));
	h->e_shnum = htole16(4);
	image.sections[1].sh_type = htole32(SHT_PROGBITS);
	image.sections[1].sh_flags = htole64(SHF_ALLOC | SHF_EXECINSTR);
	image.sections[1].sh_offset = htole64(offsetof(__typeof(image), payload));
	image.sections[1].sh_size = htole64(16);
	image.sections[2].sh_type = htole32(SHT_PROGBITS);
	image.sections[2].sh_flags = htole64(SHF_ALLOC | SHF_WRITE);
	image.sections[2].sh_offset = htole64(offsetof(__typeof(image), payload) + 16);
	image.sections[2].sh_size = htole64(8);
	image.sections[3].sh_type = htole32(SHT_NOBITS);
	image.sections[3].sh_flags = htole64(SHF_ALLOC | SHF_WRITE);
	image.sections[3].sh_size = htole64(12);
	fd = open("sample.elf", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, &image, sizeof(image)) == sizeof(image));
	ATF_REQUIRE(close(fd) == 0);
}

/* Explicit program paths allow the same checks against either build system. */
static void
check_elf_utilities(const atf_tc_t *tc, const char *prefix)
{
	char key[64], fallback[128];
	const char *program;
	char demangler[] = "c++filt", noarg[] = "_Z3foov", integer[] = "_Z3fooi";
	char plain[] = "plain", strings_name[] = "strings", all[] = "-a";
	char minimum[] = "-n", five[] = "5", filename[] = "strings-input";
	char size_name[] = "size", berkeley[] = "-B", sample[] = "sample.elf";
	char dump_name[] = "elfdump", identify[] = "-E";
	char *demangle[] = { demangler, noarg, integer, plain, NULL };
	char *strings[] = { strings_name, all, minimum, five, filename, NULL };
	char *sizes[] = { size_name, berkeley, sample, NULL };
	char *identify_args[] = { dump_name, identify, sample, NULL };
	static const char data[] = "\0alpha\0xy\0bravo!\0";
	int fd;

	(void)snprintf(key, sizeof(key), "%s_cxxfilt", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-cxxfilt", prefix);
	program = atf_tc_get_config_var_wd(tc, key, fallback);
	run_case(program, demangle, "foo()\nfoo(int)\nplain\n");
	fd = open("strings-input", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, data, sizeof(data)) == sizeof(data));
	ATF_REQUIRE(close(fd) == 0);
	(void)snprintf(key, sizeof(key), "%s_strings", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-strings", prefix);
	program = atf_tc_get_config_var_wd(tc, key, fallback);
	run_case(program, strings, "alpha\nbravo!\n");
	ATF_REQUIRE(unlink("strings-input") == 0);
	(void)snprintf(key, sizeof(key), "%s_size", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-size", prefix);
	program = atf_tc_get_config_var_wd(tc, key, fallback);
	elf_fixture();
	run_case(program, sizes,
	    "  text   data   bss   dec    hex   filename\n"
	    "    16      8    12    36   0x24   sample.elf\n");
	(void)snprintf(key, sizeof(key), "%s_elfdump", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-elfdump", prefix);
	program = atf_tc_get_config_var_wd(tc, key, fallback);
	run_case(program, identify_args, "");
	/* A non-ELF of the same length must be rejected, without diagnostics. */
	fd = open("sample.elf", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "NOPE", 4) == 4);
	ATF_REQUIRE(close(fd) == 0);
	run_case_status(program, identify_args, "", 1, NULL, 0);
	ATF_REQUIRE(unlink("sample.elf") == 0);
}

ATF_TC(elf_utilities_bazel);
ATF_TC_HEAD(elf_utilities_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Bazel demangling, strings file access, ELF identification and section sizes");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(elf_utilities_bazel, tc)
{
	check_elf_utilities(tc, "bazel");
}
ATF_TC(elf_utilities_make);
ATF_TC_HEAD(elf_utilities_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make references with identical utility runtime checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(elf_utilities_make, tc)
{
	check_elf_utilities(tc, "make");
}

static void
check_dwarf_utilities(const atf_tc_t *tc, const char *prefix)
{
	char key[64], fallback[128], address[64];
	char *fixture = strdup(atf_tc_get_config_var_wd(tc, "dwarf_fixture",
	    "/usr/tests/bazel/dwarf-fixture"));
	const char *address_path = atf_tc_get_config_var_wd(tc, "dwarf_address_file",
	    "/usr/tests/bazel/dwarf-address");
	FILE *f = fopen(address_path, "r");
	ATF_REQUIRE(fixture != NULL && f != NULL);
	ATF_REQUIRE(fgets(address, sizeof(address), f) != NULL);
	ATF_REQUIRE(fclose(f) == 0);
	address[strcspn(address, "\n")] = '\0';
	ATF_REQUIRE(address[0] != '\0' && strspn(address, "0123456789abcdefABCDEF") == strlen(address));
	char addrname[] = "addr2line", fileflag[] = "-e", funcflag[] = "-f", shortflag[] = "-s";
	char nmname[] = "nm", global[] = "-g", defined[] = "--defined-only";
	char readname[] = "readelf", symbols[] = "-s", wide[] = "-W";
	char *addrargs[] = { addrname, fileflag, fixture, funcflag, shortflag, address, NULL };
	char *nmargs[] = { nmname, global, defined, fixture, NULL };
	char *readargs[] = { readname, symbols, wide, fixture, NULL };
	(void)snprintf(key, sizeof(key), "%s_addr2line", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-addr2line", prefix);
	run_case(atf_tc_get_config_var_wd(tc, key, fallback), addrargs,
	    "dwarf_fixture_answer\ndwarf_fixture.c:102\n");
	(void)snprintf(key, sizeof(key), "%s_nm", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-nm", prefix);
	run_case_status(atf_tc_get_config_var_wd(tc, key, fallback), nmargs,
	    "dwarf_fixture_answer", 0, NULL, 1);
	(void)snprintf(key, sizeof(key), "%s_readelf", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-readelf", prefix);
	run_case_status(atf_tc_get_config_var_wd(tc, key, fallback), readargs,
	    "dwarf_fixture_answer", 0, NULL, 1);
	free(fixture);
}
ATF_TC(dwarf_utilities_bazel);
ATF_TC_HEAD(dwarf_utilities_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Bazel DWARF source lookup and ELF symbol reporting");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(dwarf_utilities_bazel, tc) { check_dwarf_utilities(tc, "bazel"); }
ATF_TC(dwarf_utilities_make);
ATF_TC_HEAD(dwarf_utilities_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make DWARF and ELF utility checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(dwarf_utilities_make, tc) { check_dwarf_utilities(tc, "make"); }

static void
sleep_cases(const char *program)
{
	char name[] = "sleep";
	char zero[] = "0", fraction[] = "0.02", seconds[] = "0s";
	char minutes[] = "0m", hours[] = "0h", days[] = "0d";
	char *values[] = { zero, fraction, seconds, minutes, hours, days };
	size_t i;

	for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		char *args[] = { name, values[i], NULL };
		run_case(program, args, "");
	}
}
ATF_TC(sleep_bazel);
ATF_TC_HEAD(sleep_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native Bazel sleep with Capsicum and DTrace retained");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(sleep_bazel, tc)
{
	sleep_cases(atf_tc_get_config_var_wd(tc, "sleep_program",
	    "/usr/tests/bazel/sleep"));
}
ATF_TC(sleep_make);
ATF_TC_HEAD(sleep_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make sleep with identical execution checks");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(sleep_make, tc)
{
	sleep_cases(atf_tc_get_config_var_wd(tc, "make_sleep_program",
	    "/usr/tests/bazel/make-sleep"));
}

static void
text_utility_case(const atf_tc_t *tc, const char *prefix, const char *name,
    char *const args[], const char *expected)
{
	char key[80], fallback[160];
	(void)snprintf(key, sizeof(key), "%s_%s", prefix, name);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-%s", prefix, name);
	run_case(atf_tc_get_config_var_wd(tc, key, fallback), args, expected);
}
static void
text_utilities(const atf_tc_t *tc, const char *prefix)
{
	const char contents[] = "alpha beta\ncharlie delta\necho foxtrot\n";
	char path[] = "text.txt", n[] = "-n", c[] = "-c", one[] = "1", five[] = "5";
	char head[] = "head", tail[] = "tail", wc[] = "wc", cut[] = "cut";
	char reverse[] = "-r", lines[] = "-l", words[] = "-w";
	char delim[] = "-d", space[] = " ", fields[] = "-f", two[] = "2";
	char *head_lines[] = {head, n, one, path, NULL};
	char *head_bytes[] = {head, c, five, path, NULL};
	char *tail_lines[] = {tail, n, one, path, NULL};
	char *tail_reverse[] = {tail, reverse, path, NULL};
	char *cut_fields[] = {cut, delim, space, fields, two, path, NULL};
	char *wc_lines[] = {wc, lines, path, NULL};
	char *wc_words[] = {wc, words, path, NULL};
	char *wc_bytes[] = {wc, c, path, NULL};
	char expected[80];
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, contents, sizeof(contents) - 1) == sizeof(contents) - 1);
	ATF_REQUIRE(close(fd) == 0);
	text_utility_case(tc, prefix, "head", head_lines, "alpha beta\n");
	text_utility_case(tc, prefix, "head", head_bytes, "alpha");
	text_utility_case(tc, prefix, "tail", tail_lines, "echo foxtrot\n");
	text_utility_case(tc, prefix, "tail", tail_reverse, "echo foxtrot\ncharlie delta\nalpha beta\n");
	text_utility_case(tc, prefix, "cut", cut_fields, "beta\ndelta\nfoxtrot\n");
	(void)snprintf(expected, sizeof(expected), "%8d text.txt\n", 3);
	text_utility_case(tc, prefix, "wc", wc_lines, expected);
	(void)snprintf(expected, sizeof(expected), "%8d text.txt\n", 6);
	text_utility_case(tc, prefix, "wc", wc_words, expected);
	(void)snprintf(expected, sizeof(expected), "%8d text.txt\n", 38);
	text_utility_case(tc, prefix, "wc", wc_bytes, expected);
	ATF_REQUIRE(unlink(path) == 0);
}
ATF_TC(text_utilities_bazel);
ATF_TC_HEAD(text_utilities_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Bazel head/tail/wc/cut with native Casper/libxo dependencies");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(text_utilities_bazel, tc) { text_utilities(tc, "bazel"); }
ATF_TC(text_utilities_make);
ATF_TC_HEAD(text_utilities_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make text utilities against the same native libraries");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(text_utilities_make, tc) { text_utilities(tc, "make"); }

static void
stream_fixture(const char *path, const char *contents)
{
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, contents, strlen(contents)) == (ssize_t)strlen(contents));
	ATF_REQUIRE(close(fd) == 0);
}
static void
stream_utilities(const atf_tc_t *tc, const char *prefix)
{
	char left[] = "left.txt", right[] = "right.txt", repeated[] = "repeated.txt";
	char joinleft[] = "joinleft.txt", joinright[] = "joinright.txt";
	char tr[] = "tr", lower[] = "a-z", upper[] = "A-Z";
	char paste[] = "paste", serial[] = "-s";
	char uniq[] = "uniq", duplicates[] = "-d";
	char comm[] = "comm", common[] = "-12";
	char join[] = "join", sed[] = "sed", script[] = "s/a/A/g";
	char *trargs[] = {tr, lower, upper, NULL};
	char *pasteargs[] = {paste, left, right, NULL};
	char *serialargs[] = {paste, serial, left, right, NULL};
	char *uniqargs[] = {uniq, repeated, NULL};
	char *dupargs[] = {uniq, duplicates, repeated, NULL};
	char *commargs[] = {comm, common, left, right, NULL};
	char *joinargs[] = {join, joinleft, joinright, NULL};
	char *sedargs[] = {sed, script, left, NULL};
	char key[80], fallback[160];
	stream_fixture(left, "a\nb\nc\n");
	stream_fixture(right, "b\nc\nd\n");
	stream_fixture(repeated, "alpha\nalpha\nbeta\nbeta\nbeta\n");
	stream_fixture(joinleft, "1 alpha\n2 beta\n3 gamma\n");
	stream_fixture(joinright, "2 two\n3 three\n4 four\n");
	(void)snprintf(key, sizeof(key), "%s_tr", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-tr", prefix);
	run_case_status_input(atf_tc_get_config_var_wd(tc, key, fallback), trargs,
	    "ALPHA\nALPHA\nBETA\nBETA\nBETA\n", 0, NULL, 0, repeated);
	text_utility_case(tc, prefix, "paste", pasteargs, "a\tb\nb\tc\nc\td\n");
	text_utility_case(tc, prefix, "paste", serialargs, "a\tb\tc\nb\tc\td\n");
	text_utility_case(tc, prefix, "uniq", uniqargs, "alpha\nbeta\n");
	text_utility_case(tc, prefix, "uniq", dupargs, "alpha\nbeta\n");
	text_utility_case(tc, prefix, "comm", commargs, "b\nc\n");
	text_utility_case(tc, prefix, "join", joinargs, "2 beta two\n3 gamma three\n");
	text_utility_case(tc, prefix, "sed", sedargs, "A\nb\nc\n");
	ATF_REQUIRE(unlink(left) == 0 && unlink(right) == 0 && unlink(repeated) == 0);
	ATF_REQUIRE(unlink(joinleft) == 0 && unlink(joinright) == 0);
}
ATF_TC(stream_utilities_bazel);
ATF_TC_HEAD(stream_utilities_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native Bazel tr/paste/uniq/comm/join/sed stream operations");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(stream_utilities_bazel, tc) { stream_utilities(tc, "bazel"); }
ATF_TC(stream_utilities_make);
ATF_TC_HEAD(stream_utilities_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make stream utilities with the same runtime");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(stream_utilities_make, tc) { stream_utilities(tc, "make"); }

/* Keep executable paths configurable so the same cases qualify both builds. */
static void
path_utilities(const atf_tc_t *tc, const char *prefix)
{
	char arg0[] = "basename";
	char arg1[] = "a/b";
	char arg2[] = "a/b/";
	char arg3[] = "/";
	char arg4[] = "";
	char arg5[] = "a/file.txt";
	char arg6[] = ".txt";
	char arg7[] = "-a";
	char arg8[] = "c/d";
	char arg9[] = "file";
	char arg10[] = "dirname";
	char arg11[] = "name";
	char arg12[] = "a/b///";
	char arg13[] = "-s";
	char arg14[] = ".c";
	char arg15[] = "one.c";
	char arg16[] = "two.c";
	char *base[][5] = {
	    { arg0, arg1, NULL },
	    { arg0, arg2, NULL },
	    { arg0, arg3, NULL },
	    { arg0, arg4, NULL },
	    { arg0, arg5, arg6, NULL },
	    { arg0, arg7, arg1, arg8, NULL },
	    { arg0, arg9, arg9, NULL },
	};
	const char *expected[] = { "b\n", "b\n", "/\n", "\n", "file\n", "b\nd\n", "file\n" };
	char *dirs[][4] = {
	    { arg10, arg1, NULL }, { arg10, arg11, NULL },
	    { arg10, arg3, NULL }, { arg10, arg4, NULL },
	    { arg10, arg1, arg8, NULL }, { arg10, arg12, NULL },
	};
	const char *dexpected[] = { "a\n", ".\n", "/\n", ".\n", "a\nc\n", "a\n" };
	char *suffix[] = { arg0, arg13, arg14, arg15, arg16, NULL };
	for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
		text_utility_case(tc, prefix, "basename", base[i], expected[i]);
	text_utility_case(tc, prefix, "basename", suffix, "one\ntwo\n");
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
		text_utility_case(tc, prefix, "dirname", dirs[i], dexpected[i]);
}

static void
yes_utilities(const atf_tc_t *tc, const char *prefix)
{
	char arg0[] = "yes";
	char arg1[] = "Hello, world!";
	char arg2[] = "The";
	char arg3[] = "Magic";
	char arg4[] = "Words";
	char key[80], fallback[160];
	char *args[][5] = { { arg0, NULL }, { arg0, arg1, NULL },
	    { arg0, arg2, arg3, arg4, NULL } };
	const char *lines[] = { "y\n", "Hello, world!\n", "The Magic Words\n" };
	(void)snprintf(key, sizeof(key), "%s_yes", prefix);
	(void)snprintf(fallback, sizeof(fallback), "/usr/tests/bazel/%s-yes", prefix);
	const char *program = atf_tc_get_config_var_wd(tc, key, fallback);
	for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		int fds[2], status;
		char data[256], expected[256] = "";
		size_t used = 0, length = 5 * strlen(lines[i]);
		ATF_REQUIRE(pipe(fds) == 0);
		pid_t child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			close(fds[0]);
			if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(126);
			close(fds[1]);
			signal(SIGPIPE, SIG_DFL);
			execv(program, args[i]);
			_exit(127);
		}
		close(fds[1]);
		while (used < length) {
			struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
			if (poll(&pfd, 1, 5000) <= 0) break;
			ssize_t n = read(fds[0], data + used, length - used);
			if (n <= 0) break;
			used += n;
		}
		close(fds[0]);
		if (used != length) kill(child, SIGKILL);
		ATF_REQUIRE(waitpid(child, &status, 0) == child);
		for (int j = 0; j < 5; j++) strcat(expected, lines[i]);
		ATF_REQUIRE(used == length && memcmp(data, expected, length) == 0);
		ATF_REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE);
	}
}
ATF_TC(path_utilities_bazel);
ATF_TC_HEAD(path_utilities_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native basename/dirname outputs and yes pipe termination");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(path_utilities_bazel, tc) { path_utilities(tc, "bazel"); yes_utilities(tc, "bazel"); }
ATF_TC(path_utilities_make);
ATF_TC_HEAD(path_utilities_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make basename/dirname outputs and yes pipe termination");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(path_utilities_make, tc) { path_utilities(tc, "make"); yes_utilities(tc, "make"); }

static void
cmp_cases(const char *program)
{
	char cmd[] = "cmp", a[] = "cmp-a", b[] = "cmp-b", c[] = "cmp-c";
	char silent[] = "-s", offset[] = "-i", four[] = "4", three[] = "3";
	char pair[] = "4:3", one[] = "1", links[] = "-h";
	char link1[] = "cmp-link1", link2[] = "cmp-link2", input[] = "-";
	char *equal[] = { cmd, a, a, NULL };
	char *different[] = { cmd, silent, a, b, NULL };
	char *skip[] = { cmd, silent, a, b, four, three, NULL };
	char *skip_pair[] = { cmd, offset, pair, silent, a, b, NULL };
	char *skip_one[] = { cmd, offset, one, silent, b, c, NULL };
	char *symlinks[] = { cmd, links, link1, link2, NULL };
	char *follow[] = { cmd, a, link1, NULL };
	char *stdin_right[] = { cmd, a, input, NULL };
	char *stdin_left[] = { cmd, input, a, NULL };
	stream_fixture(a, "1234567890");
	stream_fixture(b, "abc567890");
	stream_fixture(c, "xbc567890");
	ATF_REQUIRE(symlink(a, link1) == 0);
	ATF_REQUIRE(symlink(a, link2) == 0);
	run_case(program, equal, "");
	run_case_status(program, different, "", 1, NULL, 0);
	run_case(program, skip, "");
	run_case(program, skip_pair, "");
	run_case(program, skip_one, "");
	run_case(program, symlinks, "");
	run_case(program, follow, "");
	run_case_status_input(program, stdin_right, "", 0, NULL, 0, a);
	run_case_status_input(program, stdin_left, "", 0, NULL, 0, a);
	ATF_REQUIRE(unlink(link1) == 0 && unlink(link2) == 0);
	ATF_REQUIRE(unlink(a) == 0 && unlink(b) == 0 && unlink(c) == 0);
}
ATF_TC(cmp_bazel);
ATF_TC_HEAD(cmp_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native cmp equality, offsets, symlinks and stdin");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cmp_bazel, tc)
{
	cmp_cases(atf_tc_get_config_var_wd(tc, "bazel_cmp", "/usr/tests/bazel/bazel-cmp"));
}
ATF_TC(cmp_make);
ATF_TC_HEAD(cmp_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make cmp with the same cases and libraries");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cmp_make, tc)
{
	cmp_cases(atf_tc_get_config_var_wd(tc, "make_cmp", "/usr/tests/bazel/make-cmp"));
}

static void
diff_cases(const char *program)
{
	char cmd[] = "diff", left[] = "diff-left", right[] = "diff-right";
	char select[] = "--algorithm", stone[] = "stone", myers[] = "myers";
	char patience[] = "patience", ed[] = "-e", rcs[] = "-n";
	char unified[] = "-u", label[] = "-L", old[] = "old", new[] = "new";
	char *algorithms[] = { stone, myers, patience };
	char *equal[] = { cmd, left, left, NULL };
	stream_fixture(left, "one\ntwo\n");
	stream_fixture(right, "one\nthree\n");
	for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
		char *normal[] = { cmd, select, algorithms[i], left, right, NULL };
		char *editing[] = { cmd, select, algorithms[i], ed, left, right, NULL };
		char *revision[] = { cmd, select, algorithms[i], rcs, left, right, NULL };
		char *context[] = { cmd, select, algorithms[i], unified, label, old, label, new, left, right, NULL };
		run_case_status(program, normal, "2c2\n< two\n---\n> three\n", 1, NULL, 0);
		run_case_status(program, context, "--- old\n+++ new\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n", 1, NULL, 0);
		if (i == 0)
			run_case_status(program, editing, "2c\nthree\n.\n", 1, NULL, 0);
		else
			run_case_outputs(program, editing, "", 2, NULL, 0, NULL,
			    "diff: cannot use Myers algorithm with selected options\n");
		if (i == 0)
			run_case_status(program, revision, "d2 1\na2 1\nthree\n", 1, NULL, 0);
		else
			run_case_outputs(program, revision, "", 2, NULL, 0, NULL,
			    "diff: cannot use Myers algorithm with selected options\n");
	}
	run_case(program, equal, "");
	ATF_REQUIRE(unlink(left) == 0 && unlink(right) == 0);
}
ATF_TC(diff_bazel);
ATF_TC_HEAD(diff_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native diff algorithms and output formats");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(diff_bazel, tc)
{
	diff_cases(atf_tc_get_config_var_wd(tc, "bazel_diff", "/usr/tests/bazel/bazel-diff"));
}
ATF_TC(diff_make);
ATF_TC_HEAD(diff_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Independent Make diff with the same algorithm cases");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(diff_make, tc)
{
	diff_cases(atf_tc_get_config_var_wd(tc, "make_diff", "/usr/tests/bazel/make-diff"));
}

static void
merge_fixture_case(const char *program, char *const argv[],
    const char *reference, int exit_status)
{
	char expected[65536];
	FILE *f = fopen(reference, "r");
	size_t length;
	ATF_REQUIRE(f != NULL);
	length = fread(expected, 1, sizeof(expected) - 1, f);
	ATF_REQUIRE(!ferror(f) && feof(f));
	expected[length] = '\0';
	ATF_REQUIRE(fclose(f) == 0);
	run_case_status(program, argv, expected, exit_status, NULL, 0);
}

static void
merge_cases(const char *diff3, const char *sdiff, const char *diff,
    const char *fixtures)
{
	char helper[1024], a[1024], b[1024], c[1024], expected[1024];
	char cmd[] = "diff3", side[] = "sdiff", ed[] = "-e", conflict[] = "-E";
	char label[] = "-L", one[] = "1", two[] = "2", three[] = "3", suppress[] = "-s";
	ATF_REQUIRE(snprintf(helper, sizeof(helper), "--diff-program=%s", diff) < (int)sizeof(helper));
#define FIXTURE(dst, suffix) do { \
	int n = snprintf(dst, sizeof(dst), "%s/%s", fixtures, suffix); \
	ATF_REQUIRE(n > 0 && n < (int)sizeof(dst)); \
} while (0)
	FIXTURE(a, "diff3/1.txt"); FIXTURE(b, "diff3/2.txt"); FIXTURE(c, "diff3/3.txt");
	char *normal_args[] = { cmd, helper, a, b, c, NULL };
	char *ed_args[] = { cmd, helper, ed, a, b, c, NULL };
	char *conflict_args[] = { cmd, helper, conflict, label, one, label, two, label, three, a, b, c, NULL };
	FIXTURE(expected, "diff3/1.out");
	merge_fixture_case(diff3, normal_args, expected, 0);
	FIXTURE(expected, "diff3/2.out");
	merge_fixture_case(diff3, ed_args, expected, 0);
	FIXTURE(expected, "diff3/3.out");
	merge_fixture_case(diff3, conflict_args, expected, 1);
	FIXTURE(a, "sdiff/d_input1"); FIXTURE(b, "sdiff/d_input2");
	char *suppress_args[] = { side, helper, suppress, a, b, NULL };
	FIXTURE(expected, "sdiff/d_flags_s.out");
	merge_fixture_case(sdiff, suppress_args, expected, 1);
	FIXTURE(a, "sdiff/d_tabs1.in"); FIXTURE(b, "sdiff/d_tabs2.in");
	char *tabs_args[] = { side, helper, a, b, NULL };
	FIXTURE(expected, "sdiff/d_tabs.out");
	merge_fixture_case(sdiff, tabs_args, expected, 1);
#undef FIXTURE
}

ATF_TC(merge_bazel);
ATF_TC_HEAD(merge_bazel, tc)
{
	atf_tc_set_md_var(tc, "descr", "Native diff3 and sdiff with native diff helper");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(merge_bazel, tc)
{
	merge_cases(atf_tc_get_config_var_wd(tc, "bazel_diff3", "/usr/tests/bazel/bazel-diff3"),
	    atf_tc_get_config_var_wd(tc, "bazel_sdiff", "/usr/tests/bazel/bazel-sdiff"),
	    atf_tc_get_config_var_wd(tc, "bazel_diff", "/usr/tests/bazel/bazel-diff"),
	    atf_tc_get_config_var_wd(tc, "merge_fixtures", "/usr/tests/bazel/merge-fixtures"));
}
ATF_TC(merge_make);
ATF_TC_HEAD(merge_make, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make diff3 and sdiff with Make diff helper");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(merge_make, tc)
{
	merge_cases(atf_tc_get_config_var_wd(tc, "make_diff3", "/usr/tests/bazel/make-diff3"),
	    atf_tc_get_config_var_wd(tc, "make_sdiff", "/usr/tests/bazel/make-sdiff"),
	    atf_tc_get_config_var_wd(tc, "make_diff", "/usr/tests/bazel/make-diff"),
	    atf_tc_get_config_var_wd(tc, "merge_fixtures", "/usr/tests/bazel/merge-fixtures"));
}

static void
tee_file_check(const char *path, const char *expected)
{
    char data[128];
    FILE *f = fopen(path, "rb");
    ATF_REQUIRE(f != NULL);
    size_t n = fread(data, 1, sizeof(data), f);
    ATF_REQUIRE(!ferror(f));
    ATF_REQUIRE(fclose(f) == 0);
    ATF_REQUIRE(n == strlen(expected) && memcmp(data, expected, n) == 0);
}

static void
tee_cases(const char *program)
{
    char cmd[] = "tee", first[] = "first", second[] = "second", append[] = "-a";
    char *multi[] = { cmd, first, second, NULL };
    char *add[] = { cmd, append, first, NULL };
    stream_fixture("tee-input", "alpha\nbeta\n");
    run_case_status_input(program, multi, "alpha\nbeta\n", 0, NULL, 0, "tee-input");
    tee_file_check(first, "alpha\nbeta\n");
    tee_file_check(second, "alpha\nbeta\n");
    stream_fixture("tee-append", "extra\n");
    run_case_status_input(program, add, "extra\n", 0, NULL, 0, "tee-append");
    tee_file_check(first, "alpha\nbeta\nextra\n");
    tee_file_check(second, "alpha\nbeta\n");
}
ATF_TC(tee_bazel);
ATF_TC_HEAD(tee_bazel, tc) { atf_tc_set_md_var(tc, "timeout", "30"); }
ATF_TC_BODY(tee_bazel, tc)
{
    tee_cases(atf_tc_get_config_var_wd(tc, "bazel_tee", "/usr/tests/bazel/bazel-tee"));
}
ATF_TC(tee_make);
ATF_TC_HEAD(tee_make, tc) { atf_tc_set_md_var(tc, "timeout", "30"); }
ATF_TC_BODY(tee_make, tc)
{
    tee_cases(atf_tc_get_config_var_wd(tc, "make_tee", "/usr/tests/bazel/make-tee"));
}


static void
printenv_cases(const char *program)
{
	char cmd[] = "printenv", name[] = "BSD_BAZEL_PRINTENV_TEST";
	char other[] = "BSD_BAZEL_PRINTENV_OTHER";
	char *lookup[] = { cmd, name, NULL };
	char *all[] = { cmd, NULL };
	char *multiple[] = { cmd, name, other, NULL };

	ATF_REQUIRE(setenv(name, "two words=three", 1) == 0);
	run_case(program, lookup, "two words=three\n");
	run_case_status(program, all, "BSD_BAZEL_PRINTENV_TEST=two words=three\n",
	    0, NULL, 1);
	ATF_REQUIRE(setenv(name, "", 1) == 0);
	run_case(program, lookup, "\n");
	ATF_REQUIRE(unsetenv(name) == 0);
	run_case_status(program, lookup, "", 1, NULL, 0);
	run_case_outputs(program, multiple, "", 1, NULL, 0, NULL,
	    "usage: printenv [name]\n");
}
ATF_TC(printenv_bazel);
ATF_TC_HEAD(printenv_bazel, tc) { atf_tc_set_md_var(tc, "timeout", "30"); }
ATF_TC_BODY(printenv_bazel, tc)
{
	printenv_cases(atf_tc_get_config_var_wd(tc, "bazel_printenv",
	    "/usr/tests/bazel/bazel-printenv"));
}
ATF_TC(printenv_make);
ATF_TC_HEAD(printenv_make, tc) { atf_tc_set_md_var(tc, "timeout", "30"); }
ATF_TC_BODY(printenv_make, tc)
{
	printenv_cases(atf_tc_get_config_var_wd(tc, "make_printenv",
	    "/usr/tests/bazel/make-printenv"));
}

/* Execute an explicitly staged Bazel test launcher and retain its exit contract. */
ATF_TC(declared_bazel_test);
ATF_TC_HEAD(declared_bazel_test, tc)
{
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(declared_bazel_test, tc)
{
	const char *program = atf_tc_get_config_var_wd(tc, "bazel_test_program",
	    "/usr/tests/bazel/declared-test");
	char name[] = "declared-bazel-test";
	char *arguments[] = { name, NULL };

	pid_t child, waited;
	int status;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		execv(program, arguments);
		perror(program);
		_exit(127);
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	ATF_REQUIRE(waited == child);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s failed: wait status %#x", program, status);
}

ATF_TC_WITHOUT_HEAD(installed_account_databases);
ATF_TC_BODY(installed_account_databases, tc)
{
	struct passwd *pw;
	struct stat st;
	uid_t uid;
	gid_t gid;
	pid_t child;
	int status, fd;

	(void)tc;
	ATF_REQUIRE(geteuid() == 0);
	pw = getpwnam("root");
	ATF_REQUIRE(pw != NULL && pw->pw_uid == 0);
	pw = getpwuid(0);
	ATF_REQUIRE(pw != NULL && strcmp(pw->pw_name, "root") == 0);
	ATF_REQUIRE(stat("/etc/spwd.db", &st) == 0);
	ATF_REQUIRE((st.st_mode & 07777) == 0600 && st.st_uid == 0);
	ATF_REQUIRE(stat("/etc/pwd.db", &st) == 0);
	ATF_REQUIRE((st.st_mode & 07777) == 0644 && st.st_uid == 0);
	pw = getpwnam("nobody");
	ATF_REQUIRE(pw != NULL && pw->pw_uid != 0);
	uid = pw->pw_uid;
	gid = pw->pw_gid;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
			_exit(1);
		fd = open("/etc/pwd.db", O_RDONLY);
		if (fd < 0)
			_exit(2);
		close(fd);
		fd = open("/etc/spwd.db", O_RDONLY);
		if (fd >= 0 || errno != EACCES)
			_exit(3);
		pw = getpwnam("root");
		if (pw == NULL || pw->pw_uid != 0)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TC_WITHOUT_HEAD(installed_ctype_locale);
ATF_TC_BODY(installed_ctype_locale, tc)
{
	mbstate_t state = {0};
	wchar_t value;
	struct stat st;
	char link[128];
	ssize_t length;

	(void)tc;
	ATF_REQUIRE(lstat("/usr/share/locale/en_US.UTF-8/LC_CTYPE", &st) == 0);
	ATF_REQUIRE(S_ISLNK(st.st_mode));
	length = readlink("/usr/share/locale/en_US.UTF-8/LC_CTYPE", link, sizeof(link) - 1);
	ATF_REQUIRE(length >= 0);
	link[length] = '\0';
	ATF_REQUIRE_STREQ("../C.UTF-8/LC_CTYPE", link);
	ATF_REQUIRE(setlocale(LC_CTYPE, "en_US.UTF-8") != NULL);
	ATF_REQUIRE_EQ(2, mbrtowc(&value, "\303\244", 2, &state));
	ATF_REQUIRE_EQ(0x00e4, value);
	ATF_REQUIRE(iswalpha(value) != 0);
}

ATF_TC_WITHOUT_HEAD(installed_message_locale);
ATF_TC_BODY(installed_message_locale, tc)
{
	(void)tc;
	ATF_REQUIRE(setlocale(LC_MESSAGES, "C") != NULL);
	ATF_REQUIRE_STREQ("No such file or directory", strerror(ENOENT));
	ATF_REQUIRE(setlocale(LC_MESSAGES, "nl_NL.ISO8859-1") != NULL);
	ATF_REQUIRE_STREQ("Bestand of map niet gevonden", strerror(ENOENT));
	ATF_REQUIRE(setlocale(LC_MESSAGES, "C") != NULL);
	ATF_REQUIRE_STREQ("No such file or directory", strerror(ENOENT));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, installed_message_locale);
	ATF_TP_ADD_TC(tp, installed_ctype_locale);
	ATF_TP_ADD_TC(tp, installed_account_databases);
	ATF_TP_ADD_TC(tp, declared_bazel_test);
	ATF_TP_ADD_TC(tp, printenv_bazel);
	ATF_TP_ADD_TC(tp, printenv_make);
	ATF_TP_ADD_TC(tp, tee_bazel);
	ATF_TP_ADD_TC(tp, tee_make);
	ATF_TP_ADD_TC(tp, merge_bazel);
	ATF_TP_ADD_TC(tp, merge_make);
	ATF_TP_ADD_TC(tp, diff_bazel);
	ATF_TP_ADD_TC(tp, diff_make);
	ATF_TP_ADD_TC(tp, cmp_bazel);
	ATF_TP_ADD_TC(tp, cmp_make);
	ATF_TP_ADD_TC(tp, path_utilities_bazel);
	ATF_TP_ADD_TC(tp, path_utilities_make);
	ATF_TP_ADD_TC(tp, stream_utilities_bazel);
	ATF_TP_ADD_TC(tp, stream_utilities_make);
	ATF_TP_ADD_TC(tp, text_utilities_bazel);
	ATF_TP_ADD_TC(tp, text_utilities_make);
	ATF_TP_ADD_TC(tp, sleep_bazel);
	ATF_TP_ADD_TC(tp, sleep_make);
	ATF_TP_ADD_TC(tp, dwarf_utilities_bazel);
	ATF_TP_ADD_TC(tp, dwarf_utilities_make);
	ATF_TP_ADD_TC(tp, elf_utilities_bazel);
	ATF_TP_ADD_TC(tp, elf_utilities_make);
	ATF_TP_ADD_TC(tp, digest_bazel);
	ATF_TP_ADD_TC(tp, digest_make);
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

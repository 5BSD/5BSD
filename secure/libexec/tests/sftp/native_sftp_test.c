/* SPDX-License-Identifier: BSD-2-Clause */
/* Direct SFTP protocol tests; both executables are explicit test inputs. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <atf-c/utils.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
payload(void)
{
	FILE *file;
	unsigned char block[4096];
	size_t i;

	for (i = 0; i < sizeof(block); i++)
		block[i] = i % 256;
	ATF_REQUIRE((file = fopen("payload", "wb")) != NULL);
	for (i = 0; i < 256; i++)
		ATF_REQUIRE_EQ(sizeof(block), fwrite(block, 1, sizeof(block), file));
	ATF_REQUIRE_EQ(0, fclose(file));
}

static void
client(const atf_tc_t *tc, const char *commands, int readonly, int expected)
{
	const char *program = atf_tc_get_config_var(tc, "sftp");
	const char *server = atf_tc_get_config_var(tc, "server");
	char *command;
	FILE *file;
	pid_t pid, waited;
	int status, fd;

	ATF_REQUIRE(program[0] == '/' && server[0] == '/');
	/* argv_split accepts double-quoted paths; reject ambiguous quotes. */
	ATF_REQUIRE(strpbrk(server, "\"\\\r\n") == NULL);
	ATF_REQUIRE(asprintf(&command, "\"%s\"%s", server,
	    readonly ? " -R" : "") >= 0);
	ATF_REQUIRE((file = fopen("batch", "w")) != NULL);
	ATF_REQUIRE(fputs(commands, file) >= 0);
	ATF_REQUIRE_EQ(0, fclose(file));
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		fd = open("client.log", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
		    dup2(fd, STDERR_FILENO) < 0)
			_exit(126);
		close(fd);
		execl(program, "sftp", "-f", "-b", "batch", "-D", command,
		    (char *)NULL);
		_exit(127);
	}
	free(command);
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);
	ATF_REQUIRE_EQ(pid, waited);
	atf_utils_cat_file("client.log", "sftp: ");
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(expected, WEXITSTATUS(status));
}

static void
compare_payload(const char *path)
{
	FILE *a, *b;
	int x, y;

	ATF_REQUIRE((a = fopen("payload", "rb")) != NULL);
	ATF_REQUIRE((b = fopen(path, "rb")) != NULL);
	do {
		x = fgetc(a);
		y = fgetc(b);
		ATF_REQUIRE_EQ(x, y);
	} while (x != EOF);
	ATF_REQUIRE(!ferror(a) && !ferror(b));
	ATF_REQUIRE_EQ(0, fclose(a));
	ATF_REQUIRE_EQ(0, fclose(b));
}

ATF_TC(transfer);
ATF_TC_HEAD(transfer, tc)
{
	atf_tc_set_md_var(tc, "require.config", "sftp server");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(transfer, tc)
{
	struct stat st;
	char link[32];

	payload();
	client(tc, "mkdir remote\nput payload remote/upload\n"
	    "chmod 640 remote/upload\nrename remote/upload remote/renamed\n"
	    "ln -s renamed remote/link\nget remote/link download\nbye\n", 0, 0);
	ATF_REQUIRE_EQ(0, stat("remote/renamed", &st));
	ATF_REQUIRE_EQ(0640, st.st_mode & 0777);
	ATF_REQUIRE_EQ(7, readlink("remote/link", link, sizeof(link)));
	ATF_REQUIRE(memcmp(link, "renamed", 7) == 0);
	compare_payload("download");
}

ATF_TC(readonly);
ATF_TC_HEAD(readonly, tc)
{
	atf_tc_set_md_var(tc, "require.config", "sftp server");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(readonly, tc)
{
	struct stat st;

	payload();
	client(tc, "get payload readonly-copy\nput payload blocked\n", 1, 1);
	compare_payload("readonly-copy");
	errno = 0;
	ATF_REQUIRE_EQ(-1, lstat("blocked", &st));
	ATF_REQUIRE_EQ(ENOENT, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transfer);
	ATF_TP_ADD_TC(tp, readonly);
	return (atf_no_error());
}

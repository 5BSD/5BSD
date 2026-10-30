/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

ATF_TC(private_slave);
ATF_TC_HEAD(private_slave, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An owned PTY slave supports ordinary opens and terminal I/O");
	atf_tc_set_md_var(tc, "timeout", "15");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(private_slave, tc)
{
	struct termios term;
	struct winsize size;
	struct stat st;
	pid_t child;
	char *name, byte;
	int master, slave, status;

	(void)tc;
	ATF_REQUIRE_EQ(geteuid(), 0);
	master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	ATF_REQUIRE(master >= 0);
	ATF_REQUIRE(grantpt(master) == 0);
	ATF_REQUIRE(unlockpt(master) == 0);
	name = ptsname(master);
	ATF_REQUIRE(name != NULL);
	slave = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	ATF_REQUIRE_MSG(slave >= 0, "PTY slave open: errno %d", errno);
	ATF_REQUIRE(fstat(slave, &st) == 0);
	ATF_REQUIRE(S_ISCHR(st.st_mode));
	ATF_REQUIRE_EQ(st.st_uid, geteuid());
	ATF_REQUIRE(tcgetattr(slave, &term) == 0);
	cfmakeraw(&term);
	ATF_REQUIRE(tcsetattr(slave, TCSANOW, &term) == 0);
	size = (struct winsize){ .ws_row = 24, .ws_col = 80 };
	ATF_REQUIRE(ioctl(slave, TIOCSWINSZ, &size) == 0);
	ATF_REQUIRE(write(slave, "x", 1) == 1);
	ATF_REQUIRE(read(master, &byte, 1) == 1);
	ATF_REQUIRE_EQ(byte, 'x');
	/* Test DAC using only this newly allocated terminal, never a login TTY. */
	{
		ATF_REQUIRE(fchmod(slave, 0600) == 0);
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			close(slave);
			close(master);
			if (setgroups(0, NULL) != 0 || setgid(65534) != 0 ||
			    setuid(65534) != 0)
				_exit(2);
			slave = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
			_exit(slave == -1 && errno == EACCES ? 0 : 1);
		}
		ATF_REQUIRE(waitpid(child, &status, 0) == child);
		ATF_REQUIRE(WIFEXITED(status));
		ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	}
	ATF_REQUIRE(close(slave) == 0);
	ATF_REQUIRE(close(master) == 0);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, private_slave);
	return (atf_no_error());
}

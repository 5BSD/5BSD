/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <bsm/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>

ATF_TC(event_device);
ATF_TC_HEAD(event_device, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The device event reader opens under ordinary root DAC without granting device control");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is_exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(event_device, tc)
{
	struct stat st;
	pid_t child;
	int fd, second, status, nonblock;

	if (!atf_tc_get_config_var_as_bool_wd(tc, "disposable_vm", false))
		atf_tc_skip("requires disposable_vm=yes and a guest with devd stopped");
	ATF_REQUIRE(stat("/dev/devctl", &st) == 0);
	ATF_REQUIRE(S_ISCHR(st.st_mode));
	ATF_REQUIRE_EQ(st.st_uid, 0);
	ATF_REQUIRE_EQ(st.st_mode & 0777, 0600);
	fd = open("/dev/devctl", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0 && errno == EBUSY)
		atf_tc_skip("devctl already has a reader; do not stop host services");
	ATF_REQUIRE_MSG(fd >= 0, "root event-device open: errno %d", errno);
	second = open("/dev/devctl", O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE_ERRNO(EBUSY, second == -1);
	nonblock = 1;
	ATF_REQUIRE(ioctl(fd, FIONBIO, &nonblock) == 0);
	/* The event stream does not implement hardware-management requests. */
	ATF_REQUIRE_ERRNO(ENOTTY, ioctl(fd, _IO('Z', 250), NULL) == -1);
	ATF_REQUIRE(close(fd) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setgroups(0, NULL) != 0 || setgid(65534) != 0 ||
		    setuid(65534) != 0)
			_exit(2);
		fd = open("/dev/devctl", O_RDONLY | O_NONBLOCK);
		_exit(fd == -1 && errno == EACCES ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	/* Closing the single reader must release the device for normal devd. */
	fd = open("/dev/devctl", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	ATF_REQUIRE_MSG(fd >= 0, "reopen after close: errno %d", errno);
	ATF_REQUIRE(close(fd) == 0);
}
ATF_TC(audit_event_device);
ATF_TC_HEAD(audit_event_device, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Audit notification device remains root-only and rejects writes");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is_exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(audit_event_device, tc)
{
	struct stat st;
	pid_t child;
	int fd, second, status;

	if (!atf_tc_get_config_var_as_bool_wd(tc, "disposable_vm", false))
		atf_tc_skip("requires disposable_vm=yes and a guest with auditd stopped");
	ATF_REQUIRE(stat(AUDIT_TRIGGER_FILE, &st) == 0);
	ATF_REQUIRE(S_ISCHR(st.st_mode));
	ATF_REQUIRE_EQ(st.st_uid, 0);
	ATF_REQUIRE_EQ(st.st_mode & 0777, 0600);
	fd = open(AUDIT_TRIGGER_FILE, O_RDWR | O_CLOEXEC);
	if (fd < 0 && errno == EBUSY)
		atf_tc_skip("audit already has a reader; do not stop host services");
	ATF_REQUIRE_MSG(fd >= 0, "root audit-device open: errno %d", errno);
	second = open(AUDIT_TRIGGER_FILE, O_RDONLY);
	ATF_REQUIRE_ERRNO(EBUSY, second == -1);
	ATF_REQUIRE_ERRNO(EOPNOTSUPP, write(fd, "x", 1) == -1);
	ATF_REQUIRE(close(fd) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setgroups(0, NULL) != 0 || setgid(65534) != 0 ||
		    setuid(65534) != 0)
			_exit(2);
		fd = open(AUDIT_TRIGGER_FILE, O_RDONLY);
		_exit(fd == -1 && errno == EACCES ? 0 : 1);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	fd = open(AUDIT_TRIGGER_FILE, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(close(fd) == 0);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, event_device);
	ATF_TP_ADD_TC(tp, audit_event_device);
	return (atf_no_error());
}

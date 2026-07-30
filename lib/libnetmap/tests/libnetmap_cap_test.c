#include <sys/capsicum.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libnetmap.h>
#include <stdio.h>
#include <unistd.h>

ATF_TC(borrowed_fd);
ATF_TC_HEAD(borrowed_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "nmport_register_fd duplicates and never consumes a borrowed fd");
}
ATF_TC_BODY(borrowed_fd, tc)
{
	struct nmport_d *port;
	int fd;

	port = nmport_prepare("vale0:borrowed");
	ATF_REQUIRE(port != NULL);
	fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(-1, nmport_register_fd(port, fd));
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);
	nmport_close(port);
}

ATF_TC(invalid_fd);
ATF_TC_HEAD(invalid_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "nmport_register_fd rejects invalid descriptors without state drift");
}
ATF_TC_BODY(invalid_fd, tc)
{
	struct nmport_d *port;

	port = nmport_prepare("vale0:invalid");
	ATF_REQUIRE(port != NULL);
	ATF_CHECK_EQ(-1, nmport_register_fd(port, -1));
	ATF_CHECK_EQ(EINVAL, errno);
	nmport_close(port);
}

ATF_TC(capability_openat);
ATF_TC_HEAD(capability_openat, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a preopened /dev directory supports netmap registration in cap mode");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "netmap");
}
ATF_TC_BODY(capability_openat, tc)
{
	struct nmport_d *port;
	cap_rights_t rights;
	char portspec[64];
	int devdir, fd;

	devdir = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(devdir >= 0);
	cap_rights_init(&rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT, CAP_IOCTL,
	    CAP_LOOKUP, CAP_MMAP_RW, CAP_READ, CAP_WRITE);
	ATF_REQUIRE_EQ(0, cap_rights_limit(devdir, &rights));
	ATF_REQUIRE_EQ(0, cap_enter());
	fd = openat(devdir, "netmap", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	snprintf(portspec, sizeof(portspec), "vale99:atf%ld", (long)getpid());
	port = nmport_prepare(portspec);
	ATF_REQUIRE(port != NULL);
	ATF_REQUIRE_EQ(0, nmport_register_fd(port, fd));
	close(fd);
	ATF_REQUIRE_EQ(0, nmport_mmap(port));
	ATF_CHECK(port->reg.nr_memsize > 0);
	nmport_close(port);
	close(devdir);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, borrowed_fd);
	ATF_TP_ADD_TC(tp, invalid_fd);
	ATF_TP_ADD_TC(tp, capability_openat);
	return (atf_no_error());
}

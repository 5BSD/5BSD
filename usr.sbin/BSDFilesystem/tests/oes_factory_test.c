/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <security/oes/oes.h>
#include <string.h>
#include <unistd.h>

#include "oes_factory.h"
ATF_TC(notify_only_in_capmode);
ATF_TC_HEAD(notify_only_in_capmode, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(notify_only_in_capmode, tc)
{
	cap_rights_t rights;
	struct oes_mode_args mode = { 0 };
	struct oes_scope_args scope = { .esa_scope = OES_SCOPE_DESCENDANTS };
	oes_event_type_t event = OES_EVENT_NOTIFY_EXEC;
	struct oes_subscribe_args sub = { .esa_events = &event,
		.esa_count = 1 };
	int rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	int fd = bsdfilesystem_oes_open_notify(rootfd);
	ATF_REQUIRE_MSG(fd >= 0, "factory: %s", strerror(errno));
	close(rootfd);
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ, CAP_EVENT, CAP_IOCTL));
	ATF_REQUIRE_EQ(0, cap_enter());
	ATF_CHECK_EQ(0, ioctl(fd, OES_IOC_GET_MODE, &mode));
	ATF_CHECK_EQ(OES_MODE_NOTIFY, mode.ema_mode);
	ATF_CHECK_EQ(0, ioctl(fd, OES_IOC_SUBSCRIBE, &sub));
	event = OES_EVENT_AUTH_EXEC;
	ATF_CHECK_ERRNO(EPERM, ioctl(fd, OES_IOC_SUBSCRIBE, &sub) == -1);
	mode.ema_mode = OES_MODE_AUTH;
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, OES_IOC_SET_MODE, &mode) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, OES_IOC_SET_SCOPE, &scope) == -1);
	ATF_REQUIRE_EQ(0, close(fd));
}
ATF_TC_WITHOUT_HEAD(invalid_root);
ATF_TC_BODY(invalid_root, tc)
{
	ATF_CHECK_ERRNO(EBADF, bsdfilesystem_oes_open_notify(-1) == -1);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, notify_only_in_capmode);
	ATF_TP_ADD_TC(tp, invalid_root);
	return (atf_no_error());
}
